/**
 * Hyphae v2 Verified Human Drops — Mobile Portal Controller
 *
 * Security invariants:
 * - Immediately parses `window.location.hash` into RAM and scrubs the URL bar via `history.replaceState`.
 * - Hard-ignores any plaintext `proposedText`, `draft`, or `body` in URL fragments.
 * - Accepts optional HPKE-encrypted `encDraft` (`human.draft.v1`) ONLY on `kind === "directive"`
 *   (hard-ignored on `kind === "secret"`), decryptable strictly after Face ID / Touch ID.
 * - Derives Ed25519 signing seed & companion X25519 draft key strictly in RAM via WebAuthn Passkey + PRF -> HKDF-SHA256.
 * - Verifies `NodeCertV1` (`hcert1_`) against the derived human authority pubkey before sealing.
 * - Hard-blocks `kind === "secret"` drops on unverified nodes or reserved system secret names.
 * - Zeroes ephemeral seeds and wipes form inputs immediately after sealing, on reset/skip, on `pagehide`,
 *   or on `visibilitychange` when hidden.
 * - Falls back cleanly to 1-tap offline `hdrop1_` copy + retry if the Drop Relay is unreachable.
 */

import {
  base64urlDecode,
  base64urlEncode,
  decodeOkpJwkBytes,
  derivePrfEd25519Seed,
  derivePrfX25519Keypair,
  ed25519KeypairFromSeed,
  HUMAN_DRAFT_SUITE,
  isReservedSecretName,
  MAX_PADDED_PLAINTEXT,
  openHumanDraft,
  randomBytes,
  sasFingerprint,
  sealHumanDrop,
  signNodeCert,
  toCanonicalJson,
  utf8Bytes,
  utf8String,
  validateApprovalAction,
  validateSecretName,
  verifyNodeCert,
  zeroize,
} from "./crypto.js?v=4";
import {
  coerceBytes as readPasskeyBytes,
  copyText as copyBrowserText,
  createPasskeyOperations,
  extractPrfFirst as readPasskeyPrfFirst,
  isEmbeddedInFrame,
} from "../passkey.js?v=1";

export { isEmbeddedInFrame };

const HINT_STORAGE_PREFIX = "hyphae.drop.hint.v1:";
const MAX_DROP_TTL_MS = 10 * 60 * 1000;

// ============================================================================
// Pure Parsing & URL Safety Helpers (Exported for Unit Testing)
// ============================================================================

export function isAllowedRelayUrl(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.length === 0) return false;
  try {
    const u = new URL(rawUrl);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost")) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

export function isLoopbackCallbackUrl(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.length === 0) return false;
  try {
    const u = new URL(rawUrl);
    return u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost");
  } catch {
    return false;
  }
}

function parseOptionalEncDraft(rawDraft) {
  if (!rawDraft || typeof rawDraft !== "object" || Array.isArray(rawDraft)) {
    return null;
  }
  if (rawDraft.v !== 1 || rawDraft.suite !== HUMAN_DRAFT_SUITE) {
    return null;
  }
  if (
    typeof rawDraft.recipientKid !== "string" ||
    rawDraft.recipientKid.length === 0 ||
    typeof rawDraft.enc !== "string" ||
    typeof rawDraft.ct !== "string"
  ) {
    return null;
  }
  try {
    const encBytes = base64urlDecode(rawDraft.enc);
    const ctBytes = base64urlDecode(rawDraft.ct);
    if (encBytes.length !== 32 || ctBytes.length < 16) {
      return null;
    }
  } catch {
    return null;
  }
  // Strict field whitelist — strip any extra smuggled keys.
  return {
    v: 1,
    suite: HUMAN_DRAFT_SUITE,
    recipientKid: rawDraft.recipientKid,
    enc: rawDraft.enc,
    ct: rawDraft.ct,
  };
}

export function parseFragmentString(rawHash) {
  const hash = typeof rawHash === "string" ? rawHash.replace(/^#/, "").trim() : "";
  if (!hash) {
    return { mode: "landing" };
  }
  if (hash.startsWith("enroll=")) {
    const encoded = hash.slice("enroll=".length);
    const data = JSON.parse(utf8String(base64urlDecode(encoded)));
    if (!data || typeof data !== "object") {
      throw new Error("Enrollment payload must be a JSON object");
    }
    return { mode: "enroll", payload: data };
  }
  const encoded = hash.startsWith("drop=") ? hash.slice("drop=".length) : hash;
  const raw = JSON.parse(utf8String(base64urlDecode(encoded)));
  if (!raw || typeof raw !== "object") {
    throw new Error("Drop invite fragment must be a JSON object");
  }
  // Deliberately whitelist fields — HARD-IGNORE plaintext `proposedText`, `draft`, `summary`, `action`, or `body`!
  // Accept HPKE `encDraft` ONLY on `kind === "directive"` and `approval` ONLY on `kind === "approval"`.
  if (raw.v !== 1) {
    throw new Error(`Unsupported drop invite version: ${raw.v}`);
  }
  if (raw.kind !== "directive" && raw.kind !== "secret" && raw.kind !== "approval") {
    throw new Error(`Unsupported drop kind: ${raw.kind}`);
  }
  if (typeof raw.nodeId !== "string" || raw.nodeId.trim().length === 0) {
    throw new Error("Drop invite is missing target nodeId");
  }
  decodeOkpJwkBytes(raw.encJwk, "X25519");

  let relay = "";
  if (typeof raw.relay === "string" && raw.relay.trim().length > 0) {
    if (!isAllowedRelayUrl(raw.relay.trim())) {
      throw new Error("Drop Relay URL must use https:// (or loopback http://127.0.0.1)");
    }
    relay = raw.relay.trim().replace(/\/+$/, "");
  }

  let expiresAtMs = null;
  if (typeof raw.expiresAt === "string" && raw.expiresAt.length > 0) {
    const parsed = Date.parse(raw.expiresAt);
    if (!Number.isFinite(parsed)) {
      throw new Error("Drop invite expiresAt is not a valid timestamp");
    }
    expiresAtMs = parsed;
  }

  const encDraft = raw.kind === "directive" ? parseOptionalEncDraft(raw.encDraft) : null;
  // An approval link names the exact action to sign. It is validated here and shown from its
  // signed fields only; the node rejects a signature over anything but the action it requested.
  let approval = null;
  if (raw.kind === "approval") {
    approval = validateApprovalAction(raw.approval);
    if (approval.nodeId !== raw.nodeId) {
      throw new Error("Approval link action targets a different node than the link itself");
    }
  }

  const fragment = {
    v: 1,
    dropId: typeof raw.dropId === "string" ? raw.dropId : "",
    relay,
    postCap: typeof raw.postCap === "string" ? raw.postCap : "",
    nodeId: raw.nodeId.trim(),
    handle: typeof raw.handle === "string" ? raw.handle.trim() : "",
    encJwk: { kty: "OKP", crv: "X25519", x: raw.encJwk.x },
    nodeCert: raw.nodeCert ?? null,
    kind: raw.kind,
    secretName: typeof raw.secretName === "string" ? raw.secretName.trim() : "",
    // Non-authoritative UI cue ONLY (H15): NEVER auto-checks overwrite!
    secretExists: raw.kind === "secret" && raw.secretExists === true,
    expiresAt: typeof raw.expiresAt === "string" ? raw.expiresAt : "",
    expiresAtMs,
    humanId: typeof raw.humanId === "string" ? raw.humanId.trim() : "",
    prfSalt: typeof raw.prfSalt === "string" ? raw.prfSalt.trim() : "",
    authEpoch: Number.isInteger(raw.authEpoch) && raw.authEpoch >= 1 ? raw.authEpoch : null,
    encDraft,
    approval,
  };

  return { mode: "drop", fragment };
}

function peekNodeCertMeta(nodeCert) {
  try {
    let signed = nodeCert;
    if (typeof nodeCert === "string" && nodeCert.startsWith("hcert1_")) {
      signed = JSON.parse(utf8String(base64urlDecode(nodeCert.slice("hcert1_".length))));
    }
    if (signed && typeof signed.payload === "string") {
      const cert = JSON.parse(signed.payload);
      return {
        humanId: typeof cert.humanId === "string" ? cert.humanId : "",
        authEpoch: Number.isInteger(cert.authEpoch) && cert.authEpoch >= 1 ? cert.authEpoch : null,
        prfSalt: typeof cert.prfSalt === "string" ? cert.prfSalt : "",
      };
    }
  } catch {
    // Untrusted hint peek; full cryptographic check happens after Passkey unlock.
  }
  return { humanId: "", authEpoch: null, prfSalt: "" };
}

function formatRelayDisplay(relayUrl, hasRelay) {
  if (!hasRelay || !relayUrl) {
    return { host: "Offline", tag: "", tagClass: "", origin: "" };
  }
  try {
    const u = new URL(relayUrl);
    const host = u.host;
    if (u.origin === "https://spore.hyphae.to" || u.origin === "https://public.hyphae.to") {
      return { host, tag: "Public", tagClass: "public", origin: u.origin };
    }
    if (u.hostname === "127.0.0.1" || u.hostname === "localhost") {
      return { host, tag: "Direct", tagClass: "direct", origin: u.origin };
    }
    return { host, tag: "Relay", tagClass: "relay", origin: u.origin };
  } catch {
    return { host: "Offline", tag: "", tagClass: "", origin: "" };
  }
}

// ============================================================================
// Non-Secret Local Hint Storage (Only stores public humanId/prfSalt/credId)
// ============================================================================

function savePublicHint(humanId, hint) {
  try {
    const clean = {
      humanId,
      prfSalt: hint.prfSalt || "",
      authEpoch: hint.authEpoch || 1,
      credentialId: hint.credentialId || "",
    };
    localStorage.setItem(HINT_STORAGE_PREFIX + humanId, JSON.stringify(clean));
    localStorage.setItem(HINT_STORAGE_PREFIX + "__last__", humanId);
  } catch {
    // Storage disabled or evicted by ITP — safely ignored.
  }
}

function loadPublicHint(humanId) {
  try {
    const target = humanId || localStorage.getItem(HINT_STORAGE_PREFIX + "__last__") || "";
    if (!target) return null;
    const raw = localStorage.getItem(HINT_STORAGE_PREFIX + target);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ============================================================================
// WebAuthn Passkey + PRF Operations
// ============================================================================

export function coerceBytes(value) {
  return readPasskeyBytes(value, true);
}

export function extractPrfFirst(credential) {
  return readPasskeyPrfFirst(credential, true);
}

const { evaluatePasskeyPrf, enrollPasskeyWithPrf } = createPasskeyOperations({
  rpName: "Hyphae Verified Drops",
  missingPrfMessage:
    "Your authenticator did not return a WebAuthn PRF secret. Use Safari 18+, Chrome, or Edge with a PRF-capable Passkey (iCloud Keychain / Google Password Manager).",
  allowSerializedBytes: true,
});

// ============================================================================
// Browser UI Helpers
// ============================================================================

function $(id) {
  return document.getElementById(id);
}

function setBanner(el, titleEl, bodyEl, variant, title, body) {
  el.className = `banner ${variant}`;
  titleEl.textContent = title;
  bodyEl.textContent = body;
}

function clearBanner(el) {
  el.classList.add("hidden");
}

function formatCountdown(msRemaining) {
  if (msRemaining <= 0) return "EXPIRED";
  const totalSec = Math.ceil(msRemaining / 1000);
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  return `${mins}m ${String(secs).padStart(2, "0")}s`;
}

function formatLocalTime(date) {
  try {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return date.toISOString().slice(11, 19) + " UTC";
  }
}

function copyText(text, btn, idleLabel) {
  return copyBrowserText(text, btn, idleLabel, { timeoutMs: 2000, fallbackLabel: "Select & Copy Above" });
}

function autoSizeTextarea(el) {
  if (!el) return;
  el.style.height = "auto";
  const nextHeight = Math.max(el.scrollHeight + 2, 108);
  el.style.height = `${nextHeight}px`;
}

function formatDirectiveStats(text) {
  const charCount = [...text].length;
  const lineCount = text.length === 0 ? 0 : text.split("\n").length;
  return `${charCount} ${charCount === 1 ? "char" : "chars"} · ${lineCount} ${lineCount === 1 ? "line" : "lines"}`;
}

// ============================================================================
// App Entry Point
// ============================================================================

function initBrowserApp() {
  // 0. Immediately capture and scrub URL #fragment before any other work!
  const rawHash = window.location.hash;
  if (rawHash) {
    try {
      history.replaceState(null, "", window.location.pathname);
    } catch {
      // Ignore in restricted history contexts.
    }
  }

  // 1. Fail-closed frame-busting defense against clickjacking:
  //    `<meta http-equiv="Content-Security-Policy">` cannot enforce `frame-ancestors 'none'`.
  if (isEmbeddedInFrame(window)) {
    for (const id of ["viewLanding", "viewDrop", "viewEnroll"]) {
      const el = $(id);
      if (el) {
        el.classList.add("hidden");
        el.remove();
      }
    }
    const errView = $("viewError");
    if (errView) {
      const titleEl = errView.querySelector(".hero-title");
      if (titleEl) titleEl.textContent = "Embedded Frame Blocked";
      const strongEl = errView.querySelector(".banner strong");
      if (strongEl) strongEl.textContent = "Clickjacking Protection";
      const msgEl = $("errorMessage");
      if (msgEl) {
        msgEl.textContent =
          "For your security, Hyphae Verified Drops cannot be opened inside an embedded frame or iframe. Open this link directly in a top-level browser tab.";
      }
      errView.classList.remove("hidden");
    } else if (document.body) {
      document.body.textContent =
        "Security error: Hyphae Verified Drops cannot run inside an embedded frame.";
    }
    try {
      if (window.top && window.top.location) {
        window.top.location.href = window.location.href;
      }
    } catch {
      // Cross-origin parent frame — stay halted with interactive UI removed.
    }
    return;
  }

  let parsed;
  try {
    parsed = parseFragmentString(rawHash);
  } catch (err) {
    $("viewError").classList.remove("hidden");
    $("errorMessage").textContent = err instanceof Error ? err.message : "Invalid link fragment";
    return;
  }

  if (parsed.mode === "landing") {
    $("viewLanding").classList.remove("hidden");
    return;
  }

  if (parsed.mode === "enroll") {
    initEnrollMode(parsed.payload);
    return;
  }

  initDropMode(parsed.fragment);
}

// ============================================================================
// Enroll Mode (#enroll=...)
// ============================================================================

function initEnrollMode(payload) {
  $("viewEnroll").classList.remove("hidden");

  const humanId = typeof payload.humanId === "string" && payload.humanId.trim()
    ? payload.humanId.trim()
    : "operator";
  const authEpoch = Number.isInteger(payload.authEpoch) && payload.authEpoch >= 1
    ? payload.authEpoch
    : 1;
  const prfSalt = typeof payload.prfSalt === "string" && payload.prfSalt.trim()
    ? payload.prfSalt.trim()
    : base64urlEncode(randomBytes(16));
  const callbackUrl = isLoopbackCallbackUrl(payload.callbackUrl) ? payload.callbackUrl : "";
  const csrfToken = typeof payload.csrfToken === "string" ? payload.csrfToken : "";

  $("enrollHumanId").textContent = humanId;
  $("enrollAuthEpoch").textContent = String(authEpoch);
  $("enrollPrfSalt").textContent = prfSalt;
  $("enrollRpId").textContent = getRpId() || window.location.hostname || "localhost";

  let lastBundleJson = "";

  function showEnrollCompleteState() {
    $("enrollStageStart").classList.add("hidden");
    $("enrollFallbackBlock").classList.add("hidden");
    $("enrollDoneHero").classList.remove("hidden");
    $("enrollResultBlock").classList.remove("hidden");
    $("enrollKeysDrawer").open = false;
  }

  function showEnrollManualFallback(bannerTone, title, body, showRetry) {
    $("enrollStageStart").classList.add("hidden");
    $("enrollDoneHero").classList.add("hidden");
    $("enrollBundleBox").textContent = lastBundleJson;
    $("enrollFallbackBlock").classList.remove("hidden");
    $("enrollResultBlock").classList.remove("hidden");
    $("enrollKeysDrawer").open = false;

    const retryBtn = $("btnSendEnrollCallback");
    if (showRetry && callbackUrl) {
      retryBtn.classList.remove("hidden");
      retryBtn.disabled = false;
      $("enrollRetrySpinner").classList.add("hidden");
      $("btnSendEnrollCallbackLabel").textContent = "Retry Send to Local hyp CLI";
    } else {
      retryBtn.classList.add("hidden");
    }

    setBanner(
      $("enrollFallbackBanner"),
      $("enrollFallbackBannerTitle"),
      $("enrollFallbackBannerBody"),
      bannerTone,
      title,
      body
    );
  }

  async function postEnrollToLocalCli() {
    if (!callbackUrl || !lastBundleJson) return false;
    const headers = { "Content-Type": "application/json" };
    if (csrfToken) headers["X-Hyphae-CSRF"] = csrfToken;
    const resp = await fetch(callbackUrl, {
      method: "POST",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers,
      body: lastBundleJson,
    });
    if (!resp.ok) {
      throw new Error(`Local CLI callback returned HTTP ${resp.status}`);
    }
    return true;
  }

  $("btnEnrollPasskey").addEventListener("click", async () => {
    const btn = $("btnEnrollPasskey");
    const label = $("btnEnrollPasskeyLabel");
    const spinner = $("enrollSpinner");
    btn.disabled = true;
    spinner.classList.remove("hidden");
    label.textContent = "Waiting for Face ID / Touch ID…";
    clearBanner($("enrollErrorBanner"));

    let prfOut = null;
    let seed = null;
    let encKp = null;
    let derivedOk = false;
    try {
      const enrolled = await enrollPasskeyWithPrf(humanId, prfSalt);
      prfOut = enrolled.prfOut;
      seed = await derivePrfEd25519Seed(prfOut, humanId, authEpoch);
      const { publicKeyBytes, publicJwk, kid } = await ed25519KeypairFromSeed(seed);
      encKp = await derivePrfX25519Keypair(prfOut, humanId, authEpoch);

      const sas = await sasFingerprint(publicKeyBytes);
      const encSas = await sasFingerprint(encKp.publicKeyBytes);

      savePublicHint(humanId, {
        prfSalt,
        authEpoch,
        credentialId: enrolled.credentialId,
      });

      let nodeCert = null;
      const enrollNodeId = typeof payload.nodeId === "string" ? payload.nodeId.trim() : "";
      const enrollSignJwk = payload.nodeSignJwk || payload.signingJwk || null;
      const enrollEncJwk = payload.nodeEncJwk || payload.encryptionJwk || null;
      if (enrollNodeId && enrollSignJwk && enrollEncJwk) {
        const nowMs = Date.now();
        const certRes = await signNodeCert(
          {
            nodeId: enrollNodeId,
            signingJwk: enrollSignJwk,
            encryptionJwk: enrollEncJwk,
            humanId,
            humanKid: kid,
            authEpoch,
            issuedAt: new Date(nowMs).toISOString(),
            expiresAt: new Date(nowMs + 365 * 24 * 60 * 60 * 1000).toISOString(),
          },
          seed
        );
        nodeCert = certRes.hcert1;
      }

      const bundle = {
        v: 1,
        humanId,
        kid,
        authEpoch,
        prfSalt,
        jwk: publicJwk,
        encJwk: encKp.publicJwk,
        encKid: encKp.kid,
        credentialId: enrolled.credentialId,
        rpId: enrolled.rpId,
        ...(nodeCert ? { nodeCert } : {}),
      };
      lastBundleJson = JSON.stringify(bundle, null, 2);

      $("enrollKid").textContent = kid;
      $("enrollFingerprint").textContent = `${sas.formatted} · ${sas.phrase}`;
      $("enrollEncKid").textContent = encKp.kid;
      $("enrollEncFingerprint").textContent = `${encSas.formatted} · ${encSas.phrase}`;
      derivedOk = true;
    } catch (err) {
      setBanner(
        $("enrollErrorBanner"),
        $("enrollErrorBannerTitle"),
        $("enrollErrorBannerBody"),
        "danger",
        "Enrollment Failed",
        err instanceof Error ? err.message : "Could not enroll Passkey"
      );
      label.textContent = "Create Passkey & Enroll";
    } finally {
      if (prfOut) zeroize(prfOut);
      if (seed) zeroize(seed);
      if (encKp && encKp.privateKeyBytes) zeroize(encKp.privateKeyBytes);
      if (!derivedOk) {
        spinner.classList.add("hidden");
        btn.disabled = false;
      }
    }

    if (!derivedOk) return;

    if (callbackUrl) {
      label.textContent = "Sending to local hyp CLI…";
      try {
        await postEnrollToLocalCli();
        showEnrollCompleteState();
      } catch (err) {
        showEnrollManualFallback(
          "warn",
          "Could Not Reach Local hyp CLI",
          `${err instanceof Error ? err.message : "Failed to reach loopback CLI"} — retry below, or copy this public bundle into your terminal setup.`,
          true
        );
      } finally {
        spinner.classList.add("hidden");
      }
    } else {
      spinner.classList.add("hidden");
      showEnrollManualFallback(
        "verified",
        "Passkey Enrolled — Copy to Laptop",
        "Public Ed25519 + X25519 keys derived cleanly (ephemeral seeds wiped). Copy the bundle below into `hyp auth add` on your laptop.",
        false
      );
    }
  });

  $("btnCopyEnrollBundle").addEventListener("click", () => {
    if (lastBundleJson) {
      copyText(lastBundleJson, $("btnCopyEnrollBundle"), "Copy Public JWKs & Salt");
    }
  });

  $("btnSendEnrollCallback").addEventListener("click", async () => {
    if (!callbackUrl || !lastBundleJson) return;
    const btn = $("btnSendEnrollCallback");
    const label = $("btnSendEnrollCallbackLabel");
    const spinner = $("enrollRetrySpinner");
    btn.disabled = true;
    spinner.classList.remove("hidden");
    label.textContent = "Sending to local hyp CLI…";
    try {
      await postEnrollToLocalCli();
      showEnrollCompleteState();
    } catch (err) {
      showEnrollManualFallback(
        "warn",
        "Could Not Reach Local hyp CLI",
        `${err instanceof Error ? err.message : "Failed to reach loopback CLI"} — copy the Public JWKs & Salt above into your terminal setup instead.`,
        true
      );
    } finally {
      spinner.classList.add("hidden");
    }
  });
}

// ============================================================================
// Drop Mode (#drop=...) — 3-Stage Focused Stepper
// ============================================================================

function approvalActionHeading(actionKind) {
  switch (actionKind) {
    case "gate.apply":
      return "Apply Security Gate Policy";
    case "gate.lock":
      return "Lock Security Gate";
    case "gate.unlock":
      return "Unlock Security Gate";
    case "gate.remove":
      return "Remove Security Gate Filter";
    case "auth.admit":
      return "Admit Human and Device Policy";
    case "auth.add":
      return "Enroll Human Authority";
    case "auth.revoke":
      return "Revoke Human Authority";
    default:
      return "Security Approval";
  }
}

function isApprovalWeakening(action) {
  return Boolean(action) && (action.action === "gate.unlock" || action.action === "gate.remove");
}

async function initDropMode(fragment) {
  $("viewDrop").classList.remove("hidden");

  const isSecret = fragment.kind === "secret";
  const isApproval = fragment.kind === "approval";
  const hasRelay = Boolean(fragment.relay && fragment.dropId && fragment.postCap);
  const relayDisplay = formatRelayDisplay(fragment.relay, hasRelay);

  // Ephemeral RAM state (strictly wiped on send, lock, skip, pagehide, or hidden tab)
  const state = {
    stage: "locked", // "locked" | "unlocked" | "done"
    unlockedEdSeed: null,
    humanId: "",
    authEpoch: 1,
    certVerified: false,
    certReason: "",
    hardBlocked: false,
    expired: false,
    sealing: false,
    delivered: false,
    activeEncDraft: !isSecret && !isApproval && fragment.encDraft ? fragment.encDraft : null,
    activeApproval: isApproval ? fragment.approval : null,
    approvalAction: null,
    draftLoaded: false,
    lastHdrop1: "",
    lastEnvelopeJson: "",
  };

  // --- Context Strip Initial Render ---
  $("metaNodeId").textContent = fragment.nodeId;
  if (fragment.handle) {
    $("metaHandlePill").textContent = fragment.handle;
    $("metaHandlePill").classList.remove("hidden");
  }

  const kindBadge = $("dropKindBadge");
  kindBadge.textContent = isSecret
    ? "SECRET DROP"
    : (isApproval ? "SECURITY APPROVAL" : "DIRECTIVE");
  kindBadge.className = `kind-label ${isSecret ? "secret" : (isApproval ? "approval" : "directive")}`;

  $("metaRelayHost").textContent = relayDisplay.host;
  if (relayDisplay.tag) {
    $("metaRelayTag").textContent = relayDisplay.tag;
    $("metaRelayTag").className = `relay-tag ${relayDisplay.tagClass}`;
    $("metaRelayTag").classList.remove("hidden");
  }
  if (relayDisplay.origin) {
    $("drawerRelayUrl").textContent = relayDisplay.origin;
    $("drawerRelayRow").classList.remove("hidden");
  }

  function setCertBadge(variant, text) {
    const el = $("metaCertBadge");
    el.className = `cert-badge ${variant}`;
    el.textContent = text;
  }

  if (fragment.nodeCert) {
    setCertBadge("pending", "Cert pending");
    $("metaCertHint").textContent = "Cert attached · verifies on unlock";
  } else {
    setCertBadge("warn", "⚠ Uncertified");
    $("metaCertHint").textContent = "No NodeCert attached";
    $("securityDrawer").open = true;
  }

  if (isSecret) {
    $("metaSecretStrip").classList.remove("hidden");
    $("metaSecretName").textContent = fragment.secretName || "(missing)";
  }

  // --- Validate secret name & reserved system-key denylist up front ---
  if (isSecret) {
    const nameCheck = validateSecretName(fragment.secretName);
    if (!nameCheck.ok) {
      state.hardBlocked = true;
      $("metaSecretStrip").classList.add("danger");
      setBanner(
        $("dropGlobalBanner"),
        $("dropGlobalBannerTitle"),
        $("dropGlobalBannerBody"),
        "danger",
        "Invalid Secret Name — Blocked",
        nameCheck.message
      );
    } else if (isReservedSecretName(fragment.secretName)) {
      state.hardBlocked = true;
      $("metaSecretStrip").classList.add("danger");
      setBanner(
        $("dropGlobalBanner"),
        $("dropGlobalBannerTitle"),
        $("dropGlobalBannerBody"),
        "danger",
        "Reserved System Secret — Blocked",
        `"${fragment.secretName}" targets an internal Hyphae system key and is permanently blocked.`
      );
    }

    // H15: Always start with Overwrite unchecked (fail-closed human opt-in);
    // display a non-authoritative amber cue only when fragment.secretExists === true.
    $("chkOverwriteSecret").checked = false;
    const hintEl = $("secretExistsHint");
    if (hintEl) {
      if (fragment.secretExists && !state.hardBlocked) {
        const nameCode = document.createElement("code");
        nameCode.textContent = fragment.secretName;
        const nodeCode = document.createElement("code");
        nodeCode.textContent = fragment.nodeId;
        hintEl.textContent = "";
        hintEl.append(
          document.createTextNode("A secret named "),
          nameCode,
          document.createTextNode(" already exists on "),
          nodeCode,
          document.createTextNode(" — check Overwrite to replace it.")
        );
        hintEl.classList.remove("hidden");
      } else {
        hintEl.textContent = "";
        hintEl.classList.add("hidden");
      }
    }
  }

  // --- Render Target X25519 SAS Fingerprint ---
  const sas = await sasFingerprint(fragment.encJwk);
  $("sasHex").textContent = sas.formatted;
  $("sasWords").textContent = sas.phrase;
  $("securityDrawerPreview").textContent = sas.formatted.slice(0, 9) + "…";
  $("sasConfirmText").textContent =
    `I manually verified SAS fingerprint ${sas.formatted} (${sas.phrase}) on ${fragment.nodeId} and accept sending this directive to an uncertified key.`;

  // --- Populate Authority Parameters ---
  const certMeta = peekNodeCertMeta(fragment.nodeCert);
  const savedHint = loadPublicHint(fragment.humanId || certMeta.humanId);
  const initialHumanId = fragment.humanId || certMeta.humanId || savedHint?.humanId || "";
  const initialPrfSalt = fragment.prfSalt || certMeta.prfSalt || savedHint?.prfSalt || "";
  const initialEpoch = fragment.authEpoch || certMeta.authEpoch || savedHint?.authEpoch || 1;

  $("inputHumanId").value = initialHumanId;
  $("inputPrfSalt").value = initialPrfSalt;
  $("inputAuthEpoch").value = String(initialEpoch);

  function updateIdentitySummary() {
    const h = $("inputHumanId").value.trim();
    const s = $("inputPrfSalt").value.trim();
    const e = $("inputAuthEpoch").value.trim();
    const ok = Boolean(h && s);
    $("identitySummaryText").textContent = ok ? `${h} · epoch ${e || 1}` : "Needs humanId & salt";
    if (!ok) {
      $("securityDrawerPreview").textContent = "Needs setup";
    } else {
      $("securityDrawerPreview").textContent = sas.formatted.slice(0, 9) + "…";
    }
  }
  updateIdentitySummary();
  if (!initialHumanId || !initialPrfSalt) {
    $("securityDrawer").open = true;
  }
  $("inputHumanId").addEventListener("input", updateIdentitySummary);
  $("inputPrfSalt").addEventListener("input", updateIdentitySummary);
  $("inputAuthEpoch").addEventListener("input", updateIdentitySummary);

  // --- Stepper & Stage Transitions ---
  function updateStepper(stage) {
    const s1 = $("stepDot1");
    const s2 = $("stepDot2");
    const s3 = $("stepDot3");

    $("stepDot2Label").textContent = isSecret
      ? "Secret"
      : (isApproval || state.activeEncDraft || state.draftLoaded ? "Review" : "Write");

    if (stage === "locked") {
      s1.className = "step-pill active";
      s2.className = "step-pill";
      s3.className = "step-pill";
    } else if (stage === "unlocked") {
      s1.className = "step-pill done";
      s2.className = "step-pill active";
      s3.className = "step-pill";
    } else {
      s1.className = "step-pill done";
      s2.className = "step-pill done";
      s3.className = "step-pill done";
    }
  }

  function renderLockedCopy() {
    const hasDraft = Boolean(state.activeEncDraft && !isSecret && !isApproval);
    if (isApproval) {
      $("lockedTitle").textContent = "Unlock Security Approval";
      $("lockedSubtitle").textContent =
        `Authenticate with Face ID / Touch ID to verify ${fragment.nodeId} and decrypt the requested security action.`;
      $("btnUnlockPrimaryLabel").textContent = "Unlock Approval with Face ID / Touch ID";
      $("btnSkipDraft").classList.add("hidden");
    } else if (hasDraft) {
      $("lockedTitle").textContent = "Unlock Proposed Directive";
      $("lockedSubtitle").textContent =
        `Authenticate with Face ID / Touch ID to verify ${fragment.nodeId} and decrypt the agent's draft.`;
      $("btnUnlockPrimaryLabel").textContent = "Unlock Draft with Face ID / Touch ID";
      $("btnSkipDraft").classList.remove("hidden");
    } else if (isSecret) {
      $("lockedTitle").textContent = "Unlock to Deliver Secret";
      $("lockedSubtitle").textContent =
        `Verify ${fragment.nodeId} with Face ID / Touch ID before entering ${fragment.secretName || "this secret"}.`;
      $("btnUnlockPrimaryLabel").textContent = "Unlock with Face ID / Touch ID";
      $("btnSkipDraft").classList.add("hidden");
    } else {
      $("lockedTitle").textContent = "Unlock to Sign Directive";
      $("lockedSubtitle").textContent =
        `Authenticate with Face ID / Touch ID to verify ${fragment.nodeId}.`;
      $("btnUnlockPrimaryLabel").textContent = "Unlock with Face ID / Touch ID";
      $("btnSkipDraft").classList.add("hidden");
    }
  }

  function showStage(stage) {
    state.stage = stage;
    $("stageLocked").classList.toggle("hidden", stage !== "locked");
    $("stageUnlocked").classList.toggle("hidden", stage !== "unlocked");
    $("stageDone").classList.toggle("hidden", stage !== "done");
    if (stage !== "done") {
      $("viewDrop").classList.remove("is-delivered", "is-offline-done");
    }
    updateStepper(stage);
  }

  function supportsCssSecretMask() {
    return (
      typeof CSS !== "undefined" &&
      typeof CSS.supports === "function" &&
      CSS.supports("-webkit-text-security", "disc")
    );
  }

  function setSecretInputMasked(masked) {
    const inp = $("inputSecretValue");
    if (supportsCssSecretMask()) {
      inp.type = "text";
      inp.classList.toggle("secret-masked", masked);
    } else {
      inp.classList.remove("secret-masked");
      inp.type = masked ? "password" : "text";
    }
    inp.dataset.masked = masked ? "1" : "0";
    $("btnToggleReveal").textContent = masked ? "Reveal" : "Hide";
  }

  function wipeSecretRam({ clearDraft = false, clearSealed = false } = {}) {
    if (state.unlockedEdSeed) {
      zeroize(state.unlockedEdSeed);
      state.unlockedEdSeed = null;
    }
    state.certVerified = false;
    state.draftLoaded = false;
    state.approvalAction = null;
    if (clearDraft) {
      state.activeEncDraft = null;
    }
    if (clearSealed) {
      state.lastHdrop1 = "";
      state.lastEnvelopeJson = "";
    }
    $("inputSecretValue").value = "";
    $("inputDirectiveValue").value = "";
    $("inputDirectiveValue").style.height = "";
    setSecretInputMasked(true);
    $("chkOverwriteSecret").checked = false;
    $("draftApproveCheck").checked = false;
    $("approvalConfirmCheck").checked = false;
    $("chkManualSasConfirm").checked = false;
    $("draftWarningBanner").classList.add("hidden");
    $("draftContextRow").classList.add("hidden");
    $("draftContextText").textContent = "";
    $("draftApproveRow").classList.add("hidden");
    $("approvalReviewGroup").classList.add("hidden");
    $("approvalWeakeningBanner").classList.add("hidden");
    $("approvalMetaList").textContent = "";
    $("sasConfirmRow").classList.add("hidden");
    clearBanner($("uncertifiedBanner"));
    clearBanner($("sealActionBanner"));
  }

  function lockAndResetUi({ clearDraft = false, keepUnlockBanner = false } = {}) {
    wipeSecretRam({ clearDraft });
    if (!keepUnlockBanner) {
      clearBanner($("unlockBanner"));
    }
    if (fragment.nodeCert) {
      setCertBadge("pending", "Cert pending");
      $("metaCertHint").textContent = "Cert attached · verifies on unlock";
    } else {
      setCertBadge("warn", "⚠ Uncertified");
      $("metaCertHint").textContent = "No NodeCert attached";
    }
    renderLockedCopy();
    showStage("locked");
    syncSealControls();
  }

  // --- Lifecycle Memory-Wipe Hooks ---
  window.addEventListener("pagehide", () => wipeSecretRam({ clearDraft: true, clearSealed: true }));
  window.addEventListener("beforeunload", () => wipeSecretRam({ clearDraft: true, clearSealed: true }));
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden" && (state.unlockedEdSeed || state.draftLoaded)) {
      lockAndResetUi({ clearDraft: false });
    }
  });
  window.addEventListener("resize", () => {
    if (state.stage === "unlocked" && !isSecret && !$("directiveInputGroup").classList.contains("hidden")) {
      autoSizeTextarea($("inputDirectiveValue"));
    }
  });

  // --- Live Expiration Countdown ---
  function refreshExpiry() {
    if (state.delivered || state.sealing) return;
    const pill = $("metaExpires");
    if (!fragment.expiresAtMs) {
      pill.textContent = "10m on seal";
      pill.className = "expiry-text";
      return;
    }
    const rem = fragment.expiresAtMs - Date.now();
    pill.textContent = formatCountdown(rem);
    if (rem <= 0) {
      pill.className = "expiry-text danger";
      if (!state.expired) {
        state.expired = true;
        setBanner(
          $("dropGlobalBanner"),
          $("dropGlobalBannerTitle"),
          $("dropGlobalBannerBody"),
          "danger",
          "Drop Link Expired",
          "This drop invitation has expired. Request a fresh drop link from your node."
        );
        if (state.stage === "unlocked") {
          lockAndResetUi({ clearDraft: true });
        } else {
          syncSealControls();
        }
      }
    } else if (rem <= 2 * 60 * 1000) {
      pill.className = "expiry-text warn";
    } else {
      pill.className = "expiry-text";
    }
  }
  refreshExpiry();
  const countdownTimer = setInterval(refreshExpiry, 1000);
  window.addEventListener("pagehide", () => clearInterval(countdownTimer));

  // --- Configure Primary vs Offline Action Buttons ---
  const primarySendLabel = isSecret
    ? "Seal & Send Secret"
    : (isApproval ? "Approve & Sign with Passkey" : "Sign, Seal & Send");
  if (hasRelay) {
    $("btnSealSendLabel").textContent = primarySendLabel;
  } else {
    $("btnSealSend").classList.add("hidden");
    $("btnSealOffline").className = "btn-primary";
    $("btnSealOffline").textContent = isApproval
      ? "Sign Offline Approval (hdrop1_)"
      : "Seal Offline hdrop1_ Token";
  }

  function syncSealControls() {
    const unlocked = Boolean(state.unlockedEdSeed);
    const allowedByCert = state.certVerified || (!isSecret && $("chkManualSasConfirm").checked);
    const canEdit = unlocked && !state.hardBlocked && !state.expired && allowedByCert;

    $("inputSecretValue").disabled = !canEdit;
    $("btnToggleReveal").disabled = !canEdit;
    $("chkOverwriteSecret").disabled = !canEdit;
    $("inputDirectiveValue").disabled = !canEdit;
    $("approvalConfirmCheck").disabled = !canEdit;
    $("btnUnlockPrimary").disabled = state.hardBlocked || state.expired;
    $("btnSkipDraft").disabled = state.hardBlocked || state.expired;

    let canSubmit;
    if (isApproval) {
      const actionReady = Boolean(state.approvalAction);
      const approved = $("approvalConfirmCheck").checked;
      canSubmit = canEdit && actionReady && approved;
    } else {
      const activeVal = isSecret ? $("inputSecretValue").value : $("inputDirectiveValue").value;
      const byteLen = utf8Bytes(activeVal).length;
      const maxBodyBytes = MAX_PADDED_PLAINTEXT - 1024;
      if (isSecret) {
        $("secretByteCount").textContent = `${byteLen} B`;
      } else {
        $("directiveByteCount").textContent = formatDirectiveStats(activeVal);
      }
      const draftApproved = !state.draftLoaded || $("draftApproveCheck").checked;
      canSubmit = canEdit && draftApproved && byteLen > 0 && byteLen <= maxBodyBytes;
    }

    $("btnSealSend").disabled = !canSubmit || !hasRelay;
    $("btnSealOffline").disabled = !canSubmit;
  }

  // Initial Locked Render
  renderLockedCopy();
  showStage("locked");
  syncSealControls();

  $("inputSecretValue").addEventListener("input", syncSealControls);
  $("inputDirectiveValue").addEventListener("input", () => {
    autoSizeTextarea($("inputDirectiveValue"));
    syncSealControls();
  });
  $("chkManualSasConfirm").addEventListener("change", syncSealControls);
  $("draftApproveCheck").addEventListener("change", syncSealControls);
  $("approvalConfirmCheck").addEventListener("change", syncSealControls);

  $("btnToggleReveal").addEventListener("click", () => {
    const inp = $("inputSecretValue");
    const currentlyMasked = inp.dataset.masked !== "0";
    setSecretInputMasked(!currentlyMasked);
  });

  $("btnLockClear").addEventListener("click", () => {
    lockAndResetUi({ clearDraft: false });
  });

  $("btnSkipDraft").addEventListener("click", () => {
    lockAndResetUi({ clearDraft: true });
  });

  function readAuthorityInputs() {
    const humanId = $("inputHumanId").value.trim();
    const prfSalt = $("inputPrfSalt").value.trim();
    const authEpoch = parseInt($("inputAuthEpoch").value, 10);

    if (!humanId || !prfSalt || !Number.isInteger(authEpoch) || authEpoch < 1) {
      $("securityDrawer").open = true;
      setBanner(
        $("unlockBanner"),
        $("unlockBannerTitle"),
        $("unlockBannerBody"),
        "warn",
        "Missing Authority Parameters",
        "Enter your Human ID, PRF Salt, and Auth Epoch in the Security drawer above before unlocking."
      );
      return null;
    }
    return { humanId, prfSalt, authEpoch };
  }

  function applyCertVerificationResult(certRes, edSeed, humanId, authEpoch) {
    if (certRes.ok) {
      state.unlockedEdSeed = edSeed;
      state.humanId = humanId;
      state.authEpoch = authEpoch;
      state.certVerified = true;
      state.certReason = "";
      setCertBadge("verified", "✓ Verified");
      $("metaCertHint").textContent = `Verified by ${certRes.cert.humanId} (epoch ${certRes.cert.authEpoch})`;
      $("securityDrawer").open = false;
      $("verifiedStrip").className = "verified-strip verified";
      $("verifiedStripIcon").textContent = "✓";
      $("verifiedStripText").textContent = `Verified ${fragment.nodeId} · ${certRes.cert.humanId} (epoch ${certRes.cert.authEpoch})`;
      clearBanner($("uncertifiedBanner"));
      $("sasConfirmRow").classList.add("hidden");
      return true;
    }

    if (isSecret) {
      // HARD-BLOCK secrets on unverified nodes and immediately wipe seed!
      zeroize(edSeed);
      state.unlockedEdSeed = null;
      state.certVerified = false;
      state.hardBlocked = true;
      state.certReason = certRes.message;
      setCertBadge("danger", "⚠ Uncertified");
      $("metaCertHint").textContent = "Cert verification failed";
      $("securityDrawer").open = true;
      setBanner(
        $("unlockBanner"),
        $("unlockBannerTitle"),
        $("unlockBannerBody"),
        "danger",
        "Unverified Node — Secret Blocked",
        `${certRes.message}. Secret drops are hard-blocked unless the node holds a valid certificate signed by your Passkey.`
      );
      return false;
    }

    // Directive on unverified node: allow ONLY with prominent danger warning + auto-expanded SAS drawer + manual SAS checkbox.
    state.unlockedEdSeed = edSeed;
    state.humanId = humanId;
    state.authEpoch = authEpoch;
    state.certVerified = false;
    state.certReason = certRes.message;
    setCertBadge("danger", "⚠ Uncertified");
    $("metaCertHint").textContent = "UNVERIFIED NODE";
    $("securityDrawer").open = true;
    $("verifiedStrip").className = "verified-strip danger";
    $("verifiedStripIcon").textContent = "⚠";
    $("verifiedStripText").textContent = `Unverified ${fragment.nodeId} · ${humanId} (epoch ${authEpoch})`;
    setBanner(
      $("uncertifiedBanner"),
      $("uncertifiedBannerTitle"),
      $("uncertifiedBannerBody"),
      "danger",
      "Unverified Node Warning",
      `${certRes.message}. Compare the SAS fingerprint in the drawer above directly with ${fragment.nodeId} before confirming.`
    );
    $("sasConfirmRow").classList.remove("hidden");
    return true;
  }

  function appendApprovalMetaRow(listEl, keyText, valueText, titleText = "") {
    const row = document.createElement("div");
    row.className = "receipt-row";
    const dt = document.createElement("dt");
    dt.className = "meta-k";
    dt.textContent = keyText;
    const dd = document.createElement("dd");
    dd.className = "summary-v";
    dd.textContent = valueText;
    if (titleText) dd.title = titleText;
    row.append(dt, dd);
    listEl.append(row);
  }

  function renderApprovalReview(action) {
    const weakening = isApprovalWeakening(action);
    $("approvalActionTitle").textContent = approvalActionHeading(action.action);
    const codeBadge = $("approvalActionCode");
    codeBadge.textContent = action.action;
    codeBadge.className = weakening ? "approval-code weakening" : "approval-code";
    kindBadge.className = weakening ? "kind-label approval-weakening" : "kind-label approval";

    const warnBanner = $("approvalWeakeningBanner");
    if (weakening) {
      setBanner(
        warnBanner,
        $("approvalWeakeningTitle"),
        $("approvalWeakeningBody"),
        "danger",
        "Weakening Security Change",
        "This action weakens or unlocks Security Gate tamper protection. Approve it only if you asked for it."
      );
      $("approvalConfirmRow").className = "checkbox-row danger-confirm";
    } else {
      clearBanner(warnBanner);
      $("approvalConfirmRow").className = "checkbox-row warn-confirm";
    }

    const metaList = $("approvalMetaList");
    metaList.textContent = "";
    appendApprovalMetaRow(metaList, "Target Node", action.nodeId);
    appendApprovalMetaRow(metaList, "Permission", "This operation only; a fresh approval is required for every change.");
    if (action.parameters) {
      appendApprovalMetaRow(metaList, "Parameters", JSON.stringify(action.parameters, null, 2));
    }
    if (action.sealSeq > 0) {
      appendApprovalMetaRow(metaList, "Seal Sequence", `#${action.sealSeq}`);
    }
    if (action.policySha256) {
      appendApprovalMetaRow(
        metaList,
        "Policy SHA-256",
        `${action.policySha256.slice(0, 16)}…`,
        action.policySha256
      );
    }
    if (action.authoritiesDigest) {
      appendApprovalMetaRow(
        metaList,
        "Authorities Digest",
        `${action.authoritiesDigest.slice(0, 16)}…`,
        action.authoritiesDigest
      );
    }
    if (action.targetHumanId) {
      const rolePart = action.targetRole ? ` (${action.targetRole})` : "";
      appendApprovalMetaRow(metaList, "Target Human", `${action.targetHumanId}${rolePart}`);
    }
    if (action.targetKid) {
      appendApprovalMetaRow(
        metaList,
        "Target Kid",
        `${action.targetKid.slice(0, 16)}…`,
        action.targetKid
      );
    }
    if (action.bumpEpoch === true) {
      appendApprovalMetaRow(metaList, "Bump Auth Epoch", "Yes (monotonic)");
    }
    if (action.cascade === true) {
      appendApprovalMetaRow(metaList, "Cascade Peers", "Yes (revoke admitted peers)");
    }
  }

  function enterUnlockedStage({ draftPayload = null, approvalAction = null } = {}) {
    clearBanner($("unlockBanner"));
    clearBanner($("sealActionBanner"));

    if (isApproval && approvalAction) {
      state.approvalAction = approvalAction;
      state.draftLoaded = false;
      $("secretInputGroup").classList.add("hidden");
      $("directiveInputGroup").classList.add("hidden");
      $("draftWarningBanner").classList.add("hidden");
      $("draftContextRow").classList.add("hidden");
      $("draftApproveRow").classList.add("hidden");
      $("approvalConfirmCheck").checked = false;
      renderApprovalReview(approvalAction);
      $("approvalReviewGroup").classList.remove("hidden");
    } else if (isSecret) {
      $("approvalReviewGroup").classList.add("hidden");
      $("secretInputGroup").classList.remove("hidden");
      $("directiveInputGroup").classList.add("hidden");
      $("draftWarningBanner").classList.add("hidden");
      $("draftContextRow").classList.add("hidden");
      $("draftApproveRow").classList.add("hidden");
    } else if (draftPayload) {
      state.draftLoaded = true;
      $("approvalReviewGroup").classList.add("hidden");
      $("secretInputGroup").classList.add("hidden");
      $("directiveInputGroup").classList.remove("hidden");
      $("directiveFieldLabel").textContent = "Proposed Directive";
      $("draftWarningBanner").classList.remove("hidden");
      if (draftPayload.context) {
        $("draftContextText").textContent = draftPayload.context;
        $("draftContextRow").classList.remove("hidden");
      } else {
        $("draftContextText").textContent = "";
        $("draftContextRow").classList.add("hidden");
      }
      $("draftApproveCheck").checked = false;
      $("draftApproveRow").classList.remove("hidden");
      $("inputDirectiveValue").value = draftPayload.text;
    } else {
      state.draftLoaded = false;
      $("approvalReviewGroup").classList.add("hidden");
      $("secretInputGroup").classList.add("hidden");
      $("directiveInputGroup").classList.remove("hidden");
      $("directiveFieldLabel").textContent = "Verified Directive";
      $("draftWarningBanner").classList.add("hidden");
      $("draftContextRow").classList.add("hidden");
      $("draftApproveRow").classList.add("hidden");
    }

    showStage("unlocked");
    syncSealControls();

    if (!isSecret && !isApproval) {
      autoSizeTextarea($("inputDirectiveValue"));
    }
  }

  // --- Step 1: Unified Passkey Unlock (Handles approval, encDraft, & standard unlock) ---
  $("btnUnlockPrimary").addEventListener("click", async () => {
    if (state.hardBlocked || state.expired) return;

    const auth = readAuthorityInputs();
    if (!auth) return;

    const isDraftFlow = Boolean(state.activeEncDraft && !isSecret && !isApproval);
    const isApprovalFlow = Boolean(isApproval && state.activeApproval);
    const btn = $("btnUnlockPrimary");
    const label = $("btnUnlockPrimaryLabel");
    const spinner = $("unlockSpinner");
    btn.disabled = true;
    $("btnSkipDraft").disabled = true;
    spinner.classList.remove("hidden");
    label.textContent = isApprovalFlow
      ? "Unlocking security approval with Face ID / Touch ID…"
      : (isDraftFlow
        ? "Unlocking draft with Face ID / Touch ID…"
        : "Authenticating with Face ID / Touch ID…");
    clearBanner($("unlockBanner"));

    let prfOut = null;
    let encKp = null;
    let edSeed = null;
    let handedOffSeed = false;

    try {
      const hint = loadPublicHint(auth.humanId);
      const { prfOut: rawPrf, credentialId } = await evaluatePasskeyPrf(
        auth.humanId,
        auth.prfSalt,
        hint?.credentialId || ""
      );
      prfOut = rawPrf;

      let draftPayload = null;
      const approvalAction = isApprovalFlow ? state.activeApproval : null;
      if (isDraftFlow) {
        // Derive BOTH companion X25519 keypair and Ed25519 signing seed from the single PRF output.
        encKp = await derivePrfX25519Keypair(prfOut, auth.humanId, auth.authEpoch);
        edSeed = await derivePrfEd25519Seed(prfOut, auth.humanId, auth.authEpoch);

        try {
          draftPayload = await openHumanDraft({
            encDraft: state.activeEncDraft,
            recipientPriv32: encKp.privateKeyBytes,
            expectedNodeId: fragment.nodeId,
          });
        } finally {
          zeroize(encKp.privateKeyBytes);
          encKp = null;
        }
      } else {
        edSeed = await derivePrfEd25519Seed(prfOut, auth.humanId, auth.authEpoch);
      }

      const { publicKeyBytes } = await ed25519KeypairFromSeed(edSeed);
      savePublicHint(auth.humanId, {
        prfSalt: auth.prfSalt,
        authEpoch: auth.authEpoch,
        credentialId,
      });

      const certRes = await verifyNodeCert(
        fragment.nodeCert,
        publicKeyBytes,
        fragment.nodeId,
        fragment.encJwk,
        Date.now()
      );

      const allowed = applyCertVerificationResult(certRes, edSeed, auth.humanId, auth.authEpoch);
      if (allowed) {
        handedOffSeed = true;
        enterUnlockedStage({ draftPayload, approvalAction });
      }
    } catch (err) {
      setBanner(
        $("unlockBanner"),
        $("unlockBannerTitle"),
        $("unlockBannerBody"),
        "danger",
        isApprovalFlow
          ? "Approval Unlock Failed"
          : (isDraftFlow ? "Draft Unlock Failed" : "Passkey Unlock Failed"),
        isDraftFlow
          ? `${err instanceof Error ? err.message : "Could not unlock encrypted draft"}. Retry or skip the draft to write from scratch.`
          : (err instanceof Error ? err.message : "Could not unlock Passkey")
      );
    } finally {
      if (prfOut) zeroize(prfOut);
      if (encKp && encKp.privateKeyBytes) zeroize(encKp.privateKeyBytes);
      if (edSeed && !handedOffSeed) zeroize(edSeed);
      spinner.classList.add("hidden");
      renderLockedCopy();
      syncSealControls();
    }
  });

  // --- Relay Upload Helper (Used by Step 2 Send & Step 3 Retry) ---
  async function uploadSealedEnvelope(envelopeJson) {
    const endpoint = `${fragment.relay}/v1/drops/${encodeURIComponent(fragment.dropId)}`;
    const resp = await fetch(endpoint, {
      method: "POST",
      mode: "cors",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: {
        "Content-Type": "application/json",
        "X-Hyphae-Drop-Cap": fragment.postCap,
      },
      body: envelopeJson,
    });
    if (!resp.ok) {
      let detail = `Drop Relay responded with HTTP ${resp.status}`;
      try {
        const errJson = await resp.json();
        if (errJson && typeof errJson.error === "string" && errJson.error.trim()) {
          detail = `${errJson.error.trim()} (HTTP ${resp.status})`;
        }
      } catch {
        // Keep status message fallback.
      }
      throw new Error(detail);
    }
    return resp.json().catch(() => ({}));
  }

  function showDeliveredDoneState(ack, approvedActionName = "") {
    state.delivered = true;
    state.sealing = false;
    clearInterval(countdownTimer);
    clearBanner($("dropGlobalBanner"));
    $("metaExpires").textContent = "Delivered";
    $("metaExpires").className = "expiry-text done";
    $("securityDrawer").open = false;

    $("doneTitle").textContent = isSecret
      ? "Secret Delivered"
      : (isApproval ? "Approval Delivered" : "Directive Delivered");
    $("doneSubtitle").textContent = isApproval
      ? "Passkey-signed approval verified and delivered. Ephemeral keys wiped from memory — you can close this tab now."
      : "End-to-end encrypted. Ephemeral keys wiped from memory — you can close this tab now.";

    $("doneTarget").textContent = isSecret && fragment.handle
      ? `${fragment.nodeId} · ${fragment.handle}`
      : fragment.nodeId;

    if (isSecret) {
      $("doneKindLabel").textContent = "Secret";
      $("doneKindValue").textContent = fragment.secretName;
    } else if (isApproval) {
      $("doneKindLabel").textContent = "Action";
      $("doneKindValue").textContent = approvedActionName || "Security Approval";
    } else {
      $("doneKindLabel").textContent = "Handle";
      $("doneKindValue").textContent = fragment.handle || "Node-level";
    }

    const seqPart = ack && ack.seq !== undefined ? ` (#${ack.seq})` : "";
    $("doneDelivery").textContent = `${relayDisplay.host}${seqPart}`;
    $("doneTimestamp").textContent = formatLocalTime(new Date());

    $("doneOfflineBlock").classList.add("hidden");
    $("doneDeliveredBlock").classList.remove("hidden");
    $("viewDrop").classList.remove("is-offline-done");
    $("viewDrop").classList.add("is-delivered");
    showStage("done");
  }

  function showOfflineDoneState({ isRelayError, errorMessage }) {
    state.delivered = true;
    state.sealing = false;
    clearInterval(countdownTimer);
    clearBanner($("dropGlobalBanner"));
    $("metaExpires").textContent = "Sealed";
    $("metaExpires").className = "expiry-text done";
    $("securityDrawer").open = false;

    $("offlineTokenValue").textContent = state.lastHdrop1;
    $("doneDeliveredBlock").classList.add("hidden");
    $("doneOfflineBlock").classList.remove("hidden");

    const retryBtn = $("btnRetryUpload");
    if (isRelayError && hasRelay && state.lastEnvelopeJson) {
      setBanner(
        $("doneOfflineBanner"),
        $("doneOfflineBannerTitle"),
        $("doneOfflineBannerBody"),
        "warn",
        "Relay Unreachable — Offline Token Ready",
        `${errorMessage}. Your signed drop is already sealed & wiped from RAM — retry upload or copy the opaque hdrop1_ token below.`
      );
      retryBtn.classList.remove("hidden");
      retryBtn.disabled = false;
      $("retryUploadSpinner").classList.add("hidden");
      $("btnRetryUploadLabel").textContent = "Retry Upload";
    } else {
      setBanner(
        $("doneOfflineBanner"),
        $("doneOfflineBannerTitle"),
        $("doneOfflineBannerBody"),
        "verified",
        isApproval ? "Offline Approval Sealed" : "Offline Drop Sealed",
        isApproval
          ? "Approval signed and ephemeral keys wiped from RAM. Save the opaque hdrop1_ token to a file and pass it via --approval-file <path>."
          : "Plaintext and ephemeral keys wiped from RAM. Copy the opaque hdrop1_ token below and paste it into chat or `hyp drop ingest`."
      );
      retryBtn.classList.add("hidden");
    }

    $("viewDrop").classList.remove("is-delivered");
    $("viewDrop").classList.add("is-offline-done");
    showStage("done");
  }

  // --- Step 2: Sign, Seal & Send (or Offline Seal) — Reuses unlockedEdSeed with NO second biometric tap ---
  async function executeSeal(sendToRelay) {
    if (state.hardBlocked || state.expired) return;
    if (isSecret && !state.certVerified) return;
    if (!isSecret && !state.certVerified && !$("chkManualSasConfirm").checked) return;
    if (state.draftLoaded && !$("draftApproveCheck").checked) return;
    if (isApproval && (!state.approvalAction || !$("approvalConfirmCheck").checked)) return;

    const approvedActionName = isApproval && state.approvalAction ? state.approvalAction.action : "";
    const rawBody = isApproval
      ? toCanonicalJson(state.approvalAction)
      : (isSecret ? $("inputSecretValue").value : $("inputDirectiveValue").value);
    if (!rawBody) return;

    let signingSeed = state.unlockedEdSeed;
    let ephemeralPrfOut = null;
    let signingHumanId = state.humanId;
    let signingAuthEpoch = state.authEpoch;

    if (!signingSeed) {
      const auth = readAuthorityInputs();
      if (!auth) return;
      try {
        const hint = loadPublicHint(auth.humanId);
        const { prfOut } = await evaluatePasskeyPrf(auth.humanId, auth.prfSalt, hint?.credentialId || "");
        ephemeralPrfOut = prfOut;
        signingSeed = await derivePrfEd25519Seed(prfOut, auth.humanId, auth.authEpoch);
        signingHumanId = auth.humanId;
        signingAuthEpoch = auth.authEpoch;
      } catch (err) {
        setBanner(
          $("sealActionBanner"),
          $("sealActionTitle"),
          $("sealActionBody"),
          "danger",
          "Passkey Authentication Failed",
          err instanceof Error ? err.message : "Could not authenticate Passkey"
        );
        return;
      } finally {
        if (ephemeralPrfOut) zeroize(ephemeralPrfOut);
      }
    }

    state.sealing = true;
    $("btnSealSend").disabled = true;
    $("btnSealOffline").disabled = true;
    $("btnLockClear").disabled = true;
    if (sendToRelay && hasRelay) {
      $("sealSendSpinner").classList.remove("hidden");
      $("btnSealSendLabel").textContent = isApproval ? "Signing & delivering approval…" : "Sealing & sending…";
    }

    const nowMs = Date.now();
    const maxExpMs = nowMs + MAX_DROP_TTL_MS;
    const effectiveExpMs = fragment.expiresAtMs ? Math.min(fragment.expiresAtMs, maxExpMs) : maxExpMs;

    const claim = {
      v: 1,
      kind: fragment.kind,
      humanId: signingHumanId,
      authEpoch: signingAuthEpoch,
      issuedAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(effectiveExpMs).toISOString(),
      dropId: fragment.dropId || "",
      audience: {
        nodeId: fragment.nodeId,
        ...(fragment.handle ? { handle: fragment.handle } : {}),
      },
      ...(isSecret
        ? { secretSpec: { name: fragment.secretName, overwrite: $("chkOverwriteSecret").checked } }
        : {}),
      body: rawBody,
    };

    let sealed;
    try {
      sealed = await sealHumanDrop({
        claim,
        humanSeed32: signingSeed,
        recipientEncJwk: fragment.encJwk,
      });
    } catch (err) {
      state.sealing = false;
      if (signingSeed && signingSeed !== state.unlockedEdSeed) {
        zeroize(signingSeed);
      }
      wipeSecretRam({ clearDraft: true });
      $("sealSendSpinner").classList.add("hidden");
      $("btnSealSendLabel").textContent = primarySendLabel;
      $("btnLockClear").disabled = false;
      setBanner(
        $("unlockBanner"),
        $("unlockBannerTitle"),
        $("unlockBannerBody"),
        "danger",
        "Sealing Failed",
        err instanceof Error ? err.message : "Could not seal drop"
      );
      lockAndResetUi({ clearDraft: true, keepUnlockBanner: true });
      return;
    } finally {
      if (signingSeed && signingSeed !== state.unlockedEdSeed) {
        zeroize(signingSeed);
      }
      // Always wipe plaintext input, draft, approval state, and signing seed immediately after sealing!
      wipeSecretRam({ clearDraft: true });
    }

    state.lastHdrop1 = sealed.hdrop1;
    state.lastEnvelopeJson = toCanonicalJson(sealed.envelope);

    if (sendToRelay && hasRelay) {
      try {
        const ack = await uploadSealedEnvelope(state.lastEnvelopeJson);
        showDeliveredDoneState(ack, approvedActionName);
      } catch (err) {
        showOfflineDoneState({
          isRelayError: true,
          errorMessage: err instanceof Error ? err.message : "Network error",
        });
      } finally {
        $("sealSendSpinner").classList.add("hidden");
        $("btnSealSendLabel").textContent = primarySendLabel;
        $("btnLockClear").disabled = false;
      }
    } else {
      $("btnLockClear").disabled = false;
      showOfflineDoneState({ isRelayError: false, errorMessage: "" });
    }
  }

  $("btnSealSend").addEventListener("click", () => executeSeal(true));
  $("btnSealOffline").addEventListener("click", () => executeSeal(false));

  $("btnCopyHdrop1").addEventListener("click", () => {
    if (state.lastHdrop1) {
      copyText(state.lastHdrop1, $("btnCopyHdrop1"), "Copy hdrop1_ Token");
    }
  });

  $("btnRetryUpload").addEventListener("click", async () => {
    if (!hasRelay || !state.lastEnvelopeJson) return;
    const btn = $("btnRetryUpload");
    const label = $("btnRetryUploadLabel");
    const spinner = $("retryUploadSpinner");
    btn.disabled = true;
    spinner.classList.remove("hidden");
    label.textContent = "Retrying upload…";
    try {
      const ack = await uploadSealedEnvelope(state.lastEnvelopeJson);
      showDeliveredDoneState(ack);
    } catch (err) {
      showOfflineDoneState({
        isRelayError: true,
        errorMessage: err instanceof Error ? err.message : "Network error",
      });
    } finally {
      spinner.classList.add("hidden");
    }
  });
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  initBrowserApp();
}
