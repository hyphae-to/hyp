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
  prfEvalInput,
  randomBytes,
  sasFingerprint,
  sealHumanDrop,
  signNodeCert,
  toCanonicalJson,
  utf8Bytes,
  utf8String,
  validateSecretName,
  verifyNodeCert,
  zeroize,
} from "./crypto.js?v=2";

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
  // Deliberately whitelist fields — HARD-IGNORE plaintext `proposedText`, `draft`, or `body`!
  // Accept HPKE `encDraft` ONLY on `kind === "directive"` (HARD-IGNORE on `kind === "secret"`).
  if (raw.v !== 1) {
    throw new Error(`Unsupported drop invite version: ${raw.v}`);
  }
  if (raw.kind !== "directive" && raw.kind !== "secret") {
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
    expiresAt: typeof raw.expiresAt === "string" ? raw.expiresAt : "",
    expiresAtMs,
    humanId: typeof raw.humanId === "string" ? raw.humanId.trim() : "",
    prfSalt: typeof raw.prfSalt === "string" ? raw.prfSalt.trim() : "",
    authEpoch: Number.isInteger(raw.authEpoch) && raw.authEpoch >= 1 ? raw.authEpoch : null,
    encDraft,
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

function getRpId() {
  const host = window.location.hostname;
  if (!host || /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":")) {
    return undefined;
  }
  return host;
}

export function coerceBytes(val) {
  if (!val) return null;
  if (val instanceof Uint8Array) return new Uint8Array(val);
  if (ArrayBuffer.isView(val)) {
    return new Uint8Array(val.buffer.slice(val.byteOffset, val.byteOffset + val.byteLength));
  }
  const tag = Object.prototype.toString.call(val);
  if (
    val instanceof ArrayBuffer ||
    tag === "[object ArrayBuffer]" ||
    tag === "[object SharedArrayBuffer]"
  ) {
    return new Uint8Array(val).slice();
  }
  if (Array.isArray(val) && val.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
    return Uint8Array.from(val);
  }
  if (typeof val === "string" && val.length > 0) {
    try {
      return base64urlDecode(val.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""));
    } catch {
      return null;
    }
  }
  if (typeof val === "object") {
    // Handle cross-realm buffers and extension-serialized byte maps (`{ "0": 12, "1": 34, ... }`).
    if (typeof val.byteLength === "number" && val.byteLength > 0) {
      try {
        const view = new Uint8Array(val);
        if (view.length === val.byteLength) return view.slice();
      } catch {
        // Fall through to indexed object check.
      }
    }
    const keys = Object.keys(val);
    if (
      keys.length > 0 &&
      keys.every((k, idx) => k === String(idx) && Number.isInteger(val[k]) && val[k] >= 0 && val[k] <= 255)
    ) {
      return Uint8Array.from(keys.map((k) => val[k]));
    }
  }
  return null;
}

export function extractPrfFirst(cred) {
  const ext = typeof cred?.getClientExtensionResults === "function"
    ? cred.getClientExtensionResults()
    : null;
  const first = ext?.prf?.results?.first;
  if (!first) return null;
  const bytes = coerceBytes(first);
  return bytes && bytes.length === 32 ? bytes : null;
}

async function evaluatePasskeyPrf(humanId, prfSalt, credentialIdB64 = "") {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error("WebAuthn Passkeys are not supported in this browser");
  }
  const evalInput = await prfEvalInput(humanId, prfSalt);
  const publicKey = {
    challenge: randomBytes(32),
    userVerification: "required",
    extensions: {
      prf: {
        eval: { first: evalInput },
      },
    },
  };
  const rpId = getRpId();
  if (rpId) publicKey.rpId = rpId;
  if (credentialIdB64) {
    try {
      publicKey.allowCredentials = [
        { type: "public-key", id: base64urlDecode(credentialIdB64) },
      ];
    } catch {
      // Fall back to discoverable credential prompt.
    }
  }

  const assertion = await navigator.credentials.get({ publicKey });
  if (!assertion) {
    throw new Error("Passkey authentication was cancelled");
  }
  const prfOut = extractPrfFirst(assertion);
  if (!prfOut) {
    throw new Error(
      "Your authenticator did not return a WebAuthn PRF secret. Use Safari 18+, Chrome, or Edge with a PRF-capable Passkey (iCloud Keychain / Google Password Manager)."
    );
  }
  const rawId = coerceBytes(assertion.rawId);
  const credentialId = rawId ? base64urlEncode(rawId) : (typeof assertion.id === "string" ? assertion.id : "");
  return { prfOut, credentialId };
}

async function enrollPasskeyWithPrf(humanId, prfSalt) {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error("WebAuthn Passkeys are not supported in this browser");
  }
  const evalInput = await prfEvalInput(humanId, prfSalt);
  const rpId = getRpId();
  const rp = rpId ? { name: "Hyphae Verified Drops", id: rpId } : { name: "Hyphae Verified Drops" };

  const createOptions = {
    challenge: randomBytes(32),
    rp,
    user: {
      id: utf8Bytes(humanId),
      name: humanId,
      displayName: humanId,
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -8 },
      { type: "public-key", alg: -257 },
    ],
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    },
    attestation: "none",
    extensions: {
      prf: {
        eval: { first: evalInput },
      },
    },
  };

  const created = await navigator.credentials.create({ publicKey: createOptions });
  if (!created) {
    throw new Error("Passkey creation was cancelled");
  }
  const rawId = coerceBytes(created.rawId);
  const credId = rawId ? base64urlEncode(rawId) : (typeof created.id === "string" ? created.id : "");
  const ext = typeof created.getClientExtensionResults === "function"
    ? created.getClientExtensionResults()
    : null;

  let prfOut = extractPrfFirst(created);
  if (!prfOut) {
    if (ext?.prf && ext.prf.enabled === false) {
      throw new Error(
        "This Passkey authenticator does not support the WebAuthn PRF extension."
      );
    }
    // Many authenticators report `prf.enabled: true` on create() and evaluate on get().
    const res = await evaluatePasskeyPrf(humanId, prfSalt, credId);
    prfOut = res.prfOut;
  }

  return { prfOut, credentialId: credId, rpId: rpId || window.location.hostname };
}

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

async function copyText(text, btn, idleLabel) {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = "Copied!";
    setTimeout(() => {
      btn.textContent = idleLabel;
    }, 2000);
  } catch {
    btn.textContent = "Select & Copy Above";
  }
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
  // 1. Immediately capture and scrub URL #fragment before any other work!
  const rawHash = window.location.hash;
  if (rawHash) {
    try {
      history.replaceState(null, "", window.location.pathname);
    } catch {
      // Ignore in restricted history contexts.
    }
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

async function initDropMode(fragment) {
  $("viewDrop").classList.remove("hidden");

  const isSecret = fragment.kind === "secret";
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
    activeEncDraft: !isSecret && fragment.encDraft ? fragment.encDraft : null,
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
  kindBadge.textContent = isSecret ? "SECRET" : "DIRECTIVE";
  kindBadge.className = `kind-badge ${isSecret ? "secret" : "directive"}`;

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
      : (state.activeEncDraft || state.draftLoaded ? "Review" : "Write");

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
    const hasDraft = Boolean(state.activeEncDraft && !isSecret);
    if (hasDraft) {
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
    updateStepper(stage);
  }

  function wipeSecretRam({ clearDraft = false, clearSealed = false } = {}) {
    if (state.unlockedEdSeed) {
      zeroize(state.unlockedEdSeed);
      state.unlockedEdSeed = null;
    }
    state.certVerified = false;
    state.draftLoaded = false;
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
    $("inputSecretValue").type = "password";
    $("btnToggleReveal").textContent = "Reveal";
    $("draftApproveCheck").checked = false;
    $("chkManualSasConfirm").checked = false;
    $("draftWarningBanner").classList.add("hidden");
    $("draftContextRow").classList.add("hidden");
    $("draftContextText").textContent = "";
    $("draftApproveRow").classList.add("hidden");
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
      pill.className = "countdown-pill";
      return;
    }
    const rem = fragment.expiresAtMs - Date.now();
    pill.textContent = formatCountdown(rem);
    if (rem <= 0) {
      pill.className = "countdown-pill danger";
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
      pill.className = "countdown-pill warn";
    } else {
      pill.className = "countdown-pill";
    }
  }
  refreshExpiry();
  const countdownTimer = setInterval(refreshExpiry, 1000);
  window.addEventListener("pagehide", () => clearInterval(countdownTimer));

  // --- Configure Primary vs Offline Action Buttons ---
  if (hasRelay) {
    $("btnSealSendLabel").textContent = isSecret ? "Seal & Send Secret" : "Sign, Seal & Send";
  } else {
    $("btnSealSend").classList.add("hidden");
    $("btnSealOffline").className = "btn-primary";
    $("btnSealOffline").textContent = "Seal Offline hdrop1_ Token";
  }

  function syncSealControls() {
    const unlocked = Boolean(state.unlockedEdSeed);
    const allowedByCert = state.certVerified || (!isSecret && $("chkManualSasConfirm").checked);
    const canEdit = unlocked && !state.hardBlocked && !state.expired && allowedByCert;

    $("inputSecretValue").disabled = !canEdit;
    $("btnToggleReveal").disabled = !canEdit;
    $("chkOverwriteSecret").disabled = !canEdit;
    $("inputDirectiveValue").disabled = !canEdit;
    $("btnUnlockPrimary").disabled = state.hardBlocked || state.expired;
    $("btnSkipDraft").disabled = state.hardBlocked || state.expired;

    const activeVal = isSecret ? $("inputSecretValue").value : $("inputDirectiveValue").value;
    const byteLen = utf8Bytes(activeVal).length;
    const maxBodyBytes = MAX_PADDED_PLAINTEXT - 1024;
    if (isSecret) {
      $("secretByteCount").textContent = `${byteLen} B`;
    } else {
      $("directiveByteCount").textContent = formatDirectiveStats(activeVal);
    }

    const draftApproved = !state.draftLoaded || $("draftApproveCheck").checked;
    const canSubmit = canEdit && draftApproved && byteLen > 0 && byteLen <= maxBodyBytes;
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

  $("btnToggleReveal").addEventListener("click", () => {
    const inp = $("inputSecretValue");
    const showing = inp.type === "text";
    inp.type = showing ? "password" : "text";
    $("btnToggleReveal").textContent = showing ? "Reveal" : "Hide";
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

  function enterUnlockedStage({ draftPayload = null } = {}) {
    clearBanner($("unlockBanner"));
    clearBanner($("sealActionBanner"));

    if (isSecret) {
      $("secretInputGroup").classList.remove("hidden");
      $("directiveInputGroup").classList.add("hidden");
      $("draftWarningBanner").classList.add("hidden");
      $("draftContextRow").classList.add("hidden");
      $("draftApproveRow").classList.add("hidden");
    } else if (draftPayload) {
      state.draftLoaded = true;
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
      $("secretInputGroup").classList.add("hidden");
      $("directiveInputGroup").classList.remove("hidden");
      $("directiveFieldLabel").textContent = "Verified Directive";
      $("draftWarningBanner").classList.add("hidden");
      $("draftContextRow").classList.add("hidden");
      $("draftApproveRow").classList.add("hidden");
    }

    showStage("unlocked");
    syncSealControls();

    if (!isSecret) {
      autoSizeTextarea($("inputDirectiveValue"));
    }
  }

  // --- Step 1: Unified Passkey Unlock (Handles both encDraft & standard unlock) ---
  $("btnUnlockPrimary").addEventListener("click", async () => {
    if (state.hardBlocked || state.expired) return;

    const auth = readAuthorityInputs();
    if (!auth) return;

    const isDraftFlow = Boolean(state.activeEncDraft && !isSecret);
    const btn = $("btnUnlockPrimary");
    const label = $("btnUnlockPrimaryLabel");
    const spinner = $("unlockSpinner");
    btn.disabled = true;
    $("btnSkipDraft").disabled = true;
    spinner.classList.remove("hidden");
    label.textContent = isDraftFlow
      ? "Unlocking draft with Face ID / Touch ID…"
      : "Authenticating with Face ID / Touch ID…";
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
      if (isDraftFlow) {
        // Derive BOTH companion X25519 keypair and Ed25519 signing seed from the single PRF output.
        encKp = await derivePrfX25519Keypair(prfOut, auth.humanId, auth.authEpoch);
        edSeed = await derivePrfEd25519Seed(prfOut, auth.humanId, auth.authEpoch);

        // Decrypt & strictly validate the encrypted draft, then immediately zero X25519 private key!
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
        enterUnlockedStage({ draftPayload });
      }
    } catch (err) {
      setBanner(
        $("unlockBanner"),
        $("unlockBannerTitle"),
        $("unlockBannerBody"),
        "danger",
        isDraftFlow ? "Draft Unlock Failed" : "Passkey Unlock Failed",
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
      throw new Error(`Drop Relay responded with HTTP ${resp.status}`);
    }
    return resp.json().catch(() => ({}));
  }

  function showDeliveredDoneState(ack) {
    state.delivered = true;
    state.sealing = false;
    clearInterval(countdownTimer);
    clearBanner($("dropGlobalBanner"));
    $("metaExpires").textContent = "Delivered";
    $("metaExpires").className = "countdown-pill done";
    $("securityDrawer").open = false;

    $("doneTitle").textContent = isSecret ? "Secret Delivered" : "Directive Delivered";
    $("doneSubtitle").textContent =
      `Delivered end-to-end encrypted to ${fragment.nodeId}. Ephemeral keys wiped from memory — you can close this tab now.`;

    $("doneTarget").textContent = fragment.nodeId;

    if (isSecret) {
      $("doneKindLabel").textContent = "Secret";
      $("doneKindValue").textContent = fragment.secretName;
    } else {
      $("doneKindLabel").textContent = "Handle";
      $("doneKindValue").textContent = fragment.handle || "Node-level";
    }

    const seqPart = ack && ack.seq !== undefined ? ` (#${ack.seq})` : "";
    $("doneDelivery").textContent = `${relayDisplay.host}${seqPart}`;
    $("doneTimestamp").textContent = formatLocalTime(new Date());

    $("doneOfflineBlock").classList.add("hidden");
    $("doneDeliveredBlock").classList.remove("hidden");
    showStage("done");
  }

  function showOfflineDoneState({ isRelayError, errorMessage }) {
    state.delivered = true;
    state.sealing = false;
    clearInterval(countdownTimer);
    clearBanner($("dropGlobalBanner"));
    $("metaExpires").textContent = "Sealed";
    $("metaExpires").className = "countdown-pill done";
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
        `${errorMessage}. Your drop is already sealed & wiped from RAM — retry upload or copy the opaque hdrop1_ token below.`
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
        "Offline Drop Sealed",
        "Plaintext and ephemeral keys wiped from RAM. Copy the opaque hdrop1_ token below and paste it into chat or `hyp drop ingest`."
      );
      retryBtn.classList.add("hidden");
    }

    showStage("done");
  }

  // --- Step 2: Sign, Seal & Send (or Offline Seal) — Reuses unlockedEdSeed with NO second biometric tap ---
  async function executeSeal(sendToRelay) {
    if (state.hardBlocked || state.expired) return;
    if (isSecret && !state.certVerified) return;
    if (!isSecret && !state.certVerified && !$("chkManualSasConfirm").checked) return;
    if (state.draftLoaded && !$("draftApproveCheck").checked) return;

    const rawBody = isSecret ? $("inputSecretValue").value : $("inputDirectiveValue").value;
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
      $("btnSealSendLabel").textContent = "Sealing & sending…";
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
      $("btnSealSendLabel").textContent = isSecret ? "Seal & Send Secret" : "Sign, Seal & Send";
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
      // Always wipe plaintext input, draft, and signing seed immediately after sealing!
      wipeSecretRam({ clearDraft: true });
    }

    state.lastHdrop1 = sealed.hdrop1;
    state.lastEnvelopeJson = toCanonicalJson(sealed.envelope);

    if (sendToRelay && hasRelay) {
      try {
        const ack = await uploadSealedEnvelope(state.lastEnvelopeJson);
        showDeliveredDoneState(ack);
      } catch (err) {
        showOfflineDoneState({
          isRelayError: true,
          errorMessage: err instanceof Error ? err.message : "Network error",
        });
      } finally {
        $("sealSendSpinner").classList.add("hidden");
        $("btnSealSendLabel").textContent = isSecret ? "Seal & Send Secret" : "Sign, Seal & Send";
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
