/**
 * Hyphae v2 Verified Human Drops — Mobile Portal Controller
 *
 * Security invariants:
 * - Immediately parses `window.location.hash` into RAM and scrubs the URL bar via `history.replaceState`.
 * - Never pre-fills payload inputs (ignores any `proposedText` or `body` in URL fragments).
 * - Derives Ed25519 signing seed strictly in RAM via WebAuthn Passkey + PRF -> HKDF-SHA256.
 * - Verifies `NodeCertV1` (`hcert1_`) against the derived human authority pubkey before sealing.
 * - Hard-blocks `kind === "secret"` drops on unverified nodes or reserved system secret names.
 * - Zeroes ephemeral seeds and wipes form inputs immediately after sealing (or on page unload).
 * - Falls back cleanly to 1-tap offline `hdrop1_` copy if the Drop Relay is unreachable.
 */

import {
  base64urlDecode,
  base64urlEncode,
  decodeOkpJwkBytes,
  derivePrfEd25519Seed,
  ed25519KeypairFromSeed,
  isReservedSecretName,
  MAX_PADDED_PLAINTEXT,
  prfEvalInput,
  randomBytes,
  sasFingerprint,
  sealHumanDrop,
  toCanonicalJson,
  utf8Bytes,
  utf8String,
  validateSecretName,
  verifyNodeCert,
  zeroize,
} from "./crypto.js";

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
  // Deliberately whitelist fields — NEVER read or preserve `proposedText` or `body`!
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

function extractPrfFirst(cred) {
  const ext = typeof cred?.getClientExtensionResults === "function"
    ? cred.getClientExtensionResults()
    : null;
  const first = ext?.prf?.results?.first;
  if (!first) return null;
  const bytes = new Uint8Array(first instanceof ArrayBuffer ? first : first.buffer.slice(first.byteOffset, first.byteOffset + first.byteLength));
  return bytes.length === 32 ? bytes : null;
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
  const rawId = new Uint8Array(assertion.rawId);
  return { prfOut, credentialId: base64urlEncode(rawId) };
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
  const credId = base64urlEncode(new Uint8Array(created.rawId));
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
// Browser UI Controller
// ============================================================================

function $(id) {
  return document.getElementById(id);
}

function setBanner(el, titleEl, bodyEl, variant, title, body) {
  el.className = `banner ${variant}`;
  titleEl.textContent = title;
  bodyEl.textContent = body;
}

function formatCountdown(msRemaining) {
  if (msRemaining <= 0) return "EXPIRED";
  const totalSec = Math.ceil(msRemaining / 1000);
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  return `${mins}m ${String(secs).padStart(2, "0")}s`;
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

  $("btnEnrollPasskey").addEventListener("click", async () => {
    const btn = $("btnEnrollPasskey");
    btn.disabled = true;
    btn.textContent = "Waiting for FaceID / TouchID…";
    let prfOut = null;
    let seed = null;
    try {
      const enrolled = await enrollPasskeyWithPrf(humanId, prfSalt);
      prfOut = enrolled.prfOut;
      seed = await derivePrfEd25519Seed(prfOut, humanId, authEpoch);
      const { publicKeyBytes, publicJwk, kid } = await ed25519KeypairFromSeed(seed);
      const sas = await sasFingerprint(publicKeyBytes);

      savePublicHint(humanId, {
        prfSalt,
        authEpoch,
        credentialId: enrolled.credentialId,
      });

      const bundle = {
        v: 1,
        humanId,
        kid,
        authEpoch,
        prfSalt,
        jwk: publicJwk,
        credentialId: enrolled.credentialId,
        rpId: enrolled.rpId,
      };
      lastBundleJson = JSON.stringify(bundle, null, 2);

      $("enrollKid").textContent = kid;
      $("enrollFingerprint").textContent = `${sas.formatted} (${sas.phrase})`;
      $("enrollBundleBox").textContent = lastBundleJson;
      $("enrollResultBlock").classList.remove("hidden");

      setBanner(
        $("enrollBanner"),
        $("enrollBannerTitle"),
        $("enrollBannerBody"),
        "verified",
        "PASSKEY ENROLLED",
        "Public Ed25519 JWK derived cleanly; ephemeral private seed wiped from RAM."
      );

      if (callbackUrl) {
        $("btnSendEnrollCallback").classList.remove("hidden");
      }
      btn.textContent = "Re-derive Public Key";
    } catch (err) {
      setBanner(
        $("enrollBanner"),
        $("enrollBannerTitle"),
        $("enrollBannerBody"),
        "danger",
        "ENROLLMENT FAILED",
        err instanceof Error ? err.message : "Could not enroll Passkey"
      );
      btn.textContent = "Create Passkey & Derive Public Key";
    } finally {
      if (prfOut) zeroize(prfOut);
      if (seed) zeroize(seed);
      btn.disabled = false;
    }
  });

  $("btnCopyEnrollBundle").addEventListener("click", () => {
    if (lastBundleJson) {
      copyText(lastBundleJson, $("btnCopyEnrollBundle"), "Copy Public JWK & Salt");
    }
  });

  $("btnSendEnrollCallback").addEventListener("click", async () => {
    if (!callbackUrl || !lastBundleJson) return;
    const btn = $("btnSendEnrollCallback");
    btn.disabled = true;
    btn.textContent = "Sending to local hyp CLI…";
    try {
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
      setBanner(
        $("enrollBanner"),
        $("enrollBannerTitle"),
        $("enrollBannerBody"),
        "verified",
        "SENT TO LOCAL HYP CLI",
        "Your laptop CLI received the public Ed25519 JWK and PRF salt."
      );
      btn.textContent = "Sent to Local hyp CLI";
    } catch (err) {
      setBanner(
        $("enrollBanner"),
        $("enrollBannerTitle"),
        $("enrollBannerBody"),
        "warn",
        "CALLBACK UNREACHABLE",
        `${err instanceof Error ? err.message : "Failed to reach loopback CLI"} — copy the Public JWK & Salt above instead.`
      );
      btn.disabled = false;
      btn.textContent = "Retry Send to Local hyp CLI";
    }
  });
}

async function initDropMode(fragment) {
  $("viewDrop").classList.remove("hidden");

  const isSecret = fragment.kind === "secret";
  const hasRelay = Boolean(fragment.relay && fragment.dropId && fragment.postCap);

  // Ephemeral RAM state (strictly wiped after seal or pagehide)
  const state = {
    seed32: null,
    humanId: "",
    authEpoch: 1,
    certVerified: false,
    certReason: "",
    hardBlocked: false,
    expired: false,
    lastHdrop1: "",
  };

  function wipeSecretRam() {
    if (state.seed32) {
      zeroize(state.seed32);
      state.seed32 = null;
    }
    state.certVerified = false;
    $("inputSecretValue").value = "";
    $("inputDirectiveValue").value = "";
    $("inputSecretValue").type = "password";
    $("btnToggleReveal").textContent = "Reveal";
  }

  window.addEventListener("pagehide", wipeSecretRam);
  window.addEventListener("beforeunload", wipeSecretRam);

  // Render target metadata
  $("dropTitle").textContent = isSecret ? "Zero-Knowledge Secret Drop" : "Verified Human Directive";
  $("dropSubtitle").textContent = isSecret
    ? "Decrypts directly into the target node's SecretStore — never enters LLM context or logs."
    : "Signed by your Passkey authority and delivered directly to your target agent.";

  const badge = $("dropKindBadge");
  badge.textContent = isSecret ? "SECRET" : "DIRECTIVE";
  badge.className = `kind-badge ${isSecret ? "secret" : "directive"}`;

  $("metaNodeId").textContent = fragment.nodeId;
  $("metaHandle").textContent = fragment.handle || "(node-level)";
  $("metaRelay").textContent = hasRelay ? new URL(fragment.relay).origin : "Offline hdrop1_ only";
  $("metaCertHint").textContent = fragment.nodeCert ? "NodeCert attached" : "No NodeCert attached";

  if (isSecret) {
    $("metaSecretRow").classList.remove("hidden");
    $("metaSecretName").textContent = fragment.secretName || "(missing)";
    $("secretInputGroup").classList.remove("hidden");
    $("sealCardTitle").textContent = `Enter Secret: ${fragment.secretName || "—"}`;
  } else {
    $("directiveInputGroup").classList.remove("hidden");
    $("sealCardTitle").textContent = "Write Verified Directive";
  }

  // Validate secret name & reserved system-key denylist up front
  if (isSecret) {
    const nameCheck = validateSecretName(fragment.secretName);
    if (!nameCheck.ok) {
      state.hardBlocked = true;
      $("metaSecretName").classList.add("danger");
      setBanner(
        $("dropGlobalBanner"),
        $("dropGlobalBannerTitle"),
        $("dropGlobalBannerBody"),
        "danger",
        "INVALID SECRET NAME — BLOCKED",
        nameCheck.message
      );
    } else if (isReservedSecretName(fragment.secretName)) {
      state.hardBlocked = true;
      $("metaSecretName").classList.add("danger");
      setBanner(
        $("dropGlobalBanner"),
        $("dropGlobalBannerTitle"),
        $("dropGlobalBannerBody"),
        "danger",
        "RESERVED SYSTEM SECRET — BLOCKED",
        `"${fragment.secretName}" targets an internal Hyphae system key and is permanently blocked.`
      );
    }
  }

  // Render SAS fingerprint of target X25519 encryption key
  const sas = await sasFingerprint(fragment.encJwk);
  $("sasHex").textContent = sas.formatted;
  $("sasWords").textContent = sas.phrase;
  $("sasConfirmText").textContent =
    `I manually verified SAS fingerprint ${sas.formatted} (${sas.phrase}) on ${fragment.nodeId} and accept sending this directive to an uncertified key.`;

  // Populate authority parameters (from fragment, cert hint, or saved public hint)
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
    $("identitySummaryText").textContent = h && s ? `${h} · epoch ${e || 1}` : "Needs humanId & salt";
  }
  updateIdentitySummary();
  if (!initialHumanId || !initialPrfSalt) {
    $("identityDetails").open = true;
  }
  $("inputHumanId").addEventListener("input", updateIdentitySummary);
  $("inputPrfSalt").addEventListener("input", updateIdentitySummary);
  $("inputAuthEpoch").addEventListener("input", updateIdentitySummary);

  // Live expiration countdown
  function refreshExpiry() {
    if (!fragment.expiresAtMs) {
      $("metaExpires").textContent = "10m on seal";
      return;
    }
    const rem = fragment.expiresAtMs - Date.now();
    $("metaExpires").textContent = formatCountdown(rem);
    if (rem <= 0 && !state.expired) {
      state.expired = true;
      $("metaExpires").classList.add("danger");
      setBanner(
        $("dropGlobalBanner"),
        $("dropGlobalBannerTitle"),
        $("dropGlobalBannerBody"),
        "danger",
        "DROP LINK EXPIRED",
        "This drop invitation has expired. Request a fresh drop link from your node."
      );
      syncSealControls();
    }
  }
  refreshExpiry();
  const countdownTimer = setInterval(refreshExpiry, 1000);
  window.addEventListener("pagehide", () => clearInterval(countdownTimer));

  if (!hasRelay) {
    $("btnSealSend").classList.add("hidden");
  }

  function syncSealControls() {
    const unlocked = Boolean(state.seed32);
    const allowedByCert = state.certVerified || (!isSecret && $("chkManualSasConfirm").checked);
    const canEdit = unlocked && !state.hardBlocked && !state.expired && allowedByCert;

    $("inputSecretValue").disabled = !canEdit;
    $("btnToggleReveal").disabled = !canEdit;
    $("chkOverwriteSecret").disabled = !canEdit;
    $("inputDirectiveValue").disabled = !canEdit;

    const activeVal = isSecret ? $("inputSecretValue").value : $("inputDirectiveValue").value;
    const byteLen = utf8Bytes(activeVal).length;
    const maxBodyBytes = MAX_PADDED_PLAINTEXT - 1024;
    if (isSecret) {
      $("secretByteCount").textContent = `${byteLen} B`;
    } else {
      $("directiveByteCount").textContent = `${byteLen} / ${maxBodyBytes} B`;
    }

    const canSubmit = canEdit && byteLen > 0 && byteLen <= maxBodyBytes;
    $("btnSealSend").disabled = !canSubmit || !hasRelay;
    $("btnSealOffline").disabled = !canSubmit;
  }

  $("inputSecretValue").addEventListener("input", syncSealControls);
  $("inputDirectiveValue").addEventListener("input", syncSealControls);
  $("chkManualSasConfirm").addEventListener("change", syncSealControls);

  $("btnToggleReveal").addEventListener("click", () => {
    const inp = $("inputSecretValue");
    const showing = inp.type === "text";
    inp.type = showing ? "password" : "text";
    $("btnToggleReveal").textContent = showing ? "Reveal" : "Hide";
  });

  $("btnLockClear").addEventListener("click", () => {
    wipeSecretRam();
    $("btnLockClear").classList.add("hidden");
    $("btnUnlockPasskey").classList.remove("hidden");
    $("sasConfirmRow").classList.add("hidden");
    $("chkManualSasConfirm").checked = false;
    $("certStatusBanner").classList.add("hidden");
    syncSealControls();
  });

  // Step 1: Unlock with Passkey + Verify NodeCertV1
  $("btnUnlockPasskey").addEventListener("click", async () => {
    if (state.hardBlocked || state.expired) return;

    const humanId = $("inputHumanId").value.trim();
    const prfSalt = $("inputPrfSalt").value.trim();
    const authEpoch = parseInt($("inputAuthEpoch").value, 10);

    if (!humanId || !prfSalt || !Number.isInteger(authEpoch) || authEpoch < 1) {
      $("identityDetails").open = true;
      setBanner(
        $("certStatusBanner"),
        $("certStatusTitle"),
        $("certStatusBody"),
        "warn",
        "MISSING AUTHORITY PARAMETERS",
        "Enter your Human ID, PRF Salt, and Auth Epoch (from `hyp auth init`) before unlocking."
      );
      return;
    }

    const btn = $("btnUnlockPasskey");
    btn.disabled = true;
    btn.textContent = "Authenticating with Passkey…";

    let prfOut = null;
    try {
      const hint = loadPublicHint(humanId);
      const { prfOut: rawPrf, credentialId } = await evaluatePasskeyPrf(
        humanId,
        prfSalt,
        hint?.credentialId || ""
      );
      prfOut = rawPrf;

      const seed32 = await derivePrfEd25519Seed(prfOut, humanId, authEpoch);
      const { publicKeyBytes } = await ed25519KeypairFromSeed(seed32);

      savePublicHint(humanId, { prfSalt, authEpoch, credentialId });

      const certRes = await verifyNodeCert(
        fragment.nodeCert,
        publicKeyBytes,
        fragment.nodeId,
        fragment.encJwk,
        Date.now()
      );

      if (certRes.ok) {
        state.seed32 = seed32;
        state.humanId = humanId;
        state.authEpoch = authEpoch;
        state.certVerified = true;
        state.certReason = "";
        $("metaCertHint").textContent = "NodeCert verified";
        $("sasConfirmRow").classList.add("hidden");
        setBanner(
          $("certStatusBanner"),
          $("certStatusTitle"),
          $("certStatusBody"),
          "verified",
          "VERIFIED FLEET NODE",
          `Node certificate for ${fragment.nodeId} verified by ${certRes.cert.humanId} (epoch ${certRes.cert.authEpoch}).`
        );
        $("btnUnlockPasskey").classList.add("hidden");
        $("btnLockClear").classList.remove("hidden");
      } else if (isSecret) {
        // HARD-BLOCK secrets on unverified nodes and immediately wipe seed!
        zeroize(seed32);
        state.seed32 = null;
        state.certVerified = false;
        state.hardBlocked = true;
        state.certReason = certRes.message;
        $("metaCertHint").textContent = "Cert verification failed";
        setBanner(
          $("certStatusBanner"),
          $("certStatusTitle"),
          $("certStatusBody"),
          "danger",
          "UNVERIFIED NODE — SECRET BLOCKED",
          `${certRes.message}. Secret drops are hard-blocked unless the node holds a valid certificate signed by your Passkey.`
        );
      } else {
        // Directive on unverified node: allow ONLY with prominent red warning + manual SAS checkbox.
        state.seed32 = seed32;
        state.humanId = humanId;
        state.authEpoch = authEpoch;
        state.certVerified = false;
        state.certReason = certRes.message;
        $("metaCertHint").textContent = "UNVERIFIED NODE";
        setBanner(
          $("certStatusBanner"),
          $("certStatusTitle"),
          $("certStatusBody"),
          "danger",
          "UNVERIFIED NODE WARNING",
          `${certRes.message}. Compare the SAS fingerprint above directly with ${fragment.nodeId} before confirming.`
        );
        $("sasConfirmRow").classList.remove("hidden");
        $("btnUnlockPasskey").classList.add("hidden");
        $("btnLockClear").classList.remove("hidden");
      }
      syncSealControls();
    } catch (err) {
      setBanner(
        $("certStatusBanner"),
        $("certStatusTitle"),
        $("certStatusBody"),
        "danger",
        "PASSKEY UNLOCK FAILED",
        err instanceof Error ? err.message : "Could not unlock Passkey"
      );
    } finally {
      if (prfOut) zeroize(prfOut);
      btn.disabled = false;
      btn.textContent = "Unlock with Passkey (FaceID / TouchID)";
    }
  });

  // Step 2: Sign, Seal & Send (or Offline Copy)
  async function executeSeal(sendToRelay) {
    if (!state.seed32 || state.hardBlocked || state.expired) return;
    if (isSecret && !state.certVerified) return;
    if (!isSecret && !state.certVerified && !$("chkManualSasConfirm").checked) return;

    const rawBody = isSecret ? $("inputSecretValue").value : $("inputDirectiveValue").value;
    if (!rawBody) return;

    $("btnSealSend").disabled = true;
    $("btnSealOffline").disabled = true;

    const nowMs = Date.now();
    const maxExpMs = nowMs + MAX_DROP_TTL_MS;
    const effectiveExpMs = fragment.expiresAtMs ? Math.min(fragment.expiresAtMs, maxExpMs) : maxExpMs;

    const claim = {
      v: 1,
      kind: fragment.kind,
      humanId: state.humanId,
      authEpoch: state.authEpoch,
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
        humanSeed32: state.seed32,
        recipientEncJwk: fragment.encJwk,
      });
    } catch (err) {
      setBanner(
        $("sealActionBanner"),
        $("sealActionTitle"),
        $("sealActionBody"),
        "danger",
        "SEALING FAILED",
        err instanceof Error ? err.message : "Could not seal drop"
      );
      syncSealControls();
      return;
    } finally {
      // Always wipe plaintext input and signing seed immediately after sealing!
      wipeSecretRam();
      $("btnLockClear").classList.add("hidden");
      $("btnUnlockPasskey").classList.remove("hidden");
      $("sasConfirmRow").classList.add("hidden");
      $("chkManualSasConfirm").checked = false;
    }

    state.lastHdrop1 = sealed.hdrop1;
    $("dropResultCard").classList.remove("hidden");
    $("resClaimId").textContent = sealed.claim.claimId;

    if (sendToRelay && hasRelay) {
      try {
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
          body: toCanonicalJson(sealed.envelope),
        });
        if (!resp.ok) {
          throw new Error(`Drop Relay responded with HTTP ${resp.status}`);
        }
        const ack = await resp.json().catch(() => ({}));
        $("resultMetaGrid").classList.remove("hidden");
        $("resSeq").textContent = ack && ack.seq !== undefined ? `#${ack.seq}` : "accepted";
        $("offlineTokenBlock").classList.add("hidden");
        setBanner(
          $("resultBanner"),
          $("resultTitle"),
          $("resultMessage"),
          "verified",
          "DROP SEALED & DELIVERED",
          `Opaque ciphertext accepted by ${new URL(fragment.relay).origin}. Your input and Passkey seed were wiped from memory.`
        );
      } catch (err) {
        // Offline / Relay-Failure Fallback: show 1-tap Copy Sealed hdrop1_ token!
        $("resultMetaGrid").classList.remove("hidden");
        $("resSeq").textContent = "offline fallback";
        $("offlineTokenValue").textContent = sealed.hdrop1;
        $("offlineTokenBlock").classList.remove("hidden");
        setBanner(
          $("resultBanner"),
          $("resultTitle"),
          $("resultMessage"),
          "warn",
          "RELAY UNREACHABLE — COPY OFFLINE TOKEN",
          `${err instanceof Error ? err.message : "Network error"}. Your drop is already sealed & wiped from RAM — copy the opaque hdrop1_ token below and paste it safely into chat.`
        );
      }
    } else {
      $("resultMetaGrid").classList.remove("hidden");
      $("resSeq").textContent = "offline token";
      $("offlineTokenValue").textContent = sealed.hdrop1;
      $("offlineTokenBlock").classList.remove("hidden");
      setBanner(
        $("resultBanner"),
        $("resultTitle"),
        $("resultMessage"),
        "verified",
        "OFFLINE DROP SEALED",
        "Plaintext and Passkey seed have been wiped from RAM. Copy the opaque hdrop1_ token below and paste it safely into chat or `hyp drop ingest`."
      );
    }

    syncSealControls();
  }

  $("btnSealSend").addEventListener("click", () => executeSeal(true));
  $("btnSealOffline").addEventListener("click", () => executeSeal(false));
  $("btnCopyHdrop1").addEventListener("click", () => {
    if (state.lastHdrop1) {
      copyText(state.lastHdrop1, $("btnCopyHdrop1"), "Copy Sealed hdrop1_");
    }
  });
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  initBrowserApp();
}
