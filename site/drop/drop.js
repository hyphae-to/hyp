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
 * - Falls back cleanly to 1-tap offline `hdrop1_` copy if the Drop Relay is unreachable.
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
    let encKp = null;
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
      $("enrollFingerprint").textContent = `${sas.formatted} (${sas.phrase})`;
      $("enrollEncKid").textContent = encKp.kid;
      $("enrollEncFingerprint").textContent = `${encSas.formatted} (${encSas.phrase})`;
      $("enrollBundleBox").textContent = lastBundleJson;
      $("enrollResultBlock").classList.remove("hidden");

      setBanner(
        $("enrollBanner"),
        $("enrollBannerTitle"),
        $("enrollBannerBody"),
        "verified",
        "PASSKEY ENROLLED",
        "Public Ed25519 signing JWK and companion X25519 draft JWK derived cleanly; ephemeral private seeds wiped from RAM."
      );

      if (callbackUrl) {
        $("btnSendEnrollCallback").classList.remove("hidden");
      }
      btn.textContent = "Re-derive Public Keys";
    } catch (err) {
      setBanner(
        $("enrollBanner"),
        $("enrollBannerTitle"),
        $("enrollBannerBody"),
        "danger",
        "ENROLLMENT FAILED",
        err instanceof Error ? err.message : "Could not enroll Passkey"
      );
      btn.textContent = "Create Passkey & Derive Public Keys";
    } finally {
      if (prfOut) zeroize(prfOut);
      if (seed) zeroize(seed);
      if (encKp && encKp.privateKeyBytes) zeroize(encKp.privateKeyBytes);
      btn.disabled = false;
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
        "Your laptop CLI received your public Ed25519 signing JWK, companion X25519 draft JWK, and PRF salt."
      );
      btn.textContent = "Sent to Local hyp CLI";
    } catch (err) {
      setBanner(
        $("enrollBanner"),
        $("enrollBannerTitle"),
        $("enrollBannerBody"),
        "warn",
        "CALLBACK UNREACHABLE",
        `${err instanceof Error ? err.message : "Failed to reach loopback CLI"} — copy the Public JWKs & Salt above instead.`
      );
      btn.disabled = false;
      btn.textContent = "Retry Send to Local hyp CLI";
    }
  });
}

function autoSizeTextarea(el) {
  if (!el) return;
  el.style.height = "auto";
  const nextHeight = Math.max(el.scrollHeight + 2, 112);
  el.style.height = `${nextHeight}px`;
}

function formatDirectiveStats(text) {
  const charCount = [...text].length;
  const lineCount = text.length === 0 ? 0 : text.split("\n").length;
  return `${charCount} ${charCount === 1 ? "char" : "chars"} · ${lineCount} ${lineCount === 1 ? "line" : "lines"}`;
}

async function initDropMode(fragment) {
  $("viewDrop").classList.remove("hidden");

  const isSecret = fragment.kind === "secret";
  const hasRelay = Boolean(fragment.relay && fragment.dropId && fragment.postCap);

  // Ephemeral RAM state (strictly wiped on send, reset, skip, pagehide, or hidden tab)
  const state = {
    unlockedEdSeed: null,
    humanId: "",
    authEpoch: 1,
    certVerified: false,
    certReason: "",
    hardBlocked: false,
    expired: false,
    lastHdrop1: "",
    activeEncDraft: !isSecret && fragment.encDraft ? fragment.encDraft : null,
    draftLoaded: false,
  };

  function wipeSecretRam({ clearDraft = false } = {}) {
    if (state.unlockedEdSeed) {
      zeroize(state.unlockedEdSeed);
      state.unlockedEdSeed = null;
    }
    state.certVerified = false;
    state.draftLoaded = false;
    if (clearDraft) {
      state.activeEncDraft = null;
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
  }

  function applyFreshWriteHeadings() {
    $("unlockCardTitle").textContent = "Unlock Authority & Verify Node";
    $("unlockCardLead").textContent =
      "Tap below to authenticate with your Passkey and verify the target node certificate in RAM.";
    $("sealStepLabel").textContent = "Step 2 · Type or Paste Fresh";
    if (isSecret) {
      $("sealCardTitle").textContent = `Enter Secret: ${fragment.secretName || "—"}`;
      $("sealCardLead").textContent =
        "Drop links never pre-fill secrets. Type or paste directly here; plaintext is sealed in your browser and immediately wiped.";
    } else {
      $("sealCardTitle").textContent = "Write Verified Directive";
      $("sealCardLead").textContent =
        "Drop links never pre-fill plaintext payloads. Type or paste directly here; plaintext is sealed in your browser and immediately wiped.";
    }
  }

  function applyEncDraftLockedUi() {
    $("unlockCardTitle").textContent = "Unlock Encrypted Draft";
    $("unlockCardLead").textContent =
      "Face ID / Touch ID decrypts the draft and prepares your signing key in a single tap.";
    $("encDraftPanelText").textContent =
      `Encrypted directive draft from ${fragment.nodeId} — only readable after Face ID / Touch ID.`;
    $("encDraftPanel").classList.remove("hidden");
    $("btnUnlockPasskey").classList.add("hidden");
    $("btnLockClear").classList.add("hidden");
    $("stepSealCard").classList.add("hidden");
    $("directiveInputGroup").classList.add("hidden");
  }

  function lockAndResetUi({ clearDraft = false } = {}) {
    wipeSecretRam({ clearDraft });
    $("btnLockClear").classList.add("hidden");
    $("sasConfirmRow").classList.add("hidden");
    $("certStatusBanner").classList.add("hidden");
    if (state.activeEncDraft && !isSecret) {
      applyEncDraftLockedUi();
    } else {
      applyFreshWriteHeadings();
      $("encDraftPanel").classList.add("hidden");
      $("btnUnlockPasskey").classList.remove("hidden");
      $("stepSealCard").classList.remove("hidden");
      if (isSecret) {
        $("secretInputGroup").classList.remove("hidden");
      } else {
        $("directiveInputGroup").classList.remove("hidden");
      }
    }
    syncSealControls();
  }

  window.addEventListener("pagehide", () => wipeSecretRam({ clearDraft: true }));
  window.addEventListener("beforeunload", () => wipeSecretRam({ clearDraft: true }));
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden" && (state.unlockedEdSeed || state.draftLoaded)) {
      lockAndResetUi({ clearDraft: false });
    }
  });
  window.addEventListener("resize", () => {
    if (!isSecret && !$("directiveInputGroup").classList.contains("hidden")) {
      autoSizeTextarea($("inputDirectiveValue"));
    }
  });

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
    applyFreshWriteHeadings();
  } else if (state.activeEncDraft) {
    applyEncDraftLockedUi();
  } else {
    $("directiveInputGroup").classList.remove("hidden");
    applyFreshWriteHeadings();
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
    const unlocked = Boolean(state.unlockedEdSeed);
    const allowedByCert = state.certVerified || (!isSecret && $("chkManualSasConfirm").checked);
    const canEdit = unlocked && !state.hardBlocked && !state.expired && allowedByCert;

    $("inputSecretValue").disabled = !canEdit;
    $("btnToggleReveal").disabled = !canEdit;
    $("chkOverwriteSecret").disabled = !canEdit;
    $("inputDirectiveValue").disabled = !canEdit;
    $("btnUnlockDraft").disabled = state.hardBlocked || state.expired;
    $("btnUnlockPasskey").disabled = state.hardBlocked || state.expired;

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
      $("identityDetails").open = true;
      setBanner(
        $("certStatusBanner"),
        $("certStatusTitle"),
        $("certStatusBody"),
        "warn",
        "MISSING AUTHORITY PARAMETERS",
        "Enter your Human ID, PRF Salt, and Auth Epoch (from `hyp auth init`) before unlocking."
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
      return true;
    }
    if (isSecret) {
      // HARD-BLOCK secrets on unverified nodes and immediately wipe seed!
      zeroize(edSeed);
      state.unlockedEdSeed = null;
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
      return false;
    }
    // Directive on unverified node: allow ONLY with prominent red warning + manual SAS checkbox.
    state.unlockedEdSeed = edSeed;
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
    return true;
  }

  // Step 1A: 1-Tap Encrypted Draft Unlock (Single WebAuthn PRF -> X25519 open + Ed25519 RAM seed)
  $("btnUnlockDraft").addEventListener("click", async () => {
    if (state.hardBlocked || state.expired || !state.activeEncDraft) return;

    const auth = readAuthorityInputs();
    if (!auth) return;

    const btn = $("btnUnlockDraft");
    btn.disabled = true;
    btn.textContent = "Unlocking draft with Face ID / Touch ID…";

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

      // Derive BOTH companion X25519 keypair and Ed25519 signing seed from the single PRF output.
      encKp = await derivePrfX25519Keypair(prfOut, auth.humanId, auth.authEpoch);
      edSeed = await derivePrfEd25519Seed(prfOut, auth.humanId, auth.authEpoch);

      // Decrypt & strictly validate the encrypted draft, then immediately zero X25519 private key!
      let draftPayload;
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

      applyCertVerificationResult(certRes, edSeed, auth.humanId, auth.authEpoch);
      handedOffSeed = true;
      state.draftLoaded = true;

      $("encDraftPanel").classList.add("hidden");
      $("btnUnlockPasskey").classList.add("hidden");
      $("btnLockClear").classList.remove("hidden");

      $("sealStepLabel").textContent = "Step 2 · Review & Approve Draft";
      $("sealCardTitle").textContent = "Review Proposed Directive";
      $("sealCardLead").textContent =
        "Inspect every line carefully, edit if needed, then tick the approval box to sign with your unlocked Passkey.";

      $("draftWarningBanner").classList.remove("hidden");
      if (draftPayload.context) {
        $("draftContextText").textContent = draftPayload.context;
        $("draftContextRow").classList.remove("hidden");
      } else {
        $("draftContextText").textContent = "";
        $("draftContextRow").classList.add("hidden");
      }

      $("stepSealCard").classList.remove("hidden");
      $("directiveInputGroup").classList.remove("hidden");
      $("draftApproveCheck").checked = false;
      $("draftApproveRow").classList.remove("hidden");

      const textarea = $("inputDirectiveValue");
      textarea.value = draftPayload.text;
      syncSealControls();
      autoSizeTextarea(textarea);
    } catch (err) {
      setBanner(
        $("certStatusBanner"),
        $("certStatusTitle"),
        $("certStatusBody"),
        "danger",
        "DRAFT UNLOCK FAILED",
        `${err instanceof Error ? err.message : "Could not unlock encrypted draft"}. You can retry or skip the draft and write from scratch.`
      );
    } finally {
      if (prfOut) zeroize(prfOut);
      if (encKp && encKp.privateKeyBytes) zeroize(encKp.privateKeyBytes);
      if (edSeed && !handedOffSeed) zeroize(edSeed);
      btn.disabled = state.hardBlocked || state.expired;
      btn.textContent = "Unlock draft with Face ID / Touch ID";
    }
  });

  // Step 1B: Standard Passkey Unlock & NodeCertV1 Verify (Fresh Write / Secret Drops)
  $("btnUnlockPasskey").addEventListener("click", async () => {
    if (state.hardBlocked || state.expired) return;

    const auth = readAuthorityInputs();
    if (!auth) return;

    const btn = $("btnUnlockPasskey");
    btn.disabled = true;
    btn.textContent = "Authenticating with Passkey…";

    let prfOut = null;
    try {
      const hint = loadPublicHint(auth.humanId);
      const { prfOut: rawPrf, credentialId } = await evaluatePasskeyPrf(
        auth.humanId,
        auth.prfSalt,
        hint?.credentialId || ""
      );
      prfOut = rawPrf;

      const seed32 = await derivePrfEd25519Seed(prfOut, auth.humanId, auth.authEpoch);
      const { publicKeyBytes } = await ed25519KeypairFromSeed(seed32);

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

      const allowed = applyCertVerificationResult(certRes, seed32, auth.humanId, auth.authEpoch);
      if (allowed) {
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
      btn.disabled = state.hardBlocked || state.expired;
      btn.textContent = "Unlock with Passkey (FaceID / TouchID)";
    }
  });

  // Step 2: Sign, Seal & Send (or Offline Copy) — reuses unlockedEdSeed with NO second biometric tap
  async function executeSeal(sendToRelay) {
    if (state.hardBlocked || state.expired) return;
    if (isSecret && !state.certVerified) return;
    if (!isSecret && !state.certVerified && !$("chkManualSasConfirm").checked) return;
    if (state.draftLoaded && !$("draftApproveCheck").checked) return;

    const rawBody = isSecret ? $("inputSecretValue").value : $("inputDirectiveValue").value;
    if (!rawBody) return;

    // Use volatile unlockedEdSeed from Step 1 if present; otherwise authenticate via Passkey PRF once.
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
          "PASSKEY AUTHENTICATION FAILED",
          err instanceof Error ? err.message : "Could not authenticate Passkey"
        );
        return;
      } finally {
        if (ephemeralPrfOut) zeroize(ephemeralPrfOut);
      }
    }

    $("btnSealSend").disabled = true;
    $("btnSealOffline").disabled = true;

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
      if (signingSeed && signingSeed !== state.unlockedEdSeed) {
        zeroize(signingSeed);
      }
      // Always wipe plaintext input, draft, and signing seed immediately after sealing!
      lockAndResetUi({ clearDraft: true });
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
