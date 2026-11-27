/**
 * Hyphae v2 Team Hub Join Portal (`https://hyphae.to/join`)
 *
 * Security invariants:
 * - Parses `#hjoin1_...` or `#certify=...` strictly client-side and scrubs `window.location.hash`
 *   immediately via `history.replaceState`.
 * - Frame-busting check fails closed if embedded in an iframe.
 * - Derives Ed25519 + companion X25519 keys in RAM via WebAuthn Passkey + PRF -> HKDF-SHA256
 *   (sharing public hint storage with `hyphae.to/drop` so Verified Drops work right away).
 * - Checks device `nodeId` against the signed invite's `nodePrefix` before signing `hcert1_`.
 * - Wipes ephemeral PRF seeds in memory immediately after signing, on `pagehide`, or when hidden.
 */

import {
  base64urlDecode,
  base64urlEncode,
  decodeOkpJwkBytes,
  derivePrfEd25519Seed,
  derivePrfX25519Keypair,
  ed25519KeypairFromSeed,
  encodeHpub1,
  HJOIN1_PREFIX,
  isAllowedHubEndpoint,
  isValidNodeId,
  matchesNodePrefix,
  randomBytes,
  sasFingerprint,
  signHumanInviteClaim,
  signNodeCert,
  utf8String,
  verifyHumanInvite,
  zeroize,
} from "../drop/crypto.js?v=4";
import { copyText as copyBrowserText, createPasskeyOperations, isEmbeddedInFrame } from "../passkey.js?v=1";

export { isEmbeddedInFrame };

const HINT_STORAGE_PREFIX = "hyphae.drop.hint.v1:";
const DEFAULT_LOCAL_PORT = 47891;
const POLL_INTERVAL_MS = 1500;
const SAFARI_FALLBACK_FAILURE_THRESHOLD = 4;

// ============================================================================
// Pure Parsing, Formatting & Agent Prompt Helpers (Exported for Unit Testing)
// ============================================================================

export function parseJoinFragment(rawInput) {
  let raw = typeof rawInput === "string" ? rawInput.trim() : "";
  if (!raw) {
    return { mode: "landing" };
  }
  const hashIdx = raw.indexOf("#");
  if (hashIdx >= 0) {
    raw = raw.slice(hashIdx + 1).trim();
  }
  if (!raw) {
    return { mode: "landing" };
  }
  if (raw.startsWith(HJOIN1_PREFIX)) {
    return { mode: "invite", hjoin1: raw };
  }
  if (raw.startsWith("invite=")) {
    const tok = raw.slice("invite=".length).trim();
    if (!tok.startsWith(HJOIN1_PREFIX)) {
      throw new Error("Expected hjoin1_ token in #invite=");
    }
    return { mode: "invite", hjoin1: tok };
  }
  if (raw.startsWith("certify=")) {
    const encoded = raw.slice("certify=".length).trim();
    const data = JSON.parse(utf8String(base64urlDecode(encoded)));
    if (!data || typeof data !== "object") {
      throw new Error("Certify payload must be a JSON object");
    }
    if (!isValidNodeId(data.hubNodeId) || !isAllowedHubEndpoint(data.hubEndpoint)) {
      throw new Error("Certify payload requires valid hubNodeId and hubEndpoint");
    }
    if (!isValidNodeId(data.humanId)) {
      throw new Error("Certify payload requires valid humanId");
    }
    return { mode: "certify", certify: data };
  }
  throw new Error("Unrecognized fragment (expected #hjoin1_... or #certify=...)");
}

export function buildAgentPrompts(hubNodeId) {
  const safeHub = typeof hubNodeId === "string" && hubNodeId.trim() ? hubNodeId.trim() : "my Hyphae hub";
  return {
    existing: `Run hyp join in a terminal and tell me the 6-digit confirmation code so I can approve joining ${safeHub} in my browser.`,
    fresh: `Install Hyphae (curl -fsSL https://hyphae.to/install.sh | sh), then run hyp join and tell me the 6-digit confirmation code so I can approve joining ${safeHub} in my browser.`,
    remoteFinish: `Pipe this signed Hyphae handoff bundle into \`hyp join --stdin\` to complete joining ${safeHub}:`,
  };
}

export function formatSixDigitCodeInput(raw) {
  const digits = String(raw ?? "").replace(/\D/g, "").slice(0, 6);
  if (digits.length <= 3) return digits;
  return `${digits.slice(0, 3)}-${digits.slice(3)}`;
}

export function formatCountdown(msRemaining) {
  if (msRemaining <= 0) return "EXPIRED";
  const totalSec = Math.ceil(msRemaining / 1000);
  const hours = Math.floor(totalSec / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  const secs = totalSec % 60;
  if (hours > 0) return `${hours}h ${String(mins).padStart(2, "0")}m`;
  return `${mins}m ${String(secs).padStart(2, "0")}s`;
}

// ============================================================================
// Shared Public Hint Storage (Compatible with hyphae.to/drop)
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
    // Storage restricted — continue cleanly.
  }
}

function loadPublicHint(humanId) {
  try {
    const target = humanId || localStorage.getItem(HINT_STORAGE_PREFIX + "__last__") || "";
    if (!target) return null;
    const raw = localStorage.getItem(HINT_STORAGE_PREFIX + target);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

// ============================================================================
// WebAuthn Passkey + PRF Operations
// ============================================================================

const { evaluatePasskeyPrf, enrollPasskeyWithPrf } = createPasskeyOperations({
  rpName: "Hyphae Authority",
  missingPrfMessage:
    "Your authenticator did not return a WebAuthn PRF secret. Use Safari 18+, Chrome, or Edge with a PRF-capable Passkey.",
});

// ============================================================================
// UI Controller
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

function copyText(text, btn, idleLabel) {
  return copyBrowserText(text, btn, idleLabel, { timeoutMs: 1800, fallbackLabel: "Copy manually" });
}

const appState = {
  mode: "landing", // "invite" | "certify"
  hjoin1: null,
  invite: null, // verified HumanInviteV1 or certify info
  adminJwk: null,
  expiresAtMs: null,
  countdownTimer: null,
  pollTimer: null,
  pollFailures: 0,
  localPort: DEFAULT_LOCAL_PORT,
  fallbackOpen: false,
  // Ephemeral in-RAM Passkey-derived key material (wiped after signing / on pagehide)
  humanId: "",
  prfSalt: "",
  authEpoch: 1,
  credentialId: "",
  edSeed32: null,
  edKp: null,
  encKp: null,
  hpub1: "",
};

function wipeSecretsInRam() {
  if (appState.edSeed32) {
    zeroize(appState.edSeed32);
    appState.edSeed32 = null;
  }
  if (appState.encKp?.privateKeyBytes) {
    zeroize(appState.encKp.privateKeyBytes);
  }
}

function stopTimers() {
  if (appState.countdownTimer) {
    clearInterval(appState.countdownTimer);
    appState.countdownTimer = null;
  }
  if (appState.pollTimer) {
    clearInterval(appState.pollTimer);
    appState.pollTimer = null;
  }
}

function showView(viewId) {
  for (const id of ["viewError", "viewLanding", "viewJoin"]) {
    $(id).classList.toggle("hidden", id !== viewId);
  }
}

function showStage(stage) {
  $("viewJoin").classList.toggle("is-joined", stage === 3);
  $("stageReview").classList.toggle("hidden", stage !== 1);
  $("stageConnect").classList.toggle("hidden", stage !== 2);
  $("stageDone").classList.toggle("hidden", stage !== 3);

  const d1 = $("stepDot1");
  const d2 = $("stepDot2");
  const d3 = $("stepDot3");
  d1.className = `step-pill ${stage === 1 ? "active" : "done"}`;
  d2.className = `step-pill ${stage === 2 ? "active" : stage > 2 ? "done" : ""}`;
  d3.className = `step-pill ${stage === 3 ? "active done" : ""}`;
}

function showErrorView(message) {
  stopTimers();
  wipeSecretsInRam();
  $("errorMessage").textContent = message;
  showView("viewError");
}

async function openParsedFragment(parsed) {
  if (parsed.mode === "landing") {
    showView("viewLanding");
    return;
  }

  if (parsed.mode === "invite") {
    const check = await verifyHumanInvite(parsed.hjoin1, null, Date.now());
    if (!check.ok) {
      showErrorView(check.message);
      return;
    }
    appState.mode = "invite";
    appState.hjoin1 = parsed.hjoin1;
    appState.invite = check.invite;
    appState.adminJwk = check.adminJwk;
    appState.expiresAtMs = check.expiresAtMs;
    appState.humanId = check.invite.humanId;
  } else if (parsed.mode === "certify") {
    appState.mode = "certify";
    appState.hjoin1 = null;
    appState.invite = {
      inviteId: "",
      hubNodeId: parsed.certify.hubNodeId,
      hubEndpoint: parsed.certify.hubEndpoint,
      hubFingerprint: parsed.certify.hubFingerprint ?? null,
      humanId: parsed.certify.humanId,
      nodePrefix: parsed.certify.nodePrefix || `${parsed.certify.humanId}@*`,
      scopes: Array.isArray(parsed.certify.scopes) ? parsed.certify.scopes : ["member"],
      maxDevices: parsed.certify.maxDevices || 10,
    };
    appState.adminJwk = null;
    appState.expiresAtMs = null;
    appState.humanId = parsed.certify.humanId;
  }

  await renderReviewStage();
  showView("viewJoin");
  showStage(1);
}

async function renderReviewStage() {
  const inv = appState.invite;
  $("metaHubNodeId").textContent = inv.hubNodeId;
  $("metaHumanPill").textContent = `human:${inv.humanId}`;
  $("metaModeBadge").textContent = appState.mode === "invite" ? "INVITE" : "CERTIFY";
  $("metaHubEndpoint").textContent = inv.hubEndpoint;
  $("metaPrefixBadge").textContent = inv.nodePrefix;

  $("reviewHumanId").textContent = inv.humanId;
  $("reviewNodePrefix").textContent = inv.nodePrefix;
  $("reviewMaxDevices").textContent = `Up to ${inv.maxDevices} device${inv.maxDevices === 1 ? "" : "s"}`;
  $("reviewHubFingerprint").textContent = inv.hubFingerprint || "Verified on connect";

  $("drawerHubEndpoint").textContent = inv.hubEndpoint;
  $("drawerInviteId").textContent = inv.inviteId || "Existing authority certification";
  $("drawerRawScopes").textContent = inv.scopes.join(" ");

  if (appState.adminJwk) {
    const adminSas = await sasFingerprint(appState.adminJwk);
    $("reviewAdminFpPreview").textContent = adminSas.formatted;
    $("drawerAdminFp").textContent = `${adminSas.formatted} (${adminSas.phrase})`;
  } else {
    $("reviewAdminFpPreview").textContent = "Direct certify";
    $("drawerAdminFp").textContent = "N/A (certifying additional device under existing authority)";
  }

  const chipsEl = $("reviewScopeChips");
  chipsEl.textContent = "";
  for (const s of inv.scopes) {
    const chip = document.createElement("span");
    chip.className = "scope-chip";
    chip.textContent = s;
    chipsEl.appendChild(chip);
  }
  $("reviewScopeCount").textContent = `${inv.scopes.length} scope${inv.scopes.length === 1 ? "" : "s"}`;

  // Populate agent & terminal copy blocks for Screen 2 right away.
  const prompts = buildAgentPrompts(inv.hubNodeId);
  $("promptAgentExisting").textContent = prompts.existing;
  $("promptAgentNew").textContent = prompts.fresh;

  // Check if user already has a saved Passkey hint for this humanId.
  const existingHint = loadPublicHint(inv.humanId);
  if (existingHint && existingHint.prfSalt) {
    $("btnContinuePasskeyLabel").textContent = "Continue with Existing Touch ID / Passkey";
    $("btnUseExistingPasskey").classList.remove("hidden");
  } else {
    $("btnContinuePasskeyLabel").textContent = "Continue with Touch ID / Passkey";
    $("btnUseExistingPasskey").classList.add("hidden");
  }

  if (appState.expiresAtMs) {
    const updateCountdown = () => {
      const remaining = appState.expiresAtMs - Date.now();
      const expEl = $("metaExpires");
      expEl.textContent = formatCountdown(remaining);
      expEl.className = remaining <= 0 ? "expiry-text danger" : "expiry-text";
      if (remaining <= 0) {
        $("btnContinuePasskey").disabled = true;
        setBanner(
          $("reviewBanner"),
          $("reviewBannerTitle"),
          $("reviewBannerBody"),
          "danger",
          "Invite Expired",
          "Ask your hub admin for a fresh `hyp auth invite` link."
        );
      }
    };
    updateCountdown();
    appState.countdownTimer = setInterval(updateCountdown, 1000);
  } else {
    $("metaExpires").textContent = "No expiry";
    $("metaExpires").className = "expiry-text";
  }
}

async function authenticateWithPasskey(forceCreateNew = false) {
  clearBanner($("reviewBanner"));
  $("btnContinuePasskey").disabled = true;
  $("passkeySpinner").classList.remove("hidden");

  try {
    const humanId = appState.humanId;
    const saved = !forceCreateNew ? loadPublicHint(humanId) : null;
    let prfSalt;
    let prfOut;
    let credentialId = "";
    let authEpoch = 1;

    if (saved && saved.prfSalt) {
      prfSalt = saved.prfSalt;
      authEpoch = Number.isInteger(saved.authEpoch) && saved.authEpoch >= 1 ? saved.authEpoch : 1;
      const res = await evaluatePasskeyPrf(humanId, prfSalt, saved.credentialId || "");
      prfOut = res.prfOut;
      credentialId = res.credentialId || saved.credentialId || "";
    } else {
      prfSalt = base64urlEncode(randomBytes(16));
      const res = await enrollPasskeyWithPrf(humanId, prfSalt);
      prfOut = res.prfOut;
      credentialId = res.credentialId;
    }

    let edSeed32;
    try {
      edSeed32 = await derivePrfEd25519Seed(prfOut, humanId, authEpoch);
      const edKp = await ed25519KeypairFromSeed(edSeed32);
      const encKp = await derivePrfX25519Keypair(prfOut, humanId, authEpoch);
      const hpub1 = encodeHpub1({
        v: 1,
        humanId,
        signingJwk: edKp.publicJwk,
        encJwk: encKp.publicJwk,
      });

      appState.prfSalt = prfSalt;
      appState.authEpoch = authEpoch;
      appState.credentialId = credentialId;
      appState.edSeed32 = edSeed32;
      appState.edKp = edKp;
      appState.encKp = encKp;
      appState.hpub1 = hpub1;

      savePublicHint(humanId, { prfSalt, authEpoch, credentialId });
      const fp = await sasFingerprint(edKp.publicJwk);
      $("passkeyStripText").textContent = `Passkey ready · ${humanId} (${fp.formatted})`;
      $("doneHumanFpPreview").textContent = fp.formatted;
      $("doneHpub1Box").textContent = hpub1;
    } finally {
      zeroize(prfOut);
    }

    showStage(2);
    startLoopbackPolling();
  } catch (err) {
    setBanner(
      $("reviewBanner"),
      $("reviewBannerTitle"),
      $("reviewBannerBody"),
      "danger",
      "Passkey Authentication Failed",
      err instanceof Error ? err.message : String(err)
    );
  } finally {
    $("btnContinuePasskey").disabled = false;
    $("passkeySpinner").classList.add("hidden");
  }
}

function localBaseUrl() {
  return `http://127.0.0.1:${appState.localPort}`;
}

function showConnectSubPane(which) {
  $("connectWaitingPane").classList.toggle("hidden", which !== "waiting");
  $("connectCodePane").classList.toggle("hidden", which !== "code");
  $("connectFallbackPane").classList.toggle("hidden", which !== "fallback");
  appState.fallbackOpen = which === "fallback";
  $("btnToggleFallback").textContent = appState.fallbackOpen ? "Back to Local Mode" : "Safari / Remote VPS";
}

async function pollLocalHealthOnce() {
  if (appState.fallbackOpen) return;
  try {
    const resp = await fetch(`${localBaseUrl()}/health`, {
      method: "GET",
      mode: "cors",
      cache: "no-store",
    });
    if (resp.ok) {
      const data = await resp.json();
      if (data && data.ok === true && data.mode === "hyphae-join") {
        appState.pollFailures = 0;
        if (appState.pollTimer) {
          clearInterval(appState.pollTimer);
          appState.pollTimer = null;
        }
        showConnectSubPane("code");
        $("inputJoinCode").focus();
        return;
      }
    }
  } catch {
    appState.pollFailures += 1;
    if (appState.pollFailures >= SAFARI_FALLBACK_FAILURE_THRESHOLD) {
      $("pollStatusText").textContent =
        `Waiting for hyp join on 127.0.0.1:${appState.localPort} (using Safari or a remote server? Click "Safari / Remote VPS" above).`;
    }
  }
}

function setPollStatusListening(port) {
  const el = $("pollStatusText");
  el.textContent = "";
  el.appendChild(document.createTextNode("Listening for local "));
  const codeCmd = document.createElement("code");
  codeCmd.textContent = "hyp join";
  el.appendChild(codeCmd);
  el.appendChild(document.createTextNode(" on "));
  const codeAddr = document.createElement("code");
  codeAddr.textContent = `127.0.0.1:${port}`;
  el.appendChild(codeAddr);
  el.appendChild(document.createTextNode("…"));
}

function startLoopbackPolling() {
  if (appState.pollTimer) {
    clearInterval(appState.pollTimer);
  }
  appState.pollFailures = 0;
  setPollStatusListening(appState.localPort);
  showConnectSubPane("waiting");
  pollLocalHealthOnce();
  appState.pollTimer = setInterval(pollLocalHealthOnce, POLL_INTERVAL_MS);
}

async function buildSignedHandoffForDevice(deviceInfo) {
  if (!appState.edSeed32 || !appState.edKp) {
    throw new Error("Passkey session is locked — reload the invite link to authenticate again.");
  }
  const inv = appState.invite;
  if (!deviceInfo || typeof deviceInfo !== "object" || !isValidNodeId(deviceInfo.nodeId)) {
    throw new Error("Device info is missing a valid nodeId");
  }
  decodeOkpJwkBytes(deviceInfo.ed25519Jwk, "Ed25519");
  decodeOkpJwkBytes(deviceInfo.x25519Jwk, "X25519");

  if (!matchesNodePrefix(inv.nodePrefix, deviceInfo.nodeId)) {
    throw new Error(
      `Device nodeId "${deviceInfo.nodeId}" does NOT match allowed prefix "${inv.nodePrefix}". Restart \`hyp join --node-id ${inv.humanId}@<device>\`.`
    );
  }

  const nowMs = Date.now();
  const certRes = await signNodeCert(
    {
      nodeId: deviceInfo.nodeId,
      signingJwk: deviceInfo.ed25519Jwk,
      encryptionJwk: deviceInfo.x25519Jwk,
      humanId: appState.humanId,
      humanKid: appState.edKp.kid,
      authEpoch: appState.authEpoch,
      issuedAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + 365 * 24 * 60 * 60 * 1000).toISOString(),
    },
    appState.edSeed32
  );

  const bundle = {
    humanAuthority: {
      humanId: appState.humanId,
      signingJwk: appState.edKp.publicJwk,
      encJwk: appState.encKp?.publicJwk ?? null,
      prfSalt: appState.prfSalt || null,
      authEpoch: appState.authEpoch,
      label: "passkey-delegated",
    },
    nodeCert: certRes.hcert1,
    hubNodeId: inv.hubNodeId,
    hubEndpoint: inv.hubEndpoint,
    hubFingerprint: inv.hubFingerprint ?? null,
  };

  if (appState.hjoin1) {
    const claimRes = await signHumanInviteClaim(
      {
        inviteId: inv.inviteId,
        hubNodeId: inv.hubNodeId,
        humanId: appState.humanId,
        signingJwk: appState.edKp.publicJwk,
        encJwk: appState.encKp?.publicJwk ?? undefined,
        prfSalt: appState.prfSalt || undefined,
        timestamp: new Date(nowMs).toISOString(),
      },
      appState.edSeed32
    );
    bundle.hjoin1 = appState.hjoin1;
    bundle.humanClaim = claimRes.claim;
    bundle.humanClaimSig = claimRes.sig;
  }

  return bundle;
}

async function handleVerifyCodeAndApprove() {
  clearBanner($("codeActionBanner"));
  const rawCode = $("inputJoinCode").value.replace(/\D/g, "");
  if (rawCode.length !== 6) {
    setBanner(
      $("codeActionBanner"),
      $("codeActionTitle"),
      $("codeActionBody"),
      "warn",
      "6-Digit Code Required",
      "Enter all 6 digits displayed by `hyp join` in your terminal."
    );
    return;
  }

  $("btnVerifyAndApprove").disabled = true;
  $("approveSpinner").classList.remove("hidden");

  try {
    // 1. Fetch local device public keys with the 6-digit code.
    const infoResp = await fetch(`${localBaseUrl()}/device-info`, {
      method: "POST",
      mode: "cors",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "X-Hyphae-Join-Code": rawCode,
      },
      body: JSON.stringify({ humanId: appState.humanId }),
    });
    const infoData = await infoResp.json().catch(() => ({}));
    if (!infoResp.ok || !infoData.ok) {
      const rem = typeof infoData.attemptsRemaining === "number"
        ? ` (${infoData.attemptsRemaining} attempt${infoData.attemptsRemaining === 1 ? "" : "s"} remaining)`
        : "";
      throw new Error(
        infoData.error === "code_attempts_exceeded"
          ? "Too many wrong confirmation codes — `hyp join` locked out. Restart `hyp join` in your terminal."
          : `Confirmation code rejected${rem}. Check the 6-digit code in your terminal.`
      );
    }

    // 2. Preview device identity and validate nodePrefix match BEFORE signing!
    const deviceSas = await sasFingerprint(infoData.ed25519Jwk);
    const prefixOk = matchesNodePrefix(appState.invite.nodePrefix, infoData.nodeId);
    $("previewDeviceNodeId").textContent = infoData.nodeId;
    $("previewPrefixMatch").textContent = prefixOk
      ? `Matches ${appState.invite.nodePrefix}`
      : `MISMATCH (expected ${appState.invite.nodePrefix})`;
    $("previewDeviceSas").textContent = `${deviceSas.formatted} · ${deviceSas.phrase}`;
    $("devicePreviewCard").classList.remove("hidden");

    const handoffBundle = await buildSignedHandoffForDevice(infoData);

    // 3. POST signed handoff bundle to local `hyp join` `/complete`.
    const completeResp = await fetch(`${localBaseUrl()}/complete`, {
      method: "POST",
      mode: "cors",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "X-Hyphae-Join-Code": rawCode,
      },
      body: JSON.stringify(handoffBundle),
    });
    const completeData = await completeResp.json().catch(() => ({}));
    if (!completeResp.ok || !completeData.ok) {
      throw new Error(completeData.message || completeData.error || "Local CLI rejected the handoff bundle");
    }

    // 4. Wipe ephemeral keys from RAM immediately and show success screen!
    wipeSecretsInRam();
    stopTimers();
    $("doneNodeId").textContent = infoData.nodeId;
    $("doneHubNodeId").textContent = appState.invite.hubNodeId;
    $("doneHumanId").textContent = appState.humanId;
    showStage(3);
  } catch (err) {
    setBanner(
      $("codeActionBanner"),
      $("codeActionTitle"),
      $("codeActionBody"),
      "danger",
      "Device Approval Failed",
      err instanceof Error ? err.message : String(err)
    );
  } finally {
    $("btnVerifyAndApprove").disabled = false;
    $("approveSpinner").classList.add("hidden");
  }
}

async function handleSignRemoteDeviceCard() {
  clearBanner($("fallbackErrorBanner"));
  $("remoteSignedResult").classList.add("hidden");
  const raw = $("inputRemoteDeviceCard").value.trim();
  if (!raw) {
    setBanner(
      $("fallbackErrorBanner"),
      $("fallbackErrorTitle"),
      $("fallbackErrorBody"),
      "warn",
      "Device Card Required",
      "Run `hyp join --remote` on your target machine and paste the JSON card above."
    );
    return;
  }

  $("btnSignRemoteBundle").disabled = true;
  $("remoteSignSpinner").classList.remove("hidden");
  try {
    const deviceInfo = JSON.parse(raw);
    const bundle = await buildSignedHandoffForDevice(deviceInfo);
    const serialized = JSON.stringify(bundle);
    $("outputSignedBundle").textContent = serialized;
    const prompts = buildAgentPrompts(appState.invite.hubNodeId);
    $("promptFinishRemote").textContent = `${prompts.remoteFinish}\n\n${serialized}`;
    $("remoteSignedResult").classList.remove("hidden");
  } catch (err) {
    setBanner(
      $("fallbackErrorBanner"),
      $("fallbackErrorTitle"),
      $("fallbackErrorBody"),
      "danger",
      "Could Not Sign Device Card",
      err instanceof Error ? err.message : String(err)
    );
  } finally {
    $("btnSignRemoteBundle").disabled = false;
    $("remoteSignSpinner").classList.add("hidden");
  }
}

function initBrowserApp() {
  const rawHash = window.location.hash;
  if (rawHash) {
    try {
      history.replaceState(null, "", window.location.pathname);
    } catch {
      // Ignore restricted history APIs.
    }
  }

  if (isEmbeddedInFrame()) {
    showErrorView("Refused to open inside an embedded frame for clickjacking protection.");
    return;
  }

  window.addEventListener("pagehide", () => {
    stopTimers();
    wipeSecretsInRam();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden" && !appState.hjoin1) {
      wipeSecretsInRam();
    }
  });

  $("btnOpenManualInvite").addEventListener("click", async () => {
    clearBanner($("landingErrorBanner"));
    try {
      const parsed = parseJoinFragment($("inputManualInvite").value);
      if (parsed.mode === "landing") {
        throw new Error("Paste a full https://hyphae.to/join#hjoin1_... link or hjoin1_... token.");
      }
      await openParsedFragment(parsed);
    } catch (err) {
      setBanner(
        $("landingErrorBanner"),
        $("landingErrorTitle"),
        $("landingErrorBody"),
        "danger",
        "Invalid Invite",
        err instanceof Error ? err.message : String(err)
      );
    }
  });

  $("btnContinuePasskey").addEventListener("click", () => authenticateWithPasskey(false));
  $("btnUseExistingPasskey").addEventListener("click", () => authenticateWithPasskey(true));

  $("btnToggleFallback").addEventListener("click", () => {
    if (appState.fallbackOpen) {
      startLoopbackPolling();
    } else {
      if (appState.pollTimer) {
        clearInterval(appState.pollTimer);
        appState.pollTimer = null;
      }
      showConnectSubPane("fallback");
    }
  });

  $("btnApplyPort").addEventListener("click", () => {
    const val = Number.parseInt($("inputLocalPort").value, 10);
    if (Number.isInteger(val) && val >= 1024 && val <= 65535) {
      appState.localPort = val;
      $("customPortPreview").textContent = String(val);
      startLoopbackPolling();
    }
  });

  $("inputJoinCode").addEventListener("input", (ev) => {
    ev.target.value = formatSixDigitCodeInput(ev.target.value);
  });
  $("inputJoinCode").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      handleVerifyCodeAndApprove();
    }
  });

  $("btnVerifyAndApprove").addEventListener("click", handleVerifyCodeAndApprove);
  $("btnBackToWait").addEventListener("click", () => startLoopbackPolling());
  $("btnSignRemoteBundle").addEventListener("click", handleSignRemoteDeviceCard);

  $("btnCopyAgentExisting").addEventListener("click", () =>
    copyText($("promptAgentExisting").textContent, $("btnCopyAgentExisting"), "Copy")
  );
  $("btnCopyAgentNew").addEventListener("click", () =>
    copyText($("promptAgentNew").textContent, $("btnCopyAgentNew"), "Copy")
  );
  $("btnCopyTermExisting").addEventListener("click", () =>
    copyText($("cmdTermExisting").textContent, $("btnCopyTermExisting"), "Copy")
  );
  $("btnCopyTermNew").addEventListener("click", () =>
    copyText($("cmdTermNew").textContent, $("btnCopyTermNew"), "Copy")
  );
  $("btnCopyRemoteCmd").addEventListener("click", () =>
    copyText($("cmdRemoteCard").textContent, $("btnCopyRemoteCmd"), "Copy")
  );
  $("btnCopySignedBundle").addEventListener("click", () =>
    copyText($("outputSignedBundle").textContent, $("btnCopySignedBundle"), "Copy Bundle")
  );
  $("btnCopyFinishPrompt").addEventListener("click", () =>
    copyText($("promptFinishRemote").textContent, $("btnCopyFinishPrompt"), "Copy Prompt")
  );
  $("btnCopyHpub1").addEventListener("click", () =>
    copyText($("doneHpub1Box").textContent, $("btnCopyHpub1"), "Copy")
  );

  try {
    const parsed = parseJoinFragment(rawHash);
    openParsedFragment(parsed);
  } catch (err) {
    showErrorView(err instanceof Error ? err.message : String(err));
  }
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initBrowserApp);
  } else {
    initBrowserApp();
  }
}
