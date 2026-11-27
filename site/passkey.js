import { base64urlDecode, base64urlEncode, prfEvalInput, randomBytes, utf8Bytes } from "./drop/crypto.js?v=4";

function getRpId() {
  const host = window.location.hostname;
  if (!host || /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":")) {
    return undefined;
  }
  return host;
}

export function coerceBytes(val, allowSerializedBytes = false) {
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
  if (allowSerializedBytes && typeof val === "object") {
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

export function extractPrfFirst(cred, allowSerializedBytes = false) {
  const ext = typeof cred?.getClientExtensionResults === "function"
    ? cred.getClientExtensionResults()
    : null;
  const first = ext?.prf?.results?.first;
  if (!first) return null;
  const bytes = coerceBytes(first, allowSerializedBytes);
  return bytes && bytes.length === 32 ? bytes : null;
}

export function createPasskeyOperations({
  rpName,
  missingPrfMessage,
  allowSerializedBytes = false,
}) {
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
    const prfOut = extractPrfFirst(assertion, allowSerializedBytes);
    if (!prfOut) {
      throw new Error(missingPrfMessage);
    }
    const rawId = coerceBytes(assertion.rawId, allowSerializedBytes);
    const credentialId = rawId ? base64urlEncode(rawId) : (typeof assertion.id === "string" ? assertion.id : "");
    return { prfOut, credentialId };
  }

  async function enrollPasskeyWithPrf(humanId, prfSalt) {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      throw new Error("WebAuthn Passkeys are not supported in this browser");
    }
    const evalInput = await prfEvalInput(humanId, prfSalt);
    const rpId = getRpId();
    const rp = rpId ? { name: rpName, id: rpId } : { name: rpName };

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
    const rawId = coerceBytes(created.rawId, allowSerializedBytes);
    const credId = rawId ? base64urlEncode(rawId) : (typeof created.id === "string" ? created.id : "");
    const ext = typeof created.getClientExtensionResults === "function"
      ? created.getClientExtensionResults()
      : null;

    let prfOut = extractPrfFirst(created, allowSerializedBytes);
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

  return { evaluatePasskeyPrf, enrollPasskeyWithPrf };
}

export async function copyText(text, btn, idleLabel, { timeoutMs, fallbackLabel }) {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = "Copied!";
    setTimeout(() => {
      btn.textContent = idleLabel;
    }, timeoutMs);
  } catch {
    btn.textContent = fallbackLabel;
  }
}

export function isEmbeddedInFrame(win = typeof window !== "undefined" ? window : null) {
  if (!win) return false;
  try {
    return win.top !== win.self;
  } catch {
    // Cross-origin frame access throws SecurityError — fail closed.
    return true;
  }
}
