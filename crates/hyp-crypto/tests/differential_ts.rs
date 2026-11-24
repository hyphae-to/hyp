//! Live cross-language Node.js (TypeScript v1) <-> Rust (`hyp-crypto`) McKeeman Differential Tests.
//!
//! Spawns `node --experimental-strip-types` importing the real TypeScript v1 modules:
//! - `src/core/identity/keys.ts`
//! - `src/core/identity/grant.ts`
//! - `src/identity.ts`
//! - `src/core/transfer/seal.ts`
//! - `src/core/transfer/pack.ts`
//!
//! Verifies 100% byte-for-byte bidirectional interoperability (TS -> Rust AND Rust -> TS),
//! plus independent Node `node:crypto` verification of RFC 9180 HPKE AES-256-GCM,
//! RFC 7638 JWK Thumbprints, and system `tar -tzf` compatibility.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use tempfile::TempDir;

use hyp_crypto::compat_v1::{
    create_key_registration_v1, issue_grant_v1, open_grant_v1, open_revocation_v1, open_v1,
    pack_hyp1, parse_pairing_code_v1, seal_v1, sign_binding_v1, sign_revocation_v1, unpack_hyp1,
    verify_entry_v1, verify_key_registration_v1, EntryV1, KeyRegistrationV1, SealInputV1, SignedV1,
};
use hyp_crypto::hpke;
use hyp_crypto::keys::{
    is_small_order_ed25519_point, Ed25519KeyPair, Ed25519PublicKey, X25519KeyPair, X25519PublicKey,
};
use hyp_crypto::rfc3339::now_unix_ms;
use hyp_crypto::transfer::{pack_tar_gz_bytes, TarPackOptions};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn find_node_bin() -> PathBuf {
    let preferred = PathBuf::from("/Users/bogdan/.local/share/mise/installs/node/24.21.0/bin/node");
    if preferred.exists() {
        return preferred;
    }
    PathBuf::from("node")
}

fn run_node_ts(script: &str, stdin_json: &Value) -> Value {
    let mut child = Command::new(find_node_bin())
        .current_dir(repo_root())
        .args(["--experimental-strip-types", "--input-type=module", "-e", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn node 24");

    {
        let mut stdin = child.stdin.take().unwrap();
        let payload = serde_json::to_vec(stdin_json).unwrap();
        stdin.write_all(&payload).unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "node script failed (exit {:?}):\nSTDOUT:\n{}\nSTDERR:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("node stdout was not valid JSON")
}

#[test]
fn differential_ts_to_rust_keys_grants_bindings_keyreg_seal_and_hyp1() {
    let tmp = TempDir::new().unwrap();
    let f1 = tmp.path().join("alpha.txt");
    let f2 = tmp.path().join("beta.json");
    fs::write(&f1, b"Hello from TypeScript v1 pack!").unwrap();
    fs::write(&f2, b"{\"mesh\":\"hyphae\",\"v\":1}\n").unwrap();

    let script = r#"
import fs from "node:fs";
import {
  generatePrivateKey, exportPrivateKey, rawPublicKey, fingerprint, isSmallOrderPoint
} from "./src/core/identity/keys.ts";
import {
  issueGrant, parsePairingCode, signBinding, signRevocation
} from "./src/core/identity/grant.ts";
import { createKeyRegistration } from "./src/identity.ts";
import { seal } from "./src/core/transfer/seal.ts";
import { packFiles } from "./src/core/transfer/pack.ts";

const input = JSON.parse(fs.readFileSync(0, "utf8"));

const adminKey = generatePrivateKey("ed25519");
const aliceSign = generatePrivateKey("ed25519");
const aliceEnc = generatePrivateKey("x25519");
const bobEnc = generatePrivateKey("x25519");

const now = new Date("2026-11-24T12:00:00.000Z");
const issued = issueGrant(adminKey, "alice@macbook", ["messages:*", "files:*"], 300_000, now);
const parsedCode = parsePairingCode(issued.code);
const binding = signBinding(issued.grant, parsedCode, aliceSign, aliceEnc, now);
const entry = { grant: issued.signed, binding };
const revocation = signRevocation(adminKey, "alice@macbook", issued.grant.id, now);

const aliceKeys = {
  signingKey: aliceSign,
  encryptionKey: aliceEnc,
  signingPublic: rawPublicKey(aliceSign),
  encryptionPublic: rawPublicKey(aliceEnc),
  fingerprint: fingerprint(rawPublicKey(aliceSign)),
};
const keyReg = createKeyRegistration("alice@macbook", aliceKeys);

const packed = packFiles(input.files, { fromHandle: "claude", note: "from-ts" });
const sealed = seal(
  {
    id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    type: "files",
    from: "alice@macbook",
    to: "bob@laptop",
    toHandle: "codex",
    ttlMs: 120_000,
  },
  packed.payload,
  aliceSign,
  rawPublicKey(bobEnc),
  now,
);

const smallOrderChecks = input.pointsHex.map((h) => isSmallOrderPoint(Buffer.from(h, "hex")));

console.log(JSON.stringify({
  adminPkcs8: exportPrivateKey(adminKey),
  adminPub: rawPublicKey(adminKey),
  adminFp: fingerprint(rawPublicKey(adminKey)),
  aliceSignPkcs8: exportPrivateKey(aliceSign),
  aliceSignPub: rawPublicKey(aliceSign),
  aliceEncPkcs8: exportPrivateKey(aliceEnc),
  aliceEncPub: rawPublicKey(aliceEnc),
  bobEncPkcs8: exportPrivateKey(bobEnc),
  bobEncPub: rawPublicKey(bobEnc),
  issued,
  entry,
  revocation,
  keyReg,
  sealedHeader: sealed.header,
  sealedCiphertextB64: sealed.ciphertext.toString("base64url"),
  packedPayloadB64: packed.payload.toString("base64url"),
  smallOrderChecks,
}));
"#;

    let sample_points_hex = vec![
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29", // valid Ed25519 pubkey
    ];

    let out = run_node_ts(
        script,
        &json!({
            "files": [f1.to_str().unwrap(), f2.to_str().unwrap()],
            "pointsHex": sample_points_hex,
        }),
    );

    // 1. Differential PKCS#8 import/export byte-for-byte parity
    let admin_kp = Ed25519KeyPair::from_pkcs8_b64(out["adminPkcs8"].as_str().unwrap()).unwrap();
    assert_eq!(admin_kp.public_key_b64(), out["adminPub"].as_str().unwrap());
    assert_eq!(admin_kp.fingerprint(), out["adminFp"].as_str().unwrap());
    assert_eq!(&*admin_kp.export_pkcs8_b64(), out["adminPkcs8"].as_str().unwrap());

    let alice_sign = Ed25519KeyPair::from_pkcs8_b64(out["aliceSignPkcs8"].as_str().unwrap()).unwrap();
    assert_eq!(alice_sign.public_key_b64(), out["aliceSignPub"].as_str().unwrap());
    assert_eq!(&*alice_sign.export_pkcs8_b64(), out["aliceSignPkcs8"].as_str().unwrap());

    let alice_enc = X25519KeyPair::from_pkcs8_b64(out["aliceEncPkcs8"].as_str().unwrap()).unwrap();
    assert_eq!(alice_enc.public_key_b64(), out["aliceEncPub"].as_str().unwrap());
    assert_eq!(&*alice_enc.export_pkcs8_b64(), out["aliceEncPkcs8"].as_str().unwrap());

    let bob_enc = X25519KeyPair::from_pkcs8_b64(out["bobEncPkcs8"].as_str().unwrap()).unwrap();
    assert_eq!(bob_enc.public_key_b64(), out["bobEncPub"].as_str().unwrap());
    assert_eq!(&*bob_enc.export_pkcs8_b64(), out["bobEncPkcs8"].as_str().unwrap());

    // 2. Differential small-order point check
    let ts_checks = out["smallOrderChecks"].as_array().unwrap();
    for (hex_pt, ts_val) in sample_points_hex.iter().zip(ts_checks.iter()) {
        let bytes = hex::decode(hex_pt).unwrap();
        assert_eq!(
            is_small_order_ed25519_point(&bytes),
            ts_val.as_bool().unwrap(),
            "small-order mismatch for {hex_pt}"
        );
    }

    // 3. Rust verifies TS Grant, t3mp1_ code, Entry, Revocation, KeyRegistration
    let signed_grant: SignedV1 = serde_json::from_value(out["issued"]["signed"].clone()).unwrap();
    let grant = open_grant_v1(&signed_grant, &admin_kp.public_key()).unwrap();
    assert_eq!(grant.connector_id, "alice@macbook");

    let code = parse_pairing_code_v1(out["issued"]["code"].as_str().unwrap()).unwrap();
    assert_eq!(code.grant_id, grant.id);
    assert_eq!(code.admin_fingerprint, admin_kp.fingerprint());

    let entry: EntryV1 = serde_json::from_value(out["entry"].clone()).unwrap();
    let identity = verify_entry_v1(&entry, &admin_kp.public_key()).unwrap();
    assert_eq!(identity.connector_id, "alice@macbook");
    assert_eq!(identity.signing_key, alice_sign.public_key_b64());
    assert_eq!(identity.encryption_key, alice_enc.public_key_b64());

    let rev_signed: SignedV1 = serde_json::from_value(out["revocation"].clone()).unwrap();
    let rev = open_revocation_v1(&rev_signed, &admin_kp.public_key()).unwrap();
    assert_eq!(rev.grant_id, grant.id);

    let key_reg: KeyRegistrationV1 = serde_json::from_value(out["keyReg"].clone()).unwrap();
    let (reg_sign_pk, reg_enc_pk) = verify_key_registration_v1("alice@macbook", &key_reg).unwrap();
    assert_eq!(reg_sign_pk, alice_sign.public_key());
    assert_eq!(reg_enc_pk, alice_enc.public_key());

    // 4. Rust opens TS sealed transfer and unpacks TS HYP1 archive
    let sealed_header: SignedV1 = serde_json::from_value(out["sealedHeader"].clone()).unwrap();
    let sealed_ct = URL_SAFE_NO_PAD
        .decode(out["sealedCiphertextB64"].as_str().unwrap())
        .unwrap();
    let (hdr, opened_pack) =
        open_v1(&sealed_header, &sealed_ct, &alice_sign.public_key(), &bob_enc).unwrap();
    assert_eq!(hdr.from, "alice@macbook");
    assert_eq!(hdr.to, "bob@laptop");
    assert_eq!(hdr.to_handle.as_deref(), Some("codex"));

    let unpack_dir = tmp.path().join("rust-unpacked");
    let unpacked = unpack_hyp1(&opened_pack, &unpack_dir, None, None).unwrap();
    assert_eq!(unpacked.from_handle.as_deref(), Some("claude"));
    assert_eq!(unpacked.note.as_deref(), Some("from-ts"));
    assert_eq!(unpacked.files.len(), 2);
    assert_eq!(
        fs::read(&unpacked.files[0].path).unwrap(),
        b"Hello from TypeScript v1 pack!"
    );
    assert_eq!(
        fs::read(&unpacked.files[1].path).unwrap(),
        b"{\"mesh\":\"hyphae\",\"v\":1}\n"
    );
}

#[test]
fn differential_rust_to_ts_keys_grants_bindings_keyreg_seal_and_hyp1() {
    let tmp = TempDir::new().unwrap();
    let f1 = tmp.path().join("rust-hello.txt");
    let f2 = tmp.path().join("metrics.csv");
    fs::write(&f1, b"Hello from Rust hyp-crypto v2!").unwrap();
    fs::write(&f2, b"k,v\nlatency_ms,1.8\n").unwrap();

    let admin_kp = Ed25519KeyPair::generate().unwrap();
    let alice_sign = Ed25519KeyPair::generate().unwrap();
    let alice_enc = X25519KeyPair::generate().unwrap();
    let bob_enc = X25519KeyPair::generate().unwrap();
    let now = now_unix_ms();

    let issued = issue_grant_v1(&admin_kp, "alice@rustbox", &["*"], 300_000, now).unwrap();
    let parsed_code = parse_pairing_code_v1(&issued.code).unwrap();
    let binding = sign_binding_v1(&issued.grant, &parsed_code, &alice_sign, &alice_enc, now).unwrap();
    let entry = EntryV1 {
        grant: issued.signed.clone(),
        binding,
    };
    let revocation = sign_revocation_v1(&admin_kp, "alice@rustbox", &issued.grant.id, now).unwrap();
    let key_reg = create_key_registration_v1("alice@rustbox", &alice_sign, &alice_enc).unwrap();

    let packed = pack_hyp1(
        &[f1.as_path(), f2.as_path()],
        Some("antigravity"),
        Some("from-rust"),
        None,
        None,
    )
    .unwrap();
    let sealed = seal_v1(
        &SealInputV1 {
            id: "12345678-9abc-4def-8012-3456789abcde",
            transfer_type: "files",
            from: "alice@rustbox",
            to: "bob@tsbox",
            to_handle: Some("claude"),
            ttl_ms: 180_000,
        },
        &packed.payload,
        &alice_sign,
        &bob_enc.public_key(),
        now,
    )
    .unwrap();

    let ts_unpack_dir = tmp.path().join("ts-unpacked");

    let script = r#"
import fs from "node:fs";
import {
  importPrivateKey, rawPublicKey, publicKeyFromRaw, fingerprint
} from "./src/core/identity/keys.ts";
import {
  openGrant, parsePairingCode, verifyEntry, openRevocation
} from "./src/core/identity/grant.ts";
import { verifyKeyRegistration } from "./src/identity.ts";
import { open } from "./src/core/transfer/seal.ts";
import { unpackFiles } from "./src/core/transfer/pack.ts";

const input = JSON.parse(fs.readFileSync(0, "utf8"));

const adminPriv = importPrivateKey(input.adminPkcs8, "ed25519");
const aliceSignPriv = importPrivateKey(input.aliceSignPkcs8, "ed25519");
const aliceEncPriv = importPrivateKey(input.aliceEncPkcs8, "x25519");
const bobEncPriv = importPrivateKey(input.bobEncPkcs8, "x25519");

const adminPubObj = publicKeyFromRaw(input.adminPub, "ed25519");
const aliceSignPubObj = publicKeyFromRaw(input.aliceSignPub, "ed25519");

const grant = openGrant(input.signedGrant, adminPubObj);
if (!grant) throw new Error("TS openGrant failed");

const code = parsePairingCode(input.code);
if (!code || code.grantId !== grant.id || code.adminFingerprint !== fingerprint(input.adminPub)) {
  throw new Error("TS parsePairingCode failed");
}

const verifiedEntry = verifyEntry(input.entry, adminPubObj);
if (!verifiedEntry.ok) throw new Error("TS verifyEntry failed: " + verifiedEntry.reason);

const rev = openRevocation(input.revocation, adminPubObj);
if (!rev || rev.grantId !== grant.id) throw new Error("TS openRevocation failed");

const regCheck = verifyKeyRegistration("alice@rustbox", input.keyReg);
if (!regCheck.ok) throw new Error("TS verifyKeyRegistration failed: " + regCheck.message);

const ct = Buffer.from(input.sealedCtB64, "base64url");
const opened = open(input.sealedHeader, ct, aliceSignPubObj, bobEncPriv);
const unpacked = unpackFiles(opened.plaintext, input.destDir);

console.log(JSON.stringify({
  adminPub: rawPublicKey(adminPriv),
  adminFp: fingerprint(rawPublicKey(adminPriv)),
  aliceSignPub: rawPublicKey(aliceSignPriv),
  aliceEncPub: rawPublicKey(aliceEncPriv),
  bobEncPub: rawPublicKey(bobEncPriv),
  entryIdentity: verifiedEntry.identity,
  fromHandle: unpacked.fromHandle,
  note: unpacked.note,
  files: unpacked.files.map((f) => ({
    name: f.name,
    content: fs.readFileSync(f.path, "utf8"),
    sha256: f.sha256,
  })),
}));
"#;

    let res = run_node_ts(
        script,
        &json!({
            "adminPkcs8": &*admin_kp.export_pkcs8_b64(),
            "adminPub": admin_kp.public_key_b64(),
            "aliceSignPkcs8": &*alice_sign.export_pkcs8_b64(),
            "aliceSignPub": alice_sign.public_key_b64(),
            "aliceEncPkcs8": &*alice_enc.export_pkcs8_b64(),
            "aliceEncPub": alice_enc.public_key_b64(),
            "bobEncPkcs8": &*bob_enc.export_pkcs8_b64(),
            "bobEncPub": bob_enc.public_key_b64(),
            "signedGrant": issued.signed,
            "code": issued.code,
            "entry": entry,
            "revocation": revocation,
            "keyReg": key_reg,
            "sealedHeader": sealed.header,
            "sealedCtB64": URL_SAFE_NO_PAD.encode(&sealed.ciphertext),
            "destDir": ts_unpack_dir.to_str().unwrap(),
        }),
    );

    assert_eq!(res["adminPub"].as_str().unwrap(), admin_kp.public_key_b64());
    assert_eq!(res["adminFp"].as_str().unwrap(), admin_kp.fingerprint());
    assert_eq!(res["aliceSignPub"].as_str().unwrap(), alice_sign.public_key_b64());
    assert_eq!(res["aliceEncPub"].as_str().unwrap(), alice_enc.public_key_b64());
    assert_eq!(res["bobEncPub"].as_str().unwrap(), bob_enc.public_key_b64());
    assert_eq!(res["fromHandle"].as_str().unwrap(), "antigravity");
    assert_eq!(res["note"].as_str().unwrap(), "from-rust");
    let files = res["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["name"].as_str().unwrap(), "rust-hello.txt");
    assert_eq!(files[0]["content"].as_str().unwrap(), "Hello from Rust hyp-crypto v2!");
    assert_eq!(files[1]["name"].as_str().unwrap(), "metrics.csv");
    assert_eq!(files[1]["content"].as_str().unwrap(), "k,v\nlatency_ms,1.8\n");
}

/// Independent cross-language McKeeman differential oracle for RFC 9180 HPKE
/// `DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM` and RFC 7638 JWK Thumbprints.
#[test]
fn differential_rfc9180_hpke_aes256gcm_and_jwk_thumbprint_against_node_crypto() {
    let recipient = X25519KeyPair::generate().unwrap();
    let signer = Ed25519KeyPair::generate().unwrap();
    let info = b"hyphae/v2/differential-hpke-test";
    let aad = b"aad-binding-context";
    let pt = b"Confidential Hyphae v2 HPKE AES-256-GCM payload verified across Rust & Node!";

    let (enc, ct) = hpke::seal_base(&recipient.public_key(), info, aad, pt).unwrap();

    let script = r#"
import fs from "node:fs";
import { createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from "node:crypto";

const input = JSON.parse(fs.readFileSync(0, "utf8"));

// 1. Independent RFC 7638 OKP JWK thumbprint check
function thumbprint(jwk) {
  const canon = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return createHash("sha256").update(canon, "utf8").digest("base64url");
}
// Verify Node node:crypto accepts our JWKs natively
createPublicKey({ key: input.signJwk, format: "jwk" });
createPublicKey({ key: input.encJwk, format: "jwk" });

// 2. Independent RFC 9180 HPKE Base Mode (X25519 / HKDF-SHA256 / AES-256-GCM) Decap + Open
const KEM_SUITE = Buffer.concat([Buffer.from("KEM"), Buffer.from([0x00, 0x20])]);
const HPKE_SUITE = Buffer.concat([Buffer.from("HPKE"), Buffer.from([0x00, 0x20, 0x00, 0x01, 0x00, 0x02])]);
const HPKE_V1 = Buffer.from("HPKE-v1");

function labeledExtract(suiteId, salt, label, ikm) {
  const labeledIkm = Buffer.concat([HPKE_V1, suiteId, Buffer.from(label), ikm]);
  const key = salt.length === 0 ? Buffer.alloc(32) : salt;
  return createHmac("sha256", key).update(labeledIkm).digest();
}

function labeledExpand(suiteId, prk, label, info, L) {
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(L, 0);
  const labeledInfo = Buffer.concat([lenBuf, HPKE_V1, suiteId, Buffer.from(label), info]);
  // RFC 5869 HKDF-Expand directly from PRK
  let prev = Buffer.alloc(0);
  const out = [];
  let counter = 1;
  while (Buffer.concat(out).length < L) {
    prev = createHmac("sha256", prk).update(Buffer.concat([prev, labeledInfo, Buffer.from([counter])])).digest();
    out.push(prev);
    counter += 1;
  }
  return Buffer.concat(out).subarray(0, L);
}

const skR = createPrivateKey({ key: Buffer.from(input.recipientPkcs8, "base64url"), format: "der", type: "pkcs8" });
const pkRBytes = Buffer.from(input.encJwk.x, "base64url");
const encBytes = Buffer.from(input.encHex, "hex");
const encPub = createPublicKey({ key: { kty: "OKP", crv: "X25519", x: encBytes.toString("base64url") }, format: "jwk" });

const dh = diffieHellman({ privateKey: skR, publicKey: encPub });
const eaePrk = labeledExtract(KEM_SUITE, Buffer.alloc(0), "eae_prk", dh);
const sharedSecret = labeledExpand(KEM_SUITE, eaePrk, "shared_secret", Buffer.concat([encBytes, pkRBytes]), 32);

const infoBuf = Buffer.from(input.infoHex, "hex");
const pskIdHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
const infoHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), "info_hash", infoBuf);
const ksCtx = Buffer.concat([Buffer.from([0x00]), pskIdHash, infoHash]);
const secret = labeledExtract(HPKE_SUITE, sharedSecret, "secret", Buffer.alloc(0));
const key = labeledExpand(HPKE_SUITE, secret, "key", ksCtx, 32);
const baseNonce = labeledExpand(HPKE_SUITE, secret, "base_nonce", ksCtx, 12);

const ctBuf = Buffer.from(input.ctHex, "hex");
const aadBuf = Buffer.from(input.aadHex, "hex");
const decipher = createDecipheriv("aes-256-gcm", key, baseNonce);
decipher.setAAD(aadBuf);
decipher.setAuthTag(ctBuf.subarray(ctBuf.length - 16));
const pt = Buffer.concat([decipher.update(ctBuf.subarray(0, ctBuf.length - 16)), decipher.final()]);

console.log(JSON.stringify({
  signKid: thumbprint(input.signJwk),
  encKid: thumbprint(input.encJwk),
  plaintext: pt.toString("utf8"),
}));
"#;

    let res = run_node_ts(
        script,
        &json!({
            "signJwk": signer.to_jwk(),
            "encJwk": recipient.to_jwk(),
            "recipientPkcs8": &*recipient.export_pkcs8_b64(),
            "encHex": hex::encode(enc),
            "ctHex": hex::encode(ct),
            "infoHex": hex::encode(info),
            "aadHex": hex::encode(aad),
        }),
    );

    assert_eq!(res["signKid"].as_str().unwrap(), signer.kid());
    assert_eq!(res["encKid"].as_str().unwrap(), recipient.kid());
    assert_eq!(
        res["plaintext"].as_str().unwrap().as_bytes(),
        pt.as_slice()
    );

    // Also verify our pure-Rust SPKI DER is accepted cleanly by Node `node:crypto`
    let spki_check_script = r#"
import fs from "node:fs";
import { createPublicKey } from "node:crypto";
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const ed = createPublicKey({ key: Buffer.from(input.edSpkiHex, "hex"), format: "der", type: "spki" });
const x = createPublicKey({ key: Buffer.from(input.xSpkiHex, "hex"), format: "der", type: "spki" });
console.log(JSON.stringify({
  edX: ed.export({ format: "jwk" }).x,
  xX: x.export({ format: "jwk" }).x,
}));
"#;
    let spki_res = run_node_ts(
        spki_check_script,
        &json!({
            "edSpkiHex": hex::encode(signer.public_key().export_spki_der()),
            "xSpkiHex": hex::encode(recipient.public_key().export_spki_der()),
        }),
    );
    assert_eq!(spki_res["edX"].as_str().unwrap(), signer.public_key_b64());
    assert_eq!(spki_res["xX"].as_str().unwrap(), recipient.public_key_b64());

    // Roundtrip our SPKI keys back in Rust
    let _ = Ed25519PublicKey::from_spki_der(&signer.public_key().export_spki_der()).unwrap();
    let _ = X25519PublicKey::from_spki_der(&recipient.public_key().export_spki_der()).unwrap();
}

/// Differential check: verify our pure-Rust POSIX USTAR/PAX + gzip archive is cleanly
/// readable by the host OS `tar -tzf` tool!
#[test]
fn differential_pure_rust_tar_gz_interop_with_system_tar() {
    let tmp = TempDir::new().unwrap();
    let archive_path = tmp.path().join("bundle.tar.gz");
    let long_name = format!("dir/{}/deep-file.txt", "segment_".repeat(16));

    let mut buf = Vec::new();
    pack_tar_gz_bytes(
        &[
            ("hello.txt", b"world"),
            ("nested/data.json", b"{\"ok\":true}"),
            (&long_name, b"pax-encoded-content"),
        ],
        &mut buf,
        TarPackOptions::default(),
    )
    .unwrap();
    fs::write(&archive_path, &buf).unwrap();

    #[cfg(unix)]
    let tar_bin = if Path::new("/usr/bin/tar").exists() {
        "/usr/bin/tar"
    } else {
        "tar"
    };
    #[cfg(not(unix))]
    let tar_bin = "tar";

    let output = match Command::new(tar_bin)
        .current_dir(tmp.path())
        .args(["-tzf", "bundle.tar.gz"])
        .output()
    {
        Ok(out) => out,
        #[cfg(not(unix))]
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => panic!("failed to execute {tar_bin}: {e}"),
    };
    assert!(
        output.status.success(),
        "system tar failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listing: Vec<String> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|l| {
            #[cfg(unix)]
            {
                l.to_string()
            }
            #[cfg(not(unix))]
            {
                l.trim().replace('\\', "/")
            }
        })
        .collect();
    assert_eq!(
        listing,
        vec![
            "hello.txt".to_string(),
            "nested/data.json".to_string(),
            long_name,
        ]
    );
}
