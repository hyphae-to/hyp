//! Standards-exact **RFC 9180 HPKE Base Mode** implementation.
//!
//! Default Hyphae v2 cipher suite:
//! - KEM:  `DHKEM(X25519, HKDF-SHA256)` (`kem_id = 0x0020`)
//! - KDF:  `HKDF-SHA256` (`kdf_id = 0x0001`)
//! - AEAD: `AES-256-GCM` (`aead_id = 0x0002`)
//!
//! Also supports `AES-128-GCM` (`0x0001`) and `ChaCha20Poly1305` (`0x0003`) for
//! exact verification against RFC 9180 Appendix A.1.1 / A.2.1 test vectors.

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{self, HKDF_SHA256, KeyType, Salt};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{X25519KeyPair, X25519PublicKey};
#[cfg(test)]
use crate::x25519::x25519_dh;
use crate::x25519::x25519_public_from_private;

/// RFC 9180 §7.1 KEM ID for `DHKEM(X25519, HKDF-SHA256)`.
pub const KEM_ID_DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;

/// RFC 9180 §7.2 KDF ID for `HKDF-SHA256`.
pub const KDF_ID_HKDF_SHA256: u16 = 0x0001;

/// RFC 9180 §5.1 Mode ID for Base Mode.
pub const MODE_BASE: u8 = 0x00;

/// RFC 9180 `Nenc` / `Npk` / `Nsk` / `Nsecret` for X25519 KEM.
pub const X25519_ENC_LEN: usize = 32;

const HPKE_V1: &[u8] = b"HPKE-v1";
const KEM_SUITE_ID: [u8; 5] = [b'K', b'E', b'M', 0x00, 0x20];

/// RFC 9180 §7.3 AEAD algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AeadId {
    Aes128Gcm = 0x0001,
    Aes256Gcm = 0x0002,
    ChaCha20Poly1305 = 0x0003,
}

impl AeadId {
    pub const fn id(self) -> u16 {
        self as u16
    }

    pub const fn key_len(self) -> usize {
        match self {
            AeadId::Aes128Gcm => 16,
            AeadId::Aes256Gcm => 32,
            AeadId::ChaCha20Poly1305 => 32,
        }
    }

    pub const fn nonce_len(self) -> usize {
        12
    }

    pub const fn tag_len(self) -> usize {
        16
    }

    fn ring_alg(self) -> &'static aead::Algorithm {
        match self {
            AeadId::Aes128Gcm => &aead::AES_128_GCM,
            AeadId::Aes256Gcm => &aead::AES_256_GCM,
            AeadId::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    fn hpke_suite_id(self) -> [u8; 10] {
        let kem = KEM_ID_DHKEM_X25519_HKDF_SHA256.to_be_bytes();
        let kdf = KDF_ID_HKDF_SHA256.to_be_bytes();
        let aead = self.id().to_be_bytes();
        [
            b'H', b'P', b'K', b'E', kem[0], kem[1], kdf[0], kdf[1], aead[0], aead[1],
        ]
    }
}

struct LenKeyType(usize);

impl KeyType for LenKeyType {
    fn len(&self) -> usize {
        self.0
    }
}

/// RFC 9180 §4 `LabeledExtract(salt, label, ikm)` returning raw 32-byte PRK.
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut labeled_ikm = Zeroizing::new(Vec::with_capacity(
        HPKE_V1.len() + suite_id.len() + label.len() + ikm.len(),
    ));
    labeled_ikm.extend_from_slice(HPKE_V1);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, salt);
    let tag = ring::hmac::sign(&key, &labeled_ikm);
    let mut prk = Zeroizing::new([0u8; 32]);
    prk.copy_from_slice(tag.as_ref());
    prk
}

/// RFC 9180 §4 `LabeledExpand(prk, label, info, L)`.
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if len > u16::MAX as usize || len > 255 * 32 {
        return Err(CryptoError::Hpke(format!(
            "invalid LabeledExpand length {len}"
        )));
    }
    let len_be = (len as u16).to_be_bytes();
    let prk_obj = hkdf::Prk::new_less_safe(HKDF_SHA256, prk);
    let info_slices: [&[u8]; 5] = [&len_be, HPKE_V1, suite_id, label, info];
    let okm = prk_obj
        .expand(&info_slices, LenKeyType(len))
        .map_err(|_| CryptoError::Hpke("HKDF-Expand failed".into()))?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    okm.fill(&mut out)
        .map_err(|_| CryptoError::Hpke("HKDF-Expand fill failed".into()))?;
    Ok(out)
}

/// RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` for `DHKEM(X25519, HKDF-SHA256)`.
///
/// Returns `(sk, pk)` where `sk` is the unclamped 32-byte X25519 private key and
/// `pk = X25519(sk, G)`.
pub fn derive_keypair_x25519(ikm: &[u8]) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), CryptoError> {
    let dkp_prk = labeled_extract(&KEM_SUITE_ID, b"", b"dkp_prk", ikm);
    let sk_vec = labeled_expand(&KEM_SUITE_ID, &dkp_prk, b"sk", b"", 32)?;
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&sk_vec);
    let pk = x25519_public_from_private(&sk);
    Ok((sk, pk))
}

/// RFC 9180 §4.1 `ExtractAndExpand(dh, kem_context)`.
fn extract_and_expand(
    dh: &[u8; 32],
    enc: &[u8; 32],
    pk_r: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let eae_prk = labeled_extract(&KEM_SUITE_ID, b"", b"eae_prk", dh);
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(enc);
    kem_context[32..].copy_from_slice(pk_r);
    let ss_vec = labeled_expand(&KEM_SUITE_ID, &eae_prk, b"shared_secret", &kem_context, 32)?;
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    shared_secret.copy_from_slice(&ss_vec);
    Ok(shared_secret)
}

/// RFC 9180 §4.1 `Encap(pkR)` with deterministic ephemeral `ikm_e` (for test vectors).
#[cfg(test)]
fn encap_deterministic(
    pk_r: &X25519PublicKey,
    ikm_e: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), CryptoError> {
    let (sk_e, pk_e) = derive_keypair_x25519(ikm_e)?;
    let dh = x25519_dh(&sk_e, pk_r.as_bytes())?;
    let shared_secret = extract_and_expand(&dh, &pk_e, pk_r.as_bytes())?;
    Ok((shared_secret, pk_e))
}

/// RFC 9180 §4.1 `Encap(pkR)` with fresh OS CSPRNG ephemeral keypair.
fn encap_random(pk_r: &X25519PublicKey) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), CryptoError> {
    let ephem = X25519KeyPair::generate()?;
    let enc = ephem.public_key_bytes();
    let dh = ephem.diffie_hellman(pk_r)?;
    let shared_secret = extract_and_expand(&dh, &enc, pk_r.as_bytes())?;
    Ok((shared_secret, enc))
}

/// RFC 9180 §4.1 `Decap(enc, skR)`.
fn decap(enc: &[u8; 32], sk_r: &X25519KeyPair) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let enc_pk = X25519PublicKey::from_bytes(*enc)?;
    let dh = sk_r.diffie_hellman(&enc_pk)?;
    let pk_r = sk_r.public_key_bytes();
    extract_and_expand(&dh, enc, &pk_r)
}

struct KeyScheduleOutput {
    key: Zeroizing<Vec<u8>>,
    base_nonce: Zeroizing<[u8; 12]>,
    exporter_secret: Zeroizing<[u8; 32]>,
    #[cfg(test)]
    key_schedule_context: [u8; 65],
    #[cfg(test)]
    secret: Zeroizing<[u8; 32]>,
}

/// RFC 9180 §5.1 `KeySchedule(mode=0x00, shared_secret, info, psk="", psk_id="")`.
fn key_schedule_base(
    aead_id: AeadId,
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<KeyScheduleOutput, CryptoError> {
    let suite_id = aead_id.hpke_suite_id();

    let psk_id_hash = labeled_extract(&suite_id, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite_id, b"", b"info_hash", info);

    let mut ks_context = [0u8; 65];
    ks_context[0] = MODE_BASE;
    ks_context[1..33].copy_from_slice(&*psk_id_hash);
    ks_context[33..65].copy_from_slice(&*info_hash);

    let secret = labeled_extract(&suite_id, shared_secret, b"secret", b"");

    let key = labeled_expand(&suite_id, &secret, b"key", &ks_context, aead_id.key_len())?;
    let nonce_vec = labeled_expand(
        &suite_id,
        &secret,
        b"base_nonce",
        &ks_context,
        aead_id.nonce_len(),
    )?;
    let mut base_nonce = Zeroizing::new([0u8; 12]);
    base_nonce.copy_from_slice(&nonce_vec);

    let exp_vec = labeled_expand(&suite_id, &secret, b"exp", &ks_context, 32)?;
    let mut exporter_secret = Zeroizing::new([0u8; 32]);
    exporter_secret.copy_from_slice(&exp_vec);

    Ok(KeyScheduleOutput {
        key,
        base_nonce,
        exporter_secret,
        #[cfg(test)]
        key_schedule_context: ks_context,
        #[cfg(test)]
        secret,
    })
}

fn compute_nonce(base_nonce: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

fn export_secret_impl(
    aead_id: AeadId,
    exporter_secret: &[u8; 32],
    exporter_context: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let suite_id = aead_id.hpke_suite_id();
    labeled_expand(&suite_id, exporter_secret, b"sec", exporter_context, len)
}

/// Stateful RFC 9180 HPKE Base Mode **Sender** encryption context.
pub struct ContextS {
    aead_id: AeadId,
    key: Zeroizing<Vec<u8>>,
    base_nonce: Zeroizing<[u8; 12]>,
    exporter_secret: Zeroizing<[u8; 32]>,
    seq: u64,
    exhausted: bool,
}

impl ContextS {
    fn from_schedule(aead_id: AeadId, ks: KeyScheduleOutput) -> Self {
        Self {
            aead_id,
            key: ks.key,
            base_nonce: ks.base_nonce,
            exporter_secret: ks.exporter_secret,
            seq: 0,
            exhausted: false,
        }
    }

    /// Current sequence number (number of messages already sealed).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Encrypts `pt` with associated data `aad`, advancing the nonce sequence counter.
    /// Fails closed on sequence number overflow.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.exhausted {
            return Err(CryptoError::SequenceOverflow);
        }
        let nonce_bytes = compute_nonce(&self.base_nonce, self.seq);
        let unbound = UnboundKey::new(self.aead_id.ring_alg(), &self.key)
            .map_err(|_| CryptoError::Hpke("failed to construct AEAD key".into()))?;
        let key = LessSafeKey::new(unbound);

        let mut in_out = Vec::with_capacity(pt.len() + self.aead_id.tag_len());
        in_out.extend_from_slice(pt);
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| CryptoError::Hpke("AEAD seal failed".into()))?;

        match self.seq.checked_add(1) {
            Some(next) => self.seq = next,
            None => self.exhausted = true,
        }
        Ok(in_out)
    }

    /// RFC 9180 §5.3 `Context.Export(exporter_context, L)`.
    pub fn export(
        &self,
        exporter_context: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        export_secret_impl(self.aead_id, &self.exporter_secret, exporter_context, len)
    }

    #[cfg(test)]
    fn set_seq_for_test(&mut self, seq: u64) {
        self.seq = seq;
        self.exhausted = false;
    }
}

/// Stateful RFC 9180 HPKE Base Mode **Receiver** decryption context.
pub struct ContextR {
    aead_id: AeadId,
    key: Zeroizing<Vec<u8>>,
    base_nonce: Zeroizing<[u8; 12]>,
    exporter_secret: Zeroizing<[u8; 32]>,
    seq: u64,
    exhausted: bool,
}

impl ContextR {
    fn from_schedule(aead_id: AeadId, ks: KeyScheduleOutput) -> Self {
        Self {
            aead_id,
            key: ks.key,
            base_nonce: ks.base_nonce,
            exporter_secret: ks.exporter_secret,
            seq: 0,
            exhausted: false,
        }
    }

    /// Current sequence number (number of messages successfully opened).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Decrypts `ct` with associated data `aad`.
    /// Per RFC 9180 §5.2, sequence number is ONLY incremented on authentication success.
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if self.exhausted {
            return Err(CryptoError::SequenceOverflow);
        }
        if ct.len() < self.aead_id.tag_len() {
            return Err(CryptoError::DecryptionFailed(
                "ciphertext shorter than AEAD tag".into(),
            ));
        }
        let nonce_bytes = compute_nonce(&self.base_nonce, self.seq);
        let unbound = UnboundKey::new(self.aead_id.ring_alg(), &self.key)
            .map_err(|_| CryptoError::Hpke("failed to construct AEAD key".into()))?;
        let key = LessSafeKey::new(unbound);

        let mut buf = Zeroizing::new(ct.to_vec());
        let pt_len = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| CryptoError::DecryptionFailed("HPKE AEAD authentication failed".into()))?
            .len();
        buf.truncate(pt_len);

        match self.seq.checked_add(1) {
            Some(next) => self.seq = next,
            None => self.exhausted = true,
        }
        Ok(buf)
    }

    /// RFC 9180 §5.3 `Context.Export(exporter_context, L)`.
    pub fn export(
        &self,
        exporter_context: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        export_secret_impl(self.aead_id, &self.exporter_secret, exporter_context, len)
    }
}

/// Sets up a stateful HPKE Base Mode sender context using Hyphae v2's default suite
/// (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`).
pub fn setup_base_sender(
    pk_r: &X25519PublicKey,
    info: &[u8],
) -> Result<([u8; 32], ContextS), CryptoError> {
    setup_base_sender_with_aead(AeadId::Aes256Gcm, pk_r, info)
}

/// Sets up a stateful HPKE Base Mode sender context for the specified AEAD suite.
pub fn setup_base_sender_with_aead(
    aead_id: AeadId,
    pk_r: &X25519PublicKey,
    info: &[u8],
) -> Result<([u8; 32], ContextS), CryptoError> {
    let (shared_secret, enc) = encap_random(pk_r)?;
    let ks = key_schedule_base(aead_id, &shared_secret, info)?;
    Ok((enc, ContextS::from_schedule(aead_id, ks)))
}

/// Sets up a stateful HPKE Base Mode receiver context using Hyphae v2's default suite
/// (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`).
pub fn setup_base_receiver(
    enc: &[u8; 32],
    sk_r: &X25519KeyPair,
    info: &[u8],
) -> Result<ContextR, CryptoError> {
    setup_base_receiver_with_aead(AeadId::Aes256Gcm, enc, sk_r, info)
}

/// Sets up a stateful HPKE Base Mode receiver context for the specified AEAD suite.
pub fn setup_base_receiver_with_aead(
    aead_id: AeadId,
    enc: &[u8; 32],
    sk_r: &X25519KeyPair,
    info: &[u8],
) -> Result<ContextR, CryptoError> {
    let shared_secret = decap(enc, sk_r)?;
    let ks = key_schedule_base(aead_id, &shared_secret, info)?;
    Ok(ContextR::from_schedule(aead_id, ks))
}

/// Single-shot HPKE Base Mode seal using Hyphae v2's default suite (`AES-256-GCM`).
pub fn seal_base(
    pk_r: &X25519PublicKey,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    seal_base_with_aead(AeadId::Aes256Gcm, pk_r, info, aad, pt)
}

/// Single-shot HPKE Base Mode seal with explicit AEAD suite.
pub fn seal_base_with_aead(
    aead_id: AeadId,
    pk_r: &X25519PublicKey,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    let (enc, mut ctx) = setup_base_sender_with_aead(aead_id, pk_r, info)?;
    let ct = ctx.seal(aad, pt)?;
    Ok((enc, ct))
}

/// Single-shot HPKE Base Mode open using Hyphae v2's default suite (`AES-256-GCM`).
pub fn open_base(
    enc: &[u8; 32],
    sk_r: &X25519KeyPair,
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_base_with_aead(AeadId::Aes256Gcm, enc, sk_r, info, aad, ct)
}

/// Single-shot HPKE Base Mode open with explicit AEAD suite.
pub fn open_base_with_aead(
    aead_id: AeadId,
    enc: &[u8; 32],
    sk_r: &X25519KeyPair,
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut ctx = setup_base_receiver_with_aead(aead_id, enc, sk_r, info)?;
    ctx.open(aad, ct)
}

/// Convenience helper for RFC 5869 HKDF-SHA256 key derivation returning zeroized bytes.
pub(crate) fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let salt_obj = Salt::new(HKDF_SHA256, salt);
    let prk = salt_obj.extract(ikm);
    let info_slices = [info];
    let okm = prk
        .expand(&info_slices, LenKeyType(len))
        .map_err(|_| CryptoError::Hpke("HKDF-SHA256 expand failed".into()))?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    okm.fill(&mut out)
        .map_err(|_| CryptoError::Hpke("HKDF-SHA256 fill failed".into()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// Official RFC 9180 Appendix A.1.1 known-answer test vector:
    /// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Base Mode (mode = 0).
    /// Verifies DeriveKeyPair, Encap, Decap, KeySchedule, Encryptions (seq=0, seq=1), and Exports.
    #[test]
    fn rfc9180_appendix_a_1_1_exact_known_answer_vector() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e"); // "Ode on a Grecian Urn"
        let ikm_e = unhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        let expected_sk_em =
            unhex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        let expected_pk_em =
            unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");

        let ikm_r = unhex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
        let expected_sk_rm =
            unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        let expected_pk_rm =
            unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");

        let expected_ss = unhex("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
        let expected_ks_ctx = unhex(
            "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d\
             07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449",
        );
        let expected_secret =
            unhex("12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
        let expected_key = unhex("4531685d41d65f03dc48f6b8302c05b0");
        let expected_base_nonce = unhex("56d890e5accaaf011cff4b7d");
        let expected_exp_secret =
            unhex("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");

        // 1. DeriveKeyPair(ikmE) and DeriveKeyPair(ikmR)
        let (sk_em, pk_em) = derive_keypair_x25519(&ikm_e).unwrap();
        assert_eq!(sk_em.as_slice(), expected_sk_em.as_slice());
        assert_eq!(pk_em.as_slice(), expected_pk_em.as_slice());

        let (sk_rm, pk_rm) = derive_keypair_x25519(&ikm_r).unwrap();
        assert_eq!(sk_rm.as_slice(), expected_sk_rm.as_slice());
        assert_eq!(pk_rm.as_slice(), expected_pk_rm.as_slice());

        // 2. Encap & Decap
        let pk_r = X25519PublicKey::from_bytes(pk_rm).unwrap();
        let sk_r = X25519KeyPair::from_bytes(*sk_rm).unwrap();
        let (ss_s, enc) = encap_deterministic(&pk_r, &ikm_e).unwrap();
        assert_eq!(enc.as_slice(), expected_pk_em.as_slice());
        assert_eq!(ss_s.as_slice(), expected_ss.as_slice());

        let ss_r = decap(&enc, &sk_r).unwrap();
        assert_eq!(ss_r.as_slice(), expected_ss.as_slice());

        // 3. KeySchedule intermediate values
        let ks_s = key_schedule_base(AeadId::Aes128Gcm, &ss_s, &info).unwrap();
        assert_eq!(
            ks_s.key_schedule_context.as_slice(),
            expected_ks_ctx.as_slice()
        );
        assert_eq!(ks_s.secret.as_slice(), expected_secret.as_slice());
        assert_eq!(ks_s.key.as_slice(), expected_key.as_slice());
        assert_eq!(ks_s.base_nonce.as_slice(), expected_base_nonce.as_slice());
        assert_eq!(
            ks_s.exporter_secret.as_slice(),
            expected_exp_secret.as_slice()
        );

        let ks_r = key_schedule_base(AeadId::Aes128Gcm, &ss_r, &info).unwrap();
        let mut ctx_s = ContextS::from_schedule(AeadId::Aes128Gcm, ks_s);
        let mut ctx_r = ContextR::from_schedule(AeadId::Aes128Gcm, ks_r);

        // 4. Appendix A.1.1.1 Encryptions (seq = 0 and seq = 1)
        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
        let aad0 = unhex("436f756e742d30");
        let expected_ct0 = unhex(
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9\
             6d8770ac83d07bea87e13c512a",
        );
        let ct0 = ctx_s.seal(&aad0, &pt).unwrap();
        assert_eq!(ct0, expected_ct0);
        assert_eq!(ctx_r.open(&aad0, &ct0).unwrap().as_slice(), pt.as_slice());

        let aad1 = unhex("436f756e742d31");
        let expected_ct1 = unhex(
            "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab25\
             1c03d0c22a56b8ca42c2063b84",
        );
        let ct1 = ctx_s.seal(&aad1, &pt).unwrap();
        assert_eq!(ct1, expected_ct1);
        assert_eq!(ctx_r.open(&aad1, &ct1).unwrap().as_slice(), pt.as_slice());

        // 5. Appendix A.1.1.2 Exports ("TestContext", L = 32)
        let exported_s = ctx_s.export(b"TestContext", 32).unwrap();
        let exported_r = ctx_r.export(b"TestContext", 32).unwrap();
        let expected_export =
            unhex("e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931");
        assert_eq!(exported_s.as_slice(), expected_export.as_slice());
        assert_eq!(exported_r.as_slice(), expected_export.as_slice());
    }

    #[test]
    fn aes256_gcm_default_suite_roundtrip_and_mutations() {
        let recipient = X25519KeyPair::generate().unwrap();
        let wrong_recipient = X25519KeyPair::generate().unwrap();
        let info = b"hyphae/v2/test";
        let aad = b"associated-data";
        let pt = b"hello hyphae v2 hpke aes-256-gcm";

        let (enc, ct) = seal_base(&recipient.public_key(), info, aad, pt).unwrap();
        let opened = open_base(&enc, &recipient, info, aad, &ct).unwrap();
        assert_eq!(opened.as_slice(), pt);

        // Wrong recipient fails
        assert!(open_base(&enc, &wrong_recipient, info, aad, &ct).is_err());
        // Wrong info fails
        assert!(open_base(&enc, &recipient, b"wrong-info", aad, &ct).is_err());
        // Wrong AAD fails
        assert!(open_base(&enc, &recipient, info, b"wrong-aad", &ct).is_err());
        // 1-bit flip in enc fails
        let mut bad_enc = enc;
        bad_enc[0] ^= 0x01;
        assert!(open_base(&bad_enc, &recipient, info, aad, &ct).is_err());
        // 1-bit flip in ct fails
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(open_base(&enc, &recipient, info, aad, &bad_ct).is_err());
        // All-zero enc fails with SmallOrderKey
        assert!(matches!(
            open_base(&[0u8; 32], &recipient, info, aad, &ct),
            Err(CryptoError::SmallOrderKey)
        ));
    }

    #[test]
    fn stateful_context_sequence_overflow_and_failed_open_does_not_increment() {
        let recipient = X25519KeyPair::generate().unwrap();
        let (enc, mut sender) = setup_base_sender(&recipient.public_key(), b"stream").unwrap();
        let mut receiver = setup_base_receiver(&enc, &recipient, b"stream").unwrap();

        let ct0 = sender.seal(b"a0", b"msg0").unwrap();
        // Failed open MUST NOT advance receiver seq
        let mut tampered = ct0.clone();
        tampered[0] ^= 0x80;
        assert!(receiver.open(b"a0", &tampered).is_err());
        assert_eq!(receiver.seq(), 0);
        // Valid open still succeeds at seq=0
        assert_eq!(receiver.open(b"a0", &ct0).unwrap().as_slice(), b"msg0");
        assert_eq!(receiver.seq(), 1);

        // Sequence overflow protection
        sender.set_seq_for_test(u64::MAX);
        assert!(sender.seal(b"last", b"ok").is_ok());
        assert!(matches!(
            sender.seal(b"overflow", b"nope"),
            Err(CryptoError::SequenceOverflow)
        ));
    }
}
