//! Hyphae v2 End-to-End Encryption (E2EE) envelopes:
//! - `dm.e2ee.v1`: power-of-2 bucket padding (256 B .. 32 KiB) + RFC 9180 HPKE + Encrypt-then-Sign Ed25519
//! - `channel.e2ee.v1`: Signed Epoch Room Keys (HPKE-wrapped per member) + AES-256-GCM + Ed25519 + anti-rollback
//! - `kv.e2ee.v1`: Namespace Epoch Room Keys + AES-256-GCM with structured KV AAD + Ed25519 + version/epoch anti-rollback

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::hpke::{self, hkdf_sha256};
use crate::jcs::to_canonical_json;
use crate::keys::{
    Ed25519KeyPair, Ed25519PublicKey, SignedPayload, X25519KeyPair, X25519PublicKey,
};

/// Minimum power-of-2 bucket size for length-hiding padding (256 bytes).
pub const MIN_PADDING_BUCKET: usize = 256;

/// Maximum power-of-2 bucket size for length-hiding padding (32 KiB).
pub const MAX_PADDING_BUCKET: usize = 32 * 1024;

/// Maximum plaintext length that fits inside `MAX_PADDING_BUCKET` (32 KiB - 2B length prefix).
pub const MAX_PADDED_PLAINTEXT: usize = MAX_PADDING_BUCKET - 2;

const SUITE_DM_V1: &str = "dm.e2ee.v1";
const SUITE_CHANNEL_V1: &str = "channel.e2ee.v1";
const SUITE_KV_V1: &str = "kv.e2ee.v1";

/// Computes the target power-of-2 bucket size in `256..=32768` for `plaintext_len`.
pub fn bucket_size_for(plaintext_len: usize) -> Result<usize, CryptoError> {
    if plaintext_len > MAX_PADDED_PLAINTEXT {
        return Err(CryptoError::InvalidEnvelope(format!(
            "plaintext length {plaintext_len} exceeds maximum padded size {MAX_PADDED_PLAINTEXT}"
        )));
    }
    let needed = plaintext_len + 2;
    let mut bucket = MIN_PADDING_BUCKET;
    while bucket < needed {
        bucket <<= 1;
    }
    Ok(bucket)
}

/// Pads `plaintext` into `[2B u16 BE len][plaintext][0x00 ...]` at the next power-of-2 bucket (`256B..=32 KiB`).
pub fn pad_bucket(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let bucket = bucket_size_for(plaintext.len())?;
    let mut out = Zeroizing::new(vec![0u8; bucket]);
    let len_be = (plaintext.len() as u16).to_be_bytes();
    out[0] = len_be[0];
    out[1] = len_be[1];
    out[2..2 + plaintext.len()].copy_from_slice(plaintext);
    Ok(out)
}

/// Validates and removes power-of-2 bucket padding, failing closed on non-bucket lengths,
/// non-minimal buckets, or non-zero padding bytes.
pub fn unpad_bucket(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let len = padded.len();
    if !(MIN_PADDING_BUCKET..=MAX_PADDING_BUCKET).contains(&len) || !len.is_power_of_two() {
        return Err(CryptoError::InvalidEnvelope(format!(
            "invalid padded bucket length {len}"
        )));
    }
    let pt_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    let expected_bucket = bucket_size_for(pt_len)?;
    if expected_bucket != len || 2 + pt_len > len {
        return Err(CryptoError::InvalidEnvelope(
            "corrupt bucket padding length prefix".into(),
        ));
    }
    if padded[2 + pt_len..].iter().any(|&b| b != 0) {
        return Err(CryptoError::InvalidEnvelope(
            "non-zero trailing padding bytes".into(),
        ));
    }
    Ok(Zeroizing::new(padded[2..2 + pt_len].to_vec()))
}

// ============================================================================
// dm.e2ee.v1
// ============================================================================

/// Routing and identity context bound into `dm.e2ee.v1` HPKE info, AEAD AAD, and Ed25519 signature.
#[derive(Debug, Clone, Copy)]
pub struct DmContext<'a> {
    pub node_id: &'a str,
    pub msg_id: &'a str,
    pub sender: &'a str,
    pub recipient: &'a str,
}

/// Wire envelope for Hyphae v2 1-to-1 E2EE DMs (`dm.e2ee.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmEnvelopeV1 {
    pub v: u8,
    pub suite: String,
    #[serde(rename = "senderKid")]
    pub sender_kid: String,
    #[serde(rename = "recipientKid")]
    pub recipient_kid: String,
    pub enc: String,
    pub ct: String,
    pub sig: String,
}

#[derive(Serialize)]
struct DmSigInput<'a> {
    v: u8,
    suite: &'a str,
    #[serde(rename = "nodeId")]
    node_id: &'a str,
    #[serde(rename = "msgId")]
    msg_id: &'a str,
    sender: &'a str,
    recipient: &'a str,
    #[serde(rename = "senderKid")]
    sender_kid: &'a str,
    #[serde(rename = "recipientKid")]
    recipient_kid: &'a str,
    enc: &'a str,
    #[serde(rename = "ctSha256")]
    ct_sha256: &'a str,
}

fn dm_hpke_info(ctx: &DmContext<'_>) -> Vec<u8> {
    format!(
        "hyphae/v2/dm\n{}\n{}\n{}\n{}",
        ctx.node_id, ctx.msg_id, ctx.sender, ctx.recipient
    )
    .into_bytes()
}

fn dm_aad(ctx: &DmContext<'_>, sender_kid: &str, recipient_kid: &str) -> Vec<u8> {
    format!(
        "hyphae/v2/dm\n{}\n{}\n{}\n{}\n{}\n{}",
        ctx.node_id, ctx.msg_id, ctx.sender, ctx.recipient, sender_kid, recipient_kid
    )
    .into_bytes()
}

/// Encrypts and signs a direct message (`dm.e2ee.v1`):
/// power-of-2 bucket padding -> RFC 9180 HPKE (`AES-256-GCM`) -> Encrypt-then-Sign Ed25519.
pub fn seal_dm(
    ctx: &DmContext<'_>,
    plaintext: &[u8],
    sender_signing: &Ed25519KeyPair,
    recipient_enc_pk: &X25519PublicKey,
) -> Result<DmEnvelopeV1, CryptoError> {
    let padded = pad_bucket(plaintext)?;
    let sender_kid = sender_signing.kid();
    let recipient_kid = recipient_enc_pk.kid();

    let info = dm_hpke_info(ctx);
    let aad = dm_aad(ctx, &sender_kid, &recipient_kid);
    let (enc_bytes, ct_bytes) = hpke::seal_base(recipient_enc_pk, &info, &aad, &padded)?;

    let enc = URL_SAFE_NO_PAD.encode(enc_bytes);
    let ct = URL_SAFE_NO_PAD.encode(&ct_bytes);
    let ct_sha256 = hex::encode(Sha256::digest(&ct_bytes));

    let sig_payload = to_canonical_json(&DmSigInput {
        v: 1,
        suite: SUITE_DM_V1,
        node_id: ctx.node_id,
        msg_id: ctx.msg_id,
        sender: ctx.sender,
        recipient: ctx.recipient,
        sender_kid: &sender_kid,
        recipient_kid: &recipient_kid,
        enc: &enc,
        ct_sha256: &ct_sha256,
    })?;
    let sig = sender_signing.sign_domain_b64("dm", sig_payload.as_bytes());

    Ok(DmEnvelopeV1 {
        v: 1,
        suite: SUITE_DM_V1.to_string(),
        sender_kid,
        recipient_kid,
        enc,
        ct,
        sig,
    })
}

/// Verifies sender Ed25519 signature FIRST, then HPKE-decrypts and unpads a `dm.e2ee.v1` envelope.
pub fn open_dm(
    envelope: &DmEnvelopeV1,
    ctx: &DmContext<'_>,
    sender_signing_pk: &Ed25519PublicKey,
    recipient_enc_kp: &X25519KeyPair,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.v != 1 || envelope.suite != SUITE_DM_V1 {
        return Err(CryptoError::InvalidEnvelope(format!(
            "unsupported DM envelope v={} suite={}",
            envelope.v, envelope.suite
        )));
    }
    let expected_sender_kid = sender_signing_pk.kid();
    if envelope.sender_kid != expected_sender_kid {
        return Err(CryptoError::InvalidEnvelope(
            "senderKid does not match expected sender key".into(),
        ));
    }
    let expected_recipient_kid = recipient_enc_kp.kid();
    if envelope.recipient_kid != expected_recipient_kid {
        return Err(CryptoError::InvalidEnvelope(
            "recipientKid does not match local encryption key".into(),
        ));
    }

    let enc_vec = URL_SAFE_NO_PAD
        .decode(&envelope.enc)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid enc base64url: {e}")))?;
    let enc_bytes: [u8; 32] = enc_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope("enc must be 32 bytes".into()))?;
    let ct_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.ct)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid ct base64url: {e}")))?;
    let ct_sha256 = hex::encode(Sha256::digest(&ct_bytes));

    // Encrypt-then-Sign: verify Ed25519 signature BEFORE decrypting!
    let sig_payload = to_canonical_json(&DmSigInput {
        v: 1,
        suite: SUITE_DM_V1,
        node_id: ctx.node_id,
        msg_id: ctx.msg_id,
        sender: ctx.sender,
        recipient: ctx.recipient,
        sender_kid: &envelope.sender_kid,
        recipient_kid: &envelope.recipient_kid,
        enc: &envelope.enc,
        ct_sha256: &ct_sha256,
    })?;
    sender_signing_pk.verify_domain_b64("dm", sig_payload.as_bytes(), &envelope.sig)?;

    let info = dm_hpke_info(ctx);
    let aad = dm_aad(ctx, &envelope.sender_kid, &envelope.recipient_kid);
    let padded = hpke::open_base(&enc_bytes, recipient_enc_kp, &info, &aad, &ct_bytes)?;
    unpad_bucket(&padded)
}

// ============================================================================
// Signed Epoch Room Keys (shared by channel.e2ee.v1 and kv.e2ee.v1)
// ============================================================================

/// Scope kind for a Signed Epoch Room Key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochScope {
    Channel,
    Kv,
}

impl EpochScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            EpochScope::Channel => "channel",
            EpochScope::Kv => "kv",
        }
    }
}

/// Zeroized 256-bit epoch room key bound to an epoch number.
pub struct RoomEpochKey {
    epoch: u64,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for RoomEpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomEpochKey")
            .field("epoch", &self.epoch)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl RoomEpochKey {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Constructs a `RoomEpochKey` from raw bytes (primarily for persistence/restore).
    pub fn from_raw(epoch: u64, key: [u8; 32]) -> Self {
        Self {
            epoch,
            key: Zeroizing::new(key),
        }
    }
}

/// Member descriptor used when creating or rotating a Signed Epoch Room Key.
#[derive(Debug, Clone, Copy)]
pub struct EpochMember<'a> {
    pub node_id: &'a str,
    pub enc_pk: &'a X25519PublicKey,
}

/// HPKE-wrapped room key slot for one member node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedMemberKey {
    #[serde(rename = "nodeId")]
    pub node_id: String,
    #[serde(rename = "recipientKid")]
    pub recipient_kid: String,
    pub enc: String,
    pub ct: String,
}

/// Canonical payload of a Signed Epoch Room Key bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochKeyBundlePayload {
    pub v: u8,
    pub scope: String,
    #[serde(rename = "hostNode")]
    pub host_node: String,
    pub resource: String,
    pub epoch: u64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "createdByKid")]
    pub created_by_kid: String,
    #[serde(rename = "membersHash")]
    pub members_hash: String,
    pub wraps: Vec<WrappedMemberKey>,
}

/// Creator-signed epoch room key bundle (stored in `channel_epochs` / `kv_epochs`).
pub type SignedEpochKeyBundle = SignedPayload;

fn compute_members_hash(members: &[(String, String)]) -> Result<String, CryptoError> {
    let mut sorted = members.to_vec();
    sorted.sort();
    sorted.dedup();
    let canon = to_canonical_json(&sorted)?;
    Ok(hex::encode(Sha256::digest(canon.as_bytes())))
}

fn epoch_wrap_info(scope: EpochScope, host_node: &str, resource: &str, epoch: u64) -> Vec<u8> {
    format!(
        "hyphae/v2/epoch-wrap\n{}\n{}\n{}\n{}",
        scope.as_str(),
        host_node,
        resource,
        epoch
    )
    .into_bytes()
}

fn epoch_wrap_aad(
    host_node: &str,
    resource: &str,
    epoch: u64,
    member_node_id: &str,
    recipient_kid: &str,
    members_hash: &str,
) -> Vec<u8> {
    format!("{host_node}\n{resource}\n{epoch}\n{member_node_id}\n{recipient_kid}\n{members_hash}")
        .into_bytes()
}

/// Mints a fresh 256-bit room key for `epoch`, wraps it via RFC 9180 HPKE for each member,
/// and signs the canonical bundle with `creator_signing`.
pub fn create_epoch_bundle(
    scope: EpochScope,
    host_node: &str,
    resource: &str,
    epoch: u64,
    created_by: &str,
    creator_signing: &Ed25519KeyPair,
    members: &[EpochMember<'_>],
) -> Result<(RoomEpochKey, SignedEpochKeyBundle), CryptoError> {
    if epoch == 0 {
        return Err(CryptoError::InvalidEnvelope("epoch must be >= 1".into()));
    }
    if members.is_empty() {
        return Err(CryptoError::InvalidEnvelope(
            "epoch bundle requires at least one member".into(),
        ));
    }

    let rng = SystemRandom::new();
    let mut raw_key = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *raw_key)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;

    let mut member_pairs: Vec<(String, String, X25519PublicKey)> = members
        .iter()
        .map(|m| (m.node_id.to_string(), m.enc_pk.kid(), *m.enc_pk))
        .collect();
    member_pairs.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    member_pairs.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

    let member_ids: Vec<(String, String)> = member_pairs
        .iter()
        .map(|(n, k, _)| (n.clone(), k.clone()))
        .collect();
    let members_hash = compute_members_hash(&member_ids)?;
    let info = epoch_wrap_info(scope, host_node, resource, epoch);

    let mut wraps = Vec::with_capacity(member_pairs.len());
    for (node_id, recipient_kid, enc_pk) in &member_pairs {
        let aad = epoch_wrap_aad(
            host_node,
            resource,
            epoch,
            node_id,
            recipient_kid,
            &members_hash,
        );
        let (enc, ct) = hpke::seal_base(enc_pk, &info, &aad, &*raw_key)?;
        wraps.push(WrappedMemberKey {
            node_id: node_id.clone(),
            recipient_kid: recipient_kid.clone(),
            enc: URL_SAFE_NO_PAD.encode(enc),
            ct: URL_SAFE_NO_PAD.encode(ct),
        });
    }

    let payload = EpochKeyBundlePayload {
        v: 1,
        scope: scope.as_str().to_string(),
        host_node: host_node.to_string(),
        resource: resource.to_string(),
        epoch,
        created_by: created_by.to_string(),
        created_by_kid: creator_signing.kid(),
        members_hash,
        wraps,
    };

    let signed = creator_signing.sign_jcs("epoch-key", &payload)?;
    Ok((
        RoomEpochKey {
            epoch,
            key: raw_key,
        },
        signed,
    ))
}

/// Rotates an existing room key strictly to `prev_epoch + 1` for the updated member list.
pub fn rotate_epoch_bundle(
    scope: EpochScope,
    host_node: &str,
    resource: &str,
    prev_epoch: u64,
    created_by: &str,
    creator_signing: &Ed25519KeyPair,
    members: &[EpochMember<'_>],
) -> Result<(RoomEpochKey, SignedEpochKeyBundle), CryptoError> {
    let next_epoch = prev_epoch
        .checked_add(1)
        .ok_or(CryptoError::SequenceOverflow)?;
    create_epoch_bundle(
        scope,
        host_node,
        resource,
        next_epoch,
        created_by,
        creator_signing,
        members,
    )
}

/// Verifies creator signature, scope/resource binding, `membersHash` integrity, and anti-rollback
/// (`epoch >= min_expected_epoch`), then unwraps this node's `RoomEpochKey` via RFC 9180 HPKE.
#[allow(clippy::too_many_arguments)]
pub fn open_epoch_bundle(
    bundle: &SignedEpochKeyBundle,
    expected_scope: EpochScope,
    expected_host_node: &str,
    expected_resource: &str,
    creator_signing_pk: &Ed25519PublicKey,
    my_node_id: &str,
    my_enc_kp: &X25519KeyPair,
    min_expected_epoch: u64,
) -> Result<(RoomEpochKey, EpochKeyBundlePayload), CryptoError> {
    // 1. Verify creator signature FIRST.
    let payload: EpochKeyBundlePayload = creator_signing_pk.verify_signed("epoch-key", bundle)?;

    if payload.v != 1 || payload.scope != expected_scope.as_str() {
        return Err(CryptoError::InvalidEnvelope(
            "epoch bundle version or scope mismatch".into(),
        ));
    }
    if payload.host_node != expected_host_node || payload.resource != expected_resource {
        return Err(CryptoError::InvalidEnvelope(
            "epoch bundle hostNode or resource mismatch".into(),
        ));
    }
    if payload.created_by_kid != creator_signing_pk.kid() {
        return Err(CryptoError::InvalidEnvelope(
            "epoch bundle createdByKid does not match creator key".into(),
        ));
    }
    if payload.epoch == 0 || payload.epoch < min_expected_epoch {
        return Err(CryptoError::ReplayOrRollback(format!(
            "epoch rollback: got epoch {} < minimum {}",
            payload.epoch, min_expected_epoch
        )));
    }

    // 2. Verify membersHash covers every wrap (prevents wrap stripping/stuffing).
    let member_ids: Vec<(String, String)> = payload
        .wraps
        .iter()
        .map(|w| (w.node_id.clone(), w.recipient_kid.clone()))
        .collect();
    let recomputed_hash = compute_members_hash(&member_ids)?;
    if recomputed_hash != payload.members_hash {
        return Err(CryptoError::InvalidEnvelope(
            "epoch bundle membersHash mismatch".into(),
        ));
    }

    // 3. Find our wrap slot and HPKE-unwrap the 32-byte room key.
    let my_kid = my_enc_kp.kid();
    let slot = payload
        .wraps
        .iter()
        .find(|w| w.node_id == my_node_id && w.recipient_kid == my_kid)
        .ok_or_else(|| {
            CryptoError::DecryptionFailed(format!(
                "no epoch wrap slot for node '{my_node_id}' kid '{my_kid}'"
            ))
        })?;

    let enc_vec = URL_SAFE_NO_PAD
        .decode(&slot.enc)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid wrap enc base64url: {e}")))?;
    let enc: [u8; 32] = enc_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope("wrap enc must be 32 bytes".into()))?;
    let ct = URL_SAFE_NO_PAD
        .decode(&slot.ct)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid wrap ct base64url: {e}")))?;

    let info = epoch_wrap_info(
        expected_scope,
        &payload.host_node,
        &payload.resource,
        payload.epoch,
    );
    let aad = epoch_wrap_aad(
        &payload.host_node,
        &payload.resource,
        payload.epoch,
        &slot.node_id,
        &slot.recipient_kid,
        &payload.members_hash,
    );
    let unwrapped = hpke::open_base(&enc, my_enc_kp, &info, &aad, &ct)?;
    if unwrapped.len() != 32 {
        return Err(CryptoError::DecryptionFailed(
            "unwrapped room key is not 32 bytes".into(),
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&unwrapped);

    Ok((
        RoomEpochKey {
            epoch: payload.epoch,
            key,
        },
        payload,
    ))
}

// ============================================================================
// channel.e2ee.v1
// ============================================================================

/// Context bound into `channel.e2ee.v1` AEAD AAD and Ed25519 signature.
#[derive(Debug, Clone, Copy)]
pub struct ChannelContext<'a> {
    pub host_node: &'a str,
    pub channel: &'a str,
    pub msg_id: &'a str,
    pub sender: &'a str,
}

/// Wire envelope for E2EE `#channel` messages (`channel.e2ee.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelEnvelopeV1 {
    pub v: u8,
    pub suite: String,
    pub epoch: u64,
    #[serde(rename = "senderKid")]
    pub sender_kid: String,
    pub nonce: String,
    pub ct: String,
    pub sig: String,
}

#[derive(Serialize)]
struct ChannelSigInput<'a> {
    v: u8,
    suite: &'a str,
    #[serde(rename = "hostNode")]
    host_node: &'a str,
    channel: &'a str,
    #[serde(rename = "msgId")]
    msg_id: &'a str,
    sender: &'a str,
    epoch: u64,
    #[serde(rename = "senderKid")]
    sender_kid: &'a str,
    nonce: &'a str,
    #[serde(rename = "ctSha256")]
    ct_sha256: &'a str,
}

fn channel_aad(ctx: &ChannelContext<'_>, epoch: u64, sender_kid: &str) -> Vec<u8> {
    format!(
        "hyphae/v2/channel\n{}\n{}\n{}\n{}\n{}\n{}",
        ctx.host_node, ctx.channel, ctx.msg_id, ctx.sender, epoch, sender_kid
    )
    .into_bytes()
}

fn derive_channel_msg_key(
    room_key: &RoomEpochKey,
    ctx: &ChannelContext<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let info = format!(
        "hyphae/v2/channel-msg\n{}\n{}\n{}",
        ctx.host_node, ctx.channel, room_key.epoch
    );
    hkdf_sha256(ctx.msg_id.as_bytes(), &*room_key.key, info.as_bytes(), 32)
}

/// Encrypts a `#channel` post under `room_key` (AES-256-GCM + bucket padding) and signs with sender's Ed25519 key.
pub fn seal_channel_message(
    ctx: &ChannelContext<'_>,
    plaintext: &[u8],
    room_key: &RoomEpochKey,
    sender_signing: &Ed25519KeyPair,
) -> Result<ChannelEnvelopeV1, CryptoError> {
    let padded = pad_bucket(plaintext)?;
    let msg_key = derive_channel_msg_key(room_key, ctx)?;
    let sender_kid = sender_signing.kid();

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;

    let aad = channel_aad(ctx, room_key.epoch, &sender_kid);
    let unbound = UnboundKey::new(&aead::AES_256_GCM, &msg_key)
        .map_err(|_| CryptoError::Hpke("failed to construct AES-256-GCM key".into()))?;
    let aead_key = LessSafeKey::new(unbound);

    let mut ct_bytes = Vec::with_capacity(padded.len() + 16);
    ct_bytes.extend_from_slice(&padded);
    aead_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&aad),
            &mut ct_bytes,
        )
        .map_err(|_| CryptoError::Hpke("channel AEAD seal failed".into()))?;

    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let ct = URL_SAFE_NO_PAD.encode(&ct_bytes);
    let ct_sha256 = hex::encode(Sha256::digest(&ct_bytes));

    let sig_payload = to_canonical_json(&ChannelSigInput {
        v: 1,
        suite: SUITE_CHANNEL_V1,
        host_node: ctx.host_node,
        channel: ctx.channel,
        msg_id: ctx.msg_id,
        sender: ctx.sender,
        epoch: room_key.epoch,
        sender_kid: &sender_kid,
        nonce: &nonce,
        ct_sha256: &ct_sha256,
    })?;
    let sig = sender_signing.sign_domain_b64("channel", sig_payload.as_bytes());

    Ok(ChannelEnvelopeV1 {
        v: 1,
        suite: SUITE_CHANNEL_V1.to_string(),
        epoch: room_key.epoch,
        sender_kid,
        nonce,
        ct,
        sig,
    })
}

/// Verifies anti-rollback (`min_epoch`) and sender Ed25519 signature FIRST, then decrypts a `channel.e2ee.v1` post.
pub fn open_channel_message(
    envelope: &ChannelEnvelopeV1,
    ctx: &ChannelContext<'_>,
    room_key: &RoomEpochKey,
    sender_signing_pk: &Ed25519PublicKey,
    min_epoch: u64,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.v != 1 || envelope.suite != SUITE_CHANNEL_V1 {
        return Err(CryptoError::InvalidEnvelope(
            "unsupported channel envelope version or suite".into(),
        ));
    }
    if envelope.epoch < min_epoch {
        return Err(CryptoError::ReplayOrRollback(format!(
            "channel message epoch {} < minimum {}",
            envelope.epoch, min_epoch
        )));
    }
    if envelope.epoch != room_key.epoch {
        return Err(CryptoError::InvalidEnvelope(format!(
            "channel message epoch {} does not match supplied room key epoch {}",
            envelope.epoch, room_key.epoch
        )));
    }
    if envelope.sender_kid != sender_signing_pk.kid() {
        return Err(CryptoError::InvalidEnvelope(
            "senderKid does not match expected sender key".into(),
        ));
    }

    let nonce_vec = URL_SAFE_NO_PAD
        .decode(&envelope.nonce)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid nonce base64url: {e}")))?;
    let nonce_bytes: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope("nonce must be 12 bytes".into()))?;
    let ct_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.ct)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid ct base64url: {e}")))?;
    let ct_sha256 = hex::encode(Sha256::digest(&ct_bytes));

    // Verify sender Ed25519 signature BEFORE decrypting!
    let sig_payload = to_canonical_json(&ChannelSigInput {
        v: 1,
        suite: SUITE_CHANNEL_V1,
        host_node: ctx.host_node,
        channel: ctx.channel,
        msg_id: ctx.msg_id,
        sender: ctx.sender,
        epoch: envelope.epoch,
        sender_kid: &envelope.sender_kid,
        nonce: &envelope.nonce,
        ct_sha256: &ct_sha256,
    })?;
    sender_signing_pk.verify_domain_b64("channel", sig_payload.as_bytes(), &envelope.sig)?;

    let msg_key = derive_channel_msg_key(room_key, ctx)?;
    let aad = channel_aad(ctx, envelope.epoch, &envelope.sender_kid);
    let unbound = UnboundKey::new(&aead::AES_256_GCM, &msg_key)
        .map_err(|_| CryptoError::Hpke("failed to construct AES-256-GCM key".into()))?;
    let aead_key = LessSafeKey::new(unbound);

    let mut buf = Zeroizing::new(ct_bytes);
    let pt_len = aead_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&aad),
            &mut buf,
        )
        .map_err(|_| CryptoError::DecryptionFailed("channel AEAD authentication failed".into()))?
        .len();
    buf.truncate(pt_len);
    unpad_bucket(&buf)
}

// ============================================================================
// kv.e2ee.v1
// ============================================================================

/// Context bound into `kv.e2ee.v1` AEAD AAD (`hyphae/v2/kv\n...`) and writer Ed25519 signature.
#[derive(Debug, Clone, Copy)]
pub struct KvContext<'a> {
    pub host_node: &'a str,
    pub namespace: &'a str,
    pub key: &'a str,
    pub version: u64,
    pub writer_node_id: &'a str,
    pub writer_grant_id: &'a str,
}

/// Wire envelope for E2EE Shared KV entries (`kv.e2ee.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvEnvelopeV1 {
    pub v: u8,
    pub suite: String,
    pub epoch: u64,
    pub version: u64,
    #[serde(rename = "writerKid")]
    pub writer_kid: String,
    pub nonce: String,
    pub ct: String,
    pub sig: String,
}

#[derive(Serialize)]
struct KvSigInput<'a> {
    v: u8,
    suite: &'a str,
    #[serde(rename = "hostNode")]
    host_node: &'a str,
    namespace: &'a str,
    key: &'a str,
    version: u64,
    epoch: u64,
    #[serde(rename = "writerNodeId")]
    writer_node_id: &'a str,
    #[serde(rename = "writerGrantId")]
    writer_grant_id: &'a str,
    #[serde(rename = "writerKid")]
    writer_kid: &'a str,
    nonce: &'a str,
    #[serde(rename = "ctSha256")]
    ct_sha256: &'a str,
}

fn kv_aad(ctx: &KvContext<'_>, epoch: u64, writer_kid: &str) -> Vec<u8> {
    format!(
        "hyphae/v2/kv\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        ctx.host_node,
        ctx.namespace,
        ctx.key,
        ctx.version,
        epoch,
        ctx.writer_node_id,
        ctx.writer_grant_id,
        writer_kid
    )
    .into_bytes()
}

fn derive_kv_entry_key(
    room_key: &RoomEpochKey,
    ctx: &KvContext<'_>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let salt = format!("{}/{}@{}", ctx.namespace, ctx.key, ctx.version);
    let info = format!(
        "hyphae/v2/kv-entry\n{}\n{}\n{}",
        ctx.host_node, ctx.namespace, room_key.epoch
    );
    hkdf_sha256(salt.as_bytes(), &*room_key.key, info.as_bytes(), 32)
}

/// Encrypts a KV value under `room_key` with structured `hyphae/v2/kv\n...` AAD and writer Ed25519 signature.
pub fn seal_kv_entry(
    ctx: &KvContext<'_>,
    value: &[u8],
    room_key: &RoomEpochKey,
    writer_signing: &Ed25519KeyPair,
) -> Result<KvEnvelopeV1, CryptoError> {
    let entry_key = derive_kv_entry_key(room_key, ctx)?;
    let writer_kid = writer_signing.kid();

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;

    let aad = kv_aad(ctx, room_key.epoch, &writer_kid);
    let unbound = UnboundKey::new(&aead::AES_256_GCM, &entry_key)
        .map_err(|_| CryptoError::Hpke("failed to construct AES-256-GCM key".into()))?;
    let aead_key = LessSafeKey::new(unbound);

    let mut ct_bytes = Vec::with_capacity(value.len() + 16);
    ct_bytes.extend_from_slice(value);
    aead_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&aad),
            &mut ct_bytes,
        )
        .map_err(|_| CryptoError::Hpke("KV AEAD seal failed".into()))?;

    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let ct = URL_SAFE_NO_PAD.encode(&ct_bytes);
    let ct_sha256 = hex::encode(Sha256::digest(&ct_bytes));

    let sig_payload = to_canonical_json(&KvSigInput {
        v: 1,
        suite: SUITE_KV_V1,
        host_node: ctx.host_node,
        namespace: ctx.namespace,
        key: ctx.key,
        version: ctx.version,
        epoch: room_key.epoch,
        writer_node_id: ctx.writer_node_id,
        writer_grant_id: ctx.writer_grant_id,
        writer_kid: &writer_kid,
        nonce: &nonce,
        ct_sha256: &ct_sha256,
    })?;
    let sig = writer_signing.sign_domain_b64("kv", sig_payload.as_bytes());

    Ok(KvEnvelopeV1 {
        v: 1,
        suite: SUITE_KV_V1.to_string(),
        epoch: room_key.epoch,
        version: ctx.version,
        writer_kid,
        nonce,
        ct,
        sig,
    })
}

/// Verifies epoch + version anti-rollback and writer Ed25519 signature FIRST, then decrypts a `kv.e2ee.v1` entry.
pub fn open_kv_entry(
    envelope: &KvEnvelopeV1,
    ctx: &KvContext<'_>,
    room_key: &RoomEpochKey,
    writer_signing_pk: &Ed25519PublicKey,
    min_epoch: u64,
    max_seen_version: Option<u64>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.v != 1 || envelope.suite != SUITE_KV_V1 {
        return Err(CryptoError::InvalidEnvelope(
            "unsupported KV envelope version or suite".into(),
        ));
    }
    if envelope.epoch < min_epoch {
        return Err(CryptoError::ReplayOrRollback(format!(
            "KV epoch rollback: got {} < minimum {}",
            envelope.epoch, min_epoch
        )));
    }
    if envelope.epoch != room_key.epoch {
        return Err(CryptoError::InvalidEnvelope(
            "KV envelope epoch does not match room key epoch".into(),
        ));
    }
    if envelope.version != ctx.version {
        return Err(CryptoError::InvalidEnvelope(
            "KV envelope version does not match context version".into(),
        ));
    }
    if let Some(seen) = max_seen_version {
        if envelope.version < seen {
            return Err(CryptoError::ReplayOrRollback(format!(
                "KV version rollback: got {} < max seen {}",
                envelope.version, seen
            )));
        }
    }
    if envelope.writer_kid != writer_signing_pk.kid() {
        return Err(CryptoError::InvalidEnvelope(
            "writerKid does not match expected writer key".into(),
        ));
    }

    let nonce_vec = URL_SAFE_NO_PAD
        .decode(&envelope.nonce)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid nonce base64url: {e}")))?;
    let nonce_bytes: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope("nonce must be 12 bytes".into()))?;
    let ct_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.ct)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid ct base64url: {e}")))?;
    let ct_sha256 = hex::encode(Sha256::digest(&ct_bytes));

    // Verify writer Ed25519 signature BEFORE decrypting!
    let sig_payload = to_canonical_json(&KvSigInput {
        v: 1,
        suite: SUITE_KV_V1,
        host_node: ctx.host_node,
        namespace: ctx.namespace,
        key: ctx.key,
        version: envelope.version,
        epoch: envelope.epoch,
        writer_node_id: ctx.writer_node_id,
        writer_grant_id: ctx.writer_grant_id,
        writer_kid: &envelope.writer_kid,
        nonce: &envelope.nonce,
        ct_sha256: &ct_sha256,
    })?;
    writer_signing_pk.verify_domain_b64("kv", sig_payload.as_bytes(), &envelope.sig)?;

    let entry_key = derive_kv_entry_key(room_key, ctx)?;
    let aad = kv_aad(ctx, envelope.epoch, &envelope.writer_kid);
    let unbound = UnboundKey::new(&aead::AES_256_GCM, &entry_key)
        .map_err(|_| CryptoError::Hpke("failed to construct AES-256-GCM key".into()))?;
    let aead_key = LessSafeKey::new(unbound);

    let mut buf = Zeroizing::new(ct_bytes);
    let pt_len = aead_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&aad),
            &mut buf,
        )
        .map_err(|_| CryptoError::DecryptionFailed("KV AEAD authentication failed".into()))?
        .len();
    buf.truncate(pt_len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NodeIdentityKeys;

    #[test]
    fn padding_buckets_and_validation() {
        for &(len, expected) in &[
            (0usize, 256usize),
            (1, 256),
            (254, 256),
            (255, 512),
            (510, 512),
            (511, 1024),
            (16382, 16384),
            (16383, 32768),
            (32766, 32768),
        ] {
            let pt = vec![0x42u8; len];
            let padded = pad_bucket(&pt).unwrap();
            assert_eq!(padded.len(), expected);
            let unpadded = unpad_bucket(&padded).unwrap();
            assert_eq!(unpadded.as_slice(), pt.as_slice());
        }
        assert!(pad_bucket(&vec![0u8; 32767]).is_err());

        // Non-zero trailing padding byte rejected
        let mut corrupt = pad_bucket(b"abc").unwrap();
        corrupt[200] = 1;
        assert!(unpad_bucket(&corrupt).is_err());
    }

    #[test]
    fn dm_e2ee_v1_roundtrip_and_mutations() {
        let alice = NodeIdentityKeys::generate().unwrap();
        let bob = NodeIdentityKeys::generate().unwrap();
        let mallory = NodeIdentityKeys::generate().unwrap();

        let ctx = DmContext {
            node_id: "acme-team",
            msg_id: "msg-001",
            sender: "alice@macbook/claude",
            recipient: "bob@laptop/codex",
        };
        let env = seal_dm(
            &ctx,
            b"secret deploy token",
            &alice.signing,
            &bob.encryption.public_key(),
        )
        .unwrap();
        let opened = open_dm(&env, &ctx, &alice.signing.public_key(), &bob.encryption).unwrap();
        assert_eq!(opened.as_slice(), b"secret deploy token");

        // Wrong sender fails
        assert!(open_dm(&env, &ctx, &mallory.signing.public_key(), &bob.encryption).is_err());
        // Wrong recipient fails
        assert!(open_dm(&env, &ctx, &alice.signing.public_key(), &mallory.encryption).is_err());
        // Re-routed msg_id or recipient fails
        let mut bad_ctx = ctx;
        bad_ctx.msg_id = "msg-002";
        assert!(open_dm(&env, &bad_ctx, &alice.signing.public_key(), &bob.encryption).is_err());

        // 1-bit flip in sig
        let mut bad_sig = env.clone();
        let mut raw_sig = URL_SAFE_NO_PAD.decode(&bad_sig.sig).unwrap();
        raw_sig[0] ^= 0x01;
        bad_sig.sig = URL_SAFE_NO_PAD.encode(raw_sig);
        assert!(open_dm(&bad_sig, &ctx, &alice.signing.public_key(), &bob.encryption).is_err());

        // 1-bit flip in ct
        let mut bad_ct = env.clone();
        let mut raw_ct = URL_SAFE_NO_PAD.decode(&bad_ct.ct).unwrap();
        raw_ct[5] ^= 0x01;
        bad_ct.ct = URL_SAFE_NO_PAD.encode(raw_ct);
        assert!(open_dm(&bad_ct, &ctx, &alice.signing.public_key(), &bob.encryption).is_err());
    }

    #[test]
    fn channel_and_kv_epoch_rotation_and_anti_rollback() {
        let alice = NodeIdentityKeys::generate().unwrap();
        let bob = NodeIdentityKeys::generate().unwrap();
        let carol = NodeIdentityKeys::generate().unwrap();

        let alice_pub = alice.encryption.public_key();
        let bob_pub = bob.encryption.public_key();
        let carol_pub = carol.encryption.public_key();

        // Epoch 1: Alice + Bob
        let (rk1, bundle1) = create_epoch_bundle(
            EpochScope::Channel,
            "acme-team",
            "#incidents",
            1,
            "alice@macbook",
            &alice.signing,
            &[
                EpochMember {
                    node_id: "alice@macbook",
                    enc_pk: &alice_pub,
                },
                EpochMember {
                    node_id: "bob@laptop",
                    enc_pk: &bob_pub,
                },
            ],
        )
        .unwrap();

        let (bob_rk1, _) = open_epoch_bundle(
            &bundle1,
            EpochScope::Channel,
            "acme-team",
            "#incidents",
            &alice.signing.public_key(),
            "bob@laptop",
            &bob.encryption,
            1,
        )
        .unwrap();
        assert_eq!(bob_rk1.key_bytes(), rk1.key_bytes());

        // Carol cannot unwrap epoch 1
        assert!(
            open_epoch_bundle(
                &bundle1,
                EpochScope::Channel,
                "acme-team",
                "#incidents",
                &alice.signing.public_key(),
                "carol@dev",
                &carol.encryption,
                1,
            )
            .is_err()
        );

        // Channel message in epoch 1
        let ch_ctx = ChannelContext {
            host_node: "acme-team",
            channel: "#incidents",
            msg_id: "ch-1",
            sender: "alice@macbook/claude",
        };
        let ch_env =
            seal_channel_message(&ch_ctx, b"p0 outage in checkout", &rk1, &alice.signing).unwrap();
        let ch_pt =
            open_channel_message(&ch_env, &ch_ctx, &bob_rk1, &alice.signing.public_key(), 1)
                .unwrap();
        assert_eq!(ch_pt.as_slice(), b"p0 outage in checkout");

        // Rotate to epoch 2: Alice + Carol (Bob removed!)
        let (rk2, bundle2) = rotate_epoch_bundle(
            EpochScope::Channel,
            "acme-team",
            "#incidents",
            1,
            "alice@macbook",
            &alice.signing,
            &[
                EpochMember {
                    node_id: "alice@macbook",
                    enc_pk: &alice_pub,
                },
                EpochMember {
                    node_id: "carol@dev",
                    enc_pk: &carol_pub,
                },
            ],
        )
        .unwrap();
        assert_eq!(rk2.epoch(), 2);

        // Bob cannot open epoch 2 bundle
        assert!(
            open_epoch_bundle(
                &bundle2,
                EpochScope::Channel,
                "acme-team",
                "#incidents",
                &alice.signing.public_key(),
                "bob@laptop",
                &bob.encryption,
                2,
            )
            .is_err()
        );

        // Rollback attempt: presenting bundle1 when min_expected_epoch = 2 fails closed!
        assert!(matches!(
            open_epoch_bundle(
                &bundle1,
                EpochScope::Channel,
                "acme-team",
                "#incidents",
                &alice.signing.public_key(),
                "alice@macbook",
                &alice.encryption,
                2,
            ),
            Err(CryptoError::ReplayOrRollback(_))
        ));

        // KV E2EE + key swap & version rollback protection
        let (kv_rk, _) = create_epoch_bundle(
            EpochScope::Kv,
            "acme-team",
            "deploys",
            1,
            "alice@macbook",
            &alice.signing,
            &[EpochMember {
                node_id: "alice@macbook",
                enc_pk: &alice_pub,
            }],
        )
        .unwrap();
        let kv_ctx = KvContext {
            host_node: "acme-team",
            namespace: "deploys",
            key: "checkout/sha",
            version: 5,
            writer_node_id: "alice@macbook",
            writer_grant_id: "grant-1",
        };
        let kv_env = seal_kv_entry(&kv_ctx, b"deadbeef", &kv_rk, &alice.signing).unwrap();
        assert_eq!(
            open_kv_entry(
                &kv_env,
                &kv_ctx,
                &kv_rk,
                &alice.signing.public_key(),
                1,
                Some(5)
            )
            .unwrap()
            .as_slice(),
            b"deadbeef"
        );
        // Version rollback (max_seen_version = 6 > envelope.version = 5) fails closed
        assert!(matches!(
            open_kv_entry(
                &kv_env,
                &kv_ctx,
                &kv_rk,
                &alice.signing.public_key(),
                1,
                Some(6)
            ),
            Err(CryptoError::ReplayOrRollback(_))
        ));
        // Key swap attack fails closed
        let mut swapped = kv_ctx;
        swapped.key = "payments/sha";
        assert!(
            open_kv_entry(
                &kv_env,
                &swapped,
                &kv_rk,
                &alice.signing.public_key(),
                1,
                None
            )
            .is_err()
        );
    }
}
