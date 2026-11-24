//! Hyphae v2 File Transfer Primitives:
//! 1. **Streaming 64 KiB Chunked AES-256-GCM AEAD (`transfer.stream.v2`)**:
//!    O(64 KiB) constant-RAM streaming encrypt/decrypt over `Read`/`Write`, per-chunk nonce
//!    derivation (`base_nonce XOR chunk_index`), final-chunk AAD flag (defeats truncation,
//!    extension, reordering, duplication, and cross-transfer chunk swaps), multi-recipient
//!    RFC 9180 HPKE DEK slots, and OCI `sha256:<64hex>` digests.
//! 2. **Safe Pure-Rust POSIX `tar` (USTAR/PAX) + `gzip` (`flate2`)**:
//!    Packer & strictly fail-closed streaming unpacker rejecting symlinks, hardlinks, FIFOs,
//!    device nodes, absolute paths, `..` traversal, NUL bytes, `max_files > 200`, streaming
//!    decompression bombs (default 256 MiB, configurable), forcing `0600`/`0700` permissions,
//!    and running an optional Stage 1 attachment guard predicate with immediate cleanup.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::hpke;
use crate::keys::{
    Ed25519KeyPair, Ed25519PublicKey, SignedPayload, X25519KeyPair, X25519PublicKey,
};

/// Plaintext chunk size for `transfer.stream.v2` (64 KiB).
pub const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;

/// Default maximum files allowed in a tar+gzip archive.
pub const DEFAULT_MAX_TAR_FILES: usize = 200;

/// Default maximum uncompressed bytes allowed when packing/unpacking a tar+gzip archive (256 MiB).
pub const DEFAULT_MAX_TAR_RAW_BYTES: u64 = 256 * 1024 * 1024;

const SUITE_TRANSFER_STREAM_V2: &str = "transfer.stream.v2";
const STREAM_MAGIC: &[u8; 4] = b"HTS2";
const GCM_TAG_LEN: usize = 16;
const TAR_BLOCK_SIZE: usize = 512;
const MAX_PAX_HEADER_BYTES: usize = 64 * 1024;

// ============================================================================
// Part 1: Streaming 64 KiB Chunked AES-256-GCM (`transfer.stream.v2`)
// ============================================================================

/// Multi-recipient HPKE-wrapped DEK slot for `transfer.stream.v2`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRecipientSlot {
    pub to: String,
    #[serde(rename = "recipientKid")]
    pub recipient_kid: String,
    pub enc: String,
    #[serde(rename = "wrappedDek")]
    pub wrapped_dek: String,
}

/// Metadata header for a streaming `transfer.stream.v2` encrypted blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferStreamHeaderV2 {
    pub v: u8,
    pub suite: String,
    pub id: String,
    pub from: String,
    #[serde(rename = "senderKid")]
    pub sender_kid: String,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    #[serde(rename = "chunkSize")]
    pub chunk_size: usize,
    #[serde(rename = "baseNonce")]
    pub base_nonce: String,
    /// OCI digest (`sha256:<64hex>`) of the unencrypted payload stream.
    #[serde(rename = "plaintextDigest")]
    pub plaintext_digest: String,
    /// OCI digest (`sha256:<64hex>`) of the encrypted chunked stream.
    #[serde(rename = "ciphertextDigest")]
    pub ciphertext_digest: String,
    #[serde(rename = "plaintextBytes")]
    pub plaintext_bytes: u64,
    #[serde(rename = "ciphertextBytes")]
    pub ciphertext_bytes: u64,
    #[serde(rename = "chunkCount")]
    pub chunk_count: u64,
    pub recipients: Vec<TransferRecipientSlot>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

/// Ed25519-signed canonical JCS `TransferStreamHeaderV2`.
pub type SignedTransferHeaderV2 = SignedPayload;

/// Parameters for `encrypt_stream_v2`.
#[derive(Debug, Clone)]
pub struct StreamEncryptParams<'a> {
    pub id: &'a str,
    pub from: &'a str,
    pub media_type: &'a str,
    pub created_at: &'a str,
    pub expires_at: &'a str,
}

fn chunk_nonce(base_nonce: &[u8; 12], chunk_index: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let idx = chunk_index.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= idx[i];
    }
    nonce
}

fn chunk_aad(transfer_id: &str, sender_kid: &str, chunk_index: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(28 + transfer_id.len() + sender_kid.len() + 9);
    aad.extend_from_slice(b"hyphae/v2/transfer-chunk\n");
    aad.extend_from_slice(transfer_id.as_bytes());
    aad.push(b'\n');
    aad.extend_from_slice(sender_kid.as_bytes());
    aad.push(b'\n');
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.push(u8::from(is_final));
    aad
}

fn dek_wrap_info(transfer_id: &str, from: &str) -> Vec<u8> {
    format!("hyphae/v2/transfer-dek\n{transfer_id}\n{from}").into_bytes()
}

fn dek_wrap_aad(
    transfer_id: &str,
    from: &str,
    to: &str,
    recipient_kid: &str,
    base_nonce_b64: &str,
) -> Vec<u8> {
    format!("{transfer_id}\n{from}\n{to}\n{recipient_kid}\n{base_nonce_b64}").into_bytes()
}

fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Streams `reader` through 64 KiB chunked AES-256-GCM AEAD into `writer` in O(64 KiB) RAM,
/// wraps the random 256-bit DEK per recipient via RFC 9180 HPKE, and returns the Ed25519-signed header.
pub fn encrypt_stream_v2<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    params: &StreamEncryptParams<'_>,
    sender_signing: &Ed25519KeyPair,
    recipients: &[(&str, &X25519PublicKey)],
) -> Result<SignedTransferHeaderV2, CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::InvalidTransfer(
            "transfer requires at least one recipient".into(),
        ));
    }

    let rng = SystemRandom::new();
    let mut dek = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *dek)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;
    let mut base_nonce = [0u8; 12];
    rng.fill(&mut base_nonce)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;

    let sender_kid = sender_signing.kid();
    let base_nonce_b64 = URL_SAFE_NO_PAD.encode(base_nonce);

    let unbound = UnboundKey::new(&aead::AES_256_GCM, &*dek)
        .map_err(|_| CryptoError::Hpke("failed to construct AES-256-GCM key".into()))?;
    let aead_key = LessSafeKey::new(unbound);

    let mut pt_hasher = Sha256::new();
    let mut ct_hasher = Sha256::new();
    let mut plaintext_bytes = 0u64;
    let mut ciphertext_bytes = 0u64;

    // Write 4-byte stream magic header.
    writer.write_all(STREAM_MAGIC)?;
    ct_hasher.update(STREAM_MAGIC);
    ciphertext_bytes += STREAM_MAGIC.len() as u64;

    // Double-buffer (2 x 64 KiB) so we know `is_final` without buffering the whole payload.
    let mut cur_buf = Zeroizing::new(vec![0u8; TRANSFER_CHUNK_SIZE]);
    let mut next_buf = Zeroizing::new(vec![0u8; TRANSFER_CHUNK_SIZE]);
    let mut cur_len = read_up_to(&mut reader, &mut cur_buf)?;
    let mut chunk_index = 0u64;
    let mut ct_work = Vec::with_capacity(TRANSFER_CHUNK_SIZE + GCM_TAG_LEN);

    loop {
        let next_len = if cur_len == TRANSFER_CHUNK_SIZE {
            read_up_to(&mut reader, &mut next_buf)?
        } else {
            0
        };
        let is_final = next_len == 0;

        let chunk_pt = &cur_buf[..cur_len];
        pt_hasher.update(chunk_pt);
        plaintext_bytes = plaintext_bytes
            .checked_add(cur_len as u64)
            .ok_or_else(|| CryptoError::InvalidTransfer("plaintext size overflow".into()))?;

        ct_work.clear();
        ct_work.extend_from_slice(chunk_pt);
        let nonce = chunk_nonce(&base_nonce, chunk_index);
        let aad = chunk_aad(params.id, &sender_kid, chunk_index, is_final);
        aead_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut ct_work,
            )
            .map_err(|_| CryptoError::Hpke("transfer chunk AEAD seal failed".into()))?;

        let len_be = (ct_work.len() as u32).to_be_bytes();
        writer.write_all(&len_be)?;
        writer.write_all(&ct_work)?;
        ct_hasher.update(len_be);
        ct_hasher.update(&ct_work);
        ciphertext_bytes = ciphertext_bytes
            .checked_add(4 + ct_work.len() as u64)
            .ok_or_else(|| CryptoError::InvalidTransfer("ciphertext size overflow".into()))?;

        chunk_index = chunk_index
            .checked_add(1)
            .ok_or(CryptoError::SequenceOverflow)?;

        if is_final {
            break;
        }
        std::mem::swap(&mut cur_buf, &mut next_buf);
        cur_len = next_len;
    }

    writer.flush()?;

    // Wrap DEK for each recipient via RFC 9180 HPKE.
    let wrap_info = dek_wrap_info(params.id, params.from);
    let mut slots = Vec::with_capacity(recipients.len());
    for &(to, enc_pk) in recipients {
        let recipient_kid = enc_pk.kid();
        let wrap_aad = dek_wrap_aad(params.id, params.from, to, &recipient_kid, &base_nonce_b64);
        let (enc, wrapped_dek) = hpke::seal_base(enc_pk, &wrap_info, &wrap_aad, &*dek)?;
        slots.push(TransferRecipientSlot {
            to: to.to_string(),
            recipient_kid,
            enc: URL_SAFE_NO_PAD.encode(enc),
            wrapped_dek: URL_SAFE_NO_PAD.encode(wrapped_dek),
        });
    }

    let header = TransferStreamHeaderV2 {
        v: 2,
        suite: SUITE_TRANSFER_STREAM_V2.to_string(),
        id: params.id.to_string(),
        from: params.from.to_string(),
        sender_kid,
        media_type: params.media_type.to_string(),
        chunk_size: TRANSFER_CHUNK_SIZE,
        base_nonce: base_nonce_b64,
        plaintext_digest: format!("sha256:{}", hex::encode(pt_hasher.finalize())),
        ciphertext_digest: format!("sha256:{}", hex::encode(ct_hasher.finalize())),
        plaintext_bytes,
        ciphertext_bytes,
        chunk_count: chunk_index,
        recipients: slots,
        created_at: params.created_at.to_string(),
        expires_at: params.expires_at.to_string(),
    };

    sender_signing.sign_jcs("transfer", &header)
}

/// Verifies the signed `TransferStreamHeaderV2`, HPKE-unwraps the DEK for `my_node_id`,
/// and streams decryption of `reader` into `writer` in O(64 KiB) RAM, rejecting any truncation,
/// extension, reordering, bit-flip, or digest mismatch.
pub fn decrypt_stream_v2<R: Read, W: Write>(
    signed_header: &SignedTransferHeaderV2,
    mut reader: R,
    mut writer: W,
    sender_signing_pk: &Ed25519PublicKey,
    my_node_id: &str,
    my_enc_kp: &X25519KeyPair,
) -> Result<TransferStreamHeaderV2, CryptoError> {
    // 1. Verify sender Ed25519 signature FIRST!
    let header: TransferStreamHeaderV2 = sender_signing_pk.verify_signed("transfer", signed_header)?;

    if header.v != 2 || header.suite != SUITE_TRANSFER_STREAM_V2 {
        return Err(CryptoError::InvalidTransfer(
            "unsupported transfer stream version or suite".into(),
        ));
    }
    if header.sender_kid != sender_signing_pk.kid() {
        return Err(CryptoError::InvalidTransfer(
            "transfer senderKid does not match sender key".into(),
        ));
    }
    if header.chunk_size != TRANSFER_CHUNK_SIZE || header.chunk_count == 0 {
        return Err(CryptoError::InvalidTransfer(
            "invalid chunkSize or chunkCount in transfer header".into(),
        ));
    }

    let base_nonce_vec = URL_SAFE_NO_PAD
        .decode(&header.base_nonce)
        .map_err(|e| CryptoError::InvalidTransfer(format!("invalid baseNonce: {e}")))?;
    let base_nonce: [u8; 12] = base_nonce_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidTransfer("baseNonce must be 12 bytes".into()))?;

    // 2. Find our recipient slot and HPKE-unwrap the DEK.
    let my_kid = my_enc_kp.kid();
    let slot = header
        .recipients
        .iter()
        .find(|r| r.to == my_node_id && r.recipient_kid == my_kid)
        .ok_or_else(|| {
            CryptoError::DecryptionFailed(format!(
                "no transfer recipient slot for '{my_node_id}' kid '{my_kid}'"
            ))
        })?;

    let enc_vec = URL_SAFE_NO_PAD
        .decode(&slot.enc)
        .map_err(|e| CryptoError::InvalidTransfer(format!("invalid slot enc: {e}")))?;
    let enc: [u8; 32] = enc_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidTransfer("slot enc must be 32 bytes".into()))?;
    let wrapped_dek = URL_SAFE_NO_PAD
        .decode(&slot.wrapped_dek)
        .map_err(|e| CryptoError::InvalidTransfer(format!("invalid slot wrappedDek: {e}")))?;

    let wrap_info = dek_wrap_info(&header.id, &header.from);
    let wrap_aad = dek_wrap_aad(
        &header.id,
        &header.from,
        &slot.to,
        &slot.recipient_kid,
        &header.base_nonce,
    );
    let dek = hpke::open_base(&enc, my_enc_kp, &wrap_info, &wrap_aad, &wrapped_dek)?;
    if dek.len() != 32 {
        return Err(CryptoError::DecryptionFailed(
            "unwrapped DEK is not 32 bytes".into(),
        ));
    }

    let unbound = UnboundKey::new(&aead::AES_256_GCM, &dek)
        .map_err(|_| CryptoError::Hpke("failed to construct AES-256-GCM key".into()))?;
    let aead_key = LessSafeKey::new(unbound);

    // 3. Stream & authenticate chunks.
    let mut pt_hasher = Sha256::new();
    let mut ct_hasher = Sha256::new();
    let mut total_pt_bytes = 0u64;
    let mut total_ct_bytes = 0u64;

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).map_err(|_| {
        CryptoError::InvalidTransfer("truncated transfer stream: missing magic".into())
    })?;
    if &magic != STREAM_MAGIC {
        return Err(CryptoError::InvalidTransfer(
            "corrupt transfer stream: invalid magic".into(),
        ));
    }
    ct_hasher.update(magic);
    total_ct_bytes += 4;

    let mut chunk_buf = Zeroizing::new(Vec::with_capacity(TRANSFER_CHUNK_SIZE + GCM_TAG_LEN));

    for chunk_index in 0..header.chunk_count {
        let is_final = chunk_index + 1 == header.chunk_count;

        let mut len_be = [0u8; 4];
        reader.read_exact(&mut len_be).map_err(|_| {
            CryptoError::InvalidTransfer(format!(
                "truncated transfer stream at chunk {chunk_index}/{}",
                header.chunk_count
            ))
        })?;
        let ct_len = u32::from_be_bytes(len_be) as usize;
        if ct_len < GCM_TAG_LEN || ct_len > header.chunk_size + GCM_TAG_LEN {
            return Err(CryptoError::InvalidTransfer(format!(
                "invalid chunk ciphertext length {ct_len}"
            )));
        }
        if !is_final && ct_len != header.chunk_size + GCM_TAG_LEN {
            return Err(CryptoError::InvalidTransfer(format!(
                "non-final chunk {chunk_index} has unexpected length {ct_len}"
            )));
        }

        chunk_buf.resize(ct_len, 0);
        reader.read_exact(&mut chunk_buf).map_err(|_| {
            CryptoError::InvalidTransfer(format!("truncated chunk payload at chunk {chunk_index}"))
        })?;

        ct_hasher.update(len_be);
        ct_hasher.update(&*chunk_buf);
        total_ct_bytes += 4 + ct_len as u64;

        let nonce = chunk_nonce(&base_nonce, chunk_index);
        let aad = chunk_aad(&header.id, &header.sender_kid, chunk_index, is_final);
        let pt_len = aead_key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut chunk_buf,
            )
            .map_err(|_| {
                CryptoError::DecryptionFailed(format!(
                    "chunk {chunk_index} AEAD authentication failed"
                ))
            })?
            .len();

        let pt_slice = &chunk_buf[..pt_len];
        pt_hasher.update(pt_slice);
        writer.write_all(pt_slice)?;
        total_pt_bytes += pt_len as u64;
    }

    // 4. Reject any trailing bytes after the final chunk (extension attack defense).
    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(CryptoError::InvalidTransfer(
            "unexpected trailing bytes after final chunk".into(),
        ));
    }

    writer.flush()?;

    // 5. Verify sizes and OCI digests match the signed header.
    let actual_ct_digest = format!("sha256:{}", hex::encode(ct_hasher.finalize()));
    let actual_pt_digest = format!("sha256:{}", hex::encode(pt_hasher.finalize()));
    if total_ct_bytes != header.ciphertext_bytes || actual_ct_digest != header.ciphertext_digest {
        return Err(CryptoError::InvalidTransfer(
            "ciphertext byte count or OCI digest mismatch".into(),
        ));
    }
    if total_pt_bytes != header.plaintext_bytes || actual_pt_digest != header.plaintext_digest {
        return Err(CryptoError::InvalidTransfer(
            "plaintext byte count or OCI digest mismatch".into(),
        ));
    }

    Ok(header)
}

// ============================================================================
// Part 2: Safe Pure-Rust POSIX `tar` (USTAR/PAX) + `gzip` (`flate2`)
// ============================================================================

/// Options for packing a safe POSIX tar+gzip archive.
#[derive(Debug, Clone, Copy)]
pub struct TarPackOptions {
    pub max_files: usize,
    pub max_raw_bytes: u64,
}

impl Default for TarPackOptions {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_TAR_FILES,
            max_raw_bytes: DEFAULT_MAX_TAR_RAW_BYTES,
        }
    }
}

/// An entry to include in a tar+gzip archive.
#[derive(Debug, Clone)]
pub struct TarInputEntry {
    /// Relative POSIX archive path (e.g., `"reports/summary.md"` or `"hello.txt"`).
    pub archive_path: String,
    /// Local filesystem path to a regular file (never followed if symlink).
    pub source_path: PathBuf,
}

/// Metadata for a single packed or unpacked regular file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TarFileEntryMeta {
    pub path: String,
    pub size: u64,
    /// OCI digest (`sha256:<64hex>`).
    pub digest: String,
}

/// Result of packing a safe POSIX tar+gzip archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedTarGz {
    /// OCI digest (`sha256:<64hex>`) of the compressed tar+gzip byte stream.
    pub digest: String,
    pub compressed_bytes: u64,
    pub raw_bytes: u64,
    pub entries: Vec<TarFileEntryMeta>,
}

/// Extracted file descriptor returned by `unpack_tar_gz`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackedTarFile {
    pub archive_path: String,
    pub disk_path: PathBuf,
    pub size: u64,
    pub digest: String,
}

/// Result of unpacking a safe POSIX tar+gzip archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackedTarGz {
    pub dest_dir: PathBuf,
    /// OCI digest (`sha256:<64hex>`) of the compressed tar+gzip stream read.
    pub compressed_digest: String,
    pub total_raw_bytes: u64,
    pub files: Vec<UnpackedTarFile>,
}

/// Stage 1 attachment guard predicate: return `Err(reason)` to block an entry and wipe immediately.
pub type AttachmentGuard<'a> = &'a dyn Fn(&str) -> Result<(), String>;

/// Options for fail-closed tar+gzip extraction.
pub struct TarUnpackOptions<'a> {
    pub max_files: usize,
    pub max_raw_bytes: u64,
    /// Optional Stage 1 attachment guard predicate: return `Err(reason)` to block and wipe immediately.
    pub attachment_guard: Option<AttachmentGuard<'a>>,
}

impl Default for TarUnpackOptions<'_> {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_TAR_FILES,
            max_raw_bytes: DEFAULT_MAX_TAR_RAW_BYTES,
            attachment_guard: None,
        }
    }
}

/// Built-in Stage 1 attachment guard matching `docs/architecture-v2.md` §5.2:
/// blocks executables, scripts, shell startup files, git hooks, and agent config dirs.
pub fn default_stage1_attachment_guard(rel_path: &str) -> Result<(), String> {
    let lower = rel_path.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();

    // Block sensitive directories anywhere in path
    for window in segments.windows(2) {
        if window == [".git", "hooks"] {
            return Err(format!("blocked git hook path '{rel_path}'"));
        }
    }
    for &seg in &segments {
        if matches!(seg, ".claude" | ".agents" | ".codex" | ".cursor" | ".vscode") {
            return Err(format!("blocked agent config directory '{seg}' in '{rel_path}'"));
        }
    }

    let file_name = segments.last().copied().unwrap_or("");
    if matches!(
        file_name,
        ".bashrc"
            | ".zshrc"
            | ".bash_profile"
            | ".zprofile"
            | ".profile"
            | ".zshenv"
            | ".gitconfig"
            | ".npmrc"
            | ".env"
    ) {
        return Err(format!("blocked startup/sensitive dotfile '{rel_path}'"));
    }

    const BLOCKED_EXTS: &[&str] = &[
        ".sh", ".bash", ".zsh", ".command", ".exe", ".dmg", ".pkg", ".dylib", ".so", ".dll",
        ".ps1", ".bat", ".cmd", ".msi", ".vbs", ".scr", ".app", ".plist",
    ];
    for ext in BLOCKED_EXTS {
        if file_name.ends_with(ext) {
            return Err(format!(
                "blocked executable/script extension '{ext}' in '{rel_path}'"
            ));
        }
    }
    Ok(())
}

/// Strictly validates a relative POSIX tar archive path.
/// Rejects empty paths, leading `/`, `\`, NUL bytes, control chars, `.` or `..` segments,
/// Windows drive prefixes (`C:`), and trailing slashes for regular files.
pub fn validate_tar_archive_path(path: &str, allow_trailing_slash: bool) -> Result<String, CryptoError> {
    if path.is_empty() || path.len() > 4096 {
        return Err(CryptoError::UnsafeArchiveEntry(
            "archive path is empty or too long".into(),
        ));
    }
    if path.contains('\0') || path.contains('\\') {
        return Err(CryptoError::UnsafeArchiveEntry(format!(
            "archive path contains NUL or backslash: {path:?}"
        )));
    }
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(CryptoError::UnsafeArchiveEntry(format!(
            "archive path contains control characters: {path:?}"
        )));
    }
    if path.starts_with('/') {
        return Err(CryptoError::UnsafeArchiveEntry(format!(
            "absolute path rejected: {path}"
        )));
    }
    let trimmed = if allow_trailing_slash {
        path.trim_end_matches('/')
    } else {
        if path.ends_with('/') {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "regular file path cannot end with '/': {path}"
            )));
        }
        path
    };
    if trimmed.is_empty() {
        return Err(CryptoError::UnsafeArchiveEntry("empty archive path".into()));
    }

    let mut clean_parts = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "path traversal or invalid segment in '{path}'"
            )));
        }
        if part.len() > 255 {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "path segment exceeds 255 bytes in '{path}'"
            )));
        }
        // Reject Windows drive prefix like `C:`
        if part.len() >= 2 && part.as_bytes()[1] == b':' && part.as_bytes()[0].is_ascii_alphabetic() {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "drive-qualified path rejected: '{path}'"
            )));
        }
        clean_parts.push(part);
    }
    Ok(clean_parts.join("/"))
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    fn finish(self) -> (W, String, u64) {
        let digest = format!("sha256:{}", hex::encode(self.hasher.finalize()));
        (self.inner, digest, self.written)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn write_octal(field: &mut [u8], val: u64) -> Result<(), CryptoError> {
    // Write NUL-terminated octal value fitting in `field.len() - 1` digits.
    let width = field.len() - 1;
    let max_val = if width >= 21 { u64::MAX } else { (1u64 << (width * 3)) - 1 };
    if val > max_val {
        return Err(CryptoError::InvalidTransfer(format!(
            "tar octal field overflow for value {val}"
        )));
    }
    let formatted = format!("{val:0width$o}");
    field[..width].copy_from_slice(formatted.as_bytes());
    field[width] = 0;
    Ok(())
}

fn build_ustar_header(name: &str, size: u64, typeflag: u8, mode: u64) -> Result<[u8; TAR_BLOCK_SIZE], CryptoError> {
    let mut header = [0u8; TAR_BLOCK_SIZE];
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(100);
    header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    write_octal(&mut header[100..108], mode)?;
    write_octal(&mut header[108..116], 0)?; // uid
    write_octal(&mut header[116..124], 0)?; // gid
    write_octal(&mut header[124..136], size.min(0o77777777777))?;
    write_octal(&mut header[136..148], 0)?; // deterministic mtime = 0
    header[148..156].fill(b' '); // checksum placeholder
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    let checksum: u32 = header.iter().map(|&b| b as u32).sum();
    let chk_str = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(chk_str.as_bytes());
    Ok(header)
}

fn format_pax_record(key: &str, value: &str) -> String {
    let body = format!(" {key}={value}\n");
    // Iterate length until fixed point (max 2 iterations).
    let mut total_len = body.len() + 1;
    loop {
        let len_str = total_len.to_string();
        let candidate = len_str.len() + body.len();
        if candidate == total_len {
            return format!("{len_str}{body}");
        }
        total_len = candidate;
    }
}

fn write_tar_entry_stream<W: Write, R: Read>(
    tar_out: &mut W,
    archive_path: &str,
    size: u64,
    mut src: R,
) -> Result<String, CryptoError> {
    // Emit PAX extended header if path > 100 bytes, non-ASCII, or size > 8 GiB.
    let needs_pax =
        archive_path.len() > 100 || !archive_path.is_ascii() || size > 0o77777777777;
    if needs_pax {
        let mut pax_data = String::new();
        pax_data.push_str(&format_pax_record("path", archive_path));
        if size > 0o77777777777 {
            pax_data.push_str(&format_pax_record("size", &size.to_string()));
        }
        let pax_bytes = pax_data.as_bytes();
        let pax_hdr = build_ustar_header("PaxHeaders/entry", pax_bytes.len() as u64, b'x', 0o600)?;
        tar_out.write_all(&pax_hdr)?;
        tar_out.write_all(pax_bytes)?;
        let rem = pax_bytes.len() % TAR_BLOCK_SIZE;
        if rem != 0 {
            tar_out.write_all(&vec![0u8; TAR_BLOCK_SIZE - rem])?;
        }
    }

    let ustar_name = if archive_path.len() <= 100 && archive_path.is_ascii() {
        archive_path
    } else {
        "pax-entry"
    };
    let hdr = build_ustar_header(ustar_name, size, b'0', 0o600)?;
    tar_out.write_all(&hdr)?;

    let mut file_hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = src.read(&mut buf[..to_read])?;
        if n == 0 {
            return Err(CryptoError::InvalidTransfer(format!(
                "file '{archive_path}' shrank during packing"
            )));
        }
        file_hasher.update(&buf[..n]);
        tar_out.write_all(&buf[..n])?;
        remaining -= n as u64;
    }

    // Pad data to 512-byte boundary
    let rem = (size as usize) % TAR_BLOCK_SIZE;
    if rem != 0 {
        let pad = [0u8; TAR_BLOCK_SIZE];
        tar_out.write_all(&pad[..TAR_BLOCK_SIZE - rem])?;
    }

    Ok(format!("sha256:{}", hex::encode(file_hasher.finalize())))
}

/// Packs regular files into a standards-compliant POSIX `tar` (USTAR/PAX) + `gzip` stream
/// in O(64 KiB) RAM, computing OCI `sha256:<64hex>` digests for each file and the compressed stream.
pub fn pack_tar_gz<W: Write>(
    entries: &[TarInputEntry],
    writer: W,
    options: TarPackOptions,
) -> Result<PackedTarGz, CryptoError> {
    if entries.is_empty() {
        return Err(CryptoError::InvalidTransfer(
            "expected at least one file to pack".into(),
        ));
    }
    if entries.len() > options.max_files {
        return Err(CryptoError::ArchiveLimitExceeded(format!(
            "too many files ({}); limit is {}",
            entries.len(),
            options.max_files
        )));
    }

    let hw = HashingWriter::new(writer);
    let mut gz = GzEncoder::new(hw, Compression::default());
    let mut seen_lower = HashSet::new();
    let mut raw_bytes = 0u64;
    let mut meta_entries = Vec::with_capacity(entries.len());

    for entry in entries {
        let clean_path = validate_tar_archive_path(&entry.archive_path, false)?;
        if !seen_lower.insert(clean_path.to_ascii_lowercase()) {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "duplicate archive path '{clean_path}'"
            )));
        }
        // Use symlink_metadata (lstat) so symlinks are NEVER followed!
        let meta = fs::symlink_metadata(&entry.source_path)?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "source '{}' is not a regular file (symlinks/devices/dirs rejected)",
                entry.source_path.display()
            )));
        }
        let size = meta.len();
        raw_bytes = raw_bytes
            .checked_add(size)
            .ok_or_else(|| CryptoError::ArchiveLimitExceeded("raw byte count overflow".into()))?;
        if raw_bytes > options.max_raw_bytes {
            return Err(CryptoError::ArchiveLimitExceeded(format!(
                "archive raw bytes exceed limit of {}",
                options.max_raw_bytes
            )));
        }

        let file = File::open(&entry.source_path)?;
        let digest = write_tar_entry_stream(&mut gz, &clean_path, size, file)?;
        meta_entries.push(TarFileEntryMeta {
            path: clean_path,
            size,
            digest,
        });
    }

    // Two 512-byte zero EOF blocks per POSIX tar
    gz.write_all(&[0u8; TAR_BLOCK_SIZE * 2])?;
    let hw = gz.finish()?;
    let (mut inner, digest, compressed_bytes) = hw.finish();
    inner.flush()?;

    Ok(PackedTarGz {
        digest,
        compressed_bytes,
        raw_bytes,
        entries: meta_entries,
    })
}

/// Packs in-memory `(archive_path, bytes)` slices into a POSIX `tar` (USTAR/PAX) + `gzip` stream.
pub fn pack_tar_gz_bytes<W: Write>(
    entries: &[(&str, &[u8])],
    writer: W,
    options: TarPackOptions,
) -> Result<PackedTarGz, CryptoError> {
    if entries.is_empty() {
        return Err(CryptoError::InvalidTransfer(
            "expected at least one file to pack".into(),
        ));
    }
    if entries.len() > options.max_files {
        return Err(CryptoError::ArchiveLimitExceeded(format!(
            "too many files ({}); limit is {}",
            entries.len(),
            options.max_files
        )));
    }

    let hw = HashingWriter::new(writer);
    let mut gz = GzEncoder::new(hw, Compression::default());
    let mut seen_lower = HashSet::new();
    let mut raw_bytes = 0u64;
    let mut meta_entries = Vec::with_capacity(entries.len());

    for &(path, data) in entries {
        let clean_path = validate_tar_archive_path(path, false)?;
        if !seen_lower.insert(clean_path.to_ascii_lowercase()) {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "duplicate archive path '{clean_path}'"
            )));
        }
        let size = data.len() as u64;
        raw_bytes = raw_bytes
            .checked_add(size)
            .ok_or_else(|| CryptoError::ArchiveLimitExceeded("raw byte count overflow".into()))?;
        if raw_bytes > options.max_raw_bytes {
            return Err(CryptoError::ArchiveLimitExceeded(format!(
                "archive raw bytes exceed limit of {}",
                options.max_raw_bytes
            )));
        }

        let digest = write_tar_entry_stream(&mut gz, &clean_path, size, data)?;
        meta_entries.push(TarFileEntryMeta {
            path: clean_path,
            size,
            digest,
        });
    }

    gz.write_all(&[0u8; TAR_BLOCK_SIZE * 2])?;
    let hw = gz.finish()?;
    let (mut inner, digest, compressed_bytes) = hw.finish();
    inner.flush()?;

    Ok(PackedTarGz {
        digest,
        compressed_bytes,
        raw_bytes,
        entries: meta_entries,
    })
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish_digest(self) -> String {
        format!("sha256:{}", hex::encode(self.hasher.finalize()))
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Reader wrapper that strictly aborts mid-stream if decompressed output exceeds `limit`
/// (defeats gzip decompression bombs in O(1) RAM before hitting disk!).
struct BombGuardedReader<R> {
    inner: R,
    remaining: u64,
    tripped: bool,
}

impl<R: Read> BombGuardedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
            tripped: false,
        }
    }
}

impl<R: Read> Read for BombGuardedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.tripped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompression bomb limit exceeded",
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        // Read up to remaining + 1 so we detect exceeding the limit immediately.
        let cap = if self.remaining == u64::MAX {
            buf.len()
        } else {
            ((self.remaining + 1) as usize).min(buf.len())
        };
        let n = self.inner.read(&mut buf[..cap])?;
        if (n as u64) > self.remaining {
            self.tripped = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompression bomb limit exceeded",
            ));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn read_exact_or_bomb<R: Read>(
    reader: &mut BombGuardedReader<R>,
    buf: &mut [u8],
) -> Result<bool, CryptoError> {
    let mut offset = 0;
    while offset < buf.len() {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                if offset == 0 {
                    return Ok(false);
                }
                return Err(CryptoError::InvalidTransfer(
                    "unexpected EOF inside tar stream".into(),
                ));
            }
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                if reader.tripped {
                    return Err(CryptoError::ArchiveLimitExceeded(
                        "decompression bomb limit exceeded".into(),
                    ));
                }
                return Err(CryptoError::Io(e));
            }
        }
    }
    Ok(true)
}

fn verify_tar_checksum(block: &[u8; TAR_BLOCK_SIZE]) -> Result<(), CryptoError> {
    let stored = parse_tar_octal(&block[148..156])?;
    let mut sum = 0u64;
    for (i, &b) in block.iter().enumerate() {
        if (148..156).contains(&i) {
            sum += b' ' as u64;
        } else {
            sum += b as u64;
        }
    }
    if sum != stored {
        return Err(CryptoError::InvalidTransfer(format!(
            "tar header checksum mismatch (stored={stored}, computed={sum})"
        )));
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8]) -> Result<u64, CryptoError> {
    // Support standard ASCII octal (and reject GNU base-256 negative values).
    if field.first() == Some(&0x80) {
        let mut val = 0u64;
        for &b in &field[1..] {
            val = val
                .checked_shl(8)
                .ok_or_else(|| CryptoError::InvalidTransfer("tar size overflow".into()))?
                | (b as u64);
        }
        return Ok(val);
    }
    let trimmed = field
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .collect::<Vec<u8>>();
    let s = std::str::from_utf8(&trimmed)
        .map_err(|_| CryptoError::InvalidTransfer("non-UTF8 tar octal field".into()))?
        .trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8)
        .map_err(|_| CryptoError::InvalidTransfer(format!("invalid tar octal field '{s}'")))
}

fn parse_cstr(field: &[u8]) -> Result<&str, CryptoError> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end])
        .map_err(|_| CryptoError::UnsafeArchiveEntry("non-UTF8 tar header string".into()))
}

struct PaxOverrides {
    path: Option<String>,
    size: Option<u64>,
}

fn parse_pax_records(data: &[u8]) -> Result<PaxOverrides, CryptoError> {
    let mut pos = 0usize;
    let mut overrides = PaxOverrides {
        path: None,
        size: None,
    };
    while pos < data.len() {
        let space = data[pos..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| CryptoError::InvalidTransfer("malformed PAX record (missing space)".into()))?;
        let len_str = std::str::from_utf8(&data[pos..pos + space])
            .map_err(|_| CryptoError::InvalidTransfer("malformed PAX length".into()))?;
        let rec_len: usize = len_str
            .parse()
            .map_err(|_| CryptoError::InvalidTransfer("invalid PAX record length".into()))?;
        if rec_len <= space + 1 || pos + rec_len > data.len() {
            return Err(CryptoError::InvalidTransfer(
                "PAX record length out of bounds".into(),
            ));
        }
        let record = &data[pos + space + 1..pos + rec_len];
        if !record.ends_with(b"\n") {
            return Err(CryptoError::InvalidTransfer(
                "PAX record missing trailing newline".into(),
            ));
        }
        let body = std::str::from_utf8(&record[..record.len() - 1])
            .map_err(|_| CryptoError::UnsafeArchiveEntry("non-UTF8 PAX record".into()))?;
        if let Some((k, v)) = body.split_once('=') {
            match k {
                "path" => overrides.path = Some(v.to_string()),
                "linkpath" => {
                    return Err(CryptoError::UnsafeArchiveEntry(
                        "PAX linkpath rejected (links disallowed)".into(),
                    ));
                }
                "size" => {
                    let sz: u64 = v
                        .parse()
                        .map_err(|_| CryptoError::InvalidTransfer("invalid PAX size".into()))?;
                    overrides.size = Some(sz);
                }
                _ => {}
            }
        }
        pos += rec_len;
    }
    Ok(overrides)
}

#[cfg(unix)]
fn set_mode_strict(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode_strict(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// Fail-closed streaming POSIX `tar` (USTAR/PAX) + `gzip` unpacker.
///
/// On ANY validation, bomb, permission, guard, or I/O error, removes `dest_dir` completely so
/// zero partial or blocked files ever remain on disk.
pub fn unpack_tar_gz<R: Read>(
    reader: R,
    dest_dir: &Path,
    options: &TarUnpackOptions<'_>,
) -> Result<UnpackedTarGz, CryptoError> {
    let result = unpack_tar_gz_inner(reader, dest_dir, options);
    if result.is_err() {
        let _ = fs::remove_dir_all(dest_dir);
    }
    result
}

fn unpack_tar_gz_inner<R: Read>(
    reader: R,
    dest_dir: &Path,
    options: &TarUnpackOptions<'_>,
) -> Result<UnpackedTarGz, CryptoError> {
    fs::create_dir_all(dest_dir)?;
    set_mode_strict(dest_dir, 0o700)?;
    let abs_dest = fs::canonicalize(dest_dir)?;

    // Cap total decompressed tar stream bytes (headers + padding + PAX + file payloads)
    // to stop gzip decompression bombs mid-stream before touching disk or RAM.
    let header_overhead = (options.max_files as u64)
        .saturating_mul(8192)
        .saturating_add(16 * 1024);
    let stream_limit = options.max_raw_bytes.saturating_add(header_overhead);

    let hashing_reader = HashingReader::new(reader);
    let gz = GzDecoder::new(hashing_reader);
    let mut stream = BombGuardedReader::new(gz, stream_limit);

    let mut block = [0u8; TAR_BLOCK_SIZE];
    let mut pending_pax: Option<PaxOverrides> = None;
    let mut seen_lower = HashSet::new();
    let mut files = Vec::new();
    let mut total_raw_bytes = 0u64;
    let mut copy_buf = [0u8; 64 * 1024];

    loop {
        if !read_exact_or_bomb(&mut stream, &mut block)? {
            if files.is_empty() {
                return Err(CryptoError::InvalidTransfer(
                    "empty or truncated tar archive".into(),
                ));
            }
            break;
        }
        if block.iter().all(|&b| b == 0) {
            // Consume optional second zero EOF block (and guard against bomb trailing garbage)
            if read_exact_or_bomb(&mut stream, &mut block)? && !block.iter().all(|&b| b == 0) {
                return Err(CryptoError::InvalidTransfer(
                    "unexpected non-zero block after tar EOF marker".into(),
                ));
            }
            break;
        }

        verify_tar_checksum(&block)?;
        let typeflag = block[156];
        let header_size = parse_tar_octal(&block[124..136])?;

        // Handle POSIX PAX extended header ('x')
        if typeflag == b'x' {
            if header_size as usize > MAX_PAX_HEADER_BYTES {
                return Err(CryptoError::ArchiveLimitExceeded(
                    "PAX extended header exceeds limit".into(),
                ));
            }
            let mut pax_buf = vec![0u8; header_size as usize];
            if !pax_buf.is_empty() && !read_exact_or_bomb(&mut stream, &mut pax_buf)? {
                return Err(CryptoError::InvalidTransfer("truncated PAX header".into()));
            }
            let rem = (header_size as usize) % TAR_BLOCK_SIZE;
            if rem != 0 {
                let mut pad = [0u8; TAR_BLOCK_SIZE];
                if !read_exact_or_bomb(&mut stream, &mut pad[..TAR_BLOCK_SIZE - rem])? {
                    return Err(CryptoError::InvalidTransfer("truncated PAX padding".into()));
                }
            }
            pending_pax = Some(parse_pax_records(&pax_buf)?);
            continue;
        }

        // Fail closed on symlinks ('2'), hardlinks ('1'), char ('3'), block ('4'), FIFO ('6'),
        // global PAX ('g'), or any non-regular / non-dir typeflag.
        let is_dir = match typeflag {
            b'0' | 0 => false,
            b'5' => true,
            b'1' => {
                return Err(CryptoError::UnsafeArchiveEntry(
                    "hardlink entry rejected".into(),
                ));
            }
            b'2' => {
                return Err(CryptoError::UnsafeArchiveEntry(
                    "symlink entry rejected".into(),
                ));
            }
            b'3' | b'4' => {
                return Err(CryptoError::UnsafeArchiveEntry(
                    "device node entry rejected".into(),
                ));
            }
            b'6' => {
                return Err(CryptoError::UnsafeArchiveEntry(
                    "FIFO entry rejected".into(),
                ));
            }
            other => {
                return Err(CryptoError::UnsafeArchiveEntry(format!(
                    "unsupported tar entry typeflag 0x{other:02x}"
                )));
            }
        };

        // Ensure linkname field is empty even on regular entries.
        let linkname = parse_cstr(&block[157..257])?;
        if !linkname.is_empty() {
            return Err(CryptoError::UnsafeArchiveEntry(
                "non-empty linkname rejected".into(),
            ));
        }

        let pax = pending_pax.take();
        let entry_size = pax.as_ref().and_then(|p| p.size).unwrap_or(header_size);
        let raw_path = if let Some(p) = pax.and_then(|p| p.path) {
            p
        } else {
            let name = parse_cstr(&block[0..100])?;
            let prefix = parse_cstr(&block[345..500])?;
            if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}/{name}")
            }
        };

        if is_dir {
            if entry_size != 0 {
                return Err(CryptoError::UnsafeArchiveEntry(
                    "directory entry with non-zero size rejected".into(),
                ));
            }
            let clean_dir = validate_tar_archive_path(&raw_path, true)?;
            let dir_path = abs_dest.join(&clean_dir);
            if !dir_path.starts_with(&abs_dest) {
                return Err(CryptoError::UnsafeArchiveEntry(format!(
                    "directory path escape: '{clean_dir}'"
                )));
            }
            create_private_dirs(&abs_dest, &clean_dir)?;
            continue;
        }

        // Regular file validation
        let clean_path = validate_tar_archive_path(&raw_path, false)?;
        if !seen_lower.insert(clean_path.to_ascii_lowercase()) {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "duplicate file path in archive: '{clean_path}'"
            )));
        }
        if files.len() >= options.max_files {
            return Err(CryptoError::ArchiveLimitExceeded(format!(
                "archive exceeds max_files limit of {}",
                options.max_files
            )));
        }

        total_raw_bytes = total_raw_bytes
            .checked_add(entry_size)
            .ok_or_else(|| CryptoError::ArchiveLimitExceeded("raw byte overflow".into()))?;
        if total_raw_bytes > options.max_raw_bytes {
            return Err(CryptoError::ArchiveLimitExceeded(format!(
                "archive uncompressed size exceeds limit of {} bytes",
                options.max_raw_bytes
            )));
        }

        // Stage 1 attachment guard BEFORE creating file on disk!
        if let Some(guard) = options.attachment_guard {
            if let Err(reason) = guard(&clean_path) {
                return Err(CryptoError::AttachmentBlocked(reason));
            }
        }

        // Create parent subdirectories with strict 0o700 permissions
        if let Some(parent_rel) = Path::new(&clean_path).parent() {
            if let Some(p_str) = parent_rel.to_str() {
                if !p_str.is_empty() {
                    create_private_dirs(&abs_dest, p_str)?;
                }
            }
        }

        let target_path = abs_dest.join(&clean_path);
        if !target_path.starts_with(&abs_dest) {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "file path escape: '{clean_path}'"
            )));
        }

        let mut out_file = open_private_new_file(&target_path)?;
        let mut file_hasher = Sha256::new();
        let mut remaining = entry_size;
        while remaining > 0 {
            let to_read = (remaining as usize).min(copy_buf.len());
            if !read_exact_or_bomb(&mut stream, &mut copy_buf[..to_read])? {
                return Err(CryptoError::InvalidTransfer(format!(
                    "truncated file data for '{clean_path}'"
                )));
            }
            file_hasher.update(&copy_buf[..to_read]);
            out_file.write_all(&copy_buf[..to_read])?;
            remaining -= to_read as u64;
        }
        out_file.flush()?;
        drop(out_file);
        set_mode_strict(&target_path, 0o600)?;

        // Consume trailing 512-byte padding
        let rem = (entry_size as usize) % TAR_BLOCK_SIZE;
        if rem != 0 {
            let mut pad = [0u8; TAR_BLOCK_SIZE];
            if !read_exact_or_bomb(&mut stream, &mut pad[..TAR_BLOCK_SIZE - rem])? {
                return Err(CryptoError::InvalidTransfer("truncated tar block padding".into()));
            }
        }

        files.push(UnpackedTarFile {
            archive_path: clean_path,
            disk_path: target_path,
            size: entry_size,
            digest: format!("sha256:{}", hex::encode(file_hasher.finalize())),
        });
    }

    if files.is_empty() {
        return Err(CryptoError::InvalidTransfer(
            "archive contains zero regular files".into(),
        ));
    }

    // Drain any remaining gzip trailer bytes (so CRC32 + ISIZE are verified and hashing_reader hashes full gzip stream)
    let mut drain = [0u8; 256];
    loop {
        match stream.read(&mut drain) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(_) if stream.tripped => {
                return Err(CryptoError::ArchiveLimitExceeded(
                    "decompression bomb limit exceeded in gzip trailer".into(),
                ));
            }
            Err(e) => return Err(CryptoError::Io(e)),
        }
    }

    let compressed_digest = stream.inner.into_inner().finish_digest();

    Ok(UnpackedTarGz {
        dest_dir: abs_dest,
        compressed_digest,
        total_raw_bytes,
        files,
    })
}

fn create_private_dirs(root: &Path, rel_dir: &str) -> Result<(), CryptoError> {
    let mut cur = root.to_path_buf();
    for seg in rel_dir.split('/') {
        if seg.is_empty() {
            continue;
        }
        cur.push(seg);
        if cur.exists() {
            let meta = fs::symlink_metadata(&cur)?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(CryptoError::UnsafeArchiveEntry(format!(
                    "path component '{}' is not a real directory",
                    cur.display()
                )));
            }
        } else {
            fs::create_dir(&cur)?;
        }
        set_mode_strict(&cur, 0o700)?;
    }
    Ok(())
}

fn open_private_new_file(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NodeIdentityKeys;
    use tempfile::TempDir;

    #[test]
    fn streaming_chunked_aead_multi_recipient_and_adversarial_mutations() {
        let sender = NodeIdentityKeys::generate().unwrap();
        let alice = NodeIdentityKeys::generate().unwrap();
        let bob = NodeIdentityKeys::generate().unwrap();
        let mallory = NodeIdentityKeys::generate().unwrap();

        // 2.5 chunks (160 KiB) so we exercise multiple non-final chunks + final partial chunk
        let mut plaintext = vec![0u8; TRANSFER_CHUNK_SIZE * 2 + 12_345];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = ((i * 31 + 17) & 0xff) as u8;
        }

        let params = StreamEncryptParams {
            id: "tr-001",
            from: "sender@dev",
            media_type: "application/vnd.hyphae.tar+gzip",
            created_at: "2026-11-24T12:00:00Z",
            expires_at: "2026-11-25T12:00:00Z",
        };

        let alice_pk = alice.encryption.public_key();
        let bob_pk = bob.encryption.public_key();
        let mut ciphertext = Vec::new();
        let signed = encrypt_stream_v2(
            &plaintext[..],
            &mut ciphertext,
            &params,
            &sender.signing,
            &[("alice@macbook", &alice_pk), ("bob@laptop", &bob_pk)],
        )
        .unwrap();

        // Both Alice and Bob decrypt identically
        let mut out_alice = Vec::new();
        let hdr_a = decrypt_stream_v2(
            &signed,
            &ciphertext[..],
            &mut out_alice,
            &sender.signing.public_key(),
            "alice@macbook",
            &alice.encryption,
        )
        .unwrap();
        assert_eq!(out_alice, plaintext);
        assert_eq!(hdr_a.chunk_count, 3);

        let mut out_bob = Vec::new();
        decrypt_stream_v2(
            &signed,
            &ciphertext[..],
            &mut out_bob,
            &sender.signing.public_key(),
            "bob@laptop",
            &bob.encryption,
        )
        .unwrap();
        assert_eq!(out_bob, plaintext);

        // Mallory cannot decrypt
        let mut out_m = Vec::new();
        assert!(decrypt_stream_v2(
            &signed,
            &ciphertext[..],
            &mut out_m,
            &sender.signing.public_key(),
            "mallory@evil",
            &mallory.encryption,
        )
        .is_err());

        // 1-bit flip in ciphertext fails
        let mut flipped = ciphertext.clone();
        flipped[100] ^= 0x01;
        assert!(decrypt_stream_v2(
            &signed,
            &flipped[..],
            &mut Vec::new(),
            &sender.signing.public_key(),
            "alice@macbook",
            &alice.encryption,
        )
        .is_err());

        // Truncated stream (drop final chunk) fails
        let chunk0_and_1_end = 4 + 2 * (4 + TRANSFER_CHUNK_SIZE + GCM_TAG_LEN);
        assert!(decrypt_stream_v2(
            &signed,
            &ciphertext[..chunk0_and_1_end],
            &mut Vec::new(),
            &sender.signing.public_key(),
            "alice@macbook",
            &alice.encryption,
        )
        .is_err());

        // Extended stream (trailing byte after final chunk) fails
        let mut extended = ciphertext.clone();
        extended.push(0x00);
        assert!(decrypt_stream_v2(
            &signed,
            &extended[..],
            &mut Vec::new(),
            &sender.signing.public_key(),
            "alice@macbook",
            &alice.encryption,
        )
        .is_err());

        // Reordered chunks (swap chunk 0 and chunk 1) fails
        let c_len = 4 + TRANSFER_CHUNK_SIZE + GCM_TAG_LEN;
        let mut reordered = ciphertext.clone();
        let c0 = ciphertext[4..4 + c_len].to_vec();
        let c1 = ciphertext[4 + c_len..4 + 2 * c_len].to_vec();
        reordered[4..4 + c_len].copy_from_slice(&c1);
        reordered[4 + c_len..4 + 2 * c_len].copy_from_slice(&c0);
        assert!(decrypt_stream_v2(
            &signed,
            &reordered[..],
            &mut Vec::new(),
            &sender.signing.public_key(),
            "alice@macbook",
            &alice.encryption,
        )
        .is_err());
    }

    #[test]
    fn tar_gz_pack_unpack_pax_long_paths_and_permissions() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("extracted");

        let long_path = format!("deep/nested/{}/report.md", "a".repeat(120));
        let mut archive = Vec::new();
        let packed = pack_tar_gz_bytes(
            &[
                ("notes/hello.txt", b"hello world"),
                (&long_path, b"long path via PAX"),
            ],
            &mut archive,
            TarPackOptions::default(),
        )
        .unwrap();
        assert!(packed.digest.starts_with("sha256:"));
        assert_eq!(packed.entries.len(), 2);

        let unpacked = unpack_tar_gz(
            &archive[..],
            &dest,
            &TarUnpackOptions {
                attachment_guard: Some(&default_stage1_attachment_guard),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(unpacked.compressed_digest, packed.digest);
        assert_eq!(unpacked.files.len(), 2);
        assert_eq!(fs::read(&unpacked.files[0].disk_path).unwrap(), b"hello world");
        assert_eq!(fs::read(&unpacked.files[1].disk_path).unwrap(), b"long path via PAX");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            let file_mode = fs::metadata(&unpacked.files[0].disk_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    fn make_raw_tar_gz(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        for &(name, typeflag, data) in entries {
            let hdr = build_ustar_header(name, data.len() as u64, typeflag, 0o755).unwrap();
            gz.write_all(&hdr).unwrap();
            gz.write_all(data).unwrap();
            let rem = data.len() % TAR_BLOCK_SIZE;
            if rem != 0 {
                gz.write_all(&vec![0u8; TAR_BLOCK_SIZE - rem]).unwrap();
            }
        }
        gz.write_all(&[0u8; TAR_BLOCK_SIZE * 2]).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn tar_unpack_rejects_symlinks_traversal_bombs_and_blocked_attachments_with_cleanup() {
        let tmp = TempDir::new().unwrap();

        // 1. Symlink entry rejected + cleanup
        let symlink_tar = make_raw_tar_gz(&[("ok.txt", b'0', b"ok"), ("evil-link", b'2', b"")]);
        let d1 = tmp.path().join("d1");
        assert!(matches!(
            unpack_tar_gz(&symlink_tar[..], &d1, &TarUnpackOptions::default()),
            Err(CryptoError::UnsafeArchiveEntry(_))
        ));
        assert!(!d1.exists(), "failed unpack must wipe dest_dir");

        // 2. Path traversal `../escape.txt` rejected
        let escape_tar = make_raw_tar_gz(&[("../escape.txt", b'0', b"pwn")]);
        let d2 = tmp.path().join("d2");
        assert!(matches!(
            unpack_tar_gz(&escape_tar[..], &d2, &TarUnpackOptions::default()),
            Err(CryptoError::UnsafeArchiveEntry(_))
        ));
        assert!(!d2.exists());

        // 3. Absolute path `/etc/passwd` rejected
        let abs_tar = make_raw_tar_gz(&[("/etc/passwd", b'0', b"pwn")]);
        let d3 = tmp.path().join("d3");
        assert!(matches!(
            unpack_tar_gz(&abs_tar[..], &d3, &TarUnpackOptions::default()),
            Err(CryptoError::UnsafeArchiveEntry(_))
        ));
        assert!(!d3.exists());

        // 4. Hardlink & FIFO rejected
        let hardlink_tar = make_raw_tar_gz(&[("hl", b'1', b"")]);
        assert!(matches!(
            unpack_tar_gz(&hardlink_tar[..], &tmp.path().join("d4"), &TarUnpackOptions::default()),
            Err(CryptoError::UnsafeArchiveEntry(_))
        ));
        let fifo_tar = make_raw_tar_gz(&[("pipe", b'6', b"")]);
        assert!(matches!(
            unpack_tar_gz(&fifo_tar[..], &tmp.path().join("d5"), &TarUnpackOptions::default()),
            Err(CryptoError::UnsafeArchiveEntry(_))
        ));

        // 5. Gzip decompression bomb: 2 MiB of zeros compresses to ~2 KiB, fails fast with 64 KiB cap!
        let bomb_payload = vec![0u8; 2 * 1024 * 1024];
        let mut bomb_archive = Vec::new();
        pack_tar_gz_bytes(
            &[("zeros.bin", &bomb_payload)],
            &mut bomb_archive,
            TarPackOptions {
                max_files: 10,
                max_raw_bytes: 4 * 1024 * 1024,
            },
        )
        .unwrap();
        assert!(bomb_archive.len() < 8 * 1024, "bomb should be highly compressed");
        let d6 = tmp.path().join("d6");
        assert!(matches!(
            unpack_tar_gz(
                &bomb_archive[..],
                &d6,
                &TarUnpackOptions {
                    max_files: 10,
                    max_raw_bytes: 64 * 1024,
                    attachment_guard: None,
                },
            ),
            Err(CryptoError::ArchiveLimitExceeded(_))
        ));
        assert!(!d6.exists());

        // 6. Stage 1 attachment guard blocks `.sh` and `.git/hooks/pre-commit` with full cleanup!
        for blocked_name in ["install.sh", ".git/hooks/pre-commit", "payload.dmg", "evil.exe"] {
            let mut buf = Vec::new();
            pack_tar_gz_bytes(
                &[("readme.txt", b"hi"), (blocked_name, b"#!/bin/sh")],
                &mut buf,
                TarPackOptions::default(),
            )
            .unwrap();
            let d = tmp.path().join(format!("blocked-{}", blocked_name.replace(['/', '.'], "_")));
            assert!(matches!(
                unpack_tar_gz(
                    &buf[..],
                    &d,
                    &TarUnpackOptions {
                        attachment_guard: Some(&default_stage1_attachment_guard),
                        ..Default::default()
                    },
                ),
                Err(CryptoError::AttachmentBlocked(_))
            ));
            assert!(!d.exists(), "blocked attachment must wipe dest_dir immediately");
        }
    }
}
