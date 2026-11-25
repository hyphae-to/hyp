//! `hyp exec` — Secret-scoped subprocess execution with streaming stdout/stderr redaction.
//!
//! Injects stored secrets from `hyp-crypto::keystore::SecretStore` strictly into the child
//! process's environment (never argv, never shell interpolation, never plaintext logs) and pipes
//! both `stdout` and `stderr` through concurrent overlap-window `StreamScrubber` threads so
//! secrets—including raw, trimmed, Base64, Base64url, and URL-encoded forms split across
//! arbitrary chunk boundaries—are replaced with `[REDACTED:<secret-name>]` before reaching the
//! caller or agent context.
//!
//! Security invariants:
//! - Fail-closed env var syntax (`^[A-Za-z_][A-Za-z0-9_]*$`, `<= 128` chars), duplicate check,
//!   and case-insensitive dangerous loader/shell/Hyphae env var denylist.
//! - Fail-closed secret-name validation AND reserved Hyphae system-key denylist (blocking node
//!   identity keys, admin/human authority keys, gate policy keys, peer credentials, and pairing
//!   tokens).
//! - Secrets loaded via `SecretStore::get` (`Zeroizing<String>`) are dropped immediately after
//!   spawning the child; scrubber pattern & tail buffers are wiped on drop/drain.
//! - Direct `Command::new(program).args(args)` execution with ZERO shell invocation.

use crate::config_file::{
    load_node_or_legacy_config, open_secret_store, read_json_value, resolve_config_path_for_read,
    resolve_state_dir,
};
use crate::ui::{EXIT_ERROR, EXIT_USAGE};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use clap::Args;
use hyp_crypto::CryptoError;
use hyp_crypto::human::is_reserved_secret_name;
use hyp_crypto::keystore::validate_secret_name;
use hyp_node::engine::http_util::percent_encode;
use serde_json::Value;
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{Ordering, compiler_fence};
use std::thread;

const MAX_ENV_VAR_LEN: usize = 128;
const MIN_RAW_PATTERN_LEN: usize = 4;
const MIN_ENCODED_PATTERN_LEN: usize = 6;
const STREAM_READ_CHUNK_BYTES: usize = 4096;

/// Dangerous loader, interpreter, shell, OS, and Hyphae control env vars that MUST NEVER be
/// overridden by `hyp exec --env` (checked case-insensitively across all platforms).
const DANGEROUS_ENV_EXACT: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_ORIGIN_PATH",
    "LD_PROFILE",
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "IFS",
    "ENV",
    "BASH_ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "SHELL",
    "COMSPEC",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "HOME",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "RUBYOPT",
    "RUBYLIB",
    "PERL5OPT",
    "PERL5LIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "AGENTS_MESH_SOCKET",
];

const DANGEROUS_ENV_PREFIXES: &[&str] = &["DYLD_", "HYPHAE_", "BASH_FUNC_"];

/// Additional Hyphae internal system secret names/prefixes blocked beyond
/// `hyp_crypto::human::is_reserved_secret_name`.
const RESERVED_EXEC_SECRET_EXACT: &[&str] = &[
    "node-sign",
    "node-enc",
    "id-sign",
    "id-enc",
    "node-ed25519",
    "node-x25519",
    "peer-auth",
    "pair-p2p",
    "pair-am2",
    "p2p-offer",
    "staged-join-token",
    "t3-auth-token",
    "t3-session-token",
    "openclaw-hooks-token",
    "hyphae-admin-pubkey",
    "daemon-session-token-key",
    "gate-policy-hmac",
    "gate_policy_hmac",
];

/// Top-level `node.json` sections whose referenced secrets belong to Hyphae infrastructure
/// (bridges, sources, Security Gate, pairing, T3, OpenClaw) and MUST NOT be exposed to `hyp exec`.
const INFRA_CONFIG_SECTIONS: &[&str] = &["plugins", "sources", "gate", "pairing", "t3", "openclaw"];

/// String field keys inside Hyphae infrastructure config sections that carry `SecretStore` names.
const INFRA_SECRET_STRING_KEYS: &[&str] = &[
    "secret",
    "secretName",
    "secret_name",
    "tokenSecret",
    "token_secret",
    "policySigningSecret",
    "policy_signing_secret",
    "api_key_secret",
    "apiKeySecret",
    "webhookSecret",
    "webhook_secret",
    "bearerSecret",
    "bearer_secret",
    "passwordSecret",
    "password_secret",
    "signingSecret",
    "signing_secret",
    "authTokenSecret",
    "auth_token_secret",
    "hooksTokenSecret",
    "hooks_token_secret",
    "adminKeySecret",
    "admin_key_secret",
];

const RESERVED_EXEC_SECRET_PREFIXES: &[&str] = &[
    "node-ed25519",
    "node-x25519",
    "human-admin",
    "human-authority",
    "gate-",
    "peer-auth-",
    "pair-p2p-",
    "pair-am2-",
    "p2p-offer-",
    "staged-join-token-",
    "drop-relay-",
];

/// Run a command with stored secrets injected into env vars and streaming stdout/stderr redaction
#[derive(Debug, Clone, Args)]
pub struct ExecArgs {
    /// Inject a stored secret into an environment variable (`VAR=<secret-name>`, repeatable)
    #[arg(long = "env", short = 'e', value_name = "VAR=SECRET", required = true)]
    pub env: Vec<String>,

    /// Explicit state directory containing node.sqlite and secrets/
    #[arg(long)]
    pub state_dir: Option<PathBuf>,

    /// Explicit node.json path
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Command and arguments to execute (pass `--` before commands or hyphenated flags)
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// Validated `VAR=<secret-name>` binding parsed from `--env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvBinding {
    pub env_var: String,
    pub secret_name: String,
}

/// A single redaction rule mapping exact `needle` bytes to `replacement` bytes.
/// `needle` is deterministically wiped on `Drop`.
#[derive(Debug)]
pub struct RedactionPattern {
    needle: Vec<u8>,
    replacement: Vec<u8>,
}

impl Drop for RedactionPattern {
    fn drop(&mut self) {
        wipe_bytes(&mut self.needle);
    }
}

/// Immutable, longest-first compiled set of secret redaction patterns shared safely across
/// stdout and stderr scrubber threads.
#[derive(Debug)]
pub struct RedactionRuleSet {
    patterns: Vec<RedactionPattern>,
    starts_with_byte: [bool; 256],
    max_pattern_len: usize,
}

impl RedactionRuleSet {
    /// Returns `true` if no active redaction patterns exist.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Maximum pattern byte length (tail window upper bound is `max_pattern_len.saturating_sub(1)`).
    pub fn max_pattern_len(&self) -> usize {
        self.max_pattern_len
    }

    fn has_strict_prefix_extension(&self, tail: &[u8]) -> bool {
        // `patterns` is sorted descending by `needle.len()`, so once `pat.needle.len() <= tail.len()`
        // no remaining pattern can be strictly longer than `tail`.
        for pat in &self.patterns {
            if pat.needle.len() <= tail.len() {
                break;
            }
            if pat.needle.starts_with(tail) {
                return true;
            }
        }
        false
    }

    fn first_match(&self, tail: &[u8]) -> Option<&RedactionPattern> {
        self.patterns
            .iter()
            .find(|pat| pat.needle.len() <= tail.len() && tail.starts_with(&pat.needle))
    }
}

/// Pure, deterministic streaming overlap-window secret scrubber.
///
/// Guarantees bit-exact equivalence with whole-buffer greedy longest-match-first scrubbing across
/// arbitrary chunk sizes (`1..=N` bytes), while keeping the held lookahead tail strictly bounded
/// to at most `max_pattern_len - 1` bytes and flushing non-matching bytes immediately for
/// interactive CLIs.
pub struct StreamScrubber {
    rules: Arc<RedactionRuleSet>,
    pending: Vec<u8>,
}

impl StreamScrubber {
    /// Creates a new streaming scrubber backed by `rules`.
    pub fn new(rules: Arc<RedactionRuleSet>) -> Self {
        let cap = rules.max_pattern_len();
        Self {
            rules,
            pending: Vec::with_capacity(cap),
        }
    }

    /// Feeds the next raw byte slice from a child pipe and writes all safe scrubbed bytes to `out`.
    pub fn process_chunk<W: Write>(&mut self, chunk: &[u8], out: &mut W) -> io::Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        if self.rules.is_empty() {
            return out.write_all(chunk);
        }
        self.pending.extend_from_slice(chunk);
        self.drain_safe(out, false)
    }

    /// Flushes and scrubs any remaining overlap-window tail bytes at EOF, wiping internal memory.
    pub fn finish<W: Write>(mut self, out: &mut W) -> io::Result<()> {
        if !self.pending.is_empty() {
            self.drain_safe(out, true)?;
        }
        wipe_bytes(&mut self.pending);
        self.pending.clear();
        out.flush()
    }

    fn drain_safe<W: Write>(&mut self, out: &mut W, is_eof: bool) -> io::Result<()> {
        let len = self.pending.len();
        let mut pos = 0;

        while pos < len {
            if !self.rules.starts_with_byte[self.pending[pos] as usize] {
                let start = pos;
                pos += 1;
                while pos < len && !self.rules.starts_with_byte[self.pending[pos] as usize] {
                    pos += 1;
                }
                out.write_all(&self.pending[start..pos])?;
                continue;
            }

            let tail = &self.pending[pos..len];
            if !is_eof
                && tail.len() < self.rules.max_pattern_len
                && self.rules.has_strict_prefix_extension(tail)
            {
                break;
            }

            if let Some(pat) = self.rules.first_match(tail) {
                out.write_all(&pat.replacement)?;
                pos += pat.needle.len();
            } else {
                out.write_all(&self.pending[pos..pos + 1])?;
                pos += 1;
            }
        }

        if pos > 0 {
            let rem = len - pos;
            if rem == 0 {
                wipe_bytes(&mut self.pending);
                self.pending.clear();
            } else {
                self.pending.copy_within(pos..len, 0);
                wipe_bytes(&mut self.pending[rem..len]);
                self.pending.truncate(rem);
            }
        }

        Ok(())
    }
}

impl Drop for StreamScrubber {
    fn drop(&mut self) {
        wipe_bytes(&mut self.pending);
    }
}

fn wipe_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, uniquely borrowed mutable reference to an
        // initialized `u8` inside `buf`.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Returns `true` if `name` is a blocked loader, shell, interpreter, OS, or Hyphae env var
/// (checked case-insensitively on all platforms).
pub fn is_dangerous_env_var(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    DANGEROUS_ENV_EXACT.contains(&upper.as_str())
        || DANGEROUS_ENV_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
}

/// Validates an environment variable name fail-closed:
/// - matches `^[A-Za-z_][A-Za-z0-9_]*$` and length `<= 128`
/// - is not in the dangerous loader/shell/Hyphae env var denylist
pub fn validate_env_var_name(name: &str) -> Result<(), (&'static str, String)> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ENV_VAR_LEN {
        return Err((
            "INVALID_ENV_VAR",
            format!("Invalid environment variable name: must be 1..={MAX_ENV_VAR_LEN} ASCII chars"),
        ));
    }
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        || !bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err((
            "INVALID_ENV_VAR",
            "Invalid environment variable name: must match ^[A-Za-z_][A-Za-z0-9_]*$".to_string(),
        ));
    }
    if is_dangerous_env_var(name) {
        return Err((
            "DANGEROUS_ENV_VAR",
            format!(
                "Refusing dangerous environment variable '{name}' (loader, shell, runtime, and HYPHAE_* variables are blocked)"
            ),
        ));
    }
    Ok(())
}

/// Fail-closed case-insensitive denylist blocking Hyphae internal system keys and credentials.
pub fn is_reserved_exec_secret_name(name: &str) -> bool {
    if is_reserved_secret_name(name) {
        return true;
    }
    let lower = name.trim().to_ascii_lowercase();
    RESERVED_EXEC_SECRET_EXACT.contains(&lower.as_str())
        || RESERVED_EXEC_SECRET_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

fn is_safe_display_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Validates a secret name for `hyp exec` fail-closed (blocking reserved Hyphae system keys and
/// invalid/path-traversal names without echoing potentially sensitive raw values).
pub fn validate_exec_secret_name(name: &str) -> Result<(), (&'static str, String)> {
    if is_reserved_exec_secret_name(name) {
        let label = if is_safe_display_token(name) {
            format!("'{name}'")
        } else {
            "requested".to_string()
        };
        return Err((
            "RESERVED_SECRET_NAME",
            format!(
                "Reserved Hyphae system secret {label} is permanently blocked from `hyp exec`"
            ),
        ));
    }
    if validate_secret_name(name).is_err() {
        return Err((
            "INVALID_SECRET_NAME",
            "Invalid secret name: must match /^[a-z0-9][a-z0-9._-]{0,63}$/ (pass a stored secret name, never a raw secret value)"
                .to_string(),
        ));
    }
    Ok(())
}

/// Parses and validates a single `--env VAR=<secret-name>` binding fail-closed.
pub fn parse_env_binding(raw: &str) -> Result<EnvBinding, (&'static str, String)> {
    let Some((var, secret_name)) = raw.split_once('=') else {
        return Err((
            "INVALID_ENV_SPEC",
            "Invalid --env binding: expected VAR=<secret-name>".to_string(),
        ));
    };
    validate_env_var_name(var)?;
    validate_exec_secret_name(secret_name)?;
    Ok(EnvBinding {
        env_var: var.to_string(),
        secret_name: secret_name.to_string(),
    })
}

fn percent_encode_lower(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

fn form_urlencode(input: &str, lowercase_hex: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b == b' ' {
            out.push('+');
        } else if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else if lowercase_hex {
            out.push_str(&format!("%{b:02x}"));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn push_unique_pattern(
    patterns: &mut Vec<RedactionPattern>,
    mut needle: Vec<u8>,
    replacement: &[u8],
) {
    if needle.len() < MIN_RAW_PATTERN_LEN {
        wipe_bytes(&mut needle);
        return;
    }
    if patterns
        .iter()
        .any(|existing| existing.needle.as_slice() == needle.as_slice())
    {
        wipe_bytes(&mut needle);
        return;
    }
    patterns.push(RedactionPattern {
        needle,
        replacement: replacement.to_vec(),
    });
}

fn add_encoded_patterns(patterns: &mut Vec<RedactionPattern>, candidate: &str, replacement: &[u8]) {
    if candidate.len() < MIN_ENCODED_PATTERN_LEN {
        return;
    }
    let raw_bytes = candidate.as_bytes();
    push_unique_pattern(
        patterns,
        STANDARD.encode(raw_bytes).into_bytes(),
        replacement,
    );
    push_unique_pattern(
        patterns,
        STANDARD_NO_PAD.encode(raw_bytes).into_bytes(),
        replacement,
    );
    push_unique_pattern(
        patterns,
        URL_SAFE.encode(raw_bytes).into_bytes(),
        replacement,
    );
    push_unique_pattern(
        patterns,
        URL_SAFE_NO_PAD.encode(raw_bytes).into_bytes(),
        replacement,
    );

    let pct_upper = percent_encode(candidate);
    if pct_upper != candidate {
        push_unique_pattern(patterns, pct_upper.into_bytes(), replacement);
    }
    let pct_lower = percent_encode_lower(candidate);
    if pct_lower != candidate {
        push_unique_pattern(patterns, pct_lower.into_bytes(), replacement);
    }
    if candidate.contains(' ') {
        let form_upper = form_urlencode(candidate, false);
        if form_upper != candidate {
            push_unique_pattern(patterns, form_upper.into_bytes(), replacement);
        }
        let form_lower = form_urlencode(candidate, true);
        if form_lower != candidate {
            push_unique_pattern(patterns, form_lower.into_bytes(), replacement);
        }
    }
}

/// Builds a compiled `RedactionRuleSet` for `(secret_name, secret_value)` pairs.
///
/// Rules:
/// - Empty strings and raw values `< 4` bytes are skipped to avoid false-positive redaction.
/// - For raw values `>= 4` bytes: scrubs raw bytes and trimmed raw bytes (when `>= 4` bytes).
/// - For values `>= 6` bytes: also scrubs standard Base64 (padded + unpadded), Base64url
///   (unpadded + padded), and RFC 3986 / form percent-encoded URL forms (upper + lowercase hex).
/// - Every match is replaced with `[REDACTED:<secret-name>]`.
pub fn build_redaction_patterns(secrets: &[(&str, &str)]) -> RedactionRuleSet {
    let mut patterns: Vec<RedactionPattern> = Vec::new();

    for &(secret_name, raw_value) in secrets {
        if raw_value.is_empty() {
            continue;
        }
        let replacement = format!("[REDACTED:{secret_name}]").into_bytes();

        if raw_value.len() >= MIN_RAW_PATTERN_LEN {
            push_unique_pattern(&mut patterns, raw_value.as_bytes().to_vec(), &replacement);
            add_encoded_patterns(&mut patterns, raw_value, &replacement);
        }

        let trimmed = raw_value.trim();
        if trimmed != raw_value && trimmed.len() >= MIN_RAW_PATTERN_LEN {
            push_unique_pattern(&mut patterns, trimmed.as_bytes().to_vec(), &replacement);
            add_encoded_patterns(&mut patterns, trimmed, &replacement);
        }
    }

    // Stable descending sort by needle length ensures greedy longest-match-first with
    // deterministic registration-order tie breaking.
    patterns.sort_by(|a, b| b.needle.len().cmp(&a.needle.len()));

    let mut starts_with_byte = [false; 256];
    for pat in &patterns {
        if let Some(&first) = pat.needle.first() {
            starts_with_byte[first as usize] = true;
        }
    }
    let max_pattern_len = patterns.first().map(|p| p.needle.len()).unwrap_or(0);

    RedactionRuleSet {
        patterns,
        starts_with_byte,
        max_pattern_len,
    }
}

/// Streams all bytes from `reader` through `StreamScrubber` into `writer`, flushing after each
/// chunk for interactive CLIs and handling `EINTR` / downstream `BrokenPipe` cleanly.
pub fn scrub_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    rules: Arc<RedactionRuleSet>,
) -> io::Result<W> {
    let mut scrubber = StreamScrubber::new(rules);
    let mut buf = [0u8; STREAM_READ_CHUNK_BYTES];
    let result: io::Result<()> = (|| {
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = scrubber.process_chunk(&buf[..n], &mut writer) {
                        if e.kind() == io::ErrorKind::BrokenPipe {
                            return Ok(());
                        }
                        return Err(e);
                    }
                    if let Err(e) = writer.flush() {
                        if e.kind() == io::ErrorKind::BrokenPipe {
                            return Ok(());
                        }
                        return Err(e);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        match scrubber.finish(&mut writer) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => Err(e),
        }
    })();
    wipe_bytes(&mut buf);
    result?;
    Ok(writer)
}

/// Maps a child `ExitStatus` to a process `ExitCode` (`code as u8` or `128 + sig` on Unix signal).
pub fn exit_code_from_status(status: ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        if code == 0 {
            return ExitCode::from(0);
        }
        let byte = (code & 0xff) as u8;
        return ExitCode::from(if byte == 0 { EXIT_ERROR } else { byte });
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            let sig_u8 = u8::try_from(sig).unwrap_or(1);
            return ExitCode::from(128u8.saturating_add(sig_u8));
        }
    }
    ExitCode::from(EXIT_ERROR)
}

fn write_exec_error(
    err: &mut impl Write,
    exit_code: u8,
    code: &str,
    message: &str,
    fix: Option<&str>,
) -> ExitCode {
    let _ = writeln!(err, "FAIL [{code}] {message}");
    if let Some(hint) = fix {
        let _ = writeln!(err, "Fix:  {hint}");
    }
    let _ = err.flush();
    ExitCode::from(exit_code)
}

fn collect_secret_names_recursive(val: &Value, out: &mut HashSet<String>) {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                if INFRA_SECRET_STRING_KEYS.contains(&k.as_str()) {
                    if let Some(s) = v.as_str() {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            out.insert(trimmed.to_ascii_lowercase());
                        }
                    }
                }
                collect_secret_names_recursive(v, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_secret_names_recursive(item, out);
            }
        }
        _ => {}
    }
}

/// Collects every `SecretStore` secret name referenced inside Hyphae infrastructure sections
/// (`plugins[]`, `sources[]`, `gate`, `pairing`, `t3`, `openclaw`) of a `node.json` document,
/// whether via `{ "secret": "<name>" }` objects or string secret-reference keys (`secretName`,
/// `tokenSecret`, `policySigningSecret`, `api_key_secret`, etc.).
pub fn collect_node_config_secret_names(root: &Value) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(obj) = root.as_object() else {
        return out;
    };
    for section in INFRA_CONFIG_SECTIONS {
        if let Some(sec_val) = obj.get(*section) {
            collect_secret_names_recursive(sec_val, &mut out);
        }
    }
    out
}

fn resolve_exec_state_dir(
    state_dir_arg: Option<&Path>,
    config_arg: Option<&Path>,
) -> Result<(PathBuf, bool, Vec<Value>), String> {
    if let Some(cfg_path) = config_arg {
        if !cfg_path.exists() {
            return Err("Specified --config file does not exist".to_string());
        }
        let loaded = load_node_or_legacy_config(cfg_path)
            .map_err(|_| "Specified --config file is not valid Hyphae JSON config".to_string())?;
        let dir = if let Some(sd) = state_dir_arg {
            sd.to_path_buf()
        } else if let Some(sd) = loaded.state_dir {
            sd
        } else {
            resolve_state_dir(None, Some(cfg_path), None)
        };
        let mut docs = vec![loaded.raw];
        let state_cfg = resolve_config_path_for_read(None, Some(&dir), None);
        if state_cfg.exists() && state_cfg != cfg_path {
            if let Ok(extra_doc) = read_json_value(&state_cfg) {
                docs.push(extra_doc);
            }
        }
        return Ok((dir, true, docs));
    }

    if let Some(sd) = state_dir_arg {
        let mut docs = Vec::new();
        let state_cfg = resolve_config_path_for_read(None, Some(sd), None);
        if state_cfg.exists() {
            let doc = read_json_value(&state_cfg).map_err(|_| {
                "node.json in --state-dir is not valid JSON (failing closed on secret isolation)"
                    .to_string()
            })?;
            docs.push(doc);
        }
        return Ok((sd.to_path_buf(), true, docs));
    }

    let default_cfg = resolve_config_path_for_read(None, None, None);
    let mut docs = Vec::new();
    let cfg_for_resolve = if default_cfg.exists() {
        let doc = read_json_value(&default_cfg).map_err(|_| {
            "Default node.json is not valid JSON (failing closed on secret isolation)".to_string()
        })?;
        docs.push(doc);
        Some(default_cfg.as_path())
    } else {
        None
    };
    let dir = resolve_state_dir(None, cfg_for_resolve, None);
    Ok((dir, false, docs))
}

/// Runs `hyp exec` writing scrubbed child stdout/stderr (and fail-closed pre-spawn diagnostics)
/// to the supplied writers.
pub fn run_exec_with_writers<WOut, WErr>(
    args: ExecArgs,
    stdout_writer: WOut,
    mut stderr_writer: WErr,
) -> ExitCode
where
    WOut: Write + Send + 'static,
    WErr: Write + Send + 'static,
{
    if args.env.is_empty() {
        return write_exec_error(
            &mut stderr_writer,
            EXIT_USAGE,
            "MISSING_ENV",
            "At least one `--env VAR=<secret-name>` binding is required",
            Some("Usage: hyp exec --env VAR=<secret-name> -- <cmd> [args...]"),
        );
    }

    if args.command.is_empty() || args.command[0].is_empty() {
        return write_exec_error(
            &mut stderr_writer,
            EXIT_USAGE,
            "MISSING_COMMAND",
            "Missing command to execute after `--`",
            Some("Usage: hyp exec --env VAR=<secret-name> -- <cmd> [args...]"),
        );
    }

    // 1. Fail-closed parse & validation of all `--env` bindings (syntax, denylist, duplicates).
    let mut bindings: Vec<EnvBinding> = Vec::with_capacity(args.env.len());
    let mut seen_vars: HashSet<String> = HashSet::with_capacity(args.env.len());
    for raw in &args.env {
        let binding = match parse_env_binding(raw) {
            Ok(b) => b,
            Err((code, msg)) => {
                let fix = match code {
                    "INVALID_ENV_SPEC" => Some("Use `--env VAR=<secret-name>`."),
                    "DANGEROUS_ENV_VAR" => {
                        Some("Choose an application-specific environment variable name.")
                    }
                    "RESERVED_SECRET_NAME" => Some(
                        "Store application credentials under a user secret name via `hyp secret set <name> --web`.",
                    ),
                    _ => None,
                };
                return write_exec_error(&mut stderr_writer, EXIT_USAGE, code, &msg, fix);
            }
        };
        let canonical_var = binding.env_var.to_ascii_uppercase();
        if !seen_vars.insert(canonical_var) {
            return write_exec_error(
                &mut stderr_writer,
                EXIT_USAGE,
                "DUPLICATE_ENV_VAR",
                &format!(
                    "Duplicate environment variable '{}' in `--env` bindings",
                    binding.env_var
                ),
                Some("Specify each target environment variable at most once."),
            );
        }
        bindings.push(binding);
    }

    // 2. Resolve SecretStore & inspect node.json to isolate Hyphae infrastructure secrets fail-closed.
    let (state_dir, explicit_dir, config_docs) =
        match resolve_exec_state_dir(args.state_dir.as_deref(), args.config.as_deref()) {
            Ok(v) => v,
            Err(msg) => {
                return write_exec_error(&mut stderr_writer, EXIT_ERROR, "CONFIG_ERROR", &msg, None);
            }
        };
    let mut infra_config_secrets: HashSet<String> = HashSet::new();
    for doc in &config_docs {
        infra_config_secrets.extend(collect_node_config_secret_names(doc));
    }
    for binding in &bindings {
        if infra_config_secrets.contains(&binding.secret_name.to_ascii_lowercase()) {
            return write_exec_error(
                &mut stderr_writer,
                EXIT_USAGE,
                "RESERVED_CONFIG_SECRET",
                &format!(
                    "Secret '{}' is referenced by Hyphae infrastructure config in node.json (plugins/sources/gate/pairing/t3/openclaw) and is blocked from `hyp exec`",
                    binding.secret_name
                ),
                Some(
                    "Store application secrets under a distinct name not referenced by Hyphae infrastructure config.",
                ),
            );
        }
    }
    let store = open_secret_store(&state_dir, explicit_dir);

    // 3. Load every requested secret into `Zeroizing<String>` (returned directly by `SecretStore::get`).
    let mut loaded_secrets = Vec::with_capacity(bindings.len());
    for binding in &bindings {
        match store.get(&binding.secret_name) {
            Ok(secret_val) => {
                loaded_secrets.push((binding, secret_val));
            }
            Err(CryptoError::SecretNotFound(_)) => {
                let hint = format!(
                    "Store it via `hyp secret set {} --web` or request a verified drop via `hyp drop create --kind secret --secret-name {}`.",
                    binding.secret_name, binding.secret_name
                );
                return write_exec_error(
                    &mut stderr_writer,
                    EXIT_ERROR,
                    "SECRET_NOT_FOUND",
                    &format!("Secret '{}' was not found in SecretStore", binding.secret_name),
                    Some(&hint),
                );
            }
            Err(_) => {
                return write_exec_error(
                    &mut stderr_writer,
                    EXIT_ERROR,
                    "SECRET_STORE_ERROR",
                    &format!(
                        "Failed to load secret '{}' from SecretStore (check keystore access and 0600/0700 permissions)",
                        binding.secret_name
                    ),
                    Some("Run `hyp secret list` or `hyp doctor` to inspect SecretStore health."),
                );
            }
        }
    }

    // 4. Build streaming redaction patterns from all loaded secrets.
    let pattern_inputs: Vec<(&str, &str)> = loaded_secrets
        .iter()
        .map(|(binding, val)| (binding.secret_name.as_str(), val.as_str()))
        .collect();
    let rules = Arc::new(build_redaction_patterns(&pattern_inputs));
    drop(pattern_inputs);

    // 5. Spawn child directly (NO shell invocation!), inheriting stdin and piping stdout + stderr.
    let program = &args.command[0];
    let cmd_args = &args.command[1..];
    let mut child_cmd = Command::new(program);
    child_cmd
        .args(cmd_args)
        .envs(
            loaded_secrets
                .iter()
                .map(|(binding, val)| (binding.env_var.as_str(), val.as_str())),
        )
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let spawn_res = child_cmd.spawn();

    // Immediately drop/zeroize loaded secret copies and Command env copies after spawn attempt.
    drop(child_cmd);
    drop(loaded_secrets);

    let mut child = match spawn_res {
        Ok(c) => c,
        Err(e) => {
            let (code, detail) = if e.kind() == io::ErrorKind::NotFound {
                (
                    "COMMAND_NOT_FOUND",
                    format!("Failed to execute '{program}': command not found"),
                )
            } else {
                (
                    "EXEC_SPAWN_FAILED",
                    format!("Failed to execute '{program}': {e}"),
                )
            };
            return write_exec_error(&mut stderr_writer, EXIT_ERROR, code, &detail, None);
        }
    };

    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    // 6. Pump stdout & stderr concurrently through two OS threads so pipes never deadlock.
    let out_rules = Arc::clone(&rules);
    let stdout_handle = thread::Builder::new()
        .name("hyp-exec-stdout".to_string())
        .spawn(move || -> io::Result<WOut> {
            match child_stdout {
                Some(pipe) => scrub_stream(pipe, stdout_writer, out_rules),
                None => Ok(stdout_writer),
            }
        });

    let err_rules = Arc::clone(&rules);
    let stderr_handle = thread::Builder::new()
        .name("hyp-exec-stderr".to_string())
        .spawn(move || -> io::Result<WErr> {
            match child_stderr {
                Some(pipe) => scrub_stream(pipe, stderr_writer, err_rules),
                None => Ok(stderr_writer),
            }
        });

    let wait_res = child.wait();

    if let Ok(handle) = stdout_handle {
        let _ = handle.join();
    }
    let returned_stderr = match stderr_handle {
        Ok(handle) => match handle.join() {
            Ok(Ok(w)) => Some(w),
            _ => None,
        },
        Err(_) => None,
    };

    match wait_res {
        Ok(status) => exit_code_from_status(status),
        Err(e) => {
            if let Some(mut err_w) = returned_stderr {
                return write_exec_error(
                    &mut err_w,
                    EXIT_ERROR,
                    "EXEC_WAIT_FAILED",
                    &format!("Failed waiting for child process '{program}': {e}"),
                    None,
                );
            }
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// Entrypoint for `hyp exec` wired from `main.rs`.
pub fn run_exec(args: ExecArgs) -> ExitCode {
    run_exec_with_writers(args, io::stdout(), io::stderr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser, Subcommand};

    #[derive(Parser)]
    #[command(name = "hyp")]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(Subcommand)]
    enum TestCommands {
        Exec(ExecArgs),
    }

    fn scrub_with_chunk_size(input: &[u8], rules: Arc<RedactionRuleSet>, chunk_size: usize) -> Vec<u8> {
        let mut scrubber = StreamScrubber::new(rules);
        let mut out = Vec::new();
        for chunk in input.chunks(chunk_size) {
            scrubber.process_chunk(chunk, &mut out).unwrap();
        }
        scrubber.finish(&mut out).unwrap();
        out
    }

    #[test]
    fn clap_definition_passes_debug_assert_and_parses_flags() {
        TestCli::command().debug_assert();

        let parsed = TestCli::try_parse_from([
            "hyp",
            "exec",
            "--env",
            "API_KEY=openai-key",
            "-e",
            "SECONDARY_TOKEN=stripe-prod",
            "--state-dir",
            "/tmp/hyphae-state",
            "--",
            "curl",
            "-s",
            "--env",
            "-H",
            "Authorization: Bearer x",
        ])
        .expect("valid exec invocation");

        let TestCommands::Exec(args) = parsed.command;
        assert_eq!(args.env, vec!["API_KEY=openai-key", "SECONDARY_TOKEN=stripe-prod"]);
        assert_eq!(args.state_dir, Some(PathBuf::from("/tmp/hyphae-state")));
        assert_eq!(args.config, None);
        assert_eq!(
            args.command,
            vec!["curl", "-s", "--env", "-H", "Authorization: Bearer x"]
        );

        // Missing --env fails closed.
        assert!(TestCli::try_parse_from(["hyp", "exec", "--", "echo", "hi"]).is_err());
        // Missing command fails closed.
        assert!(TestCli::try_parse_from(["hyp", "exec", "--env", "K=my-sec"]).is_err());
        assert!(TestCli::try_parse_from(["hyp", "exec", "--env", "K=my-sec", "--"]).is_err());
    }

    #[test]
    fn dangerous_env_vars_rejected_case_insensitively() {
        let blocked = [
            "PATH",
            "path",
            "Path",
            "LD_PRELOAD",
            "ld_preload",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "dyld_library_path",
            "IFS",
            "ENV",
            "BASH_ENV",
            "ZDOTDIR",
            "PROMPT_COMMAND",
            "NODE_OPTIONS",
            "PYTHONSTARTUP",
            "PYTHONPATH",
            "RUBYOPT",
            "PERL5OPT",
            "HYPHAE_SECRET_BACKEND",
            "HYPHAE_SOCKET",
            "hyphae_state_dir",
            "BASH_FUNC_foo",
        ];
        for var in blocked {
            assert!(is_dangerous_env_var(var), "expected '{var}' to be dangerous");
            let err = validate_env_var_name(var).unwrap_err();
            assert_eq!(err.0, "DANGEROUS_ENV_VAR", "var={var}");
        }

        for allowed in [
            "API_KEY",
            "OPENAI_API_KEY",
            "LD_SDK_KEY",
            "MY_ENV",
            "_PRIVATE_TOKEN_2",
        ] {
            assert!(
                validate_env_var_name(allowed).is_ok(),
                "expected '{allowed}' to be allowed"
            );
        }
    }

    #[test]
    fn reserved_secret_names_rejected_case_insensitively() {
        let reserved = [
            "node-sign-deadbeef1234",
            "node-enc-deadbeef1234",
            "id-sign-abcdef012345",
            "id-enc-abcdef012345",
            "node-ed25519",
            "node-ed25519-key",
            "node-x25519",
            "node-x25519-primary",
            "human-admin",
            "human-admin-1234",
            "human-authority",
            "human-authority-root",
            "admin-ca",
            "admin-ca-root",
            "gate-policy",
            "gate-policy-hmac-key",
            "gate-llm-key",
            "peer-auth-deadbeef1234",
            "pair-p2p-1234",
            "pair-am2-1234",
            "p2p-offer-1234567890abcdef",
            "auth-token",
            "auth-token-prod",
            "staged-join-token",
            "GATE-POLICY-HMAC-KEY",
            "Node-Ed25519-Key",
        ];
        for name in reserved {
            assert!(
                is_reserved_exec_secret_name(name),
                "expected '{name}' to be reserved"
            );
            let err = validate_exec_secret_name(name).unwrap_err();
            assert_eq!(err.0, "RESERVED_SECRET_NAME", "name={name}");
        }

        for allowed in [
            "openai-api-key",
            "stripe_live_key",
            "db.password-2",
            "gateway-api-key",
            "my-node-sign-token",
        ] {
            assert!(
                validate_exec_secret_name(allowed).is_ok(),
                "expected '{allowed}' to be allowed"
            );
        }
    }

    #[test]
    fn scrubber_redacts_raw_trimmed_b64_b64url_and_url_encoded_across_chunk_sizes() {
        let secret = "sk-live/key+with=special&chars";
        let rules = Arc::new(build_redaction_patterns(&[("stripe-key", secret)]));

        let b64_std = STANDARD.encode(secret.as_bytes());
        let b64_url = URL_SAFE_NO_PAD.encode(secret.as_bytes());
        let pct_up = percent_encode(secret);
        let pct_lo = percent_encode_lower(secret);

        let payload = format!(
            "raw={secret}\nb64={b64_std}\nurl64={b64_url}\npctU={pct_up}\npctL={pct_lo}\ntail"
        );
        let expected = "raw=[REDACTED:stripe-key]\nb64=[REDACTED:stripe-key]\nurl64=[REDACTED:stripe-key]\npctU=[REDACTED:stripe-key]\npctL=[REDACTED:stripe-key]\ntail";

        for chunk_size in [1, 2, 3, 7, 16, 64, 4096] {
            let scrubbed = scrub_with_chunk_size(payload.as_bytes(), Arc::clone(&rules), chunk_size);
            assert_eq!(
                String::from_utf8(scrubbed).unwrap(),
                expected,
                "chunk_size={chunk_size}"
            );
        }
    }

    #[test]
    fn scrubber_skips_short_and_empty_secrets_and_respects_length_thresholds() {
        let rules = build_redaction_patterns(&[
            ("empty", ""),
            ("too-short", "abc"),
            ("four-byte", "wxyz"),
            ("five-byte", "12345"),
        ]);
        assert!(!rules.is_empty());

        let rules = Arc::new(rules);
        let b64_four = STANDARD.encode(b"wxyz");
        let b64_five = STANDARD.encode(b"12345");
        let input = format!("abc wxyz 12345 {b64_four} {b64_five}");
        let out = scrub_with_chunk_size(input.as_bytes(), rules, 1);
        // `abc` untouched (< 4); `wxyz` and `12345` scrubbed raw; their base64 untouched (< 6).
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("abc [REDACTED:four-byte] [REDACTED:five-byte] {b64_four} {b64_five}")
        );
    }
}
