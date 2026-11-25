//! Codex CLI (`codex queue`) native wakeup transport.
//!
//! Delivers queued messages directly to an existing Codex CLI thread by spawning
//! `codex queue --thread <thread_id> --message <text>` without shell interpolation.
//!
//! Security & reliability invariants:
//! - Validates `thread_id` and optional `remote` fail-closed before spawning to
//!   prevent CLI flag injection (`--...`), control-character smuggling, or empty args.
//! - Invokes `tokio::process::Command` directly with discrete argv elements (no shell).
//! - Sets `stdin(Stdio::null())`, `stdout(Stdio::null())`, `kill_on_drop(true)`,
//!   and drains `stderr` into a bounded buffer (`MAX_STDERR_BYTES`) under a strict timeout.
//! - Maps outcomes deterministically with v1 parity:
//!   - Missing binary (`NotFound`) -> `PushOutcome::Hold("codex_binary_missing")`
//!   - Exit status `0` -> `PushOutcome::Delivered`
//!   - Timeout -> kills child and returns `PushOutcome::Reject("codex_queue_timeout")`
//!   - Non-zero exit with offline/daemon stderr -> `PushOutcome::Hold("codex_queue_unavailable")`
//!   - Any other failure -> `PushOutcome::Reject("codex_queue_outcome_unknown")`

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use super::{PushMode, PushOutcome, PushTransport, TransportFuture};

/// Default Codex CLI command name.
pub const DEFAULT_CODEX_BIN: &str = "codex";

/// Default timeout for a single `codex queue` invocation (matches v1 25 s).
pub const DEFAULT_CODEX_QUEUE_TIMEOUT: Duration = Duration::from_secs(25);

/// Maximum allowed length (in Unicode scalar values) of `thread_id`.
pub const MAX_THREAD_ID_LEN: usize = 256;

/// Maximum allowed length (in Unicode scalar values) of `remote`.
pub const MAX_REMOTE_LEN: usize = 2048;

/// Maximum bytes retained from subprocess `stderr` for error classification.
/// Remaining bytes are still drained to EOF so the child never deadlocks on a full pipe.
pub const MAX_STDERR_BYTES: usize = 256 * 1024;

/// Failure reason returned when `thread_id` fails validation.
pub const REASON_INVALID_THREAD_ID: &str = "codex_invalid_thread_id";

/// Failure reason returned when `remote` fails validation.
pub const REASON_INVALID_REMOTE: &str = "codex_invalid_remote";

/// Hold reason returned when the configured `codex` binary cannot be found.
pub const REASON_BINARY_MISSING: &str = "codex_binary_missing";

/// Reject reason returned when `codex queue` exceeds its configured timeout.
pub const REASON_QUEUE_TIMEOUT: &str = "codex_queue_timeout";

/// Hold reason returned when `codex queue` reports an offline/unavailable thread or daemon.
pub const REASON_QUEUE_UNAVAILABLE: &str = "codex_queue_unavailable";

/// Reject reason returned for any other non-zero exit or subprocess I/O failure.
pub const REASON_QUEUE_OUTCOME_UNKNOWN: &str = "codex_queue_outcome_unknown";

const UNAVAILABLE_STDERR_KEYWORDS: [&str; 6] = [
    "not found",
    "offline",
    "connect",
    "socket",
    "refused",
    "daemon",
];

fn default_codex_bin() -> String {
    DEFAULT_CODEX_BIN.to_string()
}

/// Configuration targeting a pinned Codex CLI thread for `codex queue` delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodexQueueTarget {
    pub thread_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_home: Option<PathBuf>,
    /// Path or command name of `codex` binary (defaults to `"codex"`).
    #[serde(default = "default_codex_bin")]
    pub bin: String,
    #[serde(default)]
    pub resume: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
}

impl CodexQueueTarget {
    /// Creates a target with default binary (`"codex"`), `resume = false`,
    /// no `codex_home` override, and no `remote`.
    pub fn new(thread_id: impl Into<String>) -> Self {
        Self {
            thread_id: thread_id.into(),
            codex_home: None,
            bin: default_codex_bin(),
            resume: false,
            remote: None,
        }
    }

    /// Sets the `codex` executable path or command name.
    pub fn with_bin(mut self, bin: impl Into<String>) -> Self {
        self.bin = bin.into();
        self
    }

    /// Sets an explicit `CODEX_HOME` directory forwarded to the subprocess environment.
    pub fn with_codex_home(mut self, codex_home: impl Into<PathBuf>) -> Self {
        self.codex_home = Some(codex_home.into());
        self
    }

    /// Sets whether `--resume` is passed to `codex queue`.
    pub fn with_resume(mut self, resume: bool) -> Self {
        self.resume = resume;
        self
    }

    /// Sets the `--remote <url>` argument passed to `codex queue`.
    pub fn with_remote(mut self, remote: impl Into<String>) -> Self {
        self.remote = Some(remote.into());
        self
    }
}

/// Native [`PushTransport`] backed by `codex queue --thread <id> --message <text>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexQueueTransport {
    target: CodexQueueTarget,
    timeout: Duration,
}

impl CodexQueueTransport {
    /// Creates a new transport with [`DEFAULT_CODEX_QUEUE_TIMEOUT`] (25 seconds).
    pub fn new(target: CodexQueueTarget) -> Self {
        Self {
            target,
            timeout: DEFAULT_CODEX_QUEUE_TIMEOUT,
        }
    }

    /// Overrides the per-delivery subprocess timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns the configured target.
    pub fn target(&self) -> &CodexQueueTarget {
        &self.target
    }

    /// Returns the configured per-delivery timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    async fn deliver_inner(&self, text: &str) -> PushOutcome {
        let args = match build_codex_queue_args(&self.target, text) {
            Ok(args) => args,
            Err(outcome) => return outcome,
        };

        if self.target.bin.trim().is_empty() {
            return PushOutcome::hold(REASON_BINARY_MISSING);
        }

        let mut child = {
            let mut attempts = 0u32;
            loop {
                let mut cmd = Command::new(&self.target.bin);
                cmd.args(&args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);

                if let Some(ref codex_home) = self.target.codex_home {
                    if !codex_home.as_os_str().is_empty() {
                        cmd.env("CODEX_HOME", codex_home);
                    }
                }

                match cmd.spawn() {
                    Ok(child) => break child,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        return PushOutcome::hold(REASON_BINARY_MISSING);
                    }
                    Err(err)
                        if err.kind() == io::ErrorKind::ExecutableFileBusy && attempts < 5 =>
                    {
                        attempts += 1;
                        tokio::time::sleep(Duration::from_millis(10 * u64::from(attempts))).await;
                    }
                    Err(_) => {
                        return PushOutcome::reject(REASON_QUEUE_OUTCOME_UNKNOWN);
                    }
                }
            }
        };

        let stderr = child.stderr.take();
        let wait_and_read = async {
            let stderr_fut = async {
                match stderr {
                    Some(mut reader) => read_bounded_drain(&mut reader, MAX_STDERR_BYTES).await,
                    None => Ok(Vec::new()),
                }
            };
            tokio::join!(child.wait(), stderr_fut)
        };

        let (status_res, stderr_res) = match tokio::time::timeout(self.timeout, wait_and_read).await
        {
            Ok(pair) => pair,
            Err(_) => {
                let _ = child.kill().await;
                return PushOutcome::reject(REASON_QUEUE_TIMEOUT);
            }
        };

        match status_res {
            Ok(status) if status.success() => PushOutcome::delivered(),
            Ok(_) => match stderr_res {
                Ok(bytes) => {
                    let stderr_text = String::from_utf8_lossy(&bytes);
                    classify_codex_queue_failure(&stderr_text)
                }
                Err(_) => PushOutcome::reject(REASON_QUEUE_OUTCOME_UNKNOWN),
            },
            Err(_) => PushOutcome::reject(REASON_QUEUE_OUTCOME_UNKNOWN),
        }
    }
}

impl PushTransport for CodexQueueTransport {
    fn kind(&self) -> &'static str {
        "codex_queue"
    }

    fn supports_interrupt(&self) -> bool {
        false
    }

    fn target_metadata(&self) -> Value {
        json!({ "codexThreadId": self.target.thread_id })
    }

    fn deliver<'a>(&'a self, text: &'a str, _mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        Box::pin(self.deliver_inner(text))
    }
}

/// Returns `true` iff `thread_id` is a canonical 36-character hyphenated UUID (`8-4-4-4-12` hex).
pub fn is_valid_codex_uuid(thread_id: &str) -> bool {
    let bytes = thread_id.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Resolves the default Codex home directory (`$CODEX_HOME` if set and non-empty, else `~/.codex`).
pub fn default_codex_home() -> PathBuf {
    if let Ok(env_home) = std::env::var("CODEX_HOME") {
        let trimmed = env_home.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        if !h.trim().is_empty() {
            return PathBuf::from(h).join(".codex");
        }
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        if !h.trim().is_empty() {
            return PathBuf::from(h).join(".codex");
        }
    }
    PathBuf::from(".codex")
}

/// Returns `true` iff the configured `codex` binary exists as a file (if an explicit path) or
/// resolves in the current process `PATH`.
pub fn codex_binary_available(bin: &str) -> bool {
    let trimmed = bin.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return false;
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return is_executable_file(Path::new(trimmed));
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let direct = dir.join(trimmed);
        if is_executable_file(&direct) {
            return true;
        }
        #[cfg(windows)]
        {
            for ext in ["exe", "cmd", "bat"] {
                let with_ext = dir.join(format!("{trimmed}.{ext}"));
                if with_ext.is_file() {
                    return true;
                }
            }
        }
    }
    false
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Safely verifies whether `$CODEX_HOME/sessions/` contains a rollout JSONL file matching
/// `thread_id` (e.g. `sessions/YYYY/MM/DD/rollout-<ts>-<thread_id>.jsonl`).
///
/// Security & safety invariants:
/// - Rejects invalid/traversal/path-separator `thread_id`s fail-closed before touching disk.
/// - Refuses symlinks (`symlink_metadata`) at every directory/file level so symlink escapes or
///   cycles can never traverse outside `codex_home/sessions`.
/// - Strictly bounded traversal depth (`<= 4`) and visited entry cap (`<= 4096`).
pub fn verify_codex_rollout_thread(codex_home: &Path, thread_id: &str) -> bool {
    const MAX_WALK_DEPTH: usize = 4;
    const MAX_WALK_ENTRIES: usize = 4096;

    if !is_safe_rollout_thread_id(thread_id) {
        return false;
    }

    let sessions_dir = codex_home.join("sessions");
    let Ok(root_meta) = std::fs::symlink_metadata(&sessions_dir) else {
        return false;
    };
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return false;
    }

    let tid_lower = thread_id.to_ascii_lowercase();
    let mut stack: Vec<(PathBuf, usize)> = vec![(sessions_dir, 0)];
    let mut visited = 0usize;

    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry_res in entries {
            visited += 1;
            if visited > MAX_WALK_ENTRIES {
                return false;
            }
            let Ok(entry) = entry_res else {
                continue;
            };
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if depth < MAX_WALK_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if filename_matches_codex_rollout(name, &tid_lower) {
                    return true;
                }
            }
        }
    }

    false
}

fn is_safe_rollout_thread_id(thread_id: &str) -> bool {
    if !is_valid_thread_id(thread_id) {
        return false;
    }
    if thread_id.contains('/') || thread_id.contains('\\') || thread_id.contains("..") {
        return false;
    }
    thread_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn filename_matches_codex_rollout(filename: &str, tid_lower: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    if !lower.ends_with(".jsonl") {
        return false;
    }
    let stem = &lower[..lower.len() - ".jsonl".len()];
    if stem == tid_lower {
        return true;
    }
    let mut search_from = 0usize;
    while let Some(rel) = stem[search_from..].find(tid_lower) {
        let start = search_from + rel;
        let end = start + tid_lower.len();
        let left_ok = start == 0 || matches!(stem.as_bytes()[start - 1], b'-' | b'_' | b'.');
        let right_ok =
            end == stem.len() || matches!(stem.as_bytes()[end], b'-' | b'_' | b'.');
        if left_ok && right_ok {
            return true;
        }
        search_from = start + 1;
    }
    false
}

fn is_valid_thread_id(thread_id: &str) -> bool {
    if thread_id.is_empty() || thread_id.trim().is_empty() {
        return false;
    }
    if thread_id.chars().count() > MAX_THREAD_ID_LEN {
        return false;
    }
    if thread_id.starts_with('-') || thread_id.trim_start().starts_with('-') {
        return false;
    }
    if thread_id.chars().any(|c| c == '\0' || c.is_control()) {
        return false;
    }
    true
}

fn is_valid_remote(remote: &str) -> bool {
    if remote.is_empty() || remote.trim().is_empty() {
        return false;
    }
    if remote.chars().count() > MAX_REMOTE_LEN {
        return false;
    }
    if remote.starts_with('-') || remote.trim_start().starts_with('-') {
        return false;
    }
    if remote.chars().any(|c| c == '\0' || c.is_control()) {
        return false;
    }
    true
}

/// Validates `target` and constructs the discrete `codex` argv vector without shell interpolation.
///
/// Fails closed with:
/// - `Err(PushOutcome::reject("codex_invalid_thread_id"))` when `thread_id` is empty,
///   exceeds 256 chars, contains NUL/control characters, or starts with `'-'`.
/// - `Err(PushOutcome::reject("codex_invalid_remote"))` when `remote` is present and empty,
///   contains NUL/control characters, exceeds [`MAX_REMOTE_LEN`], or starts with `'-'`.
pub fn build_codex_queue_args(
    target: &CodexQueueTarget,
    text: &str,
) -> Result<Vec<String>, PushOutcome> {
    if !is_valid_thread_id(&target.thread_id) {
        return Err(PushOutcome::reject(REASON_INVALID_THREAD_ID));
    }

    if let Some(ref remote) = target.remote {
        if !is_valid_remote(remote) {
            return Err(PushOutcome::reject(REASON_INVALID_REMOTE));
        }
    }

    let mut args = Vec::with_capacity(8);
    args.push("queue".to_string());
    args.push("--thread".to_string());
    args.push(target.thread_id.clone());
    args.push("--message".to_string());
    args.push(text.to_string());

    if target.resume {
        args.push("--resume".to_string());
    }

    if let Some(ref remote) = target.remote {
        args.push("--remote".to_string());
        args.push(remote.clone());
    }

    Ok(args)
}

/// Classifies a non-zero `codex queue` exit based on its `stderr` output (exact v1 parity).
///
/// Matches (case-insensitive): `not found`, `offline`, `connect`, `socket`, `refused`, `daemon`
/// -> `PushOutcome::hold("codex_queue_unavailable")`.
/// Any other stderr -> `PushOutcome::reject("codex_queue_outcome_unknown")`.
pub fn classify_codex_queue_failure(stderr: &str) -> PushOutcome {
    let lower = stderr.to_ascii_lowercase();
    if UNAVAILABLE_STDERR_KEYWORDS
        .iter()
        .any(|kw| lower.contains(kw))
    {
        PushOutcome::hold(REASON_QUEUE_UNAVAILABLE)
    } else {
        PushOutcome::reject(REASON_QUEUE_OUTCOME_UNKNOWN)
    }
}

async fn read_bounded_drain<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        if captured.len() < max_bytes {
            let take = (max_bytes - captured.len()).min(n);
            captured.extend_from_slice(&buf[..take]);
        }
    }
    Ok(captured)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn transport_metadata_and_bounds() {
        assert_send_sync::<CodexQueueTarget>();
        assert_send_sync::<CodexQueueTransport>();

        let target = CodexQueueTarget::new("1c192b8d-aceb-4b35-a5d8-0baf687f1e7e");
        let transport = CodexQueueTransport::new(target.clone());
        assert_eq!(transport.kind(), "codex_queue");
        assert!(!transport.supports_interrupt());
        assert_eq!(transport.timeout(), DEFAULT_CODEX_QUEUE_TIMEOUT);
        assert_eq!(transport.target(), &target);

        let custom = transport.with_timeout(Duration::from_millis(250));
        assert_eq!(custom.timeout(), Duration::from_millis(250));
    }

    #[test]
    fn target_serde_defaults_and_camel_case_roundtrip() {
        let minimal: CodexQueueTarget =
            serde_json::from_str(r#"{"threadId":"thr-123"}"#).expect("valid minimal json");
        assert_eq!(minimal.thread_id, "thr-123");
        assert_eq!(minimal.bin, "codex");
        assert!(!minimal.resume);
        assert_eq!(minimal.codex_home, None);
        assert_eq!(minimal.remote, None);

        let minimal_json = serde_json::to_value(&minimal).expect("serialize minimal");
        assert_eq!(
            minimal_json,
            serde_json::json!({
                "threadId": "thr-123",
                "bin": "codex",
                "resume": false
            })
        );

        let full = CodexQueueTarget::new("thr-456")
            .with_bin("/usr/local/bin/codex")
            .with_codex_home("/var/lib/codex")
            .with_resume(true)
            .with_remote("https://codex.example.com/rpc");
        let raw = serde_json::to_string(&full).expect("serialize full");
        let decoded: CodexQueueTarget = serde_json::from_str(&raw).expect("deserialize full");
        assert_eq!(decoded, full);
    }

    #[test]
    fn build_args_preserves_exact_order_and_special_message_bytes() {
        let base = CodexQueueTarget::new("1c192b8d-aceb-4b35-a5d8-0baf687f1e7e");
        let msg = "line1\n$(evil) `id` 'single' \"double\" --flag";

        assert_eq!(
            build_codex_queue_args(&base, msg).expect("valid args"),
            vec![
                "queue",
                "--thread",
                "1c192b8d-aceb-4b35-a5d8-0baf687f1e7e",
                "--message",
                msg,
            ]
        );

        let full = base
            .clone()
            .with_resume(true)
            .with_remote("https://remote.example.test:8443");
        assert_eq!(
            build_codex_queue_args(&full, msg).expect("valid full args"),
            vec![
                "queue",
                "--thread",
                "1c192b8d-aceb-4b35-a5d8-0baf687f1e7e",
                "--message",
                msg,
                "--resume",
                "--remote",
                "https://remote.example.test:8443",
            ]
        );
    }

    #[test]
    fn build_args_validates_thread_id_boundaries_and_flag_injection() {
        let max_valid = "a".repeat(MAX_THREAD_ID_LEN);
        assert!(build_codex_queue_args(&CodexQueueTarget::new(max_valid), "hi").is_ok());

        let too_long = "a".repeat(MAX_THREAD_ID_LEN + 1);
        let invalid_cases = [
            "",
            "   ",
            "-",
            "-t",
            "--evil",
            " --evil",
            "thr\0id",
            "thr\nid",
            "thr\rid",
            "thr\tid",
            "thr\x1bid",
            "thr\x7fid",
            "thr\u{0085}id",
            too_long.as_str(),
        ];

        for bad in invalid_cases {
            let err = build_codex_queue_args(&CodexQueueTarget::new(bad), "hi")
                .expect_err(&format!("expected thread_id {bad:?} to be rejected"));
            assert_eq!(err, PushOutcome::reject(REASON_INVALID_THREAD_ID));
        }
    }

    #[test]
    fn build_args_validates_remote_flag_injection_and_control_chars() {
        let too_long = format!("https://example.com/{}", "x".repeat(MAX_REMOTE_LEN));
        let invalid_remotes = [
            "",
            "   ",
            "-",
            "--evil",
            " --evil",
            "https://example.com\0",
            "https://example.com\n--evil",
            "https://example.com\r\n",
            too_long.as_str(),
        ];

        for bad in invalid_remotes {
            let target = CodexQueueTarget::new("valid-thread").with_remote(bad);
            let err = build_codex_queue_args(&target, "hi")
                .expect_err(&format!("expected remote {bad:?} to be rejected"));
            assert_eq!(err, PushOutcome::reject(REASON_INVALID_REMOTE));
        }
    }

    #[test]
    fn classify_failure_matches_all_six_keywords_case_insensitively() {
        let unavailable_cases = [
            "thread not found",
            "ERROR: Thread NOT FOUND in store",
            "agent is offline",
            "OFFLINE mode enabled",
            "cannot connect to local rpc",
            "Failed to CONNECT",
            "unix socket closed unexpectedly",
            "SOCKET unavailable",
            "ECONNREFUSED: connection refused",
            "REFUSED by peer",
            "codex daemon not running",
            "DAEMON shutting down",
        ];

        for stderr in unavailable_cases {
            assert_eq!(
                classify_codex_queue_failure(stderr),
                PushOutcome::hold(REASON_QUEUE_UNAVAILABLE),
                "stderr should classify as unavailable: {stderr:?}"
            );
        }

        let unknown_cases = [
            "",
            "   \n",
            "not  found",
            "permission denied",
            "invalid payload schema",
            "rate limit exceeded",
            "internal server error 500",
            "thread is busy",
        ];

        for stderr in unknown_cases {
            assert_eq!(
                classify_codex_queue_failure(stderr),
                PushOutcome::reject(REASON_QUEUE_OUTCOME_UNKNOWN),
                "stderr should classify as unknown: {stderr:?}"
            );
        }
    }
}
