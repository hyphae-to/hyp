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

use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use super::{PushMode, PushOutcome, PushTransport, TransportFuture};

/// Default Codex CLI command name.
pub const DEFAULT_CODEX_BIN: &str = "codex";

/// Default timeout for a single `codex queue` invocation (matches v1 25 s).
pub const DEFAULT_CODEX_QUEUE_TIMEOUT: Duration = Duration::from_secs(25);

/// Default short timeout for probing whether `codex queue --help` is supported.
pub const DEFAULT_CODEX_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Cache TTL for `codex queue --help` support probes.
const CODEX_PROBE_CACHE_TTL: Duration = Duration::from_secs(60);

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
                    Err(err) if err.kind() == io::ErrorKind::ExecutableFileBusy && attempts < 5 => {
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

    fn is_nudge_only(&self) -> bool {
        true
    }

    fn target_metadata(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("codexThreadId".to_string(), json!(self.target.thread_id));
        if let Some(ref home) = self.target.codex_home {
            if !home.as_os_str().is_empty() {
                obj.insert(
                    "codexHome".to_string(),
                    json!(home.to_string_lossy().as_ref()),
                );
            }
        }
        if let Some(ref remote) = self.target.remote {
            if !remote.trim().is_empty() {
                obj.insert("codexRemote".to_string(), json!(remote));
            }
        }
        Value::Object(obj)
    }

    fn deliver<'a>(&'a self, text: &'a str, _mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        Box::pin(self.deliver_inner(text))
    }

    fn deliver_nudge<'a>(
        &'a self,
        message_count: usize,
        handle: Option<&'a str>,
        _batch_id: &'a str,
        mode: PushMode,
    ) -> TransportFuture<'a, PushOutcome> {
        let nudge = super::format_push_wake_nudge(message_count, handle, mode);
        Box::pin(async move { self.deliver_inner(&nudge).await })
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
    resolve_codex_binary_path(bin).is_some()
}

fn resolve_codex_binary_path(bin: &str) -> Option<PathBuf> {
    let trimmed = bin.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return None;
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        let p = PathBuf::from(trimmed);
        return is_executable_file(&p).then_some(p);
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let direct = dir.join(trimmed);
        if is_executable_file(&direct) {
            return Some(direct);
        }
        #[cfg(windows)]
        {
            for ext in ["exe", "cmd", "bat"] {
                let with_ext = dir.join(format!("{trimmed}.{ext}"));
                if with_ext.is_file() {
                    return Some(with_ext);
                }
            }
        }
    }
    None
}

fn codex_probe_cache_key(resolved: &Path) -> String {
    let canonical = std::fs::canonicalize(resolved).unwrap_or_else(|_| resolved.to_path_buf());
    let mtime_nanos = std::fs::metadata(&canonical)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}#{mtime_nanos}", canonical.display())
}

/// Uncached probe running `<bin> queue --help` with a bounded timeout to verify whether the
/// installed Codex CLI actually supports the `codex queue` subcommand.
pub async fn codex_queue_supported_uncached(bin: &str, timeout: Duration) -> bool {
    let Some(resolved) = resolve_codex_binary_path(bin) else {
        return false;
    };
    let mut cmd = Command::new(&resolved);
    cmd.args(["queue", "--help"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let probe_fut = async {
        let out_fut = async {
            if let Some(mut r) = stdout {
                let _ = read_bounded_drain(&mut r, 16 * 1024).await;
            }
        };
        let err_fut = async {
            if let Some(mut r) = stderr {
                let _ = read_bounded_drain(&mut r, 16 * 1024).await;
            }
        };
        let (status_res, _, _) = tokio::join!(child.wait(), out_fut, err_fut);
        status_res
    };

    match tokio::time::timeout(timeout, probe_fut).await {
        Ok(Ok(status)) => status.success(),
        Ok(Err(_)) => false,
        Err(_) => {
            let _ = child.kill().await;
            false
        }
    }
}

/// Cached probe verifying `<bin> queue --help` succeeds before auto-attaching
/// [`CodexQueueTransport`]. Plain Codex CLI installations without `codex queue` fail closed
/// (`false`) so `LocalDaemon` never falsely claims push wakeups are live and preserves Stop-hook
/// waiter prompts.
pub async fn codex_queue_supported(bin: &str) -> bool {
    let Some(resolved) = resolve_codex_binary_path(bin) else {
        return false;
    };
    let key = codex_probe_cache_key(&resolved);
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, bool)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let now = Instant::now();
    {
        let guard = cache.lock().expect("codex_queue_supported cache poisoned");
        if let Some(&(checked_at, supported)) = guard.get(&key) {
            if now.saturating_duration_since(checked_at) < CODEX_PROBE_CACHE_TTL {
                return supported;
            }
        }
    }

    let supported = codex_queue_supported_uncached(bin, DEFAULT_CODEX_PROBE_TIMEOUT).await;
    {
        let mut guard = cache.lock().expect("codex_queue_supported cache poisoned");
        if guard.len() >= 64 {
            guard.retain(|_, (ts, _)| now.saturating_duration_since(*ts) < CODEX_PROBE_CACHE_TTL);
        }
        guard.insert(key, (Instant::now(), supported));
    }
    supported
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

/// Classification of a Codex CLI rollout JSONL thread file (`sessions/YYYY/MM/DD/rollout-*.jsonl`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexRolloutKind {
    /// Interactive Codex CLI / TUI / IDE thread (`"source": "cli"` or minimal/legacy metadata)
    /// — eligible for automatic `codex queue --thread` push wakeup attachment.
    Interactive,
    /// Non-interactive one-shot `codex exec` thread (`"source": "exec"` or `"originator": "codex_exec"`)
    /// — MUST NOT auto-attach `codex queue` so queued pushes never collide with exited `codex exec`
    /// runs or `codex exec resume`.
    NonInteractiveExec,
}

/// Safely locates `$CODEX_HOME/sessions/` rollout JSONL file matching `thread_id`
/// (e.g. `sessions/YYYY/MM/DD/rollout-<ts>-<thread_id>.jsonl`) without following symlinks.
fn find_codex_rollout_file(codex_home: &Path, thread_id: &str) -> Option<PathBuf> {
    const MAX_WALK_DEPTH: usize = 4;
    const MAX_WALK_ENTRIES: usize = 4096;
    const MAX_DIR_COLLECT: usize = 16_384;

    if !is_safe_rollout_thread_id(thread_id) {
        return None;
    }

    let sessions_dir = codex_home.join("sessions");
    let root_meta = std::fs::symlink_metadata(&sessions_dir).ok()?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return None;
    }

    let tid_lower = thread_id.to_ascii_lowercase();
    let mut stack: Vec<(PathBuf, usize)> = vec![(sessions_dir, 0)];
    let mut visited = 0usize;

    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut subdirs: Vec<(String, PathBuf)> = Vec::new();
        let mut files: Vec<(String, PathBuf)> = Vec::new();
        for entry_res in entries {
            if subdirs.len() + files.len() >= MAX_DIR_COLLECT {
                break;
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
            let name = entry.file_name().to_string_lossy().into_owned();
            if meta.is_dir() {
                if depth < MAX_WALK_DEPTH {
                    subdirs.push((name, path));
                }
            } else if meta.is_file() {
                files.push((name, path));
            }
        }

        // Check files newest-first (descending lexicographical timestamp order).
        files.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        for (name, path) in files {
            visited += 1;
            if visited > MAX_WALK_ENTRIES {
                return None;
            }
            if filename_matches_codex_rollout(&name, &tid_lower) {
                return Some(path);
            }
        }

        // Sort subdirectories ascending before pushing onto the LIFO stack so the newest
        // `YYYY/MM/DD` directories are popped and scanned first!
        subdirs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (_, path) in subdirs {
            visited += 1;
            if visited > MAX_WALK_ENTRIES {
                return None;
            }
            stack.push((path, depth + 1));
        }
    }

    None
}

/// Inspects a single JSONL header line (typically `{"type":"session_meta","payload":{...}}`)
/// from a Codex rollout file to distinguish interactive CLI sessions (`"source": "cli"`) from
/// non-interactive one-shot `codex exec` runs (`"source": "exec"` / `"originator": "codex_exec"`).
pub fn classify_codex_rollout_header(line: &str) -> CodexRolloutKind {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return CodexRolloutKind::Interactive;
    }
    let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
        return CodexRolloutKind::Interactive;
    };
    let Some(obj) = val.as_object() else {
        return CodexRolloutKind::Interactive;
    };

    // Inspect nested `payload` (real Codex v0.172+ `session_meta` shape) as well as top-level
    // fields (compact/legacy fixtures).
    let payload_obj = obj.get("payload").and_then(Value::as_object);
    for scope in [payload_obj, Some(obj)].into_iter().flatten() {
        if let Some(source_val) = scope.get("source") {
            if let Some(src) = source_val.as_str() {
                if src.trim().eq_ignore_ascii_case("exec") {
                    return CodexRolloutKind::NonInteractiveExec;
                }
            } else if let Some(src_obj) = source_val.as_object() {
                if src_obj
                    .keys()
                    .any(|k| k.trim().eq_ignore_ascii_case("exec"))
                {
                    return CodexRolloutKind::NonInteractiveExec;
                }
            }
        }
        if let Some(orig) = scope.get("originator").and_then(Value::as_str) {
            let norm = orig.trim().to_ascii_lowercase();
            if norm == "codex_exec" || norm.starts_with("codex_exec") {
                return CodexRolloutKind::NonInteractiveExec;
            }
        }
    }

    CodexRolloutKind::Interactive
}

/// Inspects `$CODEX_HOME/sessions/` for a rollout JSONL file matching `thread_id` and classifies
/// whether it belongs to an interactive Codex session or a non-interactive `codex exec` run.
///
/// Reads at most 4 header lines within a bounded 512 KiB window (handling long `base_instructions`
/// payloads safely) and re-checks `symlink_metadata` before opening the file.
pub fn inspect_codex_rollout_thread(
    codex_home: &Path,
    thread_id: &str,
) -> Option<CodexRolloutKind> {
    const MAX_HEADER_BYTES: u64 = 512 * 1024;
    const MAX_HEADER_LINES: usize = 4;

    let path = find_codex_rollout_file(codex_home, thread_id)?;
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return None;
    }

    let Ok(file) = std::fs::File::open(&path) else {
        return None;
    };
    let mut reader = io::BufReader::new(std::io::Read::take(file, MAX_HEADER_BYTES));
    for _ in 0..MAX_HEADER_LINES {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    continue;
                }
                if classify_codex_rollout_header(&line) == CodexRolloutKind::NonInteractiveExec {
                    return Some(CodexRolloutKind::NonInteractiveExec);
                }
                // If this line was explicitly `session_meta` and NOT `exec`, we're done!
                if let Ok(val) = serde_json::from_str::<Value>(line.trim()) {
                    if val.get("type").and_then(Value::as_str) == Some("session_meta") {
                        return Some(CodexRolloutKind::Interactive);
                    }
                }
            }
            Err(_) => break,
        }
    }

    Some(CodexRolloutKind::Interactive)
}

/// Safely verifies whether `$CODEX_HOME/sessions/` contains an interactive rollout JSONL file
/// matching `thread_id` (e.g. `sessions/YYYY/MM/DD/rollout-<ts>-<thread_id>.jsonl`).
///
/// Security & safety invariants:
/// - Rejects invalid/traversal/path-separator `thread_id`s fail-closed before touching disk.
/// - Refuses symlinks (`symlink_metadata`) at every directory/file level so symlink escapes or
///   cycles can never traverse outside `codex_home/sessions`.
/// - Traverses directories and files newest-first (descending `YYYY/MM/DD` & rollout timestamp
///   order) so long-time Codex users with >4,096 historical session files still find recent
///   threads immediately within the bounded visit cap (`<= 4096`).
/// - Refuses non-interactive one-shot `codex exec` rollouts (`"source": "exec"` /
///   `"originator": "codex_exec"`) so `codex queue` never auto-attaches to exited `codex exec`
///   threads or collides with `codex exec resume`.
pub fn verify_codex_rollout_thread(codex_home: &Path, thread_id: &str) -> bool {
    matches!(
        inspect_codex_rollout_thread(codex_home, thread_id),
        Some(CodexRolloutKind::Interactive)
    )
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
        let right_ok = end == stem.len() || matches!(stem.as_bytes()[end], b'-' | b'_' | b'.');
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

    #[test]
    fn verify_rollout_thread_scans_newest_dirs_first_past_4096_old_files() {
        let tmp = tempfile::tempdir().unwrap();
        let old_dir = tmp.path().join("sessions/2024/01/01");
        let new_dir = tmp.path().join("sessions/2026/11/25");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::create_dir_all(&new_dir).unwrap();

        // Populate >4,096 old rollout files in 2024 so an unsorted/oldest-first walk would hit
        // MAX_WALK_ENTRIES before reaching 2026!
        for i in 0..4_120usize {
            let path = old_dir.join(format!("rollout-2024-01-01-{i:06}.jsonl"));
            std::fs::write(path, "{}\n").unwrap();
        }
        let target_uuid = "0196a1b2-c3d4-7e5f-8a9b-202611250001";
        std::fs::write(
            new_dir.join(format!("rollout-2026-11-25T23-59-00-{target_uuid}.jsonl")),
            "{}\n",
        )
        .unwrap();

        assert!(
            verify_codex_rollout_thread(tmp.path(), target_uuid),
            "newest-first traversal must find 2026 rollout thread despite >4,096 old files in 2024"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn codex_queue_supported_probes_subcommand_and_rejects_plain_codex() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let plain_codex = tmp.path().join("plain-codex");
        std::fs::write(
            &plain_codex,
            "#!/bin/sh\necho 'error: unrecognized subcommand queue' >&2\nexit 2\n",
        )
        .unwrap();
        std::fs::set_permissions(&plain_codex, std::fs::Permissions::from_mode(0o755)).unwrap();

        let queue_codex = tmp.path().join("queue-codex");
        std::fs::write(
            &queue_codex,
            "#!/bin/sh\nif [ \"$1\" = \"queue\" ] && [ \"$2\" = \"--help\" ]; then echo 'Usage: codex queue'; exit 0; fi\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&queue_codex, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            !codex_queue_supported(&plain_codex.display().to_string()).await,
            "plain Codex CLI without `codex queue` must return false"
        );
        assert!(
            codex_queue_supported(&queue_codex.display().to_string()).await,
            "Codex CLI supporting `codex queue --help` must return true"
        );
        assert!(
            !codex_queue_supported(&tmp.path().join("nonexistent-codex").display().to_string())
                .await
        );
    }

    #[test]
    fn rollout_verification_distinguishes_interactive_cli_from_non_interactive_exec() {
        let tmp = tempfile::tempdir().unwrap();
        let day_dir = tmp.path().join("sessions/2026/11/26");
        std::fs::create_dir_all(&day_dir).unwrap();

        let cli_uuid = "01a217e1-c5f7-7720-a22b-888b924cc101";
        let exec_uuid = "01a217e1-c5f7-7720-a22b-888b924cc102";
        let exec_orig_only_uuid = "01a217e1-c5f7-7720-a22b-888b924cc103";

        // 1. Real interactive Codex CLI rollout (`"source": "cli"`, `"originator": "codex_cli_rs"`).
        std::fs::write(
            day_dir.join(format!("rollout-2026-11-26T12-00-00-{cli_uuid}.jsonl")),
            format!(
                "{{\"timestamp\":\"2026-11-26T12:00:00Z\",\"ordinal\":0,\"type\":\"session_meta\",\"payload\":{{\"id\":\"{cli_uuid}\",\"originator\":\"codex_cli_rs\",\"cli_version\":\"0.172.0\",\"source\":\"cli\",\"base_instructions\":{{\"text\":\"{}\"}}}}}}\n",
                "x".repeat(16_384)
            ),
        )
        .unwrap();

        // 2. Real non-interactive `codex exec` rollout (`"source": "exec"`, `"originator": "codex_exec"`).
        std::fs::write(
            day_dir.join(format!("rollout-2026-11-26T12-01-00-{exec_uuid}.jsonl")),
            format!(
                "{{\"timestamp\":\"2026-11-26T12:01:00Z\",\"ordinal\":0,\"type\":\"session_meta\",\"payload\":{{\"id\":\"{exec_uuid}\",\"originator\":\"codex_exec\",\"cli_version\":\"0.172.0\",\"source\":\"exec\",\"base_instructions\":{{\"text\":\"{}\"}}}}}}\n",
                "y".repeat(16_384)
            ),
        )
        .unwrap();

        // 3. `originator: "codex_exec"` even without explicit `"source": "exec"`.
        std::fs::write(
            day_dir.join(format!(
                "rollout-2026-11-26T12-02-00-{exec_orig_only_uuid}.jsonl"
            )),
            format!(
                "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{exec_orig_only_uuid}\",\"originator\":\"codex_exec\"}}}}\n"
            ),
        )
        .unwrap();

        assert_eq!(
            inspect_codex_rollout_thread(tmp.path(), cli_uuid),
            Some(CodexRolloutKind::Interactive)
        );
        assert!(verify_codex_rollout_thread(tmp.path(), cli_uuid));

        assert_eq!(
            inspect_codex_rollout_thread(tmp.path(), exec_uuid),
            Some(CodexRolloutKind::NonInteractiveExec)
        );
        assert!(!verify_codex_rollout_thread(tmp.path(), exec_uuid));

        assert_eq!(
            inspect_codex_rollout_thread(tmp.path(), exec_orig_only_uuid),
            Some(CodexRolloutKind::NonInteractiveExec)
        );
        assert!(!verify_codex_rollout_thread(
            tmp.path(),
            exec_orig_only_uuid
        ));
    }
}
