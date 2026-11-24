//! Native Herdr (`hc`) wakeup transport: live terminal identity pinning,
//! bounded subprocess execution, interrupt-then-recheck state machine, and
//! guarded paste-send push delivery.
//!
//! Security & process-safety invariants:
//! - Every delivery re-verifies `address == target.terminal_id`, `state == "live"`,
//!   and every pinned identity field (`created_ms`, `pid`, `app`) so recycled
//!   terminal IDs never deliver to a different program.
//! - Subprocesses are always invoked directly via `tokio::process::Command`
//!   (no shell interpolation), with `Stdio::null()` on stdin, `.kill_on_drop(true)`,
//!   bounded stdout/stderr reads (`256 KiB`), and hard per-command timeouts with
//!   explicit `child.kill().await` cleanup on timeout.
//! - Missing `hc` binary, invalid terminal IDs, malformed JSON, non-live state,
//!   or unexpected interrupt/send outcomes always fail closed.

use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use super::{PushMode, PushOutcome, PushTransport, TransportFuture};

/// Default `hc` binary name resolved via `PATH`.
pub const DEFAULT_HERDR_BIN: &str = "hc";
/// Default timeout for `hc get --json <terminal_id>`.
pub const DEFAULT_GET_TIMEOUT: Duration = Duration::from_secs(5);
/// Default timeout for `hc interrupt --json --timeout 8 <terminal_id>`.
pub const DEFAULT_INTERRUPT_TIMEOUT: Duration = Duration::from_secs(12);
/// Default timeout for `hc send --json ... <terminal_id> <text>`.
pub const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(75);

/// Server-side timeout argument passed to `hc interrupt --json --timeout <secs>`.
const INTERRUPT_CLI_TIMEOUT_SECS: &str = "8";
/// Hard cap on stdout/stderr read per `hc` subprocess invocation (matches v1 `maxBuffer`).
const MAX_HERDR_OUTPUT_BYTES: usize = 256 * 1024;
/// Upper bound on agent status state token length (defends against unbounded/malformed reasons).
const MAX_AGENT_STATE_LEN: usize = 64;

fn default_herdr_bin() -> String {
    DEFAULT_HERDR_BIN.to_string()
}

/// Target identity and binary configuration for a Herdr (`hc`) terminal session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HerdrTarget {
    pub terminal_id: String,
    /// Optional identity pin from `hc get --json <terminalId>` (`created_ms`, `pid`, `app`).
    /// When pinned, every delivery re-verifies all pinned fields so recycled terminal IDs
    /// NEVER deliver to a different program!
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// Path or command name of `hc` binary (defaults to `"hc"`).
    #[serde(default = "default_herdr_bin")]
    pub bin: String,
}

impl HerdrTarget {
    /// Creates an unpinned target for `terminal_id` using the default `"hc"` binary.
    pub fn new(terminal_id: impl Into<String>) -> Self {
        Self {
            terminal_id: terminal_id.into(),
            created_ms: None,
            pid: None,
            app: None,
            bin: default_herdr_bin(),
        }
    }

    /// Overrides the `hc` binary path or command name.
    pub fn with_bin(mut self, bin: impl Into<String>) -> Self {
        self.bin = bin.into();
        self
    }

    /// Returns `true` iff `info` describes a live terminal whose address and all
    /// pinned identity fields (`created_ms`, `pid`, `app`) match this target exactly.
    pub fn matches_live_terminal(&self, info: &HerdrTerminalInfo) -> bool {
        if info.address != self.terminal_id || info.state != "live" {
            return false;
        }
        if self
            .created_ms
            .is_some_and(|expected| info.created_ms != Some(expected))
        {
            return false;
        }
        if self.pid.is_some_and(|expected| info.pid != Some(expected)) {
            return false;
        }
        if self
            .app
            .as_deref()
            .is_some_and(|expected| info.app.as_deref() != Some(expected))
        {
            return false;
        }
        true
    }
}

/// Parsed snapshot returned by `hc get --json <terminal_id>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HerdrTerminalInfo {
    pub address: String,
    pub state: String,
    pub created_ms: Option<i64>,
    pub pid: Option<u64>,
    pub app: Option<String>,
    pub agent_state: String,
}

/// Native Herdr (`hc`) [`PushTransport`] implementation.
#[derive(Debug, Clone)]
pub struct HerdrTransport {
    target: HerdrTarget,
    get_timeout: Duration,
    interrupt_timeout: Duration,
    send_timeout: Duration,
}

impl HerdrTransport {
    /// Constructs a new transport with standard production timeouts
    /// (`get`: 5s, `interrupt`: 12s, `send`: 75s).
    pub fn new(target: HerdrTarget) -> Self {
        Self {
            target,
            get_timeout: DEFAULT_GET_TIMEOUT,
            interrupt_timeout: DEFAULT_INTERRUPT_TIMEOUT,
            send_timeout: DEFAULT_SEND_TIMEOUT,
        }
    }

    /// Customizes per-phase command timeouts (useful for fast deterministic tests).
    pub fn with_timeouts(
        mut self,
        get_timeout: Duration,
        interrupt_timeout: Duration,
        send_timeout: Duration,
    ) -> Self {
        self.get_timeout = get_timeout;
        self.interrupt_timeout = interrupt_timeout;
        self.send_timeout = send_timeout;
        self
    }

    /// Returns the bound [`HerdrTarget`].
    pub fn target(&self) -> &HerdrTarget {
        &self.target
    }

    async fn deliver_with_runner<R: CommandRunner + ?Sized>(
        &self,
        runner: &R,
        text: &str,
        mode: PushMode,
    ) -> PushOutcome {
        if self.target.bin.is_empty() {
            return PushOutcome::hold("herdr_binary_missing");
        }
        if !is_valid_terminal_id(&self.target.terminal_id) {
            return PushOutcome::hold("herdr_target_unavailable");
        }

        // Step 1 & 2: Probe live terminal identity and verify every pinned field.
        let initial_state = match self.fetch_verified_agent_state(runner).await {
            GetStateOutcome::Ready(state) => state,
            GetStateOutcome::MissingBinary => return PushOutcome::hold("herdr_binary_missing"),
            GetStateOutcome::Unavailable => return PushOutcome::hold("herdr_target_unavailable"),
        };

        // Step 3: Gate on initial agent state (never interrupt in Queue mode).
        let (current_state, interrupted) = match initial_state.as_str() {
            "idle" | "done" => (initial_state, false),
            "working" if mode == PushMode::Queue => return PushOutcome::hold("herdr_working"),
            "working" => {
                // Step 4: Interrupt active work and verify stop outcome before re-checking state.
                let interrupt_args = [
                    "interrupt",
                    "--json",
                    "--timeout",
                    INTERRUPT_CLI_TIMEOUT_SECS,
                    self.target.terminal_id.as_str(),
                ];
                let interrupt_out = runner
                    .run(&self.target.bin, &interrupt_args, self.interrupt_timeout)
                    .await;
                let stopped = matches!(
                    interrupt_out,
                    CommandOutcome::Completed {
                        code: Some(0),
                        ref stdout,
                        ..
                    } if parse_herdr_interrupt_stopped(stdout)
                );
                if !stopped {
                    return PushOutcome::reject("herdr_interrupt_outcome_unknown");
                }

                // Re-run `hc get --json <terminal_id>` and verify live identity + ready state.
                match self.fetch_verified_agent_state(runner).await {
                    GetStateOutcome::Ready(state) if state == "idle" || state == "done" => {
                        (state, true)
                    }
                    _ => return PushOutcome::hold_interrupted("herdr_agent_not_ready"),
                }
            }
            other => return PushOutcome::hold(format!("herdr_{other}")),
        };

        // Step 5: Guarded paste & submit.
        // Herdr `send` supports `--if idle`; `"done"` is reported as a distinct ready state.
        let send_out = if current_state == "idle" {
            let args = [
                "send",
                "--json",
                "--if",
                "idle",
                self.target.terminal_id.as_str(),
                text,
            ];
            runner.run(&self.target.bin, &args, self.send_timeout).await
        } else {
            let args = ["send", "--json", self.target.terminal_id.as_str(), text];
            runner.run(&self.target.bin, &args, self.send_timeout).await
        };

        match send_out {
            CommandOutcome::Completed { code: Some(0), .. } => PushOutcome::delivered(),
            CommandOutcome::Completed {
                code: Some(9 | 10), ..
            } => {
                if interrupted {
                    PushOutcome::hold_interrupted("herdr_send_guard_refused")
                } else {
                    PushOutcome::hold("herdr_send_guard_refused")
                }
            }
            _ => PushOutcome::Reject {
                reason: "herdr_send_outcome_unknown".to_string(),
                interrupted,
            },
        }
    }

    async fn fetch_verified_agent_state<R: CommandRunner + ?Sized>(
        &self,
        runner: &R,
    ) -> GetStateOutcome {
        let args = ["get", "--json", self.target.terminal_id.as_str()];
        match runner.run(&self.target.bin, &args, self.get_timeout).await {
            CommandOutcome::MissingBinary => GetStateOutcome::MissingBinary,
            CommandOutcome::Completed {
                code: Some(0),
                stdout,
                ..
            } => match parse_herdr_get_output(&stdout) {
                Some(info) if self.target.matches_live_terminal(&info) => {
                    GetStateOutcome::Ready(info.agent_state)
                }
                _ => GetStateOutcome::Unavailable,
            },
            _ => GetStateOutcome::Unavailable,
        }
    }
}

impl PushTransport for HerdrTransport {
    fn kind(&self) -> &'static str {
        "herdr"
    }

    fn supports_interrupt(&self) -> bool {
        true
    }

    fn deliver<'a>(&'a self, text: &'a str, mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        Box::pin(async move { self.deliver_with_runner(&ProcessRunner, text, mode).await })
    }
}

/// Inspects `HC_TERMINAL_ID` from the current process environment.
///
/// Returns `None` when unset, blank, or not a safe terminal address.
pub fn detect_env_terminal_id() -> Option<String> {
    parse_env_terminal_id(std::env::var("HC_TERMINAL_ID").ok().as_deref())
}

fn parse_env_terminal_id(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if is_valid_terminal_id(trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Validates that a Herdr terminal identifier is non-empty, cannot be interpreted
/// as a CLI flag (does not start with `'-'`), and contains no whitespace or
/// control characters.
pub fn is_valid_terminal_id(terminal_id: &str) -> bool {
    !terminal_id.is_empty()
        && !terminal_id.starts_with('-')
        && !terminal_id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

/// Probes a live Herdr terminal via `hc get --json <terminal_id>` (5s timeout)
/// and returns a pinned [`HerdrTarget`] capturing `created_ms`, `pid`, and `app`.
///
/// Returns `None` if `hc` is missing, times out, returns a non-zero exit code,
/// reports a mismatched `address` or non-`"live"` state, or outputs invalid JSON.
pub async fn probe_herdr_terminal(bin: &str, terminal_id: &str) -> Option<HerdrTarget> {
    probe_herdr_terminal_with_timeout(bin, terminal_id, DEFAULT_GET_TIMEOUT).await
}

/// Same as [`probe_herdr_terminal`] with a caller-specified timeout.
pub async fn probe_herdr_terminal_with_timeout(
    bin: &str,
    terminal_id: &str,
    timeout: Duration,
) -> Option<HerdrTarget> {
    probe_with_runner(&ProcessRunner, bin, terminal_id, timeout).await
}

async fn probe_with_runner<R: CommandRunner + ?Sized>(
    runner: &R,
    bin: &str,
    terminal_id: &str,
    timeout: Duration,
) -> Option<HerdrTarget> {
    if bin.is_empty() || !is_valid_terminal_id(terminal_id) {
        return None;
    }
    let args = ["get", "--json", terminal_id];
    let CommandOutcome::Completed {
        code: Some(0),
        stdout,
        ..
    } = runner.run(bin, &args, timeout).await
    else {
        return None;
    };

    let info = parse_herdr_get_output(&stdout)?;
    if info.address != terminal_id || info.state != "live" {
        return None;
    }
    Some(HerdrTarget {
        terminal_id: info.address,
        created_ms: info.created_ms,
        pid: info.pid,
        app: info.app,
        bin: bin.to_string(),
    })
}

/// Parses `hc get --json <terminal_id>` output, supporting both:
/// - v0.1 nested shape: `{"address":"t3","state":"live","created_ms":...,"pid":...,"status":{"app":"codex","state":"idle"}}`
/// - flat `hc ls --json` shape: `{"address":"t3","state":"live","created_ms":...,"pid":...,"status":"idle","agent":"claude-code"}`
pub fn parse_herdr_get_output(stdout: &str) -> Option<HerdrTerminalInfo> {
    let value: Value = serde_json::from_str(stdout.trim()).ok()?;
    let obj = value.as_object()?;

    let address = obj
        .get("address")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?
        .to_string();
    let state = obj
        .get("state")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?
        .to_string();
    let created_ms = obj.get("created_ms").and_then(Value::as_i64);
    let pid = obj.get("pid").and_then(Value::as_u64);

    let (agent_state, app) = match obj.get("status")? {
        Value::Object(status_obj) => {
            let agent_state = status_obj
                .get("state")
                .and_then(Value::as_str)
                .filter(|s| is_valid_agent_state(s))?
                .to_string();
            let app = status_obj
                .get("app")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    obj.get("agent")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                })
                .map(str::to_string);
            (agent_state, app)
        }
        Value::String(status_str) if is_valid_agent_state(status_str) => {
            let app = obj
                .get("agent")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    obj.get("app")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                })
                .map(str::to_string);
            (status_str.clone(), app)
        }
        _ => return None,
    };

    Some(HerdrTerminalInfo {
        address,
        state,
        created_ms,
        pid,
        app,
        agent_state,
    })
}

fn is_valid_agent_state(state: &str) -> bool {
    !state.is_empty()
        && state.len() <= MAX_AGENT_STATE_LEN
        && !state.chars().any(char::is_control)
}

/// Returns `true` iff `hc interrupt --json` output is a JSON object with `"outcome": "stopped"`.
pub fn parse_herdr_interrupt_stopped(stdout: &str) -> bool {
    serde_json::from_str::<Value>(stdout.trim())
        .ok()
        .and_then(|v| {
            v.as_object()
                .and_then(|obj| obj.get("outcome"))
                .and_then(Value::as_str)
                .map(|outcome| outcome == "stopped")
        })
        .unwrap_or(false)
}

enum GetStateOutcome {
    Ready(String),
    MissingBinary,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandOutcome {
    Completed {
        code: Option<i32>,
        stdout: String,
        #[allow(dead_code)]
        stderr: String,
    },
    MissingBinary,
    TimedOut,
    OutputTooLarge,
    IoError,
}

trait CommandRunner: Send + Sync {
    fn run<'a>(
        &'a self,
        bin: &'a str,
        args: &'a [&'a str],
        timeout: Duration,
    ) -> TransportFuture<'a, CommandOutcome>;
}

struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run<'a>(
        &'a self,
        bin: &'a str,
        args: &'a [&'a str],
        timeout: Duration,
    ) -> TransportFuture<'a, CommandOutcome> {
        Box::pin(async move {
            let mut cmd = Command::new(bin);
            cmd.args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);

            let mut child = match cmd.spawn() {
                Ok(child) => child,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    return CommandOutcome::MissingBinary;
                }
                Err(_) => return CommandOutcome::IoError,
            };

            let stdout = child.stdout.take();
            let stderr = child.stderr.take();

            let wait_fut = async {
                let stdout_fut = async {
                    match stdout {
                        Some(reader) => read_bounded(reader, MAX_HERDR_OUTPUT_BYTES).await,
                        None => Ok((Vec::new(), false)),
                    }
                };
                let stderr_fut = async {
                    match stderr {
                        Some(reader) => read_bounded(reader, MAX_HERDR_OUTPUT_BYTES).await,
                        None => Ok((Vec::new(), false)),
                    }
                };
                tokio::join!(stdout_fut, stderr_fut, child.wait())
            };

            match tokio::time::timeout(timeout, wait_fut).await {
                Ok((Ok((out_bytes, out_trunc)), Ok((err_bytes, err_trunc)), Ok(status))) => {
                    if out_trunc || err_trunc {
                        return CommandOutcome::OutputTooLarge;
                    }
                    CommandOutcome::Completed {
                        code: status.code(),
                        stdout: String::from_utf8_lossy(&out_bytes).into_owned(),
                        stderr: String::from_utf8_lossy(&err_bytes).into_owned(),
                    }
                }
                Ok(_) => {
                    let _ = child.kill().await;
                    CommandOutcome::IoError
                }
                Err(_) => {
                    let _ = child.kill().await;
                    CommandOutcome::TimedOut
                }
            }
        })
    }
}

async fn read_bounded<R: AsyncRead + Unpin>(
    reader: R,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    let mut limited = reader.take((limit + 1) as u64);
    limited.read_to_end(&mut buf).await?;
    let truncated = buf.len() > limit;
    if truncated {
        buf.truncate(limit);
    }
    Ok((buf, truncated))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug, Default)]
    struct MockRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        responses: Mutex<VecDeque<CommandOutcome>>,
    }

    impl MockRunner {
        fn with_responses(responses: Vec<CommandOutcome>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for MockRunner {
        fn run<'a>(
            &'a self,
            bin: &'a str,
            args: &'a [&'a str],
            _timeout: Duration,
        ) -> TransportFuture<'a, CommandOutcome> {
            let bin_owned = bin.to_string();
            let args_owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            Box::pin(async move {
                self.calls.lock().unwrap().push((bin_owned, args_owned));
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(CommandOutcome::IoError)
            })
        }
    }

    fn ok_stdout(stdout: impl Into<String>) -> CommandOutcome {
        CommandOutcome::Completed {
            code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn exit_code(code: i32, stdout: impl Into<String>) -> CommandOutcome {
        CommandOutcome::Completed {
            code: Some(code),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn nested_get_json(address: &str, created_ms: i64, pid: u64, app: &str, state: &str) -> String {
        serde_json::json!({
            "address": address,
            "created_ms": created_ms,
            "pid": pid,
            "state": "live",
            "status": {
                "app": app,
                "state": state,
            }
        })
        .to_string()
    }

    fn flat_get_json(address: &str, created_ms: i64, pid: u64, agent: &str, status: &str) -> String {
        serde_json::json!({
            "address": address,
            "created_ms": created_ms,
            "pid": pid,
            "state": "live",
            "status": status,
            "agent": agent,
        })
        .to_string()
    }

    fn pinned_target() -> HerdrTarget {
        HerdrTarget {
            terminal_id: "t3".to_string(),
            created_ms: Some(1_700_000_000_000),
            pid: Some(4242),
            app: Some("codex".to_string()),
            bin: "hc".to_string(),
        }
    }

    #[test]
    fn parses_both_nested_and_flat_get_shapes() {
        let nested = parse_herdr_get_output(&nested_get_json("t3", 100, 42, "codex", "idle"))
            .expect("nested shape must parse");
        assert_eq!(
            nested,
            HerdrTerminalInfo {
                address: "t3".to_string(),
                state: "live".to_string(),
                created_ms: Some(100),
                pid: Some(42),
                app: Some("codex".to_string()),
                agent_state: "idle".to_string(),
            }
        );

        let flat = parse_herdr_get_output(&flat_get_json("t7", 200, 99, "claude-code", "working"))
            .expect("flat shape must parse");
        assert_eq!(
            flat,
            HerdrTerminalInfo {
                address: "t7".to_string(),
                state: "live".to_string(),
                created_ms: Some(200),
                pid: Some(99),
                app: Some("claude-code".to_string()),
                agent_state: "working".to_string(),
            }
        );
    }

    #[test]
    fn rejects_malformed_and_mutated_get_json() {
        let invalid_cases = [
            "",
            "not json",
            "[]",
            "{}",
            r#"{"address":"t3","state":"live"}"#,
            r#"{"address":"t3","state":"live","status":null}"#,
            r#"{"address":"t3","state":"live","status":123}"#,
            r#"{"address":"t3","state":"live","status":""}"#,
            r#"{"address":"t3","state":"live","status":{}}"#,
            r#"{"address":"t3","state":"live","status":{"state":""}}"#,
            r#"{"address":"t3","state":"live","status":{"state":"idle\n"}}"#,
            r#"{"address":"","state":"live","status":"idle"}"#,
            r#"{"address":"t3","state":"","status":"idle"}"#,
            r#"{"address":"t3","state":"live","status":"idle"} trailing"#,
        ];
        for raw in invalid_cases {
            assert!(
                parse_herdr_get_output(raw).is_none(),
                "expected invalid JSON to fail closed: {raw:?}"
            );
        }
    }

    #[test]
    fn validates_terminal_ids_and_env_parsing() {
        assert!(is_valid_terminal_id("t3"));
        assert!(is_valid_terminal_id("macbook:t12"));
        assert!(is_valid_terminal_id("dev-box.local:t1"));

        assert!(!is_valid_terminal_id(""));
        assert!(!is_valid_terminal_id("-t3"));
        assert!(!is_valid_terminal_id("--json"));
        assert!(!is_valid_terminal_id("t3 extra"));
        assert!(!is_valid_terminal_id("t3\n"));
        assert!(!is_valid_terminal_id("t3\0"));

        assert_eq!(parse_env_terminal_id(None), None);
        assert_eq!(parse_env_terminal_id(Some("")), None);
        assert_eq!(parse_env_terminal_id(Some("   ")), None);
        assert_eq!(parse_env_terminal_id(Some("--flag")), None);
        assert_eq!(parse_env_terminal_id(Some(" t9 \n")), Some("t9".into()));
    }

    #[test]
    fn parses_interrupt_outcome_strictly() {
        assert!(parse_herdr_interrupt_stopped(r#"{"outcome":"stopped"}"#));
        assert!(parse_herdr_interrupt_stopped("  {\"outcome\":\"stopped\"}\n"));
        assert!(!parse_herdr_interrupt_stopped(r#"{"outcome":"timeout"}"#));
        assert!(!parse_herdr_interrupt_stopped(r#"{"outcome":"running"}"#));
        assert!(!parse_herdr_interrupt_stopped(r#"{}"#));
        assert!(!parse_herdr_interrupt_stopped("stopped"));
        assert!(!parse_herdr_interrupt_stopped(""));
    }

    #[test]
    fn serde_roundtrip_and_pin_matching() {
        let unpinned: HerdrTarget = serde_json::from_str(r#"{"terminalId":"t4"}"#).unwrap();
        assert_eq!(unpinned.terminal_id, "t4");
        assert_eq!(unpinned.bin, "hc");
        assert_eq!(unpinned.created_ms, None);
        assert_eq!(unpinned.pid, None);
        assert_eq!(unpinned.app, None);

        let pinned = pinned_target();
        let json = serde_json::to_string(&pinned).unwrap();
        assert!(json.contains("\"terminalId\":\"t3\""));
        assert!(json.contains("\"createdMs\":1700000000000"));
        assert_eq!(serde_json::from_str::<HerdrTarget>(&json).unwrap(), pinned);

        let matching =
            parse_herdr_get_output(&nested_get_json("t3", 1_700_000_000_000, 4242, "codex", "idle"))
                .unwrap();
        assert!(pinned.matches_live_terminal(&matching));
        assert!(unpinned.matches_live_terminal(
            &parse_herdr_get_output(&flat_get_json("t4", 1, 2, "claude-code", "idle")).unwrap()
        ));

        // Every individual pin mutation must fail closed.
        let mut wrong_addr = matching.clone();
        wrong_addr.address = "t4".into();
        assert!(!pinned.matches_live_terminal(&wrong_addr));

        let mut exited = matching.clone();
        exited.state = "exited".into();
        assert!(!pinned.matches_live_terminal(&exited));

        let mut wrong_created = matching.clone();
        wrong_created.created_ms = Some(1_700_000_000_001);
        assert!(!pinned.matches_live_terminal(&wrong_created));

        let mut missing_created = matching.clone();
        missing_created.created_ms = None;
        assert!(!pinned.matches_live_terminal(&missing_created));

        let mut wrong_pid = matching.clone();
        wrong_pid.pid = Some(4243);
        assert!(!pinned.matches_live_terminal(&wrong_pid));

        let mut wrong_app = matching.clone();
        wrong_app.app = Some("claude".into());
        assert!(!pinned.matches_live_terminal(&wrong_app));
    }

    #[tokio::test]
    async fn probe_captures_live_identity_for_both_shapes() {
        let runner = MockRunner::with_responses(vec![
            ok_stdout(nested_get_json("t3", 1234, 5678, "codex", "idle")),
            ok_stdout(flat_get_json("t4", 9999, 8888, "claude-code", "done")),
            ok_stdout(
                serde_json::json!({
                    "address": "t5",
                    "created_ms": 1,
                    "pid": 2,
                    "state": "exited",
                    "status": "idle",
                    "agent": "codex"
                })
                .to_string(),
            ),
            CommandOutcome::MissingBinary,
        ]);

        let t3 = probe_with_runner(&runner, "/usr/local/bin/hc", "t3", DEFAULT_GET_TIMEOUT)
            .await
            .expect("nested live terminal must probe");
        assert_eq!(
            t3,
            HerdrTarget {
                terminal_id: "t3".into(),
                created_ms: Some(1234),
                pid: Some(5678),
                app: Some("codex".into()),
                bin: "/usr/local/bin/hc".into(),
            }
        );

        let t4 = probe_with_runner(&runner, "hc", "t4", DEFAULT_GET_TIMEOUT)
            .await
            .expect("flat live terminal must probe");
        assert_eq!(
            t4,
            HerdrTarget {
                terminal_id: "t4".into(),
                created_ms: Some(9999),
                pid: Some(8888),
                app: Some("claude-code".into()),
                bin: "hc".into(),
            }
        );

        assert!(probe_with_runner(&runner, "hc", "t5", DEFAULT_GET_TIMEOUT).await.is_none());
        assert!(probe_with_runner(&runner, "hc", "t6", DEFAULT_GET_TIMEOUT).await.is_none());
    }

    /// Reference specification oracle for McKeeman differential verification of the
    /// complete Herdr delivery state machine across all transition combinations.
    #[allow(clippy::too_many_arguments)]
    fn oracle_deliver(
        initial_get: Option<Result<&str, &'static str>>,
        mode: PushMode,
        interrupt_stopped: bool,
        recheck_get: Option<&str>,
        send_code: Option<i32>,
    ) -> PushOutcome {
        let initial = match initial_get {
            None => return PushOutcome::hold("herdr_binary_missing"),
            Some(Err(reason)) => return PushOutcome::hold(reason),
            Some(Ok(state)) => state,
        };
        let (final_state, interrupted) = match initial {
            "idle" | "done" => (initial, false),
            "working" if mode == PushMode::Queue => return PushOutcome::hold("herdr_working"),
            "working" => {
                if !interrupt_stopped {
                    return PushOutcome::reject("herdr_interrupt_outcome_unknown");
                }
                match recheck_get {
                    Some("idle") => ("idle", true),
                    Some("done") => ("done", true),
                    _ => return PushOutcome::hold_interrupted("herdr_agent_not_ready"),
                }
            }
            other => return PushOutcome::hold(format!("herdr_{other}")),
        };
        let _ = final_state;
        match send_code {
            Some(0) => PushOutcome::delivered(),
            Some(9 | 10) => {
                if interrupted {
                    PushOutcome::hold_interrupted("herdr_send_guard_refused")
                } else {
                    PushOutcome::hold("herdr_send_guard_refused")
                }
            }
            _ => PushOutcome::Reject {
                reason: "herdr_send_outcome_unknown".into(),
                interrupted,
            },
        }
    }

    #[tokio::test]
    async fn differential_state_machine_matches_oracle_exhaustively() {
        let target = pinned_target();
        let transport = HerdrTransport::new(target.clone());

        let initial_states = ["idle", "done", "working", "permission"];
        let modes = [PushMode::Queue, PushMode::Interrupt];
        let interrupt_outcomes = [true, false];
        let recheck_states = [Some("idle"), Some("done"), Some("working"), None];
        let send_codes = [Some(0), Some(9), Some(10), Some(1), None];

        for &initial in &initial_states {
            for &mode in &modes {
                for &int_ok in &interrupt_outcomes {
                    for &recheck in &recheck_states {
                        for &send_code in &send_codes {
                            let mut responses = vec![ok_stdout(nested_get_json(
                                "t3",
                                1_700_000_000_000,
                                4242,
                                "codex",
                                initial,
                            ))];

                            if initial == "working" && mode == PushMode::Interrupt {
                                if int_ok {
                                    responses.push(ok_stdout(r#"{"outcome":"stopped"}"#));
                                    match recheck {
                                        Some(st) => responses.push(ok_stdout(nested_get_json(
                                            "t3",
                                            1_700_000_000_000,
                                            4242,
                                            "codex",
                                            st,
                                        ))),
                                        None => responses.push(CommandOutcome::TimedOut),
                                    }
                                } else {
                                    responses.push(ok_stdout(r#"{"outcome":"timeout"}"#));
                                }
                            }

                            responses.push(match send_code {
                                Some(c) => exit_code(c, "{}"),
                                None => CommandOutcome::TimedOut,
                            });

                            let runner = MockRunner::with_responses(responses);
                            let actual = transport
                                .deliver_with_runner(&runner, "hello", mode)
                                .await;
                            let expected = oracle_deliver(
                                Some(Ok(initial)),
                                mode,
                                int_ok,
                                recheck,
                                send_code,
                            );
                            assert_eq!(
                                actual, expected,
                                "divergence for initial={initial} mode={mode:?} int_ok={int_ok} recheck={recheck:?} send_code={send_code:?}"
                            );

                            // Verify exact send guard arguments whenever `send` was invoked.
                            let calls = runner.calls();
                            if let Some((_bin, send_args)) =
                                calls.iter().find(|(_, a)| a.first().map(String::as_str) == Some("send"))
                            {
                                let expected_state = if initial == "working" {
                                    recheck.unwrap()
                                } else {
                                    initial
                                };
                                if expected_state == "idle" {
                                    assert_eq!(
                                        send_args,
                                        &["send", "--json", "--if", "idle", "t3", "hello"]
                                    );
                                } else {
                                    assert_eq!(send_args, &["send", "--json", "t3", "hello"]);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn missing_binary_and_unavailable_cases_match_oracle() {
        let transport = HerdrTransport::new(pinned_target());

        let missing = MockRunner::with_responses(vec![CommandOutcome::MissingBinary]);
        assert_eq!(
            transport
                .deliver_with_runner(&missing, "hi", PushMode::Queue)
                .await,
            oracle_deliver(None, PushMode::Queue, false, None, None)
        );
        assert_eq!(missing.calls().len(), 1);

        let timeout = MockRunner::with_responses(vec![CommandOutcome::TimedOut]);
        assert_eq!(
            transport
                .deliver_with_runner(&timeout, "hi", PushMode::Interrupt)
                .await,
            oracle_deliver(
                Some(Err("herdr_target_unavailable")),
                PushMode::Interrupt,
                false,
                None,
                None
            )
        );
        assert_eq!(timeout.calls().len(), 1);
    }
}
