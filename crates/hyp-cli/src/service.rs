//! `hyp service` — Background OS service lifecycle for the Hyphae v2 daemon
//! (`macOS LaunchAgent` / `Linux systemd --user` / `Windows Task Scheduler (schtasks)`).
//!
//! Keeps `hyp daemon` strictly foreground (required by LaunchAgent, systemd, Task Scheduler,
//! Docker, and all existing tests) while letting `hyp onboard` and `hyp service install|restart|stop|status`
//! manage a clean auto-restarting background daemon.

use crate::config_file::{default_config_dir, resolve_home_dir, resolve_state_dir};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use crate::config_file::{ensure_dir, write_atomic_file};
use crate::ui::{
    CliError, CommandResult, EXIT_OK, JsonEnvelope, print_json, print_next_steps, print_warnings,
};
use clap::Subcommand;
use hyp_harness::sock::{DEFAULT_SOCKET_FILENAME, daemon_rpc_sync, default_socket_path};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const MACOS_LAUNCHAGENT_LABEL: &str = "to.hyphae.daemon";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const LINUX_SYSTEMD_UNIT: &str = "hyphae-daemon.service";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const WINDOWS_TASK_NAME: &str = "HyphaeDaemon";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const WINDOWS_TASK_XML_FILENAME: &str = "hyphae-daemon-task.xml";

const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(3);
const DAEMON_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DAEMON_RPC_TIMEOUT: Duration = Duration::from_millis(250);

/// Pure fail-closed check for environment variable boolean flags (`1`, `true`, `yes`).
fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    })
}

/// Canonicalizes the longest existing ancestor of `path` and re-joins any non-existent tail
/// components, so symlinked temp paths like `/var/folders/...` <-> `/private/var/folders/...`
/// and `/tmp/...` <-> `/private/tmp/...` normalize consistently even before directories are created.
fn best_effort_canonicalize(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    let mut tail = Vec::new();
    let mut cur = path;
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            tail.push(name.to_os_string());
        }
        if parent.exists() {
            if let Ok(mut base) = std::fs::canonicalize(parent) {
                for comp in tail.into_iter().rev() {
                    base.push(comp);
                }
                return base;
            }
            break;
        }
        cur = parent;
    }
    path.to_path_buf()
}

/// Returns `true` if `home` points inside an ephemeral/temporary directory (e.g. `TempDir`,
/// `/tmp`, `/private/tmp`, `/var/folders`, `/private/var/folders`, or Windows `%TEMP%`/`Temp`).
///
/// Used as a fail-closed guard so isolated tests and ephemeral temp homes NEVER mutate the
/// live host OS service manager (`launchctl`, `systemctl --user`, or `schtasks`).
pub(crate) fn is_ephemeral_temp_home(home: &Path) -> bool {
    let raw_home = home;
    let canon_home = best_effort_canonicalize(home);

    let matches_prefix = |prefix: &Path| -> bool {
        // Guard against pathological root-only prefixes (e.g. TMPDIR=/).
        if prefix.as_os_str().is_empty() || prefix.components().count() <= 1 {
            return false;
        }
        raw_home.starts_with(prefix) || canon_home.starts_with(prefix)
    };

    let sys_tmp = std::env::temp_dir();
    if matches_prefix(&sys_tmp) || matches_prefix(&best_effort_canonicalize(&sys_tmp)) {
        return true;
    }

    for static_prefix in [
        Path::new("/tmp"),
        Path::new("/private/tmp"),
        Path::new("/var/folders"),
        Path::new("/private/var/folders"),
    ] {
        if matches_prefix(static_prefix) {
            return true;
        }
    }

    for var in ["TMPDIR", "TEMP", "TMP"] {
        if let Some(val) = std::env::var_os(var) {
            let p = PathBuf::from(val);
            if matches_prefix(&p) || matches_prefix(&best_effort_canonicalize(&p)) {
                return true;
            }
        }
    }

    // Cross-platform Windows temp path pattern (`\AppData\Local\Temp` or `\Windows\Temp`).
    let normalized = raw_home
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if normalized.contains("/appdata/local/temp/")
        || normalized.ends_with("/appdata/local/temp")
        || normalized.contains("/windows/temp/")
        || normalized.ends_with("/windows/temp")
    {
        return true;
    }

    false
}

/// Returns `Some(reason)` when host OS service control (`launchctl` / `systemctl --user` /
/// `schtasks`) MUST be disabled to protect the live host (either `HYPHAE_NO_SERVICE=1` is set
/// or `home` resolves to an ephemeral temporary directory).
pub(crate) fn service_control_disabled(home: &Path) -> Option<&'static str> {
    if env_flag_enabled("HYPHAE_NO_SERVICE") {
        return Some("HYPHAE_NO_SERVICE is set");
    }
    if is_ephemeral_temp_home(home) {
        return Some("ephemeral temporary home directory");
    }
    None
}

#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux", target_os = "windows")),
    allow(dead_code)
)]
fn ensure_service_control_allowed(home: &Path, action: &str) -> Result<(), String> {
    if let Some(reason) = service_control_disabled(home) {
        return Err(format!(
            "Refusing to run `hyp service {action}` against the host OS service manager ({reason}; home={}). \
             Run `hyp daemon` directly in isolated/test environments, or unset HYPHAE_NO_SERVICE with a persistent HOME.",
            home.display()
        ));
    }
    Ok(())
}

// ============================================================================
// Pure Cross-Platform macOS `launchd` State Machine (Testable on Every OS)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) struct LaunchctlOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
impl LaunchctlOutput {
    pub(crate) fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    pub(crate) fn detail(&self) -> String {
        let stderr = self.stderr.trim();
        let stdout = self.stdout.trim();
        if !stderr.is_empty() {
            stderr.to_string()
        } else if !stdout.is_empty() {
            stdout.to_string()
        } else {
            match self.exit_code {
                Some(code) => format!("exit status {code}"),
                None => "unknown error".to_string(),
            }
        }
    }

    fn combined_lower(&self) -> String {
        format!("{}\n{}", self.stderr, self.stdout).to_ascii_lowercase()
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) struct LaunchdRetryPolicy {
    /// Max polls waiting for `launchctl bootout` to finish tearing down (`40 × 50ms = 2.0s`).
    pub bootout_poll_attempts: usize,
    pub bootout_poll_interval: Duration,
    /// Max retries for `launchctl bootstrap` on transient unload-race errors (`10 × 150ms = 1.5s`).
    pub bootstrap_max_attempts: usize,
    pub bootstrap_retry_delay: Duration,
}

impl Default for LaunchdRetryPolicy {
    fn default() -> Self {
        Self {
            bootout_poll_attempts: 40,
            bootout_poll_interval: Duration::from_millis(50),
            bootstrap_max_attempts: 10,
            bootstrap_retry_delay: Duration::from_millis(150),
        }
    }
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn is_launchd_service_already_loaded(out: &LaunchctlOutput) -> bool {
    let lower = out.combined_lower();
    out.exit_code == Some(37)
        || lower.contains("service already loaded")
        || lower.contains("already loaded")
        || lower.contains("already bootstrapped")
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn is_launchd_transient_bootstrap_race(out: &LaunchctlOutput) -> bool {
    let lower = out.combined_lower();
    out.exit_code == Some(5)
        || out.exit_code == Some(35)
        || out.exit_code == Some(36)
        || lower.contains("input/output error")
        || lower.contains("could not find service")
        || lower.contains("service is disabled")
        || lower.contains("operation now in progress")
        || lower.contains("resource temporarily unavailable")
        || lower.contains("try again")
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn launchd_is_loaded_via<F>(target: &str, run: &mut F) -> bool
where
    F: FnMut(&[&str]) -> Result<LaunchctlOutput, String>,
{
    run(&["print", target])
        .map(|o| o.success())
        .unwrap_or(false)
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn launchd_bootout_and_wait_via<F, S>(
    target: &str,
    policy: LaunchdRetryPolicy,
    run: &mut F,
    sleep: &mut S,
) where
    F: FnMut(&[&str]) -> Result<LaunchctlOutput, String>,
    S: FnMut(Duration),
{
    let _ = run(&["bootout", target]);
    let polls = policy.bootout_poll_attempts.max(1);
    for attempt in 0..polls {
        if !launchd_is_loaded_via(target, run) {
            return;
        }
        if attempt + 1 < polls {
            sleep(policy.bootout_poll_interval);
        }
    }
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn launchd_bootstrap_with_retry_via<F, S>(
    domain: &str,
    target: &str,
    plist_str: &str,
    force_kill_if_loaded: bool,
    policy: LaunchdRetryPolicy,
    run: &mut F,
    sleep: &mut S,
) -> Result<(), String>
where
    F: FnMut(&[&str]) -> Result<LaunchctlOutput, String>,
    S: FnMut(Duration),
{
    let _ = run(&["enable", target]);
    let max_attempts = policy.bootstrap_max_attempts.max(1);
    let mut last_err = String::from("unknown error");

    for attempt in 0..max_attempts {
        let boot = run(&["bootstrap", domain, plist_str])?;
        if boot.success() {
            return Ok(());
        }

        if is_launchd_service_already_loaded(&boot) {
            let kick = if force_kill_if_loaded {
                run(&["kickstart", "-k", target])?
            } else {
                run(&["kickstart", target])?
            };
            if kick.success() {
                return Ok(());
            }
            last_err = kick.detail();
            if attempt + 1 < max_attempts {
                if launchd_is_loaded_via(target, run) {
                    launchd_bootout_and_wait_via(target, policy, run, sleep);
                } else {
                    sleep(policy.bootstrap_retry_delay);
                }
                let _ = run(&["enable", target]);
                continue;
            }
            return Err(format!(
                "launchctl bootstrap failed after {max_attempts} attempts: {last_err}"
            ));
        }

        last_err = boot.detail();
        if is_launchd_transient_bootstrap_race(&boot) {
            if attempt + 1 < max_attempts {
                let _ = run(&["enable", target]);
                sleep(policy.bootstrap_retry_delay);
                continue;
            }
            return Err(format!(
                "launchctl bootstrap failed after {max_attempts} attempts: {last_err}"
            ));
        }

        return Err(format!("launchctl bootstrap failed: {last_err}"));
    }

    Err(format!(
        "launchctl bootstrap failed after {max_attempts} attempts: {last_err}"
    ))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn launchd_install_via<F, S>(
    domain: &str,
    target: &str,
    plist_str: &str,
    policy: LaunchdRetryPolicy,
    run: &mut F,
    sleep: &mut S,
) -> Result<(), String>
where
    F: FnMut(&[&str]) -> Result<LaunchctlOutput, String>,
    S: FnMut(Duration),
{
    launchd_bootout_and_wait_via(target, policy, run, sleep);
    launchd_bootstrap_with_retry_via(domain, target, plist_str, false, policy, run, sleep)
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn launchd_start_via<F, S>(
    domain: &str,
    target: &str,
    plist_str: &str,
    policy: LaunchdRetryPolicy,
    run: &mut F,
    sleep: &mut S,
) -> Result<(), String>
where
    F: FnMut(&[&str]) -> Result<LaunchctlOutput, String>,
    S: FnMut(Duration),
{
    let _ = run(&["enable", target]);
    if launchd_is_loaded_via(target, run) {
        let kick = run(&["kickstart", target])?;
        if kick.success() {
            return Ok(());
        }
        // Recover cleanly from stale `is_loaded` race (e.g. `Could not find service` right after
        // `bootout`) or a wedged loaded job by falling through to retryable `bootstrap`.
        if launchd_is_loaded_via(target, run) {
            launchd_bootout_and_wait_via(target, policy, run, sleep);
        }
    }
    launchd_bootstrap_with_retry_via(domain, target, plist_str, false, policy, run, sleep)
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn launchd_stop_via<F, S>(
    target: &str,
    policy: LaunchdRetryPolicy,
    run: &mut F,
    sleep: &mut S,
) where
    F: FnMut(&[&str]) -> Result<LaunchctlOutput, String>,
    S: FnMut(Duration),
{
    launchd_bootout_and_wait_via(target, policy, run, sleep);
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn launchd_restart_via<F, S>(
    domain: &str,
    target: &str,
    plist_str: &str,
    policy: LaunchdRetryPolicy,
    run: &mut F,
    sleep: &mut S,
) -> Result<(), String>
where
    F: FnMut(&[&str]) -> Result<LaunchctlOutput, String>,
    S: FnMut(Duration),
{
    let _ = run(&["enable", target]);
    let kick = run(&["kickstart", "-k", target])?;
    if kick.success() {
        return Ok(());
    }
    if launchd_is_loaded_via(target, run) {
        launchd_bootout_and_wait_via(target, policy, run, sleep);
    }
    launchd_bootstrap_with_retry_via(domain, target, plist_str, true, policy, run, sleep)
}

#[derive(Subcommand)]
pub enum ServiceCommand {
    /// Install and start the Hyphae background daemon OS service (LaunchAgent / systemd --user / Windows Task Scheduler)
    Install {
        /// Explicit path to static hyp binary (defaults to current_exe)
        #[arg(long)]
        bin: Option<PathBuf>,
        /// Override home directory (defaults to $HOME)
        #[arg(long)]
        home: Option<PathBuf>,
        /// Explicit state directory for node.sqlite and logs/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path to pass to `hyp daemon`
        #[arg(long)]
        config: Option<PathBuf>,
        /// Explicit connector.sock path to pass to `hyp daemon` and probe
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Stop and remove the Hyphae background daemon OS service definition
    Uninstall {
        /// Override home directory (defaults to $HOME)
        #[arg(long)]
        home: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Start the installed Hyphae background daemon OS service
    Start {
        /// Override home directory (defaults to $HOME)
        #[arg(long)]
        home: Option<PathBuf>,
        /// Explicit connector.sock path to probe for readiness
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Stop the running Hyphae background daemon OS service
    Stop {
        /// Override home directory (defaults to $HOME)
        #[arg(long)]
        home: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Restart the Hyphae background daemon OS service cleanly
    Restart {
        /// Override home directory (defaults to $HOME)
        #[arg(long)]
        home: Option<PathBuf>,
        /// Explicit connector.sock path to probe for readiness
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Inspect installed service status and live `connector.sock` (`daemon.status`) health
    Status {
        /// Override home directory (defaults to $HOME)
        #[arg(long)]
        home: Option<PathBuf>,
        /// Explicit connector.sock path to probe
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

/// Platform-agnostic specification rendered into a LaunchAgent plist, systemd user unit,
/// or Windows Task Scheduler XML definition.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux", target_os = "windows")),
    allow(dead_code)
)]
pub struct ServiceSpec {
    pub bin_path: PathBuf,
    pub state_dir: PathBuf,
    /// When `true`, `--state-dir <state_dir>` was explicitly requested and MUST be passed to
    /// the generated daemon argv (`ExecStart` / `ProgramArguments` / Windows task args).
    pub explicit_state_dir: bool,
    pub config_path: Option<PathBuf>,
    pub socket_path: Option<PathBuf>,
    pub logs_dir: PathBuf,
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    pub path_env: String,
    /// Optional `HYPHAE_SECRET_BACKEND` value pinned into the service environment so headless
    /// background services use the exact same secret store as interactive CLI invocations.
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    pub secret_backend: Option<String>,
    /// Additional non-secret backend configuration environment variables pinned into the service
    /// definition (e.g. `HYPHAE_1PASSWORD_VAULT`, `HYPHAE_LASTPASS_PREFIX`, `HYPHAE_PASS_PREFIX`,
    /// `PASSWORD_STORE_DIR`, `GNUPGHOME`, `HYPHAE_OP_BIN`, `HYPHAE_LPASS_BIN`, `HYPHAE_PASS_BIN`).
    /// Never contains secrets or tokens (e.g. never `OP_SERVICE_ACCOUNT_TOKEN`).
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    pub extra_env: BTreeMap<String, String>,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub user_id: Option<String>,
}

/// Outcome of attempting to restart a managed background service after `hyp update`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRestartOutcome {
    pub attempted: bool,
    pub installed: bool,
    pub restarted: bool,
    pub skipped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub detail: String,
}

/// Result of attempting automatic background daemon startup during `hyp onboard`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoStartResult {
    pub started: bool,
    pub installed: bool,
    pub manager: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DaemonProbe {
    alive: bool,
    socket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u64>,
}

// ============================================================================
// Pure Cross-Platform Path & Unit Generators (Always Compiled & Unit-Tested)
// ============================================================================

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn macos_plist_path(home: &Path) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{MACOS_LAUNCHAGENT_LABEL}.plist"))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn linux_systemd_unit_path(home: &Path) -> PathBuf {
    home.join(".config")
        .join("systemd")
        .join("user")
        .join(LINUX_SYSTEMD_UNIT)
}

/// Computes the Linux `systemd --user` unit path, honoring an explicit `XDG_CONFIG_HOME` when set.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn linux_systemd_unit_path_with_xdg(home: &Path, xdg_config_home: Option<&Path>) -> PathBuf {
    if let Some(xdg) = xdg_config_home {
        if !xdg.as_os_str().is_empty() {
            return xdg.join("systemd").join("user").join(LINUX_SYSTEMD_UNIT);
        }
    }
    linux_systemd_unit_path(home)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn resolve_xdg_config_home(explicit_home: bool) -> Option<PathBuf> {
    if explicit_home {
        return None;
    }
    let raw = std::env::var_os("XDG_CONFIG_HOME")?;
    if raw.is_empty() {
        return None;
    }
    if let Some(s) = raw.to_str() {
        if s.trim().is_empty() {
            return None;
        }
    }
    Some(PathBuf::from(raw))
}

/// Parses `loginctl show-user <user> -p Linger` stdout (`Linger=yes` / `Linger=no`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_loginctl_linger(stdout: &str) -> Option<bool> {
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("Linger=") {
            let lower = val.trim().to_ascii_lowercase();
            if lower == "yes" {
                return Some(true);
            }
            if lower == "no" {
                return Some(false);
            }
        }
    }
    None
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn windows_task_xml_path(state_dir: &Path) -> PathBuf {
    state_dir.join(WINDOWS_TASK_XML_FILENAME)
}

pub fn default_daemon_logs_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("logs")
}

/// Escapes special XML characters for safe embedding inside LaunchAgent plist and
/// Windows Task Scheduler XML text nodes.
#[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
pub fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escapes a single argument for systemd `ExecStart=` (handles spaces, quotes, backslashes, and `%` specifiers).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn systemd_escape_arg(arg: &str) -> String {
    let doubled_pct = arg.replace('%', "%%");
    let needs_quote = doubled_pct.is_empty()
        || doubled_pct
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\'));
    if !needs_quote {
        return doubled_pct;
    }
    let mut quoted = String::with_capacity(doubled_pct.len() + 2);
    quoted.push('"');
    for ch in doubled_pct.chars() {
        if matches!(ch, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

/// Builds a clean deduplicated `PATH` value so background LaunchAgent / systemd services can locate
/// `node`, `hyp`, Homebrew binaries, and system utilities reliably.
pub fn build_service_path_env(current_path: Option<&str>, bin_dir: Option<&Path>) -> String {
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    let mut push_unique = |entry: &str| {
        let trimmed = entry.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            ordered.push(trimmed.to_string());
        }
    };

    if let Some(dir) = bin_dir {
        push_unique(&dir.display().to_string());
    }
    if let Some(raw) = current_path {
        for piece in raw.split(':') {
            push_unique(piece);
        }
    }
    for standard in [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ] {
        push_unique(standard);
    }
    ordered.join(":")
}

/// Builds the exact foreground daemon command line (`[<hyp>, "daemon", ...]`).
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub fn build_daemon_argv(spec: &ServiceSpec) -> Vec<String> {
    let mut argv = vec![spec.bin_path.display().to_string(), "daemon".to_string()];
    if spec.explicit_state_dir && !spec.state_dir.as_os_str().is_empty() {
        argv.push("--state-dir".to_string());
        argv.push(spec.state_dir.display().to_string());
    }
    if let Some(ref cfg) = spec.config_path {
        argv.push("--config".to_string());
        argv.push(cfg.display().to_string());
    }
    if let Some(ref sock) = spec.socket_path {
        argv.push("--socket".to_string());
        argv.push(sock.display().to_string());
    }
    argv
}

fn is_safe_service_env_value(val: &str) -> bool {
    !val.trim().is_empty() && !val.chars().any(char::is_control)
}

/// Collects ONLY safe, non-secret configuration env vars relevant to `backend` so installed
/// background services (`LaunchAgent` / `systemd --user`) target the exact same vault/prefix/store.
/// Never collects secret credentials or session tokens (e.g. never `OP_SERVICE_ACCOUNT_TOKEN`).
pub fn collect_secret_backend_service_env<F>(
    backend: hyp_crypto::keystore::SecretBackend,
    get_env: F,
) -> BTreeMap<String, String>
where
    F: Fn(&str) -> Option<String>,
{
    let mut env = BTreeMap::new();
    match backend {
        hyp_crypto::keystore::SecretBackend::OnePassword => {
            if let Some(vault) = get_env("HYPHAE_1PASSWORD_VAULT") {
                if hyp_crypto::keystore::validate_onepassword_vault(&vault).is_ok() {
                    env.insert("HYPHAE_1PASSWORD_VAULT".to_string(), vault);
                }
            }
            if let Some(bin) = get_env("HYPHAE_OP_BIN") {
                let trimmed = bin.trim();
                if is_safe_service_env_value(trimmed) {
                    env.insert("HYPHAE_OP_BIN".to_string(), trimmed.to_string());
                }
            }
        }
        hyp_crypto::keystore::SecretBackend::LastPass => {
            if let Some(prefix) = get_env("HYPHAE_LASTPASS_PREFIX") {
                if hyp_crypto::keystore::validate_lastpass_prefix(&prefix).is_ok() {
                    env.insert("HYPHAE_LASTPASS_PREFIX".to_string(), prefix);
                }
            }
            if let Some(bin) = get_env("HYPHAE_LPASS_BIN") {
                let trimmed = bin.trim();
                if is_safe_service_env_value(trimmed) {
                    env.insert("HYPHAE_LPASS_BIN".to_string(), trimmed.to_string());
                }
            }
        }
        hyp_crypto::keystore::SecretBackend::Pass => {
            if let Some(prefix) = get_env("HYPHAE_PASS_PREFIX") {
                if hyp_crypto::keystore::validate_pass_prefix(&prefix).is_ok() {
                    env.insert("HYPHAE_PASS_PREFIX".to_string(), prefix);
                }
            }
            for key in ["PASSWORD_STORE_DIR", "GNUPGHOME", "HYPHAE_PASS_BIN"] {
                if let Some(val) = get_env(key) {
                    let trimmed = val.trim();
                    if is_safe_service_env_value(trimmed) {
                        env.insert(key.to_string(), trimmed.to_string());
                    }
                }
            }
        }
        hyp_crypto::keystore::SecretBackend::File
        | hyp_crypto::keystore::SecretBackend::Keychain
        | hyp_crypto::keystore::SecretBackend::SecretService => {}
    }
    env
}

/// Renders the macOS LaunchAgent XML property list (`to.hyphae.daemon.plist`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn render_macos_plist(spec: &ServiceSpec) -> String {
    let argv = build_daemon_argv(spec);
    let mut args_xml = String::new();
    for arg in &argv {
        args_xml.push_str("    <string>");
        args_xml.push_str(&xml_escape(arg));
        args_xml.push_str("</string>\n");
    }
    let out_log = xml_escape(&spec.logs_dir.join("daemon.out.log").display().to_string());
    let err_log = xml_escape(&spec.logs_dir.join("daemon.err.log").display().to_string());
    let path_xml = xml_escape(&spec.path_env);
    let mut extra_env_xml = String::new();
    if let Some(backend) = spec
        .secret_backend
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        extra_env_xml.push_str(&format!(
            "    <key>HYPHAE_SECRET_BACKEND</key>\n    <string>{}</string>\n",
            xml_escape(backend)
        ));
    }
    for (k, v) in &spec.extra_env {
        if matches!(k.as_str(), "PATH" | "HYPHAE_SECRET_BACKEND")
            || !is_safe_service_env_value(k)
            || !is_safe_service_env_value(v)
        {
            continue;
        }
        extra_env_xml.push_str(&format!(
            "    <key>{}</key>\n    <string>{}</string>\n",
            xml_escape(k),
            xml_escape(v)
        ));
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20\x20<key>Label</key>\n\
         \x20\x20<string>{MACOS_LAUNCHAGENT_LABEL}</string>\n\
         \x20\x20<key>ProgramArguments</key>\n\
         \x20\x20<array>\n\
         {args_xml}\
         \x20\x20</array>\n\
         \x20\x20<key>RunAtLoad</key>\n\
         \x20\x20<true/>\n\
         \x20\x20<key>KeepAlive</key>\n\
         \x20\x20<true/>\n\
         \x20\x20<key>StandardOutPath</key>\n\
         \x20\x20<string>{out_log}</string>\n\
         \x20\x20<key>StandardErrorPath</key>\n\
         \x20\x20<string>{err_log}</string>\n\
         \x20\x20<key>EnvironmentVariables</key>\n\
         \x20\x20<dict>\n\
         \x20\x20\x20\x20<key>PATH</key>\n\
         \x20\x20\x20\x20<string>{path_xml}</string>\n\
         {extra_env_xml}\
         \x20\x20</dict>\n\
         </dict>\n\
         </plist>\n"
    )
}

/// Renders the Linux `systemd --user` service unit (`hyphae-daemon.service`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn render_linux_systemd_unit(spec: &ServiceSpec) -> String {
    let exec_start = build_daemon_argv(spec)
        .iter()
        .map(|arg| systemd_escape_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let escape_systemd_env = |raw: &str| {
        raw.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    };
    let env_path = escape_systemd_env(&spec.path_env);
    let mut extra_env_lines = String::new();
    if let Some(backend) = spec
        .secret_backend
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        extra_env_lines.push_str(&format!(
            "Environment=\"HYPHAE_SECRET_BACKEND={}\"\n",
            escape_systemd_env(backend)
        ));
    }
    for (k, v) in &spec.extra_env {
        if matches!(k.as_str(), "PATH" | "HYPHAE_SECRET_BACKEND")
            || !is_safe_service_env_value(k)
            || !is_safe_service_env_value(v)
        {
            continue;
        }
        extra_env_lines.push_str(&format!(
            "Environment=\"{}={}\"\n",
            escape_systemd_env(k),
            escape_systemd_env(v)
        ));
    }

    format!(
        "[Unit]\n\
         Description=Hyphae v2 Agent Mesh Daemon\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec_start}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         Environment=\"PATH={env_path}\"\n\
         {extra_env_lines}\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

/// Quotes a single Windows command-line argument following `CommandLineToArgvW` rules
/// (handles spaces, tabs, quotes, and backslashes preceding quotes or the closing quote).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn windows_quote_arg(arg: &str) -> String {
    let needs_quote = arg.is_empty() || arg.chars().any(|c| c == ' ' || c == '\t' || c == '"');
    if !needs_quote {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Encodes a UTF-8 Rust `&str` into UTF-16 LE bytes prefixed with the UTF-16 LE BOM (`0xFF, 0xFE`),
/// matching Windows Task Scheduler (`schtasks /Create /XML`) native encoding requirements.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn encode_utf16le_bom(xml: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + xml.len() * 2);
    out.push(0xFF);
    out.push(0xFE);
    for unit in xml.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Formats a Windows `DOMAIN\User` (or bare `User`) identifier for Task Scheduler `<UserId>`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn format_windows_user_id(domain: Option<&str>, user: Option<&str>) -> Option<String> {
    let username = user.map(str::trim).filter(|s| !s.is_empty())?;
    if let Some(dom) = domain.map(str::trim).filter(|s| !s.is_empty()) {
        Some(format!("{dom}\\{username}"))
    } else {
        Some(username.to_string())
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn build_windows_daemon_args(spec: &ServiceSpec) -> Vec<String> {
    let mut args = vec!["daemon".to_string()];
    if !spec.state_dir.as_os_str().is_empty() {
        args.push("--state-dir".to_string());
        args.push(spec.state_dir.display().to_string());
    }
    if let Some(ref cfg) = spec.config_path {
        args.push("--config".to_string());
        args.push(cfg.display().to_string());
    }
    if let Some(ref sock) = spec.socket_path {
        args.push("--socket".to_string());
        args.push(sock.display().to_string());
    }
    args
}

/// Renders a Windows Task Scheduler 1.2 XML definition for per-user background execution
/// (`LogonTrigger`, `LeastPrivilege`, `InteractiveToken`, battery-safe, unlimited execution time,
/// automatic restart on failure, and XML-escaped `<Command>` / `<Arguments>`).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn windows_task_xml(spec: &ServiceSpec) -> String {
    let command_xml = xml_escape(&spec.bin_path.display().to_string());
    let raw_args = build_windows_daemon_args(spec)
        .iter()
        .map(|arg| windows_quote_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let args_xml = xml_escape(&raw_args);
    let working_dir_xml = xml_escape(&spec.state_dir.display().to_string());

    let (trigger_user_xml, principal_user_xml) = match spec
        .user_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(uid) => {
            let escaped = xml_escape(uid);
            (
                format!("      <UserId>{escaped}</UserId>\n"),
                format!("      <UserId>{escaped}</UserId>\n"),
            )
        }
        None => (String::new(), String::new()),
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
         <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
         \x20\x20<RegistrationInfo>\n\
         \x20\x20\x20\x20<Description>Hyphae v2 Agent Mesh Daemon</Description>\n\
         \x20\x20</RegistrationInfo>\n\
         \x20\x20<Triggers>\n\
         \x20\x20\x20\x20<LogonTrigger>\n\
         \x20\x20\x20\x20\x20\x20<Enabled>true</Enabled>\n\
         {trigger_user_xml}\
         \x20\x20\x20\x20</LogonTrigger>\n\
         \x20\x20</Triggers>\n\
         \x20\x20<Principals>\n\
         \x20\x20\x20\x20<Principal id=\"Author\">\n\
         {principal_user_xml}\
         \x20\x20\x20\x20\x20\x20<LogonType>InteractiveToken</LogonType>\n\
         \x20\x20\x20\x20\x20\x20<RunLevel>LeastPrivilege</RunLevel>\n\
         \x20\x20\x20\x20</Principal>\n\
         \x20\x20</Principals>\n\
         \x20\x20<Settings>\n\
         \x20\x20\x20\x20<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n\
         \x20\x20\x20\x20<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n\
         \x20\x20\x20\x20<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n\
         \x20\x20\x20\x20<AllowHardTerminate>true</AllowHardTerminate>\n\
         \x20\x20\x20\x20<StartWhenAvailable>true</StartWhenAvailable>\n\
         \x20\x20\x20\x20<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n\
         \x20\x20\x20\x20<AllowStartOnDemand>true</AllowStartOnDemand>\n\
         \x20\x20\x20\x20<Enabled>true</Enabled>\n\
         \x20\x20\x20\x20<Hidden>false</Hidden>\n\
         \x20\x20\x20\x20<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n\
         \x20\x20\x20\x20<RestartOnFailure>\n\
         \x20\x20\x20\x20\x20\x20<Interval>PT1M</Interval>\n\
         \x20\x20\x20\x20\x20\x20<Count>3</Count>\n\
         \x20\x20\x20\x20</RestartOnFailure>\n\
         \x20\x20</Settings>\n\
         \x20\x20<Actions Context=\"Author\">\n\
         \x20\x20\x20\x20<Exec>\n\
         \x20\x20\x20\x20\x20\x20<Command>{command_xml}</Command>\n\
         \x20\x20\x20\x20\x20\x20<Arguments>{args_xml}</Arguments>\n\
         \x20\x20\x20\x20\x20\x20<WorkingDirectory>{working_dir_xml}</WorkingDirectory>\n\
         \x20\x20\x20\x20</Exec>\n\
         \x20\x20</Actions>\n\
         </Task>\n"
    )
}

/// Builds argv for `schtasks /Create /TN <task_name> /XML <xml_path> /F`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn build_schtasks_create_args(task_name: &str, xml_path: &Path) -> Vec<String> {
    vec![
        "/Create".to_string(),
        "/TN".to_string(),
        task_name.to_string(),
        "/XML".to_string(),
        xml_path.display().to_string(),
        "/F".to_string(),
    ]
}

/// Builds argv for `schtasks /Query /TN <task_name> /FO LIST /V`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn build_schtasks_query_args(task_name: &str) -> Vec<String> {
    vec![
        "/Query".to_string(),
        "/TN".to_string(),
        task_name.to_string(),
        "/FO".to_string(),
        "LIST".to_string(),
        "/V".to_string(),
    ]
}

/// Builds argv for `schtasks /Run /TN <task_name>`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn build_schtasks_run_args(task_name: &str) -> Vec<String> {
    vec!["/Run".to_string(), "/TN".to_string(), task_name.to_string()]
}

/// Builds argv for `schtasks /End /TN <task_name>`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn build_schtasks_end_args(task_name: &str) -> Vec<String> {
    vec!["/End".to_string(), "/TN".to_string(), task_name.to_string()]
}

/// Builds argv for `schtasks /Delete /TN <task_name> /F`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn build_schtasks_delete_args(task_name: &str) -> Vec<String> {
    vec![
        "/Delete".to_string(),
        "/TN".to_string(),
        task_name.to_string(),
        "/F".to_string(),
    ]
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    let _ = chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(ch);
            }
        } else if ch == '"' && current.is_empty() {
            in_quotes = true;
        } else if ch == ',' {
            fields.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    fields.push(current.trim().to_string());
    fields
}

/// Parses `schtasks /Query` stdout (both `/FO LIST` and `/FO CSV`, with or without `/V` or `/NH`)
/// into `(installed, running)`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn parse_schtasks_query_output(stdout: &str) -> (bool, bool) {
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() || lines[0].to_ascii_uppercase().starts_with("ERROR:") {
        return (false, false);
    }

    // CSV format (`/FO CSV`, `/FO CSV /V`, or `/FO CSV /NH`).
    if lines[0].starts_with('"') {
        let first_cols = parse_csv_line(lines[0]);
        let task_header_idx = first_cols
            .iter()
            .position(|c| c.eq_ignore_ascii_case("TaskName"));
        let status_header_idx = first_cols
            .iter()
            .position(|c| c.eq_ignore_ascii_case("Status"));

        if let Some(status_idx) = status_header_idx {
            let mut installed = false;
            let mut running = false;
            for line in lines.iter().skip(1) {
                if line.to_ascii_uppercase().starts_with("ERROR:") {
                    continue;
                }
                let cols = parse_csv_line(line);
                let has_task = task_header_idx
                    .and_then(|idx| cols.get(idx))
                    .map(|v| !v.is_empty())
                    .unwrap_or(!cols.is_empty() && !cols[0].is_empty());
                if !has_task {
                    continue;
                }
                installed = true;
                if cols
                    .get(status_idx)
                    .is_some_and(|st| st.eq_ignore_ascii_case("Running"))
                {
                    running = true;
                }
            }
            return (installed, running);
        }

        // Headerless CSV (`/FO CSV /NH`).
        let mut installed = false;
        let mut running = false;
        for line in &lines {
            if !line.starts_with('"') {
                continue;
            }
            let cols = parse_csv_line(line);
            if cols.len() < 3 || cols[0].is_empty() {
                continue;
            }
            installed = true;
            let status_idx = if cols.len() >= 4 && cols[1].starts_with('\\') {
                3
            } else {
                2
            };
            if cols
                .get(status_idx)
                .is_some_and(|st| st.eq_ignore_ascii_case("Running"))
            {
                running = true;
            }
        }
        return (installed, running);
    }

    // LIST format (`/FO LIST` or `/FO LIST /V`).
    let mut installed = false;
    let mut running = false;
    for line in &lines {
        let Some((raw_key, raw_val)) = line.split_once(':') else {
            continue;
        };
        let key = raw_key.trim();
        let val = raw_val.trim();
        if key.eq_ignore_ascii_case("TaskName") && !val.is_empty() {
            installed = true;
        } else if key.eq_ignore_ascii_case("Status") && !val.is_empty() {
            installed = true;
            if val.eq_ignore_ascii_case("Running") {
                running = true;
            }
        }
    }
    (installed, running)
}

// ============================================================================
// Live Daemon Probe (`daemon.status` over `connector.sock` / `connector.addr`)
// ============================================================================

fn resolve_probe_socket(
    explicit_socket: Option<&Path>,
    state_dir: Option<&Path>,
    home: &Path,
    explicit_home: bool,
) -> PathBuf {
    if let Some(s) = explicit_socket {
        return s.to_path_buf();
    }
    if let Some(sd) = state_dir {
        return sd.join(DEFAULT_SOCKET_FILENAME);
    }
    if explicit_home {
        let v2 = home
            .join(".config")
            .join("hyphae")
            .join(DEFAULT_SOCKET_FILENAME);
        let v1 = home
            .join(".config")
            .join("hyphae")
            .join("state")
            .join(DEFAULT_SOCKET_FILENAME);
        if !v2.exists() && v1.exists() {
            return v1;
        }
        return v2;
    }
    default_socket_path()
}

fn probe_daemon_once(socket_path: &Path) -> DaemonProbe {
    let resp = daemon_rpc_sync(
        socket_path,
        &json!({ "type": "daemon.status" }),
        DAEMON_RPC_TIMEOUT,
    );
    if resp.ok {
        let node_id = resp
            .result
            .as_ref()
            .and_then(|m| m.get("nodeId").or_else(|| m.get("connectorId")))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let pid = resp
            .result
            .as_ref()
            .and_then(|m| m.get("pid"))
            .and_then(|v| v.as_u64());
        DaemonProbe {
            alive: true,
            socket: socket_path.display().to_string(),
            node_id,
            pid,
        }
    } else {
        DaemonProbe {
            alive: false,
            socket: socket_path.display().to_string(),
            node_id: None,
            pid: None,
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn wait_for_daemon_alive(socket_path: &Path, timeout: Duration) -> DaemonProbe {
    let deadline = Instant::now() + timeout;
    loop {
        let probe = probe_daemon_once(socket_path);
        if probe.alive || Instant::now() >= deadline {
            return probe;
        }
        thread::sleep(DAEMON_POLL_INTERVAL);
    }
}

// Keep `thread` / `Instant` / `DAEMON_*` used across non-macOS/Linux/Windows targets without dead-code warnings.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn _keep_poll_helpers_used() {
    let _ = (
        DAEMON_READY_TIMEOUT,
        DAEMON_POLL_INTERVAL,
        Instant::now(),
        thread::yield_now,
    );
}

fn resolve_service_bin(explicit: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    std::env::current_exe().map_err(|e| format!("failed to resolve current hyp binary path: {e}"))
}

fn build_spec(
    bin: Option<&Path>,
    home: &Path,
    state_dir_arg: Option<&Path>,
    explicit_state_dir: bool,
    config_arg: Option<&Path>,
    socket_arg: Option<&Path>,
) -> Result<ServiceSpec, String> {
    let bin_path = resolve_service_bin(bin)?;
    let state_dir = resolve_state_dir(state_dir_arg, config_arg, Some(home));
    let logs_dir = default_daemon_logs_dir(&state_dir);
    let current_path = std::env::var("PATH").ok();
    let path_env = build_service_path_env(current_path.as_deref(), bin_path.parent());
    let explicit_backend_env = std::env::var("HYPHAE_SECRET_BACKEND")
        .ok()
        .and_then(|s| hyp_crypto::keystore::parse_backend(&s))
        .map(|b| b.as_str().to_string());
    let active_backend =
        hyp_crypto::keystore::detect_backend_with(&state_dir, explicit_backend_env.as_deref());
    let secret_backend = if let Some(explicit) = explicit_backend_env {
        Some(explicit)
    } else if active_backend == hyp_crypto::keystore::SecretBackend::File {
        Some(active_backend.as_str().to_string())
    } else {
        None
    };
    let extra_env = collect_secret_backend_service_env(active_backend, |k| std::env::var(k).ok());
    #[cfg(target_os = "windows")]
    let user_id = {
        let domain = std::env::var("USERDOMAIN").ok();
        let username = std::env::var("USERNAME").ok();
        format_windows_user_id(domain.as_deref(), username.as_deref())
    };
    #[cfg(not(target_os = "windows"))]
    let user_id = None;
    Ok(ServiceSpec {
        bin_path,
        state_dir,
        explicit_state_dir,
        config_path: config_arg.map(Path::to_path_buf),
        socket_path: socket_arg.map(Path::to_path_buf),
        logs_dir,
        path_env,
        secret_backend,
        extra_env,
        user_id,
    })
}

// ============================================================================
// Platform Backends
// ============================================================================

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceActionReport {
    action: &'static str,
    manager: &'static str,
    service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit_path: Option<String>,
    installed: bool,
    loaded: bool,
    daemon: DaemonProbe,
    detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    next: Vec<String>,
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::fs;
    use std::process::Command;

    pub const MANAGER_NAME: &str = "launchd";

    fn current_uid() -> Result<String, String> {
        let out = Command::new("id")
            .arg("-u")
            .output()
            .map_err(|e| format!("failed to determine current uid via `id -u`: {e}"))?;
        if !out.status.success() {
            return Err("`id -u` returned non-zero status".to_string());
        }
        let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if uid.is_empty() || !uid.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("unexpected uid output from `id -u`: '{uid}'"));
        }
        Ok(uid)
    }

    fn gui_domain(uid: &str) -> String {
        format!("gui/{uid}")
    }

    fn service_target(uid: &str) -> String {
        format!("gui/{uid}/{MACOS_LAUNCHAGENT_LABEL}")
    }

    fn run_launchctl(args: &[&str]) -> Result<LaunchctlOutput, String> {
        let out = Command::new("launchctl")
            .args(args)
            .output()
            .map_err(|e| format!("failed to execute launchctl: {e}"))?;
        Ok(LaunchctlOutput {
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }

    fn is_loaded(uid: &str) -> bool {
        let target = service_target(uid);
        launchd_is_loaded_via(&target, &mut run_launchctl)
    }

    pub fn install(
        spec: &ServiceSpec,
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "install")?;
        ensure_dir(&spec.state_dir, true)?;
        ensure_dir(&spec.logs_dir, true)?;

        let plist_path = macos_plist_path(home);
        let plist_xml = render_macos_plist(spec);
        write_atomic_file(&plist_path, plist_xml.as_bytes(), false)?;

        let uid = current_uid()?;
        let domain = gui_domain(&uid);
        let target = service_target(&uid);
        let plist_str = plist_path.display().to_string();

        launchd_install_via(
            &domain,
            &target,
            &plist_str,
            LaunchdRetryPolicy::default(),
            &mut run_launchctl,
            &mut thread::sleep,
        )?;

        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        let detail = if probe.alive {
            format!("LaunchAgent {MACOS_LAUNCHAGENT_LABEL} installed and running")
        } else {
            format!(
                "LaunchAgent {MACOS_LAUNCHAGENT_LABEL} loaded (socket not ready within {}s; check {})",
                DAEMON_READY_TIMEOUT.as_secs(),
                spec.logs_dir.join("daemon.err.log").display()
            )
        };

        Ok(ServiceActionReport {
            action: "install",
            manager: MANAGER_NAME,
            service: MACOS_LAUNCHAGENT_LABEL.to_string(),
            unit_path: Some(plist_str),
            installed: true,
            loaded: true,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next: vec!["hyp service status".to_string(), "hyp doctor".to_string()],
        })
    }

    pub fn uninstall(
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "uninstall")?;
        let uid = current_uid()?;
        let target = service_target(&uid);
        launchd_stop_via(
            &target,
            LaunchdRetryPolicy::default(),
            &mut run_launchctl,
            &mut thread::sleep,
        );

        let plist_path = macos_plist_path(home);
        if plist_path.exists() {
            fs::remove_file(&plist_path)
                .map_err(|e| format!("failed to remove {}: {e}", plist_path.display()))?;
        }

        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "uninstall",
            manager: MANAGER_NAME,
            service: MACOS_LAUNCHAGENT_LABEL.to_string(),
            unit_path: Some(plist_path.display().to_string()),
            installed: false,
            loaded: false,
            daemon: probe,
            detail: format!("Uninstalled LaunchAgent {MACOS_LAUNCHAGENT_LABEL}"),
            warnings: Vec::new(),
            next: vec!["hyp service install".to_string()],
        })
    }

    pub fn start(
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "start")?;
        let plist_path = macos_plist_path(home);
        if !plist_path.exists() {
            return Err(format!(
                "LaunchAgent plist not found at {} (run `hyp service install` first)",
                plist_path.display()
            ));
        }
        let uid = current_uid()?;
        let domain = gui_domain(&uid);
        let target = service_target(&uid);
        let plist_str = plist_path.display().to_string();

        launchd_start_via(
            &domain,
            &target,
            &plist_str,
            LaunchdRetryPolicy::default(),
            &mut run_launchctl,
            &mut thread::sleep,
        )?;

        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        let detail = if probe.alive {
            format!("LaunchAgent {MACOS_LAUNCHAGENT_LABEL} is running")
        } else {
            format!("Started LaunchAgent {MACOS_LAUNCHAGENT_LABEL} (socket still initializing)")
        };
        Ok(ServiceActionReport {
            action: "start",
            manager: MANAGER_NAME,
            service: MACOS_LAUNCHAGENT_LABEL.to_string(),
            unit_path: Some(plist_str),
            installed: true,
            loaded: true,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn stop(
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "stop")?;
        let uid = current_uid()?;
        let target = service_target(&uid);
        launchd_stop_via(
            &target,
            LaunchdRetryPolicy::default(),
            &mut run_launchctl,
            &mut thread::sleep,
        );

        let plist_path = macos_plist_path(home);
        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "stop",
            manager: MANAGER_NAME,
            service: MACOS_LAUNCHAGENT_LABEL.to_string(),
            unit_path: Some(plist_path.display().to_string()),
            installed: plist_path.exists(),
            loaded: false,
            daemon: probe,
            detail: format!("Stopped LaunchAgent {MACOS_LAUNCHAGENT_LABEL}"),
            warnings: Vec::new(),
            next: vec!["hyp service start".to_string()],
        })
    }

    pub fn restart(
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "restart")?;
        let plist_path = macos_plist_path(home);
        if !plist_path.exists() {
            return Err(format!(
                "LaunchAgent plist not found at {} (run `hyp service install` first)",
                plist_path.display()
            ));
        }
        let uid = current_uid()?;
        let domain = gui_domain(&uid);
        let target = service_target(&uid);
        let plist_str = plist_path.display().to_string();

        launchd_restart_via(
            &domain,
            &target,
            &plist_str,
            LaunchdRetryPolicy::default(),
            &mut run_launchctl,
            &mut thread::sleep,
        )
        .map_err(|e| format!("launchctl restart failed: {e}"))?;

        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        let detail = if probe.alive {
            format!("Restarted LaunchAgent {MACOS_LAUNCHAGENT_LABEL} (daemon responding)")
        } else {
            format!("Restarted LaunchAgent {MACOS_LAUNCHAGENT_LABEL} (socket still initializing)")
        };
        Ok(ServiceActionReport {
            action: "restart",
            manager: MANAGER_NAME,
            service: MACOS_LAUNCHAGENT_LABEL.to_string(),
            unit_path: Some(plist_str),
            installed: true,
            loaded: true,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn status(
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        let plist_path = macos_plist_path(home);
        let installed = plist_path.exists();
        let loaded = if service_control_disabled(home).is_some() {
            false
        } else {
            current_uid().map(|u| is_loaded(&u)).unwrap_or(false)
        };
        let probe = probe_daemon_once(socket);
        let detail = if probe.alive && installed {
            format!("Running (LaunchAgent {MACOS_LAUNCHAGENT_LABEL})")
        } else if probe.alive {
            "Daemon running (foreground / unmanaged; LaunchAgent not installed)".to_string()
        } else if installed && loaded {
            format!(
                "LaunchAgent {MACOS_LAUNCHAGENT_LABEL} loaded, but daemon socket not responding"
            )
        } else if installed {
            format!("LaunchAgent {MACOS_LAUNCHAGENT_LABEL} installed (stopped)")
        } else {
            "Not installed and daemon is not running".to_string()
        };
        let next = if probe.alive {
            vec!["hyp status".to_string(), "hyp doctor".to_string()]
        } else if installed {
            vec!["hyp service start".to_string()]
        } else {
            vec!["hyp service install".to_string()]
        };
        Ok(ServiceActionReport {
            action: "status",
            manager: MANAGER_NAME,
            service: MACOS_LAUNCHAGENT_LABEL.to_string(),
            unit_path: Some(plist_path.display().to_string()),
            installed,
            loaded,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next,
        })
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::fs;
    use std::process::Command;

    pub const MANAGER_NAME: &str = "systemd-user";

    fn run_systemctl(args: &[&str]) -> Result<std::process::Output, String> {
        Command::new("systemctl")
            .arg("--user")
            .args(args)
            .output()
            .map_err(|e| format!("systemctl --user unavailable: {e}"))
    }

    fn check_systemctl_ok(out: &std::process::Output, verb: &str) -> Result<(), String> {
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(format!(
            "systemctl --user {verb} failed: {}",
            if stderr.is_empty() {
                "unknown error"
            } else {
                &stderr
            }
        ))
    }

    fn unit_path_for(home: &Path, explicit_home: bool) -> PathBuf {
        let xdg = resolve_xdg_config_home(explicit_home);
        linux_systemd_unit_path_with_xdg(home, xdg.as_deref())
    }

    fn is_isolated_test_home(home: &Path, explicit_home: bool) -> bool {
        if std::env::var("HYPHAE_TEST_CHECK_LINGER").ok().as_deref() == Some("1") {
            return false;
        }
        if explicit_home {
            return true;
        }
        let sys_tmp = std::env::temp_dir();
        home.starts_with(&sys_tmp) || home.starts_with("/tmp")
    }

    /// Best-effort check for systemd user lingering (`loginctl show-user <user> -p Linger`).
    /// If disabled, attempts `loginctl enable-linger <user>`; if that requires root privileges,
    /// returns an actionable `(warning, next_step)` pair so headless Linux daemons don't die on SSH logout.
    fn check_and_enable_linger(
        home: &Path,
        explicit_home: bool,
    ) -> (Option<String>, Option<String>) {
        if is_isolated_test_home(home, explicit_home) {
            return (None, None);
        }
        let user = std::env::var("USER")
            .ok()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .or_else(|| {
                Command::new("id")
                    .arg("-un")
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .filter(|u| !u.is_empty())
            });
        let Some(user) = user else {
            return (None, None);
        };
        let Ok(show_out) = Command::new("loginctl")
            .args(["show-user", &user, "-p", "Linger"])
            .output()
        else {
            return (None, None);
        };
        if !show_out.status.success() {
            return (None, None);
        }
        let stdout = String::from_utf8_lossy(&show_out.stdout);
        if parse_loginctl_linger(&stdout) != Some(false) {
            return (None, None);
        }
        // Linger=no -> try enabling without sudo first.
        if let Ok(enable_out) = Command::new("loginctl")
            .args(["enable-linger", &user])
            .output()
        {
            if enable_out.status.success() {
                return (None, None);
            }
        }
        (
            Some(format!(
                "systemd user lingering is disabled for '{user}'; the background daemon may stop when your SSH session logs out."
            )),
            Some(format!("sudo loginctl enable-linger {user}")),
        )
    }

    pub fn install(
        spec: &ServiceSpec,
        home: &Path,
        socket: &Path,
        explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "install")?;
        ensure_dir(&spec.state_dir, true)?;
        ensure_dir(&spec.logs_dir, true)?;

        let unit_path = unit_path_for(home, explicit_home);
        let unit_content = render_linux_systemd_unit(spec);
        write_atomic_file(&unit_path, unit_content.as_bytes(), false)?;

        let reload = run_systemctl(&["daemon-reload"])?;
        check_systemctl_ok(&reload, "daemon-reload")?;
        let _ = run_systemctl(&["reset-failed", LINUX_SYSTEMD_UNIT]);
        let enable = run_systemctl(&["enable", LINUX_SYSTEMD_UNIT])?;
        check_systemctl_ok(&enable, "enable")?;
        let restart = run_systemctl(&["restart", LINUX_SYSTEMD_UNIT])?;
        check_systemctl_ok(&restart, "restart")?;

        let mut warnings = Vec::new();
        let mut next = vec!["hyp service status".to_string(), "hyp doctor".to_string()];
        let (linger_warn, linger_next) = check_and_enable_linger(home, explicit_home);
        if let Some(w) = linger_warn {
            warnings.push(w);
        }
        if let Some(n) = linger_next {
            next.insert(0, n);
        }

        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        let detail = if probe.alive {
            format!("systemd user service {LINUX_SYSTEMD_UNIT} installed and running")
        } else {
            format!("systemd user service {LINUX_SYSTEMD_UNIT} enabled (socket still initializing)")
        };

        Ok(ServiceActionReport {
            action: "install",
            manager: MANAGER_NAME,
            service: LINUX_SYSTEMD_UNIT.to_string(),
            unit_path: Some(unit_path.display().to_string()),
            installed: true,
            loaded: true,
            daemon: probe,
            detail,
            warnings,
            next,
        })
    }

    pub fn uninstall(
        home: &Path,
        socket: &Path,
        explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "uninstall")?;
        let _ = run_systemctl(&["disable", "--now", LINUX_SYSTEMD_UNIT]);
        let unit_path = unit_path_for(home, explicit_home);
        if unit_path.exists() {
            fs::remove_file(&unit_path)
                .map_err(|e| format!("failed to remove {}: {e}", unit_path.display()))?;
        }
        let _ = run_systemctl(&["daemon-reload"]);
        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "uninstall",
            manager: MANAGER_NAME,
            service: LINUX_SYSTEMD_UNIT.to_string(),
            unit_path: Some(unit_path.display().to_string()),
            installed: false,
            loaded: false,
            daemon: probe,
            detail: format!("Uninstalled systemd user service {LINUX_SYSTEMD_UNIT}"),
            warnings: Vec::new(),
            next: vec!["hyp service install".to_string()],
        })
    }

    pub fn start(
        home: &Path,
        socket: &Path,
        explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "start")?;
        let unit_path = unit_path_for(home, explicit_home);
        if !unit_path.exists() {
            return Err(format!(
                "systemd unit not found at {} (run `hyp service install` first)",
                unit_path.display()
            ));
        }
        let _ = run_systemctl(&["daemon-reload"]);
        let _ = run_systemctl(&["reset-failed", LINUX_SYSTEMD_UNIT]);
        let out = run_systemctl(&["start", LINUX_SYSTEMD_UNIT])?;
        check_systemctl_ok(&out, "start")?;
        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        Ok(ServiceActionReport {
            action: "start",
            manager: MANAGER_NAME,
            service: LINUX_SYSTEMD_UNIT.to_string(),
            unit_path: Some(unit_path.display().to_string()),
            installed: true,
            loaded: true,
            daemon: probe,
            detail: format!("Started systemd user service {LINUX_SYSTEMD_UNIT}"),
            warnings: Vec::new(),
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn stop(
        home: &Path,
        socket: &Path,
        explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "stop")?;
        let unit_path = unit_path_for(home, explicit_home);
        let _ = run_systemctl(&["stop", LINUX_SYSTEMD_UNIT]);
        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "stop",
            manager: MANAGER_NAME,
            service: LINUX_SYSTEMD_UNIT.to_string(),
            unit_path: Some(unit_path.display().to_string()),
            installed: unit_path.exists(),
            loaded: false,
            daemon: probe,
            detail: format!("Stopped systemd user service {LINUX_SYSTEMD_UNIT}"),
            warnings: Vec::new(),
            next: vec!["hyp service start".to_string()],
        })
    }

    pub fn restart(
        home: &Path,
        socket: &Path,
        explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "restart")?;
        let unit_path = unit_path_for(home, explicit_home);
        if !unit_path.exists() {
            return Err(format!(
                "systemd unit not found at {} (run `hyp service install` first)",
                unit_path.display()
            ));
        }
        let _ = run_systemctl(&["daemon-reload"]);
        let _ = run_systemctl(&["reset-failed", LINUX_SYSTEMD_UNIT]);
        let out = run_systemctl(&["restart", LINUX_SYSTEMD_UNIT])?;
        check_systemctl_ok(&out, "restart")?;
        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        Ok(ServiceActionReport {
            action: "restart",
            manager: MANAGER_NAME,
            service: LINUX_SYSTEMD_UNIT.to_string(),
            unit_path: Some(unit_path.display().to_string()),
            installed: true,
            loaded: true,
            daemon: probe,
            detail: format!("Restarted systemd user service {LINUX_SYSTEMD_UNIT}"),
            warnings: Vec::new(),
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn status(
        home: &Path,
        socket: &Path,
        explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        let unit_path = unit_path_for(home, explicit_home);
        let installed = unit_path.exists();
        let loaded = if service_control_disabled(home).is_some() {
            false
        } else {
            run_systemctl(&["is-active", "--quiet", LINUX_SYSTEMD_UNIT])
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        let probe = probe_daemon_once(socket);
        let detail = if probe.alive && installed {
            format!("Running (systemd user {LINUX_SYSTEMD_UNIT})")
        } else if probe.alive {
            "Daemon running (foreground / unmanaged; systemd user unit not installed)".to_string()
        } else if installed && loaded {
            format!(
                "systemd user unit {LINUX_SYSTEMD_UNIT} active, but daemon socket not responding"
            )
        } else if installed {
            format!("systemd user unit {LINUX_SYSTEMD_UNIT} installed (stopped)")
        } else {
            "Not installed and daemon is not running".to_string()
        };
        let next = if probe.alive {
            vec!["hyp status".to_string(), "hyp doctor".to_string()]
        } else if installed {
            vec!["hyp service start".to_string()]
        } else {
            vec!["hyp service install".to_string()]
        };
        Ok(ServiceActionReport {
            action: "status",
            manager: MANAGER_NAME,
            service: LINUX_SYSTEMD_UNIT.to_string(),
            unit_path: Some(unit_path.display().to_string()),
            installed,
            loaded,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next,
        })
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::fs;
    use std::process::Command;

    pub const MANAGER_NAME: &str = "schtasks";

    fn run_schtasks(args: &[String]) -> Result<std::process::Output, String> {
        Command::new("schtasks")
            .args(args)
            .output()
            .map_err(|e| format!("failed to execute schtasks: {e}"))
    }

    fn check_schtasks_ok(out: &std::process::Output, verb: &str) -> Result<(), String> {
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            "unknown error".to_string()
        };
        Err(format!("schtasks {verb} failed ({}): {detail}", out.status))
    }

    fn query_task(task_name: &str) -> (bool, bool) {
        let args = build_schtasks_query_args(task_name);
        match run_schtasks(&args) {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                parse_schtasks_query_output(&stdout)
            }
            _ => (false, false),
        }
    }

    fn end_task_and_wait(task_name: &str) {
        let _ = run_schtasks(&build_schtasks_end_args(task_name));
        for attempt in 0..20 {
            let (_installed, running) = query_task(task_name);
            if !running {
                return;
            }
            if attempt + 1 < 20 {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    pub fn install(
        spec: &ServiceSpec,
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "install")?;
        ensure_dir(&spec.state_dir, true)?;
        ensure_dir(&spec.logs_dir, true)?;

        let xml_path = windows_task_xml_path(&spec.state_dir);
        let xml_content = windows_task_xml(spec);
        let xml_bytes = encode_utf16le_bom(&xml_content);
        write_atomic_file(&xml_path, &xml_bytes, true)?;

        end_task_and_wait(WINDOWS_TASK_NAME);

        let create_args = build_schtasks_create_args(WINDOWS_TASK_NAME, &xml_path);
        let create_out = run_schtasks(&create_args)?;
        check_schtasks_ok(&create_out, "/Create")?;

        let run_args = build_schtasks_run_args(WINDOWS_TASK_NAME);
        let run_out = run_schtasks(&run_args)?;
        check_schtasks_ok(&run_out, "/Run")?;

        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        let detail = if probe.alive {
            format!("Windows scheduled task {WINDOWS_TASK_NAME} installed and running")
        } else {
            format!(
                "Windows scheduled task {WINDOWS_TASK_NAME} created and started (socket not ready within {}s)",
                DAEMON_READY_TIMEOUT.as_secs()
            )
        };

        Ok(ServiceActionReport {
            action: "install",
            manager: MANAGER_NAME,
            service: WINDOWS_TASK_NAME.to_string(),
            unit_path: Some(xml_path.display().to_string()),
            installed: true,
            loaded: true,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next: vec!["hyp service status".to_string(), "hyp doctor".to_string()],
        })
    }

    pub fn uninstall(
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "uninstall")?;
        end_task_and_wait(WINDOWS_TASK_NAME);
        let _ = run_schtasks(&build_schtasks_delete_args(WINDOWS_TASK_NAME));

        let state_dir = resolve_state_dir(None, None, Some(home));
        let xml_path = windows_task_xml_path(&state_dir);
        if xml_path.exists() {
            fs::remove_file(&xml_path)
                .map_err(|e| format!("failed to remove {}: {e}", xml_path.display()))?;
        }

        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "uninstall",
            manager: MANAGER_NAME,
            service: WINDOWS_TASK_NAME.to_string(),
            unit_path: Some(xml_path.display().to_string()),
            installed: false,
            loaded: false,
            daemon: probe,
            detail: format!("Uninstalled Windows scheduled task {WINDOWS_TASK_NAME}"),
            warnings: Vec::new(),
            next: vec!["hyp service install".to_string()],
        })
    }

    pub fn start(
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "start")?;
        let state_dir = resolve_state_dir(None, None, Some(home));
        let xml_path = windows_task_xml_path(&state_dir);
        let (installed, _running) = query_task(WINDOWS_TASK_NAME);
        if !installed {
            return Err(format!(
                "Windows scheduled task {WINDOWS_TASK_NAME} is not installed (run `hyp service install` first)"
            ));
        }

        let run_out = run_schtasks(&build_schtasks_run_args(WINDOWS_TASK_NAME))?;
        check_schtasks_ok(&run_out, "/Run")?;

        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        let detail = if probe.alive {
            format!("Windows scheduled task {WINDOWS_TASK_NAME} is running")
        } else {
            format!(
                "Started Windows scheduled task {WINDOWS_TASK_NAME} (socket still initializing)"
            )
        };

        Ok(ServiceActionReport {
            action: "start",
            manager: MANAGER_NAME,
            service: WINDOWS_TASK_NAME.to_string(),
            unit_path: Some(xml_path.display().to_string()),
            installed: true,
            loaded: true,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn stop(
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "stop")?;
        let state_dir = resolve_state_dir(None, None, Some(home));
        let xml_path = windows_task_xml_path(&state_dir);
        end_task_and_wait(WINDOWS_TASK_NAME);
        let (installed, _running) = query_task(WINDOWS_TASK_NAME);
        let probe = probe_daemon_once(socket);

        Ok(ServiceActionReport {
            action: "stop",
            manager: MANAGER_NAME,
            service: WINDOWS_TASK_NAME.to_string(),
            unit_path: Some(xml_path.display().to_string()),
            installed: installed || xml_path.exists(),
            loaded: false,
            daemon: probe,
            detail: format!("Stopped Windows scheduled task {WINDOWS_TASK_NAME}"),
            warnings: Vec::new(),
            next: vec!["hyp service start".to_string()],
        })
    }

    pub fn restart(
        home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        ensure_service_control_allowed(home, "restart")?;
        let state_dir = resolve_state_dir(None, None, Some(home));
        let xml_path = windows_task_xml_path(&state_dir);
        let (installed, _running) = query_task(WINDOWS_TASK_NAME);
        if !installed {
            return Err(format!(
                "Windows scheduled task {WINDOWS_TASK_NAME} is not installed (run `hyp service install` first)"
            ));
        }

        end_task_and_wait(WINDOWS_TASK_NAME);
        let run_out = run_schtasks(&build_schtasks_run_args(WINDOWS_TASK_NAME))?;
        check_schtasks_ok(&run_out, "/Run")?;

        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        let detail = if probe.alive {
            format!("Restarted Windows scheduled task {WINDOWS_TASK_NAME} (daemon responding)")
        } else {
            format!(
                "Restarted Windows scheduled task {WINDOWS_TASK_NAME} (socket still initializing)"
            )
        };

        Ok(ServiceActionReport {
            action: "restart",
            manager: MANAGER_NAME,
            service: WINDOWS_TASK_NAME.to_string(),
            unit_path: Some(xml_path.display().to_string()),
            installed: true,
            loaded: true,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn status(
        home: &Path,
        socket: &Path,
        explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        let state_dir = resolve_state_dir(None, None, Some(home));
        let xml_path = windows_task_xml_path(&state_dir);
        let xml_exists = xml_path.exists();
        let (installed, loaded) = if service_control_disabled(home).is_some() {
            (xml_exists, false)
        } else if explicit_home && !xml_exists {
            (false, false)
        } else {
            query_task(WINDOWS_TASK_NAME)
        };
        let probe = probe_daemon_once(socket);
        let detail = if probe.alive && installed {
            format!("Running (Windows Task Scheduler {WINDOWS_TASK_NAME})")
        } else if probe.alive {
            "Daemon running (foreground / unmanaged; Windows scheduled task not installed)"
                .to_string()
        } else if installed && loaded {
            format!(
                "Windows scheduled task {WINDOWS_TASK_NAME} running, but daemon socket not responding"
            )
        } else if installed {
            format!("Windows scheduled task {WINDOWS_TASK_NAME} installed (stopped)")
        } else {
            "Not installed and daemon is not running".to_string()
        };
        let next = if probe.alive {
            vec!["hyp status".to_string(), "hyp doctor".to_string()]
        } else if installed {
            vec!["hyp service start".to_string()]
        } else {
            vec!["hyp service install".to_string()]
        };

        Ok(ServiceActionReport {
            action: "status",
            manager: MANAGER_NAME,
            service: WINDOWS_TASK_NAME.to_string(),
            unit_path: Some(xml_path.display().to_string()),
            installed,
            loaded,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next,
        })
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod platform {
    use super::*;

    pub const MANAGER_NAME: &str = "manual";

    fn guidance_detail(action: &str) -> String {
        _keep_poll_helpers_used();
        format!(
            "Background OS service manager for `{action}` is not available on this OS; run `hyp daemon` under your process supervisor."
        )
    }

    fn guidance_next() -> Vec<String> {
        vec!["hyp daemon".to_string(), "hyp status".to_string()]
    }

    pub fn install(
        _spec: &ServiceSpec,
        _home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "install",
            manager: MANAGER_NAME,
            service: "hyp-daemon".to_string(),
            unit_path: None,
            installed: false,
            loaded: probe.alive,
            daemon: probe,
            detail: guidance_detail("install"),
            warnings: Vec::new(),
            next: guidance_next(),
        })
    }

    pub fn uninstall(
        _home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "uninstall",
            manager: MANAGER_NAME,
            service: "hyp-daemon".to_string(),
            unit_path: None,
            installed: false,
            loaded: probe.alive,
            daemon: probe,
            detail: guidance_detail("uninstall"),
            warnings: Vec::new(),
            next: guidance_next(),
        })
    }

    pub fn start(
        _home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "start",
            manager: MANAGER_NAME,
            service: "hyp-daemon".to_string(),
            unit_path: None,
            installed: false,
            loaded: probe.alive,
            daemon: probe,
            detail: guidance_detail("start"),
            warnings: Vec::new(),
            next: guidance_next(),
        })
    }

    pub fn stop(
        _home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "stop",
            manager: MANAGER_NAME,
            service: "hyp-daemon".to_string(),
            unit_path: None,
            installed: false,
            loaded: probe.alive,
            daemon: probe,
            detail: guidance_detail("stop"),
            warnings: Vec::new(),
            next: guidance_next(),
        })
    }

    pub fn restart(
        _home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        let probe = probe_daemon_once(socket);
        Ok(ServiceActionReport {
            action: "restart",
            manager: MANAGER_NAME,
            service: "hyp-daemon".to_string(),
            unit_path: None,
            installed: false,
            loaded: probe.alive,
            daemon: probe,
            detail: guidance_detail("restart"),
            warnings: Vec::new(),
            next: guidance_next(),
        })
    }

    pub fn status(
        _home: &Path,
        socket: &Path,
        _explicit_home: bool,
    ) -> Result<ServiceActionReport, String> {
        let probe = probe_daemon_once(socket);
        let detail = if probe.alive {
            "Daemon running".to_string()
        } else {
            guidance_detail("status")
        };
        Ok(ServiceActionReport {
            action: "status",
            manager: MANAGER_NAME,
            service: "hyp-daemon".to_string(),
            unit_path: None,
            installed: false,
            loaded: probe.alive,
            daemon: probe,
            detail,
            warnings: Vec::new(),
            next: guidance_next(),
        })
    }
}

// ============================================================================
// Public Entrypoints (`hyp service ...`, `hyp onboard`, & `hyp update` Hooks)
// ============================================================================

/// Checks whether a managed OS background daemon service is installed (and restarts it cleanly
/// after a `hyp update` binary swap). Never panics; returns a structured `ServiceRestartOutcome`.
pub fn restart_if_installed(
    home_override: Option<&Path>,
    state_dir_override: Option<&Path>,
) -> ServiceRestartOutcome {
    let Some(resolved_home) = resolve_home_dir(home_override) else {
        return ServiceRestartOutcome {
            attempted: false,
            installed: false,
            restarted: false,
            skipped: true,
            skip_reason: Some("missing_home".to_string()),
            error: None,
            detail: "Could not resolve home directory to inspect background service.".to_string(),
        };
    };
    if let Some(reason) = service_control_disabled(&resolved_home) {
        return ServiceRestartOutcome {
            attempted: false,
            installed: false,
            restarted: false,
            skipped: true,
            skip_reason: Some("service_control_disabled".to_string()),
            error: None,
            detail: format!("Skipped background service restart ({reason})."),
        };
    }
    if env_flag_enabled("HYPHAE_NO_SERVICE_RESTART") {
        return ServiceRestartOutcome {
            attempted: false,
            installed: false,
            restarted: false,
            skipped: true,
            skip_reason: Some("env_disabled".to_string()),
            error: None,
            detail: "Skipped background service restart (HYPHAE_NO_SERVICE_RESTART is set)."
                .to_string(),
        };
    }
    let explicit_home = home_override.is_some();
    let probe_sock = resolve_probe_socket(None, state_dir_override, &resolved_home, explicit_home);

    let status = match platform::status(&resolved_home, &probe_sock, explicit_home) {
        Ok(st) => st,
        Err(e) => {
            return ServiceRestartOutcome {
                attempted: false,
                installed: false,
                restarted: false,
                skipped: false,
                skip_reason: None,
                error: Some(e.clone()),
                detail: format!("Failed to inspect background service status: {e}"),
            };
        }
    };

    if !status.installed {
        if status.daemon.alive {
            return ServiceRestartOutcome {
                attempted: false,
                installed: false,
                restarted: false,
                skipped: true,
                skip_reason: Some("unmanaged_daemon".to_string()),
                error: None,
                detail: "A foreground/unmanaged daemon is running without an installed OS service; restart it to load the new binary.".to_string(),
            };
        }
        return ServiceRestartOutcome {
            attempted: false,
            installed: false,
            restarted: false,
            skipped: false,
            skip_reason: Some("not_installed".to_string()),
            error: None,
            detail: "No managed background service installed.".to_string(),
        };
    }

    match platform::restart(&resolved_home, &probe_sock, explicit_home) {
        Ok(report) => ServiceRestartOutcome {
            attempted: true,
            installed: true,
            restarted: true,
            skipped: false,
            skip_reason: None,
            error: None,
            detail: report.detail,
        },
        Err(e) => ServiceRestartOutcome {
            attempted: true,
            installed: true,
            restarted: false,
            skipped: false,
            skip_reason: None,
            error: Some(e.clone()),
            detail: format!("Background service restart failed: {e}"),
        },
    }
}

/// Installs and starts the default OS background daemon service during `hyp onboard`.
/// Never panics or fails onboarding fatally — callers surface `warning` cleanly if unavailable.
pub fn install_and_start_default(
    bin_path: &Path,
    home: &Path,
    state_dir: &Path,
) -> AutoStartResult {
    if let Some(reason) = service_control_disabled(home) {
        return AutoStartResult {
            started: false,
            installed: false,
            manager: platform::MANAGER_NAME,
            service: None,
            detail: format!("Skipped background service install ({reason})"),
            warning: None,
        };
    }
    let explicit_state = state_dir != default_config_dir(Some(home));
    let spec = match build_spec(
        Some(bin_path),
        home,
        Some(state_dir),
        explicit_state,
        None,
        None,
    ) {
        Ok(s) => s,
        Err(e) => {
            return AutoStartResult {
                started: false,
                installed: false,
                manager: platform::MANAGER_NAME,
                service: None,
                detail: "Skipped background service install".to_string(),
                warning: Some(format!(
                    "Could not prepare background daemon service ({e}); start manually with `hyp daemon`."
                )),
            };
        }
    };
    let socket = default_socket_path();
    match platform::install(&spec, home, &socket, false) {
        Ok(report) => {
            let started = report.daemon.alive;
            let warning = if !report.installed {
                Some(report.detail.clone())
            } else if !started {
                Some(format!(
                    "Background service {} installed, but daemon socket did not respond yet; inspect logs or run `hyp service status`.",
                    report.service
                ))
            } else {
                report.warnings.first().cloned()
            };
            let detail = if started && report.installed {
                format!("running ({} {})", report.manager, report.service)
            } else {
                report.detail
            };
            AutoStartResult {
                started,
                installed: report.installed,
                manager: report.manager,
                service: Some(report.service),
                detail,
                warning,
            }
        }
        Err(e) => AutoStartResult {
            started: false,
            installed: false,
            manager: platform::MANAGER_NAME,
            service: None,
            detail: "not started (start manually with `hyp daemon`)".to_string(),
            warning: Some(format!(
                "Could not auto-start background daemon service ({e}); run `hyp daemon` manually."
            )),
        },
    }
}

pub fn run_service(command: ServiceCommand) -> CommandResult {
    let (name, as_json) = match &command {
        ServiceCommand::Install { json, .. } => ("service install", *json),
        ServiceCommand::Uninstall { json, .. } => ("service uninstall", *json),
        ServiceCommand::Start { json, .. } => ("service start", *json),
        ServiceCommand::Stop { json, .. } => ("service stop", *json),
        ServiceCommand::Restart { json, .. } => ("service restart", *json),
        ServiceCommand::Status { json, .. } => ("service status", *json),
    };
    CommandResult::new(name, as_json, service(command))
}

fn service(command: ServiceCommand) -> Result<ExitCode, CliError> {
    match command {
        ServiceCommand::Install {
            bin,
            home,
            state_dir,
            config,
            socket,
            json: as_json,
        } => {
            let explicit_home = home.is_some();
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return Err(CliError::error(
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                ));
            };
            let spec = match build_spec(
                bin.as_deref(),
                &resolved_home,
                state_dir.as_deref(),
                state_dir.is_some(),
                config.as_deref(),
                socket.as_deref(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    return Err(CliError::error("SERVICE_ERROR", e));
                }
            };
            let probe_sock = resolve_probe_socket(
                socket.as_deref(),
                state_dir.as_deref(),
                &resolved_home,
                explicit_home,
            );
            match platform::install(&spec, &resolved_home, &probe_sock, explicit_home) {
                Ok(report) => emit_report("service install", &report, as_json),
                Err(e) => Err(CliError::error("SERVICE_INSTALL_FAILED", e).with_fix("Run `hyp daemon` directly in the foreground if no user service manager is available.".to_string())),
            }
        }
        ServiceCommand::Uninstall {
            home,
            json: as_json,
        } => {
            let explicit_home = home.is_some();
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return Err(CliError::error(
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                ));
            };
            let probe_sock = resolve_probe_socket(None, None, &resolved_home, explicit_home);
            match platform::uninstall(&resolved_home, &probe_sock, explicit_home) {
                Ok(report) => emit_report("service uninstall", &report, as_json),
                Err(e) => Err(CliError::error("SERVICE_UNINSTALL_FAILED", e)),
            }
        }
        ServiceCommand::Start {
            home,
            socket,
            json: as_json,
        } => {
            let explicit_home = home.is_some();
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return Err(CliError::error(
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                ));
            };
            let probe_sock =
                resolve_probe_socket(socket.as_deref(), None, &resolved_home, explicit_home);
            match platform::start(&resolved_home, &probe_sock, explicit_home) {
                Ok(report) => emit_report("service start", &report, as_json),
                Err(e) => Err(CliError::error("SERVICE_START_FAILED", e)
                    .with_fix("Run `hyp service install`.".to_string())),
            }
        }
        ServiceCommand::Stop {
            home,
            json: as_json,
        } => {
            let explicit_home = home.is_some();
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return Err(CliError::error(
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                ));
            };
            let probe_sock = resolve_probe_socket(None, None, &resolved_home, explicit_home);
            match platform::stop(&resolved_home, &probe_sock, explicit_home) {
                Ok(report) => emit_report("service stop", &report, as_json),
                Err(e) => Err(CliError::error("SERVICE_STOP_FAILED", e)),
            }
        }
        ServiceCommand::Restart {
            home,
            socket,
            json: as_json,
        } => {
            let explicit_home = home.is_some();
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return Err(CliError::error(
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                ));
            };
            let probe_sock =
                resolve_probe_socket(socket.as_deref(), None, &resolved_home, explicit_home);
            match platform::restart(&resolved_home, &probe_sock, explicit_home) {
                Ok(report) => emit_report("service restart", &report, as_json),
                Err(e) => Err(CliError::error("SERVICE_RESTART_FAILED", e)
                    .with_fix("Run `hyp service install`.".to_string())),
            }
        }
        ServiceCommand::Status {
            home,
            socket,
            json: as_json,
        } => {
            let explicit_home = home.is_some();
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return Err(CliError::error(
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                ));
            };
            let probe_sock =
                resolve_probe_socket(socket.as_deref(), None, &resolved_home, explicit_home);
            match platform::status(&resolved_home, &probe_sock, explicit_home) {
                Ok(report) => emit_report("service status", &report, as_json),
                Err(e) => Err(CliError::error("SERVICE_STATUS_FAILED", e)),
            }
        }
    }
}

fn emit_report(
    cmd: &str,
    report: &ServiceActionReport,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    if as_json {
        let envelope = JsonEnvelope::ok(cmd.to_string(), report.detail.clone(), report)
            .warnings(report.warnings.clone())
            .next(report.next.clone());
        print_json(&envelope);
    } else {
        let tag = if report.daemon.alive || matches!(report.action, "stop" | "uninstall") {
            "OK  "
        } else {
            "WARN"
        };
        println!("{tag}  {}", report.detail);
        println!("      Manager:  {}", report.manager);
        println!("      Service:  {}", report.service);
        if let Some(ref unit) = report.unit_path {
            println!("      Unit:     {unit}");
        }
        println!(
            "      Daemon:   {}",
            if report.daemon.alive {
                format!("alive ({})", report.daemon.socket)
            } else {
                format!("offline ({})", report.daemon.socket)
            }
        );
        print_warnings(&report.warnings);
        print_next_steps(&report.next);
    }
    Ok(ExitCode::from(EXIT_OK))
}

// ============================================================================
// Pure Unit Tests (Never Mutates Live OS LaunchAgents / systemd / Task Scheduler!)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec() -> ServiceSpec {
        ServiceSpec {
            bin_path: PathBuf::from("/Users/alice/.local/bin/hyp"),
            state_dir: PathBuf::from("/Users/alice/.config/hyphae"),
            explicit_state_dir: false,
            config_path: None,
            socket_path: None,
            logs_dir: PathBuf::from("/Users/alice/.config/hyphae/logs"),
            path_env: build_service_path_env(
                Some("/Users/alice/.local/bin:/usr/bin"),
                Some(Path::new("/Users/alice/.local/bin")),
            ),
            secret_backend: None,
            extra_env: BTreeMap::new(),
            user_id: None,
        }
    }

    #[test]
    fn xml_escape_handles_all_five_entities() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn macos_plist_generation_is_well_formed_and_escaped() {
        let mut spec = sample_spec();
        spec.bin_path = PathBuf::from("/Users/o'malley & co/bin/hyp");
        spec.logs_dir = PathBuf::from("/Users/o'malley & co/.config/hyphae/logs");

        let plist = render_macos_plist(&spec);
        assert!(plist.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(plist.contains("<string>to.hyphae.daemon</string>"));
        assert!(plist.contains("<string>/Users/o&apos;malley &amp; co/bin/hyp</string>"));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n  <true/>"));
        assert!(plist.contains("daemon.out.log</string>"));
        assert!(plist.contains("daemon.err.log</string>"));
        assert!(plist.contains("<key>EnvironmentVariables</key>"));
        assert!(plist.contains("/opt/homebrew/bin"));
        assert!(plist.ends_with("</plist>\n"));
    }

    #[test]
    fn linux_systemd_unit_generation_and_escaping() {
        let mut spec = sample_spec();
        spec.bin_path = PathBuf::from("/home/alice/my dir/100%/hyp");
        let unit = render_linux_systemd_unit(&spec);
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("ExecStart=\"/home/alice/my dir/100%%/hyp\" daemon"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("RestartSec=3"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn windows_quote_arg_handles_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(windows_quote_arg("daemon"), "daemon");
        assert_eq!(
            windows_quote_arg(r"C:\Users\alice\.config\hyphae"),
            r"C:\Users\alice\.config\hyphae"
        );
        assert_eq!(
            windows_quote_arg(r"C:\Program Files\Hyphae\hyp.exe"),
            r#""C:\Program Files\Hyphae\hyp.exe""#
        );
        assert_eq!(
            windows_quote_arg(r"C:\Users\Alice Smith\"),
            r#""C:\Users\Alice Smith\\""#
        );
        assert_eq!(windows_quote_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(windows_quote_arg(r#"a\"b"#), r#""a\\\"b""#);
        assert_eq!(windows_quote_arg(""), r#""""#);
    }

    #[test]
    fn windows_task_xml_is_well_formed_escaped_and_utf16_roundtrips() {
        let spec = ServiceSpec {
            bin_path: PathBuf::from(r"C:\Users\O'Malley & Co\bin\hyp.exe"),
            state_dir: PathBuf::from(r"C:\Users\O'Malley & Co\.config\hyphae"),
            explicit_state_dir: true,
            config_path: Some(PathBuf::from(
                r#"C:\Users\O'Malley & Co\cfg "v2"\node.json"#,
            )),
            socket_path: Some(PathBuf::from(
                r"C:\Users\O'Malley & Co\.config\hyphae\connector.addr",
            )),
            logs_dir: PathBuf::from(r"C:\Users\O'Malley & Co\.config\hyphae\logs"),
            path_env: String::new(),
            secret_backend: None,
            extra_env: BTreeMap::new(),
            user_id: Some(r"CORP\o'malley & co".to_string()),
        };

        let xml = windows_task_xml(&spec);
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"));
        assert!(xml.contains(
            "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
        ));
        assert!(xml.contains("<LogonTrigger>"));
        assert!(xml.contains("<UserId>CORP\\o&apos;malley &amp; co</UserId>"));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
        assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(xml.contains("<RestartOnFailure>"));
        assert!(xml.contains("<Interval>PT1M</Interval>"));
        assert!(xml.contains("<Count>3</Count>"));
        assert!(xml.contains(r"<Command>C:\Users\O&apos;Malley &amp; Co\bin\hyp.exe</Command>"));
        assert!(xml.contains(
            "<Arguments>daemon --state-dir &quot;C:\\Users\\O&apos;Malley &amp; Co\\.config\\hyphae&quot; \
             --config &quot;C:\\Users\\O&apos;Malley &amp; Co\\cfg \\&quot;v2\\&quot;\\node.json&quot; \
             --socket &quot;C:\\Users\\O&apos;Malley &amp; Co\\.config\\hyphae\\connector.addr&quot;</Arguments>"
        ));
        assert!(xml.contains(
            r"<WorkingDirectory>C:\Users\O&apos;Malley &amp; Co\.config\hyphae</WorkingDirectory>"
        ));
        assert!(xml.ends_with("</Task>\n"));

        // Verify UTF-16 LE BOM encoding round-trips losslessly.
        let utf16_bytes = encode_utf16le_bom(&xml);
        assert_eq!(&utf16_bytes[..2], &[0xFF, 0xFE]);
        let units: Vec<u16> = utf16_bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).expect("valid UTF-16LE"), xml);
    }

    #[test]
    fn windows_task_xml_omits_userid_when_unset() {
        let spec = sample_spec();
        let xml = windows_task_xml(&spec);
        assert!(!xml.contains("<UserId>"));
        assert!(xml.contains("<LogonTrigger>"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(
            xml.contains("<Arguments>daemon --state-dir /Users/alice/.config/hyphae</Arguments>")
        );
    }

    #[test]
    fn schtasks_argv_builders_and_windows_helpers() {
        let xml_path = windows_task_xml_path(Path::new(r"C:\Users\alice\.config\hyphae"));
        assert_eq!(
            xml_path,
            PathBuf::from(r"C:\Users\alice\.config\hyphae").join("hyphae-daemon-task.xml")
        );
        assert_eq!(
            build_schtasks_create_args(WINDOWS_TASK_NAME, &xml_path),
            vec![
                "/Create",
                "/TN",
                "HyphaeDaemon",
                "/XML",
                &xml_path.display().to_string(),
                "/F",
            ]
        );
        assert_eq!(
            build_schtasks_query_args(WINDOWS_TASK_NAME),
            vec!["/Query", "/TN", "HyphaeDaemon", "/FO", "LIST", "/V"]
        );
        assert_eq!(
            build_schtasks_run_args(WINDOWS_TASK_NAME),
            vec!["/Run", "/TN", "HyphaeDaemon"]
        );
        assert_eq!(
            build_schtasks_end_args(WINDOWS_TASK_NAME),
            vec!["/End", "/TN", "HyphaeDaemon"]
        );
        assert_eq!(
            build_schtasks_delete_args(WINDOWS_TASK_NAME),
            vec!["/Delete", "/TN", "HyphaeDaemon", "/F"]
        );
        assert_eq!(
            format_windows_user_id(Some("DESKTOP-1"), Some("alice")),
            Some(r"DESKTOP-1\alice".to_string())
        );
        assert_eq!(
            format_windows_user_id(None, Some("alice")),
            Some("alice".to_string())
        );
        assert_eq!(format_windows_user_id(Some("CORP"), Some("   ")), None);
    }

    #[test]
    fn parse_schtasks_query_output_handles_list_csv_and_errors() {
        assert_eq!(parse_schtasks_query_output(""), (false, false));
        assert_eq!(parse_schtasks_query_output("   \r\n  "), (false, false));
        assert_eq!(
            parse_schtasks_query_output("ERROR: The system cannot find the file specified.\r\n"),
            (false, false)
        );

        let list_running = "\r\nFolder: \\\r\n\
            HostName:                             WORKSTATION\r\n\
            TaskName:                             \\HyphaeDaemon\r\n\
            Next Run Time:                        N/A\r\n\
            Status:                               Running\r\n\
            Logon Mode:                           Interactive only\r\n";
        assert_eq!(parse_schtasks_query_output(list_running), (true, true));

        // Adversarial nearby case: path mentions "Running", but Status is Ready.
        let list_ready = "Folder: \\\r\n\
            TaskName:                             \\HyphaeDaemon\r\n\
            Status:                               Ready\r\n\
            Task To Run:                          C:\\Running\\hyp.exe daemon\r\n";
        assert_eq!(parse_schtasks_query_output(list_ready), (true, false));

        let list_disabled = "TaskName: \\HyphaeDaemon\nStatus: Disabled\n";
        assert_eq!(parse_schtasks_query_output(list_disabled), (true, false));

        let csv_running = "\"TaskName\",\"Next Run Time\",\"Status\"\r\n\
            \"\\HyphaeDaemon\",\"N/A\",\"Running\"\r\n";
        assert_eq!(parse_schtasks_query_output(csv_running), (true, true));

        let csv_ready = "\"TaskName\",\"Next Run Time\",\"Status\"\r\n\
            \"\\HyphaeDaemon\",\"N/A\",\"Ready\"\r\n";
        assert_eq!(parse_schtasks_query_output(csv_ready), (true, false));

        let csv_verbose_running = "\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Task To Run\"\r\n\
            \"MYPC\",\"\\HyphaeDaemon\",\"N/A\",\"Running\",\"C:\\bin\\hyp.exe daemon\"\r\n";
        assert_eq!(
            parse_schtasks_query_output(csv_verbose_running),
            (true, true)
        );

        let csv_header_only = "\"TaskName\",\"Next Run Time\",\"Status\"\r\n";
        assert_eq!(parse_schtasks_query_output(csv_header_only), (false, false));

        let csv_nh_running = "\"\\HyphaeDaemon\",\"N/A\",\"Running\"\r\n";
        assert_eq!(parse_schtasks_query_output(csv_nh_running), (true, true));

        let csv_nh_verbose_ready =
            "\"MYPC\",\"\\HyphaeDaemon\",\"N/A\",\"Ready\",\"C:\\Running\\hyp.exe\"\r\n";
        assert_eq!(
            parse_schtasks_query_output(csv_nh_verbose_ready),
            (true, false)
        );
    }

    #[test]
    fn target_paths_and_path_env_deduplication() {
        let home = Path::new("/tmp/test-home");
        assert_eq!(
            macos_plist_path(home),
            PathBuf::from("/tmp/test-home/Library/LaunchAgents/to.hyphae.daemon.plist")
        );
        assert_eq!(
            linux_systemd_unit_path(home),
            PathBuf::from("/tmp/test-home/.config/systemd/user/hyphae-daemon.service")
        );
        let path = build_service_path_env(
            Some("/usr/bin:/opt/homebrew/bin:/usr/bin"),
            Some(Path::new("/home/u/.local/bin")),
        );
        let parts: Vec<&str> = path.split(':').collect();
        assert_eq!(parts[0], "/home/u/.local/bin");
        assert_eq!(parts.iter().filter(|&&p| p == "/usr/bin").count(), 1);
        assert!(parts.contains(&"/opt/homebrew/bin"));
    }

    #[test]
    fn d10_and_d16_systemd_secret_backend_state_dir_xdg_and_linger_parser() {
        let mut spec = sample_spec();
        spec.state_dir = PathBuf::from("/var/lib/hyphae custom");
        spec.explicit_state_dir = true;
        spec.secret_backend = Some("file".to_string());

        let unit = render_linux_systemd_unit(&spec);
        assert!(
            unit.contains("--state-dir \"/var/lib/hyphae custom\""),
            "expected explicit --state-dir in ExecStart:\n{unit}"
        );
        assert!(
            unit.contains("Environment=\"HYPHAE_SECRET_BACKEND=file\""),
            "expected HYPHAE_SECRET_BACKEND pinned in systemd unit:\n{unit}"
        );

        let plist = render_macos_plist(&spec);
        assert!(plist.contains("<string>--state-dir</string>"));
        assert!(plist.contains("<string>/var/lib/hyphae custom</string>"));
        assert!(plist.contains("<key>HYPHAE_SECRET_BACKEND</key>"));
        assert!(plist.contains("<string>file</string>"));

        let home = Path::new("/home/alice");
        assert_eq!(
            linux_systemd_unit_path_with_xdg(home, Some(Path::new("/srv/xdg-config"))),
            PathBuf::from("/srv/xdg-config/systemd/user/hyphae-daemon.service")
        );
        assert_eq!(
            linux_systemd_unit_path_with_xdg(home, None),
            PathBuf::from("/home/alice/.config/systemd/user/hyphae-daemon.service")
        );

        assert_eq!(parse_loginctl_linger("Linger=yes\n"), Some(true));
        assert_eq!(parse_loginctl_linger("Linger=no\n"), Some(false));
        assert_eq!(parse_loginctl_linger("Other=1\n"), None);
    }

    #[test]
    fn service_env_pins_1password_lastpass_pass_non_secret_config_never_tokens() {
        use hyp_crypto::keystore::SecretBackend;

        // 1Password: pins vault & op bin, NEVER OP_SERVICE_ACCOUNT_TOKEN!
        let op_env = collect_secret_backend_service_env(SecretBackend::OnePassword, |k| match k {
            "HYPHAE_1PASSWORD_VAULT" => Some("Team Vault".to_string()),
            "HYPHAE_OP_BIN" => Some("/opt/homebrew/bin/op".to_string()),
            "OP_SERVICE_ACCOUNT_TOKEN" => Some("ops_NEVER_PIN_SECRET_TOKEN".to_string()),
            _ => None,
        });
        assert_eq!(
            op_env.get("HYPHAE_1PASSWORD_VAULT").map(String::as_str),
            Some("Team Vault")
        );
        assert_eq!(
            op_env.get("HYPHAE_OP_BIN").map(String::as_str),
            Some("/opt/homebrew/bin/op")
        );
        assert!(!op_env.contains_key("OP_SERVICE_ACCOUNT_TOKEN"));

        let mut spec = sample_spec();
        spec.secret_backend = Some("1password".to_string());
        spec.extra_env = op_env;
        let plist = render_macos_plist(&spec);
        assert!(plist.contains("<key>HYPHAE_SECRET_BACKEND</key>\n    <string>1password</string>"));
        assert!(
            plist.contains("<key>HYPHAE_1PASSWORD_VAULT</key>\n    <string>Team Vault</string>")
        );
        assert!(!plist.contains("OP_SERVICE_ACCOUNT_TOKEN"));
        let unit = render_linux_systemd_unit(&spec);
        assert!(unit.contains("Environment=\"HYPHAE_SECRET_BACKEND=1password\""));
        assert!(unit.contains("Environment=\"HYPHAE_1PASSWORD_VAULT=Team Vault\""));
        assert!(!unit.contains("OP_SERVICE_ACCOUNT_TOKEN"));

        // LastPass: pins valid prefix, rejects traversal prefix
        let lp_env = collect_secret_backend_service_env(SecretBackend::LastPass, |k| match k {
            "HYPHAE_LASTPASS_PREFIX" => Some("work/hyphae".to_string()),
            _ => None,
        });
        assert_eq!(
            lp_env.get("HYPHAE_LASTPASS_PREFIX").map(String::as_str),
            Some("work/hyphae")
        );
        let lp_bad = collect_secret_backend_service_env(SecretBackend::LastPass, |k| match k {
            "HYPHAE_LASTPASS_PREFIX" => Some("../escape".to_string()),
            _ => None,
        });
        assert!(!lp_bad.contains_key("HYPHAE_LASTPASS_PREFIX"));

        // Pass: pins prefix, PASSWORD_STORE_DIR, GNUPGHOME; rejects traversal prefix
        let pass_env = collect_secret_backend_service_env(SecretBackend::Pass, |k| match k {
            "HYPHAE_PASS_PREFIX" => Some("infra/hyphae".to_string()),
            "PASSWORD_STORE_DIR" => Some("/srv/pass-store".to_string()),
            "GNUPGHOME" => Some("/srv/gnupg".to_string()),
            _ => None,
        });
        assert_eq!(
            pass_env.get("HYPHAE_PASS_PREFIX").map(String::as_str),
            Some("infra/hyphae")
        );
        assert_eq!(
            pass_env.get("PASSWORD_STORE_DIR").map(String::as_str),
            Some("/srv/pass-store")
        );
        assert_eq!(
            pass_env.get("GNUPGHOME").map(String::as_str),
            Some("/srv/gnupg")
        );
        spec.secret_backend = Some("pass".to_string());
        spec.extra_env = pass_env;
        let pass_unit = render_linux_systemd_unit(&spec);
        assert!(pass_unit.contains("Environment=\"HYPHAE_SECRET_BACKEND=pass\""));
        assert!(pass_unit.contains("Environment=\"HYPHAE_PASS_PREFIX=infra/hyphae\""));
        assert!(pass_unit.contains("Environment=\"PASSWORD_STORE_DIR=/srv/pass-store\""));
        assert!(pass_unit.contains("Environment=\"GNUPGHOME=/srv/gnupg\""));
    }

    fn zero_sleep_policy() -> LaunchdRetryPolicy {
        LaunchdRetryPolicy {
            bootout_poll_attempts: 10,
            bootout_poll_interval: Duration::ZERO,
            bootstrap_max_attempts: 6,
            bootstrap_retry_delay: Duration::ZERO,
        }
    }

    fn ok_out() -> LaunchctlOutput {
        LaunchctlOutput {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn err_out(code: i32, stderr: &str) -> LaunchctlOutput {
        LaunchctlOutput {
            exit_code: Some(code),
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    #[test]
    fn launchd_stop_then_start_normal_flow() {
        use std::cell::{Cell, RefCell};

        let loaded = Cell::new(true);
        let print_remaining_before_unload = Cell::new(2usize);
        let calls: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
        let sleeps = Cell::new(0usize);

        let mut run = |args: &[&str]| -> Result<LaunchctlOutput, String> {
            calls
                .borrow_mut()
                .push(args.iter().map(|s| s.to_string()).collect());
            match args[0] {
                "bootout" => Ok(ok_out()),
                "print" => {
                    if loaded.get() && print_remaining_before_unload.get() > 0 {
                        print_remaining_before_unload.set(print_remaining_before_unload.get() - 1);
                        Ok(ok_out())
                    } else {
                        loaded.set(false);
                        Ok(err_out(113, "Could not find service \"to.hyphae.daemon\""))
                    }
                }
                "enable" => Ok(ok_out()),
                "bootstrap" => {
                    assert!(!loaded.get(), "bootstrap must run after service unloaded");
                    loaded.set(true);
                    Ok(ok_out())
                }
                other => panic!("unexpected launchctl subcommand: {other}"),
            }
        };
        let mut sleep = |_d: Duration| {
            sleeps.set(sleeps.get() + 1);
        };

        let target = "gui/501/to.hyphae.daemon";
        let plist = "/Users/alice/Library/LaunchAgents/to.hyphae.daemon.plist";

        launchd_stop_via(target, zero_sleep_policy(), &mut run, &mut sleep);
        assert!(
            !loaded.get(),
            "stop must poll until launchd finishes bootout"
        );
        assert_eq!(sleeps.get(), 2);

        launchd_start_via(
            "gui/501",
            target,
            plist,
            zero_sleep_policy(),
            &mut run,
            &mut sleep,
        )
        .expect("start after stop must succeed");
        assert!(loaded.get());
        let recorded = calls.borrow();
        assert!(recorded.iter().any(|c| c == &["enable", target]));
        assert!(
            recorded
                .iter()
                .any(|c| c == &["bootstrap", "gui/501", plist])
        );
    }

    #[test]
    fn launchd_start_recovers_from_stale_is_loaded_kickstart_could_not_find_service_race() {
        // Exact Issue #21 race: `print` briefly returns 0 (stale during bootout teardown),
        // then `kickstart` fails with exit 113 `Could not find service`, and `start` automatically
        // falls back to `bootstrap` and succeeds!
        let mut print_calls = 0usize;
        let mut calls: Vec<Vec<String>> = Vec::new();
        let mut run = |args: &[&str]| -> Result<LaunchctlOutput, String> {
            calls.push(args.iter().map(|s| s.to_string()).collect());
            match args[0] {
                "enable" => Ok(ok_out()),
                "print" => {
                    print_calls += 1;
                    if print_calls == 1 {
                        Ok(ok_out()) // stale: still unloading
                    } else {
                        Ok(err_out(113, "Could not find service \"to.hyphae.daemon\""))
                    }
                }
                "kickstart" => Ok(err_out(
                    113,
                    "Could not find service \"to.hyphae.daemon\" in domain for user gui: 501",
                )),
                "bootstrap" => Ok(ok_out()),
                other => panic!("unexpected launchctl subcommand: {other}"),
            }
        };
        let mut sleep = |_d: Duration| {};

        launchd_start_via(
            "gui/501",
            "gui/501/to.hyphae.daemon",
            "/Users/alice/Library/LaunchAgents/to.hyphae.daemon.plist",
            zero_sleep_policy(),
            &mut run,
            &mut sleep,
        )
        .expect("start must recover via bootstrap after kickstart race");

        assert!(
            calls
                .iter()
                .any(|c| c == &["kickstart", "gui/501/to.hyphae.daemon"])
        );
        assert!(calls.iter().any(|c| c[0] == "bootstrap"));
    }

    #[test]
    fn launchd_bootstrap_retries_transient_eio_and_succeeds_on_attempt_three() {
        let mut bootstrap_attempts = 0usize;
        let mut sleeps = 0usize;
        let mut run = |args: &[&str]| -> Result<LaunchctlOutput, String> {
            match args[0] {
                "enable" => Ok(ok_out()),
                "bootstrap" => {
                    bootstrap_attempts += 1;
                    if bootstrap_attempts < 3 {
                        Ok(err_out(5, "Bootstrap failed: 5: Input/output error"))
                    } else {
                        Ok(ok_out())
                    }
                }
                other => panic!("unexpected launchctl subcommand: {other}"),
            }
        };
        let mut sleep = |_d: Duration| {
            sleeps += 1;
        };

        launchd_bootstrap_with_retry_via(
            "gui/501",
            "gui/501/to.hyphae.daemon",
            "/Users/alice/Library/LaunchAgents/to.hyphae.daemon.plist",
            false,
            zero_sleep_policy(),
            &mut run,
            &mut sleep,
        )
        .expect("transient EIO must retry and succeed on attempt 3");

        assert_eq!(bootstrap_attempts, 3);
        assert_eq!(sleeps, 2);
    }

    #[test]
    fn launchd_bootstrap_already_loaded_recovers_via_kickstart() {
        let mut calls: Vec<Vec<String>> = Vec::new();
        let mut run = |args: &[&str]| -> Result<LaunchctlOutput, String> {
            calls.push(args.iter().map(|s| s.to_string()).collect());
            match args[0] {
                "enable" => Ok(ok_out()),
                "bootstrap" => Ok(err_out(
                    37,
                    "Bootstrap failed: 37: Operation already in progress (service already loaded)",
                )),
                "kickstart" => Ok(ok_out()),
                other => panic!("unexpected launchctl subcommand: {other}"),
            }
        };
        let mut sleep = |_d: Duration| {};

        launchd_bootstrap_with_retry_via(
            "gui/501",
            "gui/501/to.hyphae.daemon",
            "/Users/alice/Library/LaunchAgents/to.hyphae.daemon.plist",
            false,
            zero_sleep_policy(),
            &mut run,
            &mut sleep,
        )
        .expect("already loaded must recover via kickstart");

        assert!(
            calls
                .iter()
                .any(|c| c == &["kickstart", "gui/501/to.hyphae.daemon"])
        );
    }

    #[test]
    fn launchd_restart_when_already_stopped_recovers_via_bootstrap() {
        let mut calls: Vec<Vec<String>> = Vec::new();
        let mut run = |args: &[&str]| -> Result<LaunchctlOutput, String> {
            calls.push(args.iter().map(|s| s.to_string()).collect());
            match args[0] {
                "enable" => Ok(ok_out()),
                "kickstart" => Ok(err_out(
                    113,
                    "Could not find service \"to.hyphae.daemon\" in domain for user gui: 501",
                )),
                "print" => Ok(err_out(113, "Could not find service \"to.hyphae.daemon\"")),
                "bootstrap" => Ok(ok_out()),
                other => panic!("unexpected launchctl subcommand: {other}"),
            }
        };
        let mut sleep = |_d: Duration| {};

        launchd_restart_via(
            "gui/501",
            "gui/501/to.hyphae.daemon",
            "/Users/alice/Library/LaunchAgents/to.hyphae.daemon.plist",
            zero_sleep_policy(),
            &mut run,
            &mut sleep,
        )
        .expect("restart on stopped service must recover via bootstrap");

        assert!(
            calls
                .iter()
                .any(|c| c == &["kickstart", "-k", "gui/501/to.hyphae.daemon"])
        );
        assert!(calls.iter().any(|c| c[0] == "bootstrap"));
        assert!(
            !calls.iter().any(|c| c[0] == "bootout"),
            "already-unloaded restart need not run bootout: {calls:?}"
        );
    }

    #[test]
    fn launchd_bootstrap_fails_fast_on_non_transient_error() {
        let mut attempts = 0usize;
        let mut run = |args: &[&str]| -> Result<LaunchctlOutput, String> {
            match args[0] {
                "enable" => Ok(ok_out()),
                "bootstrap" => {
                    attempts += 1;
                    Ok(err_out(1, "Path had bad ownership/permissions"))
                }
                other => panic!("unexpected launchctl subcommand: {other}"),
            }
        };
        let mut sleep = |_d: Duration| {};

        let err = launchd_bootstrap_with_retry_via(
            "gui/501",
            "gui/501/to.hyphae.daemon",
            "/bad/plist",
            false,
            zero_sleep_policy(),
            &mut run,
            &mut sleep,
        )
        .expect_err("non-transient error must fail fast");

        assert_eq!(attempts, 1, "must not retry fatal bootstrap errors");
        assert!(err.contains("ownership/permissions"), "err={err}");
    }

    #[test]
    fn ephemeral_temp_home_and_service_control_disabled_guard_refuses_live_mutations() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested_nonexistent = tmp.path().join("isolated-home").join("nested");

        assert!(is_ephemeral_temp_home(tmp.path()));
        assert!(is_ephemeral_temp_home(&nested_nonexistent));
        assert!(is_ephemeral_temp_home(Path::new("/tmp/hyphae-test-home")));
        assert!(is_ephemeral_temp_home(Path::new(
            "/private/tmp/hyphae-test-home"
        )));
        assert!(is_ephemeral_temp_home(Path::new(
            "/var/folders/xx/abc/T/hyphae-test"
        )));
        assert!(is_ephemeral_temp_home(Path::new(
            "/private/var/folders/xx/abc/T/hyphae-test"
        )));
        assert!(is_ephemeral_temp_home(Path::new(
            r"C:\Users\alice\AppData\Local\Temp\hyphae-test"
        )));
        assert!(!is_ephemeral_temp_home(Path::new("/Users/alice")));
        assert!(!is_ephemeral_temp_home(Path::new("/home/alice")));

        assert!(service_control_disabled(tmp.path()).is_some());
        assert!(service_control_disabled(&nested_nonexistent).is_some());

        // `install_and_start_default` and `restart_if_installed` MUST refuse to touch live OS services
        // on temp homes even without `HYPHAE_NO_SERVICE=1`.
        let auto_res = install_and_start_default(
            Path::new("/usr/local/bin/hyp"),
            tmp.path(),
            &tmp.path().join(".config/hyphae"),
        );
        assert!(!auto_res.started);
        assert!(!auto_res.installed);

        let restart_res = restart_if_installed(Some(tmp.path()), None);
        assert!(!restart_res.attempted);
        assert!(restart_res.skipped);
        assert_eq!(
            restart_res.skip_reason.as_deref(),
            Some("service_control_disabled")
        );

        // Mutating platform entrypoints MUST fail closed on temp homes without calling launchctl/systemctl/schtasks.
        let sock = tmp.path().join("connector.sock");
        let mut spec = sample_spec();
        spec.state_dir = tmp.path().join(".config/hyphae");
        spec.logs_dir = spec.state_dir.join("logs");

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            assert!(platform::install(&spec, tmp.path(), &sock, true).is_err());
            assert!(platform::uninstall(tmp.path(), &sock, true).is_err());
            assert!(platform::start(tmp.path(), &sock, true).is_err());
            assert!(platform::stop(tmp.path(), &sock, true).is_err());
            assert!(platform::restart(tmp.path(), &sock, true).is_err());
        }

        // Read-only `status` STILL succeeds cleanly on temp homes without mutating or leaking host state.
        let st = platform::status(tmp.path(), &sock, true).expect("status must succeed");
        assert!(!st.installed);
        assert!(!st.loaded);
        assert!(!st.daemon.alive);
    }
}
