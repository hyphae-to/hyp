//! `hyp service` — Background OS service lifecycle for the Hyphae v2 daemon
//! (`macOS LaunchAgent` / `Linux systemd --user` / Windows guidance).
//!
//! Keeps `hyp daemon` strictly foreground (required by LaunchAgent, systemd, Docker,
//! and all existing tests) while letting `hyp onboard` and `hyp service install|restart|stop|status`
//! manage a clean auto-restarting background daemon.

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::config_file::{ensure_dir, write_atomic_file};
use crate::config_file::{resolve_home_dir, resolve_state_dir};
use crate::ui::{
    EXIT_ERROR, EXIT_OK, JsonEnvelope, emit_error, print_json, print_next_steps,
};
use clap::Subcommand;
use hyp_harness::sock::{daemon_rpc_sync, default_socket_path};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const MACOS_LAUNCHAGENT_LABEL: &str = "to.hyphae.daemon";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const LINUX_SYSTEMD_UNIT: &str = "hyphae-daemon.service";

const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(3);
const DAEMON_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DAEMON_RPC_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Subcommand)]
pub enum ServiceCommand {
    /// Install and start the Hyphae background daemon OS service (LaunchAgent / systemd --user)
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

/// Platform-agnostic specification rendered into a LaunchAgent plist or systemd user unit.
#[derive(Debug, Clone)]
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub struct ServiceSpec {
    pub bin_path: PathBuf,
    pub state_dir: PathBuf,
    pub config_path: Option<PathBuf>,
    pub socket_path: Option<PathBuf>,
    pub logs_dir: PathBuf,
    pub path_env: String,
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

pub fn default_daemon_logs_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("logs")
}

/// Escapes special XML characters for safe embedding inside LaunchAgent plist text nodes.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    let env_path = spec.path_env.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%");

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
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

// ============================================================================
// Live Daemon Probe (`daemon.status` over `connector.sock` / `connector.addr`)
// ============================================================================

fn resolve_probe_socket(explicit_socket: Option<&Path>, home: &Path, explicit_home: bool) -> PathBuf {
    if let Some(s) = explicit_socket {
        return s.to_path_buf();
    }
    if explicit_home {
        return home
            .join(".config")
            .join("hyphae")
            .join("state")
            .join("connector.sock");
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
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

// Keep `thread` / `Instant` / `DAEMON_*` used across non-macOS/Linux targets without dead-code warnings.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn _keep_poll_helpers_used() {
    let _ = (DAEMON_READY_TIMEOUT, DAEMON_POLL_INTERVAL, Instant::now(), thread::yield_now);
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
    config_arg: Option<&Path>,
    socket_arg: Option<&Path>,
) -> Result<ServiceSpec, String> {
    let bin_path = resolve_service_bin(bin)?;
    let state_dir = resolve_state_dir(state_dir_arg, config_arg, Some(home));
    let logs_dir = default_daemon_logs_dir(&state_dir);
    let current_path = std::env::var("PATH").ok();
    let path_env = build_service_path_env(current_path.as_deref(), bin_path.parent());
    Ok(ServiceSpec {
        bin_path,
        state_dir,
        config_path: config_arg.map(Path::to_path_buf),
        socket_path: socket_arg.map(Path::to_path_buf),
        logs_dir,
        path_env,
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

    fn run_launchctl(args: &[&str]) -> Result<std::process::Output, String> {
        Command::new("launchctl")
            .args(args)
            .output()
            .map_err(|e| format!("failed to execute launchctl: {e}"))
    }

    fn is_loaded(uid: &str) -> bool {
        let target = service_target(uid);
        run_launchctl(&["print", &target])
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn install(spec: &ServiceSpec, home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        ensure_dir(&spec.state_dir, true)?;
        ensure_dir(&spec.logs_dir, true)?;

        let plist_path = macos_plist_path(home);
        let plist_xml = render_macos_plist(spec);
        write_atomic_file(&plist_path, plist_xml.as_bytes(), false)?;

        let uid = current_uid()?;
        let domain = gui_domain(&uid);
        let target = service_target(&uid);
        let plist_str = plist_path.display().to_string();

        // Bootout any existing registration (ignore errors when not currently loaded).
        let _ = run_launchctl(&["bootout", &target]);

        let boot = run_launchctl(&["bootstrap", &domain, &plist_str])?;
        if !boot.status.success() {
            let stderr = String::from_utf8_lossy(&boot.stderr).trim().to_string();
            return Err(format!(
                "launchctl bootstrap failed ({}): {}",
                boot.status,
                if stderr.is_empty() { "unknown error" } else { &stderr }
            ));
        }

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
            next: vec![
                "hyp service status".to_string(),
                "hyp doctor".to_string(),
            ],
        })
    }

    pub fn uninstall(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let uid = current_uid()?;
        let target = service_target(&uid);
        let _ = run_launchctl(&["bootout", &target]);

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
            next: vec!["hyp service install".to_string()],
        })
    }

    pub fn start(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
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

        if is_loaded(&uid) {
            let kick = run_launchctl(&["kickstart", &target])?;
            if !kick.status.success() {
                let stderr = String::from_utf8_lossy(&kick.stderr).trim().to_string();
                return Err(format!("launchctl kickstart failed: {stderr}"));
            }
        } else {
            let boot = run_launchctl(&["bootstrap", &domain, &plist_str])?;
            if !boot.status.success() {
                let stderr = String::from_utf8_lossy(&boot.stderr).trim().to_string();
                return Err(format!("launchctl bootstrap failed: {stderr}"));
            }
        }

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
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn stop(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let uid = current_uid()?;
        let target = service_target(&uid);
        let _ = run_launchctl(&["bootout", &target]);

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
            next: vec!["hyp service start".to_string()],
        })
    }

    pub fn restart(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
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

        let kick = run_launchctl(&["kickstart", "-k", &target])?;
        if !kick.status.success() {
            let _ = run_launchctl(&["bootout", &target]);
            let boot = run_launchctl(&["bootstrap", &domain, &plist_str])?;
            if !boot.status.success() {
                let stderr = String::from_utf8_lossy(&boot.stderr).trim().to_string();
                return Err(format!("launchctl restart failed: {stderr}"));
            }
        }

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
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn status(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let plist_path = macos_plist_path(home);
        let installed = plist_path.exists();
        let loaded = current_uid().map(|u| is_loaded(&u)).unwrap_or(false);
        let probe = probe_daemon_once(socket);
        let detail = if probe.alive && installed {
            format!("Running (LaunchAgent {MACOS_LAUNCHAGENT_LABEL})")
        } else if probe.alive {
            "Daemon running (foreground / unmanaged; LaunchAgent not installed)".to_string()
        } else if installed && loaded {
            format!("LaunchAgent {MACOS_LAUNCHAGENT_LABEL} loaded, but daemon socket not responding")
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
            if stderr.is_empty() { "unknown error" } else { &stderr }
        ))
    }

    pub fn install(spec: &ServiceSpec, home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        ensure_dir(&spec.state_dir, true)?;
        ensure_dir(&spec.logs_dir, true)?;

        let unit_path = linux_systemd_unit_path(home);
        let unit_content = render_linux_systemd_unit(spec);
        write_atomic_file(&unit_path, unit_content.as_bytes(), false)?;

        let reload = run_systemctl(&["daemon-reload"])?;
        check_systemctl_ok(&reload, "daemon-reload")?;
        let enable = run_systemctl(&["enable", "--now", LINUX_SYSTEMD_UNIT])?;
        check_systemctl_ok(&enable, "enable --now")?;

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
            next: vec![
                "hyp service status".to_string(),
                "hyp doctor".to_string(),
            ],
        })
    }

    pub fn uninstall(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let _ = run_systemctl(&["disable", "--now", LINUX_SYSTEMD_UNIT]);
        let unit_path = linux_systemd_unit_path(home);
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
            next: vec!["hyp service install".to_string()],
        })
    }

    pub fn start(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let unit_path = linux_systemd_unit_path(home);
        if !unit_path.exists() {
            return Err(format!(
                "systemd unit not found at {} (run `hyp service install` first)",
                unit_path.display()
            ));
        }
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
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn stop(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let unit_path = linux_systemd_unit_path(home);
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
            next: vec!["hyp service start".to_string()],
        })
    }

    pub fn restart(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let unit_path = linux_systemd_unit_path(home);
        if !unit_path.exists() {
            return Err(format!(
                "systemd unit not found at {} (run `hyp service install` first)",
                unit_path.display()
            ));
        }
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
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn status(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let unit_path = linux_systemd_unit_path(home);
        let installed = unit_path.exists();
        let loaded = run_systemctl(&["is-active", "--quiet", LINUX_SYSTEMD_UNIT])
            .map(|o| o.status.success())
            .unwrap_or(false);
        let probe = probe_daemon_once(socket);
        let detail = if probe.alive && installed {
            format!("Running (systemd user {LINUX_SYSTEMD_UNIT})")
        } else if probe.alive {
            "Daemon running (foreground / unmanaged; systemd user unit not installed)".to_string()
        } else if installed && loaded {
            format!("systemd user unit {LINUX_SYSTEMD_UNIT} active, but daemon socket not responding")
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
            next,
        })
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;

    #[cfg(target_os = "windows")]
    pub const MANAGER_NAME: &str = "windows";
    #[cfg(not(target_os = "windows"))]
    pub const MANAGER_NAME: &str = "manual";

    fn guidance_detail(action: &str) -> String {
        _keep_poll_helpers_used();
        #[cfg(target_os = "windows")]
        {
            format!(
                "Native Windows service registration for `{action}` is not enabled; run in background with: Start-Process -WindowStyle Hidden hyp daemon"
            )
        }
        #[cfg(not(target_os = "windows"))]
        {
            format!(
                "Background OS service manager for `{action}` is not available on this OS; run `hyp daemon` under your process supervisor."
            )
        }
    }

    fn guidance_next() -> Vec<String> {
        #[cfg(target_os = "windows")]
        {
            vec![
                "Start-Process -WindowStyle Hidden hyp daemon".to_string(),
                "hyp status".to_string(),
            ]
        }
        #[cfg(not(target_os = "windows"))]
        {
            vec!["hyp daemon".to_string(), "hyp status".to_string()]
        }
    }

    pub fn install(_spec: &ServiceSpec, _home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
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
            next: guidance_next(),
        })
    }

    pub fn uninstall(_home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
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
            next: guidance_next(),
        })
    }

    pub fn start(_home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
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
            next: guidance_next(),
        })
    }

    pub fn stop(_home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
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
            next: guidance_next(),
        })
    }

    pub fn restart(_home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
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
            next: guidance_next(),
        })
    }

    pub fn status(_home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
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
            next: guidance_next(),
        })
    }
}

// ============================================================================
// Public Entrypoints (`hyp service ...` & `hyp onboard` Auto-Start Hook)
// ============================================================================

/// Installs and starts the default OS background daemon service during `hyp onboard`.
/// Never panics or fails onboarding fatally — callers surface `warning` cleanly if unavailable.
pub fn install_and_start_default(bin_path: &Path, home: &Path, state_dir: &Path) -> AutoStartResult {
    let spec = match build_spec(Some(bin_path), home, Some(state_dir), None, None) {
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
    match platform::install(&spec, home, &socket) {
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
                None
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

pub fn run_service(command: ServiceCommand) -> ExitCode {
    match command {
        ServiceCommand::Install {
            bin,
            home,
            state_dir,
            config,
            socket,
            json: as_json,
        } => {
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return emit_error(
                    "service install",
                    as_json,
                    EXIT_ERROR,
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                    None,
                );
            };
            let spec = match build_spec(
                bin.as_deref(),
                &resolved_home,
                state_dir.as_deref(),
                config.as_deref(),
                socket.as_deref(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    return emit_error("service install", as_json, EXIT_ERROR, "SERVICE_ERROR", e, None);
                }
            };
            let probe_sock = resolve_probe_socket(socket.as_deref(), &resolved_home, home.is_some());
            match platform::install(&spec, &resolved_home, &probe_sock) {
                Ok(report) => emit_report("service install", &report, as_json),
                Err(e) => emit_error(
                    "service install",
                    as_json,
                    EXIT_ERROR,
                    "SERVICE_INSTALL_FAILED",
                    e,
                    Some("Run `hyp daemon` directly in the foreground if no user service manager is available.".to_string()),
                ),
            }
        }
        ServiceCommand::Uninstall { home, json: as_json } => {
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return emit_error(
                    "service uninstall",
                    as_json,
                    EXIT_ERROR,
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                    None,
                );
            };
            let probe_sock = resolve_probe_socket(None, &resolved_home, home.is_some());
            match platform::uninstall(&resolved_home, &probe_sock) {
                Ok(report) => emit_report("service uninstall", &report, as_json),
                Err(e) => emit_error("service uninstall", as_json, EXIT_ERROR, "SERVICE_UNINSTALL_FAILED", e, None),
            }
        }
        ServiceCommand::Start {
            home,
            socket,
            json: as_json,
        } => {
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return emit_error(
                    "service start",
                    as_json,
                    EXIT_ERROR,
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                    None,
                );
            };
            let probe_sock = resolve_probe_socket(socket.as_deref(), &resolved_home, home.is_some());
            match platform::start(&resolved_home, &probe_sock) {
                Ok(report) => emit_report("service start", &report, as_json),
                Err(e) => emit_error("service start", as_json, EXIT_ERROR, "SERVICE_START_FAILED", e, Some("Run `hyp service install`.".to_string())),
            }
        }
        ServiceCommand::Stop { home, json: as_json } => {
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return emit_error(
                    "service stop",
                    as_json,
                    EXIT_ERROR,
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                    None,
                );
            };
            let probe_sock = resolve_probe_socket(None, &resolved_home, home.is_some());
            match platform::stop(&resolved_home, &probe_sock) {
                Ok(report) => emit_report("service stop", &report, as_json),
                Err(e) => emit_error("service stop", as_json, EXIT_ERROR, "SERVICE_STOP_FAILED", e, None),
            }
        }
        ServiceCommand::Restart {
            home,
            socket,
            json: as_json,
        } => {
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return emit_error(
                    "service restart",
                    as_json,
                    EXIT_ERROR,
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                    None,
                );
            };
            let probe_sock = resolve_probe_socket(socket.as_deref(), &resolved_home, home.is_some());
            match platform::restart(&resolved_home, &probe_sock) {
                Ok(report) => emit_report("service restart", &report, as_json),
                Err(e) => emit_error("service restart", as_json, EXIT_ERROR, "SERVICE_RESTART_FAILED", e, Some("Run `hyp service install`.".to_string())),
            }
        }
        ServiceCommand::Status {
            home,
            socket,
            json: as_json,
        } => {
            let Some(resolved_home) = resolve_home_dir(home.as_deref()) else {
                return emit_error(
                    "service status",
                    as_json,
                    EXIT_ERROR,
                    "MISSING_HOME",
                    "Could not determine home directory (set HOME or pass --home <dir>)",
                    None,
                );
            };
            let probe_sock = resolve_probe_socket(socket.as_deref(), &resolved_home, home.is_some());
            match platform::status(&resolved_home, &probe_sock) {
                Ok(report) => emit_report("service status", &report, as_json),
                Err(e) => emit_error("service status", as_json, EXIT_ERROR, "SERVICE_STATUS_FAILED", e, None),
            }
        }
    }
}

fn emit_report(cmd: &str, report: &ServiceActionReport, as_json: bool) -> ExitCode {
    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(report.detail.clone()),
            data: Some(report),
            warnings: Vec::new(),
            next: report.next.clone(),
            error: None,
        };
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
        print_next_steps(&report.next);
    }
    ExitCode::from(EXIT_OK)
}

// ============================================================================
// Pure Unit Tests (Never Mutates Live OS LaunchAgents / systemd!)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec() -> ServiceSpec {
        ServiceSpec {
            bin_path: PathBuf::from("/Users/alice/.local/bin/hyp"),
            state_dir: PathBuf::from("/Users/alice/.config/hyphae"),
            config_path: None,
            socket_path: None,
            logs_dir: PathBuf::from("/Users/alice/.config/hyphae/logs"),
            path_env: build_service_path_env(
                Some("/Users/alice/.local/bin:/usr/bin"),
                Some(Path::new("/Users/alice/.local/bin")),
            ),
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
}
