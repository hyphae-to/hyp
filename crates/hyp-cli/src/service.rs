//! `hyp service` — Background OS service lifecycle for the Hyphae v2 daemon
//! (`macOS LaunchAgent` / `Linux systemd --user` / `Windows Task Scheduler (schtasks)`).
//!
//! Keeps `hyp daemon` strictly foreground (required by LaunchAgent, systemd, Task Scheduler,
//! Docker, and all existing tests) while letting `hyp onboard` and `hyp service install|restart|stop|status`
//! manage a clean auto-restarting background daemon.

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use crate::config_file::{ensure_dir, write_atomic_file};
use crate::config_file::{resolve_home_dir, resolve_state_dir};
use crate::ui::{
    EXIT_ERROR, EXIT_OK, JsonEnvelope, emit_error, print_json, print_next_steps,
};
use clap::Subcommand;
use hyp_harness::sock::{DEFAULT_SOCKET_FILENAME, daemon_rpc_sync, default_socket_path};
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
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const WINDOWS_TASK_NAME: &str = "HyphaeDaemon";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub const WINDOWS_TASK_XML_FILENAME: &str = "hyphae-daemon-task.xml";

const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(3);
const DAEMON_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DAEMON_RPC_TIMEOUT: Duration = Duration::from_millis(250);

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
    pub config_path: Option<PathBuf>,
    pub socket_path: Option<PathBuf>,
    pub logs_dir: PathBuf,
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    pub path_env: String,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub user_id: Option<String>,
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

/// Quotes a single Windows command-line argument following `CommandLineToArgvW` rules
/// (handles spaces, tabs, quotes, and backslashes preceding quotes or the closing quote).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn windows_quote_arg(arg: &str) -> String {
    let needs_quote = arg.is_empty()
        || arg
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '"');
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
        config_path: config_arg.map(Path::to_path_buf),
        socket_path: socket_arg.map(Path::to_path_buf),
        logs_dir,
        path_env,
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

    pub fn status(home: &Path, socket: &Path, _explicit_home: bool) -> Result<ServiceActionReport, String> {
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

    pub fn status(home: &Path, socket: &Path, _explicit_home: bool) -> Result<ServiceActionReport, String> {
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

    pub fn install(spec: &ServiceSpec, _home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        ensure_dir(&spec.state_dir, true)?;
        ensure_dir(&spec.logs_dir, true)?;

        let xml_path = windows_task_xml_path(&spec.state_dir);
        let xml_content = windows_task_xml(spec);
        let xml_bytes = encode_utf16le_bom(&xml_content);
        write_atomic_file(&xml_path, &xml_bytes, true)?;

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
            next: vec![
                "hyp service status".to_string(),
                "hyp doctor".to_string(),
            ],
        })
    }

    pub fn uninstall(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let _ = run_schtasks(&build_schtasks_end_args(WINDOWS_TASK_NAME));
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
            next: vec!["hyp service install".to_string()],
        })
    }

    pub fn start(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
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
            format!("Started Windows scheduled task {WINDOWS_TASK_NAME} (socket still initializing)")
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
            next: vec!["hyp service status".to_string()],
        })
    }

    pub fn stop(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let state_dir = resolve_state_dir(None, None, Some(home));
        let xml_path = windows_task_xml_path(&state_dir);
        let _ = run_schtasks(&build_schtasks_end_args(WINDOWS_TASK_NAME));
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
            next: vec!["hyp service start".to_string()],
        })
    }

    pub fn restart(home: &Path, socket: &Path) -> Result<ServiceActionReport, String> {
        let state_dir = resolve_state_dir(None, None, Some(home));
        let xml_path = windows_task_xml_path(&state_dir);
        let (installed, _running) = query_task(WINDOWS_TASK_NAME);
        if !installed {
            return Err(format!(
                "Windows scheduled task {WINDOWS_TASK_NAME} is not installed (run `hyp service install` first)"
            ));
        }

        let _ = run_schtasks(&build_schtasks_end_args(WINDOWS_TASK_NAME));
        thread::sleep(Duration::from_millis(250));
        let run_out = run_schtasks(&build_schtasks_run_args(WINDOWS_TASK_NAME))?;
        check_schtasks_ok(&run_out, "/Run")?;

        let probe = wait_for_daemon_alive(socket, DAEMON_READY_TIMEOUT);
        let detail = if probe.alive {
            format!("Restarted Windows scheduled task {WINDOWS_TASK_NAME} (daemon responding)")
        } else {
            format!("Restarted Windows scheduled task {WINDOWS_TASK_NAME} (socket still initializing)")
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
        let (installed, loaded) = if explicit_home && !xml_exists {
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

    pub fn status(_home: &Path, socket: &Path, _explicit_home: bool) -> Result<ServiceActionReport, String> {
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
            let probe_sock = resolve_probe_socket(
                socket.as_deref(),
                state_dir.as_deref(),
                &resolved_home,
                home.is_some(),
            );
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
            let probe_sock = resolve_probe_socket(None, None, &resolved_home, home.is_some());
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
            let probe_sock =
                resolve_probe_socket(socket.as_deref(), None, &resolved_home, home.is_some());
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
            let probe_sock = resolve_probe_socket(None, None, &resolved_home, home.is_some());
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
            let probe_sock =
                resolve_probe_socket(socket.as_deref(), None, &resolved_home, home.is_some());
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
            let probe_sock =
                resolve_probe_socket(socket.as_deref(), None, &resolved_home, home.is_some());
            match platform::status(&resolved_home, &probe_sock, home.is_some()) {
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
// Pure Unit Tests (Never Mutates Live OS LaunchAgents / systemd / Task Scheduler!)
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
            config_path: Some(PathBuf::from(r#"C:\Users\O'Malley & Co\cfg "v2"\node.json"#)),
            socket_path: Some(PathBuf::from(r"C:\Users\O'Malley & Co\.config\hyphae\connector.addr")),
            logs_dir: PathBuf::from(r"C:\Users\O'Malley & Co\.config\hyphae\logs"),
            path_env: String::new(),
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
        assert!(xml.contains("<Arguments>daemon --state-dir /Users/alice/.config/hyphae</Arguments>"));
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
        assert_eq!(parse_schtasks_query_output(csv_verbose_running), (true, true));

        let csv_header_only = "\"TaskName\",\"Next Run Time\",\"Status\"\r\n";
        assert_eq!(parse_schtasks_query_output(csv_header_only), (false, false));

        let csv_nh_running = "\"\\HyphaeDaemon\",\"N/A\",\"Running\"\r\n";
        assert_eq!(parse_schtasks_query_output(csv_nh_running), (true, true));

        let csv_nh_verbose_ready = "\"MYPC\",\"\\HyphaeDaemon\",\"N/A\",\"Ready\",\"C:\\Running\\hyp.exe\"\r\n";
        assert_eq!(parse_schtasks_query_output(csv_nh_verbose_ready), (true, false));
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
