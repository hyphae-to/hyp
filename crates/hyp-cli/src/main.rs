//! `hyp` — Hyphae v2 native CLI (`hook`, `statusline`, `mcp`, `wait`, `watch`, `node`/`daemon`,
//! `onboard`, `setup`, `inspect`, `session`, `ui`, `status`, `doctor`, `secret`, `gate`, `inbox`,
//! `kv`, `emit`, `auth`, `drop`, `relay`, `update`, `deploy`, `pair`, `version`).
//!
//! Performance note: `hyp hook` and `hyp statusline` intercept `std::env::args()` BEFORE
//! constructing `clap` or Tokio so hot invocations pay zero async-runtime startup overhead (1–5 ms).

mod auth_cmd;
mod config_file;
mod deploy;
mod drop_cmd;
mod emit_cmd;
mod gate_cmd;
mod herdr_mod;
mod inspect_cmd;
mod kv_cmd;
mod node_cmd;
mod pair;
mod secret_cmd;
mod service;
mod session_cmd;
mod setup;
mod skill_render;
mod status_doctor;
mod statusline_cmd;
mod ui;
mod ui_tui;
mod uninstall_cmd;
mod update;
mod wizard;

use clap::{Parser, Subcommand};
use hyp_harness::hooks::{
    HandleHookOptions, HookEvent, HookTransportHints, run_hook_sync, shell_quote_cli,
};
use hyp_harness::mcp::{McpOptions, run_mcp};
use hyp_harness::protocol::HarnessKind;
use hyp_harness::sock::default_socket_path;
use hyp_harness::wait::{WaitMode, WaitOptions, run_wait};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::ui::{EXIT_ERROR, EXIT_OK, EXIT_USAGE};

#[derive(Parser)]
#[command(
    name = "hyp",
    about = "Hyphae v2 native CLI (hook, statusline, mcp, wait, watch, node, onboard, setup, inspect, session, ui, status, doctor, secret, gate, inbox, kv, emit, auth, drop, relay, update, uninstall, deploy, pair, version)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ultra-fast synchronous harness hook shim (1-3 ms cold start)
    Hook {
        /// Harness name (antigravity, claude, codex, cursor, opencode, gemini, openclaw, herdr, t3)
        harness: String,
        /// Lifecycle event (pre-tool-use|PreToolUse, post-tool-use|PostToolUse, pre-invocation|PreInvocation, stop|Stop, session-start|SessionStart)
        event: String,
        /// Explicit connector.sock path
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Stdio JSON-RPC 2.0 MCP server bridging to local hyp daemon (4 core tools + conditional hyp_bridge)
    Mcp {
        /// Optional connector.sock path (defaults to HYPHAE_SOCKET / ~/.config/hyphae/state/connector.sock)
        socket: Option<PathBuf>,
        /// Opt-in Claude CLI native push channel (`notifications/claude/channel`)
        #[arg(long)]
        claude_channel: bool,
        /// Optional explicit backend override
        #[arg(long)]
        backend: Option<String>,
        /// Explicit standalone thread UUID (e.g. codex or t3)
        #[arg(long)]
        thread: Option<String>,
        /// Allow `codex queue --resume` for explicit --thread mode
        #[arg(long)]
        resume: bool,
        /// Optional `codex queue --remote <addr>`
        #[arg(long)]
        remote: Option<String>,
        /// Optional T3 Code server URL override
        #[arg(long)]
        t3_url: Option<String>,
        /// Optional T3 Code base directory (`T3CODE_HOME`)
        #[arg(long)]
        t3_base_dir: Option<String>,
        /// Opt-in ephemeral per-process session ID (for scratch testing without hooks)
        #[arg(long)]
        ephemeral: bool,
    },
    /// Zero-polling blocking waiter (exits 0 on first item, timeout, or signal)
    Wait {
        /// Stream NDJSON items continuously instead of exiting after the first batch
        #[arg(long)]
        stream: bool,
        /// Session ID (e.g. antigravity:<id>, claude:<id>)
        #[arg(long)]
        session: Option<String>,
        /// Enrolled handle to wait on
        #[arg(long)]
        handle: Option<String>,
        /// Explicit connector.sock path
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Optional timeout in seconds (0 = wait indefinitely)
        #[arg(long)]
        timeout: Option<f64>,
        /// Emit agent-first JSON envelope for one-shot wait output
        #[arg(long)]
        json: bool,
    },
    /// Zero-polling streaming watcher (NDJSON line per item, ideal for Monitor)
    Watch {
        /// Session ID (e.g. claude:<id>)
        #[arg(long)]
        session: Option<String>,
        /// Enrolled handle to watch
        #[arg(long)]
        handle: Option<String>,
        /// Explicit connector.sock path
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Optional timeout in seconds (0 = watch indefinitely)
        #[arg(long)]
        timeout: Option<f64>,
    },
    /// Unified Hyphae v2 Node lifecycle commands (`node start`)
    Node {
        #[command(subcommand)]
        command: node_cmd::NodeCommand,
    },
    /// Alias for `node start` — runs the unified Hyphae v2 Node daemon
    Daemon(node_cmd::NodeStartArgs),
    /// Manage the Hyphae background daemon OS service (`install`, `uninstall`, `start`, `stop`, `restart`, `status`)
    Service {
        #[command(subcommand)]
        command: service::ServiceCommand,
    },
    /// Configure hooks & MCP entries for installed agent harnesses pointing to the static Rust binary
    Setup(setup::SetupArgs),
    /// One-command Hyphae v2 onboarding (node.json, persistent keys, optional join token, harness setup)
    Onboard(setup::OnboardArgs),
    /// Render Node identity, Peer Capabilities & Version Skew table, Security Gate, and update status
    Status(status_doctor::StatusArgs),
    /// Run fail-closed diagnostics across node.sqlite, peer skew, gate_policy_sig, and harness setup
    Doctor(status_doctor::DoctorArgs),
    /// Zero-leak OS Keychain / Secret Service / 0600 file secret management (stdin or one-shot --web)
    Secret {
        #[command(subcommand)]
        command: secret_cmd::SecretCommand,
    },
    /// Local Security Gate configuration, tamper-evident signing (`lock`), quarantine `review`, and `log`
    Gate {
        #[command(subcommand)]
        command: gate_cmd::GateCommand,
    },
    /// Human-CLI-only quarantine inbox disposition (`approve` / `reject`)
    Inbox {
        #[command(subcommand)]
        command: gate_cmd::InboxCommand,
    },
    /// Direct CLI access to Shared KV / Blackboard (`get`, `set`, `delete`, `list` with CAS)
    Kv {
        #[command(subcommand)]
        command: kv_cmd::KvCommand,
    },
    /// Emit a CloudEvent v1.0 (or stdin JSON) to the local ingest socket (ideal for cron/systemd/launchd)
    Emit(emit_cmd::EmitArgs),
    /// Tier 1 Ed25519 Human Authority management, node certification (`hcert1_`), and drop signing (`hdrop1_`)
    Auth {
        #[command(subcommand)]
        command: auth_cmd::AuthCommand,
    },
    /// Verified Human Drops (`create`, `wait`, `ingest` — zero-leak secret & directive drops)
    Drop {
        #[command(subcommand)]
        command: drop_cmd::DropCommand,
    },
    /// Blind Ephemeral Drop Relay configuration and health inspection (`set`, `status`)
    Relay {
        #[command(subcommand)]
        command: drop_cmd::RelayCommand,
    },
    /// Cryptographically signed self-update, release channels, and `--all` fleet rollout
    Update(update::UpdateArgs),
    /// Cleanly uninstall Hyphae (stops daemons, restores chained statusLines, removes hooks/skills/mods/state/binary)
    Uninstall(uninstall_cmd::UninstallArgs),
    /// Internet deployment provider catalog, hardened kit generator, and fail-closed health checks
    Deploy {
        #[command(subcommand)]
        command: deploy::DeployCommand,
    },
    /// Permissioned pairing guide, hp2p1_/am2_ invite generation, stdin-safe inspection/acceptance, and node join
    Pair {
        #[command(subcommand)]
        command: pair::PairCommand,
    },
    /// Ultra-fast status bar pill for Claude Code, Antigravity & generic harnesses (<5 ms cold start)
    Statusline(statusline_cmd::StatuslineArgs),
    /// Inspect live session state, subscriptions, queued metadata, rules, mutes & channels (--watch supported)
    Inspect(inspect_cmd::InspectArgs),
    /// Quick session controls (`focus`, `mute`, `unmute`, `rule`, `unsubscribe`, `leave`)
    Session(session_cmd::SessionArgs),
    /// Interactive zero-dependency fullscreen terminal UI for live sessions, subscriptions & controls
    Ui(ui_tui::UiArgs),
    /// Print version info (supports --json agent-first envelope)
    Version {
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

fn current_cli_command() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .map(|s| shell_quote_cli(&s))
        .unwrap_or_else(|| "hyp".to_string())
}

/// Zero-clap, zero-Tokio fast path for `hyp hook <harness> <event> [--socket <path>]`.
/// Returns `Some(ExitCode)` when handled directly, or `None` to fall through to `clap` (e.g. `--help`).
fn try_hook_fast_path() -> Option<ExitCode> {
    let mut args = std::env::args();
    let _bin = args.next()?;
    let cmd = args.next()?;
    if cmd != "hook" {
        return None;
    }

    let rest: Vec<String> = args.collect();
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        return None;
    }

    let mut positionals: Vec<String> = Vec::with_capacity(2);
    let mut explicit_socket: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        let arg = &rest[i];
        if arg == "--socket" {
            if i + 1 >= rest.len() {
                eprintln!("error: --socket requires a path");
                return Some(ExitCode::from(EXIT_USAGE));
            }
            explicit_socket = Some(rest[i + 1].clone());
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--socket=") {
            explicit_socket = Some(val.to_string());
            i += 1;
        } else if arg.starts_with('-') {
            eprintln!("error: unknown option '{arg}'");
            return Some(ExitCode::from(EXIT_USAGE));
        } else {
            positionals.push(arg.clone());
            i += 1;
        }
    }

    if positionals.len() != 2 {
        eprintln!(
            "error: Invalid hook arguments\nusage: hyp hook <harness> <event> [--socket <path>]"
        );
        return Some(ExitCode::from(EXIT_USAGE));
    }

    let Ok(harness) = positionals[0].parse::<HarnessKind>() else {
        eprintln!("error: Unknown harness '{}'", positionals[0]);
        return Some(ExitCode::from(EXIT_USAGE));
    };
    let Ok(event) = positionals[1].parse::<HookEvent>() else {
        eprintln!("error: Unknown hook event '{}'", positionals[1]);
        return Some(ExitCode::from(EXIT_USAGE));
    };

    let socket_path = explicit_socket
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);

    let options = HandleHookOptions {
        harness,
        event,
        socket_path,
        cli_path: Some(current_cli_command()),
        explicit_socket,
        transport_hints: HookTransportHints::from_env(),
    };
    run_hook_sync(&options);
    Some(ExitCode::from(EXIT_OK))
}

fn build_current_thread_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to start async runtime: {e}"))
}

fn main() -> ExitCode {
    if let Some(code) = try_hook_fast_path() {
        return code;
    }
    if let Some(code) = statusline_cmd::try_statusline_fast_path() {
        return code;
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::Hook {
            harness,
            event,
            socket,
        } => {
            let Ok(harness) = harness.parse::<HarnessKind>() else {
                eprintln!("error: Unknown harness '{harness}'");
                return ExitCode::from(EXIT_USAGE);
            };
            let Ok(event) = event.parse::<HookEvent>() else {
                eprintln!("error: Unknown hook event '{event}'");
                return ExitCode::from(EXIT_USAGE);
            };
            let explicit_socket = socket.as_ref().map(|p| p.display().to_string());
            let socket_path = socket.unwrap_or_else(default_socket_path);
            run_hook_sync(&HandleHookOptions {
                harness,
                event,
                socket_path,
                cli_path: Some(current_cli_command()),
                explicit_socket,
                transport_hints: HookTransportHints::from_env(),
            });
            ExitCode::from(EXIT_OK)
        }
        Commands::Mcp {
            socket,
            claude_channel,
            backend,
            thread,
            resume,
            remote,
            t3_url,
            t3_base_dir,
            ephemeral,
        } => {
            let parsed_backend = match backend {
                Some(b) => match b.parse::<HarnessKind>() {
                    Ok(kind) => Some(kind),
                    Err(e) => {
                        eprintln!("error: {e}");
                        return ExitCode::from(EXIT_USAGE);
                    }
                },
                None => None,
            };
            let options = McpOptions {
                socket_path: socket.unwrap_or_else(default_socket_path),
                backend: parsed_backend,
                channel: claude_channel,
                thread_id: thread,
                resume,
                remote,
                t3_url,
                t3_base_dir,
                ephemeral,
            };
            let rt = match build_current_thread_runtime() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(EXIT_ERROR);
                }
            };
            match rt.block_on(run_mcp(options)) {
                Ok(()) => ExitCode::from(EXIT_OK),
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(EXIT_ERROR)
                }
            }
        }
        Commands::Wait {
            stream,
            session,
            handle,
            socket,
            timeout,
            json: as_json,
        } => {
            if let Some(secs) = timeout {
                if !secs.is_finite() || secs < 0.0 {
                    eprintln!("error: Expected non-negative --timeout seconds");
                    return ExitCode::from(EXIT_USAGE);
                }
            }
            let rt = match build_current_thread_runtime() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(EXIT_ERROR);
                }
            };
            let opts = WaitOptions {
                socket_path: socket.unwrap_or_else(default_socket_path),
                mode: if stream {
                    WaitMode::Stream
                } else {
                    WaitMode::Once
                },
                session_id: session,
                handle,
                timeout_seconds: timeout,
                json: as_json,
            };
            match rt.block_on(run_wait(opts)) {
                Ok(code) => ExitCode::from(code as u8),
                Err(e) => {
                    if as_json {
                        let envelope = json!({
                            "ok": false,
                            "command": "wait",
                            "error": { "code": "WAIT_FAILED", "message": e.to_string() }
                        });
                        println!("{envelope}");
                    } else {
                        eprintln!("error: {e}");
                    }
                    ExitCode::from(EXIT_ERROR)
                }
            }
        }
        Commands::Watch {
            session,
            handle,
            socket,
            timeout,
        } => {
            if let Some(secs) = timeout {
                if !secs.is_finite() || secs < 0.0 {
                    eprintln!("error: Expected non-negative --timeout seconds");
                    return ExitCode::from(EXIT_USAGE);
                }
            }
            let rt = match build_current_thread_runtime() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(EXIT_ERROR);
                }
            };
            let opts = WaitOptions {
                socket_path: socket.unwrap_or_else(default_socket_path),
                mode: WaitMode::Stream,
                session_id: session,
                handle,
                timeout_seconds: timeout,
                json: false,
            };
            match rt.block_on(run_wait(opts)) {
                Ok(code) => ExitCode::from(code as u8),
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(EXIT_ERROR)
                }
            }
        }
        Commands::Node { command } => node_cmd::run_node(command),
        Commands::Daemon(args) => node_cmd::run_node_start(args),
        Commands::Service { command } => service::run_service(command),
        Commands::Setup(args) => setup::run_setup(args),
        Commands::Onboard(args) => setup::run_onboard(args),
        Commands::Status(args) => status_doctor::run_status(args),
        Commands::Doctor(args) => status_doctor::run_doctor(args),
        Commands::Secret { command } => secret_cmd::run_secret(command),
        Commands::Gate { command } => gate_cmd::run_gate(command),
        Commands::Inbox { command } => gate_cmd::run_inbox(command),
        Commands::Kv { command } => kv_cmd::run_kv(command),
        Commands::Emit(args) => emit_cmd::run_emit(args),
        Commands::Auth { command } => auth_cmd::run_auth(command),
        Commands::Drop { command } => drop_cmd::run_drop(command),
        Commands::Relay { command } => drop_cmd::run_relay(command),
        Commands::Update(args) => update::run_update(args),
        Commands::Uninstall(args) => uninstall_cmd::run_uninstall(args),
        Commands::Deploy { command } => deploy::run_deploy(command),
        Commands::Pair { command } => pair::run_pair(command),
        Commands::Statusline(args) => statusline_cmd::run_statusline(&args),
        Commands::Inspect(args) => inspect_cmd::run_inspect(&args),
        Commands::Session(args) => session_cmd::run_session(&args),
        Commands::Ui(args) => ui_tui::run_ui(&args),
        Commands::Version { json: as_json } => {
            let version = env!("CARGO_PKG_VERSION");
            if as_json {
                let envelope = json!({
                    "ok": true,
                    "command": "version",
                    "summary": format!("hyphae {version}"),
                    "data": {
                        "name": "hyphae",
                        "version": version,
                        "protocol": hyp_proto::PROTOCOL_VERSION
                    }
                });
                println!("{envelope}");
            } else {
                println!("hyphae {version}");
            }
            ExitCode::from(EXIT_OK)
        }
    }
}
