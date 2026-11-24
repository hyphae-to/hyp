//! `hyp-rs` — Hyphae v2 native hot-path CLI shim (`hook`, `mcp`, `wait`, `watch`, `version`).
//!
//! Performance note: `hyp-rs hook` intercepts `std::env::args()` BEFORE constructing `clap`
//! or Tokio so hook invocations pay zero async-runtime startup overhead (1–3 ms cold start).

use clap::{Parser, Subcommand};
use hyp_harness::hooks::{HandleHookOptions, HookEvent, run_hook_sync, shell_quote_cli};
use hyp_harness::mcp::{McpOptions, run_mcp};
use hyp_harness::protocol::HarnessKind;
use hyp_harness::sock::default_socket_path;
use hyp_harness::wait::{WaitMode, WaitOptions, run_wait};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;

#[derive(Parser)]
#[command(
    name = "hyp-rs",
    about = "Hyphae v2 native hot-path shim (hook, mcp, wait, watch)",
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

/// Zero-clap, zero-Tokio fast path for `hyp-rs hook <harness> <event> [--socket <path>]`.
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
            "error: Invalid hook arguments\nusage: hyp-rs hook <harness> <event> [--socket <path>]"
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
