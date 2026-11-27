//! Ultra-fast `hyp statusline` command for Claude Code, Antigravity, and generic harnesses.
//!
//! Performance contract:
//! - Executed from `try_statusline_fast_path()` in `main.rs` BEFORE `clap::Parser` or Tokio
//!   runtime initialization so hot-path execution completes in ~1–5 ms.
//! - Uses zero-Tokio synchronous `hyp_harness_ipc::sock::daemon_rpc_sync` with a tight 150 ms
//!   timeout (`connector.sock` on Unix, `connector.addr` loopback TCP on Windows).
//! - Fails safe (exit 0) when the daemon is offline, stdin is malformed/oversized, or a
//!   chained user statusLine command fails, so it never breaks the host prompt bar.
//!
//! Security contract:
//! - Reads at most 64 KiB from stdin.
//! - Strips all C0/C1 control characters, bidi overrides, and ANSI CSI/OSC/DCS/ESC escape
//!   sequences from every untrusted string (`handle`, `nodeId`, etc.) before printing.

use crate::ui::{EXIT_OK, EXIT_USAGE};
use clap::{Args, ValueEnum};
use hyp_harness_client::wait::{infer_herdr_terminal_from_env, infer_session_id_from_env};
use hyp_harness_ipc::caller::is_valid_session_id;
use hyp_harness_ipc::sock::{daemon_rpc_sync, default_socket_path};
use serde_json::{Map, Value, json};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum stdin payload accepted from a host statusLine pipe (64 KiB).
pub const MAX_STATUSLINE_STDIN_BYTES: usize = 64 * 1024;
/// Maximum size of a `--chain-file` config file (64 KiB).
const MAX_CHAIN_FILE_BYTES: usize = 64 * 1024;
/// Maximum stdout captured from a chained statusLine command (64 KiB).
const MAX_CHAIN_OUTPUT_BYTES: usize = 64 * 1024;
/// Bounded timeout for executing a chained user statusLine command.
const CHAIN_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
/// Tight synchronous RPC timeout for `session.summary` so the status bar never stalls.
const STATUSLINE_RPC_TIMEOUT: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StatuslineHarness {
    Claude,
    Antigravity,
    Generic,
}

impl StatuslineHarness {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "claude" | "claude-code" => Some(Self::Claude),
            "antigravity" | "agy" => Some(Self::Antigravity),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }

    pub const fn prefix(self) -> Option<&'static str> {
        match self {
            Self::Claude => Some("claude"),
            Self::Antigravity => Some("antigravity"),
            Self::Generic => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WhenUnenrolled {
    Hide,
    Dim,
}

impl WhenUnenrolled {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "hide" => Some(Self::Hide),
            "dim" => Some(Self::Dim),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct StatuslineArgs {
    /// Host harness stdin JSON schema (claude, antigravity, generic)
    #[arg(long, value_enum, default_value_t = StatuslineHarness::Claude)]
    pub harness: StatuslineHarness,
    /// Explicit session ID override (e.g. claude:<id>)
    #[arg(long)]
    pub session: Option<String>,
    /// Explicit Herdr terminal ID override (e.g. t4g)
    #[arg(long)]
    pub herdr_terminal: Option<String>,
    /// Optional Herdr terminal creation timestamp (ms) anti-recycle pin
    #[arg(long)]
    pub herdr_created_ms: Option<i64>,
    /// Explicit connector.sock / connector.addr path
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Behavior when session is unenrolled with zero subs/queued (hide or dim)
    #[arg(long, value_enum, default_value_t = WhenUnenrolled::Hide)]
    pub when_unenrolled: WhenUnenrolled,
    /// Disable ANSI color escapes (also honors NO_COLOR)
    #[arg(long)]
    pub plain: bool,
    /// Path to a JSON or shell-command file describing a wrapped user statusLine command
    #[arg(long)]
    pub chain_file: Option<PathBuf>,
    /// Output raw structured session.summary JSON envelope for scripting
    #[arg(long)]
    pub json: bool,
}

impl Default for StatuslineArgs {
    fn default() -> Self {
        Self {
            harness: StatuslineHarness::Claude,
            session: None,
            herdr_terminal: None,
            herdr_created_ms: None,
            socket: None,
            when_unenrolled: WhenUnenrolled::Hide,
            plain: false,
            chain_file: None,
            json: false,
        }
    }
}

/// Strips ALL ANSI escape sequences (CSI, OSC, DCS/SOS/PM/APC, 2-byte ESC, 8-bit C1 CSI/OSC),
/// C0/C1 control characters (`\x00..\x1f`, `\x7f`, `\u{80}..\u{9f}`), and Unicode bidi overrides
/// from untrusted strings before writing them to any terminal or statusline.
pub fn sanitize_terminal_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\x1b' => {
                match chars.peek().copied() {
                    Some('[') => {
                        // CSI sequence: ESC [ [0x30..=0x3f]* [0x20..=0x2f]* [0x40..=0x7e]
                        chars.next();
                        for c in chars.by_ref() {
                            if ('\x40'..='\x7e').contains(&c) {
                                break;
                            }
                        }
                    }
                    Some(']') | Some('P') | Some('X') | Some('^') | Some('_') => {
                        // OSC / DCS / SOS / PM / APC: terminated by BEL (\x07), ST (ESC \), or 8-bit ST (\u{9c}).
                        // Unterminated sequences consume to EOF so payload cannot leak.
                        chars.next();
                        while let Some(c) = chars.next() {
                            if c == '\x07' || c == '\u{009c}' {
                                break;
                            }
                            if c == '\x1b' && chars.peek() == Some(&'\\') {
                                chars.next();
                                break;
                            }
                        }
                    }
                    Some(next) if ('\x20'..='\x7e').contains(&next) => {
                        // 2-byte ESC sequence (e.g. ESC c, ESC ( B, ESC 7/8).
                        chars.next();
                        if ('\x20'..='\x2f').contains(&next) {
                            for c in chars.by_ref() {
                                if ('\x30'..='\x7e').contains(&c) {
                                    break;
                                }
                            }
                        }
                    }
                    _ => {
                        // Bare ESC at end or before control byte: drop ESC only.
                    }
                }
            }
            '\u{009b}' => {
                // 8-bit CSI
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            '\u{009d}' | '\u{0090}' | '\u{0098}' | '\u{009e}' | '\u{009f}' => {
                // 8-bit OSC / DCS / SOS / PM / APC
                while let Some(c) = chars.next() {
                    if c == '\x07' || c == '\u{009c}' {
                        break;
                    }
                    if c == '\x1b' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            c if c.is_control() => {
                // Drops C0 (\x00..\x1f), DEL (\x7f), and C1 (\u{80}..\u{9f}).
            }
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {
                // Drops Unicode bidirectional override / isolate characters.
            }
            c => out.push(c),
        }
    }

    out
}

/// Zero-clap, zero-Tokio fast path invoked BEFORE `Cli::parse()` in `main.rs`.
/// Returns `Some(ExitCode)` when handled directly, or `None` to fall through to `clap`
/// (e.g. for `-h` / `--help`).
pub fn try_statusline_fast_path() -> Option<ExitCode> {
    let mut args = std::env::args();
    let _bin = args.next()?;
    let cmd = args.next()?;
    if cmd != "statusline" {
        return None;
    }

    let rest: Vec<String> = args.collect();
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        return None;
    }

    match parse_fast_path_args(&rest) {
        Ok(parsed) => Some(run_statusline(&parsed)),
        Err(msg) => {
            eprintln!("error: {msg}");
            Some(ExitCode::from(EXIT_USAGE))
        }
    }
}

pub fn parse_fast_path_args(rest: &[String]) -> Result<StatuslineArgs, String> {
    let mut out = StatuslineArgs::default();
    let mut i = 0;

    while i < rest.len() {
        let arg = &rest[i];
        if arg == "--plain" {
            out.plain = true;
            i += 1;
        } else if arg == "--json" {
            out.json = true;
            i += 1;
        } else if let Some((flag, val)) = take_flag_value(rest, &mut i, "--harness")? {
            let _ = flag;
            out.harness = StatuslineHarness::parse(&val).ok_or_else(|| {
                format!("Invalid --harness '{val}' (expected claude, antigravity, or generic)")
            })?;
        } else if let Some((_, val)) = take_flag_value(rest, &mut i, "--session")? {
            out.session = Some(val);
        } else if let Some((_, val)) = take_flag_value(rest, &mut i, "--herdr-terminal")? {
            out.herdr_terminal = Some(val);
        } else if let Some((_, val)) = take_flag_value(rest, &mut i, "--herdr-created-ms")? {
            let ms = val
                .trim()
                .parse::<i64>()
                .map_err(|_| format!("Invalid --herdr-created-ms '{val}' (expected integer)"))?;
            out.herdr_created_ms = Some(ms);
        } else if let Some((_, val)) = take_flag_value(rest, &mut i, "--socket")? {
            out.socket = Some(PathBuf::from(val));
        } else if let Some((_, val)) = take_flag_value(rest, &mut i, "--when-unenrolled")? {
            out.when_unenrolled = WhenUnenrolled::parse(&val).ok_or_else(|| {
                format!("Invalid --when-unenrolled '{val}' (expected hide or dim)")
            })?;
        } else if let Some((_, val)) = take_flag_value(rest, &mut i, "--chain-file")? {
            out.chain_file = Some(PathBuf::from(val));
        } else {
            return Err(format!("unknown option '{arg}'"));
        }
    }

    Ok(out)
}

fn take_flag_value(
    rest: &[String],
    idx: &mut usize,
    name: &str,
) -> Result<Option<(&'static str, String)>, String> {
    let arg = &rest[*idx];
    if arg == name {
        if *idx + 1 >= rest.len() {
            return Err(format!("{name} requires a value"));
        }
        let val = rest[*idx + 1].clone();
        *idx += 2;
        return Ok(Some(("", val)));
    }
    let prefix = format!("{name}=");
    if let Some(val) = arg.strip_prefix(&prefix) {
        *idx += 1;
        return Ok(Some(("", val.to_string())));
    }
    Ok(None)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedStdinContext {
    pub session_id: Option<String>,
    pub cwd: Option<String>,
}

/// Qualifies a raw session/conversation ID with the harness prefix if not already prefixed.
pub fn qualify_session_id(harness: StatuslineHarness, raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let qualified = match harness.prefix() {
        Some(prefix) => {
            if trimmed.contains(':') {
                trimmed.to_string()
            } else {
                format!("{prefix}:{trimmed}")
            }
        }
        None => trimmed.to_string(),
    };
    if is_valid_session_id(&qualified) {
        Some(qualified)
    } else {
        None
    }
}

/// Parses bounded Claude Code / Antigravity / generic `statusLine` JSON stdin payload.
pub fn parse_statusline_stdin(harness: StatuslineHarness, bytes: &[u8]) -> ParsedStdinContext {
    if bytes.is_empty() || bytes.len() > MAX_STATUSLINE_STDIN_BYTES {
        return ParsedStdinContext::default();
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return ParsedStdinContext::default();
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return ParsedStdinContext::default();
    }
    let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(trimmed) else {
        return ParsedStdinContext::default();
    };

    let raw_id = match harness {
        StatuslineHarness::Antigravity => obj
            .get("conversation_id")
            .or_else(|| obj.get("conversationId"))
            .or_else(|| obj.get("session_id"))
            .or_else(|| obj.get("sessionId"))
            .and_then(Value::as_str),
        StatuslineHarness::Claude => obj
            .get("session_id")
            .or_else(|| obj.get("sessionId"))
            .or_else(|| obj.get("conversation_id"))
            .or_else(|| obj.get("conversationId"))
            .and_then(Value::as_str),
        StatuslineHarness::Generic => obj
            .get("session_id")
            .or_else(|| obj.get("sessionId"))
            .or_else(|| obj.get("conversation_id"))
            .or_else(|| obj.get("conversationId"))
            .or_else(|| obj.get("thread_id"))
            .or_else(|| obj.get("threadId"))
            .and_then(Value::as_str),
    };

    let session_id = raw_id.and_then(|id| qualify_session_id(harness, id));

    let cwd = obj
        .get("workspace")
        .and_then(Value::as_object)
        .and_then(|ws| {
            ws.get("current_dir")
                .or_else(|| ws.get("currentDir"))
                .or_else(|| ws.get("project_dir"))
                .or_else(|| ws.get("projectDir"))
        })
        .or_else(|| obj.get("cwd"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control))
        .map(ToString::to_string);

    ParsedStdinContext { session_id, cwd }
}

fn read_bounded_stdin() -> Vec<u8> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let mut handle = stdin.lock().take((MAX_STATUSLINE_STDIN_BYTES + 1) as u64);
    let _ = handle.read_to_end(&mut buf);
    buf
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainSpec {
    Direct { command: String, args: Vec<String> },
    Shell(String),
}

pub fn parse_chain_file_contents(raw: &str) -> Option<ChainSpec> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        match val {
            Value::String(s) => {
                let s = s.trim();
                if s.is_empty() {
                    None
                } else {
                    Some(ChainSpec::Shell(s.to_string()))
                }
            }
            Value::Object(obj) => {
                let cmd = obj.get("command").and_then(Value::as_str)?.trim();
                if cmd.is_empty() {
                    return None;
                }
                if let Some(arr) = obj.get("args").and_then(Value::as_array) {
                    let mut args = Vec::with_capacity(arr.len());
                    for item in arr {
                        let s = item.as_str()?;
                        args.push(s.to_string());
                    }
                    Some(ChainSpec::Direct {
                        command: cmd.to_string(),
                        args,
                    })
                } else {
                    Some(ChainSpec::Shell(cmd.to_string()))
                }
            }
            _ => None,
        }
    } else {
        // Plain-text shell command fallback (first non-empty line).
        let line = trimmed.lines().find(|l| !l.trim().is_empty())?.trim();
        Some(ChainSpec::Shell(line.to_string()))
    }
}

fn execute_chain_file(path: &Path, stdin_bytes: &[u8]) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut raw = String::new();
    file.take(MAX_CHAIN_FILE_BYTES as u64)
        .read_to_string(&mut raw)
        .ok()?;
    let spec = parse_chain_file_contents(&raw)?;

    let mut cmd = match spec {
        ChainSpec::Direct { command, args } => {
            let mut c = Command::new(command);
            c.args(args);
            c
        }
        ChainSpec::Shell(script) => {
            #[cfg(unix)]
            {
                let mut c = Command::new("sh");
                c.arg("-c").arg(script);
                c
            }
            #[cfg(not(unix))]
            {
                let mut c = Command::new("cmd");
                c.arg("/C").arg(script);
                c
            }
        }
    };

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().ok()?;

    // Forward original stdin bytes bounded on a helper thread so large pipes cannot deadlock.
    let forwarded = stdin_bytes[..stdin_bytes.len().min(MAX_STATUSLINE_STDIN_BYTES)].to_vec();
    if let Some(mut child_stdin) = child.stdin.take() {
        if !forwarded.is_empty() {
            thread::spawn(move || {
                let _ = child_stdin.write_all(&forwarded);
                let _ = child_stdin.flush();
            });
        }
    }

    let stdout_handle = child.stdout.take().map(|stdout| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout
                .take(MAX_CHAIN_OUTPUT_BYTES as u64)
                .read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + CHAIN_COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };

    let status = status?;
    if !status.success() {
        return None;
    }

    let out_bytes = stdout_handle?.join().ok()?;
    let text = String::from_utf8_lossy(&out_bytes);
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn color_enabled(plain_flag: bool) -> bool {
    if plain_flag {
        return false;
    }
    std::env::var("NO_COLOR").ok().is_none_or(|v| v.is_empty())
}

/// Formats the Hyphae statusline pill from a `session.summary` response result.
/// Returns `None` when the statusline should be suppressed (e.g. `--when-unenrolled hide`).
pub fn format_statusline_pill(
    summary: Option<&Map<String, Value>>,
    when_unenrolled: WhenUnenrolled,
    use_color: bool,
) -> Option<String> {
    let Some(envelope) = summary else {
        // Daemon offline / unreachable.
        return match when_unenrolled {
            WhenUnenrolled::Hide => None,
            WhenUnenrolled::Dim => {
                if use_color {
                    Some("\x1b[2mhyphae: offline\x1b[0m".to_string())
                } else {
                    Some("hyphae: offline".to_string())
                }
            }
        };
    };

    let quarantined_global = envelope
        .get("daemon")
        .and_then(Value::as_object)
        .and_then(|d| d.get("quarantinedGlobal"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let sess = envelope.get("session").and_then(Value::as_object);
    let Some(sess) = sess else {
        if quarantined_global > 0 {
            let id_seg = if use_color {
                "\x1b[32mhyphae\x1b[0m".to_string()
            } else {
                "hyphae".to_string()
            };
            let q_seg = if use_color {
                format!("\x1b[1;31m⚠ {quarantined_global} held\x1b[0m")
            } else {
                format!("⚠ {quarantined_global} held")
            };
            let sep = if use_color {
                "\x1b[2m · \x1b[0m"
            } else {
                " · "
            };
            return Some(format!("{id_seg}{sep}{q_seg}"));
        }
        return match when_unenrolled {
            WhenUnenrolled::Hide => None,
            WhenUnenrolled::Dim => {
                if use_color {
                    Some("\x1b[2mhyphae: idle\x1b[0m".to_string())
                } else {
                    Some("hyphae: idle".to_string())
                }
            }
        };
    };

    let enrolled = sess
        .get("enrolled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let counts = sess.get("counts").and_then(Value::as_object);
    let subs = counts
        .and_then(|c| c.get("subscriptions"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let bridge_labels: Vec<String> = sess
        .get("bridges")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(sanitize_terminal_text)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let bridges = counts
        .and_then(|c| c.get("bridges"))
        .and_then(Value::as_u64)
        .unwrap_or(bridge_labels.len() as u64);
    let queued = counts
        .and_then(|c| c.get("queued"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let session_quarantined = counts
        .and_then(|c| c.get("quarantined"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let quarantined = session_quarantined.max(quarantined_global);
    let muted_rules = counts
        .and_then(|c| c.get("mutedRules"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let focus_mode = sess
        .get("focusMode")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let muted_all = sess
        .get("mutedAll")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if !enrolled && subs == 0 && bridges == 0 && queued == 0 && quarantined == 0 {
        return match when_unenrolled {
            WhenUnenrolled::Hide => None,
            WhenUnenrolled::Dim => {
                if use_color {
                    Some("\x1b[2mhyphae: idle\x1b[0m".to_string())
                } else {
                    Some("hyphae: idle".to_string())
                }
            }
        };
    }

    let clean_handle = sess
        .get("handle")
        .and_then(Value::as_str)
        .map(sanitize_terminal_text)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut segments: Vec<String> = Vec::with_capacity(7);

    // Primary identity segment — always visibly labeled `hyphae` so the user knows the source.
    let id_text = match clean_handle {
        Some(h) => format!("hyphae @{h}"),
        None => "hyphae".to_string(),
    };
    if use_color {
        if muted_all {
            segments.push(format!("\x1b[2m{id_text}\x1b[0m"));
        } else {
            segments.push(format!("\x1b[32m{id_text}\x1b[0m"));
        }
    } else {
        segments.push(id_text);
    }

    // Linked bridges (e.g. `telegram:personal` or `telegram:personal +1`)
    if !bridge_labels.is_empty() {
        let label = if bridge_labels.len() == 1 {
            bridge_labels[0].clone()
        } else {
            format!("{} +{}", bridge_labels[0], bridge_labels.len() - 1)
        };
        if use_color {
            segments.push(format!("\x1b[36m{label}\x1b[0m"));
        } else {
            segments.push(label);
        }
    } else if bridges > 0 {
        let label = if bridges == 1 {
            "1 bridge".to_string()
        } else {
            format!("{bridges} bridges")
        };
        if use_color {
            segments.push(format!("\x1b[36m{label}\x1b[0m"));
        } else {
            segments.push(label);
        }
    }

    // Subscriptions count
    if subs > 0 {
        let label = if subs == 1 {
            "1 sub".to_string()
        } else {
            format!("{subs} subs")
        };
        if use_color {
            segments.push(format!("\x1b[32m{label}\x1b[0m"));
        } else {
            segments.push(label);
        }
    }

    // Queued unread count
    if queued > 0 {
        let label = format!("{queued} queued");
        if use_color {
            segments.push(format!("\x1b[33m{label}\x1b[0m"));
        } else {
            segments.push(label);
        }
    }

    // Focus Mode badge
    if focus_mode {
        if use_color {
            segments.push("\x1b[33mfocus\x1b[0m".to_string());
        } else {
            segments.push("focus".to_string());
        }
    }

    // Muted indicator
    if muted_all {
        if use_color {
            segments.push("\x1b[2mmuted\x1b[0m".to_string());
        } else {
            segments.push("muted".to_string());
        }
    } else if muted_rules > 0 {
        let label = format!("{muted_rules} muted");
        if use_color {
            segments.push(format!("\x1b[2m{label}\x1b[0m"));
        } else {
            segments.push(label);
        }
    }

    // Quarantined badge
    if quarantined > 0 {
        let label = format!("⚠ {quarantined} held");
        if use_color {
            segments.push(format!("\x1b[1;31m{label}\x1b[0m"));
        } else {
            segments.push(label);
        }
    }

    let sep = if use_color {
        "\x1b[2m · \x1b[0m"
    } else {
        " · "
    };
    Some(segments.join(sep))
}

fn build_summary_request(args: &StatuslineArgs, stdin_ctx: &ParsedStdinContext) -> Value {
    let mut pkt = Map::new();
    pkt.insert("type".into(), json!("session.summary"));
    pkt.insert("detail".into(), json!("compact"));

    // Target precedence:
    // 1. Explicit --session (qualified with harness if missing prefix)
    // 2. Explicit --herdr-terminal
    // 3. Stdin session_id / conversation_id
    // 4. Env HYPHAE_SESSION_ID
    // 5. Env HC_TERMINAL_ID
    // 6. Stdin workspace cwd
    let explicit_session = args
        .session
        .as_deref()
        .and_then(|s| qualify_session_id(args.harness, s));

    if let Some(sid) = explicit_session {
        pkt.insert("sessionId".into(), json!(sid));
        if let Some(created_ms) = args.herdr_created_ms {
            pkt.insert("herdrCreatedMs".into(), json!(created_ms));
        }
        return Value::Object(pkt);
    }

    if let Some(ref tid) = args.herdr_terminal {
        let trimmed = tid.trim();
        if !trimmed.is_empty() {
            pkt.insert("herdrTerminalId".into(), json!(trimmed));
            if let Some(created_ms) = args.herdr_created_ms {
                pkt.insert("herdrCreatedMs".into(), json!(created_ms));
            }
            return Value::Object(pkt);
        }
    }

    if let Some(ref sid) = stdin_ctx.session_id {
        pkt.insert("sessionId".into(), json!(sid));
        if let Some(created_ms) = args.herdr_created_ms {
            pkt.insert("herdrCreatedMs".into(), json!(created_ms));
        }
        return Value::Object(pkt);
    }

    if let Some(env_sid) = infer_session_id_from_env() {
        pkt.insert("sessionId".into(), json!(env_sid));
        return Value::Object(pkt);
    }

    if let Some(env_tid) = infer_herdr_terminal_from_env() {
        pkt.insert("herdrTerminalId".into(), json!(env_tid));
        if let Some(created_ms) = args.herdr_created_ms {
            pkt.insert("herdrCreatedMs".into(), json!(created_ms));
        }
        return Value::Object(pkt);
    }

    if let Some(ref cwd) = stdin_ctx.cwd {
        pkt.insert("cwd".into(), json!(cwd));
    }

    Value::Object(pkt)
}

pub fn run_statusline(args: &StatuslineArgs) -> ExitCode {
    let stdin_bytes = read_bounded_stdin();
    let stdin_ctx = parse_statusline_stdin(args.harness, &stdin_bytes);

    let socket_path = args.socket.clone().unwrap_or_else(default_socket_path);
    let req = build_summary_request(args, &stdin_ctx);
    let rpc_res = daemon_rpc_sync(&socket_path, &req, STATUSLINE_RPC_TIMEOUT);
    let summary_map = if rpc_res.ok { rpc_res.result } else { None };

    if args.json {
        let out = match summary_map {
            Some(map) => Value::Object(map),
            None => json!({
                "schemaVersion": 1,
                "rev": 0,
                "updatedAt": 0,
                "daemon": {
                    "online": false
                },
                "session": Value::Null
            }),
        };
        if let Ok(serialized) = serde_json::to_string(&out) {
            println!("{serialized}");
        }
        return ExitCode::from(EXIT_OK);
    }

    // Execute optional chained user statusLine command (bounded 2s timeout, fail-safe).
    let chain_output = args
        .chain_file
        .as_deref()
        .and_then(|p| execute_chain_file(p, &stdin_bytes));

    let use_color = color_enabled(args.plain);
    let hyp_line = format_statusline_pill(summary_map.as_ref(), args.when_unenrolled, use_color);

    let mut out = io::stdout().lock();
    if let Some(first_line) = chain_output {
        let _ = writeln!(out, "{first_line}");
    }
    if let Some(line) = hyp_line {
        let _ = writeln!(out, "{line}");
    }
    let _ = out.flush();

    ExitCode::from(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_csi_osc_dcs_c0_c1_and_bidi_overrides() {
        // CSI SGR + OSC window title + BEL + C0 newline/tab + DEL + bidi RLO
        let evil = "\x1b[31mevil\x1b]0;pwn\x07\x1b[1;32m\r\n\t\x7f\u{202e}ok\x1bPignored\x1b\\done";
        assert_eq!(sanitize_terminal_text(evil), "evilokdone");

        // Unterminated OSC must swallow trailing injection payload
        let unterminated = "alice\x1b]52;c;cHdu";
        assert_eq!(sanitize_terminal_text(unterminated), "alice");

        // 8-bit CSI (\u{9b}) and C1 controls
        let c1 = "bob\u{009b}31m\u{0085}clean";
        assert_eq!(sanitize_terminal_text(c1), "bobclean");

        // Preserves safe Unicode (e.g. handle chars, emoji, box drawing)
        assert_eq!(sanitize_terminal_text("⟁ @alice-01"), "⟁ @alice-01");
    }

    #[test]
    fn parses_claude_antigravity_and_malformed_stdin() {
        let claude = parse_statusline_stdin(
            StatuslineHarness::Claude,
            br#"{"session_id":"abc-123","workspace":{"current_dir":"/tmp/work"}}"#,
        );
        assert_eq!(claude.session_id.as_deref(), Some("claude:abc-123"));
        assert_eq!(claude.cwd.as_deref(), Some("/tmp/work"));

        // Already prefixed session_id is not double-prefixed
        let claude_pref = parse_statusline_stdin(
            StatuslineHarness::Claude,
            br#"{"session_id":"claude:already-1"}"#,
        );
        assert_eq!(claude_pref.session_id.as_deref(), Some("claude:already-1"));

        let agy = parse_statusline_stdin(
            StatuslineHarness::Antigravity,
            br#"{"conversation_id":"xyz-9","cwd":"/repo"}"#,
        );
        assert_eq!(agy.session_id.as_deref(), Some("antigravity:xyz-9"));
        assert_eq!(agy.cwd.as_deref(), Some("/repo"));

        // Malformed JSON and oversized (>64 KiB) stdin fail closed safely
        let bad = parse_statusline_stdin(StatuslineHarness::Claude, b"{not json");
        assert_eq!(bad, ParsedStdinContext::default());

        let huge = vec![b'a'; MAX_STATUSLINE_STDIN_BYTES + 10];
        assert_eq!(
            parse_statusline_stdin(StatuslineHarness::Claude, &huge),
            ParsedStdinContext::default()
        );

        // Injection inside session_id is rejected by is_valid_session_id
        let inj =
            parse_statusline_stdin(StatuslineHarness::Claude, br#"{"session_id":"$(whoami)"}"#);
        assert_eq!(inj.session_id, None);
    }

    #[test]
    fn formats_pill_plain_and_colored_and_strips_evil_handle() {
        let summary_val = json!({
            "schemaVersion": 1,
            "rev": 5,
            "daemon": { "online": true, "nodeId": "alice@mac" },
            "session": {
                "sessionId": "claude:s1",
                "enrolled": true,
                "handle": "\x1b[31malice\x1b]0;pwn\x07",
                "focusMode": true,
                "mutedAll": false,
                "counts": {
                    "subscriptions": 3,
                    "queued": 2,
                    "quarantined": 1,
                    "mutedRules": 1
                }
            }
        });
        let map = summary_val.as_object().unwrap();

        let plain = format_statusline_pill(Some(map), WhenUnenrolled::Hide, false).unwrap();
        assert_eq!(
            plain,
            "hyphae @alice · 3 subs · 2 queued · focus · 1 muted · ⚠ 1 held"
        );
        assert!(!plain.contains('\x1b'));
        assert!(!plain.contains("pwn"));

        let colored = format_statusline_pill(Some(map), WhenUnenrolled::Hide, true).unwrap();
        assert!(colored.contains("hyphae @alice"));
        assert!(colored.contains("3 subs"));
        assert!(colored.contains("2 queued"));
        assert!(colored.contains("focus"));
        assert!(colored.contains("1 muted"));
        assert!(colored.contains("⚠ 1 held"));
        assert!(!colored.contains("pwn"));
        assert!(!colored.contains("\x1b]0;"));

        let bridged = json!({
            "session": {
                "enrolled": true,
                "handle": "integration-tests",
                "bridges": ["telegram:personal"],
                "counts": { "bridges": 1, "subscriptions": 0, "queued": 0, "quarantined": 0, "mutedRules": 0 }
            }
        });
        assert_eq!(
            format_statusline_pill(bridged.as_object(), WhenUnenrolled::Hide, false).as_deref(),
            Some("hyphae @integration-tests · telegram:personal")
        );

        // Global quarantine warning appears even when this session's own quarantine count is 0 (U3)
        let global_q = json!({
            "daemon": { "online": true, "nodeId": "alice@mac", "quarantinedGlobal": 3 },
            "session": {
                "enrolled": true,
                "handle": "alice",
                "counts": { "subscriptions": 1, "queued": 0, "quarantined": 0, "mutedRules": 0 }
            }
        });
        assert_eq!(
            format_statusline_pill(global_q.as_object(), WhenUnenrolled::Hide, false).as_deref(),
            Some("hyphae @alice · 1 sub · ⚠ 3 held")
        );

        // Global quarantine warning still surfaces when session is null or unenrolled
        let global_q_no_sess = json!({
            "daemon": { "online": true, "nodeId": "alice@mac", "quarantinedGlobal": 2 },
            "session": null
        });
        assert_eq!(
            format_statusline_pill(global_q_no_sess.as_object(), WhenUnenrolled::Hide, false)
                .as_deref(),
            Some("hyphae · ⚠ 2 held")
        );
    }

    #[test]
    fn unenrolled_hide_vs_dim_and_offline_behavior() {
        assert_eq!(
            format_statusline_pill(None, WhenUnenrolled::Hide, false),
            None
        );
        assert_eq!(
            format_statusline_pill(None, WhenUnenrolled::Dim, false).as_deref(),
            Some("hyphae: offline")
        );

        let unenrolled = json!({
            "session": {
                "enrolled": false,
                "counts": { "subscriptions": 0, "queued": 0, "quarantined": 0, "mutedRules": 0 }
            }
        });
        assert_eq!(
            format_statusline_pill(unenrolled.as_object(), WhenUnenrolled::Hide, false),
            None
        );
        assert_eq!(
            format_statusline_pill(unenrolled.as_object(), WhenUnenrolled::Dim, false).as_deref(),
            Some("hyphae: idle")
        );
    }

    #[test]
    fn parses_chain_file_formats() {
        assert_eq!(
            parse_chain_file_contents(r#"{"command":"/bin/echo","args":["hi","there"]}"#),
            Some(ChainSpec::Direct {
                command: "/bin/echo".into(),
                args: vec!["hi".into(), "there".into()],
            })
        );
        assert_eq!(
            parse_chain_file_contents(r#"{"command":"echo hello"}"#),
            Some(ChainSpec::Shell("echo hello".into()))
        );
        assert_eq!(
            parse_chain_file_contents(r#""echo plain""#),
            Some(ChainSpec::Shell("echo plain".into()))
        );
        assert_eq!(
            parse_chain_file_contents("printf 'raw-shell'\n"),
            Some(ChainSpec::Shell("printf 'raw-shell'".into()))
        );
        assert_eq!(parse_chain_file_contents("   "), None);
    }

    #[test]
    fn fast_path_arg_parser_handles_all_flags() {
        let raw: Vec<String> = [
            "--harness",
            "antigravity",
            "--session=antigravity:conv-1",
            "--herdr-terminal",
            "t4g",
            "--socket=/tmp/c.sock",
            "--when-unenrolled",
            "dim",
            "--plain",
            "--chain-file",
            "/tmp/chain.json",
            "--json",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = parse_fast_path_args(&raw).unwrap();
        assert_eq!(parsed.harness, StatuslineHarness::Antigravity);
        assert_eq!(parsed.session.as_deref(), Some("antigravity:conv-1"));
        assert_eq!(parsed.herdr_terminal.as_deref(), Some("t4g"));
        assert_eq!(parsed.socket, Some(PathBuf::from("/tmp/c.sock")));
        assert_eq!(parsed.when_unenrolled, WhenUnenrolled::Dim);
        assert!(parsed.plain);
        assert_eq!(parsed.chain_file, Some(PathBuf::from("/tmp/chain.json")));
        assert!(parsed.json);
    }
}
