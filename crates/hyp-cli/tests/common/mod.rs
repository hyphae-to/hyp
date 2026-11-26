//! Shared zero-flake CLI integration test harness for `hyp-cli`.
//!
//! Enforces strict test isolation (`HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`,
//! `HYPHAE_SECRET_BACKEND=file`, `HYPHAE_NO_OPEN=1`, full `HYPHAE_*` env scrubbing),
//! bounded-timeout process I/O (never hangs CI on a stalled child), guaranteed child
//! process reaping in `Drop`, and deterministic session readiness polling.

#![allow(dead_code)]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Path to the compiled `hyp` binary under test.
pub fn hyp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hyp")
}

/// Path to the repository's `plugins/` directory for offline SHA-256 verified CLI tests.
pub fn repo_plugins_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("plugins")
}

/// Scrubs all ambient Hyphae and coding-harness environment variables from `cmd` so running
/// `cargo test` inside an active Claude Code / Herdr / Codex / OpenClaw / OpenCode / T3 /
/// Gemini session can NEVER leak live session IDs, tokens, or host config paths into child
/// processes (Blind Spot B5).
pub fn scrub_ambient_harness_env(cmd: &mut Command) {
    const PREFIXES: &[&str] = &[
        "HYPHAE_",
        "AGENTS_MESH_",
        "T3_MESH_",
        "HC_",
        "CLAUDE",
        "CODEX_",
        "OPENCLAW_",
        "OPENCODE_",
        "T3CODE_",
        "T3_",
        "GEMINI_",
        "ANTIGRAVITY_",
    ];
    for (key, _) in std::env::vars_os() {
        if let Some(s) = key.to_str() {
            if PREFIXES.iter().any(|p| s.starts_with(p)) {
                cmd.env_remove(&key);
            }
        }
    }
    cmd.env_remove("PASSWORD_STORE_DIR").env_remove("GNUPGHOME");
}

/// Applies complete hermetic environment isolation to `cmd` so live user config, sockets,
/// Keychain, host OS service managers (`HYPHAE_NO_SERVICE=1`, `HYPHAE_NO_SERVICE_RESTART=1`),
/// ambient `HYPHAE_*` variables, and parent live-harness identity variables can NEVER leak into tests.
pub fn apply_isolated_env(cmd: &mut Command, home: &Path) {
    scrub_ambient_harness_env(cmd);
    cmd.env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HYPHAE_NO_OPEN", "1")
        .env("HYPHAE_NO_SERVICE", "1")
        .env("HYPHAE_NO_SERVICE_RESTART", "1")
        .env("HYPHAE_PLUGINS_DIR", repo_plugins_dir())
        .env("HYPHAE_TAILSCALE_BIN", "none");
}

/// Constructs a `Command` for the compiled `hyp` binary with complete environment
/// isolation so live user config, sockets, Keychain, host OS service managers, and ambient
/// harness/Hyphae variables can never leak into tests. Sets `HYPHAE_PLUGINS_DIR` to the local
/// repo `plugins/` directory so `hyp setup` / `hyp plugin` exercise real compile-time SHA-256
/// verification completely offline (tests wanting offline-failure or tarball behavior can
/// remove/override it).
pub fn isolated_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(hyp_bin());
    apply_isolated_env(&mut cmd, home);
    cmd
}

/// Parses JSON stdout from a completed `Output` with rich diagnostics on failure.
pub fn parse_json_stdout(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "expected valid JSON stdout ({e}):\nstatus={:?}\nstdout={}\nstderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Managed subprocess with bounded-timeout line readers on stdout & stderr,
/// graceful `SIGTERM` on Unix, and guaranteed `kill()` + `wait()` on `Drop`.
pub struct ManagedProcess {
    label: String,
    child: Option<Child>,
    stdout_rx: Option<mpsc::Receiver<String>>,
    stderr_rx: Option<mpsc::Receiver<String>>,
    stderr_buf: Arc<Mutex<String>>,
}

impl ManagedProcess {
    /// Spawns `cmd` with piped stdout and stderr drained by background reader threads
    /// so pipe buffers never deadlock and line reads are strictly bounded by timeout.
    pub fn spawn(label: impl Into<String>, cmd: &mut Command) -> Self {
        let label = label.into();
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn '{label}': {e}"));

        let stdout_rx = child.stdout.take().map(|stdout| {
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    match line {
                        Ok(l) => {
                            if tx.send(l).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            rx
        });

        let stderr_buf = Arc::new(Mutex::new(String::new()));
        let stderr_rx = child.stderr.take().map(|stderr| {
            let (tx, rx) = mpsc::channel();
            let buf_clone = Arc::clone(&stderr_buf);
            thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    match line {
                        Ok(l) => {
                            if let Ok(mut guard) = buf_clone.lock() {
                                guard.push_str(&l);
                                guard.push('\n');
                            }
                            let _ = tx.send(l);
                        }
                        Err(_) => break,
                    }
                }
            });
            rx
        });

        Self {
            label,
            child: Some(child),
            stdout_rx,
            stderr_rx,
            stderr_buf,
        }
    }

    /// Takes ownership of the child's stdin pipe if configured with `Stdio::piped()`.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut().and_then(|c| c.stdin.take())
    }

    /// Returns a snapshot of all stderr output captured so far.
    pub fn stderr_snapshot(&self) -> String {
        self.stderr_buf
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Reads the next stdout line within `timeout`, returning an error string on timeout or EOF.
    pub fn try_read_line(&self, timeout: Duration) -> Result<String, String> {
        let rx = self
            .stdout_rx
            .as_ref()
            .ok_or_else(|| format!("'{}' has no stdout receiver", self.label))?;
        rx.recv_timeout(timeout).map_err(|e| {
            format!(
                "'{}' failed reading stdout line within {:?} ({e}); stderr={}",
                self.label,
                timeout,
                self.stderr_snapshot()
            )
        })
    }

    /// Reads the next stdout line and parses it as JSON within `timeout`.
    /// Panics with captured stderr diagnostics on timeout, EOF, or invalid JSON.
    pub fn read_json_line(&self, timeout: Duration) -> Value {
        let line = self
            .try_read_line(timeout)
            .unwrap_or_else(|err| panic!("{err}"));
        serde_json::from_str(line.trim()).unwrap_or_else(|e| {
            panic!(
                "'{}' emitted invalid JSON ({e}): line={line:?}\nstderr={}",
                self.label,
                self.stderr_snapshot()
            )
        })
    }

    /// Reads the next stderr line within `timeout`, returning an error string on timeout or EOF.
    pub fn try_read_stderr_line(&self, timeout: Duration) -> Result<String, String> {
        let rx = self
            .stderr_rx
            .as_ref()
            .ok_or_else(|| format!("'{}' has no stderr receiver", self.label))?;
        rx.recv_timeout(timeout).map_err(|e| {
            format!(
                "'{}' failed reading stderr line within {:?} ({e}); stderr={}",
                self.label,
                timeout,
                self.stderr_snapshot()
            )
        })
    }

    /// Waits up to `timeout` for the child to exit on its own.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let child = self.child.as_mut()?;
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.child = None;
                    return Some(status);
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    thread::sleep(Duration::from_millis(15));
                }
                Err(_) => return None,
            }
        }
    }

    /// Collects all remaining stdout lines until EOF (within `timeout`) and waits for exit.
    pub fn wait_stdout_output(&mut self, timeout: Duration) -> (ExitStatus, String) {
        let deadline = Instant::now() + timeout;
        let mut collected = String::new();
        if let Some(ref rx) = self.stdout_rx {
            loop {
                let rem = deadline.saturating_duration_since(Instant::now());
                if rem.is_zero() {
                    panic!(
                        "'{}' timed out waiting for stdout EOF after {:?}; partial={collected:?}\nstderr={}",
                        self.label,
                        timeout,
                        self.stderr_snapshot()
                    );
                }
                match rx.recv_timeout(rem) {
                    Ok(line) => {
                        collected.push_str(&line);
                        collected.push('\n');
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        panic!(
                            "'{}' timed out waiting for stdout EOF after {:?}; partial={collected:?}\nstderr={}",
                            self.label,
                            timeout,
                            self.stderr_snapshot()
                        );
                    }
                }
            }
        }
        let rem = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(500));
        let status = self.wait_timeout(rem).unwrap_or_else(|| {
            panic!(
                "'{}' closed stdout but did not exit within {:?}\nstderr={}",
                self.label,
                timeout,
                self.stderr_snapshot()
            )
        });
        (status, collected)
    }

    /// Collects remaining stdout lines until EOF (within `timeout`), waits for exit, and parses JSON.
    pub fn wait_json_output(&mut self, timeout: Duration) -> (ExitStatus, Value) {
        let (status, collected) = self.wait_stdout_output(timeout);
        let parsed: Value = serde_json::from_str(collected.trim()).unwrap_or_else(|e| {
            panic!(
                "'{}' produced invalid JSON stdout ({e}): status={:?}\nstdout={collected:?}\nstderr={}",
                self.label,
                status.code(),
                self.stderr_snapshot()
            )
        });
        (status, parsed)
    }

    /// Requests graceful shutdown (`SIGTERM` on Unix) and waits up to 5 seconds before
    /// falling back to forceful `kill()` + `wait()`.
    pub fn shutdown_gracefully(&mut self) -> Option<i32> {
        let mut child = self.child.take()?;
        #[cfg(unix)]
        {
            let pid = child.id().to_string();
            let _ = Command::new("kill").args(["-TERM", &pid]).status();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok(Some(status)) = child.try_wait() {
                    return status.code();
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        let _ = child.kill();
        child.wait().ok().and_then(|s| s.code())
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            {
                let pid = child.id().to_string();
                let _ = Command::new("kill").args(["-TERM", &pid]).status();
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline {
                    if let Ok(Some(_)) = child.try_wait() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Invokes the real compiled `hyp hook claude pre-tool-use` binary to register a
/// verified tool call against `socket_path`.
pub fn run_claude_pre_tool_use_hook(
    home: &Path,
    socket_path: &Path,
    session_id: &str,
    tool_use_id: &str,
    tool_name: &str,
    tool_input: Value,
) {
    let mut hook_proc = isolated_cmd(home)
        .args([
            "hook",
            "claude",
            "pre-tool-use",
            "--socket",
            socket_path.to_str().expect("UTF-8 socket path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hyp hook claude pre-tool-use");
    hook_proc
        .stdin
        .take()
        .unwrap()
        .write_all(
            json!({
                "session_id": session_id,
                "tool_use_id": tool_use_id,
                "tool_name": format!("mcp__hyphae__{tool_name}"),
                "tool_input": tool_input
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    let out = hook_proc.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "hyp hook claude pre-tool-use failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Managed `hyp mcp <socket>` stdio JSON-RPC subprocess with bounded-timeout RPC calls
/// and clean stdin EOF drain on `close()` / `Drop`.
pub struct McpSubprocess {
    proc: ManagedProcess,
    stdin: Option<ChildStdin>,
    next_id: u64,
}

impl McpSubprocess {
    /// Spawns `hyp mcp <socket_path>` using `isolated_cmd(home)`.
    pub fn spawn(home: &Path, socket_path: &Path) -> Self {
        let mut cmd = isolated_cmd(home);
        cmd.args(["mcp", socket_path.to_str().expect("UTF-8 socket path")])
            .stdin(Stdio::piped());
        let mut proc = ManagedProcess::spawn("hyp mcp", &mut cmd);
        let stdin = proc.take_stdin();
        Self {
            proc,
            stdin,
            next_id: 0,
        }
    }

    /// Sends one JSON-RPC request line and waits up to `timeout` for the JSON response line.
    pub fn rpc(&mut self, msg: Value, timeout: Duration) -> Value {
        let stdin = self
            .stdin
            .as_mut()
            .expect("McpSubprocess stdin already closed");
        writeln!(stdin, "{msg}").expect("write JSON-RPC line to hyp mcp");
        stdin.flush().expect("flush hyp mcp stdin");
        self.proc.read_json_line(timeout)
    }

    /// Sends a JSON-RPC notification line without waiting for a response.
    pub fn notify(&mut self, msg: Value) {
        let stdin = self
            .stdin
            .as_mut()
            .expect("McpSubprocess stdin already closed");
        writeln!(stdin, "{msg}").expect("write JSON-RPC notification to hyp mcp");
        stdin.flush().expect("flush hyp mcp stdin");
    }

    /// Performs the MCP `initialize` + `notifications/initialized` handshake.
    pub fn initialize(&mut self, timeout: Duration) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let resp = self.rpc(
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "hyp-cli-e2e", "version": "1" }
                }
            }),
            timeout,
        );
        self.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }));
        resp
    }

    /// Runs a real `hyp hook claude pre-tool-use` binary and invokes `tools/call`
    /// with the verified Claude `_meta.claudecode/toolUseId`.
    /// Returns `(text, is_error)`.
    pub fn call_verified_claude(
        &mut self,
        home: &Path,
        socket_path: &Path,
        session_raw: &str,
        tool_name: &str,
        arguments: Value,
        timeout: Duration,
    ) -> (String, bool) {
        self.next_id += 1;
        let id = self.next_id;
        let call_id = format!("toolu_{session_raw}_{id}");
        run_claude_pre_tool_use_hook(
            home,
            socket_path,
            session_raw,
            &call_id,
            tool_name,
            arguments.clone(),
        );
        let resp = self.rpc(
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments,
                    "_meta": { "claudecode/toolUseId": call_id }
                }
            }),
            timeout,
        );
        let result = &resp["result"];
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let is_error = result["isError"].as_bool() == Some(true);
        (text, is_error)
    }

    /// Closes stdin cleanly (EOF) and waits up to `timeout` for `hyp mcp` to exit.
    pub fn close(mut self, timeout: Duration) -> Option<i32> {
        drop(self.stdin.take());
        self.proc.wait_timeout(timeout).and_then(|s| s.code())
    }
}

impl Drop for McpSubprocess {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.proc.wait_timeout(Duration::from_millis(500));
    }
}

/// Deterministically polls `session.status` on `socket_path` via `daemon_rpc_sync`
/// until `hasLiveTransport == true`, eliminating blind `sleep()` race flakes before
/// sending messages intended to wake a live `hyp wait` subprocess.
pub fn wait_for_session_live(socket_path: &Path, session_id: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let req = json!({
        "type": "session.status",
        "sessionId": session_id
    });
    while Instant::now() < deadline {
        let res = hyp_harness::sock::daemon_rpc_sync(socket_path, &req, Duration::from_millis(500));
        if res.ok
            && res
                .result
                .as_ref()
                .and_then(|m| m.get("hasLiveTransport"))
                .and_then(Value::as_bool)
                == Some(true)
        {
            return;
        }
        thread::sleep(Duration::from_millis(15));
    }
    panic!(
        "timed out after {:?} waiting for session '{}' on '{}' to report hasLiveTransport == true",
        timeout,
        session_id,
        socket_path.display()
    );
}

/// Output captured from running the compiled `hyp` binary attached to a real POSIX PTY (`#[cfg(unix)]`).
///
/// `stdout` is captured via a dedicated pipe (keeping `--json` output 100% pure), while `tty`
/// captures everything written to the interactive terminal (`stderr` / `/dev/tty`), including
/// confirmation summaries, diffs, warnings, and `[y/N]:` prompts.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct PtyRunOutput {
    pub code: i32,
    pub stdout: String,
    pub tty: String,
}

#[cfg(unix)]
impl PtyRunOutput {
    pub fn parse_json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "expected valid JSON stdout from PTY run ({e}):\ncode={}\nstdout={}\ntty={}",
                self.code, self.stdout, self.tty
            )
        })
    }
}

/// Runs the compiled `hyp` binary inside a real POSIX PTY (via Python 3 stdlib `pty` + `setsid`
/// + `TIOCSCTTY`) with full `isolated_cmd(home)` environment isolation.
///
/// - When `piped_stdin` is `None`: `stdin` and `stderr` are attached to the PTY slave (so both
///   `stdin.is_terminal()` and `stderr.is_terminal()` are `true`).
/// - When `piped_stdin` is `Some(data)`: `stdin` receives `data` + EOF via a pipe while `stderr`
///   and the process's controlling terminal (`/dev/tty`) are attached to the PTY slave (matching
///   a human running `hyp auth add ... < key.jwk` in a real terminal!).
/// - Once `[y/N]:` appears on the PTY, writes `tty_reply` (e.g. `Some("y\n")`, `Some("n\n")`,
///   `Some("\n")`) or sends Ctrl-D EOF (`None`) to the PTY master.
#[cfg(unix)]
pub fn run_hyp_in_pty(
    home: &Path,
    args: &[&str],
    piped_stdin: Option<&str>,
    tty_reply: Option<&str>,
) -> PtyRunOutput {
    const PY_PTY_DRIVER: &str = r#"
import errno, fcntl, json, os, pty, select, subprocess, sys, termios, time

cfg = json.loads(sys.stdin.read())
argv = cfg["argv"]
stdin_data = cfg.get("stdinData")
tty_reply = cfg.get("ttyReply")
timeout = float(cfg.get("timeoutSecs", 20.0))

master_fd, slave_fd = pty.openpty()

def setup_child():
    os.setsid()
    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

stdin_pipe_r = None
stdin_pipe_w = None
if stdin_data is not None:
    stdin_pipe_r, stdin_pipe_w = os.pipe()
    child_stdin = stdin_pipe_r
else:
    child_stdin = slave_fd

stdout_r, stdout_w = os.pipe()

proc = subprocess.Popen(
    argv,
    stdin=child_stdin,
    stdout=stdout_w,
    stderr=slave_fd,
    preexec_fn=setup_child,
    close_fds=True,
)
os.close(slave_fd)
os.close(stdout_w)
if stdin_pipe_r is not None:
    os.close(stdin_pipe_r)
if stdin_pipe_w is not None:
    raw = stdin_data.encode("utf-8")
    view = memoryview(raw)
    while view:
        written = os.write(stdin_pipe_w, view)
        view = view[written:]
    os.close(stdin_pipe_w)

os.set_blocking(master_fd, False)
os.set_blocking(stdout_r, False)

tty_buf = bytearray()
stdout_buf = bytearray()
replied = False
deadline = time.monotonic() + timeout
stdout_open = True
tty_open = True

def drain_fd(fd, target):
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                return False
            target.extend(chunk)
    except OSError as e:
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            return True
        if e.errno == errno.EIO:
            return False
        raise

while stdout_open or tty_open or proc.poll() is None:
    now = time.monotonic()
    if now >= deadline:
        proc.kill()
        proc.wait()
        sys.stderr.write(
            f"PTY driver timed out after {timeout}s; tty={tty_buf.decode('utf-8', 'replace')!r}\n"
        )
        sys.exit(124)

    watch = []
    if tty_open:
        watch.append(master_fd)
    if stdout_open:
        watch.append(stdout_r)

    if watch:
        rlist, _, _ = select.select(watch, [], [], min(0.05, max(0.005, deadline - now)))
    else:
        rlist = []
        time.sleep(0.01)

    if master_fd in rlist:
        tty_open = drain_fd(master_fd, tty_buf)
    if stdout_r in rlist:
        stdout_open = drain_fd(stdout_r, stdout_buf)

    if not replied and b"[y/N]:" in tty_buf:
        replied = True
        if tty_reply is not None:
            os.write(master_fd, tty_reply.encode("utf-8"))
        else:
            os.write(master_fd, b"\x04")

    if proc.poll() is not None and not rlist:
        if tty_open:
            tty_open = drain_fd(master_fd, tty_buf)
        if stdout_open:
            stdout_open = drain_fd(stdout_r, stdout_buf)
        if not tty_open and not stdout_open:
            break
        # Give the kernel a brief tick to surface EOF after child exit
        time.sleep(0.01)
        if tty_open:
            tty_open = drain_fd(master_fd, tty_buf)
        if stdout_open:
            stdout_open = drain_fd(stdout_r, stdout_buf)
        break

exit_code = proc.wait()
os.close(master_fd)
os.close(stdout_r)
sys.stdout.write(json.dumps({
    "code": exit_code,
    "stdout": stdout_buf.decode("utf-8", errors="replace"),
    "tty": tty_buf.decode("utf-8", errors="replace"),
}))
"#;

    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(hyp_bin().to_string());
    for a in args {
        argv.push((*a).to_string());
    }
    let payload = json!({
        "argv": argv,
        "stdinData": piped_stdin,
        "ttyReply": tty_reply,
        "timeoutSecs": 20.0,
    })
    .to_string();

    let mut py = Command::new("python3");
    py.args(["-c", PY_PTY_DRIVER]);
    apply_isolated_env(&mut py, home);
    py.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = py
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn python3 PTY driver for hyp {args:?}: {e}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .expect("write PTY driver config");
    let out = child
        .wait_with_output()
        .expect("wait for python3 PTY driver");
    assert_eq!(
        out.status.code(),
        Some(0),
        "python3 PTY driver failed for hyp {args:?}:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON from python3 PTY driver ({e}): stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    PtyRunOutput {
        code: parsed["code"].as_i64().expect("pty exit code") as i32,
        stdout: parsed["stdout"].as_str().unwrap_or_default().to_string(),
        tty: parsed["tty"].as_str().unwrap_or_default().to_string(),
    }
}

/// Real Passkey Admin test actor for `#10` E2E tests (`hyp auth init --web` + loopback Passkey
/// approval ceremonies + offline `--approval-file` + adversarial mutation helpers).
pub struct TestPasskeyAdmin {
    pub human_id: String,
    pub label: String,
    pub ed_kp: hyp_crypto::keys::Ed25519KeyPair,
    pub enc_kp: hyp_crypto::keys::X25519KeyPair,
    pub auth_epoch: u64,
}

impl TestPasskeyAdmin {
    pub fn generate(human_id: &str, label: &str) -> Self {
        Self {
            human_id: human_id.to_string(),
            label: label.to_string(),
            ed_kp: hyp_crypto::keys::Ed25519KeyPair::generate().expect("generate passkey ed25519"),
            enc_kp: hyp_crypto::keys::X25519KeyPair::generate().expect("generate passkey x25519"),
            auth_epoch: 1,
        }
    }

    pub fn kid(&self) -> String {
        self.ed_kp.kid()
    }

    pub fn enc_kid(&self) -> String {
        self.enc_kp.kid()
    }

    /// Enrolls this Passkey Admin via `hyp auth init --web --no-open --port 0` on a fresh node
    /// (zero local PKCS#8 secret written to `SecretStore`, `role: admin`).
    pub fn enroll_via_web(
        &self,
        home: &Path,
        state_dir: &Path,
        config_path: Option<&Path>,
    ) -> Value {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use hyp_crypto::human::{NodeCertPayloadV1, encode_hcert1, sign_node_cert};
        use hyp_crypto::keys::OkpJwk;
        use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};

        let mut args: Vec<String> = vec![
            "auth".into(),
            "init".into(),
            "--web".into(),
            "--human-id".into(),
            self.human_id.clone(),
            "--label".into(),
            self.label.clone(),
            "--no-open".into(),
            "--port".into(),
            "0".into(),
            "--timeout".into(),
            "20".into(),
            "--state-dir".into(),
            state_dir.to_str().unwrap().into(),
            "--json".into(),
        ];
        if let Some(cfg) = config_path {
            args.push("--config".into());
            args.push(cfg.to_str().unwrap().into());
        }

        let mut cmd = isolated_cmd(home);
        cmd.args(&args).stdin(Stdio::null());
        let mut proc = ManagedProcess::spawn("hyp auth init --web (TestPasskeyAdmin)", &mut cmd);

        let deadline = Instant::now() + Duration::from_secs(10);
        let enroll_b64 = loop {
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(
                !rem.is_zero(),
                "timed out waiting for #enroll= URL; stderr={}",
                proc.stderr_snapshot()
            );
            let line = proc
                .try_read_stderr_line(rem)
                .unwrap_or_else(|e| panic!("failed reading enroll stderr: {e}"));
            if let Some((_, frag)) = line.split_once("#enroll=") {
                break frag.trim().to_string();
            }
        };

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(&enroll_b64)
            .expect("valid base64url #enroll= payload");
        let payload: Value =
            serde_json::from_slice(&payload_bytes).expect("valid JSON #enroll= payload");
        let callback_url = payload["callbackUrl"].as_str().unwrap().to_string();
        let csrf_token = payload["csrfToken"].as_str().unwrap().to_string();
        let node_id = payload["nodeId"].as_str().unwrap().to_string();
        let node_sign_jwk: OkpJwk =
            serde_json::from_value(payload["nodeSignJwk"].clone()).expect("nodeSignJwk");
        let node_enc_jwk: OkpJwk =
            serde_json::from_value(payload["nodeEncJwk"].clone()).expect("nodeEncJwk");

        let now = now_unix_ms();
        let cert_payload = NodeCertPayloadV1 {
            v: 1,
            node_id,
            signing_jwk: node_sign_jwk,
            encryption_jwk: node_enc_jwk,
            human_id: self.human_id.clone(),
            human_kid: self.ed_kp.kid(),
            auth_epoch: self.auth_epoch,
            issued_at: format_rfc3339_millis(now),
            expires_at: format_rfc3339_millis(now + 365 * 86_400_000),
        };
        let signed_cert = sign_node_cert(&cert_payload, &self.ed_kp).expect("sign NodeCertV1");
        let hcert1 = encode_hcert1(&signed_cert).expect("encode hcert1_");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let client = hyp_node::engine::http_util::HttpClient::new().unwrap();
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri(&callback_url)
                .header(http::header::ORIGIN, "https://hyphae.to")
                .header(http::header::CONTENT_TYPE, "application/json")
                .header("x-hyphae-csrf", &csrf_token)
                .body(hyp_node::engine::http_util::full_body(
                    serde_json::to_vec(&json!({
                        "v": 1,
                        "humanId": self.human_id,
                        "kid": self.ed_kp.kid(),
                        "jwk": self.ed_kp.to_jwk(),
                        "encJwk": self.enc_kp.to_jwk(),
                        "nodeCert": hcert1,
                        "label": self.label,
                        "credentialId": format!("cred-{}", self.ed_kp.kid()),
                    }))
                    .unwrap(),
                ))
                .unwrap();
            let resp = client.request(req).await.expect("POST web enroll callback");
            assert_eq!(
                resp.status(),
                http::StatusCode::OK,
                "web enroll callback failed with status {}",
                resp.status()
            );
        });

        let (status, out_json) = proc.wait_json_output(Duration::from_secs(10));
        assert_eq!(
            status.code(),
            Some(0),
            "hyp auth init --web failed: {out_json}\nstderr={}",
            proc.stderr_snapshot()
        );
        assert_eq!(out_json["ok"], true);
        assert_eq!(out_json["data"]["webEnrolled"]["role"], "admin");
        assert_eq!(out_json["data"]["passkeyBacked"], true);
        assert!(out_json["data"]["secretName"].is_null());
        out_json
    }

    /// Creates an existing-installation fixture with a Passkey Admin. This deliberately does
    /// not exercise enrollment; real first enrollment and live auth.add are covered separately.
    pub fn seed_existing_passkey_fixture(&self, state_dir: &Path) {
        let db = hyp_store::NodeDb::open(state_dir.join("node.sqlite")).unwrap();
        db.human()
            .upsert_authority(
                &hyp_store::HumanAuthorityInput {
                    human_id: self.human_id.clone(),
                    kid: self.kid(),
                    label: self.label.clone(),
                    role: hyp_store::HumanAuthorityRole::Admin,
                    jwk_json: serde_json::to_string(&self.ed_kp.to_jwk()).unwrap(),
                    enc_jwk_json: Some(serde_json::to_string(&self.enc_kp.to_jwk()).unwrap()),
                    prf_salt: Some("existing-passkey-fixture".into()),
                    auth_epoch: self.auth_epoch,
                },
                hyp_store::now_ms(),
            )
            .unwrap();
    }

    /// Parses `#drop=<base64url>` from a printed Passkey approval URL.
    pub fn parse_approval_url(url: &str) -> Value {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let (_, frag) = url
            .split_once("#drop=")
            .unwrap_or_else(|| panic!("expected #drop= fragment in approval URL: {url}"));
        let raw = URL_SAFE_NO_PAD
            .decode(frag.trim())
            .unwrap_or_else(|e| panic!("invalid base64url #drop= fragment ({e}): {url}"));
        serde_json::from_slice(&raw)
            .unwrap_or_else(|e| panic!("invalid JSON #drop= fragment ({e}): {url}"))
    }

    /// Reads the requested `approval` action from a parsed `#drop=` fragment.
    pub fn open_approval_from_fragment(
        &self,
        fragment: &Value,
    ) -> hyp_crypto::human::HumanApprovalActionV1 {
        serde_json::from_value(fragment["approval"].clone()).expect("fragment.approval")
    }

    /// Signs and HPKE-seals a `HumanApprovalActionV1` into an `hdrop1_` token + `HumanDropEnvelopeV1`
    /// targeting `fragment["encJwk"]`.
    pub fn seal_approval(
        &self,
        fragment: &Value,
        action: &hyp_crypto::human::HumanApprovalActionV1,
    ) -> (String, hyp_crypto::human::HumanDropEnvelopeV1) {
        self.seal_approval_with_signer(
            fragment,
            action,
            &self.ed_kp,
            &self.human_id,
            self.auth_epoch,
            None,
        )
    }

    /// Signs and HPKE-seals a `HumanApprovalActionV1` with an explicit signer keypair / identity
    /// (for testing non-admin, revoked, wrong-nodeId, or mutated approvals).
    pub fn seal_approval_with_signer(
        &self,
        fragment: &Value,
        action: &hyp_crypto::human::HumanApprovalActionV1,
        signer_kp: &hyp_crypto::keys::Ed25519KeyPair,
        signer_human_id: &str,
        auth_epoch: u64,
        audience_node_override: Option<&str>,
    ) -> (String, hyp_crypto::human::HumanDropEnvelopeV1) {
        use hyp_crypto::human::{
            HumanAudience, HumanClaimV1, HumanDropKind, encode_hdrop1, seal_human_drop,
        };
        use hyp_crypto::jcs::to_canonical_json;
        use hyp_crypto::keys::OkpJwk;
        use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};

        let node_id = audience_node_override
            .unwrap_or_else(|| fragment["nodeId"].as_str().expect("fragment.nodeId"));
        let enc_jwk: OkpJwk =
            serde_json::from_value(fragment["encJwk"].clone()).expect("fragment.encJwk");
        let recipient_pk = enc_jwk.to_x25519().expect("recipient X25519 pubkey");
        let drop_id = fragment["dropId"].as_str().unwrap_or_default().to_string();

        let now = now_unix_ms();
        let rand_suffix = hex::encode(
            hyp_crypto::keys::Ed25519KeyPair::generate()
                .unwrap()
                .kid()
                .as_bytes(),
        );
        let claim = HumanClaimV1 {
            v: 1,
            claim_id: format!("clm_{}_{}", now, &rand_suffix[..16]),
            kind: HumanDropKind::Approval,
            human_id: signer_human_id.to_string(),
            human_kid: signer_kp.kid(),
            auth_epoch,
            issued_at: format_rfc3339_millis(now),
            expires_at: format_rfc3339_millis(now + 5 * 60 * 1_000),
            drop_id,
            audience: HumanAudience {
                node_id: node_id.to_string(),
                node_enc_kid: recipient_pk.kid(),
                handle: None,
            },
            secret_spec: None,
            body: to_canonical_json(action).expect("canonical approval action JSON"),
        };
        let env = seal_human_drop(&claim, signer_kp, &recipient_pk).expect("seal_human_drop");
        let hdrop1 = encode_hdrop1(&env).expect("encode_hdrop1");
        (hdrop1, env)
    }

    /// POSTs an approval payload (`hdrop1_...` or JSON) to the fragment's loopback or remote relay.
    pub fn post_approval_to_fragment(
        fragment: &Value,
        payload: &str,
        origin: &str,
    ) -> (u16, Value) {
        use http_body_util::BodyExt as _;

        let relay = fragment["relay"].as_str().expect("fragment.relay");
        let drop_id = fragment["dropId"].as_str().expect("fragment.dropId");
        let post_cap = fragment["postCap"].as_str().expect("fragment.postCap");
        let url = format!("{relay}/v1/drops/{drop_id}");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let client = hyp_node::engine::http_util::HttpClient::new().unwrap();
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri(&url)
                .header(http::header::ORIGIN, origin)
                .header("x-hyphae-drop-cap", post_cap)
                .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(hyp_node::engine::http_util::full_body(
                    payload.as_bytes().to_vec(),
                ))
                .unwrap();
            let resp = client.request(req).await.expect("POST approval to relay");
            let status = resp.status().as_u16();
            let body = resp
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            let parsed = serde_json::from_slice(&body)
                .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&body) }));
            (status, parsed)
        })
    }

    /// Spawns a `hyp` command that requires a Passkey approval ceremony, reads the printed
    /// approval URL from stderr, reads the requested `approval`, signs with this Passkey Admin, POSTs
    /// to the ephemeral loopback listener, and returns `(exit_code, stdout, stderr, action)`.
    pub fn run_and_approve(
        &self,
        home: &Path,
        args: &[&str],
        stdin_data: Option<&str>,
    ) -> (
        i32,
        String,
        String,
        hyp_crypto::human::HumanApprovalActionV1,
    ) {
        let mut cmd = isolated_cmd(home);
        cmd.args(args);
        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        let mut proc = ManagedProcess::spawn(format!("hyp {}", args.join(" ")), &mut cmd);
        if let Some(data) = stdin_data {
            let mut stdin = proc.take_stdin().expect("piped stdin");
            stdin.write_all(data.as_bytes()).expect("write stdin");
            drop(stdin);
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        let approval_url = loop {
            let rem = deadline.saturating_duration_since(Instant::now());
            assert!(
                !rem.is_zero(),
                "timed out waiting for Passkey approval URL; stderr={}",
                proc.stderr_snapshot()
            );
            let line = proc.try_read_stderr_line(rem).unwrap_or_else(|e| {
                panic!(
                    "command exited or stalled before printing Passkey approval URL ({e}); stderr={}",
                    proc.stderr_snapshot()
                )
            });
            if let Some((_, url)) = line.split_once("Hyphae Passkey approval URL: ") {
                break url.trim().to_string();
            }
        };

        let fragment = Self::parse_approval_url(&approval_url);
        let action = self.open_approval_from_fragment(&fragment);
        let (hdrop1, _) = self.seal_approval(&fragment, &action);
        let (http_status, resp_json) =
            Self::post_approval_to_fragment(&fragment, &hdrop1, "https://hyphae.to");
        assert_eq!(
            http_status, 201,
            "expected HTTP 201 on valid Passkey approval POST, got {http_status}: {resp_json}"
        );

        let (status, stdout) = proc.wait_stdout_output(Duration::from_secs(10));
        let stderr = proc.stderr_snapshot();
        (status.code().unwrap_or(-1), stdout, stderr, action)
    }

    /// Convenience wrapper around `run_and_approve` for `--json` commands.
    pub fn run_and_approve_json(
        &self,
        home: &Path,
        args: &[&str],
        stdin_data: Option<&str>,
    ) -> (i32, Value, String, hyp_crypto::human::HumanApprovalActionV1) {
        let (code, stdout, stderr, action) = self.run_and_approve(home, args, stdin_data);
        let parsed: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "invalid JSON stdout from approved hyp {args:?} ({e}):\ncode={code}\nstdout={stdout:?}\nstderr={stderr}"
            )
        });
        (code, parsed, stderr, action)
    }
}
