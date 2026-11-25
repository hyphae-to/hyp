//! Shared zero-flake CLI integration test harness for `hyp-cli`.
//!
//! Enforces strict test isolation (`HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`,
//! `HYPHAE_SECRET_BACKEND=file`, `HYPHAE_NO_OPEN=1`, full `HYPHAE_*` env scrubbing),
//! bounded-timeout process I/O (never hangs CI on a stalled child), guaranteed child
//! process reaping in `Drop`, and deterministic session readiness polling.

#![allow(dead_code)]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write as _};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Path to the compiled `hyp` binary under test.
pub fn hyp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hyp")
}

/// Constructs a `Command` for the compiled `hyp` binary with complete environment
/// isolation so live user config, sockets, Keychain, and ambient `HYPHAE_*` variables
/// can never leak into tests.
pub fn isolated_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(hyp_bin());
    cmd.env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HYPHAE_NO_OPEN", "1")
        .env_remove("HYPHAE_CONFIG")
        .env_remove("HYPHAE_STATE_DIR")
        .env_remove("HYPHAE_CONFIG_DIR")
        .env_remove("HYPHAE_SOCKET")
        .env_remove("AGENTS_MESH_SOCKET")
        .env_remove("HYPHAE_RELEASE_PUBKEY")
        .env_remove("HYPHAE_DISABLE_AUTO_UPDATE")
        .env_remove("HYPHAE_DROP_PORTAL_URL");
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
        let res = hyp_harness::sock::daemon_rpc_sync(
            socket_path,
            &req,
            Duration::from_millis(500),
        );
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
