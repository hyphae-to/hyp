//! Shared restore-on-drop terminal guards; callers retain key parsing and screen policy.

use std::io::{self, Write};
#[cfg(unix)]
use std::{
    fs,
    io::Read,
    process::{Command, Stdio},
};

/// RAII alternate-screen + hidden-cursor guard.
///
/// Enters `\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l` on creation and unconditionally restores
/// `\x1b[?25h\x1b[0m\x1b[?1049l` on `leave()` or `Drop` (including early returns / panic unwinds).
pub(crate) struct AltScreenGuard {
    active: bool,
    inline_cursor: bool,
}

impl AltScreenGuard {
    pub(crate) fn wizard(enabled: bool) -> Self {
        Self::enter(enabled, false)
    }

    #[cfg(unix)]
    pub(crate) fn inspector(enabled: bool) -> Self {
        Self::enter(enabled, true)
    }

    fn enter(enabled: bool, inline_cursor: bool) -> Self {
        if enabled {
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l");
            let _ = out.flush();
        } else if inline_cursor {
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?25l");
            let _ = out.flush();
        }
        Self {
            active: enabled,
            inline_cursor,
        }
    }

    pub(crate) fn leave(&mut self) {
        if self.active {
            self.active = false;
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?25h\x1b[0m\x1b[?1049l");
            let _ = out.flush();
        } else if self.inline_cursor {
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?25h\x1b[0m\r\n");
            let _ = out.flush();
        }
    }
}

impl Drop for AltScreenGuard {
    fn drop(&mut self) {
        self.leave();
    }
}

/// Pure-Rust Unix `/dev/tty` raw-mode guard backed by `stty -g` / `stty raw -echo`.
/// Unconditionally restores the exact saved `stty` state in `Drop`.
#[cfg(unix)]
pub(crate) struct RawTtyGuard {
    saved_state: String,
    tty: fs::File,
    active: bool,
}

#[cfg(unix)]
impl RawTtyGuard {
    fn run_stty(tty: &fs::File, args: &[&str]) -> io::Result<std::process::Output> {
        let stdin_file = tty.try_clone()?;
        Command::new("stty")
            .args(args)
            .stdin(Stdio::from(stdin_file))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
    }

    pub(crate) fn enter(nonblocking: bool) -> io::Result<Self> {
        let tty = fs::File::open("/dev/tty")?;
        let saved_out = Self::run_stty(&tty, &["-g"])?;
        if !saved_out.status.success() {
            return Err(io::Error::other("stty -g failed on /dev/tty"));
        }
        let saved_state = String::from_utf8_lossy(&saved_out.stdout)
            .trim()
            .to_string();
        if saved_state.is_empty() {
            return Err(io::Error::other("stty -g returned empty state"));
        }

        let mut guard = Self {
            saved_state,
            tty,
            active: true,
        };
        if let Err(e) = guard.set_mode(nonblocking) {
            guard.restore();
            return Err(e);
        }
        Ok(guard)
    }

    pub(crate) fn set_mode(&self, nonblocking: bool) -> io::Result<()> {
        let args: &[&str] = if nonblocking {
            &["raw", "-echo", "min", "0", "time", "0"]
        } else {
            &["raw", "-echo", "min", "0", "time", "1"]
        };
        let out = Self::run_stty(&self.tty, args)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(io::Error::other("stty raw -echo failed on /dev/tty"))
        }
    }

    pub(crate) fn poll_any_key<K>(&mut self, parse: fn(&[u8]) -> K) -> Option<K> {
        let mut buf = [0u8; 8];
        match self.tty.read(&mut buf) {
            Ok(n) if n > 0 => Some(parse(&buf[..n])),
            _ => None,
        }
    }

    pub(crate) fn drain_pending(&mut self) {
        let mut buf = [0u8; 32];
        for _ in 0..4 {
            match self.tty.read(&mut buf) {
                Ok(n) if n > 0 => continue,
                _ => break,
            }
        }
    }

    /// Reads one key event with a ~100ms POSIX `stty raw -echo min 0 time 1` timeout.
    /// Returns `Ok(None)` on idle tick so the live banner can advance pulses with zero `unsafe`.
    pub(crate) fn read_key_timeout<K>(&mut self, parse: fn(&[u8]) -> K) -> io::Result<Option<K>> {
        let mut buf = [0u8; 8];
        match self.tty.read(&mut buf) {
            Ok(0) => Ok(None),
            Ok(n) => {
                let mut total = n;
                // If a lone ESC arrived, give the terminal one VTIME=1 (100ms) window
                // to deliver the remainder of an arrow-key escape sequence (`[A`/`OA`).
                if total == 1 && buf[0] == 0x1b {
                    if let Ok(extra) = self.tty.read(&mut buf[1..]) {
                        total += extra;
                    }
                }
                Ok(Some(parse(&buf[..total])))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn read_key<K>(&mut self, parse: fn(&[u8]) -> K) -> io::Result<K> {
        loop {
            if let Some(key) = self.read_key_timeout(parse)? {
                return Ok(key);
            }
        }
    }

    pub(crate) fn restore(&mut self) {
        if self.active {
            self.active = false;
            let _ = Self::run_stty(&self.tty, &[self.saved_state.as_str()]);
        }
    }
}

#[cfg(unix)]
impl Drop for RawTtyGuard {
    fn drop(&mut self) {
        self.restore();
    }
}
