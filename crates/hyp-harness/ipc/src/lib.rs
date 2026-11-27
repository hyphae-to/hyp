//! Local harness IPC shared by client shims and the daemon.
//! Owns the wire contract, socket framing, caller identifiers and ambient harness environment.

pub mod caller;
pub mod hints;
pub mod kv_auth;
pub mod paths;
pub mod protocol;
pub mod sock;

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};

static IGNORE_AMBIENT_HARNESS_ENV: AtomicBool = AtomicBool::new(false);

/// Disables reading ambient live-harness environment variables (`HYPHAE_SESSION_*`,
/// `HC_TERMINAL_ID`, `CLAUDE_ENV_FILE`, `CODEX_*`, `T3*`, `HYPHAE_CONFIG`, etc.)
/// inside in-process integration tests so `cargo test --workspace` stays 100% hermetic
/// even when invoked from inside an active Claude Code / Herdr / Codex / OpenClaw session.
pub fn enable_test_env_isolation() {
    IGNORE_AMBIENT_HARNESS_ENV.store(true, Ordering::SeqCst);
}

/// Reads an ambient harness/session environment variable unless in-process test
/// isolation has been enabled via [`enable_test_env_isolation`].
pub fn ambient_env_var(key: &str) -> Option<String> {
    if IGNORE_AMBIENT_HARNESS_ENV.load(Ordering::Relaxed) {
        return None;
    }
    std::env::var(key).ok()
}

/// Reads an ambient harness/session OS environment variable unless in-process test
/// isolation has been enabled via [`enable_test_env_isolation`].
pub fn ambient_env_var_os(key: &str) -> Option<OsString> {
    if IGNORE_AMBIENT_HARNESS_ENV.load(Ordering::Relaxed) {
        return None;
    }
    std::env::var_os(key)
}
