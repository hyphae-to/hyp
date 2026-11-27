//! Hyphae v2 harness runtime, native Rust `LocalDaemon`, and fast-path shims:
//! - [`call_registry`] — fail-closed host-verified caller session & in-flight call registry
//! - [`daemon`] — standalone async native Rust `LocalDaemon` (`connector.sock` / Windows `connector.addr`)
//! - [`hooks`] — zero-Tokio synchronous `hyp hook` (1–3 ms cold start)
//! - [`mcp`] — async stdio JSON-RPC 2.0 MCP server with lean 4-tool core catalog (+ conditional `hyp_bridge` & `hyp_kv`)
//! - [`wait`] — zero-polling blocking `wait` and streaming `watch` client
//! - [`sock`] — bounded NDJSON Unix socket / Windows loopback TCP client (sync and async)

pub mod call_registry;
pub mod daemon;
pub mod executable;
pub mod hooks;
pub mod local_kv;
pub mod mcp;
pub mod node_config;
pub mod plugin_runtime;
pub mod protocol;
pub mod sock;
pub mod transport;
pub mod wait;

pub use hyp_proto::PROTOCOL_VERSION;

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
pub(crate) fn ambient_env_var(key: &str) -> Option<String> {
    if IGNORE_AMBIENT_HARNESS_ENV.load(Ordering::Relaxed) {
        return None;
    }
    std::env::var(key).ok()
}

/// Reads an ambient harness/session OS environment variable unless in-process test
/// isolation has been enabled via [`enable_test_env_isolation`].
pub(crate) fn ambient_env_var_os(key: &str) -> Option<OsString> {
    if IGNORE_AMBIENT_HARNESS_ENV.load(Ordering::Relaxed) {
        return None;
    }
    std::env::var_os(key)
}
