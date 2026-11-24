//! Hyphae v2 harness runtime, native Rust `LocalDaemon`, and fast-path shims:
//! - [`call_registry`] — fail-closed host-verified caller session & in-flight call registry
//! - [`daemon`] — standalone async native Rust `LocalDaemon` (`connector.sock` / Windows `connector.addr`)
//! - [`hooks`] — zero-Tokio synchronous `hyp hook` (1–3 ms cold start)
//! - [`mcp`] — async stdio JSON-RPC 2.0 MCP server with lean 4-tool core catalog (+ conditional `hyp_bridge` & `hyp_kv`)
//! - [`wait`] — zero-polling blocking `wait` and streaming `watch` client
//! - [`sock`] — bounded NDJSON Unix socket / Windows loopback TCP client (sync and async)

pub mod call_registry;
pub mod daemon;
pub mod hooks;
pub mod mcp;
pub mod protocol;
pub mod sock;
pub mod wait;

pub use hyp_proto::PROTOCOL_VERSION;
