//! Hyphae v2 harness fast-path shim and adapters.
//!
//! Milestone M0 provides drop-in native Rust shims speaking the live v1 `connector.sock` NDJSON
//! protocol to the existing TypeScript `hyp daemon`:
//! - [`hooks`] — zero-Tokio synchronous `hyp-rs hook` (1–3 ms cold start)
//! - [`mcp`] — async stdio JSON-RPC 2.0 MCP server with lean 4-tool core catalog (+ conditional `hyp_bridge`)
//! - [`wait`] — zero-polling blocking `wait` and streaming `watch` client
//! - [`sock`] — bounded NDJSON Unix socket client (both sync and async)

pub mod hooks;
pub mod mcp;
pub mod protocol;
pub mod sock;
pub mod wait;

pub use hyp_proto::PROTOCOL_VERSION;
