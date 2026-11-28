//! Hyphae v2 standards-first wire protocol primitives.
//!
//! Pure, zero-I/O protocol types, validators, canonicalization, filter AST,
//! scopes, capability manifest negotiation, RFC 9457 Problem Details, and
//! JSON-RPC 2.0 / legacy fd-3 v1 plugin NDJSON framing.

pub mod address;
mod build_version;
pub mod cloudevent;
pub mod filter;
pub mod jcs;
pub mod manifest;
pub mod problem;
pub mod rfc3339;
pub mod rpc;
pub mod scopes;
pub mod uuid;

/// Release identity compiled into the running binary.
pub fn build_version() -> &'static str {
    build_version::resolve_build_version(
        option_env!("HYPHAE_BUILD_VERSION"),
        env!("CARGO_PKG_VERSION"),
    )
}

/// Current Hyphae wire protocol version.
pub const PROTOCOL_VERSION: u32 = 2;
/// Minimum supported wire protocol version (v1 legacy TypeScript interop).
pub const MIN_PROTOCOL_VERSION: u32 = 1;
