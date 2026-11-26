//! Hyphae v2 standards-first wire protocol primitives.
//!
//! Pure, zero-I/O protocol types, validators, canonicalization, filter AST,
//! scopes, capability manifest negotiation, RFC 9457 Problem Details, and
//! JSON-RPC 2.0 / legacy fd-3 v1 plugin NDJSON framing.

pub mod address;
pub mod cloudevent;
pub mod filter;
pub mod jcs;
pub mod manifest;
pub mod problem;
pub mod rpc;
pub mod scopes;

/// Current Hyphae wire protocol version.
pub const PROTOCOL_VERSION: u32 = 2;
/// Minimum supported wire protocol version (v1 legacy TypeScript interop).
pub const MIN_PROTOCOL_VERSION: u32 = 1;
