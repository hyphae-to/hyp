//! Hyphae v2 unified `Node` engine: local/router/p2p profiles, E2EE federation,
//! adapters (`github-public`, webhooks, unified fd-3/JSON-RPC 2.0 subprocess supervisor),
//! and Local Security Gates (Stage 1 deterministic + Stage 2 isolated LLM guard).

pub mod adapters;
pub mod delivery;
pub mod engine;
pub mod gates;
