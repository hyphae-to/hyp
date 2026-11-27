//! Compatibility facade for the harness APIs. Each implementation can also be built independently.

pub use hyp_daemon::{call_registry, daemon, local_kv};
pub use hyp_harness_client::{hooks, mcp, wait};
pub use hyp_harness_ipc::{enable_test_env_isolation, paths, protocol, sock};
pub use hyp_harness_plugins::{node_config, plugin_registry, plugin_runtime};
pub use hyp_harness_transport::{executable, transport};
pub use hyp_proto::PROTOCOL_VERSION;
