//! Plugin configuration, registry policies, and subprocess supervision.

pub mod node_config;
/// Official plugin ID policies generated from the shared registry.
pub mod plugin_registry {
    include!(concat!(env!("OUT_DIR"), "/plugin_ids.rs"));
}
pub mod plugin_runtime;
