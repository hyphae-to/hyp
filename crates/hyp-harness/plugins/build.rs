//! Compile the official registry's ID policies without runtime parsing.
use std::{collections::BTreeSet, env, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=plugin_specs.json");
    let specs: serde_json::Value = serde_json::from_str(include_str!("plugin_specs.json"))
        .expect("invalid official plugin registry");
    let specs = specs
        .as_array()
        .expect("official plugin registry must be an array");
    let mut seen = BTreeSet::new();
    let mut consumers = Vec::new();
    let mut sources = Vec::new();
    for spec in specs {
        let id = spec["id"]
            .as_str()
            .expect("official plugin ID must be a string");
        assert!(seen.insert(id), "duplicate official plugin ID: {id}");
        let kind = spec["kind"]
            .as_str()
            .expect("official plugin kind must be a string");
        assert!(
            matches!(kind, "bridge" | "harness"),
            "invalid official plugin kind: {kind}"
        );
        if kind == "bridge" && id != "sdk" {
            consumers.push(id);
        }
        if spec["defaultSource"]
            .as_bool()
            .expect("defaultSource must be a boolean")
        {
            assert_eq!(kind, "bridge", "only bridge plugins can default to source");
            sources.push(id);
        }
    }
    let generated = format!(
        "pub const BRIDGE_CONSUMER_IDS: &[&str] = &{consumers:?};\npub const OFFICIAL_SOURCE_PLUGIN_IDS: &[&str] = &{sources:?};\n"
    );
    fs::write(
        Path::new(&env::var("OUT_DIR").expect("OUT_DIR not set")).join("plugin_ids.rs"),
        generated,
    )
    .expect("failed to generate official plugin IDs");
}
