//! Reproduces an installed-but-too-old runtime without changing the process PATH or host tools.
#[path = "../../test-support/node_runtime.rs"]
mod node_runtime;

use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn fake_node(dir: &Path, version: &str) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("node");
        fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{version}'\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[cfg(windows)]
    {
        let path = dir.join("node.cmd");
        fs::write(&path, format!("@echo off\r\necho {version}\r\n")).unwrap();
        path
    }
}

#[test]
fn installed_old_node_fails_clearly_while_missing_node_stays_optional() {
    let tmp = TempDir::new().unwrap();
    assert!(!node_runtime::node_available_at(
        tmp.path().join("missing-node").as_os_str()
    ));
    let old_node = fake_node(tmp.path(), "v18.18.0");
    let failure =
        std::panic::catch_unwind(|| node_runtime::node_available_at(old_node.as_os_str()))
            .expect_err("an installed old runtime must fail rather than skip or run a scenario");
    let message = failure.downcast_ref::<String>().unwrap();
    assert!(message.contains("requires Node >= 24"), "{message}");
    assert!(message.contains("found v18.18.0"), "{message}");
}

#[test]
fn minimum_and_newer_node_versions_are_accepted() {
    let tmp = TempDir::new().unwrap();
    for version in ["v24.0.0", "v25.0.0"] {
        let node = fake_node(tmp.path(), version);
        assert!(node_runtime::node_available_at(node.as_os_str()));
    }
}
