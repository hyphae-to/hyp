//! Shared preflight for tests that execute the repository's Node 24 scripts.
use std::ffi::OsStr;
use std::io;
use std::process::Command;

pub const REQUIRED_NODE_MAJOR: u32 = 24;

/// Missing Node stays optional for callers that previously allowed it. An installed runtime
/// that cannot run these scripts is a toolchain error, not a skipped scenario.
#[allow(dead_code)]
pub fn node_available() -> bool {
    node_available_at(OsStr::new("node"))
}

pub fn node_available_at(executable: &OsStr) -> bool {
    let output = match Command::new(executable).arg("--version").output() {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(error) => {
            panic!("requires Node >= {REQUIRED_NODE_MAJOR}: could not run {executable:?}: {error}")
        }
    };
    let found = String::from_utf8_lossy(&output.stdout);
    let found = found.trim();
    assert!(
        output.status.success(),
        "requires Node >= {REQUIRED_NODE_MAJOR}: {executable:?} --version failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let major = found
        .strip_prefix('v')
        .unwrap_or(found)
        .split('.')
        .next()
        .and_then(|part| part.parse::<u32>().ok());
    assert!(
        major.is_some_and(|major| major >= REQUIRED_NODE_MAJOR),
        "requires Node >= {REQUIRED_NODE_MAJOR}, found {found} ({executable:?}); install the version in .tool-versions"
    );
    true
}
