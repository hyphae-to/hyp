use hyp_harness_ipc::paths::{transport_config_dir, transport_home_dir};
use std::path::PathBuf;

#[test]
fn transport_paths_honor_test_environment_isolation() {
    const CHILD: &str = "HYP_TEST_ISOLATED_PATHS";
    if std::env::var_os(CHILD).is_some() {
        hyp_harness_ipc::enable_test_env_isolation();
        assert_eq!(transport_home_dir(), PathBuf::from("."));
        assert_eq!(
            transport_config_dir(),
            PathBuf::from(".").join(".config").join("hyphae")
        );
        assert_eq!(
            hyp_harness_transport::transport::t3::default_t3_base_dir(),
            PathBuf::from(".").join(".t3")
        );
        std::fs::write(std::env::var_os("HYP_TEST_PATHS_SENTINEL").unwrap(), b"ran").unwrap();
        return;
    }
    let temp = tempfile::TempDir::new().unwrap();
    let sentinel = temp.path().join("child-ran");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "transport_paths_honor_test_environment_isolation",
        ])
        .env_clear()
        .env(CHILD, "1")
        .env("HYP_TEST_PATHS_SENTINEL", &sentinel)
        .env("HOME", "/hyp-hermetic-home")
        .env("USERPROFILE", "/hyp-hermetic-profile")
        .env("HYPHAE_CONFIG_DIR", "/hyp-hermetic-config")
        .env("XDG_CONFIG_HOME", "/hyp-hermetic-xdg")
        .env("APPDATA", "/hyp-hermetic-appdata")
        .env("T3CODE_HOME", "/hyp-hermetic-t3")
        .env("TMP", temp.path())
        .env("TEMP", temp.path())
        .env("TMPDIR", temp.path());
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", system_root);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(sentinel).unwrap(), b"ran");
}
