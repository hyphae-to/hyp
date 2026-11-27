//! Shared home lookup and transport config paths with explicit ambient-environment isolation.

use std::path::PathBuf;

/// Resolves HOME before USERPROFILE, preserving non-empty values exactly as supplied.
pub fn home_dir_from_env(mut read: impl FnMut(&str) -> Option<String>) -> Option<PathBuf> {
    for key in ["HOME", "USERPROFILE"] {
        if let Some(value) = read(key) {
            if !value.trim().is_empty() {
                return Some(PathBuf::from(value));
            }
        }
    }
    None
}

pub(crate) fn transport_home_dir() -> PathBuf {
    home_dir_from_env(crate::ambient_env_var).unwrap_or_else(|| PathBuf::from("."))
}

fn transport_config_dir_from_env(mut read: impl FnMut(&str) -> Option<String>) -> PathBuf {
    if let Some(value) = read("HYPHAE_CONFIG_DIR") {
        if !value.trim().is_empty() {
            return PathBuf::from(value.trim());
        }
    }
    if let Some(value) = read("XDG_CONFIG_HOME") {
        if !value.trim().is_empty() {
            return PathBuf::from(value.trim()).join("hyphae");
        }
    }
    #[cfg(windows)]
    if let Some(value) = read("APPDATA") {
        if !value.trim().is_empty() {
            return PathBuf::from(value.trim()).join("hyphae");
        }
    }
    home_dir_from_env(read)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("hyphae")
}

pub(crate) fn transport_config_dir() -> PathBuf {
    transport_config_dir_from_env(crate::ambient_env_var)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_precedence_and_transport_config_overrides_remain_distinct() {
        let values = |key: &str| match key {
            "HOME" => Some(" /home-with-spaces ".to_owned()),
            "USERPROFILE" => Some("/profile".to_owned()),
            "HYPHAE_CONFIG_DIR" => Some(" /explicit-config ".to_owned()),
            _ => None,
        };
        assert_eq!(
            home_dir_from_env(values),
            Some(PathBuf::from(" /home-with-spaces "))
        );
        assert_eq!(
            transport_config_dir_from_env(values),
            PathBuf::from("/explicit-config")
        );
        assert_eq!(
            home_dir_from_env(|key| (key == "USERPROFILE").then(|| "/profile".to_owned())),
            Some(PathBuf::from("/profile"))
        );
        assert_eq!(home_dir_from_env(|_| None), None);
        let appdata_only = transport_config_dir_from_env(|key| {
            (key == "APPDATA").then(|| " /roaming ".to_owned())
        });
        #[cfg(windows)]
        assert_eq!(appdata_only, PathBuf::from("/roaming").join("hyphae"));
        #[cfg(not(windows))]
        assert_eq!(
            appdata_only,
            PathBuf::from(".").join(".config").join("hyphae")
        );
    }

    #[test]
    fn transport_paths_honor_test_environment_isolation() {
        const CHILD: &str = "HYP_TEST_ISOLATED_PATHS";
        if std::env::var_os(CHILD).is_some() {
            crate::enable_test_env_isolation();
            assert_eq!(transport_home_dir(), PathBuf::from("."));
            assert_eq!(
                transport_config_dir(),
                PathBuf::from(".").join(".config").join("hyphae")
            );
            assert_eq!(
                crate::transport::t3::default_t3_base_dir(),
                PathBuf::from(".").join(".t3")
            );
            return;
        }
        let temp = tempfile::TempDir::new().unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "paths::tests::transport_paths_honor_test_environment_isolation",
            ])
            .env_clear()
            .env(CHILD, "1")
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
    }
}
