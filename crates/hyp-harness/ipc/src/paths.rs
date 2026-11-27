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

pub fn transport_home_dir() -> PathBuf {
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

pub fn transport_config_dir() -> PathBuf {
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
}
