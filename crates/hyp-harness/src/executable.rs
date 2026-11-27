//! Filesystem and PATH lookup primitives with explicit caller policies.

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

pub fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Candidate spellings to try after the direct filename on Windows.
#[derive(Clone, Copy)]
pub enum WindowsSuffixes {
    None,
    ReplaceExe,
    AppendCommon,
    ReplaceCommonIfMissing,
    PathExt,
}

#[derive(Clone, Copy)]
pub struct PathSearchPolicy {
    pub include_empty: bool,
    pub executable: bool,
    pub windows_suffixes: WindowsSuffixes,
}

/// Searches PATH in order without spawning a process or canonicalizing the result.
pub fn find_in_path(name: &Path, paths: &OsStr, policy: PathSearchPolicy) -> Option<PathBuf> {
    std::env::split_paths(paths)
        .filter(|dir| policy.include_empty || !dir.as_os_str().is_empty())
        .find_map(|dir| find_in_directory(&dir, name, policy))
}

pub fn find_in_directory(dir: &Path, name: &Path, policy: PathSearchPolicy) -> Option<PathBuf> {
    let matches = |path: &Path| {
        if policy.executable {
            is_executable_file(path)
        } else {
            path.is_file()
        }
    };
    let direct = dir.join(name);
    if matches(&direct) {
        return Some(direct);
    }
    #[cfg(windows)]
    {
        let append = |suffix: &str| {
            let mut candidate = name.as_os_str().to_os_string();
            candidate.push(suffix);
            dir.join(candidate)
        };
        return match policy.windows_suffixes {
            WindowsSuffixes::None => None,
            WindowsSuffixes::ReplaceExe => {
                let candidate = direct.with_extension("exe");
                matches(&candidate).then_some(candidate)
            }
            WindowsSuffixes::AppendCommon => [".exe", ".cmd", ".bat"]
                .iter()
                .map(|suffix| append(suffix))
                .find(|path| matches(path)),
            WindowsSuffixes::ReplaceCommonIfMissing if name.extension().is_none() => {
                ["exe", "cmd", "bat"]
                    .iter()
                    .map(|suffix| direct.with_extension(suffix))
                    .find(|path| matches(path))
            }
            WindowsSuffixes::ReplaceCommonIfMissing => None,
            WindowsSuffixes::PathExt => {
                let extensions: Vec<String> = std::env::var("PATHEXT")
                    .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
                    .split(';')
                    .filter(|ext| !ext.trim().is_empty())
                    .map(|ext| ext.trim().to_string())
                    .collect();
                for extension in extensions {
                    let candidate = append(&extension);
                    if matches(&candidate) {
                        return Some(candidate);
                    }
                    let lower = append(&extension.to_ascii_lowercase());
                    if matches(&lower) {
                        return Some(lower);
                    }
                }
                None
            }
        };
    }
    #[cfg(not(windows))]
    None
}
