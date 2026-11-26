//! Atomic configuration and status writes with private filesystem permissions.

use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Ensures directory exists with `0700` permissions on Unix when `private == true`.
pub fn ensure_dir(dir: &Path, private: bool) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("failed to create directory {}: {e}", dir.display()))?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed to chmod 0700 {}: {e}", dir.display()))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}

/// Resolves the final filesystem write target for `dest` so atomic renames through an existing
/// symlink update the symlink's target in place instead of clobbering the symlink itself.
///
/// Fails closed on symlink loops or multi-hop broken chains: only resolves either an existing
/// target via `fs::canonicalize` or a single-hop dangling relative/absolute symlink whose direct
/// target does not yet exist.
fn resolve_symlink_write_target(dest: &Path) -> Result<PathBuf, String> {
    let Ok(meta) = fs::symlink_metadata(dest) else {
        return Ok(dest.to_path_buf());
    };
    if !meta.file_type().is_symlink() {
        return Ok(dest.to_path_buf());
    }

    match fs::canonicalize(dest) {
        Ok(resolved) => Ok(resolved),
        Err(canon_err) => {
            let raw_target = fs::read_link(dest)
                .map_err(|e| format!("failed to read symlink {}: {e}", dest.display()))?;
            let candidate = if raw_target.is_absolute() {
                raw_target
            } else {
                dest.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."))
                    .join(raw_target)
            };
            // Only allow a single-hop dangling link whose direct target does not exist yet.
            // If `symlink_metadata(&candidate)` succeeds (e.g. symlink loop / multi-hop broken
            // chain) or errors with anything other than NotFound (e.g. ELOOP / EACCES), fail closed.
            match fs::symlink_metadata(&candidate) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if candidate.file_name().is_none() {
                        return Err(format!(
                            "refusing to write through invalid symlink target {} (from {})",
                            candidate.display(),
                            dest.display()
                        ));
                    }
                    Ok(candidate)
                }
                _ => Err(format!(
                    "failed to resolve symlink {} (possible symlink loop or broken chain): {canon_err}",
                    dest.display()
                )),
            }
        }
    }
}

/// Atomically writes bytes to `dest` via sibling temporary file + `sync_all` + `rename`.
/// Enforces `0600` permissions on Unix when `private == true`.
///
/// If `dest` is an existing symlink, writes into the target's parent directory and atomically
/// renames over the resolved target path so the symlink at `dest` remains intact.
pub fn write_atomic_file(dest: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    let target = resolve_symlink_write_target(dest)?;
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_dir(parent, private)?;

    let rng = SystemRandom::new();
    let mut suffix = [0u8; 8];
    rng.fill(&mut suffix)
        .map_err(|_| "OS CSPRNG failure".to_string())?;
    let tmp_path = parent.join(format!(".tmp-hyp-{}", hex::encode(suffix)));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if private { 0o600 } else { 0o644 });
    }

    let res: Result<(), String> = (|| {
        let mut f = opts
            .open(&tmp_path)
            .map_err(|e| format!("failed to create temp file {}: {e}", tmp_path.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("failed to write {}: {e}", tmp_path.display()))?;
        f.sync_all()
            .map_err(|e| format!("failed to sync {}: {e}", tmp_path.display()))?;
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if private { 0o600 } else { 0o644 };
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("failed to set permissions on {}: {e}", tmp_path.display()))?;
        }
        fs::rename(&tmp_path, &target).map_err(|e| {
            format!(
                "failed to atomically rename {} -> {}: {e}",
                tmp_path.display(),
                target.display()
            )
        })?;
        Ok(())
    })();

    if res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    res
}

/// Atomically writes pretty-printed JSON with a trailing newline.
pub fn write_atomic_json(dest: &Path, value: &Value, private: bool) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(value)
        .map_err(|e| format!("failed to serialize JSON for {}: {e}", dest.display()))?;
    text.push('\n');
    write_atomic_file(dest, text.as_bytes(), private)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_file_creates_and_updates_regular_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("nested").join("config.json");
        write_atomic_file(&dest, b"{\"v\":1}\n", true).expect("initial write");
        assert_eq!(fs::read_to_string(&dest).unwrap(), "{\"v\":1}\n");

        write_atomic_file(&dest, b"{\"v\":2}\n", false).expect("overwrite");
        assert_eq!(fs::read_to_string(&dest).unwrap(), "{\"v\":2}\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_file_preserves_symlink_and_updates_target() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let real_dir = tmp.path().join("real");
        let profile_dir = tmp.path().join("profile");
        fs::create_dir_all(&real_dir).unwrap();
        fs::create_dir_all(&profile_dir).unwrap();

        let target = real_dir.join("settings.json");
        fs::write(&target, "{\"v\":1}\n").unwrap();
        let link = profile_dir.join("settings.json");
        symlink(&target, &link).unwrap();

        write_atomic_file(&link, b"{\"v\":2}\n", false).expect("atomic write through symlink");

        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink at dest must remain a symlink after write_atomic_file"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "{\"v\":2}\n");
        assert_eq!(fs::read_to_string(&link).unwrap(), "{\"v\":2}\n");

        // Relative symlink in a sibling directory also stays intact.
        let rel_link = profile_dir.join("rel-settings.json");
        symlink(Path::new("../real/settings.json"), &rel_link).unwrap();
        write_atomic_file(&rel_link, b"{\"v\":3}\n", false).expect("atomic write via rel symlink");
        assert!(
            fs::symlink_metadata(&rel_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "{\"v\":3}\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_file_handles_dangling_symlink_and_rejects_loops() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let real_dir = tmp.path().join("real");
        let profile_dir = tmp.path().join("profile");
        fs::create_dir_all(&profile_dir).unwrap();

        // Single-hop dangling symlink pointing to a non-existent target file.
        let dangling_target = real_dir.join("future.json");
        let dangling_link = profile_dir.join("future.json");
        symlink(&dangling_target, &dangling_link).unwrap();

        write_atomic_file(&dangling_link, b"{\"created\":true}\n", false)
            .expect("single-hop dangling symlink should write target and stay symlink");
        assert!(
            fs::symlink_metadata(&dangling_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(&dangling_target).unwrap(),
            "{\"created\":true}\n"
        );

        // Symlink loop must fail closed and leave symlinks untouched.
        let loop_a = profile_dir.join("loop-a.json");
        let loop_b = profile_dir.join("loop-b.json");
        symlink(&loop_b, &loop_a).unwrap();
        symlink(&loop_a, &loop_b).unwrap();

        let err = write_atomic_file(&loop_a, b"oops", false).unwrap_err();
        assert!(
            err.contains("symlink"),
            "expected symlink resolution error, got: {err}"
        );
        assert!(
            fs::symlink_metadata(&loop_a)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
