//! Private Unix bind mechanics; callers retain their parent/stale-path/liveness policies.
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(super) fn bind_private_unix_socket(path: &Path) -> io::Result<tokio::net::UnixListener> {
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
