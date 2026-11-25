//! `hyp uninstall` — Safe, non-destructive full Hyphae uninstaller.
//!
//! By default, executes the verified `scripts/uninstall.sh` embedded directly inside the
//! compiled `hyp` binary (offline-safe, zero supply-chain network fetch). Pass `--latest`
//! to download the latest `https://hyphae.to/uninstall.sh` over HTTPS, verify its script
//! header and print its SHA-256 digest before executing it.

#[cfg(unix)]
use crate::config_file::build_http_client;
use crate::ui::{EXIT_ERROR, EXIT_OK, EXIT_USAGE, emit_error};
use clap::Args;
use http::Uri;
#[cfg(unix)]
use http::{Method, Request, header};
#[cfg(unix)]
use http_body_util::{BodyExt, Empty};
#[cfg(unix)]
use hyper::body::Bytes;
#[cfg(unix)]
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(unix))]
use std::process::ExitCode;
#[cfg(unix)]
use std::process::{Command, ExitCode, Stdio};
#[cfg(unix)]
use std::time::Duration;

/// Default HTTPS source for `hyp uninstall --latest`.
#[cfg_attr(not(unix), allow(dead_code))]
pub const DEFAULT_UNINSTALL_SCRIPT_URL: &str = "https://hyphae.to/uninstall.sh";

/// Embedded `scripts/uninstall.sh` matching this signed binary version (offline-safe default).
#[cfg_attr(not(unix), allow(dead_code))]
pub const EMBEDDED_UNINSTALL_SH: &str = include_str!("../../../scripts/uninstall.sh");

/// Upper bound on downloaded `uninstall.sh` script payload (`--latest`).
#[cfg_attr(not(unix), allow(dead_code))]
pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;

#[cfg(unix)]
const SCRIPT_FETCH_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(unix)]
const MAX_REDIRECTS: usize = 3;

#[derive(Debug, Clone, Args)]
pub struct UninstallArgs {
    /// Download the latest uninstall.sh from https://hyphae.to/uninstall.sh over HTTPS instead of running the embedded script
    #[arg(long)]
    pub latest: bool,

    /// Override download URL for --latest (https:// only, or loopback http://127.0.0.1 / http://[::1] for testing)
    #[arg(long, hide = true)]
    pub script_url: Option<String>,

    /// Print complete removal/restore plan without modifying anything
    #[arg(long, short = 'n')]
    pub dry_run: bool,

    /// Skip interactive confirmation prompt
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Keep the installed `hyp` binary (~/.local/bin/hyp)
    #[arg(long)]
    pub keep_binary: bool,

    /// Keep ~/.config/hyphae state, keys, and database
    #[arg(long)]
    pub keep_state: bool,

    /// Leave OS Keychain / Linux Secret Service entries untouched
    #[arg(long, alias = "skip-keychain")]
    pub keep_keychain: bool,

    /// Leave harness configs, skills, slash commands, statusLines, and Herdr mod untouched
    #[arg(long)]
    pub keep_harnesses: bool,

    /// Override HOME directory (ideal for isolated testing)
    #[arg(long)]
    pub home: Option<PathBuf>,
}

/// Executes `hyp uninstall`.
pub fn run_uninstall(args: UninstallArgs) -> ExitCode {
    if !args.latest && args.script_url.is_some() {
        return emit_error(
            "uninstall",
            false,
            EXIT_USAGE,
            "INVALID_FLAGS",
            "`--script-url` requires `--latest`",
            Some(
                "Pass `--latest --script-url <url>` or omit `--script-url` to run the embedded uninstaller."
                    .to_string(),
            ),
        );
    }

    #[cfg(unix)]
    {
        run_uninstall_unix(args)
    }

    #[cfg(not(unix))]
    {
        run_uninstall_windows(args)
    }
}

/// Validates a `--latest` / `--script-url` target fail-closed:
/// - Requires `https://` with a non-empty host (no credentials/userinfo)
/// - Permits `http://` ONLY for local loopback (`127.0.0.1` or `[::1]`) for testing.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn validate_uninstall_script_url(raw: &str) -> Result<Uri, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("uninstall script URL must not be empty".to_string());
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(
            "uninstall script URL must not contain whitespace or control characters".to_string(),
        );
    }

    let uri: Uri = trimmed
        .parse()
        .map_err(|e| format!("invalid uninstall script URL '{trimmed}': {e}"))?;

    let scheme = uri
        .scheme_str()
        .ok_or_else(|| format!("missing URL scheme in '{trimmed}' (expected https://)"))?;

    let authority = uri
        .authority()
        .ok_or_else(|| format!("missing host in URL '{trimmed}'"))?;
    if authority.as_str().contains('@') {
        return Err(format!(
            "refusing URL with embedded credentials/userinfo: '{trimmed}'"
        ));
    }

    let host = uri
        .host()
        .ok_or_else(|| format!("missing host in URL '{trimmed}'"))?;
    if host.is_empty() {
        return Err(format!("empty host in URL '{trimmed}'"));
    }

    match scheme {
        "https" => Ok(uri),
        "http" => {
            if matches!(host, "127.0.0.1" | "[::1]" | "::1") {
                Ok(uri)
            } else {
                Err(format!(
                    "refusing insecure http:// URL '{trimmed}': https:// is required (http:// is allowed only for 127.0.0.1 / [::1])"
                ))
            }
        }
        other => Err(format!(
            "unsupported URL scheme '{other}' in '{trimmed}': https:// is required"
        )),
    }
}

/// Validates downloaded `uninstall.sh` bytes fail-closed:
/// - Non-empty, `<= MAX_SCRIPT_BYTES`, valid UTF-8
/// - First line must be `#!/usr/bin/env bash` or `#!/usr/bin/env sh`
#[cfg_attr(not(unix), allow(dead_code))]
pub fn validate_uninstall_script_body(bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() {
        return Err("downloaded uninstall script is empty".to_string());
    }
    if bytes.len() > MAX_SCRIPT_BYTES {
        return Err(format!(
            "downloaded uninstall script exceeds {} byte safety limit",
            MAX_SCRIPT_BYTES
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| format!("downloaded uninstall script is not valid UTF-8: {e}"))?;
    let first_line = text.lines().next().unwrap_or("");
    if first_line != "#!/usr/bin/env bash" && first_line != "#!/usr/bin/env sh" {
        return Err(format!(
            "downloaded script has unexpected shebang '{first_line}' (expected '#!/usr/bin/env bash' or '#!/usr/bin/env sh')"
        ));
    }
    Ok(text.to_string())
}

/// Computes lowercase hex SHA-256 digest of `bytes`.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Builds the exact flag list forwarded to `uninstall.sh`.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn build_script_args(args: &UninstallArgs) -> Vec<&'static str> {
    let mut forwarded = Vec::new();
    if args.dry_run {
        forwarded.push("--dry-run");
    }
    if args.yes {
        forwarded.push("--yes");
    }
    if args.keep_binary {
        forwarded.push("--keep-binary");
    }
    if args.keep_state {
        forwarded.push("--keep-state");
    }
    if args.keep_keychain {
        forwarded.push("--keep-keychain");
    }
    if args.keep_harnesses {
        forwarded.push("--keep-harnesses");
    }
    forwarded
}

#[cfg(unix)]
struct TempScriptGuard {
    dir: PathBuf,
    script: PathBuf,
}

#[cfg(unix)]
impl TempScriptGuard {
    fn write_private(script_body: &str) -> Result<Self, String> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let rng = SystemRandom::new();
        let mut suffix = [0u8; 8];
        rng.fill(&mut suffix)
            .map_err(|_| "OS CSPRNG failure".to_string())?;
        let dir = std::env::temp_dir().join(format!("hyp-uninstall-{}", hex::encode(suffix)));
        fs::create_dir(&dir)
            .map_err(|e| format!("failed to create private temp dir {}: {e}", dir.display()))?;
        if let Err(e) = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir_all(&dir);
            return Err(format!(
                "failed to chmod 0700 temp dir {}: {e}",
                dir.display()
            ));
        }

        let script = dir.join("uninstall.sh");
        let write_res: Result<(), String> = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&script)
                .map_err(|e| format!("failed to create {}: {e}", script.display()))?;
            f.write_all(script_body.as_bytes())
                .map_err(|e| format!("failed to write {}: {e}", script.display()))?;
            f.sync_all()
                .map_err(|e| format!("failed to sync {}: {e}", script.display()))?;
            drop(f);
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("failed to chmod 0700 {}: {e}", script.display()))?;
            Ok(())
        })();

        if let Err(e) = write_res {
            let _ = fs::remove_dir_all(&dir);
            return Err(e);
        }

        Ok(Self { dir, script })
    }

    fn script_path(&self) -> &Path {
        &self.script
    }
}

#[cfg(unix)]
impl Drop for TempScriptGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.script);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn run_uninstall_unix(args: UninstallArgs) -> ExitCode {
    let script_content = if args.latest {
        let url = args
            .script_url
            .as_deref()
            .unwrap_or(DEFAULT_UNINSTALL_SCRIPT_URL);
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return emit_error(
                    "uninstall",
                    false,
                    EXIT_ERROR,
                    "RUNTIME_ERROR",
                    format!("Failed to initialize async runtime: {e}"),
                    Some(
                        "Re-run `hyp uninstall` without `--latest` to use the embedded script bundled with this binary."
                            .to_string(),
                    ),
                );
            }
        };

        match rt.block_on(fetch_latest_uninstall_script(url)) {
            Ok((text, digest, final_url)) => {
                println!("Downloaded latest uninstall.sh from {final_url} (sha256: {digest})");
                text
            }
            Err((code, msg)) => {
                return emit_error(
                    "uninstall",
                    false,
                    EXIT_ERROR,
                    code,
                    msg,
                    Some(
                        "Re-run `hyp uninstall` without `--latest` to use the embedded script bundled with this binary."
                            .to_string(),
                    ),
                );
            }
        }
    } else {
        EMBEDDED_UNINSTALL_SH.to_string()
    };

    let guard = match TempScriptGuard::write_private(&script_content) {
        Ok(g) => g,
        Err(e) => {
            return emit_error(
                "uninstall",
                false,
                EXIT_ERROR,
                "TEMP_SCRIPT_ERROR",
                e,
                None,
            );
        }
    };

    let forwarded = build_script_args(&args);
    let mut cmd = Command::new("/usr/bin/env");
    cmd.arg("bash")
        .arg(guard.script_path())
        .args(&forwarded)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(ref home) = args.home {
        cmd.env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_STATE_HOME", home.join(".local").join("state"));
    }

    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                "uninstall",
                false,
                EXIT_ERROR,
                "EXEC_ERROR",
                format!("Failed to run uninstall.sh via bash: {e}"),
                None,
            );
        }
    };

    drop(guard);

    match status.code() {
        Some(0) => ExitCode::from(EXIT_OK),
        Some(code) if code > 0 && code <= 255 => ExitCode::from(code as u8),
        _ => ExitCode::from(EXIT_ERROR),
    }
}

#[cfg(unix)]
async fn fetch_latest_uninstall_script(
    initial_url: &str,
) -> Result<(String, String, String), (&'static str, String)> {
    let mut current_url = initial_url.trim().to_string();
    let mut current_uri =
        validate_uninstall_script_url(&current_url).map_err(|e| ("UNSAFE_URL", e))?;
    let client = build_http_client::<Empty<Bytes>>().map_err(|e| ("HTTP_INIT_ERROR", e))?;

    for redirect_count in 0..=MAX_REDIRECTS {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&current_uri)
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(Empty::new())
            .map_err(|e| ("HTTP_ERROR", format!("Failed to build request: {e}")))?;

        let resp = tokio::time::timeout(SCRIPT_FETCH_TIMEOUT, client.request(req))
            .await
            .map_err(|_| {
                (
                    "HTTP_TIMEOUT",
                    format!(
                        "GET {current_url} timed out after {}s",
                        SCRIPT_FETCH_TIMEOUT.as_secs()
                    ),
                )
            })?
            .map_err(|e| ("HTTP_ERROR", format!("GET {current_url} failed: {e}")))?;

        let status = resp.status();
        if status.is_redirection() {
            if redirect_count >= MAX_REDIRECTS {
                return Err((
                    "TOO_MANY_REDIRECTS",
                    format!("GET {current_url} exceeded {MAX_REDIRECTS} redirects"),
                ));
            }
            let location = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    (
                        "HTTP_ERROR",
                        format!(
                            "GET {current_url} returned redirect HTTP {} without Location header",
                            status.as_u16()
                        ),
                    )
                })?;
            let next_url = if location.starts_with("http://") || location.starts_with("https://") {
                location.to_string()
            } else if location.starts_with('/') {
                let scheme = current_uri.scheme_str().unwrap_or("https");
                let authority = current_uri
                    .authority()
                    .map(|a| a.as_str())
                    .unwrap_or_default();
                format!("{scheme}://{authority}{location}")
            } else {
                return Err((
                    "UNSAFE_REDIRECT",
                    format!("Refusing unsupported redirect Location '{location}'"),
                ));
            };
            let next_uri = validate_uninstall_script_url(&next_url)
                .map_err(|e| ("UNSAFE_REDIRECT", e))?;
            if current_uri.scheme_str() == Some("https") && next_uri.scheme_str() != Some("https") {
                return Err((
                    "UNSAFE_REDIRECT",
                    format!("Refusing HTTPS-to-HTTP downgrade redirect to '{next_url}'"),
                ));
            }
            current_url = next_url;
            current_uri = next_uri;
            continue;
        }

        if !status.is_success() {
            return Err((
                "HTTP_STATUS",
                format!("GET {current_url} returned HTTP {}", status.as_u16()),
            ));
        }

        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|e| ("HTTP_ERROR", format!("body read error: {e}")))?;
            if let Some(chunk) = frame.data_ref() {
                if out.len().saturating_add(chunk.len()) > MAX_SCRIPT_BYTES {
                    return Err((
                        "RESPONSE_TOO_LARGE",
                        format!(
                            "Download from {current_url} exceeds {MAX_SCRIPT_BYTES} byte limit"
                        ),
                    ));
                }
                out.extend_from_slice(chunk);
            }
        }

        let text = validate_uninstall_script_body(&out).map_err(|e| ("INVALID_SCRIPT", e))?;
        let digest = sha256_hex(&out);
        return Ok((text, digest, current_url));
    }

    Err((
        "TOO_MANY_REDIRECTS",
        format!("GET {initial_url} exceeded redirect limit"),
    ))
}

#[cfg(not(unix))]
fn run_uninstall_windows(args: UninstallArgs) -> ExitCode {
    let _ = (
        args.latest,
        &args.script_url,
        args.yes,
        args.keep_binary,
        args.keep_state,
        args.keep_keychain,
        args.keep_harnesses,
        &args.home,
    );
    println!("Hyphae Windows uninstall steps (PowerShell):");
    println!(
        "  1. Stop running daemons:    Get-Process hyp -ErrorAction SilentlyContinue | Stop-Process"
    );
    println!(
        "  2. Restore statusLines:     hyp setup --harness claude,antigravity --restore-statusline"
    );
    println!(
        "  3. Remove Hyphae state:     Remove-Item -Recurse -Force \"$env:USERPROFILE\\.config\\hyphae\", \"$env:LOCALAPPDATA\\hyphae\" -ErrorAction SilentlyContinue"
    );
    println!(
        "  4. Remove harness skills:   Remove-Item -Recurse -Force \"$env:USERPROFILE\\.claude\\skills\\hyphae*\", \"$env:USERPROFILE\\.codex\\skills\\hyphae*\" -ErrorAction SilentlyContinue"
    );
    println!(
        "  5. Remove hyp binary:       Remove-Item -Force \"$env:LOCALAPPDATA\\Programs\\hyphae\\hyp.exe\", \"$env:USERPROFILE\\.local\\bin\\hyp.exe\" -ErrorAction SilentlyContinue"
    );
    if args.dry_run {
        ExitCode::from(EXIT_OK)
    } else {
        emit_error(
            "uninstall",
            false,
            EXIT_ERROR,
            "WINDOWS_MANUAL_UNINSTALL",
            "Automated bash uninstaller is Unix-only; follow the PowerShell steps printed above.",
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_args() -> UninstallArgs {
        UninstallArgs {
            latest: false,
            script_url: None,
            dry_run: false,
            yes: false,
            keep_binary: false,
            keep_state: false,
            keep_keychain: false,
            keep_harnesses: false,
            home: None,
        }
    }

    #[test]
    fn embedded_uninstall_script_is_valid_and_within_limit() {
        assert!(
            EMBEDDED_UNINSTALL_SH.len() <= MAX_SCRIPT_BYTES,
            "embedded uninstall.sh ({} bytes) exceeds MAX_SCRIPT_BYTES ({MAX_SCRIPT_BYTES})",
            EMBEDDED_UNINSTALL_SH.len()
        );
        let validated = validate_uninstall_script_body(EMBEDDED_UNINSTALL_SH.as_bytes())
            .expect("embedded script must pass header validation");
        assert_eq!(validated.lines().next(), Some("#!/usr/bin/env bash"));
        assert!(validated.contains("Proceed with uninstall? [y/N]:"));
        assert!(validated.contains("--keep-binary"));
        assert!(validated.contains("--keep-state"));
        assert!(validated.contains("--keep-keychain"));
        assert!(validated.contains("--keep-harnesses"));
    }

    #[test]
    fn url_validation_enforces_https_and_loopback_only() {
        assert!(validate_uninstall_script_url("https://hyphae.to/uninstall.sh").is_ok());
        assert!(validate_uninstall_script_url("https://example.com:8443/uninstall.sh").is_ok());
        assert!(validate_uninstall_script_url("http://127.0.0.1:8080/uninstall.sh").is_ok());
        assert!(validate_uninstall_script_url("http://[::1]:8080/uninstall.sh").is_ok());

        for bad in [
            "",
            "   ",
            "http://evil.com/uninstall.sh",
            "http://hyphae.to/uninstall.sh",
            "http://127.0.0.1.evil.com/uninstall.sh",
            "http://localhost:8080/uninstall.sh",
            "file:///etc/passwd",
            "ftp://hyphae.to/uninstall.sh",
            "https://user:pass@hyphae.to/uninstall.sh",
            "https://hyphae.to/uninstall.sh\n--evil",
        ] {
            assert!(
                validate_uninstall_script_url(bad).is_err(),
                "expected URL '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn script_body_validation_checks_shebang_utf8_and_size() {
        assert!(validate_uninstall_script_body(b"#!/usr/bin/env bash\necho ok\n").is_ok());
        assert!(validate_uninstall_script_body(b"#!/usr/bin/env sh\necho ok\n").is_ok());

        assert!(validate_uninstall_script_body(b"").is_err());
        assert!(validate_uninstall_script_body(b"<html>404 Not Found</html>").is_err());
        assert!(validate_uninstall_script_body(b"#!/bin/python3\nprint(1)\n").is_err());
        assert!(validate_uninstall_script_body(&[0xff, 0xfe, 0x00]).is_err());

        let mut oversized = b"#!/usr/bin/env bash\n".to_vec();
        oversized.resize(MAX_SCRIPT_BYTES + 1, b'#');
        assert!(validate_uninstall_script_body(&oversized).is_err());
    }

    #[test]
    fn sha256_helper_matches_known_vector() {
        // NIST FIPS 180-4 test vectors ("", "abc") + "hyphae"
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"hyphae"),
            "4282bdd47fad0d580cc7116bb01e51f3571ec9ebfc9f92037ba9c2a61267569e"
        );
    }

    #[test]
    fn flag_forwarding_preserves_exact_order_and_flags() {
        let empty = default_args();
        assert!(build_script_args(&empty).is_empty());

        let all = UninstallArgs {
            latest: true,
            script_url: Some("https://hyphae.to/uninstall.sh".to_string()),
            dry_run: true,
            yes: true,
            keep_binary: true,
            keep_state: true,
            keep_keychain: true,
            keep_harnesses: true,
            home: Some(PathBuf::from("/tmp/fake-home")),
        };
        assert_eq!(
            build_script_args(&all),
            vec![
                "--dry-run",
                "--yes",
                "--keep-binary",
                "--keep-state",
                "--keep-keychain",
                "--keep-harnesses",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn temp_script_guard_sets_0700_and_cleans_up_on_drop() {
        use std::os::unix::fs::PermissionsExt;

        let script_path: PathBuf;
        let dir_path: PathBuf;
        {
            let guard = TempScriptGuard::write_private("#!/usr/bin/env bash\necho hi\n")
                .expect("write private temp script");
            script_path = guard.script_path().to_path_buf();
            dir_path = guard.dir.clone();

            let script_mode = fs::metadata(&script_path).unwrap().permissions().mode() & 0o777;
            let dir_mode = fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(script_mode, 0o700);
            assert_eq!(dir_mode, 0o700);
        }
        assert!(!script_path.exists(), "temp script must be removed on Drop");
        assert!(!dir_path.exists(), "temp dir must be removed on Drop");
    }

    #[cfg(unix)]
    #[test]
    fn fetch_latest_downloads_validates_hashes_and_fails_closed_on_bad_responses() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");

            let valid_body = "#!/usr/bin/env bash\necho ok\n";
            let valid_sha = sha256_hex(valid_body.as_bytes());

            let server = tokio::spawn(async move {
                for _ in 0..3 {
                    let (mut sock, _) = listener.accept().await.expect("accept");
                    let mut buf = [0u8; 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let resp = if req.starts_with("GET /ok.sh ") {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            valid_body.len(),
                            valid_body
                        )
                    } else if req.starts_with("GET /bad.sh ") {
                        let bad = "<html>not a script</html>";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            bad.len(),
                            bad
                        )
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found".to_string()
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            });

            let ok_url = format!("http://{addr}/ok.sh");
            let (body, digest, final_url) = fetch_latest_uninstall_script(&ok_url)
                .await
                .expect("valid script fetch");
            assert_eq!(body, valid_body);
            assert_eq!(digest, valid_sha);
            assert_eq!(final_url, ok_url);

            let bad_url = format!("http://{addr}/bad.sh");
            let err_bad = fetch_latest_uninstall_script(&bad_url)
                .await
                .expect_err("HTML payload must be rejected");
            assert_eq!(err_bad.0, "INVALID_SCRIPT");

            let missing_url = format!("http://{addr}/missing.sh");
            let err_404 = fetch_latest_uninstall_script(&missing_url)
                .await
                .expect_err("404 must fail closed");
            assert_eq!(err_404.0, "HTTP_STATUS");

            server.await.expect("server task");
        });
    }
}
