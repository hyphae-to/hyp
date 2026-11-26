//! Resolve a Telegram bridge's default target via the Bot API.

use crate::engine::http_util::build_http_client;
use http::{Method, Request, Uri, header};
use http_body_util::{BodyExt, Empty};
use hyp_crypto::{CryptoError, SecretStore};
use hyp_proto::address::is_valid_handle;
use hyper::body::Bytes;
use serde_json::Value;
use std::time::Duration;

/// Default fallback target name for the Telegram bridge when `getMe` is unavailable or unconfigured.
pub const DEFAULT_TELEGRAM_TARGET: &str = "personal";
/// Default `SecretStore` key name holding the Telegram bot token.
pub const DEFAULT_TELEGRAM_SECRET_NAME: &str = "telegram-bot-token";
const TELEGRAM_API_DEFAULT_BASE: &str = "https://api.telegram.org";
const TELEGRAM_GETME_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_TELEGRAM_GETME_BYTES: usize = 64 * 1024;

/// Result of resolving the default target name for a Telegram bridge via `getMe` (with fail-safe
/// fallback to [`DEFAULT_TELEGRAM_TARGET`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramTargetResolution {
    pub target: String,
    pub source: &'static str,
    pub warning: Option<String>,
}

/// Normalizes and strictly validates a Telegram bot username into a safe Hyphae bridge target name.
///
/// Strips surrounding whitespace and any leading `@`, lowercases ASCII, and enforces Hyphae's safe
/// identifier grammar (`/^[a-z0-9][a-z0-9._-]{0,63}$/` — non-empty, `<= 64` chars, no control
/// chars, whitespace, or `:`).
pub fn normalize_telegram_target_name(raw: &str) -> Option<String> {
    let stripped = raw.trim().trim_start_matches('@');
    if stripped.is_empty() || stripped.len() > 64 {
        return None;
    }
    let lower = stripped.to_ascii_lowercase();
    if is_valid_handle(&lower) {
        Some(lower)
    } else {
        None
    }
}

/// Validates a Telegram Bot API base URL (`https://` or loopback `http://127.0.0.1` / `http://[::1]`).
/// Fails closed on insecure remote HTTP, embedded credentials, query/fragment, or control chars.
pub fn validate_telegram_api_base(raw: &str) -> Result<String, String> {
    if raw.chars().any(char::is_control) {
        return Err("TELEGRAM_API_BASE must not contain control characters".to_string());
    }
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("TELEGRAM_API_BASE must not be empty".to_string());
    }
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '?' | '#'))
    {
        return Err(
            "TELEGRAM_API_BASE must not contain whitespace, control characters, query, or fragment"
                .to_string(),
        );
    }

    let uri: Uri = trimmed
        .parse()
        .map_err(|_| "invalid TELEGRAM_API_BASE URL".to_string())?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "missing URL scheme in TELEGRAM_API_BASE (expected https://)".to_string())?;
    let authority = uri
        .authority()
        .ok_or_else(|| "missing host in TELEGRAM_API_BASE".to_string())?;
    if authority.as_str().contains('@') {
        return Err("refusing TELEGRAM_API_BASE with embedded credentials/userinfo".to_string());
    }
    let host = uri
        .host()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "missing host in TELEGRAM_API_BASE".to_string())?;

    match scheme {
        "https" => Ok(trimmed.to_string()),
        "http" => {
            if matches!(host, "127.0.0.1" | "[::1]" | "::1") {
                Ok(trimmed.to_string())
            } else {
                Err(
                    "refusing insecure http:// TELEGRAM_API_BASE: https:// is required (http:// is allowed only for 127.0.0.1 / [::1])"
                        .to_string(),
                )
            }
        }
        other => Err(format!(
            "unsupported URL scheme '{other}' in TELEGRAM_API_BASE: https:// is required"
        )),
    }
}

fn scrub_secret_from_msg(msg: String, secret: &str) -> String {
    if secret.is_empty() {
        msg
    } else {
        msg.replace(secret, "[REDACTED]")
    }
}

/// Calls `GET <api_base>/bot<token>/getMe` with a tight bounded timeout (4s), returning the
/// normalized, validated lowercase bot username (leading `@` stripped).
///
/// Security invariants:
/// - Respects `api_base` override or `TELEGRAM_API_BASE` env var (`https://` or loopback `http://` only).
/// - Never follows redirects (prevents leaking the path token across hosts).
/// - Never includes the bot token or full `/bot<token>/getMe` URI in any returned error message.
pub async fn fetch_telegram_bot_username(
    token: &str,
    api_base: Option<&str>,
) -> Result<String, String> {
    fetch_telegram_bot_username_with_timeout(token, api_base, TELEGRAM_GETME_TIMEOUT).await
}

async fn fetch_telegram_bot_username_with_timeout(
    token: &str,
    api_base: Option<&str>,
    timeout: Duration,
) -> Result<String, String> {
    let trimmed_token = token.trim();
    if trimmed_token.is_empty()
        || trimmed_token
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '?' | '#' | '@'))
    {
        return Err("Telegram bot token has invalid format".to_string());
    }

    let env_base = std::env::var("TELEGRAM_API_BASE").ok();
    let raw_base = api_base
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| env_base.as_deref().map(str::trim).filter(|s| !s.is_empty()))
        .unwrap_or(TELEGRAM_API_DEFAULT_BASE);
    let safe_base = validate_telegram_api_base(raw_base)
        .map_err(|e| scrub_secret_from_msg(e, trimmed_token))?;

    let req_uri: Uri = format!("{safe_base}/bot{trimmed_token}/getMe")
        .parse()
        .map_err(|_| format!("failed to build Telegram getMe URI for {safe_base}"))?;

    let client =
        build_http_client::<Empty<Bytes>>().map_err(|e| scrub_secret_from_msg(e, trimmed_token))?;
    let req = Request::builder()
        .method(Method::GET)
        .uri(req_uri)
        .header(
            header::USER_AGENT,
            format!("hyp/{}", env!("CARGO_PKG_VERSION")),
        )
        .body(Empty::new())
        .map_err(|_| format!("failed to construct Telegram getMe request for {safe_base}"))?;

    let body_bytes = tokio::time::timeout(timeout, async {
        let resp = client
            .request(req)
            .await
            .map_err(|_| format!("Telegram getMe request to {safe_base} failed"))?;
        let status = resp.status();
        if status.is_redirection() {
            return Err(format!(
                "Telegram getMe returned unexpected redirect HTTP {} from {safe_base}",
                status.as_u16()
            ));
        }
        if !status.is_success() {
            return Err(format!(
                "Telegram getMe returned HTTP {} from {safe_base}",
                status.as_u16()
            ));
        }
        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|_| {
                format!("failed reading Telegram getMe response body from {safe_base}")
            })?;
            if let Some(chunk) = frame.data_ref() {
                if out.len().saturating_add(chunk.len()) > MAX_TELEGRAM_GETME_BYTES {
                    return Err(format!(
                        "Telegram getMe response from {safe_base} exceeded {MAX_TELEGRAM_GETME_BYTES} byte limit"
                    ));
                }
                out.extend_from_slice(chunk);
            }
        }
        Ok::<Vec<u8>, String>(out)
    })
    .await
    .map_err(|_| {
        format!(
            "Telegram getMe request to {safe_base} timed out after {}s",
            timeout.as_secs()
        )
    })?
    .map_err(|e| scrub_secret_from_msg(e, trimmed_token))?;

    let parsed: Value = serde_json::from_slice(&body_bytes)
        .map_err(|_| format!("Telegram getMe from {safe_base} returned invalid JSON"))?;
    if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("Telegram getMe from {safe_base} returned ok=false"));
    }
    let raw_username = parsed
        .get("result")
        .and_then(|r| r.get("username"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!("Telegram getMe from {safe_base} did not include result.username")
        })?;
    normalize_telegram_target_name(raw_username).ok_or_else(|| {
        format!("Telegram getMe from {safe_base} returned an invalid target username")
    })
}

fn block_on_telegram_getme(
    token: &str,
    api_base: Option<&str>,
    timeout: Option<Duration>,
) -> Result<String, String> {
    let run_fresh = move |tok: &str, base: Option<&str>| -> Result<String, String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "Failed to initialize async runtime for Telegram getMe".to_string())?;
        match timeout {
            Some(t) => rt.block_on(fetch_telegram_bot_username_with_timeout(tok, base, t)),
            None => rt.block_on(fetch_telegram_bot_username(tok, base)),
        }
    };

    // Safely support invocation from both synchronous CLI handlers and async Tokio contexts
    // (such as `#[tokio::test]` or daemon startup).
    if tokio::runtime::Handle::try_current().is_ok() {
        let tok_owned = token.to_string();
        let base_owned = api_base.map(ToOwned::to_owned);
        std::thread::spawn(move || run_fresh(&tok_owned, base_owned.as_deref()))
            .join()
            .map_err(|_| "Telegram getMe worker thread panicked".to_string())?
    } else {
        run_fresh(token, api_base)
    }
}

/// Resolves the default Telegram bridge target from a bot token (never logging or echoing the
/// token). Always falls back cleanly to [`DEFAULT_TELEGRAM_TARGET`] (`"personal"`) on any error.
pub fn resolve_telegram_default_target_with_token(
    token: &str,
    api_base: Option<&str>,
) -> TelegramTargetResolution {
    match block_on_telegram_getme(token, api_base, None) {
        Ok(username) => TelegramTargetResolution {
            target: username,
            source: "getMe",
            warning: None,
        },
        Err(reason) => TelegramTargetResolution {
            target: DEFAULT_TELEGRAM_TARGET.to_string(),
            source: "fallback",
            warning: Some(format!(
                "Could not auto-detect Telegram bot username ({reason}); falling back to target '{DEFAULT_TELEGRAM_TARGET}'."
            )),
        },
    }
}

/// Resolves the default Telegram bridge target by reading `secret_name` from `SecretStore`
/// (zero network calls when the secret is not yet stored). Always falls back cleanly to
/// [`DEFAULT_TELEGRAM_TARGET`] (`"personal"`) on any error.
pub fn resolve_telegram_default_target_from_store(
    secrets: &SecretStore,
    secret_name: &str,
    api_base: Option<&str>,
) -> TelegramTargetResolution {
    match secrets.get(secret_name) {
        Ok(secret) => resolve_telegram_default_target_with_token(&secret, api_base),
        Err(CryptoError::SecretNotFound(_)) => TelegramTargetResolution {
            target: DEFAULT_TELEGRAM_TARGET.to_string(),
            source: "fallback",
            warning: None,
        },
        Err(_) => TelegramTargetResolution {
            target: DEFAULT_TELEGRAM_TARGET.to_string(),
            source: "fallback",
            warning: Some(format!(
                "Could not read SecretStore key '{secret_name}' to auto-detect Telegram bot username; falling back to target '{DEFAULT_TELEGRAM_TARGET}'."
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn normalize_telegram_target_name_validates_and_normalizes() {
        assert_eq!(
            normalize_telegram_target_name("Moneypenny0_Bot").as_deref(),
            Some("moneypenny0_bot")
        );
        assert_eq!(
            normalize_telegram_target_name("@Moneypenny0_Bot").as_deref(),
            Some("moneypenny0_bot")
        );
        assert_eq!(
            normalize_telegram_target_name("  @My.Bot-1_2  ").as_deref(),
            Some("my.bot-1_2")
        );
        let max_len_ok = "a".repeat(64);
        assert_eq!(
            normalize_telegram_target_name(&max_len_ok).as_deref(),
            Some(max_len_ok.as_str())
        );

        let too_long = "a".repeat(65);
        for bad in [
            "",
            "   ",
            "@",
            "@@@",
            &too_long,
            "bad:target",
            "bot name",
            "bot\ninject",
            "bot\r\nheader",
            "\x1b[31mbot",
            "../escape",
            ".hidden",
            "-flag",
            "_leading",
            "foo@bar",
            "bot/slash",
            "bot\0null",
        ] {
            assert_eq!(
                normalize_telegram_target_name(bad),
                None,
                "expected username {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn validate_telegram_api_base_enforces_https_and_loopback_only() {
        assert_eq!(
            validate_telegram_api_base("https://api.telegram.org/").unwrap(),
            "https://api.telegram.org"
        );
        assert_eq!(
            validate_telegram_api_base("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            validate_telegram_api_base("http://[::1]:8080").unwrap(),
            "http://[::1]:8080"
        );

        for bad in [
            "",
            "   ",
            "http://api.telegram.org",
            "http://evil.com",
            "http://127.0.0.1.evil.com",
            "http://localhost:8080",
            "ftp://api.telegram.org",
            "https://user:pass@api.telegram.org",
            "https://api.telegram.org?foo=bar",
            "https://api.telegram.org#frag",
            "https://api.telegram.org\n",
        ] {
            assert!(
                validate_telegram_api_base(bad).is_err(),
                "expected TELEGRAM_API_BASE {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn telegram_getme_mock_http_resolution_fallbacks_and_zero_token_leak() {
        use hyp_crypto::keystore::SecretBackend;

        let secret_ok = "10001:SUPER_SECRET_OK_TOKEN_NEVER_LEAK";
        let secret_bad_user = "10002:SUPER_SECRET_BADUSER_NEVER_LEAK";
        let secret_no_user = "10003:SUPER_SECRET_NOUSER_NEVER_LEAK";
        let secret_500 = "10004:SUPER_SECRET_500_NEVER_LEAK";
        let secret_redirect = "10005:SUPER_SECRET_302_NEVER_LEAK";
        let secret_slow = "10006:SUPER_SECRET_SLOW_NEVER_LEAK";

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);
        let (addr, stop_tx, server_thread) = {
            let (addr_tx, addr_rx) = std::sync::mpsc::channel();
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("mock tg runtime");
                rt.block_on(async move {
                    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                    let addr = listener.local_addr().expect("local addr");
                    addr_tx.send(addr).expect("send addr");
                    let mut stop_rx = stop_rx;
                    loop {
                        let accept_res = tokio::select! {
                            _ = &mut stop_rx => break,
                            res = listener.accept() => res,
                        };
                        let Ok((mut sock, _)) = accept_res else {
                            break;
                        };
                        hits_srv.fetch_add(1, Ordering::SeqCst);
                        let mut buf = [0u8; 2048];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("");

                        if path == format!("/bot{secret_ok}/getMe") {
                            let body = r#"{"ok":true,"result":{"id":42,"is_bot":true,"username":"Moneypenny0_Bot"}}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        } else if path == format!("/bot{secret_bad_user}/getMe") {
                            let body = r#"{"ok":true,"result":{"username":"@evil:inject\nnewline"}}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        } else if path == format!("/bot{secret_no_user}/getMe") {
                            let body = r#"{"ok":true,"result":{"id":42,"is_bot":true}}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        } else if path == format!("/bot{secret_500}/getMe") {
                            let body = r#"{"ok":false,"description":"internal error"}"#;
                            let resp = format!(
                                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        } else if path == format!("/bot{secret_redirect}/getMe") {
                            let resp = format!(
                                "HTTP/1.1 302 Found\r\nLocation: http://{addr}/bot{secret_ok}/getMe\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        } else if path == format!("/bot{secret_slow}/getMe") {
                            tokio::time::sleep(Duration::from_millis(400)).await;
                        } else {
                            let _ = sock
                                .write_all(
                                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                )
                                .await;
                        }
                        let _ = sock.shutdown().await;
                    }
                });
            });
            let addr = addr_rx.recv().expect("recv addr");
            (addr, stop_tx, handle)
        };

        let base = format!("http://{addr}");
        let tmp = TempDir::new().expect("tempdir");
        let store = SecretStore::new(tmp.path(), SecretBackend::File);

        // 1. Missing secret -> instant fallback to "personal" with 0 HTTP hits and no warning.
        let missing = resolve_telegram_default_target_from_store(
            &store,
            DEFAULT_TELEGRAM_SECRET_NAME,
            Some(&base),
        );
        assert_eq!(missing.target, DEFAULT_TELEGRAM_TARGET);
        assert_eq!(missing.source, "fallback");
        assert!(missing.warning.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // 2. Valid getMe username "Moneypenny0_Bot" -> normalized "moneypenny0_bot"!
        store.set(DEFAULT_TELEGRAM_SECRET_NAME, secret_ok).unwrap();
        let ok = resolve_telegram_default_target_from_store(
            &store,
            DEFAULT_TELEGRAM_SECRET_NAME,
            Some(&base),
        );
        assert_eq!(ok.target, "moneypenny0_bot");
        assert_eq!(ok.source, "getMe");
        assert!(ok.warning.is_none());

        // 3. Invalid / injection username -> falls back to "personal" with zero token leak!
        let bad_user = resolve_telegram_default_target_with_token(secret_bad_user, Some(&base));
        assert_eq!(bad_user.target, DEFAULT_TELEGRAM_TARGET);
        assert_eq!(bad_user.source, "fallback");
        let w = bad_user.warning.expect("warning expected");
        assert!(!w.contains(secret_bad_user), "token leaked in warning: {w}");

        // 4. Missing username field -> falls back cleanly with zero token leak!
        let no_user = resolve_telegram_default_target_with_token(secret_no_user, Some(&base));
        assert_eq!(no_user.target, DEFAULT_TELEGRAM_TARGET);
        assert_eq!(no_user.source, "fallback");
        let w = no_user.warning.expect("warning expected");
        assert!(!w.contains(secret_no_user), "token leaked in warning: {w}");

        // 5. HTTP 500 -> falls back cleanly with zero token leak!
        let err_500 = resolve_telegram_default_target_with_token(secret_500, Some(&base));
        assert_eq!(err_500.target, DEFAULT_TELEGRAM_TARGET);
        assert_eq!(err_500.source, "fallback");
        let w = err_500.warning.expect("warning expected");
        assert!(w.contains("500"), "expected HTTP 500 in warning: {w}");
        assert!(!w.contains(secret_500), "token leaked in warning: {w}");

        // 6. HTTP 302 redirect -> fails closed (never follows redirects!), zero token leak!
        let err_302 = resolve_telegram_default_target_with_token(secret_redirect, Some(&base));
        assert_eq!(err_302.target, DEFAULT_TELEGRAM_TARGET);
        assert_eq!(err_302.source, "fallback");
        let w = err_302.warning.expect("warning expected");
        assert!(!w.contains(secret_redirect), "token leaked in warning: {w}");

        // 7. Bounded timeout triggers cleanly without leaking token!
        let err_timeout =
            block_on_telegram_getme(secret_slow, Some(&base), Some(Duration::from_millis(50)))
                .expect_err("slow server must time out");
        assert!(
            err_timeout.contains("timed out"),
            "expected timeout message, got: {err_timeout}"
        );
        assert!(
            !err_timeout.contains(secret_slow),
            "token leaked in timeout error: {err_timeout}"
        );

        // 8. Malformed token rejected before any network call and never echoed!
        let bad_tok = "12345:bad/path?secret=1";
        let hits_before = hits.load(Ordering::SeqCst);
        let bad_tok_res = resolve_telegram_default_target_with_token(bad_tok, Some(&base));
        assert_eq!(bad_tok_res.target, DEFAULT_TELEGRAM_TARGET);
        assert_eq!(hits.load(Ordering::SeqCst), hits_before);
        let w = bad_tok_res.warning.expect("warning expected");
        assert!(!w.contains(bad_tok), "malformed token leaked: {w}");

        let _ = stop_tx.send(());
        let _ = server_thread.join();

        // 9. Unreachable / closed loopback port -> falls back to "personal" with zero token leak!
        let offline = resolve_telegram_default_target_with_token(secret_ok, Some(&base));
        assert_eq!(offline.target, DEFAULT_TELEGRAM_TARGET);
        assert_eq!(offline.source, "fallback");
        let w = offline.warning.expect("warning expected");
        assert!(!w.contains(secret_ok), "token leaked on offline error: {w}");
    }
}
