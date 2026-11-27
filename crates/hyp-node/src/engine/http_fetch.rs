//! Bounded HTTP downloads with caller-owned URL policy and diagnostics.
use super::http_util::{BoundedBodyError, build_http_client, consume_bounded_body};
use http::{Method, Request, Uri, header};
use http_body_util::Empty;
use hyper::body::Bytes;
use std::time::Duration;

#[derive(Debug)]
pub struct FetchError {
    pub code: &'static str,
    pub message: String,
}
impl FetchError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub struct FetchOptions {
    pub max_bytes: usize,
    pub max_redirects: usize,
    /// Existing callers bound the request/response-header phase separately from body consumption.
    pub request_timeout: Duration,
    pub user_agent: String,
    pub display_url: fn(&str) -> String,
}

/// Resolves only absolute HTTP(S) or root-relative locations, validates, then refuses downgrade.
pub fn resolve_redirect_url(
    current: &Uri,
    location: &str,
    trim_location: bool,
    validate: impl FnOnce(&str) -> Result<Uri, FetchError>,
) -> Result<(Uri, String), FetchError> {
    let location = if trim_location {
        location.trim()
    } else {
        location
    };
    let next_url = if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with('/') {
        let scheme = current.scheme_str().unwrap_or("https");
        let authority = current.authority().map(|a| a.as_str()).unwrap_or_default();
        format!("{scheme}://{authority}{location}")
    } else {
        return Err(FetchError::new(
            "UNSAFE_REDIRECT",
            format!("Refusing unsupported redirect Location '{location}'"),
        ));
    };
    let uri = validate(&next_url)?;
    refuse_downgrade(current, &uri, &next_url)?;
    Ok((uri, next_url))
}

fn refuse_downgrade(current: &Uri, next: &Uri, next_url: &str) -> Result<(), FetchError> {
    if current.scheme_str() == Some("https") && next.scheme_str() != Some("https") {
        return Err(FetchError::new(
            "UNSAFE_REDIRECT",
            format!("Refusing HTTPS-to-HTTP downgrade redirect to '{next_url}'"),
        ));
    }
    Ok(())
}

/// Fetches data with a byte cap, validating the initial URL and every redirect before use.
/// Redirect resolution returns both the parsed URI and the caller's diagnostic/source spelling.
pub async fn fetch_bounded_https(
    initial_url: &str,
    options: FetchOptions,
    validate_initial: impl FnOnce(&str) -> Result<Uri, FetchError>,
    resolve_redirect: impl Fn(&Uri, &str) -> Result<(Uri, String), FetchError>,
) -> Result<(Vec<u8>, String), FetchError> {
    let mut current_url = initial_url.trim().to_string();
    let mut current_uri = validate_initial(&current_url)?;
    let client =
        build_http_client::<Empty<Bytes>>().map_err(|e| FetchError::new("HTTP_INIT_ERROR", e))?;
    for redirects in 0..=options.max_redirects {
        let request = Request::builder()
            .method(Method::GET)
            .uri(&current_uri)
            .header(header::USER_AGENT, options.user_agent.as_str())
            .body(Empty::new())
            .map_err(|e| FetchError::new("HTTP_ERROR", format!("Failed to build request: {e}")))?;
        let response = tokio::time::timeout(options.request_timeout, client.request(request))
            .await
            .map_err(|_| {
                FetchError::new(
                    "HTTP_TIMEOUT",
                    format!(
                        "GET {} timed out after {}s",
                        (options.display_url)(&current_url),
                        options.request_timeout.as_secs()
                    ),
                )
            })?
            .map_err(|e| {
                FetchError::new(
                    "HTTP_ERROR",
                    format!("GET {} failed: {e}", (options.display_url)(&current_url)),
                )
            })?;
        let status = response.status();
        if status.is_redirection() {
            if redirects >= options.max_redirects {
                return Err(FetchError::new(
                    "TOO_MANY_REDIRECTS",
                    format!(
                        "GET {} exceeded {} redirects",
                        (options.display_url)(&current_url),
                        options.max_redirects
                    ),
                ));
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    FetchError::new(
                        "HTTP_ERROR",
                        format!(
                            "GET {} returned redirect HTTP {} without Location header",
                            (options.display_url)(&current_url),
                            status.as_u16()
                        ),
                    )
                })?;
            let (uri, source) = resolve_redirect(&current_uri, location)?;
            refuse_downgrade(&current_uri, &uri, &source)?;
            current_uri = uri;
            current_url = source;
            continue;
        }
        if !status.is_success() {
            return Err(FetchError::new(
                "HTTP_STATUS",
                format!(
                    "GET {} returned HTTP {}",
                    (options.display_url)(&current_url),
                    status.as_u16()
                ),
            ));
        }
        let mut out = Vec::new();
        consume_bounded_body(response.into_body(), options.max_bytes, |chunk| {
            out.extend_from_slice(chunk)
        })
        .await
        .map_err(|error| match error {
            BoundedBodyError::Read(error) => {
                FetchError::new("HTTP_ERROR", format!("body read error: {error}"))
            }
            BoundedBodyError::TooLarge => FetchError::new(
                "RESPONSE_TOO_LARGE",
                format!(
                    "Download from {} exceeds {} byte limit",
                    (options.display_url)(&current_url),
                    options.max_bytes
                ),
            ),
        })?;
        return Ok((out, (options.display_url)(&current_url)));
    }
    Err(FetchError::new(
        "TOO_MANY_REDIRECTS",
        format!(
            "GET {} exceeded {} redirects",
            (options.display_url)(&current_url),
            options.max_redirects
        ),
    ))
}
