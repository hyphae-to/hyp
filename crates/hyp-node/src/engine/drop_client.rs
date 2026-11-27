//! Shared Drop Relay client URL policy and caller-specific diagnostics.
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, Uri, request::Builder};
use http_body_util::BodyExt;
use hyper::body::Incoming;

use super::drop_relay::{CreateDropRequest, DROP_CAP_HEADER};
use super::http_util::{SseEvent, SseParser};

/// The two existing callers retain detailed and compact diagnostics for the same rejection.
#[derive(Debug)]
pub struct RelayUrlError {
    pub detailed: String,
    pub compact: String,
}

const SCHEME_MESSAGE: &str =
    "Drop Relay URL must use https:// (or loopback http://127.0.0.1 / http://localhost)";
const URI_MESSAGE: &str = "Drop Relay URL is not a valid URI";
const HOST_MESSAGE: &str = "Drop Relay URL is missing a valid host";
const USERINFO_MESSAGE: &str = "Drop Relay URL must not contain userinfo credentials";

/// Validates the strict intersection of the existing relay URL policies.
/// HTTP is limited to 127.0.0.1 or localhost; accepted spelling is otherwise retained.
pub fn validate_relay_url(raw: &str) -> Result<String, RelayUrlError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let has_query_or_fragment = trimmed.contains('#') || trimmed.contains('?');
    let has_control = trimmed.bytes().any(|byte| byte <= 0x20 || byte == 0x7f);
    let parsed = trimmed.parse::<Uri>();
    // Presentation preserves the compact caller's original rejection precedence without
    // duplicating its acceptance decision or parsing the URI twice.
    let compact = if trimmed.is_empty() || has_control || has_query_or_fragment {
        SCHEME_MESSAGE
    } else {
        match parsed.as_ref() {
            Err(_) => URI_MESSAGE,
            Ok(uri) => match uri.authority() {
                None => HOST_MESSAGE,
                Some(authority) if authority.as_str().contains('@') => USERINFO_MESSAGE,
                Some(authority) if authority.host().is_empty() => HOST_MESSAGE,
                _ => SCHEME_MESSAGE,
            },
        }
    };
    let error = |detailed: String| RelayUrlError {
        detailed,
        compact: compact.to_string(),
    };
    if trimmed.is_empty() {
        return Err(error("Drop Relay URL cannot be empty".to_string()));
    }
    if has_query_or_fragment {
        return Err(error(
            "Drop Relay URL must not contain query parameters or fragments".to_string(),
        ));
    }
    let uri =
        parsed.map_err(|cause| error(format!("invalid Drop Relay URL '{trimmed}': {cause}")))?;
    let scheme = uri.scheme_str().ok_or_else(|| {
        error(format!(
            "Drop Relay URL '{trimmed}' must include https:// scheme"
        ))
    })?;
    let authority = uri
        .authority()
        .ok_or_else(|| error(format!("Drop Relay URL '{trimmed}' is missing a host")))?;
    if authority.as_str().contains('@') {
        return Err(error(
            "Drop Relay URL must not include embedded credentials".to_string(),
        ));
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return Err(error("Drop Relay URL host cannot be empty".to_string()));
    }
    match scheme {
        "https" => {}
        "http" if matches!(host.as_str(), "127.0.0.1" | "localhost") => {}
        "http" => {
            return Err(error(format!(
                "refusing insecure http:// Drop Relay URL '{trimmed}'; use https:// (only loopback http://127.0.0.1 or http://localhost is permitted)"
            )));
        }
        other => {
            return Err(error(format!(
                "unsupported Drop Relay URL scheme '{other}' (expected https://)"
            )));
        }
    }
    if has_control {
        return Err(error(
            "Drop Relay URL must not contain whitespace or control characters".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

pub const CREATE_SLOT_PATH: &str = "/v1/drops";

type SignRelayRequest<'a> = dyn Fn(&str, &str, &[u8]) -> Result<String, String> + Sync + 'a;

pub enum RelayAuth<'a> {
    Capability(&'a str),
    Signed {
        public_key: &'a str,
        node_header: Option<&'a str>,
        sign: &'a SignRelayRequest<'a>,
    },
}

#[derive(Debug)]
pub enum RelayRequestError {
    Encode(serde_json::Error),
    Sign(String),
    Build(http::Error),
}

impl RelayAuth<'_> {
    fn apply(
        &self,
        builder: Builder,
        method: &str,
        path: &str,
        bytes: &[u8],
    ) -> Result<Builder, RelayRequestError> {
        match self {
            Self::Capability(cap) => Ok(builder.header(DROP_CAP_HEADER, *cap)),
            Self::Signed {
                public_key,
                node_header,
                sign,
            } => {
                let auth = sign(method, path, bytes).map_err(RelayRequestError::Sign)?;
                let mut builder = builder
                    .header(AUTHORIZATION, auth)
                    .header("X-Hyphae-Public-Key", *public_key);
                if let Some(node_id) = node_header {
                    builder = builder.header("x-hyphae-node", *node_id);
                }
                Ok(builder)
            }
        }
    }
}

fn json_post<B>(
    relay_base: &str,
    path: &str,
    bytes: Vec<u8>,
    auth: RelayAuth<'_>,
    body: impl FnOnce(Vec<u8>) -> B,
) -> Result<Request<B>, RelayRequestError> {
    let builder = Request::builder()
        .method(Method::POST)
        .uri(format!("{relay_base}{path}"))
        .header(CONTENT_TYPE, "application/json");
    auth.apply(builder, "POST", path, &bytes)?
        .body(body(bytes))
        .map_err(RelayRequestError::Build)
}

pub struct CreateSlotOptions<'a> {
    pub node_id: &'a str,
    pub ttl_seconds: u64,
    pub max_items: usize,
}

/// Builds a slot creation request. The caller owns transport and response handling.
pub fn create_slot<B>(
    relay_base: &str,
    slot: CreateSlotOptions<'_>,
    auth: RelayAuth<'_>,
    body: impl FnOnce(Vec<u8>) -> B,
) -> Result<Request<B>, RelayRequestError> {
    let bytes = serde_json::to_vec(&CreateDropRequest {
        ttl_seconds: Some(slot.ttl_seconds),
        max_items: Some(slot.max_items),
        target_node_id: Some(slot.node_id.to_owned()),
        burn_after_read: true,
    })
    .map_err(RelayRequestError::Encode)?;
    json_post(relay_base, CREATE_SLOT_PATH, bytes, auth, body)
}

pub fn stream_request<B>(
    relay_base: &str,
    path: &str,
    last_event_id: Option<&str>,
    auth: RelayAuth<'_>,
    body: B,
) -> Result<Request<B>, RelayRequestError> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(format!("{relay_base}{path}"))
        .header(ACCEPT, "text/event-stream");
    if let Some(event_id) = last_event_id {
        builder = builder.header("Last-Event-ID", event_id);
    }
    auth.apply(builder, "GET", path, b"")?
        .body(body)
        .map_err(RelayRequestError::Build)
}

/// Reads one frame so callers can preserve their deadline, cancellation, and cursor policies.
pub async fn stream_next(
    body: &mut Incoming,
    parser: &mut SseParser,
) -> Option<Result<Vec<SseEvent>, hyper::Error>> {
    body.frame().await.map(|result| {
        result.map(|frame| {
            frame
                .data_ref()
                .map_or_else(Vec::new, |data| parser.feed(data))
        })
    })
}

/// Builds a burn acknowledgement request. The caller decides whether to read the reply.
pub fn ack<B>(
    relay_base: &str,
    path: &str,
    seq: u64,
    auth: RelayAuth<'_>,
    body: impl FnOnce(Vec<u8>) -> B,
) -> Result<Request<B>, RelayRequestError> {
    let bytes = serde_json::to_vec(&serde_json::json!({ "seq": seq, "burn": true }))
        .map_err(RelayRequestError::Encode)?;
    json_post(relay_base, path, bytes, auth, body)
}
