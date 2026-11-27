//! Verified human drop links, relay subscriptions, and authenticated ingest.

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use super::{
    LocalDaemonInner, invalid_request, node_err_tuple, sanitize_notice_label, store_err_tuple,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyp_crypto::OkpJwk as CryptoOkpJwk;
use hyp_crypto::human::{
    EncryptedHumanDraftV1, HumanDraftPayloadV1, HumanDropEnvelopeV1, MAX_HUMAN_DRAFT_CONTEXT_CHARS,
    NodeCertPayloadV1, SignedNodeCertV1, decode_hdrop1, encode_hcert1,
    is_reserved_drop_secret_name, seal_human_draft, validate_draft_text,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keystore::validate_secret_name;
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_node::engine::drop_client::{self, CreateSlotOptions, RelayAuth, RelayRequestError};
use hyp_node::engine::http_util::{HttpClient, SseParser, empty_body, full_body};
use hyp_node::engine::{
    CreateDropRequest, CreateDropResponse, DropRelay, DropSubscriberAuth, DropSubscription,
    NodeError, UnifiedNode,
};
use hyp_store::{now_ms, sha256_hex, uuid_v4};
use serde_json::{Map, Value, json};
use tokio::sync::watch;

type DropResult<T> = Result<T, (String, String)>;

enum RelaySelection {
    Local(String),
    External(String),
    Offline,
}

/// The link renderer only needs the submitting side of a relay slot.
struct PostingSlot<'a> {
    relay_url: &'a str,
    drop_id: String,
    post_cap: String,
    expires_at_ms: i64,
}

impl<'a> PostingSlot<'a> {
    fn from_created(relay_url: &'a str, slot: CreateDropResponse) -> Self {
        Self {
            relay_url,
            drop_id: slot.drop_id,
            post_cap: slot.post_cap,
            expires_at_ms: slot.expires_at_ms,
        }
    }
}

/// Output of the synchronous identity, authority, prefill and relay checks.
/// Only the sealed draft survives into relay creation and fragment rendering.
struct DropLinkPlan<'a> {
    kind: &'static str,
    node_id: &'a str,
    enc_jwk: CryptoOkpJwk,
    enc_kid: String,
    handle: Option<String>,
    secret_name: Option<String>,
    secret_exists: bool,
    node_cert_hcert1: Option<String>,
    hint_human_id: Option<String>,
    hint_prf_salt: Option<String>,
    hint_auth_epoch: Option<u64>,
    encrypted_draft: Option<EncryptedHumanDraftV1>,
    relay: RelaySelection,
    ttl_seconds: u64,
    now: i64,
}

impl LocalDaemonInner {
    pub(super) async fn tool_drop_link(
        self: &Arc<Self>,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> DropResult<Value> {
        let plan = prepare_link(&self.node, session_id, args, || self.current_time_ms())?;
        let slot = self.open_drop_slot(session_id, &plan).await?;
        plan.render(slot, self.node.config().drop_portal_url.as_deref())
    }

    async fn open_drop_slot<'a>(
        self: &Arc<Self>,
        session_id: &str,
        plan: &'a DropLinkPlan<'_>,
    ) -> DropResult<Option<PostingSlot<'a>>> {
        let node_id = plan.node_id;
        let ttl_seconds = plan.ttl_seconds;
        let now = plan.now;
        match &plan.relay {
            RelaySelection::Offline => Ok(None),
            RelaySelection::Local(url) => {
                let local_relay = self.node.drop_relay();
                let created = local_relay
                    .create_drop(
                        node_id,
                        "127.0.0.1",
                        CreateDropRequest {
                            ttl_seconds: Some(ttl_seconds),
                            max_items: Some(4),
                            target_node_id: Some(node_id.to_string()),
                            burn_after_read: true,
                        },
                        now,
                    )
                    .map_err(|e| ("drop_relay_error".into(), e.to_string()))?;

                let sub = local_relay
                    .subscribe_drop(
                        &created.drop_id,
                        DropSubscriberAuth::SubCap(&created.sub_cap),
                        "127.0.0.1",
                        None,
                        now,
                    )
                    .map_err(|e| ("drop_relay_error".into(), e.to_string()))?;
                let watcher = DropWatcher::new(session_id, plan, &created);
                tokio::spawn(watch_local(
                    watcher,
                    Arc::clone(self),
                    local_relay,
                    sub,
                    self.shutdown_rx.clone(),
                ));
                Ok(Some(PostingSlot::from_created(url, created)))
            }
            RelaySelection::External(url) => {
                let created = create_external_drop(&self.node, url, ttl_seconds).await?;
                let watcher = DropWatcher::new(session_id, plan, &created);
                tokio::spawn(watch_external(
                    watcher,
                    Arc::clone(self),
                    url.clone(),
                    self.node.http_client().clone(),
                    self.shutdown_rx.clone(),
                    self.node.subscribe_wake_epoch(),
                    self.config.drop_watcher_backoff_ms.clone(),
                ));
                Ok(Some(PostingSlot::from_created(url, created)))
            }
        }
    }

    pub(super) async fn handle_drop_ingest_rpc(&self, packet: &Map<String, Value>) -> Value {
        let overwrite = packet
            .get("overwrite")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let current_gate = self.current_gate();

        let res = if let Some(token) = packet
            .get("token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            self.node
                .ingest_human_drop_token(token, current_gate.as_deref(), overwrite)
                .await
        } else if let Some(env_val) = packet.get("envelope") {
            let env = match serde_json::from_value::<HumanDropEnvelopeV1>(env_val.clone()) {
                Ok(env) => env,
                Err(e) => {
                    return json!({
                        "ok": false,
                        "error": format!("invalid HumanDropEnvelopeV1: {e}"),
                    });
                }
            };
            self.node
                .ingest_human_drop(&env, current_gate.as_deref(), overwrite)
                .await
        } else {
            return json!({
                "ok": false,
                "error": "Expected 'token' (hdrop1_...) or 'envelope'",
            });
        };

        match res {
            Ok(ingested) => {
                self.bump_ui_rev();
                json!({ "ok": true, "result": ingested })
            }
            Err(err) => {
                let (code, message) = node_err_tuple(err);
                json!({
                    "ok": false,
                    "code": code,
                    "error": message,
                })
            }
        }
    }
}

struct DropContent<'a> {
    kind: &'static str,
    draft: Option<&'a str>,
    context: Option<&'a str>,
    secret_name: Option<String>,
}

fn parse_content(args: &Map<String, Value>) -> DropResult<DropContent<'_>> {
    let kind = match args
        .get("kind")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None | Some("directive") => "directive",
        Some("secret") => "secret",
        Some(other) => {
            return Err(invalid_request(format!(
                "Unsupported drop kind '{other}'. Expected 'secret' or 'directive'"
            )));
        }
    };

    let draft: Option<&str> = match args.get("draft") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => {
            return Err(invalid_request("Expected string 'draft'"));
        }
    };
    let context: Option<&str> = match args.get("context") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => {
            return Err(invalid_request("Expected string 'context'"));
        }
    };

    // Fail-closed security invariant #1: secrets MUST NEVER carry draft/context prefill.
    if kind == "secret" && (draft.is_some() || context.is_some()) {
        return Err(invalid_request(
            "Draft prefill is forbidden for secret drops; secrets must be entered fresh by the human",
        ));
    }
    if draft.is_none() && context.is_some() {
        return Err(invalid_request(
            "Optional 'context' requires 'draft' for encrypted directive prefill",
        ));
    }
    if let Some(draft_text) = draft {
        validate_draft_text(draft_text).map_err(|e| invalid_request(e.to_string()))?;
        if let Some(ctx_text) = context {
            validate_draft_text(ctx_text).map_err(|e| invalid_request(e.to_string()))?;
            let ctx_chars = ctx_text.chars().count();
            if ctx_chars > MAX_HUMAN_DRAFT_CONTEXT_CHARS {
                return Err(invalid_request(format!(
                    "human draft context length {ctx_chars} exceeds maximum {MAX_HUMAN_DRAFT_CONTEXT_CHARS} chars"
                )));
            }
        }
    }

    let secret_name: Option<String> = if kind == "secret" {
        let raw_name = args
            .get("secretName")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                invalid_request("Expected non-empty 'secretName' when kind is 'secret'")
            })?;
        if is_reserved_drop_secret_name(raw_name) {
            return Err((
                "reserved_secret_name".into(),
                format!(
                    "Reserved system secret name '{raw_name}' cannot be targeted by human drops"
                ),
            ));
        }
        validate_secret_name(raw_name)
            .map_err(|e| ("invalid_secret_name".into(), e.to_string()))?;
        Some(raw_name.to_string())
    } else {
        None
    };
    Ok(DropContent {
        kind,
        draft,
        context,
        secret_name,
    })
}

fn prepare_link<'a>(
    node: &'a UnifiedNode,
    session_id: &str,
    args: &Map<String, Value>,
    clock: impl FnOnce() -> i64,
) -> DropResult<DropLinkPlan<'a>> {
    let DropContent {
        kind,
        draft,
        context,
        secret_name,
    } = parse_content(args)?;
    // Non-authoritative UI cue ONLY (H15): strictly boolean existence check; NEVER expose secret bytes.
    let secret_exists = secret_name
        .as_deref()
        .is_some_and(|sname| node.secret_store().get(sname).is_ok());

    let handle: Option<String> = match args
        .get("handle")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw_handle) => {
            let clean = raw_handle.strip_prefix('@').unwrap_or(raw_handle);
            if !hyp_store::is_handle(clean) {
                return Err(invalid_request(format!("Invalid handle '{raw_handle}'")));
            }
            Some(clean.to_string())
        }
        None => {
            let db = node.db();
            db.local()
                .get_session(session_id)
                .ok()
                .flatten()
                .and_then(|s| s.handle)
        }
    };

    let ttl_seconds: u64 = match args.get("ttlSeconds") {
        None | Some(Value::Null) => 600,
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| invalid_request("Expected positive integer 'ttlSeconds'"))?;
            n.clamp(60, 900)
        }
    };

    let now = clock();
    let node_id = node.node_id().as_str();
    let enc_jwk = node.identity().encryption_jwk();
    let enc_kid = node.identity().encryption.kid();

    let (node_cert_hcert1, mut hint_human_id, mut hint_prf_salt, mut hint_auth_epoch, min_epoch) = {
        let db = node.db();
        let min_epoch = db.human().min_auth_epoch().unwrap_or(1);
        let cert_rec = db
            .human()
            .get_latest_node_cert(node_id)
            .ok()
            .flatten()
            .filter(|c| c.expires_at > now && c.auth_epoch >= min_epoch);

        let mut encoded_cert: Option<String> = None;
        let mut matched_auth = None;
        if let Some(rec) = cert_rec {
            if let Ok(signed) = serde_json::from_str::<SignedNodeCertV1>(&rec.signed_json) {
                let cert_matches_key = serde_json::from_str::<NodeCertPayloadV1>(&signed.payload)
                    .ok()
                    .is_some_and(|p| p.node_id == node_id && p.encryption_jwk.x == enc_jwk.x);
                let auth_opt = db
                    .human()
                    .get_active_authority_by_kid(&rec.human_kid)
                    .ok()
                    .flatten();
                if cert_matches_key && auth_opt.is_some() {
                    if let Ok(armored) = encode_hcert1(&signed) {
                        encoded_cert = Some(armored);
                        matched_auth = auth_opt;
                    }
                }
            }
        }

        let hint = match matched_auth {
            Some(a) => Some(a),
            None => db
                .human()
                .list_authorities(false)
                .ok()
                .and_then(|list| list.into_iter().next()),
        };
        let human_id = hint.as_ref().map(|a| a.human_id.clone());
        let prf_salt = hint.as_ref().and_then(|a| a.prf_salt.clone());
        let auth_epoch = hint.as_ref().map(|a| a.auth_epoch.max(min_epoch));
        (encoded_cert, human_id, prf_salt, auth_epoch, min_epoch)
    };

    // Fail-closed security invariant #2: encrypt `draft` to the human's Passkey X25519 key
    // (`encDraft` ONLY — NEVER downgrade to plaintext `draft` or `proposedText`!).
    let encrypted_draft: Option<EncryptedHumanDraftV1> = if let Some(draft_text) = draft {
        let enc_authority = {
            let db = node.db();
            match hint_human_id.as_deref() {
                Some(hid) => match db
                    .human()
                    .get_preferred_human_enc_jwk(Some(hid))
                    .map_err(store_err_tuple)?
                {
                    Some(found) => Some(found),
                    None => db
                        .human()
                        .get_preferred_human_enc_jwk(None)
                        .map_err(store_err_tuple)?,
                },
                None => db
                    .human()
                    .get_preferred_human_enc_jwk(None)
                    .map_err(store_err_tuple)?,
            }
        };

        let Some(auth_rec) = enc_authority else {
            return Err((
                    "human_enc_key_missing".into(),
                    "No human X25519 encryption key enrolled for encrypted draft prefill; re-enroll via `hyp auth init --web` or omit `draft` for fresh input"
                        .into(),
                ));
        };
        let Some(ref raw_enc_jwk) = auth_rec.enc_jwk_json else {
            return Err((
                    "human_enc_key_missing".into(),
                    "No human X25519 encryption key enrolled for encrypted draft prefill; re-enroll via `hyp auth init --web` or omit `draft` for fresh input"
                        .into(),
                ));
        };

        let parsed_jwk: CryptoOkpJwk = serde_json::from_str(raw_enc_jwk).map_err(|e| {
            (
                "human_enc_key_invalid".into(),
                format!("Stored human encryption JWK is invalid: {e}"),
            )
        })?;
        let human_enc_pk = parsed_jwk.to_x25519().map_err(|e| {
            (
                "human_enc_key_invalid".into(),
                format!("Stored human encryption JWK is not a valid X25519 public key: {e}"),
            )
        })?;

        // Keep fragment Passkey PRF hints aligned with the authority whose X25519 key sealed `encDraft`.
        hint_human_id = Some(auth_rec.human_id.clone());
        if auth_rec.prf_salt.is_some() {
            hint_prf_salt = auth_rec.prf_salt.clone();
        }
        hint_auth_epoch = Some(auth_rec.auth_epoch.max(min_epoch));

        let payload = HumanDraftPayloadV1 {
            v: 1,
            node_id: node_id.to_string(),
            text: draft_text.to_string(),
            context: context.map(ToString::to_string),
            created_at: format_rfc3339_millis(now),
        };
        let sealed = seal_human_draft(&payload, &human_enc_pk)
            .map_err(|e| invalid_request(e.to_string()))?;
        Some(sealed)
    } else {
        None
    };

    let explicit_relay = args
        .get("relay")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let configured_relay = node
        .config()
        .drop_relay_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let local_enabled = node.drop_relay().is_enabled();
    let local_origin = node.endpoint_url().trim_end_matches('/').to_string();

    let selection = if let Some(raw_url) = explicit_relay.or(configured_relay) {
        let validated = validate_drop_relay_url(raw_url)?;
        if local_enabled && validated == local_origin {
            RelaySelection::Local(validated)
        } else {
            RelaySelection::External(validated)
        }
    } else if local_enabled {
        let validated = validate_drop_relay_url(&local_origin)?;
        RelaySelection::Local(validated)
    } else {
        RelaySelection::Offline
    };
    Ok(DropLinkPlan {
        kind,
        node_id,
        enc_jwk,
        enc_kid,
        handle,
        secret_name,
        secret_exists,
        node_cert_hcert1,
        hint_human_id,
        hint_prf_salt,
        hint_auth_epoch,
        encrypted_draft,
        relay: selection,
        ttl_seconds,
        now,
    })
}

impl DropLinkPlan<'_> {
    fn render(&self, slot: Option<PostingSlot<'_>>, portal: Option<&str>) -> DropResult<Value> {
        let expires_at_ms = slot.as_ref().map_or_else(
            || {
                self.now
                    .saturating_add((self.ttl_seconds as i64).saturating_mul(1_000))
            },
            |slot| slot.expires_at_ms,
        );
        let expires_at = format_rfc3339_millis(expires_at_ms);

        // Build URL fragment matching `site/drop/drop.js` `parseFragmentString` bit-for-bit!
        // Security invariant: NEVER include plaintext `draft`, `proposedText`, or `body` —
        // directive prefill uses HPKE-encrypted `encDraft` ONLY.
        let mut frag = Map::new();
        frag.insert("v".into(), json!(1));
        frag.insert("kind".into(), json!(self.kind));
        frag.insert("nodeId".into(), json!(self.node_id));
        frag.insert(
            "encJwk".into(),
            json!({
                "kty": "OKP",
                "crv": "X25519",
                "x": self.enc_jwk.x,
            }),
        );
        frag.insert("expiresAt".into(), json!(expires_at));
        if let Some(ref h) = self.handle {
            frag.insert("handle".into(), json!(h));
        }
        if let Some(ref sname) = self.secret_name {
            frag.insert("secretName".into(), json!(sname));
            if self.secret_exists {
                frag.insert("secretExists".into(), json!(true));
            }
        }
        if let Some(ref cert) = self.node_cert_hcert1 {
            frag.insert("nodeCert".into(), json!(cert));
        }
        if let Some(ref hid) = self.hint_human_id {
            frag.insert("humanId".into(), json!(hid));
        }
        if let Some(ref salt) = self.hint_prf_salt {
            frag.insert("prfSalt".into(), json!(salt));
        }
        if let Some(ep) = self.hint_auth_epoch {
            frag.insert("authEpoch".into(), json!(ep));
        }
        if let Some(ref enc_draft) = self.encrypted_draft {
            let draft_val = serde_json::to_value(enc_draft)
                .map_err(|e| ("internal_error".into(), format!("serialize encDraft: {e}")))?;
            frag.insert("encDraft".into(), draft_val);
        }
        if let Some(slot) = &slot {
            frag.insert("relay".into(), json!(slot.relay_url));
            frag.insert("dropId".into(), json!(slot.drop_id));
            frag.insert("postCap".into(), json!(slot.post_cap));
        }

        let frag_canon = to_canonical_json(&Value::Object(frag)).map_err(|e| {
            (
                "internal_error".into(),
                format!("canonicalize drop fragment: {e}"),
            )
        })?;
        let frag_encoded = URL_SAFE_NO_PAD.encode(frag_canon.as_bytes());
        let portal_base = hyp_node::engine::resolve_drop_portal_url(portal)
            .map_err(|e| ("invalid_config".into(), e))?;
        let url = format!("{portal_base}#drop={frag_encoded}");

        let mut out = Map::new();
        out.insert("ok".into(), json!(true));
        out.insert("offline".into(), json!(slot.is_none()));
        out.insert("url".into(), json!(url));
        out.insert("kind".into(), json!(self.kind));
        if let Some(ref sname) = self.secret_name {
            out.insert("secretName".into(), json!(sname));
            out.insert("secretExists".into(), json!(self.secret_exists));
        }
        if let Some(ref h) = self.handle {
            out.insert("handle".into(), json!(h));
        }
        out.insert("nodeId".into(), json!(self.node_id));
        out.insert("encKid".into(), json!(self.enc_kid));
        out.insert("hasNodeCert".into(), json!(self.node_cert_hcert1.is_some()));
        out.insert(
            "hasEncryptedDraft".into(),
            json!(self.encrypted_draft.is_some()),
        );
        out.insert("expiresAt".into(), json!(expires_at));
        out.insert("expiresAtMs".into(), json!(expires_at_ms));
        if let Some(slot) = slot {
            out.insert("relay".into(), json!(slot.relay_url));
            out.insert("dropId".into(), json!(slot.drop_id));
        }
        Ok(Value::Object(out))
    }
}

/// Validates a Drop Relay base URL matching `site/drop/drop.js` `isAllowedRelayUrl`:
/// permits `https://...` or loopback `http://127.0.0.1[:port]` / `http://localhost[:port]` only.
fn validate_drop_relay_url(raw: &str) -> Result<String, (String, String)> {
    hyp_node::engine::drop_client::validate_relay_url(raw)
        .map_err(|error| ("invalid_relay_url".to_string(), error.compact))
}

fn parse_drop_payload_bytes(bytes: &[u8]) -> Result<HumanDropEnvelopeV1, String> {
    if let Ok(env) = serde_json::from_slice::<HumanDropEnvelopeV1>(bytes) {
        return Ok(env);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let trimmed = text.trim();
        if trimmed.starts_with("hdrop1_") {
            return decode_hdrop1(trimmed).map_err(|e| e.to_string());
        }
    }
    if let Ok(val) = serde_json::from_slice::<Value>(bytes) {
        if let Some(tok) = val.as_str() {
            return decode_hdrop1(tok).map_err(|e| e.to_string());
        }
        if let Some(tok) = val.get("token").and_then(Value::as_str) {
            return decode_hdrop1(tok).map_err(|e| e.to_string());
        }
        if let Some(env_val) = val.get("envelope") {
            return serde_json::from_value::<HumanDropEnvelopeV1>(env_val.clone())
                .map_err(|e| e.to_string());
        }
    }
    Err("unrecognized human drop payload".to_string())
}

async fn create_external_drop(
    node: &UnifiedNode,
    relay_url: &str,
    ttl_seconds: u64,
) -> Result<CreateDropResponse, (String, String)> {
    let node_id = node.node_id().as_str();
    let sign = |method: &str, path: &str, bytes: &[u8]| {
        let body_sha = sha256_hex(bytes);
        let ts = now_ms();
        let nonce = uuid_v4();
        Ok(hyp_crypto::http_auth::sign_http_auth(
            node_id,
            &node.identity().signing,
            method,
            path,
            ts,
            &nonce,
            &body_sha,
        ))
    };
    let http_req = drop_client::create_slot(
        relay_url,
        CreateSlotOptions {
            node_id,
            ttl_seconds,
            max_items: 4,
        },
        RelayAuth::Signed {
            public_key: &node.identity().signing_jwk().x,
            node_header: None,
            sign: &sign,
        },
        full_body,
    )
    .map_err(|error| match error {
        RelayRequestError::Encode(error) => (
            "internal_error".into(),
            format!("serialize drop request: {error}"),
        ),
        RelayRequestError::Build(error) => (
            "drop_relay_error".into(),
            format!("build drop request: {error}"),
        ),
        RelayRequestError::Sign(error) => ("drop_relay_error".into(), error),
    })?;

    let resp = node.http_client().request(http_req).await.map_err(|e| {
        (
            "drop_relay_error".into(),
            format!("drop relay POST failed: {e}"),
        )
    })?;
    let (status, _, resp_bytes) = HttpClient::collect(resp, 64 * 1024).await.map_err(|e| {
        (
            "drop_relay_error".into(),
            format!("drop relay read failed: {e}"),
        )
    })?;
    if !status.is_success() {
        let msg = String::from_utf8_lossy(&resp_bytes);
        return Err((
            "drop_relay_error".into(),
            format!(
                "drop relay returned HTTP {}: {}",
                status.as_u16(),
                msg.trim()
            ),
        ));
    }
    serde_json::from_slice::<CreateDropResponse>(&resp_bytes).map_err(|e| {
        (
            "drop_relay_error".into(),
            format!("invalid drop relay response: {e}"),
        )
    })
}

/// Daemon effects a relay subscription can perform. Gate selection happens for each submission.
trait DropDelivery: Send + Sync + 'static {
    fn ingest(
        &self,
        envelope: &HumanDropEnvelopeV1,
    ) -> impl Future<Output = Result<(), NodeError>> + Send;
    fn ack_time_ms(&self) -> i64;
    fn received(&self);
    fn notice(
        &self,
        session_id: &str,
        item_id: String,
        text: String,
    ) -> impl Future<Output = ()> + Send;
}

impl DropDelivery for Arc<LocalDaemonInner> {
    async fn ingest(&self, envelope: &HumanDropEnvelopeV1) -> Result<(), NodeError> {
        let gate = self.current_gate();
        self.node
            .ingest_human_drop(envelope, gate.as_deref(), false)
            .await
            .map(|_| ())
    }
    fn ack_time_ms(&self) -> i64 {
        self.current_time_ms()
    }
    fn received(&self) {
        self.bump_ui_rev();
    }
    async fn notice(&self, session_id: &str, item_id: String, text: String) {
        self.enqueue_system_notice(session_id, item_id, text).await;
    }
}

struct DropWatcher {
    session_id: String,
    drop_id: String,
    sub_cap: String,
    secret_name: Option<String>,
    lifetime: Duration,
    notified_conflicts: HashSet<String>,
    unsequenced_conflicts: u64,
}

impl DropWatcher {
    fn new(session_id: &str, plan: &DropLinkPlan<'_>, slot: &CreateDropResponse) -> Self {
        Self {
            session_id: session_id.to_owned(),
            drop_id: slot.drop_id.clone(),
            sub_cap: slot.sub_cap.clone(),
            secret_name: plan.secret_name.clone(),
            lifetime: Duration::from_secs(plan.ttl_seconds.saturating_add(5)),
            notified_conflicts: HashSet::new(),
            unsequenced_conflicts: 0,
        }
    }

    async fn accept(
        &mut self,
        delivery: &impl DropDelivery,
        payload: &[u8],
        event_id: Option<&str>,
    ) -> bool {
        let Ok(env) = parse_drop_payload_bytes(payload) else {
            return false;
        };
        match delivery.ingest(&env).await {
            Ok(()) => true,
            Err(NodeError::Conflict(_)) => {
                let key = match event_id.map(str::trim).filter(|s| !s.is_empty()) {
                    Some(seq) => format!("seq:{seq}"),
                    None => {
                        self.unsequenced_conflicts = self.unsequenced_conflicts.saturating_add(1);
                        format!("attempt:{}", self.unsequenced_conflicts)
                    }
                };
                if self.notified_conflicts.insert(key.clone()) {
                    self.notify_conflict(delivery, &key).await;
                }
                false
            }
            Err(_) => false,
        }
    }

    async fn notify_conflict(&self, delivery: &impl DropDelivery, dedup_key: &str) {
        let safe_drop_id = sanitize_notice_label(&self.drop_id);
        let safe_dedup = sanitize_notice_label(dedup_key);
        let item_id = format!("drop-conflict:{safe_drop_id}:{safe_dedup}");
        let text = match self
            .secret_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(name) => {
                let safe_secret = sanitize_notice_label(name);
                format!(
                    "[hyphae notice] Verified human secret drop '{safe_drop_id}' for '{safe_secret}' was blocked because the secret already exists and 'Overwrite existing secret' was unchecked. Ask the human to resubmit with Overwrite checked."
                )
            }
            None => format!(
                "[hyphae notice] Verified human secret drop '{safe_drop_id}' was blocked because the secret already exists and 'Overwrite existing secret' was unchecked. Ask the human to resubmit with Overwrite checked."
            ),
        };
        delivery.notice(&self.session_id, item_id, text).await;
    }

    async fn expired(&self, delivery: &impl DropDelivery) {
        let drop_id = &self.drop_id;
        let text = format!(
            "[hyphae notice] Verified human drop '{drop_id}' expired before a submission was received."
        );
        delivery
            .notice(&self.session_id, format!("drop-expired:{drop_id}"), text)
            .await;
    }
}

async fn watch_local(
    mut watcher: DropWatcher,
    delivery: impl DropDelivery,
    relay: Arc<DropRelay>,
    mut sub: DropSubscription,
    mut shutdown: watch::Receiver<bool>,
) {
    let deadline = tokio::time::sleep(watcher.lifetime);
    tokio::pin!(deadline);
    loop {
        let item = tokio::select! {
            item = sub.recv() => item,
            _ = &mut deadline => break,
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
                continue;
            }
        };
        let Some(item) = item else {
            break;
        };
        if watcher
            .accept(&delivery, &item.payload, Some(&item.seq.to_string()))
            .await
        {
            let _ = relay.ack_drop(
                &watcher.drop_id,
                DropSubscriberAuth::SubCap(&watcher.sub_cap),
                item.seq,
                true,
                delivery.ack_time_ms(),
            );
            delivery.received();
            break;
        }
    }
}

async fn wait_for_wake_epoch(wake_rx: &mut watch::Receiver<u64>) {
    if wake_rx.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn watch_external(
    mut watcher: DropWatcher,
    delivery: impl DropDelivery,
    relay_url: String,
    http: HttpClient,
    mut shutdown_rx: watch::Receiver<bool>,
    mut wake_rx: watch::Receiver<u64>,
    backoff_ms: Vec<u64>,
) {
    // Start observing wakes when the subscription task starts.
    wake_rx.borrow_and_update();
    let deadline = tokio::time::Instant::now() + watcher.lifetime;
    let stream_path = format!("/v1/drops/{}/stream", watcher.drop_id);
    let backoff_schedule = if backoff_ms.is_empty() {
        vec![500, 1_000, 2_000, 5_000]
    } else {
        backoff_ms
    };
    let mut last_event_id: Option<String> = None;
    let mut reconnect_attempt: usize = 0;
    loop {
        if *shutdown_rx.borrow() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            watcher.expired(&delivery).await;
            return;
        }

        let Ok(req) = drop_client::stream_request(
            &relay_url,
            &stream_path,
            last_event_id.as_deref(),
            RelayAuth::Capability(&watcher.sub_cap),
            empty_body(),
        ) else {
            return;
        };

        let resp_res = tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return;
                }
                continue;
            }
            _ = wait_for_wake_epoch(&mut wake_rx) => {
                reconnect_attempt = 0;
                continue;
            }
            _ = tokio::time::sleep_until(deadline) => None,
            r = http.request(req) => Some(r),
        };

        let Some(resp_result) = resp_res else {
            watcher.expired(&delivery).await;
            return;
        };

        let mut wake_triggered = false;
        if let Ok(mut resp) = resp_result {
            let status = resp.status();
            if status.is_success() {
                reconnect_attempt = 0;
                let mut parser = SseParser::new();
                loop {
                    let batch = tokio::select! {
                        biased;
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                return;
                            }
                            continue;
                        }
                        _ = wait_for_wake_epoch(&mut wake_rx) => {
                            reconnect_attempt = 0;
                            wake_triggered = true;
                            break;
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            watcher.expired(&delivery).await;
                            return;
                        }
                        events = drop_client::stream_next(resp.body_mut(), &mut parser) => events,
                    };
                    let Some(Ok(events)) = batch else {
                        // Mid-stream disconnect: reconnect with bounded backoff + Last-Event-ID!
                        break;
                    };
                    for ev in events {
                        if let Some(ref eid) = ev.id {
                            let trimmed = eid.trim();
                            if !trimmed.is_empty() {
                                last_event_id = Some(trimmed.to_string());
                            }
                        }
                        if ev.data.trim().is_empty() {
                            continue;
                        }
                        if watcher
                            .accept(&delivery, ev.data.as_bytes(), ev.id.as_deref())
                            .await
                        {
                            if let Some(seq) =
                                ev.id.as_deref().and_then(|s| s.trim().parse::<u64>().ok())
                            {
                                let ack_path = format!("/v1/drops/{}/ack", watcher.drop_id);
                                if let Ok(request) = drop_client::ack(
                                    &relay_url,
                                    &ack_path,
                                    seq,
                                    RelayAuth::Capability(&watcher.sub_cap),
                                    full_body,
                                ) {
                                    let _ = http.request(request).await;
                                }
                            }
                            delivery.received();
                            return;
                        }
                    }
                }
            } else if matches!(status.as_u16(), 401 | 403 | 404 | 410) {
                let drop_id = &watcher.drop_id;
                let status = status.as_u16();
                let text = format!(
                    "[hyphae notice] Verified human drop '{drop_id}' closed on relay (HTTP {status})."
                );
                delivery
                    .notice(
                        &watcher.session_id,
                        format!("drop-closed:{drop_id}:{status}"),
                        text,
                    )
                    .await;
                return;
            }
        }

        if wake_triggered {
            continue;
        }

        let delay_ms = backoff_schedule[reconnect_attempt.min(backoff_schedule.len() - 1)];
        reconnect_attempt = reconnect_attempt.saturating_add(1);
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            continue;
        }
        let wait_for = Duration::from_millis(delay_ms).min(remaining);
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return;
                }
            }
            _ = wait_for_wake_epoch(&mut wake_rx) => {
                reconnect_attempt = 0;
            }
            _ = tokio::time::sleep(wait_for) => {}
        }
    }
}
