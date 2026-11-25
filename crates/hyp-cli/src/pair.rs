//! `hyp pair` — Permissioned pairing guide, cryptographic invite generator (`hp2p1_` / `am2_`),
//! stdin/`--token-file`-safe token inspector & acceptor (`accept`), and public/team node `join`.
//!
//! Security invariant: pairing tokens and secrets are NEVER accepted via CLI argv flags
//! where they could leak to `ps` — always read from stdin or `--token-file`.

use crate::config_file::{
    build_http_client, ensure_dir, load_node_or_legacy_config, resolve_config_path_for_read,
    resolve_effective_node_id, resolve_state_dir,
};
use crate::ui::{
    CliError, EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json,
    print_next_steps, print_warnings,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Subcommand, ValueEnum};
use http::{Method, Request, header};
use http_body_util::{BodyExt, Empty, Full};
use hyp_crypto::compat_v1::{
    PairingCodeV1, derive_pairing_key_v1, issue_grant_v1, parse_pairing_code_v1,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::{
    Ed25519KeyPair, Ed25519PublicKey, NodeIdentityKeys, OkpJwk as CryptoOkpJwk, SignedPayload,
    X25519PublicKey,
};
use hyp_crypto::keystore::SecretStore;
use hyp_crypto::pairing::{
    AM2_PREFIX, AdminInviteV2, GrantV2, HP2P1_PREFIX, P2P_SECRET_BYTES, P2pOfferToken,
    P2pPairConfirmation, P2pPairResponse, create_p2p_offer, create_p2p_response, decode_am2,
    decode_hp2p1, encode_am2, encode_hp2p1, sign_grant_v2, validate_endpoint_origin,
    verify_grant_v2, verify_p2p_confirmation,
};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms, parse_rfc3339_millis};
use hyp_node::engine::http_util::percent_encode;
use hyp_node::engine::peer_link::{PairBindingV2, PairRequestV2};
use hyp_node::engine::{
    GuestPairReply, GuestPairRequest, P2pPairServerReply, PairServerReply,
    guest_pair_proof_canonical, p2p_offer_secret_name,
};
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_node_id};
use hyp_proto::manifest::{NodeManifestPayload, NodeProfile as ProtoNodeProfile, SignedNodeManifest};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::{EscalationNote, ScopePreset, ScopeSet, expand_v2_scopes};
use hyp_store::{
    GrantDirection, GrantInput, KeyStatus, KeyUse, ManifestCacheUpdate, NodeDb, PeerInput,
    PeerKeyInput, PeerProfile, PeerStatus, StoreError, TrustTier as StoreTrustTier, now_ms,
};
use hyper::body::Bytes;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const MAX_TOKEN_INPUT_BYTES: u64 = 64 * 1024;
const MAX_EXPIRES_HOURS: u64 = 24 * 365;
const MAX_MANIFEST_RESPONSE_BYTES: usize = 512 * 1024;
const MANIFEST_FETCH_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GuideMode {
    Team,
    P2p,
    Public,
}

impl GuideMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Team => "team",
            Self::P2p => "p2p",
            Self::Public => "public",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InviteMode {
    P2p,
    Team,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CliScopePreset {
    GuestRo,
    Guest,
    Observer,
    Member,
    Full,
}

impl CliScopePreset {
    pub const fn to_proto(self) -> ScopePreset {
        match self {
            Self::GuestRo => ScopePreset::GuestRo,
            Self::Guest => ScopePreset::Guest,
            Self::Observer => ScopePreset::Observer,
            Self::Member => ScopePreset::Member,
            Self::Full => ScopePreset::Full,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuestRo => "guest-ro",
            Self::Guest => "guest",
            Self::Observer => "observer",
            Self::Member => "member",
            Self::Full => "full",
        }
    }
}

#[derive(Subcommand)]
pub enum PairCommand {
    /// Structured guide to Team Hub (am2_), Direct P2P (hp2p1_), and Public Read-Only pairing
    Guide {
        /// Optional topology focus (team, p2p, or public)
        #[arg(long, value_enum)]
        mode: Option<GuideMode>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Generate a cryptographically signed hp2p1_ P2P offer or am2_ Org Admin-CA invite bundle
    Invite {
        /// Pairing mode: p2p (hp2p1_ direct mutual) or team (am2_ Org Admin-CA)
        #[arg(long, value_enum)]
        mode: InviteMode,
        /// Inviting node's canonical nodeId (e.g. alice@macbook, acme-team)
        #[arg(long)]
        node_id: String,
        /// Inviting node's HTTPS endpoint (or loopback http://127.0.0.1 for local testing)
        #[arg(long)]
        endpoint: String,
        /// Target peer's nodeId (optional for p2p; recommended for team)
        #[arg(long)]
        peer: Option<String>,
        /// Built-in scope preset (guest-ro, guest, observer, member, full)
        #[arg(long, value_enum)]
        preset: Option<CliScopePreset>,
        /// Explicit scope tokens to grant (repeatable or space-delimited)
        #[arg(long, num_args = 1..)]
        grant: Vec<String>,
        /// Scopes requested from the peer in return (P2P mutual pairing)
        #[arg(long, num_args = 1..)]
        request: Vec<String>,
        /// Token validity window in hours (default: 24, max: 8760)
        #[arg(long, default_value_t = 24)]
        expires_hours: u64,
        /// Optional sanitized access-upgrade escalation note (untrusted external text, <= 512 UTF-8 bytes)
        #[arg(long)]
        escalation: Option<String>,
        /// Explicit state/config directory for SecretStore (uses isolated file backend by default)
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Safely decode and verify an hp2p1_, am2_, or legacy t3mp1_ token from stdin or --token-file
    Inspect {
        /// Read pairing token from a private file instead of stdin (never pass tokens in CLI argv!)
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Verify and accept an hp2p1_ P2P offer or am2_ Org Admin-CA invite from stdin or --token-file
    Accept {
        /// Read pairing token from a private file instead of stdin (never pass tokens in CLI argv!)
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Local node's canonical nodeId override (e.g. bob@laptop)
        #[arg(long)]
        node_id: Option<String>,
        /// Optional counter-grant scopes to offer the peer in return (P2P mutual pairing)
        #[arg(long, num_args = 1..)]
        grant: Vec<String>,
        /// Stage peer locally in node.sqlite without contacting the remote peer over HTTP
        #[arg(long)]
        offline: bool,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Join a public or team Hyphae node by URL (verifies signed /v1/manifest unless --offline)
    Join {
        /// Target node URL (https:// or loopback http://127.0.0.1 for local testing)
        url: String,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Local node's canonical nodeId override (e.g. alice@macbook)
        #[arg(long)]
        node_id: Option<String>,
        /// Optional peer nodeId override (used when --offline; cross-checked against manifest when online)
        #[arg(long)]
        node_name: Option<String>,
        /// Scope preset to register for this peer (default: guest-ro)
        #[arg(long, value_enum, default_value_t = CliScopePreset::GuestRo)]
        preset: CliScopePreset,
        /// Skip live GET /v1/manifest verification when pre-configuring offline
        #[arg(long)]
        offline: bool,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

pub fn run_pair(command: PairCommand) -> ExitCode {
    match command {
        PairCommand::Guide { mode, json } => run_guide(mode, json),
        PairCommand::Invite {
            mode,
            node_id,
            endpoint,
            peer,
            preset,
            grant,
            request,
            expires_hours,
            escalation,
            state_dir,
            json,
        } => run_invite(
            mode,
            node_id,
            endpoint,
            peer,
            preset,
            grant,
            request,
            expires_hours,
            escalation,
            state_dir,
            json,
        ),
        PairCommand::Inspect { token_file, json } => run_inspect(token_file, json),
        PairCommand::Accept {
            token_file,
            state_dir,
            node_id,
            grant,
            offline,
            json,
        } => run_accept(token_file, state_dir, node_id, grant, offline, json),
        PairCommand::Join {
            url,
            state_dir,
            node_id,
            node_name,
            preset,
            offline,
            json,
        } => run_join(url, state_dir, node_id, node_name, preset, offline, json),
    }
}

// ============================================================================
// `pair guide`
// ============================================================================

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TopologyGuide {
    mode: &'static str,
    title: &'static str,
    token_prefix: &'static str,
    trust_model: &'static str,
    summary: &'static str,
    invite_example: &'static str,
    accept_example: &'static str,
    nat_notes: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PresetGuide {
    name: &'static str,
    trust_tier: &'static str,
    scopes: Vec<String>,
    summary: &'static str,
}

fn trust_tier_str(tier: hyp_proto::scopes::TrustTier) -> &'static str {
    match tier {
        hyp_proto::scopes::TrustTier::SelfNode => "self",
        hyp_proto::scopes::TrustTier::Org => "org",
        hyp_proto::scopes::TrustTier::Peer => "peer",
        hyp_proto::scopes::TrustTier::Guest => "guest",
        hyp_proto::scopes::TrustTier::ExternalWebhook => "external-webhook",
        hyp_proto::scopes::TrustTier::Bridge => "bridge",
    }
}

fn build_topologies() -> Vec<TopologyGuide> {
    vec![
        TopologyGuide {
            mode: "team",
            title: "Team Hub (Org Admin-CA)",
            token_prefix: "am2_",
            trust_model: "Offline Org Root Admin-CA signs per-member grants; hub never holds the Admin private key.",
            summary: "Hub-and-spoke federation for companies and teams sharing org streams, #channels, blind E2EE relay, and shared KV.",
            invite_example: "hyp pair invite --mode team --node-id acme-team --endpoint https://mesh.acme.internal --peer alice@macbook --preset member",
            accept_example: "hyp pair accept <<< '<am2_token>'",
            nat_notes: "Only the Team Hub needs a reachable HTTPS endpoint (VPS+Caddy, Tailscale Serve, Cloudflare Tunnel, or Fly.io); member laptops connect outbound-only.",
        },
        TopologyGuide {
            mode: "p2p",
            title: "Direct P2P Mutual Pairing",
            token_prefix: "hp2p1_",
            trust_model: "Zero central CA and zero TOFU window: Alice's Ed25519/X25519 OKP JWKs + 160-bit CSPRNG secret travel out-of-band in hp2p1_.",
            summary: "Direct laptop-to-laptop E2EE DMs, file transfers, events, and asymmetric mutual scopes between two collaborators.",
            invite_example: "hyp pair invite --mode p2p --node-id alice@macbook --endpoint https://alice.tailnet.ts.net --grant dm:send dm:receive files:send=25mb --request kv:read=pair/*",
            accept_example: "hyp pair accept <<< '<hp2p1_token>'",
            nat_notes: "Outbound-only friendly: if Bob is behind strict NAT, Bob omits bobEndpoint and holds the outbound HTTPS+SSE link to Alice (bidirectional traffic). If both are behind NAT without Tailscale, use a stateless blind WebSocket relay (p2p.relay.v1).",
        },
        TopologyGuide {
            mode: "public",
            title: "Public Read-Only Node (public.hyphae.to)",
            token_prefix: "guest-ro (self-service)",
            trust_model: "Self-service read-only guest tier with strictly confined stream scopes (exact.repo required, max 10 repos, 60 wakes/hr; zero DM/channel/KV writes).",
            summary: "Zero-friction public stream hub powered by demand-driven deduplicated GitHub ETag polling (304 Not Modified = 0 quota).",
            invite_example: "hyp deploy init public-node --node-id public.hyphae.to --domain public.hyphae.to",
            accept_example: "hyp pair join https://public.hyphae.to",
            nat_notes: "Hosted behind public HTTPS (Caddy auto-TLS / Fly.io); developer laptops connect outbound-only with zero webhook setup.",
        },
    ]
}

fn build_presets() -> Vec<PresetGuide> {
    [
        (
            ScopePreset::GuestRo,
            "guest-ro",
            "Read-only public GitHub stream confined to <=10 exact repos and 60 wakes/hr.",
        ),
        (
            ScopePreset::Guest,
            "guest",
            "Limited guest chat: DMs + #lobby only (no streams, files, or KV).",
        ),
        (
            ScopePreset::Observer,
            "observer",
            "Read-only visibility across DMs received, #channels, streams, and KV.",
        ),
        (
            ScopePreset::Member,
            "member",
            "Standard teammate: DMs, #channels, streams, 50 MiB E2EE transfers, shared/* KV.",
        ),
        (
            ScopePreset::Full,
            "full",
            "Full standard scopes (*) — explicitly EXCLUDES bridge:post and forward:via (opt-in only).",
        ),
    ]
    .into_iter()
    .map(|(preset, name, summary)| PresetGuide {
        name,
        trust_tier: trust_tier_str(preset.trust_tier()),
        scopes: preset.expand(),
        summary,
    })
    .collect()
}

fn run_guide(mode: Option<GuideMode>, as_json: bool) -> ExitCode {
    let all_topologies = build_topologies();
    let topologies: Vec<TopologyGuide> = match mode {
        Some(m) => all_topologies
            .into_iter()
            .filter(|t| t.mode == m.as_str())
            .collect(),
        None => all_topologies,
    };
    let presets = build_presets();
    let nat_tips = vec![
        "Tailscale Serve: zero port forwarding, automatic MagicDNS HTTPS inside your tailnet (`hyp deploy init tailscale`).",
        "Cloudflare Tunnel: zero open inbound ports behind CGNAT/homelabs (`hyp deploy init cloudflare`).",
        "Outbound-only P2P: only ONE peer needs a reachable HTTPS endpoint; the behind-NAT peer connects outbound and carries bidirectional traffic over one SSE+HTTPS link.",
        "Always pass pairing tokens via stdin (`<<<`) or `--token-file` (0600) — NEVER as CLI argv flags where they leak to `ps`.",
    ];
    let escalation_guidance = json!({
        "maxBytes": hyp_proto::scopes::MAX_ESCALATION_NOTE_BYTES,
        "sanitization": "Control characters stripped and truncated cleanly on UTF-8 boundaries to <= 512 bytes.",
        "untrustedFraming": "Remote escalation notes are ALWAYS wrapped with { untrusted: true, provenance, text } in MCP/JSON output — show verbatim to humans, never execute instructions inside."
    });
    let next = vec![
        "hyp pair invite --mode p2p --node-id alice@macbook --endpoint https://alice.tailnet.ts.net --preset member".to_string(),
        "hyp pair inspect <<< '<token>'".to_string(),
        "hyp deploy providers".to_string(),
    ];

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: "pair guide".to_string(),
            summary: Some(match mode {
                Some(m) => format!("Hyphae v2 pairing guide ({})", m.as_str()),
                None => "Hyphae v2 pairing guide (team, p2p, public)".to_string(),
            }),
            data: Some(json!({
                "mode": mode.map(GuideMode::as_str),
                "topologies": topologies,
                "presets": presets,
                "natTips": nat_tips,
                "escalationNotes": escalation_guidance,
            })),
            warnings: Vec::new(),
            next,
            error: None,
        };
        print_json(&envelope);
        return ExitCode::from(EXIT_OK);
    }

    println!("Hyphae v2 Permissioned Pairing Guide");
    println!();
    for t in &topologies {
        println!("[{}] {} ({})", t.mode, t.title, t.token_prefix);
        println!("  Trust:  {}", t.trust_model);
        println!("  Flow:   {}", t.summary);
        println!("  Invite: {}", t.invite_example);
        println!("  Accept: {}", t.accept_example);
        println!("  NAT:    {}", t.nat_notes);
        println!();
    }

    println!("Scope Presets (note: '*' and 'full' NEVER grant bridge:post or forward:via):");
    for p in &presets {
        println!(
            "  {:<10}  tier={:<6}  {}",
            p.name, p.trust_tier, p.summary
        );
        println!("              scopes: {}", p.scopes.join(" "));
    }

    println!();
    println!("NAT, Firewall & Token Hygiene:");
    for tip in &nat_tips {
        println!("  • {tip}");
    }

    println!();
    println!("Escalation Notes (Anti-Prompt-Injection):");
    println!(
        "  • Remote escalation hints are capped at 512 UTF-8 bytes, stripped of control chars, and marked untrusted: true."
    );

    print_next_steps(&next);
    ExitCode::from(EXIT_OK)
}

// ============================================================================
// `pair invite`
// ============================================================================

/// Splits CLI scope arguments supporting multiple flags, RFC 6749 whitespace separation,
/// AND comma-separated shorthands (`"dm:*,files:send=25mb"`) without breaking commas
/// inside `stream:subscribe=github[repo=a/b,c/d]` or `dm:send=alice,bob`.
fn tokenize_scope_args(raw_args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for arg in raw_args {
        for piece in arg.split_ascii_whitespace() {
            if piece.is_empty() {
                continue;
            }
            // If it parses as a single valid v2 scope or shorthand intact, keep it as-is.
            if expand_v2_scopes(&[piece]).is_ok() {
                out.push(piece.to_string());
                continue;
            }
            // Otherwise split on commas outside `[...]` when the following segment looks like a new scope (`<word>:` or `*`).
            let mut bracket_depth: usize = 0;
            let mut start = 0usize;
            for (i, &b) in piece.as_bytes().iter().enumerate() {
                match b {
                    b'[' => bracket_depth += 1,
                    b']' => bracket_depth = bracket_depth.saturating_sub(1),
                    b',' if bracket_depth == 0 => {
                        let tail = &piece[i + 1..];
                        if looks_like_scope_start(tail) {
                            let seg = &piece[start..i];
                            if !seg.is_empty() {
                                out.push(seg.to_string());
                            }
                            start = i + 1;
                        }
                    }
                    _ => {}
                }
            }
            let last = &piece[start..];
            if !last.is_empty() {
                out.push(last.to_string());
            }
        }
    }
    out
}

fn looks_like_scope_start(s: &str) -> bool {
    if s == "*" || s.starts_with("*,") {
        return true;
    }
    let prefix = s.split([',', '=', '[']).next().unwrap_or("");
    prefix.contains(':')
}

fn generate_offer_id() -> Result<String, String> {
    let rng = SystemRandom::new();
    let mut b = [0u8; 16];
    rng.fill(&mut b)
        .map_err(|_| "OS CSPRNG failure".to_string())?;
    let h = hex::encode(b);
    Ok(format!(
        "offer-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..20]
    ))
}

fn admin_ca_secret_name(node_id: &str) -> String {
    let hash = hex::encode(Sha256::digest(node_id.as_bytes()));
    format!("admin-ca-{}", &hash[..12])
}

fn load_or_create_admin_key(store: &SecretStore, node_id: &str) -> Result<Ed25519KeyPair, String> {
    let name = admin_ca_secret_name(node_id);
    match store.get(&name) {
        Ok(b64) => Ed25519KeyPair::from_pkcs8_b64(&b64)
            .map_err(|e| format!("failed to parse stored admin key '{name}': {e}")),
        Err(hyp_crypto::CryptoError::SecretNotFound(_)) => {
            let kp = Ed25519KeyPair::generate()
                .map_err(|e| format!("failed to generate admin Ed25519 key: {e}"))?;
            let exported = kp.export_pkcs8_b64();
            store
                .set(&name, &exported)
                .map_err(|e| format!("failed to store admin key '{name}': {e}"))?;
            Ok(kp)
        }
        Err(e) => Err(format!("failed to read admin key '{name}': {e}")),
    }
}

/// Projects v2 scopes onto v1-compatible scopes for `issue_grant_v1` inside `am2_` bundles.
fn project_v2_to_v1_scopes(v2_scopes: &[String]) -> Vec<&'static str> {
    let set = ScopeSet::from_strings(v2_scopes);
    let mut v1 = Vec::new();
    if set.may_dm_send_any() {
        v1.push("messages:send");
    }
    if set.may_dm_receive() {
        v1.push("messages:receive");
    }
    if v2_scopes
        .iter()
        .any(|s| s.starts_with("stream:subscribe") || s == "events:subscribe" || s == "*")
    {
        v1.push("events:subscribe");
    }
    if v2_scopes
        .iter()
        .any(|s| s.starts_with("files:send") || s == "*")
    {
        v1.push("files:send");
    }
    if set.may_receive_files(0) {
        v1.push("files:receive");
    }
    if set.may_fork_out() {
        v1.push("forks:send");
    }
    if set.fork_ceiling().is_some() {
        v1.push("forks:receive/full-access");
    }
    if v1.is_empty() {
        v1.push("events:subscribe");
    }
    v1
}

fn infer_trust_tier(mode: InviteMode, preset: Option<CliScopePreset>, scopes: &[String]) -> &'static str {
    if let Some(p) = preset {
        return trust_tier_str(p.to_proto().trust_tier());
    }
    if scopes.len() == 1 && scopes[0].contains("require=exact.repo") {
        return "guest";
    }
    match mode {
        InviteMode::P2p => "peer",
        InviteMode::Team => "org",
    }
}

#[allow(clippy::too_many_arguments)]
fn run_invite(
    mode: InviteMode,
    node_id: String,
    endpoint: String,
    peer: Option<String>,
    preset: Option<CliScopePreset>,
    grant: Vec<String>,
    request: Vec<String>,
    expires_hours: u64,
    escalation: Option<String>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "pair invite";

    if node_id == LOCAL_NODE_ID || !is_valid_node_id(&node_id) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_NODE_ID",
            format!(
                "Invalid --node-id '{node_id}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
            ),
            Some("Example: --node-id alice@macbook".to_string()),
        );
    }

    if let Err(e) = validate_endpoint_origin(&endpoint) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_ENDPOINT",
            format!("Invalid --endpoint '{endpoint}': {e}"),
            Some("Use https:// (or loopback http://127.0.0.1 for local testing).".to_string()),
        );
    }

    if let Some(ref p) = peer {
        if p == LOCAL_NODE_ID || !is_valid_node_id(p) {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_PEER_ID",
                format!("Invalid --peer '{p}': must be a valid nodeId and not 'local'"),
                Some("Example: --peer bob@laptop".to_string()),
            );
        }
    }

    if expires_hours == 0 || expires_hours > MAX_EXPIRES_HOURS {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_EXPIRY",
            format!("--expires-hours must be between 1 and {MAX_EXPIRES_HOURS}"),
            None,
        );
    }

    // Resolve offered scopes from --preset and/or --grant.
    let mut raw_granted: Vec<String> = Vec::new();
    if let Some(p) = preset {
        raw_granted.extend(p.to_proto().expand());
    }
    raw_granted.extend(tokenize_scope_args(&grant));
    if raw_granted.is_empty() {
        raw_granted = ScopePreset::Member.expand();
    }

    let offered_scopes = match expand_v2_scopes(&raw_granted) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_SCOPE",
                format!("Invalid --grant scope: {e}"),
                Some("Run `hyp pair guide` to see valid v2 scopes and presets.".to_string()),
            );
        }
    };

    let raw_requested = tokenize_scope_args(&request);
    let requested_scopes = if raw_requested.is_empty() {
        Vec::new()
    } else {
        match expand_v2_scopes(&raw_requested) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_SCOPE",
                    format!("Invalid --request scope: {e}"),
                    Some("Run `hyp pair guide` to see valid v2 scopes.".to_string()),
                );
            }
        }
    };

    let sanitized_escalation = escalation
        .as_deref()
        .map(EscalationNote::sanitize)
        .filter(|n| !n.is_empty());

    let effective_state_dir = resolve_state_dir(state_dir.as_deref(), None, None);
    if let Err(e) = ensure_dir(&effective_state_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }
    let store = crate::config_file::open_secret_store(&effective_state_dir, state_dir.is_some());
    let now_ms = now_unix_ms();
    let ttl_ms = (expires_hours as i64) * 3_600_000;
    let expires_at = format_rfc3339_millis(now_ms + ttl_ms);
    let trust_tier = infer_trust_tier(mode, preset, &offered_scopes);
    let mut warnings = Vec::new();

    match mode {
        InviteMode::P2p => {
            let keys = match store.load_or_create_node_keys(&node_id) {
                Ok(k) => k,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "KEYSTORE_ERROR",
                        format!("Failed to load/create node identity keys: {e}"),
                        Some("Check permissions on --state-dir or HYPHAE_SECRET_BACKEND.".to_string()),
                    );
                }
            };
            let offer_id = match generate_offer_id() {
                Ok(id) => id,
                Err(e) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "RNG_ERROR", e, None);
                }
            };

            let offer = match create_p2p_offer(
                &offer_id,
                &node_id,
                &endpoint,
                &keys,
                offered_scopes.clone(),
                requested_scopes.clone(),
                &expires_at,
            ) {
                Ok(o) => o,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "OFFER_ERROR",
                        format!("Failed to construct P2P offer: {e}"),
                        None,
                    );
                }
            };

            let token = match encode_hp2p1_with_metadata(
                &offer,
                &keys.signing,
                sanitized_escalation.as_ref().map(EscalationNote::as_str),
                preset.map(|_| trust_tier),
                peer.as_deref(),
            ) {
                Ok(t) => t,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "ENCODE_ERROR",
                        format!("Failed to encode hp2p1_ token: {e}"),
                        None,
                    );
                }
            };

            // Persist single-use sentinel grant row in `node.sqlite` AND the full serialized
            // `P2pOfferToken` in `SecretStore` (zero plaintext secret on disk) so a running
            // `UnifiedNode` daemon can verify and atomically claim `POST /v1/p2p/pair/<offerId>`.
            let db_path = effective_state_dir.join("node.sqlite");
            let db = match NodeDb::open(&db_path) {
                Ok(d) => d,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "DB_ERROR",
                        format!("Failed to open {}: {e}", db_path.display()),
                        None,
                    );
                }
            };
            let sentinel_json = match serde_json::to_string(&json!({ "offerId": offer_id })) {
                Ok(s) => s,
                Err(e) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None);
                }
            };
            if let Err(e) = db.peers().add_grant(
                &GrantInput {
                    id: format!("p2p-offer:{offer_id}"),
                    peer_id: node_id.clone(),
                    direction: GrantDirection::Inbound,
                    signed_json: sentinel_json,
                    scopes: offered_scopes.clone(),
                    trust_tier: StoreTrustTier::Peer,
                    issued_at: now_ms,
                    pair_by: Some(now_ms + ttl_ms),
                    expires_at: None,
                },
                now_ms,
            ) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "DB_ERROR",
                    format!("Failed to persist single-use P2P offer grant in SQLite: {e}"),
                    None,
                );
            }
            let offer_secret_key = p2p_offer_secret_name(&offer.offer_id);
            let offer_json = match serde_json::to_string(&offer) {
                Ok(s) => s,
                Err(e) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None);
                }
            };
            if let Err(e) = store.set(&offer_secret_key, &offer_json) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "KEYSTORE_ERROR",
                    format!("Failed to persist P2P offer in SecretStore: {e}"),
                    None,
                );
            }

            let kid = keys.kid();
            let enc_kid = keys.encryption.kid();
            let fingerprint = keys.fingerprint();

            // Stdin-safe next commands (NEVER pass token as an argv flag!).
            let next = vec![
                "Send this one-shot hp2p1_ token to your peer over an out-of-band channel (Signal/Slack/1Password).".to_string(),
                "Peer inspects first (stdin-safe): hyp pair inspect <<< '<token>'".to_string(),
                "Peer accepts (stdin-safe):        hyp pair accept <<< '<token>'".to_string(),
            ];

            if as_json {
                let envelope = JsonEnvelope {
                    ok: true,
                    command: cmd.to_string(),
                    summary: Some(format!(
                        "Generated hp2p1_ P2P pairing offer for '{}' (kid {})",
                        node_id, kid
                    )),
                    data: Some(json!({
                        "mode": "p2p",
                        "format": "hp2p1",
                        "token": token,
                        "offerId": offer_id,
                        "nodeId": node_id,
                        "peerId": peer,
                        "endpoint": endpoint,
                        "kid": kid,
                        "encryptionKid": enc_kid,
                        "fingerprint": fingerprint,
                        "trustTier": trust_tier,
                        "offeredScopes": offered_scopes,
                        "requestedScopes": requested_scopes,
                        "expiresAt": expires_at,
                        "escalationNote": sanitized_escalation.as_ref().map(EscalationNote::as_str),
                        "secretBackend": store.backend().as_str(),
                        "acceptCommandTemplate": "hyp pair accept <<< '<token>'",
                    })),
                    warnings,
                    next,
                    error: None,
                };
                print_json(&envelope);
            } else {
                println!("OK    Generated Direct P2P pairing invite (hp2p1_)");
                println!("      Node ID:     {node_id}");
                if let Some(ref p) = peer {
                    println!("      Target Peer: {p}");
                }
                println!("      Endpoint:    {endpoint}");
                println!("      Offer ID:    {offer_id}");
                println!("      JWK kid:     {kid}");
                println!("      Fingerprint: {fingerprint}");
                println!("      Trust Tier:  {trust_tier}");
                println!("      Expires At:  {expires_at}");
                println!("      Grants:      {}", offered_scopes.join(" "));
                if !requested_scopes.is_empty() {
                    println!("      Requests:    {}", requested_scopes.join(" "));
                }
                if let Some(ref note) = sanitized_escalation {
                    println!("      Escalation:  {}", note.as_str());
                }
                println!();
                println!("Pairing Token (share out-of-band; never pass as a CLI argv flag):");
                println!("{token}");
                print_next_steps(&next);
            }
            ExitCode::from(EXIT_OK)
        }
        InviteMode::Team => {
            let target_peer = match peer {
                Some(p) => p,
                None => {
                    let fallback = "member@peer".to_string();
                    warnings.push(format!(
                        "No --peer specified; issued Org Admin-CA grant for default peer ID '{fallback}'. Pass --peer <user@host> for a named device."
                    ));
                    fallback
                }
            };

            let admin_key = match load_or_create_admin_key(&store, &node_id) {
                Ok(k) => k,
                Err(e) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "KEYSTORE_ERROR", e, None);
                }
            };

            let v1_scopes = project_v2_to_v1_scopes(&offered_scopes);
            let issued_v1 = match issue_grant_v1(&admin_key, &target_peer, &v1_scopes, ttl_ms, now_ms) {
                Ok(g) => g,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "GRANT_ERROR",
                        format!("Failed to issue Admin-CA grant: {e}"),
                        None,
                    );
                }
            };

            let parsed_v1 = match parse_pairing_code_v1(&issued_v1.code) {
                Ok(p) => p,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "GRANT_ERROR",
                        format!("Failed to parse issued pairing code: {e}"),
                        None,
                    );
                }
            };
            let pair_kp = match derive_pairing_key_v1(&parsed_v1.secret, &issued_v1.grant.id) {
                Ok(kp) => kp,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "GRANT_ERROR",
                        format!("Failed to derive one-time pairing key: {e}"),
                        None,
                    );
                }
            };

            // Also sign a canonical v2 GrantV2 carrying the one-time `pairingKey` and full v2 scopes
            // and persist it into `node.sqlite` so the running hub can claim `POST /v1/pair`!
            let grant_v2 = GrantV2 {
                v: 2,
                id: issued_v1.grant.id.clone(),
                node_id: target_peer.clone(),
                scopes: offered_scopes.clone(),
                trust_tier: Some(trust_tier.to_string()),
                pairing_key: Some(pair_kp.to_jwk()),
                subject_signing_jwk: None,
                subject_encryption_jwk: None,
                issued_at: issued_v1.grant.issued_at.clone(),
                pair_by: Some(expires_at.clone()),
                expires_at: Some(expires_at.clone()),
            };
            let signed_grant_v2 = match sign_grant_v2(&grant_v2, &admin_key) {
                Ok(sg) => sg,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "GRANT_ERROR",
                        format!("Failed to sign GrantV2: {e}"),
                        None,
                    );
                }
            };

            let db_path = effective_state_dir.join("node.sqlite");
            let db = match NodeDb::open(&db_path) {
                Ok(d) => d,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "DB_ERROR",
                        format!("Failed to open {}: {e}", db_path.display()),
                        None,
                    );
                }
            };
            let signed_grant_json = match serde_json::to_string(&signed_grant_v2) {
                Ok(s) => s,
                Err(e) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None);
                }
            };
            if let Err(e) = db.peers().add_grant(
                &GrantInput {
                    id: issued_v1.grant.id.clone(),
                    peer_id: target_peer.clone(),
                    direction: GrantDirection::Inbound,
                    signed_json: signed_grant_json,
                    scopes: offered_scopes.clone(),
                    trust_tier: parse_store_trust_tier(trust_tier, StoreTrustTier::Org),
                    issued_at: now_ms,
                    pair_by: Some(now_ms + ttl_ms),
                    expires_at: None,
                },
                now_ms,
            ) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "DB_ERROR",
                    format!("Failed to persist Admin-CA grant in SQLite: {e}"),
                    None,
                );
            }

            let invite = AdminInviteV2 {
                v: 2,
                router: endpoint.clone(),
                admin_jwk: admin_key.to_jwk(),
                pairing_code: issued_v1.code.clone(),
                require_e2ee: Some(true),
            };

            let token = match encode_am2_with_metadata(
                &invite,
                &node_id,
                &target_peer,
                &offered_scopes,
                trust_tier,
                &expires_at,
                sanitized_escalation.as_ref().map(EscalationNote::as_str),
                &signed_grant_v2,
            ) {
                Ok(t) => t,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "ENCODE_ERROR",
                        format!("Failed to encode am2_ bundle: {e}"),
                        None,
                    );
                }
            };

            let kid = admin_key.kid();
            let fingerprint = admin_key.fingerprint();
            let next = vec![
                "Send this one-shot am2_ bundle to the invited teammate over an out-of-band channel.".to_string(),
                "Peer inspects first (stdin-safe): hyp pair inspect <<< '<token>'".to_string(),
                "Peer accepts (stdin-safe):        hyp pair accept <<< '<token>'".to_string(),
            ];

            if as_json {
                let envelope = JsonEnvelope {
                    ok: true,
                    command: cmd.to_string(),
                    summary: Some(format!(
                        "Generated am2_ Org Admin-CA invite for '{}' on '{}' (kid {})",
                        target_peer, node_id, kid
                    )),
                    data: Some(json!({
                        "mode": "team",
                        "format": "am2",
                        "token": token,
                        "grantId": issued_v1.grant.id,
                        "nodeId": node_id,
                        "peerId": target_peer,
                        "endpoint": endpoint,
                        "kid": kid,
                        "adminJwk": admin_key.to_jwk(),
                        "adminFingerprint": fingerprint,
                        "requireE2ee": true,
                        "trustTier": trust_tier,
                        "offeredScopes": offered_scopes,
                        "expiresAt": expires_at,
                        "escalationNote": sanitized_escalation.as_ref().map(EscalationNote::as_str),
                        "signedGrantV2": signed_grant_v2,
                        "secretBackend": store.backend().as_str(),
                        "acceptCommandTemplate": "hyp pair accept <<< '<token>'",
                    })),
                    warnings,
                    next,
                    error: None,
                };
                print_json(&envelope);
            } else {
                println!("OK    Generated Org Admin-CA Team invite (am2_)");
                println!("      Node ID:     {node_id}");
                println!("      Target Peer: {target_peer}");
                println!("      Endpoint:    {endpoint}");
                println!("      Grant ID:    {}", issued_v1.grant.id);
                println!("      Admin kid:   {kid}");
                println!("      Fingerprint: {fingerprint}");
                println!("      Trust Tier:  {trust_tier}");
                println!("      Expires At:  {expires_at}");
                println!("      Scopes:      {}", offered_scopes.join(" "));
                if let Some(ref note) = sanitized_escalation {
                    println!("      Escalation:  {}", note.as_str());
                }
                println!();
                println!("Invite Bundle (share out-of-band; never pass as a CLI argv flag):");
                println!("{token}");
                print_warnings(&warnings);
                print_next_steps(&next);
            }
            ExitCode::from(EXIT_OK)
        }
    }
}

fn encode_hp2p1_with_metadata(
    offer: &hyp_crypto::pairing::P2pOfferToken,
    signing_key: &Ed25519KeyPair,
    escalation_note: Option<&str>,
    trust_tier: Option<&str>,
    peer_id: Option<&str>,
) -> Result<String, String> {
    // Always run strict hyp-crypto validation first.
    let _ = encode_hp2p1(offer).map_err(|e| e.to_string())?;
    let offer_canon = to_canonical_json(offer).map_err(|e| e.to_string())?;
    let offer_sig = signing_key.sign_domain_b64("p2p-offer", offer_canon.as_bytes());
    let mut map = match serde_json::to_value(offer).map_err(|e| e.to_string())? {
        Value::Object(m) => m,
        _ => return Err("unexpected offer serialization".to_string()),
    };
    map.insert("offerSig".to_string(), Value::String(offer_sig));
    if let Some(note) = escalation_note {
        map.insert("escalationNote".to_string(), Value::String(note.to_string()));
    }
    if let Some(tier) = trust_tier {
        map.insert("trustTier".to_string(), Value::String(tier.to_string()));
    }
    if let Some(p) = peer_id {
        map.insert("peerId".to_string(), Value::String(p.to_string()));
    }
    let canon = to_canonical_json(&Value::Object(map)).map_err(|e| e.to_string())?;
    let token = format!("{HP2P1_PREFIX}{}", URL_SAFE_NO_PAD.encode(canon.as_bytes()));
    // Cross-verify the emitted token strictly decodes back via hyp-crypto!
    decode_hp2p1(&token).map_err(|e| format!("self-verification failed: {e}"))?;
    Ok(token)
}

#[allow(clippy::too_many_arguments)]
fn encode_am2_with_metadata(
    invite: &AdminInviteV2,
    node_id: &str,
    peer_id: &str,
    scopes: &[String],
    trust_tier: &str,
    expires_at: &str,
    escalation_note: Option<&str>,
    signed_grant_v2: &SignedPayload,
) -> Result<String, String> {
    // Strictly validate via hyp-crypto first.
    let _ = encode_am2(invite).map_err(|e| e.to_string())?;
    let mut map = match serde_json::to_value(invite).map_err(|e| e.to_string())? {
        Value::Object(m) => m,
        _ => return Err("unexpected am2 serialization".to_string()),
    };
    map.insert("nodeId".to_string(), Value::String(node_id.to_string()));
    map.insert("peerId".to_string(), Value::String(peer_id.to_string()));
    map.insert(
        "scopes".to_string(),
        Value::Array(scopes.iter().cloned().map(Value::String).collect()),
    );
    map.insert("trustTier".to_string(), Value::String(trust_tier.to_string()));
    map.insert("expiresAt".to_string(), Value::String(expires_at.to_string()));
    map.insert(
        "signedGrantV2".to_string(),
        serde_json::to_value(signed_grant_v2).map_err(|e| e.to_string())?,
    );
    if let Some(note) = escalation_note {
        map.insert("escalationNote".to_string(), Value::String(note.to_string()));
    }
    let canon = to_canonical_json(&Value::Object(map)).map_err(|e| e.to_string())?;
    let token = format!("{AM2_PREFIX}{}", URL_SAFE_NO_PAD.encode(canon.as_bytes()));
    // Cross-verify strict decode via hyp-crypto!
    decode_am2(&token).map_err(|e| format!("self-verification failed: {e}"))?;
    Ok(token)
}

// ============================================================================
// `pair inspect` (stdin or --token-file ONLY)
// ============================================================================

#[cfg_attr(not(unix), allow(unused_variables, clippy::ptr_arg))]
fn read_bounded_token(token_file: Option<&Path>, warnings: &mut Vec<String>) -> Result<String, (u8, &'static str, String)> {
    let mut raw = String::new();
    match token_file {
        Some(path) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = fs::metadata(path) {
                    let mode = meta.mode() & 0o777;
                    if (mode & 0o077) != 0 {
                        warnings.push(format!(
                            "Token file {} has broad permissions ({:04o}); restrict to 0600 (chmod 600 {}).",
                            path.display(),
                            mode,
                            path.display()
                        ));
                    }
                }
            }
            let file = fs::File::open(path).map_err(|e| {
                (
                    EXIT_ERROR,
                    "TOKEN_FILE_ERROR",
                    format!("Failed to read token file {}: {e}", path.display()),
                )
            })?;
            let mut limited = file.take(MAX_TOKEN_INPUT_BYTES + 1);
            limited.read_to_string(&mut raw).map_err(|e| {
                (
                    EXIT_ERROR,
                    "TOKEN_FILE_ERROR",
                    format!("Failed to decode UTF-8 from {}: {e}", path.display()),
                )
            })?;
        }
        None => {
            let stdin = io::stdin();
            let mut limited = stdin.lock().take(MAX_TOKEN_INPUT_BYTES + 1);
            limited.read_to_string(&mut raw).map_err(|e| {
                (
                    EXIT_ERROR,
                    "STDIN_ERROR",
                    format!("Failed to read token from stdin: {e}"),
                )
            })?;
        }
    }

    if raw.len() as u64 > MAX_TOKEN_INPUT_BYTES {
        return Err((
            EXIT_ERROR,
            "TOKEN_TOO_LARGE",
            format!("Pairing token input exceeds {MAX_TOKEN_INPUT_BYTES} byte limit"),
        ));
    }

    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err((
            EXIT_ERROR,
            "EMPTY_TOKEN",
            "No pairing token received on stdin or --token-file".to_string(),
        ));
    }
    Ok(trimmed)
}

fn extract_raw_json_object(prefix: &str, token: &str) -> Option<Map<String, Value>> {
    let encoded = token.trim().strip_prefix(prefix)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    match serde_json::from_slice::<Value>(&bytes).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn extract_untrusted_escalation(
    raw_map: Option<&Map<String, Value>>,
    remote_node_id: &str,
) -> Option<hyp_proto::scopes::UntrustedEscalationNote> {
    let map = raw_map?;
    let raw_text = map
        .get("escalationNote")
        .and_then(Value::as_str)
        .or_else(|| map.get("escalation").and_then(Value::as_str))
        .or_else(|| {
            map.get("escalation")
                .and_then(|v| v.get("default"))
                .and_then(Value::as_str)
        })?;
    let sanitized = EscalationNote::sanitize(raw_text);
    if sanitized.is_empty() {
        return None;
    }
    Some(sanitized.to_untrusted_mcp(remote_node_id))
}

fn run_inspect(token_file: Option<PathBuf>, as_json: bool) -> ExitCode {
    let cmd = "pair inspect";
    let mut warnings = Vec::new();
    let token = match read_bounded_token(token_file.as_deref(), &mut warnings) {
        Ok(t) => t,
        Err((code, err_code, msg)) => {
            return emit_error(
                cmd,
                as_json,
                code,
                err_code,
                msg,
                Some("Pipe a token via stdin (`hyp pair inspect <<< '<token>'`) or pass `--token-file <path>`.".to_string()),
            );
        }
    };

    if token.starts_with(HP2P1_PREFIX) {
        inspect_hp2p1(&token, warnings, as_json)
    } else if token.starts_with(AM2_PREFIX) {
        inspect_am2(&token, warnings, as_json)
    } else if token.starts_with("t3mp1_") {
        inspect_t3mp1(&token, warnings, as_json)
    } else {
        emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "INVALID_TOKEN",
            "Unrecognized pairing token format (expected hp2p1_, am2_, or t3mp1_ prefix)",
            Some("Verify the full token was copied without extra text or truncation.".to_string()),
        )
    }
}

fn inspect_hp2p1(token: &str, mut warnings: Vec<String>, as_json: bool) -> ExitCode {
    let cmd = "pair inspect";
    let offer = match decode_hp2p1(token) {
        Ok(o) => o,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                format!("Invalid or tampered hp2p1_ pairing token: {e}"),
                Some("Ask the inviter to generate a fresh token with `hyp pair invite --mode p2p`.".to_string()),
            );
        }
    };

    let signing_pk = match offer.signing_jwk.to_ed25519() {
        Ok(pk) => pk,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_KEY",
                format!("Invalid signingJwk in hp2p1_ token: {e}"),
                None,
            );
        }
    };
    let kid = signing_pk.kid();
    let fingerprint = signing_pk.fingerprint();
    let enc_kid = match offer.encryption_jwk.thumbprint() {
        Ok(k) => k,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_KEY",
                format!("Invalid encryptionJwk in hp2p1_ token: {e}"),
                None,
            );
        }
    };

    let exp_ms = match parse_rfc3339_millis(&offer.expires_at) {
        Ok(ms) => ms,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                format!("Invalid expiresAt timestamp: {e}"),
                None,
            );
        }
    };
    let expired = now_unix_ms() > exp_ms;
    let expiry_status = if expired { "EXPIRED" } else { "OK" };

    let raw_map = extract_raw_json_object(HP2P1_PREFIX, token);
    if let Err((code, msg)) = verify_optional_hp2p1_sig(&offer, &signing_pk, raw_map.as_ref()) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            code,
            msg,
            Some("Ask the inviter to generate a fresh hp2p1_ token with `hyp pair invite --mode p2p`.".to_string()),
        );
    }
    let peer_id = raw_map
        .as_ref()
        .and_then(|m| m.get("peerId"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let trust_tier = raw_map
        .as_ref()
        .and_then(|m| m.get("trustTier"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| infer_trust_tier(InviteMode::P2p, None, &offer.offered_scopes))
        .to_string();
    let untrusted_note = extract_untrusted_escalation(raw_map.as_ref(), &offer.node_id);

    if expired {
        warnings.push(format!("Pairing offer expired at {}.", offer.expires_at));
    }

    let ok = !expired;
    let next = if ok {
        vec![
            format!("Verify JWK kid '{kid}' out-of-band with '{}'.", offer.node_id),
            "Accept via stdin: hyp pair accept <<< '<token>'".to_string(),
        ]
    } else {
        vec![format!(
            "Request a fresh hp2p1_ invite from '{}' (this offer expired at {}).",
            offer.node_id, offer.expires_at
        )]
    };

    let data = json!({
        "format": "hp2p1",
        "mode": "p2p",
        "offerId": offer.offer_id,
        "nodeId": offer.node_id,
        "peerId": peer_id,
        "endpoint": offer.endpoint,
        "kid": kid,
        "encryptionKid": enc_kid,
        "fingerprint": fingerprint,
        "secretBits": P2P_SECRET_BYTES * 8,
        "offeredScopes": offer.offered_scopes,
        "requestedScopes": offer.requested_scopes,
        "scopes": offer.offered_scopes,
        "trustTier": trust_tier,
        "expiresAt": offer.expires_at,
        "expiryStatus": expiry_status,
        "escalationNote": untrusted_note,
    });

    if as_json {
        let error = if expired {
            Some(CliError {
                code: "TOKEN_EXPIRED".to_string(),
                message: format!("P2P pairing offer '{}' expired at {}", offer.offer_id, offer.expires_at),
                fix: next.first().cloned(),
            })
        } else {
            None
        };
        let envelope = JsonEnvelope {
            ok,
            command: cmd.to_string(),
            summary: Some(format!(
                "Inspected hp2p1_ offer from '{}' (expiry: {expiry_status})",
                offer.node_id
            )),
            data: Some(data),
            warnings,
            next,
            error,
        };
        print_json(&envelope);
    } else {
        let tag = if ok { "OK" } else { "FAIL" };
        println!("{tag:<4}  Direct P2P Pairing Token (hp2p1_)");
        println!("      Node ID:     {}", offer.node_id);
        if let Some(ref p) = peer_id {
            println!("      Target Peer: {p}");
        }
        println!("      Endpoint:    {}", offer.endpoint);
        println!("      Offer ID:    {}", offer.offer_id);
        println!("      JWK kid:     {kid}");
        println!("      Fingerprint: {fingerprint}");
        println!("      Trust Tier:  {trust_tier}");
        println!("      Expiry:      {expiry_status} ({})", offer.expires_at);
        println!("      Offered:     {}", offer.offered_scopes.join(" "));
        if !offer.requested_scopes.is_empty() {
            println!("      Requested:   {}", offer.requested_scopes.join(" "));
        }
        if let Some(ref note) = untrusted_note {
            println!(
                "      Access hint (untrusted, reported by {}): {}",
                offer.node_id, note.text
            );
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    if ok {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_ERROR)
    }
}

fn inspect_am2(token: &str, mut warnings: Vec<String>, as_json: bool) -> ExitCode {
    let cmd = "pair inspect";
    let invite = match decode_am2(token) {
        Ok(i) => i,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                format!("Invalid or tampered am2_ invite bundle: {e}"),
                Some("Verify the am2_ bundle was not truncated or modified.".to_string()),
            );
        }
    };

    let admin_pk = match invite.admin_jwk.to_ed25519() {
        Ok(pk) => pk,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_KEY",
                format!("Invalid adminJwk in am2_ bundle: {e}"),
                None,
            );
        }
    };
    let kid = admin_pk.kid();
    let admin_fingerprint = admin_pk.fingerprint();
    let parsed_v1 = if invite.pairing_code.starts_with("t3mp1_") {
        parse_pairing_code_v1(&invite.pairing_code).ok()
    } else {
        None
    };

    let raw_map = extract_raw_json_object(AM2_PREFIX, token);
    if let Err((code, msg)) = verify_optional_am2_signed_grant(
        &admin_pk,
        parsed_v1.as_ref().map(|p| p.grant_id.as_str()),
        raw_map.as_ref(),
    ) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            code,
            msg,
            Some("Ask your organization administrator for a fresh am2_ invite bundle.".to_string()),
        );
    }
    let node_id = raw_map
        .as_ref()
        .and_then(|m| m.get("nodeId"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let peer_id = raw_map
        .as_ref()
        .and_then(|m| m.get("peerId"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let scopes: Vec<String> = raw_map
        .as_ref()
        .and_then(|m| m.get("scopes"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let trust_tier = raw_map
        .as_ref()
        .and_then(|m| m.get("trustTier"))
        .and_then(Value::as_str)
        .unwrap_or("org")
        .to_string();
    let expires_at = raw_map
        .as_ref()
        .and_then(|m| m.get("expiresAt"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let (expiry_status, expired) = match expires_at.as_deref() {
        Some(ts) => match parse_rfc3339_millis(ts) {
            Ok(ms) if now_unix_ms() > ms => ("EXPIRED", true),
            Ok(_) => ("OK", false),
            Err(_) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_TOKEN",
                    format!("Malformed expiresAt '{ts}' in am2_ bundle"),
                    None,
                );
            }
        },
        None => ("UNKNOWN", false),
    };

    if expired {
        if let Some(ref ts) = expires_at {
            warnings.push(format!("Invite bundle expired at {ts}."));
        }
    }

    let remote_label = node_id.as_deref().unwrap_or(&invite.router);
    let untrusted_note = extract_untrusted_escalation(raw_map.as_ref(), remote_label);

    let ok = !expired;
    let next = if ok {
        vec![
            format!("Verify Admin JWK kid '{kid}' with your organization administrator."),
            "Accept via stdin: hyp pair accept <<< '<token>'".to_string(),
        ]
    } else {
        vec!["Request a fresh am2_ invite bundle from your organization administrator.".to_string()]
    };

    let data = json!({
        "format": "am2",
        "mode": "team",
        "nodeId": node_id,
        "peerId": peer_id,
        "endpoint": invite.router,
        "grantId": parsed_v1.as_ref().map(|p| p.grant_id.as_str()),
        "kid": kid,
        "adminFingerprint": admin_fingerprint,
        "requireE2ee": invite.require_e2ee.unwrap_or(true),
        "scopes": scopes,
        "trustTier": trust_tier,
        "expiresAt": expires_at,
        "expiryStatus": expiry_status,
        "escalationNote": untrusted_note,
    });

    if as_json {
        let error = if expired {
            Some(CliError {
                code: "TOKEN_EXPIRED".to_string(),
                message: "Org Admin-CA invite bundle has expired".to_string(),
                fix: next.first().cloned(),
            })
        } else {
            None
        };
        let envelope = JsonEnvelope {
            ok,
            command: cmd.to_string(),
            summary: Some(format!(
                "Inspected am2_ Org Admin-CA bundle for {} (expiry: {expiry_status})",
                invite.router
            )),
            data: Some(data),
            warnings,
            next,
            error,
        };
        print_json(&envelope);
    } else {
        let tag = if ok { "OK" } else { "FAIL" };
        println!("{tag:<4}  Org Admin-CA Team Invite Bundle (am2_)");
        if let Some(ref nid) = node_id {
            println!("      Node ID:     {nid}");
        }
        if let Some(ref pid) = peer_id {
            println!("      Target Peer: {pid}");
        }
        println!("      Endpoint:    {}", invite.router);
        if let Some(ref p1) = parsed_v1 {
            println!("      Grant ID:    {}", p1.grant_id);
        }
        println!("      Admin kid:   {kid}");
        println!("      Fingerprint: {admin_fingerprint}");
        println!("      Trust Tier:  {trust_tier}");
        println!(
            "      RequireE2EE: {}",
            invite.require_e2ee.unwrap_or(true)
        );
        match &expires_at {
            Some(ts) => println!("      Expiry:      {expiry_status} ({ts})"),
            None => println!("      Expiry:      {expiry_status} (enforced server-side by router)"),
        }
        if !scopes.is_empty() {
            println!("      Scopes:      {}", scopes.join(" "));
        }
        if let Some(ref note) = untrusted_note {
            println!(
                "      Access hint (untrusted, reported by {}): {}",
                remote_label, note.text
            );
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    if ok {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_ERROR)
    }
}

fn inspect_t3mp1(token: &str, mut warnings: Vec<String>, as_json: bool) -> ExitCode {
    let cmd = "pair inspect";
    let parsed = match parse_pairing_code_v1(token) {
        Ok(p) => p,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                format!("Invalid or tampered legacy t3mp1_ pairing code: {e}"),
                Some("Verify the full t3mp1_ code was copied cleanly.".to_string()),
            );
        }
    };

    warnings.push(
        "Legacy v1 t3mp1_ code does not embed router URL, scopes, or expiry; prefer v2 am2_ or hp2p1_ tokens.".to_string(),
    );

    let next = vec![
        format!(
            "Verify admin fingerprint '{}' with your router administrator.",
            parsed.admin_fingerprint
        ),
        "Prefer generating v2 tokens via `hyp pair invite --mode team` or `--mode p2p`.".to_string(),
    ];

    let data = json!({
        "format": "t3mp1",
        "mode": "legacy-v1",
        "grantId": parsed.grant_id,
        "adminFingerprint": parsed.admin_fingerprint,
        "secretBits": 160,
        "trustTier": "org",
        "scopes": [],
        "expiryStatus": "UNKNOWN",
        "escalationNote": Value::Null,
    });

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!("Inspected legacy v1 t3mp1_ code (grant {})", parsed.grant_id)),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("WARN  Legacy v1 Pairing Code (t3mp1_)");
        println!("      Grant ID:    {}", parsed.grant_id);
        println!("      Admin FP:    {}", parsed.admin_fingerprint);
        println!("      Trust Tier:  org (legacy v1)");
        println!("      Expiry:      UNKNOWN (enforced server-side by router)");
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    ExitCode::from(EXIT_OK)
}

// ============================================================================
// Verification & Storage Helpers shared by `inspect`, `accept`, and `join`
// ============================================================================

fn verify_optional_hp2p1_sig(
    offer: &hyp_crypto::pairing::P2pOfferToken,
    signing_pk: &Ed25519PublicKey,
    raw_map: Option<&Map<String, Value>>,
) -> Result<(), (&'static str, String)> {
    let Some(sig_val) = raw_map.and_then(|m| m.get("offerSig")) else {
        return Ok(());
    };
    let Some(sig) = sig_val.as_str().filter(|s| !s.is_empty()) else {
        return Err((
            "INVALID_TOKEN",
            "Malformed offerSig field in hp2p1_ pairing token".to_string(),
        ));
    };
    let canon = to_canonical_json(offer).map_err(|e| {
        (
            "INVALID_TOKEN",
            format!("Failed to canonicalize hp2p1_ offer: {e}"),
        )
    })?;
    signing_pk
        .verify_domain_b64("p2p-offer", canon.as_bytes(), sig)
        .map_err(|e| {
            (
                "INVALID_SIGNATURE",
                format!("hp2p1_ offer Ed25519 signature verification failed (fail-closed): {e}"),
            )
        })
}

fn verify_optional_am2_signed_grant(
    admin_pk: &Ed25519PublicKey,
    parsed_v1_grant_id: Option<&str>,
    raw_map: Option<&Map<String, Value>>,
) -> Result<Option<(SignedPayload, GrantV2)>, (&'static str, String)> {
    let Some(sg_val) = raw_map.and_then(|m| m.get("signedGrantV2")) else {
        return Ok(None);
    };
    let signed: SignedPayload = serde_json::from_value(sg_val.clone()).map_err(|e| {
        (
            "INVALID_TOKEN",
            format!("Malformed signedGrantV2 inside am2_ bundle: {e}"),
        )
    })?;
    let grant = verify_grant_v2(&signed, admin_pk).map_err(|e| {
        (
            "INVALID_SIGNATURE",
            format!("am2_ Admin-CA GrantV2 signature verification failed (fail-closed): {e}"),
        )
    })?;
    if let Some(v1_id) = parsed_v1_grant_id {
        if v1_id != grant.id {
            return Err((
                "INVALID_TOKEN",
                format!(
                    "am2_ pairingCode grantId '{v1_id}' does not match signedGrantV2 id '{}'",
                    grant.id
                ),
            ));
        }
    }
    if let Some(meta_scopes) = raw_map
        .and_then(|m| m.get("scopes"))
        .and_then(Value::as_array)
    {
        let meta_list: Vec<String> = meta_scopes
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect();
        if meta_list.len() != meta_scopes.len() || meta_list != grant.scopes {
            return Err((
                "INVALID_TOKEN",
                "am2_ metadata scopes do not match Admin-CA signedGrantV2 scopes (possible tampering)"
                    .to_string(),
            ));
        }
    }
    Ok(Some((signed, grant)))
}

fn parse_store_trust_tier(raw: &str, default: StoreTrustTier) -> StoreTrustTier {
    match raw.trim().to_ascii_lowercase().as_str() {
        "org" => StoreTrustTier::Org,
        "peer" => StoreTrustTier::Peer,
        "guest" => StoreTrustTier::Guest,
        "self" => StoreTrustTier::SelfNode,
        _ => default,
    }
}

fn proto_tier_to_store(tier: hyp_proto::scopes::TrustTier) -> StoreTrustTier {
    match tier {
        hyp_proto::scopes::TrustTier::SelfNode => StoreTrustTier::SelfNode,
        hyp_proto::scopes::TrustTier::Org => StoreTrustTier::Org,
        hyp_proto::scopes::TrustTier::Peer => StoreTrustTier::Peer,
        hyp_proto::scopes::TrustTier::Guest
        | hyp_proto::scopes::TrustTier::ExternalWebhook
        | hyp_proto::scopes::TrustTier::Bridge => StoreTrustTier::Guest,
    }
}

fn proto_profile_to_store(profile: ProtoNodeProfile) -> PeerProfile {
    match profile {
        ProtoNodeProfile::Local => PeerProfile::Local,
        ProtoNodeProfile::Router => PeerProfile::Router,
        ProtoNodeProfile::P2p => PeerProfile::P2p,
    }
}

fn proto_jwk_to_crypto(jwk: &hyp_proto::manifest::OkpJwk) -> CryptoOkpJwk {
    CryptoOkpJwk {
        kty: jwk.kty.clone(),
        crv: jwk.crv.as_str().to_string(),
        x: jwk.x.clone(),
    }
}

fn credential_secret_name(prefix: &str, peer_id: &str) -> String {
    let hash = hex::encode(Sha256::digest(peer_id.as_bytes()));
    format!("{prefix}-{}", &hash[..12])
}

fn derive_peer_id_from_url(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| format!("unsupported URL scheme: {url}"))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.starts_with('[') {
        return Err(format!(
            "cannot derive a canonical nodeId from '{url}'; pass --node-name <node-id>"
        ));
    }
    let host = authority
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host == LOCAL_NODE_ID || !is_valid_node_id(&host) {
        return Err(format!(
            "derived host '{host}' from '{url}' is not a valid nodeId; pass --node-name <node-id>"
        ));
    }
    Ok(host)
}

fn resolve_local_node_id(
    explicit: Option<&str>,
    state_dir: &Path,
    db: Option<&NodeDb>,
) -> Result<String, (u8, &'static str, String)> {
    if let Some(raw) = explicit {
        if raw == LOCAL_NODE_ID || !is_valid_node_id(raw) {
            return Err((
                EXIT_USAGE,
                "INVALID_NODE_ID",
                format!(
                    "Invalid --node-id '{raw}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
                ),
            ));
        }
        return Ok(raw.to_string());
    }
    let cfg_path = resolve_config_path_for_read(None, Some(state_dir), None);
    let loaded = if cfg_path.exists() {
        load_node_or_legacy_config(&cfg_path).ok()
    } else {
        None
    };
    Ok(resolve_effective_node_id(loaded.as_ref(), db))
}

fn save_grant_idempotent(db: &NodeDb, input: &GrantInput, now: i64) -> Result<(), String> {
    match db.peers().add_grant(input, now) {
        Ok(_) => Ok(()),
        Err(StoreError::IdConflict(_)) => {
            let digest = hex::encode(Sha256::digest(input.signed_json.as_bytes()));
            let mut alt = input.clone();
            alt.id = format!("{}-{}", input.id, &digest[..8]);
            db.peers()
                .add_grant(&alt, now)
                .map(|_| ())
                .map_err(|e| format!("failed to persist grant '{}': {e}", alt.id))
        }
        Err(e) => Err(format!("failed to persist grant '{}': {e}", input.id)),
    }
}

fn check_existing_signing_pin(
    db: &NodeDb,
    peer_id: &str,
    expected_kid: &str,
) -> Result<(), (&'static str, String)> {
    let existing = db
        .peers()
        .list_peer_keys(peer_id, Some(KeyUse::Signing), true)
        .map_err(|e| {
            (
                "DB_ERROR",
                format!("Failed to query pinned keys for '{peer_id}': {e}"),
            )
        })?;
    if !existing.is_empty() && !existing.iter().any(|k| k.kid == expected_kid) {
        return Err((
            "KEY_PIN_MISMATCH",
            format!(
                "Peer '{peer_id}' signing key '{expected_kid}' does not match previously pinned key '{}' (refusing silent key rotation)",
                existing[0].kid
            ),
        ));
    }
    Ok(())
}

// ============================================================================
// Live HTTP Pairing Handshakes (`hp2p1_` & `am2_`, shared with `onboard --join`)
// ============================================================================

const PAIR_HTTP_TIMEOUT_SECS: u64 = 15;

pub(crate) enum LiveHandshakeError {
    Unreachable(String),
    Rejected { code: &'static str, message: String },
}

pub(crate) struct OnboardJoinResult {
    pub format: &'static str,
    pub peer_id: String,
    pub endpoint: String,
    pub kid: Option<String>,
    pub scopes: Vec<String>,
    pub enrolled: bool,
}

struct LiveP2pHandshakeResult {
    bob_grant_id: String,
    bob_grant_signed: SignedPayload,
    alice_grant_verified: GrantV2,
    alice_grant_signed: SignedPayload,
    auth_credential: String,
    signed_manifest: SignedNodeManifest,
    manifest_payload: Box<NodeManifestPayload>,
    manifest_etag: String,
}

struct LiveAm2HandshakeResult {
    hub_node_id: String,
    verified_grant: GrantV2,
    signed_grant: SignedPayload,
    auth_credential: String,
    signed_manifest: SignedNodeManifest,
    manifest_payload: Box<NodeManifestPayload>,
    hub_signing_pk: Ed25519PublicKey,
    hub_encryption_pk: X25519PublicKey,
    manifest_etag: String,
}

fn compute_manifest_etag(manifest_json: &str) -> String {
    let digest = hex::encode(Sha256::digest(manifest_json.as_bytes()));
    format!("\"{}\"", &digest[..16])
}

fn verify_signed_manifest_strict(
    signed: &SignedNodeManifest,
    expected_node_id: Option<&str>,
    expected_signing_pk: Option<&Ed25519PublicKey>,
    expected_enc_x: Option<&str>,
) -> Result<(NodeManifestPayload, Ed25519PublicKey, X25519PublicKey), (&'static str, String)> {
    let payload = signed.decode_payload().map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Invalid NodeManifestPayload in pairing reply: {e}"),
        )
    })?;
    if let Some(expected) = expected_node_id {
        if payload.node_id.as_str() != expected {
            return Err((
                "NODE_ID_MISMATCH",
                format!(
                    "Pairing reply manifest nodeId '{}' does not match expected '{expected}'",
                    payload.node_id
                ),
            ));
        }
    }
    let canonical = payload.to_canonical_payload().map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Failed to canonicalize pairing manifest payload: {e}"),
        )
    })?;
    if canonical != signed.payload {
        return Err((
            "NON_CANONICAL_MANIFEST",
            "Pairing reply manifest payload is not canonical RFC 8785 JCS (fail-closed)".to_string(),
        ));
    }
    let crypto_sign_jwk = proto_jwk_to_crypto(&payload.identity.signing_jwk);
    let crypto_enc_jwk = proto_jwk_to_crypto(&payload.identity.encryption_jwk);
    let signing_pk = crypto_sign_jwk.to_ed25519().map_err(|e| {
        (
            "INVALID_KEY",
            format!("Invalid signingJwk in pairing manifest: {e}"),
        )
    })?;
    let encryption_pk = crypto_enc_jwk.to_x25519().map_err(|e| {
        (
            "INVALID_KEY",
            format!("Invalid encryptionJwk in pairing manifest: {e}"),
        )
    })?;

    if let Some(expected_pk) = expected_signing_pk {
        if &signing_pk != expected_pk {
            return Err((
                "KEY_PIN_MISMATCH",
                "Pairing reply manifest signingJwk does not match out-of-band pinned key (fail-closed)"
                    .to_string(),
            ));
        }
    }
    if let Some(expected_x) = expected_enc_x {
        if payload.identity.encryption_jwk.x != expected_x {
            return Err((
                "KEY_PIN_MISMATCH",
                "Pairing reply manifest encryptionJwk does not match out-of-band pinned key (fail-closed)"
                    .to_string(),
            ));
        }
    }

    let verifier_pk = expected_signing_pk.unwrap_or(&signing_pk);
    verifier_pk
        .verify_domain_b64("manifest", signed.payload.as_bytes(), &signed.sig)
        .map_err(|e| {
            (
                "INVALID_SIGNATURE",
                format!("Pairing reply manifest Ed25519 signature verification failed (fail-closed): {e}"),
            )
        })?;

    let exp_ms = parse_rfc3339_millis(&payload.expires_at).map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Invalid expiresAt '{}' in pairing manifest: {e}", payload.expires_at),
        )
    })?;
    if now_unix_ms() > exp_ms {
        return Err((
            "MANIFEST_EXPIRED",
            format!(
                "Peer '{}' manifest in pairing reply expired at {}",
                payload.node_id, payload.expires_at
            ),
        ));
    }

    Ok((payload, signing_pk, encryption_pk))
}

fn post_json_handshake(url: &str, body_bytes: Vec<u8>) -> Result<(u16, Vec<u8>), LiveHandshakeError> {
    let uri: http::Uri = url.parse().map_err(|e| LiveHandshakeError::Rejected {
        code: "INVALID_ENDPOINT",
        message: format!("Invalid pairing URI '{url}': {e}"),
    })?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "RUNTIME_ERROR",
            message: format!("Failed to start async runtime: {e}"),
        })?;

    rt.block_on(async {
        let client = build_http_client::<Full<Bytes>>().map_err(|e| {
            LiveHandshakeError::Rejected {
                code: "HTTP_ERROR",
                message: format!("Failed to initialize HTTP client: {e}"),
            }
        })?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| LiveHandshakeError::Rejected {
                code: "HTTP_ERROR",
                message: format!("Failed to build pairing HTTP request: {e}"),
            })?;

        let resp = tokio::time::timeout(
            Duration::from_secs(PAIR_HTTP_TIMEOUT_SECS),
            client.request(req),
        )
        .await
        .map_err(|_| {
            LiveHandshakeError::Unreachable(format!(
                "POST {url} timed out after {PAIR_HTTP_TIMEOUT_SECS}s"
            ))
        })?
        .map_err(|e| LiveHandshakeError::Unreachable(format!("POST {url} failed: {e}")))?;

        let status = resp.status().as_u16();
        let bytes = tokio::time::timeout(Duration::from_secs(PAIR_HTTP_TIMEOUT_SECS), async {
            let mut body = resp.into_body();
            let mut out = Vec::new();
            while let Some(frame_res) = body.frame().await {
                let frame = frame_res.map_err(|e| {
                    LiveHandshakeError::Unreachable(format!("Pairing response body read error: {e}"))
                })?;
                if let Some(chunk) = frame.data_ref() {
                    if out.len() + chunk.len() > MAX_MANIFEST_RESPONSE_BYTES {
                        return Err(LiveHandshakeError::Rejected {
                            code: "PAIR_HANDSHAKE_INVALID",
                            message: format!(
                                "Pairing response exceeds {MAX_MANIFEST_RESPONSE_BYTES} byte safety cap"
                            ),
                        });
                    }
                    out.extend_from_slice(chunk);
                }
            }
            Ok::<Vec<u8>, LiveHandshakeError>(out)
        })
        .await
        .map_err(|_| {
            LiveHandshakeError::Unreachable("Timed out reading pairing response body".to_string())
        })??;

        Ok::<(u16, Vec<u8>), LiveHandshakeError>((status, bytes))
    })
}

fn decode_handshake_http_error(
    url: &str,
    status: u16,
    body_bytes: &[u8],
    not_found_code: &'static str,
    conflict_code: &'static str,
) -> LiveHandshakeError {
    if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(body_bytes) {
        let code = match (status, problem.error.as_str()) {
            (401, _) | (403, _) => "PAIR_REJECTED",
            (404, _) => not_found_code,
            (409, _) => conflict_code,
            (410, _) => "TOKEN_EXPIRED",
            (429, _) | (_, "rate_limited") => "RATE_LIMITED",
            _ => "PAIR_HANDSHAKE_FAILED",
        };
        let detail = problem
            .detail
            .unwrap_or_else(|| format!("{} (HTTP {status})", problem.title));
        return LiveHandshakeError::Rejected {
            code,
            message: format!("POST {url} rejected ({}): {detail}", problem.error),
        };
    }
    let snippet: String = String::from_utf8_lossy(body_bytes).chars().take(200).collect();
    let code = match status {
        401 | 403 => "PAIR_REJECTED",
        404 => not_found_code,
        409 => conflict_code,
        410 => "TOKEN_EXPIRED",
        429 => "RATE_LIMITED",
        _ => "PAIR_HANDSHAKE_FAILED",
    };
    LiveHandshakeError::Rejected {
        code,
        message: format!("POST {url} returned HTTP {status}: {}", snippet.trim()),
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_live_p2p_handshake(
    offer: &P2pOfferToken,
    alice_sign_pk: &Ed25519PublicKey,
    local_node_id: &str,
    local_endpoint: Option<&str>,
    local_keys: &NodeIdentityKeys,
    granted_scopes: &[String],
    trust_tier: StoreTrustTier,
) -> Result<LiveP2pHandshakeResult, LiveHandshakeError> {
    let now_db = now_ms();
    let bob_grant_id = format!("p2p-{}", offer.offer_id);
    let bob_grant = GrantV2 {
        v: 2,
        id: bob_grant_id.clone(),
        node_id: offer.node_id.clone(),
        scopes: granted_scopes.to_vec(),
        trust_tier: Some(trust_tier.as_str().to_string()),
        pairing_key: None,
        subject_signing_jwk: Some(offer.signing_jwk.clone()),
        subject_encryption_jwk: Some(offer.encryption_jwk.clone()),
        issued_at: format_rfc3339_millis(now_db),
        pair_by: None,
        expires_at: None,
    };
    let bob_grant_signed = sign_grant_v2(&bob_grant, &local_keys.signing).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "GRANT_ERROR",
            message: format!("Failed to sign local P2P counter-grant: {e}"),
        }
    })?;
    let resp_body: P2pPairResponse = create_p2p_response(
        offer,
        local_node_id,
        local_endpoint,
        local_keys,
        &bob_grant,
    )
    .map_err(|e| LiveHandshakeError::Rejected {
        code: "OFFER_ERROR",
        message: format!("Failed to construct P2P pairing response: {e}"),
    })?;
    let req_bytes = serde_json::to_vec(&resp_body).map_err(|e| LiveHandshakeError::Rejected {
        code: "ENCODE_ERROR",
        message: format!("Failed to serialize P2P pairing response: {e}"),
    })?;

    let url = format!(
        "{}/v1/p2p/pair/{}",
        offer.endpoint.trim_end_matches('/'),
        percent_encode(&offer.offer_id)
    );
    let (status, body_bytes) = post_json_handshake(&url, req_bytes)?;
    if status != 200 {
        return Err(decode_handshake_http_error(
            &url,
            status,
            &body_bytes,
            "OFFER_NOT_FOUND",
            "OFFER_ALREADY_CLAIMED",
        ));
    }

    let server_reply: P2pPairServerReply =
        serde_json::from_slice(&body_bytes).map_err(|e| LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: format!("Invalid P2pPairServerReply JSON from {url}: {e}"),
        })?;
    if server_reply.auth_credential.trim().is_empty() {
        return Err(LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: "Peer returned an empty authCredential in P2P pairing reply".to_string(),
        });
    }

    let confirmation = P2pPairConfirmation {
        offer_id: server_reply.offer_id.clone(),
        alice_grant_to_bob: server_reply.alice_grant_to_bob.clone(),
    };
    let alice_grant_verified =
        verify_p2p_confirmation(offer, &confirmation, local_node_id).map_err(|e| {
            LiveHandshakeError::Rejected {
                code: "INVALID_SIGNATURE",
                message: format!(
                    "Peer P2P confirmation failed zero-TOFU verification against out-of-band JWK: {e}"
                ),
            }
        })?;

    let (manifest_payload, _sign_pk, _enc_pk) = verify_signed_manifest_strict(
        &server_reply.signed_manifest,
        Some(&offer.node_id),
        Some(alice_sign_pk),
        Some(&offer.encryption_jwk.x),
    )
    .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;

    let manifest_json = serde_json::to_string(&server_reply.signed_manifest).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        }
    })?;
    let manifest_etag = compute_manifest_etag(&manifest_json);

    Ok(LiveP2pHandshakeResult {
        bob_grant_id,
        bob_grant_signed,
        alice_grant_verified,
        alice_grant_signed: server_reply.alice_grant_to_bob,
        auth_credential: server_reply.auth_credential,
        signed_manifest: server_reply.signed_manifest,
        manifest_payload: Box::new(manifest_payload),
        manifest_etag,
    })
}

fn execute_live_am2_handshake(
    invite: &AdminInviteV2,
    parsed_v1: &PairingCodeV1,
    admin_pk: &Ed25519PublicKey,
    expected_hub_id: Option<&str>,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
) -> Result<LiveAm2HandshakeResult, LiveHandshakeError> {
    let pair_kp =
        derive_pairing_key_v1(&parsed_v1.secret, &parsed_v1.grant_id).map_err(|e| {
            LiveHandshakeError::Rejected {
                code: "INVALID_TOKEN",
                message: format!("Failed to derive one-time pairing key from am2_ bundle: {e}"),
            }
        })?;

    let binding = PairBindingV2 {
        v: 2,
        grant_id: parsed_v1.grant_id.clone(),
        node_id: local_node_id.to_string(),
        signing_jwk: local_keys.signing_jwk(),
        encryption_jwk: local_keys.encryption_jwk(),
        bound_at: format_rfc3339_millis(now_ms()),
    };
    let payload = to_canonical_json(&binding).map_err(|e| LiveHandshakeError::Rejected {
        code: "ENCODE_ERROR",
        message: format!("Failed to canonicalize PairBindingV2: {e}"),
    })?;
    let pairing_sig = pair_kp.sign_domain_b64("binding", payload.as_bytes());
    let self_sig = local_keys
        .signing
        .sign_domain_b64("binding-self", payload.as_bytes());

    let pair_req = PairRequestV2 {
        grant_id: parsed_v1.grant_id.clone(),
        payload,
        pairing_sig,
        self_sig,
    };
    let req_bytes = serde_json::to_vec(&pair_req).map_err(|e| LiveHandshakeError::Rejected {
        code: "ENCODE_ERROR",
        message: format!("Failed to serialize PairRequestV2: {e}"),
    })?;

    let url = format!("{}/v1/pair", invite.router.trim_end_matches('/'));
    let (status, body_bytes) = post_json_handshake(&url, req_bytes)?;
    if status != 200 {
        return Err(decode_handshake_http_error(
            &url,
            status,
            &body_bytes,
            "GRANT_NOT_FOUND",
            "GRANT_ALREADY_CLAIMED",
        ));
    }

    let reply: PairServerReply =
        serde_json::from_slice(&body_bytes).map_err(|e| LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: format!("Invalid PairServerReply JSON from {url}: {e}"),
        })?;
    if reply.auth_credential.trim().is_empty() {
        return Err(LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: "Hub returned an empty authCredential in /v1/pair reply".to_string(),
        });
    }
    if reply.node_id == LOCAL_NODE_ID || !is_valid_node_id(&reply.node_id) {
        return Err(LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: format!("Hub returned invalid nodeId '{}' in /v1/pair reply", reply.node_id),
        });
    }
    if let Some(expected) = expected_hub_id {
        if reply.node_id != expected {
            return Err(LiveHandshakeError::Rejected {
                code: "NODE_ID_MISMATCH",
                message: format!(
                    "Hub /v1/pair returned nodeId '{}' which does not match expected '{expected}'",
                    reply.node_id
                ),
            });
        }
    }

    let verified_grant = verify_grant_v2(&reply.grant, admin_pk).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "INVALID_SIGNATURE",
            message: format!(
                "Hub /v1/pair returned grant that failed Admin-CA signature verification: {e}"
            ),
        }
    })?;
    if verified_grant.node_id != local_node_id {
        return Err(LiveHandshakeError::Rejected {
            code: "PAIR_REJECTED",
            message: format!(
                "Hub returned grant for nodeId '{}' which does not match local nodeId '{local_node_id}'",
                verified_grant.node_id
            ),
        });
    }

    let (manifest_payload, hub_signing_pk, hub_encryption_pk) = verify_signed_manifest_strict(
        &reply.signed_manifest,
        Some(&reply.node_id),
        None,
        None,
    )
    .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;

    let manifest_json = serde_json::to_string(&reply.signed_manifest).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        }
    })?;
    let manifest_etag = compute_manifest_etag(&manifest_json);

    Ok(LiveAm2HandshakeResult {
        hub_node_id: reply.node_id,
        verified_grant,
        signed_grant: reply.grant,
        auth_credential: reply.auth_credential,
        signed_manifest: reply.signed_manifest,
        manifest_payload: Box::new(manifest_payload),
        hub_signing_pk,
        hub_encryption_pk,
        manifest_etag,
    })
}

fn load_local_public_endpoint(state_dir: &Path) -> Option<String> {
    let cfg_path = resolve_config_path_for_read(None, Some(state_dir), None);
    if !cfg_path.exists() {
        return None;
    }
    load_node_or_legacy_config(&cfg_path)
        .ok()
        .and_then(|c| c.public_url)
        .filter(|u| validate_endpoint_origin(u).is_ok())
}

// ============================================================================
// `pair accept` (stdin or --token-file ONLY)
// ============================================================================

fn run_accept(
    token_file: Option<PathBuf>,
    state_dir_arg: Option<PathBuf>,
    node_id_arg: Option<String>,
    grant_args: Vec<String>,
    offline: bool,
    as_json: bool,
) -> ExitCode {
    let cmd = "pair accept";

    // Validate explicit --node-id early before reading stdin/opening disk state.
    if let Some(ref raw) = node_id_arg {
        if raw == LOCAL_NODE_ID || !is_valid_node_id(raw) {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_NODE_ID",
                format!(
                    "Invalid --node-id '{raw}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
                ),
                Some("Example: --node-id bob@laptop".to_string()),
            );
        }
    }

    // Validate explicit --grant scopes early.
    let explicit_grant_scopes = if grant_args.is_empty() {
        None
    } else {
        let tokenized = tokenize_scope_args(&grant_args);
        match expand_v2_scopes(&tokenized) {
            Ok(expanded) => Some(expanded),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_SCOPE",
                    format!("Invalid --grant scope: {e}"),
                    Some("Run `hyp pair guide` to see valid v2 scopes.".to_string()),
                );
            }
        }
    };

    let mut warnings = Vec::new();
    let token = match read_bounded_token(token_file.as_deref(), &mut warnings) {
        Ok(t) => t,
        Err((code, err_code, msg)) => {
            return emit_error(
                cmd,
                as_json,
                code,
                err_code,
                msg,
                Some(
                    "Pipe a token via stdin (`hyp pair accept <<< '<token>'`) or pass `--token-file <path>`."
                        .to_string(),
                ),
            );
        }
    };

    if token.starts_with(HP2P1_PREFIX) {
        accept_hp2p1(
            &token,
            state_dir_arg,
            node_id_arg,
            explicit_grant_scopes,
            offline,
            warnings,
            as_json,
        )
    } else if token.starts_with(AM2_PREFIX) {
        accept_am2(
            &token,
            state_dir_arg,
            node_id_arg,
            explicit_grant_scopes,
            offline,
            warnings,
            as_json,
        )
    } else if token.starts_with("t3mp1_") {
        emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "UNSUPPORTED_TOKEN",
            "Legacy v1 t3mp1_ codes do not include a router URL or Admin-CA JWK; use a v2 am2_ or hp2p1_ token.",
            Some("Generate a v2 invite via `hyp pair invite --mode team` or `--mode p2p`.".to_string()),
        )
    } else {
        emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "INVALID_TOKEN",
            "Unrecognized pairing token format (expected hp2p1_ or am2_ prefix)",
            Some("Verify the full token was copied without extra text or truncation.".to_string()),
        )
    }
}

fn accept_hp2p1(
    token: &str,
    state_dir_arg: Option<PathBuf>,
    node_id_arg: Option<String>,
    explicit_grant_scopes: Option<Vec<String>>,
    offline: bool,
    mut warnings: Vec<String>,
    as_json: bool,
) -> ExitCode {
    let cmd = "pair accept";
    let offer = match decode_hp2p1(token) {
        Ok(o) => o,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                format!("Invalid or tampered hp2p1_ pairing token: {e}"),
                Some("Ask the inviter to generate a fresh token with `hyp pair invite --mode p2p`.".to_string()),
            );
        }
    };

    if offer.node_id == LOCAL_NODE_ID || !is_valid_node_id(&offer.node_id) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "INVALID_TOKEN",
            format!("Invalid peer nodeId '{}' in hp2p1_ token", offer.node_id),
            None,
        );
    }

    if let Err(e) = validate_endpoint_origin(&offer.endpoint) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "INVALID_ENDPOINT",
            format!("Untrusted endpoint '{}' in hp2p1_ token: {e}", offer.endpoint),
            Some("Peer endpoints must use https:// (or loopback http://127.0.0.1 for local testing).".to_string()),
        );
    }

    let signing_pk = match offer.signing_jwk.to_ed25519() {
        Ok(pk) => pk,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_KEY",
                format!("Invalid signingJwk in hp2p1_ token: {e}"),
                None,
            );
        }
    };
    let encryption_pk = match offer.encryption_jwk.to_x25519() {
        Ok(pk) => pk,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_KEY",
                format!("Invalid encryptionJwk in hp2p1_ token: {e}"),
                None,
            );
        }
    };

    let raw_map = extract_raw_json_object(HP2P1_PREFIX, token);
    if let Err((code, msg)) = verify_optional_hp2p1_sig(&offer, &signing_pk, raw_map.as_ref()) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            code,
            msg,
            Some("Request a fresh unmodified hp2p1_ offer from the peer.".to_string()),
        );
    }

    let exp_ms = match parse_rfc3339_millis(&offer.expires_at) {
        Ok(ms) => ms,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                format!("Invalid expiresAt timestamp: {e}"),
                None,
            );
        }
    };
    let now = now_unix_ms();
    if now > exp_ms {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "TOKEN_EXPIRED",
            format!(
                "P2P pairing offer '{}' from '{}' expired at {}",
                offer.offer_id, offer.node_id, offer.expires_at
            ),
            Some(format!(
                "Ask '{}' to generate a fresh hp2p1_ invite.",
                offer.node_id
            )),
        );
    }

    let expanded_offered = if offer.offered_scopes.is_empty() {
        Vec::new()
    } else {
        match expand_v2_scopes(&offer.offered_scopes) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_TOKEN",
                    format!("Invalid offeredScopes in hp2p1_ token: {e}"),
                    None,
                );
            }
        }
    };

    let expanded_requested = if offer.requested_scopes.is_empty() {
        Vec::new()
    } else {
        match expand_v2_scopes(&offer.requested_scopes) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_TOKEN",
                    format!("Invalid requestedScopes in hp2p1_ token: {e}"),
                    None,
                );
            }
        }
    };

    let granted_scopes = if let Some(explicit) = explicit_grant_scopes {
        explicit
    } else if !expanded_requested.is_empty() {
        expanded_requested.clone()
    } else if !expanded_offered.is_empty() {
        expanded_offered.clone()
    } else {
        ScopePreset::Member.expand()
    };

    let trust_tier_raw = raw_map
        .as_ref()
        .and_then(|m| m.get("trustTier"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| infer_trust_tier(InviteMode::P2p, None, &expanded_offered));
    let trust_tier = parse_store_trust_tier(trust_tier_raw, StoreTrustTier::Peer);
    let untrusted_note = extract_untrusted_escalation(raw_map.as_ref(), &offer.node_id);

    let explicit_state = state_dir_arg.is_some();
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), None, None);
    if let Err(e) = ensure_dir(&state_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    let kid = signing_pk.kid();
    let enc_kid = encryption_pk.kid();
    let fingerprint = signing_pk.fingerprint();

    let db_path = state_dir.join("node.sqlite");
    let existing_db = if db_path.exists() {
        match NodeDb::open(&db_path) {
            Ok(d) => Some(d),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "DB_ERROR",
                    format!("Failed to open {}: {e}", db_path.display()),
                    None,
                );
            }
        }
    } else {
        None
    };

    if let Some(ref db) = existing_db {
        if let Err((code, msg)) = check_existing_signing_pin(db, &offer.node_id, &kid) {
            return emit_error(cmd, as_json, EXIT_ERROR, code, msg, None);
        }
    }

    let local_node_id = match resolve_local_node_id(
        node_id_arg.as_deref(),
        &state_dir,
        existing_db.as_ref(),
    ) {
        Ok(id) => id,
        Err((exit, code, msg)) => return emit_error(cmd, as_json, exit, code, msg, None),
    };

    let secrets = crate::config_file::open_secret_store(&state_dir, explicit_state);
    let local_keys = match secrets.load_or_create_node_keys(&local_node_id) {
        Ok(k) => k,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "KEYSTORE_ERROR",
                format!("Failed to load/create local node keys: {e}"),
                None,
            );
        }
    };

    // Execute real live HTTP `POST /v1/p2p/pair/<offerId>` handshake unless `--offline` is set!
    let live_res = if offline {
        warnings.push(
            "Accepted in --offline mode; run without --offline once the peer is reachable to complete the live mutual handshake."
                .to_string(),
        );
        None
    } else {
        let local_endpoint = load_local_public_endpoint(&state_dir);
        match execute_live_p2p_handshake(
            &offer,
            &signing_pk,
            &local_node_id,
            local_endpoint.as_deref(),
            &local_keys,
            &granted_scopes,
            trust_tier,
        ) {
            Ok(res) => Some(res),
            Err(LiveHandshakeError::Unreachable(msg)) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "PAIR_HANDSHAKE_FAILED",
                    msg,
                    Some(
                        "Verify the inviting peer is running and reachable, or pass --offline to pre-configure locally without contacting the peer."
                            .to_string(),
                    ),
                );
            }
            Err(LiveHandshakeError::Rejected { code, message }) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    code,
                    message,
                    Some(format!(
                        "Ask '{}' for a fresh hp2p1_ invite if this single-use offer was already claimed or expired.",
                        offer.node_id
                    )),
                );
            }
        }
    };

    let db = match existing_db {
        Some(d) => d,
        None => match NodeDb::open(&db_path) {
            Ok(d) => d,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "DB_ERROR",
                    format!("Failed to open {}: {e}", db_path.display()),
                    None,
                );
            }
        },
    };

    let cred_ref = if let Some(ref live) = live_res {
        let name = credential_secret_name("peer-auth", &offer.node_id);
        if let Err(e) = secrets.set(&name, &live.auth_credential) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "KEYSTORE_ERROR",
                format!("Failed to store peer authCredential in SecretStore: {e}"),
                None,
            );
        }
        name
    } else {
        let name = credential_secret_name("pair-p2p", &offer.node_id);
        if let Err(e) = secrets.set(&name, token) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "KEYSTORE_ERROR",
                format!("Failed to store pairing credential in SecretStore: {e}"),
                None,
            );
        }
        name
    };

    let now_db = now_ms();
    let _ = db.local().ensure_metadata("node_id", &local_node_id);

    if let Err(e) = db.peers().upsert_peer(
        &PeerInput {
            peer_id: offer.node_id.clone(),
            endpoint: Some(offer.endpoint.clone()),
            profile: PeerProfile::P2p,
            trust_tier,
            status: PeerStatus::Active,
            scopes: granted_scopes.clone(),
            auth_credential_ref: Some(cred_ref.clone()),
        },
        now_db,
    ) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DB_ERROR",
            format!("Failed to upsert peer '{}': {e}", offer.node_id),
            None,
        );
    }

    let sign_jwk_json = match serde_json::to_string(&offer.signing_jwk) {
        Ok(s) => s,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
    };
    let enc_jwk_json = match serde_json::to_string(&offer.encryption_jwk) {
        Ok(s) => s,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
    };

    if let Err(e) = db.peers().upsert_peer_key(
        &PeerKeyInput {
            peer_id: offer.node_id.clone(),
            kid: kid.clone(),
            key_use: KeyUse::Signing,
            jwk_json: sign_jwk_json,
            status: KeyStatus::Active,
            expires_at: None,
        },
        now_db,
    ) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DB_ERROR",
            format!("Failed to pin peer signing JWK: {e}"),
            None,
        );
    }
    if let Err(e) = db.peers().upsert_peer_key(
        &PeerKeyInput {
            peer_id: offer.node_id.clone(),
            kid: enc_kid.clone(),
            key_use: KeyUse::Encryption,
            jwk_json: enc_jwk_json,
            status: KeyStatus::Active,
            expires_at: None,
        },
        now_db,
    ) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DB_ERROR",
            format!("Failed to pin peer encryption JWK: {e}"),
            None,
        );
    }

    if let Some(ref live) = live_res {
        // Persist Alice's verified outbound grant, Bob's inbound counter-grant, and Alice's verified manifest!
        let alice_grant_json = match serde_json::to_string(&live.alice_grant_signed) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        };
        if let Err(e) = save_grant_idempotent(
            &db,
            &GrantInput {
                id: live.alice_grant_verified.id.clone(),
                peer_id: offer.node_id.clone(),
                direction: GrantDirection::Outbound,
                signed_json: alice_grant_json,
                scopes: live.alice_grant_verified.scopes.clone(),
                trust_tier,
                issued_at: now_db,
                pair_by: None,
                expires_at: None,
            },
            now_db,
        ) {
            return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
        }

        let bob_grant_json = match serde_json::to_string(&live.bob_grant_signed) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        };
        if let Err(e) = save_grant_idempotent(
            &db,
            &GrantInput {
                id: live.bob_grant_id.clone(),
                peer_id: offer.node_id.clone(),
                direction: GrantDirection::Inbound,
                signed_json: bob_grant_json,
                scopes: granted_scopes.clone(),
                trust_tier,
                issued_at: now_db,
                pair_by: Some(exp_ms),
                expires_at: Some(exp_ms),
            },
            now_db,
        ) {
            return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
        }

        let manifest_json = match serde_json::to_string(&live.signed_manifest) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        };
        let caps: Vec<String> = live
            .manifest_payload
            .capabilities
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        if let Err(e) = db.peers().cache_manifest(
            &offer.node_id,
            &ManifestCacheUpdate {
                manifest_version: live.manifest_payload.manifest_version as i64,
                manifest_json,
                etag: Some(live.manifest_etag.clone()),
                capabilities: caps,
                accept_downgrade: false,
            },
            now_db,
        ) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "MANIFEST_CACHE_ERROR",
                format!("Failed to cache verified manifest for '{}': {e}", offer.node_id),
                None,
            );
        }
    } else {
        // Offline local staging: sign and persist local counter-grant (`GrantV2`).
        let counter_grant_id = format!("p2p-{}", offer.offer_id);
        let counter_grant = GrantV2 {
            v: 2,
            id: counter_grant_id.clone(),
            node_id: offer.node_id.clone(),
            scopes: granted_scopes.clone(),
            trust_tier: Some(trust_tier.as_str().to_string()),
            pairing_key: None,
            subject_signing_jwk: Some(offer.signing_jwk.clone()),
            subject_encryption_jwk: Some(offer.encryption_jwk.clone()),
            issued_at: format_rfc3339_millis(now_db),
            pair_by: Some(offer.expires_at.clone()),
            expires_at: Some(offer.expires_at.clone()),
        };
        let signed_counter = match sign_grant_v2(&counter_grant, &local_keys.signing) {
            Ok(sg) => sg,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "GRANT_ERROR",
                    format!("Failed to sign local P2P counter-grant: {e}"),
                    None,
                );
            }
        };
        let signed_counter_json = match serde_json::to_string(&signed_counter) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None);
            }
        };
        if let Err(e) = save_grant_idempotent(
            &db,
            &GrantInput {
                id: counter_grant_id,
                peer_id: offer.node_id.clone(),
                direction: GrantDirection::Inbound,
                signed_json: signed_counter_json,
                scopes: granted_scopes.clone(),
                trust_tier,
                issued_at: now_db,
                pair_by: Some(exp_ms),
                expires_at: Some(exp_ms),
            },
            now_db,
        ) {
            return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
        }
    }

    let next = vec![
        "hyp service restart".to_string(),
        format!("hyp status --state-dir {}", state_dir.display()),
        format!("hyp daemon --state-dir {}", state_dir.display()),
    ];

    let data = json!({
        "mode": "p2p",
        "format": "hp2p1",
        "offerId": offer.offer_id,
        "nodeId": local_node_id,
        "peerId": offer.node_id,
        "endpoint": offer.endpoint,
        "kid": kid,
        "encryptionKid": enc_kid,
        "fingerprint": fingerprint,
        "trustTier": trust_tier.as_str(),
        "offeredScopes": expanded_offered,
        "requestedScopes": expanded_requested,
        "grantedScopes": granted_scopes,
        "scopes": granted_scopes,
        "expiresAt": offer.expires_at,
        "escalationNote": untrusted_note,
        "offline": offline,
        "handshakeCompleted": live_res.is_some(),
        "credentialRef": cred_ref,
        "secretBackend": secrets.backend().as_str(),
        "stateDir": state_dir.display().to_string(),
    });

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Accepted hp2p1_ P2P offer from '{}' (kid {})",
                offer.node_id, kid
            )),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    Accepted Direct P2P pairing offer (hp2p1_)");
        println!("      Local Node:  {local_node_id}");
        println!("      Peer ID:     {}", offer.node_id);
        println!("      Endpoint:    {}", offer.endpoint);
        println!("      Offer ID:    {}", offer.offer_id);
        println!("      JWK kid:     {kid}");
        println!("      Enc kid:     {enc_kid}");
        println!("      Fingerprint: {fingerprint}");
        println!("      Trust Tier:  {}", trust_tier.as_str());
        println!("      Offered:     {}", expanded_offered.join(" "));
        println!("      Granted:     {}", granted_scopes.join(" "));
        if let Some(ref note) = untrusted_note {
            println!(
                "      Access hint (untrusted, reported by {}): {}",
                offer.node_id, note.text
            );
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

fn accept_am2(
    token: &str,
    state_dir_arg: Option<PathBuf>,
    node_id_arg: Option<String>,
    explicit_grant_scopes: Option<Vec<String>>,
    offline: bool,
    mut warnings: Vec<String>,
    as_json: bool,
) -> ExitCode {
    let cmd = "pair accept";
    let invite = match decode_am2(token) {
        Ok(i) => i,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                format!("Invalid or tampered am2_ invite bundle: {e}"),
                Some("Verify the am2_ bundle was not truncated or modified.".to_string()),
            );
        }
    };

    if let Err(e) = validate_endpoint_origin(&invite.router) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "INVALID_ENDPOINT",
            format!("Untrusted router endpoint '{}' in am2_ bundle: {e}", invite.router),
            None,
        );
    }

    let admin_pk = match invite.admin_jwk.to_ed25519() {
        Ok(pk) => pk,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_KEY",
                format!("Invalid adminJwk in am2_ bundle: {e}"),
                None,
            );
        }
    };
    let kid = admin_pk.kid();
    let admin_fingerprint = admin_pk.fingerprint();

    let parsed_v1 = if invite.pairing_code.starts_with("t3mp1_") {
        match parse_pairing_code_v1(&invite.pairing_code) {
            Ok(p) => Some(p),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_TOKEN",
                    format!("Malformed pairingCode in am2_ bundle: {e}"),
                    None,
                );
            }
        }
    } else {
        None
    };

    let raw_map = extract_raw_json_object(AM2_PREFIX, token);
    let verified_grant_pair = match verify_optional_am2_signed_grant(
        &admin_pk,
        parsed_v1.as_ref().map(|p| p.grant_id.as_str()),
        raw_map.as_ref(),
    ) {
        Ok(v) => v,
        Err((code, msg)) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                code,
                msg,
                Some("Request a fresh unmodified am2_ bundle from your organization administrator.".to_string()),
            );
        }
    };

    let now = now_unix_ms();
    let mut expires_at_str = raw_map
        .as_ref()
        .and_then(|m| m.get("expiresAt"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    if expires_at_str.is_none() {
        expires_at_str = verified_grant_pair
            .as_ref()
            .and_then(|(_, g)| g.expires_at.clone().or_else(|| g.pair_by.clone()));
    }

    let mut expires_at_ms: Option<i64> = None;
    if let Some(ref ts) = expires_at_str {
        match parse_rfc3339_millis(ts) {
            Ok(ms) if now > ms => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "TOKEN_EXPIRED",
                    format!("Org Admin-CA invite bundle expired at {ts}"),
                    Some("Request a fresh am2_ invite bundle from your organization administrator.".to_string()),
                );
            }
            Ok(ms) => expires_at_ms = Some(ms),
            Err(_) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_TOKEN",
                    format!("Malformed expiresAt '{ts}' in am2_ bundle"),
                    None,
                );
            }
        }
    }
    if let Some((_, ref g)) = verified_grant_pair {
        for ts in [g.pair_by.as_deref(), g.expires_at.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Ok(ms) = parse_rfc3339_millis(ts) {
                if now > ms {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "TOKEN_EXPIRED",
                        format!("Admin-CA grant '{}' expired at {ts}", g.id),
                        Some("Request a fresh am2_ invite bundle from your organization administrator.".to_string()),
                    );
                }
            }
        }
    }

    let raw_hub_node_id = raw_map
        .as_ref()
        .and_then(|m| m.get("nodeId"))
        .and_then(Value::as_str);
    if let Some(raw_nid) = raw_hub_node_id {
        if raw_nid == LOCAL_NODE_ID || !is_valid_node_id(raw_nid) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                format!("Invalid hub nodeId '{raw_nid}' in am2_ bundle"),
                None,
            );
        }
    }

    let target_peer_id = verified_grant_pair
        .as_ref()
        .map(|(_, g)| g.node_id.clone())
        .or_else(|| {
            raw_map
                .as_ref()
                .and_then(|m| m.get("peerId"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });

    let mut scopes = if let Some((_, ref g)) = verified_grant_pair {
        match expand_v2_scopes(&g.scopes) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_TOKEN",
                    format!("Invalid scopes in signedGrantV2: {e}"),
                    None,
                );
            }
        }
    } else {
        let raw_scopes: Vec<String> = raw_map
            .as_ref()
            .and_then(|m| m.get("scopes"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        if raw_scopes.is_empty() {
            ScopePreset::Member.expand()
        } else {
            match expand_v2_scopes(&raw_scopes) {
                Ok(s) => s,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "INVALID_TOKEN",
                        format!("Invalid scopes in am2_ bundle: {e}"),
                        None,
                    );
                }
            }
        }
    };

    if explicit_grant_scopes.is_some() {
        warnings.push(
            "--grant is only used for P2P counter-grants; am2_ team scopes are signed by the Org Admin-CA."
                .to_string(),
        );
    }

    let trust_tier_raw = verified_grant_pair
        .as_ref()
        .and_then(|(_, g)| g.trust_tier.as_deref())
        .or_else(|| {
            raw_map
                .as_ref()
                .and_then(|m| m.get("trustTier"))
                .and_then(Value::as_str)
        })
        .unwrap_or("org");
    let trust_tier = parse_store_trust_tier(trust_tier_raw, StoreTrustTier::Org);

    let explicit_state = state_dir_arg.is_some();
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), None, None);
    if let Err(e) = ensure_dir(&state_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    let db_path = state_dir.join("node.sqlite");
    let existing_db = if db_path.exists() {
        match NodeDb::open(&db_path) {
            Ok(d) => Some(d),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "DB_ERROR",
                    format!("Failed to open {}: {e}", db_path.display()),
                    None,
                );
            }
        }
    } else {
        None
    };

    let local_node_id = match resolve_local_node_id(
        node_id_arg.as_deref(),
        &state_dir,
        existing_db.as_ref(),
    ) {
        Ok(id) => id,
        Err((exit, code, msg)) => return emit_error(cmd, as_json, exit, code, msg, None),
    };

    let secrets = crate::config_file::open_secret_store(&state_dir, explicit_state);
    let local_keys = match secrets.load_or_create_node_keys(&local_node_id) {
        Ok(k) => k,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "KEYSTORE_ERROR",
                format!("Failed to load/create local node keys: {e}"),
                None,
            );
        }
    };

    // Execute live HTTP `POST <invite.router>/v1/pair` handshake unless `--offline` is set!
    let live_res = if offline {
        warnings.push(
            "Accepted in --offline mode; run without --offline once the team hub is reachable to claim the single-use invite via POST /v1/pair."
                .to_string(),
        );
        None
    } else {
        let Some(ref v1_code) = parsed_v1 else {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                "am2_ invite bundle is missing a valid t3mp1_ pairingCode required for live POST /v1/pair",
                Some("Generate a fresh team invite with `hyp pair invite --mode team`.".to_string()),
            );
        };
        match execute_live_am2_handshake(
            &invite,
            v1_code,
            &admin_pk,
            raw_hub_node_id,
            &local_node_id,
            &local_keys,
        ) {
            Ok(res) => Some(res),
            Err(LiveHandshakeError::Unreachable(msg)) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "PAIR_HANDSHAKE_FAILED",
                    msg,
                    Some(
                        "Verify the team hub is running and reachable, or pass --offline to pre-configure locally without contacting the hub."
                            .to_string(),
                    ),
                );
            }
            Err(LiveHandshakeError::Rejected { code, message }) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    code,
                    message,
                    Some(
                        "Verify the hub has pairing.adminKey configured and this single-use am2_ invite has not already been claimed."
                            .to_string(),
                    ),
                );
            }
        }
    };

    let peer_id = if let Some(ref live) = live_res {
        live.hub_node_id.clone()
    } else if let Some(raw_nid) = raw_hub_node_id {
        raw_nid.to_string()
    } else {
        match derive_peer_id_from_url(&invite.router) {
            Ok(host) => host,
            Err(e) => {
                return emit_error(cmd, as_json, EXIT_ERROR, "INVALID_TOKEN", e, None);
            }
        }
    };

    if let Some(ref live) = live_res {
        scopes = live.verified_grant.scopes.clone();
        if let Some(ref db) = existing_db {
            if let Err((code, msg)) =
                check_existing_signing_pin(db, &peer_id, &live.hub_signing_pk.kid())
            {
                return emit_error(cmd, as_json, EXIT_ERROR, code, msg, None);
            }
        }
    }

    let untrusted_note = extract_untrusted_escalation(raw_map.as_ref(), &peer_id);

    let db = match existing_db {
        Some(d) => d,
        None => match NodeDb::open(&db_path) {
            Ok(d) => d,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "DB_ERROR",
                    format!("Failed to open {}: {e}", db_path.display()),
                    None,
                );
            }
        },
    };

    let cred_ref = if let Some(ref live) = live_res {
        let name = credential_secret_name("peer-auth", &peer_id);
        if let Err(e) = secrets.set(&name, &live.auth_credential) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "KEYSTORE_ERROR",
                format!("Failed to store hub authCredential in SecretStore: {e}"),
                None,
            );
        }
        name
    } else {
        let name = credential_secret_name("pair-am2", &peer_id);
        if let Err(e) = secrets.set(&name, token) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "KEYSTORE_ERROR",
                format!("Failed to store am2_ invite credential in SecretStore: {e}"),
                None,
            );
        }
        name
    };

    let now_db = now_ms();
    let _ = db.local().ensure_metadata("node_id", &local_node_id);

    if let Err(e) = db.peers().upsert_peer(
        &PeerInput {
            peer_id: peer_id.clone(),
            endpoint: Some(invite.router.clone()),
            profile: PeerProfile::Router,
            trust_tier,
            status: PeerStatus::Active,
            scopes: scopes.clone(),
            auth_credential_ref: Some(cred_ref.clone()),
        },
        now_db,
    ) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DB_ERROR",
            format!("Failed to upsert team hub peer '{peer_id}': {e}"),
            None,
        );
    }

    let admin_jwk_json = match serde_json::to_string(&invite.admin_jwk) {
        Ok(s) => s,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
    };
    if let Err(e) = db.peers().upsert_peer_key(
        &PeerKeyInput {
            peer_id: peer_id.clone(),
            kid: kid.clone(),
            key_use: KeyUse::Admin,
            jwk_json: admin_jwk_json,
            status: KeyStatus::Active,
            expires_at: None,
        },
        now_db,
    ) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DB_ERROR",
            format!("Failed to pin Admin-CA JWK: {e}"),
            None,
        );
    }

    if let Some(ref live) = live_res {
        let hub_sign_jwk = proto_jwk_to_crypto(&live.manifest_payload.identity.signing_jwk);
        let hub_enc_jwk = proto_jwk_to_crypto(&live.manifest_payload.identity.encryption_jwk);
        let hub_sign_json = match serde_json::to_string(&hub_sign_jwk) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        };
        let hub_enc_json = match serde_json::to_string(&hub_enc_jwk) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        };
        if let Err(e) = db.peers().upsert_peer_key(
            &PeerKeyInput {
                peer_id: peer_id.clone(),
                kid: live.hub_signing_pk.kid(),
                key_use: KeyUse::Signing,
                jwk_json: hub_sign_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        ) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "DB_ERROR",
                format!("Failed to pin hub signing JWK: {e}"),
                None,
            );
        }
        if let Err(e) = db.peers().upsert_peer_key(
            &PeerKeyInput {
                peer_id: peer_id.clone(),
                kid: live.hub_encryption_pk.kid(),
                key_use: KeyUse::Encryption,
                jwk_json: hub_enc_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        ) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "DB_ERROR",
                format!("Failed to pin hub encryption JWK: {e}"),
                None,
            );
        }
        let manifest_json = match serde_json::to_string(&live.signed_manifest) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        };
        let caps: Vec<String> = live
            .manifest_payload
            .capabilities
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        if let Err(e) = db.peers().cache_manifest(
            &peer_id,
            &ManifestCacheUpdate {
                manifest_version: live.manifest_payload.manifest_version as i64,
                manifest_json,
                etag: Some(live.manifest_etag.clone()),
                capabilities: caps,
                accept_downgrade: false,
            },
            now_db,
        ) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "MANIFEST_CACHE_ERROR",
                format!("Failed to cache verified hub manifest: {e}"),
                None,
            );
        }
    }

    let grant_id = live_res
        .as_ref()
        .map(|l| l.verified_grant.id.clone())
        .or_else(|| verified_grant_pair.as_ref().map(|(_, g)| g.id.clone()))
        .or_else(|| parsed_v1.as_ref().map(|p| p.grant_id.clone()))
        .unwrap_or_else(|| format!("am2-{}", &hex::encode(Sha256::digest(token.as_bytes()))[..12]));

    let stored_grant_json = if let Some(ref live) = live_res {
        match serde_json::to_string(&live.signed_grant) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        }
    } else if let Some((ref sg, _)) = verified_grant_pair {
        match serde_json::to_string(sg) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        }
    } else {
        json!({
            "format": "am2",
            "grantId": grant_id,
            "router": invite.router,
            "adminKid": kid,
            "adminFingerprint": admin_fingerprint,
            "scopes": scopes,
            "trustTier": trust_tier.as_str(),
            "requireE2ee": invite.require_e2ee.unwrap_or(true),
        })
        .to_string()
    };

    if let Err(e) = save_grant_idempotent(
        &db,
        &GrantInput {
            id: grant_id.clone(),
            peer_id: peer_id.clone(),
            direction: GrantDirection::Outbound,
            signed_json: stored_grant_json,
            scopes: scopes.clone(),
            trust_tier,
            issued_at: now_db,
            pair_by: expires_at_ms,
            expires_at: expires_at_ms,
        },
        now_db,
    ) {
        return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
    }

    let next = vec![
        "hyp service restart".to_string(),
        format!("hyp status --state-dir {}", state_dir.display()),
        format!("hyp daemon --state-dir {}", state_dir.display()),
    ];

    let data = json!({
        "mode": "team",
        "format": "am2",
        "grantId": grant_id,
        "nodeId": local_node_id,
        "peerId": peer_id,
        "targetPeerId": target_peer_id,
        "endpoint": invite.router,
        "kid": kid,
        "adminFingerprint": admin_fingerprint,
        "requireE2ee": invite.require_e2ee.unwrap_or(true),
        "trustTier": trust_tier.as_str(),
        "scopes": scopes,
        "expiresAt": expires_at_str,
        "escalationNote": untrusted_note,
        "offline": offline,
        "handshakeCompleted": live_res.is_some(),
        "credentialRef": cred_ref,
        "secretBackend": secrets.backend().as_str(),
        "stateDir": state_dir.display().to_string(),
    });

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Accepted am2_ Org Admin-CA invite for '{}' (grant {}, admin kid {})",
                peer_id, grant_id, kid
            )),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    Accepted Org Admin-CA Team invite (am2_)");
        println!("      Local Node:  {local_node_id}");
        println!("      Hub Peer ID: {peer_id}");
        if let Some(ref tp) = target_peer_id {
            println!("      Grant For:   {tp}");
        }
        println!("      Endpoint:    {}", invite.router);
        println!("      Grant ID:    {grant_id}");
        println!("      Admin kid:   {kid}");
        println!("      Fingerprint: {admin_fingerprint}");
        println!("      Trust Tier:  {}", trust_tier.as_str());
        println!("      Scopes:      {}", scopes.join(" "));
        if let Some(ref note) = untrusted_note {
            println!(
                "      Access hint (untrusted, reported by {}): {}",
                peer_id, note.text
            );
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

/// Executes a live `hp2p1_` mutual pairing handshake during `hyp onboard --join`.
pub(crate) fn live_pair_hp2p1_for_onboard(
    token: &str,
    state_dir: &Path,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
    db: &NodeDb,
    secrets: &SecretStore,
) -> Result<OnboardJoinResult, LiveHandshakeError> {
    let offer = decode_hp2p1(token).map_err(|e| LiveHandshakeError::Rejected {
        code: "INVALID_TOKEN",
        message: format!("Invalid hp2p1_ join token: {e}"),
    })?;
    if offer.node_id == LOCAL_NODE_ID || !is_valid_node_id(&offer.node_id) {
        return Err(LiveHandshakeError::Rejected {
            code: "INVALID_TOKEN",
            message: format!("Invalid peer nodeId '{}' in hp2p1_ token", offer.node_id),
        });
    }
    validate_endpoint_origin(&offer.endpoint).map_err(|e| LiveHandshakeError::Rejected {
        code: "INVALID_ENDPOINT",
        message: format!("Untrusted endpoint '{}' in hp2p1_ token: {e}", offer.endpoint),
    })?;
    let signing_pk = offer
        .signing_jwk
        .to_ed25519()
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "INVALID_KEY",
            message: format!("Invalid signingJwk in hp2p1_ token: {e}"),
        })?;
    let encryption_pk =
        offer
            .encryption_jwk
            .to_x25519()
            .map_err(|e| LiveHandshakeError::Rejected {
                code: "INVALID_KEY",
                message: format!("Invalid encryptionJwk in hp2p1_ token: {e}"),
            })?;
    let raw_map = extract_raw_json_object(HP2P1_PREFIX, token);
    verify_optional_hp2p1_sig(&offer, &signing_pk, raw_map.as_ref())
        .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;
    let exp_ms = parse_rfc3339_millis(&offer.expires_at).map_err(|e| LiveHandshakeError::Rejected {
        code: "INVALID_TOKEN",
        message: format!("Invalid expiresAt timestamp: {e}"),
    })?;
    if now_unix_ms() > exp_ms {
        return Err(LiveHandshakeError::Rejected {
            code: "TOKEN_EXPIRED",
            message: format!(
                "P2P pairing offer '{}' from '{}' expired at {}",
                offer.offer_id, offer.node_id, offer.expires_at
            ),
        });
    }
    let kid = signing_pk.kid();
    let enc_kid = encryption_pk.kid();
    check_existing_signing_pin(db, &offer.node_id, &kid)
        .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;

    let expanded_offered = if offer.offered_scopes.is_empty() {
        Vec::new()
    } else {
        expand_v2_scopes(&offer.offered_scopes).map_err(|e| LiveHandshakeError::Rejected {
            code: "INVALID_TOKEN",
            message: format!("Invalid offeredScopes in hp2p1_ token: {e}"),
        })?
    };
    let expanded_requested = if offer.requested_scopes.is_empty() {
        Vec::new()
    } else {
        expand_v2_scopes(&offer.requested_scopes).map_err(|e| LiveHandshakeError::Rejected {
            code: "INVALID_TOKEN",
            message: format!("Invalid requestedScopes in hp2p1_ token: {e}"),
        })?
    };
    let granted_scopes = if !expanded_requested.is_empty() {
        expanded_requested
    } else if !expanded_offered.is_empty() {
        expanded_offered.clone()
    } else {
        ScopePreset::Member.expand()
    };
    let trust_tier_raw = raw_map
        .as_ref()
        .and_then(|m| m.get("trustTier"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| infer_trust_tier(InviteMode::P2p, None, &expanded_offered));
    let trust_tier = parse_store_trust_tier(trust_tier_raw, StoreTrustTier::Peer);
    let local_endpoint = load_local_public_endpoint(state_dir);

    let live = execute_live_p2p_handshake(
        &offer,
        &signing_pk,
        local_node_id,
        local_endpoint.as_deref(),
        local_keys,
        &granted_scopes,
        trust_tier,
    )?;

    let cred_ref = credential_secret_name("peer-auth", &offer.node_id);
    secrets
        .set(&cred_ref, &live.auth_credential)
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "KEYSTORE_ERROR",
            message: format!("Failed to store peer authCredential in SecretStore: {e}"),
        })?;
    let now_db = now_ms();
    db.peers()
        .upsert_peer(
            &PeerInput {
                peer_id: offer.node_id.clone(),
                endpoint: Some(offer.endpoint.clone()),
                profile: PeerProfile::P2p,
                trust_tier,
                status: PeerStatus::Active,
                scopes: granted_scopes.clone(),
                auth_credential_ref: Some(cred_ref),
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to upsert peer '{}': {e}", offer.node_id),
        })?;
    let sign_jwk_json =
        serde_json::to_string(&offer.signing_jwk).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    let enc_jwk_json = serde_json::to_string(&offer.encryption_jwk).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        }
    })?;
    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: offer.node_id.clone(),
                kid: kid.clone(),
                key_use: KeyUse::Signing,
                jwk_json: sign_jwk_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to pin peer signing JWK: {e}"),
        })?;
    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: offer.node_id.clone(),
                kid: enc_kid,
                key_use: KeyUse::Encryption,
                jwk_json: enc_jwk_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to pin peer encryption JWK: {e}"),
        })?;
    let alice_grant_json =
        serde_json::to_string(&live.alice_grant_signed).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    save_grant_idempotent(
        db,
        &GrantInput {
            id: live.alice_grant_verified.id.clone(),
            peer_id: offer.node_id.clone(),
            direction: GrantDirection::Outbound,
            signed_json: alice_grant_json,
            scopes: live.alice_grant_verified.scopes.clone(),
            trust_tier,
            issued_at: now_db,
            pair_by: None,
            expires_at: None,
        },
        now_db,
    )
    .map_err(|message| LiveHandshakeError::Rejected {
        code: "DB_ERROR",
        message,
    })?;
    let bob_grant_json =
        serde_json::to_string(&live.bob_grant_signed).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    save_grant_idempotent(
        db,
        &GrantInput {
            id: live.bob_grant_id,
            peer_id: offer.node_id.clone(),
            direction: GrantDirection::Inbound,
            signed_json: bob_grant_json,
            scopes: granted_scopes.clone(),
            trust_tier,
            issued_at: now_db,
            pair_by: Some(exp_ms),
            expires_at: Some(exp_ms),
        },
        now_db,
    )
    .map_err(|message| LiveHandshakeError::Rejected {
        code: "DB_ERROR",
        message,
    })?;
    let manifest_json =
        serde_json::to_string(&live.signed_manifest).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    let caps: Vec<String> = live
        .manifest_payload
        .capabilities
        .iter()
        .map(|c| c.as_str().to_string())
        .collect();
    db.peers()
        .cache_manifest(
            &offer.node_id,
            &ManifestCacheUpdate {
                manifest_version: live.manifest_payload.manifest_version as i64,
                manifest_json,
                etag: Some(live.manifest_etag),
                capabilities: caps,
                accept_downgrade: false,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "MANIFEST_CACHE_ERROR",
            message: format!("Failed to cache verified manifest: {e}"),
        })?;

    Ok(OnboardJoinResult {
        format: "hp2p1",
        peer_id: offer.node_id,
        endpoint: offer.endpoint,
        kid: Some(kid),
        scopes: granted_scopes,
        enrolled: true,
    })
}

/// Executes a live `am2_` Org Admin-CA pairing handshake during `hyp onboard --join`.
pub(crate) fn live_pair_am2_for_onboard(
    token: &str,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
    db: &NodeDb,
    secrets: &SecretStore,
) -> Result<OnboardJoinResult, LiveHandshakeError> {
    let invite = decode_am2(token).map_err(|e| LiveHandshakeError::Rejected {
        code: "INVALID_TOKEN",
        message: format!("Invalid am2_ join token: {e}"),
    })?;
    validate_endpoint_origin(&invite.router).map_err(|e| LiveHandshakeError::Rejected {
        code: "INVALID_ENDPOINT",
        message: format!("Untrusted router endpoint '{}' in am2_ bundle: {e}", invite.router),
    })?;
    let admin_pk = invite
        .admin_jwk
        .to_ed25519()
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "INVALID_KEY",
            message: format!("Invalid adminJwk in am2_ bundle: {e}"),
        })?;
    let parsed_v1 = parse_pairing_code_v1(&invite.pairing_code).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "INVALID_TOKEN",
            message: format!("Malformed pairingCode in am2_ bundle: {e}"),
        }
    })?;
    let raw_map = extract_raw_json_object(AM2_PREFIX, token);
    verify_optional_am2_signed_grant(&admin_pk, Some(&parsed_v1.grant_id), raw_map.as_ref())
        .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;
    let raw_hub_node_id = raw_map
        .as_ref()
        .and_then(|m| m.get("nodeId"))
        .and_then(Value::as_str);

    let live = execute_live_am2_handshake(
        &invite,
        &parsed_v1,
        &admin_pk,
        raw_hub_node_id,
        local_node_id,
        local_keys,
    )?;

    check_existing_signing_pin(db, &live.hub_node_id, &live.hub_signing_pk.kid())
        .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;

    let cred_ref = credential_secret_name("peer-auth", &live.hub_node_id);
    secrets
        .set(&cred_ref, &live.auth_credential)
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "KEYSTORE_ERROR",
            message: format!("Failed to store hub authCredential in SecretStore: {e}"),
        })?;

    let trust_tier = live
        .verified_grant
        .trust_tier
        .as_deref()
        .map(|t| parse_store_trust_tier(t, StoreTrustTier::Org))
        .unwrap_or(StoreTrustTier::Org);
    let now_db = now_ms();
    db.peers()
        .upsert_peer(
            &PeerInput {
                peer_id: live.hub_node_id.clone(),
                endpoint: Some(invite.router.clone()),
                profile: PeerProfile::Router,
                trust_tier,
                status: PeerStatus::Active,
                scopes: live.verified_grant.scopes.clone(),
                auth_credential_ref: Some(cred_ref),
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to upsert hub peer '{}': {e}", live.hub_node_id),
        })?;
    let admin_jwk_json =
        serde_json::to_string(&invite.admin_jwk).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    let hub_sign_jwk = proto_jwk_to_crypto(&live.manifest_payload.identity.signing_jwk);
    let hub_enc_jwk = proto_jwk_to_crypto(&live.manifest_payload.identity.encryption_jwk);
    let hub_sign_json =
        serde_json::to_string(&hub_sign_jwk).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    let hub_enc_json =
        serde_json::to_string(&hub_enc_jwk).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: live.hub_node_id.clone(),
                kid: admin_pk.kid(),
                key_use: KeyUse::Admin,
                jwk_json: admin_jwk_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to pin Admin-CA JWK: {e}"),
        })?;
    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: live.hub_node_id.clone(),
                kid: live.hub_signing_pk.kid(),
                key_use: KeyUse::Signing,
                jwk_json: hub_sign_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to pin hub signing JWK: {e}"),
        })?;
    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: live.hub_node_id.clone(),
                kid: live.hub_encryption_pk.kid(),
                key_use: KeyUse::Encryption,
                jwk_json: hub_enc_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to pin hub encryption JWK: {e}"),
        })?;
    let signed_grant_json =
        serde_json::to_string(&live.signed_grant).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    save_grant_idempotent(
        db,
        &GrantInput {
            id: live.verified_grant.id.clone(),
            peer_id: live.hub_node_id.clone(),
            direction: GrantDirection::Outbound,
            signed_json: signed_grant_json,
            scopes: live.verified_grant.scopes.clone(),
            trust_tier,
            issued_at: now_db,
            pair_by: None,
            expires_at: None,
        },
        now_db,
    )
    .map_err(|message| LiveHandshakeError::Rejected {
        code: "DB_ERROR",
        message,
    })?;
    let manifest_json =
        serde_json::to_string(&live.signed_manifest).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    let caps: Vec<String> = live
        .manifest_payload
        .capabilities
        .iter()
        .map(|c| c.as_str().to_string())
        .collect();
    db.peers()
        .cache_manifest(
            &live.hub_node_id,
            &ManifestCacheUpdate {
                manifest_version: live.manifest_payload.manifest_version as i64,
                manifest_json,
                etag: Some(live.manifest_etag),
                capabilities: caps,
                accept_downgrade: false,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "MANIFEST_CACHE_ERROR",
            message: format!("Failed to cache verified hub manifest: {e}"),
        })?;

    Ok(OnboardJoinResult {
        format: "am2",
        peer_id: live.hub_node_id,
        endpoint: invite.router,
        kid: Some(admin_pk.kid()),
        scopes: live.verified_grant.scopes,
        enrolled: true,
    })
}

/// Executes a live public/team node URL join (`/v1/manifest` + optional `/v1/guest/pair`) during `hyp onboard --join`.
pub(crate) fn live_join_url_for_onboard(
    raw_url: &str,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
    db: &NodeDb,
    warnings: &mut Vec<String>,
) -> Result<OnboardJoinResult, LiveHandshakeError> {
    validate_endpoint_origin(raw_url).map_err(|e| LiveHandshakeError::Rejected {
        code: "INVALID_ENDPOINT",
        message: format!("Invalid target URL '{raw_url}': {e}"),
    })?;
    let trimmed = raw_url.trim().trim_end_matches('/');
    let base_url = trimmed
        .strip_suffix("/v1/manifest")
        .unwrap_or(trimmed)
        .to_string();

    let v = match fetch_and_verify_manifest(&base_url) {
        Ok(v) => v,
        Err((code, msg)) => {
            if code == "MANIFEST_FETCH_FAILED" {
                return Err(LiveHandshakeError::Unreachable(msg));
            }
            return Err(LiveHandshakeError::Rejected { code, message: msg });
        }
    };

    let peer_id = v.payload.node_id.as_str().to_string();
    let peer_profile = proto_profile_to_store(v.payload.profile);
    check_existing_signing_pin(db, &peer_id, &v.signing_pk.kid())
        .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;

    let mut enrolled = false;
    let mut effective_scopes = ScopePreset::GuestRo.expand();
    let mut effective_signed = v.signed.clone();
    let mut effective_payload = v.payload.clone();

    match attempt_guest_self_enroll(&base_url, &peer_id, &v.signing_pk, local_node_id, local_keys) {
        Ok(GuestEnrollOutcome::Enrolled {
            preset: _,
            scopes,
            manifest,
            manifest_payload,
        }) => {
            enrolled = true;
            effective_scopes = scopes;
            effective_signed = manifest;
            effective_payload = *manifest_payload;
        }
        Ok(GuestEnrollOutcome::NotEnabled) => {
            warnings.push(format!(
                "Node '{peer_id}' does not expose self-service guest pairing (POST /v1/guest/pair returned 404); request an am2_ invite from the hub admin to enroll."
            ));
        }
        Err((code, message)) => {
            if code == "GUEST_PAIR_FAILED" {
                return Err(LiveHandshakeError::Unreachable(message));
            }
            return Err(LiveHandshakeError::Rejected { code, message });
        }
    }

    let now_db = now_ms();
    db.peers()
        .upsert_peer(
            &PeerInput {
                peer_id: peer_id.clone(),
                endpoint: Some(base_url.clone()),
                profile: peer_profile,
                trust_tier: StoreTrustTier::Guest,
                status: PeerStatus::Active,
                scopes: effective_scopes.clone(),
                auth_credential_ref: None,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to register peer '{peer_id}': {e}"),
        })?;

    let sign_jwk = proto_jwk_to_crypto(&v.payload.identity.signing_jwk);
    let enc_jwk = proto_jwk_to_crypto(&v.payload.identity.encryption_jwk);
    let sign_json =
        serde_json::to_string(&sign_jwk).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    let enc_json =
        serde_json::to_string(&enc_jwk).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: peer_id.clone(),
                kid: v.signing_pk.kid(),
                key_use: KeyUse::Signing,
                jwk_json: sign_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to pin signing JWK for '{peer_id}': {e}"),
        })?;
    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: peer_id.clone(),
                kid: v.encryption_pk.kid(),
                key_use: KeyUse::Encryption,
                jwk_json: enc_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "DB_ERROR",
            message: format!("Failed to pin encryption JWK for '{peer_id}': {e}"),
        })?;
    let manifest_json =
        serde_json::to_string(&effective_signed).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        })?;
    let caps: Vec<String> = effective_payload
        .capabilities
        .iter()
        .map(|c| c.as_str().to_string())
        .collect();
    db.peers()
        .cache_manifest(
            &peer_id,
            &ManifestCacheUpdate {
                manifest_version: effective_payload.manifest_version as i64,
                manifest_json,
                etag: v.etag,
                capabilities: caps,
                accept_downgrade: false,
            },
            now_db,
        )
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "MANIFEST_CACHE_ERROR",
            message: format!("Failed to cache verified manifest for '{peer_id}': {e}"),
        })?;

    Ok(OnboardJoinResult {
        format: "url",
        peer_id,
        endpoint: base_url,
        kid: Some(v.signing_pk.kid()),
        scopes: effective_scopes,
        enrolled,
    })
}

// ============================================================================
// `pair join` (public / team node URL + signed `/v1/manifest` verification)
// ============================================================================

struct VerifiedLiveManifest {
    signed: SignedNodeManifest,
    payload: NodeManifestPayload,
    signing_pk: Ed25519PublicKey,
    encryption_pk: X25519PublicKey,
    etag: Option<String>,
}

fn fetch_and_verify_manifest(base_url: &str) -> Result<VerifiedLiveManifest, (&'static str, String)> {
    let manifest_url = format!("{}/v1/manifest", base_url.trim_end_matches('/'));
    let uri: http::Uri = manifest_url.parse().map_err(|e| {
        (
            "INVALID_ENDPOINT",
            format!("Invalid manifest URI '{manifest_url}': {e}"),
        )
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ("RUNTIME_ERROR", format!("Failed to start async runtime: {e}")))?;

    let (body_bytes, etag) = rt.block_on(async {
        let client = build_http_client::<Empty<Bytes>>()
            .map_err(|e| ("HTTP_ERROR", format!("Failed to initialize HTTP client: {e}")))?;

        let req = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(Empty::new())
            .map_err(|e| ("HTTP_ERROR", format!("Failed to build request: {e}")))?;

        let resp = tokio::time::timeout(
            Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS),
            client.request(req),
        )
        .await
        .map_err(|_| {
            (
                "MANIFEST_FETCH_FAILED",
                format!(
                    "GET {manifest_url} timed out after {MANIFEST_FETCH_TIMEOUT_SECS}s"
                ),
            )
        })?
        .map_err(|e| (
            "MANIFEST_FETCH_FAILED",
            format!("GET {manifest_url} failed: {e}"),
        ))?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err((
                "MANIFEST_FETCH_FAILED",
                format!("GET {manifest_url} returned HTTP {status} (expected 200)"),
            ));
        }
        let etag = resp
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        let bytes = tokio::time::timeout(Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS), async {
            let mut body = resp.into_body();
            let mut out = Vec::new();
            while let Some(frame_res) = body.frame().await {
                let frame = frame_res.map_err(|e| {
                    ("MANIFEST_FETCH_FAILED", format!("Manifest body read error: {e}"))
                })?;
                if let Some(chunk) = frame.data_ref() {
                    if out.len() + chunk.len() > MAX_MANIFEST_RESPONSE_BYTES {
                        return Err((
                            "INVALID_MANIFEST",
                            format!(
                                "Manifest response exceeds {MAX_MANIFEST_RESPONSE_BYTES} byte safety cap"
                            ),
                        ));
                    }
                    out.extend_from_slice(chunk);
                }
            }
            Ok::<Vec<u8>, (&'static str, String)>(out)
        })
        .await
        .map_err(|_| {
            (
                "MANIFEST_FETCH_FAILED",
                "Timed out reading /v1/manifest response body".to_string(),
            )
        })??;

        Ok::<(Vec<u8>, Option<String>), (&'static str, String)>((bytes, etag))
    })?;

    let signed: SignedNodeManifest = serde_json::from_slice(&body_bytes).map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Response from {manifest_url} is not a valid SignedNodeManifest: {e}"),
        )
    })?;

    let payload = signed.decode_payload().map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Invalid NodeManifestPayload in signed manifest: {e}"),
        )
    })?;

    let canonical = payload.to_canonical_payload().map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Failed to canonicalize manifest payload: {e}"),
        )
    })?;
    if canonical != signed.payload {
        return Err((
            "NON_CANONICAL_MANIFEST",
            "Signed manifest payload is not canonical RFC 8785 JCS (fail-closed)".to_string(),
        ));
    }

    let crypto_sign_jwk = proto_jwk_to_crypto(&payload.identity.signing_jwk);
    let crypto_enc_jwk = proto_jwk_to_crypto(&payload.identity.encryption_jwk);
    let signing_pk = crypto_sign_jwk.to_ed25519().map_err(|e| {
        (
            "INVALID_KEY",
            format!("Invalid signingJwk in manifest: {e}"),
        )
    })?;
    let encryption_pk = crypto_enc_jwk.to_x25519().map_err(|e| {
        (
            "INVALID_KEY",
            format!("Invalid encryptionJwk in manifest: {e}"),
        )
    })?;

    signing_pk
        .verify_domain_b64("manifest", signed.payload.as_bytes(), &signed.sig)
        .map_err(|e| {
            (
                "INVALID_SIGNATURE",
                format!("Manifest Ed25519 signature verification failed (fail-closed): {e}"),
            )
        })?;

    let exp_ms = parse_rfc3339_millis(&payload.expires_at).map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Invalid manifest expiresAt '{}': {e}", payload.expires_at),
        )
    })?;
    if now_unix_ms() > exp_ms {
        return Err((
            "MANIFEST_EXPIRED",
            format!(
                "Node '{}' manifest expired at {}",
                payload.node_id, payload.expires_at
            ),
        ));
    }

    Ok(VerifiedLiveManifest {
        signed,
        payload,
        signing_pk,
        encryption_pk,
        etag,
    })
}

enum GuestEnrollOutcome {
    Enrolled {
        preset: String,
        scopes: Vec<String>,
        manifest: SignedNodeManifest,
        manifest_payload: Box<NodeManifestPayload>,
    },
    NotEnabled,
}

fn attempt_guest_self_enroll(
    base_url: &str,
    hub_node_id: &str,
    hub_signing_pk: &Ed25519PublicKey,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
) -> Result<GuestEnrollOutcome, (&'static str, String)> {
    let pair_url = format!("{}/v1/guest/pair", base_url.trim_end_matches('/'));
    let uri: http::Uri = pair_url.parse().map_err(|e| {
        (
            "INVALID_ENDPOINT",
            format!("Invalid guest pairing URI '{pair_url}': {e}"),
        )
    })?;

    let ed25519_jwk = local_keys.signing_jwk();
    let x25519_jwk = local_keys.encryption_jwk();
    let timestamp = format_rfc3339_millis(now_unix_ms());
    let canonical = guest_pair_proof_canonical(
        hub_node_id,
        local_node_id,
        &ed25519_jwk,
        &x25519_jwk,
        &timestamp,
    )
    .map_err(|e| ("ENCODE_ERROR", format!("Failed to canonicalize guest-pair proof: {e}")))?;
    let proof_sig = local_keys
        .signing
        .sign_domain_b64("guest-pair", canonical.as_bytes());

    let req_body = GuestPairRequest {
        node_id: local_node_id.to_string(),
        ed25519_jwk,
        x25519_jwk,
        timestamp,
        proof_sig,
    };
    let req_bytes = serde_json::to_vec(&req_body)
        .map_err(|e| ("ENCODE_ERROR", format!("Failed to serialize guest-pair request: {e}")))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ("RUNTIME_ERROR", format!("Failed to start async runtime: {e}")))?;

    let (status, body_bytes) = rt.block_on(async {
        let client = build_http_client::<Full<Bytes>>()
            .map_err(|e| ("HTTP_ERROR", format!("Failed to initialize HTTP client: {e}")))?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(Full::new(Bytes::from(req_bytes)))
            .map_err(|e| ("HTTP_ERROR", format!("Failed to build guest-pair request: {e}")))?;

        let resp = tokio::time::timeout(
            Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS),
            client.request(req),
        )
        .await
        .map_err(|_| {
            (
                "GUEST_PAIR_FAILED",
                format!("POST {pair_url} timed out after {MANIFEST_FETCH_TIMEOUT_SECS}s"),
            )
        })?
        .map_err(|e| ("GUEST_PAIR_FAILED", format!("POST {pair_url} failed: {e}")))?;

        let status = resp.status().as_u16();
        let bytes = tokio::time::timeout(Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS), async {
            let mut body = resp.into_body();
            let mut out = Vec::new();
            while let Some(frame_res) = body.frame().await {
                let frame = frame_res.map_err(|e| {
                    (
                        "GUEST_PAIR_FAILED",
                        format!("Guest pair body read error: {e}"),
                    )
                })?;
                if let Some(chunk) = frame.data_ref() {
                    if out.len() + chunk.len() > MAX_MANIFEST_RESPONSE_BYTES {
                        return Err((
                            "GUEST_PAIR_INVALID",
                            format!(
                                "Guest pair response exceeds {MAX_MANIFEST_RESPONSE_BYTES} byte cap"
                            ),
                        ));
                    }
                    out.extend_from_slice(chunk);
                }
            }
            Ok::<Vec<u8>, (&'static str, String)>(out)
        })
        .await
        .map_err(|_| {
            (
                "GUEST_PAIR_FAILED",
                "Timed out reading /v1/guest/pair response body".to_string(),
            )
        })??;

        Ok::<(u16, Vec<u8>), (&'static str, String)>((status, bytes))
    })?;

    if status == 404 {
        return Ok(GuestEnrollOutcome::NotEnabled);
    }

    if status != 200 {
        let (code, detail) = if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(&body_bytes) {
            let err_code = match (status, problem.error.as_str()) {
                (_, "peer_key_mismatch") => "PEER_KEY_MISMATCH",
                (429, _) | (_, "rate_limited") => "RATE_LIMITED",
                (409, _) => "GUEST_PAIR_CONFLICT",
                (403, _) | (401, _) => "GUEST_PAIR_REJECTED",
                _ => "GUEST_PAIR_FAILED",
            };
            let msg = problem
                .detail
                .unwrap_or_else(|| format!("{} (HTTP {status})", problem.title));
            (err_code, format!("POST {pair_url} rejected ({}): {msg}", problem.error))
        } else {
            let snippet: String = String::from_utf8_lossy(&body_bytes).chars().take(200).collect();
            let err_code = match status {
                409 => "GUEST_PAIR_CONFLICT",
                429 => "RATE_LIMITED",
                401 | 403 => "GUEST_PAIR_REJECTED",
                _ => "GUEST_PAIR_FAILED",
            };
            (
                err_code,
                format!("POST {pair_url} returned HTTP {status}: {snippet}"),
            )
        };
        return Err((code, detail));
    }

    let reply: GuestPairReply = serde_json::from_slice(&body_bytes).map_err(|e| {
        (
            "GUEST_PAIR_INVALID",
            format!("Invalid GuestPairReply JSON from {pair_url}: {e}"),
        )
    })?;
    if !reply.ok {
        return Err((
            "GUEST_PAIR_REJECTED",
            format!("Hub '{hub_node_id}' returned ok=false on /v1/guest/pair"),
        ));
    }
    if reply.node_id != hub_node_id {
        return Err((
            "NODE_ID_MISMATCH",
            format!(
                "Hub /v1/guest/pair nodeId '{}' does not match verified manifest nodeId '{hub_node_id}'",
                reply.node_id
            ),
        ));
    }
    if reply.peer_id != local_node_id {
        return Err((
            "GUEST_PAIR_INVALID",
            format!(
                "Hub /v1/guest/pair peerId '{}' does not match local nodeId '{local_node_id}'",
                reply.peer_id
            ),
        ));
    }
    if reply.scopes.is_empty() {
        return Err((
            "GUEST_PAIR_INVALID",
            "Hub /v1/guest/pair returned empty granted scopes".to_string(),
        ));
    }
    let validated_scopes = expand_v2_scopes(&reply.scopes).map_err(|e| {
        (
            "GUEST_PAIR_INVALID",
            format!("Hub /v1/guest/pair returned invalid scopes: {e}"),
        )
    })?;

    // Verify the authenticated manifest returned by `/v1/guest/pair` against the pinned hub signing key!
    let manifest_payload = reply.manifest.decode_payload().map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Invalid NodeManifestPayload in /v1/guest/pair reply: {e}"),
        )
    })?;
    if manifest_payload.node_id.as_str() != hub_node_id {
        return Err((
            "NODE_ID_MISMATCH",
            format!(
                "Manifest nodeId '{}' in /v1/guest/pair reply does not match '{hub_node_id}'",
                manifest_payload.node_id
            ),
        ));
    }
    let canonical_manifest = manifest_payload.to_canonical_payload().map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Failed to canonicalize guest-pair manifest payload: {e}"),
        )
    })?;
    if canonical_manifest != reply.manifest.payload {
        return Err((
            "NON_CANONICAL_MANIFEST",
            "Manifest in /v1/guest/pair reply is not canonical RFC 8785 JCS (fail-closed)"
                .to_string(),
        ));
    }
    hub_signing_pk
        .verify_domain_b64(
            "manifest",
            reply.manifest.payload.as_bytes(),
            &reply.manifest.sig,
        )
        .map_err(|e| {
            (
                "INVALID_SIGNATURE",
                format!(
                    "Manifest signature in /v1/guest/pair reply failed pinned hub key verification: {e}"
                ),
            )
        })?;
    let exp_ms = parse_rfc3339_millis(&manifest_payload.expires_at).map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Invalid expiresAt in /v1/guest/pair manifest: {e}"),
        )
    })?;
    if now_unix_ms() > exp_ms {
        return Err((
            "MANIFEST_EXPIRED",
            format!("Hub manifest in /v1/guest/pair expired at {}", manifest_payload.expires_at),
        ));
    }

    Ok(GuestEnrollOutcome::Enrolled {
        preset: reply.preset,
        scopes: validated_scopes,
        manifest: reply.manifest,
        manifest_payload: Box::new(manifest_payload),
    })
}

fn run_join(
    url: String,
    state_dir_arg: Option<PathBuf>,
    node_id_arg: Option<String>,
    node_name_arg: Option<String>,
    preset: CliScopePreset,
    offline: bool,
    as_json: bool,
) -> ExitCode {
    let cmd = "pair join";

    if let Err(e) = validate_endpoint_origin(&url) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_ENDPOINT",
            format!("Invalid target URL '{url}': {e}"),
            Some("Use https:// (or loopback http://127.0.0.1 for local testing).".to_string()),
        );
    }

    let trimmed = url.trim().trim_end_matches('/');
    let base_url = trimmed
        .strip_suffix("/v1/manifest")
        .unwrap_or(trimmed)
        .to_string();

    if let Some(ref raw) = node_id_arg {
        if raw == LOCAL_NODE_ID || !is_valid_node_id(raw) {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_NODE_ID",
                format!(
                    "Invalid --node-id '{raw}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
                ),
                Some("Example: --node-id alice@macbook".to_string()),
            );
        }
    }

    if let Some(ref name) = node_name_arg {
        if name == LOCAL_NODE_ID || !is_valid_node_id(name) {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_PEER_ID",
                format!(
                    "Invalid --node-name '{name}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
                ),
                None,
            );
        }
    }

    let scopes = preset.to_proto().expand();
    let trust_tier = proto_tier_to_store(preset.to_proto().trust_tier());
    let mut warnings = Vec::new();

    // Fetch and cryptographically verify `/v1/manifest` BEFORE touching disk state!
    let verified_live = if offline {
        warnings.push(
            "Joined in --offline mode; manifest signature and pinned JWKs will be verified on first live connection."
                .to_string(),
        );
        None
    } else {
        match fetch_and_verify_manifest(&base_url) {
            Ok(v) => {
                if let Some(ref expected_name) = node_name_arg {
                    if v.payload.node_id.as_str() != expected_name {
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            "NODE_ID_MISMATCH",
                            format!(
                                "Signed manifest nodeId '{}' does not match --node-name '{expected_name}'",
                                v.payload.node_id
                            ),
                            None,
                        );
                    }
                }
                Some(v)
            }
            Err((code, msg)) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    code,
                    msg,
                    Some(format!(
                        "Verify {base_url}/v1/manifest is reachable and serving a valid SignedNodeManifest, or pass --offline to pre-configure."
                    )),
                );
            }
        }
    };

    let peer_id = if let Some(ref v) = verified_live {
        v.payload.node_id.as_str().to_string()
    } else if let Some(name) = node_name_arg {
        name
    } else {
        match derive_peer_id_from_url(&base_url) {
            Ok(host) => host,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_PEER_ID",
                    e,
                    Some("Example: --node-name public.hyphae.to".to_string()),
                );
            }
        }
    };

    let peer_profile = verified_live
        .as_ref()
        .map(|v| proto_profile_to_store(v.payload.profile))
        .unwrap_or(PeerProfile::Router);

    let explicit_state = state_dir_arg.is_some();
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), None, None);
    if let Err(e) = ensure_dir(&state_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    let db_path = state_dir.join("node.sqlite");
    let db = match NodeDb::open(&db_path) {
        Ok(d) => d,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "DB_ERROR",
                format!("Failed to open {}: {e}", db_path.display()),
                None,
            );
        }
    };

    if let Some(ref v) = verified_live {
        if let Err((code, msg)) = check_existing_signing_pin(&db, &peer_id, &v.signing_pk.kid()) {
            return emit_error(cmd, as_json, EXIT_ERROR, code, msg, None);
        }
    }

    let local_node_id = match resolve_local_node_id(node_id_arg.as_deref(), &state_dir, Some(&db)) {
        Ok(id) => id,
        Err((exit, code, msg)) => return emit_error(cmd, as_json, exit, code, msg, None),
    };

    let secrets = crate::config_file::open_secret_store(&state_dir, explicit_state);
    let local_keys = match secrets.load_or_create_node_keys(&local_node_id) {
        Ok(k) => k,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "KEYSTORE_ERROR",
                format!("Failed to load/create local node keys: {e}"),
                None,
            );
        }
    };

    // Attempt opt-in self-service `POST /v1/guest/pair` enrollment when online.
    let mut enrolled = false;
    let mut effective_preset = preset.as_str().to_string();
    let mut effective_scopes = scopes;
    let mut effective_signed_manifest: Option<SignedNodeManifest> = None;
    let mut effective_manifest_payload: Option<NodeManifestPayload> = None;

    if let Some(ref v) = verified_live {
        match attempt_guest_self_enroll(
            &base_url,
            &peer_id,
            &v.signing_pk,
            &local_node_id,
            &local_keys,
        ) {
            Ok(GuestEnrollOutcome::Enrolled {
                preset: granted_preset,
                scopes: granted_scopes,
                manifest,
                manifest_payload,
            }) => {
                enrolled = true;
                effective_preset = granted_preset;
                effective_scopes = granted_scopes;
                effective_signed_manifest = Some(manifest);
                effective_manifest_payload = Some(*manifest_payload);
            }
            Ok(GuestEnrollOutcome::NotEnabled) => {
                warnings.push(format!(
                    "Node '{peer_id}' does not expose self-service guest pairing (POST /v1/guest/pair returned 404); request an am2_ invite from the hub admin to enroll."
                ));
            }
            Err((code, msg)) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    code,
                    msg,
                    Some(
                        "Verify the local --node-id is not already claimed by another keypair, or retry after rate-limit cooldown."
                            .to_string(),
                    ),
                );
            }
        }
    }

    let now_db = now_ms();
    let _ = db.local().ensure_metadata("node_id", &local_node_id);

    if let Err(e) = db.peers().upsert_peer(
        &PeerInput {
            peer_id: peer_id.clone(),
            endpoint: Some(base_url.clone()),
            profile: peer_profile,
            trust_tier,
            status: PeerStatus::Active,
            scopes: effective_scopes.clone(),
            auth_credential_ref: None,
        },
        now_db,
    ) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DB_ERROR",
            format!("Failed to register peer '{peer_id}': {e}"),
            None,
        );
    }

    let mut kid: Option<String> = None;
    let mut enc_kid: Option<String> = None;
    let mut fingerprint: Option<String> = None;
    let mut hyphae_version: Option<String> = None;
    let mut capabilities: Vec<String> = Vec::new();

    if let Some(ref v) = verified_live {
        let signed_to_cache = effective_signed_manifest.as_ref().unwrap_or(&v.signed);
        let payload_to_cache = effective_manifest_payload.as_ref().unwrap_or(&v.payload);

        let sign_jwk = proto_jwk_to_crypto(&v.payload.identity.signing_jwk);
        let enc_jwk = proto_jwk_to_crypto(&v.payload.identity.encryption_jwk);
        let k = v.signing_pk.kid();
        let ek = v.encryption_pk.kid();
        let fp = v.signing_pk.fingerprint();

        let sign_json = match serde_json::to_string(&sign_jwk) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        };
        let enc_json = match serde_json::to_string(&enc_jwk) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        };

        if let Err(e) = db.peers().upsert_peer_key(
            &PeerKeyInput {
                peer_id: peer_id.clone(),
                kid: k.clone(),
                key_use: KeyUse::Signing,
                jwk_json: sign_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        ) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "DB_ERROR",
                format!("Failed to pin signing JWK for '{peer_id}': {e}"),
                None,
            );
        }
        if let Err(e) = db.peers().upsert_peer_key(
            &PeerKeyInput {
                peer_id: peer_id.clone(),
                kid: ek.clone(),
                key_use: KeyUse::Encryption,
                jwk_json: enc_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        ) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "DB_ERROR",
                format!("Failed to pin encryption JWK for '{peer_id}': {e}"),
                None,
            );
        }

        capabilities = payload_to_cache
            .capabilities
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        let manifest_json = match serde_json::to_string(signed_to_cache) {
            Ok(s) => s,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "ENCODE_ERROR", e.to_string(), None),
        };
        if let Err(e) = db.peers().cache_manifest(
            &peer_id,
            &ManifestCacheUpdate {
                manifest_version: payload_to_cache.manifest_version as i64,
                manifest_json,
                etag: v.etag.clone(),
                capabilities: capabilities.clone(),
                accept_downgrade: false,
            },
            now_db,
        ) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "MANIFEST_CACHE_ERROR",
                format!("Failed to cache verified manifest for '{peer_id}': {e}"),
                None,
            );
        }

        kid = Some(k);
        enc_kid = Some(ek);
        fingerprint = Some(fp);
        hyphae_version = Some(payload_to_cache.hyphae_version.clone());
    }

    let manifest_verified = verified_live.is_some();
    let next = vec![
        "hyp service restart".to_string(),
        format!("hyp status --state-dir {}", state_dir.display()),
        format!("hyp daemon --state-dir {}", state_dir.display()),
    ];

    let data = json!({
        "mode": "public",
        "nodeId": local_node_id,
        "peerId": peer_id,
        "endpoint": base_url,
        "profile": peer_profile.as_str(),
        "preset": effective_preset,
        "trustTier": trust_tier.as_str(),
        "scopes": effective_scopes,
        "offline": offline,
        "enrolled": enrolled,
        "manifestVerified": manifest_verified,
        "kid": kid,
        "encryptionKid": enc_kid,
        "fingerprint": fingerprint,
        "hyphaeVersion": hyphae_version,
        "capabilities": capabilities,
        "stateDir": state_dir.display().to_string(),
    });

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(if enrolled {
                format!(
                    "Joined and enrolled on '{}' ({}) with {} scopes",
                    peer_id, base_url, effective_preset
                )
            } else if manifest_verified {
                format!(
                    "Joined '{}' ({}) with verified signed manifest (preset={})",
                    peer_id, base_url, effective_preset
                )
            } else {
                format!(
                    "Pre-configured '{}' ({}) offline (preset={})",
                    peer_id, base_url, effective_preset
                )
            }),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "OK    Joined Hyphae node '{}' ({})",
            peer_id,
            if enrolled {
                "enrolled guest-ro + signed manifest verified"
            } else if manifest_verified {
                "signed manifest verified"
            } else {
                "offline pre-configured"
            }
        );
        println!("      Local Node:  {local_node_id}");
        println!("      Peer ID:     {peer_id}");
        println!("      Endpoint:    {base_url}");
        println!(
            "      Preset:      {} (tier={}, enrolled={})",
            effective_preset,
            trust_tier.as_str(),
            enrolled
        );
        if let Some(ref k) = kid {
            println!("      JWK kid:     {k}");
        }
        if let Some(ref fp) = fingerprint {
            println!("      Fingerprint: {fp}");
        }
        if let Some(ref v) = hyphae_version {
            println!("      Version:     {v}");
        }
        println!("      Scopes:      {}", effective_scopes.join(" "));
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_scope_args_preserves_bracket_and_target_commas() {
        let args = vec![
            "dm:*,files:send=25mb".to_string(),
            "stream:subscribe=github[repo=acme/a,acme/b]".to_string(),
            "dm:send=alice,bob kv:read=shared/*".to_string(),
        ];
        let tokens = tokenize_scope_args(&args);
        assert_eq!(
            tokens,
            vec![
                "dm:*",
                "files:send=25mb",
                "stream:subscribe=github[repo=acme/a,acme/b]",
                "dm:send=alice,bob",
                "kv:read=shared/*",
            ]
        );
        let expanded = expand_v2_scopes(&tokens).unwrap();
        assert!(expanded.contains(&"stream:subscribe=github[repo=acme/a,acme/b]".to_string()));
        assert!(expanded.contains(&"dm:send=alice,bob".to_string()));
        assert!(expanded.contains(&"files:send=25mb".to_string()));
    }
}
