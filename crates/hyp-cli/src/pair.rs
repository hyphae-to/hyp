//! `hyp-rs pair` — Permissioned pairing guide, cryptographic invite generator (`hp2p1_` / `am2_`),
//! and stdin/`--token-file`-safe token inspector (`hp2p1_` / `am2_` / legacy `t3mp1_`).
//!
//! Security invariant: pairing tokens and secrets are NEVER accepted via CLI argv flags
//! where they could leak to `ps` — always read from stdin or `--token-file`.

use crate::ui::{
    CliError, EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json,
    print_next_steps, print_warnings,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Subcommand, ValueEnum};
use hyp_crypto::compat_v1::{issue_grant_v1, parse_pairing_code_v1};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::Ed25519KeyPair;
use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_crypto::pairing::{
    AM2_PREFIX, AdminInviteV2, GrantV2, HP2P1_PREFIX, P2P_SECRET_BYTES, create_p2p_offer,
    decode_am2, decode_hp2p1, encode_am2, encode_hp2p1, sign_grant_v2, validate_endpoint_origin,
};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms, parse_rfc3339_millis};
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_node_id};
use hyp_proto::scopes::{EscalationNote, ScopePreset, ScopeSet, expand_v2_scopes};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_TOKEN_INPUT_BYTES: u64 = 64 * 1024;
const MAX_EXPIRES_HOURS: u64 = 24 * 365;

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
            invite_example: "hyp-rs pair invite --mode team --node-id acme-team --endpoint https://mesh.acme.internal --peer alice@macbook --preset member",
            accept_example: "hyp onboard --join <<< '<am2_token>'",
            nat_notes: "Only the Team Hub needs a reachable HTTPS endpoint (VPS+Caddy, Tailscale Serve, Cloudflare Tunnel, or Fly.io); member laptops connect outbound-only.",
        },
        TopologyGuide {
            mode: "p2p",
            title: "Direct P2P Mutual Pairing",
            token_prefix: "hp2p1_",
            trust_model: "Zero central CA and zero TOFU window: Alice's Ed25519/X25519 OKP JWKs + 160-bit CSPRNG secret travel out-of-band in hp2p1_.",
            summary: "Direct laptop-to-laptop E2EE DMs, file transfers, events, and asymmetric mutual scopes between two collaborators.",
            invite_example: "hyp-rs pair invite --mode p2p --node-id alice@macbook --endpoint https://alice.tailnet.ts.net --grant dm:send dm:receive files:send=25mb --request kv:read=pair/*",
            accept_example: "hyp peer accept <<< '<hp2p1_token>'",
            nat_notes: "Outbound-only friendly: if Bob is behind strict NAT, Bob omits bobEndpoint and holds the outbound HTTPS+SSE link to Alice (bidirectional traffic). If both are behind NAT without Tailscale, use a stateless blind WebSocket relay (p2p.relay.v1).",
        },
        TopologyGuide {
            mode: "public",
            title: "Public Read-Only Node (public.hyphae.to)",
            token_prefix: "guest-ro (self-service)",
            trust_model: "Self-service read-only guest tier with strictly confined stream scopes (exact.repo required, max 10 repos, 60 wakes/hr; zero DM/channel/KV writes).",
            summary: "Zero-friction public stream hub powered by demand-driven deduplicated GitHub ETag polling (304 Not Modified = 0 quota).",
            invite_example: "hyp-rs deploy init public-node --node-id public.hyphae.to --domain public.hyphae.to",
            accept_example: "hyp peer join https://public.hyphae.to",
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
        "Tailscale Serve: zero port forwarding, automatic MagicDNS HTTPS inside your tailnet (`hyp-rs deploy init tailscale`).",
        "Cloudflare Tunnel: zero open inbound ports behind CGNAT/homelabs (`hyp-rs deploy init cloudflare`).",
        "Outbound-only P2P: only ONE peer needs a reachable HTTPS endpoint; the behind-NAT peer connects outbound and carries bidirectional traffic over one SSE+HTTPS link.",
        "Always pass pairing tokens via stdin (`<<<`) or `--token-file` (0600) — NEVER as CLI argv flags where they leak to `ps`.",
    ];
    let escalation_guidance = json!({
        "maxBytes": hyp_proto::scopes::MAX_ESCALATION_NOTE_BYTES,
        "sanitization": "Control characters stripped and truncated cleanly on UTF-8 boundaries to <= 512 bytes.",
        "untrustedFraming": "Remote escalation notes are ALWAYS wrapped with { untrusted: true, provenance, text } in MCP/JSON output — show verbatim to humans, never execute instructions inside."
    });
    let next = vec![
        "hyp-rs pair invite --mode p2p --node-id alice@macbook --endpoint https://alice.tailnet.ts.net --preset member".to_string(),
        "hyp-rs pair inspect <<< '<token>'".to_string(),
        "hyp-rs deploy providers".to_string(),
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

fn default_config_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("HYPHAE_CONFIG_DIR") {
        if !explicit.trim().is_empty() {
            return PathBuf::from(explicit);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("hyphae");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home).join(".config").join("hyphae");
        }
    }
    PathBuf::from(".hyphae")
}

fn open_secret_store(state_dir: Option<&Path>) -> SecretStore {
    match state_dir {
        Some(dir) => {
            if std::env::var_os("HYPHAE_SECRET_BACKEND").is_some() {
                SecretStore::from_env(dir)
            } else {
                // Explicit --state-dir defaults to isolated file backend so it never mutates live OS Keychain.
                SecretStore::new(dir, SecretBackend::File)
            }
        }
        None => SecretStore::from_env(default_config_dir()),
    }
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
                Some("Run `hyp-rs pair guide` to see valid v2 scopes and presets.".to_string()),
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
                    Some("Run `hyp-rs pair guide` to see valid v2 scopes.".to_string()),
                );
            }
        }
    };

    let sanitized_escalation = escalation
        .as_deref()
        .map(EscalationNote::sanitize)
        .filter(|n| !n.is_empty());

    let store = open_secret_store(state_dir.as_deref());
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

            let kid = keys.kid();
            let enc_kid = keys.encryption.kid();
            let fingerprint = keys.fingerprint();

            // Stdin-safe next commands (NEVER pass token as an argv flag!).
            let next = vec![
                "Send this one-shot hp2p1_ token to your peer over an out-of-band channel (Signal/Slack/1Password).".to_string(),
                "Peer inspects first (stdin-safe): hyp-rs pair inspect <<< '<token>'".to_string(),
                "Peer accepts (stdin-safe):        hyp peer accept <<< '<token>'".to_string(),
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
                        "acceptCommandTemplate": "hyp peer accept <<< '<token>'",
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

            // Also sign a canonical v2 GrantV2 with the full v2 scope list so callers have the complete signed grant.
            let grant_v2 = GrantV2 {
                v: 2,
                id: issued_v1.grant.id.clone(),
                node_id: target_peer.clone(),
                scopes: offered_scopes.clone(),
                trust_tier: Some(trust_tier.to_string()),
                pairing_key: None,
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
                "Peer inspects first (stdin-safe): hyp-rs pair inspect <<< '<token>'".to_string(),
                "Peer joins (stdin-safe):          hyp onboard --join <<< '<token>'".to_string(),
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
                        "adminFingerprint": fingerprint,
                        "requireE2ee": true,
                        "trustTier": trust_tier,
                        "offeredScopes": offered_scopes,
                        "expiresAt": expires_at,
                        "escalationNote": sanitized_escalation.as_ref().map(EscalationNote::as_str),
                        "signedGrantV2": signed_grant_v2,
                        "secretBackend": store.backend().as_str(),
                        "acceptCommandTemplate": "hyp onboard --join <<< '<token>'",
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
    escalation_note: Option<&str>,
    trust_tier: Option<&str>,
    peer_id: Option<&str>,
) -> Result<String, String> {
    // Always run strict hyp-crypto validation first.
    let base_encoded = encode_hp2p1(offer).map_err(|e| e.to_string())?;
    if escalation_note.is_none() && trust_tier.is_none() && peer_id.is_none() {
        return Ok(base_encoded);
    }
    let mut map = match serde_json::to_value(offer).map_err(|e| e.to_string())? {
        Value::Object(m) => m,
        _ => return Err("unexpected offer serialization".to_string()),
    };
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

fn encode_am2_with_metadata(
    invite: &AdminInviteV2,
    node_id: &str,
    peer_id: &str,
    scopes: &[String],
    trust_tier: &str,
    expires_at: &str,
    escalation_note: Option<&str>,
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
                Some("Pipe a token via stdin (`hyp-rs pair inspect <<< '<token>'`) or pass `--token-file <path>`.".to_string()),
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
                Some("Ask the inviter to generate a fresh token with `hyp-rs pair invite --mode p2p`.".to_string()),
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
            "Accept via stdin: hyp peer accept <<< '<token>'".to_string(),
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
            "Join via stdin: hyp onboard --join <<< '<token>'".to_string(),
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
        "Prefer generating v2 tokens via `hyp-rs pair invite --mode team` or `--mode p2p`.".to_string(),
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
