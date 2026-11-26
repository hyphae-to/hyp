//! `hyp pair` — Permissioned pairing guide, cryptographic invite generator (`hp2p1_` / `am2_`),
//! stdin/`--token-file`-safe token inspector & acceptor (`accept`), and public/team node `join`.
//!
//! Security invariant: pairing tokens and secrets are NEVER accepted via CLI argv flags
//! where they could leak to `ps` — always read from stdin or `--token-file`.

use crate::config_file::{
    ensure_dir, load_node_or_legacy_config, resolve_config_path_for_read,
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
use http_body_util::BodyExt;
use hyp_crypto::compat_v1::{
    PairingCodeV1, derive_pairing_key_v1, issue_grant_v1, parse_pairing_code_v1,
};
use hyp_crypto::human::{
    DelegatedPairProofV1, SignedNodeCertV1, encode_hcert1, node_cert_sha256,
    sign_delegated_pair_proof,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::{
    Ed25519KeyPair, Ed25519PublicKey, NodeIdentityKeys, OkpJwk as CryptoOkpJwk, SignedPayload,
    X25519PublicKey,
};
use hyp_crypto::keystore::SecretStore;
use hyp_crypto::pairing::{
    AM2_PREFIX, AdminInviteV2, GrantV2, HP2P1_PREFIX, P2P_SECRET_BYTES, P2pOfferToken,
    P2pPairConfirmation, P2pPairResponse, SshEndpoint, create_p2p_offer, create_p2p_response,
    decode_am2, decode_hp2p1, encode_am2, encode_hp2p1, parse_ssh_endpoint, sign_grant_v2,
    validate_endpoint_origin, validate_http_endpoint_origin, validate_ssh_posix_path,
    verify_grant_v2, verify_p2p_confirmation,
};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms, parse_rfc3339_millis};
use hyp_node::engine::http_util::{
    HttpClient, empty_body, full_body, percent_encode, resolve_ssh_binary,
};
use hyp_node::engine::peer_link::{PairBindingV2, PairRequestV2};
use hyp_node::engine::{
    DelegatedPairReply, DelegatedPairRequest, GuestPairReply, GuestPairRequest, P2pPairServerReply,
    PairServerReply, guest_pair_proof_canonical, p2p_offer_secret_name,
};
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_node_id};
use hyp_proto::manifest::{
    NodeManifestPayload, NodeProfile as ProtoNodeProfile, SignedNodeManifest,
};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::{
    EscalationNote, ScopePreset, ScopeSet, V2_STAR_EXPANSION, expand_v2_scopes,
};
use hyp_store::{
    GrantDirection, GrantInput, KeyStatus, KeyUse, ManifestCacheUpdate, NodeDb, PeerInput,
    PeerKeyInput, PeerProfile, PeerStatus, RevocationInput, StoreError,
    TrustTier as StoreTrustTier, now_ms,
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
const TAILSCALE_DETECT_TIMEOUT_SECS: u64 = 2;
const MAX_TAILSCALE_STATUS_BYTES: u64 = 1024 * 1024;
const LIVE_DAEMON_RELOAD_TIMEOUT: Duration = Duration::from_millis(1_800);

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
        /// Inviting node's endpoint (`https://...`, `ssh://[user@]host[:port]`, or loopback `http://127.0.0.1:...`; auto-detected from Tailscale MagicDNS for --mode p2p if omitted)
        #[arg(long)]
        endpoint: Option<String>,
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
        /// Allow --node-id to differ from local node.json nodeId when minting a P2P invite
        #[arg(long)]
        force_node_id: bool,
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
        /// Target node URL (https://, ssh://[user@]host[:port], or loopback http://127.0.0.1 for local testing)
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
    /// One-command mutual P2P pairing over SSH (`ssh://<target>` via `hyp connect` / `peer.sock`)
    Ssh {
        /// SSH target (`[user@]host[:port]` or `ssh://[user@]host[:port][?stateDir=...&bin=...]`)
        target: String,
        /// Built-in scope preset (guest-ro, guest, observer, member, full; default: member)
        #[arg(long, value_enum)]
        preset: Option<CliScopePreset>,
        /// Explicit scopes to grant to the remote peer (repeatable or space-delimited)
        #[arg(long, num_args = 1..)]
        grant: Vec<String>,
        /// Explicit scopes to request from the remote peer in return (defaults to --preset / --grant)
        #[arg(long, num_args = 1..)]
        request: Vec<String>,
        /// Local state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Local nodeId override (e.g. alice@macbook)
        #[arg(long)]
        node_id: Option<String>,
        /// Expected remote peer nodeId override (auto-discovered from remote /v1/manifest when omitted)
        #[arg(long)]
        remote_node_id: Option<String>,
        /// Optional remote Hyphae state directory passed to remote `hyp` (`--state-dir`)
        #[arg(long)]
        remote_state_dir: Option<String>,
        /// Optional remote `hyp` binary path override
        #[arg(long)]
        remote_bin: Option<String>,
        /// Validate target/scopes and preview planned SSH pairing without executing remote commands
        #[arg(long)]
        dry_run: bool,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Revoke a paired peer, clear stored bearer credentials, and immediately drop its live link
    Revoke {
        /// Canonical peer nodeId to revoke (e.g. bob@laptop, acme-team)
        peer_id: String,
        /// Optional human-readable revocation reason recorded in the revocation log
        #[arg(long)]
        reason: Option<String>,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Explicit daemon IPC socket/addr path for live peers.reload
        #[arg(long)]
        socket: Option<PathBuf>,
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
            force_node_id,
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
            force_node_id,
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
        PairCommand::Ssh {
            target,
            preset,
            grant,
            request,
            state_dir,
            node_id,
            remote_node_id,
            remote_state_dir,
            remote_bin,
            dry_run,
            json,
        } => run_pair_ssh(
            target,
            preset,
            grant,
            request,
            state_dir,
            node_id,
            remote_node_id,
            remote_state_dir,
            remote_bin,
            dry_run,
            json,
        ),
        PairCommand::Revoke {
            peer_id,
            reason,
            state_dir,
            config,
            socket,
            json,
        } => run_revoke(peer_id, reason, state_dir, config, socket, json),
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransportGuide {
    id: &'static str,
    title: &'static str,
    best_for: &'static str,
    endpoint_format: &'static str,
    example: &'static str,
    notes: &'static str,
}

fn build_transports() -> Vec<TransportGuide> {
    vec![
        TransportGuide {
            id: "tailscale",
            title: "Tailscale Serve HTTPS (Recommended for Team Hubs & Tailnets)",
            best_for: "Private team hubs, personal laptops, and zero-port-forwarding MagicDNS meshes.",
            endpoint_format: "https://<host>.<tailnet>.ts.net",
            example: "hyp deploy init tailscale --node-id acme-team --domain hyphae.your-tailnet.ts.net --out ./deploy-tailscale",
            notes: "Automatic Let's Encrypt HTTPS certificates over WireGuard; verified automatically by `hyp status` and `hyp doctor`.",
        },
        TransportGuide {
            id: "https",
            title: "Public HTTPS / Reverse Proxy",
            best_for: "Internet-facing Team Hubs, Public Nodes, VPS+Caddy, Docker Compose, Cloudflare Tunnel, or Fly.io.",
            endpoint_format: "https://<domain>",
            example: "hyp deploy init vps --node-id acme-team --domain mesh.example.com --out ./deploy-vps",
            notes: "Standard HTTPS termination with `flush_interval -1` for zero-buffering SSE; laptops connect outbound-only.",
        },
        TransportGuide {
            id: "ssh",
            title: "Optional SSH (`ssh://`, Zero Open Ports)",
            best_for: "Personal servers, bastions, air-gapped VPCs, and hosts already reachable via `~/.ssh/config`.",
            endpoint_format: "ssh://[user@]host[:port][?stateDir=/path&bin=/path/to/hyp]",
            example: "hyp pair ssh ops@solace   # or: hyp pair invite --mode p2p --node-id solace --endpoint ssh://ops@solace",
            notes: "Tunnels Hyphae v2 HTTP/1.1 + SSE over `ssh -o BatchMode=yes -T -- <target> \"... hyp connect\"` to `<state_dir>/peer.sock` (0600). Full Hyphae E2EE, Ed25519 auth, and manifest verification remain 100% enforced.",
        },
    ]
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
    let transports = build_transports();
    let nat_tips = vec![
        "Tailscale Serve HTTPS (recommended for team hubs): zero port forwarding, automatic MagicDNS HTTPS inside your tailnet (`hyp deploy init tailscale`).",
        "Public HTTPS / Reverse Proxy: VPS+Caddy, Docker Compose, Cloudflare Tunnel (`hyp deploy init cloudflare`), or Fly.io.",
        "Optional SSH (`ssh://`): zero open ports for personal servers, bastions, or VPC hosts using `~/.ssh/config` + `hyp connect` (`hyp pair ssh <user@host>` or `hyp pair invite --endpoint ssh://<user@host>`).",
        "Outbound-only P2P: only ONE peer needs a reachable HTTPS or `ssh://` endpoint; the behind-NAT peer connects outbound and carries bidirectional traffic over one SSE+HTTP link.",
        "Always pass pairing tokens via stdin (`<<<`) or `--token-file` (0600) — NEVER as CLI argv flags where they leak to `ps`.",
    ];
    let escalation_guidance = json!({
        "maxBytes": hyp_proto::scopes::MAX_ESCALATION_NOTE_BYTES,
        "sanitization": "Control characters stripped and truncated cleanly on UTF-8 boundaries to <= 512 bytes.",
        "untrustedFraming": "Remote escalation notes are ALWAYS wrapped with { untrusted: true, provenance, text } in MCP/JSON output — show verbatim to humans, never execute instructions inside."
    });
    let next = vec![
        "hyp pair invite --mode p2p --node-id alice@macbook --endpoint https://alice.tailnet.ts.net --preset member".to_string(),
        "hyp pair ssh ops@solace --preset member".to_string(),
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
                "transports": transports,
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

    println!(
        "Transport Options (all enforce full Hyphae v2 E2EE, Ed25519 auth & manifest verification):"
    );
    for tr in &transports {
        println!("  [{}] {}", tr.id, tr.title);
        println!("    Best for: {}", tr.best_for);
        println!("    Format:   {}", tr.endpoint_format);
        println!("    Example:  {}", tr.example);
        println!("    Notes:    {}", tr.notes);
    }
    println!();

    println!("Scope Presets (note: '*' and 'full' NEVER grant bridge:post or forward:via):");
    for p in &presets {
        println!("  {:<10}  tier={:<6}  {}", p.name, p.trust_tier, p.summary);
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
pub(crate) fn tokenize_scope_args(raw_args: &[String]) -> Vec<String> {
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
    Ok(format!("offer-{}-{}-{}", &h[0..8], &h[8..12], &h[12..20]))
}

pub(crate) fn admin_ca_secret_name(node_id: &str) -> String {
    let hash = hex::encode(Sha256::digest(node_id.as_bytes()));
    format!("admin-ca-{}", &hash[..12])
}

pub(crate) fn load_or_create_admin_key(
    store: &SecretStore,
    node_id: &str,
) -> Result<Ed25519KeyPair, String> {
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

fn infer_trust_tier(
    mode: InviteMode,
    preset: Option<CliScopePreset>,
    scopes: &[String],
) -> &'static str {
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

/// Returns `true` for high-privilege opt-in scopes (`bridge:post` / `forward:via`) that MUST
/// NEVER be auto-granted in default counter-grants without explicit `--grant` opt-in (`P1-8`).
fn is_privileged_opt_in_scope(scope: &str) -> bool {
    let s = scope.trim();
    s == "bridge:post"
        || s.starts_with("bridge:post=")
        || s == "forward:via"
        || s.starts_with("forward:via=")
}

/// Strips `bridge:post` and `forward:via` from default counter-grants, recording a clear warning
/// whenever any privileged scope was removed (`P1-8`).
fn strip_privileged_default_scopes(scopes: Vec<String>, warnings: &mut Vec<String>) -> Vec<String> {
    let mut safe = Vec::with_capacity(scopes.len());
    let mut stripped = Vec::new();
    for s in scopes {
        if is_privileged_opt_in_scope(&s) {
            stripped.push(s);
        } else {
            safe.push(s);
        }
    }
    if !stripped.is_empty() {
        warnings.push(format!(
            "Stripped privileged opt-in scope(s) from default counter-grant ({}); pass --grant explicitly to opt in.",
            stripped.join(", ")
        ));
    }
    if safe.is_empty() {
        safe = vec!["dm:send".to_string(), "dm:receive".to_string()];
    }
    safe
}

/// Emits explicit security warnings in `hyp pair inspect` when a token offers or requests `*`,
/// `bridge:post`, or `forward:via` (`P1-8`).
fn warn_privileged_token_scopes(label: &str, scopes: &[String], warnings: &mut Vec<String>) {
    let has_literal_star = scopes.iter().any(|s| s.trim() == "*");
    let has_full_star_expansion = !scopes.is_empty()
        && V2_STAR_EXPANSION
            .iter()
            .all(|star_tok| scopes.iter().any(|s| s.trim() == *star_tok));
    if has_literal_star || has_full_star_expansion {
        warnings.push(format!(
            "Token {label} wildcard '*' (full standard permissions across DMs, channels, streams, files, and KV); review carefully before accepting."
        ));
    }
    let bridge_scopes: Vec<&str> = scopes
        .iter()
        .map(String::as_str)
        .filter(|s| {
            let t = s.trim();
            t == "bridge:post" || t.starts_with("bridge:post=")
        })
        .collect();
    if !bridge_scopes.is_empty() {
        warnings.push(format!(
            "Token {label} privileged scope 'bridge:post' ({}) — allows posting to external chat bridges (stripped by default unless explicitly opted in via --grant).",
            bridge_scopes.join(", ")
        ));
    }
    let forward_scopes: Vec<&str> = scopes
        .iter()
        .map(String::as_str)
        .filter(|s| {
            let t = s.trim();
            t == "forward:via" || t.starts_with("forward:via=")
        })
        .collect();
    if !forward_scopes.is_empty() {
        warnings.push(format!(
            "Token {label} privileged scope 'forward:via' ({}) — allows multi-hop transit forwarding (stripped by default unless explicitly opted in via --grant).",
            forward_scopes.join(", ")
        ));
    }
}

/// Pure parser for `tailscale status --json` output -> `https://<magicdns_host>`.
///
/// Fails closed (returns `None`) unless:
/// - JSON is valid and `BackendState == "Running"`
/// - `Self.Online` is not explicitly `false`
/// - `Self.DNSName` (with at most one trailing FQDN `.` trimmed) is a strict multi-label
///   ASCII DNS hostname (`<= 253` chars, labels `1..=63` `[A-Za-z0-9-]`, no leading/trailing `-`,
///   non-numeric TLD) that passes [`validate_endpoint_origin`].
pub(crate) fn parse_tailscale_magicdns_endpoint(json_bytes: &[u8]) -> Option<String> {
    let parsed: Value = serde_json::from_slice(json_bytes).ok()?;
    let root = parsed.as_object()?;
    if root.get("BackendState").and_then(Value::as_str) != Some("Running") {
        return None;
    }
    let self_obj = root.get("Self").and_then(Value::as_object)?;
    if self_obj.get("Online").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    let raw_dns = self_obj.get("DNSName").and_then(Value::as_str)?;
    if raw_dns.is_empty() || raw_dns.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let host_raw = raw_dns.strip_suffix('.').unwrap_or(raw_dns);
    if host_raw.is_empty() || host_raw.len() > 253 || !host_raw.contains('.') {
        return None;
    }
    let mut last_label = "";
    for label in host_raw.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
        last_label = label;
    }
    // Reject all-numeric IPv4 literals (MagicDNS DNSName must have an alphabetic TLD).
    if !last_label.bytes().any(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let candidate = format!("https://{}", host_raw.to_ascii_lowercase());
    validate_http_endpoint_origin(&candidate).ok()?;
    Some(candidate)
}

fn detect_tailscale_magicdns_endpoint_with_bin(bin: &str, timeout: Duration) -> Option<String> {
    let bin_trimmed = bin.trim();
    if bin_trimmed.is_empty()
        || bin_trimmed.eq_ignore_ascii_case("none")
        || bin_trimmed.eq_ignore_ascii_case("disabled")
    {
        return None;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async {
        use tokio::io::AsyncReadExt;
        use tokio::process::Command;

        let mut cmd = Command::new(bin_trimmed);
        cmd.args(["status", "--json"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd.spawn().ok()?;
        let mut stdout = child.stdout.take()?;

        let outcome = tokio::time::timeout(timeout, async {
            let mut buf = Vec::new();
            let mut limited = (&mut stdout).take(MAX_TAILSCALE_STATUS_BYTES + 1);
            limited.read_to_end(&mut buf).await.ok()?;
            if buf.len() as u64 > MAX_TAILSCALE_STATUS_BYTES {
                let _ = child.kill().await;
                return None;
            }
            let status = child.wait().await.ok()?;
            if !status.success() {
                return None;
            }
            parse_tailscale_magicdns_endpoint(&buf)
        })
        .await;

        match outcome {
            Ok(endpoint) => endpoint,
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                None
            }
        }
    })
}

fn detect_tailscale_magicdns_endpoint() -> Option<String> {
    if let Ok(explicit) = std::env::var("HYPHAE_TAILSCALE_BIN") {
        return detect_tailscale_magicdns_endpoint_with_bin(
            &explicit,
            Duration::from_secs(TAILSCALE_DETECT_TIMEOUT_SECS),
        );
    }
    if let Some(ep) = detect_tailscale_magicdns_endpoint_with_bin(
        "tailscale",
        Duration::from_secs(TAILSCALE_DETECT_TIMEOUT_SECS),
    ) {
        return Some(ep);
    }
    #[cfg(target_os = "macos")]
    {
        let mac_bin = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";
        if Path::new(mac_bin).is_file() {
            return detect_tailscale_magicdns_endpoint_with_bin(
                mac_bin,
                Duration::from_secs(TAILSCALE_DETECT_TIMEOUT_SECS),
            );
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn run_invite(
    mode: InviteMode,
    node_id: String,
    endpoint_arg: Option<String>,
    peer: Option<String>,
    preset: Option<CliScopePreset>,
    grant: Vec<String>,
    request: Vec<String>,
    expires_hours: u64,
    escalation: Option<String>,
    state_dir: Option<PathBuf>,
    force_node_id: bool,
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

    let (endpoint, endpoint_auto_detected) = match endpoint_arg {
        Some(ep) => (ep, false),
        None => match mode {
            InviteMode::P2p => match detect_tailscale_magicdns_endpoint() {
                Some(ts_ep) => (ts_ep, true),
                None => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_USAGE,
                        "MISSING_ENDPOINT",
                        "Missing --endpoint and could not auto-detect an active Tailscale MagicDNS endpoint.",
                        Some(
                            "Pass --endpoint <https://...> (e.g. --endpoint https://alice.tailnet.ts.net or http://127.0.0.1:8790 for local testing), or start Tailscale with MagicDNS enabled."
                                .to_string(),
                        ),
                    );
                }
            },
            InviteMode::Team => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "MISSING_ENDPOINT",
                    "Missing required --endpoint for --mode team.",
                    Some(
                        "Pass --endpoint <https://...> (e.g. --endpoint https://mesh.acme.internal or http://127.0.0.1:8790 for local testing)."
                            .to_string(),
                    ),
                );
            }
        },
    };

    if let Err(e) = validate_endpoint_origin(&endpoint) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_ENDPOINT",
            format!("Invalid --endpoint '{endpoint}': {e}"),
            Some(
                "Use https://, ssh://[user@]host[:port], or loopback http://127.0.0.1 for local testing."
                    .to_string(),
            ),
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
            // P1-14: Guard against minting a P2P invite under a mismatched --node-id when a local
            // node.json already declares a different nodeId (fail closed unless --force-node-id).
            let local_cfg_path =
                resolve_config_path_for_read(None, Some(&effective_state_dir), None);
            if local_cfg_path.exists() {
                if let Ok(loaded) = load_node_or_legacy_config(&local_cfg_path) {
                    if let Some(configured_node_id) = loaded.node_id.as_deref() {
                        if configured_node_id != node_id {
                            if !force_node_id {
                                return emit_error(
                                    cmd,
                                    as_json,
                                    EXIT_USAGE,
                                    "NODE_ID_MISMATCH",
                                    format!(
                                        "--node-id '{node_id}' does not match local node.json nodeId '{configured_node_id}' ({})",
                                        local_cfg_path.display()
                                    ),
                                    Some(format!(
                                        "Use --node-id {configured_node_id} to match your local node, or pass --force-node-id to override intentionally."
                                    )),
                                );
                            }
                            warnings.push(format!(
                                "Overriding local node.json nodeId '{configured_node_id}' with --node-id '{node_id}' (--force-node-id)."
                            ));
                        }
                    }
                }
            }

            let keys = match store.load_or_create_node_keys(&node_id) {
                Ok(k) => k,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "KEYSTORE_ERROR",
                        format!("Failed to load/create node identity keys: {e}"),
                        Some(
                            "Check permissions on --state-dir or HYPHAE_SECRET_BACKEND."
                                .to_string(),
                        ),
                    );
                }
            };
            let offer_id = match generate_offer_id() {
                Ok(id) => id,
                Err(e) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "RNG_ERROR", e, None);
                }
            };

            let mut offer = match create_p2p_offer(
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
            offer.peer_id = peer.clone();

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
            let sentinel_json = match serde_json::to_string(&json!({
                "offerId": offer_id,
                "peerId": peer,
            })) {
                Ok(s) => s,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "ENCODE_ERROR",
                        e.to_string(),
                        None,
                    );
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
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "ENCODE_ERROR",
                        e.to_string(),
                        None,
                    );
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
                        "endpointAutoDetected": endpoint_auto_detected,
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
                if endpoint_auto_detected {
                    println!(
                        "      Endpoint:    {endpoint} (auto-detected via Tailscale MagicDNS)"
                    );
                } else {
                    println!("      Endpoint:    {endpoint}");
                }
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
                print_warnings(&warnings);
                print_next_steps(&next);
            }
            ExitCode::from(EXIT_OK)
        }
        InviteMode::Team => {
            let target_peer = match peer {
                Some(p) => p,
                None => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_USAGE,
                        "MISSING_PEER",
                        "Missing required --peer <user@host> for --mode team (Org Admin-CA grants are bound to an exact peer nodeId).",
                        Some(format!(
                            "Pass the invited teammate's nodeId, e.g.: hyp pair invite --mode team --node-id {node_id} --endpoint {endpoint} --peer alice@laptop --preset member"
                        )),
                    );
                }
            };

            let admin_key = match load_or_create_admin_key(&store, &node_id) {
                Ok(k) => k,
                Err(e) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "KEYSTORE_ERROR", e, None);
                }
            };

            let v1_scopes = project_v2_to_v1_scopes(&offered_scopes);
            let issued_v1 =
                match issue_grant_v1(&admin_key, &target_peer, &v1_scopes, ttl_ms, now_ms) {
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

            // Sign a canonical v2 GrantV2 carrying the one-time `pairingKey` and full v2 scopes
            // and embed it inside the `am2_` bundle (`signedGrantV2`) so `hyp pair accept` can
            // submit it inline to `POST /v1/pair` — enabling 100% offline Admin-CA minting with
            // ZERO Admin-CA private key or pre-inserted grant row required on the Team Hub!
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
                expires_at: None,
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

            // Only mirror the grant into local `node.sqlite` when this state-dir actually hosts a
            // local router/hub (best-effort, non-fatal when running offline on an admin laptop!).
            let local_cfg_path =
                resolve_config_path_for_read(None, Some(&effective_state_dir), None);
            let is_local_router_hub = local_cfg_path.exists()
                && load_node_or_legacy_config(&local_cfg_path)
                    .ok()
                    .and_then(|c| c.profile)
                    == Some(ProtoNodeProfile::Router);
            if is_local_router_hub {
                let db_path = effective_state_dir.join("node.sqlite");
                match (
                    NodeDb::open(&db_path),
                    serde_json::to_string(&signed_grant_v2),
                ) {
                    (Ok(db), Ok(signed_grant_json)) => {
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
                            warnings.push(format!(
                                "Best-effort local hub DB grant mirror skipped ({e}); am2_ bundle still carries signedGrantV2 for offline Admin-CA pairing."
                            ));
                        }
                    }
                    (Err(e), _) => {
                        warnings.push(format!(
                            "Could not open local hub DB {} ({e}); am2_ bundle still carries signedGrantV2 for offline Admin-CA pairing.",
                            db_path.display()
                        ));
                    }
                    (_, Err(e)) => {
                        warnings.push(format!(
                            "Could not serialize grant for local hub DB ({e}); am2_ bundle still carries signedGrantV2."
                        ));
                    }
                }
            }

            let admin_jwk = admin_key.to_jwk();
            let admin_pubkey = admin_jwk.x.clone();
            let admin_jwk_compact = serde_json::to_string(&admin_jwk).unwrap_or_default();
            let hub_provision_hint =
                format!("printf '%s' '{admin_pubkey}' | hyp secret set hyphae-admin-pubkey");

            let invite = AdminInviteV2 {
                v: 2,
                router: endpoint.clone(),
                admin_jwk: admin_jwk.clone(),
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
                format!(
                    "Provision the hub once with the Admin-CA public key (keep private key offline on admin machine): {hub_provision_hint}"
                ),
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
                        "endpointAutoDetected": endpoint_auto_detected,
                        "kid": kid,
                        "adminJwk": admin_jwk,
                        "adminPubkey": admin_pubkey,
                        "adminFingerprint": fingerprint,
                        "hubAdminKeyCommand": hub_provision_hint,
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
                println!("      Node ID:      {node_id}");
                println!("      Target Peer:  {target_peer}");
                if endpoint_auto_detected {
                    println!(
                        "      Endpoint:     {endpoint} (auto-detected via Tailscale MagicDNS)"
                    );
                } else {
                    println!("      Endpoint:     {endpoint}");
                }
                println!("      Grant ID:     {}", issued_v1.grant.id);
                println!("      Admin kid:    {kid}");
                println!("      Fingerprint:  {fingerprint}");
                println!("      Admin Pubkey: {admin_pubkey}");
                println!("      Admin JWK:    {admin_jwk_compact}");
                println!("      Trust Tier:   {trust_tier}");
                println!("      Expires At:   {expires_at}");
                println!("      Scopes:       {}", offered_scopes.join(" "));
                if let Some(ref note) = sanitized_escalation {
                    println!("      Escalation:   {}", note.as_str());
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
        map.insert(
            "escalationNote".to_string(),
            Value::String(note.to_string()),
        );
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
    map.insert(
        "trustTier".to_string(),
        Value::String(trust_tier.to_string()),
    );
    map.insert(
        "expiresAt".to_string(),
        Value::String(expires_at.to_string()),
    );
    map.insert(
        "signedGrantV2".to_string(),
        serde_json::to_value(signed_grant_v2).map_err(|e| e.to_string())?,
    );
    if let Some(note) = escalation_note {
        map.insert(
            "escalationNote".to_string(),
            Value::String(note.to_string()),
        );
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
fn read_bounded_token(
    token_file: Option<&Path>,
    warnings: &mut Vec<String>,
) -> Result<String, (u8, &'static str, String)> {
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
                Some(
                    "Ask the inviter to generate a fresh token with `hyp pair invite --mode p2p`."
                        .to_string(),
                ),
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
    warn_privileged_token_scopes("requests", &offer.requested_scopes, &mut warnings);
    warn_privileged_token_scopes("offers", &offer.offered_scopes, &mut warnings);

    let ok = !expired;
    let next = if ok {
        vec![
            format!(
                "Verify JWK kid '{kid}' out-of-band with '{}'.",
                offer.node_id
            ),
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
                message: format!(
                    "P2P pairing offer '{}' expired at {}",
                    offer.offer_id, offer.expires_at
                ),
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
                Some(
                    "Ask your organization administrator for a fresh am2_ invite bundle."
                        .to_string(),
                ),
            );
        }
    };
    let node_id = raw_map
        .as_ref()
        .and_then(|m| m.get("nodeId"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let peer_id = verified_grant_pair
        .as_ref()
        .map(|(_, g)| g.node_id.clone())
        .or_else(|| {
            raw_map
                .as_ref()
                .and_then(|m| m.get("peerId"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let scopes: Vec<String> = verified_grant_pair
        .as_ref()
        .map(|(_, g)| g.scopes.clone())
        .unwrap_or_else(|| {
            raw_map
                .as_ref()
                .and_then(|m| m.get("scopes"))
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        });
    // P1-9: derive trust tier strictly from the Admin-CA-signed grant (never unsigned raw_map or "self").
    let trust_tier = verified_grant_pair
        .as_ref()
        .and_then(|(_, g)| g.trust_tier.as_deref())
        .map(|t| parse_store_trust_tier(t, StoreTrustTier::Org).as_str())
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
    warn_privileged_token_scopes("grants", &scopes, &mut warnings);

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
        println!("      RequireE2EE: {}", invite.require_e2ee.unwrap_or(true));
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
        "Prefer generating v2 tokens via `hyp pair invite --mode team` or `--mode p2p`."
            .to_string(),
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
            summary: Some(format!(
                "Inspected legacy v1 t3mp1_ code (grant {})",
                parsed.grant_id
            )),
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
    // P1-9: NEVER map remote/token input `"self"` to `StoreTrustTier::SelfNode`.
    match raw.trim().to_ascii_lowercase().as_str() {
        "org" => StoreTrustTier::Org,
        "peer" => StoreTrustTier::Peer,
        "guest" => StoreTrustTier::Guest,
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

pub(crate) fn credential_secret_name(prefix: &str, peer_id: &str) -> String {
    let hash = hex::encode(Sha256::digest(peer_id.as_bytes()));
    format!("{prefix}-{}", &hash[..12])
}

fn derive_peer_id_from_url(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    if trimmed.starts_with("ssh://") {
        let ep = parse_ssh_endpoint(trimmed).map_err(|e| e.to_string())?;
        let host = ep.host.to_ascii_lowercase();
        if host == LOCAL_NODE_ID || !is_valid_node_id(&host) {
            return Err(format!(
                "derived SSH host '{host}' from '{url}' is not a valid nodeId; pass --node-name <node-id>"
            ));
        }
        return Ok(host);
    }
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

fn normalize_endpoint_for_pin(endpoint: &str) -> String {
    endpoint.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Fail-closed pin guard (`N2`): refuses re-pointing an existing non-revoked peer to a different
/// `PeerProfile` (e.g. `Router` -> `P2p`) or a different `endpoint`.
///
/// Prevents crafted `hp2p1_` / `am2_` tokens (especially under `--offline`) from hijacking an
/// already-paired hub or peer's profile/endpoint by reusing its public key.
fn check_existing_peer_pin(
    db: &NodeDb,
    peer_id: &str,
    expected_profile: PeerProfile,
    expected_endpoint: &str,
) -> Result<(), (&'static str, String)> {
    let existing = db.peers().get_peer(peer_id).map_err(|e| {
        (
            "DB_ERROR",
            format!("Failed to query existing peer '{peer_id}': {e}"),
        )
    })?;
    let Some(peer) = existing else {
        return Ok(());
    };
    if peer.status == PeerStatus::Revoked {
        return Ok(());
    }
    if peer.profile != expected_profile {
        return Err((
            "PEER_PROFILE_CONFLICT",
            format!(
                "Peer '{peer_id}' is already paired with profile '{}' and cannot be changed to '{}' without revoking it first (`hyp pair revoke {peer_id}`).",
                peer.profile.as_str(),
                expected_profile.as_str()
            ),
        ));
    }
    if let Some(ref existing_ep) = peer.endpoint {
        if normalize_endpoint_for_pin(existing_ep) != normalize_endpoint_for_pin(expected_endpoint)
        {
            return Err((
                "PEER_ENDPOINT_CONFLICT",
                format!(
                    "Peer '{peer_id}' is already pinned to endpoint '{existing_ep}' and cannot be re-pointed to '{expected_endpoint}' without revoking it first (`hyp pair revoke {peer_id}`)."
                ),
            ));
        }
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
            "Pairing reply manifest payload is not canonical RFC 8785 JCS (fail-closed)"
                .to_string(),
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
            format!(
                "Invalid expiresAt '{}' in pairing manifest: {e}",
                payload.expires_at
            ),
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

fn post_json_handshake(
    base_endpoint: &str,
    path: &str,
    body_bytes: Vec<u8>,
) -> Result<(u16, Vec<u8>), LiveHandshakeError> {
    let display_url = format!("{}{path}", base_endpoint.trim_end_matches('/'));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "RUNTIME_ERROR",
            message: format!("Failed to start async runtime: {e}"),
        })?;

    rt.block_on(async {
        let client = HttpClient::new().map_err(|e| LiveHandshakeError::Rejected {
            code: "HTTP_ERROR",
            message: format!("Failed to initialize HTTP client: {e}"),
        })?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(full_body(Bytes::from(body_bytes)))
            .map_err(|e| LiveHandshakeError::Rejected {
                code: "HTTP_ERROR",
                message: format!("Failed to build pairing HTTP request: {e}"),
            })?;

        let outcome = async {
            let resp = tokio::time::timeout(
                Duration::from_secs(PAIR_HTTP_TIMEOUT_SECS),
                client.request_for_endpoint(base_endpoint, req),
            )
            .await
            .map_err(|_| {
                LiveHandshakeError::Unreachable(format!(
                    "POST {display_url} timed out after {PAIR_HTTP_TIMEOUT_SECS}s"
                ))
            })?
            .map_err(|e| LiveHandshakeError::Unreachable(format!("POST {display_url} failed: {e}")))?;

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
        }
        .await;

        client.shutdown_ssh();
        outcome
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
    let snippet: String = String::from_utf8_lossy(body_bytes)
        .chars()
        .take(200)
        .collect();
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
    let resp_body: P2pPairResponse =
        create_p2p_response(offer, local_node_id, local_endpoint, local_keys, &bob_grant).map_err(
            |e| LiveHandshakeError::Rejected {
                code: "OFFER_ERROR",
                message: format!("Failed to construct P2P pairing response: {e}"),
            },
        )?;
    let req_bytes = serde_json::to_vec(&resp_body).map_err(|e| LiveHandshakeError::Rejected {
        code: "ENCODE_ERROR",
        message: format!("Failed to serialize P2P pairing response: {e}"),
    })?;

    let path = format!("/v1/p2p/pair/{}", percent_encode(&offer.offer_id));
    let url = format!("{}{path}", offer.endpoint.trim_end_matches('/'));
    let (status, body_bytes) = post_json_handshake(&offer.endpoint, &path, req_bytes)?;
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
    let alice_grant_verified = verify_p2p_confirmation(offer, &confirmation, local_node_id)
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "INVALID_SIGNATURE",
            message: format!(
                "Peer P2P confirmation failed zero-TOFU verification against out-of-band JWK: {e}"
            ),
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

#[allow(clippy::too_many_arguments)]
fn execute_live_am2_handshake(
    invite: &AdminInviteV2,
    parsed_v1: &PairingCodeV1,
    admin_pk: &Ed25519PublicKey,
    expected_hub_id: Option<&str>,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
    inline_signed_grant: Option<&SignedPayload>,
) -> Result<LiveAm2HandshakeResult, LiveHandshakeError> {
    let pair_kp = derive_pairing_key_v1(&parsed_v1.secret, &parsed_v1.grant_id).map_err(|e| {
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
    let mut req_val =
        serde_json::to_value(&pair_req).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: format!("Failed to serialize PairRequestV2: {e}"),
        })?;
    if let Some(sg) = inline_signed_grant {
        if let Some(obj) = req_val.as_object_mut() {
            let sg_val = serde_json::to_value(sg).map_err(|e| LiveHandshakeError::Rejected {
                code: "ENCODE_ERROR",
                message: format!("Failed to serialize inline signedGrant: {e}"),
            })?;
            obj.insert("signedGrant".to_string(), sg_val);
        }
    }
    let req_bytes = serde_json::to_vec(&req_val).map_err(|e| LiveHandshakeError::Rejected {
        code: "ENCODE_ERROR",
        message: format!("Failed to serialize PairRequestV2: {e}"),
    })?;

    let url = format!("{}/v1/pair", invite.router.trim_end_matches('/'));
    let (status, body_bytes) = post_json_handshake(&invite.router, "/v1/pair", req_bytes)?;
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
            message: format!(
                "Hub returned invalid nodeId '{}' in /v1/pair reply",
                reply.node_id
            ),
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

    let verified_grant =
        verify_grant_v2(&reply.grant, admin_pk).map_err(|e| LiveHandshakeError::Rejected {
            code: "INVALID_SIGNATURE",
            message: format!(
                "Hub /v1/pair returned grant that failed Admin-CA signature verification: {e}"
            ),
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

    let (manifest_payload, hub_signing_pk, hub_encryption_pk) =
        verify_signed_manifest_strict(&reply.signed_manifest, Some(&reply.node_id), None, None)
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

pub(crate) struct DaemonReloadOutcome {
    pub(crate) reloaded: bool,
    pub(crate) warnings: Vec<String>,
}

fn resolve_pair_daemon_socket(state_dir: &Path, explicit_state: bool) -> PathBuf {
    if !explicit_state {
        if let Some(raw) = std::env::var_os("HYPHAE_SOCKET")
            .or_else(|| std::env::var_os("AGENTS_MESH_SOCKET"))
            .filter(|v| !v.is_empty())
        {
            return PathBuf::from(raw);
        }
    }
    state_dir.join(hyp_harness::sock::DEFAULT_SOCKET_FILENAME)
}

/// Best-effort bounded synchronous `peers.reload` ping to a running local daemon over
/// `connector.sock` / Windows loopback `connector.addr`.
///
/// Always fail-safe: returns `reloaded: false` without error if the daemon is stopped,
/// unreachable, or timed out so an already-committed pairing/revocation never fails.
pub(crate) fn try_reload_live_daemon(
    state_dir: &Path,
    explicit_state: bool,
) -> DaemonReloadOutcome {
    let socket_path = resolve_pair_daemon_socket(state_dir, explicit_state);
    try_reload_live_daemon_at_socket(&socket_path)
}

pub(crate) fn try_reload_live_daemon_at_socket(socket_path: &Path) -> DaemonReloadOutcome {
    let resp = hyp_harness::sock::daemon_rpc_sync(
        socket_path,
        &json!({ "type": "peers.reload" }),
        LIVE_DAEMON_RELOAD_TIMEOUT,
    );
    if !resp.ok {
        return DaemonReloadOutcome {
            reloaded: false,
            warnings: Vec::new(),
        };
    }
    let Some(res) = resp.result else {
        return DaemonReloadOutcome {
            reloaded: false,
            warnings: Vec::new(),
        };
    };
    let reloaded = res
        .get("reloaded")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !reloaded {
        return DaemonReloadOutcome {
            reloaded: false,
            warnings: Vec::new(),
        };
    }
    let warnings = res
        .get("warnings")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    DaemonReloadOutcome {
        reloaded: true,
        warnings,
    }
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
            Some(
                "Generate a v2 invite via `hyp pair invite --mode team` or `--mode p2p`."
                    .to_string(),
            ),
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
                Some(
                    "Ask the inviter to generate a fresh token with `hyp pair invite --mode p2p`."
                        .to_string(),
                ),
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
        // P1-8: Never auto-grant `bridge:post` or `forward:via` without explicit `--grant`.
        strip_privileged_default_scopes(expanded_requested.clone(), &mut warnings)
    } else if !expanded_offered.is_empty() {
        strip_privileged_default_scopes(expanded_offered.clone(), &mut warnings)
    } else {
        ScopePreset::Member.expand()
    };

    // P1-9: Never trust unsigned `trustTier` metadata in P2P offers; infer strictly as Peer/Guest.
    let trust_tier_raw = infer_trust_tier(InviteMode::P2p, None, &expanded_offered);
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
        if let Err((code, msg)) =
            check_existing_peer_pin(db, &offer.node_id, PeerProfile::P2p, &offer.endpoint)
        {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                code,
                msg,
                Some(format!(
                    "Revoke the existing peer first with `hyp pair revoke {}` before re-pairing to a different profile or endpoint.",
                    offer.node_id
                )),
            );
        }
    }

    let local_node_id =
        match resolve_local_node_id(node_id_arg.as_deref(), &state_dir, existing_db.as_ref()) {
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
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ENCODE_ERROR",
                e.to_string(),
                None,
            );
        }
    };
    let enc_jwk_json = match serde_json::to_string(&offer.encryption_jwk) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ENCODE_ERROR",
                e.to_string(),
                None,
            );
        }
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
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
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
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
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
                // P1-18: Do NOT stamp the short invite pairing window onto an accepted long-lived peer grant.
                pair_by: None,
                expires_at: None,
            },
            now_db,
        ) {
            return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
        }

        let manifest_json = match serde_json::to_string(&live.signed_manifest) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
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
                format!(
                    "Failed to cache verified manifest for '{}': {e}",
                    offer.node_id
                ),
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
            expires_at: None,
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
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
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
                // P1-18: Keep accepted/staged long-lived peer grant unbounded unless explicitly bounded.
                expires_at: None,
            },
            now_db,
        ) {
            return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
        }
    }

    drop(db);
    let daemon_reloaded = if offline {
        false
    } else {
        let reload = try_reload_live_daemon(&state_dir, explicit_state);
        warnings.extend(reload.warnings);
        reload.reloaded
    };

    let next = if daemon_reloaded {
        vec![format!("hyp status --state-dir {}", state_dir.display())]
    } else {
        vec![
            "hyp service restart".to_string(),
            format!("hyp status --state-dir {}", state_dir.display()),
            format!("hyp daemon --state-dir {}", state_dir.display()),
        ]
    };

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
        "daemonReloaded": daemon_reloaded,
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
        if daemon_reloaded {
            println!(
                "      Daemon:      Live daemon reloaded — peer connected immediately (no restart needed)."
            );
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
            format!(
                "Untrusted router endpoint '{}' in am2_ bundle: {e}",
                invite.router
            ),
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
                Some(
                    "Request a fresh unmodified am2_ bundle from your organization administrator."
                        .to_string(),
                ),
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
                    Some(
                        "Request a fresh am2_ invite bundle from your organization administrator."
                            .to_string(),
                    ),
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

    // P1-9: NEVER fall back to unsigned `raw_map["trustTier"]` and NEVER map remote input
    // `"self"` to `StoreTrustTier::SelfNode`. Always derive strictly from the Admin-CA-signed grant.
    let mut trust_tier = verified_grant_pair
        .as_ref()
        .and_then(|(_, g)| g.trust_tier.as_deref())
        .map(|t| parse_store_trust_tier(t, StoreTrustTier::Org))
        .unwrap_or(StoreTrustTier::Org);

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

    let local_node_id =
        match resolve_local_node_id(node_id_arg.as_deref(), &state_dir, existing_db.as_ref()) {
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

    if let Some(ref db) = existing_db {
        let preflight_peer_id = raw_hub_node_id
            .map(ToOwned::to_owned)
            .or_else(|| derive_peer_id_from_url(&invite.router).ok());
        if let Some(ref candidate_peer_id) = preflight_peer_id {
            if let Err((code, msg)) =
                check_existing_peer_pin(db, candidate_peer_id, PeerProfile::Router, &invite.router)
            {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    code,
                    msg,
                    Some(format!(
                        "Revoke the existing peer first with `hyp pair revoke {candidate_peer_id}` before re-pairing to a different profile or endpoint."
                    )),
                );
            }
        }
    }

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
                Some(
                    "Generate a fresh team invite with `hyp pair invite --mode team`.".to_string(),
                ),
            );
        };
        match execute_live_am2_handshake(
            &invite,
            v1_code,
            &admin_pk,
            raw_hub_node_id,
            &local_node_id,
            &local_keys,
            verified_grant_pair.as_ref().map(|(sg, _)| sg),
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

    if let Some(ref db) = existing_db {
        if let Err((code, msg)) =
            check_existing_peer_pin(db, &peer_id, PeerProfile::Router, &invite.router)
        {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                code,
                msg,
                Some(format!(
                    "Revoke the existing peer first with `hyp pair revoke {peer_id}` before re-pairing to a different profile or endpoint."
                )),
            );
        }
    }

    if let Some(ref live) = live_res {
        scopes = live.verified_grant.scopes.clone();
        trust_tier = live
            .verified_grant
            .trust_tier
            .as_deref()
            .map(|t| parse_store_trust_tier(t, StoreTrustTier::Org))
            .unwrap_or(StoreTrustTier::Org);
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

    // P1-8: Never auto-grant `bridge:post` or `forward:via` on accepted am2_ invites without
    // explicit `--grant` opt-in.
    let effective_peer_scopes = if explicit_grant_scopes.is_some() {
        scopes.clone()
    } else {
        strip_privileged_default_scopes(scopes.clone(), &mut warnings)
    };

    if let Err(e) = db.peers().upsert_peer(
        &PeerInput {
            peer_id: peer_id.clone(),
            endpoint: Some(invite.router.clone()),
            profile: PeerProfile::Router,
            trust_tier,
            status: PeerStatus::Active,
            scopes: effective_peer_scopes.clone(),
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
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ENCODE_ERROR",
                e.to_string(),
                None,
            );
        }
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
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
        };
        let hub_enc_json = match serde_json::to_string(&hub_enc_jwk) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
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
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
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
        .unwrap_or_else(|| {
            format!(
                "am2-{}",
                &hex::encode(Sha256::digest(token.as_bytes()))[..12]
            )
        });

    let stored_grant_json = if let Some(ref live) = live_res {
        match serde_json::to_string(&live.signed_grant) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
        }
    } else if let Some((ref sg, _)) = verified_grant_pair {
        match serde_json::to_string(sg) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
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
            scopes: effective_peer_scopes.clone(),
            trust_tier,
            issued_at: now_db,
            // P1-18: Do NOT stamp the short invite pairing window onto an accepted long-lived peer grant.
            pair_by: if offline { expires_at_ms } else { None },
            expires_at: None,
        },
        now_db,
    ) {
        return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
    }

    drop(db);
    let daemon_reloaded = if offline {
        false
    } else {
        let reload = try_reload_live_daemon(&state_dir, explicit_state);
        warnings.extend(reload.warnings);
        reload.reloaded
    };

    let next = if daemon_reloaded {
        vec![format!("hyp status --state-dir {}", state_dir.display())]
    } else {
        vec![
            "hyp service restart".to_string(),
            format!("hyp status --state-dir {}", state_dir.display()),
            format!("hyp daemon --state-dir {}", state_dir.display()),
        ]
    };

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
        "scopes": effective_peer_scopes,
        "expiresAt": expires_at_str,
        "escalationNote": untrusted_note,
        "offline": offline,
        "handshakeCompleted": live_res.is_some(),
        "daemonReloaded": daemon_reloaded,
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
        println!("      Scopes:      {}", effective_peer_scopes.join(" "));
        if daemon_reloaded {
            println!(
                "      Daemon:      Live daemon reloaded — peer connected immediately (no restart needed)."
            );
        }
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
        message: format!(
            "Untrusted endpoint '{}' in hp2p1_ token: {e}",
            offer.endpoint
        ),
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
    let exp_ms =
        parse_rfc3339_millis(&offer.expires_at).map_err(|e| LiveHandshakeError::Rejected {
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
    check_existing_peer_pin(db, &offer.node_id, PeerProfile::P2p, &offer.endpoint)
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
    let raw_default_scopes = if !expanded_requested.is_empty() {
        expanded_requested
    } else if !expanded_offered.is_empty() {
        expanded_offered.clone()
    } else {
        ScopePreset::Member.expand()
    };
    // P1-8: Never auto-grant `bridge:post` or `forward:via` during `onboard --join`.
    let mut _strip_warnings = Vec::new();
    let granted_scopes = strip_privileged_default_scopes(raw_default_scopes, &mut _strip_warnings);
    // P1-9: Never trust unsigned `trustTier` metadata in P2P offers; infer strictly as Peer/Guest.
    let trust_tier_raw = infer_trust_tier(InviteMode::P2p, None, &expanded_offered);
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
    let enc_jwk_json =
        serde_json::to_string(&offer.encryption_jwk).map_err(|e| LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
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
    let alice_grant_json = serde_json::to_string(&live.alice_grant_signed).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        }
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
    let bob_grant_json = serde_json::to_string(&live.bob_grant_signed).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        }
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
            // P1-18: Do NOT stamp the short invite pairing window onto an accepted long-lived peer grant.
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
        message: format!(
            "Untrusted router endpoint '{}' in am2_ bundle: {e}",
            invite.router
        ),
    })?;
    let admin_pk = invite
        .admin_jwk
        .to_ed25519()
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "INVALID_KEY",
            message: format!("Invalid adminJwk in am2_ bundle: {e}"),
        })?;
    let parsed_v1 =
        parse_pairing_code_v1(&invite.pairing_code).map_err(|e| LiveHandshakeError::Rejected {
            code: "INVALID_TOKEN",
            message: format!("Malformed pairingCode in am2_ bundle: {e}"),
        })?;
    let raw_map = extract_raw_json_object(AM2_PREFIX, token);
    let verified_grant_pair =
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
        verified_grant_pair.as_ref().map(|(sg, _)| sg),
    )?;

    check_existing_signing_pin(db, &live.hub_node_id, &live.hub_signing_pk.kid())
        .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;
    check_existing_peer_pin(db, &live.hub_node_id, PeerProfile::Router, &invite.router)
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
    // P1-8: Never auto-grant `bridge:post` or `forward:via` during `onboard --join`.
    let mut _strip_warnings = Vec::new();
    let effective_scopes =
        strip_privileged_default_scopes(live.verified_grant.scopes.clone(), &mut _strip_warnings);
    db.peers()
        .upsert_peer(
            &PeerInput {
                peer_id: live.hub_node_id.clone(),
                endpoint: Some(invite.router.clone()),
                profile: PeerProfile::Router,
                trust_tier,
                status: PeerStatus::Active,
                scopes: effective_scopes.clone(),
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
        scopes: effective_scopes,
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
    let trimmed = raw_url.trim();
    let base_url = if trimmed.starts_with("ssh://") {
        parse_ssh_endpoint(trimmed)
            .map_err(|e| LiveHandshakeError::Rejected {
                code: "INVALID_ENDPOINT",
                message: format!("Invalid target SSH URL '{raw_url}': {e}"),
            })?
            .canonical_url()
    } else {
        let no_slash = trimmed.trim_end_matches('/');
        no_slash
            .strip_suffix("/v1/manifest")
            .unwrap_or(no_slash)
            .to_string()
    };

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

    match attempt_guest_self_enroll(
        &base_url,
        &peer_id,
        &v.signing_pk,
        local_node_id,
        local_keys,
    ) {
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
    let sign_json = serde_json::to_string(&sign_jwk).map_err(|e| LiveHandshakeError::Rejected {
        code: "ENCODE_ERROR",
        message: e.to_string(),
    })?;
    let enc_json = serde_json::to_string(&enc_jwk).map_err(|e| LiveHandshakeError::Rejected {
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

fn fetch_and_verify_manifest(
    base_url: &str,
) -> Result<VerifiedLiveManifest, (&'static str, String)> {
    let manifest_url = format!("{}/v1/manifest", base_url.trim_end_matches('/'));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            (
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
            )
        })?;

    let (body_bytes, etag) = rt.block_on(async {
        let client = HttpClient::new()
            .map_err(|e| ("HTTP_ERROR", format!("Failed to initialize HTTP client: {e}")))?;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/manifest")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(empty_body())
            .map_err(|e| ("HTTP_ERROR", format!("Failed to build request: {e}")))?;

        let outcome = async {
            let resp = tokio::time::timeout(
                Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS),
                client.request_for_endpoint(base_url, req),
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
        }
        .await;

        client.shutdown_ssh();
        outcome
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
    .map_err(|e| {
        (
            "ENCODE_ERROR",
            format!("Failed to canonicalize guest-pair proof: {e}"),
        )
    })?;
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
    let req_bytes = serde_json::to_vec(&req_body).map_err(|e| {
        (
            "ENCODE_ERROR",
            format!("Failed to serialize guest-pair request: {e}"),
        )
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            (
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
            )
        })?;

    let (status, body_bytes) = rt.block_on(async {
        let client = HttpClient::new()
            .map_err(|e| ("HTTP_ERROR", format!("Failed to initialize HTTP client: {e}")))?;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/guest/pair")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(full_body(Bytes::from(req_bytes)))
            .map_err(|e| ("HTTP_ERROR", format!("Failed to build guest-pair request: {e}")))?;

        let outcome = async {
            let resp = tokio::time::timeout(
                Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS),
                client.request_for_endpoint(base_url, req),
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
        }
        .await;

        client.shutdown_ssh();
        outcome
    })?;

    if status == 404 {
        return Ok(GuestEnrollOutcome::NotEnabled);
    }

    if status != 200 {
        let (code, detail) =
            if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(&body_bytes) {
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
                (
                    err_code,
                    format!("POST {pair_url} rejected ({}): {msg}", problem.error),
                )
            } else {
                let snippet: String = String::from_utf8_lossy(&body_bytes)
                    .chars()
                    .take(200)
                    .collect();
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
            format!(
                "Hub manifest in /v1/guest/pair expired at {}",
                manifest_payload.expires_at
            ),
        ));
    }

    Ok(GuestEnrollOutcome::Enrolled {
        preset: reply.preset,
        scopes: validated_scopes,
        manifest: reply.manifest,
        manifest_payload: Box::new(manifest_payload),
    })
}

pub(crate) struct DelegatedEnrollSuccess {
    pub hub_node_id: String,
    pub human_id: String,
    pub auth_epoch: u64,
    pub scopes: Vec<String>,
    pub auth_credential: String,
    pub manifest: SignedNodeManifest,
    pub manifest_payload: Box<NodeManifestPayload>,
}

/// Calls `POST <base_url>/v1/pair/delegated` using a human-signed `hcert1_` NodeCert and a live
/// device Ed25519 possession proof, verifying the returned `SignedNodeManifest` against the hub's
/// pinned signing key (or self-signed manifest + optional `expected_hub_fingerprint`).
pub(crate) fn attempt_delegated_pair_enroll(
    base_url: &str,
    hub_node_id: &str,
    expected_hub_signing_pk: Option<&Ed25519PublicKey>,
    expected_hub_fingerprint: Option<&str>,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
    hcert1: &str,
) -> Result<DelegatedEnrollSuccess, (u16, &'static str, String)> {
    let pair_url = format!("{}/v1/pair/delegated", base_url.trim_end_matches('/'));
    if let Err(e) = validate_endpoint_origin(base_url) {
        return Err((
            0u16,
            "INVALID_ENDPOINT",
            format!("Invalid delegated pairing endpoint '{base_url}': {e}"),
        ));
    }

    let ed25519_jwk = local_keys.signing_jwk();
    let x25519_jwk = local_keys.encryption_jwk();
    let timestamp = format_rfc3339_millis(now_unix_ms());
    let trimmed_cert = hcert1.trim();
    let proof = DelegatedPairProofV1 {
        hub_node_id: hub_node_id.to_string(),
        node_id: local_node_id.to_string(),
        ed25519_jwk: ed25519_jwk.clone(),
        x25519_jwk: x25519_jwk.clone(),
        node_cert_sha256: node_cert_sha256(trimmed_cert),
        timestamp: timestamp.clone(),
    };
    let proof_sig = sign_delegated_pair_proof(&proof, &local_keys.signing).map_err(|e| {
        (
            0u16,
            "SIGN_ERROR",
            format!("Failed to sign DelegatedPairProofV1: {e}"),
        )
    })?;

    let req_body = DelegatedPairRequest {
        node_id: local_node_id.to_string(),
        ed25519_jwk,
        x25519_jwk,
        node_cert: trimmed_cert.to_string(),
        timestamp,
        proof_sig,
    };
    let req_bytes = serde_json::to_vec(&req_body).map_err(|e| {
        (
            0u16,
            "ENCODE_ERROR",
            format!("Failed to serialize delegated-pair request: {e}"),
        )
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            (
                0u16,
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
            )
        })?;

    let (status, body_bytes) = rt.block_on(async {
        let client = HttpClient::new().map_err(|e| {
            (
                0u16,
                "HTTP_ERROR",
                format!("Failed to initialize HTTP client: {e}"),
            )
        })?;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/pair/delegated")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(full_body(Bytes::from(req_bytes)))
            .map_err(|e| {
                (
                    0u16,
                    "HTTP_ERROR",
                    format!("Failed to build delegated-pair request: {e}"),
                )
            })?;

        let outcome = async {
            let resp = tokio::time::timeout(
                Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS),
                client.request_for_endpoint(base_url, req),
            )
            .await
            .map_err(|_| {
                (
                    0u16,
                    "DELEGATED_PAIR_FAILED",
                    format!("POST {pair_url} timed out after {MANIFEST_FETCH_TIMEOUT_SECS}s"),
                )
            })?
            .map_err(|e| {
                (
                    0u16,
                    "DELEGATED_PAIR_FAILED",
                    format!("POST {pair_url} failed: {e}"),
                )
            })?;

            let status = resp.status().as_u16();
            let bytes = tokio::time::timeout(Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS), async {
                let mut body = resp.into_body();
                let mut out = Vec::new();
                while let Some(frame_res) = body.frame().await {
                    let frame = frame_res.map_err(|e| {
                        (
                            status,
                            "DELEGATED_PAIR_FAILED",
                            format!("Delegated pair body read error: {e}"),
                        )
                    })?;
                    if let Some(chunk) = frame.data_ref() {
                        if out.len() + chunk.len() > MAX_MANIFEST_RESPONSE_BYTES {
                            return Err((
                                status,
                                "DELEGATED_PAIR_INVALID",
                                format!(
                                    "Delegated pair response exceeds {MAX_MANIFEST_RESPONSE_BYTES} byte cap"
                                ),
                            ));
                        }
                        out.extend_from_slice(chunk);
                    }
                }
                Ok::<Vec<u8>, (u16, &'static str, String)>(out)
            })
            .await
            .map_err(|_| {
                (
                    status,
                    "DELEGATED_PAIR_FAILED",
                    "Timed out reading /v1/pair/delegated response body".to_string(),
                )
            })??;

            Ok::<(u16, Vec<u8>), (u16, &'static str, String)>((status, bytes))
        }
        .await;

        client.shutdown_ssh();
        outcome
    })?;

    if status != 200 {
        let (code, detail) =
            if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(&body_bytes) {
                let err_code = match (status, problem.error.as_str()) {
                    (_, "peer_key_mismatch") => "PEER_KEY_MISMATCH",
                    (_, "human_key_mismatch") => "HUMAN_KEY_MISMATCH",
                    (429, _) | (_, "quota_exceeded") | (_, "rate_limited") => "QUOTA_EXCEEDED",
                    (409, _) => "DELEGATED_PAIR_CONFLICT",
                    (401, _) | (403, _) => "DELEGATED_PAIR_REJECTED",
                    (404, _) => "DELEGATED_PAIR_NOT_SUPPORTED",
                    _ => "DELEGATED_PAIR_FAILED",
                };
                let msg = problem
                    .detail
                    .unwrap_or_else(|| format!("{} (HTTP {status})", problem.title));
                (
                    err_code,
                    format!("POST {pair_url} rejected ({}): {msg}", problem.error),
                )
            } else {
                let snippet: String = String::from_utf8_lossy(&body_bytes)
                    .chars()
                    .take(200)
                    .collect();
                let err_code = match status {
                    409 => "DELEGATED_PAIR_CONFLICT",
                    429 => "QUOTA_EXCEEDED",
                    401 | 403 => "DELEGATED_PAIR_REJECTED",
                    404 => "DELEGATED_PAIR_NOT_SUPPORTED",
                    _ => "DELEGATED_PAIR_FAILED",
                };
                (
                    err_code,
                    format!("POST {pair_url} returned HTTP {status}: {snippet}"),
                )
            };
        return Err((status, code, detail));
    }

    let reply: DelegatedPairReply = serde_json::from_slice(&body_bytes).map_err(|e| {
        (
            200,
            "DELEGATED_PAIR_INVALID",
            format!("Invalid DelegatedPairReply JSON from {pair_url}: {e}"),
        )
    })?;
    if !reply.ok || reply.auth_credential.trim().is_empty() {
        return Err((
            200,
            "DELEGATED_PAIR_INVALID",
            format!("Hub '{hub_node_id}' returned invalid delegated pair reply"),
        ));
    }
    if reply.node_id != hub_node_id {
        return Err((
            200,
            "NODE_ID_MISMATCH",
            format!(
                "Hub /v1/pair/delegated nodeId '{}' does not match expected '{hub_node_id}'",
                reply.node_id
            ),
        ));
    }
    if reply.peer_id != local_node_id {
        return Err((
            200,
            "DELEGATED_PAIR_INVALID",
            format!(
                "Hub /v1/pair/delegated peerId '{}' does not match local nodeId '{local_node_id}'",
                reply.peer_id
            ),
        ));
    }
    let validated_scopes = expand_v2_scopes(&reply.scopes).map_err(|e| {
        (
            200,
            "DELEGATED_PAIR_INVALID",
            format!("Hub /v1/pair/delegated returned invalid scopes: {e}"),
        )
    })?;

    let manifest_payload = reply.signed_manifest.decode_payload().map_err(|e| {
        (
            200,
            "INVALID_MANIFEST",
            format!("Invalid NodeManifestPayload in /v1/pair/delegated reply: {e}"),
        )
    })?;
    if manifest_payload.node_id.as_str() != hub_node_id {
        return Err((
            200,
            "NODE_ID_MISMATCH",
            format!(
                "Manifest nodeId '{}' in /v1/pair/delegated reply does not match '{hub_node_id}'",
                manifest_payload.node_id
            ),
        ));
    }
    let canonical_manifest = manifest_payload.to_canonical_payload().map_err(|e| {
        (
            200,
            "INVALID_MANIFEST",
            format!("Failed to canonicalize delegated-pair manifest payload: {e}"),
        )
    })?;
    if canonical_manifest != reply.signed_manifest.payload {
        return Err((
            200,
            "NON_CANONICAL_MANIFEST",
            "Manifest in /v1/pair/delegated reply is not canonical RFC 8785 JCS (fail-closed)"
                .to_string(),
        ));
    }
    let manifest_sign_pk = proto_jwk_to_crypto(&manifest_payload.identity.signing_jwk)
        .to_ed25519()
        .map_err(|e| {
            (
                200,
                "INVALID_KEY",
                format!("Invalid hub signingJwk in delegated-pair manifest: {e}"),
            )
        })?;
    let verify_pk = if let Some(pinned) = expected_hub_signing_pk {
        if *pinned != manifest_sign_pk {
            return Err((
                200,
                "HUB_KEY_MISMATCH",
                "Hub signing key in /v1/pair/delegated manifest does not match pinned manifest key"
                    .to_string(),
            ));
        }
        pinned
    } else {
        &manifest_sign_pk
    };
    if let Some(expected_fp) = expected_hub_fingerprint {
        let actual_fp = verify_pk.fingerprint();
        if !expected_fp.eq_ignore_ascii_case(&actual_fp) {
            return Err((
                200,
                "HUB_FINGERPRINT_MISMATCH",
                format!(
                    "Hub signing key fingerprint '{actual_fp}' does not match pinned '{expected_fp}'"
                ),
            ));
        }
    }
    verify_pk
        .verify_domain_b64(
            "manifest",
            reply.signed_manifest.payload.as_bytes(),
            &reply.signed_manifest.sig,
        )
        .map_err(|e| {
            (
                200,
                "INVALID_SIGNATURE",
                format!("Manifest signature in /v1/pair/delegated reply failed verification: {e}"),
            )
        })?;
    let exp_ms = parse_rfc3339_millis(&manifest_payload.expires_at).map_err(|e| {
        (
            200,
            "INVALID_MANIFEST",
            format!("Invalid expiresAt in /v1/pair/delegated manifest: {e}"),
        )
    })?;
    if now_unix_ms() > exp_ms {
        return Err((
            200,
            "MANIFEST_EXPIRED",
            format!(
                "Hub manifest in /v1/pair/delegated expired at {}",
                manifest_payload.expires_at
            ),
        ));
    }

    Ok(DelegatedEnrollSuccess {
        hub_node_id: reply.node_id,
        human_id: reply.human_id,
        auth_epoch: reply.auth_epoch,
        scopes: validated_scopes,
        auth_credential: reply.auth_credential,
        manifest: reply.signed_manifest,
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

    let trimmed = url.trim();
    let base_url = if trimmed.starts_with("ssh://") {
        match parse_ssh_endpoint(trimmed) {
            Ok(ep) => ep.canonical_url(),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_ENDPOINT",
                    format!("Invalid SSH target URL '{url}': {e}"),
                    Some("Use ssh://[user@]host[:port][?stateDir=/path]".to_string()),
                );
            }
        }
    } else {
        let no_slash = trimmed.trim_end_matches('/');
        no_slash
            .strip_suffix("/v1/manifest")
            .unwrap_or(no_slash)
            .to_string()
    };

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

    // Attempt delegated human-cert pairing (`POST /v1/pair/delegated`) FIRST when this device
    // holds a valid stored `hcert1_` NodeCert; otherwise fall back to opt-in self-service
    // `POST /v1/guest/pair` enrollment when online.
    let mut join_mode = "public";
    let mut enrolled = false;
    let mut effective_preset = preset.as_str().to_string();
    let mut effective_trust_tier = trust_tier;
    let mut effective_scopes = scopes;
    let mut effective_auth_cred_ref: Option<String> = None;
    let mut delegated_human_id: Option<String> = None;
    let mut delegated_auth_epoch: Option<u64> = None;
    let mut effective_signed_manifest: Option<SignedNodeManifest> = None;
    let mut effective_manifest_payload: Option<NodeManifestPayload> = None;

    if let Some(ref v) = verified_live {
        let local_hcert1: Option<String> = db
            .human()
            .get_latest_node_cert(&local_node_id)
            .ok()
            .flatten()
            .filter(|rec| rec.expires_at > now_ms())
            .and_then(|rec| serde_json::from_str::<SignedNodeCertV1>(&rec.signed_json).ok())
            .and_then(|signed| encode_hcert1(&signed).ok());

        let mut delegated_err: Option<(&'static str, String)> = None;
        if let Some(ref hcert1) = local_hcert1 {
            match attempt_delegated_pair_enroll(
                &base_url,
                &peer_id,
                Some(&v.signing_pk),
                None,
                &local_node_id,
                &local_keys,
                hcert1,
            ) {
                Ok(del) => {
                    let cred_name = credential_secret_name("peer-auth", &peer_id);
                    if let Err(e) = secrets.set(&cred_name, &del.auth_credential) {
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            "KEYSTORE_ERROR",
                            format!("Failed to store hub authCredential in SecretStore: {e}"),
                            None,
                        );
                    }
                    join_mode = "delegated";
                    enrolled = true;
                    effective_preset = "delegated".to_string();
                    effective_trust_tier = StoreTrustTier::Org;
                    effective_scopes = del.scopes;
                    effective_auth_cred_ref = Some(cred_name);
                    delegated_human_id = Some(del.human_id);
                    delegated_auth_epoch = Some(del.auth_epoch);
                    effective_signed_manifest = Some(del.manifest);
                    effective_manifest_payload = Some(*del.manifest_payload);
                }
                Err((status, code, msg)) => {
                    // Fail closed immediately on key conflicts or device quota caps;
                    // for 401/403/404 (e.g. joining a public guest-ro hub with a personal cert),
                    // try guest pairing fallback and surface the delegated rejection if guest is disabled.
                    if matches!(status, 409 | 429) {
                        return emit_error(cmd, as_json, EXIT_ERROR, code, msg, None);
                    }
                    delegated_err = Some((code, msg));
                }
            }
        }

        if !enrolled {
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
                    if let Some((code, msg)) = delegated_err {
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            code,
                            msg,
                            Some("Verify your human authority is enrolled on this hub and your nodeId matches its allowed nodePrefix, or run `hyp join`.".to_string()),
                        );
                    }
                    warnings.push(format!(
                        "Node '{peer_id}' does not expose self-service guest pairing (POST /v1/guest/pair returned 404); request an am2_ invite or hjoin1_ human invite from the hub admin to enroll."
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
    }

    let now_db = now_ms();
    let _ = db.local().ensure_metadata("node_id", &local_node_id);

    if let Err(e) = db.peers().upsert_peer(
        &PeerInput {
            peer_id: peer_id.clone(),
            endpoint: Some(base_url.clone()),
            profile: peer_profile,
            trust_tier: effective_trust_tier,
            status: PeerStatus::Active,
            scopes: effective_scopes.clone(),
            auth_credential_ref: effective_auth_cred_ref.clone(),
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
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
        };
        let enc_json = match serde_json::to_string(&enc_jwk) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
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
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ENCODE_ERROR",
                    e.to_string(),
                    None,
                );
            }
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

    drop(db);
    let daemon_reloaded = if offline {
        false
    } else {
        let reload = try_reload_live_daemon(&state_dir, explicit_state);
        warnings.extend(reload.warnings);
        reload.reloaded
    };

    let manifest_verified = verified_live.is_some();
    let next = if daemon_reloaded {
        vec![format!("hyp status --state-dir {}", state_dir.display())]
    } else {
        vec![
            "hyp service restart".to_string(),
            format!("hyp status --state-dir {}", state_dir.display()),
            format!("hyp daemon --state-dir {}", state_dir.display()),
        ]
    };

    let data = json!({
        "mode": join_mode,
        "nodeId": local_node_id,
        "peerId": peer_id,
        "endpoint": base_url,
        "profile": peer_profile.as_str(),
        "preset": effective_preset,
        "trustTier": effective_trust_tier.as_str(),
        "scopes": effective_scopes,
        "humanId": delegated_human_id,
        "authEpoch": delegated_auth_epoch,
        "offline": offline,
        "enrolled": enrolled,
        "manifestVerified": manifest_verified,
        "daemonReloaded": daemon_reloaded,
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
            effective_trust_tier.as_str(),
            enrolled
        );
        if let Some(ref hid) = delegated_human_id {
            println!(
                "      Human Cert:  human:{hid} (ep {})",
                delegated_auth_epoch.unwrap_or(1)
            );
        }
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
        if daemon_reloaded {
            println!(
                "      Daemon:      Live daemon reloaded — peer connected immediately (no restart needed)."
            );
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

// ============================================================================
// `pair ssh <target>` — One-command zero-port mutual P2P pairing over SSH
// ============================================================================

const PAIR_SSH_REMOTE_TIMEOUT_SECS: u64 = 30;
const MAX_PAIR_SSH_STDOUT_BYTES: usize = 256 * 1024;

fn shell_single_quote_strict(raw: &str, label: &str) -> Result<String, String> {
    if raw.is_empty()
        || raw.contains('\'')
        || raw
            .chars()
            .any(|c| c.is_control() || c == '\n' || c == '\r')
    {
        return Err(format!(
            "refusing unsafe remote SSH argument for {label}: contains single quote or control characters"
        ));
    }
    Ok(format!("'{raw}'"))
}

fn build_remote_p2p_invite_cmd(
    ssh_ep: &SshEndpoint,
    remote_node_id: &str,
    canonical_endpoint: &str,
    local_node_id: &str,
    remote_offered_scopes: &[String],
    remote_requested_scopes: &[String],
) -> Result<String, String> {
    if remote_node_id == LOCAL_NODE_ID || !is_valid_node_id(remote_node_id) {
        return Err(format!("invalid remote nodeId '{remote_node_id}'"));
    }
    if local_node_id == LOCAL_NODE_ID || !is_valid_node_id(local_node_id) {
        return Err(format!("invalid local nodeId '{local_node_id}'"));
    }
    let _ = parse_ssh_endpoint(canonical_endpoint).map_err(|e| e.to_string())?;

    let mut args: Vec<String> = vec![
        "pair".to_string(),
        "invite".to_string(),
        "--mode".to_string(),
        "p2p".to_string(),
        "--node-id".to_string(),
        shell_single_quote_strict(remote_node_id, "remote_node_id")?,
        "--endpoint".to_string(),
        shell_single_quote_strict(canonical_endpoint, "endpoint")?,
        "--peer".to_string(),
        shell_single_quote_strict(local_node_id, "peer")?,
    ];
    if let Some(ref sd) = ssh_ep.state_dir {
        validate_ssh_posix_path(sd, "stateDir").map_err(|e| e.to_string())?;
        args.push("--state-dir".to_string());
        args.push(shell_single_quote_strict(sd, "stateDir")?);
    }
    if !remote_offered_scopes.is_empty() {
        args.push("--grant".to_string());
        for s in remote_offered_scopes {
            args.push(shell_single_quote_strict(s, "remote grant scope")?);
        }
    }
    if !remote_requested_scopes.is_empty() {
        args.push("--request".to_string());
        for s in remote_requested_scopes {
            args.push(shell_single_quote_strict(s, "remote request scope")?);
        }
    }
    args.push("--json".to_string());

    let joined = args.join(" ");
    match &ssh_ep.bin {
        Some(bin) => {
            validate_ssh_posix_path(bin, "bin").map_err(|e| e.to_string())?;
            Ok(format!(
                "exec {} {joined}",
                shell_single_quote_strict(bin, "bin")?
            ))
        }
        None => Ok(format!(
            "command -v hyp >/dev/null 2>&1 && exec hyp {joined} || exec \"$HOME/.local/bin/hyp\" {joined}"
        )),
    }
}

fn invoke_remote_ssh_invite(
    ssh_ep: &SshEndpoint,
    remote_cmd: &str,
) -> Result<String, (&'static str, String)> {
    let ssh_bin = resolve_ssh_binary();
    let ssh_args = ssh_ep.build_ssh_args_for_remote_cmd(remote_cmd);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            (
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
            )
        })?;

    let (status_ok, status_code, stdout_bytes, stderr_bytes) = rt.block_on(async {
        use tokio::io::AsyncReadExt;
        use tokio::process::Command;

        let mut cmd = Command::new(&ssh_bin);
        cmd.args(&ssh_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| {
            (
                "SSH_SPAWN_FAILED",
                format!("Failed to launch SSH client '{ssh_bin}': {e}"),
            )
        })?;

        let mut out_pipe = child.stdout.take().ok_or((
            "SSH_EXEC_FAILED",
            "SSH child missing stdout pipe".to_string(),
        ))?;
        let mut err_pipe = child.stderr.take().ok_or((
            "SSH_EXEC_FAILED",
            "SSH child missing stderr pipe".to_string(),
        ))?;

        let fut = async {
            let mut out_buf = Vec::new();
            let mut err_buf = Vec::new();
            let out_task = async {
                let mut lim = (&mut out_pipe).take((MAX_PAIR_SSH_STDOUT_BYTES + 1) as u64);
                lim.read_to_end(&mut out_buf).await
            };
            let err_task = async {
                let mut lim = (&mut err_pipe).take(64 * 1024);
                lim.read_to_end(&mut err_buf).await
            };
            let (out_res, err_res) = tokio::join!(out_task, err_task);
            out_res.map_err(|e| ("SSH_EXEC_FAILED", format!("Failed reading SSH stdout: {e}")))?;
            let _ = err_res;
            if out_buf.len() > MAX_PAIR_SSH_STDOUT_BYTES {
                let _ = child.kill().await;
                return Err((
                    "SSH_RESPONSE_TOO_LARGE",
                    format!("Remote SSH invite output exceeded {MAX_PAIR_SSH_STDOUT_BYTES} bytes"),
                ));
            }
            let status = child.wait().await.map_err(|e| {
                (
                    "SSH_EXEC_FAILED",
                    format!("Failed waiting for SSH child: {e}"),
                )
            })?;
            Ok((status.success(), status.code(), out_buf, err_buf))
        };

        match tokio::time::timeout(Duration::from_secs(PAIR_SSH_REMOTE_TIMEOUT_SECS), fut).await {
            Ok(res) => res,
            Err(_) => {
                let _ = child.kill().await;
                Err((
                    "SSH_TIMEOUT",
                    format!(
                        "Remote SSH pairing invite timed out after {PAIR_SSH_REMOTE_TIMEOUT_SECS}s"
                    ),
                ))
            }
        }
    })?;

    if !status_ok {
        let err_snippet: String = String::from_utf8_lossy(&stderr_bytes)
            .trim()
            .chars()
            .take(300)
            .collect();
        let out_snippet: String = String::from_utf8_lossy(&stdout_bytes)
            .trim()
            .chars()
            .take(300)
            .collect();
        let detail = if !err_snippet.is_empty() {
            err_snippet
        } else if !out_snippet.is_empty() {
            out_snippet
        } else {
            format!("exit status {:?}", status_code)
        };
        return Err((
            "SSH_REMOTE_INVITE_FAILED",
            format!("Remote `hyp pair invite` over SSH failed: {detail}"),
        ));
    }

    let parsed: Value = serde_json::from_slice(&stdout_bytes).map_err(|e| {
        (
            "SSH_INVALID_RESPONSE",
            format!("Remote `hyp pair invite --json` returned invalid JSON: {e}"),
        )
    })?;
    if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
        let msg = parsed
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("remote invite returned ok=false");
        return Err(("SSH_REMOTE_INVITE_FAILED", msg.to_string()));
    }
    let token = parsed
        .get("data")
        .and_then(|d| d.get("token"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| t.starts_with(HP2P1_PREFIX))
        .ok_or_else(|| {
            (
                "SSH_INVALID_RESPONSE",
                "Remote `hyp pair invite --json` output did not contain a valid hp2p1_ token"
                    .to_string(),
            )
        })?;
    Ok(token.to_string())
}

#[allow(clippy::too_many_arguments)]
fn run_pair_ssh(
    target: String,
    preset: Option<CliScopePreset>,
    grant_args: Vec<String>,
    request_args: Vec<String>,
    state_dir_arg: Option<PathBuf>,
    node_id_arg: Option<String>,
    remote_node_id_arg: Option<String>,
    remote_state_dir: Option<String>,
    remote_bin: Option<String>,
    dry_run: bool,
    as_json: bool,
) -> ExitCode {
    let cmd = "pair ssh";
    let raw_target = target.trim();
    if raw_target.is_empty() {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_ENDPOINT",
            "Missing SSH target (e.g. `ops@solace` or `great-northern`)",
            Some("Example: hyp pair ssh ops@solace --preset member".to_string()),
        );
    }
    if raw_target.contains("://") && !raw_target.starts_with("ssh://") {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_ENDPOINT",
            format!("`hyp pair ssh` expects an SSH target or ssh:// URL (got '{raw_target}')"),
            Some("Example: hyp pair ssh ops@solace  (or use `hyp pair join` / `hyp pair accept` for https://)".to_string()),
        );
    }

    let raw_ssh_url = if raw_target.starts_with("ssh://") {
        raw_target.to_string()
    } else {
        format!("ssh://{raw_target}")
    };
    let mut ssh_ep = match parse_ssh_endpoint(&raw_ssh_url) {
        Ok(ep) => ep,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_ENDPOINT",
                format!("Invalid SSH target '{target}': {e}"),
                Some("Use `[user@]host[:port]` or `ssh://[user@]host[:port][?stateDir=/path]` without shell metacharacters or leading '-'.".to_string()),
            );
        }
    };

    if let Some(ref sd) = remote_state_dir {
        if let Err(e) = validate_ssh_posix_path(sd, "remoteStateDir") {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_ENDPOINT",
                format!("Invalid --remote-state-dir '{sd}': {e}"),
                None,
            );
        }
        if let Some(ref existing_sd) = ssh_ep.state_dir {
            if existing_sd != sd {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_ENDPOINT",
                    format!(
                        "Conflicting remote state directories: query ?stateDir={existing_sd} vs --remote-state-dir {sd}"
                    ),
                    None,
                );
            }
        }
        ssh_ep.state_dir = Some(sd.clone());
    }
    if let Some(ref b) = remote_bin {
        if let Err(e) = validate_ssh_posix_path(b, "remoteBin") {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_ENDPOINT",
                format!("Invalid --remote-bin '{b}': {e}"),
                None,
            );
        }
        if let Some(ref existing_bin) = ssh_ep.bin {
            if existing_bin != b {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_ENDPOINT",
                    format!(
                        "Conflicting remote binaries: query ?bin={existing_bin} vs --remote-bin {b}"
                    ),
                    None,
                );
            }
        }
        ssh_ep.bin = Some(b.clone());
    }

    let canonical_endpoint = ssh_ep.canonical_url();

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
                None,
            );
        }
    }
    if let Some(ref raw) = remote_node_id_arg {
        if raw == LOCAL_NODE_ID || !is_valid_node_id(raw) {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_PEER_ID",
                format!(
                    "Invalid --remote-node-id '{raw}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
                ),
                None,
            );
        }
    }

    // Resolve mutual scopes:
    // - `local_granted_scopes`: scopes OUR local node grants to the remote peer
    // - `remote_offered_scopes`: scopes we ask the remote peer to grant US
    let mut warnings = Vec::new();
    let explicit_grant = !grant_args.is_empty();
    let mut raw_local_grants: Vec<String> = Vec::new();
    if let Some(p) = preset {
        raw_local_grants.extend(p.to_proto().expand());
    }
    raw_local_grants.extend(tokenize_scope_args(&grant_args));
    if raw_local_grants.is_empty() {
        raw_local_grants = ScopePreset::Member.expand();
    }
    let expanded_local_grants = match expand_v2_scopes(&raw_local_grants) {
        Ok(s) => s,
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
    };
    let local_granted_scopes = if explicit_grant {
        expanded_local_grants
    } else {
        strip_privileged_default_scopes(expanded_local_grants, &mut warnings)
    };

    let remote_offered_scopes = if request_args.is_empty() {
        local_granted_scopes.clone()
    } else {
        let tokenized_req = tokenize_scope_args(&request_args);
        match expand_v2_scopes(&tokenized_req) {
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

    let explicit_state = state_dir_arg.is_some();
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), None, None);
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

    let local_node_id =
        match resolve_local_node_id(node_id_arg.as_deref(), &state_dir, existing_db.as_ref()) {
            Ok(id) => id,
            Err((exit, code, msg)) => return emit_error(cmd, as_json, exit, code, msg, None),
        };

    if dry_run {
        let preview_remote_id = remote_node_id_arg
            .clone()
            .or_else(|| derive_peer_id_from_url(&canonical_endpoint).ok())
            .unwrap_or_else(|| "remote-node".to_string());
        let remote_invite_cmd = match build_remote_p2p_invite_cmd(
            &ssh_ep,
            &preview_remote_id,
            &canonical_endpoint,
            &local_node_id,
            &remote_offered_scopes,
            &local_granted_scopes,
        ) {
            Ok(c) => c,
            Err(msg) => {
                return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_ENDPOINT", msg, None);
            }
        };
        let connect_args = ssh_ep.build_ssh_args();
        let data = json!({
            "dryRun": true,
            "transport": "ssh",
            "target": ssh_ep.target(),
            "endpoint": canonical_endpoint,
            "localNodeId": local_node_id,
            "remoteNodeId": remote_node_id_arg,
            "grantedScopes": local_granted_scopes,
            "requestedScopes": remote_offered_scopes,
            "sshConnectArgs": connect_args,
            "remoteInviteCmd": remote_invite_cmd,
            "manualInviteAlternative": format!(
                "hyp pair invite --mode p2p --node-id {preview_remote_id} --endpoint {canonical_endpoint} --preset {}",
                preset.map(CliScopePreset::as_str).unwrap_or("member")
            ),
        });
        if as_json {
            let envelope = JsonEnvelope {
                ok: true,
                command: cmd.to_string(),
                summary: Some(format!(
                    "Dry-run validated SSH mutual P2P pairing plan for {canonical_endpoint}"
                )),
                data: Some(data),
                warnings,
                next: vec![format!("hyp pair ssh {}", ssh_ep.target())],
                error: None,
            };
            print_json(&envelope);
        } else {
            println!("OK    SSH Mutual P2P Pairing Plan (--dry-run)");
            println!("      Local Node:   {local_node_id}");
            println!("      SSH Target:   {}", ssh_ep.target());
            println!("      Endpoint:     {canonical_endpoint}");
            println!("      Grant To Peer: {}", local_granted_scopes.join(" "));
            println!("      Request Scope: {}", remote_offered_scopes.join(" "));
            println!("      Connect Args: ssh {}", connect_args.join(" "));
            print_warnings(&warnings);
        }
        return ExitCode::from(EXIT_OK);
    }

    // Step 1: Verify the remote node is reachable over `ssh://` (`hyp connect` -> `peer.sock`)
    // and cryptographically verify its signed `/v1/manifest`.
    let verified_manifest = match fetch_and_verify_manifest(&canonical_endpoint) {
        Ok(v) => v,
        Err((code, msg)) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                code,
                format!(
                    "Could not reach or verify remote Hyphae node via {canonical_endpoint}: {msg}"
                ),
                Some(format!(
                    "Verify passwordless SSH works (`ssh -o BatchMode=yes {} true`) and the remote Hyphae node is running (`hyp node start --profile p2p` or `--peer-socket`).",
                    ssh_ep.target()
                )),
            );
        }
    };

    let remote_node_id = verified_manifest.payload.node_id.as_str().to_string();
    if let Some(ref expected) = remote_node_id_arg {
        if *expected != remote_node_id {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "NODE_ID_MISMATCH",
                format!(
                    "Remote manifest nodeId '{remote_node_id}' does not match --remote-node-id '{expected}'"
                ),
                None,
            );
        }
    }
    if remote_node_id == local_node_id {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "PEER_ID_CONFLICT",
            format!(
                "Remote nodeId '{remote_node_id}' is identical to local nodeId '{local_node_id}'"
            ),
            Some("Pass a distinct --node-id for this machine.".to_string()),
        );
    }

    let manifest_sign_kid = verified_manifest.signing_pk.kid();
    if let Some(ref db) = existing_db {
        if let Err((code, msg)) =
            check_existing_signing_pin(db, &remote_node_id, &manifest_sign_kid)
        {
            return emit_error(cmd, as_json, EXIT_ERROR, code, msg, None);
        }
        if let Err((code, msg)) =
            check_existing_peer_pin(db, &remote_node_id, PeerProfile::P2p, &canonical_endpoint)
        {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                code,
                msg,
                Some(format!(
                    "Revoke the existing peer first with `hyp pair revoke {remote_node_id}` before re-pairing to a different endpoint."
                )),
            );
        }
    }

    // Step 2: Mint a single-use `hp2p1_` offer remotely over `ssh -o BatchMode=yes -- <target>`
    // (ZERO secrets in argv — token travels back over SSH stdout JSON into RAM only!).
    let remote_invite_cmd = match build_remote_p2p_invite_cmd(
        &ssh_ep,
        &remote_node_id,
        &canonical_endpoint,
        &local_node_id,
        &remote_offered_scopes,
        &local_granted_scopes,
    ) {
        Ok(c) => c,
        Err(msg) => {
            return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_ENDPOINT", msg, None);
        }
    };
    let hp2p1_token = match invoke_remote_ssh_invite(&ssh_ep, &remote_invite_cmd) {
        Ok(tok) => tok,
        Err((code, msg)) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                code,
                msg,
                Some(format!(
                    "Ensure `hyp` is installed on {} (or pass --remote-bin /path/to/hyp) and its node daemon is running.",
                    ssh_ep.target()
                )),
            );
        }
    };

    // Step 3: Decode & cross-verify the returned `hp2p1_` offer against the verified manifest.
    let offer = match decode_hp2p1(&hp2p1_token) {
        Ok(o) => o,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_TOKEN",
                format!("Remote host returned an invalid hp2p1_ offer: {e}"),
                None,
            );
        }
    };
    if offer.node_id != remote_node_id {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "NODE_ID_MISMATCH",
            format!(
                "Remote hp2p1_ offer nodeId '{}' does not match verified manifest nodeId '{remote_node_id}'",
                offer.node_id
            ),
            None,
        );
    }
    let offer_sign_pk = match offer.signing_jwk.to_ed25519() {
        Ok(pk) => pk,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_KEY",
                format!("Invalid signingJwk in remote hp2p1_ offer: {e}"),
                None,
            );
        }
    };
    let offer_enc_pk = match offer.encryption_jwk.to_x25519() {
        Ok(pk) => pk,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INVALID_KEY",
                format!("Invalid encryptionJwk in remote hp2p1_ offer: {e}"),
                None,
            );
        }
    };
    if offer_sign_pk != verified_manifest.signing_pk
        || offer_enc_pk != verified_manifest.encryption_pk
    {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "KEY_PIN_MISMATCH",
            "Remote hp2p1_ offer keys do not match the running node's verified /v1/manifest keys (fail-closed)".to_string(),
            Some("Verify --remote-state-dir matches the running remote Hyphae daemon's state directory.".to_string()),
        );
    }
    if offer.endpoint != canonical_endpoint {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "INVALID_ENDPOINT",
            format!(
                "Remote hp2p1_ offer endpoint '{}' does not match expected '{canonical_endpoint}'",
                offer.endpoint
            ),
            None,
        );
    }

    if let Err(e) = ensure_dir(&state_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }
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

    // Step 4: Complete live mutual P2P handshake over `ssh://` (`POST /v1/p2p/pair/<offerId>`).
    let trust_tier = StoreTrustTier::Peer;
    let local_endpoint = load_local_public_endpoint(&state_dir);
    let live = match execute_live_p2p_handshake(
        &offer,
        &offer_sign_pk,
        &local_node_id,
        local_endpoint.as_deref(),
        &local_keys,
        &local_granted_scopes,
        trust_tier,
    ) {
        Ok(res) => res,
        Err(LiveHandshakeError::Unreachable(msg)) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "PAIR_HANDSHAKE_FAILED",
                msg,
                Some(
                    "Verify the remote node daemon is running and reachable via `hyp connect`."
                        .to_string(),
                ),
            );
        }
        Err(LiveHandshakeError::Rejected { code, message }) => {
            return emit_error(cmd, as_json, EXIT_ERROR, code, message, None);
        }
    };

    // Step 5: Persist peer (`ssh://` endpoint), pin JWKs, store authCredential, grants & manifest.
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

    let cred_ref = credential_secret_name("peer-auth", &remote_node_id);
    if let Err(e) = secrets.set(&cred_ref, &live.auth_credential) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "KEYSTORE_ERROR",
            format!("Failed to store peer authCredential in SecretStore: {e}"),
            None,
        );
    }

    let now_db = now_ms();
    let _ = db.local().ensure_metadata("node_id", &local_node_id);

    if let Err(e) = db.peers().upsert_peer(
        &PeerInput {
            peer_id: remote_node_id.clone(),
            endpoint: Some(canonical_endpoint.clone()),
            profile: PeerProfile::P2p,
            trust_tier,
            status: PeerStatus::Active,
            scopes: local_granted_scopes.clone(),
            auth_credential_ref: Some(cred_ref.clone()),
        },
        now_db,
    ) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DB_ERROR",
            format!("Failed to persist SSH peer '{remote_node_id}': {e}"),
            None,
        );
    }

    let kid = offer_sign_pk.kid();
    let enc_kid = offer_enc_pk.kid();
    let fingerprint = offer_sign_pk.fingerprint();
    let sign_jwk_json = match serde_json::to_string(&offer.signing_jwk) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ENCODE_ERROR",
                e.to_string(),
                None,
            );
        }
    };
    let enc_jwk_json = match serde_json::to_string(&offer.encryption_jwk) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ENCODE_ERROR",
                e.to_string(),
                None,
            );
        }
    };

    if let Err(e) = db.peers().upsert_peer_key(
        &PeerKeyInput {
            peer_id: remote_node_id.clone(),
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
            format!("Failed to pin remote signing JWK: {e}"),
            None,
        );
    }
    if let Err(e) = db.peers().upsert_peer_key(
        &PeerKeyInput {
            peer_id: remote_node_id.clone(),
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
            format!("Failed to pin remote encryption JWK: {e}"),
            None,
        );
    }

    let alice_grant_json = match serde_json::to_string(&live.alice_grant_signed) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ENCODE_ERROR",
                e.to_string(),
                None,
            );
        }
    };
    if let Err(e) = save_grant_idempotent(
        &db,
        &GrantInput {
            id: live.alice_grant_verified.id.clone(),
            peer_id: remote_node_id.clone(),
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
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ENCODE_ERROR",
                e.to_string(),
                None,
            );
        }
    };
    if let Err(e) = save_grant_idempotent(
        &db,
        &GrantInput {
            id: live.bob_grant_id.clone(),
            peer_id: remote_node_id.clone(),
            direction: GrantDirection::Inbound,
            signed_json: bob_grant_json,
            scopes: local_granted_scopes.clone(),
            trust_tier,
            issued_at: now_db,
            pair_by: None,
            expires_at: None,
        },
        now_db,
    ) {
        return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
    }

    let manifest_json = match serde_json::to_string(&live.signed_manifest) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ENCODE_ERROR",
                e.to_string(),
                None,
            );
        }
    };
    let caps: Vec<String> = live
        .manifest_payload
        .capabilities
        .iter()
        .map(|c| c.as_str().to_string())
        .collect();
    if let Err(e) = db.peers().cache_manifest(
        &remote_node_id,
        &ManifestCacheUpdate {
            manifest_version: live.manifest_payload.manifest_version as i64,
            manifest_json,
            etag: Some(live.manifest_etag.clone()),
            capabilities: caps.clone(),
            accept_downgrade: false,
        },
        now_db,
    ) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "MANIFEST_CACHE_ERROR",
            format!("Failed to cache verified manifest: {e}"),
            None,
        );
    }

    drop(db);
    let reload = try_reload_live_daemon(&state_dir, explicit_state);
    warnings.extend(reload.warnings);
    let daemon_reloaded = reload.reloaded;

    let next = if daemon_reloaded {
        vec![format!("hyp status --state-dir {}", state_dir.display())]
    } else {
        vec![
            "hyp service restart".to_string(),
            format!("hyp status --state-dir {}", state_dir.display()),
        ]
    };

    let data = json!({
        "mode": "p2p",
        "transport": "ssh",
        "nodeId": local_node_id,
        "peerId": remote_node_id,
        "target": ssh_ep.target(),
        "endpoint": canonical_endpoint,
        "kid": kid,
        "encryptionKid": enc_kid,
        "fingerprint": fingerprint,
        "grantedScopes": local_granted_scopes,
        "peerGrantedScopes": live.alice_grant_verified.scopes,
        "capabilities": caps,
        "handshakeCompleted": true,
        "daemonReloaded": daemon_reloaded,
        "credentialRef": cred_ref,
        "secretBackend": secrets.backend().as_str(),
        "stateDir": state_dir.display().to_string(),
    });

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Paired mutually over SSH with '{}' ({}, kid {})",
                remote_node_id, canonical_endpoint, kid
            )),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    Mutual P2P pairing completed over SSH (ssh://)");
        println!("      Local Node:   {local_node_id}");
        println!("      Remote Peer:  {remote_node_id}");
        println!("      Endpoint:     {canonical_endpoint}");
        println!("      Peer kid:     {kid}");
        println!("      Fingerprint:  {fingerprint}");
        println!("      Granted:      {}", local_granted_scopes.join(" "));
        println!(
            "      Peer Granted: {}",
            live.alice_grant_verified.scopes.join(" ")
        );
        if daemon_reloaded {
            println!("      Daemon:       Live daemon reloaded — SSH peer connected immediately.");
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    ExitCode::from(EXIT_OK)
}

// ============================================================================
// `pair revoke` (P1-4)
// ============================================================================

fn run_revoke(
    peer_id: String,
    reason: Option<String>,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    socket_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "pair revoke";

    if peer_id == LOCAL_NODE_ID || !is_valid_node_id(&peer_id) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_PEER_ID",
            format!(
                "Invalid peer '{peer_id}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
            ),
            Some("Example: hyp pair revoke bob@laptop".to_string()),
        );
    }

    let explicit_state = state_dir_arg.is_some() || config_arg.is_some();
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let db_path = state_dir.join("node.sqlite");
    if !db_path.exists() {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "PEER_NOT_FOUND",
            format!(
                "Peer '{peer_id}' is not paired (state database {} does not exist)",
                db_path.display()
            ),
            Some(format!(
                "Check paired peers with `hyp status --state-dir {}`.",
                state_dir.display()
            )),
        );
    }

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

    let existing_peer = match db.peers().get_peer(&peer_id) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "PEER_NOT_FOUND",
                format!("Peer '{peer_id}' is not paired in {}", db_path.display()),
                Some(format!(
                    "List known peers with `hyp status --state-dir {}`.",
                    state_dir.display()
                )),
            );
        }
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "DB_ERROR",
                format!("Failed to look up peer '{peer_id}': {e}"),
                None,
            );
        }
    };

    let mut warnings = Vec::new();
    let previous_status = existing_peer.status;
    let already_revoked = previous_status == PeerStatus::Revoked;
    if already_revoked {
        warnings.push(format!("Peer '{peer_id}' was already revoked."));
    }

    let now_db = now_ms();
    if let Err(e) = db
        .peers()
        .set_peer_status(&peer_id, PeerStatus::Revoked, now_db)
    {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DB_ERROR",
            format!("Failed to revoke peer '{peer_id}': {e}"),
            None,
        );
    }

    let grants = match db.peers().list_grants(Some(&peer_id)) {
        Ok(list) => list,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "DB_ERROR",
                format!("Failed to list grants for peer '{peer_id}': {e}"),
                None,
            );
        }
    };

    let clean_reason = reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    let rev_json = json!({
        "peerId": peer_id,
        "revokedAt": format_rfc3339_millis(now_db),
        "reason": clean_reason,
        "source": "cli:pair-revoke",
    })
    .to_string();

    let mut revoked_grants: Vec<String> = Vec::new();
    for g in &grants {
        if let Err(e) = db.peers().add_revocation(
            &RevocationInput {
                grant_id: g.id.clone(),
                peer_id: peer_id.clone(),
                signed_json: rev_json.clone(),
            },
            now_db,
        ) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "DB_ERROR",
                format!("Failed to record grant revocation '{}': {e}", g.id),
                None,
            );
        }
        revoked_grants.push(g.id.clone());
    }
    if revoked_grants.is_empty() {
        let synthetic_id = format!("peer-revoke:{peer_id}");
        if let Err(e) = db.peers().add_revocation(
            &RevocationInput {
                grant_id: synthetic_id.clone(),
                peer_id: peer_id.clone(),
                signed_json: rev_json,
            },
            now_db,
        ) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "DB_ERROR",
                format!("Failed to record peer revocation for '{peer_id}': {e}"),
                None,
            );
        }
        revoked_grants.push(synthetic_id);
    }

    drop(db);

    // Best-effort clear stored peer bearer/pairing credentials from SecretStore.
    let secrets = crate::config_file::open_secret_store(&state_dir, explicit_state);
    let mut candidate_keys = vec![
        credential_secret_name("peer-auth", &peer_id),
        credential_secret_name("pair-p2p", &peer_id),
        credential_secret_name("pair-am2", &peer_id),
    ];
    if let Some(ref cred_ref) = existing_peer.auth_credential_ref {
        if !candidate_keys.contains(cred_ref) {
            candidate_keys.push(cred_ref.clone());
        }
    }
    let literal_peer_auth = format!("peer-auth-{peer_id}");
    if hyp_crypto::keystore::validate_secret_name(&literal_peer_auth).is_ok()
        && !candidate_keys.contains(&literal_peer_auth)
    {
        candidate_keys.push(literal_peer_auth);
    }

    let mut credentials_cleared = 0usize;
    for key_name in candidate_keys {
        match secrets.delete(&key_name) {
            Ok(true) => credentials_cleared += 1,
            Ok(false) | Err(hyp_crypto::CryptoError::SecretNotFound(_)) => {}
            Err(e) => {
                warnings.push(format!(
                    "Best-effort SecretStore cleanup for '{key_name}' skipped: {e}"
                ));
            }
        }
    }

    let socket_path =
        socket_arg.unwrap_or_else(|| resolve_pair_daemon_socket(&state_dir, explicit_state));
    let reload = try_reload_live_daemon_at_socket(&socket_path);
    warnings.extend(reload.warnings);
    let daemon_reloaded = reload.reloaded;

    let next = if daemon_reloaded {
        vec![format!("hyp status --state-dir {}", state_dir.display())]
    } else {
        vec![
            "hyp service restart".to_string(),
            format!("hyp status --state-dir {}", state_dir.display()),
        ]
    };

    let data = json!({
        "peerId": peer_id,
        "previousStatus": previous_status.as_str(),
        "status": PeerStatus::Revoked.as_str(),
        "alreadyRevoked": already_revoked,
        "revokedGrants": revoked_grants,
        "reason": clean_reason,
        "credentialsCleared": credentials_cleared,
        "daemonReloaded": daemon_reloaded,
        "socketPath": socket_path.display().to_string(),
        "stateDir": state_dir.display().to_string(),
    });

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(if already_revoked {
                format!("Peer '{peer_id}' is already revoked")
            } else {
                format!("Revoked peer '{peer_id}' and cleared stored credentials")
            }),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        let tag = if already_revoked { "WARN" } else { "OK" };
        println!("{tag:<4}  Revoked paired peer '{peer_id}'");
        println!("      Previous:    {}", previous_status.as_str());
        println!("      Status:      revoked");
        if let Some(ref r) = clean_reason {
            println!("      Reason:      {r}");
        }
        println!(
            "      Grants:      {} revocation(s) recorded",
            revoked_grants.len()
        );
        println!("      Secrets:     {credentials_cleared} credential(s) cleared");
        if daemon_reloaded {
            println!(
                "      Daemon:      Live daemon reloaded — outbound link dropped immediately."
            );
        } else {
            println!(
                "      Daemon:      Live daemon not reachable — run `hyp service restart` to apply if running."
            );
        }
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

    #[test]
    fn parse_tailscale_magicdns_endpoint_valid_stopped_malformed_and_injections() {
        // 1. Valid active Tailscale status with trailing FQDN dot + Online: true
        let valid = br#"{
            "Version": "1.76.0",
            "BackendState": "Running",
            "Self": {
                "HostName": "alice-mbp",
                "DNSName": "alice-mbp.tail9f3a.ts.net.",
                "Online": true
            }
        }"#;
        assert_eq!(
            parse_tailscale_magicdns_endpoint(valid).as_deref(),
            Some("https://alice-mbp.tail9f3a.ts.net")
        );

        // 2. Valid mixed-case DNSName without trailing dot and with Online omitted -> lowercased
        let mixed = br#"{
            "BackendState": "Running",
            "Self": { "DNSName": "Alice-MBP.Tail9F3A.TS.NET" }
        }"#;
        assert_eq!(
            parse_tailscale_magicdns_endpoint(mixed).as_deref(),
            Some("https://alice-mbp.tail9f3a.ts.net")
        );

        // 3. Offline / non-Running BackendStates MUST be rejected fail-closed
        for state in [
            "Stopped",
            "NeedsLogin",
            "Starting",
            "NoState",
            "running",
            "",
        ] {
            let payload = serde_json::to_vec(&json!({
                "BackendState": state,
                "Self": { "DNSName": "alice.tail9f3a.ts.net.", "Online": true }
            }))
            .unwrap();
            assert_eq!(
                parse_tailscale_magicdns_endpoint(&payload),
                None,
                "BackendState={state:?} must be rejected"
            );
        }

        // 4. Self.Online == false MUST be rejected even if BackendState == Running
        let offline_self = br#"{
            "BackendState": "Running",
            "Self": { "DNSName": "alice.tail9f3a.ts.net.", "Online": false }
        }"#;
        assert_eq!(parse_tailscale_magicdns_endpoint(offline_self), None);

        // 5. Injection attempts, malformed hostnames, single-label names, IPv4 literals -> rejected
        let long_label = format!("{}.ts.net.", "a".repeat(64));
        let long_host = format!(
            "{}.{}.{}.{}.ts.net.",
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60),
            "d".repeat(65)
        );
        let bad_dns_names = [
            "",
            ".",
            "alice",
            "localhost",
            "100.64.0.1",
            "127.0.0.1.",
            "alice.tail.ts.net..",
            ".alice.tail.ts.net.",
            "alice..ts.net.",
            "-alice.tail.ts.net.",
            "alice-.tail.ts.net.",
            "alice.tail.ts.net/evil",
            "alice.tail.ts.net?foo=bar",
            "alice.tail.ts.net#frag",
            "evil.com@alice.tail.ts.net",
            "alice.tail.ts.net:8443",
            "alice.tail.ts.net\nevil.example",
            " alice.tail.ts.net.",
            "alice.tail.ts.net ",
            "alice_bad.tail.ts.net.",
            "https://alice.tail.ts.net",
            long_label.as_str(),
            long_host.as_str(),
        ];
        for bad in bad_dns_names {
            let payload = serde_json::to_vec(&json!({
                "BackendState": "Running",
                "Self": { "DNSName": bad, "Online": true }
            }))
            .unwrap();
            assert_eq!(
                parse_tailscale_magicdns_endpoint(&payload),
                None,
                "invalid/injected DNSName {bad:?} must be rejected"
            );
        }

        // 6. Malformed JSON / empty / wrong structure -> None (never panics!)
        for junk in [
            &b""[..],
            b"not json",
            b"null",
            b"[]",
            b"{}",
            br#"{"BackendState":"Running"}"#,
            br#"{"BackendState":"Running","Self":null}"#,
            br#"{"BackendState":"Running","Self":{"DNSName":123}}"#,
        ] {
            assert_eq!(parse_tailscale_magicdns_endpoint(junk), None);
        }

        // 7. Hermetic disabled sentinel never spawns a binary
        assert_eq!(
            detect_tailscale_magicdns_endpoint_with_bin("none", Duration::from_millis(50)),
            None
        );
        assert_eq!(
            detect_tailscale_magicdns_endpoint_with_bin("", Duration::from_millis(50)),
            None
        );
    }

    #[test]
    fn p1_8_strip_privileged_default_scopes_and_inspect_warnings() {
        let mut warnings = Vec::new();
        let safe = strip_privileged_default_scopes(
            vec![
                "dm:send".to_string(),
                "bridge:post=slack:#general".to_string(),
                "forward:via=acme-hub".to_string(),
                "kv:read=pair/*".to_string(),
            ],
            &mut warnings,
        );
        assert_eq!(safe, vec!["dm:send", "kv:read=pair/*"]);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("bridge:post=slack:#general"));
        assert!(warnings[0].contains("forward:via=acme-hub"));

        // Only privileged scopes requested -> falls back to minimal DM pair
        let mut only_priv_warnings = Vec::new();
        let fallback = strip_privileged_default_scopes(
            vec!["bridge:post=telegram:*".to_string()],
            &mut only_priv_warnings,
        );
        assert_eq!(fallback, vec!["dm:send", "dm:receive"]);
        assert_eq!(only_priv_warnings.len(), 1);

        // `warn_privileged_token_scopes` warns on `*`, `bridge:post`, and `forward:via`
        let mut insp_warnings = Vec::new();
        warn_privileged_token_scopes(
            "requests",
            &[
                "*".to_string(),
                "bridge:post=slack:#ops".to_string(),
                "forward:via=*".to_string(),
            ],
            &mut insp_warnings,
        );
        assert_eq!(insp_warnings.len(), 3);
        assert!(insp_warnings.iter().any(|w| w.contains("wildcard '*'")));
        assert!(insp_warnings.iter().any(|w| w.contains("bridge:post")));
        assert!(insp_warnings.iter().any(|w| w.contains("forward:via")));

        // Normal `member` scopes emit zero warnings
        let mut normal_warnings = Vec::new();
        warn_privileged_token_scopes(
            "offers",
            &ScopePreset::Member.expand(),
            &mut normal_warnings,
        );
        assert!(normal_warnings.is_empty());
    }

    #[test]
    fn p1_4_and_p1_14_revoke_and_invite_node_id_mismatch_unit() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path();

        // 1. P1-4: revoking an absent peer fails cleanly with EXIT_ERROR (`PEER_NOT_FOUND`).
        let missing_code = run_revoke(
            "ghost@box".to_string(),
            None,
            Some(state.to_path_buf()),
            None,
            None,
            true,
        );
        assert_eq!(missing_code, ExitCode::from(EXIT_ERROR));

        // Seed a paired peer + grant + bearer credential in SecretStore.
        let db = NodeDb::open(state.join("node.sqlite")).unwrap();
        let now = now_ms();
        let cred_ref = credential_secret_name("peer-auth", "bob@laptop");
        let secrets = crate::config_file::open_secret_store(state, true);
        secrets.set(&cred_ref, "secret-bearer-token-val").unwrap();
        db.peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: "bob@laptop".to_string(),
                    endpoint: Some("https://bob.tailnet.ts.net".to_string()),
                    profile: PeerProfile::P2p,
                    trust_tier: StoreTrustTier::Peer,
                    status: PeerStatus::Active,
                    scopes: vec!["dm:*".to_string()],
                    auth_credential_ref: Some(cred_ref.clone()),
                },
                now,
            )
            .unwrap();
        db.peers()
            .add_grant(
                &GrantInput {
                    id: "grant-bob-1".to_string(),
                    peer_id: "bob@laptop".to_string(),
                    direction: GrantDirection::Inbound,
                    signed_json: "{}".to_string(),
                    scopes: vec!["dm:*".to_string()],
                    trust_tier: StoreTrustTier::Peer,
                    issued_at: now,
                    pair_by: None,
                    expires_at: None,
                },
                now,
            )
            .unwrap();
        drop(db);

        let revoke_ok = run_revoke(
            "bob@laptop".to_string(),
            Some("device lost".to_string()),
            Some(state.to_path_buf()),
            None,
            Some(state.join("missing.sock")),
            true,
        );
        assert_eq!(revoke_ok, ExitCode::from(EXIT_OK));

        let db_after = NodeDb::open(state.join("node.sqlite")).unwrap();
        let peer_after = db_after.peers().get_peer("bob@laptop").unwrap().unwrap();
        assert_eq!(peer_after.status, PeerStatus::Revoked);
        assert!(db_after.peers().is_grant_revoked("grant-bob-1").unwrap());
        assert!(secrets.get(&cred_ref).is_err());

        // Idempotent second revoke returns EXIT_OK cleanly.
        let revoke_again = run_revoke(
            "bob@laptop".to_string(),
            None,
            Some(state.to_path_buf()),
            None,
            Some(state.join("missing.sock")),
            true,
        );
        assert_eq!(revoke_again, ExitCode::from(EXIT_OK));

        // 2. P1-14: `pair invite --mode p2p` rejects mismatched --node-id when node.json exists
        //    unless `--force-node-id` is passed.
        fs::write(
            state.join("node.json"),
            r#"{"v":2,"nodeId":"alice@macbook","profile":"p2p"}"#,
        )
        .unwrap();
        let mismatch = run_invite(
            InviteMode::P2p,
            "wrong@host".to_string(),
            Some("https://alice.tailnet.ts.net".to_string()),
            None,
            None,
            vec![],
            vec![],
            24,
            None,
            Some(state.to_path_buf()),
            false,
            true,
        );
        assert_eq!(mismatch, ExitCode::from(EXIT_USAGE));

        let forced = run_invite(
            InviteMode::P2p,
            "wrong@host".to_string(),
            Some("https://alice.tailnet.ts.net".to_string()),
            None,
            None,
            vec![],
            vec![],
            24,
            None,
            Some(state.to_path_buf()),
            true,
            true,
        );
        assert_eq!(forced, ExitCode::from(EXIT_OK));
    }

    #[test]
    fn n2_refuses_repointing_existing_router_or_p2p_peer_via_hp2p1_or_am2() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path();
        let now = now_ms();

        // Seed an existing active Router hub peer (`acme-team`) pinned to `https://hub.acme.example`
        // and its real public signing key (`hub_keys`).
        let hub_keys = NodeIdentityKeys::generate().unwrap();
        let hub_sign_jwk_json = serde_json::to_string(&hub_keys.signing_jwk()).unwrap();
        let db = NodeDb::open(state.join("node.sqlite")).unwrap();
        db.peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: "acme-team".to_string(),
                    endpoint: Some("https://hub.acme.example".to_string()),
                    profile: PeerProfile::Router,
                    trust_tier: StoreTrustTier::Org,
                    status: PeerStatus::Active,
                    scopes: vec!["dm:*".to_string()],
                    auth_credential_ref: Some("peer-auth-acme".to_string()),
                },
                now,
            )
            .unwrap();
        db.peers()
            .upsert_peer_key(
                &PeerKeyInput {
                    peer_id: "acme-team".to_string(),
                    kid: hub_keys.kid(),
                    key_use: KeyUse::Signing,
                    jwk_json: hub_sign_jwk_json,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )
            .unwrap();

        // 1. Direct pin guard checks:
        //    - Same Router profile & same endpoint (even with trailing slash) -> OK
        assert!(
            check_existing_peer_pin(
                &db,
                "acme-team",
                PeerProfile::Router,
                "https://hub.acme.example/"
            )
            .is_ok()
        );

        //    - Profile change (Router -> P2p) -> PEER_PROFILE_CONFLICT
        let profile_err = check_existing_peer_pin(
            &db,
            "acme-team",
            PeerProfile::P2p,
            "https://hub.acme.example",
        )
        .unwrap_err();
        assert_eq!(profile_err.0, "PEER_PROFILE_CONFLICT");

        //    - Endpoint change on same Router profile -> PEER_ENDPOINT_CONFLICT
        let endpoint_err = check_existing_peer_pin(
            &db,
            "acme-team",
            PeerProfile::Router,
            "https://evil.attacker.example",
        )
        .unwrap_err();
        assert_eq!(endpoint_err.0, "PEER_ENDPOINT_CONFLICT");

        drop(db);

        // 2. End-to-end offline attack: attacker crafts an unsigned `hp2p1_` carrying the hub's
        //    real public keys (`hub_keys`, bypassing `check_existing_signing_pin`!) to re-point
        //    `acme-team` to `https://evil.attacker.example` as a P2p peer.
        let future_exp = format_rfc3339_millis(now_unix_ms() + 3_600_000);
        let forged_offer = create_p2p_offer(
            "offer-n2-hijack",
            "acme-team",
            "https://evil.attacker.example",
            &hub_keys,
            vec!["dm:send".to_string(), "dm:receive".to_string()],
            vec![],
            &future_exp,
        )
        .unwrap();
        let forged_hp2p1 = encode_hp2p1(&forged_offer).unwrap();

        let code = accept_hp2p1(
            &forged_hp2p1,
            Some(state.to_path_buf()),
            Some("bob@laptop".to_string()),
            None,
            true,
            Vec::new(),
            true,
        );
        assert_eq!(
            code,
            ExitCode::from(EXIT_ERROR),
            "N2: hp2p1_ --offline must refuse re-pointing an existing Router peer"
        );

        // Confirm SQLite record is 100% untouched (still Router, still https://hub.acme.example).
        let db_check = NodeDb::open(state.join("node.sqlite")).unwrap();
        let hub_after = db_check.peers().get_peer("acme-team").unwrap().unwrap();
        assert_eq!(hub_after.profile, PeerProfile::Router);
        assert_eq!(
            hub_after.endpoint.as_deref(),
            Some("https://hub.acme.example")
        );

        // 3. Also test `accept_am2 --offline` cannot re-point `acme-team` to a different router URL!
        let admin_kp = Ed25519KeyPair::generate().unwrap();
        let issued = issue_grant_v1(
            &admin_kp,
            "bob@laptop",
            &["messages:send"],
            3_600_000,
            now_unix_ms(),
        )
        .unwrap();
        let hijacked_am2_val = json!({
            "v": 2,
            "router": "https://evil-hub.attacker.example",
            "nodeId": "acme-team",
            "peerId": "bob@laptop",
            "adminJwk": admin_kp.to_jwk(),
            "pairingCode": issued.code,
            "requireE2ee": true,
            "scopes": ["dm:send", "dm:receive"]
        });
        let hijacked_am2 = format!(
            "{AM2_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&hijacked_am2_val).unwrap())
        );
        drop(db_check);

        let am2_code = accept_am2(
            &hijacked_am2,
            Some(state.to_path_buf()),
            Some("bob@laptop".to_string()),
            None,
            true,
            Vec::new(),
            true,
        );
        assert_eq!(
            am2_code,
            ExitCode::from(EXIT_ERROR),
            "N2: am2_ --offline must refuse re-pointing an existing Router peer's endpoint"
        );

        let db_check2 = NodeDb::open(state.join("node.sqlite")).unwrap();
        let hub_after2 = db_check2.peers().get_peer("acme-team").unwrap().unwrap();
        assert_eq!(
            hub_after2.endpoint.as_deref(),
            Some("https://hub.acme.example")
        );

        // 4. Same-profile P2p peer cannot be re-pointed to a new endpoint either!
        let alice_keys = NodeIdentityKeys::generate().unwrap();
        db_check2
            .peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: "alice@macbook".to_string(),
                    endpoint: Some("https://alice.tailnet.ts.net".to_string()),
                    profile: PeerProfile::P2p,
                    trust_tier: StoreTrustTier::Peer,
                    status: PeerStatus::Active,
                    scopes: vec!["dm:send".to_string()],
                    auth_credential_ref: Some("peer-auth-alice".to_string()),
                },
                now,
            )
            .unwrap();
        let p2p_ep_err = check_existing_peer_pin(
            &db_check2,
            "alice@macbook",
            PeerProfile::P2p,
            "https://evil.attacker.example",
        )
        .unwrap_err();
        assert_eq!(p2p_ep_err.0, "PEER_ENDPOINT_CONFLICT");

        // 5. After explicitly revoking `acme-team`, re-pairing to a new endpoint/profile is allowed!
        db_check2
            .peers()
            .set_peer_status("acme-team", PeerStatus::Revoked, now + 1)
            .unwrap();
        assert!(
            check_existing_peer_pin(
                &db_check2,
                "acme-team",
                PeerProfile::P2p,
                "https://new.acme.example"
            )
            .is_ok()
        );
        assert!(alice_keys.kid().len() > 10);
    }
}
