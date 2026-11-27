//! `hyp deploy` — Internet deployment provider catalog, hardened kit generator,
//! and fail-closed config + live manifest health checker.

use crate::drop_cmd::validate_relay_url;
use crate::ui::{
    CheckStatus, CliCheck, CliError, CommandResult, EXIT_ERROR, EXIT_OK, JsonEnvelope,
    print_checks, print_json, print_next_steps, print_warnings,
};
use clap::{Subcommand, ValueEnum};
use http_body_util::{BodyExt, Empty};
use hyp_crypto::keys::OkpJwk as CryptoOkpJwk;
use hyp_crypto::pairing::{validate_endpoint_origin, validate_http_endpoint_origin};
use hyp_crypto::rfc3339::{now_unix_ms, parse_rfc3339_millis};
use hyp_harness::executable::is_executable_file;
use hyp_node::engine::{DropRelayConfig, normalize_drop_portal_url};
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_node_id};
use hyp_proto::manifest::{NodeManifestPayload, SignedNodeManifest};
use hyp_proto::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const MAX_MANIFEST_RESPONSE_BYTES: usize = 512 * 1024;
const PROBE_TIMEOUT_SECS: u64 = 10;

const DEFAULT_DROP_RELAY_MEMORY_MB: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeployProvider {
    Tailscale,
    Vps,
    Docker,
    Cloudflare,
    Fly,
    PublicNode,
    DropRelay,
}

impl DeployProvider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tailscale => "tailscale",
            Self::Vps => "vps",
            Self::Docker => "docker",
            Self::Cloudflare => "cloudflare",
            Self::Fly => "fly",
            Self::PublicNode => "public-node",
            Self::DropRelay => "drop-relay",
        }
    }

    pub const fn default_profile(self) -> DeployProfile {
        match self {
            Self::PublicNode => DeployProfile::Public,
            Self::Tailscale
            | Self::Vps
            | Self::Docker
            | Self::Cloudflare
            | Self::Fly
            | Self::DropRelay => DeployProfile::Router,
        }
    }

    pub const fn default_node_id(self) -> &'static str {
        match self {
            Self::Tailscale => "tailnet-node",
            Self::Vps => "team-node",
            Self::Docker => "team-node",
            Self::Cloudflare => "homelab-node",
            Self::Fly => "fly-node",
            Self::PublicNode => "public.hyphae.to",
            Self::DropRelay => "drop-relay",
        }
    }

    pub const fn default_domain(self) -> &'static str {
        match self {
            Self::Tailscale => "hyphae.your-tailnet.ts.net",
            Self::Vps => "mesh.example.com",
            Self::Docker => "mesh.example.com",
            Self::Cloudflare => "mesh.example.com",
            Self::Fly => "hyphae-node.fly.dev",
            Self::PublicNode => "public.hyphae.to",
            Self::DropRelay => "drop.example.com",
        }
    }

    pub const fn default_bind(self) -> &'static str {
        match self {
            Self::Docker | Self::Fly | Self::DropRelay => "0.0.0.0:8790",
            Self::Tailscale | Self::Vps | Self::Cloudflare | Self::PublicNode => "127.0.0.1:8790",
        }
    }

    pub const fn uses_container_proxy_bind(self) -> bool {
        matches!(self, Self::Docker | Self::Fly | Self::DropRelay)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeployProfile {
    Router,
    P2p,
    Public,
}

impl DeployProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::P2p => "p2p",
            Self::Public => "public",
        }
    }

    /// Maps to the unified Hyphae v2 Node profile (`router` or `p2p`; `public` runs as hardened `router`).
    pub const fn node_profile_str(self) -> &'static str {
        match self {
            Self::Router | Self::Public => "router",
            Self::P2p => "p2p",
        }
    }
}

#[derive(Subcommand)]
pub enum DeployCommand {
    /// Discover or configure public HTTPS routing for a dedicated loopback webhook receiver
    Webhook(crate::webhook_deploy::WebhookArgs),
    /// List all 7 supported internet deployment providers with TLS, NAT, and pros/cons
    Providers {
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Generate hardened, production-ready deployment kit and node.json for a provider
    Init {
        /// Target deployment provider
        #[arg(value_enum)]
        provider: DeployProvider,
        /// Canonical Hyphae nodeId (e.g. acme-team, public.hyphae.to, drop-relay)
        #[arg(long)]
        node_id: Option<String>,
        /// Public or tailnet HTTPS hostname (without scheme, e.g. mesh.example.com)
        #[arg(long)]
        domain: Option<String>,
        /// Listen address (default 127.0.0.1:8790; 0.0.0.0:8790 inside isolated Docker/Fly/Drop-Relay containers)
        #[arg(long)]
        bind: Option<String>,
        /// Node profile (router, p2p, or public)
        #[arg(long, value_enum)]
        profile: Option<DeployProfile>,
        /// Enable the opt-in RAM-only Blind Drop Relay block in generated node.json
        #[arg(long)]
        enable_drop_relay: bool,
        /// Drop Relay maximum RAM budget in MiB (default: 256)
        #[arg(long = "drop-max-memory-mb", alias = "max-memory-mb")]
        drop_max_memory_mb: Option<usize>,
        /// Output directory for generated deployment artifacts
        #[arg(long)]
        out: Option<PathBuf>,
        /// Allow overwriting existing files in --out
        #[arg(long)]
        force: bool,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Detect local deployment tools, validate node.json fail-closed, and probe GET /v1/manifest
    Check {
        /// Remote or local node URL to probe (https://... or loopback http://127.0.0.1:...)
        #[arg(long)]
        url: Option<String>,
        /// Path to node.json config file to validate fail-closed
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedTool {
    pub name: &'static str,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderInfo {
    id: &'static str,
    name: &'static str,
    summary: &'static str,
    default_profile: &'static str,
    tls_method: &'static str,
    nat_firewall: &'static str,
    best_for: &'static str,
    pros: &'static [&'static str],
    cons: &'static [&'static str],
    required_tools: &'static [&'static str],
    detected: bool,
    init_command: &'static str,
}

pub fn run_deploy(command: DeployCommand) -> CommandResult {
    match command {
        DeployCommand::Webhook(args) => crate::webhook_deploy::run(args),
        DeployCommand::Providers { json } => {
            CommandResult::new("deploy providers", json, run_providers(json))
        }
        DeployCommand::Init {
            provider,
            node_id,
            domain,
            bind,
            profile,
            enable_drop_relay,
            drop_max_memory_mb,
            out,
            force,
            json,
        } => CommandResult::new(
            "deploy init",
            json,
            run_init(
                provider,
                node_id,
                domain,
                bind,
                profile,
                enable_drop_relay,
                drop_max_memory_mb,
                out,
                force,
                json,
            ),
        ),
        DeployCommand::Check { url, config, json } => {
            CommandResult::new("deploy check", json, run_check(url, config, json))
        }
    }
}

// ============================================================================
// Tool Detection (pure PATH scan — instant, zero hangs)
// ============================================================================

const DEPLOY_TOOL_NAMES: &[&str] = &[
    "tailscale",
    "cloudflared",
    "docker",
    "caddy",
    "flyctl",
    "systemctl",
];

pub(crate) fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = candidate.with_extension("exe");
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn detect_local_tools() -> Vec<DetectedTool> {
    DEPLOY_TOOL_NAMES
        .iter()
        .map(|&name| {
            let path = find_in_path(name).map(|p| p.display().to_string());
            DetectedTool {
                name,
                installed: path.is_some(),
                path,
            }
        })
        .collect()
}

// ============================================================================
// `deploy providers`
// ============================================================================

fn build_provider_catalog(tools: &[DetectedTool]) -> Vec<ProviderInfo> {
    let has_tool = |name: &str| tools.iter().any(|t| t.name == name && t.installed);
    vec![
        ProviderInfo {
            id: "tailscale",
            name: "Tailscale Serve (+ optional Funnel)",
            summary: "Private tailnet HTTPS with MagicDNS certificates and optional scoped Funnel for public webhooks.",
            default_profile: "router",
            tls_method: "Tailscale MagicDNS automatic Let's Encrypt TLS (private tailnet)",
            nat_firewall: "Zero port forwarding or public IP required; works behind CGNAT and corporate firewalls",
            best_for: "Solo multi-machine meshes, small engineering teams, and direct P2P laptops",
            pros: &[
                "Zero open inbound internet ports",
                "Automatic HTTPS certificates via Tailscale Serve",
                "Works identically on laptops, SSH devboxes, and homelabs",
                "A separate Funnel port can expose a dedicated webhook listener",
            ],
            cons: &[
                "Requires Tailscale client on participating nodes",
                "Funnel exposes public traffic if enabled without path scoping",
            ],
            required_tools: &["tailscale"],
            detected: has_tool("tailscale"),
            init_command: "hyp deploy init tailscale --node-id my-node --domain hyphae.your-tailnet.ts.net",
        },
        ProviderInfo {
            id: "vps",
            name: "Linux VPS (Caddy + hardened systemd)",
            summary: "Dedicated Linux host (Hetzner, DigitalOcean, AWS, Linode) with Caddy auto-TLS and strict systemd sandboxing.",
            default_profile: "router",
            tls_method: "Caddy automatic Let's Encrypt / ZeroSSL HTTPS with SSE flush_interval -1",
            nat_firewall: "Public IPv4/IPv6 with inbound TCP 80/443 to Caddy; Hyphae bound strictly to 127.0.0.1:8790",
            best_for: "Production team hubs requiring full control, low latency, and predictable monthly cost",
            pros: &[
                "Lowest memory footprint (~10-25 MB RSS for static Rust binary)",
                "Caddy handles automatic TLS renewal and unbuffered SSE streaming",
                "Hardened systemd isolation (ProtectSystem=strict, NoNewPrivileges, 0700 state)",
            ],
            cons: &[
                "Requires managing a Linux VM and DNS A/AAAA records",
                "Needs ports 80 and 443 reachable for ACME certificate issuance",
            ],
            required_tools: &["caddy", "systemctl"],
            detected: has_tool("caddy") && has_tool("systemctl"),
            init_command: "hyp deploy init vps --node-id acme-team --domain mesh.example.com",
        },
        ProviderInfo {
            id: "docker",
            name: "Docker + Caddy Compose Stack",
            summary: "Minimal multi-stage Rust Dockerfile paired with Caddy auto-TLS on an isolated Docker bridge network.",
            default_profile: "router",
            tls_method: "Caddy sidecar automatic HTTPS with SSE flush_interval -1",
            nat_firewall: "Only Caddy publishes 80/443; hyphae-node stays private on internal Docker network",
            best_for: "Container-first teams, repeatable CI/CD deployments, and quick staging nodes",
            pros: &[
                "Reproducible multi-stage static Rust build with non-root UID 10001",
                "Zero host port exposure on hyphae-node (internal network only)",
                "Built-in manifest healthcheck and persistent Docker volumes",
            ],
            cons: &[
                "Requires Docker Engine and Compose plugin on host",
                "Slightly higher disk/memory overhead than bare systemd",
            ],
            required_tools: &["docker"],
            detected: has_tool("docker"),
            init_command: "hyp deploy init docker --node-id acme-team --domain mesh.example.com",
        },
        ProviderInfo {
            id: "cloudflare",
            name: "Cloudflare Tunnel (cloudflared)",
            summary: "Outbound-only encrypted tunnel to Cloudflare Edge with zero open inbound ports.",
            default_profile: "router",
            tls_method: "Cloudflare Edge TLS terminated before outbound-only tunnel to 127.0.0.1:8790",
            nat_firewall: "Zero inbound ports required; works cleanly behind CGNAT, home routers, and laptops",
            best_for: "Homelabs, residential ISPs behind CGNAT, and laptops needing a public webhook or team URL",
            pros: &[
                "No public IP or router port forwarding needed",
                "Hides origin IP behind Cloudflare Edge + DDoS protection",
                "Pairs cleanly with Cloudflare Access or Hyphae Admin-CA grants",
            ],
            cons: &[
                "Requires a Cloudflare account and domain managed by Cloudflare DNS",
                "Cloudflare terminates outer TLS (Hyphae HPKE E2EE remains end-to-end)",
            ],
            required_tools: &["cloudflared"],
            detected: has_tool("cloudflared"),
            init_command: "hyp deploy init cloudflare --node-id homelab-node --domain mesh.example.com",
        },
        ProviderInfo {
            id: "fly",
            name: "Fly.io Always-On Machine",
            summary: "Managed global edge VM with persistent /var/lib/hyphae volume, auto-HTTPS, and always-on SSE.",
            default_profile: "router",
            tls_method: "Fly Proxy automatic HTTPS edge termination with force_https = true",
            nat_firewall: "Managed edge networking; min_machines_running = 1 keeps SSE streams alive",
            best_for: "Zero-ops cloud hosting for small teams or public stream hubs in under 3 minutes",
            pros: &[
                "One-command deploy via flyctl with automatic HTTPS",
                "Persistent volume at /var/lib/hyphae preserves node.sqlite and keys",
                "Built-in /v1/manifest health check and auto-restart",
            ],
            cons: &[
                "Requires persistent always-on machine (auto_stop_machines = off) for SSE",
                "Managed cloud pricing instead of self-hosted hardware",
            ],
            required_tools: &["flyctl"],
            detected: has_tool("flyctl"),
            init_command: "hyp deploy init fly --node-id fly-node --domain hyphae-node.fly.dev",
        },
        ProviderInfo {
            id: "public-node",
            name: "Public Read-Only Node (public.hyphae.to Kit)",
            summary: "Turnkey read-only public hub with guest-ro confinement, demand-driven github-public ETag poller, and strict rate limits.",
            default_profile: "public",
            tls_method: "Caddy automatic HTTPS (flush_interval -1) + systemd & Docker Compose kits included",
            nat_firewall: "Public HTTPS 80/443 via Caddy; hyphae-node bound to 127.0.0.1:8790 with deny forwarding",
            best_for: "Hosting public.hyphae.to or an open-source community GitHub event hub with zero DM/write exposure",
            pros: &[
                "Pre-confined guest-ro scope: exact.repo required, max 10 repos, 60 wakes/hr",
                "Demand-driven deduplicated GitHub ETag poller (304 Not Modified = 0 quota)",
                "Zero DM, channel write, or KV write privileges for guests",
                "Includes Caddyfile, hardened systemd unit, Dockerfile, and docker-compose.yml",
            ],
            cons: &[
                "Read-only by design; not intended for private team DMs or private repos",
                "Requires a dedicated public domain and optional GitHub PAT for higher ETag rate limits",
            ],
            required_tools: &["caddy", "docker", "systemctl"],
            detected: has_tool("caddy") || has_tool("docker"),
            init_command: "hyp deploy init public-node --node-id public.hyphae.to --domain public.hyphae.to",
        },
        ProviderInfo {
            id: "drop-relay",
            name: "Self-Hosted Blind Drop Relay (Zero-Disk RAM)",
            summary: "60-second privacy-hardened RAM-only blind Drop Relay for Verified Human Drops (https://hyphae.to/drop).",
            default_profile: "router",
            tls_method: "Caddy automatic HTTPS (zero /v1/drops access logs, flush_interval -1) + Fly.io & Docker Compose",
            nat_firewall: "Public HTTPS 80/443 via Caddy/Fly; container bind 0.0.0.0:8790 (loopback 127.0.0.1:8790 on systemd) with zero disk persistence for drops",
            best_for: "Self-hosting a zero-knowledge, RAM-only blind Drop Relay for your own phone-to-agent secret & directive drops",
            pros: &[
                "100% RAM-only opaque HPKE ciphertexts — zero disk or SQLite persistence for drops",
                "Privacy-hardened Caddyfile discards access logs on /v1/drops*",
                "Strict CORS allowlist (https://hyphae.to) with Chrome Private Network Access support",
                "Includes Caddyfile, read-only docker-compose.yml, fly.toml, and hardened systemd unit",
            ],
            cons: &[
                "Requires an HTTPS domain reachable from your mobile browser",
                "In-flight drops are strictly ephemeral and vanish on restart by design",
            ],
            required_tools: &["caddy", "docker", "flyctl", "systemctl"],
            detected: has_tool("caddy") || has_tool("docker") || has_tool("flyctl"),
            init_command: "hyp deploy init drop-relay --domain drop.example.com --drop-max-memory-mb 256",
        },
    ]
}

fn run_providers(as_json: bool) -> Result<ExitCode, CliError> {
    let tools = detect_local_tools();
    let providers = build_provider_catalog(&tools);
    let next = vec![
        "hyp deploy init tailscale --out ./deploy-tailscale".to_string(),
        "hyp deploy init vps --node-id acme-team --domain mesh.example.com --out ./deploy-vps"
            .to_string(),
        "hyp deploy check".to_string(),
    ];

    if as_json {
        let envelope = JsonEnvelope::ok(
            "deploy providers".to_string(),
            format!(
                "{} internet deployment providers supported",
                providers.len()
            ),
            json!({
                "providers": providers,
                "detectedTools": tools,
            }),
        )
        .next(next);
        print_json(&envelope);
        return Ok(ExitCode::from(EXIT_OK));
    }

    println!("Hyphae Internet Deployment Providers");
    println!();
    println!(
        "{:<12}  {:<8}  {:<36}  Best For",
        "Provider", "Local", "Name"
    );
    println!("{}", "-".repeat(104));
    for p in &providers {
        let tag = if p.detected { "OK" } else { "-" };
        println!("{:<12}  {:<8}  {:<36}  {}", p.id, tag, p.name, p.best_for);
    }
    println!();
    for p in &providers {
        println!("[{}] {}", p.id, p.name);
        println!("  TLS:      {}", p.tls_method);
        println!("  NAT/FW:   {}", p.nat_firewall);
        println!("  Pros:     {}", p.pros.join(" · "));
        println!("  Cons:     {}", p.cons.join(" · "));
        println!("  Init:     {}", p.init_command);
        println!();
    }
    print_next_steps(&next);
    Ok(ExitCode::from(EXIT_OK))
}

// ============================================================================
// `deploy init`
// ============================================================================

fn validate_domain_hostname(domain: &str) -> Result<String, String> {
    let trimmed = domain.trim();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err("domain must be 1..=253 characters".to_string());
    }
    if trimmed.contains("://") || trimmed.contains('/') || trimmed.contains('@') {
        return Err(
            "domain must be a bare hostname without scheme, path, or userinfo (e.g. mesh.example.com)"
                .to_string(),
        );
    }
    if trimmed
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')))
    {
        return Err("domain may only contain ASCII letters, digits, dots, and hyphens".to_string());
    }
    if trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || trimmed.starts_with('-')
        || trimmed.ends_with('-')
        || trimmed.contains("..")
    {
        return Err("domain has malformed DNS labels".to_string());
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn validate_bind_addr(bind: &str) -> Result<String, String> {
    let trimmed = bind.trim();
    if trimmed.is_empty()
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
        || trimmed.contains('{')
        || trimmed.contains('}')
        || trimmed.contains(';')
    {
        return Err("bind address contains disallowed characters".to_string());
    }
    // Validate `host:port` (including IPv6 `[::1]:8790`).
    let (host, port_str) = trimmed.rsplit_once(':').ok_or_else(|| {
        "bind address must have format <host>:<port> (e.g. 127.0.0.1:8790)".to_string()
    })?;
    if host.is_empty() {
        return Err("bind host cannot be empty".to_string());
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid bind port '{port_str}'"))?;
    if port == 0 {
        return Err("bind port must be 1..=65535".to_string());
    }
    Ok(trimmed.to_string())
}

fn bind_port(bind: &str) -> u16 {
    bind.rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(8790)
}

fn sanitize_fly_app_name(node_id: &str, domain: &str) -> String {
    let source = domain
        .strip_suffix(".fly.dev")
        .filter(|s| !s.is_empty())
        .unwrap_or(node_id);
    let mut out = String::new();
    for ch in source.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "hyphae-node".to_string()
    } else {
        trimmed.chars().take(48).collect()
    }
}

struct GeneratedArtifact {
    rel_path: &'static str,
    description: &'static str,
    content: String,
    executable: bool,
}

#[allow(clippy::too_many_arguments)]
fn run_init(
    provider: DeployProvider,
    node_id_arg: Option<String>,
    domain_arg: Option<String>,
    bind_arg: Option<String>,
    profile_arg: Option<DeployProfile>,
    enable_drop_relay_flag: bool,
    drop_max_memory_mb_arg: Option<usize>,
    out_arg: Option<PathBuf>,
    force: bool,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "deploy init";
    let profile = profile_arg.unwrap_or_else(|| provider.default_profile());
    let enable_drop_relay = enable_drop_relay_flag || provider == DeployProvider::DropRelay;
    let drop_max_memory_mb = match drop_max_memory_mb_arg {
        Some(0) => {
            return Err(CliError::usage(
                "INVALID_DROP_MEMORY",
                "--drop-max-memory-mb must be >= 1",
            )
            .with_fix("Example: --drop-max-memory-mb 256".to_string()));
        }
        Some(mb) => mb,
        None => DEFAULT_DROP_RELAY_MEMORY_MB,
    };
    let domain_raw = domain_arg.unwrap_or_else(|| provider.default_domain().to_string());
    let domain = match validate_domain_hostname(&domain_raw) {
        Ok(d) => d,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_DOMAIN",
                format!("Invalid --domain '{domain_raw}': {e}"),
            )
            .with_fix("Pass a bare hostname such as --domain mesh.example.com".to_string()));
        }
    };

    let node_id = node_id_arg.unwrap_or_else(|| {
        if provider == DeployProvider::PublicNode && is_valid_node_id(&domain) {
            domain.clone()
        } else {
            provider.default_node_id().to_string()
        }
    });
    if node_id == LOCAL_NODE_ID || !is_valid_node_id(&node_id) {
        return Err(CliError::usage("INVALID_NODE_ID", format!(
                "Invalid --node-id '{node_id}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
            )).with_fix("Example: --node-id acme-team".to_string()));
    }

    let bind_raw = bind_arg.unwrap_or_else(|| provider.default_bind().to_string());
    let bind = match validate_bind_addr(&bind_raw) {
        Ok(b) => b,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_BIND",
                format!("Invalid --bind '{bind_raw}': {e}"),
            )
            .with_fix("Example: --bind 127.0.0.1:8790".to_string()));
        }
    };

    let out_dir =
        out_arg.unwrap_or_else(|| PathBuf::from(format!("hyphae-deploy-{}", provider.as_str())));
    let artifacts = build_provider_artifacts(
        provider,
        profile,
        &node_id,
        &domain,
        &bind,
        enable_drop_relay,
        drop_max_memory_mb,
    );

    // Pre-flight overwrite guard: fail closed BEFORE creating or mutating any file.
    if !force {
        let existing: Vec<String> = artifacts
            .iter()
            .map(|a| out_dir.join(a.rel_path))
            .filter(|p| p.exists())
            .map(|p| p.display().to_string())
            .collect();
        if !existing.is_empty() {
            return Err(CliError::error(
                "FILES_EXIST",
                format!(
                    "Refusing to overwrite existing deployment files without --force: {}",
                    existing.join(", ")
                ),
            )
            .with_fix(
                "Re-run with --force to overwrite, or pass a fresh --out directory.".to_string(),
            ));
        }
    }

    fs::create_dir_all(&out_dir).map_err(|e| {
        CliError::error(
            "IO_ERROR",
            format!(
                "Failed to create output directory {}: {e}",
                out_dir.display()
            ),
        )
    })?;

    let mut written_files = Vec::with_capacity(artifacts.len());
    for artifact in &artifacts {
        let full_path = out_dir.join(artifact.rel_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                CliError::error(
                    "IO_ERROR",
                    format!("Failed to create directory {}: {e}", parent.display()),
                )
            })?;
        }
        if let Err(e) =
            write_artifact_file(&full_path, artifact.content.as_bytes(), artifact.executable)
        {
            return Err(CliError::error(
                "IO_ERROR",
                format!("Failed to write {}: {e}", full_path.display()),
            ));
        }
        written_files.push(json!({
            "path": full_path.display().to_string(),
            "relativePath": artifact.rel_path,
            "description": artifact.description,
        }));
    }

    let next = build_init_next_steps(provider, profile, &node_id, &domain, &bind, &out_dir);
    let mut warnings = Vec::new();
    if is_wildcard_bind(&bind) && !provider.uses_container_proxy_bind() {
        warnings.push(format!(
            "Bind address '{bind}' listens on all interfaces; prefer 127.0.0.1:8790 behind Caddy/Tailscale/Cloudflare."
        ));
    }

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "Generated {} deployment kit for '{}' in {}",
                provider.as_str(),
                node_id,
                out_dir.display()
            ),
            json!({
                "provider": provider.as_str(),
                "profile": profile.as_str(),
                "nodeId": node_id,
                "domain": domain,
                "endpoint": format!("https://{domain}"),
                "bind": bind,
                "dropRelayEnabled": enable_drop_relay,
                "dropMaxMemoryMb": if enable_drop_relay { Some(drop_max_memory_mb) } else { None },
                "outDir": out_dir.display().to_string(),
                "files": written_files,
            }),
        )
        .warnings(warnings)
        .next(next);
        print_json(&envelope);
        return Ok(ExitCode::from(EXIT_OK));
    }

    println!(
        "OK    Generated '{}' deployment kit for node '{}' ({})",
        provider.as_str(),
        node_id,
        profile.as_str()
    );
    println!("      Output:   {}", out_dir.display());
    println!("      Endpoint: https://{domain}");
    println!("      Bind:     {bind}");
    println!();
    println!("Generated files:");
    for a in &artifacts {
        println!("  • {:<24} {}", a.rel_path, a.description);
    }
    print_warnings(&warnings);
    print_next_steps(&next);
    Ok(ExitCode::from(EXIT_OK))
}

fn write_artifact_file(path: &Path, content: &[u8], executable: bool) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(content)?;
    f.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Generated deployment kit files (including `node.json`) contain ZERO plaintext secrets —
        // all credentials live strictly in `SecretStore` (0600) or secret env/mounts, never in
        // `node.json`. Mode `0644` (non-world-writable) guarantees bind-mounted `:ro` configs such
        // as `./node.json:/etc/hyphae/node.json:ro` are readable by container `USER 10001:10001`.
        let mode = if executable { 0o750 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    Ok(())
}

fn build_drop_relay_json(max_memory_mb: usize) -> Value {
    json!({
        "enabled": true,
        "maxMemoryMb": max_memory_mb,
        "defaultTtlSeconds": 600,
        "maxTtlSeconds": 900,
        "allowedOrigins": ["https://hyphae.to"],
        "allowPrivateNetwork": true
    })
}

fn build_node_json(
    provider: DeployProvider,
    profile: DeployProfile,
    node_id: &str,
    domain: &str,
    bind: &str,
    enable_drop_relay: bool,
    drop_max_memory_mb: usize,
) -> String {
    let behind_reverse_proxy = true;
    let state_dir = "/var/lib/hyphae";

    let mut config = if provider == DeployProvider::DropRelay {
        json!({
            "v": 2,
            "nodeId": node_id,
            "profile": "router",
            "deploymentProvider": provider.as_str(),
            "stateDir": state_dir,
            "listen": {
                "bind": bind,
                "behindReverseProxy": behind_reverse_proxy,
                "trustedProxies": ["127.0.0.1/32", "::1/128"],
                "publicUrl": format!("https://{domain}")
            },
            "policy": {
                "requirePairing": true,
                "requireE2ee": true,
                "maxTextBytes": 32768,
                "maxTransferBytes": 0
            },
            "dropRelay": build_drop_relay_json(drop_max_memory_mb),
            "forwarding": {
                "mode": "deny",
                "rules": []
            }
        })
    } else if profile == DeployProfile::Public || provider == DeployProvider::PublicNode {
        json!({
            "v": 2,
            "nodeId": node_id,
            "profile": profile.node_profile_str(),
            "deploymentProvider": provider.as_str(),
            "publicReadOnly": true,
            "stateDir": state_dir,
            "listen": {
                "bind": bind,
                "behindReverseProxy": behind_reverse_proxy,
                "trustedProxies": ["127.0.0.1/32", "::1/128"],
                "publicUrl": format!("https://{domain}")
            },
            "policy": {
                "requirePairing": false,
                "requireE2ee": false,
                "maxTextBytes": 4096,
                "maxTransferBytes": 0
            },
            "guestPairing": {
                "enabled": true,
                "preset": "guest-ro",
                "scopes": [
                    "stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]"
                ],
                "maxReposPerGuest": 10,
                "maxBatchesPerHour": 60
            },
            "sources": [
                {
                    "id": "github-public",
                    "kind": "github-public",
                    "topic": "github",
                    "mode": "demand-driven-etag",
                    "minPollIntervalSeconds": 60,
                    "graceWindowSeconds": 300,
                    "githubToken": { "secret": "github-public-token" }
                }
            ],
            "rateLimits": {
                "manifestRequestsPerMinute": 120,
                "guestJoinRequestsPerMinute": 20,
                "subscribeRequestsPerMinute": 30
            },
            "forwarding": {
                "mode": "deny",
                "rules": []
            },
            "escalation": {
                "default": format!(
                    "Free {domain} guest tier supports up to 10 public GitHub repos (exact.repo required, 60 wakes/hr). Run local.github-public with your own GitHub token for private repos or higher limits."
                )
            }
        })
    } else if profile == DeployProfile::P2p {
        json!({
            "v": 2,
            "nodeId": node_id,
            "profile": "p2p",
            "deploymentProvider": provider.as_str(),
            "stateDir": state_dir,
            "listen": {
                "bind": bind,
                "behindReverseProxy": behind_reverse_proxy,
                "trustedProxies": ["127.0.0.1/32", "::1/128"],
                "publicUrl": format!("https://{domain}")
            },
            "policy": {
                "requirePairing": true,
                "requireE2ee": true,
                "maxTextBytes": 32768,
                "maxTransferBytes": 52428800
            },
            "pairing": {
                "p2pMutual": true,
                "adminCa": false
            },
            "forwarding": {
                "mode": "deny",
                "rules": []
            },
            "escalation": {
                "default": format!(
                    "Direct P2P node '{node_id}'. Request a one-shot hp2p1_ invite from the owner to pair or widen scopes."
                )
            }
        })
    } else {
        json!({
            "v": 2,
            "nodeId": node_id,
            "profile": "router",
            "deploymentProvider": provider.as_str(),
            "stateDir": state_dir,
            "listen": {
                "bind": bind,
                "behindReverseProxy": behind_reverse_proxy,
                "trustedProxies": ["127.0.0.1/32", "::1/128"],
                "publicUrl": format!("https://{domain}")
            },
            "policy": {
                "requirePairing": true,
                "requireE2ee": true,
                "maxTextBytes": 32768,
                "maxTransferBytes": 52428800
            },
            "pairing": {
                "adminCa": true,
                "p2pMutual": true,
                "adminKey": { "secret": "hyphae-admin-pubkey" }
            },
            "sources": [
                {
                    "id": "github-webhook",
                    "kind": "github-webhook",
                    "topic": "github-webhooks",
                    "enabled": false,
                    "webhookSecret": { "secret": "github-webhook-secret" }
                }
            ],
            "forwarding": {
                "mode": "deny",
                "rules": []
            },
            "escalation": {
                "default": format!(
                    "Ask the administrator of '{node_id}' for an updated am2_ grant or scope upgrade."
                ),
                "byScope": {
                    "stream:subscribe=github-webhooks": "Request GitHub webhook stream access from your Hyphae node admin."
                }
            }
        })
    };

    if enable_drop_relay && provider != DeployProvider::DropRelay {
        if let Some(obj) = config.as_object_mut() {
            obj.insert(
                "dropRelay".to_string(),
                build_drop_relay_json(drop_max_memory_mb),
            );
        }
    }

    let mut out = serde_json::to_string_pretty(&config).expect("valid node.json");
    out.push('\n');
    out
}

fn render_caddyfile(domain: &str, upstream: &str, is_public_node: bool) -> String {
    let max_body = if is_public_node { "1MB" } else { "64MB" };
    format!(
        r#"# Hyphae v2 Caddy reverse proxy (automatic HTTPS + zero-buffering SSE)
# Generated by `hyp deploy init`

{domain} {{
    encode zstd gzip

    request_body {{
        max_size {max_body}
    }}

    header {{
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        -Server
    }}

    # Critical for Hyphae SSE (/v1/inbox): flush_interval -1 disables proxy buffering.
    reverse_proxy {upstream} {{
        flush_interval -1
        header_up X-Forwarded-Proto https
        transport http {{
            read_timeout 0
            write_timeout 0
            dial_timeout 10s
        }}
    }}
}}
"#
    )
}

fn render_systemd_unit(node_id: &str, bind: &str) -> String {
    format!(
        r#"[Unit]
Description=Hyphae v2 Node ({node_id})
Documentation=https://hyphae.to
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hyphae
Group=hyphae
StateDirectory=hyphae
StateDirectoryMode=0700
ConfigurationDirectory=hyphae
ConfigurationDirectoryMode=0750
WorkingDirectory=/var/lib/hyphae
Environment=HYPHAE_SECRET_BACKEND=file
Environment=HYPHAE_STATE_DIR=/var/lib/hyphae
Environment=HYPHAE_CONFIG=/etc/hyphae/node.json
Environment=HYPHAE_BIND={bind}
ExecStart=/usr/local/bin/hyp node start --config /etc/hyphae/node.json
Restart=on-failure
RestartSec=3s
TimeoutStopSec=15s

# Hardened sandboxing
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
"#
    )
}

fn uses_team_admin_ca(provider: DeployProvider, profile: DeployProfile) -> bool {
    provider != DeployProvider::DropRelay
        && provider != DeployProvider::PublicNode
        && profile == DeployProfile::Router
}

fn render_dockerfile(port: u16, fly_mount_entrypoint: bool) -> String {
    let runtime_tail = if fly_mount_entrypoint {
        r#"# Fly.io mounts [[mounts]] volumes (/var/lib/hyphae) root-owned (0755 root:root) on boot.
# Ensure /var/lib/hyphae is owned by UID 10001:10001 (mode 0700) and immediately drop
# privileges via util-linux `setpriv` (Essential on Debian) before exec'ing `hyp`.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'STATE_DIR="${HYPHAE_STATE_DIR:-/var/lib/hyphae}"' \
    'if [ "$(id -u)" = "0" ]; then' \
    '  mkdir -p "$STATE_DIR"' \
    '  chown -R 10001:10001 "$STATE_DIR"' \
    '  chmod 0700 "$STATE_DIR"' \
    '  export HOME=/var/lib/hyphae' \
    '  exec setpriv --reuid=10001 --regid=10001 --init-groups /usr/local/bin/hyp "$@"' \
    'fi' \
    'exec /usr/local/bin/hyp "$@"' \
    > /usr/local/bin/hyphae-entrypoint.sh \
    && chmod 0755 /usr/local/bin/hyphae-entrypoint.sh

ENV HOME=/var/lib/hyphae \
    HYPHAE_SECRET_BACKEND=file \
    HYPHAE_STATE_DIR=/var/lib/hyphae \
    HYPHAE_CONFIG=/etc/hyphae/node.json

WORKDIR /var/lib/hyphae
EXPOSE __PORT__

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["setpriv", "--reuid=10001", "--regid=10001", "--init-groups", "/usr/local/bin/hyp", "deploy", "check", "--url", "http://127.0.0.1:__PORT__", "--json"]

ENTRYPOINT ["/usr/local/bin/hyphae-entrypoint.sh"]
CMD ["node", "start", "--config", "/etc/hyphae/node.json", "--no-local-socket"]
"#
    } else {
        r#"ENV HYPHAE_SECRET_BACKEND=file \
    HYPHAE_STATE_DIR=/var/lib/hyphae \
    HYPHAE_CONFIG=/etc/hyphae/node.json

USER 10001:10001
WORKDIR /var/lib/hyphae
EXPOSE __PORT__

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/hyp", "deploy", "check", "--url", "http://127.0.0.1:__PORT__", "--json"]

ENTRYPOINT ["/usr/local/bin/hyp"]
CMD ["node", "start", "--config", "/etc/hyphae/node.json", "--no-local-socket"]
"#
    };

    format!(
        r#"# syntax=docker/dockerfile:1
# Hyphae v2 standalone runtime image (SHA-256 verified release binary, non-root UID 10001)
# Uses debian:bookworm-slim (glibc + ca-certificates) so both x86_64-unknown-linux-musl
# and aarch64-unknown-linux-gnu official release binaries execute cleanly.

FROM debian:bookworm-slim AS downloader
ARG HYP_VERSION=v__HYP_VERSION__
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/* \
    && ARCH="${{TARGETARCH:-$(dpkg --print-architecture)}}" \
    && case "${{ARCH}}" in \
         amd64) HYP_TARGET="x86_64-unknown-linux-musl" ;; \
         arm64) HYP_TARGET="aarch64-unknown-linux-gnu" ;; \
         *) echo "Unsupported TARGETARCH: ${{ARCH}}" >&2; exit 1 ;; \
       esac \
    && ARCHIVE="hyp-${{HYP_VERSION}}-${{HYP_TARGET}}.tar.gz" \
    && BASE_URL="https://github.com/hyphae-to/hyp/releases/download/${{HYP_VERSION}}" \
    && cd /tmp \
    && curl -fsSL --proto '=https' --tlsv1.2 "${{BASE_URL}}/${{ARCHIVE}}" -o "${{ARCHIVE}}" \
    && curl -fsSL --proto '=https' --tlsv1.2 "${{BASE_URL}}/SHA256SUMS.txt" -o SHA256SUMS.txt \
    && grep -E "[ *]${{ARCHIVE}}$" SHA256SUMS.txt >/dev/null \
    && sha256sum -c --ignore-missing SHA256SUMS.txt \
    && tar -xzf "${{ARCHIVE}}" -C /tmp \
    && install -m 0755 /tmp/hyp /usr/local/bin/hyp \
    && rm -rf "/tmp/${{ARCHIVE}}" /tmp/SHA256SUMS.txt /tmp/hyp

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 hyphae \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/hyphae --shell /usr/sbin/nologin hyphae \
    && mkdir -p /var/lib/hyphae /etc/hyphae \
    && chown 10001:10001 /var/lib/hyphae /etc/hyphae \
    && chmod 0700 /var/lib/hyphae

COPY --from=downloader /usr/local/bin/hyp /usr/local/bin/hyp
# node.json holds ZERO plaintext secrets (references only via SecretStore); bake it into
# /etc/hyphae/node.json owned by UID 10001 so Fly.io and standalone container runs start
# immediately without CONFIG_NOT_FOUND. Docker Compose may still bind-mount ./node.json:ro
# (mode 0644) to update config without rebuilding.
COPY --chown=10001:10001 node.json /etc/hyphae/node.json
RUN chmod 0640 /etc/hyphae/node.json

{runtime_tail}"#
    )
    .replace("__HYP_VERSION__", env!("CARGO_PKG_VERSION"))
    .replace("__PORT__", &port.to_string())
}

fn render_docker_compose(
    node_id: &str,
    port: u16,
    override_bind: bool,
    caddyfile_rel: &str,
) -> String {
    let command_block = if override_bind {
        format!(
            "    command:\n      - node\n      - start\n      - --config\n      - /etc/hyphae/node.json\n      - --bind\n      - 0.0.0.0:{port}\n      - --no-local-socket\n"
        )
    } else {
        String::new()
    };
    format!(
        r#"# Hyphae v2 Docker Compose stack ({node_id}) — hyphae-node + Caddy auto-TLS
# hyphae-node is reachable ONLY on the internal Docker bridge network; Caddy terminates HTTPS.

services:
  hyphae-node:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: hyphae-node
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:size=32M,noexec,nosuid,uid=10001,gid=10001,mode=1777
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    environment:
      HYPHAE_SECRET_BACKEND: file
      HYPHAE_STATE_DIR: /var/lib/hyphae
      HYPHAE_CONFIG: /etc/hyphae/node.json
{command_block}    volumes:
      # node.json holds zero plaintext secrets (mode 0644, readable by UID 10001:10001);
      # secrets live strictly in /var/lib/hyphae/secrets inside the hyphae_state volume.
      - ./node.json:/etc/hyphae/node.json:ro
      # Named volume inherits UID 10001:10001 mode 0700 from /var/lib/hyphae in the image.
      - hyphae_state:/var/lib/hyphae
    networks:
      - hyphae_internal

  caddy:
    image: caddy:2-alpine
    container_name: hyphae-caddy
    restart: unless-stopped
    depends_on:
      - hyphae-node
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - {caddyfile_rel}:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - hyphae_internal

networks:
  hyphae_internal:
    driver: bridge

volumes:
  hyphae_state:
  caddy_data:
  caddy_config:
"#
    )
}

fn render_cloudflared_yml(domain: &str, bind: &str, node_id: &str) -> String {
    format!(
        r#"# Cloudflare Tunnel configuration for Hyphae v2 node ({node_id})
# Replace <TUNNEL_UUID> after running: cloudflared tunnel create {node_id}
tunnel: <TUNNEL_UUID>
credentials-file: /etc/cloudflared/<TUNNEL_UUID>.json

ingress:
  - hostname: {domain}
    service: http://{bind}
    originRequest:
      connectTimeout: 10s
      keepAliveTimeout: 90s
      keepAliveConnections: 100
      noHappyEyeballs: true
  - service: http_status:404
"#
    )
}

fn render_fly_toml(app_name: &str, node_id: &str, port: u16) -> String {
    format!(
        r#"# Fly.io configuration for Hyphae v2 node ({node_id})
# Persistent /var/lib/hyphae volume + always-on SSE (min_machines_running = 1)

app = "{app_name}"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile"

[env]
  HYPHAE_SECRET_BACKEND = "file"
  HYPHAE_STATE_DIR = "/var/lib/hyphae"
  HYPHAE_CONFIG = "/etc/hyphae/node.json"

[http_service]
  internal_port = {port}
  force_https = true
  auto_stop_machines = "off"
  auto_start_machines = true
  min_machines_running = 1
  processes = ["app"]

  [http_service.concurrency]
    type = "connections"
    hard_limit = 500
    soft_limit = 400

  [[http_service.checks]]
    grace_period = "10s"
    interval = "30s"
    method = "GET"
    timeout = "5s"
    path = "/v1/health"

[[mounts]]
  source = "hyphae_data"
  destination = "/var/lib/hyphae"
  initial_size = "1gb"

[[vm]]
  memory = "256mb"
  cpu_kind = "shared"
  cpus = 1
"#
    )
}

fn render_tailscale_serve_script(node_id: &str, bind: &str, domain: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

# Expose Hyphae v2 node '{node_id}' privately over Tailscale Serve (HTTPS inside your tailnet).
# Zero public ports are opened; hyphae binds loopback ({bind}).
tailscale serve --bg --https=443 "http://{bind}"

echo "Tailscale Serve active -> https://{domain}"
echo "Verify with: hyp deploy check --url https://{domain}"

# For public webhooks, use `hyp deploy webhook` with a dedicated loopback receiver.
# Keep the private peer listener on its own Serve port.
"#
    )
}

fn render_kit_readme(
    provider: DeployProvider,
    profile: DeployProfile,
    node_id: &str,
    domain: &str,
    bind: &str,
    next: &[String],
) -> String {
    let mut out = format!(
        "# Hyphae v2 Deployment Kit (`{}`)\n\n\
         - **Node ID:** `{node_id}`\n\
         - **Profile:** `{}`\n\
         - **Endpoint:** `https://{domain}`\n\
         - **Bind:** `{bind}`\n\n\
         ## Security Invariants\n\
         - `node.json` contains **zero plaintext secrets** — store tokens via `hyp secret set <name>`.\n\
         - Reverse proxy terminates TLS and sets `flush_interval -1` for zero-buffering SSE (`/v1/inbox`).\n\
         - Unauthenticated `GET /v1/manifest` exposes empty `advertised` arrays and no escalation text.\n\
         - Pass pairing tokens via **stdin** (`<<<`) or `--token-file`, never as CLI argv flags.\n\n\
         ## Next Steps\n",
        provider.as_str(),
        profile.as_str(),
    );
    for (idx, step) in next.iter().enumerate() {
        out.push_str(&format!("{}. `{step}`\n", idx + 1));
    }
    if uses_team_admin_ca(provider, profile) {
        let app_name = sanitize_fly_app_name(node_id, domain);
        let hub_set_cmd = match provider {
            DeployProvider::Docker => {
                "printf '%s\\n' \"$ADMIN_JWK\" | docker compose exec -T hyphae-node hyp secret set hyphae-admin-pubkey\ndocker compose restart hyphae-node".to_string()
            }
            DeployProvider::Fly => format!(
                "printf '%s\\n' \"$ADMIN_JWK\" | flyctl ssh console -a {app_name} -C \"sh -c 'cat | env HOME=/var/lib/hyphae HYPHAE_SECRET_BACKEND=file HYPHAE_STATE_DIR=/var/lib/hyphae setpriv --reuid=10001 --regid=10001 --init-groups /usr/local/bin/hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae'\"\nflyctl apps restart {app_name}"
            ),
            DeployProvider::Vps | DeployProvider::Tailscale | DeployProvider::Cloudflare => {
                "printf '%s\\n' \"$ADMIN_JWK\" | sudo -u hyphae env HYPHAE_SECRET_BACKEND=file /usr/local/bin/hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae".to_string()
            }
            _ => {
                "printf '%s\\n' \"$ADMIN_JWK\" | sudo -u hyphae env HYPHAE_SECRET_BACKEND=file /usr/local/bin/hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae".to_string()
            }
        };
        out.push_str(&format!(
            "\n## Provisioning the Team Hub Admin-CA Public Key (`hyphae-admin-pubkey`)\n\n\
             `node.json` references `\"pairing\": {{ \"adminKey\": {{ \"secret\": \"hyphae-admin-pubkey\" }} }}`\n\
             so this hub can verify offline-signed `am2_` teammate invites while the Admin-CA **private** key\n\
             stays strictly on the admin laptop (never stored on the hub). Until `hyphae-admin-pubkey` is\n\
             provisioned, the hub boots with `am2_` pairing disabled.\n\n\
             1. **On the admin laptop** — mint your first invite and capture ONLY the public Ed25519 JWK\n\
                (`.data.adminJwk`, containing `kty`/`crv`/`x` and never the private key):\n\n\
             ```sh\n\
             ADMIN_JWK=$(hyp pair invite --mode team --node-id {node_id} --endpoint https://{domain} --peer alice@laptop --preset member --json | jq -c '.data.adminJwk')\n\
             ```\n\n\
             2. **On this Team Hub** — store the public JWK via stdin (`hyp secret set hyphae-admin-pubkey`)\n\
                so `am2_` pairing is active on first boot (or restart the hub after loading it):\n\n\
             ```sh\n\
             {hub_set_cmd}\n\
             ```\n\n\
             *(Alternative: because `adminJwk` is a public key, you may also replace `{{ \"secret\": \"hyphae-admin-pubkey\" }}` in `node.json` directly with the public OKP Ed25519 JWK object `{{ \"kty\": \"OKP\", \"crv\": \"Ed25519\", \"x\": \"...\" }}` — never include a private `\"d\"` field.)*\n"
        ));
    }
    if provider == DeployProvider::DropRelay {
        out.push_str(
            "\n## Cloudflare Workers + RAM-Only Durable Object (30-Second Edge Deploy)\n\n\
             Prefer zero-ops global edge hosting instead of running a VPS/container? Deploy the\n\
             zero-dependency Cloudflare Workers kit directly from `workers/drop-relay/`:\n\n\
             - **RAM-only `DropSlotDO`**: never touches Durable Object persistent storage; every\n\
               ciphertext `Uint8Array` is zeroized in RAM on burn or TTL expiry.\n\
             - **Private / Team mode (`DROP_AUTH_MODE = \"private\"`, default fail-closed)**:\n\
               set `DROP_CAP_HMAC_KEY` and `ALLOWED_NODE_KEYS` via `npx wrangler secret put`, then\n\
               run `cd workers/drop-relay && npx wrangler deploy`.\n\
             - **Public mode (`DROP_AUTH_MODE = \"open\"`, e.g. `spore.hyphae.to`)**: accepts\n\
               `Hyphae-Ed25519` requests carrying `X-Hyphae-Public-Key` with per-IP & per-key\n\
               quotas.\n",
        );
    }
    out
}

fn render_drop_relay_caddyfile(domain: &str, upstream: &str) -> String {
    format!(
        r#"# Hyphae v2 Blind Drop Relay Caddyfile (auto-HTTPS, zero /v1/drops access logging, unbuffered SSE)
# Generated by `hyp deploy init drop-relay`

{domain} {{
    # Privacy hardening: discard HTTP access logs so dropIds and client IPs never hit disk.
    log {{
        output discard
    }}

    encode zstd gzip

    request_body {{
        max_size 1MB
    }}

    header {{
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        -Server
    }}

    handle /v1/drops* {{
        reverse_proxy {upstream} {{
            flush_interval -1
            header_up X-Forwarded-Proto https
            transport http {{
                read_timeout 0
                write_timeout 0
                dial_timeout 10s
            }}
        }}
    }}

    handle {{
        reverse_proxy {upstream} {{
            flush_interval -1
            header_up X-Forwarded-Proto https
            transport http {{
                read_timeout 0
                write_timeout 0
                dial_timeout 10s
            }}
        }}
    }}
}}
"#
    )
}

fn render_drop_relay_docker_compose(node_id: &str, port: u16, max_memory_mb: usize) -> String {
    let mem_limit_mb = max_memory_mb.saturating_add(128);
    format!(
        r#"# Hyphae v2 Blind Drop Relay Docker Compose stack ({node_id})
# Zero disk volumes for drops: opaque HPKE ciphertexts live strictly in RAM and zeroize on burn/TTL.

services:
  hyphae-drop-relay:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: hyphae-drop-relay
    restart: unless-stopped
    read_only: true
    mem_limit: {mem_limit_mb}m
    tmpfs:
      - /tmp:size=32M,noexec,nosuid,uid=10001,gid=10001,mode=1777
      - /var/lib/hyphae:size=64M,uid=10001,gid=10001,mode=0700
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    environment:
      HYPHAE_SECRET_BACKEND: file
      HYPHAE_STATE_DIR: /var/lib/hyphae
      HYPHAE_CONFIG: /etc/hyphae/node.json
    command:
      - node
      - start
      - --config
      - /etc/hyphae/node.json
      - --bind
      - 0.0.0.0:{port}
      - --no-local-socket
      - --enable-drop-relay
      - --drop-max-memory-mb
      - "{max_memory_mb}"
    volumes:
      # node.json holds zero plaintext secrets (mode 0644, readable by UID 10001:10001).
      - ./node.json:/etc/hyphae/node.json:ro
    networks:
      - hyphae_drop_internal

  caddy:
    image: caddy:2-alpine
    container_name: hyphae-drop-caddy
    restart: unless-stopped
    depends_on:
      - hyphae-drop-relay
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - hyphae_drop_internal

networks:
  hyphae_drop_internal:
    driver: bridge

volumes:
  caddy_data:
  caddy_config:
"#
    )
}

fn render_drop_relay_fly_toml(
    app_name: &str,
    node_id: &str,
    port: u16,
    max_memory_mb: usize,
) -> String {
    let vm_memory_mb = max_memory_mb.saturating_add(256).max(512);
    format!(
        r#"# Fly.io configuration for Hyphae v2 Blind Drop Relay ({node_id})
# Zero disk persistence for drops; auto-HTTPS + always-on SSE streaming.

app = "{app_name}"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile"

[env]
  HYPHAE_SECRET_BACKEND = "file"
  HYPHAE_STATE_DIR = "/var/lib/hyphae"
  HYPHAE_CONFIG = "/etc/hyphae/node.json"

[http_service]
  internal_port = {port}
  force_https = true
  auto_stop_machines = "off"
  auto_start_machines = true
  min_machines_running = 1
  processes = ["app"]

  [http_service.concurrency]
    type = "connections"
    hard_limit = 1000
    soft_limit = 800

  [[http_service.checks]]
    grace_period = "10s"
    interval = "30s"
    method = "GET"
    timeout = "5s"
    path = "/v1/health"

[[vm]]
  memory = "{vm_memory_mb}mb"
  cpu_kind = "shared"
  cpus = 1
"#
    )
}

fn render_drop_relay_systemd_unit(node_id: &str, bind: &str, max_memory_mb: usize) -> String {
    let memory_max_mb = max_memory_mb.saturating_add(128);
    let port = bind_port(bind);
    // Keep bare-metal VPS systemd units bound strictly to loopback even though node.json
    // defaults to 0.0.0.0:8790 for Fly.io and Docker Compose container proxies.
    let systemd_bind = if is_wildcard_bind(bind) {
        format!("127.0.0.1:{port}")
    } else {
        bind.to_string()
    };
    format!(
        r#"[Unit]
Description=Hyphae v2 Blind Drop Relay ({node_id})
Documentation=https://hyphae.to
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hyphae
Group=hyphae
StateDirectory=hyphae
StateDirectoryMode=0700
ConfigurationDirectory=hyphae
ConfigurationDirectoryMode=0750
WorkingDirectory=/var/lib/hyphae
Environment=HYPHAE_SECRET_BACKEND=file
Environment=HYPHAE_STATE_DIR=/var/lib/hyphae
Environment=HYPHAE_CONFIG=/etc/hyphae/node.json
Environment=HYPHAE_BIND={systemd_bind}
ExecStart=/usr/local/bin/hyp node start --config /etc/hyphae/node.json --bind {systemd_bind} --no-local-socket --enable-drop-relay --drop-max-memory-mb {max_memory_mb}
Restart=on-failure
RestartSec=3s
TimeoutStopSec=15s
MemoryMax={memory_max_mb}M

# Hardened sandboxing
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
"#
    )
}

fn build_provider_artifacts(
    provider: DeployProvider,
    profile: DeployProfile,
    node_id: &str,
    domain: &str,
    bind: &str,
    enable_drop_relay: bool,
    drop_max_memory_mb: usize,
) -> Vec<GeneratedArtifact> {
    let node_json = build_node_json(
        provider,
        profile,
        node_id,
        domain,
        bind,
        enable_drop_relay,
        drop_max_memory_mb,
    );
    let dummy_out = PathBuf::from(".");
    let next_for_readme =
        build_init_next_steps(provider, profile, node_id, domain, bind, &dummy_out);
    let readme = render_kit_readme(provider, profile, node_id, domain, bind, &next_for_readme);

    match provider {
        DeployProvider::Tailscale => vec![
            GeneratedArtifact {
                rel_path: "node.json",
                description: "Hardened Hyphae v2 node config (loopback bind, secret refs only)",
                content: node_json,
                executable: false,
            },
            GeneratedArtifact {
                rel_path: "tailscale-serve.sh",
                description: "Tailscale Serve HTTPS exposure script (+ scoped Funnel note)",
                content: render_tailscale_serve_script(node_id, bind, domain),
                executable: true,
            },
            GeneratedArtifact {
                rel_path: "hyphae-node.service",
                description: "Hardened systemd unit (ProtectSystem=strict, NoNewPrivileges, 0700 state)",
                content: render_systemd_unit(node_id, bind),
                executable: false,
            },
            GeneratedArtifact {
                rel_path: "README.md",
                description: "Deployment and pairing checklist",
                content: readme,
                executable: false,
            },
        ],
        DeployProvider::Vps => vec![
            GeneratedArtifact {
                rel_path: "node.json",
                description: "Hardened Hyphae v2 node config (loopback bind, secret refs only)",
                content: node_json,
                executable: false,
            },
            GeneratedArtifact {
                rel_path: "Caddyfile",
                description: "Caddy auto-TLS reverse proxy with SSE flush_interval -1",
                content: render_caddyfile(domain, bind, profile == DeployProfile::Public),
                executable: false,
            },
            GeneratedArtifact {
                rel_path: "hyphae-node.service",
                description: "Hardened systemd unit (ProtectSystem=strict, NoNewPrivileges, 0700 state)",
                content: render_systemd_unit(node_id, bind),
                executable: false,
            },
            GeneratedArtifact {
                rel_path: "README.md",
                description: "Deployment and pairing checklist",
                content: readme,
                executable: false,
            },
        ],
        DeployProvider::Docker => {
            let port = bind_port(bind);
            vec![
                GeneratedArtifact {
                    rel_path: "node.json",
                    description: "Containerized Hyphae v2 node config (internal bridge only, secret refs only)",
                    content: node_json,
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "Dockerfile",
                    description: "Standalone release-binary image (non-root UID 10001, baked node.json, manifest healthcheck)",
                    content: render_dockerfile(port, false),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "docker-compose.yml",
                    description: "Docker Compose stack pairing hyphae-node with Caddy auto-TLS",
                    content: render_docker_compose(node_id, port, false, "./Caddyfile"),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "Caddyfile",
                    description: "Caddy auto-TLS reverse proxy targeting internal hyphae-node with flush_interval -1",
                    content: render_caddyfile(
                        domain,
                        &format!("hyphae-node:{port}"),
                        profile == DeployProfile::Public,
                    ),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "README.md",
                    description: "Deployment and pairing checklist",
                    content: readme,
                    executable: false,
                },
            ]
        }
        DeployProvider::Cloudflare => vec![
            GeneratedArtifact {
                rel_path: "node.json",
                description: "Hardened Hyphae v2 node config (loopback bind, secret refs only)",
                content: node_json,
                executable: false,
            },
            GeneratedArtifact {
                rel_path: "cloudflared.yml",
                description: "Cloudflare Tunnel ingress configuration (zero inbound open ports)",
                content: render_cloudflared_yml(domain, bind, node_id),
                executable: false,
            },
            GeneratedArtifact {
                rel_path: "hyphae-node.service",
                description: "Hardened systemd unit (ProtectSystem=strict, NoNewPrivileges, 0700 state)",
                content: render_systemd_unit(node_id, bind),
                executable: false,
            },
            GeneratedArtifact {
                rel_path: "README.md",
                description: "Deployment and pairing checklist",
                content: readme,
                executable: false,
            },
        ],
        DeployProvider::Fly => {
            let app_name = sanitize_fly_app_name(node_id, domain);
            let port = bind_port(bind);
            vec![
                GeneratedArtifact {
                    rel_path: "node.json",
                    description: "Fly.io Hyphae v2 node config (/var/lib/hyphae volume, 0.0.0.0 bind, secret refs only)",
                    content: node_json,
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "fly.toml",
                    description: "Fly.io config (auto-HTTPS, /var/lib/hyphae mount, min_machines_running = 1)",
                    content: render_fly_toml(&app_name, node_id, port),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "Dockerfile",
                    description: "Standalone release-binary image (Fly mount ownership entrypoint + setpriv drop to UID 10001:10001, baked node.json)",
                    content: render_dockerfile(port, true),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "README.md",
                    description: "Deployment and pairing checklist",
                    content: readme,
                    executable: false,
                },
            ]
        }
        DeployProvider::PublicNode => {
            let port = bind_port(bind);
            vec![
                GeneratedArtifact {
                    rel_path: "node.json",
                    description: "Turnkey public.hyphae.to read-only node config (guest-ro + demand-driven github-public)",
                    content: node_json,
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "Caddyfile",
                    description: "Hardened Caddy auto-TLS reverse proxy for bare-metal systemd (flush_interval -1, 1MB body cap)",
                    content: render_caddyfile(domain, bind, true),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "Caddyfile.docker",
                    description: "Hardened Caddy auto-TLS reverse proxy for Docker Compose targeting hyphae-node",
                    content: render_caddyfile(domain, &format!("hyphae-node:{port}"), true),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "hyphae-node.service",
                    description: "Hardened systemd unit (ProtectSystem=strict, NoNewPrivileges, 0700 state)",
                    content: render_systemd_unit(node_id, bind),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "Dockerfile",
                    description: "Standalone release-binary image (non-root UID 10001, baked node.json, manifest healthcheck)",
                    content: render_dockerfile(port, false),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "docker-compose.yml",
                    description: "Optional Docker Compose stack pairing public hyphae-node with Caddy",
                    content: render_docker_compose(node_id, port, true, "./Caddyfile.docker"),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "README.md",
                    description: "Turnkey public node deployment & verification checklist",
                    content: readme,
                    executable: false,
                },
            ]
        }
        DeployProvider::DropRelay => {
            let app_name = sanitize_fly_app_name(node_id, domain);
            let port = bind_port(bind);
            vec![
                GeneratedArtifact {
                    rel_path: "node.json",
                    description: "Hardened Blind Drop Relay node.json (RAM-only drops, 0.0.0.0 bind for Fly/Docker, strict https://hyphae.to CORS)",
                    content: node_json,
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "Caddyfile",
                    description: "Privacy-hardened Caddy auto-TLS reverse proxy targeting hyphae-drop-relay (zero /v1/drops logs, flush_interval -1)",
                    content: render_drop_relay_caddyfile(
                        domain,
                        &format!("hyphae-drop-relay:{port}"),
                    ),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "Dockerfile",
                    description: "Standalone release-binary image (non-root UID 10001, baked node.json)",
                    content: render_dockerfile(port, false),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "docker-compose.yml",
                    description: "Read-only Docker Compose stack with UID 10001 tmpfs and zero disk volumes for drops",
                    content: render_drop_relay_docker_compose(node_id, port, drop_max_memory_mb),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "fly.toml",
                    description: "Fly.io zero-disk Drop Relay config (auto-HTTPS, always-on SSE)",
                    content: render_drop_relay_fly_toml(
                        &app_name,
                        node_id,
                        port,
                        drop_max_memory_mb,
                    ),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "hyphae-drop-relay.service",
                    description: "Hardened systemd unit (loopback bind, ProtectSystem=strict, NoNewPrivileges, MemoryMax)",
                    content: render_drop_relay_systemd_unit(node_id, bind, drop_max_memory_mb),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "README.md",
                    description: "60-second Blind Drop Relay launch & verification instructions",
                    content: readme,
                    executable: false,
                },
            ]
        }
    }
}

fn build_init_next_steps(
    provider: DeployProvider,
    profile: DeployProfile,
    node_id: &str,
    domain: &str,
    bind: &str,
    out_dir: &Path,
) -> Vec<String> {
    let dir = out_dir.display();
    let pair_cmd = match profile {
        DeployProfile::Public => format!("hyp pair join https://{domain}"),
        DeployProfile::P2p => format!(
            "hyp pair invite --mode p2p --node-id {node_id} --endpoint https://{domain} --preset member"
        ),
        DeployProfile::Router => format!(
            "hyp pair invite --mode team --node-id {node_id} --endpoint https://{domain} --peer alice@laptop --preset member"
        ),
    };

    let team_admin_ca = uses_team_admin_ca(provider, profile);

    match provider {
        DeployProvider::Tailscale => {
            let mut steps = vec![format!("hyp deploy check --config {dir}/node.json")];
            if team_admin_ca {
                steps.push(
                    "sudo -u hyphae env HYPHAE_SECRET_BACKEND=file /usr/local/bin/hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae <<< '<public adminJwk JSON from admin laptop>'  # enables am2_ pairing on first boot (private Admin-CA key stays on laptop)".to_string(),
                );
            }
            steps.push(format!(
                "bash {dir}/tailscale-serve.sh  # exposes http://{bind} as https://{domain}"
            ));
            steps.push(format!(
                "hyp deploy check --url https://{domain} --config {dir}/node.json"
            ));
            steps.push(pair_cmd);
            steps
        }
        DeployProvider::Vps => {
            let mut steps = vec![
                "sudo useradd -r -s /usr/sbin/nologin hyphae || true".to_string(),
                "sudo install -m 0755 \"$(command -v hyp)\" /usr/local/bin/hyp".to_string(),
                "sudo mkdir -p /var/lib/hyphae /etc/hyphae && sudo chown -R hyphae:hyphae /var/lib/hyphae /etc/hyphae && sudo chmod 0700 /var/lib/hyphae".to_string(),
                format!("sudo install -m 0640 -o hyphae -g hyphae {dir}/node.json /etc/hyphae/node.json"),
            ];
            if team_admin_ca {
                steps.push(
                    "sudo -u hyphae env HYPHAE_SECRET_BACKEND=file /usr/local/bin/hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae <<< '<public adminJwk JSON from admin laptop>'  # enables am2_ pairing on first boot (private Admin-CA key stays on laptop)".to_string(),
                );
            }
            steps.push(format!(
                "sudo cp {dir}/hyphae-node.service /etc/systemd/system/ && sudo cp {dir}/Caddyfile /etc/caddy/Caddyfile"
            ));
            steps.push(
                "sudo systemctl daemon-reload && sudo systemctl enable --now hyphae-node caddy"
                    .to_string(),
            );
            steps.push(format!(
                "hyp deploy check --url https://{domain} --config /etc/hyphae/node.json"
            ));
            steps.push(pair_cmd);
            steps
        }
        DeployProvider::Docker => {
            let mut steps = vec![
                format!("hyp deploy check --config {dir}/node.json"),
                format!("cd {dir} && docker compose up -d --build"),
            ];
            if team_admin_ca {
                steps.push(format!(
                    "cd {dir} && docker compose exec -T hyphae-node hyp secret set hyphae-admin-pubkey <<< '<public adminJwk JSON from admin laptop>' && docker compose restart hyphae-node  # enables am2_ pairing (private Admin-CA key stays on laptop)"
                ));
            }
            steps.push(format!(
                "hyp deploy check --url https://{domain} --config {dir}/node.json"
            ));
            steps.push(pair_cmd);
            steps
        }
        DeployProvider::Cloudflare => {
            let mut steps = vec![
                format!(
                    "cloudflared tunnel create {node_id} && cloudflared tunnel route dns {node_id} {domain}"
                ),
            ];
            if team_admin_ca {
                steps.push(
                    "sudo -u hyphae env HYPHAE_SECRET_BACKEND=file /usr/local/bin/hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae <<< '<public adminJwk JSON from admin laptop>'  # enables am2_ pairing on first boot (private Admin-CA key stays on laptop)".to_string(),
                );
            }
            steps.push(format!(
                "Edit {dir}/cloudflared.yml with your tunnel UUID, then run: cloudflared tunnel --config {dir}/cloudflared.yml run"
            ));
            steps.push(format!(
                "hyp deploy check --url https://{domain} --config {dir}/node.json"
            ));
            steps.push(pair_cmd);
            steps
        }
        DeployProvider::Fly => {
            let app_name = sanitize_fly_app_name(node_id, domain);
            let mut steps = vec![
                format!("hyp deploy check --config {dir}/node.json"),
                format!(
                    "cd {dir} && flyctl apps create {app_name} && flyctl volumes create hyphae_data --size 1"
                ),
                format!("cd {dir} && flyctl deploy"),
            ];
            if team_admin_ca {
                steps.push(format!(
                    "flyctl ssh console -a {app_name} -C \"sh -c 'cat | env HOME=/var/lib/hyphae HYPHAE_SECRET_BACKEND=file HYPHAE_STATE_DIR=/var/lib/hyphae setpriv --reuid=10001 --regid=10001 --init-groups /usr/local/bin/hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae'\" <<< '<public adminJwk JSON from admin laptop>' && flyctl apps restart {app_name}  # enables am2_ pairing (private Admin-CA key stays on laptop)"
                ));
            }
            steps.push(format!(
                "hyp deploy check --url https://{domain} --config {dir}/node.json"
            ));
            steps.push(pair_cmd);
            steps
        }
        DeployProvider::PublicNode => vec![
            "hyp secret set github-public-token  # optional GitHub PAT for higher public ETag rate limits (never in node.json!)".to_string(),
            format!("hyp deploy check --config {dir}/node.json"),
            "sudo useradd -r -s /usr/sbin/nologin hyphae || true".to_string(),
            "sudo install -m 0755 \"$(command -v hyp)\" /usr/local/bin/hyp".to_string(),
            "sudo mkdir -p /var/lib/hyphae /etc/hyphae && sudo chown -R hyphae:hyphae /var/lib/hyphae /etc/hyphae && sudo chmod 0700 /var/lib/hyphae".to_string(),
            format!("sudo install -m 0640 -o hyphae -g hyphae {dir}/node.json /etc/hyphae/node.json && sudo cp {dir}/hyphae-node.service /etc/systemd/system/ && sudo cp {dir}/Caddyfile /etc/caddy/Caddyfile"),
            format!("sudo systemctl daemon-reload && sudo systemctl enable --now hyphae-node caddy  # or run via Docker Compose: cd {dir} && docker compose up -d --build"),
            format!("hyp deploy check --url https://{domain} --config {dir}/node.json"),
            pair_cmd,
        ],
        DeployProvider::DropRelay => vec![
            format!("hyp deploy check --config {dir}/node.json"),
            "sudo useradd -r -s /usr/sbin/nologin hyphae || true".to_string(),
            "sudo install -m 0755 \"$(command -v hyp)\" /usr/local/bin/hyp".to_string(),
            "sudo mkdir -p /var/lib/hyphae /etc/hyphae && sudo chown -R hyphae:hyphae /var/lib/hyphae /etc/hyphae && sudo chmod 0700 /var/lib/hyphae".to_string(),
            format!("sudo install -m 0640 -o hyphae -g hyphae {dir}/node.json /etc/hyphae/node.json && sudo cp {dir}/hyphae-drop-relay.service /etc/systemd/system/ && sudo cp {dir}/Caddyfile /etc/caddy/Caddyfile"),
            format!("sudo systemctl daemon-reload && sudo systemctl enable --now hyphae-drop-relay caddy  # or use Docker Compose ({dir}/docker-compose.yml) / Fly.io ({dir}/fly.toml)"),
            format!("hyp relay set https://{domain}"),
            format!("hyp relay status --url https://{domain}"),
            format!("hyp drop create --kind secret --secret-name example-api-key --relay https://{domain}"),
        ],
    }
}

// ============================================================================
// `deploy check`
// ============================================================================

fn is_wildcard_bind(bind: &str) -> bool {
    let trimmed = bind.trim();
    trimmed.starts_with("0.0.0.0:")
        || trimmed == "0.0.0.0"
        || trimmed.starts_with("[::]:")
        || trimmed.starts_with(":::")
        || trimmed.starts_with("*:")
}

fn is_loopback_bind(bind: &str) -> bool {
    let trimmed = bind.trim();
    trimmed.starts_with("127.0.0.1:")
        || trimmed.starts_with("[::1]:")
        || trimmed.starts_with("localhost:")
}

fn looks_like_secret_key_name(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let needles = [
        "secret",
        "token",
        "password",
        "passwd",
        "apikey",
        "api_key",
        "privatekey",
        "private_key",
        "bearer",
        "credential",
    ];
    needles.iter().any(|n| lower.contains(n))
}

fn looks_like_plaintext_secret_value(value: &str) -> bool {
    let s = value.trim();
    if s.is_empty() {
        return false;
    }
    let prefixes = [
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "AKIA",
        "xoxb-",
        "xoxp-",
        "xapp-",
        "sk-",
        "-----BEGIN ",
        "am1_",
        "am2_",
        "hp2p1_",
        "t3mp1_",
    ];
    prefixes.iter().any(|p| s.starts_with(p))
}

fn scan_for_plaintext_secrets(val: &Value, path: &str, findings: &mut Vec<String>) {
    match val {
        Value::Object(map) => {
            // Valid Hyphae secret reference object: `{ "secret": "<name>" }` or `{ "secretFile": "<path>" }`.
            if map.len() == 1 {
                if let Some(Value::String(name)) = map.get("secret") {
                    if hyp_crypto::keystore::validate_secret_name(name).is_ok() {
                        return;
                    }
                    findings.push(format!("{path}.secret has invalid secret name '{name}'"));
                    return;
                }
                if let Some(Value::String(sf)) = map.get("secretFile") {
                    if !sf.trim().is_empty() {
                        return;
                    }
                    findings.push(format!("{path}.secretFile cannot be empty"));
                    return;
                }
            }
            for (k, v) in map {
                let next_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if looks_like_secret_key_name(k) {
                    match v {
                        Value::String(s) if !s.trim().is_empty() => {
                            findings.push(format!(
                                "plaintext secret string at '{next_path}' (must use {{ \"secret\": \"<name>\" }})"
                            ));
                        }
                        Value::Object(_) | Value::Array(_) => {
                            scan_for_plaintext_secrets(v, &next_path, findings);
                        }
                        _ => {}
                    }
                } else {
                    scan_for_plaintext_secrets(v, &next_path, findings);
                }
            }
        }
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                scan_for_plaintext_secrets(item, &format!("{path}[{idx}]"), findings);
            }
        }
        Value::String(s) => {
            if looks_like_plaintext_secret_value(s) {
                findings.push(format!(
                    "value at '{path}' matches a known plaintext credential/token pattern"
                ));
            }
        }
        _ => {}
    }
}

fn validate_config_file(path: &Path, checks: &mut Vec<CliCheck>) -> Option<Value> {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            checks.push(CliCheck::fail(
                "config.read",
                format!("Failed to read {}: {e}", path.display()),
                Some("Verify --config path exists and is readable.".to_string()),
            ));
            return None;
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.mode() & 0o777;
            if (mode & 0o002) != 0 {
                checks.push(CliCheck::fail(
                    "config.permissions",
                    format!("{} is world-writable (mode {:04o})", path.display(), mode),
                    Some(format!("chmod 0640 {}", path.display())),
                ));
            } else {
                checks.push(CliCheck::ok(
                    "config.permissions",
                    format!("{} mode {:04o}", path.display(), mode),
                ));
            }
        }
    }

    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            checks.push(CliCheck::fail(
                "config.json",
                format!("Invalid JSON in {}: {e}", path.display()),
                Some("Fix JSON syntax errors in node.json.".to_string()),
            ));
            return None;
        }
    };

    // 1. Validate nodeId via hyp-proto
    match parsed.get("nodeId").and_then(Value::as_str) {
        Some(id) if id != LOCAL_NODE_ID && is_valid_node_id(id) => {
            checks.push(CliCheck::ok(
                "config.nodeId",
                format!("Valid canonical nodeId '{id}'"),
            ));
        }
        Some(id) => {
            checks.push(CliCheck::fail(
                "config.nodeId",
                format!("Invalid nodeId '{id}' (must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and not be 'local')"),
                Some("Set a valid lowercase nodeId such as \"acme-team\".".to_string()),
            ));
        }
        None => {
            checks.push(CliCheck::fail(
                "config.nodeId",
                "Missing required 'nodeId' field in node.json",
                Some("Add \"nodeId\": \"<your-node-id>\" to node.json.".to_string()),
            ));
        }
    }

    // 2. Validate profile
    match parsed.get("profile").and_then(Value::as_str) {
        Some(p @ ("local" | "router" | "p2p")) => {
            checks.push(CliCheck::ok("config.profile", format!("Profile '{p}'")));
        }
        Some(other) => {
            checks.push(CliCheck::fail(
                "config.profile",
                format!("Invalid profile '{other}' (expected local, router, or p2p)"),
                Some("Set \"profile\" to \"router\", \"p2p\", or \"local\".".to_string()),
            ));
        }
        None => {
            checks.push(CliCheck::warn(
                "config.profile",
                "No explicit 'profile' set; defaults to 'local'",
                Some("Set \"profile\": \"router\" for always-on internet hubs.".to_string()),
            ));
        }
    }

    // 3. Fail-closed plaintext secret scan
    let mut secret_findings = Vec::new();
    scan_for_plaintext_secrets(&parsed, "", &mut secret_findings);
    if secret_findings.is_empty() {
        checks.push(CliCheck::ok(
            "config.secrets",
            "Zero plaintext secrets found (references only)",
        ));
    } else {
        checks.push(CliCheck::fail(
            "config.secrets",
            format!("Plaintext secret(s) detected: {}", secret_findings.join("; ")),
            Some("Replace plaintext credentials with { \"secret\": \"<name>\" } stored via 'hyp secret set <name>'.".to_string()),
        ));
    }

    // 4. Bind address & reverse-proxy TLS safety check
    let listen_obj = parsed.get("listen");
    let bind_val = listen_obj
        .and_then(|l| l.get("bind"))
        .and_then(Value::as_str)
        .or_else(|| parsed.get("bind").and_then(Value::as_str));
    let behind_proxy = listen_obj
        .and_then(|l| l.get("behindReverseProxy"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if let Some(bind) = bind_val {
        if let Err(e) = validate_bind_addr(bind) {
            checks.push(CliCheck::fail(
                "config.bind",
                format!("Invalid bind address '{bind}': {e}"),
                Some("Use host:port format such as \"127.0.0.1:8790\".".to_string()),
            ));
        } else if is_loopback_bind(bind) {
            checks.push(CliCheck::ok(
                "config.bind",
                format!("Loopback bind '{bind}' (safe behind TLS proxy/tunnel)"),
            ));
        } else if is_wildcard_bind(bind) {
            if behind_proxy {
                checks.push(CliCheck::warn(
                    "config.bind",
                    format!(
                        "Wildcard bind '{bind}' with behindReverseProxy=true (ensure port is NOT exposed publicly without TLS)"
                    ),
                    Some("For non-container hosts, bind 127.0.0.1:8790 behind Caddy/Tailscale/Cloudflare.".to_string()),
                ));
            } else {
                checks.push(CliCheck::fail(
                    "config.bind",
                    format!(
                        "Unsafe plaintext HTTP bind on '{bind}' without reverse-proxy TLS (behindReverseProxy is false/unset)"
                    ),
                    Some("Change listen.bind to \"127.0.0.1:8790\" behind Caddy/Tailscale/Cloudflare, or set listen.behindReverseProxy=true inside an isolated container network.".to_string()),
                ));
            }
        } else {
            checks.push(CliCheck::warn(
                "config.bind",
                format!(
                    "Non-loopback bind '{bind}'; confirm TLS terminates in front of this interface"
                ),
                None,
            ));
        }
    } else {
        checks.push(CliCheck::warn(
            "config.bind",
            "No listen.bind configured (local-only mode)",
            None,
        ));
    }

    // 5. Public URL HTTPS check if present
    if let Some(pub_url) = listen_obj
        .and_then(|l| l.get("publicUrl"))
        .and_then(Value::as_str)
    {
        if let Err(e) = validate_endpoint_origin(pub_url) {
            checks.push(CliCheck::fail(
                "config.publicUrl",
                format!("Unsafe listen.publicUrl '{pub_url}': {e}"),
                Some("Use an https:// URL for internet-facing nodes.".to_string()),
            ));
        } else {
            checks.push(CliCheck::ok(
                "config.publicUrl",
                format!("Valid origin '{pub_url}'"),
            ));
        }
    }

    // 6. Forwarding policy check (no implicit open relay!)
    if let Some(mode) = parsed
        .get("forwarding")
        .and_then(|f| f.get("mode"))
        .and_then(Value::as_str)
    {
        if matches!(mode, "deny" | "allowlist") {
            checks.push(CliCheck::ok(
                "config.forwarding",
                format!("Forwarding policy '{mode}' (fail-closed)"),
            ));
        } else {
            checks.push(CliCheck::fail(
                "config.forwarding",
                format!("Unsafe forwarding.mode '{mode}' (only 'deny' or 'allowlist' permitted)"),
                Some(
                    "Set forwarding.mode to \"deny\" (or \"allowlist\" with explicit rules)."
                        .to_string(),
                ),
            ));
        }
    }

    // 7. Blind Drop Relay (`dropRelay` & `dropRelayUrl`) fail-closed validation
    if let Some(dr_val) = parsed.get("dropRelay") {
        match serde_json::from_value::<DropRelayConfig>(dr_val.clone()) {
            Ok(dr) => {
                let bad_origin = dr.allowed_origins.iter().find(|o| {
                    let t = o.trim();
                    t.is_empty() || t == "*" || t.eq_ignore_ascii_case("null")
                });
                if let Some(bad) = bad_origin {
                    checks.push(CliCheck::fail(
                        "config.dropRelay",
                        format!("Unsafe dropRelay.allowedOrigins entry '{bad}' (wildcards and null origins are forbidden)"),
                        Some("Set dropRelay.allowedOrigins to explicit HTTPS origins such as [\"https://hyphae.to\"].".to_string()),
                    ));
                } else if dr.max_memory_mb == 0 {
                    checks.push(CliCheck::fail(
                        "config.dropRelay",
                        "dropRelay.maxMemoryMb must be >= 1",
                        Some("Set dropRelay.maxMemoryMb to 256.".to_string()),
                    ));
                } else if dr.max_ttl_seconds == 0 || dr.max_ttl_seconds > 900 {
                    checks.push(CliCheck::fail(
                        "config.dropRelay",
                        format!(
                            "dropRelay.maxTtlSeconds ({}) must be in 1..=900",
                            dr.max_ttl_seconds
                        ),
                        Some("Set dropRelay.maxTtlSeconds <= 900 (15 minutes).".to_string()),
                    ));
                } else if dr.default_ttl_seconds == 0 || dr.default_ttl_seconds > dr.max_ttl_seconds
                {
                    checks.push(CliCheck::fail(
                        "config.dropRelay",
                        format!(
                            "dropRelay.defaultTtlSeconds ({}) must be in 1..={}",
                            dr.default_ttl_seconds, dr.max_ttl_seconds
                        ),
                        None,
                    ));
                } else {
                    checks.push(CliCheck::ok(
                        "config.dropRelay",
                        format!(
                            "Drop Relay {} (maxMemoryMb={}, ttl={}..={}s, origins={})",
                            if dr.enabled { "enabled" } else { "disabled" },
                            dr.max_memory_mb,
                            dr.default_ttl_seconds,
                            dr.max_ttl_seconds,
                            dr.allowed_origins.join(", ")
                        ),
                    ));
                }
            }
            Err(e) => {
                checks.push(CliCheck::fail(
                    "config.dropRelay",
                    format!("Malformed dropRelay block: {e}"),
                    None,
                ));
            }
        }
    }

    if let Some(raw_relay_url) = parsed
        .get("dropRelayUrl")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match validate_relay_url(raw_relay_url) {
            Ok(url) => checks.push(CliCheck::ok(
                "config.dropRelayUrl",
                format!("Valid Drop Relay URL '{url}'"),
            )),
            Err(e) => checks.push(CliCheck::fail(
                "config.dropRelayUrl",
                format!("Invalid dropRelayUrl '{raw_relay_url}': {e}"),
                Some("Run `hyp relay set https://<your-drop-relay>`.".to_string()),
            )),
        }
    }

    if let Some(dp_val) = parsed.get("dropPortalUrl") {
        if !dp_val.is_null() {
            match dp_val.as_str() {
                Some(raw_portal) => match normalize_drop_portal_url(raw_portal) {
                    Ok(url) => checks.push(CliCheck::ok(
                        "config.dropPortalUrl",
                        format!("Valid Drop Portal URL '{url}'"),
                    )),
                    Err(e) => checks.push(CliCheck::fail(
                        "config.dropPortalUrl",
                        format!("Invalid dropPortalUrl '{raw_portal}': {e}"),
                        Some(
                            "Set dropPortalUrl to an https:// URL (e.g. https://hyphae.to/drop)."
                                .to_string(),
                        ),
                    )),
                },
                None => checks.push(CliCheck::fail(
                    "config.dropPortalUrl",
                    "Invalid dropPortalUrl: must be a string",
                    Some(
                        "Set dropPortalUrl to an https:// URL (e.g. https://hyphae.to/drop)."
                            .to_string(),
                    ),
                )),
            }
        }
    }

    Some(parsed)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbedManifestSummary {
    url: String,
    http_status: u16,
    signed_envelope: bool,
    signature_verified: Option<bool>,
    node_id: String,
    profile: String,
    hyphae_version: String,
    protocol_min: u32,
    protocol_max: u32,
    audience: String,
    kid: String,
    capabilities: Vec<String>,
    require_pairing: bool,
    require_e2ee: bool,
    advertised_empty: bool,
    escalation_present: bool,
}

async fn probe_manifest_url(
    base_url: &str,
    checks: &mut Vec<CliCheck>,
) -> Option<ProbedManifestSummary> {
    // 1. Strictly enforce https:// or loopback http://
    if let Err(e) = validate_http_endpoint_origin(base_url) {
        checks.push(CliCheck::fail(
            "probe.origin",
            format!("Refusing unsafe URL '{base_url}': {e}"),
            Some("Serve Hyphae over HTTPS (Caddy, Tailscale Serve, Cloudflare Tunnel, or Fly.io). Only loopback http://127.0.0.1 is allowed for local testing.".to_string()),
        ));
        return None;
    }

    let trimmed = base_url.trim().trim_end_matches('/');
    let manifest_url = if trimmed.ends_with("/v1/manifest") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1/manifest")
    };

    let uri: http::Uri = match manifest_url.parse() {
        Ok(u) => u,
        Err(e) => {
            checks.push(CliCheck::fail(
                "probe.origin",
                format!("Invalid URI '{manifest_url}': {e}"),
                None,
            ));
            return None;
        }
    };

    // Ensure rustls has a default ring crypto provider installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: Client<_, Empty<hyper::body::Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let req = match http::Request::builder()
        .method(http::Method::GET)
        .uri(&uri)
        .header(http::header::ACCEPT, "application/json")
        .header(
            http::header::USER_AGENT,
            format!("hyp/{}", env!("CARGO_PKG_VERSION")),
        )
        .body(Empty::new())
    {
        Ok(r) => r,
        Err(e) => {
            checks.push(CliCheck::fail(
                "probe.request",
                format!("Failed to build HTTP request: {e}"),
                None,
            ));
            return None;
        }
    };

    let resp =
        match tokio::time::timeout(Duration::from_secs(PROBE_TIMEOUT_SECS), client.request(req))
            .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                checks.push(CliCheck::fail(
                    "probe.connect",
                    format!("GET {manifest_url} failed: {e}"),
                    Some(
                        "Verify the node is running, DNS resolves, and TLS certificates are valid."
                            .to_string(),
                    ),
                ));
                return None;
            }
            Err(_) => {
                checks.push(CliCheck::fail(
                    "probe.connect",
                    format!("GET {manifest_url} timed out after {PROBE_TIMEOUT_SECS}s"),
                    Some(
                        "Check firewall rules, reverse proxy upstream address, and node health."
                            .to_string(),
                    ),
                ));
                return None;
            }
        };

    let status = resp.status().as_u16();
    if status != 200 {
        let fix = if status == 404 {
            "GET /v1/manifest returned 404 — this may be a legacy Hyphae v1 node. Upgrade to Hyphae v2 for signed capability manifests."
        } else {
            "Verify your reverse proxy routes GET /v1/manifest to hyphae-node without requiring basic auth."
        };
        checks.push(CliCheck::fail(
            "probe.http",
            format!("GET {manifest_url} returned HTTP {status} (expected 200)"),
            Some(fix.to_string()),
        ));
        return None;
    }
    checks.push(CliCheck::ok(
        "probe.http",
        format!("GET {manifest_url} returned HTTP 200"),
    ));

    // Read bounded body
    let body_bytes = match tokio::time::timeout(Duration::from_secs(PROBE_TIMEOUT_SECS), async {
        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|e| format!("body read error: {e}"))?;
            if let Some(chunk) = frame.data_ref() {
                if out.len() + chunk.len() > MAX_MANIFEST_RESPONSE_BYTES {
                    return Err(format!(
                        "manifest response exceeds {MAX_MANIFEST_RESPONSE_BYTES} byte safety cap"
                    ));
                }
                out.extend_from_slice(chunk);
            }
        }
        Ok::<Vec<u8>, String>(out)
    })
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            checks.push(CliCheck::fail("probe.body", e, None));
            return None;
        }
        Err(_) => {
            checks.push(CliCheck::fail(
                "probe.body",
                "Timed out reading manifest response body",
                None,
            ));
            return None;
        }
    };

    let raw_json: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            checks.push(CliCheck::fail(
                "manifest.json",
                format!("Response from {manifest_url} is not valid JSON: {e}"),
                Some("Ensure /v1/manifest returns Hyphae SignedNodeManifest JSON (not an HTML proxy error page).".to_string()),
            ));
            return None;
        }
    };

    let (payload, signed_envelope, signature_verified) = if raw_json
        .get("payload")
        .and_then(Value::as_str)
        .is_some()
        && raw_json.get("sig").and_then(Value::as_str).is_some()
    {
        let signed: SignedNodeManifest = match serde_json::from_value(raw_json) {
            Ok(s) => s,
            Err(e) => {
                checks.push(CliCheck::fail(
                    "manifest.schema",
                    format!("Invalid SignedNodeManifest envelope: {e}"),
                    None,
                ));
                return None;
            }
        };
        let payload: NodeManifestPayload = match serde_json::from_str(&signed.payload) {
            Ok(p) => p,
            Err(e) => {
                checks.push(CliCheck::fail(
                    "manifest.schema",
                    format!("Invalid NodeManifestPayload JSON inside signed envelope: {e}"),
                    None,
                ));
                return None;
            }
        };
        // Verify Ed25519 signature over `"hyphae/v2/manifest\n" || payload` against embedded signingJwk.
        let crypto_jwk = CryptoOkpJwk::from(&payload.identity.signing_jwk);
        let sig_ok = match crypto_jwk.to_ed25519() {
            Ok(pk) => {
                match pk.verify_domain_b64("manifest", signed.payload.as_bytes(), &signed.sig) {
                    Ok(()) => {
                        checks.push(CliCheck::ok(
                            "manifest.signature",
                            format!("Valid Ed25519 signature (kid {})", payload.identity.kid),
                        ));
                        true
                    }
                    Err(e) => {
                        checks.push(CliCheck::fail(
                            "manifest.signature",
                            format!("Invalid Ed25519 manifest signature: {e}"),
                            Some("Check node signing key integrity and ensure proxies do not rewrite JSON bodies.".to_string()),
                        ));
                        false
                    }
                }
            }
            Err(e) => {
                checks.push(CliCheck::fail(
                    "manifest.signature",
                    format!("Invalid signingJwk in manifest: {e}"),
                    None,
                ));
                false
            }
        };
        (payload, true, Some(sig_ok))
    } else {
        let payload: NodeManifestPayload = match serde_json::from_value(raw_json) {
            Ok(p) => p,
            Err(e) => {
                checks.push(CliCheck::fail(
                    "manifest.schema",
                    format!(
                        "Response is not a valid NodeManifestPayload or SignedNodeManifest: {e}"
                    ),
                    None,
                ));
                return None;
            }
        };
        checks.push(CliCheck::warn(
            "manifest.signature",
            "Manifest served as unsigned raw JSON instead of SignedNodeManifest { payload, sig }",
            Some("Serve signed SignedNodeManifest envelopes on GET /v1/manifest.".to_string()),
        ));
        (payload, false, None)
    };

    // Anti-recon checks on unauthenticated GET /v1/manifest (§3.1)
    let advertised_empty = payload.advertised.is_empty();
    let escalation_present = payload.escalation.is_some();
    let audience_public = payload.audience == "public";

    if audience_public && advertised_empty && !escalation_present {
        checks.push(CliCheck::ok(
            "manifest.anti_recon",
            "Unauthenticated manifest is hardened (audience='public', empty advertised arrays, no escalation text)",
        ));
    } else {
        let mut leaks = Vec::new();
        if !audience_public {
            leaks.push(format!(
                "audience='{}' (expected 'public')",
                payload.audience
            ));
        }
        if !payload.advertised.topics.is_empty() {
            leaks.push(format!("{} topic(s)", payload.advertised.topics.len()));
        }
        if !payload.advertised.channels.is_empty() {
            leaks.push(format!("{} channel(s)", payload.advertised.channels.len()));
        }
        if !payload.advertised.kv_namespaces.is_empty() {
            leaks.push(format!(
                "{} kvNamespace(s)",
                payload.advertised.kv_namespaces.len()
            ));
        }
        if !payload.advertised.rpc_commands.is_empty() {
            leaks.push(format!(
                "{} rpcCommand(s)",
                payload.advertised.rpc_commands.len()
            ));
        }
        if escalation_present {
            leaks.push("escalation text".to_string());
        }
        checks.push(CliCheck::fail(
            "manifest.anti_recon",
            format!(
                "Unauthenticated GET /v1/manifest leaked internal metadata: {}",
                leaks.join(", ")
            ),
            Some("Enforce §3.1 anti-recon invariant: unauthenticated requests MUST return audience='public', empty advertised arrays, and no escalation block.".to_string()),
        ));
    }

    // Structural & cryptographic JWK/kid validation via hyp-proto
    // (Run individual checks so we still report protocol/version issues cleanly even when anti-recon failed.)
    if payload.v != 1 {
        checks.push(CliCheck::fail(
            "manifest.version",
            format!("Unsupported manifest schema v={} (expected 1)", payload.v),
            None,
        ));
    }
    match payload.identity.signing_jwk.thumbprint_sha256() {
        Ok(expected_kid) if expected_kid == payload.identity.kid => {
            if let Err(e) = payload
                .identity
                .encryption_jwk
                .validate(Some(hyp_proto::manifest::OkpCurve::X25519))
            {
                checks.push(CliCheck::fail(
                    "manifest.identity",
                    format!("Invalid encryptionJwk: {e}"),
                    None,
                ));
            } else {
                checks.push(CliCheck::ok(
                    "manifest.identity",
                    format!("Verified OKP JWKs & RFC 7638 kid {}", payload.identity.kid),
                ));
            }
        }
        Ok(expected_kid) => {
            checks.push(CliCheck::fail(
                "manifest.identity",
                format!(
                    "Manifest kid '{}' does not match signingJwk thumbprint '{}'",
                    payload.identity.kid, expected_kid
                ),
                None,
            ));
        }
        Err(e) => {
            checks.push(CliCheck::fail(
                "manifest.identity",
                format!("Invalid signingJwk: {e}"),
                None,
            ));
        }
    }

    // Protocol range intersection check
    let min_agreed = MIN_PROTOCOL_VERSION.max(payload.protocol_range.min);
    let max_agreed = PROTOCOL_VERSION.min(payload.protocol_range.max);
    if payload.protocol_range.min == 0 || payload.protocol_range.min > payload.protocol_range.max {
        checks.push(CliCheck::fail(
            "manifest.protocol",
            format!(
                "Malformed protocolRange {}..={}",
                payload.protocol_range.min, payload.protocol_range.max
            ),
            None,
        ));
    } else if max_agreed < min_agreed {
        checks.push(CliCheck::fail(
            "manifest.protocol",
            format!(
                "Protocol range {}..={} is incompatible with local {}..={}",
                payload.protocol_range.min,
                payload.protocol_range.max,
                MIN_PROTOCOL_VERSION,
                PROTOCOL_VERSION
            ),
            Some("Upgrade the node or local hyp CLI to a compatible protocol version.".to_string()),
        ));
    } else {
        checks.push(CliCheck::ok(
            "manifest.protocol",
            format!(
                "v{} agreed (remote {}..={}, hyphae {}, {} capabilities)",
                max_agreed,
                payload.protocol_range.min,
                payload.protocol_range.max,
                payload.hyphae_version,
                payload.capabilities.len()
            ),
        ));
    }

    // Expiry check
    match parse_rfc3339_millis(&payload.expires_at) {
        Ok(exp_ms) if exp_ms > now_unix_ms() => {
            checks.push(CliCheck::ok(
                "manifest.expiry",
                format!("Valid until {}", payload.expires_at),
            ));
        }
        Ok(_) => {
            checks.push(CliCheck::fail(
                "manifest.expiry",
                format!("Manifest expired at {}", payload.expires_at),
                Some("Check server clock skew (NTP) and manifest refresh interval.".to_string()),
            ));
        }
        Err(e) => {
            checks.push(CliCheck::fail(
                "manifest.expiry",
                format!("Invalid expiresAt timestamp '{}': {e}", payload.expires_at),
                None,
            ));
        }
    }

    let profile_str = serde_json::to_value(payload.profile)
        .ok()
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| format!("{:?}", payload.profile).to_ascii_lowercase());

    Some(ProbedManifestSummary {
        url: manifest_url,
        http_status: status,
        signed_envelope,
        signature_verified,
        node_id: payload.node_id.as_str().to_string(),
        profile: profile_str,
        hyphae_version: payload.hyphae_version,
        protocol_min: payload.protocol_range.min,
        protocol_max: payload.protocol_range.max,
        audience: payload.audience,
        kid: payload.identity.kid,
        capabilities: payload
            .capabilities
            .iter()
            .map(|c| c.as_str().to_string())
            .collect(),
        require_pairing: payload.policy.require_pairing,
        require_e2ee: payload.policy.require_e2ee,
        advertised_empty,
        escalation_present,
    })
}

fn run_check(
    url: Option<String>,
    config: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "deploy check";
    let tools = detect_local_tools();
    let mut checks = Vec::new();

    let installed_names: Vec<&str> = tools
        .iter()
        .filter(|t| t.installed)
        .map(|t| t.name)
        .collect();
    if installed_names.is_empty() {
        checks.push(CliCheck::warn(
            "tools.local",
            "No local deployment tools detected on PATH (checked: tailscale, cloudflared, docker, caddy, flyctl, systemctl)",
            Some("Install Tailscale, Caddy, Docker, cloudflared, or flyctl, or run `hyp deploy providers`.".to_string()),
        ));
    } else {
        checks.push(CliCheck::ok(
            "tools.local",
            format!("Detected: {}", installed_names.join(", ")),
        ));
    }

    let config_validated = config.as_ref().map(|p| {
        let valid_val = validate_config_file(p, &mut checks);
        json!({
            "path": p.display().to_string(),
            "loaded": valid_val.is_some(),
        })
    });

    let manifest_summary = if let Some(target_url) = url.as_deref() {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return Err(CliError::error(
                    "RUNTIME_ERROR",
                    format!("Failed to start async runtime: {e}"),
                ));
            }
        };
        rt.block_on(probe_manifest_url(target_url, &mut checks))
    } else {
        None
    };

    let fail_count = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .count();
    let warn_count = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warn)
        .count();
    let ok = fail_count == 0;

    let warnings: Vec<String> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warn)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();

    let mut next: Vec<String> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .filter_map(|c| c.fix.clone())
        .collect();
    if next.is_empty() {
        if config.is_none() && url.is_none() {
            next.push("hyp deploy providers".to_string());
            next.push("hyp deploy init tailscale --out ./deploy-tailscale".to_string());
        } else if let Some(ref summary) = manifest_summary {
            next.push(format!(
                "hyp pair invite --mode p2p --node-id {} --endpoint {}",
                summary.node_id,
                url.as_deref().unwrap_or(&summary.url)
            ));
        }
    }

    let summary = if ok {
        if warn_count > 0 {
            format!("Deployment check passed with {warn_count} warning(s)")
        } else {
            "All deployment checks passed".to_string()
        }
    } else {
        format!("Deployment check failed ({fail_count} failing check(s), {warn_count} warning(s))")
    };

    if as_json {
        let error = if ok {
            None
        } else {
            Some(
                CliError::error("DEPLOY_CHECK_FAILED".to_string(), summary.clone())
                    .with_optional_fix(next.first().cloned()),
            )
        };
        let envelope = JsonEnvelope::ok(
            cmd,
            summary,
            json!({
                "tools": tools,
                "config": config_validated,
                "manifest": manifest_summary,
                "checks": checks,
            }),
        )
        .warnings(warnings)
        .next(next)
        .error(error);
        print_json(&envelope);
    } else {
        println!("Hyphae Deployment Check");
        println!();
        print_checks(&checks);
        if let Some(m) = &manifest_summary {
            println!();
            println!(
                "Node: {} (profile={}, version={}, proto={}..={}, kid={})",
                m.node_id, m.profile, m.hyphae_version, m.protocol_min, m.protocol_max, m.kid
            );
            if !m.capabilities.is_empty() {
                println!("Capabilities: {}", m.capabilities.join(", "));
            }
        }
        print_next_steps(&next);
    }

    if ok {
        Ok(ExitCode::from(EXIT_OK))
    } else {
        Ok(ExitCode::from(EXIT_ERROR))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_file::load_node_or_legacy_config;

    const ALL_PROVIDERS: &[DeployProvider] = &[
        DeployProvider::Tailscale,
        DeployProvider::Vps,
        DeployProvider::Docker,
        DeployProvider::Cloudflare,
        DeployProvider::Fly,
        DeployProvider::PublicNode,
        DeployProvider::DropRelay,
    ];

    #[test]
    fn every_provider_node_json_parses_with_load_node_or_legacy_config_and_is_uid_10001_readable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for &provider in ALL_PROVIDERS {
            let profile = provider.default_profile();
            let node_id = provider.default_node_id();
            let domain = provider.default_domain();
            let bind = provider.default_bind();
            let enable_drop_relay = provider == DeployProvider::DropRelay;
            let out_dir = tmp.path().join(provider.as_str());
            fs::create_dir_all(&out_dir).expect("create out dir");

            let artifacts = build_provider_artifacts(
                provider,
                profile,
                node_id,
                domain,
                bind,
                enable_drop_relay,
                DEFAULT_DROP_RELAY_MEMORY_MB,
            );
            for a in &artifacts {
                write_artifact_file(
                    &out_dir.join(a.rel_path),
                    a.content.as_bytes(),
                    a.executable,
                )
                .expect("write artifact");
            }

            let node_path = out_dir.join("node.json");
            let loaded = load_node_or_legacy_config(&node_path).unwrap_or_else(|e| {
                panic!(
                    "load_node_or_legacy_config failed for provider {}: {e}",
                    provider.as_str()
                )
            });
            assert!(!loaded.is_legacy_v1);
            assert_eq!(loaded.node_id.as_deref(), Some(node_id));
            assert_eq!(
                loaded.bind_addr.expect("bind_addr present").to_string(),
                bind
            );
            assert_eq!(
                loaded.public_url.as_deref(),
                Some(format!("https://{domain}").as_str())
            );
            let raw_json: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&node_path).unwrap()).unwrap();
            assert_eq!(raw_json["stateDir"], "/var/lib/hyphae");
            assert!(
                loaded
                    .state_dir
                    .as_deref()
                    .is_some_and(|p| p.ends_with("var/lib/hyphae")),
                "expected state_dir ending with var/lib/hyphae, got {:?}",
                loaded.state_dir
            );

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&node_path).unwrap().permissions().mode() & 0o777;
                assert_ne!(
                    mode & 0o004,
                    0,
                    "node.json for {} must be readable by container UID 10001 (got mode {:04o})",
                    provider.as_str(),
                    mode
                );
                assert_eq!(
                    mode & 0o002,
                    0,
                    "node.json for {} must not be world-writable (got mode {:04o})",
                    provider.as_str(),
                    mode
                );
            }
        }
    }

    #[test]
    fn fly_and_drop_relay_default_bind_allows_fly_proxy_reachability() {
        assert_eq!(DeployProvider::Fly.default_bind(), "0.0.0.0:8790");
        assert_eq!(DeployProvider::DropRelay.default_bind(), "0.0.0.0:8790");
        assert_eq!(DeployProvider::Docker.default_bind(), "0.0.0.0:8790");
        assert!(DeployProvider::Fly.uses_container_proxy_bind());
        assert!(DeployProvider::DropRelay.uses_container_proxy_bind());
        assert!(DeployProvider::Docker.uses_container_proxy_bind());
    }
}
