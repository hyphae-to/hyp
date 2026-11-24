//! `hyp deploy` — Internet deployment provider catalog, hardened kit generator,
//! and fail-closed config + live manifest health checker.

use crate::ui::{
    CheckStatus, CliCheck, CliError, EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error,
    print_checks, print_json, print_next_steps, print_warnings,
};
use clap::{Subcommand, ValueEnum};
use http_body_util::{BodyExt, Empty};
use hyp_crypto::keys::OkpJwk as CryptoOkpJwk;
use hyp_crypto::pairing::validate_endpoint_origin;
use hyp_crypto::rfc3339::{now_unix_ms, parse_rfc3339_millis};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeployProvider {
    Tailscale,
    Vps,
    Docker,
    Cloudflare,
    Fly,
    PublicNode,
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
        }
    }

    pub const fn default_profile(self) -> DeployProfile {
        match self {
            Self::PublicNode => DeployProfile::Public,
            Self::Tailscale | Self::Vps | Self::Docker | Self::Cloudflare | Self::Fly => {
                DeployProfile::Router
            }
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
        }
    }

    pub const fn default_bind(self) -> &'static str {
        match self {
            Self::Docker | Self::Fly => "0.0.0.0:8790",
            Self::Tailscale | Self::Vps | Self::Cloudflare | Self::PublicNode => "127.0.0.1:8790",
        }
    }

    pub const fn uses_container_proxy_bind(self) -> bool {
        matches!(self, Self::Docker | Self::Fly)
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
    /// List all 6 supported internet deployment providers with TLS, NAT, and pros/cons
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
        /// Canonical Hyphae nodeId (e.g. acme-team, public.hyphae.to)
        #[arg(long)]
        node_id: Option<String>,
        /// Public or tailnet HTTPS hostname (without scheme, e.g. mesh.example.com)
        #[arg(long)]
        domain: Option<String>,
        /// Listen address (default 127.0.0.1:8790; 0.0.0.0:8790 inside isolated Docker/Fly containers)
        #[arg(long)]
        bind: Option<String>,
        /// Node profile (router, p2p, or public)
        #[arg(long, value_enum)]
        profile: Option<DeployProfile>,
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

pub fn run_deploy(command: DeployCommand) -> ExitCode {
    match command {
        DeployCommand::Providers { json } => run_providers(json),
        DeployCommand::Init {
            provider,
            node_id,
            domain,
            bind,
            profile,
            out,
            force,
            json,
        } => run_init(provider, node_id, domain, bind, profile, out, force, json),
        DeployCommand::Check { url, config, json } => run_check(url, config, json),
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

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
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
                "Optional Tailscale Funnel can expose webhook paths only",
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
    ]
}

fn run_providers(as_json: bool) -> ExitCode {
    let tools = detect_local_tools();
    let providers = build_provider_catalog(&tools);
    let next = vec![
        "hyp deploy init tailscale --out ./deploy-tailscale".to_string(),
        "hyp deploy init vps --node-id acme-team --domain mesh.example.com --out ./deploy-vps"
            .to_string(),
        "hyp deploy check".to_string(),
    ];

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: "deploy providers".to_string(),
            summary: Some(format!(
                "{} internet deployment providers supported",
                providers.len()
            )),
            data: Some(json!({
                "providers": providers,
                "detectedTools": tools,
            })),
            warnings: Vec::new(),
            next,
            error: None,
        };
        print_json(&envelope);
        return ExitCode::from(EXIT_OK);
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
        println!(
            "{:<12}  {:<8}  {:<36}  {}",
            p.id, tag, p.name, p.best_for
        );
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
    ExitCode::from(EXIT_OK)
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
        return Err(
            "domain may only contain ASCII letters, digits, dots, and hyphens".to_string(),
        );
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
    let (host, port_str) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| "bind address must have format <host>:<port> (e.g. 127.0.0.1:8790)".to_string())?;
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
    out_arg: Option<PathBuf>,
    force: bool,
    as_json: bool,
) -> ExitCode {
    let cmd = "deploy init";
    let profile = profile_arg.unwrap_or_else(|| provider.default_profile());
    let domain_raw = domain_arg.unwrap_or_else(|| provider.default_domain().to_string());
    let domain = match validate_domain_hostname(&domain_raw) {
        Ok(d) => d,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_DOMAIN",
                format!("Invalid --domain '{domain_raw}': {e}"),
                Some("Pass a bare hostname such as --domain mesh.example.com".to_string()),
            );
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
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_NODE_ID",
            format!(
                "Invalid --node-id '{node_id}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
            ),
            Some("Example: --node-id acme-team".to_string()),
        );
    }

    let bind_raw = bind_arg.unwrap_or_else(|| provider.default_bind().to_string());
    let bind = match validate_bind_addr(&bind_raw) {
        Ok(b) => b,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_BIND",
                format!("Invalid --bind '{bind_raw}': {e}"),
                Some("Example: --bind 127.0.0.1:8790".to_string()),
            );
        }
    };

    let out_dir = out_arg.unwrap_or_else(|| PathBuf::from(format!("hyphae-deploy-{}", provider.as_str())));
    let artifacts = build_provider_artifacts(provider, profile, &node_id, &domain, &bind);

    // Pre-flight overwrite guard: fail closed BEFORE creating or mutating any file.
    if !force {
        let existing: Vec<String> = artifacts
            .iter()
            .map(|a| out_dir.join(a.rel_path))
            .filter(|p| p.exists())
            .map(|p| p.display().to_string())
            .collect();
        if !existing.is_empty() {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "FILES_EXIST",
                format!(
                    "Refusing to overwrite existing deployment files without --force: {}",
                    existing.join(", ")
                ),
                Some(
                    "Re-run with --force to overwrite, or pass a fresh --out directory."
                        .to_string(),
                ),
            );
        }
    }

    if let Err(e) = fs::create_dir_all(&out_dir) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "IO_ERROR",
            format!("Failed to create output directory {}: {e}", out_dir.display()),
            None,
        );
    }

    let mut written_files = Vec::with_capacity(artifacts.len());
    for artifact in &artifacts {
        let full_path = out_dir.join(artifact.rel_path);
        if let Some(parent) = full_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "IO_ERROR",
                    format!("Failed to create directory {}: {e}", parent.display()),
                    None,
                );
            }
        }
        if let Err(e) = write_artifact_file(&full_path, artifact.content.as_bytes(), artifact.executable) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "IO_ERROR",
                format!("Failed to write {}: {e}", full_path.display()),
                None,
            );
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
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Generated {} deployment kit for '{}' in {}",
                provider.as_str(),
                node_id,
                out_dir.display()
            )),
            data: Some(json!({
                "provider": provider.as_str(),
                "profile": profile.as_str(),
                "nodeId": node_id,
                "domain": domain,
                "endpoint": format!("https://{domain}"),
                "bind": bind,
                "outDir": out_dir.display().to_string(),
                "files": written_files,
            })),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
        return ExitCode::from(EXIT_OK);
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
        println!(
            "  • {:<24} {}",
            a.rel_path, a.description
        );
    }
    print_warnings(&warnings);
    print_next_steps(&next);
    ExitCode::from(EXIT_OK)
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
        let mode = if executable { 0o750 } else { 0o640 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    Ok(())
}

fn build_node_json(
    provider: DeployProvider,
    profile: DeployProfile,
    node_id: &str,
    domain: &str,
    bind: &str,
) -> String {
    let behind_reverse_proxy = true;
    let state_dir = "/var/lib/hyphae";

    let config = if profile == DeployProfile::Public || provider == DeployProvider::PublicNode {
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
                    "topic": "github",
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
                    "stream:subscribe=github": "Request GitHub repo stream access from your Hyphae node admin."
                }
            }
        })
    };

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

fn render_dockerfile() -> String {
    r#"# syntax=docker/dockerfile:1
# Hyphae v2 multi-stage static Rust build (non-root UID 10001)

FROM rust:1.87-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked --bin hyp

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 hyphae \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/hyphae --shell /usr/sbin/nologin hyphae \
    && mkdir -p /var/lib/hyphae /etc/hyphae \
    && chown 10001:10001 /var/lib/hyphae /etc/hyphae \
    && chmod 0700 /var/lib/hyphae

COPY --from=builder /src/target/release/hyp /usr/local/bin/hyp

ENV HYPHAE_SECRET_BACKEND=file \
    HYPHAE_STATE_DIR=/var/lib/hyphae \
    HYPHAE_CONFIG=/etc/hyphae/node.json

USER 10001:10001
WORKDIR /var/lib/hyphae
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/hyp", "deploy", "check", "--url", "http://127.0.0.1:8790", "--json"]

ENTRYPOINT ["/usr/local/bin/hyp"]
CMD ["node", "start", "--config", "/etc/hyphae/node.json", "--no-local-socket"]
"#
    .to_string()
}

fn render_docker_compose(node_id: &str) -> String {
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
      - /tmp:size=32M,noexec,nosuid
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    environment:
      HYPHAE_SECRET_BACKEND: file
      HYPHAE_STATE_DIR: /var/lib/hyphae
      HYPHAE_CONFIG: /etc/hyphae/node.json
    volumes:
      - ./node.json:/etc/hyphae/node.json:ro
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
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
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

# OPTIONAL: Only if you need public GitHub/Stripe webhooks on a dedicated path,
# enable Tailscale Funnel ONLY on the webhook subpath (never on /v1/inbox or admin APIs):
# tailscale funnel --bg --https=443 --set-path=/webhooks "http://{bind}/webhooks"
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
    out
}

fn build_provider_artifacts(
    provider: DeployProvider,
    profile: DeployProfile,
    node_id: &str,
    domain: &str,
    bind: &str,
) -> Vec<GeneratedArtifact> {
    let node_json = build_node_json(provider, profile, node_id, domain, bind);
    let dummy_out = PathBuf::from(".");
    let next_for_readme = build_init_next_steps(provider, profile, node_id, domain, bind, &dummy_out);
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
                    description: "Multi-stage static Rust build (non-root UID 10001, manifest healthcheck)",
                    content: render_dockerfile(),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "docker-compose.yml",
                    description: "Docker Compose stack pairing hyphae-node with Caddy auto-TLS",
                    content: render_docker_compose(node_id),
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
                    description: "Fly.io Hyphae v2 node config (/var/lib/hyphae volume, secret refs only)",
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
                    description: "Multi-stage static Rust build (non-root UID 10001, manifest healthcheck)",
                    content: render_dockerfile(),
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
                    description: "Hardened Caddy auto-TLS reverse proxy (flush_interval -1, 1MB body cap)",
                    content: render_caddyfile(domain, bind, true),
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
                    description: "Multi-stage static Rust build (non-root UID 10001, manifest healthcheck)",
                    content: render_dockerfile(),
                    executable: false,
                },
                GeneratedArtifact {
                    rel_path: "docker-compose.yml",
                    description: "Optional Docker Compose stack pairing public hyphae-node with Caddy",
                    content: render_docker_compose(node_id).replace(
                        "./Caddyfile:/etc/caddy/Caddyfile:ro",
                        &format!("./Caddyfile:/etc/caddy/Caddyfile:ro # update upstream to hyphae-node:{port} when using Docker"),
                    ),
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

    match provider {
        DeployProvider::Tailscale => vec![
            format!("hyp deploy check --config {dir}/node.json"),
            format!("bash {dir}/tailscale-serve.sh  # exposes http://{bind} as https://{domain}"),
            format!("hyp deploy check --url https://{domain} --config {dir}/node.json"),
            pair_cmd,
        ],
        DeployProvider::Vps => vec![
            format!("sudo install -d -m 0750 /etc/hyphae && sudo cp {dir}/node.json /etc/hyphae/node.json"),
            format!("sudo cp {dir}/hyphae-node.service /etc/systemd/system/ && sudo cp {dir}/Caddyfile /etc/caddy/Caddyfile"),
            "sudo systemctl daemon-reload && sudo systemctl enable --now hyphae-node caddy".to_string(),
            format!("hyp deploy check --url https://{domain} --config /etc/hyphae/node.json"),
            pair_cmd,
        ],
        DeployProvider::Docker => vec![
            format!("hyp deploy check --config {dir}/node.json"),
            format!("cd {dir} && docker compose up -d --build"),
            format!("hyp deploy check --url https://{domain} --config {dir}/node.json"),
            pair_cmd,
        ],
        DeployProvider::Cloudflare => vec![
            format!("cloudflared tunnel create {node_id} && cloudflared tunnel route dns {node_id} {domain}"),
            format!("Edit {dir}/cloudflared.yml with your tunnel UUID, then run: cloudflared tunnel --config {dir}/cloudflared.yml run"),
            format!("hyp deploy check --url https://{domain} --config {dir}/node.json"),
            pair_cmd,
        ],
        DeployProvider::Fly => {
            let app_name = sanitize_fly_app_name(node_id, domain);
            vec![
                format!("hyp deploy check --config {dir}/node.json"),
                format!("cd {dir} && flyctl apps create {app_name} && flyctl volumes create hyphae_data --size 1"),
                format!("cd {dir} && flyctl deploy"),
                format!("hyp deploy check --url https://{domain} --config {dir}/node.json"),
                pair_cmd,
            ]
        }
        DeployProvider::PublicNode => vec![
            "hyp secret set github-public-token  # optional GitHub PAT for higher public ETag rate limits (never in node.json!)".to_string(),
            format!("hyp deploy check --config {dir}/node.json"),
            format!("Deploy with Caddy + systemd ({dir}/hyphae-node.service + {dir}/Caddyfile) or Docker Compose ({dir}/docker-compose.yml)"),
            format!("hyp deploy check --url https://{domain} --config {dir}/node.json"),
            pair_cmd,
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
                    format!(
                        "{} is world-writable (mode {:04o})",
                        path.display(),
                        mode
                    ),
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
                format!("Non-loopback bind '{bind}'; confirm TLS terminates in front of this interface"),
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
                Some("Set forwarding.mode to \"deny\" (or \"allowlist\" with explicit rules).".to_string()),
            ));
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
    if let Err(e) = validate_endpoint_origin(base_url) {
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

    let resp = match tokio::time::timeout(Duration::from_secs(PROBE_TIMEOUT_SECS), client.request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            checks.push(CliCheck::fail(
                "probe.connect",
                format!("GET {manifest_url} failed: {e}"),
                Some("Verify the node is running, DNS resolves, and TLS certificates are valid.".to_string()),
            ));
            return None;
        }
        Err(_) => {
            checks.push(CliCheck::fail(
                "probe.connect",
                format!("GET {manifest_url} timed out after {PROBE_TIMEOUT_SECS}s"),
                Some("Check firewall rules, reverse proxy upstream address, and node health.".to_string()),
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

    let (payload, signed_envelope, signature_verified) =
        if raw_json.get("payload").and_then(Value::as_str).is_some()
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
            let crypto_jwk = CryptoOkpJwk {
                kty: payload.identity.signing_jwk.kty.clone(),
                crv: payload.identity.signing_jwk.crv.as_str().to_string(),
                x: payload.identity.signing_jwk.x.clone(),
            };
            let sig_ok = match crypto_jwk.to_ed25519() {
                Ok(pk) => match pk.verify_domain_b64("manifest", signed.payload.as_bytes(), &signed.sig) {
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
                },
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
                        format!("Response is not a valid NodeManifestPayload or SignedNodeManifest: {e}"),
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
            leaks.push(format!("audience='{}' (expected 'public')", payload.audience));
        }
        if !payload.advertised.topics.is_empty() {
            leaks.push(format!("{} topic(s)", payload.advertised.topics.len()));
        }
        if !payload.advertised.channels.is_empty() {
            leaks.push(format!("{} channel(s)", payload.advertised.channels.len()));
        }
        if !payload.advertised.kv_namespaces.is_empty() {
            leaks.push(format!("{} kvNamespace(s)", payload.advertised.kv_namespaces.len()));
        }
        if !payload.advertised.rpc_commands.is_empty() {
            leaks.push(format!("{} rpcCommand(s)", payload.advertised.rpc_commands.len()));
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
            if let Err(e) = payload.identity.encryption_jwk.validate(Some(hyp_proto::manifest::OkpCurve::X25519)) {
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

fn run_check(url: Option<String>, config: Option<PathBuf>, as_json: bool) -> ExitCode {
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
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "RUNTIME_ERROR",
                    format!("Failed to start async runtime: {e}"),
                    None,
                );
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
            Some(CliError {
                code: "DEPLOY_CHECK_FAILED".to_string(),
                message: summary.clone(),
                fix: next.first().cloned(),
            })
        };
        let envelope = JsonEnvelope {
            ok,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "tools": tools,
                "config": config_validated,
                "manifest": manifest_summary,
                "checks": checks,
            })),
            warnings,
            next,
            error,
        };
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
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_ERROR)
    }
}
