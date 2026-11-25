//! Comprehensive integration tests for `hyp deploy` and `hyp pair`.
//!
//! Security & isolation invariants:
//! - Uses `tempfile::TempDir` everywhere (NEVER touches live macOS Keychain or `~/.config/hyphae`).
//! - Uses ephemeral loopback `127.0.0.1:0` mock manifest HTTP servers (zero external network calls).
//! - Covers McKeeman differential/mutated-valid-input cases (tampered tokens, leaky manifests,
//!   plaintext secret configs, unsafe wildcard binds, invalid domains/IDs, expired tokens).

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{ManagedProcess, isolated_cmd};
use hyp_crypto::compat_v1::issue_grant_v1;
use hyp_crypto::keys::{Ed25519KeyPair, NodeIdentityKeys};
use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_crypto::pairing::{AdminInviteV2, create_p2p_offer, encode_am2, encode_hp2p1};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_node::engine::{NodeConfig, NodeProfile as EngineNodeProfile, UnifiedNode};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::{
    AdvertisedResources, AdvertisedTopic, CapabilityToken, ManifestIdentity, ManifestPolicy,
    NodeManifestPayload, NodeProfile, OkpCurve, OkpJwk, ProtocolRange, SignedNodeManifest,
};
use hyp_proto::scopes::EscalationConfig;
use hyp_store::{KeyUse, NodeDb, PeerProfile, PeerStatus, TrustTier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn scrubbed_cmd() -> Command {
    let mut cmd = Command::new(common::hyp_bin());
    cmd.env("HYPHAE_SECRET_BACKEND", "file")
        .env("HYPHAE_NO_OPEN", "1")
        .env_remove("HYPHAE_CONFIG")
        .env_remove("HYPHAE_STATE_DIR")
        .env_remove("HYPHAE_CONFIG_DIR")
        .env_remove("HYPHAE_SOCKET")
        .env_remove("AGENTS_MESH_SOCKET")
        .env_remove("HYPHAE_RELEASE_PUBKEY")
        .env_remove("HYPHAE_DISABLE_AUTO_UPDATE")
        .env_remove("HYPHAE_DROP_PORTAL_URL")
        .env_remove("HYPHAE_TAILSCALE_BIN");
    cmd
}

fn spawn_one_shot_http_server(status_line: &str, body: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback port");
    let addr = listener.local_addr().unwrap();
    let status = status_line.to_string();
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut req_buf = [0u8; 4096];
            let _ = stream.read(&mut req_buf);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://127.0.0.1:{}", addr.port()), handle)
}

fn build_signed_manifest(
    node_id: &str,
    advertised: AdvertisedResources,
    escalation: Option<EscalationConfig>,
    tamper_sig: bool,
) -> String {
    let keys = NodeIdentityKeys::generate().unwrap();
    let signing_jwk = OkpJwk::new(OkpCurve::Ed25519, &keys.signing.public_key_bytes());
    let encryption_jwk = OkpJwk::new(OkpCurve::X25519, &keys.encryption.public_key_bytes());
    let kid = signing_jwk.thumbprint_sha256().unwrap();
    let now = now_unix_ms();

    let payload = NodeManifestPayload {
        v: 1,
        node_id: NodeId::new(node_id).unwrap(),
        profile: NodeProfile::Router,
        hyphae_version: "2.1.0".to_string(),
        protocol_range: ProtocolRange { min: 1, max: 2 },
        manifest_version: 1,
        issued_at: format_rfc3339_millis(now - 60_000),
        expires_at: format_rfc3339_millis(now + 3_600_000),
        audience: "public".to_string(),
        identity: ManifestIdentity {
            signing_jwk,
            encryption_jwk,
            kid,
            admin_jwk: None,
        },
        capabilities: vec![
            CapabilityToken::ManifestV1,
            CapabilityToken::EnvelopeCeV1,
            CapabilityToken::DmE2eeV1,
            CapabilityToken::SubPushdownV1,
        ],
        policy: ManifestPolicy {
            require_pairing: true,
            require_e2ee: true,
            max_text_bytes: 32_768,
            max_transfer_bytes: 52_428_800,
        },
        advertised,
        escalation,
    };

    let canonical = payload.to_canonical_payload().unwrap();
    let mut sig_bytes = keys.signing.sign_domain("manifest", canonical.as_bytes());
    if tamper_sig {
        sig_bytes[0] ^= 0x01;
    }
    let signed = SignedNodeManifest {
        payload: canonical,
        sig: URL_SAFE_NO_PAD.encode(sig_bytes),
    };
    serde_json::to_string(&signed).unwrap()
}

#[test]
fn deploy_providers_json_and_plain_list_all_six() {
    let out = scrubbed_cmd()
        .args(["deploy", "providers", "--json"])
        .output()
        .expect("run deploy providers --json");
    assert_eq!(out.status.code(), Some(0));

    let env: Value = serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(env["ok"], true);
    assert_eq!(env["command"], "deploy providers");
    let providers = env["data"]["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 7);
    let ids: Vec<&str> = providers
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![
            "tailscale",
            "vps",
            "docker",
            "cloudflare",
            "fly",
            "public-node",
            "drop-relay"
        ]
    );
    for p in providers {
        assert!(!p["tlsMethod"].as_str().unwrap().is_empty());
        assert!(!p["natFirewall"].as_str().unwrap().is_empty());
        assert!(!p["pros"].as_array().unwrap().is_empty());
        assert!(!p["cons"].as_array().unwrap().is_empty());
    }

    let plain = scrubbed_cmd()
        .args(["deploy", "providers"])
        .output()
        .expect("run deploy providers plain");
    assert_eq!(plain.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&plain.stdout);
    assert!(stdout.contains("tailscale"));
    assert!(stdout.contains("public-node"));
    assert!(stdout.contains("Next steps:"));
}

#[test]
fn deploy_init_all_six_providers_overwrite_guard_and_config_check() {
    let cases: &[(&str, &str, &str, &[&str])] = &[
        (
            "tailscale",
            "alice-tailnet",
            "hyphae.example.ts.net",
            &["node.json", "tailscale-serve.sh", "hyphae-node.service", "README.md"],
        ),
        (
            "vps",
            "acme-team",
            "mesh.acme.example",
            &["node.json", "Caddyfile", "hyphae-node.service", "README.md"],
        ),
        (
            "docker",
            "acme-docker",
            "docker.acme.example",
            &[
                "node.json",
                "Dockerfile",
                "docker-compose.yml",
                "Caddyfile",
                "README.md",
            ],
        ),
        (
            "cloudflare",
            "homelab-cf",
            "cf.acme.example",
            &["node.json", "cloudflared.yml", "hyphae-node.service", "README.md"],
        ),
        (
            "fly",
            "fly-hub",
            "hyphae-hub.fly.dev",
            &["node.json", "fly.toml", "Dockerfile", "README.md"],
        ),
        (
            "public-node",
            "public.hyphae.to",
            "public.hyphae.to",
            &[
                "node.json",
                "Caddyfile",
                "hyphae-node.service",
                "Dockerfile",
                "docker-compose.yml",
                "README.md",
            ],
        ),
    ];

    for &(provider, node_id, domain, expected_files) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let out_dir = tmp.path().join(provider);

        let out = scrubbed_cmd()
            .args([
                "deploy",
                "init",
                provider,
                "--node-id",
                node_id,
                "--domain",
                domain,
                "--out",
                out_dir.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run deploy init");
        assert_eq!(
            out.status.code(),
            Some(0),
            "provider={provider} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let env: Value = serde_json::from_slice(&out.stdout).expect("valid deploy init JSON");
        assert_eq!(env["ok"], true);
        assert_eq!(env["command"], "deploy init");
        assert_eq!(env["data"]["provider"], provider);
        assert_eq!(env["data"]["nodeId"], node_id);
        assert_eq!(env["data"]["domain"], domain);
        assert!(!env["next"].as_array().unwrap().is_empty());

        for rel in expected_files {
            let p = out_dir.join(rel);
            assert!(p.exists(), "missing expected file {} for {provider}", p.display());
            let content = fs::read_to_string(&p).unwrap();
            assert!(!content.trim().is_empty());
        }

        // Provider-specific hardening invariants
        if expected_files.contains(&"Caddyfile") {
            let caddy = fs::read_to_string(out_dir.join("Caddyfile")).unwrap();
            assert!(caddy.contains("flush_interval -1"), "Caddyfile must disable SSE buffering");
            assert!(caddy.contains(domain));
        }
        if expected_files.contains(&"hyphae-node.service") {
            let unit = fs::read_to_string(out_dir.join("hyphae-node.service"))
                .unwrap()
                .replace("\r\n", "\n");
            assert!(unit.contains("StateDirectory=hyphae"));
            assert!(unit.contains("ProtectSystem=strict"));
            assert!(unit.contains("NoNewPrivileges=yes"));
            assert!(unit.contains("StateDirectoryMode=0700"));
        }
        if expected_files.contains(&"Dockerfile") {
            let dockerfile = fs::read_to_string(out_dir.join("Dockerfile"))
                .unwrap()
                .replace("\r\n", "\n");
            assert!(dockerfile.contains(&format!("ARG HYP_VERSION=v{}", env!("CARGO_PKG_VERSION"))));
            assert!(dockerfile.contains("ARG TARGETARCH"));
            assert!(dockerfile.contains("x86_64-unknown-linux-musl"));
            assert!(dockerfile.contains("aarch64-unknown-linux-musl"));
            assert!(dockerfile.contains("https://github.com/hyphae-to/hyp/releases/download/${HYP_VERSION}"));
            assert!(dockerfile.contains("SHA256SUMS.txt"));
            assert!(dockerfile.contains("sha256sum -c --ignore-missing"));
            assert!(dockerfile.contains("USER 10001:10001"));
            assert!(dockerfile.contains("ENTRYPOINT [\"/usr/local/bin/hyp\"]"));
            assert!(
                !dockerfile.contains("COPY Cargo.toml") && !dockerfile.contains("COPY crates"),
                "Dockerfile for {provider} must work standalone without repo source tree"
            );
        }
        if matches!(provider, "vps" | "public-node") {
            let readme = fs::read_to_string(out_dir.join("README.md"))
                .unwrap()
                .replace("\r\n", "\n");
            let useradd_pos = readme
                .find("sudo useradd -r -s /usr/sbin/nologin hyphae || true")
                .unwrap_or_else(|| panic!("{provider} README missing useradd step:\n{readme}"));
            let bin_pos = readme
                .find("/usr/local/bin/hyp")
                .unwrap_or_else(|| panic!("{provider} README missing /usr/local/bin/hyp install:\n{readme}"));
            let dirs_pos = readme
                .find("sudo mkdir -p /var/lib/hyphae /etc/hyphae && sudo chown -R hyphae:hyphae /var/lib/hyphae /etc/hyphae && sudo chmod 0700 /var/lib/hyphae")
                .unwrap_or_else(|| panic!("{provider} README missing /var/lib/hyphae setup:\n{readme}"));
            let systemctl_pos = readme
                .find("systemctl enable --now")
                .unwrap_or_else(|| panic!("{provider} README missing systemctl enable --now:\n{readme}"));
            assert!(useradd_pos < systemctl_pos, "{provider} useradd must precede systemctl");
            assert!(bin_pos < systemctl_pos, "{provider} /usr/local/bin/hyp must precede systemctl");
            assert!(dirs_pos < systemctl_pos, "{provider} mkdir/chown must precede systemctl");

            let next_steps: Vec<&str> = env["next"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .collect();
            assert!(next_steps.iter().any(|s| s.contains("useradd -r -s /usr/sbin/nologin hyphae")));
            assert!(next_steps.iter().any(|s| s.contains("/usr/local/bin/hyp")));
            assert!(next_steps.iter().any(|s| s.contains("chmod 0700 /var/lib/hyphae")));
        }
        if expected_files.contains(&"fly.toml") {
            let fly = fs::read_to_string(out_dir.join("fly.toml")).unwrap();
            assert!(fly.contains("min_machines_running = 1"));
            assert!(fly.contains("/var/lib/hyphae"));
            assert!(fly.contains("force_https = true"));
        }
        if provider == "public-node" {
            let node_cfg: Value =
                serde_json::from_str(&fs::read_to_string(out_dir.join("node.json")).unwrap())
                    .unwrap();
            assert_eq!(node_cfg["publicReadOnly"], true);
            assert_eq!(node_cfg["guestPairing"]["preset"], "guest-ro");
            assert_eq!(node_cfg["sources"][0]["kind"], "github-public");
            assert_eq!(
                node_cfg["sources"][0]["githubToken"]["secret"],
                "github-public-token"
            );
        }

        // Every generated node.json MUST pass `deploy check --config` with zero FAIL checks & zero plaintext secrets!
        let check = scrubbed_cmd()
            .args([
                "deploy",
                "check",
                "--config",
                out_dir.join("node.json").to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run deploy check --config");
        assert_eq!(
            check.status.code(),
            Some(0),
            "generated node.json failed deploy check for {provider}: {}",
            String::from_utf8_lossy(&check.stdout)
        );
        let check_env: Value = serde_json::from_slice(&check.stdout).unwrap();
        assert_eq!(check_env["ok"], true);

        // Non-overwrite guard: re-running WITHOUT --force MUST fail closed (exit 1) and keep sentinel intact!
        let sentinel_path = out_dir.join("node.json");
        fs::write(&sentinel_path, "{\"sentinel\":true}\n").unwrap();
        let refuse = scrubbed_cmd()
            .args([
                "deploy",
                "init",
                provider,
                "--node-id",
                node_id,
                "--domain",
                domain,
                "--out",
                out_dir.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(refuse.status.code(), Some(1));
        let refuse_env: Value = serde_json::from_slice(&refuse.stdout).unwrap();
        assert_eq!(refuse_env["ok"], false);
        assert_eq!(refuse_env["error"]["code"], "FILES_EXIST");
        assert_eq!(
            fs::read_to_string(&sentinel_path).unwrap(),
            "{\"sentinel\":true}\n"
        );

        // Re-running WITH --force succeeds and regenerates cleanly.
        let forced = scrubbed_cmd()
            .args([
                "deploy",
                "init",
                provider,
                "--node-id",
                node_id,
                "--domain",
                domain,
                "--out",
                out_dir.to_str().unwrap(),
                "--force",
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(forced.status.code(), Some(0));
        let regenerated: Value =
            serde_json::from_str(&fs::read_to_string(&sentinel_path).unwrap()).unwrap();
        assert_eq!(regenerated["nodeId"], node_id);
    }

    // Mutated invalid inputs: reject Caddyfile injection in --domain and reserved 'local' --node-id
    let tmp = tempfile::tempdir().unwrap();
    let bad_domain = scrubbed_cmd()
        .args([
            "deploy",
            "init",
            "vps",
            "--domain",
            "evil.example { respond 200 }",
            "--out",
            tmp.path().join("bad1").to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_domain.status.code(), Some(2));

    let bad_node_id = scrubbed_cmd()
        .args([
            "deploy",
            "init",
            "vps",
            "--node-id",
            "local",
            "--out",
            tmp.path().join("bad2").to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_node_id.status.code(), Some(2));
}

#[test]
fn deploy_check_config_rejects_plaintext_secrets_and_unproxied_wildcard_bind() {
    let tmp = tempfile::tempdir().unwrap();

    // 1. Plaintext secret in node.json -> FAIL (exit 1)
    let leaky_cfg = tmp.path().join("leaky.json");
    fs::write(
        &leaky_cfg,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "acme-team",
            "profile": "router",
            "listen": { "bind": "127.0.0.1:8790", "behindReverseProxy": true },
            "sources": [{ "id": "gh", "githubToken": "ghp_supersecretplaintextvalue123" }],
            "forwarding": { "mode": "deny", "rules": [] }
        }))
        .unwrap(),
    )
    .unwrap();
    let out = scrubbed_cmd()
        .args(["deploy", "check", "--config", leaky_cfg.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let env: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(env["ok"], false);
    let checks = env["data"]["checks"].as_array().unwrap();
    assert!(checks.iter().any(|c| c["name"] == "config.secrets" && c["status"] == "fail"));

    // 2. Unproxied 0.0.0.0:8790 bind without behindReverseProxy -> FAIL (exit 1)
    let open_bind_cfg = tmp.path().join("open_bind.json");
    fs::write(
        &open_bind_cfg,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "acme-team",
            "profile": "router",
            "listen": { "bind": "0.0.0.0:8790", "behindReverseProxy": false },
            "forwarding": { "mode": "deny", "rules": [] }
        }))
        .unwrap(),
    )
    .unwrap();
    let out2 = scrubbed_cmd()
        .args(["deploy", "check", "--config", open_bind_cfg.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(1));
    let env2: Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(env2["ok"], false);
    assert!(env2["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "config.bind" && c["status"] == "fail"));

    // 3. Remote plaintext http:// URL -> FAIL immediately without network call
    let bad_url = scrubbed_cmd()
        .args(["deploy", "check", "--url", "http://mesh.example.com", "--json"])
        .output()
        .unwrap();
    assert_eq!(bad_url.status.code(), Some(1));
    let bad_env: Value = serde_json::from_slice(&bad_url.stdout).unwrap();
    assert_eq!(bad_env["ok"], false);
    assert!(bad_env["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "probe.origin" && c["status"] == "fail"));
}

#[test]
fn deploy_check_url_probes_hardened_and_rejects_leaky_or_tampered_manifests() {
    // 1. Passing hardened signed manifest (empty advertised arrays, no escalation)
    let good_body = build_signed_manifest(
        "acme-team",
        AdvertisedResources::default(),
        None,
        false,
    );
    let (good_url, good_srv) = spawn_one_shot_http_server("200 OK", good_body);
    let good_out = scrubbed_cmd()
        .args(["deploy", "check", "--url", &good_url, "--json"])
        .output()
        .unwrap();
    good_srv.join().unwrap();
    assert_eq!(
        good_out.status.code(),
        Some(0),
        "stdout={}",
        String::from_utf8_lossy(&good_out.stdout)
    );
    let good_env: Value = serde_json::from_slice(&good_out.stdout).unwrap();
    assert_eq!(good_env["ok"], true);
    assert_eq!(good_env["data"]["manifest"]["nodeId"], "acme-team");
    assert_eq!(good_env["data"]["manifest"]["advertisedEmpty"], true);
    assert_eq!(good_env["data"]["manifest"]["signatureVerified"], true);
    let checks = good_env["data"]["checks"].as_array().unwrap();
    assert!(checks.iter().any(|c| c["name"] == "manifest.anti_recon" && c["status"] == "ok"));
    assert!(checks.iter().any(|c| c["name"] == "manifest.signature" && c["status"] == "ok"));

    // 2. Failing leaky unauthenticated manifest (advertised topics/channels leaked!)
    let leaky_body = build_signed_manifest(
        "leaky-hub",
        AdvertisedResources {
            topics: vec![AdvertisedTopic {
                topic: "github".to_string(),
                kind: Some("webhook".to_string()),
                description: None,
            }],
            channels: vec!["#secops".to_string()],
            kv_namespaces: vec![],
            rpc_commands: vec![],
        },
        Some(EscalationConfig {
            default: Some("Ping #secret-admin".to_string()),
            by_scope: Default::default(),
        }),
        false,
    );
    let (leaky_url, leaky_srv) = spawn_one_shot_http_server("200 OK", leaky_body);
    let leaky_out = scrubbed_cmd()
        .args(["deploy", "check", "--url", &leaky_url, "--json"])
        .output()
        .unwrap();
    leaky_srv.join().unwrap();
    assert_eq!(leaky_out.status.code(), Some(1));
    let leaky_env: Value = serde_json::from_slice(&leaky_out.stdout).unwrap();
    assert_eq!(leaky_env["ok"], false);
    assert_eq!(leaky_env["data"]["manifest"]["advertisedEmpty"], false);
    assert!(leaky_env["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "manifest.anti_recon" && c["status"] == "fail"));

    // 3. Failing tampered Ed25519 signature on manifest
    let tampered_body = build_signed_manifest(
        "tampered-hub",
        AdvertisedResources::default(),
        None,
        true,
    );
    let (tampered_url, tampered_srv) = spawn_one_shot_http_server("200 OK", tampered_body);
    let tampered_out = scrubbed_cmd()
        .args(["deploy", "check", "--url", &tampered_url, "--json"])
        .output()
        .unwrap();
    tampered_srv.join().unwrap();
    assert_eq!(tampered_out.status.code(), Some(1));
    let tampered_env: Value = serde_json::from_slice(&tampered_out.stdout).unwrap();
    assert_eq!(tampered_env["ok"], false);
    assert!(tampered_env["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "manifest.signature" && c["status"] == "fail"));
}

#[test]
fn pair_guide_json_covers_all_topologies_and_presets() {
    let out = scrubbed_cmd()
        .args(["pair", "guide", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let env: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(env["ok"], true);
    assert_eq!(env["command"], "pair guide");

    let modes: Vec<&str> = env["data"]["topologies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["mode"].as_str().unwrap())
        .collect();
    assert_eq!(modes, vec!["team", "p2p", "public"]);

    let presets: Vec<&str> = env["data"]["presets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(presets, vec!["guest-ro", "guest", "observer", "member", "full"]);

    // Filtered mode
    let p2p_only = scrubbed_cmd()
        .args(["pair", "guide", "--mode", "p2p", "--json"])
        .output()
        .unwrap();
    assert_eq!(p2p_only.status.code(), Some(0));
    let p2p_env: Value = serde_json::from_slice(&p2p_only.stdout).unwrap();
    assert_eq!(p2p_env["data"]["topologies"].as_array().unwrap().len(), 1);
    assert_eq!(p2p_env["data"]["topologies"][0]["mode"], "p2p");
}

#[test]
fn pair_invite_p2p_and_team_roundtrip_via_stdin_and_token_file_and_fail_closed_mutations() {
    let state_dir = tempfile::tempdir().unwrap();

    // 1. P2P invite with explicit --grant, --request, --escalation
    let inv = scrubbed_cmd()
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--endpoint",
            "https://alice.tailnet.ts.net",
            "--peer",
            "bob@laptop",
            "--grant",
            "dm:*,files:send=25mb",
            "--request",
            "kv:read=pair/*",
            "--expires-hours",
            "12",
            "--escalation",
            "Ask @alice in #dev\x1b[31m\n\t for extra scopes",
            "--state-dir",
            state_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        inv.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&inv.stderr)
    );
    let inv_env: Value = serde_json::from_slice(&inv.stdout).unwrap();
    assert_eq!(inv_env["ok"], true);
    assert_eq!(inv_env["command"], "pair invite");
    let token = inv_env["data"]["token"].as_str().unwrap();
    let kid = inv_env["data"]["kid"].as_str().unwrap();
    let offer_id = inv_env["data"]["offerId"].as_str().unwrap();
    assert!(token.starts_with("hp2p1_"));
    // Next commands MUST be stdin-safe (<<<) and never leak token into argv
    assert!(inv_env["next"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s.as_str().unwrap().contains("<<<")));

    // Second invite in same state_dir preserves persistent node keypair `kid`, rotates `offerId`
    let inv2 = scrubbed_cmd()
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--endpoint",
            "https://alice.tailnet.ts.net",
            "--state-dir",
            state_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(inv2.status.code(), Some(0));
    let inv2_env: Value = serde_json::from_slice(&inv2.stdout).unwrap();
    assert_eq!(inv2_env["data"]["kid"].as_str().unwrap(), kid);
    assert_ne!(inv2_env["data"]["offerId"].as_str().unwrap(), offer_id);

    // 2. Pipe `hp2p1_` token via stdin into `pair inspect --json`
    let mut inspect_proc = scrubbed_cmd()
        .args(["pair", "inspect", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    inspect_proc
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{token}\n").as_bytes())
        .unwrap();
    let inspect_out = inspect_proc.wait_with_output().unwrap();
    assert_eq!(inspect_out.status.code(), Some(0));
    let insp: Value = serde_json::from_slice(&inspect_out.stdout).unwrap();
    assert_eq!(insp["ok"], true);
    assert_eq!(insp["command"], "pair inspect");
    assert_eq!(insp["data"]["format"], "hp2p1");
    assert_eq!(insp["data"]["nodeId"], "alice@macbook");
    assert_eq!(insp["data"]["endpoint"], "https://alice.tailnet.ts.net");
    assert_eq!(insp["data"]["kid"], kid);
    assert_eq!(insp["data"]["expiryStatus"], "OK");
    assert_eq!(
        insp["data"]["offeredScopes"],
        json!(["dm:send=*", "dm:receive", "files:send=25mb"])
    );
    assert_eq!(insp["data"]["requestedScopes"], json!(["kv:read=pair/*"]));
    // Escalation note sanitized (ESC/newline/tab control chars stripped) AND framed safely as untrusted: true!
    assert_eq!(insp["data"]["escalationNote"]["untrusted"], true);
    assert_eq!(
        insp["data"]["escalationNote"]["text"],
        "Ask @alice in #dev[31m for extra scopes"
    );
    assert!(
        !insp["data"]["escalationNote"]["text"]
            .as_str()
            .unwrap()
            .chars()
            .any(char::is_control)
    );
    // Raw 160-bit pairing secret MUST NOT appear in inspect output
    assert!(insp["data"].get("secret").is_none());

    // 3. Team (`am2_`) invite + inspect via `--token-file`
    let team_inv = scrubbed_cmd()
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-team",
            "--endpoint",
            "https://mesh.acme.internal",
            "--peer",
            "carol@linux",
            "--preset",
            "observer",
            "--escalation",
            "Ask #it-help for member tier",
            "--state-dir",
            state_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(team_inv.status.code(), Some(0));
    let team_env: Value = serde_json::from_slice(&team_inv.stdout).unwrap();
    let am2_token = team_env["data"]["token"].as_str().unwrap();
    let am2_kid = team_env["data"]["kid"].as_str().unwrap();
    assert!(am2_token.starts_with("am2_"));

    let token_path = state_dir.path().join("team.token");
    fs::write(&token_path, format!("{am2_token}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let am2_insp = scrubbed_cmd()
        .args([
            "pair",
            "inspect",
            "--token-file",
            token_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(am2_insp.status.code(), Some(0));
    let am2_insp_env: Value = serde_json::from_slice(&am2_insp.stdout).unwrap();
    assert_eq!(am2_insp_env["ok"], true);
    assert_eq!(am2_insp_env["data"]["format"], "am2");
    assert_eq!(am2_insp_env["data"]["nodeId"], "acme-team");
    assert_eq!(am2_insp_env["data"]["endpoint"], "https://mesh.acme.internal");
    assert_eq!(am2_insp_env["data"]["kid"], am2_kid);
    assert_eq!(am2_insp_env["data"]["expiryStatus"], "OK");
    assert_eq!(am2_insp_env["data"]["escalationNote"]["untrusted"], true);

    // 4. Legacy `t3mp1_` token inspection
    let legacy_admin = Ed25519KeyPair::generate().unwrap();
    let legacy_issued =
        issue_grant_v1(&legacy_admin, "legacy@box", &["*"], 60_000, now_unix_ms()).unwrap();
    let mut leg_proc = scrubbed_cmd()
        .args(["pair", "inspect", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    leg_proc
        .stdin
        .take()
        .unwrap()
        .write_all(legacy_issued.code.as_bytes())
        .unwrap();
    let leg_out = leg_proc.wait_with_output().unwrap();
    assert_eq!(leg_out.status.code(), Some(0));
    let leg_env: Value = serde_json::from_slice(&leg_out.stdout).unwrap();
    assert_eq!(leg_env["data"]["format"], "t3mp1");
    assert_eq!(leg_env["data"]["grantId"], legacy_issued.grant.id);
    assert_eq!(
        leg_env["data"]["adminFingerprint"],
        legacy_admin.fingerprint()
    );

    // 5. Mutated / tampered / expired tokens MUST fail closed with exit 1!
    // (a) Truncated/corrupted hp2p1_ token
    let corrupted = format!("{}AAAA_not_valid_json", &token[..12]);
    let mut bad_proc = scrubbed_cmd()
        .args(["pair", "inspect", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    bad_proc
        .stdin
        .take()
        .unwrap()
        .write_all(corrupted.as_bytes())
        .unwrap();
    let bad_out = bad_proc.wait_with_output().unwrap();
    assert_eq!(bad_out.status.code(), Some(1));
    let bad_env: Value = serde_json::from_slice(&bad_out.stdout).unwrap();
    assert_eq!(bad_env["ok"], false);
    assert_eq!(bad_env["error"]["code"], "INVALID_TOKEN");

    // (b) Expired hp2p1_ token -> exit 1 with expiryStatus == "EXPIRED"
    let alice_tmp = NodeIdentityKeys::generate().unwrap();
    let expired_offer = create_p2p_offer(
        "offer-expired",
        "alice@macbook",
        "https://alice.tailnet.ts.net",
        &alice_tmp,
        vec!["dm:send".into()],
        vec![],
        "2020-01-01T00:00:00Z",
    )
    .unwrap();
    let expired_token = encode_hp2p1(&expired_offer).unwrap();
    let mut exp_proc = scrubbed_cmd()
        .args(["pair", "inspect", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    exp_proc
        .stdin
        .take()
        .unwrap()
        .write_all(expired_token.as_bytes())
        .unwrap();
    let exp_out = exp_proc.wait_with_output().unwrap();
    assert_eq!(exp_out.status.code(), Some(1));
    let exp_env: Value = serde_json::from_slice(&exp_out.stdout).unwrap();
    assert_eq!(exp_env["ok"], false);
    assert_eq!(exp_env["error"]["code"], "TOKEN_EXPIRED");
    assert_eq!(exp_env["data"]["expiryStatus"], "EXPIRED");

    // (c) am2_ token with mismatched adminJwk vs t3mp1_ fingerprint -> exit 1
    let wrong_admin = Ed25519KeyPair::generate().unwrap();
    let bad_am2_json = serde_json::to_string(&AdminInviteV2 {
        v: 2,
        router: "https://mesh.acme.internal".into(),
        admin_jwk: wrong_admin.to_jwk(),
        pairing_code: legacy_issued.code.clone(),
        require_e2ee: Some(true),
    })
    .unwrap();
    assert!(encode_am2(&serde_json::from_str(&bad_am2_json).unwrap()).is_err());
    let forged_am2 = format!("am2_{}", URL_SAFE_NO_PAD.encode(bad_am2_json.as_bytes()));
    let mut forged_proc = scrubbed_cmd()
        .args(["pair", "inspect", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    forged_proc
        .stdin
        .take()
        .unwrap()
        .write_all(forged_am2.as_bytes())
        .unwrap();
    let forged_out = forged_proc.wait_with_output().unwrap();
    assert_eq!(forged_out.status.code(), Some(1));

    // (d) Reject remote plaintext http:// endpoint in `pair invite`
    let bad_ep = scrubbed_cmd()
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--endpoint",
            "http://public.insecure.example",
            "--state-dir",
            state_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_ep.status.code(), Some(2));

    // (e) Empty stdin and unknown prefix MUST fail closed (exit 1)
    let mut empty_proc = scrubbed_cmd()
        .args(["pair", "inspect", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    drop(empty_proc.stdin.take());
    let empty_out = empty_proc.wait_with_output().unwrap();
    assert_eq!(empty_out.status.code(), Some(1));
    let empty_env: Value = serde_json::from_slice(&empty_out.stdout).unwrap();
    assert_eq!(empty_env["error"]["code"], "EMPTY_TOKEN");

    // (f) Security invariant: `pair inspect` MUST NOT accept `--token <value>` in argv!
    let argv_token = scrubbed_cmd()
        .args(["pair", "inspect", "--token", token])
        .output()
        .unwrap();
    assert_eq!(argv_token.status.code(), Some(2));
}

#[test]
fn plain_tty_output_and_additional_config_fail_closed_checks() {
    let tmp = tempfile::tempdir().unwrap();

    // 1. Open relay forwarding mode -> FAIL (exit 1)
    let open_relay = tmp.path().join("relay.json");
    fs::write(
        &open_relay,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "acme-team",
            "profile": "router",
            "listen": { "bind": "127.0.0.1:8790", "behindReverseProxy": true },
            "forwarding": { "mode": "allow-all", "rules": [] }
        }))
        .unwrap(),
    )
    .unwrap();
    let relay_out = scrubbed_cmd()
        .args(["deploy", "check", "--config", open_relay.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(relay_out.status.code(), Some(1));
    let relay_env: Value = serde_json::from_slice(&relay_out.stdout).unwrap();
    assert!(relay_env["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "config.forwarding" && c["status"] == "fail"));

    // 2. Plain text output of `pair guide`, `deploy check`, `pair invite`, `pair inspect`
    let guide_plain = scrubbed_cmd()
        .args(["pair", "guide"])
        .output()
        .unwrap();
    assert_eq!(guide_plain.status.code(), Some(0));
    let guide_txt = String::from_utf8_lossy(&guide_plain.stdout);
    assert!(guide_txt.contains("hp2p1_"));
    assert!(guide_txt.contains("am2_"));
    assert!(guide_txt.contains("public.hyphae.to"));
    assert!(guide_txt.contains("guest-ro"));

    let check_plain = scrubbed_cmd()
        .args(["deploy", "check"])
        .output()
        .unwrap();
    assert_eq!(check_plain.status.code(), Some(0));
    let check_txt = String::from_utf8_lossy(&check_plain.stdout);
    assert!(check_txt.contains("Hyphae Deployment Check"));
    assert!(check_txt.contains("tools.local"));

    // 3. `deploy check --url` against HTTP 404 returns FAIL with legacy v1 hint
    let (not_found_url, srv) = spawn_one_shot_http_server("404 Not Found", "{}".to_string());
    let nf_out = scrubbed_cmd()
        .args(["deploy", "check", "--url", &not_found_url, "--json"])
        .output()
        .unwrap();
    srv.join().unwrap();
    assert_eq!(nf_out.status.code(), Some(1));
    let nf_env: Value = serde_json::from_slice(&nf_out.stdout).unwrap();
    assert!(nf_env["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "probe.http" && c["status"] == "fail"));
}

#[test]
fn pair_accept_p2p_and_team_persists_peers_keys_grants_and_rejects_tampered_or_expired() {
    let inviter_state = tempfile::tempdir().unwrap();
    let accepter_state = tempfile::tempdir().unwrap();

    // 1. P2P invite -> pair accept (stdin) with custom counter-grant & untrusted escalationNote
    let p2p_inv = scrubbed_cmd()
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--endpoint",
            "https://alice.tailnet.ts.net",
            "--peer",
            "bob@laptop",
            "--grant",
            "dm:*,files:send=25mb",
            "--request",
            "dm:send,kv:read=pair/*",
            "--escalation",
            "Ping @alice in #ops\x1b[31m\n for extra access",
            "--state-dir",
            inviter_state.path().to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert_eq!(p2p_inv.status.code(), Some(0));
    let p2p_inv_env: Value = serde_json::from_slice(&p2p_inv.stdout).unwrap();
    let hp2p1_token = p2p_inv_env["data"]["token"].as_str().unwrap();
    let alice_kid = p2p_inv_env["data"]["kid"].as_str().unwrap();
    let alice_enc_kid = p2p_inv_env["data"]["encryptionKid"].as_str().unwrap();
    assert!(hp2p1_token.starts_with("hp2p1_"));
    assert_eq!(
        p2p_inv_env["data"]["acceptCommandTemplate"],
        "hyp pair accept <<< '<token>'"
    );

    let mut accept_proc = scrubbed_cmd()
        .args([
            "pair",
            "accept",
            "--offline",
            "--state-dir",
            accepter_state.path().to_str().unwrap(),
            "--node-id",
            "bob@laptop",
            "--grant",
            "dm:send",
            "kv:read=pair/*",
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    accept_proc
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{hp2p1_token}\n").as_bytes())
        .unwrap();
    let accept_out = accept_proc.wait_with_output().unwrap();
    assert_eq!(
        accept_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&accept_out.stderr)
    );
    let accept_env: Value = serde_json::from_slice(&accept_out.stdout).unwrap();
    assert_eq!(accept_env["ok"], true);
    assert_eq!(accept_env["command"], "pair accept");
    assert_eq!(accept_env["data"]["offline"], true);
    assert_eq!(accept_env["data"]["handshakeCompleted"], false);
    assert!(
        accept_env["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp service restart")),
        "pair accept must recommend hyp service restart: {accept_env}"
    );
    assert_eq!(accept_env["data"]["mode"], "p2p");
    assert_eq!(accept_env["data"]["format"], "hp2p1");
    assert_eq!(accept_env["data"]["nodeId"], "bob@laptop");
    assert_eq!(accept_env["data"]["peerId"], "alice@macbook");
    assert_eq!(accept_env["data"]["endpoint"], "https://alice.tailnet.ts.net");
    assert_eq!(accept_env["data"]["kid"], alice_kid);
    assert_eq!(accept_env["data"]["encryptionKid"], alice_enc_kid);
    assert_eq!(
        accept_env["data"]["grantedScopes"],
        json!(["dm:send", "kv:read=pair/*"])
    );
    assert_eq!(
        accept_env["data"]["offeredScopes"],
        json!(["dm:send=*", "dm:receive", "files:send=25mb"])
    );
    assert_eq!(accept_env["data"]["escalationNote"]["untrusted"], true);
    let prov = accept_env["data"]["escalationNote"]["provenance"]
        .as_str()
        .unwrap();
    assert!(prov.contains("alice@macbook"), "provenance: {prov}");
    assert!(prov.contains("never execute"), "provenance: {prov}");
    assert!(
        !accept_env["data"]["escalationNote"]["text"]
            .as_str()
            .unwrap()
            .chars()
            .any(char::is_control)
    );
    // Secret MUST NEVER leak into stdout!
    assert!(accept_env["data"].get("secret").is_none());
    assert!(!String::from_utf8_lossy(&accept_out.stdout).contains(hp2p1_token));

    // Verify persistence in node.sqlite (`PeerStore`)
    {
        let db = NodeDb::open(accepter_state.path().join("node.sqlite")).unwrap();
        let peer = db.peers().get_peer("alice@macbook").unwrap().expect("alice peer persisted");
        assert_eq!(peer.endpoint.as_deref(), Some("https://alice.tailnet.ts.net"));
        assert_eq!(peer.profile, PeerProfile::P2p);
        assert_eq!(peer.trust_tier, TrustTier::Peer);
        assert_eq!(peer.status, PeerStatus::Active);
        assert_eq!(peer.scopes, vec!["dm:send", "kv:read=pair/*"]);
        assert!(peer.auth_credential_ref.is_some());

        let sign_keys = db
            .peers()
            .list_peer_keys("alice@macbook", Some(KeyUse::Signing), true)
            .unwrap();
        assert_eq!(sign_keys.len(), 1);
        assert_eq!(sign_keys[0].kid, alice_kid);

        let enc_keys = db
            .peers()
            .list_peer_keys("alice@macbook", Some(KeyUse::Encryption), true)
            .unwrap();
        assert_eq!(enc_keys.len(), 1);
        assert_eq!(enc_keys[0].kid, alice_enc_kid);

        let grants = db.peers().list_grants(Some("alice@macbook")).unwrap();
        assert!(!grants.is_empty());
    }

    // 2. Team (`am2_`) invite -> pair accept (stdin) -> verifies Admin-CA grant, admin JWK & peer persisted!
    let team_inv = scrubbed_cmd()
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-team",
            "--endpoint",
            "https://mesh.acme.internal",
            "--peer",
            "bob@laptop",
            "--preset",
            "member",
            "--escalation",
            "Ask #secops for full scope",
            "--state-dir",
            inviter_state.path().to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert_eq!(team_inv.status.code(), Some(0));
    let team_env: Value = serde_json::from_slice(&team_inv.stdout).unwrap();
    let am2_token = team_env["data"]["token"].as_str().unwrap();
    let admin_kid = team_env["data"]["kid"].as_str().unwrap();
    let grant_id = team_env["data"]["grantId"].as_str().unwrap();
    assert!(am2_token.starts_with("am2_"));

    let mut team_accept = scrubbed_cmd()
        .args([
            "pair",
            "accept",
            "--offline",
            "--state-dir",
            accepter_state.path().to_str().unwrap(),
            "--node-id",
            "bob@laptop",
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    team_accept
        .stdin
        .take()
        .unwrap()
        .write_all(am2_token.as_bytes())
        .unwrap();
    let team_accept_out = team_accept.wait_with_output().unwrap();
    assert_eq!(
        team_accept_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&team_accept_out.stderr)
    );
    let team_accept_env: Value = serde_json::from_slice(&team_accept_out.stdout).unwrap();
    assert_eq!(team_accept_env["ok"], true);
    assert_eq!(team_accept_env["command"], "pair accept");
    assert_eq!(team_accept_env["data"]["mode"], "team");
    assert_eq!(team_accept_env["data"]["format"], "am2");
    assert_eq!(team_accept_env["data"]["peerId"], "acme-team");
    assert_eq!(team_accept_env["data"]["grantId"], grant_id);
    assert_eq!(team_accept_env["data"]["kid"], admin_kid);
    assert_eq!(team_accept_env["data"]["escalationNote"]["untrusted"], true);

    {
        let db = NodeDb::open(accepter_state.path().join("node.sqlite")).unwrap();
        let hub = db.peers().get_peer("acme-team").unwrap().expect("acme-team peer persisted");
        assert_eq!(hub.endpoint.as_deref(), Some("https://mesh.acme.internal"));
        assert_eq!(hub.profile, PeerProfile::Router);
        assert_eq!(hub.trust_tier, TrustTier::Org);
        assert_eq!(hub.status, PeerStatus::Active);
        assert!(!hub.scopes.is_empty());

        let admin_keys = db
            .peers()
            .list_peer_keys("acme-team", Some(KeyUse::Admin), true)
            .unwrap();
        assert_eq!(admin_keys.len(), 1);
        assert_eq!(admin_keys[0].kid, admin_kid);

        let stored_grant = db.peers().get_grant(grant_id).unwrap().expect("Admin-CA grant persisted");
        assert_eq!(stored_grant.peer_id, "acme-team");
        assert_eq!(stored_grant.trust_tier, TrustTier::Org);
    }

    // 3. Fail-closed mutation tests on `pair accept`!
    let reject_state = tempfile::tempdir().unwrap();

    // (a) Tampered hp2p1_ offer scope (signature mismatch!) -> exit 1 & zero DB write!
    let mut hp2p1_obj: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(hp2p1_token.strip_prefix("hp2p1_").unwrap())
            .unwrap(),
    )
    .unwrap();
    hp2p1_obj["offeredScopes"] = json!(["*"]);
    let tampered_hp2p1 = format!(
        "hp2p1_{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&hp2p1_obj).unwrap())
    );
    let mut t1 = scrubbed_cmd()
        .args([
            "pair",
            "accept",
            "--state-dir",
            reject_state.path().to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    t1.stdin
        .take()
        .unwrap()
        .write_all(tampered_hp2p1.as_bytes())
        .unwrap();
    let t1_out = t1.wait_with_output().unwrap();
    assert_eq!(t1_out.status.code(), Some(1));
    let t1_env: Value = serde_json::from_slice(&t1_out.stdout).unwrap();
    assert_eq!(t1_env["ok"], false);
    assert_eq!(t1_env["error"]["code"], "INVALID_SIGNATURE");

    // (b) Expired hp2p1_ offer -> exit 1 (`TOKEN_EXPIRED`)
    let alice_tmp = NodeIdentityKeys::generate().unwrap();
    let expired_offer = create_p2p_offer(
        "offer-expired-accept",
        "alice@expired",
        "https://alice.tailnet.ts.net",
        &alice_tmp,
        vec!["dm:send".into()],
        vec![],
        "2020-01-01T00:00:00Z",
    )
    .unwrap();
    let expired_tok = encode_hp2p1(&expired_offer).unwrap();
    let mut t2 = scrubbed_cmd()
        .args([
            "pair",
            "accept",
            "--state-dir",
            reject_state.path().to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    t2.stdin
        .take()
        .unwrap()
        .write_all(expired_tok.as_bytes())
        .unwrap();
    let t2_out = t2.wait_with_output().unwrap();
    assert_eq!(t2_out.status.code(), Some(1));
    let t2_env: Value = serde_json::from_slice(&t2_out.stdout).unwrap();
    assert_eq!(t2_env["ok"], false);
    assert_eq!(t2_env["error"]["code"], "TOKEN_EXPIRED");

    // (c) Tampered am2_ scopes -> exit 1!
    let mut am2_obj: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(am2_token.strip_prefix("am2_").unwrap())
            .unwrap(),
    )
    .unwrap();
    am2_obj["scopes"] = json!(["*"]);
    let tampered_am2 = format!(
        "am2_{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&am2_obj).unwrap())
    );
    let mut t3 = scrubbed_cmd()
        .args([
            "pair",
            "accept",
            "--state-dir",
            reject_state.path().to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    t3.stdin
        .take()
        .unwrap()
        .write_all(tampered_am2.as_bytes())
        .unwrap();
    let t3_out = t3.wait_with_output().unwrap();
    assert_eq!(t3_out.status.code(), Some(1));
    let t3_env: Value = serde_json::from_slice(&t3_out.stdout).unwrap();
    assert_eq!(t3_env["ok"], false);

    // (d) Security invariant: `pair accept` MUST NOT accept `--token <value>` in argv!
    let argv_tok = scrubbed_cmd()
        .args(["pair", "accept", "--token", hp2p1_token])
        .output()
        .unwrap();
    assert_eq!(argv_tok.status.code(), Some(2));

    // Verify rejected state_dir has zero peers persisted!
    assert!(!reject_state.path().join("node.sqlite").exists());
}

#[test]
fn pair_join_verifies_live_rust_node_manifest_rejects_tampered_and_supports_offline() {
    let hub_tmp = tempfile::tempdir().unwrap();
    let client_tmp = tempfile::tempdir().unwrap();

    // 1. Start a live native Rust `hyp node start --profile router --bind 127.0.0.1:0` serving `/v1/manifest`
    let mut hub_cmd = isolated_cmd(hub_tmp.path());
    hub_cmd
        .args([
            "node",
            "start",
            "--profile",
            "router",
            "--node-id",
            "public.local",
            "--bind",
            "127.0.0.1:0",
            "--no-local-socket",
            "--state-dir",
            hub_tmp.path().to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut hub_proc = ManagedProcess::spawn("hyp node start (public.local)", &mut hub_cmd);
    let hub_env = hub_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(hub_env["ok"], true);
    assert!(hub_env["data"]["socketPath"].is_null());
    let hub_endpoint = hub_env["data"]["endpoint"].as_str().unwrap().to_string();
    let hub_kid = hub_env["data"]["kid"].as_str().unwrap().to_string();

    // 2. Run `hyp pair join <hub_endpoint> --state-dir <client_tmp> --json`
    let join_out = isolated_cmd(client_tmp.path())
        .args([
            "pair",
            "join",
            &hub_endpoint,
            "--state-dir",
            client_tmp.path().to_str().unwrap(),
            "--node-id",
            "dev@laptop",
            "--json",
        ])
        .output()
        .unwrap();

    // Clean up live router subprocess immediately after join (also guaranteed by Drop on panic)
    let _ = hub_proc.shutdown_gracefully();

    assert_eq!(
        join_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&join_out.stdout),
        String::from_utf8_lossy(&join_out.stderr)
    );
    let join_env: Value = serde_json::from_slice(&join_out.stdout).unwrap();
    assert_eq!(join_env["ok"], true);
    assert_eq!(join_env["command"], "pair join");
    assert_eq!(join_env["data"]["peerId"], "public.local");
    assert_eq!(join_env["data"]["nodeId"], "dev@laptop");
    assert_eq!(join_env["data"]["endpoint"], hub_endpoint);
    assert_eq!(join_env["data"]["preset"], "guest-ro");
    assert_eq!(join_env["data"]["trustTier"], "guest");
    assert_eq!(join_env["data"]["offline"], false);
    assert_eq!(join_env["data"]["manifestVerified"], true);
    assert_eq!(join_env["data"]["kid"], hub_kid);

    // Verify peer, pinned Ed25519 + X25519 keys, and cached manifest in node.sqlite (`PeerStore`)
    {
        let db = NodeDb::open(client_tmp.path().join("node.sqlite")).unwrap();
        let peer = db
            .peers()
            .get_peer("public.local")
            .unwrap()
            .expect("public.local peer persisted");
        assert_eq!(peer.endpoint.as_deref(), Some(hub_endpoint.as_str()));
        assert_eq!(peer.profile, PeerProfile::Router);
        assert_eq!(peer.trust_tier, TrustTier::Guest);
        assert_eq!(peer.status, PeerStatus::Active);
        assert_eq!(
            peer.scopes,
            vec!["stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]"]
        );
        assert!(peer.manifest_json.is_some());

        let sign_keys = db
            .peers()
            .list_peer_keys("public.local", Some(KeyUse::Signing), true)
            .unwrap();
        assert_eq!(sign_keys.len(), 1);
        assert_eq!(sign_keys[0].kid, hub_kid);

        let enc_keys = db
            .peers()
            .list_peer_keys("public.local", Some(KeyUse::Encryption), true)
            .unwrap();
        assert_eq!(enc_keys.len(), 1);
    }

    // 3. Fail-closed: tampered manifest signature MUST exit 1 and NOT persist peer!
    let tampered_body = build_signed_manifest(
        "tampered.local",
        AdvertisedResources::default(),
        None,
        true,
    );
    let (tampered_url, srv) = spawn_one_shot_http_server("200 OK", tampered_body);
    let bad_state = tempfile::tempdir().unwrap();
    let bad_join = scrubbed_cmd()
        .args([
            "pair",
            "join",
            &tampered_url,
            "--state-dir",
            bad_state.path().to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    srv.join().unwrap();
    assert_eq!(bad_join.status.code(), Some(1));
    let bad_env: Value = serde_json::from_slice(&bad_join.stdout).unwrap();
    assert_eq!(bad_env["ok"], false);
    assert_eq!(bad_env["error"]["code"], "INVALID_SIGNATURE");
    assert!(!bad_state.path().join("node.sqlite").exists());

    // 4. Fail-closed: remote plaintext `http://` URL rejected with exit 2 (`INVALID_ENDPOINT`)
    let insecure_join = scrubbed_cmd()
        .args([
            "pair",
            "join",
            "http://public.hyphae.to",
            "--state-dir",
            bad_state.path().to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert_eq!(insecure_join.status.code(), Some(2));
    let insec_env: Value = serde_json::from_slice(&insecure_join.stdout).unwrap();
    assert_eq!(insec_env["error"]["code"], "INVALID_ENDPOINT");

    // 5. Offline pre-configuration (`--offline`) derives `public.hyphae.to` and persists peer cleanly
    let offline_state = tempfile::tempdir().unwrap();
    let offline_join = scrubbed_cmd()
        .args([
            "pair",
            "join",
            "https://public.hyphae.to",
            "--offline",
            "--state-dir",
            offline_state.path().to_str().unwrap(),
            "--node-id",
            "dev@laptop",
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert_eq!(offline_join.status.code(), Some(0));
    let off_env: Value = serde_json::from_slice(&offline_join.stdout).unwrap();
    assert_eq!(off_env["ok"], true);
    assert_eq!(off_env["data"]["peerId"], "public.hyphae.to");
    assert_eq!(off_env["data"]["offline"], true);
    assert_eq!(off_env["data"]["manifestVerified"], false);

    let off_db = NodeDb::open(offline_state.path().join("node.sqlite")).unwrap();
    let off_peer = off_db
        .peers()
        .get_peer("public.hyphae.to")
        .unwrap()
        .expect("offline peer persisted");
    assert_eq!(off_peer.trust_tier, TrustTier::Guest);
    assert_eq!(off_peer.endpoint.as_deref(), Some("https://public.hyphae.to"));
    assert!(
        off_env["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp service restart")),
        "pair join must recommend hyp service restart: {off_env}"
    );
}

fn peer_auth_secret_name(peer_id: &str) -> String {
    let hash = hex::encode(Sha256::digest(peer_id.as_bytes()));
    format!("peer-auth-{}", &hash[..12])
}

#[test]
fn pair_live_p2p_handshake_single_use_replay_and_onboard_join() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let charlie_dir = tempfile::tempdir().unwrap();
    let offline_onboard_dir = tempfile::tempdir().unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    // 1. Start Node A (`UnifiedNode` bound on 127.0.0.1:0 sharing Node A's state_dir & SecretStore).
    let (node_a, alice_endpoint, server_handle) = rt.block_on(async {
        let mut cfg = NodeConfig::new(
            NodeId::new("alice@macbook").unwrap(),
            EngineNodeProfile::P2p,
            alice_dir.path(),
        );
        cfg.secret_backend = Some(SecretBackend::File);
        let node = UnifiedNode::open(cfg).expect("open Node A");
        let (addr, handle) = Arc::clone(&node)
            .serve("127.0.0.1:0".parse().unwrap())
            .await
            .expect("serve Node A HTTP");
        (node, format!("http://{addr}"), handle)
    });

    // 2. Run compiled `hyp pair invite --mode p2p` as a SEPARATE CLI process using Node A's state_dir!
    let inv_out = isolated_cmd(alice_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--endpoint",
            &alice_endpoint,
            "--grant",
            "dm:*,files:send=25mb",
            "--request",
            "dm:send,dm:receive",
            "--state-dir",
            alice_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run hyp pair invite --mode p2p");
    assert_eq!(
        inv_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inv_out.stdout),
        String::from_utf8_lossy(&inv_out.stderr)
    );
    let inv_env: Value = serde_json::from_slice(&inv_out.stdout).unwrap();
    let hp2p1_token = inv_env["data"]["token"].as_str().unwrap().to_string();
    let alice_kid = inv_env["data"]["kid"].as_str().unwrap().to_string();
    let alice_enc_kid = inv_env["data"]["encryptionKid"].as_str().unwrap().to_string();
    assert!(hp2p1_token.starts_with("hp2p1_"));

    let token_file = bob_dir.path().join("p2p.token");
    fs::write(&token_file, format!("{hp2p1_token}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // 3. Run compiled `hyp pair accept --token-file` for Node B -> REAL live HTTP POST /v1/p2p/pair/<offerId>!
    let accept_out = isolated_cmd(bob_dir.path())
        .args([
            "pair",
            "accept",
            "--token-file",
            token_file.to_str().unwrap(),
            "--node-id",
            "bob@laptop",
            "--state-dir",
            bob_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run live hyp pair accept");
    assert_eq!(
        accept_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&accept_out.stdout),
        String::from_utf8_lossy(&accept_out.stderr)
    );
    let accept_env: Value = serde_json::from_slice(&accept_out.stdout).unwrap();
    assert_eq!(accept_env["ok"], true);
    assert_eq!(accept_env["data"]["handshakeCompleted"], true);
    assert_eq!(accept_env["data"]["offline"], false);
    assert_eq!(accept_env["data"]["peerId"], "alice@macbook");
    assert!(
        accept_env["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp service restart"))
    );

    // Assert BOTH Node A's DB and Node B's DB have each other as Active peers with pinned JWKs
    // and Node B persisted the server-issued `authCredential` in SecretStore!
    {
        let db_a = NodeDb::open(alice_dir.path().join("node.sqlite")).unwrap();
        let bob_on_a = db_a
            .peers()
            .get_peer("bob@laptop")
            .unwrap()
            .expect("Node A must have Bob persisted as Active peer");
        assert_eq!(bob_on_a.status, PeerStatus::Active);
        assert_eq!(bob_on_a.profile, PeerProfile::P2p);
        assert_eq!(
            db_a.peers()
                .list_peer_keys("bob@laptop", Some(KeyUse::Signing), true)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            db_a.peers()
                .list_peer_keys("bob@laptop", Some(KeyUse::Encryption), true)
                .unwrap()
                .len(),
            1
        );

        let db_b = NodeDb::open(bob_dir.path().join("node.sqlite")).unwrap();
        let alice_on_b = db_b
            .peers()
            .get_peer("alice@macbook")
            .unwrap()
            .expect("Node B must have Alice persisted as Active peer");
        assert_eq!(alice_on_b.status, PeerStatus::Active);
        assert_eq!(alice_on_b.profile, PeerProfile::P2p);
        assert!(alice_on_b.manifest_json.is_some());
        let expected_cred_ref = peer_auth_secret_name("alice@macbook");
        assert_eq!(
            alice_on_b.auth_credential_ref.as_deref(),
            Some(expected_cred_ref.as_str())
        );

        let b_sign_keys = db_b
            .peers()
            .list_peer_keys("alice@macbook", Some(KeyUse::Signing), true)
            .unwrap();
        assert_eq!(b_sign_keys.len(), 1);
        assert_eq!(b_sign_keys[0].kid, alice_kid);
        let b_enc_keys = db_b
            .peers()
            .list_peer_keys("alice@macbook", Some(KeyUse::Encryption), true)
            .unwrap();
        assert_eq!(b_enc_keys.len(), 1);
        assert_eq!(b_enc_keys[0].kid, alice_enc_kid);

        let b_secrets = SecretStore::new(bob_dir.path(), SecretBackend::File);
        let auth_cred = b_secrets
            .get(&expected_cred_ref)
            .expect("authCredential must be saved in Node B SecretStore");
        assert!(!auth_cred.trim().is_empty());
        assert_ne!(&*auth_cred, hp2p1_token.as_str());
    }

    // 4. Single-use replay rejection: running `hyp pair accept` a SECOND time MUST fail closed!
    let replay_dir = tempfile::tempdir().unwrap();
    let replay_out = isolated_cmd(replay_dir.path())
        .args([
            "pair",
            "accept",
            "--token-file",
            token_file.to_str().unwrap(),
            "--node-id",
            "replay@laptop",
            "--state-dir",
            replay_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run replay hyp pair accept");
    assert_ne!(
        replay_out.status.code(),
        Some(0),
        "single-use hp2p1_ replay MUST fail closed! stdout={}",
        String::from_utf8_lossy(&replay_out.stdout)
    );
    let replay_env: Value = serde_json::from_slice(&replay_out.stdout).unwrap();
    assert_eq!(replay_env["ok"], false);

    // 5. Also verify `hyp onboard --join <token-file>` completes a live P2P handshake against Node A!
    let inv2_out = isolated_cmd(alice_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--endpoint",
            &alice_endpoint,
            "--preset",
            "member",
            "--state-dir",
            alice_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(inv2_out.status.code(), Some(0));
    let inv2_env: Value = serde_json::from_slice(&inv2_out.stdout).unwrap();
    let token2_file = charlie_dir.path().join("charlie.token");
    fs::write(
        &token2_file,
        format!("{}\n", inv2_env["data"]["token"].as_str().unwrap()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token2_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let onboard_live = isolated_cmd(charlie_dir.path())
        .args([
            "onboard",
            "--yes",
            "--no-start",
            "--node-id",
            "charlie@workstation",
            "--join",
            token2_file.to_str().unwrap(),
            "--state-dir",
            charlie_dir.path().to_str().unwrap(),
            "--home",
            charlie_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run hyp onboard --join live");
    assert_eq!(
        onboard_live.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&onboard_live.stdout),
        String::from_utf8_lossy(&onboard_live.stderr)
    );
    let onboard_json: Value = serde_json::from_slice(&onboard_live.stdout).unwrap();
    assert_eq!(onboard_json["ok"], true);
    assert_eq!(onboard_json["data"]["stagedJoin"]["paired"], true);
    assert_eq!(onboard_json["data"]["stagedJoin"]["status"], "active");
    let db_c = NodeDb::open(charlie_dir.path().join("node.sqlite")).unwrap();
    assert_eq!(
        db_c.peers().get_peer("alice@macbook").unwrap().unwrap().status,
        PeerStatus::Active
    );

    // Shut down Node A and verify unreachable `hyp onboard --join` warns & emits exact `hyp pair accept --token-file`!
    server_handle.abort();
    node_a.shutdown();
    drop(node_a);

    let inv3_out = isolated_cmd(alice_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--endpoint",
            &alice_endpoint,
            "--preset",
            "member",
            "--state-dir",
            alice_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(inv3_out.status.code(), Some(0));
    let inv3_env: Value = serde_json::from_slice(&inv3_out.stdout).unwrap();
    let unreachable_token_file = offline_onboard_dir.path().join("unreachable.token");
    fs::write(
        &unreachable_token_file,
        format!("{}\n", inv3_env["data"]["token"].as_str().unwrap()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&unreachable_token_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let onboard_offline = isolated_cmd(offline_onboard_dir.path())
        .args([
            "onboard",
            "--yes",
            "--no-start",
            "--node-id",
            "dave@offline",
            "--join",
            unreachable_token_file.to_str().unwrap(),
            "--state-dir",
            offline_onboard_dir.path().to_str().unwrap(),
            "--home",
            offline_onboard_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run hyp onboard --join unreachable");
    assert_eq!(onboard_offline.status.code(), Some(0));
    let off_onboard_json: Value = serde_json::from_slice(&onboard_offline.stdout).unwrap();
    assert_eq!(off_onboard_json["ok"], true);
    assert_eq!(off_onboard_json["data"]["stagedJoin"]["paired"], false);
    assert!(
        !off_onboard_json["warnings"].as_array().unwrap().is_empty(),
        "unreachable onboard --join must emit a warning: {off_onboard_json}"
    );
    let next_list: Vec<&str> = off_onboard_json["next"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        next_list
            .iter()
            .any(|s| s.contains("hyp pair accept --token-file")),
        "unreachable onboard --join must suggest `hyp pair accept --token-file`: {next_list:?}"
    );
    assert!(
        !next_list
            .iter()
            .any(|s| s.contains("start your node to activate")),
        "onboard --join must NEVER emit misleading staged-join-token activation prose: {next_list:?}"
    );
}

#[test]
fn node_cmd_admin_key_and_live_am2_pair_accept() {
    let hub_dir = tempfile::tempdir().unwrap();
    let hub_b64_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let client_b64_dir = tempfile::tempdir().unwrap();

    // 1. Invalid pairing.adminKey in node.json MUST fail closed with CONFIG_ERROR!
    let bad_cfg_path = hub_dir.path().join("bad-admin.json");
    fs::write(
        &bad_cfg_path,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "bad-hub",
            "profile": "router",
            "stateDir": hub_dir.path().to_str().unwrap(),
            "listen": { "bind": "127.0.0.1:0" },
            "pairing": { "adminKey": "not-a-valid-ed25519-key" }
        }))
        .unwrap(),
    )
    .unwrap();
    let bad_start = isolated_cmd(hub_dir.path())
        .args([
            "node",
            "start",
            "--config",
            bad_cfg_path.to_str().unwrap(),
            "--no-local-socket",
            "--json",
        ])
        .output()
        .expect("run node start with bad adminKey");
    assert_eq!(bad_start.status.code(), Some(1));
    let bad_env: Value = serde_json::from_slice(&bad_start.stdout).unwrap();
    assert_eq!(bad_env["ok"], false);
    assert_eq!(bad_env["error"]["code"], "CONFIG_ERROR");

    // 2. Mint an am2_ invite (creates Hub's Admin-CA key & persists signed GrantV2 in Hub's SQLite),
    //    then configure Hub's `node.json` with `pairing.adminKey` as an OKP Ed25519 JWK object,
    //    start compiled `hyp node start`, and run LIVE `hyp pair accept`!
    let pre_inv = isolated_cmd(hub_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-hub",
            "--endpoint",
            "http://127.0.0.1:1",
            "--peer",
            "setup-probe@laptop",
            "--preset",
            "member",
            "--state-dir",
            hub_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(pre_inv.status.code(), Some(0));
    let pre_env: Value = serde_json::from_slice(&pre_inv.stdout).unwrap();
    let admin_jwk = pre_env["data"]["adminJwk"].clone();
    let admin_x = admin_jwk["x"].as_str().expect("adminJwk.x").to_string();
    assert_eq!(admin_x.len(), 43);

    let hub_cfg_path = hub_dir.path().join("node.json");
    fs::write(
        &hub_cfg_path,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "acme-hub",
            "profile": "router",
            "stateDir": hub_dir.path().to_str().unwrap(),
            "listen": { "bind": "127.0.0.1:0" },
            "pairing": {
                "adminCa": true,
                "adminKey": admin_jwk
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let mut hub_cmd = isolated_cmd(hub_dir.path());
    hub_cmd
        .args([
            "node",
            "start",
            "--config",
            hub_cfg_path.to_str().unwrap(),
            "--no-local-socket",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut hub_proc = ManagedProcess::spawn("acme-hub (JWK adminKey)", &mut hub_cmd);
    let hub_startup = hub_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(hub_startup["ok"], true, "hub startup: {hub_startup}");
    let hub_endpoint = hub_startup["data"]["endpoint"]
        .as_str()
        .expect("hub endpoint")
        .to_string();

    let team_inv = isolated_cmd(hub_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-hub",
            "--endpoint",
            &hub_endpoint,
            "--peer",
            "bob@laptop",
            "--preset",
            "member",
            "--state-dir",
            hub_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(team_inv.status.code(), Some(0));
    let team_inv_env: Value = serde_json::from_slice(&team_inv.stdout).unwrap();
    let am2_token = team_inv_env["data"]["token"].as_str().unwrap().to_string();
    let am2_file = client_dir.path().join("team.token");
    fs::write(&am2_file, format!("{am2_token}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&am2_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let live_accept = isolated_cmd(client_dir.path())
        .args([
            "pair",
            "accept",
            "--token-file",
            am2_file.to_str().unwrap(),
            "--node-id",
            "bob@laptop",
            "--state-dir",
            client_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run live am2_ hyp pair accept");
    assert_eq!(
        live_accept.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&live_accept.stdout),
        String::from_utf8_lossy(&live_accept.stderr)
    );
    let acc_env: Value = serde_json::from_slice(&live_accept.stdout).unwrap();
    assert_eq!(acc_env["ok"], true);
    assert_eq!(acc_env["data"]["handshakeCompleted"], true);
    assert_eq!(acc_env["data"]["peerId"], "acme-hub");

    // Verify BOTH Hub DB and Client DB have Active peers, pinned JWKs, and Client saved `authCredential`!
    {
        let hub_db = NodeDb::open(hub_dir.path().join("node.sqlite")).unwrap();
        let bob_on_hub = hub_db
            .peers()
            .get_peer("bob@laptop")
            .unwrap()
            .expect("Hub must have Bob active after POST /v1/pair");
        assert_eq!(bob_on_hub.status, PeerStatus::Active);
        assert_eq!(
            hub_db
                .peers()
                .list_peer_keys("bob@laptop", Some(KeyUse::Signing), true)
                .unwrap()
                .len(),
            1
        );

        let client_db = NodeDb::open(client_dir.path().join("node.sqlite")).unwrap();
        let hub_on_client = client_db
            .peers()
            .get_peer("acme-hub")
            .unwrap()
            .expect("Client must have acme-hub active after POST /v1/pair");
        assert_eq!(hub_on_client.status, PeerStatus::Active);
        assert!(hub_on_client.manifest_json.is_some());
        let expected_cred_ref = peer_auth_secret_name("acme-hub");
        assert_eq!(
            hub_on_client.auth_credential_ref.as_deref(),
            Some(expected_cred_ref.as_str())
        );
        let client_secrets = SecretStore::new(client_dir.path(), SecretBackend::File);
        assert!(!client_secrets.get(&expected_cred_ref).unwrap().is_empty());
        assert_eq!(
            client_db
                .peers()
                .list_peer_keys("acme-hub", Some(KeyUse::Signing), true)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            client_db
                .peers()
                .list_peer_keys("acme-hub", Some(KeyUse::Admin), true)
                .unwrap()
                .len(),
            1
        );
    }

    // Single-use replay of `am2_` MUST fail closed!
    let replay_am2 = isolated_cmd(client_dir.path())
        .args([
            "pair",
            "accept",
            "--token-file",
            am2_file.to_str().unwrap(),
            "--node-id",
            "bob@laptop",
            "--state-dir",
            client_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_ne!(replay_am2.status.code(), Some(0));
    let _ = hub_proc.shutdown_gracefully();

    // 3. Also verify 43-char base64url string format for `pairing.adminKey` in `node.json`!
    let pre_b64 = isolated_cmd(hub_b64_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-b64-hub",
            "--endpoint",
            "http://127.0.0.1:1",
            "--peer",
            "probe@laptop",
            "--preset",
            "member",
            "--state-dir",
            hub_b64_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(pre_b64.status.code(), Some(0));
    let b64_admin_x = serde_json::from_slice::<Value>(&pre_b64.stdout).unwrap()["data"]["adminJwk"]
        ["x"]
        .as_str()
        .unwrap()
        .to_string();

    let b64_cfg_path = hub_b64_dir.path().join("node.json");
    fs::write(
        &b64_cfg_path,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "acme-b64-hub",
            "profile": "router",
            "stateDir": hub_b64_dir.path().to_str().unwrap(),
            "listen": { "bind": "127.0.0.1:0" },
            "pairing": {
                "adminCa": true,
                "adminKey": b64_admin_x
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let mut b64_cmd = isolated_cmd(hub_b64_dir.path());
    b64_cmd
        .args([
            "node",
            "start",
            "--config",
            b64_cfg_path.to_str().unwrap(),
            "--no-local-socket",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut b64_proc = ManagedProcess::spawn("acme-b64-hub (43-char adminKey)", &mut b64_cmd);
    let b64_startup = b64_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(b64_startup["ok"], true, "b64 hub startup: {b64_startup}");
    let b64_endpoint = b64_startup["data"]["endpoint"].as_str().unwrap().to_string();

    let b64_inv = isolated_cmd(hub_b64_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-b64-hub",
            "--endpoint",
            &b64_endpoint,
            "--peer",
            "carol@laptop",
            "--preset",
            "member",
            "--state-dir",
            hub_b64_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(b64_inv.status.code(), Some(0));
    let b64_token = serde_json::from_slice::<Value>(&b64_inv.stdout).unwrap()["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let b64_file = client_b64_dir.path().join("b64.token");
    fs::write(&b64_file, format!("{b64_token}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&b64_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let b64_accept = isolated_cmd(client_b64_dir.path())
        .args([
            "pair",
            "accept",
            "--token-file",
            b64_file.to_str().unwrap(),
            "--node-id",
            "carol@laptop",
            "--state-dir",
            client_b64_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    let _ = b64_proc.shutdown_gracefully();
    assert_eq!(
        b64_accept.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&b64_accept.stdout),
        String::from_utf8_lossy(&b64_accept.stderr)
    );
    let b64_acc_env: Value = serde_json::from_slice(&b64_accept.stdout).unwrap();
    assert_eq!(b64_acc_env["data"]["handshakeCompleted"], true);
    assert_eq!(b64_acc_env["data"]["daemonReloaded"], false);
}

#[test]
fn pair_accept_hot_reloads_running_daemon_without_restart_and_degrades_offline() {
    use hyp_harness::sock::{DEFAULT_SOCKET_FILENAME, daemon_rpc_sync};

    let alice_dir = tempfile::tempdir().unwrap();
    let hub_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let no_daemon_dir = tempfile::tempdir().unwrap();
    let offline_dir = tempfile::tempdir().unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    // 1. Start Alice P2P `UnifiedNode` on 127.0.0.1:0.
    let (node_a, alice_endpoint, alice_srv) = rt.block_on(async {
        let mut cfg = NodeConfig::new(
            NodeId::new("alice@macbook").unwrap(),
            EngineNodeProfile::P2p,
            alice_dir.path(),
        );
        cfg.secret_backend = Some(SecretBackend::File);
        let node = UnifiedNode::open(cfg).expect("open Alice P2P node");
        let (addr, handle) = Arc::clone(&node)
            .serve("127.0.0.1:0".parse().unwrap())
            .await
            .expect("serve Alice HTTP");
        (node, format!("http://{addr}"), handle)
    });

    // 2. Start a compiled Team Hub (`acme-hot-hub`) with `pairing.adminKey`.
    let pre_inv = isolated_cmd(hub_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-hot-hub",
            "--endpoint",
            "http://127.0.0.1:1",
            "--peer",
            "bootstrap@laptop",
            "--preset",
            "member",
            "--state-dir",
            hub_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(pre_inv.status.code(), Some(0));
    let admin_jwk = serde_json::from_slice::<Value>(&pre_inv.stdout).unwrap()["data"]["adminJwk"]
        .clone();

    let hub_cfg_path = hub_dir.path().join("node.json");
    fs::write(
        &hub_cfg_path,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "acme-hot-hub",
            "profile": "router",
            "stateDir": hub_dir.path().to_str().unwrap(),
            "listen": { "bind": "127.0.0.1:0" },
            "pairing": {
                "adminCa": true,
                "adminKey": admin_jwk
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let mut hub_cmd = isolated_cmd(hub_dir.path());
    hub_cmd
        .args([
            "node",
            "start",
            "--config",
            hub_cfg_path.to_str().unwrap(),
            "--no-local-socket",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut hub_proc = ManagedProcess::spawn("acme-hot-hub", &mut hub_cmd);
    let hub_startup = hub_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(hub_startup["ok"], true, "hub startup: {hub_startup}");
    let hub_endpoint = hub_startup["data"]["endpoint"]
        .as_str()
        .expect("hub endpoint")
        .to_string();

    // 3. Start Bob's LIVE compiled `hyp node start` daemon WITH local IPC socket enabled!
    let mut bob_cmd = isolated_cmd(bob_dir.path());
    bob_cmd
        .args([
            "node",
            "start",
            "--node-id",
            "bob@laptop",
            "--state-dir",
            bob_dir.path().to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut bob_proc = ManagedProcess::spawn("bob@laptop daemon", &mut bob_cmd);
    let bob_startup = bob_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(bob_startup["ok"], true, "bob startup: {bob_startup}");
    assert_eq!(
        bob_startup["data"]["connectedPeers"].as_array().unwrap().len(),
        0
    );
    let bob_sock = bob_dir.path().join(DEFAULT_SOCKET_FILENAME);

    // 4. Mint an `hp2p1_` offer from Alice and accept it on Bob via compiled `hyp pair accept --json`
    //    WITHOUT restarting Bob's daemon!
    let p2p_inv = isolated_cmd(alice_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--endpoint",
            &alice_endpoint,
            "--preset",
            "member",
            "--state-dir",
            alice_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(p2p_inv.status.code(), Some(0));
    let p2p_tok = serde_json::from_slice::<Value>(&p2p_inv.stdout).unwrap()["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let p2p_file = bob_dir.path().join("alice-p2p.token");
    fs::write(&p2p_file, format!("{p2p_tok}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p2p_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let p2p_accept = isolated_cmd(bob_dir.path())
        .args([
            "pair",
            "accept",
            "--token-file",
            p2p_file.to_str().unwrap(),
            "--node-id",
            "bob@laptop",
            "--state-dir",
            bob_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run hyp pair accept hp2p1 against live daemon");
    assert_eq!(
        p2p_accept.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&p2p_accept.stdout),
        String::from_utf8_lossy(&p2p_accept.stderr)
    );
    let p2p_acc_env: Value = serde_json::from_slice(&p2p_accept.stdout).unwrap();
    assert_eq!(p2p_acc_env["ok"], true);
    assert_eq!(p2p_acc_env["data"]["handshakeCompleted"], true);
    assert_eq!(
        p2p_acc_env["data"]["daemonReloaded"], true,
        "live daemon must be hot-reloaded automatically: {p2p_acc_env}"
    );
    assert!(
        !p2p_acc_env["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp service restart")),
        "hot-reloaded pair accept must NOT tell user to restart daemon: {p2p_acc_env}"
    );

    // Verify `node.status.json` was atomically refreshed and second `peers.reload` is idempotent!
    let status_after_p2p: Value =
        serde_json::from_slice(&fs::read(bob_dir.path().join("node.status.json")).unwrap())
            .unwrap();
    assert_eq!(status_after_p2p["connectedPeers"], json!(["alice@macbook"]));
    let idemp1 = daemon_rpc_sync(
        &bob_sock,
        &json!({ "type": "peers.reload" }),
        Duration::from_secs(2),
    );
    assert!(idemp1.ok, "idempotent peers.reload failed: {idemp1:?}");
    let idemp1_res = idemp1.result.unwrap();
    assert_eq!(idemp1_res["reloaded"], true);
    assert_eq!(idemp1_res["activePeers"], 1);
    assert_eq!(idemp1_res["added"], 0);

    // 5. Mint an `am2_` Team Hub invite and accept it in plain TTY mode against the SAME running daemon!
    let team_inv = isolated_cmd(hub_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-hot-hub",
            "--endpoint",
            &hub_endpoint,
            "--peer",
            "bob@laptop",
            "--preset",
            "member",
            "--state-dir",
            hub_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(team_inv.status.code(), Some(0));
    let am2_tok = serde_json::from_slice::<Value>(&team_inv.stdout).unwrap()["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let am2_file = bob_dir.path().join("hub-team.token");
    fs::write(&am2_file, format!("{am2_tok}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&am2_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let am2_accept = isolated_cmd(bob_dir.path())
        .args([
            "pair",
            "accept",
            "--token-file",
            am2_file.to_str().unwrap(),
            "--node-id",
            "bob@laptop",
            "--state-dir",
            bob_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("run TTY hyp pair accept am2 against live daemon");
    assert_eq!(
        am2_accept.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&am2_accept.stdout),
        String::from_utf8_lossy(&am2_accept.stderr)
    );
    let am2_stdout = String::from_utf8_lossy(&am2_accept.stdout);
    assert!(
        am2_stdout.contains("Live daemon reloaded — peer connected immediately (no restart needed)."),
        "TTY output must announce live daemon reload: {am2_stdout}"
    );
    assert!(
        !am2_stdout.contains("hyp service restart"),
        "TTY output must not instruct restart when live reload succeeded: {am2_stdout}"
    );

    let status_after_both: Value =
        serde_json::from_slice(&fs::read(bob_dir.path().join("node.status.json")).unwrap())
            .unwrap();
    assert_eq!(
        status_after_both["connectedPeers"],
        json!(["acme-hot-hub", "alice@macbook"])
    );
    let idemp2 = daemon_rpc_sync(
        &bob_sock,
        &json!({ "type": "peers.reload" }),
        Duration::from_secs(2),
    );
    assert!(idemp2.ok);
    let idemp2_res = idemp2.result.unwrap();
    assert_eq!(idemp2_res["activePeers"], 2);
    assert_eq!(idemp2_res["added"], 0);

    let _ = bob_proc.shutdown_gracefully();
    let _ = hub_proc.shutdown_gracefully();

    // 6. Verify clean degradation when NO daemon is running (live handshake -> daemonReloaded: false + restart hint)
    //    AND when `--offline` is passed!
    let p2p_inv2 = isolated_cmd(alice_dir.path())
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--endpoint",
            &alice_endpoint,
            "--preset",
            "member",
            "--state-dir",
            alice_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(p2p_inv2.status.code(), Some(0));
    let p2p_tok2 = serde_json::from_slice::<Value>(&p2p_inv2.stdout).unwrap()["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let tok2_file = no_daemon_dir.path().join("nodaemon.token");
    fs::write(&tok2_file, format!("{p2p_tok2}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tok2_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let no_daemon_accept = isolated_cmd(no_daemon_dir.path())
        .args([
            "pair",
            "accept",
            "--token-file",
            tok2_file.to_str().unwrap(),
            "--node-id",
            "carol@laptop",
            "--state-dir",
            no_daemon_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run live hyp pair accept without local daemon");
    assert_eq!(no_daemon_accept.status.code(), Some(0));
    let no_daemon_env: Value = serde_json::from_slice(&no_daemon_accept.stdout).unwrap();
    assert_eq!(no_daemon_env["ok"], true);
    assert_eq!(no_daemon_env["data"]["handshakeCompleted"], true);
    assert_eq!(no_daemon_env["data"]["daemonReloaded"], false);
    assert!(
        no_daemon_env["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp service restart")),
        "no-daemon pair accept must suggest hyp service restart: {no_daemon_env}"
    );

    // Offline accept degrades cleanly with daemonReloaded: false and restart hint.
    let offline_accept = isolated_cmd(offline_dir.path())
        .args([
            "pair",
            "accept",
            "--token-file",
            tok2_file.to_str().unwrap(),
            "--node-id",
            "dave@offline",
            "--offline",
            "--state-dir",
            offline_dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run --offline hyp pair accept");
    assert_eq!(offline_accept.status.code(), Some(0));
    let offline_env: Value = serde_json::from_slice(&offline_accept.stdout).unwrap();
    assert_eq!(offline_env["ok"], true);
    assert_eq!(offline_env["data"]["offline"], true);
    assert_eq!(offline_env["data"]["daemonReloaded"], false);
    assert!(
        offline_env["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp service restart"))
    );

    alice_srv.abort();
    node_a.shutdown();
}

#[test]
fn pair_invite_p2p_tailscale_magicdns_autodetect_and_missing_endpoint_guidance() {
    let dir = tempfile::tempdir().unwrap();

    // 1. Hermetic disabled Tailscale -> p2p without --endpoint exits 2 with MISSING_ENDPOINT + guidance
    let no_ts = isolated_cmd(dir.path())
        .env("HYPHAE_TAILSCALE_BIN", "none")
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "alice@macbook",
            "--state-dir",
            dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run p2p invite without endpoint and without tailscale");
    assert_eq!(no_ts.status.code(), Some(2));
    let no_ts_env: Value = serde_json::from_slice(&no_ts.stdout).unwrap();
    assert_eq!(no_ts_env["ok"], false);
    assert_eq!(no_ts_env["error"]["code"], "MISSING_ENDPOINT");
    assert!(
        no_ts_env["error"]["fix"]
            .as_str()
            .unwrap_or_default()
            .contains("--endpoint"),
        "error fix must guide user to pass --endpoint: {no_ts_env}"
    );

    // 2. Team mode without --endpoint always requires explicit --endpoint
    let team_no_ep = isolated_cmd(dir.path())
        .env("HYPHAE_TAILSCALE_BIN", "none")
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-team",
            "--state-dir",
            dir.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run team invite without endpoint");
    assert_eq!(team_no_ep.status.code(), Some(2));
    let team_no_ep_env: Value = serde_json::from_slice(&team_no_ep.stdout).unwrap();
    assert_eq!(team_no_ep_env["ok"], false);
    assert_eq!(team_no_ep_env["error"]["code"], "MISSING_ENDPOINT");

    // 3. On Unix, exercise full subprocess Tailscale MagicDNS auto-detection with isolated mock scripts!
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mock_running = dir.path().join("mock-tailscale-running.sh");
        fs::write(
            &mock_running,
            "#!/bin/sh\nprintf '%s\n' '{\"BackendState\":\"Running\",\"Self\":{\"DNSName\":\"alice-mbp.tail9f3a.ts.net.\",\"Online\":true}}'\n",
        )
        .unwrap();
        fs::set_permissions(&mock_running, fs::Permissions::from_mode(0o700)).unwrap();

        let auto_ok = isolated_cmd(dir.path())
            .env("HYPHAE_TAILSCALE_BIN", mock_running.to_str().unwrap())
            .args([
                "pair",
                "invite",
                "--mode",
                "p2p",
                "--node-id",
                "alice@macbook",
                "--state-dir",
                dir.path().to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run p2p invite with mock running tailscale");
        assert_eq!(
            auto_ok.status.code(),
            Some(0),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&auto_ok.stdout),
            String::from_utf8_lossy(&auto_ok.stderr)
        );
        let auto_env: Value = serde_json::from_slice(&auto_ok.stdout).unwrap();
        assert_eq!(auto_env["ok"], true);
        assert_eq!(
            auto_env["data"]["endpoint"],
            "https://alice-mbp.tail9f3a.ts.net"
        );
        assert_eq!(auto_env["data"]["endpointAutoDetected"], true);
        let tok = auto_env["data"]["token"].as_str().unwrap();
        let decoded = hyp_crypto::pairing::decode_hp2p1(tok).expect("valid hp2p1 token");
        assert_eq!(decoded.endpoint, "https://alice-mbp.tail9f3a.ts.net");

        // Team mode MUST NOT auto-detect Tailscale even when mock tailscale is Running!
        let team_with_ts = isolated_cmd(dir.path())
            .env("HYPHAE_TAILSCALE_BIN", mock_running.to_str().unwrap())
            .args([
                "pair",
                "invite",
                "--mode",
                "team",
                "--node-id",
                "acme-team",
                "--state-dir",
                dir.path().to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(team_with_ts.status.code(), Some(2));
        let team_with_ts_env: Value = serde_json::from_slice(&team_with_ts.stdout).unwrap();
        assert_eq!(team_with_ts_env["error"]["code"], "MISSING_ENDPOINT");

        // Stopped Tailscale -> rejected fail-closed with MISSING_ENDPOINT!
        let mock_stopped = dir.path().join("mock-tailscale-stopped.sh");
        fs::write(
            &mock_stopped,
            "#!/bin/sh\nprintf '%s\n' '{\"BackendState\":\"Stopped\",\"Self\":{\"DNSName\":\"alice-mbp.tail9f3a.ts.net.\",\"Online\":false}}'\n",
        )
        .unwrap();
        fs::set_permissions(&mock_stopped, fs::Permissions::from_mode(0o700)).unwrap();

        let stopped_out = isolated_cmd(dir.path())
            .env("HYPHAE_TAILSCALE_BIN", mock_stopped.to_str().unwrap())
            .args([
                "pair",
                "invite",
                "--mode",
                "p2p",
                "--node-id",
                "alice@macbook",
                "--state-dir",
                dir.path().to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(stopped_out.status.code(), Some(2));
        let stopped_env: Value = serde_json::from_slice(&stopped_out.stdout).unwrap();
        assert_eq!(stopped_env["error"]["code"], "MISSING_ENDPOINT");
    }
}
