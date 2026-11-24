//! Comprehensive integration tests for `hyp deploy` and `hyp pair`.
//!
//! Security & isolation invariants:
//! - Uses `tempfile::TempDir` everywhere (NEVER touches live macOS Keychain or `~/.config/hyphae`).
//! - Uses ephemeral loopback `127.0.0.1:0` mock manifest HTTP servers (zero external network calls).
//! - Covers McKeeman differential/mutated-valid-input cases (tampered tokens, leaky manifests,
//!   plaintext secret configs, unsafe wildcard binds, invalid domains/IDs, expired tokens).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyp_crypto::compat_v1::issue_grant_v1;
use hyp_crypto::keys::{Ed25519KeyPair, NodeIdentityKeys};
use hyp_crypto::pairing::{AdminInviteV2, create_p2p_offer, encode_am2, encode_hp2p1};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::{
    AdvertisedResources, AdvertisedTopic, CapabilityToken, ManifestIdentity, ManifestPolicy,
    NodeManifestPayload, NodeProfile, OkpCurve, OkpJwk, ProtocolRange, SignedNodeManifest,
};
use hyp_proto::scopes::EscalationConfig;
use hyp_store::{KeyUse, NodeDb, PeerProfile, PeerStatus, TrustTier};
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;

fn hyp_rs_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hyp")
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
    let out = Command::new(hyp_rs_bin())
        .args(["deploy", "providers", "--json"])
        .output()
        .expect("run deploy providers --json");
    assert_eq!(out.status.code(), Some(0));

    let env: Value = serde_json::from_slice(&out.stdout).expect("valid JSON envelope");
    assert_eq!(env["ok"], true);
    assert_eq!(env["command"], "deploy providers");
    let providers = env["data"]["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 6);
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
            "public-node"
        ]
    );
    for p in providers {
        assert!(!p["tlsMethod"].as_str().unwrap().is_empty());
        assert!(!p["natFirewall"].as_str().unwrap().is_empty());
        assert!(!p["pros"].as_array().unwrap().is_empty());
        assert!(!p["cons"].as_array().unwrap().is_empty());
    }

    let plain = Command::new(hyp_rs_bin())
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

        let out = Command::new(hyp_rs_bin())
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
            let unit = fs::read_to_string(out_dir.join("hyphae-node.service")).unwrap();
            assert!(unit.contains("StateDirectory=hyphae"));
            assert!(unit.contains("ProtectSystem=strict"));
            assert!(unit.contains("NoNewPrivileges=yes"));
            assert!(unit.contains("StateDirectoryMode=0700"));
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
        let check = Command::new(hyp_rs_bin())
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
        let refuse = Command::new(hyp_rs_bin())
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
        let forced = Command::new(hyp_rs_bin())
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
    let bad_domain = Command::new(hyp_rs_bin())
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

    let bad_node_id = Command::new(hyp_rs_bin())
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
    let out = Command::new(hyp_rs_bin())
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
    let out2 = Command::new(hyp_rs_bin())
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
    let bad_url = Command::new(hyp_rs_bin())
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
    let good_out = Command::new(hyp_rs_bin())
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
    let leaky_out = Command::new(hyp_rs_bin())
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
    let tampered_out = Command::new(hyp_rs_bin())
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
    let out = Command::new(hyp_rs_bin())
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
    let p2p_only = Command::new(hyp_rs_bin())
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
    let inv = Command::new(hyp_rs_bin())
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
    let inv2 = Command::new(hyp_rs_bin())
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
    let mut inspect_proc = Command::new(hyp_rs_bin())
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
    let team_inv = Command::new(hyp_rs_bin())
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
    let am2_insp = Command::new(hyp_rs_bin())
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
    let mut leg_proc = Command::new(hyp_rs_bin())
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
    let mut bad_proc = Command::new(hyp_rs_bin())
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
    let mut exp_proc = Command::new(hyp_rs_bin())
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
    let mut forged_proc = Command::new(hyp_rs_bin())
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
    let bad_ep = Command::new(hyp_rs_bin())
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
    let mut empty_proc = Command::new(hyp_rs_bin())
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
    let argv_token = Command::new(hyp_rs_bin())
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
    let relay_out = Command::new(hyp_rs_bin())
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
    let guide_plain = Command::new(hyp_rs_bin())
        .args(["pair", "guide"])
        .output()
        .unwrap();
    assert_eq!(guide_plain.status.code(), Some(0));
    let guide_txt = String::from_utf8_lossy(&guide_plain.stdout);
    assert!(guide_txt.contains("hp2p1_"));
    assert!(guide_txt.contains("am2_"));
    assert!(guide_txt.contains("public.hyphae.to"));
    assert!(guide_txt.contains("guest-ro"));

    let check_plain = Command::new(hyp_rs_bin())
        .args(["deploy", "check"])
        .output()
        .unwrap();
    assert_eq!(check_plain.status.code(), Some(0));
    let check_txt = String::from_utf8_lossy(&check_plain.stdout);
    assert!(check_txt.contains("Hyphae Deployment Check"));
    assert!(check_txt.contains("tools.local"));

    // 3. `deploy check --url` against HTTP 404 returns FAIL with legacy v1 hint
    let (not_found_url, srv) = spawn_one_shot_http_server("404 Not Found", "{}".to_string());
    let nf_out = Command::new(hyp_rs_bin())
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
    let p2p_inv = Command::new(hyp_rs_bin())
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

    let mut accept_proc = Command::new(hyp_rs_bin())
        .args([
            "pair",
            "accept",
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
    let team_inv = Command::new(hyp_rs_bin())
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

    let mut team_accept = Command::new(hyp_rs_bin())
        .args([
            "pair",
            "accept",
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
    let mut t1 = Command::new(hyp_rs_bin())
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
    let mut t2 = Command::new(hyp_rs_bin())
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
    let mut t3 = Command::new(hyp_rs_bin())
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
    let argv_tok = Command::new(hyp_rs_bin())
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
    let mut hub_child = Command::new(hyp_rs_bin())
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
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", hub_tmp.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live Rust router node");

    let mut hub_line = String::new();
    BufReader::new(hub_child.stdout.take().unwrap())
        .read_line(&mut hub_line)
        .unwrap();
    let hub_env: Value = serde_json::from_str(hub_line.trim()).expect("valid node start JSON");
    assert_eq!(hub_env["ok"], true);
    assert!(hub_env["data"]["socketPath"].is_null());
    let hub_endpoint = hub_env["data"]["endpoint"].as_str().unwrap().to_string();
    let hub_kid = hub_env["data"]["kid"].as_str().unwrap().to_string();

    // 2. Run `hyp pair join <hub_endpoint> --state-dir <client_tmp> --json`
    let join_out = Command::new(hyp_rs_bin())
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
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", client_tmp.path())
        .output()
        .unwrap();

    // Clean up live router subprocess immediately after join
    let _ = hub_child.kill();
    let _ = hub_child.wait();

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
    let bad_join = Command::new(hyp_rs_bin())
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
    let insecure_join = Command::new(hyp_rs_bin())
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
    let offline_join = Command::new(hyp_rs_bin())
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
}
