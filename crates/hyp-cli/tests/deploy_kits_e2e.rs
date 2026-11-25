//! End-to-end verification tests for all Hyphae v2 container & host deployment kits
//! (`docker`, `fly`, `vps`, `drop-relay`, `public-node`, `tailscale`, `cloudflare`),
//! checked-in `deploy/Dockerfile`, `.dockerignore`, `deploy/docker-compose.yml`,
//! `deploy/fly.toml.example`, release-matrix arm64/amd64 parity, and `D8` Team Hub
//! `hyphae-admin-pubkey` provisioning.
//!
//! Security & isolation invariants:
//! - Uses `tempfile::TempDir` everywhere with `HYPHAE_SECRET_BACKEND=file` (zero live config/Keychain mutations).
//! - Uses `127.0.0.1:0` ephemeral loopback binds for live compiled `hyp node start` boot checks.
//! - Zero external network calls.

mod common;

use common::{ManagedProcess, isolated_cmd, parse_json_stdout};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// Extracts `amd64)` and `arm64)` `HYP_TARGET="..."` triples from a generated `Dockerfile`.
fn extract_dockerfile_targets(dockerfile: &str) -> (String, String) {
    let mut amd64 = None;
    let mut arm64 = None;
    for line in dockerfile.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("amd64)") {
            if let Some(val) = extract_quoted_var(rest, "HYP_TARGET=") {
                amd64 = Some(val);
            }
        }
        if let Some(rest) = trimmed.strip_prefix("arm64)") {
            if let Some(val) = extract_quoted_var(rest, "HYP_TARGET=") {
                arm64 = Some(val);
            }
        }
    }
    (
        amd64.unwrap_or_else(|| panic!("missing amd64 HYP_TARGET in Dockerfile:\n{dockerfile}")),
        arm64.unwrap_or_else(|| panic!("missing arm64 HYP_TARGET in Dockerfile:\n{dockerfile}")),
    )
}

fn extract_quoted_var(s: &str, key: &str) -> Option<String> {
    let idx = s.find(key)?;
    let after = &s[idx + key.len()..];
    let after_open = after.strip_prefix('"')?;
    let end = after_open.find('"')?;
    Some(after_open[..end].to_string())
}

/// Parses `.github/workflows/release-rust.yml` for published `hyp-${TAG}-<triple>.tar.gz` triples.
fn published_linux_tar_targets_from_workflow(workflow_text: &str) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    for line in workflow_text.lines() {
        let trimmed = line.trim().trim_matches('"');
        if let Some(rest) = trimmed.strip_prefix("hyp-${TAG}-") {
            if let Some(triple) = rest.strip_suffix(".tar.gz") {
                if triple.contains("linux") {
                    targets.insert(triple.to_string());
                }
            }
        }
    }
    targets
}

#[test]
fn all_seven_providers_generate_valid_uid10001_readable_configs_and_boot_cleanly() {
    let cases: &[(&str, &str, &str, &str)] = &[
        ("docker", "acme-docker", "docker.acme.example", "0.0.0.0:8790"),
        ("fly", "acme-fly", "acme-fly.fly.dev", "0.0.0.0:8790"),
        ("vps", "acme-vps", "vps.acme.example", "127.0.0.1:8790"),
        ("drop-relay", "drop-relay", "drop.acme.example", "0.0.0.0:8790"),
        ("public-node", "public.hyphae.to", "public.hyphae.to", "127.0.0.1:8790"),
        ("tailscale", "alice-tailnet", "hyphae.example.ts.net", "127.0.0.1:8790"),
        ("cloudflare", "homelab-cf", "cf.acme.example", "127.0.0.1:8790"),
    ];

    for &(provider, node_id, domain, expected_bind) in cases {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let kit_dir = home.join(format!("kit-{provider}"));
        let state_dir = home.join(format!("state-{provider}"));

        let init_out = isolated_cmd(home)
            .args([
                "deploy",
                "init",
                provider,
                "--node-id",
                node_id,
                "--domain",
                domain,
                "--out",
                kit_dir.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run hyp deploy init");
        assert_eq!(
            init_out.status.code(),
            Some(0),
            "deploy init failed for {provider}: stdout={} stderr={}",
            String::from_utf8_lossy(&init_out.stdout),
            String::from_utf8_lossy(&init_out.stderr)
        );
        let init_env = parse_json_stdout(&init_out);
        assert_eq!(init_env["ok"], true);
        assert_eq!(init_env["data"]["bind"], expected_bind);

        let node_json_path = kit_dir.join("node.json");
        assert!(node_json_path.exists(), "missing node.json for {provider}");

        // 1. Verify Unix permissions allow non-root container UID 10001 to read bind-mounted :ro
        //    node.json while remaining non-world-writable (0644).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&node_json_path).unwrap().permissions().mode() & 0o777;
            assert_ne!(
                mode & 0o004,
                0,
                "{provider}: node.json must have world-read bit for UID 10001 bind mounts (got {:04o})",
                mode
            );
            assert_eq!(
                mode & 0o002,
                0,
                "{provider}: node.json must NOT be world-writable (got {:04o})",
                mode
            );
        }

        // 2. Verify JSON structure & listen.bind parses as a valid SocketAddr.
        let cfg_val: Value =
            serde_json::from_str(&read_text(&node_json_path)).expect("valid JSON node.json");
        assert_eq!(cfg_val["v"], 2);
        assert_eq!(cfg_val["nodeId"], node_id);
        assert_eq!(cfg_val["listen"]["bind"], expected_bind);
        assert!(
            expected_bind.parse::<SocketAddr>().is_ok(),
            "{provider}: invalid SocketAddr '{expected_bind}'"
        );
        assert_eq!(cfg_val["listen"]["behindReverseProxy"], true);
        assert_eq!(
            cfg_val["listen"]["trustedProxies"],
            serde_json::json!(["127.0.0.1/32", "::1/128"]),
            "{provider}: proxied node.json must declare loopback trustedProxies"
        );
        assert_eq!(cfg_val["listen"]["publicUrl"], format!("https://{domain}"));
        assert_eq!(cfg_val["stateDir"], "/var/lib/hyphae");
        if matches!(provider, "docker" | "fly" | "vps" | "tailscale" | "cloudflare") {
            assert_eq!(
                cfg_val["sources"][0]["topic"], "github-webhooks",
                "{provider}: Team Hub webhook source must use isolated topic 'github-webhooks'"
            );
        } else if provider == "public-node" {
            assert_eq!(cfg_val["sources"][0]["topic"], "github");
        }

        // 3. Verify `hyp deploy check --config` exits 0 with zero FAIL checks.
        let check_out = isolated_cmd(home)
            .args([
                "deploy",
                "check",
                "--config",
                node_json_path.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run hyp deploy check --config");
        assert_eq!(
            check_out.status.code(),
            Some(0),
            "deploy check --config failed for {provider}: {}",
            String::from_utf8_lossy(&check_out.stdout)
        );

        // 4. Boot the real compiled `hyp node start` with the generated node.json (exercises
        //    `load_node_or_legacy_config` + full `node_cmd` startup + live `/v1/manifest` check!).
        let mut node_cmd = isolated_cmd(home);
        node_cmd.args([
            "node",
            "start",
            "--config",
            node_json_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "--no-local-socket",
            "--json",
        ]);
        let mut proc = ManagedProcess::spawn(format!("boot-{provider}"), &mut node_cmd);
        let startup = proc.read_json_line(Duration::from_secs(10));
        assert_eq!(
            startup["ok"], true,
            "node start failed for {provider}: {startup}"
        );
        assert_eq!(startup["data"]["nodeId"], node_id);
        let endpoint = startup["data"]["endpoint"]
            .as_str()
            .expect("node start endpoint")
            .to_string();

        let live_check = isolated_cmd(home)
            .args(["deploy", "check", "--url", &endpoint, "--json"])
            .output()
            .expect("run live deploy check --url");
        assert_eq!(
            live_check.status.code(),
            Some(0),
            "live deploy check failed for {provider}: stdout={} stderr={}",
            String::from_utf8_lossy(&live_check.stdout),
            String::from_utf8_lossy(&live_check.stderr)
        );
        let live_env = parse_json_stdout(&live_check);
        assert_eq!(live_env["ok"], true);
        assert_eq!(live_env["data"]["manifest"]["nodeId"], node_id);
        assert_eq!(live_env["data"]["manifest"]["signatureVerified"], true);
        assert_eq!(live_env["data"]["manifest"]["advertisedEmpty"], true);

        let _ = proc.shutdown_gracefully();
    }
}

#[test]
fn fly_and_drop_relay_kits_bind_0000_copy_node_json_and_honor_custom_ports() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();

    // 1. Standard Fly kit
    let fly_dir = home.join("fly-kit");
    let out = isolated_cmd(home)
        .args([
            "deploy",
            "init",
            "fly",
            "--node-id",
            "acme-fly",
            "--domain",
            "acme-fly.fly.dev",
            "--out",
            fly_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));

    let fly_cfg: Value = serde_json::from_str(&read_text(&fly_dir.join("node.json"))).unwrap();
    assert_eq!(fly_cfg["listen"]["bind"], "0.0.0.0:8790");
    assert_eq!(fly_cfg["listen"]["behindReverseProxy"], true);

    let fly_df = read_text(&fly_dir.join("Dockerfile"));
    assert!(
        fly_df.contains("COPY --chown=10001:10001 node.json /etc/hyphae/node.json"),
        "Fly Dockerfile must bake node.json owned by 10001:10001:\n{fly_df}"
    );
    assert!(fly_df.contains("chown 10001:10001 /var/lib/hyphae /etc/hyphae"));
    assert!(fly_df.contains("chmod 0700 /var/lib/hyphae"));
    assert!(
        fly_df.contains("/usr/local/bin/hyphae-entrypoint.sh")
            && fly_df.contains("chown -R 10001:10001")
            && fly_df.contains("chmod 0700")
            && fly_df.contains("exec setpriv --reuid=10001 --regid=10001 --init-groups /usr/local/bin/hyp"),
        "OR2: Fly Dockerfile must fix root-owned [[mounts]] volume and drop to UID 10001:10001 via setpriv:\n{fly_df}"
    );
    assert!(
        fly_df.contains("ENTRYPOINT [\"/usr/local/bin/hyphae-entrypoint.sh\"]"),
        "OR2: Fly Dockerfile must invoke hyphae-entrypoint.sh:\n{fly_df}"
    );
    assert!(
        !fly_df.contains("USER 10001:10001"),
        "OR2: Fly Dockerfile must start as root briefly to chown mounted volume before dropping via setpriv:\n{fly_df}"
    );
    assert!(fly_df.contains("CMD [\"node\", \"start\", \"--config\", \"/etc/hyphae/node.json\", \"--no-local-socket\"]"));

    // 2. Fly kit with `--enable-drop-relay`
    let fly_relay_dir = home.join("fly-relay-kit");
    let out2 = isolated_cmd(home)
        .args([
            "deploy",
            "init",
            "fly",
            "--node-id",
            "fly-drop",
            "--domain",
            "fly-drop.fly.dev",
            "--enable-drop-relay",
            "--drop-max-memory-mb",
            "192",
            "--out",
            fly_relay_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(0));
    let fly_relay_cfg: Value =
        serde_json::from_str(&read_text(&fly_relay_dir.join("node.json"))).unwrap();
    assert_eq!(fly_relay_cfg["listen"]["bind"], "0.0.0.0:8790");
    assert_eq!(fly_relay_cfg["dropRelay"]["enabled"], true);
    assert_eq!(fly_relay_cfg["dropRelay"]["maxMemoryMb"], 192);
    assert!(
        read_text(&fly_relay_dir.join("Dockerfile"))
            .contains("COPY --chown=10001:10001 node.json /etc/hyphae/node.json")
    );

    // 3. Dedicated `drop-relay` kit (Fly.io + Docker Compose + systemd)
    let dr_dir = home.join("drop-relay-kit");
    let out3 = isolated_cmd(home)
        .args([
            "deploy",
            "init",
            "drop-relay",
            "--domain",
            "drop.acme.example",
            "--out",
            dr_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out3.status.code(), Some(0));
    let dr_cfg: Value = serde_json::from_str(&read_text(&dr_dir.join("node.json"))).unwrap();
    assert_eq!(
        dr_cfg["listen"]["bind"], "0.0.0.0:8790",
        "drop-relay node.json must bind 0.0.0.0:8790 so Fly Proxy can reach it"
    );
    assert_eq!(dr_cfg["dropRelay"]["enabled"], true);

    let dr_df = read_text(&dr_dir.join("Dockerfile"));
    assert!(dr_df.contains("COPY --chown=10001:10001 node.json /etc/hyphae/node.json"));

    let dr_fly = read_text(&dr_dir.join("fly.toml"));
    assert!(dr_fly.contains("internal_port = 8790"));
    assert!(dr_fly.contains("path = \"/v1/health\""));

    // Bare-metal systemd unit for drop-relay must stay safely loopback-bound even though node.json binds 0.0.0.0!
    let dr_unit = read_text(&dr_dir.join("hyphae-drop-relay.service"));
    assert!(
        dr_unit.contains("--bind 127.0.0.1:8790"),
        "drop-relay systemd unit must override bind to loopback 127.0.0.1:8790:\n{dr_unit}"
    );

    // 4. Custom port propagation (--bind 0.0.0.0:9090)
    let custom_dir = home.join("fly-custom-port");
    let out4 = isolated_cmd(home)
        .args([
            "deploy",
            "init",
            "fly",
            "--node-id",
            "custom-fly",
            "--domain",
            "custom-fly.fly.dev",
            "--bind",
            "0.0.0.0:9090",
            "--out",
            custom_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out4.status.code(), Some(0));
    let custom_df = read_text(&custom_dir.join("Dockerfile"));
    assert!(custom_df.contains("EXPOSE 9090"));
    assert!(custom_df.contains("http://127.0.0.1:9090"));
    assert!(read_text(&custom_dir.join("fly.toml")).contains("internal_port = 9090"));
}

#[test]
fn generated_dockerfiles_match_exact_release_rust_workflow_targets() {
    let workflow_path = workspace_root()
        .join(".github")
        .join("workflows")
        .join("release-rust.yml");
    let workflow_text = read_text(&workflow_path);
    let published_targets = published_linux_tar_targets_from_workflow(&workflow_text);

    assert!(
        published_targets.contains("x86_64-unknown-linux-musl"),
        "release-rust.yml expected to publish x86_64-unknown-linux-musl, found {published_targets:?}"
    );
    assert!(
        published_targets.contains("aarch64-unknown-linux-gnu"),
        "release-rust.yml expected to publish aarch64-unknown-linux-gnu, found {published_targets:?}"
    );
    assert!(
        !published_targets.contains("aarch64-unknown-linux-musl"),
        "release-rust.yml does not build aarch64-unknown-linux-musl"
    );

    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    for provider in ["docker", "fly", "public-node", "drop-relay"] {
        let dir = home.join(provider);
        let out = isolated_cmd(home)
            .args([
                "deploy",
                "init",
                provider,
                "--out",
                dir.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));

        let df = read_text(&dir.join("Dockerfile"));
        let (amd64, arm64) = extract_dockerfile_targets(&df);
        assert!(
            published_targets.contains(&amd64),
            "{provider} Dockerfile amd64 target '{amd64}' not published in release-rust.yml ({published_targets:?})"
        );
        assert!(
            published_targets.contains(&arm64),
            "{provider} Dockerfile arm64 target '{arm64}' not published in release-rust.yml ({published_targets:?})"
        );
        assert_eq!(arm64, "aarch64-unknown-linux-gnu");
        assert!(
            !df.contains("aarch64-unknown-linux-musl"),
            "{provider} Dockerfile must not reference non-existent aarch64-unknown-linux-musl"
        );
        assert!(
            df.contains("FROM debian:bookworm-slim AS runtime"),
            "{provider} Dockerfile runtime base must include glibc (debian:bookworm-slim) for aarch64-unknown-linux-gnu"
        );
    }
}

#[test]
fn drop_relay_and_docker_compose_kits_use_service_names_and_uid10001_tmpfs() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();

    // 1. Drop-relay Docker Compose kit
    let dr_dir = home.join("drop-relay");
    let dr_out = isolated_cmd(home)
        .args([
            "deploy",
            "init",
            "drop-relay",
            "--domain",
            "drop.acme.example",
            "--out",
            dr_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(dr_out.status.code(), Some(0));

    let dr_caddy = read_text(&dr_dir.join("Caddyfile"));
    assert!(
        dr_caddy.contains("reverse_proxy hyphae-drop-relay:8790"),
        "drop-relay Caddyfile must target Compose service hyphae-drop-relay:8790:\n{dr_caddy}"
    );
    assert!(
        !dr_caddy.contains("127.0.0.1"),
        "drop-relay Caddyfile must NEVER point to 127.0.0.1 (which is inside the Caddy container):\n{dr_caddy}"
    );

    let dr_compose = read_text(&dr_dir.join("docker-compose.yml"));
    assert!(
        dr_compose.contains("/var/lib/hyphae:size=64M,uid=10001,gid=10001,mode=0700"),
        "drop-relay docker-compose.yml tmpfs must be owned by uid=10001,gid=10001:\n{dr_compose}"
    );
    assert!(
        dr_compose.contains("/tmp:size=32M,noexec,nosuid,uid=10001,gid=10001"),
        "drop-relay docker-compose.yml /tmp tmpfs must specify uid=10001,gid=10001:\n{dr_compose}"
    );
    assert!(dr_compose.contains("hyphae-drop-relay:"));

    // 2. Docker Compose kit
    let docker_dir = home.join("docker");
    let docker_out = isolated_cmd(home)
        .args([
            "deploy",
            "init",
            "docker",
            "--domain",
            "mesh.acme.example",
            "--out",
            docker_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(docker_out.status.code(), Some(0));

    let docker_caddy = read_text(&docker_dir.join("Caddyfile"));
    assert!(docker_caddy.contains("reverse_proxy hyphae-node:8790"));
    assert!(!docker_caddy.contains("127.0.0.1"));
    let docker_compose = read_text(&docker_dir.join("docker-compose.yml"));
    assert!(docker_compose.contains("/tmp:size=32M,noexec,nosuid,uid=10001,gid=10001"));
    assert!(docker_compose.contains("hyphae_state:/var/lib/hyphae"));

    // 3. Public-node Docker Compose kit uses dedicated Caddyfile.docker with hyphae-node upstream
    let pub_dir = home.join("public-node");
    let pub_out = isolated_cmd(home)
        .args([
            "deploy",
            "init",
            "public-node",
            "--domain",
            "public.acme.example",
            "--out",
            pub_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(pub_out.status.code(), Some(0));

    let pub_caddy_docker = read_text(&pub_dir.join("Caddyfile.docker"));
    assert!(pub_caddy_docker.contains("reverse_proxy hyphae-node:8790"));
    assert!(!pub_caddy_docker.contains("127.0.0.1"));
    let pub_compose = read_text(&pub_dir.join("docker-compose.yml"));
    assert!(pub_compose.contains("./Caddyfile.docker:/etc/caddy/Caddyfile:ro"));
    assert!(pub_compose.contains("0.0.0.0:8790"));
}

#[test]
fn checked_in_deploy_dockerfile_and_dockerignore_cover_all_build_rs_and_include_str_paths() {
    let root = workspace_root();
    let dockerfile = read_text(&root.join("deploy/Dockerfile"));
    let dockerignore = read_text(&root.join(".dockerignore"));
    let compose = read_text(&root.join("deploy/docker-compose.yml"));
    let fly_example = read_text(&root.join("deploy/fly.toml.example"));

    // 1. Collect every top-level repo directory referenced outside `crates/` by:
    //    - `crates/hyp-cli/build.rs`
    //    - `include_str!` / `include_bytes!` in `crates/hyp-cli/src/*.rs`
    let mut external_dirs: BTreeSet<String> = BTreeSet::new();

    let build_rs = read_text(&root.join("crates/hyp-cli/build.rs"));
    for line in build_rs.lines() {
        if let Some(pos) = line.find("../../") {
            let rest = &line[pos + 6..];
            if let Some(dir) = rest.split('/').next() {
                if !dir.is_empty() && dir.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    external_dirs.insert(dir.to_string());
                }
            }
        }
    }

    let src_dir = root.join("crates/hyp-cli/src");
    for entry in fs::read_dir(&src_dir).expect("read crates/hyp-cli/src") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let text = read_text(&path);
        for macro_name in ["include_str!(", "include_bytes!("] {
            let mut cursor = text.as_str();
            while let Some(idx) = cursor.find(macro_name) {
                cursor = &cursor[idx + macro_name.len()..];
                if let Some(q_start) = cursor.find('"') {
                    let after_q = &cursor[q_start + 1..];
                    if let Some(q_end) = after_q.find('"') {
                        let rel = &after_q[..q_end];
                        // Paths from `crates/hyp-cli/src/*.rs` to workspace root begin with `../../../`
                        if let Some(rest) = rel.strip_prefix("../../../") {
                            if let Some(top) = rest.split('/').next() {
                                external_dirs.insert(top.to_string());
                            }
                        }
                        cursor = &after_q[q_end + 1..];
                    }
                }
            }
        }
    }

    // Sanity check: we expect at least plugins, skills, scripts from current sources.
    assert!(external_dirs.contains("plugins"), "expected plugins in {external_dirs:?}");
    assert!(external_dirs.contains("skills"), "expected skills in {external_dirs:?}");
    assert!(external_dirs.contains("scripts"), "expected scripts in {external_dirs:?}");

    // Every required workspace manifest + crate + external compile-time directory MUST be copied
    // in `deploy/Dockerfile` and MUST NOT be excluded by `.dockerignore`.
    assert!(dockerfile.contains("COPY Cargo.toml Cargo.lock ./"));
    assert!(dockerfile.contains("COPY crates ./crates"));
    for dir in &external_dirs {
        let expected_copy = format!("COPY {dir} ./{dir}");
        assert!(
            dockerfile.contains(&expected_copy),
            "deploy/Dockerfile is missing `{expected_copy}` required by build.rs / include_str!:\n{dockerfile}"
        );
        let ignored = dockerignore
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .any(|pattern| pattern == dir || pattern == format!("{dir}/"));
        assert!(
            !ignored,
            ".dockerignore must NOT exclude required compile-time directory '{dir}':\n{dockerignore}"
        );
    }

    // Check `.dockerignore` excludes heavy/non-build directories.
    for excluded in ["target/", ".git/", "site/", "workers/", "node_modules/"] {
        assert!(
            dockerignore.lines().any(|l| l.trim() == excluded),
            ".dockerignore missing required exclusion '{excluded}'"
        );
    }

    // Check `deploy/Dockerfile` runtime hardening & default CMD.
    assert!(dockerfile.contains("cargo build --release --locked -p hyp-cli"));
    assert!(dockerfile.contains("USER 10001:10001"));
    assert!(dockerfile.contains("chown 10001:10001 /var/lib/hyphae /etc/hyphae"));
    assert!(dockerfile.contains("chmod 0700 /var/lib/hyphae"));
    assert!(dockerfile.contains("HYPHAE_CONFIG=/etc/hyphae/node.json"));
    assert!(dockerfile.contains("\"--bind\", \"0.0.0.0:8790\""));

    // Check `deploy/docker-compose.yml` and `deploy/fly.toml.example` alignment.
    assert!(compose.contains("dockerfile: deploy/Dockerfile"));
    assert!(compose.contains("/etc/hyphae/node.json"));
    assert!(compose.contains("0.0.0.0:8790"));
    assert!(compose.contains("uid=10001,gid=10001"));

    assert!(fly_example.contains("dockerfile = \"deploy/Dockerfile\""));
    assert!(fly_example.contains("HYPHAE_CONFIG = \"/etc/hyphae/node.json\""));
    assert!(fly_example.contains("guest_path = \"/etc/hyphae/node.json\""));
    assert!(fly_example.contains("internal_port = 8790"));
    assert!(fly_example.contains("0.0.0.0:8790"));
}

#[test]
fn d8_team_hub_kits_document_admin_pubkey_and_live_hub_loads_it_on_first_boot() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();

    // 1. Every Team Hub (`router` profile) provider must document `hyphae-admin-pubkey` in both
    //    `next` steps and `README.md`, keeping the private Admin-CA key strictly on the admin laptop.
    for provider in ["docker", "fly", "vps", "tailscale", "cloudflare"] {
        let kit_dir = home.join(format!("team-{provider}"));
        let out = isolated_cmd(home)
            .args([
                "deploy",
                "init",
                provider,
                "--node-id",
                "acme-team",
                "--domain",
                "mesh.acme.example",
                "--out",
                kit_dir.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        let env = parse_json_stdout(&out);
        let next_steps: Vec<&str> = env["next"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            next_steps
                .iter()
                .any(|s| s.contains("hyp secret set hyphae-admin-pubkey")),
            "{provider} next steps missing `hyp secret set hyphae-admin-pubkey`: {next_steps:?}"
        );
        let readme = read_text(&kit_dir.join("README.md"));
        assert!(
            readme.contains("hyphae-admin-pubkey")
                && readme.contains("hyp secret set hyphae-admin-pubkey")
                && readme.contains(".data.adminJwk"),
            "{provider} README missing Admin-CA public key provisioning guide:\n{readme}"
        );
        // OR3: verify correct non-root target user for admin-pubkey provisioning on Fly & systemd kits!
        if provider == "fly" {
            assert!(
                readme.contains("setpriv --reuid=10001 --regid=10001"),
                "OR3: Fly README must drop to UID 10001 via setpriv for hyp secret set:\n{readme}"
            );
            assert!(
                next_steps
                    .iter()
                    .any(|s| s.contains("setpriv --reuid=10001 --regid=10001")
                        && s.contains("hyp secret set hyphae-admin-pubkey")),
                "OR3: Fly next steps must drop to UID 10001 via setpriv: {next_steps:?}"
            );
        } else if matches!(provider, "vps" | "tailscale" | "cloudflare") {
            assert!(
                readme.contains("sudo -u hyphae")
                    && readme.contains("HYPHAE_SECRET_BACKEND=file")
                    && readme.contains("hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae"),
                "OR3: {provider} README must run secret set as hyphae user:\n{readme}"
            );
            assert!(
                next_steps.iter().any(|s| s.contains("sudo -u hyphae")
                    && s.contains("HYPHAE_SECRET_BACKEND=file")
                    && s.contains("hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae")),
                "OR3: {provider} next steps must run secret set as hyphae user: {next_steps:?}"
            );
        }
    }

    // 2. Non-Team-Hub kits (`public-node`, `drop-relay`, and `--profile p2p`) must NOT emit
    //    `hyphae-admin-pubkey` provisioning steps.
    for (label, extra_args) in [
        ("public-node", vec!["deploy", "init", "public-node"]),
        ("drop-relay", vec!["deploy", "init", "drop-relay"]),
        ("docker-p2p", vec!["deploy", "init", "docker", "--profile", "p2p"]),
    ] {
        let kit_dir = home.join(format!("non-team-{label}"));
        let mut args: Vec<&str> = extra_args;
        args.extend(["--out", kit_dir.to_str().unwrap(), "--json"]);
        let out = isolated_cmd(home).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        let readme = read_text(&kit_dir.join("README.md"));
        assert!(
            !readme.contains("hyphae-admin-pubkey"),
            "{label} should not include Team Hub hyphae-admin-pubkey section:\n{readme}"
        );
    }

    // 3. Live E2E proof of the D8 workflow:
    //    - Admin laptop mints a team invite (`hyp pair invite --mode team --json`) and exports `.data.adminJwk`.
    //    - Team Hub loads ONLY that public JWK via `hyp secret set hyphae-admin-pubkey` (stdin).
    //    - Team Hub starts using the generated `docker` kit `node.json` with ZERO missing-adminKey warning!
    let admin_state = home.join("admin-laptop-state");
    let hub_state = home.join("hub-state");
    let hub_kit = home.join("team-docker");

    let invite_out = isolated_cmd(home)
        .args([
            "pair",
            "invite",
            "--mode",
            "team",
            "--node-id",
            "acme-team",
            "--endpoint",
            "https://mesh.acme.example",
            "--peer",
            "alice@laptop",
            "--preset",
            "member",
            "--state-dir",
            admin_state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("mint team invite on admin laptop");
    assert_eq!(invite_out.status.code(), Some(0));
    let invite_env = parse_json_stdout(&invite_out);
    let admin_jwk = &invite_env["data"]["adminJwk"];
    assert_eq!(admin_jwk["kty"], "OKP");
    assert_eq!(admin_jwk["crv"], "Ed25519");
    assert!(admin_jwk.get("d").is_none(), "adminJwk must be strictly public");
    let admin_jwk_json = serde_json::to_string(admin_jwk).unwrap();

    let mut set_proc = isolated_cmd(home)
        .args([
            "secret",
            "set",
            "hyphae-admin-pubkey",
            "--state-dir",
            hub_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hyp secret set hyphae-admin-pubkey");
    set_proc
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{admin_jwk_json}\n").as_bytes())
        .unwrap();
    let set_out = set_proc.wait_with_output().unwrap();
    assert_eq!(
        set_out.status.code(),
        Some(0),
        "secret set hyphae-admin-pubkey failed: stdout={} stderr={}",
        String::from_utf8_lossy(&set_out.stdout),
        String::from_utf8_lossy(&set_out.stderr)
    );

    let mut hub_cmd = isolated_cmd(home);
    hub_cmd.args([
        "node",
        "start",
        "--config",
        hub_kit.join("node.json").to_str().unwrap(),
        "--state-dir",
        hub_state.to_str().unwrap(),
        "--bind",
        "127.0.0.1:0",
        "--no-local-socket",
        "--json",
    ]);
    let mut hub_proc = ManagedProcess::spawn("team-hub-with-admin-pubkey", &mut hub_cmd);
    let startup = hub_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(startup["ok"], true, "hub startup failed: {startup}");
    let warnings = startup["warnings"].as_array().cloned().unwrap_or_default();
    assert!(
        !warnings
            .iter()
            .filter_map(Value::as_str)
            .any(|w| w.contains("hyphae-admin-pubkey")),
        "expected ZERO hyphae-admin-pubkey missing warning after provisioning, got: {warnings:?}"
    );
    let _ = hub_proc.shutdown_gracefully();
}
