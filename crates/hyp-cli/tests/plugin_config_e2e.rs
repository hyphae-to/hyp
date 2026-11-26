//! End-to-End Tests for `plugins[]` Configuration (`"command"` alias, error isolation,
//! plaintext secret warnings, doc snippet parity, CrashLoopBackOff `node.status.json`
//! observability, and local-only bridge topics).
//!
//! Spawns the real compiled `hyp` binary in isolated temp dirs with `HYPHAE_SECRET_BACKEND=file`
//! on BOTH Unix (fd-3) and Windows (authenticated loopback-TCP).

#[path = "../../test-support/node_runtime.rs"]
mod node_runtime;

mod plugin_config_e2e {
    use http::{Method, Request, StatusCode, header};
    use http_body_util::{BodyExt, Full};
    use hyp_crypto::keystore::{SecretBackend, SecretStore};
    use hyp_node::engine::UnifiedNode;
    use hyper::body::Bytes;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use serde_json::{Value, json};
    use std::fs;
    use std::io::{BufRead, BufReader};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn hyp_bin() -> &'static str {
        env!("CARGO_BIN_EXE_hyp")
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("resolve repo root")
            .to_path_buf()
    }

    fn find_binary(name: &str) -> Option<String> {
        if name == "node" {
            return crate::node_runtime::node_available().then(|| name.to_string());
        }
        let out = Command::new(name).arg("--version").output().ok()?;
        if out.status.success() {
            Some(name.to_string())
        } else {
            None
        }
    }

    fn find_python3_binary() -> Option<String> {
        for candidate in ["python3", "python"] {
            let Ok(out) = Command::new(candidate)
                .args(["-c", "import sys; print(sys.version_info[0])"])
                .output()
            else {
                continue;
            };
            if out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "3" {
                return Some(candidate.to_string());
            }
        }
        None
    }

    /// Minimal cross-platform Python noop plugin supporting both Unix fd-3 and Windows loopback-TCP.
    const CROSS_PLATFORM_NOOP_PLUGIN_PY: &str = r#"import json, os, socket, sys
addr = (os.environ.get("HYPHAE_PLUGIN_ADDR") or "").strip()
if addr:
    host, port_s = addr.rsplit(":", 1)
    token = os.environ.pop("HYPHAE_PLUGIN_TOKEN", "")
    s = socket.create_connection((host.strip("[]"), int(port_s)), timeout=10.0)
    s.settimeout(None)
    s.sendall((json.dumps({"type": "auth", "token": token}) + "\n").encode("utf-8"))
else:
    s = socket.socket(fileno=3)
while True:
    data = s.recv(1024)
    if not data:
        sys.exit(0)
"#;

    fn isolated_cmd(home: &Path) -> Command {
        let mut cmd = Command::new(hyp_bin());
        for (key, _) in std::env::vars_os() {
            if let Some(s) = key.to_str() {
                if [
                    "HYPHAE_",
                    "AGENTS_MESH_",
                    "T3_MESH_",
                    "HC_",
                    "CLAUDE",
                    "CODEX_",
                    "OPENCLAW_",
                    "OPENCODE_",
                    "T3CODE_",
                    "T3_",
                    "GEMINI_",
                    "ANTIGRAVITY_",
                ]
                .iter()
                .any(|p| s.starts_with(p))
                {
                    cmd.env_remove(&key);
                }
            }
        }
        cmd.env("HOME", home)
            .env("USERPROFILE", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("HYPHAE_SECRET_BACKEND", "file")
            .env("HYPHAE_NO_OPEN", "1")
            .env("HYPHAE_NO_SERVICE", "1")
            .env("HYPHAE_NO_SERVICE_RESTART", "1");
        cmd
    }

    struct ManagedDaemon {
        child: Child,
        stdout_rx: mpsc::Receiver<String>,
    }

    impl ManagedDaemon {
        fn spawn(cmd: &mut Command) -> Self {
            cmd.stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::null());
            let mut child = cmd.spawn().expect("spawn hyp daemon");
            let stdout = child.stdout.take().expect("daemon stdout");
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines().map_while(Result::ok) {
                    let _ = tx.send(line);
                }
            });
            Self {
                child,
                stdout_rx: rx,
            }
        }

        fn read_json_line(&self, timeout: Duration) -> Value {
            let deadline = Instant::now() + timeout;
            loop {
                let rem = deadline.saturating_duration_since(Instant::now());
                assert!(!rem.is_zero(), "timed out waiting for hyp daemon JSON line");
                let line = self
                    .stdout_rx
                    .recv_timeout(rem)
                    .expect("daemon exited before emitting JSON line");
                let trimmed = line.trim();
                if trimmed.starts_with('{') {
                    return serde_json::from_str(trimmed)
                        .unwrap_or_else(|e| panic!("invalid JSON line {trimmed:?}: {e}"));
                }
            }
        }

        fn shutdown(&mut self) {
            #[cfg(unix)]
            {
                let pid = self.child.id() as i32;
                unsafe {
                    unsafe extern "C" {
                        fn kill(pid: i32, sig: i32) -> i32;
                    }
                    let _ = kill(pid, 15);
                }
                let deadline = Instant::now() + Duration::from_secs(5);
                while Instant::now() < deadline {
                    if let Ok(Some(_)) = self.child.try_wait() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(25));
                }
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for ManagedDaemon {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    fn extract_plugins_json_blocks(markdown: &str) -> Vec<Value> {
        let mut out = Vec::new();
        let mut in_json = false;
        let mut buf = String::new();
        for line in markdown.lines() {
            let trimmed = line.trim();
            if !in_json {
                if trimmed == "```json" {
                    in_json = true;
                    buf.clear();
                }
            } else if trimmed == "```" {
                in_json = false;
                if let Ok(val) = serde_json::from_str::<Value>(&buf) {
                    if val.get("plugins").is_some() {
                        out.push(val);
                    }
                }
            } else {
                buf.push_str(line);
                buf.push('\n');
            }
        }
        out
    }

    #[test]
    fn documented_plugins_json_snippets_boot_real_hyp_daemon() {
        let Some(python_bin) = find_python3_binary() else {
            eprintln!(
                "SKIP documented_plugins_json_snippets_boot_real_hyp_daemon: python3 missing"
            );
            return;
        };

        let root = repo_root();
        let tmp = TempDir::new().unwrap();
        let noop_plugin = tmp.path().join("noop_plugin.py");
        fs::write(&noop_plugin, CROSS_PLATFORM_NOOP_PLUGIN_PY).unwrap();

        // Extract the REAL documented JSON snippets from BOTH docs/plugins.md and
        // skills/hyphae-setup/SKILL.md and boot `hyp daemon` using their exact schema (including `"command"`)!
        for (doc_idx, rel) in ["docs/plugins.md", "skills/hyphae-setup/SKILL.md"]
            .iter()
            .enumerate()
        {
            let content = fs::read_to_string(root.join(rel))
                .unwrap_or_else(|e| panic!("failed reading {rel}: {e}"));
            let blocks = extract_plugins_json_blocks(&content);
            assert!(
                !blocks.is_empty(),
                "{rel} must contain at least one documented plugins[] JSON snippet"
            );

            for (snip_idx, mut snippet) in blocks.into_iter().enumerate() {
                let run_dir = tmp.path().join(format!("doc-{doc_idx}-{snip_idx}"));
                let home = run_dir.join("home");
                let state_dir = run_dir.join("state");
                fs::create_dir_all(&home).unwrap();
                fs::create_dir_all(&state_dir).unwrap();

                let secrets = SecretStore::new(&state_dir, SecretBackend::File);
                for secret_name in [
                    "ci-webhook-secret",
                    "prometheus-bearer-token",
                    "telegram-bot-token",
                    "slack-app-token",
                    "slack-bot-token",
                    "sentry-auth-token",
                    "google-client-secret",
                    "google-refresh-token",
                ] {
                    secrets
                        .set(secret_name, &format!("doc-test-secret-{secret_name}"))
                        .unwrap();
                }

                // Rewrite ONLY the binary/script placeholder paths (leaving `"command"`, `"id"`,
                // `"targets"`, `"env"`, and `{ "secret": ... }` structure 100% verbatim from the doc!).
                let arr = snippet["plugins"]
                    .as_array_mut()
                    .expect("documented plugins must be array");
                let expected_count = arr.len();
                for entry in arr.iter_mut() {
                    let obj = entry.as_object_mut().expect("plugin entry object");
                    assert!(
                        obj.contains_key("command"),
                        "documented snippet in {rel} should use \"command\" key"
                    );
                    obj.insert("command".to_string(), json!(python_bin));
                    obj.insert(
                        "args".to_string(),
                        json!(["-u", noop_plugin.to_str().unwrap()]),
                    );
                }

                let cfg_obj = snippet.as_object_mut().unwrap();
                cfg_obj.insert("v".to_string(), json!(2));
                cfg_obj.insert(
                    "nodeId".to_string(),
                    json!(format!("doc{doc_idx}-{snip_idx}@box")),
                );
                cfg_obj.insert("profile".to_string(), json!("local"));
                cfg_obj.insert("stateDir".to_string(), json!(state_dir.to_str().unwrap()));

                let cfg_path = run_dir.join("node.json");
                fs::write(&cfg_path, serde_json::to_string_pretty(&snippet).unwrap()).unwrap();

                let mut cmd = isolated_cmd(&home);
                cmd.args(["daemon", "--config", cfg_path.to_str().unwrap(), "--json"]);
                let mut daemon = ManagedDaemon::spawn(&mut cmd);
                let startup = daemon.read_json_line(Duration::from_secs(15));
                assert_eq!(
                    startup["ok"], true,
                    "hyp daemon MUST boot documented snippet from {rel}: {startup}"
                );
                let plugins = startup["data"]["plugins"]
                    .as_array()
                    .expect("plugins array in startup data");
                assert_eq!(
                    plugins.len(),
                    expected_count,
                    "all documented plugins from {rel} must be running: {plugins:?}"
                );
                for p in plugins {
                    assert_eq!(
                        p["status"], "running",
                        "plugin from {rel} should be running: {p}"
                    );
                }
                daemon.shutdown();
            }
        }
    }

    #[test]
    fn command_and_exec_isolation_plaintext_warning_and_crash_loop_status_e2e() {
        let Some(python_bin) = find_python3_binary() else {
            eprintln!(
                "SKIP command_and_exec_isolation_plaintext_warning_and_crash_loop_status_e2e: python3 missing"
            );
            return;
        };

        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&state_dir).unwrap();

        let good_plugin = tmp.path().join("good_plugin.py");
        fs::write(&good_plugin, CROSS_PLATFORM_NOOP_PLUGIN_PY).unwrap();

        let crash_plugin = tmp.path().join("crash_plugin.py");
        fs::write(
            &crash_plugin,
            "import os, sys\nsecret = os.environ.get('CRASH_API_SECRET', '')\nsys.stderr.write(f'boot error with key={secret}\\n')\nsys.stderr.flush()\nsys.exit(1)\n",
        )
        .unwrap();

        let plaintext_secret = "tok_plaintext_NEVER_LEAK_887766";
        let stored_crash_secret = "sec_stored_NEVER_LEAK_554433";
        let secrets = SecretStore::new(&state_dir, SecretBackend::File);
        secrets.set("crash-secret", stored_crash_secret).unwrap();

        let cfg_path = state_dir.join("node.json");
        fs::write(
            &cfg_path,
            serde_json::to_string_pretty(&json!({
                "v": 2,
                "nodeId": "iso@box",
                "profile": "local",
                "stateDir": state_dir.to_str().unwrap(),
                "plugins": [
                    // Valid plugin using `"command"` + plaintext secret-like env var (triggers B15 warning)
                    {
                        "id": "cmd-ok",
                        "command": python_bin,
                        "args": ["-u", good_plugin.to_str().unwrap()],
                        "targets": ["personal"],
                        "env": {
                            "TELEGRAM_BOT_TOKEN": plaintext_secret
                        }
                    },
                    // Valid webhook with omitted kind + WEBHOOK_POST_URL -> Bridge (B10)
                    {
                        "id": "webhook",
                        "exec": python_bin,
                        "args": ["-u", good_plugin.to_str().unwrap()],
                        "targets": ["ops"],
                        "env": {
                            "WEBHOOK_POST_URL": "http://127.0.0.1:9999/cb"
                        }
                    },
                    // Malformed entry (missing both exec and command) -> isolated as status: "error" (B1)
                    {
                        "id": "bad-missing-cmd",
                        "targets": ["ops"]
                    },
                    // Malformed entry (invalid env type) -> isolated as status: "error" (B1)
                    {
                        "id": "bad-env",
                        "command": python_bin,
                        "targets": ["ops"],
                        "env": { "FOO": 12345 }
                    },
                    // Rapid-crashing plugin that logs a secret to stderr -> updates node.status.json + redacted log (B5)
                    {
                        "id": "crasher",
                        "command": python_bin,
                        "args": ["-u", crash_plugin.to_str().unwrap()],
                        "targets": ["ops"],
                        "env": {
                            "CRASH_API_SECRET": { "secret": "crash-secret" }
                        }
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let mut cmd = isolated_cmd(&home);
        cmd.args(["daemon", "--config", cfg_path.to_str().unwrap(), "--json"]);
        let mut daemon = ManagedDaemon::spawn(&mut cmd);
        let startup = daemon.read_json_line(Duration::from_secs(15));

        // Daemon MUST start cleanly despite malformed entries!
        assert_eq!(
            startup["ok"], true,
            "daemon must survive bad plugin entries: {startup}"
        );
        let startup_str = startup.to_string();
        assert!(
            !startup_str.contains(plaintext_secret) && !startup_str.contains(stored_crash_secret),
            "startup JSON MUST NEVER leak raw secret values"
        );

        let warnings = startup["warnings"].as_array().expect("warnings array");
        assert!(
            warnings.iter().any(|w| {
                w.as_str().is_some_and(|s| {
                    s.contains("TELEGRAM_BOT_TOKEN")
                        && s.contains("plaintext")
                        && s.contains("secret")
                })
            }),
            "expected plaintext secret warning: {warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().is_some_and(|s| s.contains("bad-missing-cmd"))),
            "expected isolated warning for bad-missing-cmd: {warnings:?}"
        );

        let initial_plugins = startup["data"]["plugins"]
            .as_array()
            .expect("plugins array");
        let find_plugin = |arr: &[Value], id: &str| {
            arr.iter()
                .find(|p| p.get("id").and_then(Value::as_str) == Some(id))
                .cloned()
        };
        assert_eq!(
            find_plugin(initial_plugins, "cmd-ok").unwrap()["status"],
            "running"
        );
        assert_eq!(
            find_plugin(initial_plugins, "webhook").unwrap()["kind"],
            "bridge"
        );
        assert_eq!(
            find_plugin(initial_plugins, "webhook").unwrap()["status"],
            "running"
        );
        assert_eq!(
            find_plugin(initial_plugins, "bad-missing-cmd").unwrap()["status"],
            "error"
        );
        assert_eq!(
            find_plugin(initial_plugins, "bad-env").unwrap()["status"],
            "error"
        );

        // Poll `node.status.json` until `crasher` transitions to `degraded` (with redacted stderr + restarts)!
        let status_path = state_dir.join("node.status.json");
        let deadline = Instant::now() + Duration::from_secs(10);
        let crasher_entry = loop {
            if let Ok(raw) = fs::read_to_string(&status_path) {
                assert!(
                    !raw.contains(stored_crash_secret) && !raw.contains(plaintext_secret),
                    "node.status.json MUST NEVER contain raw secret values"
                );
                if let Ok(doc) = serde_json::from_str::<Value>(&raw) {
                    if let Some(arr) = doc["plugins"].as_array() {
                        if let Some(entry) = find_plugin(arr, "crasher") {
                            let st = entry["status"].as_str().unwrap_or("");
                            if st == "degraded" || st == "crash_loop_backoff" {
                                break entry;
                            }
                        }
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for crasher plugin degraded status in node.status.json"
            );
            thread::sleep(Duration::from_millis(50));
        };

        let last_err = crasher_entry["lastError"]
            .as_str()
            .expect("degraded crasher must populate lastError");
        assert!(
            last_err.contains("boot error with key=[REDACTED]"),
            "expected redacted stderr in lastError, got: {last_err}"
        );
        assert!(!last_err.contains(stored_crash_secret));

        // Verify per-plugin stderr log file exists with 0600 permissions (on Unix) and redacted content!
        let log_path = state_dir.join("logs").join("plugin-crasher.log");
        assert!(log_path.is_file(), "expected {}", log_path.display());
        let log_raw = fs::read_to_string(&log_path).unwrap();
        assert!(log_raw.contains("boot error with key=[REDACTED]"));
        assert!(!log_raw.contains(stored_crash_secret));
        #[cfg(unix)]
        {
            let mode = fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "plugin stderr log must be 0600");
        }

        daemon.shutdown();
    }

    #[test]
    fn bridge_topics_stay_local_only_from_remote_peers_with_wildcard_stream_scope() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!(
                "SKIP bridge_topics_stay_local_only_from_remote_peers_with_wildcard_stream_scope: node missing"
            );
            return;
        };

        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&state_dir).unwrap();

        let peer_http_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let webhook_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let webhook_script = repo_root().join("plugins/webhook/index.mjs");
        let webhook_secret = "whsec-b9-local-only-test";
        let secrets = SecretStore::new(&state_dir, SecretBackend::File);
        secrets.set("b9-wh-secret", webhook_secret).unwrap();

        let cfg_path = state_dir.join("node.json");
        fs::write(
            &cfg_path,
            serde_json::to_string_pretty(&json!({
                "v": 2,
                "nodeId": "alice@laptop",
                "profile": "p2p",
                "bind": format!("127.0.0.1:{peer_http_port}"),
                "stateDir": state_dir.to_str().unwrap(),
                "plugins": [{
                    "id": "webhook",
                    "kind": "bridge",
                    "command": node_bin,
                    "args": [webhook_script.to_str().unwrap()],
                    "targets": ["personal"],
                    "env": {
                        "WEBHOOK_HOST": "127.0.0.1",
                        "WEBHOOK_PORT": webhook_port.to_string(),
                        "WEBHOOK_PATH": "/webhook",
                        "WEBHOOK_TARGET": "personal",
                        "WEBHOOK_SECRET": { "secret": "b9-wh-secret" }
                    }
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        // Pre-seed a paired remote observer peer holding `stream:subscribe=*` in `node.sqlite`!
        let peer_token = "hyphae_peer_tok_observer_b9_test";
        {
            let mut ncfg = hyp_node::engine::NodeConfig::p2p(
                hyp_proto::address::NodeId::new("alice@laptop").unwrap(),
                &state_dir,
            );
            ncfg.secret_backend = Some(SecretBackend::File);
            let node = UnifiedNode::open(ncfg).unwrap();
            let now = hyp_store::now_ms();
            let token_hash = {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(peer_token.as_bytes()))
            };
            {
                let db = node.db();
                db.peers()
                    .upsert_peer(
                        &hyp_store::PeerInput {
                            peer_id: "observer@remote".to_string(),
                            profile: hyp_store::PeerProfile::Local,
                            endpoint: None,
                            status: hyp_store::PeerStatus::Active,
                            trust_tier: hyp_store::TrustTier::Peer,
                            scopes: vec!["stream:subscribe=*".to_string()],
                            auth_credential_ref: None,
                        },
                        now,
                    )
                    .unwrap();
                db.local()
                    .set_metadata(&format!("auth_token:{token_hash}"), "observer@remote")
                    .unwrap();
            }
            node.shutdown();
        }

        let mut cmd = isolated_cmd(&home);
        cmd.args(["daemon", "--config", cfg_path.to_str().unwrap(), "--json"]);
        let mut daemon = ManagedDaemon::spawn(&mut cmd);
        let startup = daemon.read_json_line(Duration::from_secs(15));
        assert_eq!(startup["ok"], true, "daemon startup failed: {startup}");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let client: Client<_, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();

            // 1. Authenticated remote peer with `stream:subscribe=*` fetches `/v1/manifest`:
            //    private bridge topic `"webhook"` MUST NOT be advertised!
            let manifest_req = Request::builder()
                .method(Method::GET)
                .uri(format!("http://127.0.0.1:{peer_http_port}/v1/manifest"))
                .header(header::AUTHORIZATION, format!("Bearer {peer_token}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let manifest_resp = client.request(manifest_req).await.unwrap();
            assert_eq!(manifest_resp.status(), StatusCode::OK);
            let manifest_bytes = manifest_resp.into_body().collect().await.unwrap().to_bytes();
            let signed_manifest: hyp_proto::manifest::SignedNodeManifest =
                serde_json::from_slice(&manifest_bytes).unwrap();
            let manifest_payload = signed_manifest.decode_payload().unwrap();
            let topics = &manifest_payload.advertised.topics;
            assert!(
                !topics.iter().any(|t| t.topic == "webhook"),
                "private bridge topic 'webhook' MUST NOT be advertised in remote manifest: {topics:?}"
            );

            // 2. Even if the remote peer guesses topic `"webhook"` and tries to subscribe via
            //    PUT /v1/subscriptions, it MUST fail closed with 403 `topic_local_only`!
            let sub_body = serde_json::to_vec(&json!({
                "subscriptions": [{
                    "id": "snoop-bridge",
                    "topic": "webhook",
                    "filters": [],
                    "coalesceSeconds": 0,
                    "mode": "full"
                }]
            }))
            .unwrap();
            let sub_req = Request::builder()
                .method(Method::PUT)
                .uri(format!("http://127.0.0.1:{peer_http_port}/v1/subscriptions"))
                .header(header::AUTHORIZATION, format!("Bearer {peer_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(sub_body)))
                .unwrap();
            let sub_resp = client.request(sub_req).await.unwrap();
            assert_eq!(
                sub_resp.status(),
                StatusCode::FORBIDDEN,
                "local-only bridge topic must reject remote PUT /v1/subscriptions with 403"
            );
            let sub_err_bytes = sub_resp.into_body().collect().await.unwrap().to_bytes();
            let sub_err: Value = serde_json::from_slice(&sub_err_bytes).unwrap();
            assert_eq!(
                sub_err["error"], "topic_local_only",
                "expected topic_local_only problem payload: {sub_err}"
            );

            // 3a. BR1: Before any local session is linked to `webhook:personal`, delivering an
            //     inbound bridge message MUST fail closed with 503 Unavailable (NEVER 202 Stored)
            //     so bridge plugins do NOT advance offsets and silently drop the user's message!
            let priv_body = json!({
                "from": "alice",
                "text": "TOP_SECRET_LOCAL_BRIDGE_DM_B9"
            })
            .to_string();
            let sig = {
                use ring::hmac;
                let key = hmac::Key::new(hmac::HMAC_SHA256, webhook_secret.as_bytes());
                format!(
                    "sha256={}",
                    hex::encode(hmac::sign(&key, priv_body.as_bytes()).as_ref())
                )
            };
            let wh_url = format!("http://127.0.0.1:{webhook_port}/webhook");
            let deadline = Instant::now() + Duration::from_secs(15);
            let unlinked_resp = loop {
                let req = Request::builder()
                    .method(Method::POST)
                    .uri(&wh_url)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("x-webhook-signature-256", &sig)
                    .body(Full::new(Bytes::from(priv_body.clone())))
                    .unwrap();
                match client.request(req).await {
                    Ok(r) => break r,
                    Err(_) if Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => {
                        let plugin_log = fs::read_to_string(
                            state_dir.join("logs").join("plugin-webhook.log"),
                        )
                        .unwrap_or_else(|_| "<missing>".to_string());
                        let status_json = fs::read_to_string(state_dir.join("node.status.json"))
                            .unwrap_or_else(|_| "<missing>".to_string());
                        panic!(
                            "webhook plugin unreachable: {e}\nplugin-webhook.log:\n{plugin_log}\nnode.status.json:\n{status_json}"
                        );
                    }
                }
            };
            assert_eq!(
                unlinked_resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "BR1: unlinked local bridge target must return 503 Unavailable instead of 202 Stored"
            );

            // 3b. Link a local session to `webhook:personal`, then replay the EXACT SAME payload:
            //     must succeed with 202 Accepted (proving failed unlinked delivery did NOT poison
            //     local dedup) and deliver to the linked local session!
            {
                let db = hyp_store::NodeDb::open(state_dir.join("node.sqlite")).unwrap();
                let now = hyp_store::now_ms();
                db.local()
                    .register_session("sess-local-b9", "{}", now)
                    .unwrap();
                db.local()
                    .add_bridge_link(&hyp_store::BridgeLink {
                        plugin: "webhook".to_string(),
                        target: "personal".to_string(),
                        session_id: "sess-local-b9".to_string(),
                        linked_at: now,
                        linked_by: "test".to_string(),
                    })
                    .unwrap();
            }
            let linked_req = Request::builder()
                .method(Method::POST)
                .uri(&wh_url)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-webhook-signature-256", &sig)
                .body(Full::new(Bytes::from(priv_body)))
                .unwrap();
            let wh_resp = client.request(linked_req).await.unwrap();
            assert_eq!(wh_resp.status(), StatusCode::ACCEPTED);
        });

        // 4. Verify local linked session received the private bridge DM AND EventStore has ZERO
        //    batches queued for `observer@remote` on topic `"webhook"`!
        thread::sleep(Duration::from_millis(200));
        {
            let db = hyp_store::NodeDb::open(state_dir.join("node.sqlite")).unwrap();
            let local_items = db.local().peek_inbox("sess-local-b9", 10).unwrap();
            assert!(
                local_items
                    .iter()
                    .any(|m| m.text.contains("TOP_SECRET_LOCAL_BRIDGE_DM_B9")),
                "linked local session should receive private bridge message: {local_items:?}"
            );
            let now = hyp_store::now_ms();
            let _ = db.events().tick(now);
            let batches = db
                .events()
                .claim_due_batches("observer@remote", now)
                .unwrap();
            assert!(
                batches.is_empty(),
                "remote peer with stream:subscribe=* MUST receive ZERO private bridge messages: {batches:?}"
            );
        }

        daemon.shutdown();
    }

    /// Minimal cross-platform Python3 subprocess `kind: "source"` plugin using the real Hyphae
    /// plugin SDK (`plugins/sdk/client.py`, supporting both Unix fd-3 and Windows loopback-TCP).
    /// Exposes a loopback-only HTTP trigger (`GET /health`, `POST /emit`) so E2E tests can emit
    /// arbitrary CloudEvents (omitting or spoofing `hyphaesourcekind`) on demand.
    const CROSS_PLATFORM_SOURCE_TRIGGER_PLUGIN_PY: &str = r#"import http.server, json, os, socketserver, sys, threading
sys.stderr.write("trigger-plugin: boot\n")
sys.stderr.flush()
sys.path.insert(0, os.environ["SDK_PY_DIR"])
from client import MeshPluginClient

client = MeshPluginClient()
port_file = os.environ["TRIGGER_PORT_FILE"]
sys.stderr.write(f"trigger-plugin: hello_ok targets={client.targets!r} port_file={port_file}\n")
sys.stderr.flush()

class FastThreadingHTTPServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # Skip http.server.HTTPServer.server_bind's socket.getfqdn("127.0.0.1") reverse-DNS
        # PTR query (1.0.0.127.in-addr.arpa), which can stall 15-30s on macOS CI runners.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"ok": True, "targets": client.targets}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    def do_POST(self):
        if self.path != "/emit":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8"))
        try:
            ack = client.send(payload["to"], payload["event"], retry_unavailable=False)
            body = json.dumps({"ok": True, "ack": ack}).encode("utf-8")
            self.send_response(200)
        except Exception as e:
            body = json.dumps({"ok": False, "error": str(e)}).encode("utf-8")
            self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

srv = FastThreadingHTTPServer(("127.0.0.1", 0), Handler)
srv.daemon_threads = True
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()
tmp_port_file = port_file + ".tmp"
with open(tmp_port_file, "w", encoding="utf-8") as fh:
    fh.write(str(srv.server_address[1]))
os.replace(tmp_port_file, port_file)
sys.stderr.write(f"trigger-plugin: ready port={srv.server_address[1]}\n")
sys.stderr.flush()
client._dead.wait()
srv.shutdown()
"#;

    #[test]
    fn source_plugin_stamps_external_webhook_flushes_immediately_and_blocks_remote_until_exposed() {
        let Some(python_bin) = find_python3_binary() else {
            eprintln!(
                "SKIP source_plugin_stamps_external_webhook_flushes_immediately_and_blocks_remote_until_exposed: python3 missing"
            );
            return;
        };

        use hyp_harness::sock::daemon_rpc_sync;
        use hyp_proto::scopes::ScopePreset;
        use hyp_store::{
            DeliveryMode, GateAuditQuery, GateDecision as StoreGateDecision, SubscriptionSpec,
        };

        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&state_dir).unwrap();

        let plugin_script = tmp.path().join("trigger_source_plugin.py");
        fs::write(&plugin_script, CROSS_PLATFORM_SOURCE_TRIGGER_PLUGIN_PY).unwrap();
        let sdk_py_dir = repo_root().join("plugins/sdk");

        let alloc_port = || {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let peer_http_port = alloc_port();
        let trigger_port_file_phase1 = tmp.path().join("trigger_port_phase1.txt");
        let trigger_port_file_phase2 = tmp.path().join("trigger_port_phase2.txt");

        // Pre-seed three paired remote peers covering ALL wildcard-stream presets (`member`,
        // `observer`, `full` — every one grants `stream:subscribe=*`) plus a same-node local
        // session subscribed to `personal-mail` with `coalesceSeconds: 0`!
        let peer_presets = [
            ("member@remote", "tok_member_src_b6", ScopePreset::Member),
            (
                "observer@remote",
                "tok_observer_src_b6",
                ScopePreset::Observer,
            ),
            ("full@remote", "tok_full_src_b6", ScopePreset::Full),
        ];
        {
            let mut ncfg = hyp_node::engine::NodeConfig::p2p(
                hyp_proto::address::NodeId::new("alice@laptop").unwrap(),
                &state_dir,
            );
            ncfg.secret_backend = Some(SecretBackend::File);
            let node = UnifiedNode::open(ncfg).unwrap();
            let now = hyp_store::now_ms();
            {
                let db = node.db();
                for (peer_id, tok, preset) in &peer_presets {
                    let token_hash = {
                        use sha2::{Digest, Sha256};
                        hex::encode(Sha256::digest(tok.as_bytes()))
                    };
                    db.peers()
                        .upsert_peer(
                            &hyp_store::PeerInput {
                                peer_id: (*peer_id).to_string(),
                                profile: hyp_store::PeerProfile::Local,
                                endpoint: None,
                                status: hyp_store::PeerStatus::Active,
                                trust_tier: match preset {
                                    ScopePreset::GuestRo | ScopePreset::Guest => {
                                        hyp_store::TrustTier::Guest
                                    }
                                    ScopePreset::Observer => hyp_store::TrustTier::Peer,
                                    ScopePreset::Member | ScopePreset::Full => {
                                        hyp_store::TrustTier::Org
                                    }
                                },
                                scopes: preset.expand(),
                                auth_credential_ref: None,
                            },
                            now,
                        )
                        .unwrap();
                    db.local()
                        .set_metadata(&format!("auth_token:{token_hash}"), peer_id)
                        .unwrap();
                }

                db.local()
                    .register_session("sess-local-src", "{}", now)
                    .unwrap();
                db.events()
                    .upsert_subscription(
                        &SubscriptionSpec {
                            id: "local-src-sub-0".to_string(),
                            origin_node: "alice@laptop".to_string(),
                            topic: "personal-mail".to_string(),
                            subscriber: "sess-local-src".to_string(),
                            filters: vec![],
                            coalesce_seconds: 0,
                            max_batch_age_ms: None,
                            max_wakes_per_hour: None,
                            mode: DeliveryMode::Full,
                        },
                        now,
                    )
                    .unwrap();
            }
            node.shutdown();
        }

        let write_node_cfg =
            |cfg_path: &Path, trigger_port_file: &Path, expose_topic: Option<bool>| {
                let mut plugin_entry = json!({
                    "id": "mailfeed",
                    "kind": "source",
                    "command": python_bin,
                    "args": ["-u", plugin_script.to_str().unwrap()],
                    "targets": ["personal-mail"],
                    "env": {
                        "SDK_PY_DIR": sdk_py_dir.to_str().unwrap(),
                        "TRIGGER_PORT_FILE": trigger_port_file.to_str().unwrap(),
                    }
                });
                if let Some(exp) = expose_topic {
                    plugin_entry["exposeTopic"] = json!(exp);
                }
                let mut gate_cfg = hyp_node::gates::SecurityGateConfig::default();
                gate_cfg
                    .stage1
                    .inbound_regex_denylist
                    .push("FORBIDDEN_SOURCE_CANARY".to_string());
                gate_cfg.stage1.regex_deny_action = hyp_node::gates::Stage1DenyAction::Quarantine;
                fs::write(
                    cfg_path,
                    serde_json::to_string_pretty(&json!({
                        "v": 2,
                        "nodeId": "alice@laptop",
                        "profile": "p2p",
                        "bind": format!("127.0.0.1:{peer_http_port}"),
                        "stateDir": state_dir.to_str().unwrap(),
                        "gate": serde_json::to_value(&gate_cfg).unwrap(),
                        "plugins": [plugin_entry]
                    }))
                    .unwrap(),
                )
                .unwrap();
            };

        let cfg_path = state_dir.join("node.json");

        // =====================================================================
        // PHASE 1: Default `exposeTopic` (omitted -> `false`, strictly local-only)
        // =====================================================================
        write_node_cfg(&cfg_path, &trigger_port_file_phase1, None);
        let mut cmd1 = isolated_cmd(&home);
        cmd1.args(["daemon", "--config", cfg_path.to_str().unwrap(), "--json"]);
        let mut daemon1 = ManagedDaemon::spawn(&mut cmd1);
        let startup1 = daemon1.read_json_line(Duration::from_secs(15));
        assert_eq!(
            startup1["ok"], true,
            "phase 1 daemon startup failed: {startup1}"
        );
        let sock_path = PathBuf::from(startup1["data"]["socketPath"].as_str().unwrap());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let wait_plugin_ready = |port_file: &Path| -> u16 {
            rt.block_on(async {
                let client: Client<_, Full<Bytes>> =
                    Client::builder(TokioExecutor::new()).build_http();
                let deadline = Instant::now() + Duration::from_secs(20);
                let mut last_port: Option<u16> = None;
                loop {
                    if let Ok(raw) = fs::read_to_string(port_file) {
                        if let Ok(port) = raw.trim().parse::<u16>() {
                            last_port = Some(port);
                            let req = Request::builder()
                                .method(Method::GET)
                                .uri(format!("http://127.0.0.1:{port}/health"))
                                .body(Full::new(Bytes::new()))
                                .unwrap();
                            if let Ok(resp) = client.request(req).await {
                                if resp.status() == StatusCode::OK {
                                    return port;
                                }
                            }
                        }
                    }
                    if Instant::now() >= deadline {
                        let plugin_log = fs::read_to_string(
                            state_dir.join("logs").join("plugin-mailfeed.log"),
                        )
                        .unwrap_or_else(|_| "<no plugin-mailfeed.log>".to_string());
                        let node_status = fs::read_to_string(state_dir.join("node.status.json"))
                            .unwrap_or_else(|_| "<no node.status.json>".to_string());
                        panic!(
                            "timed out waiting for source plugin health (port={last_port:?}, file={})\nplugin-mailfeed.log:\n{plugin_log}\nnode.status.json:\n{node_status}",
                            port_file.display()
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
        };

        let emit_source_event = |port: u16, event: Value| -> Value {
            rt.block_on(async {
                let client: Client<_, Full<Bytes>> =
                    Client::builder(TokioExecutor::new()).build_http();
                let body = serde_json::to_vec(&json!({
                    "to": "personal-mail",
                    "event": event,
                }))
                .unwrap();
                let req = Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://127.0.0.1:{port}/emit"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(body)))
                    .unwrap();
                let resp = client.request(req).await.unwrap();
                let st = resp.status();
                let bytes = resp.into_body().collect().await.unwrap().to_bytes();
                let val: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(st, StatusCode::OK, "emit failed ({st}): {val}");
                assert_eq!(val["ok"], true, "emit returned error: {val}");
                val
            })
        };

        let trigger_port_phase1 = wait_plugin_ready(&trigger_port_file_phase1);

        // 1A. Issue #25 (B6): ALL three wildcard-stream presets (`member`, `observer`, `full`)
        //     MUST NOT see `personal-mail` in `/v1/manifest` AND MUST get `403 topic_local_only`
        //     on `PUT /v1/subscriptions`!
        rt.block_on(async {
            let client: Client<_, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            for (peer_id, tok, _preset) in &peer_presets {
                let m_req = Request::builder()
                    .method(Method::GET)
                    .uri(format!("http://127.0.0.1:{peer_http_port}/v1/manifest"))
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                let m_resp = client.request(m_req).await.unwrap();
                assert_eq!(m_resp.status(), StatusCode::OK);
                let m_bytes = m_resp.into_body().collect().await.unwrap().to_bytes();
                let signed_manifest: hyp_proto::manifest::SignedNodeManifest =
                    serde_json::from_slice(&m_bytes).unwrap();
                let manifest_payload = signed_manifest.decode_payload().unwrap();
                let topics = &manifest_payload.advertised.topics;
                assert!(
                    !topics.iter().any(|t| t.topic == "personal-mail"),
                    "{peer_id}: local-only source topic MUST NOT appear in /v1/manifest: {topics:?}"
                );

                let sub_body = serde_json::to_vec(&json!({
                    "subscriptions": [{
                        "id": format!("snoop-{peer_id}"),
                        "topic": "personal-mail",
                        "filters": [],
                        "coalesceSeconds": 0,
                        "mode": "full"
                    }]
                }))
                .unwrap();
                let s_req = Request::builder()
                    .method(Method::PUT)
                    .uri(format!(
                        "http://127.0.0.1:{peer_http_port}/v1/subscriptions"
                    ))
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(sub_body)))
                    .unwrap();
                let s_resp = client.request(s_req).await.unwrap();
                assert_eq!(
                    s_resp.status(),
                    StatusCode::FORBIDDEN,
                    "{peer_id} (stream:subscribe=*) MUST fail closed with 403 on local-only source topic"
                );
                let s_bytes = s_resp.into_body().collect().await.unwrap().to_bytes();
                let prob: Value = serde_json::from_slice(&s_bytes).unwrap();
                assert_eq!(
                    prob["error"], "topic_local_only",
                    "{peer_id}: expected topic_local_only error: {prob}"
                );
            }
        });

        // 1B. Issue #39 (B1) + Issue #38: Attach a live `hyp wait` on same-node `sess-local-src`
        //     (`coalesceSeconds: 0`) BEFORE publishing Event 1 (omitting `hyphaesourcekind`), and
        //     assert immediate wakeup (< 3s, no tick wait or restart) + server-stamped
        //     `hyphaesourcekind == "external-webhook"`!
        let mut wait_cmd = isolated_cmd(&home);
        wait_cmd
            .args([
                "wait",
                "--session",
                "sess-local-src",
                "--socket",
                sock_path.to_str().unwrap(),
                "--timeout",
                "8",
                "--json",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let wait_child = wait_cmd.spawn().expect("spawn hyp wait");
        let (wait_tx, wait_rx) = mpsc::channel();
        thread::spawn(move || {
            let out = wait_child.wait_with_output();
            let _ = wait_tx.send(out);
        });

        let attach_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let sum = daemon_rpc_sync(
                &sock_path,
                &json!({ "type": "session.summary", "sessionId": "sess-local-src", "detail": "compact" }),
                Duration::from_secs(2),
            );
            if sum.ok
                && sum
                    .result
                    .as_ref()
                    .is_some_and(|r| r["session"]["hasLiveTransport"] == true)
            {
                break;
            }
            assert!(
                Instant::now() < attach_deadline,
                "timed out waiting for hyp wait to attach"
            );
            thread::sleep(Duration::from_millis(25));
        }

        let t_emit = Instant::now();
        let ack1 = emit_source_event(
            trigger_port_phase1,
            json!({
                "specversion": "1.0",
                "id": "src-ev-1-omitted",
                "source": "mailfeed/gmail",
                "type": "to.hyphae.mail.received",
                "datacontenttype": "application/json",
                "data": { "subject": "INSTANT_B1_PAYLOAD_1" }
            }),
        );
        assert_eq!(ack1["ack"]["status"], "stored");

        let wait_output = wait_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("Issue #39 (B1): coalesceSeconds: 0 hyp wait timed out instead of waking immediately")
            .expect("hyp wait output");
        let elapsed = t_emit.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "Issue #39 (B1): coalesceSeconds: 0 subscriber must wake immediately, took {elapsed:?}"
        );
        let wait_stdout = String::from_utf8_lossy(&wait_output.stdout);
        let wait_out: Value = serde_json::from_str(&wait_stdout)
            .unwrap_or_else(|e| panic!("invalid hyp wait --json output ({e}): {wait_stdout}"));
        assert_eq!(
            wait_out["ok"], true,
            "hyp wait should wake cleanly with Event 1: {wait_out}"
        );
        let wait_items = wait_out["data"]["items"]
            .as_array()
            .expect("hyp wait items array");
        assert!(
            !wait_items.is_empty(),
            "Issue #39 (B1): hyp wait must deliver wake item immediately: {wait_out}"
        );
        // RFC 0004 / Issue #38: ExternalWebhook trust tier defaults to Stage 1 `CapToQueue`
        // (`notifyOnly: false`, `urgency="queue"`), so `hyp wait` wakes immediately with a
        // metadata-only `<hyphae-inbox ...>` XML digest (zero raw payload!) for `local.personal-mail`
        // while storing the full CloudEvent (stamped `hyphaesourcekind = "external-webhook"`) in mailbox!
        assert_eq!(
            wait_items[0]["notifyOnly"], false,
            "RFC 0004 / Issue #38: subprocess source event must enforce ExternalWebhook CapToQueue: {wait_out}"
        );
        let wait_text = wait_items[0]["text"].as_str().unwrap_or("");
        assert!(
            wait_text.contains("<hyphae-inbox ")
                && wait_text.contains("urgency=\"queue\"")
                && wait_text.contains("local.personal-mail"),
            "hyp wait wake digest missing queue XML for local.personal-mail: {wait_out}"
        );
        assert!(
            !wait_text.contains("INSTANT_B1_PAYLOAD_1"),
            "RFC 0004: hyp wait wake digest must NEVER include raw CloudEvent payload: {wait_out}"
        );
        {
            let db = hyp_store::NodeDb::open(state_dir.join("node.sqlite")).unwrap();
            let mailbox_items = db.local().peek_inbox("sess-local-src", 20).unwrap();
            let ev1_row = mailbox_items
                .iter()
                .find(|m| m.text.contains("INSTANT_B1_PAYLOAD_1"))
                .expect("Event 1 must be materialized immediately in local mailbox");
            let ev1_json: Value = serde_json::from_str(&ev1_row.text).unwrap();
            assert_eq!(
                ev1_json["events"][0]["hyphaesourcekind"], "external-webhook",
                "Issue #38: Event 1 (omitted hyphaesourcekind) MUST be stamped external-webhook: {ev1_json}"
            );
        }

        // 1C. Issue #38 Spoofing & Security Gate Enforcement:
        //     - Event 2 tries to spoof `"hyphaesourcekind": "self-host"` with Stage 1 denylist
        //       canary `"FORBIDDEN_SOURCE_CANARY"`: MUST be overwritten to `"external-webhook"`
        //       AND quarantined by Security Gate with `trust_tier == "external-webhook"`!
        //     - Event 3 tries to spoof `"hyphaesourcekind": "human-verified"` with clean payload:
        //       MUST be overwritten to `"external-webhook"` and delivered cleanly!
        let _ = emit_source_event(
            trigger_port_phase1,
            json!({
                "specversion": "1.0",
                "id": "src-ev-2-spoof-self",
                "source": "mailfeed/gmail",
                "type": "to.hyphae.mail.received",
                "datacontenttype": "application/json",
                "hyphaesourcekind": "self-host",
                "data": { "body": "FORBIDDEN_SOURCE_CANARY spoof attempt" }
            }),
        );
        let _ = emit_source_event(
            trigger_port_phase1,
            json!({
                "specversion": "1.0",
                "id": "src-ev-3-spoof-human",
                "source": "mailfeed/gmail",
                "type": "to.hyphae.mail.received",
                "datacontenttype": "application/json",
                "hyphaesourcekind": "human-verified",
                "data": { "subject": "SPOOF_HUMAN_OVERRIDDEN_3" }
            }),
        );

        // Trigger Security Gate evaluation via live LocalDaemon `mailbox.drain`, waiting briefly
        // until Event 2 is quarantined and Event 3 is present in local mailbox!
        let drain_deadline = Instant::now() + Duration::from_secs(3);
        let mut drained_items: Vec<Value> = Vec::new();
        loop {
            let drain = daemon_rpc_sync(
                &sock_path,
                &json!({ "type": "mailbox.drain", "sessionId": "sess-local-src" }),
                Duration::from_secs(2),
            );
            assert!(drain.ok, "mailbox.drain failed: {drain:?}");
            let batch = drain.result.unwrap()["items"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            drained_items.extend(batch);

            let db = hyp_store::NodeDb::open(state_dir.join("node.sqlite")).unwrap();
            let q = db
                .local()
                .list_quarantined(Some("sess-local-src"), 20)
                .unwrap();
            let inbox = db.local().peek_inbox("sess-local-src", 20).unwrap();
            if q.iter().any(|m| m.text.contains("FORBIDDEN_SOURCE_CANARY"))
                && inbox
                    .iter()
                    .any(|m| m.text.contains("SPOOF_HUMAN_OVERRIDDEN_3"))
            {
                break;
            }
            assert!(
                Instant::now() < drain_deadline,
                "timed out waiting for Events 2 & 3 gate evaluation: q={q:?} inbox={inbox:?}"
            );
            thread::sleep(Duration::from_millis(25));
        }

        // Event 2 MUST NOT have leaked into drained output (quarantined by Security Gate!).
        assert!(
            !drained_items.iter().any(|it| it["text"]
                .as_str()
                .unwrap_or("")
                .contains("FORBIDDEN_SOURCE_CANARY")),
            "Event 2 with denylist canary must be quarantined by Security Gate: {drained_items:?}"
        );

        // Inspect SQLite `mailbox` (Event 3 delivered + Event 2 quarantined), `gate_audit`
        // (`trust_tier == "external-webhook"`), AND `EventStore` (ZERO batches for any remote peer!).
        {
            let db = hyp_store::NodeDb::open(state_dir.join("node.sqlite")).unwrap();
            let inbox = db.local().peek_inbox("sess-local-src", 20).unwrap();
            let ev3_row = inbox
                .iter()
                .find(|m| m.text.contains("SPOOF_HUMAN_OVERRIDDEN_3"))
                .expect("Event 3 must be in local mailbox immediately");
            let ev3_parsed: Value = serde_json::from_str(&ev3_row.text).unwrap();
            assert_eq!(
                ev3_parsed["events"][0]["hyphaesourcekind"], "external-webhook",
                "Issue #38: spoofed 'human-verified' must be overwritten to 'external-webhook': {ev3_parsed}"
            );

            let quarantined = db
                .local()
                .list_quarantined(Some("sess-local-src"), 20)
                .unwrap();
            let q_ev2 = quarantined
                .iter()
                .find(|m| m.text.contains("FORBIDDEN_SOURCE_CANARY"))
                .expect("Event 2 must be parked in quarantine");
            let q_ev2_json: Value = serde_json::from_str(&q_ev2.text).unwrap();
            assert_eq!(
                q_ev2_json["events"][0]["hyphaesourcekind"], "external-webhook",
                "Issue #38: spoofed 'self-host' must be overwritten to 'external-webhook' in stored event: {q_ev2_json}"
            );

            let audits = db
                .local()
                .query_gate_audit(&GateAuditQuery {
                    session_id: Some("sess-local-src".to_string()),
                    limit: Some(50),
                    ..Default::default()
                })
                .unwrap();
            assert!(
                audits.iter().any(|a| {
                    a.decision == StoreGateDecision::Quarantine
                        && a.trust_tier.as_deref() == Some("external-webhook")
                }),
                "Issue #38: Security Gate audit must record Quarantine at ExternalWebhook trust tier: {audits:?}"
            );

            let now = hyp_store::now_ms();
            let _ = db.events().tick(now);
            for (peer_id, _, _) in &peer_presets {
                let remote_batches = db.events().claim_due_batches(peer_id, now).unwrap();
                assert!(
                    remote_batches.is_empty(),
                    "Issue #25 (B6): remote peer {peer_id} MUST receive ZERO events from local-only source plugin: {remote_batches:?}"
                );
            }
        }

        daemon1.shutdown();

        // =====================================================================
        // PHASE 2: Flip `"exposeTopic": true` -> authorized remote peer gets 200 & events!
        // =====================================================================
        write_node_cfg(&cfg_path, &trigger_port_file_phase2, Some(true));
        let mut cmd2 = isolated_cmd(&home);
        cmd2.args(["daemon", "--config", cfg_path.to_str().unwrap(), "--json"]);
        let mut daemon2 = ManagedDaemon::spawn(&mut cmd2);
        let startup2 = daemon2.read_json_line(Duration::from_secs(15));
        assert_eq!(
            startup2["ok"], true,
            "phase 2 daemon startup failed: {startup2}"
        );
        let _sock_path2 = PathBuf::from(startup2["data"]["socketPath"].as_str().unwrap());

        let trigger_port_phase2 = wait_plugin_ready(&trigger_port_file_phase2);

        // 2A. Observer's `/v1/manifest` NOW advertises `personal-mail`, and `PUT /v1/subscriptions`
        //     succeeds with `200 OK`!
        let obs_token = peer_presets[1].1;
        rt.block_on(async {
            let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
            let m_req = Request::builder()
                .method(Method::GET)
                .uri(format!("http://127.0.0.1:{peer_http_port}/v1/manifest"))
                .header(header::AUTHORIZATION, format!("Bearer {obs_token}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let m_resp = client.request(m_req).await.unwrap();
            assert_eq!(m_resp.status(), StatusCode::OK);
            let m_bytes = m_resp.into_body().collect().await.unwrap().to_bytes();
            let signed_manifest: hyp_proto::manifest::SignedNodeManifest =
                serde_json::from_slice(&m_bytes).unwrap();
            let manifest_payload = signed_manifest.decode_payload().unwrap();
            let topics = &manifest_payload.advertised.topics;
            assert!(
                topics.iter().any(|t| t.topic == "personal-mail"),
                "exposeTopic: true source topic MUST be advertised in /v1/manifest: {topics:?}"
            );

            let sub_body = serde_json::to_vec(&json!({
                "subscriptions": [{
                    "id": "obs-exposed-mail",
                    "topic": "personal-mail",
                    "filters": [],
                    "coalesceSeconds": 0,
                    "mode": "full"
                }]
            }))
            .unwrap();
            let s_req = Request::builder()
                .method(Method::PUT)
                .uri(format!(
                    "http://127.0.0.1:{peer_http_port}/v1/subscriptions"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {obs_token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(sub_body)))
                .unwrap();
            let s_resp = client.request(s_req).await.unwrap();
            assert_eq!(
                s_resp.status(),
                StatusCode::OK,
                "exposeTopic: true must allow authorized remote peer subscription with 200 OK"
            );
        });

        // 2B. Publish Event 4 (spoofing `"hyphaesourcekind": "org"`) -> BOTH local session AND
        //     remote `observer@remote` receive it carrying `"hyphaesourcekind": "external-webhook"`!
        let ack4 = emit_source_event(
            trigger_port_phase2,
            json!({
                "specversion": "1.0",
                "id": "src-ev-4-exposed-spoof-org",
                "source": "mailfeed/gmail",
                "type": "to.hyphae.mail.received",
                "datacontenttype": "application/json",
                "hyphaesourcekind": "org",
                "data": { "subject": "EXPOSED_REMOTE_OK_4" }
            }),
        );
        assert_eq!(ack4["ack"]["status"], "stored");

        // Same-node local session receives Event 4 immediately in its mailbox.
        let local4_deadline = Instant::now() + Duration::from_secs(3);
        let mut found_local_ev4 = false;
        while Instant::now() < local4_deadline {
            let db = hyp_store::NodeDb::open(state_dir.join("node.sqlite")).unwrap();
            let inbox = db.local().peek_inbox("sess-local-src", 30).unwrap();
            if let Some(ev4_row) = inbox
                .iter()
                .find(|m| m.text.contains("EXPOSED_REMOTE_OK_4"))
            {
                let parsed: Value = serde_json::from_str(&ev4_row.text).unwrap();
                assert_eq!(
                    parsed["events"][0]["hyphaesourcekind"], "external-webhook",
                    "Event 4 local copy must carry external-webhook: {parsed}"
                );
                found_local_ev4 = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(
            found_local_ev4,
            "local session must receive Event 4 immediately when exposeTopic: true"
        );

        // Authorized remote peer receives Event 4 cleanly with `hyphaesourcekind == "external-webhook"`!
        {
            let db = hyp_store::NodeDb::open(state_dir.join("node.sqlite")).unwrap();
            let now = hyp_store::now_ms();
            let _ = db.events().tick(now);
            let remote_batches = db
                .events()
                .claim_due_batches("observer@remote", now)
                .unwrap();
            assert_eq!(
                remote_batches.len(),
                1,
                "exposed source topic must queue Event 4 for subscribed remote peer: {remote_batches:?}"
            );
            assert_eq!(remote_batches[0].topic, "personal-mail");
            assert_eq!(remote_batches[0].events.len(), 1);
            assert_eq!(
                remote_batches[0].events[0].data["subject"],
                "EXPOSED_REMOTE_OK_4"
            );
            assert_eq!(
                remote_batches[0].events[0]
                    .extensions
                    .get("hyphaesourcekind")
                    .map(String::as_str),
                Some("external-webhook"),
                "Issue #38: remote-fanned source CloudEvent MUST carry hyphaesourcekind=external-webhook: {:?}",
                remote_batches[0].events[0]
            );
        }

        daemon2.shutdown();
    }
}
