//! End-to-End Tests for `plugins[]` Configuration (`"command"` alias, error isolation,
//! plaintext secret warnings, doc snippet parity, CrashLoopBackOff `node.status.json`
//! observability, and local-only bridge topics).
//!
//! Spawns the real compiled `hyp` binary in isolated temp dirs with `HYPHAE_SECRET_BACKEND=file`
//! on BOTH Unix (fd-3) and Windows (authenticated loopback-TCP).

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
        cmd.env("HOME", home)
            .env("USERPROFILE", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("HYPHAE_SECRET_BACKEND", "file")
            .env_remove("HYPHAE_CONFIG")
            .env_remove("HYPHAE_STATE_DIR")
            .env_remove("HYPHAE_SOCKET");
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
            eprintln!("SKIP documented_plugins_json_snippets_boot_real_hyp_daemon: python3 missing");
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
                for secret_name in ["telegram-bot-token", "slack-app-token", "slack-bot-token"] {
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
                cfg_obj.insert("nodeId".to_string(), json!(format!("doc{doc_idx}-{snip_idx}@box")));
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
            eprintln!("SKIP command_and_exec_isolation_plaintext_warning_and_crash_loop_status_e2e: python3 missing");
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
        assert_eq!(startup["ok"], true, "daemon must survive bad plugin entries: {startup}");
        let startup_str = startup.to_string();
        assert!(
            !startup_str.contains(plaintext_secret) && !startup_str.contains(stored_crash_secret),
            "startup JSON MUST NEVER leak raw secret values"
        );

        let warnings = startup["warnings"].as_array().expect("warnings array");
        assert!(
            warnings.iter().any(|w| {
                w.as_str().is_some_and(|s| {
                    s.contains("TELEGRAM_BOT_TOKEN") && s.contains("plaintext") && s.contains("secret")
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
        assert_eq!(find_plugin(initial_plugins, "cmd-ok").unwrap()["status"], "running");
        assert_eq!(find_plugin(initial_plugins, "webhook").unwrap()["kind"], "bridge");
        assert_eq!(find_plugin(initial_plugins, "webhook").unwrap()["status"], "running");
        assert_eq!(
            find_plugin(initial_plugins, "bad-missing-cmd").unwrap()["status"],
            "error"
        );
        assert_eq!(find_plugin(initial_plugins, "bad-env").unwrap()["status"], "error");

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
            eprintln!("SKIP bridge_topics_stay_local_only_from_remote_peers_with_wildcard_stream_scope: node missing");
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
            let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
            let topics = manifest["advertised"]["topics"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert!(
                !topics.iter().any(|t| t["topic"] == "webhook"),
                "private bridge topic 'webhook' MUST NOT be advertised in remote manifest: {topics:?}"
            );

            // 2. Even if the remote peer guesses topic `"webhook"` and subscribes via PUT /v1/subscriptions...
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
            assert_eq!(sub_resp.status(), StatusCode::OK);

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
            let batches = db.events().claim_due_batches("observer@remote", now).unwrap();
            assert!(
                batches.is_empty(),
                "remote peer with stream:subscribe=* MUST receive ZERO private bridge messages: {batches:?}"
            );
        }

        daemon.shutdown();
    }
}
