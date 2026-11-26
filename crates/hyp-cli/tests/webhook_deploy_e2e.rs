#![cfg(unix)]

mod common;

use common::{isolated_cmd, parse_json_stdout};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

const TARGET: &str = "http://127.0.0.1:8796/sentry";
const DNS: &str = "hub.tail123.ts.net";

fn script(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn cli(home: &Path, arguments: &[&str]) -> (i32, Value) {
    cli_with_target(home, TARGET, arguments)
}

fn cli_with_target(home: &Path, target: &str, arguments: &[&str]) -> (i32, Value) {
    let output = isolated_cmd(home)
        .env_remove("TAILSCALE_BIN")
        .env("FIXTURE", home)
        .env("TAILSCALE_SOCKET", home.join("tailscale.sock"))
        .env("PATH", home)
        .args(["deploy", "webhook", "--local-target", target, "--json"])
        .args(arguments)
        .output()
        .unwrap();
    (output.status.code().unwrap(), parse_json_stdout(&output))
}

struct TestTailscale {
    backend_state: &'static str,
    config: Value,
    revision: u64,
    updates: usize,
    competing_edit: Option<Value>,
}

impl TestTailscale {
    fn replace_config(&mut self, config: Value) {
        self.config = config;
        self.revision += 1;
    }
}

async fn fake_tailscale(
    home: &Path,
    backend_state: &'static str,
    config: Value,
) -> (
    std::sync::Arc<std::sync::Mutex<TestTailscale>>,
    tokio::task::JoinHandle<()>,
) {
    use http_body_util::{BodyExt, Full};
    use hyper::{
        Method, Request, Response, StatusCode,
        body::{Bytes, Incoming},
        server::conn::http1,
    };
    use hyper_util::rt::TokioIo;
    use std::sync::{Arc, Mutex};

    let socket = tokio::net::UnixListener::bind(home.join("tailscale.sock")).unwrap();
    let state = Arc::new(Mutex::new(TestTailscale {
        backend_state,
        config,
        revision: 0,
        updates: 0,
        competing_edit: None,
    }));
    let task_state = Arc::clone(&state);
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = socket.accept().await {
            let state = Arc::clone(&task_state);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|request: Request<Incoming>| {
                    let state = Arc::clone(&state);
                    async move {
                        assert_eq!(request.headers()["host"], "local-tailscaled.sock");
                        let (head, body) = request.into_parts();
                        let mut response = Response::builder();
                        let payload = body.collect().await.unwrap().to_bytes();
                        let mut state = state.lock().unwrap();
                        let output = match (head.method, head.uri.path()) {
                            (Method::GET, "/localapi/v0/status") => json!({
                                "BackendState":state.backend_state,
                                "Self":{"DNSName":format!("{DNS}."),"CapMap":{
                                    "https":[], "funnel":[], "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000":[]
                                }}
                            }),
                            (Method::GET, "/localapi/v0/serve-config") => {
                                response =
                                    response.header("etag", format!("revision-{}", state.revision));
                                state.config.clone()
                            }
                            (Method::POST, "/localapi/v0/serve-config") => {
                                if let Some(competing) = state.competing_edit.take() {
                                    state.replace_config(competing);
                                }
                                if head
                                    .headers
                                    .get("if-match")
                                    .and_then(|value| value.to_str().ok())
                                    == Some(&format!("revision-{}", state.revision))
                                {
                                    state.replace_config(serde_json::from_slice(&payload).unwrap());
                                    state.updates += 1;
                                } else {
                                    response = response.status(StatusCode::PRECONDITION_FAILED);
                                }
                                Value::Null
                            }
                            _ => panic!("unexpected LocalAPI request {}", head.uri),
                        };
                        Ok::<_, std::convert::Infallible>(
                            response
                                .body(Full::new(Bytes::from(output.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (state, server)
}

#[tokio::test(flavor = "multi_thread")]
async fn funnel_discovery_activation_and_rerun_leave_private_serve_routes_untouched() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("http://{}/sentry", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = [0; 2048];
            let read = stream.read(&mut request).await.unwrap();
            let response = if request[..read].starts_with(b"OPTIONS /sentry HTTP/1.1") {
                b"HTTP/1.1 204 No Content\r\nx-hyphae-webhook-receiver: signed\r\nConnection: close\r\n\r\n".as_slice()
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .as_slice()
            };
            stream.write_all(response).await.unwrap();
        }
    });
    let home = TempDir::new().unwrap();
    let private = json!({
        "TCP": {"8443":{"HTTPS":true}},
        "Web": {(format!("{DNS}:8443")):{"Handlers":{"/":{"Proxy":"http://127.0.0.1:8790"}}}}
    });
    let (tailscale, tailscale_server) =
        fake_tailscale(home.path(), "Running", private.clone()).await;
    let (exit, discover) = cli_with_target(home.path(), &target, &[]);
    assert_eq!(exit, 0, "{discover}");
    assert_eq!(discover["data"]["tailscale"]["status"], "available");
    assert_eq!(discover["data"]["tailscale"]["port"], 10000);
    assert_eq!(tailscale.lock().unwrap().updates, 0);

    let (exit, denied) = cli_with_target(
        home.path(),
        &target,
        &["--provider", "tailscale", "--funnel-port", "8443"],
    );
    assert_eq!(exit, 1, "{denied}");
    assert_eq!(denied["error"]["code"], "WEBHOOK_ROUTE_UNAVAILABLE");
    assert_eq!(tailscale.lock().unwrap().updates, 0);

    let (exit, plan) =
        cli_with_target(home.path(), &target, &["--provider", "tailscale", "--plan"]);
    assert_eq!(exit, 0, "{plan}");
    assert_eq!(plan["data"]["status"], "planned");
    assert_eq!(tailscale.lock().unwrap().updates, 0);

    let unrelated = target.replace("/sentry", "/admin");
    let (exit, unrelated) = cli_with_target(home.path(), &unrelated, &["--provider", "tailscale"]);
    assert_eq!(exit, 1, "{unrelated}");
    assert_eq!(unrelated["error"]["code"], "WEBHOOK_ROUTE_UNAVAILABLE");
    assert_eq!(tailscale.lock().unwrap().updates, 0);

    // A separate operator adds a private route after discovery. The LocalAPI
    // rejects the exact snapshot's ETag and the route remains private.
    let mut competing = private.clone();
    competing["TCP"]["10000"] = json!({"HTTPS":true});
    competing["Web"][format!("{DNS}:10000")] =
        json!({"Handlers":{"/admin":{"Proxy":"http://127.0.0.1:8788"}}});
    tailscale.lock().unwrap().competing_edit = Some(competing.clone());
    let (exit, raced) = cli_with_target(home.path(), &target, &["--provider", "tailscale"]);
    assert_eq!(exit, 1, "{raced}");
    assert_eq!(tailscale.lock().unwrap().updates, 0);
    assert_eq!(tailscale.lock().unwrap().config, competing);
    assert!(
        tailscale
            .lock()
            .unwrap()
            .config
            .get("AllowFunnel")
            .is_none()
    );
    tailscale.lock().unwrap().replace_config(private.clone());

    for reused in [false, true] {
        let (exit, configured) =
            cli_with_target(home.path(), &target, &["--provider", "tailscale"]);
        assert_eq!(exit, 0, "{configured}");
        assert_eq!(configured["data"]["reused"], reused);
        assert_eq!(configured["data"]["localTarget"], target);
        assert_eq!(
            configured["data"]["publicUrl"],
            "https://hub.tail123.ts.net:10000/sentry"
        );
    }
    assert_eq!(tailscale.lock().unwrap().updates, 1);
    let after = tailscale.lock().unwrap().config.clone();
    assert_eq!(
        after["Web"][format!("{DNS}:8443")],
        private["Web"][format!("{DNS}:8443")]
    );
    assert!(after["AllowFunnel"].get(format!("{DNS}:8443")).is_none());
    // Upgrade the same public path and same local socket from the previous SDK's
    // path-stripping mapping. The existing private port stays untouched.
    let mut legacy = after;
    legacy["Web"][format!("{DNS}:10000")]["Handlers"]["/sentry"]["Proxy"] =
        json!(target.strip_suffix("/sentry").unwrap());
    tailscale.lock().unwrap().replace_config(legacy);
    let (exit, configured) = cli_with_target(
        home.path(),
        &target,
        &["--provider", "tailscale", "--funnel-port", "10000"],
    );
    assert_eq!(exit, 0, "{configured}");
    let upgraded = tailscale.lock().unwrap().config.clone();
    assert_eq!(
        upgraded["Web"][format!("{DNS}:10000")]["Handlers"]["/sentry"]["Proxy"],
        target
    );

    // A clean tailscaled returns JSON null before its first Serve configuration.
    tailscale.lock().unwrap().replace_config(Value::Null);
    let (exit, clean) = cli_with_target(home.path(), &target, &[]);
    assert_eq!(exit, 0, "{clean}");
    assert_eq!(clean["data"]["tailscale"]["port"], 8443);
    tailscale_server.abort();
    server.abort();
}

#[test]
fn cloudflare_checks_configured_ingress_and_custom_proxy_keeps_exact_public_path() {
    let home = TempDir::new().unwrap();
    let config = home.path().join("config.yml");
    fs::write(&config, "fixture").unwrap();
    script(
        &home.path().join("cloudflared"),
        r#"#!/bin/sh
test "$1" = tunnel && test "$2" = --config && test "$3" = "$FIXTURE/config.yml" || exit 9
test "$4 $5" = 'ingress rule' || exit 9
case "$6" in
    https://hooks.example.com/sentry)
        echo 'Matched rule #0'
        echo '  service: http://127.0.0.1:8796'
        ;;
    https://other.example.com/sentry)
        echo 'Matched rule #1'
        echo '  service: http://127.0.0.1:8790'
        ;;
    *) exit 9 ;;
esac
"#,
    );
    let mut config_cmd = vec![
        "--provider",
        "cloudflare",
        "--cloudflare-config",
        config.to_str().unwrap(),
        "--url",
        "https://hooks.example.com/sentry",
    ];
    let (exit, result) = cli(home.path(), &config_cmd);
    assert_eq!(exit, 0, "{result}");
    assert_eq!(
        result["data"]["publicUrl"],
        "https://hooks.example.com/sentry"
    );
    assert_eq!(result["data"]["localTarget"], TARGET);
    assert_eq!(result["data"]["status"], "configured");

    *config_cmd.last_mut().unwrap() = "https://other.example.com/sentry";
    let (exit, wrong_receiver) = cli(home.path(), &config_cmd);
    assert_eq!(exit, 1, "{wrong_receiver}");
    assert!(wrong_receiver["data"].is_null());

    let url = "https://hooks.example.com/integrations/ns/sentry-callback";
    let (exit, result) = cli(home.path(), &["--provider", "existing", "--url", url]);
    assert_eq!(exit, 0, "{result}");
    assert_eq!(result["data"]["publicUrl"], url);
    assert_eq!(result["data"]["localTarget"], TARGET);
}

#[tokio::test(flavor = "multi_thread")]
async fn funnel_requires_a_running_node_and_capabilities() {
    let home = TempDir::new().unwrap();
    let (_, server) = fake_tailscale(home.path(), "NeedsLogin", Value::Null).await;
    let (exit, result) = cli(home.path(), &[]);
    assert_eq!(exit, 0, "{result}");
    assert_eq!(result["data"]["tailscale"]["status"], "needsSetup");
    assert!(
        result["data"]["tailscale"]["prerequisite"]
            .as_str()
            .unwrap()
            .contains("sign")
    );
    server.abort();
}
