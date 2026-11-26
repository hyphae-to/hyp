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
        .env("FIXTURE_TARGET", target)
        .env("PATH", home)
        .args(["deploy", "webhook", "--local-target", target, "--json"])
        .args(arguments)
        .output()
        .unwrap();
    (output.status.code().unwrap(), parse_json_stdout(&output))
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
    let state = home.path().join("state.json");
    let private = json!({
        "TCP": {"8443":{"HTTPS":true}},
        "Web": {(format!("{DNS}:8443")):{"Handlers":{"/":{"Proxy":"http://127.0.0.1:8790"}}}}
    });
    fs::write(&state, private.to_string()).unwrap();
    let mut enabled = private.clone();
    enabled["TCP"]["10000"] = json!({"HTTPS": true});
    enabled["Web"][format!("{DNS}:10000")] = json!({"Handlers":{"/sentry":{"Proxy":target}}});
    enabled["AllowFunnel"] = json!({(format!("{DNS}:10000")): true});
    fs::write(home.path().join("enabled.json"), enabled.to_string()).unwrap();
    script(
        &home.path().join("tailscale"),
        r#"#!/bin/sh
case "$1" in
    status)
        echo '{"BackendState":"Running","Self":{"DNSName":"hub.tail123.ts.net.","CapMap":{"https":[],"funnel":[],"https://tailscale.com/cap/funnel-ports?ports=443,8443,10000":[]}}}'
        ;;
    serve)
        test "$2 $3" = 'status --json' || exit 9
        /bin/cat "$FIXTURE/state.json"
        ;;
    funnel)
        echo "$*" >> "$FIXTURE/funnel.log"
        test "$*" = "funnel --bg --https=10000 --set-path=/sentry $FIXTURE_TARGET" || exit 9
        /bin/cat "$FIXTURE/enabled.json" > "$FIXTURE/state.json"
        ;;
    *) exit 9 ;;
esac
"#,
    );

    let (exit, discover) = cli_with_target(home.path(), &target, &[]);
    assert_eq!(exit, 0, "{discover}");
    assert_eq!(discover["data"]["tailscale"]["status"], "available");
    assert_eq!(discover["data"]["tailscale"]["port"], 10000);
    assert!(!home.path().join("funnel.log").exists());

    let (exit, denied) = cli_with_target(
        home.path(),
        &target,
        &["--provider", "tailscale", "--funnel-port", "8443"],
    );
    assert_eq!(exit, 1, "{denied}");
    assert_eq!(denied["error"]["code"], "WEBHOOK_ROUTE_UNAVAILABLE");
    assert!(!home.path().join("funnel.log").exists());

    let (exit, plan) =
        cli_with_target(home.path(), &target, &["--provider", "tailscale", "--plan"]);
    assert_eq!(exit, 0, "{plan}");
    assert_eq!(plan["data"]["status"], "planned");
    assert!(!home.path().join("funnel.log").exists());

    let unrelated = target.replace("/sentry", "/admin");
    let (exit, unrelated) = cli_with_target(home.path(), &unrelated, &["--provider", "tailscale"]);
    assert_eq!(exit, 1, "{unrelated}");
    assert_eq!(unrelated["error"]["code"], "WEBHOOK_ROUTE_UNAVAILABLE");
    assert!(!home.path().join("funnel.log").exists());

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
    assert_eq!(
        fs::read_to_string(home.path().join("funnel.log"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    let after: Value = serde_json::from_str(&fs::read_to_string(state).unwrap()).unwrap();
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
    fs::write(home.path().join("state.json"), legacy.to_string()).unwrap();
    let (exit, configured) = cli_with_target(
        home.path(),
        &target,
        &["--provider", "tailscale", "--funnel-port", "10000"],
    );
    assert_eq!(exit, 0, "{configured}");
    let upgraded: Value =
        serde_json::from_slice(&fs::read(home.path().join("state.json")).unwrap()).unwrap();
    assert_eq!(
        upgraded["Web"][format!("{DNS}:10000")]["Handlers"]["/sentry"]["Proxy"],
        target
    );

    // A clean tailscaled returns JSON null before its first Serve configuration.
    fs::write(home.path().join("state.json"), "null").unwrap();
    let (exit, clean) = cli_with_target(home.path(), &target, &[]);
    assert_eq!(exit, 0, "{clean}");
    assert_eq!(clean["data"]["tailscale"]["port"], 8443);
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

#[test]
fn funnel_requires_a_running_node_and_capabilities() {
    let home = TempDir::new().unwrap();
    script(
        &home.path().join("tailscale"),
        r#"#!/bin/sh
test "$1" = status || exit 9
echo '{"BackendState":"NeedsLogin"}'
"#,
    );
    let (exit, result) = cli(home.path(), &[]);
    assert_eq!(exit, 0, "{result}");
    assert_eq!(result["data"]["tailscale"]["status"], "needsSetup");
    assert!(
        result["data"]["tailscale"]["prerequisite"]
            .as_str()
            .unwrap()
            .contains("sign")
    );
}
