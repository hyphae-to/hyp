//! Host-side routing for dedicated, signed webhook listeners, independent of plugin language.

use crate::deploy::find_in_path;
use crate::ui::{EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json};
use clap::{Args, ValueEnum};
use http_body_util::Empty;
use hyper::{Method, Request, StatusCode, body::Bytes};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

const COMMAND: &str = "deploy webhook";
const FUNNEL_PORTS: [u16; 3] = [8443, 10000, 443];

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Provider {
    Tailscale,
    Cloudflare,
    Existing,
}

#[derive(Args)]
pub(crate) struct WebhookArgs {
    /// Exact URL of a dedicated signed webhook receiver on IPv4 loopback
    #[arg(long)]
    local_target: String,
    /// Discover providers if omitted. Selecting Tailscale activates the reported route.
    #[arg(long, value_enum)]
    provider: Option<Provider>,
    /// Public HTTPS callback URL for an existing proxy or configured Cloudflare Tunnel
    #[arg(long)]
    url: Option<String>,
    /// Existing cloudflared ingress file on this host (defaults to cloudflared's own lookup)
    #[arg(long)]
    cloudflare_config: Option<PathBuf>,
    /// Restrict Tailscale Funnel to a specific HTTPS port
    #[arg(long)]
    funnel_port: Option<u16>,
    /// Report the selected Funnel URL and port without enabling it
    #[arg(long, requires = "provider")]
    plan: bool,
    /// Output structured JSON
    #[arg(long)]
    json: bool,
}

struct Target {
    url: String,
    authority: String,
    path: String,
}

impl Target {
    fn parse(url: String) -> Result<Self, String> {
        let uri = url
            .parse::<hyper::Uri>()
            .map_err(|_| "Invalid local target URL.")?;
        let path = uri.path();
        if uri.scheme_str() != Some("http")
            || uri.host() != Some("127.0.0.1")
            || uri.port_u16().is_none_or(|port| port == 0)
            || uri.query().is_some()
            || path == "/"
            || path.split('/').skip(1).any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || !part.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~')
                    })
            })
            || !url.starts_with("http://127.0.0.1:")
        {
            return Err("Use the exact path of a dedicated signed receiver, for example http://127.0.0.1:8796/sentry.".into());
        }
        Ok(Self {
            authority: uri
                .authority()
                .expect("validated authority")
                .as_str()
                .to_owned(),
            path: path.to_owned(),
            url,
        })
    }
}

fn https_callback(url: &str) -> Result<hyper::Uri, String> {
    let uri = url
        .parse::<hyper::Uri>()
        .map_err(|_| "Invalid public callback URL.")?;
    if url.contains('#')
        || !url.starts_with("https://")
        || uri.scheme_str() != Some("https")
        || uri
            .authority()
            .is_none_or(|host| host.as_str().contains('@'))
    {
        return Err("Provide a public HTTPS callback URL without user credentials.".into());
    }
    Ok(uri)
}

async fn run_tool(bin: &Path, args: &[&str]) -> Result<String, String> {
    let output = tokio::time::timeout(
        Duration::from_secs(12),
        tokio::process::Command::new(bin)
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "Provider command timed out.")?
    .map_err(|e| format!("Could not launch provider tool: {e}"))?;
    if !output.status.success() {
        // Provider diagnostics can include auth URLs or credentials from local config.
        return Err(format!("Provider command failed ({}).", output.status));
    }
    String::from_utf8(output.stdout).map_err(|_| "Provider command returned invalid UTF-8.".into())
}

async fn tailscale_config(bin: &Path) -> Result<Value, String> {
    let out = run_tool(bin, &["serve", "status", "--json"])
        .await
        .map_err(|_| {
            "Run `tailscale serve status --json` as the Tailscale operator on this host."
                .to_string()
        })?;
    let config: Value = serde_json::from_str(&out)
        .map_err(|_| "Use a Tailscale client that reports Serve configuration as JSON.")?;
    if (!config.is_object() && !config.is_null())
        || ["TCP", "Web", "AllowFunnel", "Foreground"]
            .into_iter()
            .any(|key| {
                let value = &config[key];
                !value.is_object() && !value.is_null()
            })
    {
        return Err("Use a Tailscale client that reports Serve configuration as JSON.".into());
    }
    Ok(config)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Empty,
    Reuse,
    Legacy,
    Occupied,
}

fn slot(config: &Value, dns: &str, port: u16, target: &Target) -> Slot {
    let port_key = port.to_string();
    let endpoint = format!("{dns}:{port}");
    let ports = |key: &str| {
        config[key].as_object().is_some_and(|entries| {
            entries.keys().any(|name| {
                name.rsplit_once(':')
                    .is_some_and(|(_, entry_port)| entry_port == port_key)
            })
        })
    };
    // A private Serve handler on the same HTTPS port would also become public.
    // Reject any other TCP, Web or foreground config on a candidate port.
    if config["Foreground"].as_object().is_some_and(|sessions| {
        sessions
            .values()
            .any(|session| slot(session, dns, port, target) != Slot::Empty)
    }) {
        return Slot::Occupied;
    }
    if !ports("Web") && !ports("AllowFunnel") && config["TCP"][&port_key].is_null() {
        return Slot::Empty;
    }
    let only_route_at_endpoint = ["Web", "AllowFunnel"].into_iter().all(|key| {
        config[key].as_object().is_some_and(|entries| {
            entries
                .keys()
                .filter(|name| {
                    name.rsplit_once(':')
                        .is_some_and(|(_, entry_port)| entry_port == port_key)
                })
                .all(|name| name == &endpoint)
        })
    });
    if !only_route_at_endpoint
        || config["TCP"][&port_key]["HTTPS"].as_bool() != Some(true)
        || config["AllowFunnel"][&endpoint].as_bool() != Some(true)
    {
        return Slot::Occupied;
    }
    let handler = config["Web"][&endpoint]["Handlers"]
        .as_object()
        .filter(|handlers| handlers.len() == 1)
        .and_then(|handlers| handlers.get(&target.path));
    match handler.and_then(|handler| handler["Proxy"].as_str()) {
        Some(proxy) if proxy == target.url => Slot::Reuse,
        // The old SDK mounted this same path but forwarded it to the listener's root.
        Some(proxy) if proxy.trim_end_matches('/') == format!("http://{}", target.authority) => {
            Slot::Legacy
        }
        _ => Slot::Occupied,
    }
}

struct Funnel {
    bin: PathBuf,
    dns: String,
    port: u16,
    previous: Slot,
}

impl Funnel {
    fn public_url(&self, path: &str) -> String {
        let suffix = if self.port == 443 {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        format!("https://{}{suffix}{path}", self.dns)
    }
}

async fn discover_funnel(target: &Target, preferred_port: Option<u16>) -> Result<Funnel, String> {
    let bin = std::env::var_os("TAILSCALE_BIN")
        .map(PathBuf::from)
        .or_else(|| find_in_path("tailscale"))
        .ok_or("Install Tailscale on the webhook host.")?;
    let status = run_tool(&bin, &["status", "--json"])
        .await
        .map_err(|_| "Start Tailscale and sign the webhook host into its tailnet.".to_string())?;
    let status: Value = serde_json::from_str(&status)
        .map_err(|_| "Update the Tailscale client on the webhook host.")?;
    if status["BackendState"] != "Running" {
        return Err("Start Tailscale and sign the webhook host into its tailnet.".into());
    }
    let dns = status["Self"]["DNSName"]
        .as_str()
        .unwrap_or("")
        .trim_end_matches('.');
    if dns.is_empty()
        || !dns.ends_with(".ts.net")
        || !dns
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err("Enable MagicDNS for the webhook host's tailnet.".into());
    }
    let caps = status["Self"]["CapMap"].as_object();
    let legacy = status["Self"]["Capabilities"].as_array();
    let capabilities: Vec<&str> = caps
        .into_iter()
        .flat_map(|m| m.keys().map(String::as_str))
        .chain(legacy.into_iter().flatten().filter_map(Value::as_str))
        .collect();
    if !capabilities.contains(&"https") {
        return Err("Enable HTTPS certificates for the tailnet in Tailscale DNS settings.".into());
    }
    if !capabilities.contains(&"funnel") {
        return Err(
            "Grant the webhook host the `funnel` node attribute in the tailnet policy.".into(),
        );
    }
    let allowed = capabilities
        .iter()
        .find_map(|cap| cap.strip_prefix("https://tailscale.com/cap/funnel-ports?ports="))
        .ok_or("Allow a Funnel HTTPS port for this node in the tailnet policy.")?;
    let ports: Vec<u16> = FUNNEL_PORTS
        .into_iter()
        .filter(|port| {
            preferred_port.is_none_or(|preferred| *port == preferred)
                && allowed.split(',').any(|allowed| {
                    if let Some((lo, hi)) = allowed.split_once('-') {
                        lo.parse::<u16>()
                            .ok()
                            .zip(hi.parse::<u16>().ok())
                            .is_some_and(|(lo, hi)| (lo..=hi).contains(port))
                    } else {
                        allowed.parse::<u16>().ok() == Some(*port)
                    }
                })
        })
        .collect();
    if ports.is_empty() {
        return Err(
            "Allow an eligible Funnel HTTPS port for this node in the tailnet policy.".into(),
        );
    }
    let config = tailscale_config(&bin).await?;
    let (port, previous) = ports
        .iter()
        .copied()
        .map(|port| (port, slot(&config, dns, port, target)))
        .find(|(_, slot)| matches!(slot, Slot::Reuse | Slot::Legacy))
        .or_else(|| {
            ports
                .into_iter()
                .find(|port| slot(&config, dns, *port, target) == Slot::Empty)
                .map(|port| (port, Slot::Empty))
        })
        .ok_or("Free a dedicated Funnel HTTPS port or choose another public callback provider.")?;
    Ok(Funnel {
        bin,
        dns: dns.to_owned(),
        port,
        previous,
    })
}

async fn check_receiver(target: &Target) -> Result<(), String> {
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri(&target.url)
        .body(Empty::<Bytes>::new())
        .expect("validated webhook target");
    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let response = tokio::time::timeout(Duration::from_secs(3), client.request(request))
        .await
        .ok()
        .and_then(Result::ok);
    if !response.is_some_and(|response| {
        response.status() == StatusCode::NO_CONTENT
            && response
                .headers()
                .get("x-hyphae-webhook-receiver")
                .is_some_and(|value| value == "signed")
    }) {
        return Err("Start the dedicated signed webhook receiver at the local target before enabling Funnel.".into());
    }
    Ok(())
}

async fn configure_funnel(funnel: &Funnel, target: &Target) -> Result<bool, String> {
    check_receiver(target).await?;
    let config = tailscale_config(&funnel.bin).await?;
    match slot(&config, &funnel.dns, funnel.port, target) {
        Slot::Reuse => return Ok(true),
        previous
            if previous == funnel.previous && matches!(previous, Slot::Empty | Slot::Legacy) => {}
        _ => {
            return Err(
                "Tailscale routing changed. Rerun discovery to select an unused port.".into(),
            );
        }
    }
    run_tool(
        &funnel.bin,
        &[
            "funnel",
            "--bg",
            &format!("--https={}", funnel.port),
            &format!("--set-path={}", target.path),
            &target.url,
        ],
    )
    .await
    .map_err(|_| {
        "Run as the Tailscale operator authorized to configure Funnel on this host.".to_string()
    })?;
    let config = tailscale_config(&funnel.bin).await?;
    if slot(&config, &funnel.dns, funnel.port, target) != Slot::Reuse {
        return Err("Inspect `tailscale serve status --json`; the expected isolated Funnel route was not verified.".into());
    }
    Ok(false)
}

async fn check_cloudflare(
    target: &Target,
    url: Option<&str>,
    config: Option<&Path>,
) -> Result<(), String> {
    let bin = find_in_path("cloudflared").ok_or("Install cloudflared on the webhook host.")?;
    let url =
        url.ok_or("Provide the callback URL of the existing Cloudflare Tunnel with --url.")?;
    let uri = https_callback(url)?;
    if uri.path() != target.path {
        return Err(
            "Use the same path for the configured Cloudflare callback and the loopback receiver."
                .into(),
        );
    }
    let mut arguments = vec!["tunnel"];
    if let Some(config) = config {
        let config = config
            .to_str()
            .ok_or("Use a UTF-8 path for the Cloudflare ingress config.")?;
        arguments.extend(["--config", config]);
    }
    arguments.extend(["ingress", "rule", url]);
    let output = run_tool(&bin, &arguments).await.map_err(|_| "Validate the local Cloudflare ingress file with `cloudflared tunnel ingress rule <callback-url>`.".to_string())?;
    let service = output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("service: ")
            .or_else(|| line.trim().strip_prefix("Service: "))
    });
    if service.map(|service| service.trim_end_matches('/'))
        != Some(format!("http://{}", target.authority).as_str())
    {
        return Err(format!(
            "Configure a Cloudflare ingress rule for this callback path forwarding to http://{}.",
            target.authority
        ));
    }
    Ok(())
}

pub(crate) fn run(args: WebhookArgs) -> ExitCode {
    let target = match Target::parse(args.local_target) {
        Ok(target) => target,
        Err(err) => return emit_error(COMMAND, args.json, EXIT_USAGE, "INVALID_TARGET", err, None),
    };
    if args
        .funnel_port
        .is_some_and(|port| !FUNNEL_PORTS.contains(&port))
    {
        return emit_error(
            COMMAND,
            args.json,
            EXIT_USAGE,
            "INVALID_FUNNEL_PORT",
            "Use Funnel HTTPS port 8443, 10000, or 443.",
            None,
        );
    }
    if let Some(ref url) = args.url {
        if let Err(err) = https_callback(url) {
            return emit_error(
                COMMAND,
                args.json,
                EXIT_USAGE,
                "INVALID_CALLBACK_URL",
                err,
                None,
            );
        }
    }
    if args.plan && !matches!(args.provider, Some(Provider::Tailscale)) {
        return emit_error(
            COMMAND,
            args.json,
            EXIT_USAGE,
            "INVALID_PLAN_PROVIDER",
            "--plan applies to Tailscale Funnel.",
            None,
        );
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            return emit_error(
                COMMAND,
                args.json,
                EXIT_ERROR,
                "RUNTIME_ERROR",
                err.to_string(),
                None,
            );
        }
    };
    let result = runtime.block_on(async {
        let url = args.url.as_deref();
        let config = args.cloudflare_config.as_deref();
        let data = match args.provider {
            None => {
                let (tailscale, cloudflare, receiver) = tokio::join!(
                    discover_funnel(&target, args.funnel_port),
                    check_cloudflare(&target, url, config),
                    check_receiver(&target)
                );
                let tailscale = match tailscale {
                    Ok(funnel) => json!({"status": if funnel.previous == Slot::Reuse { "configured" } else { "available" },
                        "publicUrl": funnel.public_url(&target.path), "port": funnel.port}),
                    Err(prerequisite) => json!({"status":"needsSetup", "prerequisite":prerequisite}),
                };
                let cloudflare = match cloudflare {
                    Ok(()) => json!({"status":"configured", "publicUrl":url}),
                    Err(prerequisite) => json!({"status":"needsSetup", "prerequisite":prerequisite}),
                };
                let receiver = match receiver {
                    Ok(()) => json!({"status":"running"}),
                    Err(prerequisite) => json!({"status":"needsSetup", "prerequisite":prerequisite}),
                };
                json!({"localTarget":target.url,"receiver":receiver,
                    "tailscale":tailscale,"cloudflare":cloudflare,"existing":{"status":"available"}})
            }
            Some(Provider::Tailscale) => {
                let funnel = discover_funnel(&target, args.funnel_port).await?;
                let (status, reused) = if args.plan { ("planned", funnel.previous == Slot::Reuse) }
                    else { ("configured", configure_funnel(&funnel, &target).await?) };
                json!({"provider":"tailscale","localTarget":target.url,"publicUrl":funnel.public_url(&target.path),
                    "port":funnel.port, "status":status, "reused":reused})
            }
            Some(Provider::Cloudflare) => {
                check_cloudflare(&target, url, config).await?;
                json!({"provider":"cloudflare","localTarget":target.url,"publicUrl":url,"status":"configured"})
            }
            Some(Provider::Existing) => {
                let url = url.ok_or("Pass the operator-supplied HTTPS callback URL with --url.")?;
                json!({"provider":"existing","localTarget":target.url,"publicUrl":url,"status":"operatorManaged"})
            }
        };
        Ok::<Value,String>(data)
    });
    let data = match result {
        Ok(data) => data,
        Err(err) => {
            return emit_error(
                COMMAND,
                args.json,
                EXIT_ERROR,
                "WEBHOOK_ROUTE_UNAVAILABLE",
                err,
                None,
            );
        }
    };
    let next = args.provider.map(|_| vec!["Send a signed test delivery from the event provider after the receiver is running.".to_string()]).unwrap_or_default();
    if args.json {
        print_json(&JsonEnvelope {
            ok: true,
            command: COMMAND.into(),
            summary: None,
            data: Some(data),
            warnings: Vec::new(),
            next,
            error: None,
        });
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).expect("JSON result")
        );
        for step in next {
            println!("{step}");
        }
    }
    ExitCode::from(EXIT_OK)
}
