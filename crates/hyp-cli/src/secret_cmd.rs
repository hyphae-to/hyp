//! `hyp secret` — Zero-leak secret management backed by `hyp-crypto::keystore::SecretStore`.
//!
//! Security invariants:
//! - Secrets are NEVER accepted via CLI argv flags (no `--value` flag!).
//! - `secret set <name>` reads strictly from stdin OR `--web` (a one-shot `127.0.0.1:0`
//!   localhost HTML form protected by a random URL path token AND a constant-time verified
//!   CSRF nonce that writes directly into `SecretStore` and shuts down immediately).
//! - Secret values are NEVER printed to stdout, stderr, or `--json` output.

use crate::config_file::{
    ct_eq, open_secret_store, resolve_config_path_for_read, resolve_state_dir,
};
use crate::ui::{CliError, EXIT_OK, JsonEnvelope, print_json, print_next_steps, print_warnings};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Subcommand;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyp_crypto::keystore::{SecretMetadata, SecretStore, validate_secret_name};
use hyp_node::node_file::NodeFile;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::{Value, json};
use std::convert::Infallible;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const MAX_SECRET_INPUT_BYTES: u64 = 64 * 1024;
const DEFAULT_WEB_TIMEOUT_SECS: u64 = 300;

#[derive(Subcommand)]
pub enum SecretCommand {
    /// Save a secret into OS Keychain / Secret Service / 1Password / LastPass / pass / 0600 file store (reads stdin or --web, NEVER argv!)
    Set {
        /// Secret name matching /^[a-z0-9][a-z0-9._-]{0,63}$/
        #[arg(value_name = "NAME")]
        name_pos: Option<String>,
        /// Secret name (flag form)
        #[arg(long = "name")]
        name_flag: Option<String>,
        /// Start an ephemeral one-shot 127.0.0.1 HTML form with CSRF nonce (zero bytes enter LLM context!)
        #[arg(long)]
        web: bool,
        /// Optional loopback port override for --web (0 = ephemeral OS port)
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Timeout in seconds for --web submission (default: 300)
        #[arg(long, default_value_t = DEFAULT_WEB_TIMEOUT_SECS)]
        timeout: u64,
        /// Do not attempt to auto-open a local browser window for --web
        #[arg(long)]
        no_open: bool,
        /// Explicit state directory for SecretStore
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope (never includes secret values)
        #[arg(long)]
        json: bool,
    },
    /// List stored secret metadata (never reads or prints secret values)
    List {
        /// Explicit state directory for SecretStore
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Delete a stored secret
    Delete {
        /// Secret name to delete
        #[arg(value_name = "NAME")]
        name_pos: Option<String>,
        /// Secret name (flag form)
        #[arg(long = "name")]
        name_flag: Option<String>,
        /// Explicit state directory for SecretStore
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretListItem {
    name: String,
    backend: String,
    location: String,
    mode_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
}

impl From<SecretMetadata> for SecretListItem {
    fn from(m: SecretMetadata) -> Self {
        Self {
            name: m.name,
            backend: m.backend.as_str().to_string(),
            location: m.location,
            mode_ok: m.mode_ok,
            bytes: m.bytes,
        }
    }
}

pub fn run_secret(command: SecretCommand) -> crate::ui::CommandResult {
    match command {
        SecretCommand::Set {
            name_pos,
            name_flag,
            web,
            port,
            timeout,
            no_open,
            state_dir,
            json,
        } => crate::ui::CommandResult::new(
            "secret set",
            json,
            run_secret_set(
                name_flag.or(name_pos),
                web,
                port,
                timeout,
                no_open,
                state_dir,
                json,
            ),
        ),
        SecretCommand::List { state_dir, json } => {
            crate::ui::CommandResult::new("secret list", json, run_secret_list(state_dir, json))
        }
        SecretCommand::Delete {
            name_pos,
            name_flag,
            state_dir,
            json,
        } => crate::ui::CommandResult::new(
            "secret delete",
            json,
            run_secret_delete(name_flag.or(name_pos), state_dir, json),
        ),
    }
}

fn resolve_store(state_dir: Option<&PathBuf>) -> (PathBuf, SecretStore) {
    let dir = resolve_state_dir(state_dir.map(PathBuf::as_path), None, None);
    let store = open_secret_store(&dir, state_dir.is_some());
    (dir, store)
}

fn collect_secret_refs_recursive(val: &Value, prefix: &str, target: &str, out: &mut Vec<String>) {
    match val {
        Value::Object(map) => {
            if map.len() == 1 && map.get("secret").and_then(Value::as_str) == Some(target) {
                out.push(prefix.to_string());
                return;
            }
            for (k, v) in map {
                collect_secret_refs_recursive(v, &format!("{prefix}.{k}"), target, out);
            }
        }
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                let label = item
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| idx.to_string());
                collect_secret_refs_recursive(item, &format!("{prefix}[{label}]"), target, out);
            }
        }
        _ => {}
    }
}

/// Best-effort inspection of `node.json` for `{ "secret": "<name>" }` references inside
/// `plugins[]`, `sources[]`, or `pairing.adminKey`. Never fails secret operations if `node.json`
/// is missing or unreadable.
fn find_secret_references_in_node_json(
    state_dir: &Path,
    explicit_state: bool,
    secret_name: &str,
) -> Vec<String> {
    let cfg_path = resolve_config_path_for_read(
        None,
        if explicit_state {
            Some(state_dir)
        } else {
            None
        },
        None,
    );
    let Ok(root) = NodeFile::read_document(&cfg_path) else {
        return Vec::new();
    };
    let mut refs = Vec::new();
    if let Some(plugins) = root.get("plugins") {
        collect_secret_refs_recursive(plugins, "plugins", secret_name, &mut refs);
    }
    if let Some(sources) = root.get("sources") {
        collect_secret_refs_recursive(sources, "sources", secret_name, &mut refs);
    }
    if let Some(admin_key) = root.get("pairing").and_then(|p| p.get("adminKey")) {
        collect_secret_refs_recursive(admin_key, "pairing.adminKey", secret_name, &mut refs);
    }
    refs
}

fn run_secret_set(
    name: Option<String>,
    web: bool,
    port: u16,
    timeout_secs: u64,
    no_open: bool,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "secret set";
    let Some(name) = name else {
        return Err(CliError::usage(
            "MISSING_NAME",
            "Missing secret name (pass `<name>` or `--name <name>`)",
        )
        .with_fix(
            "Example: printf '%s' \"$API_KEY\" | hyp secret set anthropic-api-key".to_string(),
        ));
    };

    validate_secret_name(&name).map_err(|e| {
        CliError::usage(
            "INVALID_SECRET_NAME",
            format!("Invalid secret name '{name}': {e}"),
        )
        .with_fix("Use lowercase [a-z0-9._-] starting with [a-z0-9] (max 64 chars).".to_string())
    })?;

    let (dir, store) = resolve_store(state_dir.as_ref());

    if web {
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
        return match rt.block_on(capture_secret_via_web(
            &name,
            &store,
            port,
            timeout_secs,
            no_open,
        )) {
            Ok(saved) => {
                let referenced_by =
                    find_secret_references_in_node_json(&dir, state_dir.is_some(), &name);
                let mut warnings = Vec::new();
                let mut next = Vec::new();
                if !referenced_by.is_empty() {
                    warnings.push(format!(
                        "Secret '{name}' is referenced in node.json ({}); restart running plugins/sources so the updated value takes effect.",
                        referenced_by.join(", ")
                    ));
                    next.push("hyp service restart --json".to_string());
                } else {
                    next.push(format!(
                        "Reference in node.json as {{ \"secret\": \"{name}\" }} (never plaintext!)."
                    ));
                }
                if as_json {
                    let envelope = JsonEnvelope::ok(
                        cmd.to_string(),
                        format!(
                            "Saved secret '{name}' via one-shot localhost form into {}",
                            saved.backend
                        ),
                        json!({
                            "name": name,
                            "backend": saved.backend,
                            "location": saved.location,
                            "captureMode": "web",
                            "stateDir": dir.display().to_string(),
                            "referencedBy": referenced_by,
                        }),
                    )
                    .warnings(warnings)
                    .next(next);
                    print_json(&envelope);
                } else {
                    println!(
                        "OK    Saved secret '{name}' via localhost web capture ({})",
                        saved.backend
                    );
                    println!("      Location: {}", saved.location);
                    print_warnings(&warnings);
                    print_next_steps(&next);
                }
                Ok(ExitCode::from(EXIT_OK))
            }
            Err(e) => Err(CliError::error("WEB_CAPTURE_FAILED", e)),
        };
    }

    // Stdin mode: bounded read, never accepts argv values!
    let mut raw = String::new();
    let read_res = io::stdin()
        .lock()
        .take(MAX_SECRET_INPUT_BYTES + 1)
        .read_to_string(&mut raw);
    read_res.map_err(|e| {
        CliError::error(
            "STDIN_ERROR",
            format!("Failed to read secret from stdin: {e}"),
        )
    })?;
    if raw.len() as u64 > MAX_SECRET_INPUT_BYTES {
        return Err(CliError::error(
            "SECRET_TOO_LARGE",
            format!("Secret input exceeds {MAX_SECRET_INPUT_BYTES} byte safety cap"),
        ));
    }
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err(CliError::error("EMPTY_SECRET", format!("No secret value received on stdin for '{name}'")).with_fix(format!(
                "Pipe secret over stdin (`hyp secret set {name} <<< \"$SECRET\"`) or run `hyp secret set {name} --web`."
            )));
    }

    match store.set(&name, &trimmed) {
        Ok(saved) => {
            let referenced_by =
                find_secret_references_in_node_json(&dir, state_dir.is_some(), &name);
            let mut warnings = Vec::new();
            let mut next = Vec::new();
            if !referenced_by.is_empty() {
                warnings.push(format!(
                    "Secret '{name}' is referenced in node.json ({}); restart running plugins/sources so the updated value takes effect.",
                    referenced_by.join(", ")
                ));
                next.push("hyp service restart --json".to_string());
            } else {
                next.push(format!(
                    "Reference in node.json as {{ \"secret\": \"{name}\" }} (never plaintext!)."
                ));
            }
            if as_json {
                let envelope = JsonEnvelope::ok(
                    cmd.to_string(),
                    format!("Saved secret '{name}' into {}", saved.backend.as_str()),
                    json!({
                        "name": saved.name,
                        "backend": saved.backend.as_str(),
                        "location": saved.location,
                        "captureMode": "stdin",
                        "stateDir": dir.display().to_string(),
                        "referencedBy": referenced_by,
                    }),
                )
                .warnings(warnings)
                .next(next);
                print_json(&envelope);
            } else {
                println!(
                    "OK    Saved secret '{}' ({})",
                    saved.name,
                    saved.backend.as_str()
                );
                println!("      Location: {}", saved.location);
                print_warnings(&warnings);
                print_next_steps(&next);
            }
            Ok(ExitCode::from(EXIT_OK))
        }
        Err(e) => Err(CliError::error(
            "SECRET_STORE_ERROR",
            format!("Failed to store secret '{name}': {e}"),
        )),
    }
}

fn run_secret_list(state_dir: Option<PathBuf>, as_json: bool) -> Result<ExitCode, CliError> {
    let cmd = "secret list";
    let (dir, store) = resolve_store(state_dir.as_ref());
    let items: Vec<SecretListItem> = match store.list() {
        Ok(list) => list.into_iter().map(SecretListItem::from).collect(),
        Err(e) => {
            return Err(CliError::error(
                "SECRET_STORE_ERROR",
                format!("Failed to list secrets: {e}"),
            ));
        }
    };

    let warnings: Vec<String> = items
        .iter()
        .filter(|i| !i.mode_ok)
        .map(|i| {
            format!(
                "Secret '{}' at {} has overly broad permissions (expected 0600).",
                i.name, i.location
            )
        })
        .collect();

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "{} secret(s) stored in {} ({})",
                items.len(),
                store.backend().as_str(),
                dir.display()
            ),
            json!({
                "backend": store.backend().as_str(),
                "stateDir": dir.display().to_string(),
                "secrets": items,
            }),
        )
        .warnings(warnings)
        .next(if items.is_empty() {
            vec!["hyp secret set <name> --web".to_string()]
        } else {
            Vec::new()
        });
        print_json(&envelope);
    } else {
        println!(
            "Hyphae Secrets (backend: {}, count: {})",
            store.backend().as_str(),
            items.len()
        );
        if items.is_empty() {
            println!("  (none)");
        } else {
            println!();
            println!("{:<4}  {:<28}  {:<14}  Location", "Stat", "Name", "Backend");
            println!("{}", "-".repeat(78));
            for item in &items {
                let tag = if item.mode_ok { "OK" } else { "WARN" };
                println!(
                    "{:<4}  {:<28}  {:<14}  {}",
                    tag, item.name, item.backend, item.location
                );
            }
        }
    }
    Ok(ExitCode::from(EXIT_OK))
}

fn run_secret_delete(
    name: Option<String>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "secret delete";
    let Some(name) = name else {
        return Err(CliError::usage(
            "MISSING_NAME",
            "Missing secret name (pass `<name>` or `--name <name>`)",
        ));
    };
    validate_secret_name(&name).map_err(|e| {
        CliError::usage(
            "INVALID_SECRET_NAME",
            format!("Invalid secret name '{name}': {e}"),
        )
    })?;

    let (dir, store) = resolve_store(state_dir.as_ref());
    match store.delete(&name) {
        Ok(true) => {
            let referenced_by =
                find_secret_references_in_node_json(&dir, state_dir.is_some(), &name);
            let mut warnings = Vec::new();
            let mut next = Vec::new();
            if !referenced_by.is_empty() {
                warnings.push(format!(
                    "Deleted secret '{name}' is still referenced in node.json ({}); update or remove those references and restart the service.",
                    referenced_by.join(", ")
                ));
                next.push("hyp service restart --json".to_string());
            }
            if as_json {
                let envelope = JsonEnvelope::ok(
                    cmd.to_string(),
                    format!("Deleted secret '{name}'"),
                    json!({
                        "name": name,
                        "deleted": true,
                        "backend": store.backend().as_str(),
                        "stateDir": dir.display().to_string(),
                        "referencedBy": referenced_by,
                    }),
                )
                .warnings(warnings)
                .next(next);
                print_json(&envelope);
            } else {
                println!("OK    Deleted secret '{name}'");
                print_warnings(&warnings);
                print_next_steps(&next);
            }
            Ok(ExitCode::from(EXIT_OK))
        }
        Ok(false) => Err(CliError::error(
            "SECRET_NOT_FOUND",
            format!("Secret '{name}' was not found"),
        )
        .with_fix("Run `hyp secret list` to inspect stored secrets.".to_string())),
        Err(e) => Err(CliError::error(
            "SECRET_STORE_ERROR",
            format!("Failed to delete secret '{name}': {e}"),
        )),
    }
}

// ============================================================================
// One-Shot Out-Of-Band Localhost Web Capture (`secret set <name> --web`)
// ============================================================================

struct WebSaved {
    backend: String,
    location: String,
}

fn random_b64url(len: usize) -> Result<String, String> {
    let rng = SystemRandom::new();
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf)
        .map_err(|_| "OS CSPRNG failure".to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn percent_decode_form(input: &str) -> String {
    hyp_node::engine::http_util::percent_decode_form(input)
}

fn parse_form_urlencoded(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode_form(k), percent_decode_form(v)),
            None => (percent_decode_form(pair), String::new()),
        })
        .collect()
}

fn html_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONNECTION, "close")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .header(header::REFERRER_POLICY, "no-referrer")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(Bytes::from(body)))
        .expect("valid HTML response")
}

fn friendly_backend_label(raw: &str) -> String {
    match raw {
        "keychain" => "macOS Keychain".to_string(),
        "secret-service" => "Linux Secret Service".to_string(),
        "1password" => "1Password CLI (op)".to_string(),
        "lastpass" => "LastPass CLI (lpass)".to_string(),
        "pass" => "Linux pass (password-store)".to_string(),
        "file" => "0600 Private Secret File".to_string(),
        other => escape_html(other),
    }
}

const WEB_CAPTURE_CSS: &str = r#"
:root {
  --bg: #0b0f0c;
  --surface: #121814;
  --surface-2: #18211b;
  --border: rgba(232, 236, 224, 0.11);
  --border-strong: rgba(229, 185, 92, 0.36);
  --text: #eef2e6;
  --muted: #98a89a;
  --gold: #e5b95c;
  --gold-hover: #efc874;
  --sage: #86d39a;
  --sage-bg: rgba(134, 211, 154, 0.1);
  --sage-border: rgba(134, 211, 154, 0.3);
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  min-height: 100%;
  background: radial-gradient(900px 520px at 50% -120px, rgba(134, 211, 154, 0.08), transparent 60%),
              radial-gradient(640px 420px at 90% 100%, rgba(229, 185, 92, 0.06), transparent 65%),
              var(--bg);
  color: var(--text);
  font-family: var(--sans);
  -webkit-font-smoothing: antialiased;
}
body {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 24px 16px;
}
.shell {
  width: 100%;
  max-width: 480px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
  padding: 0 4px;
}
.brand {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  color: var(--text);
  text-decoration: none;
}
.brand-mark {
  width: 30px;
  height: 30px;
  border-radius: 9px;
  display: grid;
  place-items: center;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--gold);
}
.brand-name {
  font-weight: 600;
  font-size: 0.98rem;
  letter-spacing: -0.01em;
}
.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: var(--mono);
  font-size: 0.72rem;
  color: var(--gold);
  background: rgba(229, 185, 92, 0.08);
  border: 1px solid rgba(229, 185, 92, 0.25);
  border-radius: 999px;
  padding: 5px 10px;
  white-space: nowrap;
}
.pill-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--gold);
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
}
.eyebrow {
  margin: 0 0 6px;
  font-family: var(--mono);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--gold);
}
h1 {
  margin: 0 0 8px;
  font-size: 1.4rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  line-height: 1.25;
}
.lead {
  margin: 0 0 20px;
  color: var(--muted);
  font-size: 0.92rem;
  line-height: 1.5;
}
.meta-strip {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 12px;
  align-items: center;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 12px 14px;
  margin-bottom: 20px;
}
.meta-label {
  display: block;
  font-family: var(--mono);
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  margin-bottom: 3px;
}
.meta-name {
  font-family: var(--mono);
  font-size: 0.96rem;
  font-weight: 600;
  color: var(--gold);
  word-break: break-all;
}
.backend-chip {
  font-family: var(--mono);
  font-size: 0.72rem;
  color: var(--sage);
  background: var(--sage-bg);
  border: 1px solid var(--sage-border);
  border-radius: 999px;
  padding: 4px 10px;
  white-space: nowrap;
}
.field-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}
label {
  font-size: 0.84rem;
  font-weight: 500;
  color: var(--text);
}
.hint {
  font-family: var(--mono);
  font-size: 0.74rem;
  color: var(--muted);
}
.input-row {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
}
input[type="password"], input[type="text"] {
  flex: 1;
  min-width: 0;
  background: #0c110e;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 14px;
  font-family: var(--mono);
  font-size: 0.92rem;
  outline: none;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}
input[type="password"]:focus, input[type="text"]:focus {
  border-color: var(--border-strong);
  box-shadow: 0 0 0 3px rgba(229, 185, 92, 0.14);
}
input.secret-masked {
  -webkit-text-security: disc;
}
.btn-toggle {
  background: var(--surface-2);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 0 14px;
  font-size: 0.82rem;
  font-weight: 500;
  cursor: pointer;
  white-space: nowrap;
}
.btn-toggle:hover { border-color: var(--border-strong); }
.btn-primary {
  width: 100%;
  background: var(--gold);
  color: #111510;
  border: none;
  border-radius: 11px;
  padding: 13px 16px;
  font-size: 0.95rem;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.15s ease, transform 0.05s ease;
}
.btn-primary:hover { background: var(--gold-hover); }
.btn-primary:active { transform: translateY(1px); }
.done-banner {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  background: var(--sage-bg);
  border: 1px solid var(--sage-border);
  border-radius: 12px;
  padding: 14px 16px;
  margin-bottom: 18px;
}
.done-icon {
  flex: 0 0 auto;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: rgba(134, 211, 154, 0.2);
  color: var(--sage);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-top: 1px;
}
.done-icon svg {
  display: block;
}
.done-banner strong {
  display: block;
  color: var(--sage);
  font-size: 0.88rem;
  margin-bottom: 3px;
}
.done-banner > div span {
  display: block;
  color: var(--text);
  font-size: 0.86rem;
  line-height: 1.45;
}
.code-ref {
  font-family: var(--mono);
  font-size: 0.8rem;
  color: var(--muted);
  background: #0c110e;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 10px 12px;
  word-break: break-all;
}
.footer {
  margin-top: 14px;
  text-align: center;
  font-size: 0.74rem;
  color: var(--muted);
  line-height: 1.5;
}
"#;

const HYPHAE_BRAND_SVG: &str = r#"<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="3" fill="currentColor" stroke="none"/><path d="M12 3v6M12 15v6M3 12h6M15 12h6M5.6 5.6l4.2 4.2M14.2 14.2l4.2 4.2M18.4 5.6l-4.2 4.2M9.8 14.2l-4.2 4.2"/></svg>"#;

fn render_web_capture_form_html(
    safe_name: &str,
    backend_raw: &str,
    expected_path: &str,
    csrf_nonce: &str,
) -> String {
    let backend_pretty = friendly_backend_label(backend_raw);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>Hyphae · Save secret {safe_name}</title>
  <style>{WEB_CAPTURE_CSS}</style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">{HYPHAE_BRAND_SVG}</span>
        <span class="brand-name">hyphae</span>
      </div>
      <span class="pill"><span class="pill-dot" aria-hidden="true"></span>127.0.0.1 · One-Shot</span>
    </header>
    <section class="card">
      <p class="eyebrow">Out-of-Band Secret Capture</p>
      <h1>Save secret locally</h1>
      <p class="lead">Captured directly into your OS keystore over loopback. Never enters LLM context, chat logs, or shell history.</p>
      <div class="meta-strip">
        <div>
          <span class="meta-label">Secret Name</span>
          <span class="meta-name">{safe_name}</span>
        </div>
        <span class="backend-chip">{backend_pretty}</span>
      </div>
      <form method="POST" action="{expected_path}" autocomplete="off" data-1p-ignore="true" data-lpignore="true" data-bwignore="true" data-protonpass-ignore="true" data-form-type="other">
        <input type="hidden" name="csrf" value="{csrf_nonce}" />
        <div class="field-head">
          <label for="secretValue">Secret Value</label>
          <span id="lenHint" class="hint">0 chars</span>
        </div>
        <div class="input-row">
          <input id="secretValue" class="secret-masked" type="text" name="value" autocomplete="off" aria-autocomplete="none" autocorrect="off" autocapitalize="off" spellcheck="false" data-1p-ignore="true" data-lpignore="true" data-bwignore="true" data-protonpass-ignore="true" data-form-type="other" placeholder="Paste secret value…" autofocus required />
          <button id="toggleBtn" class="btn-toggle" type="button">Show</button>
        </div>
        <button id="submitBtn" class="btn-primary" type="submit">Save Secret &amp; Finish</button>
      </form>
    </section>
    <p class="footer">Server exits immediately after saving · Zero network egress · CSRF protected</p>
  </main>
  <script>
    (function () {{
      var input = document.getElementById("secretValue");
      var toggle = document.getElementById("toggleBtn");
      var hint = document.getElementById("lenHint");
      var btn = document.getElementById("submitBtn");
      var supportsCssMask = typeof CSS !== "undefined" && CSS.supports && CSS.supports("-webkit-text-security", "disc");
      var masked = true;
      function syncMask() {{
        if (supportsCssMask) {{
          input.type = "text";
          input.classList.toggle("secret-masked", masked);
        }} else {{
          input.classList.remove("secret-masked");
          input.type = masked ? "password" : "text";
        }}
        toggle.textContent = masked ? "Show" : "Hide";
      }}
      syncMask();
      function updateLen() {{
        var n = input.value.trim().length;
        hint.textContent = n === 1 ? "1 char" : n + " chars";
      }}
      input.addEventListener("input", updateLen);
      toggle.addEventListener("click", function () {{
        masked = !masked;
        syncMask();
        input.focus();
      }});
      input.form.addEventListener("submit", function () {{
        btn.disabled = true;
        btn.textContent = "Saving…";
      }});
    }})();
  </script>
</body>
</html>"#
    )
}

const HYPHAE_CHECK_SVG: &str = r#"<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>"#;

fn render_web_capture_saved_html(safe_name: &str, backend_raw: &str) -> String {
    let backend_pretty = friendly_backend_label(backend_raw);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>Hyphae · Saved {safe_name}</title>
  <style>{WEB_CAPTURE_CSS}</style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">{HYPHAE_BRAND_SVG}</span>
        <span class="brand-name">hyphae</span>
      </div>
      <span class="pill"><span class="pill-dot" aria-hidden="true"></span>Saved Locally</span>
    </header>
    <section class="card">
      <p class="eyebrow">Secret Saved</p>
      <h1>Return to your setup now</h1>
      <p class="lead">Your secret was saved securely and the one-shot local listener has shut down. You can close this tab.</p>
      <div class="done-banner">
        <span class="done-icon" aria-hidden="true">{HYPHAE_CHECK_SVG}</span>
        <div>
          <strong>Stored in {backend_pretty}</strong>
          <span>Saved under <code>{safe_name}</code> without echoing any secret bytes.</span>
        </div>
      </div>
      <div class="code-ref">Reference in node.json: {{ "secret": "{safe_name}" }}</div>
    </section>
    <p class="footer">You can safely close this tab now.</p>
  </main>
</body>
</html>"#
    )
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONNECTION, "close")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("valid text response")
}

fn should_skip_browser_open(no_open: bool, store: &SecretStore) -> bool {
    if no_open {
        return true;
    }
    if std::env::var_os("HYPHAE_NO_OPEN").is_some() || std::env::var_os("CI").is_some() {
        return true;
    }
    // Never pop up a real browser window when running against ephemeral temp dirs (tests!).
    let tmp = std::env::temp_dir();
    let canon_tmp = std::fs::canonicalize(&tmp).unwrap_or(tmp);
    let dir = store.config_dir();
    let canon_dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    canon_dir.starts_with(&canon_tmp)
        || dir.starts_with("/tmp")
        || dir.starts_with("/private/tmp")
        || dir.starts_with("/var/folders")
        || dir.starts_with("/private/var/folders")
}

fn try_open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let _ = url;
}

struct WebCaptureState {
    name: String,
    expected_path: String,
    csrf_nonce: String,
    store: SecretStore,
    form_html: String,
    done_tx: Mutex<Option<oneshot::Sender<Result<WebSaved, String>>>>,
}

async fn capture_secret_via_web(
    name: &str,
    store: &SecretStore,
    port: u16,
    timeout_secs: u64,
    no_open: bool,
) -> Result<WebSaved, String> {
    let url_token = random_b64url(24)?;
    let csrf_nonce = random_b64url(24)?;
    let expected_path = format!("/s/{url_token}");
    let safe_name = escape_html(name);
    let form_html = render_web_capture_form_html(
        &safe_name,
        store.backend().as_str(),
        &expected_path,
        &csrf_nonce,
    );

    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("failed to bind 127.0.0.1:{port}: {e}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to query local address: {e}"))?;
    let url = format!("http://127.0.0.1:{}{expected_path}", local_addr.port());

    let (done_tx, mut done_rx) = oneshot::channel::<Result<WebSaved, String>>();
    let state = Arc::new(WebCaptureState {
        name: name.to_string(),
        expected_path,
        csrf_nonce,
        store: store.clone(),
        form_html,
        done_tx: Mutex::new(Some(done_tx)),
    });

    // Emit ephemeral URL on stderr and flush immediately so humans or test harnesses can open it
    // while keeping stdout clean for the final `--json` envelope.
    eprintln!("Hyphae secret capture URL (one-shot, 127.0.0.1 only): {url}");
    let _ = io::stderr().flush();

    if !should_skip_browser_open(no_open, store) {
        try_open_browser(&url);
    }

    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs.max(1)));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            res = &mut done_rx => {
                // Allow a brief moment for the HTTP 200 response frame to flush before exiting.
                tokio::time::sleep(Duration::from_millis(50)).await;
                return res.map_err(|_| "secret capture channel closed unexpectedly".to_string())?;
            }
            _ = &mut timeout => {
                return Err(format!("timed out after {timeout_secs}s waiting for secret '{name}' submission"));
            }
            accept = listener.accept() => {
                let Ok((stream, _)) = accept else {
                    continue;
                };
                let st = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let st = Arc::clone(&st);
                        async move { Ok::<_, Infallible>(handle_web_capture_request(st, req).await) }
                    });
                    let _ = AutoServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        }
    }
}

async fn handle_web_capture_request(
    state: Arc<WebCaptureState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    if path == "/favicon.ico" {
        return text_response(StatusCode::NO_CONTENT, "");
    }
    if !ct_eq(path.as_bytes(), state.expected_path.as_bytes()) {
        return text_response(StatusCode::NOT_FOUND, "Not found");
    }

    match *req.method() {
        Method::GET => html_response(StatusCode::OK, state.form_html.clone()),
        Method::POST => {
            let mut body_bytes = Vec::new();
            let mut body = req.into_body();
            while let Some(frame_res) = body.frame().await {
                let Ok(frame) = frame_res else {
                    return text_response(StatusCode::BAD_REQUEST, "Failed to read request body");
                };
                if let Some(chunk) = frame.data_ref() {
                    if body_bytes.len() + chunk.len() > MAX_SECRET_INPUT_BYTES as usize {
                        return text_response(StatusCode::PAYLOAD_TOO_LARGE, "Payload too large");
                    }
                    body_bytes.extend_from_slice(chunk);
                }
            }

            let body_str = String::from_utf8_lossy(&body_bytes);
            let mut submitted_csrf: Option<String> = None;
            let mut submitted_value: Option<String> = None;

            if body_str.trim_start().starts_with('{') {
                if let Ok(serde_json::Value::Object(map)) =
                    serde_json::from_str::<serde_json::Value>(&body_str)
                {
                    submitted_csrf = map
                        .get("csrf")
                        .or_else(|| map.get("token"))
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned);
                    submitted_value = map
                        .get("value")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned);
                }
            } else {
                for (k, v) in parse_form_urlencoded(&body_str) {
                    if k == "csrf" || k == "token" {
                        submitted_csrf = Some(v);
                    } else if k == "value" {
                        submitted_value = Some(v);
                    }
                }
            }

            let csrf_ok = submitted_csrf
                .as_deref()
                .is_some_and(|c| ct_eq(c.as_bytes(), state.csrf_nonce.as_bytes()));
            if !csrf_ok {
                return text_response(StatusCode::FORBIDDEN, "Invalid CSRF nonce");
            }

            let value = submitted_value.unwrap_or_default().trim().to_string();
            if value.is_empty() {
                return text_response(StatusCode::BAD_REQUEST, "Secret value cannot be empty");
            }

            match state.store.set(&state.name, &value) {
                Ok(saved) => {
                    let backend = saved.backend.as_str().to_string();
                    let location = saved.location.clone();
                    if let Ok(mut guard) = state.done_tx.lock() {
                        if let Some(tx) = guard.take() {
                            let _ = tx.send(Ok(WebSaved {
                                backend: backend.clone(),
                                location,
                            }));
                        }
                    }
                    let safe_name = escape_html(&state.name);
                    html_response(
                        StatusCode::OK,
                        render_web_capture_saved_html(&safe_name, &backend),
                    )
                }
                Err(e) => {
                    let msg = format!("Failed to store secret '{}': {e}", state.name);
                    if let Ok(mut guard) = state.done_tx.lock() {
                        if let Some(tx) = guard.take() {
                            let _ = tx.send(Err(msg));
                        }
                    }
                    text_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to save secret")
                }
            }
        }
        _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed"),
    }
}

#[cfg(test)]
mod tests {
    use super::{friendly_backend_label, render_web_capture_form_html};

    #[test]
    fn friendly_backend_labels_cover_all_six_backends() {
        assert_eq!(friendly_backend_label("1password"), "1Password CLI (op)");
        assert_eq!(friendly_backend_label("lastpass"), "LastPass CLI (lpass)");
        assert_eq!(
            friendly_backend_label("pass"),
            "Linux pass (password-store)"
        );
        assert_eq!(friendly_backend_label("keychain"), "macOS Keychain");
        assert_eq!(
            friendly_backend_label("secret-service"),
            "Linux Secret Service"
        );
        assert_eq!(friendly_backend_label("file"), "0600 Private Secret File");
    }

    #[test]
    fn web_capture_form_disables_password_manager_autofill_prompts() {
        let html = render_web_capture_form_html("telegram-bot-token", "keychain", "/s/abc", "n1");
        assert!(html.contains(r#"class="secret-masked" type="text""#));
        assert!(html.contains(r#"data-1p-ignore="true""#));
        assert!(html.contains(r#"data-lpignore="true""#));
        assert!(html.contains(r#"data-bwignore="true""#));
        assert!(html.contains(r#"data-form-type="other""#));
        assert!(html.contains("-webkit-text-security: disc;"));
        // Initial <form> markup must not declare type="password" so password managers
        // (1Password, iCloud Passwords, etc.) do not show a "Sign in" overlay on 127.0.0.1.
        let form_start = html.find("<form ").expect("form tag");
        let form_end = html.find("</form>").expect("closing form tag");
        let form_html = &html[form_start..form_end];
        assert!(!form_html.contains(r#"type="password""#));
    }
}
