//! Node-ID and hostname primitives with the existing caller policies preserved.

use hyp_proto::address::{LOCAL_NODE_ID, is_valid_node_id};

fn environment_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

fn environment_hostname() -> Result<String, std::env::VarError> {
    std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME"))
}

pub(crate) fn config_default_node_id() -> String {
    let raw_user = environment_user();
    let raw_host = environment_hostname().unwrap_or_else(|_| "local-host".to_string());
    format_default_node_id(&raw_user, &raw_host, "host")
}

pub(crate) fn setup_default_node_id() -> String {
    let raw_user = environment_user();
    let env_host = environment_hostname().ok();
    let host = resolve_machine_hostname(env_host.as_deref());
    format_default_node_id(&raw_user, &host, "local-host")
}

fn is_generic_localhost(raw: &str) -> bool {
    let trimmed = raw.trim().to_ascii_lowercase();
    let short = trimmed.split('.').next().unwrap_or("");
    short.is_empty() || matches!(short, "localhost" | "local-host" | "localdomain")
}

fn run_trimmed_stdout(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn resolve_machine_hostname(env_host: Option<&str>) -> String {
    if let Some(h) = env_host.filter(|h| !is_generic_localhost(h)) {
        return h.to_string();
    }
    if let Some(h) = run_trimmed_stdout("hostname", &["-s"]).filter(|h| !is_generic_localhost(h)) {
        return h;
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(h) = run_trimmed_stdout("scutil", &["--get", "LocalHostName"])
            .filter(|h| !is_generic_localhost(h))
        {
            return h;
        }
        if let Some(h) = run_trimmed_stdout("scutil", &["--get", "ComputerName"])
            .filter(|h| !is_generic_localhost(h))
        {
            return h;
        }
    }
    "local-host".to_string()
}

fn sanitize_id_segment(raw: &str, fallback: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        let low = ch.to_ascii_lowercase();
        if low.is_ascii_alphanumeric() || matches!(low, '.' | '_' | '-') {
            out.push(low);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.chars().take(28).collect()
    }
}

fn format_default_node_id(raw_user: &str, raw_host: &str, host_fallback: &str) -> String {
    let user = sanitize_id_segment(raw_user, "user");
    let host_short = raw_host.split('.').next().unwrap_or("local-host");
    let host = sanitize_id_segment(host_short, host_fallback);
    let candidate = format!("{user}@{host}");
    if candidate != LOCAL_NODE_ID && is_valid_node_id(&candidate) {
        candidate
    } else {
        "user@local-host".to_string()
    }
}

pub(crate) fn short_hostname() -> String {
    let env_host = environment_hostname().ok().filter(|s| !s.trim().is_empty());
    #[cfg(unix)]
    let raw = env_host
        .or_else(|| {
            std::process::Command::new("hostname")
                .arg("-s")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "laptop".to_string());
    #[cfg(not(unix))]
    let raw = env_host.unwrap_or_else(|| "laptop".to_string());
    let first = raw.split('.').next().unwrap_or("laptop");
    let cleaned: String = first
        .chars()
        .map(|c| {
            let low = c.to_ascii_lowercase();
            if low.is_ascii_alphanumeric() || matches!(low, '-' | '_') {
                low
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() {
        "laptop".to_string()
    } else {
        trimmed.chars().take(28).collect()
    }
}

#[cfg(test)]
#[test]
fn format_default_node_id_sanitizes_macos_local_host_name() {
    assert_eq!(
        format_default_node_id("Riley", "Studio-MacBook-Pro", "local-host"),
        "riley@studio-macbook-pro"
    );
    assert_eq!(
        format_default_node_id("Alice", "Alice's MacBook Pro.local", "local-host"),
        "alice@alice-s-macbook-pro"
    );
}

#[cfg(test)]
#[test]
fn generic_localhost_detection_catches_macos_fallbacks() {
    assert!(is_generic_localhost(""));
    assert!(is_generic_localhost("localhost"));
    assert!(is_generic_localhost("localhost.localdomain"));
    assert!(is_generic_localhost("LOCAL-HOST"));
    assert!(!is_generic_localhost("Studio-MacBook-Pro"));
    assert!(!is_generic_localhost("workstation.local"));
}
