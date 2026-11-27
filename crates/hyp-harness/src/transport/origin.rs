//! Shared strict HTTP loopback or explicitly enabled HTTPS origin validation.

use http::Uri;
use std::net::Ipv6Addr;

pub(super) fn normalize_origin(
    raw: &str,
    allow_remote: bool,
    invalid_url: &str,
) -> Result<String, String> {
    if raw.is_empty()
        || raw
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || b == b'\\' || b == b'?' || b == b'#')
    {
        return Err(invalid_url.to_string());
    }

    let Some(scheme_end) = raw.find("://") else {
        return Err(invalid_url.to_string());
    };
    let scheme = raw[..scheme_end].to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(invalid_url.to_string());
    }

    let after_scheme = &raw[scheme_end + 3..];
    if after_scheme.is_empty() {
        return Err(invalid_url.to_string());
    }

    let (authority, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, ""),
    };

    // Only empty path or root "/" is permitted.
    if !path.is_empty() && path != "/" {
        return Err(invalid_url.to_string());
    }

    // Reject any userinfo / credentials (`@`).
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid_url.to_string());
    }

    let (host_lower, port_opt) = if let Some(rest) = authority.strip_prefix('[') {
        let Some(close_bracket) = rest.find(']') else {
            return Err(invalid_url.to_string());
        };
        let ipv6_str = &rest[..close_bracket];
        let ipv6: Ipv6Addr = ipv6_str.parse().map_err(|_| invalid_url.to_string())?;
        let after_bracket = &rest[close_bracket + 1..];
        let port = parse_optional_port(after_bracket, invalid_url)?;
        (format!("[{ipv6}]"), port)
    } else {
        if authority.contains('[') || authority.contains(']') {
            return Err(invalid_url.to_string());
        }
        let (host, port_str) = match authority.rfind(':') {
            Some(colon) => (&authority[..colon], Some(&authority[colon..])),
            None => (authority, None),
        };
        if host.is_empty() || host.contains(':') {
            return Err(invalid_url.to_string());
        }
        if !is_valid_hostname(host) {
            return Err(invalid_url.to_string());
        }
        let port = match port_str {
            Some(p) => parse_optional_port(p, invalid_url)?,
            None => None,
        };
        (host.to_ascii_lowercase(), port)
    };

    let is_loopback = matches!(host_lower.as_str(), "localhost" | "127.0.0.1" | "[::1]");
    let allowed = is_loopback || (allow_remote && scheme == "https");
    if !allowed {
        return Err(invalid_url.to_string());
    }

    let default_port = if scheme == "https" { 443 } else { 80 };
    let origin = match port_opt {
        Some(port) if port != default_port => format!("{scheme}://{host_lower}:{port}"),
        _ => format!("{scheme}://{host_lower}"),
    };

    // Final cross-check with `http::Uri` so downstream hyper requests always accept this origin.
    origin.parse::<Uri>().map_err(|_| invalid_url.to_string())?;

    Ok(origin)
}

fn parse_optional_port(suffix: &str, invalid_url: &str) -> Result<Option<u16>, String> {
    if suffix.is_empty() {
        return Ok(None);
    }
    let Some(digits) = suffix.strip_prefix(':') else {
        return Err(invalid_url.to_string());
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid_url.to_string());
    }
    let port: u16 = digits.parse().map_err(|_| invalid_url.to_string())?;
    if port == 0 {
        return Err(invalid_url.to_string());
    }
    Ok(Some(port))
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.contains("..") {
        return false;
    }
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.is_empty() {
        return false;
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    true
}
