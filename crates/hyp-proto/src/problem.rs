//! RFC 9457 Problem Details (`application/problem+json`) with backward-compatible
//! Hyphae v1 `"error"` extension field (§3.2, §4.2, §6.4).

use crate::manifest::{CapabilityToken, ProtocolRange};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const CONTENT_TYPE_PROBLEM_JSON: &str = "application/problem+json";
pub const ERROR_TYPE_BASE: &str = "https://hyphae.to/errors/";

/// RFC 9457 Problem Details object carrying Hyphae's backward-compatible `"error"` code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Backward-compatible v1 machine error code extension (e.g. `"not_granted"`).
    pub error: String,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ProblemDetails {
    pub fn new(
        error_code: impl Into<String>,
        slug: &str,
        title: impl Into<String>,
        status: u16,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            problem_type: format!("{ERROR_TYPE_BASE}{slug}"),
            title: title.into(),
            status,
            detail: Some(detail.into()),
            instance: None,
            error: error_code.into(),
            extensions: BTreeMap::new(),
        }
    }

    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }

    pub fn with_extension(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    /// `403` `not_granted` (§4.2) with `missingScope`, `currentScopes`, and optional sanitized `escalationNote`.
    pub fn not_granted(
        missing_scope: impl Into<String>,
        current_scopes: &[String],
        escalation_note: Option<&str>,
    ) -> Self {
        let missing = missing_scope.into();
        let detail = format!("Scope '{missing}' is not granted for this peer.");
        let mut p = Self::new("not_granted", "not-granted", "Scope Not Granted", 403, detail)
            .with_extension("missingScope", json!(missing))
            .with_extension("currentScopes", json!(current_scopes));
        if let Some(note) = escalation_note {
            p = p.with_extension("escalationNote", json!(note));
        }
        p
    }

    /// `501` `capability_unsupported` (§3.2).
    #[allow(clippy::too_many_arguments)]
    pub fn capability_unsupported(
        capability: &CapabilityToken,
        peer: &str,
        local_version: &str,
        remote_version: &str,
        min_remote_version: Option<&str>,
        required: bool,
        fix: Option<&str>,
    ) -> Self {
        let cap_str = capability.as_str();
        let detail = match min_remote_version {
            Some(min_v) => format!(
                "Peer '{peer}' (v{remote_version}) does not support '{cap_str}' (requires >= {min_v})."
            ),
            None => format!("Peer '{peer}' (v{remote_version}) does not support '{cap_str}'."),
        };
        let mut p = Self::new(
            "capability_unsupported",
            "capability-unsupported",
            if required {
                "Required Capability Unsupported"
            } else {
                "Capability Unsupported"
            },
            501,
            detail,
        )
        .with_extension("capability", json!(cap_str))
        .with_extension("peer", json!(peer))
        .with_extension("localVersion", json!(local_version))
        .with_extension("remoteVersion", json!(remote_version))
        .with_extension("required", json!(required));
        if let Some(min_v) = min_remote_version {
            p = p.with_extension("minRemoteVersion", json!(min_v));
        }
        if let Some(fix_cmd) = fix {
            p = p.with_extension("fix", json!(fix_cmd));
        }
        p
    }

    /// `426` `protocol_incompatible` (§3.2).
    pub fn protocol_incompatible(
        peer: &str,
        local_range: ProtocolRange,
        remote_range: ProtocolRange,
        fix: Option<&str>,
    ) -> Self {
        let detail = format!(
            "No overlapping Hyphae protocol version with peer '{peer}' (local {}..={}, remote {}..={}).",
            local_range.min, local_range.max, remote_range.min, remote_range.max
        );
        let mut p = Self::new(
            "protocol_incompatible",
            "protocol-incompatible",
            "Protocol Version Incompatible",
            426,
            detail,
        )
        .with_extension("peer", json!(peer))
        .with_extension("localRange", json!({ "min": local_range.min, "max": local_range.max }))
        .with_extension("remoteRange", json!({ "min": remote_range.min, "max": remote_range.max }));
        if let Some(fix_cmd) = fix {
            p = p.with_extension("fix", json!(fix_cmd));
        }
        p
    }

    /// `400` `routing_loop` (§2.3).
    pub fn routing_loop(node_id: &str, via: &[String]) -> Self {
        Self::new(
            "routing_loop",
            "routing-loop",
            "Routing Loop Detected",
            400,
            format!("Refusing to forward event through '{node_id}': cycle detected in hyphaevia."),
        )
        .with_extension("nodeId", json!(node_id))
        .with_extension("via", json!(via))
    }

    /// `400` `hop_limit_exceeded` (§2.3).
    pub fn hop_limit_exceeded(hops: u8, max_hops: u8) -> Self {
        Self::new(
            "hop_limit_exceeded",
            "hop-limit-exceeded",
            "Hop Limit Exceeded",
            400,
            format!("Event hop count ({hops}) reached maximum allowed hops ({max_hops})."),
        )
        .with_extension("hops", json!(hops))
        .with_extension("maxHops", json!(max_hops))
    }

    /// `409` `version_conflict` (§7.1 KV CAS).
    pub fn version_conflict(
        expected_version: u64,
        current_version: u64,
        namespace: Option<&str>,
        key: Option<&str>,
    ) -> Self {
        let mut p = Self::new(
            "version_conflict",
            "version-conflict",
            "Version Conflict",
            409,
            format!(
                "CAS write failed: expected version {expected_version}, current version is {current_version}."
            ),
        )
        .with_extension("expectedVersion", json!(expected_version))
        .with_extension("currentVersion", json!(current_version));
        if let Some(ns) = namespace {
            p = p.with_extension("namespace", json!(ns));
        }
        if let Some(k) = key {
            p = p.with_extension("key", json!(k));
        }
        p
    }

    /// `409` `manifest_rollback_detected` (§3.2).
    pub fn manifest_rollback_detected(
        peer: &str,
        received_version: u64,
        last_seen_version: u64,
    ) -> Self {
        Self::new(
            "manifest_rollback_detected",
            "manifest-rollback-detected",
            "Manifest Rollback Detected",
            409,
            format!(
                "Peer '{peer}' presented manifestVersion {received_version}, older than last seen {last_seen_version}."
            ),
        )
        .with_extension("peer", json!(peer))
        .with_extension("receivedVersion", json!(received_version))
        .with_extension("lastSeenVersion", json!(last_seen_version))
    }

    /// `409` `capability_downgrade_detected` (§3.2).
    pub fn capability_downgrade_detected(peer: &str, missing_capabilities: &[CapabilityToken]) -> Self {
        let missing: Vec<&str> = missing_capabilities.iter().map(CapabilityToken::as_str).collect();
        Self::new(
            "capability_downgrade_detected",
            "capability-downgrade-detected",
            "Security Capability Downgrade Detected",
            409,
            format!(
                "Peer '{peer}' dropped previously negotiated security capabilities: {}.",
                missing.join(", ")
            ),
        )
        .with_extension("peer", json!(peer))
        .with_extension("missingCapabilities", json!(missing))
        .with_extension(
            "fix",
            json!(format!(
                "Verify peer '{peer}' was intentionally downgraded, or run `hyp peer trust --accept-downgrade {peer}`."
            )),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_details_matches_architecture_contract() {
        let p = ProblemDetails::capability_unsupported(
            &CapabilityToken::KvE2eeV1,
            "acme-team",
            "2.2.0",
            "2.0.1",
            Some("2.1.0"),
            true,
            Some("Upgrade node 'acme-team' to hyp >= 2.1.0"),
        );
        let val = serde_json::to_value(&p).unwrap();
        assert_eq!(val["type"], "https://hyphae.to/errors/capability-unsupported");
        assert_eq!(val["title"], "Required Capability Unsupported");
        assert_eq!(val["status"], 501);
        assert_eq!(val["error"], "capability_unsupported");
        assert_eq!(val["capability"], "kv.e2ee.v1");
        assert_eq!(val["peer"], "acme-team");
        assert_eq!(val["localVersion"], "2.2.0");
        assert_eq!(val["remoteVersion"], "2.0.1");
        assert_eq!(val["minRemoteVersion"], "2.1.0");
        assert_eq!(val["required"], true);

        let roundtrip: ProblemDetails = serde_json::from_value(val).unwrap();
        assert_eq!(roundtrip, p);
    }

    #[test]
    fn all_standard_problem_constructors_roundtrip() {
        let items = vec![
            ProblemDetails::not_granted(
                "stream:subscribe=github[repo=acme/billing]",
                &["dm:send".to_string()],
                Some("Ask @secops"),
            ),
            ProblemDetails::protocol_incompatible(
                "future-node",
                ProtocolRange { min: 1, max: 2 },
                ProtocolRange { min: 3, max: 3 },
                None,
            ),
            ProblemDetails::routing_loop("acme-team", &["acme-team".to_string()]),
            ProblemDetails::hop_limit_exceeded(2, 2),
            ProblemDetails::version_conflict(4, 5, Some("shared"), Some("lock")),
            ProblemDetails::manifest_rollback_detected("acme-team", 3, 5),
            ProblemDetails::capability_downgrade_detected(
                "acme-team",
                &[CapabilityToken::DmE2eeV1],
            ),
        ];

        for item in items {
            let s = serde_json::to_string(&item).unwrap();
            let decoded: ProblemDetails = serde_json::from_str(&s).unwrap();
            assert_eq!(decoded, item);
            assert!(decoded.problem_type.starts_with(ERROR_TYPE_BASE));
        }
    }
}
