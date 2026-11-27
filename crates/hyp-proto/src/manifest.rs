//! Signed Node Capability Manifest, RFC 7517/8037 OKP JWK, RFC 7638 JWK Thumbprint (`kid`),
//! fail-closed capability negotiation (anti-rollback, anti-downgrade, protocol intersection,
//! legacy v1 synthesis), and optional read-only A2A `AgentCard` projection (§3.1–3.2, §6.4).

use crate::address::{NodeId, is_valid_topic};
use crate::cloudevent::parse_rfc3339_utc_nanos;
use crate::jcs::{JcsError, serialize_jcs, to_jcs_string};
use crate::problem::ProblemDetails;
use crate::scopes::EscalationConfig;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use semver::Version;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

/// Domain-separation prefix for Ed25519 manifest signatures (§3.1).
pub const MANIFEST_SIGNING_PREFIX: &str = "hyphae/v2/manifest\n";

/// Synthetic SemVer label used when synthesizing capabilities for a legacy v1 TS router.
pub const LEGACY_V1_VERSION: &str = "legacy-v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ManifestError {
    #[error("unsupported manifest schema version {0} (expected 1)")]
    UnsupportedVersion(u32),
    #[error("invalid protocol range {min}..={max}")]
    InvalidProtocolRange { min: u32, max: u32 },
    #[error("invalid SemVer hyphaeVersion {0:?}")]
    InvalidSemVer(String),
    #[error("invalid RFC 3339 timestamp for {field}: {value:?}")]
    InvalidTimestamp { field: &'static str, value: String },
    #[error("manifest expiresAt ({expires_at}) must be after issuedAt ({issued_at})")]
    InvalidValidityWindow {
        issued_at: String,
        expires_at: String,
    },
    #[error("invalid OKP JWK: {0}")]
    InvalidJwk(String),
    #[error("identity kid {got:?} does not match signingJwk RFC 7638 thumbprint {expected:?}")]
    KidMismatch { got: String, expected: String },
    #[error("public manifest must have empty advertised resources and no escalation text")]
    PublicManifestLeak,
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

/// RFC 8037 OKP elliptic curves used by Hyphae v2 nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OkpCurve {
    Ed25519,
    X25519,
}

impl OkpCurve {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
        }
    }
}

/// RFC 7517 / RFC 8037 OKP JSON Web Key for Ed25519 / X25519 public keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OkpJwk<Curve = OkpCurve, Text = String> {
    pub kty: Text,
    pub crv: Curve,
    pub x: Text,
}

/// RFC 7638 thumbprint for a validated OKP curve and raw 32-byte public key.
pub fn okp_key_thumbprint(crv: OkpCurve, raw_public_key: &[u8; 32]) -> String {
    let x = URL_SAFE_NO_PAD.encode(raw_public_key);
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"OKP\",\"x\":\"{x}\"}}",
        crv.as_str()
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

impl OkpJwk<OkpCurve> {
    pub fn new(crv: OkpCurve, raw_public_key: &[u8; 32]) -> Self {
        Self {
            kty: "OKP".to_string(),
            crv,
            x: URL_SAFE_NO_PAD.encode(raw_public_key),
        }
    }

    /// Validates `kty == "OKP"`, expected curve, and strict unpadded base64url 32-byte `x`.
    pub fn validate(&self, expected_crv: Option<OkpCurve>) -> Result<[u8; 32], ManifestError> {
        if self.kty != "OKP" {
            return Err(ManifestError::InvalidJwk(format!(
                "kty must be \"OKP\", got {:?}",
                self.kty
            )));
        }
        if let Some(crv) = expected_crv {
            if self.crv != crv {
                return Err(ManifestError::InvalidJwk(format!(
                    "expected crv {}, got {}",
                    crv.as_str(),
                    self.crv.as_str()
                )));
            }
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|_| ManifestError::InvalidJwk("x is not valid base64url".to_string()))?;
        let raw: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
            ManifestError::InvalidJwk(format!("expected 32-byte OKP key, got {} bytes", v.len()))
        })?;
        // Reject non-canonical trailing bits / encodings.
        if URL_SAFE_NO_PAD.encode(raw) != self.x {
            return Err(ManifestError::InvalidJwk(
                "x is not canonically base64url-encoded".to_string(),
            ));
        }
        Ok(raw)
    }

    /// Computes the **RFC 7638 SHA-256 JWK Thumbprint** (`kid`) encoded as unpadded base64url.
    ///
    /// Per RFC 8037 §2, the required members for OKP JWKs in lexicographical order are
    /// `crv`, `kty`, and `x`: `{"crv":"<crv>","kty":"OKP","x":"<x>"}`.
    pub fn thumbprint_sha256(&self) -> Result<String, ManifestError> {
        let raw = self.validate(None)?;
        Ok(okp_key_thumbprint(self.crv, &raw))
    }
}

/// Node deployment profile (§1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeProfile {
    Local,
    Router,
    P2p,
}

/// Inclusive wire protocol version range supported by a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolRange {
    pub min: u32,
    pub max: u32,
}

/// Canonical versioned Hyphae capability tokens (§3.1) plus forward-compatible `Other(String)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityToken {
    ManifestV1,
    EnvelopeCeV1,
    DmV1,
    DmE2eeV1,
    ChannelV1,
    ChannelE2eeV1,
    TransferV1,
    TransferStreamV2,
    EventsV1,
    SubPushdownV1,
    EventsE2eeV1,
    KvV1,
    KvE2eeV1,
    PairingAdminCaV1,
    PairingP2pMutualV1,
    PairingGuestV1,
    GatePolicyV1,
    P2pDirectV1,
    P2pRelayV1,
    KeysPrekeyV1,
    HumanAuthV1,
    DropRelayV1,
    Other(String),
}

impl CapabilityToken {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ManifestV1 => "manifest.v1",
            Self::EnvelopeCeV1 => "envelope.ce.v1",
            Self::DmV1 => "dm.v1",
            Self::DmE2eeV1 => "dm.e2ee.v1",
            Self::ChannelV1 => "channel.v1",
            Self::ChannelE2eeV1 => "channel.e2ee.v1",
            Self::TransferV1 => "transfer.v1",
            Self::TransferStreamV2 => "transfer.stream.v2",
            Self::EventsV1 => "events.v1",
            Self::SubPushdownV1 => "sub.pushdown.v1",
            Self::EventsE2eeV1 => "events.e2ee.v1",
            Self::KvV1 => "kv.v1",
            Self::KvE2eeV1 => "kv.e2ee.v1",
            Self::PairingAdminCaV1 => "pairing.admin-ca.v1",
            Self::PairingP2pMutualV1 => "pairing.p2p-mutual.v1",
            Self::PairingGuestV1 => "pairing.guest.v1",
            Self::GatePolicyV1 => "gate.policy.v1",
            Self::P2pDirectV1 => "p2p.direct.v1",
            Self::P2pRelayV1 => "p2p.relay.v1",
            Self::KeysPrekeyV1 => "keys.prekey.v1",
            Self::HumanAuthV1 => "human.auth.v1",
            Self::DropRelayV1 => "drop.relay.v1",
            Self::Other(s) => s.as_str(),
        }
    }

    pub fn from_token_str(s: &str) -> Result<Self, String> {
        Ok(match s {
            "manifest.v1" => Self::ManifestV1,
            "envelope.ce.v1" => Self::EnvelopeCeV1,
            "dm.v1" => Self::DmV1,
            "dm.e2ee.v1" => Self::DmE2eeV1,
            "channel.v1" => Self::ChannelV1,
            "channel.e2ee.v1" => Self::ChannelE2eeV1,
            "transfer.v1" => Self::TransferV1,
            "transfer.stream.v2" => Self::TransferStreamV2,
            "events.v1" => Self::EventsV1,
            "sub.pushdown.v1" => Self::SubPushdownV1,
            "events.e2ee.v1" => Self::EventsE2eeV1,
            "kv.v1" => Self::KvV1,
            "kv.e2ee.v1" => Self::KvE2eeV1,
            "pairing.admin-ca.v1" => Self::PairingAdminCaV1,
            "pairing.p2p-mutual.v1" => Self::PairingP2pMutualV1,
            "pairing.guest.v1" => Self::PairingGuestV1,
            "gate.policy.v1" => Self::GatePolicyV1,
            "p2p.direct.v1" => Self::P2pDirectV1,
            "p2p.relay.v1" => Self::P2pRelayV1,
            "keys.prekey.v1" => Self::KeysPrekeyV1,
            "human.auth.v1" => Self::HumanAuthV1,
            "drop.relay.v1" => Self::DropRelayV1,
            other => {
                if !is_valid_topic(other) {
                    return Err(format!("invalid capability token {other:?}"));
                }
                Self::Other(other.to_string())
            }
        })
    }

    /// Returns true for security-ratcheted E2EE capabilities subject to anti-downgrade enforcement.
    pub fn is_anti_downgrade_security_cap(&self) -> bool {
        matches!(self, Self::DmE2eeV1 | Self::ChannelE2eeV1)
    }
}

impl fmt::Display for CapabilityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for CapabilityToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CapabilityToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_token_str(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestIdentity {
    pub signing_jwk: OkpJwk,
    pub encryption_jwk: OkpJwk,
    pub kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_jwk: Option<OkpJwk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestPolicy {
    pub require_pairing: bool,
    pub require_e2ee: bool,
    pub max_text_bytes: u64,
    pub max_transfer_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvertisedTopic {
    pub topic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KvMode {
    E2ee,
    Plaintext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KvWriteModel {
    Owner,
    Shared,
    Allowlist,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvertisedKvNamespace {
    pub name: String,
    pub mode: KvMode,
    pub write_model: KvWriteModel,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvertisedResources {
    #[serde(default)]
    pub topics: Vec<AdvertisedTopic>,
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub kv_namespaces: Vec<AdvertisedKvNamespace>,
    #[serde(default)]
    pub rpc_commands: Vec<String>,
}

impl AdvertisedResources {
    pub fn is_empty(&self) -> bool {
        self.topics.is_empty()
            && self.channels.is_empty()
            && self.kv_namespaces.is_empty()
            && self.rpc_commands.is_empty()
    }
}

/// Signed Node Capability Manifest payload (`GET /v1/manifest`, §3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeManifestPayload {
    pub v: u32,
    pub node_id: NodeId,
    pub profile: NodeProfile,
    pub hyphae_version: String,
    pub protocol_range: ProtocolRange,
    pub manifest_version: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub audience: String,
    pub identity: ManifestIdentity,
    pub capabilities: Vec<CapabilityToken>,
    pub policy: ManifestPolicy,
    pub advertised: AdvertisedResources,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation: Option<EscalationConfig>,
}

impl NodeManifestPayload {
    /// Serializes this manifest payload into strict RFC 8785 JCS canonical JSON.
    pub fn to_canonical_payload(&self) -> Result<String, JcsError> {
        serialize_jcs(self)
    }

    /// Produces the exact domain-separated bytes signed by Ed25519:
    /// `"hyphae/v2/manifest\n" || JCS(payload)`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, JcsError> {
        let canonical = self.to_canonical_payload()?;
        let mut bytes = Vec::with_capacity(MANIFEST_SIGNING_PREFIX.len() + canonical.len());
        bytes.extend_from_slice(MANIFEST_SIGNING_PREFIX.as_bytes());
        bytes.extend_from_slice(canonical.as_bytes());
        Ok(bytes)
    }

    /// Validates structural, cryptographic JWK/kid, SemVer, timestamp, and public-audience invariants.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.v != 1 {
            return Err(ManifestError::UnsupportedVersion(self.v));
        }
        if self.protocol_range.min == 0 || self.protocol_range.min > self.protocol_range.max {
            return Err(ManifestError::InvalidProtocolRange {
                min: self.protocol_range.min,
                max: self.protocol_range.max,
            });
        }
        if self.hyphae_version != LEGACY_V1_VERSION && Version::parse(&self.hyphae_version).is_err()
        {
            return Err(ManifestError::InvalidSemVer(self.hyphae_version.clone()));
        }
        let issued = parse_rfc3339_utc_nanos(&self.issued_at).ok_or_else(|| {
            ManifestError::InvalidTimestamp {
                field: "issuedAt",
                value: self.issued_at.clone(),
            }
        })?;
        let expires = parse_rfc3339_utc_nanos(&self.expires_at).ok_or_else(|| {
            ManifestError::InvalidTimestamp {
                field: "expiresAt",
                value: self.expires_at.clone(),
            }
        })?;
        if expires <= issued {
            return Err(ManifestError::InvalidValidityWindow {
                issued_at: self.issued_at.clone(),
                expires_at: self.expires_at.clone(),
            });
        }

        self.identity
            .signing_jwk
            .validate(Some(OkpCurve::Ed25519))?;
        self.identity
            .encryption_jwk
            .validate(Some(OkpCurve::X25519))?;
        if let Some(admin) = &self.identity.admin_jwk {
            admin.validate(Some(OkpCurve::Ed25519))?;
        }
        let expected_kid = self.identity.signing_jwk.thumbprint_sha256()?;
        if self.identity.kid != expected_kid {
            return Err(ManifestError::KidMismatch {
                got: self.identity.kid.clone(),
                expected: expected_kid,
            });
        }

        // Security invariant (§3.1): unauthenticated/public manifests MUST NOT leak private resources.
        if self.audience == "public" && (!self.advertised.is_empty() || self.escalation.is_some()) {
            return Err(ManifestError::PublicManifestLeak);
        }

        Ok(())
    }

    /// Projects this signed Node Manifest into an optional read-only A2A `AgentCard`
    /// (`GET /.well-known/agent.json`, §6.4). Public manifests automatically expose zero private skills.
    pub fn to_a2a_agent_card(&self, endpoint_url: &str) -> AgentCard {
        let mut skills = Vec::new();
        if self.audience != "public" {
            for t in &self.advertised.topics {
                skills.push(AgentCardSkill {
                    id: format!("stream:{}", t.topic),
                    name: format!("Stream {}", t.topic),
                    description: t
                        .description
                        .clone()
                        .unwrap_or_else(|| format!("Hyphae CloudEvents stream '{}'", t.topic)),
                    tags: vec!["hyphae".to_string(), "stream".to_string()],
                });
            }
            for ch in &self.advertised.channels {
                skills.push(AgentCardSkill {
                    id: format!("channel:{ch}"),
                    name: format!("Channel {ch}"),
                    description: format!("Hyphae channel {ch}"),
                    tags: vec!["hyphae".to_string(), "channel".to_string()],
                });
            }
            for cmd in &self.advertised.rpc_commands {
                skills.push(AgentCardSkill {
                    id: format!("rpc:{cmd}"),
                    name: cmd.clone(),
                    description: format!("Hyphae node RPC command '{cmd}'"),
                    tags: vec!["hyphae".to_string(), "rpc".to_string()],
                });
            }
        }

        let caps_set: BTreeSet<&CapabilityToken> = self.capabilities.iter().collect();
        AgentCard {
            name: self.node_id.to_string(),
            description: format!("Hyphae v2 node ({:?})", self.profile),
            url: endpoint_url.to_string(),
            version: self.hyphae_version.clone(),
            kid: self.identity.kid.clone(),
            capabilities: AgentCardCapabilities {
                streaming: caps_set.contains(&CapabilityToken::EventsV1)
                    || caps_set.contains(&CapabilityToken::SubPushdownV1),
                push_notifications: caps_set.contains(&CapabilityToken::SubPushdownV1),
                e2ee: caps_set.contains(&CapabilityToken::DmE2eeV1),
            },
            authentication: AgentCardAuth {
                schemes: if self.policy.require_pairing {
                    vec!["hyphae-grant".to_string()]
                } else {
                    vec!["hyphae-guest".to_string()]
                },
            },
            skills,
        }
    }
}

/// Wire envelope served at `GET /v1/manifest` (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedNodeManifest {
    /// RFC 8785 JCS canonical JSON of `NodeManifestPayload`.
    pub payload: String,
    /// RFC 8032 Ed25519 signature over `"hyphae/v2/manifest\n" + payload` (base64url).
    pub sig: String,
}

impl SignedNodeManifest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MANIFEST_SIGNING_PREFIX.len() + self.payload.len());
        bytes.extend_from_slice(MANIFEST_SIGNING_PREFIX.as_bytes());
        bytes.extend_from_slice(self.payload.as_bytes());
        bytes
    }

    pub fn decode_payload(&self) -> Result<NodeManifestPayload, ManifestError> {
        let payload: NodeManifestPayload = serde_json::from_str(&self.payload)
            .map_err(|e| ManifestError::Canonicalization(e.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }
}

// ---- Capability Negotiation (§3.2) ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum E2eePolicy {
    Required,
    Prefer,
    Disabled,
}

/// Persisted per-peer anti-rollback & anti-downgrade trust state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerTrustHistory {
    pub last_seen_manifest_version: Option<u64>,
    pub previously_seen_capabilities: BTreeSet<CapabilityToken>,
    /// Explicitly set only via `hyp peer trust --accept-downgrade <peer>`.
    pub accept_downgrade: bool,
}

/// Capability descriptor used for signed-manifest negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCapabilitiesView {
    pub node_id: NodeId,
    pub hyphae_version: String,
    pub protocol_range: ProtocolRange,
    pub manifest_version: Option<u64>,
    pub audience: Option<String>,
    pub expires_at: Option<String>,
    pub capabilities: BTreeSet<CapabilityToken>,
    pub require_e2ee: bool,
}

impl PeerCapabilitiesView {
    pub fn from_manifest(manifest: &NodeManifestPayload) -> Self {
        Self {
            node_id: manifest.node_id.clone(),
            hyphae_version: manifest.hyphae_version.clone(),
            protocol_range: manifest.protocol_range,
            manifest_version: Some(manifest.manifest_version),
            audience: Some(manifest.audience.clone()),
            expires_at: Some(manifest.expires_at.clone()),
            capabilities: manifest.capabilities.iter().cloned().collect(),
            require_e2ee: manifest.policy.require_e2ee,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NegotiationStatus {
    Ok,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedSession {
    pub agreed_protocol: u32,
    pub shared_capabilities: BTreeSet<CapabilityToken>,
    pub missing_optional_capabilities: BTreeSet<CapabilityToken>,
    pub status: NegotiationStatus,
    pub warnings: Vec<String>,
    pub updated_manifest_version: Option<u64>,
    pub updated_seen_capabilities: BTreeSet<CapabilityToken>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NegotiationError {
    #[error("manifest audience mismatch: expected {expected:?}, got {got:?}")]
    AudienceMismatch { expected: String, got: String },
    #[error("manifest expired at {expires_at} (now: {now})")]
    ManifestExpired { expires_at: String, now: String },
    #[error(
        "manifest rollback detected for peer {peer}: received {received} < last seen {last_seen}"
    )]
    ManifestRollbackDetected {
        peer: String,
        received: u64,
        last_seen: u64,
    },
    #[error("capability downgrade detected for peer {peer}: missing {missing:?}")]
    CapabilityDowngradeDetected {
        peer: String,
        missing: Vec<CapabilityToken>,
    },
    #[error(
        "protocol incompatible with peer {peer}: local {local_range:?}, remote {remote_range:?}"
    )]
    ProtocolIncompatible {
        peer: String,
        local_range: ProtocolRange,
        remote_range: ProtocolRange,
    },
    #[error("required capability {capability} unsupported by peer {peer}")]
    RequiredCapabilityUnsupported {
        peer: String,
        capability: CapabilityToken,
        local_version: String,
        remote_version: String,
    },
}

impl NegotiationError {
    /// Converts this fail-closed negotiation error into a standard RFC 9457 `ProblemDetails`.
    pub fn to_problem_details(&self) -> ProblemDetails {
        match self {
            Self::AudienceMismatch { expected, got } => ProblemDetails::new(
                "invalid_manifest",
                "invalid-manifest",
                "Manifest Audience Mismatch",
                403,
                format!("Manifest audience {got:?} does not match expected caller {expected:?}."),
            ),
            Self::ManifestExpired { expires_at, now } => ProblemDetails::new(
                "manifest_expired",
                "manifest-expired",
                "Manifest Expired",
                401,
                format!("Peer manifest expired at {expires_at} (now {now})."),
            ),
            Self::ManifestRollbackDetected {
                peer,
                received,
                last_seen,
            } => ProblemDetails::manifest_rollback_detected(peer, *received, *last_seen),
            Self::CapabilityDowngradeDetected { peer, missing } => {
                ProblemDetails::capability_downgrade_detected(peer, missing)
            }
            Self::ProtocolIncompatible {
                peer,
                local_range,
                remote_range,
            } => ProblemDetails::protocol_incompatible(
                peer,
                *local_range,
                *remote_range,
                Some(&format!(
                    "Upgrade node '{peer}' or local `hyp` to a compatible major protocol version."
                )),
            ),
            Self::RequiredCapabilityUnsupported {
                peer,
                capability,
                local_version,
                remote_version,
            } => ProblemDetails::capability_unsupported(
                capability,
                peer,
                local_version,
                remote_version,
                None,
                true,
                Some(&format!("Upgrade node '{peer}' to support '{capability}'")),
            ),
        }
    }
}

/// Negotiates protocol version and capability intersection with strict fail-closed
/// audience, expiry, anti-rollback, anti-downgrade, and E2EE enforcement (§3.2).
pub fn negotiate_capabilities(
    local: &PeerCapabilitiesView,
    remote: &PeerCapabilitiesView,
    expected_audience: &str,
    now_rfc3339: &str,
    e2ee_policy: E2eePolicy,
    history: &PeerTrustHistory,
) -> Result<NegotiatedSession, NegotiationError> {
    let peer = remote.node_id.as_str().to_string();

    // 1. Audience & expiry checks for signed v2 manifests.
    if let Some(aud) = &remote.audience {
        if aud != expected_audience {
            return Err(NegotiationError::AudienceMismatch {
                expected: expected_audience.to_string(),
                got: aud.clone(),
            });
        }
    }
    if let Some(exp_str) = &remote.expires_at {
        let exp =
            parse_rfc3339_utc_nanos(exp_str).ok_or_else(|| NegotiationError::ManifestExpired {
                expires_at: exp_str.clone(),
                now: now_rfc3339.to_string(),
            })?;
        let now = parse_rfc3339_utc_nanos(now_rfc3339).ok_or_else(|| {
            NegotiationError::ManifestExpired {
                expires_at: exp_str.clone(),
                now: now_rfc3339.to_string(),
            }
        })?;
        if exp <= now {
            return Err(NegotiationError::ManifestExpired {
                expires_at: exp_str.clone(),
                now: now_rfc3339.to_string(),
            });
        }
    }

    // 2. Anti-rollback check (`manifestVersion` must be monotonically non-decreasing).
    if let (Some(last_seen), Some(received)) =
        (history.last_seen_manifest_version, remote.manifest_version)
    {
        if received < last_seen {
            return Err(NegotiationError::ManifestRollbackDetected {
                peer,
                received,
                last_seen,
            });
        }
    }

    // 3. Anti-downgrade check: previously observed E2EE capabilities may never silently vanish.
    if !history.accept_downgrade {
        let missing_security: Vec<CapabilityToken> = history
            .previously_seen_capabilities
            .iter()
            .filter(|cap| {
                cap.is_anti_downgrade_security_cap() && !remote.capabilities.contains(*cap)
            })
            .cloned()
            .collect();
        if !missing_security.is_empty() {
            return Err(NegotiationError::CapabilityDowngradeDetected {
                peer,
                missing: missing_security,
            });
        }
    }

    // 4. Protocol version range intersection.
    let min_agreed = local.protocol_range.min.max(remote.protocol_range.min);
    let max_agreed = local.protocol_range.max.min(remote.protocol_range.max);
    if max_agreed < min_agreed {
        return Err(NegotiationError::ProtocolIncompatible {
            peer,
            local_range: local.protocol_range,
            remote_range: remote.protocol_range,
        });
    }
    let agreed_protocol = max_agreed;

    // 5. Capability intersection.
    let shared_capabilities: BTreeSet<CapabilityToken> = local
        .capabilities
        .intersection(&remote.capabilities)
        .cloned()
        .collect();
    let missing_optional_capabilities: BTreeSet<CapabilityToken> = local
        .capabilities
        .difference(&remote.capabilities)
        .cloned()
        .collect();

    // 6. Required E2EE enforcement (local or remote policy).
    let must_e2ee =
        e2ee_policy == E2eePolicy::Required || local.require_e2ee || remote.require_e2ee;
    if must_e2ee && !shared_capabilities.contains(&CapabilityToken::DmE2eeV1) {
        return Err(NegotiationError::RequiredCapabilityUnsupported {
            peer,
            capability: CapabilityToken::DmE2eeV1,
            local_version: local.hyphae_version.clone(),
            remote_version: remote.hyphae_version.clone(),
        });
    }

    // 7. Operator status & ratchet tracking.
    let mut warnings = Vec::new();
    if !missing_optional_capabilities.is_empty() {
        let missing_names: Vec<&str> = missing_optional_capabilities
            .iter()
            .map(CapabilityToken::as_str)
            .collect();
        warnings.push(format!(
            "Peer '{peer}' ({}) lacks optional capabilities: {}.",
            remote.hyphae_version,
            missing_names.join(", ")
        ));
    }

    let status = if warnings.is_empty() {
        NegotiationStatus::Ok
    } else {
        NegotiationStatus::Warn
    };

    let mut updated_seen = history.previously_seen_capabilities.clone();
    if history.accept_downgrade {
        updated_seen = remote.capabilities.clone();
    } else {
        updated_seen.extend(remote.capabilities.iter().cloned());
    }

    let updated_manifest_version =
        match (history.last_seen_manifest_version, remote.manifest_version) {
            (Some(prev), Some(curr)) => Some(prev.max(curr)),
            (None, Some(curr)) => Some(curr),
            (prev, None) => prev,
        };

    Ok(NegotiatedSession {
        agreed_protocol,
        shared_capabilities,
        missing_optional_capabilities,
        status,
        warnings,
        updated_manifest_version,
        updated_seen_capabilities: updated_seen,
    })
}

// ---- Optional Read-Only A2A AgentCard Projection (§6.4) ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    pub name: String,
    pub description: String,
    pub url: String,
    pub version: String,
    pub kid: String,
    pub capabilities: AgentCardCapabilities,
    pub authentication: AgentCardAuth,
    pub skills: Vec<AgentCardSkill>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCardCapabilities {
    pub streaming: bool,
    pub push_notifications: bool,
    pub e2ee: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCardAuth {
    pub schemes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCardSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8037_appendix_a3_ed25519_jwk_thumbprint_vector() {
        // Official RFC 8037 Appendix A.3 test vector for Ed25519 JWK Thumbprint (RFC 7638).
        let jwk = OkpJwk {
            kty: "OKP".to_string(),
            crv: OkpCurve::Ed25519,
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_string(),
        };
        let kid = jwk.thumbprint_sha256().unwrap();
        assert_eq!(kid, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    fn sample_manifest(
        node: &str,
        version: &str,
        manifest_version: u64,
        caps: Vec<CapabilityToken>,
    ) -> NodeManifestPayload {
        let sign = OkpJwk::new(OkpCurve::Ed25519, &[7u8; 32]);
        let enc = OkpJwk::new(OkpCurve::X25519, &[9u8; 32]);
        let kid = sign.thumbprint_sha256().unwrap();
        NodeManifestPayload {
            v: 1,
            node_id: NodeId::new(node).unwrap(),
            profile: NodeProfile::Router,
            hyphae_version: version.to_string(),
            protocol_range: ProtocolRange { min: 1, max: 2 },
            manifest_version,
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-01-02T00:00:00Z".to_string(),
            audience: "alice@macbook".to_string(),
            identity: ManifestIdentity {
                signing_jwk: sign,
                encryption_jwk: enc,
                kid,
                admin_jwk: None,
            },
            capabilities: caps,
            policy: ManifestPolicy {
                require_pairing: true,
                require_e2ee: false,
                max_text_bytes: 32 * 1024,
                max_transfer_bytes: 50 * 1024 * 1024,
            },
            advertised: AdvertisedResources {
                topics: vec![AdvertisedTopic {
                    topic: "github".to_string(),
                    kind: Some("github-webhook".to_string()),
                    description: Some("Org GitHub events".to_string()),
                }],
                channels: vec!["#incidents".to_string()],
                kv_namespaces: vec![],
                rpc_commands: vec![],
            },
            escalation: None,
        }
    }

    #[test]
    fn manifest_validation_and_public_leak_guard() {
        let mut m = sample_manifest(
            "acme-team",
            "2.2.0",
            1,
            vec![CapabilityToken::ManifestV1, CapabilityToken::DmE2eeV1],
        );
        m.validate().unwrap();

        // Public manifest with advertised topics MUST fail closed!
        m.audience = "public".to_string();
        assert!(matches!(
            m.validate(),
            Err(ManifestError::PublicManifestLeak)
        ));

        m.advertised = AdvertisedResources::default();
        m.validate().unwrap();
        let card = m.to_a2a_agent_card("https://mesh.acme.internal");
        assert!(card.skills.is_empty());
    }

    #[test]
    fn negotiation_matrix_anti_rollback_and_anti_downgrade() {
        let local_m = sample_manifest(
            "alice@macbook",
            "2.2.0",
            1,
            vec![
                CapabilityToken::DmV1,
                CapabilityToken::DmE2eeV1,
                CapabilityToken::ChannelE2eeV1,
                CapabilityToken::KvE2eeV1,
                CapabilityToken::EventsV1,
            ],
        );
        let remote_m = sample_manifest(
            "acme-team",
            "2.0.1",
            5,
            vec![
                CapabilityToken::DmV1,
                CapabilityToken::DmE2eeV1,
                CapabilityToken::ChannelE2eeV1,
                CapabilityToken::EventsV1,
            ],
        );
        let local = PeerCapabilitiesView::from_manifest(&local_m);
        let remote = PeerCapabilitiesView::from_manifest(&remote_m);

        // Full negotiation -> WARN because remote lacks kv.e2ee.v1.
        let res = negotiate_capabilities(
            &local,
            &remote,
            "alice@macbook",
            "2026-01-01T12:00:00Z",
            E2eePolicy::Required,
            &PeerTrustHistory::default(),
        )
        .unwrap();
        assert_eq!(res.agreed_protocol, 2);
        assert_eq!(res.status, NegotiationStatus::Warn);
        assert!(res.shared_capabilities.contains(&CapabilityToken::DmE2eeV1));
        assert!(
            res.missing_optional_capabilities
                .contains(&CapabilityToken::KvE2eeV1)
        );

        // Anti-rollback: older manifestVersion 4 < 5 MUST fail closed!
        let history = PeerTrustHistory {
            last_seen_manifest_version: res.updated_manifest_version,
            previously_seen_capabilities: res.updated_seen_capabilities,
            accept_downgrade: false,
        };
        let older_m = sample_manifest("acme-team", "2.0.1", 4, remote_m.capabilities.clone());
        let err = negotiate_capabilities(
            &local,
            &PeerCapabilitiesView::from_manifest(&older_m),
            "alice@macbook",
            "2026-01-01T12:00:00Z",
            E2eePolicy::Required,
            &history,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            NegotiationError::ManifestRollbackDetected { .. }
        ));
        assert_eq!(err.to_problem_details().error, "manifest_rollback_detected");

        // Anti-downgrade: dropping dm.e2ee.v1 MUST fail closed!
        let downgraded_m = sample_manifest(
            "acme-team",
            "2.0.1",
            6,
            vec![CapabilityToken::DmV1, CapabilityToken::EventsV1],
        );
        let err2 = negotiate_capabilities(
            &local,
            &PeerCapabilitiesView::from_manifest(&downgraded_m),
            "alice@macbook",
            "2026-01-01T12:00:00Z",
            E2eePolicy::Prefer,
            &history,
        )
        .unwrap_err();
        assert!(matches!(
            err2,
            NegotiationError::CapabilityDowngradeDetected { .. }
        ));
        assert_eq!(
            err2.to_problem_details().error,
            "capability_downgrade_detected"
        );
    }

    #[test]
    fn human_auth_and_drop_relay_capability_tokens_roundtrip() {
        for (tok, expected) in [
            (CapabilityToken::HumanAuthV1, "human.auth.v1"),
            (CapabilityToken::DropRelayV1, "drop.relay.v1"),
        ] {
            assert_eq!(tok.as_str(), expected);
            assert_eq!(CapabilityToken::from_token_str(expected).unwrap(), tok);
            let encoded = serde_json::to_string(&tok).unwrap();
            assert_eq!(encoded, format!("\"{expected}\""));
            let decoded: CapabilityToken = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, tok);
            assert!(!tok.is_anti_downgrade_security_cap());
        }
    }
}
