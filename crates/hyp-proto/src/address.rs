//! Validators, strongly-typed identifiers, and qualified namespace resolution
//! matching `src/core/address.ts`, `src/core/router/cloudevent.ts`, `src/protocol.ts`,
//! and Hyphae v2 Architecture §2.1.

use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Reserved node identifier denoting the local node itself.
pub const LOCAL_NODE_ID: &str = "local";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AddressError {
    #[error("invalid node id {0:?}: must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/")]
    InvalidNodeId(String),
    #[error("invalid handle {0:?}: must match /^[a-z0-9][a-z0-9._-]{{0,63}}$/")]
    InvalidHandle(String),
    #[error("invalid channel {0:?}: must match /^#[a-z0-9][a-z0-9._-]{{0,62}}$/")]
    InvalidChannel(String),
    #[error("invalid topic {0:?}: must match /^[a-z0-9][a-z0-9._-]{{0,63}}$/")]
    InvalidTopic(String),
    #[error("invalid address {0:?}: expected <node-id>/<handle>")]
    InvalidAddress(String),
    #[error("invalid bridge target {0:?}: expected [local.|<node>/]<bridge>:<target>")]
    InvalidBridgeTarget(String),
    #[error("invalid kv path {0:?}: expected [<node>.]kv/<namespace>/<key>")]
    InvalidKvPath(String),
    #[error("cannot resolve qualified topic {0:?}")]
    UnresolvedTopic(String),
    #[error("peer alias {0:?} is reserved or conflicts with existing peer {1:?}")]
    PeerAliasConflict(String, String),
}

/// Validates a Hyphae `NodeId` / v1 `connectorId` (`/^[a-z0-9][a-z0-9@._-]{0,63}$/`).
pub fn is_valid_node_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !is_lower_alnum(bytes[0]) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| is_lower_alnum(b) || matches!(b, b'@' | b'.' | b'_' | b'-'))
}

/// Validates a Hyphae `Handle` (`/^[a-z0-9][a-z0-9._-]{0,63}$/`).
pub fn is_valid_handle(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !is_lower_alnum(bytes[0]) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| is_lower_alnum(b) || matches!(b, b'.' | b'_' | b'-'))
}

/// Validates a Hyphae `Channel` (`/^#[a-z0-9][a-z0-9._-]{0,62}$/`).
pub fn is_valid_channel(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes.len() > 64 || bytes[0] != b'#' {
        return false;
    }
    if !is_lower_alnum(bytes[1]) {
        return false;
    }
    bytes[2..]
        .iter()
        .all(|&b| is_lower_alnum(b) || matches!(b, b'.' | b'_' | b'-'))
}

/// Validates a Hyphae `Topic` (`/^[a-z0-9][a-z0-9._-]{0,63}$/`).
pub fn is_valid_topic(value: &str) -> bool {
    is_valid_handle(value)
}

/// Validates a KV namespace (`/^[a-z0-9][a-z0-9._-]{0,63}$/`).
pub fn is_valid_kv_namespace(value: &str) -> bool {
    is_valid_handle(value)
}

/// Validates a KV key (1..=256 chars, no whitespace/control chars, no leading/trailing `/`, no `..` path traversal).
pub fn is_valid_kv_key(value: &str) -> bool {
    if value.is_empty() || value.len() > 256 {
        return false;
    }
    if value.starts_with('/') || value.ends_with('/') || value.contains("//") {
        return false;
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    !value.split('/').any(|seg| seg == "." || seg == "..")
}

/// Validates a bridge target name (non-empty, <= 128 bytes, no whitespace/control chars).
pub fn is_valid_bridge_target_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

#[inline]
fn is_lower_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

macro_rules! validated_string_type {
    ($name:ident, $validator:ident, $err:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, AddressError> {
                let s = value.into();
                if $validator(&s) {
                    Ok(Self(s))
                } else {
                    Err(AddressError::$err(s))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = AddressError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = AddressError;
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = AddressError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

validated_string_type!(
    NodeId,
    is_valid_node_id,
    InvalidNodeId,
    "Canonical node identifier (v1 `connectorId`), matching `/^[a-z0-9][a-z0-9@._-]{0,63}$/`."
);
validated_string_type!(
    Handle,
    is_valid_handle,
    InvalidHandle,
    "Agent handle on a node, matching `/^[a-z0-9][a-z0-9._-]{0,63}$/`."
);
validated_string_type!(
    Channel,
    is_valid_channel,
    InvalidChannel,
    "Room / channel name, matching `/^#[a-z0-9][a-z0-9._-]{0,62}$/`."
);
validated_string_type!(
    Topic,
    is_valid_topic,
    InvalidTopic,
    "Event stream topic name, matching `/^[a-z0-9][a-z0-9._-]{0,63}$/`."
);

impl NodeId {
    /// Returns `true` if this identifier is the reserved `"local"` node alias.
    pub fn is_local(&self) -> bool {
        self.0 == LOCAL_NODE_ID
    }
}

impl Channel {
    /// Normalizes a human/agent channel string (`"incidents"` or `" #Deploys.Prod_1 "` -> `"#deploys.prod_1"`),
    /// matching `normalizeChannelName` in `src/protocol.ts`.
    pub fn normalize(raw: &str) -> Result<Self, AddressError> {
        let trimmed = raw.trim().to_ascii_lowercase();
        let with_hash = if trimmed.starts_with('#') {
            trimmed
        } else {
            format!("#{trimmed}")
        };
        Self::new(with_hash)
    }
}

/// v1 / canonical `<node-id>/<handle>` mesh address (matching `src/core/address.ts`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    pub node_id: NodeId,
    pub handle: Handle,
}

impl Address {
    /// Parses `<node-id>/<handle>` by splitting on the last `/` (matching `parseAddress` in `src/core/address.ts`).
    pub fn parse(value: &str) -> Result<Self, AddressError> {
        let Some(slash) = value.rfind('/') else {
            return Err(AddressError::InvalidAddress(value.to_string()));
        };
        let node_part = &value[..slash];
        let handle_part = &value[slash + 1..];
        let node_id =
            NodeId::new(node_part).map_err(|_| AddressError::InvalidAddress(value.to_string()))?;
        let handle = Handle::new(handle_part)
            .map_err(|_| AddressError::InvalidAddress(value.to_string()))?;
        Ok(Self { node_id, handle })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.node_id, self.handle)
    }
}

impl FromStr for Address {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Whether a resolved entity lives on this local Node or a specific remote peer Node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeScope {
    Local,
    Remote(NodeId),
}

impl NodeScope {
    pub fn from_node_id(node_id: NodeId) -> Self {
        if node_id.is_local() {
            Self::Local
        } else {
            Self::Remote(node_id)
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Local => LOCAL_NODE_ID,
            Self::Remote(id) => id.as_str(),
        }
    }

    /// Expands `Local` into the concrete `self_node_id`.
    pub fn concrete_node_id<'a>(&'a self, self_node_id: &'a NodeId) -> &'a NodeId {
        match self {
            Self::Local => self_node_id,
            Self::Remote(id) => id,
        }
    }
}

impl fmt::Display for NodeScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolved event topic reference: `local.<topic>` or `<node-id>.<topic>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QualifiedTopic {
    pub node: NodeScope,
    pub topic: Topic,
}

impl fmt::Display for QualifiedTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.node, self.topic)
    }
}

/// Resolves an event topic reference using §2.1 deterministic longest-prefix peer matching:
/// - `local.<topic>` always targets `NodeScope::Local`.
/// - `<peer>.<topic>` matches the **longest** known peer ID in `known_peers` followed by `.`
///   whose suffix is a valid `Topic` (so `public.hyphae.to.github` splits into
///   `peer = "public.hyphae.to"`, `topic = "github"`).
/// - Bare `<topic>` (v1 shorthand) resolves against `default_node`.
pub fn resolve_topic(
    input: &str,
    known_peers: &[NodeId],
    default_node: &NodeScope,
) -> Result<QualifiedTopic, AddressError> {
    if let Some(rest) = input.strip_prefix("local.") {
        let topic = Topic::new(rest)?;
        return Ok(QualifiedTopic {
            node: NodeScope::Local,
            topic,
        });
    }

    // Longest-prefix match across paired peers.
    let mut best: Option<(&NodeId, Topic)> = None;
    for peer in known_peers {
        if peer.is_local() {
            continue;
        }
        let prefix = peer.as_str();
        if input.len() > prefix.len() + 1
            && input.starts_with(prefix)
            && input.as_bytes()[prefix.len()] == b'.'
        {
            let rest = &input[prefix.len() + 1..];
            if let Ok(topic) = Topic::new(rest) {
                match &best {
                    Some((best_peer, _)) if best_peer.as_str().len() >= prefix.len() => {}
                    _ => best = Some((peer, topic)),
                }
            }
        }
    }
    if let Some((peer, topic)) = best {
        return Ok(QualifiedTopic {
            node: NodeScope::Remote(peer.clone()),
            topic,
        });
    }

    // v1 shorthand: bare `<topic>`
    if let Ok(topic) = Topic::new(input) {
        return Ok(QualifiedTopic {
            node: default_node.clone(),
            topic,
        });
    }

    Err(AddressError::UnresolvedTopic(input.to_string()))
}

/// Checks that a newly added peer alias does not collide with `local` or an existing peer.
pub fn validate_new_peer_alias(
    candidate: &NodeId,
    existing_peers: &[NodeId],
) -> Result<(), AddressError> {
    if candidate.is_local() {
        return Err(AddressError::PeerAliasConflict(
            candidate.to_string(),
            LOCAL_NODE_ID.to_string(),
        ));
    }
    for peer in existing_peers {
        if peer == candidate {
            return Err(AddressError::PeerAliasConflict(
                candidate.to_string(),
                peer.to_string(),
            ));
        }
    }
    Ok(())
}

/// Direct agent peer target: `<handle>`, `<node>/<handle>`, or `<hub>!<node>/<handle>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerTarget {
    /// Direct or default-routed peer: `local/<handle>`, `<node>/<handle>`, or shorthand `<handle>`.
    Direct { node: NodeScope, handle: Handle },
    /// Explicitly hub-routed peer disambiguating dual routes: `<hub>!<node>/<handle>`.
    ViaHub {
        hub: NodeId,
        node: NodeId,
        handle: Handle,
    },
}

impl PeerTarget {
    /// Parses `<hub>!<node>/<handle>`, `<node>/<handle>`, or shorthand `<handle>` (resolved as `local/<handle>`).
    pub fn parse(input: &str) -> Result<Self, AddressError> {
        if let Some((hub_part, rest)) = input.split_once('!') {
            let hub = NodeId::new(hub_part)?;
            if hub.is_local() {
                return Err(AddressError::InvalidAddress(input.to_string()));
            }
            let addr = Address::parse(rest)?;
            if addr.node_id.is_local() {
                return Err(AddressError::InvalidAddress(input.to_string()));
            }
            return Ok(Self::ViaHub {
                hub,
                node: addr.node_id,
                handle: addr.handle,
            });
        }
        if input.contains('/') {
            let addr = Address::parse(input)?;
            return Ok(Self::Direct {
                node: NodeScope::from_node_id(addr.node_id),
                handle: addr.handle,
            });
        }
        let handle = Handle::new(input)?;
        Ok(Self::Direct {
            node: NodeScope::Local,
            handle,
        })
    }
}

impl fmt::Display for PeerTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct { node, handle } => write!(f, "{node}/{handle}"),
            Self::ViaHub { hub, node, handle } => write!(f, "{hub}!{node}/{handle}"),
        }
    }
}

/// Qualified `#channel` reference: `<node-id>/#channel`, `local/#channel`, or shorthand `#channel`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QualifiedChannel {
    pub node: NodeScope,
    pub channel: Channel,
}

impl QualifiedChannel {
    /// Resolves `<node-id>/#channel`, `local/#channel`, or bare `#channel` against `default_node`.
    pub fn resolve(input: &str, default_node: &NodeScope) -> Result<Self, AddressError> {
        if let Some((node_part, chan_part)) = input.split_once('/') {
            let node_id = NodeId::new(node_part)?;
            let channel = Channel::new(chan_part)?;
            return Ok(Self {
                node: NodeScope::from_node_id(node_id),
                channel,
            });
        }
        let channel = Channel::new(input)?;
        Ok(Self {
            node: default_node.clone(),
            channel,
        })
    }
}

impl fmt::Display for QualifiedChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.node, self.channel)
    }
}

/// Chat bridge sink reference: `<bridge>:<target>`, `local.<bridge>:<target>`, or `<node>/<bridge>:<target>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QualifiedBridgeTarget {
    pub node: NodeScope,
    pub bridge: Topic,
    pub target: String,
}

impl QualifiedBridgeTarget {
    /// Parses `<bridge>:<target>`, `local.<bridge>:<target>`, or `<node>/<bridge>:<target>`.
    pub fn parse(input: &str) -> Result<Self, AddressError> {
        let Some((lhs, target_part)) = input.split_once(':') else {
            return Err(AddressError::InvalidBridgeTarget(input.to_string()));
        };
        if !is_valid_bridge_target_name(target_part) {
            return Err(AddressError::InvalidBridgeTarget(input.to_string()));
        }

        let (node, bridge_str) = if let Some((node_part, bridge_part)) = lhs.split_once('/') {
            let node_id = NodeId::new(node_part)
                .map_err(|_| AddressError::InvalidBridgeTarget(input.to_string()))?;
            (NodeScope::from_node_id(node_id), bridge_part)
        } else if let Some(rest) = lhs.strip_prefix("local.") {
            (NodeScope::Local, rest)
        } else {
            (NodeScope::Local, lhs)
        };

        let bridge = Topic::new(bridge_str)
            .map_err(|_| AddressError::InvalidBridgeTarget(input.to_string()))?;
        Ok(Self {
            node,
            bridge,
            target: target_part.to_string(),
        })
    }
}

impl fmt::Display for QualifiedBridgeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.node {
            NodeScope::Local => write!(f, "local.{}:{}", self.bridge, self.target),
            NodeScope::Remote(id) => write!(f, "{}/{}:{}", id, self.bridge, self.target),
        }
    }
}

/// Shared KV path reference: `<node-id>.kv/<namespace>/<key>`, `local.kv/<ns>/<key>`, or `kv/<ns>/<key>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QualifiedKvPath {
    pub node: NodeScope,
    pub namespace: String,
    pub key: String,
}

impl QualifiedKvPath {
    /// Parses `<node-id>.kv/<namespace>/<key>`, `local.kv/<namespace>/<key>`,
    /// or shorthand `kv/<namespace>/<key>` (using `default_node`).
    pub fn resolve(input: &str, default_node: &NodeScope) -> Result<Self, AddressError> {
        let (node, rest) = if let Some(rest) = input.strip_prefix("local.kv/") {
            (NodeScope::Local, rest)
        } else if let Some(rest) = input.strip_prefix("kv/") {
            (default_node.clone(), rest)
        } else if let Some((head, rest)) = input.split_once(".kv/") {
            let node_id =
                NodeId::new(head).map_err(|_| AddressError::InvalidKvPath(input.to_string()))?;
            (NodeScope::from_node_id(node_id), rest)
        } else {
            return Err(AddressError::InvalidKvPath(input.to_string()));
        };

        let Some((ns, key)) = rest.split_once('/') else {
            return Err(AddressError::InvalidKvPath(input.to_string()));
        };
        if !is_valid_kv_namespace(ns) || !is_valid_kv_key(key) {
            return Err(AddressError::InvalidKvPath(input.to_string()));
        }
        Ok(Self {
            node,
            namespace: ns.to_string(),
            key: key.to_string(),
        })
    }
}

impl fmt::Display for QualifiedKvPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.kv/{}/{}", self.node, self.namespace, self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_peer_resolution_handles_dotted_nodes() {
        let peers = vec![
            NodeId::new("public").unwrap(),
            NodeId::new("public.hyphae.to").unwrap(),
            NodeId::new("alice.smith@macbook").unwrap(),
            NodeId::new("acme-team").unwrap(),
        ];
        let local_default = NodeScope::Local;

        let resolved = resolve_topic("public.hyphae.to.github", &peers, &local_default).unwrap();
        assert_eq!(
            resolved.node,
            NodeScope::Remote(NodeId::new("public.hyphae.to").unwrap())
        );
        assert_eq!(resolved.topic.as_str(), "github");

        let resolved2 =
            resolve_topic("alice.smith@macbook.ci.builds", &peers, &local_default).unwrap();
        assert_eq!(
            resolved2.node,
            NodeScope::Remote(NodeId::new("alice.smith@macbook").unwrap())
        );
        assert_eq!(resolved2.topic.as_str(), "ci.builds");

        let local = resolve_topic("local.github-public", &peers, &local_default).unwrap();
        assert_eq!(local.node, NodeScope::Local);
        assert_eq!(local.topic.as_str(), "github-public");

        // Shorthand falls back to default_node.
        let bare = resolve_topic(
            "github",
            &peers,
            &NodeScope::Remote(NodeId::new("acme-team").unwrap()),
        )
        .unwrap();
        assert_eq!(
            bare.node,
            NodeScope::Remote(NodeId::new("acme-team").unwrap())
        );
        assert_eq!(bare.topic.as_str(), "github");
    }

    #[test]
    fn peer_target_and_channel_and_bridge_and_kv_parsers() {
        assert_eq!(
            PeerTarget::parse("codex").unwrap(),
            PeerTarget::Direct {
                node: NodeScope::Local,
                handle: Handle::new("codex").unwrap()
            }
        );
        assert_eq!(
            PeerTarget::parse("alice@macbook/claude").unwrap(),
            PeerTarget::Direct {
                node: NodeScope::Remote(NodeId::new("alice@macbook").unwrap()),
                handle: Handle::new("claude").unwrap()
            }
        );
        assert_eq!(
            PeerTarget::parse("acme-team!bob@laptop/codex").unwrap(),
            PeerTarget::ViaHub {
                hub: NodeId::new("acme-team").unwrap(),
                node: NodeId::new("bob@laptop").unwrap(),
                handle: Handle::new("codex").unwrap()
            }
        );

        let ch = QualifiedChannel::resolve("acme-team/#incidents", &NodeScope::Local).unwrap();
        assert_eq!(ch.to_string(), "acme-team/#incidents");

        let ch_norm = Channel::normalize("  #Deploys.Prod_1  ").unwrap();
        assert_eq!(ch_norm.as_str(), "#deploys.prod_1");

        let br_local = QualifiedBridgeTarget::parse("slack:ops").unwrap();
        assert_eq!(br_local.node, NodeScope::Local);
        assert_eq!(br_local.bridge.as_str(), "slack");
        assert_eq!(br_local.target, "ops");

        let br_remote = QualifiedBridgeTarget::parse("acme-team/slack:C01234").unwrap();
        assert_eq!(br_remote.to_string(), "acme-team/slack:C01234");

        let kv =
            QualifiedKvPath::resolve("public.hyphae.to.kv/deploys/checkout/v2", &NodeScope::Local)
                .unwrap();
        assert_eq!(
            kv.node,
            NodeScope::Remote(NodeId::new("public.hyphae.to").unwrap())
        );
        assert_eq!(kv.namespace, "deploys");
        assert_eq!(kv.key, "checkout/v2");

        let kv_short = QualifiedKvPath::resolve(
            "kv/shared/plan",
            &NodeScope::Remote(NodeId::new("acme-team").unwrap()),
        )
        .unwrap();
        assert_eq!(kv_short.to_string(), "acme-team.kv/shared/plan");

        // Reject traversal in KV key.
        assert!(QualifiedKvPath::resolve("local.kv/shared/../secret", &NodeScope::Local).is_err());
    }
}
