//! Hyphae v2 cryptography, E2EE envelopes, streaming transfers, v1 `t3-mesh` interop,
//! and zero-leak OS keystore.

pub use hyp_proto::PROTOCOL_VERSION;

mod armor;
mod compare;
pub mod compat_v1;
pub mod e2ee;
pub mod error;
pub mod hpke;
pub mod human;
pub mod jcs;
pub mod keys;
pub mod keystore;
pub mod manifest;
pub mod pairing;
pub mod rfc3339;
pub mod transfer;
mod x25519;

pub use compare::constant_time_eq;
pub use error::CryptoError;
pub use keys::{
    Ed25519KeyPair, Ed25519PublicKey, NodeIdentityKeys, OkpJwk, SignedPayload, X25519KeyPair,
    X25519PublicKey,
};
pub use keystore::{SecretBackend, SecretStore};
