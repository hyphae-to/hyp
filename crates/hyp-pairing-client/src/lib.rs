//! Blocking clients for pairing and enrollment over node HTTP and SSH transports.
//! Call from a synchronous thread outside a Tokio runtime, or via `spawn_blocking`.
//! Callers own peer pin checks against local state, credential storage and offline fallback.

mod enrollment;
mod handshake;
mod manifest;

pub use enrollment::{
    DelegatedEnrollSuccess, GuestEnrollOutcome, attempt_delegated_pair_enroll,
    attempt_guest_self_enroll,
};
pub use handshake::{
    LiveAm2HandshakeResult, LiveHandshakeError, LiveP2pHandshakeResult, execute_live_am2_handshake,
    execute_live_p2p_handshake,
};
pub use manifest::{VerifiedLiveManifest, fetch_and_verify_manifest};

const MAX_MANIFEST_RESPONSE_BYTES: usize = 512 * 1024;
const MANIFEST_FETCH_TIMEOUT_SECS: u64 = 10;
