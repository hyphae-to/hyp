//! Pure metadata-only digest selection and rendering; no runtime or storage access.

pub mod packer;
pub mod selection;
mod urgency;

pub use packer::{InboxDigest, PackableItem, PackedDeliveryBatch, pack_inbox_digest};
pub use selection::{BuiltDigestBatch, DigestCandidate, DigestPolicy, DrainScope, build_digest};
pub use urgency::{DeliveryError, DeliveryUrgency};
