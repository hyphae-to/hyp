//! Federation, pairing, keys & manifest trust store (`peers`, `grants`, `revocations`,
//! `peer_keys`) with strict monotonic `manifest_version` anti-rollback,
//! E2EE capability anti-downgrade ratcheting, single-use pairing grant claims, and directory
//! checkpoint anti-rollback protection.

use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::NodeDb;
use crate::error::{StoreError, StoreResult};
use crate::types::{
    GrantDirection, KeyStatus, KeyUse, PeerProfile, PeerStatus, TrustTier, is_node_id,
};

/// Input to register or update a paired peer node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInput {
    pub peer_id: String,
    pub endpoint: Option<String>,
    pub profile: PeerProfile,
    pub trust_tier: TrustTier,
    pub status: PeerStatus,
    pub scopes: Vec<String>,
    /// Keychain / secret reference name (never plaintext secrets).
    pub auth_credential_ref: Option<String>,
}

/// Persisted paired peer record including verified manifest cache & E2EE downgrade ratchet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub peer_id: String,
    pub endpoint: Option<String>,
    pub profile: PeerProfile,
    pub trust_tier: TrustTier,
    pub status: PeerStatus,
    pub scopes: Vec<String>,
    pub auth_credential_ref: Option<String>,
    pub manifest_json: Option<String>,
    pub manifest_version: i64,
    pub manifest_etag: Option<String>,
    pub manifest_fetched_at: Option<i64>,
    pub observed_e2ee_caps: Vec<String>,
    /// Delegated human authority ID that admitted this peer via `POST /v1/pair/delegated`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_by_human_id: Option<String>,
    /// Monotonic human `auth_epoch` pinned when this peer was admitted via delegated human cert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_auth_epoch: Option<u64>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Update applied to a peer's verified signed capability manifest cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestCacheUpdate {
    pub manifest_version: i64,
    pub manifest_json: String,
    pub etag: Option<String>,
    /// All capability tokens advertised in the verified manifest.
    pub capabilities: Vec<String>,
    /// Explicit operator override (`hyp peer trust --accept-downgrade <peer>`) permitting
    /// previously observed E2EE capability tokens to disappear.
    pub accept_downgrade: bool,
}

/// Input to store a signed pairing grant (`am2_` / `hp2p1_` / legacy `t3mp1_`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantInput {
    pub id: String,
    pub peer_id: String,
    pub direction: GrantDirection,
    pub signed_json: String,
    pub scopes: Vec<String>,
    pub trust_tier: TrustTier,
    pub issued_at: i64,
    pub pair_by: Option<i64>,
    pub expires_at: Option<i64>,
}

/// Persisted grant record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    pub id: String,
    pub peer_id: String,
    pub direction: GrantDirection,
    pub signed_json: String,
    pub scopes: Vec<String>,
    pub trust_tier: TrustTier,
    pub issued_at: i64,
    pub pair_by: Option<i64>,
    pub expires_at: Option<i64>,
    pub entry_json: Option<String>,
    pub paired_at: Option<i64>,
}

/// Input to record a signed grant revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationInput {
    pub grant_id: String,
    pub peer_id: String,
    pub signed_json: String,
}

/// Persisted revocation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub grant_id: String,
    pub peer_id: String,
    pub signed_json: String,
    pub revoked_at: i64,
}

/// Input to store a peer's RFC 7517 OKP JWK keyed by `(peer_id, kid)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerKeyInput {
    pub peer_id: String,
    pub kid: String,
    pub key_use: KeyUse,
    pub jwk_json: String,
    pub status: KeyStatus,
    pub expires_at: Option<i64>,
}

/// Persisted peer JWK record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerKeyRecord {
    pub peer_id: String,
    pub kid: String,
    pub key_use: KeyUse,
    pub jwk_json: String,
    pub status: KeyStatus,
    pub registered_at: i64,
    pub expires_at: Option<i64>,
}

/// Persisted multi-hub route directing traffic for `target_node` through `via_peer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRoute {
    pub target_node: String,
    pub via_peer: String,
    pub updated_at: i64,
}

/// Federation, pairing & manifest trust store view borrowed from [`NodeDb`].
pub struct PeerStore<'a> {
    db: &'a NodeDb,
}

impl<'a> PeerStore<'a> {
    pub(crate) fn new(db: &'a NodeDb) -> Self {
        Self { db }
    }

    // ---- Peers & Manifest Cache ----

    /// Registers or updates a paired peer record (preserving existing manifest cache & E2EE ratchet).
    pub fn upsert_peer(&self, input: &PeerInput, now_ms: i64) -> StoreResult<PeerRecord> {
        if !is_node_id(&input.peer_id) || input.peer_id == "local" {
            return Err(StoreError::InvalidInput(format!(
                "invalid peer_id '{}' ('local' is reserved)",
                input.peer_id
            )));
        }
        let scopes_json = serde_json::to_string(&input.scopes)?;
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "INSERT INTO peers
             (peer_id, endpoint, profile, trust_tier, status, scopes_json, auth_credential_ref,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(peer_id) DO UPDATE SET
               endpoint = excluded.endpoint,
               profile = excluded.profile,
               trust_tier = excluded.trust_tier,
               status = excluded.status,
               scopes_json = excluded.scopes_json,
               auth_credential_ref = excluded.auth_credential_ref,
               updated_at = excluded.updated_at",
            params![
                &input.peer_id,
                input.endpoint.as_deref(),
                input.profile.as_str(),
                input.trust_tier.as_str(),
                input.status.as_str(),
                &scopes_json,
                input.auth_credential_ref.as_deref(),
                now_ms
            ],
        )?;
        if input.status == PeerStatus::Revoked {
            tx.conn().execute(
                "DELETE FROM peer_routes WHERE via_peer = ?1",
                params![&input.peer_id],
            )?;
            let _ = delete_peer_bearer_tokens_in_conn(tx.conn(), &input.peer_id)?;
        }
        let record = tx.conn().query_row(
            "SELECT * FROM peers WHERE peer_id = ?1",
            params![&input.peer_id],
            decode_peer_row,
        )??;
        tx.commit()?;
        Ok(record)
    }

    /// Registers or updates a paired peer record while explicitly setting delegated human
    /// admission provenance (`admitted_by_human_id`, `admitted_auth_epoch`).
    pub fn upsert_peer_with_admission(
        &self,
        input: &PeerInput,
        admitted_by_human_id: Option<&str>,
        admitted_auth_epoch: Option<u64>,
        now_ms: i64,
    ) -> StoreResult<PeerRecord> {
        if !is_node_id(&input.peer_id) || input.peer_id == "local" {
            return Err(StoreError::InvalidInput(format!(
                "invalid peer_id '{}' ('local' is reserved)",
                input.peer_id
            )));
        }
        if let Some(hid) = admitted_by_human_id {
            if !is_node_id(hid) || hid == "local" {
                return Err(StoreError::InvalidInput(format!(
                    "invalid admitted_by_human_id '{hid}'"
                )));
            }
        }
        let epoch_i64 = match admitted_auth_epoch {
            Some(0) => {
                return Err(StoreError::InvalidInput(
                    "admitted_auth_epoch must be >= 1".to_string(),
                ));
            }
            Some(ep) => Some(i64::try_from(ep).map_err(|_| {
                StoreError::InvalidInput("admitted_auth_epoch exceeds SQLite i64 range".to_string())
            })?),
            None => None,
        };
        let scopes_json = serde_json::to_string(&input.scopes)?;
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "INSERT INTO peers
             (peer_id, endpoint, profile, trust_tier, status, scopes_json, auth_credential_ref,
              admitted_by_human_id, admitted_auth_epoch, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
             ON CONFLICT(peer_id) DO UPDATE SET
               endpoint = excluded.endpoint,
               profile = excluded.profile,
               trust_tier = excluded.trust_tier,
               status = excluded.status,
               scopes_json = excluded.scopes_json,
               auth_credential_ref = excluded.auth_credential_ref,
               admitted_by_human_id = excluded.admitted_by_human_id,
               admitted_auth_epoch = excluded.admitted_auth_epoch,
               updated_at = excluded.updated_at",
            params![
                &input.peer_id,
                input.endpoint.as_deref(),
                input.profile.as_str(),
                input.trust_tier.as_str(),
                input.status.as_str(),
                &scopes_json,
                input.auth_credential_ref.as_deref(),
                admitted_by_human_id,
                epoch_i64,
                now_ms
            ],
        )?;
        if input.status == PeerStatus::Revoked {
            tx.conn().execute(
                "DELETE FROM peer_routes WHERE via_peer = ?1",
                params![&input.peer_id],
            )?;
            let _ = delete_peer_bearer_tokens_in_conn(tx.conn(), &input.peer_id)?;
        }
        let record = tx.conn().query_row(
            "SELECT * FROM peers WHERE peer_id = ?1",
            params![&input.peer_id],
            decode_peer_row,
        )??;
        tx.commit()?;
        Ok(record)
    }

    /// Counts active peers admitted under `human_id`, optionally excluding `exclude_peer_id`
    /// (so idempotent re-pairing of the same device counts as 0 new devices against `max_devices`).
    pub fn count_active_peers_admitted_by_human(
        &self,
        human_id: &str,
        exclude_peer_id: Option<&str>,
    ) -> StoreResult<u32> {
        let count: i64 = if let Some(excl) = exclude_peer_id {
            self.db.conn().query_row(
                "SELECT COUNT(*) FROM peers
                 WHERE admitted_by_human_id = ?1 AND status = 'active' AND peer_id != ?2",
                params![human_id, excl],
                |row| row.get(0),
            )?
        } else {
            self.db.conn().query_row(
                "SELECT COUNT(*) FROM peers
                 WHERE admitted_by_human_id = ?1 AND status = 'active'",
                params![human_id],
                |row| row.get(0),
            )?
        };
        Ok(u32::try_from(count.max(0)).unwrap_or(u32::MAX))
    }

    /// Lists peers admitted under `human_id` ordered by `peer_id ASC`.
    pub fn list_peers_admitted_by_human(
        &self,
        human_id: &str,
        active_only: bool,
    ) -> StoreResult<Vec<PeerRecord>> {
        let sql = if active_only {
            "SELECT * FROM peers WHERE admitted_by_human_id = ?1 AND status = 'active' ORDER BY peer_id ASC"
        } else {
            "SELECT * FROM peers WHERE admitted_by_human_id = ?1 ORDER BY peer_id ASC"
        };
        let mut stmt = self.db.conn().prepare(sql)?;
        let rows = stmt
            .query_map(params![human_id], decode_peer_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }

    /// Atomically revokes ALL non-revoked peers admitted under `human_id`, deletes their
    /// `peer_routes` and stored `auth_token:*` bearer tokens inside a single `BEGIN IMMEDIATE`
    /// transaction, and returns the sorted list of revoked `peer_id`s.
    pub fn revoke_peers_admitted_by_human(
        &self,
        human_id: &str,
        now_ms: i64,
    ) -> StoreResult<Vec<String>> {
        let tx = self.db.immediate_tx()?;
        let revoked_ids: Vec<String> = {
            let mut stmt = tx.conn().prepare(
                "SELECT peer_id FROM peers
                 WHERE admitted_by_human_id = ?1 AND status != 'revoked'
                 ORDER BY peer_id ASC",
            )?;
            let mut rows = Vec::new();
            for row in stmt.query_map(params![human_id], |row| row.get::<_, String>(0))? {
                rows.push(row?);
            }
            rows
        };
        if !revoked_ids.is_empty() {
            tx.conn().execute(
                "UPDATE peers
                 SET status = 'revoked', updated_at = ?2
                 WHERE admitted_by_human_id = ?1 AND status != 'revoked'",
                params![human_id, now_ms],
            )?;
            for pid in &revoked_ids {
                tx.conn()
                    .execute("DELETE FROM peer_routes WHERE via_peer = ?1", params![pid])?;
                let _ = delete_peer_bearer_tokens_in_conn(tx.conn(), pid)?;
            }
        }
        tx.commit()?;
        Ok(revoked_ids)
    }

    pub fn get_peer(&self, peer_id: &str) -> StoreResult<Option<PeerRecord>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM peers WHERE peer_id = ?1",
                params![peer_id],
                decode_peer_row,
            )
            .optional()?
            .transpose()
    }

    pub fn list_peers(&self, status: Option<PeerStatus>) -> StoreResult<Vec<PeerRecord>> {
        if let Some(st) = status {
            let mut stmt = self
                .db
                .conn()
                .prepare("SELECT * FROM peers WHERE status = ?1 ORDER BY peer_id ASC")?;
            let rows = stmt
                .query_map(params![st.as_str()], decode_peer_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect()
        } else {
            let mut stmt = self
                .db
                .conn()
                .prepare("SELECT * FROM peers ORDER BY peer_id ASC")?;
            let rows = stmt
                .query_map([], decode_peer_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect()
        }
    }

    pub fn set_peer_status(
        &self,
        peer_id: &str,
        status: PeerStatus,
        now_ms: i64,
    ) -> StoreResult<bool> {
        let tx = self.db.immediate_tx()?;
        let changed = tx.conn().execute(
            "UPDATE peers SET status = ?1, updated_at = ?2 WHERE peer_id = ?3",
            params![status.as_str(), now_ms, peer_id],
        )?;
        if status == PeerStatus::Revoked {
            tx.conn().execute(
                "DELETE FROM peer_routes WHERE via_peer = ?1",
                params![peer_id],
            )?;
            let _ = delete_peer_bearer_tokens_in_conn(tx.conn(), peer_id)?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    pub fn delete_peer(&self, peer_id: &str) -> StoreResult<bool> {
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "DELETE FROM peer_routes WHERE via_peer = ?1",
            params![peer_id],
        )?;
        let _ = delete_peer_bearer_tokens_in_conn(tx.conn(), peer_id)?;
        let changed = tx
            .conn()
            .execute("DELETE FROM peers WHERE peer_id = ?1", params![peer_id])?;
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Atomically deletes all stored `auth_token:*` bearer token metadata records bound to
    /// `peer_id` (supporting both structured JSON `{ "peerId": ... }` and legacy plain
    /// `"<peer_id>"` metadata values). Returns the number of deleted tokens (`N1`).
    pub fn delete_bearer_tokens_for_peer(&self, peer_id: &str) -> StoreResult<usize> {
        let tx = self.db.immediate_tx()?;
        let deleted = delete_peer_bearer_tokens_in_conn(tx.conn(), peer_id)?;
        tx.commit()?;
        Ok(deleted)
    }

    /// Caches a verified signed Node Capability Manifest for `peer_id`.
    ///
    /// **Fail-closed security invariants:**
    /// 1. **Monotonic `manifest_version` anti-rollback:** Rejects any `manifest_version < current`
    ///    and rejects equivocation (`manifest_version == current` with differing `manifest_json`)
    ///    with [`StoreError::ManifestRollback`].
    /// 2. **E2EE capability anti-downgrade:** Any previously observed `.e2ee.` capability token
    ///    (e.g. `dm.e2ee.v1`, `channel.e2ee.v1`, `kv.e2ee.v1`, `events.e2ee.v1`) disappearing from
    ///    `capabilities` fails closed with [`StoreError::CapabilityDowngrade`] unless
    ///    `update.accept_downgrade == true`.
    pub fn cache_manifest(
        &self,
        peer_id: &str,
        update: &ManifestCacheUpdate,
        now_ms: i64,
    ) -> StoreResult<PeerRecord> {
        if update.manifest_version <= 0 {
            return Err(StoreError::InvalidInput(
                "manifest_version must be positive".to_string(),
            ));
        }

        let tx = self.db.immediate_tx()?;
        let current: PeerRecord = tx
            .conn()
            .query_row(
                "SELECT * FROM peers WHERE peer_id = ?1",
                params![peer_id],
                decode_peer_row,
            )
            .optional()?
            .transpose()?
            .ok_or_else(|| StoreError::NotFound(format!("peer '{peer_id}' not found")))?;

        // 1. Monotonic anti-rollback & same-version equivocation guard.
        if update.manifest_version < current.manifest_version {
            return Err(StoreError::ManifestRollback {
                peer_id: peer_id.to_string(),
                expected_min: current.manifest_version,
                received: update.manifest_version,
            });
        }
        if update.manifest_version == current.manifest_version {
            if let Some(prev_json) = &current.manifest_json {
                if prev_json != &update.manifest_json {
                    return Err(StoreError::ManifestRollback {
                        peer_id: peer_id.to_string(),
                        expected_min: current.manifest_version + 1,
                        received: update.manifest_version,
                    });
                }
            }
        }

        // 2. E2EE capability anti-downgrade check & forward ratchet.
        let prev_e2ee: BTreeSet<String> = current.observed_e2ee_caps.iter().cloned().collect();
        let new_e2ee: BTreeSet<String> = update
            .capabilities
            .iter()
            .filter(|cap| is_e2ee_capability(cap))
            .cloned()
            .collect();

        let missing: Vec<String> = prev_e2ee.difference(&new_e2ee).cloned().collect();
        if !missing.is_empty() && !update.accept_downgrade {
            return Err(StoreError::CapabilityDowngrade {
                peer_id: peer_id.to_string(),
                missing_capabilities: missing,
            });
        }

        let next_e2ee: Vec<String> = if update.accept_downgrade {
            new_e2ee.into_iter().collect()
        } else {
            prev_e2ee.union(&new_e2ee).cloned().collect()
        };
        let next_e2ee_json = serde_json::to_string(&next_e2ee)?;

        tx.conn().execute(
            "UPDATE peers
             SET manifest_json = ?1,
                 manifest_version = ?2,
                 manifest_etag = ?3,
                 manifest_fetched_at = ?4,
                 observed_e2ee_caps_json = ?5,
                 updated_at = ?4
             WHERE peer_id = ?6",
            params![
                &update.manifest_json,
                update.manifest_version,
                update.etag.as_deref(),
                now_ms,
                &next_e2ee_json,
                peer_id
            ],
        )?;

        let updated = tx.conn().query_row(
            "SELECT * FROM peers WHERE peer_id = ?1",
            params![peer_id],
            decode_peer_row,
        )??;
        tx.commit()?;
        Ok(updated)
    }

    // ---- Grants ----

    /// Stores a signed pairing grant (idempotent for identical `signed_json`, fails closed on
    /// conflicting content or already-expired `pair_by`).
    pub fn add_grant(&self, input: &GrantInput, now_ms: i64) -> StoreResult<GrantRecord> {
        if input.id.is_empty() {
            return Err(StoreError::InvalidInput(
                "grant id must be non-empty".to_string(),
            ));
        }
        if !is_node_id(&input.peer_id) {
            return Err(StoreError::InvalidInput(format!(
                "invalid peer_id '{}'",
                input.peer_id
            )));
        }
        let scopes_json = serde_json::to_string(&input.scopes)?;

        let tx = self.db.immediate_tx()?;
        let existing: Option<GrantRecord> = tx
            .conn()
            .query_row(
                "SELECT * FROM grants WHERE id = ?1",
                params![&input.id],
                decode_grant_row,
            )
            .optional()?
            .transpose()?;
        if let Some(prev) = existing {
            if prev.signed_json == input.signed_json {
                tx.commit()?;
                return Ok(prev);
            }
            return Err(StoreError::IdConflict(format!(
                "grant '{}' already exists with different content",
                input.id
            )));
        }

        if let Some(pair_by) = input.pair_by {
            if pair_by <= now_ms {
                return Err(StoreError::Expired(format!(
                    "grant '{}' pairing window has already ended",
                    input.id
                )));
            }
        }

        tx.conn().execute(
            "INSERT INTO grants
             (id, peer_id, direction, signed_json, scopes_json, trust_tier, issued_at, pair_by, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &input.id,
                &input.peer_id,
                input.direction.as_str(),
                &input.signed_json,
                &scopes_json,
                input.trust_tier.as_str(),
                input.issued_at,
                input.pair_by,
                input.expires_at
            ],
        )?;
        let saved = tx.conn().query_row(
            "SELECT * FROM grants WHERE id = ?1",
            params![&input.id],
            decode_grant_row,
        )??;
        tx.commit()?;
        Ok(saved)
    }

    pub fn get_grant(&self, id: &str) -> StoreResult<Option<GrantRecord>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM grants WHERE id = ?1",
                params![id],
                decode_grant_row,
            )
            .optional()?
            .transpose()
    }

    pub fn list_grants(&self, peer_id: Option<&str>) -> StoreResult<Vec<GrantRecord>> {
        if let Some(pid) = peer_id {
            let mut stmt = self.db.conn().prepare(
                "SELECT * FROM grants WHERE peer_id = ?1 ORDER BY issued_at ASC, id ASC",
            )?;
            let rows = stmt
                .query_map(params![pid], decode_grant_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect()
        } else {
            let mut stmt = self
                .db
                .conn()
                .prepare("SELECT * FROM grants ORDER BY issued_at ASC, id ASC")?;
            let rows = stmt
                .query_map([], decode_grant_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect()
        }
    }

    /// Atomically claims a single-use pairing grant inside `BEGIN IMMEDIATE` so two concurrent
    /// pairing attempts racing for the same grant cannot both succeed.
    pub fn claim_grant(&self, id: &str, entry_json: &str, now_ms: i64) -> StoreResult<GrantRecord> {
        let tx = self.db.immediate_tx()?;
        let grant: GrantRecord = tx
            .conn()
            .query_row(
                "SELECT * FROM grants WHERE id = ?1",
                params![id],
                decode_grant_row,
            )
            .optional()?
            .transpose()?
            .ok_or_else(|| StoreError::NotFound(format!("grant '{id}' not found")))?;

        if grant.entry_json.is_some() {
            return Err(StoreError::AlreadyPaired(format!(
                "grant '{id}' has already been used"
            )));
        }
        if let Some(pair_by) = grant.pair_by {
            if pair_by <= now_ms {
                return Err(StoreError::Expired(format!(
                    "grant '{id}' pairing window has ended"
                )));
            }
        }
        if let Some(expires_at) = grant.expires_at {
            if expires_at <= now_ms {
                return Err(StoreError::Expired(format!("grant '{id}' has expired")));
            }
        }
        let changed = tx.conn().execute(
            "UPDATE grants SET entry_json = ?1, paired_at = ?2 WHERE id = ?3 AND entry_json IS NULL",
            params![entry_json, now_ms, id],
        )?;
        if changed == 0 {
            return Err(StoreError::AlreadyPaired(format!(
                "grant '{id}' has already been used"
            )));
        }
        let updated = tx.conn().query_row(
            "SELECT * FROM grants WHERE id = ?1",
            params![id],
            decode_grant_row,
        )??;
        tx.commit()?;
        Ok(updated)
    }

    /// Atomically claims an existing single-use grant OR inserts and claims an offline
    /// Admin-CA-signed grant in a single `BEGIN IMMEDIATE` transaction.
    ///
    /// Replay of an already-claimed grant ID fails closed with [`StoreError::AlreadyPaired`].
    /// Conflicting content for the same grant ID fails closed with [`StoreError::IdConflict`].
    pub fn claim_or_insert_grant(
        &self,
        input: &GrantInput,
        entry_json: &str,
        now_ms: i64,
    ) -> StoreResult<GrantRecord> {
        if input.id.is_empty() {
            return Err(StoreError::InvalidInput(
                "grant id must be non-empty".to_string(),
            ));
        }
        if !is_node_id(&input.peer_id) {
            return Err(StoreError::InvalidInput(format!(
                "invalid peer_id '{}'",
                input.peer_id
            )));
        }
        let scopes_json = serde_json::to_string(&input.scopes)?;

        let tx = self.db.immediate_tx()?;
        let revoked: Option<i64> = tx
            .conn()
            .query_row(
                "SELECT 1 FROM revocations WHERE grant_id = ?1",
                params![&input.id],
                |row| row.get(0),
            )
            .optional()?;
        if revoked.is_some() {
            return Err(StoreError::Unauthorized(format!(
                "grant '{}' has been revoked",
                input.id
            )));
        }

        let existing: Option<GrantRecord> = tx
            .conn()
            .query_row(
                "SELECT * FROM grants WHERE id = ?1",
                params![&input.id],
                decode_grant_row,
            )
            .optional()?
            .transpose()?;

        if let Some(prev) = existing {
            if prev.entry_json.is_some() {
                return Err(StoreError::AlreadyPaired(format!(
                    "grant '{}' has already been used",
                    input.id
                )));
            }
            if prev.signed_json != input.signed_json {
                return Err(StoreError::IdConflict(format!(
                    "grant '{}' already exists with different content",
                    input.id
                )));
            }
            if let Some(pair_by) = prev.pair_by {
                if pair_by <= now_ms {
                    return Err(StoreError::Expired(format!(
                        "grant '{}' pairing window has ended",
                        input.id
                    )));
                }
            }
            if let Some(expires_at) = prev.expires_at {
                if expires_at <= now_ms {
                    return Err(StoreError::Expired(format!(
                        "grant '{}' has expired",
                        input.id
                    )));
                }
            }
            let changed = tx.conn().execute(
                "UPDATE grants SET entry_json = ?1, paired_at = ?2 WHERE id = ?3 AND entry_json IS NULL",
                params![entry_json, now_ms, &input.id],
            )?;
            if changed == 0 {
                return Err(StoreError::AlreadyPaired(format!(
                    "grant '{}' has already been used",
                    input.id
                )));
            }
        } else {
            if let Some(pair_by) = input.pair_by {
                if pair_by <= now_ms {
                    return Err(StoreError::Expired(format!(
                        "grant '{}' pairing window has ended",
                        input.id
                    )));
                }
            }
            if let Some(expires_at) = input.expires_at {
                if expires_at <= now_ms {
                    return Err(StoreError::Expired(format!(
                        "grant '{}' has expired",
                        input.id
                    )));
                }
            }
            tx.conn().execute(
                "INSERT INTO grants
                 (id, peer_id, direction, signed_json, scopes_json, trust_tier, issued_at,
                  pair_by, expires_at, entry_json, paired_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    &input.id,
                    &input.peer_id,
                    input.direction.as_str(),
                    &input.signed_json,
                    &scopes_json,
                    input.trust_tier.as_str(),
                    input.issued_at,
                    input.pair_by,
                    input.expires_at,
                    entry_json,
                    now_ms
                ],
            )?;
        }

        let updated = tx.conn().query_row(
            "SELECT * FROM grants WHERE id = ?1",
            params![&input.id],
            decode_grant_row,
        )??;
        tx.commit()?;
        Ok(updated)
    }

    // ---- Revocations ----

    pub fn add_revocation(
        &self,
        input: &RevocationInput,
        now_ms: i64,
    ) -> StoreResult<RevocationRecord> {
        if input.grant_id.is_empty() || !is_node_id(&input.peer_id) {
            return Err(StoreError::InvalidInput(
                "invalid revocation grant_id or peer_id".to_string(),
            ));
        }
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "INSERT OR IGNORE INTO revocations (grant_id, peer_id, signed_json, revoked_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![&input.grant_id, &input.peer_id, &input.signed_json, now_ms],
        )?;
        let rec = tx.conn().query_row(
            "SELECT grant_id, peer_id, signed_json, revoked_at FROM revocations WHERE grant_id = ?1",
            params![&input.grant_id],
            decode_revocation_row,
        )?;
        tx.commit()?;
        Ok(rec)
    }

    pub fn is_grant_revoked(&self, grant_id: &str) -> StoreResult<bool> {
        let found: Option<i64> = self
            .db
            .conn()
            .query_row(
                "SELECT 1 FROM revocations WHERE grant_id = ?1",
                params![grant_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn list_revocations(&self, peer_id: Option<&str>) -> StoreResult<Vec<RevocationRecord>> {
        if let Some(pid) = peer_id {
            let mut stmt = self.db.conn().prepare(
                "SELECT grant_id, peer_id, signed_json, revoked_at FROM revocations
                 WHERE peer_id = ?1 ORDER BY revoked_at ASC, grant_id ASC",
            )?;
            let rows = stmt
                .query_map(params![pid], decode_revocation_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            let mut stmt = self.db.conn().prepare(
                "SELECT grant_id, peer_id, signed_json, revoked_at FROM revocations
                 ORDER BY revoked_at ASC, grant_id ASC",
            )?;
            let rows = stmt
                .query_map([], decode_revocation_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    // ---- Peer Keys (RFC 7517 OKP JWKs + RFC 7638 kid) ----

    /// Pins a peer JWK in `peer_keys`.
    ///
    /// Fail-closed security invariants:
    /// - Refuses to overwrite an existing `(peer_id, kid)` with differing `jwk_json`.
    /// - Refuses to reactivate a previously `Revoked` key.
    /// - For `KeyUse::Signing` and `KeyUse::Encryption`, refuses to silently insert a second
    ///   `Active` key when an `Active` key with a different `kid` already exists; callers
    ///   performing authorized key rotation must use [`PeerStore::rotate_peer_key`].
    pub fn upsert_peer_key(&self, input: &PeerKeyInput, now_ms: i64) -> StoreResult<PeerKeyRecord> {
        if !is_node_id(&input.peer_id) || input.kid.is_empty() {
            return Err(StoreError::InvalidInput(
                "invalid peer_id or kid".to_string(),
            ));
        }
        let tx = self.db.immediate_tx()?;
        let existing_same: Option<PeerKeyRecord> = tx
            .conn()
            .query_row(
                "SELECT * FROM peer_keys WHERE peer_id = ?1 AND kid = ?2",
                params![&input.peer_id, &input.kid],
                decode_peer_key_row,
            )
            .optional()?
            .transpose()?;
        if let Some(prev) = existing_same {
            if prev.jwk_json != input.jwk_json {
                return Err(StoreError::IdConflict(format!(
                    "peer '{}' key '{}' already exists with different JWK material",
                    input.peer_id, input.kid
                )));
            }
            if prev.status == KeyStatus::Revoked && input.status == KeyStatus::Active {
                return Err(StoreError::InvalidState(format!(
                    "cannot reactivate revoked key '{}' for peer '{}'",
                    input.kid, input.peer_id
                )));
            }
        }
        if input.status == KeyStatus::Active
            && matches!(input.key_use, KeyUse::Signing | KeyUse::Encryption)
        {
            let conflicting_kid: Option<String> = tx
                .conn()
                .query_row(
                    "SELECT kid FROM peer_keys
                     WHERE peer_id = ?1 AND key_use = ?2 AND status = 'active' AND kid != ?3
                     LIMIT 1",
                    params![&input.peer_id, input.key_use.as_str(), &input.kid],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing_kid) = conflicting_kid {
                return Err(StoreError::IdConflict(format!(
                    "peer '{}' already has active {} key '{}'; refusing silent key replacement with '{}'",
                    input.peer_id,
                    input.key_use.as_str(),
                    existing_kid,
                    input.kid
                )));
            }
        }

        tx.conn().execute(
            "INSERT INTO peer_keys
             (peer_id, kid, key_use, jwk_json, status, registered_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(peer_id, kid) DO UPDATE SET
               key_use = excluded.key_use,
               jwk_json = excluded.jwk_json,
               status = excluded.status,
               expires_at = excluded.expires_at",
            params![
                &input.peer_id,
                &input.kid,
                input.key_use.as_str(),
                &input.jwk_json,
                input.status.as_str(),
                now_ms,
                input.expires_at
            ],
        )?;
        let rec = tx.conn().query_row(
            "SELECT * FROM peer_keys WHERE peer_id = ?1 AND kid = ?2",
            params![&input.peer_id, &input.kid],
            decode_peer_key_row,
        )??;
        tx.commit()?;
        Ok(rec)
    }

    /// Explicitly rotates a peer's active key for `(peer_id, key_use)`, atomically marking all
    /// prior active keys for that `key_use` with differing `kid` as [`KeyStatus::Retired`] so
    /// no ambiguous duplicate active keys remain.
    pub fn rotate_peer_key(&self, input: &PeerKeyInput, now_ms: i64) -> StoreResult<PeerKeyRecord> {
        if !is_node_id(&input.peer_id) || input.kid.is_empty() {
            return Err(StoreError::InvalidInput(
                "invalid peer_id or kid".to_string(),
            ));
        }
        if input.status != KeyStatus::Active {
            return Err(StoreError::InvalidInput(
                "rotate_peer_key requires KeyStatus::Active".to_string(),
            ));
        }
        let tx = self.db.immediate_tx()?;
        let existing_same: Option<PeerKeyRecord> = tx
            .conn()
            .query_row(
                "SELECT * FROM peer_keys WHERE peer_id = ?1 AND kid = ?2",
                params![&input.peer_id, &input.kid],
                decode_peer_key_row,
            )
            .optional()?
            .transpose()?;
        if let Some(prev) = existing_same {
            if prev.jwk_json != input.jwk_json {
                return Err(StoreError::IdConflict(format!(
                    "peer '{}' key '{}' already exists with different JWK material",
                    input.peer_id, input.kid
                )));
            }
            if prev.status == KeyStatus::Revoked {
                return Err(StoreError::InvalidState(format!(
                    "cannot reactivate revoked key '{}' for peer '{}'",
                    input.kid, input.peer_id
                )));
            }
        }

        tx.conn().execute(
            "UPDATE peer_keys
             SET status = ?1
             WHERE peer_id = ?2 AND key_use = ?3 AND status = 'active' AND kid != ?4",
            params![
                KeyStatus::Retired.as_str(),
                &input.peer_id,
                input.key_use.as_str(),
                &input.kid
            ],
        )?;

        tx.conn().execute(
            "INSERT INTO peer_keys
             (peer_id, kid, key_use, jwk_json, status, registered_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(peer_id, kid) DO UPDATE SET
               key_use = excluded.key_use,
               jwk_json = excluded.jwk_json,
               status = excluded.status,
               expires_at = excluded.expires_at",
            params![
                &input.peer_id,
                &input.kid,
                input.key_use.as_str(),
                &input.jwk_json,
                KeyStatus::Active.as_str(),
                now_ms,
                input.expires_at
            ],
        )?;
        let rec = tx.conn().query_row(
            "SELECT * FROM peer_keys WHERE peer_id = ?1 AND kid = ?2",
            params![&input.peer_id, &input.kid],
            decode_peer_key_row,
        )??;
        tx.commit()?;
        Ok(rec)
    }

    pub fn get_peer_key(&self, peer_id: &str, kid: &str) -> StoreResult<Option<PeerKeyRecord>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM peer_keys WHERE peer_id = ?1 AND kid = ?2",
                params![peer_id, kid],
                decode_peer_key_row,
            )
            .optional()?
            .transpose()
    }

    pub fn list_peer_keys(
        &self,
        peer_id: &str,
        key_use: Option<KeyUse>,
        active_only: bool,
    ) -> StoreResult<Vec<PeerKeyRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT * FROM peer_keys WHERE peer_id = ?1 ORDER BY registered_at ASC, kid ASC",
        )?;
        let all = stmt
            .query_map(params![peer_id], decode_peer_key_row)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(all
            .into_iter()
            .filter(|k| key_use.is_none_or(|u| k.key_use == u))
            .filter(|k| !active_only || k.status == KeyStatus::Active)
            .collect())
    }

    pub fn set_peer_key_status(
        &self,
        peer_id: &str,
        kid: &str,
        status: KeyStatus,
    ) -> StoreResult<bool> {
        let changed = self.db.conn().execute(
            "UPDATE peer_keys SET status = ?1 WHERE peer_id = ?2 AND kid = ?3",
            params![status.as_str(), peer_id, kid],
        )?;
        Ok(changed > 0)
    }

    // ---- Persisted Multi-Hub Peer Routes ----

    /// Persists or updates a multi-hub route directing `target_node` via `via_peer`.
    ///
    /// Rejects invalid node IDs and self-loops (`target_node == via_peer`).
    pub fn upsert_peer_route(
        &self,
        target_node: &str,
        via_peer: &str,
        now_ms: i64,
    ) -> StoreResult<PeerRoute> {
        if !is_node_id(target_node) {
            return Err(StoreError::InvalidInput(format!(
                "invalid target_node '{target_node}'"
            )));
        }
        if !is_node_id(via_peer) {
            return Err(StoreError::InvalidInput(format!(
                "invalid via_peer '{via_peer}'"
            )));
        }
        if target_node == via_peer {
            return Err(StoreError::InvalidInput(format!(
                "peer route cannot be a self-loop ('{target_node}')"
            )));
        }
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "INSERT INTO peer_routes (target_node, via_peer, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(target_node) DO UPDATE SET
               via_peer = excluded.via_peer,
               updated_at = excluded.updated_at",
            params![target_node, via_peer, now_ms],
        )?;
        let route = tx.conn().query_row(
            "SELECT target_node, via_peer, updated_at FROM peer_routes WHERE target_node = ?1",
            params![target_node],
            decode_peer_route_row,
        )?;
        tx.commit()?;
        Ok(route)
    }

    /// Looks up the persisted route for `target_node`.
    pub fn get_peer_route(&self, target_node: &str) -> StoreResult<Option<PeerRoute>> {
        self.db
            .conn()
            .query_row(
                "SELECT target_node, via_peer, updated_at FROM peer_routes WHERE target_node = ?1",
                params![target_node],
                decode_peer_route_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Lists all persisted multi-hub peer routes ordered by `target_node ASC`.
    pub fn list_peer_routes(&self) -> StoreResult<Vec<PeerRoute>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT target_node, via_peer, updated_at FROM peer_routes ORDER BY target_node ASC",
        )?;
        let rows = stmt
            .query_map([], decode_peer_route_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Deletes all routes forwarded through `via_peer`. Returns the count of deleted routes.
    pub fn delete_peer_routes_via(&self, via_peer: &str) -> StoreResult<usize> {
        let changed = self.db.conn().execute(
            "DELETE FROM peer_routes WHERE via_peer = ?1",
            params![via_peer],
        )?;
        Ok(changed)
    }

    /// Deletes the route for `target_node`. Returns `true` if a route was removed.
    pub fn delete_peer_route(&self, target_node: &str) -> StoreResult<bool> {
        let changed = self.db.conn().execute(
            "DELETE FROM peer_routes WHERE target_node = ?1",
            params![target_node],
        )?;
        Ok(changed > 0)
    }
}

/// Identifies E2EE capability tokens protected by the permanent anti-downgrade ratchet
/// (e.g. `dm.e2ee.v1`, `channel.e2ee.v1`, `kv.e2ee.v1`, `events.e2ee.v1`).
fn is_e2ee_capability(cap: &str) -> bool {
    cap.contains(".e2ee.") || cap.ends_with(".e2ee")
}

fn decode_peer_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<PeerRecord>> {
    let peer_id: String = row.get("peer_id")?;
    let endpoint: Option<String> = row.get("endpoint")?;
    let profile_str: String = row.get("profile")?;
    let trust_str: String = row.get("trust_tier")?;
    let status_str: String = row.get("status")?;
    let scopes_json: String = row.get("scopes_json")?;
    let auth_credential_ref: Option<String> = row.get("auth_credential_ref")?;
    let manifest_json: Option<String> = row.get("manifest_json")?;
    let manifest_version: i64 = row.get("manifest_version")?;
    let manifest_etag: Option<String> = row.get("manifest_etag")?;
    let manifest_fetched_at: Option<i64> = row.get("manifest_fetched_at")?;
    let observed_e2ee_caps_json: String = row.get("observed_e2ee_caps_json")?;
    let admitted_by_human_id: Option<String> = row.get("admitted_by_human_id")?;
    let admitted_auth_epoch_i64: Option<i64> = row.get("admitted_auth_epoch")?;
    let created_at: i64 = row.get("created_at")?;
    let updated_at: i64 = row.get("updated_at")?;

    Ok((|| {
        let profile = PeerProfile::parse(&profile_str)?;
        let trust_tier = TrustTier::parse(&trust_str)?;
        let status = PeerStatus::parse(&status_str)?;
        let scopes: Vec<String> = serde_json::from_str(&scopes_json)?;
        let observed_e2ee_caps: Vec<String> = serde_json::from_str(&observed_e2ee_caps_json)?;
        let admitted_auth_epoch = match admitted_auth_epoch_i64 {
            Some(ep) => Some(u64::try_from(ep).map_err(|_| {
                StoreError::InvalidState(format!(
                    "corrupt admitted_auth_epoch '{ep}' for peer '{peer_id}'"
                ))
            })?),
            None => None,
        };
        Ok(PeerRecord {
            peer_id,
            endpoint,
            profile,
            trust_tier,
            status,
            scopes,
            auth_credential_ref,
            manifest_json,
            manifest_version,
            manifest_etag,
            manifest_fetched_at,
            observed_e2ee_caps,
            admitted_by_human_id,
            admitted_auth_epoch,
            created_at,
            updated_at,
        })
    })())
}

fn decode_grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<GrantRecord>> {
    let id: String = row.get("id")?;
    let peer_id: String = row.get("peer_id")?;
    let direction_str: String = row.get("direction")?;
    let signed_json: String = row.get("signed_json")?;
    let scopes_json: String = row.get("scopes_json")?;
    let trust_str: String = row.get("trust_tier")?;
    let issued_at: i64 = row.get("issued_at")?;
    let pair_by: Option<i64> = row.get("pair_by")?;
    let expires_at: Option<i64> = row.get("expires_at")?;
    let entry_json: Option<String> = row.get("entry_json")?;
    let paired_at: Option<i64> = row.get("paired_at")?;

    Ok((|| {
        let direction = GrantDirection::parse(&direction_str)?;
        let trust_tier = TrustTier::parse(&trust_str)?;
        let scopes: Vec<String> = serde_json::from_str(&scopes_json)?;
        Ok(GrantRecord {
            id,
            peer_id,
            direction,
            signed_json,
            scopes,
            trust_tier,
            issued_at,
            pair_by,
            expires_at,
            entry_json,
            paired_at,
        })
    })())
}

fn decode_revocation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RevocationRecord> {
    Ok(RevocationRecord {
        grant_id: row.get(0)?,
        peer_id: row.get(1)?,
        signed_json: row.get(2)?,
        revoked_at: row.get(3)?,
    })
}

fn decode_peer_key_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<PeerKeyRecord>> {
    let peer_id: String = row.get("peer_id")?;
    let kid: String = row.get("kid")?;
    let key_use_str: String = row.get("key_use")?;
    let jwk_json: String = row.get("jwk_json")?;
    let status_str: String = row.get("status")?;
    let registered_at: i64 = row.get("registered_at")?;
    let expires_at: Option<i64> = row.get("expires_at")?;

    Ok((|| {
        let key_use = KeyUse::parse(&key_use_str)?;
        let status = KeyStatus::parse(&status_str)?;
        Ok(PeerKeyRecord {
            peer_id,
            kid,
            key_use,
            jwk_json,
            status,
            registered_at,
            expires_at,
        })
    })())
}

fn decode_peer_route_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerRoute> {
    Ok(PeerRoute {
        target_node: row.get("target_node")?,
        via_peer: row.get("via_peer")?,
        updated_at: row.get("updated_at")?,
    })
}

fn bearer_metadata_matches_peer(raw_value: &str, peer_id: &str) -> bool {
    if raw_value == peer_id {
        return true;
    }
    if raw_value.starts_with('{') {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(raw_value) {
            if val.get("peerId").and_then(serde_json::Value::as_str) == Some(peer_id) {
                return true;
            }
        }
    }
    false
}

fn delete_peer_bearer_tokens_in_conn(
    conn: &rusqlite::Connection,
    peer_id: &str,
) -> StoreResult<usize> {
    let mut stmt = conn.prepare("SELECT key, value FROM metadata WHERE key LIKE 'auth_token:%'")?;
    let matching_keys: Vec<String> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|(_, val)| bearer_metadata_matches_peer(val, peer_id))
        .map(|(k, _)| k)
        .collect();
    drop(stmt);

    let mut deleted = 0usize;
    for key in matching_keys {
        deleted += conn.execute("DELETE FROM metadata WHERE key = ?1", params![key])?;
    }
    Ok(deleted)
}
