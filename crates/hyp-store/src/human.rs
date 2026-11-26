//! Human Authority registry, monotonic `min_auth_epoch` anti-rollback, canonical
//! `authorities_digest` for `gate_policy_sig` tamper binding, atomic single-use `claim_id`
//! nonce consumption, human-signed `NodeCertV1` storage, and `mailbox.human_auth_json`.

use hyp_proto::scopes::{validate_delegated_human_scopes, validate_node_prefix_pattern};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::NodeDb;
use crate::error::{StoreError, StoreResult};
use crate::query::{query_opt, query_vec};
use crate::types::string_enum;
use crate::types::{canonical_json, is_node_id, sha256_hex};

/// Metadata key storing the strictly monotonic minimum accepted human `auth_epoch`.
pub const HUMAN_MIN_AUTH_EPOCH_META_KEY: &str = "human.min_auth_epoch";

string_enum! {
    /// Role assigned to an enrolled human signing key.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum HumanAuthorityRole {
        Admin => "admin",
        Signer => "signer",
    }
    InvalidState: "human authority role";
}

string_enum! {
    /// Lifecycle status of an enrolled human signing key.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum HumanAuthorityStatus {
        Active => "active",
        Revoked => "revoked",
    }
    InvalidState: "human authority status";
}

string_enum! {
    /// Kind of human claim tracked in `human_claim_nonces`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum HumanClaimKind {
        Directive => "directive",
        Secret => "secret",
        HumanInvite => "human_invite",
        Approval => "approval",
    }
    InvalidState: "human claim kind";
}

/// The single Passkey-signed Security Gate lock seal row (`gate_lock_seal`, `id = 1`).
///
/// `signed_claim_json` is the Passkey Admin's `SignedHumanClaimV1` (`kind = "approval"`); every
/// other fact about the seal (locked, policy hash, signer) is read from that signed claim, so no
/// unsigned column can be edited to change its meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateLockSealRecord {
    pub seal_seq: u64,
    pub signed_claim_json: String,
    pub updated_at: i64,
}

/// Input for configuring a human's delegated device admission policy (`human_delegation_policies`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanDelegationPolicyInput {
    pub human_id: String,
    pub node_prefix: String,
    pub scopes: Vec<String>,
    pub max_devices: u32,
    pub delegation_enabled: bool,
}

/// Persisted delegated device admission policy record from `human_delegation_policies`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanDelegationPolicy {
    pub human_id: String,
    pub node_prefix: String,
    pub scopes: Vec<String>,
    pub max_devices: u32,
    pub delegation_enabled: bool,
    pub updated_at: i64,
}

/// Input for enrolling or updating an active human authority key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanAuthorityInput {
    pub human_id: String,
    pub kid: String,
    pub label: String,
    pub role: HumanAuthorityRole,
    pub jwk_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_jwk_json: Option<String>,
    pub prf_salt: Option<String>,
    pub auth_epoch: u64,
}

/// Persisted human authority key record from `human_authorities`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanAuthorityRecord {
    pub human_id: String,
    pub kid: String,
    pub label: String,
    pub role: HumanAuthorityRole,
    pub jwk_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_jwk_json: Option<String>,
    pub prf_salt: Option<String>,
    pub auth_epoch: u64,
    pub status: HumanAuthorityStatus,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub revocation_json: Option<String>,
}

/// Input for storing a human-signed `NodeCertV1` (`hcert1_`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanNodeCertInput {
    pub node_id: String,
    pub human_kid: String,
    pub auth_epoch: u64,
    pub signed_json: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Persisted human-signed `NodeCertV1` record from `human_node_certs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanNodeCertRecord {
    pub node_id: String,
    pub human_kid: String,
    pub auth_epoch: u64,
    pub signed_json: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Scoped Human Authority store view borrowed from [`NodeDb`].
pub struct HumanAuthorityStore<'a> {
    db: &'a NodeDb,
}

impl<'a> HumanAuthorityStore<'a> {
    pub(crate) fn new(db: &'a NodeDb) -> Self {
        Self { db }
    }

    /// Enrolls or updates an active human authority key in `human_authorities`.
    ///
    /// Fails closed if `(human_id, kid)` was previously revoked (revoked keys cannot be
    /// silently resurrected) or if `kid` is already bound to a different `human_id`.
    pub fn upsert_authority(
        &self,
        input: &HumanAuthorityInput,
        now_ms: i64,
    ) -> StoreResult<HumanAuthorityRecord> {
        self.upsert_authority_inner(input, now_ms, false)
    }

    /// Bootstrap enrollment is serialized with other writers and refuses once Passkey
    /// enrollment history or signed policy evidence exists. A pending initial ceremony cannot
    /// become an authority-injection bypass after another process enrolls the first admin.
    pub fn bootstrap_authority(
        &self,
        input: &HumanAuthorityInput,
        now_ms: i64,
    ) -> StoreResult<HumanAuthorityRecord> {
        self.upsert_authority_inner(input, now_ms, true)
    }

    fn upsert_authority_inner(
        &self,
        input: &HumanAuthorityInput,
        now_ms: i64,
        bootstrap: bool,
    ) -> StoreResult<HumanAuthorityRecord> {
        validate_human_id(&input.human_id)?;
        validate_token_id("kid", &input.kid)?;
        validate_label(&input.label)?;
        validate_json_object("jwk_json", &input.jwk_json)?;
        if let Some(enc_jwk) = &input.enc_jwk_json {
            validate_json_object("enc_jwk_json", enc_jwk)?;
        }
        if let Some(salt) = &input.prf_salt {
            validate_token_id("prf_salt", salt)?;
        }
        let epoch_i64 = validate_epoch(input.auth_epoch)?;

        let tx = self.db.immediate_tx()?;
        if bootstrap && self.requires_live_approval()? {
            return Err(StoreError::InvalidState(
                "Passkey enrollment history exists; bootstrap cannot mutate authorities".into(),
            ));
        }

        // Prevent cross-human kid collisions and fail closed on revoked-key resurrection.
        let existing: Option<(String, String, i64)> = tx
            .conn()
            .query_row(
                "SELECT human_id, status, created_at FROM human_authorities WHERE kid = ?1 LIMIT 1",
                params![input.kid],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        let created_at =
            if let Some((existing_human_id, existing_status, existing_created_at)) = existing {
                if existing_human_id != input.human_id {
                    return Err(StoreError::IdConflict(format!(
                        "human authority kid '{}' is already bound to human '{}'",
                        input.kid, existing_human_id
                    )));
                }
                if existing_status == HumanAuthorityStatus::Revoked.as_str() {
                    return Err(StoreError::InvalidState(format!(
                        "cannot reactivate revoked human authority '{}' kid '{}'",
                        input.human_id, input.kid
                    )));
                }
                existing_created_at
            } else {
                now_ms
            };

        tx.conn().execute(
            "INSERT INTO human_authorities
                (human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status, created_at, revoked_at, revocation_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, NULL, NULL)
             ON CONFLICT(human_id, kid) DO UPDATE SET
                label = excluded.label,
                role = excluded.role,
                jwk_json = excluded.jwk_json,
                enc_jwk_json = excluded.enc_jwk_json,
                prf_salt = excluded.prf_salt,
                auth_epoch = excluded.auth_epoch",
            params![
                input.human_id,
                input.kid,
                input.label,
                input.role.as_str(),
                input.jwk_json,
                input.enc_jwk_json,
                input.prf_salt,
                epoch_i64,
                created_at,
            ],
        )?;
        tx.commit()?;

        Ok(HumanAuthorityRecord {
            human_id: input.human_id.clone(),
            kid: input.kid.clone(),
            label: input.label.clone(),
            role: input.role,
            jwk_json: input.jwk_json.clone(),
            enc_jwk_json: input.enc_jwk_json.clone(),
            prf_salt: input.prf_salt.clone(),
            auth_epoch: input.auth_epoch,
            status: HumanAuthorityStatus::Active,
            created_at,
            revoked_at: None,
            revocation_json: None,
        })
    }

    /// Looks up an active human authority key by RFC 7638 `kid`.
    /// Returns `None` for unknown or revoked keys.
    pub fn get_active_authority_by_kid(
        &self,
        kid: &str,
    ) -> StoreResult<Option<HumanAuthorityRecord>> {
        if kid.is_empty() {
            return Ok(None);
        }
        self.db
            .conn()
            .query_row(
                "SELECT human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status,
                        created_at, revoked_at, revocation_json
                 FROM human_authorities
                 WHERE kid = ?1 AND status = 'active'
                 LIMIT 1",
                params![kid],
                row_to_authority,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Looks up a human authority record by `(human_id, kid)` regardless of status.
    pub fn get_authority(
        &self,
        human_id: &str,
        kid: &str,
    ) -> StoreResult<Option<HumanAuthorityRecord>> {
        self.db
            .conn()
            .query_row(
                "SELECT human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status,
                        created_at, revoked_at, revocation_json
                 FROM human_authorities
                 WHERE human_id = ?1 AND kid = ?2",
                params![human_id, kid],
                row_to_authority,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Lists enrolled active human authorities deterministically ordered by `(human_id ASC, kid ASC)`.
    pub fn list_active_authorities(&self) -> StoreResult<Vec<HumanAuthorityRecord>> {
        self.list_authorities(false)
    }

    /// Lists enrolled human authorities deterministically ordered by `(human_id ASC, kid ASC)`.
    pub fn list_authorities(
        &self,
        include_revoked: bool,
    ) -> StoreResult<Vec<HumanAuthorityRecord>> {
        let sql = if include_revoked {
            "SELECT human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status,
                    created_at, revoked_at, revocation_json
             FROM human_authorities
             ORDER BY human_id ASC, kid ASC"
        } else {
            "SELECT human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status,
                    created_at, revoked_at, revocation_json
             FROM human_authorities
             WHERE status = 'active'
             ORDER BY human_id ASC, kid ASC"
        };
        query_vec(self.db.conn(), sql, [], row_to_authority)
    }

    /// Upgrades an active human authority key with its companion X25519 encryption JWK.
    ///
    /// Returns `Ok(true)` if an active authority with `kid` was updated, or `Ok(false)` if
    /// `kid` does not exist or has been revoked.
    pub fn update_authority_enc_jwk(
        &self,
        kid: &str,
        enc_jwk_json: &str,
        _now_ms: i64,
    ) -> StoreResult<bool> {
        validate_token_id("kid", kid)?;
        validate_json_object("enc_jwk_json", enc_jwk_json)?;

        let tx = self.db.immediate_tx()?;
        let changed = tx.conn().execute(
            "UPDATE human_authorities
             SET enc_jwk_json = ?1
             WHERE kid = ?2 AND status = 'active'",
            params![enc_jwk_json, kid],
        )?;
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Returns the most recently added active human authority matching optional `human_id`
    /// that has a companion X25519 encryption key (`enc_jwk_json IS NOT NULL`).
    pub fn get_preferred_human_enc_jwk(
        &self,
        human_id: Option<&str>,
    ) -> StoreResult<Option<HumanAuthorityRecord>> {
        if let Some(hid) = human_id {
            validate_human_id(hid)?;
            self.db
                .conn()
                .query_row(
                    "SELECT human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status,
                            created_at, revoked_at, revocation_json
                     FROM human_authorities
                     WHERE status = 'active' AND enc_jwk_json IS NOT NULL AND human_id = ?1
                     ORDER BY created_at DESC, auth_epoch DESC, kid DESC
                     LIMIT 1",
                    params![hid],
                    row_to_authority,
                )
                .optional()
                .map_err(StoreError::from)
        } else {
            self.db
                .conn()
                .query_row(
                    "SELECT human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status,
                            created_at, revoked_at, revocation_json
                     FROM human_authorities
                     WHERE status = 'active' AND enc_jwk_json IS NOT NULL
                     ORDER BY created_at DESC, auth_epoch DESC, kid DESC
                     LIMIT 1",
                    [],
                    row_to_authority,
                )
                .optional()
                .map_err(StoreError::from)
        }
    }

    /// Returns the strictly monotonic minimum accepted `auth_epoch` (defaults to `1`).
    pub fn min_auth_epoch(&self) -> StoreResult<u64> {
        read_min_auth_epoch(self.db.conn())
    }

    /// Atomically revokes `(human_id, kid)`, persists `revocation_json`, and monotonically
    /// advances `metadata['human.min_auth_epoch'] = max(current, new_min_auth_epoch)`.
    ///
    /// Returns the resulting monotonic `min_auth_epoch`. Never rolls back `min_auth_epoch`.
    pub fn revoke_authority_monotonic(
        &self,
        human_id: &str,
        kid: &str,
        new_min_auth_epoch: u64,
        revocation_json: &str,
        now_ms: i64,
    ) -> StoreResult<u64> {
        validate_human_id(human_id)?;
        validate_token_id("kid", kid)?;
        let _ = validate_epoch(new_min_auth_epoch)?;
        validate_json_object("revocation_json", revocation_json)?;

        let tx = self.db.immediate_tx()?;
        let changed = tx.conn().execute(
            "UPDATE human_authorities
             SET status = 'revoked',
                 revoked_at = COALESCE(revoked_at, ?1),
                 revocation_json = ?2
             WHERE human_id = ?3 AND kid = ?4",
            params![now_ms, revocation_json, human_id, kid],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound(format!(
                "human authority '{human_id}' kid '{kid}' not found"
            )));
        }

        let current_min = read_min_auth_epoch(tx.conn())?;
        let effective_min = current_min.max(new_min_auth_epoch);
        tx.conn().execute(
            "INSERT INTO metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![HUMAN_MIN_AUTH_EPOCH_META_KEY, effective_min.to_string()],
        )?;
        tx.commit()?;

        Ok(effective_min)
    }

    /// Whether normal authority mutations require a live local Passkey ceremony. This uses
    /// enrollment history, not active-key availability or the legacy locked/unlocked bit.
    pub fn requires_live_approval(&self) -> StoreResult<bool> {
        Ok(self.get_gate_lock_seal()?.is_some()
            || self
                .list_authorities(true)?
                .iter()
                .any(|a| a.role == HumanAuthorityRole::Admin && a.prf_salt.is_some()))
    }

    /// Computes a canonical SHA-256 hex digest over sorted enrolled authority identity tuples
    /// `(human_id, kid, role, jwk_json, enc_jwk_json, auth_epoch)` for binding into
    /// `gate_policy_sig`.
    ///
    /// **N3 invariant:** Intentionally excludes strictly-monotonic revocation state (`status`,
    /// `revoked_at`, `revocation_json`) and `metadata['human.min_auth_epoch']`. Because revoked
    /// keys can NEVER be resurrected (`upsert_authority` fails closed on `status = 'revoked'`),
    /// digesting the enrolled identity tuples detects every unauthorized key injection, deletion,
    /// role escalation, JWK swap, or row `auth_epoch` tamper while allowing cryptographically
    /// verified mesh revocations (`to.hyphae.human.revocation.v1`) to take effect without
    /// bricking a locked Security Gate.
    pub fn authorities_digest(&self) -> StoreResult<String> {
        let entries = query_vec(
            self.db.conn(),
            "SELECT human_id, kid, role, jwk_json, enc_jwk_json, auth_epoch
             FROM human_authorities
             ORDER BY human_id ASC, kid ASC",
            [],
            |row| {
                let human_id: String = row.get(0)?;
                let kid: String = row.get(1)?;
                let role: String = row.get(2)?;
                let jwk_json: String = row.get(3)?;
                let enc_jwk_json: Option<String> = row.get(4)?;
                let auth_epoch: i64 = row.get(5)?;
                Ok(json!({
                    "humanId": human_id,
                    "kid": kid,
                    "role": role,
                    "jwkJson": jwk_json,
                    "encJwkJson": enc_jwk_json,
                    "authEpoch": auth_epoch,
                }))
            },
        )?;

        let payload = json!({
            "authorities": entries,
        });
        let canon = canonical_json(&payload);
        Ok(sha256_hex(canon.as_bytes()))
    }

    /// Atomically consumes a single-use `claim_id` nonce inside `BEGIN IMMEDIATE`.
    ///
    /// Returns `Ok(true)` iff `claim_id` was newly inserted, and `Ok(false)` on replay.
    pub fn consume_claim_nonce(
        &self,
        claim_id: &str,
        human_kid: &str,
        kind: HumanClaimKind,
        expires_at: i64,
        now_ms: i64,
    ) -> StoreResult<bool> {
        validate_token_id("claim_id", claim_id)?;
        validate_token_id("human_kid", human_kid)?;

        let tx = self.db.immediate_tx()?;
        let changed = tx.conn().execute(
            "INSERT OR IGNORE INTO human_claim_nonces
                (claim_id, human_kid, kind, expires_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![claim_id, human_kid, kind.as_str(), expires_at, now_ms],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }

    /// Prunes expired claim nonces (`expires_at <= now_ms`) and returns the number deleted.
    pub fn prune_expired_nonces(&self, now_ms: i64) -> StoreResult<usize> {
        let tx = self.db.immediate_tx()?;
        let deleted = tx.conn().execute(
            "DELETE FROM human_claim_nonces WHERE expires_at <= ?1",
            params![now_ms],
        )?;
        tx.commit()?;
        Ok(deleted)
    }

    /// Returns the earliest `expires_at` across all stored claim nonces, or `None` if empty.
    pub fn next_nonce_expiry_deadline_ms(&self) -> StoreResult<Option<i64>> {
        let deadline: Option<i64> = self.db.conn().query_row(
            "SELECT MIN(expires_at) FROM human_claim_nonces",
            [],
            |row| row.get(0),
        )?;
        Ok(deadline)
    }

    /// Stores or updates a human-signed `NodeCertV1` in `human_node_certs`.
    ///
    /// Rejects silent `auth_epoch` rollback for an existing `(node_id, human_kid)` pair.
    pub fn put_node_cert(&self, input: &HumanNodeCertInput) -> StoreResult<HumanNodeCertRecord> {
        if !is_node_id(&input.node_id) {
            return Err(StoreError::InvalidInput(format!(
                "invalid node_id '{}'",
                input.node_id
            )));
        }
        validate_token_id("human_kid", &input.human_kid)?;
        let epoch_i64 = validate_epoch(input.auth_epoch)?;
        validate_json_object("signed_json", &input.signed_json)?;
        if input.expires_at <= input.issued_at {
            return Err(StoreError::InvalidInput(
                "node cert expires_at must be strictly after issued_at".into(),
            ));
        }

        let tx = self.db.immediate_tx()?;
        let existing_epoch: Option<i64> = tx
            .conn()
            .query_row(
                "SELECT auth_epoch FROM human_node_certs WHERE node_id = ?1 AND human_kid = ?2",
                params![input.node_id, input.human_kid],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(prev) = existing_epoch {
            if epoch_i64 < prev {
                return Err(StoreError::InvalidState(format!(
                    "node cert epoch rollback for '{}' kid '{}': got {} < existing {}",
                    input.node_id, input.human_kid, epoch_i64, prev
                )));
            }
        }

        tx.conn().execute(
            "INSERT INTO human_node_certs
                (node_id, human_kid, auth_epoch, signed_json, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(node_id, human_kid) DO UPDATE SET
                auth_epoch = excluded.auth_epoch,
                signed_json = excluded.signed_json,
                issued_at = excluded.issued_at,
                expires_at = excluded.expires_at",
            params![
                input.node_id,
                input.human_kid,
                epoch_i64,
                input.signed_json,
                input.issued_at,
                input.expires_at,
            ],
        )?;
        tx.commit()?;

        Ok(HumanNodeCertRecord {
            node_id: input.node_id.clone(),
            human_kid: input.human_kid.clone(),
            auth_epoch: input.auth_epoch,
            signed_json: input.signed_json.clone(),
            issued_at: input.issued_at,
            expires_at: input.expires_at,
        })
    }

    /// Returns the newest stored `NodeCertV1` for `node_id` (ordered by `auth_epoch DESC, issued_at DESC, expires_at DESC`).
    pub fn get_latest_node_cert(&self, node_id: &str) -> StoreResult<Option<HumanNodeCertRecord>> {
        self.db
            .conn()
            .query_row(
                "SELECT node_id, human_kid, auth_epoch, signed_json, issued_at, expires_at
                 FROM human_node_certs
                 WHERE node_id = ?1
                 ORDER BY auth_epoch DESC, issued_at DESC, expires_at DESC
                 LIMIT 1",
                params![node_id],
                row_to_node_cert,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Attaches verified human-authority metadata JSON (`mailbox.human_auth_json`) to an existing
    /// mailbox receipt without modifying existing `MailboxInsert` / `MailboxEntry` structs.
    ///
    /// Returns `Ok(true)` if the receipt existed and was updated, `Ok(false)` otherwise.
    pub fn set_mailbox_human_auth(
        &self,
        receipt: &str,
        human_auth_json: &str,
    ) -> StoreResult<bool> {
        if receipt.trim().is_empty() {
            return Err(StoreError::InvalidInput("receipt must be non-empty".into()));
        }
        validate_json_object("human_auth_json", human_auth_json)?;

        let tx = self.db.immediate_tx()?;
        let changed = tx.conn().execute(
            "UPDATE mailbox SET human_auth_json = ?1 WHERE receipt = ?2",
            params![human_auth_json, receipt],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }

    /// Reads `mailbox.human_auth_json` for a given mailbox `receipt`, if present.
    pub fn get_mailbox_human_auth(&self, receipt: &str) -> StoreResult<Option<String>> {
        let found: Option<Option<String>> = self
            .db
            .conn()
            .query_row(
                "SELECT human_auth_json FROM mailbox WHERE receipt = ?1",
                params![receipt],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.flatten())
    }

    /// Lists all authorities registered for `human_id`, ordered deterministically by `kid ASC`.
    pub fn list_authorities_for_human(
        &self,
        human_id: &str,
        include_revoked: bool,
    ) -> StoreResult<Vec<HumanAuthorityRecord>> {
        validate_human_id(human_id)?;
        let sql = if include_revoked {
            "SELECT human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status,
                    created_at, revoked_at, revocation_json
             FROM human_authorities
             WHERE human_id = ?1
             ORDER BY kid ASC"
        } else {
            "SELECT human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status,
                    created_at, revoked_at, revocation_json
             FROM human_authorities
             WHERE human_id = ?1 AND status = 'active'
             ORDER BY kid ASC"
        };
        query_vec(self.db.conn(), sql, params![human_id], row_to_authority)
    }

    /// Looks up an active human authority strictly matching BOTH `human_id` and `kid`.
    pub fn get_active_authority_by_human_and_kid(
        &self,
        human_id: &str,
        kid: &str,
    ) -> StoreResult<Option<HumanAuthorityRecord>> {
        if human_id.is_empty() || kid.is_empty() {
            return Ok(None);
        }
        self.db
            .conn()
            .query_row(
                "SELECT human_id, kid, label, role, jwk_json, enc_jwk_json, prf_salt, auth_epoch, status,
                        created_at, revoked_at, revocation_json
                 FROM human_authorities
                 WHERE human_id = ?1 AND kid = ?2 AND status = 'active'
                 LIMIT 1",
                params![human_id, kid],
                row_to_authority,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Creates or updates a delegated device admission policy for `human_id` in
    /// `human_delegation_policies` (schema v7).
    ///
    /// Fails closed on invalid `human_id`, invalid `node_prefix`, disallowed scopes
    /// (`*`, `bridge:post`, `forward:via`), or `max_devices` outside `1..=100`.
    pub fn upsert_delegation_policy(
        &self,
        input: &HumanDelegationPolicyInput,
        now_ms: i64,
    ) -> StoreResult<HumanDelegationPolicy> {
        validate_human_id(&input.human_id)?;
        validate_node_prefix_pattern(&input.node_prefix, false)
            .map_err(|e| StoreError::InvalidInput(format!("invalid node_prefix: {e}")))?;
        let validated_scopes = validate_delegated_human_scopes(&input.scopes)
            .map_err(|e| StoreError::InvalidInput(format!("invalid delegation scopes: {e}")))?;
        if input.max_devices == 0 || input.max_devices > 100 {
            return Err(StoreError::InvalidInput(format!(
                "max_devices {} must be in 1..=100",
                input.max_devices
            )));
        }
        let scopes_json = serde_json::to_string(&validated_scopes)?;
        let enabled_int: i64 = if input.delegation_enabled { 1 } else { 0 };

        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "INSERT INTO human_delegation_policies
                (human_id, node_prefix, scopes_json, max_devices, delegation_enabled, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(human_id) DO UPDATE SET
                node_prefix = excluded.node_prefix,
                scopes_json = excluded.scopes_json,
                max_devices = excluded.max_devices,
                delegation_enabled = excluded.delegation_enabled,
                updated_at = excluded.updated_at",
            params![
                input.human_id,
                input.node_prefix,
                scopes_json,
                i64::from(input.max_devices),
                enabled_int,
                now_ms,
            ],
        )?;
        tx.commit()?;

        Ok(HumanDelegationPolicy {
            human_id: input.human_id.clone(),
            node_prefix: input.node_prefix.clone(),
            scopes: validated_scopes,
            max_devices: input.max_devices,
            delegation_enabled: input.delegation_enabled,
            updated_at: now_ms,
        })
    }

    /// Reads the delegated admission policy for `human_id`, if configured.
    pub fn get_delegation_policy(
        &self,
        human_id: &str,
    ) -> StoreResult<Option<HumanDelegationPolicy>> {
        if human_id.is_empty() {
            return Ok(None);
        }
        query_opt(
            self.db.conn(),
            "SELECT human_id, node_prefix, scopes_json, max_devices, delegation_enabled, updated_at
                 FROM human_delegation_policies
                 WHERE human_id = ?1",
            params![human_id],
            row_to_delegation_policy,
        )
    }

    /// Lists all configured delegated human admission policies ordered by `human_id ASC`.
    pub fn list_delegation_policies(&self) -> StoreResult<Vec<HumanDelegationPolicy>> {
        let rows = query_vec(
            self.db.conn(),
            "SELECT human_id, node_prefix, scopes_json, max_devices, delegation_enabled, updated_at
             FROM human_delegation_policies
             ORDER BY human_id ASC",
            [],
            row_to_delegation_policy,
        )?;
        rows.into_iter().collect()
    }

    /// Toggles `delegation_enabled` on an existing `human_delegation_policies` row.
    pub fn set_delegation_enabled(
        &self,
        human_id: &str,
        enabled: bool,
        now_ms: i64,
    ) -> StoreResult<bool> {
        let tx = self.db.immediate_tx()?;
        let changed = tx.conn().execute(
            "UPDATE human_delegation_policies
             SET delegation_enabled = ?1, updated_at = ?2
             WHERE human_id = ?3",
            params![if enabled { 1i64 } else { 0i64 }, now_ms, human_id],
        )?;
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Reads the Passkey-signed Security Gate lock seal, if one was ever written.
    pub fn get_gate_lock_seal(&self) -> StoreResult<Option<GateLockSealRecord>> {
        self.db
            .conn()
            .query_row(
                "SELECT seal_seq, signed_claim_json, updated_at FROM gate_lock_seal WHERE id = 1",
                [],
                |row| {
                    let seq: i64 = row.get(0)?;
                    Ok(GateLockSealRecord {
                        seal_seq: u64::try_from(seq).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Integer,
                                Box::new(e),
                            )
                        })?,
                        signed_claim_json: row.get(1)?,
                        updated_at: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Replaces the lock seal. `seal_seq` must be strictly greater than the stored one, so an
    /// approval requested before the latest seal can never be applied after it.
    pub fn put_gate_lock_seal(
        &self,
        seal_seq: u64,
        signed_claim_json: &str,
        now_ms: i64,
    ) -> StoreResult<GateLockSealRecord> {
        let seq = i64::try_from(seal_seq)
            .ok()
            .filter(|s| *s >= 1)
            .ok_or_else(|| {
                StoreError::InvalidInput("gate_lock_seal seal_seq must be in 1..=i64::MAX".into())
            })?;
        validate_json_object("signed_claim_json", signed_claim_json)?;

        let tx = self.db.immediate_tx()?;
        let prev: Option<i64> = tx
            .conn()
            .query_row(
                "SELECT seal_seq FROM gate_lock_seal WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if prev.is_some_and(|prev| seq <= prev) {
            return Err(StoreError::InvalidState(format!(
                "gate_lock_seal seal_seq rollback rejected: got {seq} <= existing {}",
                prev.unwrap_or_default()
            )));
        }
        tx.conn().execute(
            "INSERT INTO gate_lock_seal (id, seal_seq, signed_claim_json, updated_at)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                seal_seq = excluded.seal_seq,
                signed_claim_json = excluded.signed_claim_json,
                updated_at = excluded.updated_at",
            params![seq, signed_claim_json, now_ms],
        )?;
        tx.commit()?;

        Ok(GateLockSealRecord {
            seal_seq,
            signed_claim_json: signed_claim_json.to_string(),
            updated_at: now_ms,
        })
    }

    /// Computes the exact canonical `authorities_digest()` that would result from applying
    /// `upsert_authority(input)` WITHOUT mutating SQLite, so Passkey approval ceremonies can bind
    /// the resulting digest before touching `human_authorities`.
    pub fn projected_authorities_digest_after_upsert(
        &self,
        input: &HumanAuthorityInput,
    ) -> StoreResult<String> {
        validate_human_id(&input.human_id)?;
        validate_token_id("kid", &input.kid)?;
        validate_label(&input.label)?;
        validate_json_object("jwk_json", &input.jwk_json)?;
        if let Some(enc_jwk) = &input.enc_jwk_json {
            validate_json_object("enc_jwk_json", enc_jwk)?;
        }
        if let Some(salt) = &input.prf_salt {
            validate_token_id("prf_salt", salt)?;
        }
        let epoch_i64 = validate_epoch(input.auth_epoch)?;

        // Match `upsert_authority` conflict/revocation checks fail-closed.
        let existing: Option<(String, String)> = self
            .db
            .conn()
            .query_row(
                "SELECT human_id, status FROM human_authorities WHERE kid = ?1 LIMIT 1",
                params![input.kid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_human_id, existing_status)) = existing {
            if existing_human_id != input.human_id {
                return Err(StoreError::IdConflict(format!(
                    "human authority kid '{}' is already bound to human '{}'",
                    input.kid, existing_human_id
                )));
            }
            if existing_status == HumanAuthorityStatus::Revoked.as_str() {
                return Err(StoreError::InvalidState(format!(
                    "cannot reactivate revoked human authority '{}' kid '{}'",
                    input.human_id, input.kid
                )));
            }
        }

        let mut rows: Vec<(String, String, String, String, Option<String>, i64)> = query_vec(
            self.db.conn(),
            "SELECT human_id, kid, role, jwk_json, enc_jwk_json, auth_epoch
             FROM human_authorities
             ORDER BY human_id ASC, kid ASC",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;

        let new_tuple = (
            input.human_id.clone(),
            input.kid.clone(),
            input.role.as_str().to_string(),
            input.jwk_json.clone(),
            input.enc_jwk_json.clone(),
            epoch_i64,
        );
        if let Some(existing_row) = rows
            .iter_mut()
            .find(|r| r.0 == input.human_id && r.1 == input.kid)
        {
            *existing_row = new_tuple;
        } else {
            rows.push(new_tuple);
            rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        }

        let entries: Vec<serde_json::Value> = rows
            .into_iter()
            .map(
                |(human_id, kid, role, jwk_json, enc_jwk_json, auth_epoch)| {
                    json!({
                        "humanId": human_id,
                        "kid": kid,
                        "role": role,
                        "jwkJson": jwk_json,
                        "encJwkJson": enc_jwk_json,
                        "authEpoch": auth_epoch,
                    })
                },
            )
            .collect();
        let payload = json!({ "authorities": entries });
        let canon = canonical_json(&payload);
        Ok(sha256_hex(canon.as_bytes()))
    }
}

fn row_to_delegation_policy(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoreResult<HumanDelegationPolicy>> {
    let human_id: String = row.get(0)?;
    let node_prefix: String = row.get(1)?;
    let scopes_json: String = row.get(2)?;
    let max_devices_i64: i64 = row.get(3)?;
    let enabled_i64: i64 = row.get(4)?;
    let updated_at: i64 = row.get(5)?;

    Ok((|| {
        let scopes: Vec<String> = serde_json::from_str(&scopes_json)?;
        let max_devices = u32::try_from(max_devices_i64).map_err(|_| {
            StoreError::InvalidState(format!(
                "corrupt max_devices '{max_devices_i64}' for human '{human_id}'"
            ))
        })?;
        Ok(HumanDelegationPolicy {
            human_id,
            node_prefix,
            scopes,
            max_devices,
            delegation_enabled: enabled_i64 != 0,
            updated_at,
        })
    })())
}

fn read_min_auth_epoch(conn: &rusqlite::Connection) -> StoreResult<u64> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![HUMAN_MIN_AUTH_EPOCH_META_KEY],
            |row| row.get(0),
        )
        .optional()?;
    let Some(val) = raw else {
        return Ok(1);
    };
    let parsed: u64 = val.parse().map_err(|_| {
        StoreError::InvalidState(format!(
            "corrupt metadata '{HUMAN_MIN_AUTH_EPOCH_META_KEY}' value '{val}'"
        ))
    })?;
    if parsed == 0 {
        return Err(StoreError::InvalidState(format!(
            "corrupt metadata '{HUMAN_MIN_AUTH_EPOCH_META_KEY}' value 0"
        )));
    }
    Ok(parsed)
}

fn row_to_authority(row: &rusqlite::Row<'_>) -> rusqlite::Result<HumanAuthorityRecord> {
    let role_raw: String = row.get(3)?;
    let epoch_i64: i64 = row.get(7)?;
    let status_raw: String = row.get(8)?;

    let role = HumanAuthorityRole::parse(&role_raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let status = HumanAuthorityStatus::parse(&status_raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let auth_epoch = u64::try_from(epoch_i64).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Integer, Box::new(e))
    })?;

    Ok(HumanAuthorityRecord {
        human_id: row.get(0)?,
        kid: row.get(1)?,
        label: row.get(2)?,
        role,
        jwk_json: row.get(4)?,
        enc_jwk_json: row.get(5)?,
        prf_salt: row.get(6)?,
        auth_epoch,
        status,
        created_at: row.get(9)?,
        revoked_at: row.get(10)?,
        revocation_json: row.get(11)?,
    })
}

fn row_to_node_cert(row: &rusqlite::Row<'_>) -> rusqlite::Result<HumanNodeCertRecord> {
    let epoch_i64: i64 = row.get(2)?;
    let auth_epoch = u64::try_from(epoch_i64).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Integer, Box::new(e))
    })?;
    Ok(HumanNodeCertRecord {
        node_id: row.get(0)?,
        human_kid: row.get(1)?,
        auth_epoch,
        signed_json: row.get(3)?,
        issued_at: row.get(4)?,
        expires_at: row.get(5)?,
    })
}

fn validate_human_id(id: &str) -> StoreResult<()> {
    if !is_node_id(id) {
        return Err(StoreError::InvalidInput(format!("invalid human_id '{id}'")));
    }
    Ok(())
}

fn validate_token_id(field: &str, value: &str) -> StoreResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(StoreError::InvalidInput(format!(
            "invalid {field} '{value}'"
        )));
    }
    Ok(())
}

fn validate_label(label: &str) -> StoreResult<()> {
    let trimmed = label.trim();
    if trimmed.is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
        return Err(StoreError::InvalidInput(
            "label must be 1..=128 printable characters".into(),
        ));
    }
    Ok(())
}

fn validate_epoch(epoch: u64) -> StoreResult<i64> {
    if epoch == 0 {
        return Err(StoreError::InvalidInput("auth_epoch must be >= 1".into()));
    }
    i64::try_from(epoch)
        .map_err(|_| StoreError::InvalidInput("auth_epoch exceeds SQLite i64 range".into()))
}

fn validate_json_object(field: &str, raw: &str) -> StoreResult<()> {
    let parsed: serde_json::Value = serde_json::from_str(raw)?;
    if !parsed.is_object() {
        return Err(StoreError::InvalidInput(format!(
            "{field} must be a JSON object"
        )));
    }
    Ok(())
}
