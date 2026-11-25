//! Durable wakeup scheduler store (`wakeups` table: one-shot timers and 5-field crons)
//! with quota enforcement, ownership checks, laptop-sleep catch-up coalescing, and
//! consecutive-failure auto-pause.

use hyp_proto::cron::{CronExpr, CronTimezone, DEFAULT_MIN_CRON_INTERVAL_SECS, apply_cron_jitter};
use rusqlite::types::Value as SqlValue;
use rusqlite::{OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};

use crate::db::NodeDb;
use crate::error::{StoreError, StoreResult};
use crate::types::uuid_v4;

/// Default TTL applied to wakeup mailbox entries (1 hour).
pub const DEFAULT_WAKEUP_TTL_MS: i64 = 3_600_000;
/// Maximum number of missed cron slots walked slot-by-slot before switching to O(1) jump.
const MAX_MISSED_WALK: u64 = 10_000;
/// Maximum UTF-8 byte length for an explicit wakeup ID.
const MAX_WAKEUP_ID_BYTES: usize = 128;

/// Kind of trigger backing a durable wakeup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WakeupTriggerKind {
    Timer,
    Cron,
}

impl WakeupTriggerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Timer => "timer",
            Self::Cron => "cron",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "timer" => Ok(Self::Timer),
            "cron" => Ok(Self::Cron),
            other => Err(StoreError::InvalidInput(format!(
                "invalid wakeup trigger_kind '{other}'"
            ))),
        }
    }
}

/// Lifecycle state of a durable wakeup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WakeupState {
    Active,
    Paused,
    Completed,
    Cancelled,
    Failed,
}

impl WakeupState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "active" => Ok(Self::Active),
            "paused" => Ok(Self::Paused),
            "completed" => Ok(Self::Completed),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::InvalidInput(format!(
                "invalid wakeup state '{other}'"
            ))),
        }
    }
}

/// Delivery urgency requested when a wakeup fires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WakeupUrgency {
    Interrupt,
    #[default]
    Queue,
    Notify,
}

impl WakeupUrgency {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Queue => "queue",
            Self::Notify => "notify",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "interrupt" => Ok(Self::Interrupt),
            "queue" => Ok(Self::Queue),
            "notify" => Ok(Self::Notify),
            other => Err(StoreError::InvalidInput(format!(
                "invalid wakeup urgency '{other}'"
            ))),
        }
    }
}

/// Configurable quota and validation limits for [`WakeupStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeupLimits {
    pub max_active_per_session: usize,
    pub max_active_global: usize,
    pub max_note_bytes: usize,
    pub max_label_bytes: usize,
    pub min_cron_interval_seconds: u64,
    pub min_timer_delay_ms: i64,
    pub max_timer_delay_ms: i64,
    pub min_ttl_ms: i64,
    pub max_ttl_ms: i64,
    pub max_consecutive_failures: u32,
}

impl Default for WakeupLimits {
    fn default() -> Self {
        Self {
            max_active_per_session: 16,
            max_active_global: 128,
            max_note_bytes: 1024,
            max_label_bytes: 128,
            min_cron_interval_seconds: DEFAULT_MIN_CRON_INTERVAL_SECS,
            min_timer_delay_ms: 1,
            max_timer_delay_ms: 365 * 24 * 60 * 60 * 1000,
            min_ttl_ms: 1,
            max_ttl_ms: 30 * 24 * 60 * 60 * 1000,
            max_consecutive_failures: 5,
        }
    }
}

/// Input specification for creating a durable wakeup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeupInsert {
    /// Optional caller-supplied ID; auto-generated UUID-backed ID when `None`.
    pub id: Option<String>,
    /// Owning agent session ID, or `None` for human CLI / static node config wakeups.
    pub owner_session_id: Option<String>,
    pub target_session_id: Option<String>,
    pub target_handle: Option<String>,
    pub target_topic: Option<String>,
    pub label: String,
    pub note: String,
    pub trigger_kind: WakeupTriggerKind,
    /// Required 5-field cron expression for [`WakeupTriggerKind::Cron`]; must be `None` for `Timer`.
    pub cron_expr: Option<String>,
    /// Cron timezone interpretation (defaults to [`CronTimezone::Local`]).
    pub timezone: CronTimezone,
    /// When `true`, disables deterministic cron jitter.
    pub exact_timing: bool,
    pub urgency: WakeupUrgency,
    /// Mailbox TTL in milliseconds applied when this wakeup delivers to a session.
    pub ttl_ms: i64,
    /// When `true`, unread wakeup deliveries coalesce in place per wakeup key.
    pub coalesce: bool,
    /// Required fire timestamp (epoch ms) for [`WakeupTriggerKind::Timer`]; must be `None` for `Cron`.
    pub fire_at: Option<i64>,
    /// Maximum executions before completing. Required (`>= 1`) for agent-owned crons.
    pub max_iterations: Option<u64>,
    pub cold_revival_template: Option<String>,
}

/// Persisted durable wakeup record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeupRecord {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_topic: Option<String>,
    pub label: String,
    pub note: String,
    pub trigger_kind: WakeupTriggerKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron_expr: Option<String>,
    pub timezone: CronTimezone,
    pub exact_timing: bool,
    pub urgency: WakeupUrgency,
    pub ttl_ms: i64,
    pub coalesce: bool,
    pub next_fire_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_fired_at: Option<i64>,
    pub iteration: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_iterations: Option<u64>,
    pub consecutive_failures: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cold_revival_template: Option<String>,
    pub state: WakeupState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Output emitted by [`WakeupStore::claim_due_wakeups`] for each claimed fire event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiredWakeup {
    pub wakeup: WakeupRecord,
    /// Scheduled fire timestamp (`next_fire_at`) that triggered this claim.
    pub scheduled_for_ms: i64,
    /// Actual wall-clock timestamp at which the claim ran (`now_ms`).
    pub fired_at_ms: i64,
    /// Number of intermediate cron slots skipped due to clock jump / sleep (`0` for normal fire).
    pub missed_count: u64,
    /// `true` when this fire transitioned the wakeup to [`WakeupState::Completed`].
    pub completed: bool,
}

/// Durable wakeup scheduler store view borrowed from [`NodeDb`].
pub struct WakeupStore<'a> {
    db: &'a NodeDb,
}

impl<'a> WakeupStore<'a> {
    pub(crate) fn new(db: &'a NodeDb) -> Self {
        Self { db }
    }

    /// Creates a new durable wakeup after fail-closed validation and quota checks.
    pub fn create_wakeup(
        &self,
        input: &WakeupInsert,
        limits: &WakeupLimits,
        now_ms: i64,
    ) -> StoreResult<WakeupRecord> {
        let id = match input.id.as_deref() {
            Some(explicit) => {
                validate_wakeup_id(explicit)?;
                explicit.to_string()
            }
            None => format!("wk-{}", uuid_v4()),
        };

        let label = input.label.trim();
        if label.is_empty() {
            return Err(StoreError::InvalidInput(
                "wakeup label must be non-empty".to_string(),
            ));
        }
        if label.len() > limits.max_label_bytes {
            return Err(StoreError::TooLarge(format!(
                "wakeup label is {} bytes; limit {}",
                label.len(),
                limits.max_label_bytes
            )));
        }

        if input.note.trim().is_empty() {
            return Err(StoreError::InvalidInput(
                "wakeup note must be non-empty".to_string(),
            ));
        }
        if input.note.len() > limits.max_note_bytes {
            return Err(StoreError::TooLarge(format!(
                "wakeup note is {} bytes; limit {}",
                input.note.len(),
                limits.max_note_bytes
            )));
        }

        validate_optional_non_empty("owner_session_id", input.owner_session_id.as_deref())?;
        validate_optional_non_empty("target_session_id", input.target_session_id.as_deref())?;
        validate_optional_non_empty("target_handle", input.target_handle.as_deref())?;
        validate_optional_non_empty("target_topic", input.target_topic.as_deref())?;
        validate_optional_non_empty(
            "cold_revival_template",
            input.cold_revival_template.as_deref(),
        )?;

        if input.target_session_id.is_none()
            && input.target_handle.is_none()
            && input.target_topic.is_none()
        {
            return Err(StoreError::InvalidInput(
                "wakeup requires at least one target (target_session_id, target_handle, or target_topic)"
                    .to_string(),
            ));
        }

        if input.ttl_ms < limits.min_ttl_ms || input.ttl_ms > limits.max_ttl_ms {
            return Err(StoreError::InvalidInput(format!(
                "wakeup ttl_ms {} must be in {}..={}",
                input.ttl_ms, limits.min_ttl_ms, limits.max_ttl_ms
            )));
        }

        if input.max_iterations == Some(0) {
            return Err(StoreError::InvalidInput(
                "wakeup max_iterations must be >= 1".to_string(),
            ));
        }

        let (canonical_cron, next_fire_at, normalized_max_iterations) = match input.trigger_kind {
            WakeupTriggerKind::Timer => {
                if input.cron_expr.is_some() {
                    return Err(StoreError::InvalidInput(
                        "timer wakeup must not specify cron_expr".to_string(),
                    ));
                }
                if let Some(max_it) = input.max_iterations {
                    if max_it != 1 {
                        return Err(StoreError::InvalidInput(
                            "timer wakeup max_iterations must be None or Some(1)".to_string(),
                        ));
                    }
                }
                let fire_at = input.fire_at.ok_or_else(|| {
                    StoreError::InvalidInput("timer wakeup requires fire_at".to_string())
                })?;
                let min_fire = now_ms.saturating_add(limits.min_timer_delay_ms);
                let max_fire = now_ms.saturating_add(limits.max_timer_delay_ms);
                if fire_at < min_fire {
                    return Err(StoreError::InvalidInput(format!(
                        "timer fire_at ({fire_at}) must be at least {min_fire}"
                    )));
                }
                if fire_at > max_fire {
                    return Err(StoreError::InvalidInput(format!(
                        "timer fire_at ({fire_at}) exceeds maximum allowed horizon ({max_fire})"
                    )));
                }
                (None, fire_at, Some(1u64))
            }
            WakeupTriggerKind::Cron => {
                if input.fire_at.is_some() {
                    return Err(StoreError::InvalidInput(
                        "cron wakeup must not specify explicit fire_at".to_string(),
                    ));
                }
                if input.owner_session_id.is_some() && input.max_iterations.is_none() {
                    return Err(StoreError::InvalidInput(
                        "agent-owned cron wakeup requires max_iterations >= 1".to_string(),
                    ));
                }
                let raw_cron = input.cron_expr.as_deref().ok_or_else(|| {
                    StoreError::InvalidInput("cron wakeup requires cron_expr".to_string())
                })?;
                let parsed = CronExpr::parse(raw_cron)
                    .map_err(|e| StoreError::InvalidInput(e.to_string()))?;
                parsed
                    .validate_min_interval(limits.min_cron_interval_seconds)
                    .map_err(|e| StoreError::InvalidInput(e.to_string()))?;

                let first_base = parsed
                    .next_fire_after(now_ms, input.timezone)
                    .ok_or_else(|| {
                        StoreError::InvalidInput(format!(
                            "cron expression '{}' has no future fire time after {now_ms}",
                            parsed.as_str()
                        ))
                    })?;
                let interval_ms = parsed
                    .next_fire_after(first_base, input.timezone)
                    .map(|n| n.saturating_sub(first_base))
                    .unwrap_or(0);
                let first_fire = apply_cron_jitter(first_base, interval_ms, &id, input.exact_timing);

                (
                    Some(parsed.as_str().to_string()),
                    first_fire,
                    input.max_iterations,
                )
            }
        };

        let tx = self.db.immediate_tx()?;

        let active_global: i64 = tx.conn().query_row(
            "SELECT COUNT(*) FROM wakeups WHERE state = 'active'",
            [],
            |row| row.get(0),
        )?;
        if active_global as usize >= limits.max_active_global {
            return Err(StoreError::QuotaExceeded(format!(
                "global active wakeup limit reached ({active_global}/{})",
                limits.max_active_global
            )));
        }

        if let Some(owner) = input.owner_session_id.as_deref() {
            let active_owner: i64 = tx.conn().query_row(
                "SELECT COUNT(*) FROM wakeups WHERE owner_session_id = ?1 AND state = 'active'",
                params![owner],
                |row| row.get(0),
            )?;
            if active_owner as usize >= limits.max_active_per_session {
                return Err(StoreError::QuotaExceeded(format!(
                    "session '{owner}' active wakeup limit reached ({active_owner}/{})",
                    limits.max_active_per_session
                )));
            }
        }

        let insert_res = tx.conn().execute(
            "INSERT INTO wakeups
             (id, owner_session_id, target_session_id, target_handle, target_topic,
              label, note, trigger_kind, cron_expr, timezone, exact_timing, urgency,
              ttl_ms, coalesce, next_fire_at, last_fired_at, iteration, max_iterations,
              consecutive_failures, cold_revival_template, state, last_error, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                     NULL, 0, ?16, 0, ?17, 'active', NULL, ?18, ?18)",
            params![
                &id,
                input.owner_session_id.as_deref(),
                input.target_session_id.as_deref(),
                input.target_handle.as_deref(),
                input.target_topic.as_deref(),
                label,
                &input.note,
                input.trigger_kind.as_str(),
                canonical_cron.as_deref(),
                input.timezone.as_str(),
                i64::from(input.exact_timing),
                input.urgency.as_str(),
                input.ttl_ms,
                i64::from(input.coalesce),
                next_fire_at,
                normalized_max_iterations.map(|v| v as i64),
                input.cold_revival_template.as_deref(),
                now_ms,
            ],
        );

        match insert_res {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(StoreError::IdConflict(format!(
                    "wakeup id '{id}' already exists"
                )));
            }
            Err(err) => return Err(err.into()),
        }

        let rec = tx.conn().query_row(
            "SELECT * FROM wakeups WHERE id = ?1",
            params![&id],
            decode_wakeup_row,
        )??;
        tx.commit()?;
        Ok(rec)
    }

    /// Fetches a single wakeup by ID.
    pub fn get_wakeup(&self, id: &str) -> StoreResult<Option<WakeupRecord>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM wakeups WHERE id = ?1",
                params![id],
                decode_wakeup_row,
            )
            .optional()?
            .transpose()
    }

    /// Lists wakeups filtered optionally by `owner_session_id` and/or [`WakeupState`],
    /// ordered deterministically by `(next_fire_at ASC, id ASC)`.
    pub fn list_wakeups(
        &self,
        owner_session_filter: Option<&str>,
        state_filter: Option<WakeupState>,
    ) -> StoreResult<Vec<WakeupRecord>> {
        let mut sql = String::from("SELECT * FROM wakeups WHERE 1 = 1");
        let mut bind: Vec<SqlValue> = Vec::new();

        if let Some(owner) = owner_session_filter {
            sql.push_str(" AND owner_session_id = ?");
            bind.push(SqlValue::Text(owner.to_string()));
        }
        if let Some(state) = state_filter {
            sql.push_str(" AND state = ?");
            bind.push(SqlValue::Text(state.as_str().to_string()));
        }
        sql.push_str(" ORDER BY next_fire_at ASC, id ASC");

        let mut stmt = self.db.conn().prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(bind), decode_wakeup_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }

    /// Lists active or paused wakeups owned by or targeting `session_id` (and optionally `handle`),
    /// ordered deterministically by `(next_fire_at ASC, id ASC)`.
    pub fn list_active_wakeups_for_session(
        &self,
        session_id: &str,
        handle: Option<&str>,
    ) -> StoreResult<Vec<WakeupRecord>> {
        let mut sql = String::from(
            "SELECT * FROM wakeups
             WHERE state IN ('active', 'paused')
               AND (owner_session_id = ?1 OR target_session_id = ?1",
        );
        let mut bind: Vec<SqlValue> = vec![SqlValue::Text(session_id.to_string())];
        if let Some(h) = handle.filter(|s| !s.is_empty()) {
            sql.push_str(" OR target_handle = ?2");
            bind.push(SqlValue::Text(h.to_string()));
        }
        sql.push_str(") ORDER BY next_fire_at ASC, id ASC");

        let mut stmt = self.db.conn().prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(bind), decode_wakeup_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }

    /// Cancels a wakeup atomically, enforcing session ownership whenever `caller_session_opt` is `Some`.
    pub fn cancel_wakeup(
        &self,
        id: &str,
        caller_session_opt: Option<&str>,
        now_ms: i64,
    ) -> StoreResult<WakeupRecord> {
        let tx = self.db.immediate_tx()?;
        let existing = fetch_wakeup_in_tx(tx.conn(), id)?;
        enforce_ownership(&existing, caller_session_opt)?;

        if !matches!(existing.state, WakeupState::Active | WakeupState::Paused) {
            return Err(StoreError::InvalidState(format!(
                "wakeup '{id}' is in terminal state '{}' and cannot be cancelled",
                existing.state.as_str()
            )));
        }

        tx.conn().execute(
            "UPDATE wakeups SET state = 'cancelled', updated_at = ?1 WHERE id = ?2",
            params![now_ms, id],
        )?;
        let updated = fetch_wakeup_in_tx(tx.conn(), id)?;
        tx.commit()?;
        Ok(updated)
    }

    /// Pauses an active wakeup atomically, enforcing ownership when `caller_session_opt` is `Some`.
    pub fn pause_wakeup(
        &self,
        id: &str,
        caller_session_opt: Option<&str>,
        now_ms: i64,
    ) -> StoreResult<WakeupRecord> {
        let tx = self.db.immediate_tx()?;
        let existing = fetch_wakeup_in_tx(tx.conn(), id)?;
        enforce_ownership(&existing, caller_session_opt)?;

        if existing.state != WakeupState::Active {
            return Err(StoreError::InvalidState(format!(
                "wakeup '{id}' is in state '{}', expected 'active'",
                existing.state.as_str()
            )));
        }

        tx.conn().execute(
            "UPDATE wakeups SET state = 'paused', updated_at = ?1 WHERE id = ?2",
            params![now_ms, id],
        )?;
        let updated = fetch_wakeup_in_tx(tx.conn(), id)?;
        tx.commit()?;
        Ok(updated)
    }

    /// Resumes a paused wakeup atomically, clearing `consecutive_failures` and `last_error`
    /// and advancing stale cron `next_fire_at` strictly past `now_ms`.
    pub fn resume_wakeup(
        &self,
        id: &str,
        caller_session_opt: Option<&str>,
        now_ms: i64,
    ) -> StoreResult<WakeupRecord> {
        let tx = self.db.immediate_tx()?;
        let existing = fetch_wakeup_in_tx(tx.conn(), id)?;
        enforce_ownership(&existing, caller_session_opt)?;

        if existing.state != WakeupState::Paused {
            return Err(StoreError::InvalidState(format!(
                "wakeup '{id}' is in state '{}', expected 'paused'",
                existing.state.as_str()
            )));
        }

        let mut next_fire_at = existing.next_fire_at;
        if existing.trigger_kind == WakeupTriggerKind::Cron && next_fire_at <= now_ms {
            let raw_cron = existing.cron_expr.as_deref().ok_or_else(|| {
                StoreError::InvalidState(format!("cron wakeup '{id}' missing cron_expr"))
            })?;
            let parsed = CronExpr::parse(raw_cron)
                .map_err(|e| StoreError::InvalidState(format!("corrupt cron_expr: {e}")))?;
            let next_base = parsed.next_fire_after(now_ms, existing.timezone).ok_or_else(|| {
                StoreError::InvalidState(format!(
                    "cron wakeup '{id}' has no future fire time after {now_ms}"
                ))
            })?;
            let interval_ms = parsed
                .next_fire_after(next_base, existing.timezone)
                .map(|n| n.saturating_sub(next_base))
                .unwrap_or(0);
            next_fire_at = apply_cron_jitter(next_base, interval_ms, &existing.id, existing.exact_timing);
        }

        tx.conn().execute(
            "UPDATE wakeups
             SET state = 'active',
                 consecutive_failures = 0,
                 last_error = NULL,
                 next_fire_at = ?1,
                 updated_at = ?2
             WHERE id = ?3",
            params![next_fire_at, now_ms, id],
        )?;
        let updated = fetch_wakeup_in_tx(tx.conn(), id)?;
        tx.commit()?;
        Ok(updated)
    }

    /// Cancels all `active` and `paused` wakeups owned by `session_id` (e.g., on session leave/prune).
    pub fn cancel_owned_by_session(&self, session_id: &str, now_ms: i64) -> StoreResult<usize> {
        let tx = self.db.immediate_tx()?;
        let changed = tx.conn().execute(
            "UPDATE wakeups
             SET state = 'cancelled', updated_at = ?1
             WHERE owner_session_id = ?2 AND state IN ('active', 'paused')",
            params![now_ms, session_id],
        )?;
        tx.commit()?;
        Ok(changed)
    }

    /// Records the delivery outcome of a fired wakeup.
    ///
    /// - On success: resets `consecutive_failures = 0` and clears `last_error`.
    /// - On failure: increments `consecutive_failures`, records `last_error`, and auto-pauses
    ///   (`state = 'paused'`) an `active` wakeup once `consecutive_failures >= max_consecutive_failures`.
    pub fn record_delivery_result(
        &self,
        id: &str,
        succeeded: bool,
        terminal_error_opt: Option<&str>,
        max_consecutive_failures: u32,
        now_ms: i64,
    ) -> StoreResult<WakeupRecord> {
        let tx = self.db.immediate_tx()?;
        let existing = fetch_wakeup_in_tx(tx.conn(), id)?;

        if succeeded {
            tx.conn().execute(
                "UPDATE wakeups
                 SET consecutive_failures = 0, last_error = NULL, updated_at = ?1
                 WHERE id = ?2",
                params![now_ms, id],
            )?;
        } else {
            let new_failures = existing.consecutive_failures.saturating_add(1);
            let threshold = max_consecutive_failures.max(1);
            let new_state = if existing.state == WakeupState::Active && new_failures >= threshold {
                WakeupState::Paused
            } else {
                existing.state
            };
            let err_text = terminal_error_opt
                .map(|s| s.to_string())
                .or_else(|| existing.last_error.clone())
                .unwrap_or_else(|| "delivery failed".to_string());

            tx.conn().execute(
                "UPDATE wakeups
                 SET consecutive_failures = ?1,
                     state = ?2,
                     last_error = ?3,
                     updated_at = ?4
                 WHERE id = ?5",
                params![
                    i64::from(new_failures),
                    new_state.as_str(),
                    &err_text,
                    now_ms,
                    id,
                ],
            )?;
        }

        let updated = fetch_wakeup_in_tx(tx.conn(), id)?;
        tx.commit()?;
        Ok(updated)
    }

    /// Atomically claims all due wakeups (`state = 'active' AND next_fire_at <= now_ms`).
    ///
    /// - Takes zero write lock when no wakeups are due.
    /// - One-shot timers and exhausted `max_iterations` crons transition to `completed`.
    /// - Recurring crons skip missed wall-clock slots after sleep, reporting `missed_count` and
    ///   advancing `next_fire_at` strictly `> now_ms` (at most 1 catch-up tick, never a burst).
    pub fn claim_due_wakeups(&self, now_ms: i64) -> StoreResult<Vec<FiredWakeup>> {
        let has_due: bool = self.db.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM wakeups WHERE state = 'active' AND next_fire_at <= ?1)",
            params![now_ms],
            |row| row.get(0),
        )?;
        if !has_due {
            return Ok(Vec::new());
        }

        let tx = self.db.immediate_tx()?;
        let mut stmt = tx.conn().prepare(
            "SELECT * FROM wakeups
             WHERE state = 'active' AND next_fire_at <= ?1
             ORDER BY next_fire_at ASC, id ASC",
        )?;
        let due = stmt
            .query_map(params![now_ms], decode_wakeup_row)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<StoreResult<Vec<_>>>()?;
        drop(stmt);

        let mut fired = Vec::with_capacity(due.len());

        for rec in due {
            let scheduled_for_ms = rec.next_fire_at;
            let new_iteration = rec.iteration.saturating_add(1);

            match rec.trigger_kind {
                WakeupTriggerKind::Timer => {
                    tx.conn().execute(
                        "UPDATE wakeups
                         SET iteration = ?1,
                             last_fired_at = ?2,
                             state = 'completed',
                             updated_at = ?2
                         WHERE id = ?3",
                        params![new_iteration as i64, now_ms, &rec.id],
                    )?;
                    let updated = fetch_wakeup_in_tx(tx.conn(), &rec.id)?;
                    fired.push(FiredWakeup {
                        wakeup: updated,
                        scheduled_for_ms,
                        fired_at_ms: now_ms,
                        missed_count: 0,
                        completed: true,
                    });
                }
                WakeupTriggerKind::Cron => {
                    let parsed = match rec.cron_expr.as_deref().map(CronExpr::parse) {
                        Some(Ok(expr)) => expr,
                        Some(Err(err)) => {
                            let msg = format!("corrupt cron_expr: {err}");
                            tx.conn().execute(
                                "UPDATE wakeups
                                 SET state = 'failed', last_error = ?1, updated_at = ?2
                                 WHERE id = ?3",
                                params![&msg, now_ms, &rec.id],
                            )?;
                            continue;
                        }
                        None => {
                            tx.conn().execute(
                                "UPDATE wakeups
                                 SET state = 'failed', last_error = 'missing cron_expr', updated_at = ?1
                                 WHERE id = ?2",
                                params![now_ms, &rec.id],
                            )?;
                            continue;
                        }
                    };

                    let (missed_count, next_base_opt) =
                        advance_cron_after_fire(&parsed, rec.timezone, scheduled_for_ms, now_ms);

                    let exhausted = rec
                        .max_iterations
                        .is_some_and(|max_it| new_iteration >= max_it);

                    let (new_state, new_next_fire_at) = if exhausted {
                        (WakeupState::Completed, scheduled_for_ms)
                    } else if let Some(next_base) = next_base_opt {
                        let interval_ms = parsed
                            .next_fire_after(next_base, rec.timezone)
                            .map(|n| n.saturating_sub(next_base))
                            .unwrap_or(0);
                        let next_fire =
                            apply_cron_jitter(next_base, interval_ms, &rec.id, rec.exact_timing);
                        (WakeupState::Active, next_fire)
                    } else {
                        (WakeupState::Completed, scheduled_for_ms)
                    };

                    tx.conn().execute(
                        "UPDATE wakeups
                         SET iteration = ?1,
                             last_fired_at = ?2,
                             next_fire_at = ?3,
                             state = ?4,
                             updated_at = ?2
                         WHERE id = ?5",
                        params![
                            new_iteration as i64,
                            now_ms,
                            new_next_fire_at,
                            new_state.as_str(),
                            &rec.id,
                        ],
                    )?;
                    let updated = fetch_wakeup_in_tx(tx.conn(), &rec.id)?;
                    fired.push(FiredWakeup {
                        wakeup: updated,
                        scheduled_for_ms,
                        fired_at_ms: now_ms,
                        missed_count,
                        completed: new_state == WakeupState::Completed,
                    });
                }
            }
        }

        tx.commit()?;
        Ok(fired)
    }

    /// Returns the earliest `next_fire_at` among all active wakeups, or `None` when idle.
    pub fn next_deadline_ms(&self) -> StoreResult<Option<i64>> {
        let next: Option<i64> = self.db.conn().query_row(
            "SELECT MIN(next_fire_at) FROM wakeups WHERE state = 'active'",
            [],
            |row| row.get(0),
        )?;
        Ok(next)
    }
}

/// Counts missed wall-clock cron slots `<= now_ms` after `scheduled_for_ms` and returns
/// `(missed_count, next_un_jittered_fire_ms_strictly_gt_now_ms)`.
fn advance_cron_after_fire(
    cron: &CronExpr,
    timezone: CronTimezone,
    scheduled_for_ms: i64,
    now_ms: i64,
) -> (u64, Option<i64>) {
    let mut missed: u64 = 0;
    let mut cursor = scheduled_for_ms;

    loop {
        let Some(candidate) = cron.next_fire_after(cursor, timezone) else {
            return (missed, None);
        };
        if candidate <= now_ms {
            missed = missed.saturating_add(1);
            cursor = candidate;
            if missed >= MAX_MISSED_WALK {
                if let Some(min_secs) = cron.min_interval_seconds() {
                    let remaining_ms = now_ms.saturating_sub(cursor);
                    let step_ms = (min_secs as i64).saturating_mul(1000).max(60_000);
                    missed = missed.saturating_add((remaining_ms / step_ms).max(0) as u64);
                }
                return (missed, cron.next_fire_after(now_ms, timezone));
            }
        } else {
            return (missed, Some(candidate));
        }
    }
}

fn validate_wakeup_id(id: &str) -> StoreResult<()> {
    if id.is_empty() || id.len() > MAX_WAKEUP_ID_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "wakeup id must be 1..={MAX_WAKEUP_ID_BYTES} ASCII bytes"
        )));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(StoreError::InvalidInput(format!(
            "wakeup id '{id}' contains disallowed characters"
        )));
    }
    Ok(())
}

fn validate_optional_non_empty(field: &str, value: Option<&str>) -> StoreResult<()> {
    if let Some(s) = value {
        if s.trim().is_empty() {
            return Err(StoreError::InvalidInput(format!(
                "wakeup {field} must be non-empty when provided"
            )));
        }
    }
    Ok(())
}

fn enforce_ownership(rec: &WakeupRecord, caller_session_opt: Option<&str>) -> StoreResult<()> {
    if let Some(caller) = caller_session_opt {
        if rec.owner_session_id.as_deref() != Some(caller) {
            return Err(StoreError::Unauthorized(format!(
                "session '{caller}' does not own wakeup '{}'",
                rec.id
            )));
        }
    }
    Ok(())
}

fn fetch_wakeup_in_tx(conn: &rusqlite::Connection, id: &str) -> StoreResult<WakeupRecord> {
    conn.query_row(
        "SELECT * FROM wakeups WHERE id = ?1",
        params![id],
        decode_wakeup_row,
    )
    .optional()?
    .transpose()?
    .ok_or_else(|| StoreError::NotFound(format!("wakeup '{id}' not found")))
}

fn decode_wakeup_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<WakeupRecord>> {
    let id: String = row.get("id")?;
    let owner_session_id: Option<String> = row.get("owner_session_id")?;
    let target_session_id: Option<String> = row.get("target_session_id")?;
    let target_handle: Option<String> = row.get("target_handle")?;
    let target_topic: Option<String> = row.get("target_topic")?;
    let label: String = row.get("label")?;
    let note: String = row.get("note")?;
    let trigger_kind_str: String = row.get("trigger_kind")?;
    let cron_expr: Option<String> = row.get("cron_expr")?;
    let timezone_str: String = row.get("timezone")?;
    let exact_timing: i64 = row.get("exact_timing")?;
    let urgency_str: String = row.get("urgency")?;
    let ttl_ms: i64 = row.get("ttl_ms")?;
    let coalesce: i64 = row.get("coalesce")?;
    let next_fire_at: i64 = row.get("next_fire_at")?;
    let last_fired_at: Option<i64> = row.get("last_fired_at")?;
    let iteration: i64 = row.get("iteration")?;
    let max_iterations: Option<i64> = row.get("max_iterations")?;
    let consecutive_failures: i64 = row.get("consecutive_failures")?;
    let cold_revival_template: Option<String> = row.get("cold_revival_template")?;
    let state_str: String = row.get("state")?;
    let last_error: Option<String> = row.get("last_error")?;
    let created_at: i64 = row.get("created_at")?;
    let updated_at: i64 = row.get("updated_at")?;

    Ok((|| {
        let trigger_kind = WakeupTriggerKind::parse(&trigger_kind_str)?;
        let timezone = CronTimezone::parse(&timezone_str)
            .map_err(|e| StoreError::InvalidInput(e.to_string()))?;
        let urgency = WakeupUrgency::parse(&urgency_str)?;
        let state = WakeupState::parse(&state_str)?;

        Ok(WakeupRecord {
            id,
            owner_session_id,
            target_session_id,
            target_handle,
            target_topic,
            label,
            note,
            trigger_kind,
            cron_expr,
            timezone,
            exact_timing: exact_timing != 0,
            urgency,
            ttl_ms,
            coalesce: coalesce != 0,
            next_fire_at,
            last_fired_at,
            iteration: iteration.max(0) as u64,
            max_iterations: max_iterations.map(|v| v.max(0) as u64),
            consecutive_failures: consecutive_failures.clamp(0, i64::from(u32::MAX)) as u32,
            cold_revival_template,
            state,
            last_error,
            created_at,
            updated_at,
        })
    })())
}
