//! Session activity leases, one-shot retries, expiry and runtime lifecycle.

use super::{
    DaemonStateLock, GATE_HOLD_RETRY_MARGIN_MS, GATE_HOLD_RETRY_MAX_ATTEMPTS,
    GATE_HOLD_RETRY_MAX_MS, GATE_HOLD_RETRY_MIN_MS, LocalDaemonInner, SessionRuntime,
};
use hyp_harness_ipc::protocol::HarnessKind;
use hyp_node::delivery::DeliveryUrgency;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

/// Sliding hook-observed activity lease for a session (`Active` until `active_until`,
/// immediately cleared to `Idle` on TurnEnd `Stop` / `agent_end` / `wait.subscribe`).
#[derive(Debug, Clone, Copy)]
struct SessionActivity {
    harness: HarnessKind,
    active_until: Instant,
}

#[derive(Debug, Clone, Copy)]
struct ActivityGraceTimer {
    generation: u64,
    fire_at: Instant,
    mode: SessionFlushMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionFlushMode {
    Normal,
    InterruptGraceExpired,
    ClaudeIdleWake,
}

struct InterruptWakeCooldown {
    generation: u64,
    deferred: bool,
}

#[derive(Clone, Copy)]
struct HoldRetry {
    attempt: u32,
    generation: u64,
}

#[derive(Clone, Copy)]
struct GateHoldRetry {
    attempt: u32,
    generation: u64,
    fire_at_ms: i64,
}

/// Lease and retry state is private to its scheduling/lifecycle owner.
#[derive(Default)]
pub(super) struct SessionTimers {
    activity: Option<SessionActivity>,
    activity_grace: Option<ActivityGraceTimer>,
    interrupt_wake: Option<InterruptWakeCooldown>,
    transport_retry: Option<HoldRetry>,
    gate_retry: Option<GateHoldRetry>,
}

impl LocalDaemonInner {
    pub(super) fn cancel_hold_retry(&self, session_id: &str) {
        self.clear_runtime_field(session_id, |runtime| runtime.timers.transport_retry = None);
    }

    pub(super) fn session_runtime(&self) -> MutexGuard<'_, HashMap<String, SessionRuntime>> {
        self.session_runtime
            .lock_state("session_runtime lock poisoned")
    }

    pub(super) fn update_runtime<T>(
        &self,
        session_id: &str,
        update: impl FnOnce(&mut SessionRuntime) -> T,
    ) -> Option<T> {
        let mut sessions = self.session_runtime();
        let runtime = sessions.get_mut(session_id)?;
        let result = update(runtime);
        if runtime.is_empty() {
            sessions.remove(session_id);
        }
        Some(result)
    }

    pub(super) fn clear_runtime_field(
        &self,
        session_id: &str,
        clear: impl FnOnce(&mut SessionRuntime),
    ) {
        self.update_runtime(session_id, clear);
    }

    pub(super) fn cancel_activity_grace(&self, session_id: &str) {
        self.clear_runtime_field(session_id, |runtime| {
            if !runtime
                .timers
                .activity_grace
                .is_some_and(|timer| timer.mode == SessionFlushMode::ClaudeIdleWake)
            {
                runtime.timers.activity_grace = None;
            }
        });
    }

    pub(super) fn infer_session_harness(
        session_id: &str,
        explicit: Option<HarnessKind>,
    ) -> Option<HarnessKind> {
        if explicit.is_some() {
            return explicit;
        }
        let prefix = session_id.split(':').next()?;
        prefix.parse::<HarnessKind>().ok()
    }

    pub(super) fn can_drain_mid_turn(harness: HarnessKind) -> bool {
        matches!(
            harness,
            HarnessKind::Claude
                | HarnessKind::Codex
                | HarnessKind::Cursor
                | HarnessKind::Gemini
                | HarnessKind::Opencode
                | HarnessKind::Antigravity
        )
    }

    pub(super) fn can_drain_turn_end(harness: HarnessKind) -> bool {
        matches!(
            harness,
            HarnessKind::Claude
                | HarnessKind::Codex
                | HarnessKind::Cursor
                | HarnessKind::Gemini
                | HarnessKind::Opencode
                | HarnessKind::Antigravity
                | HarnessKind::Openclaw
        )
    }

    /// Marks `session_id` as `Active` (turn in flight) for a sliding lease window.
    pub(super) fn mark_session_active(&self, session_id: &str, harness: HarnessKind) {
        if self.config.queue_activity_lease.is_zero() {
            return;
        }
        let active_until = Instant::now() + self.config.queue_activity_lease;
        self.session_runtime()
            .entry(session_id.to_owned())
            .or_default()
            .timers
            .activity = Some(SessionActivity {
            harness,
            active_until,
        });
    }

    pub(super) fn reset_midturn_digest_timer(&self, session_id: &str) {
        self.clear_runtime_field(session_id, |runtime| {
            runtime.last_midturn_digest_at_ms = None
        });
    }

    pub(super) fn record_midturn_digest_timestamp(&self, session_id: &str, ts_ms: i64) {
        self.session_runtime()
            .entry(session_id.to_owned())
            .or_default()
            .last_midturn_digest_at_ms = Some(ts_ms);
    }

    /// Immediately transitions `session_id` to `Idle` and cancels any pending activity grace timer.
    pub(super) fn mark_session_idle(&self, session_id: &str) -> SessionFlushMode {
        let awaiting_claude_idle_wake = self.update_runtime(session_id, |runtime| {
            runtime.timers.activity = None;
            runtime.last_midturn_digest_at_ms = None;
            runtime
                .timers
                .activity_grace
                .take()
                .is_some_and(|timer| timer.mode == SessionFlushMode::ClaudeIdleWake)
        });
        if awaiting_claude_idle_wake == Some(true) {
            SessionFlushMode::ClaudeIdleWake
        } else {
            SessionFlushMode::Normal
        }
    }

    /// Returns the active hook activity lease for `session_id`, pruning it if already expired.
    pub(super) fn active_session_lease(&self, session_id: &str) -> Option<(HarnessKind, Duration)> {
        let now = Instant::now();
        let mut sessions = self.session_runtime();
        let runtime = sessions.get_mut(session_id)?;
        let activity = runtime.timers.activity?;
        if activity.active_until > now {
            return Some((
                activity.harness,
                activity.active_until.saturating_duration_since(now),
            ));
        }
        runtime.timers.activity = None;
        if runtime.is_empty() {
            sessions.remove(session_id);
        }
        None
    }

    /// Schedules one fallback flush after tool-boundary grace or idle lease expiry.
    /// A pending Claude idle wake retains queue semantics if another transport attaches.
    pub(super) fn schedule_activity_grace_flush(
        self: &Arc<Self>,
        session_id: &str,
        delay: Duration,
        mode: SessionFlushMode,
    ) {
        let delay = delay.max(Duration::from_millis(1));
        let now = Instant::now();
        let fire_at = now + delay;

        let generation = {
            let mut sessions = self.session_runtime();
            let runtime = sessions.entry(session_id.to_owned()).or_default();
            if let Some(existing) = runtime.timers.activity_grace {
                let waiting_for_idle = existing.mode == SessionFlushMode::ClaudeIdleWake;
                if waiting_for_idle {
                    if mode != SessionFlushMode::ClaudeIdleWake || existing.fire_at > now {
                        return;
                    }
                } else if mode != SessionFlushMode::ClaudeIdleWake
                    && existing.fire_at > now
                    && (existing.fire_at <= fire_at
                        || (existing.mode == SessionFlushMode::InterruptGraceExpired
                            && mode == SessionFlushMode::Normal))
                {
                    return;
                }
            }
            let generation = self.next_seq();
            runtime.timers.activity_grace = Some(ActivityGraceTimer {
                generation,
                fire_at,
                mode,
            });
            generation
        };

        let daemon = Arc::clone(self);
        let sid = session_id.to_string();
        let mut shutdown_rx = self.shutdown_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown_rx.changed() => {
                    return;
                }
            }
            if *shutdown_rx.borrow() {
                return;
            }
            let still_current = {
                let mut sessions = daemon.session_runtime();
                if let Some(runtime) = sessions.get_mut(&sid) {
                    if runtime
                        .timers
                        .activity_grace
                        .is_some_and(|timer| timer.generation == generation)
                    {
                        runtime.timers.activity_grace = None;
                        if runtime.is_empty() {
                            sessions.remove(&sid);
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if !still_current {
                return;
            }
            let _ = daemon.flush_session_inner(&sid, mode).await;
        });
    }

    pub(super) fn flush_lock_for(&self, session_id: &str) -> Arc<AsyncMutex<()>> {
        let mut sessions = self.session_runtime();
        let runtime = sessions.entry(session_id.to_owned()).or_default();
        Arc::clone(
            runtime
                .flush_lock
                .get_or_insert_with(|| Arc::new(AsyncMutex::new(()))),
        )
    }

    /// Defers repeated interrupt-capable pushes without consuming any mailbox receipts.
    pub(super) fn defer_interrupt_wake(&self, session_id: &str) -> bool {
        let mut sessions = self.session_runtime();
        if let Some(cooldown) = sessions
            .get_mut(session_id)
            .and_then(|runtime| runtime.timers.interrupt_wake.as_mut())
        {
            cooldown.deferred = true;
            return true;
        }
        false
    }

    /// A hook or inbox read can consume some or all deferred receipts during the window.
    /// Keep this timer independent of activity grace so the follow-up uses a fresh snapshot.
    pub(super) fn start_interrupt_wake_cooldown(self: &Arc<Self>, session_id: &str) {
        let delay = self.config.interrupt_wake_cooldown;
        if delay.is_zero() {
            return;
        }
        let generation = self.next_seq();
        self.session_runtime()
            .entry(session_id.to_owned())
            .or_default()
            .timers
            .interrupt_wake = Some(InterruptWakeCooldown {
            generation,
            deferred: false,
        });

        let daemon = Arc::clone(self);
        let sid = session_id.to_owned();
        let deadline = tokio::time::Instant::now() + delay;
        let mut shutdown_rx = self.shutdown_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {}
                _ = shutdown_rx.changed() => return,
            }
            // Serialize with any in-flight flush to avoid dropping the final wake on contention.
            let Some(lock) = daemon
                .session_runtime()
                .get(&sid)
                .and_then(|runtime| runtime.flush_lock.clone())
            else {
                return;
            };
            let guard = lock.lock().await;
            if *shutdown_rx.borrow() {
                return;
            }
            let deferred = daemon.update_runtime(&sid, |runtime| {
                let timer = &mut runtime.timers.interrupt_wake;
                if timer
                    .as_ref()
                    .is_some_and(|timer| timer.generation == generation)
                {
                    return timer.take().is_some_and(|timer| timer.deferred);
                }
                false
            });
            if deferred == Some(true) {
                let _ = daemon
                    .flush_session_locked(&sid, SessionFlushMode::Normal)
                    .await;
            }
            drop(guard);
            drop(lock);
            daemon.update_runtime(&sid, |_| ());
        });
    }

    pub(super) fn reconcile_lock_for(&self, session_id: &str) -> Arc<AsyncMutex<()>> {
        let mut sessions = self.session_runtime();
        let runtime = sessions.entry(session_id.to_owned()).or_default();
        Arc::clone(
            runtime
                .reconcile_lock
                .get_or_insert_with(|| Arc::new(AsyncMutex::new(()))),
        )
    }

    pub(super) fn cancel_gate_hold_retry(&self, session_id: &str) {
        self.clear_runtime_field(session_id, |runtime| runtime.timers.gate_retry = None);
    }

    /// Schedules a bounded delayed retry for Security Gate `Hold` verdicts (`rate_limited` /
    /// `gate_busy`) so held rows are retained unscreened and automatically reconciled & flushed
    /// once the rate-limit / concurrency window clears (G4).
    pub(super) fn schedule_gate_hold_retry(
        self: &Arc<Self>,
        session_id: &str,
        retry_after_ms: u64,
    ) {
        let delay_ms = retry_after_ms
            .saturating_add(GATE_HOLD_RETRY_MARGIN_MS)
            .clamp(GATE_HOLD_RETRY_MIN_MS, GATE_HOLD_RETRY_MAX_MS);
        let now = self.current_time_ms();
        let fire_at_ms = now.saturating_add(delay_ms as i64);

        let generation = {
            let mut sessions = self.session_runtime();
            let runtime = sessions.entry(session_id.to_owned()).or_default();
            if let Some(retry) = runtime.timers.gate_retry {
                if retry.fire_at_ms > now && retry.fire_at_ms <= fire_at_ms {
                    // An earlier retry timer is already armed for this session; don't starve it.
                    return;
                }
            }
            let next_attempt = runtime
                .timers
                .gate_retry
                .map(|retry| retry.attempt.saturating_add(1))
                .unwrap_or(1);
            if next_attempt > GATE_HOLD_RETRY_MAX_ATTEMPTS {
                runtime.timers.gate_retry = None;
                if runtime.is_empty() {
                    sessions.remove(session_id);
                }
                return;
            }
            let generation = self.next_seq();
            runtime.timers.gate_retry = Some(GateHoldRetry {
                attempt: next_attempt,
                generation,
                fire_at_ms,
            });
            generation
        };

        let daemon = Arc::clone(self);
        let sid = session_id.to_string();
        let mut shutdown_rx = self.shutdown_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                _ = shutdown_rx.changed() => {
                    return;
                }
            }
            if *shutdown_rx.borrow() {
                return;
            }
            let still_current = {
                let mut sessions = daemon.session_runtime();
                match sessions
                    .get_mut(&sid)
                    .and_then(|runtime| runtime.timers.gate_retry.as_mut())
                {
                    Some(retry) if retry.generation == generation => {
                        // Mark timer as fired while preserving the consecutive-attempt counter.
                        retry.fire_at_ms = 0;
                        true
                    }
                    _ => false,
                }
            };
            if !still_current {
                return;
            }
            if daemon.reconcile_session_inbox(&sid).await {
                daemon.flush_session(&sid).await;
            }
            daemon.bump_ui_rev();
        });
    }

    /// Schedules a single bounded Tier 3 retry task for a transient `Hold` outcome
    /// (`herdr_working`, `herdr_send_guard_refused`, `herdr_agent_not_ready`,
    /// `t3_server_unreachable`, `codex_queue_unavailable`).
    ///
    /// Zero background polling when `hold_retries` is empty; immediately invalidated
    /// whenever `commit_delivered_batch`, `mailbox.drain`, `hyp_inbox(ack)`, `tool_leave`,
    /// or daemon shutdown clears the session's pending items.
    pub(super) fn schedule_hold_retry(self: &Arc<Self>, session_id: &str) {
        let max_attempts = self.config.delivery_retry.hold_retry_max_attempts;
        if max_attempts == 0 || self.config.delivery_retry.hold_retry_backoff_ms.is_empty() {
            return;
        }
        let (generation, delay_ms) = {
            let mut sessions = self.session_runtime();
            let runtime = sessions.entry(session_id.to_owned()).or_default();
            let next_attempt = runtime
                .timers
                .transport_retry
                .map(|retry| retry.attempt.saturating_add(1))
                .unwrap_or(1);
            if next_attempt > max_attempts {
                runtime.timers.transport_retry = None;
                if runtime.is_empty() {
                    sessions.remove(session_id);
                }
                return;
            }
            let generation = self.next_seq();
            runtime.timers.transport_retry = Some(HoldRetry {
                attempt: next_attempt,
                generation,
            });
            let idx = ((next_attempt - 1) as usize)
                .min(self.config.delivery_retry.hold_retry_backoff_ms.len() - 1);
            let delay = self.config.delivery_retry.hold_retry_backoff_ms[idx].max(1);
            (generation, delay)
        };

        let daemon = Arc::clone(self);
        let sid = session_id.to_string();
        let mut shutdown_rx = self.shutdown_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                _ = shutdown_rx.changed() => {
                    return;
                }
            }
            if *shutdown_rx.borrow() {
                return;
            }
            let still_current = daemon
                .session_runtime()
                .get(&sid)
                .and_then(|runtime| runtime.timers.transport_retry)
                .is_some_and(|retry| retry.generation == generation);
            if !still_current {
                return;
            }
            let _ = daemon.flush_session(&sid).await;
        });
    }

    fn active_session_ids(&self) -> HashSet<String> {
        self.session_runtime()
            .iter()
            .filter(|(_, runtime)| {
                runtime.channel.is_some()
                    || !runtime.waiters.is_empty()
                    || runtime.attached_transport.is_some()
            })
            .map(|(session_id, _)| session_id.clone())
            .collect()
    }

    /// Safely prunes idle sessions older than `config.session_prune_after_ms` while skipping
    /// currently connected sessions and any session holding `gate_state = 'quarantined'` items (`U6`/`G16`).
    pub(super) fn prune_stale_sessions_now(&self) -> Vec<String> {
        let max_age_ms = self.config.session_prune_after_ms;
        if max_age_ms <= 0 {
            return Vec::new();
        }
        let now = self.current_time_ms();
        let cutoff = now.saturating_sub(max_age_ms);
        let active = self.active_session_ids();
        let pruned = {
            let db = self.node.db();
            db.local()
                .prune_sessions(cutoff, &active)
                .map(|r| r.pruned_sessions)
                .unwrap_or_default()
        };
        if !pruned.is_empty() {
            {
                let mut guard = self.item_meta.lock_state("item_meta lock poisoned");
                for sid in &pruned {
                    guard.remove(sid);
                }
            }
            {
                let mut guard = self.sub_meta.lock_state("sub_meta lock poisoned");
                for sid in &pruned {
                    guard.remove(sid);
                }
            }
            {
                let mut guard = self
                    .herdr_terminal_index
                    .lock_state("herdr_terminal_index lock poisoned");
                let pruned_set: HashSet<&str> = pruned.iter().map(String::as_str).collect();
                guard.retain(|_, list| {
                    list.retain(|s| !pruned_set.contains(s.as_str()));
                    !list.is_empty()
                });
            }
            {
                let mut guard = self
                    .hook_registered_sessions
                    .lock_state("hook_registered_sessions lock poisoned");
                for sid in &pruned {
                    guard.remove(sid);
                }
            }
            {
                let mut sessions = self.session_runtime();
                for session_id in &pruned {
                    if let Some(runtime) = sessions.get_mut(session_id) {
                        runtime.herdr_bare_shell_rejection = None;
                        runtime.lazy_hydrate_attempt_at = None;
                        runtime.quarantine_notices.clear();
                        runtime.env_file_exported = false;
                        if runtime.is_empty() {
                            sessions.remove(session_id);
                        }
                    }
                }
            }
            self.bump_ui_rev();
        }
        pruned
    }

    /// Sweeps expired persistent TTL mutes from SQLite and removes matching session `Mute` rules
    /// from `DeliveryEngine` (`U4`). Takes zero write lock when nothing has expired.
    pub(super) fn sweep_expired_mutes_and_policies(&self, now: i64) -> usize {
        let expired = {
            let db = self.node.db();
            let removed = db.local().sweep_expired_mutes(now).unwrap_or_default();
            for (scope, pattern) in &removed {
                if scope != "*" {
                    let _ = self.delivery.update_policy(&db, scope, |p| {
                        let is_mute = p.overrides.iter().any(|r| {
                            r.target.eq_ignore_ascii_case(pattern)
                                && r.delivery == DeliveryUrgency::Mute
                        });
                        if is_mute {
                            p.remove_rule(pattern);
                        }
                    });
                }
            }
            removed
        };
        if !expired.is_empty() {
            self.bump_ui_rev();
        }
        expired.len()
    }
    /// Disarm retry state before listener/task shutdown, retaining unrelated live state.
    pub(super) fn clear_session_retries(&self) {
        self.session_runtime().retain(|_, runtime| {
            runtime.timers.transport_retry = None;
            runtime.timers.gate_retry = None;
            !runtime.is_empty()
        });
    }

    /// Clear sleep-stale leases and transport failures; return interrupted sessions and retry count.
    pub(super) fn reset_runtime_after_wake(&self) -> (Vec<String>, usize) {
        let now_inst = Instant::now();
        let mut interrupted_active = Vec::new();
        let mut cleared_hold_retries = 0;
        self.session_runtime().retain(|session_id, runtime| {
            if runtime
                .timers
                .activity
                .take()
                .is_some_and(|activity| activity.active_until > now_inst)
            {
                interrupted_active.push(session_id.clone());
            }
            runtime.timers.activity_grace = None;
            runtime.timers.interrupt_wake = None;
            if runtime.timers.transport_retry.take().is_some() {
                cleared_hold_retries += 1;
            }
            !runtime.is_empty()
        });
        interrupted_active.sort();
        self.session_runtime().retain(|_, runtime| {
            runtime.lazy_hydrate_attempt_at = None;
            runtime.openclaw_session_missing = false;
            !runtime.is_empty()
        });
        (interrupted_active, cleared_hold_retries)
    }
}

impl SessionRuntime {
    pub(super) fn has_pending_retry_or_grace(&self) -> bool {
        self.has_transport_retry() || self.timers.activity_grace.is_some()
    }

    pub(super) fn has_transport_retry(&self) -> bool {
        self.timers.transport_retry.is_some()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.timers.activity.is_none()
            && self.timers.activity_grace.is_none()
            && self.timers.interrupt_wake.is_none()
            && self.last_midturn_digest_at_ms.is_none()
            && self.lazy_hydrate_attempt_at.is_none()
            && self.timers.transport_retry.is_none()
            && self.timers.gate_retry.is_none()
            && self.reconcile_lock.is_none()
            && self.quarantine_notices.is_empty()
            && self.herdr_bare_shell_rejection.is_none()
            && !self.openclaw_session_missing
            && self.waiters.is_empty()
            && self.channel.is_none()
            && self.attached_transport.is_none()
            && self.openclaw_target.is_none()
            && !self.env_file_exported
            && self
                .flush_lock
                .as_ref()
                .is_none_or(|lock| Arc::strong_count(lock) == 1)
    }
}
