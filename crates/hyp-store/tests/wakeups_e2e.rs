//! Comprehensive differential, oracle, migration, sleep-catch-up, mailbox coalescing/TTL,
//! and zero-polling scheduler tests for schema v3 (`WakeupStore` + `CronExpr`).

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use hyp_proto::cloudevent::TYPE_WAKEUP_V1;
use hyp_proto::cron::{CronExpr, CronTimezone, apply_cron_jitter, next_fire_after_with_offset};
use hyp_store::{
    CURRENT_SCHEMA_VERSION, DEFAULT_WAKEUP_TTL_MS, GateState, MailboxInsert, MailboxKind,
    MailboxPutOptions, MailboxPutResult, NodeDb, StoreConfig, StoreError, WakeupInsert,
    WakeupLimits, WakeupRecord, WakeupState, WakeupTriggerKind, WakeupUrgency,
};
use rusqlite::{Connection, OpenFlags, params};
use tempfile::TempDir;

const SCHEMA_V1_SQL: &str = include_str!("../migrations/0001_initial_v2.sql");
const SCHEMA_V2_SQL: &str = include_str!("../migrations/0002_discovery_and_routes.sql");

const MIN_MS: i64 = 60_000;
const HOUR_MS: i64 = 60 * MIN_MS;
// 2026-06-15T00:00:00.000Z (Monday)
const BASE_T0: i64 = 1_781_481_600_000;

fn timer_insert(
    id: Option<&str>,
    owner: Option<&str>,
    target_session: &str,
    fire_at: i64,
) -> WakeupInsert {
    WakeupInsert {
        id: id.map(str::to_string),
        owner_session_id: owner.map(str::to_string),
        target_session_id: Some(target_session.to_string()),
        target_handle: None,
        target_topic: None,
        label: "timer-check".to_string(),
        note: "Check deployment health".to_string(),
        trigger_kind: WakeupTriggerKind::Timer,
        cron_expr: None,
        timezone: CronTimezone::Local,
        exact_timing: true,
        urgency: WakeupUrgency::Queue,
        ttl_ms: DEFAULT_WAKEUP_TTL_MS,
        coalesce: true,
        fire_at: Some(fire_at),
        max_iterations: None,
        cold_revival_template: None,
    }
}

fn cron_insert(
    id: Option<&str>,
    owner: Option<&str>,
    target_session: &str,
    expr: &str,
    tz: CronTimezone,
    exact: bool,
    max_iterations: Option<u64>,
) -> WakeupInsert {
    WakeupInsert {
        id: id.map(str::to_string),
        owner_session_id: owner.map(str::to_string),
        target_session_id: Some(target_session.to_string()),
        target_handle: None,
        target_topic: None,
        label: "cron-check".to_string(),
        note: "Periodic status sweep".to_string(),
        trigger_kind: WakeupTriggerKind::Cron,
        cron_expr: Some(expr.to_string()),
        timezone: tz,
        exact_timing: exact,
        urgency: WakeupUrgency::Queue,
        ttl_ms: DEFAULT_WAKEUP_TTL_MS,
        coalesce: true,
        fire_at: None,
        max_iterations,
        cold_revival_template: None,
    }
}

fn wakeup_mailbox_insert(session_id: &str, wakeup_id: &str, item_id: &str, text: &str) -> MailboxInsert {
    MailboxInsert {
        session_id: session_id.to_string(),
        origin_node: "local".to_string(),
        item_id: item_id.to_string(),
        text: text.to_string(),
        kind: MailboxKind::Event,
        source: format!("wakeup:{wakeup_id}"),
        gate_state: GateState::Pending,
        gate_reason: None,
        traceparent: None,
    }
}

// =========================================================================
// 1. Validation, Ownership, Quotas, Auto-Pause & Session Leave Cleanup
// =========================================================================

#[test]
fn wakeup_validation_ownership_quotas_and_autopause() {
    assert_eq!(TYPE_WAKEUP_V1, "to.hyphae.wakeup.v1");
    let db = NodeDb::open_in_memory().unwrap();
    let limits = WakeupLimits::default();

    // Fail-closed validation matrix (mutated invalid inputs).
    let mut bad_empty_label = timer_insert(None, Some("sess-a"), "sess-a", BASE_T0 + 5_000);
    bad_empty_label.label = "   ".to_string();
    assert!(matches!(
        db.wakeups().create_wakeup(&bad_empty_label, &limits, BASE_T0),
        Err(StoreError::InvalidInput(_))
    ));

    let mut bad_huge_note = timer_insert(None, Some("sess-a"), "sess-a", BASE_T0 + 5_000);
    bad_huge_note.note = "x".repeat(limits.max_note_bytes + 1);
    assert!(matches!(
        db.wakeups().create_wakeup(&bad_huge_note, &limits, BASE_T0),
        Err(StoreError::TooLarge(_))
    ));

    let mut bad_no_target = timer_insert(None, Some("sess-a"), "sess-a", BASE_T0 + 5_000);
    bad_no_target.target_session_id = None;
    assert!(matches!(
        db.wakeups().create_wakeup(&bad_no_target, &limits, BASE_T0),
        Err(StoreError::InvalidInput(_))
    ));

    // Timer in the past or zero delay -> rejected.
    assert!(matches!(
        db.wakeups()
            .create_wakeup(&timer_insert(None, Some("sess-a"), "sess-a", BASE_T0), &limits, BASE_T0),
        Err(StoreError::InvalidInput(_))
    ));

    // Agent-owned cron without max_iterations -> rejected fail-closed!
    let agent_unbounded_cron =
        cron_insert(None, Some("sess-a"), "sess-a", "*/5 * * * *", CronTimezone::Utc, true, None);
    assert!(matches!(
        db.wakeups().create_wakeup(&agent_unbounded_cron, &limits, BASE_T0),
        Err(StoreError::InvalidInput(_))
    ));

    // Human-owned cron (owner_session_id = None) without max_iterations -> ALLOWED!
    let human_cron = db
        .wakeups()
        .create_wakeup(
            &cron_insert(
                Some("human-daily"),
                None,
                "sess-a",
                "0 9 * * 1-5",
                CronTimezone::Utc,
                true,
                None,
            ),
            &limits,
            BASE_T0,
        )
        .unwrap();
    assert_eq!(human_cron.state, WakeupState::Active);
    assert_eq!(human_cron.max_iterations, None);
    assert_eq!(human_cron.next_fire_at, BASE_T0 + 9 * HOUR_MS);

    // Duplicate ID fails closed with IdConflict.
    assert!(matches!(
        db.wakeups().create_wakeup(
            &cron_insert(
                Some("human-daily"),
                None,
                "sess-a",
                "0 9 * * 1-5",
                CronTimezone::Utc,
                true,
                None,
            ),
            &limits,
            BASE_T0,
        ),
        Err(StoreError::IdConflict(_))
    ));

    // Sub-interval cron rejected when min_cron_interval_seconds is stricter.
    let strict_limits = WakeupLimits {
        min_cron_interval_seconds: 300,
        ..WakeupLimits::default()
    };
    assert!(matches!(
        db.wakeups().create_wakeup(
            &cron_insert(
                Some("too-fast"),
                Some("sess-a"),
                "sess-a",
                "*/2 * * * *",
                CronTimezone::Utc,
                true,
                Some(5),
            ),
            &strict_limits,
            BASE_T0,
        ),
        Err(StoreError::InvalidInput(_))
    ));

    // Ownership checks: agent cannot cancel human wakeup or another session's wakeup!
    let agent_a = db
        .wakeups()
        .create_wakeup(
            &cron_insert(
                Some("agent-a-cron"),
                Some("sess-a"),
                "sess-a",
                "*/10 * * * *",
                CronTimezone::Utc,
                true,
                Some(10),
            ),
            &limits,
            BASE_T0,
        )
        .unwrap();
    assert!(matches!(
        db.wakeups().cancel_wakeup(&human_cron.id, Some("sess-a"), BASE_T0 + 1),
        Err(StoreError::Unauthorized(_))
    ));
    assert!(matches!(
        db.wakeups().cancel_wakeup(&agent_a.id, Some("sess-b"), BASE_T0 + 1),
        Err(StoreError::Unauthorized(_))
    ));
    assert!(matches!(
        db.wakeups().pause_wakeup(&agent_a.id, Some("sess-b"), BASE_T0 + 1),
        Err(StoreError::Unauthorized(_))
    ));

    // Consecutive-failure auto-pause & success reset!
    let r1 = db
        .wakeups()
        .record_delivery_result(&agent_a.id, false, Some("target busy"), 3, BASE_T0 + 10)
        .unwrap();
    assert_eq!(r1.consecutive_failures, 1);
    assert_eq!(r1.state, WakeupState::Active);
    assert_eq!(r1.last_error.as_deref(), Some("target busy"));

    let r2 = db
        .wakeups()
        .record_delivery_result(&agent_a.id, true, None, 3, BASE_T0 + 20)
        .unwrap();
    assert_eq!(r2.consecutive_failures, 0);
    assert_eq!(r2.last_error, None);
    assert_eq!(r2.state, WakeupState::Active);

    for attempt in 1..=3u32 {
        let rec = db
            .wakeups()
            .record_delivery_result(
                &agent_a.id,
                false,
                Some(&format!("err-{attempt}")),
                3,
                BASE_T0 + 100 + i64::from(attempt),
            )
            .unwrap();
        assert_eq!(rec.consecutive_failures, attempt);
        if attempt < 3 {
            assert_eq!(rec.state, WakeupState::Active);
        } else {
            assert_eq!(rec.state, WakeupState::Paused);
            assert_eq!(rec.last_error.as_deref(), Some("err-3"));
        }
    }

    // Resuming resets failures, clears last_error, and advances stale next_fire_at > now!
    let resumed = db
        .wakeups()
        .resume_wakeup(&agent_a.id, Some("sess-a"), BASE_T0 + 2 * HOUR_MS)
        .unwrap();
    assert_eq!(resumed.state, WakeupState::Active);
    assert_eq!(resumed.consecutive_failures, 0);
    assert_eq!(resumed.last_error, None);
    assert!(resumed.next_fire_at > BASE_T0 + 2 * HOUR_MS);

    // Session-leave cleanup cancels all owned wakeups (active + paused) while preserving human wakeups.
    db.wakeups()
        .create_wakeup(
            &timer_insert(Some("agent-a-timer"), Some("sess-a"), "sess-a", BASE_T0 + 3 * HOUR_MS),
            &limits,
            BASE_T0,
        )
        .unwrap();
    db.wakeups()
        .pause_wakeup("agent-a-timer", Some("sess-a"), BASE_T0 + 2 * HOUR_MS + 1)
        .unwrap();
    let cancelled_count = db
        .wakeups()
        .cancel_owned_by_session("sess-a", BASE_T0 + 2 * HOUR_MS + 2)
        .unwrap();
    assert_eq!(cancelled_count, 2);
    assert_eq!(
        db.wakeups().get_wakeup(&human_cron.id).unwrap().unwrap().state,
        WakeupState::Active
    );

    // Admin (caller = None) can cancel human wakeup.
    let cancelled_human = db
        .wakeups()
        .cancel_wakeup(&human_cron.id, None, BASE_T0 + 2 * HOUR_MS + 3)
        .unwrap();
    assert_eq!(cancelled_human.state, WakeupState::Cancelled);

    // Per-session quota (16) and global quota (128).
    for i in 0..limits.max_active_per_session {
        db.wakeups()
            .create_wakeup(
                &timer_insert(
                    Some(&format!("quota-s1-{i}")),
                    Some("quota-s1"),
                    "quota-s1",
                    BASE_T0 + 10_000 + (i as i64) * 1000,
                ),
                &limits,
                BASE_T0,
            )
            .unwrap();
    }
    assert!(matches!(
        db.wakeups().create_wakeup(
            &timer_insert(
                Some("quota-s1-overflow"),
                Some("quota-s1"),
                "quota-s1",
                BASE_T0 + 99_000,
            ),
            &limits,
            BASE_T0,
        ),
        Err(StoreError::QuotaExceeded(_))
    ));

    // Fill up to global cap (128) across multiple sessions.
    let mut created = limits.max_active_per_session;
    let mut sess_idx = 2usize;
    while created < limits.max_active_global {
        let sess = format!("quota-s{sess_idx}");
        let mut per_s = 0usize;
        while per_s < limits.max_active_per_session && created < limits.max_active_global {
            db.wakeups()
                .create_wakeup(
                    &timer_insert(
                        Some(&format!("quota-g-{created}")),
                        Some(&sess),
                        &sess,
                        BASE_T0 + 10_000 + (created as i64) * 1000,
                    ),
                    &limits,
                    BASE_T0,
                )
                .unwrap();
            per_s += 1;
            created += 1;
        }
        sess_idx += 1;
    }
    // 129th active wakeup (even human-owned!) hits global quota!
    assert!(matches!(
        db.wakeups().create_wakeup(
            &timer_insert(Some("quota-global-overflow"), None, "sess-x", BASE_T0 + 500_000),
            &limits,
            BASE_T0,
        ),
        Err(StoreError::QuotaExceeded(_))
    ));

    // Session pruning also cancels owned wakeups of pruned stale sessions.
    db.local().register_session("quota-s1", "{}", BASE_T0).unwrap();
    let prune = db
        .local()
        .prune_sessions(BASE_T0 + 1_000, &HashSet::new())
        .unwrap();
    assert_eq!(prune.pruned_sessions, vec!["quota-s1"]);
    assert!(
        db.wakeups()
            .list_wakeups(Some("quota-s1"), Some(WakeupState::Active))
            .unwrap()
            .is_empty()
    );
}

// =========================================================================
// 2. Laptop-Sleep Catch-Up (At Most 1 Tick, Exact missed_count, Zero Burst)
// =========================================================================

#[test]
fn laptop_sleep_five_hour_jump_produces_single_catchup_and_exact_missed_count() {
    let db = NodeDb::open_in_memory().unwrap();
    let limits = WakeupLimits::default();

    // Start at 2026-06-15T00:30:00Z.
    let t_start = BASE_T0 + 30 * MIN_MS;

    // 1. Hourly exact UTC cron: scheduled for 01:00.
    let hourly = db
        .wakeups()
        .create_wakeup(
            &cron_insert(
                Some("hourly-exact"),
                None,
                "sess-1",
                "0 * * * *",
                CronTimezone::Utc,
                true,
                None,
            ),
            &limits,
            t_start,
        )
        .unwrap();
    assert_eq!(hourly.next_fire_at, BASE_T0 + HOUR_MS);

    // 2. Every-5-min jittered UTC cron: base 00:35 + deterministic jitter in [0, 30_000].
    let five_min = db
        .wakeups()
        .create_wakeup(
            &cron_insert(
                Some("five-min-jitter"),
                Some("sess-1"),
                "sess-1",
                "*/5 * * * *",
                CronTimezone::Utc,
                false,
                Some(100),
            ),
            &limits,
            t_start,
        )
        .unwrap();
    let expected_five_base = BASE_T0 + 35 * MIN_MS;
    assert_eq!(
        five_min.next_fire_at,
        apply_cron_jitter(expected_five_base, 5 * MIN_MS, "five-min-jitter", false)
    );

    // 3. One-shot timer at 02:00.
    let timer = db
        .wakeups()
        .create_wakeup(
            &timer_insert(Some("oneshot"), Some("sess-1"), "sess-1", BASE_T0 + 2 * HOUR_MS),
            &limits,
            t_start,
        )
        .unwrap();
    assert_eq!(timer.next_fire_at, BASE_T0 + 2 * HOUR_MS);

    // Laptop sleeps 5 hours and wakes at 05:30:00Z!
    let t_wake = t_start + 5 * HOUR_MS; // 05:30:00Z
    let rep = db.tick(t_wake).unwrap();
    assert_eq!(rep.wakeups_fired.len(), 3, "each due wakeup fires at most ONCE");

    let by_id: BTreeMap<String, _> = rep
        .wakeups_fired
        .into_iter()
        .map(|f| (f.wakeup.id.clone(), f))
        .collect();

    // Hourly: due slots were 01:00, 02:00, 03:00, 04:00, 05:00 (5 slots -> 1 delivered, 4 missed).
    let fh = &by_id["hourly-exact"];
    assert_eq!(fh.missed_count, 4);
    assert_eq!(fh.wakeup.iteration, 1);
    assert_eq!(fh.wakeup.state, WakeupState::Active);
    assert_eq!(fh.wakeup.next_fire_at, BASE_T0 + 6 * HOUR_MS);
    assert!(!fh.completed);

    // 5-min: due slots from 00:35 through 05:30 inclusive = 60 slots -> 1 delivered, 59 missed!
    let f5 = &by_id["five-min-jitter"];
    assert_eq!(f5.missed_count, 59);
    assert_eq!(f5.wakeup.iteration, 1);
    assert_eq!(f5.wakeup.state, WakeupState::Active);
    assert!(
        f5.wakeup.next_fire_at > t_wake,
        "next_fire_at ({}) must be strictly > wake time ({t_wake})",
        f5.wakeup.next_fire_at
    );
    let expected_next_5 = apply_cron_jitter(BASE_T0 + 5 * HOUR_MS + 35 * MIN_MS, 5 * MIN_MS, "five-min-jitter", false);
    assert_eq!(f5.wakeup.next_fire_at, expected_next_5);

    // One-shot timer: completed with missed_count = 0.
    let ft = &by_id["oneshot"];
    assert_eq!(ft.missed_count, 0);
    assert_eq!(ft.wakeup.iteration, 1);
    assert_eq!(ft.wakeup.state, WakeupState::Completed);
    assert!(ft.completed);

    // Immediate second tick at the exact same timestamp produces ZERO additional fires (no burst!).
    let rep2 = db.tick(t_wake).unwrap();
    assert!(rep2.wakeups_fired.is_empty());

    // Massive 10-year clock jump on a 1-minute cron completes instantaneously without hanging!
    db.wakeups()
        .create_wakeup(
            &cron_insert(
                Some("every-min"),
                None,
                "sess-1",
                "* * * * *",
                CronTimezone::Utc,
                true,
                None,
            ),
            &limits,
            t_wake,
        )
        .unwrap();
    let ten_years_later = t_wake + 10 * 365 * 24 * HOUR_MS;
    let jump_rep = db.tick(ten_years_later).unwrap();
    let fm = jump_rep
        .wakeups_fired
        .iter()
        .find(|f| f.wakeup.id == "every-min")
        .unwrap();
    assert!(fm.missed_count >= 5_000_000);
    assert!(fm.wakeup.next_fire_at > ten_years_later);
    assert!(db.tick(ten_years_later).unwrap().wakeups_fired.is_empty());
}

// =========================================================================
// 3. Mailbox Coalescing, Queue-Full Supersede, Quarantine Isolation & TTL
// =========================================================================

#[test]
fn mailbox_coalescing_missed_count_ttl_and_zero_polling_deadlines() {
    let config = StoreConfig {
        mailbox_max_pending_per_session: 2,
        ..StoreConfig::default()
    };
    let db = NodeDb::open_in_memory_with_config(config).unwrap();

    // Idle DB reports None for all deadlines (zero polling!).
    let bd0 = db.next_deadline_breakdown(BASE_T0).unwrap();
    assert_eq!(bd0.wakeups, None);
    assert_eq!(bd0.mailbox_ttl, None);
    assert_eq!(bd0.earliest(), None);
    assert_eq!(bd0.earliest, None);

    // Put #1 with coalesce_key + TTL.
    let opts1 = MailboxPutOptions {
        coalesce_key: Some("wakeup:wk-1".to_string()),
        expires_at: Some(BASE_T0 + 60_000),
    };
    let r1 = match db
        .local()
        .put_in_mailbox_ex(
            &wakeup_mailbox_insert("sess-1", "wk-1", "tick-1", "first tick"),
            &opts1,
            BASE_T0,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected Stored, got {other:?}"),
    };
    db.local().mark_mailbox_notified("sess-1").unwrap();
    let ex1 = db.local().get_mailbox_entry_ex(&r1).unwrap().unwrap();
    assert_eq!(ex1.coalesce_key.as_deref(), Some("wakeup:wk-1"));
    assert_eq!(ex1.expires_at, Some(BASE_T0 + 60_000));
    assert_eq!(ex1.missed_count, 0);
    assert!(ex1.entry.notified);

    // Fill the 2nd (and final!) queue slot with a regular non-TTL message.
    db.local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "sess-1".to_string(),
                origin_node: "local".to_string(),
                item_id: "dm-1".to_string(),
                text: "regular dm".to_string(),
                kind: MailboxKind::Message,
                source: "alice/claude".to_string(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            },
            BASE_T0 + 1_000,
        )
        .unwrap();

    // A non-matching new item hits QueueFull.
    assert_eq!(
        db.local()
            .put_in_mailbox_ex(
                &wakeup_mailbox_insert("sess-1", "wk-other", "other-1", "overflow"),
                &MailboxPutOptions {
                    coalesce_key: Some("wakeup:wk-other".to_string()),
                    expires_at: Some(BASE_T0 + 30_000),
                },
                BASE_T0 + 2_000,
            )
            .unwrap(),
        MailboxPutResult::QueueFull
    );

    // Coalescing into the existing pending `wakeup:wk-1` slot SUCCEEDS even while queue is full!
    let opts2 = MailboxPutOptions {
        coalesce_key: Some("wakeup:wk-1".to_string()),
        expires_at: Some(BASE_T0 + 120_000),
    };
    let r2 = match db
        .local()
        .put_in_mailbox_ex(
            &wakeup_mailbox_insert("sess-1", "wk-1", "tick-2", "second tick"),
            &opts2,
            BASE_T0 + 10_000,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected coalesced Stored, got {other:?}"),
    };
    assert_eq!(r2, r1, "coalescing must reuse existing receipt");
    let ex2 = db.local().get_mailbox_entry_ex(&r1).unwrap().unwrap();
    assert_eq!(ex2.entry.item_id, "tick-2");
    assert_eq!(ex2.entry.text, "second tick");
    assert_eq!(ex2.entry.received_at, BASE_T0 + 10_000);
    assert_eq!(ex2.expires_at, Some(BASE_T0 + 120_000));
    assert!(!ex2.entry.notified, "coalesced update must reset notified = false");
    assert_eq!(ex2.missed_count, 1);

    // Exact duplicate retry of `tick-2` returns Duplicate without bumping missed_count!
    assert_eq!(
        db.local()
            .put_in_mailbox_ex(
                &wakeup_mailbox_insert("sess-1", "wk-1", "tick-2", "second tick"),
                &opts2,
                BASE_T0 + 11_000,
            )
            .unwrap(),
        MailboxPutResult::Duplicate
    );
    assert_eq!(
        db.local().get_mailbox_entry_ex(&r1).unwrap().unwrap().missed_count,
        1
    );

    // Quarantined row with same coalesce_key must NOT merge into pending row.
    let mut quarantined_insert = wakeup_mailbox_insert("sess-1", "wk-1", "q-1", "suspicious");
    quarantined_insert.gate_state = GateState::Quarantined;
    let rq = match db
        .local()
        .put_in_mailbox_ex(&quarantined_insert, &opts2, BASE_T0 + 12_000)
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected quarantined Stored, got {other:?}"),
    };
    assert_ne!(rq, r1);
    assert_eq!(
        db.local().get_mailbox_entry_ex(&r1).unwrap().unwrap().missed_count,
        1
    );

    // Scheduler deadline breakdown accurately tracks updated TTL (BASE_T0 + 120_000).
    let bd1 = db.next_deadline_breakdown(BASE_T0 + 15_000).unwrap();
    assert_eq!(bd1.mailbox_ttl, Some(BASE_T0 + 120_000));
    assert_eq!(bd1.earliest(), Some(BASE_T0 + 120_000));
    assert_eq!(bd1.earliest, Some(BASE_T0 + 120_000));

    // Before TTL: tick expires 0.
    assert_eq!(db.tick(BASE_T0 + 119_999).unwrap().mailbox_expired, 0);
    assert_eq!(db.local().pending_count("sess-1").unwrap(), 2);

    // At TTL: tick expires ONLY the pending TTL item (regular DM & quarantined item untouched!).
    let rep = db.tick(BASE_T0 + 120_000).unwrap();
    assert_eq!(rep.mailbox_expired, 1);
    assert!(db.local().get_mailbox_entry(&r1).unwrap().is_none());
    assert_eq!(db.local().pending_count("sess-1").unwrap(), 1);
    assert!(db.local().get_mailbox_entry(&rq).unwrap().is_some());
    assert_eq!(db.next_deadline_ms(BASE_T0 + 120_000).unwrap(), None);

    // After draining or expiring, a subsequent insert with the same coalesce_key creates a fresh row.
    let r_fresh = match db
        .local()
        .put_in_mailbox_ex(
            &wakeup_mailbox_insert("sess-1", "wk-1", "tick-3", "fresh after ttl"),
            &MailboxPutOptions {
                coalesce_key: Some("wakeup:wk-1".to_string()),
                expires_at: Some(BASE_T0 + 300_000),
            },
            BASE_T0 + 130_000,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected Stored, got {other:?}"),
    };
    assert_ne!(r_fresh, r1);
    let ex_fresh = db.local().get_mailbox_entry_ex(&r_fresh).unwrap().unwrap();
    assert_eq!(ex_fresh.missed_count, 0);

    // Drain delivers it; next put creates another fresh row with missed_count = 0.
    let drained = db.local().drain_inbox_ex("sess-1", 10, BASE_T0 + 135_000).unwrap();
    assert_eq!(drained.len(), 2);
    assert_eq!(db.next_deadline_ms(BASE_T0 + 135_000).unwrap(), None);

    // Idle wakeup & mailbox TTL sweeps + deadline computation take ZERO write lock
    // (verified on file-backed WAL DB while another connection holds `BEGIN IMMEDIATE`).
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("idle.sqlite");
    let file_db = NodeDb::open(&path).unwrap();
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE;").unwrap();
    assert_eq!(file_db.next_deadline_ms(BASE_T0).unwrap(), None);
    assert!(
        file_db
            .wakeups()
            .claim_due_wakeups(BASE_T0 + 1_000)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        file_db
            .local()
            .expire_pending_mailbox(BASE_T0 + 1_000)
            .unwrap(),
        0
    );
    writer.execute_batch("ROLLBACK;").unwrap();
    let idle_rep = file_db.tick(BASE_T0 + 1_000).unwrap();
    assert!(idle_rep.wakeups_fired.is_empty());
    assert_eq!(idle_rep.mailbox_expired, 0);
}

// =========================================================================
// 4. Differential Oracle: Pure In-Memory Reference Model vs Real WAL SQLite
// =========================================================================

struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn range(&mut self, upper: usize) -> usize {
        (self.next() as usize) % upper
    }
}

#[derive(Debug, Clone)]
struct OracleMailboxRow {
    receipt: String,
    session_id: String,
    item_id: String,
    text: String,
    received_at: i64,
    notified: bool,
    coalesce_key: Option<String>,
    expires_at: Option<i64>,
    missed_count: u64,
}

#[derive(Default)]
struct ReferenceOracle {
    wakeups: BTreeMap<String, WakeupRecord>,
    pending_mailbox: Vec<OracleMailboxRow>,
    seen_mailbox_keys: HashSet<(String, String)>, // (session_id, item_id)
    max_pending_per_session: usize,
    limits: WakeupLimits,
}

impl ReferenceOracle {
    fn new(limits: WakeupLimits, max_pending_per_session: usize) -> Self {
        Self {
            wakeups: BTreeMap::new(),
            pending_mailbox: Vec::new(),
            seen_mailbox_keys: HashSet::new(),
            max_pending_per_session,
            limits,
        }
    }

    fn create_wakeup(&mut self, input: &WakeupInsert, now_ms: i64) -> Result<WakeupRecord, &'static str> {
        let id = input.id.clone().expect("oracle uses explicit ids");
        if self.wakeups.contains_key(&id) {
            return Err("id_conflict");
        }
        let active_global = self
            .wakeups
            .values()
            .filter(|w| w.state == WakeupState::Active)
            .count();
        if active_global >= self.limits.max_active_global {
            return Err("quota");
        }
        if let Some(owner) = input.owner_session_id.as_deref() {
            let active_owner = self
                .wakeups
                .values()
                .filter(|w| w.state == WakeupState::Active && w.owner_session_id.as_deref() == Some(owner))
                .count();
            if active_owner >= self.limits.max_active_per_session {
                return Err("quota");
            }
        }
        let (canonical_cron, next_fire_at, max_iterations) = match input.trigger_kind {
            WakeupTriggerKind::Timer => {
                let fire_at = input.fire_at.ok_or("invalid")?;
                if fire_at < now_ms + self.limits.min_timer_delay_ms {
                    return Err("invalid");
                }
                (None, fire_at, Some(1u64))
            }
            WakeupTriggerKind::Cron => {
                if input.owner_session_id.is_some() && input.max_iterations.is_none() {
                    return Err("invalid");
                }
                let expr = CronExpr::parse(input.cron_expr.as_deref().ok_or("invalid")?)
                    .map_err(|_| "invalid")?;
                expr.validate_min_interval(self.limits.min_cron_interval_seconds)
                    .map_err(|_| "invalid")?;
                let first_base = expr.next_fire_after(now_ms, input.timezone).ok_or("invalid")?;
                let interval = expr
                    .next_fire_after(first_base, input.timezone)
                    .map(|n| n - first_base)
                    .unwrap_or(0);
                let first_fire = apply_cron_jitter(first_base, interval, &id, input.exact_timing);
                (Some(expr.as_str().to_string()), first_fire, input.max_iterations)
            }
        };

        let rec = WakeupRecord {
            id: id.clone(),
            owner_session_id: input.owner_session_id.clone(),
            target_session_id: input.target_session_id.clone(),
            target_handle: input.target_handle.clone(),
            target_topic: input.target_topic.clone(),
            label: input.label.trim().to_string(),
            note: input.note.clone(),
            trigger_kind: input.trigger_kind,
            cron_expr: canonical_cron,
            timezone: input.timezone,
            exact_timing: input.exact_timing,
            urgency: input.urgency,
            ttl_ms: input.ttl_ms,
            coalesce: input.coalesce,
            next_fire_at,
            last_fired_at: None,
            iteration: 0,
            max_iterations,
            consecutive_failures: 0,
            cold_revival_template: input.cold_revival_template.clone(),
            state: WakeupState::Active,
            last_error: None,
            created_at: now_ms,
            updated_at: now_ms,
        };
        self.wakeups.insert(id, rec.clone());
        Ok(rec)
    }

    fn cancel_wakeup(&mut self, id: &str, caller: Option<&str>, now_ms: i64) -> Result<(), &'static str> {
        let Some(rec) = self.wakeups.get_mut(id) else {
            return Err("not_found");
        };
        if let Some(c) = caller {
            if rec.owner_session_id.as_deref() != Some(c) {
                return Err("unauthorized");
            }
        }
        if !matches!(rec.state, WakeupState::Active | WakeupState::Paused) {
            return Err("invalid_state");
        }
        rec.state = WakeupState::Cancelled;
        rec.updated_at = now_ms;
        Ok(())
    }

    fn record_delivery(
        &mut self,
        id: &str,
        succeeded: bool,
        err: Option<&str>,
        max_fail: u32,
        now_ms: i64,
    ) {
        if let Some(rec) = self.wakeups.get_mut(id) {
            if succeeded {
                rec.consecutive_failures = 0;
                rec.last_error = None;
            } else {
                rec.consecutive_failures += 1;
                rec.last_error = Some(err.unwrap_or("delivery failed").to_string());
                if rec.state == WakeupState::Active && rec.consecutive_failures >= max_fail.max(1) {
                    rec.state = WakeupState::Paused;
                }
            }
            rec.updated_at = now_ms;
        }
    }

    fn tick(&mut self, now_ms: i64) -> (Vec<(String, u64, bool)>, usize) {
        let mut due_ids: Vec<(i64, String)> = self
            .wakeups
            .values()
            .filter(|w| w.state == WakeupState::Active && w.next_fire_at <= now_ms)
            .map(|w| (w.next_fire_at, w.id.clone()))
            .collect();
        due_ids.sort();

        let mut fired = Vec::new();
        for (scheduled, id) in due_ids {
            let rec = self.wakeups.get_mut(&id).unwrap();
            rec.iteration += 1;
            rec.last_fired_at = Some(now_ms);
            rec.updated_at = now_ms;
            let (missed, completed) = match rec.trigger_kind {
                WakeupTriggerKind::Timer => {
                    rec.state = WakeupState::Completed;
                    (0u64, true)
                }
                WakeupTriggerKind::Cron => {
                    let expr = CronExpr::parse(rec.cron_expr.as_deref().unwrap()).unwrap();
                    let mut missed = 0u64;
                    let mut cursor = scheduled;
                    let next_base = loop {
                        let cand = expr.next_fire_after(cursor, rec.timezone).unwrap();
                        if cand <= now_ms {
                            missed += 1;
                            cursor = cand;
                        } else {
                            break cand;
                        }
                    };
                    if rec.max_iterations.is_some_and(|m| rec.iteration >= m) {
                        rec.state = WakeupState::Completed;
                        (missed, true)
                    } else {
                        let interval = expr.next_fire_after(next_base, rec.timezone).unwrap() - next_base;
                        rec.next_fire_at = apply_cron_jitter(next_base, interval, &rec.id, rec.exact_timing);
                        (missed, false)
                    }
                }
            };
            fired.push((id, missed, completed));
        }

        let before = self.pending_mailbox.len();
        self.pending_mailbox
            .retain(|row| row.expires_at.is_none_or(|exp| exp > now_ms));
        let expired = before - self.pending_mailbox.len();

        (fired, expired)
    }

    fn put_mailbox(
        &mut self,
        session_id: &str,
        item_id: &str,
        text: &str,
        opts: &MailboxPutOptions,
        actual_receipt: Option<&str>,
        now_ms: i64,
    ) -> &'static str {
        if let Some(key) = opts.coalesce_key.as_deref() {
            if self
                .seen_mailbox_keys
                .contains(&(session_id.to_string(), item_id.to_string()))
            {
                return "duplicate";
            }
            if let Some(existing) = self
                .pending_mailbox
                .iter_mut()
                .rev()
                .find(|r| r.session_id == session_id && r.coalesce_key.as_deref() == Some(key))
            {
                existing.item_id = item_id.to_string();
                existing.text = text.to_string();
                existing.received_at = now_ms;
                existing.expires_at = opts.expires_at;
                existing.notified = false;
                existing.missed_count += 1;
                self.seen_mailbox_keys
                    .insert((session_id.to_string(), item_id.to_string()));
                return "stored";
            }
        }
        let pending_for_sess = self
            .pending_mailbox
            .iter()
            .filter(|r| r.session_id == session_id)
            .count();
        if pending_for_sess >= self.max_pending_per_session {
            return "queue_full";
        }
        if !self
            .seen_mailbox_keys
            .insert((session_id.to_string(), item_id.to_string()))
        {
            return "duplicate";
        }
        self.pending_mailbox.push(OracleMailboxRow {
            receipt: actual_receipt.unwrap_or_default().to_string(),
            session_id: session_id.to_string(),
            item_id: item_id.to_string(),
            text: text.to_string(),
            received_at: now_ms,
            notified: false,
            coalesce_key: opts.coalesce_key.clone(),
            expires_at: opts.expires_at,
            missed_count: 0,
        });
        "stored"
    }

    fn drain_mailbox(&mut self, session_id: &str) -> Vec<OracleMailboxRow> {
        let mut drained = Vec::new();
        let mut keep = Vec::new();
        for row in self.pending_mailbox.drain(..) {
            if row.session_id == session_id {
                drained.push(row);
            } else {
                keep.push(row);
            }
        }
        self.pending_mailbox = keep;
        drained.sort_by(|a, b| a.received_at.cmp(&b.received_at).then(a.receipt.cmp(&b.receipt)));
        drained
    }

    fn next_wakeup_deadline(&self) -> Option<i64> {
        self.wakeups
            .values()
            .filter(|w| w.state == WakeupState::Active)
            .map(|w| w.next_fire_at)
            .min()
    }

    fn next_mailbox_ttl_deadline(&self) -> Option<i64> {
        self.pending_mailbox
            .iter()
            .filter_map(|r| r.expires_at)
            .min()
    }
}

#[test]
fn differential_oracle_wakeup_and_mailbox_state_machine_with_crash_reopen() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("oracle-node.sqlite");

    let limits = WakeupLimits {
        max_active_per_session: 4,
        max_active_global: 10,
        max_consecutive_failures: 3,
        ..WakeupLimits::default()
    };
    let store_cfg = StoreConfig {
        wakeup_limits: limits,
        mailbox_max_pending_per_session: 5,
        ..StoreConfig::default()
    };

    let mut db = NodeDb::open_with_config(&db_path, store_cfg.clone()).unwrap();
    let mut oracle = ReferenceOracle::new(limits, 5);
    let mut rng = XorShift64(0xDEAD_BEEF_CAFE_BABEu64);

    let sessions = ["sess-a", "sess-b", "sess-c"];
    let crons = ["*/5 * * * *", "*/15 * * * *", "0 * * * *", "0,30 * * * *"];

    let mut now = BASE_T0;
    let mut next_wk_seq = 0usize;
    let mut next_item_seq = 0usize;

    for step in 0..320usize {
        // Periodically close and reopen WAL SQLite to verify crash/restart persistence parity!
        if step > 0 && step % 64 == 0 {
            drop(db);
            db = NodeDb::open_with_config(&db_path, store_cfg.clone()).unwrap();
        }

        let op = rng.range(100);
        if op < 24 {
            // Create timer or cron wakeup (mix human + agent, exact + jittered).
            next_wk_seq += 1;
            let id = format!("wk-{next_wk_seq}");
            let owner = if rng.range(4) == 0 {
                None
            } else {
                Some(sessions[rng.range(sessions.len())])
            };
            let target = sessions[rng.range(sessions.len())];
            let insert = if rng.range(2) == 0 {
                let delay = ((rng.range(12) as i64) + 1) * MIN_MS;
                timer_insert(Some(&id), owner, target, now + delay)
            } else {
                let expr = crons[rng.range(crons.len())];
                let exact = rng.range(2) == 0;
                let max_it = if owner.is_some() {
                    Some((rng.range(5) as u64) + 1)
                } else if rng.range(2) == 0 {
                    Some((rng.range(6) as u64) + 1)
                } else {
                    None
                };
                cron_insert(Some(&id), owner, target, expr, CronTimezone::Utc, exact, max_it)
            };

            let o_res = oracle.create_wakeup(&insert, now);
            let s_res = db.wakeups().create_wakeup(&insert, &limits, now);
            assert_eq!(
                o_res.is_ok(),
                s_res.is_ok(),
                "step {step}: create_wakeup ok mismatch: oracle={o_res:?} store={s_res:?}"
            );
            if let (Ok(ore), Ok(sre)) = (o_res, s_res) {
                assert_eq!(ore, sre, "step {step}: created wakeup record mismatch");
            }
        } else if op < 38 && !oracle.wakeups.is_empty() {
            // Cancel random wakeup with either admin or random session caller.
            let keys: Vec<String> = oracle.wakeups.keys().cloned().collect();
            let id = &keys[rng.range(keys.len())];
            let caller = if rng.range(3) == 0 {
                None
            } else {
                Some(sessions[rng.range(sessions.len())])
            };
            let o_res = oracle.cancel_wakeup(id, caller, now);
            let s_res = db.wakeups().cancel_wakeup(id, caller, now);
            assert_eq!(
                o_res.is_ok(),
                s_res.is_ok(),
                "step {step}: cancel mismatch for {id} caller={caller:?}: oracle={o_res:?} store={s_res:?}"
            );
        } else if op < 52 {
            // Advance clock (small step OR occasional 5-hour laptop-sleep jump!) and tick!
            let delta = match rng.range(10) {
                0 => 5 * HOUR_MS, // laptop sleep jump!
                1..=3 => 17 * MIN_MS,
                _ => ((rng.range(6) as i64) + 1) * MIN_MS,
            };
            now += delta;

            let (o_fired, o_expired) = oracle.tick(now);
            let s_rep = db.tick(now).unwrap();
            let s_fired: Vec<(String, u64, bool)> = s_rep
                .wakeups_fired
                .iter()
                .map(|f| (f.wakeup.id.clone(), f.missed_count, f.completed))
                .collect();
            assert_eq!(s_fired, o_fired, "step {step} at now={now}: fired wakeups mismatch");
            assert_eq!(
                s_rep.mailbox_expired, o_expired,
                "step {step} at now={now}: mailbox_expired mismatch"
            );

            // Simulate delivery into target session mailbox + record_delivery_result for each fired wakeup!
            for f in &s_rep.wakeups_fired {
                let succeeded = rng.range(4) != 0; // 75% success, 25% failure
                if succeeded {
                    next_item_seq += 1;
                    let item_id = format!("fired-{next_item_seq}");
                    let target = f.wakeup.target_session_id.as_deref().unwrap();
                    let opts = MailboxPutOptions {
                        coalesce_key: if f.wakeup.coalesce {
                            Some(format!("wakeup:{}", f.wakeup.id))
                        } else {
                            None
                        },
                        expires_at: Some(now + 30 * MIN_MS),
                    };
                    let s_put = db
                        .local()
                        .put_in_mailbox_ex(
                            &wakeup_mailbox_insert(target, &f.wakeup.id, &item_id, &f.wakeup.note),
                            &opts,
                            now,
                        )
                        .unwrap();
                    let (s_tag, receipt_opt) = match &s_put {
                        MailboxPutResult::Stored { receipt } => ("stored", Some(receipt.as_str())),
                        MailboxPutResult::Duplicate => ("duplicate", None),
                        MailboxPutResult::QueueFull => ("queue_full", None),
                    };
                    let o_tag = oracle.put_mailbox(
                        target,
                        &item_id,
                        &f.wakeup.note,
                        &opts,
                        receipt_opt,
                        now,
                    );
                    assert_eq!(s_tag, o_tag, "step {step}: mailbox put outcome mismatch");
                }
                oracle.record_delivery(
                    &f.wakeup.id,
                    succeeded,
                    if succeeded { None } else { Some("delivery_timeout") },
                    limits.max_consecutive_failures,
                    now,
                );
                db.wakeups()
                    .record_delivery_result(
                        &f.wakeup.id,
                        succeeded,
                        if succeeded { None } else { Some("delivery_timeout") },
                        limits.max_consecutive_failures,
                        now,
                    )
                    .unwrap();
            }
        } else if op < 78 {
            // Standalone mailbox put with coalescing + optional TTL.
            next_item_seq += 1;
            let sess = sessions[rng.range(sessions.len())];
            let wk_key = format!("wk-mb-{}", rng.range(3));
            let item_id = format!("mb-{next_item_seq}");
            let text = format!("payload-{next_item_seq}");
            let opts = MailboxPutOptions {
                coalesce_key: if rng.range(3) != 0 {
                    Some(format!("wakeup:{wk_key}"))
                } else {
                    None
                },
                expires_at: if rng.range(2) == 0 {
                    Some(now + ((rng.range(5) as i64) + 1) * 10 * MIN_MS)
                } else {
                    None
                },
            };
            let s_put = db
                .local()
                .put_in_mailbox_ex(&wakeup_mailbox_insert(sess, &wk_key, &item_id, &text), &opts, now)
                .unwrap();
            let (s_tag, receipt_opt) = match &s_put {
                MailboxPutResult::Stored { receipt } => ("stored", Some(receipt.as_str())),
                MailboxPutResult::Duplicate => ("duplicate", None),
                MailboxPutResult::QueueFull => ("queue_full", None),
            };
            let o_tag = oracle.put_mailbox(sess, &item_id, &text, &opts, receipt_opt, now);
            assert_eq!(s_tag, o_tag, "step {step}: standalone mailbox put mismatch");
        } else {
            // Drain a random session's inbox.
            let sess = sessions[rng.range(sessions.len())];
            let o_drained = oracle.drain_mailbox(sess);
            let s_drained = db.local().drain_inbox_ex(sess, 100, now).unwrap();
            assert_eq!(s_drained.len(), o_drained.len(), "step {step}: drain count mismatch");
            for (sd, od) in s_drained.iter().zip(o_drained.iter()) {
                assert_eq!(sd.entry.receipt, od.receipt);
                assert_eq!(sd.entry.item_id, od.item_id);
                assert_eq!(sd.entry.text, od.text);
                assert_eq!(sd.coalesce_key, od.coalesce_key);
                assert_eq!(sd.expires_at, od.expires_at);
                assert_eq!(sd.missed_count, od.missed_count);
            }
        }

        // ---- Post-step full state parity check ----
        let s_wakeups: BTreeMap<String, WakeupRecord> = db
            .wakeups()
            .list_wakeups(None, None)
            .unwrap()
            .into_iter()
            .map(|w| (w.id.clone(), w))
            .collect();
        assert_eq!(s_wakeups, oracle.wakeups, "step {step}: full wakeups table mismatch");

        let bd = db.next_deadline_breakdown(now).unwrap();
        assert_eq!(
            bd.wakeups,
            oracle.next_wakeup_deadline(),
            "step {step}: wakeups deadline mismatch"
        );
        assert_eq!(
            bd.mailbox_ttl,
            oracle.next_mailbox_ttl_deadline(),
            "step {step}: mailbox_ttl deadline mismatch"
        );
        assert_eq!(bd.earliest, bd.earliest());

        for sess in sessions {
            let s_inbox = db.local().peek_inbox_ex(sess, 100).unwrap();
            let mut o_inbox: Vec<&OracleMailboxRow> = oracle
                .pending_mailbox
                .iter()
                .filter(|r| r.session_id == sess)
                .collect();
            o_inbox.sort_by(|a, b| a.received_at.cmp(&b.received_at).then(a.receipt.cmp(&b.receipt)));
            assert_eq!(s_inbox.len(), o_inbox.len(), "step {step} {sess}: pending len mismatch");
            for (si, oi) in s_inbox.iter().zip(o_inbox.iter()) {
                assert_eq!(si.entry.receipt, oi.receipt);
                assert_eq!(si.entry.item_id, oi.item_id);
                assert_eq!(si.entry.text, oi.text);
                assert_eq!(si.entry.notified, oi.notified);
                assert_eq!(si.coalesce_key, oi.coalesce_key);
                assert_eq!(si.expires_at, oi.expires_at);
                assert_eq!(si.missed_count, oi.missed_count);
            }
        }
    }
}

// =========================================================================
// 5. Migration v1 -> v2 -> v3 and v2 -> v3 Roundtrip + Automatic Backup
// =========================================================================

type TableColumns = Vec<(String, String, i64, Option<String>)>;

fn snapshot_schema_tables_and_columns(conn: &Connection) -> BTreeMap<String, TableColumns> {
    let mut tables = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name ASC",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        tables.extend(rows);
    }

    let mut out = BTreeMap::new();
    for table in tables {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .unwrap();
        let cols = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        out.insert(table, cols);
    }
    out
}

fn snapshot_indexes(conn: &Connection) -> BTreeMap<String, (String, Option<String>)> {
    let mut stmt = conn
        .prepare(
            "SELECT name, tbl_name, sql FROM sqlite_master
             WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
             ORDER BY name ASC",
        )
        .unwrap();
    stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            (r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?),
        ))
    })
    .unwrap()
    .collect::<Result<BTreeMap<_, _>, _>>()
    .unwrap()
}

fn seed_v2_db(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    let _: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );",
    )
    .unwrap();
    conn.execute_batch(SCHEMA_V1_SQL).unwrap();
    conn.execute_batch(SCHEMA_V2_SQL).unwrap();
    conn.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (1, ?1), (2, ?2)",
        params![BASE_T0, BASE_T0 + 100],
    )
    .unwrap();

    // Seed v2 data across handles (with description), peer_routes, sessions, and mailbox.
    conn.execute(
        "INSERT INTO handles (node_id, handle, session_id, registered_at, last_heartbeat_at, description)
         VALUES ('local', 'claude', 'sess-v2', ?1, ?1, 'v2 reviewer')",
        params![BASE_T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO peer_routes (target_node, via_peer, updated_at)
         VALUES ('bob@lap', 'acme-hub', ?1)",
        params![BASE_T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO sessions (id, backend_json, handle, last_seen, delivery_mode, created_at)
         VALUES ('sess-v2', '{\"harness\":\"claude\"}', 'claude', ?1, 'full', ?1)",
        params![BASE_T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO mailbox (receipt, session_id, origin_node, item_id, text, received_at, kind, source, gate_state)
         VALUES ('rcpt-v2', 'sess-v2', 'acme-hub', 'msg-v2', 'preserved across v2->v3', ?1, 'message', 'bob@lap/codex', 'pending')",
        params![BASE_T0 + 50],
    )
    .unwrap();
}

#[test]
fn migration_v2_to_v3_and_v1_to_v3_backup_parity_and_zero_data_loss() {
    let dir = TempDir::new().unwrap();
    let v2_path = dir.path().join("v2-upgrade").join("node.sqlite");
    let v1_path = dir.path().join("v1-upgrade").join("node.sqlite");
    let fresh_path = dir.path().join("fresh-v3").join("node.sqlite");

    // 1. Seed v2 DB & open to upgrade v2 -> v3.
    seed_v2_db(&v2_path);
    let migrated_v2 = NodeDb::open(&v2_path).unwrap();

    // 2. Seed v1 DB & open to upgrade v1 -> v2 -> v3.
    {
        fs::create_dir_all(v1_path.parent().unwrap()).unwrap();
        let conn = Connection::open(&v1_path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);",
        )
        .unwrap();
        conn.execute_batch(SCHEMA_V1_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (1, ?1)",
            params![BASE_T0],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO mailbox (receipt, session_id, origin_node, item_id, text, received_at, kind, source, gate_state)
             VALUES ('rcpt-v1', 'sess-v1', 'local', 'msg-v1', 'preserved across v1->v3', ?1, 'message', 'local/bot', 'pending')",
            params![BASE_T0],
        )
        .unwrap();
    }
    let migrated_v1 = NodeDb::open(&v1_path).unwrap();
    let fresh_v3 = NodeDb::open(&fresh_path).unwrap();

    assert_eq!(migrated_v2.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(migrated_v1.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(fresh_v3.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert!(migrated_v2.schema_version().unwrap() >= 3);

    // Exact schema parity: v2->v3 and v1->v2->v3 both match fresh v3 bit-for-bit!
    let fresh_cols = snapshot_schema_tables_and_columns(fresh_v3.connection());
    let fresh_idx = snapshot_indexes(fresh_v3.connection());
    assert_eq!(
        snapshot_schema_tables_and_columns(migrated_v2.connection()),
        fresh_cols
    );
    assert_eq!(
        snapshot_schema_tables_and_columns(migrated_v1.connection()),
        fresh_cols
    );
    assert_eq!(snapshot_indexes(migrated_v2.connection()), fresh_idx);
    assert_eq!(snapshot_indexes(migrated_v1.connection()), fresh_idx);

    // Verify v2->v3 backup exists, is 0600, and is a genuine pre-migration v2 snapshot!
    let v2_backups = migrated_v2.list_migration_backups().unwrap();
    assert_eq!(v2_backups.len(), 1);
    let bak_name = v2_backups[0].file_name().unwrap().to_str().unwrap();
    assert!(
        bak_name.starts_with(&format!("node.sqlite.v2-to-v{CURRENT_SCHEMA_VERSION}-"))
            && bak_name.ends_with(".bak"),
        "unexpected v2->v{CURRENT_SCHEMA_VERSION} backup name: {bak_name}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&v2_backups[0]).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let bak_conn =
        Connection::open_with_flags(&v2_backups[0], OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let bak_ver: i64 = bak_conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(bak_ver, 2);
    let bak_cols = snapshot_schema_tables_and_columns(&bak_conn);
    assert!(!bak_cols.contains_key("wakeups"));

    // Verify v1->latest backup exists and is a genuine v1 snapshot!
    let v1_backups = migrated_v1.list_migration_backups().unwrap();
    assert_eq!(v1_backups.len(), 1);
    assert!(
        v1_backups[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(&format!("node.sqlite.v1-to-v{CURRENT_SCHEMA_VERSION}-"))
    );

    // Verify all pre-existing v2 data survived untouched and mailbox defaults are clean.
    let h = migrated_v2
        .messages()
        .get_handle("local", "claude")
        .unwrap()
        .unwrap();
    assert_eq!(h.description.as_deref(), Some("v2 reviewer"));
    assert_eq!(
        migrated_v2
            .peers()
            .get_peer_route("bob@lap")
            .unwrap()
            .unwrap()
            .via_peer,
        "acme-hub"
    );
    let mb_v2 = migrated_v2.local().get_mailbox_entry_ex("rcpt-v2").unwrap().unwrap();
    assert_eq!(mb_v2.entry.text, "preserved across v2->v3");
    assert_eq!(mb_v2.coalesce_key, None);
    assert_eq!(mb_v2.expires_at, None);
    assert_eq!(mb_v2.missed_count, 0);

    let mb_v1 = migrated_v1.local().get_mailbox_entry_ex("rcpt-v1").unwrap().unwrap();
    assert_eq!(mb_v1.entry.text, "preserved across v1->v3");
    assert_eq!(mb_v1.missed_count, 0);

    // Post-upgrade DB immediately supports creating and firing wakeups!
    let wk = migrated_v2
        .wakeups()
        .create_wakeup(
            &cron_insert(
                Some("post-upgrade-cron"),
                None,
                "sess-v2",
                "0 9 * * *",
                CronTimezone::Utc,
                true,
                None,
            ),
            &WakeupLimits::default(),
            BASE_T0,
        )
        .unwrap();
    assert_eq!(wk.next_fire_at, BASE_T0 + 9 * HOUR_MS);
    let rep = migrated_v2.tick(BASE_T0 + 9 * HOUR_MS).unwrap();
    assert_eq!(rep.wakeups_fired.len(), 1);
    assert_eq!(rep.wakeups_fired[0].wakeup.id, "post-upgrade-cron");
}

// =========================================================================
// 6. Cross-Check Cron Timezone Offset Evaluation via hyp-proto Re-export
// =========================================================================

#[test]
fn cron_offset_and_leap_year_integration_smoke() {
    let feb29 = CronExpr::parse("0 9 29 2 *").unwrap();
    // 2028-02-29 09:00 UTC-5 == 2028-02-29 14:00 UTC.
    let start_2027 = 1_798_761_600_000i64; // 2027-01-01T00:00:00Z
    let fire = next_fire_after_with_offset(&feb29, start_2027, -5 * 3600).unwrap();
    assert_eq!(
        hyp_store::epoch_ms_to_rfc3339(fire),
        "2028-02-29T14:00:00.000Z"
    );
}
