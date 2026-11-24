-- =========================================================================
-- Schema v3: Durable Wakeups (Timers & Cron) + Mailbox Coalescing & TTL
-- =========================================================================

CREATE TABLE IF NOT EXISTS wakeups (
    id TEXT PRIMARY KEY,
    owner_session_id TEXT,
    target_session_id TEXT,
    target_handle TEXT,
    target_topic TEXT,
    label TEXT NOT NULL,
    note TEXT NOT NULL,
    trigger_kind TEXT NOT NULL CHECK (trigger_kind IN ('timer', 'cron')),
    cron_expr TEXT,
    timezone TEXT NOT NULL DEFAULT 'local',
    exact_timing INTEGER NOT NULL DEFAULT 0,
    urgency TEXT NOT NULL DEFAULT 'queue' CHECK (urgency IN ('interrupt', 'queue', 'notify')),
    ttl_ms INTEGER NOT NULL DEFAULT 3600000,
    coalesce INTEGER NOT NULL DEFAULT 1,
    next_fire_at INTEGER NOT NULL,
    last_fired_at INTEGER,
    iteration INTEGER NOT NULL DEFAULT 0,
    max_iterations INTEGER,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    cold_revival_template TEXT,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'paused', 'completed', 'cancelled', 'failed')),
    last_error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS wakeups_next_fire
    ON wakeups (next_fire_at) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS wakeups_owner_active
    ON wakeups (owner_session_id, state) WHERE owner_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS wakeups_target_session
    ON wakeups (target_session_id, state) WHERE target_session_id IS NOT NULL;

ALTER TABLE mailbox ADD COLUMN coalesce_key TEXT;
ALTER TABLE mailbox ADD COLUMN expires_at INTEGER;
ALTER TABLE mailbox ADD COLUMN missed_count INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS mailbox_coalesce_pending
    ON mailbox (session_id, coalesce_key)
    WHERE gate_state = 'pending' AND coalesce_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS mailbox_expires_pending
    ON mailbox (expires_at)
    WHERE gate_state = 'pending' AND expires_at IS NOT NULL;
