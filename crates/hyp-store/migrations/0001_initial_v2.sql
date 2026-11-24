-- =========================================================================
-- 1. Messaging & Channels
-- =========================================================================

CREATE TABLE IF NOT EXISTS handles (
    node_id TEXT NOT NULL,
    handle TEXT NOT NULL,
    session_id TEXT,
    registered_at INTEGER NOT NULL,
    last_heartbeat_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, handle)
);
CREATE INDEX IF NOT EXISTS handles_heartbeat ON handles (last_heartbeat_at);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    channel TEXT,
    text TEXT NOT NULL,
    digest TEXT NOT NULL,
    sent_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'rejected', 'expired')),
    reason TEXT,
    hold_until INTEGER NOT NULL DEFAULT 0,
    settled_at INTEGER,
    origin_environment_id TEXT,
    origin_thread_id TEXT,
    e2ee_epoch INTEGER
);
CREATE INDEX IF NOT EXISTS messages_pending ON messages (to_addr, sent_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS messages_recent ON messages (to_addr, sent_at);
CREATE INDEX IF NOT EXISTS messages_settled ON messages (settled_at) WHERE state != 'pending' AND settled_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS messages_hold ON messages (hold_until) WHERE state = 'pending' AND hold_until > 0;

CREATE TABLE IF NOT EXISTS channel_members (
    host_node TEXT NOT NULL DEFAULT 'local',
    channel TEXT NOT NULL,
    address TEXT NOT NULL,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (host_node, channel, address)
);
CREATE INDEX IF NOT EXISTS channel_members_address ON channel_members (address);

CREATE TABLE IF NOT EXISTS channel_epochs (
    host_node TEXT NOT NULL DEFAULT 'local',
    channel TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    creator_node_id TEXT NOT NULL,
    key_envelope_json TEXT NOT NULL,
    members_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (host_node, channel, epoch)
);
CREATE INDEX IF NOT EXISTS channel_epochs_latest ON channel_epochs (host_node, channel, epoch DESC);

-- =========================================================================
-- 2. Universal CloudEvents Bus & Pushdown Subscriptions
-- =========================================================================

CREATE TABLE IF NOT EXISTS publishers (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS publisher_grants (
    publisher_id TEXT NOT NULL REFERENCES publishers(id) ON DELETE CASCADE,
    topic TEXT NOT NULL,
    PRIMARY KEY (publisher_id, topic)
);

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    origin_node TEXT NOT NULL DEFAULT 'local',
    topic TEXT NOT NULL,
    publisher TEXT NOT NULL,
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    body TEXT,
    bytes INTEGER NOT NULL,
    matched INTEGER NOT NULL DEFAULT 0,
    received_at INTEGER NOT NULL,
    UNIQUE (origin_node, topic, publisher, source, event_id)
);
CREATE INDEX IF NOT EXISTS events_received ON events (received_at);
CREATE INDEX IF NOT EXISTS events_with_body ON events (received_at) WHERE body IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_origin_topic ON events (origin_node, topic, received_at);

CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    origin_node TEXT NOT NULL DEFAULT 'local',
    topic TEXT NOT NULL,
    subscriber TEXT NOT NULL,
    filters_json TEXT NOT NULL,
    coalesce_seconds INTEGER NOT NULL DEFAULT 0,
    max_batch_age_ms INTEGER,
    max_wakes_per_hour INTEGER,
    mode TEXT NOT NULL DEFAULT 'full' CHECK (mode IN ('full', 'notify')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS subscriptions_origin_topic ON subscriptions (origin_node, topic);
CREATE INDEX IF NOT EXISTS subscriptions_subscriber ON subscriptions (subscriber);

CREATE TABLE IF NOT EXISTS batches (
    id TEXT PRIMARY KEY,
    subscription_id TEXT NOT NULL,
    origin_node TEXT NOT NULL DEFAULT 'local',
    subscriber TEXT NOT NULL,
    topic TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'pending', 'delivered', 'rejected', 'dropped')),
    event_count INTEGER NOT NULL DEFAULT 0,
    opened_at INTEGER NOT NULL,
    last_event_at INTEGER NOT NULL,
    flush_at INTEGER NOT NULL,
    closed_at INTEGER,
    hold_until INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    settled_at INTEGER
);
CREATE INDEX IF NOT EXISTS batches_subscription ON batches (subscription_id, state, closed_at);
CREATE INDEX IF NOT EXISTS batches_state ON batches (state);
CREATE INDEX IF NOT EXISTS batches_open_flush ON batches (flush_at) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS batches_subscriber_pending ON batches (subscriber, state, closed_at);

CREATE TABLE IF NOT EXISTS batch_events (
    batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    event_seq INTEGER NOT NULL,
    PRIMARY KEY (batch_id, position)
);
CREATE INDEX IF NOT EXISTS batch_events_event ON batch_events (event_seq);

CREATE TABLE IF NOT EXISTS upstream_pushdowns (
    id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL,
    topic TEXT NOT NULL,
    shard_index INTEGER NOT NULL DEFAULT 0,
    filters_json TEXT NOT NULL,
    coalesce_seconds INTEGER NOT NULL,
    local_sub_count INTEGER NOT NULL DEFAULT 0,
    digest TEXT NOT NULL,
    synced_at INTEGER,
    last_error TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE (peer_id, topic, shard_index)
);
CREATE INDEX IF NOT EXISTS upstream_pushdowns_peer ON upstream_pushdowns (peer_id, topic);

-- =========================================================================
-- 3. Encrypted File Transfers
-- =========================================================================

CREATE TABLE IF NOT EXISTS transfers (
    id TEXT PRIMARY KEY,
    from_node TEXT NOT NULL,
    to_node TEXT NOT NULL,
    transfer_type TEXT NOT NULL,
    header_json TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    sent_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'rejected', 'expired')),
    reason TEXT,
    hold_until INTEGER NOT NULL DEFAULT 0,
    settled_at INTEGER
);
CREATE INDEX IF NOT EXISTS transfers_pending ON transfers (to_node, sent_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS transfers_expires ON transfers (expires_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS transfers_hold ON transfers (hold_until) WHERE state = 'pending' AND hold_until > 0;

-- =========================================================================
-- 4. Shared KV / Blackboard
-- =========================================================================

CREATE TABLE IF NOT EXISTS kv_entries (
    host_node TEXT NOT NULL DEFAULT 'local',
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/json',
    version INTEGER NOT NULL,
    write_model TEXT NOT NULL DEFAULT 'owner' CHECK (write_model IN ('owner', 'shared', 'allowlist')),
    owner_id TEXT,
    allowlist_json TEXT,
    writer_id TEXT NOT NULL,
    e2ee_epoch INTEGER,
    signature TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (host_node, namespace, key)
);
CREATE INDEX IF NOT EXISTS kv_entries_expires ON kv_entries (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS kv_epochs (
    host_node TEXT NOT NULL DEFAULT 'local',
    namespace TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    creator_node_id TEXT NOT NULL,
    key_envelope_json TEXT NOT NULL,
    members_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (host_node, namespace, epoch)
);
CREATE INDEX IF NOT EXISTS kv_epochs_latest ON kv_epochs (host_node, namespace, epoch DESC);

-- =========================================================================
-- 5. Federation, Pairing, Keys & Directory Trust
-- =========================================================================

CREATE TABLE IF NOT EXISTS peers (
    peer_id TEXT PRIMARY KEY,
    endpoint TEXT,
    profile TEXT NOT NULL DEFAULT 'router' CHECK (profile IN ('local', 'router', 'p2p')),
    trust_tier TEXT NOT NULL DEFAULT 'peer' CHECK (trust_tier IN ('self', 'org', 'peer', 'guest')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active', 'paused', 'revoked')),
    scopes_json TEXT NOT NULL DEFAULT '[]',
    auth_credential_ref TEXT,
    manifest_json TEXT,
    manifest_version INTEGER NOT NULL DEFAULT 0,
    manifest_etag TEXT,
    manifest_fetched_at INTEGER,
    observed_e2ee_caps_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS peers_status ON peers (status);

CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL,
    direction TEXT NOT NULL DEFAULT 'inbound' CHECK (direction IN ('inbound', 'outbound')),
    signed_json TEXT NOT NULL,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    trust_tier TEXT NOT NULL DEFAULT 'peer' CHECK (trust_tier IN ('self', 'org', 'peer', 'guest')),
    issued_at INTEGER NOT NULL,
    pair_by INTEGER,
    expires_at INTEGER,
    entry_json TEXT,
    paired_at INTEGER
);
CREATE INDEX IF NOT EXISTS grants_peer ON grants (peer_id, issued_at);

CREATE TABLE IF NOT EXISTS revocations (
    grant_id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL,
    signed_json TEXT NOT NULL,
    revoked_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS revocations_peer ON revocations (peer_id, revoked_at);

CREATE TABLE IF NOT EXISTS peer_keys (
    peer_id TEXT NOT NULL,
    kid TEXT NOT NULL,
    key_use TEXT NOT NULL CHECK (key_use IN ('signing', 'encryption', 'prekey', 'admin')),
    jwk_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'revoked')),
    registered_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (peer_id, kid)
);
CREATE INDEX IF NOT EXISTS peer_keys_peer_use ON peer_keys (peer_id, key_use, status);

CREATE TABLE IF NOT EXISTS directory_checkpoints (
    authority_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    root_hash TEXT NOT NULL,
    signed_json TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (authority_id, version)
);
CREATE INDEX IF NOT EXISTS directory_checkpoints_latest ON directory_checkpoints (authority_id, version DESC);

-- =========================================================================
-- 6. Local Runtime, Mailbox, Mutes, Bridges & Immutable Security Gate Audit
-- =========================================================================

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    backend_json TEXT NOT NULL,
    handle TEXT UNIQUE,
    last_seen INTEGER NOT NULL DEFAULT 0,
    delivery_mode TEXT NOT NULL DEFAULT 'full' CHECK (delivery_mode IN ('full', 'notify')),
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_last_seen ON sessions (last_seen);

CREATE TABLE IF NOT EXISTS mailbox (
    receipt TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    origin_node TEXT NOT NULL,
    item_id TEXT NOT NULL,
    text TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'message' CHECK (kind IN ('message', 'event', 'plugin', 'transfer', 'kv')),
    source TEXT NOT NULL DEFAULT '',
    notified INTEGER NOT NULL DEFAULT 0,
    gate_state TEXT NOT NULL DEFAULT 'pending' CHECK (gate_state IN ('pending', 'delivered', 'quarantined', 'rejected')),
    gate_reason TEXT,
    traceparent TEXT,
    payload_sha256 TEXT,
    reviewed_at INTEGER,
    UNIQUE (origin_node, item_id, session_id)
);
CREATE INDEX IF NOT EXISTS mailbox_session_state ON mailbox (session_id, gate_state, received_at);
CREATE INDEX IF NOT EXISTS mailbox_quarantined ON mailbox (gate_state, received_at) WHERE gate_state = 'quarantined';

CREATE TABLE IF NOT EXISTS deliveries (
    origin_node TEXT NOT NULL,
    item_id TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (origin_node, item_id)
);
CREATE INDEX IF NOT EXISTS deliveries_created ON deliveries (created_at);

CREATE TABLE IF NOT EXISTS muted_sources (
    scope TEXT NOT NULL,
    pattern TEXT NOT NULL,
    muted_at INTEGER NOT NULL,
    muted_by TEXT NOT NULL,
    PRIMARY KEY (scope, pattern)
);

CREATE TABLE IF NOT EXISTS plugin_targets (
    plugin TEXT NOT NULL,
    target TEXT NOT NULL,
    session_id TEXT NOT NULL,
    set_at INTEGER NOT NULL,
    set_by TEXT NOT NULL,
    PRIMARY KEY (plugin, target)
);

CREATE TABLE IF NOT EXISTS bridge_links (
    plugin TEXT NOT NULL,
    target TEXT NOT NULL,
    session_id TEXT NOT NULL,
    linked_at INTEGER NOT NULL,
    linked_by TEXT NOT NULL,
    PRIMARY KEY (plugin, target, session_id)
);
CREATE INDEX IF NOT EXISTS bridge_links_session ON bridge_links (session_id);

CREATE TABLE IF NOT EXISTS gate_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound', 'review')),
    stage TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'quarantine', 'block', 'error')),
    origin_node TEXT,
    source TEXT,
    session_id TEXT,
    receipt_id TEXT,
    event_type TEXT,
    trust_tier TEXT,
    confidence REAL,
    categories_json TEXT,
    reason TEXT,
    traceparent TEXT,
    payload_sha256 TEXT NOT NULL,
    reviewer TEXT
);
CREATE INDEX IF NOT EXISTS gate_audit_created ON gate_audit (created_at);
CREATE INDEX IF NOT EXISTS gate_audit_decision_created ON gate_audit (decision, created_at);

CREATE TRIGGER IF NOT EXISTS gate_audit_no_update
BEFORE UPDATE ON gate_audit
BEGIN
    SELECT RAISE(ABORT, 'gate_audit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS gate_audit_no_delete
BEFORE DELETE ON gate_audit
BEGIN
    SELECT RAISE(ABORT, 'gate_audit is immutable');
END;
