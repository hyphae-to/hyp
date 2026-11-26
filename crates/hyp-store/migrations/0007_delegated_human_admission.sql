-- =========================================================================
-- Schema v7: Delegated Human-Cert Admission, Provenance & Cascade Revocation
-- =========================================================================

CREATE TABLE IF NOT EXISTS human_delegation_policies (
    human_id TEXT PRIMARY KEY,
    node_prefix TEXT NOT NULL,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    max_devices INTEGER NOT NULL DEFAULT 10,
    delegation_enabled INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

ALTER TABLE peers ADD COLUMN admitted_by_human_id TEXT;
ALTER TABLE peers ADD COLUMN admitted_auth_epoch INTEGER;

CREATE INDEX IF NOT EXISTS peers_admitted_by_human
    ON peers (admitted_by_human_id, status);

CREATE TABLE human_claim_nonces_v7 (
    claim_id TEXT PRIMARY KEY,
    human_kid TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('directive', 'secret', 'human_invite')),
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL
);

INSERT INTO human_claim_nonces_v7 (claim_id, human_kid, kind, expires_at, consumed_at)
    SELECT claim_id, human_kid, kind, expires_at, consumed_at FROM human_claim_nonces;

DROP TABLE human_claim_nonces;

ALTER TABLE human_claim_nonces_v7 RENAME TO human_claim_nonces;

CREATE INDEX IF NOT EXISTS human_claim_nonces_expires
    ON human_claim_nonces (expires_at);
