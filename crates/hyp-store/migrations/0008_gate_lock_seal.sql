-- =========================================================================
-- Schema v8: External Passkey-Signed Gate Lock Seal & Approval Claim Nonces
-- =========================================================================

-- One row: the Passkey Admin's signed approval claim that last locked or unlocked the gate.
-- Everything else about the seal is read from the signed claim itself.
CREATE TABLE IF NOT EXISTS gate_lock_seal (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seal_seq INTEGER NOT NULL CHECK (seal_seq >= 1),
    signed_claim_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE human_claim_nonces_v8 (
    claim_id TEXT PRIMARY KEY,
    human_kid TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('directive', 'secret', 'human_invite', 'approval')),
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL
);

INSERT INTO human_claim_nonces_v8 (claim_id, human_kid, kind, expires_at, consumed_at)
    SELECT claim_id, human_kid, kind, expires_at, consumed_at FROM human_claim_nonces;

DROP TABLE human_claim_nonces;

ALTER TABLE human_claim_nonces_v8 RENAME TO human_claim_nonces;

CREATE INDEX IF NOT EXISTS human_claim_nonces_expires
    ON human_claim_nonces (expires_at);
