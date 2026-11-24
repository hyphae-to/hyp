-- =========================================================================
-- Schema v4: Human Authority Registry, Single-Use Claim Nonces & Node Certs
-- =========================================================================

CREATE TABLE IF NOT EXISTS human_authorities (
    human_id TEXT NOT NULL,
    kid TEXT NOT NULL,
    label TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'signer')),
    jwk_json TEXT NOT NULL,
    prf_salt TEXT,
    auth_epoch INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revocation_json TEXT,
    PRIMARY KEY (human_id, kid)
);
CREATE INDEX IF NOT EXISTS human_authorities_kid
    ON human_authorities (kid, status);

CREATE TABLE IF NOT EXISTS human_claim_nonces (
    claim_id TEXT PRIMARY KEY,
    human_kid TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('directive', 'secret')),
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS human_claim_nonces_expires
    ON human_claim_nonces (expires_at);

CREATE TABLE IF NOT EXISTS human_node_certs (
    node_id TEXT NOT NULL,
    human_kid TEXT NOT NULL,
    auth_epoch INTEGER NOT NULL,
    signed_json TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, human_kid)
);

ALTER TABLE mailbox ADD COLUMN human_auth_json TEXT;
