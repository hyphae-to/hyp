ALTER TABLE handles ADD COLUMN description TEXT;

CREATE TABLE IF NOT EXISTS peer_routes (
    target_node TEXT PRIMARY KEY,
    via_peer TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS peer_routes_via ON peer_routes (via_peer);
