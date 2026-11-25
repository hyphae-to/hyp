-- Hyphae v2 Schema Migration 0006: Persistent TTL expiration for muted_sources
-- Enables temporary mute --ttl rules to survive daemon restarts and expire deterministically.
-- Purely additive: preserves all v1-v5 rows with zero table rebuilds.
ALTER TABLE muted_sources ADD COLUMN expires_at INTEGER;
