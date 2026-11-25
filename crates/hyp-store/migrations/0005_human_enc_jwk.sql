-- Hyphae v2 Schema Migration 0005: Companion X25519 encryption JWK for Human Authorities
-- Enables HPKE-encrypted directive draft prefills (`encDraft`) in `#drop=` links.
-- Purely additive: preserves all v1-v4 rows with zero table rebuilds.
ALTER TABLE human_authorities ADD COLUMN enc_jwk_json TEXT;
