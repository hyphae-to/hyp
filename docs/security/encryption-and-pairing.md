# Encryption & Pairing

All cryptographic primitives live in `crates/hyp-crypto` (`ring`, `sha2`, `zeroize`, `flate2`).

---

## 1. Persistent Node Identity & Memory Zeroization

- Each node generates persistent **Ed25519** signing and **RFC 7748 X25519** encryption keypairs stored in `SecretStore` (`node-sign-<hash12>`, `node-enc-<hash12>`, transparently reading legacy `id-sign-*`/`id-enc-*`).
- Public keys travel as standard **RFC 7517 / RFC 8037 OKP JWKs** identified by **RFC 7638 SHA-256 JWK Thumbprints** (`kid`).
- Private keys, HPKE shared secrets, epoch room keys, and streaming file-transfer DEKs live in `Zeroizing` buffers wiped deterministically on drop.

---

## 2. End-to-End Encryption (RFC 9180 HPKE Base Mode)

Between paired Hyphae nodes, all payload classes are end-to-end encrypted:

- **1-to-1 DMs (`dm.e2ee.v1`):** Sealed with `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `AES-256-GCM` and signed with domain-separated Ed25519 over RFC 8785 JCS. Hubs relay ciphertext only.
- **Epoch-Rotated `#channels` (`channel.e2ee.v1`) & `#announcements`:** 256-bit symmetric epoch room keys wrapped via HPKE per authorized member, rotated on membership leave/revocation.
- **Shared KV (`kv.e2ee.v1`):** Namespace-scoped E2EE with `AES-256-GCM` AAD binding `(host, namespace, key, version, epoch, writer)` plus optimistic CAS (`If-Match` / `expectedVersion`).
- **Streaming File Drops (`transfer.stream.v2`):** Constant `O(64 KiB)` RAM streaming POSIX `tar.gz` encrypted in 64 KiB AES-256-GCM chunks (`base_nonce XOR chunk_index` + final-chunk AAD flag) with multi-recipient HPKE DEK slots and OCI `sha256:<hex>` digests. Unpacking fails closed on symlinks, hardlinks, FIFOs, device nodes, absolute paths, `..` traversal, NUL bytes, `> 200` files, or `> 256 MiB` uncompressed decompression bombs, and forces `0600`/`0700` modes.

### Anti-Downgrade & Directory Key Trust

- **E2EE ratchet:** Signed capability manifests (`GET /v1/manifest`) enforce monotonic `manifestVersion`, expiry checks, and an anti-downgrade ratchet — if a peer previously advertised `dm.e2ee.v1` or `channel.e2ee.v1` and drops it, connections fail closed with `capability_downgrade_detected`.
- **Team Hub directory keys:** Peer public keys fetched through a Team Hub currently use **pin-on-first-use** (once pinned, unexpected key swaps fail closed). Signed anti-rollback directory checkpoints (`directory.checkpoint.v1`) are planned.

---

## 3. Pairing Trust Models & Live Revocation

Pairing tokens (`hp2p1_`, `am2_`, `t3mp1_`) are **never** accepted as CLI argv flags — always pipe via stdin (`<<< "$TOKEN"`) or read from a `0600` `--token-file`:

1. **Direct P2P Mutual Pairing (`hp2p1_`):** Zero CA, zero TOFU window. The inviter's OKP JWKs and a single-use 160-bit CSPRNG pairing secret travel out-of-band; the accepter proves possession of both the secret and its own Ed25519 key.
2. **Team Hub Admin-CA Pairing (`am2_`):** An offline Org Root Admin-CA signs per-device grants. The Team Hub stores **only** the public Admin-CA JWK (`hyphae-admin-pubkey`) — never the private Admin-CA key.
3. **Self-Service Public Guest Pairing (`guest-ro`):** `POST /v1/guest/pair` requires a fresh (±5 min) Ed25519 possession proof (`409 peer_key_mismatch` on key hijacking) and confines guests strictly to `stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]`.
4. **Anti-Recon Manifests:** Unauthenticated `GET /v1/manifest` requests return `audience: "public"` with strictly empty `advertised` arrays and no `escalation` text.
5. **Transit Enforcement & Live Revocation:** Transit/hub nodes enforce `forwarding` allowlists alongside explicit `forward:via` and `dm:receive` scopes (`*` and `full` never grant `forward:via` or `bridge:post`). Running `hyp pair revoke <peer>` clears credentials and fires live `peers.reload` to tear down active links immediately.

See [Scopes & Presets](../reference/scopes.md) for the complete scope grammar.
