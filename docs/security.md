# Security Documentation Has Moved

Hyphae's security documentation is now organized under [`docs/security/`](security/threat-model.md):

- **[Threat Model (Start Here)](security/threat-model.md)** — what Hyphae defends against, the honest same-OS-user boundary, untrusted framing, `hyp exec` limits, and Drop Relay storage.
- **[Local Security Gates & Quarantine](security/gate.md)** — Stage 1/Stage 2 filters, `gate_policy_sig`, and quarantine review.
- **[Encryption & Pairing](security/encryption-and-pairing.md)** — RFC 9180 HPKE, Ed25519, E2EE channels/KV/transfers, and pairing trust models.
- **[Human Authority & Drop Relay](security/human-authority.md)** — Passkey+PRF drops, `encDraft`, and `spore.hyphae.to` vs. RAM-only relays.
- **[Local Hardening Guide](security/hardening.md)** — running untrusted coding agents under a separate OS user or container.
