# Testing Strategy (McKeeman Differential Testing)

Hyphae's test suite is grounded in William M. McKeeman's *Differential Testing for Software* (1998) — see [AGENTS.md](../../AGENTS.md) for the full philosophy.

---

## Core Suites Across the 6-Crate Workspace

- **Frozen Golden Interop Vectors:** `crates/hyp-proto/tests/golden_interop.rs` and `crates/hyp-crypto/tests/golden_interop.rs` verify bit-exact RFC 8785 JCS, CloudEvents v1.0, filter ASTs, scopes, Ed25519/X25519, RFC 9180 HPKE, and `t3mp1_`/`seal_v1` interop.
- **Reference Specification Oracle vs. WAL SQLite:** `crates/hyp-store/tests/differential_oracle.rs` and `concurrency_wal.rs` drive seeded multi-step stateful sequences against both a pure in-memory reference model and real WAL `node.sqlite`, comparing post-state after every step.
- **Adversarial & Mutated-Input Suites:** `crates/hyp-crypto/tests/adversarial_mutations.rs` and `crates/hyp-node/tests/security_gates.rs` perturb 1-bit signatures/tags, tamper with `gate_policy_sig`, inject decompression bombs and path traversals, and verify fail-closed security behavior.
- **Full-Stack Delivery, Chaos & Multi-Node E2E:** `crates/hyp-node/tests/{delivery_policy_e2e,full_stack_chaos_e2e,adapters_public_github,real_plugins_e2e,pairing_revoke_and_drops_e2e,human_drops_and_relay_http_e2e}.rs` test concurrent epoch rotations, hub restarts mid-SSE, bridge `CrashLoopBackOff`, and Drop Relay burn-after-read.
- **Harness Parity & Live Hot-Reload E2E:** `crates/hyp-harness/tests/{native_rust_daemon_e2e,gate_inbox_hot_reload_e2e,harness_parity_wave3_e2e,daemon_hardening_wave2_e2e}.rs` verify `peers.reload`, `gate.reload`, `inbox.wake`, `sessionToken` binding, and push transports.
- **Compiled CLI & Docs Parity E2E:** `crates/hyp-cli/tests/{cli_e2e,full_cli_e2e,deploy_kits_e2e,deploy_pair_cli,public_node_e2e,plugin_cmd_e2e,plugin_config_e2e,wizard_e2e,exec_cmd_e2e,opencode_e2e}.rs` spawn the real compiled `hyp` binary — including parsing and booting real documented `plugins[]` JSON snippets from `docs/plugins.md` and `skills/hyphae-setup/SKILL.md`.

---

## Isolation Invariants & Running Tests

Every test runs in strict isolation (`tempfile::TempDir`, `127.0.0.1:0`, `HYPHAE_SECRET_BACKEND=file`, isolated `HOME`, zero live user config or Keychain mutations, zero cloud calls):

```sh
cargo clippy --workspace --all-targets -- -D warnings
HYPHAE_SECRET_BACKEND=file cargo test --workspace
bash scripts/test-installer.sh
```
