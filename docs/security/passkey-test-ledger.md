# Per-operation approval test update

Base: c5d0511. Scope: gate policy and authority administration.

- `passkey_gate_boundary_e2e`: repair live signature, role, revoked-key, wrong-node, CSRF, signed-policy tamper, restart, and alternate-entrypoint proofs. Replace offline lifecycle with rejection of removed CLI paths. An unsigned init is now a proposal or a timed-out live ceremony. Keep existing real SQLite and daemon checks.
- `tty_confirmation_e2e`: retain quarantine/body-review/signing and HTTPS guard tests. Replace lock/unlock, offline preview, TTY-authority approval and unlocked-removal lifecycles with live-operation tests. Those behaviors are obsolete; no TTY can authorize those changes now. Preserve tamper summaries, weakening/removal, signing-key redirection rejection, fresh approval, and no-mutation-on-timeout checks.
- Other CLI suites: rename gate lock to apply, remove obsolete --lock flag, keep hot reload/offline daemon/topology assertions. Unsigned setup becomes proposal staging where a later live apply already exists.
- `security_gates`: retain historical signed locked/unlocked fixtures and expiry behavior, add actual local identity binding and cross-node rejection. Historical fixtures remain migration evidence, not mutation authorization.

Validation: focused CLI Passkey, TTY, hot-reload, store/node security suites; then repository formatting, JS lint/tests, Clippy, clean-environment workspace tests, release build and installer checks. No baseline causal result is claimed for new command-removal tests: the public API deliberately changed. Regression tests for fresh nonce/old unlocked records exercise supported commands with independent signed fixtures.
