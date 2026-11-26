# Security Policy

## Supported Versions

Security fixes are applied to the latest minor release line (`0.7.x`) and `main`.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report suspected vulnerabilities privately using GitHub Security Advisories:

- **GitHub Private Vulnerability Reporting:** `https://github.com/hyphae-to/hyp/security/advisories/new`

Please include:
- A clear description of the issue and the affected component (`hyp-proto`, `hyp-crypto`, `hyp-store`, `hyp-node`, `hyp-harness`, `hyp-cli`, `plugins/`, or `workers/drop-relay/`).
- Minimal reproduction steps or a failing test case.
- The `hyp version --json` output and OS/platform.

We aim to acknowledge reports within 48 hours and provide an assessment or mitigation plan promptly.

## Threat Model & Known Scope Boundaries

Before reporting local-privilege issues, please read the [Threat Model](docs/security/threat-model.md) and [Hardening Guide](docs/security/hardening.md).

In particular:
- **In scope:** Cryptographic breaks, authentication or scope bypasses, E2EE downgrade/rollback issues, prompt-injection framing escapes (`packer.rs`), webhook auth/dedup bypasses, secret leakage into logs/argv/`node.status.json`/`ui/state.json`, path traversal or decompression bombs in file drops, SSRF/header spoofing bypassing `trustedProxies`, and unauthenticated access to `/v1/manifest` internals.
- **Explicit non-goal (same-OS-user shell isolation):** Gate-policy and human-authority administration require fresh live Passkey approval at supported command boundaries. Hyphae does not sandbox arbitrary same-user shell processes or provide an external anti-rollback anchor for `node.sqlite`. A process that can replace the binary or rewrite/restore all state is outside this boundary. Run untrusted agents under a separate OS user or container without access to Hyphae state when that isolation is needed. See [the threat model](docs/security/threat-model.md).
