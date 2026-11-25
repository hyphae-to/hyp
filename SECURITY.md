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
- **Explicit non-goal (same-OS-user shell isolation):** Hyphae protects against untrusted network input; it does **not** create an OS sandbox against a coding agent running with arbitrary shell access as the **same OS user**. Interactive TTY confirmation prompts (`hyp gate lock`, `hyp inbox approve`/`reject`, `hyp auth revoke`, etc.) raise friction against accidental, scripted, and MCP-driven misuse until hardware Passkey confirmation ships (`#2`, `#10`), but a same-user shell can access `~/.config/hyphae` or drive a PTY. For hard local isolation today, run untrusted agents under a separate OS user or container without access to `~/.config/hyphae`.
