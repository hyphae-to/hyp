# Hyphae (`hyp`) Black-Box Integration Test Suite (`itest/`)

Strict black-box end-to-end tests driving the compiled `hyp` binary alongside **real installed coding harnesses** (OpenClaw, Claude Code, Codex, Herdr, OpenCode, Gemini CLI) while shimming **only** external LLM Model APIs (`FakeBrain` / `llm-shim`) on loopback `127.0.0.1:0`.

## Architectural Invariants

1. **Strict Black-Box Boundary:** `itest/` sits outside the Cargo workspace and invokes `hyp` strictly as a compiled binary (`HYP_BIN`), never importing internal Rust structs.
2. **Hermetic Isolation:** Every test runs inside an isolated temporary directory with a strict allowlist-only scrubbed environment (`HYPHAE_SECRET_BACKEND=file`, `HYPHAE_TAILSCALE_BIN=none`, `HYPHAE_NO_OPEN=1`, `HYPHAE_NO_SERVICE=1`, loopback egress blackhole).
3. **Zero Host Pollution:** `HostCanary` snapshots host `~/.config/hyphae`, `~/.openclaw`, `~/.claude`, `~/.codex` before & after every test and fails immediately if any host file is touched.
4. **Zero Zombie Processes:** `ProcessReaper` spawns daemons, gateways, and harnesses in isolated POSIX process groups (`detached: true`) and kills `-pgid` (`SIGTERM` -> `SIGKILL`) on exit/failure.
5. **Five Always-On `llm-shim` Auditors:** Every model request passes through Zero Secret Leak, Untrusted Provenance Wrapper, Metadata-Only Wake Nudge, Duplicate-Delivery & Session-Coherence, and MCP Tool Schema Footprint auditors.

## Prerequisites

- **Node.js 24+** (native TypeScript type-stripping + `node:test`, zero build step).
- Compiled `hyp` binary (`cargo build --bin hyp`, or set `HYP_BIN=/path/to/hyp`).
- Installed real harnesses (either via isolated cache or already installed on host).

## Provisioning / Discovering Harnesses

```bash
# Discover already-installed host binaries and compare against versions.lock.json:
node itest/scripts/provision.mjs --use-host-bins --json

# Or populate isolated version-pinned npm prefixes under ~/.cache/hyphae-itest/:
node itest/scripts/provision.mjs --tools openclaw,claude
```

## Running Tests

```bash
# Run all Phase 1 suites (llm-shim self-tests + real OpenClaw + real Claude Code):
HYP_BIN=./target/debug/hyp npm --prefix itest run itest:phase1

# Run individual suites:
node --test itest/suites/llm-shim.test.ts
HYP_BIN=./target/debug/hyp node --test itest/suites/openclaw.test.ts
HYP_BIN=./target/debug/hyp node --test itest/suites/claude.test.ts
```

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `HYP_BIN` | Explicit path to compiled `hyp` binary (defaults to `<repo>/target/debug/hyp` then `<repo>/target/release/hyp`). |
| `OPENCLAW_BIN` | Explicit path to `openclaw` binary (auto-discovers `PATH` and `~/Workspace/openclaw-hyphae-sandbox/runtime/node_modules/.bin/openclaw`). |
| `CLAUDE_BIN` | Explicit path to `claude` binary (auto-discovers `PATH` and `~/.local/bin/claude`). |
| `HYPHAE_ITEST_USE_HOST_BINS=1` | Prefer host binaries over `~/.cache/hyphae-itest/`. |
| `HYPHAE_ITEST_KEEP_LOGS=1` | Always dump forensics bundles to `itest-forensics/<test-name>/` even on pass. |

## Failure Forensics

When any test fails (or when `HYPHAE_ITEST_KEEP_LOGS=1`), `Sandbox` writes a diagnostic bundle under `itest-forensics/<test-name>/` containing:
- `llm-shim-requests.json` (captured canonical + raw model requests & auditor findings)
- `daemon.log` (`hyp daemon` stdout/stderr)
- `gateway.log` (when running OpenClaw Gateway)
- `harness-stdout.log` (harness process logs)
- `hyp-inspect.json` (`hyp inspect --all --json` snapshot before teardown)
