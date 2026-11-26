# Hyphae (`hyp`) Black-Box Integration Test Suite (`itest/`)

Strict black-box end-to-end tests driving the compiled `hyp` binary alongside **real installed coding harnesses & orchestrators** (OpenClaw, Claude Code, Codex, Herdr, OpenCode, Gemini CLI, T3 Code, plus wire-exact Cursor & Antigravity IDE lifecycle replay) while shimming **only** external LLM Model APIs (`FakeBrain` / `llm-shim`) and third-party SaaS endpoints on loopback `127.0.0.1:0`.

## Architectural Invariants

1. **Strict Black-Box Boundary:** `itest/` sits outside the Cargo workspace and invokes `hyp` strictly as a compiled binary (`HYP_BIN`), never importing internal Rust structs.
2. **Hermetic Isolation:** Every test runs inside an isolated temporary directory with a strict allowlist-only scrubbed environment (`HYPHAE_SECRET_BACKEND=file`, `HYPHAE_TAILSCALE_BIN=none`, `HYPHAE_NO_OPEN=1`, `HYPHAE_NO_SERVICE=1`, loopback egress blackhole).
3. **Zero Host Pollution:** `HostCanary` snapshots host `~/.config/hyphae`, `~/.openclaw`, `~/.claude`, `~/.codex`, `~/.config/opencode`, `~/.config/herdr-core`, `~/.config/herdr-app`, `~/.gemini` (including Antigravity CLI/plugin files), `~/.cursor`, and `~/.t3` before & after every test and fails immediately if any host file is touched.
4. **Zero Zombie Processes:** `ProcessReaper` spawns daemons, gateways, isolated `hc` servers, `t3 serve` instances, PTY sessions, and harnesses in isolated POSIX process groups (`detached: true`) and kills `-pgid` (`SIGTERM` -> `SIGKILL`) on exit/failure.
5. **Five Always-On `llm-shim` Auditors:** Every model request across Anthropic Messages, OpenAI Responses, OpenAI Chat Completions, and Google Gemini (`generateContent` / `streamGenerateContent`) passes through Zero Secret Leak, Untrusted Provenance Wrapper, Metadata-Only Wake Nudge, Duplicate-Delivery & Session-Coherence, and MCP Tool Schema Footprint auditors.

## Prerequisites

- **Node.js 24+** (native TypeScript type-stripping, `node:test`, and `node:sqlite` — zero build step).
- **Python 3** (stdlib `pty` module used for zero-dependency interactive PTY sessions and human-CLI confirmations).
- Compiled `hyp` binary (`cargo build --bin hyp`, or set `HYP_BIN=/path/to/hyp`).
- Installed real harnesses (either via isolated `~/.cache/hyphae-itest/` cache or host binaries via `HYPHAE_ITEST_USE_HOST_BINS=1`).
- **Zero Docker required** for all default Tier 1 and local Tier 2 runs.

## Provisioning / Discovering Harnesses

```bash
# Discover already-installed host binaries and compare against versions.lock.json:
node itest/scripts/provision.mjs --use-host-bins --json

# Or populate isolated version-pinned npm prefixes under ~/.cache/hyphae-itest/ (never `npm -g`):
node itest/scripts/provision.mjs --tools openclaw,claude,codex,gemini
```

## Running Tests

Use the root [`Justfile`](../Justfile) recipes or `npm --prefix itest run ...`:

```bash
# Tier 1 Core PR Gate (zero Docker):
just itest-core
# or: HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 npm --prefix itest run itest:core

# Tier 2 Full Matrix (all 15 suites across Phases 1-4):
just itest-full
# or: HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 npm --prefix itest run itest:all

# Run by Phase:
just itest-phase1   # llm-shim + OpenClaw + Claude Code
just itest-phase2   # Codex + Herdr + OpenCode + Gemini + P1-P8 Differential Parity Matrix
just itest-phase3   # Chat Bridges + Compiled-In/SaaS Sources + Onboarding Trees
just itest-phase4   # T3 Code + Cursor/Antigravity Replay + Multi-Node E2EE Topology + Schema Compat

# Run individual Phase 4 suites:
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/t3-orchestrator.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/replay-ide-harnesses.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/topology-multinode.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/schema-compat.test.ts
```

## Suite Overview (Phases 1–4)

### Phase 1 & 2: Real Coding Harnesses & Cross-Harness Differential Parity (P1–P8)
- `openclaw.test.ts`, `claude.test.ts`, `codex.test.ts`, `herdr-orchestrator.test.ts`, `opencode.test.ts`, `gemini.test.ts`
- `parity-matrix.test.ts`: drives identical **P1–P8** scenarios across every available real headless harness via `RealHarnessAdapter` (`itest/lib/harnesses/types.ts`) and compares normalized `ObservableTrace` outputs differentially.

### Phase 3: Chat Bridges, Sources & SaaS Plugins (Zero-Dependency Loopback Wire-Mocks)
- `bridges-e2e.test.ts`: full mock -> real plugin subprocess -> compiled `hyp` -> real Claude Code -> outbound reply (`telegram`, `slack`, `whatsapp`) + Blind Spot **B2** (`CrashLoopBackOff` + `0600` redacted logs).
- `saas-sources-e2e.test.ts`: `github-public`/`github-webhook`, Rust vs Node `prometheus` & `webhook` differential parity (incl. **B1**), `localIngest` (`ingest.sock` / `hyp emit`), and all 6 SaaS source mocks (**B3** inclusive cursors & WS/REST races).
- `onboarding-trees.test.ts`: `hyp plugin install` / `verify` / tamper detection + `hyphae.onboarding/v1` tree validator.

### Phase 4: T3 Code, IDE Replay, Multi-Node E2EE Topology, Schema Compat & CI Infrastructure
- **`t3-orchestrator.test.ts` (`lib/harnesses/t3.ts`):** Boots real isolated `t3 serve --mode desktop --host 127.0.0.1 --port <P> --base-dir $TMP/t3 --no-browser` (`t3 project add` + `t3 auth session issue`), verifies `hyp setup --harness t3`, read-only `statev2.sqlite` provider-session auto-attach, `/api/auth/session` + `/api/auth/websocket-ticket` + Effect WS RPC `orchestration.getThreadProjection` & `orchestration.dispatchCommand` metadata-only `<hyphae-wake>` nudges, bad auth token `401` fail-closed/detach, archived/deleted thread fail-closed guards, arbitrary `tokenSecret` exfiltration rejection, and active-run dispatch modes (`queue_after_active`, `steer_active`, `restart_active`) via schema-pinned contract fallback.
- **`replay-ide-harnesses.test.ts` (`lib/harnesses/replay-cursor-agy.ts`):** Wire-exact compiled-binary lifecycle replay for **Cursor** (`hyp setup --harness cursor`, preservation, `call_id` binding, spoof rejection, `UNTRUSTED_PROVENANCE`, mid-turn `afterMCPExecution` vs `stop` drain, `hyp wait`) and **Antigravity** (`hyp setup --harness antigravity --statusline`, stacked custom statusLine preservation/execution/restore, sidecar `--if-not-running` dedup, direct + lazy `call_mcp_tool` `_meshCall` unwrapping & single-use replay rejection, `PreInvocation` `injectSteps`, `Stop` anti-loop, `hyp wait`), plus opt-in Tier 3 live smoke hooks (`HYPHAE_ITEST_LIVE_CURSOR=1`, `HYPHAE_ITEST_LIVE_AGY=1`).
- **`topology-multinode.test.ts`:** 3-node compiled `hyp` topology on `127.0.0.1:0` — blind Router Hub (`acme-hub`) + real Claude Code (`alice@node-a`) <-> real Codex CLI (`bob@node-b`) via live `am2_` Admin-CA pairing — verifying bidirectional E2EE DM, E2EE `#ops` channel, Shared E2EE KV + CAS conflict/update, Verified Human Drops (`hyp auth init` + PTY `hyp auth sign` + `hyp drop ingest` secret & directive + non-TTY guard + replay rejection), cryptographic zero-knowledge Hub SQLite/WAL audit, and Blind Spot **B6 (`#25`)** private topic ACL checks.
- **`schema-compat.test.ts` (Blind Spot B4):** Deterministic `node:sqlite` forward migration tests (`v5 -> v7` & `v6 -> v7` with automatic `0600` pre-migration backups & zero data loss), future schema fail-closed guard (`v99 -> v7` asserting `SCHEMA_TOO_NEW` across `status`, `doctor`, and `daemon` with zero DB corruption), plus optional real `HYP_PREV_BIN` (`N-1` vs `N`) cross-binary skew check.
- **CI, GHCR Image & Tier 2 Emulators:**
  - `.github/workflows/blackbox-itest.yml`: Tier 1 PR gate (with Blind Spot **B5** poisoned parent env), nightly Tier 2 full matrix (`0 2 * * *` on `ubuntu-latest` + `macos-latest`), every-3-days non-blocking upstream harness canary (`0 5 */3 * *`), and automatic `ghcr.io/hyphae-to/hyp-itest:latest` image builds.
  - `itest/Dockerfile`: Pre-baked CI image with Node 24, Python 3, `alertmanager`, `mosquitto`, and pinned npm harnesses under `/opt/hyphae-itest` (non-root `itest` user).
  - `itest/docker-compose.mocks.yml`: Optional loopback-only Tier 2 vendor emulators (`alertmanager`, `tg-mock`, `mock-oauth2-server`, `mosquitto`, plus `stripe-mock`, `prism`, `svix-server` profiles).

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `HYP_BIN` | Explicit path to compiled `hyp` binary (defaults to `<repo>/target/debug/hyp` then `<repo>/target/release/hyp`). |
| `HYP_PREV_BIN` | Optional path to previous release `hyp` (`N-1`) binary for live cross-binary schema skew tests in `schema-compat.test.ts`. |
| `OPENCLAW_BIN`, `CLAUDE_BIN`, `CODEX_BIN`, `HC_BIN`, `OPENCODE_BIN`, `GEMINI_BIN`, `T3_BIN` | Explicit binary overrides for individual harnesses/orchestrators. |
| `HYPHAE_ITEST_USE_HOST_BINS=1` | Prefer host binaries over `~/.cache/hyphae-itest/` (falling back to cache when absent on host). |
| `HYPHAE_ITEST_SAAS_PLUGINS_DIR` | Optional read-only directory containing the 6 SaaS source plugins (`agentmail`, `gmail`, `google-calendar`, `sentry`, `vercel`, `notion`). |
| `HYPHAE_ITEST_LIVE_CURSOR=1` / `HYPHAE_ITEST_LIVE_AGY=1` | Opt-in Tier 3 live cloud smoke tests against authenticated `cursor-agent` / `agy` (always skipped by default). |
| `HYPHAE_ITEST_KEEP_LOGS=1` | Always dump forensics bundles to `itest-forensics/<test-name>/` even on pass. |

## Failure Forensics

When any test fails (or when `HYPHAE_ITEST_KEEP_LOGS=1`), `Sandbox` writes a diagnostic bundle under `itest-forensics/<test-name>/` containing `summary.json`, `llm-shim-requests.json`, `daemon.log`, `gateway.log`, `harness-stdout.log`, and `hyp-inspect.json`.
