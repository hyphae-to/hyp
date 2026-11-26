# Hyphae (`hyp`) Black-Box Integration Test Suite (`itest/`)

Strict black-box end-to-end tests driving the compiled `hyp` binary alongside **real installed coding harnesses** (OpenClaw, Claude Code, Codex, Herdr, OpenCode, Gemini CLI) while shimming **only** external LLM Model APIs (`FakeBrain` / `llm-shim`) on loopback `127.0.0.1:0`.

## Architectural Invariants

1. **Strict Black-Box Boundary:** `itest/` sits outside the Cargo workspace and invokes `hyp` strictly as a compiled binary (`HYP_BIN`), never importing internal Rust structs.
2. **Hermetic Isolation:** Every test runs inside an isolated temporary directory with a strict allowlist-only scrubbed environment (`HYPHAE_SECRET_BACKEND=file`, `HYPHAE_TAILSCALE_BIN=none`, `HYPHAE_NO_OPEN=1`, `HYPHAE_NO_SERVICE=1`, loopback egress blackhole).
3. **Zero Host Pollution:** `HostCanary` snapshots host `~/.config/hyphae`, `~/.openclaw`, `~/.claude`, `~/.codex`, `~/.config/opencode`, `~/.config/herdr-core`, `~/.config/herdr-app`, and `~/.gemini` before & after every test and fails immediately if any host file is touched.
4. **Zero Zombie Processes:** `ProcessReaper` spawns daemons, gateways, isolated `hc` servers, PTY sessions, and harnesses in isolated POSIX process groups (`detached: true`) and kills `-pgid` (`SIGTERM` -> `SIGKILL`) on exit/failure.
5. **Five Always-On `llm-shim` Auditors:** Every model request across Anthropic Messages, OpenAI Responses, OpenAI Chat Completions, and Google Gemini (`generateContent` / `streamGenerateContent`) passes through Zero Secret Leak, Untrusted Provenance Wrapper, Metadata-Only Wake Nudge, Duplicate-Delivery & Session-Coherence, and MCP Tool Schema Footprint auditors.

## Prerequisites

- **Node.js 24+** (native TypeScript type-stripping + `node:test`, zero build step).
- **Python 3** (stdlib `pty` module used by `itest/lib/pty.ts` for zero-dependency interactive PTY sessions and human-CLI confirmations).
- Compiled `hyp` binary (`cargo build --bin hyp`, or set `HYP_BIN=/path/to/hyp`).
- Installed real harnesses (either via isolated cache or already installed on host).

## Provisioning / Discovering Harnesses

```bash
# Discover already-installed host binaries and compare against versions.lock.json:
node itest/scripts/provision.mjs --use-host-bins --json

# Or populate isolated version-pinned npm prefixes under ~/.cache/hyphae-itest/ (never `npm -g`):
node itest/scripts/provision.mjs --tools gemini
node itest/scripts/provision.mjs --tools openclaw,claude,codex,gemini
```

## Running Tests

```bash
# Run all Phase 1 + Phase 2 suites:
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 npm --prefix itest run itest:all

# Run Phase 1 only (llm-shim + OpenClaw + Claude Code):
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 npm --prefix itest run itest:phase1

# Run Phase 2 only (Gemini llm-shim + Codex + Herdr + OpenCode + Gemini + P1–P8 Parity Matrix):
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 npm --prefix itest run itest:phase2

# Run individual suites:
node --test itest/suites/llm-shim.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/openclaw.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/claude.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/codex.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/herdr-orchestrator.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/opencode.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/gemini.test.ts
HYP_BIN=./target/debug/hyp HYPHAE_ITEST_USE_HOST_BINS=1 node --test itest/suites/parity-matrix.test.ts
```

## Cross-Harness Differential Parity Matrix (P1–P8)

`itest/suites/parity-matrix.test.ts` drives the same declarative P1–P8 scenario matrix across every available real headless harness (`OpenClaw`, `Claude Code`, `Codex`, `Herdr+Claude`, `Gemini CLI`, and tracks `OpenCode`) via the unified `RealHarnessAdapter` interface (`itest/lib/harnesses/types.ts`) and compares normalized `ObservableTrace` outputs differentially:

- **P1**: Idle DM Wake & Reply (exact single delivery, zero secret leaks)
- **P2**: Mid-Turn Queue Hold -> TurnEnd Flush (deterministic `pauseMidStream` latch)
- **P3**: Mid-Turn Interrupt (`hc interrupt` mid-stream preemption on Herdr; earliest `PostToolUse`/`AfterTool` on hook harnesses)
- **P4**: Focus Mode & Notify Digest (buffered non-urgent, VIP bypass, Focus exit drain)
- **P5**: Burst Protection & Coalescing (10 rapid DMs -> `<= 2` wake turns)
- **P6**: Security Gate Quarantine + Interactive PTY `hyp inbox approve` (0 bytes leaked before approve, metadata-only `hyp gate review --json`, non-TTY fail-closed check, `gate_audit` verified)
- **P7**: Multi-Session Isolation (2 concurrent sessions on 1 `hyp daemon`, zero cross-bleed)
- **P8**: Daemon Restart Survival (`SIGTERM` + restart `hyp daemon` with unread mailbox -> 0 loss, single delivery)

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `HYP_BIN` | Explicit path to compiled `hyp` binary (defaults to `<repo>/target/debug/hyp` then `<repo>/target/release/hyp`). |
| `OPENCLAW_BIN` | Explicit path to `openclaw` binary (auto-discovers `PATH` and `~/Workspace/openclaw-hyphae-sandbox/runtime/node_modules/.bin/openclaw`). |
| `CLAUDE_BIN` | Explicit path to `claude` binary (auto-discovers `PATH` and `~/.local/bin/claude`). |
| `CODEX_BIN` | Explicit path to `codex` binary (auto-discovers `PATH` and `~/.local/bin/codex`). |
| `HC_BIN` | Explicit path to Herdr `hc` binary (auto-discovers `PATH` and `~/.local/bin/hc`). |
| `OPENCODE_BIN` | Explicit path to `opencode` binary (auto-discovers `PATH` and `~/.opencode/bin/opencode`). |
| `GEMINI_BIN` | Explicit path to `gemini` binary (auto-discovers `~/.cache/hyphae-itest/` and `PATH`). |
| `HYPHAE_ITEST_USE_HOST_BINS=1` | Prefer host binaries over `~/.cache/hyphae-itest/` (falling back to cache for tools like `gemini`). |
| `HYPHAE_ITEST_KEEP_LOGS=1` | Always dump forensics bundles to `itest-forensics/<test-name>/` even on pass. |

## Failure Forensics

When any test fails (or when `HYPHAE_ITEST_KEEP_LOGS=1`), `Sandbox` writes a diagnostic bundle under `itest-forensics/<test-name>/` containing:
- `llm-shim-requests.json` (captured canonical + raw model requests & auditor findings)
- `daemon.log` (`hyp daemon` stdout/stderr)
- `gateway.log` (when running OpenClaw Gateway)
- `harness-stdout.log` (harness process logs)
- `hyp-inspect.json` (`hyp inspect --all --json` snapshot before teardown)
