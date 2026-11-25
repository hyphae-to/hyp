# Event Sources, External Chat Bridges & Secrets

Hyphae v2 unifies event sources and chat bridges onto the single Rust `Node` CloudEvents v1.0 bus (`node.sqlite`) via `NodeAdapter` (`crates/hyp-node/src/adapters/`), separating **compiled-in pure-Rust event source adapters** from **optional external chat bridge scripts** in `plugins/`.

> **Zero runtime dependency for core `hyp`:** The static Rust `hyp` binary requires **no** Node.js or Python runtime. Scripts under `plugins/` are **optional external subprocesses** (Node or Python) supervised over duplex Unix fd 3 — you only need Node or Python installed if you opt in to running those specific external bridge scripts.

---

## 1. Architecture: Compiled-In Sources vs. External Bridges

| Layer | Implementation | Routing Model | Secrets Location | Best For |
| --- | --- | --- | --- | --- |
| **Compiled-In Rust Event Sources & Local Ingest** (`crates/hyp-node/src/adapters/`, `engine/local_ingest.rs`) | Pure Rust in-process (`github-public`, `github-webhook`, `prometheus-webhook`, `webhook-stream`, plus default-enabled socket-only `localIngest` on `ingest.sock` / `ingest.addr`) — zero Node/Python needed | **1-to-many Pub/Sub** via standard `hyp_stream` with server-side CloudEvents filter pushdown (including `local.schedule` / `local.<topic>` triggered via `hyp emit` or raw NDJSON) | Node's `SecretStore` (`{ "secret": "<name>" }` in `node.json`) | Public or org **GitHub** streams (`github-public` ETag poller + GitHub App webhooks), **Prometheus Alertmanager v4**, signed **HTTP webhooks**, and OS-scheduled **Local Ingest & Cron triggers** |
| **External Subprocess Bridges & Custom Sources** (`plugins/`) | Optional self-contained scripts (`plugins/slack`, `plugins/telegram`, `plugins/whatsapp`, `plugins/webhook`, `plugins/prometheus`, or custom executables) supervised by `SubprocessSupervisor` over fd 3 | **Thread-owned + multi-thread fan-in + outbound replies** via `hyp_bridge` and `hyp_send({ to: "<plugin>:<target>", text })` | Local machine's `SecretStore` — scrubbed subprocess env, never sent to remote hubs | Personal **Slack / Telegram / WhatsApp** bridges, local callbacks, and custom scripts in any language |

---

## 2. Secrets Management (`hyp secret`)

Never put raw API tokens or webhook secrets directly in `node.json` or CLI argv. `hyp secret set` stores secrets in your OS secret store first, with a private `0600` file fallback on headless hosts and Windows:

- **macOS Keychain** (`/usr/bin/security -i` over stdin, service `hyphae`)
- **Linux Secret Service** (`secret-tool` over stdin when `DBUS_SESSION_BUS_ADDRESS` is available)
- **Private local file fallback** (`~/.config/hyphae/secrets/<name>.secret`, `0700` dir / `0600` file, symlink-rejecting; override via `HYPHAE_SECRET_BACKEND=keychain|secret-service|file`)

```sh
# Recommended for agents & interactive laptops (one-shot 127.0.0.1 CSRF-protected form):
hyp secret set slack-app-token --web

# Headless servers / scripts (stdin only — NEVER CLI argv!):
printf '%s' "$GITHUB_PUBLIC_PAT" | hyp secret set github-public-token

# Audit stored secret names, backends, and 0600 modes (never prints values):
hyp secret list
hyp secret list --json

# Remove an unused secret:
hyp secret delete old-token
```

Reference secrets in `node.json` strictly as `{ "secret": "<name>" }`.

---

## 3. Compiled-In Rust Event Sources (`sources[]` in `node.json`)

### Choosing GitHub Ingestion: Webhook (`github-webhook`) vs. Polling (`github-public`)

Pick the transport that matches your node topology:

| Mode | Best Node Topology | Latency | Event Coverage | Auth / Secrets |
| --- | --- | --- | --- | --- |
| **Webhook (`github-webhook`) — Recommended whenever possible** | **Hub / Server Node (`profile: router`)** on a VPS, Fly.io, Docker + Caddy, Cloudflare Tunnel, or Tailscale Funnel | Real-time (`<1–2s`) | **All GitHub events**, including live CI pass/fail (`workflow_run`, `check_run`) and full payloads | **Zero GitHub PAT** — shared HMAC-SHA256 webhook secret only (`X-Hub-Signature-256`) |
| **Polling (`github-public` + `repoTokens`) — Zero-infra NAT fallback** | **Local Node (`profile: local`)** on a laptop behind NAT (or public read-only node) with no public webhook URL | ~30s avg / 60s max (`304 Not Modified` uses 0 quota) | Repo activity only (pushes, PRs, issues, comments, reviews, releases) — **GitHub's `/events` API does NOT emit `workflow_run` / `check_run` CI events** | Optional per-owner/per-repo fine-grained PATs via `repoTokens` (5,000 req/hr per owner token; 60 req/hr unauthenticated for public repos) |

> **Rule of thumb:** **Hub Nodes (`profile: router`) are the natural place to terminate `github-webhook` deliveries** once and fan normalized CloudEvents out over E2EE streams to every paired laptop. Use **`github-public` + `repoTokens`** as the zero-infra fallback on a **Local Node (`profile: local`)** behind NAT when you don't have (or don't want to expose) a hub or public HTTPS endpoint yet.

### A. `github-public` — Demand-Driven Deduplicated ETag Poller (+ Multi-Owner `repoTokens` & Optional `<1s` GitHub App Push)

Compiled directly into `hyp` (`crates/hyp-node/src/adapters/github_public.rs`). Used both on read-only public nodes (`hyp deploy init public-node`) and locally on developer machines behind NAT.

Because GitHub fine-grained PATs are scoped to a **single resource owner** (one personal account OR one organization), `sources[].repoTokens` lets you coalesce personal repos, multiple organizations, exact per-repo overrides, and unauthenticated public repos inside **one single `github-public` source** — never leaking one org's token to another owner or third-party public repos:

```sh
# Store one fine-grained read-only PAT per personal account / GitHub org out-of-band:
hyp secret set github-alice-token --web
hyp secret set github-acme-token --web
```

```json
{
  "sources": [
    {
      "id": "github-public",
      "kind": "github-public",
      "topic": "github",
      "enabled": true,
      "allowPrivateWithToken": true,
      "minPollIntervalSeconds": 60,
      "graceWindowSeconds": 300,
      "maxActivePollers": 100,
      "repoTokens": {
        "alice/*": { "secret": "github-alice-token" },
        "acme/*": { "secret": "github-acme-token" },
        "acme/special": { "secret": "github-acme-special-token" }
      },
      "appWebhookSecret": { "secret": "github-app-webhook-secret" }
    }
  ]
}
```

- **Strict token scoping & precedence**: For each `owner/repo`, Hyphae resolves the token in strict specificity order: (1) exact `owner/repo` in `repoTokens`, (2) owner wildcard `owner/*` in `repoTokens` (bare `owner` also normalizes to `owner/*`), (3) optional fallback `githubToken`, (4) `None` (unauthenticated public mode — zero `Authorization` header sent). Invalid or overly broad patterns (`*`, `*/*`, `..`, empty) and raw plaintext strings fail closed at startup. Missing secrets in `repoTokens` emit an isolated startup warning without crashing the daemon or blocking already-configured owners.
- **Single `github-public` source**: Consolidate all GitHub tokens into `sources[0].repoTokens`; if multiple enabled `github-public` entries exist, only the first is active and Hyphae emits a startup warning.
- **1 poller per distinct `owner/repo` + bounded rate-limit hardening**: Regardless of subscriber count, conditional `If-None-Match` polls returning `304 Not Modified` consume **0** GitHub API quota, adaptively back off on idle repos, enforce bounded backoff on HTTP `403`/`429` (`Retry-After` and `X-RateLimit-Remaining: 0` + `X-RateLimit-Reset`), cap concurrent active pollers at `maxActivePollers` (default `100`), and tear down after `graceWindowSeconds` when active subscribers drop to `0`.
- **Private repo access**: On non-`publicReadOnly` local/private nodes, setting `"allowPrivateWithToken": true` permits watching a private repo **only** when `token_for_repo(repo)` resolves a matching token (unmatched orgs/private repos still fail closed!).
- **Optional `<1s` GitHub App webhooks**: Setting `appWebhookSecret` enables HMAC-verified `POST /v1/webhooks/github-app` (returns `404` when unconfigured, `401` on invalid `X-Hub-Signature-256`).

### B. `github-webhook`, `prometheus-webhook` & `webhook-stream` (`crates/hyp-node/src/adapters/webhooks.rs`)

Pure-Rust normalizers verify HMAC-SHA256 / bearer tokens in constant time (`ring::hmac`) and emit normalized CloudEvents v1.0:
- **GitHub (`com.github.*`)**: Attributes `repo` (`"owner/repo"`), `source` (`"github.com/owner/repo"`), `type` (`"com.github.pull_request.opened"`, etc.), `action`, `actor`, and `subject` (`"pull/<n>"`, `"issues/<n>"`, `"actions/runs/<id>"`, `"refs/heads/<branch>"`).
- **Prometheus Alertmanager v4**: Emits one CloudEvent per alert (`io.prometheus.alert.firing` / `io.prometheus.alert.resolved`) with `alertname`, `severity`, `service`, and `subject: "severity=<severity>/<alertname>"`.
- **Generic Webhook**: Optional constant-time HMAC-SHA256 verification and CloudEvents v1.0 pass-through/wrapping.

### C. `localIngest` — Default Socket-Only Local Event Ingest Route (`ingest.sock` & `hyp emit`)

Compiled directly into `hyp` (`crates/hyp-node/src/engine/local_ingest.rs`) and **enabled by default** with zero extra MCP tools, the socket-only Local Ingest Route lets local scripts and OS schedulers (`systemd-run --user`, `crontab`, `launchd`, `schtasks`) push structured CloudEvents v1.0 (or compact JSON shorthand) onto `local.schedule` (default) or any configured `local.<topic>` — with **zero FIFO pipes**, strict local permissions, declarative route filters, rate limiting, Security Gate screening, and optional Ed25519 signature verification. See [skills/hyphae-schedule/SKILL.md](../skills/hyphae-schedule/SKILL.md) for agent recipes.

- **Socket-only transport & DoS bounds**: Listens on `~/.config/hyphae/state/ingest.sock` (`0600` Unix domain socket inside `0700` dir) on macOS/Linux, or loopback `127.0.0.1` TCP + `0600` `<state_dir>/ingest.addr` protected by a constant-time 32-byte CSPRNG bearer token on Windows. Enforces 64 KiB max NDJSON lines, 5 s read timeout, and 64 max concurrent connections.
- **Declarative policy (`localIngest` in `node.json`)**: If omitted, Hyphae activates a built-in default route accepting `to.hyphae.scheduled.v1` and `to.hyphae.local.v1` on `["schedule", "local"]` (`maxPerMinute: 30`, `burst: 10`, `onLimit: "drop"`, `maxPayloadBytes: 32768`, `gate: true`, `requireSignature: false`). Override or add stricter routes declaratively:

```json
{
  "localIngest": {
    "enabled": true,
    "defaultTopic": "schedule",
    "routes": [
      {
        "id": "signed-ops",
        "allowedTypes": ["to.hyphae.scheduled.v1"],
        "allowedTopics": ["schedule"],
        "filters": [{ "prefix": { "label": "prod-" } }],
        "maxPerMinute": 10,
        "burst": 3,
        "onLimit": "coalesce",
        "maxPayloadBytes": 32768,
        "gate": true,
        "requireSignature": true
      },
      {
        "id": "default-schedule",
        "allowedTypes": ["to.hyphae.scheduled.v1", "to.hyphae.local.v1"],
        "allowedTopics": ["schedule", "local"],
        "filters": [],
        "maxPerMinute": 30,
        "burst": 10,
        "onLimit": "drop",
        "maxPayloadBytes": 32768,
        "gate": true,
        "requireSignature": false
      }
    ]
  }
}
```

- **2-step scheduling flow for agents & OS triggers**:
  1. Subscribe using the standard **`hyp_stream`** MCP tool:
     ```json
     hyp_stream({
       "action": "subscribe",
       "topic": "local.schedule",
       "filters": [{ "exact": { "label": "check-ci" } }],
       "urgency": "interrupt"
     })
     ```
  2. Emit via **`hyp emit`** from any OS scheduler or write NDJSON directly to `ingest.sock`:
     ```sh
     # One-shot Linux (systemd-run --user)
     systemd-run --user --on-active=15m -- hyp emit --label check-ci --note "Verify build"

     # Recurring Unix (crontab -e)
     0 9 * * 1-5 $HOME/.local/bin/hyp emit --label morning-triage --note "Review open PRs"

     # Windows Task Scheduler (schtasks)
     schtasks /Create /SC DAILY /TN "HyphaeMorningTriage" /ST 09:00 /TR "hyp emit --label morning-triage --note \"Review open PRs\""

     # Raw Unix socket NDJSON (zero CLI spawn)
     printf '{"type":"to.hyphae.scheduled.v1","label":"check-ci","note":"Done"}\n' \
       | nc -U ~/.config/hyphae/state/ingest.sock

     # Optional Ed25519-signed trigger (attaches hyphaesig -> TrustTier::HumanVerified)
     hyp emit --sign --label prod-rollout --note "Start canary"
     ```
- **Signature verification & Security Gate**: Whenever an inbound event carries the `hyphaesig` CloudEvents extension (`ed25519:<kid>:<b64url>`), it is **always** verified fail-closed against active `human_authorities` and upgrades the event to `TrustTier::HumanVerified` (writing an immutable `gate_audit` row). Routes with `requireSignature: true` reject unsigned events fail-closed. With `gate: true`, all matching events pass through `SecurityGatePipeline` before publishing onto `local.<topic>`.
- **Rate limiting (`onLimit`)**: `"drop"` rejects excess bursts (`rate_limited`); `"coalesce"` collapses saturated bursts under a shared mailbox coalesce key.
- **Inherited Tier 1–3 delivery ladder (+ opt-in Tier 4 revival)**:
  1. **Tier 1 / 2 (Native push)**: Delivers immediately to live sessions via `hc send`/`hc interrupt`, T3 RPC, `codex queue`, hooks, `--claude-channel`, or `hyp wait`.
  2. **Tier 3 (Busy `Hold` backoff & durable mailbox)**: Busy turns enter bounded retry backoff (`5s -> 15s -> 30s -> 60s`), cancelled immediately if a hook drains first, and coalesce cleanly in the durable local mailbox with TTL.
  3. **Tier 4 (Strictly opt-in cold revival)**: Offline sessions are never spawned unexpectedly unless explicitly opted in via `node.json` (`codexResume` or allowlisted `herdrSpawnAllowlist`).

### Subscribing from Any Agent (`hyp_stream`)

Agents inspect topics and subscribe with CloudEvents Subscriptions API v1.0 filters (pushed down to upstream nodes so non-matching events never cross the wire, and evaluated locally for `local.schedule` / `local.<topic>`):

```json
hyp_stream({ "action": "topics" })

hyp_stream({
  "action": "subscribe",
  "topic": "local.schedule",
  "filters": [{ "exact": { "label": "check-ci" } }],
  "urgency": "interrupt"
})

hyp_stream({
  "action": "subscribe",
  "key": "gh:checkout",
  "topic": "public.hyphae.to.github",
  "filters": [{ "exact": { "repo": "owner/repo" } }],
  "mode": "queue",
  "coalesceSeconds": 15,
  "strict": true
})

hyp_stream({
  "action": "subscribe",
  "key": "prom:critical",
  "topic": "acme-team.alerts",
  "filters": [{ "prefix": { "subject": "severity=critical" } }],
  "mode": "interrupt"
})
```

*(For GitHub streams, always filter on `repo` or `source`, **not** `subject`; `strict: true` fails closed on unreachable or misconfigured filters.)*

---

## 4. Optional External Chat Bridges (`plugins/`)

External scripts under `plugins/` run as optional child processes managed by the unified Rust `SubprocessSupervisor` (`crates/hyp-node/src/adapters/supervisor.rs`) over an anonymous duplex Unix socketpair duped onto **fd 3**:

- **Scrubbed environment**: Inherits only `PATH`, `HOME`, `TMPDIR`, `LANG`, `XDG_RUNTIME_DIR`, and `DBUS_SESSION_BUS_ADDRESS` plus explicitly configured env vars/secrets and protocol headers (`HYPHAE_FD=3`, `HYPHAE_PLUGIN=<id>`, `HYPHAE_PROTOCOL=2`).
- **Bounded framing & resilience**: Strict 64 KiB `LineSplitter`, exponential restart backoff (`1s -> 60s`), and clean `SIGTERM -> SIGKILL` shutdown.
- **Dual wire protocol auto-detection**: Speaks **JSON-RPC 2.0 v2** (`hyphae/hello`, `hyphae/publish`, `hyphae/post`, `hyphae/status`, `hyphae/deliveryFailed`) and automatically detects unmodified **legacy fd-3 v1** plugins (`hello`, `event`, `ack`, `nack`, `request`, `response`, `status`, `delivery_failed`).

### Managing Bridges from MCP (`hyp_bridge` + `hyp_send`)

When local bridges are enabled, the conditional `hyp_bridge` tool is advertised alongside the 4 core tools (0 schema tokens otherwise):

- **List linked targets**: `hyp_bridge({ action: "targets" })`
- **Multi-thread fan-in link/unlink**: `hyp_bridge({ action: "link", plugin: "slack", target: "pm" })` / `hyp_bridge({ action: "unlink", plugin: "slack", target: "pm" })` (also accepts `"target": "slack:pm"` shorthand)
- **Live primary handoff**: `hyp_bridge({ action: "handoff", plugin: "slack", target: "pm", handle: "codex-pm" })`
- **Outbound reply**: `hyp_send({ to: "slack:pm", text: "Fix PR #412 is green.", replyTo: "1732435200.000100" })`

### Installing, Updating & Verifying Official Plugins & Harness Mods (`hyp plugin`)

You do **not** need to clone the Hyphae git repository to install or update official bridges or harness UI mods. To keep the static `hyp` binary 100% pure Rust (zero embedded JS/TS/TSX/SVG/PNG assets), every tagged GitHub Release publishes a single self-contained POSIX `ustar` archive **`hyp-vX.Y.Z-plugins.tar.gz`** (and **`hyp-nightly-plugins.tar.gz`** on the rolling `nightly` release) together with **`plugins-manifest.json`**, included in `SHA256SUMS.txt` and covered by the Ed25519-signed `release-manifest.json`:

- **Bridges & SDK (`kind: "bridge"`)**: `sdk` (`sdk/client.mjs`, `sdk/client.py`), `telegram`, `slack`, `whatsapp`, `webhook`, `prometheus` -> installed under `~/.config/hyphae/plugins/` (`0700`/`0600`).
- **Harness UI mods & plugins (`kind: "harness"`)**:
  - `claude-panel` (`claude-code/hooks/{register.tsx,state.ts}` + minimal UI-only `.claude-plugin/plugin.json` & `hooks/hooks.json`) -> installed into `~/.claude/skills/hyphae-panel/` (and `$CLAUDE_CONFIG_DIR/skills/hyphae-panel/`, symlink-safe).
  - `claude-code` (full 12-file Claude Code plugin bundle including raw-hashed binary `icon.png`) -> installed under `~/.config/hyphae/plugins/claude-code/`.
  - `herdr-mod` (`hyphae-pane` + `hyphae-panel` GPUI mods, 9 files) -> installed as real directories under `~/.config/herdr-app/mods/` (FSEvents hot-reload friendly; never touches `keys.json` or custom/symlinked layouts unless run via `hyp setup --harness herdr --mod`).

The `hyp` binary pins only per-file SHA-256 digests (LF-normalized for text files, raw bytes for binary `.png`) and deterministic per-plugin `treeSha256` digests at compile time (`crates/hyp-cli/build.rs`). Every install or update resolves sources in strict precedence order and verifies every required file in constant time **before writing a single byte**:

1. `--archive <path>` / `HYPHAE_PLUGINS_ARCHIVE`
2. `--from-dir <path>` / `HYPHAE_PLUGINS_DIR`
3. Local verified tarball cache (`~/.config/hyphae/plugins-cache/hyp-vX.Y.Z-plugins.tar.gz`, `0600`)
4. HTTPS release asset (`https://github.com/hyphae-to/hyp/releases/download/vX.Y.Z/hyp-vX.Y.Z-plugins.tar.gz`) — saved into the local cache only after constant-time verification succeeds.

Installed plugins record receipts in `~/.config/hyphae/plugins/installed.json` (`0600`). Comparing **on-disk hash (`disk`)**, **receipt hash (`installed`)**, and **binary pinned hash (`pinned`)** powers safe selective updates:

| Condition | Status | `hyp plugin update` Behavior |
| --- | --- | --- |
| `disk == pinned` | `up_to_date` | Skips immediately (**0 network calls, 0 disk writes**) |
| `disk == installed && disk != pinned` | `outdated` | Downloads/reads archive at most once, verifies SHA-256, updates only changed plugins atomically |
| `disk != pinned && (!installed \|\| disk != installed)` | `modified` | **Refuses to overwrite** by default (protects local edits & pre-receipt legacy installs); requires `--force` |
| Missing file / symlink tampered | `corrupt` | Fails closed in `hyp plugin verify` & `hyp doctor`; repair with `hyp plugin install <name> --force` |

```sh
# List all official bridges & harness mods with three-way status (`up_to_date`, `outdated`, `modified`, `corrupt`, `not_installed`)
hyp plugin list --json

# Download, verify, and atomically install one plugin/mod (or `all`)
hyp plugin install telegram --json
hyp plugin install claude-panel --json
hyp plugin install herdr-mod --json
hyp plugin install all --json

# Selectively update only outdated installed plugins & harness mods (0 downloads if up to date)
hyp plugin update --all --dry-run --json
hyp plugin update --all --json
hyp plugin update telegram --force --json   # overwrite a locally modified plugin explicitly

# Air-gapped / offline verification from a downloaded release tarball or local checkout
hyp plugin install telegram --archive ./hyp-v0.6.2-plugins.tar.gz --json
hyp plugin install herdr-mod --from-dir ./plugins --json

# Re-verify installed plugins & harness mods against compile-time pinned SHA-256 digests
# (exits 1 if any file is tampered, outdated, or missing)
hyp plugin verify --json
hyp plugin verify telegram --json

# Remove one installed plugin/mod (automatically removes sdk/ when the last bridge is removed) or `all`
hyp plugin remove telegram --json
hyp plugin remove all --json
```

> **Automatic post-upgrade sync & diagnostics:** `hyp update` automatically runs `<new_hyp> plugin update --all --json` after replacing the binary (pass `--no-plugins` to skip; non-fatal if offline). `hyp doctor` reports `OK` / `WARN` / `FAIL` checks for every installed bridge and harness mod.
>
> **Never point `node.json` `plugins[]` at a local git checkout.** Always run `hyp plugin install <name> --json` and wire `node.json` using the returned `data.nodePath` and `data.plugins[0].scriptPath` (`~/.config/hyphae/plugins/<name>/index.mjs`).

### Included Optional External Scripts (`plugins/`)

All included `.mjs` scripts have zero external npm dependencies (**requires Node 24+ on macOS/Linux**; fd-3 subprocess bridges are Unix-only):

| Script | Kind | Protocol / Transport | Required Fail-Closed Allowlist / Auth Env Vars |
| --- | --- | --- | --- |
| [plugins/slack/index.mjs](../plugins/slack/index.mjs) | `bridge` | Slack Socket Mode (WebSocket, no public port needed) + `chat.postMessage` | `SLACK_APP_TOKEN`, `SLACK_BOT_TOKEN`, `SLACK_ALLOWED_USERS` / `SLACK_ALLOWED_CHANNELS` |
| [plugins/telegram/index.mjs](../plugins/telegram/index.mjs) | `bridge` | Telegram Bot API long polling + `sendMessage` | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_ALLOWED_USERS` / `TELEGRAM_ALLOWED_CHATS` *(numeric IDs)* |
| [plugins/whatsapp/index.mjs](../plugins/whatsapp/index.mjs) | `bridge` | Meta WhatsApp Business Cloud API webhook (`X-Hub-Signature-256`) + Graph API | `WHATSAPP_VERIFY_TOKEN`, `WHATSAPP_APP_SECRET`, `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_ALLOWED_NUMBERS` |
| [plugins/webhook/index.mjs](../plugins/webhook/index.mjs) | `source` | Local HTTP webhook receiver (`X-Webhook-Signature-256`) + optional `WEBHOOK_POST_URL` | `WEBHOOK_PORT`, `WEBHOOK_SECRET`, optional `WEBHOOK_POST_URL` |
| [plugins/prometheus/index.mjs](../plugins/prometheus/index.mjs) | `source` | Standalone Alertmanager v4 webhook script (when not using compiled-in Rust adapter) | `PROMETHEUS_PORT`, `PROMETHEUS_BEARER_TOKEN` and/or `PROMETHEUS_WEBHOOK_SECRET` |

### Example `plugins[]` Configuration (`~/.config/hyphae/node.json`)

Install the verified plugins first (`hyp plugin install telegram --json`, `hyp plugin install slack --json`), store tokens out-of-band (`hyp secret set telegram-bot-token --web`, `hyp secret set slack-app-token --web`, `hyp secret set slack-bot-token --web`), then wire `node.json` using the returned `data.nodePath` and `data.plugins[0].scriptPath`:

```json
{
  "plugins": [
    {
      "id": "telegram",
      "command": "/opt/homebrew/bin/node",
      "args": ["/Users/you/.config/hyphae/plugins/telegram/index.mjs"],
      "targets": ["personal"],
      "env": {
        "TELEGRAM_BOT_TOKEN": { "secret": "telegram-bot-token" },
        "TELEGRAM_ALLOWED_USERS": "123456789",
        "TELEGRAM_DEFAULT_CHAT": "123456789",
        "TELEGRAM_STATE_FILE": "/Users/you/.config/hyphae/state/telegram-offset.json"
      }
    },
    {
      "id": "slack",
      "command": "/opt/homebrew/bin/node",
      "args": ["/Users/you/.config/hyphae/plugins/slack/index.mjs"],
      "targets": ["pm"],
      "env": {
        "SLACK_APP_TOKEN": { "secret": "slack-app-token" },
        "SLACK_BOT_TOKEN": { "secret": "slack-bot-token" },
        "SLACK_ALLOWED_USERS": "U0123456789"
      }
    }
  ]
}
```

After saving `node.json`, restart the daemon and refresh skills so harnesses see `hyp_bridge`:

```sh
hyp service restart
hyp setup --refresh-skills
```

*(A misconfigured bridge logs a startup warning without taking down the local agent mesh daemon.)*

---

## 5. Writing a Custom Subprocess Plugin (JSON-RPC 2.0 v2 or fd-3 v1)

Any language that can read/write newline-delimited JSON (≤ 64 KiB/line) on fd 3 works directly.

### Option A: JSON-RPC 2.0 over fd 3 (`HYPHAE_PROTOCOL=2`, recommended for new plugins)

- Host <-> Plugin notifications & requests on fd 3:
  - `hyphae/hello` (notification: `{ protocol: 2, plugin, targets }`)
  - `hyphae/publish` (request from plugin: `{ target, event: <CloudEvent v1.0> }` -> JSON-RPC result `{ status: "stored" | "duplicate" }`)
  - `hyphae/post` (request from host to plugin: `{ target, params: { text, replyTo?, ... } }` -> JSON-RPC result `{ ... }`)
  - `hyphae/status` & `hyphae/deliveryFailed` (notifications)

### Option B: Bundled Zero-Dependency fd-3 v1 SDKs

Use [plugins/sdk/client.mjs](../plugins/sdk/client.mjs) (Node) or [plugins/sdk/client.py](../plugins/sdk/client.py) (Python 3 stdlib) — `SubprocessSupervisor` auto-detects v1 framing automatically:

```js
#!/usr/bin/env node
import { MeshPluginClient } from "./plugins/sdk/client.mjs";

const mesh = new MeshPluginClient();
const { targets } = await mesh.ready;

mesh.onPost(async ({ target, text, replyTo }) => {
  // Dispatch outbound reply to your external service
  return { delivered: true, target };
});

await mesh.send(targets[0], {
  specversion: "1.0",
  id: crypto.randomUUID(),
  source: "my-plugin/local",
  type: "com.example.ping",
  datacontenttype: "application/json",
  data: { text: "hello from custom plugin" },
});
```

Exit cleanly when fd 3 reaches EOF.
