# Event Sources, External Chat Bridges & Secrets

> **Looking for a focused guide?** See [Events & OS Cron](guides/events-and-cron.md), [Chat Bridges (Beta)](guides/chat-bridges.md), [Phone Drops & `hyp exec`](guides/phone-drops.md), or the [Plugin SDK Reference](reference/plugin-sdk.md). This page remains the consolidated quick-reference for `hyp plugin` and `node.json` `sources[]` / `plugins[]` configuration.

Hyphae unifies event sources and chat bridges onto the single Rust `Node` CloudEvents v1.0 bus (`node.sqlite`) via `NodeAdapter` (`crates/hyp-node/src/adapters/`), separating **compiled-in pure-Rust event source adapters** from **optional external chat bridge scripts** in `plugins/`.

> **Zero runtime dependency for core `hyp`:** The self-contained Rust `hyp` binary requires **no** Node.js or Python runtime. Scripts under `plugins/` are **optional external subprocesses** (Node or Python) supervised natively over duplex Unix fd 3 (macOS/Linux) or authenticated loopback TCP (Windows) — you only need Node or Python installed if you opt in to running those specific external bridge scripts.

---

## 1. Architecture: Compiled-In Sources vs. External Bridges

| Layer | Implementation | Routing Model | Secrets Location | Best For |
| --- | --- | --- | --- | --- |
| **Compiled-In Rust Event Sources & Local Ingest** (`crates/hyp-node/src/adapters/`, `engine/local_ingest.rs`) | Pure Rust wired directly into `hyp node start` (`github-public`, `github-webhook`, plus default-enabled socket-only `localIngest` on `ingest.sock` / `ingest.addr`) — zero Node/Python needed | **1-to-many Pub/Sub** via standard `hyp_stream` with server-side CloudEvents filter pushdown (including `local.schedule` / `local.<topic>` triggered via `hyp emit` or raw NDJSON) | Node's `SecretStore` (`{ "secret": "<name>" }` in `node.json`) | Public or org **GitHub** streams (`github-public` ETag poller + `github-webhook`) and OS-scheduled **Local Ingest & Cron triggers** |
| **External Subprocess Bridges & Custom Sources** (`plugins/`) | Optional self-contained scripts (`plugins/slack`, `plugins/telegram`, `plugins/whatsapp`, `plugins/webhook`, `plugins/prometheus`, or custom executables) supervised by `SubprocessSupervisor` (Unix fd 3 / Windows loopback TCP) | **Thread-owned + multi-thread fan-in + outbound replies** via `hyp_bridge` and `hyp_send({ to: "<plugin>:<target>", text })`; bridge topics stay **local-only by default** (`exposeTopic: true` opt-in) | Local machine's `SecretStore` — scrubbed subprocess env, never sent to remote hubs | Personal **Slack / Telegram / WhatsApp** bridges, local callbacks, and custom scripts in any language |

---

## 2. Secrets Management (`hyp secret`) & Scoped Execution (`hyp exec`)

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

# Run a user command with stored app secrets injected into child env + streaming stdout/stderr redaction
# (blocks Hyphae system keys, node.json secrets, and dangerous loader env vars):
hyp exec --env STRIPE_API_KEY=stripe-key -- ./scripts/check-billing.sh

# Remove an unused secret:
hyp secret delete old-token
```

Reference secrets in core `node.json` fields strictly as `{ "secret": "<name>" }` (and strongly recommended for `plugins[].env`, where plaintext secret-like env values emit a startup warning).

---

## 3. Compiled-In Rust Event Sources (`sources[]` in `node.json`)

### Choosing GitHub Ingestion: Webhook (`github-webhook`) vs. Polling (`github-public`)

Pick the transport that matches your node topology:

| Mode | Best Node Topology | Latency | Event Coverage | Auth / Secrets |
| --- | --- | --- | --- | --- |
| **Webhook (`github-webhook`) — Recommended whenever possible** | **Hub / Server Node (`profile: router`)** on a VPS, Fly.io, Docker + Caddy, Cloudflare Tunnel, or Tailscale Funnel | Real-time (`<1–2s`) | **All GitHub events**, including live CI pass/fail (`workflow_run`, `check_run`) and full payloads | **Zero GitHub PAT** — shared HMAC-SHA256 webhook secret only (`X-Hub-Signature-256`) |
| **Polling (`github-public` + `repoTokens`) — Zero-infra NAT fallback** | **Local Node (`profile: local`)** on a laptop behind NAT (or public read-only node) with no public webhook URL | ~30s avg / 60s max (`304 Not Modified` uses 0 quota) | Repo activity only (pushes, PRs, issues, comments, reviews, releases) — **GitHub's `/events` API does NOT emit `workflow_run` / `check_run` CI events** | Optional per-owner/per-repo fine-grained PATs via `repoTokens` (5,000 req/hr per owner token; 60 req/hr unauthenticated for public repos) |

> **Rule of thumb:** **Hub Nodes (`profile: router`) are the natural place to terminate `github-webhook` deliveries** once and fan normalized CloudEvents out over E2EE streams to every paired laptop. Use **`github-public` + `repoTokens`** as the zero-infra fallback on a **Local Node (`profile: local`)** behind NAT when you don't have (or don't want to expose) a hub or public HTTPS endpoint yet.

### A. `github-public` — Demand-Driven Deduplicated ETag Poller with Multi-Owner `repoTokens`

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
      }
    }
  ]
}
```

- **Strict token scoping & precedence**: For each `owner/repo`, Hyphae resolves the token in strict specificity order: (1) exact `owner/repo` in `repoTokens`, (2) owner wildcard `owner/*` in `repoTokens` (bare `owner` also normalizes to `owner/*`), (3) optional fallback `githubToken`, (4) `None` (unauthenticated public mode — zero `Authorization` header sent). Invalid or overly broad patterns (`*`, `*/*`, `..`, empty) and raw plaintext strings fail closed at startup. Missing secrets in `repoTokens` emit an isolated startup warning without crashing the daemon or blocking already-configured owners.
- **Single `github-public` source**: Consolidate all GitHub tokens into `sources[0].repoTokens`; if multiple enabled `github-public` entries exist, only the first is active and Hyphae emits a startup warning.
- **1 poller per distinct `owner/repo` + bounded rate-limit hardening**: Regardless of subscriber count, conditional `If-None-Match` polls returning `304 Not Modified` consume **0** GitHub API quota, adaptively back off on idle repos, enforce bounded backoff on HTTP `403`/`429` (`Retry-After` and `X-RateLimit-Remaining: 0` + `X-RateLimit-Reset`), cap concurrent active pollers at `maxActivePollers` (default `100`), and tear down after `graceWindowSeconds` when active subscribers drop to `0`.
- **Private repo access**: On non-`publicReadOnly` local/private nodes, setting `"allowPrivateWithToken": true` permits watching a private repo **only** when `token_for_repo(repo)` resolves a matching token (unmatched orgs/private repos still fail closed!).

### B. GitHub repository webhooks

The `github-webhook` source runs inside `hyp` and verifies `X-Hub-Signature-256` with the configured SecretStore reference. For repository events, `repository.full_name` must contain exactly two nonempty GitHub slug segments. Dot segments are invalid. When supplied, `repository.owner.login` must match the owner segment case-insensitively. `allowedRepos` matches whole repository slugs and `allowedOrgs` matches whole owner segments, both case-insensitively. A repository-free `ping` is accepted only with no repository or organization allowlist. Normalized repository events carry `repo`, `source`, `type`, `action`, `actor`, and `subject`.

#### Repository webhook setup

1. Add a `github-webhook` source to `node.json`. Give it a unique `id`, set `allowedRepos` to the repository slug, and use a private topic such as `github-webhooks`. Limit subscription grants on that topic to the intended peers.
2. Store a unique shared secret with `hyp secret set github-webhook-secret --web` on the node that runs the receiver. Reference it as `"secret": { "secret": "github-webhook-secret" }` and restart the node.
3. Expose `POST /v1/webhooks/github/<id>` through your public HTTPS proxy or tunnel. Route only the webhook endpoint if the node also serves private peer or admin routes.
4. In the repository's **Settings → Webhooks → Add webhook**, enter the public payload URL, for example `https://hooks.example.com/v1/webhooks/github/org-github`. Choose **application/json**, enter the same secret, and select the events to deliver. Check **Recent Deliveries** to verify GitHub reached the receiver.

#### Webhook plugin migration

`webhook` and `prometheus` handle generic signed webhooks and Alertmanager v4. On the receiver host, install the release-matched plugins with `hyp plugin install webhook --json` or `hyp plugin install prometheus --json`. The output supplies `data.nodePath` and `data.plugins[0].scriptPath` for `command` and `args`.

```json
{
  "plugins": [
    {
      "id": "ci-events",
      "kind": "source",
      "command": "<nodePath>",
      "args": ["<webhook scriptPath>"],
      "targets": ["ci"],
      "env": {
        "WEBHOOK_SECRET": { "secret": "ci-webhook-secret" },
        "WEBHOOK_LEGACY_NATIVE": "1"
      }
    },
    {
      "id": "prom-alerts",
      "kind": "source",
      "command": "<nodePath>",
      "args": ["<prometheus scriptPath>"],
      "targets": ["alerts"],
      "env": {
        "PROMETHEUS_BEARER_TOKEN": { "secret": "prometheus-bearer-token" },
        "PROMETHEUS_LEGACY_NATIVE": "1"
      }
    }
  ]
}
```

Use the old source topic as the plugin target to keep subscriptions. Remove the retired `webhook-stream` or `prometheus-webhook` entry from `sources[]`. The node skips old entries and reports a migration warning at startup. Keep plugin topics local by default. On a team hub, set `exposeTopic: true` only when the intended peers already have or need grants for that private topic.

| Former native setting | Plugin environment |
| --- | --- |
| Generic `secret`, `signatureHeader`, `maxBodyBytes` | `WEBHOOK_SECRET`, `WEBHOOK_SIGNATURE_HEADER`, `WEBHOOK_MAX_BODY_BYTES` |
| Generic `defaultSource`, `defaultType` | `WEBHOOK_SOURCE`, `WEBHOOK_EVENT_TYPE` |
| Alertmanager `bearerToken`, `webhookSecret`, `maxBodyBytes` | `PROMETHEUS_BEARER_TOKEN`, `PROMETHEUS_WEBHOOK_SECRET`, `PROMETHEUS_MAX_BODY_BYTES` |
| Alertmanager `basicAuth` | `PROMETHEUS_BASIC_AUTH` references a SecretStore entry whose value is `username:password` |

Use the migration flags shown above for existing sources. They preserve native event IDs and the generic native CloudEvents pass-through contract. New plugin entries can omit them. Retain signature and timestamp headers when forwarding.

The default loopback targets are `http://127.0.0.1:8795/webhook` and `http://127.0.0.1:8793/alerts`. Set `WEBHOOK_PORT` / `WEBHOOK_PATH` or `PROMETHEUS_PORT` / `PROMETHEUS_PATH` when running multiple receivers. Update the sender or proxy to reach the new listener. For public callbacks, use [webhook routing setup](operations/deploying.md#public-webhook-routing) to preserve the existing HTTPS path or choose a new one. Send an authenticated test delivery and verify the event reaches the existing topic.

### C. `localIngest` — Default Socket-Only Local Event Ingest Route (`ingest.sock` & `hyp emit`)

Compiled directly into `hyp` (`crates/hyp-node/src/engine/local_ingest.rs`) and **enabled by default** with zero extra MCP tools, the socket-only Local Ingest Route lets local scripts and OS schedulers (`systemd-run --user`, `crontab`, `launchd`, `schtasks`) push structured CloudEvents v1.0 (or compact JSON shorthand) onto `local.schedule` (default) or any configured `local.<topic>` — with **zero FIFO pipes**, strict local permissions, declarative route filters, rate limiting, Security Gate screening, and optional Ed25519 signature verification. See [skills/hyp-schedule/SKILL.md](../skills/hyp-schedule/SKILL.md) for agent recipes.

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

     # Optional Ed25519-signed trigger (interactive TTY confirm; attaches hyphaesig -> TrustTier::HumanVerified)
     hyp emit --sign --label prod-rollout --note "Start canary"
     ```
- **Signature verification & Security Gate**: Whenever an inbound event carries the `hyphaesig` CloudEvents extension (`ed25519:<kid>:<b64url>`), it is **always** verified fail-closed against active `human_authorities` and upgrades the event to `TrustTier::HumanVerified` (writing an immutable `gate_audit` row). Routes with `requireSignature: true` reject unsigned events fail-closed. With `gate: true`, all matching events pass through `SecurityGatePipeline` before publishing onto `local.<topic>`.
- **Rate limiting (`onLimit`)**: `"drop"` rejects excess bursts (`rate_limited`); `"coalesce"` collapses saturated bursts under a shared mailbox coalesce key.
- **Inherited Tier 1–3 delivery ladder (+ opt-in Tier 4 revival)**:
  1. **Tier 1 / 2 (Native push)**: Delivers immediately to live sessions via `hc send`/`hc interrupt`, T3 RPC, `codex queue`, OpenClaw Gateway hooks, OpenCode lifecycle hooks, Claude Code channel notices, or `hyp wait`.
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

External scripts under `plugins/` run as optional child processes managed by the unified cross-platform Rust `SubprocessSupervisor` (`crates/hyp-node/src/adapters/supervisor.rs`) over an anonymous duplex Unix socketpair duped onto **fd 3** (macOS/Linux) or an authenticated single-accept loopback TCP channel (`127.0.0.1:0` + per-spawn 256-bit CSPRNG token on Windows):

- **Scrubbed environment**: Inherits only safe OS runtime paths (`PATH`, `HOME`, `TMPDIR`, `LANG`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, plus Windows OS/temp/profile paths on Windows) plus explicitly configured env vars/secrets and protocol headers (`HYPHAE_FD=3` on Unix or `HYPHAE_PLUGIN_TRANSPORT=tcp` / `HYPHAE_PLUGIN_ADDR` / `HYPHAE_PLUGIN_TOKEN` on Windows, along with `HYPHAE_PLUGIN=<id>` and `HYPHAE_PROTOCOL=2`). Plaintext secret-like values in `plugins[].env` (instead of `{ "secret": "<name>" }`) emit a startup warning without logging the secret.
- **Local-only bridge topics by default (`exposeTopic: true` opt-in)**: Topics emitted by local chat bridges (`slack`, `telegram`, `whatsapp`, `webhook`) are kept strictly local by default — paired remote peers (even holding `stream:subscribe=*`) never see them in `/v1/manifest` and cannot subscribe to them unless the operator explicitly sets **`"exposeTopic": true`** on that entry in `plugins[]` (or lists the topic explicitly in `topics[]`).
- **Bounded framing, crash-loop circuit breaker & secret-redacted logs**: Enforces a strict 64 KiB `LineSplitter`, exponential restart backoff (`1s -> 60s`), and clean `SIGTERM -> SIGKILL` shutdown. After **5 consecutive rapid crashes**, the circuit breaker trips into **`CrashLoopBackOff`** (`status: "crash_loop_backoff"` in `node.status.json` and `hyp doctor`), stopping runaway respawns while keeping the rest of the daemon up. Subprocess stderr is captured into **`<state_dir>/logs/plugin-<id>.log`** with user-only **`0600`** permissions and automatic secret redaction (`[REDACTED]`).
- **One deterministic wire protocol**: Speaks **JSON-RPC 2.0 v2** (`hyphae/hello`, `hyphae/publish`, `hyphae/post`, `hyphae/status`, `hyphae/deliveryFailed`). The host sends its hello immediately after transport authentication. Legacy v1 frames are rejected; migrate custom plugins to the bundled v2 SDKs.

### Managing Bridges from MCP (`hyp_bridge` + `hyp_send`)

When local bridges are enabled, the conditional `hyp_bridge` tool is advertised alongside the 4 core tools (0 schema tokens otherwise):

- **List linked targets**: `hyp_bridge({ action: "targets" })`
- **Multi-thread fan-in link/unlink**: `hyp_bridge({ action: "link", plugin: "slack", target: "pm" })` / `hyp_bridge({ action: "unlink", plugin: "slack", target: "pm" })` (also accepts `"target": "slack:pm"` shorthand)
- **Live primary handoff**: `hyp_bridge({ action: "handoff", plugin: "slack", target: "pm", handle: "codex-pm" })`
- **Outbound reply**: `hyp_send({ to: "slack:pm", text: "Fix PR #412 is green.", replyTo: "1732435200.000100" })`

### Installing, Updating & Verifying Official Plugins & Harness Mods (`hyp plugin`)

You do **not** need to clone the Hyphae git repository to install or update official bridges or harness UI mods. To keep the `hyp` binary 100% pure Rust (zero embedded JS/TS/TSX/SVG/PNG assets), every tagged GitHub Release publishes a single self-contained POSIX `ustar` archive **`hyp-vX.Y.Z-plugins.tar.gz`** (and **`hyp-nightly-plugins.tar.gz`** on the rolling `nightly` release) together with **`plugins-manifest.json`**, included in `SHA256SUMS.txt` and covered by the Ed25519-signed `release-manifest.json`:

- **Bridges & SDK (`kind: "bridge"`)**: `sdk` (`sdk/client.mjs`, `sdk/client.py`), `telegram`, `slack`, `whatsapp`, `webhook`, `prometheus` -> installed under `~/.config/hyphae/plugins/` (`0700`/`0600`).
- **Harness UI mods & plugins (`kind: "harness"`)**:
  - `claude-panel` (`claude-code/hooks/{register.tsx,state.ts}` + minimal UI-only `.claude-plugin/plugin.json` & `hooks/hooks.json`) -> installed into `~/.claude/skills/hyp-panel/` (and `$CLAUDE_CONFIG_DIR/skills/hyp-panel/`, symlink-safe).
  - `claude-code` (full 12-file Claude Code plugin bundle including raw-hashed binary `icon.png`) -> installed under `~/.config/hyphae/plugins/claude-code/`.
  - `herdr-mod` (`hyphae-pane` + `hyphae-panel` GPUI mods, 9 files) -> installed as real directories under `~/.config/herdr-app/mods/` (FSEvents hot-reload friendly; never touches `keys.json` or custom/symlinked layouts unless run via `hyp setup --harness herdr --mod`).
  - `herdr-status` installs an optional Shared KV publisher under the node's plugins directory. Use the [publisher setup guide](../plugins/herdr-status/README.md) to bind and start it explicitly.

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
hyp plugin install telegram --archive ./hyp-v0.7.0-plugins.tar.gz --json
hyp plugin install herdr-mod --from-dir ./plugins --json

# Re-verify installed plugins & harness mods against compile-time pinned SHA-256 digests
# (exits 1 if any file is tampered, outdated, or missing)
hyp plugin verify --json
hyp plugin verify telegram --json

# Remove one installed plugin/mod or `all`
# (automatically cleans matching `plugins[]` entries in `node.json` and removes `sdk/` when the last bridge is removed;
#  pass `--keep-config` to preserve `node.json` entries)
hyp plugin remove telegram --json
hyp plugin remove telegram --keep-config --json
hyp plugin remove all --json
```

> **Automatic post-upgrade sync & diagnostics:** `hyp update` automatically runs `<new_hyp> plugin update --all --json` after replacing the binary (pass `--no-plugins` to skip; non-fatal if offline). `hyp doctor` reports `OK` / `WARN` / `FAIL` checks for every installed bridge and harness mod.
>
> **Never point `node.json` `plugins[]` at a local git checkout.** Always run `hyp plugin install <name> --json` and wire `node.json` using the returned `data.nodePath` and `data.plugins[0].scriptPath` (`~/.config/hyphae/plugins/<name>/index.mjs`).

### Included Optional External Scripts (`plugins/`)

All included `.mjs` scripts have zero external npm dependencies (**requires Node 24+ on macOS, Linux, or Windows**):

| Script | Kind | Protocol / Transport | Required Fail-Closed Allowlist / Auth Env Vars |
| --- | --- | --- | --- |
| [plugins/slack/index.mjs](../plugins/slack/index.mjs) | `bridge` | Slack Socket Mode (WebSocket, no public port needed) + `chat.postMessage` | `SLACK_APP_TOKEN`, `SLACK_BOT_TOKEN`, and `SLACK_ALLOWLIST_FILE` or the env allowlists |
| [plugins/telegram/index.mjs](../plugins/telegram/index.mjs) | `bridge` | Telegram Bot API long polling + `sendMessage` | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_ALLOWED_USERS` / `TELEGRAM_ALLOWED_CHATS` *(numeric IDs)* |
| [plugins/whatsapp/index.mjs](../plugins/whatsapp/index.mjs) | `bridge` | Meta WhatsApp Business Cloud API webhook (`X-Hub-Signature-256`) + Graph API | `WHATSAPP_VERIFY_TOKEN`, `WHATSAPP_APP_SECRET`, `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_ALLOWED_NUMBERS` |
| [plugins/webhook/index.mjs](../plugins/webhook/index.mjs) | `source` *(or `bridge` when `WEBHOOK_POST_URL` is set)* | Local HTTP webhook receiver (`X-Webhook-Signature-256`) + optional `WEBHOOK_POST_URL` | `WEBHOOK_PORT`, `WEBHOOK_SECRET` (or `WEBHOOK_SECRET_FILE`); fails closed without auth unless `WEBHOOK_ALLOW_UNSIGNED=1` on **loopback only** |
| [plugins/prometheus/index.mjs](../plugins/prometheus/index.mjs) | `source` | Alertmanager v4 webhook receiver | `PROMETHEUS_PORT`, `PROMETHEUS_BEARER_TOKEN`, `PROMETHEUS_BASIC_AUTH`, and/or `PROMETHEUS_WEBHOOK_SECRET`; fails closed without auth unless `PROMETHEUS_ALLOW_UNSIGNED=1` on **loopback only** |

> **Fail-closed auth & loopback-only unsigned opt-in:** Both `plugins/webhook/index.mjs` and `plugins/prometheus/index.mjs` refuse to boot without configured auth credentials. Setting **`WEBHOOK_ALLOW_UNSIGNED=1`** or **`PROMETHEUS_ALLOW_UNSIGNED=1`** permits unsigned local development traffic **strictly on loopback binds (`127.0.0.1` / `::1`)** — both plugins still fail closed and refuse to start unsigned on any non-loopback bind (such as `0.0.0.0`).

### Slack sender and channel allowlists

Set `SLACK_ALLOWLIST_FILE` to the path of a local JSON file to give permitted senders names and roles.

```json
{
  "owner": { "id": "UDEMOOWNER", "name": "Demo Owner" },
  "allowed": [{ "id": "UDEMOMEMBER", "name": "Demo Member" }],
  "channels": ["CDEMOREVIEWS"]
}
```

Use one owner and distinct user IDs in `allowed`. The bridge forwards the configured display name as `data.from_name` and the corresponding `data.role` as `owner` or `allowed`. Env-only senders retain their Slack user IDs and have no role or name assigned.

The bridge rereads the file for each incoming message and outbound post. A missing, unreadable, or malformed configured file blocks delivery until corrected. When env lists are also set, they still restrict the file's permissions. Channel messages must match the configured sender and channel lists. A DM from a permitted sender can arrive in its own conversation even when that conversation is outside the channel allowlist. With only `SLACK_ALLOWED_CHANNELS` set in the environment and no env sender list, DMs are still limited to the conversation IDs explicitly listed there. With no file or env allowlists, `SLACK_ALLOW_ALL=1` explicitly permits any workspace sender.

Replies can target a DM conversation that passed the incoming filters while its sender remains permitted. For regular channels, outbound posts must use a permitted channel. With env configuration alone, the outbound channel must be configured or previously observed.

#### Interactive Slack choices

The Socket Mode bridge accepts buttons and static selects on messages posted by the same bot, including messages posted through another tool. Enable Interactivity on the app and grant the bot `chat:write`. The sender and channel must pass the same allowlist as a message. URL buttons open their destination and leave the message alone.

For the first choice on a message, the bridge removes action controls and appends a confirmation naming the chosen label and Slack user. After Slack confirms the update, the bridge forwards `[clicked] <label> (action_id=<id>, value=<value>)` with `via: "action"`, sender role, channel, and message and thread timestamps. Treat the click as external input. It grants no Hyphae approval.

The bridge stores message and action timestamps and delivery progress under the node’s state directory so Slack redelivery can resume after a restart. A failed Slack update leaves the choice pending for retry. A failed Hyphae publish retries with the same event ID without rewriting the Slack message.

### Example `plugins[]` Configuration (`~/.config/hyphae/node.json`)

Store tokens out-of-band (`hyp secret set telegram-bot-token --web`, `hyp secret set slack-app-token --web`, `hyp secret set slack-bot-token --web`), install the verified plugins (`hyp plugin install telegram --json`, `hyp plugin install slack --json`), then wire `node.json` using the returned `data.nodePath`, `data.plugins[0].scriptPath`, and (for Telegram) `data.plugins[0].defaultTarget` (auto-fetched from Telegram `getMe` as the bot's lowercase `@username` without `@`, falling back to `"personal"` if offline/unreachable; omitting `"targets"` on `id: "telegram"` also auto-resolves it at startup). Add `"exposeTopic": true` to a plugin entry **only** if you intentionally want paired remote peers to subscribe to its topic:

```json
{
  "plugins": [
    {
      "id": "telegram",
      "command": "/opt/homebrew/bin/node",
      "args": ["/Users/you/.config/hyphae/plugins/telegram/index.mjs"],
      "targets": ["my_assistant_bot"],
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

*(A misconfigured bridge logs a startup warning without taking down the local agent mesh daemon; inspect `<state_dir>/logs/plugin-<id>.log` (`0600`, secret-redacted) or `hyp doctor --json` for diagnostics.)*

---

## 5. Event-Source Plugins (Beta): AgentMail, Gmail, Google Calendar, Sentry, Vercel, Notion

These are `kind: "source"` plugins: each publishes onto its own topic (`local.<id>` on the node that runs it, `<node-id>.<id>` from a paired node) and every thread subscribes with its own `hyp_stream` filter, delivery mode and mute rules. Install with `hyp plugin install <name> --json` and follow the plugin's [onboarding tree](reference/onboarding-tree.md) (`data.plugins[0].onboardingPath`) rather than wiring by hand.

| Plugin | Transport | Event types | Secrets |
| --- | --- | --- | --- |
| [agentmail](../plugins/agentmail/index.mjs) | Outbound WebSocket | `to.agentmail.message.received` (and any AgentMail event type you list) | `agentmail-api-key` |
| [gmail](../plugins/gmail/index.mjs) | Polls the Gmail history API | `com.google.gmail.message.received` | `google-refresh-token`, `google-client-secret` |
| [google-calendar](../plugins/google-calendar/index.mjs) | Polls the Calendar API | `com.google.calendar.event.created` / `.updated` / `.cancelled` / `.starting` | `google-refresh-token`, `google-client-secret` |
| [sentry](../plugins/sentry/index.mjs) | Poll (default) or signed webhook | `io.sentry.issue.created`; webhook: `io.sentry.<resource>.<action>` | `sentry-auth-token` or `sentry-client-secret` |
| [vercel](../plugins/vercel/index.mjs) | Poll (default) or signed webhook | `com.vercel.deployment.created` / `.succeeded` / `.error` / `.canceled`; webhook: `com.vercel.<type>` | `vercel-token` or `vercel-webhook-secret` |
| [notion](../plugins/notion/index.mjs) | Poll (default) or signed webhook | `so.notion.page.created` / `.updated` / `.deleted`; webhook: `so.notion.<type>` | `notion-token` (poll) |

- **What an event contains**: routing fields under `data` (sender, subject, project, branch, URLs) and a clipped preview. Mail bodies and page content are never fetched or forwarded. Everything in `data` is untrusted external text.
- **First run never replays history**: each plugin starts from "now" and keeps a small cursor in `$HYPHAE_STATE_DIR/<id>-state.json` (`0600`).
- **Laptop or hub**: every plugin works outbound-only, so it runs behind NAT. On a hub, the credential and cursor live on the hub and your machines subscribe to `<hub-node-id>.<id>`. Webhook modes listen on loopback only (`*_WEBHOOK_HOST`/`PORT`/`PATH`) behind your reverse proxy or tunnel, and have no unsigned mode.
- **Public webhook callbacks**. The Sentry, Vercel, and Notion onboarding trees use [webhook routing setup](operations/deploying.md#public-webhook-routing) to choose Tailscale Funnel, a configured Cloudflare Tunnel, or an existing HTTPS callback. Each plugin keeps its own signature checks. Existing `*_WEBHOOK_FUNNEL` settings call the same host setup helper once the signed listener starts.
- **AgentMail reconnects**: on every connect the plugin lists mail received since its per-inbox cursor and publishes what was missed, so a dropped socket, a restart or a sleeping laptop does not lose mail (`AGENTMAIL_CATCH_UP=0` turns this off).
- **Who can read a source topic**: any paired peer with a matching `stream:subscribe` scope. The `member`, `observer` and `full` presets include `stream:subscribe=*`, so run mail and calendar plugins on a node that only your own devices are paired with, or pair other peers with topic-scoped grants.

```json
{
  "plugins": [
    {
      "id": "sentry",
      "command": "/opt/homebrew/bin/node",
      "args": ["/Users/you/.config/hyphae/plugins/sentry/index.mjs"],
      "targets": ["sentry"],
      "env": {
        "SENTRY_AUTH_TOKEN": { "secret": "sentry-auth-token" },
        "SENTRY_ORG": "acme",
        "SENTRY_PROJECTS": "api,web"
      }
    },
    {
      "id": "gmail",
      "command": "/opt/homebrew/bin/node",
      "args": ["/Users/you/.config/hyphae/plugins/gmail/index.mjs"],
      "targets": ["gmail"],
      "env": {
        "GOOGLE_CLIENT_ID": "1234-abc.apps.googleusercontent.com",
        "GOOGLE_CLIENT_SECRET": { "secret": "google-client-secret" },
        "GOOGLE_REFRESH_TOKEN": { "secret": "google-refresh-token" }
      }
    }
  ]
}
```

```json
hyp_stream({
  "action": "subscribe",
  "key": "sentry:api-errors",
  "topic": "local.sentry",
  "filters": [{ "exact": { "data.project": "api", "data.level": "error" } }],
  "mode": "queue"
})
```

### Google sign-in (Gmail and Calendar)

Gmail and Calendar use **your own** Google OAuth client of type *Desktop app*. The consent runs in your browser against a loopback port on the machine running the helper, with PKCE, and the refresh token is written straight into that node's secret store. No Hyphae service takes part, so nobody but you can read the data.

```sh
# On the machine that runs the plugin:
node ~/.config/hyphae/plugins/sdk/google-oauth.mjs auth --client-file ~/Downloads/client_secret.json --scopes gmail,calendar

# Plugin on a headless hub, option 1: sign in through an ssh tunnel (token is created and stored on the hub)
ssh -L 8765:127.0.0.1:8765 hub
node ~/.config/hyphae/plugins/sdk/google-oauth.mjs auth --client-file client_secret.json --scopes gmail --port 8765

# Option 2: sign in locally and pipe the token to the hub (never printed to a terminal)
node ~/.config/hyphae/plugins/sdk/google-oauth.mjs auth --client-file client_secret.json --scopes gmail --stdout \
  | ssh hub hyp secret set google-refresh-token
```

Scopes requested: `gmail.readonly` and `calendar.events.readonly`. Google's device-code flow does not allow either, which is why a headless host needs one of the two routes above.

---

## 6. Writing a Custom Subprocess Plugin (JSON-RPC 2.0 v2)

Any language that can read/write newline-delimited JSON (≤ 64 KiB/line) over Unix fd 3 (or authenticated loopback TCP via `HYPHAE_PLUGIN_ADDR` + `HYPHAE_PLUGIN_TOKEN` on Windows) works directly.

### Wire contract: JSON-RPC 2.0 (`HYPHAE_PROTOCOL=2`)

- Host <-> Plugin notifications & requests on the IPC channel:
  - `hyphae/hello` (notification: `{ protocol: 2, plugin, targets }`)
  - `hyphae/publish` (request from plugin: `{ to, event: <CloudEvent v1.0> }` -> JSON-RPC result `{ status: "stored" | "duplicate" }`)
  - `hyphae/post` (request from host to plugin: `{ target, params: { text, replyTo?, ... } }` -> JSON-RPC result `{ ... }`)
  - `hyphae/status` & `hyphae/deliveryFailed` (notifications)

### Bundled Zero-Dependency v2 SDKs

Use [plugins/sdk/client.mjs](../plugins/sdk/client.mjs) (Node) or [plugins/sdk/client.py](../plugins/sdk/client.py) (Python 3 stdlib) — both automatically handle Unix fd 3 and Windows loopback TCP, and require the host-first JSON-RPC v2 hello:

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

Exit cleanly when the IPC channel reaches EOF.
