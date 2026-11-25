# Events & OS Cron Triggers

Wake the right agent automatically when a local timer fires, a GitHub PR updates, or a Prometheus alert triggers — without polling loops burning tokens.

---

## 1. Local Cron & Scheduled Wakeups (`hyp emit` + `ingest.sock`)

Hyphae's socket-only **Local Ingest Route** (`~/.config/hyphae/state/ingest.sock` `0600` on macOS/Linux; `ingest.addr` loopback TCP + bearer token on Windows) is **enabled by default** with zero `node.json` configuration.

### Step 1: Subscribe your agent session
Ask your agent to subscribe to `local.schedule` via `hyp_stream`:

```json
hyp_stream({
  "action": "subscribe",
  "topic": "local.schedule",
  "filters": [{ "exact": { "label": "check-ci" } }],
  "mode": "interrupt"
})
```

### Step 2: Schedule an OS trigger calling `hyp emit`

```sh
# One-shot Linux timer (systemd-run --user)
systemd-run --user --on-active=15m -- hyp emit --label check-ci --note "Verify CI build"

# Recurring Unix cron (crontab -e)
0 9 * * 1-5 $HOME/.local/bin/hyp emit --label morning-triage --note "Review open PRs"

# Raw Unix socket NDJSON (zero CLI spawn)
printf '{"type":"to.hyphae.scheduled.v1","label":"check-ci","note":"Build finished"}\n' \
  | nc -U ~/.config/hyphae/state/ingest.sock
```

```powershell
# Windows Task Scheduler (schtasks)
schtasks /Create /SC DAILY /TN "HyphaeMorningTriage" /ST 09:00 /TR "hyp emit --label morning-triage --note \"Review open PRs\""
```

For high-trust scheduled triggers, run `hyp emit --sign --label prod-rollout --note "Start canary"` in an interactive terminal (attaches an Ed25519 `hyphaesig` extension -> `TrustTier::HumanVerified`). To tighten route allowlists, rate limits, or `requireSignature: true`, see the [`localIngest` section in `node.json`](../reference/node-json.md#localingest).

---

## 2. GitHub Event Streams: Webhook vs. Local Polling

Choose the ingestion mode that fits your network topology:

| Mode | Best Topology | Latency | Event Coverage | Auth / Secrets |
| --- | --- | --- | --- | --- |
| **Compiled-in `github-webhook`** *(recommended when reachable)* | Hub / Server (`profile: router`) or laptop behind Tailscale Funnel / Cloudflare Tunnel | `<1–2s` real-time | **All GitHub events**, including live Actions CI (`workflow_run`, `check_run`) | Shared HMAC-SHA256 secret only (`X-Hub-Signature-256`) — zero GitHub PAT |
| **Compiled-in `github-public` + `repoTokens`** *(zero-infra NAT fallback)* | Local laptop behind NAT (or public read-only node) | ~30s avg / 60s max (`304 = 0` quota) | Pushes, PRs, issues, comments, reviews, releases *(GitHub `/events` does NOT emit `workflow_run` / `check_run`)* | Optional fine-grained read-only PAT per owner via `repoTokens` (5,000 req/hr per owner; 60 req/hr public unauthenticated) |

### Option A: Subscribe to a Public Node (zero GitHub token)

```sh
hyp pair join https://public.hyphae.to
```

Then ask your agent to subscribe to a public repository:

```json
hyp_stream({
  "action": "subscribe",
  "key": "gh:rust",
  "topic": "public.hyphae.to.github",
  "filters": [{ "exact": { "repo": "owner/repo" } }],
  "mode": "queue",
  "coalesceSeconds": 15,
  "strict": true
})
```

### Option B: Local `github-public` with Per-Owner `repoTokens`

Store one fine-grained read-only PAT per personal account or GitHub org out-of-band:

```sh
hyp secret set github-alice-token --web
hyp secret set github-acme-token --web
```

Add one `github-public` entry under `sources[]` in `~/.config/hyphae/node.json`:

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
        "acme/*": { "secret": "github-acme-token" }
      }
    }
  ]
}
```

Restart the service (`hyp service restart`). Tokens resolve strictly by specificity (exact `owner/repo` -> `owner/*` -> optional fallback `githubToken` -> unauthenticated) and never leak across owners.

---

## 3. Compiled-In Pure-Rust Webhooks (`github-webhook`, `prometheus-webhook`, `webhook-stream`)

All three webhook adapters compile directly into `hyp` and wire into `hyp node start` via `sources[]` in `node.json` — zero Node.js or Python subprocess required. They verify HMAC-SHA256 / bearer / basic auth in constant time (`ring::hmac`), deduplicate on raw-body SHA-256, and cap hub-relayed events at `ExternalWebhook` trust tier.

```json
{
  "sources": [
    {
      "id": "org-github",
      "kind": "github-webhook",
      "topic": "github-webhooks",
      "secret": { "secret": "github-webhook-secret" },
      "allowedOrgs": ["acme"]
    },
    {
      "id": "prom-alerts",
      "kind": "prometheus-webhook",
      "topic": "alerts",
      "bearerToken": { "secret": "prometheus-bearer-token" }
    }
  ]
}
```

> **Hub isolation tip:** On hubs that also enable `guest-ro` pairing (which grants `stream:subscribe=github[...]`), set **`"topic": "github-webhooks"`** on your private `github-webhook` source so internal repo webhooks stay isolated from the public `"github"` topic.

---

## What You Should See

- Running `hyp emit --label check-ci --note "Hello"` immediately wakes the subscribed session with `[hyphae interrupt · local.schedule]`.
- `hyp inspect` shows your active subscriptions under the **Subs** tab with topic, filters, and delivery tier.

If events are dropped or not waking your session, check `hyp doctor` and [Troubleshooting](../operations/troubleshooting.md).
