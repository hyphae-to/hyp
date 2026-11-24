export interface SecretSpec {
  readonly secretName: string;
  readonly envKey: string;
  readonly prompt: string;
  readonly required: boolean;
  readonly useFile?: boolean;
}

export interface PluginOrStreamGuide {
  readonly id: string;
  readonly kind: "router-stream" | "connector-bridge";
  readonly label: string;
  readonly tagline: string;
  readonly summary: string;
  readonly defaultName: string;
  readonly defaultTopicOrTarget: string;
  readonly secrets: readonly SecretSpec[];
  readonly instructions: readonly string[];
  readonly agentUsage: readonly string[];
}

export const ROUTER_STREAM_GUIDES: readonly PluginOrStreamGuide[] = [
  {
    id: "github-webhook",
    kind: "router-stream",
    label: "GitHub Events Stream",
    tagline: "PRs, issues, pushes, reviews & CI checks -> router topic `github`",
    summary: "Verifies GitHub X-Hub-Signature-256 webhooks and publishes normalized CloudEvents into a router topic so any agent on any machine can subscribe with repo/event filters.",
    defaultName: "github",
    defaultTopicOrTarget: "github",
    secrets: [
      {
        secretName: "github-webhook-secret",
        envKey: "GITHUB_WEBHOOK_SECRET",
        prompt: "GitHub webhook secret (generate with `openssl rand -hex 32`)",
        required: true,
      },
    ],
    instructions: [
      "Option A — Repository or Organization Webhook (fastest):",
      "  1. In GitHub: Repo or Org -> Settings -> Webhooks -> Add webhook.",
      "  2. Payload URL: https://<your-public-host>/hooks/github (reverse-proxying to 127.0.0.1:<GITHUB_WEBHOOK_PORT>, default 8791).",
      "  3. Content type: application/json",
      "  4. Secret: the exact secret saved via `hyp secret set github-webhook-secret --web` (0600).",
      "  5. Select individual events: Pull requests, Pull request reviews, Pull request review comments, Issues, Issue comments, Workflow runs, Pushes.",
      "",
      "Option B — GitHub App (best for orgs & selective repos):",
      "  1. GitHub -> Settings -> Developer settings -> GitHub Apps -> New GitHub App.",
      "  2. Webhook: Active = true, URL = https://<your-public-host>/hooks/github, Secret = `github-webhook-secret`.",
      "  3. Permissions (Read-only): Pull requests, Issues, Actions, Contents, Metadata -> Subscribe to the matching events.",
      "  4. Install the GitHub App on the exact repositories (or org) you want monitored.",
      "",
      "Scope & Reachability (prevents dead subscriptions!):",
      "  - Set `GITHUB_REPOS` (e.g. `hyphae-to/hyp,org/api`) or `GITHUB_ORGS` (`hyphae-to`) in stream env (or `scope.repos` / `scope.orgs`).",
      "  - `hyp_topics` advertises this scope + observed webhook sources to models, and `hyp_subscribe` warns if an agent subscribes to an unmonitored repo or filters `subject` instead of `repo`.",
      "  - Verify delivery: click 'Redeliver' on the initial `ping` in GitHub Recent Deliveries (expect HTTP 202) and run `hyp_topics`.",
    ],
    agentUsage: [
      'Inspect monitored repos & schema first: hyp_topics()',
      'Filter by repository (use `repo`, NOT `subject`!): hyp_subscribe({ key: "gh:hyp-prs", topic: "github", filters: [{ exact: { repo: "hyphae-to/hyp" } }, { prefix: { type: "com.github.pull_request." } }] })',
      'Fail closed on unmonitored repos: hyp_subscribe({ key: "gh:strict", topic: "github", filters: [{ exact: { repo: "org/repo" } }], strict: true })',
    ],
  },
  {
    id: "webhook-stream",
    kind: "router-stream",
    label: "Signed Webhook Data Stream",
    tagline: "Linear, Sentry, Stripe, CI or custom HTTP POSTs -> any router topic",
    summary: "Runs a local/proxied HTTP receiver with optional HMAC-SHA256 verification and publishes incoming JSON/CloudEvents to a router topic for multi-agent filtered subscriptions.",
    defaultName: "webhooks",
    defaultTopicOrTarget: "webhooks",
    secrets: [
      {
        secretName: "webhook-stream-secret",
        envKey: "WEBHOOK_SECRET",
        prompt: "Optional HMAC-SHA256 signing secret (leave blank to allow unsigned localhost calls)",
        required: false,
      },
    ],
    instructions: [
      "1. Point your webhook sender (CI, Sentry, Linear, cron) at http://127.0.0.1:<WEBHOOK_PORT>/webhook (or expose via HTTPS reverse proxy).",
      "2. If a secret is set, sign raw request bodies with `X-Webhook-Signature-256: sha256=<hex>`.",
      "3. Test locally with curl:",
      '   curl -X POST http://127.0.0.1:8792/webhook -H "content-type: application/json" -d \'{"type":"com.ci.failed","source":"ci/main","data":{"repo":"app"}}\'',
    ],
    agentUsage: [
      'hyp_subscribe({ key: "ci:failures", topic: "webhooks", filters: [{ exact: { type: "com.ci.failed" } }] })',
    ],
  },
  {
    id: "prometheus-webhook",
    kind: "router-stream",
    label: "Prometheus Alertmanager Stream",
    tagline: "Firing & resolved Alertmanager v4 alerts -> router topic `alerts`",
    summary: "Receives standard Prometheus Alertmanager webhook payloads (optional Bearer token or HMAC verification) and publishes one CloudEvent per alert with subject `severity=<level>/<alertname>`.",
    defaultName: "prometheus",
    defaultTopicOrTarget: "alerts",
    secrets: [
      {
        secretName: "prometheus-bearer-token",
        envKey: "PROMETHEUS_BEARER_TOKEN",
        prompt: "Optional Alertmanager Bearer token (leave blank to allow unauthenticated loopback)",
        required: false,
      },
    ],
    instructions: [
      "1. In alertmanager.yml, add a webhook_configs receiver pointing to http://127.0.0.1:<PROMETHEUS_PORT>/alerts (default 8793).",
      "2. If a Bearer token is set, configure `http_config: { authorization: { credentials: ... } }` in Alertmanager.",
      "3. Alerts emit `io.prometheus.alert.firing` and `io.prometheus.alert.resolved` with subject `severity=<severity>/<alertname>`.",
    ],
    agentUsage: [
      'hyp_subscribe({ key: "alerts:critical", topic: "alerts", filters: [{ prefix: { subject: "severity=critical" } }] })',
    ],
  },
  {
    id: "custom-stream",
    kind: "router-stream",
    label: "Custom Data Source Plugin",
    tagline: "Any Node / Python / Go executable emitting CloudEvents on fd 3 -> router topic",
    summary: "Supervised child process on the router host using the zero-dependency MeshPluginClient SDK (Node or Python) to poll APIs, tail logs, or stream databases into a filterable router topic.",
    defaultName: "custom-feed",
    defaultTopicOrTarget: "custom-feed",
    secrets: [],
    instructions: [
      "1. Write an executable script importing plugins/sdk/client.mjs (Node 24) or plugins/sdk/client.py (Python 3).",
      "2. Call `await mesh.send(targets[0], cloudEvent)` whenever new data arrives.",
      "3. Store any API keys safely with `hyp secret set <name>` and reference them in `env` as `{ \"secret\": \"<name>\" }`.",
    ],
    agentUsage: [
      'hyp_subscribe({ key: "custom:feed", topic: "custom-feed", filters: [{ prefix: { type: "com.custom." } }] })',
    ],
  },
];

export const CONNECTOR_BRIDGE_GUIDES: readonly PluginOrStreamGuide[] = [
  {
    id: "slack",
    kind: "connector-bridge",
    label: "Slack Thread Bridge (Socket Mode)",
    tagline: "Connect Slack DMs, @mentions & threads directly to a local agent handle",
    summary: "Outbound WebSocket via Slack Socket Mode (no public URL required). Tokens stay on your local machine; events route to one owning agent handle with live `hyp_plugin_handoff`.",
    defaultName: "slack",
    defaultTopicOrTarget: "pm",
    secrets: [
      {
        secretName: "slack-app-token",
        envKey: "SLACK_APP_TOKEN",
        prompt: "Slack App-Level Token (xapp-..., requires connections:write)",
        required: true,
      },
      {
        secretName: "slack-bot-token",
        envKey: "SLACK_BOT_TOKEN",
        prompt: "Slack Bot Token (xoxb-..., requires app_mentions:read, im:history, chat:write)",
        required: true,
      },
    ],
    instructions: [
      "1. Open https://api.slack.com/apps -> Create New App -> From scratch.",
      "2. Enable Socket Mode -> generate an App-Level Token (`xapp-...`) with `connections:write`.",
      "3. OAuth & Permissions -> add Bot Scopes: `app_mentions:read`, `im:history`, `im:read`, `channels:history`, `chat:write` -> Install to Workspace -> copy `xoxb-...`.",
      "4. Event Subscriptions -> Enable -> Subscribe to bot events: `app_mention`, `message.im`.",
      "5. Restrict who can trigger your agent by setting `SLACK_ALLOWED_USERS` (comma-separated Slack member IDs, e.g. U01234567).",
    ],
    agentUsage: [
      'Claim target handle: hyp_join({ handle: "pm" })',
      'Reply back to Slack: hyp_plugin_post({ plugin: "slack", target: "pm", text: "PR #42 merged." })',
      'Link extra thread or hand off: hyp_bridge_link({ plugin: "slack", target: "pm", handle: "reviewer" }) / hyp_plugin_handoff(...)',
    ],
  },
  {
    id: "telegram",
    kind: "connector-bridge",
    label: "Telegram Bot Bridge (Long Polling)",
    tagline: "Chat with a pinned agent directly from Telegram (no public URL needed)",
    summary: "Uses Telegram Bot API long-polling with durable offset checkpointing. Supports outbound replies via `hyp_plugin_post` and multi-thread fan-in via `hyp_bridge_link`.",
    defaultName: "telegram",
    defaultTopicOrTarget: "assistant",
    secrets: [
      {
        secretName: "telegram-bot-token",
        envKey: "TELEGRAM_BOT_TOKEN",
        prompt: "Telegram Bot Token (from @BotFather /newbot)",
        required: true,
      },
    ],
    instructions: [
      "1. Message @BotFather on Telegram -> send `/newbot` and copy the bot token.",
      "2. Find your numeric Telegram user ID via @userinfobot.",
      "3. Set `TELEGRAM_ALLOWED_USERS` to your numeric user ID so strangers cannot message your agent.",
      "4. Send a message to your bot — it wakes your enrolled agent handle automatically!",
    ],
    agentUsage: [
      'Claim target handle: hyp_join({ handle: "assistant" })',
      'Reply back to Telegram: hyp_plugin_post({ plugin: "telegram", target: "assistant", text: "Done!" })',
      'Link or hand off: hyp_bridge_link({ plugin: "telegram", target: "assistant", handle: "ops" }) / hyp_plugin_handoff(...)',
    ],
  },
  {
    id: "whatsapp",
    kind: "connector-bridge",
    label: "WhatsApp Cloud API Bridge",
    tagline: "Bidirectional WhatsApp Business Cloud API webhook + outbound replies",
    summary: "Verifies Meta webhook handshakes and HMAC-SHA256 signatures (`X-Hub-Signature-256`), enforces `WHATSAPP_ALLOWED_NUMBERS`, and supports outbound replies via `hyp_plugin_post`.",
    defaultName: "whatsapp",
    defaultTopicOrTarget: "assistant",
    secrets: [
      {
        secretName: "whatsapp-verify-token",
        envKey: "WHATSAPP_VERIFY_TOKEN",
        prompt: "Meta Webhook Verify Token (for GET hub.verify_token handshake)",
        required: true,
      },
      {
        secretName: "whatsapp-app-secret",
        envKey: "WHATSAPP_APP_SECRET",
        prompt: "Meta App Secret (verifies X-Hub-Signature-256 on inbound POSTs)",
        required: true,
      },
      {
        secretName: "whatsapp-access-token",
        envKey: "WHATSAPP_ACCESS_TOKEN",
        prompt: "WhatsApp Cloud API permanent access token (for outbound hyp_plugin_post replies)",
        required: true,
      },
    ],
    instructions: [
      "1. In Meta Developers -> WhatsApp -> Configuration, set Callback URL to https://<your-host>/whatsapp (proxying to WHATSAPP_PORT, default 8796).",
      "2. Enter the exact Verify Token saved as `whatsapp-verify-token` and subscribe to the `messages` field.",
      "3. Set `WHATSAPP_PHONE_NUMBER_ID` and `WHATSAPP_ALLOWED_NUMBERS` (comma-separated E.164 digits, e.g. 15551234567).",
    ],
    agentUsage: [
      'Claim target handle: hyp_join({ handle: "assistant" })',
      'Reply on WhatsApp: hyp_plugin_post({ plugin: "whatsapp", target: "assistant", text: "Deploy complete." })',
      'Fan-in to another thread: hyp_bridge_link({ plugin: "whatsapp", target: "assistant", handle: "ops" })',
    ],
  },
  {
    id: "webhook",
    kind: "connector-bridge",
    label: "Local Webhook Bridge",
    tagline: "Loopback HTTP + HMAC-SHA256 -> pinned local agent handle",
    summary: "Ideal for machine-local alerts, cron jobs, or personal automations routed directly to one agent handle without exposing a router topic.",
    defaultName: "local-alerts",
    defaultTopicOrTarget: "ops",
    secrets: [
      {
        secretName: "local-webhook-secret",
        envKey: "WEBHOOK_SECRET",
        prompt: "Optional HMAC-SHA256 signing secret (leave blank for unsigned localhost testing)",
        required: false,
      },
    ],
    instructions: [
      "1. POST JSON to http://127.0.0.1:<WEBHOOK_PORT>/webhook.",
      "2. If a secret is configured, sign raw body with header `X-Webhook-Signature-256: sha256=<hex>`.",
    ],
    agentUsage: [
      'Claim target handle: hyp_join({ handle: "ops" })',
    ],
  },
  {
    id: "custom-plugin",
    kind: "connector-bridge",
    label: "Custom / Existing t3-mesh Plugin",
    tagline: "Run any local executable or existing t3-mesh Python bridge on fd 3",
    summary: "100% drop-in compatible with existing t3-mesh connector plugins (e.g. Python Slack/Telegram/ops bridges) and custom scripts using plugins/sdk/client.{mjs,py}.",
    defaultName: "custom-bridge",
    defaultTopicOrTarget: "ops",
    secrets: [],
    instructions: [
      "1. Provide an absolute executable path (`exec`) and optional arguments (`args`).",
      "2. Store any secrets with `hyp secret set <name>` and reference them in `env` as `{ \"secret\": \"<name>\" }` or `{ \"secretFile\": \"<name>\" }`.",
    ],
    agentUsage: [
      'Claim target handle: hyp_join({ handle: "ops" })',
    ],
  },
];

export const ALL_GUIDES: readonly PluginOrStreamGuide[] = [
  ...ROUTER_STREAM_GUIDES,
  ...CONNECTOR_BRIDGE_GUIDES,
];

export function findGuide(id: string): PluginOrStreamGuide | undefined {
  return ALL_GUIDES.find((g) => g.id === id);
}
