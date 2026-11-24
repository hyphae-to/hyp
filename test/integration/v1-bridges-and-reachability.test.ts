import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { join } from "node:path";
import { test } from "node:test";
import { loadConfig } from "../../src/config.ts";
import { startDaemon } from "../../src/daemon.ts";
import { writeSecret } from "../../src/secrets.ts";
import { runOnboard } from "../../src/setup.ts";
import { freePort, McpClient, MeshTopology, waitFor } from "./harness/topology.ts";
import { deliverGithubWebhook, makeGithubPullRequestPayload } from "./shims/services.ts";

test(
  "end-to-end Team Node streams (github-webhook + builtin prometheus-webhook): hyp_topics, reachability lint, strict mode & live delivery over real MCP",
  { timeout: 25_000 },
  async () => {
    const topo = new MeshTopology("hyphae-v1-reach-");
    try {
      const routerPort = await freePort();
      const ghPort = await freePort();
      const promPort = await freePort();
      const ghSecret = "gh-v1-integ-secret";
      const promToken = "prom-v1-bearer-token";

      const hubDir = topo.subDir("hub");
      writeSecret("github-webhook-secret", ghSecret, hubDir);
      writeSecret("prom-bearer-token", promToken, hubDir);

      const cfgPath = join(hubDir, "connector.json");
      await runOnboard({
        configPath: cfgPath,
        connectorId: "ops@team-hub",
        port: routerPort,
        harnesses: [],
        startDaemon: false,
        localRouterExposure: "private",
        localRouterStreams: [
          {
            name: "github",
            topic: "github",
            builtin: "github-webhook",
            env: {
              GITHUB_WEBHOOK_HOST: "127.0.0.1",
              GITHUB_WEBHOOK_PORT: String(ghPort),
              GITHUB_WEBHOOK_SECRET: { secret: "github-webhook-secret" },
              GITHUB_REPOS: "acme/checkout",
              GITHUB_ORGS: "acme-infra",
            },
          },
          {
            name: "prometheus",
            topic: "alerts",
            builtin: "prometheus-webhook",
            env: {
              PROMETHEUS_HOST: "127.0.0.1",
              PROMETHEUS_PORT: String(promPort),
              PROMETHEUS_TOPIC: "alerts",
              PROMETHEUS_BEARER_TOKEN: { secret: "prom-bearer-token" },
            },
          },
        ],
      });

      const daemon = await startDaemon(loadConfig(cfgPath), { quiet: true });
      topo.track(() => daemon.stop());

      // Connect a real `hyp mcp` subprocess
      const mcp = new McpClient(daemon.socketPath, ["--backend", "claude", "--ephemeral"]);
      topo.track(() => mcp.close());
      await mcp.initialize();

      const joinRes = await mcp.callTool("hyp_join", { handle: "oncall" });
      assert.equal(joinRes.isError, false, joinRes.text);
      const caps = (await mcp.callTool("hyp_capabilities", {})).json() as { sessionId: string };

      // 1. Inspect topics & declared scope before subscribing
      const topicsRes = (await mcp.callTool("hyp_topics", {})).json() as {
        routers: Array<{
          router: string;
          topics: Array<{
            topic: string;
            metadata?: { kind?: string; scope?: { repos?: string[]; orgs?: string[] }; setupGuide?: string };
            observed: { eventCount: number; repos: string[] };
          }>;
        }>;
      };
      const routerTopics = topicsRes.routers[0]?.topics ?? [];
      const ghTopic = routerTopics.find((t) => t.topic === "github");
      const promTopic = routerTopics.find((t) => t.topic === "alerts");
      assert.ok(ghTopic && promTopic, "Both github and alerts topics must appear in hyp_topics");
      assert.deepEqual(ghTopic.metadata?.scope?.repos, ["acme/checkout"]);
      assert.deepEqual(ghTopic.metadata?.scope?.orgs, ["acme-infra"]);
      assert.equal(promTopic.metadata?.kind, "prometheus-webhook");

      // 2. Unmonitored repo with strict: true fails closed over MCP
      const strictFail = await mcp.callTool("hyp_subscribe", {
        key: "gh:unmonitored",
        topic: "github",
        filters: [{ exact: { repo: "stranger/not-installed" } }],
        coalesceSeconds: 0,
        strict: true,
      });
      assert.equal(strictFail.isError, true);
      assert.match(strictFail.text, /NOT in the configured 'github' stream scope/i);

      // 3. Wrong GitHub `subject` filter returns reachable: false + suggestedFilter
      const badAttr = (await mcp.callTool("hyp_subscribe", {
        key: "gh:wrong-attr",
        topic: "github",
        filters: [{ prefix: { subject: "acme/checkout" } }],
        coalesceSeconds: 0,
      })).json() as {
        reachable: boolean;
        diagnostics?: Array<{ code: string; suggestedFilter?: Record<string, unknown> }>;
      };
      assert.equal(badAttr.reachable, false);
      const suggested = badAttr.diagnostics?.find((d) => d.code === "invalid_github_subject_filter")?.suggestedFilter;
      assert.deepEqual(suggested, { exact: { repo: "acme/checkout" } });

      // 4. Subscribe cleanly using the suggested repo filter + critical Prometheus alerts filter
      const ghSub = (await mcp.callTool("hyp_subscribe", {
        key: "gh:checkout",
        topic: "github",
        filters: [suggested!],
        coalesceSeconds: 0,
        strict: true,
      })).json() as { reachable: boolean };
      assert.equal(ghSub.reachable, true);

      const promSub = (await mcp.callTool("hyp_subscribe", {
        key: "prom:crit",
        topic: "alerts",
        filters: [{ prefix: { subject: "severity=critical" } }],
        coalesceSeconds: 0,
      })).json() as { reachable: boolean };
      assert.equal(promSub.reachable, true);

      // 5. Deliver real signed GitHub PR webhook + real Alertmanager v4 payload
      const ghDelivery = await deliverGithubWebhook({
        receiverUrl: `http://127.0.0.1:${ghPort}`,
        secret: ghSecret,
        event: "pull_request",
        deliveryId: "v1-pr-101",
        payload: makeGithubPullRequestPayload({
          repo: "acme/checkout",
          number: 101,
          title: "Fix Stripe idempotency race",
        }),
      });
      assert.equal(ghDelivery.status, 202);

      // Wait for prometheus-webhook child process HTTP listener and POST Alertmanager v4 payload
      await waitFor(async () => {
        try {
          const h = await fetch(`http://127.0.0.1:${promPort}/health`);
          return h.ok;
        } catch {
          return false;
        }
      }, { label: "prometheus-webhook /health" });

      const promBadAuth = await fetch(`http://127.0.0.1:${promPort}/alerts`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer wrong" },
        body: JSON.stringify({ alerts: [] }),
      });
      assert.equal(promBadAuth.status, 401);

      const promOk = await fetch(`http://127.0.0.1:${promPort}/alerts`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${promToken}` },
        body: JSON.stringify({
          receiver: "hyphae",
          status: "firing",
          alerts: [
            {
              status: "firing",
              fingerprint: "crit-checkout-500",
              startsAt: "2026-11-24T10:00:00Z",
              labels: { alertname: "CheckoutHigh5xx", severity: "critical", service: "checkout" },
              annotations: { summary: "5xx spike > 5%" },
            },
            {
              status: "firing",
              fingerprint: "warn-disk",
              startsAt: "2026-11-24T10:00:00Z",
              labels: { alertname: "DiskWarm", severity: "warning", service: "checkout" },
              annotations: { summary: "Disk 72%" },
            },
          ],
        }),
      });
      assert.equal(promOk.status, 200);

      // Both GitHub PR and critical Prometheus alert arrive in mailbox (warning alert filtered out!)
      const items = await waitFor(
        () => {
          if (daemon.state.pendingCount(caps.sessionId) < 2) return null;
          return daemon.connector.drainMailbox(caps.sessionId, 10);
        },
        { label: "GitHub PR + critical Prometheus alert delivery" },
      );
      const combined = items.map((i) => i.text).join("\n");
      assert.match(combined, /Fix Stripe idempotency race/);
      assert.match(combined, /CheckoutHigh5xx/);
      assert.doesNotMatch(combined, /DiskWarm/);

      // 6. hyp_topics now reflects observed repo `acme/checkout`!
      const topicsAfter = (await mcp.callTool("hyp_topics", { router: "primary" })).json() as {
        routers: Array<{ topics: Array<{ topic: string; observed: { eventCount: number; repos: string[] } }> }>;
      };
      const ghAfter = topicsAfter.routers[0]?.topics.find((t) => t.topic === "github");
      assert.equal(ghAfter?.observed.eventCount, 1);
      assert.deepEqual(ghAfter?.observed.repos, ["acme/checkout"]);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "end-to-end built-in WhatsApp bridge with 0600 secrets, cross-harness hyp_bridge_link fan-in, and outbound hyp_plugin_post over real MCP",
  { timeout: 25_000 },
  async () => {
    const topo = new MeshTopology("hyphae-v1-wa-");
    try {
      const routerPort = await freePort();
      const waPort = await freePort();
      const verifyToken = "wa-verify-secret-xyz";
      const appSecret = "wa-app-hmac-secret-abc";
      const accessToken = "EAAG-test-permanent-token";

      const graphPosts: Array<{ auth: string | undefined; path: string; body: Record<string, unknown> }> = [];
      const mockGraph = createHttpServer(async (req, res) => {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(c as Buffer);
        const body = chunks.length > 0 ? (JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>) : {};
        graphPosts.push({ auth: req.headers.authorization, path: req.url ?? "", body });
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ messages: [{ id: "wamid.out.1" }] }));
      });
      await new Promise<void>((r) => mockGraph.listen(0, "127.0.0.1", r));
      topo.track(() => new Promise<void>((r) => mockGraph.close(() => r())));
      const graphAddr = mockGraph.address();
      assert.ok(graphAddr && typeof graphAddr === "object");
      const graphBase = `http://127.0.0.1:${graphAddr.port}/v21.0`;

      const dir = topo.subDir("wa");
      writeSecret("wa-verify", verifyToken, dir);
      writeSecret("wa-secret", appSecret, dir);
      writeSecret("wa-access", accessToken, dir);

      const cfgPath = join(dir, "connector.json");
      await runOnboard({
        configPath: cfgPath,
        connectorId: "alex@wa-host",
        port: routerPort,
        harnesses: [],
        startDaemon: false,
        plugins: [
          {
            name: "wa",
            builtin: "whatsapp",
            env: {
              WHATSAPP_HOST: "127.0.0.1",
              WHATSAPP_PORT: String(waPort),
              WHATSAPP_PATH: "/whatsapp",
              WHATSAPP_TARGET: "support",
              WHATSAPP_PHONE_NUMBER_ID: "555000111",
              WHATSAPP_ALLOWED_NUMBERS: "+15551234567",
              WHATSAPP_VERIFY_TOKEN: { secret: "wa-verify" },
              WHATSAPP_APP_SECRET: { secret: "wa-secret" },
              WHATSAPP_ACCESS_TOKEN: { secret: "wa-access" },
              WHATSAPP_API_BASE: graphBase,
            },
            targets: [{ name: "support", handle: "lead", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 }],
          },
        ],
      });

      const daemon = await startDaemon(loadConfig(cfgPath), { quiet: true });
      topo.track(() => daemon.stop());

      // Three sessions across 3 different harnesses via real MCP processes
      const leadMcp = new McpClient(daemon.socketPath, ["--backend", "antigravity", "--ephemeral"]);
      const helperMcp = new McpClient(daemon.socketPath, ["--backend", "claude", "--ephemeral"]);
      const outsiderMcp = new McpClient(daemon.socketPath, ["--backend", "openclaw", "--ephemeral"]);
      topo.track(() => leadMcp.close());
      topo.track(() => helperMcp.close());
      topo.track(() => outsiderMcp.close());
      await Promise.all([leadMcp.initialize(), helperMcp.initialize(), outsiderMcp.initialize()]);

      await leadMcp.callTool("hyp_join", { handle: "lead" });
      await helperMcp.callTool("hyp_join", { handle: "helper" });
      await outsiderMcp.callTool("hyp_join", { handle: "outsider" });

      const leadCaps = (await leadMcp.callTool("hyp_capabilities", {})).json() as { sessionId: string };
      const helperCaps = (await helperMcp.callTool("hyp_capabilities", {})).json() as { sessionId: string };
      const outsiderCaps = (await outsiderMcp.callTool("hyp_capabilities", {})).json() as { sessionId: string };

      // Wait for WhatsApp HTTP listener & verify Meta GET challenge handshake
      await waitFor(async () => {
        try {
          const r = await fetch(
            `http://127.0.0.1:${waPort}/whatsapp?hub.mode=subscribe&hub.verify_token=${verifyToken}&hub.challenge=CHALLENGE_OK`,
          );
          return r.status === 200 && (await r.text()) === "CHALLENGE_OK";
        } catch {
          return false;
        }
      }, { label: "WhatsApp GET verification handshake" });

      // Lead links helper to `wa/support` for multi-thread fan-in
      const linkRes = await leadMcp.callTool("hyp_bridge_link", { plugin: "wa", target: "support", handle: "helper" });
      assert.equal(linkRes.isError, false, linkRes.text);

      // Deliver signed inbound Meta WhatsApp message -> fans in to BOTH lead (antigravity) & helper (claude)
      const sendMetaMsg = async (id: string, bodyText: string) => {
        const raw = JSON.stringify({
          object: "whatsapp_business_account",
          entry: [{
            changes: [{
              value: {
                metadata: { phone_number_id: "555000111" },
                contacts: [{ wa_id: "15551234567", profile: { name: "Bogdan" } }],
                messages: [{ id, from: "15551234567", timestamp: "1764000000", type: "text", text: { body: bodyText } }],
              },
            }],
          }],
        });
        const sig = "sha256=" + createHmac("sha256", appSecret).update(raw).digest("hex");
        return fetch(`http://127.0.0.1:${waPort}/whatsapp`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-hub-signature-256": sig },
          body: raw,
        });
      };

      assert.equal((await sendMetaMsg("wamid.in.10", "Status on prod deploy?")).status, 200);
      await waitFor(
        () => daemon.state.pendingCount(leadCaps.sessionId) >= 1 && daemon.state.pendingCount(helperCaps.sessionId) >= 1,
        { label: "WhatsApp fan-in to lead + helper" },
      );
      assert.match(daemon.connector.drainMailbox(leadCaps.sessionId, 5)[0].text, /Status on prod deploy/);
      assert.match(daemon.connector.drainMailbox(helperCaps.sessionId, 5)[0].text, /Status on prod deploy/);
      assert.equal(daemon.state.pendingCount(outsiderCaps.sessionId), 0);

      // Linked helper sends outbound WhatsApp reply via `hyp_plugin_post`
      const postRes = await helperMcp.callTool("hyp_plugin_post", {
        plugin: "wa",
        target: "support",
        text: "Prod deploy is green!",
        replyTo: "wamid.in.10",
      });
      assert.equal(postRes.isError, false, postRes.text);
      assert.equal(graphPosts.length, 1);
      assert.equal(graphPosts[0].auth, `Bearer ${accessToken}`);
      assert.equal(graphPosts[0].path, "/v21.0/555000111/messages");
      assert.equal(graphPosts[0].body.to, "15551234567");
      assert.deepEqual(graphPosts[0].body.text, { preview_url: false, body: "Prod deploy is green!" });
      assert.deepEqual(graphPosts[0].body.context, { message_id: "wamid.in.10" });

      // Outsider fails closed on `hyp_plugin_post`
      const outsiderPost = await outsiderMcp.callTool("hyp_plugin_post", {
        plugin: "wa",
        target: "support",
        text: "unauthorized reply",
      });
      assert.equal(outsiderPost.isError, true);
      assert.match(outsiderPost.text, /not_target_holder|not the holder/i);

      // Helper unlinks -> stops receiving subsequent messages & cannot post
      const unlinkRes = await helperMcp.callTool("hyp_bridge_unlink", { plugin: "wa", target: "support" });
      assert.equal(unlinkRes.isError, false, unlinkRes.text);
      assert.equal((await sendMetaMsg("wamid.in.11", "Second message for lead only")).status, 200);
      await waitFor(() => daemon.state.pendingCount(leadCaps.sessionId) >= 1, { label: "lead-only WhatsApp delivery" });
      assert.match(daemon.connector.drainMailbox(leadCaps.sessionId, 5)[0].text, /Second message for lead only/);
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(daemon.state.pendingCount(helperCaps.sessionId), 0);
    } finally {
      await topo.cleanup();
    }
  },
);
