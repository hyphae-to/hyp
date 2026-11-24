import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type Server } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Plugins } from "./core/plugins/plugins.ts";
import type { CloudEvent } from "./core/router/cloudevent.ts";
import { RouterCore } from "./core/router/core.ts";
import type { InboundEventBatch } from "./core/router/types.ts";
import type { RouterStreamConfig } from "./config.ts";
import { buildStreamTopicMap, RouterStreamHost } from "./streams.ts";

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createNetServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => {
        if (addr && typeof addr === "object") resolve(addr.port);
        else reject(new Error("Could not allocate free port"));
      });
    });
  });
}

async function waitForHttp(url: string, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.status > 0) return;
    } catch {
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  throw new Error(`HTTP endpoint did not start listening in time: ${url}`);
}

async function waitUntil(predicate: () => boolean, timeoutMs = 5_000, label = "condition"): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 40));
  }
  if (!predicate()) {
    throw new Error(`Timed out waiting for ${label}`);
  }
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
}

test(
  "WhatsApp plugin: GET verification, HMAC enforcement, allowlist filtering, inbound CloudEvent, and outbound Graph API post",
  { timeout: 15_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "hyphae-wa-"));
    const waPort = await freePort();

    const appSecret = "wa-test-app-secret-123";
    const verifyToken = "wa-verify-token-xyz";
    const accessToken = "wa-bearer-access-token-999";

    const appSecretFile = join(dir, "wa-app.secret");
    const accessTokenFile = join(dir, "wa-access.token");
    writeFileSync(appSecretFile, appSecret + "\n", { mode: 0o600 });
    writeFileSync(accessTokenFile, accessToken + "\n", { mode: 0o600 });
    chmodSync(appSecretFile, 0o600);
    chmodSync(accessTokenFile, 0o600);

    // Local mock Meta Graph API server
    const graphRequests: Array<{
      method: string | undefined;
      url: string | undefined;
      authorization: string | undefined;
      body: Record<string, unknown>;
    }> = [];
    const mockGraph = createHttpServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
      graphRequests.push({
        method: req.method,
        url: req.url,
        authorization: req.headers["authorization"],
        body,
      });
      res
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ messaging_product: "whatsapp", messages: [{ id: "wamid.out.42" }] }));
    });
    await new Promise<void>((resolve) => mockGraph.listen(0, "127.0.0.1", () => resolve()));
    const mockAddr = mockGraph.address();
    assert.ok(mockAddr && typeof mockAddr === "object");
    const mockBaseUrl = `http://127.0.0.1:${mockAddr.port}/v21.0`;

    const receivedBatches: InboundEventBatch[] = [];
    const plugins = new Plugins({
      dbPath: join(dir, "local.db"),
      plugins: [
        {
          name: "whatsapp",
          exec: process.execPath,
          args: [join(process.cwd(), "plugins", "whatsapp", "index.mjs")],
          cwd: dir,
          env: {
            WHATSAPP_HOST: "127.0.0.1",
            WHATSAPP_PORT: String(waPort),
            WHATSAPP_PATH: "/whatsapp",
            WHATSAPP_TARGET: "whatsapp",
            WHATSAPP_VERIFY_TOKEN: verifyToken,
            WHATSAPP_APP_SECRET_FILE: appSecretFile,
            WHATSAPP_ACCESS_TOKEN_FILE: accessTokenFile,
            WHATSAPP_ALLOWED_NUMBERS: "+1 (555) 123-4567",
            WHATSAPP_API_BASE: mockBaseUrl,
          },
          targets: [
            {
              name: "whatsapp",
              threadId: "thread-wa",
              coalesceSeconds: 0,
              maxWaitSeconds: 5,
              wakesPerHour: 120,
            },
          ],
        },
      ],
    });

    plugins.attach(async (batch) => {
      receivedBatches.push(batch);
      return { kind: "delivered" };
    });
    plugins.start();

    try {
      await waitForHttp(`http://127.0.0.1:${waPort}/health`);

      // 1. Meta GET verification challenge
      const badVerify = await fetch(
        `http://127.0.0.1:${waPort}/whatsapp?hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=chal-1`,
      );
      assert.equal(badVerify.status, 403);

      const missingChallenge = await fetch(
        `http://127.0.0.1:${waPort}/whatsapp?hub.mode=subscribe&hub.verify_token=${encodeURIComponent(verifyToken)}`,
      );
      assert.equal(missingChallenge.status, 400);

      const okVerify = await fetch(
        `http://127.0.0.1:${waPort}/whatsapp?hub.mode=subscribe&hub.verify_token=${encodeURIComponent(verifyToken)}&hub.challenge=challenge-token-777`,
      );
      assert.equal(okVerify.status, 200);
      assert.match(okVerify.headers.get("content-type") ?? "", /text\/plain/i);
      assert.equal(await okVerify.text(), "challenge-token-777");

      // 2. POST HMAC signature enforcement
      const samplePayload = JSON.stringify({
        object: "whatsapp_business_account",
        entry: [
          {
            id: "waba-1",
            changes: [
              {
                field: "messages",
                value: {
                  messaging_product: "whatsapp",
                  metadata: { display_phone_number: "15550001111", phone_number_id: "987654321" },
                  contacts: [
                    { wa_id: "15559999999", profile: { name: "Stranger" } },
                    { wa_id: "15551234567", profile: { name: "Alice" } },
                  ],
                  messages: [
                    {
                      from: "15559999999",
                      id: "wamid.stranger.1",
                      timestamp: "1732438100",
                      type: "text",
                      text: { body: "Ignore me!" },
                    },
                    {
                      from: "15551234567",
                      id: "wamid.in.1",
                      timestamp: "1732438200",
                      type: "text",
                      text: { body: "Deploy status?" },
                    },
                  ],
                },
              },
            ],
          },
        ],
      });

      const noSigRes = await fetch(`http://127.0.0.1:${waPort}/whatsapp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: samplePayload,
      });
      assert.equal(noSigRes.status, 401);

      const badSigRes = await fetch(`http://127.0.0.1:${waPort}/whatsapp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-hub-signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        },
        body: samplePayload,
      });
      assert.equal(badSigRes.status, 401);

      // 3. Valid HMAC + allowlist filtering
      const validSig = "sha256=" + createHmac("sha256", appSecret).update(samplePayload).digest("hex");
      const okPost = await fetch(`http://127.0.0.1:${waPort}/whatsapp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-hub-signature-256": validSig,
        },
        body: samplePayload,
      });
      assert.equal(okPost.status, 200);
      assert.deepEqual(await okPost.json(), { ok: true, delivered: 1, ignored: 1 });

      await waitUntil(() => receivedBatches.length >= 1, 5_000, "WhatsApp CloudEvent delivery");
      assert.equal(receivedBatches.length, 1);
      assert.equal(receivedBatches[0].events.length, 1);

      const ev = receivedBatches[0].events[0];
      assert.equal(ev.specversion, "1.0");
      assert.equal(ev.id, "wamid.in.1");
      assert.equal(ev.type, "com.whatsapp.message.received");
      assert.equal(ev.source, "whatsapp/987654321");
      assert.equal(ev.subject, "wa/15551234567");
      assert.equal(ev.time, new Date(1732438200 * 1000).toISOString());
      assert.equal(ev.datacontenttype, "application/json");
      assert.deepEqual(ev.data, {
        from: "15551234567",
        name: "Alice",
        message_id: "wamid.in.1",
        type: "text",
        text: "Deploy status?",
        phone_number_id: "987654321",
      });

      // 4. Outbound post via Plugins.request hits local mock Graph API using remembered sender & phone_number_id
      const postRes = await plugins.request("whatsapp", "post", "whatsapp", {
        text: "Deploy green!",
        replyTo: "wamid.1",
      });
      assert.deepEqual(postRes, {
        ok: true,
        result: {
          ok: true,
          to: "15551234567",
          messageId: "wamid.out.42",
          phoneNumberId: "987654321",
        },
      });
      assert.equal(graphRequests.length, 1);
      assert.equal(graphRequests[0].method, "POST");
      assert.equal(graphRequests[0].url, "/v21.0/987654321/messages");
      assert.equal(graphRequests[0].authorization, `Bearer ${accessToken}`);
      assert.deepEqual(graphRequests[0].body, {
        messaging_product: "whatsapp",
        recipient_type: "individual",
        to: "15551234567",
        type: "text",
        text: { preview_url: false, body: "Deploy green!" },
        context: { message_id: "wamid.1" },
      });

      // 5. Outbound post to non-allowlisted number fails closed without hitting Graph API
      const blockedRes = await plugins.request("whatsapp", "post", "whatsapp", {
        text: "Should be blocked",
        to: "+15559999999",
      });
      assert.equal(blockedRes.ok, false);
      if (!blockedRes.ok) {
        assert.match(blockedRes.error, /WHATSAPP_ALLOWED_NUMBERS/);
      }
      assert.equal(graphRequests.length, 1);
    } finally {
      await plugins.stop();
      await closeServer(mockGraph);
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "Prometheus Alertmanager plugin: Bearer + HMAC auth and RouterCore CloudEvent filtering for firing/resolved alerts",
  { timeout: 15_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "hyphae-prom-"));
    const promPort = await freePort();

    const bearerToken = "prom-bearer-secret-42";
    const webhookSecret = "prom-hmac-secret-99";
    const bearerFile = join(dir, "prom-bearer.token");
    writeFileSync(bearerFile, bearerToken + "\n", { mode: 0o600 });
    chmodSync(bearerFile, 0o600);

    const streams: RouterStreamConfig[] = [
      {
        name: "prometheus",
        topic: "alerts",
        exec: process.execPath,
        args: [join(process.cwd(), "plugins", "prometheus", "index.mjs")],
        env: {
          PROMETHEUS_HOST: "127.0.0.1",
          PROMETHEUS_PORT: String(promPort),
          PROMETHEUS_PATH: "/alerts",
          PROMETHEUS_TOPIC: "alerts",
          PROMETHEUS_BEARER_TOKEN_FILE: bearerFile,
          PROMETHEUS_WEBHOOK_SECRET: webhookSecret,
        },
        cwd: dir,
      },
    ];

    const core = new RouterCore({
      dbPath: join(dir, "router.sqlite"),
      topics: buildStreamTopicMap(streams),
    });
    core.addConnector("oncall@ops");

    // Subscribe only to critical alerts via CloudEvents prefix filter on `subject`
    const subRes = core.events.setSubscriptions("oncall@ops", [
      {
        id: randomUUID(),
        topic: "alerts",
        filters: [{ prefix: { subject: "severity=critical" } }],
        coalesceSeconds: 0,
      },
    ]);
    assert.equal(subRes.ok, true);

    const receivedEvents: CloudEvent[] = [];
    const detach = core.attach("oncall@ops", (item) => {
      if (item.kind === "event") {
        receivedEvents.push(...item.events);
        core.ack("oncall@ops", item.id, { kind: "delivered" });
      }
    });

    const streamHost = new RouterStreamHost(core, "http://127.0.0.1:0", streams);
    await streamHost.start();

    const postSigned = (raw: string, opts: { token?: string; sig?: string } = {}) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (opts.token !== undefined) headers["authorization"] = `Bearer ${opts.token}`;
      if (opts.sig !== undefined) headers["x-webhook-signature-256"] = opts.sig;
      return fetch(`http://127.0.0.1:${promPort}/alerts`, {
        method: "POST",
        headers,
        body: raw,
      });
    };

    try {
      await waitForHttp(`http://127.0.0.1:${promPort}/health`);
      const healthRes = await fetch(`http://127.0.0.1:${promPort}/health`);
      assert.equal(healthRes.status, 200);
      assert.deepEqual(await healthRes.json(), { ok: true });

      const firingPayload = JSON.stringify({
        version: "4",
        receiver: "hyphae-oncall",
        status: "firing",
        groupLabels: { service: "checkout" },
        commonLabels: { env: "prod" },
        commonAnnotations: { runbook: "https://runbooks.internal/checkout" },
        externalURL: "http://alertmanager.internal:9093",
        alerts: [
          {
            status: "firing",
            fingerprint: "fp-crit-01",
            labels: {
              alertname: "HighErrorRate",
              severity: "critical",
              service: "checkout",
              instance: "10.0.0.12:8080",
            },
            annotations: {
              summary: "Checkout 5xx error rate above 5%",
              description: "Checkout API returning 503 responses for 5m",
            },
            startsAt: "2026-11-24T08:00:00Z",
            endsAt: "0001-01-01T00:00:00Z",
            generatorURL: "http://prometheus.internal:9090/graph?g0.expr=http_5xx",
          },
          {
            status: "firing",
            fingerprint: "fp-warn-02",
            labels: {
              alertname: "DiskSpaceWarning",
              severity: "warning",
              job: "node-exporter",
              instance: "10.0.0.15:9100",
            },
            annotations: {
              summary: "Disk usage at 82%",
            },
            startsAt: "2026-11-24T08:01:00Z",
            endsAt: "0001-01-01T00:00:00Z",
          },
        ],
      });
      const firingSig = "sha256=" + createHmac("sha256", webhookSecret).update(firingPayload).digest("hex");

      // 1. Auth enforcement: bad/missing Bearer token & bad HMAC must return 401
      const noAuth = await postSigned(firingPayload, { sig: firingSig });
      assert.equal(noAuth.status, 401);

      const badBearer = await postSigned(firingPayload, { token: "wrong-token", sig: firingSig });
      assert.equal(badBearer.status, 401);

      const badHmac = await postSigned(firingPayload, { token: bearerToken, sig: "sha256=deadbeef" });
      assert.equal(badHmac.status, 401);

      // 2. Valid Bearer + HMAC delivers firing critical + warning alerts (2 processed)
      const okFiring = await postSigned(firingPayload, { token: bearerToken, sig: firingSig });
      assert.equal(okFiring.status, 200);
      assert.deepEqual(await okFiring.json(), { ok: true, alerts: 2 });

      // 3. Send resolved critical alert
      const resolvedPayload = JSON.stringify({
        version: "4",
        receiver: "hyphae-oncall",
        status: "resolved",
        commonLabels: { env: "prod" },
        commonAnnotations: { runbook: "https://runbooks.internal/checkout" },
        externalURL: "http://alertmanager.internal:9093",
        alerts: [
          {
            status: "resolved",
            fingerprint: "fp-crit-01",
            labels: {
              alertname: "HighErrorRate",
              severity: "critical",
              service: "checkout",
              instance: "10.0.0.12:8080",
            },
            annotations: {
              summary: "Checkout 5xx error rate recovered",
              description: "Error rate back below 0.5%",
            },
            startsAt: "2026-11-24T08:00:00Z",
            endsAt: "2026-11-24T08:05:00Z",
            generatorURL: "http://prometheus.internal:9090/graph?g0.expr=http_5xx",
          },
        ],
      });
      const resolvedSig = "sha256=" + createHmac("sha256", webhookSecret).update(resolvedPayload).digest("hex");
      const okResolved = await postSigned(resolvedPayload, { token: bearerToken, sig: resolvedSig });
      assert.equal(okResolved.status, 200);
      assert.deepEqual(await okResolved.json(), { ok: true, alerts: 1 });

      // 4. Verify subscriber receives ONLY the 2 critical events (firing + resolved), NOT the warning alert
      await waitUntil(() => receivedEvents.length >= 2, 5_000, "critical Prometheus events");
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(receivedEvents.length, 2);

      const [firingEv, resolvedEv] = receivedEvents;

      assert.equal(firingEv.specversion, "1.0");
      assert.equal(firingEv.id, "fp-crit-01:firing:2026-11-24T08:00:00Z");
      assert.equal(firingEv.type, "io.prometheus.alert.firing");
      assert.equal(firingEv.source, "prometheus/alertmanager");
      assert.equal(firingEv.subject, "severity=critical/HighErrorRate");
      assert.equal(firingEv.time, "2026-11-24T08:00:00Z");
      assert.equal(firingEv.datacontenttype, "application/json");
      assert.deepEqual(firingEv.data, {
        status: "firing",
        alertname: "HighErrorRate",
        severity: "critical",
        service: "checkout",
        instance: "10.0.0.12:8080",
        summary: "Checkout 5xx error rate above 5%",
        description: "Checkout API returning 503 responses for 5m",
        labels: {
          env: "prod",
          alertname: "HighErrorRate",
          severity: "critical",
          service: "checkout",
          instance: "10.0.0.12:8080",
        },
        annotations: {
          runbook: "https://runbooks.internal/checkout",
          summary: "Checkout 5xx error rate above 5%",
          description: "Checkout API returning 503 responses for 5m",
        },
        startsAt: "2026-11-24T08:00:00Z",
        endsAt: "0001-01-01T00:00:00Z",
        generatorURL: "http://prometheus.internal:9090/graph?g0.expr=http_5xx",
        receiver: "hyphae-oncall",
        externalURL: "http://alertmanager.internal:9093",
      });

      assert.equal(resolvedEv.specversion, "1.0");
      assert.equal(resolvedEv.id, "fp-crit-01:resolved:2026-11-24T08:00:00Z");
      assert.equal(resolvedEv.type, "io.prometheus.alert.resolved");
      assert.equal(resolvedEv.source, "prometheus/alertmanager");
      assert.equal(resolvedEv.subject, "severity=critical/HighErrorRate");
      assert.equal(resolvedEv.time, "2026-11-24T08:05:00Z");
      assert.equal(resolvedEv.datacontenttype, "application/json");
      assert.equal(resolvedEv.data["status"], "resolved");
      assert.equal(resolvedEv.data["alertname"], "HighErrorRate");
      assert.equal(resolvedEv.data["severity"], "critical");
      assert.equal(resolvedEv.data["endsAt"], "2026-11-24T08:05:00Z");

      // Confirm warning alert was never delivered
      assert.equal(
        receivedEvents.some((e) => e.subject?.includes("DiskSpaceWarning")),
        false,
      );
    } finally {
      detach();
      await streamHost.stop();
      core.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
