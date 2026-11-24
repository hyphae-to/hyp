import assert from "node:assert/strict";
import { test } from "node:test";
import { MeshTopology, waitFor } from "./harness/topology.ts";

test(
  "multi-router networked topology: shared Team Router + per-user Private Routers + 3 connectors (peers, #channels, isolated event routing)",
  { timeout: 25_000 },
  async () => {
    const topo = new MeshTopology("hyphae-net-");
    try {
      // Shared Team/Public Router with a `team-ci` event topic + two isolated per-user Private Routers
      const teamRouter = await topo.addRouter({
        name: "team",
        topics: new Map([["team-ci", ["ci-bot"]]]),
      });
      const alexPrivate = await topo.addRouter({
        name: "alex-private",
        topics: new Map([["personal", ["alex-cron"]]]),
      });
      const alicePrivate = await topo.addRouter({
        name: "alice-private",
        topics: new Map([["personal", ["alice-cron"]]]),
      });

      const teamCiToken = teamRouter.core.events.addPublisher("ci-bot", ["team-ci"]);
      const alexPrivToken = alexPrivate.core.events.addPublisher("alex-cron", ["personal"]);
      const alicePrivToken = alicePrivate.core.events.addPublisher("alice-cron", ["personal"]);

      // Three independent connector daemons across the mesh
      const alex = await topo.addConnector({
        connectorId: "alex@laptop",
        links: [
          { name: "primary", router: teamRouter },
          { name: "private", router: alexPrivate },
        ],
      });
      const alice = await topo.addConnector({
        connectorId: "alice@laptop",
        links: [
          { name: "primary", router: teamRouter },
          { name: "private", router: alicePrivate },
        ],
      });
      const jack = await topo.addConnector({
        connectorId: "jack@prod",
        links: [{ name: "primary", router: teamRouter }],
      });

      // Enroll sessions on all 3 connectors across different harnesses
      alex.daemon.state.register("claude:alex-1", { kind: "claude" });
      alice.daemon.state.register("antigravity:alice-1", { kind: "antigravity" });
      jack.daemon.state.register("codex:jack-1", { kind: "codex" });

      await alex.daemon.connector.call("claude:alex-1", "hyp_join", { handle: "dev" });
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_join", { handle: "ops" });
      await jack.daemon.connector.call("codex:jack-1", "hyp_join", { handle: "prod" });

      // 1. Cross-connector peer discovery via Team Router
      const peersRes = (await alex.daemon.connector.call("claude:alex-1", "hyp_peers", {})) as {
        self: string;
        peers: Array<{ address: string; online: boolean }>;
      };
      assert.equal(peersRes.self, "alex@laptop/dev");
      assert.deepEqual(
        peersRes.peers.map((p) => p.address).sort(),
        ["alex@laptop/dev", "alice@laptop/ops", "jack@prod/prod"],
      );

      // Verify capabilities report both configured routers for Alex and only primary for Jack
      const alexCaps = (await alex.daemon.connector.call("claude:alex-1", "hyp_capabilities", {})) as { routers: string[] };
      const jackCaps = (await jack.daemon.connector.call("codex:jack-1", "hyp_capabilities", {})) as { routers: string[] };
      assert.deepEqual(alexCaps.routers, ["primary", "private"]);
      assert.deepEqual(jackCaps.routers, ["primary"]);

      // 2. Cross-connector direct messaging (`hyp_send`) Alex -> Jack -> Alice
      await alex.daemon.connector.call("claude:alex-1", "hyp_send", {
        to: "jack@prod/prod",
        text: "deploy-check-from-alex",
      });
      const jackItems = await waitFor(
        () => {
          const drained = jack.daemon.connector.drainMailbox("codex:jack-1", 5);
          return drained.length > 0 ? drained : null;
        },
        { label: "Jack receiving Alex's direct message" },
      );
      assert.match(jackItems[0].text, /hyphae from alex@laptop\/dev/);
      assert.match(jackItems[0].text, /deploy-check-from-alex/);

      // 3. Cross-connector `#deploys` channel fan-out and leave
      await alex.daemon.connector.call("claude:alex-1", "hyp_channel_join", { channel: "#deploys" });
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_channel_join", { channel: "deploys" });
      const chJoin = (await jack.daemon.connector.call("codex:jack-1", "hyp_channel_join", { channel: "#deploys" })) as {
        channel: string;
        members: string[];
      };
      assert.equal(chJoin.channel, "#deploys");
      assert.deepEqual(chJoin.members, ["alex@laptop/dev", "alice@laptop/ops", "jack@prod/prod"]);

      const post1 = (await jack.daemon.connector.call("codex:jack-1", "hyp_channel_post", {
        channel: "#deploys",
        text: "v2.4.1 rolling out to eu-west",
      })) as { deliveredTo: string[] };
      assert.deepEqual(post1.deliveredTo, ["alex@laptop/dev", "alice@laptop/ops"]);

      const [alexChMsg, aliceChMsg] = await Promise.all([
        waitFor(() => {
          const items = alex.daemon.connector.drainMailbox("claude:alex-1", 5);
          return items.length > 0 ? items[0] : null;
        }, { label: "Alex #deploys fan-out" }),
        waitFor(() => {
          const items = alice.daemon.connector.drainMailbox("antigravity:alice-1", 5);
          return items.length > 0 ? items[0] : null;
        }, { label: "Alice #deploys fan-out" }),
      ]);
      assert.match(alexChMsg.text, /\[#deploys\] v2\.4\.1 rolling out/);
      assert.match(aliceChMsg.text, /\[#deploys\] v2\.4\.1 rolling out/);
      // Poster does not receive echo
      assert.equal(jack.daemon.state.pendingCount("codex:jack-1"), 0);

      // Alice leaves #deploys -> next post goes only to Alex
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_channel_leave", { channel: "#deploys" });
      const post2 = (await jack.daemon.connector.call("codex:jack-1", "hyp_channel_post", {
        channel: "#deploys",
        text: "rollout complete",
      })) as { deliveredTo: string[] };
      assert.deepEqual(post2.deliveredTo, ["alex@laptop/dev"]);

      const alexChMsg2 = await waitFor(() => {
        const items = alex.daemon.connector.drainMailbox("claude:alex-1", 5);
        return items.length > 0 ? items[0] : null;
      }, { label: "Alex second #deploys post" });
      assert.match(alexChMsg2.text, /rollout complete/);
      assert.equal(alice.daemon.state.pendingCount("antigravity:alice-1"), 0);

      // 4. Multi-router event subscriptions with strict private-router isolation
      await alex.daemon.connector.call("claude:alex-1", "hyp_subscribe", {
        key: "team:ci",
        router: "primary",
        topic: "team-ci",
        filters: [{ exact: { type: "com.ci.failed" } }],
        coalesceSeconds: 0,
      });
      await alex.daemon.connector.call("claude:alex-1", "hyp_subscribe", {
        key: "priv:notes",
        router: "private",
        topic: "personal",
        filters: [{ prefix: { type: "com.personal." } }],
        coalesceSeconds: 0,
      });
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_subscribe", {
        key: "team:ci",
        router: "primary",
        topic: "team-ci",
        filters: [{ exact: { type: "com.ci.failed" } }],
        coalesceSeconds: 0,
      });
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_subscribe", {
        key: "priv:notes",
        router: "private",
        topic: "personal",
        filters: [{ prefix: { type: "com.personal." } }],
        coalesceSeconds: 0,
      });

      // Publish a Team CI failure -> both Alex and Alice receive it
      const publishEvent = async (routerUrl: string, token: string, topic: string, event: Record<string, unknown>) => {
        const res = await fetch(`${routerUrl}/v1/events?topic=${encodeURIComponent(topic)}`, {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify(event),
        });
        assert.equal(res.status, 202, `Expected 202 publishing to ${topic}, got ${res.status}`);
      };

      await publishEvent(teamRouter.url, teamCiToken, "team-ci", {
        specversion: "1.0",
        id: "ci-evt-1",
        source: "ci/team",
        type: "com.ci.failed",
        datacontenttype: "application/json",
        data: { build: "team-build-77" },
      });
      // Publish a private event on Alex's Private Router -> ONLY Alex receives it, NEVER Alice!
      await publishEvent(alexPrivate.url, alexPrivToken, "personal", {
        specversion: "1.0",
        id: "alex-priv-1",
        source: "cron/alex",
        type: "com.personal.reminder",
        datacontenttype: "application/json",
        data: { note: "alex-private-secret-reminder" },
      });
      // Publish a private event on Alice's Private Router -> ONLY Alice receives it, NEVER Alex!
      await publishEvent(alicePrivate.url, alicePrivToken, "personal", {
        specversion: "1.0",
        id: "alice-priv-1",
        source: "cron/alice",
        type: "com.personal.reminder",
        datacontenttype: "application/json",
        data: { note: "alice-private-secret-reminder" },
      });

      const alexEvents = await waitFor(
        () => (alex.daemon.state.pendingCount("claude:alex-1") >= 2 ? alex.daemon.connector.drainMailbox("claude:alex-1", 10) : null),
        { label: "Alex team + private events" },
      );
      const aliceEvents = await waitFor(
        () => (alice.daemon.state.pendingCount("antigravity:alice-1") >= 2 ? alice.daemon.connector.drainMailbox("antigravity:alice-1", 10) : null),
        { label: "Alice team + private events" },
      );

      const alexJoined = alexEvents.map((e) => e.text).join("\n");
      const aliceJoined = aliceEvents.map((e) => e.text).join("\n");

      assert.match(alexJoined, /team-build-77/);
      assert.match(alexJoined, /alex-private-secret-reminder/);
      assert.doesNotMatch(alexJoined, /alice-private-secret-reminder/);

      assert.match(aliceJoined, /team-build-77/);
      assert.match(aliceJoined, /alice-private-secret-reminder/);
      assert.doesNotMatch(aliceJoined, /alex-private-secret-reminder/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "connector-level and session-level muting across peer, connector/*, #channel, and topic:* with hyp_mutes/hyp_unmute",
  { timeout: 20_000 },
  async () => {
    const topo = new MeshTopology("hyphae-mutes-");
    try {
      const router = await topo.addRouter({
        name: "team",
        topics: new Map([["metrics", ["prom"]]]),
      });
      const promToken = router.core.events.addPublisher("prom", ["metrics"]);

      const receiver = await topo.addConnector({
        connectorId: "alex@laptop",
        links: [{ name: "primary", router }],
      });
      const noisy = await topo.addConnector({
        connectorId: "noisy@prod",
        links: [{ name: "primary", router }],
      });
      const ally = await topo.addConnector({
        connectorId: "alice@laptop",
        links: [{ name: "primary", router }],
      });

      // Two distinct local sessions on receiver's connector (`alex@laptop/main` and `alex@laptop/side`)
      receiver.daemon.state.register("claude:main", { kind: "claude" });
      receiver.daemon.state.register("antigravity:side", { kind: "antigravity" });
      await receiver.daemon.connector.call("claude:main", "hyp_join", { handle: "main" });
      await receiver.daemon.connector.call("antigravity:side", "hyp_join", { handle: "side" });

      noisy.daemon.state.register("codex:n1", { kind: "codex" });
      noisy.daemon.state.register("codex:n2", { kind: "codex" });
      await noisy.daemon.connector.call("codex:n1", "hyp_join", { handle: "bot1" });
      await noisy.daemon.connector.call("codex:n2", "hyp_join", { handle: "bot2" });

      ally.daemon.state.register("claude:ally", { kind: "claude" });
      await ally.daemon.connector.call("claude:ally", "hyp_join", { handle: "ally" });

      // Join #chatter and subscribe to topic:metrics on both receiver sessions
      for (const sid of ["claude:main", "antigravity:side"]) {
        await receiver.daemon.connector.call(sid, "hyp_channel_join", { channel: "#chatter" });
        await receiver.daemon.connector.call(sid, "hyp_subscribe", {
          key: "ops:metrics",
          topic: "metrics",
          filters: [{ exact: { type: "com.metrics.spike" } }],
          coalesceSeconds: 0,
        });
      }
      await ally.daemon.connector.call("claude:ally", "hyp_channel_join", { channel: "#chatter" });

      // 1. Connector-level wildcard mute `noisy@prod/*` drops BOTH bot1 & bot2 for ALL local sessions on alex@laptop
      await receiver.daemon.connector.call("claude:main", "hyp_mute", { target: "noisy@prod/*" });
      // 2. Session-level mute of `alice@laptop/ally` ONLY on `claude:main` (side still receives ally!)
      await receiver.daemon.connector.call("claude:main", "hyp_mute", { target: "alice@laptop/ally", scope: "session" });
      // 3. Connector-level `#chatter` and `topic:metrics` mutes
      await receiver.daemon.connector.call("claude:main", "hyp_mute", { target: "#chatter" });
      await receiver.daemon.connector.call("claude:main", "hyp_mute", { target: "topic:metrics" });

      const mainMutes = (await receiver.daemon.connector.call("claude:main", "hyp_mutes", {})) as {
        mutes: Array<{ pattern: string; scope: string }>;
      };
      const sideMutes = (await receiver.daemon.connector.call("antigravity:side", "hyp_mutes", {})) as {
        mutes: Array<{ pattern: string; scope: string }>;
      };
      assert.equal(mainMutes.mutes.length, 4);
      assert.equal(sideMutes.mutes.length, 3); // connector-scoped rules only, not main's session rule!

      // Fire messages from noisy@prod/bot1, noisy@prod/bot2, #chatter, topic:metrics, AND direct from ally
      await noisy.daemon.connector.call("codex:n1", "hyp_send", { to: "alex@laptop/main", text: "blocked-wildcard-1" });
      await noisy.daemon.connector.call("codex:n2", "hyp_send", { to: "alex@laptop/side", text: "blocked-wildcard-2" });
      await ally.daemon.connector.call("claude:ally", "hyp_channel_post", { channel: "#chatter", text: "blocked-channel" });
      await ally.daemon.connector.call("claude:ally", "hyp_send", { to: "alex@laptop/main", text: "blocked-session-peer" });
      await ally.daemon.connector.call("claude:ally", "hyp_send", { to: "alex@laptop/side", text: "allowed-for-side" });

      const ev1Res = await fetch(`${router.url}/v1/events?topic=metrics`, {
        method: "POST",
        headers: { authorization: `Bearer ${promToken}`, "content-type": "application/json" },
        body: JSON.stringify({
          specversion: "1.0",
          id: "m-1",
          source: "prom/prod",
          type: "com.metrics.spike",
          datacontenttype: "application/json",
          data: { cpu: 99 },
        }),
      });
      assert.equal(ev1Res.status, 202);

      // Side session receives ONLY ally's direct message (wildcard, #chatter, topic:metrics all dropped)
      const sideItems = await waitFor(
        () => (receiver.daemon.state.pendingCount("antigravity:side") >= 1 ? receiver.daemon.connector.drainMailbox("antigravity:side", 10) : null),
        { label: "side session receiving unmuted ally message" },
      );
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(sideItems.length, 1);
      assert.match(sideItems[0].text, /allowed-for-side/);
      assert.equal(receiver.daemon.state.pendingCount("claude:main"), 0);

      // Unmute `noisy@prod/*` and `topic:metrics` -> delivery resumes immediately
      await receiver.daemon.connector.call("claude:main", "hyp_unmute", { target: "noisy@prod/*" });
      await receiver.daemon.connector.call("claude:main", "hyp_unmute", { target: "topic:metrics" });

      await noisy.daemon.connector.call("codex:n1", "hyp_send", { to: "alex@laptop/main", text: "resumed-after-unmute" });
      const ev2Res = await fetch(`${router.url}/v1/events?topic=metrics`, {
        method: "POST",
        headers: { authorization: `Bearer ${promToken}`, "content-type": "application/json" },
        body: JSON.stringify({
          specversion: "1.0",
          id: "m-2",
          source: "prom/prod",
          type: "com.metrics.spike",
          datacontenttype: "application/json",
          data: { cpu: 88 },
        }),
      });
      assert.equal(ev2Res.status, 202);

      const resumed = await waitFor(
        () => (receiver.daemon.state.pendingCount("claude:main") >= 2 ? receiver.daemon.connector.drainMailbox("claude:main", 10) : null),
        { label: "main session receiving unmuted peer + topic event" },
      );
      const joined = resumed.map((i) => i.text).join("\n");
      assert.match(joined, /resumed-after-unmute/);
      assert.match(joined, /"cpu":88/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "slim notify mode end-to-end with real hyp wait & hyp watch push wakeup, hyp_inbox read/ack, and switching back to full mode",
  { timeout: 20_000 },
  async () => {
    const topo = new MeshTopology("hyphae-notify-e2e-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({ connectorId: "alex@laptop", links: [{ name: "primary", router }] });
      const alice = await topo.addConnector({ connectorId: "alice@laptop", links: [{ name: "primary", router }] });

      alex.daemon.state.register("antigravity:reader", { kind: "antigravity" });
      alice.daemon.state.register("claude:sender", { kind: "claude" });
      await alex.daemon.connector.call("antigravity:reader", "hyp_join", { handle: "reader" });
      await alice.daemon.connector.call("claude:sender", "hyp_join", { handle: "sender" });

      // Enable slim notification mode
      const modeRes = await alex.daemon.connector.call("antigravity:reader", "hyp_mode", { mode: "notify" });
      assert.deepEqual(modeRes, { deliveryMode: "notify", unread: 0 });

      // Arm a REAL blocking `hyp wait` CLI subprocess (using ANTIGRAVITY_SOURCE_METADATA auto-inference!)
      const waiter = alex.spawnWait({
        env: {
          ...process.env,
          ANTIGRAVITY_SOURCE_METADATA: JSON.stringify({ tool: { conversationId: "reader" } }),
        },
        timeoutSeconds: 10,
      });

      await waitFor(
        () => alex.daemon.connector.sessionStatus("antigravity:reader")?.hasLiveTransport === true,
        { label: "hyp wait attaching to daemon" },
      );

      // Alice sends a message with sensitive/large body; waiter wakes with ONLY a slim unread digest!
      await alice.daemon.connector.call("claude:sender", "hyp_send", {
        to: "alex@laptop/reader",
        text: "CONFIDENTIAL_BODY_PAYLOAD_ALPHA",
      });

      const waitRes = await waiter.output;
      assert.equal(waitRes.code, 0, `hyp wait exited ${waitRes.code}: ${waitRes.stderr}`);
      assert.match(waitRes.stdout, /hyphae notice · 1 unread \(1 message\) · from alice@laptop\/sender · call hyp_inbox to read/);
      assert.doesNotMatch(waitRes.stdout, /CONFIDENTIAL_BODY_PAYLOAD_ALPHA/);

      // Second message arrives while still in notify mode; start streaming `hyp watch`
      const watcher = alex.spawnWatch({ handle: "reader" });
      await waitFor(
        () => alex.daemon.connector.sessionStatus("antigravity:reader")?.hasLiveTransport === true,
        { label: "hyp watch attaching" },
      );

      await alice.daemon.connector.call("claude:sender", "hyp_send", {
        to: "alex@laptop/reader",
        text: "CONFIDENTIAL_BODY_PAYLOAD_BETA",
      });

      const watchLine = await watcher.waitForLine((l) => l.includes("2 unread"));
      const parsedWatch = JSON.parse(watchLine) as { text: string };
      assert.match(parsedWatch.text, /hyphae notice · 2 unread \(2 messages\)/);
      assert.doesNotMatch(parsedWatch.text, /CONFIDENTIAL_BODY_PAYLOAD_BETA/);

      // Query hyp_inbox: returns both full payloads; acknowledge ONLY the first receipt
      const inbox1 = (await alex.daemon.connector.call("antigravity:reader", "hyp_inbox", {})) as {
        unread: number;
        items: Array<{ receipt: string; text: string }>;
      };
      assert.equal(inbox1.unread, 2);
      assert.equal(inbox1.items.length, 2);
      assert.match(inbox1.items[0].text, /CONFIDENTIAL_BODY_PAYLOAD_ALPHA/);
      assert.match(inbox1.items[1].text, /CONFIDENTIAL_BODY_PAYLOAD_BETA/);

      const inbox2 = (await alex.daemon.connector.call("antigravity:reader", "hyp_inbox", {
        acknowledge: [inbox1.items[0].receipt],
      })) as { unread: number; items: Array<{ receipt: string; text: string }> };
      assert.equal(inbox2.unread, 1);
      assert.equal(inbox2.items.length, 1);
      assert.match(inbox2.items[0].text, /CONFIDENTIAL_BODY_PAYLOAD_BETA/);

      // Switch back to `full` mode -> daemon automatically flushes the remaining unread full payload to `hyp watch`!
      const backToFull = (await alex.daemon.connector.call("antigravity:reader", "hyp_mode", { mode: "full" })) as {
        deliveryMode: string;
        unread: number;
      };
      assert.equal(backToFull.deliveryMode, "full");
      assert.equal(backToFull.unread, 0);

      const flushedLine = await watcher.waitForLine((l) => l.includes("CONFIDENTIAL_BODY_PAYLOAD_BETA"));
      const flushed = JSON.parse(flushedLine) as { text: string };
      assert.match(flushed.text, /CONFIDENTIAL_BODY_PAYLOAD_BETA/);
      watcher.stop();
      assert.equal(alex.daemon.state.pendingCount("antigravity:reader"), 0);
    } finally {
      await topo.cleanup();
    }
  },
);
