# Delivery Engine, Metadata-Only Digests & Wakeup Ladder

The node evaluates delivery policy, burst limits and inbox queries. The daemon screens pending receipts and commits notifications after delivery. The digest crate selects eligible metadata for each drain scope and renders the RFC 0004 XML. [Node policy](../../crates/hyp-node/src/delivery/) · [Daemon delivery](../../crates/hyp-harness/daemon/src/daemon/delivery.rs) · [Digest selection and rendering](../../crates/hyp-delivery-digest/src/)

Every inbound source entering a local node — DMs, `#channels` / `#announcements`, stream subscriptions, `localIngest` triggers, and chat bridges — commits durably to `node.sqlite` before upstream ack and flows through one unified metadata-only delivery engine.

---

## 1. Four Delivery Tiers

All four tiers emit the exact same compact `<hyphae-inbox>` XML count digest (never raw bodies, subjects, display names, or previews). Untrusted payload content enters an agent's context **only** when the agent calls `hyp_inbox` (which acknowledges returned unread items by default; pass `ack: false` to peek).

| Tier | Trigger | Payload | Typical Use |
| --- | --- | --- | --- |
| **`interrupt`** | On arrival, including mid-turn (`PostToolUse`) or push wake if idle. | `<hyphae-inbox ... urgency="interrupt">` digest | `@oncall`, `#incidents`, critical alerts |
| **`queue`** *(default)* | Turn end (`Stop`), idle push wake, or periodic long-turn `PostToolUse` reminder (default `1800`s / 30 min via `delivery.midturnQueueDigestSeconds`, `0` disables). | `<hyphae-inbox ... urgency="queue">` digest | Normal DMs, PR reviews, team `#channels`, external event plugins (Stage 1 `cap_to_queue`) |
| **`notify`** | Never wakes on its own; rides along on the next turn-start or higher-tier digest. | Counted in `<hyphae-inbox>` | Focus Mode (`* -> notify`), burst-demoted sources |
| **`mute`** | Never wakes or emits standalone digests; inspectable via `hyp_inbox({ state: "muted" })`. | `<muted count="N"/>` counter on other digests | Noisy channels or paused peers |

---

## 2. Focus Mode, Rules & Adaptive Burst Protection

- **Focus Mode & Per-Source Overrides:** `hyp_inbox({ mode: "notify", rules: [...] })` demotes `* -> notify` while evaluating specificity-ranked overrides (`@handle`, `<node>/<handle>`, `<node>/*`, `#channel`, `<node>.<topic>`, `topic:<topic>`, `<plugin>:<target>`, `*`). VIP `Interrupt` items bypass Focus Mode without leaking or acknowledging Focus-buffered items.
- **Stage 1 Trust-Tier Ceiling:** `Guest` and `ExternalWebhook` default to `cap_to_queue` (steps `interrupt` down to `queue`, allowing source plugins to wake idle threads safely via metadata-only digests while never interrupting mid-turn).
- **Adaptive Burst Protection ("Noisy Mode"):** Exceeding `10` arrivals inside a `60s` rolling window per source engages a `300s` cooldown (`min_delivery_interval: 30s`), automatically stepping `interrupt`/`queue` floods down to `notify` (`mute` stays `mute`).
- **Session Interrupt Cooldown:** An active hook-capable session gets the usual two-second grace for `PostToolUse` before the first external interrupt. After an interrupt-capable push succeeds or confirms it cancelled the turn, further interrupt pushes to that session wait five seconds. Hook digests and inbox reads continue during this window. At expiry the daemon rechecks deferred receipts and can wake the session for arrivals outside an earlier inbox snapshot, even without new traffic.

---

## 3. Unified Metadata-Only XML Digest Renderer (`packer.rs`)

Both hooks (`PreInvocation`/`UserPromptSubmit`, `PostToolUse`, `Stop`, etc.) and push wake transports (`Herdr`, `Codex Queue`, `T3 Code`, `OpenClaw`, Claude Code channels, `hyp wait`) render through `pack_inbox_digest`:

```xml
<hyphae-inbox handle="plugins-dev" unread="5" urgency="queue">
  <dm from="bogdan@macbook/concierge" count="1"/>
  <channel name="#incidents" count="1"/>
  <bridge target="telegram:moneypenny0bot" count="1"/>
  <stream subscription="gmail:bowd" topic="local.gmail" count="2"/>
  <muted count="3"/>
</hyphae-inbox>
```

- **Zero Body Leak:** `pack_inbox_digest` never reads `item.text`. Every attribute value strips control/BiDi characters and strictly XML-escapes `&`, `<`, `>`, `"`, `'`.
- **Unread-Only Listing:** Lists only sources/subscriptions with unread items; omits `<muted>` when 0; omits empty categories.
- **Verified & Quarantine Isolation:** `human-verified` items carry `verified="true"` in a separate group key (unverified items can never merge into a verified count). Quarantined items are never counted in `unread="..."` and surface at most once as a single `<quarantined count="N"/>` element; details stay in `hyp gate review` (and `hyp_inbox`'s `quarantinedNotices`).
- **At-Most-Once Watermark:** Delivering a digest via a hook, confirmed native push, or blocking waiter stamps counted receipts `notified = 1` (keeping items `unread` in SQLite until `hyp_inbox` reads them) and cancels any pending duplicate wake nudge.

---

## 4. Best-Effort Tier 1–3 Wakeup Ladder (+ Opt-In Tier 4)

1. **Tier 1 / 2 (Native Push & Blocking Waiters):** Live push via Herdr (`hc send`/`hc interrupt`), `codex queue`, T3 WebSocket RPC, OpenClaw Gateway (`hyphae-wake` / `/hooks/wake`), OpenCode `session.idle` SDK prompt, Claude Code channels, hooks (`PostToolUse`/`Stop`/`PreInvocation`), or blocking `hyp wait` / `hyp watch`. When available, proven push and armed waiters take precedence over Claude Code channels. Channel submission leaves receipt and hook state untouched. When a hook has observed activity, the sliding activity lease gives Stop or an inbox read time to handle the receipt. A receipt still awaiting a wake at lease expiry gets one idle wake through an available route. Native transports use queue mode for this wake.
2. **Tier 3 (Busy `Hold` Backoff & Durable Mailbox):** Busy turns enter bounded retry backoff (`5s -> 15s -> 30s -> 60s`), cancelled immediately when a hook drains first, and coalesce cleanly in SQLite with TTL.
3. **Tier 4 (Strictly Opt-In Cold Revival):** Offline sessions are never spawned unless explicitly opted in via `node.json` (`codexResume` or allowlisted `herdrSpawnAllowlist`), passing only the `<hyphae-inbox>` digest.

When Herdr interrupts Claude Code during a tool call, Claude Code can display the cancelled tool as a user rejection. A retry of `hyp_inbox` can retrieve any messages still unread after the cancellation.
