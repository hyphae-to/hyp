# Delivery Engine, Batch Packing & Wakeup Ladder

Implemented in `crates/hyp-node/src/delivery/` (`policy.rs`, `burst.rs`, `packer.rs`, `inbox_query.rs`) and `crates/hyp-harness/src/daemon.rs`.

Every inbound source entering a local node — DMs, `#channels` / `#announcements`, stream subscriptions, `localIngest` triggers, and chat bridges — commits durably to `node.sqlite` before upstream ack and flows through one unified delivery engine.

---

## 1. Four Delivery Tiers

| Tier | Behavior | Typical Use |
| --- | --- | --- |
| **`interrupt`** | Wakes an active or idle session immediately via native transport. | `@oncall`, `#incidents`, critical alerts |
| **`queue`** *(default)* | Coalesces arrivals and delivers cleanly at the next turn or hook boundary. | Normal DMs, PR reviews, team `#channels` |
| **`notify`** | Holds full payload `unread` in local inbox and attaches a slim 1-line digest at the next turn/idle boundary. | Focus Mode (`* -> notify`), high-volume streams |
| **`mute`** | Archives silently (`state = "muted"`) — never wakes or emits standalone digests; piggybacks `· N muted` onto other deliveries and remains queryable via `hyp_inbox({ state: "muted" })`. | Noisy channels or paused peers |

---

## 2. Focus Mode, Rules & Adaptive Burst Protection

- **Focus Mode & Per-Source Overrides:** `hyp_inbox({ mode: "notify", rules: [...] })` demotes `* -> notify` while evaluating specificity-ranked overrides (`@handle`, `<node>/<handle>`, `<node>/*`, `#channel`, `<node>.<topic>`, `topic:<topic>`, `<plugin>:<target>`, `*`).
- **Adaptive Burst Protection ("Noisy Mode"):** Exceeding `10` arrivals inside a `60s` rolling window per source engages a `300s` cooldown (`min_delivery_interval: 30s`), automatically stepping `interrupt`/`queue` floods down to `notify` digests (`mute` stays `mute`).

---

## 3. Token-Budget Hybrid Batch Packer & Framing Defense (`packer.rs`)

- **Budgets:** Defaults `max_batch_tokens = 1200` (~4,800 chars), `max_inline_items = 6`, `max_single_item_share = 0.60`.
- **Priority Ordering:** `interrupt` -> `queue` DM / `#announcement` -> `queue` `#channel` / stream -> `notify` / burst-demoted.
- **Inline vs. Spillover:** Packs highest-priority non-`notify` items inline in full, truncates single oversized items with a `hyp_inbox(ids:["..."])` pointer, and spills remaining items into a compact 1-line digest footer grouped by source (plus `· N muted` whenever muted items exist).
- **Untrusted Framing Neutralization:**
  - Every non-system item is wrapped with `[hyphae · <source>]` (or `[hyphae interrupt · <source>]`).
  - `sanitize_source_label` strips control characters, newlines, and BiDi overrides and converts `[`/`]` to `(`/`)`.
  - `sanitize_untrusted_body` prefixes any inbound body line starting with `---` or `[hyphae` with `> ` so untrusted peer/bridge/webhook text cannot forge sibling delivery blocks.
  - Only daemon-generated notices (such as metadata-only quarantine alerts) set `is_system_notice = true`.

---

## 4. Best-Effort Tier 1–3 Wakeup Ladder (+ Opt-In Tier 4)

1. **Tier 1 / 2 (Native Push & Blocking Waiters):** Live push via Herdr (`hc send`/`hc interrupt`), `codex queue`, T3 WebSocket RPC, OpenClaw Gateway hooks, OpenCode `session.idle` SDK prompt, `--claude-channel`, hooks (`PostToolUse`/`Stop`/`PreInvocation`), or blocking `hyp wait` / `hyp watch`.
2. **Tier 3 (Busy `Hold` Backoff & Durable Mailbox):** Busy turns enter bounded retry backoff (`5s -> 15s -> 30s -> 60s`), cancelled immediately when a hook drains first, and coalesce cleanly in SQLite with TTL.
3. **Tier 4 (Strictly Opt-In Cold Revival):** Offline sessions are never spawned unless explicitly opted in via `node.json` (`codexResume` or allowlisted `herdrSpawnAllowlist`).
