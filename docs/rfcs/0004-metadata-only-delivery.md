# RFC 0004: Metadata-Only Delivery

- **Status:** Implemented
- **Date:** 2026-11-26 (UTC)
- **Decided by:** Bogdan (direction), implemented in `hyp` (#49)

## Summary

Hooks and wake nudges stop carrying message or event content. Every delivery becomes a small XML digest of counts. An agent reads content only by calling `hyp_inbox`.

## Why

- **Untrusted text enters context only on request.** Today `interrupt` and `queue` items are injected inline. With event-source plugins (mail, calendar, Sentry) that means a stranger's subject line and preview land in an agent's context automatically.
- **One rule for every source.** Today the Security Gate floors plugin events to `notify` to keep their text out. That also stops them waking a thread: on 2026-11-26 a one-time code, seven mails and a calendar reminder all sat unseen until the user nudged the session. If no delivery carries text, the floor is unnecessary.
- **Smaller, predictable hook output.** A digest is a few lines regardless of how much arrived.

## Behaviour per tier

| Tier | Trigger | Transport | Payload |
| --- | --- | --- | --- |
| `interrupt` | on arrival, including mid-turn | hook injection at the next tool boundary; wake nudge if idle | digest |
| `queue` | turn end, idle timeout, or long-turn mid-turn reminder (default every 30 min, tuneable) | wake nudge message; hook injection at turn boundary or periodic `PostToolUse` reminder during long active turns | digest |
| `notify` | never on its own | rides along on the next digest | counted in the digest |
| `mute` | never | rides along on the next digest | one muted counter |

A digest sent while a turn is active is the same digest the wake nudge would have carried: one renderer, two transports. If a hook delivers it, the pending wake nudge for those items is cancelled.

## Digest format

```xml
<hyphae-inbox handle="plugins-dev" unread="4" urgency="queue">
  <dm from="bogdan@macbook/concierge" count="1"/>
  <channel name="#incidents" count="1"/>
  <bridge target="telegram:moneypenny0bot" count="1"/>
  <stream subscription="gmail:bowd" topic="local.gmail" count="2"/>
  <muted count="3"/>
</hyphae-inbox>
```

- `urgency` is the highest tier among the counted items.
- DMs, channels and bridges are grouped by source; stream events by subscription key (falling back to topic when the subscription has no key).
- Attribute values are node-generated identifiers. Sender display names, subjects and bodies never appear.
- `human-verified` items get `verified="true"` on their element so an agent can prioritise them without reading them.

## Reading

- `hyp_inbox` is the only way content reaches an agent. It already supports filters, limits, summaries and ack.
- Every returned item states its trust tier, so untrusted content is labelled at the moment it is read.
- Target: a filtered `hyp_inbox` read returns in well under 100 ms locally, since every message now costs one call.

## Security Gate changes

- Remove the Stage 1 "downgrade to notify" for the `external-webhook` and `guest` tiers. Replace it with a cap: those tiers may not use `interrupt` (it becomes `queue`).
- Quarantine and block decisions are unchanged. Quarantined items are not counted in any digest.
- Burst protection is unchanged: a source exceeding the per-minute threshold is still demoted to `notify`.

## What changes for users

- Messages from trusted sources (your own Telegram, DMs between your agents) no longer appear inline. An agent needs one tool call before it can answer.
- Harness skills must say: a digest means "call `hyp_inbox`", not "the message is above".

## Scope of work

1. `delivery/packer.rs`: replace inline rendering with the digest renderer.
2. Daemon delivery paths and hook output for all nine harnesses; cancel a pending nudge when a hook delivers the same items.
3. Wake nudges: same digest body as hooks (they are already XML and metadata-only).
4. Gate Stage 1 tier policy as above.
5. Skills (`hyphae`, `hyphae-setup`, per-harness variants) and docs (`concepts.md`, `reference/mcp-tools.md`, site copy on delivery tiers).
6. Tests: the delivery and cross-harness suites assert on inline text today and need rewriting against the digest; add tests that no body text of any tier appears in hook output.

## Decisions (settled)

1. ~~Should `interrupt` from a trusted peer still be allowed to carry one line of content?~~ **Decided 2026-11-26 (Bogdan): digest only is absolute for now, for every source and tier. Revisit once it has been used.**
2. ~~Does a digest list every subscription, or only those with unread items?~~ **Decided 2026-11-26 (Bogdan): only subscriptions and sources with unread items are listed.**
3. ~~Should reading with `hyp_inbox` ack by default?~~ **Decided 2026-11-26 (Bogdan): yes. Reading acknowledges by default; passing `ack: false` peeks without acknowledging.**
4. **Long-turn mid-turn `queue` digest reminder (Decided 2026-11-26, Bogdan):** During long active turns where `Stop` has not fired yet, inject a periodic `<hyphae-inbox>` digest on `PostToolUse` when unread `queue` items are waiting, gated by a tuneable interval (default **30 minutes** since the oldest un-reminded `queue` item arrived / last mid-turn reminder; configurable per node/session, `0` to disable). Items stay `unread` until read via `hyp_inbox` and never re-inject between intervals.
