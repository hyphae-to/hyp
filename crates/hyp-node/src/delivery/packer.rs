//! Token-Budget-Aware Hybrid Batch Packer (`pack_delivery_batch`, `docs/architecture-v2.md` §2.5).
//!
//! Enforces:
//! 1. **Strict `mute` invariant:** `muted` items NEVER wake or emit a standalone delivery
//!    (`pending_unread.is_empty()` -> returns `None` even if `muted_count == 50`).
//! 2. **Strict `notify` invariant:** When only `Notify`-tier unread items exist (e.g. Focus Mode),
//!    STILL emits a slim 1-line digest queued for the agent's next turn / idle boundary.
//! 3. **Hybrid inline-then-spillover packing:**
//!    - Priority sort: `Interrupt` > `Queue` DM/`#announcement` > `Queue` `#channel`/stream > `Notify`/burst-demoted.
//!    - Pack highest-priority non-`Notify` items verbatim while `est_tokens <= max_batch_tokens`
//!      and `inline_count < max_inline_items`.
//!    - Single giant payloads > `max_single_item_share * max_batch_tokens` are truncated cleanly
//!      with a preview + `"full body in hyp_inbox(ids:[...])"`.
//!    - All remaining items (overflow + `Notify`) spill into a compact 1-line digest footer grouped
//!      by source with a ready-to-use `hyp_inbox({ filter, limit, cursor })` pagination hint.
//!    - Whenever ANY batch or digest fires AND `muted_count > 0`, piggyback `· <muted_count> muted`
//!      right onto the footer!

use std::collections::HashMap;

use hyp_store::MailboxKind;
use serde::{Deserialize, Serialize};

use crate::delivery::policy::{DeliveryUrgency, SessionDeliveryPolicy};

const SEPARATOR: &str = "\n---\n";
const MAX_FOOTER_SOURCES: usize = 4;

/// Single pending `unread` inbox item supplied to [`pack_delivery_batch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackableItem {
    pub id: String,
    pub urgency: DeliveryUrgency,
    pub kind: MailboxKind,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// True when this item comes from a read-only `#announcement` channel (elevated in Queue band).
    #[serde(default)]
    pub is_announcement: bool,
    pub text: String,
    pub created_at_ms: i64,
    /// True when Adaptive Burst Protection stepped this item down into Noisy Mode.
    #[serde(default)]
    pub burst_demoted: bool,
}

impl PackableItem {
    /// Priority band per §2.5:
    /// - `0`: `Interrupt` (not burst-demoted)
    /// - `1`: `Queue` DM (`kind == Message && channel.is_none()`) or `#announcement`
    /// - `2`: `Queue` `#channel`, stream, bridge, transfer, kv
    /// - `3`: `Notify` or burst-demoted
    pub fn priority_band(&self) -> u8 {
        if self.burst_demoted || self.urgency == DeliveryUrgency::Notify {
            return 3;
        }
        match self.urgency {
            DeliveryUrgency::Interrupt => 0,
            DeliveryUrgency::Queue => {
                if (self.kind == MailboxKind::Message && self.channel.is_none())
                    || self.is_announcement
                {
                    1
                } else {
                    2
                }
            }
            DeliveryUrgency::Notify => 3,
            DeliveryUrgency::Mute => 4,
        }
    }

    pub fn is_notify_tier(&self) -> bool {
        self.burst_demoted || self.urgency == DeliveryUrgency::Notify
    }
}

/// Output of [`pack_delivery_batch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackedDeliveryBatch {
    /// Rendered delivery text (inline items + optional compact 1-line digest/muted footer).
    pub rendered: String,
    /// Estimated token count of `rendered` (`ceil(chars / 4)`).
    pub estimated_tokens: usize,
    /// IDs of items packed inline in full (safe to mark `delivered` upon injection/push).
    pub inline_ids: Vec<String>,
    /// IDs of oversized items rendered as a truncated preview (full body kept in inbox).
    pub truncated_ids: Vec<String>,
    /// IDs of items spilled to the compact digest footer (kept `unread` in inbox for `hyp_inbox`).
    pub spilled_ids: Vec<String>,
    /// True when zero items were packed inline and the batch is purely a 1-line `notify` digest.
    pub notify_only: bool,
    /// Number of muted items piggybacked onto the footer (`0` if none).
    pub muted_count: usize,
    /// Highest urgency present in the packed batch.
    pub max_urgency: DeliveryUrgency,
}

/// Conservative token estimator (`ceil(chars / 4)`, ~4 characters per token).
pub fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

/// Packs pending `unread` inbox items into a token-budgeted hybrid delivery batch (§2.5).
///
/// Returns `None` if `pending_unread` contains zero non-`Mute` items (even if `muted_count > 0`).
pub fn pack_delivery_batch(
    pending_unread: &[PackableItem],
    muted_count: usize,
    policy: &SessionDeliveryPolicy,
) -> Option<PackedDeliveryBatch> {
    // Defense-in-depth: muted items NEVER trigger a wake or standalone delivery.
    let mut items: Vec<&PackableItem> = pending_unread
        .iter()
        .filter(|it| it.urgency != DeliveryUrgency::Mute)
        .collect();
    if items.is_empty() {
        return None;
    }

    // Priority sort: Interrupt -> Queue DM/#announcement -> Queue #channel/stream -> Notify/burst.
    // Deterministic tie-break by arrival time then receipt ID.
    items.sort_by(|a, b| {
        a.priority_band()
            .cmp(&b.priority_band())
            .then_with(|| a.created_at_ms.cmp(&b.created_at_ms))
            .then_with(|| a.id.cmp(&b.id))
    });

    let max_urgency = items
        .iter()
        .map(|it| it.urgency)
        .min_by_key(|u| u.rank())
        .unwrap_or(DeliveryUrgency::Notify);

    let max_budget = policy.max_batch_tokens.max(32);
    let max_inline = policy.max_inline_items;
    let max_single_tokens = policy.max_single_item_tokens();

    let mut inline_blocks: Vec<String> = Vec::new();
    let mut inline_ids: Vec<String> = Vec::new();
    let mut truncated_ids: Vec<String> = Vec::new();
    let mut spilled_start: usize = items.len();

    for (idx, item) in items.iter().enumerate() {
        if item.is_notify_tier() || inline_blocks.len() >= max_inline {
            spilled_start = idx;
            break;
        }

        let raw_block = format_inline_block(item);
        let (mut candidate, mut was_truncated) =
            if estimate_tokens(&raw_block) > max_single_tokens {
                (truncate_item_preview(&raw_block, &item.id, max_single_tokens), true)
            } else {
                (raw_block, false)
            };

        let remaining_after = &items[idx + 1..];
        let footer_after = build_footer(remaining_after, muted_count, false);
        let candidate_total = compose_rendered_tokens(&inline_blocks, Some(&candidate), footer_after.as_deref());

        if candidate_total > max_budget {
            if inline_blocks.is_empty() {
                // Always try to deliver at least a preview of the #1 highest-priority critical item
                // while staying strictly inside `max_batch_tokens`!
                let footer_tokens = footer_after
                    .as_deref()
                    .map(|f| estimate_tokens(f) + estimate_tokens("\n\n"))
                    .unwrap_or(0);
                let avail_tokens = max_budget.saturating_sub(footer_tokens);
                if avail_tokens >= 20 {
                    candidate = truncate_item_preview(&candidate, &item.id, avail_tokens);
                    was_truncated = true;
                } else {
                    spilled_start = idx;
                    break;
                }
            } else {
                spilled_start = idx;
                break;
            }
        }

        inline_blocks.push(candidate);
        if was_truncated {
            truncated_ids.push(item.id.clone());
        } else {
            inline_ids.push(item.id.clone());
        }
    }

    let spilled = &items[spilled_start..];
    let spilled_ids: Vec<String> = spilled.iter().map(|it| it.id.clone()).collect();
    let notify_only = inline_blocks.is_empty();

    let footer = build_footer(spilled, muted_count, notify_only);
    let rendered = compose_rendered(&inline_blocks, footer.as_deref());
    let estimated_tokens = estimate_tokens(&rendered);

    Some(PackedDeliveryBatch {
        rendered,
        estimated_tokens,
        inline_ids,
        truncated_ids,
        spilled_ids,
        notify_only,
        muted_count,
        max_urgency,
    })
}

fn format_inline_block(item: &PackableItem) -> String {
    if item.text.starts_with("hyphae ") {
        item.text.clone()
    } else if item.urgency == DeliveryUrgency::Interrupt {
        format!("[hyphae interrupt · {}]\n{}", item.source, item.text)
    } else {
        format!("[hyphae · {}]\n{}", item.source, item.text)
    }
}

fn truncate_item_preview(block: &str, item_id: &str, max_tokens: usize) -> String {
    let suffix = format!("\n… [truncated; full body in hyp_inbox(ids:[\"{item_id}\"])]");
    let max_chars = max_tokens.saturating_mul(4);
    let suffix_chars = suffix.chars().count();
    if max_chars <= suffix_chars + 4 {
        return suffix.trim_start_matches('\n').to_string();
    }
    let keep_chars = max_chars - suffix_chars;
    let preview: String = block.chars().take(keep_chars).collect();
    let trimmed = preview.trim_end();
    format!("{trimmed}{suffix}")
}

fn compose_rendered(inline_blocks: &[String], footer: Option<&str>) -> String {
    match (inline_blocks.is_empty(), footer) {
        (true, Some(f)) => f.to_string(),
        (false, None) => inline_blocks.join(SEPARATOR),
        (false, Some(f)) => format!("{}\n\n{f}", inline_blocks.join(SEPARATOR)),
        (true, None) => String::new(),
    }
}

fn compose_rendered_tokens(
    existing: &[String],
    extra: Option<&str>,
    footer: Option<&str>,
) -> usize {
    let mut total_chars = 0usize;
    let count = existing.len() + usize::from(extra.is_some());
    for (i, b) in existing.iter().enumerate() {
        if i > 0 {
            total_chars += SEPARATOR.chars().count();
        }
        total_chars += b.chars().count();
    }
    if let Some(e) = extra {
        if !existing.is_empty() {
            total_chars += SEPARATOR.chars().count();
        }
        total_chars += e.chars().count();
    }
    if let Some(f) = footer {
        if count > 0 {
            total_chars += 2; // "\n\n"
        }
        total_chars += f.chars().count();
    }
    total_chars.div_ceil(4)
}

fn build_footer(spilled: &[&PackableItem], muted_count: usize, notify_only: bool) -> Option<String> {
    let muted_suffix = if muted_count > 0 {
        format!(" · {muted_count} muted")
    } else {
        String::new()
    };

    if spilled.is_empty() {
        if muted_count > 0 {
            return Some(format!(
                "[hyphae · {muted_count} muted] → hyp_inbox({{ state: \"muted\", limit: 20 }})"
            ));
        }
        return None;
    }

    // Group spilled items by source in first-seen (priority) order.
    let mut order: Vec<&str> = Vec::new();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for item in spilled {
        let src = if item.source.trim().is_empty() {
            "unknown"
        } else {
            item.source.as_str()
        };
        if !counts.contains_key(src) {
            order.push(src);
        }
        *counts.entry(src).or_insert(0) += 1;
    }

    let mut summary_parts: Vec<String> = Vec::new();
    for src in order.iter().take(MAX_FOOTER_SOURCES) {
        let n = counts[src];
        let short_src = shorten_label(src, 40);
        summary_parts.push(format!("{short_src} ({n})"));
    }
    if order.len() > MAX_FOOTER_SOURCES {
        summary_parts.push(format!("+{} sources", order.len() - MAX_FOOTER_SOURCES));
    }
    let grouped = summary_parts.join(", ");

    let limit_hint = spilled.len().clamp(1, 20);
    let hint = if order.len() == 1 {
        let only = spilled[0];
        if let Some(ref ch) = only.channel {
            format!(
                "hyp_inbox({{ filter: {{ channel: \"{}\" }}, limit: {limit_hint} }})",
                escape_hint(ch)
            )
        } else if only.kind == MailboxKind::Event || only.kind == MailboxKind::Kv {
            format!(
                "hyp_inbox({{ filter: {{ topic: \"{}\" }}, limit: {limit_hint} }})",
                escape_hint(&only.source)
            )
        } else {
            format!(
                "hyp_inbox({{ filter: {{ from: \"{}\" }}, limit: {limit_hint} }})",
                escape_hint(&only.source)
            )
        }
    } else {
        format!("hyp_inbox({{ filter: {{}}, limit: {limit_hint}, cursor: null }})")
    };

    let n = spilled.len();
    if notify_only {
        Some(format!(
            "[hyphae notify · {n} unread: {grouped}{muted_suffix}] → {hint}"
        ))
    } else {
        Some(format!(
            "[hyphae +{n} more unread: {grouped}{muted_suffix}] → {hint}"
        ))
    }
}

fn shorten_label(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let head: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn escape_hint(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(id: &str, urgency: DeliveryUrgency, source: &str, text: &str, ts: i64) -> PackableItem {
        PackableItem {
            id: id.into(),
            urgency,
            kind: MailboxKind::Message,
            source: source.into(),
            channel: None,
            is_announcement: false,
            text: text.into(),
            created_at_ms: ts,
            burst_demoted: false,
        }
    }

    #[test]
    fn muted_only_never_emits_batch() {
        let policy = SessionDeliveryPolicy::default();
        assert!(pack_delivery_batch(&[], 50, &policy).is_none());

        let muted_item = mk("m1", DeliveryUrgency::Mute, "bot/spam", "noise", 1);
        assert!(pack_delivery_batch(&[muted_item], 50, &policy).is_none());
    }

    #[test]
    fn notify_only_emits_slim_digest_with_piggybacked_muted() {
        let policy = SessionDeliveryPolicy::focus_mode();
        let items = vec![
            mk("n1", DeliveryUrgency::Notify, "bob@laptop/codex", "PR ready", 10),
            mk("n2", DeliveryUrgency::Notify, "bob@laptop/codex", "Tests green", 20),
        ];
        let batch = pack_delivery_batch(&items, 7, &policy).expect("digest must emit");
        assert!(batch.notify_only);
        assert!(batch.inline_ids.is_empty());
        assert_eq!(batch.spilled_ids, vec!["n1", "n2"]);
        assert!(batch.rendered.contains("hyphae notify · 2 unread"));
        assert!(batch.rendered.contains("· 7 muted"));
        assert!(batch.rendered.contains("hyp_inbox("));
        assert!(batch.estimated_tokens <= policy.max_batch_tokens);
    }

    #[test]
    fn giant_item_truncates_cleanly_with_inbox_hint() {
        let policy = SessionDeliveryPolicy {
            max_batch_tokens: 200,
            max_single_item_share: 0.60,
            ..SessionDeliveryPolicy::default()
        };
        let huge = "X".repeat(4_000);
        let item = mk("big-1", DeliveryUrgency::Interrupt, "ops/oncall", &huge, 1);
        let batch = pack_delivery_batch(&[item], 0, &policy).unwrap();
        assert_eq!(batch.truncated_ids, vec!["big-1"]);
        assert!(batch.inline_ids.is_empty());
        assert!(batch.rendered.contains("full body in hyp_inbox(ids:[\"big-1\"])"));
        assert!(batch.estimated_tokens <= policy.max_batch_tokens);
    }
}
