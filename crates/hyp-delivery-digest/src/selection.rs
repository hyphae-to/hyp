//! Drain selection over resolved metadata, independent of mailbox reads and delivery commits.

use crate::{DeliveryUrgency, PackableItem, PackedDeliveryBatch, pack_inbox_digest};

/// Result of building a metadata-only XML digest batch for a session & drain scope.
pub struct BuiltDigestBatch {
    pub batch: PackedDeliveryBatch,
    /// True when produced by RFC 0004 Decision #4 periodic long-turn `PostToolUse` `Queue` reminder
    /// (updates `last_midturn_digest_at_ms` without prematurely stamping `Queue` items `notified = 1`).
    pub is_midturn_queue_reminder: bool,
}

/// Delivery drain scope requested by `mailbox.drain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainScope {
    /// Default / backwards-compatible full drain (raw `mailbox.drain` callers omitting `scope`).
    All,
    /// Mid-turn tool hook (`PostToolUse` / `AfterTool` / `afterMCPExecution` / `tool.execute.after`):
    /// drains `Interrupt` items ONLY; `Queue` and `Notify` stay held cleanly until TurnEnd / TurnStart.
    MidTurn,
    /// TurnEnd hook (`Stop` / `AfterAgent` / `session.idle`):
    /// drains `Interrupt` + `Queue`; ignores `notify_only` batches so TurnEnd never forces an extra turn for an FYI.
    TurnBoundary,
    /// TurnStart hook (`UserPromptSubmit` / `BeforeAgent` / `beforeSubmitPrompt` / `PreInvocation` / `before_prompt_build`):
    /// drains `Interrupt` + `Queue` + `NudgePending` + 1-line `Notify` digests.
    PreTurn,
    /// Out-of-band push wakeup flush (`flush_session_inner`): when Focus Mode is ON and a VIP
    /// (`Interrupt`) bypasses Focus Mode, strictly excludes Focus-buffered `Notify` items so they
    /// are NEVER folded into the VIP wake nudge count or stamped `notified = true`.
    PushFlush,
}

/// Resolved item metadata. No message bodies or database handles cross this boundary.
pub struct DigestCandidate {
    pub item: PackableItem,
    pub already_notified: bool,
}

/// Snapshot of the session settings needed for drain selection.
pub struct DigestPolicy {
    pub focus_mode: bool,
    pub midturn_queue_digest_seconds: u64,
    pub last_midturn_digest_at_ms: Option<i64>,
}

/// Whether the mid-turn queue path can reach its reminder timer read.
/// The daemon uses this guard before reading mutable session runtime state.
pub fn needs_midturn_reminder_timestamp(
    candidates: &[DigestCandidate],
    scope: DrainScope,
    interval_seconds: u64,
) -> bool {
    scope == DrainScope::MidTurn
        && interval_seconds > 0
        && candidates.iter().any(|candidate| {
            candidate.item.urgency == DeliveryUrgency::Queue && !candidate.item.burst_demoted
        })
        && !candidates.iter().any(|candidate| {
            !candidate.already_notified
                && candidate.item.urgency == DeliveryUrgency::Interrupt
                && !candidate.item.burst_demoted
        })
}

/// Selects and renders a digest without changing notification state.
pub fn build_digest(
    session_handle: Option<&str>,
    candidates: Vec<DigestCandidate>,
    policy: DigestPolicy,
    scope: DrainScope,
    now: i64,
    muted: usize,
    quarantined_receipts: &[String],
) -> Option<BuiltDigestBatch> {
    let mut packable: Vec<PackableItem> = Vec::with_capacity(candidates.len());
    let mut midturn_queue_reminder_items: Vec<PackableItem> = Vec::new();
    let mut oldest_unread_queue_ms: Option<i64> = None;
    let mut any_deliverable = false;
    let mut any_deliverable_interrupt = false;
    let mut any_deliverable_non_notify = false;

    for candidate in candidates {
        let mut item = candidate.item;
        let urgency = item.urgency;
        if urgency == DeliveryUrgency::Mute {
            continue;
        }
        let burst_demoted = item.burst_demoted;
        let treat_as_deliverable = !candidate.already_notified;
        let effective_urgency = if treat_as_deliverable {
            urgency
        } else {
            DeliveryUrgency::Notify
        };
        item.urgency = effective_urgency;
        if scope == DrainScope::MidTurn {
            // Track unread `Queue` items for RFC 0004 Decision #4 periodic long-turn reminders.
            if urgency == DeliveryUrgency::Queue && !burst_demoted {
                oldest_unread_queue_ms = Some(
                    oldest_unread_queue_ms
                        .map_or(item.created_at_ms, |prev| prev.min(item.created_at_ms)),
                );
                let mut reminder_item = item.clone();
                reminder_item.urgency = DeliveryUrgency::Queue;
                midturn_queue_reminder_items.push(reminder_item);
            } else if !policy.focus_mode && item.is_notify_tier() {
                midturn_queue_reminder_items.push(item.clone());
            }

            // Normal mid-turn path drains ONLY deliverable `Interrupt` items (plus non-Focus
            // `Notify` ride-along); `Queue` items stay held until TurnEnd or long-turn interval.
            if effective_urgency == DeliveryUrgency::Queue {
                continue;
            }
        }

        if treat_as_deliverable {
            any_deliverable = true;
            if effective_urgency == DeliveryUrgency::Interrupt && !burst_demoted {
                any_deliverable_interrupt = true;
            }
            if effective_urgency != DeliveryUrgency::Notify && !burst_demoted {
                any_deliverable_non_notify = true;
            }
        }

        packable.push(item);
    }

    if scope == DrainScope::MidTurn {
        if any_deliverable_interrupt {
            if policy.focus_mode {
                packable.retain(|item| !item.is_notify_tier());
            }
            let batch = pack_inbox_digest(session_handle, &packable, muted, quarantined_receipts)?;
            return Some(BuiltDigestBatch {
                batch,
                is_midturn_queue_reminder: false,
            });
        }

        // RFC 0004 Decision #4: Tuneable periodic long-turn `PostToolUse` `Queue` reminder.
        let interval_secs = policy.midturn_queue_digest_seconds;
        if interval_secs > 0 {
            if let Some(oldest_queue_ms) = oldest_unread_queue_ms {
                let interval_ms = (interval_secs as i64).saturating_mul(1_000);
                let last_reminded = policy.last_midturn_digest_at_ms.unwrap_or(0);
                let anchor_ms = last_reminded.max(oldest_queue_ms);
                if now.saturating_sub(anchor_ms) >= interval_ms {
                    let batch = pack_inbox_digest(
                        session_handle,
                        &midturn_queue_reminder_items,
                        muted,
                        quarantined_receipts,
                    )?;
                    return Some(BuiltDigestBatch {
                        batch,
                        is_midturn_queue_reminder: true,
                    });
                }
            }
        }
        return None;
    }

    if packable.is_empty() || !any_deliverable {
        return None;
    }
    if scope == DrainScope::TurnBoundary && !any_deliverable_non_notify {
        return None;
    }
    // Issue #32: When Focus Mode is ON and a VIP (`Interrupt`/`Queue`) triggers a wake or
    // turn drain, strictly exclude Focus-buffered `Notify` items so they are NEVER folded into
    // the VIP digest count or stamped `notified = true` in SQLite / `item_meta`.
    if policy.focus_mode && any_deliverable_non_notify {
        packable.retain(|item| !item.is_notify_tier());
        if packable.is_empty() {
            return None;
        }
    }

    let batch = pack_inbox_digest(session_handle, &packable, muted, quarantined_receipts)?;
    if scope == DrainScope::TurnBoundary && batch.notify_only {
        return None;
    }
    Some(BuiltDigestBatch {
        batch,
        is_midturn_queue_reminder: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyp_store::MailboxKind;

    fn candidate(id: &str, urgency: DeliveryUrgency, notified: bool) -> DigestCandidate {
        DigestCandidate {
            item: PackableItem {
                id: id.into(),
                urgency,
                kind: MailboxKind::Message,
                source: "sender".into(),
                channel: None,
                is_announcement: false,
                created_at_ms: 1_000,
                burst_demoted: false,
                is_system_notice: false,
                topic: None,
                subscription_key: None,
                human_verified: false,
            },
            already_notified: notified,
        }
    }

    fn policy(focus_mode: bool) -> DigestPolicy {
        DigestPolicy {
            focus_mode,
            midturn_queue_digest_seconds: 10,
            last_midturn_digest_at_ms: None,
        }
    }

    #[test]
    fn focus_wake_counts_and_commits_only_vip_receipts() {
        for scope in [
            DrainScope::All,
            DrainScope::PreTurn,
            DrainScope::PushFlush,
            DrainScope::TurnBoundary,
            DrainScope::MidTurn,
        ] {
            let built = build_digest(
                None,
                vec![
                    candidate("vip", DeliveryUrgency::Interrupt, false),
                    candidate("buffered", DeliveryUrgency::Notify, false),
                    candidate("old", DeliveryUrgency::Queue, true),
                ],
                policy(true),
                scope,
                20_000,
                0,
                &[],
            )
            .unwrap();
            assert_eq!(built.batch.receipt_ids, ["vip"]);
            assert!(built.batch.rendered.as_str().contains("unread=\"1\""));
            assert!(!built.is_midturn_queue_reminder);
        }
    }

    #[test]
    fn notification_state_cannot_trigger_another_digest() {
        for scope in [
            DrainScope::All,
            DrainScope::PreTurn,
            DrainScope::PushFlush,
            DrainScope::TurnBoundary,
            DrainScope::MidTurn,
        ] {
            assert!(
                build_digest(
                    None,
                    vec![candidate("old", DeliveryUrgency::Interrupt, true)],
                    policy(false),
                    scope,
                    20_000,
                    12,
                    &["quarantine".into()]
                )
                .is_none()
            );
        }
    }

    #[test]
    fn periodic_queue_reminder_obeys_both_arrival_and_last_reminder() {
        for (now, last, expected) in [
            (10_999, None, false),
            (11_000, None, true),
            (15_000, Some(10_000), false),
            (20_000, Some(10_000), true),
        ] {
            let mut settings = policy(false);
            settings.last_midturn_digest_at_ms = last;
            let built = build_digest(
                None,
                vec![candidate("queue", DeliveryUrgency::Queue, true)],
                settings,
                DrainScope::MidTurn,
                now,
                0,
                &[],
            );
            assert_eq!(built.is_some(), expected);
            if let Some(built) = built {
                assert!(built.is_midturn_queue_reminder);
                assert_eq!(built.batch.receipt_ids, ["queue"]);
            }
        }
    }
}
