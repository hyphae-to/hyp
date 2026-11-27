//! Adaptive per-source Burst Protection ("Noisy Mode") tracker (`docs/architecture-v2.md` §2.5).
//!
//! Tracks rolling arrival timestamps per source. When a source exceeds
//! `max_events_per_window` arrivals inside `window_secs`, the tracker engages
//! **Noisy Mode** until `noisy_cooldown_secs` elapses — automatically stepping
//! `Interrupt`/`Queue` floods down to `Notify` and honoring `min_delivery_interval_secs`
//! so flapping CI jobs or chatty bots never drown an agent's context window.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::delivery::policy::{BurstProtectionConfig, DeliveryUrgency};

#[derive(Debug, Clone, Default)]
struct SourceBurstState {
    arrivals_ms: VecDeque<i64>,
    noisy_until_ms: Option<i64>,
    last_delivery_ms: Option<i64>,
}

/// Outcome of evaluating an inbound arrival against [`BurstTracker`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BurstAssessment {
    /// Final urgency after applying Noisy Mode demotion (if active).
    pub effective_urgency: DeliveryUrgency,
    /// True if this source is currently in Noisy Mode.
    pub noisy_mode: bool,
    /// True if Noisy Mode stepped `Interrupt`/`Queue` down to `Notify`.
    pub demoted: bool,
    /// True if the source is inside `min_delivery_interval_secs` since its last delivery/digest.
    pub throttled_by_interval: bool,
    /// Current number of arrivals observed inside the rolling `window_secs`.
    pub events_in_window: usize,
    /// Epoch milliseconds when Noisy Mode cooldown expires (`None` if not noisy).
    pub cooldown_until_ms: Option<i64>,
}

/// Per-source rolling arrival tracker implementing §2.5 Adaptive Burst Protection.
#[derive(Debug, Clone, Default)]
pub struct BurstTracker {
    sources: HashMap<String, SourceBurstState>,
}

impl BurstTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a new arrival for `source_key` at `now_ms` and evaluates burst/Noisy Mode state.
    ///
    /// - `DeliveryUrgency::Mute` is never altered (stays `Mute`, never trips noisy notifications).
    /// - Once `events_in_window > config.max_events_per_window` inside `config.window_secs`,
    ///   marks `source_key` in Noisy Mode until `now_ms + config.noisy_cooldown_secs * 1000`.
    /// - While in Noisy Mode, `Interrupt` and `Queue` are automatically demoted to `Notify`.
    pub fn record_and_evaluate(
        &mut self,
        source_key: &str,
        base_urgency: DeliveryUrgency,
        config: &BurstProtectionConfig,
        now_ms: i64,
    ) -> BurstAssessment {
        let key = normalize_source_key(source_key);
        if base_urgency == DeliveryUrgency::Mute {
            return BurstAssessment {
                effective_urgency: DeliveryUrgency::Mute,
                noisy_mode: self.is_noisy(&key, now_ms),
                demoted: false,
                throttled_by_interval: false,
                events_in_window: self.events_in_window(&key, config, now_ms),
                cooldown_until_ms: self.cooldown_until_ms(&key, now_ms),
            };
        }

        let window_ms = (config.window_secs as i64).saturating_mul(1_000);
        let cooldown_ms = (config.noisy_cooldown_secs as i64).saturating_mul(1_000);
        let min_interval_ms = (config.min_delivery_interval_secs as i64).saturating_mul(1_000);

        let entry = self.sources.entry(key).or_default();

        // Evict timestamps outside the rolling window.
        let cutoff = now_ms.saturating_sub(window_ms);
        while entry.arrivals_ms.front().is_some_and(|&ts| ts < cutoff) {
            entry.arrivals_ms.pop_front();
        }
        entry.arrivals_ms.push_back(now_ms);
        let events_in_window = entry.arrivals_ms.len();

        // Clear expired cooldown before checking current window threshold.
        if entry.noisy_until_ms.is_some_and(|until| now_ms >= until) {
            entry.noisy_until_ms = None;
        }

        // Trip (or extend) Noisy Mode when exceeding `max_events_per_window`.
        if events_in_window > config.max_events_per_window {
            let until = now_ms.saturating_add(cooldown_ms);
            entry.noisy_until_ms = Some(entry.noisy_until_ms.map_or(until, |prev| prev.max(until)));
        }

        let noisy_mode = entry.noisy_until_ms.is_some_and(|until| now_ms < until);
        let (effective_urgency, demoted) = if noisy_mode
            && matches!(
                base_urgency,
                DeliveryUrgency::Interrupt | DeliveryUrgency::Queue
            ) {
            (DeliveryUrgency::Notify, true)
        } else {
            (base_urgency, false)
        };

        let throttled_by_interval = noisy_mode
            && min_interval_ms > 0
            && entry
                .last_delivery_ms
                .is_some_and(|last| now_ms.saturating_sub(last) < min_interval_ms);

        BurstAssessment {
            effective_urgency,
            noisy_mode,
            demoted,
            throttled_by_interval,
            events_in_window,
            cooldown_until_ms: entry.noisy_until_ms,
        }
    }

    /// Records that a batch or digest containing `source_key` was delivered at `now_ms`.
    pub fn record_delivery(&mut self, source_key: &str, now_ms: i64) {
        let key = normalize_source_key(source_key);
        let entry = self.sources.entry(key).or_default();
        entry.last_delivery_ms = Some(now_ms);
    }

    /// Returns `true` if `source_key` is currently in Noisy Mode at `now_ms`.
    pub fn is_noisy(&self, source_key: &str, now_ms: i64) -> bool {
        let key = normalize_source_key(source_key);
        self.sources
            .get(&key)
            .and_then(|s| s.noisy_until_ms)
            .is_some_and(|until| now_ms < until)
    }

    /// Returns `true` if `source_key` is allowed to emit a delivery/digest at `now_ms`
    /// under `min_delivery_interval_secs` (always `true` when not in Noisy Mode).
    pub fn can_deliver(
        &self,
        source_key: &str,
        config: &BurstProtectionConfig,
        now_ms: i64,
    ) -> bool {
        let key = normalize_source_key(source_key);
        let Some(state) = self.sources.get(&key) else {
            return true;
        };
        if state.noisy_until_ms.is_none_or(|until| now_ms >= until) {
            return true;
        }
        let min_interval_ms = (config.min_delivery_interval_secs as i64).saturating_mul(1_000);
        if min_interval_ms <= 0 {
            return true;
        }
        state
            .last_delivery_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= min_interval_ms)
    }

    fn events_in_window(&self, key: &str, config: &BurstProtectionConfig, now_ms: i64) -> usize {
        let window_ms = (config.window_secs as i64).saturating_mul(1_000);
        let cutoff = now_ms.saturating_sub(window_ms);
        self.sources
            .get(key)
            .map(|s| s.arrivals_ms.iter().filter(|&&ts| ts >= cutoff).count())
            .unwrap_or(0)
    }

    fn cooldown_until_ms(&self, key: &str, now_ms: i64) -> Option<i64> {
        self.sources
            .get(key)
            .and_then(|s| s.noisy_until_ms)
            .filter(|&until| now_ms < until)
    }
}

fn normalize_source_key(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_noisy_mode_on_burst_and_recovers_after_cooldown() {
        let mut tracker = BurstTracker::new();
        let cfg = BurstProtectionConfig {
            window_secs: 60,
            max_events_per_window: 3,
            noisy_cooldown_secs: 300,
            min_delivery_interval_secs: 30,
        };

        let t0 = 1_000_000;
        for i in 0..3 {
            let a =
                tracker.record_and_evaluate("ci-bot", DeliveryUrgency::Queue, &cfg, t0 + i * 1_000);
            assert!(!a.noisy_mode);
            assert!(!a.demoted);
            assert_eq!(a.effective_urgency, DeliveryUrgency::Queue);
        }

        // 4th event within 60s exceeds max_events_per_window=3 -> Noisy Mode!
        let tripped =
            tracker.record_and_evaluate("ci-bot", DeliveryUrgency::Interrupt, &cfg, t0 + 4_000);
        assert!(tripped.noisy_mode);
        assert!(tripped.demoted);
        assert_eq!(tripped.effective_urgency, DeliveryUrgency::Notify);
        assert_eq!(tripped.cooldown_until_ms, Some(t0 + 4_000 + 300_000));

        // Record delivery -> throttled within 30s min_delivery_interval_secs.
        tracker.record_delivery("ci-bot", t0 + 4_000);
        assert!(!tracker.can_deliver("ci-bot", &cfg, t0 + 10_000));
        assert!(tracker.can_deliver("ci-bot", &cfg, t0 + 35_000));

        // After cooldown expires (and window slides), returns to normal Queue urgency!
        let recovered = tracker.record_and_evaluate(
            "ci-bot",
            DeliveryUrgency::Queue,
            &cfg,
            t0 + 4_000 + 300_001,
        );
        assert!(!recovered.noisy_mode);
        assert!(!recovered.demoted);
        assert_eq!(recovered.effective_urgency, DeliveryUrgency::Queue);
    }
}
