//! Cross-platform zero-FFI system sleep/wake detector & recovery configuration.
//!
//! Compares elapsed wall-clock time (`SystemTime::now()`, which advances across
//! macOS/Linux/Windows sleep/suspend) against elapsed monotonic uptime
//! (`std::time::Instant::now()`, which pauses during sleep on macOS `CLOCK_UPTIME_RAW`
//! and Linux `CLOCK_MONOTONIC`).
//!
//! Whenever `wall_delta.saturating_sub(monotonic_delta) >= min_sleep`, emits a
//! [`SystemWakeEvent`] so [`crate::engine::UnifiedNode`], `PeerLink` SSE workers,
//! external Drop Relay watchers, external plugins, and `LocalDaemon` immediately
//! recycle half-open sockets, clear stale activity leases/holds, and flush pending mail.

use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hyp_store::now_ms;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Default periodic check cadence for [`spawn_wake_watcher`] (5 seconds; zero busy-polling).
pub const DEFAULT_WAKE_CHECK_INTERVAL_SECS: u64 = 5;
/// Default minimum wall-vs-monotonic clock drift classified as system sleep (15 seconds).
pub const DEFAULT_WAKE_MIN_SLEEP_SECONDS: u64 = 15;

const fn default_true() -> bool {
    true
}

const fn default_min_sleep_seconds() -> u64 {
    DEFAULT_WAKE_MIN_SLEEP_SECONDS
}

/// Configuration for automatic laptop sleep/wake detection and recovery (`node.json` -> `wakeRecovery`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WakeRecoveryConfig {
    /// Enable automatic sleep/wake detection and recovery (default: `true`).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Minimum wall-vs-monotonic drift in seconds required to fire a wake event (default: `15`).
    #[serde(default = "default_min_sleep_seconds")]
    pub min_sleep_seconds: u64,
    /// Enqueue a concise local `[hyphae notice]` ONLY for sessions whose `session_activity`
    /// was `Active` across the sleep boundary (i.e. mid-turn interrupted; default: `true`).
    #[serde(default = "default_true")]
    pub notify_interrupted_active: bool,
    /// Also enqueue a wake notice for quiet idle enrolled sessions (default: `false`; opt-in only).
    #[serde(default)]
    pub notify_all_enrolled: bool,
}

impl Default for WakeRecoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_sleep_seconds: DEFAULT_WAKE_MIN_SLEEP_SECONDS,
            notify_interrupted_active: true,
            notify_all_enrolled: false,
        }
    }
}

impl WakeRecoveryConfig {
    /// Returns the effective minimum sleep threshold clamped to at least 1 second.
    pub fn min_sleep_duration(&self) -> Duration {
        Duration::from_secs(self.min_sleep_seconds.max(1))
    }
}

/// Event emitted when host sleep/wake is detected via wall-vs-monotonic clock drift
/// or triggered explicitly via `notify_system_wake` / `system.wake`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemWakeEvent {
    /// Estimated duration the host was asleep (`wall_delta - monotonic_delta`).
    pub slept_for: Duration,
    /// Unix timestamp in milliseconds when wake was observed.
    pub woke_at_ms: i64,
}

/// Pure, deterministic sleep-gap detector comparing wall-clock progression against
/// monotonic uptime progression.
///
/// - Normal tick (`wall_delta ≈ monotonic_delta`) -> `None`.
/// - Backward NTP clock step (`curr_wall < prev_wall`) -> `None` (never false-triggers).
/// - Drift below `min_sleep` -> `None`.
/// - `wall_delta - monotonic_delta >= min_sleep` -> `Some(SystemWakeEvent)`.
pub fn detect_sleep_gap(
    prev_wall: SystemTime,
    curr_wall: SystemTime,
    monotonic_delta: Duration,
    min_sleep: Duration,
) -> Option<SystemWakeEvent> {
    if min_sleep.is_zero() {
        return None;
    }
    let wall_delta = curr_wall.duration_since(prev_wall).ok()?;
    let drift = wall_delta.saturating_sub(monotonic_delta);
    if drift < min_sleep {
        return None;
    }
    let woke_at_ms = curr_wall
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or_else(now_ms);
    Some(SystemWakeEvent {
        slept_for: drift,
        woke_at_ms,
    })
}

/// Stateful cross-platform sleep/wake detector with injectable clock sampling for tests.
#[derive(Debug, Clone)]
pub struct SleepWakeDetector {
    last_wall: SystemTime,
    last_monotonic: Instant,
    min_sleep: Duration,
}

impl SleepWakeDetector {
    /// Creates a detector anchored at `(SystemTime::now(), Instant::now())`.
    pub fn new(min_sleep: Duration) -> Self {
        Self::with_initial(SystemTime::now(), Instant::now(), min_sleep)
    }

    /// Creates a detector anchored at explicit initial clock readings (useful in deterministic tests).
    pub fn with_initial(wall: SystemTime, monotonic: Instant, min_sleep: Duration) -> Self {
        Self {
            last_wall: wall,
            last_monotonic: monotonic,
            min_sleep,
        }
    }

    /// Evaluates a `(curr_wall, curr_monotonic)` sample, advances the internal baseline, and
    /// returns `Some(SystemWakeEvent)` iff a sleep gap `>= min_sleep` occurred.
    pub fn poll_sample(
        &mut self,
        curr_wall: SystemTime,
        curr_monotonic: Instant,
    ) -> Option<SystemWakeEvent> {
        let monotonic_delta = curr_monotonic.saturating_duration_since(self.last_monotonic);
        let event = detect_sleep_gap(self.last_wall, curr_wall, monotonic_delta, self.min_sleep);
        self.last_wall = curr_wall;
        self.last_monotonic = curr_monotonic;
        event
    }

    /// Evaluates an explicit `(curr_wall, monotonic_delta)` step and advances `last_wall`
    /// (deterministic test helper avoiding OS `Instant` sleeps).
    pub fn poll_with_delta(
        &mut self,
        curr_wall: SystemTime,
        monotonic_delta: Duration,
    ) -> Option<SystemWakeEvent> {
        let event = detect_sleep_gap(self.last_wall, curr_wall, monotonic_delta, self.min_sleep);
        self.last_wall = curr_wall;
        event
    }

    /// Samples the live OS wall & monotonic clocks and returns `Some(SystemWakeEvent)` on wake.
    pub fn poll_now(&mut self) -> Option<SystemWakeEvent> {
        self.poll_sample(SystemTime::now(), Instant::now())
    }
}

/// Formats a sleep duration concisely for human/agent wake notices (e.g. `"20s"`, `"10m"`, `"1h 5m"`).
pub fn format_human_duration(dur: Duration) -> String {
    let total_secs = dur.as_secs();
    if total_secs == 0 {
        return "<1s".to_string();
    }
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if hours > 0 {
        if mins > 0 {
            format!("{hours}h {mins}m")
        } else {
            format!("{hours}h")
        }
    } else if mins > 0 {
        if secs > 0 {
            format!("{mins}m {secs}s")
        } else {
            format!("{mins}m")
        }
    } else {
        format!("{secs}s")
    }
}

/// Spawns a lightweight, `shutdown_rx`-cancellable background watcher task that checks
/// wall-vs-monotonic clock drift every `check_interval` (default 5s) and invokes `on_wake`
/// whenever a sleep gap `>= min_sleep` is detected.
pub fn spawn_wake_watcher<F, Fut>(
    check_interval: Duration,
    min_sleep: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
    mut on_wake: F,
) -> JoinHandle<()>
where
    F: FnMut(SystemWakeEvent) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let interval = check_interval.max(Duration::from_millis(100));
    tokio::spawn(async move {
        let mut detector = SleepWakeDetector::new(min_sleep);
        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
            }
            if *shutdown_rx.borrow() {
                break;
            }
            if let Some(event) = detector.poll_now() {
                on_wake(event).await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_sleep_gap_normal_tick_emits_none() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t1 = t0 + Duration::from_secs(5);
        assert_eq!(
            detect_sleep_gap(t0, t1, Duration::from_secs(5), Duration::from_secs(15)),
            None
        );
        // Minor scheduling jitter (250ms) stays silent.
        let t1_jitter = t0 + Duration::from_millis(5_250);
        assert_eq!(
            detect_sleep_gap(
                t0,
                t1_jitter,
                Duration::from_secs(5),
                Duration::from_secs(15)
            ),
            None
        );
    }

    #[test]
    fn detect_sleep_gap_backward_ntp_jump_emits_none() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let t1_backward = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(
            detect_sleep_gap(
                t0,
                t1_backward,
                Duration::from_secs(5),
                Duration::from_secs(15)
            ),
            None
        );
    }

    #[test]
    fn detect_sleep_gap_below_threshold_emits_none_and_at_or_above_emits_event() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let min_sleep = Duration::from_secs(15);

        // wall +19s, monotonic +5s -> drift = 14s (< 15s threshold) -> None.
        let t_below = t0 + Duration::from_secs(19);
        assert_eq!(
            detect_sleep_gap(t0, t_below, Duration::from_secs(5), min_sleep),
            None
        );

        // wall +20s, monotonic +5s -> drift = 15s (exact threshold) -> Some(15s).
        let t_exact = t0 + Duration::from_secs(20);
        let ev_exact = detect_sleep_gap(t0, t_exact, Duration::from_secs(5), min_sleep)
            .expect("exact threshold must emit wake");
        assert_eq!(ev_exact.slept_for, Duration::from_secs(15));
        assert_eq!(ev_exact.woke_at_ms, 1_700_000_020_000);

        // wall +25s, monotonic +5s -> drift = 20s -> Some(20s).
        let t_jump = t0 + Duration::from_secs(25);
        let ev_jump = detect_sleep_gap(t0, t_jump, Duration::from_secs(5), min_sleep)
            .expect("+20s sleep jump must emit wake");
        assert_eq!(ev_jump.slept_for, Duration::from_secs(20));
        assert_eq!(ev_jump.woke_at_ms, 1_700_000_025_000);
    }

    #[test]
    fn stateful_detector_recovers_baseline_after_backward_ntp_and_after_wake() {
        let base_wall = UNIX_EPOCH + Duration::from_secs(1_700_000_500);
        let mut detector =
            SleepWakeDetector::with_initial(base_wall, Instant::now(), Duration::from_secs(15));

        // Step 1: Normal tick -> None.
        let w1 = base_wall + Duration::from_secs(5);
        assert_eq!(detector.poll_with_delta(w1, Duration::from_secs(5)), None);

        // Step 2: Backward NTP step (-60s) -> None, baseline resets to w2.
        let w2 = w1 - Duration::from_secs(60);
        assert_eq!(detector.poll_with_delta(w2, Duration::from_secs(5)), None);

        // Step 3: Normal tick from new baseline -> None.
        let w3 = w2 + Duration::from_secs(5);
        assert_eq!(detector.poll_with_delta(w3, Duration::from_secs(5)), None);

        // Step 4: +20s sleep jump (wall +25s, monotonic +5s) -> Some(20s).
        let w4 = w3 + Duration::from_secs(25);
        let ev = detector
            .poll_with_delta(w4, Duration::from_secs(5))
            .expect("sleep jump must emit wake");
        assert_eq!(ev.slept_for, Duration::from_secs(20));

        // Step 5: Next normal tick after wake -> None (no sticky/duplicate wake).
        let w5 = w4 + Duration::from_secs(5);
        assert_eq!(detector.poll_with_delta(w5, Duration::from_secs(5)), None);
    }

    #[test]
    fn format_human_duration_handles_seconds_minutes_hours() {
        assert_eq!(format_human_duration(Duration::from_millis(500)), "<1s");
        assert_eq!(format_human_duration(Duration::from_secs(20)), "20s");
        assert_eq!(format_human_duration(Duration::from_secs(60)), "1m");
        assert_eq!(format_human_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_human_duration(Duration::from_secs(600)), "10m");
        assert_eq!(format_human_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_human_duration(Duration::from_secs(3900)), "1h 5m");
    }

    #[test]
    fn wake_recovery_config_defaults_and_serde() {
        let cfg: WakeRecoveryConfig = serde_json::from_str("{}").expect("empty object");
        assert_eq!(cfg, WakeRecoveryConfig::default());
        assert!(cfg.enabled);
        assert_eq!(cfg.min_sleep_seconds, 15);
        assert!(cfg.notify_interrupted_active);
        assert!(!cfg.notify_all_enrolled);
    }
}
