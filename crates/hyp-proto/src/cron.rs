//! Pure-Rust 5-field POSIX cron parser, timezone-aware next-fire evaluator,
//! minimum-interval validator, and deterministic jitter helper.
//!
//! Zero external calendar/timezone crate dependencies: uses exact proleptic Gregorian
//! calendar math (Howard Hinnant's civil/days algorithms) with platform-native
//! local timezone offset lookup (`localtime_r` on Unix, `_localtime64_s` on Windows)
//! and an injectable offset resolver for deterministic cross-OS testing across UTC,
//! arbitrary fixed offsets, leap days, and DST transitions.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Default minimum allowed interval between consecutive cron ticks (60 seconds).
pub const DEFAULT_MIN_CRON_INTERVAL_SECS: u64 = 60;
/// Maximum deterministic jitter window added to non-exact cron ticks (30 seconds).
pub const MAX_CRON_JITTER_MS: i64 = 30_000;
/// Maximum number of years searched forward when computing the next fire instant.
const MAX_SEARCH_YEARS: i64 = 400;
/// Number of consecutive ticks sampled when checking shortest interval.
const MIN_INTERVAL_SAMPLE_TICKS: usize = 128;

/// Structured errors returned when parsing or validating 5-field cron schedules.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CronError {
    #[error("cron expression must not be empty")]
    EmptyExpression,
    #[error("cron expression must have exactly {expected} whitespace-separated fields, got {got}")]
    InvalidFieldCount { expected: usize, got: usize },
    #[error("invalid cron {field} field token '{token}': {reason}")]
    InvalidField {
        field: &'static str,
        token: String,
        reason: String,
    },
    #[error("invalid cron timezone '{0}': expected 'local' or 'utc'")]
    InvalidTimezone(String),
    #[error("cron schedule can never match any valid calendar date: {0}")]
    ImpossibleSchedule(String),
    #[error(
        "cron shortest interval ({shortest_seconds}s) is below minimum allowed ({min_seconds}s)"
    )]
    IntervalTooShort {
        shortest_seconds: u64,
        min_seconds: u64,
    },
}

/// Timezone interpretation for 5-field cron schedules.
///
/// Defaults to [`CronTimezone::Local`] (host local timezone, matching `crontab`/`launchd`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum CronTimezone {
    #[default]
    Local,
    Utc,
}

impl CronTimezone {
    /// Parses `"local"` or `"utc"` (case-insensitive, trimmed).
    pub fn parse(input: &str) -> Result<Self, CronError> {
        match input.trim().to_ascii_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "utc" => Ok(Self::Utc),
            _ => Err(CronError::InvalidTimezone(input.to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Utc => "utc",
        }
    }
}

impl fmt::Display for CronTimezone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CronTimezone {
    type Err = CronError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for CronTimezone {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CronTimezone {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Parsed, validated standard 5-field POSIX cron expression:
/// `minute hour day-of-month month day-of-week`.
///
/// Supports `*`, `*/n`, `a`, `a-b`, `a-b/n`, comma-separated lists `a,b,c`, Sunday as `0` or `7`,
/// and POSIX OR semantics when both day-of-month and day-of-week are restricted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpr {
    raw: String,
    minutes: u64,
    hours: u32,
    days_of_month: u32,
    months: u16,
    days_of_week: u8,
    dom_restricted: bool,
    dow_restricted: bool,
}

impl CronExpr {
    /// Parses and strictly validates a 5-field POSIX cron expression.
    pub fn parse(expr: &str) -> Result<Self, CronError> {
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            return Err(CronError::EmptyExpression);
        }
        let fields: Vec<&str> = trimmed.split_ascii_whitespace().collect();
        if fields.len() != 5 {
            return Err(CronError::InvalidFieldCount {
                expected: 5,
                got: fields.len(),
            });
        }

        let minutes = parse_field(fields[0], "minute", 0, 59, false)?;
        let hours = parse_field(fields[1], "hour", 0, 23, false)? as u32;
        let days_of_month = parse_field(fields[2], "day-of-month", 1, 31, false)? as u32;
        let months = parse_field(fields[3], "month", 1, 12, false)? as u16;
        let days_of_week = parse_field(fields[4], "day-of-week", 0, 7, true)? as u8;

        let dom_restricted = fields[2] != "*";
        let dow_restricted = fields[4] != "*";

        // Fail closed on impossible calendar combinations (e.g., Feb 30/31 or Apr 31)
        // when day-of-month is the sole day constraint.
        if dom_restricted && !dow_restricted && !has_possible_dom_month(months, days_of_month) {
            return Err(CronError::ImpossibleSchedule(format!(
                "no valid calendar date matches day-of-month '{}' in month '{}'",
                fields[2], fields[3]
            )));
        }

        let canonical = fields.join(" ");
        Ok(Self {
            raw: canonical,
            minutes,
            hours,
            days_of_month,
            months,
            days_of_week,
            dom_restricted,
            dow_restricted,
        })
    }

    /// Returns the normalized whitespace-canonical 5-field expression string.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns true if the given calendar tuple matches this cron expression.
    ///
    /// `month` is `1..=12`, `day` is `1..=31`, `dow` is `0..=6` (`0 = Sunday`),
    /// `hour` is `0..=23`, `minute` is `0..=59`.
    pub fn matches_parts(&self, month: u8, day: u8, dow: u8, hour: u8, minute: u8) -> bool {
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || dow > 6
            || hour > 23
            || minute > 59
        {
            return false;
        }
        ((self.months & (1u16 << month)) != 0)
            && self.day_matches(day, dow)
            && ((self.hours & (1u32 << hour)) != 0)
            && ((self.minutes & (1u64 << minute)) != 0)
    }

    /// Computes the next fire timestamp (Unix epoch ms) strictly greater than `after_unix_ms`
    /// in the requested [`CronTimezone`].
    pub fn next_fire_after(&self, after_unix_ms: i64, timezone: CronTimezone) -> Option<i64> {
        match timezone {
            CronTimezone::Utc => self.next_fire_after_with_offset(after_unix_ms, 0),
            CronTimezone::Local => {
                self.next_fire_after_with_resolver(after_unix_ms, host_local_offset_secs)
            }
        }
    }

    /// Computes the next fire timestamp (Unix epoch ms) strictly greater than `after_unix_ms` in UTC.
    pub fn next_fire_after_utc(&self, after_unix_ms: i64) -> Option<i64> {
        self.next_fire_after_with_offset(after_unix_ms, 0)
    }

    /// Computes the next fire timestamp (Unix epoch ms) strictly greater than `after_unix_ms`
    /// using a fixed local UTC offset in seconds (positive east of UTC, negative west of UTC).
    pub fn next_fire_after_with_offset(&self, after_unix_ms: i64, offset_secs: i32) -> Option<i64> {
        self.next_fire_after_with_resolver(after_unix_ms, |_| offset_secs)
    }

    /// Computes the next fire timestamp (Unix epoch ms) strictly greater than `after_unix_ms`
    /// using an injectable timezone offset resolver `offset_at_unix_sec(unix_sec) -> offset_secs`.
    ///
    /// Handles DST transitions cleanly:
    /// - Spring-forward gaps (non-existent wall-clock minutes) are skipped forward to the next
    ///   valid matching local minute.
    /// - Fall-back ambiguous hours select the earliest valid UTC instant strictly after
    ///   `after_unix_ms`, and never fire backward in UTC time.
    pub fn next_fire_after_with_resolver<F>(
        &self,
        after_unix_ms: i64,
        offset_at_unix_sec: F,
    ) -> Option<i64>
    where
        F: Fn(i64) -> i32,
    {
        // Cron fires at whole-minute (:00.000) instants, so candidate_sec * 1000 > after_unix_ms
        // holds iff candidate_sec >= after_unix_ms.div_euclid(1000) + 1.
        let min_utc_sec = after_unix_ms.div_euclid(1000).checked_add(1)?;
        let start_off = i64::from(offset_at_unix_sec(min_utc_sec));
        let start_local_sec = min_utc_sec.checked_add(start_off)?;
        let mut cursor_local_min = start_local_sec.checked_add(59)?.div_euclid(60);

        for _ in 0..1024 {
            let matched_local_min = self.next_wall_clock_match(cursor_local_min)?;
            let local_sec = matched_local_min.checked_mul(60)?;

            // Probe offsets bracketing +/-24h (plus the starting offset) so any DST boundary
            // within the full IANA [-12h, +14h] offset range is captured deterministically.
            let probe_offsets = [
                offset_at_unix_sec(local_sec.saturating_sub(86_400)),
                offset_at_unix_sec(local_sec.saturating_sub(start_off)),
                offset_at_unix_sec(local_sec),
                offset_at_unix_sec(local_sec.saturating_add(86_400)),
            ];

            let mut best_utc: Option<i64> = None;
            for off in probe_offsets {
                let cand_utc = local_sec.saturating_sub(i64::from(off));
                if cand_utc >= min_utc_sec {
                    let verify_off = offset_at_unix_sec(cand_utc);
                    if cand_utc.saturating_add(i64::from(verify_off)) == local_sec {
                        best_utc = Some(match best_utc {
                            Some(prev) => prev.min(cand_utc),
                            None => cand_utc,
                        });
                    }
                }
            }

            if let Some(utc_sec) = best_utc {
                return utc_sec.checked_mul(1000);
            }

            // Non-existent wall-clock time (DST spring-forward gap): advance past this minute.
            cursor_local_min = matched_local_min.checked_add(1)?;
        }

        None
    }

    /// Computes the shortest interval in seconds observed across consecutive UTC ticks.
    pub fn min_interval_seconds(&self) -> Option<u64> {
        // Anchor at 2024-01-01T00:00:00Z (leap year) minus 1 ms so 00:00:00Z itself can match.
        let anchor_ms = days_from_civil(2024, 1, 1) * 86_400_000 - 1;
        let mut prev = self.next_fire_after_utc(anchor_ms)?;
        let mut shortest: Option<u64> = None;

        for _ in 0..MIN_INTERVAL_SAMPLE_TICKS {
            let Some(next) = self.next_fire_after_utc(prev) else {
                break;
            };
            let gap_ms = next.saturating_sub(prev);
            if gap_ms > 0 {
                let gap_secs = (gap_ms / 1000) as u64;
                shortest = Some(match shortest {
                    Some(cur) => cur.min(gap_secs),
                    None => gap_secs,
                });
                // 60s is the theoretical floor for 5-field cron; no shorter gap is possible.
                if gap_secs <= 60 {
                    break;
                }
            }
            prev = next;
        }
        shortest
    }

    /// Validates that the shortest gap between consecutive ticks is at least `min_secs`.
    ///
    /// Returns the observed shortest interval in seconds on success, or fails closed with
    /// [`CronError::IntervalTooShort`] / [`CronError::ImpossibleSchedule`].
    pub fn validate_min_interval(&self, min_secs: u64) -> Result<u64, CronError> {
        let Some(shortest) = self.min_interval_seconds() else {
            return Err(CronError::ImpossibleSchedule(self.raw.clone()));
        };
        if shortest < min_secs {
            return Err(CronError::IntervalTooShort {
                shortest_seconds: shortest,
                min_seconds: min_secs,
            });
        }
        Ok(shortest)
    }

    fn day_matches(&self, day: u8, dow: u8) -> bool {
        let dom_hit = (self.days_of_month & (1u32 << day)) != 0;
        let dow_hit = (self.days_of_week & (1u8 << dow)) != 0;
        match (self.dom_restricted, self.dow_restricted) {
            (false, false) => true,
            (true, false) => dom_hit,
            (false, true) => dow_hit,
            // Standard POSIX cron OR semantics when both dom and dow are restricted.
            (true, true) => dom_hit || dow_hit,
        }
    }

    /// Finds the smallest wall-clock minute `>= start_local_min` matching this expression.
    fn next_wall_clock_match(&self, start_local_min: i64) -> Option<i64> {
        let start_days = start_local_min.div_euclid(1_440);
        let min_of_day = start_local_min.rem_euclid(1_440) as u32;
        let (mut year, mut month, mut day) = civil_from_days(start_days);
        let mut hour = min_of_day / 60;
        let mut minute = min_of_day % 60;

        let max_year = year.saturating_add(MAX_SEARCH_YEARS);

        while year <= max_year {
            // 1. Month
            let Some(next_month) = next_set_bit_u16(self.months, month, 12) else {
                year = year.checked_add(1)?;
                month = 1;
                day = 1;
                hour = 0;
                minute = 0;
                continue;
            };
            if next_month != month {
                month = next_month;
                day = 1;
                hour = 0;
                minute = 0;
            }

            // 2. Day of month / week
            let dim = days_in_month(year, month);
            if day > dim {
                if month == 12 {
                    year = year.checked_add(1)?;
                    month = 1;
                } else {
                    month += 1;
                }
                day = 1;
                hour = 0;
                minute = 0;
                continue;
            }
            let days_epoch = days_from_civil(year, month, day);
            let dow = weekday_from_days(days_epoch);
            if !self.day_matches(day as u8, dow) {
                day += 1;
                hour = 0;
                minute = 0;
                continue;
            }

            // 3. Hour
            let Some(next_hour) = next_set_bit_u32(self.hours, hour, 23) else {
                day += 1;
                hour = 0;
                minute = 0;
                continue;
            };
            if next_hour != hour {
                hour = next_hour;
                minute = 0;
            }

            // 4. Minute
            let Some(next_min) = next_set_bit_u64(self.minutes, minute, 59) else {
                hour += 1;
                minute = 0;
                if hour > 23 {
                    day += 1;
                    hour = 0;
                }
                continue;
            };

            let matched_days = days_from_civil(year, month, day);
            return matched_days
                .checked_mul(1_440)?
                .checked_add(i64::from(hour) * 60 + i64::from(next_min));
        }

        None
    }
}

impl fmt::Display for CronExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for CronExpr {
    type Err = CronError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Standalone helper delegating to [`CronExpr::next_fire_after_with_offset`].
pub fn next_fire_after_with_offset(
    expr: &CronExpr,
    after_unix_ms: i64,
    offset_secs: i32,
) -> Option<i64> {
    expr.next_fire_after_with_offset(after_unix_ms, offset_secs)
}

/// Applies deterministic, reproducible positive jitter to a scheduled cron fire timestamp.
///
/// - When `exact` is `true`, returns `base_fire_ms` unmodified (`0` jitter).
/// - When `exact` is `false`, adds a deterministic offset in
///   `[0, min(interval_ms / 10, 30_000)]` hashed via SHA-256 from `(wakeup_id, base_fire_ms)`.
/// - Never fires early (`result >= base_fire_ms`) and never drifts across restarts.
pub fn apply_cron_jitter(base_fire_ms: i64, interval_ms: i64, wakeup_id: &str, exact: bool) -> i64 {
    if exact || interval_ms <= 0 {
        return base_fire_ms;
    }
    let max_jitter = (interval_ms / 10).min(MAX_CRON_JITTER_MS);
    if max_jitter <= 0 {
        return base_fire_ms;
    }

    let mut hasher = Sha256::new();
    hasher.update(wakeup_id.as_bytes());
    hasher.update(b":");
    hasher.update(base_fire_ms.to_be_bytes());
    let digest = hasher.finalize();
    let sample = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    let window = (max_jitter as u64) + 1;
    let offset = (sample % window) as i64;
    base_fire_ms.saturating_add(offset)
}

/// Queries the host OS local timezone UTC offset in seconds at `unix_sec`
/// (positive east of UTC, negative west of UTC).
///
/// Uses thread-safe POSIX `localtime_r` on Unix and `_localtime64_s` on Windows,
/// relying strictly on the C89/POSIX-standardized first 9 `c_int` fields of `struct tm`
/// with generous trailing padding and pure-Rust Gregorian arithmetic.
pub fn host_local_offset_secs(unix_sec: i64) -> i32 {
    #[cfg(all(unix, target_pointer_width = "64"))]
    {
        use std::ffi::{c_int, c_long};

        #[repr(C)]
        struct PosixTm {
            tm_sec: c_int,
            tm_min: c_int,
            tm_hour: c_int,
            tm_mday: c_int,
            tm_mon: c_int,
            tm_year: c_int,
            tm_wday: c_int,
            tm_yday: c_int,
            tm_isdst: c_int,
            // Over-allocate trailing space for platform extensions (`tm_gmtoff`, `tm_zone`).
            _pad: [u64; 8],
        }

        unsafe extern "C" {
            fn localtime_r(timep: *const c_long, result: *mut PosixTm) -> *mut PosixTm;
        }

        let t: c_long = unix_sec;
        let mut tm = PosixTm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            _pad: [0; 8],
        };
        // SAFETY: `t` and `tm` are valid stack locals; `PosixTm` is strictly larger than
        // platform `struct tm` and begins with the standardized 9 `c_int` fields.
        let res = unsafe { localtime_r(&t, &mut tm) };
        if res.is_null() {
            return 0;
        }
        offset_from_tm_fields(
            unix_sec,
            i64::from(tm.tm_year) + 1900,
            (tm.tm_mon + 1) as u32,
            tm.tm_mday as u32,
            tm.tm_hour as u32,
            tm.tm_min as u32,
            tm.tm_sec.clamp(0, 59) as u32,
        )
    }

    #[cfg(windows)]
    {
        use std::ffi::c_int;

        #[repr(C)]
        struct WinTm {
            tm_sec: c_int,
            tm_min: c_int,
            tm_hour: c_int,
            tm_mday: c_int,
            tm_mon: c_int,
            tm_year: c_int,
            tm_wday: c_int,
            tm_yday: c_int,
            tm_isdst: c_int,
            _pad: [u64; 4],
        }

        unsafe extern "C" {
            fn _localtime64_s(tm: *mut WinTm, time: *const i64) -> c_int;
        }

        let mut tm = WinTm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            _pad: [0; 4],
        };
        // SAFETY: `tm` and `unix_sec` are valid stack locals.
        let rc = unsafe { _localtime64_s(&mut tm, &unix_sec) };
        if rc != 0 {
            return 0;
        }
        offset_from_tm_fields(
            unix_sec,
            i64::from(tm.tm_year) + 1900,
            (tm.tm_mon + 1) as u32,
            tm.tm_mday as u32,
            tm.tm_hour as u32,
            tm.tm_min as u32,
            tm.tm_sec.clamp(0, 59) as u32,
        )
    }

    #[cfg(not(any(all(unix, target_pointer_width = "64"), windows)))]
    {
        let _ = unix_sec;
        0
    }
}

#[cfg(any(all(unix, target_pointer_width = "64"), windows))]
fn offset_from_tm_fields(
    unix_sec: i64,
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> i32 {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return 0;
    }
    let local_epoch_sec = days_from_civil(year, month, day) * 86_400
        + i64::from(hour) * 3600
        + i64::from(minute) * 60
        + i64::from(second);
    let diff = local_epoch_sec - unix_sec;
    if (-86_400..=86_400).contains(&diff) {
        diff as i32
    } else {
        0
    }
}

// ---- Field parsing helpers ----

fn parse_field(
    token: &str,
    field: &'static str,
    min: u32,
    max: u32,
    sunday_7_is_0: bool,
) -> Result<u64, CronError> {
    if token.is_empty() {
        return Err(CronError::InvalidField {
            field,
            token: token.to_string(),
            reason: "field must not be empty".to_string(),
        });
    }

    let max_step = if sunday_7_is_0 { 7 } else { max - min + 1 };
    let mut mask: u64 = 0;

    for part in token.split(',') {
        if part.is_empty() {
            return Err(CronError::InvalidField {
                field,
                token: token.to_string(),
                reason: "empty list entry".to_string(),
            });
        }

        let (base, step) = if let Some((lhs, rhs)) = part.split_once('/') {
            if rhs.contains('/') {
                return Err(CronError::InvalidField {
                    field,
                    token: part.to_string(),
                    reason: "multiple '/' step separators".to_string(),
                });
            }
            let step = parse_strict_u32(rhs).ok_or_else(|| CronError::InvalidField {
                field,
                token: part.to_string(),
                reason: "invalid step value".to_string(),
            })?;
            if step == 0 || step > max_step {
                return Err(CronError::InvalidField {
                    field,
                    token: part.to_string(),
                    reason: format!("step must be in 1..={max_step}"),
                });
            }
            (lhs, Some(step))
        } else {
            (part, None)
        };

        let (start, end) = if base == "*" {
            let eff_max = if sunday_7_is_0 { 6 } else { max };
            (min, eff_max)
        } else if let Some((a_str, b_str)) = base.split_once('-') {
            if b_str.contains('-') {
                return Err(CronError::InvalidField {
                    field,
                    token: part.to_string(),
                    reason: "multiple '-' range separators".to_string(),
                });
            }
            let a = parse_strict_u32(a_str).ok_or_else(|| CronError::InvalidField {
                field,
                token: part.to_string(),
                reason: "invalid range start".to_string(),
            })?;
            let b = parse_strict_u32(b_str).ok_or_else(|| CronError::InvalidField {
                field,
                token: part.to_string(),
                reason: "invalid range end".to_string(),
            })?;
            if a < min || a > max || b < min || b > max {
                return Err(CronError::InvalidField {
                    field,
                    token: part.to_string(),
                    reason: format!("values must be in {min}..={max}"),
                });
            }
            if a > b {
                return Err(CronError::InvalidField {
                    field,
                    token: part.to_string(),
                    reason: format!("range start {a} exceeds end {b}"),
                });
            }
            (a, b)
        } else {
            if step.is_some() {
                return Err(CronError::InvalidField {
                    field,
                    token: part.to_string(),
                    reason: "step '/n' requires '*' or a range 'a-b'".to_string(),
                });
            }
            let v = parse_strict_u32(base).ok_or_else(|| CronError::InvalidField {
                field,
                token: part.to_string(),
                reason: "expected integer, '*', or range 'a-b'".to_string(),
            })?;
            if v < min || v > max {
                return Err(CronError::InvalidField {
                    field,
                    token: part.to_string(),
                    reason: format!("value {v} out of range {min}..={max}"),
                });
            }
            (v, v)
        };

        let inc = step.unwrap_or(1);
        let mut v = start;
        while v <= end {
            let bit = if sunday_7_is_0 && v == 7 { 0 } else { v };
            mask |= 1u64 << bit;
            match v.checked_add(inc) {
                Some(next) => v = next,
                None => break,
            }
        }
    }

    if mask == 0 {
        return Err(CronError::InvalidField {
            field,
            token: token.to_string(),
            reason: "field matched no values".to_string(),
        });
    }
    Ok(mask)
}

fn parse_strict_u32(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 3 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>().ok()
}

fn has_possible_dom_month(months: u16, dom: u32) -> bool {
    for month in 1u32..=12 {
        if (months & (1u16 << month)) == 0 {
            continue;
        }
        let max_dom = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => 29, // leap years allow Feb 29
            _ => 0,
        };
        for day in 1u32..=max_dom {
            if (dom & (1u32 << day)) != 0 {
                return true;
            }
        }
    }
    false
}

fn next_set_bit_u16(mask: u16, from: u32, max: u32) -> Option<u32> {
    (from..=max).find(|&bit| (mask & (1u16 << bit)) != 0)
}

fn next_set_bit_u32(mask: u32, from: u32, max: u32) -> Option<u32> {
    (from..=max).find(|&bit| (mask & (1u32 << bit)) != 0)
}

fn next_set_bit_u64(mask: u64, from: u32, max: u32) -> Option<u32> {
    (from..=max).find(|&bit| (mask & (1u64 << bit)) != 0)
}

// ---- Proleptic Gregorian Calendar Math (Howard Hinnant) ----

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Days since 1970-01-01 from proleptic Gregorian `(year, month, day)`.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let d = i64::from(day);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Proleptic Gregorian `(year, month, day)` from days since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

/// Day of week (`0 = Sunday .. 6 = Saturday`) from days since 1970-01-01 (Thursday = 4).
fn weekday_from_days(days: i64) -> u8 {
    (days + 4).rem_euclid(7) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc_ms(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
        let days = days_from_civil(year, month, day);
        let secs = days * 86_400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec);
        secs * 1000
    }

    #[test]
    fn calendar_roundtrip_and_weekdays() {
        // 1970-01-01 = Thursday (4)
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(weekday_from_days(0), 4);
        assert_eq!(civil_from_days(0), (1970, 1, 1));

        // 2024-02-29 = Thursday (4), 2028-02-29 = Tuesday (2), 2000-02-29 = Tuesday (2)
        assert_eq!(weekday_from_days(days_from_civil(2024, 2, 29)), 4);
        assert_eq!(weekday_from_days(days_from_civil(2028, 2, 29)), 2);
        assert_eq!(weekday_from_days(days_from_civil(2000, 2, 29)), 2);

        // Verify civil_from_days(days_from_civil(y, m, d)) roundtrips across leap & century years.
        for year in [1969, 1970, 1999, 2000, 2024, 2026, 2028, 2099, 2100, 2104] {
            for month in 1..=12 {
                let dim = days_in_month(year, month);
                for day in [1, 15, dim] {
                    let d = days_from_civil(year, month, day);
                    assert_eq!(civil_from_days(d), (year, month, day));
                }
            }
        }
    }

    #[test]
    fn parse_wildcards_steps_ranges_lists_and_sunday_0_7() {
        let every_min = CronExpr::parse("* * * * *").unwrap();
        assert_eq!(every_min.as_str(), "* * * * *");
        assert_eq!(
            every_min.next_fire_after_utc(utc_ms(2026, 6, 15, 10, 0, 0)),
            Some(utc_ms(2026, 6, 15, 10, 1, 0))
        );
        assert_eq!(
            every_min.next_fire_after_utc(utc_ms(2026, 6, 15, 10, 0, 59) + 999),
            Some(utc_ms(2026, 6, 15, 10, 1, 0))
        );

        let step_expr = CronExpr::parse("*/15 9-17/2 * * 1-5").unwrap();
        // 2026-06-15 is Monday (dow=1). At 08:50 -> 09:00.
        assert_eq!(
            step_expr.next_fire_after_utc(utc_ms(2026, 6, 15, 8, 50, 0)),
            Some(utc_ms(2026, 6, 15, 9, 0, 0))
        );
        // At 09:45 -> 11:00 (step 2 hours: 9, 11, 13, 15, 17).
        assert_eq!(
            step_expr.next_fire_after_utc(utc_ms(2026, 6, 15, 9, 45, 0)),
            Some(utc_ms(2026, 6, 15, 11, 0, 0))
        );

        let list_expr = CronExpr::parse("5,20,35,50 8,20 1,15 1,6,12 *").unwrap();
        assert_eq!(
            list_expr.next_fire_after_utc(utc_ms(2026, 6, 1, 8, 20, 0)),
            Some(utc_ms(2026, 6, 1, 8, 35, 0))
        );
        assert_eq!(
            list_expr.next_fire_after_utc(utc_ms(2026, 6, 15, 20, 50, 0)),
            Some(utc_ms(2026, 12, 1, 8, 5, 0))
        );

        // Sunday as 0 and Sunday as 7 produce identical schedules.
        let sun_0 = CronExpr::parse("0 9 * * 0").unwrap();
        let sun_7 = CronExpr::parse("0 9 * * 7").unwrap();
        // 2026-06-15 is Monday; next Sunday is 2026-06-21.
        let base = utc_ms(2026, 6, 15, 10, 0, 0);
        assert_eq!(
            sun_0.next_fire_after_utc(base),
            Some(utc_ms(2026, 6, 21, 9, 0, 0))
        );
        assert_eq!(
            sun_0.next_fire_after_utc(base),
            sun_7.next_fire_after_utc(base)
        );

        // Range 5-7 includes Fri (5), Sat (6), Sun (0).
        let weekend = CronExpr::parse("0 10 * * 5-7").unwrap();
        assert_eq!(
            weekend.next_fire_after_utc(utc_ms(2026, 6, 18, 12, 0, 0)), // Thu -> Fri 19
            Some(utc_ms(2026, 6, 19, 10, 0, 0))
        );
        assert_eq!(
            weekend.next_fire_after_utc(utc_ms(2026, 6, 20, 10, 0, 0)), // Sat -> Sun 21
            Some(utc_ms(2026, 6, 21, 10, 0, 0))
        );
        assert_eq!(
            weekend.next_fire_after_utc(utc_ms(2026, 6, 21, 10, 0, 0)), // Sun -> next Fri 26
            Some(utc_ms(2026, 6, 26, 10, 0, 0))
        );
    }

    #[test]
    fn posix_or_semantics_when_both_dom_and_dow_restricted() {
        // 09:00 on the 15th of the month OR on any Monday (1).
        let expr = CronExpr::parse("0 9 15 * 1").unwrap();
        // 2026-07-01 is Wednesday.
        // July 6 = Mon, July 13 = Mon, July 15 = Wed (15th!), July 20 = Mon.
        let t1 = expr
            .next_fire_after_utc(utc_ms(2026, 7, 1, 0, 0, 0))
            .unwrap();
        assert_eq!(t1, utc_ms(2026, 7, 6, 9, 0, 0));
        let t2 = expr.next_fire_after_utc(t1).unwrap();
        assert_eq!(t2, utc_ms(2026, 7, 13, 9, 0, 0));
        let t3 = expr.next_fire_after_utc(t2).unwrap();
        assert_eq!(t3, utc_ms(2026, 7, 15, 9, 0, 0));
        let t4 = expr.next_fire_after_utc(t3).unwrap();
        assert_eq!(t4, utc_ms(2026, 7, 20, 9, 0, 0));
    }

    #[test]
    fn leap_day_2028_and_century_non_leap_2100() {
        let feb29 = CronExpr::parse("30 8 29 2 *").unwrap();
        // From 2025-01-01 -> 2028-02-29T08:30:00Z.
        assert_eq!(
            feb29.next_fire_after_utc(utc_ms(2025, 1, 1, 0, 0, 0)),
            Some(utc_ms(2028, 2, 29, 8, 30, 0))
        );
        // From 2096-02-29T08:30:00Z -> skips 2100 (not leap!) -> 2104-02-29T08:30:00Z!
        assert_eq!(
            feb29.next_fire_after_utc(utc_ms(2096, 2, 29, 8, 30, 0)),
            Some(utc_ms(2104, 2, 29, 8, 30, 0))
        );
    }

    #[test]
    fn positive_negative_and_half_hour_timezone_offsets() {
        // 09:00 weekdays
        let expr = CronExpr::parse("0 9 * * 1-5").unwrap();

        // UTC+2 (+7200s): 09:00 local == 07:00 UTC.
        // Start at 2026-06-15 (Mon) 06:30 UTC (08:30 local) -> 07:00 UTC.
        assert_eq!(
            next_fire_after_with_offset(&expr, utc_ms(2026, 6, 15, 6, 30, 0), 7200),
            Some(utc_ms(2026, 6, 15, 7, 0, 0))
        );

        // UTC-5 (-18000s): 09:00 local == 14:00 UTC.
        // Start at 2026-06-15 13:59 UTC (08:59 local) -> 14:00 UTC.
        assert_eq!(
            next_fire_after_with_offset(&expr, utc_ms(2026, 6, 15, 13, 59, 0), -18_000),
            Some(utc_ms(2026, 6, 15, 14, 0, 0))
        );

        // UTC+5:30 (+19800s, India): 09:00 local == 03:30 UTC.
        assert_eq!(
            next_fire_after_with_offset(&expr, utc_ms(2026, 6, 15, 3, 0, 0), 19_800),
            Some(utc_ms(2026, 6, 15, 3, 30, 0))
        );

        // Day-of-week rollover across UTC midnight!
        // At 2026-06-14 (Sun UTC) 22:30 UTC in UTC+2 it is ALREADY 2026-06-15 (Mon) 00:30 local!
        // So next 09:00 weekday is 2026-06-15 09:00 local == 2026-06-15 07:00 UTC.
        assert_eq!(
            next_fire_after_with_offset(&expr, utc_ms(2026, 6, 14, 22, 30, 0), 7200),
            Some(utc_ms(2026, 6, 15, 7, 0, 0))
        );
    }

    #[test]
    fn dst_spring_forward_and_fall_back_deterministic_resolver() {
        // Simulated US Eastern (EST = -5h, EDT = -4h):
        // Spring forward: 2026-03-08 07:00:00Z (02:00 EST -> 03:00 EDT; 02:00..02:59 skipped).
        // Fall back:      2026-11-01 06:00:00Z (02:00 EDT -> 01:00 EST; 01:00..01:59 repeated).
        let spring_utc = utc_ms(2026, 3, 8, 7, 0, 0) / 1000;
        let fall_utc = utc_ms(2026, 11, 1, 6, 0, 0) / 1000;
        let us_eastern = |u: i64| -> i32 {
            if u >= spring_utc && u < fall_utc {
                -4 * 3600
            } else {
                -5 * 3600
            }
        };

        // 1. Spring-forward gap: 02:30 does NOT exist on 2026-03-08 -> advances to 2026-03-09 02:30 EDT (06:30Z).
        let at_0230 = CronExpr::parse("30 2 * * *").unwrap();
        let next = at_0230
            .next_fire_after_with_resolver(utc_ms(2026, 3, 8, 6, 0, 0), us_eastern)
            .unwrap();
        assert_eq!(next, utc_ms(2026, 3, 9, 6, 30, 0));

        // 2. Spring-forward 15-min cadence: 01:45 EST (06:45Z) -> 03:00 EDT (07:00Z), exact 15m elapsed!
        let every_15 = CronExpr::parse("*/15 * * * *").unwrap();
        let next_15 = every_15
            .next_fire_after_with_resolver(utc_ms(2026, 3, 8, 6, 45, 0), us_eastern)
            .unwrap();
        assert_eq!(next_15, utc_ms(2026, 3, 8, 7, 0, 0));

        // 3. Fall-back ambiguous hour: 01:30 daily fires at first 01:30 (EDT = 05:30Z), then next day (06:30Z),
        //    never double-firing on the same night!
        let at_0130 = CronExpr::parse("30 1 * * *").unwrap();
        let first = at_0130
            .next_fire_after_with_resolver(utc_ms(2026, 11, 1, 4, 0, 0), us_eastern)
            .unwrap();
        assert_eq!(first, utc_ms(2026, 11, 1, 5, 30, 0));
        let second = at_0130
            .next_fire_after_with_resolver(first, us_eastern)
            .unwrap();
        assert_eq!(second, utc_ms(2026, 11, 2, 6, 30, 0));

        // 4. Starting inside the second ambiguous 01:xx hour (01:15 EST = 06:15Z) finds 01:30 EST (06:30Z).
        let in_second_hour = at_0130
            .next_fire_after_with_resolver(utc_ms(2026, 11, 1, 6, 15, 0), us_eastern)
            .unwrap();
        assert_eq!(in_second_hour, utc_ms(2026, 11, 1, 6, 30, 0));
    }

    #[test]
    fn min_interval_validation_and_wraparound_detection() {
        let every_min = CronExpr::parse("* * * * *").unwrap();
        assert_eq!(every_min.validate_min_interval(60).unwrap(), 60);
        assert!(matches!(
            every_min.validate_min_interval(120),
            Err(CronError::IntervalTooShort {
                shortest_seconds: 60,
                min_seconds: 120
            })
        ));

        // Sneaky wraparound: :59 -> :00 is a 60s gap even though 0 and 59 look far apart!
        let wrap = CronExpr::parse("0,59 * * * *").unwrap();
        assert_eq!(wrap.min_interval_seconds(), Some(60));
        assert!(matches!(
            wrap.validate_min_interval(300),
            Err(CronError::IntervalTooShort {
                shortest_seconds: 60,
                min_seconds: 300
            })
        ));

        let every_5 = CronExpr::parse("*/5 * * * *").unwrap();
        assert_eq!(every_5.validate_min_interval(300).unwrap(), 300);
        assert!(every_5.validate_min_interval(301).is_err());

        // Leap-day schedule (4-year minimum interval).
        let feb29 = CronExpr::parse("0 9 29 2 *").unwrap();
        assert!(feb29.validate_min_interval(86_400).unwrap() >= 4 * 365 * 86_400);
    }

    #[test]
    fn deterministic_jitter_bounds_exact_and_reproducibility() {
        let base = utc_ms(2026, 6, 15, 9, 0, 0);

        // Exact timing always produces 0 jitter.
        assert_eq!(apply_cron_jitter(base, 3_600_000, "wk-1", true), base);

        // 1-minute interval -> max jitter = min(60_000 / 10, 30_000) = 6_000 ms.
        for i in 0..50 {
            let id = format!("wk-{i}");
            let j1 = apply_cron_jitter(base, 60_000, &id, false);
            let j2 = apply_cron_jitter(base, 60_000, &id, false);
            assert_eq!(j1, j2, "jitter must be deterministic across calls");
            assert!(j1 >= base && j1 <= base + 6_000);
        }

        // 1-hour interval -> capped at 30_000 ms (not 360_000 ms!).
        for i in 0..50 {
            let id = format!("wk-hr-{i}");
            let j = apply_cron_jitter(base, 3_600_000, &id, false);
            assert!(j >= base && j <= base + MAX_CRON_JITTER_MS);
        }

        // Different IDs spread across the window (not all collapsed to 0).
        let distinct: std::collections::HashSet<i64> = (0..32)
            .map(|i| apply_cron_jitter(base, 3_600_000, &format!("wk-{i}"), false))
            .collect();
        assert!(distinct.len() > 16);

        // Non-positive interval -> 0 jitter.
        assert_eq!(apply_cron_jitter(base, 0, "wk-1", false), base);
        assert_eq!(apply_cron_jitter(base, -1000, "wk-1", false), base);
    }

    #[test]
    fn timezone_parsing_and_serde_default() {
        assert_eq!(CronTimezone::default(), CronTimezone::Local);
        assert_eq!(CronTimezone::parse("local").unwrap(), CronTimezone::Local);
        assert_eq!(CronTimezone::parse("LOCAL").unwrap(), CronTimezone::Local);
        assert_eq!(CronTimezone::parse(" utc ").unwrap(), CronTimezone::Utc);
        assert_eq!(CronTimezone::parse("UTC").unwrap(), CronTimezone::Utc);
        assert!(CronTimezone::parse("America/New_York").is_err());
        assert!(CronTimezone::parse("").is_err());

        assert_eq!(
            serde_json::to_string(&CronTimezone::Local).unwrap(),
            "\"local\""
        );
        assert_eq!(
            serde_json::to_string(&CronTimezone::Utc).unwrap(),
            "\"utc\""
        );
        assert_eq!(
            serde_json::from_str::<CronTimezone>("\"UTC\"").unwrap(),
            CronTimezone::Utc
        );
        assert_eq!(
            serde_json::from_str::<CronTimezone>("\"local\"").unwrap(),
            CronTimezone::Local
        );

        // Host local offset lookup must execute cleanly without panicking and stay within valid bounds.
        let off = host_local_offset_secs(1_700_000_000);
        assert!((-14 * 3600..=14 * 3600).contains(&off));
        // Local next_fire_after must always return a timestamp strictly greater than after_unix_ms.
        let expr = CronExpr::parse("*/5 * * * *").unwrap();
        let now = 1_700_000_000_000;
        let next_local = expr.next_fire_after(now, CronTimezone::Local).unwrap();
        assert!(next_local > now);
        assert!(next_local - now <= 5 * 60 * 1000);
    }

    #[test]
    fn mutated_invalid_cron_expressions_fail_closed() {
        let invalid_cases = [
            "",
            "   ",
            "* * * *",           // 4 fields
            "* * * * * *",       // 6 fields (seconds unsupported)
            "60 * * * *",        // minute out of range
            "-1 * * * *",        // negative
            "* 24 * * *",        // hour out of range
            "* * 0 * *",         // dom 0
            "* * 32 * *",        // dom 32
            "* * * 0 *",         // month 0
            "* * * 13 *",        // month 13
            "* * * * 8",         // dow 8
            "*/0 * * * *",       // zero step
            "*/61 * * * *",      // step > field size
            "10-5 * * * *",      // reversed range
            "1-5-9 * * * *",     // double dash
            "*/2/3 * * * *",     // double slash
            "5/15 * * * *",      // single value with step
            ",5 * * * *",        // leading comma
            "5, * * * *",        // trailing comma
            "1,,2 * * * *",      // empty list item
            "0 9 * * MON",       // named weekday unsupported
            "0 9 31 2 *",        // impossible Feb 31
            "0 9 30 2 *",        // impossible Feb 30
            "0 9 31 4,6,9,11 *", // impossible 31st in 30-day months
            "abc * * * *",       // non-numeric
            "0 9 * * 0-8",       // range end out of bounds
        ];

        for bad in invalid_cases {
            assert!(
                CronExpr::parse(bad).is_err(),
                "expected invalid cron expression to fail closed: {bad:?}"
            );
        }
    }
}
