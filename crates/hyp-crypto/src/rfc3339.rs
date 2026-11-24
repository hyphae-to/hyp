//! Minimal, zero-dependency RFC 3339 timestamp parser & millisecond UTC formatter.
//!
//! Uses Howard Hinnant's exact civil-calendar algorithms so `hyp-crypto` has zero external
//! datetime crate version constraints on Rust 1.87+.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::CryptoError;

/// Current UTC wall-clock time as Unix epoch milliseconds.
pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i64, month: u8) -> u8 {
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

fn days_from_civil(year: i64, month: u8, day: u8) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let m_adj = if month > 2 {
        (month - 3) as u64
    } else {
        (month + 9) as u64
    };
    let doy = (153 * m_adj + 2) / 5 + (day as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

/// Formats Unix epoch milliseconds as `YYYY-MM-DDTHH:MM:SS.sssZ` (matching JS `Date.toISOString()`).
pub fn format_rfc3339_millis(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1_000);
    let millis = unix_ms.rem_euclid(1_000) as u32;
    let days = secs.div_euclid(86_400);
    let sec_of_day = secs.rem_euclid(86_400) as u32;
    let hour = sec_of_day / 3600;
    let minute = (sec_of_day % 3600) / 60;
    let second = sec_of_day % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Strictly parses an RFC 3339 timestamp string into Unix epoch milliseconds.
pub fn parse_rfc3339_millis(ts: &str) -> Result<i64, CryptoError> {
    let b = ts.as_bytes();
    if b.len() < 20 {
        return Err(CryptoError::InvalidPairing(format!(
            "invalid RFC 3339 timestamp '{ts}'"
        )));
    }
    let parse_u = |slice: &[u8]| -> Result<u32, CryptoError> {
        let s = std::str::from_utf8(slice)
            .map_err(|_| CryptoError::InvalidPairing(format!("invalid RFC 3339 timestamp '{ts}'")))?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return Err(CryptoError::InvalidPairing(format!(
                "invalid RFC 3339 timestamp '{ts}'"
            )));
        }
        s.parse::<u32>()
            .map_err(|_| CryptoError::InvalidPairing(format!("invalid RFC 3339 timestamp '{ts}'")))
    };

    if b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(CryptoError::InvalidPairing(format!(
            "invalid RFC 3339 timestamp '{ts}'"
        )));
    }

    let year = parse_u(&b[0..4])? as i64;
    let month = parse_u(&b[5..7])? as u8;
    let day = parse_u(&b[8..10])? as u8;
    let hour = parse_u(&b[11..13])? as i64;
    let minute = parse_u(&b[14..16])? as i64;
    let second = parse_u(&b[17..19])? as i64;

    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(CryptoError::InvalidPairing(format!(
            "out-of-range RFC 3339 timestamp '{ts}'"
        )));
    }

    let mut pos = 19;
    let mut millis = 0i64;
    if pos < b.len() && b[pos] == b'.' {
        pos += 1;
        let start = pos;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == start {
            return Err(CryptoError::InvalidPairing(format!(
                "empty fractional seconds in '{ts}'"
            )));
        }
        let frac = &b[start..pos];
        let d0 = (frac[0] - b'0') as i64;
        let d1 = if frac.len() > 1 { (frac[1] - b'0') as i64 } else { 0 };
        let d2 = if frac.len() > 2 { (frac[2] - b'0') as i64 } else { 0 };
        millis = d0 * 100 + d1 * 10 + d2;
    }

    let tz = &b[pos..];
    let offset_secs: i64 = if tz == b"Z" || tz == b"z" {
        0
    } else if tz.len() == 6 && matches!(tz[0], b'+' | b'-') && tz[3] == b':' {
        let sign = if tz[0] == b'+' { 1i64 } else { -1i64 };
        let off_h = parse_u(&tz[1..3])? as i64;
        let off_m = parse_u(&tz[4..6])? as i64;
        if off_h > 23 || off_m > 59 {
            return Err(CryptoError::InvalidPairing(format!(
                "invalid timezone offset in '{ts}'"
            )));
        }
        sign * (off_h * 3600 + off_m * 60)
    } else {
        return Err(CryptoError::InvalidPairing(format!(
            "missing or invalid timezone in '{ts}'"
        )));
    };

    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    Ok(secs * 1_000 + millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_roundtrip_and_offsets() {
        assert_eq!(parse_rfc3339_millis("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(format_rfc3339_millis(0), "1970-01-01T00:00:00.000Z");

        let ms = parse_rfc3339_millis("2026-11-24T12:34:56.789Z").unwrap();
        assert_eq!(format_rfc3339_millis(ms), "2026-11-24T12:34:56.789Z");

        // Offset equivalence: +02:00
        let ms_off = parse_rfc3339_millis("2026-11-24T14:34:56.789+02:00").unwrap();
        assert_eq!(ms_off, ms);

        // Leap day valid in 2024, invalid in 2026
        assert!(parse_rfc3339_millis("2024-02-29T00:00:00Z").is_ok());
        assert!(parse_rfc3339_millis("2026-02-29T00:00:00Z").is_err());
    }
}
