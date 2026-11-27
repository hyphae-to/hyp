//! RFC 3339 parsing and civil-calendar formatting shared by wire and crypto callers.
//! Uses Howard Hinnant's civil-calendar algorithms.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampParseError {
    InvalidTimestamp,
    OutOfRange,
    EmptyFraction,
    InvalidOffset,
    MissingTimezone,
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

/// Formats whole UTC seconds while preserving the millisecond formatter's date range.
pub fn format_rfc3339_seconds(unix_ms: i64) -> String {
    let mut formatted = format_rfc3339_millis(unix_ms);
    formatted.truncate(formatted.len() - 5);
    formatted.push('Z');
    formatted
}

/// Parses UTC nanoseconds. Strict mode requires uppercase T/Z; compatibility mode also
/// accepts lowercase t/z and a space between date and time.
pub fn parse_rfc3339_nanos(ts: &str, strict: bool) -> Result<i128, TimestampParseError> {
    use TimestampParseError::*;
    let bytes = ts.as_bytes();
    if bytes.len() < 20 {
        return Err(InvalidTimestamp);
    }
    let valid_separator = if strict {
        bytes[10] == b'T'
    } else {
        matches!(bytes[10], b'T' | b't' | b' ')
    };
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || !valid_separator
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(InvalidTimestamp);
    }
    let year = i64::from(parse_digits(&bytes[0..4])?);
    let month = parse_digits(&bytes[5..7])? as u8;
    let day = parse_digits(&bytes[8..10])? as u8;
    let hour = i64::from(parse_digits(&bytes[11..13])?);
    let minute = i64::from(parse_digits(&bytes[14..16])?);
    let second = i64::from(parse_digits(&bytes[17..19])?);
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(OutOfRange);
    }
    let mut pos = 19;
    let mut nanos = 0i128;
    if bytes[pos] == b'.' {
        pos += 1;
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == start {
            return Err(EmptyFraction);
        }
        let mut scale = 100_000_000i128;
        for byte in &bytes[start..start + (pos - start).min(9)] {
            nanos += i128::from(byte - b'0') * scale;
            scale /= 10;
        }
    }
    let timezone = &bytes[pos..];
    let offset = if timezone == b"Z" || (!strict && timezone == b"z") {
        0
    } else if timezone.len() == 6 && matches!(timezone[0], b'+' | b'-') && timezone[3] == b':' {
        let hours = i64::from(parse_digits(&timezone[1..3])?);
        let minutes = i64::from(parse_digits(&timezone[4..6])?);
        if hours > 23 || minutes > 59 {
            return Err(InvalidOffset);
        }
        let sign = if timezone[0] == b'+' { 1 } else { -1 };
        sign * (hours * 3600 + minutes * 60)
    } else {
        return Err(MissingTimezone);
    };
    let seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    Ok(i128::from(seconds) * 1_000_000_000 + nanos)
}

fn parse_digits(bytes: &[u8]) -> Result<u32, TimestampParseError> {
    if bytes.is_empty() {
        return Err(TimestampParseError::InvalidTimestamp);
    }
    bytes
        .iter()
        .try_fold(0u32, |number, byte| {
            if byte.is_ascii_digit() {
                number.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
            } else {
                None
            }
        })
        .ok_or(TimestampParseError::InvalidTimestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_timestamp_rejects_unicode_without_panicking() {
        let parse = crate::cloudevent::parse_rfc3339_utc_nanos;
        assert!(parse("2026-11-26T23:44:00Z").is_some());
        assert!(parse("2026-11-26T23:44:工Z").is_none());
    }

    #[test]
    fn strict_and_compatibility_case_rules_remain_distinct() {
        for timestamp in [
            "1970-01-01t00:00:00Z",
            "1970-01-01 00:00:00Z",
            "1970-01-01T00:00:00z",
        ] {
            assert_eq!(parse_rfc3339_nanos(timestamp, false), Ok(0));
            assert!(parse_rfc3339_nanos(timestamp, true).is_err());
        }
        assert_eq!(format_rfc3339_millis(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(format_rfc3339_seconds(-1), "1969-12-31T23:59:59Z");
    }
}
