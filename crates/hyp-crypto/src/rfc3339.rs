//! Compatibility RFC 3339 entry points backed by the shared protocol calendar.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::CryptoError;

/// Current UTC wall-clock time as Unix epoch milliseconds.
pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub use hyp_proto::rfc3339::{format_rfc3339_millis, format_rfc3339_seconds};

/// Parses legacy-compatible RFC 3339 into milliseconds, retaining crypto diagnostics.
pub fn parse_rfc3339_millis(ts: &str) -> Result<i64, CryptoError> {
    use hyp_proto::rfc3339::{TimestampParseError, parse_rfc3339_nanos};
    let nanos = parse_rfc3339_nanos(ts, false).map_err(|error| {
        let message = match error {
            TimestampParseError::InvalidTimestamp => format!("invalid RFC 3339 timestamp '{ts}'"),
            TimestampParseError::OutOfRange => format!("out-of-range RFC 3339 timestamp '{ts}'"),
            TimestampParseError::EmptyFraction => format!("empty fractional seconds in '{ts}'"),
            TimestampParseError::InvalidOffset => format!("invalid timezone offset in '{ts}'"),
            TimestampParseError::MissingTimezone => {
                format!("missing or invalid timezone in '{ts}'")
            }
        };
        CryptoError::InvalidPairing(message)
    })?;
    i64::try_from(nanos.div_euclid(1_000_000))
        .map_err(|_| CryptoError::InvalidPairing(format!("out-of-range RFC 3339 timestamp '{ts}'")))
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
