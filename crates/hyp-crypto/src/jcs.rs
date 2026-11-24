//! Strict RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Produces deterministic UTF-8 JSON with:
//! - Object keys sorted lexicographically by UTF-16 code units (RFC 8785 §3.2.3).
//! - Minimal string escaping (RFC 8785 §3.2.2.2).
//! - Normalized numbers (`-0.0` -> `0`, rejecting NaN/Infinity).
//! - Zero insignificant whitespace.

use serde::Serialize;
use serde_json::Value;

use crate::error::CryptoError;

/// Canonicalizes a `serde_json::Value` according to RFC 8785 (JCS).
pub fn canonicalize_value(value: &Value) -> Result<String, CryptoError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

/// Serializes any `Serialize` value and canonicalizes it according to RFC 8785 (JCS).
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    let json_val = serde_json::to_value(value)?;
    canonicalize_value(&json_val)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), CryptoError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(num) => write_number(num, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (idx, (k, v)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_canonical(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(num: &serde_json::Number, out: &mut String) -> Result<(), CryptoError> {
    if let Some(i) = num.as_i64() {
        use std::fmt::Write as _;
        let _ = write!(out, "{i}");
        return Ok(());
    }
    if let Some(u) = num.as_u64() {
        use std::fmt::Write as _;
        let _ = write!(out, "{u}");
        return Ok(());
    }
    let f = num
        .as_f64()
        .ok_or_else(|| CryptoError::InvalidEnvelope("unsupported JSON number".into()))?;
    if !f.is_finite() {
        return Err(CryptoError::InvalidEnvelope(
            "non-finite JSON number is not valid in RFC 8785 JCS".into(),
        ));
    }
    if f == 0.0 {
        out.push('0');
        return Ok(());
    }
    // RFC 8785 §3.2.2.3 ES6 Number serialization for finite non-zero floats.
    let abs = f.abs();
    if abs.fract() == 0.0 && abs < 1e21 {
        if f < 0.0 {
            out.push('-');
        }
        // Format exact integer value without ".0".
        let s = format!("{abs:.0}");
        out.push_str(&s);
        return Ok(());
    }
    // Use Rust's shortest round-trip representation (Ryū/Dragonbox in std)
    // and adjust exponent thresholds to match ES6 (1e-6 .. 1e21 fixed, else e+/e-).
    let s = format_es6_float(f);
    out.push_str(&s);
    Ok(())
}

fn format_es6_float(f: f64) -> String {
    let neg = f.is_sign_negative();
    let abs = f.abs();
    // Scientific notation via Rust shortest round-trip `{:e}`.
    let sci = format!("{abs:e}");
    let (mantissa, exp_str) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp_str.parse().unwrap_or(0);

    // Strip decimal point to obtain raw significant digits (k digits).
    let digits: String = mantissa.chars().filter(|&c| c != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1; // ES6 notation: value = 0.<digits> * 10^n

    let mut result = String::new();
    if neg {
        result.push('-');
    }

    if k <= n && n <= 21 {
        result.push_str(&digits);
        for _ in 0..(n - k) {
            result.push('0');
        }
    } else if 0 < n && n <= 21 {
        let split = n as usize;
        result.push_str(&digits[..split]);
        result.push('.');
        result.push_str(&digits[split..]);
    } else if -6 < n && n <= 0 {
        result.push_str("0.");
        for _ in 0..(-n) {
            result.push('0');
        }
        result.push_str(&digits);
    } else if k == 1 {
        result.push_str(&digits);
        result.push('e');
        if exp >= 0 {
            result.push('+');
        }
        result.push_str(&exp.to_string());
    } else {
        result.push_str(&digits[..1]);
        result.push('.');
        result.push_str(&digits[1..]);
        result.push('e');
        if exp >= 0 {
            result.push('+');
        }
        result.push_str(&exp.to_string());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jcs_rfc8785_key_sorting_and_utf16() {
        // RFC 8785 §3.2.3 sorting example:
        // U+E000 (\ue000) sorts AFTER U+1F600 (surrogate pair 0xD83D 0xDE00) in UTF-16!
        let val = json!({
            "\u{e000}": "pua",
            "\u{1f600}": "emoji",
            "b": 2,
            "a": 1,
            "\r": "cr"
        });
        let canon = canonicalize_value(&val).unwrap();
        assert_eq!(
            canon,
            "{\"\\r\":\"cr\",\"a\":1,\"b\":2,\"\u{1f600}\":\"emoji\",\"\u{e000}\":\"pua\"}"
        );
    }

    #[test]
    fn jcs_rfc8785_numbers_and_escapes() {
        let val = json!({
            "neg_zero": -0.0,
            "small": 1e-7,
            "fixed_small": 1e-6,
            "big_int": 1e20,
            "sci_big": 1e21,
            "ctrl": "\u{0000}\u{0008}\u{000c}\n\r\t\"\\/"
        });
        let canon = canonicalize_value(&val).unwrap();
        assert_eq!(
            canon,
            "{\"big_int\":100000000000000000000,\"ctrl\":\"\\u0000\\b\\f\\n\\r\\t\\\"\\\\/\",\"fixed_small\":0.000001,\"neg_zero\":0,\"sci_big\":1e+21,\"small\":1e-7}"
        );
    }
}
