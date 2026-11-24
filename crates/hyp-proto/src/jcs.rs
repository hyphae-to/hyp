//! Strict RFC 8785 JSON Canonicalization Scheme (JCS) + SHA-256 digest helpers.
//!
//! Implements:
//! - RFC 8785 §3.2.2.2 string escaping (lowercase `\u00xx` control escapes, raw UTF-8 otherwise)
//! - RFC 8785 §3.2.2.3 ECMA-262 IEEE-754 double serialization (`Number.prototype.toString(10)`)
//! - RFC 8785 §3.2.3 object property sorting by UTF-16 code unit sequence

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JcsError {
    #[error("RFC 8785 JCS forbids non-finite IEEE-754 numbers (NaN or Infinity)")]
    NonFiniteNumber,
    #[error("failed to convert value to JSON: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Canonicalizes a `serde_json::Value` into an RFC 8785 JCS UTF-8 string.
pub fn to_jcs_string(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_jcs(value, &mut out)?;
    Ok(out)
}

/// Canonicalizes a `serde_json::Value` into RFC 8785 JCS UTF-8 bytes.
pub fn to_jcs_bytes(value: &Value) -> Result<Vec<u8>, JcsError> {
    Ok(to_jcs_string(value)?.into_bytes())
}

/// Serializes any `Serialize` type into RFC 8785 JCS UTF-8 text.
pub fn serialize_jcs<T: Serialize>(value: &T) -> Result<String, JcsError> {
    let json = serde_json::to_value(value)?;
    to_jcs_string(&json)
}

/// Computes lowercase hex-encoded SHA-256 over raw bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Computes lowercase hex-encoded SHA-256 over the RFC 8785 JCS representation of `value`.
pub fn jcs_sha256_hex(value: &Value) -> Result<String, JcsError> {
    let canonical = to_jcs_string(value)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn write_jcs(value: &Value, out: &mut String) -> Result<(), JcsError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            let f = n.as_f64().ok_or(JcsError::NonFiniteNumber)?;
            write_ecma_number(f, out)?;
        }
        Value::String(s) => write_jcs_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // RFC 8785 §3.2.3: sort property names by UTF-16 code unit sequence.
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            for (idx, (key, val)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs_string(key, out);
                out.push(':');
                write_jcs(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2 string serialization.
fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                // RFC 8785 §3.2.2.2 mandates lowercase hex digits for \u00xx escapes.
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Formats an IEEE-754 double according to ECMA-262 §7.1.12.1 / RFC 8785 §3.2.2.3.
pub fn format_ecma_number(f: f64) -> Result<String, JcsError> {
    let mut out = String::new();
    write_ecma_number(f, &mut out)?;
    Ok(out)
}

fn write_ecma_number(f: f64, out: &mut String) -> Result<(), JcsError> {
    if !f.is_finite() {
        return Err(JcsError::NonFiniteNumber);
    }
    // RFC 8785 §3.2.2.3: both +0.0 and -0.0 serialize as "0".
    if f == 0.0 {
        out.push('0');
        return Ok(());
    }
    let abs = if f.is_sign_negative() {
        out.push('-');
        -f
    } else {
        f
    };

    // Rust's {:e} uses the exact shortest round-trip IEEE-754 representation with
    // round-to-nearest-even tie breaking (Dragon/Grisu3), matching V8 & ECMA-262.
    let sci = format!("{abs:e}");
    let (mantissa, exp_str) = sci
        .split_once('e')
        .expect("scientific notation always contains 'e'");
    let exp: i32 = exp_str.parse().expect("valid exponent");

    // Extract significant digits without '.' (e.g. "1.23" -> "123", "5" -> "5").
    let mut digits = String::with_capacity(mantissa.len());
    for b in mantissa.bytes() {
        if b != b'.' {
            digits.push(b as char);
        }
    }
    // Strip any trailing zeros (shortest form should already have none, defensive guard).
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }

    let k = digits.len() as i32;
    // ECMA-262 notation: value = 0.<digits> * 10^n, so n = exp + 1.
    let n = exp + 1;

    if k <= n && n <= 21 {
        // Step 6: integer form with trailing zeros.
        out.push_str(&digits);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        // Step 7: fixed decimal with integer and fractional parts.
        let split = n as usize;
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
    } else if -6 < n && n <= 0 {
        // Step 8: 0.<zeros><digits>
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        // Steps 9 & 10: scientific notation with explicit '+' or '-' sign.
        if k == 1 {
            out.push_str(&digits);
        } else {
            out.push_str(&digits[..1]);
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        let e = n - 1;
        if e >= 0 {
            out.push('+');
        }
        use std::fmt::Write as _;
        let _ = write!(out, "{e}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc8785_section_3_2_2_3_number_vectors() {
        // Official RFC 8785 §3.2.2.3 & Appendix B test vectors.
        let cases: &[(&str, &str)] = &[
            ("0", "0"),
            ("-0.0", "0"),
            ("0.0", "0"),
            ("1", "1"),
            ("4.50", "4.5"),
            ("2e-3", "0.002"),
            ("0.000001", "0.000001"),
            ("0.0000001", "1e-7"),
            ("0.000000000000000000000000001", "1e-27"),
            ("1e20", "100000000000000000000"),
            ("1e21", "1e+21"),
            ("1E30", "1e+30"),
            ("333333333.33333329", "333333333.3333333"),
            ("100000000000000000000", "100000000000000000000"),
            ("999999999999999900000", "999999999999999900000"),
            ("5e-324", "5e-324"),
            ("1.7976931348623157e+308", "1.7976931348623157e+308"),
            ("-1e-7", "-1e-7"),
            ("-1e-6", "-0.000001"),
            ("-1e+21", "-1e+21"),
            ("1000000000000000000000", "1e+21"),
        ];

        for (input, expected) in cases {
            let val: Value = serde_json::from_str(input).unwrap();
            let got = to_jcs_string(&val).unwrap();
            assert_eq!(got, *expected, "RFC 8785 number vector failed for {input}");
        }
    }

    #[test]
    fn rfc8785_section_3_2_3_utf16_key_sorting() {
        // Official RFC 8785 §3.2.3 sorting test vector:
        // Note: U+1F600 (UTF-16: D83D DE00) MUST sort BEFORE U+E000 (UTF-16: E000)!
        let input = r#"{
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "1": "One",
            "\u0080": "Control",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "\ud83d\ude00": "Emoji: Grinning Face",
            "\u00f6": "Latin Small Letter O With Diaeresis",
            "\u008a": "Control 2",
            "\ue000": "Private Use"
        }"#;
        let val: Value = serde_json::from_str(input).unwrap();
        let canonical = to_jcs_string(&val).unwrap();
        let expected = concat!(
            "{",
            "\"\\r\":\"Carriage Return\",",
            "\"1\":\"One\",",
            "\"\u{0080}\":\"Control\",",
            "\"\u{008a}\":\"Control 2\",",
            "\"\u{00f6}\":\"Latin Small Letter O With Diaeresis\",",
            "\"\u{20ac}\":\"Euro Sign\",",
            "\"\u{1f600}\":\"Emoji: Grinning Face\",",
            "\"\u{e000}\":\"Private Use\",",
            "\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"",
            "}"
        );
        assert_eq!(canonical, expected);
    }

    #[test]
    fn rfc8785_section_3_2_2_2_string_escaping() {
        let val = json!({
            "controls": "\u{0000}\u{0008}\u{0009}\u{000a}\u{000c}\u{000d}\u{001f}",
            "slash": "a/b\"c\\d",
            "unicode": "café 日本語 🚀"
        });
        let got = to_jcs_string(&val).unwrap();
        assert_eq!(
            got,
            r#"{"controls":"\u0000\b\t\n\f\r\u001f","slash":"a/b\"c\\d","unicode":"café 日本語 🚀"}"#
        );
    }

    #[test]
    fn rfc8785_appendix_b_complete_structure_vector() {
        // Official RFC 8785 §3.2.4 / Appendix B canonicalization example.
        let input = r#"{
            "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
            "string": "\u20ac$\u000F\nA'B\"\\",
            "literals": [null, true, false]
        }"#;
        let val: Value = serde_json::from_str(input).unwrap();
        let got = to_jcs_string(&val).unwrap();
        let expected = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\"}";
        assert_eq!(got, expected);
    }

    #[test]
    fn non_finite_numbers_fail_closed() {
        assert!(format_ecma_number(f64::NAN).is_err());
        assert!(format_ecma_number(f64::INFINITY).is_err());
        assert!(format_ecma_number(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn sha256_helpers_are_deterministic() {
        let a = json!({"b": 1, "a": [true, null, "x"]});
        let b = json!({"a": [true, null, "x"], "b": 1.0});
        assert_eq!(jcs_sha256_hex(&a).unwrap(), jcs_sha256_hex(&b).unwrap());
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
