//! A Stream that is not text, carried the way `PostgreSQL` itself writes
//! binary: the bytea hex form, `\x` and two digits a byte.
//!
//! A text column holds UTF-8 without a NUL and nothing else, so a Stream
//! that is anything else is inserted as the hex literal a bytea column
//! reads as the bytes and a text column keeps verbatim. Coming back, a
//! value in that form is the bytes again — which is what a bytea column
//! answers under the default `bytea_output`, and what a text column that
//! kept the literal answers too. Text that happens to start with `\x` and
//! run in hex is read as bytes; that is `PostgreSQL`'s own ambiguity, and
//! the same one.

use std::fmt::Write as _;

/// True when `bytes` can be one text column: UTF-8 without a NUL.
#[must_use]
pub fn is_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| !text.contains('\0'))
}

/// `bytes` in the bytea hex form: `\x` then two lower-case digits a byte.
#[must_use]
pub fn hex_literal(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("\\x");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bytes a value in the bytea hex form names, or `None` when `text` is
/// not in that form.
#[must_use]
pub fn from_hex_literal(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("\\x")?;
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(digits.get(at..at + 2)?, 16).ok())
        .collect()
}

/// A column value as the bytes it carries: decoded when in the hex form,
/// the text's bytes otherwise.
#[must_use]
pub fn column_bytes(text: String) -> Vec<u8> {
    from_hex_literal(&text).unwrap_or_else(|| text.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_utf8_without_a_nul() {
        assert!(is_text(b"a row"));
        assert!(is_text(b""));
        assert!(!is_text(b"a\0row"));
        assert!(!is_text(&[0xff, 0xfe]));
    }

    #[test]
    fn bytes_round_trip_through_the_hex_form() {
        let bytes: Vec<u8> = (0..=255).collect();
        let literal = hex_literal(&bytes);
        assert!(literal.starts_with("\\x000102"));
        assert_eq!(from_hex_literal(&literal), Some(bytes.clone()));
        assert_eq!(column_bytes(literal), bytes);
        assert_eq!(hex_literal(b""), "\\x");
        assert_eq!(from_hex_literal("\\x"), Some(Vec::new()));
    }

    #[test]
    fn what_is_not_the_hex_form_is_text() {
        assert_eq!(from_hex_literal("plain"), None);
        assert_eq!(from_hex_literal("\\xabc"), None, "an odd digit count");
        assert_eq!(from_hex_literal("\\xzz"), None, "not hex");
        assert_eq!(column_bytes("plain".to_string()), b"plain");
    }
}
