//! A Stream in a column declared binary, carried the way `PostgreSQL`
//! itself writes binary: the bytea hex form, `\x` and two digits a byte.
//!
//! Every Stream is inserted as the hex literal a bytea column reads as the
//! bytes. Coming back, the value must be in that form — what a bytea
//! column answers under the default `bytea_output` — and anything else is
//! refused rather than taken for bytes: a column that holds text is
//! declared `column = "text"` (`transport::sql::Column`).

/// `bytes` in the bytea hex form: `\x` then two lower-case digits a byte.
#[must_use]
pub fn hex_literal(bytes: &[u8]) -> String {
    format!("\\x{}", codec::hex::encode(bytes))
}

/// The bytes a value in the bytea hex form names, or `None` when `text` is
/// not in that form.
#[must_use]
pub fn from_hex_literal(text: &str) -> Option<Vec<u8>> {
    codec::hex::decode(text.strip_prefix("\\x")?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_through_the_hex_form() {
        let bytes: Vec<u8> = (0..=255).collect();
        let literal = hex_literal(&bytes);
        assert!(literal.starts_with("\\x000102"));
        assert_eq!(from_hex_literal(&literal), Some(bytes));
        assert_eq!(hex_literal(b""), "\\x");
        assert_eq!(from_hex_literal("\\x"), Some(Vec::new()));
    }

    #[test]
    fn what_is_not_the_hex_form_is_not_bytes() {
        assert_eq!(from_hex_literal("plain"), None);
        assert_eq!(from_hex_literal("\\xabc"), None, "an odd digit count");
        assert_eq!(from_hex_literal("\\xzz"), None, "not hex");
    }
}
