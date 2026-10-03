//! All display text must pass this boundary, even after signature verification.
use std::fmt;

#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedText<const MAX: usize>(String);
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TextError {
    #[error("text length out of bounds")]
    Length,
    #[error("text contains unsafe display characters")]
    Control,
}
fn unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}
impl<const MAX: usize> ValidatedText<MAX> {
    pub fn new(value: &str) -> Result<Self, TextError> {
        if value.is_empty() || value.len() > MAX {
            return Err(TextError::Length);
        }
        if value.chars().any(unsafe_char) {
            return Err(TextError::Control);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<const MAX: usize> fmt::Debug for ValidatedText<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedText([REDACTED])")
    }
}

/// Bounded output; strips terminal controls and bidi display controls. Does not
/// interpret ANSI: residual printable escape text is harmless and remains visible.
pub fn sanitize_terminal(input: &str, max_bytes: usize) -> String {
    let limit = max_bytes.min(crate::limits::CHAT_BYTES);
    let mut result = String::with_capacity(input.len().min(limit));
    for (offset, c) in input.char_indices() {
        if offset >= crate::limits::CHAT_BYTES {
            break;
        }
        if result.len().saturating_add(c.len_utf8()) > limit {
            break;
        }
        if !unsafe_char(c) {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ansi_osc_controls_bidi_and_long_utf8() {
        for text in [
            "\x1b[2J",
            "\x1b]52;c;payload\x07",
            "x\n",
            "\u{009b}2J",
            "a\u{202e}b",
            "\0",
        ] {
            assert_eq!(ValidatedText::<64>::new(text), Err(TextError::Control));
            assert!(!sanitize_terminal(text, 64).chars().any(unsafe_char));
        }
        assert_eq!(ValidatedText::<3>::new("🙂"), Err(TextError::Length));
        assert!(ValidatedText::<4>::new("🙂").is_ok());
        assert_eq!(sanitize_terminal("🙂hello", 3), "");
    }
    #[test]
    fn every_unicode_control_is_neutralized() {
        for c in (0..=0x10ffff)
            .filter_map(char::from_u32)
            .filter(|c| unsafe_char(*c))
        {
            assert!(sanitize_terminal(&c.to_string(), 64).is_empty());
        }
        assert_eq!(
            sanitize_terminal(&"a".repeat(9000), usize::MAX).len(),
            crate::limits::CHAT_BYTES
        );
    }
}
