//! Bounded editable input; pasted line breaks never execute multiple commands.
use nulllobby_core::text::sanitize_terminal;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_BYTES: usize = 8192;
pub const MAX_LINES: usize = 32;
#[derive(Default)]
pub struct Input {
    text: Zeroizing<String>,
    cursor: usize,
    pub pasted: bool,
}
impl Input {
    pub fn text(&self) -> &str {
        &self.text
    }
    pub fn clear(&mut self) {
        self.text.zeroize();
        self.cursor = 0;
        self.pasted = false;
    }
    pub fn insert(&mut self, c: char) {
        if !c.is_control() && self.text.len() + c.len_utf8() <= MAX_BYTES {
            self.text.insert(self.cursor, c);
            self.cursor += c.len_utf8();
        }
    }
    pub fn paste(&mut self, text: &str) -> Result<(), &'static str> {
        if text.len() > MAX_BYTES {
            return Err("Paste exceeds 8 KiB");
        }
        let normalized = Zeroizing::new(text.replace("\r\n", "\n").replace('\r', "\n"));
        let mut clean = Zeroizing::new(String::new());
        for (i, line) in normalized.split('\n').enumerate() {
            if i > 0 {
                clean.push('\n');
            }
            clean.push_str(&sanitize_terminal(&line.replace('\t', "    "), MAX_BYTES));
        }
        if self.text.len() + clean.len() > MAX_BYTES {
            return Err("Input exceeds 8 KiB");
        }
        let lines = self.text.bytes().filter(|c| *c == b'\n').count()
            + clean.bytes().filter(|c| *c == b'\n').count()
            + 1;
        if lines > MAX_LINES {
            return Err("Paste is limited to 32 lines");
        }
        self.text.insert_str(self.cursor, &clean);
        self.cursor += clean.len();
        self.pasted = true;
        Ok(())
    }
    pub fn left(&mut self) {
        self.cursor = self.text[..self.cursor]
            .char_indices()
            .last()
            .map_or(0, |(i, _)| i);
    }
    pub fn right(&mut self) {
        if let Some(c) = self.text[self.cursor..].chars().next() {
            self.cursor += c.len_utf8();
        }
    }
    pub fn home(&mut self) {
        self.cursor = 0;
    }
    pub fn end(&mut self) {
        self.cursor = self.text.len();
    }
    pub fn backspace(&mut self) {
        let end = self.cursor;
        self.left();
        if self.cursor < end {
            self.text.replace_range(self.cursor..end, "");
        }
    }
    pub fn delete(&mut self) {
        if let Some(c) = self.text[self.cursor..].chars().next() {
            self.text
                .replace_range(self.cursor..self.cursor + c.len_utf8(), "");
        }
    }
    pub fn compact(&self) -> bool {
        self.text.contains('\n') || (self.pasted && self.text.len() > 120)
    }
    pub fn display(&self) -> String {
        if self.text.trim_start().starts_with("/join ") {
            return "/join [card hidden]".into();
        }
        if self.compact() {
            return format!(
                "[Pasted {} lines · {} bytes]  Enter sends text · F6 previews · Esc clears",
                self.text.lines().count().max(1),
                self.text.len()
            );
        }
        sanitize_terminal(&self.text, MAX_BYTES)
    }
    pub fn cursor_columns(&self) -> usize {
        unicode_width::UnicodeWidthStr::width(&self.text[..self.cursor])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paste_stays_compact_bounded_and_terminal_safe() {
        let mut input = Input::default();
        input
            .paste("first\r\n/quit\n\x1b]52;c;payload\x07")
            .unwrap();
        assert!(input.compact());
        assert!(input.display().starts_with("[Pasted 3 lines"));
        assert!(!input.text().contains('\x1b'));
        assert!(input.text().contains("\n/quit\n"));
        let prior = input.text().to_owned();
        assert!(input.paste(&"x\n".repeat(33)).is_err());
        assert_eq!(input.text(), prior);
        assert!(input.paste(&"x".repeat(MAX_BYTES + 1)).is_err());
    }
    #[test]
    fn unicode_editing_never_splits_characters() {
        let mut input = Input::default();
        input.paste("a🙂z").unwrap();
        input.left();
        input.backspace();
        assert_eq!(input.text(), "az");
        input.home();
        input.delete();
        assert_eq!(input.text(), "z");
        input.clear();
        assert_eq!(input.text(), "");
    }
}
