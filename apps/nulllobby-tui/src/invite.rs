//! Explicit invitation display/copy. Remote chat never reaches this path.
use base64::{Engine, engine::general_purpose::STANDARD};
use crossterm::{
    cursor::MoveTo,
    queue,
    style::{Color, Print, SetBackgroundColor, SetForegroundColor},
    terminal::EnableLineWrap,
};
use ratatui::{
    layout::Rect,
    widgets::{Paragraph, Wrap},
};
use std::io::{self, Write};
use zeroize::Zeroizing;

pub const INSTRUCTIONS: &str = "Select the card below with your terminal's copy shortcut.\nCtrl+Y requests clipboard copy (terminal support required).\nPrivate card = lobby access. Clipboard/scrollback may retain it.\nEsc hides the card. Nothing is copied automatically.";
pub fn card_area(overlay: Rect) -> Rect {
    if overlay.width == 0 {
        return Rect::default();
    }
    let offset = Paragraph::new(INSTRUCTIONS)
        .wrap(Wrap { trim: false })
        .line_count(overlay.width)
        .min(u16::MAX as usize) as u16
        + 2;
    let y = overlay.y.saturating_add(offset).min(overlay.bottom());
    Rect::new(
        overlay.x,
        y,
        overlay.width,
        overlay.bottom().saturating_sub(y).saturating_sub(1),
    )
}
fn valid_card_text(card: &str) -> bool {
    card.starts_with("nl:v1:")
        && card.len() <= nulllobby_core::limits::CARD_TEXT_BYTES
        && card
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_'))
}
pub fn fits(card: &str, area: Rect) -> bool {
    valid_card_text(card)
        && area.width > 0
        && card.len().div_ceil(area.width as usize) <= area.height as usize
}
pub fn draw(
    writer: &mut impl Write,
    card: &str,
    area: Rect,
    foreground: Color,
    background: Color,
) -> io::Result<()> {
    if !fits(card, area) {
        return Ok(());
    }
    // A single Print lets the terminal mark soft wraps. Per-line widget writes
    // would insert hard selection boundaries or include panel borders in a copy.
    queue!(
        writer,
        EnableLineWrap,
        MoveTo(area.x, area.y),
        SetForegroundColor(foreground),
        SetBackgroundColor(background),
        Print(card)
    )?;
    writer.flush()
}
pub fn copy(writer: &mut impl Write, card: &str) -> io::Result<()> {
    if !valid_card_text(card) {
        return Err(io::Error::other("Invalid invitation"));
    }
    let encoded = Zeroizing::new(STANDARD.encode(card));
    // Only the user's explicit Ctrl+Y in an already revealed invite invokes this.
    write!(writer, "\x1b]52;c;{}\x07", encoded.as_str())?;
    writer.flush()
}
pub fn color(color: ratatui::style::Color) -> Color {
    use ratatui::style::Color as R;
    match color {
        R::Reset => Color::Reset,
        R::Black => Color::Black,
        R::Red => Color::DarkRed,
        R::Green => Color::DarkGreen,
        R::Yellow => Color::DarkYellow,
        R::Blue => Color::DarkBlue,
        R::Magenta => Color::DarkMagenta,
        R::Cyan => Color::DarkCyan,
        R::Gray => Color::Grey,
        R::DarkGray => Color::DarkGrey,
        R::LightRed => Color::Red,
        R::LightGreen => Color::Green,
        R::LightYellow => Color::Yellow,
        R::LightBlue => Color::Blue,
        R::LightMagenta => Color::Magenta,
        R::LightCyan => Color::Cyan,
        R::White => Color::White,
        R::Indexed(n) => Color::AnsiValue(n),
        R::Rgb(r, g, b) => Color::Rgb { r, g, b },
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn card_display_is_one_unbroken_write_and_clipboard_needs_explicit_call() {
        let card = format!("nl:v1:direct-private:{}", "A".repeat(200));
        let mut output = Vec::new();
        draw(
            &mut output,
            &card,
            Rect::new(0, 7, 80, 8),
            Color::White,
            Color::Black,
        )
        .unwrap();
        assert!(output.ends_with(card.as_bytes()));
        assert!(!output.contains(&b'\n'));
        assert!(!output.windows(4).any(|s| s == b"]52;"));
        output.clear();
        copy(&mut output, &card).unwrap();
        let encoded = &output[7..output.len() - 1];
        assert_eq!(STANDARD.decode(encoded).unwrap(), card.as_bytes());
        assert!(!fits(&card, Rect::new(0, 0, 10, 2)));
        assert!(copy(&mut Vec::new(), "nl:v1:\x1b]52;c;bad\x07").is_err());
    }
}
