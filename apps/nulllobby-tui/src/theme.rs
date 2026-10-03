//! Data-only palettes and bounded irssi abstract imports. No terminal escapes,
//! template execution, scripts, includes or environment expansion are supported.
use ratatui::{
    style::{Color, Modifier, Style},
    widgets::BorderType,
};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

#[derive(Clone)]
pub struct Theme {
    pub name: String,
    pub text: Style,
    pub background: Color,
    pub border: Style,
    pub accent: Style,
    pub muted: Style,
    pub warning: Style,
    pub error: Style,
    pub nick: Style,
    pub own: Style,
    pub status: Style,
    pub border_type: BorderType,
}
impl Default for Theme {
    fn default() -> Self {
        Self::builtin("null").unwrap()
    }
}
impl Theme {
    pub fn builtin(name: &str) -> Option<Self> {
        let (background, text, accent, muted) = match name {
            "null" => (
                Color::Rgb(12, 17, 24),
                Color::Rgb(219, 226, 237),
                Color::Rgb(94, 231, 215),
                Color::Rgb(112, 131, 153),
            ),
            "ember" => (
                Color::Rgb(22, 16, 16),
                Color::Rgb(242, 224, 207),
                Color::Rgb(255, 168, 97),
                Color::Rgb(157, 122, 107),
            ),
            "ice" => (
                Color::Rgb(13, 22, 35),
                Color::Rgb(218, 234, 248),
                Color::Rgb(116, 190, 255),
                Color::Rgb(112, 145, 177),
            ),
            "classic" => (Color::Reset, Color::Gray, Color::Cyan, Color::DarkGray),
            "light" => (
                Color::Rgb(243, 246, 250),
                Color::Rgb(29, 42, 56),
                Color::Rgb(0, 107, 113),
                Color::Rgb(88, 108, 127),
            ),
            _ => return None,
        };
        Some(Self {
            name: name.into(),
            text: Style::default().fg(text),
            background,
            border: Style::default().fg(muted),
            accent: Style::default().fg(accent).add_modifier(Modifier::BOLD),
            muted: Style::default().fg(muted),
            warning: Style::default().fg(Color::Yellow),
            error: Style::default().fg(Color::LightRed),
            nick: Style::default().fg(accent),
            own: Style::default().fg(Color::LightMagenta),
            status: Style::default().fg(text).bg(background),
            border_type: BorderType::Rounded,
        })
    }
    pub fn load(path: &Path) -> Result<(Self, String), &'static str> {
        if !path
            .metadata()
            .map_err(|_| "Cannot inspect theme")?
            .is_file()
        {
            return Err("Theme must be a regular file");
        }
        let mut file = File::open(path).map_err(|_| "Cannot open theme")?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| "Cannot read theme")?;
        if bytes.len() > 65536 {
            return Err("Theme exceeds 64 KiB");
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| "Theme is not UTF-8")?;
        if text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return Err("Theme contains terminal controls");
        }
        if path.extension().is_some_and(|e| e == "theme") {
            Self::irssi(text)
        } else {
            Self::palette(text)
        }
    }
    fn palette(text: &str) -> Result<(Self, String), &'static str> {
        // Palette files use flat TOML tables, never recursively nested input.
        if text.contains('{') || text.contains('}') {
            return Err("Inline theme tables are unsupported");
        }
        let doc = text
            .parse::<toml_edit::DocumentMut>()
            .map_err(|_| "Invalid theme TOML")?;
        let mut theme = Self {
            name: "custom".into(),
            ..Self::default()
        };
        let table = doc
            .get("colors")
            .and_then(|v| v.as_table())
            .ok_or("Theme needs [colors]")?;
        if table.len() > 16 {
            return Err("Too many palette fields");
        }
        for (key, value) in table {
            let color = value
                .as_str()
                .ok_or("Palette colors must be strings")?
                .parse::<Color>()
                .map_err(|_| "Invalid palette color")?;
            match key {
                "background" => theme.background = color,
                "text" => theme.text = theme.text.fg(color),
                "border" => theme.border = theme.border.fg(color),
                "accent" => theme.accent = theme.accent.fg(color),
                "muted" => theme.muted = theme.muted.fg(color),
                "warning" => theme.warning = theme.warning.fg(color),
                "error" => theme.error = theme.error.fg(color),
                "nick" => theme.nick = theme.nick.fg(color),
                "own" => theme.own = theme.own.fg(color),
                "status" => theme.status = theme.status.fg(color),
                _ => return Err("Unknown palette color field"),
            }
        }
        theme.status = theme.status.bg(theme.background);
        Ok((theme, "Loaded NullLobby palette".into()))
    }
    pub fn irssi(text: &str) -> Result<(Self, String), &'static str> {
        let tokens = lex(text)?;
        let mut parser = Parser {
            tokens: &tokens,
            cursor: 0,
            entries: 0,
        };
        let root = parser.table(0, false)?;
        let Some(Value::Table(abstracts)) = root.get("abstracts") else {
            return Err("Irssi theme needs an abstracts block");
        };
        let mut theme = Self::builtin("classic").unwrap();
        theme.name = "irssi import".into();
        let mut count = 0;
        for (source, target) in [
            ("window_border", "border"),
            ("sb_background", "status"),
            ("timestamp", "muted"),
            ("hilight", "accent"),
            ("error", "error"),
            ("pubnick", "nick"),
            ("ownnick", "own"),
            ("menick", "warning"),
        ] {
            if let Some(style) = abstract_style(source, abstracts, 0, &mut 256) {
                match target {
                    "border" => theme.border = style,
                    "status" => theme.status = style,
                    "muted" => theme.muted = style,
                    "accent" => theme.accent = style,
                    "error" => theme.error = style,
                    "nick" => theme.nick = style,
                    "own" => theme.own = style,
                    "warning" => theme.warning = style,
                    _ => {}
                }
                count += 1;
            }
        }
        if let Some(Value::Text(value)) = root.get("default_color")
            && let Ok(index) = value.parse::<u8>()
        {
            theme.text = theme.text.fg(Color::Indexed(index));
        }
        Ok((
            theme,
            format!(
                "Imported {count} irssi color/style roles. IRC formats, replacements, scripts and layout templates are not executed."
            ),
        ))
    }
}
#[derive(Clone)]
enum Value {
    Text(String),
    Table(BTreeMap<String, Value>),
}
#[derive(Clone, PartialEq)]
enum Token {
    Text(String),
    Open,
    Close,
    Equal,
    Semi,
}
fn lex(text: &str) -> Result<Vec<Token>, &'static str> {
    if text.len() > 65536 {
        return Err("Theme exceeds 64 KiB");
    }
    let mut chars = text.chars().peekable();
    let mut out = Vec::new();
    while let Some(c) = chars.next() {
        if out.len() >= 8192 {
            return Err("Too many theme tokens");
        }
        match c {
            c if c.is_whitespace() => {}
            '#' => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            '{' => out.push(Token::Open),
            '}' => out.push(Token::Close),
            '=' => out.push(Token::Equal),
            ';' => out.push(Token::Semi),
            '"' => {
                let mut value = String::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    if c == '"' {
                        closed = true;
                        break;
                    }
                    if c == '\\' {
                        let next = chars.next().ok_or("Unterminated theme escape")?;
                        value.push(next);
                    } else {
                        value.push(c);
                    }
                    if c.is_control() && !c.is_whitespace() {
                        return Err("Theme contains controls");
                    }
                    if value.len() > 4096 {
                        return Err("Theme value exceeds limit");
                    }
                }
                if !closed {
                    return Err("Unterminated theme string");
                }
                out.push(Token::Text(value));
            }
            c if c.is_ascii_alphanumeric() || c == '_' || c == '-' => {
                let mut value = String::from(c);
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                {
                    value.push(chars.next().unwrap());
                }
                if value.len() > 128 {
                    return Err("Theme name exceeds limit");
                }
                out.push(Token::Text(value));
            }
            _ => return Err("Unsupported irssi theme syntax"),
        }
    }
    Ok(out)
}
struct Parser<'a> {
    tokens: &'a [Token],
    cursor: usize,
    entries: usize,
}
impl Parser<'_> {
    fn take(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.cursor)?.clone();
        self.cursor += 1;
        Some(token)
    }
    fn table(
        &mut self,
        depth: usize,
        nested: bool,
    ) -> Result<BTreeMap<String, Value>, &'static str> {
        if depth > 8 {
            return Err("Theme nesting exceeds limit");
        }
        let mut map = BTreeMap::new();
        loop {
            let key = match self.take() {
                Some(Token::Text(key)) => key,
                Some(Token::Close) if nested => break,
                None if !nested => break,
                _ => return Err("Invalid theme block"),
            };
            self.entries += 1;
            if self.entries > 512 {
                return Err("Too many theme entries");
            }
            if self.take() != Some(Token::Equal) {
                return Err("Expected theme assignment");
            }
            let value = match self.take() {
                Some(Token::Text(value)) => Value::Text(value),
                Some(Token::Open) => Value::Table(self.table(depth + 1, true)?),
                _ => return Err("Invalid theme value"),
            };
            if self.take() != Some(Token::Semi) {
                return Err("Expected theme semicolon");
            }
            if map.insert(key, value).is_some() {
                return Err("Duplicate theme key");
            }
        }
        Ok(map)
    }
}
fn abstract_style(
    name: &str,
    table: &BTreeMap<String, Value>,
    depth: usize,
    budget: &mut usize,
) -> Option<Style> {
    if depth > 8 || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let Value::Text(text) = table.get(name)? else {
        return None;
    };
    let mut style = Style::default();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            break;
        }
        if c == '{' {
            let name = chars
                .by_ref()
                .take_while(|c| !c.is_whitespace() && *c != '}')
                .collect::<String>();
            if let Some(inherited) = abstract_style(&name, table, depth + 1, budget) {
                style = style.patch(inherited);
            }
        }
        if c != '%' {
            continue;
        }
        let Some(code) = chars.next() else {
            break;
        };
        let color = match code {
            'k' => Some(Color::Black),
            'K' => Some(Color::DarkGray),
            'r' => Some(Color::Red),
            'R' => Some(Color::LightRed),
            'g' => Some(Color::Green),
            'G' => Some(Color::LightGreen),
            'y' => Some(Color::Yellow),
            'Y' => Some(Color::LightYellow),
            'b' => Some(Color::Blue),
            'B' => Some(Color::LightBlue),
            'm' | 'p' => Some(Color::Magenta),
            'M' | 'P' => Some(Color::LightMagenta),
            'c' => Some(Color::Cyan),
            'C' => Some(Color::LightCyan),
            'w' => Some(Color::Gray),
            'W' => Some(Color::White),
            _ => None,
        };
        if let Some(color) = color {
            style = style.fg(color);
            continue;
        }
        match code {
            '0'..='7' => {
                style = style.bg([
                    Color::Black,
                    Color::Red,
                    Color::Green,
                    Color::Yellow,
                    Color::Blue,
                    Color::Magenta,
                    Color::Cyan,
                    Color::Gray,
                ][code as usize - '0' as usize])
            }
            '_' | '9' | 'U' | 'I' | '8' => {
                let modifier = match code {
                    '_' | '9' => Modifier::BOLD,
                    'U' => Modifier::UNDERLINED,
                    'I' => Modifier::ITALIC,
                    _ => Modifier::REVERSED,
                };
                style = if style.add_modifier.contains(modifier) {
                    style.remove_modifier(modifier)
                } else {
                    style.add_modifier(modifier)
                };
            }
            'N' | 'n' => style = Style::default(),
            'X' | 'x' => {
                let plane = chars.next();
                let digit = chars.next();
                if let Some(color) = plane.zip(digit).and_then(|(a, b)| extended_color(a, b)) {
                    style = if code == 'X' {
                        style.fg(color)
                    } else {
                        style.bg(color)
                    };
                }
            }
            'Z' | 'z' => {
                let hex = chars.by_ref().take(6).collect::<String>();
                if hex.len() == 6
                    && hex.is_ascii()
                    && let Ok(rgb) = u32::from_str_radix(&hex, 16)
                {
                    let color = Color::Rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8);
                    style = if code == 'Z' {
                        style.fg(color)
                    } else {
                        style.bg(color)
                    };
                }
            }
            _ => {}
        }
    }
    Some(style)
}
// Irssi's extended plane encoding, documented in formats.txt and formats.c.
fn extended_color(plane: char, digit: char) -> Option<Color> {
    let value = match plane {
        '0' => digit.to_digit(16)?,
        '1'..='6' => 16 + (plane as u32 - '1' as u32) * 36 + digit.to_digit(36)?,
        '7' if digit.is_ascii_alphabetic() => 232 + digit.to_ascii_lowercase() as u32 - 'a' as u32,
        _ => return None,
    };
    u8::try_from(value).ok().map(Color::Indexed)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shipped_palettes_and_irssi_example_load() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(Theme::load(&root.join("themes/ember.toml")).is_ok());
        assert!(Theme::load(&root.join("themes/nulllobby.theme")).is_ok());
    }
    #[test]
    fn imports_irssi_roles_without_executing_templates() {
        let (theme,notice)=Theme::irssi("default_color = \"-1\"; abstracts = { error = \"%R$*%n\"; ownnick = \"%_$*%n\"; sb_background = \"%4%w\"; pubnick = \"%Z123456$*\"; }; ").unwrap();
        assert_eq!(theme.error.fg, Some(Color::LightRed));
        assert_eq!(theme.status.bg, Some(Color::Blue));
        assert_eq!(theme.nick.fg, Some(Color::Rgb(0x12, 0x34, 0x56)));
        assert!(notice.contains("not executed"));
    }
    #[test]
    fn rejects_deep_large_and_malformed_themes() {
        assert!(Theme::irssi(&"a={".repeat(20)).is_err());
        assert!(Theme::irssi(&"x".repeat(65537)).is_err());
        assert!(Theme::irssi("abstracts={ error=\"unterminated").is_err());
        let table = BTreeMap::from([
            ("a".into(), Value::Text("{b}".repeat(100))),
            ("b".into(), Value::Text("{c}".repeat(100))),
            ("c".into(), Value::Text("%R".into())),
        ]);
        let mut budget = 8;
        assert!(abstract_style("a", &table, 0, &mut budget).is_some());
        assert_eq!(budget, 0, "branching references must share a work budget");
        let recursive = "abstracts={ error=\"{error $*}\"; };";
        assert!(Theme::irssi(recursive).is_ok());
    }
    #[test]
    fn extended_colors_cover_all_256_indices() {
        for index in 0..=255u16 {
            let (a, b) = match index {
                0..=15 => ('0', char::from_digit(index as u32, 16).unwrap()),
                16..=231 => (
                    char::from_digit(((index - 16) / 36 + 1) as u32, 10).unwrap(),
                    char::from_digit(((index - 16) % 36) as u32, 36).unwrap(),
                ),
                _ => (
                    '7',
                    char::from_u32('a' as u32 + index as u32 - 232).unwrap(),
                ),
            };
            assert_eq!(extended_color(a, b), Some(Color::Indexed(index as u8)));
        }
        assert_eq!(extended_color('7', 'z'), None);
        let (theme, _) =
            Theme::irssi("abstracts={pubnick=\"%X4A$*\";sb_background=\"%x7X\";};").unwrap();
        assert_eq!(theme.nick.fg, Some(Color::Indexed(134)));
        assert_eq!(theme.status.bg, Some(Color::Indexed(255)));
    }
}
