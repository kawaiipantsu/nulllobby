use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use nulllobby_core::{
    LobbyId, LobbyKind, branding,
    domain::{AppCommand, AppEvent, LobbyView, PaddingPolicy},
    text::sanitize_terminal,
};
use nulllobby_transport::TransportKind;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, IsTerminal},
    time::Duration,
};
use tokio::sync::mpsc;
use zeroize::{Zeroize, Zeroizing};

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
    }
}
struct State {
    mode: TransportKind,
    current: Option<LobbyId>,
    lobbies: Vec<LobbyView>,
    padding: PaddingPolicy,
    history: HashMap<Option<LobbyId>, VecDeque<Zeroizing<String>>>,
    input: Zeroizing<String>,
    invite: Option<SecretString>,
    scroll: u16,
    quitting: bool,
}
impl State {
    fn new() -> Self {
        Self {
            mode: TransportKind::Direct,
            current: None,
            lobbies: vec![],
            padding: PaddingPolicy::Bucketed,
            history: HashMap::new(),
            input: Zeroizing::new(String::with_capacity(8192)),
            invite: None,
            scroll: 0,
            quitting: false,
        }
    }
    fn push(&mut self, lobby: Option<LobbyId>, line: String) {
        let line = Zeroizing::new(line);
        if !self.history.contains_key(&lobby) && self.history.len() >= 17 {
            return;
        }
        let history = self.history.entry(lobby).or_default();
        if history.len() >= 512 {
            history.pop_front();
        }
        history.push_back(Zeroizing::new(sanitize_terminal(&line, 8192)));
    }
    fn event(&mut self, event: AppEvent) -> bool {
        match event {
            AppEvent::View {
                transport,
                current,
                lobbies,
                padding,
            } => {
                self.mode = transport;
                self.current = current;
                self.lobbies = lobbies;
                self.padding = padding;
            }
            AppEvent::Notice { lobby, text } => self.push(lobby, text),
            AppEvent::MessageReceived {
                lobby,
                fingerprint,
                nickname,
                body,
                verified,
            } => {
                self.push(
                    Some(lobby),
                    format!(
                        "<{nickname} {} {}>",
                        &fingerprint.to_string()[..19],
                        if verified { "verified" } else { "unverified" }
                    ),
                );
                self.push(Some(lobby), body);
            }
            AppEvent::Invite(card) => self.invite = Some(card),
            AppEvent::LobbyLeft(id) => {
                self.history.remove(&Some(id));
                self.invite = None;
            }
            AppEvent::ShutdownComplete => return false,
            _ => {}
        }
        true
    }
    fn draw(&self, frame: &mut ratatui::Frame<'_>) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(frame.area());
        let lobby = self.lobbies.iter().find(|l| Some(l.id) == self.current);
        let mode = match self.mode {
            TransportKind::Direct => "DIRECT | IP EXPOSED TO PEERS",
            TransportKind::Tor => "TOR | ONION TRANSPORT",
        };
        let kind = lobby.map_or("NO LOBBY", |l| match l.kind {
            LobbyKind::Private => "PRIVATE | PSK AUTH",
            LobbyKind::PublicUnlisted => "PUBLIC UNLISTED",
            LobbyKind::PublicDiscoverable => "DISCOVERABLE",
        });
        let title = format!(
            "{} | {} | {} | {} | {} peers",
            branding::PROJECT,
            lobby.map_or("/help", |l| &l.name),
            mode,
            kind,
            lobby.map_or(0, |l| l.peers)
        );
        frame.render_widget(
            Paragraph::new(title).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Encrypted sessions required · identities need human verification"),
            ),
            rows[0],
        );
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(21),
                Constraint::Min(20),
                Constraint::Length(31),
            ])
            .split(rows[1]);
        let lobbies: Vec<_> = self
            .lobbies
            .iter()
            .enumerate()
            .map(|(i, l)| {
                ListItem::new(format!(
                    "{} {} {}",
                    if Some(l.id) == self.current { ">" } else { " " },
                    i + 1,
                    l.name
                ))
            })
            .collect();
        frame.render_widget(
            List::new(lobbies).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Lobbies /switch #"),
            ),
            cols[0],
        );
        let mut lines = Vec::new();
        if let Some(history) = self.history.get(&None) {
            for text in history {
                lines.push(Line::from(text.as_str()));
            }
        }
        if self.current.is_some()
            && let Some(history) = self.history.get(&self.current)
        {
            for text in history {
                lines.push(Line::from(text.as_str()));
            }
        }
        let messages = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Messages · RAM only · PgUp/PgDn"),
        );
        let line_count = messages.line_count(cols[1].width.saturating_sub(2));
        let offset = line_count
            .saturating_sub(cols[1].height.saturating_sub(2) as usize)
            .min(u16::MAX as usize) as u16;
        frame.render_widget(
            messages.scroll((offset.saturating_sub(self.scroll), 0)),
            cols[1],
        );
        let members: Vec<_> = lobby
            .into_iter()
            .flat_map(|l| &l.members)
            .flat_map(|member| {
                [
                    Line::from(member.nickname.clone()),
                    Line::from(format!("{} …", &member.fingerprint.to_string()[..24])),
                    Line::from(if member.verified {
                        "encrypted / verified"
                    } else {
                        "encrypted / unverified"
                    })
                    .style(Style::default().fg(if member.verified {
                        Color::Cyan
                    } else {
                        Color::Yellow
                    })),
                    Line::from(""),
                ]
            })
            .collect();
        frame.render_widget(
            Paragraph::new(members).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Members · /who for full FP"),
            ),
            cols[2],
        );
        let display = if self.quitting {
            "Closing endpoints…".to_owned()
        } else if self
            .input
            .trim_start()
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/join "))
        {
            "/join [card hidden]".to_owned()
        } else {
            sanitize_terminal(&self.input, 8192)
        };
        let input = Paragraph::new(display).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Enter to send · /help · Ctrl+C to quit"),
        );
        frame.render_widget(input, rows[2]);
        if let Some(invite) = &self.invite {
            let area = frame.area();
            frame.render_widget(Clear, area);
            let text = format!(
                "Explicit lobby invitation\n\n{}\n\nPrivate cards grant access. Copy only to intended recipients. Terminal scrollback and clipboard managers are outside the security boundary.\n\nPress Esc to hide this invitation.",
                invite.expose_secret()
            );
            frame.render_widget(
                Paragraph::new(text).wrap(Wrap { trim: false }).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("/invite · no automatic clipboard access"),
                ),
                area,
            );
        }
    }
}
pub fn run(
    commands: mpsc::Sender<AppCommand>,
    mut events: mpsc::Receiver<AppEvent>,
) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other("TUI requires a terminal"));
    }
    enable_raw_mode()?;
    let _guard = TerminalGuard;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut state = State::new();
    loop {
        for _ in 0..128 {
            match events.try_recv() {
                Ok(event) => {
                    if !state.event(event) {
                        return Ok(());
                    }
                }
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
                Err(_) => break,
            }
        }
        terminal.draw(|frame| state.draw(frame))?;
        if !event::poll(Duration::from_millis(50))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                if commands.try_send(AppCommand::Shutdown).is_ok() {
                    state.quitting = true;
                }
                continue;
            }
            if state.quitting {
                continue;
            }
            if state.invite.is_some() {
                if key.code == KeyCode::Esc {
                    state.invite = None;
                }
                continue;
            }
            match key.code {
                KeyCode::Enter if !state.input.is_empty() => {
                    let result = nulllobby_app::command::parse(&state.input, state.current);
                    state.input.zeroize();
                    state.scroll = 0;
                    match result {
                        Ok(command) => {
                            let quitting = matches!(command, AppCommand::Shutdown);
                            if commands.try_send(command).is_err() {
                                state.push(
                                    state.current,
                                    "Command queue full; retry shortly".to_owned(),
                                );
                            } else if quitting {
                                state.quitting = true;
                            }
                        }
                        Err(message) => state.push(state.current, message.to_owned()),
                    }
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !c.is_control()
                        && state.input.len() + c.len_utf8() <= 8192 =>
                {
                    state.input.push(c)
                }
                KeyCode::Backspace => {
                    state.input.pop();
                }
                KeyCode::Esc => state.input.zeroize(),
                KeyCode::PageUp => state.scroll = state.scroll.saturating_add(10),
                KeyCode::PageDown => state.scroll = state.scroll.saturating_sub(10),
                _ => {}
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ui_history_and_rendering_are_bounded() {
        let mut state = State::new();
        for _ in 0..600 {
            state.push(None, "\x1b]52;c;payload\x07hello".to_owned());
        }
        assert_eq!(state.history[&None].len(), 512);
        assert!(state.history[&None].iter().all(|s| !s.contains('\x1b')));
        let backend = ratatui::backend::TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| state.draw(frame)).unwrap();
    }
}
