use crate::{input::Input, settings::Settings, theme::Theme};
use chrono::{Local, NaiveDate};
use crossterm::{
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use nulllobby_core::{
    LobbyCard, LobbyId, LobbyKind, branding,
    domain::{AppCommand, AppEvent, Inspection, LobbyView, PaddingPolicy},
    text::{ValidatedText, sanitize_terminal},
};
use nulllobby_transport::{NetworkStatus, TransportKind};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, IsTerminal},
    time::Duration,
};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "screenshots.rs"]
mod screenshots;

const HELP: &str = r#"QUICK START
/nick name
/create public team     Random, unlisted lobby
/create private team    Random capability; share /invite privately
/join <card>            Join an existing lobby
/transport tor          Select before joining; configure Tor at launch

IDENTITIES
/who /fingerprint /verify <full fingerprint> /unverify <fingerprint>
Nicknames are cosmetic. Compare fingerprints out of band. Restart loses trust.

VIEW / INPUT
F1 or Alt+H  Help       F2 or Alt+L  Lobbies panel
F3 or Alt+U  Members    F4  Settings    F5  Network/privacy
F6  Paste preview      F7  Notices     F8  Remembered lobbies
F9  Timestamps         F10 / Ctrl+C  Quit
PgUp/PgDn  Scroll      Esc  Dismiss overlay / clear input
Paste with your terminal's shortcut. Enter sends; multiline paste is text.
/theme null|ember|ice|classic|light|<path>
/timestamps on|off  /icons on|off  /borders ascii|rounded
/remember <label>  /bookmarks  /connect <number>
/autoconnect <number> on|off  /forget <number>

OPTIONAL TEAM FEATURES (protocol v2)
/identity persistent|ephemeral  /stored  /resume <number>
/delivery live|durable  /mailbox on|off  /sync
Persistence needs an explicitly opened encrypted --vault; trust stays in RAM.
/rotate  /revoke <full fingerprint>  Private lobby administrator only
/org trust <issuer key>  /org request <file>  /org import <file>  /org off
Organization membership is separate from human verification and admission.

/privacy /security /padding none|bucketed /reconnect /leave /quit"#;
const WELCOME: &str = r#"EPHEMERAL LOBBY CHAT

1  Choose a nickname: /nick name
2  Create: /create public team   or   /create private team
3  Share /invite, or join with /join <card>
4  Compare full fingerprints out of band; use /verify to mark trust.

Noise encryption is always required. Private lobbies also require a random capability. Direct exposes peer IPs. Select /transport tor before joining to use onion transport; configure external Tor or experimental Arti at launch.

Defaults keep identities, trust and live chat in RAM. Unsaved fingerprints change on restart.
F4 opens optional preferences. Secret storage needs a separate explicit encrypted vault and per-lobby opt-in. Human trust always stays in RAM.

F1 opens help at any time. Esc or Enter dismisses this welcome screen."#;
const ASCII: ratatui::symbols::border::Set = ratatui::symbols::border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};
struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
    }
}
#[derive(Clone, Copy, PartialEq)]
enum Modal {
    Welcome,
    Help,
    Settings,
    Notices,
    Invite,
    Preview,
    Bookmarks,
}
enum Record {
    Day(NaiveDate),
    Message {
        id: [u8; 16],
        delivery: Option<nulllobby_core::domain::DeliveryState>,
        historical: bool,
        time: String,
        nick: Zeroizing<String>,
        body: Zeroizing<String>,
        fingerprint: String,
        verified: bool,
        own: bool,
    },
}
struct History {
    day: NaiveDate,
    records: VecDeque<Record>,
}
impl History {
    fn push(&mut self, record: Record) {
        if self.records.len() >= 512 {
            self.records.pop_front();
        }
        self.records.push_back(record);
    }
    fn rollover(&mut self, day: NaiveDate) {
        if self.day != day {
            self.day = day;
            self.push(Record::Day(day));
        }
    }
}
struct State {
    mode: TransportKind,
    current: Option<LobbyId>,
    lobbies: Vec<LobbyView>,
    padding: PaddingPolicy,
    network: NetworkStatus,
    progress: String,
    history: HashMap<LobbyId, History>,
    notices: VecDeque<Zeroizing<String>>,
    input: Input,
    invite: Option<SecretString>,
    invite_revision: u64,
    invite_feedback: Option<&'static str>,
    scroll: u16,
    modal_scroll: u16,
    quitting: bool,
    settings: Settings,
    theme: Theme,
    modal: Option<Modal>,
    unread: usize,
    remember: Option<String>,
}
impl State {
    fn new(settings: Settings, mode: TransportKind) -> Self {
        let selected = Theme::builtin(&settings.theme)
            .map(|t| (t, String::new()))
            .or_else(|| Theme::load(std::path::Path::new(&settings.theme)).ok());
        let missing = selected.is_none();
        let (theme, _) = selected.unwrap_or((Theme::default(), String::new()));
        let modal = if settings.welcome_seen {
            None
        } else {
            Some(Modal::Welcome)
        };
        let mut state = Self {
            mode,
            current: None,
            lobbies: vec![],
            padding: PaddingPolicy::Bucketed,
            network: NetworkStatus::Stopped,
            progress: String::new(),
            history: HashMap::new(),
            notices: VecDeque::new(),
            input: Input::default(),
            invite: None,
            invite_revision: 0,
            invite_feedback: None,
            scroll: 0,
            modal_scroll: 0,
            quitting: false,
            settings,
            theme,
            modal,
            unread: 0,
            remember: None,
        };
        if missing {
            state.notice("Saved theme could not be loaded; using null palette", true);
        }
        state
    }
    fn notice(&mut self, text: &str, show: bool) {
        if self.notices.len() >= 128 {
            self.notices.pop_front();
        }
        self.notices
            .push_back(Zeroizing::new(sanitize_terminal(text, 8192)));
        self.unread = (self.unread + 1).min(128);
        if show {
            self.open(Modal::Notices);
        }
    }
    fn open(&mut self, modal: Modal) {
        self.modal = Some(modal);
        self.modal_scroll = 0;
        if modal == Modal::Notices {
            self.unread = 0;
        }
    }
    fn dismiss(&mut self) {
        let welcome = self.modal == Some(Modal::Welcome);
        self.modal = None;
        self.invite = None;
        self.modal_scroll = 0;
        if welcome {
            self.settings.welcome_seen = true;
            self.persist();
        }
    }
    fn persist(&mut self) {
        if let Err(error) = self.settings.save() {
            self.notice(error, true);
        }
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
            AppEvent::TransportStatus { transport, status } => {
                self.mode = transport;
                self.network = status;
            }
            AppEvent::Notice { text, .. } => {
                if text.contains("BOOTSTRAP") || text.contains("BOOTSTRAPPING") {
                    self.progress = sanitize_terminal(&text, 140);
                }
                let show = text.starts_with("WARNING")
                    || text.starts_with("Transport unavailable")
                    || text.starts_with("No reachable")
                    || text.contains("failed")
                    || text.contains("disconnected");
                if show {
                    self.remember = None;
                }
                self.notice(&text, show);
            }
            AppEvent::MessageReceived {
                id,
                historical,
                lobby,
                fingerprint,
                nickname,
                body,
                verified,
            } => {
                if !self.history.contains_key(&lobby) && self.history.len() >= 16 {
                    return true;
                }
                let now = Local::now();
                let day = now.date_naive();
                let history = self.history.entry(lobby).or_insert_with(|| History {
                    day,
                    records: VecDeque::new(),
                });
                history.rollover(day);
                let own = self
                    .lobbies
                    .iter()
                    .any(|l| l.id == lobby && l.fingerprint == fingerprint);
                history.push(Record::Message {
                    id,
                    delivery: if own {
                        Some(nulllobby_core::domain::DeliveryState::Queued)
                    } else {
                        None
                    },
                    historical,
                    time: now.format("%H:%M:%S").to_string(),
                    nick: Zeroizing::new(sanitize_terminal(&nickname, 32)),
                    body: Zeroizing::new(sanitize_terminal(&body, 8192)),
                    fingerprint: fingerprint.to_string()[..9].into(),
                    verified,
                    own,
                });
            }
            AppEvent::Delivery { lobby, id, state } => {
                if let Some(history) = self.history.get_mut(&lobby) {
                    for record in &mut history.records {
                        if let Record::Message {
                            id: message_id,
                            delivery,
                            ..
                        } = record
                            && *message_id == id
                        {
                            *delivery = Some(state.clone());
                        }
                    }
                }
            }
            AppEvent::Invite(card) => {
                if let Some(name) = self.remember.take() {
                    match self.settings.add(&name, card.expose_secret(), false) {
                        Ok(()) => {
                            self.persist();
                            self.notice("Public lobby remembered. Autoconnect is off; identities and trust still rotate on restart.", true);
                        }
                        Err(e) => self.notice(e, true),
                    }
                } else {
                    self.invite = Some(card);
                    self.invite_revision = self.invite_revision.wrapping_add(1);
                    self.invite_feedback = None;
                    self.open(Modal::Invite);
                }
            }
            AppEvent::LobbyLeft(id) => {
                self.history.remove(&id);
                self.invite = None;
                if self.modal == Some(Modal::Invite) {
                    self.modal = None;
                }
            }
            AppEvent::ShutdownComplete => return false,
            AppEvent::FatalError => self.notice("Application stopped after a fatal error", true),
            AppEvent::PrivacyWarning(_) => self.notice("Review /privacy before continuing", true),
            _ => {}
        }
        true
    }
    fn block(&self, title: impl Into<Line<'static>>) -> Block<'static> {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(self.theme.border)
            .border_type(self.theme.border_type)
            .title(title)
            .title_style(self.theme.accent);
        if self.settings.ascii {
            block.border_set(ASCII)
        } else {
            block
        }
    }
    fn settings_text(&self) -> String {
        format!(
            "PREFERENCES\n\n1  Timestamps: {}\n2  Nerd Font icons: {} (install a Nerd Font in your terminal)\n3  Lobbies panel: {}\n4  Members panel: {}\n5  Borders: {}\n6  Cycle palette: {}\n7  Remember preferences: {}\n\nEnabling remembered settings writes theme, nickname and public lobby cards to a private local file. Reusing nicknames or cards can correlate activity. Identities, trust, history and private invitations stay in RAM.\n\n/remember <label> saves a public lobby; /autoconnect <number> on enables joining at startup in the matching transport.\n/theme <path.theme> imports supported irssi colors/styles; custom palettes use [colors] TOML.\n\nEsc closes. Changes apply immediately.",
            on(self.settings.timestamps),
            on(self.settings.icons),
            on(self.settings.lobbies),
            on(self.settings.members),
            if self.settings.ascii {
                "ASCII"
            } else {
                "rounded"
            },
            self.theme.name,
            if self.settings.path.is_some() {
                "ON"
            } else {
                "OFF — RAM only"
            }
        )
    }
    fn bookmarks_text(&self) -> String {
        let mut text = String::from("REMEMBERED PUBLIC LOBBIES\n\n");
        for (i, b) in self.settings.bookmarks.iter().enumerate() {
            text.push_str(&format!(
                "{}  {}  autoconnect: {}\n",
                i + 1,
                b.name,
                on(b.autoconnect)
            ));
        }
        text.push_str("\n/connect <number> joins using a fresh identity.\n/autoconnect <number> on|off changes startup behavior.\n/forget <number> removes a remembered lobby.\n\nPrivate invites are never saved. Tor seeds may be offline after restart.");
        text
    }
    fn draw(&self, frame: &mut ratatui::Frame<'_>) {
        let area = frame.area();
        frame.render_widget(
            Block::default().style(self.theme.text.bg(self.theme.background)),
            area,
        );
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(4),
                Constraint::Min(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(area);
        let menus = Line::from(vec![
            Span::styled(format!(" {} ", branding::PROJECT), self.theme.accent),
            Span::styled(
                " F1 Help  F2 Lobbies  F3 Members  F4 Settings  F5 Network  F6 Paste  F7 Notices  F8 Saved  F9 Time  F10 Quit",
                self.theme.muted,
            ),
        ]);
        frame.render_widget(Paragraph::new(menus), rows[0]);
        let lobby = self.lobbies.iter().find(|l| Some(l.id) == self.current);
        let mode = if self.mode == TransportKind::Tor {
            "TOR / ONION TRANSPORT"
        } else {
            "DIRECT / IP EXPOSED TO PEERS"
        };
        let connection = if self.quitting {
            "CLOSING"
        } else if self.network == NetworkStatus::Starting {
            "CONNECTING"
        } else if self.network == NetworkStatus::Unavailable {
            "UNAVAILABLE"
        } else if lobby.is_some_and(|l| l.peers > 0) {
            "CONNECTED"
        } else if lobby.is_some_and(|l| l.network.pending_connections > 0) {
            "CONNECTING / NO PEERS"
        } else if lobby.is_some_and(|l| {
            matches!(
                l.network.discovery,
                nulllobby_core::domain::DiscoveryState::Starting
                    | nulllobby_core::domain::DiscoveryState::Querying
            )
        }) {
            "DISCOVERING / NO PEERS"
        } else if lobby.is_some_and(|l| {
            l.network.discovery == nulllobby_core::domain::DiscoveryState::Unavailable
        }) {
            "DHT UNAVAILABLE / NO PEERS"
        } else if lobby.is_some() {
            "LISTENING / NO PEERS"
        } else {
            "DISCONNECTED"
        };
        let security = if lobby.is_some_and(|l| l.peers > 0) {
            "ENCRYPTED"
        } else {
            "ENCRYPTION REQUIRED"
        };
        let kind = lobby.map_or("NO LOBBY", |l| match l.kind {
            LobbyKind::Private => "PRIVATE / PSK",
            LobbyKind::PublicUnlisted => "PUBLIC UNLISTED",
            LobbyKind::PublicDiscoverable => "DISCOVERABLE",
        });
        let icon = if self.settings.icons { "󰒃 " } else { "" };
        let status = vec![
            Line::from(vec![
                Span::styled(
                    format!("{icon}{connection}"),
                    if self.network == NetworkStatus::Unavailable {
                        self.theme.error
                    } else {
                        self.theme.accent
                    },
                ),
                Span::raw(format!(
                    "  |  {mode}  |  {} peers",
                    lobby.map_or(0, |l| l.peers)
                )),
            ]),
            Line::from(format!(
                "{security}  |  {kind}  |  {} verified  |  padding: {}",
                lobby.map_or(0, |l| l
                    .members
                    .iter()
                    .filter(|m| m.verified && m.fingerprint != l.fingerprint)
                    .count()),
                if self.padding == PaddingPolicy::Bucketed {
                    "bucketed"
                } else {
                    "none"
                }
            )),
        ];
        frame.render_widget(
            Paragraph::new(status).style(self.theme.status).block(
                self.block(lobby.map_or("No lobby".into(), |l| sanitize_terminal(&l.name, 96))),
            ),
            rows[1],
        );
        let show_lobbies = self.settings.lobbies && area.width >= 65;
        let show_members = self.settings.members && area.width >= 95;
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(if show_lobbies { 20 } else { 0 }),
                Constraint::Min(1),
                Constraint::Length(if show_members { 27 } else { 0 }),
            ])
            .split(rows[2]);
        if show_lobbies {
            let items = self
                .lobbies
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    ListItem::new(format!(
                        "{} {} {}",
                        if Some(l.id) == self.current { ">" } else { " " },
                        i + 1,
                        sanitize_terminal(&l.name, 96)
                    ))
                    .style(if Some(l.id) == self.current {
                        self.theme.accent
                    } else {
                        self.theme.text
                    })
                })
                .collect::<Vec<_>>();
            frame.render_widget(
                List::new(items).block(self.block("Lobbies · /switch #")),
                cols[0],
            );
        }
        let mut lines = Vec::new();
        if let Some(history) = self.current.and_then(|id| self.history.get(&id)) {
            for record in &history.records {
                match record {
                    Record::Day(day) => {
                        let side = if self.settings.ascii { "-" } else { "─" }.repeat(6);
                        lines.push(Line::styled(
                            format!("{side} {day} {side}"),
                            self.theme.muted,
                        ));
                    }
                    Record::Message {
                        delivery,
                        historical,
                        time,
                        nick,
                        body,
                        fingerprint,
                        verified,
                        own,
                        ..
                    } => {
                        let mut spans = Vec::new();
                        if self.settings.timestamps {
                            spans.push(Span::styled(format!("{time} "), self.theme.muted));
                        }
                        spans.push(Span::styled(
                            format!("<{}> ", nick.as_str()),
                            if *own {
                                self.theme.own
                            } else {
                                self.theme.nick
                            },
                        ));
                        let trust = if *own {
                            "you"
                        } else if *verified {
                            "verified"
                        } else {
                            "unverified"
                        };
                        spans.push(Span::styled(
                            format!("[{fingerprint} {trust}] "),
                            self.theme.muted,
                        ));
                        spans.push(Span::raw(body.as_str()));
                        if *historical {
                            spans.push(Span::styled(" [durable]", self.theme.muted));
                        }
                        if let Some(delivery) = delivery {
                            use nulllobby_core::domain::DeliveryState;
                            let status = match delivery {
                                DeliveryState::Queued => "queued",
                                DeliveryState::Sent => "sent",
                                DeliveryState::Received(_) => "peer received",
                                DeliveryState::Stored(_) => "mailbox stored",
                                DeliveryState::Expired => "expired",
                                DeliveryState::Failed => "failed",
                            };
                            spans.push(Span::styled(format!(" [{status}]"), self.theme.muted));
                        }
                        lines.push(Line::from(spans));
                    }
                }
            }
        }
        let messages = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(
                self.block(if lobby.is_some_and(|l| l.durable || l.mailbox) {
                    "Chat · durable opt-in"
                } else {
                    "Chat · live / RAM"
                }),
            );
        let line_count = messages.line_count(cols[1].width.saturating_sub(2));
        let offset = line_count
            .saturating_sub(cols[1].height.saturating_sub(2) as usize)
            .min(u16::MAX as usize) as u16;
        frame.render_widget(
            messages.scroll((offset.saturating_sub(self.scroll), 0)),
            cols[1],
        );
        if show_members {
            let mut members = Vec::new();
            for member in lobby.into_iter().flat_map(|l| &l.members) {
                let own = lobby.is_some_and(|l| l.fingerprint == member.fingerprint);
                members.push(Line::styled(
                    sanitize_terminal(&member.nickname, 32),
                    self.theme.nick,
                ));
                members.push(Line::styled(
                    member.fingerprint.to_string()[..24].to_owned(),
                    self.theme.muted,
                ));
                members.push(Line::styled(
                    if own {
                        if lobby.is_some_and(|l| l.persistent) {
                            "you · saved identity"
                        } else {
                            "you · ephemeral identity"
                        }
                    } else if member.verified {
                        "encrypted / verified"
                    } else {
                        "encrypted / unverified"
                    },
                    if own || member.verified {
                        self.theme.accent
                    } else {
                        self.theme.warning
                    },
                ));
                if let Some(org) = &member.organization {
                    members.push(Line::styled(
                        format!("org: {}", sanitize_terminal(org, 100)),
                        self.theme.accent,
                    ));
                }
                members.push(Line::default());
            }
            frame.render_widget(
                Paragraph::new(members).block(self.block("Members · /who")),
                cols[2],
            );
        }
        let detail = if self.network == NetworkStatus::Starting {
            self.progress.as_str()
        } else {
            lobby.map_or(
                "F1 help · F4 settings · fingerprints need human verification",
                |l| &l.status,
            )
        };
        frame.render_widget(
            Paragraph::new(format!(
                " {}   |   {} notices   |   {}",
                sanitize_terminal(detail, 200),
                self.unread,
                if lobby.is_some_and(|l| l.mailbox) {
                    "encrypted vault · mailbox ON"
                } else if lobby.is_some_and(|l| l.durable) {
                    "encrypted vault · durable sending"
                } else if lobby.is_some_and(|l| l.persistent) {
                    "saved identity · live chat RAM"
                } else if self.settings.path.is_some() {
                    "preferences saved · live chat RAM"
                } else {
                    "RAM only"
                }
            ))
            .style(self.theme.muted),
            rows[3],
        );
        let display = if self.quitting {
            "Closing endpoints…".to_owned()
        } else {
            self.input.display()
        };
        let cursor = if self.input.text().trim_start().starts_with("/join ") {
            unicode_width::UnicodeWidthStr::width(display.as_str())
        } else {
            self.input.cursor_columns()
        };
        let offset = if self.input.compact() {
            0
        } else {
            cursor.saturating_sub(rows[4].width.saturating_sub(3) as usize)
        };
        frame.render_widget(
            Paragraph::new(format!("> {display}"))
                .style(self.theme.text.bg(self.theme.background))
                .scroll((0, offset.min(u16::MAX as usize) as u16)),
            rows[4],
        );
        if self.modal.is_none() && !self.quitting && rows[4].width > 0 && rows[4].height > 0 {
            frame.set_cursor_position((
                rows[4].x
                    + (if self.input.compact() {
                        2
                    } else {
                        cursor.saturating_sub(offset) + 2
                    })
                    .min(rows[4].width.saturating_sub(1) as usize) as u16,
                rows[4].y,
            ));
        }
        if let Some(modal) = self.modal {
            let popup = overlay_area(area);
            frame.render_widget(Clear, popup);
            let text = Zeroizing::new(match modal {
                Modal::Welcome => WELCOME.into(),
                Modal::Help => HELP.into(),
                Modal::Settings => self.settings_text(),
                Modal::Bookmarks => self.bookmarks_text(),
                Modal::Notices => self
                    .notices
                    .iter()
                    .rev()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("\n\n"),
                Modal::Invite => crate::invite::INSTRUCTIONS.into(),
                Modal::Preview => format!(
                    "PASTE PREVIEW — Enter in the input sends each nonempty line as text.\n\n{}",
                    if self.input.text().contains("nl:")
                        || self.input.text().trim_start().starts_with("/join ")
                    {
                        "[Lobby card hidden]"
                    } else {
                        self.input.text()
                    }
                ),
            });
            let title = match modal {
                Modal::Welcome => "Welcome · Enter/Esc closes",
                Modal::Help => "Help · PgUp/PgDn · Esc closes",
                Modal::Settings => "Settings · press 1–7 · Esc closes",
                Modal::Notices => "Notifications · PgUp/PgDn · Esc closes",
                Modal::Invite => "Invitation · Ctrl+Y copy · Esc hides",
                Modal::Preview => "Paste preview · Esc closes",
                Modal::Bookmarks => "Remembered lobbies · Esc closes",
            };
            frame.render_widget(
                Paragraph::new(text.as_str())
                    .style(self.theme.text.bg(self.theme.background))
                    .wrap(Wrap { trim: false })
                    .scroll((self.modal_scroll, 0))
                    .block(Block::default().title(title).title_style(self.theme.accent)),
                popup,
            );
            if modal == Modal::Invite {
                let card_area = crate::invite::card_area(popup);
                if !self
                    .invite
                    .as_ref()
                    .is_some_and(|card| crate::invite::fits(card.expose_secret(), card_area))
                {
                    frame.render_widget(
                        Paragraph::new(
                            "Enlarge the terminal to select the whole card, or use Ctrl+Y.",
                        )
                        .style(self.theme.warning)
                        .wrap(Wrap { trim: false }),
                        card_area,
                    );
                }
                if let Some(feedback) = self.invite_feedback
                    && popup.height > 0
                {
                    frame.render_widget(
                        Paragraph::new(feedback).style(self.theme.warning),
                        Rect::new(popup.x, popup.bottom() - 1, popup.width, 1),
                    );
                }
            }
        }
    }
    fn queue(&mut self, commands: &mpsc::Sender<AppCommand>, command: AppCommand) -> bool {
        if commands.try_send(command).is_err() {
            self.notice("Command queue full; retry shortly", true);
            false
        } else {
            true
        }
    }
    fn submit(&mut self, commands: &mpsc::Sender<AppCommand>) {
        if self.input.text().is_empty() {
            return;
        }
        if self.input.text().contains('\n') {
            if self.input.text().contains("nl:")
                || self
                    .input
                    .text()
                    .lines()
                    .any(|l| l.trim_start().starts_with("/join "))
            {
                self.notice("A lobby card was found in a multiline paste. Nothing sent; join with a single-line /join command.", true);
                return;
            }
            let Some(lobby) = self.current else {
                self.notice("Join a lobby before sending pasted text", true);
                return;
            };
            let result = self
                .input
                .text()
                .lines()
                .filter(|s| !s.is_empty())
                .map(|line| {
                    ValidatedText::new(line).map(|body| AppCommand::SendMessage { lobby, body })
                })
                .collect::<Result<Vec<_>, _>>();
            let Ok(batch) = result else {
                self.notice("Paste contains unsupported text", true);
                return;
            };
            let Ok(permits) = commands.try_reserve_many(batch.len()) else {
                self.notice("Not enough queue space for the paste; nothing sent", true);
                return;
            };
            for (permit, command) in permits.zip(batch) {
                permit.send(command);
            }
            self.input.clear();
            self.scroll = 0;
            return;
        }
        let text = Zeroizing::new(self.input.text().to_owned());
        match self.local_command(&text, commands) {
            Ok(true) => {
                self.input.clear();
                return;
            }
            Err(error) => {
                self.notice(error, true);
                return;
            }
            Ok(false) => {}
        }
        match nulllobby_app::command::parse(&text, self.current) {
            Ok(command) => {
                let quitting = matches!(command, AppCommand::Shutdown);
                let nickname = if let AppCommand::SetNickname(ref nick) = command {
                    Some(nick.as_str().to_owned())
                } else {
                    None
                };
                if matches!(command, AppCommand::Inspect(_)) {
                    self.open(Modal::Notices);
                }
                if matches!(
                    command,
                    AppCommand::Inspect(Inspection::Privacy | Inspection::Security)
                ) {
                    self.notice(if self.settings.path.is_some() {
                        "Preferences: saved locally by choice. Nickname and public cards may correlate activity; keys, trust and history remain in RAM."
                    } else { "Preferences: RAM only; no settings file is written." }, false);
                }
                if self.queue(commands, command) {
                    self.input.clear();
                    self.scroll = 0;
                    self.quitting = quitting;
                    if let Some(nick) = nickname {
                        self.settings.nickname = Some(nick);
                        self.persist();
                    }
                }
            }
            Err(error) => self.notice(error, true),
        }
    }
    fn local_command(
        &mut self,
        text: &str,
        commands: &mpsc::Sender<AppCommand>,
    ) -> Result<bool, &'static str> {
        let (command, arg) = text.trim().split_once(' ').unwrap_or((text.trim(), ""));
        let arg = arg.trim();
        match command {
            "/help" if arg.is_empty() => self.open(Modal::Help),
            "/settings" if arg.is_empty() => self.open(Modal::Settings),
            "/bookmarks" if arg.is_empty() => self.open(Modal::Bookmarks),
            "/theme" => {
                if arg.len() > 512 {
                    return Err("Theme path exceeds 512 bytes");
                }
                let (theme, notice) = if let Some(theme) = Theme::builtin(arg) {
                    (theme, "Palette changed".into())
                } else {
                    Theme::load(std::path::Path::new(arg))?
                };
                self.theme = theme;
                self.settings.theme = arg.into();
                self.persist();
                self.notice(&notice, true);
            }
            "/timestamps" | "/icons" => {
                let enabled = match arg {
                    "on" => true,
                    "off" => false,
                    _ => return Err("Use on or off"),
                };
                if command == "/timestamps" {
                    self.settings.timestamps = enabled;
                } else {
                    self.settings.icons = enabled;
                }
                self.persist();
            }
            "/borders" => {
                self.settings.ascii = match arg {
                    "ascii" => true,
                    "rounded" => false,
                    _ => return Err("Use /borders ascii|rounded"),
                };
                self.persist();
            }
            "/remember" => {
                if self.settings.path.is_none() {
                    return Err(
                        "Enable remembered preferences in F4 first; this writes public lobby metadata to disk",
                    );
                }
                nulllobby_core::domain::LobbyName::new(arg).map_err(|_| "Use /remember <label>")?;
                let lobby = self
                    .lobbies
                    .iter()
                    .find(|l| Some(l.id) == self.current)
                    .ok_or("Join a public lobby first")?;
                if lobby.kind == LobbyKind::Private {
                    return Err("Private invitations stay in RAM; private lobbies cannot be saved");
                }
                if self.remember.is_some() {
                    return Err("A bookmark export is already pending");
                }
                if self.queue(commands, AppCommand::ExportInvite) {
                    self.remember = Some(arg.into());
                }
            }
            "/connect" | "/forget" | "/autoconnect" => {
                let (number, option) = arg.split_once(' ').unwrap_or((arg, ""));
                let index = number
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .filter(|i| *i < self.settings.bookmarks.len())
                    .ok_or("Use a remembered lobby number from /bookmarks")?;
                if command == "/connect" {
                    if !option.is_empty() {
                        return Err("Use /connect <number>");
                    }
                    let card = LobbyCard::parse(&self.settings.bookmarks[index].card)
                        .map_err(|_| "Invalid remembered card")?;
                    if card.transport() != self.mode {
                        return Err(
                            "Bookmark uses another transport; leave active lobbies and select it explicitly",
                        );
                    }
                    self.queue(commands, AppCommand::JoinLobby(card));
                } else if command == "/forget" {
                    if !option.is_empty() {
                        return Err("Use /forget <number>");
                    }
                    self.settings.bookmarks.remove(index);
                    self.persist();
                } else {
                    self.settings.bookmarks[index].autoconnect = match option {
                        "on" => true,
                        "off" => false,
                        _ => return Err("Use /autoconnect <number> on|off"),
                    };
                    self.persist();
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
    fn key(&mut self, key: KeyEvent, commands: &mpsc::Sender<AppCommand>) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.code == KeyCode::F(10)
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            if self.queue(commands, AppCommand::Shutdown) {
                self.quitting = true;
            }
            return;
        }
        if self.quitting {
            return;
        }
        if self.modal.is_some() {
            match key.code {
                KeyCode::Char('y')
                    if self.modal == Some(Modal::Invite)
                        && key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    if let Some(card) = &self.invite {
                        let result = crate::invite::copy(&mut io::stdout(), card.expose_secret());
                        self.invite_feedback = Some(if result.is_ok() {
                            "Copy requested; terminal support/permission required."
                        } else {
                            "Copy request failed; select the card manually."
                        });
                        self.notice(if result.is_ok() {
                            "Clipboard copy requested. Your terminal may require permission or may not support OSC52."
                        } else { "Clipboard request failed; select the invitation manually." }, false);
                    }
                }
                KeyCode::Esc | KeyCode::Enter => self.dismiss(),
                KeyCode::PageUp => self.modal_scroll = self.modal_scroll.saturating_sub(8),
                KeyCode::PageDown => self.modal_scroll = self.modal_scroll.saturating_add(8),
                KeyCode::Char(key) if self.modal == Some(Modal::Settings) => {
                    match key {
                        '1' => self.settings.timestamps = !self.settings.timestamps,
                        '2' => self.settings.icons = !self.settings.icons,
                        '3' => self.settings.lobbies = !self.settings.lobbies,
                        '4' => self.settings.members = !self.settings.members,
                        '5' => self.settings.ascii = !self.settings.ascii,
                        '6' => {
                            let names = ["null", "ember", "ice", "classic", "light"];
                            let next = (names
                                .iter()
                                .position(|n| *n == self.settings.theme)
                                .unwrap_or(0)
                                + 1)
                                % names.len();
                            self.settings.theme = names[next].into();
                            self.theme = Theme::builtin(names[next]).unwrap();
                        }
                        '7' => {
                            if self.settings.path.is_some() {
                                if let Err(error) = self.settings.disable() {
                                    self.notice(error, true);
                                } else {
                                    self.notice("Saved preferences removed. Current preferences remain in RAM for this session.", true);
                                }
                            } else if let Err(error) = self.settings.enable() {
                                self.notice(error, true);
                            } else {
                                self.notice("Remembered preferences enabled. Reused nicknames and saved public cards may correlate activity; identity keys, trust and chat remain in RAM.", true);
                            }
                        }
                        _ => {}
                    }
                    self.persist();
                }
                _ => {}
            }
            return;
        }
        if key.modifiers.contains(KeyModifiers::ALT) {
            match key.code {
                KeyCode::Char('l') => {
                    self.settings.lobbies = !self.settings.lobbies;
                    self.persist();
                }
                KeyCode::Char('u') => {
                    self.settings.members = !self.settings.members;
                    self.persist();
                }
                KeyCode::Char('h') => self.open(Modal::Help),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::F(1) => self.open(Modal::Help),
            KeyCode::F(2) => {
                self.settings.lobbies = !self.settings.lobbies;
                self.persist();
            }
            KeyCode::F(3) => {
                self.settings.members = !self.settings.members;
                self.persist();
            }
            KeyCode::F(4) => self.open(Modal::Settings),
            KeyCode::F(5) => {
                self.open(Modal::Notices);
                self.queue(commands, AppCommand::Inspect(Inspection::Privacy));
            }
            KeyCode::F(6) => self.open(Modal::Preview),
            KeyCode::F(7) => self.open(Modal::Notices),
            KeyCode::F(8) => self.open(Modal::Bookmarks),
            KeyCode::F(9) => {
                self.settings.timestamps = !self.settings.timestamps;
                self.persist();
            }
            KeyCode::Enter => self.submit(commands),
            KeyCode::Backspace => self.input.backspace(),
            KeyCode::Delete => self.input.delete(),
            KeyCode::Left => self.input.left(),
            KeyCode::Right => self.input.right(),
            KeyCode::Home => self.input.home(),
            KeyCode::End => self.input.end(),
            KeyCode::Esc => self.input.clear(),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.input.insert(c)
            }
            _ => {}
        }
    }
}
fn on(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}
fn overlay_area(area: Rect) -> Rect {
    Rect::new(
        area.x,
        area.y.saturating_add(1).min(area.bottom()),
        area.width,
        area.height.saturating_sub(1),
    )
}
pub fn run(
    commands: mpsc::Sender<AppCommand>,
    mut events: mpsc::Receiver<AppEvent>,
    settings: Settings,
    mode: TransportKind,
) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other("TUI requires a terminal"));
    }
    enable_raw_mode()?;
    let _guard = TerminalGuard;
    execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut state = State::new(settings, mode);
    if let Some(nick) = &state.settings.nickname
        && let Ok(nick) = nulllobby_core::domain::Nickname::new(nick)
    {
        state.queue(&commands, AppCommand::SetNickname(nick));
    }
    let cards = state
        .settings
        .bookmarks
        .iter()
        .filter(|b| b.autoconnect)
        .map(|b| LobbyCard::parse(&b.card))
        .collect::<Vec<_>>();
    for card in cards.into_iter().flatten() {
        if card.transport() == mode {
            state.queue(&commands, AppCommand::JoinLobby(card));
        } else {
            state.notice("Autoconnect skipped a lobby with a different transport; select the transport explicitly", true);
        }
    }
    let mut invite_was_visible = false;
    let mut last_invite_revision = 0;
    let mut last_size = Rect::default();
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
        let day = Local::now().date_naive();
        for history in state.history.values_mut() {
            history.rollover(day);
        }
        let size = terminal.size()?;
        let size = Rect::new(0, 0, size.width, size.height);
        let invite_visible = state.modal == Some(Modal::Invite);
        let invite_changed = state.invite_revision != last_invite_revision;
        if invite_was_visible && (!invite_visible || size != last_size || invite_changed) {
            // Raw soft-wrapped card cells are deliberately absent from Ratatui's
            // buffer; clear them before a different view/size can be rendered.
            terminal.clear()?;
        }
        terminal.draw(|frame| state.draw(frame))?;
        if invite_visible
            && (!invite_was_visible || size != last_size || invite_changed)
            && let Some(card) = &state.invite
        {
            crate::invite::draw(
                &mut io::stdout(),
                card.expose_secret(),
                crate::invite::card_area(overlay_area(size)),
                crate::invite::color(state.theme.text.fg.unwrap_or(ratatui::style::Color::Reset)),
                crate::invite::color(state.theme.background),
            )?;
        }
        invite_was_visible = invite_visible;
        last_invite_revision = state.invite_revision;
        last_size = size;
        if !event::poll(Duration::from_millis(50))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) => state.key(key, &commands),
            Event::Paste(text) if state.modal.is_none() && !state.quitting => {
                let text = Zeroizing::new(text);
                if let Err(error) = state.input.paste(&text) {
                    state.notice(error, true);
                }
            }
            _ => {}
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clean_chat_notices_and_small_layouts() {
        let settings = Settings {
            welcome_seen: true,
            ..Settings::default()
        };
        let mut state = State::new(settings, TransportKind::Direct);
        for _ in 0..200 {
            state.notice("\x1b]52;c;attack\x07notice", false);
        }
        assert_eq!(state.notices.len(), 128);
        assert!(state.history.is_empty());
        assert!(state.notices.iter().all(|s| !s.contains('\x1b')));
        for (w, h) in [(120, 30), (60, 20), (20, 5), (1, 1)] {
            let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
            terminal.draw(|f| state.draw(f)).unwrap();
            state.open(Modal::Help);
            terminal.draw(|f| state.draw(f)).unwrap();
            let screen = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(!screen.contains("Chat · RAM only"));
            assert!(!screen.contains("Members · /who"));
            state.modal = None;
        }
    }
    #[test]
    fn multiline_paste_never_executes_commands_and_queue_is_atomic() {
        let mut state = State::new(Settings::default(), TransportKind::Direct);
        state.current = Some(LobbyId::from_bytes([1; 32]));
        state.modal = None;
        state.input.paste("hello\n/quit").unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        state.submit(&tx);
        assert!(rx.try_recv().is_err());
        assert!(!state.input.text().is_empty());
        let (tx, mut rx) = mpsc::channel(2);
        state.submit(&tx);
        for _ in 0..2 {
            assert!(matches!(rx.try_recv(), Ok(AppCommand::SendMessage { .. })));
        }
        state
            .input
            .paste("/join nl:v2:direct-private:synthetic\n")
            .unwrap();
        state.submit(&tx);
        assert!(
            rx.try_recv().is_err(),
            "a trailing newline must not broadcast an invite"
        );
        assert!(!state.input.text().is_empty());
        assert!(!state.quitting);
    }
    #[test]
    fn calendar_rollover_adds_one_separator_without_waiting_for_chat() {
        let day = NaiveDate::from_ymd_opt(2026, 10, 3).unwrap();
        let mut history = History {
            day,
            records: VecDeque::new(),
        };
        let next = day.succ_opt().unwrap();
        history.rollover(next);
        history.rollover(next);
        assert_eq!(history.records.len(), 1);
        assert!(matches!(history.records[0], Record::Day(d) if d == next));
    }
}
