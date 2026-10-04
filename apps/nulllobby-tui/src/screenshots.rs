//! Reproducible documentation images from the real renderer, synthetic data only.
use super::*;
use nulllobby_core::{Fingerprint, domain::MemberView};
use nulllobby_platform::HardeningStatus;
use ratatui::{
    backend::TestBackend,
    style::{Color, Modifier},
};
use std::{fmt::Write as _, fs};

#[test]
#[ignore = "documentation renderer; set NULLLOBBY_SCREENSHOT_DIR explicitly"]
fn render_documentation() {
    let output =
        std::env::var_os("NULLLOBBY_SCREENSHOT_DIR").expect("explicit screenshot directory");
    let output = std::path::PathBuf::from(output);
    fs::create_dir_all(&output).unwrap();
    let mut state = State::new(
        Settings {
            welcome_seen: true,
            ..Settings::default()
        },
        TransportKind::Tor,
    );
    let id = LobbyId::from_bytes([1; 32]);
    let own = Fingerprint::of_public_key(&[1; 32]);
    let peer = Fingerprint::of_public_key(&[2; 32]);
    let visitor = Fingerprint::of_public_key(&[3; 32]);
    let members = vec![
        MemberView {
            nickname: "demo-you".into(),
            fingerprint: own,
            verified: false,
            organization: None,
        },
        MemberView {
            nickname: "demo-scout".into(),
            fingerprint: peer,
            verified: true,
            organization: None,
        },
        MemberView {
            nickname: "demo-helper[bot]".into(),
            fingerprint: visitor,
            verified: false,
            organization: None,
        },
    ];
    state.current = Some(id);
    state.network = NetworkStatus::Ready;
    state.lobbies = vec![
        LobbyView {
            id,
            name: "coordination".into(),
            kind: LobbyKind::Private,
            peers: 2,
            members,
            fingerprint: own,
            memory: [HardeningStatus::Active; 2],
            persistent: false,
            durable: false,
            mailbox: false,
            administrator: false,
            status: "Connected · synthetic documentation preview".into(),
        },
        LobbyView {
            id: LobbyId::from_bytes([2; 32]),
            name: "field-notes".into(),
            kind: LobbyKind::Private,
            peers: 0,
            members: vec![],
            fingerprint: Fingerprint::of_public_key(&[4; 32]),
            memory: [HardeningStatus::Active; 2],
            persistent: false,
            durable: false,
            mailbox: false,
            administrator: false,
            status: "Listening".into(),
        },
    ];
    for (fingerprint, nickname, body, verified) in [
        (
            own,
            "demo-you",
            "Welcome to the authorized test lab. Keep this lobby scoped to the exercise.",
            false,
        ),
        (
            peer,
            "demo-scout",
            "Fingerprint compared out of band. Ready to coordinate.",
            true,
        ),
        (
            own,
            "demo-you",
            "Share observations here; keep credentials and operational secrets out of the chat.",
            false,
        ),
        (
            visitor,
            "demo-helper[bot]",
            "[bot:local model] Automated bot. Only @demo-helper prompts go to the local model.",
            false,
        ),
        (
            peer,
            "demo-scout",
            "The network checks are complete. I will add a short summary.",
            true,
        ),
    ] {
        state.event(AppEvent::MessageReceived {
            id: [0; 16],
            historical: false,
            lobby: id,
            fingerprint,
            nickname: nickname.into(),
            body: body.into(),
            verified,
        });
    }
    let history = state.history.get_mut(&id).unwrap();
    history.day = NaiveDate::from_ymd_opt(2026, 10, 3).unwrap();
    for (index, record) in history.records.iter_mut().enumerate() {
        if let Record::Message { time, .. } = record {
            *time = format!("19:24:{:02}", index * 7);
        }
    }
    state
        .input
        .paste("First observation\nSecond observation\nThird observation")
        .unwrap();
    capture(&state, &output.join("chat.svg"));
    state.input.clear();
    state.mode = TransportKind::Direct;
    state.theme = Theme::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/nulllobby.theme"),
    )
    .unwrap()
    .0;
    state.settings.theme = "themes/nulllobby.theme".into();
    capture(&state, &output.join("irssi.svg"));
    state.theme = Theme::builtin("ember").unwrap();
    state.settings.theme = "ember".into();
    state.open(Modal::Settings);
    capture(&state, &output.join("settings.svg"));
    state.theme = Theme::default();
    state.settings.theme = "null".into();
    state.open(Modal::Help);
    capture(&state, &output.join("help.svg"));
    state.modal = None;
    state.mode = TransportKind::Tor;
    state.lobbies[0].persistent = true;
    state.lobbies[0].durable = true;
    state.lobbies[0].mailbox = true;
    state.lobbies[0].members[1].organization = Some("Synthetic Team / member".into());
    state.event(AppEvent::MessageReceived {
        lobby: id,
        id: [9; 16],
        historical: true,
        fingerprint: own,
        nickname: "demo-you".into(),
        body:
            "Synthetic durable update: available from an opted-in peer mailbox for up to 24 hours."
                .into(),
        verified: false,
    });
    state.event(AppEvent::Delivery {
        lobby: id,
        id: [9; 16],
        state: nulllobby_core::domain::DeliveryState::Stored(peer),
    });
    if let Some(Record::Message { time, .. }) =
        state.history.get_mut(&id).unwrap().records.back_mut()
    {
        *time = "19:25:00".into();
    }
    capture(&state, &output.join("delivery.svg"));
}
fn capture(state: &State, path: &std::path::Path) {
    let mut terminal = Terminal::new(TestBackend::new(140, 32)).unwrap();
    terminal.draw(|f| state.draw(f)).unwrap();
    let buffer = terminal.backend().buffer();
    let mut svg = String::from(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1400\" height=\"640\" viewBox=\"0 0 1400 640\"><title>NullLobby synthetic documentation preview</title><rect width=\"100%\" height=\"100%\" fill=\"#0c1118\"/>",
    );
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            let cell = &buffer[(x, y)];
            if cell.diff_option == ratatui::buffer::CellDiffOption::Skip {
                continue;
            }
            let mut fg = color(cell.fg, "#dbe2ed");
            let mut bg = color(cell.bg, "#0c1118");
            if cell.modifier.contains(Modifier::REVERSED) {
                std::mem::swap(&mut fg, &mut bg);
            }
            let px = x as usize * 10;
            let py = y as usize * 20;
            write!(
                svg,
                "<rect x=\"{px}\" y=\"{py}\" width=\"10\" height=\"20\" fill=\"{bg}\"/>"
            )
            .unwrap();
            if cell.symbol() != " " {
                let symbol = cell
                    .symbol()
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;");
                write!(svg,"<text x=\"{px}\" y=\"{}\" fill=\"{fg}\" font-family=\"DejaVu Sans Mono,monospace\" font-size=\"16.6\" font-weight=\"{}\">{symbol}</text>",
                    py+16,if cell.modifier.contains(Modifier::BOLD){"bold"}else{"normal"}).unwrap();
            }
        }
    }
    svg.push_str("</svg>");
    fs::write(path, svg).unwrap();
}
fn color(color: Color, default: &str) -> String {
    match color {
        Color::Reset => default.into(),
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Indexed(n) => {
            let base = [
                "#000000", "#aa0000", "#00aa00", "#aaaa00", "#0000aa", "#aa00aa", "#00aaaa",
                "#aaaaaa", "#555555", "#ff5555", "#55ff55", "#ffff55", "#5555ff", "#ff55ff",
                "#55ffff", "#ffffff",
            ];
            match n {
                0..=15 => base[n as usize].into(),
                16..=231 => {
                    let n = n - 16;
                    let v = [0u8, 95, 135, 175, 215, 255];
                    format!(
                        "#{:02x}{:02x}{:02x}",
                        v[(n / 36) as usize],
                        v[((n / 6) % 6) as usize],
                        v[(n % 6) as usize]
                    )
                }
                _ => {
                    let v = 8 + (n - 232) * 10;
                    format!("#{v:02x}{v:02x}{v:02x}")
                }
            }
        }
        c => color_from_named(c),
    }
}
fn color_from_named(color: Color) -> String {
    let index = match color {
        Color::Black => 0,
        Color::Red => 1,
        Color::Green => 2,
        Color::Yellow => 3,
        Color::Blue => 4,
        Color::Magenta => 5,
        Color::Cyan => 6,
        Color::Gray => 7,
        Color::DarkGray => 8,
        Color::LightRed => 9,
        Color::LightGreen => 10,
        Color::LightYellow => 11,
        Color::LightBlue => 12,
        Color::LightMagenta => 13,
        Color::LightCyan => 14,
        Color::White => 15,
        _ => 7,
    };
    self::color(Color::Indexed(index), "#dbe2ed")
}
