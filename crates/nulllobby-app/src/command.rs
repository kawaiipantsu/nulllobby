use nulllobby_core::{
    Fingerprint, LobbyCard, LobbyId,
    domain::{AppCommand, Inspection, LobbyName, Nickname, PaddingPolicy},
    text::ValidatedText,
};
use nulllobby_transport::TransportKind;

pub const HELP: &str = "/help /about /nick <name> /create public|private|discoverable <name> /join <card> /confirm /leave /reconnect /switch <number> /lobbies /who /fingerprint /verify <full fingerprint> /unverify <full fingerprint> /verified /invite /transport direct|tor /security /network /privacy /padding none|bucketed /quit";
pub fn parse(line: &str, current: Option<LobbyId>) -> Result<AppCommand, &'static str> {
    if line.len() > 8192 {
        return Err("Input exceeds 8 KiB");
    }
    let line = if line.trim_start().starts_with('/') {
        line.trim_start()
    } else {
        line
    };
    if !line.starts_with('/') {
        return Ok(AppCommand::SendMessage {
            lobby: current.ok_or("Join a lobby first")?,
            body: ValidatedText::new(line).map_err(|_| "Invalid message text")?,
        });
    }
    let (command, arg) = line.split_once(' ').unwrap_or((line, ""));
    let arg = arg.trim();
    let inspection = match command {
        "/about" => Some(Inspection::About),
        "/help" => Some(Inspection::Help),
        "/lobbies" => Some(Inspection::Lobbies),
        "/who" => Some(Inspection::Members),
        "/fingerprint" => Some(Inspection::Fingerprint),
        "/verified" => Some(Inspection::Verified),
        "/security" => Some(Inspection::Security),
        "/network" => Some(Inspection::Network),
        "/privacy" => Some(Inspection::Privacy),
        _ => None,
    };
    if let Some(inspection) = inspection {
        if !arg.is_empty() {
            return Err("Unexpected argument");
        }
        return Ok(AppCommand::Inspect(inspection));
    }
    match command {
        "/create" => {
            let (kind, name) = arg
                .split_once(' ')
                .ok_or("Use /create public|private|discoverable <name>")?;
            let name = LobbyName::new(name).map_err(|_| "Invalid lobby name")?;
            match kind {
                "public" => Ok(AppCommand::CreatePublicLobby(name)),
                "private" => Ok(AppCommand::CreatePrivateLobby(name)),
                "discoverable" => Ok(AppCommand::CreateDiscoverableLobby(name)),
                _ => Err("Unknown lobby type"),
            }
        }
        "/join" => Ok(AppCommand::JoinLobby(
            LobbyCard::parse(arg).map_err(|_| "Invalid lobby card")?,
        )),
        "/nick" => Ok(AppCommand::SetNickname(
            Nickname::new(arg).map_err(|_| "Invalid nickname")?,
        )),
        "/verify" | "/unverify" => {
            let lobby = current.ok_or("Join a lobby first")?;
            let fingerprint = arg
                .parse::<Fingerprint>()
                .map_err(|_| "Use the complete 256-bit fingerprint")?;
            if command == "/verify" {
                Ok(AppCommand::VerifyPeer { lobby, fingerprint })
            } else {
                Ok(AppCommand::UnverifyPeer { lobby, fingerprint })
            }
        }
        "/transport" => Ok(AppCommand::SetTransport(match arg {
            "direct" => TransportKind::Direct,
            "tor" => TransportKind::Tor,
            _ => return Err("Use /transport direct|tor"),
        })),
        "/padding" => Ok(AppCommand::SetPadding(match arg {
            "none" => PaddingPolicy::None,
            "bucketed" => PaddingPolicy::Bucketed,
            _ => return Err("Use /padding none|bucketed"),
        })),
        "/switch" => Ok(AppCommand::SelectLobby(
            arg.parse::<usize>()
                .ok()
                .filter(|i| *i > 0 && *i <= 16)
                .ok_or("Use /switch <lobby number>")?
                - 1,
        )),
        "/leave" if arg.is_empty() => {
            Ok(AppCommand::LeaveLobby(current.ok_or("Join a lobby first")?))
        }
        "/invite" if arg.is_empty() => Ok(AppCommand::ExportInvite),
        "/confirm" if arg.is_empty() => Ok(AppCommand::ConfirmDiscoverable),
        "/reconnect" if arg.is_empty() => Ok(AppCommand::Reconnect),
        "/quit" if arg.is_empty() => Ok(AppCommand::Shutdown),
        _ => Err("Unknown command or invalid arguments; use /help"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inputs_are_bounded_and_terminal_safe() {
        assert!(parse(&"x".repeat(8193), None).is_err());
        assert!(parse("/nick a\x1b]52;c;attack\x07", None).is_err());
        assert!(parse("/verify ABCD", Some(LobbyId::from_bytes([0; 32]))).is_err());
        assert!(matches!(
            parse("/create public team", None),
            Ok(AppCommand::CreatePublicLobby(_))
        ));
        assert!(parse("/quit ignored", None).is_err());
    }
}
