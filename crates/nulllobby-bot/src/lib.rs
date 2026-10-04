//! Headless, explicitly addressed bots using the same authenticated chat core.
#![forbid(unsafe_code)]
pub mod provider;

use nulllobby_core::{
    Fingerprint, LobbyCard, LobbyId,
    domain::{AppCommand, AppEvent, LobbyName, Nickname},
    text::ValidatedText,
};
use provider::Provider;
use secrecy::ExposeSecret;
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinSet};
use zeroize::Zeroizing;

pub enum Start {
    Join(LobbyCard),
    Public(LobbyName),
    Private(LobbyName),
}
pub struct Bot {
    provider: Arc<Provider>,
    name: String,
    nickname: Nickname,
    max_requests: u32,
}
impl Bot {
    pub fn new(provider: Provider, name: &str, max_requests: u32) -> Result<Self, &'static str> {
        if name.is_empty() || name.chars().any(char::is_whitespace) || name.starts_with('@') {
            return Err("Bot name must be a single nickname without @ prefix");
        }
        let nickname = Nickname::new(&format!("{name}[bot]"))
            .map_err(|_| "Bot name is too long or invalid")?;
        if !(1..=10000).contains(&max_requests) {
            return Err("Bot request limit must be 1–10000");
        }
        Ok(Self {
            provider: Arc::new(provider),
            name: name.into(),
            nickname,
            max_requests,
        })
    }

    /// No transcripts are printed. An invite is printed only when explicitly requested.
    pub async fn run(
        self,
        commands: mpsc::Sender<AppCommand>,
        mut events: mpsc::Receiver<AppEvent>,
        start: Start,
        export_invite: bool,
    ) -> Result<(), &'static str> {
        commands
            .send(AppCommand::SetNickname(self.nickname))
            .await
            .map_err(|_| "Application stopped")?;
        commands
            .send(match start {
                Start::Join(card) => AppCommand::JoinLobby(card),
                Start::Public(name) => AppCommand::CreatePublicLobby(name),
                Start::Private(name) => AppCommand::CreatePrivateLobby(name),
            })
            .await
            .map_err(|_| "Application stopped")?;
        let mut lobby: Option<(LobbyId, Fingerprint)> = None;
        let mut members = BTreeSet::new();
        let mut requests = 0u32;
        let mut last_request: Option<Instant> = None;
        let mut jobs: JoinSet<(LobbyId, Result<Zeroizing<String>, &'static str>)> = JoinSet::new();
        let prefix = format!("@{} ", self.name);
        let label = self.provider.kind().label();
        let deadline = tokio::time::sleep(Duration::from_secs(300));
        tokio::pin!(deadline);
        let result = loop {
            tokio::select! {
                _ = &mut deadline, if lobby.is_none() => break Err("Bot lobby startup timed out; no fallback"),
                result = jobs.join_next(), if !jobs.is_empty() => {
                    match result {
                        Some(Ok((id, Ok(reply)))) if lobby.is_some_and(|l| l.0 == id) => {
                            let reply = Zeroizing::new(format!("[bot:{label}] {}", reply.as_str()));
                            if let Ok(body) = ValidatedText::new(&reply) {
                                let _ = commands.try_send(AppCommand::SendMessage { lobby: id, body });
                            }
                        }
                        Some(Ok((_, Err(category)))) => eprintln!("{category}"),
                        _ => {}
                    }
                }
                event = events.recv() => match event {
                    Some(AppEvent::View { lobbies, .. }) => {
                        if let Some(view) = lobbies.first() {
                            if lobby.is_none() {
                                lobby = Some((view.id, view.fingerprint));
                                eprintln!("Bot lobby active; only explicitly addressed prompts are processed. Provider: {label}");
                                if export_invite { let _ = commands.try_send(AppCommand::ExportInvite); }
                            }
                            let fresh = view.members.iter().any(|m| m.fingerprint != view.fingerprint && !members.contains(&m.fingerprint));
                            if fresh {
                                let disclosure = format!("[bot:{label}] Automated bot. Use @{} <prompt>. Addressed prompts are sent to {label}; no history is sent. Responses can be wrong.", self.name);
                                if let Ok(body) = ValidatedText::new(&disclosure) {
                                    let _ = commands.try_send(AppCommand::SendMessage { lobby: view.id, body });
                                }
                            }
                            // Keep only current members; at most the core's bounded member list.
                            members = view.members.iter().map(|m| m.fingerprint).collect();
                        }
                    }
                    Some(AppEvent::MessageReceived { lobby: id, fingerprint, body, historical:false, .. }) => {
                        let body = Zeroizing::new(body);
                        if !lobby.is_some_and(|l| l.0 == id && l.1 != fingerprint) || !jobs.is_empty()
                            || requests >= self.max_requests || last_request.is_some_and(|t| t.elapsed() < Duration::from_secs(5)) { continue; }
                        let Some(prompt) = body.strip_prefix(&prefix).filter(|s| !s.trim().is_empty()) else { continue; };
                        let prompt = Zeroizing::new(prompt.to_owned());
                        requests += 1;
                        last_request = Some(Instant::now());
                        let provider = self.provider.clone();
                        jobs.spawn(async move { (id, provider.reply(&prompt).await) });
                    }
                    Some(AppEvent::Invite(card)) if export_invite => println!("{}", card.expose_secret()),
                    Some(AppEvent::TransportStatus { status: nulllobby_transport::NetworkStatus::Unavailable, .. }) => break Err("Bot transport unavailable; no fallback"),
                    Some(AppEvent::LobbyLeft(_)) => break Err("Bot lobby disconnected"),
                    Some(AppEvent::FatalError) => break Err("Bot application failed"),
                    Some(AppEvent::ShutdownComplete) | None => break Ok(()),
                    _ => {}
                }
            }
        };
        jobs.abort_all();
        let _ = commands.try_send(AppCommand::Shutdown);
        result
    }
}
