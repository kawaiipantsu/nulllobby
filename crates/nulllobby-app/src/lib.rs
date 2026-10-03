//! Application orchestration. Clients send commands and render events; all networking lives here.
#![forbid(unsafe_code)]
pub mod command;
mod room;

use nulllobby_core::{
    LobbyCard, LobbyId, LobbyKind,
    domain::{AppCommand, AppEvent, Inspection, LobbyName, LobbyView, Nickname, PaddingPolicy},
    message::Payload,
};
use nulllobby_direct::{DirectConfig, DirectTransport};
use nulllobby_tor::{TorConfig, TorTransport};
use nulllobby_transport::{Endpoint, ModePolicy, NetworkObserver, Transport, TransportKind};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinSet,
};

pub use nulllobby_direct::DirectConfig as DirectOptions;
pub use nulllobby_tor::TorConfig as TorOptions;
#[derive(Clone)]
pub struct Config {
    pub direct: DirectConfig,
    pub tor: TorConfig,
    pub no_dht: bool,
    pub peers: Vec<Endpoint>,
    pub mode: TransportKind,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            direct: DirectConfig::default(),
            tor: TorConfig::default(),
            no_dht: false,
            peers: vec![],
            mode: TransportKind::Direct,
        }
    }
}
struct Lobby {
    id: LobbyId,
    commands: mpsc::Sender<room::Command>,
    view: Option<LobbyView>,
}
enum Pending {
    Create(LobbyName),
    Join(LobbyCard),
}
pub struct App {
    config: Config,
    observer: Option<Arc<dyn NetworkObserver>>,
    commands: mpsc::Receiver<AppCommand>,
    events: mpsc::Sender<AppEvent>,
    rooms: Vec<Lobby>,
    current: Option<LobbyId>,
    nickname: Nickname,
    padding: PaddingPolicy,
    global: Arc<Semaphore>,
    pending_handshakes: Arc<Semaphore>,
    pending_discoverable: Option<(Pending, Instant)>,
    workers: JoinSet<()>,
    room_tx: mpsc::Sender<room::Event>,
    room_rx: mpsc::Receiver<room::Event>,
}
impl App {
    pub fn new(
        config: Config,
        commands: mpsc::Receiver<AppCommand>,
        events: mpsc::Sender<AppEvent>,
    ) -> Self {
        let (room_tx, room_rx) = mpsc::channel(128);
        Self {
            config,
            observer: None,
            commands,
            events,
            rooms: vec![],
            current: None,
            nickname: Nickname::new("guest").expect("valid default nickname"),
            padding: PaddingPolicy::Bucketed,
            global: Arc::new(Semaphore::new(128)),
            pending_handshakes: Arc::new(Semaphore::new(32)),
            pending_discoverable: None,
            workers: JoinSet::new(),
            room_tx,
            room_rx,
        }
    }
    pub fn with_observer(mut self, observer: Arc<dyn NetworkObserver>) -> Self {
        self.observer = Some(observer);
        self
    }
    async fn notice(&self, text: impl Into<String>) {
        let _ = self
            .events
            .send(AppEvent::Notice {
                lobby: self.current,
                text: text.into(),
            })
            .await;
    }
    async fn view(&self) {
        let _ = self
            .events
            .send(AppEvent::View {
                transport: self.config.mode,
                current: self.current,
                lobbies: self.rooms.iter().filter_map(|r| r.view.clone()).collect(),
                padding: self.padding,
            })
            .await;
    }
    fn send(&self, id: LobbyId, command: room::Command) -> Result<(), &'static str> {
        self.rooms
            .iter()
            .find(|r| r.id == id)
            .ok_or("Lobby no longer active")?
            .commands
            .try_send(command)
            .map_err(|_| "Lobby command queue full or disconnected")
    }
    async fn open(
        &mut self,
        name: LobbyName,
        kind: LobbyKind,
        card: Option<LobbyCard>,
    ) -> Result<(), &'static str> {
        if self.rooms.len() >= 16 {
            return Err("Maximum 16 lobbies");
        }
        if let Some(card) = &card {
            if card.transport() != self.config.mode {
                return Err(
                    "Card uses another transport; leave all lobbies and select the matching transport first",
                );
            }
            if self.rooms.iter().any(|r| r.id == card.lobby_id()) {
                self.current = Some(card.lobby_id());
                return Ok(());
            }
        }
        if self.config.mode == TransportKind::Tor && kind == LobbyKind::PublicDiscoverable {
            return Err("Discoverable Tor lobbies are unsupported; use a lobby card");
        }
        let observer = self
            .observer
            .clone()
            .unwrap_or_else(|| Arc::new(ModePolicy(self.config.mode)));
        let mut transport: Box<dyn Transport> = match self.config.mode {
            TransportKind::Direct => Box::new(
                DirectTransport::new(
                    self.config.direct.clone(),
                    observer.clone(),
                    self.global.clone(),
                )
                .with_pending(self.pending_handshakes.clone()),
            ),
            TransportKind::Tor => Box::new(TorTransport::new(
                self.config.tor.clone(),
                observer.clone(),
                self.global.clone(),
                self.pending_handshakes.clone(),
            )),
        };
        self.notice(match self.config.mode {
            TransportKind::Direct => "DIRECT / ENCRYPTED SESSIONS REQUIRED / IP EXPOSED TO PEERS",
            TransportKind::Tor => "TOR / BOOTSTRAPPING / NO DIRECT FALLBACK",
        })
        .await;
        transport.start().await.map_err(|_| "Transport unavailable; Tor requires a bootstrapped daemon, SAFECOOKIE cookie path and local SOCKS/Control ports")?;
        let (card, local) = if self.config.mode == TransportKind::Tor && card.is_none() {
            let local = transport
                .create_endpoint([0; 32])
                .await
                .map_err(|_| "Unable to create ephemeral onion service")?;
            let seed = transport
                .local_transport_identity(local)
                .map_err(|_| "Onion endpoint unavailable")?;
            let card = if kind == LobbyKind::Private {
                LobbyCard::private(self.config.mode, vec![seed])
            } else {
                LobbyCard::public(self.config.mode, vec![seed])
            }
            .map_err(|_| "Lobby capability generation failed")?;
            (card, local)
        } else {
            let card = match card { Some(card) => card, None => match kind { LobbyKind::PublicUnlisted => LobbyCard::public(self.config.mode,vec![]), LobbyKind::Private => LobbyCard::private(self.config.mode,vec![]), LobbyKind::PublicDiscoverable => LobbyCard::discoverable(name.as_str()) }.map_err(|_| "Lobby creation failed; discoverable names use 1..64 ASCII letters, digits, '-' or '_'")? };
            let scope = card
                .discovery_scope()
                .map_err(|_| "Discovery derivation failed")?;
            let local = transport
                .create_endpoint(scope)
                .await
                .map_err(|_| "Listener creation failed")?;
            (card, local)
        };
        let id = card.lobby_id();
        let (tx, rx) = mpsc::channel(32);
        let room = room::Room::new(
            room::Start {
                card,
                name,
                nickname: self.nickname.clone(),
                padding: self.padding,
                transport,
                local,
                config: self.config.clone(),
                observer,
            },
            self.room_tx.clone(),
            rx,
        )?;
        self.rooms.push(Lobby {
            id,
            commands: tx,
            view: None,
        });
        self.current = Some(id);
        self.workers.spawn(room.run());
        self.notice("Lobby identity is ephemeral. Compare complete fingerprints out of band before /verify. Trust and history disappear on exit.").await;
        Ok(())
    }
    async fn inspect(&self, inspection: Inspection) {
        let room = self
            .rooms
            .iter()
            .find(|r| Some(r.id) == self.current)
            .and_then(|r| r.view.as_ref());
        match inspection {
            Inspection::About => {
                self.notice(format!(
                    "{} — created by {} for {}. {}",
                    nulllobby_core::branding::PROJECT,
                    nulllobby_core::branding::AUTHOR,
                    nulllobby_core::branding::COMMUNITY,
                    nulllobby_core::branding::DESCRIPTION
                ))
                .await;
                self.notice("Identities, trust and history stay in RAM. Direct exposes peer IPs; Tor uses onion services. No independent professional security audit has yet been completed.").await;
            }
            Inspection::Help => self.notice(command::HELP).await,
            Inspection::Lobbies => {
                for (i, lobby) in self.rooms.iter().enumerate() {
                    self.notice(format!(
                        "{}: {}",
                        i + 1,
                        lobby.view.as_ref().map_or("Starting", |v| &v.name)
                    ))
                    .await;
                }
            }
            Inspection::Members | Inspection::Verified => {
                if let Some(room) = room {
                    for member in &room.members {
                        if matches!(inspection, Inspection::Members) || member.verified {
                            self.notice(format!(
                                "{} | {} | encrypted / {}",
                                member.nickname,
                                member.fingerprint,
                                if member.verified {
                                    "verified"
                                } else {
                                    "unverified"
                                }
                            ))
                            .await;
                        }
                    }
                }
            }
            Inspection::Fingerprint => {
                if let Some(room) = room {
                    self.notice(format!("Your lobby fingerprint: {}", room.fingerprint))
                        .await;
                } else {
                    self.notice("Join a lobby first").await;
                }
            }
            Inspection::Security | Inspection::Network | Inspection::Privacy => {
                self.notice(match self.config.mode { TransportKind::Direct => "DIRECT / IP EXPOSED TO PEERS. DHT observers can correlate IPs and swarm identifiers. BitTorrent and NL_chat may be identifiable. Direct is not anonymous.", TransportKind::Tor => "TOR / ONION TRANSPORT. Peer IPs are hidden by onion transport. Tor use may be observable locally; sufficiently powerful observers may correlate traffic. No exit peers, DHT or Direct fallback. SOCKS isolation is requested per lobby; configure IsolateSOCKSAuth explicitly." }).await;
                self.notice("History, identities and trust: RAM only. No professional security audit completed. Authorized lobby recipients can read messages. Terminal scrollback, kernel compromise and physical memory are outside this boundary.").await;
                if let Some(room) = room {
                    self.notice(format!(
                        "{} | peers: {} | memory locks: {:?} | identity: ephemeral, lobby scoped",
                        room.status, room.peers, room.memory
                    ))
                    .await;
                    self.notice(if room.kind == LobbyKind::Private {
                        nulllobby_core::session::PRIVATE_SUITE
                    } else {
                        nulllobby_core::session::PUBLIC_SUITE
                    })
                    .await;
                    self.notice(format!("Fingerprint: {}", room.fingerprint))
                        .await;
                }
            }
        }
    }
    async fn handle(&mut self, command: AppCommand) -> Result<bool, &'static str> {
        match command {
            AppCommand::CreatePublicLobby(name) => {
                self.open(name, LobbyKind::PublicUnlisted, None).await?
            }
            AppCommand::CreatePrivateLobby(name) => {
                self.open(name, LobbyKind::Private, None).await?
            }
            AppCommand::CreateDiscoverableLobby(name) => {
                if self.config.mode == TransportKind::Tor {
                    return Err("Globally discoverable Tor lobbies are unsupported");
                }
                self.pending_discoverable = Some((Pending::Create(name), Instant::now()));
                self.discoverable_warning().await;
            }
            AppCommand::JoinLobby(card) => {
                if card.kind() == LobbyKind::PublicDiscoverable {
                    self.pending_discoverable = Some((Pending::Join(card), Instant::now()));
                    self.discoverable_warning().await;
                } else {
                    self.open(
                        LobbyName::new("Joining lobby").expect("valid name"),
                        card.kind(),
                        Some(card),
                    )
                    .await?;
                }
            }
            AppCommand::ConfirmDiscoverable => {
                let (pending, created) = self
                    .pending_discoverable
                    .take()
                    .ok_or("No pending discoverable lobby")?;
                if created.elapsed() > Duration::from_secs(60) {
                    return Err("Confirmation expired; issue the create or join command again");
                }
                match pending {
                    Pending::Create(name) => {
                        self.open(name, LobbyKind::PublicDiscoverable, None).await?
                    }
                    Pending::Join(card) => {
                        self.open(
                            LobbyName::new("Joining lobby").expect("valid name"),
                            card.kind(),
                            Some(card),
                        )
                        .await?
                    }
                }
            }
            AppCommand::LeaveLobby(id) => {
                self.send(id, room::Command::Stop)?;
            }
            AppCommand::SendMessage { lobby, body } => {
                self.send(lobby, room::Command::Send(Payload::Chat(body)))?
            }
            AppCommand::SetNickname(nickname) => {
                self.nickname = nickname.clone();
                for room in &self.rooms {
                    let _ = room
                        .commands
                        .try_send(room::Command::Nick(nickname.clone()));
                }
            }
            AppCommand::VerifyPeer { lobby, fingerprint } => {
                self.send(lobby, room::Command::Trust(fingerprint, true))?;
                self.notice("Fingerprint marked verified in this lobby. This records your out-of-band comparison.").await;
            }
            AppCommand::UnverifyPeer { lobby, fingerprint } => {
                self.send(lobby, room::Command::Trust(fingerprint, false))?
            }
            AppCommand::SetTransport(mode) => {
                if !self.rooms.is_empty() {
                    return Err("Leave all lobbies before changing transport");
                }
                self.config.mode = mode;
                self.pending_discoverable = None;
            }
            AppCommand::SetPadding(padding) => {
                self.padding = padding;
                for room in &self.rooms {
                    let _ = room.commands.try_send(room::Command::Padding(padding));
                }
            }
            AppCommand::SelectLobby(index) => {
                self.current = Some(self.rooms.get(index).ok_or("Unknown lobby number")?.id);
            }
            AppCommand::Inspect(inspection) => self.inspect(inspection).await,
            AppCommand::ExportInvite => {
                self.notice("Invite disclosure is explicit. Private cards grant access; terminal scrollback and clipboard managers are outside the security boundary.").await;
                self.send(
                    self.current.ok_or("Join a lobby first")?,
                    room::Command::Invite,
                )?;
            }
            AppCommand::Reconnect => self.send(
                self.current.ok_or("Join a lobby first")?,
                room::Command::Reconnect,
            )?,
            AppCommand::Shutdown => return Ok(false),
        }
        self.view().await;
        Ok(true)
    }
    async fn discoverable_warning(&self) {
        self.notice("WARNING: discoverable lobbies can be enumerated and monitored through their public discovery identifier. Use /confirm within 60 seconds to proceed.").await;
    }
    async fn room_event(&mut self, event: room::Event) {
        match event {
            room::Event::Ui(event) => {
                let _ = self.events.send(event).await;
            }
            room::Event::View(view) => {
                if let Some(room) = self.rooms.iter_mut().find(|r| r.id == view.id) {
                    room.view = Some(view);
                }
                self.view().await;
            }
            room::Event::Stopped(id) => {
                self.rooms.retain(|r| r.id != id);
                if self.current == Some(id) {
                    self.current = self.rooms.first().map(|r| r.id);
                }
                let _ = self.events.send(AppEvent::LobbyLeft(id)).await;
                self.view().await;
            }
        }
    }
    pub async fn run(mut self) {
        self.notice("NullLobby — RAM-only Linux client. /help lists commands. Direct exposes your IP to peers. Use /transport tor before creating or joining onion lobbies.").await;
        self.view().await;
        loop {
            tokio::select! {
                command = self.commands.recv() => { let Some(command) = command else { break; }; match self.handle(command).await { Ok(true) => {}, Ok(false) => break, Err(message) => self.notice(message).await } }
                Some(event) = self.room_rx.recv() => self.room_event(event).await,
                _ = self.workers.join_next(), if !self.workers.is_empty() => {},
                _ = self.events.closed() => break,
            }
        }
        for room in &self.rooms {
            let _ = room.commands.try_send(room::Command::Stop);
        }
        let shutdown = tokio::time::sleep(Duration::from_secs(8));
        tokio::pin!(shutdown);
        while !self.workers.is_empty() {
            tokio::select! { _ = self.workers.join_next() => {}, Some(event) = self.room_rx.recv() => { if let room::Event::Stopped(id) = event { self.rooms.retain(|r| r.id != id); } }, _ = &mut shutdown => { self.workers.abort_all(); break; } }
        }
        while self.workers.join_next().await.is_some() {}
        let _ = self.events.send(AppEvent::ShutdownComplete).await;
    }
}
