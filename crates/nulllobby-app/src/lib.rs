//! Application orchestration. Clients send commands and render events; all networking lives here.
#![forbid(unsafe_code)]
pub mod command;
pub mod organization;
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
#[cfg(feature = "tor-arti-experimental")]
struct ArtiProgress {
    observer: Arc<dyn NetworkObserver>,
    events: mpsc::Sender<AppEvent>,
}
#[cfg(feature = "tor-arti-experimental")]
impl NetworkObserver for ArtiProgress {
    fn before_network_action(
        &self,
        action: nulllobby_transport::NetworkAction,
    ) -> Result<(), nulllobby_transport::TransportError> {
        self.observer.before_network_action(action)
    }
    fn connection_state(&self, state: nulllobby_transport::ConnectionState) {
        self.observer.connection_state(state);
    }
    fn bootstrap_progress(&self, percent: u8) {
        self.observer.bootstrap_progress(percent);
        let _ = self.events.try_send(AppEvent::Notice {
            lobby: None,
            text: format!("EXPERIMENTAL ARTI / BOOTSTRAP {percent}% / NO DIRECT FALLBACK"),
        });
    }
    fn transport_diagnostic(&self, category: &str) {
        self.observer.transport_diagnostic(category);
        let _ = self.events.try_send(AppEvent::Notice {
            lobby: None,
            text: category.into(),
        });
    }
}
#[cfg(feature = "tor-arti-experimental")]
pub use nulllobby_tor::arti::ArtiConfig as ArtiOptions;
#[derive(Clone)]
pub struct Config {
    pub vault: Option<Arc<nulllobby_store::Vault>>,
    pub direct: DirectConfig,
    pub tor: TorConfig,
    #[cfg(feature = "tor-arti-experimental")]
    pub arti: Option<ArtiOptions>,
    pub no_dht: bool,
    pub peers: Vec<Endpoint>,
    pub mode: TransportKind,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            vault: None,
            direct: DirectConfig::default(),
            tor: TorConfig::default(),
            #[cfg(feature = "tor-arti-experimental")]
            arti: None,
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
    #[cfg(feature = "tor-arti-experimental")]
    arti: Option<Arc<nulllobby_tor::arti::ArtiPool>>,
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
            #[cfg(feature = "tor-arti-experimental")]
            arti: config
                .arti
                .clone()
                .map(|config| Arc::new(nulllobby_tor::arti::ArtiPool::new(config))),
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
        let created = card.is_none();
        if self.rooms.len() >= 16 {
            return Err("Maximum 16 lobbies");
        }
        if let Some(card) = &card {
            if let Some(vault) = &self.config.vault
                && vault
                    .retired(card.lobby_id())
                    .map_err(|_| "Vault state unavailable")?
            {
                return Err("This capability was retired; obtain the replacement invitation");
            }
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
            TransportKind::Tor => {
                #[cfg(feature = "tor-arti-experimental")]
                if let Some(pool) = &self.arti {
                    Box::new(nulllobby_tor::arti::ArtiTransport::new(
                        pool.clone(),
                        Arc::new(ArtiProgress {
                            observer: observer.clone(),
                            events: self.events.clone(),
                        }),
                        self.global.clone(),
                        self.pending_handshakes.clone(),
                    ))
                } else {
                    Box::new(TorTransport::new(
                        self.config.tor.clone(),
                        observer.clone(),
                        self.global.clone(),
                        self.pending_handshakes.clone(),
                    ))
                }
                #[cfg(not(feature = "tor-arti-experimental"))]
                Box::new(TorTransport::new(
                    self.config.tor.clone(),
                    observer.clone(),
                    self.global.clone(),
                    self.pending_handshakes.clone(),
                ))
            }
        };
        self.notice(match self.config.mode {
            TransportKind::Direct => "DIRECT / ENCRYPTED SESSIONS REQUIRED / IP EXPOSED TO PEERS",
            TransportKind::Tor => "TOR / BOOTSTRAPPING / NO DIRECT FALLBACK",
        })
        .await;
        #[cfg(feature = "tor-arti-experimental")]
        if self.config.mode == TransportKind::Tor && self.arti.is_some() {
            self.notice("EXPERIMENTAL ARTI / ONION TRANSPORT / RAM-only lobby services; normal Tor guards/cache persist").await;
        }
        let _ = self
            .events
            .send(AppEvent::TransportStatus {
                transport: self.config.mode,
                status: nulllobby_transport::NetworkStatus::Starting,
            })
            .await;
        if transport.start().await.is_err() {
            let _ = self
                .events
                .send(AppEvent::TransportStatus {
                    transport: self.config.mode,
                    status: nulllobby_transport::NetworkStatus::Unavailable,
                })
                .await;
            return Err(
                "Transport unavailable; check the selected backend configuration and /network. No fallback was attempted.",
            );
        }
        let _ = self
            .events
            .send(AppEvent::TransportStatus {
                transport: self.config.mode,
                status: nulllobby_transport::NetworkStatus::Ready,
            })
            .await;
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
                created,
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
        )
        .await?;
        self.rooms.push(Lobby {
            id,
            commands: tx,
            view: None,
        });
        self.current = Some(id);
        self.workers.spawn(room.run());
        self.notice("Compare complete fingerprints out of band before /verify. Trust stays in RAM. Persistence and delivery settings are shown in /privacy.").await;
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
                            if let Some(organization) = &member.organization {
                                self.notice(format!("Organization attestation: {organization}; separate from human verification")).await;
                            }
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
                self.notice(match self.config.mode { TransportKind::Direct => "DIRECT / IP EXPOSED TO PEERS. DHT observers can correlate IPs and swarm identifiers. BitTorrent and NL_chat may be identifiable. Direct is not anonymous.", TransportKind::Tor => "TOR / ONION TRANSPORT. Peer IPs are hidden by onion transport. Tor use may be observable locally; sufficiently powerful observers may correlate traffic. No exit peers, DHT or Direct fallback." }).await;
                if self.config.mode == TransportKind::Tor {
                    #[cfg(feature = "tor-arti-experimental")]
                    if self.arti.is_some() {
                        self.notice("Backend: EXPERIMENTAL ARTI 0.47.0; isolated client per lobby. Lobby service keys/state/replay filters stay in RAM. Normal Tor guards/cache persist; shared relay maintenance may continue until process exit.").await;
                    } else {
                        self.notice("Backend: external Tor. SOCKS isolation is requested per lobby; configure IsolateSOCKSAuth explicitly.").await;
                    }
                    #[cfg(not(feature = "tor-arti-experimental"))]
                    self.notice("Backend: external Tor. SOCKS isolation is requested per lobby; configure IsolateSOCKSAuth explicitly.").await;
                }
                self.notice("RAM-only by default. Per-lobby identity, durable outbox and peer mailbox storage require explicit opt-in to an encrypted vault. Trust stays in RAM. No professional security audit completed. Authorized recipients can read messages; terminal scrollback and compromised endpoints are outside this boundary.").await;
                if let Some(vault) = &self.config.vault {
                    match vault.memory_status() {
                        Ok(status)=>self.notice(format!("Encrypted vault key memory lock: {status:?}; Noise internals and storage temporaries are not all locked")).await,
                        Err(_)=>self.notice("Encrypted vault state unavailable").await,
                    }
                }
                if let Some(room) = room {
                    self.notice(format!(
                        "{} | peers: {} | identity memory locks: {:?} | persistent identity: {} | durable sending: {} | mailbox: {} | private administrator: {} | lobby scoped",
                        room.status, room.peers, room.memory, room.persistent, room.durable, room.mailbox,room.administrator
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
            AppCommand::PersistIdentity(on) => self.send(
                self.current.ok_or("Join a lobby first")?,
                room::Command::Persist(on),
            )?,
            AppCommand::DurableDelivery(on) => self.send(
                self.current.ok_or("Join a lobby first")?,
                room::Command::Durable(on),
            )?,
            AppCommand::Mailbox(on) => self.send(
                self.current.ok_or("Join a lobby first")?,
                room::Command::Mailbox(on),
            )?,
            AppCommand::SyncMailbox => self.send(
                self.current.ok_or("Join a lobby first")?,
                room::Command::Sync,
            )?,
            AppCommand::RotatePrivate(exclude) => self.send(
                self.current.ok_or("Join a lobby first")?,
                room::Command::Rotate(exclude),
            )?,
            AppCommand::OrganizationTrust(issuer) => self.send(
                self.current.ok_or("Join a lobby first")?,
                room::Command::OrgTrust(issuer),
            )?,
            AppCommand::OrganizationRequest(path) => self.send(
                self.current.ok_or("Join a lobby first")?,
                room::Command::OrgRequest(path),
            )?,
            AppCommand::OrganizationImport(path) => self.send(
                self.current.ok_or("Join a lobby first")?,
                room::Command::OrgImport(path),
            )?,
            AppCommand::StoredLobbies => {
                let vault = self
                    .config
                    .vault
                    .clone()
                    .ok_or("Open an encrypted --vault first")?;
                let profiles = tokio::task::spawn_blocking(move || vault.profiles())
                    .await
                    .map_err(|_| "Vault worker failed")?
                    .map_err(|_| "Vault unavailable")?;
                for (index, (_, name)) in profiles.iter().enumerate() {
                    self.notice(format!("{}: {}", index + 1, name)).await;
                }
                if profiles.is_empty() {
                    self.notice("No saved lobby identities").await;
                }
            }
            AppCommand::ResumeLobby(index) => {
                let vault = self
                    .config
                    .vault
                    .clone()
                    .ok_or("Open an encrypted --vault first")?;
                let (card, name) = tokio::task::spawn_blocking(move || {
                    let profiles = vault.profiles()?;
                    let (id, name) = profiles.get(index).ok_or(nulllobby_store::Error::Missing)?;
                    Ok::<_, nulllobby_store::Error>((vault.card(*id)?, name.clone()))
                })
                .await
                .map_err(|_| "Vault worker failed")?
                .map_err(|_| "Stored lobby unavailable")?;
                self.open(
                    LobbyName::new(&name).map_err(|_| "Invalid stored name")?,
                    card.kind(),
                    Some(card),
                )
                .await?;
            }
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
            room::Event::PrepareRotation { old, name } => {
                let listen = self.config.direct.listen;
                self.config.direct.listen.set_port(0);
                let result = self.open(name, LobbyKind::Private, None).await;
                self.config.direct.listen = listen;
                match result {
                    Ok(()) => {
                        if let Some(id) = self.current {
                            let _ = self.send(id, room::Command::RotationExport(old));
                        }
                    }
                    Err(error) => {
                        let _ = self.send(old, room::Command::RotationFailed);
                        self.notice(error).await;
                    }
                }
            }
            room::Event::RotationReady { old, card } => {
                if let Err(error) = self.send(old, room::Command::RotationReady(card)) {
                    self.notice(error).await;
                }
            }
            room::Event::FollowRotation { old, card } => {
                let _ = self.send(old, room::Command::Stop);
                let listen = self.config.direct.listen;
                self.config.direct.listen.set_port(0);
                let result = self
                    .open(
                        LobbyName::new("Joining lobby").expect("valid"),
                        LobbyKind::Private,
                        Some(card),
                    )
                    .await;
                self.config.direct.listen = listen;
                if let Err(error) = result {
                    self.notice(error).await;
                    self.notice("Rotation join failed; old capability remains retired. Obtain a fresh invite. No transport fallback.").await;
                }
            }
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
