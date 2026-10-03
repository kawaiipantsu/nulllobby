use crate::Config;
use nulllobby_core::{
    EphemeralIdentity, Fingerprint, LobbyCard, LobbyId,
    domain::{AppEvent, LobbyName, LobbyTrust, LobbyView, MemberView, Nickname, PaddingPolicy},
    message::{Packet, Payload, SignedMessage},
    replay::ReplayGuard,
    secret::PrivateLobbyKeys,
    session::SecureSession,
};
use nulllobby_transport::{
    Endpoint, EndpointHandle, NetworkObserver, NetworkStatus, Transport, TransportKind,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc,
    task::{AbortHandle, JoinSet},
};
use zeroize::Zeroizing;

pub(crate) enum Command {
    Send(Payload),
    Nick(Nickname),
    Trust(Fingerprint, bool),
    Invite,
    Padding(PaddingPolicy),
    Reconnect,
    Stop,
}
pub(crate) enum Event {
    View(LobbyView),
    Ui(AppEvent),
    Stopped(LobbyId),
}
struct Connection {
    key: [u8; 32],
    reader: nulllobby_core::session::SecureReader,
    writer: nulllobby_core::session::SecureWriter,
}
enum Net {
    Connected {
        session: Connection,
        outbound: bool,
        endpoint: Option<Endpoint>,
    },
    Failed(Option<Endpoint>),
    Packet([u8; 32], u64, Packet),
    Closed([u8; 32], u64),
    Discovered(Vec<Endpoint>),
}
struct Peer {
    tx: mpsc::Sender<Packet>,
    task: AbortHandle,
    generation: u64,
    outbound: bool,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Member {
    join: SignedMessage,
    seen: Instant,
}
pub(crate) struct Room {
    card: LobbyCard,
    identity: Arc<EphemeralIdentity>,
    keys: Option<Arc<PrivateLobbyKeys>>,
    transport: Arc<dyn Transport>,
    local: EndpointHandle,
    name: LobbyName,
    nickname: Nickname,
    padding: PaddingPolicy,
    config: Config,
    observer: Arc<dyn NetworkObserver>,
    tx: mpsc::Sender<Event>,
    net_tx: mpsc::Sender<Net>,
    net_rx: mpsc::Receiver<Net>,
    commands: mpsc::Receiver<Command>,
    tasks: JoinSet<()>,
    peers: HashMap<[u8; 32], Peer>,
    members: HashMap<[u8; 32], Member>,
    ads: nulllobby_core::endpoint::EndpointBook,
    presence_sequences: HashMap<[u8; 32], u64>,
    replay: ReplayGuard,
    trust: LobbyTrust,
    sequence: u64,
    generation: u64,
    dialing: Vec<Endpoint>,
    seeds: Vec<Endpoint>,
    own: Endpoint,
    status: String,
}
pub(crate) struct Start {
    pub card: LobbyCard,
    pub name: LobbyName,
    pub nickname: Nickname,
    pub padding: PaddingPolicy,
    pub transport: Box<dyn Transport>,
    pub local: EndpointHandle,
    pub config: Config,
    pub observer: Arc<dyn NetworkObserver>,
}
impl Room {
    pub fn new(
        start: Start,
        tx: mpsc::Sender<Event>,
        commands: mpsc::Receiver<Command>,
    ) -> Result<Self, &'static str> {
        let Start {
            card,
            name,
            nickname,
            padding,
            transport,
            local,
            config,
            observer,
        } = start;
        let id = card.lobby_id();
        let identity =
            Arc::new(EphemeralIdentity::generate(id).map_err(|_| "Identity generation failed")?);
        let own = transport
            .local_transport_identity(local)
            .map_err(|_| "Endpoint unavailable")?;
        let keys = card
            .private_keys()
            .map_err(|_| "Capability derivation failed")?
            .map(Arc::new);
        let seeds = card.seeds().to_vec();
        let (net_tx, net_rx) = mpsc::channel(128);
        Ok(Self {
            card,
            identity,
            keys,
            transport: Arc::from(transport),
            local,
            name,
            nickname,
            padding,
            config,
            observer,
            tx,
            net_tx,
            net_rx,
            commands,
            tasks: JoinSet::new(),
            peers: HashMap::new(),
            members: HashMap::new(),
            ads: nulllobby_core::endpoint::EndpointBook::new(id),
            presence_sequences: HashMap::new(),
            replay: ReplayGuard::new(id),
            trust: LobbyTrust::new(id),
            sequence: 0,
            generation: 0,
            dialing: vec![],
            seeds,
            own,
            status: "Listening; encrypted sessions required".to_owned(),
        })
    }
    async fn ui(&self, event: AppEvent) {
        let _ = self.tx.send(Event::Ui(event)).await;
    }
    async fn notice(&self, text: impl Into<String>) {
        self.ui(AppEvent::Notice {
            lobby: Some(self.card.lobby_id()),
            text: text.into(),
        })
        .await;
    }
    async fn view(&self) {
        let members = self
            .members
            .iter()
            .filter_map(|(key, member)| {
                let Payload::Join { nickname, .. } = member.join.payload() else {
                    return None;
                };
                let fingerprint = Fingerprint::of_public_key(key);
                Some(MemberView {
                    nickname: nickname.as_str().to_owned(),
                    fingerprint,
                    verified: self.trust.is_verified(self.card.lobby_id(), &fingerprint),
                })
            })
            .collect();
        let _ = self
            .tx
            .send(Event::View(LobbyView {
                id: self.card.lobby_id(),
                name: self.name.as_str().to_owned(),
                kind: self.card.kind(),
                peers: self.peers.len(),
                members,
                fingerprint: self.identity.fingerprint(),
                memory: self.identity.memory_status(),
                status: self.status.clone(),
            }))
            .await;
    }
    fn spawn_acceptors(&mut self) {
        for _ in 0..4 {
            let transport = self.transport.clone();
            let identity = self.identity.clone();
            let keys = self.keys.clone();
            let tx = self.net_tx.clone();
            let local = self.local;
            self.tasks.spawn(async move {
                loop {
                    match transport.accept(local).await {
                        Ok(stream) => {
                            let session =
                                authenticate(stream, &identity, keys.as_deref(), false).await;
                            if let Ok(session) = session
                                && tx
                                    .send(Net::Connected {
                                        session,
                                        outbound: false,
                                        endpoint: None,
                                    })
                                    .await
                                    .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => {
                            if transport.network_status() != NetworkStatus::Ready {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
            });
        }
    }
    fn dial(&mut self, endpoint: Endpoint) {
        if endpoint == self.own
            || endpoint.transport() != self.card.transport()
            || self.dialing.contains(&endpoint)
            || self.dialing.len() >= 8
            || self.peers.len() >= 16
        {
            return;
        }
        self.dialing.push(endpoint.clone());
        let transport = self.transport.clone();
        let identity = self.identity.clone();
        let keys = self.keys.clone();
        let tx = self.net_tx.clone();
        let local = self.local;
        self.tasks.spawn(async move {
            let result = async {
                let stream = transport.connect(local, &endpoint).await.map_err(|_| ())?;
                authenticate(stream, &identity, keys.as_deref(), true).await
            }
            .await;
            let event = match result {
                Ok(session) => Net::Connected {
                    session,
                    outbound: true,
                    endpoint: Some(endpoint),
                },
                Err(()) => Net::Failed(Some(endpoint)),
            };
            let _ = tx.send(event).await;
        });
    }
    fn discovery(&mut self) {
        if self.card.transport() != TransportKind::Direct || self.config.no_dht {
            return;
        }
        let Endpoint::Direct { port, .. } = self.own else {
            return;
        };
        let Ok(scope) = self.card.discovery_scope() else {
            return;
        };
        let observer = self.observer.clone();
        let tx = self.net_tx.clone();
        self.tasks.spawn(async move {
            let Ok(mut discovery) =
                nulllobby_direct::discovery::Discovery::start(observer, None).await
            else {
                let _ = tx.send(Net::Failed(None)).await;
                return;
            };
            loop {
                match discovery.discover_and_announce(scope, port).await {
                    Ok(peers) => {
                        if tx.send(Net::Discovered(peers)).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = tx.send(Net::Failed(None)).await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(120)).await;
            }
        });
    }
    fn broadcast(&mut self, packet: Packet, except: Option<[u8; 32]>) {
        self.peers
            .retain(|key, peer| Some(*key) == except || peer.tx.try_send(packet.clone()).is_ok());
    }
    fn new_presence(&mut self, sender: [u8; 32], sequence: u64) -> bool {
        if self
            .presence_sequences
            .get(&sender)
            .is_some_and(|previous| *previous >= sequence)
        {
            return false;
        }
        if self.presence_sequences.len() >= 64 && !self.presence_sequences.contains_key(&sender) {
            return false;
        }
        self.presence_sequences.insert(sender, sequence);
        true
    }
    async fn local(&mut self, payload: Payload) -> Result<(), ()> {
        self.sequence = self.sequence.checked_add(1).ok_or(())?;
        let message = SignedMessage::new(&self.identity, self.sequence, payload).map_err(|_| ())?;
        self.receive(message, None).await
    }
    async fn receive(&mut self, message: SignedMessage, via: Option<[u8; 32]>) -> Result<(), ()> {
        if matches!(message.payload(), Payload::Endpoint { .. })
            && self.card.transport() != TransportKind::Tor
        {
            return Err(());
        }
        if !self
            .replay
            .accept(&message, Instant::now())
            .map_err(|_| ())?
        {
            return Ok(());
        }
        let sender = *message.sender();
        let fingerprint = Fingerprint::of_public_key(&sender);
        match message.payload() {
            Payload::Join { nickname: _, name } => {
                if !self.new_presence(sender, message.sequence()) {
                    return Ok(());
                }
                if self.members.len() >= 64 && !self.members.contains_key(&sender) {
                    return Err(());
                }
                if self.name.as_str() == "Joining lobby" {
                    self.name = name.clone();
                }
                self.members.insert(
                    sender,
                    Member {
                        join: message.clone(),
                        seen: Instant::now(),
                    },
                );
            }
            Payload::Chat(body) => {
                let nickname = self
                    .members
                    .get(&sender)
                    .and_then(|m| match m.join.payload() {
                        Payload::Join { nickname, .. } => Some(nickname.as_str()),
                        _ => None,
                    })
                    .unwrap_or("unknown")
                    .to_owned();
                self.ui(AppEvent::MessageReceived {
                    lobby: self.card.lobby_id(),
                    fingerprint,
                    nickname,
                    body: body.as_str().to_owned(),
                    verified: self.trust.is_verified(self.card.lobby_id(), &fingerprint),
                })
                .await;
            }
            Payload::Leave => {
                if !self.new_presence(sender, message.sequence()) {
                    return Ok(());
                }
                self.members.remove(&sender);
                self.ads.remove(&sender);
            }
            Payload::Endpoint {
                service_key,
                port,
                expires,
            } => {
                if self
                    .ads
                    .accept(message.clone(), unix_time())
                    .map_err(|_| ())?
                    && via.is_some()
                    && self.peers.len() < 8
                {
                    self.dial(Endpoint::Onion {
                        service_key: *service_key,
                        port: std::num::NonZeroU16::new(*port).ok_or(())?,
                    });
                }
                let _ = expires;
            }
        }
        self.broadcast(Packet::Signed(message), via);
        self.view().await;
        Ok(())
    }
    async fn advertise(&mut self) -> Result<(), ()> {
        self.local(Payload::Join {
            nickname: self.nickname.clone(),
            name: self.name.clone(),
        })
        .await?;
        if let Endpoint::Onion { service_key, port } = self.own {
            self.local(Payload::Endpoint {
                service_key,
                port: port.get(),
                expires: unix_time().saturating_add(300),
            })
            .await?;
        }
        Ok(())
    }
    async fn connected(&mut self, session: Connection, outbound: bool) {
        let key = session.key;
        let preferred = self.identity.public_key() < key;
        if let Some(peer) = self.peers.get(&key)
            && (peer.outbound == preferred || outbound != preferred)
        {
            return;
        }
        if !self.peers.contains_key(&key) && self.peers.len() >= 64 {
            return;
        }
        let Some(generation) = self.generation.checked_add(1) else {
            return;
        };
        self.generation = generation;
        let (tx, rx) = mpsc::channel(32);
        let mut bootstrap = Vec::new();
        if let Some(ours) = self.members.get(&self.identity.public_key()) {
            bootstrap.push(Packet::Signed(ours.join.clone()));
        }
        for (sender, member) in &self.members {
            if sender != &self.identity.public_key() && bootstrap.len() < 17 {
                bootstrap.push(Packet::Signed(member.join.clone()));
            }
        }
        let ads: Vec<_> = self.ads.values().take(8).cloned().collect();
        if !ads.is_empty() {
            bootstrap.push(Packet::EndpointList(ads));
        }
        for packet in bootstrap {
            if tx.try_send(packet).is_err() {
                return;
            }
        }
        let task = self.tasks.spawn(peer_loop(
            session,
            rx,
            self.net_tx.clone(),
            generation,
            self.padding,
        ));
        self.peers.insert(
            key,
            Peer {
                tx,
                task,
                generation,
                outbound,
            },
        );
        self.status = "Encrypted / identities require fingerprint verification".to_owned();
        self.view().await;
    }
    async fn invite(&mut self) {
        let mut seeds = Vec::new();
        match &self.own {
            Endpoint::Onion { .. } => seeds.push(self.own.clone()),
            Endpoint::Direct { address, .. } if !address.is_unspecified() => {
                seeds.push(self.own.clone())
            }
            _ => {}
        }
        if self.card.transport() == TransportKind::Tor {
            for ad in self.ads.values() {
                if let Payload::Endpoint {
                    service_key,
                    port,
                    expires,
                } = ad.payload()
                    && *expires > unix_time()
                    && let Some(port) = std::num::NonZeroU16::new(*port)
                {
                    let endpoint = Endpoint::Onion {
                        service_key: *service_key,
                        port,
                    };
                    if !seeds.contains(&endpoint) && seeds.len() < 8 {
                        seeds.push(endpoint);
                    }
                }
            }
        }
        if self.card.set_seeds(seeds).is_ok() {
            self.ui(AppEvent::Invite(self.card.export())).await;
        }
    }
    async fn handle_command(&mut self, command: Option<Command>) -> bool {
        match command {
            Some(Command::Send(payload)) => {
                if self.local(payload).await.is_err() {
                    self.notice("Message rejected by lobby resource limits")
                        .await;
                }
            }
            Some(Command::Nick(nick)) => {
                self.nickname = nick;
                let _ = self.advertise().await;
            }
            Some(Command::Trust(fp, verified)) => {
                if verified {
                    if self.trust.verify(fp).is_err() {
                        self.notice("Trust list limit reached").await;
                    }
                } else {
                    self.trust.unverify(&fp);
                }
                self.view().await;
            }
            Some(Command::Invite) => self.invite().await,
            Some(Command::Padding(padding)) => {
                self.padding = padding;
                self.peers.clear();
                self.notice("Padding updated; reconnecting peer sessions")
                    .await;
                self.reconnect();
            }
            Some(Command::Reconnect) => self.reconnect(),
            Some(Command::Stop) | None => {
                let _ = self.local(Payload::Leave).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
                return false;
            }
        }
        true
    }
    fn reconnect(&mut self) {
        for endpoint in self.seeds.clone() {
            self.dial(endpoint);
        }
        let endpoints: Vec<_> = self
            .ads
            .values()
            .filter_map(|ad| match ad.payload() {
                Payload::Endpoint {
                    service_key,
                    port,
                    expires,
                } if *expires > unix_time() => Some(Endpoint::Onion {
                    service_key: *service_key,
                    port: std::num::NonZeroU16::new(*port)?,
                }),
                _ => None,
            })
            .take(8)
            .collect();
        for endpoint in endpoints {
            self.dial(endpoint);
        }
    }
    async fn handle_network(&mut self, event: Net) {
        match event {
            Net::Connected {
                session,
                outbound,
                endpoint,
            } => {
                if let Some(endpoint) = endpoint {
                    self.dialing.retain(|e| *e != endpoint);
                }
                self.connected(session, outbound).await;
            }
            Net::Failed(endpoint) => {
                if let Some(endpoint) = endpoint {
                    self.dialing.retain(|e| *e != endpoint);
                } else {
                    self.notice("Direct DHT discovery unavailable; existing encrypted peer sessions remain usable").await;
                }
                if self.card.transport() == TransportKind::Tor
                    && self.peers.is_empty()
                    && self.dialing.is_empty()
                {
                    self.status = "No reachable Tor lobby seed".to_owned();
                    self.notice(self.status.clone()).await;
                    self.view().await;
                }
            }
            Net::Discovered(peers) => {
                for endpoint in peers {
                    if !self.seeds.contains(&endpoint) && self.seeds.len() < 64 {
                        self.seeds.push(endpoint.clone());
                    }
                    self.dial(endpoint);
                }
            }
            Net::Closed(key, generation) => {
                if self
                    .peers
                    .get(&key)
                    .is_some_and(|p| p.generation == generation)
                {
                    self.peers.remove(&key);
                    self.view().await;
                }
            }
            Net::Packet(key, generation, packet) => {
                if !self
                    .peers
                    .get(&key)
                    .is_some_and(|p| p.generation == generation)
                {
                    return;
                }
                let valid = match packet {
                    Packet::Signed(message) => self.receive(message, Some(key)).await.is_ok(),
                    Packet::EndpointList(ads) if self.card.transport() == TransportKind::Tor => {
                        let mut valid = true;
                        for ad in ads {
                            if self.receive(ad, Some(key)).await.is_err() {
                                valid = false;
                                break;
                            }
                        }
                        valid
                    }
                    Packet::Ping(nonce) => self
                        .peers
                        .get(&key)
                        .is_some_and(|p| p.tx.try_send(Packet::Pong(nonce)).is_ok()),
                    Packet::Pong(_) => true,
                    _ => false,
                };
                if !valid {
                    self.peers.remove(&key);
                    self.notice("Peer disconnected: invalid application record")
                        .await;
                    self.view().await;
                }
            }
        }
    }
    async fn tick(&mut self, heartbeat: u64) -> bool {
        if self.transport.network_status() != NetworkStatus::Ready {
            self.peers.clear();
            self.status = "Transport unavailable; lobby disconnected".to_owned();
            self.notice(self.status.clone()).await;
            self.view().await;
            return false;
        }
        self.broadcast(Packet::Ping(heartbeat), None);
        self.members.retain(|key, m| {
            *key == self.identity.public_key() || m.seen.elapsed() < Duration::from_secs(180)
        });
        self.ads.expire(unix_time());
        if heartbeat.is_multiple_of(2) {
            let _ = self.advertise().await;
        }
        if self.peers.len() < 8 {
            self.reconnect();
        }
        self.view().await;
        true
    }
    pub async fn run(mut self) {
        self.spawn_acceptors();
        self.discovery();
        if self.advertise().await.is_err() {
            self.notice("Lobby initialization failed").await;
        } else {
            for endpoint in self
                .seeds
                .clone()
                .into_iter()
                .chain(self.config.peers.clone())
            {
                self.dial(endpoint);
            }
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            tick.tick().await;
            let mut heartbeat = 0u64;
            loop {
                tokio::select! {
                    command = self.commands.recv() => { if !self.handle_command(command).await { break; } }
                    Some(event) = self.net_rx.recv() => self.handle_network(event).await,
                    _ = tick.tick() => {
                        heartbeat = heartbeat.wrapping_add(1);
                        if !self.tick(heartbeat).await { break; }
                    }
                    _ = self.tasks.join_next(), if !self.tasks.is_empty() => {}
                }
            }
        }
        self.peers.clear();
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        if let Some(transport) = Arc::get_mut(&mut self.transport) {
            let _ = transport.destroy_endpoint(self.local).await;
            let _ = transport.stop().await;
        }
        let _ = self.tx.send(Event::Stopped(self.card.lobby_id())).await;
    }
}
fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
async fn authenticate(
    stream: nulllobby_transport::BoxStream,
    identity: &EphemeralIdentity,
    keys: Option<&PrivateLobbyKeys>,
    initiator: bool,
) -> Result<Connection, ()> {
    let session = SecureSession::establish(stream, identity, keys.map(|k| &k.noise_psk), initiator)
        .await
        .map_err(|_| ())?;
    let key = session.peer_key();
    let (mut reader, mut writer) = session.split();
    // Hello is exchanged below the UI, after the encrypted identity proof.
    tokio::time::timeout(Duration::from_secs(5), async {
        writer
            .send(
                &Packet::Hello.encode().map_err(|_| ())?,
                PaddingPolicy::None,
            )
            .await
            .map_err(|_| ())?;
        if !matches!(
            Packet::decode(&reader.receive().await.map_err(|_| ())?),
            Ok(Packet::Hello)
        ) {
            return Err(());
        }
        Ok(())
    })
    .await
    .map_err(|_| ())??;
    Ok(Connection {
        key,
        reader,
        writer,
    })
}
async fn peer_loop(
    session: Connection,
    mut outgoing: mpsc::Receiver<Packet>,
    tx: mpsc::Sender<Net>,
    generation: u64,
    padding: PaddingPolicy,
) {
    let Connection {
        key,
        mut reader,
        mut writer,
    } = session;
    let read = async {
        let mut window = Instant::now();
        let mut count = 0usize;
        loop {
            let bytes = tokio::time::timeout(Duration::from_secs(120), reader.receive())
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if window.elapsed() >= Duration::from_secs(1) {
                window = Instant::now();
                count = 0;
            }
            let packet = Packet::decode(&bytes).map_err(|_| ())?;
            count += match &packet {
                Packet::EndpointList(ads) => ads.len().max(1),
                _ => 1,
            };
            if count > 64 {
                return Err::<(), ()>(());
            }
            tx.send(Net::Packet(key, generation, packet))
                .await
                .map_err(|_| ())?;
        }
    };
    let write = async {
        while let Some(packet) = outgoing.recv().await {
            let bytes = Zeroizing::new(packet.encode().map_err(|_| ())?);
            writer.send(&bytes, padding).await.map_err(|_| ())?;
        }
        Ok::<(), ()>(())
    };
    tokio::select! { _ = read => {}, _ = write => {} }
    let _ = tx.send(Net::Closed(key, generation)).await;
}
