use nulllobby_app::{App, Config};
use nulllobby_core::{
    LobbyCard, LobbyId,
    domain::{AppCommand, AppEvent, LobbyName, LobbyView, Nickname},
    text::ValidatedText,
};
use nulllobby_transport::{
    Endpoint, ModePolicy, NetworkAction, NetworkObserver, TransportError, TransportKind,
};
use secrecy::ExposeSecret;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;

#[path = "../../../tests/support/dht.rs"]
mod dht;

#[tokio::test]
async fn discovery_progress_reaches_views_before_the_round_finishes() {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let fixture = dht::Fixture::start_with_announcement_gate(gate.clone()).await;
    let mut client = Client::start(Config {
        discovery_bootstrap: Some(vec![fixture.bootstrap]),
        ..Default::default()
    });
    client
        .send(AppCommand::CreatePublicLobby(
            LobbyName::new("live discovery").unwrap(),
        ))
        .await;
    let querying = tokio::time::timeout(
        Duration::from_secs(1),
        client.view(|l| {
            l.network.discovery == nulllobby_core::domain::DiscoveryState::Querying
                && l.network.tokens == 1
        }),
    )
    .await
    .expect("live view must arrive before the held announcement times out");
    assert_eq!(querying.network.queries, 2);
    assert_eq!(querying.network.replies, 2);
    assert_eq!(querying.network.announces, 0);
    assert_eq!(querying.peers, 0);
    assert_eq!(
        fixture.announces.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    gate.add_permits(1);
    let ready = client
        .view(|l| l.network.discovery == nulllobby_core::domain::DiscoveryState::Ready)
        .await;
    assert_eq!(ready.network.announces, 1);
    assert_eq!(
        ready.peers, 0,
        "ready discovery does not establish an encrypted peer session"
    );
    client.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_listeners_seedless_invite_discovery_and_encrypted_chat() {
    let fixture = dht::Fixture::start().await;
    let cfg = Config {
        discovery_bootstrap: Some(vec![fixture.bootstrap]),
        ..Default::default()
    };
    assert!(cfg.peers.is_empty());
    assert!(!cfg.no_dht);
    assert!(cfg.direct.listen.ip().is_unspecified());
    assert_eq!(cfg.direct.listen.port(), 0);
    let mut creator = Client::start(cfg.clone());
    creator
        .send(AppCommand::SetNickname(Nickname::new("creator").unwrap()))
        .await;
    creator
        .send(AppCommand::CreatePublicLobby(
            LobbyName::new("default workflow").unwrap(),
        ))
        .await;
    let a = creator.view(|l| l.network.announces > 0).await;
    let card = creator.card().await;
    assert!(
        card.seeds().is_empty(),
        "default wildcard listener must not enter invite"
    );
    let mut joiner = Client::start(cfg);
    joiner
        .send(AppCommand::SetNickname(Nickname::new("joiner").unwrap()))
        .await;
    joiner.send(AppCommand::JoinLobby(card)).await;
    let b = joiner
        .view(|l| l.peers == 1 && l.members.len() == 2 && l.name == "default workflow")
        .await;
    assert_eq!(a.id, b.id);
    assert_ne!(a.fingerprint, b.fingerprint);
    joiner
        .send(AppCommand::SendMessage {
            lobby: b.id,
            body: ValidatedText::new("default invite chat").unwrap(),
        })
        .await;
    let (id, sender) = creator.message("default invite chat").await;
    assert_eq!(id, b.id);
    assert_eq!(sender, b.fingerprint);
    assert!(fixture.announces.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    joiner.stop().await;
    creator.stop().await;
}

#[tokio::test]
async fn configured_peer_is_retried_after_initial_connection_failure() {
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let card = LobbyCard::public(TransportKind::Direct, vec![]).unwrap();
    let other_card = LobbyCard::parse(card.export().expose_secret()).unwrap();
    let mut caller_config = config();
    caller_config.peers.push(Endpoint::Direct {
        address: address.ip(),
        port: address.port().try_into().unwrap(),
    });
    let mut caller = Client::start(caller_config);
    caller.send(AppCommand::JoinLobby(card)).await;
    let failed = caller.view(|l| l.network.failed_connections > 0).await;
    assert_eq!(failed.peers, 0);
    assert_eq!(
        failed.network.discovery,
        nulllobby_core::domain::DiscoveryState::Disabled
    );
    assert_eq!(
        failed.network.last_failure,
        Some("Transport connect or peer handshake failed")
    );
    let mut server_config = config();
    server_config.direct.listen = address;
    let mut server = Client::start(server_config);
    server.send(AppCommand::JoinLobby(other_card)).await;
    server.view(|l| !l.members.is_empty()).await;
    caller.send(AppCommand::Reconnect).await;
    caller.view(|l| l.peers == 1).await;
    caller.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn unavailable_dht_is_visible_in_network_inspection() {
    let reserved = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let std::net::SocketAddr::V4(seed) = reserved.local_addr().unwrap() else {
        unreachable!()
    };
    // Bound socket intentionally never replies, so the request times out.
    let mut client = Client::start(Config {
        discovery_bootstrap: Some(vec![seed]),
        ..Default::default()
    });
    client
        .send(AppCommand::CreatePublicLobby(
            LobbyName::new("discovery failure").unwrap(),
        ))
        .await;
    let view = client
        .view(|l| l.network.discovery == nulllobby_core::domain::DiscoveryState::Unavailable)
        .await;
    assert_eq!(view.network.queries, 1);
    assert_eq!(view.network.replies, 0);
    assert_eq!(view.network.announces, 0);
    client
        .send(AppCommand::Inspect(
            nulllobby_core::domain::Inspection::Network,
        ))
        .await;
    loop {
        if let AppEvent::Notice { text, .. } = client.event().await
            && text.contains("DHT: Unavailable")
        {
            assert!(text.contains("0 announcements"));
            break;
        }
    }
    client.stop().await;
}

struct Client {
    deadline: tokio::time::Instant,
    tx: mpsc::Sender<AppCommand>,
    rx: mpsc::Receiver<AppEvent>,
    task: tokio::task::JoinHandle<()>,
}
impl Client {
    fn start(config: Config) -> Self {
        let (tx, cmd) = nulllobby_transport::command_channel();
        let (ev, rx) = nulllobby_transport::event_channel();
        let task = tokio::spawn(App::new(config, cmd, ev).run());
        Self {
            tx,
            rx,
            task,
            deadline: tokio::time::Instant::now() + Duration::from_secs(90),
        }
    }
    async fn send(&self, command: AppCommand) {
        self.tx.send(command).await.unwrap();
    }
    async fn event(&mut self) -> AppEvent {
        tokio::time::timeout_at(
            self.deadline
                .min(tokio::time::Instant::now() + Duration::from_secs(15)),
            self.rx.recv(),
        )
        .await
        .expect("event deadline")
        .expect("runtime alive")
    }
    async fn view(&mut self, ready: impl Fn(&LobbyView) -> bool) -> LobbyView {
        loop {
            if let AppEvent::View { lobbies, .. } = self.event().await
                && let Some(lobby) = lobbies.into_iter().find(|l| ready(l))
            {
                return lobby;
            }
        }
    }
    async fn card(&mut self) -> LobbyCard {
        self.send(AppCommand::ExportInvite).await;
        loop {
            if let AppEvent::Invite(card) = self.event().await {
                return LobbyCard::parse(card.expose_secret()).unwrap();
            }
        }
    }
    async fn message(&mut self, text: &str) -> (LobbyId, nulllobby_core::Fingerprint) {
        loop {
            if let AppEvent::MessageReceived {
                lobby,
                body,
                fingerprint,
                ..
            } = self.event().await
                && body == text
            {
                return (lobby, fingerprint);
            }
        }
    }
    async fn stop(mut self) {
        self.send(AppCommand::Shutdown).await;
        loop {
            if matches!(self.event().await, AppEvent::ShutdownComplete) {
                break;
            }
        }
        self.task.await.unwrap();
    }
}
fn config() -> Config {
    Config {
        direct: nulllobby_app::DirectOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        no_dht: true,
        ..Config::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_peer_private_signed_gossip_verification_and_cleanup() {
    let mut alice = Client::start(config());
    alice
        .send(AppCommand::SetNickname(Nickname::new("alice").unwrap()))
        .await;
    alice
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("test lobby").unwrap(),
        ))
        .await;
    let a = alice.view(|l| !l.members.is_empty()).await;
    let card = alice.card().await;
    let mut bob = Client::start(config());
    bob.send(AppCommand::SetNickname(Nickname::new("bob").unwrap()))
        .await;
    bob.send(AppCommand::JoinLobby(card)).await;
    bob.view(|l| l.peers == 1 && l.members.len() >= 2).await;
    let mut card = bob.card().await;
    // The third member connects only to Bob, exercising signed forwarding.
    assert_eq!(card.seeds().len(), 1);
    let b_seed = card.seeds()[0].clone();
    card.set_seeds(vec![b_seed.clone()]).unwrap();
    let mut charlie = Client::start(config());
    charlie.send(AppCommand::JoinLobby(card)).await;
    charlie.view(|l| l.peers == 1 && l.members.len() >= 3).await;
    alice
        .send(AppCommand::SendMessage {
            lobby: a.id,
            body: ValidatedText::new("signed gossip canary").unwrap(),
        })
        .await;
    let (id, fingerprint) = charlie.message("signed gossip canary").await;
    assert_eq!(id, a.id);
    assert_eq!(fingerprint, a.fingerprint);
    charlie
        .send(AppCommand::VerifyPeer {
            lobby: id,
            fingerprint,
        })
        .await;
    charlie
        .view(|l| {
            l.members
                .iter()
                .any(|m| m.fingerprint == fingerprint && m.verified)
        })
        .await;
    charlie
        .send(AppCommand::CreatePublicLobby(
            LobbyName::new("other lobby").unwrap(),
        ))
        .await;
    let other = charlie.view(|l| l.id != id && !l.members.is_empty()).await;
    assert_ne!(other.fingerprint, a.fingerprint);
    assert!(
        !other
            .members
            .iter()
            .any(|m| m.fingerprint == fingerprint && m.verified)
    );
    charlie.stop().await;
    bob.stop().await;
    alice.stop().await;
    let Endpoint::Direct { address, port } = b_seed else {
        panic!("direct fixture")
    };
    assert!(
        tokio::net::TcpStream::connect((address, port.get()))
            .await
            .is_err()
    );
}
struct TorOnly(Mutex<Vec<NetworkAction>>);
impl NetworkObserver for TorOnly {
    fn before_network_action(&self, action: NetworkAction) -> Result<(), TransportError> {
        self.0.lock().unwrap().push(action);
        assert!(
            matches!(
                action,
                NetworkAction::LocalTorControl | NetworkAction::LocalTorSocks
            ),
            "forbidden Tor network operation"
        );
        ModePolicy(TransportKind::Tor).before_network_action(action)
    }
}
#[tokio::test]
async fn unavailable_tor_does_not_start_direct_dht_or_dns() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = listener.local_addr().unwrap();
    drop(listener);
    let mut cfg = config();
    cfg.mode = TransportKind::Tor;
    cfg.no_dht = false;
    cfg.tor.control = closed;
    cfg.tor.cookie = Some("unused-cookie-path".into());
    let observer = Arc::new(TorOnly(Mutex::new(vec![])));
    let (tx, rx) = nulllobby_transport::command_channel();
    let (events, mut ev) = nulllobby_transport::event_channel();
    let app = tokio::spawn(
        App::new(cfg, rx, events)
            .with_observer(observer.clone())
            .run(),
    );
    tx.send(AppCommand::CreatePublicLobby(
        LobbyName::new("tor only").unwrap(),
    ))
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(AppEvent::Notice { text, .. }) = ev.recv().await
                && text.starts_with("Transport unavailable")
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        *observer.0.lock().unwrap(),
        vec![NetworkAction::LocalTorControl]
    );
    tx.send(AppCommand::Shutdown).await.unwrap();
    app.await.unwrap();
}

#[test]
fn direct_runtime_operates_with_unwritable_home() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "three_peer_private_signed_gossip_verification_and_cleanup",
        ])
        .env("HOME", "/proc")
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "isolated Direct runtime regression failed"
    );
}

#[path = "../../nulllobby-tor/tests/support/mod.rs"]
mod tor_fixture;
#[tokio::test]
async fn successful_tor_lobbies_keep_endpoints_scoped_and_never_use_direct() {
    let fixture = tor_fixture::Fixture::start().await;
    let audit = Arc::new(TorOnly(Mutex::new(vec![])));
    let start = || {
        let cfg = Config {
            mode: TransportKind::Tor,
            tor: fixture.config.clone(),
            no_dht: false,
            discovery_bootstrap: Some(vec!["127.0.0.1:9".parse().unwrap()]),
            ..Config::default()
        };
        let (tx, commands) = nulllobby_transport::command_channel();
        let (events, rx) = nulllobby_transport::event_channel();
        let task = tokio::spawn(
            App::new(cfg, commands, events)
                .with_observer(audit.clone())
                .run(),
        );
        Client {
            tx,
            rx,
            task,
            deadline: tokio::time::Instant::now() + Duration::from_secs(90),
        }
    };
    let mut alice = start();
    alice
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("Tor A").unwrap(),
        ))
        .await;
    let first = alice.view(|l| l.name == "Tor A").await;
    let card_a = alice.card().await;
    let first_endpoint = card_a.seeds()[0].clone();
    alice
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("Tor B").unwrap(),
        ))
        .await;
    let second = alice.view(|l| l.name == "Tor B").await;
    let card_b = alice.card().await;
    assert_ne!(first.fingerprint, second.fingerprint);
    assert!(!card_b.seeds().contains(&first_endpoint));
    let second_endpoint = card_b.seeds()[0].clone();
    let mut bob = start();
    bob.send(AppCommand::JoinLobby(card_a)).await;
    bob.view(|l| l.peers >= 1 && l.members.len() >= 2).await;
    let bob_card = bob.card().await;
    assert!(!bob_card.seeds().contains(&second_endpoint));
    alice
        .send(AppCommand::SendMessage {
            lobby: first.id,
            body: ValidatedText::new("synthetic Tor runtime gossip").unwrap(),
        })
        .await;
    assert_eq!(
        bob.message("synthetic Tor runtime gossip").await.1,
        first.fingerprint
    );
    bob.stop().await;
    alice.stop().await;
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.created, 3);
    assert_eq!(state.deleted, 3);
    assert!(state.routes.is_empty());
    assert!(!state.detached);
    assert!(audit.0.lock().unwrap().iter().all(|a| matches!(
        a,
        NetworkAction::LocalTorControl | NetworkAction::LocalTorSocks
    )));
}

#[tokio::test]
async fn authenticated_peer_flood_is_disconnected_and_app_remains_responsive() {
    use nulllobby_core::{
        EphemeralIdentity, domain::PaddingPolicy, message::Packet, session::SecureSession,
    };
    use nulllobby_direct::DirectTransport;
    use nulllobby_transport::Transport;
    let mut app = Client::start(config());
    app.send(AppCommand::CreatePrivateLobby(
        LobbyName::new("bounded peer test").unwrap(),
    ))
    .await;
    let lobby = app.view(|l| !l.members.is_empty()).await;
    let card = app.card().await;
    let mut transport = DirectTransport::new(
        config().direct,
        Arc::new(ModePolicy(TransportKind::Direct)),
        Arc::new(tokio::sync::Semaphore::new(128)),
    );
    transport.start().await.unwrap();
    let local = transport
        .create_endpoint(card.discovery_scope().unwrap())
        .await
        .unwrap();
    let stream = transport.connect(local, &card.seeds()[0]).await.unwrap();
    let identity = EphemeralIdentity::generate(card.lobby_id()).unwrap();
    let keys = card.private_keys().unwrap().unwrap();
    let session = SecureSession::establish(stream, &identity, Some(&keys.noise_psk), true)
        .await
        .unwrap();
    let (mut reader, mut writer) = session.split();
    writer
        .send(&Packet::Hello.encode().unwrap(), PaddingPolicy::None)
        .await
        .unwrap();
    assert!(matches!(
        Packet::decode(&reader.receive().await.unwrap()),
        Ok(Packet::Hello)
    ));
    app.view(|l| l.peers == 1).await;
    // An authenticated recipient can send hostile traffic. Flood without reading
    // responses: the rate/queue bounds must close it rather than grow forever.
    for nonce in 0..256 {
        if writer
            .send(&Packet::Ping(nonce).encode().unwrap(), PaddingPolicy::None)
            .await
            .is_err()
        {
            break;
        }
    }
    app.view(|l| l.id == lobby.id && l.peers == 0).await;
    app.send(AppCommand::CreatePublicLobby(
        LobbyName::new("still responsive").unwrap(),
    ))
    .await;
    app.view(|l| l.name == "still responsive").await;
    transport.stop().await.unwrap();
    app.stop().await;
}

#[path = "support/v050.rs"]
mod v050;
