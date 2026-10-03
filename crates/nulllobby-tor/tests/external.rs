//! Deterministic external Tor integration tests.
mod support;
use nulllobby_core::{
    EphemeralIdentity, LobbyId, PrivateLobbySecret, domain::PaddingPolicy, session::SecureSession,
};
use nulllobby_tor::TorTransport;
use nulllobby_transport::{
    Endpoint, ModePolicy, NetworkAction, NetworkObserver, NetworkStatus, Transport, TransportError,
    TransportKind,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use support::Fixture;
use tokio::sync::Semaphore;

#[derive(Default)]
struct Audit(Mutex<Vec<NetworkAction>>);
impl NetworkObserver for Audit {
    fn before_network_action(&self, action: NetworkAction) -> Result<(), TransportError> {
        assert!(matches!(
            action,
            NetworkAction::LocalTorSocks | NetworkAction::LocalTorControl
        ));
        self.0.lock().unwrap().push(action);
        ModePolicy(TransportKind::Tor).before_network_action(action)
    }
}
fn backend(fixture: &Fixture, audit: Arc<Audit>) -> TorTransport {
    TorTransport::new(
        fixture.config.clone(),
        audit,
        Arc::new(Semaphore::new(128)),
        Arc::new(Semaphore::new(32)),
    )
}

#[tokio::test]
async fn ephemeral_lobby_onions_safecookie_isolation_noise_and_explicit_cleanup() {
    let fixture = Fixture::start().await;
    let audit = Arc::new(Audit::default());
    let mut tor = backend(&fixture, audit.clone());
    tor.start().await.unwrap();
    assert!(tor.isolation_confirmed());
    let a = tor.create_endpoint([1; 32]).await.unwrap();
    let b = tor.create_endpoint([2; 32]).await.unwrap();
    let a_ep = tor.local_transport_identity(a).unwrap();
    let b_ep = tor.local_transport_identity(b).unwrap();
    assert_ne!(a_ep, b_ep);
    let pending = Arc::new(Semaphore::new(32));
    let mut other = TorTransport::new(
        fixture.config.clone(),
        audit,
        Arc::new(Semaphore::new(128)),
        pending.clone(),
    );
    other.start().await.unwrap();
    let c = other.create_endpoint([1; 32]).await.unwrap();
    assert_ne!(a, c);
    assert!(tor.local_transport_identity(c).is_err());
    assert!(other.local_transport_identity(a).is_err());
    let (out, incoming) = tokio::join!(other.connect(c, &a_ep), tor.accept(a));
    let secret = PrivateLobbySecret::generate().unwrap();
    let keys = secret.derive().unwrap();
    let identity_a = EphemeralIdentity::generate(keys.lobby_id).unwrap();
    let identity_c = EphemeralIdentity::generate(keys.lobby_id).unwrap();
    assert_eq!(pending.available_permits(), 31);
    let (left, right) = tokio::join!(
        SecureSession::establish(out.unwrap(), &identity_c, Some(&keys.noise_psk), true),
        SecureSession::establish(incoming.unwrap(), &identity_a, Some(&keys.noise_psk), false)
    );
    let (_, mut writer) = left.unwrap().split();
    let (mut reader, _) = right.unwrap().split();
    assert_eq!(pending.available_permits(), 32);
    writer
        .send(
            b"Tor also requires independent Noise",
            PaddingPolicy::Bucketed,
        )
        .await
        .unwrap();
    assert_eq!(
        &*reader.receive().await.unwrap(),
        b"Tor also requires independent Noise"
    );
    let (out, incoming) = tokio::join!(tor.connect(b, &a_ep), tor.accept(a));
    drop(out.unwrap());
    drop(incoming.unwrap());
    {
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.created, 3);
        assert!(!state.detached);
        assert_eq!(state.isolation.len(), 2);
        assert_ne!(state.isolation[0], state.isolation[1]);
    }
    tor.destroy_endpoint(a).await.unwrap();
    assert!(reader.receive().await.is_err());
    tor.stop().await.unwrap();
    other.stop().await.unwrap();
    assert_eq!(fixture.state.lock().unwrap().deleted, 3);
    assert!(fixture.state.lock().unwrap().routes.is_empty());
}
#[tokio::test]
async fn offline_seed_and_invalid_destination_fail_closed() {
    let fixture = Fixture::start().await;
    let audit = Arc::new(Audit::default());
    let mut tor = backend(&fixture, audit.clone());
    tor.start().await.unwrap();
    let local = tor.create_endpoint([0; 32]).await.unwrap();
    let unknown = Endpoint::Onion {
        service_key: [255; 32],
        port: 80.try_into().unwrap(),
    };
    assert!(tor.connect(local, &unknown).await.is_err());
    let direct = Endpoint::Direct {
        address: "127.0.0.1".parse().unwrap(),
        port: 80.try_into().unwrap(),
    };
    assert!(matches!(
        tor.connect(local, &direct).await,
        Err(TransportError::WrongTransport)
    ));
    fixture.control.abort();
    tokio::time::timeout(Duration::from_secs(22), async {
        while tor.network_status() == NetworkStatus::Ready {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert!(tor.connect(local, &unknown).await.is_err());
    assert!(audit.0.lock().unwrap().iter().all(|a| matches!(
        a,
        NetworkAction::LocalTorControl | NetworkAction::LocalTorSocks
    )));
    let _ = tor.stop().await;
}
#[tokio::test]
async fn remote_control_and_socks_addresses_are_rejected_before_network() {
    let fixture = Fixture::start().await;
    let audit = Arc::new(Audit::default());
    let mut config = fixture.config.clone();
    config.socks = "192.0.2.1:9050".parse().unwrap();
    let mut tor = TorTransport::new(
        config,
        audit.clone(),
        Arc::new(Semaphore::new(128)),
        Arc::new(Semaphore::new(32)),
    );
    assert_eq!(tor.start().await, Err(TransportError::WrongTransport));
    assert!(audit.0.lock().unwrap().is_empty());
    assert_ne!(
        EphemeralIdentity::generate(LobbyId::from_bytes([1; 32]))
            .unwrap()
            .public_key(),
        EphemeralIdentity::generate(LobbyId::from_bytes([1; 32]))
            .unwrap()
            .public_key()
    );
}
