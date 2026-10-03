#![cfg(feature = "tor-arti-experimental")]
use nulllobby_tor::arti::{ArtiConfig, ArtiPool, ArtiTransport};
use nulllobby_transport::{
    Endpoint, EndpointHandle, NetworkAction, NetworkObserver, NetworkStatus, Transport,
    TransportError,
};
use std::{
    num::NonZeroU16,
    sync::{Arc, Mutex},
};
use tokio::sync::Semaphore;

#[derive(Default)]
struct DenyNetwork(Mutex<Vec<NetworkAction>>);
impl NetworkObserver for DenyNetwork {
    fn before_network_action(&self, action: NetworkAction) -> Result<(), TransportError> {
        self.0.lock().unwrap().push(action);
        Err(TransportError::Unavailable)
    }
}
fn transport(observer: Arc<DenyNetwork>, state: &str) -> ArtiTransport {
    ArtiTransport::new(
        Arc::new(ArtiPool::new(ArtiConfig {
            state_dir: state.into(),
            cache_dir: "/unused/arti-cache".into(),
        })),
        observer,
        Arc::new(Semaphore::new(128)),
        Arc::new(Semaphore::new(32)),
    )
}
#[tokio::test]
async fn denied_bootstrap_and_direct_destination_have_no_fallback() {
    let observer = Arc::new(DenyNetwork::default());
    let mut transport = transport(observer.clone(), "/unused/arti-state");
    assert_eq!(transport.start().await, Err(TransportError::Unavailable));
    assert_eq!(transport.network_status(), NetworkStatus::Unavailable);
    assert!(transport.create_endpoint([1; 32]).await.is_err());
    let direct = Endpoint::Direct {
        address: "192.0.2.1".parse().unwrap(),
        port: NonZeroU16::new(443).unwrap(),
    };
    assert!(matches!(
        transport.connect(EndpointHandle(1), &direct).await,
        Err(TransportError::WrongTransport)
    ));
    assert!(transport.accept(EndpointHandle(1)).await.is_err());
    transport.stop().await.unwrap();
    assert_eq!(
        *observer.0.lock().unwrap(),
        vec![NetworkAction::EmbeddedTor]
    );
}
#[tokio::test]
async fn invalid_storage_configuration_fails_before_network() {
    let observer = Arc::new(DenyNetwork::default());
    let mut transport = transport(observer.clone(), "relative-state");
    assert!(transport.start().await.is_err());
    assert!(observer.0.lock().unwrap().is_empty());
}
#[test]
fn service_keys_are_independent_even_with_reused_local_nickname() {
    use tor_hsservice::{OnionService, config::OnionServiceConfigBuilder};
    let config = OnionServiceConfigBuilder::default()
        .nickname("same-local-name".parse().unwrap())
        .build()
        .unwrap();
    let make = || {
        let service = OnionService::new_ephemeral(config.clone()).unwrap();
        service
            .generate_identity_key(tor_keymgr::KeystoreSelector::Primary)
            .unwrap()
    };
    assert_ne!(make(), make());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "uses real Tor relays; set NULLLOBBY_TEST_ARTI_STATE and NULLLOBBY_TEST_ARTI_CACHE"]
async fn real_arti_onion_noise_ram_state_and_cleanup() {
    use nulllobby_core::{
        EphemeralIdentity, PrivateLobbySecret, domain::PaddingPolicy, session::SecureSession,
    };
    use nulllobby_transport::{ModePolicy, TransportKind};
    use std::time::Duration;
    let state_dir: std::path::PathBuf = std::env::var_os("NULLLOBBY_TEST_ARTI_STATE")
        .expect("set persistent Tor test state path")
        .into();
    let cache_dir = std::env::var_os("NULLLOBBY_TEST_ARTI_CACHE")
        .expect("set Tor cache path")
        .into();
    let pool = Arc::new(ArtiPool::new(ArtiConfig {
        state_dir: state_dir.clone(),
        cache_dir,
    }));
    let global = Arc::new(Semaphore::new(128));
    let pending = Arc::new(Semaphore::new(32));
    struct Progress;
    impl NetworkObserver for Progress {
        fn before_network_action(&self, action: NetworkAction) -> Result<(), TransportError> {
            ModePolicy(TransportKind::Tor).before_network_action(action)
        }
        fn bootstrap_progress(&self, percent: u8) {
            eprintln!("Tor bootstrap: {percent}%");
        }
        fn transport_diagnostic(&self, category: &str) {
            eprintln!("{category}");
        }
    }
    let mut backend = ArtiTransport::new(pool, Arc::new(Progress), global.clone(), pending.clone());
    backend.start().await.expect("Arti bootstrap");
    assert_eq!(
        backend.network_status(),
        NetworkStatus::Ready,
        "bootstrap ready state"
    );
    let keys = PrivateLobbySecret::generate().unwrap().derive().unwrap();
    let a = backend
        .create_endpoint(*keys.lobby_id.as_bytes())
        .await
        .expect("create first service");
    let b = backend
        .create_endpoint(*keys.lobby_id.as_bytes())
        .await
        .expect("create second service");
    let address = backend.local_transport_identity(a).unwrap();
    assert_ne!(address, backend.local_transport_identity(b).unwrap());
    let connect = async {
        for _ in 0..10 {
            if let Ok(stream) = backend.connect(b, &address).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        panic!("Arti seed not reachable before deadline");
    };
    let (out, incoming) = tokio::time::timeout(Duration::from_secs(360), async {
        tokio::join!(connect, backend.accept(a))
    })
    .await
    .expect("onion publication deadline");
    let a_id = EphemeralIdentity::generate(keys.lobby_id).unwrap();
    let b_id = EphemeralIdentity::generate(keys.lobby_id).unwrap();
    let (a_session, b_session) = tokio::join!(
        SecureSession::establish(incoming.unwrap(), &a_id, Some(&keys.noise_psk), false),
        SecureSession::establish(out, &b_id, Some(&keys.noise_psk), true)
    );
    let (mut reader, _) = a_session.unwrap().split();
    let (_, mut writer) = b_session.unwrap().split();
    writer
        .send(b"synthetic Arti record", PaddingPolicy::Bucketed)
        .await
        .unwrap();
    assert_eq!(&*reader.receive().await.unwrap(), b"synthetic Arti record");
    // No service state, onion keys, introduction-point or replay directories in
    // the normal persistent Tor state. Guard state must remain intact.
    assert!(!state_dir.join("hss").exists());
    assert!(!state_dir.join("keystore").exists());
    backend.destroy_endpoint(a).await.unwrap();
    assert!(backend.local_transport_identity(a).is_err());
    assert!(
        tokio::time::timeout(Duration::from_secs(5), reader.receive())
            .await
            .unwrap()
            .is_err()
    );
    drop(reader);
    drop(writer);
    backend.stop().await.unwrap();
    assert_eq!(global.available_permits(), 128);
    assert_eq!(pending.available_permits(), 32);
}
