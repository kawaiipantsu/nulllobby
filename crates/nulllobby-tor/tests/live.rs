//! Opt-in smoke test against a separately managed, fully bootstrapped Tor daemon.
use nulllobby_core::{
    EphemeralIdentity, PrivateLobbySecret, domain::PaddingPolicy, session::SecureSession,
};
use nulllobby_tor::{TorConfig, TorTransport};
use nulllobby_transport::{ModePolicy, Transport, TransportKind};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[tokio::test]
#[ignore = "requires explicit NULLLOBBY_TEST_TOR_COOKIE, SOCKS and CONTROL configuration"]
async fn real_external_tor_onion_noise_roundtrip() {
    let config = TorConfig {
        socks: std::env::var("NULLLOBBY_TEST_TOR_SOCKS")
            .expect("set test SOCKS address")
            .parse()
            .unwrap(),
        control: std::env::var("NULLLOBBY_TEST_TOR_CONTROL")
            .expect("set test ControlPort address")
            .parse()
            .unwrap(),
        cookie: Some(
            std::env::var_os("NULLLOBBY_TEST_TOR_COOKIE")
                .expect("set cookie path")
                .into(),
        ),
    };
    let policy = Arc::new(ModePolicy(TransportKind::Tor));
    let global = Arc::new(Semaphore::new(128));
    let pending = Arc::new(Semaphore::new(32));
    let mut alice = TorTransport::new(
        config.clone(),
        policy.clone(),
        global.clone(),
        pending.clone(),
    );
    let mut bob = TorTransport::new(config, policy, global, pending);
    alice.start().await.expect("Tor start");
    assert!(
        alice.isolation_confirmed(),
        "explicit test SOCKSPort isolation should be confirmed"
    );
    bob.start().await.expect("Tor start");
    let capability = PrivateLobbySecret::generate().unwrap().derive().unwrap();
    let a = alice
        .create_endpoint(*capability.lobby_id.as_bytes())
        .await
        .unwrap();
    let a_other = alice.create_endpoint([0x23; 32]).await.unwrap();
    let b = bob
        .create_endpoint(*capability.lobby_id.as_bytes())
        .await
        .unwrap();
    let address = alice.local_transport_identity(a).unwrap();
    assert_ne!(address, alice.local_transport_identity(a_other).unwrap());
    let result = tokio::time::timeout(Duration::from_secs(180), async {
        let dial = async {
            for _ in 0..8 {
                if let Ok(stream) = bob.connect(b, &address).await {
                    return stream;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            panic!("onion seed not reachable before deadline");
        };
        let (out, incoming) = tokio::join!(dial, alice.accept(a));
        let a_id = EphemeralIdentity::generate(capability.lobby_id).unwrap();
        let b_id = EphemeralIdentity::generate(capability.lobby_id).unwrap();
        let (left, right) = tokio::join!(
            SecureSession::establish(out, &b_id, Some(&capability.noise_psk), true),
            SecureSession::establish(incoming.unwrap(), &a_id, Some(&capability.noise_psk), false)
        );
        let (_, mut writer) = left.unwrap().split();
        let (mut reader, _) = right.unwrap().split();
        writer
            .send(b"synthetic onion smoke test", PaddingPolicy::Bucketed)
            .await
            .unwrap();
        assert_eq!(
            &*reader.receive().await.unwrap(),
            b"synthetic onion smoke test"
        );
    })
    .await;
    alice.stop().await.unwrap();
    bob.stop().await.unwrap();
    result.expect("Tor smoke test deadline");
}
