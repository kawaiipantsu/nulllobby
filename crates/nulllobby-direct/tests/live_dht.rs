use nulllobby_direct::discovery::Discovery;
use nulllobby_transport::{ModePolicy, TransportKind};
use std::{sync::Arc, time::Duration};
#[tokio::test]
#[ignore = "contacts public Mainline DHT and exposes the test host's public IP"]
async fn public_dht_get_peers_and_announce() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port().try_into().unwrap();
    let mut scope = [0; 32];
    getrandom::fill(&mut scope).unwrap();
    let mut dht = Discovery::start(Arc::new(ModePolicy(TransportKind::Direct)), None)
        .await
        .unwrap();
    let peers = tokio::time::timeout(
        Duration::from_secs(110),
        dht.discover_and_announce(scope, port),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(peers.len() <= 64);
    let stats = dht.stats();
    assert!(stats.replies > 0);
    assert!(stats.announces > 0);
    assert!(stats.queries <= 24);
}
