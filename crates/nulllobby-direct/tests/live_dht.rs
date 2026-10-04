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
    eprintln!("DHT counters (no endpoints or identifiers): {stats:?}");
    assert!(stats.replies > 0);
    assert!(stats.announces > 0);
    assert!(stats.queries <= 24);
}

#[tokio::test]
#[ignore = "contacts public Mainline DHT and exposes the test host's public IP"]
async fn independent_client_discovers_announced_listener() {
    tokio::time::timeout(Duration::from_secs(300), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let publisher_port = listener.local_addr().unwrap().port().try_into().unwrap();
        let other_listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let seeker_port = other_listener.local_addr().unwrap().port().try_into().unwrap();
        let mut scope = [0; 32];
        getrandom::fill(&mut scope).unwrap();
        let policy = Arc::new(ModePolicy(TransportKind::Direct));
        let mut publisher = Discovery::start(policy.clone(), None).await.unwrap();
        publisher.discover_and_announce(scope, publisher_port).await.unwrap();
        assert!(publisher.stats().announces > 0);
        let mut seeker = Discovery::start(policy, None).await.unwrap();
        for _ in 0..3 {
            let peers = seeker.discover_and_announce(scope, seeker_port).await.unwrap();
            eprintln!("Independent lookup counters: {:?}; candidates: {}", seeker.stats(), peers.len());
            if peers.iter().any(|peer| matches!(peer, nulllobby_transport::Endpoint::Direct { port, .. } if *port == publisher_port)) {
                return;
            }
        }
        panic!("Independent DHT client did not discover the publisher");
    }).await.expect("bounded live DHT test");
}
