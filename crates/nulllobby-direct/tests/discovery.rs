#[path = "../../../tests/support/dht.rs"]
mod dht;
use nulllobby_direct::discovery::Discovery;
use nulllobby_transport::{Endpoint, ModePolicy, TransportKind};
use std::{
    num::NonZeroU16,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

#[tokio::test]
async fn bootstrap_find_node_then_token_authenticated_announce_and_independent_lookup() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = dht::Fixture::start().await;
        let policy = Arc::new(ModePolicy(TransportKind::Direct));
        let mut publisher = Discovery::start(policy.clone(), Some(vec![fixture.bootstrap]))
            .await
            .unwrap();
        let port = NonZeroU16::new(50001).unwrap();
        assert!(
            publisher
                .discover_and_announce([42; 32], port)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(publisher.stats().announces, 1);
        let mut seeker = Discovery::start(policy, Some(vec![fixture.bootstrap]))
            .await
            .unwrap();
        let peers = seeker
            .discover_and_announce([42; 32], NonZeroU16::new(50002).unwrap())
            .await
            .unwrap();
        assert_eq!(
            peers,
            vec![Endpoint::Direct {
                address: "127.0.0.1".parse().unwrap(),
                port
            }]
        );
        assert_eq!(seeker.stats().queries, 2);
        assert_eq!(seeker.stats().announces, 1);
        assert_eq!(fixture.announces.load(Ordering::SeqCst), 2);
    })
    .await
    .expect("bounded fixture exchange");
}
