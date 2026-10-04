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

#[tokio::test]
async fn progress_reports_candidates_before_announcement_reply_and_resets_each_round() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        let fixture = dht::Fixture::start_with_announcement_gate(gate.clone()).await;
        let policy = Arc::new(ModePolicy(TransportKind::Direct));
        let mut discovery = Discovery::start(policy, Some(vec![fixture.bootstrap]))
            .await
            .unwrap();
        let port = NonZeroU16::new(50003).unwrap();
        discovery
            .discover_and_announce([43; 32], port)
            .await
            .unwrap();
        assert_eq!(discovery.stats().announces, 1);
        let (progress, mut receiver) = tokio::sync::watch::channel(discovery.stats());
        let task = tokio::spawn(async move {
            let mut updates = Vec::new();
            let peers = discovery
                .discover_and_announce_with_progress([43; 32], port, |stats| {
                    assert!(
                        updates.len() < 100,
                        "bounded round has bounded progress callbacks"
                    );
                    updates.push(stats);
                    progress.send_replace(stats);
                })
                .await
                .unwrap();
            (peers, updates)
        });
        let pending = *receiver
            .wait_for(|stats| stats.tokens == 1 && stats.candidates == 1 && stats.announces == 0)
            .await
            .unwrap();
        assert_eq!(pending.queries, 2);
        assert_eq!(pending.replies, 2);
        assert!(
            !task.is_finished(),
            "counters must update while the DHT request is pending"
        );
        gate.add_permits(1);
        let (peers, updates) = task.await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(
            updates[0],
            Default::default(),
            "new round resets all counters"
        );
        assert_eq!(updates.last().unwrap().announces, 1);
        assert_eq!(updates.last().unwrap().candidates, 1);
        assert!(
            updates
                .windows(2)
                .all(|pair| pair[0].queries <= pair[1].queries
                    && pair[0].replies <= pair[1].replies
                    && pair[0].announces <= pair[1].announces)
        );
    })
    .await
    .expect("progress before bounded request timeout");
}
