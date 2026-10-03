#![cfg(feature = "tor-arti-experimental")]
use nulllobby_app::{App, ArtiOptions, Config};
use nulllobby_core::domain::{AppCommand, AppEvent, LobbyName};
use nulllobby_transport::{NetworkAction, NetworkObserver, TransportError, TransportKind};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Default)]
struct Denied(Mutex<Vec<NetworkAction>>);
impl NetworkObserver for Denied {
    fn before_network_action(&self, action: NetworkAction) -> Result<(), TransportError> {
        self.0.lock().unwrap().push(action);
        Err(TransportError::Unavailable)
    }
}

#[tokio::test]
async fn selected_arti_failure_never_starts_external_tor_or_direct_discovery() {
    let observer = Arc::new(Denied::default());
    let config = Config {
        mode: TransportKind::Tor,
        arti: Some(ArtiOptions {
            state_dir: "/unused/arti-state".into(),
            cache_dir: "/unused/arti-cache".into(),
        }),
        ..Config::default()
    };
    let (commands, rx) = nulllobby_transport::command_channel();
    let (events, mut ev_rx) = nulllobby_transport::event_channel();
    let task = tokio::spawn(
        App::new(config, rx, events)
            .with_observer(observer.clone())
            .run(),
    );
    commands
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("synthetic").unwrap(),
        ))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = ev_rx.recv().await {
            if matches!(event, AppEvent::Notice { text, .. } if text.contains("Transport unavailable")) { return; }
        }
        panic!("missing failure event");
    }).await.unwrap();
    assert_eq!(*observer.0.lock().unwrap(), [NetworkAction::EmbeddedTor]);
    commands.send(AppCommand::Shutdown).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
