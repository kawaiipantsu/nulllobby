//! Real Direct/Noise chat with a bounded local HTTP fixture, no cloud credentials.
use nulllobby_app::{App, Config, DirectOptions};
use nulllobby_bot::{
    Bot, Start,
    provider::{Kind, Options, Provider},
};
use nulllobby_core::{
    LobbyCard,
    domain::{AppCommand, AppEvent, LobbyName},
    text::ValidatedText,
};
use nulllobby_transport::TransportKind;
use secrecy::ExposeSecret;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

async fn event(rx: &mut mpsc::Receiver<AppEvent>) -> AppEvent {
    tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .unwrap()
        .unwrap()
}
fn client() -> (
    mpsc::Sender<AppCommand>,
    mpsc::Receiver<AppEvent>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = nulllobby_transport::command_channel();
    let (ev, events) = nulllobby_transport::event_channel();
    let config = Config {
        no_dht: true,
        direct: DirectOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        ..Config::default()
    };
    (tx, events, tokio::spawn(App::new(config, rx, ev).run()))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn addressed_prompt_only_crosses_provider_boundary_and_reply_is_signed_chat() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let payload = loop {
            let mut buf = [0u8; 1024];
            let count = socket.read(&mut buf).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 16384);
            bytes.extend_from_slice(&buf[..count]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                let len: usize = headers
                    .lines()
                    .find_map(|h| {
                        h.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap();
                if bytes.len() >= end + 4 + len {
                    break bytes[end + 4..end + 4 + len].to_vec();
                }
            }
        };
        observed.fetch_add(1, Ordering::SeqCst);
        let text = std::str::from_utf8(&payload).unwrap();
        assert!(!text.contains("unaddressed-canary"));
        assert!(!text.contains("private-lobby-canary"));
        assert!(!text.contains("nl:"));
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(json["messages"][1]["content"], "synthetic request");
        assert_eq!(json["messages"].as_array().unwrap().len(), 2);
        let body = r#"{"choices":[{"message":{"content":"/quit synthetic response"}}]}"#;
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    });
    let (human, mut events, human_task) = client();
    human
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("private-lobby-canary").unwrap(),
        ))
        .await
        .unwrap();
    let id = loop {
        if let AppEvent::View { lobbies, .. } = event(&mut events).await
            && let Some(lobby) = lobbies.first()
        {
            break lobby.id;
        }
    };
    human.send(AppCommand::ExportInvite).await.unwrap();
    let card = loop {
        if let AppEvent::Invite(card) = event(&mut events).await {
            break LobbyCard::parse(card.expose_secret()).unwrap();
        }
    };
    let (commands, mut actual_events, app_task) = client();
    let (relay_tx, bot_events) = mpsc::channel(128);
    let relay = tokio::spawn(async move {
        while let Some(event) = actual_events.recv().await {
            if let AppEvent::MessageReceived {
                lobby,
                fingerprint,
                body,
                ..
            } = &event
                && body == "unaddressed-canary"
            {
                // A mailbox replay can arrive immediately after joining. Even
                // an addressed replay must never trigger a provider request.
                relay_tx
                    .send(AppEvent::MessageReceived {
                        lobby: *lobby,
                        fingerprint: *fingerprint,
                        nickname: "synthetic".into(),
                        body: "@helper durable replay must stay local".into(),
                        verified: false,
                        id: [5; 16],
                        historical: true,
                    })
                    .await
                    .unwrap();
            }
            if relay_tx.send(event).await.is_err() {
                break;
            }
        }
    });
    let stop = commands.clone();
    let provider = Provider::new(
        Options {
            kind: Kind::Local,
            model: "fixture-model".into(),
            local_endpoint: Some(endpoint),
            key: None,
            allow_cloud: false,
        },
        TransportKind::Direct,
    )
    .unwrap();
    let bot = Bot::new(provider, "helper", 1).unwrap();
    let bot_task = tokio::spawn(bot.run(commands, bot_events, Start::Join(card), false));
    loop {
        if let AppEvent::MessageReceived { body, .. } = event(&mut events).await
            && body.contains("Automated bot")
        {
            break;
        }
    }
    for text in ["unaddressed-canary", "@helper synthetic request"] {
        human
            .send(AppCommand::SendMessage {
                lobby: id,
                body: ValidatedText::new(text).unwrap(),
            })
            .await
            .unwrap();
    }
    loop {
        if let AppEvent::MessageReceived { nickname, body, .. } = event(&mut events).await
            && body == "[bot:local model] /quit synthetic response"
        {
            assert_eq!(nickname, "helper[bot]");
            break;
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.await.unwrap();
    stop.send(AppCommand::Shutdown).await.unwrap();
    bot_task.await.unwrap().unwrap();
    app_task.await.unwrap();
    relay.await.unwrap();
    human.send(AppCommand::Shutdown).await.unwrap();
    while !matches!(event(&mut events).await, AppEvent::ShutdownComplete) {}
    human_task.await.unwrap();
}
