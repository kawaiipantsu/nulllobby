use super::*;
use nulllobby_core::domain::DeliveryState;
use nulllobby_platform::SecretBytes;
use nulllobby_store::{RecordKind, Vault, keyring::KeyProvider};
use std::{
    collections::HashMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
struct Keys(Mutex<HashMap<[u8; 16], [u8; 32]>>);
impl KeyProvider for Keys {
    fn create(&self, id: &[u8; 16], key: &[u8; 32]) -> nulllobby_store::Result<()> {
        self.0.lock().unwrap().insert(*id, *key);
        Ok(())
    }
    fn load(&self, id: &[u8; 16]) -> nulllobby_store::Result<SecretBytes<32>> {
        let mut key = SecretBytes::zeroed().unwrap();
        key.expose_secret_mut().copy_from_slice(
            self.0
                .lock()
                .unwrap()
                .get(id)
                .ok_or(nulllobby_store::Error::Keyring)?,
        );
        Ok(key)
    }
}
struct Storage {
    path: PathBuf,
    keys: Keys,
}
impl Storage {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        Self {
            path: std::env::temp_dir()
                .join(format!(
                    "nl-delivery-test-{:032x}",
                    u128::from_le_bytes(random)
                ))
                .join("store.vault"),
            keys: Keys(Mutex::new(HashMap::new())),
        }
    }
    fn open(&self, create: bool) -> Arc<Vault> {
        Arc::new(Vault::open(&self.path, create, &self.keys).unwrap())
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
    }
}
fn with_vault(vault: Arc<Vault>) -> Config {
    Config {
        vault: Some(vault),
        ..config()
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
async fn persistent(c: &mut Client) {
    c.send(AppCommand::PersistIdentity(true)).await;
    c.view(|l| l.persistent).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mailbox_delivers_after_sender_exit_and_deduplicates_across_recipient_restart() {
    let sender_store = Storage::new();
    let sender_vault = sender_store.open(true);
    let mut sender = Client::start(with_vault(sender_vault.clone()));
    sender
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("durable synthetic test").unwrap(),
        ))
        .await;
    let lobby = sender.view(|l| !l.members.is_empty()).await;
    persistent(&mut sender).await;
    sender.send(AppCommand::DurableDelivery(true)).await;
    sender.view(|l| l.durable).await;
    let card = sender.card().await;
    let mailbox_store = Storage::new();
    let mailbox_vault = mailbox_store.open(true);
    let mut mailbox = Client::start(with_vault(mailbox_vault.clone()));
    mailbox.send(AppCommand::JoinLobby(card)).await;
    mailbox.view(|l| l.peers == 1 && l.members.len() == 2).await;
    // No mailbox is enabled by opening a vault or saving an identity.
    persistent(&mut mailbox).await;
    let defaults = mailbox.view(|l| l.persistent).await;
    assert!(!defaults.mailbox);
    assert!(!defaults.durable);
    mailbox.send(AppCommand::Mailbox(true)).await;
    mailbox.view(|l| l.mailbox).await;
    sender
        .send(AppCommand::SendMessage {
            lobby: lobby.id,
            body: ValidatedText::new("durable synthetic offline canary").unwrap(),
        })
        .await;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let AppEvent::Delivery {
                state: DeliveryState::Stored(_),
                ..
            } = sender.event().await
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(sender_vault.records(lobby.id, now()).unwrap().is_empty());
    assert_eq!(
        mailbox_vault
            .records(lobby.id, now())
            .unwrap()
            .iter()
            .filter(|r| r.kind == RecordKind::Mailbox)
            .count(),
        1
    );
    let mailbox_card = mailbox.card().await;
    let encoded = mailbox_card.export();
    sender.stop().await;
    drop(sender_vault);
    let recipient_store = Storage::new();
    let recipient_vault = recipient_store.open(true);
    let mut recipient = Client::start(with_vault(recipient_vault.clone()));
    recipient.send(AppCommand::JoinLobby(mailbox_card)).await;
    recipient
        .view(|l| l.peers > 0 && l.members.len() >= 2)
        .await;
    persistent(&mut recipient).await;
    recipient.send(AppCommand::SyncMailbox).await;
    assert_eq!(
        recipient
            .message("durable synthetic offline canary")
            .await
            .1,
        lobby.fingerprint
    );
    recipient.send(AppCommand::SyncMailbox).await;
    recipient.stop().await;
    drop(recipient_vault);
    let restored = recipient_store.open(false);
    let mut recipient = Client::start(with_vault(restored.clone()));
    recipient
        .send(AppCommand::JoinLobby(
            LobbyCard::parse(encoded.expose_secret()).unwrap(),
        ))
        .await;
    recipient.view(|l| l.persistent && l.peers > 0).await;
    let limit = tokio::time::sleep(Duration::from_secs(7));
    tokio::pin!(limit);
    loop {
        tokio::select! {_=&mut limit=>break,event=recipient.rx.recv()=>if let Some(AppEvent::MessageReceived{body,..})=event{assert_ne!(body,"durable synthetic offline canary","durable replay displayed twice");}}
    }
    recipient.stop().await;
    drop(restored);
    mailbox.stop().await;
    drop(mailbox_vault);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_rotation_moves_retained_peer_but_excludes_revoked_peer() {
    let mut owner = Client::start(config());
    owner
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("rotation synthetic").unwrap(),
        ))
        .await;
    let original = owner
        .view(|l| l.administrator && !l.members.is_empty())
        .await;
    let invitation = owner.card().await.export();
    let mut kept = Client::start(config());
    kept.send(AppCommand::JoinLobby(
        LobbyCard::parse(invitation.expose_secret()).unwrap(),
    ))
    .await;
    kept.view(|l| l.peers == 1 && l.members.len() == 2).await;
    let mut revoked = Client::start(config());
    revoked
        .send(AppCommand::JoinLobby(
            LobbyCard::parse(invitation.expose_secret()).unwrap(),
        ))
        .await;
    let excluded = revoked.view(|l| l.peers == 1 && l.members.len() >= 2).await;
    owner.view(|l| l.members.len() == 3 && l.peers == 2).await;
    // An unverified alias under the old shared capability must not receive a
    // replacement automatically, even when a different key is excluded.
    owner
        .send(AppCommand::RotatePrivate(Some(excluded.fingerprint)))
        .await;
    loop {
        if let AppEvent::Notice { text, .. } = owner.event().await
            && text.starts_with("Verify every retained")
        {
            break;
        }
    }
    let retained = kept.view(|l| l.id == original.id).await;
    owner
        .send(AppCommand::VerifyPeer {
            lobby: original.id,
            fingerprint: retained.fingerprint,
        })
        .await;
    owner
        .view(|l| {
            l.members
                .iter()
                .any(|m| m.fingerprint == retained.fingerprint && m.verified)
        })
        .await;
    kept.send(AppCommand::RotatePrivate(None)).await;
    loop {
        if let AppEvent::Notice { text, .. } = kept.event().await
            && text.starts_with("Operation failed")
        {
            break;
        }
    }
    owner
        .send(AppCommand::RotatePrivate(Some(excluded.fingerprint)))
        .await;
    let replacement = owner.view(|l| l.id != original.id && l.administrator).await;
    let joined = kept
        .view(|l| l.id == replacement.id && l.peers > 0 && l.members.len() >= 2)
        .await;
    assert_ne!(joined.fingerprint, original.fingerprint);
    assert!(joined.members.iter().all(|m| !m.verified));
    owner
        .send(AppCommand::SendMessage {
            lobby: replacement.id,
            body: ValidatedText::new("new capability only").unwrap(),
        })
        .await;
    kept.message("new capability only").await;
    let limit = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(limit);
    loop {
        tokio::select! {_=&mut limit=>break,event=revoked.rx.recv()=>match event{
            Some(AppEvent::MessageReceived{body,..})=>assert_ne!(body,"new capability only"),
            Some(AppEvent::View{lobbies,..})=>assert!(lobbies.iter().all(|l|l.id==original.id)),_=>{}
        }}
    }
    kept.stop().await;
    revoked.stop().await;
    owner.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn organization_attestation_never_becomes_fingerprint_trust() {
    use nulllobby_core::membership::{EnrollmentRequest, OrganizationAuthority};
    let files = Storage::new();
    std::fs::create_dir_all(files.path.parent().unwrap()).unwrap();
    let request_file = files.path.with_file_name("request.cbor");
    let credential_file = files.path.with_file_name("credential.cose");
    let authority = OrganizationAuthority::generate().unwrap();
    let mut alice = Client::start(config());
    alice
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("organization synthetic").unwrap(),
        ))
        .await;
    alice.view(|l| !l.members.is_empty()).await;
    let card = alice.card().await;
    let mut bob = Client::start(config());
    bob.send(AppCommand::JoinLobby(card)).await;
    bob.view(|l| l.peers > 0 && l.members.len() == 2).await;
    alice
        .send(AppCommand::OrganizationTrust(Some(authority.public_key())))
        .await;
    bob.send(AppCommand::OrganizationTrust(Some(authority.public_key())))
        .await;
    bob.send(AppCommand::OrganizationRequest(request_file.clone()))
        .await;
    loop {
        if let AppEvent::Notice { text, .. } = bob.event().await
            && text.starts_with("Enrollment request exported")
        {
            break;
        }
    }
    let request = EnrollmentRequest::decode(&std::fs::read(request_file).unwrap(), now()).unwrap();
    std::fs::write(
        &credential_file,
        authority
            .issue(&request, "Synthetic Team", "member", now(), 3600)
            .unwrap()
            .encode()
            .unwrap(),
    )
    .unwrap();
    bob.send(AppCommand::OrganizationImport(credential_file))
        .await;
    let view = alice
        .view(|l| l.members.iter().any(|m| m.organization.is_some()))
        .await;
    assert!(view.members.iter().all(|m| !m.verified));
    bob.send(AppCommand::CreatePublicLobby(
        LobbyName::new("independent lobby").unwrap(),
    ))
    .await;
    let other = bob.view(|l| l.name == "independent lobby").await;
    assert!(other.members.iter().all(|m| m.organization.is_none()));
    bob.stop().await;
    alice.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_durable_delivery_and_rotation_retire_old_storage_without_clearnet() {
    let fixture = tor_fixture::Fixture::start().await;
    let audit = Arc::new(TorOnly(Mutex::new(vec![])));
    let start = |vault: Arc<Vault>| {
        let (tx, commands) = nulllobby_transport::command_channel();
        let (events, rx) = nulllobby_transport::event_channel();
        let cfg = Config {
            mode: TransportKind::Tor,
            tor: fixture.config.clone(),
            vault: Some(vault),
            ..Config::default()
        };
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
    let owner_store = Storage::new();
    let owner_vault = owner_store.open(true);
    let mut owner = start(owner_vault.clone());
    owner
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("Tor durable rotation").unwrap(),
        ))
        .await;
    let old = owner
        .view(|l| l.administrator && !l.members.is_empty())
        .await;
    persistent(&mut owner).await;
    owner.send(AppCommand::DurableDelivery(true)).await;
    owner.view(|l| l.durable).await;
    let old_card = owner.card().await.export();
    let peer_store = Storage::new();
    let peer_vault = peer_store.open(true);
    let mut peer = start(peer_vault.clone());
    peer.send(AppCommand::JoinLobby(
        LobbyCard::parse(old_card.expose_secret()).unwrap(),
    ))
    .await;
    peer.view(|l| l.peers > 0).await;
    persistent(&mut peer).await;
    peer.send(AppCommand::Mailbox(true)).await;
    let retained = peer.view(|l| l.mailbox).await;
    owner
        .send(AppCommand::VerifyPeer {
            lobby: old.id,
            fingerprint: retained.fingerprint,
        })
        .await;
    owner
        .view(|l| {
            l.members
                .iter()
                .any(|m| m.fingerprint == retained.fingerprint && m.verified)
        })
        .await;
    owner
        .send(AppCommand::SendMessage {
            lobby: old.id,
            body: ValidatedText::new("Tor durable synthetic").unwrap(),
        })
        .await;
    loop {
        if let AppEvent::Delivery {
            state: DeliveryState::Stored(_),
            ..
        } = owner.event().await
        {
            break;
        }
    }
    owner.send(AppCommand::RotatePrivate(None)).await;
    let new = owner.view(|l| l.id != old.id && l.administrator).await;
    let joined = peer.view(|l| l.id == new.id && l.peers > 0).await;
    assert!(!joined.persistent);
    assert!(!joined.mailbox);
    assert_ne!(new.fingerprint, old.fingerprint);
    assert!(owner_vault.retired(old.id).unwrap());
    assert!(peer_vault.retired(old.id).unwrap());
    assert!(peer_vault.records(old.id, now()).unwrap().is_empty());
    owner
        .send(AppCommand::JoinLobby(
            LobbyCard::parse(old_card.expose_secret()).unwrap(),
        ))
        .await;
    loop {
        if let AppEvent::Notice { text, .. } = owner.event().await
            && text.contains("capability was retired")
        {
            break;
        }
    }
    peer.stop().await;
    owner.stop().await;
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.created, 4);
    assert_eq!(state.deleted, 4);
    assert!(state.routes.is_empty());
    assert!(audit.0.lock().unwrap().iter().all(|a| matches!(
        a,
        NetworkAction::LocalTorControl | NetworkAction::LocalTorSocks
    )));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarted_sender_outbox_retries_with_saved_identity_and_new_sequence_range() {
    let storage = Storage::new();
    let vault = storage.open(true);
    let mut sender = Client::start(with_vault(vault.clone()));
    sender
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("outbox restart").unwrap(),
        ))
        .await;
    let first = sender.view(|l| !l.members.is_empty()).await;
    persistent(&mut sender).await;
    sender.send(AppCommand::DurableDelivery(true)).await;
    sender.view(|l| l.durable).await;
    let invite = sender.card().await.export();
    sender
        .send(AppCommand::SendMessage {
            lobby: first.id,
            body: ValidatedText::new("queued while all peers offline").unwrap(),
        })
        .await;
    sender.message("queued while all peers offline").await;
    assert_eq!(vault.records(first.id, now()).unwrap().len(), 1);
    sender.stop().await;
    drop(vault);
    let holder_store = Storage::new();
    let holder_vault = holder_store.open(true);
    let mut holder = Client::start(with_vault(holder_vault.clone()));
    holder
        .send(AppCommand::JoinLobby(
            LobbyCard::parse(invite.expose_secret()).unwrap(),
        ))
        .await;
    holder.view(|l| !l.members.is_empty()).await;
    persistent(&mut holder).await;
    holder.send(AppCommand::Mailbox(true)).await;
    holder.view(|l| l.mailbox).await;
    // Fresh seed is explicit: no global directory or Direct fallback is invented.
    let fresh_card = holder.card().await;
    let vault = storage.open(false);
    let mut sender = Client::start(with_vault(vault.clone()));
    sender.send(AppCommand::JoinLobby(fresh_card)).await;
    let restored = sender.view(|l| l.peers > 0 && l.persistent).await;
    assert_eq!(restored.fingerprint, first.fingerprint);
    holder.message("queued while all peers offline").await;
    loop {
        if let AppEvent::Delivery {
            state: DeliveryState::Stored(_),
            ..
        } = sender.event().await
        {
            break;
        }
    }
    assert!(vault.records(first.id, now()).unwrap().is_empty());
    sender.stop().await;
    holder.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_only_messages_never_enter_an_enabled_peer_mailbox() {
    let mut sender = Client::start(config());
    sender
        .send(AppCommand::CreatePrivateLobby(
            LobbyName::new("live consent").unwrap(),
        ))
        .await;
    let lobby = sender.view(|l| !l.members.is_empty()).await;
    let card = sender.card().await;
    let storage = Storage::new();
    let vault = storage.open(true);
    let mut peer = Client::start(with_vault(vault.clone()));
    peer.send(AppCommand::JoinLobby(card)).await;
    peer.view(|l| l.peers > 0).await;
    persistent(&mut peer).await;
    peer.send(AppCommand::Mailbox(true)).await;
    peer.view(|l| l.mailbox).await;
    for i in 0..100 {
        let body = format!("synthetic live load {i}");
        sender
            .send(AppCommand::SendMessage {
                lobby: lobby.id,
                body: ValidatedText::new(&body).unwrap(),
            })
            .await;
        peer.message(&body).await;
        loop {
            if let AppEvent::Delivery {
                state: DeliveryState::Received(_),
                ..
            } = sender.event().await
            {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(70)).await;
    }
    assert!(vault.records(lobby.id, now()).unwrap().is_empty());
    peer.stop().await;
    sender.stop().await;
}
