use super::*;
use nulllobby_core::LobbyKind;

impl Room {
    pub(super) async fn vault<T: Send + 'static>(
        &self,
        op: impl FnOnce(&Vault) -> nulllobby_store::Result<T> + Send + 'static,
    ) -> Result<T, ()> {
        let vault = self.config.vault.clone().ok_or(())?;
        tokio::task::spawn_blocking(move || op(&vault))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
    }
    pub(super) async fn stored_records(&self) -> Result<Vec<StoredRecord>, ()> {
        let id = self.card.lobby_id();
        self.vault(move |v| v.records(id, unix_time())).await
    }
    pub(super) async fn sign(&mut self, payload: Payload) -> Result<SignedMessage, ()> {
        if self.persistent && self.sequence >= self.sequence_limit {
            let id = self.card.lobby_id();
            self.sequence_limit = self.vault(move |v| v.reserve(id)).await?;
        }
        self.sequence = self.sequence.checked_add(1).ok_or(())?;
        SignedMessage::new(&self.identity, self.sequence, payload).map_err(|_| ())
    }
    pub(super) async fn delivery(&self, id: [u8; 16], state: DeliveryState) {
        self.ui(AppEvent::Delivery {
            lobby: self.card.lobby_id(),
            id,
            state,
        })
        .await;
    }
    pub(super) async fn accept_durable(&mut self, message: &SignedMessage) -> Result<bool, ()> {
        message.verify(self.card.lobby_id()).map_err(|_| ())?;
        let Payload::DurableChat {
            created, expires, ..
        } = message.payload()
        else {
            return Err(());
        };
        self.durable_clock = self.durable_clock.max(unix_time());
        let now = self.durable_clock;
        if *created > now.saturating_add(60) {
            return Err(());
        }
        if *expires <= now {
            return Ok(false);
        }
        let (lobby, sender, id, sequence, expires) = (
            message.lobby(),
            *message.sender(),
            message.id(),
            message.sequence(),
            *expires,
        );
        if self.persistent {
            return self
                .vault(move |v| v.seen(lobby, sender, id, sequence, expires, now))
                .await;
        }
        self.durable_seen.retain(|v| v.3 > now);
        if self
            .durable_seen
            .iter()
            .any(|v| v.0 == sender && (v.1 == id || v.2 == sequence))
        {
            return Ok(false);
        }
        if self.durable_seen.len() >= 1024 {
            return Err(());
        }
        self.durable_seen.push((sender, id, sequence, expires));
        Ok(true)
    }
    pub(super) async fn acknowledge(&mut self, message: &SignedMessage) -> Result<(), ()> {
        if message.sender() == &self.identity.public_key() {
            return Ok(());
        }
        let stored = match message.payload() {
            Payload::Chat(_) => false,
            Payload::DurableChat { expires, .. } => {
                if *expires <= unix_time() {
                    return Ok(());
                }
                if self.mailbox {
                    let record = StoredRecord {
                        lobby: message.lobby(),
                        kind: RecordKind::Mailbox,
                        expires: *expires,
                        message: message.clone(),
                    };
                    match self.vault(move |v| v.put(record, unix_time())).await {
                        Ok(()) => true,
                        Err(()) => {
                            self.notice(
                                "Mailbox capacity or storage unavailable; no stored receipt issued",
                            )
                            .await;
                            false
                        }
                    }
                } else {
                    false
                }
            }
            _ => return Ok(()),
        };
        let sender = *message.sender();
        let id = message.id();
        if let Some((_, _, _, receipt, last)) = self
            .receipts
            .iter_mut()
            .find(|v| v.0 == sender && v.1 == id && v.2 == stored)
        {
            if last.elapsed() < Duration::from_secs(4) {
                return Ok(());
            }
            *last = Instant::now();
            let receipt = receipt.clone();
            self.broadcast(Packet::Signed(receipt), None);
            return Ok(());
        }
        let receipt = self.sign(Payload::Receipt { sender, id, stored }).await?;
        if self.receipts.len() >= 256 {
            self.receipts.remove(0);
        }
        self.receipts
            .push((sender, id, stored, receipt.clone(), Instant::now()));
        self.broadcast(Packet::Signed(receipt), None);
        Ok(())
    }
    pub(super) async fn receive_receipt(
        &mut self,
        peer: [u8; 32],
        sender: [u8; 32],
        id: [u8; 16],
        stored: bool,
    ) -> Result<(), ()> {
        if sender != self.identity.public_key() || peer == sender {
            return Ok(());
        }
        let Some((message, _)) = self.pending.get(&id) else {
            return Ok(());
        };
        let durable = matches!(message.payload(), Payload::DurableChat { .. });
        if stored && !durable {
            return Ok(());
        }
        let fp = Fingerprint::of_public_key(&peer);
        if !durable || stored {
            if durable {
                let lobby = self.card.lobby_id();
                self.vault(move |v| v.remove_outbox(lobby, id)).await?;
            }
            self.pending.remove(&id);
        }
        self.delivery(
            id,
            if stored {
                DeliveryState::Stored(fp)
            } else {
                DeliveryState::Received(fp)
            },
        )
        .await;
        Ok(())
    }
    pub(super) async fn sync_peer(&mut self, key: [u8; 32]) -> Result<(), ()> {
        if !self.mailbox {
            return Ok(());
        }
        let Some(peer) = self.peers.get(&key) else {
            return Err(());
        };
        if peer
            .synced
            .is_some_and(|t| t.elapsed() < Duration::from_secs(2))
        {
            return Ok(());
        }
        let mut records = self.stored_records().await?;
        records.retain(|r| r.kind == RecordKind::Mailbox);
        let peer = self.peers.get_mut(&key).ok_or(())?;
        if peer.sync_cursor >= records.len() {
            peer.sync_cursor = 0;
        }
        for record in records.iter().skip(peer.sync_cursor).take(4) {
            if !peer.queue(Packet::Signed(record.message.clone())) {
                return Err(());
            }
            peer.sync_cursor += 1;
        }
        peer.synced = Some(Instant::now());
        Ok(())
    }
    pub(super) async fn retry(&mut self) {
        let now = unix_time();
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, (m, t))| match m.payload() {
                Payload::DurableChat { expires, .. } => *expires <= now,
                _ => t.elapsed() > Duration::from_secs(600),
            })
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.pending.remove(&id);
            self.delivery(id, DeliveryState::Expired).await;
        }
        let mut ids: Vec<_> = self.pending.keys().copied().collect();
        ids.sort_unstable();
        let count = ids.len().min(4);
        let resend: Vec<_> = if ids.is_empty() {
            Vec::new()
        } else {
            (0..count)
                .map(|i| {
                    self.pending[&ids[(self.retry_cursor + i) % ids.len()]]
                        .0
                        .clone()
                })
                .collect()
        };
        self.retry_cursor = if ids.is_empty() {
            0
        } else {
            (self.retry_cursor % ids.len() + count) % ids.len()
        };
        for message in resend {
            self.broadcast(Packet::Signed(message), None);
        }
        if self.persistent {
            self.broadcast(Packet::Sync, None);
            if self.vault(move |v| v.expire(now)).await.is_err() {
                self.notice("Vault write failed; durable state remains pending")
                    .await;
            }
        }
        self.credentials.retain(|_, c| c.expires > now);
    }
    pub(super) async fn feature_command(&mut self, command: Command) -> Result<(), ()> {
        let lobby = self.card.lobby_id();
        match command {
            Command::Persist(enabled) => {
                if enabled == self.persistent {
                    return Ok(());
                }
                if enabled {
                    let card = self.prepare_card()?;
                    let identity = self.identity.clone();
                    let name = self.name.as_str().to_owned();
                    let sequence = self.sequence;
                    self.sequence_limit = self
                        .vault(move |v| v.remember(&identity, &card, &name, sequence))
                        .await?;
                    self.persistent = true;
                    self.notice("Persistent identity enabled for this lobby: fingerprint and capability are saved in the encrypted vault. Trust remains in RAM; Noise keys change on reconnect/restart.").await;
                } else {
                    self.vault(move |v| v.forget(lobby)).await?;
                    self.persistent = false;
                    self.durable = false;
                    self.mailbox = false;
                    self.pending
                        .retain(|_, (m, _)| !matches!(m.payload(), Payload::DurableChat { .. }));
                    self.notice("Saved lobby identity and local durable records removed. This session keeps its current identity until leaving. Backups and other peers' copies cannot be erased.").await;
                }
            }
            Command::Durable(enabled) | Command::Mailbox(enabled) => {
                if !self.persistent {
                    self.notice("Enable /identity persistent first; a Secret Service protected --vault is required").await;
                    return Err(());
                }
                let (durable, mailbox) = if matches!(command, Command::Durable(_)) {
                    (enabled, self.mailbox)
                } else {
                    (self.durable, enabled)
                };
                self.vault(move |v| v.settings(lobby, durable, mailbox))
                    .await?;
                self.durable = durable;
                self.mailbox = mailbox;
                self.notice(format!("Durable sending: {durable}; peer mailbox: {mailbox}. Durable messages allow authorized lobby peers to retain and replay them for up to 24 hours. Live messages are never intentionally stored. Existing outbox deliveries remain pending until stored or expired.")).await;
            }
            Command::Sync => {
                self.broadcast(Packet::Sync, None);
                self.notice("Requested bounded mailbox replay. A reachable participant holding an unexpired copy is required.").await;
            }
            Command::Rotate(exclude) => {
                if self.card.kind() != LobbyKind::Private
                    || self.card.administrator() != Some(self.identity.public_key())
                    || self.rotating.is_some()
                {
                    return Err(());
                }
                // Possession of the old shared capability permits new aliases.
                // Only an explicitly reviewed recipient roster may learn the
                // replacement; a fresh alias must not bypass exclusion.
                if self.peers.keys().any(|key| {
                    let fp = Fingerprint::of_public_key(key);
                    Some(fp) != exclude && !self.trust.is_verified(lobby, &fp)
                }) {
                    self.notice("Verify every retained directly connected fingerprint out of band before rotating. An old capability holder can create unverified aliases; those identities cannot automatically receive the replacement invite.").await;
                    return Err(());
                }
                if let Some(fp) = exclude {
                    if fp == self.identity.fingerprint()
                        || !self
                            .members
                            .keys()
                            .any(|k| Fingerprint::of_public_key(k) == fp)
                    {
                        return Err(());
                    }
                    self.peers
                        .retain(|key, _| Fingerprint::of_public_key(key) != fp);
                }
                self.rotating = Some(exclude);
                self.tx
                    .send(Event::PrepareRotation {
                        old: lobby,
                        name: self.name.clone(),
                    })
                    .await
                    .map_err(|_| ())?;
            }
            Command::RotationExport(old) => {
                let card = self.prepare_card()?;
                self.tx
                    .send(Event::RotationReady { old, card })
                    .await
                    .map_err(|_| ())?;
            }
            Command::RotationReady(card) => {
                if self.finish_rotation(card).await.is_err() {
                    self.closing = true;
                    self.notice("Rotation failed; old lobby disconnected. Vault retirement may be incomplete; repair storage before reusing saved state. No old-lobby fallback.").await;
                    return Err(());
                }
            }
            Command::RotationFailed => {
                self.rotating = None;
                self.notice(
                    "Rotation could not create its new endpoint; no replacement invite was sent",
                )
                .await;
            }
            Command::OrgTrust(issuer) => {
                self.issuer = issuer;
                self.credentials.clear();
                self.request = None;
                self.notice("Organization issuer policy changed for this lobby only. Membership is separate from human fingerprint verification and private-lobby admission; no CA lookup is performed.").await;
            }
            Command::OrgRequest(path) => {
                if self.issuer.is_none() {
                    return Err(());
                }
                let request =
                    EnrollmentRequest::new(&self.identity, unix_time()).map_err(|_| ())?;
                let bytes = request.encode().map_err(|_| ())?;
                tokio::task::spawn_blocking(move || {
                    crate::organization::write_public(&path, &bytes)
                })
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
                self.request = Some(request);
                self.notice("Enrollment request exported. Send it privately to your independently verified organization issuer; it discloses this lobby ID and public key.").await;
            }
            Command::OrgImport(path) => {
                let bytes = tokio::task::spawn_blocking(move || {
                    crate::organization::read_public(&path, 1024)
                })
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
                let credential = Credential::decode(&bytes).map_err(|_| ())?;
                let request = self.request.as_ref().ok_or(())?;
                if credential.subject != self.identity.public_key()
                    || credential.challenge != request.challenge
                {
                    return Err(());
                }
                self.membership(bytes, None).await?;
                self.request = None;
                self.notice("Organization credential accepted. It expires within eight hours and is shared only inside this lobby's encrypted sessions.").await;
            }
            _ => return Err(()),
        }
        Ok(())
    }
    pub(super) async fn membership(
        &mut self,
        bytes: Vec<u8>,
        via: Option<[u8; 32]>,
    ) -> Result<(), ()> {
        let Some(issuer) = self.issuer else {
            return Ok(());
        };
        let credential = Credential::decode(&bytes).map_err(|_| ())?;
        credential
            .verify(
                self.card.lobby_id(),
                credential.subject,
                issuer,
                unix_time(),
            )
            .map_err(|_| ())?;
        if self
            .credentials
            .get(&credential.subject)
            .is_some_and(|c| c.serial == credential.serial || c.issued > credential.issued)
        {
            return Ok(());
        }
        if self.credentials.len() >= 64 && !self.credentials.contains_key(&credential.subject) {
            return Err(());
        }
        self.credentials.insert(credential.subject, credential);
        self.broadcast(Packet::Membership(bytes), via);
        self.view().await;
        Ok(())
    }
    async fn finish_rotation(&mut self, card: LobbyCard) -> Result<(), ()> {
        let exclude = self.rotating.ok_or(())?;
        let old = self.card.lobby_id();
        if card.kind() != LobbyKind::Private
            || card.transport() != self.card.transport()
            || card.lobby_id() == old
        {
            return Err(());
        }
        if self.persistent {
            self.vault(move |v| v.retire(old)).await?;
        }
        self.sequence = self.sequence.checked_add(1).ok_or(())?;
        let mut waits = JoinSet::new();
        for (key, peer) in &self.peers {
            let fingerprint = Fingerprint::of_public_key(key);
            if exclude == Some(fingerprint) || !self.trust.is_verified(old, &fingerprint) {
                continue;
            }
            let offer = RotationOffer::new(
                &self.identity,
                *key,
                self.sequence,
                unix_time().saturating_add(300),
                &card,
            )
            .map_err(|_| ())?;
            let (tx, rx) = oneshot::channel();
            if peer
                .tx
                .try_send(Outbound {
                    packet: Packet::Rotation(offer),
                    written: Some(tx),
                })
                .is_ok()
            {
                waits.spawn(async move {
                    let _ = rx.await;
                });
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while waits.join_next().await.is_some() {}
        })
        .await;
        waits.abort_all();
        self.closing = true;
        self.notice("Private capability rotated. Old local identity, outbox and mailbox retired. Replacement offers were addressed individually; peers that did not join need a fresh /invite. New lobby identity, trust and storage choices start fresh. Old copies/forks cannot be revoked.").await;
        Ok(())
    }
    pub(super) async fn follow_rotation(
        &mut self,
        offer: RotationOffer,
        peer: [u8; 32],
    ) -> Result<(), ()> {
        let card = offer
            .verify(&self.card, self.identity.public_key(), peer, unix_time())
            .map_err(|_| ())?;
        let old = self.card.lobby_id();
        self.closing = true;
        if self.persistent && self.vault(move |v| v.retire(old)).await.is_err() {
            self.notice("Rotation failed to retire saved state; old lobby disconnected. Repair the vault and obtain a fresh invite.").await;
            return Err(());
        }
        self.tx
            .send(Event::FollowRotation { old, card })
            .await
            .map_err(|_| ())?;
        Ok(())
    }
}
