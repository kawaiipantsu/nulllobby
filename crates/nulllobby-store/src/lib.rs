//! Explicit opt-in, bounded encrypted state. Never opened by the default client.
#![forbid(unsafe_code)]
pub mod keyring;
mod state;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use nulllobby_core::{EphemeralIdentity, LobbyCard, LobbyId};
use nulllobby_platform::SecretBytes;
use secrecy::ExposeSecret;
use state::State;
pub use state::{RecordKind, Seen, StoredLobby, StoredRecord};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;

pub const MAX_FILE: usize = 4 * 1024 * 1024;
pub const MAX_RECORDS: usize = 256;
pub const MAX_PROFILES: usize = 16;
pub const SEQUENCE_BLOCK: u64 = 4096;
pub type RestoredIdentity = (EphemeralIdentity, u64, u64, bool, bool);
const MAGIC: &[u8; 8] = b"NLVAULT1";
const HEADER: usize = 8 + 16 + 24;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "Encrypted vault key unavailable; unlock/configure the Linux Secret Service (libsecret-tools); no plaintext fallback"
    )]
    Keyring,
    #[error(
        "Vault path requires account-owned private regular files and a private directory; symlinks are rejected"
    )]
    Permissions,
    #[error("Vault is in use by another process")]
    Locked,
    #[error("Vault file unavailable or atomic storage operation failed")]
    Io,
    #[error("Vault authentication, encoding or version is invalid")]
    Invalid,
    #[error("Vault resource limit reached")]
    Limit,
    #[error("Lobby capability has been retired in this vault")]
    Retired,
    #[error("Persistent lobby identity is required")]
    Missing,
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}
impl From<minicbor::decode::Error> for Error {
    fn from(_: minicbor::decode::Error) -> Self {
        Self::Invalid
    }
}
impl From<minicbor::encode::Error<std::convert::Infallible>> for Error {
    fn from(_: minicbor::encode::Error<std::convert::Infallible>) -> Self {
        Self::Invalid
    }
}

pub struct Vault {
    inner: Mutex<Inner>,
}
struct Inner {
    path: PathBuf,
    id: [u8; 16],
    key: SecretBytes<32>,
    state: State,
    _lock: File,
}
impl Vault {
    pub fn memory_status(&self) -> Result<nulllobby_platform::HardeningStatus> {
        self.inner
            .lock()
            .map(|inner| inner.key.lock_status())
            .map_err(|_| Error::Io)
    }
    pub fn open(path: &Path, create: bool, provider: &dyn keyring::KeyProvider) -> Result<Self> {
        if !path.is_absolute() {
            return Err(Error::Permissions);
        }
        let parent = path.parent().ok_or(Error::Permissions)?;
        if create {
            let mut d = fs::DirBuilder::new();
            d.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                d.mode(0o700);
            }
            d.create(parent)?;
        }
        check_private(parent, true)?;
        let lock_path = path.with_extension("lock");
        if lock_path == path {
            return Err(Error::Permissions);
        }
        let lock = private_open(&lock_path, true, false)?;
        lock.try_lock().map_err(|_| Error::Locked)?;
        let (id, key, state) = if create {
            if path.try_exists()? {
                return Err(Error::Io);
            }
            let mut id = [0; 16];
            getrandom::fill(&mut id).map_err(|_| Error::Io)?;
            let mut key = SecretBytes::zeroed().map_err(|_| Error::Io)?;
            getrandom::fill(key.expose_secret_mut()).map_err(|_| Error::Io)?;
            provider.create(&id, key.expose_secret())?;
            // Verify retrieval before any state is entrusted to the vault.
            let loaded = provider.load(&id)?;
            if loaded.expose_secret() != key.expose_secret() {
                return Err(Error::Keyring);
            }
            (id, key, State::default())
        } else {
            let bytes = read_private(path, MAX_FILE + HEADER + 16)?;
            if bytes.len() < HEADER + 16 || &bytes[..8] != MAGIC {
                return Err(Error::Invalid);
            }
            let id = bytes[8..24].try_into().map_err(|_| Error::Invalid)?;
            let key = provider.load(&id)?;
            let plain = open_bytes(key.expose_secret(), &bytes)?;
            (id, key, State::decode(&plain)?)
        };
        let mut inner = Inner {
            path: path.to_owned(),
            id,
            key,
            state,
            _lock: lock,
        };
        if create {
            inner.save()?;
        }
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }
    fn read<T>(&self, op: impl FnOnce(&State) -> Result<T>) -> Result<T> {
        let inner = self.inner.lock().map_err(|_| Error::Io)?;
        op(&inner.state)
    }
    fn change<T>(&self, op: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let mut inner = self.inner.lock().map_err(|_| Error::Io)?;
        let before = inner.state.encode()?;
        match op(&mut inner.state).and_then(|v| {
            inner.save()?;
            Ok(v)
        }) {
            Ok(v) => Ok(v),
            Err(error) => {
                inner.state = State::decode(&before)?;
                Err(error)
            }
        }
    }
    pub fn retired(&self, lobby: LobbyId) -> Result<bool> {
        self.read(|s| Ok(s.retired.contains(&lobby)))
    }
    pub fn profiles(&self) -> Result<Vec<(LobbyId, String)>> {
        self.read(|s| {
            Ok(s.lobbies
                .iter()
                .map(|p| (p.lobby, p.name.clone()))
                .collect())
        })
    }
    pub fn card(&self, lobby: LobbyId) -> Result<LobbyCard> {
        self.read(|s| {
            LobbyCard::parse(s.profile(lobby)?.card.expose_secret()).map_err(|_| Error::Invalid)
        })
    }
    pub fn remember(
        &self,
        identity: &EphemeralIdentity,
        card: &LobbyCard,
        name: &str,
        current_sequence: u64,
    ) -> Result<u64> {
        if identity.lobby() != card.lobby_id() {
            return Err(Error::Invalid);
        }
        let seed = identity.persistence_seed().map_err(|_| Error::Io)?;
        self.change(|s| {
            if s.issuer.is_some() {
                return Err(Error::Invalid);
            }
            if s.retired.contains(&card.lobby_id()) {
                return Err(Error::Retired);
            }
            if s.lobbies.iter().any(|p| p.lobby == card.lobby_id()) {
                return Err(Error::Invalid);
            }
            if s.lobbies.len() >= MAX_PROFILES {
                return Err(Error::Limit);
            }
            nulllobby_core::domain::LobbyName::new(name).map_err(|_| Error::Invalid)?;
            let upper = current_sequence
                .checked_add(SEQUENCE_BLOCK)
                .ok_or(Error::Limit)?;
            s.lobbies.push(StoredLobby {
                lobby: card.lobby_id(),
                seed,
                card: card.export(),
                name: name.into(),
                upper,
                mailbox: false,
                durable: false,
            });
            Ok(upper)
        })
    }
    pub fn restore(&self, lobby: LobbyId) -> Result<Option<RestoredIdentity>> {
        if self.retired(lobby)? {
            return Err(Error::Retired);
        }
        if !self.read(|s| Ok(s.lobbies.iter().any(|p| p.lobby == lobby)))? {
            return Ok(None);
        }
        self.change(|s| {
            if s.retired.contains(&lobby) {
                return Err(Error::Retired);
            }
            let Some(p) = s.lobbies.iter_mut().find(|p| p.lobby == lobby) else {
                return Ok(None);
            };
            let mut seed = SecretBytes::zeroed().map_err(|_| Error::Io)?;
            seed.expose_secret_mut()
                .copy_from_slice(p.seed.expose_secret());
            let identity = EphemeralIdentity::from_persisted(lobby, seed).map_err(|_| Error::Io)?;
            let start = p.upper;
            p.upper = p.upper.checked_add(SEQUENCE_BLOCK).ok_or(Error::Limit)?;
            Ok(Some((identity, start, p.upper, p.durable, p.mailbox)))
        })
    }
    pub fn reserve(&self, lobby: LobbyId) -> Result<u64> {
        self.change(|s| {
            let p = s.profile_mut(lobby)?;
            p.upper = p.upper.checked_add(SEQUENCE_BLOCK).ok_or(Error::Limit)?;
            Ok(p.upper)
        })
    }
    pub fn settings(&self, lobby: LobbyId, durable: bool, mailbox: bool) -> Result<()> {
        self.change(|s| {
            let p = s.profile_mut(lobby)?;
            p.durable = durable;
            p.mailbox = mailbox;
            if !mailbox {
                s.records
                    .retain(|r| r.lobby != lobby || r.kind != RecordKind::Mailbox);
            }
            Ok(())
        })
    }
    pub fn refresh_card(&self, lobby: LobbyId, card: &LobbyCard) -> Result<()> {
        if card.lobby_id() != lobby {
            return Err(Error::Invalid);
        }
        self.change(|s| {
            s.profile_mut(lobby)?.card = card.export();
            Ok(())
        })
    }
    pub fn records(&self, lobby: LobbyId, now: u64) -> Result<Vec<StoredRecord>> {
        self.read(|s| {
            Ok(s.records
                .iter()
                .filter(|r| r.lobby == lobby && r.expires > now.max(s.clock))
                .cloned()
                .collect())
        })
    }
    pub fn put(&self, record: StoredRecord, now: u64) -> Result<()> {
        self.change(|s| {
            s.expire(now);
            let p = s.profile(record.lobby)?;
            if (record.kind == RecordKind::Mailbox && !p.mailbox)
                || (record.kind == RecordKind::Outbox && !p.durable)
            {
                return Err(Error::Invalid);
            }
            if record.expires <= s.clock || record.expires > now.saturating_add(86460) {
                return Err(Error::Invalid);
            }
            record.validate()?;
            if record.kind == RecordKind::Outbox {
                let mut seed = SecretBytes::zeroed().map_err(|_| Error::Io)?;
                seed.expose_secret_mut()
                    .copy_from_slice(p.seed.expose_secret());
                let identity =
                    EphemeralIdentity::from_persisted(record.lobby, seed).map_err(|_| Error::Io)?;
                if record.message.sender() != &identity.public_key() {
                    return Err(Error::Invalid);
                }
            }
            if s.records.iter().any(|r| {
                r.lobby == record.lobby
                    && r.kind == record.kind
                    && r.message.id() == record.message.id()
                    && r.message.sender() == record.message.sender()
            }) {
                return Ok(());
            }
            if s.records.len() >= MAX_RECORDS
                || s.records
                    .iter()
                    .filter(|r| r.lobby == record.lobby && r.kind == record.kind)
                    .count()
                    >= 128
            {
                return Err(Error::Limit);
            }
            s.records.push(record);
            Ok(())
        })
    }
    pub fn remove_outbox(&self, lobby: LobbyId, id: [u8; 16]) -> Result<()> {
        self.change(|s| {
            s.records.retain(|r| {
                r.lobby != lobby || r.kind != RecordKind::Outbox || r.message.id() != id
            });
            Ok(())
        })
    }
    pub fn seen(
        &self,
        lobby: LobbyId,
        sender: [u8; 32],
        id: [u8; 16],
        sequence: u64,
        expires: u64,
        now: u64,
    ) -> Result<bool> {
        self.change(|s| {
            s.expire(now);
            s.profile(lobby)?;
            if expires <= s.clock {
                return Ok(false);
            }
            if sequence == 0 || expires <= now || expires > now.saturating_add(86460) {
                return Err(Error::Invalid);
            }
            if s.seen.iter().any(|v| {
                v.lobby == lobby && v.sender == sender && (v.id == id || v.sequence == sequence)
            }) {
                return Ok(false);
            }
            if s.seen.len() >= 4096 {
                return Err(Error::Limit);
            }
            s.seen.push(Seen {
                lobby,
                sender,
                id,
                sequence,
                expires,
            });
            Ok(true)
        })
    }
    pub fn retire(&self, lobby: LobbyId) -> Result<()> {
        self.change(|s| {
            if !s.retired.contains(&lobby) {
                if s.retired.len() >= 1024 {
                    return Err(Error::Limit);
                }
                s.retired.push(lobby);
            }
            s.lobbies.retain(|p| p.lobby != lobby);
            s.records.retain(|r| r.lobby != lobby);
            s.seen.retain(|v| v.lobby != lobby);
            Ok(())
        })
    }
    pub fn forget(&self, lobby: LobbyId) -> Result<()> {
        self.change(|s| {
            s.lobbies.retain(|p| p.lobby != lobby);
            s.records.retain(|r| r.lobby != lobby);
            s.seen.retain(|v| v.lobby != lobby);
            Ok(())
        })
    }
    pub fn expire(&self, now: u64) -> Result<()> {
        self.change(|s| {
            s.expire(now);
            Ok(())
        })
    }
    pub fn set_issuer(&self, seed: SecretBytes<32>) -> Result<()> {
        self.change(|s| {
            if s.issuer.is_some() || !s.lobbies.is_empty() {
                return Err(Error::Invalid);
            }
            s.issuer = Some(seed);
            Ok(())
        })
    }
    pub fn issuer(&self) -> Result<SecretBytes<32>> {
        self.read(|s| {
            let seed = s.issuer.as_ref().ok_or(Error::Missing)?;
            let mut copy = SecretBytes::zeroed().map_err(|_| Error::Io)?;
            copy.expose_secret_mut()
                .copy_from_slice(seed.expose_secret());
            Ok(copy)
        })
    }
}
impl Inner {
    fn save(&mut self) -> Result<()> {
        let plain = self.state.encode()?;
        let bytes = seal(self.key.expose_secret(), self.id, &plain)?;
        let parent = self.path.parent().ok_or(Error::Permissions)?;
        let mut rand = [0; 16];
        getrandom::fill(&mut rand).map_err(|_| Error::Io)?;
        let temp = parent.join(format!(".vault-{:032x}.tmp", u128::from_le_bytes(rand)));
        let result = (|| {
            let mut f = private_open(&temp, true, true)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            fs::rename(&temp, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result
    }
}
fn seal(key: &[u8; 32], id: [u8; 16], plain: &[u8]) -> Result<Vec<u8>> {
    if plain.len() > MAX_FILE {
        return Err(Error::Limit);
    }
    let mut bytes = Vec::with_capacity(HEADER + plain.len() + 16);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&id);
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| Error::Io)?;
    bytes.extend_from_slice(&nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Invalid)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plain,
                aad: &bytes,
            },
        )
        .map_err(|_| Error::Invalid)?;
    bytes.extend_from_slice(&ciphertext);
    Ok(bytes)
}
fn open_bytes(key: &[u8; 32], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() < HEADER + 16 || bytes.len() > HEADER + MAX_FILE + 16 || &bytes[..8] != MAGIC {
        return Err(Error::Invalid);
    }
    let nonce: [u8; 24] = bytes[24..HEADER].try_into().map_err(|_| Error::Invalid)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Invalid)?;
    let plain = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &bytes[HEADER..],
                aad: &bytes[..HEADER],
            },
        )
        .map_err(|_| Error::Invalid)?;
    Ok(Zeroizing::new(plain))
}
#[cfg(unix)]
fn check_private(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let uid = fs::metadata("/proc/self")
        .map_err(|_| Error::Permissions)?
        .uid();
    let meta = fs::symlink_metadata(path).map_err(|_| Error::Permissions)?;
    if meta.uid() != uid
        || meta.mode() & 0o077 != 0
        || (directory && !meta.is_dir())
        || (!directory && (!meta.is_file() || meta.nlink() != 1))
    {
        return Err(Error::Permissions);
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_private(_: &Path, _: bool) -> Result<()> {
    Err(Error::Permissions)
}
fn private_open(path: &Path, create: bool, exclusive: bool) -> Result<File> {
    if path.try_exists()? {
        check_private(path, false)?;
    }
    let mut o = OpenOptions::new();
    o.read(true)
        .write(true)
        .create(create)
        .create_new(exclusive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let f = o.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = f.metadata()?;
        let uid = fs::metadata("/proc/self")
            .map_err(|_| Error::Permissions)?
            .uid();
        if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o077 != 0 || meta.uid() != uid {
            return Err(Error::Permissions);
        }
    }
    check_private(path, false)?;
    Ok(f)
}
fn read_private(path: &Path, limit: usize) -> Result<Vec<u8>> {
    check_private(path, false)?;
    let f = private_open(path, false, false)?;
    if f.metadata()?.len() > limit as u64 {
        return Err(Error::Limit);
    }
    let mut bytes = Vec::new();
    f.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Limit);
    }
    Ok(bytes)
}

/// Decoder surface for coverage-guided fuzzing; never opens files or keyrings.
#[cfg(feature = "fuzzing")]
pub fn validate_snapshot(bytes: &[u8]) -> Result<()> {
    state::State::decode(bytes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nulllobby_core::{
        TransportKind,
        message::{Payload, SignedMessage},
        text::ValidatedText,
    };
    struct Keys;
    impl keyring::KeyProvider for Keys {
        fn create(&self, _: &[u8; 16], key: &[u8; 32]) -> Result<()> {
            self._store(key);
            Ok(())
        }
        fn load(&self, _: &[u8; 16]) -> Result<SecretBytes<32>> {
            let mut k = SecretBytes::zeroed().unwrap();
            k.expose_secret_mut()
                .copy_from_slice(&KEY.with(|k| *k.borrow()));
            Ok(k)
        }
    }
    thread_local! {static KEY:std::cell::RefCell<[u8;32]>=const{std::cell::RefCell::new([0;32])};}
    impl Keys {
        fn _store(&self, key: &[u8; 32]) {
            KEY.with(|k| *k.borrow_mut() = *key);
        }
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut r = [0; 16];
            getrandom::fill(&mut r).unwrap();
            Self(std::env::temp_dir().join(format!(
                "nulllobby-vault-test-{:032x}",
                u128::from_le_bytes(r)
            )))
        }
        fn file(&self) -> PathBuf {
            self.0.join("state.vault")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn encrypted_restart_keeps_only_selected_identity_and_reserves_sequence_ranges() {
        let dir = Temp::new();
        let provider = Keys;
        let v = Vault::open(&dir.file(), true, &provider).unwrap();
        let card = LobbyCard::private(TransportKind::Direct, vec![]).unwrap();
        let id = EphemeralIdentity::generate(card.lobby_id()).unwrap();
        let noise = id.noise_public_key();
        let upper = v
            .remember(&id, &card, "Synthetic stored lobby", 50)
            .unwrap();
        let disk = fs::read(dir.file()).unwrap();
        assert!(!disk.windows(22).any(|w| w == b"Synthetic stored lobby"));
        assert!(
            !disk
                .windows(32)
                .any(|w| w == id.persistence_seed().unwrap().expose_secret())
        );
        assert!(matches!(
            Vault::open(&dir.file(), false, &provider),
            Err(Error::Locked)
        ));
        drop(v);
        let v = Vault::open(&dir.file(), false, &provider).unwrap();
        let (restored, start, end, _, _) = v.restore(card.lobby_id()).unwrap().unwrap();
        assert_eq!(restored.public_key(), id.public_key());
        assert_ne!(restored.noise_public_key(), noise);
        assert_eq!(start, upper);
        assert_eq!(end, upper + SEQUENCE_BLOCK);
        assert!(
            v.restore(LobbyId::random_public().unwrap())
                .unwrap()
                .is_none()
        );
        v.retire(card.lobby_id()).unwrap();
        assert!(matches!(v.restore(card.lobby_id()), Err(Error::Retired)));
    }
    #[test]
    fn mailbox_only_retains_explicit_durable_records_and_expiry_removes_them() {
        let dir = Temp::new();
        let v = Vault::open(&dir.file(), true, &Keys).unwrap();
        let card = LobbyCard::public(TransportKind::Direct, vec![]).unwrap();
        let id = EphemeralIdentity::generate(card.lobby_id()).unwrap();
        v.remember(&id, &card, "test", 0).unwrap();
        v.settings(card.lobby_id(), false, true).unwrap();
        let message = SignedMessage::new(
            &id,
            1,
            Payload::DurableChat {
                body: ValidatedText::new("stored synthetic body").unwrap(),
                created: 1000,
                expires: 2000,
            },
        )
        .unwrap();
        v.put(
            StoredRecord {
                lobby: card.lobby_id(),
                kind: RecordKind::Mailbox,
                expires: 2000,
                message: message.clone(),
            },
            1000,
        )
        .unwrap();
        assert!(
            v.seen(
                card.lobby_id(),
                id.public_key(),
                message.id(),
                1,
                2000,
                1000
            )
            .unwrap()
        );
        assert!(
            !v.seen(
                card.lobby_id(),
                id.public_key(),
                message.id(),
                1,
                2000,
                1000
            )
            .unwrap()
        );
        let live = SignedMessage::new(
            &id,
            2,
            Payload::Chat(ValidatedText::new("never store live").unwrap()),
        )
        .unwrap();
        assert!(
            v.put(
                StoredRecord {
                    lobby: card.lobby_id(),
                    kind: RecordKind::Mailbox,
                    expires: 2000,
                    message: live
                },
                1000
            )
            .is_err()
        );
        assert_eq!(v.records(card.lobby_id(), 1000).unwrap().len(), 1);
        v.expire(2000).unwrap();
        assert!(v.records(card.lobby_id(), 2000).unwrap().is_empty());
        drop(v);
        let v = Vault::open(&dir.file(), false, &Keys).unwrap();
        assert!(v.records(card.lobby_id(), 1000).unwrap().is_empty());
        assert!(
            !v.seen(
                card.lobby_id(),
                id.public_key(),
                message.id(),
                1,
                2000,
                1000
            )
            .unwrap()
        );
    }
    #[test]
    fn mailbox_quota_rejects_new_records_without_evicting_unexpired_work() {
        let dir = Temp::new();
        let v = Vault::open(&dir.file(), true, &Keys).unwrap();
        let card = LobbyCard::private(TransportKind::Direct, vec![]).unwrap();
        let identity = EphemeralIdentity::generate(card.lobby_id()).unwrap();
        v.remember(&identity, &card, "quota", 0).unwrap();
        v.settings(card.lobby_id(), false, true).unwrap();
        for sequence in 1..=129 {
            let message = SignedMessage::new(
                &identity,
                sequence,
                Payload::DurableChat {
                    body: ValidatedText::new("quota synthetic").unwrap(),
                    created: 1000,
                    expires: 2000,
                },
            )
            .unwrap();
            let result = v.put(
                StoredRecord {
                    lobby: card.lobby_id(),
                    kind: RecordKind::Mailbox,
                    expires: 2000,
                    message,
                },
                1000,
            );
            if sequence <= 128 {
                result.unwrap();
            } else {
                assert!(matches!(result, Err(Error::Limit)));
            }
        }
        assert_eq!(v.records(card.lobby_id(), 1000).unwrap().len(), 128);
        v.settings(card.lobby_id(), false, false).unwrap();
        assert!(v.records(card.lobby_id(), 1000).unwrap().is_empty());
    }
    #[test]
    fn unavailable_key_provider_cannot_open_or_create_a_plaintext_fallback() {
        struct Locked;
        impl keyring::KeyProvider for Locked {
            fn create(&self, _: &[u8; 16], _: &[u8; 32]) -> Result<()> {
                Err(Error::Keyring)
            }
            fn load(&self, _: &[u8; 16]) -> Result<SecretBytes<32>> {
                Err(Error::Keyring)
            }
        }
        let dir = Temp::new();
        assert!(matches!(
            Vault::open(&dir.file(), true, &Locked),
            Err(Error::Keyring)
        ));
        assert!(!dir.file().exists());
        let vault = Vault::open(&dir.file(), true, &Keys).unwrap();
        drop(vault);
        assert!(matches!(
            Vault::open(&dir.file(), false, &Locked),
            Err(Error::Keyring)
        ));
    }
    #[test]
    fn aead_binds_header_key_nonce_and_ciphertext() {
        let bytes = seal(&[7; 32], [8; 16], b"private synthetic state").unwrap();
        assert_eq!(
            open_bytes(&[7; 32], &bytes).unwrap().as_slice(),
            b"private synthetic state"
        );
        assert!(open_bytes(&[6; 32], &bytes).is_err());
        for i in 0..bytes.len() {
            let mut altered = bytes.clone();
            altered[i] ^= 1;
            assert!(open_bytes(&[7; 32], &altered).is_err());
        }
        assert_ne!(
            bytes,
            seal(&[7; 32], [8; 16], b"private synthetic state").unwrap()
        );
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn public_readable_files_and_symlinks_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = Temp::new();
        let v = Vault::open(&dir.file(), true, &Keys).unwrap();
        drop(v);
        fs::set_permissions(dir.file(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Vault::open(&dir.file(), false, &Keys).is_err());
        fs::set_permissions(dir.file(), fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.0.join("link.vault");
        symlink(dir.file(), &link).unwrap();
        assert!(Vault::open(&link, false, &Keys).is_err());
    }
}
