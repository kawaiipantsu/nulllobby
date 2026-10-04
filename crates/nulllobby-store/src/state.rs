use crate::{Error, MAX_FILE, MAX_PROFILES, MAX_RECORDS, Result};
use minicbor::{Decoder, Encoder};
use nulllobby_core::{LobbyCard, LobbyId, message::SignedMessage};
use nulllobby_platform::SecretBytes;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

pub struct StoredLobby {
    pub lobby: LobbyId,
    pub(crate) seed: SecretBytes<32>,
    pub(crate) card: SecretString,
    pub name: String,
    pub upper: u64,
    pub mailbox: bool,
    pub durable: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Outbox,
    Mailbox,
}
#[derive(Clone)]
pub struct StoredRecord {
    pub lobby: LobbyId,
    pub kind: RecordKind,
    pub expires: u64,
    pub message: SignedMessage,
}
impl StoredRecord {
    pub fn validate(&self) -> Result<()> {
        self.message
            .verify(self.lobby)
            .map_err(|_| Error::Invalid)?;
        let nulllobby_core::message::Payload::DurableChat { expires, .. } = self.message.payload()
        else {
            return Err(Error::Invalid);
        };
        if *expires != self.expires {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
pub struct Seen {
    pub lobby: LobbyId,
    pub sender: [u8; 32],
    pub id: [u8; 16],
    pub sequence: u64,
    pub expires: u64,
}
#[derive(Default)]
pub(crate) struct State {
    pub clock: u64,
    pub lobbies: Vec<StoredLobby>,
    pub records: Vec<StoredRecord>,
    pub seen: Vec<Seen>,
    pub retired: Vec<LobbyId>,
    pub issuer: Option<SecretBytes<32>>,
}
impl State {
    pub fn profile(&self, id: LobbyId) -> Result<&StoredLobby> {
        self.lobbies
            .iter()
            .find(|p| p.lobby == id)
            .ok_or(Error::Missing)
    }
    pub fn profile_mut(&mut self, id: LobbyId) -> Result<&mut StoredLobby> {
        self.lobbies
            .iter_mut()
            .find(|p| p.lobby == id)
            .ok_or(Error::Missing)
    }
    pub fn expire(&mut self, now: u64) {
        self.clock = self.clock.max(now);
        self.records.retain(|r| r.expires > self.clock);
        self.seen.retain(|r| r.expires > self.clock);
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(Vec::new());
        {
            let mut e = Encoder::new(&mut *bytes);
            e.array(7)?
                .u8(1)?
                .u64(self.clock)?
                .array(self.lobbies.len() as u64)?;
            for p in &self.lobbies {
                e.array(7)?
                    .bytes(p.lobby.as_bytes())?
                    .bytes(p.seed.expose_secret())?
                    .str(p.card.expose_secret())?
                    .str(&p.name)?
                    .u64(p.upper)?
                    .bool(p.durable)?
                    .bool(p.mailbox)?;
            }
            e.array(self.records.len() as u64)?;
            for r in &self.records {
                e.array(4)?
                    .bytes(r.lobby.as_bytes())?
                    .u8(if r.kind == RecordKind::Outbox { 0 } else { 1 })?
                    .u64(r.expires)?
                    .bytes(&r.message.encode().map_err(|_| Error::Invalid)?)?;
            }
            e.array(self.seen.len() as u64)?;
            for s in &self.seen {
                e.array(5)?
                    .bytes(s.lobby.as_bytes())?
                    .bytes(&s.sender)?
                    .bytes(&s.id)?
                    .u64(s.sequence)?
                    .u64(s.expires)?;
            }
            e.array(self.retired.len() as u64)?;
            for id in &self.retired {
                e.bytes(id.as_bytes())?;
            }
            if let Some(seed) = &self.issuer {
                e.bytes(seed.expose_secret())?;
            } else {
                e.bytes(&[])?;
            }
        }
        if bytes.len() > MAX_FILE {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FILE {
            return Err(Error::Limit);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 7)?;
        if d.u8()? != 1 {
            return Err(Error::Invalid);
        }
        let mut s = Self {
            clock: d.u64()?,
            ..Self::default()
        };
        for _ in 0..count(&mut d, MAX_PROFILES)? {
            array(&mut d, 7)?;
            let lobby = LobbyId::from_bytes(fixed(&mut d)?);
            let mut seed = SecretBytes::zeroed().map_err(|_| Error::Io)?;
            seed.expose_secret_mut()
                .copy_from_slice(&fixed::<32>(&mut d)?);
            let card = d.str()?;
            let parsed = LobbyCard::parse(card).map_err(|_| Error::Invalid)?;
            if parsed.lobby_id() != lobby || s.lobbies.iter().any(|p| p.lobby == lobby) {
                return Err(Error::Invalid);
            }
            let name =
                nulllobby_core::domain::LobbyName::new(d.str()?).map_err(|_| Error::Invalid)?;
            s.lobbies.push(StoredLobby {
                lobby,
                seed,
                card: SecretString::from(card),
                name: name.as_str().into(),
                upper: d.u64()?,
                durable: d.bool()?,
                mailbox: d.bool()?,
            });
        }
        for _ in 0..count(&mut d, MAX_RECORDS)? {
            array(&mut d, 4)?;
            let lobby = LobbyId::from_bytes(fixed(&mut d)?);
            s.profile(lobby)?;
            let kind = match d.u8()? {
                0 => RecordKind::Outbox,
                1 => RecordKind::Mailbox,
                _ => return Err(Error::Invalid),
            };
            let expires = d.u64()?;
            let message = SignedMessage::decode(d.bytes()?).map_err(|_| Error::Invalid)?;
            let record = StoredRecord {
                lobby,
                kind,
                expires,
                message,
            };
            record.validate()?;
            s.records.push(record);
        }
        for _ in 0..count(&mut d, 4096)? {
            array(&mut d, 5)?;
            let lobby = LobbyId::from_bytes(fixed(&mut d)?);
            s.profile(lobby)?;
            s.seen.push(Seen {
                lobby,
                sender: fixed(&mut d)?,
                id: fixed(&mut d)?,
                sequence: d.u64()?,
                expires: d.u64()?,
            });
        }
        for _ in 0..count(&mut d, 1024)? {
            let id = LobbyId::from_bytes(fixed(&mut d)?);
            if s.retired.contains(&id) || s.lobbies.iter().any(|p| p.lobby == id) {
                return Err(Error::Invalid);
            }
            s.retired.push(id);
        }
        let seed = d.bytes()?;
        if !seed.is_empty() {
            if seed.len() != 32 || !s.lobbies.is_empty() {
                return Err(Error::Invalid);
            }
            let mut k = SecretBytes::zeroed().map_err(|_| Error::Io)?;
            k.expose_secret_mut().copy_from_slice(seed);
            s.issuer = Some(k);
        }
        if d.position() != bytes.len() || s.encode()?.as_slice() != bytes {
            return Err(Error::Invalid);
        }
        Ok(s)
    }
}
fn count(d: &mut Decoder<'_>, max: usize) -> Result<usize> {
    let n = d.array()?.ok_or(Error::Invalid)?;
    if n > max as u64 {
        return Err(Error::Limit);
    }
    Ok(n as usize)
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array()? != Some(n) {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()?.try_into().map_err(|_| Error::Invalid)
}
