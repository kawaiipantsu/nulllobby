//! Strict, flat, versioned binary cards. The checksum is not authentication.
use crate::{LobbyId, LobbyKind, PrivateLobbySecret, SecretError, limits};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nulllobby_transport::{Endpoint, TransportKind};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 3] = b"NLC";
const VERSION: u8 = 2;
const CHECKSUM_DOMAIN: &[u8] = b"nulllobby.card-checksum.v1";

pub struct LobbyCard {
    transport: TransportKind,
    kind: LobbyKind,
    lobby: LobbyId,
    secret: Option<PrivateLobbySecret>,
    seeds: Vec<Endpoint>,
    administrator: Option<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum CardError {
    #[error("lobby card exceeds limits")]
    Limit,
    #[error("malformed lobby card")]
    Malformed,
    #[error("unsupported lobby card version or type")]
    Unsupported,
    #[error("lobby card checksum mismatch")]
    Checksum,
    #[error("inconsistent lobby card fields")]
    Inconsistent,
    #[error("lobby card secret operation failed")]
    Secret(#[from] SecretError),
}

impl LobbyCard {
    /// ASCII-only discoverable names: trim ASCII whitespace, lowercase, 1..64
    /// bytes from a-z, 0-9, '-' and '_'. No Unicode normalization ambiguity.
    pub fn discoverable(name: &str) -> Result<Self, CardError> {
        let normalized = name
            .trim_matches(|c: char| c.is_ascii_whitespace())
            .to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.len() > 64
            || !normalized
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(CardError::Malformed);
        }
        let mut hash = Sha256::new();
        hash.update(b"nulllobby.discoverable.v1");
        hash.update([normalized.len() as u8]);
        hash.update(normalized.as_bytes());
        Self::checked(
            TransportKind::Direct,
            LobbyKind::PublicDiscoverable,
            LobbyId::from_bytes(hash.finalize().into()),
            None,
            vec![],
        )
    }
    pub fn set_seeds(&mut self, seeds: Vec<Endpoint>) -> Result<(), CardError> {
        if seeds.len() > limits::CARD_SEEDS
            || (self.transport == TransportKind::Tor && seeds.is_empty())
        {
            return Err(CardError::Limit);
        }
        for (i, seed) in seeds.iter().enumerate() {
            if seed.transport() != self.transport || seeds[..i].contains(seed) {
                return Err(CardError::Inconsistent);
            }
        }
        self.seeds = seeds;
        Ok(())
    }
    pub fn discovery_scope(&self) -> Result<[u8; 32], SecretError> {
        if let Some(keys) = self.private_keys()? {
            return Ok(*keys.discovery.expose_secret());
        }
        let mut hash = Sha256::new();
        hash.update(b"nulllobby.public-discovery.v1");
        hash.update(self.lobby.as_bytes());
        Ok(hash.finalize().into())
    }
    pub fn public(transport: TransportKind, seeds: Vec<Endpoint>) -> Result<Self, CardError> {
        Self::checked(
            transport,
            LobbyKind::PublicUnlisted,
            LobbyId::random_public()?,
            None,
            seeds,
        )
    }
    pub fn private(transport: TransportKind, seeds: Vec<Endpoint>) -> Result<Self, CardError> {
        let secret = PrivateLobbySecret::generate()?;
        let lobby = secret.derive()?.lobby_id;
        Self::checked(transport, LobbyKind::Private, lobby, Some(secret), seeds)
    }
    fn checked(
        transport: TransportKind,
        kind: LobbyKind,
        lobby: LobbyId,
        secret: Option<PrivateLobbySecret>,
        seeds: Vec<Endpoint>,
    ) -> Result<Self, CardError> {
        if seeds.len() > limits::CARD_SEEDS {
            return Err(CardError::Limit);
        }
        if kind == LobbyKind::PublicDiscoverable && transport == TransportKind::Tor {
            return Err(CardError::Unsupported);
        }
        if (kind == LobbyKind::Private) != secret.is_some() {
            return Err(CardError::Inconsistent);
        }
        if transport == TransportKind::Tor && seeds.is_empty() {
            return Err(CardError::Inconsistent);
        }
        for (i, seed) in seeds.iter().enumerate() {
            if seed.transport() != transport || seeds[..i].contains(seed) {
                return Err(CardError::Inconsistent);
            }
        }
        if let Some(secret) = &secret
            && secret.derive()?.lobby_id != lobby
        {
            return Err(CardError::Inconsistent);
        }
        Ok(Self {
            transport,
            kind,
            lobby,
            secret,
            seeds,
            administrator: None,
        })
    }
    pub fn lobby_id(&self) -> LobbyId {
        self.lobby
    }
    pub fn transport(&self) -> TransportKind {
        self.transport
    }
    pub fn kind(&self) -> LobbyKind {
        self.kind
    }
    pub fn seeds(&self) -> &[Endpoint] {
        &self.seeds
    }
    pub fn administrator(&self) -> Option<[u8; 32]> {
        self.administrator
    }
    pub fn set_administrator(&mut self, key: [u8; 32]) -> Result<(), CardError> {
        if self.kind != LobbyKind::Private
            || self.administrator.is_some()
            || ed25519_dalek::VerifyingKey::from_bytes(&key).map_or(true, |k| k.is_weak())
        {
            return Err(CardError::Inconsistent);
        }
        self.administrator = Some(key);
        Ok(())
    }
    pub fn private_keys(&self) -> Result<Option<crate::secret::PrivateLobbyKeys>, SecretError> {
        self.secret
            .as_ref()
            .map(PrivateLobbySecret::derive)
            .transpose()
    }
    fn prefix(&self) -> &'static str {
        match (self.transport, self.kind) {
            (TransportKind::Direct, LobbyKind::PublicUnlisted) => "nl:v2:direct-public:",
            (TransportKind::Direct, LobbyKind::Private) => "nl:v2:direct-private:",
            (TransportKind::Tor, LobbyKind::PublicUnlisted) => "nl:v2:tor-public:",
            (TransportKind::Tor, LobbyKind::Private) => "nl:v2:tor-private:",
            (TransportKind::Direct, LobbyKind::PublicDiscoverable) => "nl:v2:direct-discoverable:",
            (TransportKind::Tor, LobbyKind::PublicDiscoverable) => {
                unreachable!("validated card kind")
            }
        }
    }
    /// Explicit disclosure only. Never automatically print or copy this value.
    /// Once displayed, terminal scrollback/clipboard managers are outside our boundary.
    pub fn export(&self) -> SecretString {
        let mut bytes = Zeroizing::new(Vec::with_capacity(limits::CARD_BINARY_BYTES));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&[VERSION, self.transport as u8, self.kind as u8]);
        bytes.extend_from_slice(self.lobby.as_bytes());
        if let Some(secret) = &self.secret {
            bytes.extend_from_slice(secret.bytes());
        }
        bytes.push(self.seeds.len() as u8);
        for seed in &self.seeds {
            match seed {
                Endpoint::Direct { address, port } => {
                    match address {
                        IpAddr::V4(ip) => {
                            bytes.push(4);
                            bytes.extend_from_slice(&ip.octets());
                        }
                        IpAddr::V6(ip) => {
                            bytes.push(6);
                            bytes.extend_from_slice(&ip.octets());
                        }
                    }
                    bytes.extend_from_slice(&port.get().to_be_bytes());
                }
                Endpoint::Onion { service_key, port } => {
                    bytes.push(3);
                    bytes.extend_from_slice(service_key);
                    bytes.extend_from_slice(&port.get().to_be_bytes());
                }
            }
        }
        bytes.push(u8::from(self.administrator.is_some()));
        if let Some(key) = self.administrator {
            bytes.extend_from_slice(&key);
        }
        let checksum = checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        let mut output = Zeroizing::new(String::with_capacity(limits::CARD_TEXT_BYTES));
        output.push_str(self.prefix());
        URL_SAFE_NO_PAD.encode_string(&*bytes, &mut output);
        SecretString::from(output.as_str())
    }

    /// Does not echo input on errors. Allocation and work are bounded before base64 decoding.
    pub fn parse(input: &str) -> Result<Self, CardError> {
        if input.len() > limits::CARD_TEXT_BYTES {
            return Err(CardError::Limit);
        }
        let mut parts = input.splitn(4, ':');
        if parts.next() != Some("nl") || parts.next() != Some("v2") {
            return Err(CardError::Unsupported);
        }
        let label = parts.next().ok_or(CardError::Malformed)?;
        let data = parts.next().ok_or(CardError::Malformed)?;
        if data.len() > limits::CARD_BINARY_BYTES * 4 / 3 + 3 {
            return Err(CardError::Limit);
        }
        let mut buffer = Zeroizing::new([0; limits::CARD_BINARY_BYTES]);
        let len = URL_SAFE_NO_PAD
            .decode_slice(data, buffer.as_mut())
            .map_err(|_| CardError::Malformed)?;
        let bytes = &buffer[..len];
        let checksum_at = len.checked_sub(32).ok_or(CardError::Malformed)?;
        if checksum(&bytes[..checksum_at]) != bytes[checksum_at..] {
            return Err(CardError::Checksum);
        }
        let mut reader = Reader {
            bytes: &bytes[..checksum_at],
            offset: 0,
        };
        if reader.take(3)? != MAGIC {
            return Err(CardError::Malformed);
        }
        if reader.byte()? != VERSION {
            return Err(CardError::Unsupported);
        }
        let transport = match reader.byte()? {
            1 => TransportKind::Direct,
            2 => TransportKind::Tor,
            _ => return Err(CardError::Unsupported),
        };
        let kind = match reader.byte()? {
            1 => LobbyKind::PublicUnlisted,
            2 => LobbyKind::Private,
            3 => LobbyKind::PublicDiscoverable,
            _ => return Err(CardError::Unsupported),
        };
        let lobby = LobbyId::from_bytes(reader.array()?);
        let secret = if kind == LobbyKind::Private {
            let raw: &[u8; 32] = reader
                .take(32)?
                .try_into()
                .map_err(|_| CardError::Malformed)?;
            Some(PrivateLobbySecret::from_bytes(raw)?)
        } else {
            None
        };
        let count = usize::from(reader.byte()?);
        if count > limits::CARD_SEEDS {
            return Err(CardError::Limit);
        }
        let mut seeds = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = reader.byte()?;
            let seed = match (transport, tag) {
                (TransportKind::Direct, 4) => Endpoint::Direct {
                    address: IpAddr::V4(Ipv4Addr::from(reader.array::<4>()?)),
                    port: reader.port()?,
                },
                (TransportKind::Direct, 6) => Endpoint::Direct {
                    address: IpAddr::V6(Ipv6Addr::from(reader.array::<16>()?)),
                    port: reader.port()?,
                },
                (TransportKind::Tor, 3) => Endpoint::Onion {
                    service_key: reader.array()?,
                    port: reader.port()?,
                },
                _ => return Err(CardError::Inconsistent),
            };
            seeds.push(seed);
        }
        let administrator = match reader.byte()? {
            0 => None,
            1 => Some(reader.array()?),
            _ => return Err(CardError::Malformed),
        };
        if reader.offset != reader.bytes.len() {
            return Err(CardError::Malformed);
        }
        let mut card = Self::checked(transport, kind, lobby, secret, seeds)?;
        if let Some(key) = administrator {
            card.set_administrator(key)?;
        }
        if card.prefix().split(':').nth(2) != Some(label) {
            return Err(CardError::Inconsistent);
        }
        Ok(card)
    }
}
impl fmt::Debug for LobbyCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LobbyCard")
            .field("transport", &self.transport)
            .field("kind", &self.kind)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], CardError> {
        let end = self.offset.checked_add(count).ok_or(CardError::Limit)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(CardError::Malformed)?;
        self.offset = end;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, CardError> {
        Ok(self.take(1)?[0])
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CardError> {
        self.take(N)?.try_into().map_err(|_| CardError::Malformed)
    }
    fn port(&mut self) -> Result<NonZeroU16, CardError> {
        NonZeroU16::new(u16::from_be_bytes(self.array()?)).ok_or(CardError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    #[test]
    fn discoverable_names_are_precise_and_cards_preserve_warning_type() {
        let a = LobbyCard::discoverable("  Team-1\t").unwrap();
        let b = LobbyCard::discoverable("team-1").unwrap();
        assert_eq!(a.lobby_id(), b.lobby_id());
        assert_ne!(
            a.lobby_id(),
            LobbyCard::discoverable("team-2").unwrap().lobby_id()
        );
        assert_eq!(
            LobbyCard::parse(a.export().expose_secret()).unwrap().kind(),
            LobbyKind::PublicDiscoverable
        );
        for invalid in ["", "équipe", "team name", "team/name", "a\x1b"] {
            assert!(LobbyCard::discoverable(invalid).is_err());
        }
    }
    fn onion() -> Endpoint {
        Endpoint::Onion {
            service_key: [7; 32],
            port: NonZeroU16::new(80).unwrap(),
        }
    }
    fn direct() -> Endpoint {
        Endpoint::Direct {
            address: "127.0.0.1".parse().unwrap(),
            port: NonZeroU16::new(50000).unwrap(),
        }
    }
    fn mutate(card: &LobbyCard, edit: impl FnOnce(&mut Vec<u8>)) -> SecretString {
        let exported = card.export();
        let mut bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(exported.expose_secret().rsplit(':').next().unwrap())
                .unwrap(),
        );
        let body_len = bytes.len() - 32;
        bytes.truncate(body_len);
        edit(&mut bytes);
        let sum = checksum(&bytes);
        bytes.extend_from_slice(&sum);
        let mut text = card.prefix().to_owned();
        URL_SAFE_NO_PAD.encode_string(&*bytes, &mut text);
        text.into()
    }
    #[test]
    fn all_card_types_roundtrip_canonically() {
        for mode in [TransportKind::Direct, TransportKind::Tor] {
            for private in [false, true] {
                let seeds = vec![if mode == TransportKind::Direct {
                    direct()
                } else {
                    onion()
                }];
                let card = if private {
                    LobbyCard::private(mode, seeds)
                } else {
                    LobbyCard::public(mode, seeds)
                }
                .unwrap();
                let encoded = card.export();
                let decoded = LobbyCard::parse(encoded.expose_secret()).unwrap();
                assert_eq!(decoded.lobby_id(), card.lobby_id());
                assert_eq!(decoded.seeds(), card.seeds());
                assert_eq!(decoded.transport(), mode);
                assert_eq!(decoded.export().expose_secret(), encoded.expose_secret());
                assert_eq!(decoded.secret.is_some(), private);
                assert!(!format!("{card:?}").contains(encoded.expose_secret()));
            }
        }
    }
    #[test]
    fn rejects_truncation_corruption_noncanonical_text_and_oversize() {
        let card = LobbyCard::private(TransportKind::Direct, vec![]).unwrap();
        let encoded = card.export();
        for len in 0..encoded.expose_secret().len() {
            assert!(LobbyCard::parse(&encoded.expose_secret()[..len]).is_err());
        }
        for suffix in ["=", " ", "\n", ":"] {
            let malformed = Zeroizing::new(format!("{}{suffix}", encoded.expose_secret()));
            assert!(LobbyCard::parse(&malformed).is_err());
        }
        let mut broken = Zeroizing::new(encoded.expose_secret().as_bytes().to_vec());
        let last = broken.len() - 4;
        broken[last] = if broken[last] == b'A' { b'B' } else { b'A' };
        assert!(LobbyCard::parse(std::str::from_utf8(&broken).unwrap()).is_err());
        assert!(LobbyCard::parse(&"A".repeat(limits::CARD_TEXT_BYTES + 1)).is_err());
    }
    #[test]
    fn valid_checksums_cannot_bypass_semantic_checks() {
        let card = LobbyCard::private(TransportKind::Direct, vec![direct()]).unwrap();
        for field in [3, 4, 5, 6, 38, 70, 71] {
            let corrupted = mutate(&card, |bytes| bytes[field] ^= 0xff);
            assert!(
                LobbyCard::parse(corrupted.expose_secret()).is_err(),
                "field {field}"
            );
        }
        let extra = mutate(&card, |bytes| bytes.push(0));
        assert!(LobbyCard::parse(extra.expose_secret()).is_err());
        let port_zero = mutate(&card, |bytes| {
            let end = bytes.len();
            bytes[end - 3..end - 1].fill(0); // Port precedes the administrator flag.
        });
        assert!(LobbyCard::parse(port_zero.expose_secret()).is_err());
    }
    #[test]
    fn endpoints_are_bounded_mode_specific_and_unique() {
        assert!(LobbyCard::public(TransportKind::Tor, vec![]).is_err());
        assert!(LobbyCard::public(TransportKind::Tor, vec![direct()]).is_err());
        assert!(LobbyCard::public(TransportKind::Direct, vec![onion()]).is_err());
        assert!(LobbyCard::public(TransportKind::Direct, vec![direct(); 2]).is_err());
        assert!(
            LobbyCard::public(TransportKind::Tor, vec![onion(); limits::CARD_SEEDS + 1]).is_err()
        );
        let seeds: Vec<_> = (1..=limits::CARD_SEEDS)
            .map(|i| Endpoint::Onion {
                service_key: [i as u8; 32],
                port: NonZeroU16::new(80).unwrap(),
            })
            .collect();
        let maximum = LobbyCard::private(TransportKind::Tor, seeds)
            .unwrap()
            .export();
        assert!(maximum.expose_secret().len() <= limits::CARD_TEXT_BYTES);
        assert!(LobbyCard::parse(maximum.expose_secret()).is_ok());
    }
    #[test]
    fn ipv6_roundtrip_and_prefix_binding() {
        let card = LobbyCard::public(
            TransportKind::Direct,
            vec![Endpoint::Direct {
                address: "::1".parse().unwrap(),
                port: NonZeroU16::new(42).unwrap(),
            }],
        )
        .unwrap();
        let encoded = card.export();
        assert_eq!(
            LobbyCard::parse(encoded.expose_secret()).unwrap().seeds(),
            card.seeds()
        );
        assert!(
            LobbyCard::parse(
                &encoded
                    .expose_secret()
                    .replace("direct-public", "tor-public")
            )
            .is_err()
        );
    }
    #[test]
    fn arbitrary_short_inputs_do_not_panic() {
        for byte in 0..=255u8 {
            let input = format!(
                "nl:v2:direct-public:{}",
                URL_SAFE_NO_PAD.encode([byte; 128])
            );
            assert!(LobbyCard::parse(&input).is_err());
        }
    }
}
