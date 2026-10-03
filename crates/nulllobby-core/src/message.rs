//! Canonical, bounded CBOR and Ed25519 signed logical lobby messages.
use crate::{
    EphemeralIdentity, LobbyId,
    domain::{LobbyName, Nickname},
    identity, limits,
    text::ValidatedText,
};
use minicbor::{Decoder, Encoder};
use std::convert::Infallible;

pub const MAX_MESSAGE_BYTES: usize = 12_288;
const DOMAIN: &str = "nulllobby.message.v1";
#[derive(Clone)]
pub enum Payload {
    Join {
        nickname: Nickname,
        name: LobbyName,
    },
    Chat(ValidatedText<{ limits::CHAT_BYTES }>),
    Leave,
    Endpoint {
        service_key: [u8; 32],
        port: u16,
        expires: u64,
    },
}
#[derive(Clone)]
pub struct SignedMessage {
    lobby: LobbyId,
    sender: [u8; 32],
    sequence: u64,
    id: [u8; 16],
    payload: Payload,
    signature: [u8; 64],
}
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum MessageError {
    #[error("invalid application encoding")]
    Encoding,
    #[error("unsupported application version")]
    Version,
    #[error("application message resource limit")]
    Limit,
    #[error("application signature or lobby mismatch")]
    Authentication,
    #[error("application entropy unavailable")]
    Entropy,
}
impl From<minicbor::decode::Error> for MessageError {
    fn from(_: minicbor::decode::Error) -> Self {
        Self::Encoding
    }
}
impl From<minicbor::encode::Error<Infallible>> for MessageError {
    fn from(_: minicbor::encode::Error<Infallible>) -> Self {
        Self::Encoding
    }
}

impl SignedMessage {
    pub fn new(
        identity: &EphemeralIdentity,
        sequence: u64,
        payload: Payload,
    ) -> Result<Self, MessageError> {
        if sequence == 0 {
            return Err(MessageError::Encoding);
        }
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| MessageError::Entropy)?;
        let mut message = Self {
            lobby: identity.lobby(),
            sender: identity.public_key(),
            sequence,
            id,
            payload,
            signature: [0; 64],
        };
        message.signature = identity.sign(&message.unsigned()?);
        Ok(message)
    }
    pub fn sender(&self) -> &[u8; 32] {
        &self.sender
    }
    pub fn lobby(&self) -> LobbyId {
        self.lobby
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn id(&self) -> [u8; 16] {
        self.id
    }
    pub fn payload(&self) -> &Payload {
        &self.payload
    }
    fn unsigned(&self) -> Result<Vec<u8>, MessageError> {
        let mut e = Encoder::new(Vec::with_capacity(256));
        e.array(8)?
            .str(DOMAIN)?
            .u16(1)?
            .bytes(self.lobby.as_bytes())?
            .bytes(&self.sender)?
            .u64(self.sequence)?
            .bytes(&self.id)?;
        match &self.payload {
            Payload::Join { nickname, name } => {
                e.u8(1)?
                    .array(2)?
                    .str(nickname.as_str())?
                    .str(name.as_str())?;
            }
            Payload::Chat(body) => {
                e.u8(2)?.str(body.as_str())?;
            }
            Payload::Leave => {
                e.u8(3)?.array(0)?;
            }
            Payload::Endpoint {
                service_key,
                port,
                expires,
            } => {
                if *port == 0 {
                    return Err(MessageError::Encoding);
                }
                e.u8(4)?
                    .array(3)?
                    .bytes(service_key)?
                    .u16(*port)?
                    .u64(*expires)?;
            }
        }
        Ok(e.into_writer())
    }
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut e = Encoder::new(Vec::with_capacity(256));
        e.array(2)?
            .bytes(&self.unsigned()?)?
            .bytes(&self.signature)?;
        let output = e.into_writer();
        if output.len() > MAX_MESSAGE_BYTES {
            return Err(MessageError::Limit);
        }
        Ok(output)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(MessageError::Limit);
        }
        let mut outer = Decoder::new(bytes);
        array(&mut outer, 2)?;
        let unsigned = outer.bytes()?;
        let signature = fixed(&mut outer)?;
        done(&outer, bytes)?;
        let mut d = Decoder::new(unsigned);
        array(&mut d, 8)?;
        if d.str()? != DOMAIN {
            return Err(MessageError::Encoding);
        }
        if d.u16()? != 1 {
            return Err(MessageError::Version);
        }
        let lobby = LobbyId::from_bytes(fixed(&mut d)?);
        let sender = fixed(&mut d)?;
        let sequence = d.u64()?;
        if sequence == 0 {
            return Err(MessageError::Encoding);
        }
        let id = fixed(&mut d)?;
        let payload = match d.u8()? {
            1 => {
                array(&mut d, 2)?;
                Payload::Join {
                    nickname: Nickname::new(d.str()?).map_err(|_| MessageError::Encoding)?,
                    name: LobbyName::new(d.str()?).map_err(|_| MessageError::Encoding)?,
                }
            }
            2 => Payload::Chat(ValidatedText::new(d.str()?).map_err(|_| MessageError::Encoding)?),
            3 => {
                array(&mut d, 0)?;
                Payload::Leave
            }
            4 => {
                array(&mut d, 3)?;
                let service_key = fixed(&mut d)?;
                let port = d.u16()?;
                if port == 0 {
                    return Err(MessageError::Encoding);
                }
                Payload::Endpoint {
                    service_key,
                    port,
                    expires: d.u64()?,
                }
            }
            _ => return Err(MessageError::Encoding),
        };
        done(&d, unsigned)?;
        let message = Self {
            lobby,
            sender,
            sequence,
            id,
            payload,
            signature,
        };
        if message.encode()? != bytes {
            return Err(MessageError::Encoding);
        }
        Ok(message)
    }
    pub fn verify(&self, expected: LobbyId) -> Result<(), MessageError> {
        if self.lobby != expected
            || !identity::verify(&self.sender, &self.unsigned()?, &self.signature)
        {
            return Err(MessageError::Authentication);
        }
        Ok(())
    }
}
fn array(d: &mut Decoder<'_>, count: u64) -> Result<(), MessageError> {
    if d.array()? == Some(count) {
        Ok(())
    } else {
        Err(MessageError::Encoding)
    }
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], MessageError> {
    d.bytes()?.try_into().map_err(|_| MessageError::Encoding)
}
fn done(d: &Decoder<'_>, bytes: &[u8]) -> Result<(), MessageError> {
    if d.position() == bytes.len() {
        Ok(())
    } else {
        Err(MessageError::Encoding)
    }
}

#[derive(Clone)]
pub enum Packet {
    Hello,
    Signed(SignedMessage),
    EndpointList(Vec<SignedMessage>),
    Ping(u64),
    Pong(u64),
    Disconnect,
    Error,
}
impl Packet {
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut e = Encoder::new(Vec::with_capacity(256));
        e.array(3)?.u16(1)?;
        match self {
            Self::Hello => {
                e.u8(0)?.u8(0)?;
            } // No optional metadata or detailed client version.
            Self::Signed(message) => {
                e.u8(1)?.bytes(&message.encode()?)?;
            }
            Self::EndpointList(messages) => {
                if messages.len() > 8 {
                    return Err(MessageError::Limit);
                }
                e.u8(2)?.array(messages.len() as u64)?;
                for message in messages {
                    if !matches!(message.payload(), Payload::Endpoint { .. }) {
                        return Err(MessageError::Encoding);
                    }
                    e.bytes(&message.encode()?)?;
                }
            }
            Self::Ping(nonce) => {
                e.u8(3)?.u64(*nonce)?;
            }
            Self::Pong(nonce) => {
                e.u8(4)?.u64(*nonce)?;
            }
            Self::Disconnect => {
                e.u8(5)?.u8(0)?;
            }
            Self::Error => {
                e.u8(6)?.u8(0)?;
            }
        }
        let bytes = e.into_writer();
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(MessageError::Limit);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(MessageError::Limit);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 3)?;
        if d.u16()? != 1 {
            return Err(MessageError::Version);
        }
        let packet = match d.u8()? {
            0 => {
                if d.u8()? != 0 {
                    return Err(MessageError::Version);
                }
                Self::Hello
            }
            1 => Self::Signed(SignedMessage::decode(d.bytes()?)?),
            2 => {
                let count = d.array()?.ok_or(MessageError::Encoding)?;
                if count > 8 {
                    return Err(MessageError::Limit);
                }
                let mut ads = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let ad = SignedMessage::decode(d.bytes()?)?;
                    if !matches!(ad.payload(), Payload::Endpoint { .. }) {
                        return Err(MessageError::Encoding);
                    }
                    ads.push(ad);
                }
                Self::EndpointList(ads)
            }
            3 => Self::Ping(d.u64()?),
            4 => Self::Pong(d.u64()?),
            5 => {
                if d.u8()? != 0 {
                    return Err(MessageError::Encoding);
                }
                Self::Disconnect
            }
            6 => {
                if d.u8()? != 0 {
                    return Err(MessageError::Encoding);
                }
                Self::Error
            }
            _ => return Err(MessageError::Encoding),
        };
        done(&d, bytes)?;
        if packet.encode()? != bytes {
            return Err(MessageError::Encoding);
        }
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_cover_lobby_sender_sequence_type_and_payload() {
        let id = EphemeralIdentity::generate(LobbyId::random_public().unwrap()).unwrap();
        let message =
            SignedMessage::new(&id, 1, Payload::Chat(ValidatedText::new("hello").unwrap()))
                .unwrap();
        let bytes = message.encode().unwrap();
        SignedMessage::decode(&bytes)
            .unwrap()
            .verify(id.lobby())
            .unwrap();
        for offset in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            if let Ok(message) = SignedMessage::decode(&bad) {
                assert!(message.verify(id.lobby()).is_err());
            }
        }
        assert!(message.verify(LobbyId::random_public().unwrap()).is_err());
        assert!(SignedMessage::new(&id, 0, Payload::Leave).is_err());
    }
    #[test]
    fn hostile_cbor_is_bounded_and_never_panics() {
        for len in 0..256 {
            for byte in [0, 0x9f, 0xbf, 0xff, 0x5b, 0x83] {
                assert!(Packet::decode(&vec![byte; len]).is_err());
            }
        }
        assert!(Packet::decode(&vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
        assert!(Packet::decode(&[0x83, 0x18, 0x01, 0, 0]).is_err()); // nonminimal version
        assert!(
            Packet::decode(&[
                0x83, 0x01, 0x02, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ])
            .is_err()
        );
        for packet in [
            Packet::Hello,
            Packet::Ping(17),
            Packet::Pong(17),
            Packet::Disconnect,
            Packet::Error,
        ] {
            let bytes = packet.encode().unwrap();
            assert_eq!(Packet::decode(&bytes).unwrap().encode().unwrap(), bytes);
        }
    }
}
