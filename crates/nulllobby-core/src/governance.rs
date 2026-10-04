//! Individually addressed rotation offers. Never put these in signed gossip.
use crate::{EphemeralIdentity, LobbyCard, LobbyId, LobbyKind, identity, message::MessageError};
use minicbor::{Decoder, Encoder};
use nulllobby_transport::TransportKind;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct RotationOffer {
    lobby: LobbyId,
    owner: [u8; 32],
    recipient: [u8; 32],
    sequence: u64,
    expires: u64,
    card: SecretString,
    signature: [u8; 64],
}
impl RotationOffer {
    pub fn new(
        owner: &EphemeralIdentity,
        recipient: [u8; 32],
        sequence: u64,
        expires: u64,
        card: &LobbyCard,
    ) -> Result<Self, MessageError> {
        let mut offer = Self {
            lobby: owner.lobby(),
            owner: owner.public_key(),
            recipient,
            sequence,
            expires,
            card: card.export(),
            signature: [0; 64],
        };
        offer.signature = owner.sign(&offer.body()?);
        Ok(offer)
    }
    fn body(&self) -> Result<Zeroizing<Vec<u8>>, MessageError> {
        let mut bytes = Zeroizing::new(Vec::new());
        Encoder::new(&mut *bytes)
            .array(8)?
            .str("nulllobby.rotation.v1")?
            .u16(2)?
            .bytes(self.lobby.as_bytes())?
            .bytes(&self.owner)?
            .bytes(&self.recipient)?
            .u64(self.sequence)?
            .u64(self.expires)?
            .str(self.card.expose_secret())?;
        Ok(bytes)
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, MessageError> {
        let mut bytes = Zeroizing::new(Vec::new());
        Encoder::new(&mut *bytes)
            .array(2)?
            .bytes(&self.body()?)?
            .bytes(&self.signature)?;
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > 2048 {
            return Err(MessageError::Limit);
        }
        let mut outer = Decoder::new(bytes);
        if outer.array()? != Some(2) {
            return Err(MessageError::Encoding);
        }
        let body = outer.bytes()?;
        let signature = fixed(&mut outer)?;
        if outer.position() != bytes.len() {
            return Err(MessageError::Encoding);
        }
        let mut d = Decoder::new(body);
        if d.array()? != Some(8) || d.str()? != "nulllobby.rotation.v1" || d.u16()? != 2 {
            return Err(MessageError::Encoding);
        }
        let offer = Self {
            lobby: LobbyId::from_bytes(fixed(&mut d)?),
            owner: fixed(&mut d)?,
            recipient: fixed(&mut d)?,
            sequence: d.u64()?,
            expires: d.u64()?,
            card: SecretString::from(d.str()?),
            signature,
        };
        if offer.card.expose_secret().len() > crate::limits::CARD_TEXT_BYTES
            || d.position() != body.len()
            || offer.encode()?.as_slice() != bytes
        {
            return Err(MessageError::Encoding);
        }
        Ok(offer)
    }
    pub fn verify(
        &self,
        old: &LobbyCard,
        recipient: [u8; 32],
        peer: [u8; 32],
        now: u64,
    ) -> Result<LobbyCard, MessageError> {
        if old.administrator() != Some(self.owner)
            || peer != self.owner
            || self.recipient != recipient
            || self.lobby != old.lobby_id()
            || self.sequence == 0
            || self.expires <= now
            || self.expires > now.saturating_add(300)
            || !identity::verify(&self.owner, &self.body()?, &self.signature)
        {
            return Err(MessageError::Authentication);
        }
        let new =
            LobbyCard::parse(self.card.expose_secret()).map_err(|_| MessageError::Encoding)?;
        if new.kind() != LobbyKind::Private
            || new.transport() != old.transport()
            || new.lobby_id() == old.lobby_id()
            || new.administrator().is_none()
        {
            return Err(MessageError::Authentication);
        }
        // Cards already reject clearnet seed endpoints in Tor mode.
        if old.transport() == TransportKind::Tor && new.seeds().is_empty() {
            return Err(MessageError::Authentication);
        }
        Ok(new)
    }
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], MessageError> {
    d.bytes()?.try_into().map_err(|_| MessageError::Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_is_addressed_bound_to_owner_and_never_changes_transport() {
        let mut old = LobbyCard::private(TransportKind::Direct, vec![]).unwrap();
        let owner = EphemeralIdentity::generate(old.lobby_id()).unwrap();
        old.set_administrator(owner.public_key()).unwrap();
        let recipient = EphemeralIdentity::generate(old.lobby_id()).unwrap();
        let stranger = EphemeralIdentity::generate(old.lobby_id()).unwrap();
        let mut new = LobbyCard::private(TransportKind::Direct, vec![]).unwrap();
        let next = EphemeralIdentity::generate(new.lobby_id()).unwrap();
        new.set_administrator(next.public_key()).unwrap();
        let offer = RotationOffer::new(&owner, recipient.public_key(), 1, 1200, &new).unwrap();
        let bytes = offer.encode().unwrap();
        let decoded = RotationOffer::decode(&bytes).unwrap();
        assert_eq!(
            decoded
                .verify(&old, recipient.public_key(), owner.public_key(), 1000)
                .unwrap()
                .lobby_id(),
            new.lobby_id()
        );
        assert!(
            decoded
                .verify(&old, stranger.public_key(), owner.public_key(), 1000)
                .is_err()
        );
        assert!(
            decoded
                .verify(&old, recipient.public_key(), stranger.public_key(), 1000)
                .is_err()
        );
        assert!(
            decoded
                .verify(&old, recipient.public_key(), owner.public_key(), 1200)
                .is_err()
        );
        assert!(
            decoded
                .verify(&old, recipient.public_key(), owner.public_key(), 899)
                .is_err()
        );
        let forged = RotationOffer::new(&stranger, recipient.public_key(), 1, 1200, &new).unwrap();
        assert!(
            forged
                .verify(&old, recipient.public_key(), stranger.public_key(), 1000)
                .is_err()
        );
        for i in 0..bytes.len() {
            let mut bad = bytes.to_vec();
            bad[i] ^= 1;
            assert!(
                RotationOffer::decode(&bad)
                    .and_then(|o| o.verify(&old, recipient.public_key(), owner.public_key(), 1000))
                    .is_err()
            );
        }
        assert!(RotationOffer::decode(&vec![0; 2049]).is_err());
    }
}
