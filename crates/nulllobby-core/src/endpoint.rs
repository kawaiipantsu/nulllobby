//! Signed onion advertisements are scoped to one authenticated lobby and expire in RAM.
use crate::{
    LobbyId,
    message::{MessageError, Payload, SignedMessage},
};
use std::collections::HashMap;

pub struct EndpointBook {
    lobby: LobbyId,
    entries: HashMap<[u8; 32], SignedMessage>,
    sequences: HashMap<[u8; 32], u64>,
}
impl EndpointBook {
    pub fn new(lobby: LobbyId) -> Self {
        Self {
            lobby,
            entries: HashMap::new(),
            sequences: HashMap::new(),
        }
    }
    /// Call only for messages received over an authenticated lobby session (or signed locally).
    pub fn accept(&mut self, message: SignedMessage, now: u64) -> Result<bool, MessageError> {
        message.verify(self.lobby)?;
        let Payload::Endpoint { expires, port, .. } = message.payload() else {
            return Err(MessageError::Encoding);
        };
        if *expires <= now || *expires > now.saturating_add(600) || *port == 0 {
            return Err(MessageError::Encoding);
        }
        let key = *message.sender();
        if let Some(previous) = self.sequences.get(&key) {
            if message.sequence() <= *previous {
                return Ok(false);
            }
        } else if self.sequences.len() >= 64 {
            return Err(MessageError::Limit);
        }
        self.sequences.insert(key, message.sequence());
        self.entries.insert(key, message);
        Ok(true)
    }
    pub fn values(&self) -> impl Iterator<Item = &SignedMessage> {
        self.entries.values()
    }
    pub fn remove(&mut self, key: &[u8; 32]) {
        self.entries.remove(key);
    }
    pub fn expire(&mut self, now: u64) {
        self.entries
            .retain(|_, m| matches!(m.payload(),Payload::Endpoint{expires,..} if *expires > now));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::EphemeralIdentity;
    fn ad(identity: &EphemeralIdentity, sequence: u64, expires: u64) -> SignedMessage {
        SignedMessage::new(
            identity,
            sequence,
            Payload::Endpoint {
                service_key: [sequence as u8; 32],
                port: 1234,
                expires,
            },
        )
        .unwrap()
    }
    #[test]
    fn other_lobby_endpoints_never_enter_the_book_and_history_is_not_retained() {
        let a = LobbyId::from_bytes([1; 32]);
        let b = LobbyId::from_bytes([2; 32]);
        let identity = EphemeralIdentity::generate(a).unwrap();
        let mut book = EndpointBook::new(b);
        assert!(book.accept(ad(&identity, 1, 200), 100).is_err());
        assert_eq!(book.values().count(), 0);
        let mut book = EndpointBook::new(a);
        assert!(book.accept(ad(&identity, 2, 200), 100).unwrap());
        assert!(!book.accept(ad(&identity, 1, 200), 100).unwrap());
        assert_eq!(book.values().count(), 1);
        assert!(book.accept(ad(&identity, 3, 201), 100).unwrap());
        assert_eq!(book.values().count(), 1);
        book.expire(201);
        assert_eq!(book.values().count(), 0);
        assert!(!book.accept(ad(&identity, 2, 300), 202).unwrap());
        assert!(book.accept(ad(&identity, 4, 900), 202).is_err());
    }
}
