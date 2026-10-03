//! In-memory replay window: no wall-clock assumptions; sender state is never evicted.
use crate::{
    LobbyId, limits,
    message::{MessageError, SignedMessage},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};
const RECENT_IDS: usize = 4096;
const TTL: Duration = Duration::from_secs(600);
struct Window {
    highest: u64,
    seen: u128,
}
pub struct ReplayGuard {
    lobby: LobbyId,
    senders: HashMap<[u8; 32], Window>,
    ids: HashSet<([u8; 32], [u8; 16])>,
    order: VecDeque<(Instant, [u8; 32], [u8; 16])>,
}
impl ReplayGuard {
    pub fn new(lobby: LobbyId) -> Self {
        Self {
            lobby,
            senders: HashMap::new(),
            ids: HashSet::new(),
            order: VecDeque::new(),
        }
    }
    /// Signature verification precedes all replay-state mutation and display/forwarding.
    pub fn accept(&mut self, message: &SignedMessage, now: Instant) -> Result<bool, MessageError> {
        message.verify(self.lobby)?;
        while self
            .order
            .front()
            .is_some_and(|(time, _, _)| now.saturating_duration_since(*time) >= TTL)
            || self.order.len() >= RECENT_IDS
        {
            if let Some((_, key, id)) = self.order.pop_front() {
                self.ids.remove(&(key, id));
            }
        }
        let sender = *message.sender();
        let id = message.id();
        let sequence = message.sequence();
        if self.ids.contains(&(sender, id)) {
            return Ok(false);
        }
        if !self.senders.contains_key(&sender) && self.senders.len() >= limits::PEERS_PER_LOBBY {
            return Err(MessageError::Limit);
        }
        let window = self.senders.entry(sender).or_insert(Window {
            highest: 0,
            seen: 0,
        });
        if sequence > window.highest {
            let shift = sequence - window.highest;
            window.seen = if shift >= 128 {
                1
            } else {
                (window.seen << shift) | 1
            };
            window.highest = sequence;
        } else {
            let distance = window.highest - sequence;
            if distance >= 128 || window.seen & (1u128 << distance) != 0 {
                return Ok(false);
            }
            window.seen |= 1u128 << distance;
        }
        self.ids.insert((sender, id));
        self.order.push_back((now, sender, id));
        Ok(true)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EphemeralIdentity, message::Payload};
    #[test]
    fn replay_handles_reordering_duplicate_sequences_expiry_and_bounds() {
        let lobby = LobbyId::random_public().unwrap();
        let id = EphemeralIdentity::generate(lobby).unwrap();
        let mut replay = ReplayGuard::new(lobby);
        let now = Instant::now();
        let one = SignedMessage::new(&id, 1, Payload::Leave).unwrap();
        let two = SignedMessage::new(&id, 2, Payload::Leave).unwrap();
        assert!(replay.accept(&two, now).unwrap());
        assert!(replay.accept(&one, now).unwrap());
        assert!(!replay.accept(&one, now + TTL).unwrap());
        let duplicate_sequence = SignedMessage::new(&id, 2, Payload::Leave).unwrap();
        assert!(!replay.accept(&duplicate_sequence, now + TTL).unwrap());
        let jump = SignedMessage::new(&id, 1000, Payload::Leave).unwrap();
        assert!(replay.accept(&jump, now + TTL).unwrap());
        assert!(!replay.accept(&two, now + TTL).unwrap());
        for i in 0..RECENT_IDS {
            replay.order.push_back((now, [7; 32], [i as u8; 16]));
        }
        let next = SignedMessage::new(&id, 1001, Payload::Leave).unwrap();
        replay.accept(&next, now + TTL).unwrap();
        assert!(replay.order.len() <= RECENT_IDS);
    }
}
