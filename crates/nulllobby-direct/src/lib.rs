//! Phase 1 only: BEP 3 handshake codec. No TCP, DHT or BEP 10 negotiation.
#![forbid(unsafe_code)]

pub const HANDSHAKE_BYTES: usize = 68;
const PROTOCOL: &[u8; 19] = b"BitTorrent protocol";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwarmId(pub [u8; 20]);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerId([u8; 20]);
impl PeerId {
    /// Fresh random bytes, without a forged client prefix or stable installation data.
    pub fn generate() -> Result<Self, HandshakeError> {
        let mut bytes = [0; 20];
        getrandom::fill(&mut bytes).map_err(|_| HandshakeError::RandomUnavailable)?;
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}
impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerId([EPHEMERAL])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Handshake {
    reserved: [u8; 8],
    swarm: SwarmId,
    peer_id: PeerId,
}
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum HandshakeError {
    #[error("BitTorrent handshake must be exactly 68 bytes")]
    Length,
    #[error("invalid BitTorrent protocol header")]
    Protocol,
    #[error("peer does not support the extension protocol")]
    ExtensionsRequired,
    #[error("unexpected BitTorrent swarm identifier")]
    WrongSwarm,
    #[error("OS random source unavailable")]
    RandomUnavailable,
}
impl Handshake {
    pub fn new(swarm: SwarmId, peer_id: PeerId) -> Self {
        let mut reserved = [0; 8];
        reserved[5] = 0x10;
        Self {
            reserved,
            swarm,
            peer_id,
        }
    }
    pub fn encode(&self) -> [u8; HANDSHAKE_BYTES] {
        let mut bytes = [0; HANDSHAKE_BYTES];
        bytes[0] = 19;
        bytes[1..20].copy_from_slice(PROTOCOL);
        bytes[20..28].copy_from_slice(&self.reserved);
        bytes[28..48].copy_from_slice(&self.swarm.0);
        bytes[48..68].copy_from_slice(&self.peer_id.0);
        bytes
    }
    /// Exact frame only: callers must read 68 bytes with a timeout, never buffer to EOF.
    /// Unknown reserved bits are preserved for interoperability.
    pub fn parse(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.len() != HANDSHAKE_BYTES {
            return Err(HandshakeError::Length);
        }
        if bytes[0] != 19 || &bytes[1..20] != PROTOCOL {
            return Err(HandshakeError::Protocol);
        }
        let mut reserved = [0; 8];
        reserved.copy_from_slice(&bytes[20..28]);
        let mut swarm = [0; 20];
        swarm.copy_from_slice(&bytes[28..48]);
        let mut peer = [0; 20];
        peer.copy_from_slice(&bytes[48..68]);
        Ok(Self {
            reserved,
            swarm: SwarmId(swarm),
            peer_id: PeerId(peer),
        })
    }
    /// Required validation before the future Direct connection enters BEP 10.
    pub fn validate_for(&self, expected: SwarmId) -> Result<(), HandshakeError> {
        if self.swarm != expected {
            return Err(HandshakeError::WrongSwarm);
        }
        if !self.supports_extensions() {
            return Err(HandshakeError::ExtensionsRequired);
        }
        Ok(())
    }
    pub fn supports_extensions(&self) -> bool {
        self.reserved[5] & 0x10 != 0
    }
    pub fn swarm(&self) -> SwarmId {
        self.swarm
    }
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_wire_layout_and_extension_bit() {
        let handshake = Handshake::new(SwarmId([0x11; 20]), PeerId([0x22; 20]));
        let bytes = handshake.encode();
        assert_eq!(&bytes[..20], b"\x13BitTorrent protocol");
        assert_eq!(&bytes[20..28], &[0, 0, 0, 0, 0, 0x10, 0, 0]);
        assert_eq!(&bytes[28..48], &[0x11; 20]);
        assert_eq!(&bytes[48..], &[0x22; 20]);
        assert_eq!(Handshake::parse(&bytes).unwrap(), handshake);
        assert!(handshake.validate_for(SwarmId([0x11; 20])).is_ok());
    }
    #[test]
    fn reject_lengths_protocol_wrong_swarm_and_no_extensions() {
        let good = Handshake::new(SwarmId([1; 20]), PeerId([2; 20])).encode();
        for len in 0..68 {
            assert!(Handshake::parse(&good[..len]).is_err());
        }
        assert!(Handshake::parse(&[0; 69]).is_err());
        for offset in 0..20 {
            let mut bad = good;
            bad[offset] ^= 1;
            assert_eq!(Handshake::parse(&bad), Err(HandshakeError::Protocol));
        }
        let mut no_extensions = good;
        no_extensions[25] = 0;
        let parsed = Handshake::parse(&no_extensions).unwrap();
        assert_eq!(
            parsed.validate_for(SwarmId([1; 20])),
            Err(HandshakeError::ExtensionsRequired)
        );
        assert_eq!(
            parsed.validate_for(SwarmId([3; 20])),
            Err(HandshakeError::WrongSwarm)
        );
    }
    #[test]
    fn random_peer_ids_and_no_panics_for_arbitrary_bytes() {
        assert_ne!(PeerId::generate().unwrap(), PeerId::generate().unwrap());
        for byte in 0..=255 {
            let _ = Handshake::parse(&[byte; 68]);
        }
        let mut bytes = Handshake::new(SwarmId([1; 20]), PeerId([2; 20])).encode();
        bytes[20] = 0xff;
        assert_eq!(Handshake::parse(&bytes).unwrap().encode(), bytes);
    }
}
