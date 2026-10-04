//! The only route from a transport byte stream to authenticated application records.
use crate::{EphemeralIdentity, LobbyId, domain::PaddingPolicy, identity, secret::NoisePsk};
use nulllobby_transport::{
    BoxStream,
    framing::{self, RecordReader},
};
use snow::{Builder, TransportState};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{ReadHalf, WriteHalf};
use zeroize::Zeroizing;

pub const PUBLIC_SUITE: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const PRIVATE_SUITE: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
pub const MAX_PLAINTEXT: usize = 16_366;
const PROOF_LEN: usize = 226;
const PROOF_DOMAIN: &[u8] = b"nulllobby.identity.v2";

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session network failure")]
    Io,
    #[error("session authentication failed")]
    Authentication,
    #[error("session protocol violation")]
    Protocol,
    #[error("session timed out")]
    Timeout,
    #[error("session entropy unavailable")]
    Entropy,
}
impl From<std::io::Error> for SessionError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}
impl From<snow::Error> for SessionError {
    fn from(_: snow::Error) -> Self {
        Self::Authentication
    }
}

/// Proof additionally binds the Noise transcript, preventing reuse in another connection.
fn proof(identity: &EphemeralIdentity, hash: &[u8; 32]) -> Result<[u8; PROOF_LEN], SessionError> {
    let mut proof = [0; PROOF_LEN];
    proof[..2].copy_from_slice(&crate::domain::PROTOCOL_VERSION.to_be_bytes());
    proof[2..34].copy_from_slice(identity.lobby().as_bytes());
    proof[34..66].copy_from_slice(&identity.public_key());
    proof[66..98].copy_from_slice(&identity.noise_public_key());
    getrandom::fill(&mut proof[98..130]).map_err(|_| SessionError::Entropy)?;
    proof[130..162].copy_from_slice(hash);
    let mut signed = PROOF_DOMAIN.to_vec();
    signed.extend_from_slice(&proof[..162]);
    proof[162..].copy_from_slice(&identity.sign(&signed));
    Ok(proof)
}
pub fn verify_identity_proof(
    bytes: &[u8],
    lobby: LobbyId,
    remote_static: &[u8; 32],
    hash: &[u8; 32],
) -> Result<[u8; 32], SessionError> {
    if bytes.len() != PROOF_LEN
        || bytes[..2] != crate::domain::PROTOCOL_VERSION.to_be_bytes()
        || bytes[2..34] != *lobby.as_bytes()
        || bytes[66..98] != *remote_static
        || bytes[130..162] != *hash
    {
        return Err(SessionError::Authentication);
    }
    let key: [u8; 32] = bytes[34..66]
        .try_into()
        .map_err(|_| SessionError::Protocol)?;
    let signature = bytes[162..]
        .try_into()
        .map_err(|_| SessionError::Protocol)?;
    let mut signed = PROOF_DOMAIN.to_vec();
    signed.extend_from_slice(&bytes[..162]);
    if !identity::verify(&key, &signed, &signature) {
        return Err(SessionError::Authentication);
    }
    Ok(key)
}

pub struct SecureSession {
    stream: BoxStream,
    noise: TransportState,
    peer: [u8; 32],
}
impl SecureSession {
    /// No metadata enters Noise handshake payloads. No usable session is returned before proof validation.
    pub async fn establish(
        stream: BoxStream,
        local: &EphemeralIdentity,
        psk: Option<&NoisePsk>,
        initiator: bool,
    ) -> Result<Self, SessionError> {
        tokio::time::timeout(
            Duration::from_secs(20),
            Self::handshake(stream, local, psk, initiator),
        )
        .await
        .map_err(|_| SessionError::Timeout)?
    }
    async fn handshake(
        mut stream: BoxStream,
        local: &EphemeralIdentity,
        psk: Option<&NoisePsk>,
        initiator: bool,
    ) -> Result<Self, SessionError> {
        stream.connection_state(nulllobby_transport::ConnectionState::NoiseHandshaking);
        let suite = if psk.is_some() {
            PRIVATE_SUITE
        } else {
            PUBLIC_SUITE
        };
        let mut prologue = b"nulllobby.session.v2".to_vec();
        prologue.extend_from_slice(local.lobby().as_bytes());
        let mut builder = Builder::new(suite.parse()?)
            .local_private_key(local.noise_secret())?
            .prologue(&prologue)?;
        if let Some(psk) = psk {
            builder = builder.psk(3, psk.expose_secret())?;
        }
        let mut handshake = if initiator {
            builder.build_initiator()?
        } else {
            builder.build_responder()?
        };
        let mut reader = RecordReader::default();
        let mut scratch = Zeroizing::new([0; 512]);
        for step in 0..3 {
            if (step % 2 == 0) == initiator {
                let len = handshake.write_message(&[], &mut *scratch)?;
                framing::write(&mut stream, framing::HANDSHAKE, &scratch[..len]).await?;
            } else {
                let (tag, bytes) = reader.read(&mut stream).await?;
                if tag != framing::HANDSHAKE || bytes.len() > 512 {
                    return Err(SessionError::Protocol);
                }
                if handshake.read_message(&bytes, &mut *scratch)? != 0 {
                    return Err(SessionError::Protocol);
                }
            }
        }
        let remote_static: [u8; 32] = handshake
            .get_remote_static()
            .ok_or(SessionError::Authentication)?
            .try_into()
            .map_err(|_| SessionError::Authentication)?;
        let hash: [u8; 32] = handshake
            .get_handshake_hash()
            .try_into()
            .map_err(|_| SessionError::Authentication)?;
        let mut noise = handshake.into_transport_mode()?;
        stream.connection_state(nulllobby_transport::ConnectionState::AuthenticatingIdentity);
        let local_proof = proof(local, &hash)?;
        let len = noise.write_message(&local_proof, &mut *scratch)?;
        framing::write(&mut stream, framing::CIPHERTEXT, &scratch[..len]).await?;
        let (tag, bytes) = reader.read(&mut stream).await?;
        if tag != framing::CIPHERTEXT || bytes.len() != PROOF_LEN + 16 {
            return Err(SessionError::Protocol);
        }
        let len = noise.read_message(&bytes, &mut *scratch)?;
        let peer = verify_identity_proof(&scratch[..len], local.lobby(), &remote_static, &hash)?;
        if peer == local.public_key() {
            return Err(SessionError::Authentication);
        }
        stream.authenticated();
        stream.connection_state(nulllobby_transport::ConnectionState::Secure);
        Ok(Self {
            stream,
            noise,
            peer,
        })
    }
    pub fn peer_key(&self) -> [u8; 32] {
        self.peer
    }
    pub fn split(self) -> (SecureReader, SecureWriter) {
        let (read, write) = tokio::io::split(self.stream);
        let noise = Arc::new(Mutex::new(self.noise));
        (
            SecureReader {
                read,
                frames: RecordReader::default(),
                noise: noise.clone(),
                failed: false,
            },
            SecureWriter {
                write,
                noise,
                failed: false,
            },
        )
    }
}
pub struct SecureReader {
    read: ReadHalf<BoxStream>,
    frames: RecordReader,
    noise: Arc<Mutex<TransportState>>,
    failed: bool,
}
pub struct SecureWriter {
    write: WriteHalf<BoxStream>,
    noise: Arc<Mutex<TransportState>>,
    failed: bool,
}
impl SecureReader {
    pub async fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        if self.failed {
            return Err(SessionError::Protocol);
        }
        let result = self.receive_inner().await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    async fn receive_inner(&mut self) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        let (tag, ciphertext) = self.frames.read(&mut self.read).await?;
        if tag != framing::CIPHERTEXT || ciphertext.len() > 16_384 {
            return Err(SessionError::Protocol);
        }
        let mut plain = Zeroizing::new(vec![0; ciphertext.len()]);
        let len = self
            .noise
            .lock()
            .map_err(|_| SessionError::Protocol)?
            .read_message(&ciphertext, &mut plain)?;
        if len < 2 {
            return Err(SessionError::Protocol);
        }
        let content_len = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
        if content_len == 0 || content_len > len - 2 {
            return Err(SessionError::Protocol);
        }
        Ok(Zeroizing::new(plain[2..2 + content_len].to_vec()))
    }
}
impl SecureWriter {
    /// Cancellation of a write requires dropping the session; counters cannot be reused.
    pub async fn send(&mut self, bytes: &[u8], padding: PaddingPolicy) -> Result<(), SessionError> {
        if self.failed || bytes.is_empty() || bytes.len() > MAX_PLAINTEXT {
            return Err(SessionError::Protocol);
        }
        self.failed = true;
        let base = bytes.len() + 2 + 16;
        let target = match padding {
            PaddingPolicy::None => base,
            PaddingPolicy::Bucketed => [512, 1024, 2048, 4096, 8192, 16384]
                .into_iter()
                .find(|size| *size >= base)
                .ok_or(SessionError::Protocol)?,
        };
        let mut plain = Zeroizing::new(vec![0; target - 16]);
        plain[..2].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
        plain[2..2 + bytes.len()].copy_from_slice(bytes);
        getrandom::fill(&mut plain[2 + bytes.len()..]).map_err(|_| SessionError::Entropy)?;
        let mut ciphertext = vec![0; target];
        let len = self
            .noise
            .lock()
            .map_err(|_| SessionError::Protocol)?
            .write_message(&plain, &mut ciphertext)?;
        tokio::time::timeout(
            Duration::from_secs(15),
            framing::write(&mut self.write, framing::CIPHERTEXT, &ciphertext[..len]),
        )
        .await
        .map_err(|_| SessionError::Timeout)??;
        self.failed = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateLobbySecret;
    #[tokio::test]
    async fn exact_suites_authenticate_and_encrypt_records() {
        for private in [false, true] {
            let lobby = LobbyId::random_public().unwrap();
            let a = EphemeralIdentity::generate(lobby).unwrap();
            let b = EphemeralIdentity::generate(lobby).unwrap();
            let keys = PrivateLobbySecret::generate().unwrap().derive().unwrap();
            let psk = private.then_some(&keys.noise_psk);
            let (left, right) = tokio::io::duplex(65_536);
            let (left, right) = tokio::join!(
                SecureSession::establish(Box::new(left), &a, psk, true),
                SecureSession::establish(Box::new(right), &b, psk, false)
            );
            let left = left.unwrap();
            let right = right.unwrap();
            assert_eq!(left.peer_key(), b.public_key());
            let (_, mut sender) = left.split();
            let (mut receiver, _) = right.split();
            for padding in [PaddingPolicy::None, PaddingPolicy::Bucketed] {
                sender
                    .send(b"confidential test message", padding)
                    .await
                    .unwrap();
                assert_eq!(
                    &**receiver.receive().await.unwrap(),
                    b"confidential test message"
                );
            }
        }
    }
    #[tokio::test]
    async fn wrong_psk_and_wrong_lobby_never_produce_authenticated_session() {
        for same_lobby in [false, true] {
            let lobby = LobbyId::random_public().unwrap();
            let a = EphemeralIdentity::generate(lobby).unwrap();
            let b = EphemeralIdentity::generate(if same_lobby {
                lobby
            } else {
                LobbyId::random_public().unwrap()
            })
            .unwrap();
            let ka = PrivateLobbySecret::generate().unwrap().derive().unwrap();
            let kb = PrivateLobbySecret::generate().unwrap().derive().unwrap();
            let (left, right) = tokio::io::duplex(65_536);
            let (left, right) = tokio::join!(
                SecureSession::establish(Box::new(left), &a, Some(&ka.noise_psk), true),
                SecureSession::establish(Box::new(right), &b, Some(&kb.noise_psk), false)
            );
            assert!(left.is_err() && right.is_err());
        }
    }
    #[test]
    fn proof_binds_signature_lobby_actual_noise_key_and_transcript() {
        let id = EphemeralIdentity::generate(LobbyId::random_public().unwrap()).unwrap();
        let bytes = proof(&id, &[7; 32]).unwrap();
        assert!(
            verify_identity_proof(&bytes, id.lobby(), &id.noise_public_key(), &[7; 32]).is_ok()
        );
        assert!(verify_identity_proof(&bytes, id.lobby(), &[1; 32], &[7; 32]).is_err());
        assert!(
            verify_identity_proof(&bytes, id.lobby(), &id.noise_public_key(), &[8; 32]).is_err()
        );
        for offset in 0..bytes.len() {
            let mut bad = bytes;
            bad[offset] ^= 1;
            assert!(
                verify_identity_proof(&bad, id.lobby(), &id.noise_public_key(), &[7; 32]).is_err()
            );
        }
    }
}
