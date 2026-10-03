use crate::{SecretError, limits, text::ValidatedText};
use nulllobby_transport::TransportKind;
use std::collections::BTreeSet;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LobbyId([u8; 32]);
impl LobbyId {
    /// Unlisted public identifiers are rendezvous identifiers, not authentication secrets.
    pub fn random_public() -> Result<Self, SecretError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| SecretError::RandomUnavailable)?;
        Ok(Self(bytes))
    }
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum LobbyKind {
    #[default]
    PublicUnlisted = 1,
    Private = 2,
    /// Explicitly enumerable, with ASCII normalization specified by LobbyCard.
    PublicDiscoverable = 3,
}

pub type Nickname = ValidatedText<{ limits::NICKNAME_BYTES }>;
pub type LobbyName = ValidatedText<{ limits::LOBBY_NAME_BYTES }>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaddingPolicy {
    None,
    Bucketed,
}

pub use nulllobby_transport::ConnectionState;

/// RAM-only trust for a single lobby. Full fingerprints are required.
pub struct LobbyTrust {
    lobby: LobbyId,
    verified: BTreeSet<crate::Fingerprint>,
}
impl LobbyTrust {
    pub fn new(lobby: LobbyId) -> Self {
        Self {
            lobby,
            verified: BTreeSet::new(),
        }
    }
    pub fn verify(&mut self, fingerprint: crate::Fingerprint) -> Result<(), TrustLimit> {
        if !self.verified.contains(&fingerprint) && self.verified.len() >= limits::PEERS_PER_LOBBY {
            return Err(TrustLimit);
        }
        self.verified.insert(fingerprint);
        Ok(())
    }
    pub fn unverify(&mut self, fingerprint: &crate::Fingerprint) {
        self.verified.remove(fingerprint);
    }
    pub fn is_verified(&self, lobby: LobbyId, fingerprint: &crate::Fingerprint) -> bool {
        lobby == self.lobby && self.verified.contains(fingerprint)
    }
}
#[derive(Debug, thiserror::Error)]
#[error("lobby trust entry limit reached")]
pub struct TrustLimit;

/// UI intent. Networking and cryptography are implemented below the UI boundary.
/// Private cards remain secret-wrapped; UI events never contain key material.
pub enum AppCommand {
    CreatePublicLobby(LobbyName),
    CreatePrivateLobby(LobbyName),
    CreateDiscoverableLobby(LobbyName),
    JoinLobby(crate::LobbyCard),
    LeaveLobby(LobbyId),
    SendMessage {
        lobby: LobbyId,
        body: ValidatedText<{ limits::CHAT_BYTES }>,
    },
    SetNickname(Nickname),
    VerifyPeer {
        lobby: LobbyId,
        fingerprint: crate::Fingerprint,
    },
    UnverifyPeer {
        lobby: LobbyId,
        fingerprint: crate::Fingerprint,
    },
    SetTransport(TransportKind),
    SetPadding(PaddingPolicy),
    SelectLobby(usize),
    Inspect(Inspection),
    ExportInvite,
    ConfirmDiscoverable,
    Reconnect,
    Shutdown,
}

#[derive(Clone, Copy)]
pub enum Inspection {
    About,
    Help,
    Lobbies,
    Members,
    Fingerprint,
    Verified,
    Security,
    Network,
    Privacy,
}

#[derive(Clone)]
pub struct MemberView {
    pub nickname: String,
    pub fingerprint: crate::Fingerprint,
    pub verified: bool,
}
#[derive(Clone)]
pub struct LobbyView {
    pub id: LobbyId,
    pub name: String,
    pub kind: LobbyKind,
    pub peers: usize,
    pub members: Vec<MemberView>,
    pub fingerprint: crate::Fingerprint,
    pub memory: [nulllobby_platform::HardeningStatus; 2],
    pub status: String,
}

pub enum AppEvent {
    View {
        transport: TransportKind,
        current: Option<LobbyId>,
        lobbies: Vec<LobbyView>,
        padding: PaddingPolicy,
    },
    Notice {
        lobby: Option<LobbyId>,
        text: String,
    },
    MessageReceived {
        lobby: LobbyId,
        fingerprint: crate::Fingerprint,
        nickname: String,
        body: String,
        verified: bool,
    },
    Invite(secrecy::SecretString),
    ShutdownComplete,
    LobbyCreated(LobbyId),
    LobbyJoined(LobbyId),
    LobbyLeft(LobbyId),
    IdentityVerified {
        lobby: LobbyId,
        fingerprint: crate::Fingerprint,
    },
    TransportStatus {
        transport: TransportKind,
        status: nulllobby_transport::NetworkStatus,
    },
    PrivacyWarning(PrivacyWarning),
    FatalError,
}

#[derive(Debug)]
pub enum PrivacyWarning {
    DirectIpExposed,
    DiscoverableEnumeration,
    EphemeralIdentity,
    TerminalOutsideBoundary,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_ids_are_random_and_unlisted_is_default() {
        let ids: BTreeSet<_> = (0..64).map(|_| LobbyId::random_public().unwrap()).collect();
        assert_eq!(ids.len(), 64);
        assert_eq!(LobbyKind::default(), LobbyKind::PublicUnlisted);
    }
    #[test]
    fn trust_is_lobby_scoped_bounded_and_ephemeral() {
        let a = LobbyId::random_public().unwrap();
        let b = LobbyId::random_public().unwrap();
        let fp = crate::Fingerprint::of_public_key(&[1; 32]);
        let mut trust = LobbyTrust::new(a);
        trust.verify(fp).unwrap();
        assert!(trust.is_verified(a, &fp));
        assert!(!trust.is_verified(b, &fp));
        assert!(!LobbyTrust::new(a).is_verified(a, &fp));
        trust.unverify(&fp);
        assert!(!trust.is_verified(a, &fp));
        for i in 0..limits::PEERS_PER_LOBBY {
            trust
                .verify(crate::Fingerprint::of_public_key(&[i as u8; 32]))
                .unwrap();
        }
        assert!(
            trust
                .verify(crate::Fingerprint::of_public_key(&[255; 32]))
                .is_err()
        );
    }
}
