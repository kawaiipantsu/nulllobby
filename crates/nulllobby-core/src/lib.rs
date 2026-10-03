//! Offline foundations. No messaging, encryption sessions, persistence or networking yet.
#![forbid(unsafe_code)]

pub mod branding;
pub mod card;
pub mod domain;
pub mod identity;
pub mod secret;
pub mod text;

pub use card::LobbyCard;
pub use domain::{LobbyId, LobbyKind};
pub use identity::{EphemeralIdentity, Fingerprint};
pub use nulllobby_transport::TransportKind;
pub use secret::{PrivateLobbySecret, SecretError};

pub mod limits {
    pub const GLOBAL_PEERS: usize = 128;
    pub const PEERS_PER_LOBBY: usize = 64;
    pub const PENDING_HANDSHAKES: usize = 32;
    pub const CHAT_BYTES: usize = 8 * 1024;
    pub const FRAME_BYTES: usize = 64 * 1024;
    pub const NICKNAME_BYTES: usize = 64;
    pub const LOBBY_NAME_BYTES: usize = 128;
    pub const CARD_SEEDS: usize = 8;
    pub const CARD_BINARY_BYTES: usize = 512;
    pub const CARD_TEXT_BYTES: usize = 768;
}
