//! Transport-neutral byte streams and instrumentation for fail-closed network policy.
#![forbid(unsafe_code)]
pub mod framing;
pub mod scoped;

use std::{future::Future, net::IpAddr, num::NonZeroU16, pin::Pin};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransportKind {
    Direct = 1,
    Tor = 2,
}

/// Addresses only, never socket handles or DNS names. Onion service public keys
/// encode v3 endpoints without accepting arbitrary hostnames or exit destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Endpoint {
    Direct {
        address: IpAddr,
        port: NonZeroU16,
    },
    Onion {
        service_key: [u8; 32],
        port: NonZeroU16,
    },
}
impl Endpoint {
    pub fn transport(&self) -> TransportKind {
        match self {
            Self::Direct { .. } => TransportKind::Direct,
            Self::Onion { .. } => TransportKind::Tor,
        }
    }
}

/// Opaque, process-local handle; backends must reject handles from another scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EndpointHandle(pub u64);
impl EndpointHandle {
    /// Unique within the process, including across independently owned backends.
    pub fn allocate() -> Result<Self, TransportError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map(Self)
            .map_err(|_| TransportError::ResourceLimit)
    }
}

pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send {
    fn connection_state(&mut self, _state: ConnectionState) {}
    /// Release the pending-handshake resource only after core validates identity.
    fn authenticated(&mut self) {}
}
impl ByteStream for tokio::io::DuplexStream {}
pub type BoxStream = Box<dyn ByteStream>;
pub type TransportFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("transport unavailable")]
    Unavailable,
    #[error("endpoint does not belong to the selected transport")]
    WrongTransport,
    #[error("transport resource limit reached")]
    ResourceLimit,
    #[error("transport operation timed out")]
    Timeout,
    #[error("transport operation unsupported")]
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkStatus {
    Stopped,
    Starting,
    Ready,
    Unavailable,
}

/// Implementations must enforce timeouts, bounded resources and mode selection.
/// Direct returns a byte stream after BitTorrent/BEP 10 adaptation; Tor returns
/// an onion stream. Neither stream is trusted until core completes Noise + proof.
/// No method can choose a fallback transport. Stop/destroy must close owned streams.
pub trait Transport: Send + Sync {
    fn kind(&self) -> TransportKind;
    fn start(&mut self) -> TransportFuture<'_, ()>;
    fn stop(&mut self) -> TransportFuture<'_, ()>;
    fn create_endpoint(&mut self, lobby_scope: [u8; 32]) -> TransportFuture<'_, EndpointHandle>;
    fn destroy_endpoint(&mut self, endpoint: EndpointHandle) -> TransportFuture<'_, ()>;
    fn connect<'a>(
        &'a self,
        local: EndpointHandle,
        peer: &'a Endpoint,
    ) -> TransportFuture<'a, BoxStream>;
    fn accept(&self, local: EndpointHandle) -> TransportFuture<'_, BoxStream>;
    fn local_transport_identity(&self, local: EndpointHandle) -> Result<Endpoint, TransportError>;
    fn network_status(&self) -> NetworkStatus;
}

/// Backends call this instrumentation boundary before network operations.
/// Backend integration tests exercise this policy in addition to unit tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAction {
    MainlineDht,
    UdpDiscovery,
    DirectPeerTcp,
    Tracker,
    PeerDns,
    LocalTorControl,
    LocalTorSocks,
    /// Relay connectivity inside the embedded Tor implementation boundary.
    EmbeddedTor,
}

pub trait NetworkObserver: Send + Sync {
    fn before_network_action(&self, action: NetworkAction) -> Result<(), TransportError>;
    fn connection_state(&self, _state: ConnectionState) {}
    fn bootstrap_progress(&self, _percent: u8) {}
    /// Local fixed categories only; never include endpoint or credential values.
    fn transport_diagnostic(&self, _category: &str) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connecting,
    BtHandshaking,
    ExtensionNegotiating,
    TorBootstrapping,
    CreatingOnion,
    ConnectingOnion,
    NoiseHandshaking,
    AuthenticatingIdentity,
    Secure,
    Closing,
}

pub struct ModePolicy(pub TransportKind);
impl NetworkObserver for ModePolicy {
    fn before_network_action(&self, action: NetworkAction) -> Result<(), TransportError> {
        let tor_local = matches!(
            action,
            NetworkAction::LocalTorControl
                | NetworkAction::LocalTorSocks
                | NetworkAction::EmbeddedTor
        );
        if (self.0 == TransportKind::Tor) == tor_local {
            Ok(())
        } else {
            Err(TransportError::WrongTransport)
        }
    }
}

pub const COMMAND_QUEUE_CAPACITY: usize = 32;
pub const EVENT_QUEUE_CAPACITY: usize = 128;
pub fn command_channel<T>() -> (tokio::sync::mpsc::Sender<T>, tokio::sync::mpsc::Receiver<T>) {
    tokio::sync::mpsc::channel(COMMAND_QUEUE_CAPACITY)
}
pub fn event_channel<T>() -> (tokio::sync::mpsc::Sender<T>, tokio::sync::mpsc::Receiver<T>) {
    tokio::sync::mpsc::channel(EVENT_QUEUE_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tor_policy_rejects_every_clearnet_operation() {
        let policy = ModePolicy(TransportKind::Tor);
        for action in [
            NetworkAction::MainlineDht,
            NetworkAction::UdpDiscovery,
            NetworkAction::DirectPeerTcp,
            NetworkAction::Tracker,
            NetworkAction::PeerDns,
        ] {
            assert_eq!(
                policy.before_network_action(action),
                Err(TransportError::WrongTransport)
            );
        }
        assert!(
            policy
                .before_network_action(NetworkAction::LocalTorSocks)
                .is_ok()
        );
        assert!(
            policy
                .before_network_action(NetworkAction::LocalTorControl)
                .is_ok()
        );
    }
    #[test]
    fn channels_have_backpressure_and_shutdown() {
        let (tx, rx) = command_channel();
        for _ in 0..COMMAND_QUEUE_CAPACITY {
            tx.try_send(1u8).unwrap();
        }
        assert!(matches!(
            tx.try_send(1),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_))
        ));
        drop(rx);
        assert!(matches!(
            tx.try_send(1),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_))
        ));
        let (tx, _rx) = event_channel::<u8>();
        assert_eq!(tx.capacity(), EVENT_QUEUE_CAPACITY);
    }
    #[test]
    fn transport_is_object_safe() {
        fn check(_: Option<Box<dyn Transport>>) {}
        check(None);
    }
}
