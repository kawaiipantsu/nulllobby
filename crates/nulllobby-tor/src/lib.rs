//! External Tor backend. Only configured loopback ControlPort/SOCKSPort are contacted.
#![forbid(unsafe_code)]
#[cfg(feature = "tor-arti-experimental")]
pub mod arti;
mod control;
pub mod onion;
mod socks;

use nulllobby_platform::SecretBytes;
use nulllobby_transport::{
    BoxStream, Endpoint, EndpointHandle, ModePolicy, NetworkAction, NetworkObserver, NetworkStatus,
    Transport, TransportError, TransportFuture, TransportKind, scoped::ScopedStream,
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU16,
    path::PathBuf,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, watch},
    task::JoinHandle,
};

#[derive(Clone)]
pub struct TorConfig {
    pub socks: SocketAddr,
    pub control: SocketAddr,
    pub cookie: Option<PathBuf>,
}
impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks: SocketAddr::from((Ipv4Addr::LOCALHOST, 9050)),
            control: SocketAddr::from((Ipv4Addr::LOCALHOST, 9051)),
            cookie: None,
        }
    }
}
struct Listener {
    socket: TcpListener,
    endpoint: Endpoint,
    close: watch::Sender<bool>,
    isolation: SecretBytes<32>,
    peers: Arc<Semaphore>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.close.send_replace(true);
    }
}
type Closers = Arc<StdMutex<HashMap<EndpointHandle, watch::Sender<bool>>>>;
pub struct TorTransport {
    config: TorConfig,
    observer: Arc<dyn NetworkObserver>,
    control: Option<Arc<Mutex<control::Control>>>,
    endpoints: HashMap<EndpointHandle, Listener>,
    global: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    active: Arc<AtomicBool>,
    closers: Closers,
    monitor: Option<JoinHandle<()>>,
    isolation_confirmed: bool,
}
impl TorTransport {
    pub fn new(
        config: TorConfig,
        observer: Arc<dyn NetworkObserver>,
        global: Arc<Semaphore>,
        pending: Arc<Semaphore>,
    ) -> Self {
        Self {
            config,
            observer,
            control: None,
            endpoints: HashMap::new(),
            global,
            pending,
            active: Arc::new(AtomicBool::new(false)),
            closers: Arc::new(StdMutex::new(HashMap::new())),
            monitor: None,
            isolation_confirmed: false,
        }
    }
    pub fn isolation_confirmed(&self) -> bool {
        self.isolation_confirmed
    }
    fn allow(&self, action: NetworkAction) -> Result<(), TransportError> {
        ModePolicy(TransportKind::Tor).before_network_action(action)?;
        self.observer.before_network_action(action)
    }
    fn ready(&self) -> Result<(), TransportError> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(TransportError::Unavailable)
        }
    }
    fn entry(&self, local: EndpointHandle) -> Result<&Listener, TransportError> {
        self.ready()?;
        self.endpoints
            .get(&local)
            .ok_or(TransportError::Unavailable)
    }
}
impl Drop for TorTransport {
    fn drop(&mut self) {
        if let Some(monitor) = self.monitor.take() {
            monitor.abort();
        }
        self.endpoints.clear();
        self.control.take(); // Non-detached onions die with this authenticated connection.
    }
}
impl Transport for TorTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tor
    }
    fn start(&mut self) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            self.observer
                .connection_state(nulllobby_transport::ConnectionState::TorBootstrapping);
            if self.control.is_some() {
                return Err(TransportError::Unavailable);
            }
            if !self.config.socks.ip().is_loopback()
                || !self.config.control.ip().is_loopback()
                || self.config.socks.port() == 0
                || self.config.control.port() == 0
            {
                return Err(TransportError::WrongTransport);
            }
            let cookie = self
                .config
                .cookie
                .as_ref()
                .ok_or(TransportError::Unavailable)?;
            self.allow(NetworkAction::LocalTorControl)?;
            let socket = tokio::time::timeout(
                Duration::from_secs(5),
                TcpStream::connect(self.config.control),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Unavailable)?;
            let mut controller = tokio::time::timeout(
                Duration::from_secs(20),
                control::Control::authenticate(socket, cookie),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Unavailable)?;
            let reply = controller
                .command("GETCONF SocksPort")
                .await
                .map_err(|_| TransportError::Unavailable)?;
            // Only claim isolation when the exact configured port explicitly enables it.
            self.isolation_confirmed = reply.iter().any(|line| {
                let mut words = line.trim_matches('"').split_ascii_whitespace();
                let address = words.next().and_then(|s| s.strip_prefix("SocksPort="));
                let flags: Vec<_> = words.collect();
                address.is_some_and(|s| {
                    s == self.config.socks.to_string() || s == self.config.socks.port().to_string()
                }) && flags.contains(&"IsolateSOCKSAuth")
                    && !flags.contains(&"NoIsolateSOCKSAuth")
            });
            self.allow(NetworkAction::LocalTorSocks)?;
            socks::probe(self.config.socks)
                .await
                .map_err(|_| TransportError::Unavailable)?;
            self.active.store(true, Ordering::Release);
            let control = Arc::new(Mutex::new(controller));
            self.control = Some(control.clone());
            let active = self.active.clone();
            let closers = self.closers.clone();
            let observer = self.observer.clone();
            self.monitor = Some(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    if observer
                        .before_network_action(NetworkAction::LocalTorControl)
                        .is_err()
                        || control.lock().await.bootstrap().await.is_err()
                    {
                        active.store(false, Ordering::Release);
                        if let Ok(entries) = closers.lock() {
                            for close in entries.values() {
                                close.send_replace(true);
                            }
                        }
                        break;
                    }
                }
            }));
            Ok(())
        })
    }
    fn stop(&mut self) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            if let Some(monitor) = self.monitor.take() {
                monitor.abort();
            }
            let handles: Vec<_> = self.endpoints.keys().copied().collect();
            for handle in handles {
                let _ = self.destroy_endpoint(handle).await;
            }
            self.control.take();
            self.active.store(false, Ordering::Release);
            Ok(())
        })
    }
    fn create_endpoint(&mut self, _scope: [u8; 32]) -> TransportFuture<'_, EndpointHandle> {
        Box::pin(async move {
            self.ready()?;
            self.observer
                .connection_state(nulllobby_transport::ConnectionState::CreatingOnion);
            if self.endpoints.len() >= 16 {
                return Err(TransportError::ResourceLimit);
            }
            self.allow(NetworkAction::LocalTorControl)?;
            let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|_| TransportError::Unavailable)?;
            let port = NonZeroU16::new(
                socket
                    .local_addr()
                    .map_err(|_| TransportError::Unavailable)?
                    .port(),
            )
            .ok_or(TransportError::Unavailable)?;
            let command =
                format!("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port={port},127.0.0.1:{port}");
            let reply = self
                .control
                .as_ref()
                .ok_or(TransportError::Unavailable)?
                .lock()
                .await
                .command(&command)
                .await
                .map_err(|_| TransportError::Unavailable)?;
            let service = reply
                .iter()
                .find_map(|l| l.strip_prefix("ServiceID="))
                .ok_or(TransportError::Unavailable)?;
            let key = onion::parse_service_id(service).map_err(|_| TransportError::Unavailable)?;
            if self
                .endpoints
                .values()
                .any(|l| matches!(l.endpoint,Endpoint::Onion{service_key,..} if service_key == key))
            {
                return Err(TransportError::Unavailable);
            }
            let handle = EndpointHandle::allocate()?;
            let (close, _) = watch::channel(false);
            let mut isolation =
                SecretBytes::<32>::zeroed().map_err(|_| TransportError::Unavailable)?;
            getrandom::fill(isolation.expose_secret_mut())
                .map_err(|_| TransportError::Unavailable)?;
            self.closers
                .lock()
                .map_err(|_| TransportError::Unavailable)?
                .insert(handle, close.clone());
            self.endpoints.insert(
                handle,
                Listener {
                    socket,
                    endpoint: Endpoint::Onion {
                        service_key: key,
                        port,
                    },
                    close,
                    isolation,
                    peers: Arc::new(Semaphore::new(64)),
                },
            );
            Ok(handle)
        })
    }
    fn destroy_endpoint(&mut self, local: EndpointHandle) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            let entry = self
                .endpoints
                .remove(&local)
                .ok_or(TransportError::Unavailable)?;
            entry.close.send_replace(true);
            self.closers
                .lock()
                .map_err(|_| TransportError::Unavailable)?
                .remove(&local);
            let Endpoint::Onion { service_key, .. } = entry.endpoint else {
                return Err(TransportError::WrongTransport);
            };
            self.allow(NetworkAction::LocalTorControl)?;
            let hostname = onion::hostname(&service_key);
            if let Some(controller) = &self.control {
                controller
                    .lock()
                    .await
                    .command(&format!("DEL_ONION {}", &hostname[..56]))
                    .await
                    .map_err(|_| TransportError::Unavailable)?;
            }
            Ok(())
        })
    }
    fn connect<'a>(
        &'a self,
        local: EndpointHandle,
        peer: &'a Endpoint,
    ) -> TransportFuture<'a, BoxStream> {
        Box::pin(async move {
            let Endpoint::Onion { service_key, port } = peer else {
                return Err(TransportError::WrongTransport);
            };
            let entry = self.entry(local)?;
            self.allow(NetworkAction::LocalTorSocks)?;
            let global = self
                .global
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            let per_peer = entry
                .peers
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            let pending = self
                .pending
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            self.observer
                .connection_state(nulllobby_transport::ConnectionState::ConnectingOnion);
            let stream = socks::connect(
                self.config.socks,
                service_key,
                *port,
                entry.isolation.expose_secret(),
            )
            .await
            .map_err(|_| TransportError::Unavailable)?;
            self.ready()?;
            Ok(ScopedStream::wrap(
                stream,
                entry.close.subscribe(),
                vec![global, per_peer],
                pending,
                self.observer.clone(),
            ))
        })
    }
    fn accept(&self, local: EndpointHandle) -> TransportFuture<'_, BoxStream> {
        Box::pin(async move {
            let entry = self.entry(local)?;
            let (stream, address) = entry
                .socket
                .accept()
                .await
                .map_err(|_| TransportError::Unavailable)?;
            if !address.ip().is_loopback() {
                return Err(TransportError::WrongTransport);
            }
            self.ready()?;
            let global = self
                .global
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            let peer = entry
                .peers
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            let pending = self
                .pending
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            Ok(ScopedStream::wrap(
                stream,
                entry.close.subscribe(),
                vec![global, peer],
                pending,
                self.observer.clone(),
            ))
        })
    }
    fn local_transport_identity(&self, local: EndpointHandle) -> Result<Endpoint, TransportError> {
        Ok(self.entry(local)?.endpoint.clone())
    }
    fn network_status(&self) -> NetworkStatus {
        if self.active.load(Ordering::Acquire) {
            NetworkStatus::Ready
        } else {
            NetworkStatus::Unavailable
        }
    }
}
