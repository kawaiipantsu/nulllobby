use crate::{Handshake, PeerId, SwarmId, extension};
use nulllobby_transport::{
    BoxStream, ConnectionState, Endpoint, EndpointHandle, ModePolicy, NetworkAction,
    NetworkObserver, NetworkStatus, Transport, TransportError, TransportFuture, TransportKind,
    framing,
};
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU16,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinHandle,
};

#[derive(Clone)]
pub struct DirectConfig {
    pub listen: SocketAddr,
}
impl Default for DirectConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}
struct Listener {
    socket: Arc<TcpListener>,
    swarm: SwarmId,
    close: watch::Sender<bool>,
    peers: Arc<Semaphore>,
}
pub struct DirectTransport {
    config: DirectConfig,
    observer: Arc<dyn NetworkObserver>,
    status: NetworkStatus,
    endpoints: HashMap<EndpointHandle, Listener>,
    pending: Arc<Semaphore>,
    global: Arc<Semaphore>,
}
impl DirectTransport {
    pub fn new(
        config: DirectConfig,
        observer: Arc<dyn NetworkObserver>,
        global: Arc<Semaphore>,
    ) -> Self {
        Self {
            config,
            observer,
            status: NetworkStatus::Stopped,
            endpoints: HashMap::new(),
            pending: Arc::new(Semaphore::new(32)),
            global,
        }
    }
    fn allow(&self) -> Result<(), TransportError> {
        ModePolicy(TransportKind::Direct).before_network_action(NetworkAction::DirectPeerTcp)?;
        self.observer
            .before_network_action(NetworkAction::DirectPeerTcp)
    }
    pub fn with_pending(mut self, pending: Arc<Semaphore>) -> Self {
        self.pending = pending;
        self
    }
    async fn prepare(
        &self,
        mut socket: TcpStream,
        entry: &Listener,
        permit: OwnedSemaphorePermit,
        global: OwnedSemaphorePermit,
    ) -> Result<BoxStream, TransportError> {
        let pending = self
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| TransportError::ResourceLimit)?;
        let close = entry.close.subscribe();
        self.observer
            .connection_state(ConnectionState::BtHandshaking);
        let handshake = async {
            let local = Handshake::new(
                entry.swarm,
                PeerId::generate().map_err(|_| TransportError::Unavailable)?,
            );
            socket
                .write_all(&local.encode())
                .await
                .map_err(|_| TransportError::Unavailable)?;
            let mut bytes = [0; 68];
            socket
                .read_exact(&mut bytes)
                .await
                .map_err(|_| TransportError::Unavailable)?;
            Handshake::parse(&bytes)
                .and_then(|h| h.validate_for(entry.swarm))
                .map_err(|_| TransportError::Unavailable)?;
            self.observer
                .connection_state(ConnectionState::ExtensionNegotiating);
            extension::negotiate(&mut socket)
                .await
                .map_err(|_| TransportError::Unavailable)
        };
        let extension = tokio::time::timeout(Duration::from_secs(10), handshake)
            .await
            .map_err(|_| TransportError::Timeout)??;
        Ok(bridge(
            socket,
            extension,
            close,
            permit,
            global,
            pending,
            self.observer.clone(),
        ))
    }
}
impl Transport for DirectTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Direct
    }
    fn start(&mut self) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            self.allow()?;
            self.status = NetworkStatus::Ready;
            Ok(())
        })
    }
    fn stop(&mut self) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            self.endpoints.clear();
            self.status = NetworkStatus::Stopped;
            Ok(())
        })
    }
    fn create_endpoint(&mut self, scope: [u8; 32]) -> TransportFuture<'_, EndpointHandle> {
        Box::pin(async move {
            if self.status != NetworkStatus::Ready {
                return Err(TransportError::Unavailable);
            }
            if self.endpoints.len() >= 16 {
                return Err(TransportError::ResourceLimit);
            }
            self.allow()?;
            let listener = TcpListener::bind(self.config.listen)
                .await
                .map_err(|_| TransportError::Unavailable)?;
            let handle = EndpointHandle::allocate()?;
            let mut swarm = [0; 20];
            swarm.copy_from_slice(&scope[..20]);
            let (close, _) = watch::channel(false);
            self.endpoints.insert(
                handle,
                Listener {
                    socket: Arc::new(listener),
                    swarm: SwarmId(swarm),
                    close,
                    peers: Arc::new(Semaphore::new(64)),
                },
            );
            Ok(handle)
        })
    }
    fn destroy_endpoint(&mut self, endpoint: EndpointHandle) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            self.endpoints
                .remove(&endpoint)
                .ok_or(TransportError::Unavailable)?;
            Ok(())
        })
    }
    fn connect<'a>(
        &'a self,
        local: EndpointHandle,
        peer: &'a Endpoint,
    ) -> TransportFuture<'a, BoxStream> {
        Box::pin(async move {
            let Endpoint::Direct { address, port } = peer else {
                return Err(TransportError::WrongTransport);
            };
            self.allow()?;
            let entry = self
                .endpoints
                .get(&local)
                .ok_or(TransportError::Unavailable)?;
            self.observer.connection_state(ConnectionState::Connecting);
            let permit = entry
                .peers
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            let global = self
                .global
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            let socket = tokio::time::timeout(
                Duration::from_secs(10),
                TcpStream::connect(SocketAddr::new(*address, port.get())),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Unavailable)?;
            self.prepare(socket, entry, permit, global).await
        })
    }
    fn accept(&self, local: EndpointHandle) -> TransportFuture<'_, BoxStream> {
        Box::pin(async move {
            self.allow()?;
            let entry = self
                .endpoints
                .get(&local)
                .ok_or(TransportError::Unavailable)?;
            let (socket, _) = entry
                .socket
                .accept()
                .await
                .map_err(|_| TransportError::Unavailable)?;
            let permit = entry
                .peers
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            let global = self
                .global
                .clone()
                .try_acquire_owned()
                .map_err(|_| TransportError::ResourceLimit)?;
            self.prepare(socket, entry, permit, global).await
        })
    }
    fn local_transport_identity(&self, local: EndpointHandle) -> Result<Endpoint, TransportError> {
        let address = self
            .endpoints
            .get(&local)
            .ok_or(TransportError::Unavailable)?
            .socket
            .local_addr()
            .map_err(|_| TransportError::Unavailable)?;
        Ok(Endpoint::Direct {
            address: address.ip(),
            port: NonZeroU16::new(address.port()).ok_or(TransportError::Unavailable)?,
        })
    }
    fn network_status(&self) -> NetworkStatus {
        self.status
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.close.send(true);
    }
}

struct Bridge {
    io: DuplexStream,
    task: JoinHandle<()>,
    _peer: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
    pending: Option<OwnedSemaphorePermit>,
    observer: Arc<dyn NetworkObserver>,
}
impl nulllobby_transport::ByteStream for Bridge {
    fn connection_state(&mut self, state: ConnectionState) {
        self.observer.connection_state(state);
    }
    fn authenticated(&mut self) {
        self.pending.take();
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.observer.connection_state(ConnectionState::Closing);
        self.task.abort();
    }
}
impl AsyncRead for Bridge {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for Bridge {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
fn bridge(
    socket: TcpStream,
    peer_extension: u8,
    mut close: watch::Receiver<bool>,
    peer: OwnedSemaphorePermit,
    global: OwnedSemaphorePermit,
    pending: OwnedSemaphorePermit,
    observer: Arc<dyn NetworkObserver>,
) -> BoxStream {
    let (client, adapter) = tokio::io::duplex(65_536);
    let task = tokio::spawn(async move {
        let (mut net_read, mut net_write) = socket.into_split();
        let (mut app_read, mut app_write) = tokio::io::split(adapter);
        let send = async {
            let mut records = framing::RecordReader::default();
            loop {
                let (tag, bytes) = records.read(&mut app_read).await?;
                let mut payload = Vec::with_capacity(bytes.len() + 1);
                payload.push(tag);
                payload.extend_from_slice(&bytes);
                extension::send(&mut net_write, peer_extension, &payload).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), io::Error>(())
        };
        let receive = async {
            let mut updates = 0u8;
            loop {
                let (id, bytes) = extension::receive(&mut net_read, 65_530).await?;
                if id == 0 {
                    // BEP 10 permits updates. Accept unchanged negotiation only, with a strict bound.
                    updates = updates.checked_add(1).ok_or(io::ErrorKind::InvalidData)?;
                    if updates > 4 || extension::parse_handshake(&bytes)? != peer_extension {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    continue;
                }
                if id != extension::LOCAL_EXTENSION || bytes.len() < 2 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                framing::write(&mut app_write, bytes[0], &bytes[1..]).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), io::Error>(())
        };
        tokio::select! { _ = send => {}, _ = receive => {}, _ = close.changed() => {} }
    });
    Box::new(Bridge {
        io: client,
        task,
        _peer: peer,
        _global: global,
        pending: Some(pending),
        observer,
    })
}
