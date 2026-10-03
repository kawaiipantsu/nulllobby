//! Experimental embedded Arti. Only onion destinations cross the peer boundary.
//! Tor's guard/cache state is durable; each service has its own RAM-only store.
use arti_client::{TorClient, TorClientConfig, config::TorClientConfigBuilder};
use futures::StreamExt;
use nulllobby_transport::{
    BoxStream, ConnectionState, Endpoint, EndpointHandle, ModePolicy, NetworkAction,
    NetworkObserver, NetworkStatus, Transport, TransportError, TransportFuture, TransportKind,
    scoped::ScopedStream,
};
use std::{collections::HashMap, num::NonZeroU16, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_error::HasKind;
use tor_hsservice::{OnionService, RunningOnionService, status::State};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;

pub const REVIEWED_ARTI_VERSION: &str = "0.47.0";
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const ONION_PORT: u16 = 443;
type Client = Arc<TorClient<PreferredRuntime>>;

#[derive(Clone)]
pub struct ArtiConfig {
    /// Normal Tor guard state; deliberately persistent and never reset on leave.
    pub state_dir: PathBuf,
    /// Normal Tor directory cache; contains no NullLobby service state or keys.
    pub cache_dir: PathBuf,
}
impl ArtiConfig {
    fn client_config(&self) -> Result<TorClientConfig, TransportError> {
        if !self.state_dir.is_absolute()
            || !self.cache_dir.is_absolute()
            || self.state_dir == self.cache_dir
        {
            return Err(TransportError::Unavailable);
        }
        let mut config = TorClientConfigBuilder::from_directories(&self.state_dir, &self.cache_dir);
        config
            .storage()
            .keystore()
            .primary()
            .kind(tor_keymgr::config::ArtiKeystoreKind::Ephemeral.into());
        // Arti's accounting is approximate, not a bound on total process RSS.
        config.system().memory().max(64 * 1024 * 1024_usize);
        config.system().memory().low_water(48 * 1024 * 1024_usize);
        config.build().map_err(|_| TransportError::Unavailable)
    }
}

/// One Tor client per process, shared by all Arti lobby transports. No onion
/// identity or service state is stored here. No fallback backend is available.
pub struct ArtiPool {
    config: ArtiConfig,
    client: Mutex<Option<Client>>,
}
impl ArtiPool {
    pub fn new(config: ArtiConfig) -> Self {
        Self {
            config,
            client: Mutex::new(None),
        }
    }
    async fn client(&self, observer: &dyn NetworkObserver) -> Result<Client, TransportError> {
        let config = self.config.client_config()?;
        let mut entry = self.client.lock().await;
        if let Some(client) = &*entry {
            if client.bootstrap_status().ready_for_traffic() {
                return Ok(client.clone());
            }
            return Err(TransportError::Unavailable);
        }
        ModePolicy(TransportKind::Tor).before_network_action(NetworkAction::EmbeddedTor)?;
        observer.before_network_action(NetworkAction::EmbeddedTor)?;
        // Upstream enables multiple TLS providers transitively. Select ring
        // before constructing its runtime; another initialized provider is kept.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let runtime = PreferredRuntime::current().map_err(|_| TransportError::Unavailable)?;
        let client = TorClient::with_runtime(runtime)
            .config(config)
            .create_unbootstrapped_async()
            .await
            .map_err(|_| TransportError::Unavailable)?;
        let bootstrap = client.bootstrap();
        tokio::pin!(bootstrap);
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut last = None;
        let mut bootstrapped = false;
        tokio::time::timeout(BOOTSTRAP_TIMEOUT, async {
            loop {
                tokio::select! {
                    result = &mut bootstrap, if !bootstrapped => {
                        result.map_err(|_| TransportError::Unavailable)?;
                        bootstrapped = true;
                    },
                    _ = tick.tick() => {
                        let progress = (client.bootstrap_status().as_frac().clamp(0.0, 1.0) * 100.0) as u8;
                        if last != Some(progress) {
                            observer.bootstrap_progress(progress);
                            last = Some(progress);
                        }
                        // The status stream can lag behind bootstrap completion.
                        if bootstrapped && client.bootstrap_status().ready_for_traffic() {
                            break Ok::<(), TransportError>(());
                        }
                    }
                }
            }
        }).await.map_err(|_| TransportError::Timeout)??;
        observer.bootstrap_progress(100);
        *entry = Some(client.clone());
        Ok(client.clone())
    }
}

struct Listener {
    service: Arc<RunningOnionService>,
    endpoint: Endpoint,
    client: Client,
    close: watch::Sender<bool>,
    incoming: Mutex<mpsc::Receiver<BoxStream>>,
    task: JoinHandle<()>,
    peers: Arc<Semaphore>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.close.send_replace(true);
        self.task.abort();
    }
}

pub struct ArtiTransport {
    pool: Arc<ArtiPool>,
    client: Option<Client>,
    observer: Arc<dyn NetworkObserver>,
    global: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    endpoints: HashMap<EndpointHandle, Listener>,
}
impl ArtiTransport {
    pub fn new(
        pool: Arc<ArtiPool>,
        observer: Arc<dyn NetworkObserver>,
        global: Arc<Semaphore>,
        pending: Arc<Semaphore>,
    ) -> Self {
        Self {
            pool,
            client: None,
            observer,
            global,
            pending,
            endpoints: HashMap::new(),
        }
    }
    fn entry(&self, local: EndpointHandle) -> Result<&Listener, TransportError> {
        if self.network_status() != NetworkStatus::Ready {
            return Err(TransportError::Unavailable);
        }
        let entry = self
            .endpoints
            .get(&local)
            .ok_or(TransportError::Unavailable)?;
        if *entry.close.borrow() {
            return Err(TransportError::Unavailable);
        }
        Ok(entry)
    }
}
impl Transport for ArtiTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tor
    }
    fn start(&mut self) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            if self.client.is_some() {
                return Err(TransportError::Unavailable);
            }
            self.observer
                .connection_state(ConnectionState::TorBootstrapping);
            self.client = Some(self.pool.client(self.observer.as_ref()).await?);
            Ok(())
        })
    }
    fn stop(&mut self) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            self.endpoints.clear();
            self.client = None;
            Ok(())
        })
    }
    fn create_endpoint(&mut self, _scope: [u8; 32]) -> TransportFuture<'_, EndpointHandle> {
        Box::pin(async move {
            if self.network_status() != NetworkStatus::Ready {
                return Err(TransportError::Unavailable);
            }
            if self.endpoints.len() >= 16 {
                return Err(TransportError::ResourceLimit);
            }
            let client = self.client.as_ref().ok_or(TransportError::Unavailable)?;
            self.observer
                .connection_state(ConnectionState::CreatingOnion);
            let handle = EndpointHandle::allocate()?;
            // Nicknames are local, process-scoped and never sent by NullLobby.
            let config = tor_hsservice::config::OnionServiceConfigBuilder::default()
                .nickname(
                    format!("ephemeral-{}", handle.0)
                        .parse()
                        .map_err(|_| TransportError::Unavailable)?,
                )
                .build()
                .map_err(|_| TransportError::Unavailable)?;
            let service =
                OnionService::new_ephemeral(config).map_err(|_| TransportError::Unavailable)?;
            let (service, requests) = service
                .launch(
                    client.runtime().clone(),
                    client.dirmgr().map_err(|_| TransportError::Unavailable)?,
                    client
                        .hs_circ_pool()
                        .map_err(|_| TransportError::Unavailable)?,
                    Arc::new(tor_config_path::CfgPathResolver::default()),
                )
                .map_err(|_| TransportError::Unavailable)?
                .ok_or(TransportError::Unavailable)?;
            let onion = service.onion_address().ok_or(TransportError::Unavailable)?;
            let key = *onion.as_ref();
            let endpoint = Endpoint::Onion {
                service_key: key,
                port: NonZeroU16::new(ONION_PORT).ok_or(TransportError::Unavailable)?,
            };
            let (close, mut closing) = watch::channel(false);
            let (tx, incoming) = mpsc::channel(8);
            let peers = Arc::new(Semaphore::new(64));
            let limits = Limits {
                global: self.global.clone(),
                pending: self.pending.clone(),
                peers: peers.clone(),
            };
            let observer = self.observer.clone();
            let close_worker = close.clone();
            let service_health = Arc::downgrade(&service);
            let client_health = client.clone();
            let task = tokio::spawn(async move {
                let mut requests = Box::pin(requests);
                let mut handlers = JoinSet::new();
                let mut health = tokio::time::interval(Duration::from_secs(5));
                let mut last_state = None;
                loop {
                    tokio::select! {
                        biased;
                        _ = closing.changed() => break,
                        _ = health.tick() => {
                            if let Some(service) = service_health.upgrade() {
                                let status = service.status();
                                if last_state != Some(status.state()) {
                                    observer.transport_diagnostic(&format!("Arti onion service: {:?}", status.state()));
                                    last_state = Some(status.state());
                                }
                                if let Some(tor_hsservice::status::Problem::Runtime(error)) = status.current_problem() {
                                    observer.transport_diagnostic(&format!("Arti service failure: {:?}", error.kind()));
                                }
                            }
                            let broken = service_health.upgrade().is_none_or(|service| matches!(service.status().state(), State::Broken));
                            if broken || !client_health.bootstrap_status().ready_for_traffic() {
                                observer.transport_diagnostic("Arti service or relay connectivity unavailable; closing streams");
                                break;
                            }
                        }
                        _ = handlers.join_next(), if !handlers.is_empty() => {},
                        request = requests.next() => {
                            let Some(request) = request else { break; };
                            if handlers.len() >= 16 { let _ = request.reject().await; continue; }
                            let tx = tx.clone();
                            let limits = limits.clone();
                            let observer = observer.clone();
                            let close = close_worker.clone();
                            handlers.spawn(async move {
                                let Ok(Ok(mut streams)) = tokio::time::timeout(Duration::from_secs(20), request.accept()).await else { return; };
                                loop {
                                    let Ok(Some(request)) = tokio::time::timeout(Duration::from_secs(120), streams.next()).await else { break; };
                                    if !matches!(request.request(), IncomingStreamRequest::Begin(begin) if begin.port() == ONION_PORT) {
                                        let _ = request.shutdown_circuit(); break;
                                    }
                                    let Ok((permits, pending)) = limits.acquire() else { let _ = request.shutdown_circuit(); break; };
                                    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), request.accept(tor_cell::relaycell::msg::Connected::new_empty())).await else { break; };
                                    if *close.borrow() { break; }
                                    let stream = ScopedStream::wrap(stream.compat(), close.subscribe(), permits, pending, observer.clone());
                                    if tx.try_send(stream).is_err() { break; }
                                }
                            });
                        }
                    }
                }
                close_worker.send_replace(true);
            });
            self.endpoints.insert(
                handle,
                Listener {
                    service,
                    endpoint,
                    client: client.isolated_client(),
                    close,
                    incoming: Mutex::new(incoming),
                    task,
                    peers,
                },
            );
            Ok(handle)
        })
    }
    fn destroy_endpoint(&mut self, local: EndpointHandle) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            self.endpoints
                .remove(&local)
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
            let Endpoint::Onion { service_key, port } = peer else {
                return Err(TransportError::WrongTransport);
            };
            let entry = self.entry(local)?;
            self.observer
                .before_network_action(NetworkAction::EmbeddedTor)?;
            let (permits, pending) = Limits {
                global: self.global.clone(),
                pending: self.pending.clone(),
                peers: entry.peers.clone(),
            }
            .acquire()?;
            self.observer
                .connection_state(ConnectionState::ConnectingOnion);
            let address = crate::onion::hostname(service_key);
            let stream = tokio::time::timeout(
                CONNECT_TIMEOUT,
                entry.client.connect((address.as_str(), port.get())),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|error| {
                self.observer
                    .transport_diagnostic(&format!("Arti connection failed: {:?}", error.kind()));
                TransportError::Unavailable
            })?;
            self.entry(local)?;
            Ok(ScopedStream::wrap(
                stream.compat(),
                entry.close.subscribe(),
                permits,
                pending,
                self.observer.clone(),
            ))
        })
    }
    fn accept(&self, local: EndpointHandle) -> TransportFuture<'_, BoxStream> {
        Box::pin(async move {
            let entry = self.entry(local)?;
            let mut close = entry.close.subscribe();
            if *close.borrow() {
                return Err(TransportError::Unavailable);
            }
            let mut incoming = entry.incoming.lock().await;
            tokio::select! {
                _ = close.changed() => Err(TransportError::Unavailable),
                stream = incoming.recv() => {
                    self.entry(local)?;
                    stream.ok_or(TransportError::Unavailable)
                }
            }
        })
    }
    fn local_transport_identity(&self, local: EndpointHandle) -> Result<Endpoint, TransportError> {
        Ok(self.entry(local)?.endpoint.clone())
    }
    fn network_status(&self) -> NetworkStatus {
        if self
            .client
            .as_ref()
            .is_some_and(|c| c.bootstrap_status().ready_for_traffic())
            && self
                .endpoints
                .values()
                .all(|e| !*e.close.borrow() && !matches!(e.service.status().state(), State::Broken))
        {
            NetworkStatus::Ready
        } else {
            NetworkStatus::Unavailable
        }
    }
}
#[derive(Clone)]
struct Limits {
    global: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    peers: Arc<Semaphore>,
}
impl Limits {
    fn acquire(&self) -> Result<(Vec<OwnedSemaphorePermit>, OwnedSemaphorePermit), TransportError> {
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| TransportError::ResourceLimit)?;
        let peer = self
            .peers
            .clone()
            .try_acquire_owned()
            .map_err(|_| TransportError::ResourceLimit)?;
        let pending = self
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| TransportError::ResourceLimit)?;
        Ok((vec![global, peer], pending))
    }
}
