//! Local protocol fixtures emulate the external Tor boundary; no relay network is used.
use hmac::{Hmac, KeyInit, Mac};
use nulllobby_tor::{TorConfig, onion};
use sha2::Sha256;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};

#[derive(Default)]
pub struct State {
    pub routes: HashMap<String, SocketAddr>,
    pub isolation: Vec<Vec<u8>>,
    pub created: usize,
    pub deleted: usize,
    pub detached: bool,
}
pub struct Fixture {
    pub config: TorConfig,
    pub state: Arc<Mutex<State>>,
    cookie: PathBuf,
    pub control: JoinHandle<()>,
    socks: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.control.abort();
        self.socks.abort();
        let _ = std::fs::remove_file(&self.cookie);
    }
}
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02X}")).collect()
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn mac(label: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(label).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
impl Fixture {
    pub async fn start() -> Self {
        let mut cookie_bytes = [0; 32];
        getrandom::fill(&mut cookie_bytes).unwrap();
        let cookie = std::env::temp_dir().join(format!(
            "nulllobby-tor-fixture-{}-{}",
            std::process::id(),
            hex(&cookie_bytes[..8])
        ));
        // This simulates Tor's own authentication file, never a NullLobby identity file.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        options
            .open(&cookie)
            .unwrap()
            .write_all(&cookie_bytes)
            .unwrap();
        let controls = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = TorConfig {
            socks: socks.local_addr().unwrap(),
            control: controls.local_addr().unwrap(),
            cookie: Some(cookie.clone()),
        };
        let state = Arc::new(Mutex::new(State::default()));
        let control_state = state.clone();
        let socks_port = config.socks;
        let control_task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    Ok((socket,_)) = controls.accept() => { let state = control_state.clone(); clients.spawn(async move { control_client(socket,cookie_bytes,state,socks_port).await; }); }
                    _ = clients.join_next(), if !clients.is_empty() => {}
                }
            }
        });
        let socks_state = state.clone();
        let socks_task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    Ok((socket,_)) = socks.accept() => { let state = socks_state.clone(); clients.spawn(async move { let _ = socks_client(socket,state).await; }); }
                    _ = clients.join_next(), if !clients.is_empty() => {}
                }
            }
        });
        Self {
            config,
            state,
            cookie,
            control: control_task,
            socks: socks_task,
        }
    }
}
async fn control_client(
    socket: TcpStream,
    cookie: [u8; 32],
    state: Arc<Mutex<State>>,
    socks: SocketAddr,
) {
    let mut socket = BufReader::new(socket);
    let mut line = String::new();
    let mut expected = String::new();
    let mut authenticated = false;
    let mut services = Vec::new();
    loop {
        line.clear();
        if socket.read_line(&mut line).await.unwrap_or(0) == 0 {
            break;
        }
        let command = line.trim();
        let response = if command == "PROTOCOLINFO 1" {
            "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE COOKIEFILE=\"ignored-by-client\"\r\n250 OK\r\n".to_owned()
        } else if let Some(client) = command.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
            let client = unhex(client);
            let server = [0x34; 32];
            let data = [cookie.as_slice(), &client, &server].concat();
            expected = hex(&mac(
                b"Tor safe cookie authentication controller-to-server hash",
                &data,
            ));
            format!(
                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                hex(&mac(
                    b"Tor safe cookie authentication server-to-controller hash",
                    &data
                )),
                hex(&server)
            )
        } else if let Some(proof) = command.strip_prefix("AUTHENTICATE ") {
            if proof != expected || expected.is_empty() {
                break;
            }
            authenticated = true;
            "250 OK\r\n".to_owned()
        } else {
            assert!(authenticated);
            if command == "GETINFO status/bootstrap-phase" {
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n".to_owned()
            } else if command == "GETCONF SocksPort" {
                format!("250 SocksPort={socks} IsolateSOCKSAuth\r\n")
            } else if let Some(parameters) = command.strip_prefix("ADD_ONION NEW:ED25519-V3 ") {
                assert!(parameters.contains("Flags=DiscardPK"));
                let mut state = state.lock().unwrap();
                state.detached |= parameters.contains("Detach");
                let address: SocketAddr = parameters.split_once(',').unwrap().1.parse().unwrap();
                assert!(address.ip().is_loopback());
                let mut key = [0; 32];
                getrandom::fill(&mut key).unwrap();
                let hostname = onion::hostname(&key);
                state.routes.insert(hostname.clone(), address);
                state.created += 1;
                services.push(hostname.clone());
                format!("250-ServiceID={}\r\n250 OK\r\n", &hostname[..56])
            } else if let Some(service) = command.strip_prefix("DEL_ONION ") {
                let name = format!("{service}.onion");
                let mut state = state.lock().unwrap();
                state.routes.remove(&name);
                state.deleted += 1;
                "250 OK\r\n".to_owned()
            } else {
                panic!("unexpected control command category");
            }
        };
        if socket
            .get_mut()
            .write_all(response.as_bytes())
            .await
            .is_err()
        {
            break;
        }
    }
    let mut state = state.lock().unwrap();
    for service in services {
        state.routes.remove(&service);
    }
}
async fn socks_client(mut socket: TcpStream, state: Arc<Mutex<State>>) -> std::io::Result<()> {
    let mut hello = [0; 3];
    socket.read_exact(&mut hello).await?;
    assert_eq!(hello, [5, 1, 2]);
    socket.write_all(&[5, 2]).await?;
    let version = socket.read_u8().await?;
    assert_eq!(version, 1);
    let count = socket.read_u8().await? as usize;
    let mut username = vec![0; count];
    socket.read_exact(&mut username).await?;
    let count = socket.read_u8().await? as usize;
    let mut password = vec![0; count];
    socket.read_exact(&mut password).await?;
    assert_eq!(username, password);
    state.lock().unwrap().isolation.push(username);
    socket.write_all(&[1, 0]).await?;
    let mut header = [0; 5];
    socket.read_exact(&mut header).await?;
    assert_eq!(header, [5, 1, 0, 3, 62]);
    let mut host = [0; 62];
    socket.read_exact(&mut host).await?;
    let host = std::str::from_utf8(&host).unwrap();
    assert!(host.ends_with(".onion"));
    onion::parse_service_id(&host[..56]).unwrap();
    let _port = socket.read_u16().await?;
    let target = state.lock().unwrap().routes.get(host).copied();
    let Some(target) = target else {
        socket.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(());
    };
    let mut peer = TcpStream::connect(target).await?;
    socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut socket, &mut peer).await?;
    Ok(())
}
