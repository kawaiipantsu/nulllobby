#![forbid(unsafe_code)]
use nulllobby_core::{
    EphemeralIdentity, LobbyId, PrivateLobbySecret, domain::PaddingPolicy, session::SecureSession,
};
use nulllobby_direct::{DirectConfig, DirectTransport};
use nulllobby_transport::{
    ConnectionState, Endpoint, ModePolicy, NetworkAction, NetworkObserver, Transport,
    TransportError, TransportKind,
};
use std::{
    net::SocketAddr,
    num::NonZeroU16,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
#[derive(Default)]
struct States(Mutex<Vec<ConnectionState>>);
impl NetworkObserver for States {
    fn before_network_action(&self, action: NetworkAction) -> Result<(), TransportError> {
        ModePolicy(TransportKind::Direct).before_network_action(action)
    }
    fn connection_state(&self, state: ConnectionState) {
        self.0.lock().unwrap().push(state);
    }
}

#[tokio::test]
async fn real_tcp_uses_bt_extension_noise_proof_and_hides_plaintext() {
    let config = DirectConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
    };
    let observer = Arc::new(States::default());
    let global = Arc::new(Semaphore::new(128));
    let mut a = DirectTransport::new(config.clone(), observer.clone(), global.clone());
    let mut b = DirectTransport::new(config, Arc::new(ModePolicy(TransportKind::Direct)), global);
    a.start().await.unwrap();
    b.start().await.unwrap();
    let ha = a.create_endpoint([7; 32]).await.unwrap();
    let hb = b.create_endpoint([7; 32]).await.unwrap();
    let Endpoint::Direct { address, port } = b.local_transport_identity(hb).unwrap() else {
        panic!("wrong transport")
    };
    let target = SocketAddr::new(address, port.get());
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let wire = captured.clone();
    let proxy_task = tokio::spawn(async move {
        let (client, _) = proxy.accept().await.unwrap();
        let upstream = TcpStream::connect(target).await.unwrap();
        let (mut ar, mut aw) = client.into_split();
        let (mut br, mut bw) = upstream.into_split();
        let outgoing = async {
            let mut buf = [0; 4096];
            loop {
                let n = ar.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                {
                    let mut log = wire.lock().unwrap();
                    assert!(log.len() + n <= 262144);
                    log.extend_from_slice(&buf[..n]);
                }
                bw.write_all(&buf[..n]).await.unwrap();
            }
        };
        let incoming = async {
            let _ = tokio::io::copy(&mut br, &mut aw).await;
        };
        tokio::join!(outgoing, incoming);
    });
    let peer = Endpoint::Direct {
        address: proxy_addr.ip(),
        port: NonZeroU16::new(proxy_addr.port()).unwrap(),
    };
    let (ca, cb) = tokio::join!(a.connect(ha, &peer), b.accept(hb));
    let lobby = LobbyId::random_public().unwrap();
    let ia = EphemeralIdentity::generate(lobby).unwrap();
    let ib = EphemeralIdentity::generate(lobby).unwrap();
    let keys = PrivateLobbySecret::generate().unwrap().derive().unwrap();
    let (sa, sb) = tokio::join!(
        SecureSession::establish(ca.unwrap(), &ia, Some(&keys.noise_psk), true),
        SecureSession::establish(cb.unwrap(), &ib, Some(&keys.noise_psk), false)
    );
    let (_, mut sender) = sa.unwrap().split();
    let (mut receiver, _) = sb.unwrap().split();
    assert_eq!(
        *observer.0.lock().unwrap(),
        vec![
            ConnectionState::Connecting,
            ConnectionState::BtHandshaking,
            ConnectionState::ExtensionNegotiating,
            ConnectionState::NoiseHandshaking,
            ConnectionState::AuthenticatingIdentity,
            ConnectionState::Secure
        ]
    );
    let plaintext = b"synthetic chat canary never visible on the network";
    sender
        .send(plaintext, PaddingPolicy::Bucketed)
        .await
        .unwrap();
    assert_eq!(&**receiver.receive().await.unwrap(), plaintext);
    {
        let log = captured.lock().unwrap();
        assert_eq!(&log[..20], b"\x13BitTorrent protocol");
        assert!(log.windows(7).any(|w| w == b"NL_chat"));
        assert!(!log.windows(plaintext.len()).any(|w| w == plaintext));
        assert!(!log.windows(32).any(|w| w == ia.public_key()));
    }
    b.destroy_endpoint(hb).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), receiver.receive())
            .await
            .unwrap()
            .is_err()
    );
    proxy_task.abort();
    a.stop().await.unwrap();
}
