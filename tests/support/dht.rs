//! Loopback bootstrap router and storage node. Models routers which only
//! supply routing contacts for find_node, never get_peers.
use bendy::decoding::{Decoder, Object};
use std::{
    collections::HashSet,
    net::SocketAddrV4,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{net::UdpSocket, task::JoinHandle};

pub struct Fixture {
    pub bootstrap: SocketAddrV4,
    pub announces: Arc<AtomicUsize>,
    tasks: [JoinHandle<()>; 2],
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
#[derive(Default)]
struct Request {
    transaction: Vec<u8>,
    method: Vec<u8>,
    scope: Vec<u8>,
    token: Vec<u8>,
    port: u16,
    implied_port: bool,
    read_only: bool,
}
fn request(input: &[u8]) -> Request {
    let mut decoder = Decoder::new(input).with_max_depth(4);
    let Some(Object::Dict(mut root)) = decoder.next_object().unwrap() else {
        panic!("query dictionary")
    };
    let mut out = Request::default();
    while let Some((key, value)) = root.next_pair().unwrap() {
        match (key, value) {
            (b"t", Object::Bytes(v)) => out.transaction = v.to_vec(),
            (b"q", Object::Bytes(v)) => out.method = v.to_vec(),
            (b"ro", Object::Integer(v)) => out.read_only = v == "1",
            (b"a", Object::Dict(mut args)) => {
                while let Some((key, value)) = args.next_pair().unwrap() {
                    match (key, value) {
                        (b"info_hash" | b"target", Object::Bytes(v)) => out.scope = v.to_vec(),
                        (b"token", Object::Bytes(v)) => out.token = v.to_vec(),
                        (b"port", Object::Integer(v)) => out.port = v.parse().unwrap(),
                        (b"implied_port", Object::Integer(v)) => out.implied_port = v != "0",
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    drop(root);
    assert_eq!(out.transaction.len(), 8);
    assert_eq!(out.scope.len(), 20);
    assert!(out.read_only);
    assert!(decoder.next_object().unwrap().is_none());
    out
}
fn response(mut body: Vec<u8>, transaction: &[u8]) -> Vec<u8> {
    body.extend_from_slice(b"e1:t8:");
    body.extend_from_slice(transaction);
    body.extend_from_slice(b"1:y1:re");
    body
}
impl Fixture {
    pub async fn start() -> Self {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let storage = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(bootstrap) = router.local_addr().unwrap() else {
            unreachable!()
        };
        let port = storage.local_addr().unwrap().port();
        let router_task = tokio::spawn(async move {
            let mut buffer = [0; 2048];
            loop {
                let (len, from) = router.recv_from(&mut buffer).await.unwrap();
                let q = request(&buffer[..len]);
                let mut body = b"d1:rd2:id20:12345678901234567890".to_vec();
                if q.method == b"find_node" {
                    body.extend_from_slice(b"5:nodes26:23456789012345678901");
                    body.extend_from_slice(&[127, 0, 0, 1]);
                    body.extend_from_slice(&port.to_be_bytes());
                }
                router
                    .send_to(&response(body, &q.transaction), from)
                    .await
                    .unwrap();
            }
        });
        let announces = Arc::new(AtomicUsize::new(0));
        let count = announces.clone();
        let storage_task = tokio::spawn(async move {
            let mut buffer = [0; 2048];
            let mut ports = HashSet::new();
            let mut scope = None;
            loop {
                let (len, from) = storage.recv_from(&mut buffer).await.unwrap();
                let q = request(&buffer[..len]);
                assert_eq!(scope.get_or_insert_with(|| q.scope.clone()), &q.scope);
                let mut body = b"d1:rd2:id20:23456789012345678901".to_vec();
                match q.method.as_slice() {
                    b"get_peers" => {
                        body.extend_from_slice(b"5:token10:test-token6:valuesl");
                        for port in &ports {
                            body.extend_from_slice(b"6:");
                            body.extend_from_slice(&[127, 0, 0, 1]);
                            body.extend_from_slice(&u16::to_be_bytes(*port));
                        }
                        body.push(b'e');
                    }
                    b"announce_peer" => {
                        assert_eq!(q.token, b"test-token");
                        assert!(!q.implied_port);
                        assert_ne!(q.port, 0);
                        assert!(ports.len() < 64);
                        ports.insert(q.port);
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => panic!("unexpected storage-node method"),
                }
                storage
                    .send_to(&response(body, &q.transaction), from)
                    .await
                    .unwrap();
            }
        });
        Self {
            bootstrap,
            announces,
            tasks: [router_task, storage_task],
        }
    }
}
