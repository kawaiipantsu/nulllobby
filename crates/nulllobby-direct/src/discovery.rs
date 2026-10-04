//! Bounded read-only BEP 5 discovery client. Uses mainline's BEP 42 node IDs,
//! avoiding its actor API's unbounded channels. Never stores application content.
use bendy::decoding::{Decoder, Object};
use nulllobby_transport::{Endpoint, NetworkAction, NetworkObserver, TransportError};
use std::{
    collections::HashSet,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    sync::Arc,
    time::Duration,
};
use tokio::net::UdpSocket;

const MAX_DATAGRAM: usize = 2048;
const MAX_NODES: usize = 64;
const MAX_QUERIES: usize = 24;
const BOOTSTRAPS: [&str; 3] = [
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
];
pub struct Discovery {
    socket: UdpSocket,
    id: [u8; 20],
    bootstrap: Vec<SocketAddrV4>,
    observer: Arc<dyn NetworkObserver>,
    local_fixture: bool,
    public_ip: Option<Ipv4Addr>,
    stats: DiscoveryStats,
}
#[derive(Clone, Copy, Default, Debug)]
pub struct DiscoveryStats {
    pub queries: usize,
    pub replies: usize,
    pub announces: usize,
    pub tokens: usize,
    pub observations: usize,
}
#[derive(Default)]
struct Reply {
    transaction: Vec<u8>,
    token: Vec<u8>,
    nodes: Vec<([u8; 20], SocketAddrV4)>,
    peers: Vec<SocketAddrV4>,
    public_ip: Option<Ipv4Addr>,
    response: bool,
}
enum Query<'a> {
    FindNode,
    GetPeers,
    Announce(NonZeroU16, &'a [u8]),
}
impl Discovery {
    pub async fn start(
        observer: Arc<dyn NetworkObserver>,
        seeds: Option<Vec<SocketAddrV4>>,
    ) -> Result<Self, TransportError> {
        observer.before_network_action(NetworkAction::MainlineDht)?;
        observer.before_network_action(NetworkAction::UdpDiscovery)?;
        let local_fixture = seeds.is_some();
        let mut bootstrap = seeds.unwrap_or_default();
        if bootstrap.is_empty() {
            observer.before_network_action(NetworkAction::PeerDns)?;
            for name in BOOTSTRAPS {
                if let Ok(Ok(addresses)) =
                    tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(name))
                        .await
                {
                    bootstrap.extend(
                        addresses
                            .filter_map(|address| {
                                if let SocketAddr::V4(v4) = address {
                                    Some(v4)
                                } else {
                                    None
                                }
                            })
                            .take(4),
                    );
                }
            }
        }
        bootstrap.truncate(12);
        if bootstrap.is_empty() {
            return Err(TransportError::Unavailable);
        }
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|_| TransportError::Unavailable)?;
        let mut id = [0; 20];
        getrandom::fill(&mut id).map_err(|_| TransportError::Unavailable)?;
        Ok(Self {
            socket,
            id,
            bootstrap,
            observer,
            local_fixture,
            public_ip: None,
            stats: DiscoveryStats::default(),
        })
    }
    pub fn stats(&self) -> DiscoveryStats {
        self.stats
    }
    pub async fn discover_and_announce(
        &mut self,
        scope: [u8; 32],
        port: NonZeroU16,
    ) -> Result<Vec<Endpoint>, TransportError> {
        self.observer
            .before_network_action(NetworkAction::MainlineDht)?;
        self.stats = DiscoveryStats::default();
        let mut hash = [0; 20];
        hash.copy_from_slice(&scope[..20]);
        let mut candidates: Vec<_> = self
            .bootstrap
            .iter()
            .map(|address| ([0; 20], *address))
            .collect();
        let mut visited = HashSet::new();
        let mut peers = HashSet::new();
        for _ in 0..MAX_QUERIES {
            candidates.sort_by_key(|(id, _)| {
                let mut distance = [0; 20];
                for i in 0..20 {
                    distance[i] = id[i] ^ hash[i];
                }
                distance
            });
            let Some(index) = candidates.iter().position(|(_, a)| !visited.contains(a)) else {
                break;
            };
            let (node_id, address) = candidates.remove(index);
            visited.insert(address);
            self.stats.queries += 1;
            // Bootstrap routers supply routing contacts, not necessarily
            // get_peers tokens/values. First find the nodes nearest this swarm.
            let bootstrap = node_id == [0; 20];
            let query = if bootstrap {
                Query::FindNode
            } else {
                Query::GetPeers
            };
            let Ok(reply) = self.request(address, hash, query).await else {
                continue;
            };
            self.stats.replies += 1;
            if !reply.token.is_empty() {
                self.stats.tokens += 1;
            }
            if reply.public_ip.is_some() {
                self.stats.observations += 1;
            }
            if let Some(ip) = reply
                .public_ip
                .filter(|ip| public_v4(*ip) && Some(*ip) != self.public_ip)
            {
                self.id = mainline::Id::from_ipv4(ip).into();
                self.public_ip = Some(ip);
            }
            for peer in reply.peers {
                if peers.len() < 64 && (self.local_fixture || public_v4(*peer.ip())) {
                    peers.insert(peer);
                }
            }
            for node in reply.nodes {
                if candidates.len() < MAX_NODES
                    && (self.local_fixture || public_v4(*node.1.ip()))
                    && !visited.contains(&node.1)
                    && !candidates.iter().any(|(_, a)| *a == node.1)
                {
                    candidates.push(node);
                }
            }
            if !bootstrap
                && !reply.token.is_empty()
                && self
                    .request(address, hash, Query::Announce(port, &reply.token))
                    .await
                    .is_ok()
            {
                self.stats.announces += 1;
            }
        }
        if self.stats.replies == 0 {
            return Err(TransportError::Unavailable);
        }
        Ok(peers
            .into_iter()
            .filter_map(|address| {
                Some(Endpoint::Direct {
                    address: (*address.ip()).into(),
                    port: NonZeroU16::new(address.port())?,
                })
            })
            .collect())
    }
    async fn request(
        &self,
        address: SocketAddrV4,
        hash: [u8; 20],
        query: Query<'_>,
    ) -> io::Result<Reply> {
        self.observer
            .before_network_action(NetworkAction::UdpDiscovery)
            .map_err(|_| io::ErrorKind::PermissionDenied)?;
        let mut transaction = [0; 8];
        getrandom::fill(&mut transaction).map_err(|_| io::ErrorKind::Other)?;
        let mut request = b"d1:ad2:id20:".to_vec();
        request.extend_from_slice(&self.id);
        if matches!(query, Query::Announce(..)) {
            request.extend_from_slice(b"12:implied_porti0e");
        }
        request.extend_from_slice(if matches!(query, Query::FindNode) {
            b"6:target20:"
        } else {
            b"9:info_hash20:"
        });
        request.extend_from_slice(&hash);
        if let Query::Announce(port, token) = query {
            request.extend_from_slice(
                format!("4:porti{}e5:token{}:", port.get(), token.len()).as_bytes(),
            );
            request.extend_from_slice(token);
            request.extend_from_slice(b"e1:q13:announce_peer");
        } else if matches!(query, Query::GetPeers) {
            request.extend_from_slice(b"e1:q9:get_peers");
        } else {
            request.extend_from_slice(b"e1:q9:find_node");
        }
        request.extend_from_slice(b"2:roi1e1:t8:");
        request.extend_from_slice(&transaction);
        request.extend_from_slice(b"1:y1:qe");
        self.socket.send_to(&request, address).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut buffer = [0; MAX_DATAGRAM + 1];
        for _ in 0..64 {
            let (len, from) = tokio::time::timeout_at(deadline, self.socket.recv_from(&mut buffer))
                .await
                .map_err(|_| io::ErrorKind::TimedOut)??;
            if from != SocketAddr::V4(address) || len > MAX_DATAGRAM {
                continue;
            }
            if let Ok(reply) = parse(&buffer[..len])
                && reply.transaction == transaction
                && reply.response
            {
                return Ok(reply);
            }
        }
        Err(io::ErrorKind::InvalidData.into())
    }
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn bytes<'a>(object: Object<'_, 'a>) -> io::Result<&'a [u8]> {
    object.try_into_bytes().map_err(|_| invalid())
}
fn address(bytes: &[u8]) -> Option<SocketAddrV4> {
    if bytes.len() != 6 {
        return None;
    }
    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let port = u16::from_be_bytes([bytes[4], bytes[5]]);
    if port == 0 || ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    Some(SocketAddrV4::new(ip, port))
}
fn parse(input: &[u8]) -> io::Result<Reply> {
    if input.len() > MAX_DATAGRAM {
        return Err(invalid());
    }
    let mut reply = Reply::default();
    let mut decoder = Decoder::new(input).with_max_depth(6);
    {
        let Some(Object::Dict(mut root)) = decoder.next_object().map_err(|_| invalid())? else {
            return Err(invalid());
        };
        while let Some((key, value)) = root.next_pair().map_err(|_| invalid())? {
            match key {
                b"t" => {
                    let value = bytes(value)?;
                    if value.len() > 8 {
                        return Err(invalid());
                    }
                    reply.transaction = value.to_vec();
                }
                b"y" => reply.response = bytes(value)? == b"r",
                b"ip" => reply.public_ip = address(bytes(value)?).map(|address| *address.ip()),
                b"r" => {
                    let Object::Dict(mut data) = value else {
                        return Err(invalid());
                    };
                    while let Some((key, value)) = data.next_pair().map_err(|_| invalid())? {
                        match key {
                            b"token" => {
                                let value = bytes(value)?;
                                if value.len() > 128 {
                                    return Err(invalid());
                                }
                                reply.token = value.to_vec();
                            }
                            b"nodes" => {
                                let value = bytes(value)?;
                                if value.len() % 26 != 0 || value.len() > 26 * 32 {
                                    return Err(invalid());
                                }
                                for node in value.as_chunks::<26>().0 {
                                    if let Some(address) = address(&node[20..]) {
                                        let mut id = [0; 20];
                                        id.copy_from_slice(&node[..20]);
                                        reply.nodes.push((id, address));
                                    }
                                }
                            }
                            b"values" => {
                                let Object::List(mut list) = value else {
                                    return Err(invalid());
                                };
                                let mut count = 0;
                                while let Some(value) = list.next_object().map_err(|_| invalid())? {
                                    count += 1;
                                    if count > 64 {
                                        return Err(invalid());
                                    }
                                    if let Some(peer) = address(bytes(value)?) {
                                        reply.peers.push(peer);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if decoder.next_object().map_err(|_| invalid())?.is_some() {
        return Err(invalid());
    }
    Ok(reply)
}
/// Fuzz entry point: full structural validation without issuing network operations.
pub fn validate_reply(bytes: &[u8]) -> bool {
    parse(bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_dht_response_parser() {
        assert!(parse(b"d1:rd5:token3:abce1:t8:123456781:y1:re").is_ok());
        assert!(parse(&[0; 2049]).is_err());
        assert!(parse(b"d1:rd5:nodes1:xe1:t8:123456781:y1:re").is_err());
        for byte in 0..=255 {
            let _ = parse(&[byte; 128]);
        }
    }
    #[tokio::test]
    async fn tor_observer_prevents_dht_before_dns_or_udp() {
        let policy = Arc::new(nulllobby_transport::ModePolicy(
            nulllobby_transport::TransportKind::Tor,
        ));
        assert!(matches!(
            Discovery::start(policy, None).await,
            Err(TransportError::WrongTransport)
        ));
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_documentation()
        && !ip.is_unspecified()
        && a != 0
        && a < 240
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 198 && (b == 18 || b == 19))
        && !(a == 192 && b == 0)
}

#[cfg(test)]
mod network_tests {
    use super::*;
    #[test]
    fn public_dht_cannot_direct_lan_or_reserved_address_probes() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "0.1.2.3",
        ] {
            assert!(!public_v4(ip.parse().unwrap()));
        }
        assert!(public_v4("8.8.8.8".parse().unwrap()));
    }
}
