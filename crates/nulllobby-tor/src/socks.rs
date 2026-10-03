use crate::onion;
use std::{io, net::SocketAddr, num::NonZeroU16, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::Zeroizing;

pub(crate) async fn probe(address: SocketAddr) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(address).await?;
        negotiate(&mut stream).await
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}
async fn negotiate(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(&[5, 1, 2]).await?;
    let mut response = [0; 2];
    stream.read_exact(&mut response).await?;
    if response != [5, 2] {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}
pub(crate) async fn connect(
    address: SocketAddr,
    key: &[u8; 32],
    port: NonZeroU16,
    isolation: &[u8; 32],
) -> io::Result<TcpStream> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let mut stream = TcpStream::connect(address).await?;
        negotiate(&mut stream).await?;
        let mut credentials = Zeroizing::new(Vec::with_capacity(67));
        credentials.extend_from_slice(&[1, 32]);
        credentials.extend_from_slice(isolation);
        credentials.push(32);
        credentials.extend_from_slice(isolation);
        stream.write_all(&credentials).await?;
        let mut response = [0; 2];
        stream.read_exact(&mut response).await?;
        if response != [1, 0] {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let hostname = onion::hostname(key);
        let mut request = Vec::with_capacity(69);
        request.extend_from_slice(&[5, 1, 0, 3, 62]);
        request.extend_from_slice(hostname.as_bytes());
        request.extend_from_slice(&port.get().to_be_bytes());
        stream.write_all(&request).await?;
        let mut head = [0; 4];
        stream.read_exact(&mut head).await?;
        if head[..3] != [5, 0, 0] {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        let count = match head[3] {
            1 => 4,
            4 => 16,
            3 => stream.read_u8().await? as usize,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        let mut rest = [0; 257];
        stream.read_exact(&mut rest[..count + 2]).await?;
        Ok(stream)
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}
