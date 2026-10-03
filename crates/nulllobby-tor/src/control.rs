use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{io, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::Zeroizing;

pub(crate) struct Control {
    socket: TcpStream,
    healthy: bool,
}
impl Control {
    pub async fn authenticate(socket: TcpStream, cookie_path: &Path) -> io::Result<Self> {
        let mut this = Self {
            socket,
            healthy: true,
        };
        let info = this.command("PROTOCOLINFO 1").await?;
        let safe = info.iter().any(|line| {
            line.split_ascii_whitespace().any(|part| {
                part.strip_prefix("METHODS=")
                    .is_some_and(|m| m.split(',').any(|s| s == "SAFECOOKIE"))
            })
        });
        if !safe {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // The path comes from the user, never from an unauthenticated control server.
        let metadata = tokio::fs::metadata(cookie_path).await?;
        if !metadata.is_file() || metadata.len() != 32 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut file = tokio::fs::File::open(cookie_path).await?;
        if !file.metadata().await?.is_file() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut cookie = Zeroizing::new([0; 33]);
        file.read_exact(&mut cookie[..32]).await?;
        if file.read(&mut cookie[32..]).await? != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut client = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *client).map_err(|_| io::ErrorKind::Other)?;
        let command = Zeroizing::new(format!("AUTHCHALLENGE SAFECOOKIE {}", hex(&*client)));
        let reply = this.command(&command).await?;
        let server_hash = field_hex(&reply, "SERVERHASH=")?;
        let server_nonce = field_hex(&reply, "SERVERNONCE=")?;
        let mut message = Zeroizing::new([0; 96]);
        message[..32].copy_from_slice(&cookie[..32]);
        message[32..64].copy_from_slice(&*client);
        message[64..].copy_from_slice(&server_nonce);
        let mut mac = Hmac::<Sha256>::new_from_slice(
            b"Tor safe cookie authentication server-to-controller hash",
        )
        .map_err(|_| io::ErrorKind::Other)?;
        mac.update(&*message);
        mac.verify_slice(&server_hash)
            .map_err(|_| io::ErrorKind::PermissionDenied)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(
            b"Tor safe cookie authentication controller-to-server hash",
        )
        .map_err(|_| io::ErrorKind::Other)?;
        mac.update(&*message);
        let mut hash = Zeroizing::new([0; 32]);
        hash.copy_from_slice(&mac.finalize().into_bytes());
        let command = Zeroizing::new(format!("AUTHENTICATE {}", hex(&*hash)));
        this.command(&command).await?;
        this.bootstrap().await?;
        Ok(this)
    }
    pub async fn bootstrap(&mut self) -> io::Result<()> {
        let reply = self.command("GETINFO status/bootstrap-phase").await?;
        if reply
            .iter()
            .any(|s| s.split_ascii_whitespace().any(|p| p == "PROGRESS=100"))
        {
            Ok(())
        } else {
            Err(io::ErrorKind::NotConnected.into())
        }
    }
    pub async fn command(&mut self, command: &str) -> io::Result<Vec<Zeroizing<String>>> {
        if !self.healthy || command.len() > 512 || command.contains(['\r', '\n']) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.healthy = false;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            self.socket.write_all(command.as_bytes()).await?;
            self.socket.write_all(b"\r\n").await?;
            let mut lines = Vec::new();
            let mut total = 0;
            loop {
                let mut line = Zeroizing::new(Vec::new());
                loop {
                    if line.len() >= 1024 || total >= 16_384 {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    let b = self.socket.read_u8().await?;
                    total += 1;
                    line.push(b);
                    if b == b'\n' {
                        break;
                    }
                }
                if line.len() < 6 || &line[..3] != b"250" || !line.ends_with(b"\r\n") {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                let more = match line[3] {
                    b'-' => true,
                    b' ' => false,
                    _ => return Err(io::ErrorKind::InvalidData.into()),
                };
                let text = std::str::from_utf8(&line[4..line.len() - 2])
                    .map_err(|_| io::ErrorKind::InvalidData)?;
                lines.push(Zeroizing::new(text.to_owned()));
                if !more {
                    return Ok(lines);
                }
                if lines.len() >= 32 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            }
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?;
        if result.is_ok() {
            self.healthy = true;
        }
        result
    }
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
fn field_hex(lines: &[Zeroizing<String>], prefix: &str) -> io::Result<[u8; 32]> {
    let mut found = None;
    for part in lines.iter().flat_map(|l| l.split_ascii_whitespace()) {
        if let Some(value) = part.strip_prefix(prefix) {
            if found.is_some() || value.len() != 64 || !value.is_ascii() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut result = [0; 32];
            for (i, b) in result.iter_mut().enumerate() {
                *b = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
                    .map_err(|_| io::ErrorKind::InvalidData)?;
            }
            found = Some(result);
        }
    }
    found.ok_or(io::ErrorKind::InvalidData.into())
}
