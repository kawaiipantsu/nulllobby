//! Truthful BEP 10 negotiation; no nickname, lobby name or version metadata.
use bendy::decoding::{Decoder, Object};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const EXTENSION_HANDSHAKE: &[u8] = b"d1:md7:NL_chati1eee";
pub const LOCAL_EXTENSION: u8 = 1;
pub const MAX_EXTENSION_HANDSHAKE: usize = 4096;

pub fn parse_handshake(bytes: &[u8]) -> io::Result<u8> {
    if bytes.len() > MAX_EXTENSION_HANDSHAKE {
        return Err(invalid());
    }
    let mut decoder = Decoder::new(bytes).with_max_depth(8);
    let mut id = None;
    {
        let Some(Object::Dict(mut dictionary)) = decoder.next_object().map_err(|_| invalid())?
        else {
            return Err(invalid());
        };
        while let Some((key, value)) = dictionary.next_pair().map_err(|_| invalid())? {
            if key == b"m" {
                let Object::Dict(mut extensions) = value else {
                    return Err(invalid());
                };
                let mut seen = [false; 256];
                while let Some((name, value)) = extensions.next_pair().map_err(|_| invalid())? {
                    let Object::Integer(number) = value else {
                        return Err(invalid());
                    };
                    let number: u8 = number.parse().map_err(|_| invalid())?;
                    if number != 0 && seen[usize::from(number)] {
                        return Err(invalid());
                    }
                    seen[usize::from(number)] = true;
                    if name == b"NL_chat" {
                        id = Some(number);
                    }
                }
            }
        }
    }
    if decoder.next_object().map_err(|_| invalid())?.is_some() {
        return Err(invalid());
    }
    id.filter(|id| *id != 0).ok_or_else(invalid)
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
pub async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    extension: u8,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > 65_530 {
        return Err(invalid());
    }
    writer
        .write_all(&((payload.len() + 2) as u32).to_be_bytes())
        .await?;
    writer.write_all(&[20, extension]).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}
pub async fn receive<R: AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> io::Result<(u8, Vec<u8>)> {
    let length = reader.read_u32().await? as usize;
    if length < 2 || length > max.saturating_add(2).min(65_532) {
        return Err(invalid());
    }
    if reader.read_u8().await? != 20 {
        return Err(invalid());
    }
    let extension = reader.read_u8().await?;
    let mut bytes = vec![0; length - 2];
    reader.read_exact(&mut bytes).await?;
    Ok((extension, bytes))
}
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<u8> {
    send(stream, 0, EXTENSION_HANDSHAKE).await?;
    let (extension, bytes) = receive(stream, MAX_EXTENSION_HANDSHAKE).await?;
    if extension != 0 {
        return Err(invalid());
    }
    parse_handshake(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiation_is_bounded_truthful_and_canonical() {
        assert_eq!(parse_handshake(EXTENSION_HANDSHAKE).unwrap(), 1);
        assert_eq!(parse_handshake(b"d1:md7:NL_chati42eee").unwrap(), 42);
        for bad in [
            b"d1:md7:NL_chati0eee".as_slice(),
            b"d1:md7:NL_chati256eee",
            b"d1:md7:NL_chati01eee",
            b"d1:md7:NL_chati1eeeX",
            b"d1:md7:NL_chati1e3:fooi1eee",
            b"d1:mlleee",
        ] {
            assert!(parse_handshake(bad).is_err());
        }
        assert_eq!(EXTENSION_HANDSHAKE, b"d1:md7:NL_chati1eee");
        assert!(parse_handshake(&[b'l'; 4097]).is_err());
    }
}
