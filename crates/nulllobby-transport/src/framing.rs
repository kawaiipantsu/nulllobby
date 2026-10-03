//! Bounded outer records shared by both transport adapters. Cancellation-safe reads.
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_RECORD: usize = 65_532;
pub const HANDSHAKE: u8 = 1;
pub const CIPHERTEXT: u8 = 2;

#[derive(Default)]
pub struct RecordReader {
    prefix: [u8; 4],
    prefix_read: usize,
    body: Vec<u8>,
    body_read: usize,
}
impl RecordReader {
    pub async fn read<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
    ) -> io::Result<(u8, Vec<u8>)> {
        while self.prefix_read < 4 {
            let n = stream.read(&mut self.prefix[self.prefix_read..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.prefix_read += n;
        }
        if self.body.is_empty() {
            let len = u32::from_be_bytes(self.prefix) as usize;
            if !(2..=MAX_RECORD).contains(&len) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.body.resize(len, 0);
        }
        while self.body_read < self.body.len() {
            let n = stream.read(&mut self.body[self.body_read..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.body_read += n;
        }
        let tag = self.body[0];
        if !matches!(tag, HANDSHAKE | CIPHERTEXT) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let body = self.body[1..].to_vec();
        self.prefix_read = 0;
        self.body.clear();
        self.body_read = 0;
        Ok((tag, body))
    }
}
pub async fn write<W: AsyncWrite + Unpin>(stream: &mut W, tag: u8, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() >= MAX_RECORD || !matches!(tag, HANDSHAKE | CIPHERTEXT) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    stream
        .write_all(&((bytes.len() + 1) as u32).to_be_bytes())
        .await?;
    stream.write_all(&[tag]).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn oversized_length_fails_before_body_allocation() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let mut reader = RecordReader::default();
        assert!(reader.read(&mut b).await.is_err());
        assert!(reader.body.is_empty());
    }
    #[tokio::test]
    async fn cancelled_partial_read_preserves_frame() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 0]).await.unwrap();
        let mut reader = RecordReader::default();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), reader.read(&mut b))
                .await
                .is_err()
        );
        a.write_all(&[0, 3, CIPHERTEXT, 7, 8]).await.unwrap();
        assert_eq!(reader.read(&mut b).await.unwrap(), (CIPHERTEXT, vec![7, 8]));
    }
}
