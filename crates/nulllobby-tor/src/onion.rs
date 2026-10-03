//! Tor v3 address encoding, including the SHA3 checksum and version byte.
use data_encoding::BASE32_NOPAD;
use sha3::{Digest, Sha3_256};
use std::io;

pub fn hostname(key: &[u8; 32]) -> String {
    let mut bytes = [0; 35];
    bytes[..32].copy_from_slice(key);
    bytes[32..34].copy_from_slice(&checksum(key));
    bytes[34] = 3;
    format!("{}.onion", BASE32_NOPAD.encode(&bytes).to_ascii_lowercase())
}
pub fn parse_service_id(input: &str) -> io::Result<[u8; 32]> {
    if input.len() != 56
        || !input
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let bytes = BASE32_NOPAD
        .decode(input.to_ascii_uppercase().as_bytes())
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let key: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    if bytes[34] != 3 || bytes[32..34] != checksum(&key) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(key)
}
fn checksum(key: &[u8; 32]) -> [u8; 2] {
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(key);
    hash.update([3]);
    let digest = hash.finalize();
    [digest[0], digest[1]]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v3_roundtrip_rejects_ip_exit_and_corruption() {
        let name = hostname(&[42; 32]);
        assert_eq!(name.len(), 62);
        assert_eq!(parse_service_id(&name[..56]).unwrap(), [42; 32]);
        for bad in [
            "127.0.0.1",
            "example.org",
            "foo.exit",
            &"a".repeat(56),
            &name,
        ] {
            assert!(parse_service_id(bad).is_err());
        }
    }
}
