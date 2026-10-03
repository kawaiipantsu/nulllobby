use crate::{
    LobbyId, SecretError,
    secret::{NoiseStaticSecret, random_secret},
};
use ed25519_dalek::SigningKey;
use nulllobby_platform::{HardeningStatus, SecretBytes};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

pub struct EphemeralIdentity {
    lobby: LobbyId,
    seed: SecretBytes<32>,
    noise_static: NoiseStaticSecret,
}
impl EphemeralIdentity {
    /// Each join generates independent OS randomness; nothing is derived from a master key.
    pub fn generate(lobby: LobbyId) -> Result<Self, SecretError> {
        Ok(Self {
            lobby,
            seed: random_secret()?,
            noise_static: NoiseStaticSecret::generate()?,
        })
    }
    pub fn lobby(&self) -> LobbyId {
        self.lobby
    }
    pub fn public_key(&self) -> [u8; 32] {
        // Dalek's temporary signing key zeroizes on drop. It is not itself mlocked.
        SigningKey::from_bytes(self.seed.expose_secret())
            .verifying_key()
            .to_bytes()
    }
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_public_key(&self.public_key())
    }
    pub fn memory_status(&self) -> [HardeningStatus; 2] {
        [self.seed.lock_status(), self.noise_static.lock_status()]
    }
}
impl fmt::Debug for EphemeralIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EphemeralIdentity([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Fingerprint([u8; 32]);
impl Fingerprint {
    pub fn of_public_key(public_key: &[u8; 32]) -> Self {
        Self(Sha256::digest(public_key).into())
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, pair) in self.0.as_chunks::<2>().0.iter().enumerate() {
            if i > 0 {
                f.write_str("-")?;
            }
            write!(f, "{:02X}{:02X}", pair[0], pair[1])?;
        }
        Ok(())
    }
}
impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("expected a complete 256-bit fingerprint in sixteen four-digit hex groups")]
pub struct InvalidFingerprint;
impl FromStr for Fingerprint {
    type Err = InvalidFingerprint;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() != 79 || !input.is_ascii() {
            return Err(InvalidFingerprint);
        }
        let mut bytes = [0; 32];
        let mut count = 0;
        for (i, group) in input.split('-').enumerate() {
            if i >= 16 || group.len() != 4 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(InvalidFingerprint);
            }
            bytes[2 * i] = u8::from_str_radix(&group[..2], 16).map_err(|_| InvalidFingerprint)?;
            bytes[2 * i + 1] =
                u8::from_str_radix(&group[2..], 16).map_err(|_| InvalidFingerprint)?;
            count += 1;
        }
        if count != 16 {
            return Err(InvalidFingerprint);
        }
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_lobbies_and_rejoins_have_independent_keys() {
        let lobby = LobbyId::random_public().unwrap();
        let first = EphemeralIdentity::generate(lobby).unwrap();
        let other = EphemeralIdentity::generate(LobbyId::random_public().unwrap()).unwrap();
        let restarted = EphemeralIdentity::generate(lobby).unwrap();
        assert_ne!(first.public_key(), other.public_key());
        assert_ne!(first.public_key(), restarted.public_key());
        assert_ne!(
            first.noise_static.expose_secret(),
            other.noise_static.expose_secret()
        );
        assert_ne!(
            first.noise_static.expose_secret(),
            restarted.noise_static.expose_secret()
        );
        assert_ne!(
            first.seed.expose_secret(),
            first.noise_static.expose_secret()
        );
        assert_eq!(first.lobby(), lobby);
    }
    #[test]
    fn fingerprint_retains_all_256_bits_and_has_strict_parser() {
        let fp = Fingerprint::of_public_key(&[0; 32]);
        assert_eq!(
            fp.to_string(),
            "6668-7AAD-F862-BD77-6C8F-C18B-8E9F-8E20-0897-1485-6EE2-33B3-902A-591D-0D5F-2925"
        );
        assert_eq!(fp.to_string().parse::<Fingerprint>().unwrap(), fp);
        assert_eq!(
            fp.to_string()
                .to_lowercase()
                .parse::<Fingerprint>()
                .unwrap(),
            fp
        );
        for bad in ["1234", "", &"A".repeat(79), &"é".repeat(40)] {
            assert!(bad.parse::<Fingerprint>().is_err());
        }
    }
}
