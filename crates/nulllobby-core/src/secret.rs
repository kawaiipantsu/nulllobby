use crate::LobbyId;
use hkdf::Hkdf;
use nulllobby_platform::{HardeningStatus, SecretBytes};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("OS random source unavailable")]
    RandomUnavailable,
    #[error("secret allocation failed")]
    Allocation,
    #[error("key derivation failed")]
    Derivation,
}

pub(crate) fn random_secret() -> Result<SecretBytes<32>, SecretError> {
    let mut result = SecretBytes::zeroed().map_err(|_| SecretError::Allocation)?;
    getrandom::fill(result.expose_secret_mut()).map_err(|_| SecretError::RandomUnavailable)?;
    Ok(result)
}

/// Random 256-bit capability. No Clone, Display, serialization or public raw export.
pub struct PrivateLobbySecret(SecretBytes<32>);
impl PrivateLobbySecret {
    pub fn generate() -> Result<Self, SecretError> {
        Ok(Self(random_secret()?))
    }
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SecretError> {
        let mut storage = SecretBytes::zeroed().map_err(|_| SecretError::Allocation)?;
        storage.expose_secret_mut().copy_from_slice(bytes);
        Ok(Self(storage))
    }
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
    pub fn lock_status(&self) -> HardeningStatus {
        self.0.lock_status()
    }
    pub fn derive(&self) -> Result<PrivateLobbyKeys, SecretError> {
        // RFC 5869: absent salt means HashLen zero octets. Info labels are exact UTF-8.
        let (mut prk, hkdf) = Hkdf::<Sha256>::extract(None, self.bytes());
        prk.as_mut_slice().zeroize();
        let expand = |label| {
            let mut output = SecretBytes::zeroed().map_err(|_| SecretError::Allocation)?;
            hkdf.expand(label, output.expose_secret_mut())
                .map_err(|_| SecretError::Derivation)?;
            Ok::<_, SecretError>(output)
        };
        let id = expand(b"nulllobby.lobby-id.v1")?;
        Ok(PrivateLobbyKeys {
            lobby_id: LobbyId::from_bytes(*id.expose_secret()),
            discovery: DiscoveryMaterial(expand(b"nulllobby.discovery.v1")?),
            noise_psk: NoisePsk(expand(b"nulllobby.noise-psk.v1")?),
        })
    }
}
impl fmt::Debug for PrivateLobbySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateLobbySecret([REDACTED])")
    }
}

#[derive(Debug)]
pub struct PrivateLobbyKeys {
    pub lobby_id: LobbyId,
    pub discovery: DiscoveryMaterial,
    pub noise_psk: NoisePsk,
}

macro_rules! secret_type {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        pub struct $name(SecretBytes<32>);
        impl $name {
            /// Explicit access for the future cryptographic/discovery boundary.
            pub fn expose_secret(&self) -> &[u8; 32] {
                self.0.expose_secret()
            }
            pub fn lock_status(&self) -> HardeningStatus {
                self.0.lock_status()
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}
secret_type!(DiscoveryMaterial);
secret_type!(NoisePsk);

secret_type!(
    /// Placeholder material only: Phase 2 will compute X25519 and bind it to Ed25519.
    /// No public key derivation, Noise handshake, session or cipher exists yet.
    NoiseStaticSecret
);
impl NoiseStaticSecret {
    pub fn generate() -> Result<Self, SecretError> {
        Ok(Self(random_secret()?))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoiseStaticPublicKey(pub [u8; 32]);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_derivations_are_separated_and_reproducible() {
        let a = PrivateLobbySecret::generate().unwrap();
        let keys = a.derive().unwrap();
        let repeated = a.derive().unwrap();
        assert_eq!(keys.lobby_id, repeated.lobby_id);
        assert_eq!(
            keys.noise_psk.expose_secret(),
            repeated.noise_psk.expose_secret()
        );
        assert_ne!(
            keys.discovery.expose_secret(),
            keys.noise_psk.expose_secret()
        );
        assert_ne!(keys.lobby_id.as_bytes(), keys.discovery.expose_secret());
        assert_ne!(keys.lobby_id.as_bytes(), keys.noise_psk.expose_secret());
        assert_ne!(a.bytes(), keys.noise_psk.expose_secret());
        assert_ne!(
            keys.lobby_id,
            PrivateLobbySecret::generate()
                .unwrap()
                .derive()
                .unwrap()
                .lobby_id
        );
        assert!(!format!("{keys:?}").contains(&format!("{:?}", a.bytes())));
    }
    #[test]
    fn hkdf_rfc5869_case_one() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut output = [0; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut output)
            .unwrap();
        assert_eq!(
            output,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );
    }
    #[test]
    fn private_lobby_generation_does_not_take_a_name() {
        let same_name = "team";
        let a = PrivateLobbySecret::generate().unwrap().derive().unwrap();
        let b = PrivateLobbySecret::generate().unwrap().derive().unwrap();
        assert_ne!(
            a.lobby_id, b.lobby_id,
            "independent capabilities for {same_name}"
        );
    }
}
