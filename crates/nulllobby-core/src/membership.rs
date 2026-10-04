//! Narrow COSE_Sign1 profile (RFC 9052), Ed25519 (-19, RFC 9864).
//! No network lookup, certificate chains, names/emails or implicit trust roots.
use crate::{EphemeralIdentity, LobbyId, identity, secret::random_secret, text::ValidatedText};
use ed25519_dalek::{Signer, SigningKey};
use minicbor::{Decoder, Encoder, data::Tag};
use nulllobby_platform::SecretBytes;
pub const MAX_CREDENTIAL: usize = 1024;
pub const MAX_LIFETIME: u64 = 8 * 3600;
const PROTECTED: &[u8] = &[0xa1, 0x01, 0x32]; // {1: -19}, fully specified Ed25519.
const AAD: &[u8] = b"nulllobby.organization.v1";
#[derive(Debug, thiserror::Error)]
#[error("invalid, expired or untrusted lobby organization credential")]
pub struct MembershipError;
type Result<T> = std::result::Result<T, MembershipError>;
impl From<minicbor::decode::Error> for MembershipError {
    fn from(_: minicbor::decode::Error) -> Self {
        Self
    }
}
impl From<minicbor::encode::Error<std::convert::Infallible>> for MembershipError {
    fn from(_: minicbor::encode::Error<std::convert::Infallible>) -> Self {
        Self
    }
}

pub struct EnrollmentRequest {
    pub lobby: LobbyId,
    pub subject: [u8; 32],
    pub challenge: [u8; 32],
    pub created: u64,
    signature: [u8; 64],
}
impl EnrollmentRequest {
    pub fn new(identity: &EphemeralIdentity, now: u64) -> Result<Self> {
        let mut r = Self {
            lobby: identity.lobby(),
            subject: identity.public_key(),
            challenge: [0; 32],
            created: now,
            signature: [0; 64],
        };
        getrandom::fill(&mut r.challenge).map_err(|_| MembershipError)?;
        r.signature = identity.sign(&r.body()?);
        Ok(r)
    }
    fn body(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(6)?
            .str("nulllobby.org-enrollment.v1")?
            .u8(1)?
            .bytes(self.lobby.as_bytes())?
            .bytes(&self.subject)?
            .bytes(&self.challenge)?
            .u64(self.created)?;
        Ok(e.into_writer())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(2)?.bytes(&self.body()?)?.bytes(&self.signature)?;
        Ok(e.into_writer())
    }
    pub fn decode(bytes: &[u8], now: u64) -> Result<Self> {
        if bytes.len() > 512 {
            return Err(MembershipError);
        }
        let mut d = Decoder::new(bytes);
        array(&mut d, 2)?;
        let body = d.bytes()?;
        let signature = fixed(&mut d)?;
        if d.position() != bytes.len() {
            return Err(MembershipError);
        }
        let mut d = Decoder::new(body);
        array(&mut d, 6)?;
        if d.str()? != "nulllobby.org-enrollment.v1" || d.u8()? != 1 {
            return Err(MembershipError);
        }
        let r = Self {
            lobby: LobbyId::from_bytes(fixed(&mut d)?),
            subject: fixed(&mut d)?,
            challenge: fixed(&mut d)?,
            created: d.u64()?,
            signature,
        };
        if d.position() != body.len()
            || r.created > now.saturating_add(60)
            || now.saturating_sub(r.created) > 3600
            || r.encode()? != bytes
            || !identity::verify(&r.subject, body, &r.signature)
        {
            return Err(MembershipError);
        }
        Ok(r)
    }
}

/// Dedicated issuer key, never a lobby identity or release key.
pub struct OrganizationAuthority {
    seed: SecretBytes<32>,
}
impl OrganizationAuthority {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            seed: random_secret().map_err(|_| MembershipError)?,
        })
    }
    pub fn from_seed(seed: SecretBytes<32>) -> Self {
        Self { seed }
    }
    pub fn into_seed(self) -> SecretBytes<32> {
        self.seed
    }
    pub fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(self.seed.expose_secret())
            .verifying_key()
            .to_bytes()
    }
    /// The offline operator must approve the requester's eligibility independently.
    pub fn issue(
        &self,
        request: &EnrollmentRequest,
        organization: &str,
        role: &str,
        now: u64,
        lifetime: u64,
    ) -> Result<Credential> {
        let request = EnrollmentRequest::decode(&request.encode()?, now)?;
        if lifetime == 0 || lifetime > MAX_LIFETIME {
            return Err(MembershipError);
        }
        let mut c = Credential {
            issuer: self.public_key(),
            lobby: request.lobby,
            subject: request.subject,
            challenge: request.challenge,
            organization: ValidatedText::new(organization).map_err(|_| MembershipError)?,
            role: ValidatedText::new(role).map_err(|_| MembershipError)?,
            issued: now,
            expires: now.checked_add(lifetime).ok_or(MembershipError)?,
            serial: [0; 16],
            signature: [0; 64],
        };
        getrandom::fill(&mut c.serial).map_err(|_| MembershipError)?;
        c.signature = SigningKey::from_bytes(self.seed.expose_secret())
            .sign(&signature_input(&c.payload()?)?)
            .to_bytes();
        Ok(c)
    }
}
#[derive(Clone)]
pub struct Credential {
    pub issuer: [u8; 32],
    pub lobby: LobbyId,
    pub subject: [u8; 32],
    pub challenge: [u8; 32],
    pub organization: ValidatedText<64>,
    pub role: ValidatedText<32>,
    pub issued: u64,
    pub expires: u64,
    pub serial: [u8; 16],
    signature: [u8; 64],
}
impl Credential {
    fn payload(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(10)?
            .u8(1)?
            .bytes(&self.issuer)?
            .bytes(self.lobby.as_bytes())?
            .bytes(&self.subject)?
            .bytes(&self.challenge)?
            .str(self.organization.as_str())?
            .str(self.role.as_str())?
            .u64(self.issued)?
            .u64(self.expires)?
            .bytes(&self.serial)?;
        Ok(e.into_writer())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.tag(Tag::new(18))?
            .array(4)?
            .bytes(PROTECTED)?
            .map(0)?
            .bytes(&self.payload()?)?
            .bytes(&self.signature)?;
        let bytes = e.into_writer();
        if bytes.len() > MAX_CREDENTIAL {
            return Err(MembershipError);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CREDENTIAL {
            return Err(MembershipError);
        }
        let mut d = Decoder::new(bytes);
        if d.tag()? != Tag::new(18) {
            return Err(MembershipError);
        }
        array(&mut d, 4)?;
        if d.bytes()? != PROTECTED || d.map()? != Some(0) {
            return Err(MembershipError);
        }
        let payload = d.bytes()?;
        let signature = fixed(&mut d)?;
        if d.position() != bytes.len() {
            return Err(MembershipError);
        }
        let mut d = Decoder::new(payload);
        array(&mut d, 10)?;
        if d.u8()? != 1 {
            return Err(MembershipError);
        }
        let c = Self {
            issuer: fixed(&mut d)?,
            lobby: LobbyId::from_bytes(fixed(&mut d)?),
            subject: fixed(&mut d)?,
            challenge: fixed(&mut d)?,
            organization: ValidatedText::new(d.str()?).map_err(|_| MembershipError)?,
            role: ValidatedText::new(d.str()?).map_err(|_| MembershipError)?,
            issued: d.u64()?,
            expires: d.u64()?,
            serial: fixed(&mut d)?,
            signature,
        };
        if d.position() != payload.len() || c.encode()? != bytes {
            return Err(MembershipError);
        }
        Ok(c)
    }
    pub fn verify(
        &self,
        lobby: LobbyId,
        subject: [u8; 32],
        trusted_issuer: [u8; 32],
        now: u64,
    ) -> Result<()> {
        if self.lobby != lobby
            || self.subject != subject
            || self.issuer != trusted_issuer
            || self.issued > now.saturating_add(60)
            || self.expires <= now
            || self.expires <= self.issued
            || self.expires - self.issued > MAX_LIFETIME
            || !identity::verify(
                &self.issuer,
                &signature_input(&self.payload()?)?,
                &self.signature,
            )
        {
            return Err(MembershipError);
        }
        Ok(())
    }
}
fn signature_input(payload: &[u8]) -> Result<Vec<u8>> {
    let mut e = Encoder::new(Vec::new());
    e.array(4)?
        .str("Signature1")?
        .bytes(PROTECTED)?
        .bytes(AAD)?
        .bytes(payload)?;
    Ok(e.into_writer())
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array()? != Some(n) {
        return Err(MembershipError);
    }
    Ok(())
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()?.try_into().map_err(|_| MembershipError)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_require_exact_lobby_key_issuer_purpose_and_validity() {
        let id = EphemeralIdentity::generate(LobbyId::random_public().unwrap()).unwrap();
        let a = OrganizationAuthority::generate().unwrap();
        let r = EnrollmentRequest::new(&id, 1000).unwrap();
        let c = a.issue(&r, "Example Team", "member", 1000, 3600).unwrap();
        let bytes = c.encode().unwrap();
        let c = Credential::decode(&bytes).unwrap();
        c.verify(id.lobby(), id.public_key(), a.public_key(), 1001)
            .unwrap();
        assert!(
            c.verify(
                LobbyId::random_public().unwrap(),
                id.public_key(),
                a.public_key(),
                1001
            )
            .is_err()
        );
        assert!(c.verify(id.lobby(), [9; 32], a.public_key(), 1001).is_err());
        assert!(
            c.verify(id.lobby(), id.public_key(), [8; 32], 1001)
                .is_err()
        );
        assert!(
            c.verify(id.lobby(), id.public_key(), a.public_key(), 4600)
                .is_err()
        );
        assert!(
            c.verify(id.lobby(), id.public_key(), a.public_key(), 900)
                .is_err()
        );
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert!(
                Credential::decode(&bad)
                    .and_then(|c| c.verify(id.lobby(), id.public_key(), a.public_key(), 1001))
                    .is_err()
            );
        }
        assert!(
            a.issue(&r, "Example", "member", 1000, MAX_LIFETIME + 1)
                .is_err()
        );
    }
    #[test]
    fn enrollment_proves_key_possession_and_is_bounded() {
        let id = EphemeralIdentity::generate(LobbyId::random_public().unwrap()).unwrap();
        let r = EnrollmentRequest::new(&id, 1000).unwrap();
        let bytes = r.encode().unwrap();
        EnrollmentRequest::decode(&bytes, 1001).unwrap();
        assert!(EnrollmentRequest::decode(&bytes, 5000).is_err());
        for i in 0..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 1;
            assert!(EnrollmentRequest::decode(&b, 1001).is_err());
        }
        for n in 0..512 {
            let b = vec![n as u8; n];
            let _ = Credential::decode(&b);
            let _ = EnrollmentRequest::decode(&b, 1001);
        }
    }
}
