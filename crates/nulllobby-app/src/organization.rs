//! Explicit local storage and offline organization issuance. No network operations.
use nulllobby_core::{
    Fingerprint,
    membership::{EnrollmentRequest, OrganizationAuthority},
};
use nulllobby_store::{Vault, keyring::SecretService};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
pub fn open_vault(path: &Path, create: bool) -> Result<Arc<Vault>, &'static str> {
    Vault::open(path,create,&SecretService).map(Arc::new).map_err(|_|"Vault unavailable: use an absolute private path, unlock the Linux Secret Service and install libsecret-tools. No plaintext fallback.")
}
pub(crate) fn read_public(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let f = options
        .open(path)
        .map_err(|_| "Credential file unavailable")?;
    let metadata = f.metadata().map_err(|_| "Credential file unavailable")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("Credential file type or size rejected");
    }
    let mut bytes = Vec::new();
    f.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Credential read failed")?;
    if bytes.len() > limit {
        return Err("Credential file too large");
    }
    Ok(bytes)
}
pub(crate) fn write_public(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .map_err(|_| "Output exists or cannot be created")?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| "Credential write failed")
}
pub fn create_issuer(path: &Path) -> Result<String, &'static str> {
    let vault = open_vault(path, true)?;
    let issuer = OrganizationAuthority::generate().map_err(|_| "Issuer generation failed")?;
    let key = issuer.public_key();
    vault
        .set_issuer(issuer.into_seed())
        .map_err(|_| "Issuer storage failed")?;
    Ok(format!(
        "Dedicated organization issuer public key: {}\nFingerprint: {}\nIndependently verify this key before using /org trust. Keep issuance separate from release signing.",
        hex(&key),
        Fingerprint::of_public_key(&key)
    ))
}
pub fn issue(
    issuer_path: &Path,
    request_path: &Path,
    output: &Path,
    organization: &str,
    role: &str,
    hours: u64,
) -> Result<(), &'static str> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Clock unavailable")?
        .as_secs();
    let request = EnrollmentRequest::decode(&read_public(request_path, 512)?, now)
        .map_err(|_| "Invalid or expired enrollment request")?;
    let vault = open_vault(issuer_path, false)?;
    let issuer = OrganizationAuthority::from_seed(
        vault
            .issuer()
            .map_err(|_| "Dedicated issuer key unavailable")?,
    );
    let lifetime = hours
        .checked_mul(3600)
        .ok_or("Invalid credential lifetime")?;
    let credential = issuer
        .issue(&request, organization, role, now, lifetime)
        .map_err(|_| "Credential issuance rejected (maximum eight hours)")?;
    write_public(
        output,
        &credential
            .encode()
            .map_err(|_| "Credential encoding failed")?,
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
