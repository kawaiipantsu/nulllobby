//! The OS Secret Service is the only production key provider. It may prompt
//! through the desktop session. Never silently substitute a file or password.
use crate::{Error, Result};
use nulllobby_platform::SecretBytes;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub trait KeyProvider: Send + Sync {
    fn create(&self, id: &[u8; 16], key: &[u8; 32]) -> Result<()>;
    fn load(&self, id: &[u8; 16]) -> Result<SecretBytes<32>>;
}
pub struct SecretService;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl SecretService {
    fn invoke(args: &[&str], input: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
        let mut child = Command::new("/usr/bin/secret-tool")
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Keyring)?;
        let result = (|| {
            if let Some(input) = input {
                child
                    .stdin
                    .take()
                    .ok_or(Error::Keyring)?
                    .write_all(input)
                    .map_err(|_| Error::Keyring)?;
            }
            let mut output = child.stdout.take().ok_or(Error::Keyring)?;
            // Provider output has a strict bound. A separate reader allows us to
            // enforce the deadline even when a desktop unlock prompt is open.
            let reader = std::thread::spawn(move || {
                let mut bytes = Zeroizing::new(Vec::new());
                output
                    .by_ref()
                    .take(257)
                    .read_to_end(&mut bytes)
                    .map(|_| bytes)
            });
            let deadline = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(status) = child.try_wait().map_err(|_| Error::Keyring)? {
                    break status;
                }
                if Instant::now() >= deadline {
                    return Err(Error::Keyring);
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let bytes = reader
                .join()
                .map_err(|_| Error::Keyring)?
                .map_err(|_| Error::Keyring)?;
            if !status.success() || bytes.len() > 256 {
                return Err(Error::Keyring);
            }
            Ok(bytes)
        })();
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}
impl KeyProvider for SecretService {
    fn create(&self, id: &[u8; 16], key: &[u8; 32]) -> Result<()> {
        let id = hex(id);
        let value = Zeroizing::new(hex(key));
        Self::invoke(
            &[
                "store",
                "--label=NullLobby encrypted vault",
                "application",
                "nulllobby-vault-v1",
                "vault",
                &id,
            ],
            Some(value.as_bytes()),
        )?;
        Ok(())
    }
    fn load(&self, id: &[u8; 16]) -> Result<SecretBytes<32>> {
        let id = hex(id);
        let bytes = Self::invoke(
            &["lookup", "application", "nulllobby-vault-v1", "vault", &id],
            None,
        )?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::Keyring)?
            .trim_end_matches('\n');
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Keyring);
        }
        let mut key = SecretBytes::zeroed().map_err(|_| Error::Keyring)?;
        for (i, part) in text.as_bytes().chunks_exact(2).enumerate() {
            key.expose_secret_mut()[i] =
                u8::from_str_radix(std::str::from_utf8(part).map_err(|_| Error::Keyring)?, 16)
                    .map_err(|_| Error::Keyring)?;
        }
        Ok(key)
    }
}
