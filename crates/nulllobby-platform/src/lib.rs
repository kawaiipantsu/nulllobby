//! Small audited boundary for process hardening and owned secret memory.
#![deny(unsafe_code)]

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::{fmt, io};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardeningStatus {
    Active,
    Failed { os_error: Option<i32> },
    Unsupported,
}

/// Process-wide, irreversible reduction. Call at startup, before creating secrets.
pub fn disable_core_dumps() -> HardeningStatus {
    #[cfg(target_os = "linux")]
    {
        linux::disable_core_dumps()
    }
    #[cfg(not(target_os = "linux"))]
    {
        HardeningStatus::Unsupported
    }
}

/// Never formats panic payloads, locations, backtraces or application state.
pub fn install_safe_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr().lock(),
            "Fatal internal error; details suppressed to protect application state."
        );
    }));
}

/// Non-cloneable secret storage, zeroized before unlock/free. Locking is best effort.
/// Linux uses a separate anonymous mapping per allocation to avoid shared heap pages.
pub struct SecretBytes<const N: usize>(SecretBox<Storage<N>>);

impl<const N: usize> SecretBytes<N> {
    pub fn zeroed() -> io::Result<Self> {
        if N == 0 || N > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret size out of bounds",
            ));
        }
        Ok(Self(SecretBox::new(Box::new(Storage::new()?))))
    }

    pub fn expose_secret(&self) -> &[u8; N] {
        self.0.expose_secret().bytes()
    }
    pub fn expose_secret_mut(&mut self) -> &mut [u8; N] {
        self.0.expose_secret_mut().bytes_mut()
    }
    pub fn lock_status(&self) -> HardeningStatus {
        self.0.expose_secret().status()
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

#[cfg(target_os = "linux")]
type Storage<const N: usize> = linux::Mapping<N>;

#[cfg(not(target_os = "linux"))]
struct Storage<const N: usize>([u8; N]);
#[cfg(not(target_os = "linux"))]
impl<const N: usize> Storage<N> {
    fn new() -> io::Result<Self> {
        Ok(Self([0; N]))
    }
    fn bytes(&self) -> &[u8; N] {
        &self.0
    }
    fn bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
    fn status(&self) -> HardeningStatus {
        HardeningStatus::Unsupported
    }
}
#[cfg(not(target_os = "linux"))]
impl<const N: usize> Zeroize for Storage<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Explicitly clearable for controlled reuse; drop clearing is supplied by SecretBox.
impl<const N: usize> Zeroize for SecretBytes<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_hook_suppresses_payload_and_location() {
        const CHILD: &str = "NULLLOBBY_PANIC_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            install_safe_panic_hook();
            panic!("secret-panic-canary");
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::panic_hook_suppresses_payload_and_location",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("details suppressed"));
        assert!(!error.contains("secret-panic-canary"));
        assert!(!error.contains("src/lib.rs"));
    }

    #[test]
    fn secrets_are_bounded_redacted_and_clearable() {
        assert!(SecretBytes::<0>::zeroed().is_err());
        assert!(SecretBytes::<65537>::zeroed().is_err());
        let mut secret = SecretBytes::<32>::zeroed().unwrap();
        secret.expose_secret_mut().fill(0x42);
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
        secret.zeroize();
        assert_eq!(secret.expose_secret(), &[0; 32]);
    }

    #[test]
    fn live_allocations_are_independent() {
        let a = SecretBytes::<32>::zeroed().unwrap();
        let mut b = SecretBytes::<32>::zeroed().unwrap();
        b.expose_secret_mut()[0] = 7;
        assert_ne!(a.expose_secret().as_ptr(), b.expose_secret().as_ptr());
        drop(a);
        assert_eq!(b.expose_secret()[0], 7);
    }
}
