//! All application unsafe code is confined to this module.
use crate::HardeningStatus;
use std::{io, ptr::NonNull};
use zeroize::Zeroize;

pub(super) fn disable_core_dumps() -> HardeningStatus {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: pointer references a valid rlimit for the duration of the syscall.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return failed();
    }
    // Linux's dumpable flag also inhibits common piped core collectors.
    // SAFETY: PR_SET_DUMPABLE accepts the scalar value zero; no pointers supplied.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return failed();
    }
    HardeningStatus::Active
}

fn failed() -> HardeningStatus {
    HardeningStatus::Failed {
        os_error: io::Error::last_os_error().raw_os_error(),
    }
}

pub(super) struct Mapping<const N: usize> {
    ptr: NonNull<u8>,
    len: usize,
    status: HardeningStatus,
}

// SAFETY: Mapping exclusively owns its allocation, and mutable access requires &mut.
unsafe impl<const N: usize> Send for Mapping<N> {}
// SAFETY: shared access only returns immutable bytes, and drop requires ownership.
unsafe impl<const N: usize> Sync for Mapping<N> {}

impl<const N: usize> Mapping<N> {
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: sysconf has no pointer arguments.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page)
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| io::Error::other("page size unavailable"))?;
        let len = N
            .checked_add(page - 1)
            .and_then(|n| (n / page).checked_mul(page))
            .ok_or_else(|| io::Error::other("secret allocation overflow"))?;
        // SAFETY: requests a new private, anonymous read/write mapping, no fixed address.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let Some(ptr) = NonNull::new(raw.cast::<u8>()) else {
            // SAFETY: even a mapping at address zero must be released; Rust cannot reference it.
            unsafe {
                libc::munmap(raw, len);
            }
            return Err(io::Error::other("null mapping address"));
        };
        // SAFETY: range is an owned, valid page-aligned allocation.
        let status = if unsafe { libc::mlock(raw, len) } == 0 {
            HardeningStatus::Active
        } else {
            failed()
        };
        Ok(Self { ptr, len, status })
    }
    pub(super) fn bytes(&self) -> &[u8; N] {
        // SAFETY: len >= N, mapping is initialized and alive, shared access is immutable.
        unsafe { &*self.ptr.as_ptr().cast::<[u8; N]>() }
    }
    pub(super) fn bytes_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: owned mapping, len >= N, exclusive access enforced by &mut self.
        unsafe { &mut *self.ptr.as_ptr().cast::<[u8; N]>() }
    }
    pub(super) fn status(&self) -> HardeningStatus {
        self.status
    }
}

impl<const N: usize> Zeroize for Mapping<N> {
    fn zeroize(&mut self) {
        // SAFETY: exclusive access to the entire owned, initialized mapping.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }.zeroize();
    }
}
impl<const N: usize> Drop for Mapping<N> {
    fn drop(&mut self) {
        self.zeroize();
        // SAFETY: zeroized owned mapping is released once; no references can survive drop.
        unsafe {
            if self.status == HardeningStatus::Active {
                libc::munlock(self.ptr.as_ptr().cast(), self.len);
            }
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn core_prevention_and_mlock_failure_in_child() {
        if std::env::var_os("NULLLOBBY_HARDENING_TEST_CHILD").is_some() {
            assert_eq!(disable_core_dumps(), HardeningStatus::Active);
            let mut limit = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: valid output pointer; process limits only changed in this child.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
            assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
            // SAFETY: no pointers for this prctl operation.
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: valid rlimit input pointer.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &zero) }, 0);
            // Capable privileged processes can bypass the limit; status must match the kernel.
            let mapping = Mapping::<32>::new().unwrap();
            let status = mapping.status();
            assert!(matches!(
                status,
                HardeningStatus::Active | HardeningStatus::Failed { .. }
            ));
            if status == HardeningStatus::Active {
                assert!(
                    std::fs::read_to_string("/proc/self/status")
                        .unwrap()
                        .lines()
                        .any(|line| line.starts_with("VmLck:")
                            && line.split_whitespace().nth(1) != Some("0"))
                );
            }
            return;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "linux::tests::core_prevention_and_mlock_failure_in_child",
            ])
            .env("NULLLOBBY_HARDENING_TEST_CHILD", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "hardening child test failed");
    }
}
