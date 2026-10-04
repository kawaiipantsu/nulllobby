#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    use nulllobby_core::membership::{Credential, EnrollmentRequest};
    if let Ok(c) = Credential::decode(bytes) {
        let _ = c.verify(c.lobby, c.subject, c.issuer, 1000);
    }
    let _ = EnrollmentRequest::decode(bytes, 1000);
});
