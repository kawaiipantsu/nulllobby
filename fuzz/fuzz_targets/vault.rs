#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    let _ = nulllobby_store::validate_snapshot(bytes);
});
