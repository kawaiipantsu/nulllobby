#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = nulllobby_direct::Handshake::parse(data);
});
