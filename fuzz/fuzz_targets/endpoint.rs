#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = nulllobby_tor::onion::parse_service_id(text);
    }
    let _ = nulllobby_core::message::Packet::decode(data);
});
