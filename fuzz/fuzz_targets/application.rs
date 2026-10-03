#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = nulllobby_core::message::Packet::decode(data);
    let _ = nulllobby_core::message::SignedMessage::decode(data);
});
