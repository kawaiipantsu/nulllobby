#![no_main]
libfuzzer_sys::fuzz_target!(|data: &str| {
    let _ = nulllobby_core::LobbyCard::parse(data);
});
