#![no_main]
libfuzzer_sys::fuzz_target!(|data: &str| {
    if data.len() <= 768 {
        let _ = nulllobby_core::LobbyCard::parse(&format!("nl:v2:direct-private:{data}"));
        let _ = nulllobby_core::LobbyCard::parse(&format!("nl:v2:tor-private:{data}"));
    }
});
