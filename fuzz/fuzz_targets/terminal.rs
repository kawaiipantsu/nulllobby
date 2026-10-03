#![no_main]
libfuzzer_sys::fuzz_target!(|data: &str| {
    let _ = nulllobby_core::text::sanitize_terminal(data, 8192);
    let _ = nulllobby_core::domain::Nickname::new(data);
});
