#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    });
    runtime.block_on(async {
        let mut reader = nulllobby_transport::framing::RecordReader::default();
        let mut bytes = data;
        let _ = reader.read(&mut bytes).await;
    });
});
