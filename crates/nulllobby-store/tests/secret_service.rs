//! Runs a real libsecret/DBus/keyring roundtrip in an isolated synthetic session.
use std::{
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};
#[test]
#[ignore = "requires dbus-run-session, gnome-keyring-daemon and libsecret-tools"]
fn isolated_secret_service_roundtrip() {
    if std::env::var_os("NULLLOBBY_KEYRING_TEST_CHILD").is_some() {
        let path =
            std::path::PathBuf::from(std::env::var_os("NULLLOBBY_KEYRING_TEST_DIR").unwrap());
        let mut daemon = Command::new("/usr/bin/gnome-keyring-daemon")
            .args(["--foreground", "--components=secrets", "--unlock"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        daemon
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic isolated test password\n")
            .unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let file = path.join("private/state.vault");
        let result = (|| {
            let vault = nulllobby_store::Vault::open(
                &file,
                true,
                &nulllobby_store::keyring::SecretService,
            )?;
            let card =
                nulllobby_core::LobbyCard::private(nulllobby_core::TransportKind::Direct, vec![])
                    .unwrap();
            let identity = nulllobby_core::EphemeralIdentity::generate(card.lobby_id()).unwrap();
            vault.remember(&identity, &card, "Synthetic keyring roundtrip", 0)?;
            drop(vault);
            let vault = nulllobby_store::Vault::open(
                &file,
                false,
                &nulllobby_store::keyring::SecretService,
            )?;
            let (restored, ..) = vault.restore(card.lobby_id())?.unwrap();
            assert_eq!(identity.public_key(), restored.public_key());
            assert_ne!(identity.noise_public_key(), restored.noise_public_key());
            Ok::<_, nulllobby_store::Error>(())
        })();
        let _ = daemon.kill();
        let _ = daemon.wait();
        assert!(result.is_ok(), "isolated Secret Service roundtrip failed");
        return;
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "nl-secretservice-test-{:032x}",
        u128::from_le_bytes(random)
    ));
    let mut builder = std::fs::DirBuilder::new();
    use std::os::unix::fs::DirBuilderExt;
    builder.mode(0o700).create(&dir).unwrap();
    let output = Command::new("/usr/bin/dbus-run-session")
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "isolated_secret_service_roundtrip", "--ignored"])
        .env("NULLLOBBY_KEYRING_TEST_CHILD", "1")
        .env("NULLLOBBY_KEYRING_TEST_DIR", &dir)
        .env("HOME", &dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_RUNTIME_DIR", &dir)
        .env_remove("GNOME_KEYRING_CONTROL")
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    assert!(
        output.status.success(),
        "isolated Secret Service test failed (provider details suppressed)"
    );
}
