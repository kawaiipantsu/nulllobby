#![forbid(unsafe_code)]
use std::process::Command;

#[test]
fn diagnostics_work_without_a_writable_home_and_do_not_print_keys() {
    let output = Command::new(env!("CARGO_BIN_EXE_nulllobby"))
        .arg("--self-check")
        .env("HOME", "/proc")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Core-dump prevention: Active"));
    assert!(stdout.contains("Network: inactive"));
    assert!(stdout.contains("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s"));
    assert!(!stdout.contains("nl:"));
    assert!(output.stderr.is_empty());
}

#[test]
fn unsupported_arguments_are_never_echoed() {
    let output = Command::new(env!("CARGO_BIN_EXE_nulllobby"))
        .arg("sensitive-input-canary")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("sensitive-input-canary")
    );
}

#[test]
fn vault_and_issuer_cli_fail_closed_without_touching_a_keyring() {
    for args in [
        vec!["--vault", "sensitive-relative-path-canary"],
        vec!["--org-create-issuer", "sensitive-relative-path-canary"],
        vec![
            "--org-issuer",
            "sensitive-relative-path-canary",
            "--org-hours",
            "9",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_nulllobby"))
            .args(args)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/nonexistent/nulllobby-test-bus",
            )
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            !String::from_utf8(output.stderr)
                .unwrap()
                .contains("sensitive-relative-path-canary")
        );
    }
}

#[test]
fn cloud_bot_is_rejected_in_tor_before_key_or_stdin_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_nulllobby"))
        .args([
            "--transport",
            "tor",
            "--bot",
            "--bot-name",
            "helper",
            "--bot-provider",
            "openai",
            "--bot-model",
            "synthetic",
            "--allow-cloud",
            "--bot-card-stdin",
        ])
        .env_remove("OPENAI_API_KEY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Cloud bots are disabled in Tor mode")
    );
}
