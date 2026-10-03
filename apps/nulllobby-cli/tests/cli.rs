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
    assert!(stdout.contains("Noise: not implemented"));
    assert!(!stdout.contains("nl:v1:"));
    assert!(output.stderr.is_empty());
}

#[test]
fn unsupported_arguments_are_never_echoed() {
    let output = Command::new(env!("CARGO_BIN_EXE_nulllobby"))
        .arg("sensitive-input-canary")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("sensitive-input-canary")
    );
}
