#![forbid(unsafe_code)]
use std::{fs, process::Command};

#[test]
fn bump_updates_workspace_internal_requirements_and_lockfile_only() {
    let path = std::env::temp_dir().join(format!("nulllobby-version-test-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    let manifest = "[workspace.package]\nversion = '1.2.3'\n[workspace.dependencies]\nlocal = { path = 'local', version = '=1.2.3' }\nexternal = '4.5.6'\n";
    let lock = "version = 4\n[[package]]\nname = 'local'\nversion = '1.2.3'\n[[package]]\nname = 'external'\nversion = '4.5.6'\nsource = 'registry+https://github.com/rust-lang/crates.io-index'\n";
    for (level, expected) in [("major", "2.0.0"), ("minor", "1.3.0"), ("patch", "1.2.4")] {
        fs::write(path.join("Cargo.toml"), manifest).unwrap();
        fs::write(path.join("Cargo.lock"), lock).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["bump", level])
            .current_dir(&path)
            .output()
            .unwrap();
        assert!(output.status.success());
        let actual: toml_edit::DocumentMut = fs::read_to_string(path.join("Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            actual["workspace"]["package"]["version"].as_str(),
            Some(expected)
        );
        assert_eq!(
            actual["workspace"]["dependencies"]["local"]["version"].as_str(),
            Some(format!("={expected}").as_str())
        );
        assert_eq!(
            actual["workspace"]["dependencies"]["external"].as_str(),
            Some("4.5.6")
        );
        let actual: toml_edit::DocumentMut = fs::read_to_string(path.join("Cargo.lock"))
            .unwrap()
            .parse()
            .unwrap();
        let packages = actual["package"].as_array_of_tables().unwrap();
        assert_eq!(packages.get(0).unwrap()["version"].as_str(), Some(expected));
        assert_eq!(packages.get(1).unwrap()["version"].as_str(), Some("4.5.6"));
    }
    fs::remove_dir_all(path).unwrap();
}
