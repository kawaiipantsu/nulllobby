//! Debian packages always use the supported glibc baseline, independently of
//! the maintainer host. No host home, credentials or Docker socket enter the build.
use crate::Result;
use std::{fs, path::Path, process::Command};

const IMAGE: &str = "nulllobby-bookworm:rust-1.94.1";
const TARGET_CACHE: &str = "nulllobby-bookworm-rust1941-target";
const REGISTRY_CACHE: &str = "nulllobby-bookworm-registry";

pub(crate) fn package(arti: bool) -> Result<()> {
    crate::command(
        "docker",
        &[
            "build",
            "--platform",
            "linux/amd64",
            "--file",
            "packaging/bookworm.Dockerfile",
            "--tag",
            IMAGE,
            "packaging",
        ],
    )?;
    let root = std::env::current_dir()?.canonicalize()?;
    fs::create_dir_all(root.join("dist"))?;
    let source = bind_mount(&root, "/workspace", true)?;
    let artifacts = bind_mount(&root.join("dist"), "/workspace/dist", false)?;
    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--init",
            "--platform",
            "linux/amd64",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--workdir=/workspace",
            "--mount",
            &source,
            "--mount",
            &artifacts,
            "--mount",
            &format!("type=volume,source={TARGET_CACHE},target=/workspace/target"),
            "--mount",
            &format!("type=volume,source={REGISTRY_CACHE},target=/usr/local/cargo/registry"),
            "--env=CARGO_BUILD_JOBS=4",
            IMAGE,
            "cargo",
            "xtask",
            if arti {
                "deb-arti-native"
            } else {
                "deb-native"
            },
        ])
        .status()?;
    if !status.success() {
        return Err("Debian 12 package build failed; no host-build fallback".into());
    }
    Ok(())
}

fn bind_mount(path: &Path, destination: &str, readonly: bool) -> Result<String> {
    let path = path.to_str().ok_or("build path must be UTF-8")?;
    if path.contains([',', '\n', '\r']) {
        return Err("build path cannot contain commas or line breaks".into());
    }
    Ok(format!(
        "type=bind,source={path},target={destination}{}",
        if readonly { ",readonly" } else { "" }
    ))
}

pub(crate) fn require_baseline() -> Result<()> {
    if crate::output("getconf", &["GNU_LIBC_VERSION"])? != "glibc 2.36" {
        return Err("native Debian packaging requires glibc 2.36; use make deb or make deb-arti for the pinned Debian 12 container".into());
    }
    Ok(())
}

pub(crate) fn validate_elf(elf: &str) -> Result<()> {
    let required = crate::glibc_requirement(elf)?;
    let required = required
        .split('.')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if required.as_slice() > [2, 36].as_slice() {
        return Err(
            "binary requires glibc newer than 2.36; refusing an incompatible Debian package".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_newer_glibc_including_weak_symbol_requirements() {
        assert!(validate_elf("Name: GLIBC_2.34 Name: GLIBC_2.36").is_ok());
        assert!(validate_elf("Name: GLIBC_2.34").is_ok());
        assert!(validate_elf("Name: GLIBC_2.39 Flags: WEAK Version: 21").is_err());
        assert!(validate_elf("Name: GLIBC_2.100").is_err());
        assert!(validate_elf("Name: GLIBC_2.36.1").is_err());
        assert!(validate_elf("invalid ELF output").is_err());
    }

    #[test]
    fn mount_paths_cannot_inject_docker_options() {
        assert!(bind_mount(Path::new("/tmp/source,readonly=false"), "/workspace", true).is_err());
        assert!(bind_mount(Path::new("/tmp/source\nother"), "/workspace", true).is_err());
        assert!(bind_mount(Path::new("/tmp/a project"), "/workspace", true).is_ok());
    }
}
