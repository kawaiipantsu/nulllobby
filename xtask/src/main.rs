//! Rust-only build, package and version tooling. External commands are invoked
//! with structured arguments, never interpolated shell command text.
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};
use toml_edit::{DocumentMut, value};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const TARGET: &str = "x86_64-unknown-linux-gnu";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Task failed: {error}");
            ExitCode::FAILURE
        }
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["build"] => build(false),
        ["build-arti"] => build(true),
        ["deb"] => deb(false),
        ["deb-arti"] => deb(true),
        ["check"] => check(),
        ["fuzz-smoke"] => fuzz_smoke(),
        ["screenshots"] => screenshots(),
        ["bump", level] => bump(level),
        ["release"] => release(),
        ["announce", tag] => announce(tag),
        _ => {
            Err("use: cargo xtask build|deb|check|bump major|bump minor|bump patch|release".into())
        }
    }
}
fn screenshots() -> Result<()> {
    let directory = "target/docs-screenshots";
    let status = Command::new("cargo")
        .args([
            "test",
            "--locked",
            "-p",
            "nulllobby-tui",
            "render_documentation",
            "--",
            "--ignored",
        ])
        .env(
            "NULLLOBBY_SCREENSHOT_DIR",
            std::env::current_dir()?.join(directory),
        )
        .status()?;
    if !status.success() {
        return Err("screenshot renderer failed".into());
    }
    fs::create_dir_all("assets/screenshots")?;
    for name in ["chat", "irssi", "help", "settings"] {
        command(
            "rsvg-convert",
            &[
                &format!("{directory}/{name}.svg"),
                "-o",
                &format!("assets/screenshots/{name}.png"),
            ],
        )?;
    }
    Ok(())
}
fn command(program: &str, args: &[&str]) -> Result<()> {
    if !Command::new(program).args(args).status()?.success() {
        return Err(format!("{program} failed").into());
    }
    Ok(())
}
fn output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(format!("{program} failed (output withheld)").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
fn manifest() -> Result<DocumentMut> {
    Ok(fs::read_to_string("Cargo.toml")?.parse()?)
}
fn version() -> Result<String> {
    Ok(manifest()?["workspace"]["package"]["version"]
        .as_str()
        .ok_or("missing workspace version")?
        .to_owned())
}
fn check() -> Result<()> {
    command("cargo", &["fmt", "--check"])?;
    command(
        "cargo",
        &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    command("cargo", &["test", "--locked", "--workspace"])?;
    command(
        "cargo",
        &["test", "--locked", "--workspace", "--all-features"],
    )?;
    // Release checks deliberately require both tools; do not silently skip security gates.
    command("cargo", &["audit"])?;
    command("cargo", &["deny", "check"])
}
fn build(arti: bool) -> Result<()> {
    let root = std::env::current_dir()?;
    let mut flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if flags.is_empty() {
        flags = std::env::var("RUSTFLAGS")
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("\x1f");
    }
    let mut remaps = vec![format!("--remap-path-prefix={}=/workspace", root.display())];
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    if let Some(path) = cargo_home {
        remaps.push(format!(
            "--remap-path-prefix={}=/rust-dependencies",
            path.display()
        ));
    }
    for remap in remaps {
        if !flags.is_empty() {
            flags.push('\x1f');
        }
        flags.push_str(&remap);
    }
    let mut cargo = Command::new("cargo");
    cargo.args([
        "build",
        "--locked",
        "--release",
        "--target",
        TARGET,
        "--package",
        "nulllobby-tui",
    ]);
    if arti {
        cargo.args(["--features", "tor-arti-experimental"]);
    }
    let status = cargo.env("CARGO_ENCODED_RUSTFLAGS", flags).status()?;
    if !status.success() {
        return Err("release build failed".into());
    }
    Ok(())
}
fn deb(arti: bool) -> Result<()> {
    if output("dpkg", &["--print-architecture"])? != "amd64" {
        return Err("Debian packaging requires an amd64 Linux builder".into());
    }
    build(arti)?;
    command("cargo", &["fetch", "--locked"])?;
    let version = version()?;
    let stage = Path::new("target/debian-stage");
    if stage.exists() {
        fs::remove_dir_all(stage)?;
    }
    fs::create_dir_all(stage.join("DEBIAN"))?;
    fs::create_dir_all(stage.join("usr/bin"))?;
    fs::create_dir_all(stage.join("usr/share/doc/nulllobby"))?;
    let binary = format!("target/{TARGET}/release/nulllobby");
    fs::copy(&binary, stage.join("usr/bin/nulllobby"))?;
    for file in ["README.md", "SECURITY.md", "LICENSE"] {
        fs::copy(file, stage.join("usr/share/doc/nulllobby").join(file))?;
    }
    for file in ["docs/wiki/Terminal.md", "docs/wiki/Bots.md"] {
        fs::copy(
            file,
            stage.join("usr/share/doc/nulllobby").join(
                Path::new(file)
                    .file_name()
                    .ok_or("missing guide filename")?,
            ),
        )?;
    }
    fs::create_dir_all(stage.join("usr/share/nulllobby/themes"))?;
    for name in ["ember.toml", "nulllobby.theme"] {
        fs::copy(
            Path::new("themes").join(name),
            stage.join("usr/share/nulllobby/themes").join(name),
        )?;
    }
    fs::copy(
        "packaging/copyright",
        stage.join("usr/share/doc/nulllobby/copyright"),
    )?;
    fs::write(
        stage.join("usr/share/doc/nulllobby/THIRD-PARTY-NOTICES.txt"),
        dependency_notices(arti)?,
    )?;
    // Derive glibc minimum from ELF version requirements on the actual built binary.
    let elf = output("readelf", &["--version-info", &binary])?;
    let minimum = glibc_requirement(&elf)?;
    let package = if arti {
        "nulllobby-arti-experimental"
    } else {
        "nulllobby"
    };
    let extra = if arti {
        "Provides: nulllobby\nConflicts: nulllobby\nReplaces: nulllobby\n"
    } else {
        ""
    };
    let libraries = if arti { ", libsqlite3-0" } else { "" };
    if arti {
        for file in ["docs/ARTI-DEPENDENCIES.md", "docs/wiki/Arti-Review.md"] {
            fs::copy(
                file,
                stage
                    .join("usr/share/doc/nulllobby")
                    .join(Path::new(file).file_name().ok_or("missing filename")?),
            )?;
        }
    }
    fs::write(
        stage.join("DEBIAN/control"),
        format!(
            "Package: {package}\nVersion: {version}\nSection: net\nPriority: optional\nArchitecture: amd64\nMaintainer: NullLobby maintainers\nDepends: libc6 (>= {minimum}), libgcc-s1, ca-certificates{libraries}\nSuggests: tor\n{extra}Homepage: https://thugs.red\nDescription: RAM-first encrypted decentralized lobby chat\n Linux terminal client with signed messages, Direct P2P and Tor onion transport.\n Embedded Arti support in this package: {arti}.\n"
        ),
    )?;
    fs::create_dir_all("dist")?;
    let name = format!("{package}_{version}_amd64.deb");
    command(
        "dpkg-deb",
        &[
            "--root-owner-group",
            "--build",
            "target/debian-stage",
            &format!("dist/{name}"),
        ],
    )?;
    let tar = format!("{package}_{version}_{TARGET}.tar.gz");
    command(
        "tar",
        &[
            "--sort=name",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "-czf",
            &format!("dist/{tar}"),
            "-C",
            "target/debian-stage",
            "usr",
        ],
    )?;
    let mut checksums = String::new();
    for file in [&name, &tar] {
        let hash = Sha256::digest(fs::read(Path::new("dist").join(file))?);
        let hex = hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        checksums.push_str(&format!("{hex}  {file}\n"));
    }
    fs::write(
        if arti {
            "dist/SHA256SUMS-arti"
        } else {
            "dist/SHA256SUMS"
        },
        checksums,
    )?;
    println!("Built Debian package, Linux archive and SHA256SUMS in dist/");
    Ok(())
}
fn glibc_requirement(elf: &str) -> Result<String> {
    elf.split_whitespace()
        .filter_map(|word| word.strip_prefix("GLIBC_"))
        .filter_map(|version| {
            version
                .split('.')
                .map(str::parse::<u32>)
                .collect::<std::result::Result<Vec<_>, _>>()
                .ok()
        })
        .max()
        .map(|version| {
            version
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(".")
        })
        .ok_or_else(|| "could not determine glibc requirement from ELF".into())
}
fn next_version(current: &str, level: &str) -> Result<String> {
    let mut parts = current
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if parts.len() != 3 {
        return Err("version must have exactly three numeric components".into());
    }
    let index = match level {
        "major" => 0,
        "minor" => 1,
        "patch" => 2,
        _ => return Err("bump must be major, minor or patch".into()),
    };
    parts[index] = parts[index].checked_add(1).ok_or("version overflow")?;
    parts[index + 1..].fill(0);
    Ok(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
}
fn bump(level: &str) -> Result<()> {
    let mut manifest = manifest()?;
    let next = next_version(&version()?, level)?;
    manifest["workspace"]["package"]["version"] = value(&next);
    for (_, dependency) in manifest["workspace"]["dependencies"]
        .as_table_mut()
        .ok_or("missing dependencies")?
        .iter_mut()
    {
        if dependency.get("path").is_some() {
            dependency["version"] = value(format!("={next}"));
        }
    }
    let mut names = vec!["xtask".to_owned()];
    for (name, dependency) in manifest["workspace"]["dependencies"]
        .as_table()
        .ok_or("missing dependencies")?
    {
        if dependency.get("path").is_some() {
            names.push(name.to_owned());
        }
    }
    names.push("nulllobby-tui".to_owned());
    for path in ["Cargo.lock", "fuzz/Cargo.lock"] {
        let mut lock: DocumentMut = fs::read_to_string(path)?.parse()?;
        bump_lock(&mut lock, &names, &next)?;
        fs::write(path, lock.to_string())?;
    }
    fs::write("Cargo.toml", manifest.to_string())?;
    println!(
        "Workspace version is now {next}; review the manifest and both lockfiles before release."
    );
    Ok(())
}
fn bump_lock(lock: &mut DocumentMut, names: &[String], next: &str) -> Result<()> {
    for package in lock["package"]
        .as_array_of_tables_mut()
        .ok_or("invalid lockfile")?
        .iter_mut()
    {
        if !package.contains_key("source")
            && package["name"]
                .as_str()
                .is_some_and(|name| names.iter().any(|n| n == name))
        {
            package["version"] = value(next);
        }
    }
    Ok(())
}
fn release() -> Result<()> {
    if !output("git", &["status", "--porcelain"])?.is_empty() {
        return Err("commit reviewed changes before creating a release".into());
    }
    let commit = output("git", &["rev-parse", "HEAD"])?;
    let remote = output("git", &["ls-remote", "origin", "refs/heads/main"])?;
    if remote.split_whitespace().next() != Some(commit.as_str()) {
        return Err("release commit must equal published origin/main".into());
    }
    check()?;
    deb(false)?;
    deb(true)?;
    let version = version()?;
    let tag = format!("v{version}");
    if !output(
        "git",
        &["ls-remote", "--tags", "origin", &format!("refs/tags/{tag}")],
    )?
    .is_empty()
    {
        return Err("release tag already exists; inspect it before proceeding".into());
    }
    let deb = format!("dist/nulllobby_{version}_amd64.deb");
    let tar = format!("dist/nulllobby_{version}_{TARGET}.tar.gz");
    let arti_deb = format!("dist/nulllobby-arti-experimental_{version}_amd64.deb");
    let arti_tar = format!("dist/nulllobby-arti-experimental_{version}_{TARGET}.tar.gz");
    command(
        "gh",
        &[
            "release",
            "create",
            &tag,
            &deb,
            &tar,
            "dist/SHA256SUMS",
            &arti_deb,
            &arti_tar,
            "dist/SHA256SUMS-arti",
            "--draft",
            "--target",
            &commit,
            "--title",
            &format!("NullLobby {version} — Linux preview"),
            "--notes-file",
            "docs/RELEASE-NOTES.md",
        ],
    )?;
    println!(
        "Draft created. Publish after review; the release workflow will post a Discussion notification."
    );
    Ok(())
}

fn dependency_notices(arti: bool) -> Result<String> {
    let mut missing = Vec::new();
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .ok_or("Cargo cache location unavailable")?;
    let registries =
        fs::read_dir(cargo_home.join("registry/src"))?.collect::<std::io::Result<Vec<_>>>()?;
    let lock: DocumentMut = fs::read_to_string("Cargo.lock")?.parse()?;
    let mut args = vec![
        "tree",
        "--locked",
        "--target",
        TARGET,
        "--package",
        "nulllobby-tui",
        "--edges",
        "normal,build",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ];
    if arti {
        args.extend(["--features", "tor-arti-experimental"]);
    }
    let tree = output("cargo", &args)?;
    let included: std::collections::BTreeSet<_> = tree
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((fields.next()?, fields.next()?.strip_prefix('v')?))
        })
        .collect();
    let mut notices = String::from(
        "NullLobby source dependency notices\nIncludes a superset of the binary's dependencies. Each dependency retains its original license.\n\n",
    );
    for package in lock["package"]
        .as_array_of_tables()
        .ok_or("invalid lockfile")?
    {
        let name = package["name"].as_str().ok_or("missing name")?;
        let version = package["version"].as_str().ok_or("missing version")?;
        if !included.contains(&(name, version)) {
            continue;
        }
        if !package.contains_key("source") && name != "tor-hsservice" {
            continue;
        }
        let source = if name == "tor-hsservice" {
            PathBuf::from("vendor/tor-hsservice")
        } else {
            registries
                .iter()
                .map(|registry| registry.path().join(format!("{name}-{version}")))
                .find(|path| path.is_dir())
                .ok_or("dependency source unavailable; run cargo fetch --locked")?
        };
        let mut files = fs::read_dir(&source)?.collect::<std::io::Result<Vec<_>>>()?;
        files.sort_by_key(|file| file.file_name());
        let mut found = false;
        notices.push_str(&format!("===== {name} {version} =====\n"));
        for file in files {
            let name = file.file_name().to_string_lossy().to_uppercase();
            if file.file_type()?.is_dir() && name == "LICENSES" {
                let mut nested = fs::read_dir(file.path())?.collect::<std::io::Result<Vec<_>>>()?;
                nested.sort_by_key(|entry| entry.file_name());
                for license in nested {
                    if license.file_type()?.is_file() {
                        notices.push_str(&fs::read_to_string(license.path())?);
                        notices.push_str("\n\n");
                        found = true;
                    }
                }
            }
            if file.file_type()?.is_file()
                && (name.starts_with("LICENSE")
                    || name.starts_with("LICENCE")
                    || name == "UNLICENSE"
                    || name.starts_with("COPYING")
                    || name.starts_with("NOTICE"))
            {
                notices.push_str(&fs::read_to_string(file.path())?);
                notices.push_str("\n\n");
                found = true;
            }
        }
        if !found {
            let metadata: DocumentMut = fs::read_to_string(source.join("Cargo.toml"))?.parse()?;
            let repository = metadata["package"]["repository"]
                .as_str()
                .unwrap_or("")
                .trim_end_matches('/');
            let license = metadata["package"]["license"].as_str().unwrap_or("");
            // Arti crate archives omit the shared root licenses. Preserve the
            // exact upstream release's umbrella notices for reviewed Arti crates.
            if repository == "https://gitlab.torproject.org/tpo/core/arti.git"
                && (license == "MIT OR Apache-2.0" || license == "Apache-2.0 OR MIT")
            {
                for file in ["LICENSE-MIT", "LICENSE-APACHE"] {
                    notices.push_str(&fs::read_to_string(
                        Path::new("vendor/tor-hsservice").join(file),
                    )?);
                    notices.push_str("\n\n");
                }
                continue;
            }
            let reviewed = Path::new("packaging/licenses").join(format!("{name}-{version}.txt"));
            if reviewed.is_file() {
                notices.push_str(&fs::read_to_string(reviewed)?);
                notices.push_str("\n\n");
            } else {
                missing.push(format!("{name}-{version}"));
            }
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "missing license texts: {}; review packaging",
            missing.join(", ")
        )
        .into());
    }
    Ok(notices)
}

/// Explicit release notification; invoked only by publication or a maintainer.
fn announce(tag: &str) -> Result<()> {
    if !tag.starts_with('v') || !tag[1..].bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err("release tag must be v followed by a numeric version".into());
    }
    let published = output(
        "gh",
        &[
            "release", "view", tag, "--json", "isDraft", "--jq", ".isDraft",
        ],
    )?;
    if published != "false" {
        return Err("only published releases can be announced".into());
    }
    let url = output(
        "gh",
        &["release", "view", tag, "--json", "url", "--jq", ".url"],
    )?;
    let title = format!("NullLobby {tag} released");
    let query = "query { repository(owner: \"kawaiipantsu\", name: \"nulllobby\") { id discussionCategories(first: 25) { nodes { id name } } discussions(first: 100, orderBy: {field: CREATED_AT, direction: DESC}) { nodes { title } } } }";
    let field = format!("query={query}");
    let existing = output(
        "gh",
        &[
            "api",
            "graphql",
            "-f",
            &field,
            "--jq",
            ".data.repository.discussions.nodes[].title",
        ],
    )?;
    if existing.lines().any(|line| line == title) {
        println!("Release Discussion already exists.");
        return Ok(());
    }
    let repository_id = output(
        "gh",
        &[
            "api",
            "graphql",
            "-f",
            &field,
            "--jq",
            ".data.repository.id",
        ],
    )?;
    let category_id = output(
        "gh",
        &[
            "api",
            "graphql",
            "-f",
            &field,
            "--jq",
            ".data.repository.discussionCategories.nodes[] | select(.name == \"Announcements\") | .id",
        ],
    )?;
    if category_id.is_empty() {
        return Err("Announcements Discussion category unavailable".into());
    }
    let body = format!(
        "Release: [{tag}]({url})\n\n{}\n\nShare reproducible feedback here. Do not post real lobby cards, chat contents or private environment details.",
        fs::read_to_string("docs/RELEASE-NOTES.md")?
    );
    let mutation = "mutation($repository: ID!, $category: ID!, $title: String!, $body: String!) { createDiscussion(input: {repositoryId: $repository, categoryId: $category, title: $title, body: $body}) { discussion { url } } }";
    let result = output(
        "gh",
        &[
            "api",
            "graphql",
            "-f",
            &format!("query={mutation}"),
            "-f",
            &format!("repository={repository_id}"),
            "-f",
            &format!("category={category_id}"),
            "-f",
            &format!("title={title}"),
            "-f",
            &format!("body={body}"),
            "--jq",
            ".data.createDiscussion.discussion.url",
        ],
    )?;
    println!("{result}");
    Ok(())
}

fn fuzz_smoke() -> Result<()> {
    let toolchain = format!(
        "+{}",
        std::env::var("NULLLOBBY_FUZZ_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_owned())
    );
    for target in [
        "bt_handshake",
        "bep10",
        "bencode",
        "lobby_card",
        "invite",
        "noise_outer",
        "application",
        "endpoint",
        "terminal",
    ] {
        command(
            "cargo",
            &[
                &toolchain,
                "fuzz",
                "run",
                target,
                "--",
                "-max_total_time=10",
                "-max_len=65536",
                "-rss_limit_mb=512",
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn semantic_version_bumps_reset_lower_components() {
        assert_eq!(next_version("1.2.3", "major").unwrap(), "2.0.0");
        assert_eq!(next_version("1.2.3", "minor").unwrap(), "1.3.0");
        assert_eq!(next_version("1.2.3", "patch").unwrap(), "1.2.4");
        for (version, level) in [
            ("1.2", "patch"),
            ("1.2.3-beta", "patch"),
            ("1.2.3", "typo"),
            ("18446744073709551615.0.0", "major"),
        ] {
            assert!(next_version(version, level).is_err());
        }
    }
    #[test]
    fn version_bumps_preserve_vendored_and_fuzz_package_versions() {
        let mut lock: DocumentMut = "[[package]]\nname = 'nulllobby-core'\nversion = '0.2.0'\n[[package]]\nname = 'tor-hsservice'\nversion = '0.47.0'\n[[package]]\nname = 'nulllobby-fuzz'\nversion = '0.0.0'\n".parse().unwrap();
        bump_lock(&mut lock, &["nulllobby-core".into()], "0.3.0").unwrap();
        let packages = lock["package"].as_array_of_tables().unwrap();
        assert_eq!(packages.get(0).unwrap()["version"].as_str(), Some("0.3.0"));
        assert_eq!(packages.get(1).unwrap()["version"].as_str(), Some("0.47.0"));
        assert_eq!(packages.get(2).unwrap()["version"].as_str(), Some("0.0.0"));
    }
    #[test]
    fn glibc_versions_sort_numerically() {
        assert_eq!(
            glibc_requirement("Name: GLIBC_2.9 Name: GLIBC_2.34 Name: GLIBC_2.3.4 GLIBC_PRIVATE")
                .unwrap(),
            "2.34"
        );
        assert!(glibc_requirement("no ELF versions").is_err());
    }
}
