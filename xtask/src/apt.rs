//! Official APT publication. This module is maintainer tooling only.
use crate::Result;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const ARCHIVE: &str = "https://apt.thugs.red/repo";
const SUITE: &str = "zerotrust";
const KEY_HASH: &str = "026dd9704f4c3c51dc060e39d2834e81d21bf25f71e6ac943061ac2b4c2c1019";
const KEY_FINGERPRINT: &str = "FAE8475A738BE7656B2550A421A7B0A5B3579EE0";
const NAMES: [&str; 2] = ["nulllobby", "nulllobby-arti-experimental"];
const MAX_JSON: usize = 1024 * 1024;
const MAX_INDEX: usize = 8 * 1024 * 1024;
const MAX_DEB: usize = 64 * 1024 * 1024;

struct Config {
    api: reqwest::Url,
    token: SecretString,
}
impl Config {
    fn load() -> Result<Self> {
        let path = if let Some(path) = std::env::var_os("NULLLOBBY_APT_CONFIG") {
            PathBuf::from(path)
        } else {
            let base = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
                .ok_or("APT credential location unavailable")?;
            base.join("xxc-aptd/nulllobby.toml")
        };
        if fs::canonicalize(&path)
            .map_err(|_| "APT configuration unavailable")?
            .starts_with(fs::canonicalize(".")?)
        {
            return Err("APT credentials must be outside the repository".into());
        }
        private_permissions(&path)?;
        let data = Zeroizing::new(read_bounded(&path, 16 * 1024)?);
        Self::parse(std::str::from_utf8(&data).map_err(|_| "invalid APT configuration")?)
    }
    fn parse(text: &str) -> Result<Self> {
        let doc: toml_edit::DocumentMut = text.parse().map_err(|_| "invalid APT configuration")?;
        if doc
            .iter()
            .any(|(k, _)| !matches!(k, "api_base" | "suite" | "api_token" | "allow_private_http"))
            || doc.get("suite").and_then(|v| v.as_str()) != Some(SUITE)
        {
            return Err(
                "APT configuration must select the zerotrust suite and supported fields".into(),
            );
        }
        let api = doc
            .get("api_base")
            .and_then(|v| v.as_str())
            .ok_or("missing APT API base")?;
        let api = reqwest::Url::parse(api).map_err(|_| "invalid APT API base")?;
        let private_http = match doc.get("allow_private_http") {
            Some(value) => value.as_bool().ok_or("invalid APT private HTTP setting")?,
            None => false,
        };
        let allowed_http = private_http
            && api.scheme() == "http"
            && api.host_str().is_some_and(|h| {
                h.parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|ip| ip.is_private())
            });
        if (api.scheme() != "https" && !allowed_http)
            || api.host_str().is_none()
            || !api.username().is_empty()
            || api.password().is_some()
            || api.query().is_some()
            || api.fragment().is_some()
            || !api.path().ends_with("/api/v1")
        {
            return Err("APT API base requires HTTPS or explicitly permitted private IPv4 HTTP, ending in /api/v1 without credentials, query or fragment".into());
        }
        let token = doc
            .get("api_token")
            .and_then(|v| v.as_str())
            .ok_or("missing APT credential")?;
        if !(32..=256).contains(&token.len())
            || !token.starts_with("xxc_aptd_")
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("invalid APT credential format".into());
        }
        Ok(Self {
            api,
            token: SecretString::from(token.to_owned()),
        })
    }
}

#[cfg(target_os = "linux")]
fn private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let uid = fs::metadata("/proc/self")?.uid();
    let f = fs::symlink_metadata(path)?;
    let d = fs::symlink_metadata(path.parent().ok_or("missing APT credential directory")?)?;
    if !f.is_file()
        || !d.is_dir()
        || f.uid() != uid
        || d.uid() != uid
        || f.mode() & 0o077 != 0
        || d.mode() & 0o077 != 0
    {
        return Err(
            "APT config requires an account-owned 0600 file in a 0700 directory; symlinks rejected"
                .into(),
        );
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn private_permissions(_: &Path) -> Result<()> {
    Err("APT publishing credential checks require Linux".into())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err("APT input must be a regular file; symlinks rejected".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("APT input exceeds size limit".into());
    }
    Ok(bytes)
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| "invalid APT response field".into())
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| "invalid APT response collection".into())
}
fn uuid(id: &str) -> Result<&str> {
    if id.len() != 36
        || !id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err("invalid APT object ID".into());
    }
    Ok(id)
}

struct Api {
    client: reqwest::Client,
    base: Option<reqwest::Url>,
    authorization: Option<reqwest::header::HeaderValue>,
}
impl Api {
    fn new(config: Option<Config>) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let base = config.as_ref().map(|c| c.api.clone());
        let https_only = base.as_ref().is_none_or(|url| url.scheme() == "https");
        let authorization = config
            .map(|c| {
                let value = Zeroizing::new(format!("Bearer {}", c.token.expose_secret()));
                let mut h = reqwest::header::HeaderValue::from_str(&value)
                    .map_err(|_| "invalid APT authorization")?;
                h.set_sensitive(true);
                Ok::<_, Box<dyn std::error::Error>>(h)
            })
            .transpose()?;
        let client = reqwest::Client::builder()
            .https_only(https_only)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| "APT HTTP client initialization failed")?;
        Ok(Self {
            client,
            base,
            authorization,
        })
    }
    async fn bytes(&self, request: reqwest::RequestBuilder, limit: usize) -> Result<Vec<u8>> {
        let mut response = request
            .send()
            .await
            .map_err(|_| "APT request failed; inspect status before retrying mutations")?;
        if !response.status().is_success() {
            return Err(format!(
                "APT HTTP {}; response details withheld",
                response.status().as_u16()
            )
            .into());
        }
        if response.content_length().is_some_and(|s| s > limit as u64) {
            return Err("APT response too large".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "APT response interrupted")?
        {
            if chunk.len() > limit.saturating_sub(bytes.len()) {
                return Err("APT response too large".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    async fn request(&self, path: &str, body: Option<(&str, Vec<u8>)>) -> Result<Value> {
        let base = self.base.as_ref().ok_or("APT credentials required")?;
        let url = format!("{base}{path}?suite={SUITE}");
        let req = match body {
            None => self.client.get(url),
            Some((kind, bytes)) => self
                .client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, kind)
                .body(bytes),
        }
        .header(
            reqwest::header::AUTHORIZATION,
            self.authorization
                .as_ref()
                .ok_or("APT credentials required")?
                .clone(),
        );
        let bytes = Zeroizing::new(self.bytes(req, MAX_JSON).await?);
        serde_json::from_slice(&bytes).map_err(|_| "invalid APT JSON response".into())
    }
    async fn public(&self, path: &str, limit: usize) -> Result<Vec<u8>> {
        // No authorization header ever reaches the public download endpoints.
        self.bytes(self.client.get(format!("{ARCHIVE}/{path}")), limit)
            .await
    }
    async fn check_suite(&self) -> Result<()> {
        let suites = self.request("/suites", None).await?;
        if !array(&suites, "suites")?
            .iter()
            .any(|s| s.as_str() == Some(SUITE))
        {
            return Err("APT token cannot access zerotrust".into());
        }
        Ok(())
    }
}

struct Artifact {
    name: String,
    version: String,
    bytes: Vec<u8>,
    sha256: String,
}
impl Artifact {
    fn matches(&self, value: &Value) -> bool {
        value.get("name").and_then(Value::as_str) == Some(self.name.as_str())
            && value.get("version").and_then(Value::as_str) == Some(self.version.as_str())
            && value.get("architecture").and_then(Value::as_str) == Some("amd64")
            && value.get("sha256").and_then(Value::as_str) == Some(self.sha256.as_str())
            && value.get("size").and_then(Value::as_u64) == Some(self.bytes.len() as u64)
            && value.get("component").and_then(Value::as_str) == Some("main")
    }
}
fn artifacts() -> Result<Vec<Artifact>> {
    crate::signing::run("verify-release")?;
    let version = crate::version()?;
    NAMES
        .iter()
        .map(|name| {
            let path = format!("dist/{name}_{version}_amd64.deb");
            let bytes = read_bounded(Path::new(&path), MAX_DEB)?;
            let metadata = crate::output(
                "dpkg-deb",
                &[
                    "--show",
                    "--showformat=${Package}\n${Version}\n${Architecture}",
                    &path,
                ],
            )?;
            if metadata != format!("{name}\n{version}\namd64") {
                return Err("Debian package metadata mismatch".into());
            }
            Ok(Artifact {
                name: (*name).to_owned(),
                version: version.clone(),
                sha256: hash(&bytes),
                bytes,
            })
        })
        .collect()
}

/// The server review token binds this exact shared-suite selection. Never publish
/// removals, downgrades or another project's staged work on their behalf.
fn review(diff: &Value, allowed: &[&Artifact]) -> Result<SecretString> {
    if string(diff, "suite")? != SUITE
        || !array(diff, "removed")?.is_empty()
        || !array(diff, "downgrades")?.is_empty()
        || !array(diff, "architectures_removed")?.is_empty()
        || array(diff, "architectures_added")?
            .iter()
            .any(|a| a.as_str() != Some("amd64"))
    {
        return Err(
            "APT preview contains unexpected suite, removals, downgrades or architectures".into(),
        );
    }
    let added = array(diff, "added")?;
    let mut seen = BTreeSet::new();
    for package in added {
        let a = allowed
            .iter()
            .find(|a| a.matches(package))
            .ok_or("APT preview contains unrelated or mismatched packages")?;
        if !seen.insert(a.name.as_str()) {
            return Err("APT preview contains duplicate packages".into());
        }
    }
    let mut upgrades = BTreeSet::new();
    for upgrade in array(diff, "upgrades")? {
        let name = string(upgrade, "name")?;
        if !seen.contains(name)
            || string(upgrade, "architecture")? != "amd64"
            || !allowed.iter().any(|a| {
                a.name == name
                    && Some(a.version.as_str()) == upgrade.get("after").and_then(Value::as_str)
            })
            || !upgrades.insert(name)
        {
            return Err("APT preview contains an unrelated upgrade".into());
        }
    }
    let size = allowed
        .iter()
        .filter(|a| seen.contains(a.name.as_str()))
        .map(|a| a.bytes.len() as u64)
        .sum::<u64>();
    if diff.get("size_delta").and_then(Value::as_u64) != Some(size) {
        return Err("APT preview size does not match selected packages".into());
    }
    let token = string(diff, "token")?;
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid APT review token".into());
    }
    Ok(SecretString::from(token.to_owned()))
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Result<Self> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| "temporary directory entropy unavailable")?;
        let path = std::env::temp_dir().join(format!(
            "nulllobby-apt-{:032x}",
            u128::from_le_bytes(random)
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn timestamp(text: &str) -> Result<u64> {
    if text.len() > 80 || text.contains(['\r', '\n']) {
        return Err("invalid archive date".into());
    }
    crate::output("date", &["--utc", "--date", text, "+%s"])?
        .parse()
        .map_err(|_| "invalid archive date".into())
}
fn index_digest(release: &str, now: u64) -> Result<(String, usize)> {
    let date = release
        .lines()
        .find_map(|l| l.strip_prefix("Date: "))
        .ok_or("archive date missing")?;
    let until = release
        .lines()
        .find_map(|l| l.strip_prefix("Valid-Until: "))
        .ok_or("archive expiry missing")?;
    if timestamp(date)? > now + 600 || timestamp(until)? <= now {
        return Err("APT metadata is expired or dated in the future".into());
    }
    if !release.lines().any(|l| l == "Suite: zerotrust") {
        return Err("incorrect signed APT suite".into());
    }
    let section = release
        .split_once("\nSHA256:\n")
        .ok_or("APT SHA256 metadata missing")?
        .1;
    let mut found = None;
    for line in section.lines().take_while(|l| l.starts_with(' ')) {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 3 {
            return Err("invalid APT checksum entry".into());
        }
        if f[2] == "main/binary-amd64/Packages" {
            let size: usize = f[1].parse().map_err(|_| "invalid APT index size")?;
            if found.is_some()
                || f[0].len() != 64
                || !f[0].bytes().all(|b| b.is_ascii_hexdigit())
                || size > MAX_INDEX
            {
                return Err("invalid APT index hash or size".into());
            }
            found = Some((f[0].to_owned(), size));
        }
    }
    found.ok_or_else(|| "amd64 APT index missing".into())
}
fn parse_index(text: &str) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n").filter(|s| !s.trim().is_empty()) {
        if out.len() >= 16_384 {
            return Err("APT index package limit reached".into());
        }
        let mut item = serde_json::Map::new();
        for line in stanza.lines().filter(|l| !l.starts_with([' ', '\t'])) {
            let (key, value) = line.split_once(": ").ok_or("invalid APT index field")?;
            let name = match key {
                "Package" => "name",
                "Version" => "version",
                "Architecture" => "architecture",
                "SHA256" => "sha256",
                "Size" => "size",
                "Filename" => "filename",
                _ => continue,
            };
            let value = if name == "size" {
                Value::from(value.parse::<u64>().map_err(|_| "invalid package size")?)
            } else {
                Value::from(value)
            };
            if item.insert(name.to_owned(), value).is_some() {
                return Err("duplicate APT index field".into());
            }
        }
        item.insert("component".into(), Value::from("main"));
        out.push(Value::Object(item));
    }
    Ok(out)
}
async fn public_index(api: &Api) -> Result<Vec<Value>> {
    let temp = Temp::new()?;
    let key = read_bounded(
        Path::new("packaging/thugsred-archive-keyring.gpg"),
        64 * 1024,
    )?;
    if hash(&key) != KEY_HASH {
        return Err("APT archive key differs from reviewed SHA256 pin".into());
    }
    fs::write(temp.0.join("keyring.gpg"), key)?;
    let release = api.public("dists/zerotrust/Release", MAX_JSON).await?;
    let signature = api.public("dists/zerotrust/Release.gpg", 64 * 1024).await?;
    fs::write(temp.0.join("Release"), &release)?;
    fs::write(temp.0.join("Release.gpg"), signature)?;
    let output = Command::new("timeout")
        .args(["--signal=KILL", "30s", "gpgv", "--homedir"])
        .arg(&temp.0)
        .arg("--keyring")
        .arg(temp.0.join("keyring.gpg"))
        .args(["--status-fd", "1"])
        .arg(temp.0.join("Release.gpg"))
        .arg(temp.0.join("Release"))
        .output()
        .map_err(|_| "APT signature verifier unavailable")?;
    if !output.status.success() {
        return Err("APT Release.gpg signature verification failed".into());
    }
    crate::signing::validate_signature_status(
        std::str::from_utf8(&output.stdout).map_err(|_| "invalid APT signature status")?,
        KEY_FINGERPRINT,
    )
    .map_err(|_| "APT signature must be valid Ed25519/SHA-256 from the pinned archive key")?;
    let (digest, size) = index_digest(
        std::str::from_utf8(&release).map_err(|_| "invalid APT Release encoding")?,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    // Acquire by hash to avoid observing a different generation between reads.
    let index = api
        .public(
            &format!("dists/zerotrust/main/binary-amd64/by-hash/SHA256/{digest}"),
            MAX_INDEX,
        )
        .await?;
    if index.len() != size || hash(&index) != digest {
        return Err("APT index differs from signed metadata".into());
    }
    parse_index(std::str::from_utf8(&index).map_err(|_| "invalid APT index encoding")?)
}
fn published<'a>(packages: &'a [Value], a: &Artifact) -> Result<Option<&'a Value>> {
    let matches: Vec<_> = packages
        .iter()
        .filter(|p| {
            p.get("name").and_then(Value::as_str) == Some(a.name.as_str())
                && p.get("version").and_then(Value::as_str) == Some(a.version.as_str())
                && p.get("architecture").and_then(Value::as_str) == Some("amd64")
        })
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [p] if a.matches(p) => Ok(Some(p)),
        _ => Err(
            "published APT version conflicts with local signed artifact; refusing replacement"
                .into(),
        ),
    }
}
fn pool_path(path: &str) -> Result<&str> {
    if !path.starts_with("pool/main/")
        || !path.ends_with(".deb")
        || path.len() > 512
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._+-".contains(&b))
    {
        return Err("invalid public APT package path".into());
    }
    Ok(path)
}
async fn verify_public(api: &Api, artifacts: &[Artifact]) -> Result<()> {
    let index = public_index(api).await?;
    for a in artifacts {
        let p = published(&index, a)?.ok_or("released package absent from signed APT index")?;
        let bytes = api
            .public(pool_path(string(p, "filename")?)?, MAX_DEB)
            .await?;
        if hash(&bytes) != a.sha256 || bytes.len() != a.bytes.len() {
            return Err("public APT download differs from signed release".into());
        }
        println!(
            "Verified APT: {} {} amd64 (signed metadata and exact release bytes)",
            a.name, a.version
        );
    }
    Ok(())
}

fn validate_github_release(release: &Value, artifacts: &[Artifact]) -> Result<()> {
    let version = artifacts
        .first()
        .ok_or("no release artifacts")?
        .version
        .as_str();
    if release.get("draft").and_then(Value::as_bool) != Some(false)
        || release.get("prerelease").and_then(Value::as_bool) != Some(false)
        || string(release, "tag_name")? != format!("v{version}")
    {
        return Err("APT publication requires the matching published GitHub release".into());
    }
    for a in artifacts {
        let name = format!("{}_{}_amd64.deb", a.name, a.version);
        let matching: Vec<_> = array(release, "assets")?
            .iter()
            .filter(|p| p.get("name").and_then(Value::as_str) == Some(name.as_str()))
            .collect();
        if matching.len() != 1 || string(matching[0], "digest")? != format!("sha256:{}", a.sha256) {
            return Err("APT package differs from published GitHub release asset digest".into());
        }
    }
    Ok(())
}

async fn github_release(api: &Api, artifacts: &[Artifact]) -> Result<()> {
    let manifest = crate::manifest()?;
    let repo = manifest["workspace"]["package"]["repository"]
        .as_str()
        .and_then(|s| s.strip_prefix("https://github.com/"))
        .ok_or("GitHub project URL required")?;
    if repo.split('/').count() != 2
        || repo.split('/').any(str::is_empty)
        || !repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
    {
        return Err("invalid GitHub project URL".into());
    }
    let version = crate::version()?;
    if version.split('.').count() != 3 || version.split('.').any(|v| v.parse::<u64>().is_err()) {
        return Err("invalid release version".into());
    }
    let request = api
        .client
        .get(format!(
            "https://api.github.com/repos/{repo}/releases/tags/v{version}"
        ))
        .header(reqwest::header::USER_AGENT, "nulllobby-release-tool");
    let bytes = api.bytes(request, MAX_JSON).await?;
    let release = serde_json::from_slice(&bytes).map_err(|_| "invalid GitHub release metadata")?;
    validate_github_release(&release, artifacts)
}

async fn publish(api: &Api, artifacts: &[Artifact]) -> Result<()> {
    github_release(api, artifacts).await?;
    api.check_suite().await?;
    let index = public_index(api).await?;
    let mut missing = Vec::new();
    for a in artifacts {
        if published(&index, a)?.is_none() {
            missing.push(a);
        }
    }
    if missing.is_empty() {
        println!("Both packages are already published; no repository changes.");
        return verify_public(api, artifacts).await;
    }
    let initial = api.request("/repository/diff", None).await?;
    review(&initial, &missing)?;
    let staged: BTreeSet<_> = array(&initial, "added")?
        .iter()
        .map(|p| string(p, "name"))
        .collect::<Result<_>>()?;
    for a in &missing {
        if staged.contains(a.name.as_str()) {
            continue;
        }
        println!("Uploading {} {} to zerotrust", a.name, a.version);
        let upload = api
            .request(
                "/uploads",
                Some(("application/vnd.debian.binary-package", a.bytes.clone())),
            )
            .await?;
        if !a.matches(&upload) {
            return Err("APT upload metadata differs from verified local package".into());
        }
        let id = uuid(string(&upload, "id")?)?;
        let stage = api
            .request(
                &format!("/uploads/{id}/stage"),
                Some(("application/json", b"{}".to_vec())),
            )
            .await?;
        if stage.get("staged").and_then(Value::as_bool) != Some(true) {
            return Err("APT package was not staged".into());
        }
    }
    let diff = api.request("/repository/diff", None).await?;
    let token = review(&diff, &missing)?;
    if array(&diff, "added")?.len() != missing.len() {
        return Err("APT preview does not include every missing release artifact".into());
    }
    println!(
        "Reviewed {} exact package additions; no removals or unrelated changes.",
        missing.len()
    );
    let accepted = api
        .request(
            "/repository/publish",
            Some((
                "application/json",
                serde_json::to_vec(&json!({"review_token":token.expose_secret()}))?,
            )),
        )
        .await?;
    let id = uuid(string(&accepted, "job_id")?)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    loop {
        let job = api.request(&format!("/jobs/{id}"), None).await?;
        if string(&job, "id")? != id {
            return Err("APT returned a different publication job".into());
        }
        match string(&job, "state")? {
            "succeeded" => break,
            "failed" => {
                return Err("APT publication job failed; inspect repository administration".into());
            }
            "running" if tokio::time::Instant::now() < deadline => {
                println!("APT publication running…");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            _ => {
                return Err(
                    "APT publication still pending or unknown; inspect status before retrying"
                        .into(),
                );
            }
        }
    }
    verify_public(api, artifacts).await
}

pub(crate) fn run(action: &str) -> Result<()> {
    let artifacts = if action == "apt-status" {
        Vec::new()
    } else {
        artifacts()?
    };
    let config = if action == "apt-verify" {
        None
    } else {
        Some(Config::load()?)
    };
    let api = Api::new(config)?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        match action {
            "apt-publish"=>publish(&api, &artifacts).await,
            "apt-verify"=>verify_public(&api, &artifacts).await,
            "apt-status"=>{
                api.check_suite().await?;
                let diff = api.request("/repository/diff", None).await?;
                println!("APT zerotrust accessible; staged additions: {}, removals: {}, upgrades: {}, downgrades: {}",
                    array(&diff,"added")?.len(),array(&diff,"removed")?.len(),array(&diff,"upgrades")?.len(),array(&diff,"downgrades")?.len());
                Ok(())
            }
            _=>Err("unknown APT action".into()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn artifact() -> Artifact {
        Artifact {
            name: "nulllobby".into(),
            version: "0.4.2".into(),
            bytes: vec![1, 2],
            sha256: hash(&[1, 2]),
        }
    }
    fn package(a: &Artifact) -> Value {
        json!({"name":a.name,"version":a.version,"architecture":"amd64","sha256":a.sha256,"size":2,"component":"main"})
    }
    fn diff(a: &Artifact) -> Value {
        json!({"suite":SUITE,"token":"a".repeat(64),"added":[package(a)],"removed":[],"upgrades":[],"downgrades":[],"architectures_added":[],"architectures_removed":[],"size_delta":2})
    }
    #[test]
    fn review_rejects_unrelated_or_changed_selection() {
        let a = artifact();
        let good = diff(&a);
        assert!(review(&good, &[&a]).is_ok());
        for field in ["removed", "downgrades", "architectures_removed"] {
            let mut bad = good.clone();
            bad[field] = json!(["unexpected"]);
            assert!(review(&bad, &[&a]).is_err());
        }
        for (field, value) in [
            ("suite", json!("other")),
            ("size_delta", json!(3)),
            ("token", json!("bad")),
            ("architectures_added", json!(["arm64"])),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(review(&bad, &[&a]).is_err());
        }
        for field in ["name", "version", "architecture", "sha256", "component"] {
            let mut bad = good.clone();
            bad["added"][0][field] = json!("wrong");
            assert!(review(&bad, &[&a]).is_err());
        }
        let mut duplicate = good.clone();
        duplicate["added"].as_array_mut().unwrap().push(package(&a));
        assert!(review(&duplicate, &[&a]).is_err());
        let mut extra = good;
        extra["upgrades"] = json!([{"name":"another","architecture":"amd64","after":a.version}]);
        assert!(review(&extra, &[&a]).is_err());
    }
    #[test]
    fn upgrade_must_match_verified_addition() {
        let a = artifact();
        let mut d = diff(&a);
        d["upgrades"] =
            json!([{"name":a.name,"architecture":"amd64","before":"0.4.1","after":a.version}]);
        assert!(review(&d, &[&a]).is_ok());
        d["upgrades"][0]["after"] = json!("9.0.0");
        assert!(review(&d, &[&a]).is_err());
    }
    #[test]
    fn existing_versions_cannot_be_replaced() {
        let a = artifact();
        assert!(published(&[], &a).unwrap().is_none());
        assert!(published(&[package(&a)], &a).unwrap().is_some());
        let mut p = package(&a);
        p["sha256"] = json!("0".repeat(64));
        assert!(published(&[p], &a).is_err());
        assert!(published(&[package(&a), package(&a)], &a).is_err());
    }
    #[test]
    fn credential_errors_do_not_echo_input_or_allow_insecure_destinations() {
        const API: &str = "https://apt.thugs.red/admin/api/v1";
        let secret = "xxc_aptd_012345678901234567890123456789";
        let text = format!("api_base = '{API}'\nsuite = '{SUITE}'\napi_token = '{secret}'");
        assert!(Config::parse(&text).is_ok());
        for bad in [
            text.replace(API, "http://apt.thugs.red/admin/api/v1"),
            text.replace(API, "https://user:password@apt.thugs.red/api/v1"),
            text.replace(API, "https://apt.thugs.red/api/v1?forward=1"),
            text.replace(API, "https://apt.thugs.red/api/v1#fragment"),
            text.replace(SUITE, "wrong"),
            format!("{text}\nother='{secret}'"),
            format!("broken {secret}"),
        ] {
            let err = Config::parse(&bad).err().unwrap().to_string();
            assert!(!err.contains(secret));
        }
    }
    #[test]
    fn reject_index_ambiguity_and_path_injection() {
        assert!(parse_index("Package: a\nPackage: b\n").is_err());
        assert!(parse_index("Package: a\nSize: invalid\n").is_err());
        for p in [
            "https://other/a.deb",
            "pool/main/../a.deb",
            "pool/main/a.deb?token=1",
            "pool/main//a.deb",
            "pool/main/%2e%2e/a.deb",
        ] {
            assert!(pool_path(p).is_err());
        }
        assert!(pool_path("pool/main/n/nulllobby/nulllobby_0.4.2_amd64.deb").is_ok());
        assert!(uuid("../../../secret").is_err());
        assert!(uuid("00000000-0000-0000-0000-000000000000").is_ok());
    }

    #[test]
    fn private_http_requires_explicit_opt_in_and_numeric_private_destination() {
        let config = "api_base='http://192.168.50.10:8089/api/v1'\nsuite='zerotrust'\napi_token='xxc_aptd_synthetic_not_a_real_credential'";
        assert!(Config::parse(config).is_err());
        let enabled = format!("{config}\nallow_private_http=true");
        assert!(Config::parse(&enabled).is_ok());
        for host in ["example.invalid", "8.8.8.8", "169.254.169.254", "127.0.0.1"] {
            assert!(Config::parse(&enabled.replace("192.168.50.10", host)).is_err());
        }
    }

    #[test]
    fn apt_requires_a_published_github_release_with_identical_packages() {
        let a = artifact();
        let good = json!({"draft":false,"prerelease":false,"tag_name":"v0.4.2",
            "assets":[{"name":"nulllobby_0.4.2_amd64.deb","digest":format!("sha256:{}",a.sha256)}]});
        validate_github_release(&good, std::slice::from_ref(&a)).unwrap();
        for field in ["draft", "prerelease"] {
            let mut bad = good.clone();
            bad[field] = json!(true);
            assert!(validate_github_release(&bad, std::slice::from_ref(&a)).is_err());
        }
        let mut bad = good.clone();
        bad["assets"][0]["digest"] = json!("sha256:modified");
        assert!(validate_github_release(&bad, std::slice::from_ref(&a)).is_err());
        bad = good.clone();
        bad["assets"] = json!([]);
        assert!(validate_github_release(&bad, std::slice::from_ref(&a)).is_err());
        bad = good;
        bad["tag_name"] = json!("v0.0.1");
        assert!(validate_github_release(&bad, &[a]).is_err());
    }

    #[test]
    fn archive_metadata_rejects_expiry_future_dates_wrong_suite_and_large_indexes() {
        let now = timestamp("2026-10-04 12:00:00 UTC").unwrap();
        let text = format!(
            "Suite: zerotrust\nDate: 2026-10-04 11:00:00 UTC\nValid-Until: 2026-10-05 00:00:00 UTC\nSHA256:\n {} 123 main/binary-amd64/Packages\nSHA512:\n",
            "a".repeat(64)
        );
        assert_eq!(index_digest(&text, now).unwrap(), ("a".repeat(64), 123));
        for bad in [
            text.replace("2026-10-05", "2026-10-03"),
            text.replace("11:00:00", "13:00:00"),
            text.replace("zerotrust", "another-suite"),
            text.replace("123", "999999999999"),
            text.replace("SHA256:", "SHA1:"),
        ] {
            assert!(index_digest(&bad, now).is_err());
        }
        let duplicate = text.replace(
            "SHA512:",
            &format!(
                " {} 123 main/binary-amd64/Packages\nSHA512:",
                "a".repeat(64)
            ),
        );
        assert!(index_digest(&duplicate, now).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn apt_credentials_reject_public_permissions_symlinks_and_oversized_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = Temp::new().unwrap();
        let path = dir.0.join("credentials");
        fs::write(&path, b"synthetic").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_permissions(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        private_permissions(&path).unwrap();
        let link = dir.0.join("link");
        symlink(&path, &link).unwrap();
        assert!(private_permissions(&link).is_err());
        assert!(read_bounded(&link, 32).is_err());
        assert!(read_bounded(&path, 2).is_err());
    }
}
