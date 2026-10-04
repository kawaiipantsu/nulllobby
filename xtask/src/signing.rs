//! Optional maintainer tooling. Never linked into the chat client.
//! XXC keeps the release private key; local GnuPG independently checks signatures.
use crate::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use toml_edit::DocumentMut;
use zeroize::Zeroizing;

const API: &str = "https://ca.xxc.dk/api/v1";
const KEY: &str = "nulllobby-release-key.asc";
const PIN: &str = "nulllobby-release-key.sha256";
const NAME: &str = "NullLobby Release Signing";
const MAX_CONFIG: usize = 16 * 1024;
const MAX_KEY: usize = 64 * 1024;
const MAX_MANIFEST: usize = 4096;
const MAX_RESPONSE: usize = 1024 * 1024;
const MANIFESTS: [&str; 2] = ["SHA256SUMS", "SHA256SUMS-arti"];
pub(crate) const RELEASE_ASSETS: [&str; 4] = [
    "dist/SHA256SUMS.asc",
    "dist/SHA256SUMS-arti.asc",
    "dist/nulllobby-release-key.asc",
    "dist/nulllobby-release-key.sha256",
];

struct Config {
    path: PathBuf,
    token: SecretString,
    key_id: Option<String>,
    email: Option<String>,
}

fn config_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("NULLLOBBY_SIGNING_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or("signing configuration location unavailable")?;
    Ok(base.join("xxc-ca/nulllobby-release.toml"))
}

fn load_config() -> Result<Config> {
    let path = config_path()?;
    let canonical = fs::canonicalize(&path).map_err(|_| "signing configuration unavailable")?;
    if canonical.starts_with(fs::canonicalize(".")?) {
        return Err("signing credentials must be outside the repository".into());
    }
    private_permissions(&path)?;
    let data = Zeroizing::new(read_bounded(&path, MAX_CONFIG)?);
    let text = std::str::from_utf8(&data).map_err(|_| "invalid signing configuration")?;
    parse_config(path, text)
}

#[cfg(target_os = "linux")]
fn private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let owner = fs::metadata("/proc/self")?.uid();
    let file = fs::symlink_metadata(path)?;
    let directory = fs::symlink_metadata(path.parent().ok_or("missing credential directory")?)?;
    if !file.is_file()
        || !directory.is_dir()
        || file.uid() != owner
        || directory.uid() != owner
        || file.mode() & 0o077 != 0
        || directory.mode() & 0o077 != 0
    {
        return Err("signing config must be account-owned, mode 0600, in an account-owned 0700 directory; symlinks are rejected".into());
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn private_permissions(_: &Path) -> Result<()> {
    Err("release signing credential checks currently require Linux".into())
}

fn parse_config(path: PathBuf, text: &str) -> Result<Config> {
    let doc: DocumentMut = text.parse().map_err(|_| "invalid signing configuration")?;
    if doc
        .iter()
        .any(|(key, _)| !matches!(key, "api_base" | "api_token" | "key_id" | "signing_email"))
    {
        return Err("unknown signing configuration field".into());
    }
    if doc.get("api_base").and_then(|v| v.as_str()) != Some(API) {
        return Err("signing endpoint must be the reviewed XXC HTTPS API".into());
    }
    let token = doc
        .get("api_token")
        .and_then(|v| v.as_str())
        .ok_or("missing signing credential")?;
    if token.len() < 16
        || token.len() > 256
        || !token.starts_with("xxc_")
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("invalid signing credential format".into());
    }
    let key_id = doc
        .get("key_id")
        .map(|v| v.as_str().ok_or("invalid signing key ID"))
        .transpose()?
        .map(str::to_owned);
    if key_id.as_ref().is_some_and(|id| !valid_key_id(id)) {
        return Err("invalid signing key ID".into());
    }
    let email = doc
        .get("signing_email")
        .map(|v| v.as_str().ok_or("invalid project signing email"))
        .transpose()?
        .map(str::to_owned);
    if email.as_ref().is_some_and(|value| !valid_email(value)) {
        return Err("invalid project signing email".into());
    }
    Ok(Config {
        path,
        token: SecretString::from(token.to_owned()),
        key_id,
        email,
    })
}

fn valid_key_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_email(email: &str) -> bool {
    email.len() <= 254
        && email.split('@').count() == 2
        && !email.starts_with('@')
        && !email.ends_with('@')
        && email
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
}

struct Ca {
    client: reqwest::Client,
    authorization: reqwest::header::HeaderValue,
}
impl Ca {
    fn new(config: &Config) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!(
            "Bearer {}",
            config.token.expose_secret()
        ))
        .map_err(|_| "invalid signing authorization")?;
        authorization.set_sensitive(true);
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| "cannot initialize signing HTTPS client")?;
        Ok(Self {
            client,
            authorization,
        })
    }
    async fn request(&self, path: &str, body: Option<Value>, limit: usize) -> Result<Vec<u8>> {
        let url = format!("{API}{path}");
        let request = match body {
            Some(body) => self.client.post(url).json(&body),
            None => self.client.get(url),
        }
        .header(reqwest::header::AUTHORIZATION, self.authorization.clone());
        let mut response = request
            .send()
            .await
            .map_err(|_| "XXC HTTPS request failed; no fallback")?;
        if !response.status().is_success() {
            return Err(format!(
                "XXC returned HTTP {}; response details withheld",
                response.status().as_u16()
            )
            .into());
        }
        if response.content_length().is_some_and(|n| n > limit as u64) {
            return Err("XXC response exceeds size limit".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "XXC response failed")? {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|n| n > limit)
            {
                return Err("XXC response exceeds size limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    async fn json(&self, path: &str, body: Option<Value>) -> Result<Value> {
        serde_json::from_slice(&self.request(path, body, MAX_RESPONSE).await?)
            .map_err(|_| "invalid XXC JSON response".into())
    }
    async fn sign(&self, id: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        if !valid_key_id(id) || bytes.len() > MAX_MANIFEST {
            return Err("invalid signing request".into());
        }
        let response = self
            .json(
                &format!("/openpgp/keys/{id}/sign"),
                Some(json!({"data_base64": STANDARD.encode(bytes), "format":"detached"})),
            )
            .await?;
        decode_signature(&response)
    }
}

fn decode_signature(response: &Value) -> Result<Vec<u8>> {
    let encoded = response
        .get("data_base64")
        .and_then(Value::as_str)
        .ok_or("missing XXC signature")?;
    if encoded.len() > MAX_KEY {
        return Err("XXC signature exceeds limit".into());
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "invalid XXC signature encoding")?;
    if !bytes.starts_with(b"-----BEGIN PGP SIGNATURE-----") {
        return Err("expected detached OpenPGP signature".into());
    }
    // Server filenames are deliberately ignored.
    Ok(bytes)
}

pub(crate) fn run(action: &str) -> Result<()> {
    if action == "verify-release" {
        return verify_release();
    }
    let config = load_config()?;
    let ca = Ca::new(&config)?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        match action {
            "ca-status" => {
                let inventory = ca.json("/openpgp/keys?q=NullLobby", None).await?;
                let count = inventory.get("total").and_then(Value::as_u64).ok_or("invalid XXC key inventory")?;
                println!("XXC authentication: accepted. Project key matches: {count}. Signing key configured: {}.", config.key_id.is_some());
                Ok(())
            }
            "ca-enroll" => enroll(&ca, &config).await,
            "sign-release" => sign_release(&ca, &config).await,
            _ => Err("unknown signing action".into()),
        }
    })
}

pub(crate) fn preflight() -> Result<()> {
    if load_config()?.key_id.is_none() {
        return Err("release signing key is not configured".into());
    }
    Verifier::new(&pinned_key()?)?;
    Ok(())
}

async fn enroll(ca: &Ca, config: &Config) -> Result<()> {
    if config.key_id.is_some()
        || Path::new("packaging").join(KEY).exists()
        || Path::new("packaging").join(PIN).exists()
    {
        return Err(
            "signing identity already configured; rotation requires explicit review".into(),
        );
    }
    let email = config.email.as_deref().ok_or(
        "set an approved public project signing_email in the external configuration first",
    )?;
    let inventory = ca.json("/openpgp/keys?q=NullLobby", None).await?;
    if inventory.get("total").and_then(Value::as_u64) != Some(0) {
        return Err(
            "a project key already exists; review it before configuring or creating another".into(),
        );
    }
    // Explicit enrollment only. No auto-generation, retry, public exchange publication or private-key export.
    let metadata = ca
        .json(
            "/openpgp/keys",
            Some(json!({"name":NAME,"email":email,"algorithm":"Ed25519","days":365})),
        )
        .await?;
    let id = metadata
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| valid_key_id(id))
        .ok_or("invalid new signing key ID")?;
    let public = ca
        .request(
            &format!("/openpgp/keys/{id}/download?format=armor"),
            None,
            MAX_KEY,
        )
        .await?;
    let verifier = Verifier::new(&public)?;
    let proof = b"nulllobby.release-signing.enrollment.v1\n";
    verifier.verify(proof, &ca.sign(id, proof).await?)?;
    // Reject any unexpected identity before making this public key a repository artifact.
    if verifier.user_ids != [format!("{NAME} <{email}>")] {
        return Err(
            "new signing key has unexpected user IDs; inspect XXC without publishing it".into(),
        );
    }
    let pin = format!("{}  {KEY}\n", hex(&Sha256::digest(&public)));
    write_new(&Path::new("packaging").join(KEY), &public)?;
    write_new(&Path::new("packaging").join(PIN), pin.as_bytes())?;
    // Credential file stays outside the repository and retains restricted permissions.
    private_permissions(&config.path)?;
    let current = Zeroizing::new(read_bounded(&config.path, MAX_CONFIG)?);
    let mut doc: DocumentMut = std::str::from_utf8(&current)
        .map_err(|_| "invalid signing config")?
        .parse()
        .map_err(|_| "invalid signing config")?;
    doc["key_id"] = toml_edit::value(id);
    let text = Zeroizing::new(doc.to_string());
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&config.path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    println!(
        "Release key enrolled and locally verified. Review the public key and SHA-256 pin before publishing them. The private key remains in XXC."
    );
    Ok(())
}

async fn sign_release(ca: &Ca, config: &Config) -> Result<()> {
    let id = config
        .key_id
        .as_deref()
        .ok_or("release signing key is not configured; explicit enrollment is required")?;
    let public = pinned_key()?;
    let verifier = Verifier::new(&public)?;
    let manifests = checked_manifests(Path::new("dist"), &crate::version()?)?;
    let metadata = ca.json(&format!("/openpgp/keys/{id}"), None).await?;
    if metadata.get("status").and_then(Value::as_str) != Some("active")
        || metadata.get("has_private_key").and_then(Value::as_bool) != Some(true)
        || metadata.get("fingerprint").and_then(Value::as_str)
            != Some(verifier.fingerprint.as_str())
    {
        return Err(
            "XXC signing key is unavailable or does not match the pinned public key".into(),
        );
    }
    let mut signatures = Vec::new();
    for bytes in &manifests {
        let signature = ca.sign(id, bytes).await?;
        verifier.verify(bytes, &signature)?;
        signatures.push(signature);
    }
    // Recheck artifacts before committing outputs; no valid-looking outputs from a failed request.
    if checked_manifests(Path::new("dist"), &crate::version()?)? != manifests {
        return Err("release artifacts changed during signing".into());
    }
    for (name, signature) in MANIFESTS.iter().zip(signatures) {
        fs::write(Path::new("dist").join(format!("{name}.asc")), signature)?;
    }
    fs::write(Path::new("dist").join(KEY), public)?;
    fs::copy(
        Path::new("packaging").join(PIN),
        Path::new("dist").join(PIN),
    )?;
    println!(
        "Both release checksum manifests signed and independently verified. Chat data and keys were not sent to XXC."
    );
    Ok(())
}

fn verify_release() -> Result<()> {
    let public = pinned_key()?;
    if read_bounded(&Path::new("dist").join(KEY), MAX_KEY)? != public {
        return Err("downloaded release public key differs from the trusted repository pin".into());
    }
    let verifier = Verifier::new(&public)?;
    let manifests = checked_manifests(Path::new("dist"), &crate::version()?)?;
    for (name, bytes) in MANIFESTS.iter().zip(manifests) {
        verifier.verify(
            &bytes,
            &read_bounded(&Path::new("dist").join(format!("{name}.asc")), MAX_KEY)?,
        )?;
    }
    println!(
        "Offline verification passed: pinned release key, Ed25519/SHA-256 signatures and all four artifact checksums."
    );
    Ok(())
}

fn pinned_key() -> Result<Vec<u8>> {
    let public = read_bounded(&Path::new("packaging").join(KEY), MAX_KEY)?;
    let expected = format!("{}  {KEY}\n", hex(&Sha256::digest(&public)));
    if read_bounded(&Path::new("packaging").join(PIN), 256)? != expected.as_bytes() {
        return Err("release public key SHA-256 pin mismatch".into());
    }
    Ok(public)
}

fn checked_manifests(directory: &Path, version: &str) -> Result<Vec<Vec<u8>>> {
    let mut manifests = Vec::new();
    for (name, package) in MANIFESTS
        .iter()
        .zip(["nulllobby", "nulllobby-arti-experimental"])
    {
        let expected_names = [
            format!("{package}_{version}_amd64.deb"),
            format!("{package}_{version}_{}.tar.gz", crate::TARGET),
        ];
        let bytes = read_bounded(&directory.join(name), MAX_MANIFEST)?;
        let parsed = parse_manifest(&bytes, &expected_names)?;
        for (expected_hash, filename) in parsed {
            let path = directory.join(filename);
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
                return Err("release artifact must be a bounded regular file".into());
            }
            let mut file = File::open(path)?.take(512 * 1024 * 1024 + 1);
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let length = file.read(&mut buffer)?;
                if length == 0 {
                    break;
                }
                hasher.update(&buffer[..length]);
            }
            if hex(&hasher.finalize()) != expected_hash {
                return Err("release artifact checksum mismatch".into());
            }
        }
        manifests.push(bytes);
    }
    Ok(manifests)
}

fn parse_manifest<'a>(bytes: &'a [u8], expected: &[String; 2]) -> Result<Vec<(&'a str, &'a str)>> {
    if bytes.len() > MAX_MANIFEST || !bytes.ends_with(b"\n") {
        return Err("invalid release checksum manifest".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid release checksum manifest")?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 2 {
        return Err("manifest must contain exactly the two expected artifacts".into());
    }
    let mut result = Vec::new();
    for (line, name) in lines.into_iter().zip(expected) {
        let (hash, filename) = line
            .split_once("  ")
            .ok_or("invalid release checksum line")?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || filename != name
        {
            return Err("manifest hash, version or filename is invalid".into());
        }
        result.push((hash, filename));
    }
    Ok(result)
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err("expected regular file; symlinks are rejected".into());
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("file exceeds signing size limit".into());
    }
    Ok(bytes)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

struct TemporaryDirectory(PathBuf);
impl TemporaryDirectory {
    fn new() -> Result<Self> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| "temporary directory randomness unavailable")?;
        let path = std::env::temp_dir().join(format!("nulllobby-release-{}", hex(&random)));
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
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Verifier {
    directory: TemporaryDirectory,
    fingerprint: String,
    user_ids: Vec<String>,
}
impl Verifier {
    fn new(public: &[u8]) -> Result<Self> {
        if public.len() > MAX_KEY || !public.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----") {
            return Err("expected a bounded armored public release key".into());
        }
        let directory = TemporaryDirectory::new()?;
        fs::write(directory.0.join(KEY), public)?;
        gpg(&directory.0, &["--import", KEY])?;
        let listing = gpg(
            &directory.0,
            &["--with-colons", "--with-fingerprint", "--list-keys"],
        )?;
        let (fingerprint, user_ids) = parse_public_key(&listing)?;
        Ok(Self {
            directory,
            fingerprint,
            user_ids,
        })
    }
    fn verify(&self, bytes: &[u8], signature: &[u8]) -> Result<()> {
        if bytes.len() > MAX_MANIFEST || signature.len() > MAX_KEY {
            return Err("verification size limit exceeded".into());
        }
        fs::write(self.directory.0.join("manifest"), bytes)?;
        fs::write(self.directory.0.join("signature.asc"), signature)?;
        let status = gpg(
            &self.directory.0,
            &["--status-fd", "1", "--verify", "signature.asc", "manifest"],
        )?;
        validate_signature_status(&status, &self.fingerprint)
    }
}

fn gpg(directory: &Path, arguments: &[&str]) -> Result<String> {
    // A separate public-only keyring; no personal config, ownertrust, agents or keyserver lookup.
    let result = Command::new("timeout")
        .args(["--signal=KILL", "30s", "gpg"])
        .args([
            "--no-options",
            "--batch",
            "--no-tty",
            "--no-autostart",
            "--disable-dirmngr",
            "--no-auto-key-retrieve",
            "--no-auto-key-import",
            "--max-output",
            "1048576",
            "--auto-key-locate",
            "clear",
            "--homedir",
        ])
        .arg(directory)
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "GnuPG unavailable; install gnupg")?;
    if !result.status.success() {
        return Err("GnuPG rejected release key or signature; details withheld".into());
    }
    if result.stdout.len() > MAX_RESPONSE {
        return Err("GnuPG output exceeds limit".into());
    }
    String::from_utf8(result.stdout).map_err(|_| "invalid GnuPG output".into())
}

fn parse_public_key(listing: &str) -> Result<(String, Vec<String>)> {
    let mut count = 0;
    let mut primary = false;
    let mut fingerprint = None;
    let mut user_ids = Vec::new();
    for line in listing.lines() {
        let fields: Vec<_> = line.split(':').collect();
        match fields.first().copied() {
            Some("pub") => {
                count += 1;
                if !matches!(fields.get(3), Some(&"22") | Some(&"27"))
                    || fields.get(16) != Some(&"ed25519")
                    || fields
                        .get(1)
                        .is_some_and(|v| matches!(*v, "r" | "e" | "i" | "d"))
                {
                    return Err("release signing requires an active Ed25519 public key".into());
                }
                primary = true;
            }
            Some("sub") => {
                primary = false;
            }
            Some("sec" | "ssb") => return Err("private key data is forbidden".into()),
            Some("fpr") if primary => {
                fingerprint = fields.get(9).map(|v| (*v).to_owned());
                primary = false;
            }
            Some("uid") => {
                user_ids.push(
                    fields
                        .get(9)
                        .ok_or("invalid public key user ID")?
                        .to_string(),
                );
            }
            _ => {}
        }
    }
    let fingerprint = fingerprint
        .filter(|s| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("missing public key fingerprint")?;
    if count != 1 || user_ids.is_empty() || user_ids.len() > 8 {
        return Err("expected exactly one release public key".into());
    }
    Ok((fingerprint, user_ids))
}

pub(crate) fn validate_signature_status(status: &str, fingerprint: &str) -> Result<()> {
    let mut valid = 0;
    for line in status.lines() {
        let Some(payload) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        let fields: Vec<_> = payload.split_whitespace().collect();
        match fields.first().copied() {
            Some("VALIDSIG") => {
                let primary = fields.get(10).or(fields.get(1)).copied();
                if primary != Some(fingerprint)
                    || !matches!(fields.get(7), Some(&"22") | Some(&"27"))
                    || fields.get(8) != Some(&"8")
                    || fields.get(9) != Some(&"00")
                {
                    return Err("unexpected release signer, signature type or digest".into());
                }
                valid += 1;
            }
            Some(
                "BADSIG" | "ERRSIG" | "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG" | "FAILURE" | "ERROR",
            ) => return Err("invalid, expired or revoked release signature".into()),
            _ => {}
        }
    }
    if valid != 1 {
        return Err("expected exactly one valid release signature".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_TOKEN: &str = "xxc_synthetic_test_credential_not_usable";
    fn configuration() -> String {
        format!("api_base = \"{API}\"\napi_token = \"{SYNTHETIC_TOKEN}\"\n")
    }

    #[test]
    fn credentials_reject_remote_endpoints_injection_and_unknown_fields() {
        assert!(parse_config(PathBuf::new(), &configuration()).is_ok());
        for bad in [
            configuration().replace(API, "http://ca.xxc.dk/api/v1"),
            configuration().replace(API, "https://example.invalid/api/v1"),
            format!("{}key_id = \"../other\"", configuration()),
            format!("{}unknown = true", configuration()),
            configuration().replace(SYNTHETIC_TOKEN, "xxc_invalid\\nInjected: header"),
            format!("{}signing_email = \"a@b\\nInjected\"", configuration()),
            format!("{}api_token = \"duplicate\"", configuration()),
        ] {
            let error = match parse_config(PathBuf::new(), &bad) {
                Err(error) => error,
                Ok(_) => panic!("invalid configuration accepted"),
            };
            assert!(!error.to_string().contains(SYNTHETIC_TOKEN));
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn credentials_require_private_permissions_and_reject_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = TemporaryDirectory::new().unwrap();
        let file = directory.0.join("credential");
        fs::write(&file, configuration()).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_permissions(&file).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        private_permissions(&file).unwrap();
        let link = directory.0.join("link");
        symlink(&file, &link).unwrap();
        assert!(private_permissions(&link).is_err());
        assert!(read_bounded(&link, MAX_CONFIG).is_err());
    }

    #[test]
    fn manifests_require_exact_version_paths_hashes_and_bounds() {
        let expected = [
            "nulllobby_0.4.1_amd64.deb".into(),
            "nulllobby_0.4.1_x86_64-unknown-linux-gnu.tar.gz".into(),
        ];
        let good = format!(
            "{}  {}\n{}  {}\n",
            "a".repeat(64),
            expected[0],
            "b".repeat(64),
            expected[1]
        );
        assert_eq!(parse_manifest(good.as_bytes(), &expected).unwrap().len(), 2);
        for bad in [
            good.replace("0.4.1", "0.4.0"),
            good.replace(&expected[0], "../private-file"),
            good.replace(&expected[1], &expected[0]),
            good.replace(&"a".repeat(64), &"a".repeat(40)),
            good.replace(&"a".repeat(64), &"g".repeat(64)),
            good.trim_end().to_owned(),
            format!("{good}extra\n"),
            "a".repeat(MAX_MANIFEST + 1),
        ] {
            assert!(parse_manifest(bad.as_bytes(), &expected).is_err());
        }
    }

    #[test]
    fn returned_artifacts_cannot_choose_output_paths() {
        let signature = b"-----BEGIN PGP SIGNATURE-----\nsynthetic\n";
        let response =
            json!({"filename":"../../credential", "data_base64":STANDARD.encode(signature)});
        assert_eq!(decode_signature(&response).unwrap(), signature);
        for bad in [
            json!({}),
            json!({"data_base64":"%%"}),
            json!({"data_base64":STANDARD.encode(b"-----BEGIN PGP PRIVATE KEY BLOCK-----")}),
            json!({"data_base64":"A".repeat(MAX_KEY + 1)}),
        ] {
            assert!(decode_signature(&bad).is_err());
        }
    }

    #[test]
    fn gpg_status_requires_one_pinned_ed25519_sha256_signature() {
        let fingerprint = "A".repeat(40);
        let good = format!(
            "[GNUPG:] VALIDSIG {fingerprint} 2026-10-03 1791000000 0 4 0 22 8 00 {fingerprint}\n"
        );
        validate_signature_status(&good, &fingerprint).unwrap();
        for bad in [
            good.replace(" 22 8 ", " 22 2 "), // SHA-1 is not an allowed digest.
            good.replace(" 22 8 ", " 1 8 "),  // No RSA fallback.
            good.replace(" 00 ", " 01 "),
            good.replace(&fingerprint, &"B".repeat(40)),
            format!("{good}{good}"),
            "[GNUPG:] GOODSIG short synthetic\n".into(),
            format!("{good}[GNUPG:] EXPKEYSIG expired\n"),
            format!("{good}[GNUPG:] REVKEYSIG revoked\n"),
            format!("{good}[GNUPG:] FAILURE verify\n"),
        ] {
            assert!(validate_signature_status(&bad, &fingerprint).is_err());
        }
    }

    struct FixtureAgent(TemporaryDirectory);
    impl Drop for FixtureAgent {
        fn drop(&mut self) {
            let _ = Command::new("gpgconf")
                .arg("--homedir")
                .arg(&self.0.0)
                .args(["--kill", "gpg-agent"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    fn fixture_signature(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let directory = FixtureAgent(TemporaryDirectory::new().unwrap());
        let run = |args: &[&str]| {
            let result = Command::new("timeout")
                .args([
                    "--signal=KILL",
                    "30s",
                    "gpg",
                    "--no-options",
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--homedir",
                ])
                .arg(&directory.0.0)
                .args(args)
                .current_dir(&directory.0.0)
                .output()
                .unwrap();
            assert!(result.status.success(), "GnuPG signing fixture failed");
            result.stdout
        };
        run(&[
            "--quick-generate-key",
            "NullLobby synthetic release fixture",
            "ed25519",
            "sign",
            "1d",
        ]);
        let public = run(&["--armor", "--export"]);
        fs::write(directory.0.0.join("message"), message).unwrap();
        run(&[
            "--digest-algo",
            "SHA256",
            "--armor",
            "--detach-sign",
            "--output",
            "signature",
            "message",
        ]);
        let signature = fs::read(directory.0.0.join("signature")).unwrap();
        (public, signature)
    }

    #[test]
    fn real_gpg_rejects_tampered_manifests_signatures_and_unrelated_keys() {
        let message = b"synthetic release checksum manifest\n";
        let (public, signature) = fixture_signature(message);
        let verifier = Verifier::new(&public).unwrap();
        verifier.verify(message, &signature).unwrap();
        assert!(
            verifier
                .verify(b"tampered release checksum manifest\n", &signature)
                .is_err()
        );
        let (unrelated, _) = fixture_signature(message);
        let other_verifier = Verifier::new(&unrelated).unwrap();
        assert!(other_verifier.verify(message, &signature).is_err());
        let mut corrupt = signature.clone();
        corrupt[60] ^= 1;
        assert!(verifier.verify(message, &corrupt).is_err());
    }

    #[test]
    fn all_artifact_hashes_are_checked_before_signing() {
        let directory = TemporaryDirectory::new().unwrap();
        for (manifest, package) in MANIFESTS
            .iter()
            .zip(["nulllobby", "nulllobby-arti-experimental"])
        {
            let mut text = String::new();
            for filename in [
                format!("{package}_1.2.3_amd64.deb"),
                format!("{package}_1.2.3_{}.tar.gz", crate::TARGET),
            ] {
                fs::write(directory.0.join(&filename), b"synthetic package").unwrap();
                text.push_str(&format!(
                    "{}  {filename}\n",
                    hex(&Sha256::digest(b"synthetic package"))
                ));
            }
            fs::write(directory.0.join(manifest), text).unwrap();
        }
        checked_manifests(&directory.0, "1.2.3").unwrap();
        fs::write(
            directory.0.join("nulllobby_1.2.3_amd64.deb"),
            b"tampered package",
        )
        .unwrap();
        assert!(checked_manifests(&directory.0, "1.2.3").is_err());
    }
}
