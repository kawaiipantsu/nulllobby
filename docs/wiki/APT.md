# Official APT repository

NullLobby Debian packages are published in the public [THUGS(red) APT repository](https://apt.thugs.red), suite **zerotrust**, component **main**. Version **0.4.2** is available for **amd64** in two variants:

| Package | Tor backend |
| --- | --- |
| `nulllobby` | External/system Tor; recommended default |
| `nulllobby-arti-experimental` | External Tor plus experimental embedded Arti |

Choose one variant; both install `/usr/bin/nulllobby` and conflict with each other. These packages require glibc 2.39 or newer. Debian 13 and Ubuntu 24.04 meet that requirement; Debian 12 does not. The repository also supports arm64, but NullLobby has no arm64 release package yet. No independent professional security audit has been completed.

## Install

No API key is needed to install or update packages. The archive has its own signing key, separate from the NullLobby release key and all lobby identities.

Archive public-key file SHA-256:

```text
026dd9704f4c3c51dc060e39d2834e81d21bf25f71e6ac943061ac2b4c2c1019
```

OpenPGP lookup fingerprint:

```text
FAE8 475A 738B E765 6B25 50A4 21A7 B0A5 B357 9EE0
```

Compare the SHA-256 pin through an already trusted project channel. A pin downloaded alongside a key does not independently authenticate it. The commands below use a repository-specific keyring and `Signed-By`; they do not grant global APT trust.

```sh
(
set -eu
nulllobby_apt_dir="$(mktemp -d)"
trap 'rm -rf "$nulllobby_apt_dir"' EXIT
curl --fail --silent --show-error --proto '=https' \
  https://apt.thugs.red/repo/thugsred-archive-keyring.gpg \
  -o "$nulllobby_apt_dir/keyring.gpg"
printf '026dd9704f4c3c51dc060e39d2834e81d21bf25f71e6ac943061ac2b4c2c1019  %s\n' \
  "$nulllobby_apt_dir/keyring.gpg" | sha256sum --check -
sudo install -d -m 0755 /usr/share/keyrings
sudo install -m 0644 "$nulllobby_apt_dir/keyring.gpg" \
  /usr/share/keyrings/thugsred-archive-keyring.gpg
printf '%s\n' \
  'Types: deb' \
  'URIs: https://apt.thugs.red/repo' \
  'Suites: zerotrust' \
  'Components: main' \
  'Architectures: amd64' \
  'Signed-By: /usr/share/keyrings/thugsred-archive-keyring.gpg' \
  > "$nulllobby_apt_dir/thugsred.sources"
sudo install -m 0644 "$nulllobby_apt_dir/thugsred.sources" \
  /etc/apt/sources.list.d/thugsred.sources
sudo apt update
sudo apt install nulllobby
)
nulllobby --version
nulllobby --self-check
```

If the THUGS(red) repository is already configured, use `sudo apt update` and `sudo apt install nulllobby`. Do not add duplicate source entries. Standard system upgrades will then include NullLobby updates. To evaluate the experimental variant, explicitly install `nulllobby-arti-experimental` instead.

APT verifies signed repository metadata and package hashes. Detached GitHub checksum signatures remain useful for standalone downloads, but `apt install ./file.deb` does not automatically check them. See [Release signing](Release-Signing).

## Maintainer publishing

The Rust `xtask` implements the [XXC-APTD publishing API](https://apt.thugs.red/api/openapi.json). The public website serves API documentation; the publishing API may have a separate private address. Obtain its actual base URL from the repository operator. Do not assume the example `/admin` URL in OpenAPI is reachable.

Store configuration outside the checkout at `$XDG_CONFIG_HOME/xxc-aptd/nulllobby.toml`, falling back to `$HOME/.config/xxc-aptd/nulllobby.toml`. `NULLLOBBY_APT_CONFIG` can select another external file. Use an account-owned directory with mode 0700 and an account-owned file with mode 0600. Final file/directory symlinks and files inside the repository are rejected.

The configuration fields are:

- `api_base`: the operator-supplied API URL, ending in `/api/v1`.
- `suite`: `zerotrust`.
- `api_token`: the scoped project token, entered locally without including it in shell arguments, Git, documentation or client settings.
- `allow_private_http`: defaults to `false`. An operator-authorized plain HTTP endpoint requires explicit `true` and a numeric RFC 1918 IPv4 destination. **HTTP sends the bearer credential without transport encryption.** Use it only on the operator's trusted management network; prefer HTTPS or an authenticated tunnel where available. There is no automatic HTTP fallback.

The private API address and token remain local. Public archive downloads always use HTTPS. Redirects and environment proxies are disabled for API requests; responses, file sizes and request time are bounded. API errors withhold response bodies and credentials. Secret wrappers cannot erase every temporary parser or HTTP-library memory copy.

The token needs `read`, `upload`, `stage` and `publish` scopes for `zerotrust`. The publisher sends that suite explicitly on every request. It does not need repository administration, token management, deletion or signing-key export permission. The archive service manages its signing key; the client never obtains a private archive key.

After publishing the reviewed, signed GitHub release, keep its original artifacts and signatures in `dist/` in a checkout with the matching workspace version:

```sh
make apt-status
make apt-publish
make apt-verify
```

The tools require Linux, GnuPG (`gpg` and `gpgv`), GNU coreutils (`date` and `timeout`), `dpkg-deb`, and the build toolchain. No new Rust dependency version was added for APT support.

`apt-publish`:

1. Verifies both signed checksum manifests and all four original release artifacts offline.
2. Requires a published, non-prerelease GitHub release with matching Debian asset hashes.
3. Verifies the existing archive metadata using the pinned archive public key and checks for conflicting published versions.
4. Uploads the two `.deb` files as raw binary bodies, validates the returned metadata and stages the exact uploads.
5. Reviews the shared suite diff. Unrelated additions/upgrades, removals, downgrades, mismatched hashes/sizes or unexpected architectures stop publication. Already staged matching additions can be resumed.
6. Publishes using the server's review token, then polls the returned job for at most five minutes.
7. Verifies public `Release.gpg`, the metadata dates, the SHA-256 package index fetched by hash, and both downloaded packages against the original signed release bytes.

Repeating a successful publication verifies the existing packages without changing the repository. A published version with different bytes is rejected. On a stale review, timeout or failed job, inspect repository state before retrying. The tool never removes someone else's staged work or rolls the archive back to recover. An upload interrupted before staging may require operator inspection of the upload list.

`apt-verify` reads no maintainer credentials and makes no management API calls. It verifies public metadata and downloads against the signed artifacts in `dist/`. It requires current, unexpired archive metadata; refresh/archive key rotation remains the repository operator's responsibility. The pinned key and its SHA-256 constant must be reviewed when the archive key changes.

CI tests use synthetic credentials and signatures. Production APT credentials are not uploaded to GitHub. Publication runs from the authorized maintainer host, where the private management endpoint is reachable; GitHub-hosted runners are not assumed to have that access.

## Verification record

On 2026-10-04, both 0.4.2 variants were published through the scoped API. Public downloads matched their GitHub release hashes. A separate APT run with an isolated source list, keyring, package lists and cache accepted `InRelease`, selected both 0.4.2 candidates and downloaded both packages with matching hashes. This check did not modify the host's system APT sources or installed packages. A repeated publisher run made no repository changes.

Nine new tests cover publication review, version conflicts, GitHub asset hashes, private HTTP opt-in, credential permissions, metadata expiry and parser limits. Formatting, Clippy with all targets/features and warnings denied, workspace tests (91 default; 95 with all features), `cargo audit` and `cargo deny check` passed. Audit/deny retain the existing documented dependency exceptions. A local scan found no production publishing/signing token or private management address in tracked or non-ignored project files.
