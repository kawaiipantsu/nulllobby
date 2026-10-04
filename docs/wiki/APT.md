# Official APT repository

NullLobby Debian packages are published in the public [THUGS(red) APT repository](https://apt.thugs.red), suite **zerotrust**, component **main**. Version **0.5.3** is available for **amd64** in two variants:

| Package | Tor backend |
| --- | --- |
| `nulllobby` | External/system Tor; recommended default |
| `nulllobby-arti-experimental` | External Tor plus experimental embedded Arti |

Choose one variant; both install `/usr/bin/nulllobby` and conflict with each other. Starting with 0.5.1, both variants target Debian 12 and newer with `libc6 (>= 2.36)`, using a pinned Debian 12 builder and an ELF compatibility check. Earlier releases, including 0.5.0, require glibc 2.39. There is no need to upgrade or replace Debian 12's system libc. The repository also supports arm64, but NullLobby has no arm64 release package yet. No independent professional security audit has been completed.

**Upgrading from 0.4.x:** upgrade every lobby participant and distribute fresh v2 invitation cards. Older cards and peers are rejected. Identity persistence, durable delivery and peer mailboxes remain separate opt-in choices; installing the package enables none of them.

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

### 0.5.3 — Live DHT header

The Direct header now reports bootstrap, querying, ready, retry and disabled states without repeatedly opening `/network`. Counts update while requests are pending, reset per round and follow the selected lobby. See [connectivity](Connectivity) and the [synthetic renderer screenshot](Screenshots#live-direct-discovery).

Formatting, all-target/all-feature Clippy with warnings denied, workspace tests (115 default; 119 all-feature), audit and deny passed locally. Tests hold an announcement reply pending to verify intermediate updates, then verify completion, round resets, narrow header layouts, lobby switching and Tor separation. Existing dependency exceptions remain unchanged. The independent [CI run](https://github.com/kawaiipantsu/nulllobby/actions/runs/37213969608) records hosted checks.

Both variants were built in pinned Debian 12 userspace, installed separately in clean Debian 12 containers and passed offline diagnostics. Signed GitHub assets were downloaded and verified before publishing the exact two packages to `zerotrust`. Public signed metadata and both package bytes were checked by the publisher and a separate `apt-verify`. A clean Debian 12 container also installed the standard variant by name from the public APT repository and compared its download with the signed original.

The maintainer host upgraded the standard package from 0.5.2 to 0.5.3 through APT without adding or removing other packages. Its installed executable matched the signed package; version and offline checks passed. Restart running clients to load the new header. Protocol/card v2 remains compatible with 0.5.0–0.5.2.

| Package | SHA-256 |
| --- | --- |
| `nulllobby_0.5.3_amd64.deb` | `d4f2953032e7314e2845a3064ce3c64d2bc1cd066f969affa5034a048e55ab2c` |
| `nulllobby-arti-experimental_0.5.3_amd64.deb` | `62cb2350667131923a654c8215e5d2da9fefda7ff6ecec865f2ca6cc591b9f9a` |

### 0.5.2 — Direct discovery

On 2026-10-04, both variants were built in pinned Debian 12 userspace, signed through XXC Trust, downloaded from the GitHub release and independently verified. The APT publisher reviewed exactly two package additions, published to `zerotrust`, and verified signed public metadata plus exact package bytes. A separate `apt-verify` passed.

Two clean Debian 12 containers installed the respective variants by name from the public APT repository. Both downloads matched the signed release, and installed version/offline diagnostics passed with glibc 2.36. The maintainer host upgraded the standard package from 0.5.0 to 0.5.2 through APT without adding or removing other packages; its installed binary matched the signed package and diagnostics passed.

This patch fixes default seedless Direct invitation discovery and adds F5/`/network` diagnostics. See [connectivity](Connectivity) and the [regression evidence](https://github.com/kawaiipantsu/nulllobby/blob/main/docs/DIRECT-DISCOVERY-VERIFICATION.md). Protocol/card v2 remains compatible with 0.5.0/0.5.1. Restart running processes after upgrading; ephemeral sessions need a newly created lobby and invitation.

| Package | SHA-256 |
| --- | --- |
| `nulllobby_0.5.2_amd64.deb` | `5bf5242c7901815ff82e74b0d15b0c16e3ca89da80cd50244713a22d289c7e31` |
| `nulllobby-arti-experimental_0.5.2_amd64.deb` | `3c398b833f101423e5d08f1876038ad5006d6c10645c278eadf06f28fb1dd8d9` |

### 0.5.1 — Debian 12

On 2026-10-04, both variants were rebuilt with pinned Rust 1.94.1 and Debian 12 userspace. Their highest ELF glibc requirement is 2.34; package metadata declares the tested baseline `libc6 (>= 2.36)`. The signed GitHub artifacts were verified after downloading, then the exact packages were published to `zerotrust`. Public archive verification passed.

Two clean Debian 12 containers installed the variants independently by name from `apt.thugs.red`, using the pinned archive key and `Signed-By`. Each APT download matched the signed release before installation. Both installed versions and offline diagnostics passed with glibc 2.36, including `HOME=/proc`. Containers share the host kernel; a separate Debian 12 host test remains with the project owner. See the [full build and verification record](https://github.com/kawaiipantsu/nulllobby/blob/main/docs/DEBIAN12-VERIFICATION.md).

0.5.1 uses the same protocol/card v2 as 0.5.0. Upgrading between those versions does not require exchanging new invitation cards. Earlier published packages remain unchanged.

### 0.5.0

On 2026-10-04, both 0.5.0 variants were signed through XXC Trust, verified locally, downloaded from GitHub and checked again before publication. The APT publisher verified their GitHub digests, staged only these two versions and published them to `zerotrust`. Signed public archive metadata and both public downloads matched the signed release bytes. A separate `make apt-verify` passed.

The local host was configured with the pinned archive key and repository-specific `Signed-By`. APT accepted `InRelease`, selected 0.5.0 from the public repository and downloaded the standard package. Its bytes matched the signed release before installation. APT upgraded the installed standard package from 0.4.2 to 0.5.0 without adding or removing other packages. The installed executable matched the signed package; version and offline diagnostics passed, including with `HOME=/proc`. Core-dump prevention and both tested secret memory locks reported active.

SHA-256 of the published Debian packages:

| Package | SHA-256 |
| --- | --- |
| `nulllobby_0.5.0_amd64.deb` | `95b6ba6c239fc7bce337f2fec0ca2a9fe7c5cc9be55c28d13a526fb84cf6d8ef` |
| `nulllobby-arti-experimental_0.5.0_amd64.deb` | `accf9e6021069473352a0af0cacf0ad156ce4f0d12cf234744d9355ed8f429f8` |

### 0.4.2

On 2026-10-04, both 0.4.2 variants were published through the scoped API. Public downloads matched their GitHub release hashes. A separate APT run with an isolated source list, keyring, package lists and cache accepted `InRelease`, selected both 0.4.2 candidates and downloaded both packages with matching hashes. This check did not modify the host's system APT sources or installed packages. A repeated publisher run made no repository changes.

Nine new tests cover publication review, version conflicts, GitHub asset hashes, private HTTP opt-in, credential permissions, metadata expiry and parser limits. Formatting, Clippy with all targets/features and warnings denied, workspace tests (91 default; 95 with all features), `cargo audit` and `cargo deny check` passed. Audit/deny retain the existing documented dependency exceptions. A local scan found no production publishing/signing token or private management address in tracked or non-ignored project files.
