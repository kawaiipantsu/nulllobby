# Release signing with XXC Trust

NullLobby uses a dedicated Ed25519 OpenPGP release key held by [XXC Trust](https://ca.xxc.dk/developers). Its [documented API](https://ca.xxc.dk/assets/openapi.yaml) supports detached SHA-256 OpenPGP signatures and Debian repository metadata signing. The initial integration signs the two existing checksum manifests; those hashes cover the standard and experimental `.deb` and `.tar.gz` files. Only those public manifests reach the signing service.

This is maintainer tooling in Rust `xtask`. It is not part of the chat client. Noise, private lobby PSKs, per-lobby fingerprints and manual peer verification remain independent of release signing.

Publishing the public key on XXC's exchange is optional. It allows discovery and GPG keyserver retrieval; it also exposes every public user ID and does not independently authenticate the publisher. Release downloads already carry the public key. Enrollment leaves exchange publication disabled. Compare the SHA-256 pin through a trusted channel regardless of where you retrieve the key. See the [implementation and dependency review](https://github.com/kawaiipantsu/nulllobby/blob/main/docs/SIGNING-VERIFICATION.md).

## Published release key

The project owner enabled exchange publication after enrollment. The [public exchange download](https://ca.xxc.dk/api/v1/exchange/keys/7C4F775BBE504B9CC755A1128FB8F0DA9692F8B0/download?format=armor) was checked byte for byte against the committed public-key file.

SHA-256 of the exact armored key file:

```text
4a5a9e840123dc8d1064b09a9b3da1ec1a7a85563e4bc03ed5f958eae7613a7b
```

GnuPG lookup identifier (distinct from the SHA-256 pin): `7C4F775BBE504B9CC755A1128FB8F0DA9692F8B0`.

XXC also documents explicit GPG retrieval through its keyserver:

```sh
gpg --keyserver hkps://ca.xxc.dk --recv-keys 7C4F775BBE504B9CC755A1128FB8F0DA9692F8B0
```

This imports a public key into your chosen GnuPG keyring; it does not mark its identity as trusted. The SHA-256 pin above applies to the downloaded file, including its armor formatting, rather than to a locally reformatted/re-exported key. Verify that pin through an already trusted channel. Automatic keyserver retrieval remains disabled in the release verifier.

## Verify downloads

Install `gnupg`. Obtain `packaging/nulllobby-release-key.asc` and its SHA-256 pin from an already trusted checkout or compare the pin through a trusted project channel. Download the release's packages, archives, `SHA256SUMS`, `SHA256SUMS-arti`, both `.asc` signatures and the public key into `dist/` in a checkout matching the artifact version. Then run:

```sh
make verify-release
```

For v0.4.1, the signing tools were added after the original release tag. Use source commit `89e821c1a4547f52b98d588db2d9e43363078c94` (workspace version 0.4.1) or the manual verification method below; the original v0.4.1 tag has no `verify-release` command.

This command is offline and does not read maintainer credentials. It checks the key against the trusted repository pin, verifies both signatures locally, rejects unexpected signing algorithms and checks all four artifact hashes. The verifier uses a separate temporary GnuPG keyring with automatic key retrieval disabled. It rejects invalid, expired, revoked, duplicate and unexpected signatures. Signature hashing is SHA-256; only Ed25519 release signatures are accepted.

For manual inspection, GnuPG can verify a detached manifest signature with `gpg --verify SHA256SUMS.asc SHA256SUMS` after importing and independently authenticating the project public key into your chosen keyring. Check the artifact hashes with `sha256sum -c SHA256SUMS`; repeat for the experimental manifest. The Rust verifier enforces more policy than this simple manual example.

The `.sha256` file uses SHA-256 over the exact armored public-key file. Legacy OpenPGP v4 fingerprints displayed by GnuPG are protocol lookup identifiers, not the trust anchor. They are unrelated to NullLobby lobby fingerprints. A public key and checksum downloaded from the same compromised source would not independently identify the publisher. Establish the initial pin separately, and review changes to it.

Detached signatures are **not automatically checked by `apt install ./file.deb`**. Verify before installation. An APT repository would need `Packages`/`Release` metadata and signed `InRelease` or `Release.gpg`; this project does not create or advertise an APT repository yet. See [Debian's apt-secure documentation](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html).

## Maintainer configuration

Use `$XDG_CONFIG_HOME/xxc-ca/nulllobby-release.toml`, falling back to `$HOME/.config/xxc-ca/nulllobby-release.toml`. `NULLLOBBY_SIGNING_CONFIG` can explicitly select another external file. The directory must be owned by the invoking account with mode 0700; the file must be account-owned with mode 0600. Final file/directory symlinks and credentials stored inside the repository are rejected. Do not copy real tokens into documentation, shell command lines, GitHub artifacts or the client settings.

The file contains `api_base` set to `https://ca.xxc.dk/api/v1`, `api_token`, and the selected `key_id`. First enrollment also needs an approved `signing_email`; that email becomes public in the release key. The key ID and API token remain local. Parse and HTTP errors withhold credentials and API response bodies. Secret wrappers reduce accidental exposure; they do not guarantee erasure of every parser/HTTP-library memory copy.

```sh
make ca-status
make ca-enroll       # explicit first enrollment only
```

Enrollment creates a 365-day Ed25519 project key and verifies a fixed enrollment signature with local GnuPG. It writes only the public key and SHA-256 pin into `packaging/`. Review those files and commit them before releasing. It does not download private keys or publish the key in XXC's public exchange. The service stores the release private key; this is separate from the application's RAM-only lobby identities.

Enrollment requires `openpgp.read` and `openpgp.manage`, and its proof signature requires `openpgp.sign`. Routine signing needs `openpgp.read` and `openpgp.sign`. Prefer a separate narrowly scoped signing token after enrollment. Do not grant export, decrypt, publish or administration permissions solely for releases.

Enrollment never runs implicitly during signing. If it fails after the server creates a key, inspect XXC and recover the existing key/configuration deliberately. Do not repeatedly create replacement identities. An existing project key or local pin makes enrollment stop.

## Sign and release

```sh
make deb
make deb-arti
make sign-release
make verify-release
```

`sign-release` requires both manifests to contain exactly the expected versioned filenames and SHA-256 hashes. It verifies each local artifact before requesting signatures and again before writing outputs. The service's response filenames are ignored. The tool sends HTTPS only to the reviewed XXC host, disables redirects/environment proxies, and bounds request time, response size and local verification time. No failure changes transport or permits an unsigned result.

After a reviewed version bump, commit and push, `make release` (or its `make release-signed` alias) performs checks, builds both variants, signs them and attaches ten files to a draft release. It checks local signing configuration before starting the builds. `make release-unsigned` is the separate unsigned workflow; it does not silently take over when signing fails. Publication remains explicit. CI checks the signer with synthetic keys and never receives the production token.

For an existing release, verify that local package/archive checksums exactly match the already published assets, sign those same manifests and upload only the four new signing artifacts. Do not rebuild or replace existing release binaries just to add signatures. Record the later signing date in the release notes.

## Trust, expiry and rotation

XXC administrators and holders of a signing-capable token can produce release signatures. Compromise of either is a release-authenticity risk. The service also observes the maintainer's network address, request timing and public artifact hashes. No chat, lobby secrets, ephemeral identities or trust lists are submitted.

Track the one-year signing-key expiry. Rotation is a reviewed change to the public key and SHA-256 pin, plus the external key ID. Publish the new pin through an existing trusted channel; when appropriate, sign the transition with both old and new keys. Stop releases on unexpected key changes.

If compromised, revoke the API token, revoke the signing key using XXC's supported revocation workflow, investigate affected releases and publish a security notice through trusted channels. Do not rely on an attacker-controlled old key alone to authenticate its replacement. Offline verification cannot discover a newly published revocation until operators update their trusted key material. It also does not prevent rollback to an older valid release or prove build reproducibility or source safety.
