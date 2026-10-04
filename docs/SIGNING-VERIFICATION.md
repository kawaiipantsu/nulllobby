# Release signing verification

Reviewed on 2026-10-03 UTC. This records implementation checks, not an independent security audit.

## API and trust boundary

The [XXC developer page](https://ca.xxc.dk/developers) and [OpenAPI specification](https://ca.xxc.dk/assets/openapi.yaml) were inspected before implementation. The API accepted the configured bearer token. A dedicated 365-day Ed25519 release key was enrolled with the approved public project identity. The private key remains in XXC; no private-key export or public-exchange publication was requested.

A fixed enrollment challenge and both original v0.4.1 checksum manifests were signed by the live service and verified locally. The existing release manifests matched the downloaded GitHub assets byte for byte. Signing does not rebuild or modify those binaries. Offline verification also passed with the signing-configuration environment variable pointing to an unavailable path.

The project owner subsequently enabled public-exchange publication. An unauthenticated download from the documented exchange endpoint matched the committed public key byte for byte, including its SHA-256 pin. No local CA token is required to retrieve that public key.

The CA client exists only in Rust `xtask`; it adds no runtime CA request path or shared global identity to the chat application. Its HTTP, JSON, encoding and secret-handling dependencies reuse versions already pinned in the workspace. No new registry package version was selected. Workspace audit/deny checks passed with the existing documented exceptions.

## GnuPG review

The verifier uses the installed, distribution-maintained GnuPG and GNU coreutils `timeout`, rather than bundling them. The local Debian packages tested were `gpg 2.4.7-21+deb13u1+b5` and `gnupg 2.4.7-21+deb13u1`. Keep distribution security updates enabled. Upstream 2.4 support ended in June 2026; using a distribution build depends on its continuing security maintenance. See [upstream maintenance information](https://gnupg.org/blog/20250827-new-repository.html) and [Debian's package tracker](https://security-tracker.debian.org/tracker/source-package/gnupg2).

At review, Debian listed open issues affecting CMS (`gpgsm`), TPM operations and cleartext-signed messages. This integration invokes OpenPGP `gpg` for detached binary-document signatures, disables agent autostart, and uses no CMS, TPM or cleartext-signature path. It checks machine-readable `VALIDSIG` records, signer, algorithm, digest and signature class rather than trusting a human-readable success message. Those scope restrictions are an applicability assessment, not a claim that GnuPG is vulnerability-free. The listed small-input denial-of-service concern is mitigated by input bounds and a 30-second subprocess deadline; time limits do not prove the absence of parser vulnerabilities. Machine-readable fields follow [GnuPG's documented status interface](https://raw.githubusercontent.com/gpg/gnupg/master/doc/DETAILS).

## Tests

- Real GnuPG fixtures accept a valid Ed25519/SHA-256 detached signature and reject changed content, damaged signatures and an unrelated public key.
- Status parsing rejects SHA-1, RSA, unexpected signature class, wrong signer, duplicate signatures and expired/revoked/error reports.
- Every package/archive hash is checked; wrong versions, path traversal, duplicate filenames, malformed hashes and oversized manifests fail before signing.
- Credential parsing rejects unsupported endpoints, header injection and unknown fields without echoing secrets.
- Credential permissions reject public-readable files and symlinks.
- Returned artifact names cannot select local output paths, and malformed/oversized signature envelopes are rejected.
- Formatting and Clippy with all targets/features and warnings denied passed. Full workspace tests passed: 82 default, 86 with all features. Explicit live network tests and screenshot generation remain ignored in those standard suites.

CI repeats the synthetic signing tests without production credentials. A local scan found no production CA token in tracked or non-ignored project files. Only the public release key and its SHA-256 pin are committed. The approved project email is intentionally present in the public OpenPGP identity.

APT publishing was added on 2026-10-04 through the official THUGS(red) archive's scoped management API. It uses a separate pinned archive public key and locally verifies detached `Release.gpg` signatures with `gpgv`, followed by metadata dates, SHA-256 index hashes and downloaded package hashes. Only Ed25519/SHA-256 binary-document signatures from that archive key are accepted. The archive also supplies `InRelease` for ordinary APT clients. See the [APT verification record](wiki/APT.md).

No automatic exchange publication, CA root installation, signing-key revocation/rotation service, GUI certificate feature or organization credential protocol is implemented. See the [release guide](wiki/Release-Signing.md) and [organization identity proposal](ORGANIZATION-IDENTITY.md).
