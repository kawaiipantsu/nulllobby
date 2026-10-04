# Building and publishing releases

All project helper logic is Rust in `xtask`. Make is a command shortcut. The standard Linux package includes external Tor support. `make deb-arti` builds a separate experimental embedded-Arti package, with its full dependency notices and advisory review. Release notes retain the unaudited and experimental status; desktop clients are deferred.

## Local build and packages

```sh
make check
make deb
```

Outputs for version 0.4.2:

```text
dist/nulllobby_0.4.2_amd64.deb
dist/nulllobby_0.4.2_x86_64-unknown-linux-gnu.tar.gz
dist/SHA256SUMS
```

Packaging builds the locked Linux target, derives the glibc requirement from ELF symbol versions, adds `libgcc-s1`, and includes project/dependency license notices. It fails if a dependency notice cannot be found. Cargo may download missing source packages for these notices. The maintainer field uses the project name, not personal contact information. These are standalone developer packages; Debian archive submission would require its additional policy/maintainer review.

The package stage lives under `target/debian-stage`. No package is installed automatically. No post-install scripts, daemon, account or application state are added. Archives normalize owners/order/timestamps, but fully reproducible builds across different toolchains/distributions are not claimed. Use a consistent builder to compare artifacts.

Install or upgrade the standard package locally:

```sh
sudo apt install ./dist/nulllobby_0.4.2_amd64.deb
nulllobby --version
nulllobby --self-check
```

The experimental package conflicts with the standard package because both install `/usr/bin/nulllobby`. Choose the standard package unless you explicitly want to evaluate embedded Arti. Installing a package does not launch the client or change the system Tor configuration.

## Version bumps

```sh
make bump-patch  # 0.4.2 -> 0.4.3
make bump-minor  # 0.4.2 -> 0.5.0
make bump-major  # 0.4.2 -> 1.0.0
```

Choose **one** command per intended bump. It updates `[workspace.package].version`, exact internal workspace dependency versions and workspace package versions in Cargo.lock and fuzz/Cargo.lock. Vendored upstream and fuzz-harness package versions are preserved. It does not change registry dependency versions, commit, tag or publish. Lower version components reset for major/minor; invalid levels/overflow fail.

Review the diff, update `docs/RELEASE-NOTES.md`, run checks, commit using your configured global Git identity and push to `main`. The CLI version and artifact filenames follow the workspace version automatically.

## Draft a GitHub release

Prerequisites: authenticated `gh` with repository release permission, a clean tree, all required security tools, and local HEAD equal to published `origin/main`.

```sh
make release-signed
```

This reruns all checks, builds packages, signs the checksum manifests through XXC Trust and creates a **draft** `v<version>` release targeted at the exact published commit. It attaches standard and separately named experimental-Arti `.deb`/`.tar.gz` artifacts, separate checksum files, detached signatures and the public verification key. See [Release signing](Release-Signing) for the one-time maintainer setup and offline verification. Signing failure stops the release; there is no unsigned fallback. `make release` also requires signing. `make release-unsigned` is the separate, explicitly unsigned draft workflow.

Both workflows use `docs/RELEASE-NOTES.md` without shell interpolation. A duplicate tag/release fails through GitHub instead of overwriting it. Signing runs only in maintainer tooling; running chat never contacts the CA.

Review the draft's scope and artifacts in GitHub, then publish it. This is an explicit maintainer action; building or bumping never publishes automatically.

## Publish Debian packages to APT

The official public archive is `https://apt.thugs.red/repo`, suite `zerotrust`. After GitHub publication, run `make apt-publish` on the authorized maintainer host with the original signed release artifacts in `dist/`. It verifies GitHub asset hashes, uploads and stages both variants, reviews the suite diff and publishes through the scoped API. Then it verifies signed archive metadata and public package downloads. `make apt-verify` repeats that public check without maintainer credentials.

See [APT setup and publishing](APT) for the separate archive key, restricted external configuration, required token scopes and recovery rules. Keep the private API address and credentials outside Git. Do not rebuild an existing release merely to publish it to APT.

## Discussion notification

The `release-notification.yml` workflow runs on a published release, with `discussions: write` and `contents: read`. Rust tooling validates the tag, refuses a draft release, discovers the Announcements category and posts a link plus release notes. It checks the latest 100 Discussions for the same title before posting to reduce rerun duplicates; this is not a cross-process atomic deduplication guarantee.

Manual recovery after an unsuccessful workflow:

```sh
cargo xtask announce v0.4.2
```

Run from the checked-out release commit with authenticated `gh`. Release-body data is passed as structured command arguments, not shell code. Do not put secrets into release notes, source fixtures or package metadata. Changing feature maturity requires updating the notes before the release.

## Wiki maintenance

The source is `docs/wiki/`. Review changes in the main repository, copy those Markdown pages into the `nulllobby.wiki.git` checkout, commit using the existing global Git identity and push. Do not overwrite unrelated wiki pages. Wiki synchronization is separate from publishing an application release.
