# Building and publishing releases

All project helper logic is Rust in `xtask`. Make is a command shortcut. Phase 1 packages are offline diagnostics; release titles/notes must keep that limitation visible.

## Local build and packages

```sh
make check
make deb
```

Outputs for version 0.1.0:

```text
dist/nulllobby_0.1.0_amd64.deb
dist/nulllobby_0.1.0_x86_64-unknown-linux-gnu.tar.gz
dist/SHA256SUMS
```

Packaging builds the locked Linux target, derives the glibc requirement from ELF symbol versions, adds `libgcc-s1`, and includes project/dependency license notices. It fails if a dependency notice cannot be found. Cargo may download missing source packages for these notices. The maintainer field uses the project name, not personal contact information. These are standalone developer packages; Debian archive submission would require its additional policy/maintainer review.

The package stage lives under `target/debian-stage`. No package is installed automatically. No post-install scripts, daemon, account or application state are added. Archives normalize owners/order/timestamps, but fully reproducible builds across different toolchains/distributions are not claimed. Use a consistent builder to compare artifacts.

## Version bumps

```sh
make bump-patch  # 0.1.0 -> 0.1.1
make bump-minor  # 0.1.0 -> 0.2.0
make bump-major  # 0.1.0 -> 1.0.0
```

Choose **one** command per intended bump. It updates `[workspace.package].version`, exact internal workspace dependency versions and every workspace package version in Cargo.lock. It does not change registry dependency versions, commit, tag or publish. Lower version components reset for major/minor; invalid levels/overflow fail.

Review the diff, update `docs/RELEASE-NOTES.md`, run checks, commit using your configured global Git identity and push to `main`. The CLI version and artifact filenames follow the workspace version automatically.

## Draft a GitHub release

Prerequisites: authenticated `gh` with repository release permission, a clean tree, all required security tools, and local HEAD equal to published `origin/main`.

```sh
make release
```

This reruns all checks, builds packages and creates a **draft** `v<version>` release targeted at the exact published commit. It attaches `.deb`, `.tar.gz` and checksums, using `docs/RELEASE-NOTES.md` without shell interpolation. A duplicate tag/release fails through GitHub instead of overwriting it.

Review the draft's scope and artifacts in GitHub, then publish it. This is an explicit maintainer action; building or bumping never publishes automatically.

## Discussion notification

The `release-notification.yml` workflow runs on a published release, with `discussions: write` and `contents: read`. Rust tooling validates the tag, refuses a draft release, discovers the Announcements category and posts a link plus release notes. It checks the latest 100 Discussions for the same title before posting to reduce rerun duplicates; this is not a cross-process atomic deduplication guarantee.

Manual recovery after an unsuccessful workflow:

```sh
cargo xtask announce v0.1.0
```

Run from the checked-out release commit with authenticated `gh`. Release-body data is passed as structured command arguments, not shell code. Do not put secrets into release notes, source fixtures or package metadata. Changing feature maturity requires updating the notes before the release.

## Wiki maintenance

The source is `docs/wiki/`. Review changes in the main repository, copy those Markdown pages into the `nulllobby.wiki.git` checkout, commit using the existing global Git identity and push. Do not overwrite unrelated wiki pages. Wiki synchronization is separate from publishing an application release.
