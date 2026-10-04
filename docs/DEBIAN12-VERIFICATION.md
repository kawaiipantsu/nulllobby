# Debian 12 compatibility verification — 0.5.1

Checked on 2026-10-04. Source: `9ab971cb52ce5126d01aa8f08f0de0e2a35710a8`.

## Build baseline

Debian 12 ships [glibc 2.36](https://packages.debian.org/bookworm/libc6). Both amd64 package variants and Linux archives were built with Rust 1.94.1 inside:

```text
rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55
```

The old 0.5.0 binary referenced weak `pidfd_spawnp` and `pidfd_getpid` symbols with glibc 2.39 version requirements. Rebuilding against Debian 12 removes those version requirements. Both new binaries have a highest ELF glibc requirement of 2.34; package metadata deliberately declares the tested baseline `libc6 (>= 2.36)`. Packaging rejects any requirement above 2.36, including weak requirements. Invoking native packaging on the glibc 2.41 host failed before building, as intended; there is no host-build fallback.

No application dependency version, protocol, invitation format or encryption suite changed. The version bump updates workspace packages in both lockfiles. 0.5.0 artifacts remain unchanged; 0.5.0 and 0.5.1 participants use the same protocol/card v2.

## Completed checks

- Formatting, all-target/all-feature Clippy with warnings denied, default and all-feature workspace tests passed.
- Cargo audit and cargo deny passed under the existing documented dependency exceptions; no new exception was introduced.
- Tests cover rejection of newer/weak glibc requirements, numeric version ordering, missing ELF information and Docker mount-option injection through paths.
- Standard and experimental packages installed independently in clean Debian 12 containers. Their version and offline diagnostics passed with `HOME=/proc`; core-dump prevention and both tested secret memory locks reported active.
- Extracted binaries also passed offline diagnostics on the newer glibc 2.41 host.
- Both checksum manifests were signed through XXC and verified offline. All ten GitHub assets were downloaded and matched the local signed release before publication.
- The APT publisher verified GitHub digests, staged only the two 0.5.1 packages, published them to `zerotrust` and verified signed public metadata and package bytes. A separate `make apt-verify` passed.
- Two fresh Debian 12 containers then installed the standard and experimental packages **by package name from the public APT repository**, using its pinned archive key and `Signed-By`. APT selected 0.5.1; each downloaded `.deb` matched the signed release before installation. Both installed binaries passed version and offline diagnostics, including with an unwritable HOME.
- The release Discussion workflow succeeded. Credentials and the private publishing endpoint remained outside project files and artifacts.

The runtime image was:

```text
debian:12-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
```

APT used Debian 12's `libc6 2.36-9+deb12u14`; the experimental package used `libsqlite3-0 3.40.1-2+deb12u2`.

| Debian package | SHA-256 |
| --- | --- |
| `nulllobby_0.5.1_amd64.deb` | `c8f567637c1a609aed60e671a15fcb35198b2ef558aa93ae97c7a32821656976` |
| `nulllobby-arti-experimental_0.5.1_amd64.deb` | `0584818d41a3b366f9ff36514fe517b2898cffe7d9c9bdcf4a57c278612303e1` |

## Scope

Containers exercise Debian 12 userspace while sharing the host kernel. This is not a test of a separate Debian 12 VM, a physical Debian 12 host, its terminal/fonts, or its system Tor/keyring configuration. The project owner will test on their Debian 12 host. Live public Tor/DHT and remote sandbox tests were not repeated for this packaging-only change. The normal CI now runs inside pinned Debian 12 userspace and installs both package variants; see the [release-commit CI run](https://github.com/kawaiipantsu/nulllobby/actions/runs/37185946374) for its result. No independent professional security audit has been completed.
