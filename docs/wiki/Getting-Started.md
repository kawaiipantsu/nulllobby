# Getting started

## Requirements

- Linux x86_64, glibc and a C linker; initial target `x86_64-unknown-linux-gnu`.
- Rust 1.94 or later with Cargo, rustfmt and Clippy. CI pins 1.94.1.
- GNU Make for shortcuts. Every helper implementation is Rust in `xtask`.
- For Debian packages: `dpkg-deb`, `dpkg`, GNU `tar`, and `readelf` from binutils.
- Git and GitHub CLI only for repository/release tasks. No account is needed to run diagnostics.

On Debian/Ubuntu, install distribution build tools using your normal package manager. Obtain a compatible Rust toolchain from a trusted source; no installer is bundled or executed by the application. No Python is used by this project.

## Build from source

```sh
git clone https://github.com/kawaiipantsu/nulllobby.git
cd nulllobby
make build
make test
```

The Makefile delegates to Rust `xtask`. `make build` uses the locked dependency graph and release settings and remaps source/cache paths in compiled output. Direct Cargo equivalent, without automatic path remapping:

```sh
cargo build --locked --release --target x86_64-unknown-linux-gnu -p nulllobby-cli
```

No private key, invite or application state is needed to build. Cargo's package cache and compiled artifacts are developer files, not application state.

## Run diagnostics

```sh
./target/x86_64-unknown-linux-gnu/release/nulllobby --help
./target/x86_64-unknown-linux-gnu/release/nulllobby --version
./target/x86_64-unknown-linux-gnu/release/nulllobby --about
./target/x86_64-unknown-linux-gnu/release/nulllobby --security
./target/x86_64-unknown-linux-gnu/release/nulllobby --self-check
```

`--security` and `--self-check` disable core dumps, create temporary secret material and report per-allocation lock status. They do not reveal identities, invites or private material. `Network: inactive` and `Noise: not implemented` are intentional.

There is no chat prompt yet. `--listen`, `--peer`, `--tor-socks`, `--tor-control`, `/join`, `/invite` and other chat commands are planned, not accepted arguments in Phase 1.

An unwritable HOME is supported by the offline binary:

```sh
env HOME=/proc ./target/x86_64-unknown-linux-gnu/release/nulllobby --self-check
```

Later Direct networking must retain this property; its runtime test is deferred until that backend exists.

## Debian package

```sh
make deb
dpkg-deb --info dist/nulllobby_0.1.0_amd64.deb
sudo apt install ./dist/nulllobby_0.1.0_amd64.deb
nulllobby --security
```

Replace `0.1.0` with the workspace version after a bump. Installation is optional. Packages install `/usr/bin/nulllobby` and `/usr/share/doc/nulllobby/`; they add no service, user account or state directory. The package contains an offline diagnostic executable, not a usable chat client.

`dist/SHA256SUMS` covers the `.deb` and `.tar.gz`. SHA-256 checksums detect corruption but do not authenticate a download against a compromised release account. Signed provenance is future work. Build from the reviewed source when appropriate.

## Troubleshooting

| Symptom | Action |
|---|---|
| Rust is too old | Install Rust 1.94 or later; use CI's pinned version to reproduce its checks |
| `mlock` reports `Failed` | Inspect your service/container locked-memory limit. Do not assume keys are locked; the allocation still zeroizes on drop |
| Core-dump prevention fails | Diagnostics refuse to create secrets. Check OS/container syscall restrictions |
| Package needs a newer libc | Build it on the oldest glibc distribution you intend to support |
| Missing dependency license text | Packaging stops for review. Do not remove the license gate |
| `cargo audit` or `cargo deny` unavailable | Install the versions listed in the repository README |
| No chat/Tor commands | Expected in Phase 1; see the roadmap |

Do not include personal environment details or actual application secrets in bug reports. Error output deliberately omits unsupported argument values and panic payloads.
