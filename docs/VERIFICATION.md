# Phase 1 verification

Verified locally on Linux x86_64 on 2026-10-03. This is an implementation check, not an independent security audit.

| Check | Result |
|---|---|
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed |
| `cargo test --workspace` | 30 tests passed |
| `cargo audit` (0.22.2) | Passed; no known vulnerabilities reported |
| `cargo deny check` (0.20.2) | Passed; documented `syn` 2/3 duplication warning |
| `make deb` | Built amd64 Debian package, Linux archive and SHA256SUMS |
| Release CLI with `HOME=/proc` | Passed; core-dump prevention and both identity secret locks active on the test host |
| Release binary local path scan | No local source/home paths found in printable strings |

Compiler: rustc 1.94.1. The local distribution supplies rustfmt 1.9.0 and Clippy 0.1.98; CI pins the complete upstream Rust 1.94.1 toolchain for a consistent runner environment. Cargo.lock contains 48 registry packages and six workspace packages, including developer/build/platform dependencies.

Test counts: core 15, Direct codec 3, platform 4, transport 3, CLI integration 2, tooling unit 2, tooling integration 1. Tests cover codec rejection paths, capability/identity separation, full fingerprints, scoped trust, terminal controls, bounded queues, Linux process hardening, panic redaction, unwritable HOME and version changes.

The local package requires `libc6 >= 2.34` and `libgcc-s1`, as determined from the compiled ELF. This can vary by builder. Package contents contain the offline binary and documentation/licenses, without services or application state directories.

Not yet exercised or implemented: network confidentiality, BEP 10 negotiation, Noise identity proofs, wrong-PSK sessions, DHT, real Tor fail-closed behavior, per-lobby onion creation/cleanup, signed gossip/replay, GUI/TUI or cargo-fuzz targets. The mode-policy unit test must not be described as a Tor network integration test. See the roadmap before extending claims.
