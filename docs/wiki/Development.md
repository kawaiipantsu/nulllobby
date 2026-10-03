# Development and verification

All application/helper/test/fuzz code is Rust. No Python is used. Required stable toolchain: Rust 1.94 or later. `Cargo.lock` pins the application graph; `fuzz/Cargo.lock` pins the separate fuzz graph.

## Gates

```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo audit
cargo deny check
```

`make check` runs these through Rust xtask. CI also builds the Debian package and runs offline diagnostics with an unwritable HOME. A runtime integration test runs three Direct clients with HOME pointing at `/proc`.

Integration tests use actual localhost TCP for BitTorrent/BEP 10/Noise/proof, signed gossip and scoped trust. Captured bytes must contain neither chat plaintext nor identity public keys. Tor tests emulate supported local control/SOCKS protocols with SAFECOOKIE verification, distinct service endpoints, isolation values and service cleanup. Network instrumentation rejects Direct/DHT/DNS operations under Tor. Wrong PSKs and proof/key/transcript mismatches never produce a usable session.

A separate opt-in test uses a real external Tor daemon; see [Tor](Tor.md). Another opt-in test contacts public DHT and exposes the test machine's IP:

```sh
cargo test -p nulllobby-direct --test live_dht -- --ignored
```

Normal CI does not depend on public Tor or DHT availability.

## Fuzzing

Install a Rust nightly and cargo-fuzz:

```sh
rustup toolchain install nightly-2026-10-03 --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
NULLLOBBY_FUZZ_TOOLCHAIN=nightly-2026-10-03 make fuzz-smoke
```

Nine libFuzzer targets exercise BitTorrent handshake, BEP 10, DHT bencode, cards, private invite text, Noise outer framing, canonical application messages, endpoints and terminal sanitation. The smoke task gives each target ten seconds, caps input length at 65536 and memory at 512 MiB. Longer campaigns should include valid canonical seeds and targeted mutations, particularly for checksummed/signed structures; random input alone reaches only a subset of semantic paths.

```sh
cargo +nightly-2026-10-03 fuzz run application -- -max_total_time=3600 -max_len=65536
```

Corpora, artifacts and coverage are ignored by Git. Do not use operational chat, production invitations or real identities as fuzz seeds. Fuzzing supplements semantic regression tests; it is not a proof of parser correctness.

## Review expectations

- Preserve Tor fail-closed selection and per-lobby identity/endpoint separation.
- Bound before allocation; use checked lengths and bounded queues.
- Never log packet contents, invites, credentials or keys; error strings describe categories only.
- Keep all necessary unsafe code inside the platform FFI boundary.
- Review current crate APIs and RustSec before upgrades. Do not guess protocol or library method names.
- Re-run relevant regressions when changing cryptography, persistence, state ownership or parser limits.
- Do not claim an independent audit based on local tests, cargo audit or this implementation review.

See [verification results](https://github.com/kawaiipantsu/nulllobby/blob/main/docs/VERIFICATION.md), [dependency review](https://github.com/kawaiipantsu/nulllobby/blob/main/docs/DEPENDENCIES.md) and the [protocol](Protocol.md).
