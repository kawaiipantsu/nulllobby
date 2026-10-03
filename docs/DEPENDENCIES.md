# Phase 1 dependency review

Reviewed on 2026-10-03 using current `cargo search`/`cargo info`, downloaded source APIs and the RustSec advisory database. `Cargo.lock` is the exact resolved graph. Direct crates are selected from maintained upstream projects; absence of a known advisory does not prove correctness. No dependency is accepted merely because its API name is familiar.

| Direct dependency | Selected | Reason and upstream |
|---|---|---|
| ed25519-dalek | 3.0.0 | [Dalek](https://github.com/dalek-cryptography/curve25519-dalek); current stable API, zeroization, no hazmat/legacy compatibility |
| sha2 | 0.11.0 | [RustCrypto hashes](https://github.com/RustCrypto/hashes); SHA-256 fingerprints/checksums, zeroize enabled |
| hkdf / hmac | 0.13.0 / 0.13.0 | [RustCrypto KDFs](https://github.com/RustCrypto/KDFs), [MACs](https://github.com/RustCrypto/MACs); RFC 5869, HMAC zeroize feature explicitly unified |
| getrandom | 0.4.3 | [rust-random](https://github.com/rust-random/getrandom); fallible OS entropy, no deterministic seed fallback |
| secrecy | 0.10.3 | [iqlusion](https://github.com/iqlusioninc/crates/tree/main/secrecy); explicit exposure and redacted SecretBox/SecretString |
| zeroize | 1.9.0 | [RustCrypto utils](https://github.com/RustCrypto/utils); secret-buffer clearing |
| tokio | 1.53.2 | [Tokio](https://github.com/tokio-rs/tokio); only `io-util` and `sync`, no runtime network/filesystem features |
| base64 | 0.23.1 | [rust-base64](https://github.com/marshallpierce/rust-base64); strict URL-safe no-padding engine; optional unsafe SIMD disabled |
| thiserror | 2.0.21 | [thiserror](https://github.com/dtolnay/thiserror); fixed error categories with no payload reflection |
| libc | 0.2.190 | [rust-lang/libc](https://github.com/rust-lang/libc); stable series selected instead of 1.0 alpha, Linux FFI only |
| toml_edit | 0.25.15 | [toml-rs](https://github.com/toml-rs/toml); developer tooling only, manifest/lockfile edits |

The graph has 48 registry packages (including optional/platform/build packages) and 6 local workspace packages. Runtime dependencies are smaller than the full workspace graph. `syn` 2 and 3 are both required by upstream proc macros; cargo-deny reports this as a duplication warning, not an advisory exception. No RustSec advisory ignores are configured.

Relevant historical advisories checked: [Dalek RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093.html), [curve25519-dalek RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html), [Tokio RUSTSEC-2025-0023](https://rustsec.org/advisories/RUSTSEC-2025-0023.html), [SHA-2 RUSTSEC-2021-0100](https://rustsec.org/advisories/RUSTSEC-2021-0100.html), older Tokio/base64/zeroize-derive entries. Selected versions are outside their affected ranges. `cargo audit` checks the entire current lockfile, including transitive dependencies. Do not treat this static document as a substitute for rerunning it.

The preliminary RustSec source snapshot was `ef6173cbc5c50ec8166f9a5b28f07834144373ee`. Final audit/deny runs fetch the current database. Tool versions used: cargo-audit 0.22.2, cargo-deny 0.20.2. Registry API HTTP access was unavailable in the build environment; Cargo registry lookup and package downloads succeeded.

Source review confirmed Dalek `SigningKey::from_bytes`/`verifying_key` and zeroize-on-drop, `getrandom::fill`, secrecy's allocation/exposure behavior and HKDF extraction/expansion. HMAC/SHA zeroization does not guarantee clearing all upstream intermediate stack values. No blanket guarantee of secret erasure is made.

Not selected yet: `snow`, `mainline`, bencode/CBOR application codecs, Ratatui/Crossterm, Tor control/SOCKS crates, Arti and Iced. Inspect current APIs, release security status and dependency costs in the phase that actually introduces them. In particular, verify the exact XXpsk3 suite before Phase 2 and Arti onion hosting maturity before an experimental backend.

`cargo deny check` enforces known advisories, reviewed licenses, registry/git sources and version policies. Dependency license texts are bundled by the Rust packaging tool. The project license is AGPL-3.0-or-later; dependencies retain their original licenses.
