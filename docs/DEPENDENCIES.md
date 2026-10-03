# Dependency review

Reviewed on 2026-10-03 using current Cargo registry releases, downloaded source APIs, upstream protocol documentation and RustSec. The lockfiles specify exact graphs. A clean advisory scan is not proof of correctness or an independent application audit.

| Dependency | Selected | Review |
|---|---|---|
| tokio | 1.53.2 | Bounded channels, runtime, TCP/UDP, deadlines and local cookie-file read. No unbounded Tokio channels |
| snow | 0.10.0 | Exact XX and XXpsk3/25519/ChaChaPoly/BLAKE2s patterns verified against parser/build APIs and upstream vectors; both exercised by tests. Only required algorithms enabled |
| ed25519-dalek | 3.0.0 | Independent signing seeds, strict verification, weak-key rejection; zeroize enabled |
| x25519-dalek | 3.0.0 | Static public-key derivation and zeroizing secret type; actual key checked against Noise |
| sha2 / hkdf / hmac | 0.11.0 / 0.13.0 / 0.13.0 | SHA-256 fingerprints/checksums, RFC 5869 domain separation and Tor SAFECOOKIE HMAC; available zeroize features enabled |
| getrandom | 0.4.3 | Fallible OS randomness, no deterministic or time-based fallback |
| secrecy / zeroize | 0.10.3 / 1.9.0 | Explicit exposure, redacted secret wrappers and owned-buffer wiping |
| mainline | 8.0.1 | Default/actor features disabled. Only maintained BEP 42 IPv4 ID helper used; actor request/response queues use unbounded flume channels and were not accepted as the app discovery path |
| bendy | 0.6.1 | Canonical bencode decoder with explicit depth/input/collection limits; used by the bounded BEP 5 and BEP 10 implementations |
| minicbor | 2.3.0 | Manual definite-length canonical CBOR, fixed arrays and bounds; no hostile serde deserialization |
| base64 | 0.23.1 | Strict URL-safe, no-padding card codec; optional unsafe SIMD disabled |
| data-encoding / sha3 | 2.11.1 / 0.12.0 | Tor's specified v3 Base32 and SHA3 address checksum only |
| ratatui / crossterm | 0.30.2 / 0.29.0 | Linux TUI. Ratatui defaults reduced to Crossterm and rendered-line-count support for scrolling; no OSC52 clipboard feature |
| libc | 0.2.190 | Isolated Linux FFI for private mappings, mlock and core-dump controls |
| thiserror | 2.0.21 | Fixed public error categories, no payload reflection |
| toml_edit | 0.25.15 | Developer tooling only; consistent workspace/lockfile version bumps |
| cargo-fuzz / libfuzzer-sys | 0.13.2 / 0.4.13 | Separate developer fuzz graph; Rust wrappers, standard libFuzzer engine |

## Crypto review

The exact private snow pattern appears in upstream Cacophony vectors. Tests cover both suites, wrong PSK, wrong lobby, every identity-proof byte mutation, actual remote static-key mismatch, transcript mismatch, signed-message mutation and captured-wire confidentiality. The historical [snow authentication advisory](https://rustsec.org/advisories/RUSTSEC-2024-0011.html) is fixed in selected 0.10.0. Dalek, Tokio and RustCrypto historical advisories were checked through the current full graph scan; the experimental Arti graph adds narrowly named exceptions documented in [its dependency review](ARTI-DEPENDENCIES.md).

Dalek enables zeroization. Stored identity seeds, capabilities, static keys and derived PSKs use dedicated platform mappings. **Snow does not expose complete wiping/locking of its internal handshake/cipher state.** The memory-lock status applies to our retained secret wrappers, not every library allocation or temporary. No claim of complete secret erasure is made.

## Direct discovery decision

Mainline's current high-level API was inspected rather than guessed. Its actor uses unbounded response/request channels. NullLobby therefore implements a small bounded read-only BEP 5 client with bendy and Tokio, retaining mainline's BEP 42 ID implementation. It does not use the crate's unbounded actor, recursive serde network decoder or persistence. The transitive SHA-1 helper belongs to the BitTorrent crate; NullLobby uses SHA-256/HKDF for application security and does not call that SHA-1 helper.

## Tor decision

External Tor integration follows the [ControlPort](https://spec.torproject.org/control-spec/commands.html), [SOCKS](https://spec.torproject.org/socks-extensions.html) and [v3 address](https://spec.torproject.org/rend-spec/encoding-onion-addresses.html) specifications. A narrow local protocol implementation avoids an unnecessary control library dependency graph. Authentication is SAFECOOKIE only; requests/replies and SOCKS addresses have fixed limits. Local protocol fixtures and a real Tor 0.4.9.12 smoke test passed.

Arti 0.47.0 is implemented behind `tor-arti-experimental`, using an isolated local service-storage patch. Each lobby uses a distinct RAM-only key store and replay filter while normal Tor guards/cache persist. The graph, upstream API, maintenance advisories and license additions are reviewed in [ARTI-DEPENDENCIES.md](ARTI-DEPENDENCIES.md). No desktop dependency tree is included.

## License and advisory gates

`cargo audit` and `cargo deny check` scan the locked application graph. Duplicate versions arise from upstream crypto/proc-macro/TUI constraints and are warnings, not suppressed advisories. The license allowlist includes the existing project/crypto/TUI licenses and the reviewed Arti additions documented in ARTI-DEPENDENCIES.md; see `deny.toml` for exact identifiers. Fuzz-only libFuzzer additionally uses NCSA; it is outside shipped binaries. Rust packaging bundles the actual target's dependency license texts.

Primary upstreams: [Snow](https://github.com/mcginty/snow), [Dalek](https://github.com/dalek-cryptography/curve25519-dalek), [RustCrypto](https://github.com/RustCrypto), [Tokio](https://github.com/tokio-rs/tokio), [mainline](https://github.com/pubky/mainline), [minicbor](https://github.com/twittner/minicbor), [bendy](https://github.com/P3KI/bendy), [Ratatui](https://github.com/ratatui/ratatui), [RustSec](https://rustsec.org/).
