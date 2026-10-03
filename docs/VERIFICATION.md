# Linux preview verification

Version **0.2.0**, checked on 2026-10-03. These are implementation checks, not an independent professional security audit.

## Results

| Check | Result |
|---|---|
| `cargo fmt --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed |
| `cargo test --workspace` | 58 passed; two external-network tests ignored by default |
| Experimental Arti unavailable-boundary test | Passed separately with all features |
| `cargo audit` | No known vulnerabilities in the 175-package locked dependency graph |
| `cargo deny check` | Advisories, licenses, sources and bans passed; reviewed duplicate-version warnings remain |
| Nine cargo-fuzz smoke targets | 43,778,214 total executions; no crash in ten seconds per target (11 seconds reported including termination) |
| Real external Tor 0.4.9.12 | Private onion → Noise → identity proof → encrypted record roundtrip passed; distinct services, explicit SOCKS isolation and cleanup checked |
| Public Mainline DHT | Live get_peers and token-authorized announce_peer passed, within query/peer limits |
| Debian package and archive | Built for amd64; checksums verified; extracted binary passed offline diagnostics with HOME=/proc |
| Source path hygiene | Release binary checked for local source/home paths; no matches |

The final stable checks used Rust 1.94.1 with its matching rustfmt and Clippy components. Fuzzing used nightly 1.101.0 (2026-10-03), cargo-fuzz 0.13.2 and libfuzzer-sys 0.4.13. CI independently installs the same pinned toolchains.

Fuzz totals by target: BitTorrent 16,117,311; BEP 10 521,538; bencode 500,692; cards 4,055,284; invites 1,908,864; Noise framing 3,673,325; application CBOR 6,253,391; endpoints 6,234,111; terminal sanitation 4,513,698. These short runs are smoke tests, not exhaustive campaigns. Valid-checksum/signature semantic paths also require the structured unit/integration tests below.

## Privacy regression map

| Requirement | Evidence |
|---|---|
| Independent Ed25519 keys across lobbies/restarts | `identity::tests::independent_lobbies_and_rejoins_have_independent_keys` |
| Different onion endpoints per lobby | Tor fixture and live service tests |
| No cross-lobby endpoint advertisements | Core EndpointBook scope test; successful two-lobby Tor app integration |
| Random public-unlisted IDs | Domain public-ID uniqueness test |
| Private IDs independent of names | Private generation/KDF tests |
| Different private PSK and discovery bytes | HKDF separation and RFC 5869 vector tests |
| No nicknames/names in BEP 10 | Exact truthful extension handshake test; no application metadata fields in encoder |
| No chat plaintext or Ed25519 identity in captured Direct bytes | Real TCP proxy/capture integration through BitTorrent, BEP 10, Noise and proof |
| Tor never invokes DHT, UDP, direct peer TCP, trackers or peer DNS | Instrumented unavailable-Tor and successful multi-lobby Tor app tests; external backend failure/invalid destination tests |
| Wrong PSK never receives lobby metadata | No usable session on wrong PSK/lobby; handshake payloads are empty, proof and application metadata encrypted |
| ANSI/OSC/bidi neutralized | Core control-character tests, command input test and TUI rendering test |
| Bounded remote resources | Frame/allocation limits, bounded channels, oversized decoder tests and authenticated-peer flood/disconnect test |
| Trust does not cross lobbies | Core LobbyTrust scope test and three-peer app test |
| Endpoint handles do not cross backends | Foreign handle rejection in Tor integration |
| Explicit secure transition | Direct state trace reaches Secure only after Noise and identity proof |
| RAM-only Direct with unwritable HOME | Child-process three-peer integration with HOME=/proc, plus extracted CLI diagnostics |

## Boundaries of this evidence

Tests do not establish global anonymity, complete memory erasure, successful delivery across every network partition, universal NAT reachability or safety against a compromised OS. The public network tests are opt-in and may fail under restricted networks; their absence does not trigger fallback. Tor publication timing varies substantially.

The external Tor daemon's normal guard/cache files were preserved; no attempt was made to erase guard state to simulate application RAM-only behavior. Synthetic chat and ephemeral test identities were used. Operational invitations, private identities and control credentials are not included in reports or artifacts.

Embedded Arti and Windows/macOS clients are not implemented. The Arti feature returns Unsupported pending the documented service-state review. See SECURITY.md, the protocol guide and dependency review for exact properties and remaining limits.
