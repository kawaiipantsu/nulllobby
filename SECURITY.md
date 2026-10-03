# Security model

## Implementation boundary

Phase 1 is offline. It supplies identity/capability primitives, bounded codecs and hardening; it cannot send encrypted messages. All network properties below are **requirements for later phases**, not tested network guarantees of this release. No independent professional security audit has yet been completed.

Assume attackers possess every executable, source file and protocol specification. Security must depend on standard cryptography and protected keys, consistent with Kerckhoffs's principle. Native compilation, LTO and symbol stripping are not cryptographic controls.

## Implemented invariants

- Fresh OS randomness for every lobby identity seed, Noise placeholder and private capability. No public master identity, persistent key or installation identifier.
- SHA-256 fingerprints display all 256 bits. Trust is bounded, in memory and scoped to a lobby. Nicknames make no identity claim.
- Public-unlisted IDs are random 256-bit rendezvous IDs. Private IDs, discovery bytes and future Noise PSKs use separate HKDF-SHA-256 labels; no password/name derivation.
- Card parsing caps text, decoded bytes and endpoint count before dependent work. It validates checksums, lengths, version, transport/type agreement, seed uniqueness, nonzero ports, secret/ID consistency and complete consumption. Unknown versions/types fail. Checksum verification is not sender authentication.
- Secret wrappers are redacted and non-cloneable where practical. Exported cards use `SecretString`; the library exposes them only through an explicit export method. There is no automatic logging or clipboard integration.
- Terminal text rejects controls, ESC/OSC sequences, C1 controls and bidi control characters. The bounded sanitizer strips those characters before future display.
- Handshake parsing accepts exactly 68 bytes and the standard BitTorrent header. Future callers must validate both swarm and extension support before continuing. Peer IDs use fresh randomness.
- Transport trait exposes byte streams, no sockets. No backend exists. Tor mode policy rejects DHT, UDP discovery, direct peer TCP, trackers and peer DNS. Future implementations must route all network operations through the observer and pass integration tests.
- Only bounded Tokio channels exist. The core contains no filesystem persistence or network APIs.

## Intended threat matrices

### Passive local observer

| Mode | Can observe | Intended protection |
|---|---|---|
| Direct | Source IP, BitTorrent/DHT, timing, size, potentially the custom extension | Noise prevents reading application plaintext |
| Tor | Tor connectivity, timing and sizes unless bridges change observability | Onion routing hides peers' public IPs; Noise protects application plaintext |

### Malicious lobby peer

| Capability | Boundary |
|---|---|
| Reads received lobby plaintext, records it or forwards it outside the app | Authorized recipients cannot be cryptographically prevented from disclosing plaintext |
| Knows nicknames, fingerprints, timings and received record sizes | Nicknames are untrusted; first contact is `encrypted / unverified` |
| Attempts impersonation or gossip forgery | Future Ed25519 message signatures and verified fingerprints authenticate the sender key |
| Sends malformed frames, replays or floods | Future bounded sessions, replay windows and queue limits must reject/drop excess work |

### DHT crawler

| Mode | Exposure |
|---|---|
| Direct | Can correlate public source IP and swarm identifiers. A random lobby ID prevents trivial name enumeration, not correlation of observed traffic |
| Tor | Mainline DHT must never be used |

### ISP

| Mode | Exposure |
|---|---|
| Direct | Direct BitTorrent activity, peers and metadata; application plaintext must remain encrypted |
| Tor | Usually Tor use, timing and size; application plaintext must remain encrypted. Bridges may alter observability |

### Global traffic observer

| Mode | Limitation |
|---|---|
| Direct | No network anonymity; broad observation correlates endpoints and traffic |
| Tor | A sufficiently capable observer across multiple network points may correlate timing/volume. No mathematical guarantee of anonymity |

### Compromised endpoint

| Attacker control | Limitation |
|---|---|
| Client process, OS/kernel, hypervisor or physical memory | Plaintext and keys may be exposed; outside the protection offered by the protocol |

## Memory and process hardening

Linux startup sets both RLIMIT_CORE limits to zero and PR_SET_DUMPABLE to zero. Diagnostics refuse to create secrets if this fails. An embedding application must install the safe panic hook and call hardening before creating secrets. Library loading alone does not change process limits.

Each high-value secret gets its own private anonymous mapping. `mlock` success or the kernel error is retained per allocation. Mapping failure is an error. Lock failure leaves usable but explicitly unlocked, zeroizing memory; never report it as locked. Pages are zeroized before `munlock`/`munmap`. No heap-page sharing means one secret's drop cannot unlock a neighboring secret. Other OS implementations currently report `Unsupported` and zeroize heap storage.

Dalek enables zeroization; SHA-256/HMAC buffers enable available zeroization features. The retained HKDF PRK is explicitly cleared. Not all internal dependency temporaries are guaranteed to be erased. Temporary signing keys, KDF internals and card encoding buffers are **not all mlocked**. Compiler temporaries, CPU registers, kernel buffers, swap behavior, terminal scrollback, clipboard managers, hypervisors, compromised kernels and physical acquisition cannot be absolutely controlled by ordinary Rust code. Abort/OOM termination does not run Rust destructors.

No chat history, invites, keys, fingerprints, trust, nickname/config, routing state, onion keys or endpoint history is intentionally written to disk. Build artifacts and release tools are developer filesystem operations, separate from application runtime. No telemetry, crash uploader, database or analytics exists.

## Required later protocol properties

- Public: `Noise_XX_25519_ChaChaPoly_BLAKE2s`. Private: `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`. Verify the selected `snow` release and exact PSK pattern first. No plaintext/cipher downgrade, fallback cipher or BitTorrent MSE security boundary.
- After Noise, exchange an encrypted canonical identity proof binding version, lobby ID, Ed25519 key, the **actual remote Noise static key** and a random session nonce under `nulllobby.identity.v1`. Accept application messages only after proof validation in `Secure` state.
- Private peers must prove PSK possession before receiving lobby names, nicknames, membership or chat.
- Sign logical messages under `nulllobby.message.v1`, including version, lobby, sender, sequence, random message ID, type and canonical payload. Verify before attribution/display, use bounded replay windows and forward the original signed message only over authenticated links.
- Standard BitTorrent + truthful `NL_chat` BEP 10 extension in Direct mode. No application metadata in the extended handshake. Payload tags expose only Noise handshake (`0x01`) or Noise ciphertext (`0x02`). Random listening port, configurable; no stable installation peer ID.
- Tor onion-only streams, distinct ephemeral onion service per lobby, authenticated local ControlPort, loopback listener, per-lobby SOCKS isolation where supported. No detach, private-key persistence, clearnet fallback, DHT, tracker, peer DNS or Tor exit destination. On leave/stop close streams and remove owned services. Missing seeds: `No reachable Tor lobby seed`.
- Signed endpoint advertisements stay inside the authenticated lobby, expire within bounded lifetimes and use monotonic sequences. No permanent endpoint history.
- Padding is encrypted and bounded (`none` or future buckets accounting for Noise overhead); it reduces simple length inference without eliminating traffic analysis.

## State and privacy distinctions

External Tor can retain normal guard/cache state. Do not delete or rotate it to satisfy NullLobby's RAM-only rule. NullLobby-specific onion keys must be ephemeral and application secrets must never enter Tor state files. Ordinary Tor use may be observable without bridges/pluggable transports. Bridges are not a guarantee of invisibility.

An OS VPN is not a NullLobby transport. Correct routing usually exposes its egress to Direct peers; the operator becomes part of the trust model. Split routing or failure can expose direct connectivity. Users relying on the VPN need its kill switch. NullLobby cannot guarantee VPN behavior, equate it with onion mode, or probe public IP-reporting services automatically.

## Review and reporting

Use GitHub private vulnerability reporting when available. Public reports should contain synthetic reproductions and no private operational data. The [development guide](docs/wiki/Development.md) maps current tests and deferred network regressions. A clean RustSec audit is a dependency check, not a professional security audit of this application.
