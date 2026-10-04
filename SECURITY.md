# Security model

## Implementation boundary

The Linux preview implements encrypted Direct and external Tor transports, signed lobby gossip and a terminal client. An optional experimental embedded Arti backend uses a reviewed local service-storage patch. Unit, integration and live smoke tests cover the listed properties, with explicit limits below. No independent professional security audit has yet been completed.

Assume attackers possess every executable, source file and protocol specification. Security must depend on standard cryptography and protected keys, consistent with Kerckhoffs's principle. Native compilation, LTO and symbol stripping are not cryptographic controls.

## Implemented invariants

- Fresh OS randomness for every lobby identity seed, Noise static key and private capability. No public master identity, persistent key or installation identifier.
- SHA-256 fingerprints display all 256 bits. Trust is bounded, in memory and scoped to a lobby. Nicknames make no identity claim.
- Public-unlisted IDs are random 256-bit rendezvous IDs. Private IDs, discovery bytes and Noise PSKs use separate HKDF-SHA-256 labels; no password/name derivation.
- Card parsing caps text, decoded bytes and endpoint count before dependent work. It validates checksums, lengths, version, transport/type agreement, seed uniqueness, nonzero ports, secret/ID consistency and complete consumption. Unknown versions/types fail. Checksum verification is not sender authentication.
- Secret wrappers are redacted and non-cloneable where practical. Exported cards use `SecretString`; the library exposes them only through an explicit export method. There is no automatic logging or clipboard integration.
- Terminal text rejects controls, ESC/OSC sequences, C1 controls and bidi control characters. The bounded sanitizer strips those characters before terminal display.
- Handshake parsing accepts exactly 68 bytes and the standard BitTorrent header. The Direct backend validates both swarm and extension support before negotiating BEP 10. Peer IDs use fresh randomness.
- Transport trait exposes byte streams, no sockets. Tor mode policy rejects DHT, UDP discovery, direct peer TCP, trackers and peer DNS. The app selects exactly one backend; integration tests instrument unavailable Tor, SOCKS, service lifecycle and daemon failure. There is no fallback branch.
- Only bounded Tokio channels exist. The core contains no filesystem persistence or network APIs.

## Threat matrices

### Passive local observer

| Mode | Can observe | Protection |
|---|---|---|
| Direct | Source IP, BitTorrent/DHT, timing, size, potentially the custom extension | Noise prevents reading application plaintext |
| Tor | Tor connectivity, timing and sizes unless bridges change observability | Onion routing hides peers' public IPs; Noise protects application plaintext |

### Malicious lobby peer

| Capability | Boundary |
|---|---|
| Reads received lobby plaintext, records it or forwards it outside the app | Authorized recipients cannot be cryptographically prevented from disclosing plaintext |
| Knows nicknames, fingerprints, timings and received record sizes | Nicknames are untrusted; first contact is `encrypted / unverified` |
| Attempts impersonation or gossip forgery | Ed25519 message signatures and verified fingerprints authenticate the sender key |
| Sends malformed frames, replays or floods | Bounded sessions, replay windows, queues and rate limits reject/drop excess work |

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

Linux startup sets both RLIMIT_CORE limits to zero and PR_SET_DUMPABLE to zero. The executable refuses to create secrets or start chat if this fails. An embedding application must install the safe panic hook and call hardening before creating secrets. Library loading alone does not change process limits.

Each high-value secret gets its own private anonymous mapping. `mlock` success or the kernel error is retained per allocation. Mapping failure is an error. Lock failure leaves usable but explicitly unlocked, zeroizing memory; never report it as locked. Pages are zeroized before `munlock`/`munmap`. No heap-page sharing means one secret's drop cannot unlock a neighboring secret. Other OS implementations currently report `Unsupported` and zeroize heap storage.

Dalek enables zeroization; SHA-256/HMAC buffers enable available zeroization features. The retained HKDF PRK is explicitly cleared. Not all internal dependency temporaries are guaranteed to be erased. In particular, snow 0.10.0's internal handshake and cipher state does not expose complete zeroization or locking controls; retained session state is not covered by the seed/PSK memory-lock indicator. Temporary signing keys, KDF internals and card encoding buffers are **not all mlocked**. Compiler temporaries, CPU registers, kernel buffers, swap behavior, terminal scrollback, clipboard managers, hypervisors, compromised kernels and physical acquisition cannot be absolutely controlled by ordinary Rust code. Abort/OOM termination does not run Rust destructors.

No chat history, private invites, application keys, fingerprints, trust, DHT routing state or onion keys are intentionally written to disk. Defaults also keep preferences in RAM. Explicitly enabling remembered settings saves display preferences, nickname, welcome dismissal and at most 16 public cards with current seeds/autoconnect flags. This metadata can correlate activity despite fresh identities. Private capabilities are rejected. Settings use bounded parsing, mode 0600 and atomic replacement; deletion is not secure erasure. There is no accumulated endpoint history.

Build/release filesystem operations are separate from application runtime. No telemetry, crash uploader, chat database or analytics exists. Embedded Arti retains ordinary guard state and a SQLite directory cache at explicitly configured paths; application/onion secrets never enter that cache.

### Release signing

The optional Rust maintainer tooling uses XXC Trust to sign the public SHA-256 checksum manifests with a dedicated Ed25519 OpenPGP release key. The release private key stays in XXC; XXC administrators and anyone holding a token with signing permission can authorize signatures. The local API token is explicitly persisted in an account-owned private configuration outside the repository, with mode 0600 in a 0700 directory. Neither the token nor this configuration enters the client or Debian packages. The tool does not request private-key exports or install a CA in the system trust store.

HTTPS uses normal certificate verification, a fixed reviewed endpoint, no redirects or environment proxies, deadlines and bounded responses. Public artifact names/hashes, the maintainer connection address and signing times are visible to XXC. Chat, invitations, lobby identities and trust decisions never go to this API. The application has no CA client or background certificate lookup, including in Tor mode.

Signing checks every expected artifact hash and locally verifies the returned Ed25519/SHA-256 signatures using an isolated GnuPG public keyring. Verification disables keyserver retrieval and personal GnuPG configuration. The trust anchor is the reviewed public key pinned by SHA-256. Legacy OpenPGP v4 fingerprints are only GnuPG lookup identifiers; they are not used as NullLobby's SHA-256 lobby fingerprints or as the release trust anchor. A fingerprint or key downloaded alongside an otherwise untrusted release does not independently establish publisher identity. Distribute/compare the SHA-256 key pin through an already trusted channel.

Release signatures authenticate publisher authorization of exact bytes. They do not establish that a binary is safe, audited, reproducible or the newest release. Offline checks cannot discover a newly revoked key without an updated trusted key. Detached checksum/package signatures are not automatically verified by `apt install ./file.deb`; APT repository authentication requires signed repository metadata. See [verification, rotation and compromise handling](docs/wiki/Release-Signing.md). Organization credentials remain a [design proposal](docs/ORGANIZATION-IDENTITY.md), separate from the implemented chat protocol.

The official `apt.thugs.red` archive uses a separate Ed25519 archive key scoped through APT's `Signed-By`. The Rust publisher verifies release signatures and GitHub asset hashes before uploading, rejects unrelated shared-suite changes, and validates signed archive metadata and public downloads afterward. A bearer token with publication permission can authorize repository changes; archive administrators and archive-key compromise are also part of this trust model. Management credentials stay in private local configuration outside the repository. HTTPS is the default; an operator-authorized numeric RFC 1918 HTTP endpoint requires an explicit setting and sends the token unencrypted on that management network. There is no HTTP fallback. Public package downloads always use HTTPS. See [APT trust setup and publishing](docs/wiki/APT.md).

Headless bots are authorized recipients. Only explicitly addressed prompts reach the provider, without previous chat or lobby metadata. Cloud APIs need explicit opt-in and are rejected in Tor mode; local models require literal loopback IPs. Redirects and environment proxies are disabled. Providers/local servers may retain prompts under their own policies. HTTP/JSON temporaries and API credentials are not guaranteed fully erased or locked. Model outputs cannot execute commands/tools. See [bot limits](docs/wiki/Bots.md).

## Implemented protocol properties

- Public: `Noise_XX_25519_ChaChaPoly_BLAKE2s`. Private: `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`. `snow` 0.10.0 implements both exact suites; tests establish each and reject mismatched PSKs. No plaintext/cipher downgrade, fallback cipher or BitTorrent MSE security boundary.
- After Noise, exchange an encrypted canonical identity proof binding version, lobby ID, Ed25519 key, the **actual remote Noise static key** , the Noise transcript hash and a random session nonce under `nulllobby.identity.v1`. Accept application messages only after proof validation in `Secure` state.
- Private peers must prove PSK possession before receiving lobby names, nicknames, membership or chat.
- Sign logical messages under `nulllobby.message.v1`, including version, lobby, sender, sequence, random message ID, type and canonical payload. Verify before attribution/display, use bounded replay windows and forward the original signed message only over authenticated links.
- Standard BitTorrent + truthful `NL_chat` BEP 10 extension in Direct mode. No application metadata in the extended handshake. Payload tags expose only Noise handshake (`0x01`) or Noise ciphertext (`0x02`). Random listening port, configurable; no stable installation peer ID.
- Tor onion-only streams, distinct ephemeral onion service per lobby, authenticated local ControlPort, loopback listener, per-lobby SOCKS isolation where supported. No detach, private-key persistence, clearnet fallback, DHT, tracker, peer DNS or Tor exit destination. On leave/stop close streams and remove owned services. Missing seeds: `No reachable Tor lobby seed`.
- Signed endpoint advertisements stay inside the authenticated lobby, expire within bounded lifetimes and use monotonic sequences. No permanent endpoint history.
- Padding is encrypted and bounded (`none` or buckets accounting for Noise overhead); it reduces simple length inference without eliminating traffic analysis.

## Bounds and remaining risks

- Global live connections: 128. Pending transport/Noise handshakes: 32, held through identity validation. Lobbies: 16. Peers and lifetime sender keys per lobby: 64.
- Command queues: 32. UI/worker receive queues: 128. Per-peer send queues: 32. Slow recipients are disconnected when send queues fill.
- Maximum chat: 8192 UTF-8 bytes. Wire frame: 65536 bytes. Application packet: 12288 bytes. Noise ciphertext record: 16384 bytes. Handshake record: 512 bytes.
- Maximum 64 signed records per peer per second, charging each endpoint-list entry separately. This limits resource use; it does not eliminate denial of service.
- Replay: random 128-bit message IDs, sender sequences and a 128-position window. Recent ID cache: 4096 entries / ten minutes. Sender high-water marks remain until lobby leave; after 64 distinct keys, a lobby must be recreated/rejoined to admit more.
- Endpoint advertisements: one current endpoint per sender, at most 64 senders, expiry at most 600 seconds ahead, at most eight advertisements per packet. Expiry uses the wall clock for freshness only; sequences and message IDs prevent replay independently.
- BEP 10 handshake: 4096 bytes / depth 8. DHT replies: 2048 bytes / depth 6, candidate queue 64, 24 node queries per discovery cycle, 64 returned peers. Public discovery filters private/reserved IPv4 addresses; explicit user seeds may be local.
- Terminal history: 512 bounded lines per lobby plus a bounded system buffer. No disk history. Member summaries shorten fingerprints for space; only complete fingerprints are accepted for verification.
- Automatic NAT traversal, delivery acknowledgements and durable offline delivery are absent. Network partitions and bounded queues can lose messages; the UI does not promise delivery to every member.
- DHT and authorized peers can deny availability or attempt eclipse attacks. Public lobbies admit anyone holding the public card. Private capability compromise requires starting a fresh private lobby and redistributing its card; key rotation/revocation is not implemented.
- Onion publication can take time. A dead card seed cannot be recovered by global lookup. Tor control health is checked every 15 seconds with a five-second command timeout; failure closes streams and the lobby worker then reports disconnection.
- The optional experimental Arti backend pins libraries 0.47.0 and patches service storage to use independent RAM-only keystores and replay filters. Normal Tor guard/cache state remains durable. Service status is checked every five seconds; failures close streams without changing backend. The shared Tor client may maintain relay connections until process exit. Replay filters fail closed at 100,000 insertions per live filter. Memory accounting covers selected Tor queues, not total RSS. See the [implementation review](docs/wiki/Arti-Review.md).
- The optional Arti graph has documented RSA applicability and unmaintained-dependency exceptions. These are not repaired upstream vulnerabilities or a vulnerability-free audit result. See the [dependency assessment](docs/ARTI-DEPENDENCIES.md). Desktop clients remain future work.

## State and privacy distinctions

External Tor and embedded Arti retain normal guard/cache state. Do not delete or rotate it to satisfy NullLobby's RAM-only rule. NullLobby-specific onion keys must be ephemeral and application secrets must never enter Tor state files. Ordinary Tor use may be observable without bridges/pluggable transports. Bridges are not a guarantee of invisibility.

An OS VPN is not a NullLobby transport. Correct routing usually exposes its egress to Direct peers; the operator becomes part of the trust model. Split routing or failure can expose direct connectivity. Users relying on the VPN need its kill switch. NullLobby cannot guarantee VPN behavior, equate it with onion mode, or probe public IP-reporting services automatically.

## Review and reporting

Use GitHub private vulnerability reporting when available. Public reports should contain synthetic reproductions and no private operational data. The [development guide](docs/wiki/Development.md) maps current tests and deferred network regressions. A clean RustSec audit is a dependency check, not a professional security audit of this application.
