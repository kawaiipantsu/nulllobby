<div align="center">

<img src="assets/github_banner.png" width="1100" alt="NullLobby / THUGS(red)" />

**Ephemeral identities. Decentralized lobbies. Explicit privacy choices.**

![Status](https://img.shields.io/badge/STATUS-LINUX_PREVIEW-ff3b47?style=for-the-badge)
![Rust](https://img.shields.io/badge/RUST-LINUX-11151d?style=for-the-badge&logo=rust)
[![License](https://img.shields.io/badge/LICENSE-AGPL_3.0_OR_LATER-ff3b47?style=for-the-badge)](LICENSE)

<samp>Created by Kawaiipantsu for the THUGS(red) security community</samp>

[**THUGS(red)**](https://thugs.red) · [**Wiki**](https://github.com/kawaiipantsu/nulllobby/wiki) · [**Discussions**](https://github.com/kawaiipantsu/nulllobby/discussions) · [**Security model**](SECURITY.md)

</div>

## NullLobby

**NullLobby provides encrypted decentralized lobby chat.** The Linux terminal client uses a shared Rust core, signed messages, independent identities per lobby, and either Direct peer connections or external Tor onion services. It is a communications application for authorized security work and internal coordination.

**Direct mode provides confidentiality, NOT network anonymity.** **Tor mode uses onion-service transport to hide peer IP addresses from other lobby participants.** Tor never falls back to Direct. A sufficiently capable observer can still correlate traffic; ordinary Tor usage may be observable to the local network.

The application is **RAM-first/RAM-only for its own identity, trust and history state in v1**. Restarting creates new fingerprints and loses verification and history. **No independent professional security audit has yet been completed.** This is an experimental Linux preview; review the threat model before sensitive use.

## Build and run

Requires Linux, Rust 1.94+, a C linker and Make. Packaging also needs `dpkg-deb`, `readelf` and GNU `tar`.

```sh
make build
./target/x86_64-unknown-linux-gnu/release/nulllobby
```

Inside the full-screen client:

```text
/nick operator
/create private coordination
/invite
```

Share the explicitly revealed card through an appropriate channel. Another participant uses `/join <card>`. Compare complete fingerprints out of band, then `/verify <fingerprint>`. Nicknames are cosmetic; a new key is `encrypted / unverified`.

```text
/help                         /who                  /fingerprint
/create public <name>         /verify <fingerprint> /unverify <fingerprint>
/create private <name>        /verified             /invite
/create discoverable <name>   /confirm              /lobbies
/join <card>                  /switch <number>      /leave
/reconnect                    /transport direct    /transport tor
/security                     /network              /privacy
/padding none                 /padding bucketed    /quit
```

Public lobbies default to **unlisted**, with random 256-bit IDs. Discoverable lobbies are Direct-only, can be enumerated, and require an explicit warning confirmation. Private lobbies use random capabilities, not passwords. Transport changes require leaving all lobbies. `/invite` displays a card without copying it to the clipboard; Esc hides it. Terminal scrollback and clipboard managers are outside the application's boundary.

## Direct and Tor

| Mode | Session status | Exposure |
|---|---|---|
| Direct | `DIRECT / ENCRYPTED / IP EXPOSED TO PEERS` | Peers see IPs. DHT and network observers see metadata and may recognize BitTorrent and `NL_chat` |
| Tor | `TOR / ENCRYPTED / ONION TRANSPORT` | Onion services hide public peer IPs. Tor use, timing and traffic correlation remain concerns |

Direct uses a random listening port by default. Public Internet connectivity requires reachable peers; automatic NAT traversal/UPnP is not implemented. Deterministic local testing uses the complete BitTorrent → BEP 10 → Noise → identity-proof path:

```sh
nulllobby --no-dht --listen 127.0.0.1:50001
nulllobby --no-dht --listen 127.0.0.1:50002 --peer 127.0.0.1:50001
```

Create a lobby in the first client and join its card in the second. There is no plaintext test transport.

For Tor, configure a separately installed daemon with a loopback SOCKSPort, an authenticated loopback ControlPort, `CookieAuthentication 1`, and explicit `IsolateSOCKSAuth` on the SOCKSPort. Give the client permission to read that daemon's authentication cookie; never make it world-readable.

```sh
nulllobby --transport tor \
  --tor-socks 127.0.0.1:9050 \
  --tor-control 127.0.0.1:9051 \
  --tor-cookie /path/to/tor/control_auth_cookie
```

The daemon must finish bootstrapping first. NullLobby uses SAFECOOKIE mutual authentication, creates a distinct non-detached ephemeral v3 onion service for each lobby, and deletes it on leave. Tor cards need a reachable seed; otherwise the client reports `No reachable Tor lobby seed`. The daemon retains its normal guards/cache; NullLobby does not reset them. See the [Tor guide](docs/wiki/Tor.md).

Windows/macOS GUI clients and an embedded Arti backend remain future work. The `tor-arti-experimental` feature reserves an explicitly unavailable backend boundary pending the [storage review](docs/wiki/Arti-Review.md); it does not enable an embedded client.

## Architecture

```text
apps/nulllobby-tui          Ratatui/Crossterm presentation and input
crates/nulllobby-app        Bounded command/event runtime and lobby workers
crates/nulllobby-core       Identities, Noise, signed CBOR, replay, cards and trust
crates/nulllobby-transport  Async byte streams, framing, limits and network policy
crates/nulllobby-direct     BitTorrent, BEP 10 and bounded BEP 5 discovery
crates/nulllobby-tor        SAFECOOKIE ControlPort, onion-only SOCKS, ephemeral services
crates/nulllobby-platform   Linux core-dump prevention, locked secret mappings
xtask                      Rust build, package, version, fuzz and release tools
fuzz                       Rust cargo-fuzz targets
docs/wiki                  Version-controlled GitHub Wiki source
```

No mandatory central chat server, database, application log, telemetry or automatic public-IP probe. Encryption sits above both transports. UI code contains no networking or cryptographic implementation. Presentation metadata is centralized in [branding.rs](crates/nulllobby-core/src/branding.rs); protocol domains stay stable when branding changes.

Security follows Kerckhoffs's principle: assume the executable, source and protocol are public. Release LTO and symbol stripping are build hardening; they do not prevent reverse engineering or supply cryptographic security.

## Check, package and release

```sh
cargo install cargo-audit --version 0.22.2 --locked --no-default-features
cargo install cargo-deny --version 0.20.2 --locked
make check
make deb
make bump-patch        # also bump-minor / bump-major
# Review, commit and push the version change:
make release           # validates and creates a draft GitHub release
```

Exact build and test commands:

```sh
cargo build --locked --release --target x86_64-unknown-linux-gnu -p nulllobby-tui
cargo test --locked --workspace
```

`make build` additionally removes local source/cache paths from compiled artifacts. Debian packages include the binary, security documentation and dependency license notices. They install no service, state directory, Tor configuration or secrets. The glibc requirement comes from the actual binary; build on the oldest distribution you intend to support. Publishing a reviewed draft triggers an Announcements Discussion.

## Documentation and contribution

[Getting started](docs/wiki/Getting-Started.md) · [Architecture](docs/wiki/Architecture.md) · [Protocol](docs/wiki/Protocol.md) · [Privacy](docs/wiki/Privacy.md) · [Tor](docs/wiki/Tor.md) · [Development](docs/wiki/Development.md) · [Releases](docs/wiki/Releases.md) · [Verification](docs/VERIFICATION.md) · [Dependency review](docs/DEPENDENCIES.md)

Use [Discussions](https://github.com/kawaiipantsu/nulllobby/discussions) for feature, encryption, lobby and workflow ideas. Use synthetic examples in reports; never publish operational chat, invites, credentials, private keys or personal environment details. See [CONTRIBUTING.md](CONTRIBUTING.md).

**License:** AGPL-3.0-or-later. Dependencies retain their licenses. The banner was supplied by the project owner.

---
<div align="center"><samp>NullLobby · Kawaiipantsu · THUGS(red) · AUTHORIZED WORK</samp></div>
