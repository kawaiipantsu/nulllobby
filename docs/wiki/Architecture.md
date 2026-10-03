# Architecture

## Crate boundaries

| Crate | Owns |
|---|---|
| `nulllobby-core` | Lobby IDs/cards, per-lobby identities, Noise sessions, canonical signed messages, replay, endpoint books, fingerprints and trust |
| `nulllobby-transport` | Async byte streams, framing, endpoint types, mode policy, bounded channels and resource permits |
| `nulllobby-direct` | Standard BitTorrent handshake, BEP 10 adapter and bounded BEP 5 discovery |
| `nulllobby-tor` | SAFECOOKIE control, local SOCKS, v3 onion validation, ephemeral service lifecycle |
| `nulllobby-platform` | Secret memory mappings, zeroization, Linux core-dump controls and isolated FFI |
| `nulllobby-app` | Command/event orchestration, lobby workers, authenticated gossip, peer lifecycle |
| `nulllobby-tui` | Ratatui/Crossterm rendering, keyboard input and explicit invite display |
| `xtask` | Developer build/package/version/fuzz/release helpers |

```text
Linux TUI / future Iced desktop
              |
       bounded AppCommand / AppEvent
              |
       lobby + trust + signed gossip
              |
       Noise + encrypted identity proof
              |
       transport-neutral byte stream
          /                 \
 Direct adapter             Tor adapter
 BEP 10 + BitTorrent        onion service stream
 TCP + Mainline DHT         external Tor daemon
```

Core never imports socket types. The object-safe async `Transport` trait covers start/stop, create/destroy endpoint, connect/accept, local identity and network status. A returned transport stream is untrusted: only a successfully constructed `SecureSession` can carry application packets. The session constructor performs Noise and verifies the encrypted identity proof before exposing read/write halves.

Direct progresses through TCP connection, BitTorrent handshake, extension negotiation, Noise, identity authentication and established application records. Tor progresses through daemon bootstrap, service creation, onion connection, Noise and identity authentication. Errors close the stream; there is no alternate cipher or transport path. `Transport::start` means network readiness, not authenticated peer identity.

## Ownership

Each lobby worker owns its card, independent identity, trust list, replay state, member cache and endpoint book. Identities and private cards are non-cloneable secret wrappers; async tasks share ownership through `Arc`. UI events carry display metadata and, only after `/invite`, a redacted card wrapper. They never carry identity private keys or Noise key material.

One process-wide semaphore caps live peers at 128 and another caps pending handshakes at 32. A stream retains its handshake permit through BitTorrent/SOCKS, Noise and proof validation. Only the core's authenticated transition releases it. Listener/stream ownership closes connections on leave; dropping task sets aborts their work. Per-peer outgoing queues are bounded; slow peers disconnect instead of consuming unbounded RAM.

`AppCommand` handles typed user intent. `AppEvent` reports bounded view snapshots, verified messages, notices and lifecycle changes. The TUI imports no socket or cipher implementation. Future desktop clients can reuse the same boundary.

All normal application state lives in memory. Secret seeds, capabilities and static Noise keys use dedicated locked mappings when permitted. Noise library internals and terminal buffers are not all locked or guaranteed to zeroize; see the security model. Build/release files and test fixtures are developer operations, separate from runtime persistence.

## Transport selection

The application selects exactly one network mode and requires leaving all lobbies before changing it. Backends use an injectable `NetworkObserver`. Tor rejects every Direct/DHT/UDP/peer-DNS/tracker action. It only contacts explicitly configured numeric loopback SOCKS/Control endpoints and exposes loopback service listeners. Onion endpoints are fixed public service keys and ports, never arbitrary hostnames or exit destinations.

A separate external-Tor control connection owns each lobby worker's services. No service is detached. Local ControlPort loss closes peer streams, reports unavailability, and removes services when Tor observes the closed controller. Explicit shutdown attempts `DEL_ONION` before dropping control ownership.

## Deferred platforms

Windows and macOS desktop implementations remain future work. Use Iced and the shared Rust core, with no Electron. Windows starts with `x86_64-pc-windows-msvc`, then optional ARM64; macOS starts with ARM64, then optional x86-64. Add VirtualLock/dump controls and native signing/packaging on Windows, appropriate memory locking and signing/notarization on macOS. Credentials stay outside the repository.

The Arti feature is a reviewed unavailable extension point; see [Arti review](Arti-Review.md). It cannot substitute Direct.

## Renaming

1. Replace `branding.rs` presentation constants.
2. Update Cargo package/binary/path names, Debian metadata, release filenames and repository URLs.
3. Replace README/banner/about text and wiki navigation.
4. Preserve versioned protocol domains and card prefixes for compatibility. A product rename does not require new cryptographic domains.
5. If wire identifiers must change, design an explicit version migration and interoperability tests.
