# Architecture

## Implemented workspace

| Crate | Owns | Does not own |
|---|---|---|
| `nulllobby-core` | Lobby IDs/types, private KDF, cards, identities, fingerprints, trust and safe text | Socket handles, files, UI rendering or network implementation |
| `nulllobby-transport` | Async byte-stream trait, endpoint/address types, network policy, bounded channels | Cryptography, DHT, TCP or Tor backend |
| `nulllobby-direct` | Exact standard BitTorrent handshake codec and ephemeral peer ID | TCP connections, BEP 10 parser/negotiation, DHT |
| `nulllobby-platform` | Owned zeroizing secret memory and Linux core-dump prevention | Lobby protocol or display logic |
| `nulllobby-cli` | Offline diagnostics and about/help text | Chat, terminal UI or connectivity |
| `xtask` | Developer build/package/version/release tasks | Application runtime state |

Core depends on transport and platform. Direct currently stands alone as a codec. Network implementations will implement the transport trait without forcing core to import their socket types. Every crate forbids unsafe code except the platform crate, where the Linux module contains documented FFI.

## Future connection path

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
 TCP + Mainline DHT         external Tor first
```

Direct will need a stream adapter that preserves BEP 10 framing and handshake/ciphertext outer tags. Tor will supply a framed onion stream. Application messages become legal only after the same Noise and identity authentication process for either mode. `Transport::start` does not imply cryptographic authentication.

The trait is object-safe and returns boxed `Send` futures. It covers start/stop, per-lobby endpoint creation/destruction, connect/accept, local transport identity and status. Endpoint handles are opaque process-local identifiers; backend implementations must check their ownership and lobby scope. Stop/destroy must terminate owned peer streams as well as listening endpoints.

## Ownership and state

`EphemeralIdentity` owns independently generated Ed25519 seed and future Noise static material. No identity object is clonable or serializable. Public keys are computed with Dalek; the retained seed uses a dedicated Linux mapping. Fingerprints and trust are public identity metadata, but still are not persisted by the application.

`LobbyCard` owns an optional capability and a bounded seed list. Public cards contain no authentication secret. Private cards carry the capability needed to derive the future PSK. Export returns a redacted `SecretString`, requiring an explicit caller decision to expose it. There is no UI export/clipboard path yet.

`LobbyTrust` is bound to a lobby ID, caps entries at 64 and defaults to unverified. Commands carry validated input; existing events contain no private keys. Full chat/presence events will be added alongside their verified payload types in Phase 3.

Transport-specific connection states are declared for later state machines. Phase 1 does not implement their transitions or accept any application messages. No enum declaration is treated as a completed security control.

## Transport choice

The future application owns one explicit transport choice. It must require leaving/rejoining to change mode inside a lobby. Tor mode has no Direct fallback. `NetworkObserver` is the injection seam for future tests; the mode policy rejects nonlocal-Tor actions when Tor is selected. Backends must make it impossible to bypass this seam in application-controlled networking.

Onion endpoints are modeled as a 32-byte v3 service public key and a nonzero virtual port. No DNS hostname or clearnet address is accepted in a Tor card. Address construction/checksum validation against the Tor v3 format belongs to the future Tor backend. No onion keypair or service is created in Phase 1.

## Platform roadmap

Linux first. Later Windows `x86_64-pc-windows-msvc`, then optional ARM64; macOS ARM64, then optional x86_64. Both desktops should share Iced code over the existing core. No Electron. Add VirtualLock and suitable dump controls for Windows; appropriate memory locking, signing and notarization for macOS. Signing credentials stay outside the repository.

## Renaming

1. Change presentation constants in `crates/nulllobby-core/src/branding.rs`.
2. Update package/binary names, the workspace path dependencies, Debian metadata, Make/release artifact names and repository URLs.
3. Update README/banner/about text and wiki navigation.
4. Keep existing protocol domains, card prefix and versioned wire identifiers stable for compatibility. A display-name change does not justify changing security domains.
5. If a wire rename is required, design an explicit version migration and tests; do not silently reinterpret existing invitations.

There is no hidden executable name in cryptographic key derivation: the labels are explicit versioned protocol constants documented in the protocol guide.
