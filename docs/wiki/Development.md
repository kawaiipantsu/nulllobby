# Development and testing

## Required gates

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo audit
cargo deny check
```

CI also uses `--locked` where applicable, builds a Debian package and runs the release executable with `HOME=/proc`. `make check` requires all five tools; it does not silently skip audit/deny. The workflow uses pinned action commits, a pinned Rust toolchain and minimum permissions. No Python scripts or wrappers are used.

## Current tests

- Independent keys for different lobbies and recreated identities; separate random Ed25519/Noise input.
- Complete fingerprint known answer and strict parsing; random public IDs; capability generation independent of names.
- RFC 5869 known-answer KDF test and separated outputs.
- Public/private Direct/Tor card round trips, IPv4/IPv6, maximum seed count, duplicate/mixed seeds, wrong prefix/version/type, invalid private ID/capability relationship, zero ports, checksummed trailing data, all truncations, corrupt base64/checksum and excessive sizes.
- Exact BitTorrent wire offsets, reserved-bit preservation, extension/swarm validation, truncated/oversized/invalid protocol input and random peer IDs.
- Lobby-scoped, bounded trust and bounded-channel backpressure/closure.
- Terminal escape/OSC/control/bidi rejection, UTF-8 byte limits and every Unicode control tested against the sanitizer.
- Secret redaction/explicit zeroization, independent allocation ownership, and process-isolated Linux core-limit/dumpable checks with locked-memory-limit reduction.
- CLI diagnostics with unwritable HOME and rejection of unsupported arguments without reflecting input.
- Major/minor/patch version transitions and actual ELF glibc requirement parsing.

Tests are not a security audit or a substitute for fuzzing. Randomness separation assertions check correct construction; they do not prove the entropy source cryptographically.

## Resource limits

| Resource | Current bound | Enforcement status |
|---|---|---|
| Card text / binary | 768 / 512 bytes | Parser enforced |
| Seeds/card | 8 | Parser/constructor enforced |
| BitTorrent handshake | 68 bytes exactly | Parser enforced |
| Nickname / lobby name | 64 / 128 UTF-8 bytes | Constructors enforced |
| Validated chat body | 8192 UTF-8 bytes | Type constructor enforced; no messaging yet |
| Command / event queues | 32 / 128 entries | Bounded channels |
| Trust entries | 64 per lobby | Store enforced |
| Global peers / peers per lobby | 128 / 64 | Constants only; backend enforcement deferred |
| Pending handshakes / frame bytes | 32 / 65536 | Constants only; handshake/record enforcement deferred |

Future work must bound every receive/send/gossip queue, decoded collection, member list and endpoint list. Do not allocate directly from hostile length fields. Set handshake/idle timeouts and cancellation/cleanup semantics before enabling networking.

## Deferred security regressions

Phases 2–7 must add actual captured-byte confidentiality tests, wrong-PSK metadata withholding, signature/binding failures, replay/gossip limits, distinct ephemeral onion services, endpoint separation across lobbies, service cleanup, and injected failures proving **no Tor-to-Direct/DHT/DNS fallback**. The existing mode-policy unit test is not a Tor integration test. BEP 10 metadata absence cannot be tested until BEP 10 exists.

Phase 8 adds cargo-fuzz for BitTorrent/BEP 10/bencode, cards/invites, Noise outer frames, application decoding, endpoint advertisements and terminal sanitization. Use Rust harnesses, bounded allocation and fixed corpus examples. No Python fuzz wrappers. Sanitizer/Miri review of platform ownership should supplement ordinary tests where supported.

## Dependencies

See the repository's [dependency review](https://github.com/kawaiipantsu/nulllobby/blob/main/docs/DEPENDENCIES.md). Phase 1 intentionally has no `snow`, `mainline`, Tor, UI, serde application codec or filesystem runtime dependency. Tokio enables only IO utility and bounded sync features; `net`, `fs` and process features are not enabled by the application.

Review upstream APIs before implementation, not from remembered examples. For Phase 2 verify exact XX/XXpsk3 support and RustSec status. For Phase 4 inspect current `mainline` API/maintenance. For Phase 9 inspect Arti's current onion hosting/connect APIs and maturity before adding `tor-arti-experimental`.

## Repository hygiene

Application errors must not include remote payloads or unsupported argument values. Avoid `Debug` implementations that reveal private material. No credentials or real operational examples in tests, CI artifacts, docs or Discussions. Use the configured Git author identity, with no invented author/co-author. Release artifacts remain ignored under `dist/`; source, lockfile and license are committed.
