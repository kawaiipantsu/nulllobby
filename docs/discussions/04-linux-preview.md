# Linux preview: Direct and Tor lobby chat are ready for testing

The Linux terminal client and shared Rust core now support encrypted decentralized lobby chat: private capabilities, public unlisted cards, explicitly discoverable Direct lobbies, independent lobby identities, full fingerprints and manual verification.

Direct uses BitTorrent/BEP 10, bounded Mainline DHT discovery and Noise. Direct exposes IP addresses. External Tor uses SAFECOOKIE, onion-only SOCKS and a separate ephemeral onion service per lobby; failures never switch to Direct. Both modes require Noise and encrypted identity proof, then forward signed messages with bounded replay protection.

Validation includes three-peer signed gossip, successful multi-lobby Tor sessions with network instrumentation, unavailable Tor and daemon-failure tests, hostile-peer flooding, live Tor/DHT smoke tests and nine parser fuzz targets. Debian packages, version bumps and draft-release tooling are included. See the [verification report](https://github.com/kawaiipantsu/nulllobby/blob/main/docs/VERIFICATION.md) and [getting-started guide](https://github.com/kawaiipantsu/nulllobby/wiki/Getting-Started).

This is an experimental preview. No independent professional security audit has yet been completed. Identities, trust and history disappear at exit. Embedded Arti is deferred pending per-service RAM-state review; native Windows/macOS clients come later.

## Feedback that would help

- Which IRC-style workflows matter most during authorized team coordination?
- Are the separate transport, IP exposure and verification indicators clear enough?
- What should a useful offline-seed/reconnect experience look like without a centralized directory?
- Review the canonical protocol, replay limits, private-capability model and Tor isolation semantics. Which interoperability or adversarial tests should we add next?

Use synthetic examples and test lobbies. Keep operational chat, private invitations and credentials out of public reports.
