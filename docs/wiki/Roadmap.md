# Roadmap

| Phase | Status |
|---|---|
| 1: workspace, identities, capabilities, cards, memory controls, handshake | Implemented |
| 2: BEP 10, exact Noise suites, encrypted identity proof/framing | Implemented |
| 3: canonical signed messages, replay and bounded gossip | Implemented |
| 4: bounded Direct DHT discovery, public/private/discoverable joining | Implemented; IPv4 public DHT, explicit IPv6 TCP seeds |
| 5: Linux Ratatui interface and command/event boundary | Implemented |
| 6: external Tor SAFECOOKIE/SOCKS, ephemeral per-lobby onions | Implemented |
| 7: Tor fail-closed/privacy regressions and bounded encrypted padding | Implemented |
| 8: parser fuzz targets, implementation review, documentation, CI/packages | Implemented; longer campaigns and independent audit remain recommended |
| 9: experimental embedded Arti | Reviewed and deferred pending per-service RAM-state separation; feature explicitly returns Unsupported |
| 10: native Windows/macOS Iced GUI | Deferred; user selected Linux/shared core first |

## Next phase

Resolve the embedded Arti service-state boundary described in [Arti review](Arti-Review.md), then implement and subject it to the same transport tests. Keep external Tor available independently. Do not persist application onion keys or delete Tor guard state to simplify the backend.

Before broader deployment, seek an independent professional security audit and longer fuzz/load/interoperability campaigns. Known functional limits include no automatic NAT traversal, durable/offline delivery, delivery receipts, persistent identities or private-capability revocation. None of those features should be implied by the current UI.
