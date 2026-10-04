# Roadmap

| Phase | Status |
|---|---|
| 1: workspace, identities, capabilities, cards, memory controls, handshake | Implemented |
| 2: BEP 10, exact Noise suites, encrypted identity proof/framing | Implemented |
| 3: canonical signed messages, replay and bounded gossip | Implemented |
| 4: Direct DHT, public/private/discoverable joining | Implemented; IPv4 public DHT, explicit IPv6 TCP seeds |
| 5: Linux Ratatui interface and command/event boundary | Implemented |
| 6: external Tor SAFECOOKIE/SOCKS, ephemeral per-lobby onions | Implemented |
| 7: Tor fail-closed/privacy regressions and encrypted padding | Implemented |
| 8: fuzz targets, implementation review, docs, CI/packages | Implemented; longer campaigns and independent audit still needed |
| 9: experimental embedded Arti | Implemented behind an opt-in feature; local storage patch and documented dependency exceptions remain |
| 10: Windows/macOS Iced GUI | Deferred; Linux/shared core remain the selected scope |

## 0.5.0 Linux additions

- Managed private capability rotation and fingerprint exclusion, with individually addressed encrypted replacement offers.
- Separately opted-in encrypted per-lobby identities, sender outboxes and peer mailboxes.
- Signed received/stored receipts, bounded retry/replay, expiry and durable duplicate suppression.
- Optional offline organization credentials scoped to a lobby/key, separate from human verification and private admission.
- Protocol/card v2, new fuzz targets, migration and privacy/storage documentation.

The existing Linux UX, irssi color/style import, screenshots, headless local/cloud bots, release signing and APT publishing remain available. Bots ignore durable/replayed records; cloud bots remain disabled under Tor.

## Remaining work

Seek independent review of cryptography, storage, rotation and mailbox semantics before broader sensitive deployment. Extend multi-hour load/partition/interoperability tests and fuzz coverage. Review the Arti storage patch upstream before treating embedded Arti as stable.

Future features need separate designs: organization-only admission, live XXC membership enrollment over a reviewed Tor-only path, issuer rollover/revocation snapshots, administrator recovery/transfer, hardware-backed rollback resistance, mailbox replication/availability policy, NAT traversal, bridges and Windows/macOS clients. Current receipts do not guarantee all-member delivery, a human reading a message or honest retention by a mailbox.
