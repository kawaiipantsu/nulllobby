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
| 9: experimental embedded Arti | Implemented behind an opt-in feature, with a reviewed local service-storage patch and explicit dependency exceptions |
| 10: native Windows/macOS Iced GUI | Deferred; user selected Linux/shared core first |

## Next phase

Phase 9 uses the existing Tor core/protocol with separate RAM-only service state. Review the local patch with upstream and extend soak/interoperability coverage before treating embedded Arti as stable. External Tor remains available independently.

The next requested product work is a Linux UX pass: compact pasted blocks, timestamps and day separators, panel/menu shortcuts, optional Nerd Font icons, themes and bounded irssi-theme import, clearer connection/privacy status, dismissible welcome/help/notification overlays, and opt-in remembered preferences/lobbies/autoconnect. Identities, trust and history remain ephemeral. Bot mode with local and explicitly selected cloud model providers is also requested; it must preserve transport privacy and clearly disclose the bot/provider boundary.

The shared Iced Windows/macOS desktop client (Phase 10) remains deferred until requested. It will reuse the current core and command/event boundary.

Before broader deployment, seek an independent professional security audit and longer fuzz/load/interoperability campaigns. Known functional limits include no automatic NAT traversal, durable/offline delivery, delivery receipts, persistent identities or private-capability revocation. None of those features should be implied by the current UI.
