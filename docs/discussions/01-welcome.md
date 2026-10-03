NullLobby is being built for THUGS(red) and other security teams coordinating authorized work. The source and protocol are public by design; security must not rely on obscurity.

**The initial implementation is Phase 1 only:** Rust workspace, ephemeral per-lobby identities, random lobby capabilities/IDs, bounded card and BitTorrent handshake codecs, Linux hardening, tests, packaging and documentation. The executable is an offline diagnostic tool. Messaging, Noise sessions, DHT, Tor and the TUI are still planned. No independent professional security audit has been completed.

Where should the Linux IRC-style workflow focus first?

- How should lobby switching, member lists and reconnection behave during an engagement?
- Which security details need to remain visible while typing?
- What should a useful `/privacy` view explain without suggesting that encryption equals anonymity?
- What synthetic local testing scenarios would help you contribute?

Start with the [README](https://github.com/kawaiipantsu/nulllobby) and [wiki](https://github.com/kawaiipantsu/nulllobby/wiki). Please use fictional examples; do not post live operation details, private invitations, keys or identifying environment data.
