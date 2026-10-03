Public lobbies will be **unlisted by default**, using random rendezvous IDs shared in cards. Private lobbies use random 256-bit capabilities, not human passwords. Discoverable Direct lobbies need an explicit enumeration warning. Tor discovery will use onion seeds rather than Mainline DHT.

The privacy distinction must stay visible:

- Direct: encrypted communications, IP addresses exposed to peers and observable BitTorrent/DHT metadata.
- Tor: per-lobby ephemeral onion endpoints, independent Noise encryption, no clearnet fallback. Tor use and powerful traffic-correlation observers remain concerns.

The networking implementations are not available in Phase 1. This is a design discussion for later phases.

Useful questions:

- How should a stale invitation explain that every Tor seed is offline?
- What member/reconnect behavior fits ephemeral identities without silently carrying trust across restarts?
- How should `/invite` warn about terminal scrollback while keeping explicit sharing practical?
- What bounded peer/seed limits are reasonable for small authorized teams?
- Which chat features matter enough to justify additional metadata?

Bring fictional scenarios and privacy tradeoffs, not real onion endpoints or private cards. [Privacy guide](https://github.com/kawaiipantsu/nulllobby/wiki/Privacy) · [Roadmap](https://github.com/kawaiipantsu/nulllobby/wiki/Roadmap).
