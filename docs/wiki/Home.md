# NullLobby

A RAM-first decentralized encrypted lobby chat client created by Kawaiipantsu for THUGS(red), for authorized security work and internal coordination.

The Linux preview implements Direct and external Tor transports, Noise encryption, independent lobby identities, signed gossip and fingerprint verification. Direct exposes peer IPs. Tor uses onion services and never falls back to Direct. Unsaved identities and live history disappear at process exit; human trust always stays in RAM. Explicit encrypted vaults support saved per-lobby identities and separately enabled durable outboxes/peer mailboxes. No independent professional security audit has yet been completed.

- [Getting started](Getting-Started)
- [Terminal and irssi themes](Terminal)
- [Screenshots](Screenshots)
- [Local and cloud bots](Bots)
- [Encrypted storage and offline delivery](Storage-and-Delivery)
- [Private rotation and revocation](Private-Lobbies)
- [Optional organization membership](Organization)
- [External Tor setup](Tor)
- [Architecture and renaming](Architecture)
- [Protocol v2](Protocol)
- [Privacy and VPN guidance](Privacy)
- [Development and fuzzing](Development)
- [Build, packages and releases](Releases)
- [Roadmap](Roadmap)
- [Embedded Arti review](Arti-Review)
- [Repository](https://github.com/kawaiipantsu/nulllobby)
- [Community Discussions](https://github.com/kawaiipantsu/nulllobby/discussions)

The wiki's source is versioned under `docs/wiki` in the main repository. Licensing: AGPL-3.0-or-later.
