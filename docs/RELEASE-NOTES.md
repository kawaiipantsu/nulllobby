## Phase 1 — offline foundations

This release provides the Rust workspace, transport interfaces, ephemeral lobby identity and capability primitives, strict lobby-card and BitTorrent handshake codecs, Linux memory/process hardening, and an offline diagnostic executable.

It includes Rust build/version/release tooling, Debian packaging, CI and technical documentation. Application state is held in memory.

**This is not a working chat client.** No Noise session, message exchange, DHT, Tor, TUI or GUI is implemented. Do not use it for sensitive communications. No independent professional security audit has yet been completed.

Next: Phase 2, Direct BEP 10 negotiation, reviewed Noise XX/XXpsk3 support, encrypted framing and encrypted identity proofs. Direct networking remains visibly non-anonymous; Tor will require fail-closed onion-only operation in later phases.
