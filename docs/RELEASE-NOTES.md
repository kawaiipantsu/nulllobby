## Linux preview

NullLobby now includes a Ratatui terminal client and the shared Rust networking/security core.

- Direct TCP uses the standard BitTorrent handshake, truthful NL_chat BEP 10 negotiation, bounded Mainline DHT discovery, Noise and encrypted identity proof.
- Public unlisted lobbies use random IDs. Private lobbies use 256-bit capabilities and XXpsk3. Discoverable Direct lobbies require an explicit enumeration warning confirmation.
- Independent per-lobby identities, full fingerprints, manual scoped verification, signed gossip, replay protection and bounded encrypted padding.
- External Tor uses SAFECOOKIE, onion-only SOCKS and distinct non-detached ephemeral v3 services per lobby. Tor failure never selects Direct.
- RAM-only application history/identity/trust, Linux core-dump controls, honest secret-memory lock reporting, strict terminal sanitation and bounded resources.
- Deterministic integration tests, opt-in live Tor/DHT smoke tests, nine Rust fuzz targets, Debian packages and version/release tooling.

### Limits

Direct exposes IPs and recognizable BitTorrent/extension metadata. Tor does not guarantee anonymity against traffic correlation. Restarting loses identities, trust and history. Delivery acknowledgements, durable/offline delivery, automatic NAT traversal and capability revocation are absent.

No independent professional security audit has yet been completed. Internal cryptographic library state is not all locked or guaranteed to zeroize. Embedded Arti remains explicitly unavailable pending per-service RAM-state review. Windows/macOS desktop clients are deferred.
