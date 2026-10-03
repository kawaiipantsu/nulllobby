## NullLobby 0.3.0 — experimental embedded Arti

The Linux client can now use embedded Arti behind `tor-arti-experimental`. External Tor remains the default Tor backend.

- Arti 0.47.0 with distinct ephemeral onion services and native outgoing stream isolation per lobby.
- A documented local `tor-hsservice` patch keeps service keys, publication state and replay filters in RAM. Ordinary Tor guard state and directory cache remain persistent in explicitly configured paths.
- The same Noise, identity proof, signed gossip and trust rules apply to Direct, external Tor and embedded Arti. Backend failures never select another transport.
- Bootstrap progress, bounded service handlers, resource accounting and service/stream cleanup.
- Separate standard and experimental Debian packages, dependency notices, and version bumps that preserve vendored and fuzz harness versions.

Build the standard package with `make deb`, or explicitly select `make deb-arti`. The experimental package additionally requires `libsqlite3-0` for Arti's Tor directory cache; it does not store chat there. Packages conflict because both install `/usr/bin/nulllobby`.

### Review before enabling Arti

The backend includes a local change to security-sensitive upstream code. It is experimental and has not received an independent professional security audit. The expanded dependency graph has a documented RSA advisory applicability exception and transitive maintenance warnings; see [the dependency assessment](https://github.com/kawaiipantsu/nulllobby/blob/main/docs/ARTI-DEPENDENCIES.md).

Direct exposes peer IPs. Tor cannot guarantee protection against sufficiently powerful traffic correlation. Restart loses application identities, trust and history. Delivery acknowledgements, durable offline delivery, automatic NAT traversal and capability revocation remain absent. Windows/macOS desktop clients remain deferred.
