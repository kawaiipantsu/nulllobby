# Embedded Arti review

Reviewed upstream `arti-client` and `tor-hsservice` **0.47.0** on 2026-10-03. This is a design review, not an independent security audit.

The current API supports bootstrapping, onion connections, `TorClient::launch_onion_service`, and an optional ephemeral keystore. Onion hosting itself exists; lack of a hosting API is not the reason for deferral.

The supported high-level service launcher also attaches the client's persistent state directory. Its source has explicit TODOs for overriding the KeyMgr and StateMgr for ephemeral operation. The introduction-point manager writes per-service records containing relay identifiers, introduction-point IDs and retirement history. An ephemeral keystore alone therefore does **not** establish that all lobby-related service state stays in RAM.

NullLobby's requirement is stricter than merely generating a new onion identity. Before accepting this backend, review how to keep per-lobby service state and all service key material ephemeral while preserving Tor's normal durable guard/cache state. Do not erase guards or turn every Tor state directory into temporary storage as a shortcut.

The `tor-arti-experimental` Cargo feature exposes an explicit unavailable-backend constructor. It returns `Unsupported`; it cannot choose Direct or silently select a different backend. No Arti dependency graph is included in the stable Linux binary. The external-daemon Tor backend is implemented and tested independently.

## Proposed backend

- Implement the existing `Transport` trait in an isolated backend module.
- Bootstrap one Tor client; retain ordinary Tor guard/cache state under an explicitly selected Tor state policy.
- Generate an independent service nickname and onion key for every lobby; use a proven in-memory service key/state provider.
- Adapt Arti streams to the common byte-stream interface; keep Noise and identity proof unchanged.
- Use stream isolation per lobby, bounded rendezvous handlers, 128 global peers and 32 pending handshakes.
- Treat relay connectivity as the Tor implementation boundary. Peer destinations remain validated v3 onions only.
- Re-run the same failure, scope, cleanup, capture and wrong-PSK tests before offering the backend in the UI.

## Upstream sources

- [arti-client 0.47.0](https://docs.rs/arti-client/0.47.0/arti_client/)
- [TorClient source](https://docs.rs/arti-client/0.47.0/src/arti_client/client.rs.html), `launch_onion_service` and ephemeral keystore initialization
- [tor-hsservice 0.47.0](https://docs.rs/tor-hsservice/0.47.0/tor_hsservice/)
- [Arti source repository](https://gitlab.torproject.org/tpo/core/arti)

Future desktop clients are also deferred. Both will reuse the current core and command/event boundary; Iced is the intended native UI toolkit.
