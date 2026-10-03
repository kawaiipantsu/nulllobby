# Experimental embedded Arti

Reviewed upstream `arti-client` and `tor-hsservice` **0.47.0** on 2026-10-03. This is a design review, not an independent security audit.

The current API supports bootstrapping, onion connections, `TorClient::launch_onion_service`, and an optional ephemeral keystore. Onion hosting itself exists; lack of a hosting API is not the reason for deferral.

The supported high-level service launcher attaches the client's persistent state directory. An ephemeral keystore alone does **not** keep all service state in RAM. NullLobby uses the lower-level launcher with a local storage patch; the normal persistent launcher is not used.

The patch creates a fresh in-memory key store per lobby and supplies no filesystem handle for service state. Introduction-point records and publication times remain in existing runtime structures. Replay filters stay in memory, retain history for the key's lifetime, and fail closed after 100,000 insertions. No temporary filesystem is used for service state. See the [patch record](https://github.com/kawaiipantsu/nulllobby/blob/main/vendor/tor-hsservice/NULLLOBBY-PATCH.md).

Normal Tor guard state and directory cache remain persistent. Arti uses its normal SQLite directory cache; NullLobby messages, identities, trust, invitations and service keys are never stored there. Do not delete Tor state to simulate application RAM-only behavior. Library allocations, OS swap and hibernation remain subject to the memory limitations in SECURITY.md.

## Build and run

```sh
make build-arti
./target/x86_64-unknown-linux-gnu/release/nulllobby \
  --transport tor --tor-backend arti \
  --arti-state /absolute/tor-state --arti-cache /absolute/tor-cache
```

Supply distinct absolute paths for normal Tor state; keep Arti's permission checks enabled. Bootstrap progress and service state appear as notices. The standard build rejects `--tor-backend arti`; compile the feature explicitly. `--tor-backend external` remains the default and uses SAFECOOKIE/SOCKS options. Neither backend falls back to the other or to Direct.

`make deb-arti` creates a separately named `nulllobby-arti-experimental` package and archive. It provides the same executable and conflicts with the standard package. It includes extra dependency notices and the advisory review. It does not install a service or create Tor state until explicitly run with the Arti backend.

## Runtime boundaries

- One shared Tor client handles relay connectivity. Each lobby gets an isolated outgoing client and a distinct ephemeral service/key store.
- Peer destinations are typed v3 onion endpoints only. No exit peers, peer DNS, DHT, SOCKS, ControlPort or Direct backend is used by Arti mode.
- Commands, lobby cards, Noise proofs and signed messages use the same core as external Tor.
- Bootstrap has a 180-second deadline; connections have a 60-second deadline. Unavailable relay/service state closes the lobby's streams.
- Each service permits at most 16 rendezvous handlers and eight queued incoming streams, plus the shared 128-peer/32-handshake limits. Wrong ports/request types close the circuit.
- Arti tracks Tor queues against a 64 MiB quota, with a 48 MiB low-water mark. This is approximate accounting, not a hard bound on total memory.
- Leaving drops the service and cancels handlers and peer streams. Shared Tor relay maintenance may continue until process exit; guard/cache state is preserved.

## Experimental status and checks

This backend changes a security-sensitive upstream component locally. It is not an upstream-approved or independently audited Arti release. The default binary continues to use external Tor. The [dependency review](https://github.com/kawaiipantsu/nulllobby/blob/main/docs/ARTI-DEPENDENCIES.md) records the RSA advisory applicability assessment and transitive maintenance exceptions.

```sh
cargo test --locked --workspace --all-features
cargo test --locked --manifest-path vendor/tor-hsservice/Cargo.toml \
  --lib --features ephemeral-service
```

The ignored real-network test requires `NULLLOBBY_TEST_ARTI_STATE` and `NULLLOBBY_TEST_ARTI_CACHE` (absolute paths). It bootstraps, creates independent services, establishes private Noise, checks encrypted delivery and cleanup, and asserts that persistent Tor state contains no service/keystore directories. It can fail on restricted networks or slow descriptor publication. Preserve guard state between retries.

## Upstream sources

- [arti-client 0.47.0](https://docs.rs/arti-client/0.47.0/arti_client/)
- [TorClient source](https://docs.rs/arti-client/0.47.0/src/arti_client/client.rs.html), `launch_onion_service` and ephemeral keystore initialization
- [tor-hsservice 0.47.0](https://docs.rs/tor-hsservice/0.47.0/tor_hsservice/)
- [Arti source repository](https://gitlab.torproject.org/tpo/core/arti)

Future desktop clients are also deferred. Both will reuse the current core and command/event boundary; Iced is the intended native UI toolkit.
