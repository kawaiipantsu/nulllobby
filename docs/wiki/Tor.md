# External Tor how-to

Install and maintain Tor using your operating system's supported packages. NullLobby does not install, reconfigure or launch the system daemon. The supported backend needs Tor v3 ephemeral services and SAFECOOKIE authentication.

## Daemon configuration

An example local Tor configuration:

```text
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth
ControlPort 127.0.0.1:9051
CookieAuthentication 1
```

Control access is powerful. Use normal OS permissions to grant your account access to the authentication cookie; never expose ControlPort publicly or make the cookie world-readable. Paths differ across installations. Supply the actual readable cookie path explicitly; NullLobby never follows a path supplied by an unauthenticated control server. Password and unauthenticated control methods are not accepted by this backend.

Wait for Tor to report bootstrap completion, then:

```sh
nulllobby --transport tor --tor-socks 127.0.0.1:9050 \
  --tor-control 127.0.0.1:9051 --tor-cookie /path/to/tor/control_auth_cookie
```

Create `/create private team` or `/create public team`. Export `/invite`, share the card, and join using `/join <card>`. Tor has no discoverable-name mode. Leave all current lobbies before changing transport.

## Protocol behavior

1. Connect to the numeric loopback ControlPort and issue `PROTOCOLINFO 1`.
2. Require SAFECOOKIE. Read exactly the configured 32-byte cookie, send a fresh challenge, verify the daemon's HMAC in constant time, then authenticate with the controller HMAC.
3. Require bootstrap `PROGRESS=100`; inspect the SOCKSPort configuration and probe SOCKS authentication support.
4. Bind a fresh service target on `127.0.0.1:0`.
5. Request `ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=...`. No `Detach`; no private-key response is requested or retained.
6. Validate the returned v3 address checksum/version. Every lobby has a different service endpoint.
7. Connect only to validated `.onion` destinations using SOCKS5 domain requests. No peer DNS, exits, DHT, trackers or direct peer sockets.
8. Run the same Noise suite and encrypted identity proof as Direct. Private lobbies require the PSK before exposing metadata.
9. Exchange signed encrypted onion advertisements with bounded expiry and sequence checks. At most eight entries are forwarded in one endpoint-list packet.

Separate random SOCKS authentication values are generated per lobby. The backend reports confirmed isolation only when the configured port explicitly lists `IsolateSOCKSAuth`; otherwise configuration semantics are unconfirmed. Tor's upstream defaults may provide isolation, but NullLobby does not infer a guarantee from them. The privacy screen advises explicit configuration.

Leaving closes peer streams and issues `DEL_ONION`. Closing the authenticated control connection removes any remaining non-detached services, including after an abort/crash. The client monitors control health every 15 seconds. A missing daemon or dead seed fails closed; no Direct fallback exists.

## Troubleshooting

- **Transport unavailable:** verify bootstrap completion, numeric loopback addresses, cookie file permissions and SAFECOOKIE support. Errors never echo credentials or control responses.
- **No reachable Tor lobby seed:** allow service publication time and retry `/reconnect`; obtain a current card from an online participant. If all seeds are offline, discovery is impossible in this MVP.
- **Lost service after daemon restart:** the lobby disconnects. Create/join again using a current card; new endpoints and identities are ephemeral.
- **Slow first connection:** introduction/rendezvous and publication can take longer than Direct. Connection attempts are bounded and retry periodically.

## Privacy limits

Peers receive onion endpoints, not public IPs. Tor itself usually remains visible to the local ISP/network. Bridges/pluggable transports can change observability when configured externally, but NullLobby has no bridge-management UI. Multi-point observers may correlate traffic. Noise remains mandatory over Tor.

The external daemon's guard/cache state is ordinary Tor state; preserve it. NullLobby never writes chat, identity keys or private invitations into it. Ephemeral service keys are kept in Tor memory. See [Privacy](Privacy.md) and [Arti review](Arti-Review.md).

## Tests

Normal tests use local Rust protocol fixtures and an instrumented network policy. Optional live smoke test:

```sh
NULLLOBBY_TEST_TOR_SOCKS=127.0.0.1:9050 \
NULLLOBBY_TEST_TOR_CONTROL=127.0.0.1:9051 \
NULLLOBBY_TEST_TOR_COOKIE=/path/to/tor/control_auth_cookie \
cargo test -p nulllobby-tor --test live -- --ignored
```

It creates temporary services, completes a private Noise session over an onion stream, exchanges synthetic text, and removes the services. It uses the daemon's existing guard state.
