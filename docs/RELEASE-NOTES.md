# NullLobby 0.5.2 — Direct invitation discovery

Fixes a DHT bootstrap defect that could leave ordinary create → invite → join sessions at **LISTENING / NO PEERS**. The client now asks bootstrap routers for routing contacts with BEP 5 `find_node`, then uses `get_peers` and token-authenticated `announce_peer` on the discovered nodes. Previously, routers could return empty responses to `get_peers` and discovery never reached the nodes storing lobby announcements.

## Changes

- Default public and private invitations retain the same workflow; no extra launch flags are required.
- Initial and failed discovery rounds retry after ten seconds. Successful periodic discovery returns to a two-minute pause after the initial rounds. `/reconnect` also requests a bounded, coalesced DHT refresh.
- F5 and `/network` show the local listener, last-round DHT counters, pending connections, failed outbound attempts and a fixed error category. The header distinguishes discovery and connection attempts from an idle listener.
- Configured `--peer` endpoints are retried after an initial failure.
- Regressions cover a router that only supplies contacts through `find_node`, independent lookup, a default wildcard listener with a seedless invite and encrypted signed chat, failed discovery, and retrying an initially unavailable peer. Tor tests retain the no-DHT/no-Direct invariant.

## Upgrade both clients

With the [official APT repository configured](https://github.com/kawaiipantsu/nulllobby/wiki/APT):

```sh
sudo apt update
sudo apt install nulllobby
nulllobby --version
```

Quit and restart both running clients after upgrading. Recreate the lobby and share its new invitation when using ephemeral sessions. Protocol/card v2 and encryption suites are unchanged from 0.5.0/0.5.1; this patch adds no protocol downgrade or plaintext path.

Direct discovery is asynchronous. At least one participant's TCP listener must be reachable, with DNS and outbound UDP allowed for DHT. This patch does not add automatic port forwarding or NAT hole punching. See [connection troubleshooting](https://github.com/kawaiipantsu/nulllobby/wiki/Connectivity).

Both amd64 package variants retain the Debian 12 baseline, `libc6 (>= 2.36)`. Embedded Arti remains experimental. Direct exposes peer IPs; Tor never falls back to Direct. No independent professional security audit has been completed.
