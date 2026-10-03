# Getting started

For keyboard shortcuts, compact paste, themes (including irssi import), optional remembered public lobbies and autoconnect, see [Terminal and themes](Terminal). Headless local/OpenAI/Claude setup is in [Bots](Bots).

NullLobby is a Linux terminal preview. Direct, external Tor, Noise sessions, signed gossip and manual fingerprint verification are implemented. There is no independent professional security audit.

## Build

Use Linux x86-64 with Rust 1.94+, a C linker and Make:

```sh
make build
./target/x86_64-unknown-linux-gnu/release/nulllobby --self-check
./target/x86_64-unknown-linux-gnu/release/nulllobby
```

Core-dump prevention must succeed before chat starts. Memory locking is best effort and its actual status appears under `/privacy`. Normal runtime needs no writable HOME. No application config file, chat database or identity storage is created.

## First lobby

1. `/nick operator` selects a cosmetic nickname.
2. `/create private team` makes a random private capability and a fresh lobby identity.
3. `/invite` explicitly reveals a card. Esc hides it. Share it only with intended members.
4. Other users enter `/join <card>`; pasted card input is hidden by the UI once the `/join ` prefix is present.
5. `/fingerprint` and `/who` show complete SHA-256 fingerprints. Compare them out of band.
6. `/verify <complete fingerprint>` records your comparison in this lobby only.
7. Type text and Enter to send. PgUp/PgDn scroll. Ctrl+C or `/quit` shuts down endpoints.

Use `/switch <number>` to select another lobby; `/lobbies` shows numbering. `/leave` removes the current lobby and its state. Rejoining or restarting gives a new identity and loses trust/history. `/reconnect` retries known seeds while the lobby remains active.

## Public choices

`/create public name` is unlisted by default: random rendezvous ID, no authentication secret. Anyone with the card may join. `/create discoverable name` is Direct-only and waits for `/confirm` after an enumeration warning. Names normalize to ASCII lowercase after trimming ASCII whitespace; only 1..64 letters, digits, '-' and '_' are allowed. Discoverable creation with the same normalized name finds the same public namespace.

## Local development

```sh
nulllobby --no-dht --listen 127.0.0.1:50001
nulllobby --no-dht --listen 127.0.0.1:50002 --peer 127.0.0.1:50001
```

Create a lobby in the first and join its exported card in the second. This path includes BitTorrent, BEP 10, Noise and identity authentication. Explicit `--peer` values must be numeric IP:port addresses and are Direct-only.

Public Direct connectivity requires a reachable listener on at least one peer. NAT mappings, firewall rules and VPN routing belong to the OS/network; automatic UPnP or NAT hole punching is absent. DHT stores only swarm rendezvous records, never chat or invites.

## Tor

Follow [Tor setup](Tor.md). Choose `--transport tor` at launch or `/transport tor` before creating/joining a lobby. No Direct sockets or DHT are started merely by launching in Tor mode. Transport changes require leaving all lobbies.

## Debian package

```sh
make deb
sudo apt install ./dist/nulllobby_0.3.0_amd64.deb
nulllobby
```

The package installs one binary plus documentation/licenses. It creates no service or Tor configuration. A build's minimum glibc is recorded in package dependencies. `--about`, `--version`, `--security` and `--self-check` run without a terminal and without network activity.
