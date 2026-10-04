# NullLobby 0.5.3 — Live DHT status

Direct mode now shows discovery progress live in a dedicated header row. Counters update while requests are in flight, so opening `/network` repeatedly is no longer necessary.

```text
DHT: Bootstrapping...
DHT: Discovering | Q/8 R/5 T/4 A/3 - 2 candidates
DHT: Ready | Q/24 R/13 T/11 A/10 - 2 candidates
```

## Changes

- `Q/R/T/A` show lookup attempts, matching replies, received tokens and acknowledged announcements. Candidates are endpoints found before authentication.
- Counters reset at the start of each round and remain visible afterward. Failure/retry and disabled states are explicit; each lobby has its own snapshot.
- Narrow terminals use compact labels. Tor shows no DHT row and never starts Direct discovery.
- Progress snapshots replace older snapshots without queuing every update. The app publishes live progress up to ten times per second; progress reporting does not wait for the display.
- Peer connectivity, encryption and verification remain separate. `DHT: Ready` means an announcement succeeded.
- Tests hold a DHT reply pending to verify that intermediate counts reach the application, then check completion and counter resets. Renderer tests cover narrow widths, lobby switching and Tor separation. Documentation includes an updated discovery screenshot.

## Upgrade

With the [official APT repository configured](https://github.com/kawaiipantsu/nulllobby/wiki/APT):

```sh
sudo apt update
sudo apt install nulllobby
nulllobby --version
```

Restart a running client after upgrading. Recreate the lobby and share its new invitation when using ephemeral sessions. Protocol/card v2 and encryption suites remain compatible with 0.5.0–0.5.2. No configuration change is required.

Direct discovery is asynchronous. At least one participant's TCP listener must be reachable, with DNS and outbound UDP allowed for DHT. See [connection troubleshooting](https://github.com/kawaiipantsu/nulllobby/wiki/Connectivity).

Both amd64 package variants retain the Debian 12 baseline, `libc6 (>= 2.36)`. Embedded Arti remains experimental. Direct exposes peer IPs; Tor never falls back to Direct. No independent professional security audit has been completed.
