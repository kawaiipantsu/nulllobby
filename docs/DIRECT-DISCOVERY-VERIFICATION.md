# Direct discovery regression — 0.5.2

## Defect and scope

A default Direct listener binds `0.0.0.0` on a random TCP port. Its invitation omits that unusable wildcard address, so another ordinary client relies on DHT rendezvous. The previous client sent `get_peers` directly to bootstrap routers. Live routers could return valid responses without routing contacts or tokens, leaving the lobby undiscoverable.

0.5.2 sends `find_node` to bootstrap routers before asking discovered storage nodes for peers and announcing the actual TCP listener port. It preserves the existing limits: 24 lookup queries, at most 64 routing candidates/peer results, 2048-byte replies, eight-byte random transactions, bounded decoder depth and token length, source/transaction matching, and read-only DHT operation. It does not implement a DHT database or change application encryption.

## Evidence recorded on 2026-10-04

| Check | Result |
| --- | --- |
| Original live announcement smoke test | Failed: 6 lookup queries, 2 replies, 0 tokens, 0 successful announcements |
| Same live smoke test after bootstrap correction | Passed: 24 lookups, 13 replies, 11 tokens, 10 successful announcements |
| Independent client lookup on public DHT | Passed after a retry; second client retrieved the first client's randomly chosen listener port in a fresh random namespace |
| Router/storage fixture | Router supplies contacts only to `find_node`; storage checks the token, read-only flag, explicit TCP port and `implied_port=0`; independent lookup finds the announced port |
| Default application workflow | Default wildcard/random listeners, DHT enabled, no configured peers, seedless public invite; peers authenticate and exchange signed chat through the real BitTorrent/BEP 10/Noise stack |
| Initially unavailable configured peer | Failure counter/category visible; `/reconnect` succeeds after the other participant starts |
| Unresponsive DHT | Bounded query times out; `/network` reports unavailable discovery and zero announcements |
| Tor separation | Existing successful and failed Tor integration tests pass; an injected DHT fixture is ignored in Tor mode |

The deterministic application test substitutes only the DHT bootstrap/storage endpoints with loopback fixtures. It does not substitute a plaintext application transport or bypass authentication. The two live DHT clients run on one test host; their result establishes discovery, **not** TCP reachability between the project owner's AWS and home networks. That specific deployment still needs a user retest.

Live checks generate disposable random namespaces and report counters only. They do not use operational invitations, capture chat, or print network addresses. Public DHT use exposes the test host's public IP to DHT nodes.

## Workspace gates

Rust 1.94.1: formatting, all-target/all-feature Clippy with warnings denied, default workspace tests (112 passed), all-feature workspace tests (116 passed), `cargo audit`, and `cargo deny check` passed. Optional external-service, screenshot and live-network tests remain ignored in the ordinary suites. The public-DHT tests above were invoked explicitly.

Existing documented dependency exceptions remain unchanged. No new cryptographic dependency or primitive was introduced. These checks are not an independent professional security audit.

## Reproduce

```sh
cargo test --locked -p nulllobby-direct --test discovery
cargo test --locked -p nulllobby-app --test chat
cargo test --locked -p nulllobby-direct --test live_dht -- --ignored --nocapture
make check
```

The third command contacts the public DHT and can fail due to network conditions. Normal CI uses bounded local fixtures. See [connection troubleshooting](wiki/Connectivity.md) for default end-user operation.

## Release and installation

The [0.5.2 release](https://github.com/kawaiipantsu/nulllobby/releases/tag/v0.5.2) targets source commit `43bd717399f4aaef00fa72ddff26aaca275f3288`. Both variants were built in pinned Debian 12 userspace with `libc6 (>= 2.36)`, signed through XXC Trust, and verified again after downloading all ten GitHub assets. The release Discussion notification was posted automatically.

The official `zerotrust` APT publication contained exactly the two expected package additions. Signed archive metadata and both package downloads matched the release originals; a separate public `apt-verify` passed. Both variants then installed by name from the public repository in separate clean Debian 12 containers, with exact download comparisons and successful offline checks. These containers share the host kernel.

The maintainer host upgraded its standard installation from 0.5.0 to 0.5.2 through APT. No other packages were added or removed. The installed executable matched the signed package; version, core-dump prevention, secret memory lock checks and offline diagnostics passed. Package hashes are recorded in the [APT guide](wiki/APT.md).

The [GitHub workflow run](https://github.com/kawaiipantsu/nulllobby/actions/runs/37188364626) records the independent CI jobs. Local gate results above do not imply that a remote CI job has finished.
