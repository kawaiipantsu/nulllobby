# Privacy and security choices

This page describes the Linux preview. Direct, external Tor and opt-in experimental embedded Arti are implemented; desktop clients remain deferred. No independent professional security audit has yet been completed.

## Direct

Status: `DIRECT / ENCRYPTED / IP EXPOSED TO PEERS`.

Direct uses BitTorrent TCP/BEP 10, Mainline DHT discovery, and independent Noise encryption. Peers see source IP addresses. DHT infrastructure/crawlers can observe IP/swarm metadata. Network observers can recognize BitTorrent and may recognize the truthful `NL_chat` extension. A random port and peer ID avoid unnecessary stable identifiers; they do not make traffic anonymous.

The DHT holds only rendezvous announcements. No messages, nicknames, member lists, private capabilities, identity keys or chat database. A shared DHT instance can correlate lobbies by source IP regardless of random identity fields.

## Tor

Status: `TOR / ENCRYPTED / ONION TRANSPORT`.

Tor mode connects v3 onion services to v3 onion services. Every process/lobby gets a distinct ephemeral onion service, never one cross-lobby address. Identity keys and onion identities remain independent. Noise is still mandatory.

An external Tor daemon is the first backend: local SOCKS, authenticated local ControlPort, an application listener bound to loopback, and supported v3 ephemeral-service creation. Do not detach services or persist their private keys. The application must delete them on lobby leave/shutdown where possible; ownership by the control connection provides cleanup on connection loss.

**Tor selection must never fall back to Direct.** No Mainline DHT, UDP discovery, trackers, remote peer DNS, direct peer TCP, clearnet addresses in lobby metadata, or exit connections. Tor unavailability means disconnect and an explicit error. Only configured local control/SOCKS connections are allowed at the external-backend boundary.

Tor lobby cards contain one or more current onion seeds. After PSK/identity authentication as appropriate, peers exchange bounded signed encrypted endpoint advertisements for this lobby only. If all seeds are offline and there are no other known peers, joining fails with `No reachable Tor lobby seed`. There is no central directory or magical global name lookup.

Distinct random SOCKS credentials per lobby request isolation. The backend inspects the configured SOCKSPort; only an explicit matching IsolateSOCKSAuth option is reported as confirmed. A username/password alone is not proof of isolation. Do not force a new circuit for each message.

Tor hides peer public IPs from other lobby participants but is not a mathematical anonymity guarantee. A powerful observer across multiple network points may correlate traffic. A local ISP/network observer can generally see Tor use unless bridges/pluggable transports change that visibility. Bridges are optional future work and do not make identification impossible.

## Public versus private lobbies

| Lobby | Discovery | Authorization |
|---|---|---|
| Public unlisted (default) | Random 256-bit lobby ID and shareable card | Anyone with the card may attempt to join; no secret |
| Private | Capability-derived ID and optional seed endpoints | A random 256-bit capability derives the Noise PSK |
| Public discoverable (Direct only) | Precisely normalized public name, deterministic namespace | Public; identifiers can be enumerated/monitored |

Before discoverable create/join, show: `WARNING: discoverable lobbies can be enumerated and monitored through their public discovery identifier.` No discoverable Tor lobbies in the MVP.

Public encryption does not prove that a first-seen key belongs to a named person. Show `encrypted / unverified` until users compare the **full fingerprint** out of band and explicitly verify it for this lobby. Then show `encrypted / verified`. Nicknames are cosmetic.

## RAM-only application state

Independent per-lobby Ed25519 seeds and Noise static material are generated afresh. Restart means new fingerprints. Trust, history, private invitations and identity secrets disappear at exit.

Optional remembered preferences save a nickname, appearance settings and explicitly selected public lobby cards/seeds with autoconnect flags. Defaults write none of this. Saved metadata can correlate activity even though keys rotate. Private capabilities cannot be saved. See the Terminal guide for opting in, deleting preferences and first-start behavior.

Optional bots send only explicitly addressed prompts to the selected provider. Cloud APIs require explicit opt-in and are disabled in Tor mode. Local loopback models are supported; the model service's own retention/network behavior is outside NullLobby. See the Bots guide.

`mlock` and zeroization reduce exposure but do not cover all temporary copies, kernel buffers, physical acquisition or a compromised endpoint. Terminal scrollback and clipboard managers are outside the security boundary. Never copy a private invite to the clipboard automatically. Even explicit invite display may leave a terminal record.

An external Tor daemon may keep ordinary Tor state, cache and guard information. This is distinct from NullLobby application state. Do not delete/rotate Tor guards for a superficial RAM-only claim; doing so can harm anonymity. Application onion keys must still be ephemeral, and chat/identity secrets must never enter Tor state files.

## OS VPNs

A VPN is not a NullLobby transport. Direct mode routed correctly by an OS VPN normally presents the VPN egress address to peers. The VPN operator becomes part of the trust model. Split routing or VPN failure can reveal direct connectivity; NullLobby cannot guarantee the VPN. Use the VPN's system kill switch if IP privacy depends on it. Direct + VPN is not equivalent to onion transport. NullLobby does not probe external “what is my IP” services.

## What encryption cannot hide

An authorized recipient can read and copy messages. Encryption does not remove timings, all lengths, visible transport use, malicious peer behavior or endpoint compromise. Bucketed padding reduces basic length inference only. No release should use claims such as “untraceable,” “invisible,” “unbreakable” or “completely anonymous.”
