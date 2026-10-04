# Direct connection troubleshooting

## Ordinary use

Launch `nulllobby` on both machines, with no flags. On the machine accepting connections:

```text
/nick operator
/create public coordination
/invite
```

On the other machine, select a nickname and enter `/join <card>`. Keep the first process and lobby open. Private lobbies use the same workflow with `/create private coordination`; treat their cards as secrets.

Use **0.5.2 or newer** on both machines. Earlier 0.5.x clients could query bootstrap routers incorrectly and fail to announce or find a lobby. The corrected client first requests routing contacts with [`find_node`](https://www.bittorrent.org/beps/bep_0005.html), then queries and announces to the nodes storing the swarm's rendezvous records.

No CLI peer override or fixed listening port is required for this workflow. Default listeners bind a random TCP port on all IPv4 interfaces. The invitation normally has no explicit seed address because a wildcard bind is not a usable public address. The random lobby identifier allows both clients to find the same DHT namespace. It is not a global name lookup.

Discovery can take tens of seconds or several rounds. Initial rounds retry after ten seconds; later successful rounds pause for two minutes. `/reconnect` retries known endpoints and requests a fresh DHT round, with a minimum ten-second pause between rounds. It never changes transport.

## F5 or `/network`

The network overlay reports local diagnostic data without printing invitations, keys, chat or remote address histories.

| Field | Meaning |
| --- | --- |
| Local listener | Local bind address and actual TCP port; `0.0.0.0` is not a public IP |
| DHT Starting / Querying | Bootstrap or a bounded lookup round is in progress |
| DHT Ready | At least one node acknowledged an announcement in the last round |
| DHT Unavailable | No successful announcement in the last round; retries continue |
| Queries / replies | Lookup requests and matching replies; bootstrap replies alone do not prove usable discovery |
| Tokens / announcements | Nodes returning announce tokens and acknowledging announcements |
| Candidate peers | DHT endpoints found before authentication; may include stale records or this client |
| Pending connections | Outbound transport/authentication attempts still running |
| Failed outbound attempts | Cumulative attempt count, including retries; not a count of distinct peers |
| Last failure | Fixed transport/peer-handshake or Noise/identity category, not untrusted remote error text |

Ready DHT status does **not** prove that a listener is reachable. Encryption is reported as established only when an authenticated peer session exists. A discovered endpoint may be offline or unreachable. “Joining lobby” changes to the lobby name after authenticated membership information arrives.

If discovery has replies but no announcements, retry and inspect the counters. If it has no replies, check outbound DNS/UDP and filtering. If it finds candidates but connection attempts fail, inspect TCP reachability and the error category. If Noise/identity authentication fails, confirm both clients use a compatible version and the same current card. Do not share private invitation cards in issue reports.

## AWS and a home network

At least one participant must accept inbound TCP. AWS Elastic IPs are mapped to instance private addresses, so a wildcard listener is appropriate; do not bind the Elastic IP as a local interface address. The AWS security group, network ACL and guest firewall must allow the actual listener port. An open security group alone does not verify the other layers. See [AWS Internet gateway routing](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html).

A home client initiating a connection to a reachable AWS listener normally needs no inbound port forward. OPNsense must allow outbound TCP, DNS and DHT UDP plus the associated reply traffic. IDS/IPS or BitTorrent filtering can still block discovery. Use the firewall's logs to establish whether traffic is blocked before changing rules.

If the home machine must accept incoming connections, a suitable port forward is required. NullLobby does not implement UPnP or NAT hole punching, and a random port changes between sessions. An optional fixed `--listen` port can help administrators maintain a narrow firewall rule, but it is not required when the listener is already reachable.

No public “what is my IP” service is queried. DHT stores rendezvous metadata only. Direct exposes IP addresses to peers and DHT observers.

## Tor

These DHT checks do not apply to Tor. Tor cards require a reachable onion seed and the selected Tor backend. Unavailable Tor never triggers Direct discovery or fallback. See [Tor setup](Tor).
