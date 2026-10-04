# NullLobby 0.5.0 — Linux preview

## Team privacy and delivery

- Private-lobby administrators can rotate capabilities and exclude a full lobby fingerprint from individually encrypted replacement offers to verified retained peers. New capabilities, identities and endpoints replace the old local lobby; offline/indirect participants need a fresh invite.
- Optional encrypted vaults save independently selected lobby identities and cards. Restoring an identity creates a fresh Noise static key; Tor services remain ephemeral. Human verification stays in RAM.
- Separately enabled durable sender outboxes and peer mailboxes retain signed durable records for at most 24 hours. Live messages are never intentionally stored. Received/stored receipts, bounded retry/replay and persisted duplicate suppression distinguish delivery states without claiming every member received or read a message.
- Optional offline organization credentials bind a dedicated issuer to a lobby/key, coarse group/role and short validity. They are separate from human trust, private admission and release signing. No CA lookup or live XXC enrollment is performed.
- The TUI shows storage, durable messages, delivery state and organization labels. Bots ignore durable/replayed prompts. Invitation copying/redaction supports v2 cards.

## Upgrade boundary

**Protocol and lobby-card v2 are mandatory.** Upgrade all participants and distribute fresh cards. Old peers/cards are rejected; there is no crypto or transport downgrade. Old public bookmarks cannot silently migrate; remove/recreate them with v2 cards. Defaults remain ephemeral and RAM-only; opening a vault saves no lobby automatically.

Vault use requires `libsecret-tools` and an unlocked, properly protected Linux Secret Service. Packages only suggest these optional dependencies. `/identity persistent`, `/delivery durable` and `/mailbox on` are distinct per-lobby choices. See [storage and delivery](https://github.com/kawaiipantsu/nulllobby/wiki/Storage-and-Delivery), [private rotation](https://github.com/kawaiipantsu/nulllobby/wiki/Private-Lobbies) and [organization membership](https://github.com/kawaiipantsu/nulllobby/wiki/Organization).

## Build and distribution

Standard Linux amd64 packages support Direct and external Tor. The separate experimental Arti package adds embedded Tor; choose one package. Neither installs a service, creates a vault or changes Tor configuration. Both retain the existing release-signing and official APT publishing workflow. Publication is a separate step from building these sources.

```sh
make check
make deb
make deb-arti
```

Verify signed checksum manifests against the independently trusted public key before installing a downloaded `.deb`. APT repository signatures use a separate scoped archive key. See [Release Signing](https://github.com/kawaiipantsu/nulllobby/wiki/Release-Signing) and [APT](https://github.com/kawaiipantsu/nulllobby/wiki/APT).

## Security limits

Direct exposes peer IPs. Tor hides peer IPs through onion transport and never falls back to Direct; traffic correlation remains possible. Mailboxes are authorized plaintext recipients and can lie about retention. Availability requires a reachable holder/seed. Rotation cannot erase old messages/forks or stop a retained member leaking a new card. Old vault backups can roll sequence/retirement state back; recreate affected identities before reuse.

Organization-only admission, online issuer enrollment/revocation, administrator recovery, NAT traversal and Windows/macOS clients remain future work. Embedded Arti and its local patch remain experimental. Existing documented RustSec applicability/maintenance exceptions remain; no independent professional security audit has been completed.
