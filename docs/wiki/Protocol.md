# Protocol v2 (0.5.0)

The Linux implementation uses the formats below. Protocol identifiers remain stable even if the presentation name changes.

## Identity and fingerprints

For each joined lobby, generate an independent 32-byte Ed25519 seed using the OS CSPRNG (`getrandom::fill`). Construct the public key with `ed25519-dalek::SigningKey::from_bytes` and `verifying_key`. Separately generate 32 random bytes for the X25519 static key. Use x25519-dalek's standard scalar handling and public-key derivation. The actual Noise static key must match the encrypted signed identity proof.

Fingerprint = SHA-256 of the 32-byte Ed25519 public key. Display 32 digest bytes as uppercase hexadecimal, two bytes per group, separated by `-`: sixteen groups, 79 ASCII characters. Parsing accepts uppercase/lowercase hex but requires all sixteen groups. Partial fingerprints are rejected. Ed25519 uses strict verification and rejects weak public keys.

No master key, public installation identity or shared cross-lobby identity exists. Unsaved identity recreation produces new randomness. Explicit vault restoration reuses only that lobby's Ed25519 seed and reserves a new signing sequence range; its Noise static key is freshly generated. Verification is RAM-only and lobby-scoped.

## Lobby identifiers and KDF

Public unlisted lobby: 32 independent OS-random bytes. This is a rendezvous identifier, not an authorization secret. Lobby names do not participate in its generation.

Private lobby: 32 independent OS-random capability bytes. HKDF-SHA-256 follows [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), with absent salt (equivalent to 32 zero octets) and these **exact ASCII info strings**, without trailing NUL:

| Output | Info | Length |
|---|---|---|
| Lobby ID | `nulllobby.lobby-id.v1` | 32 bytes |
| Discovery material | `nulllobby.discovery.v1` | 32 bytes |
| Noise PSK | `nulllobby.noise-psk.v1` | 32 bytes |

Each expansion uses the same HKDF extract result with a distinct info value. Raw capability bytes are never reused as the PSK or discovery bytes. A name/password is never input. The retained PRK is explicitly zeroized after extraction. Secret outputs are separately wrapped; only the lobby ID is a public identifier.

Direct swarm namespace = the first 20 bytes of private discovery material, or of SHA-256(`nulllobby.public-discovery.v1` || 32-byte public lobby ID). This 160-bit BitTorrent namespace is a rendezvous value, not NullLobby's cryptographic security level. Application security does not use SHA-1.

Discoverable names are trimmed of ASCII whitespace and converted to ASCII lowercase. Accept 1..64 bytes from a-z, 0-9, '-' and '_'. Their lobby ID is SHA-256(`nulllobby.discoverable.v1` || one-byte normalized length || normalized ASCII name). Apply the public discovery derivation above to obtain the swarm namespace. Tor rejects this lobby kind.

## Lobby card v2

Text prefixes:

```text
nl:v2:direct-public:<base64url>
nl:v2:direct-private:<base64url>
nl:v2:direct-discoverable:<base64url>
nl:v2:tor-public:<base64url>
nl:v2:tor-private:<base64url>
```

Base64url uses the URL-safe alphabet and **no padding**, whitespace or trailing data. Prefix and decoded mode/type must agree. Limits: 768 total text bytes, 512 decoded bytes and at most 8 seed endpoints. Unknown versions/types fail. Discoverable cards require the same explicit enumeration-warning confirmation as creation.

The decoded bytes use the following flat canonical format; all integers larger than one byte are big-endian:

| Field | Size | Value |
|---|---|---|
| Magic | 3 | ASCII `NLC` |
| Card version | 1 | `0x02` |
| Transport | 1 | `0x01` Direct, `0x02` Tor |
| Lobby kind | 1 | `0x01` public unlisted, `0x02` private, `0x03` Direct discoverable |
| Lobby ID | 32 | Random public ID or capability-derived private ID |
| Capability | 32 if private, absent if public | Random private secret |
| Seed count | 1 | `0..8`; Tor requires `1..8` |
| Seed records | Variable, bounded | Described below |
| Administrator flag | 1 | `0` absent, `1` followed by a 32-byte nonweak Ed25519 public key; private cards only |
| Checksum | 32 | SHA-256(`nulllobby.card-checksum.v1` ASCII bytes || all preceding binary fields) |

The fixed checksum domain is followed by a fully specified flat encoding, so there is no ambiguous field concatenation. The checksum detects transcription errors; anyone can recompute it. It is **not a signature or MAC**. Private authorization relies on PSK-authenticated Noise, not this checksum.

Seed records:

| Tag | Address | Port | Allowed transport |
|---|---|---|---|
| `0x04` | 4 IPv4 octets | 2 bytes, nonzero | Direct |
| `0x06` | 16 IPv6 octets | 2 bytes, nonzero | Direct |
| `0x03` | 32-byte Tor v3 service public key | 2 bytes, nonzero | Tor |

IPv4-mapped IPv6 is treated as its encoded IPv6 endpoint, not normalized to IPv4. Endpoint ordering is preserved; exact duplicates are rejected. The service key is public address material, **not an onion private key**. Tor hostnames encode BASE32(public key || first two bytes of SHA3-256(`.onion checksum` || public key || `0x03`) || `0x03`), lowercase, plus `.onion`. Only this validated v3 form reaches SOCKS. It is never interpreted as a hostname or IP in this format.

Private decode rederives the lobby ID and rejects mismatch. Count/length checks happen before endpoint allocation. Every byte must be consumed before the checksum. No nickname, human lobby name, participant identity list or onion private key is in a card. Managed private cards explicitly pin the creator's lobby Ed25519 public key as rotation authority. Anyone with a public card can attempt to join. Anyone with a private card has the capability; keep it private.

## BitTorrent handshake

The codec follows the [BEP 3 peer handshake](https://www.bittorrent.org/beps/bep_0003.html) and reserves the [BEP 10 extension bit](https://www.bittorrent.org/beps/bep_0010.html):

```text
1 byte   19
19 bytes "BitTorrent protocol"
8 bytes  reserved; outgoing byte 5 is 0x10, other bytes zero
20 bytes swarm namespace
20 bytes fresh random peer ID
```

Total: exactly 68 bytes. `parse` rejects short/long input and invalid protocol strings. Unknown reserved bits are retained for interoperability. `validate_for` additionally rejects a different swarm and a missing extension bit. The stream reader reads exactly 68 bytes under the transport handshake timeout.

Peer IDs contain no project/client impersonation prefix, nickname, host identity or stable installation ID. A random ID is not the application identity. See the BEP 10 and DHT sections below.

## BEP 10 and outer records

After the standard handshake, both peers send the extended handshake as a BitTorrent message: big-endian u32 length, message ID 20, extension ID 0, then canonical bencode:

```text
d1:md7:NL_chati1eee
```

The local receive extension ID is 1. Outgoing payloads use the peer's negotiated nonzero ID. Handshakes contain no nickname, lobby name, identity key, secret or client version. Unknown metadata is bounded and ignored; malformed, duplicate and disabled IDs fail. At most four unchanged extended-handshake updates are accepted.

Each custom extension payload is one byte (1 = Noise handshake, 2 = Noise ciphertext), followed by opaque Noise bytes. No plaintext application event type is exposed.

The transport-neutral stream uses u32 big-endian record length, one-byte tag and payload. In Direct mode the adapter translates this framing into BEP 10 messages; in Tor mode it travels directly over the onion stream. All outer frames are at most 65536 bytes including their prefix. Unknown tags, empty payloads and oversized frames fail before payload allocation.

## Noise and identity authentication

Use snow 0.10.0:

- Public: `Noise_XX_25519_ChaChaPoly_BLAKE2s`
- Private: `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`, PSK slot 3

The Noise prologue is ASCII `nulllobby.session.v2` followed by the fixed 32-byte lobby ID. Three handshake records carry **empty application payloads**; each handshake record payload is bounded to 512 bytes. No fallback pattern, cipher, MSE security boundary or plaintext mode exists. Establishment has a 20-second deadline.

After Noise completes, both sides exchange the following 226-byte proof **inside a dedicated encrypted Noise record (before application length/padding framing)**:

| Field | Size |
|---|---|
| Protocol version, big-endian 2 | 2 |
| Lobby ID | 32 |
| Ed25519 public key | 32 |
| Actual X25519 Noise static public key | 32 |
| Fresh random session nonce | 32 |
| Noise transcript hash | 32 |
| Ed25519 signature | 64 |

Signature input is the fixed ASCII domain `nulllobby.identity.v2` followed by the first 162 bytes. Verify strict Ed25519, lobby, version, transcript and the Noise handshake's actual remote static key. Reject a peer claiming the local key. The usable `SecureSession` type is returned only after proof validation; application metadata cannot be sent through the runtime before this point. Holding a valid key does not establish a human identity until fingerprint verification.

Encrypted plaintext records are u16 big-endian payload length, payload, then encrypted padding. Maximum payload 16366 bytes; ChaChaPoly adds a 16-byte tag. With no padding, ciphertext length is payload+18. Bucketed records reach total ciphertext sizes 512, 1024, 2048, 4096, 8192 or 16384 bytes using OS-random padding. Padding reduces simple length inference, not traffic analysis. Failed/cancelled writes poison the writer; failed reads poison the reader. No nonce is reused for another send.

## Canonical application CBOR

minicbor performs manual bounded decoding, with exact array arity and fixed-length byte fields. Definite-length encodings only; re-encoding must equal the input. Unknown mandatory versions/types, noncanonical integers, excess fields, indefinite/nested surprises and trailing bytes fail. No hostile serde collection is deserialized. Maximum packet is 12288 bytes.

Packet = `[version=2, type, payload]`:

| Type | Payload |
|---|---|
| 0 Hello | integer 0 (required capabilities only) |
| 1 Signed | byte string containing signed envelope |
| 2 EndpointList | array of at most 8 signed endpoint envelopes as byte strings |
| 3 Ping | u64 nonce |
| 4 Pong | u64 nonce |
| 5 Disconnect | integer 0 |
| 6 Error | integer 0 |
| 7 Rotation | addressed signed offer bytes, at most 2048 bytes |
| 8 Sync | integer 0; authenticated bounded mailbox replay request |
| 9 Membership | COSE credential bytes, at most 1024 bytes |

Hello is exchanged after identity proof with a five-second deadline. Only established sessions carry further packets.

Signed envelope = `[unsigned-bytes, signature-bytes64]`.

Unsigned bytes encode this canonical array of eight fields:

```text
["nulllobby.message.v2", 2, lobby-id-bytes32, sender-ed25519-bytes32,
 sender-sequence-u64, random-message-id-bytes16, message-type, payload]
```

The signature covers the complete unsigned CBOR encoding. Sender sequence starts at 1 and is shared across that identity's message types.

| Message type | Canonical payload |
|---|---|
| 1 Join/presence | [nickname UTF-8 text, lobby-name UTF-8 text] |
| 2 Chat | UTF-8 text, maximum 8192 bytes |
| 3 Leave | empty array |
| 4 Onion endpoint | [service-public-key bytes32, nonzero u16 port, expiry UNIX seconds] |
| 5 DurableChat | [UTF-8 body at most 8192 bytes, created UNIX seconds, expires UNIX seconds]; lifetime in 1..86400 seconds |
| 6 Receipt | [original sender key bytes32, original message ID bytes16, stored boolean] |

Nicknames are at most 64 UTF-8 bytes; lobby names at most 128. Controls, ESC/OSC and bidi controls are rejected, then display is sanitized again. No OS, hostname, locale or detailed build metadata is sent.

## Replay, gossip and membership

Verify signatures and lobby scope before attribution. Track a 128-sequence replay window per sender plus at most 4096 recent IDs for ten minutes. Retain at most 64 sender high-water marks for the lifetime of a lobby. Older presence updates cannot roll nicknames back. Keep trust by full fingerprint, scoped to the current lobby.

Forward the original signed logical envelope over other authenticated encrypted sessions. Never sign a relayed message as the relay. Private lobby sessions all completed the PSK suite. Live chat is not stored. Explicitly durable records may be replayed by separately enabled peer mailboxes to authorized same-lobby joiners until expiry. They have a separate bounded ID/sequence duplicate set so a sender's resumed sequence range does not invalidate legitimate older mailbox records. Persistent duplicate state is committed before display/receipt; signatures remain mandatory.

Presence is refreshed every minute and expires after three minutes without a signed refresh. Ping/Pong runs every five seconds; inactive readers expire after 120 seconds. Up to 16 outbound peer connections are attempted, with at most eight simultaneous dials; global/per-lobby limits still apply. Slow send queues disconnect peers. Signed receipts distinguish peer acceptance from claimed mailbox retention; neither guarantees human reading or global delivery.

Onion advertisements are accepted only inside authenticated Tor lobby sessions. Validate signature, lobby, strictly increasing advertisement sequence, nonzero port and expiry in (now, now+600 seconds]. Retain one current endpoint per sender and erase expired endpoints, without an address history. Advertisements from another lobby cannot enter the endpoint book. At most eight current endpoints are sent to a new peer. A new process/lobby creates a new service. Only an explicitly saved Ed25519 identity can be restored; the onion service and Noise static key remain fresh.

## Direct discovery

The bounded BEP 5 client issues `get_peers` and token-authenticated `announce_peer`. It uses mainline 8.0.1's BEP 42 IPv4 node-ID helper, with the crate's actor feature disabled because its response channels are unbounded. The application never calls that actor API or treats DHT IDs as identities.

The client declares read-only DHT participation using `ro=1`; it does not store other nodes' chat/discovery records. Keep at most 64 candidates, visit at most 24 nodes per cycle, cap replies at 2048 bytes/depth 6 and returned peers at 64. Verify transaction ID and response source. Public discovery rejects LAN/reserved peer and node addresses. Explicit local fixture seeds bypass that filter for deterministic tests.

Default bootstrap names are router.bittorrent.com, router.utorrent.com and dht.transmissionbt.com, port 6881. Each DNS lookup has a deadline and bounded retained results; only Direct invokes it. Announcements use the actual ephemeral TCP listener port. There is no tracker, BEP 44 or chat database. DHT state stays in RAM. Current public discovery is IPv4; explicit TCP seeds can use IPv6.

## References

[BEP 5](https://www.bittorrent.org/beps/bep_0005.html), [BEP 10](https://www.bittorrent.org/beps/bep_0010.html), [BEP 42](https://www.bittorrent.org/beps/bep_0042.html), [BEP 43](https://www.bittorrent.org/beps/bep_0043.html), [Noise specification](https://noiseprotocol.org/noise.html), [Tor control specification](https://spec.torproject.org/control-spec/commands.html), [Tor v3 addresses](https://spec.torproject.org/rend-spec/encoding-onion-addresses.html).

## Rotation and organization records

A rotation offer is canonical `[body-bytes, signature-bytes64]`, with body:

```text
["nulllobby.rotation.v1", 2, old-lobby-id-bytes32, owner-key-bytes32,
 recipient-key-bytes32, sequence-u64, expires-u64, replacement-card-text]
```

Maximum offer size is 2048 bytes. The recipient requires the pinned old-card administrator as both signer and actual authenticated peer, its own key as addressee, expiry in `(now, now+300]`, a different private lobby ID, an administrator pin and the same transport. Tor cards still require onion-only seeds. Offers are individually sent, never gossiped. See [rotation semantics](Private-Lobbies.md).

Organization COSE_Sign1 uses tag 18, protected bytes `a1 01 32` (`{1: -19}`), an empty unprotected map, byte-string payload and 64-byte signature. The RFC 9052 signature structure uses external AAD `nulllobby.organization.v1`. Payload:

```text
[1, issuer-key-bytes32, lobby-id-bytes32, subject-key-bytes32,
 challenge-bytes32, organization-text<=64, role-text<=32,
 issued-u64, expires-u64, serial-bytes16]
```

Credential maximum is 1024 bytes, cache maximum 64; lifetime at most eight hours. Issuance may be at most 60 seconds ahead. The signed enrollment request body is `["nulllobby.org-enrollment.v1",1,lobby-id,key,challenge,created]`, wrapped as `[body-bytes,signature-bytes64]`, at most 512 bytes and at most one hour old. Import additionally requires the locally outstanding challenge. Issuer selection is explicit per lobby, not inherited from release trust. See [organization policy](Organization.md).

Vault framing, consent, quotas, sequence reservations, expiry clock floor, duplicate suppression and receipt limitations are specified in [Storage and delivery](Storage-and-Delivery.md). Storage format v1 is distinct from application/card protocol v2. Old protocol/card versions fail; they are not upgraded or silently accepted.
