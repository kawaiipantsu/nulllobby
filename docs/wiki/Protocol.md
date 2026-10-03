# Phase 1 protocol foundations

Only the formats in this page's **implemented** sections exist. Application packets, Noise handshakes, identity proofs and gossip are not yet implemented. Protocol identifiers remain stable even if the presentation name changes.

## Identity and fingerprints — implemented

For each joined lobby, generate an independent 32-byte Ed25519 seed using the OS CSPRNG (`getrandom::fill`). Construct the public key with `ed25519-dalek::SigningKey::from_bytes` and `verifying_key`. Separately generate 32 random bytes for the future X25519 static-secret input. No X25519 public key is computed in Phase 1; do not treat the placeholder bytes as a ready session.

Fingerprint = SHA-256 of the 32-byte Ed25519 public key. Display 32 digest bytes as uppercase hexadecimal, two bytes per group, separated by `-`: sixteen groups, 79 ASCII characters. Parsing accepts uppercase/lowercase hex but requires all sixteen groups. Partial fingerprints are rejected. Signing and strict public-key/message verification enter in later phases.

No master key, public installation identity or shared cross-lobby identity exists. Dropping/recreating an identity produces new randomness. Verification is RAM-only and lobby-scoped.

## Lobby identifiers and KDF — implemented

Public unlisted lobby: 32 independent OS-random bytes. This is a rendezvous identifier, not an authorization secret. Lobby names do not participate in its generation.

Private lobby: 32 independent OS-random capability bytes. HKDF-SHA-256 follows [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), with absent salt (equivalent to 32 zero octets) and these **exact ASCII info strings**, without trailing NUL:

| Output | Info | Length |
|---|---|---|
| Lobby ID | `nulllobby.lobby-id.v1` | 32 bytes |
| Discovery material | `nulllobby.discovery.v1` | 32 bytes |
| Future Noise PSK | `nulllobby.noise-psk.v1` | 32 bytes |

Each expansion uses the same HKDF extract result with a distinct info value. Raw capability bytes are never reused as the PSK or discovery bytes. A name/password is never input. The retained PRK is explicitly zeroized after extraction. Secret outputs are separately wrapped; only the lobby ID is a public identifier.

Conversion from discovery material/public IDs to a 20-byte Direct swarm namespace is **not defined or implemented yet**. Phase 4 must specify it and its privacy implications before using DHT. No SHA-1 application security code exists.

## Lobby card v1 — implemented

Text prefixes:

```text
nl:v1:direct-public:<base64url>
nl:v1:direct-private:<base64url>
nl:v1:tor-public:<base64url>
nl:v1:tor-private:<base64url>
```

Base64url uses the URL-safe alphabet and **no padding**, whitespace or trailing data. Prefix and decoded mode/type must agree. Limits: 768 total text bytes, 512 decoded bytes and at most 8 seed endpoints. Unknown versions/types fail. Globally discoverable cards are deliberately unsupported until the privacy warning and normalization scheme exist.

The decoded bytes use the following flat canonical format; all integers larger than one byte are big-endian:

| Field | Size | Value |
|---|---|---|
| Magic | 3 | ASCII `NLC` |
| Card version | 1 | `0x01` |
| Transport | 1 | `0x01` Direct, `0x02` Tor |
| Lobby kind | 1 | `0x01` public unlisted, `0x02` private |
| Lobby ID | 32 | Random public ID or capability-derived private ID |
| Capability | 32 if private, absent if public | Random private secret |
| Seed count | 1 | `0..8`; Tor requires `1..8` |
| Seed records | Variable, bounded | Described below |
| Checksum | 32 | SHA-256(`nulllobby.card-checksum.v1` ASCII bytes || all preceding binary fields) |

The fixed checksum domain is followed by a fully specified flat encoding, so there is no ambiguous field concatenation. The checksum detects transcription errors; anyone can recompute it. It is **not a signature or MAC**. Private authorization will rely on PSK-authenticated Noise, not this checksum.

Seed records:

| Tag | Address | Port | Allowed transport |
|---|---|---|---|
| `0x04` | 4 IPv4 octets | 2 bytes, nonzero | Direct |
| `0x06` | 16 IPv6 octets | 2 bytes, nonzero | Direct |
| `0x03` | 32-byte Tor v3 service public key | 2 bytes, nonzero | Tor |

IPv4-mapped IPv6 is treated as its encoded IPv6 endpoint, not normalized to IPv4. Endpoint ordering is preserved; exact duplicates are rejected. The service key is public address material, **not an onion private key**. Tor v3 text address encoding/checksum and backend endpoint acceptance will be implemented and reviewed with Tor support. It is never interpreted as a hostname or IP in this format.

Private decode rederives the lobby ID and rejects mismatch. Count/length checks happen before endpoint allocation. Every byte must be consumed before the checksum. No nickname, human lobby name, Ed25519 identity or onion private key is in a card. Anyone with a public card can attempt to join. Anyone with a private card has the capability; keep it private.

## BitTorrent handshake — implemented

The codec follows the [BEP 3 peer handshake](https://www.bittorrent.org/beps/bep_0003.html) and reserves the [BEP 10 extension bit](https://www.bittorrent.org/beps/bep_0010.html):

```text
1 byte   19
19 bytes "BitTorrent protocol"
8 bytes  reserved; outgoing byte 5 is 0x10, other bytes zero
20 bytes swarm namespace
20 bytes fresh random peer ID
```

Total: exactly 68 bytes. `parse` rejects short/long input and invalid protocol strings. Unknown reserved bits are retained for interoperability. `validate_for` additionally rejects a different swarm and a missing extension bit. The future stream reader must read exactly 68 bytes with a timeout, never buffer until EOF.

Peer IDs contain no project/client impersonation prefix, nickname, host identity or stable installation ID. A random ID is not the application identity. No extension message or DHT implementation is present.

## Future application protocol

Phase 2 must inspect the selected `snow` release and verify exact `Noise_XX_25519_ChaChaPoly_BLAKE2s` and `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` support. No fallback suite or plaintext mode is permitted. Direct outer records reveal only Noise handshake/ciphertext tags, with strict lengths. Noise remains mandatory over Tor.

An encrypted canonical identity proof will bind protocol version, lobby ID, Ed25519 public key, the session's X25519 static key and a random session nonce under `nulllobby.identity.v1`. Proof verification must compare to the actual remote Noise static key, not merely accept a signed claim about an unrelated key. Private PSK authentication precedes all identifying metadata.

Phase 3 adds signed canonical logical messages under `nulllobby.message.v1`, sender sequence, random message ID, replay window and bounded gossip. Application encoding will use a reviewed maintained binary codec with explicit length/collection/nesting bounds. The fixed card codec does not prescribe an unbounded serde application decoder.
