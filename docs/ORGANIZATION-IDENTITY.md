# Optional organization identity: design for review

Status: **proposal only**. No organization certificate exchange, CA lookup or changed lobby authentication is implemented. The working release-signing integration is separate and must never be used as a chat identity issuer by accident.

## Purpose and existing protection

Noise already protects each peer connection. The encrypted identity proof binds a fresh per-lobby Ed25519 identity to its Noise static key, lobby and session. Signed messages identify that lobby key; out-of-band fingerprint comparison establishes the human relationship. Private lobby PSKs independently control admission.

An optional issuer could additionally attest that a particular ephemeral lobby key belongs to an eligible member of an organization. This answers a different question from manual human verification. A valid organization credential would not automatically prove a nickname belongs to a specific person or add that fingerprint to `/verified`.

Do not replace Noise with PGP encryption, put a stable global PGP key in each lobby, reuse a release signing key for membership, or install a private CA as a global system trust root. Those changes either duplicate existing protection, create correlation identifiers or broaden trust unnecessarily.

## Two distinct policies

1. **Organization membership only:** a short-lived credential binds a fresh lobby key to a coarse organization/role claim. It carries no stable user identifier, account name or email. Peers learn the issuer and claimed group, so small groups/rare roles can still identify people. The issuer knows whom it authorized and can correlate enrollments.
2. **Named organization identity:** an explicitly enabled credential discloses a stable corporate identity. It necessarily permits cross-lobby correlation. Show that disclosure before enabling it in each lobby. It must not be the default or silently follow a saved nickname/bookmark into another lobby.

Neither policy supplies anonymous credentials or zero-knowledge membership. Removing the visible account name does not make enrollment unlinkable to the issuer. Do not invent cryptographic schemes to claim otherwise.

## Credential requirements

Use an established signed credential envelope after a separate dependency and protocol review, for example COSE_Sign1 over bounded canonical CBOR. The signed claims would include:

- A NullLobby organization-credential domain and mandatory version.
- Organization issuer identifier and explicit credential purpose, separate from release signing.
- Exact lobby ID and ephemeral Ed25519 public key.
- A fresh enrollment challenge, bounded validity and a random credential serial.
- A small allowlisted membership/role claim, with optional named identity only under the named policy.

The client proves possession of the lobby key when enrolling. The existing encrypted session proof continues to bind that key to the actual Noise session. The credential cannot authorize another lobby, another key or a different role; it cannot be a bearer token granting access simply because someone copied it.

Do not expose credentials, claims, enrollment challenges or lobby keys in Direct discovery, BitTorrent/BEP 10 negotiation or Tor addresses. Exchange them only after Noise and the existing identity proof succeed. Private lobbies still require their PSK first. No organization credential bypasses possession of a private invitation.

Issuer keys are explicitly allowlisted per lobby. A credential under a different issuer, unsupported version/purpose, different lobby/key, invalid signature or invalid validity period fails policy enforcement. Bound credential size, number of claims, chain depth and verification work. A proposed starting validity is at most eight hours with a small documented clock-skew allowance; this needs review. Expiry depends on a trustworthy clock and does not replace sequence/challenge replay protection.

An enforcing lobby fails closed when required membership cannot be validated. An optional-credential lobby may show a peer as organization-unverified, but must not display a failed or expired credential as verified. Manual human verification remains a separate lobby-scoped property.

## Issuance and Tor

No synchronous public CA lookup occurs on receiving a message or connecting to a peer. That would reveal lobby activity to an observer and create a central availability dependency.

The first implementation should use a separate administrator enrollment tool and bounded offline import into the client. The administrator sees the enrollment identity, lobby ID and public key; users must understand this disclosure. No identity private key or Noise secret is sent to the issuer. Credentials and their accepted trust state are RAM-only unless a later explicit storage design is approved.

Live enrollment in Tor mode requires a separately reviewed Tor-only issuer endpoint and authentication flow. XXC currently documents an HTTPS API; this integration has no reviewed onion endpoint. The chat client must not call the current clearnet API from Tor mode, use a Tor exit, resolve its DNS name, or fall back to Direct. Missing credentials/issuer reachability must fail according to lobby policy.

Issuer outages need not disconnect already authenticated peers while a cached credential remains valid. Renewal failure must be visible and cannot extend validity indefinitely. Revocation has an availability/privacy tradeoff: use reviewed short validity and, if needed later, bounded signed revocation snapshots distributed through authenticated lobby links. Offline peers cannot promise immediate knowledge of every revocation.

## What XXC needs before this can ship

The reviewed XXC API already supports OpenPGP signing and X.509 CSR issuance. Its current X.509 templates list TLS server/client and email usages, with DNS/IP/email SAN rules and ECDSA/RSA choices. It does not document the lobby-scoped Ed25519 membership claims, challenge enrollment or purpose-restricted COSE issuance described here. A normal TLS or email certificate must not be relabeled as a NullLobby membership credential.

Before implementation, add/review dedicated membership issuance policy in XXC, a separate issuer key and least-privilege scopes, authenticated enrollment authorization and possession proofs, bounded validity/claim rules, and revocation semantics. Review server-side audit retention and correlation, too. No API method or guarantee is assumed to exist merely because generic signing is available.

## UI and acceptance tests

Show transport privacy, encryption, private-lobby admission, human verification and organization membership independently. Example labels: `encrypted / human unverified / organization member` or `encrypted / human verified / organization credential expired`. Do not collapse them into a green “secure” badge.

Required tests before rollout:

- Different lobbies/restarts keep independent keys and credentials; trust does not transfer automatically.
- A valid credential copied to another key/lobby/session challenge is rejected.
- Wrong issuer, purpose, signature, role, version, expiry and malformed/oversized input fail cleanly.
- Private-PSK failure reveals no credential or membership metadata.
- Tor instrumentation rejects every DNS/Direct/DHT/HTTP issuer attempt by the chat client.
- Issuer outage, delayed revocation, clock changes and expired cached credentials have explicit bounded behavior.
- Named identity disclosure is opt-in per lobby; no silent persistence or remote API lookup occurs.
- Issuer revocation/rotation cannot reuse the release-signing trust configuration.

Sources reviewed: [XXC developer documentation](https://ca.xxc.dk/developers), [XXC OpenAPI](https://ca.xxc.dk/assets/openapi.yaml), and the implemented NullLobby identity/session model in `crates/nulllobby-core`. This design needs a dedicated security review before becoming a protocol feature.
