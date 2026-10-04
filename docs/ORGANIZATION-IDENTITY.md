# Optional organization identity: 0.5.0

## Implemented scope

NullLobby supports an optional offline organization attestation for an independent lobby signing key. A dedicated Rust issuer creates bounded COSE_Sign1 Ed25519 credentials; the application verifies exact issuer/lobby/key/challenge/validity before displaying a membership label. No individual name, email or stable cross-lobby identity is required. Issuer policy and credentials stay in RAM.

The [operator guide](wiki/Organization.md) documents initialization, independent requester authorization, enrollment, issuance, import, removal and limits. The [separate privacy design](0.5-DESIGN.md) covers correlation and storage boundaries. The [protocol](wiki/Protocol.md) specifies mandatory v2 behavior.

Organization membership remains separate from:

- Noise confidentiality and per-lobby identity proofs.
- Private-capability possession and administrator rotation authority.
- Human fingerprint verification.
- OpenPGP release signatures and the APT archive key.

Default operation requires no issuer. Choosing an issuer in one lobby neither installs a global trust root nor configures another lobby. Missing or expired credentials cannot create an organization label. Membership is informational in this version; it is not an enforced organization-only admission policy.

## Correlation and authorization

An issuer sees the lobby ID, public key, challenge and authorization context supplied by the operator. It can correlate its enrollments. Authorized lobby peers see organization/role claims; even a coarse group label can reveal affiliation. Transfer exported request/credential files privately. No identity secret, capability or Noise key is sent to an issuer.

Enrollment requests prove key possession, not eligibility. An operator issuing a credential must independently authorize the requester. Credentials last at most eight hours and require renewal through a fresh request. Cached attestations are rejected after expiry; clock reliability matters. This is not immediate global revocation. `/org off` clears the local policy; private rotation can restrict access to a replacement lobby.

The narrow standard profile follows [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html) and Ed25519 algorithm `-19` from [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html). Existing maintained minicbor and ed25519-dalek provide encoding and signatures. There are no custom cryptographic primitives, certificate chains, automatic remote key retrieval or general-purpose COSE algorithm negotiation.

## XXC integration still requiring a separate review

XXC Trust continues to sign project releases. Its reviewed [developer API](https://ca.xxc.dk/developers) and [OpenAPI](https://ca.xxc.dk/assets/openapi.yaml) provide general OpenPGP signing and X.509 CSR issuance. They do not define NullLobby's purpose-bound lobby membership claims or enrollment authorization policy. Generic TLS/email certificates are never relabeled as lobby credentials.

A future online issuer needs a dedicated issuance policy/key, least-privilege API authorization, reviewed requester eligibility, possession proofs, short validity, audit-retention policy and revocation semantics. Tor clients would need a reviewed Tor-only issuer endpoint; they must never use peer DNS, clearnet HTTPS, a Tor exit or Direct fallback for enrollment. The implemented offline workflow makes no CA calls in either transport.

Future required-membership admission, named credentials, signed revocation snapshots and issuer rollover need explicit designs and tests. Windows/macOS key protection remains deferred with their clients. No independent professional security audit of this profile has been completed.
