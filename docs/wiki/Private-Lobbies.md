# Private capabilities, rotation and revocation

Private lobbies use random 256-bit capabilities, never human passwords. HKDF-SHA-256 derives separate discovery, lobby ID and Noise PSK values. Every connection must complete `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` before names, members, organization credentials or chat can be exchanged.

0.5.0 private cards additionally pin the creator's lobby-scoped administrator public key. This authorizes rotation; it does not prove a person's real-world identity. Compare complete fingerprints independently.

## Commands

```text
/create private exercise
/invite
/rotate
/revoke FULL-LOBBY-FINGERPRINT
```

`/rotate` replaces the capability for all retained, directly connected peers. `/revoke` excludes the specified current member identity from replacement offers. Only the creator whose key is pinned by the card can perform these operations. A nickname is not an identity and is never a revocation target.

Before rotating, compare and `/verify` every retained directly connected peer's full fingerprint. Rotation fails while any retained recipient is unverified: possession of the old shared capability allows an attacker to create new aliases, which must not automatically receive the replacement. Do not mark an unknown key verified just to bypass this check. If the old lobby is flooded with unknown identities, create a fresh private lobby and invite independently verified recipients instead.

The client creates a fresh private capability, lobby ID, administrator identity and endpoint in the same transport. It sends signed, recipient-addressed offers individually through existing authenticated Noise links to retained verified identities only. Replacement secrets are never gossiped through the old lobby. Each offer binds the old lobby/owner, intended recipient, nonzero sequence, replacement card and an expiry within five minutes. Recipients require that the actual authenticated peer is the pinned administrator.

The old local endpoint and streams close. Saved old identities, capabilities, outboxes and mailboxes are retired in the opened vault, which rejects rejoining that retired capability. The new lobby starts with fresh identity/trust, organization policy and storage choices. Enable persistence again explicitly if wanted. A free lobby slot is required while preparing the new endpoint.

Offline or indirectly connected retained participants need a fresh `/invite` through an appropriate channel. A failed connection to the replacement is reported; there is no automatic return to the retired lobby and no Direct fallback under Tor. A preparation failure before publishing offers leaves the old lobby available and reports failure. Do not assume every retained peer received its offer simply because a rotation was requested.

## Limits

Revocation excludes an identity from automatic redistribution. It cannot erase old plaintext, stop old members operating an old-lobby fork, stop a retained member deliberately leaking the replacement card, or stop a revoked person joining under a fresh key if they obtain that card. All private invite holders remain capable of admitting others by sharing their capability.

Administrator ownership is not transferred or recovered automatically. Save the administrator's lobby identity explicitly if it must survive a restart. Without that saved key, recreate the private lobby and distribute a fresh card manually. Organization membership is a separate optional attestation, not a substitute for private capability possession or an enforced admission directory.

Protocol/card v2 is mandatory. 0.4.x clients and v1 cards cannot participate; obtain a fresh v2 card after upgrading all participants.
