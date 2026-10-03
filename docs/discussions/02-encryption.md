The next implementation phase is BEP 10 plus Noise and encrypted identity proofs. This thread is for reviewing that boundary before messages are enabled.

The intended suites are `Noise_XX_25519_ChaChaPoly_BLAKE2s` for public lobbies and `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` for private lobbies, subject to checking the selected `snow` release's exact support and advisories. There will be no plaintext mode, fallback cipher or custom cryptographic primitive.

Each lobby gets independent Ed25519 identity and X25519 static material. An encrypted signed proof must bind the actual remote Noise static key to the lobby identity and lobby ID. A first-seen key is still **unverified** until a person compares the full fingerprint out of band. Restart changes the fingerprint because v1 keeps no persistent identity.

Review ideas:

- How should fingerprint comparison work in a busy terminal without encouraging partial-fingerprint verification?
- Which failure cases should be mandatory tests for XXpsk3 metadata withholding and key binding?
- How should canonical encoding and protocol version negotiation fail on ambiguous input?
- What signing/replay/gossip limits should Phase 3 enforce?

Please ground protocol suggestions in established constructions and maintained implementations. “Hard to reverse engineer” is not a security argument. See the [protocol wiki](https://github.com/kawaiipantsu/nulllobby/wiki/Protocol) and [threat model](https://github.com/kawaiipantsu/nulllobby/blob/main/SECURITY.md).
