# Optional organization membership

0.5.0 supports a dedicated offline organization issuer and short-lived COSE credentials. The default client requires no organization, issuer or CA. An attestation labels a lobby identity as belonging to a group/role; it does not automatically mark its human fingerprint verified or enforce organization-only admission.

## Create an issuer

Run on an administrator-controlled Linux environment with an unlocked, protected Secret Service and `libsecret-tools`:

```sh
nulllobby --org-create-issuer "$HOME/.local/share/nulllobby-org/issuer.vault"
```

The command creates a separate encrypted issuer vault and prints only its public key and SHA-256 fingerprint. Distribute/compare that key through an already trusted channel. Do not reuse release-signing keys, personal identity keys or lobby administrator keys. The tool does not upload anything or install a system trust root.

## Enroll a lobby identity

In the joined lobby, each participant selects the organization's public issuer key and requests enrollment:

```text
/org trust 64_HEX_CHARACTERS_OF_THE_ISSUER_PUBLIC_KEY
/org request /private/path/enrollment.cbor
```

The exported file proves possession of the current lobby signing key and contains the lobby ID, public key, random challenge and creation time. It does not contain a private key or capability. Send it privately to the issuer: these public claims are still sensitive metadata and can correlate activity at the issuer.

The administrator must independently authorize the requester before issuing. Possession of an enrollment key alone is not proof of organizational membership.

```sh
nulllobby --org-issuer "$HOME/.local/share/nulllobby-org/issuer.vault" \
  --org-issue /private/path/enrollment.cbor \
  --org-output /private/path/membership.cose \
  --org-name 'THUGS(red)' --org-role member --org-hours 8
```

Then import the returned credential in the same running lobby:

```text
/org import /private/path/membership.cose
```

The client requires its outstanding challenge, exact lobby/key, trusted issuer, valid signature and bounded validity. Requests expire after one hour; credentials last at most eight hours with up to 60 seconds of issuance clock skew. Output files are created privately without overwriting existing files. They remain until the operator removes them.

Credentials are exchanged only inside authenticated encrypted lobby sessions, after private PSK authentication where applicable. No email, stable person ID or cross-lobby public master key is present. Group labels/roles themselves are visible to authorized lobby participants. Each new lobby needs a separate credential. Human trust, issuer selection, enrollment challenges and credentials stay in RAM; rotation/restart requires selecting/enrolling again, including when the lobby key itself is saved.

`/org off` removes the current lobby's issuer policy and cached attestations. Expired credentials lose their displayed label. There is no online revocation lookup, signed revocation directory or required-membership gate in 0.5.0. Short validity limits stale attestations; offline clients cannot promise immediate knowledge of revocation. Use private capability rotation to restrict replacement-lobby access.

## Protocol and XXC boundary

The narrow profile uses canonical CBOR, COSE_Sign1 tag 18, protected algorithm `-19` (Ed25519), no unprotected fields, and external authenticated data `nulllobby.organization.v1`. Credentials cap at 1024 bytes and peers cache at most 64. Claims bind version, issuer public key, lobby ID, subject public key, challenge, organization, role, issue/expiry times and random serial. Verification rejects malformed/noncanonical data before any label is trusted.

XXC Trust continues to sign releases. Its currently reviewed general OpenPGP/X.509 APIs do not supply this dedicated lobby membership policy. The offline issuer is implemented in Rust inside NullLobby's application layer; the chat client does not call XXC, HTTPS, DNS or Tor exits for membership. Future live XXC enrollment needs a reviewed dedicated API, issuer authorization and Tor-only design. Generic TLS certificates are never treated as lobby membership credentials.

Standards: [COSE RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), [fully specified algorithms RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html). This is an implemented experimental profile, not an independently audited credential system.
