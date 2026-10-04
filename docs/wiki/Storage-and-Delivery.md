# Encrypted storage and offline delivery

0.5.0 keeps ephemeral identities, RAM-only live chat and RAM-only human verification as defaults. Persistence is a separate per-lobby decision. There is no automatic migration of preferences, no plaintext history file, and no account registration.

## Create and open a vault

Install `libsecret-tools` and use a correctly configured, password-protected Linux Secret Service such as GNOME Keyring. Unlock it through your normal desktop session. A missing/locked provider, denied unlock or failed key lookup stops the operation; there is no file/password/plaintext fallback. A misconfigured unprotected keyring does not protect the vault key. The application cannot certify the strength of an independently configured provider.

```sh
nulllobby --vault-init "$HOME/.local/share/nulllobby/state.vault"
nulllobby --vault "$HOME/.local/share/nulllobby/state.vault"
```

Initialization creates an empty encrypted vault and exits. Paths must be absolute; the immediate directory must be account-owned/private and files must be private regular files. Symlink files are rejected. Existing vaults are never overwritten during initialization. One process may open a vault at a time.

Inside a joined lobby:

```text
/identity persistent
/delivery durable
```

The first command saves that lobby's independent Ed25519 seed, current card/capability, label and reserved sender sequence range. It makes its fingerprint stable on resume. The second enables durable sending only in that lobby. Opening a vault alone never saves the current lobby. The UI shows saved identity/durable/mailbox state separately; `/privacy` reports it too.

Use `/stored` and `/resume N` to restore a saved lobby in the currently selected transport. A saved card can contain stale seeds: obtain a fresh card from a reachable participant and `/join` it to restore the same saved identity using that seed. Direct DHT may rediscover peers; Tor requires a reachable onion seed. There is no automatic transport migration or central directory.

Restored identities always receive fresh Noise static keys and fresh onion services. Human trust and organization policy/credentials remain in RAM. Public preference bookmarks remain a separate feature; they cannot store private invitations or key material.

## Peer mailbox opt-in

A participant willing to hold messages enables:

```text
/identity persistent
/mailbox on
```

Only messages explicitly sent with `/delivery durable` can enter its encrypted mailbox. Ordinary live chat is rejected by the storage layer. Each durable message permits authorized members of that same lobby, including later joiners with its card, to receive it until expiry (maximum 24 hours). A mailbox is an authorized recipient and can read plaintext. This is not end-to-end encryption against the mailbox operator.

Persistent participants automatically request small replay batches on connection and periodically. `/sync` explicitly requests replay, including for an ephemeral participant. Signatures are verified before attribution; persisted duplicate IDs/sequences prevent displaying replay twice across normal restarts. Bots ignore durable/replayed records so mailbox history cannot trigger delayed model requests.

Delivery labels mean:

| Label | Meaning |
|---|---|
| queued | Accepted into the bounded local outbox; no peer receipt yet |
| sent | Offered to connected encrypted sessions |
| peer received | A peer signed an acceptance receipt; no human-read or all-members claim |
| mailbox stored | A peer signed a retention receipt; the sender may remove its durable outbox copy |
| expired | Local retry/retention deadline passed |

A malicious mailbox can lie about retention or later discard data. One stored receipt does not guarantee redundant storage, delivery to every member or availability. There is no delivery when all holders are offline or all usable seeds are gone. The sender retries while online; an online mailbox can deliver after the sender exits.

## Bounds and failure behavior

- At most 16 saved lobby profiles per vault.
- Vault plaintext at most 4 MiB; ciphertext adds a 48-byte authenticated header and 16-byte tag.
- At most 256 stored messages total; at most 128 per lobby per outbox/mailbox kind. Full storage rejects new work instead of evicting unexpired records.
- At most 128 pending sends per lobby. Live retry lasts at most ten minutes in RAM. Durable expiry is at most 24 hours, signed into the message.
- Four records per retry/replay batch; authenticated sync requests are limited to once every two seconds per connection.
- Durable deduplication: 4096 entries per vault or 1024 per ephemeral lobby, retained until message expiry. Full unexpired dedup state rejects new messages.
- Sequence ranges of 4096 are committed before use. Ordinary crash/restart cannot reuse the previous range.
- Expiry uses a nondecreasing observed clock floor in the vault, so a normal backward clock change cannot resurrect expired records. A large forward jump can expire pending work early. Signatures and ID/sequence checks remain necessary.

Local disk failures never cause a plaintext write or a successful stored receipt. Record acceptance is committed before display/receipt; a crash after committing but before display can suppress an otherwise unseen display on restart. This favors duplicate suppression and does not promise exactly-once human delivery. Device failure, filesystem rollback and old backups cannot be solved by ordinary file synchronization.

## Encryption and removal

RustCrypto XChaCha20-Poly1305 protects the vault using a random 256-bit key stored only in the OS Secret Service. Each save gets a fresh random 192-bit nonce. The authenticated header binds the format, opaque vault ID and nonce. Files use private permissions, exclusive locking and atomic replacement with file/directory synchronization. There is no SQLite database, chat log, plaintext temporary vault, analytics or cloud key escrow.

`/delivery live` stops creating new durable messages; pending durable records continue until stored or expired. `/mailbox off` removes local mailbox records. `/identity ephemeral` removes that profile, its capability, pending durable records and duplicate state; the running session keeps its key until leaving. These commands cannot erase copies held by peers, backups, snapshots or SSD remnants. The OS keyring may retain its empty vault key after a vault is manually deleted.

Restoring an old vault backup can roll signing sequences and retirement state back. Rotate/recreate the affected lobby identity before sending from a restored old backup. There is no hardware rollback counter. Same-account processes, an unlocked keyring, compromised kernels and physical memory remain in the endpoint trust boundary. Secret buffers are zeroized where practical, but no complete erasure guarantee is made.
