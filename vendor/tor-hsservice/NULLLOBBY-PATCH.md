# Ephemeral service storage patch

Base: published `tor-hsservice` **0.47.0**, upstream commit
`ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087` (`arti-v2.7.0`).
Source: https://gitlab.torproject.org/tpo/core/arti .
Changes by the NullLobby project, 2026-10-03. This is a local experimental patch,
not an upstream Tor release or an independently audited modification.

Upstream MIT/Apache-2.0 licenses remain applicable. Their texts were copied from
that exact upstream commit. Public author attribution is retained; author email
addresses were omitted from manifest metadata at the project owner's request.

## Changes

- `OnionService::new_ephemeral` creates a separate `ArtiEphemeralKeystore` and
  `KeyMgr` for every service. It never accepts a persistent key store or restores
  an old service identity.
- `service_storage::Instance/Storage` preserves existing filesystem behavior for
  persistent services. An ephemeral instance has no filesystem handle; loads
  start empty and stores skip serialization. The authoritative live state stays
  in the existing manager structs.
- Introduction-point, publication and proof-of-work state use that policy.
  Ephemeral replay logs use upstream's existing in-memory filter implementation;
  neither introduction nor proof-of-work replay files are created.
- Ephemeral replay filters stop accepting new requests at 100,000 successful
  insertions. They retain earlier entries and never rotate/evict history while
  the associated key remains usable. Reaching the cap may deny availability
  until normal introduction-point/key retirement; it never permits replays.
- The ordinary builder still requires an explicit state directory. Missing
  configuration cannot accidentally combine persistent keys with ephemeral
  replay filters.
- Persistent-path tests were adjusted for wrappers; new tests cover absent
  filesystem handles and replay exhaustion. Upstream cryptographic primitives,
  descriptor formats, relay selection and Tor guard handling are unchanged.

## Review and maintenance

Review `docs/ARTI-DEPENDENCIES.md` and `docs/wiki/Arti-Review.md`. A separate,
reviewable source diff is kept at `vendor/tor-hsservice-ephemeral.patch`. That diff
omits the author-email metadata redaction described above.
Do not update the vendored crate without reapplying and reviewing each change,
running its library tests and the NullLobby all-features tests, and repeating
the live service/storage/cleanup test. The upstream release's lockfile is
retained for repeatable standalone tests; NullLobby uses the workspace lockfile.

```sh
cargo test --locked --manifest-path vendor/tor-hsservice/Cargo.toml \
  --lib --features ephemeral-service
```

No application writes to `/tmp`, tmpfs or a hidden disk directory are used as a
substitute for in-memory service state. Arti's ordinary guard and directory
cache storage remains separate and persistent.
