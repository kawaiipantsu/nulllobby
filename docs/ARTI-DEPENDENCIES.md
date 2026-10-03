# Experimental Arti dependency review

Reviewed 2026-10-03 against Arti libraries **0.47.0** (Arti 2.7.0). The backend is opt-in. The standard external-Tor/Direct binary does not link this graph. Arti adds roughly 400 locked registry packages, including its directory cache, Rustls, relay protocol, certificate validation and service implementation. This is a substantial dependency and review surface, accepted only behind `tor-arti-experimental`.

The [upstream 2.7.0 release](https://blog.torproject.org/arti_2_7_0_released/) includes security fixes and recommends upgrading, especially for onion services. Direct application encryption remains Snow XX/XXpsk3, independent of Arti. Arti's legacy relay/certificate algorithms are Tor compatibility details, not new NullLobby cryptographic choices.

## Known advisory exceptions

| Advisory | Scope and decision |
|---|---|
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071), `rsa` 0.9.10 | No upstream fixed version. Timing recovery concerns private RSA operations. This backend runs a Tor client and v3 onion services, verifies public relay/directory RSA signatures, and never provisions a private RSA key, runs an authority/relay, or exposes RSA decryption/signing. Reviewed `tor-proto`, `tor-chanmgr`, `tor-hsclient`, `tor-hsservice`, `tor-netdoc`, `tor-key-forge` and `tor-llcrypto` call sites. A narrowly named audit/deny exception records this applicability assessment; it does not repair the dependency. Reassess before any Arti role/feature or key-store change. |
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436), `paste` 1.0.15 | Unmaintained macro dependency through upstream crates. Build-time token expansion, not a network parser. Accepted maintenance exception for the pinned Arti graph; remove when upstream replaces it. |
| [RUSTSEC-2025-0141](https://rustsec.org/advisories/RUSTSEC-2025-0141), `bincode` 2.0.1 | Cargo resolves an unused optional dependency into the lockfile. It is absent from the enabled Linux graph (`cargo tree --all-features -i bincode`); Cargo audit still reports its maintenance warning. Do not enable it without review. |

These are documented exceptions, not a claim of a vulnerability-free graph. Other advisories still fail the checks. Review these decisions on every Arti upgrade. No exceptions apply to NullLobby's Ed25519, Noise, HKDF or application decoders.

## Features and boundaries

- Select Tokio, Rustls, directory compression, onion client/service, vanguards, memory accounting and the experimental lower-level API. No relay/authority, RPC, bridge process, executable plugin or external command support is selected.
- Each service uses the vendored storage patch and a separate upstream ephemeral keystore. The high-level persistent service launcher is not used.
- Normal Arti guard state and directory cache remain durable. Arti uses SQLite for its Tor directory cache; NullLobby chat, trust, identities, invitations and onion-service state never enter it.
- Arti memory accounting is set to 64 MiB with a 48 MiB low-water mark. It covers tracked Tor queues, not all process memory. Application queues and service handlers have separate bounds.
- Native Arti stream isolation separates each lobby's outgoing circuits. It does not isolate timing observations or allocate a circuit per message.
- Upstream tracing has no installed subscriber in NullLobby. Errors are mapped to categories, without formatting paths, keys, addresses or decrypted packets.

## Licensing

Arti is MIT OR Apache-2.0. The vendored service code retains upstream notices and has an explicit modification record. The expanded graph also requires BSD-2-Clause, ISC, Unlicense, CC0-1.0, BSL-1.0 (the Boost Software License) and MPL-2.0. MPL-2.0 is selected for `priority-queue` (dual licensed) and retained for `option-ext`; their source remains available under its original license. No LGPL option is selected. Distributions of an experimental binary must include notices for its actual dependency graph.
