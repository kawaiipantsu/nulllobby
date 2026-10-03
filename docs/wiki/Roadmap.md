# Roadmap

Only Phase 1 is implemented. The project name is provisional. Linux and the shared Rust core come first; no Windows/macOS GUI is being implemented yet.

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Workspace, transport interfaces, domain, capability KDF/cards, per-lobby identities, fingerprints, secret/platform hardening, BitTorrent codec and tests | Implemented |
| 2 | Direct BEP 10, reviewed Noise XX/XXpsk3, encrypted records, encrypted identity proofs | **Next; not started** |
| 3 | Signed logical messages, replay window, bounded gossip | Planned |
| 4 | Reviewed Mainline DHT, Direct discovery and private/public joining | Planned |
| 5 | Ratatui/Crossterm Linux full-screen IRC-style interface | Planned |
| 6 | External Tor ControlPort/SOCKS, ephemeral per-lobby v3 services, onion seeds/advertisements | Planned |
| 7 | Actual Tor fail-closed/privacy regressions and bounded metadata padding | Planned |
| 8 | cargo-fuzz, security review, expanded documentation and CI | Planned; baseline documentation/CI already provided |
| 9 | Optional `tor-arti-experimental` after current API/security review | Deferred |
| 10 | Shared Iced Windows/macOS desktop and native packaging | Deferred |

## Exact next phase

1. Review current `snow` release, dependency advisories and exact support for `Noise_XX_25519_ChaChaPoly_BLAKE2s` and `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`.
2. Implement bounded BEP 10 bencode/extension negotiation with a truthful `NL_chat` extension, omitting optional detailed client metadata.
3. Add strict outer Noise handshake/ciphertext framing and bounded encrypted application records. No plaintext or cipher fallback.
4. Compute fresh per-lobby X25519 static keys through the selected maintained implementation, replacing placeholder usage.
5. Define canonical, domain-separated identity proof bytes. Exchange proofs inside Noise and check the actual remote Noise key before `Secure` state.
6. Test wrong PSK before metadata disclosure, wrong lobby/version/key binding, tampering, oversized records, handshake timeouts and absence of chat plaintext in captured bytes.
7. Keep local developer connections on the same BitTorrent → BEP 10 → Noise → proof path. Do not add a plaintext shortcut.

Phase 2 does not authorize moving on to DHT, Tor or the GUI. Finish and review each boundary separately.

## Planned Linux commands

These are **not available in Phase 1**:

```text
/help
/nick <nickname>
/create public <name>          public unlisted by default
/create private <name>         random capability, never a human password
/create discoverable <name>    Direct only, explicit enumeration warning
/join <lobby-card>
/leave
/lobbies
/who
/fingerprint
/verify <full-fingerprint>
/unverify <full-fingerprint>
/verified
/invite                        explicit disclosure; no automatic clipboard
/transport direct
/transport tor
/security
/network
/privacy
/padding none
/padding bucketed
/quit
```

Changing transport inside a lobby requires leaving/rejoining. Direct developer flags will include `--listen` and `--peer`; Tor will accept local `--tor-socks` and `--tor-control`. Credentials are never hardcoded or echoed. Tor bootstrap failure remains an error, never a mode change.

## UI principles

Top: project, current lobby, mode, encryption and exposure. Left: lobbies. Center: messages. Right: members/full fingerprints or a clearly marked shortened display with full inspection. Bottom: input. Show separate properties instead of a single green “secure” indicator.

`/privacy` will report transport, peer-IP exposure, ephemeral lobby-scoped identity, RAM-only history, actual Noise suite/private PSK state, full fingerprint, actual memory-lock results and Tor status. Never claim guaranteed anonymity.

## Desktop future

Iced over the same core for native Windows/macOS. Windows begins with `x86_64-pc-windows-msvc`; WiX packaging and Authenticode when credentials are supplied. macOS begins with ARM64, hardened signed `.app`, notarization and optional DMG. No Electron and no signing credentials in source. External Tor remains supported; embedded Arti cannot downgrade to clearnet on failure.
