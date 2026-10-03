# Linux UX and bot verification

Reviewed 2026-10-03 for the 0.4.0 Linux preview.

## Automated checks

- Formatting and workspace Clippy with all targets/features and warnings denied.
- Default workspace: 75 tests passed; two live network tests and the explicit screenshot-generation task remain ignored.
- All-feature workspace: 79 tests passed; three live network tests and screenshot generation remain ignored.
- Audit/deny passed with the existing documented Arti advisory exceptions and a scoped CDLA-Permissive-2.0 certificate-data license exception. This is not an independent security audit.
- New cases cover bounded sanitized paste, atomic queue admission, literal slash lines, blocked multiline invitation disclosure, UTF-8 editing, midnight rollover, small terminal sizes, clean chat/overlays, preferences roundtrip/private permissions/private-card rejection, all 256 irssi color indices, malformed/deep themes and shipped palettes.
- Bot tests reject Tor cloud providers and non-loopback local URLs, reject redirects, bound/sanitize provider JSON, check stateless API schemas, and exercise a real private Direct/Noise lobby against a Rust HTTP fixture. The fixture receives only an addressed synthetic prompt, never unaddressed chat or the lobby name/card. A slash-prefixed response remains signed chat.
- CLI checks cover an unwritable HOME, redacted invalid arguments and Tor/cloud rejection before credentials or stdin are used.

## Terminal and Debian VM checks

A real pseudo-terminal loaded irssi's upstream default.theme, exercised a private lobby, colors, timestamped messages, compact three-line paste and the preview overlay. Sending the block displayed its /quit line as chat and kept the application running. The NO_COLOR environment setting is respected.

After the overlay revision, an 80-column terminal copied a 168-byte private test card as one logical soft-wrapped line, with no injected line breaks or borders. All underlying panels were hidden, and dismissal cleared the card. Unit tests check that ordinary invitation display emits no clipboard command; only an explicit copy action does so, with the exact original bytes. Documentation screenshots use a deterministic synthetic fixture, never these private cards.

A retained XXC Run Debian 13 x64 investigation ran the 0.4.0 UI candidate with loopback Direct listening and DHT disabled. Welcome was a dismissible overlay; lobby creation left chat empty and showed the local ephemeral identity separately from peer verification. Synthetic chat and theme switching were checked through the VM controls. No operational lobby or credentials were used.

Candidate SHA-256: 8ddfce3879dc60e32f1d2be32ffbbf26eafef510b5e6b0299af2026ea1da07cf. This VM candidate preceded the full-screen overlay/copy revision, which was checked separately in the pseudo-terminal, and a CLI help clarification. Final package checksums are in dist/SHA256SUMS and dist/SHA256SUMS-arti.

Investigations are preserved for the owner. Raw VM recordings/captures are not committed because they may include guest environment details. This UI smoke test does not establish Internet reachability or TLS-inspection resistance. Earlier protocol and Arti sandbox evidence is summarized in [ARTI-VERIFICATION.md](ARTI-VERIFICATION.md).

## Limits

Irssi support imports color/style roles; it does not reproduce all IRC templates/layouts. In RAM-only preference mode, welcome dismissal lasts one process. Public bookmarks can retain old onion seeds and correlate activity. Private invitations, trust and identities cannot be persisted.

Live paid OpenAI/Claude calls were not made: no provider credentials were supplied for those services. The local HTTP fixture verifies protocol construction, response handling and the lobby/provider boundary; provider availability, billing and retention depend on the operator's account and selected model.
