# Experimental Arti verification

Version **0.3.0**, checked on 2026-10-03. This records implementation checks, not an independent professional security audit.

## Local checks

| Check | Result |
|---|---|
| Formatting and all-features Clippy with warnings denied | Passed |
| Default workspace tests | 59 passed; two live-network tests ignored |
| All-features workspace tests | 63 passed; three live-network tests ignored |
| Patched upstream service tests | 42 passed; two upstream ignored tests |
| Patched service tests with optional proof-of-work code enabled | 47 passed; two upstream ignored tests |
| Real Arti onion transport | Passed: bootstrap, two independent services, private Noise/proof, encrypted record roundtrip, stream cleanup and released connection permits |
| Persistent Tor state separation | Live test found no service or key-store directory in the normal Tor state directory; unit test confirms ephemeral storage has no filesystem handle |
| Dependency gates | Audit and deny passed with the documented RSA applicability exception and maintenance warnings; see [dependency review](ARTI-DEPENDENCIES.md) |
| Standard and experimental Debian packages | Built; archive/package checksums passed; offline diagnostics passed with `HOME=/proc` |
| Nine parser fuzz targets | All completed ten-second smoke campaigns without a crash; 41,562,643 total executions |

The live Arti test uses ordinary Tor relays and preserves Tor guard/cache state between retries. A first attempt exceeded its publication deadline; a later run passed in 23.84 seconds. This does not establish universal reachability or protect against traffic correlation. Only synthetic records and ephemeral test identities were used.

The experimental Debian package additionally requires `libsqlite3-0` for Arti's normal directory cache. The packaged application does not write chat data there. Both packages report a glibc minimum derived from their ELF requirements; these builds require glibc 2.39.

## External Debian sandbox

Two investigations were retained in the project owner's analysis service, using Debian 13 x64 and its full-network policy:

- The actual experimental TUI binary launched and passed offline core-dump/memory-lock diagnostics. A private Tor lobby creation stayed at 0% bootstrap, reached its deadline, reported transport failure and attempted no backend fallback.
- The separately built Rust application integration executable passed all five tests in 1.73 seconds: three-peer private signed forwarding/trust/cleanup, Direct with an unwritable HOME, scoped Tor endpoints using local fixtures, unavailable Tor without Direct/DHT/DNS, and authenticated flood rejection.

The TUI investigation's PCAP contains 216 TCP SYNs and 216 resets, with no TCP payload or completed TLS exchange. Other traffic is guest DHCP, local multicast discovery and link maintenance. No BitTorrent or DHT payload appears. The sandbox's HTTPS exchange export is empty. This is evidence of failed connectivity and observed fail-closed behavior, **not** evidence that TLS interception succeeded or caused the failure. Successful real-Arti delivery was verified separately outside this sandbox.

The protocol tests use loopback TCP, which is not present in the sandbox's external-interface PCAP. The passing assertions establish those roundtrips; do not misrepresent the external capture as a capture of their ciphertext. Tor fixture tests emulate local Tor interfaces; they do not contact real onion services.

Recordings, screenshots, PCAP and SCAP exports remain in both investigations. The service describes its SCAP as exported observations rather than a complete kernel syscall trace; its collectors and packet budgets limit conclusions. No operational lobby data or credentials were used. Investigation links are supplied privately to the owner, rather than published here.

## Reproduce

```sh
make check
make deb
make deb-arti
cargo test --locked --manifest-path vendor/tor-hsservice/Cargo.toml \
  --lib --features ephemeral-service,hs-pow-full
NULLLOBBY_TEST_ARTI_STATE=/absolute/tor-state \
NULLLOBBY_TEST_ARTI_CACHE=/absolute/tor-cache \
cargo test -p nulllobby-tor --features tor-arti-experimental \
  --test arti real_arti -- --ignored --nocapture
```

For the established Direct, external-Tor, signature, replay and terminal-input regressions, see the [v0.2 verification map](VERIFICATION.md). Those regressions remain part of the workspace checks.
