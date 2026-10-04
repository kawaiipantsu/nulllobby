# NullLobby 0.5.1 — Debian 12 support

Both Linux amd64 package variants now target **Debian 12 and newer, with `libc6 (>= 2.36)`**. The binaries and Linux archives are compiled inside a digest-pinned Rust 1.94.1 / Debian 12 environment. Packaging checks ELF symbol requirements and refuses any dependency on a newer glibc, including weak symbol requirements.

This changes the actual build baseline. There is no system libc downgrade or bundled replacement libc. Published 0.5.0 artifacts remain unchanged.

## Install or upgrade

With the [official APT repository configured](https://github.com/kawaiipantsu/nulllobby/wiki/APT):

```sh
sudo apt update
sudo apt install nulllobby
nulllobby --version
nulllobby --self-check
```

The suite is `zerotrust`, component `main`, architecture `amd64`. Choose `nulllobby-arti-experimental` only to evaluate embedded Arti; the variants conflict because both install the same executable. Optional encrypted vaults need `libsecret-tools` and a protected, unlocked Secret Service. Installing the package does not enable persistence or install a service.

## Compatibility and build checks

- The application protocol, v2 invitation cards and encryption suites are unchanged from 0.5.0. Existing 0.5.0 participants can communicate with 0.5.1.
- Upgrading from 0.4.x still requires upgrading all participants and exchanging fresh v2 cards.
- `make deb`, `make deb-arti` and signed release builds use the Debian 12 container; Docker access is required for packaging, with no host-build fallback.
- CI runs workspace checks and installs both package variants in Debian 12 userspace. The ELF guard also rejects glibc 2.39 weak requirements that appeared in the older build.

Direct exposes peer IPs. Tor onion transport never falls back to Direct; traffic correlation remains possible. Embedded Arti remains experimental, and existing documented dependency exceptions remain. No independent professional security audit has been completed.
