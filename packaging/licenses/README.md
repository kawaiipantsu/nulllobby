# Reviewed dependency notices

Fallback copies are used only when the registry crate omitted its license file. Filenames include the exact dependency version; upgrades require a fresh review.

- `bendy-0.6.1.txt`: BSD-3-Clause text from `P3KI/bendy`, commit `aa55b38a86ebb1dad1e6390fe002f66159714713`, root `LICENSE-BSD3`. This commit is recorded in the published crate's `.cargo_vcs_info.json`.
- `amplify_num-0.5.4.txt`: Apache-2.0, `rust-amplify/amplify-num`, commit `872842c3d151296b18314dfa5bf86548c2ce4f29`, root `LICENSE`.
- `amplify_syn-2.0.1.txt`: Apache-2.0, `rust-amplify/amplify-derive`, commit `29ca86c56316ce683bf3827a9d245334db69ce1f`, root `LICENSE`.
- `asn1-rs-impl-0.2.0.txt`: MIT, `rusticata/asn1-rs`, commit `a20e5f7319c896737ad0f2557037817b91ad854f`, root `LICENSE-MIT`.
- `cookie-factory-0.3.3.txt`: MIT, `rust-bakery/cookie-factory`, commit `d36b805dbd7dd65f2df947235c5bcc573afe2c76`, `LICENSES/MIT.txt`.
- `priority-queue-2.7.0.txt`: MPL-2.0, `garro95/priority-queue`, commit `0c76fb8fe75e4457f16f8e6c8e86508d1a89ba1d`, root `MPL-2.0.txt`.
- `void-1.0.2.txt`: MIT, `reem/rust-void`, commit `a6e061227f47ba8798b7e828ed0ac4e25382eb15`, root `LICENSE-MIT`.
- `derive-deftly-macros-1.12.1.txt`: MIT, copied from the matching published `derive-deftly` 1.12.1 archive's `LICENCE`.

Arti 0.47.0 crates that omit root license texts use `vendor/tor-hsservice/LICENSE-MIT` and `LICENSE-APACHE`, obtained from the exact Arti upstream commit recorded in `vendor/tor-hsservice/NULLLOBBY-PATCH.md`. The packager checks the repository and license expression before applying this fallback.

Only trailing whitespace and the extra final blank line are normalized; license wording is unchanged.
