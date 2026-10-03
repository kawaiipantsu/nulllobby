# Contributing

Implement one roadmap phase at a time. Linux preview has no network backend or UI. Preserve the separation between core, transport, platform and presentation.

Run `make check` and `make deb`. Use Rust for application code, helper tools, tests and generators. No Python. Keep Cargo.lock committed, inspect new dependency releases/upstream maintenance/RustSec status, and enable only required features.

Changes to security boundaries need negative tests: wrong mode, wrong lobby, wrong secret, malformed input, replay or resource exhaustion as appropriate. Never accept a failing security gate by adding a blanket exception. Explain any narrow exception in the dependency review.

Keep real lobby data out of issues, examples, fixtures and CI. Use generated test data. Do not include secrets in panic/error/debug output. Changes to unsafe code belong only in the platform module and require a written ownership/lifetime justification.

Use your configured Git author identity; do not add generated co-author identities. Do not commit credentials, local state, package output or signing material. Keep documentation explicit about implemented versus planned behavior. See the [wiki sources](docs/wiki/Home.md) and [release guide](docs/wiki/Releases.md).
