# Screenshots

These images come from the current Ratatui renderer using synthetic demo content, fixed demonstration fingerprints and no network connections. They contain no private invitations, credentials, operational messages or machine details.

## Chat and compact paste

The header separates connection state, transport, encryption, private-lobby authentication and verification. A pasted block keeps the input one line high.

![Chat and compact paste](https://raw.githubusercontent.com/kawaiipantsu/nulllobby/main/assets/screenshots/chat.png)

## Direct transport and irssi colors

The bundled irssi-compatible example imports a blue status background and supported color/style roles. Direct peer-IP exposure remains visible.

![Imported irssi color roles](https://raw.githubusercontent.com/kawaiipantsu/nulllobby/main/assets/screenshots/irssi.png)

## Live Direct discovery

The extra Direct header row updates during the lookup: queries, replies, tokens, acknowledged announcements and candidate peers. This synthetic example has no authenticated peer session yet, so it still says `ENCRYPTION REQUIRED`. Counters do not expose addresses or invitation contents.

![Live DHT discovery](https://raw.githubusercontent.com/kawaiipantsu/nulllobby/main/assets/screenshots/discovery.png)

## Full-screen settings

Settings cover the screen below the top menu. The ember palette is selected here; persistence remains off.

![Settings](https://raw.githubusercontent.com/kawaiipantsu/nulllobby/main/assets/screenshots/settings.png)

## Full-screen help

Help covers the underlying panels and explains commands without adding messages to chat.

![Help](https://raw.githubusercontent.com/kawaiipantsu/nulllobby/main/assets/screenshots/help.png)

## Optional durable delivery and organization labels

This synthetic example enables persistent identity, durable sending and a peer mailbox. The stored receipt is distinct from human trust and the optional organization label.

![Durable delivery and organization status](https://raw.githubusercontent.com/kawaiipantsu/nulllobby/main/assets/screenshots/delivery.png)

## Regenerate

Install Rust, librsvg's `rsvg-convert` and DejaVu Sans Mono (Debian packages `librsvg2-bin fonts-dejavu-core`), then run:

~~~sh
make screenshots
~~~

The Rust screenshot fixture uses the real UI drawing function and writes SVG into `target/docs-screenshots`. Rust xtask invokes librsvg to produce the PNGs in `assets/screenshots`. This optional documentation task runs without Tor, model credentials or network peers.
