# Terminal interface and themes

Chat starts empty. Welcome, help, invitations and notifications fill the screen below the top menu, hiding the underlying panels and their borders. Esc closes the overlay. Routine notices stay behind F7. Errors open the notification window.

## Controls

| Key | Action |
|---|---|
| F1 / Alt+H | Help |
| F2 / Alt+L | Toggle lobbies |
| F3 / Alt+U | Toggle members |
| F4 | Settings |
| F5 | Network/security inspection |
| F6 | Paste preview |
| F7 | Notifications, newest first |
| F8 | Remembered public lobbies |
| F9 | Toggle timestamps |
| F10 / Ctrl+C | Quit |
| PgUp / PgDn | Scroll chat or an overlay |
| Esc | Close overlay or clear input |
| Left / Right / Home / End / Backspace / Delete | Edit input |

Use the terminal's normal copy/paste keys, often Ctrl+Shift+C/V. Bracketed paste preserves a block as one editable input. Multiple lines display `[Pasted N lines · N bytes]` in the one-line input; F6 previews it. Enter sends each nonempty line as chat, including lines beginning with `/`. It never runs a pasted block as a command script. Single-line commands still work, including a pasted `/join` command.

Pastes are limited to 8 KiB and 32 lines. The entire block needs space in the bounded command queue before submission; otherwise it stays in the input. Local submission does not guarantee delivery to every peer. NullLobby never accesses the clipboard automatically.

A multiline paste containing a lobby card or a `/join` line is blocked from chat submission, including a pasted card command with a trailing newline. Enter the join command on one line. Card previews are hidden.

## Copy invitations

`/invite` displays the card as one unbroken logical terminal line. The terminal may soft-wrap it across the full screen width; NullLobby adds no line breaks, indentation or border characters to the card. Select it with your terminal's normal copy shortcut. The card is not continually redrawn while you select it.

Alternatively, press **Ctrl+Y** inside the invitation overlay to explicitly request a clipboard copy through OSC52. This copies the original complete card, including when the terminal is too small to display it. Your terminal may require permission or may not support OSC52; the UI reports a request, not guaranteed clipboard success. Remote messages cannot trigger this action. Clipboard managers and terminal scrollback are outside the security boundary. Esc clears the displayed card.

Timestamps use local `HH:MM:SS`; `/timestamps on|off` or F9 toggles them. A horizontal date separator appears at local midnight even without a new message. These display times do not participate in replay security.

The header separately shows connectivity, transport/IP exposure, encryption, lobby type, verified peers and padding. F5 and `/security` show details. Short fingerprints in chat/member panels are only labels: use `/fingerprint`, `/who` and full fingerprints for verification.

## Palettes and borders

Built-in palettes: `null`, `ember`, `ice`, `classic`, `light`.

~~~text
/theme ember
/borders ascii
/borders unicode
/icons on
/timestamps off
~~~

Nerd Font icons default off and require a compatible terminal font. NullLobby does not install fonts. Narrow terminals hide sidebars automatically.

Native palettes use a TOML `[colors]` table. Roles: `background`, `text`, `border`, `accent`, `muted`, `warning`, `error`, `nick`, `own`, `status`. Colors accept Ratatui names or `#RRGGBB`; see `themes/ember.toml`.

~~~sh
nulllobby --theme themes/ember.toml
~~~

## Import an irssi theme directly

~~~sh
nulllobby --theme /absolute/path/to/favorite.theme
~~~

Or use `/theme /absolute/path/to/favorite.theme` while running. The `.theme` extension selects the irssi parser. No conversion utility is required. `themes/nulllobby.theme` is an original example.

This imports a **color/style subset**, not the complete irssi rendering engine:

| irssi abstract | NullLobby role |
|---|---|
| `window_border` | Panel borders |
| `sb_background` | Header foreground/background |
| `timestamp` | Timestamps and muted text |
| `hilight` | Accents |
| `error` | Error style |
| `pubnick` | Remote nicknames |
| `ownnick` | Own nickname |
| `menick` | Warning style |

Supported: standard 16 colors, `%0`–`%7` backgrounds, `%XAB`/`%xAB` indexed colors, `%Zrrggbb`/`%zrrggbb` RGB, bold, underline, italic and reverse. Extraction reads the prefix before the first `$` parameter and follows bounded abstract references. `%n`/`%N` reset the extracted style; irssi's nested “previous color” behavior is not reproduced.

IRC message formats, replacements, decorations, statusbar layout, blinking, scripts and includes do not execute or change layout. Unsupported style codes are ignored. Unsupported file syntax produces an error. Some themes therefore look different; use a native palette for exact role mapping.

Files are capped at 64 KiB, 8,192 tokens, 512 assignments, eight nesting levels and bounded abstract recursion. Controls cannot become raw terminal escapes. The import notice reports mapped roles. Loading a theme saves preferences only if saving is enabled.

Sources: [irssi format codes](https://raw.githubusercontent.com/irssi/irssi/master/docs/formats.txt), [default theme structure](https://raw.githubusercontent.com/irssi/irssi/master/themes/default.theme).

## Optional remembered settings

Defaults remain RAM-only. F4 → `7` enables saved preferences, or start with `--settings /absolute/path/settings.toml`. Default location: `$XDG_CONFIG_HOME/nulllobby/settings.toml`, otherwise `$HOME/.config/nulllobby/settings.toml`. Files must be regular files with private permissions; writes use atomic replacement and mode 0600.

The file contains display preferences, nickname, welcome-dismissed flag and at most 16 explicitly remembered **public** cards. No identity keys, trust, fingerprints, history or private invitations. Reusing a nickname, public lobby ID or seed can correlate activity despite fresh identities.

~~~text
/remember team-room
/bookmarks
/autoconnect 1 on
/connect 1
/forget 1
~~~

`/remember` requires saving enabled and an active public lobby. Autoconnect defaults off and joins only cards matching the explicitly selected transport. It never switches transport. Tor cards fail when all saved ephemeral seeds go offline. Private cards must be supplied again after restart.

F4 → `7` disables saving and removes the settings file; this is not secure erasure from backups/storage. With RAM-only settings, welcome appears once per process. Enable preferences to remember dismissal across processes, or pass `--no-welcome`. Bot mode ignores TUI preferences/bookmarks.
