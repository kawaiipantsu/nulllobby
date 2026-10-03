# Headless bots

Bots use the same Direct/Tor, Noise, identity-proof and signed-message core as the TUI. They have fresh lobby identities, nicknames ending in `[bot]`, and provider-labeled replies.

Only messages beginning `@NAME ` are processed, excluding the bot's own signed messages. Only that prompt reaches the provider: no previous chat, nicknames, fingerprints, cards or lobby names. Users may still include sensitive information in a prompt; addressed prompts intentionally cross the lobby encryption boundary.

One request can be in flight, with five seconds between requests. Busy/excess prompts are dropped. Default session quota: 100 requests; `--bot-max-requests` accepts 1–10000. Lobby members can consume this quota. No tools, shell, files or agent actions are exposed. Output is bounded, sanitized and sent as chat even if it begins with `/`.

## Local model

Run a model server supporting OpenAI-compatible `/v1/chat/completions`, such as a configured [Ollama server](https://docs.ollama.com/api/openai-compatibility). Choose an installed model; NullLobby does not download/select one.

~~~sh
nulllobby --bot --bot-name helper --bot-provider local --bot-model YOUR_MODEL --bot-create public --bot-lobby-name coordination --bot-export-invite
~~~

Default endpoint: `http://127.0.0.1:11434/v1/chat/completions`. Override with `--bot-endpoint http://127.0.0.1:PORT/v1/chat/completions`. Only literal loopback IPs are accepted; no hostnames, redirects, proxy environment variables or remote destinations.

To join, replace create/name options with `--bot-card-stdin`. Supply the card on stdin and end input with EOF. Avoid private cards in shell arguments/history, files or shared terminal transcripts. `--bot-export-invite` explicitly prints the invitation to stdout; otherwise invites/chat are not printed. Never redirect a private card to an unprotected log.

Send `@helper summarize this synthetic example` in the lobby. A signed disclosure announces the provider to new members; every reply also names it. Nicknames remain cosmetic: verify full fingerprints to authenticate the operator.

## OpenAI or Claude

Cloud providers require **both** provider selection and `--allow-cloud`. Credentials come from `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in the process environment, never CLI values/settings files. Provision them through your secret-management environment without echoing/committing them. Environment variables and HTTP-library copies are not guaranteed locked/zeroized.

~~~sh
nulllobby --bot --bot-name helper --bot-provider openai --bot-model YOUR_MODEL --allow-cloud --bot-card-stdin
~~~

Use `--bot-provider claude` for Anthropic. Choose an available model and check the service fits the lobby's data-handling expectations. Requests use fixed official HTTPS endpoints; custom cloud URLs are rejected.

OpenAI uses the [Responses API](https://developers.openai.com/api/docs/guides/migrate-to-responses) with `store:false`, no conversation identifier, tools or background mode. This does **not** guarantee zero provider retention: [abuse monitoring and account data controls](https://developers.openai.com/api/docs/guides/your-data) are separate. Claude uses [Messages](https://platform.claude.com/docs/en/api/messages/create) with one user message and no tools. Provider policies apply outside NullLobby.

## Tor boundary and limits

Cloud bots are rejected in Tor mode before any provider connection. No clearnet API fallback or cloud-over-exit option. A local loopback model works with external Tor or experimental Arti; supply the usual Tor arguments. The model service's own network activity is outside NullLobby's control. Use a genuinely local model if prompts must remain on that machine.

Replies are capped at 64 KiB of JSON and 8 KiB of extracted text, with connection/read/total deadlines. Errors print fixed categories, never prompts, responses or credentials. Tests use Rust HTTP fixtures and real encrypted lobby connections. Live paid-provider calls need operator credentials and are not part of CI.
