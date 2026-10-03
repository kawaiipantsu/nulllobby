use nulllobby_bot::{
    Bot, Start,
    provider::{Kind, Options, Provider},
};
use nulllobby_core::{LobbyCard, domain::LobbyName};
use nulllobby_transport::TransportKind;
use std::{ffi::OsString, io::Read};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct Args {
    enabled: bool,
    touched: bool,
    name: Option<String>,
    model: Option<String>,
    provider: Option<Kind>,
    endpoint: Option<String>,
    create: Option<String>,
    lobby_name: Option<String>,
    stdin: bool,
    cloud: bool,
    export: bool,
    limit: Option<u32>,
}
impl Args {
    pub fn parse<'a>(
        &mut self,
        option: &str,
        args: &mut impl Iterator<Item = &'a OsString>,
    ) -> Result<bool, &'static str> {
        let takes_value = matches!(
            option,
            "--bot-name"
                | "--bot-model"
                | "--bot-provider"
                | "--bot-endpoint"
                | "--bot-create"
                | "--bot-lobby-name"
                | "--bot-max-requests"
        );
        if !takes_value
            && !matches!(
                option,
                "--bot" | "--bot-card-stdin" | "--bot-export-invite" | "--allow-cloud"
            )
        {
            return Ok(false);
        }
        self.touched = true;
        let value = if takes_value {
            args.next()
                .and_then(|a| a.to_str())
                .filter(|s| s.len() <= 2048)
                .ok_or("Bot option requires a bounded UTF-8 value")?
        } else {
            ""
        };
        match option {
            "--bot" => self.enabled = true,
            "--bot-name" => self.name = Some(value.into()),
            "--bot-model" => self.model = Some(value.into()),
            "--bot-provider" => {
                self.provider = Some(match value {
                    "local" => Kind::Local,
                    "openai" => Kind::OpenAi,
                    "claude" => Kind::Claude,
                    _ => return Err("Bot provider must be local, openai or claude"),
                })
            }
            "--bot-endpoint" => self.endpoint = Some(value.into()),
            "--bot-create" => self.create = Some(value.into()),
            "--bot-lobby-name" => self.lobby_name = Some(value.into()),
            "--bot-card-stdin" => self.stdin = true,
            "--allow-cloud" => self.cloud = true,
            "--bot-export-invite" => self.export = true,
            "--bot-max-requests" => {
                self.limit = Some(value.parse().map_err(|_| "Invalid bot request limit")?)
            }
            _ => unreachable!(),
        }
        Ok(true)
    }
    pub fn build(self, mode: TransportKind) -> Result<Option<(Bot, Start, bool)>, &'static str> {
        if !self.enabled {
            return if self.touched {
                Err("Bot options require --bot")
            } else {
                Ok(None)
            };
        }
        let kind = self.provider.ok_or("--bot-provider is required")?;
        let key = match kind {
            Kind::Local => None,
            Kind::OpenAi => Some("OPENAI_API_KEY"),
            Kind::Claude => Some("ANTHROPIC_API_KEY"),
        }
        .and_then(|name| std::env::var(name).ok())
        .map(secrecy::SecretString::from);
        let provider = Provider::new(
            Options {
                kind,
                model: self.model.ok_or("--bot-model is required")?,
                local_endpoint: self.endpoint,
                key,
                allow_cloud: self.cloud,
            },
            mode,
        )?;
        let bot = Bot::new(
            provider,
            &self.name.ok_or("--bot-name is required")?,
            self.limit.unwrap_or(100),
        )?;
        let start = if self.stdin {
            if self.create.is_some() || self.lobby_name.is_some() {
                return Err("Choose --bot-card-stdin or --bot-create");
            }
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .lock()
                .take(16385)
                .read_to_end(&mut bytes)
                .map_err(|_| "Cannot read lobby card from stdin")?;
            if bytes.len() > 16384 {
                return Err("Lobby card input exceeds limit");
            }
            let text = std::str::from_utf8(&bytes).map_err(|_| "Invalid lobby card encoding")?;
            let card = LobbyCard::parse(text.trim()).map_err(|_| "Invalid lobby card")?;
            if card.transport() != mode {
                return Err("Bot card transport does not match --transport");
            }
            Start::Join(card)
        } else {
            let name = LobbyName::new(
                &self
                    .lobby_name
                    .ok_or("--bot-lobby-name is required when creating a lobby")?,
            )
            .map_err(|_| "Invalid bot lobby name")?;
            match self.create.as_deref() {
                Some("public") => Start::Public(name),
                Some("private") => Start::Private(name),
                _ => return Err("Use --bot-card-stdin or --bot-create public|private"),
            }
        };
        if self.export {
            eprintln!(
                "Explicit invite export enabled: stdout may contain a private capability. Protect terminal scrollback and shell redirection."
            );
        }
        if kind != Kind::Local {
            eprintln!(
                "Cloud bot enabled: addressed prompts leave the lobby and are sent to the selected API provider."
            );
        }
        Ok(Some((bot, start, self.export)))
    }
}
