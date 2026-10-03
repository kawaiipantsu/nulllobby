//! Fixed cloud endpoints or literal loopback local models. No redirects, proxy
//! environment, tools, conversation persistence or logging of provider payloads.
use nulllobby_core::text::sanitize_terminal;
use nulllobby_transport::TransportKind;
use reqwest::{Client, Url, header::HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::{net::IpAddr, time::Duration};
use zeroize::Zeroizing;

const MAX_RESPONSE: usize = 65536;
const INSTRUCTIONS: &str = "You are a clearly identified lobby chat bot. Reply concisely to the current request. You have no tools, files, chat history or ability to take external actions.";
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Local,
    OpenAi,
    Claude,
}
impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "local model",
            Self::OpenAi => "OpenAI",
            Self::Claude => "Claude",
        }
    }
}
pub struct Options {
    pub kind: Kind,
    pub model: String,
    pub local_endpoint: Option<String>,
    pub key: Option<SecretString>,
    pub allow_cloud: bool,
}
pub struct Provider {
    client: Client,
    endpoint: Url,
    options: Options,
}
impl Provider {
    pub fn new(options: Options, mode: TransportKind) -> Result<Self, &'static str> {
        let endpoint = endpoint(&options, mode)?;
        if options.model.is_empty()
            || options.model.len() > 128
            || options.model.chars().any(char::is_control)
        {
            return Err("Bot model identifier must be 1–128 printable bytes");
        }
        if options
            .key
            .as_ref()
            .is_some_and(|s| s.expose_secret().len() > 4096)
        {
            return Err("Provider credential exceeds limit");
        }
        if options.kind != Kind::Local
            && options
                .key
                .as_ref()
                .is_none_or(|s| s.expose_secret().is_empty())
        {
            return Err("Cloud provider API key is missing");
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|_| "Bot HTTP client initialization failed")?;
        Ok(Self {
            client,
            endpoint,
            options,
        })
    }
    pub fn kind(&self) -> Kind {
        self.options.kind
    }
    pub async fn reply(&self, prompt: &str) -> Result<Zeroizing<String>, &'static str> {
        if prompt.is_empty() || prompt.len() > 8192 {
            return Err("Bot request exceeds limit");
        }
        let body = request(self.options.kind, &self.options.model, prompt);
        let mut request = self.client.post(self.endpoint.clone()).json(&body);
        if let Some(key) = &self.options.key {
            let header = if self.options.kind == Kind::Claude {
                key.expose_secret().to_owned()
            } else {
                format!("Bearer {}", key.expose_secret())
            };
            let header = Zeroizing::new(header);
            let mut value =
                HeaderValue::from_str(&header).map_err(|_| "Invalid provider credential")?;
            value.set_sensitive(true);
            request = request.header(
                if self.options.kind == Kind::Claude {
                    "x-api-key"
                } else {
                    "authorization"
                },
                value,
            );
        }
        if self.options.kind == Kind::Claude {
            request = request.header("anthropic-version", "2023-06-01");
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| "Provider request failed")?;
        if !response.status().is_success() {
            return Err("Provider rejected the request; response details withheld");
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE as u64)
        {
            return Err("Provider response exceeds 64 KiB");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "Provider response failed")?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE {
                return Err("Provider response exceeds 64 KiB");
            }
            bytes.extend_from_slice(&chunk);
        }
        decode(self.options.kind, &bytes)
    }
}
fn endpoint(options: &Options, mode: TransportKind) -> Result<Url, &'static str> {
    if options.kind != Kind::Local {
        if mode == TransportKind::Tor {
            return Err("Cloud bots are disabled in Tor mode; no clearnet API fallback");
        }
        if !options.allow_cloud {
            return Err(
                "Cloud bots require --allow-cloud; addressed prompts leave the lobby encryption boundary",
            );
        }
        if options.local_endpoint.is_some() {
            return Err("Cloud provider endpoints cannot be overridden");
        }
        return Url::parse(match options.kind {
            Kind::OpenAi => "https://api.openai.com/v1/responses",
            Kind::Claude => "https://api.anthropic.com/v1/messages",
            Kind::Local => unreachable!(),
        })
        .map_err(|_| "Invalid built-in provider endpoint");
    }
    let url = options
        .local_endpoint
        .as_deref()
        .unwrap_or("http://127.0.0.1:11434/v1/chat/completions");
    if url.len() > 2048 {
        return Err("Local model URL exceeds limit");
    }
    let endpoint = Url::parse(url).map_err(|_| "Invalid local model URL")?;
    let address = endpoint
        .host_str()
        .and_then(|s| s.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .ok_or("Local models require a literal loopback IP; no DNS")?;
    if !address.is_loopback()
        || !matches!(endpoint.scheme(), "http" | "https")
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(
            "Local models require a loopback HTTP(S) endpoint without credentials or query",
        );
    }
    Ok(endpoint)
}
fn request(kind: Kind, model: &str, prompt: &str) -> Value {
    match kind {
        Kind::OpenAi => {
            json!({"model":model,"instructions":INSTRUCTIONS,"input":prompt,"max_output_tokens":512,"store":false,"stream":false})
        }
        Kind::Claude => {
            json!({"model":model,"system":INSTRUCTIONS,"messages":[{"role":"user","content":prompt}],"max_tokens":512,"stream":false})
        }
        Kind::Local => {
            json!({"model":model,"messages":[{"role":"system","content":INSTRUCTIONS},{"role":"user","content":prompt}],"max_tokens":512,"stream":false})
        }
    }
}
fn decode(kind: Kind, bytes: &[u8]) -> Result<Zeroizing<String>, &'static str> {
    if bytes.len() > MAX_RESPONSE {
        return Err("Provider response exceeds limit");
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "Invalid provider JSON")?;
    let mut text = Zeroizing::new(String::new());
    let mut append = |part: &str| -> Result<(), &'static str> {
        if text
            .len()
            .saturating_add(part.len())
            .saturating_add(usize::from(!text.is_empty()))
            > 8192
        {
            return Err("Provider text exceeds 8 KiB");
        }
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(part);
        Ok(())
    };
    match kind {
        Kind::Local => append(
            value
                .pointer("/choices/0/message/content")
                .and_then(Value::as_str)
                .ok_or("Provider returned no text")?,
        )?,
        Kind::Claude => {
            let blocks = value["content"]
                .as_array()
                .filter(|a| a.len() <= 32)
                .ok_or("Invalid provider content")?;
            for block in blocks {
                if block["type"] == "text" {
                    append(block["text"].as_str().ok_or("Invalid provider text")?)?;
                }
            }
        }
        Kind::OpenAi => {
            let output = value["output"]
                .as_array()
                .filter(|a| a.len() <= 16)
                .ok_or("Invalid provider output")?;
            for item in output {
                if item["type"] != "message" {
                    continue;
                }
                let blocks = item["content"]
                    .as_array()
                    .filter(|a| a.len() <= 32)
                    .ok_or("Invalid provider content")?;
                for block in blocks {
                    if block["type"] == "output_text" {
                        append(block["text"].as_str().ok_or("Invalid provider text")?)?;
                    }
                }
            }
        }
    }
    let flattened = Zeroizing::new(text.replace(['\n', '\r', '\t'], " "));
    let safe = Zeroizing::new(sanitize_terminal(&flattened, 8000));
    if safe.trim().is_empty() {
        return Err("Provider returned no displayable text");
    }
    Ok(safe)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn options(kind: Kind, url: Option<&str>) -> Options {
        Options {
            kind,
            model: "test-model".into(),
            local_endpoint: url.map(str::to_owned),
            key: None,
            allow_cloud: false,
        }
    }
    #[test]
    fn tor_cloud_and_nonlocal_models_are_rejected_before_network() {
        for kind in [Kind::OpenAi, Kind::Claude] {
            let mut config = options(kind, None);
            config.allow_cloud = true;
            assert!(endpoint(&config, TransportKind::Tor).is_err());
            config.allow_cloud = false;
            assert!(endpoint(&config, TransportKind::Direct).is_err());
        }
        for url in [
            "http://localhost/v1/chat/completions",
            "http://192.0.2.1/v1",
            "http://127.0.0.1.example/v1",
            "http://key@127.0.0.1/v1",
        ] {
            assert!(endpoint(&options(Kind::Local, Some(url)), TransportKind::Tor).is_err());
        }
    }
    #[test]
    fn schemas_are_stateless_and_responses_are_bounded_and_sanitized() {
        let body = request(Kind::OpenAi, "selected-model", "synthetic request");
        assert_eq!(body["store"], false);
        assert!(body.get("tools").is_none());
        assert!(body.get("previous_response_id").is_none());
        let response=br#"{"output":[{"type":"message","content":[{"type":"output_text","text":"hello\n\u001b]52;c;bad\u0007"}]}]}"#;
        let result = decode(Kind::OpenAi, response).unwrap();
        assert!(!result.contains('\x1b'));
        assert!(!result.contains('\n'));
        assert!(decode(Kind::Claude, &vec![0; 65537]).is_err());
        assert_eq!(
            &*decode(
                Kind::Claude,
                br#"{"content":[{"type":"text","text":"ok"}]}"#
            )
            .unwrap(),
            "ok"
        );
    }
    #[tokio::test]
    async fn local_http_uses_actual_client_and_never_follows_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = vec![0; 16384];
            let n = stream.read(&mut data).await.unwrap();
            let request = String::from_utf8_lossy(&data[..n]);
            assert!(request.starts_with("POST /v1/chat/completions"));
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        });
        let provider = Provider::new(
            options(
                Kind::Local,
                Some(&format!("http://{address}/v1/chat/completions")),
            ),
            TransportKind::Tor,
        )
        .unwrap();
        assert!(provider.reply("synthetic").await.is_err());
        server.await.unwrap();
    }
}
