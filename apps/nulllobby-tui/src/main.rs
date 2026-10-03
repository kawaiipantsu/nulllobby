#![forbid(unsafe_code)]
mod ui;
use nulllobby_app::{App, Config};
use nulllobby_core::{EphemeralIdentity, LobbyCard, LobbyId, branding};
use nulllobby_platform::{HardeningStatus, disable_core_dumps, install_safe_panic_hook};
use nulllobby_transport::{Endpoint, TransportKind};
use std::{net::SocketAddr, num::NonZeroU16, process::ExitCode};

fn main() -> ExitCode {
    install_safe_panic_hook();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stderr(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::cursor::Show
        );
        hook(info);
    }));
    let hardening = disable_core_dumps();
    match run(hardening) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
fn run(hardening: HardeningStatus) -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args_os().skip(1).take(40).collect();
    if args.len() >= 40 {
        return Err("Too many arguments; use --help");
    }
    let mut config = Config::default();
    let mut diagnostic = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let option = arg.to_str().ok_or("Invalid option; use --help")?;
        match option {
            "--help" | "-h" | "--version" | "--about" | "--security" | "--self-check" => {
                if diagnostic.replace(option).is_some() {
                    return Err("Choose one diagnostic option");
                }
            }
            "--listen" => {
                config.direct.listen = args
                    .next()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse().ok())
                    .ok_or("--listen requires a numeric IP:port")?
            }
            "--peer" => {
                let address: SocketAddr = args
                    .next()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse().ok())
                    .ok_or("--peer requires a numeric IP:port")?;
                if config.peers.len() >= 8 {
                    return Err("Maximum 8 explicit peers");
                }
                config.peers.push(Endpoint::Direct {
                    address: address.ip(),
                    port: NonZeroU16::new(address.port()).ok_or("Peer port must be nonzero")?,
                });
            }
            "--no-dht" => config.no_dht = true,
            "--tor-socks" => {
                config.tor.socks = args
                    .next()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse().ok())
                    .ok_or("--tor-socks requires a numeric loopback IP:port")?
            }
            "--tor-control" => {
                config.tor.control = args
                    .next()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse().ok())
                    .ok_or("--tor-control requires a numeric loopback IP:port")?
            }
            "--tor-cookie" => {
                config.tor.cookie = Some(
                    args.next()
                        .ok_or("--tor-cookie requires a readable Tor authentication cookie file")?
                        .into(),
                )
            }
            "--transport" => {
                config.mode = match args.next().and_then(|s| s.to_str()) {
                    Some("direct") => TransportKind::Direct,
                    Some("tor") => TransportKind::Tor,
                    _ => return Err("--transport requires direct or tor"),
                }
            }
            _ => return Err("Unsupported option; use --help. Argument values are not logged."),
        }
    }
    if let Some(option) = diagnostic {
        match option {
            "--help" | "-h" => println!(
                "{} {}\n\nRun without options for the terminal client.\n--transport direct|tor\n--listen IP:PORT          Direct listener (default random port)\n--peer IP:PORT            Explicit Direct peer (up to 8)\n--no-dht                  Direct localhost/developer mode\n--tor-socks 127.0.0.1:9050\n--tor-control 127.0.0.1:9051\n--tor-cookie PATH         Explicit SAFECOOKIE authentication file\n--help --version --about --security --self-check\n\nDirect exposes peer IPs. Tor never falls back to Direct. Application state is RAM only.",
                branding::PROJECT,
                env!("CARGO_PKG_VERSION")
            ),
            "--version" => println!("{} {}", branding::PROJECT, env!("CARGO_PKG_VERSION")),
            "--about" => println!(
                "{}\nCreated by {} for {}\n{}\n\n{}\n\nApplication identities, trust and history are RAM only. Direct is not anonymous. Tor uses onion-service transport. No independent professional security audit has yet been completed.",
                branding::PROJECT,
                branding::AUTHOR,
                branding::COMMUNITY,
                branding::WEBSITE,
                branding::DESCRIPTION
            ),
            "--security" | "--self-check" => {
                println!("Core-dump prevention: {hardening:?}");
                if hardening != HardeningStatus::Active {
                    return Err("Core-dump prevention failed; refusing to create secrets");
                }
                let lobby = LobbyId::random_public().map_err(|_| "Entropy unavailable")?;
                let identity =
                    EphemeralIdentity::generate(lobby).map_err(|_| "Identity generation failed")?;
                let _card = LobbyCard::private(TransportKind::Direct, vec![])
                    .map_err(|_| "Capability generation failed")?;
                println!(
                    "Secret memory locks: {:?}\nApplication state: RAM only\nOffline checks: passed\nNetwork: inactive for diagnostics\nPublic suite: {}\nPrivate suite: {}\nDirect is not anonymous. Tor never falls back to Direct. No independent security audit.",
                    identity.memory_status(),
                    nulllobby_core::session::PUBLIC_SUITE,
                    nulllobby_core::session::PRIVATE_SUITE
                );
            }
            _ => return Err("Unsupported diagnostic"),
        }
        return Ok(());
    }
    if hardening != HardeningStatus::Active {
        return Err("Core-dump prevention failed; refusing to start chat");
    }
    if config.mode == TransportKind::Tor && !config.peers.is_empty() {
        return Err("--peer is Direct-only; Tor peers come from onion lobby cards");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "Runtime initialization failed")?;
    let (commands, rx) = nulllobby_transport::command_channel();
    #[cfg(unix)]
    {
        let shutdown = commands.clone();
        runtime.spawn(async move {
            use tokio::signal::unix::{signal,SignalKind};
            let Ok(mut terminate) = signal(SignalKind::terminate()) else { return; };
            let Ok(mut hangup) = signal(SignalKind::hangup()) else { return; };
            tokio::select! { _ = terminate.recv() => {}, _ = hangup.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
            let _ = shutdown.send(nulllobby_core::domain::AppCommand::Shutdown).await;
        });
    }
    let (events, ev_rx) = nulllobby_transport::event_channel();
    let task = runtime.spawn(App::new(config, rx, events).run());
    let result = ui::run(commands, ev_rx)
        .map_err(|_| "Terminal unavailable; run in an interactive terminal or use --help");
    runtime.block_on(async {
        if tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .is_err()
        { /* Runtime drop closes all owned endpoints. */ }
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}
