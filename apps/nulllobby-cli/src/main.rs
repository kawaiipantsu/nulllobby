#![forbid(unsafe_code)]

use nulllobby_core::{EphemeralIdentity, LobbyCard, LobbyId, branding};
use nulllobby_platform::{HardeningStatus, disable_core_dumps, install_safe_panic_hook};
use std::process::ExitCode;

fn main() -> ExitCode {
    install_safe_panic_hook();
    let core_dumps = disable_core_dumps();
    let args: Vec<_> = std::env::args_os().skip(1).take(2).collect();
    if args.len() > 1 {
        return usage_error();
    }
    let arg = match args.first() {
        Some(arg) => match arg.to_str() {
            Some(arg) => arg,
            None => return usage_error(),
        },
        None => "--help",
    };
    match arg {
        "--help" | "-h" => {
            println!(
                "{} {}\n{}\n\nOptions: --help --version --about --security --self-check\nNo network connections or chat commands are available in Phase 1.",
                branding::PROJECT,
                env!("CARGO_PKG_VERSION"),
                branding::IMPLEMENTATION_STATUS
            );
        }
        "--version" => println!("{} {}", branding::PROJECT, env!("CARGO_PKG_VERSION")),
        "--about" => {
            println!(
                "{}\nCreated by {} for {}\n{}\n\nPlanned product: {}\n\n{}\nNo independent professional security audit has yet been completed.",
                branding::PROJECT,
                branding::AUTHOR,
                branding::COMMUNITY,
                branding::WEBSITE,
                branding::DESCRIPTION,
                branding::IMPLEMENTATION_STATUS
            );
        }
        "--security" | "--self-check" => {
            println!(
                "{}\nCore-dump prevention: {core_dumps:?}",
                branding::IMPLEMENTATION_STATUS
            );
            if core_dumps != HardeningStatus::Active {
                eprintln!(
                    "Core-dump prevention unavailable; refusing to create diagnostic secrets."
                );
                return ExitCode::FAILURE;
            }
            match check_foundations() {
                Ok(memory) => println!(
                    "Identity seed memory lock: {:?}\nNoise placeholder memory lock: {:?}\nApplication state: RAM only\nNetwork: inactive\nNoise: not implemented\nOffline foundation checks: passed",
                    memory[0], memory[1]
                ),
                Err(()) => {
                    eprintln!("Offline foundation check failed; details suppressed.");
                    return ExitCode::FAILURE;
                }
            }
        }
        _ => return usage_error(),
    }
    ExitCode::SUCCESS
}

fn usage_error() -> ExitCode {
    eprintln!("Unsupported arguments. Use --help. No input values were logged.");
    ExitCode::from(2)
}
fn check_foundations() -> Result<[HardeningStatus; 2], ()> {
    let lobby = LobbyId::random_public().map_err(|_| ())?;
    let identity = EphemeralIdentity::generate(lobby).map_err(|_| ())?;
    let fingerprint = identity.fingerprint();
    if fingerprint
        .to_string()
        .parse::<nulllobby_core::Fingerprint>()
        .map_err(|_| ())?
        != fingerprint
    {
        return Err(());
    }
    // No card is exported or printed by the diagnostics.
    let _card =
        LobbyCard::private(nulllobby_core::TransportKind::Direct, vec![]).map_err(|_| ())?;
    Ok(identity.memory_status())
}
