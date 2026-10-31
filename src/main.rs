//! `rbkeeperd enroll | pubkey | run --server URL` (see README.md and DEPLOY.md).

use std::path::PathBuf;
use std::process::ExitCode;

use log::{error, info};
use rb_keeperd::daemon::{self, Config};
use rb_keeperd::identity::{Identity, DEFAULT_IDENTITY_PATH};
use rb_keeperd::{hardening, host, logging};

/// The unit's `RestartPreventExitStatus=78` (EX_CONFIG): the server refused this
/// identity, or the host is not set up; restarting would only repeat it.
const EXIT_CONFIG: u8 = 78;

fn usage() -> String {
    format!(
        "usage:
  rbkeeperd enroll [--identity PATH]      create the identity once; print its public key and fingerprint
  rbkeeperd pubkey [--identity PATH]      print the public key and fingerprint of an existing identity
  rbkeeperd run --server URL [--identity PATH]
                                          unlock through a desktop Keeper and serve auto-fills

The identity defaults to {}. No secret is ever read
from argv or the environment.",
        DEFAULT_IDENTITY_PATH
    )
}

struct Args {
    command: String,
    identity: PathBuf,
    server: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let command = it.next().ok_or("missing command")?;
    if command == "-h" || command == "--help" {
        return Err(String::new());
    }
    let mut args = Args { command, identity: PathBuf::from(DEFAULT_IDENTITY_PATH), server: None };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--identity" => args.identity = it.next().ok_or("--identity needs a path")?.into(),
            "--server" => args.server = Some(it.next().ok_or("--server needs a URL")?),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {:?}", other)),
        }
    }
    Ok(args)
}

fn print_identity(identity: &Identity) {
    println!("headless_id: {}", identity.headless_id());
    println!("public_key:  {}", identity.public_b64());
    println!("fingerprint: {}", identity.fingerprint());
}

fn run(args: &Args) -> Result<(), (u8, String)> {
    let config_err = |m: String| (EXIT_CONFIG, m);
    let server = args.server.as_deref().ok_or_else(|| config_err("run needs --server URL".into()))?;
    let server = url::Url::parse(server).map_err(|e| config_err(format!("--server: {}", e)))?;
    daemon::check_server_url(&server).map_err(config_err)?;

    // Before any secret exists in the process, and before the runtime starts threads.
    let applied = hardening::harden_process().map_err(|e| config_err(e.to_string()))?;
    hardening::check_swap().map_err(|e| config_err(e.to_string()))?;
    info!("hardening: {}; swap is off or encrypted", applied);

    let identity = Identity::load(&args.identity).map_err(|e| config_err(e.to_string()))?;
    let boot_id = host::boot_id().map_err(config_err)?;
    let hostname = host::hostname().unwrap_or_else(|| "headless".into());
    let cfg = Config::new(server, hostname, boot_id);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| (1, format!("runtime: {}", e)))?;
    rt.block_on(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| (1, format!("SIGTERM handler: {}", e)))?;
        tokio::select! {
            r = daemon::run(cfg, identity) => r.map_err(|f| (EXIT_CONFIG, f.to_string())),
            // Returning drops the `run` future and with it every SecretString and
            // Zeroizing buffer it held: the token, password and vault are wiped.
            _ = term.recv() => { info!("SIGTERM: wiping keys and exiting"); Ok(()) }
            _ = tokio::signal::ctrl_c() => { info!("interrupt: wiping keys and exiting"); Ok(()) }
        }
    })
}

fn main() -> ExitCode {
    logging::init();
    let args = match parse_args() {
        Ok(a) => a,
        Err(m) => {
            if !m.is_empty() {
                eprintln!("rbkeeperd: {}", m);
            }
            eprintln!("{}", usage());
            return ExitCode::from(if m.is_empty() { 0 } else { 2 });
        }
    };
    let result = match args.command.as_str() {
        "enroll" => Identity::enroll(&args.identity)
            .map(|(identity, created)| {
                if created {
                    eprintln!("created {} (mode 0600); the private key stays in that file", args.identity.display());
                } else {
                    eprintln!("{} already exists; reprinting its public key", args.identity.display());
                }
                print_identity(&identity);
            })
            .map_err(|e| (1, e.to_string())),
        "pubkey" => Identity::load(&args.identity).map(|i| print_identity(&i)).map_err(|e| (1, e.to_string())),
        "run" => run(&args),
        other => {
            eprintln!("rbkeeperd: unknown command {:?}\n{}", other, usage());
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            error!("{}", msg);
            ExitCode::from(code)
        }
    }
}
