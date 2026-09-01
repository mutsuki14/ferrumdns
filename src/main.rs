use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ferrumdns::{Config, Live, Runtime, VERSION};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ferrumdns", version = VERSION, about = "High-performance plugin-pipeline DNS forwarder")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the forwarder
    Start {
        #[arg(short, long, default_value = "config.yaml")]
        config: PathBuf,
    },
    /// Validate a config file without listening
    Check {
        #[arg(short, long, default_value = "config.yaml")]
        config: PathBuf,
    },
    /// Print version
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Version => {
            println!("ferrumdns {VERSION}");
            Ok(())
        }
        Command::Check { config } => {
            init_log("info");
            let cfg = Config::load_file(&config)
                .with_context(|| format!("load {}", config.display()))?;
            let _rt = Runtime::build(cfg).await.context("build runtime")?;
            println!("config ok ({})", config.display());
            Ok(())
        }
        Command::Start { config } => {
            let cfg = Config::load_file(&config)
                .with_context(|| format!("load {}", config.display()))?;
            init_log(&cfg.log.level);
            tracing::info!(file = %config.display(), version = VERSION, "starting ferrumdns");
            let _ = rustls::crypto::ring::default_provider().install_default();
            let rt = Runtime::build(cfg).await.context("build runtime")?;
            let live = Live::new(rt);
            let reloader = live.clone();
            let cfg_path = config.clone();
            tokio::spawn(async move {
                reload_loop(reloader, cfg_path).await;
            });
            let shutdown = shutdown_signal();
            tokio::select! {
                r = live.serve() => r.context("serve")?,
                _ = shutdown => tracing::info!("shutdown"),
            }
            Ok(())
        }
    }
}

fn init_log(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("ferrumdns={level},info")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

/// SIGHUP rebuilds plugins from disk without dropping UDP/TCP sockets.
/// Listen address / protocol changes still need a process restart.
#[cfg(unix)]
async fn reload_loop(live: Live, path: PathBuf) {
    let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(err = %e, "could not install SIGHUP handler");
            return;
        }
    };
    loop {
        hangup.recv().await;
        tracing::info!(file = %path.display(), "SIGHUP: reloading plugins");
        match live.reload_file(&path).await {
            Ok(()) => tracing::info!("reload ok (listeners unchanged; cache rebuilt)"),
            Err(e) => tracing::error!(err = %e, "reload failed; keeping previous config"),
        }
    }
}

#[cfg(not(unix))]
async fn reload_loop(_live: Live, _path: PathBuf) {}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
