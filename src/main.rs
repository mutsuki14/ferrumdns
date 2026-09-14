use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ferrumdns::config::LogConfig;
use ferrumdns::{Config, Live, Runtime, VERSION};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
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
            init_log(&LogConfig::default())?;
            let cfg =
                Config::load_file(&config).with_context(|| format!("load {}", config.display()))?;
            let rt = Runtime::build(cfg).await.context("build runtime")?;
            rt.validate_service().context("validate service")?;
            println!("config ok ({})", config.display());
            Ok(())
        }
        Command::Start { config } => {
            let cfg =
                Config::load_file(&config).with_context(|| format!("load {}", config.display()))?;
            init_log(&cfg.log)?;
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

fn init_log(log: &LogConfig) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(format!("ferrumdns={},info", log.level)))
        .context("invalid log filter")?;
    let writer = if let Some(path) = &log.file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open log file {path}"))?;
        BoxMakeWriter::new(Mutex::new(file))
    } else {
        BoxMakeWriter::new(std::io::stdout)
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(log.file.is_none())
        .with_target(false)
        .compact()
        .init();
    Ok(())
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
    while hangup.recv().await.is_some() {
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
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
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
