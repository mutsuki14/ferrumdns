use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ferrumdns::{Config, Runtime, VERSION};
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
            let shutdown = shutdown_signal();
            tokio::select! {
                r = rt.serve() => r.context("serve")?,
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
