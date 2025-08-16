use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::time::ChronoLocal;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or(EnvFilter::from("debug")))
        .with_timer(ChronoLocal::new("%Y-%m-%d %H:%M:%S%.3f".to_string()))
        .with_ansi(atty::is(atty::Stream::Stdout))
        .init();
    info!("Logger started");

    let (ctrlc_tx, _) = broadcast::channel::<bool>(1);
    let ctrlc_tx_for_subscribe = ctrlc_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = signal::ctrl_c().await {
            panic!("Failed to listen for the ctrl-c signal: {e:?}");
        }
        info!("Ctrl-c received");
        if let Err(e) = ctrlc_tx.send(true) {
            panic!("Failed to send shutdown signal: {e:?}");
        }
    });

    if let Err(e) = ferry::run(args.config_path, ctrlc_tx_for_subscribe).await {
        error!("{e:?}");
    }

    info!("Shutdown");
    Ok(())
}

#[derive(Parser, Debug, Default, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Configuration file
    #[arg(short, long, default_value = "./config.json")]
    pub config_path: PathBuf,
}
