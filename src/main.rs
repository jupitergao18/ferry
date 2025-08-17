use std::path::PathBuf;

use anyhow::Result;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{error, info};
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<String>>();
    let config_path = PathBuf::from(if args.len() < 2 {
        "./config.json".to_string()
    } else {
        args[1].clone()
    });

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

    if let Err(e) = ferry::run(config_path, ctrlc_tx_for_subscribe).await {
        error!("{e:?}");
    }

    info!("Shutdown");
    Ok(())
}
