use std::path::PathBuf;

use anyhow::Result;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{Level, error, info};
use tracing_subscriber::fmt::time::ChronoLocal;

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<String>>();
    let level = if args.iter().any(|v| v.as_str() == "-d") {
        Level::DEBUG
    } else {
        Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_timer(ChronoLocal::new("%Y-%m-%d %H:%M:%S%.3f".to_string()))
        .with_ansi(atty::is(atty::Stream::Stdout))
        .init();
    info!("Log level = {level}");
    let values = &args[1..]
        .iter()
        .filter(|v| !v.starts_with("-"))
        .collect::<Vec<_>>();
    let config_path = PathBuf::from(if values.is_empty() {
        "./config.json".to_string()
    } else {
        values[1].clone()
    });
    info!("Using config: {:?}", config_path);

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
