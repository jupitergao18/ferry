use crate::client::Client;
use crate::config::{Config, ConfigChangeEvent};
use crate::server::Server;
use anyhow::Result;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

mod client;
mod config;
mod noise;
mod server;
// mod service;
mod protocol;

pub async fn run(config_path: PathBuf, ctrlc_tx: broadcast::Sender<bool>) -> Result<()> {
    if let Err(e) = fdlimit::raise_fd_limit() {
        warn!("Raise fd limit error: {e:?}");
    }

    let ctrlc_rx = ctrlc_tx.subscribe();
    let (config_change_tx, mut config_change_rx) = mpsc::unbounded_channel::<ConfigChangeEvent>();
    tokio::spawn(async move { config::watch(config_path, config_change_tx, ctrlc_rx).await });

    let mut instance_stop_tx: Option<broadcast::Sender<()>> = None;

    while let Some(change_event) = config_change_rx.recv().await {
        match change_event {
            ConfigChangeEvent::FullRestart(config) => {
                info!("ConfigChangeEvent::FullRestart");
                if let Some(previous_stop_tx) = &instance_stop_tx {
                    info!("Sending stop signal");
                    if let Err(e) = previous_stop_tx.send(()) {
                        error!("Stop previous instance error: {e:?}");
                        break;
                    }
                }

                let (stop_tx, _) = broadcast::channel::<()>(1024);
                let new_instance = Instance::new(config, stop_tx.clone());
                tokio::spawn(async move { new_instance.run().await });

                instance_stop_tx = Some(stop_tx);
            }
        }
    }

    if let Some(stop_tx) = &instance_stop_tx {
        if let Err(e) = stop_tx.send(()) {
            error!("Stop instance error: {e:?}");
        }
    }

    Ok(())
}

struct Instance {
    config: Config,
    stop_tx: broadcast::Sender<()>,
}

impl Instance {
    fn new(config: Config, stop_tx: broadcast::Sender<()>) -> Self {
        info!("Instance created");
        Self { config, stop_tx }
    }

    async fn run(&self) -> Result<()> {
        let server_stop_rx = self.stop_tx.subscribe();
        if let Some(server_config) = self.config.server.clone() {
            let mut server = Server::from_config(server_config)?;
            tokio::spawn(async move { server.run(server_stop_rx).await });
        }

        for client_config in self.config.clients.clone() {
            let client_stop_rx = self.stop_tx.subscribe();
            let mut client = Client::from_config(client_config).await?;
            tokio::spawn(async move { client.run(client_stop_rx).await });
        }

        if let Err(e) = self.stop_tx.subscribe().recv().await {
            error!("instance stop signal receive error: {e:?}");
        }

        info!("Instance shutdown");

        Ok(())
    }

    // fn config_change(&mut self, config: Config, _change: ConfigChangeEvent) -> Result<()> {
    //     self.config = config;
    //     Ok(())
    // }
}

pub fn hash(input: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

pub fn set_tcp_opt(
    stream: &TcpStream,
    nodelay: bool,
    keepalive_secs: u64,
    keepalive_interval: u64,
) -> Result<()> {
    let s = stream;
    s.set_nodelay(nodelay)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(keepalive_secs))
        .with_interval(Duration::from_secs(keepalive_interval));
    Ok(socket2::SockRef::from(s).set_tcp_keepalive(&keepalive)?)
}
