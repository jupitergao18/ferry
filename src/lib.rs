use crate::client::Client;
use crate::config::{Config, ConfigChangeEvent};
use crate::server::Server;
use anyhow::Result;
use futures_util::future::join_all;
use std::path::PathBuf;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

mod client;
mod config;
mod server;
// protocol service;
mod protocol;
mod proxy;

pub async fn run(config_path: PathBuf, ctrlc_tx: broadcast::Sender<bool>) -> Result<()> {
    if let Err(e) = fdlimit::raise_fd_limit() {
        warn!("Raise fd limit error: {e:?}");
    }

    let ctrlc_rx = ctrlc_tx.subscribe();
    let (config_change_tx, mut config_change_rx) = mpsc::unbounded_channel::<ConfigChangeEvent>();
    tokio::spawn(async move { config::watch(config_path, config_change_tx, ctrlc_rx).await });

    let mut instance_stop_tx: Option<broadcast::Sender<()>> = None;
    let mut instance_task: Option<JoinHandle<Result<()>>> = None;

    while let Some(change_event) = config_change_rx.recv().await {
        match change_event {
            ConfigChangeEvent::FullRestart(config) => {
                if instance_stop_tx.is_some() {
                    info!("Config file changed, restarting...");
                } else {
                    info!("Config file loaded, starting...");
                }
                if let Some(previous_stop_tx) = &instance_stop_tx {
                    debug!("Sending stop signal");
                    if let Err(e) = previous_stop_tx.send(()) {
                        error!("Previous instance stop signal send error: {e:?}");
                        break;
                    }
                    if let Some(task) = instance_task {
                        _ = task.await;
                    }
                }

                let (stop_tx, _) = broadcast::channel::<()>(1024);
                let new_instance = Instance::new(config, stop_tx.clone());
                let new_task = tokio::spawn(async move { new_instance.run().await });

                instance_stop_tx = Some(stop_tx);
                instance_task = Some(new_task);
            }
        }
    }

    if let Some(stop_tx) = &instance_stop_tx
        && let Err(e) = stop_tx.send(())
    {
        error!("Instance shutdown error: {e:?}");
    }

    if let Some(task) = instance_task {
        _ = task.await;
    }

    Ok(())
}

struct Instance {
    config: Config,
    stop_tx: broadcast::Sender<()>,
}

impl Instance {
    fn new(config: Config, stop_tx: broadcast::Sender<()>) -> Self {
        Self { config, stop_tx }
    }

    async fn run(&self) -> Result<()> {
        info!("Instance starting...");
        let mut tasks = vec![];
        let server_stop_rx = self.stop_tx.subscribe();
        if let Some(server_config) = self.config.server.clone() {
            let mut server = Server::from_config(server_config)?;
            let task = tokio::spawn(async move { server.run(server_stop_rx).await });
            tasks.push(task);
        }

        for client_config in self.config.clients.clone() {
            let client_stop_rx = self.stop_tx.subscribe();
            let mut client = Client::from_config(client_config).await?;
            let task = tokio::spawn(async move { client.run(client_stop_rx).await });
            tasks.push(task);
        }
        info!("Instance started");

        if let Err(e) = self.stop_tx.subscribe().recv().await {
            error!("instance stop signal receive error: {e:?}");
        }
        info!("Instance shutting down...");

        join_all(tasks).await;

        info!("Instance shutdown");

        Ok(())
    }

    // fn config_change(&mut self, config: Config, _change: ConfigChangeEvent) -> Result<()> {
    //     self.config = config;
    //     Ok(())
    // }
}
