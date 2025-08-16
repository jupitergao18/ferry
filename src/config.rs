use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use notify::Watcher;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;
const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 70;
const DEFAULT_RETRY_INTERVAL_SECS: u64 = 1;
const DEFAULT_NODELAY: bool = true;
const DEFAULT_KEEPALIVE_SECS: u64 = 20;
const DEFAULT_KEEPALIVE_INTERVAL: u64 = 8;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub server: Option<ServerConfig>,
    #[serde(default = "default_clients")]
    pub clients: Vec<ClientConfig>,
}

fn default_clients() -> Vec<ClientConfig> {
    Vec::new()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub psk: String,
    pub service: HashMap<String, ServiceConfig>,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,
    #[serde(default = "default_nodelay")]
    pub nodelay: bool,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientConfig {
    pub server_address: String,
    pub psk: String,
    pub service: HashMap<String, ServiceConfig>,
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: u64,
    #[serde(default = "default_client_retry_interval")]
    pub retry_interval: u64,
    #[serde(default = "default_nodelay")]
    pub nodelay: bool,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceConfig {
    pub bind_address: Option<String>, // consumer
    pub address: Option<String>,      // provider
    pub nodelay: Option<bool>,        // provider and consumer
    pub retry_interval: Option<u64>,  // provider
}

fn default_heartbeat_interval() -> u64 {
    DEFAULT_HEARTBEAT_INTERVAL_SECS
}

fn default_heartbeat_timeout() -> u64 {
    DEFAULT_HEARTBEAT_TIMEOUT_SECS
}

fn default_client_retry_interval() -> u64 {
    DEFAULT_RETRY_INTERVAL_SECS
}

fn default_nodelay() -> bool {
    DEFAULT_NODELAY
}

fn default_keepalive_secs() -> u64 {
    DEFAULT_KEEPALIVE_SECS
}

fn default_keepalive_interval() -> u64 {
    DEFAULT_KEEPALIVE_INTERVAL
}

impl Config {
    fn from_file(config_path: PathBuf) -> Result<Self> {
        let config_content = std::fs::read_to_string(config_path)?;
        Ok(serde_json::from_str::<Self>(&config_content)?)
    }
}

pub enum ConfigChangeEvent {
    FullRestart(Config),
}

pub async fn watch(
    config_path: PathBuf,
    config_change_tx: mpsc::UnboundedSender<ConfigChangeEvent>,
    mut ctrlc_rx: broadcast::Receiver<bool>,
) {
    info!("Loading configuration");
    let mut old = Config::from_file(config_path.clone()).expect("Invalid configuration");
    info!("Configuration loaded");
    if let Err(e) = config_change_tx.send(ConfigChangeEvent::FullRestart(old.clone())) {
        panic!("Configuration send error: {e:?}");
    }

    let parent_path = config_path.parent().expect("no parent dir for config file");
    let config_path_clone = config_path.clone();
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<bool>();

    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(e) => {
                if matches!(e.kind, notify::EventKind::Modify(_))
                    && e.paths
                        .iter()
                        .map(|x| x.file_name())
                        .any(|x| x == config_path_clone.file_name())
                    && let Err(e) = notify_tx.send(true)
                {
                    warn!("config change event send error: {e:?}");
                }
            }
            Err(e) => error!("watch error: {:#}", e),
        })
        .expect("watcher create error");

    watcher
        .watch(parent_path, notify::RecursiveMode::NonRecursive)
        .expect("watcher start error");

    info!("Config watcher started");

    loop {
        tokio::select! {
          e = notify_rx.recv() => {
            match e {
              Some(_) => {
                    info!("Reloading configuration");
                    let new = match Config::from_file(config_path.clone()) {
                      Ok(v) => v,
                      Err(e) => {
                        error!("Invalid configuration ignored, {e:#}");
                        continue;
                      }
                    };

                    if let Err(e) = config_change_tx.send(ConfigChangeEvent::from_configs(&old, &new)) {
                        panic!("Configuration send error: {e:?}");
                    }

                    old = new;
              },
              None => break
            }
          },
          _ = ctrlc_rx.recv() => break
        }
    }

    info!("Config watcher shutdown");
}

impl ConfigChangeEvent {
    fn from_configs(_old: &Config, new: &Config) -> Self {
        Self::FullRestart(new.clone())
    }
}
