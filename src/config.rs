use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use notify::Watcher;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

const DEFAULT_RETRY_INTERVAL_SECS: u64 = 1;
const DEFAULT_NODELAY: bool = true;
const DEFAULT_KEEPALIVE_SECS: u64 = 20;
const DEFAULT_KEEPALIVE_INTERVAL: u64 = 8;
const DEFAULT_TIMEOUT: u64 = 10;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub server: Option<ServerConfig>,
    #[serde(default = "default_clients")]
    pub clients: Vec<ClientConfig>,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_clients() -> Vec<ClientConfig> {
    Vec::new()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub psk: String,
    pub service: HashMap<String, ServiceConfig>,
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
    pub proxy: Option<String>,
    pub service: HashMap<String, ServiceConfig>,
    #[serde(default = "default_client_retry_interval")]
    pub retry_interval: u64,
    #[serde(default = "default_nodelay")]
    pub nodelay: bool,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
pub enum ServiceType {
    #[serde(rename = "tcp")]
    #[default]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
}

fn default_service_type() -> ServiceType {
    Default::default()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceConfig {
    pub bind_address: Option<String>, // consumer only
    pub address: Option<String>,      // provider only
    pub nodelay: Option<bool>,
    pub retry_interval: Option<u64>,
    #[serde(default = "default_service_type")]
    pub service_type: ServiceType,
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

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        assert_eq!(default_client_retry_interval(), 1);
        assert_eq!(default_nodelay(), true);
        assert_eq!(default_keepalive_secs(), 20);
        assert_eq!(default_keepalive_interval(), 8);
        assert_eq!(default_timeout(), 10);
        assert!(default_clients().is_empty());
    }

    #[test]
    fn test_config_deserialize_full() {
        let json = r#"{
            "timeout": 30,
            "server": {
                "bind_address": "0.0.0.0:17000",
                "psk": "testkey",
                "service": {
                    "svc1": {}
                },
                "nodelay": false,
                "keepalive_secs": 60,
                "keepalive_interval": 10
            },
            "clients": [
                {
                    "server_address": "127.0.0.1:17000",
                    "psk": "clientkey",
                    "service": {
                        "svc1": {
                            "bind_address": "127.0.0.1:18080",
                            "address": "127.0.0.1:8080"
                        }
                    },
                    "retry_interval": 5,
                    "nodelay": false,
                    "keepalive_secs": 60,
                    "keepalive_interval": 10
                }
            ]
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.timeout, 30);
        assert!(config.server.is_some());
        let server = config.server.unwrap();
        assert_eq!(server.bind_address, "0.0.0.0:17000");
        assert_eq!(server.psk, "testkey");
        assert!(!server.nodelay);
        assert_eq!(server.keepalive_secs, 60);
        assert_eq!(server.keepalive_interval, 10);
        assert_eq!(config.clients.len(), 1);
        let client = &config.clients[0];
        assert_eq!(client.server_address, "127.0.0.1:17000");
        assert_eq!(client.retry_interval, 5);
        assert!(!client.nodelay);
        assert_eq!(client.keepalive_secs, 60);
    }

    #[test]
    fn test_config_deserialize_defaults() {
        let json = r#"{
            "server": {
                "bind_address": "0.0.0.0:17000",
                "psk": "key",
                "service": {}
            }
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.timeout, 10);
        let server = config.server.unwrap();
        assert!(server.nodelay);
        assert_eq!(server.keepalive_secs, 20);
        assert_eq!(server.keepalive_interval, 8);
        assert!(config.clients.is_empty());
    }

    #[test]
    fn test_client_config_defaults() {
        let json = r#"{
            "server_address": "127.0.0.1:17000",
            "psk": "key",
            "service": {}
        }"#;

        let client: ClientConfig = serde_json::from_str(json).unwrap();
        assert_eq!(client.retry_interval, 1);
        assert!(client.nodelay);
        assert_eq!(client.keepalive_secs, 20);
        assert_eq!(client.keepalive_interval, 8);
        assert!(client.proxy.is_none());
    }

    #[test]
    fn test_service_config_service_type() {
        let json_tcp = r#"{ "bind_address": ":8080", "service_type": "tcp" }"#;
        let svc: ServiceConfig = serde_json::from_str(json_tcp).unwrap();
        assert!(matches!(svc.service_type, ServiceType::Tcp));

        let json_udp = r#"{ "bind_address": ":8080", "service_type": "udp" }"#;
        let svc: ServiceConfig = serde_json::from_str(json_udp).unwrap();
        assert!(matches!(svc.service_type, ServiceType::Udp));
    }

    #[test]
    fn test_service_config_default_type() {
        let json = r#"{ "bind_address": ":8080" }"#;
        let svc: ServiceConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(svc.service_type, ServiceType::Tcp));
    }

    #[test]
    fn test_config_serialize_roundtrip() {
        let config = Config {
            timeout: 42,
            server: Some(ServerConfig {
                bind_address: "0.0.0.0:17000".to_string(),
                psk: "secret".to_string(),
                service: HashMap::new(),
                nodelay: true,
                keepalive_secs: 20,
                keepalive_interval: 8,
            }),
            clients: vec![ClientConfig {
                server_address: "127.0.0.1:17000".to_string(),
                psk: "client".to_string(),
                proxy: None,
                service: HashMap::new(),
                retry_interval: 1,
                nodelay: true,
                keepalive_secs: 20,
                keepalive_interval: 8,
            }],
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.timeout, config.timeout);
        assert_eq!(parsed.clients.len(), config.clients.len());
    }

    #[test]
    fn test_config_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("ferry_test_config.json");
        let json = r#"{"timeout": 7, "server": {"bind_address": ":9000", "psk": "k", "service": {}}}"#;
        std::fs::write(&path, json).unwrap();
        let config = Config::from_file(path).unwrap();
        assert_eq!(config.timeout, 7);
    }

    #[test]
    fn test_config_change_event_from_configs() {
        let old = Config {
            timeout: 10,
            server: None,
            clients: vec![],
        };
        let new = Config {
            timeout: 20,
            server: None,
            clients: vec![],
        };
        let event = ConfigChangeEvent::from_configs(&old, &new);
        match event {
            ConfigChangeEvent::FullRestart(cfg) => assert_eq!(cfg.timeout, 20),
        }
    }
}
