use crate::config::ServerConfig;
use crate::protocol::{
    ClientRequest, ClientResponse, NonceDigest, SecureStream, ServerRequest, ServerResponse,
    ServiceDigest, hash, read_client_request, read_client_response, server_handshake, set_tcp_opt,
    write_and_flush,
};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, broadcast};
use tokio::time;
use tracing::{debug, error, info, warn};

type ServerState = Arc<InnerServerState>;
struct InnerServerState {
    digest_stream: RwLock<HashMap<ServiceDigest, SecureStream>>,
    digest_service: RwLock<HashMap<ServiceDigest, String>>,
    wait_stream: RwLock<HashMap<NonceDigest, (SecureStream, String)>>,
}

pub struct Server {
    config: ServerConfig,
    state: ServerState,
}

impl Server {
    pub fn from_config(config: ServerConfig) -> Result<Self> {
        let digest_service = RwLock::new(
            config
                .service
                .keys()
                .map(|service_name| (hash(service_name), service_name.clone()))
                .collect::<HashMap<[u8; 32], String>>(),
        );
        let state = Arc::new(InnerServerState {
            digest_stream: RwLock::new(HashMap::new()),
            digest_service,
            wait_stream: RwLock::new(HashMap::new()),
        });
        Ok(Self { config, state })
    }

    pub async fn run(&mut self, mut stop_rx: broadcast::Receiver<()>) -> Result<()> {
        info!("Server starting...");
        let bind_address = &self.config.bind_address;
        let listener = TcpListener::bind(bind_address).await?;
        info!("Server started, listening on {bind_address}");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Err(e) => {
                            warn!("Server: accept error: {e}, sleep 100ms");
                            time::sleep(Duration::from_millis(100)).await;
                        }
                        Ok((conn, addr)) => {
                            debug!("Server: incoming connection from {addr}");
                            match server_handshake(conn, &self.config.psk, self.config.nodelay, self.config.keepalive_secs, self.config.keepalive_interval).await {
                                Ok(stream) => {
                                    let server_state = self.state.clone();
                                    let server_config = self.config.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_connection(stream, server_state, server_config).await {
                                            warn!("Server: handle connection error: {e}");
                                        }
                                    });
                                }
                                Err(e) => {
                                    warn!("Server: handshake error: {e}");
                                }
                            }
                        }
                    }
                }
                _ = stop_rx.recv() => {
                    info!("Server shutting down...");
                    break;
                }
            }
        }

        info!("Server shutdown");

        Ok(())
    }
}

async fn handle_connection(
    mut stream: SecureStream,
    server_state: ServerState,
    server_config: ServerConfig,
) -> Result<()> {
    match read_client_request(&mut stream).await? {
        ClientRequest::ProvideService(service_digest) => {
            debug!(
                "Server: client provide service: {:?}",
                hex::encode(service_digest)
            );
            let digest_service = server_state.digest_service.read().await;
            let service_name = digest_service.get(&service_digest);
            if service_name.is_none() {
                if let Err(e) = write_and_flush(&mut stream, ServerResponse::UnknownService).await {
                    warn!("Server: response UnknownService to client error: {e:?}");
                }
                return Ok(());
            }
            let service_name = service_name.unwrap().to_string();
            debug!("Server: found service: {service_name}");
            if let Err(e) = write_and_flush(&mut stream, ServerResponse::Ok).await {
                warn!("Server: response Ok to client error: {e:?}");
            }
            server_state
                .digest_stream
                .write()
                .await
                .insert(service_digest, stream);
            debug!("Server: provider stream saved: {service_name}");
        }
        ClientRequest::ConsumeService(service_digest) => {
            debug!(
                "Server: client consume service: {:?}",
                hex::encode(service_digest)
            );
            let digest_service = server_state.digest_service.read().await;
            let service_name = digest_service.get(&service_digest);
            if service_name.is_none() {
                if let Err(e) = write_and_flush(&mut stream, ServerResponse::UnknownService).await {
                    error!("response to client error: {e:?}");
                }
                return Ok(());
            }
            let service_name = service_name.unwrap().to_string();
            debug!("Server: found service: {service_name}");
            let mut digest_stream = server_state.digest_stream.write().await;
            if let Some(provider_stream) = digest_stream.get_mut(&service_digest) {
                debug!("Server: found provider");
                let consume_service_request = ServerRequest::consume_service();
                let ServerRequest::ConsumeService(nonce) = consume_service_request;
                server_state
                    .wait_stream
                    .write()
                    .await
                    .insert(nonce, (stream, service_name.clone()));
                debug!("Server: request provider instance: {service_name}");
                if let Err(e) = write_and_flush(provider_stream, consume_service_request).await {
                    warn!("Server: send to provider error: {e:?}");
                }
                match read_client_response(provider_stream).await {
                    Ok(provider_response) => {
                        if matches!(provider_response, ClientResponse::Unavailable) {
                            warn!("Server: provider service unavailable, response to consumer");
                            if let Some((mut stream, _)) =
                                server_state.wait_stream.write().await.remove(&nonce)
                                && let Err(e) =
                                    write_and_flush(&mut stream, ServerResponse::NoProvider).await
                            {
                                warn!("Server: response NoProvider to consumer error: {e:?}");
                            }
                        };
                    }
                    Err(e) => {
                        warn!(
                            "Server: provider stream read error {e}, response NoProvider to consumer and remove provider stream"
                        );
                        digest_stream.remove(&service_digest);
                        if let Some((mut stream, _)) =
                            server_state.wait_stream.write().await.remove(&nonce)
                            && let Err(e) =
                                write_and_flush(&mut stream, ServerResponse::NoProvider).await
                        {
                            warn!("Server: response NoProvider to client error: {e:?}");
                        }
                    }
                }
            } else if let Err(e) = write_and_flush(&mut stream, ServerResponse::NoProvider).await {
                warn!("Server: response NoProvider to client error: {e:?}");
            }
        }
        ClientRequest::ServiceInstance(nonce) => {
            debug!("Server: client provide instance: {}", hex::encode(nonce));
            if let Err(e) = write_and_flush(&mut stream, ServerResponse::Ok).await {
                warn!("Server: response Ok to provider data stream error: {e:?}");
            }
            if let Some((mut wait, service_name)) =
                server_state.wait_stream.write().await.remove(&nonce)
            {
                if let Err(e) = write_and_flush(&mut wait, ServerResponse::Ok).await {
                    warn!("Server: response Ok to visitor error: {e:?}");
                }
                if let Some(service_config) = server_config.service.get(&service_name) {
                    if let Err(e) = set_tcp_opt(
                        wait.get_inner(),
                        service_config.nodelay.unwrap_or(server_config.nodelay),
                        server_config.keepalive_secs,
                        server_config.keepalive_interval,
                    ) {
                        warn!("Server: set tcp option for visitor error: {e:?}");
                    }
                    if let Err(e) = set_tcp_opt(
                        stream.get_inner(),
                        service_config.nodelay.unwrap_or(server_config.nodelay),
                        server_config.keepalive_secs,
                        server_config.keepalive_interval,
                    ) {
                        warn!("Server: set tcp option for provider error: {e:?}");
                    }
                }

                debug!("Server: copy_bidirectional");
                tokio::spawn(async move { copy_bidirectional(&mut wait, &mut stream).await });
            } else {
                debug!("Server: not waiting for {:?}", nonce);
            }
        }
    }
    Ok(())
}
