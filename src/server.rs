use crate::config::ServerConfig;
use crate::hash;
use crate::protocol::{
    ClientRequest, ClientResponse, NonceDigest, SecureStream, ServerRequest, ServerResponse,
    ServiceDigest, read_client_request, read_client_response, server_handshake, write_and_flush,
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
    wait_stream: RwLock<HashMap<NonceDigest, SecureStream>>,
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
        let bind_address = &self.config.bind_address;
        let listener = TcpListener::bind(bind_address).await?;
        info!("listening on {bind_address}");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Err(e) => {
                            warn!("accept error: {e}, sleep 100ms");
                            time::sleep(Duration::from_millis(100)).await;
                        }
                        Ok((conn, addr)) => {
                            info!("Incoming connection from {addr}");
                            match server_handshake(conn, &self.config.psk, self.config.nodelay, self.config.keepalive_secs, self.config.keepalive_interval).await {
                                Ok(stream) => {
                                    let server_state = self.state.clone();
                                    tokio::spawn(async move {
                                        if let Err(err) = handle_connection(stream, server_state).await {
                                            error!("handle connection error: {err:#}");
                                        }
                                    });
                                }
                                Err(e) => {
                                    warn!("handshake error: {e}");
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

        Ok(())
    }
}

async fn handle_connection(mut stream: SecureStream, server_state: ServerState) -> Result<()> {
    match read_client_request(&mut stream).await? {
        ClientRequest::ProvideService(service_digest) => {
            debug!(
                "Server: Receive client provide service: {:?}",
                service_digest
            );
            if !server_state
                .digest_service
                .read()
                .await
                .contains_key(&service_digest)
            {
                if let Err(e) = write_and_flush(&mut stream, ServerResponse::UnknownService).await {
                    error!("response to client error: {e:?}");
                }
            } else {
                if let Err(e) = write_and_flush(&mut stream, ServerResponse::Ok).await {
                    error!("response to client error: {e:?}");
                }
                server_state
                    .digest_stream
                    .write()
                    .await
                    .insert(service_digest, stream);
            }
        }
        ClientRequest::ConsumeService(service_digest) => {
            debug!(
                "Server: Receive client consume service: {:?}",
                service_digest
            );
            if !server_state
                .digest_service
                .read()
                .await
                .contains_key(&service_digest)
            {
                if let Err(e) = write_and_flush(&mut stream, ServerResponse::UnknownService).await {
                    error!("response to client error: {e:?}");
                }
            } else if let Some(provider_stream) = server_state
                .digest_stream
                .write()
                .await
                .get_mut(&service_digest)
            {
                let consume_service_request = ServerRequest::consume_service();
                let ServerRequest::ConsumeService(nonce) = consume_service_request;
                server_state.wait_stream.write().await.insert(nonce, stream);
                debug!(
                    "Server: Request client provide service instance: {:?}",
                    nonce
                );
                if let Err(e) = write_and_flush(provider_stream, consume_service_request).await {
                    error!("send to client error: {e:?}");
                }
                if matches!(
                    read_client_response(provider_stream).await?,
                    ClientResponse::Unavailable
                ) {
                    debug!("Server: Provider service unavailable, response to Consumer");
                    if let Some(mut stream) = server_state.wait_stream.write().await.remove(&nonce)
                    {
                        if let Err(e) =
                            write_and_flush(&mut stream, ServerResponse::NoProvider).await
                        {
                            error!("response to client error: {e:?}");
                        }
                    }
                };
            } else if let Err(e) = write_and_flush(&mut stream, ServerResponse::NoProvider).await {
                error!("response to client error: {e:?}");
            }
        }
        ClientRequest::ServiceInstance(nonce) => {
            debug!("Server: Receive new service instance");
            if let Err(e) = write_and_flush(&mut stream, ServerResponse::Ok).await {
                error!("response to provider client data stream error: {e:?}");
            }
            if let Some(mut wait) = server_state.wait_stream.write().await.remove(&nonce) {
                if let Err(e) = write_and_flush(&mut wait, ServerResponse::Ok).await {
                    error!("response to visitor client error: {e:?}");
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
