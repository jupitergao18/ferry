use crate::config::{ClientConfig, ServiceConfig};
use crate::protocol::{
    client_handshake, read_server_request, read_server_response, write_and_flush, ClientRequest, ClientResponse,
    SecureStream, ServerRequest, ServerResponse,
};
use crate::set_tcp_opt;
use anyhow::{bail, Result};
use backon::{BackoffBuilder, ExponentialBuilder};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot, RwLock};
use tokio::time;
use tracing::{debug, error, info, warn};

type ClientState = Arc<InnerClientState>;
struct InnerClientState {
    service_stop_tx: RwLock<HashMap<String, oneshot::Sender<()>>>,
}

pub struct Client {
    server_socket_addr: Option<SocketAddr>,
    config: ClientConfig,
    state: ClientState,
}

impl Client {
    pub async fn from_config(config: ClientConfig) -> Result<Self> {
        let state = Arc::new(InnerClientState {
            service_stop_tx: RwLock::new(HashMap::new()),
        });
        let server_socket_addr = lookup_host(&config.server_address).await?.next();
        Ok(Self {
            server_socket_addr,
            config,
            state,
        })
    }

    pub async fn run(&mut self, mut stop_rx: broadcast::Receiver<()>) -> Result<()> {
        for (service_name, service_config) in &self.config.service {
            if service_config.address.is_some() || service_config.bind_address.is_some() {
                let (service_stop_tx, service_stop_rx) = oneshot::channel::<()>();
                let mut service = Service::from_config(
                    service_name.clone(),
                    service_config.clone(),
                    self.config.clone(),
                    self.server_socket_addr,
                    service_stop_rx,
                )?;

                let retry_backoff_builder = ExponentialBuilder::new()
                    .with_jitter()
                    .with_max_delay(Duration::from_secs(
                        service_config
                            .retry_interval
                            .unwrap_or(self.config.retry_interval),
                    ))
                    .without_max_times();

                tokio::spawn(async move {
                    let mut start = time::Instant::now();
                    let mut retry_backoff = retry_backoff_builder.build();
                    while let Err(e) = service.run().await {
                        if service.stop_rx.try_recv() != Err(oneshot::error::TryRecvError::Empty) {
                            break;
                        }

                        if start.elapsed() > Duration::from_secs(3) {
                            retry_backoff = retry_backoff_builder.build();
                        }

                        if let Some(duration) = retry_backoff.next() {
                            error!("Service error {e}. Retry in {duration:?}...");
                            time::sleep(duration).await;
                        } else {
                            // Should never reach
                            panic!("Retry Break, error: {:?}", e);
                        }

                        start = time::Instant::now();
                    }
                });
                self.state
                    .service_stop_tx
                    .write()
                    .await
                    .insert(service_name.clone(), service_stop_tx);
            }
        }

        _ = stop_rx.recv().await;

        info!("Client shutting down...");

        Ok(())
    }
}

pub struct Service {
    service_name: String,
    service_config: ServiceConfig,
    client_config: ClientConfig,
    server_socket_addr: Option<SocketAddr>,
    stop_rx: oneshot::Receiver<()>,
}

impl Service {
    pub fn from_config(
        service_name: String,
        service_config: ServiceConfig,
        client_config: ClientConfig,
        server_socket_addr: Option<SocketAddr>,
        stop_rx: oneshot::Receiver<()>,
    ) -> Result<Self> {
        Ok(Self {
            service_name,
            service_config,
            client_config,
            server_socket_addr,
            stop_rx,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        if self.service_config.bind_address.is_none() && self.service_config.address.is_none() {
            bail!("both of bind_address and address unset")
        }
        if self.service_config.address.is_some() {
            let mut stream = client_handshake(
                self.server_socket_addr,
                &self.client_config.server_address,
                &self.client_config.psk,
                self.service_config
                    .nodelay
                    .unwrap_or(self.client_config.nodelay),
                self.client_config.keepalive_secs,
                self.client_config.keepalive_interval,
            )
            .await?;
            debug!("Provider: Providing service {}", self.service_name);
            write_and_flush(
                &mut stream,
                ClientRequest::provide_service(&self.service_name),
            )
            .await?;
            match read_server_response(&mut stream).await? {
                ServerResponse::Ok => {
                    let service_config = self.service_config.clone();
                    let client_config = self.client_config.clone();
                    let server_socket_addr = self.server_socket_addr;
                    tokio::spawn(async move {
                        debug!("Provider: Waiting server request");
                        handle_server_request(
                            stream,
                            service_config,
                            client_config,
                            server_socket_addr,
                        )
                        .await
                    });
                }
                ServerResponse::UnknownService => {
                    bail!("server response unknown service: {}", self.service_name)
                }
                ServerResponse::NoProvider => {
                    bail!("unexpected server response")
                }
            }
        }
        if let Some(bind_address) = &self.service_config.bind_address {
            let listener = TcpListener::bind(bind_address).await?;
            info!(
                "listening on {bind_address} for service {}",
                self.service_name
            );
            loop {
                tokio::select! {
                accept_result = listener.accept() => {
                        match accept_result {
                    Err(e) => {
                        warn!("accept error: {e}, sleep 100ms");
                        time::sleep(Duration::from_millis(100)).await;
                    }
                    Ok((conn, addr)) => {
                        info!("Incoming visitor connection from {addr}");
                        let service_config = self.service_config.clone();
                        let client_config = self.client_config.clone();
                        let service_name = self.service_name.clone();
                        let server_socket_addr = self.server_socket_addr;
                        tokio::spawn(async move {
                            if let Err(err) = handle_visitor_connection(conn,service_name,service_config,client_config,server_socket_addr).await {
                                error!("handle visitor connection error: {err:#}");
                            }
                        });
                    }
                }
                }
                _ = &mut self.stop_rx => {
                    info!("Service {} shutting down...", self.service_name);
                    break;
                }
                }
            }
        }

        Ok(())
    }
}

async fn handle_server_request(
    mut stream: SecureStream,
    service_config: ServiceConfig,
    client_config: ClientConfig,
    server_socket_addr: Option<SocketAddr>,
) -> Result<()> {
    let up_address = service_config.address.clone().unwrap();
    let up_socket_addr = lookup_host(&up_address).await?.next();
    loop {
        match read_server_request(&mut stream).await? {
            ServerRequest::ConsumeService(nonce) => {
                debug!(
                    "Provider: Receive server consume Service: {}",
                    hex::encode(nonce)
                );
                debug!("Provider: Connecting upstream");
                let up_stream = match up_socket_addr {
                    Some(s) => TcpStream::connect(s).await,
                    None => TcpStream::connect(&up_address).await,
                };
                if up_stream.is_err() {
                    debug!("Provider: Upstream unavailable");
                    write_and_flush(&mut stream, ClientResponse::Unavailable).await?;
                    continue;
                }
                let mut up_stream = up_stream?;
                if let Err(e) = set_tcp_opt(
                    &up_stream,
                    service_config.nodelay.unwrap_or(client_config.nodelay),
                    client_config.keepalive_secs,
                    client_config.keepalive_interval,
                ) {
                    error!("set tcp option error: {e:?}");
                }
                let mut data_stream = client_handshake(
                    server_socket_addr,
                    &client_config.server_address,
                    &client_config.psk,
                    service_config.nodelay.unwrap_or(client_config.nodelay),
                    client_config.keepalive_secs,
                    client_config.keepalive_interval,
                )
                .await?;
                debug!("Provider: Provide new service instance");
                write_and_flush(&mut data_stream, ClientRequest::service_instance(nonce)).await?;
                if !matches!(
                    read_server_response(&mut data_stream).await?,
                    ServerResponse::Ok
                ) {
                    bail!("unexpected server response")
                }
                write_and_flush(&mut stream, ClientResponse::Ok).await?;
                debug!("Provider: copy_bidirectional");
                tokio::spawn(
                    async move { copy_bidirectional(&mut data_stream, &mut up_stream).await },
                );
            }
        }
    }
}

async fn handle_visitor_connection(
    mut visitor_stream: TcpStream,
    service_name: String,
    service_config: ServiceConfig,
    client_config: ClientConfig,
    server_socket_addr: Option<SocketAddr>,
) -> Result<()> {
    if let Err(e) = set_tcp_opt(
        &visitor_stream,
        service_config.nodelay.unwrap_or(client_config.nodelay),
        client_config.keepalive_secs,
        client_config.keepalive_interval,
    ) {
        error!("set tcp option error: {e:?}");
    }
    let mut data_stream = client_handshake(
        server_socket_addr,
        &client_config.server_address,
        &client_config.psk,
        service_config.nodelay.unwrap_or(client_config.nodelay),
        client_config.keepalive_secs,
        client_config.keepalive_interval,
    )
    .await?;
    debug!("Consumer: Consume service: {service_name}");
    write_and_flush(
        &mut data_stream,
        ClientRequest::consume_service(&service_name),
    )
    .await?;

    match read_server_response(&mut data_stream).await? {
        ServerResponse::Ok => {
            debug!("Consumer: copy_bidirectional");
            copy_bidirectional(&mut data_stream, &mut visitor_stream).await?;
            Ok(())
        }
        ServerResponse::UnknownService => {
            bail!("server response: unknown service")
        }
        ServerResponse::NoProvider => {
            bail!("server response: no provider")
        }
    }
}
