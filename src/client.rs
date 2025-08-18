use crate::config::{ClientConfig, ServiceConfig};
use crate::protocol::{
    ClientRequest, ClientResponse, SecureStream, ServerRequest, ServerResponse, client_handshake,
    read_server_request, read_server_response, write_and_flush,
};
use crate::set_tcp_opt;
use anyhow::{Result, bail};
use backon::{BackoffBuilder, ExponentialBuilder};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::time;
use tracing::{debug, error, info, warn};

type ClientState = Arc<InnerClientState>;
struct InnerClientState {
    service_stop_tx: RwLock<HashMap<String, mpsc::Sender<()>>>,
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
                let retry_backoff_builder = ExponentialBuilder::new()
                    .with_jitter()
                    .with_max_delay(Duration::from_secs(
                        service_config
                            .retry_interval
                            .unwrap_or(self.config.retry_interval),
                    ))
                    .without_max_times();
                let service_name = service_name.clone();
                let service_config = service_config.clone();
                let config = self.config.clone();
                let state = self.state.clone();
                let server_socket_addr = self.server_socket_addr;

                tokio::spawn(async move {
                    let mut start = time::Instant::now();
                    let mut retry_backoff = retry_backoff_builder.build();
                    loop {
                        let (service_stop_tx, service_stop_rx) = mpsc::channel::<()>(1);
                        match Service::from_config(
                            service_name.clone(),
                            service_config.clone(),
                            config.clone(),
                            server_socket_addr,
                            service_stop_rx,
                        ) {
                            Ok(mut service) => {
                                state
                                    .service_stop_tx
                                    .write()
                                    .await
                                    .insert(service_name.clone(), service_stop_tx);
                                if let Err(e) = service.run().await {
                                    if service.stop_rx.try_recv()
                                        != Err(mpsc::error::TryRecvError::Empty)
                                    {
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
                            }
                            Err(e) => {
                                error!("Service create error: {e}");
                                break;
                            }
                        }
                    }
                });
            }
        }

        _ = stop_rx.recv().await;

        let service_stop_tx = self.state.service_stop_tx.read().await;
        for (service_name, stop_tx) in service_stop_tx.iter() {
            info!("Service {service_name} shutting down");
            if let Err(e) = stop_tx.send(()).await {
                error!("send service stop signal error: {e}");
            }
        }

        info!("Client shutting down...");

        Ok(())
    }
}

pub struct Service {
    service_name: String,
    service_config: ServiceConfig,
    client_config: ClientConfig,
    server_socket_addr: Option<SocketAddr>,
    stop_rx: mpsc::Receiver<()>,
}

impl Service {
    pub fn from_config(
        service_name: String,
        service_config: ServiceConfig,
        client_config: ClientConfig,
        server_socket_addr: Option<SocketAddr>,
        stop_rx: mpsc::Receiver<()>,
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
        let (service_stop_tx, _) = broadcast::channel::<()>(1);
        let (provider_error_tx, mut provider_error_rx) = mpsc::unbounded_channel::<String>();
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
                    let service_stop_rx = service_stop_tx.subscribe();
                    let service_name = self.service_name.clone();
                    tokio::spawn(async move {
                        debug!("Provider: Waiting server request");
                        if let Err(e) = handle_server_request(
                            stream,
                            service_config,
                            client_config,
                            server_socket_addr,
                            service_stop_rx,
                            service_name,
                        )
                        .await
                        {
                            error!("Provider: handle server request error: {e}");
                            if let Err(e) = provider_error_tx.send(e.to_string()) {
                                error!("send provider error signal error: {e}");
                            }
                        }
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
            let service_config = self.service_config.clone();
            let client_config = self.client_config.clone();
            let service_name = self.service_name.clone();
            let server_socket_addr = self.server_socket_addr;
            let mut service_stop_rx = service_stop_tx.subscribe();
            tokio::spawn(async move {
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
                            let service_config = service_config.clone();
                            let client_config = client_config.clone();
                            let service_name = service_name.clone();
                            tokio::spawn(async move {
                                if let Err(err) = handle_visitor_connection(conn,service_name,service_config,client_config,server_socket_addr).await {
                                    error!("Consumer: handle visitor connection error: {err:#}");
                                }
                            });
                        }
                    }
                    }
                    _ = service_stop_rx.recv() => {
                        info!("Service consumer {} shutting down...", service_name);
                        break;
                    }
                    }
                }
            });
        }

        tokio::select! {
            _ = self.stop_rx.recv() => {
                if let Err(e) = service_stop_tx.send(()) {
                    error!("send service stop signal error: {e}");
                }
                Ok(())
            },
            e = provider_error_rx.recv() => {
                if let Err(e) = service_stop_tx.send(()) {
                    error!("send service stop signal error: {e}");
                }
                bail!("{e:?}")
            }
        }
    }
}

/// 处理 Client Service Provider 服务端控制流
/// 从服务端读取控制请求报错时， 返回 Err， 重启服务
/// up stream 连接失败时，正常执行响应
/// 设置流选项时报错 warn， 继续处理
/// 安全连接握手时报错 error， 返回 Err，重启服务
/// 向服务端提供新实例时报错， 返回 Err，重启服务
/// 从服务端读取提供新实例返回时报错， 返回 Err，重启服务
/// 向服务端返回提供新实例请求时报错， 返回 Err，重启服务
/// 异步双向复制，不处理结果
async fn handle_server_request(
    mut stream: SecureStream,
    service_config: ServiceConfig,
    client_config: ClientConfig,
    server_socket_addr: Option<SocketAddr>,
    mut service_stop_rx: broadcast::Receiver<()>,
    service_name: String,
) -> Result<()> {
    let up_address = service_config.address.clone().unwrap();
    let up_socket_addr = match lookup_host(&up_address).await {
        Ok(mut addrs) => addrs.next(),
        Err(_) => None,
    };
    loop {
        tokio::select! {
            request = read_server_request(&mut stream) => {
                match request? {
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
                            warn!("set tcp option error: {e:?}");
                        }
                        match client_handshake(
                            server_socket_addr,
                            &client_config.server_address,
                            &client_config.psk,
                            service_config.nodelay.unwrap_or(client_config.nodelay),
                            client_config.keepalive_secs,
                            client_config.keepalive_interval,
                        )
                        .await {
                            Ok(mut data_stream) => {
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
                            Err(e) => {
                                bail!("Provider: handle server request handshake error: {e}");
                            }
                        }
                    }
                }
            },
            _ = service_stop_rx.recv() => {
                info!("Service provider {service_name} shutting down...");
                break;
            }
        }
    }
    Ok(())
}

/// 处理 Client Service Consumer Listener 访问流
/// 设置流选项时报错 warn， 继续处理
/// 安全连接握手时报错 error， 返回OK，不重试
/// 向服务端发送消费请求时报错 error，返回Err，不重试
/// 从服务端读取消费请求返回时报错 error，返回Err，不重试
/// 双向复制过程中报错返回Ok，不重试
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
        warn!("set tcp option error: {e:?}");
    }
    match client_handshake(
        server_socket_addr,
        &client_config.server_address,
        &client_config.psk,
        service_config.nodelay.unwrap_or(client_config.nodelay),
        client_config.keepalive_secs,
        client_config.keepalive_interval,
    )
    .await
    {
        Ok(mut data_stream) => {
            debug!("Consumer: Consuming service: {service_name}");
            write_and_flush(
                &mut data_stream,
                ClientRequest::consume_service(&service_name),
            )
            .await?;

            match read_server_response(&mut data_stream).await? {
                ServerResponse::Ok => {
                    debug!("Consumer: copy_bidirectional");
                    _ = copy_bidirectional(&mut data_stream, &mut visitor_stream).await;
                }
                ServerResponse::UnknownService => {
                    error!("server response: unknown service");
                }
                ServerResponse::NoProvider => {
                    error!("server response: no provider");
                }
            }
        }
        Err(e) => {
            error!("Consumer: handle visitor connection handshake error: {e}");
        }
    }
    Ok(())
}
