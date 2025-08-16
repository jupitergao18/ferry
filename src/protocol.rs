use crate::{hash, set_tcp_opt};
use crate::noise::{NoiseStream, initiator_handshake, responder_handshake};
use anyhow::{Result, bail};
use bincode::enc::write::SizeWriter;
use bincode::{Decode, Encode};
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;
use tracing::error;

pub type Version = u8;
pub type SecureStream = NoiseStream<TcpStream>;
pub type ServiceDigest = [u8; 32];
pub type NonceDigest = [u8; 32];

pub const VERSION: Version = 1;

const HANDSHAKE_TIMEOUT: u64 = 5;

#[derive(Encode, Decode)]
pub enum ClientVersion {
    Version(Version),
}

impl ClientVersion {
    pub fn version() -> Self {
        Self::Version(VERSION)
    }
}

#[derive(Encode, Decode)]
pub enum ClientRequest {
    ProvideService(ServiceDigest),
    ConsumeService(ServiceDigest),
    ServiceInstance(NonceDigest),
}

impl ClientRequest {
    pub fn provide_service(service_name: &str) -> Self {
        Self::ProvideService(hash(service_name))
    }

    pub fn consume_service(service_name: &str) -> Self {
        Self::ConsumeService(hash(service_name))
    }

    pub fn service_instance(nonce: NonceDigest) -> Self {
        Self::ServiceInstance(nonce)
    }
}

#[derive(Encode, Decode)]
pub enum ServerResponse {
    Ok,
    UnknownService,
    NoProvider,
}

#[derive(Encode, Decode)]
pub enum ServerRequest {
    ConsumeService(NonceDigest),
}

impl ServerRequest {
    pub fn consume_service() -> Self {
        let mut nonce = vec![0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        Self::ConsumeService(nonce.try_into().unwrap())
    }
}

#[derive(Encode, Decode)]
pub enum ClientResponse {
    Ok,
    Unavailable,
}

pub static SIZE: LazyLock<Size> = LazyLock::new(|| {
    let client_version = sizeof(ClientVersion::version());
    let client_request = sizeof(ClientRequest::provide_service("default"));
    let server_response = sizeof(ServerResponse::Ok);
    let server_request = sizeof(ServerRequest::consume_service());
    let client_response = sizeof(ClientResponse::Ok);
    Size {
        client_version,
        client_request,
        server_response,
        server_request,
        client_response,
    }
});

#[derive(Debug)]
pub struct Size {
    pub client_version: usize,
    pub client_request: usize,
    pub server_response: usize,
    pub server_request: usize,
    pub client_response: usize,
}

pub async fn server_handshake(
    stream: TcpStream,
    psk: &str,
    nodelay: bool,
    keepalive_secs: u64,
    keepalive_interval: u64,
) -> Result<SecureStream> {
    match time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT),
        responder_handshake(stream, psk),
    )
    .await
    {
        Ok(stream) => match stream {
            Ok(mut stream) => {
                if let Err(e) = set_tcp_opt(stream.get_inner(), nodelay, keepalive_secs, keepalive_interval)
                {
                    bail!("set noise option error: {e}")
                }
                read_client_version(&mut stream).await?;
                write_and_flush(&mut stream, ServerResponse::Ok).await?;
                Ok(stream)
            }
            Err(e) => bail!("handshake error: {e}"),
        },
        Err(e) => bail!("handshake timeout: {e}"),
    }
}

pub async fn client_handshake(
    server_socket_addr: Option<SocketAddr>,
    server_address: &str,
    psk: &str,
    nodelay: bool,
    keepalive_secs: u64,
    keepalive_interval: u64,
) -> Result<SecureStream> {
    let stream = match server_socket_addr {
        Some(s) => TcpStream::connect(s).await?,
        None => TcpStream::connect(server_address).await?,
    };
    let mut stream = initiator_handshake(stream, psk).await?;
    if let Err(e) = set_tcp_opt(stream.get_inner(), nodelay, keepalive_secs, keepalive_interval) {
        bail!("set tcp option error: {e:?}");
    }
    write_and_flush(&mut stream, ClientVersion::version()).await?;
    if !matches!(read_server_response(&mut stream).await?, ServerResponse::Ok) {
        bail!("unexpected server response")
    }
    Ok(stream)
}

fn sizeof<E: bincode::Encode>(val: E) -> usize {
    let mut sw = SizeWriter::default();
    if let Err(e) = bincode::encode_into_writer(val, &mut sw, bincode::config::standard()) {
        error!("bincode encode error: {e:?}");
    }
    sw.bytes_written
}

fn encode<E: bincode::Encode>(val: E) -> Vec<u8> {
    bincode::encode_to_vec(val, bincode::config::standard()).expect("bincode encode error")
}

pub async fn write_and_flush<E: bincode::Encode>(
    stream: &mut SecureStream,
    content: E,
) -> Result<()> {
    stream.write_all(&encode(content)).await?;
    stream.flush().await?;
    Ok(())
}

fn decode<D: bincode::Decode<()>>(src: &[u8]) -> Result<D> {
    Ok(bincode::decode_from_slice(src, bincode::config::standard())?.0)
}

pub async fn read_client_version(stream: &mut SecureStream) -> Result<()> {
    let mut buf = vec![0u8; SIZE.client_version];
    stream.read_exact(&mut buf).await?;
    match decode::<ClientVersion>(&buf)? {
        ClientVersion::Version(v) => {
            if v == VERSION {
                Ok(())
            } else {
                bail!("mismatch version")
            }
        }
    }
}

pub async fn read_client_request(stream: &mut SecureStream) -> Result<ClientRequest> {
    let mut buf = vec![0u8; SIZE.client_request];
    stream.read_exact(&mut buf).await?;
    decode::<ClientRequest>(&buf)
}

pub async fn read_server_response(stream: &mut SecureStream) -> Result<ServerResponse> {
    let mut buf = vec![0u8; SIZE.server_response];
    stream.read_exact(&mut buf).await?;
    decode::<ServerResponse>(&buf)
}

pub async fn read_server_request(stream: &mut SecureStream) -> Result<ServerRequest> {
    let mut buf = vec![0u8; SIZE.server_request];
    stream.read_exact(&mut buf).await?;
    decode::<ServerRequest>(&buf)
}

pub async fn read_client_response(stream: &mut SecureStream) -> Result<ClientResponse> {
    let mut buf = vec![0u8; SIZE.client_response];
    stream.read_exact(&mut buf).await?;
    decode::<ClientResponse>(&buf)
}
