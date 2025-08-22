use crate::proxy::proxy_stream;
use anyhow::{Result, bail};
use bincode::enc::write::SizeWriter;
use bincode::{Decode, Encode};
use noise::NoiseStream;
use rand::RngCore;
use snow::Builder;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tokio::time;
use tracing::{error, trace};

mod noise;

const NOISE_PATTERN: &str = "Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s";

pub type Version = u8;
pub type SecureStream = NoiseStream<TcpStream>;
pub type ServiceDigest = [u8; 32];
pub type NonceDigest = [u8; 32];

pub const VERSION: Version = 1;

const HANDSHAKE_TIMEOUT: u64 = 5;

const UDP_MTU: usize = 2048;

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

pub async fn responder_handshake(stream: TcpStream, psk: &str) -> Result<SecureStream> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let keypair = builder.generate_keypair()?;
    let psk_hash = hash(psk);
    NoiseStream::handshake(
        stream,
        builder
            .local_private_key(&keypair.private)?
            .psk(0, &psk_hash)?
            .build_responder()?,
    )
    .await
}

pub async fn initiator_handshake(stream: TcpStream, psk: &str) -> Result<SecureStream> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let keypair = builder.generate_keypair()?;
    let psk_hash = hash(psk);
    NoiseStream::handshake(
        stream,
        builder
            .local_private_key(&keypair.private)?
            .psk(0, &psk_hash)?
            .build_initiator()?,
    )
    .await
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
                set_tcp_opt(
                    stream.get_inner(),
                    nodelay,
                    keepalive_secs,
                    keepalive_interval,
                )?;
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
    proxy: &Option<String>,
    psk: &str,
    nodelay: bool,
    keepalive_secs: u64,
    keepalive_interval: u64,
) -> Result<SecureStream> {
    let stream = if let Some(proxy) = proxy {
        proxy_stream(proxy, server_address).await?
    } else if let Some(s) = server_socket_addr {
        TcpStream::connect(s).await?
    } else {
        TcpStream::connect(server_address).await?
    };
    let mut stream = initiator_handshake(stream, psk).await?;
    set_tcp_opt(
        stream.get_inner(),
        nodelay,
        keepalive_secs,
        keepalive_interval,
    )?;
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

type UdpPacketLen = u16; // `u16` should be enough for any practical UDP traffic on the Internet
#[derive(Encode, Decode, Debug)]
struct UdpHeader {
    from: SocketAddr,
    len: UdpPacketLen,
}

pub async fn udp_write_slice<T: AsyncWrite + Unpin>(
    writer: &mut T,
    from: SocketAddr,
    data: &[u8],
) -> Result<()> {
    let hdr = UdpHeader {
        from,
        len: data.len() as UdpPacketLen,
    };
    let hdr_bin = encode(&hdr);
    writer.write_u8(hdr_bin.len() as u8).await?;
    writer.write_all(&hdr_bin).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn udp_read<T: AsyncRead + Unpin>(
    reader: &mut T,
    hdr_len: u8,
) -> Result<(SocketAddr, Vec<u8>)> {
    let mut buf = vec![0; hdr_len as usize];
    reader.read_exact(&mut buf).await?;
    let hdr = decode::<UdpHeader>(&buf)?;
    let mut data = vec![0; hdr.len as usize];
    reader.read_exact(&mut data).await?;
    Ok((hdr.from, data))
}

pub async fn udp_copy_provider(udp_socket: &UdpSocket, stream: &mut SecureStream) -> Result<()> {
    let mut buf = [0u8; UDP_MTU];
    let mut from = None;
    loop {
        tokio::select! {
            // read from upstream
            val = udp_socket.recv(&mut buf) => {
                let n= val?;
                trace!("udp->stream: {n} bytes: {:?}",&buf[..n]);
                //send to consumer
                if let Some(from) = from {
                    udp_write_slice(stream, from, &buf[..n]).await?;
                }
            },
            // read from consumer
            hdr_len = stream.read_u8() => {
                let (new_from, data) = udp_read(stream, hdr_len?).await?;
                from = Some(new_from);
                trace!("stream->udp: {} bytes: {:?}",data.len(), data);
                //send to upstream
                udp_socket.send(&data).await?;
            }
        }
    }
}

pub async fn udp_copy_consumer(
    udp_socket: &UdpSocket,
    stream: &mut SecureStream,
    mut stop_rx: broadcast::Receiver<()>,
) -> Result<()> {
    let mut buf = [0u8; UDP_MTU];
    loop {
        tokio::select! {
            //read from visitor
            val = udp_socket.recv_from(&mut buf) => {
                let (n, from) = val?;
                trace!("udp->stream: {n} bytes: {:?}",&buf[..n]);
                // send to provider
                udp_write_slice(stream, from, &buf[..n]).await?;
            },
            //read from provider
            hdr_len = stream.read_u8() => {
                let (from, data) = udp_read(stream, hdr_len?).await?;
                trace!("stream->udp: {} bytes: {:?}",data.len(), data);
                udp_socket.send_to(&data, from).await?;
            },
            _ = stop_rx.recv() => {
                break Ok(());
            }
        }
    }
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
