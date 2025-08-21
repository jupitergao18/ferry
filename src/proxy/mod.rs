use anyhow::{Result, anyhow};
use tokio::net::TcpStream;
use url::Url;

pub mod http;
pub mod socks5;

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Auth {
    pub username: String,
    pub password: String,
}

impl Auth {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}

pub async fn proxy_stream(proxy: &str, server_address: &str) -> Result<TcpStream> {
    let proxy = Url::parse(proxy)?;
    let mut proxy_stream = TcpStream::connect((
        proxy.host_str().expect("proxy url should have host field"),
        proxy.port().expect("proxy url should have port field"),
    ))
    .await?;
    let auth = if !proxy.username().is_empty() || proxy.password().is_some() {
        Some(Auth::new(
            proxy.username().to_string(),
            proxy.password().unwrap_or("").to_string(),
        ))
    } else {
        None
    };
    let semi = server_address
        .rfind(':')
        .ok_or(anyhow!("missing semicolon"))?;
    let host = &server_address[..semi];
    let port = server_address[semi + 1..].parse()?;
    match proxy.scheme() {
        "socks5" => {
            socks5::connect(&mut proxy_stream, (host, port), auth).await?;
        }
        "http" => {
            http::connect(&mut proxy_stream, (host, port), auth).await?;
        }
        _ => panic!("unknown proxy scheme"),
    }
    Ok(proxy_stream)
}
