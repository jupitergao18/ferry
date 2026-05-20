use anyhow::{Result, anyhow};
use tokio::net::TcpStream;
use url::Url;

mod http;
mod socks5;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_new() {
        let auth = Auth::new("user".to_string(), "pass".to_string());
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");
    }

    #[test]
    fn test_auth_clone_eq() {
        let auth1 = Auth::new("u".to_string(), "p".to_string());
        let auth2 = auth1.clone();
        assert_eq!(auth1, auth2);
    }

    #[test]
    fn test_proxy_url_parse_socks5() {
        let url = Url::parse("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(url.scheme(), "socks5");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(1080));
        assert!(url.username().is_empty());
        assert!(url.password().is_none());
    }

    #[test]
    fn test_proxy_url_parse_socks5_with_auth() {
        let url = Url::parse("socks5://user:pass@127.0.0.1:1080").unwrap();
        assert_eq!(url.username(), "user");
        assert_eq!(url.password(), Some("pass"));
    }

    #[test]
    fn test_proxy_url_parse_http() {
        let url = Url::parse("http://proxy.example.com:8080").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("proxy.example.com"));
        assert_eq!(url.port(), Some(8080));
    }

    #[test]
    fn test_server_address_parsing() {
        let addr = "127.0.0.1:8080";
        let semi = addr.rfind(':').unwrap();
        let host = &addr[..semi];
        let port: u16 = addr[semi + 1..].parse().unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_server_address_ipv6() {
        let addr = "[::1]:8080";
        let semi = addr.rfind(':').unwrap();
        let host = &addr[..semi];
        let port: u16 = addr[semi + 1..].parse().unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_server_address_missing_colon() {
        let addr = "nocolon";
        assert!(addr.rfind(':').is_none());
    }
}
