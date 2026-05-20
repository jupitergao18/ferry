use crate::proxy::Auth;
use httparse::{EMPTY_HEADER, Response};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufStream};

pub const MAXIMUM_RESPONSE_HEADER_LENGTH: usize = 4096;
pub const MAXIMUM_RESPONSE_HEADERS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP parse error: {0}")]
    HttpParse(#[from] httparse::Error),
    #[error("The maximum response header length is exceeded: {0}")]
    MaximumResponseHeaderLengthExceeded(String),
    #[error("The end of file is reached")]
    EndOfFile,
    #[error("No HTTP code was found in the response")]
    NoHttpCode,
    #[error("The HTTP code is not equal 200: {0}")]
    HttpCodeNot200(u16),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn connect<S>(conn: &mut S, (host, port): (&str, u16), auth: Option<Auth>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufStream::new(conn);
    send(&mut stream, (host, port), auth).await?;
    recv(&mut stream).await
}

async fn send<S>(
    stream: &mut BufStream<S>,
    (host, port): (&str, u16),
    auth: Option<Auth>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = format!(
        "CONNECT {0}:{1} HTTP/1.1\r\n\
         Host: {0}:{1}\r\n\
         Proxy-Connection: Keep-Alive\r\n",
        host, port
    );

    if let Some(auth) = auth {
        use base64::prelude::*;
        let authorization = format!("{}:{}", auth.username, auth.password);
        let authorization = BASE64_STANDARD.encode(authorization.as_bytes());
        let proxy_authorization = format!("Proxy-Authorization: Basic {}\r\n", authorization);
        request.push_str(&proxy_authorization);
    }

    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn recv<S>(stream: &mut BufStream<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut response_string = String::new();
    loop {
        if stream.read_line(&mut response_string).await? == 0 {
            return Err(Error::EndOfFile);
        }
        if MAXIMUM_RESPONSE_HEADER_LENGTH < response_string.len() {
            return Err(Error::MaximumResponseHeaderLengthExceeded(response_string));
        }
        if response_string.ends_with("\r\n\r\n") {
            break;
        }
    }
    let mut response_headers = [EMPTY_HEADER; MAXIMUM_RESPONSE_HEADERS];
    let mut response = Response::new(&mut response_headers[..]);
    response.parse(response_string.as_bytes())?;
    match response.code {
        Some(code) => {
            if code == 200 {
                Ok(())
            } else {
                Err(Error::HttpCodeNot200(code))
            }
        }
        None => Err(Error::NoHttpCode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err = Error::Io(io_err);
        assert!(err.to_string().contains("IO Error"));
    }

    #[test]
    fn test_error_display_http_code_not_200() {
        let err = Error::HttpCodeNot200(403);
        assert!(err.to_string().contains("403"));
    }

    #[test]
    fn test_error_display_eof() {
        let err = Error::EndOfFile;
        assert!(err.to_string().contains("end of file"));
    }

    #[test]
    fn test_error_display_no_http_code() {
        let err = Error::NoHttpCode;
        assert!(err.to_string().contains("No HTTP code"));
    }

    #[test]
    fn test_error_display_maximum_length_exceeded() {
        let err = Error::MaximumResponseHeaderLengthExceeded("foo".to_string());
        assert!(err.to_string().contains("maximum response header length"));
    }
}
