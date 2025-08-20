use crate::proxy::Auth;
use httparse::Error as HttpParseError;
use httparse::{EMPTY_HEADER, Response};
use std::io::Error as IoError;
use std::io::Result as IoResult;
use thiserror::Error as ThisError;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufStream};

pub const MAXIMUM_RESPONSE_HEADER_LENGTH: usize = 4096;
pub const MAXIMUM_RESPONSE_HEADERS: usize = 64;

/// This enum contains all errors, which can occur during the HTTP `CONNECT`.
#[derive(Debug, ThisError)]
pub enum HttpError {
    #[error("IO Error: {0}")]
    IoError(#[from] IoError),
    #[error("HTTP parse error: {0}")]
    HttpParseError(#[from] HttpParseError),
    #[error("The maximum response header length is exceeded: {0}")]
    MaximumResponseHeaderLengthExceeded(String),
    #[error("The end of file is reached")]
    EndOfFile,
    #[error("No HTTP code was found in the response")]
    NoHttpCode,
    #[error("The HTTP code is not equal 200: {0}")]
    HttpCode200(u16),
}

pub async fn connect<IO>(
    io: &mut IO,
    (host, port): (&str, u16),
    auth: Option<Auth>,
) -> Result<(), HttpError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufStream::new(io);
    if let Some(auth) = auth {
        send_request_with_basic_auth(&mut stream, host, port, &auth.username, &auth.password)
            .await?;
    } else {
        send_request(&mut stream, host, port).await?;
    }
    recv_and_check_response(&mut stream).await?;
    Ok(())
}

// request
fn get_proxy_authorization(username: &str, password: &str) -> String {
    use base64::prelude::*;
    let authorization = format!("{}:{}", username, password);
    let authorization = BASE64_STANDARD.encode(authorization.as_bytes());
    format!("Proxy-Authorization: Basic {}\r\n", authorization)
}

fn make_request(host: &str, port: u16) -> String {
    format!(
        "CONNECT {0}:{1} HTTP/1.1\r\n\
         Host: {0}:{1}\r\n\
         Proxy-Connection: Keep-Alive\r\n",
        host, port
    )
}

fn make_request_without_basic_auth(host: &str, port: u16) -> String {
    let mut request = make_request(host, port);
    request.push_str("\r\n");
    request
}

fn make_request_with_basic_auth(host: &str, port: u16, username: &str, password: &str) -> String {
    let mut request = make_request(host, port);
    let proxy_authorization = get_proxy_authorization(username, password);
    request.push_str(&proxy_authorization);
    request.push_str("\r\n");
    request
}

pub(crate) async fn send_request<IO>(
    stream: &mut BufStream<IO>,
    host: &str,
    port: u16,
) -> IoResult<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let request = make_request_without_basic_auth(host, port);
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await
}

pub(crate) async fn send_request_with_basic_auth<IO>(
    stream: &mut BufStream<IO>,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> IoResult<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let request = make_request_with_basic_auth(host, port, username, password);
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await
}

// response
async fn get_response<IO>(stream: &mut BufStream<IO>) -> Result<String, HttpError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut response = String::new();
    loop {
        if stream.read_line(&mut response).await? == 0 {
            return Err(HttpError::EndOfFile);
        }
        if MAXIMUM_RESPONSE_HEADER_LENGTH < response.len() {
            return Err(HttpError::MaximumResponseHeaderLengthExceeded(response));
        }
        if response.ends_with("\r\n\r\n") {
            return Ok(response);
        }
    }
}

fn check_code(response: &Response<'_, '_>) -> Result<(), HttpError> {
    match response.code {
        Some(code) => {
            if code == 200 {
                Ok(())
            } else {
                Err(HttpError::HttpCode200(code))
            }
        }
        None => Err(HttpError::NoHttpCode),
    }
}

fn parse_and_check(response_string: &str) -> Result<(), HttpError> {
    let mut response_headers = [EMPTY_HEADER; MAXIMUM_RESPONSE_HEADERS];
    let mut response = Response::new(&mut response_headers[..]);
    response.parse(response_string.as_bytes())?;
    check_code(&response)?;
    Ok(())
}

pub(crate) async fn recv_and_check_response<IO>(stream: &mut BufStream<IO>) -> Result<(), HttpError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let response_string = get_response(stream).await?;
    parse_and_check(&response_string)?;
    Ok(())
}
