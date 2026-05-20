use crate::proxy::Auth;
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    string::FromUtf8Error,
};
use tokio::{
    io,
    io::{AsyncReadExt, AsyncWriteExt},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("{0}")]
    FromUtf8(
        #[from]
        #[source]
        FromUtf8Error,
    ),
    #[error("Invalid SOCKS version: {0:x}")]
    InvalidVersion(u8),
    #[error("Invalid address type: {0:x}")]
    InvalidAtyp(u8),
    #[error("Invalid reserved bytes: {0:x}")]
    InvalidReserved(u8),
    #[error("Invalid authentication status: {0:x}")]
    InvalidAuthStatus(u8),
    #[error("Invalid authentication version of subnegotiation: {0:x}")]
    InvalidAuthSubnegotiation(u8),
    #[error("Invalid authentication method: {0:?}")]
    InvalidAuthMethod(AuthMethod),
    #[error("SOCKS version is 4 when 5 is expected")]
    WrongVersion,
    #[error("No acceptable methods")]
    NoAcceptableMethods,
    #[error("Unsuccessful reply: {0:?}")]
    Response(UnsuccessfulReply),
    #[error("{0:?} length is more than 255 bytes")]
    TooLongString(StringKind),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum StringKind {
    Domain,
    Username,
    Password,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

trait ReadExt: AsyncReadExt + Unpin {
    async fn read_version(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        match value {
            0x04 => Err(Error::WrongVersion),
            0x05 => Ok(()),
            _ => Err(Error::InvalidVersion(value)),
        }
    }

    async fn read_method(&mut self) -> Result<AuthMethod> {
        let value = self.read_u8().await?;

        let method = match value {
            0x00 => AuthMethod::None,
            0x01 => AuthMethod::GssApi,
            0x02 => AuthMethod::UsernamePassword,
            0x03..=0x7f => AuthMethod::IanaReserved(value),
            0x80..=0xfe => AuthMethod::Private(value),
            _ => return Err(Error::NoAcceptableMethods),
        };

        Ok(method)
    }

    async fn read_atyp(&mut self) -> Result<Atyp> {
        let value = self.read_u8().await?;
        let atyp = match value {
            0x01 => Atyp::V4,
            0x03 => Atyp::Domain,
            0x04 => Atyp::V6,
            _ => return Err(Error::InvalidAtyp(value)),
        };
        Ok(atyp)
    }

    async fn read_reserved(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        match value {
            0x00 => Ok(()),
            _ => Err(Error::InvalidReserved(value)),
        }
    }

    async fn read_reply(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        let reply = match value {
            0x00 => return Ok(()),
            0x01 => UnsuccessfulReply::GeneralFailure,
            0x02 => UnsuccessfulReply::ConnectionNotAllowedByRules,
            0x03 => UnsuccessfulReply::NetworkUnreachable,
            0x04 => UnsuccessfulReply::HostUnreachable,
            0x05 => UnsuccessfulReply::ConnectionRefused,
            0x06 => UnsuccessfulReply::TtlExpired,
            0x07 => UnsuccessfulReply::CommandNotSupported,
            0x08 => UnsuccessfulReply::AddressTypeNotSupported,
            _ => UnsuccessfulReply::Unassigned(value),
        };

        Err(Error::Response(reply))
    }

    async fn read_target_addr(&mut self) -> Result<AddrKind> {
        let atyp: Atyp = self.read_atyp().await?;

        let addr = match atyp {
            Atyp::V4 => {
                let mut ip = [0; 4];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                AddrKind::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            Atyp::V6 => {
                let mut ip = [0; 16];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                AddrKind::Ip(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )))
            }
            Atyp::Domain => {
                let str = self.read_string().await?;
                let port = self.read_u16().await?;
                AddrKind::Domain(str, port)
            }
        };

        Ok(addr)
    }

    async fn read_string(&mut self) -> Result<String> {
        let len = self.read_u8().await?;
        let mut str = vec![0; len as usize];
        self.read_exact(&mut str).await?;
        let str = String::from_utf8(str)?;
        Ok(str)
    }

    async fn read_auth_version(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        if value != 0x01 {
            return Err(Error::InvalidAuthSubnegotiation(value));
        }

        Ok(())
    }

    async fn read_auth_status(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        if value != 0x00 {
            return Err(Error::InvalidAuthStatus(value));
        }

        Ok(())
    }

    async fn read_selection_msg(&mut self) -> Result<AuthMethod> {
        self.read_version().await?;
        self.read_method().await
    }

    async fn read_final(&mut self) -> Result<AddrKind> {
        self.read_version().await?;
        self.read_reply().await?;
        self.read_reserved().await?;
        let addr = self.read_target_addr().await?;
        Ok(addr)
    }
}

impl<T: AsyncReadExt + Unpin> ReadExt for T {}

trait WriteExt: AsyncWriteExt + Unpin {
    async fn write_version(&mut self) -> Result<()> {
        self.write_u8(0x05).await?;
        Ok(())
    }

    async fn write_method(&mut self, method: AuthMethod) -> Result<()> {
        let value = match method {
            AuthMethod::None => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UsernamePassword => 0x02,
            AuthMethod::IanaReserved(value) => value,
            AuthMethod::Private(value) => value,
        };
        self.write_u8(value).await?;
        Ok(())
    }

    async fn write_command(&mut self, command: Command) -> Result<()> {
        self.write_u8(command as u8).await?;
        Ok(())
    }

    async fn write_atyp(&mut self, atyp: Atyp) -> Result<()> {
        self.write_u8(atyp as u8).await?;
        Ok(())
    }

    async fn write_reserved(&mut self) -> Result<()> {
        self.write_u8(0x00).await?;
        Ok(())
    }

    async fn write_target_addr(&mut self, target_addr: &AddrKind) -> Result<()> {
        match target_addr {
            AddrKind::Ip(SocketAddr::V4(addr)) => {
                self.write_atyp(Atyp::V4).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            AddrKind::Ip(SocketAddr::V6(addr)) => {
                self.write_atyp(Atyp::V6).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            AddrKind::Domain(domain, port) => {
                self.write_atyp(Atyp::Domain).await?;
                self.write_string(domain, StringKind::Domain).await?;
                self.write_u16(*port).await?;
            }
        }
        Ok(())
    }

    async fn write_string(&mut self, string: &str, kind: StringKind) -> Result<()> {
        let bytes = string.as_bytes();
        if bytes.len() > 255 {
            return Err(Error::TooLongString(kind));
        }
        self.write_u8(bytes.len() as u8).await?;
        self.write_all(bytes).await?;
        Ok(())
    }

    async fn write_auth_version(&mut self) -> Result<()> {
        self.write_u8(0x01).await?;
        Ok(())
    }

    async fn write_methods(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_u8(methods.len() as u8).await?;
        for method in methods {
            self.write_method(*method).await?;
        }
        Ok(())
    }

    async fn write_selection_msg(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_version().await?;
        self.write_methods(methods).await?;
        self.flush().await?;
        Ok(())
    }

    async fn write_final(&mut self, command: Command, addr: &AddrKind) -> Result<()> {
        self.write_version().await?;
        self.write_command(command).await?;
        self.write_reserved().await?;
        self.write_target_addr(addr).await?;
        self.flush().await?;
        Ok(())
    }
}

impl<T: AsyncWriteExt + Unpin> WriteExt for T {}

async fn username_password_auth<S>(stream: &mut S, auth: Auth) -> Result<()>
where
    S: WriteExt + ReadExt + Send,
{
    stream.write_auth_version().await?;
    stream
        .write_string(&auth.username, StringKind::Username)
        .await?;
    stream
        .write_string(&auth.password, StringKind::Password)
        .await?;
    stream.flush().await?;

    stream.read_auth_version().await?;
    stream.read_auth_status().await
}

async fn init<S, A>(
    stream: &mut S,
    command: Command,
    addr: A,
    auth: Option<Auth>,
) -> Result<AddrKind>
where
    S: WriteExt + ReadExt + Send,
    A: Into<AddrKind>,
{
    let addr: AddrKind = addr.into();

    let mut methods = Vec::with_capacity(2);
    methods.push(AuthMethod::None);
    if auth.is_some() {
        methods.push(AuthMethod::UsernamePassword);
    }
    stream.write_selection_msg(&methods).await?;

    let method: AuthMethod = stream.read_selection_msg().await?;
    match method {
        AuthMethod::None => {}
        AuthMethod::UsernamePassword if auth.is_some() => {
            username_password_auth(stream, auth.unwrap()).await?;
        }
        _ => return Err(Error::InvalidAuthMethod(method)),
    }

    stream.write_final(command, &addr).await?;
    stream.read_final().await
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum AuthMethod {
    /// No authentication required.
    None,
    /// GSS API.
    GssApi,
    /// A username + password authentication.
    UsernamePassword,
    /// IANA reserved.
    IanaReserved(u8),
    /// A private authentication method.
    Private(u8),
}

enum Command {
    Connect = 0x01,
}

enum Atyp {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x4,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum UnsuccessfulReply {
    GeneralFailure,
    ConnectionNotAllowedByRules,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Unassigned(u8),
}

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum AddrKind {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl From<(IpAddr, u16)> for AddrKind {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for AddrKind {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for AddrKind {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(String, u16)> for AddrKind {
    fn from((domain, port): (String, u16)) -> Self {
        Self::Domain(domain, port)
    }
}

impl From<(&'_ str, u16)> for AddrKind {
    fn from((domain, port): (&'_ str, u16)) -> Self {
        Self::Domain(domain.to_owned(), port)
    }
}

impl From<SocketAddr> for AddrKind {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<SocketAddrV4> for AddrKind {
    fn from(value: SocketAddrV4) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddrV6> for AddrKind {
    fn from(value: SocketAddrV6) -> Self {
        Self::Ip(value.into())
    }
}

pub async fn connect<S>(
    socket: &mut S,
    (host, port): (&str, u16),
    auth: Option<Auth>,
) -> Result<AddrKind>
where
    S: AsyncWriteExt + AsyncReadExt + Send + Unpin,
{
    init(socket, Command::Connect, (host, port), auth).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_method_to_u8(method: AuthMethod) -> u8 {
        match method {
            AuthMethod::None => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UsernamePassword => 0x02,
            AuthMethod::IanaReserved(v) => v,
            AuthMethod::Private(v) => v,
        }
    }

    #[test]
    fn test_auth_method_none() {
        assert_eq!(auth_method_to_u8(AuthMethod::None), 0x00);
    }

    #[test]
    fn test_auth_method_gssapi() {
        assert_eq!(auth_method_to_u8(AuthMethod::GssApi), 0x01);
    }

    #[test]
    fn test_auth_method_username_password() {
        assert_eq!(auth_method_to_u8(AuthMethod::UsernamePassword), 0x02);
    }

    #[test]
    fn test_auth_method_iana_reserved() {
        let m = AuthMethod::IanaReserved(0x05);
        assert_eq!(auth_method_to_u8(m), 0x05);
    }

    #[test]
    fn test_auth_method_private() {
        let m = AuthMethod::Private(0x80);
        assert_eq!(auth_method_to_u8(m), 0x80);
    }

    #[test]
    fn test_command_connect() {
        assert_eq!(Command::Connect as u8, 0x01);
    }

    #[test]
    fn test_atyp_values() {
        assert_eq!(Atyp::V4 as u8, 0x01);
        assert_eq!(Atyp::Domain as u8, 0x03);
        assert_eq!(Atyp::V6 as u8, 0x04);
    }

    #[test]
    fn test_unsuccessful_reply_display() {
        let r = UnsuccessfulReply::GeneralFailure;
        assert_eq!(format!("{:?}", r), "GeneralFailure");
    }

    #[test]
    fn test_addr_kind_from_ipv4() {
        let addr = AddrKind::from((Ipv4Addr::new(127, 0, 0, 1), 8080u16));
        match addr {
            AddrKind::Ip(SocketAddr::V4(a)) => {
                assert_eq!(a.ip(), &Ipv4Addr::new(127, 0, 0, 1));
                assert_eq!(a.port(), 8080);
            }
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn test_addr_kind_from_ipv6() {
        let addr = AddrKind::from((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 9090u16));
        match addr {
            AddrKind::Ip(SocketAddr::V6(a)) => {
                assert_eq!(a.ip(), &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
                assert_eq!(a.port(), 9090);
            }
            _ => panic!("expected IPv6"),
        }
    }

    #[test]
    fn test_addr_kind_from_ip_addr() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let addr = AddrKind::from((ip, 443u16));
        match addr {
            AddrKind::Ip(SocketAddr::V4(a)) => {
                assert_eq!(a.ip(), &Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(a.port(), 443);
            }
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn test_addr_kind_from_socket_addr() {
        let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53));
        let addr = AddrKind::from(sa);
        match addr {
            AddrKind::Ip(SocketAddr::V4(a)) => {
                assert_eq!(a.ip(), &Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(a.port(), 53);
            }
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn test_addr_kind_from_socket_addr_v4() {
        let sa = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80);
        let addr = AddrKind::from(sa);
        match addr {
            AddrKind::Ip(SocketAddr::V4(a)) => {
                assert_eq!(a.ip(), &Ipv4Addr::new(1, 2, 3, 4));
                assert_eq!(a.port(), 80);
            }
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn test_addr_kind_from_socket_addr_v6() {
        let sa = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443, 0, 0);
        let addr = AddrKind::from(sa);
        match addr {
            AddrKind::Ip(SocketAddr::V6(a)) => {
                assert_eq!(a.ip(), &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
                assert_eq!(a.port(), 443);
            }
            _ => panic!("expected IPv6"),
        }
    }

    #[test]
    fn test_addr_kind_from_str() {
        let addr = AddrKind::from(("example.com", 443u16));
        match addr {
            AddrKind::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn test_addr_kind_from_string() {
        let addr = AddrKind::from(("example.com".to_string(), 443u16));
        match addr {
            AddrKind::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected Domain"),
        }
    }

    #[test]
    fn test_error_display_invalid_version() {
        let err = Error::InvalidVersion(0x04);
        let msg = err.to_string();
        assert!(msg.contains("Invalid SOCKS version"));
        assert!(msg.contains("4"));
    }

    #[test]
    fn test_error_display_invalid_atyp() {
        let err = Error::InvalidAtyp(0xFF);
        let msg = err.to_string();
        assert!(msg.contains("Invalid address type"));
        assert!(msg.contains("ff"));
    }

    #[test]
    fn test_error_display_invalid_reserved() {
        let err = Error::InvalidReserved(0x01);
        let msg = err.to_string();
        assert!(msg.contains("Invalid reserved bytes"));
        assert!(msg.contains("1"));
    }

    #[test]
    fn test_error_display_invalid_auth_status() {
        let err = Error::InvalidAuthStatus(0x02);
        let msg = err.to_string();
        assert!(msg.contains("Invalid authentication status"));
        assert!(msg.contains("2"));
    }

    #[test]
    fn test_error_display_invalid_auth_subnegotiation() {
        let err = Error::InvalidAuthSubnegotiation(0x02);
        let msg = err.to_string();
        assert!(msg.contains("Invalid authentication version of subnegotiation"));
        assert!(msg.contains("2"));
    }

    #[test]
    fn test_error_display_invalid_auth_method() {
        let err = Error::InvalidAuthMethod(AuthMethod::GssApi);
        assert!(err.to_string().contains("GssApi"));
    }

    #[test]
    fn test_error_display_wrong_version() {
        let err = Error::WrongVersion;
        assert!(err.to_string().contains("version is 4"));
    }

    #[test]
    fn test_error_display_no_acceptable_methods() {
        let err = Error::NoAcceptableMethods;
        assert!(err.to_string().contains("No acceptable methods"));
    }

    #[test]
    fn test_error_display_response() {
        let err = Error::Response(UnsuccessfulReply::ConnectionRefused);
        assert!(err.to_string().contains("ConnectionRefused"));
    }

    #[test]
    fn test_error_display_too_long_string() {
        let err = Error::TooLongString(StringKind::Domain);
        assert!(err.to_string().contains("Domain"));
    }

    #[test]
    fn test_string_kind_display() {
        assert_eq!(format!("{:?}", StringKind::Domain), "Domain");
        assert_eq!(format!("{:?}", StringKind::Username), "Username");
        assert_eq!(format!("{:?}", StringKind::Password), "Password");
    }
}
