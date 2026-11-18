//! The network path to a device: an optional proxy for the first TCP
//! connection and a chain of SSH jump hosts.

use std::fmt;
#[cfg(any(feature = "ssh", feature = "https"))]
use std::time::Duration;

#[cfg(any(feature = "ssh", feature = "https"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(any(feature = "ssh", feature = "https"))]
use tokio::net::TcpStream;

/// The SSH algorithm sets of a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithms {
    /// ML-KEM, Curve25519, ECDH on the NIST curves and DH groups with
    /// SHA-2, AEAD and CTR ciphers, MACs with SHA-2, and host keys with SHA-2
    /// signatures. Strict key exchange is on when the server supports it.
    #[default]
    Modern,
    /// The modern set, then the SHA-1 DH groups, the CBC ciphers, the SHA-1
    /// MACs and `ssh-rsa` host keys with SHA-1 signatures. Older network
    /// operating systems need these.
    Legacy,
}

/// A user name and a password of a proxy.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProxyLogin {
    pub user: String,
    pub password: String,
}

impl fmt::Debug for ProxyLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyLogin({}, ..)", self.user)
    }
}

/// A proxy for the first TCP connection of a route.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proxy {
    /// An HTTP proxy that accepts `CONNECT host:port`.
    Http {
        host: String,
        port: u16,
        login: Option<ProxyLogin>,
    },
    /// A SOCKS5 proxy, with no login or with a user name and a password.
    Socks5 {
        host: String,
        port: u16,
        login: Option<ProxyLogin>,
    },
}

impl Proxy {
    /// Reads `http://[user:password@]host:port` or
    /// `socks5://[user:password@]host:port`, with the reader of the
    /// inventory. An error does not show the login.
    pub fn parse(url: &str) -> Result<Proxy, String> {
        let p = rsim_inventory::env::parse_proxy(url)?;
        let login = p
            .login
            .map(|(user, password)| ProxyLogin { user, password });
        let (host, port) = (p.host, p.port);
        if p.scheme == "http" {
            Ok(Proxy::Http { host, port, login })
        } else {
            Ok(Proxy::Socks5 { host, port, login })
        }
    }

    /// The address of the proxy, with no login.
    pub fn address(&self) -> String {
        match self {
            Proxy::Http { host, port, .. } | Proxy::Socks5 { host, port, .. } => {
                if host.contains(':') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                }
            }
        }
    }
}

/// An SSH jump host. It has its own credential and its own pinned host
/// key. The credential of the device is never sent to it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Jump {
    /// The host name or the address, with an optional port.
    pub address: String,
    /// The name of the credential in the credential source.
    pub credential: String,
    pub algorithms: Algorithms,
}

/// The path to a device: the proxy of the first TCP connection, then the
/// jump hosts in order. The empty route is a direct connection.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Route {
    pub proxy: Option<Proxy>,
    pub jumps: Vec<Jump>,
}

impl Route {
    /// The name of the pin of a host at the end of the first `hops` jumps.
    /// A host with no jump before it has its address as the name. A host
    /// behind jumps has the addresses of the jumps and its own address,
    /// separated by `>`, because the same private address can be behind 2
    /// different jump hosts.
    pub fn pin_name(&self, hops: usize, address: &str) -> String {
        let mut parts: Vec<&str> = self.jumps[..hops]
            .iter()
            .map(|j| j.address.as_str())
            .collect();
        parts.push(address);
        parts.join(">")
    }
}

/// A byte stream to a device, through a proxy or through jump hosts.
#[cfg(any(feature = "ssh", feature = "https"))]
pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

#[cfg(any(feature = "ssh", feature = "https"))]
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

/// A TCP connection to `host:port`, through the proxy if there is one. The
/// time limit covers the connection and the proxy handshake. An error names
/// the proxy or the host.
#[cfg(any(feature = "ssh", feature = "https"))]
pub async fn tcp(
    proxy: Option<&Proxy>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let open = async {
        match proxy {
            None => TcpStream::connect((host, port))
                .await
                .map_err(|e| format!("{host}:{port}: {e}")),
            Some(p) => {
                let (ph, pp) = match p {
                    Proxy::Http { host, port, .. } | Proxy::Socks5 { host, port, .. } => {
                        (host.as_str(), *port)
                    }
                };
                let mut s = TcpStream::connect((ph, pp))
                    .await
                    .map_err(|e| format!("proxy {}: {e}", p.address()))?;
                match p {
                    Proxy::Http { login, .. } => {
                        http_connect(&mut s, host, port, login.as_ref()).await
                    }
                    Proxy::Socks5 { login, .. } => socks5(&mut s, host, port, login.as_ref()).await,
                }
                .map_err(|e| format!("proxy {}: {e}", p.address()))?;
                Ok(s)
            }
        }
    };
    let s = tokio::time::timeout(timeout, open)
        .await
        .map_err(|_| match proxy {
            Some(p) => format!(
                "proxy {}: no connection to {host}:{port} in {timeout:?}",
                p.address()
            ),
            None => format!("{host}:{port}: no connection in {timeout:?}"),
        })??;
    let _ = s.set_nodelay(true);
    Ok(s)
}

#[cfg(any(feature = "ssh", feature = "https"))]
fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in input.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= c.len() {
                out.push(T[((n >> shift) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(any(feature = "ssh", feature = "https"))]
async fn http_connect(
    s: &mut TcpStream,
    host: &str,
    port: u16,
    login: Option<&ProxyLogin>,
) -> Result<(), String> {
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(ProxyLogin {
        user: u,
        password: p,
    }) = login
    {
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(format!("{u}:{p}").as_bytes())
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    // Read the reply head byte by byte, so no byte of the tunnel is read.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err("the reply head is too long".into());
        }
        let mut b = [0u8; 1];
        let n = s.read(&mut b).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("the proxy closed the connection".into());
        }
        head.push(b[0]);
    }
    let line = String::from_utf8_lossy(&head);
    let status = line.lines().next().unwrap_or_default().to_string();
    let code = status.split_whitespace().nth(1).unwrap_or_default();
    if code.starts_with('2') {
        Ok(())
    } else {
        Err(format!("CONNECT {target} gave {status}"))
    }
}

#[cfg(any(feature = "ssh", feature = "https"))]
async fn socks5(
    s: &mut TcpStream,
    host: &str,
    port: u16,
    login: Option<&ProxyLogin>,
) -> Result<(), String> {
    let err = |e: std::io::Error| e.to_string();
    let method = if login.is_some() { 2u8 } else { 0u8 };
    s.write_all(&[5, 1, method]).await.map_err(err)?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.map_err(err)?;
    if r[0] != 5 || r[1] != method {
        return Err(format!("the proxy refused the login method {method}"));
    }
    if let Some(ProxyLogin {
        user: u,
        password: p,
    }) = login
    {
        let mut m = vec![
            1,
            u8::try_from(u.len()).map_err(|_| "the user name is too long")?,
        ];
        m.extend_from_slice(u.as_bytes());
        m.push(u8::try_from(p.len()).map_err(|_| "the password is too long")?);
        m.extend_from_slice(p.as_bytes());
        s.write_all(&m).await.map_err(err)?;
        s.read_exact(&mut r).await.map_err(err)?;
        if r[1] != 0 {
            return Err("the proxy did not accept the login".into());
        }
    }
    let mut m = vec![5, 1, 0];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => {
            m.push(1);
            m.extend_from_slice(&a.octets());
        }
        Ok(std::net::IpAddr::V6(a)) => {
            m.push(4);
            m.extend_from_slice(&a.octets());
        }
        Err(_) => {
            m.push(3);
            m.push(u8::try_from(host.len()).map_err(|_| "the host name is too long")?);
            m.extend_from_slice(host.as_bytes());
        }
    }
    m.extend_from_slice(&port.to_be_bytes());
    s.write_all(&m).await.map_err(err)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(err)?;
    if head[1] != 0 {
        return Err(format!(
            "the proxy refused {host}:{port} with code {}",
            head[1]
        ));
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(err)?;
            usize::from(l[0])
        }
        x => return Err(format!("the proxy gave address type {x}")),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await.map_err(err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxies_parse() {
        assert_eq!(
            Proxy::parse("http://proxy.example:3128").unwrap(),
            Proxy::Http {
                host: "proxy.example".into(),
                port: 3128,
                login: None
            }
        );
        assert_eq!(
            Proxy::parse("socks5://u:p@192.0.2.9:1080/").unwrap(),
            Proxy::Socks5 {
                host: "192.0.2.9".into(),
                port: 1080,
                login: Some(ProxyLogin {
                    user: "u".into(),
                    password: "p".into()
                })
            }
        );
        assert_eq!(
            Proxy::parse("http://[2001:db8::7]:8080").unwrap().address(),
            "[2001:db8::7]:8080"
        );
        assert!(Proxy::parse("ftp://x:1").is_err());
        assert!(Proxy::parse("http://x").is_err());
    }

    #[test]
    fn the_login_of_a_proxy_stays_hidden() {
        let p = Proxy::parse("socks5://u:hunter2@192.0.2.9:1080").unwrap();
        assert!(!format!("{p:?}").contains("hunter2"));
        let e = Proxy::parse("gopher://u:hunter2@192.0.2.9:1080").unwrap_err();
        assert!(!e.contains("hunter2"), "{e}");
        let e = Proxy::parse("http://u:hunter2@192.0.2.9").unwrap_err();
        assert!(!e.contains("hunter2"), "{e}");
    }

    #[test]
    fn a_pin_name_has_the_jumps() {
        let jump = |a: &str| Jump {
            address: a.into(),
            credential: "j".into(),
            algorithms: Algorithms::Modern,
        };
        let r = Route {
            proxy: None,
            jumps: vec![jump("bastion.example"), jump("10.0.0.1")],
        };
        assert_eq!(r.pin_name(0, "bastion.example"), "bastion.example");
        assert_eq!(r.pin_name(1, "10.0.0.1"), "bastion.example>10.0.0.1");
        assert_eq!(
            r.pin_name(2, "10.0.0.9"),
            "bastion.example>10.0.0.1>10.0.0.9"
        );
    }

    #[test]
    #[cfg(any(feature = "ssh", feature = "https"))]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
    }
}
