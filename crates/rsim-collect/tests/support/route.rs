//! Servers on 127.0.0.1 for the routes of the transport tests: an SSH jump
//! host that logs each login attempt, an HTTP CONNECT proxy and a SOCKS5
//! proxy. Each server counts the connections that it forwards. Each test
//! crate uses a part of the servers.

#![allow(dead_code)]

use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Response, Session};
use russh::{Channel, MethodKind, MethodSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A running server: its address and the number of forwarded connections.
pub struct Forwarder {
    pub address: String,
    pub forwards: Arc<AtomicUsize>,
}

impl Forwarder {
    pub fn forwards(&self) -> usize {
        self.forwards.load(Ordering::SeqCst)
    }
}

/// A running jump host.
pub struct BastionFixture {
    pub forwarder: Forwarder,
    /// The host key in the OpenSSH form.
    pub host_key: String,
    /// Each login attempt as `method user secret`.
    pub log: Arc<Mutex<Vec<String>>>,
}

impl BastionFixture {
    pub fn address(&self) -> &str {
        &self.forwarder.address
    }

    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

#[derive(Clone)]
struct Bastion {
    user: String,
    password: String,
    log: Arc<Mutex<Vec<String>>>,
    forwards: Arc<AtomicUsize>,
}

impl russh::server::Handler for Bastion {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.log
            .lock()
            .unwrap()
            .push(format!("password {user} {password}"));
        let ok = user == self.user && password == self.password;
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        match response {
            None => Ok(Auth::Partial {
                name: Cow::Borrowed(""),
                instructions: Cow::Borrowed(""),
                prompts: Cow::Owned(vec![(Cow::Borrowed("Password: "), false)]),
            }),
            Some(mut r) => {
                let answer = r
                    .next()
                    .map(|b| String::from_utf8_lossy(&b).to_string())
                    .unwrap_or_default();
                self.log
                    .lock()
                    .unwrap()
                    .push(format!("keyboard-interactive {user} {answer}"));
                let ok = user == self.user && answer == self.password;
                Ok(if ok { Auth::Accept } else { Auth::reject() })
            }
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.log.lock().unwrap().push(format!("publickey {user} -"));
        Ok(Auth::reject())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let target = format!("{host_to_connect}:{port_to_connect}");
        let Ok(tcp) = TcpStream::connect(&target).await else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        reply.accept().await;
        self.forwards.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let mut tcp = tcp;
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
        Ok(())
    }
}

/// Starts a jump host that accepts only `user` with `password`.
pub async fn bastion(user: &str, password: &str) -> BastionFixture {
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let text = host.public_key().to_openssh().unwrap();
    let host_key = text
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    methods.push(MethodKind::KeyboardInteractive);
    methods.push(MethodKind::PublicKey);
    let config = Arc::new(russh::server::Config {
        keys: vec![host],
        methods,
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let log = Arc::new(Mutex::new(Vec::new()));
    let forwards = Arc::new(AtomicUsize::new(0));
    let handler = Bastion {
        user: user.into(),
        password: password.into(),
        log: log.clone(),
        forwards: forwards.clone(),
    };
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let config = config.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    BastionFixture {
        forwarder: Forwarder { address, forwards },
        host_key,
        log,
    }
}

async fn pipe(mut a: TcpStream, target: &str) {
    if let Ok(mut b) = TcpStream::connect(target).await {
        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
    }
}

/// Starts a forwarder to `target` that closes its first connection at once
/// and forwards the connections after it.
pub async fn flaky(target: String) -> Forwarder {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let forwards = Arc::new(AtomicUsize::new(0));
    let count = forwards.clone();
    tokio::spawn(async move {
        let (first, _) = listener.accept().await.unwrap();
        drop(first);
        loop {
            let (s, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let target = target.clone();
            tokio::spawn(async move { pipe(s, &target).await });
        }
    });
    Forwarder { address, forwards }
}

/// Starts an HTTP proxy that accepts `CONNECT`. With a login, a request
/// with no `Proxy-Authorization` of `user:password` gets HTTP 407.
pub async fn http_proxy(login: Option<&'static str>) -> Forwarder {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let forwards = Arc::new(AtomicUsize::new(0));
    let count = forwards.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let count = count.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut b = [0u8; 1];
                    if s.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let target = text
                    .lines()
                    .next()
                    .and_then(|l| l.strip_prefix("CONNECT "))
                    .and_then(|l| l.split_whitespace().next())
                    .unwrap_or_default()
                    .to_string();
                if let Some(login) = login {
                    let want = format!("Proxy-Authorization: Basic {}", base64(login.as_bytes()));
                    if !text.lines().any(|l| l == want) {
                        let _ = s
                            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                            .await;
                        return;
                    }
                }
                let _ = s
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await;
                count.fetch_add(1, Ordering::SeqCst);
                pipe(s, &target).await;
            });
        }
    });
    Forwarder { address, forwards }
}

/// Starts a SOCKS5 proxy with no login that accepts IPv4 addresses and
/// host names.
pub async fn socks5_proxy() -> Forwarder {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let forwards = Arc::new(AtomicUsize::new(0));
    let count = forwards.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let count = count.clone();
            tokio::spawn(async move {
                let mut g = [0u8; 3];
                if s.read_exact(&mut g).await.is_err() || g != [5, 1, 0] {
                    return;
                }
                s.write_all(&[5, 0]).await.unwrap();
                let mut h = [0u8; 4];
                s.read_exact(&mut h).await.unwrap();
                let host = match h[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        s.read_exact(&mut a).await.unwrap();
                        std::net::Ipv4Addr::from(a).to_string()
                    }
                    3 => {
                        let mut l = [0u8; 1];
                        s.read_exact(&mut l).await.unwrap();
                        let mut n = vec![0u8; usize::from(l[0])];
                        s.read_exact(&mut n).await.unwrap();
                        String::from_utf8(n).unwrap()
                    }
                    _ => return,
                };
                let mut p = [0u8; 2];
                s.read_exact(&mut p).await.unwrap();
                let target = format!("{host}:{}", u16::from_be_bytes(p));
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                pipe(s, &target).await;
            });
        }
    });
    Forwarder { address, forwards }
}

/// The standard base64 form of bytes.
pub fn base64(input: &[u8]) -> String {
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
