//! SSH logins to the hops of a route: the jump hosts and the device. The
//! SSH transport and the HTTPS transport use them.

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelStream, Disconnect, Preferred, cipher, kex, mac};

use crate::path::{Algorithms, Io, Route, tcp};
use crate::trust::{
    Credential, Credentials, PinKind, Secret, TrustStore, host_port, plain_address,
};

/// The time before the second try of a hop that closes the connection
/// before the key exchange ends.
const EARLY_CLOSE_RETRY: Duration = Duration::from_secs(2);

impl Algorithms {
    pub(crate) fn preferred(self) -> Preferred {
        let modern_keys = vec![
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
        ];
        let base = Preferred::DEFAULT;
        let mut kexes = base.kex.to_vec();
        let mut extra = vec![
            kex::ECDH_SHA2_NISTP256,
            kex::ECDH_SHA2_NISTP384,
            kex::ECDH_SHA2_NISTP521,
        ];
        let mut keys = modern_keys;
        let mut ciphers = base.cipher.to_vec();
        let mut macs = base.mac.to_vec();
        if self == Algorithms::Legacy {
            extra.extend([kex::DH_GEX_SHA1, kex::DH_G14_SHA1, kex::DH_G1_SHA1]);
            keys.push(Algorithm::Rsa { hash: None });
            ciphers.extend([
                cipher::AES_256_CBC,
                cipher::AES_192_CBC,
                cipher::AES_128_CBC,
            ]);
            macs.extend([mac::HMAC_SHA1_ETM, mac::HMAC_SHA1]);
        }
        let ext = kexes
            .iter()
            .position(|k| *k == kex::EXTENSION_SUPPORT_AS_CLIENT)
            .unwrap_or(kexes.len());
        kexes.splice(ext..ext, extra);
        Preferred {
            kex: Cow::Owned(kexes),
            key: Cow::Owned(keys),
            cipher: Cow::Owned(ciphers),
            mac: Cow::Owned(macs),
            ..base
        }
    }
}

/// The time limits of the hops of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HopLimits {
    /// The TCP connection, the proxy handshake, or the opening of the
    /// channel through the jump host before the hop.
    pub connect: Duration,
    /// The key exchange and the login of one hop.
    pub handshake: Duration,
    /// The keepalive interval of the last SSH hop of the route.
    pub keepalive: Duration,
}

/// The SSH client of one hop. It accepts the host key only if the trust
/// store accepts it for the pin name of the hop. With `pinned`, the key
/// must be the pin, whatever the policy of the store.
pub(crate) struct Client {
    trust: Arc<TrustStore>,
    pin: String,
    pinned: bool,
    rejected: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            *self.rejected.lock().expect("the lock is not poisoned") =
                Some("the host offers a certificate in place of a host key".into());
            return Ok(false);
        };
        let Ok(text) = key.to_openssh() else {
            return Ok(false);
        };
        let text: Vec<&str> = text.split_whitespace().take(2).collect();
        let key = text.join(" ");
        let checked = if self.pinned {
            self.trust.check_pinned(PinKind::Ssh, &self.pin, &key)
        } else {
            self.trust.check(PinKind::Ssh, &self.pin, &key)
        };
        match checked {
            Ok(()) => Ok(true),
            Err(e) => {
                *self.rejected.lock().expect("the lock is not poisoned") = Some(e);
                Ok(false)
            }
        }
    }
}

/// One hop of a route, with the data for its login.
pub(crate) struct Hop<'a> {
    /// `device` or `bastion`, for the error text.
    pub role: &'static str,
    pub address: &'a str,
    pub pin: String,
    /// True if the host key must be the pin, whatever the policy of the
    /// trust store.
    pub pinned: bool,
    pub credential: Credential,
    pub algorithms: Algorithms,
    /// True for the last SSH hop of the route, which gets the keepalive.
    pub last: bool,
}

impl Hop<'_> {
    fn name(&self) -> String {
        format!("{} {}", self.role, self.address)
    }
}

/// True if the error is a close of the connection before the login.
fn early_close(e: &russh::Error) -> bool {
    match e {
        russh::Error::Disconnect | russh::Error::HUP => true,
        russh::Error::IO(io) => matches!(
            io.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
        ),
        _ => false,
    }
}

/// Logs in to a hop over the streams that `open` gives. A hop that closes
/// the connection before the key exchange ends gets one more try. Each
/// error names the hop.
pub(crate) async fn login<F, Fut>(
    hop: &Hop<'_>,
    trust: &Arc<TrustStore>,
    limits: HopLimits,
    open: F,
) -> Result<Handle<Client>, String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<Box<dyn Io + 'static>, String>>,
{
    let name = hop.name();
    let config = Arc::new(client::Config {
        preferred: hop.algorithms.preferred(),
        keepalive_interval: hop.last.then_some(limits.keepalive),
        keepalive_max: 3,
        nodelay: true,
        ..client::Config::default()
    });
    let mut tries = 0;
    let handle = loop {
        tries += 1;
        let stream = open().await?;
        let rejected = Arc::new(Mutex::new(None));
        let handler = Client {
            trust: trust.clone(),
            pin: hop.pin.clone(),
            pinned: hop.pinned,
            rejected: rejected.clone(),
        };
        let connect = client::connect_stream(config.clone(), stream, handler);
        match tokio::time::timeout(limits.handshake, connect).await {
            Err(_) => {
                return Err(format!("{name}: no key exchange in {:?}", limits.handshake));
            }
            Ok(Ok(h)) => break h,
            Ok(Err(russh::Error::UnknownKey)) => {
                let why = rejected
                    .lock()
                    .expect("the lock is not poisoned")
                    .take()
                    .unwrap_or_else(|| "the host key is not accepted".into());
                return Err(format!("{name}: {why}"));
            }
            Ok(Err(e)) if early_close(&e) && tries == 1 => {
                tokio::time::sleep(EARLY_CLOSE_RETRY).await;
            }
            Ok(Err(e)) if early_close(&e) => {
                return Err(format!(
                    "{name}: the host closed the connection before the login: {e}"
                ));
            }
            Ok(Err(e)) => return Err(format!("{name}: {e}")),
        }
    };
    let mut handle = handle;
    let auth = authenticate(&mut handle, &hop.credential, &name);
    let ok = tokio::time::timeout(limits.handshake, auth)
        .await
        .map_err(|_| format!("{name}: no login in {:?}", limits.handshake))??;
    if !ok {
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
        return Err(format!(
            "{name}: the host did not accept the credential of {}",
            hop.credential.user
        ));
    }
    Ok(handle)
}

async fn authenticate(
    handle: &mut Handle<Client>,
    credential: &Credential,
    name: &str,
) -> Result<bool, String> {
    let err = |e: russh::Error| format!("{name}: {e}");
    let user = credential.user.clone();
    match &credential.secret {
        Secret::Password(password) => {
            let r = handle
                .authenticate_password(user.clone(), password.clone())
                .await
                .map_err(err)?;
            if r.success() {
                return Ok(true);
            }
            keyboard_interactive(handle, &user, password)
                .await
                .map_err(err)
        }
        Secret::Key { pem, passphrase } => {
            let key = russh::keys::decode_secret_key(pem, passphrase.as_deref())
                .map_err(|e| format!("{name}: the private key does not decode: {e}"))?;
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(err)?
                .flatten();
            let r: AuthResult = handle
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
                .map_err(err)?;
            Ok(r.success())
        }
        Secret::Agent { socket } => agent(handle, &user, socket.clone(), name).await,
        Secret::ApiKey(_) => Err(format!("{name}: an API key is not an SSH credential")),
        Secret::Token(_) => Err(format!("{name}: an API token is not an SSH credential")),
        Secret::OAuthClient(_) => Err(format!("{name}: an OAuth client is not an SSH credential")),
    }
}

#[cfg(unix)]
async fn agent(
    handle: &mut Handle<Client>,
    user: &str,
    socket: Option<PathBuf>,
    name: &str,
) -> Result<bool, String> {
    use russh::keys::agent::client::AgentClient;
    let socket = socket
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from))
        .ok_or_else(|| format!("{name}: no agent socket, and SSH_AUTH_SOCK is not set"))?;
    let mut client = AgentClient::connect_uds(&socket)
        .await
        .map_err(|e| format!("{name}: the agent at {}: {e}", socket.display()))?;
    let identities = client
        .request_identities()
        .await
        .map_err(|e| format!("{name}: the agent gives no keys: {e}"))?;
    let hash = handle
        .best_supported_rsa_hash()
        .await
        .map_err(|e| format!("{name}: {e}"))?
        .flatten();
    for identity in identities {
        let key = identity.public_key().into_owned();
        let hash = matches!(key.algorithm(), Algorithm::Rsa { .. })
            .then_some(hash)
            .flatten();
        if let Ok(r) = handle
            .authenticate_publickey_with(user, key, hash, &mut client)
            .await
            && r.success()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(not(unix))]
async fn agent(
    _handle: &mut Handle<Client>,
    _user: &str,
    _socket: Option<PathBuf>,
    name: &str,
) -> Result<bool, String> {
    Err(format!("{name}: an SSH agent needs a Unix socket"))
}

async fn keyboard_interactive(
    handle: &mut Handle<Client>,
    user: &str,
    password: &str,
) -> Result<bool, russh::Error> {
    let mut r = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await?;
    for _ in 0..4 {
        match r {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = prompts.iter().map(|_| password.to_string()).collect();
                r = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Ok(false)
}

/// The logged-in jump hosts of a route. A dropped tunnel closes its
/// connections.
pub(crate) struct Tunnel {
    hops: Vec<(String, Handle<Client>)>,
}

impl Tunnel {
    /// Logs in to each jump host of the route in order, each through the
    /// jump host before it. `last` is true if no SSH hop comes after the
    /// tunnel, and the last jump host then gets the keepalive. With
    /// `pinned`, the host key of each jump host must be its pin, whatever
    /// the policy of the trust store.
    pub async fn connect(
        route: &Route,
        credentials: &dyn Credentials,
        trust: &Arc<TrustStore>,
        limits: HopLimits,
        last: bool,
        pinned: bool,
    ) -> Result<Tunnel, String> {
        let mut tunnel = Tunnel { hops: Vec::new() };
        for (i, jump) in route.jumps.iter().enumerate() {
            let name = format!("bastion {}", jump.address);
            let credential = credentials
                .get(&jump.credential)
                .map_err(|e| format!("{name}: {e}"))?;
            let address =
                plain_address(&jump.address, "ssh").map_err(|e| format!("{name}: {e}"))?;
            let (host, port) = host_port(address, 22).map_err(|e| format!("{name}: {e}"))?;
            let hop = Hop {
                role: "bastion",
                address,
                pin: route.pin_name(i, address),
                pinned,
                credential,
                algorithms: jump.algorithms,
                last: last && i + 1 == route.jumps.len(),
            };
            let handle = if i == 0 {
                let proxy = route.proxy.as_ref();
                login(&hop, trust, limits, || {
                    let host = host.clone();
                    let name = name.clone();
                    async move {
                        let s = tcp(proxy, &host, port, limits.connect)
                            .await
                            .map_err(|e| format!("{name}: {e}"))?;
                        Ok(Box::new(s) as Box<dyn Io>)
                    }
                })
                .await?
            } else {
                let tunnel = &tunnel;
                login(&hop, trust, limits, || {
                    let host = host.clone();
                    async move {
                        let s = tunnel.open(&host, port, limits.connect).await?;
                        Ok(Box::new(s) as Box<dyn Io>)
                    }
                })
                .await?
            };
            tunnel.hops.push((name, handle));
        }
        Ok(tunnel)
    }

    /// A stream to `host:port` from the last jump host.
    pub async fn open(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<ChannelStream<Msg>, String> {
        let (name, handle) = self.hops.last().expect("a tunnel has a jump host");
        let open = handle.channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0);
        let channel = tokio::time::timeout(timeout, open)
            .await
            .map_err(|_| format!("{name}: no channel to {host}:{port} in {timeout:?}"))?
            .map_err(|e| format!("{name}: no channel to {host}:{port}: {e}"))?;
        Ok(channel.into_stream())
    }

    /// True if a connection of the tunnel is closed.
    pub fn is_closed(&self) -> bool {
        self.hops.iter().any(|(_, h)| h.is_closed())
    }

    /// Closes the connections, the last jump host first.
    pub async fn close(&self) {
        for (_, h) in self.hops.iter().rev() {
            let _ = h.disconnect(Disconnect::ByApplication, "", "en").await;
        }
    }
}

/// A stream to `host:port` on a route: through the tunnel of the jump
/// hosts if the route has jump hosts, else through the proxy or directly.
pub(crate) async fn stream(
    route: &Route,
    tunnel: Option<&Tunnel>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Box<dyn Io + 'static>, String> {
    match tunnel {
        Some(t) => Ok(Box::new(t.open(host, port, timeout).await?)),
        None => Ok(Box::new(
            tcp(route.proxy.as_ref(), host, port, timeout).await?,
        )),
    }
}
