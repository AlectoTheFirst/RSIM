//! The SSH transport. It keeps one connection for each device and runs the
//! commands of a device on parallel exec channels of that connection.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, Preferred, cipher, kex, mac};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::trust::{Credentials, PinKind, Secret, TrustStore, host_port};
use crate::{BoxFuture, Device, Ssh, TransportError};

/// The algorithm sets of a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

impl Algorithms {
    fn preferred(self) -> Preferred {
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

/// The connection settings of a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SshProfile {
    pub algorithms: Algorithms,
    /// The largest number of exec channels open at one time on the
    /// connection.
    pub max_channels: usize,
}

impl Default for SshProfile {
    fn default() -> SshProfile {
        SshProfile {
            algorithms: Algorithms::Modern,
            max_channels: 8,
        }
    }
}

/// The limits of the SSH transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SshLimits {
    /// The time for the TCP connection, the key exchange and the
    /// authentication.
    pub connect_timeout: Duration,
    /// A connection with no traffic for this time is closed.
    pub idle_timeout: Duration,
    /// The largest output of one command. A larger output is an error.
    pub max_output: usize,
}

impl Default for SshLimits {
    fn default() -> SshLimits {
        SshLimits {
            connect_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(300),
            max_output: 256 << 20,
        }
    }
}

struct Client {
    trust: Arc<TrustStore>,
    address: String,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };
        let Ok(text) = key.to_openssh() else {
            return Ok(false);
        };
        let text: Vec<&str> = text.split_whitespace().take(2).collect();
        Ok(self
            .trust
            .check(PinKind::Ssh, &self.address, &text.join(" "))
            .is_ok())
    }
}

struct Conn {
    handle: Handle<Client>,
    channels: Arc<Semaphore>,
}

type Slot = Arc<tokio::sync::Mutex<Option<Arc<Conn>>>>;

/// An SSH transport over `russh`.
pub struct SshTransport {
    credentials: Arc<dyn Credentials>,
    trust: Arc<TrustStore>,
    limits: SshLimits,
    default_profile: SshProfile,
    profiles: HashMap<String, SshProfile>,
    slots: Mutex<HashMap<String, Slot>>,
}

enum ExecError {
    /// The channel did not open. A new connection can help.
    Channel(String),
    Transport(TransportError),
}

impl SshTransport {
    pub fn new(
        credentials: Arc<dyn Credentials>,
        trust: Arc<TrustStore>,
        limits: SshLimits,
    ) -> SshTransport {
        SshTransport {
            credentials,
            trust,
            limits,
            default_profile: SshProfile::default(),
            profiles: HashMap::new(),
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Sets the profile of the devices with no profile of their own.
    pub fn with_default_profile(mut self, profile: SshProfile) -> SshTransport {
        self.default_profile = profile;
        self
    }

    /// Sets the profile of a device.
    pub fn with_profile(mut self, device: &str, profile: SshProfile) -> SshTransport {
        self.profiles.insert(device.to_string(), profile);
        self
    }

    fn profile(&self, device: &Device) -> SshProfile {
        self.profiles
            .get(&device.id)
            .copied()
            .unwrap_or(self.default_profile)
    }

    /// Closes the connection of a device, if it has one.
    pub async fn close(&self, device: &str) {
        let slot = self
            .slots
            .lock()
            .expect("the lock is not poisoned")
            .remove(device);
        if let Some(slot) = slot
            && let Some(conn) = slot.lock().await.take()
        {
            let _ = conn
                .handle
                .disconnect(Disconnect::ByApplication, "", "en")
                .await;
        }
    }

    fn slot(&self, device: &Device) -> Slot {
        self.slots
            .lock()
            .expect("the lock is not poisoned")
            .entry(device.id.clone())
            .or_default()
            .clone()
    }

    async fn connection(&self, device: &Device) -> Result<Arc<Conn>, TransportError> {
        let slot = self.slot(device);
        let mut guard = slot.lock().await;
        if let Some(conn) = guard.as_ref()
            && !conn.handle.is_closed()
        {
            return Ok(conn.clone());
        }
        *guard = None;
        let conn = tokio::time::timeout(self.limits.connect_timeout, self.connect(device))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let conn = Arc::new(conn);
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn forget(&self, device: &Device, conn: &Arc<Conn>) {
        let slot = self.slot(device);
        let mut guard = slot.lock().await;
        if guard.as_ref().is_some_and(|c| Arc::ptr_eq(c, conn)) {
            *guard = None;
        }
    }

    async fn connect(&self, device: &Device) -> Result<Conn, TransportError> {
        let connect = |e: String| TransportError::Connect(e);
        let profile = self.profile(device);
        let credential = self.credentials.get(&device.credential).map_err(connect)?;
        let (host, port) = host_port(&device.address, 22).map_err(connect)?;
        let config = Arc::new(client::Config {
            preferred: profile.algorithms.preferred(),
            inactivity_timeout: Some(self.limits.idle_timeout),
            nodelay: true,
            ..client::Config::default()
        });
        let handler = Client {
            trust: self.trust.clone(),
            address: device.address.clone(),
        };
        let mut handle = client::connect(config, (host.as_str(), port), handler)
            .await
            .map_err(|e| match e {
                russh::Error::UnknownKey => connect(format!(
                    "the host key of {} does not match its pin",
                    device.address
                )),
                e => connect(e.to_string()),
            })?;
        let user = credential.user;
        let ok = match credential.secret {
            Secret::Password(password) => {
                let r = handle
                    .authenticate_password(user.clone(), password.clone())
                    .await
                    .map_err(|e| connect(e.to_string()))?;
                if r.success() {
                    true
                } else {
                    keyboard_interactive(&mut handle, &user, &password).await?
                }
            }
            Secret::Key { pem, passphrase } => {
                let key = russh::keys::decode_secret_key(&pem, passphrase.as_deref())
                    .map_err(|e| connect(format!("the private key does not decode: {e}")))?;
                let hash = handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|e| connect(e.to_string()))?
                    .flatten();
                let r: AuthResult = handle
                    .authenticate_publickey(
                        user.clone(),
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                    )
                    .await
                    .map_err(|e| connect(e.to_string()))?;
                r.success()
            }
            Secret::ApiKey(_) => {
                return Err(connect("an API key is not an SSH credential".into()));
            }
        };
        if !ok {
            return Err(connect(format!(
                "{} did not accept the credential of {user}",
                device.address
            )));
        }
        Ok(Conn {
            handle,
            channels: Arc::new(Semaphore::new(profile.max_channels.max(1))),
        })
    }

    async fn exec(
        &self,
        conn: &Conn,
        _permit: OwnedSemaphorePermit,
        command: &str,
    ) -> Result<Vec<u8>, ExecError> {
        let mut channel = conn
            .handle
            .channel_open_session()
            .await
            .map_err(|e| ExecError::Channel(e.to_string()))?;
        let failed = |e: String| ExecError::Transport(TransportError::Command(e));
        channel
            .exec(true, command)
            .await
            .map_err(|e| failed(e.to_string()))?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut status = None;
        let mut ended = false;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    if stdout.len() + data.len() > self.limits.max_output {
                        let _ = channel.close().await;
                        return Err(failed(format!(
                            "the output is larger than {} bytes",
                            self.limits.max_output
                        )));
                    }
                    stdout.extend_from_slice(&data);
                }
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    if stderr.len() < 4096 {
                        stderr.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Eof | ChannelMsg::Close => ended = true,
                ChannelMsg::Failure => {
                    return Err(failed("the device did not accept the exec request".into()));
                }
                _ => {}
            }
        }
        match status {
            Some(0) => Ok(stdout),
            None if ended => Ok(stdout),
            None => Err(failed(
                "the connection closed before the command ended".into(),
            )),
            Some(code) => {
                let text = String::from_utf8_lossy(&stderr);
                let text: String = text.trim().chars().take(512).collect();
                Err(failed(format!("exit status {code}: {text}")))
            }
        }
    }
}

async fn keyboard_interactive(
    handle: &mut Handle<Client>,
    user: &str,
    password: &str,
) -> Result<bool, TransportError> {
    let connect = |e: russh::Error| TransportError::Connect(e.to_string());
    let mut r = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await
        .map_err(connect)?;
    for _ in 0..4 {
        match r {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = prompts.iter().map(|_| password.to_string()).collect();
                r = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(connect)?;
            }
        }
    }
    Ok(false)
}

impl Ssh for SshTransport {
    fn run<'a>(
        &'a self,
        device: &'a Device,
        command: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let mut last = String::new();
            for _ in 0..2 {
                let conn = self.connection(device).await?;
                let permit = conn
                    .channels
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("the semaphore is not closed");
                match self.exec(&conn, permit, command).await {
                    Ok(out) => return Ok(out),
                    Err(ExecError::Transport(e)) => return Err(e),
                    Err(ExecError::Channel(e)) => {
                        self.forget(device, &conn).await;
                        last = e;
                    }
                }
            }
            Err(TransportError::Connect(format!(
                "no channel opens on {}: {last}",
                device.address
            )))
        })
    }
}
