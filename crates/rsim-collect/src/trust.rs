//! Credentials and the pinned keys of the devices.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The secret of a credential.
#[derive(Clone, PartialEq, Eq)]
pub enum Secret {
    /// A password. SSH tries the password method and then the
    /// keyboard-interactive method with the same password.
    Password(String),
    /// A private key in the OpenSSH format or the PEM format, with its
    /// passphrase.
    Key {
        pem: String,
        passphrase: Option<String>,
    },
    /// An API key that HTTPS sends in the `X-API-KEY` header.
    ApiKey(String),
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Secret::Password(_) => "Password(..)",
            Secret::Key { .. } => "Key(..)",
            Secret::ApiKey(_) => "ApiKey(..)",
        })
    }
}

/// A user name with its secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub user: String,
    pub secret: Secret,
}

/// Gives the credential for the credential name of a device.
pub trait Credentials: Send + Sync {
    fn get(&self, name: &str) -> Result<Credential, String>;
}

/// Credentials in memory.
#[derive(Debug, Default)]
pub struct MemoryCredentials(HashMap<String, Credential>);

impl MemoryCredentials {
    pub fn new() -> MemoryCredentials {
        MemoryCredentials::default()
    }

    pub fn insert(&mut self, name: &str, credential: Credential) {
        self.0.insert(name.to_string(), credential);
    }
}

impl Credentials for MemoryCredentials {
    fn get(&self, name: &str) -> Result<Credential, String> {
        self.0
            .get(name)
            .cloned()
            .ok_or_else(|| format!("no credential is named {name}"))
    }
}

/// The kind of a pinned key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PinKind {
    /// An SSH host key in the OpenSSH public key form, for example
    /// `ssh-ed25519 AAAA...`.
    Ssh,
    /// The SHA-256 of the DER form of the TLS certificate of the server, in
    /// lower-case hex.
    Tls,
}

impl PinKind {
    fn name(self) -> &'static str {
        match self {
            PinKind::Ssh => "ssh",
            PinKind::Tls => "tls",
        }
    }

    fn parse(s: &str) -> Option<PinKind> {
        match s {
            "ssh" => Some(PinKind::Ssh),
            "tls" => Some(PinKind::Tls),
            _ => None,
        }
    }
}

/// What the trust store does with a key of an address that has no pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinPolicy {
    /// The key is rejected.
    Strict,
    /// The key is pinned at first contact.
    AcceptNew,
}

/// The pinned keys of the devices, by kind and address. A key that differs
/// from its pin is always rejected.
///
/// The file form has one pin on each line: the kind, the address and the
/// key, separated by spaces. An empty line and a line that starts with `#`
/// are ignored.
#[derive(Debug)]
pub struct TrustStore {
    policy: PinPolicy,
    path: Option<PathBuf>,
    pins: Mutex<BTreeMap<(PinKind, String), String>>,
}

impl TrustStore {
    /// A trust store in memory.
    pub fn memory(policy: PinPolicy) -> TrustStore {
        TrustStore {
            policy,
            path: None,
            pins: Mutex::new(BTreeMap::new()),
        }
    }

    /// A trust store in a file. A file that does not exist is an empty
    /// store. A new pin is written to the file before the key is accepted.
    pub fn open(path: &Path, policy: PinPolicy) -> Result<TrustStore, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let store = TrustStore {
            policy,
            path: Some(path.to_path_buf()),
            pins: Mutex::new(parse(&text).map_err(|e| format!("{}: {e}", path.display()))?),
        };
        Ok(store)
    }

    /// Pins a key. An earlier pin of the same kind and address is replaced.
    pub fn pin(&self, kind: PinKind, address: &str, key: &str) {
        self.lock()
            .insert((kind, address.to_string()), key.to_string());
    }

    /// The pin of a kind and address.
    pub fn get(&self, kind: PinKind, address: &str) -> Option<String> {
        self.lock().get(&(kind, address.to_string())).cloned()
    }

    /// The store in its file form.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for ((kind, address), key) in self.lock().iter() {
            out.push_str(&format!("{} {address} {key}\n", kind.name()));
        }
        out
    }

    /// Accepts the key if it is the pin of the address. With
    /// [`PinPolicy::AcceptNew`], it also accepts and pins the key of an
    /// address with no pin.
    pub fn check(&self, kind: PinKind, address: &str, key: &str) -> Result<(), String> {
        let mut pins = self.lock();
        let id = (kind, address.to_string());
        match pins.get(&id) {
            Some(pin) if pin == key => Ok(()),
            Some(pin) => Err(format!(
                "the {} key of {address} is {key}, and the pin is {pin}",
                kind.name()
            )),
            None if self.policy == PinPolicy::Strict => Err(format!(
                "the {} key of {address} has no pin: {key}",
                kind.name()
            )),
            None => {
                pins.insert(id, key.to_string());
                if let Some(path) = &self.path {
                    let mut text = String::new();
                    for ((k, a), v) in pins.iter() {
                        text.push_str(&format!("{} {a} {v}\n", k.name()));
                    }
                    write_atomic(path, text.as_bytes())
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                }
                Ok(())
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<(PinKind, String), String>> {
        self.pins.lock().expect("the lock is not poisoned")
    }
}

fn parse(text: &str) -> Result<BTreeMap<(PinKind, String), String>, String> {
    let mut pins = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(3, ' ');
        let (Some(kind), Some(address), Some(key)) = (it.next(), it.next(), it.next()) else {
            return Err(format!("line {} has no kind, address and key", i + 1));
        };
        let kind = PinKind::parse(kind)
            .ok_or_else(|| format!("line {}: {kind} is not ssh or tls", i + 1))?;
        pins.insert((kind, address.to_string()), key.trim().to_string());
    }
    Ok(pins)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// The host and the port of an address. The address is a host name, an IP
/// address, `host:port`, or `[ipv6]:port`.
#[cfg(any(feature = "ssh", feature = "https"))]
pub(crate) fn host_port(address: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return Ok((ip.to_string(), default_port));
    }
    if let Some(rest) = address.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("{address} has no closing bracket"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("{address} has a bad port"))?,
            None if tail.is_empty() => default_port,
            None => return Err(format!("{address} is not a valid address")),
        };
        return Ok((host.to_string(), port));
    }
    match address.rsplit_once(':') {
        Some((host, port)) => Ok((
            host.to_string(),
            port.parse()
                .map_err(|_| format!("{address} has a bad port"))?,
        )),
        None => Ok((address.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_accepts_its_key_and_rejects_another() {
        let t = TrustStore::memory(PinPolicy::Strict);
        assert!(
            t.check(PinKind::Ssh, "192.0.2.1", "ssh-ed25519 AAAA")
                .is_err()
        );
        t.pin(PinKind::Ssh, "192.0.2.1", "ssh-ed25519 AAAA");
        assert!(
            t.check(PinKind::Ssh, "192.0.2.1", "ssh-ed25519 AAAA")
                .is_ok()
        );
        assert!(
            t.check(PinKind::Ssh, "192.0.2.1", "ssh-ed25519 BBBB")
                .is_err()
        );
        assert!(
            t.check(PinKind::Tls, "192.0.2.1", "ssh-ed25519 AAAA")
                .is_err()
        );
    }

    #[test]
    fn accept_new_pins_the_first_key_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins");
        let t = TrustStore::open(&path, PinPolicy::AcceptNew).unwrap();
        t.check(PinKind::Tls, "unifi.example:8443", "ab12").unwrap();
        assert!(t.check(PinKind::Tls, "unifi.example:8443", "cd34").is_err());

        let again = TrustStore::open(&path, PinPolicy::Strict).unwrap();
        assert_eq!(
            again.get(PinKind::Tls, "unifi.example:8443").as_deref(),
            Some("ab12")
        );
        assert_eq!(again.to_text(), "tls unifi.example:8443 ab12\n");
    }

    #[test]
    fn a_bad_line_is_an_error() {
        assert!(parse("ssh 192.0.2.1\n").is_err());
        assert!(parse("ftp 192.0.2.1 x\n").is_err());
        assert_eq!(parse("# c\n\nssh h k e y\n").unwrap().len(), 1);
    }

    #[test]
    #[cfg(any(feature = "ssh", feature = "https"))]
    fn addresses_give_host_and_port() {
        assert_eq!(
            host_port("192.0.2.1", 22).unwrap(),
            ("192.0.2.1".into(), 22)
        );
        assert_eq!(host_port("r1:2222", 22).unwrap(), ("r1".into(), 2222));
        assert_eq!(
            host_port("2001:db8::1", 22).unwrap(),
            ("2001:db8::1".into(), 22)
        );
        assert_eq!(
            host_port("[2001:db8::1]:830", 22).unwrap(),
            ("2001:db8::1".into(), 830)
        );
        assert_eq!(
            host_port("[2001:db8::1]", 443).unwrap(),
            ("2001:db8::1".into(), 443)
        );
        assert!(host_port("r1:x", 22).is_err());
    }

    #[test]
    fn debug_hides_the_secret() {
        let c = Credential {
            user: "u".into(),
            secret: Secret::Password("hunter2".into()),
        };
        assert!(!format!("{c:?}").contains("hunter2"));
    }
}
