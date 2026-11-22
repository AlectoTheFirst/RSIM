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
    /// The keys of an SSH agent at a Unix socket. With no socket, the
    /// socket is the value of `SSH_AUTH_SOCK`.
    Agent { socket: Option<PathBuf> },
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Secret::Password(_) => "Password(..)",
            Secret::Key { .. } => "Key(..)",
            Secret::ApiKey(_) => "ApiKey(..)",
            Secret::Agent { .. } => "Agent(..)",
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
                pins.insert(id.clone(), key.to_string());
                if let Some(path) = &self.path {
                    let mut text = String::new();
                    for ((k, a), v) in pins.iter() {
                        text.push_str(&format!("{} {a} {v}\n", k.name()));
                    }
                    if let Err(e) = write_atomic(path, text.as_bytes()) {
                        pins.remove(&id);
                        return Err(format!("{}: {e}", path.display()));
                    }
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

/// The address of a URL `<scheme>://<address>`, with or without a final `/`,
/// or the address itself when it is not a URL. A URL of another scheme, or
/// with a user, a path, a query or a fragment, is an error.
#[cfg(any(feature = "ssh", feature = "https"))]
pub(crate) fn plain_address<'a>(address: &'a str, scheme: &str) -> Result<&'a str, String> {
    let Some((given, rest)) = address.split_once("://") else {
        return Ok(address);
    };
    let head = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if !given.eq_ignore_ascii_case(scheme) {
        return Err(format!("the URL scheme {given} is not {scheme}"));
    }
    if head.contains('@') {
        return Err(format!("the {scheme} URL has a user"));
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if head.is_empty() {
        return Err(format!("the {scheme} URL has no host"));
    }
    if rest != head {
        return Err(format!(
            "the URL {scheme}://{head} has a path, a query or a fragment"
        ));
    }
    Ok(head)
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
    fn accept_new_keeps_no_pin_that_the_file_did_not_get() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("pins");
        let t = TrustStore::open(&path, PinPolicy::AcceptNew).unwrap();
        assert!(
            t.check(PinKind::Ssh, "192.0.2.1", "ssh-ed25519 AAAA")
                .is_err()
        );
        assert!(
            t.check(PinKind::Ssh, "192.0.2.1", "ssh-ed25519 AAAA")
                .is_err()
        );
        assert_eq!(t.get(PinKind::Ssh, "192.0.2.1"), None);

        std::fs::create_dir(dir.path().join("missing")).unwrap();
        t.check(PinKind::Ssh, "192.0.2.1", "ssh-ed25519 AAAA")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "ssh 192.0.2.1 ssh-ed25519 AAAA\n"
        );
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
    #[cfg(any(feature = "ssh", feature = "https"))]
    fn a_url_gives_its_address() {
        assert_eq!(plain_address("192.0.2.8", "https").unwrap(), "192.0.2.8");
        assert_eq!(
            plain_address("https://192.0.2.8", "https").unwrap(),
            "192.0.2.8"
        );
        assert_eq!(
            plain_address("HTTPS://192.0.2.8/", "https").unwrap(),
            "192.0.2.8"
        );
        assert_eq!(
            plain_address("https://unifi.example:8443", "https").unwrap(),
            "unifi.example:8443"
        );
        assert_eq!(
            plain_address("https://[2001:db8::8]:8443/", "https").unwrap(),
            "[2001:db8::8]:8443"
        );
        assert_eq!(plain_address("ssh://r1:2222", "ssh").unwrap(), "r1:2222");
        assert!(plain_address("http://192.0.2.8", "https").is_err());
        assert!(plain_address("https://192.0.2.8", "ssh").is_err());
        assert!(plain_address("https://192.0.2.8/manage", "https").is_err());
        assert!(plain_address("https://192.0.2.8?x=1", "https").is_err());
        assert!(plain_address("https://", "https").is_err());
        let e = plain_address("https://admin:hunter2@192.0.2.8", "https").unwrap_err();
        assert!(!e.contains("hunter2"));
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
