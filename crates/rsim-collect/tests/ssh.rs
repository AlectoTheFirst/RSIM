//! The SSH transport against an SSH server in the test process.

#![cfg(feature = "ssh")]

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::future::join_all;
use rsim_collect::ssh::{Algorithms, SshLimits, SshProfile, SshTransport};
use rsim_collect::{
    Credential, Device, MemoryCredentials, PinKind, PinPolicy, Secret, Ssh, TransportError,
    TrustStore, Vendor,
};
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Response, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Preferred, cipher, kex, mac};
use tokio::net::TcpListener;

#[derive(Default)]
struct Stats {
    connections: AtomicUsize,
    open: AtomicUsize,
    max_open: AtomicUsize,
}

#[derive(Clone)]
struct Server {
    stats: Arc<Stats>,
    client_key: Option<PublicKey>,
    password: Option<String>,
    password_method: bool,
}

impl russh::server::Handler for Server {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let ok = user == "collector" && self.client_key.as_ref() == Some(key.public_key);
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let ok = self.password_method
            && user == "collector"
            && self.password.as_deref() == Some(password);
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
                let answer = r.next().map(|b| String::from_utf8_lossy(&b).to_string());
                let ok = user == "collector" && answer.is_some() && answer == self.password;
                Ok(if ok { Auth::Accept } else { Auth::reject() })
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        if command == "bye" {
            return Err(russh::Error::Disconnect);
        }
        session.channel_success(channel)?;
        let handle = session.handle();
        let stats = self.stats.clone();
        tokio::spawn(async move {
            let n = stats.open.fetch_add(1, Ordering::SeqCst) + 1;
            stats.max_open.fetch_max(n, Ordering::SeqCst);
            let (out, err, code) = respond(&command).await;
            if !out.is_empty() {
                let _ = handle.data(channel, out).await;
            }
            if !err.is_empty() {
                let _ = handle.extended_data(channel, 1, err).await;
            }
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.eof(channel).await;
            stats.open.fetch_sub(1, Ordering::SeqCst);
            let _ = handle.close(channel).await;
        });
        Ok(())
    }
}

/// `sleep <ms> <text>` waits and prints the text, `big <n>` prints n bytes,
/// `fail` prints to stderr and exits with 3, and other commands print
/// themselves.
async fn respond(command: &str) -> (Vec<u8>, Vec<u8>, u32) {
    let mut words = command.splitn(3, ' ');
    match words.next() {
        Some("sleep") => {
            let ms: u64 = words.next().unwrap().parse().unwrap();
            tokio::time::sleep(Duration::from_millis(ms)).await;
            (words.next().unwrap_or("").as_bytes().to_vec(), vec![], 0)
        }
        Some("big") => {
            let n: usize = words.next().unwrap().parse().unwrap();
            (vec![b'x'; n], vec![], 0)
        }
        Some("fail") => (vec![], b"bad command\n".to_vec(), 3),
        _ => (command.as_bytes().to_vec(), vec![], 0),
    }
}

struct Fixture {
    address: String,
    host_key: String,
    stats: Arc<Stats>,
}

fn openssh(key: &PublicKey) -> String {
    let text = key.to_openssh().unwrap();
    text.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

async fn serve(server: Server, preferred: Preferred) -> Fixture {
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let host_key = openssh(host.public_key());
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::PublicKey);
    methods.push(MethodKind::Password);
    methods.push(MethodKind::KeyboardInteractive);
    let config = Arc::new(russh::server::Config {
        keys: vec![host],
        preferred,
        methods,
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let stats = server.stats.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            server.stats.connections.fetch_add(1, Ordering::SeqCst);
            let config = config.clone();
            let handler = server.clone();
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    Fixture {
        address,
        host_key,
        stats,
    }
}

fn device(address: &str) -> Device {
    Device {
        id: "r1".into(),
        vendor: Vendor::Vyos,
        address: address.into(),
        credential: "lab".into(),
        site: None,
    }
}

fn credentials(secret: Secret) -> Arc<MemoryCredentials> {
    let mut c = MemoryCredentials::new();
    c.insert(
        "lab",
        Credential {
            user: "collector".into(),
            secret,
        },
    );
    Arc::new(c)
}

fn pinned(f: &Fixture) -> Arc<TrustStore> {
    let t = TrustStore::memory(PinPolicy::Strict);
    t.pin(PinKind::Ssh, &f.address, &f.host_key);
    Arc::new(t)
}

fn key_server() -> (Server, Secret) {
    let client = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let pem = client
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap();
    let server = Server {
        stats: Arc::default(),
        client_key: Some(client.public_key().clone()),
        password: None,
        password_method: true,
    };
    (
        server,
        Secret::Key {
            pem: pem.to_string(),
            passphrase: None,
        },
    )
}

#[tokio::test]
async fn the_commands_of_a_device_share_one_connection() {
    let (server, secret) = key_server();
    let f = serve(server, Preferred::default()).await;
    let t = SshTransport::new(credentials(secret), pinned(&f), SshLimits::default());
    let d = device(&f.address);

    let commands: Vec<String> = (0..8).map(|i| format!("sleep 100 out{i}")).collect();
    let outs = join_all(commands.iter().map(|c| t.run(&d, c))).await;
    for (i, out) in outs.into_iter().enumerate() {
        assert_eq!(out.unwrap(), format!("out{i}").into_bytes());
    }
    assert_eq!(t.run(&d, "show version").await.unwrap(), b"show version");
    assert_eq!(f.stats.connections.load(Ordering::SeqCst), 1);
    assert_eq!(f.stats.max_open.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn the_profile_limits_the_open_channels() {
    let (server, secret) = key_server();
    let f = serve(server, Preferred::default()).await;
    let profile = SshProfile {
        max_channels: 2,
        ..SshProfile::default()
    };
    let t = SshTransport::new(credentials(secret), pinned(&f), SshLimits::default())
        .with_profile("r1", profile);
    let d = device(&f.address);
    let commands: Vec<String> = (0..6).map(|i| format!("sleep 50 out{i}")).collect();
    let outs = join_all(commands.iter().map(|c| t.run(&d, c))).await;
    assert!(outs.iter().all(Result::is_ok));
    assert_eq!(f.stats.max_open.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_password_works_with_the_password_and_keyboard_interactive_methods() {
    for password_method in [true, false] {
        let server = Server {
            stats: Arc::default(),
            client_key: None,
            password: Some("s3cret".into()),
            password_method,
        };
        let f = serve(server, Preferred::default()).await;
        let t = SshTransport::new(
            credentials(Secret::Password("s3cret".into())),
            pinned(&f),
            SshLimits::default(),
        );
        assert_eq!(
            t.run(&device(&f.address), "uptime").await.unwrap(),
            b"uptime"
        );

        let wrong = SshTransport::new(
            credentials(Secret::Password("other".into())),
            pinned(&f),
            SshLimits::default(),
        );
        let e = wrong.run(&device(&f.address), "uptime").await.unwrap_err();
        assert!(
            matches!(&e, TransportError::Connect(m) if m.contains("did not accept")),
            "{e}"
        );
    }
}

#[tokio::test]
async fn a_host_key_that_is_not_the_pin_is_rejected() {
    let (server, secret) = key_server();
    let f = serve(server, Preferred::default()).await;
    let other = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let trust = TrustStore::memory(PinPolicy::Strict);
    trust.pin(PinKind::Ssh, &f.address, &openssh(other.public_key()));
    let t = SshTransport::new(
        credentials(secret.clone()),
        Arc::new(trust),
        SshLimits::default(),
    );
    let e = t.run(&device(&f.address), "uptime").await.unwrap_err();
    assert!(
        matches!(&e, TransportError::Connect(m) if m.contains("pin")),
        "{e}"
    );

    let unknown = SshTransport::new(
        credentials(secret.clone()),
        Arc::new(TrustStore::memory(PinPolicy::Strict)),
        SshLimits::default(),
    );
    assert!(unknown.run(&device(&f.address), "uptime").await.is_err());

    let tofu = Arc::new(TrustStore::memory(PinPolicy::AcceptNew));
    let t = SshTransport::new(credentials(secret), tofu.clone(), SshLimits::default());
    assert!(t.run(&device(&f.address), "uptime").await.is_ok());
    assert_eq!(tofu.get(PinKind::Ssh, &f.address), Some(f.host_key.clone()));
}

#[tokio::test]
async fn a_failed_command_gives_its_status_and_stderr() {
    let (server, secret) = key_server();
    let f = serve(server, Preferred::default()).await;
    let limits = SshLimits {
        max_output: 1000,
        ..SshLimits::default()
    };
    let t = SshTransport::new(credentials(secret), pinned(&f), limits);
    let d = device(&f.address);
    let e = t.run(&d, "fail").await.unwrap_err();
    assert_eq!(
        e,
        TransportError::Command("exit status 3: bad command".into())
    );
    let e = t.run(&d, "big 5000").await.unwrap_err();
    assert!(
        matches!(&e, TransportError::Command(m) if m.contains("larger")),
        "{e}"
    );
    assert_eq!(t.run(&d, "big 1000").await.unwrap().len(), 1000);
}

#[tokio::test]
async fn a_closed_connection_is_opened_again() {
    let (server, secret) = key_server();
    let f = serve(server, Preferred::default()).await;
    let t = SshTransport::new(credentials(secret), pinned(&f), SshLimits::default());
    let d = device(&f.address);
    assert!(t.run(&d, "one").await.is_ok());
    assert!(t.run(&d, "bye").await.is_err());
    assert_eq!(t.run(&d, "two").await.unwrap(), b"two");
    assert_eq!(f.stats.connections.load(Ordering::SeqCst), 2);

    t.close("r1").await;
    assert_eq!(t.run(&d, "three").await.unwrap(), b"three");
    assert_eq!(f.stats.connections.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_legacy_device_needs_the_legacy_profile() {
    let (server, secret) = key_server();
    let legacy = Preferred {
        kex: Cow::Owned(vec![kex::DH_G14_SHA1]),
        cipher: Cow::Owned(vec![cipher::AES_128_CBC]),
        mac: Cow::Owned(vec![mac::HMAC_SHA1]),
        ..Preferred::default()
    };
    let f = serve(server, legacy).await;
    let d = device(&f.address);
    let modern = SshTransport::new(
        credentials(secret.clone()),
        pinned(&f),
        SshLimits::default(),
    );
    assert!(modern.run(&d, "uptime").await.is_err());

    let profile = SshProfile {
        algorithms: Algorithms::Legacy,
        ..SshProfile::default()
    };
    let t = SshTransport::new(credentials(secret), pinned(&f), SshLimits::default())
        .with_profile("r1", profile);
    assert_eq!(t.run(&d, "uptime").await.unwrap(), b"uptime");
}

#[tokio::test]
async fn a_large_output_arrives_intact() {
    let (server, secret) = key_server();
    let f = serve(server, Preferred::default()).await;
    let t = SshTransport::new(credentials(secret), pinned(&f), SshLimits::default());
    let out = t.run(&device(&f.address), "big 3000000").await.unwrap();
    assert_eq!(out.len(), 3_000_000);
    assert!(out.iter().all(|b| *b == b'x'));
}
