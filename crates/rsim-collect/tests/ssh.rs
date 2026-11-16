//! The SSH transport against an SSH server in the test process.

#![cfg(feature = "ssh")]

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::future::join_all;
use rsim_collect::cli::CliRules;
use rsim_collect::ssh::{Algorithms, CommandMode, SshLimits, SshProfile, SshTransport};
use rsim_collect::{
    Credential, Device, Jump, MemoryCredentials, PinKind, PinPolicy, Proxy, RawSection, Route,
    Secret, SectionSpec, Ssh, TransportError, TrustStore, Vendor, fetch_sections,
};
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Response, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Preferred, cipher, kex, mac};
use tokio::net::TcpListener;

#[path = "support/route.rs"]
mod route;

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
    /// The bytes of the shell since the last line end.
    line: Vec<u8>,
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

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    /// The shell prints a banner that ends with a line of `#`, which has
    /// the form of a prompt, and the prompt `r1#` a moment later.
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(
            channel,
            &b"\x1b[2JAuthorized use only\r\nr1# is in the banner\r\n#####\r\n"[..],
        )?;
        let handle = session.handle();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = handle.data(channel, &b"r1#"[..]).await;
        });
        Ok(())
    }

    /// Each line of the shell gets its echo, its answer and the prompt.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        for &b in data {
            if b != b'\n' && b != b'\r' {
                self.line.push(b);
                continue;
            }
            let line = String::from_utf8_lossy(&std::mem::take(&mut self.line)).to_string();
            let mut out = Vec::new();
            if !line.is_empty() {
                out.extend_from_slice(format!("{line}\r\n").as_bytes());
                out.extend_from_slice(&shell_answer(&line));
            }
            out.extend_from_slice(b"\r\nr1#");
            session.data(channel, out)?;
        }
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

/// The answer of the shell to a command.
fn shell_answer(command: &str) -> Vec<u8> {
    match command {
        "terminal length 0" => Vec::new(),
        "show color" => b"\x1b[1;32mgreen\x1b[0m\r\ndescription r1# here\r\n".to_vec(),
        "show big" => (0..3000)
            .map(|i| format!("line {i}\r\n"))
            .collect::<String>()
            .into_bytes(),
        "bad" => b"% Invalid input detected at '^' marker.\r\n".to_vec(),
        c => format!("{c}\r\n").into_bytes(),
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
        route: Default::default(),
    }
}

fn password_server() -> Server {
    Server {
        stats: Arc::default(),
        client_key: None,
        password: Some("s3cret".into()),
        password_method: true,
        line: Vec::new(),
    }
}

/// The device credential `lab` and the jump host credential `hop`.
fn route_credentials() -> Arc<MemoryCredentials> {
    let mut c = MemoryCredentials::new();
    c.insert(
        "lab",
        Credential {
            user: "collector".into(),
            secret: Secret::Password("s3cret".into()),
        },
    );
    c.insert(
        "hop",
        Credential {
            user: "hop".into(),
            secret: Secret::Password("hop-pass".into()),
        },
    );
    Arc::new(c)
}

fn jump(address: &str) -> Jump {
    Jump {
        address: address.into(),
        credential: "hop".into(),
        algorithms: Algorithms::Modern,
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
        line: Vec::new(),
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
            line: Vec::new(),
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

#[tokio::test]
async fn a_shell_reads_each_answer_up_to_the_prompt() {
    let f = serve(password_server(), Preferred::default()).await;
    let profile = SshProfile {
        mode: CommandMode::Shell,
        shell_setup: vec!["terminal length 0".into()],
        ..SshProfile::default()
    };
    let t = SshTransport::new(
        credentials(Secret::Password("s3cret".into())),
        pinned(&f),
        SshLimits::default(),
    )
    .with_profile("r1", profile);
    let d = device(&f.address);
    assert!(!t.banner_each_command(&d));
    let color = t.run(&d, "show color").await.unwrap();
    assert_eq!(color, b"green\ndescription r1# here\n");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let runs = join_all((0..3).map(|_| t.run(&d, "show big"))).await;
    for big in runs {
        let big = String::from_utf8(big.unwrap()).unwrap();
        assert_eq!(big.lines().count(), 3000);
        assert_eq!(big.lines().last(), Some("line 2999"));
    }
    let bad = t.run(&d, "bad").await;
    let spec = SectionSpec {
        name: "bad",
        command: "bad".into(),
        class: rsim_store::Class::Observation,
        format: rsim_store::Format::Text,
        volatile: &[],
        extracts: &[],
        keep: &[],
        optional: true,
    };
    let mut sections = vec![RawSection { spec, result: bad }];
    CliRules::CISCO.apply(&mut sections, t.banner_each_command(&d));
    assert!(sections[0].absent());
    assert_eq!(f.stats.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_connection_mode_logs_in_for_each_command() {
    let f = serve(password_server(), Preferred::default()).await;
    let profile = SshProfile {
        mode: CommandMode::Connection,
        ..SshProfile::default()
    };
    let t = SshTransport::new(
        credentials(Secret::Password("s3cret".into())),
        pinned(&f),
        SshLimits::default(),
    )
    .with_profile("r1", profile);
    let d = device(&f.address);
    let outs = join_all(["a", "b", "c"].map(|c| t.run(&d, c))).await;
    let outs: Vec<Vec<u8>> = outs.into_iter().map(Result::unwrap).collect();
    assert_eq!(outs, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    assert_eq!(f.stats.connections.load(Ordering::SeqCst), 3);
    assert_eq!(f.stats.max_open.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_jump_host_never_gets_the_device_credential() {
    let f = serve(password_server(), Preferred::default()).await;
    let b = route::bastion("hop", "hop-pass").await;
    let trust = TrustStore::memory(PinPolicy::Strict);
    trust.pin(PinKind::Ssh, b.address(), &b.host_key);
    trust.pin(
        PinKind::Ssh,
        &format!("{}>{}", b.address(), f.address),
        &f.host_key,
    );
    let t = SshTransport::new(route_credentials(), Arc::new(trust), SshLimits::default());
    let mut d = device(&f.address);
    d.route = Route {
        proxy: None,
        jumps: vec![jump(b.address())],
    };
    assert_eq!(t.run(&d, "one").await.unwrap(), b"one");
    assert_eq!(t.run(&d, "two").await.unwrap(), b"two");
    assert_eq!(b.forwarder.forwards(), 1);
    let log = b.log();
    assert_eq!(log, ["password hop hop-pass"]);
    assert!(
        log.iter()
            .all(|l| !l.contains("collector") && !l.contains("s3cret"))
    );
}

#[tokio::test]
async fn a_chain_of_2_jump_hosts_reaches_the_device() {
    let f = serve(password_server(), Preferred::default()).await;
    let b1 = route::bastion("hop", "hop-pass").await;
    let b2 = route::bastion("hop", "hop-pass").await;
    let trust = TrustStore::memory(PinPolicy::AcceptNew);
    let trust = Arc::new(trust);
    let t = SshTransport::new(route_credentials(), trust.clone(), SshLimits::default());
    let mut d = device(&f.address);
    d.route = Route {
        proxy: None,
        jumps: vec![jump(b1.address()), jump(b2.address())],
    };
    assert_eq!(t.run(&d, "one").await.unwrap(), b"one");
    t.close("r1").await;
    assert_eq!(t.run(&d, "two").await.unwrap(), b"two");
    assert_eq!(b1.forwarder.forwards(), 2);
    assert_eq!(b2.forwarder.forwards(), 2);
    let chain = format!("{}>{}", b1.address(), b2.address());
    assert_eq!(
        trust.get(PinKind::Ssh, b1.address()),
        Some(b1.host_key.clone())
    );
    assert_eq!(trust.get(PinKind::Ssh, &chain), Some(b2.host_key.clone()));
    assert_eq!(
        trust.get(PinKind::Ssh, &format!("{chain}>{}", f.address)),
        Some(f.host_key.clone())
    );
    assert_eq!(trust.get(PinKind::Ssh, &f.address), None);
}

#[tokio::test]
async fn an_error_names_the_hop_that_failed() {
    let f = serve(password_server(), Preferred::default()).await;
    let b = route::bastion("hop", "hop-pass").await;
    let trust = TrustStore::memory(PinPolicy::Strict);
    trust.pin(PinKind::Ssh, b.address(), &f.host_key);
    let t = SshTransport::new(route_credentials(), Arc::new(trust), SshLimits::default());
    let mut d = device(&f.address);
    d.route.jumps = vec![jump(b.address())];
    let Err(TransportError::Connect(e)) = t.run(&d, "x").await else {
        panic!("a wrong bastion key is a connect error");
    };
    assert!(e.starts_with(&format!("bastion {}", b.address())), "{e}");

    let trust = TrustStore::memory(PinPolicy::AcceptNew);
    let mut creds = MemoryCredentials::new();
    creds.insert(
        "lab",
        Credential {
            user: "collector".into(),
            secret: Secret::Password("wrong".into()),
        },
    );
    creds.insert(
        "hop",
        Credential {
            user: "hop".into(),
            secret: Secret::Password("hop-pass".into()),
        },
    );
    let t = SshTransport::new(Arc::new(creds), Arc::new(trust), SshLimits::default());
    let Err(TransportError::Connect(e)) = t.run(&d, "x").await else {
        panic!("a wrong device password is a connect error");
    };
    assert!(e.starts_with(&format!("device {}", f.address)), "{e}");
    assert!(b.log().iter().all(|l| !l.contains("wrong")));
}

#[tokio::test]
async fn a_proxy_carries_the_first_connection() {
    let f = serve(password_server(), Preferred::default()).await;
    let http = route::http_proxy(Some("pu:pp")).await;
    let socks = route::socks5_proxy().await;
    for (url, forwards) in [
        (format!("http://pu:pp@{}", http.address), &http.forwards),
        (format!("socks5://{}", socks.address), &socks.forwards),
    ] {
        let t = SshTransport::new(
            credentials(Secret::Password("s3cret".into())),
            pinned(&f),
            SshLimits::default(),
        );
        let mut d = device(&f.address);
        d.route.proxy = Some(Proxy::parse(&url).unwrap());
        assert_eq!(t.run(&d, "via").await.unwrap(), b"via");
        assert_eq!(forwards.load(Ordering::SeqCst), 1, "{url}");
    }
    let t = SshTransport::new(
        credentials(Secret::Password("s3cret".into())),
        pinned(&f),
        SshLimits::default(),
    );
    let mut d = device(&f.address);
    d.route.proxy = Some(Proxy::parse(&format!("http://pu:bad@{}", http.address)).unwrap());
    let Err(TransportError::Connect(e)) = t.run(&d, "x").await else {
        panic!("a refused proxy login is a connect error");
    };
    assert!(
        e.contains(&format!("proxy {}", http.address)) && e.contains("407"),
        "{e}"
    );
    assert!(!e.contains("bad"), "{e}");
}

#[tokio::test]
async fn a_jump_host_behind_a_proxy() {
    let f = serve(password_server(), Preferred::default()).await;
    let b = route::bastion("hop", "hop-pass").await;
    let socks = route::socks5_proxy().await;
    let t = SshTransport::new(
        route_credentials(),
        Arc::new(TrustStore::memory(PinPolicy::AcceptNew)),
        SshLimits::default(),
    );
    let mut d = device(&f.address);
    d.route = Route {
        proxy: Some(Proxy::parse(&format!("socks5://{}", socks.address)).unwrap()),
        jumps: vec![jump(b.address())],
    };
    assert_eq!(t.run(&d, "x").await.unwrap(), b"x");
    assert_eq!(socks.forwards.load(Ordering::SeqCst), 1);
    assert_eq!(b.forwarder.forwards(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn an_agent_key_logs_in() {
    use russh::keys::agent::client::AgentClient;

    #[derive(Clone)]
    struct Agent;
    impl russh::keys::agent::server::Agent for Agent {}

    let (server, secret) = key_server();
    let Secret::Key { pem, .. } = secret else {
        unreachable!()
    };
    let key = russh::keys::decode_secret_key(&pem, None).unwrap();
    let f = serve(server, Preferred::default()).await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let incoming = futures_util::stream::unfold(listener, |l| async move {
        let r = l.accept().await.map(|(s, _)| s);
        Some((r, l))
    });
    tokio::spawn(russh::keys::agent::server::serve(Box::pin(incoming), Agent));
    let mut client = AgentClient::connect_uds(&socket).await.unwrap();
    client.add_identity(&key, &[]).await.unwrap();
    let t = SshTransport::new(
        credentials(Secret::Agent {
            socket: Some(socket.clone()),
        }),
        pinned(&f),
        SshLimits::default(),
    );
    assert_eq!(t.run(&device(&f.address), "agent").await.unwrap(), b"agent");
}

#[tokio::test]
async fn an_idle_connection_is_closed() {
    let f = serve(password_server(), Preferred::default()).await;
    let limits = SshLimits {
        idle_timeout: Duration::from_millis(300),
        ..SshLimits::default()
    };
    let t = SshTransport::new(
        credentials(Secret::Password("s3cret".into())),
        pinned(&f),
        limits,
    );
    let d = device(&f.address);
    t.run(&d, "a").await.unwrap();
    t.run(&d, "b").await.unwrap();
    assert_eq!(f.stats.connections.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(1600)).await;
    t.run(&d, "c").await.unwrap();
    assert_eq!(f.stats.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_host_that_closes_before_the_login_gets_one_more_try() {
    let f = serve(password_server(), Preferred::default()).await;
    let flaky = route::flaky(f.address.clone()).await;
    let trust = TrustStore::memory(PinPolicy::Strict);
    trust.pin(PinKind::Ssh, &flaky.address, &f.host_key);
    let t = SshTransport::new(
        credentials(Secret::Password("s3cret".into())),
        Arc::new(trust),
        SshLimits::default(),
    );
    assert_eq!(t.run(&device(&flaky.address), "x").await.unwrap(), b"x");
    assert_eq!(flaky.forwards(), 1);
}

#[tokio::test]
async fn serial_commands_each_get_the_full_time_limit() {
    let f = serve(password_server(), Preferred::default()).await;
    let profile = SshProfile {
        mode: CommandMode::Connection,
        ..SshProfile::default()
    };
    let t = SshTransport::new(
        credentials(Secret::Password("s3cret".into())),
        pinned(&f),
        SshLimits::default(),
    )
    .with_profile("r1", profile);
    let d = device(&f.address);
    assert!(t.serial(&d));
    let specs: Vec<SectionSpec> = ["a", "b", "c", "d"]
        .into_iter()
        .map(|n| SectionSpec {
            name: n,
            command: format!("sleep 400 {n}"),
            class: rsim_store::Class::Observation,
            format: rsim_store::Format::Text,
            volatile: &[],
            extracts: &[],
            keep: &[],
            optional: false,
        })
        .collect();
    let out = fetch_sections(specs, Duration::from_secs(1), t.serial(&d), |c| {
        let t = &t;
        let d = &d;
        Box::pin(async move { t.run(d, &c).await })
    })
    .await;
    let got: Vec<Vec<u8>> = out.into_iter().map(|s| s.result.unwrap()).collect();
    assert_eq!(
        got,
        [b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
    );
}
