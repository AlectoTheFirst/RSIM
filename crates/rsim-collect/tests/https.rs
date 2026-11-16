//! The HTTPS transport against a UniFi-like HTTPS server in the test process.

#![cfg(feature = "https")]

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::future::join_all;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use rsim_collect::https::{
    ClientCert, HttpsLimits, HttpsProfile, HttpsTransport, TlsTrust, certificate_pin,
};
use rsim_collect::{
    Algorithms, Credential, Device, Https, Jump, MemoryCredentials, PinKind, PinPolicy, Proxy,
    Secret, TransportError, TrustStore, Vendor,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[path = "support/route.rs"]
mod route;

#[derive(Default)]
struct State {
    connections: AtomicUsize,
    logins: AtomicUsize,
    token: Mutex<Option<String>>,
}

impl State {
    fn expire(&self) {
        *self.token.lock().unwrap() = None;
    }
}

fn reply(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(body.into()))
        .unwrap()
}

async fn handle(state: Arc<State>, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    if path == "/api/auth/login" {
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if v["username"] != "collector" || v["password"] != "s3cret" {
            return reply(StatusCode::UNAUTHORIZED, "{}");
        }
        let n = state.logins.fetch_add(1, Ordering::SeqCst) + 1;
        let token = format!("tok{n}");
        *state.token.lock().unwrap() = Some(token.clone());
        return Response::builder()
            .header(
                header::SET_COOKIE,
                format!("TOKEN={token}; Path=/; HttpOnly"),
            )
            .header("x-csrf-token", format!("csrf-{token}"))
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
    }
    let api_key = headers.get("x-api-key").is_some_and(|v| v == "key1");
    let token = state.token.lock().unwrap().clone();
    let session = token.is_some_and(|t| {
        let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
        let csrf = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
        cookie == Some(&format!("TOKEN={t}")) && csrf == Some(&format!("csrf-{t}"))
    });
    if !api_key && !session {
        return reply(StatusCode::UNAUTHORIZED, "{}");
    }
    match path.as_str() {
        "/big" => reply(StatusCode::OK, vec![b'x'; 5000]),
        "/missing" => reply(StatusCode::NOT_FOUND, "{}"),
        _ => reply(StatusCode::OK, format!("{{\"path\":\"{path}\"}}")),
    }
}

struct Fixture {
    address: String,
    pin: String,
    state: Arc<State>,
}

async fn serve(versions: &[&'static rustls::SupportedProtocolVersion]) -> Fixture {
    let ck =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der: CertificateDer<'static> = ck.cert.der().clone();
    let pin = certificate_pin(&der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der], key)
    .unwrap();
    let (address, state) = serve_config(config).await;
    Fixture {
        address,
        pin,
        state,
    }
}

/// Serves the test API with a TLS server configuration.
async fn serve_config(config: rustls::ServerConfig) -> (String, Arc<State>) {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let state = Arc::new(State::default());
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            st.connections.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let st = st.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |req| {
                    let st = st.clone();
                    async move { Ok::<_, Infallible>(handle(st, req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (address, state)
}

fn pem(label: &str, der: &[u8]) -> String {
    let b = route::base64(der);
    let lines: Vec<&str> = b
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// A test CA. `leaf` makes a certificate signed by the CA, with its key.
struct Ca {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    der: CertificateDer<'static>,
}

impl Ca {
    fn new() -> Ca {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let der = params.self_signed(&key).unwrap().der().clone();
        Ca {
            issuer: rcgen::Issuer::new(params, key),
            der,
        }
    }

    fn pem(&self) -> String {
        pem("CERTIFICATE", &self.der)
    }

    fn leaf(
        &self,
        names: &[&str],
        usage: rcgen::ExtendedKeyUsagePurpose,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![usage];
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        let k = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        (cert.der().clone(), k)
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A server with a certificate of the CA. With `client_ca`, the server
/// needs a client certificate of that CA.
async fn serve_ca(ca: &Ca, client_ca: Option<&Ca>) -> (String, Arc<State>) {
    let (cert, key) = ca.leaf(
        &["127.0.0.1", "localhost"],
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    );
    let builder = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap();
    let config = match client_ca {
        None => builder.with_no_client_auth(),
        Some(c) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(c.der.clone()).unwrap();
            let v = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider(),
            )
            .build()
            .unwrap();
            builder.with_client_cert_verifier(v)
        }
    }
    .with_single_cert(vec![cert], key)
    .unwrap();
    serve_config(config).await
}

fn device(address: &str, site: &str) -> Device {
    Device {
        id: format!("console/{site}"),
        vendor: Vendor::Unifi,
        address: address.into(),
        credential: "lab".into(),
        site: Some(site.into()),
        route: Default::default(),
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
    t.pin(PinKind::Tls, &f.address, &f.pin);
    Arc::new(t)
}

fn password() -> Secret {
    Secret::Password("s3cret".into())
}

#[tokio::test]
async fn one_login_and_one_connection_serve_the_sites_of_a_console() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = HttpsTransport::new(credentials(password()), pinned(&f), HttpsLimits::default());
    for site in ["default", "branch"] {
        let d = device(&f.address, site);
        for path in ["/a", "/b", "/c"] {
            let body = t.get(&d, path).await.unwrap();
            assert_eq!(body, format!("{{\"path\":\"{path}\"}}").into_bytes());
        }
    }
    assert_eq!(f.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(f.state.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn parallel_reads_open_a_bounded_set_of_connections() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let limits = HttpsLimits {
        max_connections: 2,
        ..HttpsLimits::default()
    };
    let t = HttpsTransport::new(credentials(password()), pinned(&f), limits);
    let d = device(&f.address, "default");
    let paths: Vec<String> = (0..8).map(|i| format!("/p{i}")).collect();
    for round in 0..2 {
        let outs = join_all(paths.iter().map(|p| t.get(&d, p))).await;
        assert!(outs.iter().all(Result::is_ok), "round {round}");
    }
    assert_eq!(f.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(f.state.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_expired_session_logs_in_again() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = HttpsTransport::new(credentials(password()), pinned(&f), HttpsLimits::default());
    let d = device(&f.address, "default");
    assert!(t.get(&d, "/a").await.is_ok());
    f.state.expire();
    assert!(t.get(&d, "/a").await.is_ok());
    assert_eq!(f.state.logins.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_api_key_needs_no_login() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = HttpsTransport::new(
        credentials(Secret::ApiKey("key1".into())),
        pinned(&f),
        HttpsLimits::default(),
    );
    assert!(t.get(&device(&f.address, "default"), "/a").await.is_ok());
    assert_eq!(f.state.logins.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_wrong_password_is_a_connect_error() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = HttpsTransport::new(
        credentials(Secret::Password("other".into())),
        pinned(&f),
        HttpsLimits::default(),
    );
    let e = t
        .get(&device(&f.address, "default"), "/a")
        .await
        .unwrap_err();
    assert!(
        matches!(&e, TransportError::Connect(m) if m.contains("401")),
        "{e}"
    );
}

#[tokio::test]
async fn a_certificate_that_is_not_the_pin_is_rejected() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let d = device(&f.address, "default");
    let trust = TrustStore::memory(PinPolicy::Strict);
    trust.pin(PinKind::Tls, &f.address, &"0".repeat(64));
    let t = HttpsTransport::new(
        credentials(password()),
        Arc::new(trust),
        HttpsLimits::default(),
    );
    let e = t.get(&d, "/a").await.unwrap_err();
    assert!(
        matches!(&e, TransportError::Connect(m) if m.contains("TLS")),
        "{e}"
    );

    let tofu = Arc::new(TrustStore::memory(PinPolicy::AcceptNew));
    let t = HttpsTransport::new(
        credentials(password()),
        tofu.clone(),
        HttpsLimits::default(),
    );
    assert!(t.get(&d, "/a").await.is_ok());
    assert_eq!(tofu.get(PinKind::Tls, &f.address), Some(f.pin.clone()));
}

#[tokio::test]
async fn tls_1_2_and_tls_1_3_both_work() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let f = serve(&[version]).await;
        let t = HttpsTransport::new(credentials(password()), pinned(&f), HttpsLimits::default());
        let out = t.get(&device(&f.address, "default"), "/a").await;
        assert!(out.is_ok(), "{version:?}: {out:?}");
    }
}

#[tokio::test]
async fn an_error_status_and_a_large_body_are_command_errors() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let limits = HttpsLimits {
        max_body: 1000,
        ..HttpsLimits::default()
    };
    let t = HttpsTransport::new(credentials(password()), pinned(&f), limits);
    let d = device(&f.address, "default");
    let e = t.get(&d, "/missing").await.unwrap_err();
    assert_eq!(
        e,
        TransportError::NotFound("HTTP 404 Not Found for /missing".into())
    );
    let e = t.get(&d, "/big").await.unwrap_err();
    assert!(matches!(e, TransportError::Command(_)), "{e}");
    assert!(t.get(&d, "/a").await.is_ok());
}

fn jump_credentials() -> Arc<MemoryCredentials> {
    let mut c = MemoryCredentials::new();
    c.insert(
        "lab",
        Credential {
            user: "collector".into(),
            secret: password(),
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

#[tokio::test]
async fn a_proxy_carries_the_connections_to_a_console() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let http = route::http_proxy(None).await;
    let socks = route::socks5_proxy().await;
    for (scheme, p) in [("http", &http), ("socks5", &socks)] {
        let t = HttpsTransport::new(credentials(password()), pinned(&f), HttpsLimits::default());
        let mut d = device(&f.address, "default");
        d.route.proxy = Some(Proxy::parse(&format!("{scheme}://{}", p.address)).unwrap());
        for path in ["/a", "/b"] {
            assert_eq!(
                t.get(&d, path).await.unwrap(),
                format!("{{\"path\":\"{path}\"}}").into_bytes()
            );
        }
        assert_eq!(p.forwards(), 1, "{scheme}");
    }
}

#[tokio::test]
async fn one_jump_host_login_serves_the_connections_of_a_console() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let b = route::bastion("hop", "hop-pass").await;
    let trust = TrustStore::memory(PinPolicy::Strict);
    trust.pin(PinKind::Ssh, b.address(), &b.host_key);
    trust.pin(
        PinKind::Tls,
        &format!("{}>{}", b.address(), f.address),
        &f.pin,
    );
    let limits = HttpsLimits {
        max_connections: 3,
        ..HttpsLimits::default()
    };
    let t = HttpsTransport::new(jump_credentials(), Arc::new(trust), limits);
    let mut d = device(&f.address, "default");
    d.route.jumps = vec![Jump {
        address: b.address().into(),
        credential: "hop".into(),
        algorithms: Algorithms::Modern,
    }];
    let paths: Vec<String> = (0..9).map(|i| format!("/p{i}")).collect();
    let outs = join_all(paths.iter().map(|p| t.get(&d, p))).await;
    assert!(outs.iter().all(Result::is_ok), "{outs:?}");
    assert_eq!(b.log(), ["password hop hop-pass"]);
    let n = f.state.connections.load(Ordering::SeqCst);
    assert!((1..=3).contains(&n), "{n} connections");
    assert_eq!(b.forwarder.forwards(), n);

    let wrong = TrustStore::memory(PinPolicy::Strict);
    wrong.pin(PinKind::Ssh, b.address(), &b.host_key);
    wrong.pin(PinKind::Tls, &f.address, &f.pin);
    let t = HttpsTransport::new(jump_credentials(), Arc::new(wrong), HttpsLimits::default());
    let Err(TransportError::Connect(e)) = t.get(&d, "/a").await else {
        panic!("the pin of the direct address does not apply behind a jump host");
    };
    assert!(e.contains("TLS"), "{e}");
}

#[tokio::test]
async fn a_ca_bundle_checks_the_certificate() {
    let ca = Ca::new();
    let (address, _) = serve_ca(&ca, None).await;
    let strict = || Arc::new(TrustStore::memory(PinPolicy::Strict));
    let profile = HttpsProfile {
        trust: TlsTrust::CaBundle(ca.pem()),
        client: None,
    };
    let t = HttpsTransport::new(credentials(password()), strict(), HttpsLimits::default())
        .with_default_profile(profile);
    assert!(t.get(&device(&address, "default"), "/a").await.is_ok());

    let other = Ca::new();
    let profile = HttpsProfile {
        trust: TlsTrust::CaBundle(other.pem()),
        client: None,
    };
    let t = HttpsTransport::new(credentials(password()), strict(), HttpsLimits::default())
        .with_default_profile(profile);
    let Err(TransportError::Connect(e)) = t.get(&device(&address, "default"), "/a").await else {
        panic!("a certificate of another CA is rejected");
    };
    assert!(e.contains("TLS"), "{e}");

    let profile = HttpsProfile {
        trust: TlsTrust::CaBundle("no pem here".into()),
        client: None,
    };
    let t = HttpsTransport::new(credentials(password()), strict(), HttpsLimits::default())
        .with_default_profile(profile);
    assert!(t.get(&device(&address, "default"), "/a").await.is_err());
}

#[tokio::test]
async fn no_verify_accepts_the_certificate_and_writes_no_pin() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let trust = Arc::new(TrustStore::memory(PinPolicy::AcceptNew));
    let profile = HttpsProfile {
        trust: TlsTrust::NoVerify,
        client: None,
    };
    let t = HttpsTransport::new(
        credentials(password()),
        trust.clone(),
        HttpsLimits::default(),
    )
    .with_profile("console/default", profile);
    assert!(t.get(&device(&f.address, "default"), "/a").await.is_ok());
    assert_eq!(trust.to_text(), "");
}

#[tokio::test]
async fn a_client_certificate_gives_mutual_tls() {
    let ca = Ca::new();
    let clients = Ca::new();
    let (address, _) = serve_ca(&ca, Some(&clients)).await;
    let (cert, key) = clients.leaf(&["collector"], rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let client = ClientCert {
        chain: pem("CERTIFICATE", &cert),
        key: pem("PRIVATE KEY", key.secret_der()),
    };
    assert!(!format!("{client:?}").contains("PRIVATE"));
    let d = device(&address, "default");
    let strict = || Arc::new(TrustStore::memory(PinPolicy::Strict));
    let without = HttpsTransport::new(credentials(password()), strict(), HttpsLimits::default())
        .with_default_profile(HttpsProfile {
            trust: TlsTrust::CaBundle(ca.pem()),
            client: None,
        });
    assert!(without.get(&d, "/a").await.is_err());
    let with = HttpsTransport::new(credentials(password()), strict(), HttpsLimits::default())
        .with_default_profile(HttpsProfile {
            trust: TlsTrust::CaBundle(ca.pem()),
            client: Some(client),
        });
    assert!(with.get(&d, "/a").await.is_ok());
}

#[tokio::test]
async fn each_site_of_a_console_keeps_its_tls_mode() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = HttpsTransport::new(
        credentials(password()),
        Arc::new(TrustStore::memory(PinPolicy::Strict)),
        HttpsLimits::default(),
    )
    .with_profile(
        "console/default",
        HttpsProfile {
            trust: TlsTrust::NoVerify,
            client: None,
        },
    );
    assert!(t.get(&device(&f.address, "default"), "/a").await.is_ok());
    assert!(t.get(&device(&f.address, "branch"), "/a").await.is_err());
}
