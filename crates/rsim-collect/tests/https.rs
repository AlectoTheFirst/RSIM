//! The HTTPS transport against a UniFi-like HTTPS server in the test process.

#![cfg(feature = "https")]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::future::join_all;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use rsim_collect::https::{
    ApiServer, ClientCert, HttpsLimits, HttpsProfile, HttpsTransport, OAUTH_TOKEN_PATH, TlsTrust,
    certificate_pin,
};
use rsim_collect::{
    Algorithms, Credential, Device, HttpReply, Https, Jump, MemoryCredentials, PinKind, PinPolicy,
    Proxy, Secret, TokioClock, TransportError, TrustStore, Vendor,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[path = "support/route.rs"]
mod route;

#[derive(Default)]
struct State {
    connections: AtomicUsize,
    logins: AtomicUsize,
    token: Mutex<Option<String>>,
    authorization: Mutex<Option<String>>,
    posts: Mutex<Vec<(String, Bytes)>>,
    starts: Mutex<Vec<(String, Instant)>>,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
    /// The open connections after the TLS handshake, and their peak.
    open: AtomicUsize,
    open_peak: AtomicUsize,
    /// The 429 replies of the paths `/limited/..`, each with its
    /// `Retry-After` value or with none.
    limits: Mutex<VecDeque<Option<String>>>,
}

impl State {
    fn expire(&self) {
        *self.token.lock().unwrap() = None;
    }

    /// The start times of the requests to the paths with the prefix.
    fn starts(&self, prefix: &str) -> Vec<Instant> {
        let mut out: Vec<Instant> = self
            .starts
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p.starts_with(prefix))
            .map(|(_, t)| *t)
            .collect();
        out.sort();
        out
    }

    fn limit(&self, retry_after: Option<&str>) {
        self.limits
            .lock()
            .unwrap()
            .push_back(retry_after.map(str::to_string));
    }
}

fn reply(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(body.into()))
        .unwrap()
}

fn too_many(retry_after: Option<String>) -> Response<Full<Bytes>> {
    let mut b = Response::builder().status(StatusCode::TOO_MANY_REQUESTS);
    if let Some(v) = retry_after {
        b = b.header(header::RETRY_AFTER, v);
    }
    b.body(Full::new(Bytes::from_static(b"{\"error\":\"rate\"}")))
        .unwrap()
}

async fn handle(state: Arc<State>, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let n = state.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    state.peak.fetch_max(n, Ordering::SeqCst);
    let r = respond(state.clone(), req).await;
    state.in_flight.fetch_sub(1, Ordering::SeqCst);
    r
}

async fn respond(state: Arc<State>, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    if path != "/api/auth/login" && path != OAUTH_TOKEN_PATH {
        state
            .starts
            .lock()
            .unwrap()
            .push((path.clone(), Instant::now()));
    }
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let api_token = authorization.as_deref() == Some("Token tok-velo");
    *state.authorization.lock().unwrap() = authorization;
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
    if path == OAUTH_TOKEN_PATH {
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        state
            .posts
            .lock()
            .unwrap()
            .push((path.clone(), body.clone()));
        if v["client_id"] == "no-token" {
            return reply(StatusCode::OK, "{\"expires_in\":3600}");
        }
        if v["grant_type"] != "client_credentials"
            || v["client_id"] != "collector"
            || v["client_secret"] != "s3cret"
        {
            return reply(StatusCode::UNAUTHORIZED, "{\"error\":\"invalid_client\"}");
        }
        let n = state.logins.fetch_add(1, Ordering::SeqCst) + 1;
        let token = format!("bear{n}");
        *state.token.lock().unwrap() = Some(token.clone());
        return reply(
            StatusCode::OK,
            format!("{{\"access_token\":\"{token}\",\"expires_in\":3600}}"),
        );
    }
    let api_key = headers.get("x-api-key").is_some_and(|v| v == "key1");
    let token = state.token.lock().unwrap().clone();
    let bearer = token.as_ref().is_some_and(|t| {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {t}"))
    });
    let session = token.is_some_and(|t| {
        let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
        let csrf = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
        cookie == Some(&format!("TOKEN={t}")) && csrf == Some(&format!("csrf-{t}"))
    });
    if !api_key && !session && !api_token && !bearer {
        return reply(StatusCode::UNAUTHORIZED, "{}");
    }
    if method == Method::POST {
        state
            .posts
            .lock()
            .unwrap()
            .push((path.clone(), body.clone()));
    }
    if path.starts_with("/limited/") {
        let next = state.limits.lock().unwrap().pop_front();
        if let Some(retry_after) = next {
            return too_many(retry_after);
        }
    }
    if path.starts_with("/always-429/") {
        return too_many(Some("0".into()));
    }
    if path.starts_with("/slow/") {
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }
    match path.as_str() {
        "/big" => reply(StatusCode::OK, vec![b'x'; 5000]),
        "/missing" => reply(StatusCode::NOT_FOUND, "{}"),
        "/forbidden" => reply(StatusCode::FORBIDDEN, forbidden_body()),
        "/unimplemented" => reply(StatusCode::NOT_IMPLEMENTED, unimplemented_body()),
        _ if method == Method::POST => reply(StatusCode::OK, body),
        _ => reply(StatusCode::OK, format!("{{\"path\":\"{path}\"}}")),
    }
}

fn forbidden_body() -> String {
    format!("{{\"error\":\"denied\"}}\n{}", "y".repeat(300))
}

fn unimplemented_body() -> String {
    format!("{{\"error\":\"not implemented\"}}\r\n{}", "z".repeat(300))
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
                let open = st.open.fetch_add(1, Ordering::SeqCst) + 1;
                st.open_peak.fetch_max(open, Ordering::SeqCst);
                let service = service_fn({
                    let st = st.clone();
                    move |req| {
                        let st = st.clone();
                        async move { Ok::<_, Infallible>(handle(st, req).await) }
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
                st.open.fetch_sub(1, Ordering::SeqCst);
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
        capture_bgp: Default::default(),
        route: Default::default(),
        interval: rsim_collect::DEFAULT_INTERVAL,
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
            secret: Secret::Password(route::hop_pass().into()),
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
        let proxy = Proxy::parse(&format!("{scheme}://{}", p.address)).unwrap();
        let trust = TrustStore::memory(PinPolicy::Strict);
        trust.pin(
            PinKind::Tls,
            &format!("{}>{}", proxy.address(), f.address),
            &f.pin,
        );
        let t = HttpsTransport::new(
            credentials(password()),
            Arc::new(trust),
            HttpsLimits::default(),
        );
        let mut d = device(&f.address, "default");
        d.route.proxy = Some(proxy);
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
    let b = route::bastion("hop", route::hop_pass()).await;
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
    assert_eq!(b.log(), [format!("password hop {}", route::hop_pass())]);
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

/// The read paths of the POST tests.
const READS: &[&str] = &[
    "/portal/rest/edge/getEdgeConfigurationStack",
    "/unimplemented",
];

/// 2026-11-23 08:00:00 UTC in milliseconds since the Unix epoch.
const CLOCK_MS: u64 = 1_795_420_800_000;

fn token() -> Secret {
    Secret::Token("tok-velo".into())
}

/// The credentials `lab` and `lab2`, each with the API token.
fn token_credentials() -> Arc<MemoryCredentials> {
    let mut c = MemoryCredentials::new();
    for name in ["lab", "lab2"] {
        c.insert(
            name,
            Credential {
                user: String::new(),
                secret: token(),
            },
        );
    }
    Arc::new(c)
}

/// A transport with the address of the fixture as an API server.
fn api(f: &Fixture, concurrency: usize, limits: HttpsLimits) -> HttpsTransport {
    HttpsTransport::new(token_credentials(), pinned(f), limits)
        .with_api_server(&f.address, ApiServer { concurrency })
}

fn retries(n: u32) -> HttpsLimits {
    HttpsLimits {
        retries: n,
        ..HttpsLimits::default()
    }
}

/// Asserts that 2 request starts in a row are at least `interval` apart,
/// less 50 ms for the latency of the test server.
fn assert_pace(starts: &[Instant], interval: Duration) {
    for w in starts.windows(2) {
        let gap = w[1] - w[0];
        assert!(gap + Duration::from_millis(50) >= interval, "{gap:?}");
    }
}

/// Asserts that the first and the last of 8 request starts are 7 intervals
/// of 250 ms apart, with 50 ms for the latency of the test server and 1 s
/// for the load of the test machine.
fn assert_span(starts: &[Instant]) {
    let span = starts[7] - starts[0];
    assert!(
        span + Duration::from_millis(50) >= Duration::from_millis(1750)
            && span < Duration::from_millis(2750),
        "{span:?}"
    );
}

/// The time between the 2 requests to the paths with the prefix.
fn retry_gap(state: &State, prefix: &str) -> Duration {
    let s = state.starts(prefix);
    assert_eq!(s.len(), 2, "{s:?}");
    s[1] - s[0]
}

#[tokio::test]
async fn an_api_token_goes_in_the_authorization_header() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let d = device(&f.address, "default");
    let t = HttpsTransport::new(credentials(token()), pinned(&f), HttpsLimits::default());
    let out = t.get_status(&d, "/a").await.unwrap();
    assert_eq!(out, HttpReply::Body(b"{\"path\":\"/a\"}".to_vec()));
    assert_eq!(
        f.state.authorization.lock().unwrap().as_deref(),
        Some("Token tok-velo")
    );
    assert_eq!(f.state.logins.load(Ordering::SeqCst), 0);
    assert_eq!(format!("{:?}", token()), "Token(..)");

    let t = HttpsTransport::new(
        credentials(Secret::Token("tok-other".into())),
        pinned(&f),
        HttpsLimits::default(),
    );
    let out = t.get_status(&d, "/a").await.unwrap();
    assert_eq!(
        out,
        HttpReply::Status {
            status: 401,
            text: "{}".into()
        }
    );
}

#[tokio::test]
async fn a_post_read_sends_its_exact_body() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, HttpsLimits::default());
    let d = device(&f.address, "default");
    let request = json!({"enterpriseId": 1, "edgeId": 7, "with": ["modules"]});
    let out = t.post_read(&d, READS, READS[0], &request).await.unwrap();
    let sent = request.to_string();
    assert_eq!(out, HttpReply::Body(sent.clone().into_bytes()));
    let posts = f.state.posts.lock().unwrap().clone();
    assert_eq!(posts, [(READS[0].to_string(), Bytes::from(sent))]);
}

#[tokio::test]
async fn a_post_path_outside_the_read_paths_is_never_sent() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, HttpsLimits::default());
    let d = device(&f.address, "default");
    let path = "/portal/rest/enterprise/deleteEnterprise";
    let e = t
        .post_read(&d, READS, path, &json!({"id": 1}))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, TransportError::Command(m) if m.contains("not a read path")),
        "{e}"
    );
    assert_eq!(f.state.connections.load(Ordering::SeqCst), 0);
    assert!(f.state.starts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_429_waits_for_retry_after_in_seconds() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, retries(1));
    f.state.limit(Some("1"));
    let out = t
        .get_status(&device(&f.address, "default"), "/limited/a")
        .await
        .unwrap();
    assert!(matches!(out, HttpReply::Body(_)), "{out:?}");
    let gap = retry_gap(&f.state, "/limited/");
    assert!(
        gap >= Duration::from_millis(990) && gap < Duration::from_secs(3),
        "{gap:?}"
    );
}

#[tokio::test]
async fn a_429_waits_until_the_http_date_of_retry_after() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, retries(1)).with_clock(Arc::new(TokioClock::new(CLOCK_MS)));
    f.state.limit(Some("Mon, 23 Nov 2026 08:00:02 GMT"));
    let out = t
        .get_status(&device(&f.address, "default"), "/limited/a")
        .await
        .unwrap();
    assert!(matches!(out, HttpReply::Body(_)), "{out:?}");
    let gap = retry_gap(&f.state, "/limited/");
    assert!(
        gap >= Duration::from_millis(1500) && gap < Duration::from_secs(4),
        "{gap:?}"
    );
}

#[tokio::test]
async fn the_retries_of_a_429_end_after_3() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let d = device(&f.address, "default");
    let rate = HttpReply::Status {
        status: 429,
        text: "{\"error\":\"rate\"}".into(),
    };
    let t = api(&f, 4, retries(3));
    assert_eq!(t.get_status(&d, "/always-429/a").await.unwrap(), rate);
    assert_eq!(f.state.starts("/always-429/a").len(), 4);

    let t = api(&f, 4, HttpsLimits::default());
    assert_eq!(t.get_status(&d, "/always-429/b").await.unwrap(), rate);
    assert_eq!(f.state.starts("/always-429/b").len(), 1);

    let t = api(&f, 4, HttpsLimits::default()).with_retries("console/default", 1);
    assert_eq!(t.get_status(&d, "/always-429/c").await.unwrap(), rate);
    assert_eq!(f.state.starts("/always-429/c").len(), 2);
}

#[tokio::test]
async fn a_429_holds_the_requests_of_4_workers() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, retries(1));
    let d = device(&f.address, "default");
    f.state.limit(Some("1"));
    let paths: Vec<String> = (0..4).map(|i| format!("/limited/{i}")).collect();
    let outs = join_all(paths.iter().map(|p| t.get_status(&d, p))).await;
    assert!(
        outs.iter().all(|o| matches!(o, Ok(HttpReply::Body(_)))),
        "{outs:?}"
    );
    let s = f.state.starts("/limited/");
    assert_eq!(s.len(), 5, "{s:?}");
    for later in &s[1..] {
        let gap = *later - s[0];
        assert!(gap >= Duration::from_millis(990), "{gap:?}");
    }
}

#[tokio::test]
async fn four_requests_start_in_each_second_at_concurrency_4() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, HttpsLimits::default());
    let d = device(&f.address, "default");
    let paths: Vec<String> = (0..8).map(|i| format!("/p{i}")).collect();
    let outs = join_all(paths.iter().map(|p| t.get_status(&d, p))).await;
    assert!(outs.iter().all(Result::is_ok), "{outs:?}");
    let s = f.state.starts("/p");
    assert_eq!(s.len(), 8);
    assert_pace(&s, Duration::from_millis(250));
    assert_span(&s);
}

#[tokio::test]
async fn two_devices_of_one_api_server_share_its_pace() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, HttpsLimits::default());
    let one = device(&f.address, "e1");
    let mut two = device(&f.address, "e2");
    two.credential = "lab2".into();
    let reads: Vec<(&Device, String)> = (0..8)
        .map(|i| (if i < 4 { &one } else { &two }, format!("/p{i}")))
        .collect();
    let outs = join_all(reads.iter().map(|(d, p)| t.get_status(d, p))).await;
    assert!(outs.iter().all(Result::is_ok), "{outs:?}");
    let s = f.state.starts("/p");
    assert_eq!(s.len(), 8);
    assert_pace(&s, Duration::from_millis(250));
    assert_span(&s);
}

#[tokio::test]
async fn the_parallel_requests_to_an_api_server_stop_at_its_concurrency() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, HttpsLimits::default());
    let d = device(&f.address, "default");
    let paths: Vec<String> = (0..8).map(|i| format!("/slow/{i}")).collect();
    let outs = join_all(paths.iter().map(|p| t.get_status(&d, p))).await;
    assert!(outs.iter().all(Result::is_ok), "{outs:?}");
    assert_eq!(f.state.peak.load(Ordering::SeqCst), 4);
    let n = f.state.connections.load(Ordering::SeqCst);
    assert!((1..=4).contains(&n), "{n} connections");
}

#[tokio::test]
async fn two_devices_of_one_api_server_share_its_connection_limit() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, HttpsLimits::default());
    let one = device(&f.address, "e1");
    let mut two = device(&f.address, "e2");
    two.credential = "lab2".into();
    let reads: Vec<(&Device, String)> = (0..8)
        .map(|i| (if i < 4 { &one } else { &two }, format!("/slow/{i}")))
        .collect();
    let outs = join_all(reads.iter().map(|(d, p)| t.get_status(d, p))).await;
    assert!(outs.iter().all(Result::is_ok), "{outs:?}");
    assert_eq!(f.state.peak.load(Ordering::SeqCst), 4);
    let open = f.state.open_peak.load(Ordering::SeqCst);
    assert!((1..=4).contains(&open), "{open} open connections");
    let n = f.state.connections.load(Ordering::SeqCst);
    assert!(n >= 5, "{n} connections");
}

#[tokio::test]
async fn a_403_and_a_501_reach_the_source_with_200_characters_of_the_body() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = api(&f, 4, HttpsLimits::default());
    let d = device(&f.address, "default");
    let cut =
        |body: String| -> String { body.replace(['\r', '\n'], " ").chars().take(200).collect() };
    let out = t.get_status(&d, "/forbidden").await.unwrap();
    assert_eq!(
        out,
        HttpReply::Status {
            status: 403,
            text: cut(forbidden_body())
        }
    );
    let out = t
        .post_read(&d, READS, "/unimplemented", &json!({}))
        .await
        .unwrap();
    assert_eq!(
        out,
        HttpReply::Status {
            status: 501,
            text: cut(unimplemented_body())
        }
    );
    let HttpReply::Status { text, .. } = out else {
        panic!("a 501 is a status");
    };
    assert_eq!(text.chars().count(), 200);
    assert!(!text.contains(['\r', '\n']));
    assert_eq!(
        t.get(&d, "/forbidden").await.unwrap_err(),
        TransportError::Command("HTTP 403 Forbidden for /forbidden".into())
    );
}

#[tokio::test]
async fn a_jump_host_with_no_pin_is_refused_on_the_route_of_an_api_server() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let b = route::bastion("hop", route::hop_pass()).await;
    let trust = Arc::new(TrustStore::memory(PinPolicy::AcceptNew));
    let mut d = device(&f.address, "default");
    d.route.jumps = vec![Jump {
        address: b.address().into(),
        credential: "hop".into(),
        algorithms: Algorithms::Modern,
    }];
    let t = HttpsTransport::new(jump_credentials(), trust.clone(), HttpsLimits::default())
        .with_api_server(&f.address, ApiServer { concurrency: 4 });
    let Err(TransportError::Connect(e)) = t.get_status(&d, "/a").await else {
        panic!("a jump host with no pin is refused");
    };
    assert!(e.contains("has no pin"), "{e}");
    assert_eq!(trust.to_text(), "");
    assert!(b.log().is_empty());

    let t = HttpsTransport::new(jump_credentials(), trust.clone(), HttpsLimits::default());
    assert!(t.get_status(&d, "/a").await.is_ok());
    assert_eq!(
        trust.get(PinKind::Ssh, b.address()),
        Some(b.host_key.clone())
    );
}

#[tokio::test]
async fn public_roots_reject_a_certificate_of_a_private_ca() {
    let ca = Ca::new();
    let (address, _) = serve_ca(&ca, None).await;
    let t = HttpsTransport::new(
        credentials(token()),
        Arc::new(TrustStore::memory(PinPolicy::AcceptNew)),
        HttpsLimits::default(),
    )
    .with_default_profile(HttpsProfile {
        trust: TlsTrust::PublicRoots,
        client: None,
    });
    let Err(TransportError::Connect(e)) = t.get_status(&device(&address, "default"), "/a").await
    else {
        panic!("a certificate of a private CA is rejected");
    };
    assert!(e.contains("TLS"), "{e}");
}

fn oauth(secret: &str) -> Secret {
    Secret::OAuthClient(secret.into())
}

/// The bodies of the POST requests to `path`.
fn posts_to(state: &State, path: &str) -> Vec<Bytes> {
    state
        .posts
        .lock()
        .unwrap()
        .iter()
        .filter(|(p, _)| p == path)
        .map(|(_, b)| b.clone())
        .collect()
}

#[tokio::test]
async fn an_oauth_client_gets_one_token_and_sends_it_as_bearer() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = HttpsTransport::new(
        credentials(oauth("s3cret")),
        pinned(&f),
        HttpsLimits::default(),
    );
    let d = device(&f.address, "default");
    assert_eq!(
        t.get_status(&d, "/a").await.unwrap(),
        HttpReply::Body(b"{\"path\":\"/a\"}".to_vec())
    );
    let request = json!({"filter": {"or": []}});
    assert_eq!(
        t.post_read(&d, READS, READS[0], &request).await.unwrap(),
        HttpReply::Body(request.to_string().into_bytes())
    );
    assert_eq!(f.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.state.authorization.lock().unwrap().as_deref(),
        Some("Bearer bear1")
    );
    let login: serde_json::Value =
        serde_json::from_slice(&posts_to(&f.state, OAUTH_TOKEN_PATH)[0]).unwrap();
    assert_eq!(
        login,
        json!({"grant_type": "client_credentials", "client_id": "collector", "client_secret": "s3cret"})
    );
    assert_eq!(format!("{:?}", oauth("s3cret")), "OAuthClient(..)");
}

#[tokio::test]
async fn a_401_renews_the_token_and_sends_the_same_body_again() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = HttpsTransport::new(
        credentials(oauth("s3cret")),
        pinned(&f),
        HttpsLimits::default(),
    );
    let d = device(&f.address, "default");
    let request = json!({"pagination": {"offset": 0, "limit": 100}});
    assert!(t.post_read(&d, READS, READS[0], &request).await.is_ok());
    f.state.expire();
    assert_eq!(
        t.post_read(&d, READS, READS[0], &request).await.unwrap(),
        HttpReply::Body(request.to_string().into_bytes())
    );
    f.state.expire();
    assert!(t.get(&d, "/a").await.is_ok());
    assert_eq!(f.state.logins.load(Ordering::SeqCst), 3);
    assert_eq!(
        posts_to(&f.state, READS[0]),
        [
            Bytes::from(request.to_string()),
            Bytes::from(request.to_string())
        ]
    );
}

#[tokio::test]
async fn a_refused_token_request_names_no_secret() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let t = HttpsTransport::new(
        credentials(oauth("wrong-s3cret")),
        pinned(&f),
        HttpsLimits::default(),
    );
    let d = device(&f.address, "default");
    let e = t.get_status(&d, "/a").await.unwrap_err();
    let text = e.to_string();
    assert!(
        matches!(&e, TransportError::Connect(m) if m.contains("401")),
        "{text}"
    );
    assert!(!text.contains("wrong-s3cret") && !format!("{e:?}").contains("wrong-s3cret"));
    assert_eq!(f.state.starts("/a"), Vec::<Instant>::new());
}

#[tokio::test]
async fn a_token_answer_with_no_access_token_is_a_login_error() {
    let f = serve(rustls::DEFAULT_VERSIONS).await;
    let mut c = MemoryCredentials::new();
    c.insert(
        "lab",
        Credential {
            user: "no-token".into(),
            secret: oauth("s3cret"),
        },
    );
    let t = HttpsTransport::new(Arc::new(c), pinned(&f), HttpsLimits::default());
    let e = t
        .get_status(&device(&f.address, "default"), "/a")
        .await
        .unwrap_err();
    assert!(
        matches!(&e, TransportError::Connect(m) if m == "the token answer of Equinix has no access_token"),
        "{e}"
    );
}
