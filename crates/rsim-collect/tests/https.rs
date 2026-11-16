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
use rsim_collect::https::{HttpsLimits, HttpsTransport, certificate_pin};
use rsim_collect::{
    Credential, Device, Https, MemoryCredentials, PinKind, PinPolicy, Secret, TransportError,
    TrustStore, Vendor,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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
    Fixture {
        address,
        pin,
        state,
    }
}

fn device(address: &str, site: &str) -> Device {
    Device {
        id: format!("console/{site}"),
        vendor: Vendor::Unifi,
        address: address.into(),
        credential: "lab".into(),
        site: Some(site.into()),
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
        TransportError::Command("HTTP 404 Not Found for /missing".into())
    );
    let e = t.get(&d, "/big").await.unwrap_err();
    assert!(matches!(e, TransportError::Command(_)), "{e}");
    assert!(t.get(&d, "/a").await.is_ok());
}
