//! The HTTPS transport for UniFi OS consoles. It reaches each console
//! directly, through a proxy, or through a chain of SSH jump hosts. It
//! checks the certificate of each console against a pin, a CA bundle, or
//! not at all, keeps the login session of each console, and reuses the
//! connections.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http1::SendRequest;
use hyper::{Method, Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::path::Route;
use crate::trust::{
    Credential, Credentials, PinKind, Secret, TrustStore, host_port, plain_address,
};
use crate::tunnel::{HopLimits, Tunnel, stream};
use crate::{BoxFuture, Device, Https, TransportError};

/// How the transport checks the certificate of a console. The modes do not
/// mix: a pin is not a fallback of a CA bundle, and the mode with no check
/// writes no pin.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum TlsTrust {
    /// The SHA-256 of the certificate must be the pin of the console in the
    /// trust store.
    #[default]
    Pin,
    /// The certificate must chain to a CA of the bundle, in PEM, and name
    /// the host of the console.
    CaBundle(String),
    /// The certificate is not checked. The handshake signatures are still
    /// checked with the key of the certificate.
    NoVerify,
}

/// A client certificate for mutual TLS, in PEM: the chain and its private
/// key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientCert {
    pub chain: String,
    pub key: String,
}

impl std::fmt::Debug for ClientCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientCert(..)")
    }
}

/// The TLS settings of a console.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HttpsProfile {
    pub trust: TlsTrust,
    pub client: Option<ClientCert>,
}

/// The limits of the HTTPS transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpsLimits {
    /// The time for the TCP connection and the TLS handshake. It is also
    /// the time to open a channel through a jump host.
    pub connect_timeout: Duration,
    /// The key exchange and the login of one jump host.
    pub handshake_timeout: Duration,
    /// The interval of the keepalive on the last jump host.
    pub keepalive: Duration,
    /// The largest response body. A larger body is an error.
    pub max_body: usize,
    /// The largest number of connections to one console. A request waits
    /// for a free connection.
    pub max_connections: usize,
}

impl Default for HttpsLimits {
    fn default() -> HttpsLimits {
        HttpsLimits {
            connect_timeout: Duration::from_secs(15),
            handshake_timeout: Duration::from_secs(30),
            keepalive: Duration::from_secs(30),
            max_body: 256 << 20,
            max_connections: 4,
        }
    }
}

/// The SHA-256 of a DER certificate in lower-case hex: the form of a TLS pin.
pub fn certificate_pin(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Accepts a server certificate only if the trust store accepts its pin.
/// The handshake signatures are checked with the key of that certificate.
#[derive(Debug)]
struct PinVerifier {
    trust: Arc<TrustStore>,
    address: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.trust
            .check(PinKind::Tls, &self.address, &certificate_pin(end_entity))
            .map(|_| ServerCertVerified::assertion())
            .map_err(rustls::Error::General)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accepts each server certificate. The handshake signatures are checked
/// with the key of that certificate.
#[derive(Debug)]
struct NoVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The TLS client settings of a console.
fn tls_config(
    profile: &HttpsProfile,
    trust: &Arc<TrustStore>,
    pin: String,
) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let builder = match &profile.trust {
        TlsTrust::Pin => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                trust: trust.clone(),
                address: pin,
                provider,
            })),
        TlsTrust::NoVerify => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier { provider })),
        TlsTrust::CaBundle(pem) => {
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
                let cert = cert.map_err(|e| format!("the CA bundle does not read: {e}"))?;
                roots
                    .add(cert)
                    .map_err(|e| format!("a CA of the bundle is not valid: {e}"))?;
            }
            if roots.is_empty() {
                return Err("the CA bundle has no certificate".into());
            }
            let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| e.to_string())?;
            builder.with_webpki_verifier(verifier)
        }
    };
    match &profile.client {
        None => Ok(builder.with_no_client_auth()),
        Some(c) => {
            let chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(c.chain.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("the client certificate does not read: {e}"))?;
            let key = PrivateKeyDer::from_pem_slice(c.key.as_bytes())
                .map_err(|e| format!("the client key does not read: {e}"))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| format!("the client certificate is not valid: {e}"))
        }
    }
}

/// The login state of a console. `generation` counts the logins.
#[derive(Default)]
struct Session {
    headers: Vec<(header::HeaderName, String)>,
    generation: u64,
}

struct Console {
    host: String,
    port: u16,
    route: Route,
    tunnel: tokio::sync::Mutex<Option<Arc<Tunnel>>>,
    credential: Credential,
    tls: TlsConnector,
    session: tokio::sync::Mutex<Session>,
    idle: Mutex<Vec<SendRequest<Full<Bytes>>>>,
    permits: Arc<tokio::sync::Semaphore>,
}

/// A console is one address with one credential, one route and one TLS
/// profile.
type ConsoleKey = (String, String, Route, HttpsProfile);

/// An HTTPS transport over `hyper` and `rustls` with the `ring` provider.
pub struct HttpsTransport {
    credentials: Arc<dyn Credentials>,
    trust: Arc<TrustStore>,
    limits: HttpsLimits,
    default_profile: HttpsProfile,
    profiles: HashMap<String, HttpsProfile>,
    consoles: Mutex<HashMap<ConsoleKey, Arc<Console>>>,
}

impl HttpsTransport {
    pub fn new(
        credentials: Arc<dyn Credentials>,
        trust: Arc<TrustStore>,
        limits: HttpsLimits,
    ) -> HttpsTransport {
        HttpsTransport {
            credentials,
            trust,
            limits,
            default_profile: HttpsProfile::default(),
            profiles: HashMap::new(),
            consoles: Mutex::new(HashMap::new()),
        }
    }

    /// Sets the profile of the consoles with no profile of their own.
    pub fn with_default_profile(mut self, profile: HttpsProfile) -> HttpsTransport {
        self.default_profile = profile;
        self
    }

    /// Sets the profile of a device.
    pub fn with_profile(mut self, device: &str, profile: HttpsProfile) -> HttpsTransport {
        self.profiles.insert(device.to_string(), profile);
        self
    }

    fn console(&self, device: &Device) -> Result<Arc<Console>, TransportError> {
        let connect = |e: String| TransportError::Connect(e);
        let profile = self
            .profiles
            .get(&device.id)
            .unwrap_or(&self.default_profile);
        let key = (
            device.address.clone(),
            device.credential.clone(),
            device.route.clone(),
            profile.clone(),
        );
        if let Some(c) = self
            .consoles
            .lock()
            .expect("the lock is not poisoned")
            .get(&key)
        {
            return Ok(c.clone());
        }
        let credential = self.credentials.get(&device.credential).map_err(connect)?;
        let address = plain_address(&device.address, "https").map_err(connect)?;
        let (host, port) = host_port(address, 443).map_err(connect)?;
        let route = &device.route;
        let pin = route.pin_name(route.jumps.len(), address);
        let config = tls_config(profile, &self.trust, pin)
            .map_err(|e| connect(format!("console {}: {e}", device.address)))?;
        let console = Arc::new(Console {
            host,
            port,
            route: route.clone(),
            tunnel: tokio::sync::Mutex::new(None),
            credential,
            tls: TlsConnector::from(Arc::new(config)),
            session: tokio::sync::Mutex::new(Session::default()),
            idle: Mutex::new(Vec::new()),
            permits: Arc::new(tokio::sync::Semaphore::new(
                self.limits.max_connections.max(1),
            )),
        });
        Ok(self
            .consoles
            .lock()
            .expect("the lock is not poisoned")
            .entry(key)
            .or_insert(console)
            .clone())
    }

    /// An idle connection, or a new connection when `fresh` is true or no
    /// idle connection is ready. The flag is true for an idle connection.
    async fn sender(
        &self,
        console: &Console,
        fresh: bool,
    ) -> Result<(SendRequest<Full<Bytes>>, bool), TransportError> {
        if !fresh {
            loop {
                let idle = console.idle.lock().expect("the lock is not poisoned").pop();
                let Some(mut s) = idle else { break };
                if s.ready().await.is_ok() {
                    return Ok((s, true));
                }
            }
        }
        let connect = |e: String| TransportError::Connect(e);
        let tunnel = self.tunnel(console).await?;
        let open = async {
            let tcp = stream(
                &console.route,
                tunnel.as_deref(),
                &console.host,
                console.port,
                self.limits.connect_timeout,
            )
            .await
            .map_err(|e| {
                connect(if tunnel.is_some() {
                    e
                } else {
                    format!("console {}: {e}", console.host)
                })
            })?;
            let name =
                ServerName::try_from(console.host.clone()).map_err(|e| connect(e.to_string()))?;
            let tls = console
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| connect(format!("TLS: {e}")))?;
            let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|e| connect(e.to_string()))?;
            tokio::spawn(conn);
            Ok((sender, false))
        };
        let r = tokio::time::timeout(self.limits.connect_timeout, open)
            .await
            .map_err(|_| TransportError::Timeout)
            .and_then(|r| r);
        if r.is_err()
            && let Some(t) = tunnel
        {
            let mut g = console.tunnel.lock().await;
            if g.as_ref().is_some_and(|c| Arc::ptr_eq(c, &t)) {
                *g = None;
            }
            drop(g);
            t.close().await;
        }
        r
    }

    /// The logged-in jump hosts of a console, or `None` for a route with no
    /// jump host. One tunnel serves all connections of the console.
    async fn tunnel(&self, console: &Console) -> Result<Option<Arc<Tunnel>>, TransportError> {
        if console.route.jumps.is_empty() {
            return Ok(None);
        }
        let mut g = console.tunnel.lock().await;
        if let Some(t) = g.as_ref()
            && !t.is_closed()
        {
            return Ok(Some(t.clone()));
        }
        if let Some(old) = g.take() {
            old.close().await;
        }
        let limits = HopLimits {
            connect: self.limits.connect_timeout,
            handshake: self.limits.handshake_timeout,
            keepalive: self.limits.keepalive,
        };
        let t = Tunnel::connect(
            &console.route,
            self.credentials.as_ref(),
            &self.trust,
            limits,
            true,
        )
        .await
        .map_err(TransportError::Connect)?;
        let t = Arc::new(t);
        *g = Some(t.clone());
        Ok(Some(t))
    }

    async fn send(
        &self,
        console: &Console,
        request: Request<Full<Bytes>>,
    ) -> Result<(StatusCode, header::HeaderMap, Bytes), TransportError> {
        let failed = |e: String| TransportError::Command(e);
        let _permit = console
            .permits
            .acquire()
            .await
            .expect("the semaphore is not closed");
        let (mut sender, reused) = self.sender(console, false).await?;
        let retry = reused.then(|| clone_request(&request));
        let response = match sender.send_request(request).await {
            Ok(r) => r,
            Err(_) if retry.is_some() => {
                (sender, _) = self.sender(console, true).await?;
                sender
                    .send_request(retry.expect("the retry request is set"))
                    .await
                    .map_err(|e| failed(e.to_string()))?
            }
            Err(e) => return Err(failed(e.to_string())),
        };
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, self.limits.max_body)
            .collect()
            .await
            .map_err(|e| failed(format!("the body does not read: {e}")))?
            .to_bytes();
        let mut idle = console.idle.lock().expect("the lock is not poisoned");
        if !sender.is_closed() && idle.len() < self.limits.max_connections {
            idle.push(sender);
        }
        Ok((parts.status, parts.headers, body))
    }

    fn request(
        console: &Console,
        method: Method,
        path: &str,
        headers: &[(header::HeaderName, String)],
        body: Bytes,
    ) -> Result<Request<Full<Bytes>>, TransportError> {
        let host = if console.port == 443 {
            console.host.clone()
        } else {
            format!("{}:{}", console.host, console.port)
        };
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, host)
            .header(header::ACCEPT, "application/json");
        if !body.is_empty() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        for (k, v) in headers {
            b = b.header(k, v);
        }
        b.body(Full::new(body))
            .map_err(|e| TransportError::Command(e.to_string()))
    }

    /// Logs in if the session has the generation `seen`, and gives the
    /// headers of the session.
    async fn login(
        &self,
        console: &Console,
        seen: Option<u64>,
    ) -> Result<(Vec<(header::HeaderName, String)>, u64), TransportError> {
        let mut session = console.session.lock().await;
        let fresh = match seen {
            Some(g) => session.generation != g,
            None => session.generation > 0,
        };
        if fresh {
            return Ok((session.headers.clone(), session.generation));
        }
        let headers = match &console.credential.secret {
            Secret::ApiKey(key) => {
                vec![(header::HeaderName::from_static("x-api-key"), key.clone())]
            }
            Secret::Password(password) => {
                let body = serde_json::json!({
                    "username": console.credential.user,
                    "password": password,
                    "remember": true,
                });
                let req = Self::request(
                    console,
                    Method::POST,
                    "/api/auth/login",
                    &[],
                    Bytes::from(body.to_string()),
                )?;
                let (status, headers, _) = self.send(console, req).await?;
                if !status.is_success() {
                    return Err(TransportError::Connect(format!(
                        "the login of {} gave HTTP {status}",
                        console.credential.user
                    )));
                }
                session_headers(&headers)
            }
            Secret::Key { .. } | Secret::Agent { .. } => {
                return Err(TransportError::Connect(
                    "an SSH key is not an HTTPS credential".into(),
                ));
            }
        };
        session.headers = headers;
        session.generation += 1;
        Ok((session.headers.clone(), session.generation))
    }
}

/// A copy of a request with a body in memory.
fn clone_request(r: &Request<Full<Bytes>>) -> Request<Full<Bytes>> {
    let mut b = Request::builder()
        .method(r.method().clone())
        .uri(r.uri().clone());
    for (k, v) in r.headers() {
        b = b.header(k, v);
    }
    let body = r.body().clone();
    b.body(body).expect("the parts come from a valid request")
}

/// The cookie and the CSRF token of a login response.
fn session_headers(headers: &header::HeaderMap) -> Vec<(header::HeaderName, String)> {
    let cookies: Vec<&str> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .map(str::trim)
        .filter(|v| v.contains('='))
        .collect();
    let mut out = Vec::new();
    if !cookies.is_empty() {
        out.push((header::COOKIE, cookies.join("; ")));
    }
    if let Some(csrf) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) {
        out.push((
            header::HeaderName::from_static("x-csrf-token"),
            csrf.to_string(),
        ));
    }
    out
}

impl Https for HttpsTransport {
    fn get<'a>(
        &'a self,
        device: &'a Device,
        path: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            let console = self.console(device)?;
            let (mut headers, mut generation) = self.login(&console, None).await?;
            for attempt in 0..2 {
                let req = Self::request(&console, Method::GET, path, &headers, Bytes::new())?;
                let (status, _, body) = self.send(&console, req).await?;
                if status.is_success() {
                    return Ok(body.to_vec());
                }
                let expired = status == StatusCode::UNAUTHORIZED
                    && matches!(console.credential.secret, Secret::Password(_));
                if expired && attempt == 0 {
                    (headers, generation) = self.login(&console, Some(generation)).await?;
                    continue;
                }
                let text = format!("HTTP {status} for {path}");
                if status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST {
                    return Err(TransportError::NotFound(text));
                }
                return Err(TransportError::Command(text));
            }
            Err(TransportError::Command(format!(
                "HTTP 401 for {path} after a new login"
            )))
        })
    }
}
