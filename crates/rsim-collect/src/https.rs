//! The HTTPS transport for UniFi OS consoles. It pins the certificate of
//! each console, keeps the login session of each console, and reuses the
//! connections.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http1::SendRequest;
use hyper::{Method, Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::trust::{Credential, Credentials, PinKind, Secret, TrustStore, host_port};
use crate::{BoxFuture, Device, Https, TransportError};

/// The limits of the HTTPS transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpsLimits {
    /// The time for the TCP connection and the TLS handshake.
    pub connect_timeout: Duration,
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

/// The login state of a console. `generation` counts the logins.
#[derive(Default)]
struct Session {
    headers: Vec<(header::HeaderName, String)>,
    generation: u64,
}

struct Console {
    host: String,
    port: u16,
    credential: Credential,
    tls: TlsConnector,
    session: tokio::sync::Mutex<Session>,
    idle: Mutex<Vec<SendRequest<Full<Bytes>>>>,
    permits: Arc<tokio::sync::Semaphore>,
}

/// An HTTPS transport over `hyper` and `rustls` with the `ring` provider.
pub struct HttpsTransport {
    credentials: Arc<dyn Credentials>,
    trust: Arc<TrustStore>,
    limits: HttpsLimits,
    consoles: Mutex<HashMap<(String, String), Arc<Console>>>,
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
            consoles: Mutex::new(HashMap::new()),
        }
    }

    fn console(&self, device: &Device) -> Result<Arc<Console>, TransportError> {
        let connect = |e: String| TransportError::Connect(e);
        let key = (device.address.clone(), device.credential.clone());
        if let Some(c) = self
            .consoles
            .lock()
            .expect("the lock is not poisoned")
            .get(&key)
        {
            return Ok(c.clone());
        }
        let credential = self.credentials.get(&device.credential).map_err(connect)?;
        let (host, port) = host_port(&device.address, 443).map_err(connect)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = PinVerifier {
            trust: self.trust.clone(),
            address: device.address.clone(),
            provider: provider.clone(),
        };
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| connect(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        let console = Arc::new(Console {
            host,
            port,
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
        let open = async {
            let tcp = TcpStream::connect((console.host.as_str(), console.port))
                .await
                .map_err(|e| connect(e.to_string()))?;
            tcp.set_nodelay(true).map_err(|e| connect(e.to_string()))?;
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
        tokio::time::timeout(self.limits.connect_timeout, open)
            .await
            .map_err(|_| TransportError::Timeout)?
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
            Secret::Key { .. } => {
                return Err(TransportError::Connect(
                    "a private key is not an HTTPS credential".into(),
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
                return Err(TransportError::Command(format!("HTTP {status} for {path}")));
            }
            Err(TransportError::Command(format!(
                "HTTP 401 for {path} after a new login"
            )))
        })
    }
}
