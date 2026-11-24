//! The HTTPS transport for UniFi OS consoles and API servers. It reaches
//! each console directly, through a proxy, or through a chain of SSH jump
//! hosts. It checks the certificate of each console against a pin, a CA
//! bundle, the public roots of `webpki-roots`, or not at all, keeps the
//! login session of each console, and reuses the connections. The devices
//! of one API server share its pace, its connection limit and its wait
//! after a 429.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, UNIX_EPOCH};

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
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::path::Route;
use crate::transport::read_path;
use crate::trust::{
    Credential, Credentials, PinKind, Secret, TrustStore, host_port, plain_address,
};
use crate::tunnel::{HopLimits, Tunnel, stream};
use crate::{BoxFuture, Clock, Device, HttpReply, Https, TokioClock, TransportError, error_text};

/// The wait after a 429 with no `Retry-After` value that the transport
/// reads.
pub const DEFAULT_RETRY_WAIT: Duration = Duration::from_secs(5);

/// The longest wait after a 429.
pub const MAX_RETRY_WAIT: Duration = Duration::from_secs(86_400);

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
    /// The certificate must chain to a public root of `webpki-roots` and
    /// name the host of the console.
    PublicRoots,
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
    /// The largest number of connections to one console that is not an API
    /// server. A request waits for a free connection.
    pub max_connections: usize,
    /// The time for one request and its response body.
    pub request_timeout: Duration,
    /// The retries of a read with a status that goes to the source after a
    /// 429, for a device with no retries of its own.
    pub retries: u32,
}

impl Default for HttpsLimits {
    fn default() -> HttpsLimits {
        HttpsLimits {
            connect_timeout: Duration::from_secs(15),
            handshake_timeout: Duration::from_secs(30),
            keepalive: Duration::from_secs(30),
            max_body: 256 << 20,
            max_connections: 4,
            request_timeout: Duration::from_secs(60),
            retries: 0,
        }
    }
}

/// An HTTPS server that serves more than one device, such as an SD-WAN
/// orchestrator. All devices with its address share its pace and its
/// connection limit, and a jump host on the route to it needs a pinned
/// host key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiServer {
    /// The largest number of requests in flight, of open connections, and
    /// of request starts in one second.
    pub concurrency: usize,
}

/// The idle connections of a console.
type Pool = Mutex<Vec<SendRequest<Full<Bytes>>>>;

/// The state that the consoles of one address share.
struct Server {
    /// The limit of requests in flight to an API server.
    permits: Option<Arc<Semaphore>>,
    /// The connection limit of an API server. Each open connection holds a
    /// permit until it closes.
    connections: Option<Arc<Semaphore>>,
    /// The idle connections of the consoles of the address.
    pools: Mutex<Vec<Weak<Pool>>>,
    /// The least time between 2 request starts of an API server.
    interval: Option<Duration>,
    /// The earliest start of the next request.
    next: Mutex<Instant>,
    /// The end of the wait after a 429.
    hold: Mutex<Option<Instant>>,
}

impl Server {
    fn new(api: Option<ApiServer>) -> Server {
        let concurrency = api.map(|a| a.concurrency.max(1));
        Server {
            permits: concurrency.map(|c| Arc::new(Semaphore::new(c))),
            connections: concurrency.map(|c| Arc::new(Semaphore::new(c))),
            pools: Mutex::new(Vec::new()),
            interval: concurrency
                .map(|c| Duration::from_secs(1) / u32::try_from(c).unwrap_or(u32::MAX)),
            next: Mutex::new(Instant::now()),
            hold: Mutex::new(None),
        }
    }

    /// Adds the idle connections of a console to the connections that
    /// [`Server::connection`] can close.
    fn add_pool(&self, pool: &Arc<Pool>) {
        let mut pools = self.pools.lock().expect("the lock is not poisoned");
        pools.retain(|p| p.strong_count() > 0);
        pools.push(Arc::downgrade(pool));
    }

    /// Closes one idle connection of a console of the address, if a console
    /// has one.
    fn close_idle(&self) {
        let pools = self.pools.lock().expect("the lock is not poisoned");
        for pool in pools.iter().filter_map(Weak::upgrade) {
            let idle = pool.lock().expect("the lock is not poisoned").pop();
            if idle.is_some() {
                return;
            }
        }
    }

    /// The permit of a new connection to an API server, or `None` for a
    /// server that is not an API server. With no free permit, it closes an
    /// idle connection of a console of the address and waits for a
    /// connection to close.
    async fn connection(&self) -> Option<OwnedSemaphorePermit> {
        let limit = self.connections.as_ref()?;
        if let Ok(permit) = limit.clone().try_acquire_owned() {
            return Some(permit);
        }
        self.close_idle();
        Some(
            limit
                .clone()
                .acquire_owned()
                .await
                .expect("the semaphore is not closed"),
        )
    }

    fn held(&self) -> Option<Instant> {
        let hold = *self.hold.lock().expect("the lock is not poisoned");
        hold.filter(|h| *h > Instant::now())
    }

    /// Waits for the end of the wait after a 429, then for the start time
    /// of the request. The start time is reserved under the lock, and the
    /// wait for it is outside the lock.
    async fn ready(&self) {
        loop {
            if let Some(h) = self.held() {
                tokio::time::sleep_until(h).await;
                continue;
            }
            let Some(interval) = self.interval else {
                return;
            };
            let start = {
                let mut next = self.next.lock().expect("the lock is not poisoned");
                let start = (*next).max(Instant::now());
                *next = start + interval;
                start
            };
            tokio::time::sleep_until(start).await;
            if self.held().is_none() {
                return;
            }
        }
    }

    /// Holds each request until `wait` from now.
    fn hold_for(&self, wait: Duration) {
        let until = Instant::now() + wait;
        let mut hold = self.hold.lock().expect("the lock is not poisoned");
        if (*hold).is_none_or(|h| h < until) {
            *hold = Some(until);
        }
    }
}

/// The wait that the headers of a 429 give: `Retry-After` in seconds or as
/// an HTTP date against `now_ms`, else [`DEFAULT_RETRY_WAIT`], and at most
/// [`MAX_RETRY_WAIT`].
fn retry_wait(headers: &header::HeaderMap, now_ms: u64) -> Duration {
    let value = headers
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let wait = match value {
        None => DEFAULT_RETRY_WAIT,
        Some(v) => {
            if let Ok(seconds) = v.parse::<u64>() {
                Duration::from_secs(seconds)
            } else if let Ok(at) = httpdate::parse_http_date(v) {
                let at_ms = at
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                Duration::from_millis(at_ms.saturating_sub(now_ms))
            } else {
                DEFAULT_RETRY_WAIT
            }
        }
    };
    wait.min(MAX_RETRY_WAIT)
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
        TlsTrust::PublicRoots => {
            let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
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
    idle: Arc<Pool>,
    max_idle: usize,
    permits: Arc<Semaphore>,
    server: Arc<Server>,
    /// True if each jump host of the route needs a pinned host key.
    pinned_jumps: bool,
}

/// A console is one address with one credential, one route and one TLS
/// profile.
type ConsoleKey = (String, String, Route, HttpsProfile);

/// An HTTPS transport over `hyper` and `rustls` with the `ring` provider.
pub struct HttpsTransport {
    credentials: Arc<dyn Credentials>,
    trust: Arc<TrustStore>,
    limits: HttpsLimits,
    clock: Arc<dyn Clock>,
    default_profile: HttpsProfile,
    profiles: HashMap<String, HttpsProfile>,
    retries: HashMap<String, u32>,
    request_timeouts: HashMap<String, Duration>,
    api_servers: HashMap<String, ApiServer>,
    servers: Mutex<HashMap<String, Arc<Server>>>,
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
            clock: Arc::new(TokioClock::system()),
            default_profile: HttpsProfile::default(),
            profiles: HashMap::new(),
            retries: HashMap::new(),
            request_timeouts: HashMap::new(),
            api_servers: HashMap::new(),
            servers: Mutex::new(HashMap::new()),
            consoles: Mutex::new(HashMap::new()),
        }
    }

    /// Sets the clock that reads the HTTP date of `Retry-After`.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> HttpsTransport {
        self.clock = clock;
        self
    }

    /// Sets the retries after a 429 of a device.
    pub fn with_retries(mut self, device: &str, retries: u32) -> HttpsTransport {
        self.retries.insert(device.to_string(), retries);
        self
    }

    /// Sets the time for one request of a device and its response body.
    pub fn with_request_timeout(mut self, device: &str, timeout: Duration) -> HttpsTransport {
        self.request_timeouts.insert(device.to_string(), timeout);
        self
    }

    /// The time for one request of a device.
    fn request_timeout(&self, device: &Device) -> Duration {
        self.request_timeouts
            .get(&device.id)
            .copied()
            .unwrap_or(self.limits.request_timeout)
    }

    /// Makes the server at `address` an API server, which the devices with
    /// that address share.
    pub fn with_api_server(mut self, address: &str, server: ApiServer) -> HttpsTransport {
        let address = plain_address(address, "https").unwrap_or(address);
        self.api_servers.insert(address.to_string(), server);
        self
    }

    /// The shared state of the consoles of an address.
    fn server(&self, address: &str) -> Arc<Server> {
        let api = self.api_servers.get(address).copied();
        self.servers
            .lock()
            .expect("the lock is not poisoned")
            .entry(address.to_string())
            .or_insert_with(|| Arc::new(Server::new(api)))
            .clone()
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
        let api = self.api_servers.get(address);
        let max_idle = api
            .map_or(self.limits.max_connections, |a| a.concurrency)
            .max(1);
        let server = self.server(address);
        let permits = server
            .permits
            .clone()
            .unwrap_or_else(|| Arc::new(Semaphore::new(max_idle)));
        let idle = Arc::new(Mutex::new(Vec::new()));
        server.add_pool(&idle);
        let console = Arc::new(Console {
            host,
            port,
            route: route.clone(),
            tunnel: tokio::sync::Mutex::new(None),
            credential,
            tls: TlsConnector::from(Arc::new(config)),
            session: tokio::sync::Mutex::new(Session::default()),
            idle,
            max_idle,
            permits,
            server,
            pinned_jumps: api.is_some(),
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
        let permit = console.server.connection().await;
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
            Ok((sender, conn))
        };
        let r = tokio::time::timeout(self.limits.connect_timeout, open)
            .await
            .map_err(|_| TransportError::Timeout)
            .and_then(|r| r);
        match r {
            Ok((sender, conn)) => {
                tokio::spawn(async move {
                    let _permit = permit;
                    conn.await
                });
                Ok((sender, false))
            }
            Err(e) => {
                if let Some(t) = tunnel {
                    let mut g = console.tunnel.lock().await;
                    if g.as_ref().is_some_and(|c| Arc::ptr_eq(c, &t)) {
                        *g = None;
                    }
                    drop(g);
                    t.close().await;
                }
                Err(e)
            }
        }
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
            console.pinned_jumps,
        )
        .await
        .map_err(TransportError::Connect)?;
        let t = Arc::new(t);
        *g = Some(t.clone());
        Ok(Some(t))
    }

    /// Sends a request on a free connection after the wait of the server,
    /// and reads the response within `timeout`.
    async fn send(
        &self,
        console: &Console,
        request: Request<Full<Bytes>>,
        timeout: Duration,
    ) -> Result<(StatusCode, header::HeaderMap, Bytes), TransportError> {
        let failed = |e: String| TransportError::Command(e);
        let _permit = console
            .permits
            .acquire()
            .await
            .expect("the semaphore is not closed");
        console.server.ready().await;
        let (mut sender, reused) = self.sender(console, false).await?;
        let retry = reused.then(|| clone_request(&request));
        let exchange = async {
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
            Ok::<_, TransportError>((parts, body))
        };
        let (parts, body) = tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| TransportError::Timeout)??;
        let mut idle = console.idle.lock().expect("the lock is not poisoned");
        if !sender.is_closed() && idle.len() < console.max_idle {
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
            Secret::Token(token) => vec![(header::AUTHORIZATION, format!("Token {token}"))],
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
                let (status, headers, _) =
                    self.send(console, req, self.limits.request_timeout).await?;
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

    /// A read whose status from 400 to 599 goes to the source. A 401 with
    /// a password gives one new login. A 429 holds each request to the
    /// server for the wait of `Retry-After`, and the read tries again while
    /// the device has retries.
    async fn read(
        &self,
        device: &Device,
        method: Method,
        path: &str,
        body: Bytes,
    ) -> Result<HttpReply, TransportError> {
        let console = self.console(device)?;
        let timeout = self.request_timeout(device);
        let mut retries = self
            .retries
            .get(&device.id)
            .copied()
            .unwrap_or(self.limits.retries);
        let (mut headers, mut generation) = self.login(&console, None).await?;
        let mut login_again = matches!(console.credential.secret, Secret::Password(_));
        loop {
            let req = Self::request(&console, method.clone(), path, &headers, body.clone())?;
            let (status, reply_headers, reply) = self.send(&console, req, timeout).await?;
            if status.is_success() {
                return Ok(HttpReply::Body(reply.to_vec()));
            }
            if status == StatusCode::UNAUTHORIZED && login_again {
                login_again = false;
                (headers, generation) = self.login(&console, Some(generation)).await?;
                continue;
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                let wait = retry_wait(&reply_headers, self.clock.now_ms());
                console.server.hold_for(wait);
                if retries > 0 {
                    retries -= 1;
                    continue;
                }
            }
            if status.is_client_error() || status.is_server_error() {
                return Ok(HttpReply::Status {
                    status: status.as_u16(),
                    text: error_text(&reply),
                });
            }
            return Err(TransportError::Command(format!("HTTP {status} for {path}")));
        }
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
            let timeout = self.request_timeout(device);
            let (mut headers, mut generation) = self.login(&console, None).await?;
            for attempt in 0..2 {
                let req = Self::request(&console, Method::GET, path, &headers, Bytes::new())?;
                let (status, _, body) = self.send(&console, req, timeout).await?;
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

    fn get_status<'a>(
        &'a self,
        device: &'a Device,
        path: &'a str,
    ) -> BoxFuture<'a, Result<HttpReply, TransportError>> {
        Box::pin(self.read(device, Method::GET, path, Bytes::new()))
    }

    fn post_read<'a>(
        &'a self,
        device: &'a Device,
        allowed: &'static [&'static str],
        path: &'a str,
        body: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<HttpReply, TransportError>> {
        Box::pin(async move {
            read_path(allowed, path)?;
            let body = Bytes::from(body.to_string());
            self.read(device, Method::POST, path, body).await
        })
    }
}

#[cfg(test)]
mod tests {
    use futures_util::future::join_all;

    use super::*;
    use crate::{DEFAULT_INTERVAL, MemoryCredentials, PinPolicy, Vendor};

    /// 2026-11-23 08:00:00 UTC in milliseconds since the Unix epoch.
    const CLOCK_MS: u64 = 1_795_420_800_000;

    fn api_server() -> Arc<Server> {
        Arc::new(Server::new(Some(ApiServer { concurrency: 4 })))
    }

    /// The time from `t0` at which `ready` returns, for each server in
    /// order.
    async fn starts(servers: Vec<Arc<Server>>, t0: Instant) -> Vec<Duration> {
        join_all(servers.iter().map(|s| async move {
            s.ready().await;
            Instant::now() - t0
        }))
        .await
    }

    fn ms(values: &[u64]) -> Vec<Duration> {
        values.iter().map(|v| Duration::from_millis(*v)).collect()
    }

    fn retry_after(value: &str) -> header::HeaderMap {
        let mut h = header::HeaderMap::new();
        h.insert(
            header::RETRY_AFTER,
            header::HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    fn device(id: &str, credential: &str) -> Device {
        Device {
            id: id.into(),
            vendor: Vendor::Unifi,
            address: "192.0.2.10".into(),
            credential: credential.into(),
            site: None,
            capture_bgp: Default::default(),
            route: Default::default(),
            interval: DEFAULT_INTERVAL,
        }
    }

    #[test]
    fn retry_after_gives_the_wait_of_a_429() {
        let wait = |value| retry_wait(&retry_after(value), CLOCK_MS);
        assert_eq!(wait("7"), Duration::from_secs(7));
        assert_eq!(
            wait("Mon, 23 Nov 2026 08:00:02 GMT"),
            Duration::from_secs(2)
        );
        assert_eq!(wait("Mon, 23 Nov 2026 07:59:00 GMT"), Duration::ZERO);
        assert_eq!(wait("soon"), DEFAULT_RETRY_WAIT);
        assert_eq!(wait("31536000"), MAX_RETRY_WAIT);
        assert_eq!(
            retry_wait(&header::HeaderMap::new(), CLOCK_MS),
            DEFAULT_RETRY_WAIT
        );
    }

    #[tokio::test(start_paused = true)]
    async fn concurrency_4_starts_a_request_each_250_ms() {
        let t0 = Instant::now();
        let server = api_server();
        assert_eq!(
            starts(vec![server; 8], t0).await,
            ms(&[0, 250, 500, 750, 1000, 1250, 1500, 1750])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn two_devices_of_one_api_server_share_its_pace() {
        let t0 = Instant::now();
        let mut c = MemoryCredentials::new();
        for name in ["lab", "lab2"] {
            c.insert(
                name,
                Credential {
                    user: String::new(),
                    secret: Secret::Token("tok-velo".into()),
                },
            );
        }
        let t = HttpsTransport::new(
            Arc::new(c),
            Arc::new(TrustStore::memory(PinPolicy::Strict)),
            HttpsLimits::default(),
        )
        .with_api_server("192.0.2.10", ApiServer { concurrency: 4 });
        let one = t.console(&device("velocloud/e1", "lab")).unwrap();
        let two = t.console(&device("velocloud/e2", "lab2")).unwrap();
        assert!(!Arc::ptr_eq(&one, &two));
        assert!(Arc::ptr_eq(&one.server, &two.server));
        let servers: Vec<Arc<Server>> = (0..8)
            .map(|i| (if i % 2 == 0 { &one } else { &two }).server.clone())
            .collect();
        assert_eq!(
            starts(servers, t0).await,
            ms(&[0, 250, 500, 750, 1000, 1250, 1500, 1750])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_429_with_no_retry_after_holds_4_workers_for_5_s() {
        let t0 = Instant::now();
        let server = api_server();
        server.hold_for(retry_wait(&header::HeaderMap::new(), CLOCK_MS));
        assert_eq!(
            starts(vec![server; 4], t0).await,
            ms(&[5000, 5250, 5500, 5750])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_429_holds_a_request_that_waits_for_its_start() {
        let t0 = Instant::now();
        let server = api_server();
        server.ready().await;
        let s = server.clone();
        let waiting = tokio::spawn(async move {
            s.ready().await;
            Instant::now() - t0
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        server.hold_for(Duration::from_secs(1));
        assert_eq!(waiting.await.unwrap(), Duration::from_millis(1100));
    }
}
