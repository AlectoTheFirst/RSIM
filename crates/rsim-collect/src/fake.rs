//! A transport that replays recorded replies, for the tests, the
//! benchmarks and the seed of the demo estate.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::transport::read_path;
use crate::{BoxFuture, Device, HttpReply, Https, Ssh, TransportError};

type Replies = HashMap<(String, String), Result<Vec<u8>, TransportError>>;

/// A transport with a fixed reply for each device and command. A command
/// with no reply fails. Each call waits for the delay of the transport.
#[derive(Debug, Default)]
pub struct FakeTransport {
    replies: Mutex<Replies>,
    delay: Duration,
    calls: AtomicUsize,
    in_flight: Mutex<BTreeMap<String, usize>>,
    max_devices: AtomicUsize,
    max_per_device: AtomicUsize,
}

impl FakeTransport {
    pub fn new(delay: Duration) -> FakeTransport {
        FakeTransport {
            delay,
            ..FakeTransport::default()
        }
    }

    /// Sets the reply of a command on a device.
    pub fn reply(&self, device: &str, command: &str, reply: Result<Vec<u8>, TransportError>) {
        self.replies
            .lock()
            .expect("the lock is not poisoned")
            .insert((device.to_string(), command.to_string()), reply);
    }

    /// Removes all replies of a device, so each of its commands fails.
    pub fn clear(&self, device: &str) {
        self.replies
            .lock()
            .expect("the lock is not poisoned")
            .retain(|(d, _), _| d != device);
    }

    /// The number of calls.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The largest number of devices with a call in flight at one time.
    pub fn max_devices(&self) -> usize {
        self.max_devices.load(Ordering::SeqCst)
    }

    /// The largest number of calls in flight on one device at one time.
    pub fn max_per_device(&self) -> usize {
        self.max_per_device.load(Ordering::SeqCst)
    }

    async fn call(&self, device: &Device, command: &str) -> Result<Vec<u8>, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        {
            let mut m = self.in_flight.lock().expect("the lock is not poisoned");
            let n = m.entry(device.id.clone()).or_default();
            *n += 1;
            self.max_per_device.fetch_max(*n, Ordering::SeqCst);
            self.max_devices.fetch_max(m.len(), Ordering::SeqCst);
        }
        tokio::time::sleep(self.delay).await;
        {
            let mut m = self.in_flight.lock().expect("the lock is not poisoned");
            let n = m.get_mut(&device.id).expect("the call is in the map");
            *n -= 1;
            if *n == 0 {
                m.remove(&device.id);
            }
        }
        self.replies
            .lock()
            .expect("the lock is not poisoned")
            .get(&(device.id.clone(), command.to_string()))
            .cloned()
            .unwrap_or_else(|| Err(TransportError::Connect("no reply is recorded".into())))
    }
}

impl Ssh for FakeTransport {
    fn run<'a>(
        &'a self,
        device: &'a Device,
        command: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(self.call(device, command))
    }
}

impl Https for FakeTransport {
    fn get<'a>(
        &'a self,
        device: &'a Device,
        path: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(self.call(device, path))
    }

    /// The reply of the command `path` as a body.
    fn get_status<'a>(
        &'a self,
        device: &'a Device,
        path: &'a str,
    ) -> BoxFuture<'a, Result<HttpReply, TransportError>> {
        Box::pin(async move { self.call(device, path).await.map(HttpReply::Body) })
    }

    /// The reply of the command `POST <path> <body>` as a body.
    fn post_read<'a>(
        &'a self,
        device: &'a Device,
        allowed: &'static [&'static str],
        path: &'a str,
        body: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<HttpReply, TransportError>> {
        Box::pin(async move {
            read_path(allowed, path)?;
            self.call(device, &format!("POST {path} {body}"))
                .await
                .map(HttpReply::Body)
        })
    }
}
