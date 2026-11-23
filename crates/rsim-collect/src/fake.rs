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
/// An HTTPS read can also reply with a status from 400 to 599.
#[derive(Debug, Default)]
pub struct FakeTransport {
    replies: Mutex<Replies>,
    statuses: Mutex<HashMap<(String, String), (u16, String)>>,
    log: Mutex<Vec<(String, String)>>,
    delay: Duration,
    calls: AtomicUsize,
    in_flight: Mutex<BTreeMap<String, usize>>,
    max_devices: AtomicUsize,
    max_per_device: AtomicUsize,
    max_calls: AtomicUsize,
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
        let key = (device.to_string(), command.to_string());
        self.statuses
            .lock()
            .expect("the lock is not poisoned")
            .remove(&key);
        self.replies
            .lock()
            .expect("the lock is not poisoned")
            .insert(key, reply);
    }

    /// Sets a status from 400 to 599 with its text as the reply of an
    /// HTTPS read of a command on a device.
    pub fn reply_status(&self, device: &str, command: &str, status: u16, text: &str) {
        self.statuses
            .lock()
            .expect("the lock is not poisoned")
            .insert(
                (device.to_string(), command.to_string()),
                (status, text.to_string()),
            );
    }

    /// Removes all replies of a device, so each of its commands fails.
    pub fn clear(&self, device: &str) {
        self.replies
            .lock()
            .expect("the lock is not poisoned")
            .retain(|(d, _), _| d != device);
        self.statuses
            .lock()
            .expect("the lock is not poisoned")
            .retain(|(d, _), _| d != device);
    }

    /// The device and the command of each call, in the order of the calls.
    pub fn log(&self) -> Vec<(String, String)> {
        self.log.lock().expect("the lock is not poisoned").clone()
    }

    /// Empties the log of the calls.
    pub fn clear_log(&self) {
        self.log.lock().expect("the lock is not poisoned").clear();
    }

    /// The largest number of calls in flight at one time, on all devices.
    pub fn max_calls(&self) -> usize {
        self.max_calls.load(Ordering::SeqCst)
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

    /// Counts and logs a call and waits for the delay.
    async fn wait(&self, device: &Device, command: &str) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.log
            .lock()
            .expect("the lock is not poisoned")
            .push((device.id.clone(), command.to_string()));
        {
            let mut m = self.in_flight.lock().expect("the lock is not poisoned");
            let n = m.entry(device.id.clone()).or_default();
            *n += 1;
            self.max_per_device.fetch_max(*n, Ordering::SeqCst);
            self.max_devices.fetch_max(m.len(), Ordering::SeqCst);
            self.max_calls.fetch_max(m.values().sum(), Ordering::SeqCst);
        }
        tokio::time::sleep(self.delay).await;
        let mut m = self.in_flight.lock().expect("the lock is not poisoned");
        let n = m.get_mut(&device.id).expect("the call is in the map");
        *n -= 1;
        if *n == 0 {
            m.remove(&device.id);
        }
    }

    async fn call(&self, device: &Device, command: &str) -> Result<Vec<u8>, TransportError> {
        self.wait(device, command).await;
        self.reply_of(device, command)
    }

    fn reply_of(&self, device: &Device, command: &str) -> Result<Vec<u8>, TransportError> {
        self.replies
            .lock()
            .expect("the lock is not poisoned")
            .get(&(device.id.clone(), command.to_string()))
            .cloned()
            .unwrap_or_else(|| Err(TransportError::Connect("no reply is recorded".into())))
    }

    /// The status of a command, else its reply as a body.
    async fn status_call(
        &self,
        device: &Device,
        command: &str,
    ) -> Result<HttpReply, TransportError> {
        self.wait(device, command).await;
        let status = self
            .statuses
            .lock()
            .expect("the lock is not poisoned")
            .get(&(device.id.clone(), command.to_string()))
            .cloned();
        match status {
            Some((status, text)) => Ok(HttpReply::Status { status, text }),
            None => self.reply_of(device, command).map(HttpReply::Body),
        }
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

    /// The status of the command `path`, else its reply as a body.
    fn get_status<'a>(
        &'a self,
        device: &'a Device,
        path: &'a str,
    ) -> BoxFuture<'a, Result<HttpReply, TransportError>> {
        Box::pin(self.status_call(device, path))
    }

    /// The status of the command `POST <path> <body>`, else its reply as a
    /// body. The body is the compact JSON text with sorted keys.
    fn post_read<'a>(
        &'a self,
        device: &'a Device,
        allowed: &'static [&'static str],
        path: &'a str,
        body: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<HttpReply, TransportError>> {
        Box::pin(async move {
            read_path(allowed, path)?;
            self.status_call(device, &format!("POST {path} {body}"))
                .await
        })
    }
}
