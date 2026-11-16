use std::fmt;
use std::future::Future;
use std::pin::Pin;

use crate::Device;

/// A future that a trait object can return.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An error of a transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The device did not accept a session.
    Connect(String),
    /// The session is open, and the command or the request failed.
    Command(String),
    /// The command did not finish in its time.
    Timeout,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Connect(e) => write!(f, "connect: {e}"),
            TransportError::Command(e) => write!(f, "command: {e}"),
            TransportError::Timeout => f.write_str("timeout"),
        }
    }
}

/// Runs read-only commands on a device over SSH. One session serves all
/// commands of a device, and the commands can run at the same time.
pub trait Ssh: Send + Sync {
    fn run<'a>(
        &'a self,
        device: &'a Device,
        command: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>;
}

/// Reads API paths of a console over HTTPS. The transport logs in and keeps
/// the session of each console.
pub trait Https: Send + Sync {
    fn get<'a>(
        &'a self,
        device: &'a Device,
        path: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>;
}
