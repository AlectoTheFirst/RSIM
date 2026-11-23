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
    /// The device does not have the command or the API path, for example an
    /// HTTP 400 or 404 reply.
    NotFound(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Connect(e) => write!(f, "connect: {e}"),
            TransportError::Command(e) => write!(f, "command: {e}"),
            TransportError::Timeout => f.write_str("timeout"),
            TransportError::NotFound(e) => write!(f, "not found: {e}"),
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

    /// True if each command of the device runs in its own exec session, in
    /// which the device can print its login banner in front of the answer.
    fn banner_each_command(&self, _device: &Device) -> bool {
        false
    }

    /// True if the commands of the device run one at a time. A source then
    /// sends them one after the other, so that the time limit of a command
    /// does not include the wait for the commands before it.
    fn serial(&self, _device: &Device) -> bool {
        false
    }
}

/// The reply of an HTTPS read that gives its status to the source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpReply {
    /// A status from 200 to 299, with the body.
    Body(Vec<u8>),
    /// A status from 400 to 599, with at most [`ERROR_TEXT_CHARS`]
    /// characters of the body on one line.
    Status { status: u16, text: String },
}

/// The largest number of characters of an error body in an [`HttpReply`].
pub const ERROR_TEXT_CHARS: usize = 200;

/// At most [`ERROR_TEXT_CHARS`] characters of a body, with each control
/// character as a space.
pub fn error_text(body: &[u8]) -> String {
    String::from_utf8_lossy(body)
        .chars()
        .take(ERROR_TEXT_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Accepts a POST path only if it is in the read paths of the source.
pub(crate) fn read_path(allowed: &[&str], path: &str) -> Result<(), TransportError> {
    if allowed.contains(&path) {
        Ok(())
    } else {
        Err(TransportError::Command(format!(
            "POST {path} is not a read path of the source"
        )))
    }
}

/// Reads API paths of a console over HTTPS. The transport logs in and keeps
/// the session of each console.
pub trait Https: Send + Sync {
    /// The body of a GET. A 400 or a 404 gives [`TransportError::NotFound`],
    /// and each other status that is not from 200 to 299 gives
    /// [`TransportError::Command`].
    fn get<'a>(
        &'a self,
        device: &'a Device,
        path: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>>;

    /// A GET that gives a status from 400 to 599 to the source.
    fn get_status<'a>(
        &'a self,
        device: &'a Device,
        path: &'a str,
    ) -> BoxFuture<'a, Result<HttpReply, TransportError>>;

    /// A POST of a JSON body to a path that only reads. `allowed` is the
    /// fixed list of read paths of the source: a path outside it is not
    /// sent and gives [`TransportError::Command`]. A status from 400 to 599
    /// goes to the source.
    fn post_read<'a>(
        &'a self,
        device: &'a Device,
        allowed: &'static [&'static str],
        path: &'a str,
        body: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<HttpReply, TransportError>>;
}
