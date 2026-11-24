//! The SSH transport. It reaches each device directly, through a proxy, or
//! through a chain of jump hosts, and runs the commands of a device in one
//! of 3 command modes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg, Disconnect};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::cli::{SHELL_HEIGHT, SHELL_WIDTH, at_prompt, echo_line, output_of, prompt_of, sanitize};
pub use crate::path::Algorithms;
use crate::trust::{Credentials, TrustStore, host_port, plain_address};
use crate::tunnel::{Client, Hop, HopLimits, Tunnel, login, stream};
use crate::{BoxFuture, Device, Ssh, TransportError};

/// How the commands of a device reach the device.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CommandMode {
    /// An exec channel for each command on one connection. The commands
    /// run at the same time, up to the channel limit of the profile.
    #[default]
    Exec,
    /// One interactive shell with a terminal for all commands. The prompt
    /// of the device ends each answer, so the commands run one at a time.
    /// The login banner comes once and is dropped.
    Shell,
    /// A new connection with one exec channel for each command, for a
    /// device that closes the connection after one command. The commands
    /// run one at a time.
    Connection,
}

/// The connection settings of a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshProfile {
    pub algorithms: Algorithms,
    /// The largest number of exec channels open at one time on the
    /// connection in the exec mode.
    pub max_channels: usize,
    pub mode: CommandMode,
    /// The commands that a shell runs after the login, for example
    /// `terminal length 0`. A rejection of a setup command is ignored.
    pub shell_setup: Vec<String>,
}

impl Default for SshProfile {
    fn default() -> SshProfile {
        SshProfile {
            algorithms: Algorithms::Modern,
            max_channels: 8,
            mode: CommandMode::Exec,
            shell_setup: Vec::new(),
        }
    }
}

/// The limits of the SSH transport. The connect time and the handshake
/// time apply to each hop of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SshLimits {
    /// The TCP connection with the proxy handshake, or the opening of the
    /// channel through a jump host.
    pub connect_timeout: Duration,
    /// The key exchange and the login of one hop, and the prompt of a
    /// shell.
    pub handshake_timeout: Duration,
    /// A connection that no command used for this time is closed.
    pub idle_timeout: Duration,
    /// The interval of the keepalive on the connection to the device.
    pub keepalive: Duration,
    /// The largest output of one command. A larger output is an error.
    pub max_output: usize,
}

impl Default for SshLimits {
    fn default() -> SshLimits {
        SshLimits {
            connect_timeout: Duration::from_secs(15),
            handshake_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            keepalive: Duration::from_secs(30),
            max_output: 256 << 20,
        }
    }
}

impl SshLimits {
    fn hops(&self) -> HopLimits {
        HopLimits {
            connect: self.connect_timeout,
            handshake: self.handshake_timeout,
            keepalive: self.keepalive,
        }
    }
}

/// The time that a shell waits for more output before it takes a burst
/// with no prompt as complete.
const SHELL_QUIET: Duration = Duration::from_secs(1);
/// The number of newlines that a shell sends until the prompt is the same
/// twice.
const PROMPT_TRIES: usize = 3;
/// The bytes at the end of a shell read in which the prompt can be.
const PROMPT_TAIL: usize = 4096;

/// An interactive shell. `busy` is true from the send of a command until
/// its prompt. A shell that is busy at the start of a command lost its
/// place in the stream and is not used again.
struct Shell {
    channel: Channel<Msg>,
    prompt: String,
    busy: bool,
}

struct Conn {
    handle: Handle<Client>,
    tunnel: Option<Tunnel>,
    channels: Arc<Semaphore>,
    max_channels: usize,
    shell: tokio::sync::Mutex<Option<Shell>>,
    used: Mutex<Instant>,
}

impl Conn {
    fn touch(&self) {
        *self.used.lock().expect("the lock is not poisoned") = Instant::now();
    }

    fn closed(&self) -> bool {
        self.handle.is_closed() || self.tunnel.as_ref().is_some_and(Tunnel::is_closed)
    }

    async fn close(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        if let Some(t) = &self.tunnel {
            t.close().await;
        }
    }
}

type Slot = Arc<tokio::sync::Mutex<Option<Arc<Conn>>>>;

/// An SSH transport over `russh`.
pub struct SshTransport {
    credentials: Arc<dyn Credentials>,
    trust: Arc<TrustStore>,
    limits: SshLimits,
    default_profile: SshProfile,
    profiles: HashMap<String, SshProfile>,
    slots: Mutex<HashMap<String, Slot>>,
    serial: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

enum ExecError {
    /// The channel did not open. A new connection can help.
    Channel(String),
    Transport(TransportError),
}

impl SshTransport {
    pub fn new(
        credentials: Arc<dyn Credentials>,
        trust: Arc<TrustStore>,
        limits: SshLimits,
    ) -> SshTransport {
        SshTransport {
            credentials,
            trust,
            limits,
            default_profile: SshProfile::default(),
            profiles: HashMap::new(),
            slots: Mutex::new(HashMap::new()),
            serial: Mutex::new(HashMap::new()),
        }
    }

    /// Sets the profile of the devices with no profile of their own.
    pub fn with_default_profile(mut self, profile: SshProfile) -> SshTransport {
        self.default_profile = profile;
        self
    }

    /// Sets the profile of a device.
    pub fn with_profile(mut self, device: &str, profile: SshProfile) -> SshTransport {
        self.profiles.insert(device.to_string(), profile);
        self
    }

    fn profile(&self, device: &Device) -> &SshProfile {
        self.profiles
            .get(&device.id)
            .unwrap_or(&self.default_profile)
    }

    /// Closes the connection of a device, if it has one.
    pub async fn close(&self, device: &str) {
        let slot = self
            .slots
            .lock()
            .expect("the lock is not poisoned")
            .remove(device);
        if let Some(slot) = slot
            && let Some(conn) = slot.lock().await.take()
        {
            conn.close().await;
        }
    }

    fn slot(&self, device: &Device) -> Slot {
        self.slots
            .lock()
            .expect("the lock is not poisoned")
            .entry(device.id.clone())
            .or_default()
            .clone()
    }

    fn serial(&self, device: &Device) -> Arc<tokio::sync::Mutex<()>> {
        self.serial
            .lock()
            .expect("the lock is not poisoned")
            .entry(device.id.clone())
            .or_default()
            .clone()
    }

    /// The connection of a device. A new connection gets a task that
    /// closes it after the idle time.
    async fn connection(&self, device: &Device) -> Result<Arc<Conn>, TransportError> {
        let slot = self.slot(device);
        let mut guard = slot.lock().await;
        if let Some(conn) = guard.as_ref()
            && !conn.closed()
        {
            conn.touch();
            return Ok(conn.clone());
        }
        if let Some(old) = guard.take() {
            old.close().await;
        }
        let conn = Arc::new(self.connect(device).await?);
        *guard = Some(conn.clone());
        drop(guard);
        let idle = self.limits.idle_timeout;
        let weak_slot = Arc::downgrade(&slot);
        let weak = Arc::downgrade(&conn);
        tokio::spawn(async move {
            loop {
                let Some(conn) = weak.upgrade() else { return };
                let idle_now = |c: &Conn| {
                    let used = *c.used.lock().expect("the lock is not poisoned");
                    c.channels.available_permits() == c.max_channels
                        && c.shell.try_lock().is_ok()
                        && used.elapsed() >= idle
                };
                if idle_now(&conn) {
                    let Some(slot) = weak_slot.upgrade() else {
                        return;
                    };
                    let mut g = slot.lock().await;
                    if !idle_now(&conn) {
                        continue;
                    }
                    if g.as_ref().is_some_and(|c| Arc::ptr_eq(c, &conn)) {
                        *g = None;
                    }
                    drop(g);
                    conn.close().await;
                    return;
                }
                if conn.closed() {
                    return;
                }
                let used = *conn.used.lock().expect("the lock is not poisoned");
                let wait = idle
                    .saturating_sub(used.elapsed())
                    .max(Duration::from_secs(1));
                drop(conn);
                tokio::time::sleep(wait).await;
            }
        });
        Ok(conn)
    }

    /// Removes a connection from its slot. The commands that still use it
    /// keep it, and it closes when the last of them drops it.
    async fn forget(&self, device: &Device, conn: &Arc<Conn>) {
        let slot = self.slot(device);
        let mut guard = slot.lock().await;
        if guard.as_ref().is_some_and(|c| Arc::ptr_eq(c, conn)) {
            *guard = None;
        }
    }

    /// Logs in to the jump hosts of the route and then to the device.
    async fn connect(&self, device: &Device) -> Result<Conn, TransportError> {
        let connect = |e: String| TransportError::Connect(e);
        let profile = self.profile(device);
        let route = &device.route;
        let limits = self.limits.hops();
        let credential = self
            .credentials
            .get(&device.credential)
            .map_err(|e| connect(format!("device {}: {e}", device.address)))?;
        let address = plain_address(&device.address, "ssh")
            .map_err(|e| connect(format!("device {}: {e}", device.address)))?;
        let (host, port) = host_port(address, 22)
            .map_err(|e| connect(format!("device {}: {e}", device.address)))?;
        let tunnel = if route.jumps.is_empty() {
            None
        } else {
            Some(
                Tunnel::connect(
                    route,
                    self.credentials.as_ref(),
                    &self.trust,
                    limits,
                    false,
                    false,
                )
                .await
                .map_err(connect)?,
            )
        };
        let hop = Hop {
            role: "device",
            address,
            pin: route.pin_name(route.jumps.len(), address),
            pinned: false,
            credential,
            algorithms: profile.algorithms,
            last: true,
        };
        let name = format!("device {}", device.address);
        let handle = login(&hop, &self.trust, limits, || {
            let host = host.clone();
            let name = name.clone();
            let tunnel = tunnel.as_ref();
            async move {
                stream(route, tunnel, &host, port, limits.connect)
                    .await
                    .map_err(|e| {
                        if tunnel.is_some() {
                            e
                        } else {
                            format!("{name}: {e}")
                        }
                    })
            }
        })
        .await;
        let handle = match handle {
            Ok(h) => h,
            Err(e) => {
                if let Some(t) = &tunnel {
                    t.close().await;
                }
                return Err(connect(e));
            }
        };
        let max = profile.max_channels.max(1);
        Ok(Conn {
            handle,
            tunnel,
            channels: Arc::new(Semaphore::new(max)),
            max_channels: max,
            shell: tokio::sync::Mutex::new(None),
            used: Mutex::new(Instant::now()),
        })
    }

    async fn exec(
        &self,
        conn: &Conn,
        _permit: Option<OwnedSemaphorePermit>,
        command: &str,
    ) -> Result<Vec<u8>, ExecError> {
        let mut channel = conn
            .handle
            .channel_open_session()
            .await
            .map_err(|e| ExecError::Channel(e.to_string()))?;
        let failed = |e: String| ExecError::Transport(TransportError::Command(e));
        channel
            .exec(true, command)
            .await
            .map_err(|e| failed(e.to_string()))?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut status = None;
        let mut ended = false;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    if stdout.len() + data.len() > self.limits.max_output {
                        let _ = channel.close().await;
                        return Err(failed(format!(
                            "the output is larger than {} bytes",
                            self.limits.max_output
                        )));
                    }
                    stdout.extend_from_slice(&data);
                }
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    if stderr.len() < 4096 {
                        stderr.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Eof | ChannelMsg::Close => ended = true,
                ChannelMsg::Failure => {
                    return Err(failed("the device did not accept the exec request".into()));
                }
                _ => {}
            }
        }
        conn.touch();
        match status {
            Some(0) => Ok(stdout),
            None if ended => Ok(stdout),
            None => Err(failed(
                "the connection closed before the command ended".into(),
            )),
            Some(code) => Err(failed(format!(
                "exit status {code}: {}",
                failure_text(&stderr, &stdout)
            ))),
        }
    }

    async fn run_exec(&self, device: &Device, command: &str) -> Result<Vec<u8>, TransportError> {
        let mut last = String::new();
        for _ in 0..2 {
            let conn = self.connection(device).await?;
            let permit = conn
                .channels
                .clone()
                .acquire_owned()
                .await
                .expect("the semaphore is not closed");
            match self.exec(&conn, Some(permit), command).await {
                Ok(out) => return Ok(out),
                Err(ExecError::Transport(e)) => return Err(e),
                Err(ExecError::Channel(e)) => {
                    self.forget(device, &conn).await;
                    last = e;
                }
            }
        }
        Err(TransportError::Connect(format!(
            "device {}: no channel opens: {last}",
            device.address
        )))
    }

    async fn run_connection(
        &self,
        device: &Device,
        command: &str,
    ) -> Result<Vec<u8>, TransportError> {
        let serial = self.serial(device);
        let _one = serial.lock().await;
        let conn = self.connect(device).await?;
        let out = self.exec(&conn, None, command).await;
        conn.close().await;
        match out {
            Ok(o) => Ok(o),
            Err(ExecError::Transport(e)) => Err(e),
            Err(ExecError::Channel(e)) => Err(TransportError::Connect(format!(
                "device {}: no channel opens: {e}",
                device.address
            ))),
        }
    }

    async fn run_shell(&self, device: &Device, command: &str) -> Result<Vec<u8>, TransportError> {
        let conn = self.connection(device).await?;
        let mut guard = conn.shell.lock().await;
        if guard.as_ref().is_some_and(|s| s.busy)
            && let Some(old) = guard.take()
        {
            let _ = old.channel.close().await;
        }
        if guard.is_none() {
            match self.open_shell(&conn, device).await {
                Ok(s) => *guard = Some(s),
                Err(e) => {
                    drop(guard);
                    self.forget(device, &conn).await;
                    return Err(e);
                }
            }
        }
        let shell = guard.as_mut().expect("the shell is open");
        let out = shell_command(shell, command, self.limits.max_output).await;
        conn.touch();
        if out.is_err()
            && let Some(old) = guard.take()
        {
            let _ = old.channel.close().await;
        }
        out.map(String::into_bytes)
    }

    /// Opens a shell with a terminal, learns its prompt and runs the setup
    /// commands.
    async fn open_shell(&self, conn: &Conn, device: &Device) -> Result<Shell, TransportError> {
        let name = format!("device {}", device.address);
        let connect = |e: String| TransportError::Connect(format!("{name}: {e}"));
        let channel = conn
            .handle
            .channel_open_session()
            .await
            .map_err(|e| connect(format!("no shell channel: {e}")))?;
        channel
            .request_pty(true, "vt100", SHELL_WIDTH, SHELL_HEIGHT, 0, 0, &[])
            .await
            .map_err(|e| connect(format!("no terminal: {e}")))?;
        channel
            .request_shell(true)
            .await
            .map_err(|e| connect(format!("no shell: {e}")))?;
        let mut shell = Shell {
            channel,
            prompt: String::new(),
            busy: true,
        };
        let learn = learn_prompt(&mut shell, self.limits.max_output);
        shell.prompt = tokio::time::timeout(self.limits.handshake_timeout, learn)
            .await
            .map_err(|_| connect(format!("no prompt in {:?}", self.limits.handshake_timeout)))?
            .map_err(|e| connect(e.to_string()))?;
        shell.busy = false;
        for setup in &self.profile(device).shell_setup {
            let run = shell_command(&mut shell, setup, self.limits.max_output);
            tokio::time::timeout(self.limits.handshake_timeout, run)
                .await
                .map_err(|_| connect(format!("the setup command {setup:?} did not end")))?
                .map_err(|e| connect(format!("the setup command {setup:?}: {e}")))?;
        }
        Ok(shell)
    }
}

/// The text of a failed exec command: the error output, or else the first
/// line of the output that is not empty, at most 200 characters.
fn failure_text(stderr: &[u8], stdout: &[u8]) -> String {
    let err = String::from_utf8_lossy(stderr);
    let err = err.trim();
    if !err.is_empty() {
        return err.chars().take(512).collect();
    }
    let out = String::from_utf8_lossy(stdout);
    out.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}

/// The next data of a shell. `None` after the quiet time with no data.
async fn shell_read(
    channel: &mut Channel<Msg>,
    quiet: Option<Duration>,
) -> Result<Option<Vec<u8>>, TransportError> {
    loop {
        let msg = match quiet {
            Some(q) => match tokio::time::timeout(q, channel.wait()).await {
                Ok(m) => m,
                Err(_) => return Ok(None),
            },
            None => channel.wait().await,
        };
        match msg {
            Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                return Ok(Some(data.to_vec()));
            }
            Some(ChannelMsg::Failure) => {
                return Err(TransportError::Command(
                    "the device refused the terminal or the shell".into(),
                ));
            }
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {
                return Err(TransportError::Command(
                    "the device closed the shell".into(),
                ));
            }
            Some(_) => {}
        }
    }
}

fn tail(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(PROMPT_TAIL);
    sanitize(&String::from_utf8_lossy(&bytes[start..]))
}

/// The output up to a line with the form of a prompt, or up to a quiet
/// time after some output.
async fn burst(shell: &mut Shell, max: usize) -> Result<String, TransportError> {
    let mut buf = Vec::new();
    loop {
        if prompt_of(&tail(&buf)).is_some() {
            break;
        }
        match shell_read(&mut shell.channel, Some(SHELL_QUIET)).await? {
            Some(d) => {
                if buf.len() + d.len() > max {
                    return Err(TransportError::Command(format!(
                        "the output before the prompt is larger than {max} bytes"
                    )));
                }
                buf.extend_from_slice(&d);
            }
            None if !buf.is_empty() => break,
            None => {}
        }
    }
    Ok(sanitize(&String::from_utf8_lossy(&buf)))
}

/// Drops the login output, then sends newlines until the device gives the
/// same prompt twice. A banner line comes only once, so it cannot be the
/// prompt.
async fn learn_prompt(shell: &mut Shell, max: usize) -> Result<String, TransportError> {
    burst(shell, max).await?;
    let mut seen = String::new();
    for _ in 0..PROMPT_TRIES {
        shell
            .channel
            .data(&b"\n"[..])
            .await
            .map_err(|e| TransportError::Command(e.to_string()))?;
        let prompt = prompt_of(&burst(shell, max).await?).unwrap_or_default();
        if !prompt.is_empty() && prompt == seen {
            return Ok(prompt);
        }
        seen = prompt;
    }
    Err(TransportError::Command(format!(
        "the prompt did not settle in {PROMPT_TRIES} newlines; the last line was {seen:?}"
    )))
}

/// Sends a command to a shell and reads its answer up to the prompt.
async fn shell_command(
    shell: &mut Shell,
    command: &str,
    max: usize,
) -> Result<String, TransportError> {
    shell.busy = true;
    shell
        .channel
        .data(format!("{command}\n").as_bytes())
        .await
        .map_err(|e| TransportError::Command(e.to_string()))?;
    let mut buf = Vec::new();
    let mut echo = false;
    while !(echo && at_prompt(&tail(&buf), &shell.prompt)) {
        let d = shell_read(&mut shell.channel, None)
            .await?
            .expect("a read with no quiet time gives data");
        if buf.len() + d.len() > max {
            return Err(TransportError::Command(format!(
                "the output is larger than {max} bytes"
            )));
        }
        buf.extend_from_slice(&d);
        if !echo {
            let head = &buf[..buf.len().min(PROMPT_TAIL)];
            echo = echo_line(
                &sanitize(&String::from_utf8_lossy(head)),
                command,
                &shell.prompt,
            )
            .is_some();
        }
    }
    shell.busy = false;
    let text = sanitize(&String::from_utf8_lossy(&buf));
    Ok(output_of(&text, command, &shell.prompt))
}

impl Ssh for SshTransport {
    fn run<'a>(
        &'a self,
        device: &'a Device,
        command: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, TransportError>> {
        Box::pin(async move {
            match self.profile(device).mode {
                CommandMode::Exec => self.run_exec(device, command).await,
                CommandMode::Shell => self.run_shell(device, command).await,
                CommandMode::Connection => self.run_connection(device, command).await,
            }
        })
    }

    fn banner_each_command(&self, device: &Device) -> bool {
        self.profile(device).mode != CommandMode::Shell
    }

    fn serial(&self, device: &Device) -> bool {
        let p = self.profile(device);
        p.mode != CommandMode::Exec || p.max_channels <= 1
    }
}
