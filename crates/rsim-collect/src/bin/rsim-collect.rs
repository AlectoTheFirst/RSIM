//! Collects the devices of an env file into a snapshot store.
//!
//! The env file has one `KEY=VALUE` on each line:
//!
//! | Key | Value |
//! |---|---|
//! | `VYOS_<NAME>_IP` | The address of the VyOS router `<name>` |
//! | `VYOS_<NAME>_PROFILE` | `legacy` for the legacy SSH algorithm set |
//! | `VYOS_<NAME>_MODE` | `exec` (the default), `shell` or `connection` |
//! | `VYOS_USER`, `VYOS_PASS` | The credential of the VyOS routers |
//! | `VYOS_KEY_FILE`, `VYOS_KEY_PASS` | A private key file and its passphrase, used in place of `VYOS_PASS` |
//! | `VYOS_AGENT` | The socket of an SSH agent, or `default` for `SSH_AUTH_SOCK`, used in place of `VYOS_PASS` |
//! | `VYOS_VIA`, `VYOS_<NAME>_VIA` | The jump hosts to the routers, in order, separated by commas |
//! | `VYOS_PROXY`, `VYOS_<NAME>_PROXY` | A proxy for the first connection: `http://host:port` or `socks5://host:port`, with an optional `user:password@` |
//! | `NXOS_<NAME>_IP`, `NXOS_USER`, `NXOS_PASS` | An NX-OS switch and the credential of the switches, with the same `KEY_FILE`, `AGENT`, `VIA`, `PROXY`, `MODE` and `PROFILE` keys as VyOS |
//! | `NXOS_<NAME>_JSON` | `native` for `\| json native` (NX-OS 9.3 and later), needed for a large route table |
//! | `IOSXR_<NAME>_IP`, `IOSXR_USER`, `IOSXR_PASS` | An IOS XR router and the credential of the IOS XR routers, with the same `KEY_FILE`, `AGENT`, `VIA`, `PROXY`, `MODE` and `PROFILE` keys as VyOS |
//! | `IOSXE_<NAME>_IP`, `IOSXE_USER`, `IOSXE_PASS` | An IOS XE device and the credential of the IOS XE devices, with the same keys as IOS XR |
//! | `NXOS_<NAME>_CHANNELS`, `IOSXR_<NAME>_CHANNELS`, `IOSXE_<NAME>_CHANNELS` | The exec channels at one time. The default is 1: one command after the other. |
//! | `<P>_TIMEOUT`, `<P>_<NAME>_TIMEOUT` | The time for all sections of a device, in whole seconds from 1 to 86400. The default is 45. `<P>` is `VYOS`, `NXOS`, `IOSXR`, `IOSXE` or `UNIFI`; UniFi has only the vendor key. |
//! | `<P>_SECTION_TIMEOUT`, `<P>_<NAME>_SECTION_TIMEOUT` | The time for one section, in whole seconds from 1 to 86400. The default is 20. |
//! | `<P>_CAPTURE_BGP`, `<P>_<NAME>_CAPTURE_BGP` | The BGP sections of a router: `sessions` (the default) for the session summaries, `all` for the summaries, the neighbour detail and the tables of each neighbour, or `off`. `<P>` is `VYOS`, `NXOS`, `IOSXR` or `IOSXE`. A router with `all` can need a longer `<P>_<NAME>_TIMEOUT`. |
//! | `UNIFI_CONTROLLER` | The addresses of the UniFi consoles, separated by commas |
//! | `UNIFI_SITES` | The sites, separated by commas. The default is `default`. |
//! | `UNIFI_USER`, `UNIFI_PASS` | The credential of the UniFi consoles |
//! | `UNIFI_API_KEY` | An API key, used in place of the user and the password |
//! | `UNIFI_VIA`, `UNIFI_PROXY` | The jump hosts and the proxy to the consoles |
//! | `UNIFI_TLS` | `pin` (the default), `ca` with `UNIFI_CA_FILE`, or `none` for no check of the certificate |
//! | `UNIFI_CLIENT_CERT`, `UNIFI_CLIENT_KEY` | PEM files of a client certificate for mutual TLS |
//! | `JUMP_<NAME>_IP` | The address of the jump host `<name>` |
//! | `JUMP_<NAME>_USER` | The user on the jump host |
//! | `JUMP_<NAME>_PASS`, `JUMP_<NAME>_KEY_FILE`, `JUMP_<NAME>_KEY_PASS`, `JUMP_<NAME>_AGENT` | The secret of the jump host, as for VyOS |
//! | `JUMP_<NAME>_PROFILE` | `legacy` for the legacy SSH algorithm set |
//!
//! A `<NAME>` of a device or a jump host is in upper case with `_`; the id
//! is in lower case with `-`. Two devices with one id are an error. A jump
//! host gets only its own credential. A key of a device wins over the key
//! of its vendor. A device named `SECTION`, or with a name that ends in
//! `_SECTION`, with its `<P>_<NAME>_TIMEOUT` set is an error, because the
//! key is also the section time of the vendor or of another device name.
//!
//! The data folder holds the store, the store keys and the pin file. The
//! keys are made at the first run.
//!
//! With an inventory database, from `--inventory`, the environment variable
//! `RSIM_INVENTORY_URL` or the env key `RSIM_INVENTORY_URL`, the collector
//! reads the devices, the groups, the routes and the credential references
//! from the database at the start of each cycle, and the snapshot records
//! the inventory version. The env file then gives only the secrets of the
//! references: the reference `env:<P>` reads `<P>_USER` with `<P>_PASS`,
//! `<P>_KEY_FILE` and `<P>_KEY_PASS`, or `<P>_AGENT`, and for an HTTPS device
//! `<P>_API_KEY` or `<P>_USER` with `<P>_PASS`; the reference
//! `env-url:<KEY>` reads the login in the URL of `<KEY>`. The client
//! certificate of the UniFi consoles stays in `UNIFI_CLIENT_CERT` and
//! `UNIFI_CLIENT_KEY`. `--inventory-ca-file`, `RSIM_INVENTORY_CA_FILE` or the
//! env key of the same name gives the CA bundle of the database server. A
//! cycle whose inventory read fails writes nothing; with `--repeat` the next
//! cycle reads again. A device of a vendor with no collector is skipped.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rsim_collect::https::{ClientCert, HttpsLimits, HttpsProfile, HttpsTransport, TlsTrust};
use rsim_collect::iosxe::{IosxeSource, SHELL_SETUP as IOSXE_SHELL_SETUP};
use rsim_collect::iosxr::{IosxrSource, SHELL_SETUP as IOSXR_SHELL_SETUP};
use rsim_collect::nxos::{NxosSource, SHELL_SETUP};
use rsim_collect::ssh::{Algorithms, CommandMode, SshLimits, SshProfile, SshTransport};
use rsim_collect::unifi::UnifiSource;
use rsim_collect::vyos::VyosSource;
use rsim_collect::{
    CaptureBgp, Collector, Credential, CycleReport, Device, InventoryList, Jump, Limits,
    MemoryCredentials, PinPolicy, Proxy, ProxyLogin, Route, Schedule, Secret, Source, TimeLimits,
    TokioClock, TrustStore, Vendor,
};
use rsim_inventory::env::parse_env;
use rsim_inventory::{CredentialSource, Inventory};
use rsim_store::{Keys, SectionStatus, Store};

#[derive(Parser)]
#[command(
    name = "rsim-collect",
    about = "Collects devices into a snapshot store"
)]
struct Cli {
    /// The env file with the devices and the credentials, or with only the
    /// secrets of the credential references of an inventory database.
    #[arg(long)]
    env: PathBuf,
    /// The folder of the store, the keys and the pins.
    #[arg(long)]
    data: PathBuf,
    /// The URL of the inventory database: postgres://user:password@host:port/db.
    #[arg(long, env = rsim_inventory::URL_VAR, hide_env_values = true)]
    inventory: Option<String>,
    /// The PEM file of the CA bundle of the inventory database server.
    #[arg(long, env = rsim_inventory::CA_FILE_VAR)]
    inventory_ca_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Collects the devices.
    Run {
        /// Runs cycles until SIGINT or SIGTERM. Without this flag, runs one
        /// cycle.
        #[arg(long)]
        repeat: bool,
        /// Rejects a host key or a certificate with no pin.
        #[arg(long)]
        strict_pins: bool,
    },
    /// Shows the sections of each device in the newest snapshot.
    Status,
    /// Writes the raw bytes of a section of the newest snapshot to stdout.
    Show { device: String, section: String },
}

struct Setup {
    devices: Vec<Device>,
    credentials: MemoryCredentials,
    profiles: Vec<(String, SshProfile)>,
    /// The profile of the consoles with no profile of their own.
    https: HttpsProfile,
    /// The profile of each console with its own profile.
    https_profiles: Vec<(String, HttpsProfile)>,
    /// The NX-OS switches that get `| json native`.
    native_json: Vec<String>,
    /// The devices with a time key, with their time limits.
    times: Vec<(String, TimeLimits)>,
}

/// The largest time limit in seconds.
const MAX_SECONDS: u64 = 86_400;

/// The seconds of a time key, from 1 to `MAX_SECONDS`.
fn seconds(env: &BTreeMap<String, String>, key: &str) -> Result<Option<Duration>, String> {
    let Some(v) = env.get(key) else {
        return Ok(None);
    };
    match v.parse::<u64>() {
        Ok(n) if (1..=MAX_SECONDS).contains(&n) => Ok(Some(Duration::from_secs(n))),
        _ => Err(format!(
            "{key} {v} is not a positive number of seconds: a whole number from 1 to {MAX_SECONDS}"
        )),
    }
}

/// The time limits of a device of the prefix: `<P>_<NAME>_TIMEOUT` or
/// `<P>_TIMEOUT` for the device, `<P>_<NAME>_SECTION_TIMEOUT` or
/// `<P>_SECTION_TIMEOUT` for one section, and the default limits for a key
/// that is not set. `None` if no key is set.
fn time_limits(
    env: &BTreeMap<String, String>,
    prefix: &str,
    name: Option<&str>,
) -> Result<Option<TimeLimits>, String> {
    let pick = |k: &str| -> Result<Option<Duration>, String> {
        let vendor = seconds(env, &format!("{prefix}_{k}"))?;
        let device = match name {
            Some(n) => seconds(env, &format!("{prefix}_{n}_{k}"))?,
            None => None,
        };
        Ok(device.or(vendor))
    };
    if let Some(n) = name
        && (n == "SECTION" || n.ends_with("_SECTION"))
        && env.contains_key(&format!("{prefix}_{n}_TIMEOUT"))
    {
        let other = n
            .strip_suffix("_SECTION")
            .map_or(prefix.to_string(), |base| format!("{prefix}_{base}"));
        return Err(format!(
            "{prefix}_{n}_TIMEOUT is the device time of {prefix}_{n}_IP and the section \
             time of {other}; give the device another name"
        ));
    }
    let device = pick("TIMEOUT")?;
    let section = pick("SECTION_TIMEOUT")?;
    if device.is_none() && section.is_none() {
        return Ok(None);
    }
    let d = Limits::default();
    Ok(Some(TimeLimits {
        section: section.unwrap_or(d.section_timeout),
        device: device.unwrap_or(d.device_timeout),
    }))
}

/// The BGP setting of a device of the prefix: `<P>_<NAME>_CAPTURE_BGP`, else
/// `<P>_CAPTURE_BGP`, else the default.
fn capture_bgp(
    env: &BTreeMap<String, String>,
    prefix: &str,
    name: &str,
) -> Result<CaptureBgp, String> {
    let read = |key: String| -> Result<Option<CaptureBgp>, String> {
        env.get(&key)
            .map(|v| {
                CaptureBgp::parse(v).ok_or_else(|| format!("{key} {v} is not sessions, all or off"))
            })
            .transpose()
    };
    let vendor = read(format!("{prefix}_CAPTURE_BGP"))?;
    let device = read(format!("{prefix}_{name}_CAPTURE_BGP"))?;
    Ok(device.or(vendor).unwrap_or_default())
}

/// The SSH devices of one vendor: `<P>_<NAME>_IP` with the keys of the
/// route, the mode, the algorithm set, the time limits and, for NX-OS, the
/// JSON form and the channel limit. The credential of the vendor is `<P>_USER` with its
/// secret.
fn ssh_devices(
    env: &BTreeMap<String, String>,
    prefix: &str,
    vendor: Vendor,
    s: &mut Setup,
) -> Result<(), String> {
    let credential = vendor.name().to_string();
    for (key, address) in env {
        let Some(name) = key
            .strip_prefix(&format!("{prefix}_"))
            .and_then(|k| k.strip_suffix("_IP"))
        else {
            continue;
        };
        let id = name.to_lowercase().replace('_', "-");
        let route = route(env, prefix, Some(name), &mut s.credentials)?;
        if let Some(t) = time_limits(env, prefix, Some(name))? {
            s.times.push((id.clone(), t));
        }
        s.devices.push(Device {
            id: id.clone(),
            vendor,
            address: address.clone(),
            credential: credential.clone(),
            site: None,
            capture_bgp: capture_bgp(env, prefix, name)?,
            route,
        });
        let get = |k: &str| env.get(&format!("{prefix}_{name}_{k}")).map(String::as_str);
        let mode = match get("MODE") {
            None | Some("exec") => CommandMode::Exec,
            Some("shell") => CommandMode::Shell,
            Some("connection") => CommandMode::Connection,
            Some(m) => {
                return Err(format!(
                    "{prefix}_{name}_MODE {m} is not exec, shell or connection"
                ));
            }
        };
        let mut profile = SshProfile {
            algorithms: algorithms(env, &format!("{prefix}_{name}_PROFILE")),
            mode,
            ..SshProfile::default()
        };
        if matches!(vendor, Vendor::Nxos | Vendor::Iosxr | Vendor::Iosxe) {
            profile.max_channels = match get("CHANNELS") {
                None => 1,
                Some(n) => n
                    .parse()
                    .map_err(|_| format!("{prefix}_{name}_CHANNELS {n} is not a number"))?,
            };
        }
        if vendor == Vendor::Nxos {
            profile.shell_setup = SHELL_SETUP.iter().map(|c| (*c).to_string()).collect();
            match get("JSON") {
                None | Some("plain") => {}
                Some("native") => s.native_json.push(id.clone()),
                Some(j) => return Err(format!("{prefix}_{name}_JSON {j} is not plain or native")),
            }
        }
        if vendor == Vendor::Iosxr {
            profile.shell_setup = IOSXR_SHELL_SETUP.iter().map(|c| (*c).to_string()).collect();
        }
        if vendor == Vendor::Iosxe {
            profile.shell_setup = IOSXE_SHELL_SETUP.iter().map(|c| (*c).to_string()).collect();
        }
        if profile != SshProfile::default() {
            s.profiles.push((id, profile));
        }
    }
    if s.devices.iter().any(|d| d.vendor == vendor) {
        let user = env
            .get(&format!("{prefix}_USER"))
            .ok_or_else(|| format!("{prefix}_USER is not set"))?;
        let secret = ssh_secret(env, prefix)?;
        s.credentials.insert(
            &credential,
            Credential {
                user: user.clone(),
                secret,
            },
        );
    }
    Ok(())
}

fn read_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

/// The SSH secret of a prefix: `<P>_KEY_FILE`, `<P>_AGENT` or `<P>_PASS`.
fn ssh_secret(env: &BTreeMap<String, String>, prefix: &str) -> Result<Secret, String> {
    let get = |k: &str| env.get(&format!("{prefix}_{k}"));
    if let Some(path) = get("KEY_FILE") {
        return Ok(Secret::Key {
            pem: read_file(path)?,
            passphrase: get("KEY_PASS").cloned(),
        });
    }
    if let Some(socket) = get("AGENT") {
        let socket = (socket != "default").then(|| PathBuf::from(socket));
        return Ok(Secret::Agent { socket });
    }
    match get("PASS") {
        Some(p) => Ok(Secret::Password(p.clone())),
        None => Err(format!(
            "{prefix}_PASS, {prefix}_KEY_FILE or {prefix}_AGENT is not set"
        )),
    }
}

fn algorithms(env: &BTreeMap<String, String>, key: &str) -> Algorithms {
    if env
        .get(key)
        .is_some_and(|p| p.eq_ignore_ascii_case("legacy"))
    {
        Algorithms::Legacy
    } else {
        Algorithms::Modern
    }
}

/// The route of a device: `<P>_<NAME>_VIA` or `<P>_VIA`, and
/// `<P>_<NAME>_PROXY` or `<P>_PROXY`. Each jump host gets its credential.
fn route(
    env: &BTreeMap<String, String>,
    vendor: &str,
    name: Option<&str>,
    credentials: &mut MemoryCredentials,
) -> Result<Route, String> {
    let pick = |k: &str| {
        name.and_then(|n| env.get(&format!("{vendor}_{n}_{k}")))
            .or_else(|| env.get(&format!("{vendor}_{k}")))
    };
    let proxy = pick("PROXY").map(|p| Proxy::parse(p)).transpose()?;
    let mut jumps = Vec::new();
    for j in pick("VIA")
        .map(|v| v.split(',').map(str::trim).filter(|x| !x.is_empty()))
        .into_iter()
        .flatten()
    {
        let key = j.to_uppercase().replace('-', "_");
        let prefix = format!("JUMP_{key}");
        let address = env
            .get(&format!("{prefix}_IP"))
            .ok_or_else(|| format!("{prefix}_IP is not set"))?;
        let user = env
            .get(&format!("{prefix}_USER"))
            .ok_or_else(|| format!("{prefix}_USER is not set"))?;
        let credential = format!("jump-{}", key.to_lowercase().replace('_', "-"));
        credentials.insert(
            &credential,
            Credential {
                user: user.clone(),
                secret: ssh_secret(env, &prefix)?,
            },
        );
        jumps.push(Jump {
            address: address.clone(),
            credential,
            algorithms: algorithms(env, &format!("{prefix}_PROFILE")),
        });
    }
    Ok(Route { proxy, jumps })
}

fn setup(env: &BTreeMap<String, String>) -> Result<Setup, String> {
    let mut s = Setup {
        devices: Vec::new(),
        credentials: MemoryCredentials::new(),
        profiles: Vec::new(),
        https: HttpsProfile::default(),
        https_profiles: Vec::new(),
        native_json: Vec::new(),
        times: Vec::new(),
    };
    let list = |key: &str| -> Vec<String> {
        env.get(key)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    for (prefix, vendor) in [
        ("VYOS", Vendor::Vyos),
        ("NXOS", Vendor::Nxos),
        ("IOSXR", Vendor::Iosxr),
        ("IOSXE", Vendor::Iosxe),
    ] {
        ssh_devices(env, prefix, vendor, &mut s)?;
    }
    let consoles = list("UNIFI_CONTROLLER");
    if !consoles.is_empty() {
        let mut sites = list("UNIFI_SITES");
        if sites.is_empty() {
            sites.push("default".into());
        }
        let route = route(env, "UNIFI", None, &mut s.credentials)?;
        let times = time_limits(env, "UNIFI", None)?;
        s.https.trust = match env.get("UNIFI_TLS").map(String::as_str) {
            None | Some("pin") => TlsTrust::Pin,
            Some("ca") => TlsTrust::CaBundle(read_file(
                env.get("UNIFI_CA_FILE")
                    .ok_or("UNIFI_TLS=ca needs UNIFI_CA_FILE")?,
            )?),
            Some("none") => TlsTrust::NoVerify,
            Some(t) => return Err(format!("UNIFI_TLS {t} is not pin, ca or none")),
        };
        s.https.client = match (env.get("UNIFI_CLIENT_CERT"), env.get("UNIFI_CLIENT_KEY")) {
            (Some(c), Some(k)) => Some(ClientCert {
                chain: read_file(c)?,
                key: read_file(k)?,
            }),
            (None, None) => None,
            _ => return Err("UNIFI_CLIENT_CERT and UNIFI_CLIENT_KEY go together".into()),
        };
        for console in &consoles {
            for site in &sites {
                let id = if consoles.len() == 1 {
                    format!("unifi-{site}")
                } else {
                    format!("unifi-{console}-{site}")
                };
                if let Some(t) = times {
                    s.times.push((id.clone(), t));
                }
                s.devices.push(Device {
                    id,
                    vendor: Vendor::Unifi,
                    address: console.clone(),
                    credential: "unifi".into(),
                    site: Some(site.clone()),
                    capture_bgp: Default::default(),
                    route: route.clone(),
                });
            }
        }
        let credential = match (env.get("UNIFI_API_KEY"), env.get("UNIFI_USER")) {
            (Some(key), _) => Credential {
                user: String::new(),
                secret: Secret::ApiKey(key.clone()),
            },
            (None, Some(user)) => Credential {
                user: user.clone(),
                secret: Secret::Password(
                    env.get("UNIFI_PASS")
                        .ok_or("UNIFI_PASS is not set")?
                        .clone(),
                ),
            },
            (None, None) => return Err("UNIFI_USER or UNIFI_API_KEY is not set".into()),
        };
        s.credentials.insert("unifi", credential);
    }
    if s.devices.is_empty() {
        return Err(
            "the env file has no VYOS_<NAME>_IP, no NXOS_<NAME>_IP, no IOSXR_<NAME>_IP, \
                    no IOSXE_<NAME>_IP and no UNIFI_CONTROLLER"
                .into(),
        );
    }
    let mut seen: BTreeMap<&str, &Device> = BTreeMap::new();
    for d in &s.devices {
        if let Some(first) = seen.insert(&d.id, d) {
            return Err(format!(
                "the {} device {} and the {} device {} have one id: {}",
                first.vendor.name(),
                first.address,
                d.vendor.name(),
                d.address,
                d.id
            ));
        }
    }
    Ok(s)
}

/// The secret of a credential reference from the env file. An HTTPS
/// device takes `<P>_API_KEY` or `<P>_USER` with `<P>_PASS`; an SSH device
/// or a jump host takes `<P>_USER` with its SSH secret; `env-url` takes the
/// login in the URL of its key.
fn env_credential(
    env: &BTreeMap<String, String>,
    c: &rsim_inventory::Credential,
    https: bool,
) -> Result<Credential, String> {
    let p = &c.key;
    match c.source {
        CredentialSource::Env if https => {
            match (
                env.get(&format!("{p}_API_KEY")),
                env.get(&format!("{p}_USER")),
            ) {
                (Some(key), _) => Ok(Credential {
                    user: String::new(),
                    secret: Secret::ApiKey(key.clone()),
                }),
                (None, Some(user)) => Ok(Credential {
                    user: user.clone(),
                    secret: Secret::Password(
                        env.get(&format!("{p}_PASS"))
                            .ok_or_else(|| format!("{p}_PASS is not set"))?
                            .clone(),
                    ),
                }),
                (None, None) => Err(format!("{p}_USER or {p}_API_KEY is not set")),
            }
        }
        CredentialSource::Env => Ok(Credential {
            user: env
                .get(&format!("{p}_USER"))
                .ok_or_else(|| format!("{p}_USER is not set"))?
                .clone(),
            secret: ssh_secret(env, p)?,
        }),
        CredentialSource::EnvUrl => {
            let url = env.get(p).ok_or_else(|| format!("{p} is not set"))?;
            let login = match Proxy::parse(url).map_err(|e| format!("{p}: {e}"))? {
                Proxy::Http { login, .. } | Proxy::Socks5 { login, .. } => login,
            };
            let login = login.ok_or_else(|| format!("the URL of {p} has no login"))?;
            Ok(Credential {
                user: login.user,
                secret: Secret::Password(login.password),
            })
        }
    }
}

/// The credential reference of a name, from the inventory and the env file.
fn reference(
    inv: &Inventory,
    env: &BTreeMap<String, String>,
    name: &str,
    https: bool,
) -> Result<Credential, String> {
    let c = inv
        .credential(name)
        .ok_or_else(|| format!("no credential reference is named {name}"))?;
    env_credential(env, c, https).map_err(|e| format!("the credential {name}: {e}"))
}

/// The secrets of the credential references of an inventory, with the
/// first user of each reference. A reference gives the secret of its use:
/// an API key or a password for HTTPS, a key, an agent or a password for
/// SSH.
#[derive(Default)]
struct References(BTreeMap<String, (Credential, String)>);

impl References {
    /// Adds the secret of a reference for a user. A reference whose
    /// secret for this user differs from its secret for an earlier user is
    /// an error, because the collector keeps one secret for each name.
    fn add(&mut self, name: &str, credential: Credential, user: String) -> Result<(), String> {
        match self.0.get(name) {
            Some((c, first)) if *c != credential => Err(format!(
                "the credential {name} gives {first} and {user} different secrets; \
                 give each use its own credential reference"
            )),
            Some(_) => Ok(()),
            None => {
                self.0.insert(name.to_string(), (credential, user));
                Ok(())
            }
        }
    }

    fn into_credentials(self) -> MemoryCredentials {
        let mut m = MemoryCredentials::new();
        for (name, (c, _)) in self.0 {
            m.insert(&name, c);
        }
        m
    }
}

/// The route of a name of the inventory. Each jump host gets its
/// credential. No name is a direct connection.
fn inventory_route(
    inv: &Inventory,
    env: &BTreeMap<String, String>,
    name: Option<&str>,
    credentials: &mut References,
) -> Result<Route, String> {
    let Some(name) = name else {
        return Ok(Route::default());
    };
    let r = inv
        .route(name)
        .ok_or_else(|| format!("no route is named {name}"))?;
    let mut proxy = r
        .proxy
        .as_deref()
        .map(Proxy::parse)
        .transpose()
        .map_err(|e| format!("the route {name}: {e}"))?;
    if let (Some(p), Some(c)) = (&mut proxy, &r.proxy_credential) {
        let cred = reference(inv, env, c, false)?;
        let Secret::Password(password) = cred.secret else {
            return Err(format!(
                "the proxy credential {c} of {name} has no password"
            ));
        };
        let login = Some(ProxyLogin {
            user: cred.user,
            password,
        });
        match p {
            Proxy::Http { login: l, .. } | Proxy::Socks5 { login: l, .. } => *l = login,
        }
    }
    let mut jumps = Vec::new();
    for j in &r.jumps {
        let host = inv
            .jump_host(j)
            .ok_or_else(|| format!("no jump host is named {j}"))?;
        credentials.add(
            &host.credential,
            reference(inv, env, &host.credential, false)?,
            format!("the jump host {j} (SSH)"),
        )?;
        jumps.push(Jump {
            address: host.address.clone(),
            credential: host.credential.clone(),
            algorithms: match host.ssh_algorithms {
                rsim_inventory::SshAlgorithms::Modern => Algorithms::Modern,
                rsim_inventory::SshAlgorithms::Legacy => Algorithms::Legacy,
            },
        });
    }
    Ok(Route { proxy, jumps })
}

/// The setup of an inventory, with the secrets from the env file, and a
/// note for each device that is not collected. Each device of a vendor with
/// a collector needs its credential; a device with no credential, or a
/// reference that the env file does not give, is an error, so that a
/// cycle does not remove a device for a typing error.
fn setup_from_inventory(
    inv: &Inventory,
    env: &BTreeMap<String, String>,
) -> Result<(Setup, Vec<String>), String> {
    let mut s = Setup {
        devices: Vec::new(),
        credentials: MemoryCredentials::new(),
        profiles: Vec::new(),
        https: HttpsProfile::default(),
        https_profiles: Vec::new(),
        native_json: Vec::new(),
        times: Vec::new(),
    };
    let client = match (env.get("UNIFI_CLIENT_CERT"), env.get("UNIFI_CLIENT_KEY")) {
        (Some(c), Some(k)) => Some(ClientCert {
            chain: read_file(c)?,
            key: read_file(k)?,
        }),
        (None, None) => None,
        _ => return Err("UNIFI_CLIENT_CERT and UNIFI_CLIENT_KEY go together".into()),
    };
    let mut notes = Vec::new();
    let mut references = References::default();
    for d in inv.resolve()? {
        let Some(vendor) = Vendor::ALL.into_iter().find(|v| v.name() == d.vendor) else {
            notes.push(format!(
                "{} is not collected: the vendor {} has no collector",
                d.name, d.vendor
            ));
            continue;
        };
        let st = &d.settings;
        let https = vendor == Vendor::Unifi;
        let credential = st
            .credential
            .value
            .clone()
            .ok_or_else(|| format!("the device {} has no credential", d.name))?;
        let secret = reference(inv, env, &credential, https)
            .map_err(|e| format!("the device {}: {e}", d.name))?;
        let user = format!(
            "the device {} ({})",
            d.name,
            if https { "HTTPS" } else { "SSH" }
        );
        references.add(&credential, secret, user)?;
        let route = inventory_route(inv, env, st.route.value.as_deref(), &mut references)
            .map_err(|e| format!("the device {}: {e}", d.name))?;
        if st.timeout_seconds.is_set() || st.section_timeout_seconds.is_set() {
            s.times.push((
                d.name.clone(),
                TimeLimits {
                    section: Duration::from_secs(st.section_timeout_seconds.value.into()),
                    device: Duration::from_secs(st.timeout_seconds.value.into()),
                },
            ));
        }
        if https {
            let trust = match st.tls_trust.value {
                rsim_inventory::TlsTrust::Pin => TlsTrust::Pin,
                rsim_inventory::TlsTrust::None => TlsTrust::NoVerify,
                rsim_inventory::TlsTrust::Ca => {
                    TlsTrust::CaBundle(read_file(st.tls_ca_file.value.as_deref().ok_or_else(
                        || format!("the device {} has tls_trust ca and no tls_ca_file", d.name),
                    )?)?)
                }
            };
            s.https_profiles.push((
                d.name.clone(),
                HttpsProfile {
                    trust,
                    client: client.clone(),
                },
            ));
        } else {
            let mut profile = SshProfile {
                algorithms: match st.ssh_algorithms.value {
                    rsim_inventory::SshAlgorithms::Modern => Algorithms::Modern,
                    rsim_inventory::SshAlgorithms::Legacy => Algorithms::Legacy,
                },
                mode: match st.ssh_mode.value {
                    rsim_inventory::SshMode::Exec => CommandMode::Exec,
                    rsim_inventory::SshMode::Shell => CommandMode::Shell,
                    rsim_inventory::SshMode::Connection => CommandMode::Connection,
                },
                ..SshProfile::default()
            };
            if matches!(vendor, Vendor::Nxos | Vendor::Iosxr | Vendor::Iosxe) {
                profile.max_channels = st.ssh_channels.value as usize;
            }
            let setup: &[&str] = match vendor {
                Vendor::Nxos => &SHELL_SETUP,
                Vendor::Iosxr => &IOSXR_SHELL_SETUP,
                Vendor::Iosxe => &IOSXE_SHELL_SETUP,
                _ => &[],
            };
            profile.shell_setup = setup.iter().map(|c| (*c).to_string()).collect();
            if vendor == Vendor::Nxos && st.nxos_json.value == rsim_inventory::NxosJson::Native {
                s.native_json.push(d.name.clone());
            }
            if profile != SshProfile::default() {
                s.profiles.push((d.name.clone(), profile));
            }
        }
        s.devices.push(Device {
            id: d.name.clone(),
            vendor,
            address: d.address.clone(),
            credential,
            site: d.console_site.clone(),
            capture_bgp: match st.capture_bgp.value {
                rsim_inventory::CaptureBgp::Off => CaptureBgp::Off,
                rsim_inventory::CaptureBgp::Sessions => CaptureBgp::Sessions,
                rsim_inventory::CaptureBgp::All => CaptureBgp::All,
            },
            route,
        });
    }
    if s.devices.is_empty() {
        return Err(format!(
            "the inventory at version {} has no device with a collector",
            inv.version
        ));
    }
    s.credentials = references.into_credentials();
    Ok((s, notes))
}

/// The devices of a setup, its sources and the time limits of its devices.
struct Collection {
    devices: Vec<Device>,
    sources: Vec<Arc<dyn Source>>,
    times: BTreeMap<String, TimeLimits>,
}

/// The sources of a setup, with its transports, and the time limits of its
/// devices.
fn sources(setup: Setup, trust: &Arc<TrustStore>) -> Collection {
    let credentials = Arc::new(setup.credentials);
    let mut ssh = SshTransport::new(credentials.clone(), trust.clone(), SshLimits::default());
    for (id, p) in setup.profiles {
        ssh = ssh.with_profile(&id, p);
    }
    let ssh = Arc::new(ssh);
    let mut nxos = NxosSource::new(ssh.clone());
    for id in &setup.native_json {
        nxos = nxos.with_native_json(id);
    }
    let vyos = VyosSource::new(ssh.clone());
    let iosxr = IosxrSource::new(ssh.clone());
    let iosxe = IosxeSource::new(ssh);
    let mut https = HttpsTransport::new(credentials, trust.clone(), HttpsLimits::default())
        .with_default_profile(setup.https);
    for (id, p) in setup.https_profiles {
        https = https.with_profile(&id, p);
    }
    let sources: Vec<Arc<dyn Source>> = vec![
        Arc::new(vyos),
        Arc::new(nxos),
        Arc::new(iosxr),
        Arc::new(iosxe),
        Arc::new(UnifiSource::new(Arc::new(https))),
    ];
    Collection {
        devices: setup.devices,
        sources,
        times: setup.times.into_iter().collect(),
    }
}

fn print_devices(devices: &[Device]) {
    for d in devices {
        let via: Vec<&str> = d.route.jumps.iter().map(|j| j.address.as_str()).collect();
        let proxy = d.route.proxy.as_ref().map(Proxy::address);
        eprintln!(
            "device {} ({}) at {}{}{}",
            d.id,
            d.vendor,
            d.address,
            if via.is_empty() {
                String::new()
            } else {
                format!(" via {}", via.join(", "))
            },
            proxy.map_or(String::new(), |p| format!(" through proxy {p}"))
        );
    }
}

fn print_report(r: &CycleReport) {
    println!(
        "due {} snapshot {:?} failed {:?}",
        r.due, r.snapshot, r.failed
    );
    for (device, classes) in &r.changed {
        println!("changed {device}: {classes:?}");
    }
    for (device, section, error) in &r.extract_errors {
        println!("extract error {device}/{section}: {error}");
    }
    for device in &r.removed {
        println!("removed {device}");
    }
}

/// Reads the inventory and sets the collector up for one cycle. Gives the
/// inventory, so that the caller sees its version.
async fn configure_from_inventory(
    db: &rsim_inventory::Db,
    env: &BTreeMap<String, String>,
    trust: &Arc<TrustStore>,
    collector: &mut Collector,
) -> Result<(Inventory, Vec<Device>), String> {
    let inv = db.load().await.map_err(|e| e.to_string())?;
    let (setup, notes) = setup_from_inventory(&inv, env)?;
    for n in notes {
        eprintln!("{n}");
    }
    let Collection {
        devices,
        sources,
        times,
    } = sources(setup, trust);
    collector.reconfigure(
        Box::new(InventoryList {
            devices: devices.clone(),
            version: Some(inv.version),
        }),
        sources,
        times,
    );
    Ok((inv, devices))
}

/// Reads the store keys, or makes new keys in a file that only the owner
/// can read.
fn keys(path: &Path) -> Result<Keys, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Keys::from_hex(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = [0u8; 64];
            getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            let text = format!("{}\n{}\n", hex(&bytes[..32]), hex(&bytes[32..]));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut f = options
                .open(path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            f.write_all(text.as_bytes())
                .and_then(|_| f.sync_all())
                .map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!("new store keys in {}", path.display());
            Keys::from_hex(&text).map_err(|e| e.to_string())
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn open_store(data: &Path) -> Result<Store, String> {
    std::fs::create_dir_all(data).map_err(|e| format!("{}: {e}", data.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", data.display()))?;
    }
    let keys = keys(&data.join("keys"))?;
    Store::open(data.join("store"), keys).map_err(|e| e.to_string())
}

fn status(store: &Store) -> Result<(), String> {
    let Some(snap) = store.latest().map_err(|e| e.to_string())? else {
        println!("the store has no snapshot");
        return Ok(());
    };
    println!("snapshot {}", snap.manifest.cycle);
    for (device, m) in &snap.devices {
        println!("{device} ({})", m.vendor);
        for s in &m.sections {
            let size = s
                .blob
                .as_ref()
                .and_then(|b| store.read_blob(b).ok())
                .map_or(String::new(), |b| format!(" {} bytes", b.len()));
            let state = match &s.status {
                SectionStatus::Fresh => "fresh".to_string(),
                SectionStatus::Old { error } => format!("old: {error}"),
                SectionStatus::Absent { reason } => format!("absent: {reason}"),
                SectionStatus::Missing { error } => format!("missing: {error}"),
            };
            println!("  {:<16} {state}{size}", s.name);
        }
        for (table, t) in &m.tables {
            println!("  table {table}: {} rows", t.rows);
        }
    }
    Ok(())
}

fn show(store: &Store, device: &str, section: &str) -> Result<(), String> {
    let snap = store
        .latest()
        .map_err(|e| e.to_string())?
        .ok_or("the store has no snapshot")?;
    let m = snap
        .devices
        .get(device)
        .ok_or_else(|| format!("no device {device} in the snapshot"))?;
    let s = m
        .sections
        .iter()
        .find(|s| s.name == section)
        .ok_or_else(|| format!("no section {section} on {device}"))?;
    let blob = s
        .blob
        .as_ref()
        .ok_or_else(|| format!("section {section} has no blob"))?;
    let bytes = store.read_blob(blob).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|e| e.to_string())
}

/// The inventory database of the flags, the environment or the env file,
/// if any.
fn inventory_db(
    cli: &Cli,
    env: &BTreeMap<String, String>,
) -> Result<Option<rsim_inventory::Db>, String> {
    let url = cli
        .inventory
        .clone()
        .or_else(|| env.get(rsim_inventory::URL_VAR).cloned());
    let Some(url) = url else {
        return Ok(None);
    };
    let ca_file = cli
        .inventory_ca_file
        .as_ref()
        .map(|p| p.display().to_string())
        .or_else(|| env.get(rsim_inventory::CA_FILE_VAR).cloned());
    let ca = ca_file.as_deref().map(read_file).transpose()?;
    rsim_inventory::Db::new(&url, ca.as_deref())
        .map(Some)
        .map_err(|e| e.to_string())
}

async fn run(cli: &Cli, repeat: bool, strict: bool) -> Result<(), String> {
    let text =
        std::fs::read_to_string(&cli.env).map_err(|e| format!("{}: {e}", cli.env.display()))?;
    let env = parse_env(&text);
    let db = inventory_db(cli, &env)?;
    let store = open_store(&cli.data)?;
    let policy = if strict {
        PinPolicy::Strict
    } else {
        PinPolicy::AcceptNew
    };
    let trust = Arc::new(TrustStore::open(&cli.data.join("pins"), policy)?);
    let mut collector = Collector::new(
        store,
        Box::new(Vec::<Device>::new()),
        Schedule::default(),
        Limits::default(),
        Arc::new(TokioClock::system()),
    )
    .map_err(|e| e.to_string())?;
    match db {
        None => {
            let Collection {
                devices,
                sources,
                times,
            } = sources(setup(&env)?, &trust);
            print_devices(&devices);
            collector.reconfigure(Box::new(devices), sources, times);
            if repeat {
                collector
                    .run(stop_signal())
                    .await
                    .map_err(|e| e.to_string())?;
            } else {
                let r = collector.run_cycle().await.map_err(|e| e.to_string())?;
                print_report(&r);
                status(collector.store())?;
            }
        }
        Some(db) => {
            let stop = stop_signal();
            tokio::pin!(stop);
            let mut tick = tokio::time::interval(collector.scheduler().schedule().interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut shown = None;
            loop {
                tokio::select! {
                    _ = &mut stop => break,
                    _ = tick.tick() => {}
                }
                match configure_from_inventory(&db, &env, &trust, &mut collector).await {
                    Ok((inv, devices)) => {
                        if shown != Some(inv.version) {
                            eprintln!("inventory version {}", inv.version);
                            print_devices(&devices);
                            shown = Some(inv.version);
                        }
                    }
                    Err(e) if repeat => {
                        eprintln!("error: inventory: {e}; the cycle writes nothing");
                        continue;
                    }
                    Err(e) => return Err(format!("inventory: {e}")),
                }
                let r = collector.run_cycle().await.map_err(|e| e.to_string())?;
                if !repeat {
                    print_report(&r);
                    status(collector.store())?;
                    break;
                }
            }
        }
    }
    let pins = trust.to_text();
    if !pins.is_empty() {
        eprintln!("pins in {}:\n{pins}", cli.data.join("pins").display());
    }
    Ok(())
}

/// Waits for SIGINT or, on Unix, SIGTERM, the stop signal of a container.
async fn stop_signal() {
    #[cfg(unix)]
    if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Run {
            repeat,
            strict_pins,
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(run(&cli, *repeat, *strict_pins))),
        Command::Status => open_store(&cli.data).and_then(|s| status(&s)),
        Command::Show { device, section } => {
            open_store(&cli.data).and_then(|s| show(&s, device, section))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imported(env: &BTreeMap<String, String>) -> Inventory {
        let r = rsim_inventory::env::import(env).unwrap();
        Inventory {
            version: 3,
            credentials: r.credentials,
            jump_hosts: r.jump_hosts,
            routes: r.routes,
            groups: r.groups,
            devices: r.devices,
            bindings: Default::default(),
        }
    }

    /// The parts of a setup that a collection uses, in device order.
    #[allow(clippy::type_complexity)]
    fn effective(
        s: &Setup,
    ) -> (
        Vec<Device>,
        Vec<(String, Credential)>,
        Vec<(String, SshProfile)>,
        Vec<String>,
        Vec<(String, TimeLimits)>,
        Vec<(String, HttpsProfile)>,
    ) {
        use rsim_collect::Credentials;
        let mut devices = s.devices.clone();
        devices.sort();
        let mut names: Vec<String> = devices
            .iter()
            .flat_map(|d| {
                std::iter::once(d.credential.clone())
                    .chain(d.route.jumps.iter().map(|j| j.credential.clone()))
            })
            .collect();
        names.sort();
        names.dedup();
        let credentials = names
            .into_iter()
            .map(|n| {
                let c = s.credentials.get(&n).unwrap();
                (n, c)
            })
            .collect();
        let mut profiles = s.profiles.clone();
        profiles.sort_by(|a, b| a.0.cmp(&b.0));
        let mut native = s.native_json.clone();
        native.sort();
        let mut times = s.times.clone();
        times.sort_by(|a, b| a.0.cmp(&b.0));
        let https = devices
            .iter()
            .filter(|d| d.vendor == Vendor::Unifi)
            .map(|d| {
                let p = s
                    .https_profiles
                    .iter()
                    .find(|(id, _)| *id == d.id)
                    .map_or(s.https.clone(), |(_, p)| p.clone());
                (d.id.clone(), p)
            })
            .collect();
        (devices, credentials, profiles, native, times, https)
    }

    #[test]
    fn the_inventory_of_an_env_import_collects_what_the_env_file_collects() {
        let env = parse_env(
            "VYOS_CORE1_IP=10.0.0.1\nVYOS_CORE1_MODE=shell\nVYOS_EDGE_IP=10.0.0.2\n\
             VYOS_EDGE_VIA=\nVYOS_EDGE_2_IP=10.0.0.3\nVYOS_EDGE_2_PROFILE=legacy\n\
             VYOS_EDGE_2_PROXY=http://u:v@192.0.2.10:3128\n\
             VYOS_VIA=bastion-a, inner\nVYOS_PROXY=socks5://p:q@192.0.2.9:1080\n\
             VYOS_USER=ro\nVYOS_AGENT=default\nVYOS_CAPTURE_BGP=all\nVYOS_EDGE_CAPTURE_BGP=off\n\
             VYOS_SECTION_TIMEOUT=30\nVYOS_CORE1_TIMEOUT=90\n\
             JUMP_BASTION_A_IP=192.0.2.20\nJUMP_BASTION_A_USER=hop\nJUMP_BASTION_A_PASS=h\n\
             JUMP_INNER_IP=10.0.0.254:2222\nJUMP_INNER_USER=hop2\nJUMP_INNER_AGENT=/tmp/agent\n\
             JUMP_INNER_PROFILE=legacy\n\
             NXOS_LEAF_1_IP=192.0.2.31\nNXOS_LEAF_1_JSON=native\nNXOS_SPINE_IP=192.0.2.32\n\
             NXOS_SPINE_CHANNELS=4\nNXOS_USER=ro\nNXOS_PASS=p\nNXOS_TIMEOUT=120\n\
             IOSXR_PE1_IP=192.0.2.41\nIOSXR_PE1_MODE=connection\nIOSXR_USER=x\nIOSXR_PASS=y\n\
             IOSXE_E1_IP=192.0.2.5\nIOSXE_E1_SECTION_TIMEOUT=5\nIOSXE_USER=u\nIOSXE_PASS=p\n\
             IOSXE_CAPTURE_BGP=off\n\
             UNIFI_CONTROLLER=192.0.2.8, 192.0.2.9\nUNIFI_SITES=default, branch\n\
             UNIFI_USER=ro\nUNIFI_PASS=x\nUNIFI_VIA=bastion-a\nUNIFI_TLS=none\nUNIFI_TIMEOUT=60\n",
        );
        let direct = setup(&env).unwrap();
        let (through, notes) = setup_from_inventory(&imported(&env), &env).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        let (a, b) = (effective(&direct), effective(&through));
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
        assert_eq!(a.2, b.2);
        assert_eq!(a.3, b.3);
        assert_eq!(a.4, b.4);
        assert_eq!(a.5, b.5);
        assert_eq!(a.0.len(), 11);
        let edge2 = a.0.iter().find(|d| d.id == "edge-2").unwrap();
        assert!(matches!(
            &edge2.route.proxy,
            Some(Proxy::Http { login: Some(l), .. }) if l.user == "u" && l.password == "v"
        ));
    }

    #[test]
    fn the_defaults_of_the_inventory_are_the_limits_of_the_collector() {
        let d = Limits::default();
        assert_eq!(
            d.device_timeout,
            Duration::from_secs(rsim_inventory::DEFAULT_TIMEOUT_SECONDS.into())
        );
        assert_eq!(
            d.section_timeout,
            Duration::from_secs(rsim_inventory::DEFAULT_SECTION_TIMEOUT_SECONDS.into())
        );
    }

    #[test]
    fn a_credential_reference_with_one_secret_for_https_and_another_for_ssh_is_an_error() {
        let devices = "VYOS_CORE1_IP=192.0.2.1\nVYOS_USER=u\nVYOS_PASS=p\n\
                       UNIFI_CONTROLLER=192.0.2.8\nUNIFI_USER=u\nUNIFI_PASS=p\n";
        let mut inv = imported(&parse_env(devices));
        inv.credentials.push(rsim_inventory::Credential {
            name: "lab".into(),
            source: CredentialSource::Env,
            key: "LAB".into(),
            description: None,
        });
        for g in &mut inv.groups {
            g.settings.credential = Some("lab".into());
        }
        assert_eq!(inv.groups.len(), 2);

        let same = parse_env("LAB_USER=u\nLAB_PASS=p\n");
        let (s, _) = setup_from_inventory(&inv, &same).unwrap();
        assert_eq!(s.devices.len(), 2);
        assert!(s.devices.iter().all(|d| d.credential == "lab"));

        for env in [
            "LAB_USER=u\nLAB_PASS=p\nLAB_API_KEY=k\n",
            "LAB_USER=u\nLAB_PASS=p\nLAB_AGENT=default\n",
        ] {
            let err = setup_from_inventory(&inv, &parse_env(env)).err().unwrap();
            assert!(
                err.contains("credential lab") && err.contains("different secrets"),
                "{err}"
            );
        }

        // A jump host and a UniFi controller on one reference.
        let mut inv = imported(&parse_env(&format!(
            "{devices}UNIFI_VIA=bastion\nJUMP_BASTION_IP=192.0.2.20\n\
             JUMP_BASTION_USER=u\nJUMP_BASTION_PASS=p\n"
        )));
        inv.credentials.push(rsim_inventory::Credential {
            name: "lab".into(),
            source: CredentialSource::Env,
            key: "LAB".into(),
            description: None,
        });
        for j in &mut inv.jump_hosts {
            j.credential = "lab".into();
        }
        for g in inv.groups.iter_mut().filter(|g| g.vendor == "unifi") {
            g.settings.credential = Some("lab".into());
        }
        let env = parse_env(&format!("{devices}LAB_USER=u\nLAB_PASS=p\nLAB_API_KEY=k\n"));
        let err = setup_from_inventory(&inv, &env).err().unwrap();
        assert!(
            err.contains("jump host") && err.contains("different secrets"),
            "{err}"
        );
    }

    #[test]
    fn a_vendor_with_no_collector_is_skipped_and_a_missing_secret_is_an_error() {
        let env = parse_env("VYOS_R1_IP=192.0.2.1\nVYOS_USER=u\nVYOS_PASS=p\n");
        let mut inv = imported(&env);
        inv.groups.push(rsim_inventory::Group {
            name: "fw".into(),
            vendor: "checkpoint".into(),
            description: None,
            settings: Default::default(),
        });
        inv.devices.push(rsim_inventory::Device {
            name: "fw1".into(),
            group: "fw".into(),
            address: "192.0.2.7".into(),
            site: None,
            location: None,
            console_site: None,
            settings: Default::default(),
        });
        let (s, notes) = setup_from_inventory(&inv, &env).unwrap();
        assert_eq!(s.devices.len(), 1);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("fw1") && notes[0].contains("checkpoint"));

        let no_pass = parse_env("VYOS_USER=u\n");
        let err = setup_from_inventory(&inv, &no_pass).err().unwrap();
        assert!(err.contains("r1") && err.contains("VYOS_PASS"), "{err}");

        inv.devices.retain(|d| d.name == "fw1");
        let err = setup_from_inventory(&inv, &env).err().unwrap();
        assert!(err.contains("no device with a collector"), "{err}");
    }

    #[test]
    fn the_env_file_gives_devices_and_credentials() {
        let env = parse_env(
            "# lab\nVYOS_CORE1_IP=192.0.2.1\nVYOS_EDGE_2_IP=192.0.2.2\nVYOS_EDGE_2_PROFILE=legacy\n\
             VYOS_USER=ro\nexport VYOS_PASS=\"p w\"\nUNIFI_CONTROLLER=192.0.2.8\n\
             UNIFI_SITES=default, branch\nUNIFI_USER=ro\nUNIFI_PASS='x'\n",
        );
        assert_eq!(env["VYOS_PASS"], "p w");
        let s = setup(&env).unwrap();
        let ids: Vec<&str> = s.devices.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, ["core1", "edge-2", "unifi-default", "unifi-branch"]);
        assert_eq!(s.profiles.len(), 1);
        assert_eq!(s.profiles[0].0, "edge-2");
        use rsim_collect::Credentials;
        assert_eq!(
            s.credentials.get("vyos").unwrap().secret,
            Secret::Password("p w".into())
        );
        assert!(setup(&parse_env("VYOS_CORE1_IP=192.0.2.1\n")).is_err());
    }

    #[test]
    fn the_env_file_gives_nxos_switches() {
        let env = parse_env(
            "NXOS_LEAF_1_IP=192.0.2.31\nNXOS_LEAF_1_JSON=native\nNXOS_SPINE_IP=192.0.2.32\n\
             NXOS_SPINE_CHANNELS=4\nNXOS_USER=ro\nNXOS_PASS=p\n",
        );
        let s = setup(&env).unwrap();
        let ids: Vec<(&str, Vendor)> = s
            .devices
            .iter()
            .map(|d| (d.id.as_str(), d.vendor))
            .collect();
        assert_eq!(ids, [("leaf-1", Vendor::Nxos), ("spine", Vendor::Nxos)]);
        assert_eq!(s.native_json, ["leaf-1"]);
        assert_eq!(s.profiles[0].1.max_channels, 1);
        assert_eq!(
            s.profiles[0].1.shell_setup,
            ["terminal length 0", "terminal width 511"]
        );
        assert_eq!(s.profiles[1].1.max_channels, 4);
        use rsim_collect::Credentials;
        assert_eq!(s.credentials.get("nxos").unwrap().user, "ro");
        assert!(
            setup(&parse_env(
                "NXOS_X_IP=192.0.2.1\nNXOS_USER=u\nNXOS_PASS=p\nNXOS_X_JSON=xml\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn the_device_key_of_a_time_limit_wins_over_the_vendor_key() {
        let env = parse_env(
            "VYOS_R1_IP=192.0.2.1\nVYOS_R2_IP=192.0.2.2\nVYOS_R3_IP=192.0.2.3\n\
             VYOS_SECTION_TIMEOUT=30\nVYOS_R1_TIMEOUT=90\nVYOS_R2_SECTION_TIMEOUT=5\n\
             VYOS_USER=u\nVYOS_PASS=p\nNXOS_S1_IP=192.0.2.4\nNXOS_TIMEOUT=120\n\
             NXOS_USER=u\nNXOS_PASS=p\nIOSXE_E1_IP=192.0.2.5\nIOSXE_USER=u\nIOSXE_PASS=p\n\
             UNIFI_CONTROLLER=192.0.2.8\nUNIFI_API_KEY=k\nUNIFI_TIMEOUT=60\n",
        );
        let s = setup(&env).unwrap();
        let secs = Duration::from_secs;
        let limits = |section, device| TimeLimits {
            section: secs(section),
            device: secs(device),
        };
        assert_eq!(
            s.times,
            [
                ("r1".to_string(), limits(30, 90)),
                ("r2".to_string(), limits(5, 45)),
                ("r3".to_string(), limits(30, 45)),
                ("s1".to_string(), limits(20, 120)),
                ("unifi-default".to_string(), limits(20, 60)),
            ]
        );
    }

    #[test]
    fn a_time_limit_that_is_not_a_positive_number_is_an_error() {
        let base = "VYOS_R1_IP=192.0.2.1\nVYOS_USER=u\nVYOS_PASS=p\n";
        for (line, key) in [
            ("VYOS_R1_TIMEOUT=0", "VYOS_R1_TIMEOUT"),
            ("VYOS_R1_SECTION_TIMEOUT=-5", "VYOS_R1_SECTION_TIMEOUT"),
            ("VYOS_TIMEOUT=abc", "VYOS_TIMEOUT"),
            ("VYOS_SECTION_TIMEOUT=", "VYOS_SECTION_TIMEOUT"),
            ("VYOS_TIMEOUT=2.5", "VYOS_TIMEOUT"),
            ("VYOS_R1_TIMEOUT=18446744073709551615", "VYOS_R1_TIMEOUT"),
        ] {
            let err = setup(&parse_env(&format!("{base}{line}\n")))
                .err()
                .unwrap_or_else(|| panic!("{line}"));
            assert!(err.starts_with(key), "{err}");
            assert!(err.contains("positive number of seconds"), "{err}");
        }
        let err = setup(&parse_env(&format!(
            "{base}VYOS_TIMEOUT=0\nVYOS_R1_TIMEOUT=60\n"
        )))
        .err()
        .expect("a vendor key is checked when each device has its own key");
        assert!(err.starts_with("VYOS_TIMEOUT"), "{err}");
        let err = setup(&parse_env(&format!(
            "{base}VYOS_SECTION_IP=192.0.2.2\nVYOS_SECTION_TIMEOUT=10\n"
        )))
        .err()
        .expect("a device named SECTION makes the key ambiguous");
        assert!(err.contains("VYOS_SECTION_TIMEOUT"), "{err}");
        let err = setup(&parse_env(&format!(
            "{base}VYOS_R1_SECTION_IP=192.0.2.3\nVYOS_R1_SECTION_TIMEOUT=10\n"
        )))
        .err()
        .expect("a device name that ends in _SECTION makes the key ambiguous");
        assert!(err.starts_with("VYOS_R1_SECTION_TIMEOUT"), "{err}");
    }

    #[test]
    fn the_device_key_of_the_bgp_setting_wins_over_the_vendor_key() {
        let env = parse_env(
            "VYOS_R1_IP=192.0.2.1\nVYOS_R2_IP=192.0.2.2\nVYOS_CAPTURE_BGP=all\n\
             VYOS_R2_CAPTURE_BGP=sessions\nVYOS_USER=u\nVYOS_PASS=p\n\
             NXOS_S1_IP=192.0.2.4\nNXOS_S1_CAPTURE_BGP=off\nNXOS_USER=u\nNXOS_PASS=p\n\
             IOSXE_E1_IP=192.0.2.5\nIOSXE_USER=u\nIOSXE_PASS=p\n",
        );
        let s = setup(&env).unwrap();
        let got: Vec<(&str, CaptureBgp)> = s
            .devices
            .iter()
            .map(|d| (d.id.as_str(), d.capture_bgp))
            .collect();
        assert_eq!(
            got,
            [
                ("r1", CaptureBgp::All),
                ("r2", CaptureBgp::Sessions),
                ("s1", CaptureBgp::Off),
                ("e1", CaptureBgp::Sessions),
            ]
        );
    }

    #[test]
    fn a_bgp_setting_that_is_not_a_word_of_the_list_is_an_error() {
        let base = "VYOS_R1_IP=192.0.2.1\nVYOS_USER=u\nVYOS_PASS=p\n";
        for (line, key) in [
            ("VYOS_R1_CAPTURE_BGP=none", "VYOS_R1_CAPTURE_BGP"),
            ("VYOS_CAPTURE_BGP=ALL", "VYOS_CAPTURE_BGP"),
        ] {
            let err = setup(&parse_env(&format!("{base}{line}\n")))
                .err()
                .unwrap_or_else(|| panic!("{line}"));
            assert!(err.starts_with(key), "{err}");
            assert!(err.contains("sessions, all or off"), "{err}");
        }
    }

    #[test]
    fn two_devices_with_one_id_are_an_error() {
        for text in [
            "VYOS_CORE1_IP=192.0.2.1\nNXOS_CORE1_IP=192.0.2.2\n",
            "IOSXR_EDGE_1_IP=192.0.2.1\nIOSXE_EDGE_1_IP=192.0.2.2\n",
            "VYOS_EDGE_2_IP=192.0.2.1\nVYOS_EDGE-2_IP=192.0.2.2\n",
            "VYOS_UNIFI_DEFAULT_IP=192.0.2.1\nUNIFI_CONTROLLER=192.0.2.8\nUNIFI_API_KEY=k\n",
        ] {
            let creds = "VYOS_USER=u\nVYOS_PASS=p\nNXOS_USER=u\nNXOS_PASS=p\n\
                         IOSXR_USER=u\nIOSXR_PASS=p\nIOSXE_USER=u\nIOSXE_PASS=p\n";
            let err = setup(&parse_env(&format!("{text}{creds}")))
                .err()
                .unwrap_or_else(|| panic!("{text}"));
            assert!(err.contains("one id"), "{err}");
        }
    }

    #[test]
    fn the_env_file_gives_routes() {
        let env = parse_env(
            "VYOS_CORE1_IP=10.0.0.1\nVYOS_CORE1_MODE=shell\nVYOS_EDGE_IP=10.0.0.2\n\
             VYOS_EDGE_VIA=\nVYOS_VIA=bastion-a, inner\nVYOS_PROXY=socks5://p:q@192.0.2.9:1080\n\
             VYOS_USER=ro\nVYOS_AGENT=default\n\
             JUMP_BASTION_A_IP=192.0.2.20\nJUMP_BASTION_A_USER=hop\nJUMP_BASTION_A_PASS=h\n\
             JUMP_INNER_IP=10.0.0.254:2222\nJUMP_INNER_USER=hop2\nJUMP_INNER_AGENT=/tmp/agent\n\
             JUMP_INNER_PROFILE=legacy\nUNIFI_CONTROLLER=10.0.0.8\nUNIFI_USER=u\nUNIFI_PASS=p\n\
             UNIFI_VIA=bastion-a\nUNIFI_TLS=none\n",
        );
        let s = setup(&env).unwrap();
        let core = &s.devices[0];
        let jumps: Vec<&str> = core
            .route
            .jumps
            .iter()
            .map(|j| j.address.as_str())
            .collect();
        assert_eq!(jumps, ["192.0.2.20", "10.0.0.254:2222"]);
        assert_eq!(core.route.jumps[1].algorithms, Algorithms::Legacy);
        assert_eq!(
            core.route.proxy.as_ref().unwrap().address(),
            "192.0.2.9:1080"
        );
        assert!(
            s.devices[1].route.jumps.is_empty(),
            "an empty VIA is a direct route"
        );
        assert_eq!(
            s.profiles,
            [(
                "core1".to_string(),
                SshProfile {
                    mode: CommandMode::Shell,
                    ..SshProfile::default()
                }
            )]
        );
        use rsim_collect::Credentials;
        assert_eq!(
            s.credentials.get("vyos").unwrap().secret,
            Secret::Agent { socket: None }
        );
        let inner = s.credentials.get("jump-inner").unwrap();
        assert_eq!(inner.user, "hop2");
        assert_eq!(
            inner.secret,
            Secret::Agent {
                socket: Some("/tmp/agent".into())
            }
        );
        assert_eq!(s.devices[2].route.jumps.len(), 1);
        assert_eq!(s.https.trust, TlsTrust::NoVerify);
        assert!(
            setup(&parse_env(
                "VYOS_X_IP=10.0.0.1\nVYOS_X_VIA=nope\nVYOS_USER=u\nVYOS_PASS=p\n"
            ))
            .is_err()
        );
    }
}
