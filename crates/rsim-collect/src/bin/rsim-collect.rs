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
//! | `NXOS_<NAME>_CHANNELS` | The exec channels at one time. The default is 1: one command after the other. |
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
//! is in lower case with `-`. A jump host gets only its own credential.
//!
//! The data folder holds the store, the store keys and the pin file. The
//! keys are made at the first run.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rsim_collect::https::{ClientCert, HttpsLimits, HttpsProfile, HttpsTransport, TlsTrust};
use rsim_collect::nxos::{NxosSource, SHELL_SETUP};
use rsim_collect::ssh::{Algorithms, CommandMode, SshLimits, SshProfile, SshTransport};
use rsim_collect::unifi::UnifiSource;
use rsim_collect::vyos::VyosSource;
use rsim_collect::{
    Collector, Credential, Device, Jump, Limits, MemoryCredentials, PinPolicy, Proxy, Route,
    Schedule, Secret, TokioClock, TrustStore, Vendor,
};
use rsim_store::{Keys, SectionStatus, Store};

#[derive(Parser)]
#[command(
    name = "rsim-collect",
    about = "Collects devices into a snapshot store"
)]
struct Cli {
    /// The env file with the devices and the credentials.
    #[arg(long)]
    env: PathBuf,
    /// The folder of the store, the keys and the pins.
    #[arg(long)]
    data: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Collects the devices.
    Run {
        /// Runs cycles until Ctrl-C. Without this flag, runs one cycle.
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

fn parse_env(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("export ").unwrap_or(l).split_once('='))
        .map(|(k, v)| {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(v);
            (k.trim().to_string(), v.to_string())
        })
        .collect()
}

struct Setup {
    devices: Vec<Device>,
    credentials: MemoryCredentials,
    profiles: Vec<(String, SshProfile)>,
    https: HttpsProfile,
    /// The NX-OS switches that get `| json native`.
    native_json: Vec<String>,
}

/// The SSH devices of one vendor: `<P>_<NAME>_IP` with the keys of the
/// route, the mode, the algorithm set and, for NX-OS, the JSON form and the
/// channel limit. The credential of the vendor is `<P>_USER` with its
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
        s.devices.push(Device {
            id: id.clone(),
            vendor,
            address: address.clone(),
            credential: credential.clone(),
            site: None,
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
        if vendor == Vendor::Nxos {
            profile.max_channels = match get("CHANNELS") {
                None => 1,
                Some(n) => n
                    .parse()
                    .map_err(|_| format!("{prefix}_{name}_CHANNELS {n} is not a number"))?,
            };
            profile.shell_setup = SHELL_SETUP.iter().map(|c| (*c).to_string()).collect();
            match get("JSON") {
                None | Some("plain") => {}
                Some("native") => s.native_json.push(id.clone()),
                Some(j) => return Err(format!("{prefix}_{name}_JSON {j} is not plain or native")),
            }
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
        native_json: Vec::new(),
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
    for (prefix, vendor) in [("VYOS", Vendor::Vyos), ("NXOS", Vendor::Nxos)] {
        ssh_devices(env, prefix, vendor, &mut s)?;
    }
    let consoles = list("UNIFI_CONTROLLER");
    if !consoles.is_empty() {
        let mut sites = list("UNIFI_SITES");
        if sites.is_empty() {
            sites.push("default".into());
        }
        let route = route(env, "UNIFI", None, &mut s.credentials)?;
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
                s.devices.push(Device {
                    id,
                    vendor: Vendor::Unifi,
                    address: console.clone(),
                    credential: "unifi".into(),
                    site: Some(site.clone()),
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
            "the env file has no VYOS_<NAME>_IP, no NXOS_<NAME>_IP and no UNIFI_CONTROLLER".into(),
        );
    }
    Ok(s)
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

async fn run(cli: &Cli, repeat: bool, strict: bool) -> Result<(), String> {
    let text =
        std::fs::read_to_string(&cli.env).map_err(|e| format!("{}: {e}", cli.env.display()))?;
    let setup = setup(&parse_env(&text))?;
    let store = open_store(&cli.data)?;
    let policy = if strict {
        PinPolicy::Strict
    } else {
        PinPolicy::AcceptNew
    };
    let trust = Arc::new(TrustStore::open(&cli.data.join("pins"), policy)?);
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
    let https = HttpsTransport::new(credentials, trust.clone(), HttpsLimits::default())
        .with_default_profile(setup.https);
    let devices = setup.devices;
    for d in &devices {
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
    let mut collector = Collector::new(
        store,
        Box::new(devices),
        Schedule::default(),
        Limits::default(),
        Arc::new(TokioClock::system()),
    )
    .map_err(|e| e.to_string())?
    .with_source(Arc::new(VyosSource::new(ssh)))
    .with_source(Arc::new(nxos))
    .with_source(Arc::new(UnifiSource::new(Arc::new(https))));
    if repeat {
        let stop = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        collector.run(stop).await.map_err(|e| e.to_string())?;
    } else {
        let r = collector.run_cycle().await.map_err(|e| e.to_string())?;
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
        status(collector.store())?;
    }
    let pins = trust.to_text();
    if !pins.is_empty() {
        eprintln!("pins in {}:\n{pins}", cli.data.join("pins").display());
    }
    Ok(())
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
