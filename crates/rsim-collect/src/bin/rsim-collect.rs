//! Collects the devices of an env file into a snapshot store.
//!
//! The env file has one `KEY=VALUE` on each line:
//!
//! | Key | Value |
//! |---|---|
//! | `VYOS_<NAME>_IP` | The address of the VyOS router `<name>` |
//! | `VYOS_<NAME>_PROFILE` | `legacy` for the legacy SSH algorithm set |
//! | `VYOS_USER`, `VYOS_PASS` | The credential of the VyOS routers |
//! | `VYOS_KEY_FILE` | A private key file, used in place of `VYOS_PASS` |
//! | `UNIFI_CONTROLLER` | The addresses of the UniFi consoles, separated by commas |
//! | `UNIFI_SITES` | The sites, separated by commas. The default is `default`. |
//! | `UNIFI_USER`, `UNIFI_PASS` | The credential of the UniFi consoles |
//! | `UNIFI_API_KEY` | An API key, used in place of the user and the password |
//!
//! The data folder holds the store, the store keys and the pin file. The
//! keys are made at the first run.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rsim_collect::https::{HttpsLimits, HttpsTransport};
use rsim_collect::ssh::{Algorithms, SshLimits, SshProfile, SshTransport};
use rsim_collect::unifi::UnifiSource;
use rsim_collect::vyos::VyosSource;
use rsim_collect::{
    Collector, Credential, Device, Limits, MemoryCredentials, PinPolicy, Schedule, Secret,
    TokioClock, TrustStore, Vendor,
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
}

fn setup(env: &BTreeMap<String, String>) -> Result<Setup, String> {
    let mut s = Setup {
        devices: Vec::new(),
        credentials: MemoryCredentials::new(),
        profiles: Vec::new(),
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
    for (key, address) in env {
        let Some(name) = key
            .strip_prefix("VYOS_")
            .and_then(|k| k.strip_suffix("_IP"))
        else {
            continue;
        };
        let id = name.to_lowercase().replace('_', "-");
        s.devices.push(Device {
            id: id.clone(),
            vendor: Vendor::Vyos,
            address: address.clone(),
            credential: "vyos".into(),
            site: None,
        });
        if env
            .get(&format!("VYOS_{name}_PROFILE"))
            .is_some_and(|p| p.eq_ignore_ascii_case("legacy"))
        {
            let profile = SshProfile {
                algorithms: Algorithms::Legacy,
                ..SshProfile::default()
            };
            s.profiles.push((id, profile));
        }
    }
    if s.devices.iter().any(|d| d.vendor == Vendor::Vyos) {
        let user = env.get("VYOS_USER").ok_or("VYOS_USER is not set")?;
        let secret = match (env.get("VYOS_KEY_FILE"), env.get("VYOS_PASS")) {
            (Some(path), _) => Secret::Key {
                pem: std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?,
                passphrase: env.get("VYOS_KEY_PASS").cloned(),
            },
            (None, Some(p)) => Secret::Password(p.clone()),
            (None, None) => return Err("VYOS_PASS or VYOS_KEY_FILE is not set".into()),
        };
        s.credentials.insert(
            "vyos",
            Credential {
                user: user.clone(),
                secret,
            },
        );
    }
    let consoles = list("UNIFI_CONTROLLER");
    if !consoles.is_empty() {
        let mut sites = list("UNIFI_SITES");
        if sites.is_empty() {
            sites.push("default".into());
        }
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
        return Err("the env file has no VYOS_<NAME>_IP and no UNIFI_CONTROLLER".into());
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
    let https = HttpsTransport::new(credentials, trust.clone(), HttpsLimits::default());
    let devices = setup.devices;
    for d in &devices {
        eprintln!("device {} ({}) at {}", d.id, d.vendor, d.address);
    }
    let mut collector = Collector::new(
        store,
        Box::new(devices),
        Schedule::default(),
        Limits::default(),
        Arc::new(TokioClock::system()),
    )
    .map_err(|e| e.to_string())?
    .with_source(Arc::new(VyosSource::new(Arc::new(ssh))))
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
}
