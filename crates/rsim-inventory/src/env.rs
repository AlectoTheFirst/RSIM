//! The env file of the collector and its import into inventory records.
//!
//! The import gives one group for each vendor of the file, named after the
//! vendor, with the credential reference `env:<P>`, the route of `<P>_VIA`
//! and `<P>_PROXY`, and the vendor keys of the time limits and the BGP
//! sections. A device with its own `VIA` or `PROXY` key gets its own route.
//! Each VeloCloud orchestrator `VELOCLOUD_<NAME>_URL` is the group
//! `velocloud-<name>` with the credential reference `env:VELOCLOUD_<NAME>`,
//! and each of its enterprises is a device. Each Equinix account
//! `EQUINIX_<NAME>_URL` is the group `equinix-<name>` with the device
//! `equinix-<name>`, and its credential reference is `env:EQUINIX_<NAME>`
//! with its own client, else `env:EQUINIX`. A proxy login becomes the
//! reference `env-url:<key>`, so no secret leaves the env file.

use std::collections::BTreeMap;

use crate::types::{
    CaptureBgp, Credential, CredentialSource, Device, Group, JumpHost, NxosJson, Route, Settings,
    SshAlgorithms, SshMode, TlsTrust,
};

/// Reads the lines `KEY=VALUE` of an env file. A line can start with
/// `export `, and a value can be in single or double quotes. Empty lines
/// and lines that start with `#` are ignored.
pub fn parse_env(text: &str) -> BTreeMap<String, String> {
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

/// The SSH vendors of the env file: the key prefix and the vendor word.
pub const SSH_PREFIXES: [(&str, &str); 4] = [
    ("VYOS", "vyos"),
    ("NXOS", "nxos"),
    ("IOSXR", "iosxr"),
    ("IOSXE", "iosxe"),
];

/// The largest time limit in seconds.
pub const MAX_SECONDS: u32 = 86_400;

/// The most requests in flight to a VeloCloud orchestrator.
pub const MAX_CONCURRENCY: u32 = 16;

/// The most retries of a read after a 429.
pub const MAX_RETRIES: u32 = 10;

/// Checks a VeloCloud release of 3 or 4 numbers: it must be 5.0.0.0 or
/// later.
pub fn check_release(release: &str) -> Result<(), String> {
    let parts: Option<Vec<u64>> = release.split('.').map(|p| p.parse().ok()).collect();
    let mut parts = match parts {
        Some(p) if (3..=4).contains(&p.len()) => p,
        _ => return Err(format!("the release {release} is not 3 or 4 numbers")),
    };
    parts.resize(4, 0);
    if parts.as_slice() < [5, 0, 0, 0].as_slice() {
        return Err(format!(
            "the release {release} is before 5.0.0.0, the first release with the API v2 reads"
        ));
    }
    Ok(())
}

/// The enterprise logicalIds of a list, separated by commas or by lines.
pub fn enterprise_ids(text: &str) -> Vec<String> {
    text.split([',', '\n'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

/// The store device of an enterprise of a VeloCloud orchestrator.
pub fn enterprise_device(orchestrator: &str, enterprise: &str) -> String {
    format!("vco-{orchestrator}-{enterprise}")
}

/// The records of an env file, in the order of their dependencies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Records {
    pub credentials: Vec<Credential>,
    pub jump_hosts: Vec<JumpHost>,
    pub routes: Vec<Route>,
    pub groups: Vec<Group>,
    pub devices: Vec<Device>,
}

/// The id of a device or a jump host of a `<NAME>`: lower case with `-`.
pub fn id_of(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

/// The seconds of a time key, from 1 to [`MAX_SECONDS`].
pub fn seconds(env: &BTreeMap<String, String>, key: &str) -> Result<Option<u32>, String> {
    let Some(v) = env.get(key) else {
        return Ok(None);
    };
    match v.parse::<u32>() {
        Ok(n) if (1..=MAX_SECONDS).contains(&n) => Ok(Some(n)),
        _ => Err(format!(
            "{key} {v} is not a positive number of seconds: a whole number from 1 to {MAX_SECONDS}"
        )),
    }
}

/// The check that a device named `SECTION`, or with a name that ends in
/// `_SECTION`, has no `<P>_<NAME>_TIMEOUT`: that key is also the section
/// time of the vendor or of another device.
pub fn check_section_name(
    env: &BTreeMap<String, String>,
    prefix: &str,
    name: &str,
) -> Result<(), String> {
    if (name == "SECTION" || name.ends_with("_SECTION"))
        && env.contains_key(&format!("{prefix}_{name}_TIMEOUT"))
    {
        let other = name
            .strip_suffix("_SECTION")
            .map_or(prefix.to_string(), |base| format!("{prefix}_{base}"));
        return Err(format!(
            "{prefix}_{name}_TIMEOUT is the device time of {prefix}_{name}_IP and the section \
             time of {other}; give the device another name"
        ));
    }
    Ok(())
}

/// The BGP setting of a key, if it is set.
pub fn capture_bgp(
    env: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<CaptureBgp>, String> {
    env.get(key)
        .map(|v| {
            CaptureBgp::parse(v).ok_or_else(|| format!("{key} {v} is not sessions, all or off"))
        })
        .transpose()
}

/// The algorithm set of a `PROFILE` key: legacy for `legacy` in any case.
pub fn algorithms(env: &BTreeMap<String, String>, key: &str) -> SshAlgorithms {
    if env
        .get(key)
        .is_some_and(|p| p.eq_ignore_ascii_case("legacy"))
    {
        SshAlgorithms::Legacy
    } else {
        SshAlgorithms::Modern
    }
}

/// The parts of a proxy URL. The login is a user name and a password.
pub struct ProxyUrl {
    /// `http`, `socks5` or `socks5h`.
    pub scheme: String,
    /// The host name or the address, an IPv6 address with no brackets.
    pub host: String,
    pub port: u16,
    pub login: Option<(String, String)>,
}

/// Reads a proxy URL `scheme://[user:password@]host:port[/]`, with an IPv6
/// host in brackets. The collector reads its proxies with it. An error
/// does not show the login.
pub fn parse_proxy(url: &str) -> Result<ProxyUrl, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "the proxy has no scheme".to_string())?;
    if !matches!(scheme, "http" | "socks5" | "socks5h") {
        return Err(format!("the proxy scheme {scheme} is not supported"));
    }
    let (login, hostport) = match rest.rsplit_once('@') {
        Some((l, h)) => {
            let (u, p) = l
                .split_once(':')
                .ok_or_else(|| format!("the login of the proxy {h} has no password"))?;
            (Some((u.to_string(), p.to_string())), h)
        }
        None => (None, rest),
    };
    let address = hostport.trim_end_matches('/');
    let (host, port) = if let Some(rest) = address.strip_prefix('[') {
        rest.split_once("]:")
            .ok_or_else(|| format!("the proxy {address} has no port"))?
    } else {
        address
            .rsplit_once(':')
            .ok_or_else(|| format!("the proxy {address} has no port"))?
    };
    if host.is_empty() {
        return Err(format!("the proxy {address} has no host"));
    }
    let port = port
        .parse()
        .map_err(|_| format!("the proxy {address} has a bad port"))?;
    Ok(ProxyUrl {
        scheme: scheme.to_string(),
        host: host.to_string(),
        port,
        login,
    })
}

/// The split of a proxy URL `scheme://[user:password@]host:port[/]` into
/// the URL with no login and whether it has a login. The URL must be one
/// that [`parse_proxy`] reads.
pub fn split_proxy(url: &str) -> Result<(String, bool), String> {
    let p = parse_proxy(url)?;
    let host = if p.host.contains(':') {
        format!("[{}]", p.host)
    } else {
        p.host
    };
    Ok((
        format!("{}://{host}:{}", p.scheme, p.port),
        p.login.is_some(),
    ))
}

/// The secret keys of an env credential prefix: one of them must be set.
fn check_secret(env: &BTreeMap<String, String>, prefix: &str) -> Result<(), String> {
    if ["KEY_FILE", "AGENT", "PASS"]
        .iter()
        .any(|k| env.contains_key(&format!("{prefix}_{k}")))
    {
        Ok(())
    } else {
        Err(format!(
            "{prefix}_PASS, {prefix}_KEY_FILE or {prefix}_AGENT is not set"
        ))
    }
}

struct Builder<'a> {
    env: &'a BTreeMap<String, String>,
    out: Records,
}

impl Builder<'_> {
    fn credential(&mut self, name: &str, source: CredentialSource, key: &str) {
        if self.out.credentials.iter().all(|c| c.name != name) {
            self.out
                .credentials
                .push(Credential::env(name, source, key));
        }
    }

    /// The route `name` of the keys `<vendor>[_<NAME>]_VIA` and `_PROXY`,
    /// a device key before the vendor key. Each jump host gets its record
    /// and its credential reference.
    fn route(&mut self, name: &str, vendor: &str, device: Option<&str>) -> Result<(), String> {
        let pick = |k: &str| -> Option<(String, &String)> {
            if let Some(n) = device {
                let key = format!("{vendor}_{n}_{k}");
                if let Some(v) = self.env.get(&key) {
                    return Some((key, v));
                }
            }
            let key = format!("{vendor}_{k}");
            self.env.get(&key).map(|v| (key, v))
        };
        let proxy = pick("PROXY");
        let via: Vec<String> = pick("VIA")
            .map(|(_, v)| {
                v.split(',')
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let (proxy, proxy_credential) = match proxy {
            Some((key, url)) => {
                let (url, login) = split_proxy(url).map_err(|e| format!("{key}: {e}"))?;
                let cred = login.then(|| {
                    let c = format!("{name}-proxy");
                    (c, key)
                });
                (Some(url), cred)
            }
            None => (None, None),
        };
        if let Some((c, key)) = &proxy_credential {
            self.credential(c, CredentialSource::EnvUrl, key);
        }
        let mut jumps = Vec::new();
        for j in via {
            let key = j.to_uppercase().replace('-', "_");
            let prefix = format!("JUMP_{key}");
            let address = self
                .env
                .get(&format!("{prefix}_IP"))
                .ok_or_else(|| format!("{prefix}_IP is not set"))?
                .clone();
            if !self.env.contains_key(&format!("{prefix}_USER")) {
                return Err(format!("{prefix}_USER is not set"));
            }
            check_secret(self.env, &prefix)?;
            let id = id_of(&key);
            let credential = format!("jump-{id}");
            self.credential(&credential, CredentialSource::Env, &prefix);
            if self.out.jump_hosts.iter().all(|h| h.name != id) {
                self.out.jump_hosts.push(JumpHost {
                    name: id.clone(),
                    address,
                    credential,
                    ssh_algorithms: algorithms(self.env, &format!("{prefix}_PROFILE")),
                });
            }
            jumps.push(id);
        }
        self.out.routes.push(Route {
            name: name.to_string(),
            proxy,
            proxy_credential: proxy_credential.map(|(c, _)| c),
            jumps,
        });
        Ok(())
    }

    fn has_route_keys(&self, vendor: &str, device: Option<&str>) -> bool {
        let base = match device {
            Some(n) => format!("{vendor}_{n}"),
            None => vendor.to_string(),
        };
        self.env.contains_key(&format!("{base}_VIA"))
            || self.env.contains_key(&format!("{base}_PROXY"))
    }

    fn ssh_vendor(&mut self, prefix: &str, vendor: &str) -> Result<(), String> {
        let env = self.env;
        let mut devices = Vec::new();
        for (key, address) in env {
            let Some(name) = key
                .strip_prefix(&format!("{prefix}_"))
                .and_then(|k| k.strip_suffix("_IP"))
            else {
                continue;
            };
            check_section_name(env, prefix, name)?;
            let id = id_of(name);
            let get = |k: &str| env.get(&format!("{prefix}_{name}_{k}")).map(String::as_str);
            let mut s = Settings::default();
            if self.has_route_keys(prefix, Some(name)) {
                let route = format!("{vendor}-{id}");
                self.route(&route, prefix, Some(name))?;
                s.route = Some(route);
            }
            s.ssh_mode = match get("MODE") {
                None => None,
                Some(m) => Some(SshMode::parse(m).ok_or_else(|| {
                    format!("{prefix}_{name}_MODE {m} is not exec, shell or connection")
                })?),
            };
            if algorithms(env, &format!("{prefix}_{name}_PROFILE")) == SshAlgorithms::Legacy {
                s.ssh_algorithms = Some(SshAlgorithms::Legacy);
            }
            if matches!(vendor, "nxos" | "iosxr" | "iosxe")
                && let Some(n) = get("CHANNELS")
            {
                let c: u32 = n
                    .parse()
                    .map_err(|_| format!("{prefix}_{name}_CHANNELS {n} is not a number"))?;
                s.ssh_channels = Some(c.max(1));
            }
            if vendor == "nxos" {
                s.nxos_json = match get("JSON") {
                    None => None,
                    Some(j) => Some(NxosJson::parse(j).ok_or_else(|| {
                        format!("{prefix}_{name}_JSON {j} is not plain or native")
                    })?),
                };
            }
            s.capture_bgp = capture_bgp(env, &format!("{prefix}_{name}_CAPTURE_BGP"))?;
            s.timeout_seconds = seconds(env, &format!("{prefix}_{name}_TIMEOUT"))?;
            s.section_timeout_seconds = seconds(env, &format!("{prefix}_{name}_SECTION_TIMEOUT"))?;
            devices.push(Device {
                name: id,
                group: vendor.to_string(),
                address: address.clone(),
                site: None,
                location: None,
                console_site: None,
                settings: s,
            });
        }
        if devices.is_empty() {
            return Ok(());
        }
        if !env.contains_key(&format!("{prefix}_USER")) {
            return Err(format!("{prefix}_USER is not set"));
        }
        check_secret(env, prefix)?;
        self.credential(vendor, CredentialSource::Env, prefix);
        let mut g = Settings {
            credential: Some(vendor.to_string()),
            capture_bgp: capture_bgp(env, &format!("{prefix}_CAPTURE_BGP"))?,
            timeout_seconds: seconds(env, &format!("{prefix}_TIMEOUT"))?,
            section_timeout_seconds: seconds(env, &format!("{prefix}_SECTION_TIMEOUT"))?,
            ..Settings::default()
        };
        if self.has_route_keys(prefix, None) {
            self.route(vendor, prefix, None)?;
            g.route = Some(vendor.to_string());
        }
        self.out.groups.push(Group {
            name: vendor.to_string(),
            vendor: vendor.to_string(),
            description: None,
            settings: g,
        });
        self.out.devices.extend(devices);
        Ok(())
    }

    fn unifi(&mut self) -> Result<(), String> {
        let env = self.env;
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
        let consoles = list("UNIFI_CONTROLLER");
        if consoles.is_empty() {
            return Ok(());
        }
        let mut sites = list("UNIFI_SITES");
        if sites.is_empty() {
            sites.push("default".into());
        }
        let mut g = Settings {
            credential: Some("unifi".into()),
            timeout_seconds: seconds(env, "UNIFI_TIMEOUT")?,
            section_timeout_seconds: seconds(env, "UNIFI_SECTION_TIMEOUT")?,
            ..Settings::default()
        };
        if self.has_route_keys("UNIFI", None) {
            self.route("unifi", "UNIFI", None)?;
            g.route = Some("unifi".into());
        }
        g.tls_trust = match env.get("UNIFI_TLS").map(String::as_str) {
            None => None,
            Some(t) => Some(
                TlsTrust::parse(t)
                    .ok_or_else(|| format!("UNIFI_TLS {t} is not pin, ca, public or none"))?,
            ),
        };
        if g.tls_trust == Some(TlsTrust::Ca) {
            g.tls_ca_file = Some(
                env.get("UNIFI_CA_FILE")
                    .ok_or("UNIFI_TLS=ca needs UNIFI_CA_FILE")?
                    .clone(),
            );
        }
        match (env.get("UNIFI_API_KEY"), env.get("UNIFI_USER")) {
            (Some(_), _) => {}
            (None, Some(_)) => {
                if !env.contains_key("UNIFI_PASS") {
                    return Err("UNIFI_PASS is not set".into());
                }
            }
            (None, None) => return Err("UNIFI_USER or UNIFI_API_KEY is not set".into()),
        }
        self.credential("unifi", CredentialSource::Env, "UNIFI");
        self.out.groups.push(Group {
            name: "unifi".into(),
            vendor: "unifi".into(),
            description: None,
            settings: g,
        });
        for console in &consoles {
            for site in &sites {
                let name = if consoles.len() == 1 {
                    format!("unifi-{site}")
                } else {
                    format!("unifi-{console}-{site}")
                };
                self.out.devices.push(Device {
                    name,
                    group: "unifi".into(),
                    address: console.clone(),
                    site: None,
                    location: None,
                    console_site: Some(site.clone()),
                    settings: Settings::default(),
                });
            }
        }
        Ok(())
    }

    /// The VeloCloud orchestrators: one group `velocloud-<name>` for each
    /// `VELOCLOUD_<NAME>_URL` with the keys of `<NAME>`, and one device
    /// `vco-<name>-<logicalId>` for each enterprise, with the logicalId as
    /// its console site.
    fn velocloud(&mut self) -> Result<(), String> {
        let env = self.env;
        for (key, url) in env {
            let Some(name) = key
                .strip_prefix("VELOCLOUD_")
                .and_then(|k| k.strip_suffix("_URL"))
            else {
                continue;
            };
            check_section_name(env, "VELOCLOUD", name)?;
            let prefix = format!("VELOCLOUD_{name}");
            let key = |k: &str| format!("{prefix}_{k}");
            let get = |k: &str| env.get(&key(k));
            let id = id_of(name);
            let group = format!("velocloud-{id}");
            if get("TOKEN").is_none() {
                return Err(format!("{} is not set", key("TOKEN")));
            }
            for k in ["CLIENT_CERT", "CLIENT_KEY"] {
                if get(k).is_some() {
                    return Err(format!(
                        "{}: the inventory has no client certificate of an orchestrator",
                        key(k)
                    ));
                }
            }
            let release = get("RELEASE").ok_or_else(|| format!("{} is not set", key("RELEASE")))?;
            check_release(release).map_err(|e| format!("{}: {e}", key("RELEASE")))?;
            let concurrency = match get("CONCURRENCY") {
                None => None,
                Some(c) => Some(
                    c.parse::<u32>()
                        .ok()
                        .filter(|n| (1..=MAX_CONCURRENCY).contains(n))
                        .ok_or_else(|| {
                            format!(
                                "{} {c} is not a number from 1 to {MAX_CONCURRENCY}",
                                key("CONCURRENCY")
                            )
                        })?,
                ),
            };
            let refresh_seconds = match get("REFRESH") {
                None => None,
                Some(r) => Some(
                    r.parse::<u32>()
                        .ok()
                        .filter(|n| *n <= MAX_SECONDS)
                        .ok_or_else(|| {
                            format!(
                                "{} {r} is not a whole number of seconds from 0 to {MAX_SECONDS}",
                                key("REFRESH")
                            )
                        })?,
                ),
            };
            let retries = match get("RETRIES") {
                None => None,
                Some(r) => Some(
                    r.parse::<u32>()
                        .ok()
                        .filter(|n| *n <= MAX_RETRIES)
                        .ok_or_else(|| {
                            format!(
                                "{} {r} is not a number from 0 to {MAX_RETRIES}",
                                key("RETRIES")
                            )
                        })?,
                ),
            };
            let tls_trust =
                match get("TLS") {
                    None => None,
                    Some(t) => Some(TlsTrust::parse(t).ok_or_else(|| {
                        format!("{} {t} is not public, pin, ca or none", key("TLS"))
                    })?),
                };
            let tls_ca_file = if tls_trust == Some(TlsTrust::Ca) {
                Some(
                    get("CA_FILE")
                        .ok_or_else(|| format!("{}=ca needs {}", key("TLS"), key("CA_FILE")))?
                        .clone(),
                )
            } else {
                None
            };
            let either = |k: &str| -> Result<Option<u32>, String> {
                Ok(seconds(env, &key(k))?.or(seconds(env, &format!("VELOCLOUD_{k}"))?))
            };
            let mut g = Settings {
                credential: Some(group.clone()),
                tls_trust,
                tls_ca_file,
                timeout_seconds: either("TIMEOUT")?,
                section_timeout_seconds: either("SECTION_TIMEOUT")?,
                request_timeout_seconds: seconds(env, &key("REQUEST_TIMEOUT"))?,
                retries,
                orchestrator_release: Some(release.clone()),
                api_base: get("BASE").map(|b| b.trim_end_matches('/').to_string()),
                concurrency,
                refresh_seconds,
                ..Settings::default()
            };
            if self.has_route_keys("VELOCLOUD", Some(name))
                || self.has_route_keys("VELOCLOUD", None)
            {
                self.route(&group, "VELOCLOUD", Some(name))?;
                g.route = Some(group.clone());
            }
            self.credential(&group, CredentialSource::Env, &prefix);
            self.out.groups.push(Group {
                name: group.clone(),
                vendor: "velocloud".into(),
                description: None,
                settings: g,
            });
            let address = url.trim_end_matches('/').to_string();
            for e in get("ENTERPRISES")
                .map(|e| enterprise_ids(e.as_str()))
                .unwrap_or_default()
            {
                self.out.devices.push(Device {
                    name: enterprise_device(&id, &e),
                    group: group.clone(),
                    address: address.clone(),
                    site: None,
                    location: None,
                    console_site: Some(e),
                    settings: Settings::default(),
                });
            }
        }
        Ok(())
    }
}

impl Builder<'_> {
    /// The Equinix accounts: one group and one device `equinix-<name>` for
    /// each `EQUINIX_<NAME>_URL`. The credential is `equinix-<name>` with
    /// `EQUINIX_<NAME>_CLIENT_ID`, else `equinix` with `EQUINIX_CLIENT_ID`.
    fn equinix(&mut self) -> Result<(), String> {
        let env = self.env;
        for (key, url) in env {
            let Some(name) = key
                .strip_prefix("EQUINIX_")
                .and_then(|k| k.strip_suffix("_URL"))
            else {
                continue;
            };
            check_section_name(env, "EQUINIX", name)?;
            let prefix = format!("EQUINIX_{name}");
            let key = |k: &str| format!("{prefix}_{k}");
            let id = id_of(name);
            let group = format!("equinix-{id}");
            let (credential, reference) = equinix_client(env, name)?;
            let either = |k: &str| -> Result<Option<u32>, String> {
                Ok(seconds(env, &key(k))?.or(seconds(env, &format!("EQUINIX_{k}"))?))
            };
            let tls = env
                .get(&key("TLS"))
                .map(|t| (key("TLS"), t))
                .or_else(|| env.get("EQUINIX_TLS").map(|t| ("EQUINIX_TLS".into(), t)));
            let tls_trust = match &tls {
                None => None,
                Some((k, t)) => Some(
                    TlsTrust::parse(t)
                        .ok_or_else(|| format!("{k} {t} is not public, pin, ca or none"))?,
                ),
            };
            let tls_ca_file = if tls_trust == Some(TlsTrust::Ca) {
                let k = tls.as_ref().map_or(String::new(), |(k, _)| k.clone());
                let file = k.strip_suffix("_TLS").unwrap_or(&k).to_string() + "_CA_FILE";
                Some(
                    env.get(&file)
                        .ok_or_else(|| format!("{k}=ca needs {file}"))?
                        .clone(),
                )
            } else {
                None
            };
            let mut g = Settings {
                credential: Some(credential.clone()),
                tls_trust,
                tls_ca_file,
                timeout_seconds: either("TIMEOUT")?,
                paged_section_timeout_seconds: either("SECTION_TIMEOUT")?,
                request_timeout_seconds: either("REQUEST_TIMEOUT")?,
                ..Settings::default()
            };
            if self.has_route_keys("EQUINIX", Some(name)) || self.has_route_keys("EQUINIX", None) {
                self.route(&group, "EQUINIX", Some(name))?;
                g.route = Some(group.clone());
            }
            self.credential(&credential, CredentialSource::Env, &reference);
            self.out.groups.push(Group {
                name: group.clone(),
                vendor: "equinix".into(),
                description: None,
                settings: g,
            });
            self.out.devices.push(Device {
                name: group,
                group: format!("equinix-{id}"),
                address: url.trim_end_matches('/').to_string(),
                site: None,
                location: None,
                console_site: None,
                settings: Settings::default(),
            });
        }
        Ok(())
    }
}

/// The credential name and the env key prefix of the OAuth client of the
/// Equinix account `<NAME>`: `equinix-<name>` and `EQUINIX_<NAME>` when
/// `EQUINIX_<NAME>_CLIENT_ID` is set, else `equinix` and `EQUINIX`. The
/// prefix needs `<P>_CLIENT_ID` and `<P>_CLIENT_SECRET`.
pub fn equinix_client(
    env: &BTreeMap<String, String>,
    name: &str,
) -> Result<(String, String), String> {
    let own = format!("EQUINIX_{name}");
    let (credential, prefix) = if env.contains_key(&format!("{own}_CLIENT_ID")) {
        (format!("equinix-{}", id_of(name)), own)
    } else {
        ("equinix".to_string(), "EQUINIX".to_string())
    };
    for k in ["CLIENT_ID", "CLIENT_SECRET"] {
        if !env.contains_key(&format!("{prefix}_{k}")) {
            return Err(format!("{prefix}_{k} is not set"));
        }
    }
    Ok((credential, prefix))
}

/// The inventory records of an env file. The checks are those of the
/// collector: a device needs the credential of its vendor, each jump host
/// of a route needs its address and its credential, and the words and the
/// time limits must be valid. Two devices with one name are an error.
pub fn import(env: &BTreeMap<String, String>) -> Result<Records, String> {
    let mut b = Builder {
        env,
        out: Records::default(),
    };
    for (prefix, vendor) in SSH_PREFIXES {
        b.ssh_vendor(prefix, vendor)?;
    }
    b.unifi()?;
    b.velocloud()?;
    b.equinix()?;
    let mut seen: BTreeMap<&str, &Device> = BTreeMap::new();
    for d in &b.out.devices {
        if let Some(first) = seen.insert(&d.name, d) {
            return Err(format!(
                "the {} device {} and the {} device {} have one id: {}",
                first.group, first.address, d.group, d.address, d.name
            ));
        }
    }
    Ok(b.out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Inventory;

    fn inventory(r: Records) -> Inventory {
        Inventory {
            version: 1,
            credentials: r.credentials,
            jump_hosts: r.jump_hosts,
            routes: r.routes,
            groups: r.groups,
            devices: r.devices,
            bindings: Default::default(),
            collection: Default::default(),
        }
    }

    #[test]
    fn an_equinix_account_is_a_group_and_a_device() {
        let env = parse_env(
            "EQUINIX_PROD_URL=https://api.equinix.com/\nEQUINIX_LAB_URL=https://api.equinix.com\n\
             EQUINIX_CLIENT_ID=group-id\nEQUINIX_CLIENT_SECRET=fake-secret\n\
             EQUINIX_LAB_CLIENT_ID=lab-id\nEQUINIX_LAB_CLIENT_SECRET=fake-lab-secret\n\
             EQUINIX_SECTION_TIMEOUT=600\nEQUINIX_LAB_TLS=ca\nEQUINIX_LAB_CA_FILE=/ca.pem\n\
             EQUINIX_PROXY=http://192.0.2.9:3128\n",
        );
        let r = import(&env).unwrap();
        let devices: Vec<(&str, &str, &str)> = r
            .devices
            .iter()
            .map(|d| (d.name.as_str(), d.group.as_str(), d.address.as_str()))
            .collect();
        assert_eq!(
            devices,
            [
                ("equinix-lab", "equinix-lab", "https://api.equinix.com"),
                ("equinix-prod", "equinix-prod", "https://api.equinix.com"),
            ]
        );
        let refs: Vec<(&str, Option<&str>)> = r
            .credentials
            .iter()
            .filter(|c| c.source == CredentialSource::Env)
            .map(|c| (c.name.as_str(), c.key.as_deref()))
            .collect();
        assert_eq!(
            refs,
            [
                ("equinix-lab", Some("EQUINIX_LAB")),
                ("equinix", Some("EQUINIX"))
            ]
        );
        let lab = &r.groups[0].settings;
        assert_eq!(lab.credential.as_deref(), Some("equinix-lab"));
        assert_eq!(lab.tls_trust, Some(TlsTrust::Ca));
        assert_eq!(lab.tls_ca_file.as_deref(), Some("/ca.pem"));
        assert_eq!(lab.paged_section_timeout_seconds, Some(600));
        assert_eq!(lab.route.as_deref(), Some("equinix-lab"));
        let prod = &r.groups[1].settings;
        assert_eq!(prod.credential.as_deref(), Some("equinix"));
        assert_eq!(prod.tls_trust, None);
        assert_eq!(r.groups[1].vendor, "equinix");

        let mut e = env.clone();
        e.remove("EQUINIX_CLIENT_SECRET");
        assert_eq!(import(&e).unwrap_err(), "EQUINIX_CLIENT_SECRET is not set");
    }

    #[test]
    fn the_env_file_gives_groups_devices_and_references() {
        let env = parse_env(
            "# lab\nVYOS_CORE1_IP=192.0.2.1\nVYOS_EDGE_2_IP=192.0.2.2\nVYOS_EDGE_2_PROFILE=legacy\n\
             VYOS_USER=ro\nexport VYOS_PASS=\"p w\"\nVYOS_CAPTURE_BGP=all\nVYOS_EDGE_2_TIMEOUT=90\n\
             UNIFI_CONTROLLER=192.0.2.8\nUNIFI_SITES=default, branch\nUNIFI_USER=ro\nUNIFI_PASS='x'\n",
        );
        let r = import(&env).unwrap();
        let names: Vec<&str> = r.devices.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["core1", "edge-2", "unifi-default", "unifi-branch"]);
        let groups: Vec<&str> = r.groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(groups, ["vyos", "unifi"]);
        assert_eq!(
            r.credentials,
            [
                Credential::env("vyos", CredentialSource::Env, "VYOS"),
                Credential::env("unifi", CredentialSource::Env, "UNIFI"),
            ]
        );
        let text = format!("{r:?}");
        assert!(!text.contains("p w") && !text.contains("\"x\""), "{text}");
        let inv = inventory(r);
        let devices = inv.resolve().unwrap();
        let edge = devices.iter().find(|d| d.name == "edge-2").unwrap();
        assert_eq!(edge.settings.ssh_algorithms.value, SshAlgorithms::Legacy);
        assert_eq!(edge.settings.timeout_seconds.value, 90);
        assert_eq!(edge.settings.capture_bgp.value, CaptureBgp::All);
        assert_eq!(
            edge.settings.capture_bgp.origin,
            crate::resolve::Origin::Group
        );
        let branch = devices.iter().find(|d| d.name == "unifi-branch").unwrap();
        assert_eq!(branch.console_site.as_deref(), Some("branch"));
        assert_eq!(branch.address, "192.0.2.8");
    }

    #[test]
    fn a_velocloud_orchestrator_is_a_group_and_each_enterprise_a_device() {
        let env = parse_env(
            "VELOCLOUD_LAB_URL=https://198.51.100.10/\nVELOCLOUD_LAB_TOKEN=fake-token\n\
             VELOCLOUD_LAB_ENTERPRISES=ent-a, ent-b\nVELOCLOUD_LAB_RELEASE=6.4.0\n\
             VELOCLOUD_LAB_BASE=/api/sdwan/v2/\nVELOCLOUD_LAB_CONCURRENCY=2\n\
             VELOCLOUD_LAB_REFRESH=0\nVELOCLOUD_LAB_RETRIES=3\n\
             VELOCLOUD_LAB_REQUEST_TIMEOUT=90\nVELOCLOUD_TIMEOUT=300\n",
        );
        let r = import(&env).unwrap();
        assert_eq!(
            r.credentials,
            [Credential::env(
                "velocloud-lab",
                CredentialSource::Env,
                "VELOCLOUD_LAB"
            )]
        );
        assert!(!format!("{r:?}").contains("fake-token"));
        let g = &r.groups[0];
        assert_eq!(
            (g.name.as_str(), g.vendor.as_str()),
            ("velocloud-lab", "velocloud")
        );
        assert_eq!(
            g.settings,
            Settings {
                credential: Some("velocloud-lab".into()),
                timeout_seconds: Some(300),
                request_timeout_seconds: Some(90),
                retries: Some(3),
                orchestrator_release: Some("6.4.0".into()),
                api_base: Some("/api/sdwan/v2".into()),
                concurrency: Some(2),
                refresh_seconds: Some(0),
                ..Settings::default()
            }
        );
        let names: Vec<(&str, &str, Option<&str>)> = r
            .devices
            .iter()
            .map(|d| {
                (
                    d.name.as_str(),
                    d.address.as_str(),
                    d.console_site.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            names,
            [
                ("vco-lab-ent-a", "https://198.51.100.10", Some("ent-a")),
                ("vco-lab-ent-b", "https://198.51.100.10", Some("ent-b")),
            ]
        );
        let devices = inventory(r).resolve().unwrap();
        assert_eq!(devices[0].settings.tls_trust.value, TlsTrust::Public);
    }

    #[test]
    fn an_empty_via_of_a_device_is_a_direct_route_and_a_proxy_login_is_a_reference() {
        let env = parse_env(
            "VYOS_CORE1_IP=10.0.0.1\nVYOS_EDGE_IP=10.0.0.2\nVYOS_EDGE_VIA=\n\
             VYOS_VIA=bastion-a, inner\nVYOS_PROXY=socks5://p:q@192.0.2.9:1080\n\
             VYOS_USER=ro\nVYOS_AGENT=default\n\
             JUMP_BASTION_A_IP=192.0.2.20\nJUMP_BASTION_A_USER=hop\nJUMP_BASTION_A_PASS=h\n\
             JUMP_INNER_IP=10.0.0.254:2222\nJUMP_INNER_USER=hop2\nJUMP_INNER_AGENT=/tmp/agent\n\
             JUMP_INNER_PROFILE=legacy\n",
        );
        let r = import(&env).unwrap();
        let group_route = r.routes.iter().find(|x| x.name == "vyos").unwrap();
        assert_eq!(group_route.jumps, ["bastion-a", "inner"]);
        assert_eq!(
            group_route.proxy.as_deref(),
            Some("socks5://192.0.2.9:1080")
        );
        assert_eq!(group_route.proxy_credential.as_deref(), Some("vyos-proxy"));
        let edge_route = r.routes.iter().find(|x| x.name == "vyos-edge").unwrap();
        assert!(
            edge_route.jumps.is_empty(),
            "an empty VIA is a direct route"
        );
        assert_eq!(
            edge_route.proxy.as_deref(),
            Some("socks5://192.0.2.9:1080"),
            "the device takes the proxy of the vendor"
        );
        let proxy = r
            .credentials
            .iter()
            .find(|c| c.name == "vyos-proxy")
            .unwrap();
        assert_eq!(
            (proxy.source, proxy.key.as_deref().unwrap_or("")),
            (CredentialSource::EnvUrl, "VYOS_PROXY")
        );
        let inner = r.jump_hosts.iter().find(|j| j.name == "inner").unwrap();
        assert_eq!(inner.ssh_algorithms, SshAlgorithms::Legacy);
        assert_eq!(inner.credential, "jump-inner");
        assert!(!format!("{r:?}").contains("p:q"));
        let inv = inventory(r);
        let devices = inv.resolve().unwrap();
        assert_eq!(devices[0].name, "core1");
        assert_eq!(devices[0].settings.route.value.as_deref(), Some("vyos"));
        assert_eq!(
            devices[0].settings.route.origin,
            crate::resolve::Origin::Group
        );
        assert_eq!(
            devices[1].settings.route.value.as_deref(),
            Some("vyos-edge")
        );
        assert_eq!(
            devices[1].settings.route.origin,
            crate::resolve::Origin::Device
        );
    }

    #[test]
    fn the_import_checks_what_the_collector_checks() {
        for (text, needle) in [
            ("VYOS_CORE1_IP=192.0.2.1\n", "VYOS_USER"),
            ("VYOS_CORE1_IP=192.0.2.1\nVYOS_USER=u\n", "VYOS_PASS"),
            (
                "VYOS_X_IP=10.0.0.1\nVYOS_X_VIA=nope\nVYOS_USER=u\nVYOS_PASS=p\n",
                "JUMP_NOPE_IP",
            ),
            (
                "VYOS_R1_IP=192.0.2.1\nVYOS_USER=u\nVYOS_PASS=p\nVYOS_R1_TIMEOUT=0\n",
                "positive number of seconds",
            ),
            (
                "VYOS_R1_IP=192.0.2.1\nVYOS_USER=u\nVYOS_PASS=p\nVYOS_CAPTURE_BGP=ALL\n",
                "sessions, all or off",
            ),
            (
                "VYOS_R1_SECTION_IP=192.0.2.3\nVYOS_R1_SECTION_TIMEOUT=10\nVYOS_USER=u\nVYOS_PASS=p\n",
                "another name",
            ),
            (
                "VYOS_CORE1_IP=192.0.2.1\nNXOS_CORE1_IP=192.0.2.2\nVYOS_USER=u\nVYOS_PASS=p\n\
                 NXOS_USER=u\nNXOS_PASS=p\n",
                "one id",
            ),
            (
                "NXOS_X_IP=192.0.2.1\nNXOS_USER=u\nNXOS_PASS=p\nNXOS_X_JSON=xml\n",
                "plain or native",
            ),
            (
                "UNIFI_CONTROLLER=192.0.2.8\nUNIFI_TLS=ca\nUNIFI_API_KEY=k\n",
                "UNIFI_CA_FILE",
            ),
            (
                "VYOS_R1_IP=192.0.2.1\nVYOS_USER=u\nVYOS_PASS=p\nVYOS_PROXY=ftp://h:1\n",
                "scheme ftp",
            ),
            (
                "VELOCLOUD_LAB_URL=https://198.51.100.10\nVELOCLOUD_LAB_RELEASE=6.4.0\n",
                "VELOCLOUD_LAB_TOKEN",
            ),
            (
                "VELOCLOUD_LAB_URL=https://198.51.100.10\nVELOCLOUD_LAB_TOKEN=t\n\
                 VELOCLOUD_LAB_RELEASE=4.5.0\n",
                "before 5.0.0.0",
            ),
            (
                "VELOCLOUD_LAB_URL=https://198.51.100.10\nVELOCLOUD_LAB_TOKEN=t\n",
                "VELOCLOUD_LAB_RELEASE",
            ),
            (
                "VELOCLOUD_LAB_URL=https://198.51.100.10\nVELOCLOUD_LAB_TOKEN=t\n\
                 VELOCLOUD_LAB_RELEASE=6.4.0\nVELOCLOUD_LAB_CONCURRENCY=17\n",
                "from 1 to 16",
            ),
            (
                "VELOCLOUD_LAB_URL=https://198.51.100.10\nVELOCLOUD_LAB_TOKEN=t\n\
                 VELOCLOUD_LAB_RELEASE=6.4.0\nVELOCLOUD_LAB_CLIENT_CERT=/c.pem\n",
                "client certificate",
            ),
        ] {
            let err = import(&parse_env(text))
                .err()
                .unwrap_or_else(|| panic!("{text}"));
            assert!(err.contains(needle), "{text}: {err}");
        }
    }

    #[test]
    fn a_proxy_url_loses_its_login() {
        assert_eq!(
            split_proxy("http://u:p@proxy.example:3128/").unwrap(),
            ("http://proxy.example:3128".to_string(), true)
        );
        assert_eq!(
            split_proxy("socks5://[2001:db8::1]:1080").unwrap(),
            ("socks5://[2001:db8::1]:1080".to_string(), false)
        );
        assert!(split_proxy("http://proxy.example").is_err());
    }

    #[test]
    fn a_proxy_url_needs_a_host_and_a_numeric_port() {
        for (url, needle) in [
            ("socks5://[2001:db8::1]", "no port"),
            ("http://proxy.example:abc", "bad port"),
            ("http://proxy.example:70000", "bad port"),
            ("http://:3128", "no host"),
            ("http://u@proxy.example:3128", "no password"),
        ] {
            let err = split_proxy(url).err().unwrap_or_else(|| panic!("{url}"));
            assert!(err.contains(needle), "{url}: {err}");
        }
        let err = import(&parse_env(
            "VYOS_R1_IP=192.0.2.1\nVYOS_USER=u\nVYOS_PASS=p\nVYOS_PROXY=socks5://[2001:db8::1]\n",
        ))
        .err()
        .unwrap();
        assert!(
            err.contains("VYOS_PROXY") && err.contains("no port"),
            "{err}"
        );
    }
}
