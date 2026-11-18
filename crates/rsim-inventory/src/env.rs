//! The env file of the collector and its import into inventory records.
//!
//! The import gives one group for each vendor of the file, named after the
//! vendor, with the credential reference `env:<P>`, the route of `<P>_VIA`
//! and `<P>_PROXY`, and the vendor keys of the time limits and the BGP
//! sections. A device with its own `VIA` or `PROXY` key gets its own route.
//! A proxy login becomes the reference `env-url:<key>`, so no secret leaves
//! the env file.

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

/// The split of a proxy URL `scheme://[user:password@]host:port[/]` into
/// the URL with no login and whether it has a login.
pub fn split_proxy(url: &str) -> Result<(String, bool), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "the proxy has no scheme".to_string())?;
    if !matches!(scheme, "http" | "socks5" | "socks5h") {
        return Err(format!("the proxy scheme {scheme} is not supported"));
    }
    let (login, host) = match rest.rsplit_once('@') {
        Some((_, h)) => (true, h),
        None => (false, rest),
    };
    let host = host.trim_end_matches('/');
    if host.is_empty() || !host.contains(':') {
        return Err(format!("the proxy {host} has no port"));
    }
    Ok((format!("{scheme}://{host}"), login))
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
            self.out.credentials.push(Credential {
                name: name.to_string(),
                source,
                key: key.to_string(),
                description: None,
            });
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
                    .ok_or_else(|| format!("UNIFI_TLS {t} is not pin, ca or none"))?,
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
        }
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
                Credential {
                    name: "vyos".into(),
                    source: CredentialSource::Env,
                    key: "VYOS".into(),
                    description: None
                },
                Credential {
                    name: "unifi".into(),
                    source: CredentialSource::Env,
                    key: "UNIFI".into(),
                    description: None
                },
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
            (proxy.source, proxy.key.as_str()),
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
}
