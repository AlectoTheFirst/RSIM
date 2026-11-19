//! The records of the inventory and the words of their settings.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An enum of words: each variant has one word in the database and in
/// JSON.
macro_rules! words {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $v:ident = $w:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
        pub enum $name {
            $($(#[$vm])* #[serde(rename = $w)] $v),+
        }

        impl $name {
            /// All words, in order.
            pub const ALL: &'static [$name] = &[$($name::$v),+];

            pub fn word(self) -> &'static str {
                match self {
                    $($name::$v => $w),+
                }
            }

            pub fn parse(word: &str) -> Option<$name> {
                match word {
                    $($w => Some($name::$v),)+
                    _ => None,
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.word())
            }
        }
    };
}

words! {
    /// The source of a credential.
    CredentialSource {
        /// The keys `<KEY>_USER` and `<KEY>_PASS`, `<KEY>_KEY_FILE` with
        /// `<KEY>_KEY_PASS`, `<KEY>_AGENT` or `<KEY>_API_KEY` of the env
        /// file of the collector.
        Env = "env",
        /// The user and the password in the URL of the env key `<KEY>`,
        /// for example the login of a proxy URL.
        EnvUrl = "env-url",
    }
}

words! {
    /// The SSH algorithm set of a connection.
    SshAlgorithms {
        Modern = "modern",
        /// The modern set with the SHA-1 and CBC algorithms that older
        /// network operating systems need.
        Legacy = "legacy",
    }
}

words! {
    /// How SSH sends the commands of a device.
    SshMode {
        /// One exec channel for each command.
        Exec = "exec",
        /// One interactive shell for all commands.
        Shell = "shell",
        /// One connection for each command.
        Connection = "connection",
    }
}

words! {
    /// The JSON form of the NX-OS answers.
    NxosJson {
        /// `| json`.
        Plain = "plain",
        /// `| json native`, NX-OS 9.3 and later.
        Native = "native",
    }
}

words! {
    /// The check of the TLS certificate of an HTTPS device.
    TlsTrust {
        /// The certificate is pinned at first contact.
        Pin = "pin",
        /// The certificate chains to the CA bundle of `tls_ca_file`.
        Ca = "ca",
        /// No check of the certificate.
        None = "none",
    }
}

words! {
    /// The BGP sections that the collector reads of a router.
    CaptureBgp {
        Off = "off",
        /// The summary of each session.
        Sessions = "sessions",
        /// The summaries, the neighbour detail and the tables of each
        /// neighbour.
        All = "all",
    }
}

words! {
    /// What a trace does at an HA pair or a cluster whose active node is
    /// not collected.
    Ha {
        /// The trace stops at the pair with `Unknown`.
        None = "none",
        /// The trace follows each node.
        All = "all",
        /// The trace follows one node, chosen in a fixed order.
        One = "one",
    }
}

words! {
    /// The transport of a collector.
    CollectorTransport {
        Ssh = "ssh",
        Https = "https",
    }
}

/// The vendors that have a collector, each with its transport, in name
/// order.
pub const COLLECTOR_VENDORS: &[(&str, CollectorTransport)] = &[
    ("iosxe", CollectorTransport::Ssh),
    ("iosxr", CollectorTransport::Ssh),
    ("nxos", CollectorTransport::Ssh),
    ("unifi", CollectorTransport::Https),
    ("vyos", CollectorTransport::Ssh),
];

/// A reference to a credential. The secret stays in its source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    /// The name of the reference. In a PUT body it can be left out; the
    /// path gives it.
    #[serde(default)]
    pub name: String,
    pub source: CredentialSource,
    /// The key in the source.
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// An SSH jump host with its own credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JumpHost {
    #[serde(default)]
    pub name: String,
    /// The host name or the address, with an optional port.
    pub address: String,
    /// The name of the credential reference.
    pub credential: String,
    #[serde(default = "modern")]
    pub ssh_algorithms: SshAlgorithms,
}

fn modern() -> SshAlgorithms {
    SshAlgorithms::Modern
}

/// The network path to a device: an optional proxy for the first TCP
/// connection, then the jump hosts in order. A route with no proxy and no
/// jump host is a direct connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default)]
    pub name: String,
    /// `http://host:port`, `socks5://host:port` or `socks5h://host:port`,
    /// with no login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// The credential reference of the login of the proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_credential: Option<String>,
    /// The names of the jump hosts, in order.
    #[serde(default)]
    pub jumps: Vec<String>,
}

/// The settings of a device group or of a device. On a device, a setting
/// that is not given takes the value of the group; on a group, a setting
/// that is not given takes the default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The name of the credential reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    /// The name of the route. The default is a direct connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_algorithms: Option<SshAlgorithms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_mode: Option<SshMode>,
    /// The exec channels at one time. The default is 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_channels: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nxos_json: Option<NxosJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_trust: Option<TlsTrust>,
    /// The PEM file of the CA bundle of `tls_trust` `ca`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_bgp: Option<CaptureBgp>,
    /// The time for all sections of a device, from 1 to 86400 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
    /// The time for one section, from 1 to 86400 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_timeout_seconds: Option<u32>,
    /// The time for one HTTP request, from 1 to 86400 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_seconds: Option<u32>,
    /// The time for the read of all pages of one section, from 1 to 86400
    /// seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paged_section_timeout_seconds: Option<u32>,
    /// The retries of a failed section, from 0 to 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ha: Option<Ha>,
}

/// A device group: the vendor and the settings of its devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Group {
    #[serde(default)]
    pub name: String,
    /// The vendor, for example `vyos`, `nxos`, `iosxr`, `iosxe` or `unifi`.
    /// A vendor with no collector is allowed; the collector skips its
    /// devices.
    pub vendor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub settings: Settings,
}

/// A device of the inventory. Its name is the device of the snapshot
/// store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Device {
    #[serde(default)]
    pub name: String,
    /// The name of the device group.
    pub group: String,
    /// The host name or the address of the management plane.
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The site of a controller that the device reads, for example the
    /// UniFi site of a console.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_site: Option<String>,
    /// The settings that the device sets in place of its group.
    #[serde(default)]
    pub settings: Settings,
}

/// A Fabric port of an Equinix account and the device port at the other
/// end of its cross connect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FabricPortBinding {
    /// The device of the account. In a PUT body it can be left out; the
    /// path gives it.
    #[serde(default)]
    pub account: String,
    /// The uuid or the name of the Fabric port.
    #[serde(default)]
    pub fabric_port: String,
    pub device: String,
    pub port: String,
}

/// A Network Edge device of an Equinix account and the device of the
/// estate that it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EdgeDeviceBinding {
    #[serde(default)]
    pub account: String,
    /// The uuid of the Network Edge device.
    #[serde(default)]
    pub edge_device: String,
    pub device: String,
}

/// The bindings of the inventory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Bindings {
    pub fabric_ports: Vec<FabricPortBinding>,
    pub edge_devices: Vec<EdgeDeviceBinding>,
}

/// The whole inventory at one version, with each list sorted by its key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Inventory {
    /// The version. Each change of the inventory increases it by 1.
    pub version: u64,
    pub credentials: Vec<Credential>,
    pub jump_hosts: Vec<JumpHost>,
    pub routes: Vec<Route>,
    pub groups: Vec<Group>,
    pub devices: Vec<Device>,
    pub bindings: Bindings,
}

/// The kind of a change of the audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Update,
    Delete,
}

impl Action {
    pub fn word(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Update => "update",
            Action::Delete => "delete",
        }
    }
}

/// One record of the audit log: who changed what and when, with the old
/// and the new value of the record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuditRecord {
    pub id: i64,
    /// The time of the change in UTC, RFC 3339.
    pub at: String,
    pub actor: String,
    /// The inventory version that the change made.
    pub version: u64,
    /// `credential`, `jump_host`, `route`, `group`, `device`,
    /// `fabric_port_binding` or `edge_device_binding`.
    pub kind: String,
    /// The key of the record, for example the device name.
    pub key: String,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<serde_json::Value>,
}

/// A page of the audit log, the newest record first.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuditPage {
    pub records: Vec<AuditRecord>,
    /// The `before` value of the next page, if there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_before: Option<i64>,
}

/// True if a name of a credential, a jump host, a route or a group is
/// valid: lower-case letters, digits, `.`, `_` and `-`, starting with a
/// letter or a digit.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
}

/// True if a device name is valid: not empty, with no `/` and no space.
pub fn valid_device_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| c == '/' || c.is_whitespace())
}
