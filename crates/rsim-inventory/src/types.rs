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
    /// Credential source
    CredentialSource {
        /// Env credential
        Env = "env",
        /// Env URL credential
        EnvUrl = "env-url",
        /// Managed credential
        Managed = "managed",
    }
}

words! {
    /// Secret kind
    CredentialKind {
        /// Password
        Password = "password",
        /// SSH key
        SshKey = "ssh-key",
        /// API key
        ApiKey = "api-key",
    }
}

words! {
    /// SSH algorithms
    SshAlgorithms {
        Modern = "modern",
        /// Legacy algorithms
        Legacy = "legacy",
    }
}

words! {
    /// SSH command mode
    SshMode {
        /// Exec channel per command
        Exec = "exec",
        /// Shell
        Shell = "shell",
        /// Connection per command
        Connection = "connection",
    }
}

words! {
    /// NX-OS JSON form
    NxosJson {
        /// JSON
        Plain = "plain",
        /// JSON native
        Native = "native",
    }
}

words! {
    /// TLS trust
    TlsTrust {
        /// Pinned at first contact
        Pin = "pin",
        /// CA bundle
        Ca = "ca",
        /// No check
        None = "none",
    }
}

words! {
    /// BGP sections
    CaptureBgp {
        Off = "off",
        /// Sessions
        Sessions = "sessions",
        /// All
        All = "all",
    }
}

words! {
    /// HA setting
    Ha {
        /// None
        None = "none",
        /// All nodes
        All = "all",
        /// One node
        One = "one",
    }
}

words! {
    /// Transport
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

/// Credential
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    /// Name
    #[serde(default)]
    pub name: String,
    pub source: CredentialSource,
    /// Env key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Secret kind
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CredentialKind>,
    /// User
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Secret revision
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_revision: Option<u64>,
}

impl Credential {
    /// A credential of the env file.
    pub fn env(name: &str, source: CredentialSource, key: &str) -> Credential {
        Credential {
            name: name.to_string(),
            source,
            key: Some(key.to_string()),
            kind: None,
            user: None,
            description: None,
            secret_revision: None,
        }
    }

    /// The check of the fields of the source, with no database.
    pub fn check(&self) -> Result<(), String> {
        let n = &self.name;
        match self.source {
            CredentialSource::Env | CredentialSource::EnvUrl => {
                let key = self.key.as_deref().ok_or_else(|| {
                    format!(
                        "the credential {n} of the source {} needs a key",
                        self.source
                    )
                })?;
                if key.is_empty()
                    || !key
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
                    return Err(format!(
                        "the key {key:?} of {n} is not upper-case letters, digits and '_'"
                    ));
                }
                if self.kind.is_some() || self.user.is_some() {
                    return Err(format!(
                        "the credential {n} of the source {} takes its kind and user from the env file",
                        self.source
                    ));
                }
            }
            CredentialSource::Managed => {
                if self.key.is_some() {
                    return Err(format!("the managed credential {n} has no key"));
                }
                let kind = self
                    .kind
                    .ok_or_else(|| format!("the managed credential {n} needs a kind"))?;
                match (kind, self.user.as_deref()) {
                    (CredentialKind::ApiKey, Some(_)) => {
                        return Err(format!("the api-key credential {n} has no user"));
                    }
                    (CredentialKind::Password | CredentialKind::SshKey, None | Some("")) => {
                        return Err(format!("the {kind} credential {n} needs a user"));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// Jump host
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JumpHost {
    #[serde(default)]
    pub name: String,
    /// Address
    pub address: String,
    /// Name
    pub credential: String,
    #[serde(default = "modern")]
    pub ssh_algorithms: SshAlgorithms,
}

fn modern() -> SshAlgorithms {
    SshAlgorithms::Modern
}

/// Route
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default)]
    pub name: String,
    /// Proxy URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Proxy credential
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_credential: Option<String>,
    /// Jump hosts
    #[serde(default)]
    pub jumps: Vec<String>,
}

/// Settings
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    /// Route
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_algorithms: Option<SshAlgorithms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_mode: Option<SshMode>,
    /// Exec channels
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_channels: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nxos_json: Option<NxosJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_trust: Option<TlsTrust>,
    /// CA file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_bgp: Option<CaptureBgp>,
    /// Device time limit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
    /// Section time limit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_timeout_seconds: Option<u32>,
    /// Request time limit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_seconds: Option<u32>,
    /// Paged section time limit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paged_section_timeout_seconds: Option<u32>,
    /// Retries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ha: Option<Ha>,
}

/// Device group
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Group {
    #[serde(default)]
    pub name: String,
    /// Vendor
    pub vendor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub settings: Settings,
}

/// Device
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Device {
    #[serde(default)]
    pub name: String,
    /// Device group
    pub group: String,
    /// Address
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Controller site
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_site: Option<String>,
    /// Device settings
    #[serde(default)]
    pub settings: Settings,
}

/// Fabric port binding
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FabricPortBinding {
    /// Device
    #[serde(default)]
    pub account: String,
    /// Fabric port
    #[serde(default)]
    pub fabric_port: String,
    pub device: String,
    pub port: String,
}

/// Edge device binding
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EdgeDeviceBinding {
    #[serde(default)]
    pub account: String,
    /// Edge device
    #[serde(default)]
    pub edge_device: String,
    pub device: String,
}

/// Bindings
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Bindings {
    pub fabric_ports: Vec<FabricPortBinding>,
    pub edge_devices: Vec<EdgeDeviceBinding>,
}

/// Inventory
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Inventory {
    /// Version
    pub version: u64,
    pub credentials: Vec<Credential>,
    pub jump_hosts: Vec<JumpHost>,
    pub routes: Vec<Route>,
    pub groups: Vec<Group>,
    pub devices: Vec<Device>,
    pub bindings: Bindings,
}

/// Change kind
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

/// Audit record
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuditRecord {
    pub id: i64,
    /// Time
    pub at: String,
    pub actor: String,
    /// Inventory version
    pub version: u64,
    /// Record kind
    pub kind: String,
    /// Record key
    pub key: String,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<serde_json::Value>,
}

/// Audit log page
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuditPage {
    pub records: Vec<AuditRecord>,
    /// Next before
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
