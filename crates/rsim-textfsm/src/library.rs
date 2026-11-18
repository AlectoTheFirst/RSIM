//! A set of templates with their index, and the templates that the crate
//! carries.

use std::collections::BTreeMap;
use std::fmt;

use crate::index::{Index, IndexError};
use crate::template::{Template, TemplateError};

macro_rules! builtin {
    ($($name:literal),* $(,)?) => {
        /// The templates that the crate carries: the file name and the text.
        pub const BUILTIN_TEMPLATES: &[(&str, &str)] = &[
            $(($name, include_str!(concat!("../templates/", $name))),)*
        ];
    };
}

builtin!(
    "cisco_ios_show_cdp_neighbors_detail.textfsm",
    "cisco_ios_show_interfaces.textfsm",
    "cisco_ios_show_ip_access-lists.textfsm",
    "cisco_ios_show_ip_arp.textfsm",
    "cisco_ios_show_ip_bgp_summary.textfsm",
    "cisco_ios_show_ip_ospf_database_network.textfsm",
    "cisco_ios_show_ip_ospf_database_router.textfsm",
    "cisco_ios_show_ip_ospf_neighbor.textfsm",
    "cisco_ios_show_ip_route.textfsm",
    "cisco_ios_show_lldp_neighbors_detail.textfsm",
    "cisco_ios_show_mac-address-table.textfsm",
    "cisco_ios_show_spanning-tree.textfsm",
    "cisco_ios_show_standby.textfsm",
    "cisco_ios_show_standby_brief.textfsm",
    "cisco_ios_show_version.textfsm",
    "cisco_ios_show_vlan.textfsm",
    "cisco_ios_show_vrf.textfsm",
    "cisco_ios_show_vrf_detail.textfsm",
    "cisco_ios_show_vrrp_all.textfsm",
    "cisco_ios_show_vrrp_brief.textfsm",
    "cisco_xr_admin_show_inventory.textfsm",
    "cisco_xr_show_arp.textfsm",
    "cisco_xr_show_cdp_neighbors_detail.textfsm",
    "cisco_xr_show_hsrp.textfsm",
    "cisco_xr_show_interfaces.textfsm",
    "cisco_xr_show_ip_route.textfsm",
    "cisco_xr_show_lldp_neighbors_detail.textfsm",
    "cisco_xr_show_ospf_neighbor.textfsm",
    "cisco_xr_show_version.textfsm",
    "cisco_xr_show_vrf_all_detail.textfsm",
);

/// The index of the templates that the crate carries.
pub const BUILTIN_INDEX: &str = include_str!("../templates/index");

/// A library that cannot be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LibraryError {
    /// The index cannot be read.
    Index(IndexError),
    /// A template cannot be read.
    Template {
        /// The file name of the template.
        name: String,
        /// The error of the template.
        error: TemplateError,
    },
    /// The index names a template that the library does not have.
    Missing {
        /// The file name of the template.
        name: String,
        /// The line of the index row, from 1.
        line: usize,
    },
}

impl fmt::Display for LibraryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Index(error) => error.fmt(f),
            Self::Template { name, error } => write!(f, "{name}: {error}"),
            Self::Missing { name, line } => {
                write!(f, "index line {line}: no template '{name}'")
            }
        }
    }
}

impl std::error::Error for LibraryError {}

/// Templates by file name, with the index that selects them.
#[derive(Clone, Debug)]
pub struct Library {
    index: Index,
    templates: BTreeMap<String, Template>,
}

impl Library {
    /// Builds a library from the text of an index and the file name and text
    /// of each template. Each template that the index names must be given.
    pub fn new<'a>(
        index: &str,
        templates: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, LibraryError> {
        let index = Index::parse(index).map_err(LibraryError::Index)?;
        let mut parsed = BTreeMap::new();
        for (name, text) in templates {
            let template = Template::parse(text).map_err(|error| LibraryError::Template {
                name: name.to_string(),
                error,
            })?;
            parsed.insert(name.to_string(), template);
        }
        for row in index.rows() {
            for name in row.templates() {
                if !parsed.contains_key(name) {
                    return Err(LibraryError::Missing {
                        name: name.to_string(),
                        line: row.line(),
                    });
                }
            }
        }
        Ok(Self {
            index,
            templates: parsed,
        })
    }

    /// The library of the templates that the crate carries.
    pub fn builtin() -> Result<Self, LibraryError> {
        Self::new(BUILTIN_INDEX, BUILTIN_TEMPLATES.iter().copied())
    }

    /// The index.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// The template of a file name.
    pub fn template(&self, name: &str) -> Option<&Template> {
        self.templates.get(name)
    }

    /// The template of a platform and a command, with its file name.
    pub fn find(&self, platform: &str, command: &str) -> Option<(&str, &Template)> {
        let name = self.index.template_for(platform, command)?;
        let (name, template) = self.templates.get_key_value(name)?;
        Some((name.as_str(), template))
    }
}
