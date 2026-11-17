//! The interface names of an NX-OS switch. The config prints each name in
//! full, for example `Ethernet1/1`, and the collected sections can print it
//! short, for example `Eth1/1` or `Po10`.

use std::collections::{BTreeMap, BTreeSet};

/// The interface types of NX-OS with their short forms, in lower case.
const TYPES: &[(&str, &[&str])] = &[
    ("ethernet", &["eth", "et", "e"]),
    ("port-channel", &["po"]),
    ("vlan", &["vl"]),
    ("loopback", &["lo"]),
    ("mgmt", &["mgmt", "management", "mg"]),
    ("tunnel", &["tu"]),
    ("nve", &["nv"]),
    ("null", &["nu"]),
];

/// Splits a name into its type word and its number, for example
/// `Eth1/1.10` into `Eth` and `1/1.10`.
fn split(name: &str) -> Option<(&str, &str)> {
    let name = name.trim();
    let i = name.find(|c: char| c.is_ascii_digit())?;
    let (word, number) = name.split_at(i);
    let word = word.trim();
    (!word.is_empty() && word.chars().all(|c| c.is_ascii_alphabetic() || c == '-'))
        .then_some((word, number))
}

/// The canonical type of a type word, in lower case, if NX-OS has it.
fn canonical_type(word: &str) -> Option<&'static str> {
    let w = word.to_ascii_lowercase();
    TYPES
        .iter()
        .find(|(full, short)| *full == w || short.contains(&w.as_str()))
        .map(|(full, _)| *full)
}

/// Resolves the names of a section against the interface names of the
/// config.
///
/// A name resolves, in order, to itself if the config has it, or to the one
/// config name with the same canonical type and the same number. The number
/// must be the same text, so `Eth1/1.10` does not resolve to `Ethernet1/1`.
/// A name with no unique answer stays as it is, because a wrong answer puts
/// a row on another interface.
#[derive(Clone, Debug, Default)]
pub struct Names {
    exact: BTreeSet<String>,
    by_key: BTreeMap<(String, String), Vec<String>>,
}

impl Names {
    pub fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> Names {
        let mut n = Names::default();
        for name in names {
            n.exact.insert(name.to_string());
            if let Some((word, number)) = split(name)
                && let Some(t) = canonical_type(word)
            {
                n.by_key
                    .entry((t.to_string(), number.to_ascii_lowercase()))
                    .or_default()
                    .push(name.to_string());
            }
        }
        n
    }

    /// The config name of a name that a section prints.
    pub fn resolve(&self, name: &str) -> String {
        let name = name.trim();
        if self.exact.contains(name) {
            return name.to_string();
        }
        let found = split(name).and_then(|(word, number)| {
            let t = canonical_type(word)?;
            match self
                .by_key
                .get(&(t.to_string(), number.to_ascii_lowercase()))?
                .as_slice()
            {
                [one] => Some(one.clone()),
                _ => None,
            }
        });
        found.unwrap_or_else(|| name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_name_resolves_to_the_config_name() {
        let n = Names::new([
            "Ethernet1/1",
            "Ethernet1/2.10",
            "port-channel10",
            "Vlan10",
            "loopback0",
            "mgmt0",
        ]);
        assert_eq!(n.resolve("Eth1/1"), "Ethernet1/1");
        assert_eq!(n.resolve("Ethernet1/1"), "Ethernet1/1");
        assert_eq!(n.resolve("Po10"), "port-channel10");
        assert_eq!(n.resolve("Vlan10"), "Vlan10");
        assert_eq!(n.resolve("Lo0"), "loopback0");
        assert_eq!(n.resolve("Eth1/2.10"), "Ethernet1/2.10");
        // A different number does not resolve.
        assert_eq!(n.resolve("Eth1/2"), "Eth1/2");
        // An unknown type stays.
        assert_eq!(n.resolve("Null0"), "Null0");
        assert_eq!(n.resolve("sup-eth1"), "sup-eth1");
    }
}
