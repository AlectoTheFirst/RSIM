//! Hand-built topologies for the tests, the benchmarks, `rsim-cli` and
//! `rsim-mcp`.
//!
//! All vendor profile values here are hand-built test data. They are not
//! confirmed against a device.

#![allow(clippy::type_complexity)]

mod builders;
mod chain;
mod ecmp;
mod edge_dnat;
mod hairpin;
mod helpers;
mod layer2_site;
mod mini_enterprise;
mod profiles;
mod routing_loop;

pub use builders::*;
pub use chain::chain;
pub use ecmp::ecmp;
pub use edge_dnat::{EdgeOpts, edge_dnat};
pub use hairpin::hairpin;
pub use helpers::*;
pub use layer2_site::*;
pub use mini_enterprise::{MiniOpts, mini_enterprise};
pub use profiles::*;
pub use routing_loop::routing_loop;

use rsim_engine::{Twin, TwinBuilder};

/// The built-in topologies by name, in a fixed order.
const BUILTIN: [(&str, fn() -> TwinBuilder); 6] = [
    ("mini-enterprise", || mini_enterprise(MiniOpts::default())),
    ("edge-dnat", || edge_dnat(EdgeOpts::default())),
    ("ecmp", ecmp),
    ("routing-loop", routing_loop),
    ("hairpin", hairpin),
    ("chain", || chain(10, 20, 100)),
];

/// The names of the built-in topologies, in a fixed order.
pub fn names() -> Vec<&'static str> {
    BUILTIN.iter().map(|(n, _)| *n).collect()
}

/// The twin of a built-in topology, or `None` for a name that is not in
/// [`names`].
///
/// # Panics
///
/// Panics if a built-in topology does not build. A test of this crate
/// builds each one.
pub fn builtin(name: &str) -> Option<Twin> {
    let (_, make) = BUILTIN.iter().find(|(n, _)| *n == name)?;
    Some(
        make()
            .build()
            .unwrap_or_else(|e| panic!("built-in topology {name} does not build: {e:?}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_builtin_topology_builds_and_each_function_has_a_device() {
        for name in names() {
            let twin = builtin(name).expect("listed name");
            assert!(twin.functions().all(|f| f.device().is_some()), "{name}");
        }
    }

    #[test]
    fn a_name_that_is_not_listed_gives_no_twin() {
        assert!(builtin("no-such-topology").is_none());
    }
}
