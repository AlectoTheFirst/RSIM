//! The claims: assessment questions about the network that rsim confirms
//! or refutes, with evidence rows. Data that is not collected gives
//! `unknown`, never `confirmed`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::twin::TwinJson;

/// Claim result
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClaimResult {
    Confirmed,
    Refuted,
    Unknown,
}

/// Claim
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct ClaimDef {
    pub name: &'static str,
    pub description: &'static str,
    /// Scopes
    pub scopes: &'static [&'static str],
    /// Read data
    pub reads: &'static [&'static str],
}

/// The claims, in a fixed order.
pub const CLAIMS: &[ClaimDef] = &[
    ClaimDef {
        name: "link-speed-duplex",
        description: "Same speed and duplex on both link ends",
        scopes: &["twin", "devices", "query"],
        reads: &["speed and duplex of both link ends"],
    },
    ClaimDef {
        name: "path-mtu",
        description: "Same MTU on both link ends, at least the minimum",
        scopes: &["twin", "devices", "query"],
        reads: &["MTU of both link ends"],
    },
    ClaimDef {
        name: "no-unknown",
        description: "No Unknown branch",
        scopes: &["query"],
        reads: &["query answer"],
    },
    ClaimDef {
        name: "bgp-peers-up",
        description: "BGP neighbours established",
        scopes: &["twin", "devices", "query"],
        reads: &["BGP neighbours of the config", "BGP session sections"],
    },
    ClaimDef {
        name: "bgp-peers-agree",
        description: "BGP peerings agree",
        scopes: &["twin", "devices", "query"],
        reads: &[
            "BGP neighbours and listen ranges of the config",
            "local addresses and collected routes",
            "BGP session sections",
        ],
    },
    ClaimDef {
        name: "rib-fib-agree",
        description: "Computed routes agree with the collected routes",
        scopes: &["twin", "devices"],
        reads: &[
            "connected and static routes of the config",
            "collected route tables",
        ],
    },
];

/// The claim of a name.
pub fn claim(name: &str) -> Option<&'static ClaimDef> {
    CLAIMS.iter().find(|c| c.name == name)
}

/// Evidence row
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    /// Subject
    pub subject: String,
    pub result: ClaimResult,
    pub expected: Option<Value>,
    pub observed: Option<Value>,
    /// Reason code
    pub reason: String,
    pub detail: String,
    /// Source spans
    pub provenance: Vec<String>,
}

/// Counts
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Counts {
    pub confirmed: usize,
    pub refuted: usize,
    pub unknown: usize,
}

/// Claim result
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ClaimOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub claim: String,
    /// Scope
    pub scope: String,
    pub result: ClaimResult,
    pub counts: Counts,
    /// Detail
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    pub evidence: Vec<Evidence>,
}

/// Claim catalog
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ClaimsOut {
    pub rsim_json: u32,
    pub kind: String,
    pub claims: &'static [ClaimDef],
}

/// The result of evidence rows: one refuted row refutes the claim; with no
/// refuted row, one unknown row makes it unknown; with no row, it is
/// unknown, because nothing confirms it.
pub fn combine(evidence: &[Evidence]) -> (ClaimResult, Counts) {
    let mut c = Counts::default();
    for e in evidence {
        match e.result {
            ClaimResult::Confirmed => c.confirmed += 1,
            ClaimResult::Refuted => c.refuted += 1,
            ClaimResult::Unknown => c.unknown += 1,
        }
    }
    let r = if c.refuted > 0 {
        ClaimResult::Refuted
    } else if c.unknown > 0 || c.confirmed == 0 {
        ClaimResult::Unknown
    } else {
        ClaimResult::Confirmed
    };
    (r, c)
}

/// The arguments of a claim.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimArgs {
    /// Topology
    pub topology: String,
    /// Claim
    pub claim: String,
    /// Devices
    pub devices: Option<Vec<String>>,
    /// Path query
    pub query: Option<Map<String, Value>>,
    /// Minimum MTU
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(r: ClaimResult) -> Evidence {
        Evidence {
            subject: "s".into(),
            result: r,
            expected: None,
            observed: None,
            reason: "x".into(),
            detail: String::new(),
            provenance: Vec::new(),
        }
    }

    #[test]
    fn one_refuted_row_refutes_and_one_unknown_row_makes_it_unknown() {
        use ClaimResult::*;
        assert_eq!(
            combine(&[row(Confirmed), row(Refuted), row(Unknown)]).0,
            Refuted
        );
        assert_eq!(combine(&[row(Confirmed), row(Unknown)]).0, Unknown);
        assert_eq!(combine(&[row(Confirmed), row(Confirmed)]).0, Confirmed);
        assert_eq!(combine(&[]).0, Unknown);
        assert_eq!(combine(&[row(Confirmed), row(Refuted)]).1.refuted, 1);
    }
}
