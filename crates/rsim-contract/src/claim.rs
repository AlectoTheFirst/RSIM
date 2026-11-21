//! The claims: assessment questions about the network that rsim confirms
//! or refutes, with evidence rows. Data that is not collected gives
//! `unknown`, never `confirmed`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::twin::TwinJson;

/// The result of a claim or of one evidence row.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClaimResult {
    Confirmed,
    Refuted,
    Unknown,
}

/// One claim of the catalog.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct ClaimDef {
    pub name: &'static str,
    pub description: &'static str,
    /// The scopes on which the claim runs: `twin`, `devices` or `query`.
    pub scopes: &'static [&'static str],
    /// The data that the claim reads.
    pub reads: &'static [&'static str],
}

/// The claims, in a fixed order.
pub const CLAIMS: &[ClaimDef] = &[
    ClaimDef {
        name: "link-speed-duplex",
        description: "The 2 ends of each link have the same speed and the same duplex. A link with an end whose speed or duplex is not collected is unknown.",
        scopes: &["twin", "devices", "query"],
        reads: &["the link facts of the egress functions: speed and duplex of both ends"],
    },
    ClaimDef {
        name: "no-unknown",
        description: "No branch of the answer of a query, and of its replies, ends in Unknown.",
        scopes: &["query"],
        reads: &["the answer of the query"],
    },
    ClaimDef {
        name: "bgp-peers-up",
        description: "Each configured BGP neighbour of the scope is established. A neighbour with no session row is refuted only when the session section was read in full and its scope covers the VRF and each address family of the neighbour; else it is unknown. A neighbour whose peer is outside the twin gives a row from its session state. A neighbour with shutdown gives no row, and the detail counts it. A scope with no BGP neighbour is unknown.",
        scopes: &["twin", "devices", "query"],
        reads: &[
            "the BGP neighbours of the config after the inheritance",
            "the BGP session sections: the state of each session and the outcome and the scope of the read",
        ],
    },
    ClaimDef {
        name: "bgp-peers-agree",
        description: "The 2 sides of each configured BGP neighbour whose peer is a device of the twin agree. They pair on the exact transport addresses in both directions: the far device has a neighbour for the source address of the near side that sends from the peer address of the near side, or a listen range that holds the source address. A one-sided peering, a far neighbour that sends from another address, a neighbour of the far side that names another address of the near device, an AS of the peer that is not the AS that the other side presents, and 2 sides with no common address family, when both sets are known in full, refute. An AS or a source address that does not resolve, different session states and different prefix counts give unknown. A neighbour with shutdown and a neighbour whose peer is outside the twin give no row, and the detail counts them. A scope with no BGP neighbour is unknown.",
        scopes: &["twin", "devices", "query"],
        reads: &[
            "the BGP neighbours and listen ranges of the config after the inheritance, with the presented local AS",
            "the local addresses of each device and the collected routes for the source address",
            "the BGP session sections: the state and the prefix counts of each session",
        ],
    },
];

/// The claim of a name.
pub fn claim(name: &str) -> Option<&'static ClaimDef> {
    CLAIMS.iter().find(|c| c.name == name)
}

/// One evidence row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    /// What the row is about, for example a link or a branch.
    pub subject: String,
    pub result: ClaimResult,
    pub expected: Option<Value>,
    pub observed: Option<Value>,
    /// A reason code: `match`, `mismatch`, `not_collected`, `unknown`.
    pub reason: String,
    pub detail: String,
    /// The source spans of the data: file:first-last.
    pub provenance: Vec<String>,
}

/// The number of evidence rows of each result.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Counts {
    pub confirmed: usize,
    pub refuted: usize,
    pub unknown: usize,
}

/// The result of a claim on a scope.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ClaimOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    pub claim: String,
    /// `twin`, `devices` or `query`.
    pub scope: String,
    pub result: ClaimResult,
    pub counts: Counts,
    /// What the claim leaves out of its rows, or why it has none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    pub evidence: Vec<Evidence>,
}

/// The claim catalog.
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
    /// `store` for the newest snapshot of the store
    /// of the server.
    pub topology: String,
    /// The claim. The tool `list_claims` gives the claims.
    pub claim: String,
    /// The devices of the scope `devices`.
    pub devices: Option<Vec<String>>,
    /// The path query of the scope `query`: the arguments of `path_query`
    /// without `topology` and `form`.
    pub query: Option<Map<String, Value>>,
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
