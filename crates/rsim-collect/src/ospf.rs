//! The OSPF sections of a router: for OSPFv2 and OSPFv3 the process, the
//! interfaces, the neighbours and one section for each LSA type of the
//! link-state database. Each section is optional: a device with no OSPF
//! refuses the command, and the section is absent.
//!
//! The age, the sequence number and the checksum of an LSA, the timers and
//! the counters are volatile, so a refresh of an LSA gives no new snapshot.
//! The OSPFv2 commands are the commands of the HST collector. The OSPFv3
//! commands follow the command names of each vendor. No command is
//! confirmed on a device.

use rsim_store::{Class, Format};
use serde_json::Value;

use crate::bgp::Part;
use crate::{RawSection, SectionSpec};

/// The search path that each FRR command sets.
const PATH: &str = "PATH=/usr/sbin:/sbin:/usr/bin:/bin";

/// The OSPFv2 sections, in the order of the fetch: the process, the
/// interfaces, the neighbours, and the router, network, summary,
/// ASBR-summary, external and NSSA external LSAs.
pub const V2: [&str; 9] = [
    "ospf",
    "ospf_interfaces",
    "ospf_neighbors",
    "ospf_lsdb_router",
    "ospf_lsdb_network",
    "ospf_lsdb_summary",
    "ospf_lsdb_asbr_summary",
    "ospf_lsdb_external",
    "ospf_lsdb_nssa_external",
];

/// The OSPFv3 sections, in the order of the fetch: the process, the
/// interfaces, the neighbours, and the router, network, inter-area-prefix,
/// inter-area-router, AS-external, NSSA, link and intra-area-prefix LSAs.
pub const V3: [&str; 11] = [
    "ospfv3",
    "ospfv3_interfaces",
    "ospfv3_neighbors",
    "ospfv3_lsdb_router",
    "ospfv3_lsdb_network",
    "ospfv3_lsdb_inter_area_prefix",
    "ospfv3_lsdb_inter_area_router",
    "ospfv3_lsdb_external",
    "ospfv3_lsdb_nssa",
    "ospfv3_lsdb_link",
    "ospfv3_lsdb_intra_area_prefix",
];

/// True for the name of an OSPF section.
pub fn is_ospf(name: &str) -> bool {
    V2.contains(&name) || V3.contains(&name)
}

/// The volatile line starts and word shapes of the Cisco text sections.
/// IOS XR prints the time of the command before each answer.
macro_rules! cisco {
    ($($p:expr),* $(,)?) => {
        &["Mon ", "Tue ", "Wed ", "Thu ", "Fri ", "Sat ", "Sun ", $($p),*]
    };
}

/// The age, the sequence number and the checksum of each LSA.
const CISCO_LSDB: &[&str] = cisco!["LS age:", "LS Seq Number:", "Checksum:"];
/// The SPF runs, the counts and the checksum sums of the process.
const CISCO_PROCESS: &[&str] = cisco![
    "SPF algorithm",
    "Number of ",
    "Checksum Sum",
    "Last SPF",
    "Flood list length",
    "~#:#:#",
    "~#:#:#.#",
];
/// The timers and the counts of the interfaces.
const CISCO_INTERFACES: &[&str] = cisco![
    "Hello due in",
    "Index ",
    "Last flood scan",
    "Next ",
    "Neighbor Count",
    "Adjacent neighbor count",
    "~#:#:#",
    "~#:#:#.#",
];
/// The dead times and the up times of the neighbours.
const CISCO_NEIGHBORS: &[&str] = cisco!["~#:#:#", "~#d#h", "~#w#d", "~#y#w", "~#h#m", "~#ms"];

/// The age, the sequence number and the checksum of each NX-OS LSA, below
/// an area row and right below the context row, with each key that HST
/// reads for them.
const NXOS_LSDB: &[&str] = &[
    "/*/*/*/*/*/*/*/*/*/age",
    "/*/*/*/*/*/*/*/*/*/lsa_age",
    "/*/*/*/*/*/*/*/*/*/seqno",
    "/*/*/*/*/*/*/*/*/*/seq",
    "/*/*/*/*/*/*/*/*/*/seq_no",
    "/*/*/*/*/*/*/*/*/*/seqnum",
    "/*/*/*/*/*/*/*/*/*/*cksum*",
    "/*/*/*/*/*/*/*/*/*/*checksum*",
    "/*/*/*/*/*/*/age",
    "/*/*/*/*/*/*/lsa_age",
    "/*/*/*/*/*/*/seqno",
    "/*/*/*/*/*/*/seq",
    "/*/*/*/*/*/*/seq_no",
    "/*/*/*/*/*/*/seqnum",
    "/*/*/*/*/*/*/*cksum*",
    "/*/*/*/*/*/*/*checksum*",
];
/// The times and the counters of the NX-OS process, interface and
/// neighbour rows, and of the area rows of the process.
const NXOS_STATE: &[&str] = &[
    "/*/*/*/*time*",
    "/*/*/*/*spf*",
    "/*/*/*/*cnt*",
    "/*/*/*/*count*",
    "/*/*/*/*cksum*",
    "/*/*/*/*/*/*/*time*",
    "/*/*/*/*/*/*/*spf*",
    "/*/*/*/*/*/*/*cnt*",
    "/*/*/*/*/*/*/*count*",
    "/*/*/*/*/*/*/*cksum*",
    "/*/*/*/*/*/*/*due*",
    "/*/*/*/*/*/*/*dead*",
    "/*/*/*/*/*/*/*expir*",
    "/*/*/*/*/*/*/uptime",
];

/// The age, the sequence number and the checksum of each FRR OSPFv2 LSA in
/// the answer of each VRF.
const FRR_V2_LSDB: &[&str] = &[
    "/*/answer/*/areas/*/*/lsaAge",
    "/*/answer/*/areas/*/*/lsaSeqNumber",
    "/*/answer/*/areas/*/*/checksum",
    "/*/answer/asExternalLinkStates/*/lsaAge",
    "/*/answer/asExternalLinkStates/*/lsaSeqNumber",
    "/*/answer/asExternalLinkStates/*/checksum",
];
/// The timers and the counters of the FRR OSPFv2 process, interfaces and
/// neighbours of each VRF.
const FRR_V2_STATE: &[&str] = &[
    "/*/answer/*Msecs",
    "/*/answer/*Msec",
    "/*/answer/spf*",
    "/*/answer/lsa*",
    "/*/answer/*Count*",
    "/*/answer/areas/*/spf*",
    "/*/answer/areas/*/lsa*",
    "/*/answer/areas/*/*Count*",
    "/*/answer/areas/*/*Number*",
    "/*/answer/interfaces/*/timer*",
    "/*/answer/interfaces/*/*Msecs",
    "/*/answer/interfaces/*/*Count*",
    "/*/answer/neighbors/*/*/*Msecs",
    "/*/answer/neighbors/*/*/*Timer*",
    "/*/answer/neighbors/*/*/*Count*",
    "/*/answer/neighbors/*/*/upTime*",
];
/// The age, the sequence number, the checksum and the duration of each FRR
/// OSPFv3 LSA in its scope list.
const FRR_V3_LSDB: &[&str] = &[
    "/*/*/lsa/*/age",
    "/*/*/lsa/*/lsSequenceNumber",
    "/*/*/lsa/*/checksum",
    "/*/*/lsa/*/duration",
];
/// The timers and the counters of the FRR OSPFv3 process, interfaces and
/// neighbours.
const FRR_V3_STATE: &[&str] = &[
    "/running",
    "/*Msecs",
    "/spf*",
    "/numberOf*",
    "/AuthTrailer*",
    "/areas/*/spf*",
    "/areas/*/numberOf*",
    "/areas/*/lsaStatistics",
    "/*/pendingLsa*",
    "/*/*SendThread",
    "/*/numberOf*",
    "/neighbors/*/deadTime",
    "/neighbors/*/duration",
];

fn spec(
    name: &'static str,
    command: String,
    format: Format,
    volatile: &'static [&'static str],
) -> SectionSpec {
    SectionSpec {
        name,
        command,
        class: Class::Observation,
        format,
        volatile,
        extracts: &[],
        keep: &[],
        optional: true,
    }
}

fn is_lsdb(name: &str) -> bool {
    name.contains("_lsdb_")
}

/// The OSPF sections of an NX-OS switch: JSON for all VRFs.
pub fn nxos() -> Vec<SectionSpec> {
    let v2 = [
        "",
        "interface ",
        "neighbors ",
        "database router detail ",
        "database network detail ",
        "database summary detail ",
        "database asbr-summary detail ",
        "database external detail ",
        "database nssa-external detail ",
    ];
    let v3 = [
        "",
        "interface ",
        "neighbors ",
        "database router detail ",
        "database network detail ",
        "database inter-area-prefix detail ",
        "database inter-area-router detail ",
        "database external detail ",
        "database nssa detail ",
        "database link detail ",
        "database intra-area-prefix detail ",
    ];
    let both = V2
        .iter()
        .zip(v2)
        .map(|(n, c)| (*n, format!("show ip ospf {c}vrf all | json")))
        .chain(
            V3.iter()
                .zip(v3)
                .map(|(n, c)| (*n, format!("show ospfv3 {c}vrf all | json"))),
        );
    both.map(|(n, c)| {
        let volatile = if is_lsdb(n) { NXOS_LSDB } else { NXOS_STATE };
        spec(n, c, Format::Json, volatile)
    })
    .collect()
}

fn cisco_specs(v2: [&str; 9], v3: [&str; 11]) -> Vec<SectionSpec> {
    V2.iter()
        .zip(v2)
        .chain(V3.iter().zip(v3))
        .map(|(n, c)| {
            let volatile = if is_lsdb(n) {
                CISCO_LSDB
            } else if n.ends_with("_interfaces") {
                CISCO_INTERFACES
            } else if n.ends_with("_neighbors") {
                CISCO_NEIGHBORS
            } else {
                CISCO_PROCESS
            };
            spec(n, c.to_string(), Format::Text, volatile)
        })
        .collect()
}

/// The OSPF sections of an IOS XE device: each process of each VRF.
pub fn iosxe() -> Vec<SectionSpec> {
    cisco_specs(
        [
            "show ip ospf",
            "show ip ospf interface",
            "show ip ospf neighbor",
            "show ip ospf database router",
            "show ip ospf database network",
            "show ip ospf database summary",
            "show ip ospf database asbr-summary",
            "show ip ospf database external",
            "show ip ospf database nssa-external",
        ],
        [
            "show ipv6 ospf",
            "show ipv6 ospf interface",
            "show ipv6 ospf neighbor",
            "show ipv6 ospf database router",
            "show ipv6 ospf database network",
            "show ipv6 ospf database inter-area prefix",
            "show ipv6 ospf database inter-area router",
            "show ipv6 ospf database external",
            "show ipv6 ospf database nssa-external",
            "show ipv6 ospf database link",
            "show ipv6 ospf database prefix",
        ],
    )
}

/// The OSPF sections of an IOS XR router: the processes of the default
/// VRF.
pub fn iosxr() -> Vec<SectionSpec> {
    cisco_specs(
        [
            "show ospf",
            "show ospf interface",
            "show ospf neighbor",
            "show ospf database router detail",
            "show ospf database network detail",
            "show ospf database summary detail",
            "show ospf database asbr-summary detail",
            "show ospf database external detail",
            "show ospf database nssa-external detail",
        ],
        [
            "show ospfv3",
            "show ospfv3 interface",
            "show ospfv3 neighbor",
            "show ospfv3 database router",
            "show ospfv3 database network",
            "show ospfv3 database inter-area-prefix",
            "show ospfv3 database inter-area-router",
            "show ospfv3 database external",
            "show ospfv3 database nssa-external",
            "show ospfv3 database link",
            "show ospfv3 database prefix",
        ],
    )
}

/// The `show ip ospf` words of each OSPFv2 section of FRR.
const FRR_V2_WORDS: [&str; 9] = [
    "",
    "interface",
    "neighbor",
    "database router",
    "database network",
    "database summary",
    "database asbr-summary",
    "database external",
    "database nssa-external",
];

/// The `show ipv6 ospf6` words of each OSPFv3 section of FRR.
const FRR_V3_WORDS: [&str; 11] = [
    "",
    "interface",
    "neighbor",
    "database router detail",
    "database network detail",
    "database inter-prefix detail",
    "database inter-router detail",
    "database as-external detail",
    "database type-7 detail",
    "database link detail",
    "database intra-prefix detail",
];

/// The FRR command of an OSPFv2 section in a VRF. The VRF comes after
/// `ospf`, as the grammar of FRR has it.
pub fn frr_v2_command(name: &str, vrf: &str) -> Option<String> {
    let i = V2.iter().position(|n| *n == name)?;
    let scope = if vrf == crate::bgp::DEFAULT_VRF {
        String::new()
    } else {
        format!("vrf {vrf} ")
    };
    let words = FRR_V2_WORDS[i];
    let sep = if words.is_empty() { "" } else { " " };
    Some(format!(
        r#"{PATH} vtysh -c "show ip ospf {scope}{words}{sep}json""#
    ))
}

/// The OSPF sections of a VyOS router: the OSPFv2 sections combine the
/// answers of each VRF of the config with OSPF, and the OSPFv3 sections are
/// the answers of the default VRF.
pub fn vyos() -> Vec<SectionSpec> {
    let v2 = V2.iter().zip(FRR_V2_WORDS).map(|(n, w)| {
        let sep = if w.is_empty() { "" } else { " " };
        let volatile = if is_lsdb(n) {
            FRR_V2_LSDB
        } else {
            FRR_V2_STATE
        };
        spec(
            n,
            format!(r#"{PATH} vtysh -c "show ip ospf [vrf <vrf>] {w}{sep}json""#),
            Format::Json,
            volatile,
        )
    });
    let v3 = V3.iter().zip(FRR_V3_WORDS).map(|(n, w)| {
        let sep = if w.is_empty() { "" } else { " " };
        let volatile = if is_lsdb(n) {
            FRR_V3_LSDB
        } else {
            FRR_V3_STATE
        };
        spec(
            n,
            format!(r#"{PATH} vtysh -c "show ipv6 ospf6 {w}{sep}json""#),
            Format::Json,
            volatile,
        )
    });
    v2.chain(v3).collect()
}

/// The VRFs with `protocols ospf` of a VyOS config in JSON, `default` for
/// the main table, in name order, and whether the main table has `protocols
/// ospfv3`.
pub fn vyos_plan(config: &[u8]) -> Result<(Vec<String>, bool), String> {
    let v: Value =
        serde_json::from_slice(config).map_err(|e| format!("the config is not JSON: {e}"))?;
    let mut vrfs = Vec::new();
    if v.pointer("/protocols/ospf").is_some() {
        vrfs.push(crate::bgp::DEFAULT_VRF.to_string());
    }
    if let Some(Value::Object(names)) = v.pointer("/vrf/name") {
        let mut named: Vec<String> = names
            .iter()
            .filter(|(_, node)| node.pointer("/protocols/ospf").is_some())
            .map(|(n, _)| n.clone())
            .collect();
        named.sort();
        vrfs.extend(named);
    }
    Ok((vrfs, v.pointer("/protocols/ospfv3").is_some()))
}

/// The parts of an OSPFv2 section: one command for each VRF.
pub(crate) fn vyos_parts(name: &str, vrfs: &[String]) -> Vec<Part> {
    vrfs.iter()
        .filter_map(|v| {
            Some(Part {
                head: v.clone(),
                command: frr_v2_command(name, v)?,
            })
        })
        .collect()
}

/// The answers of the VRFs as one JSON object by VRF. Each VRF is
/// `{"answer": <answer>}`, with an answer that is not JSON as a string, or
/// `{"failed": <error>}`.
pub(crate) fn combine_vrfs(parts: &[Part], answers: &[RawSection]) -> Vec<u8> {
    let mut top = serde_json::Map::new();
    for (p, a) in parts.iter().zip(answers) {
        let v = match &a.result {
            Ok(bytes) => {
                let answer = serde_json::from_slice::<Value>(bytes)
                    .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(bytes).into_owned()));
                serde_json::json!({ "answer": answer })
            }
            Err(e) => serde_json::json!({ "failed": e.to_string() }),
        };
        top.insert(p.head.clone(), v);
    }
    Value::Object(top).to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vrfs_of_a_vyos_config_and_the_commands_of_a_vrf() {
        let config = br#"{"protocols":{"ospf":{"area":{"0":{}}},"ospfv3":{}},
            "vrf":{"name":{"RED":{"protocols":{"ospf":{}}},"BLUE":{"table":"100"}}}}"#;
        assert_eq!(
            vyos_plan(config).unwrap(),
            (vec!["default".to_string(), "RED".to_string()], true)
        );
        assert_eq!(
            frr_v2_command("ospf_lsdb_router", "RED").unwrap(),
            r#"PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf vrf RED database router json""#
        );
        assert_eq!(
            frr_v2_command("ospf", "default").unwrap(),
            r#"PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf json""#
        );
    }

    #[test]
    fn each_vendor_has_each_section_once() {
        for specs in [nxos(), iosxe(), iosxr(), vyos()] {
            let names: Vec<&str> = specs.iter().map(|s| s.name).collect();
            assert_eq!(
                names,
                V2.iter().chain(V3.iter()).copied().collect::<Vec<_>>()
            );
            assert!(specs.iter().all(|s| s.optional));
        }
    }
}
