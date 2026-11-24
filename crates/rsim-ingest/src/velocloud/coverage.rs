//! The classification of the stanzas of the sections of an enterprise.
//!
//! The path of a stanza has `*` for each element of an array and for each
//! member of an object keyed by a name or an id, and the module name for
//! each element of a `modules` array. A path of the report is
//! `<section>/<path>`, each key through `mask::report_key`.

use crate::coverage::{Coverage, Reach, State, Table};
use crate::stanza::{Body, Stanza};

use super::json::Parsed;
use super::mask::report_key;

use Reach::{Node as N, Subtree as S};
use State::{Handled as H, Irrelevant as I};

/// The sections whose root is an object keyed by edge logicalId.
const BY_EDGE: &[&str] = &["edge_modules", "sdwan_peers"];

/// The keys whose members are keyed by a name.
const MAPS: &[&str] = &["loopbackInterfaces"];

type Rows = &'static [(&'static str, State, Reach)];

const DEVICE_SETTINGS: Rows = &[
    ("", H, N),
    ("segments", H, N),
    ("segments/*", H, N),
    ("segments/*/segment", H, S),
    ("segments/*/segmentId", H, N),
    ("segments/*/bgp", H, N),
    ("segments/*/bgp/enabled", H, N),
    ("segments/*/bgp/ASN", H, N),
    ("segments/*/bgp/asn", H, N),
    ("segments/*/bgp/routerId", H, N),
    ("segments/*/bgp/neighbors", H, N),
    ("segments/*/bgp/neighbors/*", H, N),
    ("segments/*/bgp/neighbors/*/neighborIp", H, N),
    ("segments/*/bgp/neighbors/*/neighborAS", H, N),
    ("segments/*/bgp/neighbors/*/localIp", H, N),
    ("segments/*/bgp/neighbors/*/neighborTag", I, N),
    ("segments/*/vpn", H, N),
    ("segments/*/vpn/enabled", H, N),
    ("segments/*/vpn/edgeToEdgeDetail", H, N),
    ("segments/*/vpn/edgeToEdgeDetail/vpnHubs", H, S),
    ("segments/*/vpn/backHaulEdges", H, S),
    ("segments/*/routes", H, N),
    ("routedInterfaces", H, N),
    ("routedInterfaces/*", H, N),
    ("routedInterfaces/*/name", H, N),
    ("routedInterfaces/*/wanOverlay", H, N),
    ("routedInterfaces/*/segmentId", H, N),
    ("routedInterfaces/*/disabled", H, N),
    ("routedInterfaces/*/natDirect", H, N),
    ("routedInterfaces/*/subinterfaces", H, N),
    ("routedInterfaces/*/subinterfaces/*", H, N),
    ("routedInterfaces/*/subinterfaces/*/subinterfaceId", H, N),
    ("routedInterfaces/*/subinterfaces/*/vlanId", H, N),
    ("routedInterfaces/*/subinterfaces/*/segmentId", H, N),
    ("routedInterfaces/*/subinterfaces/*/disabled", H, N),
    ("loopbackInterfaces", H, N),
    ("loopbackInterfaces/*", H, N),
    ("loopbackInterfaces/*/cidrIp", H, N),
    ("loopbackInterfaces/*/cidrPrefix", H, N),
    ("loopbackInterfaces/*/netmask", H, N),
    ("loopbackInterfaces/*/disableV4", H, N),
    ("loopbackInterfaces/*/segmentId", H, N),
    ("lan", H, N),
    ("lan/networks", H, N),
    ("lan/networks/*", H, N),
    ("lan/networks/*/name", H, N),
    ("lan/networks/*/vlanId", H, N),
    ("lan/networks/*/cidrIp", H, N),
    ("lan/networks/*/cidrPrefix", H, N),
    ("lan/networks/*/netmask", H, N),
    ("lan/networks/*/segmentId", H, N),
    ("lan/networks/*/disabled", H, N),
    ("snmp", I, S),
];

/// The fields of an `addressing` object.
const ADDRESSING: Rows = &[
    ("", H, N),
    ("type", H, N),
    ("cidrIp", H, N),
    ("cidrPrefix", H, N),
    ("netmask", H, N),
    ("gateway", H, N),
];

/// The fields of a static route.
const STATIC: Rows = &[
    ("", H, N),
    ("*", H, N),
    ("*/destination", H, N),
    ("*/cidrPrefix", H, N),
    ("*/netmask", H, N),
    ("*/gateway", H, N),
    ("*/wanInterface", H, N),
    ("*/subinterfaceId", H, N),
    ("*/cost", H, N),
    ("*/preferred", H, N),
    ("*/advertise", H, N),
    ("*/description", I, N),
];

/// The fields of a rule of the firewall or of the business policy.
const RULE: Rows = &[
    ("", H, N),
    ("*", H, N),
    ("*/name", H, N),
    ("*/ruleLogicalId", H, N),
    ("*/match", H, S),
    ("*/action", H, N),
];

/// The fields of a route action of a business rule.
const ROUTE_ACTION: Rows = &[
    ("", H, N),
    ("routePolicy", H, N),
    ("linkPolicy", H, N),
    ("serviceGroup", H, N),
    ("wanlink", H, N),
    ("linkInternalLogicalId", H, N),
    ("interface", H, N),
    ("vlanId", H, N),
    ("linkOuterDscpTag", H, N),
    ("linkInnerDscpTag", H, N),
    ("routeCfg", H, N),
    ("routeCfg/backhaulEdges", H, S),
];

/// The fields of the action of a business rule.
const BUSINESS_ACTION: Rows = &[
    ("routeType", H, N),
    ("QoS", H, N),
    ("QoS/type", H, N),
    ("QoS/txScheduler", H, N),
    ("QoS/txScheduler/priority", H, N),
    ("QoS/txScheduler/bandwidthCapPct", H, N),
    ("QoS/rxScheduler", H, N),
    ("QoS/rxScheduler/priority", H, N),
    ("QoS/rxScheduler/bandwidthCapPct", H, N),
    ("nat", H, S),
    ("natV6", H, S),
    ("sla", I, S),
];

/// The fields of the action of an inbound firewall rule.
const INBOUND_ACTION: Rows = &[
    ("type", H, N),
    ("nat", H, N),
    ("nat/lan_ip", H, N),
    ("nat/lan_port", H, N),
    ("nat/outbound", H, N),
    ("interface", H, N),
    ("subinterfaceId", H, N),
];

/// The top-level fields of the firewall module.
const FIREWALL: Rows = &[
    ("", H, N),
    ("firewall_enabled", H, N),
    ("stateful_firewall_enabled", H, N),
    ("firewall_logging_enabled", I, N),
    ("inboundLoggingEnabled", I, N),
    ("syslog_forwarding", I, N),
    ("segments", H, N),
    ("segments/*", H, N),
    ("segments/*/segment", H, S),
    ("segments/*/stateful_firewall_enabled", H, N),
    ("segments/*/firewall_logging_enabled", I, N),
];

/// The top-level fields of the QOS module.
const QOS: Rows = &[
    ("", H, N),
    ("segments", H, N),
    ("segments/*", H, N),
    ("segments/*/segment", H, S),
];

/// The fields of an exit of the route table.
const EXIT: Rows = &[
    ("", H, N),
    ("*", H, N),
    ("*/type", H, N),
    ("*/exitType", H, N),
    ("*/entity", H, N),
    ("*/state", H, N),
    ("*/protocol", H, N),
    ("*/routeType", H, N),
    ("*/cost", H, N),
    ("*/metric", H, N),
    ("*/segmentId", H, N),
    ("*/edgeId", H, N),
    ("*/edgeLogicalId", H, N),
    ("*/interface", H, N),
    ("*/neighborIp", H, N),
    ("*/nextHopIp", H, N),
    ("*/filtered", H, N),
    ("*/learnedBy", I, N),
    ("*/isOwner", I, N),
    ("*/advertise", I, N),
    ("*/neighborTag", I, N),
    ("*/cidrIp", I, N),
    ("*/cidrPrefix", I, N),
];

fn join(base: &str, path: &str) -> String {
    match (base.is_empty(), path.is_empty()) {
        (true, _) => path.to_string(),
        (_, true) => base.to_string(),
        _ => format!("{base}/{path}"),
    }
}

fn add(t: &mut Table, base: &str, rows: &[(&str, State, Reach)]) {
    for (path, state, reach) in rows {
        t.push(&join(base, path), *state, *reach);
    }
}

/// The entries of the body of the `deviceSettings` module at `base`.
fn device_settings(t: &mut Table, base: &str) {
    add(t, base, DEVICE_SETTINGS);
    add(t, &join(base, "routedInterfaces/*/addressing"), ADDRESSING);
    add(
        t,
        &join(base, "routedInterfaces/*/subinterfaces/*/addressing"),
        ADDRESSING,
    );
    for k in ["static", "staticV6"] {
        add(t, &join(base, &format!("segments/*/routes/{k}")), STATIC);
    }
}

/// The entries of the body of the `QOS` module at `base`.
fn qos(t: &mut Table, base: &str) {
    add(t, base, QOS);
    for list in ["rules", "defaults"] {
        let rules = join(base, &format!("segments/*/{list}"));
        add(t, &rules, RULE);
        add(t, &join(&rules, "*/action"), BUSINESS_ACTION);
        for k in [
            "edge2EdgeRouteAction",
            "edge2DataCenterRouteAction",
            "edge2CloudRouteAction",
        ] {
            add(t, &join(&rules, &format!("*/action/{k}")), ROUTE_ACTION);
        }
    }
}

/// The entries of the body of the `firewall` module at `base`.
fn firewall(t: &mut Table, base: &str) {
    add(t, base, FIREWALL);
    let outbound = join(base, "segments/*/outbound");
    add(t, &outbound, RULE);
    t.push(&join(&outbound, "*/action/allow_or_deny"), H, N);
    for k in ["inbound", "inboundV6"] {
        let inbound = join(base, k);
        add(t, &inbound, RULE);
        add(t, &join(&inbound, "*/action"), INBOUND_ACTION);
    }
}

/// The entries of the module bodies of a module list at `base`: the
/// `deviceSettings`, `QOS` and `firewall` bodies under `body`.
fn modules(t: &mut Table, base: &str, body: &str) {
    device_settings(t, &join(base, &format!("deviceSettings/{body}")));
    qos(t, &join(base, &format!("QOS/{body}")));
    firewall(t, &join(base, &format!("firewall/{body}")));
}

/// The classification table of a section.
pub fn table(section: &str) -> Table {
    let mut t = Table::new(&[]);
    match section {
        "aggregates" => add(
            &mut t,
            "",
            &[
                ("*", I, S),
                ("enterprises", H, N),
                ("enterprises/*", I, S),
                ("enterprises/*/id", H, N),
                ("enterprises/*/logicalId", H, N),
                ("enterprises/*/name", H, N),
                ("*/id", H, N),
                ("*/logicalId", H, N),
                ("*/name", H, N),
            ],
        ),
        "edges" => {
            add(
                &mut t,
                "",
                &[
                    ("*", H, N),
                    ("*/logicalId", H, N),
                    ("*/id", H, N),
                    ("*/name", H, N),
                    ("*/serialNumber", H, N),
                    ("*/modelNumber", H, N),
                    ("*/softwareVersion", H, N),
                    ("*/isHub", H, N),
                    ("*/edgeState", I, N),
                    ("*/haState", I, N),
                    ("*/lastActive", I, N),
                    ("*/lastContact", I, N),
                    ("*/activationKey", I, N),
                    ("*/_href", I, N),
                    ("*/created", I, N),
                    ("*/modified", I, N),
                    ("*/description", I, N),
                    ("*/site", I, S),
                    ("*/ha", H, N),
                    ("*/ha/type", H, N),
                    ("*/ha/data", H, N),
                    ("*/ha/data/haSerialNumber", H, N),
                    ("*/ha/data/clusterName", H, N),
                    ("*/ha/data/clusterId", I, N),
                    ("*/ha/data/haState", I, N),
                    ("*/links", H, N),
                    ("*/links/*", H, N),
                    ("*/links/*/logicalId", H, N),
                    ("*/links/*/internalId", H, N),
                    ("*/links/*/interface", H, N),
                    ("*/links/*/ipAddress", H, N),
                    ("*/links/*/networkSide", H, N),
                    ("*/links/*/displayName", H, N),
                    ("*/links/*/isp", H, N),
                    ("*/links/*/org", H, N),
                    ("*/links/*/networkType", I, N),
                    ("*/links/*/_href", I, N),
                    ("*/links/*/state", I, N),
                    ("*/links/*/linkMode", I, N),
                    ("*/links/*/vpnState", I, N),
                    ("*/links/*/backupState", I, N),
                    ("*/links/*/lastActive", I, N),
                    ("*/configuration", H, N),
                    ("*/configuration/*", H, N),
                    ("*/configuration/*/id", H, N),
                    ("*/configuration/*/name", I, N),
                    ("*/configuration/*/modules", H, N),
                    ("*/configuration/*/modules/*", H, N),
                    ("*/configuration/*/modules/*/name", H, N),
                    ("*/configuration/*/modules/*/type", I, N),
                    ("*/configuration/*/modules/*/version", I, N),
                    ("*/configuration/*/modules/*/isEdgeSpecific", I, N),
                ],
            );
            modules(&mut t, "*/configuration/*/modules", "edgeSpecificData");
        }
        "edge_state" => add(
            &mut t,
            "",
            &[
                ("*", H, N),
                ("*/*", I, S),
                ("*/logicalId", H, N),
                ("*/edgeState", H, N),
                ("*/haState", H, N),
                ("*/ha", H, N),
                ("*/ha/data", H, N),
                ("*/ha/data/haState", H, N),
                ("*/links", H, N),
                ("*/links/*", H, N),
                ("*/links/*/logicalId", H, N),
                ("*/links/*/internalId", H, N),
                ("*/links/*/state", H, N),
                ("*/links/*/linkMode", H, N),
                ("*/links/*/vpnState", H, N),
                ("*/links/*/backupState", H, N),
            ],
        ),
        "profiles" => {
            add(
                &mut t,
                "",
                &[
                    ("*", H, N),
                    ("*/id", H, N),
                    ("*/name", I, N),
                    ("*/type", I, N),
                    ("*/description", I, N),
                    ("*/created", I, N),
                    ("*/modified", I, N),
                    ("*/modules", H, N),
                    ("*/modules/*", H, N),
                    ("*/modules/*/name", H, N),
                    ("*/modules/*/type", I, N),
                    ("*/modules/*/version", I, N),
                    ("*/modules/*/schemaVersion", I, N),
                    ("*/modules/*/id", I, N),
                    ("*/modules/*/created", I, N),
                    ("*/modules/*/modified", I, N),
                    ("*/modules/WAN/data", I, S),
                ],
            );
            modules(&mut t, "*/modules", "data");
        }
        "route_table" => {
            add(
                &mut t,
                "",
                &[
                    ("profiles", I, S),
                    ("reduced", I, N),
                    ("subnets", H, N),
                    ("subnets/*", H, N),
                    ("subnets/*/subnet", H, N),
                    ("subnets/*/ipVersion", I, N),
                    ("subnets/*/learnedRoute", H, N),
                    ("subnets/*/learnedRoute/cidrIp", H, N),
                    ("subnets/*/learnedRoute/cidrPrefix", H, N),
                    ("subnets/*/learnedRoute/segmentId", H, N),
                    ("subnets/*/learnedRoute/logicalId", I, N),
                ],
            );
            add(&mut t, "subnets/*/preferredExits", EXIT);
            add(&mut t, "subnets/*/eligableExits", EXIT);
        }
        "edges_v2" => add(
            &mut t,
            "",
            &[
                ("*", H, N),
                ("*/logicalId", H, N),
                ("*/name", H, N),
                ("*/serialNumber", H, N),
                ("*/modelNumber", H, N),
                ("*/softwareVersion", H, N),
                ("*/edgeState", I, N),
                ("*/activationKey", I, N),
                ("*/_href", I, N),
                ("*/created", I, N),
                ("*/modified", I, N),
                ("*/site", I, S),
            ],
        ),
        "edge_modules" => add(
            &mut t,
            "",
            &[
                ("*", H, N),
                ("*/_freshness", H, S),
                ("*/_capability", H, S),
                ("*/WAN", H, N),
                ("*/WAN/version", I, N),
                ("*/WAN/schemaVersion", I, N),
                ("*/WAN/type", I, N),
                ("*/WAN/data", H, N),
                ("*/WAN/data/links", H, N),
                ("*/WAN/data/links/*", H, N),
                ("*/WAN/data/links/*/logicalId", H, N),
                ("*/WAN/data/links/*/internalId", H, N),
                ("*/WAN/data/links/*/name", H, N),
                ("*/WAN/data/links/*/mode", H, N),
                ("*/WAN/data/links/*/type", H, N),
                ("*/WAN/data/links/*/isp", H, N),
                ("*/WAN/data/links/*/nextHopIpAddress", H, N),
                ("*/WAN/data/links/*/privateNetwork", H, S),
                ("*/WAN/data/links/*/mplsNetwork", H, S),
                ("*/WAN/data/links/*/upstreamMbps", I, N),
                ("*/WAN/data/links/*/downstreamMbps", I, N),
                ("*/WAN/data/links/*/MTU", I, N),
                ("*/controlPlane", H, N),
                ("*/controlPlane/version", I, N),
                ("*/controlPlane/type", I, N),
                ("*/controlPlane/data", H, N),
                ("*/controlPlane/data/gatewaySegmentDetailList", H, N),
                ("*/controlPlane/data/gatewaySegmentDetailList/*", H, N),
                (
                    "*/controlPlane/data/gatewaySegmentDetailList/*/segment",
                    H,
                    S,
                ),
                (
                    "*/controlPlane/data/gatewaySegmentDetailList/*/segmentId",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/gatewaySegmentDetailList/*/gatewayDetailList",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/gatewaySegmentDetailList/*/gatewayDetailList/*",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/gatewaySegmentDetailList/*/gatewayDetailList/*/name",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/gatewaySegmentDetailList/*/gatewayDetailList/*/ipAddress",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/gatewaySegmentDetailList/*/gatewayDetailList/*/logicalId",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/gatewaySegmentDetailList/*/gatewayDetailList/*/roles",
                    H,
                    S,
                ),
                ("*/controlPlane/data/gatewayDetailList", H, N),
                ("*/controlPlane/data/gatewayDetailList/*", H, N),
                ("*/controlPlane/data/gatewayDetailList/*/name", H, N),
                ("*/controlPlane/data/gatewayDetailList/*/ipAddress", H, N),
                ("*/controlPlane/data/gatewayDetailList/*/logicalId", H, N),
                ("*/controlPlane/data/gatewayDetailList/*/roles", H, S),
                ("*/controlPlane/data/segments", H, N),
                ("*/controlPlane/data/segments/*", H, N),
                ("*/controlPlane/data/segments/*/segment", H, S),
                ("*/controlPlane/data/segments/*/segmentId", H, N),
                ("*/controlPlane/data/segments/*/vpn", H, N),
                ("*/controlPlane/data/segments/*/vpn/dataCenterEdges", H, N),
                ("*/controlPlane/data/segments/*/vpn/dataCenterEdges/*", H, N),
                (
                    "*/controlPlane/data/segments/*/vpn/dataCenterEdges/*/logicalId",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/segments/*/vpn/dataCenterEdges/*/_href",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/segments/*/vpn/dataCenterEdges/*/clusterLogicalId",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/segments/*/vpn/dataCenterEdges/*/clusterName",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/segments/*/vpn/dataCenterEdges/*/type",
                    H,
                    N,
                ),
                (
                    "*/controlPlane/data/segments/*/vpn/dataCenterEdges/*/name",
                    I,
                    N,
                ),
                ("*/controlPlane/data/segments/*/dataCenterEdgeList", H, S),
                ("*/controlPlane/data/memberCluster", H, N),
                ("*/controlPlane/data/memberCluster/clusterLogicalId", H, N),
                ("*/controlPlane/data/memberCluster/clusterName", H, N),
                ("*/controlPlane/data/memberCluster/members", H, N),
                ("*/controlPlane/data/memberCluster/members/*", H, N),
                (
                    "*/controlPlane/data/memberCluster/members/*/edgeLogicalId",
                    H,
                    N,
                ),
                ("*/controlPlane/data/memberCluster/members/*/edgeId", I, N),
            ],
        ),
        "sdwan_peers" => add(
            &mut t,
            "",
            &[
                ("*", H, N),
                ("*/_capability", H, S),
                ("*/*", H, N),
                ("*/*/edgeLogicalId", H, N),
                ("*/*/deviceLogicalId", H, N),
                ("*/*/peerName", H, N),
                ("*/*/peerType", H, N),
                ("*/*/peerHAType", H, N),
                ("*/*/clusterId", H, N),
                ("*/*/pathStatusCount", H, S),
                ("*/*/description", I, N),
                ("*/*/scoreAfterVoice", I, N),
                ("*/*/scoreAfterVideo", I, N),
                ("*/*/scoreAfterTrans", I, N),
                ("*/*/pathQoe", I, N),
            ],
        ),
        "object_groups" => add(
            &mut t,
            "",
            &[
                ("*", H, N),
                ("*/*", I, S),
                ("*/logicalId", H, N),
                ("*/name", H, N),
                ("*/type", H, N),
                ("*/data", H, S),
            ],
        ),
        "bgp_sessions" => add(
            &mut t,
            "",
            &[
                ("*", H, N),
                ("*/edge", H, N),
                ("*/edge/_href", H, N),
                ("*/edge/logicalId", H, N),
                ("*/neighborIp", H, N),
                ("*/neighborAS", H, N),
                ("*/state", H, N),
                ("*/timestamp", I, N),
                ("*/pfxRcvd", I, N),
                ("*/upDownTime", I, N),
            ],
        ),
        _ => {}
    }
    t
}

/// The sections whose root is an array of edge rows.
const EDGE_ROWS: &[&str] = &["edges", "edge_state", "edges_v2"];

/// The stanzas that a coverage report counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part<'a> {
    All,
    /// The stanzas of one edge, by its logicalId: its rows of `edges`,
    /// `edge_state` and `edges_v2`, and its members of `edge_modules` and
    /// `sdwan_peers`.
    Edge(&'a str),
    /// The stanzas of no single edge.
    Shared,
}

/// The logicalId of the edge of a top-level stanza of a section.
fn edge_of(section: &str, s: &Stanza) -> Option<String> {
    if BY_EDGE.contains(&section) {
        return Some(s.key.clone());
    }
    if EDGE_ROWS.contains(&section) {
        return s
            .get("logicalId")
            .and_then(Stanza::text)
            .map(str::to_string);
    }
    None
}

/// The coverage of the sections of an enterprise, with the path of each
/// unhandled stanza under the name of its section.
pub fn classify(p: &Parsed) -> Coverage {
    classify_part(p, Part::All)
}

/// The coverage of a part of the sections of an enterprise.
pub fn classify_part(p: &Parsed, part: Part<'_>) -> Coverage {
    let mut cov = Coverage::default();
    for (name, section) in &p.sections {
        let t = table(name);
        let by_edge = BY_EDGE.contains(&name.as_str());
        let mut path = Vec::new();
        for c in section.doc.root.children() {
            let keep = match part {
                Part::All => true,
                Part::Edge(e) => edge_of(name, c).as_deref() == Some(e),
                Part::Shared => edge_of(name, c).is_none(),
            };
            if !keep {
                continue;
            }
            let key = match (&section.doc.root.body, by_edge) {
                (Body::Array(_), _) | (_, true) => "*".to_string(),
                _ => c.key.clone(),
            };
            path.push(key);
            walk(c, name, &t, &mut path, &mut cov, false);
            path.pop();
        }
    }
    cov
}

fn walk(
    s: &Stanza,
    section: &str,
    t: &Table,
    path: &mut Vec<String>,
    cov: &mut Coverage,
    inside: bool,
) {
    let refs: Vec<&str> = path.iter().map(String::as_str).collect();
    let state = t.state(&refs);
    if state == State::Unhandled && !inside {
        let keys: Vec<String> = path.iter().map(|k| report_key(k.as_str())).collect();
        let e = cov
            .unhandled
            .entry(format!("{section}/{}", keys.join("/")))
            .or_default();
        e.0 += 1;
        e.1 += s.last_line - s.first_line + 1;
    }
    let child_lines: u32 = s
        .children()
        .iter()
        .map(|c| c.last_line - c.first_line + 1)
        .sum();
    *cov.lines.entry(state).or_default() += s.last_line - s.first_line + 1 - child_lines;
    let modules = path.last().is_some_and(|k| k == "modules");
    let map = path.last().is_some_and(|k| MAPS.contains(&k.as_str()));
    for c in s.children() {
        let key = match &s.body {
            Body::Array(_) if modules => c
                .get("name")
                .and_then(Stanza::text)
                .map_or_else(|| "*".to_string(), str::to_string),
            Body::Array(_) => "*".to_string(),
            _ if map => "*".to_string(),
            _ => c.key.clone(),
        };
        path.push(key);
        walk(c, section, t, path, cov, state == State::Unhandled);
        path.pop();
    }
}
