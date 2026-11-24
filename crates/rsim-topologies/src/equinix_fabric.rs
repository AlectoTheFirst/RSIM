//! Two switched sites joined by the circuits of an Equinix Fabric account.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rsim_core::{
    BridgeDomainId, EndpointId, FunctionId, InterfaceId, Mac, NetFunction, ObjectId, PortId,
    Prefix, PrefixTable, SourceSpan, TriePrefixTable,
};
use rsim_engine::{AttachmentKind, AttachmentRecord, Endpoint, TwinBuilder};
use rsim_functions::{
    AclMatch, Circuit, CircuitLeg, FarEnd, Flood, HostMac, HostResolution, MacEntry, MacLookup,
    PortEgress, PortIngress, PortPeer, Rule, RuleAction, TagOp, TagStack, Tags, VlanTag,
};

use crate::builders::*;
use crate::helpers::*;
use crate::profiles::*;

/// The device of the account.
const ACCOUNT: &str = "equinix-acct";
/// The TPID of an IEEE 802.1ad service tag.
const TPID_8021AD: u16 = 0x88a8;
/// The service tag of the QinQ end of the circuit `evpl-qinq`.
const S_TAG: VlanTag = VlanTag {
    vlan: 300,
    tpid: TPID_8021AD,
};

fn mac(last: u8) -> Mac {
    Mac([0x00, 0x00, 0x5e, 0x00, 0x53, last])
}

fn bd(device: &str, vlan: u16) -> BridgeDomainId {
    BridgeDomainId::new(format!("{device}/vlan{vlan}"))
}

/// A host on an access port.
struct Host {
    name: &'static str,
    device: &'static str,
    port: &'static str,
    vlan: u16,
    addr: &'static str,
    net: &'static str,
    mac: u8,
}

static HOSTS: [Host; 6] = [
    Host {
        name: "ha",
        device: "sw-a",
        port: "port/2",
        vlan: 100,
        addr: "192.0.2.10",
        net: "192.0.2.0/26",
        mac: 0x21,
    },
    Host {
        name: "ha2",
        device: "sw-a",
        port: "port/3",
        vlan: 200,
        addr: "198.51.100.10",
        net: "198.51.100.0/26",
        mac: 0x23,
    },
    Host {
        name: "ha3",
        device: "sw-a",
        port: "port/4",
        vlan: 150,
        addr: "198.51.100.70",
        net: "198.51.100.64/26",
        mac: 0x25,
    },
    Host {
        name: "ha4",
        device: "sw-a",
        port: "port/5",
        vlan: 400,
        addr: "203.0.113.10",
        net: "203.0.113.0/24",
        mac: 0x27,
    },
    Host {
        name: "hb",
        device: "sw-b",
        port: "port/3",
        vlan: 100,
        addr: "192.0.2.20",
        net: "192.0.2.0/26",
        mac: 0x22,
    },
    Host {
        name: "hb2",
        device: "sw-b",
        port: "port/4",
        vlan: 200,
        addr: "198.51.100.20",
        net: "198.51.100.0/26",
        mac: 0x24,
    },
];

/// The addresses outside the twin with a MAC in a table of `sw-a`: a host
/// behind the account in VLAN 150, and the router of the service profile
/// in VLAN 400.
static REMOTE: [(&str, u8); 2] = [("198.51.100.80", 0x26), ("203.0.113.1", 0x28)];

/// A trunk port of a switch with the ingress function of its link peer.
struct Trunk {
    port: &'static str,
    vlans: &'static [u16],
    peer: &'static str,
}

/// The port functions, the MAC lookup and the flood of a switch. `macs`
/// gives the MAC table: the VLAN, the MAC and the port.
fn switch(dev: &Dev, trunks: &[Trunk], macs: &[(u16, Mac, &str)]) -> Vec<Arc<dyn NetFunction>> {
    let name = dev.name.as_str();
    let mut ports: Vec<(
        &str,
        Option<u16>,
        Vec<u16>,
        Option<&str>,
        BTreeMap<Mac, EndpointId>,
    )> = trunks
        .iter()
        .map(|t| {
            (
                t.port,
                None,
                t.vlans.to_vec(),
                Some(t.peer),
                BTreeMap::new(),
            )
        })
        .collect();
    for h in HOSTS.iter().filter(|h| h.device == name) {
        ports.push((
            h.port,
            Some(h.vlan),
            Vec::new(),
            None,
            BTreeMap::from([(mac(h.mac), EndpointId::new(h.name))]),
        ));
    }
    let mut fns: Vec<Arc<dyn NetFunction>> = Vec::new();
    let mut flood: BTreeMap<BridgeDomainId, Vec<(PortId, FunctionId)>> = BTreeMap::new();
    let mut egress = BTreeMap::new();
    for (i, (p, native, tagged, peer, hosts)) in ports.into_iter().enumerate() {
        let line = 10 + 2 * i as u32;
        let port = PortId::new(p);
        let native = native.map(|v| bd(name, v));
        fns.push(Arc::new(PortIngress {
            meta: dev.meta(&format!("{p}/in"), line, line),
            port: port.clone(),
            native: native.clone(),
            tagged: tagged.iter().map(|v| (*v, bd(name, *v))).collect(),
            next: dev.id("mac"),
        }));
        let out = dev.id(&format!("{p}/out"));
        fns.push(Arc::new(PortEgress {
            meta: dev.meta(&format!("{p}/out"), line + 1, line + 1),
            port: port.clone(),
            native: native.clone(),
            tagged: tagged.iter().map(|v| (bd(name, *v), *v)).collect(),
            peers: peer
                .map(|t| PortPeer {
                    target: fid(t),
                    link: None,
                })
                .into_iter()
                .collect(),
            hosts,
        }));
        for b in native
            .into_iter()
            .chain(tagged.iter().map(|v| bd(name, *v)))
        {
            flood
                .entry(b)
                .or_default()
                .push((port.clone(), out.clone()));
        }
        egress.insert(port, out);
    }
    let mut tables: BTreeMap<BridgeDomainId, BTreeMap<Mac, MacEntry>> = BTreeMap::new();
    for (v, m, p) in macs {
        tables.entry(bd(name, *v)).or_default().insert(
            *m,
            MacEntry {
                port: PortId::new(*p),
                spans: vec![SourceSpan::line(format!("{name}.macs"), 1)],
            },
        );
    }
    fns.push(Arc::new(MacLookup {
        meta: dev.meta("mac", 50, 50),
        tables,
        egress,
        flood: dev.id("flood"),
        hairpin: BTreeSet::new(),
        blocked: BTreeMap::new(),
    }));
    fns.push(Arc::new(Flood {
        meta: dev.meta("flood", 51, 51),
        ports: flood,
    }));
    fns
}

fn connection(first: u32) -> Vec<SourceSpan> {
    vec![SourceSpan::new(
        format!("{ACCOUNT}/connections"),
        first,
        first + 9,
    )]
}

fn far(port: &str, tags: Tags, peer: &str) -> FarEnd {
    FarEnd::Port {
        port: PortId::new(port),
        tags,
        peer: fid(peer),
    }
}

/// The twin:
///
/// - switch `sw-a` at site A: port 1 trunk to the Fabric port `fp-a` with
///   VLANs 100, 150, 200 and 400, and the access ports 2 to 5 with ha
///   192.0.2.10 in VLAN 100, ha2 198.51.100.10 in VLAN 200, ha3
///   198.51.100.70 in VLAN 150 and ha4 203.0.113.10 in VLAN 400
/// - switch `sw-b` at site B: port 1 trunk to `fp-b1` with VLAN 100, port 2
///   to the QinQ Fabric port `fp-b2` with VLAN 200 inside the service tag
///   300 with the TPID `0x88a8`, and the access ports 3 and 4 with hb
///   192.0.2.20 in VLAN 100 and hb2 198.51.100.20 in VLAN 200
/// - the account `equinix-acct` with the circuit `evpl-100` from `fp-a` VLAN
///   100 to `fp-b1` VLAN 100, the circuit `evpl-qinq` from `fp-a` VLAN 200
///   to `fp-b2` VLAN 300 with the TPID `0x88a8` and the inner VLAN 200, and
///   the circuit `sp-cloud` from `fp-a` VLAN 400 to the service profile
///   `cloud-onramp-1`; VLAN 150 of `fp-a` has no circuit
pub fn equinix_fabric() -> TwinBuilder {
    let a = Dev::new("sw-a", generic_router());
    let b = Dev::new("sw-b", generic_router());
    let acct = Dev::new(ACCOUNT, equinix());
    let gate = |p: &str| format!("{ACCOUNT}/port/{p}/in");
    let mut fns: Vec<Arc<dyn NetFunction>> = Vec::new();

    let ha = mac(0x21);
    let hb = mac(0x22);
    let ha2 = mac(0x23);
    let hb2 = mac(0x24);
    fns.extend(switch(
        &a,
        &[Trunk {
            port: "port/1",
            vlans: &[100, 150, 200, 400],
            peer: "equinix-acct/port/fp-a/in",
        }],
        &[
            (100, ha, "port/2"),
            (100, hb, "port/1"),
            (200, ha2, "port/3"),
            (200, hb2, "port/1"),
            (150, mac(0x25), "port/4"),
            (150, mac(REMOTE[0].1), "port/1"),
            (400, mac(0x27), "port/5"),
            (400, mac(REMOTE[1].1), "port/1"),
        ],
    ));
    fns.extend(switch(
        &b,
        &[
            Trunk {
                port: "port/1",
                vlans: &[100],
                peer: "equinix-acct/port/fp-b1/in",
            },
            Trunk {
                port: "port/2",
                vlans: &[200],
                peer: "sw-b/port/2/push",
            },
        ],
        &[
            (100, hb, "port/3"),
            (100, ha, "port/1"),
            (200, hb2, "port/4"),
            (200, ha2, "port/2"),
        ],
    ));
    fns.push(Arc::new(TagStack {
        meta: b.meta("port/2/pop", 60, 60),
        port: PortId::new("port/2"),
        op: TagOp::Pop(S_TAG),
        next: b.id("port/2/in"),
    }));
    fns.push(Arc::new(TagStack {
        meta: b.meta("port/2/push", 61, 61),
        port: PortId::new("port/2"),
        op: TagOp::Push(S_TAG),
        next: fid(&gate("fp-b2")),
    }));

    // The account: a gate and the circuits of each Fabric port.
    let dot1q = |v: u16| Tags::one(VlanTag::dot1q(v));
    let qinq = Tags::two(S_TAG, VlanTag::dot1q(200));
    let sink = acct.id("circuit/sp-cloud/sink");
    let ports: [(&str, u32, Vec<CircuitLeg>); 3] = [
        (
            "fp-a",
            1,
            vec![
                CircuitLeg {
                    circuit: "evpl-100".into(),
                    near: dot1q(100),
                    far: far("port/fp-b1", dot1q(100), "sw-b/port/1/in"),
                    spans: connection(1),
                },
                CircuitLeg {
                    circuit: "evpl-qinq".into(),
                    near: dot1q(200),
                    far: far("port/fp-b2", qinq, "sw-b/port/2/pop"),
                    spans: connection(11),
                },
                CircuitLeg {
                    circuit: "sp-cloud".into(),
                    near: dot1q(400),
                    far: FarEnd::Sink(sink.clone()),
                    spans: connection(21),
                },
            ],
        ),
        (
            "fp-b1",
            11,
            vec![CircuitLeg {
                circuit: "evpl-100".into(),
                near: dot1q(100),
                far: far("port/fp-a", dot1q(100), "sw-a/port/1/in"),
                spans: connection(1),
            }],
        ),
        (
            "fp-b2",
            21,
            vec![CircuitLeg {
                circuit: "evpl-qinq".into(),
                near: qinq,
                far: far("port/fp-a", dot1q(200), "sw-a/port/1/in"),
                spans: connection(11),
            }],
        ),
    ];
    for (p, first, legs) in ports {
        let span = SourceSpan::new(format!("{ACCOUNT}/ports"), first, first + 9);
        let mut rules: Vec<Rule<RuleAction>> = legs
            .iter()
            .map(|l| {
                let mut r = Rule::new(l.circuit.clone(), l.near.predicate(), RuleAction::Permit);
                r.spans = l.spans.clone();
                r
            })
            .collect();
        rules.push(Rule::unhandled("no circuit for the frame tags", span));
        fns.push(Arc::new(AclMatch {
            meta: acct.meta(&format!("port/{p}/in"), first, first + 9),
            acl: ObjectId::new(format!("{ACCOUNT}:port/{p}")),
            rules,
            default: RuleAction::Deny,
            next: acct.id(&format!("port/{p}/circuit")),
        }));
        fns.push(Arc::new(Circuit {
            meta: acct.meta(&format!("port/{p}/circuit"), first, first + 9),
            port: PortId::new(format!("port/{p}")),
            legs,
        }));
    }
    let sp = connection(21).remove(0);
    fns.push(Arc::new(AclMatch {
        meta: acct.meta("circuit/sp-cloud/sink", 21, 30),
        acl: ObjectId::new(format!("{ACCOUNT}:circuit/sp-cloud")),
        rules: vec![Rule::unhandled(
            "the far end is the service profile cloud-onramp-1 of the provider example-cloud",
            sp,
        )],
        default: RuleAction::Deny,
        next: sink,
    }));

    // The hosts: each attachment point knows the MAC of each address of
    // the hosts and of the remote addresses.
    let mut known: TriePrefixTable<HostMac> = TriePrefixTable::new();
    let addresses = HOSTS
        .iter()
        .map(|h| (h.addr, h.mac))
        .chain(REMOTE.iter().copied());
    for (addr, m) in addresses {
        known.insert(
            Prefix::host(ip(addr)),
            HostMac {
                mac: mac(m),
                spans: vec![SourceSpan::line("sites.clients", 1)],
            },
        );
    }
    let mut builder = TwinBuilder::new();
    for h in &HOSTS {
        let dev = if h.device == "sw-a" { &a } else { &b };
        fns.push(Arc::new(HostResolution {
            meta: dev.meta(&format!("host/{}", h.port), 70, 70),
            interface: InterfaceId::new(h.port),
            hosts: known.clone(),
            local: vec![pfx(h.net)],
            gateway: None,
            next: dev.id(&format!("{}/in", h.port)),
        }));
        builder.endpoint(Endpoint {
            id: EndpointId::new(h.name),
            addresses: vec![ip(h.addr)],
        });
        builder.attachment(AttachmentRecord {
            address: ip(h.addr),
            device: h.device.into(),
            interface: InterfaceId::new(h.port),
            kind: AttachmentKind::Client,
            host: h.name.into(),
            provenance: vec![SourceSpan::line("sites.clients", 2)],
        });
    }
    for f in fns {
        builder.add_arc(f);
    }
    builder
}
