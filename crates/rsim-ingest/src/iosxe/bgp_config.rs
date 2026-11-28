//! The BGP processes of an IOS-XE running config for the BGP calculation:
//! the process of the default VRF and of each VRF of an `address-family
//! <family> vrf <name>` stanza, with the router ID, the cluster ID, the
//! `bgp` options, `maximum-paths`, the `network` and `aggregate-address`
//! lines and the neighbours, and the route maps, the prefix lists, the
//! community lists and the AS-path lists in the form of NX-OS.
//!
//! The settings of a neighbour in a unicast family come from its own
//! `neighbor <peer> <keyword>` lines of the address family, and for IPv4
//! unicast of the default VRF also of the global part, then from the
//! `template peer-policy` stanzas that it inherits in the order of their
//! sequence numbers, then from its peer group. A VRF takes the router ID of
//! its `bgp router-id` line, else the one of the global part. A line of a
//! process, a neighbour, a peer group or a template that the reader does
//! not lower, other than a line with no effect on the routes, is a gap.
//!
//! The lines that import or export routes between VRFs or between EVPN and
//! a VRF are gaps of their VRF: each `route-target`, `import` and `export`
//! line and the `vnid` line of a `vrf definition` or an `ip vrf`, an
//! `address-family l2vpn` stanza of `router bgp` with a VRF, and
//! `advertise l2vpn evpn` of a unicast family of a VRF.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rsim_core::Prefix;
use rsim_routing::Platform;
use rsim_routing::bgp::{
    Aggregate, Asn, BgpOptions, BgpProcess, Family, Network, NextHopSelf, RouteKey,
};

use crate::bgp_build::CollectedBgp;
use crate::bgp_config::{AfSettings, DeviceBgp, UNICAST, neighbor, no_effect, span, unicast_of};
use crate::bgp_peers::{BgpConfig, DEFAULT_VRF, family};
use crate::coverage::{Reach, State, Table};
use crate::links::BgpPeer;
use crate::stanza::{Document, Stanza};

fn words(s: &Stanza) -> Vec<&str> {
    s.key.split_whitespace().collect()
}

fn lines(s: &Stanza) -> (u32, u32) {
    (s.first_line, s.last_line)
}

/// The handled lines of the global part of `router bgp`.
const PROCESS_LINES: &[&str] = &[
    "bgp router-id *",
    "bgp cluster-id *",
    "bgp always-compare-med",
    "bgp deterministic-med",
    "bgp bestpath compare-routerid",
    "bgp bestpath med missing-as-worst",
    "bgp bestpath as-path multipath-relax",
    "bgp default local-preference *",
    "no synchronization",
    "no auto-summary",
];

/// The handled `neighbor` lines of the settings of an address family, in
/// the global part and in an address family.
const NEIGHBOR_LINES: &[&str] = &[
    "neighbor * route-map * in",
    "neighbor * route-map * out",
    "neighbor * route-reflector-client",
    "neighbor * next-hop-self",
    "neighbor * next-hop-self all",
    "neighbor * send-community",
    "neighbor * send-community *",
    "neighbor * remove-private-as",
];

/// The handled lines of an address family.
const AF_LINES: &[&str] = &[
    "network *",
    "network * route-map *",
    "network * mask *",
    "network * mask * route-map *",
    "maximum-paths *",
    "maximum-paths ibgp *",
    "bgp router-id *",
    "no synchronization",
    "no auto-summary",
];

/// The handled lines of a `template peer-policy`.
const TEMPLATE_LINES: &[&str] = &[
    "route-map * in",
    "route-map * out",
    "route-reflector-client",
    "next-hop-self",
    "next-hop-self all",
    "send-community",
    "send-community *",
    "remove-private-as",
];

/// Adds the handled lines that the reader lowers. Call it before the
/// entries of the routing processes and of the route maps and lists.
pub fn push_entries(t: &mut Table) {
    let tree =
        |t: &mut Table, levels: &[&str]| t.push_levels(levels, State::Handled, Reach::Subtree);
    let p = "router bgp *";
    for line in PROCESS_LINES.iter().chain(NEIGHBOR_LINES) {
        tree(t, &[p, line]);
    }
    for line in AF_LINES.iter().chain(NEIGHBOR_LINES) {
        tree(t, &[p, "address-family ..", line]);
    }
    t.push_checked(
        &[p, "address-family ..", "aggregate-address .."],
        State::Handled,
        Reach::Subtree,
        aggregate_options,
    );
    for line in TEMPLATE_LINES {
        tree(t, &[p, "template peer-policy *", line]);
    }
    for object in [
        "route-map * permit *",
        "route-map * deny *",
        "route-map * permit",
        "route-map * deny",
        "ip prefix-list ..",
        "ipv6 prefix-list ..",
        "ip community-list ..",
        "ip as-path access-list ..",
    ] {
        tree(t, &[object]);
    }
}

/// True for an `aggregate-address` line with a prefix, or an address and
/// a mask, and only the options `summary-only` and `as-set`.
fn aggregate_options(key: &str) -> bool {
    let w: Vec<&str> = key.split_whitespace().collect();
    let ["aggregate-address", _, rest @ ..] = w.as_slice() else {
        return false;
    };
    let opts = match rest {
        [m, opts @ ..] if m.parse::<Ipv4Addr>().is_ok() => opts,
        _ => rest,
    };
    opts.iter().all(|o| matches!(*o, "summary-only" | "as-set"))
}

/// The kind of a line of a neighbour, a peer group or a template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    /// The reader of this module reads the line.
    Read,
    /// The reader of the neighbours reads the line.
    Other,
    NoEffect,
    Gap,
}

/// Reads the words of a line of a neighbour after `neighbor <peer>`, or of
/// a template, into the settings of an address family.
fn af_line(w: &[&str], af: &mut AfSettings) -> Line {
    match w {
        ["route-map", m, "in"] => af.import = Some((*m).to_string()),
        ["route-map", m, "out"] => af.export = Some((*m).to_string()),
        ["route-reflector-client"] => af.rr_client = Some(true),
        ["next-hop-self"] => af.next_hop_self = Some(NextHopSelf::On),
        ["next-hop-self", "all"] => af.next_hop_self = Some(NextHopSelf::All),
        ["send-community"] | ["send-community", "standard"] => af.send_community = Some(true),
        ["send-community", "extended"] => af.send_community_extended = Some(true),
        ["send-community", "both"] => {
            af.send_community = Some(true);
            af.send_community_extended = Some(true);
        }
        ["remove-private-as"] => af.remove_private_as = Some(true),
        ["remote-as", ..]
        | ["peer-group"]
        | ["peer-group", _]
        | ["update-source", _]
        | ["shutdown"]
        | ["local-as", ..]
        | ["inherit", ..]
        | ["activate"]
        | ["exit-peer-policy"]
        | ["exit-peer-session"] => return Line::Other,
        w if no_effect(w) => return Line::NoEffect,
        _ => return Line::Gap,
    }
    Line::Read
}

/// The words after `address-family`: the VRF and the unicast family, for
/// example `ipv4 vrf RED`. `None` for a family other than IPv4 and IPv6
/// unicast.
fn af_scope(w: &[&str]) -> (String, Option<Family>) {
    let (fam, vrf) = match w.iter().position(|x| *x == "vrf") {
        Some(i) => (&w[..i], w.get(i + 1).copied()),
        None => (w, None),
    };
    (
        vrf.unwrap_or(DEFAULT_VRF).to_string(),
        family(fam).and_then(|f| unicast_of(&f)),
    )
}

/// The name of a neighbour or a peer group as a key: an address in its
/// canonical text, else the name.
fn key(name: &str) -> String {
    name.parse::<IpAddr>()
        .map_or_else(|_| name.to_string(), |a| a.to_string())
}

/// A gap line: the masked text, the lines and the families.
type GapLine = (String, (u32, u32), Vec<Family>);

/// The settings of a neighbour, a peer group or a `template peer-policy` in
/// one family.
#[derive(Clone, Debug, Default)]
struct Entry {
    settings: AfSettings,
    /// The peer-policy templates that it inherits, with their sequence
    /// numbers.
    policies: Vec<(u32, String)>,
    gaps: Vec<GapLine>,
}

/// The originations and the options of the address families of a VRF.
#[derive(Default)]
struct VrfLines {
    router_id: Option<Ipv4Addr>,
    networks: Vec<Network>,
    aggregates: Vec<Aggregate>,
    ebgp_paths: Option<u32>,
    ibgp_paths: Option<u32>,
}

struct Reader<'a> {
    mask: &'a dyn Fn(&str) -> String,
    file: &'a str,
    /// The settings of each VRF, family and name.
    af: BTreeMap<(String, Family, String), Entry>,
    /// The peer group of each VRF and name.
    group_of: BTreeMap<(String, String), String>,
    /// The peer-session templates of each VRF and name.
    sessions: BTreeMap<(String, String), Vec<String>>,
    policy_templates: BTreeMap<String, Entry>,
    /// The peer-session templates that each one inherits, and its gaps.
    session_templates: BTreeMap<String, (Vec<String>, Vec<GapLine>)>,
    vrfs: BTreeMap<String, VrfLines>,
}

/// The prefix of an address and a dotted mask.
fn with_mask(a: &str, m: &str) -> Option<Prefix> {
    let addr: Ipv4Addr = a.parse().ok()?;
    let bits = u32::from(m.parse::<Ipv4Addr>().ok()?);
    if bits.count_ones() != bits.leading_ones() {
        return None;
    }
    format!("{addr}/{}", bits.leading_ones()).parse().ok()
}

/// The prefix of a `network` or `aggregate-address` line with no mask: an
/// IPv6 prefix, or an IPv4 address with its classful length.
fn bare(a: &str) -> Option<Prefix> {
    if a.contains(':') {
        return a.parse().ok();
    }
    if !crate::bgp_table::network_ok(a) || a.contains('/') {
        return None;
    }
    crate::bgp_table::classful(a).parse().ok()
}

impl Reader<'_> {
    fn entry(&mut self, vrf: &str, f: Family, name: &str) -> &mut Entry {
        self.af.entry((vrf.to_string(), f, key(name))).or_default()
    }

    /// Reads one `neighbor <name> <words>` line of the global part, with
    /// `fam` `None`, or of an address family of `vrf`.
    fn neighbor_line(
        &mut self,
        vrf: &str,
        fam: Option<Family>,
        name: &str,
        rest: &[&str],
        s: &Stanza,
        read: &mut BTreeSet<u32>,
    ) {
        let f = fam.unwrap_or(Family::Ipv4Unicast);
        match rest {
            ["peer-group", g] => {
                self.group_of
                    .insert((vrf.to_string(), key(name)), (*g).to_string());
            }
            ["inherit", "peer-policy", t, seq @ ..] => {
                let seq = seq.first().and_then(|x| x.parse().ok()).unwrap_or(0);
                self.entry(vrf, f, name)
                    .policies
                    .push((seq, (*t).to_string()));
            }
            ["inherit", "peer-session", t, ..] => {
                self.sessions
                    .entry((vrf.to_string(), key(name)))
                    .or_default()
                    .push((*t).to_string());
            }
            _ => {
                let mask = self.mask;
                let e = self.entry(vrf, f, name);
                match af_line(rest, &mut e.settings) {
                    Line::Read => {
                        read.insert(s.first_line);
                    }
                    Line::Gap => e.gaps.push((
                        mask(&s.key),
                        lines(s),
                        fam.map_or(UNICAST.to_vec(), |f| vec![f]),
                    )),
                    Line::Other | Line::NoEffect => {}
                }
            }
        }
    }

    /// Reads one line of an address family of `vrf` in the family `f`
    /// other than a `neighbor` line. Gives false for a gap.
    fn af_item(&mut self, vrf: &str, f: Family, w: &[&str], s: &Stanza) -> bool {
        let spans = vec![span(self.file, lines(s))];
        let v = self.vrfs.entry(vrf.to_string()).or_default();
        let fits = |p: Option<Prefix>| p.map(RouteKey::unicast).filter(|k| k.family == f);
        let network = |k: RouteKey, policy: Option<&str>| Network {
            key: k,
            policy: policy.map(str::to_string),
            spans: spans.clone(),
        };
        match w {
            ["network", a, "mask", m] => fits(with_mask(a, m))
                .map(|k| v.networks.push(network(k, None)))
                .is_some(),
            ["network", a, "mask", m, "route-map", r] => fits(with_mask(a, m))
                .map(|k| v.networks.push(network(k, Some(*r))))
                .is_some(),
            ["network", a] => fits(bare(a))
                .map(|k| v.networks.push(network(k, None)))
                .is_some(),
            ["network", a, "route-map", r] => fits(bare(a))
                .map(|k| v.networks.push(network(k, Some(*r))))
                .is_some(),
            ["aggregate-address", rest @ ..] => {
                let (p, opts) = match rest {
                    [a, m, opts @ ..] if m.parse::<Ipv4Addr>().is_ok() => (with_mask(a, m), opts),
                    [a, opts @ ..] => (bare(a), opts),
                    [] => (None, rest),
                };
                if !opts.iter().all(|o| matches!(*o, "summary-only" | "as-set")) {
                    return false;
                }
                fits(p)
                    .map(|k| {
                        v.aggregates.push(Aggregate {
                            key: k,
                            summary_only: opts.contains(&"summary-only"),
                            as_set: opts.contains(&"as-set"),
                            spans: spans.clone(),
                        })
                    })
                    .is_some()
            }
            ["maximum-paths", n] => n
                .parse::<u32>()
                .ok()
                .filter(|n| v.ebgp_paths.is_none_or(|x| x == *n))
                .map(|n| v.ebgp_paths = Some(n))
                .is_some(),
            ["maximum-paths", "ibgp", n] => n
                .parse::<u32>()
                .ok()
                .filter(|n| v.ibgp_paths.is_none_or(|x| x == *n))
                .map(|n| v.ibgp_paths = Some(n))
                .is_some(),
            ["bgp", "router-id", a] if vrf != DEFAULT_VRF => a
                .parse::<Ipv4Addr>()
                .ok()
                .map(|x| v.router_id = Some(x))
                .is_some(),
            ["no", "synchronization"] | ["no", "auto-summary"] => true,
            _ => false,
        }
    }

    /// The settings of a `template peer-policy` and of the templates that it
    /// inherits, with their gap lines.
    fn policy_template(
        &self,
        name: &str,
        path: &mut Vec<String>,
        gaps: &mut Vec<GapLine>,
    ) -> AfSettings {
        let Some(t) = self.policy_templates.get(name) else {
            return AfSettings::default();
        };
        if path.iter().any(|p| p == name) {
            return AfSettings::default();
        }
        path.push(name.to_string());
        let mut own = t.settings.clone();
        gaps.extend(t.gaps.iter().cloned());
        let mut more = t.policies.clone();
        more.sort();
        for (_, n) in &more {
            let p = self.policy_template(n, path, gaps);
            own.fill(&p);
        }
        path.pop();
        own
    }

    /// The settings of a neighbour or a peer group in `vrf` and `f`: its
    /// own lines, then its peer-policy templates, then its peer group.
    fn settings(
        &self,
        vrf: &str,
        f: Family,
        name: &str,
        seen: &mut Vec<String>,
        gaps: &mut Vec<GapLine>,
    ) -> AfSettings {
        let k = key(name);
        if seen.contains(&k) {
            return AfSettings::default();
        }
        seen.push(k.clone());
        let e = self
            .af
            .get(&(vrf.to_string(), f, k.clone()))
            .cloned()
            .unwrap_or_default();
        let mut own = e.settings;
        gaps.extend(e.gaps);
        let mut policies = e.policies;
        policies.sort();
        for (_, p) in &policies {
            let x = self.policy_template(p, &mut Vec::new(), gaps);
            own.fill(&x);
        }
        if let Some(g) = self.group_of.get(&(vrf.to_string(), k)) {
            let x = self.settings(vrf, f, g, seen, gaps);
            own.fill(&x);
        }
        own
    }

    /// The gap lines of the peer-session templates of a neighbour or a
    /// peer group, of the templates that they inherit and of its peer
    /// group.
    fn session_gaps(&self, vrf: &str, name: &str, seen: &mut Vec<String>, gaps: &mut Vec<GapLine>) {
        let k = key(name);
        if seen.contains(&k) {
            return;
        }
        seen.push(k.clone());
        let mut todo: Vec<String> = self
            .sessions
            .get(&(vrf.to_string(), k.clone()))
            .cloned()
            .unwrap_or_default();
        let mut done: Vec<String> = Vec::new();
        while let Some(t) = todo.pop() {
            if done.contains(&t) {
                continue;
            }
            if let Some((parents, g)) = self.session_templates.get(&t) {
                gaps.extend(g.iter().cloned());
                todo.extend(parents.iter().cloned());
            }
            done.push(t);
        }
        if let Some(g) = self.group_of.get(&(vrf.to_string(), k)) {
            self.session_gaps(vrf, g, seen, gaps);
        }
    }
}

/// The selected BGP routes of the collected route table by VRF and prefix,
/// with the next hops of their paths.
pub fn collected(
    cfg: &super::Config,
    sections: &BTreeMap<String, (Vec<u8>, String)>,
) -> Vec<CollectedBgp> {
    let st = super::state::read(sections, &super::names(cfg));
    match &st.l3.rib {
        Some(Ok(rib)) => crate::iosxr::bgp_config::collected_of(rib),
        _ => Vec::new(),
    }
}

/// Each `route-target`, `import`, `export` and `vnid` line of a VRF is a
/// gap of its VRF.
fn vrf_imports(doc: &Document, file: &str, mask: &dyn Fn(&str) -> String, out: &mut DeviceBgp) {
    for s in doc.root.children() {
        let w = words(s);
        let vrf = match w.as_slice() {
            ["vrf", "definition", v] | ["ip", "vrf", v] => *v,
            _ => continue,
        };
        let check = |c: &Stanza, fams: &[Family], out: &mut DeviceBgp| {
            if matches!(
                words(c).as_slice(),
                ["route-target", "import" | "export" | "both", ..]
                    | ["import" | "export" | "vnid", ..]
            ) {
                out.gap(vrf, fams, mask(&c.key), vec![span(file, lines(c))]);
            }
            // An export into the global table is a gap of the default VRF
            // too.
            if let ["export", "ipv4" | "ipv6", "unicast", ..] = words(c).as_slice() {
                out.gap(DEFAULT_VRF, fams, mask(&c.key), vec![span(file, lines(c))]);
            }
        };
        for c in s.children() {
            let cw = words(c);
            if let ["address-family", fam @ ..] = cw.as_slice() {
                if let Some(f) = family(fam).and_then(|x| unicast_of(&x)) {
                    for a in c.children() {
                        check(a, &[f], out);
                    }
                }
            } else {
                check(c, &UNICAST, out);
            }
        }
    }
}

/// Reads the BGP processes of the config with the policies and the gaps.
/// `bgp` is the BGP config after the inheritance. Each line that the reader
/// lowers goes into `read`.
pub fn read(
    doc: &Document,
    bgp: &BgpConfig,
    file: &str,
    mask: &dyn Fn(&str) -> String,
    read: &mut BTreeSet<u32>,
) -> DeviceBgp {
    let mut out = DeviceBgp::default();
    let policy = crate::nxos::bgp_config::policies(doc, file, mask, read);
    vrf_imports(doc, file, mask, &mut out);
    let Some(rb) = doc
        .root
        .children()
        .iter()
        .find(|s| words(s).starts_with(&["router", "bgp"]))
    else {
        return out;
    };
    let mut r = Reader {
        mask,
        file,
        af: BTreeMap::new(),
        group_of: BTreeMap::new(),
        sessions: BTreeMap::new(),
        policy_templates: BTreeMap::new(),
        session_templates: BTreeMap::new(),
        vrfs: BTreeMap::new(),
    };
    let mut options = BgpOptions::default();
    let mut router_id = None;
    let mut cluster_id = None;
    let mut no_default_ipv4 = false;
    let gap = |out: &mut DeviceBgp, vrf: &str, fams: &[Family], c: &Stanza| {
        out.gap(vrf, fams, mask(&c.key), vec![span(file, lines(c))]);
    };
    for c in rb.children() {
        let w = words(c);
        match w.as_slice() {
            ["template", "peer-policy", name] => {
                let mut e = Entry::default();
                for l in c.children() {
                    let lw = words(l);
                    if let ["inherit", "peer-policy", n, seq @ ..] = lw.as_slice() {
                        let seq = seq.first().and_then(|x| x.parse().ok()).unwrap_or(0);
                        e.policies.push((seq, (*n).to_string()));
                        continue;
                    }
                    match af_line(&lw, &mut e.settings) {
                        Line::Read => {
                            read.insert(l.first_line);
                        }
                        Line::Gap => e.gaps.push((mask(&l.key), lines(l), UNICAST.to_vec())),
                        Line::Other | Line::NoEffect => {}
                    }
                }
                r.policy_templates.insert((*name).to_string(), e);
            }
            ["template", "peer-session", name] => {
                let mut parents = Vec::new();
                let mut gaps = Vec::new();
                for l in c.children() {
                    let lw = words(l);
                    match lw.as_slice() {
                        ["inherit", "peer-session", n, ..] => parents.push((*n).to_string()),
                        ["remote-as", ..]
                        | ["update-source", _]
                        | ["shutdown"]
                        | ["local-as", ..]
                        | ["inherit", ..]
                        | ["exit-peer-session"] => {}
                        w if no_effect(w) => {}
                        _ => gaps.push((mask(&l.key), lines(l), UNICAST.to_vec())),
                    }
                }
                r.session_templates
                    .insert((*name).to_string(), (parents, gaps));
            }
            ["address-family", rest @ ..] => {
                let (vrf, fam) = af_scope(rest);
                let Some(f) = fam else {
                    if vrf != DEFAULT_VRF && rest.first() == Some(&"l2vpn") {
                        gap(&mut out, &vrf, &UNICAST, c);
                    }
                    continue;
                };
                for a in c.children() {
                    let aw = words(a);
                    match aw.as_slice() {
                        ["neighbor", name, more @ ..] => {
                            r.neighbor_line(&vrf, Some(f), name, more, a, read);
                        }
                        ["no", "neighbor", ..] | ["exit-address-family"] => {}
                        w if r.af_item(&vrf, f, w, a) => {
                            read.insert(a.first_line);
                        }
                        w if no_effect(w) => {}
                        _ => gap(&mut out, &vrf, &[f], a),
                    }
                }
            }
            ["neighbor", name, more @ ..] => {
                r.neighbor_line(DEFAULT_VRF, None, name, more, c, read);
            }
            ["no", "neighbor", ..]
            | ["bgp", "confederation", ..]
            | ["bgp", "listen", ..]
            | ["exit-peer-session" | "exit-peer-policy" | "exit-address-family"] => {}
            ["no", "bgp", "default", "ipv4-unicast"] => no_default_ipv4 = true,
            ["bgp", rest @ ..] => {
                let ok = match rest {
                    ["router-id", a] => match a.parse::<Ipv4Addr>() {
                        Ok(x) => {
                            router_id = Some(x);
                            true
                        }
                        Err(_) => false,
                    },
                    ["cluster-id", a] => match a.parse::<Ipv4Addr>() {
                        Ok(x) => {
                            cluster_id = Some(x);
                            true
                        }
                        Err(_) => false,
                    },
                    ["always-compare-med"] => {
                        options.always_compare_med = true;
                        true
                    }
                    ["deterministic-med"] => {
                        options.deterministic_med = Some(true);
                        true
                    }
                    ["bestpath", "compare-routerid"] => {
                        options.compare_routerid = true;
                        true
                    }
                    ["bestpath", "med", "missing-as-worst"] => {
                        options.missing_as_worst = Some(true);
                        true
                    }
                    ["bestpath", "as-path", "multipath-relax"] => {
                        options.multipath_relax = true;
                        true
                    }
                    ["default", "local-preference", n] => match n.parse::<u32>() {
                        Ok(n) => {
                            options.default_local_pref = Some(n);
                            true
                        }
                        Err(_) => false,
                    },
                    _ => false,
                };
                if ok {
                    read.insert(c.first_line);
                } else if !no_effect(&w) {
                    gap(&mut out, DEFAULT_VRF, &UNICAST, c);
                }
            }
            ["no", "synchronization"] | ["no", "auto-summary"] => {
                read.insert(c.first_line);
            }
            w if no_effect(w) => {}
            _ => gap(&mut out, DEFAULT_VRF, &UNICAST, c),
        }
    }
    let processes: Vec<String> = bgp.processes.keys().cloned().collect();
    for vrf in processes {
        let process = &bgp.processes[&vrf];
        let asn = match &process.asn.value {
            Ok(a) => *a,
            Err(e) => {
                out.gap(&vrf, &UNICAST, e.clone(), vec![span(file, lines(rb))]);
                continue;
            }
        };
        let v = r.vrfs.remove(&vrf).unwrap_or_default();
        let id = v.router_id.or(router_id);
        let mut p = BgpProcess::new("", &vrf, Some(Platform::Iosxe), Asn(asn), id);
        p.cluster_id = cluster_id;
        p.options = options.clone();
        p.options.maximum_paths_ebgp = v.ebgp_paths;
        p.options.maximum_paths_ibgp = v.ibgp_paths;
        // The reader of the neighbours activates IPv4 unicast in the default
        // VRF by the default of the profile, and the family of the stanza in
        // a VRF.
        if vrf != DEFAULT_VRF || no_default_ipv4 {
            p.options.default_ipv4_unicast = Some(false);
        }
        p.networks = v.networks;
        p.aggregates = v.aggregates;
        p.policy = policy.clone();
        p.spans = vec![span(file, (rb.first_line, rb.first_line))];
        if let Some(id) = &process.confederation.identifier {
            match &id.value {
                Ok(a) => p.confederation_id = Some(Asn(*a)),
                Err(t) => out.gap(&vrf, &UNICAST, t.clone(), vec![span(file, id.lines)]),
            }
        }
        if let Some(peers) = &process.confederation.peers {
            match &peers.value {
                Ok(m) => p.confederation_peers = m.iter().map(|a| Asn(*a)).collect(),
                Err(t) => out.gap(&vrf, &UNICAST, t.clone(), vec![span(file, peers.lines)]),
            }
        }
        for n in bgp.neighbours.iter().filter(|n| n.vrf == vrf) {
            let name = match &n.peer {
                BgpPeer::Address(a) => a.to_string(),
                BgpPeer::Range(x) => x.to_string(),
                BgpPeer::Interface(i) => i.clone(),
            };
            let mut gaps = Vec::new();
            r.session_gaps(&vrf, &name, &mut Vec::new(), &mut gaps);
            let mut af = BTreeMap::new();
            for f in UNICAST {
                af.insert(f, r.settings(&vrf, f, &name, &mut Vec::new(), &mut gaps));
            }
            gaps.sort();
            gaps.dedup();
            for (text, l, fams) in gaps {
                out.gap(&vrf, &fams, text, vec![span(file, l)]);
            }
            match neighbor(n, asn, &af, file) {
                Ok(nb) => {
                    p.neighbors.insert(nb.address, nb);
                }
                Err(why) => out.gap(&vrf, &UNICAST, why, vec![span(file, n.lines)]),
            }
        }
        out.processes.push(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const CONFIG: &str = "\
hostname r1
router bgp 64500
 template peer-policy RR
  route-reflector-client
  route-map IN in
  soft-reconfiguration inbound
 exit-peer-policy
 !
 template peer-session IBGP
  remote-as 64500
  update-source Loopback0
  fall-over bfd
 exit-peer-session
 !
 bgp router-id 192.0.2.1
 bgp log-neighbor-changes
 bgp always-compare-med
 bgp bestpath as-path multipath-relax
 no bgp default ipv4-unicast
 neighbor GROUP peer-group
 neighbor GROUP remote-as 64501
 neighbor 192.0.2.2 inherit peer-session IBGP
 neighbor 198.51.100.1 peer-group GROUP
 neighbor 198.51.100.1 description isp
 neighbor 198.51.100.9 remote-as 64502
 neighbor 198.51.100.9 allowas-in 2
 !
 address-family ipv4
  network 203.0.113.0 mask 255.255.255.0
  network 10.0.0.0
  aggregate-address 203.0.112.0 255.255.254.0 summary-only
  aggregate-address 198.51.100.0 255.255.255.0 attribute-map SET
  maximum-paths 2
  redistribute connected
  neighbor GROUP route-map OUT out
  neighbor GROUP send-community both
  neighbor 192.0.2.2 activate
  neighbor 192.0.2.2 inherit peer-policy RR 10
  neighbor 192.0.2.2 next-hop-self
  neighbor 198.51.100.1 activate
  neighbor 198.51.100.1 route-map IN in
 exit-address-family
 !
 address-family ipv4 vrf RED
  bgp router-id 192.0.2.99
  neighbor 203.0.113.9 remote-as 64510
  neighbor 203.0.113.9 activate
 exit-address-family
!
ip prefix-list LAN seq 5 permit 203.0.113.0/24 le 26
ip community-list 10 permit 64500:1
ip as-path access-list 5 permit ^64501_
!
route-map IN permit 10
 match ip address prefix-list LAN
 set local-preference 200
!
route-map OUT permit 10
 match community 10
!
vrf definition RED
 address-family ipv4
  route-target import 64500:1
";

    fn lowered() -> (DeviceBgp, BTreeSet<u32>) {
        let doc = super::super::read_text(CONFIG.as_bytes());
        let mut read = BTreeSet::new();
        let rb = doc
            .root
            .children()
            .iter()
            .find(|s| s.key.starts_with("router bgp"))
            .unwrap();
        let bgp = super::super::bgp::read(rb, &mut read, &|k| k.to_string());
        let out = super::read(&doc, &bgp, "r1/config", &|k| k.to_string(), &mut read);
        (out, read)
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_processes_take_the_options_the_originations_and_the_inherited_settings() {
        let (d, _) = lowered();
        let p = d.processes.iter().find(|p| p.vrf == "default").unwrap();
        assert_eq!(p.router_id, Some("192.0.2.1".parse::<Ipv4Addr>().unwrap()));
        assert!(p.options.always_compare_med && p.options.multipath_relax);
        assert_eq!(p.options.maximum_paths_ebgp, Some(2));
        assert_eq!(p.options.default_ipv4_unicast, Some(false));
        let nets: Vec<String> = p
            .networks
            .iter()
            .map(|n| n.key.prefix.to_string())
            .collect();
        assert_eq!(nets, ["203.0.113.0/24", "10.0.0.0/8"]);
        assert!(p.aggregates[0].summary_only);
        assert_eq!(p.aggregates[0].key.prefix.to_string(), "203.0.112.0/23");
        let ibgp = &p.neighbors[&addr("192.0.2.2")];
        assert_eq!(ibgp.remote_as, Asn(64500));
        assert!(ibgp.route_reflector_client);
        assert_eq!(ibgp.next_hop_self, NextHopSelf::On);
        assert_eq!(ibgp.import_policy.as_deref(), Some("IN"));
        let ebgp = &p.neighbors[&addr("198.51.100.1")];
        assert_eq!(ebgp.remote_as, Asn(64501));
        assert_eq!(ebgp.import_policy.as_deref(), Some("IN"));
        assert_eq!(ebgp.export_policy.as_deref(), Some("OUT"));
        assert!(ebgp.send_community && ebgp.send_community_extended);
        assert!(ebgp.activated.contains(&Family::Ipv4Unicast));
        let red = d.processes.iter().find(|p| p.vrf == "RED").unwrap();
        assert_eq!(
            red.router_id,
            Some("192.0.2.99".parse::<Ipv4Addr>().unwrap())
        );
        assert!(red.neighbors.contains_key(&addr("203.0.113.9")));
        assert!(p.policy.community_lists.contains_key("10"));
        assert!(p.policy.as_path_lists.contains_key("5"));
    }

    #[test]
    fn the_lines_that_are_not_lowered_are_gaps() {
        let (d, _) = lowered();
        let texts: Vec<(&str, &str)> = d
            .gaps
            .iter()
            .map(|g| (g.vrf.as_str(), g.text.as_str()))
            .collect();
        for want in [
            ("default", "redistribute connected"),
            (
                "default",
                "aggregate-address 198.51.100.0 255.255.255.0 attribute-map SET",
            ),
            ("default", "neighbor 198.51.100.9 allowas-in 2"),
            ("default", "fall-over bfd"),
            ("RED", "route-target import 64500:1"),
        ] {
            assert!(texts.contains(&want), "{want:?} not in {texts:?}");
        }
    }

    #[test]
    fn the_lines_that_import_routes_into_a_vrf_are_gaps_of_the_vrf() {
        let doc = super::super::read_text(
            b"\
router bgp 64500
 bgp router-id 192.0.2.1
 address-family ipv4 vrf RED
  advertise l2vpn evpn
 exit-address-family
 !
 address-family l2vpn evpn vrf RED
 exit-address-family
!
vrf definition RED
 rd 64500:1
 vnid 10010 evpn-instance vni 10010
 address-family ipv4
  route-target import 64500:10
  route-target export 64500:10
  route-target both 64500:11
  import ipv4 unicast map FROM-GLOBAL
  export ipv4 unicast map TO-GLOBAL
 exit-address-family
!
ip vrf BLUE
 route-target export 64500:20
",
        );
        let mut read = BTreeSet::new();
        let rb = doc
            .root
            .children()
            .iter()
            .find(|s| s.key.starts_with("router bgp"))
            .unwrap();
        let bgp = super::super::bgp::read(rb, &mut read, &|k| k.to_string());
        let d = super::read(&doc, &bgp, "r1/config", &|k| k.to_string(), &mut read);
        let texts: Vec<(&str, &str)> = d
            .gaps
            .iter()
            .map(|g| (g.vrf.as_str(), g.text.as_str()))
            .collect();
        for want in [
            ("RED", "vnid 10010 evpn-instance vni 10010"),
            ("RED", "route-target import 64500:10"),
            ("RED", "route-target export 64500:10"),
            ("RED", "route-target both 64500:11"),
            ("RED", "import ipv4 unicast map FROM-GLOBAL"),
            ("RED", "export ipv4 unicast map TO-GLOBAL"),
            ("default", "export ipv4 unicast map TO-GLOBAL"),
            ("RED", "advertise l2vpn evpn"),
            ("RED", "address-family l2vpn evpn vrf RED"),
            ("BLUE", "route-target export 64500:20"),
        ] {
            assert!(texts.contains(&want), "{want:?} not in {texts:?}");
        }
        let default: Vec<&str> = texts
            .iter()
            .filter(|(v, _)| *v == "default")
            .map(|(_, t)| *t)
            .collect();
        assert_eq!(default, ["export ipv4 unicast map TO-GLOBAL"], "{texts:?}");
    }

    #[test]
    fn each_handled_line_is_read() {
        let doc = super::super::read_text(CONFIG.as_bytes());
        let tables = crate::route_tables::RouteTables::uniform(true, Default::default());
        let table = super::super::table(&tables);
        let cfg = super::super::read(&doc, &table);
        assert_eq!(
            super::super::unread(&doc, &table, &cfg.read),
            Vec::<String>::new()
        );
        assert_eq!(cfg.bgp_routing.processes.len(), 2);
    }
}
