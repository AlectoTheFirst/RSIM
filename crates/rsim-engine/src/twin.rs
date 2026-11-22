//! The compiled twin: function instances and endpoints, immutable after the
//! build. The build validates the composition.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use rsim_core::{
    ContextAttr, DdError, DeviceId, EndpointId, FunctionId, InterfaceId, NetFunction, Prefix,
    PrefixTable, Reason, ReasonCode, SetArena, SetBase, SourceSpan, TriePrefixTable,
};

use crate::answer::{Ingress, IngressBasis};

/// A host that sends and receives packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub id: EndpointId,
    pub addresses: Vec<IpAddr>,
}

/// The kind of an attachment record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttachmentKind {
    /// The collected client attachment of a controller.
    Client,
    /// A neighbour entry that names a host.
    Neighbour,
}

/// A record that an address is attached at an interface of a device.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttachmentRecord {
    pub address: IpAddr,
    pub device: DeviceId,
    pub interface: InterfaceId,
    pub kind: AttachmentKind,
    /// The host that the record names.
    pub host: String,
    pub provenance: Vec<SourceSpan>,
}

/// A candidate ingress for the source addresses of a prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub device: DeviceId,
    pub interface: InterfaceId,
    pub function: FunctionId,
    /// True for an attachment record, false for a connected network.
    pub record: bool,
    pub spans: Vec<SourceSpan>,
}

/// The ingress of the source addresses of a prefix. Attachment records
/// come before connected networks. Exactly one interface gives the ingress.
/// No candidate, or 2 or more, give no ingress, and the reason names the
/// candidates.
pub fn ingress_of(p: &Prefix, cands: &[Candidate]) -> Ingress {
    let records: Vec<&Candidate> = cands.iter().filter(|c| c.record).collect();
    let chosen: Vec<&Candidate> = if records.is_empty() {
        cands.iter().collect()
    } else {
        records
    };
    match chosen.as_slice() {
        [one] => Ingress::Found {
            device: one.device.clone(),
            interface: one.interface.clone(),
            function: one.function.clone(),
            basis: if one.record {
                IngressBasis::Attachment(one.spans.clone())
            } else {
                IngressBasis::ConnectedNetwork {
                    network: *p,
                    spans: one.spans.clone(),
                }
            },
        },
        many => {
            let names: Vec<String> = many
                .iter()
                .map(|c| format!("{}/{}", c.device, c.interface))
                .collect();
            Ingress::NotFound(Reason::new(
                ReasonCode::AmbiguousOwner,
                format!(
                    "no ingress, source {p} has {} ingress candidates: {}",
                    names.len(),
                    names.join(", ")
                ),
            ))
        }
    }
}

/// An interface at the edge of the network, with its connected networks.
/// A match of a source address on a connected network of an edge interface
/// is an ingress with a host that is not confirmed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeInterface {
    pub device: DeviceId,
    pub interface: InterfaceId,
    pub networks: Vec<Prefix>,
    pub provenance: Vec<SourceSpan>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BuildError {
    DuplicateFunction(FunctionId),
    DuplicateEndpoint(EndpointId),
    UnknownSuccessor {
        from: FunctionId,
        to: FunctionId,
    },
    /// A record names an interface that has no ingress function.
    UnknownInterface {
        device: DeviceId,
        interface: InterfaceId,
    },
    /// Two ingress functions are on one interface.
    DuplicateIngress {
        device: DeviceId,
        interface: InterfaceId,
    },
    /// The frozen base of the packet sets does not build.
    SetBase(String),
    /// A function requires a context attribute that a path to it does not
    /// provide. `via` is a predecessor on such a path, or `None` if the
    /// function has no predecessor.
    MissingContext {
        function: FunctionId,
        attribute: ContextAttr,
        via: Option<FunctionId>,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::DuplicateFunction(id) => write!(f, "function {id} is defined twice"),
            BuildError::DuplicateEndpoint(id) => write!(f, "endpoint {id} is defined twice"),
            BuildError::UnknownSuccessor { from, to } => {
                write!(f, "{from} forwards to {to}, which does not exist")
            }
            BuildError::UnknownInterface { device, interface } => {
                write!(f, "{device}/{interface} has no ingress function")
            }
            BuildError::DuplicateIngress { device, interface } => {
                write!(f, "{device}/{interface} has two ingress functions")
            }
            BuildError::SetBase(e) => write!(f, "the packet set base does not build: {e}"),
            BuildError::MissingContext {
                function,
                attribute,
                via,
            } => match via {
                Some(v) => write!(
                    f,
                    "{function} requires {attribute:?}, and the path through {v} does not provide it"
                ),
                None => write!(
                    f,
                    "{function} requires {attribute:?}, and it has no predecessor"
                ),
            },
        }
    }
}

impl std::error::Error for BuildError {}

#[derive(Default)]
pub struct TwinBuilder {
    functions: Vec<Arc<dyn NetFunction>>,
    endpoints: Vec<Endpoint>,
    attachments: Vec<AttachmentRecord>,
    edges: Vec<EdgeInterface>,
}

impl TwinBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, f: impl NetFunction + 'static) -> &mut Self {
        self.functions.push(Arc::new(f));
        self
    }

    pub fn add_arc(&mut self, f: Arc<dyn NetFunction>) -> &mut Self {
        self.functions.push(f);
        self
    }

    pub fn endpoint(&mut self, e: Endpoint) -> &mut Self {
        self.endpoints.push(e);
        self
    }

    pub fn attachment(&mut self, a: AttachmentRecord) -> &mut Self {
        self.attachments.push(a);
        self
    }

    pub fn edge_interface(&mut self, e: EdgeInterface) -> &mut Self {
        self.edges.push(e);
        self
    }

    /// Builds the twin. All errors are reported, in a fixed order.
    pub fn build(self) -> Result<Twin, Vec<BuildError>> {
        let mut errors = Vec::new();
        let mut functions: BTreeMap<FunctionId, Arc<dyn NetFunction>> = BTreeMap::new();
        for f in self.functions {
            let id = f.id().clone();
            if functions.insert(id.clone(), f).is_some() {
                errors.push(BuildError::DuplicateFunction(id));
            }
        }
        let mut ingress: BTreeMap<(DeviceId, InterfaceId), FunctionId> = BTreeMap::new();
        for (id, f) in &functions {
            if let (Some(d), Some(i)) = (f.device(), f.ingress_interface()) {
                let k = (d.clone(), i.clone());
                if ingress.insert(k, id.clone()).is_some() {
                    errors.push(BuildError::DuplicateIngress {
                        device: d.clone(),
                        interface: i.clone(),
                    });
                }
            }
        }
        let named = self
            .attachments
            .iter()
            .map(|a| (&a.device, &a.interface))
            .chain(self.edges.iter().map(|e| (&e.device, &e.interface)));
        for (d, i) in named {
            if !ingress.contains_key(&(d.clone(), i.clone())) {
                errors.push(BuildError::UnknownInterface {
                    device: d.clone(),
                    interface: i.clone(),
                });
            }
        }
        let mut endpoints = BTreeMap::new();
        for e in self.endpoints {
            let id = e.id.clone();
            if endpoints.insert(id.clone(), e).is_some() {
                errors.push(BuildError::DuplicateEndpoint(id));
            }
        }
        let mut successors: BTreeMap<FunctionId, Vec<FunctionId>> = BTreeMap::new();
        for (id, f) in &functions {
            let mut s = f.successors();
            s.sort();
            s.dedup();
            for to in &s {
                if !functions.contains_key(to) {
                    errors.push(BuildError::UnknownSuccessor {
                        from: id.clone(),
                        to: to.clone(),
                    });
                }
            }
            s.retain(|to| functions.contains_key(to));
            successors.insert(id.clone(), s);
        }
        errors.extend(validate_composition(&functions, &successors));
        let base = match SetBase::build(functions.values().flat_map(|f| f.predicates())) {
            Ok(b) => Some(b),
            Err(e) => {
                errors.push(BuildError::SetBase(e.to_string()));
                None
            }
        };
        if let (true, Some(base)) = (errors.is_empty(), base) {
            let mut attachments = self.attachments;
            attachments.sort();
            attachments.dedup();
            let mut edges = self.edges;
            edges.sort();
            edges.dedup();
            let ingress_table = ingress_table(&attachments, &edges, &ingress);
            Ok(Twin {
                ingress_table,
                functions,
                endpoints,
                ingress,
                attachments,
                edges,
                base,
            })
        } else {
            errors.sort();
            errors.dedup();
            Err(errors)
        }
    }
}

/// A must-analysis over the function graph: the attributes that are set on
/// every path to a function.
fn validate_composition(
    functions: &BTreeMap<FunctionId, Arc<dyn NetFunction>>,
    successors: &BTreeMap<FunctionId, Vec<FunctionId>>,
) -> Vec<BuildError> {
    let mut preds: BTreeMap<&FunctionId, Vec<&FunctionId>> = BTreeMap::new();
    for (from, tos) in successors {
        for to in tos {
            preds.entry(to).or_default().push(from);
        }
    }
    let all: BTreeSet<ContextAttr> = ALL_ATTRS.iter().copied().collect();
    let mut avail: BTreeMap<&FunctionId, BTreeSet<ContextAttr>> = functions
        .keys()
        .map(|id| {
            let start = if preds.contains_key(id) {
                all.clone()
            } else {
                BTreeSet::new()
            };
            (id, start)
        })
        .collect();
    let out_of = |id: &FunctionId, input: &BTreeSet<ContextAttr>| -> BTreeSet<ContextAttr> {
        let f = &functions[id];
        let mut o: BTreeSet<ContextAttr> = if f.enters_device() {
            input
                .iter()
                .copied()
                .filter(|a| ContextAttr::CROSS_DEVICE.contains(a))
                .collect()
        } else {
            input.clone()
        };
        o.extend(f.provides());
        o
    };
    loop {
        let mut changed = false;
        for id in functions.keys() {
            let Some(ps) = preds.get(id) else { continue };
            let mut acc: Option<BTreeSet<ContextAttr>> = None;
            for p in ps {
                let o = out_of(p, &avail[p]);
                acc = Some(match acc {
                    None => o,
                    Some(a) => a.intersection(&o).copied().collect(),
                });
            }
            let acc = acc.unwrap_or_default();
            if acc != avail[id] {
                avail.insert(id, acc);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut errors = Vec::new();
    for (id, f) in functions {
        for attr in f.requires() {
            if avail[id].contains(&attr) {
                continue;
            }
            let via = preds.get(id).and_then(|ps| {
                ps.iter()
                    .find(|p| !out_of(p, &avail[*p]).contains(&attr))
                    .map(|p| (*p).clone())
            });
            errors.push(BuildError::MissingContext {
                function: id.clone(),
                attribute: attr,
                via,
            });
        }
    }
    errors
}

const ALL_ATTRS: [ContextAttr; 15] = [
    ContextAttr::Device,
    ContextAttr::IngressInterface,
    ContextAttr::Vrf,
    ContextAttr::SrcZone,
    ContextAttr::DstZone,
    ContextAttr::Session,
    ContextAttr::EgressInterface,
    ContextAttr::NextHop,
    ContextAttr::NeighbourTarget,
    ContextAttr::Application,
    ContextAttr::TrafficClass,
    ContextAttr::DropPrecedence,
    ContextAttr::Queue,
    ContextAttr::IngressPort,
    ContextAttr::BridgeDomain,
];

/// The compiled twin of one version. It is immutable, so queries can run in
/// parallel on many threads.
pub struct Twin {
    functions: BTreeMap<FunctionId, Arc<dyn NetFunction>>,
    endpoints: BTreeMap<EndpointId, Endpoint>,
    ingress: BTreeMap<(DeviceId, InterfaceId), FunctionId>,
    attachments: Vec<AttachmentRecord>,
    edges: Vec<EdgeInterface>,
    base: Arc<SetBase>,
    ingress_table: TriePrefixTable<Vec<Candidate>>,
}

/// The candidates of each host address of a record and of each connected
/// network of an edge interface. The candidates of one interface join.
fn ingress_table(
    attachments: &[AttachmentRecord],
    edges: &[EdgeInterface],
    ingress: &BTreeMap<(DeviceId, InterfaceId), FunctionId>,
) -> TriePrefixTable<Vec<Candidate>> {
    let mut t: TriePrefixTable<Vec<Candidate>> = TriePrefixTable::new();
    let mut add = |p: Prefix,
                   device: &DeviceId,
                   interface: &InterfaceId,
                   record: bool,
                   spans: &[SourceSpan]| {
        let Some(f) = ingress.get(&(device.clone(), interface.clone())) else {
            return;
        };
        let mut v = t.get(&p).cloned().unwrap_or_default();
        match v
            .iter_mut()
            .find(|c| c.device == *device && c.interface == *interface && c.record == record)
        {
            Some(c) => c.spans.extend(spans.iter().cloned()),
            None => v.push(Candidate {
                device: device.clone(),
                interface: interface.clone(),
                function: f.clone(),
                record,
                spans: spans.to_vec(),
            }),
        }
        t.insert(p, v);
    };
    for a in attachments {
        add(
            Prefix::host(a.address),
            &a.device,
            &a.interface,
            true,
            &a.provenance,
        );
    }
    for e in edges {
        for n in &e.networks {
            add(*n, &e.device, &e.interface, false, &e.provenance);
        }
    }
    t
}

impl Twin {
    /// The ingress candidates by source prefix.
    pub fn ingress_table(&self) -> &TriePrefixTable<Vec<Candidate>> {
        &self.ingress_table
    }

    /// The ingress function of an interface.
    pub fn ingress(&self, device: &DeviceId, interface: &InterfaceId) -> Option<&FunctionId> {
        self.ingress.get(&(device.clone(), interface.clone()))
    }

    /// The attachment records, in a fixed order.
    pub fn attachments(&self) -> &[AttachmentRecord] {
        &self.attachments
    }

    /// The edge interfaces, in a fixed order.
    pub fn edge_interfaces(&self) -> &[EdgeInterface] {
        &self.edges
    }

    /// The frozen base of the packet sets.
    pub fn set_base(&self) -> &Arc<SetBase> {
        &self.base
    }

    /// A new arena for the packet sets of one query.
    pub fn arena(&self, budget: Option<usize>) -> Arc<SetArena> {
        SetArena::new(&self.base, budget)
    }

    /// A new arena for one run of a query, with the table room of the
    /// earlier runs on this twin.
    pub fn run_arena(&self, budget: Option<usize>) -> Arc<SetArena> {
        SetArena::for_run(&self.base, budget)
    }

    /// The fault of the frozen base, if its validation fails.
    pub fn validate(&self) -> Result<(), DdError> {
        self.base.validate()
    }

    pub fn function(&self, id: &FunctionId) -> Option<&Arc<dyn NetFunction>> {
        self.functions.get(id)
    }

    pub fn endpoint(&self, id: &EndpointId) -> Option<&Endpoint> {
        self.endpoints.get(id)
    }

    pub fn functions(&self) -> impl Iterator<Item = &Arc<dyn NetFunction>> {
        self.functions.values()
    }

    /// The device identifiers, in identifier order.
    pub fn devices(&self) -> Vec<DeviceId> {
        let devices: BTreeSet<&DeviceId> =
            self.functions.values().filter_map(|f| f.device()).collect();
        devices.into_iter().cloned().collect()
    }

    /// The endpoints, in identifier order.
    pub fn endpoints(&self) -> impl Iterator<Item = &Endpoint> {
        self.endpoints.values()
    }

    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    pub fn device_count(&self) -> usize {
        let devices: BTreeSet<_> = self
            .functions
            .values()
            .filter_map(|f| f.device().cloned())
            .collect();
        devices.len()
    }
}

impl fmt::Debug for Twin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Twin")
            .field("functions", &self.functions.len())
            .field("endpoints", &self.endpoints.len())
            .field("attachments", &self.attachments.len())
            .finish()
    }
}
