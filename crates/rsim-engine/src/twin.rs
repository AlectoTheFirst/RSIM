//! The compiled twin: function instances and endpoints, immutable after the
//! build. The build validates the composition.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use rsim_core::{ContextAttr, EndpointId, FunctionId, NetFunction};

/// A host that sends and receives packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub id: EndpointId,
    pub addresses: Vec<IpAddr>,
    /// The ingress function where packets from the endpoint enter the network.
    pub attachment: FunctionId,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BuildError {
    DuplicateFunction(FunctionId),
    DuplicateEndpoint(EndpointId),
    UnknownSuccessor {
        from: FunctionId,
        to: FunctionId,
    },
    UnknownAttachment {
        endpoint: EndpointId,
        function: FunctionId,
    },
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
            BuildError::UnknownAttachment { endpoint, function } => {
                write!(
                    f,
                    "endpoint {endpoint} attaches to {function}, which does not exist"
                )
            }
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
        let mut endpoints = BTreeMap::new();
        for e in self.endpoints {
            if !functions.contains_key(&e.attachment) {
                errors.push(BuildError::UnknownAttachment {
                    endpoint: e.id.clone(),
                    function: e.attachment.clone(),
                });
            }
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
        if errors.is_empty() {
            Ok(Twin {
                functions,
                endpoints,
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
}

impl Twin {
    pub fn function(&self, id: &FunctionId) -> Option<&Arc<dyn NetFunction>> {
        self.functions.get(id)
    }

    pub fn endpoint(&self, id: &EndpointId) -> Option<&Endpoint> {
        self.endpoints.get(id)
    }

    pub fn functions(&self) -> impl Iterator<Item = &Arc<dyn NetFunction>> {
        self.functions.values()
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
            .finish()
    }
}
