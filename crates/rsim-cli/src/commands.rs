//! The commands that `rsim` and `rsim-mcp` share. Each command takes a
//! twin and gives a JSON output object or a query error.

use crate::json::FromEngine;
use std::collections::BTreeMap;

use rsim_contract::twin::TwinJson;
use rsim_engine::{Answer, Executor, Twin};

use crate::error::{ErrorCode, QueryError};
use crate::json::{
    AnswerJson, AttachmentJson, DeviceJson, DevicesOut, EdgeInterfaceJson, EndpointJson,
    FunctionJson, PathAnswerOut, SpanJson, StepOut, VERSION, snake,
};
use crate::json::{QueryJson, SetAnswerOut};
use crate::query::QueryInput;
use crate::set_query::SetInput;

/// The prefix of a topology name that names the data folder of a store.
pub const STORE_PREFIX: &str = "store:";

/// A twin with its identity.
pub struct Loaded {
    pub twin: Twin,
    pub identity: TwinJson,
    /// The coverage report of each device of a store twin; empty for a
    /// hand-built topology of the tests.
    pub coverage: BTreeMap<String, rsim_ingest::coverage::Coverage>,
    /// The BGP peer facts of each device of a store twin; empty for a
    /// hand-built topology of the tests.
    pub bgp: BTreeMap<String, Vec<rsim_ingest::links::BgpPeerFact>>,
    /// The facts of each device of a store twin, by twin device; empty for
    /// a hand-built topology of the tests.
    pub facts: BTreeMap<String, rsim_ingest::facts::DeviceFacts>,
    /// The LLDP and CDP records of a store twin that name a neighbour with
    /// no device in the twin; empty for a hand-built topology of the tests.
    pub seen: Vec<rsim_ingest::links::SeenNeighbour>,
    /// The columns of the tables of the twin, built when a request first
    /// names a table.
    pub tables: crate::tables::TableCache,
    /// The store and the snapshot of a store twin, for the text of its
    /// source lines; none for a hand-built topology of the tests.
    pub source: Option<crate::sources::SourceStore>,
}

impl std::ops::Deref for Loaded {
    type Target = Twin;
    fn deref(&self) -> &Twin {
        &self.twin
    }
}

/// The twin of `store:<folder>`: the newest snapshot of the store in the
/// data folder of `rsim-collect`. The folder holds the store in `store` and
/// the store keys in `keys`.
pub fn load(topology: &str) -> Result<Loaded, QueryError> {
    if let Some(folder) = topology.strip_prefix(STORE_PREFIX) {
        return load_store(folder);
    }
    fixture(topology)
}

/// A twin that is not `store:<folder>`: none in the product.
#[cfg(not(feature = "test-fixtures"))]
fn fixture(topology: &str) -> Result<Loaded, QueryError> {
    Err(QueryError::new(
        ErrorCode::UnknownTopology,
        format!("{topology} is not a twin; a twin comes from a store: {STORE_PREFIX}<data folder>"),
    ))
}

/// A hand-built topology of the tests by its name.
#[cfg(feature = "test-fixtures")]
fn fixture(topology: &str) -> Result<Loaded, QueryError> {
    let unknown = || {
        QueryError::new(
            ErrorCode::UnknownTopology,
            format!(
                "{topology} is not a twin; the hand-built topologies of the tests are {}",
                rsim_topologies::names().join(", ")
            ),
        )
    };
    let twin = rsim_topologies::builtin(topology).ok_or_else(unknown)?;
    let identity = TwinJson::builtin(topology).map_err(|_| unknown())?;
    Ok(Loaded {
        twin,
        identity,
        coverage: BTreeMap::new(),
        bgp: BTreeMap::new(),
        facts: BTreeMap::new(),
        seen: Vec::new(),
        tables: Default::default(),
        source: None,
    })
}

/// The twin of the newest snapshot of a store. It reads the store and
/// writes nothing.
pub fn load_store(folder: &str) -> Result<Loaded, QueryError> {
    load_store_at(folder, None)
}

/// The store in a data folder, opened to read: the folder holds the store
/// in `store` and the store keys in `keys`.
pub fn open_store(folder: &str) -> Result<rsim_store::Store, QueryError> {
    let err = |d: String| QueryError::new(ErrorCode::Store, d);
    let folder = home_path(folder);
    let keys = std::fs::read_to_string(format!("{folder}/keys"))
        .map_err(|e| err(format!("{folder}/keys: {e}")))?;
    let keys = rsim_store::Keys::from_hex(&keys).map_err(|e| err(e.to_string()))?;
    rsim_store::Store::open_read(format!("{folder}/store"), keys).map_err(|e| err(e.to_string()))
}

/// A data folder with `~/` replaced by the home folder.
fn home_path(folder: &str) -> String {
    match (folder.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => folder.to_string(),
    }
}

/// True for a data folder with no store keys and no store: the collector
/// has not written to it yet.
pub fn new_data_folder(folder: &str) -> bool {
    let folder = std::path::PathBuf::from(home_path(folder));
    !folder.join("keys").exists() && !folder.join("store").exists()
}

/// The twin of the snapshot `cycle` of a store, or of its newest snapshot
/// with `None`. It reads the store and writes nothing.
pub fn load_store_at(folder: &str, cycle: Option<u64>) -> Result<Loaded, QueryError> {
    let err = |d: String| QueryError::new(ErrorCode::Store, d);
    let store = open_store(folder)?;
    let snap = match cycle {
        Some(c) => store.snapshot(c).map_err(|e| err(e.to_string()))?,
        None => store
            .latest()
            .map_err(|e| err(e.to_string()))?
            .ok_or_else(|| err(format!("{folder} has no snapshot")))?,
    };
    let estate = rsim_ingest::estate::build(&store, &snap).map_err(|e| err(e.to_string()))?;
    let coverage = estate.coverage.clone();
    let bgp = estate.bgp.clone();
    let facts = estate.facts.clone();
    let seen = estate.seen.clone();
    let twin = estate.builder.build().map_err(|errors| {
        let text: Vec<String> = errors.iter().map(ToString::to_string).collect();
        err(format!("the twin does not build: {}", text.join("; ")))
    })?;
    Ok(Loaded {
        twin,
        identity: TwinJson::snapshot(snap.manifest.time),
        coverage,
        bgp,
        facts,
        seen,
        tables: Default::default(),
        source: Some(crate::sources::SourceStore::new(store, snap)),
    })
}

/// The names of the hand-built topologies of the tests, in a fixed order;
/// none in the product.
pub fn topology_names() -> Vec<&'static str> {
    #[cfg(feature = "test-fixtures")]
    return rsim_topologies::names();
    #[cfg(not(feature = "test-fixtures"))]
    Vec::new()
}

pub fn devices(topology: &str, twin: &Loaded) -> DevicesOut {
    let mut by_device: BTreeMap<String, Vec<FunctionJson>> = twin
        .devices()
        .iter()
        .map(|d| (d.to_string(), Vec::new()))
        .collect();
    for f in twin.functions() {
        if let Some(d) = f.device() {
            by_device
                .entry(d.to_string())
                .or_default()
                .push(FunctionJson {
                    function: f.id().to_string(),
                    kind: snake(&f.kind()),
                });
        }
    }
    DevicesOut {
        rsim_json: VERSION,
        kind: "devices".into(),
        topology: topology.to_string(),
        twin: twin.identity.clone(),
        devices: twin
            .devices()
            .iter()
            .map(|d| DeviceJson {
                device: d.to_string(),
                functions: by_device.remove(d.as_str()).unwrap_or_default(),
            })
            .collect(),
        endpoints: twin
            .endpoints()
            .map(|e| EndpointJson {
                endpoint: e.id.to_string(),
                addresses: e.addresses.iter().map(|a| a.to_string()).collect(),
            })
            .collect(),
        attachments: twin
            .attachments()
            .iter()
            .map(|a| AttachmentJson {
                address: a.address.to_string(),
                device: a.device.to_string(),
                interface: a.interface.to_string(),
                kind: snake(&a.kind),
                host: a.host.clone(),
                provenance: a.provenance.iter().map(SpanJson::new).collect(),
            })
            .collect(),
        edge_interfaces: twin
            .edge_interfaces()
            .iter()
            .map(|e| EdgeInterfaceJson {
                device: e.device.to_string(),
                interface: e.interface.to_string(),
                networks: e.networks.iter().map(|n| n.to_string()).collect(),
                provenance: e.provenance.iter().map(SpanJson::new).collect(),
            })
            .collect(),
    }
}

/// Runs the query on the twin and gives the engine answer.
pub fn run(input: &QueryInput, twin: &Twin) -> Result<Answer, QueryError> {
    let q = input.to_query(twin)?;
    Executor::new(twin)
        .run(&q)
        .map_err(|e| crate::error::from_exec(&e))
}

pub fn path(input: &QueryInput, twin: &Loaded) -> Result<PathAnswerOut, QueryError> {
    let answer = run(input, twin)?;
    Ok(PathAnswerOut {
        rsim_json: VERSION,
        kind: "path_answer".into(),
        topology: input.topology.clone(),
        twin: twin.identity.clone(),
        query: input.echo(),
        notes: input.notes(),
        answer: AnswerJson::new(&answer),
    })
}

/// The answer of a path query in a brief form, with no description of the
/// packet sets of the trace steps.
pub fn path_brief(
    input: &QueryInput,
    twin: &Loaded,
    form: rsim_contract::args::Form,
) -> Result<rsim_contract::json::PathBriefOut, QueryError> {
    let answer = run(input, twin)?;
    Ok(rsim_contract::json::PathBriefOut {
        rsim_json: VERSION,
        kind: "path_brief".into(),
        topology: input.topology.clone(),
        twin: twin.identity.clone(),
        form,
        query: input.echo(),
        notes: input.notes(),
        answer: crate::json::brief_json(&answer, form),
    })
}

/// The answer of a set query in a brief form.
pub fn set_brief(
    input: &SetInput,
    twin: &Loaded,
    form: rsim_contract::args::Form,
) -> Result<rsim_contract::json::SetBriefOut, QueryError> {
    let answer = run_set(input, twin)?;
    Ok(rsim_contract::json::SetBriefOut {
        rsim_json: VERSION,
        kind: "set_brief".into(),
        topology: input.topology.clone(),
        twin: twin.identity.clone(),
        form,
        query: input.echo(),
        answer: crate::json::brief_json(&answer, form),
    })
}

/// The indexes of one trace step. With `reply_of`, `branch` and `step` are
/// indexes in the reply of that forward branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepRef {
    pub reply_of: Option<usize>,
    pub branch: usize,
    pub step: usize,
}

/// Runs the set query on the twin and gives the engine answer.
pub fn run_set(input: &SetInput, twin: &Twin) -> Result<Answer, QueryError> {
    let q = input.to_query(twin)?;
    Executor::new(twin)
        .run(&q)
        .map_err(|e| crate::error::from_exec(&e))
}

pub fn set(input: &SetInput, twin: &Loaded) -> Result<SetAnswerOut, QueryError> {
    let answer = run_set(input, twin)?;
    Ok(SetAnswerOut {
        rsim_json: VERSION,
        kind: "set_answer".into(),
        topology: input.topology.clone(),
        twin: twin.identity.clone(),
        query: input.echo(),
        answer: AnswerJson::new(&answer),
    })
}

/// Runs the query again and gives one trace step of the answer.
pub fn explain(input: &QueryInput, at: StepRef, twin: &Loaded) -> Result<StepOut, QueryError> {
    let forward = run(input, twin)?;
    step_of(
        &forward,
        at,
        &input.topology,
        &twin.identity,
        QueryJson::Path(Box::new(input.echo())),
    )
}

/// Runs the set query again and gives one trace step of the answer.
pub fn explain_set(input: &SetInput, at: StepRef, twin: &Loaded) -> Result<StepOut, QueryError> {
    let forward = run_set(input, twin)?;
    step_of(
        &forward,
        at,
        &input.topology,
        &twin.identity,
        QueryJson::Set(Box::new(input.echo())),
    )
}

fn step_of(
    forward: &Answer,
    at: StepRef,
    topology: &str,
    twin: &TwinJson,
    query: QueryJson,
) -> Result<StepOut, QueryError> {
    let no_such = |d: String| QueryError::new(ErrorCode::NoSuchStep, d);
    let answer: &Answer = match at.reply_of {
        None => forward,
        Some(n) => forward.reply_of(n).ok_or_else(|| {
            no_such(format!(
                "forward branch {n} has no reply that ran; the answer has {} forward branches",
                forward.branches().len()
            ))
        })?,
    };
    let branches = answer.branches();
    let branch = branches.get(at.branch).ok_or_else(|| {
        no_such(format!(
            "branch {} is not in the answer; the answer has {} branches",
            at.branch,
            branches.len()
        ))
    })?;
    let step = branch.steps.get(at.step).ok_or_else(|| {
        no_such(format!(
            "step {} is not in branch {}; the branch has {} steps",
            at.step,
            at.branch,
            branch.steps.len()
        ))
    })?;
    Ok(StepOut {
        rsim_json: VERSION,
        kind: "step".into(),
        topology: topology.to_string(),
        twin: twin.clone(),
        query,
        reply_of: at.reply_of,
        branch: at.branch,
        step: at.step,
        trace_step: crate::json::trace_step_json(at.step, step),
        source_lines: None,
    })
}
