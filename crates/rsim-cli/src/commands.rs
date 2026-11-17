//! The commands that `rsim` and `rsim-mcp` share. Each command takes a
//! twin and gives a JSON output object or a query error.

use crate::json::FromEngine;
use std::collections::BTreeMap;

use rsim_engine::{Answer, Executor, Twin};

use crate::error::{ErrorCode, QueryError};
use crate::json::{
    AnswerJson, AttachmentJson, DeviceJson, DevicesOut, EdgeInterfaceJson, EndpointJson,
    FunctionJson, PathAnswerOut, SpanJson, StepOut, TopologiesOut, VERSION, snake,
};
use crate::json::{QueryJson, SetAnswerOut};
use crate::query::QueryInput;
use crate::set_query::SetInput;

/// The prefix of a topology name that names the data folder of a store.
pub const STORE_PREFIX: &str = "store:";

/// The twin of a topology: a built-in topology, or `store:<folder>` for the
/// newest snapshot of the store in the data folder of `rsim-collect`. The
/// folder holds the store in `store` and the store keys in `keys`.
pub fn load(topology: &str) -> Result<Twin, QueryError> {
    if let Some(folder) = topology.strip_prefix(STORE_PREFIX) {
        return load_store(folder);
    }
    rsim_topologies::builtin(topology).ok_or_else(|| {
        QueryError::new(
            ErrorCode::UnknownTopology,
            format!(
                "{topology} is not a built-in topology; the names are {}",
                rsim_topologies::names().join(", ")
            ),
        )
    })
}

/// The twin of the newest snapshot of a store. It reads the store and
/// writes nothing.
pub fn load_store(folder: &str) -> Result<Twin, QueryError> {
    let err = |d: String| QueryError::new(ErrorCode::Store, d);
    let folder = match (folder.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => folder.to_string(),
    };
    let keys = std::fs::read_to_string(format!("{folder}/keys"))
        .map_err(|e| err(format!("{folder}/keys: {e}")))?;
    let keys = rsim_store::Keys::from_hex(&keys).map_err(|e| err(e.to_string()))?;
    let store = rsim_store::Store::open_read(format!("{folder}/store"), keys)
        .map_err(|e| err(e.to_string()))?;
    let snap = store
        .latest()
        .map_err(|e| err(e.to_string()))?
        .ok_or_else(|| err(format!("{folder} has no snapshot")))?;
    let estate = rsim_ingest::estate::build(&store, &snap).map_err(|e| err(e.to_string()))?;
    estate.builder.build().map_err(|errors| {
        let text: Vec<String> = errors.iter().map(ToString::to_string).collect();
        err(format!("the twin does not build: {}", text.join("; ")))
    })
}

/// The names of the built-in topologies, in a fixed order.
pub fn topology_names() -> Vec<&'static str> {
    rsim_topologies::names()
}

pub fn topologies() -> TopologiesOut {
    TopologiesOut {
        rsim_json: VERSION,
        kind: "topologies".into(),
        topologies: rsim_topologies::names()
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

pub fn devices(topology: &str, twin: &Twin) -> DevicesOut {
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

pub fn path(input: &QueryInput, twin: &Twin) -> Result<PathAnswerOut, QueryError> {
    let answer = run(input, twin)?;
    Ok(PathAnswerOut {
        rsim_json: VERSION,
        kind: "path_answer".into(),
        topology: input.topology.clone(),
        query: input.echo(),
        answer: AnswerJson::new(&answer),
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

pub fn set(input: &SetInput, twin: &Twin) -> Result<SetAnswerOut, QueryError> {
    let answer = run_set(input, twin)?;
    Ok(SetAnswerOut {
        rsim_json: VERSION,
        kind: "set_answer".into(),
        topology: input.topology.clone(),
        query: input.echo(),
        answer: AnswerJson::new(&answer),
    })
}

/// Runs the query again and gives one trace step of the answer.
pub fn explain(input: &QueryInput, at: StepRef, twin: &Twin) -> Result<StepOut, QueryError> {
    let forward = run(input, twin)?;
    step_of(
        &forward,
        at,
        &input.topology,
        QueryJson::Path(Box::new(input.echo())),
    )
}

/// Runs the set query again and gives one trace step of the answer.
pub fn explain_set(input: &SetInput, at: StepRef, twin: &Twin) -> Result<StepOut, QueryError> {
    let forward = run_set(input, twin)?;
    step_of(
        &forward,
        at,
        &input.topology,
        QueryJson::Set(Box::new(input.echo())),
    )
}

fn step_of(
    forward: &Answer,
    at: StepRef,
    topology: &str,
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
        query,
        reply_of: at.reply_of,
        branch: at.branch,
        step: at.step,
        trace_step: crate::json::trace_step_json(at.step, step),
    })
}
