//! The commands that `rsim` and `rsim-mcp` share. Each command takes a
//! twin and gives a JSON output object or a query error.

use std::collections::BTreeMap;

use rsim_engine::{Answer, Executor, Twin};

use crate::error::{ErrorCode, QueryError};
use crate::json::{
    AnswerJson, DeviceJson, DevicesOut, EndpointJson, FunctionJson, PathAnswerOut, StepOut,
    TopologiesOut, TraceStepJson, VERSION, snake,
};
use crate::query::QueryInput;

/// The twin of a built-in topology.
pub fn load(topology: &str) -> Result<Twin, QueryError> {
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

/// The names of the built-in topologies, in a fixed order.
pub fn topology_names() -> Vec<&'static str> {
    rsim_topologies::names()
}

pub fn topologies() -> TopologiesOut {
    TopologiesOut {
        rsim_json: VERSION,
        kind: "topologies",
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
        kind: "devices",
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
                attachment: e.attachment.to_string(),
            })
            .collect(),
    }
}

/// Runs the query on the twin and gives the engine answer.
pub fn run(input: &QueryInput, twin: &Twin) -> Result<Answer, QueryError> {
    let q = input.to_query(twin)?;
    Executor::new(twin)
        .run(&q)
        .map_err(|e| QueryError::from_exec(&e))
}

pub fn path(input: &QueryInput, twin: &Twin) -> Result<PathAnswerOut, QueryError> {
    let answer = run(input, twin)?;
    Ok(PathAnswerOut {
        rsim_json: VERSION,
        kind: "path_answer",
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

/// Runs the query again and gives one trace step of the answer.
pub fn explain(input: &QueryInput, at: StepRef, twin: &Twin) -> Result<StepOut, QueryError> {
    let forward = run(input, twin)?;
    let no_such = |d: String| QueryError::new(ErrorCode::NoSuchStep, d);
    let answer: &Answer = match at.reply_of {
        None => &forward,
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
        kind: "step",
        topology: input.topology.clone(),
        query: input.echo(),
        reply_of: at.reply_of,
        branch: at.branch,
        step: at.step,
        trace_step: TraceStepJson::new(at.step, step),
    })
}
