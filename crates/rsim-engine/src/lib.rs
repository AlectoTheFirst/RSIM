//! The twin build, the executor, verdict aggregation and the
//! return path of rsim.

pub mod answer;
pub mod exec;
pub mod twin;

pub use answer::{
    Answer, BranchView, End, ExecEdge, ExecNode, Ingress, IngressBasis, Mode, Part, Reply,
    ReplyResult, Run, RunBody, Summary,
};
pub use exec::{ExecError, ExecOptions, Executor, Query, check_contract, check_partition};
pub use twin::{
    AttachmentKind, AttachmentRecord, BuildError, Candidate, EdgeInterface, Endpoint, Twin,
    TwinBuilder, ingress_of,
};
