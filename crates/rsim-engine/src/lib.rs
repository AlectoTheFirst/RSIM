//! The twin build, the concrete-mode executor, verdict aggregation and the
//! return path of rsim.

pub mod answer;
pub mod exec;
pub mod twin;

pub use answer::{Answer, BranchView, ExecEdge, ExecNode, Reply, ReplyResult, Summary};
pub use exec::{ExecError, ExecOptions, Executor, Query, check_contract, check_partition};
pub use twin::{BuildError, Endpoint, Twin, TwinBuilder};
