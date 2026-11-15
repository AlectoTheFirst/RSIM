//! Core types of the rsim network digital twin (section 4 of the build brief).

pub mod addr;
pub mod branch;
pub mod context;
pub mod delay;
pub mod field;
pub mod flow_state;
pub mod function;
pub mod header;
pub mod id;
pub mod outcome;
pub mod packet_set;
pub mod predicate;
pub mod prefix_table;
pub mod provenance;
pub mod trace;

pub use addr::{Mac, Prefix};
pub use branch::{Alternative, Branch, FloodCopy, RateCondition};
pub use context::{Attr, Context, ContextAttr, NeighbourTarget, NextHop, SessionMatch};
pub use delay::{Delay, DelayGap};
pub use field::{FieldValue, Tri};
pub use flow_state::{FlowState, Session};
pub use function::{Dependency, FunctionKind, NetFunction};
pub use header::{Encap, FlowKey, Fragment, Header, HeaderField, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
pub use id::{
    ApplicationId, BridgeDomainId, DeviceId, EndpointId, FunctionId, InterfaceId, ObjectId, PortId,
    VrfId, ZoneId,
};
pub use outcome::{Destination, Outcome, Reason, ReasonCode, Verdict, VerdictKind};
pub use packet_set::{AddrField, PacketPair, PacketSet, PrefixPartition, Rewrite, Split, Uniform};
pub use predicate::{
    AddrCond, FlagsCond, FragmentCond, MacCond, Match, MatchClass, OpenField, PortCond, RangeCond,
    RulePredicate, ValueCond,
};
pub use prefix_table::{PrefixTable, TriePrefixTable};
pub use provenance::SourceSpan;
pub use trace::{QosView, RibGuardFlag, TraceStep};
