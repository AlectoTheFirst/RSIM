//! Core types of the rsim network digital twin.

pub mod addr;
pub mod bits;
pub mod branch;
pub mod context;
pub mod delay;
pub mod describe;
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
pub mod set;
pub mod spec;
pub mod trace;

pub use addr::{Mac, Prefix};
pub use branch::{Alternative, Branch, FloodCopy, RateCondition};
pub use context::{Attr, Context, ContextAttr, NeighbourTarget, NextHop, SessionMatch};
pub use delay::{Delay, DelayGap};
pub use describe::{EncapDesc, HEADER_FIELDS, HeaderDesc, Member, Values};
pub use field::{FieldValue, Tri};
pub use flow_state::{FlowState, Session};
pub use function::{Dependency, FunctionKind, NetFunction};
pub use header::{
    DefaultValue, Encap, Fragment, Header, HeaderField, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP,
    PROTO_UDP, UNSTATED_DEFAULTS, Unstated,
};
pub use id::{
    ApplicationId, BridgeDomainId, DeviceId, EndpointId, FunctionId, InterfaceId, ObjectId, PortId,
    VrfId, ZoneId,
};
pub use outcome::{Destination, ExitPoint, Outcome, Reason, ReasonCode, Verdict, VerdictKind};
pub use packet_set::{
    AddrField, Decapsulated, Encapsulated, GroupPart, GroupPartition, PacketPair, PacketSet,
    PrefixPartition, Rewrite, SessionDirection, SessionSplit, Split, Uniform,
};
pub use predicate::{
    AddrCond, FlagsCond, FragmentCond, MacCond, Match, MatchClass, OpenField, PortCond, RangeCond,
    RulePredicate, ValueCond,
};
pub use prefix_table::{PrefixTable, TriePrefixTable, WalkNode};
pub use provenance::SourceSpan;
pub use rsim_dd::DdError;
pub use set::{SetArena, SetBase};
pub use spec::SetSpec;
pub use trace::{QosView, RibGuardFlag, TraceStep};
