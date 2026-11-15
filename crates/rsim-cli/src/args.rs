//! The query input from the JSON arguments of an MCP tool.

use serde_json::{Map, Value};

use crate::commands::StepRef;
use crate::error::{ErrorCode, QueryError};
use crate::query::{IcmpType, IngressRef, Protocol, QueryInput, TcpFlag, parse_mac};

/// The names of the query arguments, in the order of the query input.
pub const QUERY_FIELDS: [&str; 19] = [
    "topology",
    "ingress",
    "source.ip",
    "destination.ip",
    "network.iana_number",
    "network.transport",
    "source.port",
    "destination.port",
    "source.mac",
    "destination.mac",
    "network.vlan.id",
    "l2_priority",
    "tcp_flags",
    "icmp_type",
    "icmp_code",
    "dscp",
    "ecn",
    "fragment",
    "reply",
];

/// The names of the arguments that select a trace step.
pub const STEP_FIELDS: [&str; 3] = ["branch", "step", "reply_of"];

fn invalid(detail: String) -> QueryError {
    QueryError::new(ErrorCode::InvalidQuery, detail)
}

/// Checks that each argument name is in `allowed`.
pub fn check_names(args: &Map<String, Value>, allowed: &[&str]) -> Result<(), QueryError> {
    match args.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(invalid(format!("{k} is not an argument of this tool"))),
        None => Ok(()),
    }
}

/// The value of an argument. `null` is the same as an argument that is not
/// given.
fn get<'a>(args: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    args.get(name).filter(|v| !v.is_null())
}

fn required<'a>(args: &'a Map<String, Value>, name: &str) -> Result<&'a Value, QueryError> {
    get(args, name).ok_or_else(|| invalid(format!("{name} is not given")))
}

fn string(v: &Value, name: &str) -> Result<String, QueryError> {
    v.as_str()
        .map(str::to_string)
        .ok_or_else(|| invalid(format!("{name} is not a string")))
}

fn number(v: &Value, name: &str, max: u64) -> Result<u64, QueryError> {
    match v.as_u64() {
        Some(n) if n <= max => Ok(n),
        _ => Err(invalid(format!("{name} is not a number 0 to {max}"))),
    }
}

fn boolean(v: &Value, name: &str) -> Result<bool, QueryError> {
    v.as_bool()
        .ok_or_else(|| invalid(format!("{name} is not true or false")))
}

fn opt<T>(
    args: &Map<String, Value>,
    name: &str,
    f: impl FnOnce(&Value) -> Result<T, QueryError>,
) -> Result<Option<T>, QueryError> {
    get(args, name).map(f).transpose()
}

/// The topology name, the only argument of `list_devices`.
pub fn topology(args: &Map<String, Value>) -> Result<String, QueryError> {
    check_names(args, &["topology"])?;
    string(required(args, "topology")?, "topology")
}

/// The query input from the arguments. Names in `extra` are allowed and
/// are not read.
pub fn query(args: &Map<String, Value>, extra: &[&str]) -> Result<QueryInput, QueryError> {
    let allowed: Vec<&str> = QUERY_FIELDS.iter().chain(extra).copied().collect();
    check_names(args, &allowed)?;
    let addr = |v: &Value, name: &str| {
        let s = string(v, name)?;
        s.parse()
            .map_err(|_| invalid(format!("{name} {s:?} is not an IP address")))
    };
    let n8 = |name: &str, max: u64| opt(args, name, |v| Ok(number(v, name, max)? as u8));
    let n16 = |name: &str, max: u64| opt(args, name, |v| Ok(number(v, name, max)? as u16));
    let mac = |name: &str| {
        opt(args, name, |v| {
            let s = string(v, name)?;
            parse_mac(&s).map_err(invalid)
        })
    };
    Ok(QueryInput {
        topology: string(required(args, "topology")?, "topology")?,
        ingress: opt(args, "ingress", |v| {
            string(v, "ingress")?.parse::<IngressRef>().map_err(invalid)
        })?,
        source_ip: addr(required(args, "source.ip")?, "source.ip")?,
        destination_ip: addr(required(args, "destination.ip")?, "destination.ip")?,
        iana_number: n8("network.iana_number", 255)?,
        transport: opt(args, "network.transport", |v| {
            let s = string(v, "network.transport")?;
            match s.parse::<Protocol>() {
                Ok(p) if p.name().is_some() => Ok(p),
                _ => Err(invalid(format!(
                    "network.transport {s:?} is not tcp, udp, icmp or icmpv6"
                ))),
            }
        })?,
        source_port: n16("source.port", 65535)?,
        destination_port: n16("destination.port", 65535)?,
        source_mac: mac("source.mac")?,
        destination_mac: mac("destination.mac")?,
        vlan_id: n16("network.vlan.id", 4095)?,
        l2_priority: n8("l2_priority", 7)?,
        tcp_flags: opt(args, "tcp_flags", |v| {
            let list = v
                .as_array()
                .ok_or_else(|| invalid("tcp_flags is not a list".to_string()))?;
            list.iter()
                .map(|f| string(f, "a TCP flag")?.parse::<TcpFlag>().map_err(invalid))
                .collect()
        })?,
        icmp_type: opt(args, "icmp_type", |v| match v {
            Value::String(s) => s.parse::<IcmpType>().map_err(invalid),
            v => Ok(IcmpType::Number(number(v, "icmp_type", 255)? as u8)),
        })?,
        icmp_code: n8("icmp_code", 255)?,
        dscp: n8("dscp", 63)?,
        ecn: n8("ecn", 3)?,
        fragment: opt(args, "fragment", |v| {
            string(v, "fragment")?.parse().map_err(invalid)
        })?,
        reply: opt(args, "reply", |v| boolean(v, "reply"))?,
    })
}

/// The query input and the indexes of a trace step.
pub fn step(args: &Map<String, Value>) -> Result<(QueryInput, StepRef), QueryError> {
    let input = query(args, &STEP_FIELDS)?;
    let index = |v: &Value, name: &str| Ok(number(v, name, u32::MAX as u64)? as usize);
    let at = StepRef {
        reply_of: opt(args, "reply_of", |v| index(v, "reply_of"))?,
        branch: index(required(args, "branch")?, "branch")?,
        step: index(required(args, "step")?, "step")?,
    };
    Ok((input, at))
}
