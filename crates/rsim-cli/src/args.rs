//! The query input from the JSON arguments of an MCP tool.

use serde_json::{Map, Value};

use crate::commands::StepRef;
use crate::error::{ErrorCode, QueryError};
use crate::query::{IcmpType, Protocol, QueryInput, TcpFlag};

/// The names of the query arguments, in the order of the query input.
pub const QUERY_FIELDS: [&str; 14] = [
    "topology",
    "from",
    "dst",
    "protocol",
    "src",
    "src_port",
    "dst_port",
    "tcp_flags",
    "icmp_type",
    "icmp_code",
    "dscp",
    "ecn",
    "later_fragment",
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
    let protocol = match required(args, "protocol")? {
        Value::String(s) => s.parse::<Protocol>().map_err(invalid)?,
        v => Protocol(number(v, "protocol", 255)? as u8),
    };
    Ok(QueryInput {
        topology: string(required(args, "topology")?, "topology")?,
        from: string(required(args, "from")?, "from")?,
        dst: addr(required(args, "dst")?, "dst")?,
        protocol,
        src: opt(args, "src", |v| addr(v, "src"))?,
        src_port: opt(args, "src_port", |v| {
            Ok(number(v, "src_port", 65535)? as u16)
        })?,
        dst_port: opt(args, "dst_port", |v| {
            Ok(number(v, "dst_port", 65535)? as u16)
        })?,
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
        icmp_code: opt(
            args,
            "icmp_code",
            |v| Ok(number(v, "icmp_code", 255)? as u8),
        )?,
        dscp: opt(args, "dscp", |v| Ok(number(v, "dscp", 63)? as u8))?,
        ecn: opt(args, "ecn", |v| Ok(number(v, "ecn", 3)? as u8))?,
        later_fragment: opt(args, "later_fragment", |v| boolean(v, "later_fragment"))?,
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
