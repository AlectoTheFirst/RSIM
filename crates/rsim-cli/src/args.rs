//! The query input from the JSON arguments of an MCP tool.

use serde_json::{Map, Value};

use crate::commands::StepRef;
use crate::error::{ErrorCode, QueryError};
use crate::query::{IcmpType, IngressRef, Protocol, QueryInput, TcpFlag, parse_mac};
use crate::set_query::{
    Ranges, SetInput, parse_fragments, parse_macs, parse_prefixes, parse_tcp_flags,
    parse_transports,
};

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
    let mut extra = STEP_FIELDS.to_vec();
    extra.push("mode");
    let input = query(args, &extra)?;
    let index = |v: &Value, name: &str| Ok(number(v, name, u32::MAX as u64)? as usize);
    let at = StepRef {
        reply_of: opt(args, "reply_of", |v| index(v, "reply_of"))?,
        branch: index(required(args, "branch")?, "branch")?,
        step: index(required(args, "step")?, "step")?,
    };
    Ok((input, at))
}

/// The names of the set query arguments: the path query names without the
/// required fields.
pub const SET_FIELDS: [&str; 19] = QUERY_FIELDS;

/// The text of a set argument: a string, a number, or a list of strings
/// and numbers that joins with commas.
fn set_text(v: &Value, name: &str) -> Result<String, QueryError> {
    let one = |v: &Value| match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(invalid(format!(
            "{name} is not a string, a number or a list of them"
        ))),
    };
    match v {
        Value::Array(items) => Ok(items
            .iter()
            .map(one)
            .collect::<Result<Vec<_>, _>>()?
            .join(",")),
        v => one(v),
    }
}

/// The set query input from the arguments. Names in `extra` are allowed and
/// are not read. Each field takes a set.
pub fn set_query(args: &Map<String, Value>, extra: &[&str]) -> Result<SetInput, QueryError> {
    let allowed: Vec<&str> = SET_FIELDS.iter().chain(extra).copied().collect();
    check_names(args, &allowed)?;
    let text = |name: &str| opt(args, name, |v| set_text(v, name));
    let ranges = |name: &str, max: u32| -> Result<Option<Ranges>, QueryError> {
        text(name)?
            .map(|t| Ranges::parse(&t, name, max).map_err(invalid))
            .transpose()
    };
    Ok(SetInput {
        topology: string(required(args, "topology")?, "topology")?,
        ingress: opt(args, "ingress", |v| {
            string(v, "ingress")?.parse::<IngressRef>().map_err(invalid)
        })?,
        source_ip: text("source.ip")?
            .map(|t| parse_prefixes(&t, "source.ip").map_err(invalid))
            .transpose()?,
        destination_ip: text("destination.ip")?
            .map(|t| parse_prefixes(&t, "destination.ip").map_err(invalid))
            .transpose()?,
        iana_number: ranges("network.iana_number", 255)?,
        transport: text("network.transport")?
            .map(|t| parse_transports(&t).map_err(invalid))
            .transpose()?,
        source_port: ranges("source.port", 65535)?,
        destination_port: ranges("destination.port", 65535)?,
        source_mac: text("source.mac")?
            .map(|t| parse_macs(&t).map_err(invalid))
            .transpose()?,
        destination_mac: text("destination.mac")?
            .map(|t| parse_macs(&t).map_err(invalid))
            .transpose()?,
        vlan_id: ranges("network.vlan.id", 4095)?,
        l2_priority: ranges("l2_priority", 7)?,
        tcp_flags: text("tcp_flags")?
            .map(|t| parse_tcp_flags(&t).map_err(invalid))
            .transpose()?,
        icmp_type: ranges("icmp_type", 255)?,
        icmp_code: ranges("icmp_code", 255)?,
        dscp: ranges("dscp", 63)?,
        ecn: ranges("ecn", 3)?,
        fragment: text("fragment")?
            .map(|t| parse_fragments(&t).map_err(invalid))
            .transpose()?,
        reply: opt(args, "reply", |v| boolean(v, "reply"))?,
    })
}

/// The mode of `explain_step`: `path` or `set`.
pub fn mode(args: &Map<String, Value>) -> Result<bool, QueryError> {
    match get(args, "mode") {
        None => Ok(false),
        Some(Value::String(s)) if s == "path" => Ok(false),
        Some(Value::String(s)) if s == "set" => Ok(true),
        Some(_) => Err(invalid("mode is not path or set".to_string())),
    }
}

/// The set query input and the indexes of a trace step.
pub fn set_step(args: &Map<String, Value>) -> Result<(SetInput, StepRef), QueryError> {
    let mut extra = STEP_FIELDS.to_vec();
    extra.push("mode");
    let input = set_query(args, &extra)?;
    let index = |v: &Value, name: &str| Ok(number(v, name, u32::MAX as u64)? as usize);
    let at = StepRef {
        reply_of: opt(args, "reply_of", |v| index(v, "reply_of"))?,
        branch: index(required(args, "branch")?, "branch")?,
        step: index(required(args, "step")?, "step")?,
    };
    Ok((input, at))
}

/// The form of the answer of a tool. The default is `summary`.
pub fn form(args: &Map<String, Value>) -> Result<rsim_contract::args::Form, QueryError> {
    use rsim_contract::args::Form;
    match get(args, "form") {
        None => Ok(Form::Summary),
        Some(v) => match v.as_str() {
            Some("summary") => Ok(Form::Summary),
            Some("steps") => Ok(Form::Steps),
            Some("full") => Ok(Form::Full),
            _ => Err(invalid(format!("form {v} is not summary, steps or full"))),
        },
    }
}
