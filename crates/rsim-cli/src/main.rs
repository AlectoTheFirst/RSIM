//! The command `rsim`: path queries and set queries on the built-in
//! topologies.

#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

use std::collections::BTreeMap;

use rsim_cli::tables;
use rsim_contract::args::Form;
use rsim_contract::json::{PathBriefOut, SetBriefOut};
use rsim_contract::table::Selection;
use std::io::Write;
use std::net::IpAddr;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use rsim_cli::json::{self, ErrorOut};
use rsim_cli::query::{FragmentName, IngressRef, parse_mac};
use rsim_cli::set_query::{
    Ranges, SetInput, parse_fragments, parse_macs, parse_prefixes, parse_tcp_flags,
    parse_transports,
};
use rsim_cli::{IcmpType, Protocol, QueryError, QueryInput, StepRef, TcpFlag, commands, text};
use rsim_core::{Mac, Prefix};
use serde::Serialize;

/// Path queries and set queries on the built-in topologies of rsim.
#[derive(Parser, Clone)]
#[command(name = "rsim", version)]
struct Cli {
    /// The output format.
    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,
    /// With `--format json`: indented JSON.
    #[arg(long, global = true)]
    pretty: bool,
    /// With `--format json`, the form of a path or set answer: summary,
    /// steps or full.
    #[arg(long, value_enum, default_value_t = FormArg::Full, global = true)]
    form: FormArg,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormArg {
    Summary,
    Steps,
    Full,
}

impl Cli {
    /// The brief form of a JSON answer, or `None` for the full form or
    /// the text output.
    fn brief(&self) -> Option<Form> {
        match (self.format, self.form) {
            (Format::Json, FormArg::Summary) => Some(Form::Summary),
            (Format::Json, FormArg::Steps) => Some(Form::Steps),
            _ => None,
        }
    }
}

#[derive(Subcommand, Clone)]
enum Command {
    /// The catalog of the tables: their columns and verbs.
    Tables,
    /// A table of a twin: `rsim <twin> <table> [show|summarize|unique|top|lpm|describe] [--<column> <values>] [--<column>.<op> <value>] [--columns a,b] [--sort a,-b] [--limit n] [--cursor c]`.
    #[command(external_subcommand)]
    Table(Vec<String>),
    /// The names of the built-in topologies.
    Topologies,
    /// The devices, the functions and the endpoints of a topology.
    Devices {
        /// A built-in topology, or `store:<data folder>` for the newest snapshot of a store. or `store:<data folder>` for the newest snapshot of a store.
        topology: String,
    },
    /// The answer for one packet, with the trace and the reply. A field
    /// that the query does not state is not known.
    Path(QueryArgs),
    /// The answer for a set of packets: the parts of the set with their
    /// results, the traces and the replies. A field that the query does not
    /// give has all values.
    Set(SetArgs),
    /// One trace step of the answer of a set query.
    ExplainSet {
        #[command(flatten)]
        query: SetArgs,
        /// The branch index.
        #[arg(long)]
        branch: usize,
        /// The step index in the branch.
        #[arg(long)]
        step: usize,
        /// Select the reply of this forward branch. Then the branch index and
        /// the step index are indexes in the reply.
        #[arg(long)]
        reply_of: Option<usize>,
    },
    /// One trace step of the answer.
    Explain {
        #[command(flatten)]
        query: QueryArgs,
        /// The branch index.
        #[arg(long)]
        branch: usize,
        /// The step index in the branch.
        #[arg(long)]
        step: usize,
        /// Select the reply of this forward branch. Then the branch index and
        /// the step index are indexes in the reply.
        #[arg(long)]
        reply_of: Option<usize>,
    },
}

#[derive(Args, Clone)]
struct QueryArgs {
    /// A built-in topology, or `store:<data folder>` for the newest snapshot of a store.
    topology: String,
    /// The ingress point as <device>/<interface>. Without it, the attachment
    /// records of the source address give the ingress.
    #[arg(long)]
    ingress: Option<IngressRef>,
    /// The source address.
    #[arg(long = "source.ip")]
    source_ip: IpAddr,
    /// The destination address.
    #[arg(long = "destination.ip")]
    destination_ip: IpAddr,
    /// The protocol number, 0 to 255.
    #[arg(long = "network.iana_number")]
    iana_number: Option<u8>,
    /// tcp, udp, icmp or icmpv6.
    #[arg(long = "network.transport", value_parser = transport)]
    transport: Option<Protocol>,
    #[arg(long = "source.port")]
    source_port: Option<u16>,
    #[arg(long = "destination.port")]
    destination_port: Option<u16>,
    /// Six hexadecimal bytes with colons.
    #[arg(long = "source.mac", value_parser = parse_mac)]
    source_mac: Option<Mac>,
    /// Six hexadecimal bytes with colons.
    #[arg(long = "destination.mac", value_parser = parse_mac)]
    destination_mac: Option<Mac>,
    /// 0 to 4095.
    #[arg(long = "network.vlan.id", value_parser = clap::value_parser!(u16).range(0..=4095))]
    vlan_id: Option<u16>,
    /// 0 to 7. It needs network.vlan.id.
    #[arg(long = "l2_priority", value_parser = clap::value_parser!(u8).range(0..=7))]
    l2_priority: Option<u8>,
    /// A comma-separated list of fin, syn, rst, psh, ack, urg, ece, cwr.
    #[arg(long = "tcp_flags", value_delimiter = ',')]
    tcp_flags: Option<Vec<TcpFlag>>,
    /// 0 to 255, echo-request or echo-reply.
    #[arg(long = "icmp_type")]
    icmp_type: Option<IcmpType>,
    #[arg(long = "icmp_code")]
    icmp_code: Option<u8>,
    /// 0 to 63.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=63))]
    dscp: Option<u8>,
    /// 0 to 3.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=3))]
    ecn: Option<u8>,
    /// unfragmented, first or later.
    #[arg(long)]
    fragment: Option<FragmentName>,
    /// Do not run the reply.
    #[arg(long)]
    no_reply: bool,
}

/// The fields of a set query. Each field takes a set: an address, a
/// prefix, a number, a range such as `1-1023`, or a comma list.
#[derive(Args, Clone)]
struct SetArgs {
    /// A built-in topology, or `store:<data folder>` for the newest snapshot of a store.
    topology: String,
    /// The ingress point as <device>/<interface>.
    #[arg(long)]
    ingress: Option<IngressRef>,
    /// Addresses and prefixes. Without it, the attached addresses of the
    /// ingress, or all addresses.
    #[arg(long = "source.ip", value_parser = |s: &str| parse_prefixes(s, "source.ip").map(List))]
    source_ip: Option<List<Prefix>>,
    #[arg(long = "destination.ip", value_parser = |s: &str| parse_prefixes(s, "destination.ip").map(List))]
    destination_ip: Option<List<Prefix>>,
    #[arg(long = "network.iana_number", value_parser = |s: &str| Ranges::parse(s, "network.iana_number", 255))]
    iana_number: Option<Ranges>,
    /// A comma list of tcp, udp, icmp and icmpv6.
    #[arg(long = "network.transport", value_parser = |s: &str| parse_transports(s).map(List))]
    transport: Option<List<Protocol>>,
    #[arg(long = "source.port", value_parser = |s: &str| Ranges::parse(s, "source.port", 65535))]
    source_port: Option<Ranges>,
    #[arg(long = "destination.port", value_parser = |s: &str| Ranges::parse(s, "destination.port", 65535))]
    destination_port: Option<Ranges>,
    #[arg(long = "source.mac", value_parser = |s: &str| parse_macs(s).map(List))]
    source_mac: Option<List<Mac>>,
    #[arg(long = "destination.mac", value_parser = |s: &str| parse_macs(s).map(List))]
    destination_mac: Option<List<Mac>>,
    #[arg(long = "network.vlan.id", value_parser = |s: &str| Ranges::parse(s, "network.vlan.id", 4095))]
    vlan_id: Option<Ranges>,
    #[arg(long = "l2_priority", value_parser = |s: &str| Ranges::parse(s, "l2_priority", 7))]
    l2_priority: Option<Ranges>,
    /// Numbers, ranges, or flag names joined with +, for example syn+ack.
    #[arg(long = "tcp_flags", value_parser = parse_tcp_flags)]
    tcp_flags: Option<Ranges>,
    #[arg(long = "icmp_type", value_parser = |s: &str| Ranges::parse(s, "icmp_type", 255))]
    icmp_type: Option<Ranges>,
    #[arg(long = "icmp_code", value_parser = |s: &str| Ranges::parse(s, "icmp_code", 255))]
    icmp_code: Option<Ranges>,
    #[arg(long, value_parser = |s: &str| Ranges::parse(s, "dscp", 63))]
    dscp: Option<Ranges>,
    #[arg(long, value_parser = |s: &str| Ranges::parse(s, "ecn", 3))]
    ecn: Option<Ranges>,
    /// A comma list of unfragmented, first and later.
    #[arg(long, value_parser = |s: &str| parse_fragments(s).map(List))]
    fragment: Option<List<FragmentName>>,
    /// Do not run the replies.
    #[arg(long)]
    no_reply: bool,
}

impl SetArgs {
    fn input(&self) -> SetInput {
        let a = self.clone();
        SetInput {
            topology: a.topology,
            ingress: a.ingress,
            source_ip: a.source_ip.map(|l| l.0),
            destination_ip: a.destination_ip.map(|l| l.0),
            iana_number: a.iana_number,
            transport: a.transport.map(|l| l.0),
            source_port: a.source_port,
            destination_port: a.destination_port,
            source_mac: a.source_mac.map(|l| l.0),
            destination_mac: a.destination_mac.map(|l| l.0),
            vlan_id: a.vlan_id,
            l2_priority: a.l2_priority,
            tcp_flags: a.tcp_flags,
            icmp_type: a.icmp_type,
            icmp_code: a.icmp_code,
            dscp: a.dscp,
            ecn: a.ecn,
            fragment: a.fragment.map(|l| l.0),
            reply: a.no_reply.then_some(false),
        }
    }
}

/// A comma list of one CLI flag.
#[derive(Clone, Debug)]
struct List<T>(Vec<T>);

/// A protocol name.
fn transport(s: &str) -> Result<Protocol, String> {
    match s.parse::<Protocol>() {
        Ok(p) if p.name().is_some() => Ok(p),
        _ => Err(format!(
            "network.transport {s:?} is not tcp, udp, icmp or icmpv6"
        )),
    }
}

impl QueryArgs {
    fn clone_input(&self) -> QueryInput {
        let a = self.clone();
        QueryInput {
            topology: a.topology,
            ingress: a.ingress,
            source_ip: a.source_ip,
            destination_ip: a.destination_ip,
            iana_number: a.iana_number,
            transport: a.transport,
            source_port: a.source_port,
            destination_port: a.destination_port,
            source_mac: a.source_mac,
            destination_mac: a.destination_mac,
            vlan_id: a.vlan_id,
            l2_priority: a.l2_priority,
            tcp_flags: a.tcp_flags,
            icmp_type: a.icmp_type,
            icmp_code: a.icmp_code,
            dscp: a.dscp,
            ecn: a.ecn,
            fragment: a.fragment,
            reply: a.no_reply.then_some(false),
        }
    }
}

/// Writes the output and gives the exit code.
fn emit<T: Serialize>(
    cli: &Cli,
    result: Result<T, QueryError>,
    as_text: impl FnOnce(&T) -> String,
) -> ExitCode {
    let (out, err, code) = match (&result, cli.format) {
        (Ok(v), Format::Text) => (as_text(v), String::new(), 0),
        (Ok(v), Format::Json) => (json::to_text(v, cli.pretty) + "\n", String::new(), 0),
        (Err(e), Format::Text) => (String::new(), text::error(e), 1),
        (Err(e), Format::Json) => (
            json::to_text(&ErrorOut::new(e.clone()), cli.pretty) + "\n",
            String::new(),
            1,
        ),
    };
    let _ = std::io::stdout().lock().write_all(out.as_bytes());
    let _ = std::io::stderr().lock().write_all(err.as_bytes());
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Command::Topologies => emit(&cli, Ok(commands::topologies()), text::topologies),
        Command::Tables => emit(&cli, Ok(tables::catalog()), |c| {
            c.tables
                .iter()
                .map(|t| format!("{:<16} {}\n", t.name, t.description))
                .collect()
        }),
        Command::Table(args) => table_command(&cli, args),
        Command::Devices { topology } => {
            let r = commands::load(topology).map(|t| commands::devices(topology, &t));
            emit(&cli, r, text::devices)
        }
        Command::Path(q) => {
            let input = q.clone_input();
            let r = commands::load(&input.topology).and_then(|t| commands::path(&input, &t));
            match cli.brief() {
                Some(f) => emit(&cli, r.map(|o| PathBriefOut::from_full(&o, f)), |_| {
                    String::new()
                }),
                None => emit(&cli, r, text::path),
            }
        }
        Command::Set(q) => {
            let input = q.input();
            let r = commands::load(&input.topology).and_then(|t| commands::set(&input, &t));
            match cli.brief() {
                Some(f) => emit(&cli, r.map(|o| SetBriefOut::from_full(&o, f)), |_| {
                    String::new()
                }),
                None => emit(&cli, r, text::set),
            }
        }
        Command::ExplainSet {
            query,
            branch,
            step,
            reply_of,
        } => {
            let input = query.input();
            let at = StepRef {
                reply_of: *reply_of,
                branch: *branch,
                step: *step,
            };
            let r =
                commands::load(&input.topology).and_then(|t| commands::explain_set(&input, at, &t));
            emit(&cli, r, text::step)
        }
        Command::Explain {
            query,
            branch,
            step,
            reply_of,
        } => {
            let input = query.clone_input();
            let at = StepRef {
                reply_of: *reply_of,
                branch: *branch,
                step: *step,
            };
            let r = commands::load(&input.topology).and_then(|t| commands::explain(&input, at, &t));
            emit(&cli, r, text::step)
        }
    }
}

/// The value of a flag of a table command.
fn flag_value<'a>(
    it: &mut std::slice::Iter<'a, String>,
    flag: &str,
) -> Result<&'a String, QueryError> {
    it.next().ok_or_else(|| {
        QueryError::new(
            rsim_cli::ErrorCode::InvalidQuery,
            format!("--{flag} needs a value"),
        )
    })
}

/// The text form of table rows: one line for each row, with aligned
/// columns.
fn rows_text(columns: &[String], rows: &[Vec<serde_json::Value>]) -> String {
    let cell = |v: &serde_json::Value| match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => a
            .iter()
            .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_string))
            .collect::<Vec<_>>()
            .join(" "),
        serde_json::Value::Null => "-".into(),
        other => other.to_string(),
    };
    let cells: Vec<Vec<String>> = rows.iter().map(|r| r.iter().map(cell).collect()).collect();
    let mut width: Vec<usize> = columns.iter().map(String::len).collect();
    for r in &cells {
        for (i, c) in r.iter().enumerate() {
            width[i] = width[i].max(c.chars().count());
        }
    }
    let line = |r: &[String]| -> String {
        let parts: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<w$}", w = width[i]))
            .collect();
        parts.join("  ").trim_end().to_string() + "\n"
    };
    let mut out = line(columns);
    for r in &cells {
        out.push_str(&line(r));
    }
    out
}

/// The parts of a table command: the twin, the table, the verb, the
/// positional arguments, the selection and the other options.
type Parsed = (
    String,
    String,
    String,
    Vec<String>,
    Selection,
    BTreeMap<String, String>,
);

/// `rsim <twin> <table> [verb] [flags]`.
fn table_command(cli: &Cli, args: &[String]) -> ExitCode {
    // The global output flags can also follow the twin.
    let mut own = cli.clone();
    let mut kept = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pretty" => own.pretty = true,
            "--format" => match it.next().map(String::as_str) {
                Some("json") => own.format = Format::Json,
                Some("text") => own.format = Format::Text,
                other => {
                    return usage_error(&format!(
                        "--format {} is not text or json",
                        other.unwrap_or("")
                    ));
                }
            },
            _ => kept.push(a.clone()),
        }
    }
    let cli = &own;
    let args = &kept[..];
    let usage = |d: String| QueryError::new(rsim_cli::ErrorCode::InvalidQuery, d);
    let parsed = (|| -> Result<Parsed, QueryError> {
        let twin = args
            .first()
            .ok_or_else(|| usage("a twin is needed".into()))?;
        let twin = twin.strip_prefix("builtin.").unwrap_or(twin).to_string();
        let table = args
            .get(1)
            .ok_or_else(|| usage("a table is needed; `rsim tables` lists them".into()))?
            .clone();
        let mut rest = args[2..].iter();
        let mut verb = "show".to_string();
        let mut positional = Vec::new();
        let mut sel = Selection::default();
        let mut opts = BTreeMap::new();
        let mut first = true;
        while let Some(a) = rest.next() {
            match a.strip_prefix("--") {
                Some("columns") => {
                    sel.columns = Some(
                        flag_value(&mut rest, "columns")?
                            .split(',')
                            .map(str::to_string)
                            .collect(),
                    );
                }
                Some("sort") => {
                    sel.sort = Some(
                        flag_value(&mut rest, "sort")?
                            .split(',')
                            .map(str::to_string)
                            .collect(),
                    );
                }
                Some("limit") => {
                    let v = flag_value(&mut rest, "limit")?;
                    sel.limit = Some(
                        v.parse()
                            .map_err(|_| usage(format!("--limit {v} is not a number")))?,
                    );
                }
                Some("cursor") => sel.cursor = Some(flag_value(&mut rest, "cursor")?.clone()),
                Some(k @ ("column" | "count")) => {
                    opts.insert(k.to_string(), flag_value(&mut rest, k)?.clone());
                }
                Some("ascending") => {
                    opts.insert("ascending".into(), "true".into());
                }
                Some(k) if k.contains('.') => {
                    sel.typed
                        .insert(k.to_string(), flag_value(&mut rest, k)?.clone());
                }
                Some(k) => {
                    let v = flag_value(&mut rest, k)?;
                    sel.filters
                        .insert(k.to_string(), v.split(',').map(str::to_string).collect());
                }
                None if first => verb = a.clone(),
                None => positional.push(a.clone()),
            }
            first = false;
        }
        Ok((twin, table, verb, positional, sel, opts))
    })();
    let (twin, table, verb, positional, sel, opts) = match parsed {
        Ok(p) => p,
        Err(e) => return usage_error(&e.detail),
    };
    let loaded = match commands::load(&twin) {
        Ok(l) => l,
        Err(e) => return emit::<()>(cli, Err(e), |_| String::new()),
    };
    match verb.as_str() {
        "show" => emit(cli, tables::show(&twin, &loaded, &table, &sel), |o| {
            rows_text(&o.columns, &o.rows)
        }),
        "top" => {
            let column = opts.get("column").cloned().unwrap_or_default();
            let n = opts.get("count").and_then(|c| c.parse().ok()).unwrap_or(5);
            emit(
                cli,
                tables::top(
                    &twin,
                    &loaded,
                    &table,
                    &column,
                    n,
                    opts.contains_key("ascending"),
                    &sel,
                ),
                |o| rows_text(&o.columns, &o.rows),
            )
        }
        "lpm" => {
            let column = opts
                .get("column")
                .cloned()
                .unwrap_or_else(|| "prefix".into());
            let address = positional.first().cloned().unwrap_or_default();
            emit(
                cli,
                tables::lpm(&twin, &loaded, &table, &column, &address, &sel),
                |o| rows_text(&o.columns, &o.rows),
            )
        }
        "unique" => {
            let columns = sel.columns.clone().unwrap_or_default();
            let mut s = sel.clone();
            s.columns = None;
            emit(
                cli,
                tables::unique(&twin, &loaded, &table, &columns, &s),
                |o| rows_text(&o.columns, &o.rows),
            )
        }
        "summarize" => emit(cli, tables::summarize(&twin, &loaded, &table, &sel), |o| {
            let mut t = format!("{} rows\n", o.total);
            for c in &o.columns {
                t.push_str(&format!(
                    "{:<16} distinct {:<6} nulls {}\n",
                    c.column, c.distinct, c.nulls
                ));
            }
            t
        }),
        "describe" => emit(cli, tables::def(&table), |d| {
            d.columns
                .iter()
                .map(|c| format!("{:<12} {:?}  {}\n", c.name, c.kind, c.description))
                .collect()
        }),
        v => usage_error(&format!(
            "{v} is not a verb; the verbs are show, summarize, unique, top, lpm and describe"
        )),
    }
}

/// A usage error of a table command: the text on stderr and the exit code
/// 2, as for the other usage errors.
fn usage_error(detail: &str) -> ExitCode {
    let _ = writeln!(std::io::stderr().lock(), "error: {detail}");
    ExitCode::from(2)
}
