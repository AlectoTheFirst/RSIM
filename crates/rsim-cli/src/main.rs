//! The command `rsim`: path queries on the built-in topologies.

#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

use std::io::Write;
use std::net::IpAddr;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use rsim_cli::json::{self, ErrorOut};
use rsim_cli::{IcmpType, Protocol, QueryError, QueryInput, StepRef, TcpFlag, commands, text};
use serde::Serialize;

/// Path queries on the built-in topologies of rsim.
#[derive(Parser)]
#[command(name = "rsim", version)]
struct Cli {
    /// The output format.
    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,
    /// With `--format json`: indented JSON.
    #[arg(long, global = true)]
    pretty: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// The names of the built-in topologies.
    Topologies,
    /// The devices, the functions and the endpoints of a topology.
    Devices {
        /// A built-in topology.
        topology: String,
    },
    /// The answer for one packet, with the trace and the reply.
    Path(QueryArgs),
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
    /// A built-in topology.
    topology: String,
    /// The endpoint that sends the packet.
    #[arg(long)]
    from: String,
    /// The destination address.
    #[arg(long)]
    dst: IpAddr,
    /// tcp, udp, icmp, icmpv6 or a number 0 to 255.
    #[arg(long)]
    protocol: Protocol,
    /// The source address. The default is the first address of the endpoint.
    #[arg(long)]
    src: Option<IpAddr>,
    #[arg(long)]
    src_port: Option<u16>,
    #[arg(long)]
    dst_port: Option<u16>,
    /// A comma-separated list of fin, syn, rst, psh, ack, urg, ece, cwr.
    #[arg(long, value_delimiter = ',')]
    tcp_flags: Option<Vec<TcpFlag>>,
    /// 0 to 255, echo-request or echo-reply.
    #[arg(long)]
    icmp_type: Option<IcmpType>,
    #[arg(long)]
    icmp_code: Option<u8>,
    /// 0 to 63.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=63))]
    dscp: Option<u8>,
    /// 0 to 3.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=3))]
    ecn: Option<u8>,
    /// The packet is a later fragment.
    #[arg(long)]
    later_fragment: bool,
    /// Do not run the reply.
    #[arg(long)]
    no_reply: bool,
}

impl QueryArgs {
    fn clone_input(&self) -> QueryInput {
        let a = self.clone();
        QueryInput {
            topology: a.topology,
            from: a.from,
            dst: a.dst,
            protocol: a.protocol,
            src: a.src,
            src_port: a.src_port,
            dst_port: a.dst_port,
            tcp_flags: a.tcp_flags,
            icmp_type: a.icmp_type,
            icmp_code: a.icmp_code,
            dscp: a.dscp,
            ecn: a.ecn,
            later_fragment: a.later_fragment.then_some(true),
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
        Command::Devices { topology } => {
            let r = commands::load(topology).map(|t| commands::devices(topology, &t));
            emit(&cli, r, text::devices)
        }
        Command::Path(q) => {
            let input = q.clone_input();
            let r = commands::load(&input.topology).and_then(|t| commands::path(&input, &t));
            emit(&cli, r, text::path)
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
