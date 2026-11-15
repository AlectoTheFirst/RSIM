# rsim

rsim is a Rust engine for a network digital twin.

The engine compiles device configs into typed network functions. The functions stay in memory. The engine sends packets through the functions to answer reachability questions. Each answer has a full trace.

## Status

The engine has the core types, the forwarding functions, the concrete-mode executor, the trace and the return path. The topologies are built by hand in `rsim-topologies`. The command `rsim` and the MCP server `rsim-mcp` run path queries for one packet on these topologies. The crate `rsim-dd` holds the decision diagram engine for packet sets. The engine does not use it yet. No config parser exists yet.

## Principles

- If the engine cannot be sure, it returns `Unknown` with a reason.
- The same input gives the same output.
- Each function keeps the source lines from which it came.
- Vendor defaults are data in vendor profiles.
- Functions contain no buffers, timers, queues or I/O.
- Functions calculate the delay as virtual time.
- Functions calculate the QoS marking, the traffic class, the selected queue.
- A policer or a shaper adds a rate condition to the branch. The engine does not simulate rates.

## Crates

| Crate | Contents |
|---|---|
| `rsim-core` | Packets, packet sets, context, flow state, outcomes, traces |
| `rsim-dd` | Reduced ordered binary decision diagrams with complement edges, for the packet sets |
| `rsim-functions` | The network function library: forwarding, ACL, NAT, sessions |
| `rsim-engine` | The twin, the executor, verdict aggregation, the return path |
| `rsim-topologies` | The hand-built topologies for the tests, the benchmarks, `rsim` and `rsim-mcp` |
| `rsim-cli` | The command `rsim`: path queries with text output and versioned JSON output |
| `rsim-mcp` | A Model Context Protocol server on stdio with the tools `list_devices`, `path_query` and `explain_step` |

## Build

You need Rust 1.99 or later.

| Task | Command |
|---|---|
| Build | `cargo build --workspace` |
| All tests | `cargo test --workspace` |
| One test file | `cargo test -p rsim-engine --test forwarding` |
| One test | `cargo test -p rsim-engine --test forwarding <test_name>` |
| Lint | `cargo clippy --workspace --all-targets` |
| Format check | `cargo fmt --all --check` |
| Path query benchmark | `cargo bench -p rsim-engine --bench single_path` |
| Memory per device | `cargo bench -p rsim-engine --bench memory` |
| Decision diagram operations | `cargo bench -p rsim-dd --bench ops` |

## Path queries with rsim

`rsim` loads a built-in topology by name. The names are `mini-enterprise`, `edge-dnat`, `ecmp`, `routing-loop`, `hairpin` and `chain`.

| Task | Command |
|---|---|
| List the topologies | `cargo run -p rsim-cli -- topologies` |
| List the devices, functions, endpoints and attachment records | `cargo run -p rsim-cli -- devices mini-enterprise` |
| Run a path query with its reply | `cargo run -p rsim-cli -- path mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --source.port 40000 --destination.port 53` |
| Show one trace step | `cargo run -p rsim-cli -- explain mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --destination.port 53 --branch 0 --step 7` |
| Show one trace step of the reply of branch 0 | Add `--reply-of 0` to the `explain` command |
| Get JSON | Add `--format json`. Add `--pretty` for indented JSON. |
| Show all flags | `cargo run -p rsim-cli -- path --help` |

The query flags use the names of the Elastic Common Schema where it has one: `--source.ip`, `--destination.ip`, `--network.iana_number`, `--network.transport`, `--source.port`, `--destination.port`, `--source.mac`, `--destination.mac` and `--network.vlan.id`. The other flags are `--l2_priority`, `--tcp_flags`, `--icmp_type`, `--icmp_code`, `--dscp`, `--ecn`, `--fragment`, `--ingress` and `--no-reply`. `--tcp_flags` takes a comma-separated list, for example `syn,ack`.

- A path query needs `--source.ip`, `--destination.ip`, and `--network.iana_number` or `--network.transport`.
- `--ingress <device>/<interface>` states where the packet enters. Without it, the attachment records of the source address give the ingress. A source address on a connected network of an edge interface gives an ingress with a host that is not confirmed.
- A field that the query does not state is not known. If the result depends on such a field, the summary is `unknown`. The branches show each part exactly.

The exit code is 0 if the engine gave an answer. `Drop` and `Unknown` are answers. The exit code is 1 for a query error and 2 for a usage error.

The JSON output has the field `rsim_json` with the version number 2. The same query gives the same bytes. A packet set is a list of members, and each member is a product of field values.

## MCP server

`rsim-mcp` is a Model Context Protocol server with the stdio transport. It supports the protocol revisions `2026-07-28` and `2025-11-25`. It writes only protocol messages to stdout and its log to stderr. It writes no files.

1. Build the server with `cargo build --release -p rsim-mcp`.
2. Add `target/release/rsim-mcp` to your MCP client as a stdio server with no arguments.

| Tool | Arguments | Result |
|---|---|---|
| `list_devices` | `topology` | The devices, functions, endpoints, attachment records and edge interfaces |
| `path_query` | The query fields of `rsim path` with the same names: `topology`, `source.ip`, `destination.ip`, the protocol and the optional fields | The answer with the ingress, the trace and the reply |
| `explain_step` | The query fields, `branch`, `step` and the optional `reply_of` | One trace step. The tool runs the query again. |

The JSON of a tool result is the same as the output of `rsim` with `--format json`.

## License

MIT
