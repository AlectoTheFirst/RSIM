# rsim

rsim is a Rust engine for a network digital twin.

The engine compiles device configs into typed network functions. The functions stay in memory. The engine sends packets through the functions to answer reachability questions. Each answer has a full trace.

## Status

Initial phase contains the core types, the forwarding functions, the concrete-mode executor, the trace and the return path. Tests build the topologies by hand. No config parser exists yet.

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
| `rsim-functions` | The network function library: forwarding, ACL, NAT, sessions |
| `rsim-engine` | The twin, the executor, verdict aggregation, the return path |

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

## License

MIT
