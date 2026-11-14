# rsim

rsim is a Rust engine for a network digital twin.

The engine compiles device configs into typed network functions. The functions stay in memory. The engine sends packets through the functions to answer reachability questions. Each answer has a full trace.

## Status

The project is at step 1. Step 1 contains the core types, the forwarding functions, the executor, the trace, the return path. Tests build the topologies by hand. No config parser exists yet.

## Principles

- If the engine cannot be sure, it returns `Indeterminate` with a reason.
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

```sh
cargo build --workspace
cargo test --workspace
cargo test -p rsim-engine <test_name>
cargo bench -p rsim-engine --bench single_path
```

## License

MIT
