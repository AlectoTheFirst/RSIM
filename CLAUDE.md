# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

Steps 1, 1b and 2 of the build are complete. Step 3 is in progress: collection, the snapshot store, the snapshot view and ingestion. The collection and the ingestion of VyOS, UniFi and NX-OS are complete, with one link join for all vendors. The current batch is EVPN, VXLAN and the anycast gateway in 7 pull requests; pull request 1, the encapsulation in the core, is complete. Then come the HTTP API parts A1 to A3, the Rust TextFSM engine, IOS-XR and IOS-XE. `../rsim-project/roadmap.md` gives the order. The Cargo workspace has 10 crates in `crates/`: `rsim-core`, `rsim-dd`, `rsim-functions`, `rsim-engine`, `rsim-topologies`, `rsim-cli`, `rsim-mcp`, `rsim-store`, `rsim-collect` and `rsim-ingest`. The other crates of section 3 come with their steps.

The two design documents are in the adjacent folder `../rsim-project/`. This repository is public, so the design documents stay out of it. Do not commit the design documents, real configs or collected state to this repository.

- `../rsim-project/PROJECT_SUMMARY.md` gives the reasoning. Read it first.
- `../rsim-project/BUILD_BRIEF.md` is the build specification. It says what to build.

If the two documents disagree, `BUILD_BRIEF.md` governs.

## Where documentation goes

This repository holds only code, tests, usage how-tos and the information that the owner selects for it, such as the README. All other documentation goes in `../rsim-project/`: design notes, benchmark records, fixtures, reports and project notes. Do not add a `docs/` folder or another documentation file to this repository unless the owner asks for it.

| Item | Location |
|---|---|
| Design notes | `../rsim-project/design/` |
| Roadmap | `../rsim-project/roadmap.md` |
| Benchmark records | `../rsim-project/benchmarks.md` |
| Baseline fixtures | `../rsim-project/fixtures/` |
| Data folder of the `ci` Neo4j baseline | `../rsim-project/neo4j-baseline-data/` |

## Code comments

A comment or a docstring describes the code that it belongs to. Do not write design text, reasons for a decision, build step numbers or section numbers of the brief in the code. Design text goes in `../rsim-project/`.

## Commands

| Task | Command |
|---|---|
| Build | `cargo build --workspace` |
| All tests | `cargo test --workspace` |
| One test file | `cargo test -p rsim-engine --test forwarding` |
| One test | `cargo test -p rsim-engine --test forwarding guest_to_dns_through_firewall_snat_ips_and_acl_and_back` |
| Lint | `cargo clippy --workspace --all-targets` |
| Format check | `cargo fmt --all --check` |
| Path query benchmark | `cargo bench -p rsim-engine --bench single_path` |
| Memory per device | `cargo bench -p rsim-engine --bench memory` |
| CLI tests | `cargo test -p rsim-cli --test cli` |
| MCP stdio tests | `cargo test -p rsim-mcp --test stdio` |
| List the built-in topologies | `cargo run -p rsim-cli -- topologies` |
| Path query with its reply | `cargo run -p rsim-cli -- path mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --source.port 40000 --destination.port 53` |
| Path query as JSON | Add `--format json` to the `path` command. Add `--pretty` for indented JSON. |
| Set query | `cargo run -p rsim-cli -- set mini-enterprise --source.ip 172.31.10.0/24 --destination.ip 10.20.0.53 --network.transport udp,tcp` |
| One trace step of a set query | `cargo run -p rsim-cli -- explain-set mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --destination.port 53,80 --branch 1 --step 7` |
| Set query benchmark | `cargo bench -p rsim-engine --bench set_query` |
| One trace step | `cargo run -p rsim-cli -- explain mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --destination.port 53 --branch 0 --step 7` |
| MCP server on stdio | `cargo run -p rsim-mcp` |
| Path query on the newest snapshot of a store | `cargo run -p rsim-cli -- path store:<data folder> --source.ip <a> --destination.ip <b> ...`. The data folder is the folder of `rsim-collect` with `store` and `keys`. |
| MCP server with a store | `cargo run -p rsim-mcp -- --store <data folder>`. The tools then accept the topology `store`. |
| Decision diagram tests | `cargo test -p rsim-dd` |
| Decision diagram tests, release build with the validator | `cargo test -p rsim-dd --release --features dd-check` |
| Decision diagram benchmark | `cargo bench -p rsim-dd --bench ops` |
| Snapshot store tests | `cargo test -p rsim-store` |
| Collection tests | `cargo test -p rsim-collect` |
| NX-OS collection tests | `cargo test -p rsim-collect --test nxos` |
| One collection cycle of real devices | `cargo run -p rsim-collect --bin rsim-collect -- --env <env file> --data <data folder> run`. Add `--repeat` for a cycle every 60 s. The `status` command shows the sections of the newest snapshot, and `show <device> <section>` writes the raw bytes of a section. The env file and the data folder stay outside the repository. |
| SSH transport tests | `cargo test -p rsim-collect --test ssh` |
| HTTPS transport tests | `cargo test -p rsim-collect --test https` |
| Collection benchmark | `cargo bench -p rsim-collect --bench cycle` |
| Ingestion tests | `cargo test -p rsim-ingest` |
| Layer 2 tests | `cargo test -p rsim-engine --test layer2` |
| VXLAN fabric tests | `cargo test -p rsim-engine --test tunnel` |
| Forwarding table benchmark at internet scale | `cargo bench -p rsim-functions --bench fib`. `RSIM_FIB_SKIP_ALL=1` leaves out the split of all destinations, which does not scale yet. |
| Twin of the newest snapshot of a store | `cargo run -p rsim-ingest --example estate -- <data folder>`. Add `<source> <destination> tcp\|udp <port>` for a path query; the ingress comes from the attachment of the source. |
| Coverage of a VyOS config | `cargo run -p rsim-ingest --example vyos_coverage < config.json` |
| Coverage of an NX-OS running config | `cargo run -p rsim-ingest --example nxos_coverage < running-config.txt`. Each printed line goes through the mask of the secrets. |
| NX-OS ingestion tests | `cargo test -p rsim-ingest --test nxos` |
| NX-OS vPC tests | `cargo test -p rsim-ingest --test nxos_vpc` |
| Link join tests | `cargo test -p rsim-ingest --test links` |
| Twin of a VyOS device of a store | `cargo run -p rsim-ingest --example vyos_snapshot -- <data folder> <device>`. Add `<ingress interface> <source> <destination> tcp\|udp <port>` for a path query. |

The hand-built topologies are in the crate `rsim-topologies`, with one module for each topology in `crates/rsim-topologies/src/`. `layer2_site()` is a switched site behind a router for the layer 2 tests; it is not a built-in topology. The tests and the benchmarks of `rsim-engine` use it as a development dependency. `rsim-topologies::builtin(name)` gives the twin of a built-in topology.

`leaf_spine()` is a VXLAN fabric of 4 leaves and 2 spines with symmetric routing in one tenant VRF; `rsim-functions/src/tunnel.rs` holds its tunnel ends `VxlanEncap` and `VxlanDecap`.

The stored JSON answers of the CLI tests are in `crates/rsim-cli/tests/golden/`. `leaf-spine-acl.json` and `leaf-spine-no-route.json` are the answers of `FABRIC_QUERIES` in `crates/rsim-cli/tests/cli.rs`. `set-mini-enterprise.json` is the answer of the set query `SET_QUERY` in `crates/rsim-cli/tests/cli.rs`; make it again with `rsim set` and these flags. The CLI test and the MCP stdio test compare their outputs with these files. If an intended change alters the JSON output, make the files again with `rsim path <topology> <flags> --format json`. The flags of each file are in `QUERIES` in `crates/rsim-cli/tests/cli.rs`.

The prefix table in `rsim-core/src/prefix_table.rs` is a path-compressed trie with a read-only walk; `PacketSet::partition_by_prefix` and `PacketSet::partition_by_group` use the walk. `rsim-functions/src/fib.rs` holds the forwarding table `Fib`: the trie, the interned next-hop groups and compact spans. `RouteLookup` splits a packet set by next-hop group, so a set query gives one branch for each forwarding result. `crates/rsim-core/tests/prefix_oracle.rs` compares the trie and both partitions with a brute-force longest-prefix match. `../rsim-project/design/rib-fib.md` gives the design.

`rsim-core` keeps the packet sets in `packet_set.rs`, the bit table in `bits.rs`, the arenas in `set.rs` and the description of a set as members in `describe.rs`. `crates/rsim-core/tests/explicit_oracle.rs` compares each set operation with an explicit list of packet pairs. Each header bit has 4 levels: the original request, the current header, the work level and the inner level. A packet has at most one encapsulation: `PacketSet::encapsulate` moves the current header to the inner level and puts the outer header in the current fields, and `PacketSet::decapsulate` brings it back. The inner level is free for a packet with no encapsulation, and `PacketSet::has_free_levels` checks this in the tests. An outer header states each field. The JSON shows the inner header as `inner` of the current header. A path query runs on the set of its packet; the design note gives the rule for an unstated field. The ingress of a query comes from `--ingress` or from the attachment records and edge interfaces of the twin.

The tests of `rsim-dd` turn on the feature `dd-shadow` through a development dependency of the crate on itself. Each public operation then also runs in a plain BDD, and the 2 results must be the same set. A benchmark turns the shadow check off with `Dd::set_shadow(false)`. The OxiDD oracle in `crates/rsim-dd/tests/oracle.rs` compares the results with OxiDD on 3,052 levels. OxiDD is a development dependency only.

`crates/rsim-cli/clippy.toml` and `crates/rsim-mcp/clippy.toml` deny the file write functions and the network socket types. Only a test helper can allow them.

`rsim-store` holds the format of the snapshot store, the writer and the reader. It has no network code. `rsim-collect` is the only crate that talks to devices. It runs a collection cycle as stages with bounded channels: schedule, fetch, classify and hash, extract, and store. The SSH transport is in `ssh.rs`, the HTTPS transport in `https.rs`, and the credentials and the pins of host keys and certificates in `trust.rs`. `path.rs` holds the route of a device: the proxy and the jump hosts. `tunnel.rs` logs in to each hop of a route, and both transports use it. `cli.rs` holds the text rules of a command line: the cleanup of terminal bytes, the prompt, the banner and the rejection lines of a vendor. The SSH transport has 3 command modes: `exec`, `shell` and `connection`. `../rsim-project/design/vendors.md` gives the rules. The features `ssh` and `https` turn on the transports, and `vyos`, `unifi` and `nxos` turn on the sources. The NX-OS source is in `nxos.rs`: the JSON answers get one shape, with each `ROW_x` as a list, and a keep list of a section names the fields that the change hash covers. The sections of the VXLAN tunnels, the EVPN MAC routes and the multicast routing have JSON keys that are not confirmed on a device, so they use volatile patterns for their times in place of a keep list. `https` needs `ssh`, because a console can be behind jump hosts. The pipeline tests use the fake transport in `fake.rs` and the synthetic fixtures in `crates/rsim-collect/tests/fixtures/`. The fixtures use only documentation addresses and documentation MAC addresses. The transport tests in `tests/ssh.rs` and `tests/https.rs` run the real transports against servers on 127.0.0.1 in the test process. `tests/support/route.rs` holds the test jump host, which logs each login attempt, and the HTTP CONNECT and SOCKS5 test proxies. The test keys and certificates are made at test time. Do not commit private keys. The scheduler tests and the cycle tests use paused `tokio` time.

`rsim-ingest` reads the snapshot store and gives function instances. It has no network code, no async runtime, no clock and no randomness. `stanza.rs` reads JSON, and indented config text such as a Cisco running config, into a tree of stanzas with the line ranges of the canonical form. In a classification table, a segment with a space or a final `..` is a word pattern for the line of an indented config, for example `interface */ip address ..`. `coverage.rs` classifies each stanza as handled, known-irrelevant or unhandled from a table of paths, and gives the coverage report. `collected.rs` reads the rows of the collected tables. The VyOS handlers are in `vyos/config.rs`, the table in `vyos/table.rs`, the lowering in `vyos/lower.rs` and the vendor profile in `vyos/profile.rs`. Each handler records the stanzas that it reads, and `vyos::unread` lists each handled stanza that no handler read. A new handled path needs a handler that reads it. The tests use the synthetic config in `crates/rsim-ingest/tests/fixtures/vyos/`. The UniFi handlers are in `unifi/site.rs`, the coverage rules in `unifi/coverage.rs` and the lowering in `unifi/lower.rs`. The NX-OS module is in `nxos/`: `nxos/table.rs` classifies the lines of the running config, `nxos/mask.rs` masks the secrets of each line that leaves the ingestion, `nxos/config.rs` holds the handlers, `nxos/names.rs` resolves the short interface names of the collected sections, `nxos/state.rs` reads the collected JSON sections (the interface state, HSRP, VRRP, LLDP and CDP), `nxos/lower.rs` lowers the layer 3 part of a switch, `nxos/layer2.rs` lowers the switch ports, the MAC table, the flood, the SVI hand-off and the endpoints,  and `nxos/profile.rs` holds the vendor profile and the port defaults. A table can have a mask, and the coverage report and `coverage::unread` print each key through it. The tests use the synthetic running config and JSON sections in `crates/rsim-ingest/tests/fixtures/nxos/`; the config has fake secrets. `links.rs` holds the one link join of the estate: each device gives a summary (its ports with their entry functions, MACs and layer 3 addresses, its neighbour records, its MAC table and ARP rows, its next hops); the NX-OS switches, the VyOS routers and the root devices of each UniFi site give one, and the join gives the peers of each port and the place of each endpoint; it knows no vendor, and `tests/links.rs` tests it on hand-built summaries. `estate.rs` joins the routers, the UniFi sites and the NX-OS switches into one twin; it lowers each NX-OS switch twice, first for its summary and then with its links and endpoints; `estate::assemble` takes the device inputs, so the tests in `tests/estate.rs` run on the synthetic sections in `crates/rsim-ingest/tests/fixtures/unifi/` with no store.

CI is in `.github/workflows/ci.yml`. For each pull request, it runs the format check, clippy and the tests on Linux `amd64`. It does not run for a change of only Markdown files. A new push cancels the run of the older push of the same branch. The tests compile with `opt-level = 1`, and the dependencies with `opt-level = 2`.

## What the project is

The project is a Rust engine for a network digital twin. The engine compiles configs and collected state into typed network functions that stay in memory. The engine converges the routing internally. To answer reachability questions and policy questions, the engine sends packets or packet sets through the functions. Each answer has a full trace.

The scale target is 10,000+ routers and 50,000+ endpoints.

Section 3 of the brief shows the data flow and the crate layout. The project name is `rsim`, and each crate has the `rsim-` prefix.

## Rules that constrain all code

Section 2 of the brief gives 5 principles. Each principle changes how you write code.

| Principle | Effect on code |
|---|---|
| No confident wrong answers | Return `Unknown` with a reason when the engine cannot be sure. `Unknown` is a valid result. Do not report it as an error. |
| Deterministic | Do not use clocks or randomness. Do not let a result depend on the iteration order of an unordered collection. |
| Provenance everywhere | Each function instance keeps the source spans from which it came. A source span is a file and a line range. |
| Vendor behaviour is data | Put vendor defaults, tie-breakers and implicit rules in vendor behaviour profiles. Do not put them in engine code. |
| Functions written for simulation | Do not add packet buffers, checksums, queues, timers or I/O. |

## Function contract

Section 5 of the brief defines the contract for each function type. The `NetFunction` trait and the `Branch` struct in that section are illustrations. The implementer selects the final form. These invariants are not optional:

- A function accepts a `PacketSet` and returns one or more branches. The branches partition the input. No packet is lost and no packet is duplicated. At a forwarding choice, this rule applies in each alternative. At a flood, it applies in each copy.
- A function declares the context attributes that it needs and the context attributes that it supplies. The compile step of the twin validates the composition. A violation is a build error for that twin.
- A function declares the objects that it reads. These declarations control delta recompilation.
- A function declares the QoS header fields that it reads and writes. The context attribute declarations cover the QoS attributes. Refer to section 16.
- `FlowState` goes into a function and comes out of a function as a value. Do not hide session state or NAT state in a function.
- If part of a function came from an unhandled config stanza, the function returns `Unknown` for the affected packets. If only the match set of a predicate is incompletely known, use the match bounds in item 7 of section 5.

The delay, the alternative of a forwarding choice and the rate condition are part of the core types from step 1. Delay is virtual time. A function does not sleep. An unknown delay stays unknown, and the total is then a lower bound. Refer to section 12.

## Semantics

Sections 4, 5 and 7 of the brief define the semantics. Use the result types `Outcome` and `Unknown`. Do not use the result words `open`, `split` and `partly`.

- **Original request.** A `PacketSet` holds pairs of the original request header and the current header. A rewrite changes only the current header.
- **Forwarding choice.** The same packets can go to more than one alternative, for example on equal-cost paths. The engine follows each alternative in a fixed order. The answer shows each path with its own result and a summary over all paths. Section 7 gives the rule.
- **Match bounds.** An uncertain match set has a definite set and an upper bound. `Unknown` applies only to packets for which the continuations give different outcomes.
- **Knowledge mask and header validity.** An unstated field is not a field with all values. A field exists only where its header is present.
- **Loop.** A loop is a return to the same full state. A second visit to a device is not proof of a loop.
- **Reply header.** An echo request gives an echo reply. TCP flags with only SYN give SYN and ACK. All other TCP flags and ICMP types, the DSCP and the ECN are unstated in the reply.

## QoS and the 3D function view

Section 16 of the brief makes each function QoS aware. Section 17 defines the 3D function view.

- The QoS fields of the packet and the QoS context attributes are part of the core types from step 1, the same as the delay field.
- A function with no declared QoS write passes the marking and the class unchanged.
- Before step 8, lowering changes a QoS stanza into a function that forwards the packets and makes the marking and the class unknown. The trace step names the stanza as not evaluated.
- Functions calculate the marking, the traffic class and the selected queue. Do not simulate queues or rates. For a policer, a shaper or a queue drop, record a rate condition on the branch. With no load data, the branch keeps its outcome. Do not follow the exceed continuation.
- An unhandled QoS stanza does not make a path `Unknown` by itself. The marking becomes unknown, and a later function that reads it uses the match bounds.
- For a query run, the executor emits the events for the 3D view from the trace. The routing step and the delta step emit their own events. Do not put I/O in a function. Do not put render code in the engine.
- The anchor positions and the event stream are deterministic.

## Layer 2

Section 18 of the brief defines layer 2 for the UniFi estate. The first two vendors are UniFi and VyOS.

- The layer 2 fields of the packet and the flood copy are part of the core types from step 1. The layer 2 functions come in step 3.
- A bridge domain is one flood domain. Do not use the VLAN number as its identity.
- A flood is a replication. The rule for a forwarding choice does not apply to it. Section 7 gives its verdict rule.
- The MAC table, the ARP table, the port state and the client attachment are collected state from the snapshot store. Do not calculate spanning tree.

## Current information only

Docs, code comments, docstrings, commit-tracked notes and test descriptions state only the current design and the current state. Do not refer to earlier decisions, earlier designs, earlier values or rejected options. Do not write "was", "previously", "changed from", "instead of" or "no longer" about the project. If a design or a value changes, overwrite the old text. Git history keeps the old states.

## Other design constraints

- Hide the `PacketSet` representation behind the interface in section 4. The representation is an in-house decision diagram engine. OxiDD is a development dependency for tests only, as the oracle for the set operations. Do not make it a dependency of the product.
- The prefix table is in-house, behind a trait.
- Only the `rsim-collect` crate talks to devices. It writes the append-only snapshot store, and the engine reads only the store.
- Lowering changes vendor structures directly into function instances. There is no vendor-neutral config model between them. Refer to section 9.
- The structural parsers contain no vendor knowledge. Classify each stanza as handled, known-irrelevant or unhandled. Do not drop a stanza silently.
- Routing convergence gives one of three results: `Converged`, `MultipleStableOutcomes` or `NoConvergence`. Detect the last two. Do not hide them behind an iteration limit.
- The compiled twin is immutable for each version and is not persisted. The source snapshots are persisted append-only. Rebuild the twin from the sources.
- Batfish is a test aid for oracle comparison only. Do not make it a dependency of the product.
- The product is Rust. `ring` is the only dependency that builds C code, and only `rsim-collect` uses it, for SSH and TLS. Do not add another dependency that builds C or C++ code. Do not turn on `aws-lc-rs` in `russh`, `rustls` or `tokio-rustls`. `blake3` uses its `pure` feature, and `parquet` uses the pure Rust Snappy codec. On Linux, the dependency tree has no `-sys` crate. On macOS, `chrono` adds `core-foundation-sys`, a binding to a system framework.
- `russh` is pinned to one exact version. Turn on the `Legacy` SSH algorithm set only for the devices that need it.
- Only `rsim-collect` uses an async runtime. A clock and random bytes are used only in `rsim-collect` and in the writer of `rsim-store`. The reader of `rsim-store` uses neither.

## Build order

Section 13 of the brief gives the steps, each with a "Done when" condition. Do the steps in sequence. Steps 1, 1b and 2 are complete. Step 1b gives these rules for `rsim-cli` and `rsim-mcp`:

- `rsim-topologies` holds the hand-built topologies. The tests, the benchmarks, `rsim-cli` and `rsim-mcp` use it.
- `rsim-cli` and `rsim-mcp` load a built-in topology by name and run a path query for one packet with its reply.
- The JSON output is versioned and deterministic: the same query gives the same bytes.
- `rsim-mcp` uses the stdio transport, has the tools `list_devices`, `path_query`, `set_query` and `explain_step`, and writes nothing. With `--store <data folder>`, the topology `store` is the newest snapshot of that store when a call first names it. A tool call cannot name another store.
- A topology name `store:<data folder>` loads the twin of the newest snapshot of a store through `rsim-ingest`. The store is opened with `Store::open_read`, which writes nothing. It keeps no answer between calls. `explain_step` takes the query, the branch index and the step index, and runs the query again.
- The libraries are `serde` and `serde_json` for JSON and `clap` for the arguments. The MCP protocol code is in-house and has no async runtime.
- The JSON output is version 2. The summary is a list of parts, and each packet value is a set of members with field values. The field names are the names of the Elastic Common Schema where it has one, for example `source.ip`.

`../rsim-project/design/step-1b-cli-mcp.md` gives the design of step 1b.

Step 2 is complete: the packet-set engine in `rsim-dd`, `PacketSet` on `rsim-dd`, the sessions as relations, set-mode execution, the ingress resolver, JSON version 2, the set input of the query, `rsim set`, `set_query` and the set benchmark. `../rsim-project/design/step-2-packet-set.md` gives the design.

Step 3 is the current step. The store, the collector, the ingestion of VyOS, UniFi and NX-OS, the path questions on a store and the one link join are complete. The EVPN, VXLAN and anycast gateway batch is in progress (`../rsim-project/design/vendors.md`). The snapshot view comes later in step 3. Step 3 then adds the next vendors in this order: IOS-XR and IOS-XE. HST (`../HST`) is the reference for the commands and the parsing of each vendor; port its tested behaviour and do not design a collector from nothing. `../rsim-project/design/step-3-collect.md` gives the design.

Section 14 gives the test types. The property tests are: branches partition the input in each alternative of a forwarding choice and in each copy of a flood, the result is deterministic, and concrete mode agrees with set mode.

## Open decisions

Section 15 of the brief lists the decisions that belong to the owner. Each item is decided. Four points are open, and the brief marks each one:

- Step 7. The source of the formula for the queueing delay.
- Step 8. The field of `RateCondition` that holds the result of an evaluation.
- Step 9. The location of the declaration of the editable parameters of each function type, and a trial scene for the look of the 3D view.

Do not make these decisions silently.

`../rsim-project/design/step-1b-cli-mcp.md` gives the design of step 1b. `../rsim-project/design/step-2-packet-set.md` gives the design of step 2. `../rsim-project/design/step-3-collect.md` gives the design of step 3. If your work needs a decision that the brief and the design notes do not have, ask the owner.
