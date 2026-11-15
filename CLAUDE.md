# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

Steps 1 and 1b of the build are complete. Step 2 is in progress: the packet-set engine in `rsim-dd` and set-mode execution. Step 2 comes in 3 pull requests. Pull request 1 is the crate `rsim-dd`. Pull request 2 puts `PacketSet` on `rsim-dd`. `../rsim-project/roadmap.md` gives the order. The Cargo workspace has 7 crates in `crates/`: `rsim-core`, `rsim-dd`, `rsim-functions`, `rsim-engine`, `rsim-topologies`, `rsim-cli` and `rsim-mcp`. The other crates of section 3 come with their steps.

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
| One trace step | `cargo run -p rsim-cli -- explain mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --destination.port 53 --branch 0 --step 7` |
| MCP server on stdio | `cargo run -p rsim-mcp` |
| Decision diagram tests | `cargo test -p rsim-dd` |
| Decision diagram tests, release build with the validator | `cargo test -p rsim-dd --release --features dd-check` |
| Decision diagram benchmark | `cargo bench -p rsim-dd --bench ops` |

The hand-built topologies are in the crate `rsim-topologies`, with one module for each topology in `crates/rsim-topologies/src/`. The tests and the benchmarks of `rsim-engine` use it as a development dependency. `rsim-topologies::builtin(name)` gives the twin of a built-in topology.

The stored JSON answers of the CLI tests are in `crates/rsim-cli/tests/golden/`. The CLI test and the MCP stdio test compare their outputs with these files. If an intended change alters the JSON output, make the files again with `rsim path <topology> <flags> --format json`. The flags of each file are in `QUERIES` in `crates/rsim-cli/tests/cli.rs`.

`rsim-core` keeps the packet sets in `packet_set.rs`, the bit table in `bits.rs`, the arenas in `set.rs` and the description of a set as members in `describe.rs`. `crates/rsim-core/tests/explicit_oracle.rs` compares each set operation with an explicit list of packet pairs. A path query runs on the set of its packet; the design note gives the rule for an unstated field. The ingress of a query comes from `--ingress` or from the attachment records and edge interfaces of the twin.

The tests of `rsim-dd` turn on the feature `dd-shadow` through a development dependency of the crate on itself. Each public operation then also runs in a plain BDD, and the 2 results must be the same set. A benchmark turns the shadow check off with `Dd::set_shadow(false)`. The OxiDD oracle in `crates/rsim-dd/tests/oracle.rs` compares the results with OxiDD on 2,289 levels. OxiDD is a development dependency only.

`crates/rsim-cli/clippy.toml` and `crates/rsim-mcp/clippy.toml` deny the file write functions and the network socket types. Only a test helper can allow them.

CI is in `.github/workflows/ci.yml`. For each pull request, it runs the format check, clippy, the build and the tests on Linux `amd64`.

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

- Hide the `PacketSet` representation behind the interface in section 4. The representation is an in-house decision diagram engine. OxiDD is a development dependency for tests only, as the oracle for the set operations. Do not make it a dependency of the product. Until step 2, the only implementation is a set with one concrete packet.
- The prefix table is in-house, behind a trait.
- Only the `rsim-collect` crate talks to devices. It writes the append-only snapshot store, and the engine reads only the store.
- Lowering changes vendor structures directly into function instances. There is no vendor-neutral config model between them. Refer to section 9.
- The structural parsers contain no vendor knowledge. Classify each stanza as handled, known-irrelevant or unhandled. Do not drop a stanza silently.
- Routing convergence gives one of three results: `Converged`, `MultipleStableOutcomes` or `NoConvergence`. Detect the last two. Do not hide them behind an iteration limit.
- The compiled twin is immutable for each version and is not persisted. The source snapshots are persisted append-only. Rebuild the twin from the sources.
- Batfish is a test aid for oracle comparison only. Do not make it a dependency of the product.

## Build order

Section 13 of the brief gives the steps, each with a "Done when" condition. Do the steps in sequence. Steps 1 and 1b are complete. Step 1b gives these rules for `rsim-cli` and `rsim-mcp`:

- `rsim-topologies` holds the hand-built topologies. The tests, the benchmarks, `rsim-cli` and `rsim-mcp` use it.
- `rsim-cli` and `rsim-mcp` load a built-in topology by name and run a path query for one packet with its reply.
- The JSON output is versioned and deterministic: the same query gives the same bytes.
- `rsim-mcp` uses the stdio transport, has the tools `list_devices`, `path_query` and `explain_step`, and writes nothing. It keeps no answer between calls. `explain_step` takes the query, the branch index and the step index, and runs the query again.
- The libraries are `serde` and `serde_json` for JSON and `clap` for the arguments. The MCP protocol code is in-house and has no async runtime.
- The JSON output is version 2. The summary is a list of parts, and each packet value is a set of members with field values. The field names are the names of the Elastic Common Schema where it has one, for example `source.ip`.

`../rsim-project/design/step-1b-cli-mcp.md` gives the design of step 1b.

Step 2 is the current step: the packet-set engine in `rsim-dd` and set-mode execution. Pull request 1 is the crate `rsim-dd`. Pull request 2 is `PacketSet` on `rsim-dd`, the sessions as relations, set-mode execution, the ingress resolver, JSON version 2 and the JSON set form. Pull request 3 is the set input of the query, `rsim set`, `set_query` and the set benchmark. `../rsim-project/design/step-2-packet-set.md` gives the design.

Section 14 gives the test types. The property tests are: branches partition the input in each alternative of a forwarding choice and in each copy of a flood, the result is deterministic, and concrete mode agrees with set mode.

## Open decisions

Section 15 of the brief lists the decisions that belong to the owner. Each item is decided. Four points are open, and the brief marks each one:

- Step 7. The source of the formula for the queueing delay.
- Step 8. The field of `RateCondition` that holds the result of an evaluation.
- Step 9. The location of the declaration of the editable parameters of each function type, and a trial scene for the look of the 3D view.

Do not make these decisions silently.

`../rsim-project/design/step-1b-cli-mcp.md` gives the design of step 1b. `../rsim-project/design/step-2-packet-set.md` gives the design of step 2. If your work needs a decision that the brief and the design notes do not have, ask the owner.
