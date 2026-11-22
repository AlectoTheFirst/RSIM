# CLAUDE.md

Instructions for Claude Code in this repository.

## Where to find

- `STATUS.md`: the state of the build steps
- `../rsim-project/BUILD_BRIEF.md`: the build specification. It governs when 2 documents disagree.
- `../rsim-project/PROJECT_SUMMARY.md`: the reasoning. Read it first.
- `../rsim-project/roadmap.md`: the order of the work
- `../rsim-project/design/architecture.md`: the crates, the modules, the tools and CI
- `../rsim-project/design/step-1b-cli-mcp.md`, `../rsim-project/design/step-2-packet-set.md` and `../rsim-project/design/step-3-collect.md`: the design of steps 1b, 2 and 3
- `../rsim-project/design/vendors.md`: the vendor rules and the transports
- `../rsim-project/design/http-api.md`: the API specification
- `../rsim-project/design/twin-reload.md`: the reload of the store twin and the delta twin
- `../rsim-project/design/rib-fib.md`: the forwarding table
- `../rsim-project/design/ui-design-language.md`: the UI tokens and section 7.1 "Forbidden prose"
- `../HST`: the reference for the commands and the parsing of each vendor

## Public repository

- This repository is public. Do not commit the design documents, real configs, collected state, private keys or host names of the owner's infrastructure.
- Test fixtures use only documentation addresses and documentation MAC addresses. A fixture config has fake secrets. Tests make their keys and certificates at test time.
- The env file and the data folder of `rsim-collect` stay outside the repository.

## Where documentation goes

This repository holds only code, tests, usage how-tos, `STATUS.md` and the information that the owner selects for it, such as the README. All other documentation goes in `../rsim-project/`: design notes, benchmark records, fixtures, reports and project notes. Do not add a `docs/` folder or another documentation file to this repository unless the owner asks for it.

| Item | Location |
|---|---|
| Design notes | `../rsim-project/design/` |
| Crates and modules | `../rsim-project/design/architecture.md` |
| Roadmap | `../rsim-project/roadmap.md` |
| Benchmark records | `../rsim-project/benchmarks.md` |
| Baseline fixtures | `../rsim-project/fixtures/` |
| Data folder of the `ci` Neo4j baseline | `../rsim-project/neo4j-baseline-data/` |

## Code comments

A comment or a docstring describes the code that it belongs to. Do not write design text, reasons for a decision, build step numbers or section numbers of the brief in the code. Design text goes in `../rsim-project/`.

## Current information only

Docs, code comments, docstrings, commit-tracked notes and test descriptions state only the current design and the current state. Do not refer to earlier decisions, earlier designs, earlier values or rejected options. Do not write "was", "previously", "changed from", "instead of" or "no longer" about the project. If a design or a value changes, overwrite the old text. Git history keeps the old states.

## No AI slop

AI slop in any form is forbidden. The rule has no exception. It applies to each text that Claude writes for this project:

- the product text: a label, a button, a column head, a section head, a placeholder, a hint, a note, a `title`, an `aria-label`, an option of a select, an empty state
- the API text: a problem title and detail, a description of a table, a column, a claim, an operation, an argument or a field, an OpenAPI or MCP text, a CLI help text and error
- the reason text of the engine and the evidence text of a claim
- the README, `STATUS.md`, the docs, the design notes in `../rsim-project/`, the code comments, the docstrings and the test names
- the commit messages, the pull request texts, the review comments and the answers to the owner

AI slop is text that a generator adds and a person does not need: padding, explanation that nobody asked for, hedging, comparison, selling, narration, summary, decoration, false precision or false warmth. The tables below list known forms. They are not complete. A text in any of these forms is forbidden, also when no listed word is in it. Write the fact and stop.

### Product text

- A name is the bare name of the thing, with nothing added: "Network functions", "Forwarding table", "Manifest time", "Next hops". No qualifier, no "with ...", no "of the twin", no format, no unit, no list of values, no second part after a comma or a colon. A unit goes in the `unit` field of a column or a setting.
- A label names a thing or a state in a few words: "not known", "no reply", "no secret key", "no device group". A button names its action: "Add credential", "Delete core-01", "Select entry point".
- A label, a hint, a note or a description is never a sentence. No full stop. A `title` holds one short phrase at most.
- A section head has no note that explains the section, its rules or its security.
- No text explains why a thing is absent, disabled or not used. A setting, a field or a control that does nothing for the record is not shown. "not used over HTTPS" and "not read by the collector" are slop.
- No text repeats what the page already shows. A count, a total or a summary box that a person does not act on is slop: "12 not stated", "22 functions on 3 devices", "2 route lookups, no RIB check", "Deliver 0".
- A value shows as the value itself, in full. "varies", "mixed", "several" or a cut text with an ellipsis in place of the value is slop. A value with no information shows the hatch with "not available". A value that the twin cannot know shows the hatch with "not known".
- No key hints, tips, onboarding text, help paragraphs or legends that explain the controls.
- Sentence case, present tense. No Title Case, no ALL CAPS.

### Docs, design notes, STATUS.md and the README

- State the current design and the current facts only. No reason why, no history, no earlier decision, no rejected option, no comparison with an earlier state, no conjecture, no plan written as a fact.
- No introduction, no "Overview" that restates the headings, no closing summary, no "Why X?" or "Features" sales section, no "Next steps" that nobody asked for.
- A number in place of a vague quantity: "3 devices", not "several devices" or "a number of devices".
- The concrete noun in place of an abstract noun: "the collector reads the inventory", not "the collection functionality leverages inventory capabilities".

### Code comments, docstrings and test names

- A comment states what the code does or holds, in the terms of the code. It does not narrate obvious code, it does not address the reader, it gives no reason for a decision, and it does not hedge.
- No "Note:", "Here we", "This function", "Simply", "Basically", "Helper to", "Handles the case where", "TODO: maybe".

### Commit messages, pull request texts and answers to the owner

- A commit message names the change: "rsim-collect: random store keys in the demo test". No "This commit", "Refactor to improve", "Enhance", "Update X to better", "various fixes".
- A pull request text lists the changes and the checks. No sales text, no "This PR", no summary of the summary.
- An answer to the owner leads with the result, and then gives only the facts that the owner needs. It does not praise the question, it does not apologize, it does not restate the question, it does not narrate what Claude is about to do in more than one sentence, it does not end with an offer or a question that nobody needs, and it does not claim a result that no check confirmed.
- Options go to the owner only when the owner must decide. Each option has a distinct label. One question at a time when the questions depend on each other.

### Forbidden forms

| Form | Examples |
|---|---|
| Sentences and explanations in product text | "A jump host never gets the device credential.", "RSIM keeps the reference. The secret stays in its source.", "The network functions of the twin, with the source lines from which each came." |
| Qualifiers in a name | "network functions with source lines", "manifest time, UTC", "next hops as `<gateway>@<interface>`", "devices of the twin with their facts" |
| Notes on what does not apply | "not used over HTTPS", "not read by the collector", "only for NX-OS", "has no effect here" |
| Redundant text | a value that the page shows elsewhere, a count or a summary box that no person acts on, a count of 0 |
| Placeholder values | "varies", "mixed", "N/A", "TBD", "...", "etc.", "and more", "and so on" |
| Conjectures and hedges | might, may, could, likely, probably, possibly, perhaps, seems, appears to, it looks like, should work, typically, generally, usually, in most cases, tends to, arguably, to some extent |
| Vague quantities | several, various, numerous, a number of, many, some, a few, a lot of, significant, substantial, a wide range of |
| Comparisons | instead of, rather than, unlike, better than, more than before, no longer, now as a comparison, compared to, as opposed to, whereas, while (as a contrast) |
| Filler and intensifiers | simply, just, easily, actually, really, basically, quickly, fully, truly, very, quite, rather, pretty, literally, essentially, of course, clearly, obviously, needless to say, it goes without saying |
| Connectors of generated text | furthermore, moreover, additionally, in addition, notably, importantly, ultimately, effectively, indeed, that said, with that in mind, to that end, as such, in other words, that is to say, this means that |
| Hype words and Claudisms | seamless, seamlessly, powerful, robust, comprehensive, intuitive, effortless, elegant, clean, smart, intelligent, modern, lightweight, blazing, leverage, unlock, empower, elevate, streamline, delve, dive into, explore, journey, landscape, realm, crucial, vital, pivotal, paramount, essential, key (as an adjective), ensure, holistic, nuanced, intricate, meticulous, tailored, foster, harness, enhance, showcase, underscore, testament, tapestry, beacon, embark, navigate (as a metaphor), boasts, myriad, plethora, a variety of, ever-evolving, game-changer, cutting-edge, next-level, state-of-the-art, best-in-class, world-class, revolutionize, supercharge |
| Buzzword phrases | best practices, out of the box, under the hood, at scale, end-to-end, first-class, battle-tested, production-ready, single source of truth, peace of mind, gracefully, with ease |
| Abstract nouns | functionality, capability, capabilities, solution, mechanism, utilize, facilitate, in order to, the ability to |
| Talk to the user | you, your, you can, feel free to, let's, we, our, please, don't worry, great, oops, sorry, rest assured |
| Chat forms | Certainly, Absolutely, Of course, Sure, Great question, Good catch, You're right to ask, I hope this helps, Happy to help, Let me know if, I'd be glad to, It is important to note, To be clear, Honestly, Frankly |
| Meta-commentary | I will now, Let me, As an AI, As mentioned, As noted above, In this section, The following, This document describes |
| Narration | Here is, Below you will find, This view shows, This page lets, Note that, Keep in mind, It is worth noting |
| Summaries | In short, Overall, In summary, All in all, To sum up, In conclusion, TL;DR, Key takeaways |
| Rhetorical forms | a question in a label or a heading, "Not only ... but also", "It's not X, it's Y", "X, Y, and Z" lists and groups of 3 adjectives for rhythm, a sentence fragment for effect |
| Decoration | emoji, glyphs such as `·`, `→`, `✓`, `✔`, `✕` and `•`, an em dash, an ellipsis as style, an exclamation mark, quotation marks for emphasis, bold for emphasis in running text, a heading or a table for 2 items |

Before a change is done, read each new or changed text of the change against this section. Section 7.1 "Forbidden prose" of `../rsim-project/design/ui-design-language.md` carries the same rule.

## Where to build

- Build and test in CI or in the Kubernetes cluster of the owner, never on the laptop of the owner. This covers each `cargo build`, `cargo test`, `cargo clippy`, `cargo bench`, release build, container build and local server of the workspace, also for one crate.
- Allowed on the laptop: editing, `cargo fmt`, and `npm --prefix ui run build` and `npm --prefix ui test`.
- A heavier local run needs the approval of the owner for that task. Do not ask for it: the owner says when a local run is fine.
- To check a change: push the branch and read the result of CI (`gh pr checks`, `gh run view --log-failed`). To build the images: the build Job of the cluster.

## Disk space

- Build in the shared folder `target` of this repository. For a build of a worktree or another checkout, set `CARGO_TARGET_DIR` to that folder.
- Do not make a separate target folder for a worktree, a branch, a benchmark or a check.
- Do not copy the source tree to make a build. Use a worktree.
- When the work of a worktree, a scratch folder or a source copy is done, delete it.
- Before a full build, a benchmark or a release build, do a check of the free space with `df -h`. If less than 20 GB is free, stop and tell the owner.
- If the folder `target/debug/incremental` is more than 20 GB, delete it.

## Commands

Run builds and tests by the rule "Where to build": CI or the cluster of the owner.

| Task | Command |
|---|---|
| Build | `cargo build --workspace` |
| All tests | `cargo test --workspace` |
| One test file | `cargo test -p <crate> --test <file>`, for example `cargo test -p rsim-engine --test forwarding` |
| One test | `cargo test -p rsim-engine --test forwarding guest_to_dns_through_firewall_snat_ips_and_acl_and_back` |
| Lint | `cargo clippy --workspace --all-targets` |
| Format check | `cargo fmt --all --check` |
| A command on a hand-built topology | `cargo run -p rsim-cli --features test-fixtures -- path mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --source.port 40000 --destination.port 53` |
| Source line mask tests | `cargo test -p rsim-ingest --lib mask` |
| Decision diagram tests with the validator | `cargo test -p rsim-dd --release --features dd-check` |
| SQL tests | `/opt/podman/bin/podman run -d --rm --name rsim-pg -e POSTGRES_USER=rsim -e POSTGRES_PASSWORD=rsim-test -e POSTGRES_DB=rsim_test -p 127.0.0.1:5432:5432 docker.io/library/postgres:17.6`, then `RSIM_TEST_DATABASE_URL=postgres://rsim:rsim-test@127.0.0.1:5432/rsim_test cargo test --workspace`, then `/opt/podman/bin/podman stop rsim-pg`. With `RSIM_TEST_DATABASE_URL` unset, the SQL tests print that they are skipped and pass. |
| Install the UI dependencies | `npm --prefix ui ci` |
| Build the UI | `npm --prefix ui run build`: the type check and the Vite build into `ui/dist`, which `rsim-api` embeds at build time. Build `rsim-api` again after it. |
| UI tests | `npm --prefix ui test` |
| UI types from the OpenAPI document | `npm --prefix ui run api`; `npm --prefix ui run api:check` fails if a generated file is not current |
| Stored answers of the CLI | `cargo run -p rsim-cli --features test-fixtures -- path <topology> <flags> --format json`, with the flags of each file in `QUERIES` of `crates/rsim-cli/tests/cli.rs`; `set-mini-enterprise.json` from `set` with the flags of `SET_QUERY` |
| Stored answers of the BGP claims | `RSIM_BLESS=1 cargo test -p rsim-cli --test bgp_claims` writes `claim-bgp-*.json` |
| Helm chart | `helm lint --strict deploy/helm/rsim -f deploy/helm/rsim/ci/<instance>-values.yaml` and `helm template <instance> deploy/helm/rsim -f ...` for the instances `rsim`, `rsim-dev` and `rsim-demo` |
| Forwarding table benchmark | `cargo bench -p rsim-functions --bench fib`; `RSIM_FIB_SKIP_ALL=1` leaves out the split of all destinations |
| Scale benchmark | `RSIM_SCALE_PERCENT=1 cargo bench -p rsim-cli --bench scale`, with `RSIM_SCALE_PHASES`, `RSIM_SCALE_FILL=0` and `RSIM_SCALE_CAP_GIB` (default 12). The `table` phase runs only up to 50 % on a 16 GB machine. |
| API load test | `cargo run --release -p rsim-api --example load -- 1,4 20`: clients, then requests per client. Keep the numbers small. |

`architecture.md` lists the options of `rsim`, `rsim-api`, `rsim-collect`, `rsim-inventory`, the examples and the benchmarks.

## Rules for code

### Principles

Section 2 of the brief gives 5 principles.

| Principle | Rule |
|---|---|
| No confident wrong answers | Return `Unknown` with a reason when the engine cannot be sure. `Unknown` is a valid result. Do not report it as an error. |
| Deterministic | Do not use clocks or randomness. Do not let a result depend on the iteration order of an unordered collection. |
| Provenance everywhere | Each function instance keeps the source spans from which it came. A source span is a file and a line range. |
| Vendor behaviour is data | Put vendor defaults, tie-breakers and implicit rules in vendor behaviour profiles. Do not put them in engine code. |
| Functions written for simulation | Do not add packet buffers, checksums, queues, timers or I/O. |

### Function contract

Section 5 of the brief defines the contract. The `NetFunction` trait and the `Branch` struct there are illustrations; the implementer selects the final form. These invariants hold:

- A function accepts a `PacketSet` and returns one or more branches. The branches partition the input: no packet is lost and no packet is duplicated, in each alternative of a forwarding choice and in each copy of a flood.
- A function declares the context attributes that it needs and supplies. The compile step of the twin validates the composition; a violation is a build error for that twin.
- A function declares the objects that it reads. These declarations control delta recompilation.
- A function declares the QoS header fields that it reads and writes. The context attribute declarations cover the QoS attributes (section 16).
- `FlowState` goes into a function and comes out of it as a value. Do not hide session state or NAT state in a function.
- If part of a function came from an unhandled config stanza, the function returns `Unknown` for the affected packets. If only the match set of a predicate is incompletely known, use the match bounds of item 7 of section 5.
- The delay, the alternative of a forwarding choice and the rate condition are core types. Delay is virtual time. A function does not sleep. An unknown delay stays unknown, and the total is then a lower bound (section 12).

### Semantics

Sections 4, 5 and 7 of the brief define the semantics. Use the result types `Outcome` and `Unknown`. Do not use the result words `open`, `split` and `partly`.

- **Original request.** A `PacketSet` holds pairs of the original request header and the current header. A rewrite changes only the current header.
- **Forwarding choice.** The same packets can go to more than one alternative, for example on equal-cost paths. The engine follows each alternative in a fixed order. The answer shows each path with its own result and a summary over all paths (section 7).
- **Exit.** A packet that leaves the twin on an edge interface ends in `Exit` with the device and the interface. An edge interface has no link, and its device marks it as an edge (`ExitMark` of `Egress`): a PPPoE interface, an interface that the owner marks, or an interface of a next hop of the default route of the main table whose gateway is outside the twin. `ExitMark::DefaultRoute` holds those gateways, and only the packets whose next hop is one of them exit; the mark of `::/0` applies only to IPv6 packets. A gateway that is an address of a device of the twin, a next hop with no gateway, a link-local gateway and a WireGuard interface give no mark. An egress with no link on another interface, or with another next hop, is `Unknown`. `Exit` is a terminal verdict like `Deliver` and `Drop`, and it is not `Unknown`. ECMP paths combine by equality and kind, a flood is `Exit` if no copy delivers and at least one copy exits, and an `Exit` branch has no reply. The JSON value of the verdict kind and the outcome kind is `exit`.
- **Match bounds.** An uncertain match set has a definite set and an upper bound. `Unknown` applies only to packets for which the continuations give different outcomes.
- **Knowledge mask and header validity.** An unstated field is not a field with all values. A field exists only where its header is present.
- **Loop.** A loop is a return to the same full state. A second visit to a device is not proof of a loop.
- **Reply header.** An echo request gives an echo reply. TCP flags with only SYN give SYN and ACK. All other TCP flags and ICMP types, the DSCP and the ECN are unstated in the reply.

### QoS and the 3D function view

Section 16 of the brief makes each function QoS aware. Section 17 defines the 3D function view.

- The QoS fields of the packet and the QoS context attributes are core types, as the delay field is.
- A function with no declared QoS write passes the marking and the class unchanged.
- Before step 8, lowering changes a QoS stanza into a function that forwards the packets and makes the marking and the class unknown. The trace step names the stanza as not evaluated.
- Functions calculate the marking, the traffic class and the selected queue. Do not simulate queues or rates. For a policer, a shaper or a queue drop, record a rate condition on the branch. With no load data, the branch keeps its outcome. Do not follow the exceed continuation.
- An unhandled QoS stanza does not make a path `Unknown` by itself. The marking becomes unknown, and a later function that reads it uses the match bounds.
- For a query run, the executor emits the events for the 3D view from the trace. The routing step and the delta step emit their own events. Do not put I/O in a function. Do not put render code in the engine.
- The anchor positions and the event stream are deterministic.

### Layer 2

Section 18 of the brief defines layer 2.

- The layer 2 fields of the packet and the flood copy are core types.
- A bridge domain is one flood domain. Do not use the VLAN number as its identity.
- A flood is a replication. The rule for a forwarding choice does not apply to it. Section 7 gives its verdict rule.
- The MAC table, the ARP table, the port state and the client attachment are collected state from the snapshot store. Do not calculate spanning tree.

### Design constraints

- Hide the `PacketSet` representation behind the interface of section 4. The representation is the in-house decision diagram engine `rsim-dd`.
- The prefix table is in-house, behind a trait.
- Only `rsim-collect` talks to devices. It writes the snapshot store, and the engine reads only the store.
- Lowering changes vendor structures directly into function instances. There is no vendor-neutral config model between them (section 9).
- The structural parsers contain no vendor knowledge. Classify each stanza as handled, known-irrelevant or unhandled. Do not drop a stanza silently.
- A new handled path needs a handler that reads it.
- Routing convergence gives one of 3 results: `Converged`, `MultipleStableOutcomes` or `NoConvergence`. Detect the last 2. Do not hide them behind an iteration limit.
- The compiled twin is immutable for each version and is not persisted. The source snapshots are persisted: the writer adds files, and only the prune of the history deletes them. Rebuild the twin from the sources.
- The engine does not read the inventory database. A twin is built from the snapshot store only.
- `rsim-contract` has no engine dependency. `links.rs` of `rsim-ingest` knows no vendor.
- `rsim-store` and `rsim-ingest` have no network code.
- `ui/src/app.css` uses only the CSS custom properties of `ui/src/theme.ts`.

### Dependencies and runtime

- The product is Rust. `ring` is the only dependency that builds C code, and only `rsim-collect` and `rsim-inventory` use it, for SSH and TLS; `rsim-api` has it through `rsim-inventory`. Do not add another dependency that builds C or C++ code. A development dependency of the tests or the benchmarks can build C code, for example `alloca` through `criterion`.
- Do not turn on `aws-lc-rs` in `russh`, `rustls` or `tokio-rustls`. `blake3` uses its `pure` feature, and `parquet` uses the pure Rust Snappy codec. On Linux, the dependency tree has no `-sys` crate. On macOS, `chrono` adds `core-foundation-sys` and `whoami` of `tokio-postgres` adds `objc2-system-configuration`, bindings to system frameworks.
- `russh` is pinned to one exact version. Turn on the `Legacy` SSH algorithm set only for the devices that need it.
- OxiDD and Batfish are test aids for oracle comparison only. Do not make them a dependency of the product.
- Only `rsim-collect`, `rsim-inventory` and the server of `rsim-api` use an async runtime.
- A clock and random bytes are used only in `rsim-collect`, in the writer of `rsim-store`, and for the sign-in: `rsim-inventory` makes the random session tokens, API tokens and password salts, and `rsim-api` uses a monotonic timer for the limit of the request rate. The reader of `rsim-store` and `rsim-ingest` use neither. The database gives the time of each audit record, sign-in event and session, so `rsim-api` and `rsim-inventory` read no wall clock.
- `crates/rsim-cli/clippy.toml` and `crates/rsim-mcp/clippy.toml` deny the file write functions and the network socket types. `crates/rsim-api/clippy.toml` denies the file write functions; the server opens its TCP listener and, with `--inventory`, its connection to the inventory database, and it writes only to that database. Only a test helper can allow them.
- The UI dependencies have exact versions in `ui/package.json`, and the lockfile is committed.
- Each GitHub action is pinned by its commit SHA, with the release tag as a comment. Each base image of `Containerfile` is pinned by its digest. `compose.yaml` uses only features of both `podman compose` and Docker Compose.

### CLI, MCP and JSON

- The product has no built-in topology. A twin comes only from collected data, the newest snapshot of a store.
- `rsim-topologies` holds the hand-built topologies, which are test fixtures. The tests, the benchmarks, `rsim-cli` and `rsim-mcp` use it. `rsim-cli` loads them by name only with its feature `test-fixtures`, which only the dev-dependencies of `rsim-cli`, `rsim-mcp` and `rsim-api` turn on: a test build has them and no binary of the product has them. CI fails when `rsim-topologies` is a normal dependency of `rsim-api`, `rsim-cli` or `rsim-mcp`.
- The JSON output is versioned and deterministic: the same query gives the same bytes.
- The JSON output is version 2. The summary is a list of parts, and each packet value is a set of members with field values. The field names are the names of the Elastic Common Schema where it has one, for example `source.ip`.
- If an intended change alters the JSON output, make the stored answers in `crates/rsim-cli/tests/golden/` again (section "Commands"). The CLI test and the MCP stdio test compare their outputs with these files.
- `rsim-mcp` uses the stdio transport and writes nothing. With `--store <data folder>`, the topology `store` is the newest snapshot of that store when a call first names it. A tool call cannot name another store.
- A topology name `store:<data folder>` opens the store with `Store::open_read`, which writes nothing. It keeps no answer between calls.
- The libraries are `serde` and `serde_json` for JSON and `clap` for the arguments. The MCP protocol code is in-house and has no async runtime.

## Work order

- Section 13 of the brief gives the steps, each with a "Done when" condition. Do the steps in sequence.
- For the commands and the parsing of a vendor, port the tested behaviour of HST (`../HST`). Do not design a collector from nothing.
- Section 14 gives the test types. The property tests are: branches partition the input in each alternative of a forwarding choice and in each copy of a flood, the result is deterministic, and concrete mode agrees with set mode.
- Do not make an open decision of the brief silently; ask the owner. The open points:
  - Step 7: the source of the formula for the queueing delay.
  - Step 8: the field of `RateCondition` that holds the result of an evaluation.
  - Step 9: the location of the declaration of the editable parameters of each function type.
  - Step 9: a trial scene for the look of the 3D view.
- If the work needs a decision that the brief and the design notes do not have, ask the owner.
