# CLAUDE.md

Instructions for Claude Code in this repository.

## Where to find

- `STATUS.md`: the state of the build steps, included at the end of this file
- `../rsim-project/BUILD_BRIEF.md`: the build specification. It governs when 2 documents disagree.
- `../rsim-project/PROJECT_SUMMARY.md`: the reasoning. Read it first.
- `../rsim-project/roadmap.md`: the order of the work
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
| Description and commands of each crate and of the UI | `.claude/rules/` |
| Design notes | `../rsim-project/design/` |
| Roadmap | `../rsim-project/roadmap.md` |
| Benchmark records | `../rsim-project/benchmarks.md` |
| Baseline fixtures | `../rsim-project/fixtures/` |
| Data folder of the `ci` Neo4j baseline | `../rsim-project/neo4j-baseline-data/` |

## Code comments

A comment or a docstring describes the code that it belongs to. Do not write design text, reasons for a decision, build step numbers or section numbers of the brief in the code. Design text goes in `../rsim-project/`.

## Current information only

Docs, code comments, docstrings, commit-tracked notes and test descriptions state only the current design and the current state. They do not tell the history of the project: no earlier decision, earlier design, earlier value or rejected option. If a design or a value changes, overwrite the old text. Git history keeps the old states. A text about the running system can use the past tense and state changes: "A collection target no longer exists or is disabled." is correct.

## No AI slop

AI slop is forbidden. It applies to each text that Claude writes for this project:

- the product text: a label, a button, a column head, a section head, a placeholder, a hint, a note, a `title`, an `aria-label`, an option of a select, an empty state
- the API text: a problem title and detail, a description of a table, a column, a claim, an operation, an argument or a field, an OpenAPI or MCP text, a CLI help text and error
- the reason text of the engine and the evidence text of a claim
- the README, `STATUS.md`, the docs, the design notes in `../rsim-project/`, the code comments, the docstrings and the test names
- the commit messages, the pull request texts, the review comments and the answers to the owner

AI slop is a style, not a set of words. It is text that a generator adds and a person does not need. A word is never forbidden by itself. A text is slop when its form matches a style in the table below. Do not change a correct, plain text only because it contains a word that slop text also uses.

### Forbidden styles

| Style | Test | Slop | Plain |
|---|---|---|---|
| Explanation nobody asked for | The text gives a reason, a purpose or a justification that the reader does not need to act. | "COALESCE because NULLs are distinct in a unique index, and ..." | "COALESCE maps NULL to 0 for the unique index." or no comment |
| History and comparison | The text compares the current state with an earlier state of the project or with a rejected option. | "The cap is now per user rather than per process." | "The cap is per user." |
| Contrast pairs | The text states what a thing is not, next to what it is. | "says the file is missing, not that the table was empty" | "says that the file is missing" |
| Hedging | The text weakens a fact that the code or the data settles. | "This should usually return the newest run." | "This returns the newest run." |
| Vague amounts | The text gives a size or a count without the number, when the number is known. | "several devices" | "3 devices" |
| Selling | The text praises the product or the code. | "a robust, seamless trace engine" | "the trace engine" |
| Narration | The text describes what the reader sees, what the code obviously does, or what the text is about to say. | "Here we loop over the devices." | no comment |
| Talk to the reader | The text speaks to the reader or to the owner as a person, or uses chat phrases. | "Note that you can ...", "Great question" | the fact alone |
| Summary and padding | The text repeats what the text, the page or the code already says, or opens with an introduction. | "In short, the loader writes the run." | no text |
| Colon chains | One sentence joins 2 or more clauses with colons or semicolons. | "The load landed; what it landed can still be less than the whole device." | "The load can write less than the whole device." |
| Explanation after a colon | A short claim is followed by a colon and its explanation. | "No QOS body means the profile read was refused: the ..." | "The profile read was refused if the QOS body is missing." |
| Verbs as metaphors | Data or code is said to speak, carry or name. | "the row carries the filter", "the leg says so" | "the row holds the filter", "the leg has a note" |
| Compressed fragments | The sentence has no subject, no verb or no articles, so the reader must decode it. | "Not blocked, and not a clean pass: the engine could not decide." | "The engine could not decide the gate." |
| Stacked qualifiers | The noun has 2 or more qualifiers that the reader does not need. | "a confirmed, undecided-free permit, which a later reply ..." | "a permit" |
| Riddle wording | The text uses an unusual phrase where a plain phrase exists. | "past the sample the row says how many" | "after the sample, the row holds the count" |
| Self-reference | The text refers to itself or to its own function in place of the name. | "this function's own parameter" | "the parameter `detail`" |
| Rhetorical forms | The text uses a question, a group of 3 for rhythm, or a fragment for effect. | "Fast, safe, and simple." | no text |
| Decoration | The text uses emoji, glyphs such as `·`, `→`, `✓` and `•`, an em dash, an exclamation mark, bold in running text, or a heading or a table for 2 items. | "Trace →" | "Trace flow" |

Write full, plain sentences: a subject, a verb and an object, with articles. One fact per sentence.

### Product text

- A name is the bare name of the thing: "Network functions", "Forwarding table", "Next hops". It has no qualifier, no format, no unit and no second part after a comma or a colon. A unit goes in the `unit` field of a column or a setting.
- A label names a thing or a state in a few words: "not known", "no reply", "no device group". A button names its action: "Add credential", "Delete core-01".
- A label, a hint, a note or a description is not a sentence and has no full stop. A `title` holds one short phrase at most.
- No text explains a section, or why a thing is absent, disabled or not used. A control that does nothing for the record is not shown.
- No text repeats what the page already shows. A count or a summary box that a person does not act on is not shown.
- A value shows as the value itself, in full, not as "varies", "mixed" or a cut text with an ellipsis. A value with no information shows the hatch with "not available". A value that the twin cannot know shows the hatch with "not known".
- No key hints, tips, onboarding text or legends that explain the controls.
- Sentence case, present tense.

### Docs, design notes, STATUS.md and the README

- State the current design and the current facts only. No plan written as a fact.
- No introduction, no overview that restates the headings, no closing summary, no sales section, no next steps that nobody asked for.

### Code comments, docstrings and test names

- A comment states what the code does or holds, in the terms of the code. If the code already shows it, write no comment.
- A comment keeps a fact that the code depends on: a bound, an order, a format or a constraint.

### Commit messages, pull request texts and answers to the owner

- A commit message names the change: "rsim-collect: random store keys in the demo test".
- A pull request text lists the changes and the checks.
- An answer to the owner leads with the result, and then gives only the facts that the owner needs. It does not praise, apologize, restate the question or end with an offer that nobody needs. It does not claim a result that no check confirmed.
- Options go to the owner only when the owner must decide.

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
| Install the UI dependencies | `npm --prefix ui ci`. The versions are exact and the lockfile is committed. |
| Build the UI | `npm --prefix ui run build`: the type check and the Vite build into `ui/dist`, which `rsim-api` embeds at build time. Build `rsim-api` again after it. With `RSIM_UI_REQUIRED=1`, as in CI, a missing UI is a build error of `rsim-api`. |
| UI tests | `npm --prefix ui test`: the layout of the ladder on the stored answers in `crates/rsim-cli/tests/golden/` |
| UI types from the OpenAPI document | `npm --prefix ui run api` writes `ui/src/api/schema.ts` and, through `ui/scripts/fields.mjs`, the query fields `ui/src/api/fields.ts` from `crates/rsim-api/openapi.json`; `npm --prefix ui run api:check` fails if a file is not current |
| UI with reload on change | `npm --prefix ui run dev` on port 5173, with `cargo run -p rsim-api -- --allow-origin http://localhost:5173`; the Vite server sends `/v1` to it |
| Container images | `/opt/podman/bin/podman build --target rsim -t localhost/rsim:dev .` and `--target rsim-collect -t localhost/rsim-collect:dev`. `Containerfile` builds the UI on Node 24.22.2, the release binaries on Rust 1.99.1 with `RSIM_UI_REQUIRED=1`, and runs them on distroless `cc-debian13` as the user 65532 with `/data` as the data folder; each base image is pinned by its digest, and `.dockerignore` keeps `target` out of the build context. Behind a proxy that signs TLS with its own CA, add `--secret id=ca,src=<CA PEM file>`: cargo then trusts that CA and the public roots of the image (`CARGO_HTTP_CAINFO`). |
| Local instance in containers | `/opt/podman/bin/podman compose up --build` with `RSIM_DB_PASSWORD` and `RSIM_ENV_FILE`, the path of an env file outside the repository with the line `RSIM_SECRET_KEY=<64 hex digits from openssl rand -hex 32>`, in the ignored file `.env`: PostgreSQL 17.11 with no published port, `rsim-api` with sign-in on `127.0.0.1:8787` and the volume `rsim-data` read only. `rsim-api` reads only `RSIM_SECRET_KEY` from the env file. `--profile collect` adds the collector, which reads the devices from that database and writes `rsim-data`. `podman compose` runs `/usr/local/bin/docker-compose`, so the file uses only features of both. |
| Helm chart | `helm lint --strict deploy/helm/rsim -f deploy/helm/rsim/ci/<instance>-values.yaml` and `helm template <instance> deploy/helm/rsim -f ...` for the instances `rsim`, `rsim-dev` and `rsim-demo`. One pod with `rsim-api` (the volume read only) and, with `collector.enabled`, the collector, on the data folder `/data/rsim`, because the collector sets the mode 0700 on a folder that it owns; with `demo.seed`, an init container of the collector image runs `seed --demo /usr/share/rsim/demo --if-empty` on that folder; a PostgreSQL StatefulSet with a read-only root file system; NetworkPolicies for the API port (`networkPolicy.apiFrom`) and for PostgreSQL. `rsim.validate` in `_helpers.tpl` refuses an HTTPS origin with no `api.trustedProxies`, an ingress with no host or TLS secret, and no database password; `rsim-api` and the collector get `RSIM_SECRET_KEY`, the key that seals the secrets of the managed credentials, from the optional key `secret-key` of the database Secret; the env file of the collector (`collector.envSecret`) is optional, and with none the collector reads the devices from the inventory database and uses only the managed credentials. |
| Path query with its reply | `cargo run -p rsim-cli --features test-fixtures -- path mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --source.port 40000 --destination.port 53` |
| Path query as JSON | Add `--format json` to the `path` command. Add `--pretty` for indented JSON, and `--form summary` or `--form steps` for a brief form. |
| Set query | `cargo run -p rsim-cli --features test-fixtures -- set mini-enterprise --source.ip 172.31.10.0/24 --destination.ip 10.20.0.53 --network.transport udp,tcp` |
| One trace step of a set query | `cargo run -p rsim-cli --features test-fixtures -- explain-set mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --destination.port 53,80 --branch 1 --step 7` |
| Set query benchmark | `cargo bench -p rsim-engine --bench set_query` |
| One trace step | `cargo run -p rsim-cli --features test-fixtures -- explain mini-enterprise --source.ip 172.31.10.20 --destination.ip 10.20.0.53 --network.transport udp --destination.port 53 --branch 0 --step 7`. Add `--source-lines` for the masked source lines of each span of the step; a hand-built topology of the tests has no source text. |
| MCP server on stdio | `cargo run -p rsim-mcp` |
| Path query on the newest snapshot of a store | `cargo run -p rsim-cli -- path store:<data folder> --source.ip <a> --destination.ip <b> ...`. The data folder is the folder of `rsim-collect` with `store` and `keys`. |
| MCP server with a store | `cargo run -p rsim-mcp -- --store <data folder>`. The tools then accept the topology `store`. |
| Decision diagram tests | `cargo test -p rsim-dd` |
| Decision diagram tests, release build with the validator | `cargo test -p rsim-dd --release --features dd-check` |
| Decision diagram benchmark | `cargo bench -p rsim-dd --bench ops` |
| TextFSM tests, with the conformance to Python textfsm | `cargo test -p rsim-textfsm` |
| Layer 2 tests | `cargo test -p rsim-engine --test layer2` |
| VXLAN fabric tests | `cargo test -p rsim-engine --test tunnel` |
| Equinix Fabric circuit tests | `cargo test -p rsim-engine --test equinix` |

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
- **Candidate.** The alternatives of a decision point have a kind, `AlternativeKind`. `Choice` is a forwarding choice. `Candidate` is a selection that is not collected: the device sends the packets to one or more of the alternatives, and the engine follows each one. Candidates with one result give that result, candidates with one kind of result give that kind, and each other case gives `Unknown` with the reason code `SelectionNotCollected` (`answer::combine_candidates`). A branch has an optional assumption: a statement that the collected data does not prove and on which its result depends. The JSON has `kind` with the value `candidate` on the alternative and `assumption` on the trace step only when they are present.
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

## Architecture

The project is a Rust engine for a network digital twin. The engine compiles configs and collected state into typed network functions that stay in memory. The engine converges the routing internally. To answer reachability questions and policy questions, the engine sends packets or packet sets through the functions. Each answer has a full trace.

The scale target is 10,000+ routers and 50,000+ endpoints.

Section 3 of the brief shows the data flow and the crate layout. The project name is `rsim`, and each crate has the `rsim-` prefix.

The tests of `rsim-dd` turn on the feature `dd-shadow` through a development dependency of the crate on itself. Each public operation then also runs in a plain BDD, and the 2 results must be the same set. A benchmark turns the shadow check off with `Dd::set_shadow(false)`. The OxiDD oracle in `crates/rsim-dd/tests/oracle.rs` compares the results with OxiDD on 3,256 levels. OxiDD is a development dependency only.

CI is in `.github/workflows/ci.yml`. For each pull request, it runs the format check, clippy and the tests on Linux `amd64`, `cargo audit` on the lockfile in a separate job, and the job `image`, which builds the images `rsim` and `rsim-collect` for `amd64` with no push, and the job `chart`, which runs `helm lint --strict` and `helm template` for the 3 value sets with the Helm of the runner. `.github/workflows/image.yml` pushes the 2 images to `ghcr.io/<owner>/<image>:<commit>` only for a run by hand or a tag `v*`, and writes the digests in the summary of the run; the workflows use the Docker CLI of the runner and no Docker action. Each action is pinned by its commit SHA, with the release tag as a comment, and each checkout sets `persist-credentials: false`. The job `secrets` of `ci.yml` runs gitleaks with `.gitleaks.toml` on the commits of the pull request. The CI workflow runs for each pull request, and for a push to `main` that changes a file other than a Markdown file. `.github/workflows/codeql.yml` runs the CodeQL analysis with the query suite `security-extended` of Actions, JavaScript and TypeScript, and Rust for each pull request, for a push to `main` that changes a file other than a Markdown file, and once each week. The ruleset `protect-main` requires a pull request, a linear history, and the checks `check`, `audit`, `image`, `chart`, `secrets` and the 3 CodeQL `Analyze` jobs on a branch that is up to date with `main`. The ruleset `protect-release-tags` blocks the deletion, the update and the force push of a tag `v*`. `.github/dependabot.yml` opens the weekly updates of the crates, the UI packages, the base images, the compose images and the actions. A new push cancels the run of the older push of the same branch. The tests compile with `opt-level = 1`, and the dependencies with `opt-level = 2`.

`.claude/rules/` holds the description and the commands of each crate and of the UI. Each file has a `paths` field, and Claude Code loads the file when it reads, writes or edits a file that matches. For a question about a crate, read its rule file first.

| Rule file | Content |
|---|---|
| `topologies.md` | `rsim-topologies` |
| `contract-cli.md` | `rsim-contract` and `rsim-cli` |
| `core.md` | `rsim-core` |
| `api.md` | `rsim-api` |
| `ui.md` | UI |
| `inventory.md` | `rsim-inventory` |
| `store.md` | `rsim-store` |
| `collect.md` | `rsim-collect` |
| `ingest.md` | `rsim-ingest` |
| `ingest-vyos.md` | `rsim-ingest`, VyOS |
| `ingest-unifi.md` | `rsim-ingest`, UniFi |
| `ingest-velocloud.md` | `rsim-ingest`, VeloCloud |
| `ingest-equinix.md` | `rsim-ingest`, Equinix |
| `ingest-nxos.md` | `rsim-ingest`, NX-OS |
| `ingest-iosxr.md` | `rsim-ingest`, IOS-XR |
| `ingest-iosxe.md` | `rsim-ingest`, IOS-XE |

## Status

@STATUS.md
