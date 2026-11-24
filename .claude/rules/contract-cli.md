---
paths:
  - "crates/rsim-contract/**"
  - "crates/rsim-cli/**"
---

# `rsim-contract` and `rsim-cli`

`rsim-contract` has no engine dependency. It holds the JSON output types, the query echo and error types, the typed arguments of the operations, the brief forms `summary` and `steps`, and the registry of operations in `registry.rs`; `rsim-mcp` makes its tools and their schemas from the registry. `rsim-cli` converts the engine values with the trait `json::FromEngine`.

`rsim-contract/src/table.rs` holds the table catalog, the selection parameters and the output types of a table request. `rsim-cli/src/frame.rs` holds the rows of a table as columns: each column is an Arrow dictionary array, one `u32` key for each row over the distinct values, and the rows are in key order. The selection works on the columns: a filter is evaluated once for each distinct value, a scan runs in chunks on `rayon`, a sort orders row numbers by the ranks of the distinct values with the row number as the last key, a page with no sort stops its scan at the end of the page, and JSON is made only for the rows of the answer; `crates/rsim-cli/src/frame/tests.rs` compares it with a selection on rows of JSON values.

`rsim-cli/src/tables.rs` fills the columns of each table from a loaded twin once, when a request first names the table, and keeps them in `Loaded::tables`; the MCP tools `list_tables` and `table_query` and the REST API use them.

The table `bgp-sessions` has one row for each BGP peer fact of a store twin, from `Loaded::bgp`.

The table `sdwan-paths` has one row for each tunnel of each `OverlaySelect`: the device, the selection, its segment, the tunnel, the WAN interface and the peer address of its `VcmpEncap`, the transport (`public` or the name of a private network), the one device with the tunnel end of the peer and its WAN interface from its `VcmpEncap`, the state `up` or `down`, else null with its `state_reason` (`not_collected` for SD-WAN peers that are not collected, `link_state_not_known`, `paths_not_collected`, or `paths_differ` for live paths of the far end that differ from the tunnels whose links are up), the stable and unstable paths of the far end in the collected state (`far_paths`, 0 when the collected peers have no row of the far end) and the spans; a twin with no SD-WAN has no row.

The table `fabric-connections` has one row for each circuit of each Equinix account of a store twin, from `Loaded::fabric`: the connection, its name, type and state, the A end and the Z end as text, the result `lowered`, `ended` or `unknown` with its reason, and the spans of its items.

The table `neighbours` has one row for each LLDP or CDP record of a store twin that names a neighbour with no device in the twin, from `Loaded::seen` (`links::SeenNeighbour`): no device has its name or its host name and its MACs name no device, and the protocol is the section `lldp` or `cdp` of its span.

The table `devices` has one row for each device with a function and each device of `Loaded::facts`: the vendor, the platform, the OS version, the serial, the management address and the time of the device manifest, each fact null with its column `<fact>_reason` (`not_collected` or `not_read`) when it is not known, the device of the store whose manifest gives the facts (`store_device`: the console of a UniFi device, the enterprise of a VeloCloud edge), and the spans of the facts; a hand-built topology of the tests has each fact `not_collected`. In the UI, the row panel of the table `devices` has the button "View functions", which opens the table `functions` filtered to the device, and a cell that the twin does not know has a hatch square and the words "not known" with the reason as its title.

A claim answer has the field `detail` for what the claim leaves out of its rows.

The BGP claims `bgp-peers-up` and `bgp-peers-agree` read `Loaded::bgp` with the far end of each neighbour from the join; a neighbour with `shutdown` gives no row in either claim, a neighbour whose peer is outside the twin gives no row in `bgp-peers-agree`, the detail counts them, and a scope with no row has the detail `no BGP neighbour in scope`.

`bgp-peers-up` has one row for each configured neighbour and each dynamic peer of a listen range, a peer outside the twin included: established is confirmed, another state word is refuted, and a neighbour with no session row is refuted with `not in session table` only when the session section is `Complete` or `CompleteEmpty` and its scope covers the VRF and each activated address family of the neighbour; else it is unknown, as is a neighbour whose inheritance gap can hide a shutdown line and a neighbour named by its interface.

`bgp-peers-agree` has one row for each configured neighbour whose peer address is an address of another device: a far side with no neighbour and no listen range for the source address refutes (`one-sided peering`) when the BGP config of the far device is read in full (`Summary::bgp_read`, which also counts the BGP stanzas that collected route rows make known-irrelevant), the neighbour of the far side for the source address refutes (`source address mismatch`) when it sends from a known address other than the peer address of the near side and gives unknown when its source address is not known, a neighbour of the far side that names another address of the near device refutes (`source address mismatch`) only when the far config is read in full, the far side has no session with the source address and no other neighbour of the near device can be its far side, an AS of the peer that is not an AS that the other side presents refutes in each direction (`asn mismatch`), and 2 sides with no common address family refute when both sets are known in full, with no inheritance gap and no address family that the reader does not name; a neighbour whose inheritance gap can hide its update-source has no known source address, and a gap that can hide a shutdown line turns each refute of its row into unknown; an AS or a source address that does not resolve, different session states and a count of sent prefixes that differs from the count of received prefixes of the far side with no inbound policy give unknown, never refuted.

The scope of a query is the devices of the functions on its paths. `rsim-contract/src/claim.rs` holds the claim catalog and the rule of the result: one refuted row refutes, one unknown row makes it unknown, and no row is unknown; `rsim-cli/src/claims.rs` gives the evidence rows of each claim, and data that is not collected is unknown.

`commands::load` gives a `Loaded` twin with its identity `twin::TwinJson`, and each top-level answer has the field `twin`: `builtin.<topology>` or `snapshot-YYYY-MM-DD-HHMMSS`, the UTC second of the manifest time of the snapshot (`twin::snapshot_name`, read back by `twin::snapshot_second` only for a name that formats back to itself), with its `snapshot` field the UTC time in RFC 3339 and an empty list of what-if layers. The cycle number stays inside the store.

`crates/rsim-cli/tests/schema.rs` checks each stored answer against the schema of its kind and through a round trip, and the flags of `rsim path` and `rsim set` against the registry. `../rsim-project/design/http-api.md` is the API specification.

The stored JSON answers of the CLI tests are in `crates/rsim-cli/tests/golden/`. `<name>.summary.json` and `<name>.steps.json` are the brief forms of `--form summary` and `--form steps`. `leaf-spine-acl.json` and `leaf-spine-no-route.json` are the answers of `FABRIC_QUERIES` in `crates/rsim-cli/tests/cli.rs`. `equinix-fabric-qinq.json`, `equinix-fabric-no-circuit.json` and `equinix-fabric-service-profile.json` are the answers of `EQUINIX_QUERIES` in `crates/rsim-cli/tests/cli.rs`. `set-mini-enterprise.json` is the answer of the set query `SET_QUERY` in `crates/rsim-cli/tests/cli.rs`; make it again with `cargo run -p rsim-cli --features test-fixtures -- set` and these flags. The CLI test and the MCP stdio test compare their outputs with these files. If an intended change alters the JSON output, make the files again with `cargo run -p rsim-cli --features test-fixtures -- path <topology> <flags> --format json`. The flags of each file are in `QUERIES` in `crates/rsim-cli/tests/cli.rs`.

## Commands

| Task | Command |
|---|---|
| CLI tests | `cargo test -p rsim-cli --test cli` |
| Schema tests of the stored answers | `cargo test -p rsim-cli --test schema` |
| A table of a twin | `cargo run -p rsim-cli --features test-fixtures -- leaf-spine fib show --device leaf1`. The verbs are `show`, `summarize`, `unique --columns a,b`, `top --column c`, `lpm <address>` and `describe`; `--<column> v1,v2` and `--<column>.<op> v` filter, `--columns`, `--sort`, `--limit` and `--cursor` select. `rsim tables` lists the tables. |
| Span index tests of the source lines | `cargo test -p rsim-cli --test span_index` |
| Topology of a twin | `cargo run -p rsim-cli --features test-fixtures -- leaf-spine topology`. Add `--level function`, `--layer physical,overlay`, `--device a,b`, `--around <device> --hops n`, `--claims link-speed-duplex`, or `--as mermaid`, `d2` or `graphml`. |
| A claim | `cargo run -p rsim-cli --features test-fixtures -- leaf-spine claim run no-unknown --source.ip 10.1.0.10 --destination.ip 10.2.0.10 --network.transport tcp`. `--device a,b` gives the scope of devices; with no query and no device, the scope is the twin. The exit code is 0 for confirmed, 1 for refuted and 3 for unknown. `claim list` lists the claims. |
| BGP claim tests on hand-built summaries | `cargo test -p rsim-cli --test bgp_claims`. `RSIM_BLESS=1` writes the stored answers `claim-bgp-*.json`. |
| Equinix table tests | `cargo test -p rsim-cli --test equinix` |
| VeloCloud topology, table and fact tests | `cargo test -p rsim-cli --test velocloud` |
| Scale benchmark | `RSIM_SCALE_PERCENT=1 cargo bench -p rsim-cli --bench scale`: a generated estate at 1 % of 10,000 routers, 1,000 firewalls with 60,000 rules and 60,000 endpoints. It prints the heap and the build time of the twin, the time of a path query and of a set query, and the time and peak heap of the `fib` table request. `RSIM_SCALE_PHASES` selects the parts (`twin`, `path`, `set`, `table`, `fulltable`), `RSIM_SCALE_FILL=0` keeps only the routes of the estate, and `RSIM_SCALE_CAP_GIB` (default 12) stops the run at that live heap. `RSIM_SCALE_PERCENT=100` with `RSIM_SCALE_PHASES=twin,path,set` needs about 3 GB; the `table` part needs a peak of about 14.9 GiB on top of the 2.6 GiB twin at 100 %, so it runs only up to 50 % on a 16 GB machine. |
