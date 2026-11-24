---
paths:
  - "crates/rsim-ingest/src/equinix/**"
  - "crates/rsim-ingest/tests/equinix*.rs"
  - "crates/rsim-ingest/tests/fixtures/equinix/**"
---

# `rsim-ingest`, Equinix

The Equinix module is in `equinix/`: `reader.rs` reads the Fabric ports and the connections, `coverage.rs` classifies their nested paths with `*` for each element of a list, and the Network Edge sections are unhandled; `lower.rs` gives each Fabric port `port/<uuid>` of the account device a gate `port/<uuid>/in`, an `AclMatch` with one rule for the tags of each leg and a last unhandled rule, and a `Circuit` `port/<uuid>/circuit`. A port is lowered when its state is `ACTIVE` and its encapsulation is `DOT1Q`, `QINQ` or `UNTAGGED`, with the TPID of `tagProtocolId` (default `0x8100`, `0x88a8` for QinQ). A circuit of the type `EVPL_VC` in the state `ACTIVE` with both ends on lowered ports is lowered: `DOT1Q` gives one tag, `QINQ` the S-tag with the TPID of its port over the C-tag, and `UNTAGGED` and `NULL` a port-based leg (`CircuitLeg::port_based`) when both ends are port-based. The states of `ENDED_STATES` give no leg. Each other case, a service profile end, a far port outside the account, a Network Edge end, 2 items of one uuid that differ, a hairpin circuit and 2 circuits with the same tags on one port send the frames of the legs to the sink `circuit/<uuid>/sink` with the reason; a far port with no link peer sends them to `port/<uuid>/unbound`.

The section `bindings` of an account holds the bindings of its Fabric ports from the inventory records `fabric_port_bindings` of the account, which the Equinix source writes with no read; `equinix::summary` gives the gates of the Fabric ports as the entries and each binding as a `links::Binding`. The join links each binding to the lowered port of the device that it names with no record at the far end, removes each other link of its 2 ends with a note, and gives a note for a device or a port that the twin does not have; the account lowering then sends the frames of a circuit to the entry of the bound port of the far Fabric port. The join also links a port whose description (`Summary::descriptions`, from the `description` line of an interface of NX-OS, IOS-XE, IOS-XR and VyOS) names one Fabric port of `Summary::fabric_ports` by the rule of HST (`links::names_fabric_port`), when the description states no cable id (`links::cable_ids`) or a cross connect id of the port; a description of 2 Fabric ports, a Fabric port of 2 descriptions and a stated cable id that is no cross connect id give a note and no link, and an operator binding wins.

## Commands

| Task | Command |
|---|---|
| Equinix ingestion tests | `cargo test -p rsim-ingest --test equinix` |
| Equinix estate tests | `cargo test -p rsim-ingest --test equinix_estate` |
