---
paths:
  - "crates/rsim-routing/**"
---

# `rsim-routing`

`rsim-routing` holds the routing calculation. It depends on `rsim-core` and `rsim-functions`, and it has no I/O, no clock and no randomness. `install.rs` selects the route of each prefix from its candidates by the administrative distance and resolves the gateways of the candidates over the installed routes. `platform.rs` holds `Platform` and the administrative distance of each `Origin`.

`ospf/` holds the OSPF calculation. `ospf/config.rs` holds the OSPF config of a router in one form for all vendors, and `ospf/build.rs` builds the databases of the twin from these configs. `tests/ospf_oracle.rs` and `tests/ospf_build_oracle.rs` check the calculation and the builder against a second shortest-path calculation in the test. A `Database` is the link-state database of one process of a device in one VRF and one `Version`: the router ID, the stated area types, the interfaces, the neighbours and the LSAs by `LsaKey` (the area with the AS-external LSAs last, the type, the link-state ID and the advertising router), each `Lsa` with the span of its lines. `Database::insert` keeps the newer instance of an LSA (RFC 2328 13.1). The OSPFv3 types share the variants of the OSPFv2 types of the same role: `Summary` is the inter-area-prefix LSA, `AsbrSummary` the inter-area-router LSA, `External` the AS-external LSA and `NssaExternal` the NSSA LSA; `Link` and `IntraAreaPrefix` are OSPFv3 only.

`compute(database, router ID, profile)` in `ospf/spf.rs` follows RFC 2328 section 16 with RFC 3101 for NSSA areas and RFC 5340 for OSPFv3, with one shortest-path code: a network vertex is the link-state ID of an OSPFv2 network LSA, or the designated router and its interface ID for OSPFv3; the prefixes of OSPFv3 come from the intra-area-prefix LSAs, and its next hops from the link-local address of the link LSA of the neighbour. A next hop has the gateway and the interface of the calculating router, from its interface address (OSPFv2) or its interface ID (OSPFv3) in `Database::interfaces`. The subnets of the calculating router are not routes. An area border router reads only the summary LSAs of the backbone. `OspfProfile::of(Platform)` holds the RFC 1583 setting, the reference bandwidth and the cost rounding of HST `simul/platforms.py`; IOS-XE is RFC 1583 compatible.

An LSA that the calculation needs and the database lacks is a `Gap`, listed once by type, link-state ID and area. A gap of the shortest path tree reaches the intra-area routes with a cost of at least the cost at which the tree meets it, and each inter-area and external route (`GapReach::FromCost`); the missing router LSA of the calculating router reaches each route (`GapReach::All`); a border router or an AS boundary router with no LSA reaches the prefixes of its summary or external LSAs (`GapReach::Prefixes`). `Database::gaps` holds the LSAs that the builder `ospf/build.rs` leaves out in the flooding scope of the database, and `compute` adds them to the gaps of the calculation: the left-out LSAs of known prefixes reach those prefixes (`GapReach::Prefixes`), left-out summary LSAs of prefixes that are not known reach each inter-area and external route (`GapReach::InterArea`), and left-out external LSAs of prefixes that are not known reach each external route (`GapReach::External`); the last 2 also reach each prefix with no route. The NSSA border router with the highest router ID that the NSSA calculation of each other router of the NSSA reaches translates the NSSA LSAs with the P bit, except the default route, into AS-external LSAs (RFC 3101 3.1 and 3.2). A left-out process has a gap of its interface prefixes and its redistributed prefixes in each of its areas, and an area border router carries this gap into its other areas. A route that a gap reaches has the reason in `Route::unknown`, and `Calculation::absent_gap` gives the gap that makes a prefix with no route unknown. A virtual link of the calculating router is not computed and gives a note. `ospf/change.rs` holds the changes of an OSPFv2 database: an interface cost, an adjacency down and an interface in another area; each gives a new database.

The tests in `tests/ospf.rs` are the cases of HST `tests/test_simul_ospf.py` with documentation addresses and the OSPFv3 cases; the expected outputs are not confirmed against a device.

## Commands

| Task | Command |
|---|---|
| Routing tests | `cargo test -p rsim-routing` |
| OSPF tests | `cargo test -p rsim-routing --test ospf` |
