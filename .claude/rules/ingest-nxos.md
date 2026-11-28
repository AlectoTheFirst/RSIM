---
paths:
  - "crates/rsim-ingest/src/nxos/**"
  - "crates/rsim-ingest/tests/nxos*.rs"
  - "crates/rsim-ingest/tests/fixtures/nxos/**"
  - "crates/rsim-ingest/examples/nxos_coverage.rs"
---

# `rsim-ingest`, NX-OS

The NX-OS module is in `nxos/`: `nxos/table.rs` classifies the lines of the running config, `nxos/mask.rs` masks the secrets of each line that leaves the ingestion, `nxos/config.rs` holds the handlers, `nxos/ospf_config.rs` reads the `router ospf` and `router ospfv3` stanzas and the OSPF lines of the interfaces into the `RouterConfig` of `rsim-routing` and puts each line that it does not read into the unhandled lines of its process, `nxos/names.rs` resolves the short interface names of the collected sections, `nxos/state.rs` reads the collected JSON sections (the interface state, HSRP, VRRP, LLDP and CDP), `nxos/lower.rs` lowers the layer 3 part of a switch, `nxos/layer2.rs` lowers the switch ports, the MAC table, the flood, the SVI hand-off and the endpoints,  and `nxos/vxlan.rs` lowers the VXLAN tunnel end: the NVE interface, the `vn-segment` lines and the NVE sections give a `VxlanEncap` for each peer tunnel end of the MAC table and the flood, a route lookup `vxlan/route` of the default VRF for the outer header, a `VxlanDecap` at the local delivery, and the MAC lookup `mac-tunnel` and the flood `flood-tunnel` of a frame out of the tunnel, which never goes back into it.

A layer 3 VNI of a VRF gives `vxlan/encap-l3`: a route path with a VXLAN encapsulation in the route table section goes to the NVE interface, a point-to-point egress of the next-hop resolution, and the decapsulation `vxlan-decap-l3` sends the packets to the ingress of the SVI of the VNI. An SVI with `fabric forwarding mode anycast-gateway` has the MAC of `fabric forwarding anycast-gateway-mac` as an active virtual MAC. On a switch of a lowered vPC domain, the tunnel end is the secondary address of the source interface, which both switches share, and the flood of a frame from the peer link does not go into the tunnel. A VNI with `mcast-group` floods one copy to the group through `vxlan/mroute`. `nxos/mcast.rs` reads the multicast routes into the `MulticastLookup` `mroute` before the unicast route lookup; a copy goes to `mcast/out/<interface>` or, for the NVE interface, to the decapsulation.

`nxos/bgp_config.rs` lowers the BGP config for the BGP calculation: the process of the default VRF and of each `vrf` stanza with `router-id`, `cluster-id`, the `bestpath` options, `maximum-paths` and `maximum-paths ibgp`, `network` with an optional `route-map`, `aggregate-address` with `summary-only` and `as-set`, and the neighbours. A VRF with no `router-id` line has no process and a gap. The settings of a neighbour in a unicast family come from its own address-family lines (`route-map <name> in` and `out`, `route-reflector-client`, `next-hop-self` and `next-hop-self all`, `send-community` with `standard`, `extended` or `both`), then from the `template peer-policy` stanzas that the family inherits by sequence number, then from its `template peer` stanzas; `remove-private-as` is a line of the neighbour or the template. The policies are the route maps with `continue` and the lines `match ip address prefix-list`, `match ipv6 address prefix-list`, `match ip next-hop prefix-list`, `match community`, `match as-path`, `match route-type`, `match tag` and `match metric`, and `set local-preference`, `metric`, `weight`, `origin`, `community`, `comm-list <name> delete`, `extcommunity rt ... additive`, `as-path prepend`, `ip next-hop` and `tag`; the prefix lists as `ip <name>` and `ipv6 <name>`, the standard and expanded community lists and the AS-path access lists. A route map line that is not read is an unknown term or action, and a prefix list with a line that is not read is left out of the set. Each import route target of a `vrf context` (`route-target import` or `both`) is a gap of its VRF and family. `nxos/bgp_config::collected` gives the selected BGP routes of the collected rows.

`nxos/profile.rs` holds the vendor profile and the port defaults. A table can have a mask, and the coverage report and `coverage::unread` print each key through it. The tests use the synthetic running config and JSON sections in `crates/rsim-ingest/tests/fixtures/nxos/`; the config has fake secrets.

## Commands

| Task | Command |
|---|---|
| Coverage of an NX-OS running config | `cargo run -p rsim-ingest --example nxos_coverage < running-config.txt`. Each printed line goes through the mask of the secrets. |
| NX-OS ingestion tests | `cargo test -p rsim-ingest --test nxos` |
| NX-OS vPC tests | `cargo test -p rsim-ingest --test nxos_vpc` |
| NX-OS VXLAN tests | `cargo test -p rsim-ingest --test nxos_vxlan` |
| NX-OS symmetric routing and anycast gateway tests | `cargo test -p rsim-ingest --test nxos_irb` |
| NX-OS vPC tunnel end tests | `cargo test -p rsim-ingest --test nxos_vpc_vtep` |
| NX-OS multicast underlay tests | `cargo test -p rsim-ingest --test nxos_mcast` |
