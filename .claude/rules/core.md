---
paths:
  - "crates/rsim-core/**"
  - "crates/rsim-functions/src/fib.rs"
---

# `rsim-core`

The prefix table in `rsim-core/src/prefix_table.rs` is a path-compressed trie with a read-only walk; `PacketSet::partition_by_prefix` and `PacketSet::partition_by_group` use the walk. `rsim-functions/src/fib.rs` holds the forwarding table `Fib`: the trie, the interned next-hop groups, compact spans and the protocol of each learned route as a column of its entry. A learned route (`RouteKind::Learned` with its `RouteProtocol`) shares the group of a static route with the same next hops, and the `fib` table and the step text name its protocol, for example `bgp`. `RouteLookup` splits a packet set by next-hop group, so a set query gives one branch for each forwarding result. `crates/rsim-core/tests/prefix_oracle.rs` compares the trie and both partitions with a brute-force longest-prefix match. `../rsim-project/design/rib-fib.md` gives the design.

`rsim-core` keeps the packet sets in `packet_set.rs`, the bit table in `bits.rs`, the arenas in `set.rs` and the description of a set as members in `describe.rs`. `crates/rsim-core/tests/explicit_oracle.rs` compares each set operation with an explicit list of packet pairs. Each header bit has 4 levels: the original request, the current header, the work level and the inner level.

A frame has 0, 1 or 2 VLAN tags, each with its VLAN, its priority and its TPID: the outer tag `network.vlan.id`, `l2_priority` and `network.vlan.tpid`, and the inner tag `network.inner.vlan.id`, `inner_l2_priority` and `network.inner.vlan.tpid`; the bits of the 2 tags alternate, an inner tag needs an outer tag (`PacketSet::has_valid_tags`), `push_vlan` and `pop_vlan` move the outer tag to the inner tag and back, and `set_vlan(None)` removes both tags. In each setting of `unstated`, an inner tag that the query does not state is absent and a TPID that it does not state is `0x8100`; with `defaults`, a stated inner tag gives the outer TPID `0x88a8`. The JSON shows a TPID only when it is not `0x8100` and an inner tag only when it is present, and the query echo has the tag fields only when the query gives them. A layer 2 function gives `Unknown` for a frame with an inner tag.

The encapsulation kinds are GRE, VXLAN, MPLS, WireGuard and VCMP. A VCMP encapsulation has its segment in the bits of the VXLAN network identifier, `PacketSet::vcmp_segment` selects the packets of a segment, and the JSON shows the segment as `segment`. A packet has at most one encapsulation: `PacketSet::encapsulate` moves the current header to the inner level and puts the outer header in the current fields, and `PacketSet::decapsulate` brings it back. The inner level is free for a packet with no encapsulation, and `PacketSet::has_free_levels` checks this in the tests. An outer header states each field. The JSON shows the inner header as `inner` of the current header.

A path query runs on the set of its packet; the design note gives the rule for an unstated field. The ingress of a query comes from `--ingress` or from the attachment records and edge interfaces of the twin.

## Commands

| Task | Command |
|---|---|
| Forwarding table benchmark at internet scale | `cargo bench -p rsim-functions --bench fib`. `RSIM_FIB_SKIP_ALL=1` leaves out the split of all destinations, which does not scale yet. |
