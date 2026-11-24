---
paths:
  - "crates/rsim-ingest/src/vyos/**"
  - "crates/rsim-ingest/tests/vyos*.rs"
  - "crates/rsim-ingest/tests/fixtures/vyos/**"
  - "crates/rsim-ingest/examples/vyos_*.rs"
---

# `rsim-ingest`, VyOS

The VyOS handlers are in `vyos/config.rs`, the table in `vyos/table.rs`, the lowering in `vyos/lower.rs` and the vendor profile in `vyos/profile.rs`. Each handler records the stanzas that it reads, and `vyos::unread` lists each handled stanza that no handler read. A new handled path needs a handler that reads it. The tests use the synthetic config in `crates/rsim-ingest/tests/fixtures/vyos/`.

A route to a WireGuard interface goes to `wireguard/<interface>` (`WireguardEncap` in `rsim-functions/src/tunnel.rs`) in place of an egress: the peer is the peer with the longest allowed IP that contains the destination, an allowed IP of more than one peer is `Unknown` ("more than one WireGuard peer allows <prefix>"), and a destination that no allowed IP contains is dropped; a peer with no endpoint address and port is `Unknown`. The outer header is UDP from the listen port (unknown with no `port` line) to the endpoint, with DSCP 0, and its source is the one address of the family of the endpoint on the one interface of the route of the main table to the endpoint, else unknown. The encapsulated packets are packets of the router: they go to the route lookup of the main table, with the local zone as their source zone (unknown with zones and no local zone), through the zone policy, the source NAT and the next-hop resolution to the egress; a global output filter or `policy local-route` makes them `Unknown`. The outer flow has the session state `SessionMatch::Untracked`: it is new or established, by which end started it, so `FirewallPolicy` evaluates it both as new and with the action of the state policy for established (`established`), and the packets for which the two differ are `Unknown`. `DeviceDelivery` gives `Unknown` for an encapsulated packet ("WireGuard packet at <device>, decapsulation not modelled"), so an outer packet to a router of the twin does not deliver. Handshakes and keepalives are not modelled, and the keys are not read.

The session lookup `SessionLookup` applies `StateActions`, the action of each connection state: accept, drop, continue or unknown. The VyOS lowering takes them from `firewall global-options state-policy`, where a state with no action continues; with no action for established, the zone policy evaluates the packets of a session too, and a rule with `state` matches the connection state through its `ZoneScope`. The other vendors use the default, with which the packets of a session pass the policy.

## Commands

| Task | Command |
|---|---|
| Coverage of a VyOS config | `cargo run -p rsim-ingest --example vyos_coverage < config.json` |
| Twin of a VyOS device of a store | `cargo run -p rsim-ingest --example vyos_snapshot -- <data folder> <device>`. Add `<ingress interface> <source> <destination> tcp\|udp <port>` for a path query. |
