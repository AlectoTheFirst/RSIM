---
paths:
  - "crates/rsim-ingest/src/unifi/**"
  - "crates/rsim-ingest/tests/unifi*.rs"
  - "crates/rsim-ingest/tests/fixtures/unifi/**"
  - "crates/rsim-ingest/tests/estate.rs"
---

# `rsim-ingest`, UniFi

The UniFi handlers are in `unifi/site.rs`, the coverage rules in `unifi/coverage.rs` and the lowering in `unifi/lower.rs`. An SSID with one WLAN on an access point has the port `wlan/<ssid>`; an SSID with more than one WLAN there has a port `wlan/<ssid>/wlan-<id>` for each, and a wireless client takes the port of its `radio`. The radio picks the port only if each vap of the SSID names its radio. A client whose network is not the network of its port, or whose SSID port its radio does not tell, is not placed: a note names it, and the ingress function `Unplaced` at `unplaced/<endpoint>` makes each packet from it unknown. A client whose port has no known network is not placed and has a note.
