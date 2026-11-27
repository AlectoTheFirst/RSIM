---
paths:
  - "crates/rsim-guard/**"
---

# `rsim-guard`

`rsim-guard` compares the computed route table of a device and VRF with its collected route table. It has no I/O. `compare` gives one row for each prefix of the 2 tables in prefix order, with one category: `match` (the same kind and next hops), `differ` (with the fields `kind` or `next_hops`), `only_computed`, `only_collected`, `not_computed` (a collected route of a protocol that the calculation does not compute, or a collected route with no next hop, with the reason) and `seeded` (a collected route that the calculation takes as its input). A prefix of the collected table with no collected route, for example a local route of the config, is left out. `mark` sets `MatchesCollected` and `DiffersFromCollected` on the routes of the collected table. `Counts::rate` is the share of the matches in the compared routes, in percent with 1 decimal; the routes that are not computed and the seeds are outside it.

## Commands

| Task | Command |
|---|---|
| Guard tests | `cargo test -p rsim-guard` |
