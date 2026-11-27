---
paths:
  - "crates/rsim-guard/**"
---

# `rsim-guard`

`rsim-guard` compares the computed route table of a device and VRF with its collected route table. It has no I/O. `compare` gives one row for each prefix of the 2 tables in prefix order, with one category: `match` (the same kind and next hops), `differ` (with the fields `kind` or `next_hops`), `only_computed`, `only_collected`, `not_computed` and `seeded` (a collected route that the calculation takes as its input). A route is `not_computed` with its reason when the class of the collected route is `NotComputed`, when the collected route has no next hop (`collected route unknown: <reason>`), or when the computed route has no next hop and is not a local or a discard route (`computed route unknown: <reason>`), also with no collected route. A prefix of the collected table with no collected route, for example a local route of the config, is left out. If no collected route is a local route, the computed local routes are left out. `mark` sets `MatchesCollected` and `DiffersFromCollected` on the routes of the collected table, and no flag for a route that is `not_computed` or `seeded`. `Counts::rate` is the share of the matches in the compared routes, in percent with 1 decimal; the routes that are not computed and the seeds are outside it.

## Commands

| Task | Command |
|---|---|
| Guard tests | `cargo test -p rsim-guard` |
