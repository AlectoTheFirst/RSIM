---
paths:
  - "crates/rsim-store/**"
---

# `rsim-store`

`rsim-store` holds the format of the snapshot store, the writer and the reader. It has no network code. A device manifest records the host name or the address to which the collector connected (`management_address`), which an older manifest does not have. A snapshot manifest lists the devices that the snapshot removes and the version of the inventory database that the cycle read (`inventory_version`), which a cycle with no inventory database leaves out; the reader leaves a removed device out of that snapshot and the snapshots after it until a later snapshot lists the device again, and a checkpoint leaves it out. Each snapshot has its own second: `Store::begin` refuses a time in the second of the newest snapshot or before it, and the collector waits for the next second.

`Store::read_table` gives the rows of all devices of a snapshot in 1 table, and `Store::read_table_of` the rows of the devices that a filter takes, with only their table files read.

`Store::prune` (`prune.rs`) deletes each snapshot whose manifest time is older than a cutoff, except the newest snapshot: the kept snapshots are the newest snapshot and its parents at or after the cutoff; the oldest kept snapshot becomes a checkpoint with no parent by an atomic rename, the other manifests before the newest snapshot are deleted oldest first, and then each device manifest, blob and table file that no kept snapshot names; a table file of a cycle after `HEAD` stays. A reader whose walk of the parents meets a deleted manifest walks again. `Store::open` takes a shared lock on the file `LOCK` of the store and holds it until the store is dropped. A prune takes the exclusive lock, and it fails with `StoreError::Conflict` and deletes nothing while another writer has the store open. Each cycle of the collector removes each device of the newest snapshot that is not in the inventory, and the scheduler then takes a device that comes back as new. After a written snapshot, at most once an hour (`PRUNE_INTERVAL`), the collector prunes the snapshots older than the history: `history_days` of the inventory, else 30 days; a prune error goes in the cycle report and the collector goes on.

## Commands

| Task | Command |
|---|---|
| Snapshot store tests | `cargo test -p rsim-store` |
