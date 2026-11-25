# Status

Section 13 of `../rsim-project/BUILD_BRIEF.md` gives the steps. `../rsim-project/roadmap.md` gives the order.

| Step | State |
|---|---|
| 1 | Complete |
| 1b: `rsim-topologies`, `rsim-cli` and `rsim-mcp` | Complete |
| 2: the packet sets | Complete |
| 3: collection, the snapshot store, ingestion and the snapshot view | In progress |
| 4 to 9 | Not started |

## Step 1b

`rsim-cli` and `rsim-mcp` load a twin and run a path query for one packet with its reply. `rsim-mcp` has the tools `list_devices`, `path_query`, `set_query` and `explain_step`. The JSON output is version 2.

## Step 2

The packet-set engine in `rsim-dd`, `PacketSet` on `rsim-dd`, the sessions as relations, set-mode execution, the ingress resolver, JSON version 2, the set input of the query, `rsim set`, `set_query` and the set benchmark.

## Step 3

Complete:

- the snapshot store `rsim-store` and the collector `rsim-collect` with the SSH and HTTPS transports
- the collection and the ingestion of VyOS, UniFi, NX-OS, IOS-XR and IOS-XE, with one link join for all vendors
- the collection and the ingestion of VeloCloud SD-WAN
- the collection and the ingestion of the Equinix Fabric ports, circuits and Network Edge devices, with the bindings in the link join
- EVPN, VXLAN and the anycast gateway on NX-OS
- the Rust TextFSM engine `rsim-textfsm`
- the BGP sessions, the BGP neighbour config and the claims `bgp-peers-up` and `bgp-peers-agree`
- the collection interval of each device and the retention of the snapshot history
- the manual collection of a device or a group

Open: the snapshot view.

## Other parts

Complete:

- the REST server `rsim-api` with the tables, the claims and the MCP tools over HTTP
- the inventory in PostgreSQL, `rsim-inventory`
- the sign-in of `rsim-api` and the load of a newer snapshot with no restart
- the browser UI in `ui/`
- the second VLAN tag with the TPIDs
- the container images, the compose file, the Helm chart and the CI image build

The Cargo workspace has 14 crates. The other crates of section 3 of the brief come with their steps.
