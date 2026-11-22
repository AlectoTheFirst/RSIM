# Status

Section 13 of `../rsim-project/BUILD_BRIEF.md` gives the steps. `../rsim-project/roadmap.md` gives the order and the pull requests.

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

- the snapshot store `rsim-store` and the collector `rsim-collect` with the SSH and HTTPS transports, jump hosts and proxies
- the collection and the ingestion of VyOS, UniFi, NX-OS, IOS-XR and IOS-XE, with one link join for all vendors
- EVPN, VXLAN and the anycast gateway on NX-OS
- the Rust TextFSM engine `rsim-textfsm`
- BGP parts B1 to B5: the route table of each VRF, the next-hop resolution, the session collection, the neighbour config and the claims `bgp-peers-up` and `bgp-peers-agree`
- the HTTP API parts A1 to A3b: the registry, the twin identity, the tables, the claims, the REST server `rsim-api` and the MCP tools over HTTP
- the inventory in PostgreSQL, `rsim-inventory`
- the sign-in of `rsim-api` (A6-1) and the load of a newer snapshot with no restart (A6-2)
- the browser UI in `ui/`
- the second VLAN tag with the TPIDs
- the container images, the compose file, the Helm chart and the CI image build
- the collection interval of each device and the retention of the snapshot history

Next: Equinix Fabric F1 to F6. Check Point and VeloCloud follow the owner decisions of their design notes.

Open in step 3: the snapshot view, pull request 4b.

Deployment, open: the Argo CD applications, the demo seed and OIDC sign-in (A6-3).

The Cargo workspace has 14 crates. The other crates of section 3 of the brief come with their steps.
