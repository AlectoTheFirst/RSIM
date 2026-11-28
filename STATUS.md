# Status

Section 13 of `../rsim-project/BUILD_BRIEF.md` gives the steps. `../rsim-project/roadmap.md` gives the order.

| Step | State |
|---|---|
| 1 | Complete |
| 1b: `rsim-topologies`, `rsim-cli` and `rsim-mcp` | Complete |
| 2: the packet sets | Complete |
| 3: collection, the snapshot store, ingestion and the snapshot view | Complete |
| 4: routing, convergence and the RIB guard | In progress |
| 5: what-if | In progress |
| 6 to 9 | Not started |

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
- the snapshot view: the tables of the collected state with their join columns and the frames of each device shared between twins, the table `links` and the claim `path-mtu`, the indexes of the lookups, the export as CSV or Parquet, and the difference of a table, a query and a claim between the 2 held twins

## Step 4

Complete:

- the crate `rsim-routing` with the administrative distances and the install stage with recursive next-hop resolution
- the connected, local and static routes from the config of VyOS, NX-OS, IOS-XR and IOS-XE
- OSPFv2 and OSPFv3 from the config: the config readers of the 4 vendors, the database builder of the twin and the shortest-path calculation
- the collection and the readers of the OSPF databases of the 4 vendors, the reference of the database guard
- the crate `rsim-guard`: the database guard (the table `ospf-guard`) and the route guard (the table `rib-guard`, the claim `rib-fib-agree` and the guard flag of each route lookup step)
- the BGP calculation in `rsim-routing`: the policy evaluator, the decision function, the propagation and the convergence detection, on hand-built inputs
- BGP from the config of VyOS, NX-OS, IOS-XR and IOS-XE, the section `bgp_routes` and the BGP rows of the guard

Not started: redistribution, VRF leaking and the EVPN import, which are gaps of the BGP rows, and the benchmark.

## Step 5

Complete: the unnamed scenario of a snapshot with the layer `link-down`, rule W0, and the option `--down` of `rsim-cli`, the argument `down` of `rsim-mcp` and the query parameter `down` of `rsim-api`.

Not started: the named scenarios and the other layer kinds.

## Other parts

Complete:

- the REST server `rsim-api` with the tables, the claims and the MCP tools over HTTP
- the inventory in PostgreSQL, `rsim-inventory`
- the sign-in of `rsim-api` and the load of a newer snapshot with no restart
- the browser UI in `ui/`
- the second VLAN tag with the TPIDs
- the container images, the compose file, the Helm chart and the CI image build

The Cargo workspace has 16 crates. The other crates of section 3 of the brief come with their steps.
