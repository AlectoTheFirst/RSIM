/// <reference types="node" />
// The map graph of the stored topology answers, the paths of a stored
// answer, and the scope of the map with its requests.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ApiProblem } from "../src/api/client";
import { buildGraph, countsOf, deviceId, endpointId, groupId, linkCount, linksOfEdge, natural, neighboursOf, outsideId, pairKey, portOf, speedText, speedsOf, type TopologyOut } from "../src/topology/graph";
import { overlayOf, pathDevices, pathGraphInput, pathMarks, pathsOf, queryText, withPeers, type PathBriefOut } from "../src/topology/paths";
import { MAX_DRAWN, type Scope, type ScopeApi, collapseScope, expandScope, resolveScope, scopeOf, scopeSearch, siteOptions, sitesOf, tooManyNodes, withoutQuery } from "../src/topology/scope";
import { activeLines, deviceFacts, entryPoint, linksOf } from "../src/topology/select";
import { site } from "./topologyEstates";

const read = <T>(path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as T;
const topology = read<TopologyOut>("../../crates/rsim-api/tests/golden/leaf-spine.topology.json");
const drawing = read<TopologyOut>("../../crates/rsim-api/tests/golden/leaf-spine.path.json");
const steps = read<PathBriefOut>("../../crates/rsim-cli/tests/golden/leaf-spine.steps.json");

describe("the names and the ports", () => {
  it("orders the digit runs as numbers", () => {
    expect(["leaf10", "leaf2", "leaf1", "Leaf3"].sort(natural)).toEqual(["Leaf3", "leaf1", "leaf2", "leaf10"]);
  });

  it("takes the port from an egress, an ingress, a hand-off and a switch port", () => {
    expect(portOf("leaf1/out/eth1", "leaf1")).toBe("eth1");
    expect(portOf("sw-01/in/Ethernet1/1", "sw-01")).toBe("Ethernet1/1");
    expect(portOf("r-01/handoff/Te0/0/0/1", "r-01")).toBe("Te0/0/0/1");
    expect(portOf("sw-01/port/Ethernet1/2/in", "sw-01")).toBe("Ethernet1/2");
    expect(portOf("sw-01/vxlan-encap", "sw-01")).toBe("vxlan-encap");
  });

  it("joins the 2 directions of a link into one link with the port at each end", () => {
    const e = topology.edges.find((x) => x.id === "physical:leaf4|spine1")!;
    expect(linksOfEdge(e.facts, "leaf4", "spine1")).toEqual([
      {
        a: { port: "eth1", subports: [], speedMbps: null, fullDuplex: null },
        b: { port: "eth4", subports: [], speedMbps: null, fullDuplex: null },
        subjects: ["leaf4/out/eth1 to spine1/in/eth4", "spine1/out/eth4 to leaf4/in/eth1"],
      },
    ]);
  });

  it("joins the sub-interfaces of a port into the link of the port", () => {
    const facts = {
      links: [
        { link: "edge-01/out/eth1 to sw-01/port/7/in", local: { speed_mbps: 1000, full_duplex: true }, remote: null },
        { link: "edge-01/out/eth1.20 to sw-01/port/7/in", local: null, remote: null },
        { link: "edge-01/out/eth1.10 to sw-01/port/7/in", local: null, remote: null },
        { link: "sw-01/port/7/out to edge-01/handoff/eth1", local: { speed_mbps: 1000, full_duplex: true }, remote: null },
        { link: "edge-01/out/eth2.30 to sw-01/port/8/in", local: null, remote: null },
      ],
    };
    const links = linksOfEdge(facts, "edge-01", "sw-01");
    expect(links.map((l) => [l.a.port, l.a.subports, l.b.port, l.a.speedMbps, l.b.speedMbps, l.subjects.length])).toEqual([
      ["eth1", ["eth1.10", "eth1.20"], "7", 1000, 1000, 4],
      ["eth2", ["eth2.30"], "8", null, null, 1],
    ]);
  });

  it("prints a speed in Gbit/s when it is whole", () => {
    expect([speedText(10000), speedText(2500), speedText(100)]).toEqual(["10 Gbit/s", "2500 Mbit/s", "100 Mbit/s"]);
  });
});

describe("the graph of leaf-spine", () => {
  const g = buildGraph({ topology });

  it("has one card for each device and one pair for each device pair and layer", () => {
    expect(g.nodes.map((n) => n.id)).toEqual(["d:leaf1", "d:leaf2", "d:leaf3", "d:leaf4", "d:spine1", "d:spine2"]);
    expect(g.pairs.filter((p) => p.layer === "physical")).toHaveLength(8);
    expect(g.pairs.filter((p) => p.layer === "overlay")).toHaveLength(6);
  });

  it("joins the tunnels of both directions of a leaf pair into one line", () => {
    const p = g.pair.get(pairKey("overlay", "d:leaf1", "d:leaf2"))!;
    expect(p.tunnels.map((t) => t.encap)).toEqual(["leaf1/vxlan-encap", "leaf2/vxlan-encap"]);
    expect(linkCount(p)).toBe(2);
  });

  it("keeps the claim of an edge", () => {
    expect(g.pair.get(pairKey("physical", "d:leaf1", "d:spine1"))!.claim).toBe("unknown");
  });
});

describe("the graph of a site", () => {
  const g = buildGraph({
    topology: site(),
    endpoints: new Map([
      ["acc-01", 49],
      ["acc-02", 12],
    ]),
    outside: [
      { device: "edge-01", port: "Te0/0/0/2", neighbour: "isp-a", remotePort: null },
      { device: "edge-02", port: "Te0/0/0/2", neighbour: "isp-a", remotePort: "xe-0/0/1" },
      { device: "not-on-map", port: null, neighbour: "isp-b", remotePort: null },
    ],
    pathEndpoints: [
      { label: "198.51.100.20", device: "acc-01", port: "Gi1/0/7" },
      { label: "203.0.113.53", device: "acc-03", port: null },
    ],
    pathHops: [["acc-01", "acc-03"]],
  });

  it("makes one line with 2 links for the 2 links between the cores", () => {
    const p = g.pair.get(pairKey("physical", "d:core-01", "d:core-02"))!;
    expect(p.links.map((l) => [l.a.port, l.b.port])).toEqual([
      ["Te1/0/47", "Te1/0/47"],
      ["Te1/0/48", "Te1/0/48"],
    ]);
    expect(linkCount(p)).toBe(2);
    expect(speedsOf(p)).toEqual([10000]);
  });

  it("gives a neighbour outside the twin one card with the hatch and a dashed line to each device that sees it", () => {
    const o = g.node.get(outsideId("isp-a"))!;
    expect(o.hatch).toBe(true);
    expect(g.pairsOf.get(o.id)).toEqual([pairKey("physical", "d:edge-01", "o:isp-a"), pairKey("physical", "d:edge-02", "o:isp-a")]);
    expect(g.pair.get(pairKey("physical", "d:edge-02", "o:isp-a"))!.dashed).toBe(true);
    expect(g.node.has(outsideId("isp-b"))).toBe(false);
  });

  it("gives the other endpoints of a device one card with their number", () => {
    expect(g.node.get(groupId("acc-01"))).toMatchObject({ kind: "endpoints", count: 49, device: "acc-01" });
    expect(g.node.has(groupId("acc-03"))).toBe(false);
  });

  it("gives each endpoint of a path a card with the port of its device", () => {
    const id = endpointId("acc-01", "198.51.100.20");
    expect(g.node.get(id)).toMatchObject({ kind: "endpoint", label: "198.51.100.20" });
    const p = g.pair.get(pairKey("physical", "d:acc-01", id))!;
    expect(p.links[0]!.a.port).toBe("Gi1/0/7");
  });

  it("marks a hop of a path with no link of the API", () => {
    expect(g.pair.get(pairKey("physical", "d:acc-01", "d:acc-03"))!.hop).toBe(true);
    expect(g.pair.get(pairKey("physical", "d:core-01", "d:acc-01"))!.hop).toBe(false);
  });

  it("lists the links of a device from its side, by the name of the far card", () => {
    const l = linksOf(g, "d:core-02", "physical");
    expect(l.map((x) => g.node.get(x.far)!.label)).toEqual(["acc-02", "acc-03", "core-01", "edge-02"]);
    expect(l[0]!.links[0]).toEqual({
      near: { port: "Te1/0/4", subports: [], speedMbps: 10000, fullDuplex: true },
      far: { port: "Te1/1/2", subports: [], speedMbps: 10000, fullDuplex: true },
    });
  });

  it("gives the lines of the selected card and of the card under the pointer in one layer", () => {
    expect([...activeLines(g, ["d:acc-01", null], "overlay")]).toEqual([pairKey("overlay", "d:acc-01", "d:acc-03")]);
    expect(activeLines(g, ["d:edge-01", "o:isp-a"], "physical").size).toBe(3);
  });
});

describe("the paths of leaf-spine", () => {
  const paths = pathsOf(steps);

  it("has one path for each branch with its devices in path order and the endpoints at its ends", () => {
    expect(paths.map((p) => [p.index, p.devices, p.outcome])).toEqual([
      [0, ["leaf1", "spine1", "leaf2"], "deliver"],
      [1, ["leaf1", "spine2", "leaf2"], "deliver"],
    ]);
    expect(paths[0]!.source).toEqual({ label: "10.1.0.10", device: "leaf1", port: "eth9" });
    expect(paths[0]!.destination).toEqual({ label: "host2", device: "leaf2", port: null });
    expect(pathDevices(paths)).toEqual(["leaf1", "spine1", "leaf2", "spine2"]);
  });

  const g = buildGraph({ topology, ...pathGraphInput(paths) });

  it("marks the devices and links of each path, and of the selected path", () => {
    const all = pathMarks(g, paths, null);
    expect([...all.cards].sort()).toEqual(["d:leaf1", "d:leaf2", "d:spine1", "d:spine2", "e:leaf1:10.1.0.10", "e:leaf2:host2"]);
    expect(all.pairs.size).toBe(6);
    const one = pathMarks(g, paths, 1);
    expect(one.cards.has("d:spine1")).toBe(false);
    expect(one.pairs.has(pairKey("physical", "d:leaf1", "d:spine2"))).toBe(true);
    expect(one.ends.get("e:leaf2:host2")).toBe("deliver");
  });

  it("marks the tunnel of the paths in the layer overlay from the path drawing", () => {
    const over = overlayOf(drawing);
    expect(over.get(0)).toEqual([pairKey("overlay", "d:leaf1", "d:leaf2")]);
    expect([...pathMarks(g, paths, 0, "overlay", over).pairs]).toEqual([pairKey("overlay", "d:leaf1", "d:leaf2")]);
  });
});

describe("the facts of a device", () => {
  it("gives each fact with the reason of a fact that the twin does not know", () => {
    const facts = deviceFacts(
      ["device", "vendor", "vendor_reason", "platform", "platform_reason", "serial", "serial_reason"],
      [["core-01", "ios-xe", null, null, "not_read", "FDO0000X000", null]],
    )!;
    expect(facts.slice(0, 4)).toEqual([
      { fact: "vendor", value: "ios-xe", reason: null },
      { fact: "platform", value: null, reason: "not_read" },
      { fact: "os_version", value: null, reason: null },
      { fact: "serial", value: "FDO0000X000", reason: null },
    ]);
    expect(deviceFacts(["device"], [])).toBeNull();
  });

  it("gives the entry point of a device and of a port", () => {
    expect([entryPoint("core-01"), entryPoint("core-01", "Te1/0/1")]).toEqual(["core-01", "core-01/Te1/0/1"]);
  });
});

describe("a transport network of an SD-WAN", () => {
  const twinJson = { id: "builtin.sdwan", base: "builtin.sdwan", snapshot: null, layers: [] };
  const node = (id: string, kind: string) => ({ id, kind, label: id, device: id, functions: 4 });
  const link = (from: string, to: string) => ({ id: `physical:${from}|${to}`, layer: "physical", from, to, facts: { links: [] }, provenance: [], claims: {}, branches: [], overlay: null });
  const topo = {
    rsim_json: 2,
    kind: "topology",
    topology: "sdwan",
    twin: twinJson,
    level: "device",
    layers: ["physical", "overlay"],
    nodes: [node("e1", "device"), node("e2", "device"), node("ent/transport/public", "network")],
    edges: [link("e1", "ent/transport/public"), link("e2", "ent/transport/public")],
  } as unknown as TopologyOut;
  const g = buildGraph({ topology: topo });

  it("draws the network as a card of the twin with a link to each edge", () => {
    expect(g.node.get("d:ent/transport/public")).toMatchObject({ kind: "network", device: "ent/transport/public", hatch: false });
    expect(g.node.get("d:e1")).toMatchObject({ kind: "device" });
    expect(g.pair.has(pairKey("physical", "d:e1", "d:ent/transport/public"))).toBe(true);
    expect(g.pair.get(pairKey("physical", "d:e2", "d:ent/transport/public"))!.dashed).toBe(false);
  });
});

describe("a path into a WireGuard tunnel to a peer outside the twin", () => {
  const twinJson = { id: "builtin.vpn", base: "builtin.vpn", snapshot: null, layers: [] };
  const peerNode = { id: "peer:203.0.113.5", kind: "peer", label: "remote", device: null, functions: null };
  const r1 = { id: "r1", kind: "device", label: "r1", device: "r1", functions: 12 };
  const tunnel = {
    id: "overlay:r1>peer:203.0.113.5",
    layer: "overlay",
    from: "r1",
    to: "peer:203.0.113.5",
    facts: { tunnels: [{ encap: "r1/wireguard/wg0", peer_from: "fixed", name: "remote", source: "198.51.100.1", peer: "203.0.113.5", port: 51820, vnis: [] }] },
    provenance: [],
    claims: {},
    branches: [0],
    overlay: null,
  };
  const topo = { rsim_json: 2, kind: "topology", topology: "vpn", twin: twinJson, level: "device", layers: ["physical", "overlay"], nodes: [r1, peerNode], edges: [tunnel] } as unknown as TopologyOut;
  const brief = {
    query: { "source.ip": "192.0.2.10", "destination.ip": "198.51.100.53", "network.transport": "udp", "destination.port": 53 },
    answer: {
      ingress: [{ found: true, device: "r1", interface: "eth1", function: "r1/in/eth1" }],
      branches: [
        {
          index: 0,
          verdict: { kind: "exit", destination: null, reason: { code: "exited", detail: "r1 pppoe0" } },
          steps: [
            { index: 0, function: "r1/in/eth1", device: "r1", outcome: "forward", reason: { code: "passed", detail: "" } },
            { index: 1, function: "r1/wireguard/wg0", device: "r1", outcome: "forward", reason: { code: "encapsulated", detail: "" } },
            { index: 2, function: "r1/out/pppoe0", device: "r1", outcome: "exit", reason: { code: "exited", detail: "" } },
          ],
        },
      ],
    },
  } as unknown as PathBriefOut;
  const drawing = { nodes: [r1, peerNode], edges: [tunnel] };
  const paths = withPeers(pathsOf(brief), drawing);
  const g = buildGraph({ topology: topo, ...pathGraphInput(paths) });

  it("gives the exit port, the tunnel peer and the text of the query", () => {
    expect(paths[0]!.exit).toEqual({ device: "r1", port: "pppoe0", peer: "peer:203.0.113.5" });
    expect(queryText(brief)).toBe("192.0.2.10 to 198.51.100.53 udp 53");
  });

  it("draws the peer as a hatched card with the tunnel and the exit link from its port", () => {
    expect(g.node.get("p:peer:203.0.113.5")).toMatchObject({ kind: "peer", label: "remote", hatch: true });
    const t = g.pair.get(pairKey("overlay", "d:r1", "p:peer:203.0.113.5"))!;
    expect([t.dashed, t.tunnels[0]!.name, t.tunnels[0]!.port]).toEqual([true, "remote", 51820]);
    const x = g.pair.get(pairKey("physical", "d:r1", "p:peer:203.0.113.5"))!;
    expect([x.dashed, x.links.map((l) => (x.a === "d:r1" ? l.a.port : l.b.port))]).toEqual([true, ["pppoe0"]]);
  });

  it("marks the exit link in the layer physical and the tunnel in the layer overlay, with the peer as the end", () => {
    const phys = pathMarks(g, paths, null);
    expect([...phys.pairs].sort()).toEqual([pairKey("physical", "d:r1", "p:peer:203.0.113.5"), pairKey("physical", "d:r1", "e:r1:192.0.2.10")].sort());
    expect(phys.ends.get("p:peer:203.0.113.5")).toBe("exit");
    const over = pathMarks(g, paths, null, "overlay", overlayOf(drawing));
    expect(over.pairs.has(pairKey("overlay", "d:r1", "p:peer:203.0.113.5"))).toBe(true);
  });
});

describe("the scope of the map", () => {
  it("reads the scope from the URL: the device, else the site, else the query, else the twin", () => {
    expect(scopeOf("?view=topology&device=core-01&site=fra01")).toEqual({ kind: "device", device: "core-01", expand: [] });
    expect(scopeOf("?device=core-01&expand=acc-10,core-01,acc-2,acc-2")).toEqual({ kind: "device", device: "core-01", expand: ["acc-2", "acc-10"] });
    expect(scopeOf("?site=fra01&q=qabc&expand=acc-01")).toEqual({ kind: "site", site: "fra01" });
    expect(scopeOf("?q=qabc&expand=acc-01")).toEqual({ kind: "paths", expand: ["acc-01"] });
    expect(scopeOf("?view=topology&expand=acc-01")).toEqual({ kind: "twin" });
  });

  it("writes the scope into the URL and keeps the other parameters", () => {
    expect(scopeSearch("?view=topology&q=qabc&site=fra01", { kind: "device", device: "core-01", expand: ["acc-10", "acc-2"] })).toBe(
      "?view=topology&q=qabc&device=core-01&expand=acc-2%2Cacc-10",
    );
    expect(scopeSearch("?view=topology&device=core-01&expand=acc-01", { kind: "paths", expand: [] })).toBe("?view=topology");
    expect(scopeSearch("?q=qabc&device=core-01", { kind: "site", site: "fra01" })).toBe("?q=qabc&site=fra01");
  });

  it("adds and removes the neighbours of a device, and removes the query", () => {
    const d: Scope = { kind: "device", device: "core-01", expand: [] };
    expect(expandScope(d, "acc-01")).toEqual({ kind: "device", device: "core-01", expand: ["acc-01"] });
    expect(expandScope(d, "core-01")).toBeNull();
    expect(expandScope({ kind: "paths", expand: ["acc-01"] }, "acc-01")).toBeNull();
    expect(expandScope({ kind: "twin" }, "acc-01")).toBeNull();
    expect(collapseScope({ kind: "paths", expand: ["acc-01", "acc-02"] }, "acc-01")).toEqual({ kind: "paths", expand: ["acc-02"] });
    expect(withoutQuery("?view=topology&q=qabc&expand=acc-01")).toBe("?view=topology");
    expect(withoutQuery("?view=topology&q=qabc&device=core-01&expand=acc-01")).toBe("?view=topology&device=core-01&expand=acc-01");
  });

  it("lists the sites of the inventory once each", () => {
    expect(sitesOf([{ site: "fra01" }, { site: null }, { site: "ams02" }, { site: "fra01" }, {}])).toEqual(["ams02", "fra01"]);
  });
});

/** A fake API on a topology: `around` with `hops`, `device`, and the counts of the table `devices`. */
function fakeApi(t: TopologyOut, opts: { total?: number; refuseAround?: string } = {}): ScopeApi & { calls: string[] } {
  const calls: string[] = [];
  const names = t.nodes.map((n) => n.id);
  const near = (d: string) => t.edges.filter((e) => e.layer === "physical" && (e.from === d || e.to === d)).map((e) => (e.from === d ? e.to : e.from));
  const view = (keep: Set<string>): TopologyOut => ({
    ...t,
    nodes: t.nodes.filter((n) => keep.has(n.id)),
    edges: t.edges.filter((e) => keep.has(e.from) && keep.has(e.to)),
  });
  return {
    calls,
    deviceTotal: async () => {
      calls.push("total");
      return opts.total ?? names.length;
    },
    devicesWhere: async (column, values, limit) => {
      calls.push(`devices ${column}`);
      const d = column === "device" ? names.filter((n) => values.includes(n)) : [];
      return { devices: d.slice(0, limit), total: d.length };
    },
    topology: async (p) => {
      calls.push(`topology ${new URLSearchParams(p).toString()}`);
      if (p["around"]) {
        if (p["around"] === opts.refuseAround) throw new ApiProblem(422, "invalid_filter", "the view has 2400 nodes, more than 2000; use the level device, the filter devices or around");
        const keep = new Set([p["around"]]);
        for (let h = 0; h < Number(p["hops"] ?? 1); h++) for (const d of [...keep]) for (const m of near(d)) keep.add(m);
        return view(keep);
      }
      if (p["device"]) return view(new Set(p["device"].split(",")));
      return t;
    },
    endpointCounts: async () => new Map(),
    outside: async () => [],
    paths: async () => [],
  };
}

describe("the reads of a scope", () => {
  it("draws a twin of at most 300 devices and counts a larger twin with no read of its topology", async () => {
    expect((await resolveScope({ kind: "twin" }, fakeApi(site()), null, null)).state).toBe("draw");
    const big = fakeApi(site(), { total: MAX_DRAWN + 1 });
    expect(await resolveScope({ kind: "twin" }, big, null, null)).toEqual({ state: "too-many", count: 301 });
    expect(big.calls).toEqual(["total"]);
  });

  it("draws the devices of a site of the inventory", async () => {
    const inv = [
      { name: "core-01", site: "fra01" },
      { name: "acc-01", site: "fra01" },
      { name: "edge-01", site: "ams02" },
    ];
    const r = await resolveScope({ kind: "site", site: "fra01" }, fakeApi(site()), inv, null);
    expect(r.state === "draw" && r.devices).toEqual(["acc-01", "core-01"]);
    expect(await resolveScope({ kind: "site", site: "lon03" }, fakeApi(site()), inv, null)).toEqual({ state: "none" });
    const many = Array.from({ length: 301 }, (_, i) => ({ name: `acc-${i}`, site: "fra01" }));
    const api = fakeApi(site());
    expect(await resolveScope({ kind: "site", site: "fra01" }, api, many, null)).toEqual({ state: "too-many", count: 301 });
    expect(api.calls).toEqual([]);
  });

  it("draws a device with its neighbours and the neighbours of each expanded device, and counts a view that the API refuses", async () => {
    const r = await resolveScope({ kind: "device", device: "core-01", expand: [] }, fakeApi(site()), null, null);
    expect(r.state === "draw" && [...r.devices].sort()).toEqual(["acc-01", "acc-02", "core-01", "core-02", "edge-01"]);
    const refused = await resolveScope({ kind: "device", device: "core-01", expand: [] }, fakeApi(site(), { refuseAround: "core-01" }), null, null);
    expect(refused).toEqual({ state: "too-many", count: 2400 });
    const wide = await resolveScope({ kind: "device", device: "acc-01", expand: [] }, fakeApi(site()), null, null);
    const more = await resolveScope({ kind: "device", device: "acc-01", expand: ["core-01"] }, fakeApi(site()), null, null);
    expect(wide.state === "draw" && more.state === "draw" && more.devices.length > wide.devices.length).toBe(true);
  });

  it("draws the paths with the neighbours of their devices, and the paths alone when the neighbours make more than 300", async () => {
    const paths = pathsOf(steps);
    const r = await resolveScope({ kind: "paths", expand: [] }, fakeApi(topology), null, paths);
    expect(r.state === "draw" && [r.devices.length, r.neighbours]).toEqual([6, true]);
    const alone = await resolveScope({ kind: "paths", expand: [] }, fakeApi(topology, { refuseAround: "spine1" }), null, paths);
    expect(alone.state === "draw" && [[...alone.devices].sort(), alone.neighbours]).toEqual([["leaf1", "leaf2", "spine1", "spine2"], false]);
    expect(await resolveScope({ kind: "paths", expand: [] }, fakeApi(topology), null, [])).toEqual({ state: "none" });
  });
});

describe("the ids of the cards", () => {
  it("keeps a device, an endpoint, an endpoints card and an outside card apart", () => {
    expect(new Set([deviceId("x"), groupId("x"), endpointId("x", "x"), outsideId("x")]).size).toBe(4);
  });
});

describe("the answers of the API on the map", () => {
  it("reads the number of nodes of a refused view", () => {
    const detail = "the view has 412 nodes, more than 400; use the level device, the filter devices or around";
    expect(tooManyNodes(new ApiProblem(422, "invalid_filter", detail))).toBe(412);
    expect(tooManyNodes(new ApiProblem(422, "invalid_filter", "more than 400 nodes"))).toBeNull();
    expect(tooManyNodes(new ApiProblem(422, "unknown_device", detail))).toBeUndefined();
    expect(tooManyNodes(new Error(detail))).toBeUndefined();
  });

  it("adds the endpoint counts of each device and drops a row with no device", () => {
    const counts = countsOf(["device", "count"], [["leaf-001", 3], ["leaf-001", 2], [null, 1]]);
    expect([...counts]).toEqual([["leaf-001", 5]]);
  });

  it("reads the neighbour rows by column name and drops a row with no device or no neighbour", () => {
    const rows = neighboursOf(
      ["neighbour", "remote_port", "device", "port"],
      [
        ["phone-01", "eth0", "leaf-001", "Ethernet1/5"],
        ["", "eth0", "leaf-001", "Ethernet1/6"],
        ["phone-02", null, null, "Ethernet1/7"],
      ],
    );
    expect(rows).toEqual([{ device: "leaf-001", port: "Ethernet1/5", neighbour: "phone-01", remotePort: "eth0" }]);
  });

  it("gives the sites that start with the text, one page at a time", () => {
    const sites = Array.from({ length: 120 }, (_, i) => `site-${String(i).padStart(3, "0")}`);
    expect(siteOptions(sites, "", 1)).toEqual({ list: sites.slice(0, 50), more: true });
    expect(siteOptions(sites, "SITE-11", 1)).toEqual({ list: sites.slice(110, 120), more: false });
    expect(siteOptions(sites, "", 3)).toEqual({ list: sites, more: false });
  });
});
