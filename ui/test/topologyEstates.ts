// Generated topology answers for the tests of the map: a fabric of spines
// and leaves, and a 3-tier campus, with invented names.
import type { TopoEdge, TopologyOut } from "../src/topology/graph";

const twin = { id: "builtin.test", base: "builtin.test", snapshot: null, layers: [] };

function out(nodes: string[], edges: TopoEdge[]): TopologyOut {
  return {
    rsim_json: 2,
    kind: "topology",
    topology: "test",
    twin,
    level: "device",
    layers: ["physical", "overlay"],
    nodes: nodes.map((id) => ({ id, kind: "device", label: id, device: id, functions: 10 })),
    edges,
  } as TopologyOut;
}

/** A physical edge of the API with the 2 directions of each link `[port at a, port at b, speed]`. */
export function physical(a: string, b: string, links: [string, string, number | null][]): TopoEdge {
  const [x, y] = a <= b ? [a, b] : [b, a];
  const ls = links.flatMap(([pa, pb, s]) => {
    const [px, py] = a <= b ? [pa, pb] : [pb, pa];
    const e = s === null ? null : { speed_mbps: s, full_duplex: true };
    return [
      { link: `${x}/out/${px} to ${y}/in/${py}`, local: e, remote: e },
      { link: `${y}/out/${py} to ${x}/in/${px}`, local: e, remote: e },
    ];
  });
  return { id: `physical:${x}|${y}`, layer: "physical", from: x, to: y, facts: { links: ls }, provenance: [], claims: {}, branches: [], overlay: null };
}

export function overlay(a: string, b: string, vni: number): TopoEdge {
  return {
    id: `overlay:${a}>${b}`,
    layer: "overlay",
    from: a,
    to: b,
    facts: { tunnels: [{ encap: `${a}/vxlan-encap`, peer: "192.0.2.2", peer_from: "next-hop", source: "192.0.2.1", vnis: [vni] }] },
    provenance: [],
    claims: {},
    branches: [],
    overlay: null,
  };
}

const pad = (n: number, w: number) => String(n).padStart(w, "0");

/** A fabric of `spines` spines and `leaves` leaves, each leaf with one link to each spine, and `endpoints` endpoints spread over the leaves. */
export function fabric(spines: number, leaves: number, endpoints: number): { topology: TopologyOut; counts: Map<string, number> } {
  const s = Array.from({ length: spines }, (_, i) => `spine-${pad(i + 1, 2)}`);
  const l = Array.from({ length: leaves }, (_, i) => `leaf-${pad(i + 1, 3)}`);
  const edges: TopoEdge[] = [];
  s.forEach((sp, i) => l.forEach((lf, j) => edges.push(physical(sp, lf, [[`Ethernet1/${j + 1}`, `Ethernet1/${49 + i}`, 100000]]))));
  const counts = new Map<string, number>();
  for (let i = 0; i < endpoints; i++) {
    const d = l[i % leaves]!;
    counts.set(d, (counts.get(d) ?? 0) + 1);
  }
  return { topology: out([...s, ...l], edges), counts };
}

/** A campus of 4 cores, 96 distribution switches and 1,900 access switches: 2,000 devices and 4,000 links. */
export function campus(): { topology: TopologyOut; counts: Map<string, number> } {
  const core = Array.from({ length: 4 }, (_, i) => `core-${pad(i + 1, 2)}`);
  const dist = Array.from({ length: 96 }, (_, i) => `dist-${pad(i + 1, 3)}`);
  const acc = Array.from({ length: 1900 }, (_, i) => `acc-${pad(i + 1, 4)}`);
  const edges: TopoEdge[] = [];
  for (let i = 0; i < core.length; i++) for (let j = i + 1; j < core.length; j++) edges.push(physical(core[i]!, core[j]!, [[`Te0/${j}`, `Te0/${i}`, 10000]]));
  dist.forEach((d, i) => {
    edges.push(physical(core[i % 4]!, d, [[`Te1/${i}`, "Te0/1", 10000]]));
    edges.push(physical(core[(i + 1) % 4]!, d, [[`Te2/${i}`, "Te0/2", 10000]]));
  });
  edges.push(physical(dist[0]!, dist[1]!, [["Te0/3", "Te0/3", 10000]]));
  edges.push(physical(dist[2]!, dist[3]!, [["Te0/3", "Te0/3", 10000]]));
  const counts = new Map<string, number>();
  acc.forEach((a, i) => {
    const d1 = dist[i % 96]!;
    const d2 = dist[(i + 1) % 96]!;
    edges.push(physical(d1, a, [[`Gi1/${i}`, "Gi0/49", 1000]]));
    edges.push(physical(d2, a, [[`Gi2/${i}`, "Gi0/50", 1000]]));
    counts.set(a, 24);
  });
  return { topology: out([...core, ...dist, ...acc], edges), counts };
}

/** A small site: 2 edge routers with a neighbour outside the twin, 2 cores with 2 links between them, 3 access switches. */
export function site(): TopologyOut {
  const edges = [
    physical("core-01", "core-02", [
      ["Te1/0/47", "Te1/0/47", 10000],
      ["Te1/0/48", "Te1/0/48", 10000],
    ]),
    physical("edge-01", "core-01", [["Te0/0/0/1", "Te1/0/1", 10000]]),
    physical("edge-02", "core-02", [["Te0/0/0/1", "Te1/0/1", 10000]]),
    physical("core-01", "acc-01", [["Te1/0/3", "Te1/1/1", null]]),
    physical("core-01", "acc-02", [["Te1/0/4", "Te1/1/1", 1000]]),
    physical("core-02", "acc-02", [["Te1/0/4", "Te1/1/2", 10000]]),
    physical("core-02", "acc-03", [["Te1/0/5", "Te1/1/1", 10000]]),
    overlay("acc-01", "acc-03", 50001),
    overlay("acc-03", "acc-01", 50001),
  ];
  return out(["acc-01", "acc-02", "acc-03", "core-01", "core-02", "edge-01", "edge-02"], edges);
}
