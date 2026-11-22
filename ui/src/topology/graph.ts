// The map graph of the Topology view from the answers of the API: the
// devices, the cards of endpoints and of neighbours outside the twin, and
// one pair for each 2 nodes and layer with the links or tunnels between them.
import type { components } from "../api/schema";

export type TopologyOut = components["schemas"]["TopologyOut"];
export type TopoEdge = components["schemas"]["TopoEdge"];
export type TopoNode = components["schemas"]["TopoNode"];

export type Layer = "physical" | "overlay";
export const LAYERS: readonly Layer[] = ["physical", "overlay"];

/** The kind of a card: a device of the twin, an endpoint of a path, the other endpoints of a device, a neighbour outside the twin. */
export type NodeKind = "device" | "endpoint" | "endpoints" | "outside";

export interface MapNode {
  /** `d:<device>`, `e:<device>:<label>`, `g:<device>` or `o:<neighbour>`. */
  id: string;
  kind: NodeKind;
  /** The name on the card: the device, the endpoint, the neighbour; empty for `endpoints`. */
  label: string;
  /** The device of a device card, or the device that an endpoint card hangs from; null for `outside`. */
  device: string | null;
  /** The number of endpoints of an `endpoints` card, else null. */
  count: number | null;
  /** The number of functions of a device, from the API, else null. */
  functions: number | null;
  /** Whether the card has the hatch: a node outside the twin. */
  hatch: boolean;
}

export interface LinkEnd {
  /** The port name, or null when the API does not name it. */
  port: string | null;
  /** The sub-interfaces of the port that the link carries, `<port>.<number>`, by name. */
  subports: string[];
  speedMbps: number | null;
  fullDuplex: boolean | null;
}

/** One link of a pair: the end at `pair.a` and the end at `pair.b`. */
export interface LinkFact {
  a: LinkEnd;
  b: LinkEnd;
  /** The subjects of the API for this link, `<egress> to <peer>`, one for each direction. */
  subjects: string[];
}

export interface Tunnel {
  encap: string;
  source: string;
  peer: string;
  peerFrom: string;
  vnis: number[];
}

/** The lines between 2 nodes in one layer: one line on the map. */
export interface Pair {
  /** `<layer>|<a>|<b>` with `a` before `b`. */
  key: string;
  layer: Layer;
  a: string;
  b: string;
  /** The links, in the order of their ports. */
  links: LinkFact[];
  /** The tunnels of an overlay pair, both directions. */
  tunnels: Tunnel[];
  /** The ids of the edges of the API. */
  edges: string[];
  /** The result of the claim `link-speed-duplex` when the API gives it. */
  claim: string | null;
  /** Whether a link or a tunnel leaves the twin: a link to an `outside` card. */
  dashed: boolean;
  /** A hop of a path between 2 devices with no link of the API. */
  hop: boolean;
}

export interface MapGraph {
  /** The nodes in the order: devices, outside, endpoint cards. */
  nodes: MapNode[];
  pairs: Pair[];
  node: Map<string, MapNode>;
  pair: Map<string, Pair>;
  /** The keys of the pairs of each node. */
  pairsOf: Map<string, string[]>;
}

export const deviceId = (d: string) => `d:${d}`;
export const groupId = (d: string) => `g:${d}`;
export const endpointId = (d: string, label: string) => `e:${d}:${label}`;
export const outsideId = (n: string) => `o:${n}`;

export function pairKey(layer: Layer, x: string, y: string): string {
  const [a, b] = x <= y ? [x, y] : [y, x];
  return `${layer}|${a}|${b}`;
}

/** Compares 2 names with the digit runs as numbers, then as text: `leaf2` before `leaf10`. */
export function natural(x: string, y: string): number {
  const re = /(\d+)|(\D+)/g;
  const px = x.match(re) ?? [];
  const py = y.match(re) ?? [];
  const n = Math.min(px.length, py.length);
  for (let i = 0; i < n; i++) {
    const a = px[i]!;
    const b = py[i]!;
    if (a === b) continue;
    const da = /^\d/.test(a);
    const db = /^\d/.test(b);
    if (da && db) {
      const d = Number(a) - Number(b);
      if (d !== 0) return d;
      if (a.length !== b.length) return a.length - b.length;
    }
    return a < b ? -1 : 1;
  }
  if (px.length !== py.length) return px.length - py.length;
  return x < y ? -1 : x > y ? 1 : 0;
}

/** The port of a function id of a device: the name after `out/`, `in/` or `handoff/`, or between `port/` and its last part; else the id without the device. */
export function portOf(fn: string, device: string): string {
  const rest = fn.startsWith(`${device}/`) ? fn.slice(device.length + 1) : fn;
  const m = /^(?:out|in|handoff)\/(.+)$/.exec(rest) ?? /^port\/(.+?)(?:\/(?:in|out|stp))?$/.exec(rest);
  return m ? m[1]! : rest;
}

interface RawEnd {
  speed_mbps?: number | null;
  full_duplex?: boolean | null;
}

interface RawLink {
  link?: string;
  local?: RawEnd | null;
  remote?: RawEnd | null;
}

interface RawTunnel {
  encap?: string;
  source?: string;
  peer?: string;
  peer_from?: string;
  vnis?: number[];
}

/** The physical port of a port name: the name without a sub-interface number `.<number>`. */
export function basePort(port: string): string {
  const m = /^(.+)\.\d+$/.exec(port);
  return m ? m[1]! : port;
}

function end(port: string | null, e: RawEnd | null | undefined): LinkEnd {
  const base = port === null ? null : basePort(port);
  return { port: base, subports: port !== null && port !== base ? [port] : [], speedMbps: e?.speed_mbps ?? null, fullDuplex: e?.full_duplex ?? null };
}

/** Joins 2 views of one end: a known value wins. */
function joinEnd(x: LinkEnd, y: LinkEnd): LinkEnd {
  const subports = [...new Set([...x.subports, ...y.subports])].sort(natural);
  return { port: x.port ?? y.port, subports, speedMbps: x.speedMbps ?? y.speedMbps, fullDuplex: x.fullDuplex ?? y.fullDuplex };
}

/** A link end with only a port name. */
export function portEnd(port: string | null): LinkEnd {
  return end(port, null);
}

/**
 * The links of a physical edge between the devices `a` and `b` (`a` before
 * `b`): the 2 directions of one link, `a/out/p to b/in/q` and
 * `b/out/q to a/in/p`, and the sub-interfaces `p.<number>` of a port are one
 * link.
 */
export function linksOfEdge(facts: unknown, a: string, b: string): LinkFact[] {
  const raw = (facts as { links?: RawLink[] } | null)?.links ?? [];
  const byPorts = new Map<string, LinkFact>();
  for (const l of raw) {
    const subject = l.link ?? "";
    const [from, to] = subject.split(" to ");
    if (from === undefined || to === undefined) continue;
    const fromA = from.startsWith(`${a}/`) && to.startsWith(`${b}/`);
    const fromB = from.startsWith(`${b}/`) && to.startsWith(`${a}/`);
    if (!fromA && !fromB) continue;
    const pa = portOf(fromA ? from : to, a);
    const pb = portOf(fromA ? to : from, b);
    const ea = end(pa, fromA ? l.local : l.remote);
    const eb = end(pb, fromA ? l.remote : l.local);
    const k = `${ea.port}\u0000${eb.port}`;
    const had = byPorts.get(k);
    if (had) {
      had.a = joinEnd(had.a, ea);
      had.b = joinEnd(had.b, eb);
      had.subjects.push(subject);
    } else {
      byPorts.set(k, { a: ea, b: eb, subjects: [subject] });
    }
  }
  return [...byPorts.values()].sort((x, y) => natural(x.a.port ?? "", y.a.port ?? "") || natural(x.b.port ?? "", y.b.port ?? ""));
}

function tunnelsOf(facts: unknown): Tunnel[] {
  const raw = (facts as { tunnels?: RawTunnel[] } | null)?.tunnels ?? [];
  return raw.map((t) => ({
    encap: t.encap ?? "",
    source: t.source ?? "",
    peer: t.peer ?? "",
    peerFrom: t.peer_from ?? "",
    vnis: t.vnis ?? [],
  }));
}

/** A row of the table `neighbours`: a neighbour outside the twin seen by a device. */
export interface OutsideNeighbour {
  device: string;
  port: string | null;
  neighbour: string;
  remotePort: string | null;
}

/** The rows of the table `neighbours` by their columns. */
export function neighboursOf(columns: readonly string[], rows: readonly unknown[][]): OutsideNeighbour[] {
  const at = (n: string) => columns.indexOf(n);
  const [d, p, n, r] = [at("device"), at("port"), at("neighbour"), at("remote_port")];
  const text = (v: unknown) => (typeof v === "string" && v !== "" ? v : null);
  const out: OutsideNeighbour[] = [];
  for (const row of rows) {
    const device = text(row[d]);
    const neighbour = text(row[n]);
    if (device === null || neighbour === null) continue;
    out.push({ device, port: text(row[p]), neighbour, remotePort: text(row[r]) });
  }
  return out;
}

/** The counts of the verb `unique` with the column `device`: the endpoints of each device. */
export function countsOf(columns: readonly string[], rows: readonly unknown[][]): Map<string, number> {
  const d = columns.indexOf("device");
  const c = columns.indexOf("count");
  const out = new Map<string, number>();
  for (const row of rows) {
    const device = row[d];
    const n = row[c];
    if (typeof device === "string" && typeof n === "number") out.set(device, (out.get(device) ?? 0) + n);
  }
  return out;
}

/** An endpoint card of a path: its name and the device and port where it attaches. */
export interface PathEndpoint {
  label: string;
  device: string;
  port: string | null;
}

export interface GraphInput {
  topology: TopologyOut;
  /** The endpoints of each device (attachment records), for the `endpoints` cards. */
  endpoints?: ReadonlyMap<string, number>;
  /** The neighbours outside the twin of the devices of the map. */
  outside?: readonly OutsideNeighbour[];
  /** The endpoints of the paths of the query. */
  pathEndpoints?: readonly PathEndpoint[];
  /** The hops of the paths of the query between 2 devices. */
  pathHops?: readonly (readonly [string, string])[];
}

/** The map graph of a topology answer at the device level. */
export function buildGraph(input: GraphInput): MapGraph {
  const nodes: MapNode[] = [];
  const node = new Map<string, MapNode>();
  const add = (n: MapNode) => {
    if (node.has(n.id)) return;
    node.set(n.id, n);
    nodes.push(n);
  };
  const devices = input.topology.nodes
    .filter((n) => n.kind === "device")
    .map((n) => ({ name: n.device ?? n.id, functions: n.functions ?? null }))
    .sort((x, y) => natural(x.name, y.name));
  for (const d of devices) {
    add({ id: deviceId(d.name), kind: "device", label: d.name, device: d.name, count: null, functions: d.functions, hatch: false });
  }
  const pair = new Map<string, Pair>();
  const pairOf = (layer: Layer, x: string, y: string): Pair => {
    const key = pairKey(layer, x, y);
    let p = pair.get(key);
    if (!p) {
      const [a, b] = x <= y ? [x, y] : [y, x];
      p = { key, layer, a, b, links: [], tunnels: [], edges: [], claim: null, dashed: false, hop: false };
      pair.set(key, p);
    }
    return p;
  };
  for (const e of input.topology.edges) {
    if (e.layer !== "physical" && e.layer !== "overlay") continue;
    const x = deviceId(e.from);
    const y = deviceId(e.to);
    if (!node.has(x) || !node.has(y) || x === y) continue;
    const p = pairOf(e.layer, x, y);
    p.edges.push(e.id);
    if (e.layer === "physical") {
      const [da, db] = p.a === x ? [e.from, e.to] : [e.to, e.from];
      p.links.push(...linksOfEdge(e.facts, da, db));
      const c = e.claims["link-speed-duplex"];
      if (c !== undefined) p.claim = c;
    } else {
      p.tunnels.push(...tunnelsOf(e.facts));
    }
  }
  const outside = [...(input.outside ?? [])]
    .filter((o) => node.has(deviceId(o.device)))
    .sort((x, y) => natural(x.neighbour, y.neighbour) || natural(x.device, y.device) || natural(x.port ?? "", y.port ?? ""));
  for (const o of outside) {
    add({ id: outsideId(o.neighbour), kind: "outside", label: o.neighbour, device: null, count: null, functions: null, hatch: true });
  }
  for (const o of outside) {
    const d = deviceId(o.device);
    const n = outsideId(o.neighbour);
    const p = pairOf("physical", d, n);
    p.dashed = true;
    const dev = portEnd(o.port);
    const far = portEnd(o.remotePort);
    p.links.push(p.a === d ? { a: dev, b: far, subjects: [] } : { a: far, b: dev, subjects: [] });
  }
  for (const [x, y] of input.pathHops ?? []) {
    const dx = deviceId(x);
    const dy = deviceId(y);
    if (dx === dy || !node.has(dx) || !node.has(dy)) continue;
    const key = pairKey("physical", dx, dy);
    if (!pair.has(key)) pairOf("physical", dx, dy).hop = true;
  }
  const ends = [...(input.pathEndpoints ?? [])]
    .filter((e) => node.has(deviceId(e.device)))
    .sort((x, y) => natural(x.device, y.device) || natural(x.label, y.label));
  for (const e of ends) {
    const id = endpointId(e.device, e.label);
    const fresh = !node.has(id);
    add({ id, kind: "endpoint", label: e.label, device: e.device, count: null, functions: null, hatch: false });
    const p = pairOf("physical", deviceId(e.device), id);
    if (!fresh && p.links.some((l) => (p.a === id ? l.b.port : l.a.port) === (e.port === null ? null : basePort(e.port)))) continue;
    const dev = portEnd(e.port);
    const far = portEnd(null);
    p.links.push(p.a === id ? { a: far, b: dev, subjects: [] } : { a: dev, b: far, subjects: [] });
  }
  for (const d of devices) {
    const n = input.endpoints?.get(d.name) ?? 0;
    if (n <= 0) continue;
    const id = groupId(d.name);
    add({ id, kind: "endpoints", label: "", device: d.name, count: n, functions: null, hatch: false });
    pairOf("physical", deviceId(d.name), id);
  }
  const pairs = [...pair.values()].sort((x, y) => (x.key < y.key ? -1 : x.key > y.key ? 1 : 0));
  const pairsOf = new Map<string, string[]>();
  for (const p of pairs) {
    for (const id of [p.a, p.b]) {
      const l = pairsOf.get(id);
      if (l) l.push(p.key);
      else pairsOf.set(id, [p.key]);
    }
  }
  return { nodes, pairs, node, pair, pairsOf };
}

/** The speed of a link end as text: `10 Gbit/s`, `100 Mbit/s`. */
export function speedText(mbps: number): string {
  return mbps >= 1000 && mbps % 1000 === 0 ? `${mbps / 1000} Gbit/s` : `${mbps} Mbit/s`;
}

/** The distinct known speeds of the links of a pair, in ascending order. */
export function speedsOf(p: Pair): number[] {
  const s = new Set<number>();
  for (const l of p.links) {
    if (l.a.speedMbps !== null) s.add(l.a.speedMbps);
    if (l.b.speedMbps !== null) s.add(l.b.speedMbps);
  }
  return [...s].sort((x, y) => x - y);
}

/** The number of lines that a pair stands for: its links, its tunnels, or 1. */
export function linkCount(p: Pair): number {
  return Math.max(1, p.layer === "overlay" ? p.tunnels.length : p.links.length);
}
