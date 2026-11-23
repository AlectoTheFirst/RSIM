// The paths of a query answer on the map: the devices, hops and endpoints
// of each branch, and the marks of all paths or of the selected path.
import type { components } from "../api/schema";
import { type Layer, type MapGraph, type PathEndpoint, type PathExit, apiNodeId, deviceId, endpointId, pairKey, peerId, portOf } from "./graph";

export type PathBriefOut = components["schemas"]["PathBriefOut"];
export type SetBriefOut = components["schemas"]["SetBriefOut"];

export type PathOutcome = "deliver" | "exit" | "drop" | "unknown";

export interface MapPath {
  /** The index of the branch in the answer. */
  index: number;
  /** The devices in path order, each once for each visit. */
  devices: string[];
  /** The hops between 2 devices in path order. */
  hops: [string, string][];
  outcome: PathOutcome;
  /** The source endpoint: the source of the query at the ingress device. */
  source: PathEndpoint | null;
  /** The destination endpoint of a delivery to an endpoint. */
  destination: PathEndpoint | null;
  /** The exit of a path that leaves the twin, with the tunnel peer of the outer packet from the path drawing. */
  exit: PathExit | null;
}

function outcomeOf(kind: string): PathOutcome {
  return kind === "deliver" || kind === "exit" || kind === "drop" ? kind : "unknown";
}

function text(v: unknown): string | null {
  if (typeof v === "string" && v !== "") return v;
  if (typeof v === "number") return String(v);
  return null;
}

/** The paths of a brief answer (`form=steps`), in the order of the answer. */
export function pathsOf(out: PathBriefOut | SetBriefOut): MapPath[] {
  const q = out.query as Record<string, unknown>;
  const sourceLabel = text(q["source.ip"]);
  const destinationLabel = text(q["destination.ip"]);
  const ingress = out.answer.ingress;
  return out.answer.branches.map((b) => {
    const devices: string[] = [];
    for (const s of b.steps) {
      const d = s.device ?? null;
      if (d !== null && devices[devices.length - 1] !== d) devices.push(d);
    }
    const hops: [string, string][] = [];
    for (let i = 1; i < devices.length; i++) hops.push([devices[i - 1]!, devices[i]!]);
    const first = devices[0] ?? null;
    const last = devices[devices.length - 1] ?? null;
    const at = first === null ? undefined : ingress.find((x) => x.found && x.device === first);
    const source = first !== null && sourceLabel !== null ? { label: sourceLabel, device: first, port: at?.interface ?? null } : null;
    const outcome = outcomeOf(b.verdict.kind);
    const dest = b.verdict.destination;
    const label = outcome === "deliver" && dest && !dest.device ? (dest.endpoint ?? destinationLabel) : null;
    const destination = label !== null && last !== null ? { label, device: last, port: null } : null;
    const end = b.steps[b.steps.length - 1];
    const exit = outcome === "exit" && last !== null && end ? { device: last, port: portOf(end.function, last), peer: null } : null;
    return { index: b.index, devices, hops, outcome, source, destination, exit };
  });
}

/** The query of a brief answer as the text of its chip: the source, the destination, the protocol and the destination port. */
export function queryText(out: PathBriefOut | SetBriefOut): string {
  const q = out.query as Record<string, unknown>;
  const parts = [text(q["source.ip"]), "to", text(q["destination.ip"]), text(q["network.transport"]), text(q["destination.port"])];
  return parts.filter((x): x is string => x !== null).join(" ");
}

type Drawing = { nodes: readonly { id: string; kind: string }[]; edges: readonly { layer: string; from: string; to: string; branches: number[] }[] };

/** The paths with the tunnel peer of each exit: the peer node of the overlay edge of the branch from the exit device in the path drawing. */
export function withPeers(paths: readonly MapPath[], drawing: Drawing): MapPath[] {
  const peers = new Set(drawing.nodes.filter((n) => n.kind === "peer").map((n) => n.id));
  return paths.map((p) => {
    if (!p.exit) return p;
    const e = drawing.edges.find((x) => x.layer === "overlay" && x.from === p.exit!.device && peers.has(x.to) && x.branches.includes(p.index));
    return e ? { ...p, exit: { ...p.exit, peer: e.to } } : p;
  });
}

/** The devices of the paths, each once, in the order of their first visit. */
export function pathDevices(paths: readonly MapPath[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of paths) {
    for (const d of p.devices) {
      if (!seen.has(d)) {
        seen.add(d);
        out.push(d);
      }
    }
  }
  return out;
}

/** The endpoint cards and the hops of the paths, for `buildGraph`. */
export function pathGraphInput(paths: readonly MapPath[]): { pathEndpoints: PathEndpoint[]; pathHops: [string, string][]; pathExits: PathExit[] } {
  const pathEndpoints: PathEndpoint[] = [];
  const pathExits: PathExit[] = [];
  const pathHops: [string, string][] = [];
  const seenHop = new Set<string>();
  for (const p of paths) {
    if (p.source) pathEndpoints.push(p.source);
    if (p.destination) pathEndpoints.push(p.destination);
    if (p.exit?.peer) pathExits.push(p.exit);
    for (const [x, y] of p.hops) {
      const k = x <= y ? `${x}\u0000${y}` : `${y}\u0000${x}`;
      if (seenHop.has(k)) continue;
      seenHop.add(k);
      pathHops.push([x, y]);
    }
  }
  return { pathEndpoints, pathHops, pathExits };
}

/** The overlay pairs of each branch, from the path drawing of the API (`/queries/{qid}/topology`). */
export function overlayOf(drawing: Drawing): Map<number, string[]> {
  const out = new Map<number, string[]>();
  const idOf = apiNodeId(drawing.nodes);
  for (const e of drawing.edges) {
    if (e.layer !== "overlay") continue;
    const key = pairKey("overlay", idOf(e.from), idOf(e.to));
    for (const b of e.branches) {
      const l = out.get(b);
      if (l) {
        if (!l.includes(key)) l.push(key);
      } else {
        out.set(b, [key]);
      }
    }
  }
  return out;
}

/** The cards and the pairs of the paths on the map. */
export interface PathMarks {
  cards: Set<string>;
  pairs: Set<string>;
  /** The end card of each path with the outcome of the path; a card that ends paths of 2 outcomes takes `unknown`. */
  ends: Map<string, PathOutcome>;
}

/**
 * The marks of the paths: of the path `selected` (a branch index), or of
 * each path when it is null. The overlay pairs come from `overlay` when the
 * layer is `overlay`.
 */
export function pathMarks(
  g: MapGraph,
  paths: readonly MapPath[],
  selected: number | null,
  layer: Layer = "physical",
  overlay: ReadonlyMap<number, string[]> | null = null,
): PathMarks {
  const cards = new Set<string>();
  const pairs = new Set<string>();
  const ends = new Map<string, PathOutcome>();
  for (const p of paths) {
    if (selected !== null && p.index !== selected) continue;
    for (const d of p.devices) if (g.node.has(deviceId(d))) cards.add(deviceId(d));
    if (layer === "physical") {
      for (const [x, y] of p.hops) {
        const k = pairKey("physical", deviceId(x), deviceId(y));
        if (g.pair.has(k)) pairs.add(k);
      }
    } else {
      for (const k of overlay?.get(p.index) ?? []) {
        if (!g.pair.has(k)) continue;
        pairs.add(k);
        const q = g.pair.get(k)!;
        for (const id of [q.a, q.b]) if (id.startsWith("p:")) cards.add(id);
      }
    }
    const peer = p.exit?.peer ? peerId(p.exit.peer) : null;
    if (peer !== null && g.node.has(peer)) {
      cards.add(peer);
      const k = pairKey("physical", deviceId(p.exit!.device), peer);
      if (layer === "physical" && g.pair.has(k)) pairs.add(k);
    }
    for (const e of [p.source, p.destination]) {
      if (!e) continue;
      const id = endpointId(e.device, e.label);
      if (!g.node.has(id)) continue;
      cards.add(id);
      if (layer === "physical") {
        const k = pairKey("physical", deviceId(e.device), id);
        if (g.pair.has(k)) pairs.add(k);
      }
    }
    const endCard = p.destination
      ? endpointId(p.destination.device, p.destination.label)
      : peer !== null && g.node.has(peer)
        ? peer
        : deviceId(p.devices[p.devices.length - 1] ?? "");
    if (g.node.has(endCard)) {
      const had = ends.get(endCard);
      ends.set(endCard, had === undefined || had === p.outcome ? p.outcome : "unknown");
    }
  }
  return { cards, pairs, ends };
}
