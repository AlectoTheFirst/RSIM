// The layout of the map: a rank for each device, each neighbour outside the
// twin and each tunnel peer from the link graph and the tunnels to the
// peers, rows of at most 32 cards, the endpoint cards in a stack below their
// device, and each line as horizontal and vertical segments from the border
// of one card to the border of the other.
import { SIZE } from "../theme";
import { type Layer, type MapGraph, type MapNode, type Pair, natural } from "./graph";

/** The most cards of one row; a longer rank wraps. */
export const ROW_MAX = 32;

export type Side = "top" | "bottom" | "left" | "right";

export interface Card {
  id: string;
  node: MapNode;
  x: number;
  y: number;
  w: number;
  h: number;
  /** The rank of a device or outside card from the top; the rank of its device for an endpoint card. */
  rank: number;
  /** The row on the map from the top, endpoint rows included. */
  row: number;
  col: number;
  /** The place in the stack below its device, 0 for a card that is not in a stack. */
  stack: number;
}

export interface LineEnd {
  x: number;
  y: number;
  side: Side;
}

export interface Line {
  /** The key of the pair. */
  key: string;
  layer: Layer;
  pair: Pair;
  /** The points as a flat list of x and y, from the card of `pair.a` to the card of `pair.b`. */
  pts: number[];
  /** The end at the card of `pair.a` and the end at the card of `pair.b`. */
  ends: [LineEnd, LineEnd];
  /** The middle of the line by its length, and whether the segment there is horizontal. */
  mid: { x: number; y: number; horizontal: boolean };
}

export interface MapLayout {
  cards: Card[];
  card: Map<string, Card>;
  lines: Line[];
  line: Map<string, Line>;
  width: number;
  height: number;
  /** The number of ranks of devices and outside cards. */
  ranks: number;
}

const W = SIZE.mapCard;
const H = SIZE.mapCardHeight;
const GAP_X = SIZE.mapColGap;
const GAP_Y = SIZE.mapRowGap;
const PITCH = W + GAP_X;
const STACK_GAP = SIZE.mapStackGap;
const MARGIN = SIZE.mapMargin;
const TRACK = SIZE.mapTrack;
/** The tracks of a channel or a gutter on each side of its middle. */
const TRACKS_Y = Math.max(0, Math.floor(GAP_Y / 4 / TRACK));
const TRACKS_X = Math.max(0, Math.floor(GAP_X / 8 / TRACK));

const isStack = (n: MapNode) => n.kind === "endpoint" || n.kind === "endpoints";

/** Whether a pair places its cards: a physical pair, or a pair with a tunnel peer card. */
const places = (p: Pair) => p.layer === "physical" || p.a.startsWith("p:") || p.b.startsWith("p:");

/** The offset of track `i` from the middle, in the order 0, +1, -1, +2, -2, with `n` tracks on each side. */
function track(i: number, n: number): number {
  const k = i % (2 * n + 1);
  const step = Math.ceil(k / 2);
  return (k % 2 === 1 ? step : -step) * TRACK;
}

/** The rank of each device and outside node: the hops from the nearest device with endpoints, with those devices at the bottom. */
export function ranksOf(g: MapGraph): { rank: Map<string, number>; ranks: number } {
  const ranked = g.nodes.filter((n) => !isStack(n));
  const adj = new Map<string, string[]>();
  for (const n of ranked) adj.set(n.id, []);
  const sources = new Set<string>();
  for (const p of g.pairs) {
    if (!places(p)) continue;
    const a = g.node.get(p.a)!;
    const b = g.node.get(p.b)!;
    if (isStack(a)) sources.add(p.b);
    else if (isStack(b)) sources.add(p.a);
    else {
      adj.get(p.a)!.push(p.b);
      adj.get(p.b)!.push(p.a);
    }
  }
  // A device with the same neighbours as a device with endpoints is in the same rank.
  const neighbourKey = (id: string) => [...adj.get(id)!].sort().join("\u0000");
  const sourceKeys = new Set([...sources].map(neighbourKey).filter((k) => k !== ""));
  for (const n of ranked) if (n.kind === "device" && !sources.has(n.id) && sourceKeys.has(neighbourKey(n.id))) sources.add(n.id);
  const dist = new Map<string, number>();
  let deepest = 0;
  const seen = new Set<string>();
  for (const start of ranked) {
    if (seen.has(start.id)) continue;
    const comp: string[] = [start.id];
    seen.add(start.id);
    for (let i = 0; i < comp.length; i++) {
      for (const m of adj.get(comp[i]!)!) {
        if (!seen.has(m)) {
          seen.add(m);
          comp.push(m);
        }
      }
    }
    let roots = comp.filter((id) => sources.has(id));
    if (roots.length === 0) {
      const devices = comp.filter((id) => g.node.get(id)!.kind === "device");
      const pool = devices.length > 0 ? devices : comp;
      const min = Math.min(...pool.map((id) => adj.get(id)!.length));
      roots = pool.filter((id) => adj.get(id)!.length === min);
    }
    const queue = [...roots];
    for (const r of roots) dist.set(r, 0);
    for (let i = 0; i < queue.length; i++) {
      const id = queue[i]!;
      const d = dist.get(id)!;
      if (d > deepest) deepest = d;
      for (const m of adj.get(id)!) {
        if (!dist.has(m)) {
          dist.set(m, d + 1);
          queue.push(m);
        }
      }
    }
  }
  const rank = new Map<string, number>();
  for (const n of ranked) rank.set(n.id, deepest - dist.get(n.id)!);
  return { rank, ranks: ranked.length === 0 ? 0 : deepest + 1 };
}

/** The order of the cards of each rank: by name, then 3 sweeps by the mean place of the neighbours in the rank above or below. */
function orderRanks(g: MapGraph, rank: Map<string, number>, ranks: number): string[][] {
  const base = new Map<string, number>();
  g.nodes.forEach((n, i) => base.set(n.id, i));
  const rows: string[][] = Array.from({ length: ranks }, () => []);
  for (const n of g.nodes) {
    const r = rank.get(n.id);
    if (r !== undefined) rows[r]!.push(n.id);
  }
  const adj = new Map<string, string[]>();
  for (const p of g.pairs) {
    if (!places(p) || !rank.has(p.a) || !rank.has(p.b)) continue;
    (adj.get(p.a) ?? adj.set(p.a, []).get(p.a)!).push(p.b);
    (adj.get(p.b) ?? adj.set(p.b, []).get(p.b)!).push(p.a);
  }
  const place = new Map<string, number>();
  const setPlaces = (r: number) => {
    const row = rows[r]!;
    const n = Math.max(1, row.length - 1);
    row.forEach((id, i) => place.set(id, row.length === 1 ? 0.5 : i / n));
  };
  for (let r = 0; r < ranks; r++) setPlaces(r);
  const sweep = (r: number, from: number) => {
    const key = new Map<string, number>();
    for (const id of rows[r]!) {
      let sum = 0;
      let n = 0;
      for (const m of adj.get(id) ?? []) {
        if (rank.get(m) === from) {
          sum += place.get(m)!;
          n++;
        }
      }
      key.set(id, n === 0 ? Number.POSITIVE_INFINITY : sum / n);
    }
    rows[r]!.sort((x, y) => {
      const kx = key.get(x)!;
      const ky = key.get(y)!;
      if (kx !== ky) return kx < ky ? -1 : 1;
      return base.get(x)! - base.get(y)!;
    });
    setPlaces(r);
  };
  for (let r = 1; r < ranks; r++) sweep(r, r - 1);
  for (let r = ranks - 2; r >= 0; r--) sweep(r, r + 1);
  for (let r = 1; r < ranks; r++) sweep(r, r - 1);
  return rows;
}

/** The layout of a map graph: the cards and one line for each pair of both layers. */
export function layoutMap(g: MapGraph): MapLayout {
  const { rank, ranks } = ranksOf(g);
  const order = orderRanks(g, rank, ranks);
  // The stack of each device: its endpoint cards by name, then its endpoints card.
  const stacks = new Map<string, MapNode[]>();
  for (const n of g.nodes) {
    if (!isStack(n) || n.device === null) continue;
    const owner = `d:${n.device}`;
    (stacks.get(owner) ?? stacks.set(owner, []).get(owner)!).push(n);
  }
  for (const s of stacks.values()) {
    s.sort((x, y) => (x.kind === y.kind ? natural(x.label, y.label) : x.kind === "endpoint" ? -1 : 1));
  }
  const widest = Math.min(ROW_MAX, Math.max(1, ...order.map((r) => r.length)));
  const cards: Card[] = [];
  const card = new Map<string, Card>();
  let y = MARGIN;
  let row = 0;
  for (let r = 0; r < ranks; r++) {
    const ids = order[r]!;
    for (let start = 0; start < ids.length; start += ROW_MAX) {
      const chunk = ids.slice(start, start + ROW_MAX);
      const offset = Math.floor((widest - chunk.length) / 2);
      let deepest = 0;
      chunk.forEach((id, i) => {
        const col = offset + i;
        const c: Card = { id, node: g.node.get(id)!, x: MARGIN + col * PITCH, y, w: W, h: H, rank: r, row, col, stack: 0 };
        cards.push(c);
        card.set(id, c);
        deepest = Math.max(deepest, stacks.get(id)?.length ?? 0);
      });
      y += H + GAP_Y;
      row++;
      if (deepest === 0) continue;
      for (const id of chunk) {
        const owner = card.get(id)!;
        (stacks.get(id) ?? []).forEach((n, k) => {
          const c: Card = { id: n.id, node: n, x: owner.x, y: y + k * (H + STACK_GAP), w: W, h: H, rank: r, row, col: owner.col, stack: k };
          cards.push(c);
          card.set(n.id, c);
        });
      }
      y += deepest * H + (deepest - 1) * STACK_GAP + GAP_Y;
      row++;
    }
  }
  // A stack card whose device is not on the map: a row of its own at the end.
  const loose = g.nodes.filter((n) => isStack(n) && !card.has(n.id));
  loose.forEach((n, i) => {
    const col = i % widest;
    if (i > 0 && col === 0) {
      y += H + GAP_Y;
      row++;
    }
    const c: Card = { id: n.id, node: n, x: MARGIN + col * PITCH, y, w: W, h: H, rank: ranks, row, col, stack: 0 };
    cards.push(c);
    card.set(n.id, c);
  });
  if (loose.length > 0) {
    y += H + GAP_Y;
    row++;
  }
  const rowBottom: number[] = [];
  const rowTop: number[] = [];
  for (const c of cards) {
    rowTop[c.row] = Math.min(rowTop[c.row] ?? c.y, c.y);
    rowBottom[c.row] = Math.max(rowBottom[c.row] ?? c.y + c.h, c.y + c.h);
  }
  const lines = routeAll(g, card, rowTop, rowBottom);
  const width = cards.length === 0 ? 2 * MARGIN : MARGIN * 2 + widest * PITCH - GAP_X;
  const height = cards.length === 0 ? 2 * MARGIN : y - GAP_Y + MARGIN;
  return { cards, card, lines, line: new Map(lines.map((l) => [l.key, l])), width, height, ranks };
}

interface Plan {
  pair: Pair;
  up: Card;
  low: Card;
  /** The route: a straight line between 2 cards side by side, a line into a stack card beside its upper cards, or a route through the channels. */
  kind: "side" | "stack" | "route";
}

function routeAll(g: MapGraph, card: Map<string, Card>, rowTop: number[], rowBottom: number[]): Line[] {
  const plans: Plan[] = [];
  for (const p of g.pairs) {
    const a = card.get(p.a);
    const b = card.get(p.b);
    if (!a || !b) continue;
    const [up, low] = a.row < b.row || (a.row === b.row && a.col <= b.col) ? [a, b] : [b, a];
    let kind: Plan["kind"] = "route";
    if (up.row === low.row && low.col - up.col === 1 && up.y === low.y) kind = "side";
    else if (low.stack > 0 && low.node.device !== null && up.id === `d:${low.node.device}`) kind = "stack";
    plans.push({ pair: p, up, low, kind });
  }
  // The ports on the top and the bottom of each card, ordered by the place of the far end.
  const slots = new Map<string, { plan: Plan; far: number }[]>();
  const slot = (c: Card, side: "top" | "bottom", plan: Plan, far: number) => {
    const k = `${c.id}\u0000${side}`;
    (slots.get(k) ?? slots.set(k, []).get(k)!).push({ plan, far });
  };
  for (const pl of plans) {
    if (pl.kind === "side") continue;
    slot(pl.up, "bottom", pl, pl.low.x + pl.low.w / 2);
    if (pl.kind === "route") slot(pl.low, pl.low.row === pl.up.row ? "bottom" : "top", pl, pl.up.x + pl.up.w / 2);
  }
  const portX = new Map<string, number>();
  for (const [k, list] of slots) {
    const [id] = k.split("\u0000");
    const c = card.get(id!)!;
    list.sort((x, y) => x.far - y.far || (x.plan.pair.key < y.plan.pair.key ? -1 : 1));
    list.forEach((s, i) => portX.set(`${k}\u0000${s.plan.pair.key}`, c.x + (c.w * (i + 1)) / (list.length + 1)));
  }
  const px = (c: Card, side: "top" | "bottom", key: string) => portX.get(`${c.id}\u0000${side}\u0000${key}`)!;
  const below = (row: number) => rowBottom[row]! + GAP_Y / 2;
  const above = (row: number) => rowTop[row]! - GAP_Y / 2;
  const lines: Line[] = [];
  for (const pl of plans) {
    const { up, low, pair } = pl;
    const key = pair.key;
    let pts: number[];
    let ends: [LineEnd, LineEnd];
    if (pl.kind === "side") {
      const yy = up.y + up.h / 2;
      pts = [up.x + up.w, yy, low.x, yy];
      ends = [
        { x: up.x + up.w, y: yy, side: "right" },
        { x: low.x, y: yy, side: "left" },
      ];
    } else if (pl.kind === "stack") {
      const xa = px(up, "bottom", key);
      const ch = below(up.row) + track(up.col, TRACKS_Y);
      const xs = low.x - GAP_X / 4 - ((low.stack - 1) % Math.max(1, TRACKS_X)) * TRACK;
      const yy = low.y + low.h / 2;
      pts = [xa, up.y + up.h, xa, ch, xs, ch, xs, yy, low.x, yy];
      ends = [
        { x: xa, y: up.y + up.h, side: "bottom" },
        { x: low.x, y: yy, side: "left" },
      ];
    } else if (up.row === low.row) {
      const xa = px(up, "bottom", key);
      const xb = px(low, "bottom", key);
      const ch = below(up.row) + track(up.col, TRACKS_Y);
      pts = [xa, up.y + up.h, xa, ch, xb, ch, xb, low.y + low.h];
      ends = [
        { x: xa, y: up.y + up.h, side: "bottom" },
        { x: xb, y: low.y + low.h, side: "bottom" },
      ];
    } else {
      const xa = px(up, "bottom", key);
      const xb = px(low, "top", key);
      const ch1 = below(up.row) + track(up.col, TRACKS_Y);
      if (low.row === up.row + 1) {
        pts = [xa, up.y + up.h, xa, ch1, xb, ch1, xb, low.y];
      } else {
        const ch2 = above(low.row) + track(low.col, TRACKS_Y);
        const gutter = Math.max(0, Math.round((xb - MARGIN + GAP_X / 2) / PITCH));
        const gx = MARGIN + gutter * PITCH - GAP_X / 2 + track(up.col, TRACKS_X);
        pts = [xa, up.y + up.h, xa, ch1, gx, ch1, gx, ch2, xb, ch2, xb, low.y];
      }
      ends = [
        { x: xa, y: up.y + up.h, side: "bottom" },
        { x: xb, y: low.y, side: "top" },
      ];
    }
    pts = simplify(pts);
    if (up.id !== pair.a) {
      pts = reversePts(pts);
      ends = [ends[1], ends[0]];
    }
    lines.push({ key, layer: pair.layer, pair, pts, ends, mid: midOf(pts) });
  }
  return lines;
}

/** The points with each repeated point and each point inside a straight run removed. */
function simplify(pts: number[]): number[] {
  const out: number[] = [];
  for (let i = 0; i < pts.length; i += 2) {
    const x = pts[i]!;
    const y = pts[i + 1]!;
    const n = out.length;
    if (n >= 2 && out[n - 2] === x && out[n - 1] === y) continue;
    if (n >= 4) {
      const x0 = out[n - 4]!;
      const y0 = out[n - 3]!;
      const x1 = out[n - 2]!;
      const y1 = out[n - 1]!;
      if ((x0 === x1 && x1 === x) || (y0 === y1 && y1 === y)) {
        out[n - 2] = x;
        out[n - 1] = y;
        continue;
      }
    }
    out.push(x, y);
  }
  return out;
}

function reversePts(pts: number[]): number[] {
  const out: number[] = [];
  for (let i = pts.length - 2; i >= 0; i -= 2) out.push(pts[i]!, pts[i + 1]!);
  return out;
}

/** The point at half the length of a line. */
export function midOf(pts: readonly number[]): { x: number; y: number; horizontal: boolean } {
  let total = 0;
  for (let i = 2; i < pts.length; i += 2) total += Math.abs(pts[i]! - pts[i - 2]!) + Math.abs(pts[i + 1]! - pts[i - 1]!);
  let left = total / 2;
  for (let i = 2; i < pts.length; i += 2) {
    const x0 = pts[i - 2]!;
    const y0 = pts[i - 1]!;
    const x1 = pts[i]!;
    const y1 = pts[i + 1]!;
    const len = Math.abs(x1 - x0) + Math.abs(y1 - y0);
    if (left <= len) {
      const t = len === 0 ? 0 : left / len;
      return { x: x0 + (x1 - x0) * t, y: y0 + (y1 - y0) * t, horizontal: y0 === y1 };
    }
    left -= len;
  }
  return { x: pts[0] ?? 0, y: pts[1] ?? 0, horizontal: true };
}
