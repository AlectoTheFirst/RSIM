// The window of the map: zoom, pan and fit, the cards and lines inside a
// window from a grid index, the zoom below which a card shows no text, and
// the hit test of a point.
import { SIZE, TYPE } from "../theme";
import type { Layer } from "./graph";
import type { Card, Line, MapLayout } from "./layout";

/** The window: the map point at the top left of the screen and the screen pixels for each map unit. */
export interface MapView {
  x: number;
  y: number;
  zoom: number;
}

export const ZOOM_MIN = 0.02;
export const ZOOM_MAX = 2;
/** The factor of one press of "Zoom in" or "Zoom out". */
export const ZOOM_STEP = 1.25;

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

const clampZoom = (z: number) => Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, z));

/** The view that shows the whole map in a screen of `w` by `h`, centred, at most at zoom 1. */
export function fitView(layout: Pick<MapLayout, "width" | "height">, w: number, h: number): MapView {
  const zoom = clampZoom(Math.min(1, w / Math.max(1, layout.width), h / Math.max(1, layout.height)));
  return { zoom, x: layout.width / 2 - w / 2 / zoom, y: layout.height / 2 - h / 2 / zoom };
}

/** The view that shows a rect of the map, such as a card, at the centre of the screen at the current zoom. */
export function centreOn(v: MapView, r: Rect, w: number, h: number): MapView {
  return { zoom: v.zoom, x: r.x + r.w / 2 - w / 2 / v.zoom, y: r.y + r.h / 2 - h / 2 / v.zoom };
}

/** The view after a zoom by `factor` that keeps the map point under the screen point `sx`, `sy`. */
export function zoomAt(v: MapView, factor: number, sx: number, sy: number): MapView {
  const zoom = clampZoom(v.zoom * factor);
  const mx = v.x + sx / v.zoom;
  const my = v.y + sy / v.zoom;
  return { zoom, x: mx - sx / zoom, y: my - sy / zoom };
}

/** "Zoom in" and "Zoom out": a zoom step at the centre of the screen. */
export const zoomIn = (v: MapView, w: number, h: number) => zoomAt(v, ZOOM_STEP, w / 2, h / 2);
export const zoomOut = (v: MapView, w: number, h: number) => zoomAt(v, 1 / ZOOM_STEP, w / 2, h / 2);

/** The view after a drag of the map by `dx`, `dy` screen pixels. */
export function panBy(v: MapView, dx: number, dy: number): MapView {
  return { zoom: v.zoom, x: v.x - dx / v.zoom, y: v.y - dy / v.zoom };
}

/** The map rect that a screen of `w` by `h` shows. */
export function windowOf(v: MapView, w: number, h: number): Rect {
  return { x: v.x, y: v.y, w: w / v.zoom, h: h / v.zoom };
}

/** The screen point of a map point. */
export function toScreen(v: MapView, x: number, y: number): { x: number; y: number } {
  return { x: (x - v.x) * v.zoom, y: (y - v.y) * v.zoom };
}

/** The map point of a screen point. */
export function toMap(v: MapView, sx: number, sy: number): { x: number; y: number } {
  return { x: v.x + sx / v.zoom, y: v.y + sy / v.zoom };
}

/** Whether a card shows its text at a zoom: its name is at least 9px high on the screen. */
export function showsText(zoom: number): boolean {
  return TYPE.value.size * zoom >= SIZE.mapTextMin;
}

const CELL = 512;

/** The grid index of the cards and of the segments of each layer. */
export interface MapIndex {
  layout: MapLayout;
  cols: number;
  rows: number;
  cards: Map<number, number[]>;
  segments: Record<Layer, Map<number, number[]>>;
}

function cellsOf(ix: { cols: number; rows: number }, x0: number, y0: number, x1: number, y1: number, each: (k: number) => void) {
  const c0 = Math.max(0, Math.floor(Math.min(x0, x1) / CELL));
  const c1 = Math.min(ix.cols - 1, Math.floor(Math.max(x0, x1) / CELL));
  const r0 = Math.max(0, Math.floor(Math.min(y0, y1) / CELL));
  const r1 = Math.min(ix.rows - 1, Math.floor(Math.max(y0, y1) / CELL));
  for (let r = r0; r <= r1; r++) for (let c = c0; c <= c1; c++) each(r * ix.cols + c);
}

function push(m: Map<number, number[]>, k: number, v: number) {
  const l = m.get(k);
  if (l === undefined) m.set(k, [v]);
  else if (l[l.length - 1] !== v) l.push(v);
}

/** The grid index of a layout, built once for each layout. */
export function indexLayout(layout: MapLayout): MapIndex {
  const ix: MapIndex = {
    layout,
    cols: Math.max(1, Math.ceil(layout.width / CELL)),
    rows: Math.max(1, Math.ceil(layout.height / CELL)),
    cards: new Map(),
    segments: { physical: new Map(), overlay: new Map() },
  };
  layout.cards.forEach((c, i) => cellsOf(ix, c.x, c.y, c.x + c.w, c.y + c.h, (k) => push(ix.cards, k, i)));
  layout.lines.forEach((l, i) => {
    const m = ix.segments[l.layer];
    for (let j = 2; j < l.pts.length; j += 2) cellsOf(ix, l.pts[j - 2]!, l.pts[j - 1]!, l.pts[j]!, l.pts[j + 1]!, (k) => push(m, k, i));
  });
  return ix;
}

const intersects = (a: Rect, x0: number, y0: number, x1: number, y1: number) =>
  Math.max(x0, x1) >= a.x && Math.min(x0, x1) <= a.x + a.w && Math.max(y0, y1) >= a.y && Math.min(y0, y1) <= a.y + a.h;

/** The cards and the lines of a layer with a part inside the map rect `r`, in layout order. */
export function cull(ix: MapIndex, r: Rect, layer: Layer): { cards: Card[]; lines: Line[] } {
  const seenCards = new Set<number>();
  const seenLines = new Set<number>();
  const cardIds: number[] = [];
  const lineIds: number[] = [];
  const { cards, lines } = ix.layout;
  cellsOf(ix, r.x, r.y, r.x + r.w, r.y + r.h, (k) => {
    for (const i of ix.cards.get(k) ?? []) {
      if (seenCards.has(i)) continue;
      seenCards.add(i);
      const c = cards[i]!;
      if (intersects(r, c.x, c.y, c.x + c.w, c.y + c.h)) cardIds.push(i);
    }
    for (const i of ix.segments[layer].get(k) ?? []) {
      if (seenLines.has(i)) continue;
      seenLines.add(i);
      const p = lines[i]!.pts;
      for (let j = 2; j < p.length; j += 2) {
        if (intersects(r, p[j - 2]!, p[j - 1]!, p[j]!, p[j + 1]!)) {
          lineIds.push(i);
          break;
        }
      }
    }
  });
  cardIds.sort((a, b) => a - b);
  lineIds.sort((a, b) => a - b);
  return { cards: cardIds.map((i) => cards[i]!), lines: lineIds.map((i) => lines[i]!) };
}

export type Hit = { kind: "card"; card: Card } | { kind: "line"; line: Line } | null;

/** The card under a screen point, else the nearest line of the layer within `SIZE.mapHit` screen pixels, else null. */
export function hitTest(ix: MapIndex, v: MapView, sx: number, sy: number, layer: Layer): Hit {
  const p = toMap(v, sx, sy);
  const tol = SIZE.mapHit / v.zoom;
  const k = Math.floor(p.y / CELL) * ix.cols + Math.floor(p.x / CELL);
  if (p.x >= 0 && p.y >= 0 && p.x < ix.cols * CELL && p.y < ix.rows * CELL) {
    for (const i of ix.cards.get(k) ?? []) {
      const c = ix.layout.cards[i]!;
      if (p.x >= c.x && p.x <= c.x + c.w && p.y >= c.y && p.y <= c.y + c.h) return { kind: "card", card: c };
    }
  }
  let best: Line | null = null;
  let bestD = tol;
  const near = cull(ix, { x: p.x - tol, y: p.y - tol, w: 2 * tol, h: 2 * tol }, layer).lines;
  for (const l of near) {
    const q = l.pts;
    for (let j = 2; j < q.length; j += 2) {
      const d = distToSegment(p.x, p.y, q[j - 2]!, q[j - 1]!, q[j]!, q[j + 1]!);
      if (d <= bestD) {
        bestD = d;
        best = l;
      }
    }
  }
  return best ? { kind: "line", line: best } : null;
}

function distToSegment(x: number, y: number, x0: number, y0: number, x1: number, y1: number): number {
  const dx = x1 - x0;
  const dy = y1 - y0;
  const len = dx * dx + dy * dy;
  const t = len === 0 ? 0 : Math.max(0, Math.min(1, ((x - x0) * dx + (y - y0) * dy) / len));
  return Math.hypot(x - (x0 + t * dx), y - (y0 + t * dy));
}
