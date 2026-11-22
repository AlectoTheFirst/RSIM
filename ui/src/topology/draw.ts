// The parts of the map drawing with no drawing code: the text lines of a
// card, the boxes of the port tags and of the labels at the middle of a
// line with no overlap, the rows of the panel, the requests of the Device
// field and of Export, and the keys and the wheel of the map.
import { SIZE, TYPE } from "../theme";
import { type Layer, type MapGraph, type MapNode, natural, speedText } from "./graph";
import type { Line, LineEnd, MapLayout } from "./layout";
import { linksOf } from "./select";
import type { Scope } from "./scope";
import { type MapView, ZOOM_STEP, fitView, showsText } from "./view";

/** The places after which a long name wraps: after `/`, `-`, `.`, `_` or `:`. */
const BREAK = /[/\-._:]/;

/** The lines of a name of at most `max` characters each: a break after a separator, else at `max`. */
export function wrapName(name: string, max: number): string[] {
  const m = Math.max(1, max);
  const out: string[] = [];
  let rest = name;
  while (rest.length > m) {
    let cut = -1;
    for (let i = m - 1; i > 0; i--) {
      if (BREAK.test(rest[i]!)) {
        cut = i + 1;
        break;
      }
    }
    if (cut <= 0) cut = m;
    out.push(rest.slice(0, cut));
    rest = rest.slice(cut);
  }
  if (rest !== "" || out.length === 0) out.push(rest);
  return out;
}

export interface CardLine {
  text: string;
  /** `name` in the type value at the weight 600, `sub` in the type index in ink-muted. */
  kind: "name" | "sub";
}

/** The left inset of the text of a card: the padding, after the hatch strip of a card outside the twin. */
export function textInset(node: MapNode): number {
  return SIZE.mapCardPad + (node.hatch ? SIZE.hatchSquare : 0);
}

/** The most lines of text in a card. */
export const CARD_LINES = Math.floor(SIZE.mapCardHeight / SIZE.mapCardLine);

/**
 * The text of a card: the name in lines that fit the card, then the vendor
 * of a device when the lines leave room for it; the number of an
 * `endpoints` card with the word endpoints.
 */
export function cardLines(node: MapNode, vendor: string | null): CardLine[] {
  if (node.kind === "endpoints") {
    const n = node.count ?? 0;
    return [{ text: `${n} ${n === 1 ? "endpoint" : "endpoints"}`, kind: "name" }];
  }
  const inner = SIZE.mapCard - textInset(node) - SIZE.mapCardPad;
  const lines: CardLine[] = wrapName(node.label, Math.floor(inner / SIZE.valueChar)).map((text) => ({ text, kind: "name" }));
  if (vendor && node.kind === "device" && lines.length < CARD_LINES) lines.push({ text: vendor, kind: "sub" });
  return lines;
}

export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** The width of a text of the type index with the padding of a tag. */
export function tagWidth(text: string): number {
  return text.length * SIZE.indexChar + 2 * SIZE.mapTagPad;
}

/** The box of a port tag beside the end of a line, outside its card. */
export function tagBox(end: LineEnd, text: string): Box {
  const w = tagWidth(text);
  const h = SIZE.mapTag;
  const g = SIZE.mapTagGap;
  switch (end.side) {
    case "bottom":
      return { x: end.x + g, y: end.y + g, w, h };
    case "top":
      return { x: end.x + g, y: end.y - g - h, w, h };
    case "left":
      return { x: end.x - g - w, y: end.y - g - h, w, h };
    case "right":
      return { x: end.x + g, y: end.y - g - h, w, h };
  }
}

/** The box of the number of links at the middle of a line. */
export function countBox(line: Line, count: number): Box {
  const w = tagWidth(String(count));
  return { x: line.mid.x - w / 2, y: line.mid.y - SIZE.mapTag / 2, w, h: SIZE.mapTag };
}

/** The box of the speed text at the middle of a line: above a horizontal segment, at the right of a vertical one, after the box of the number. */
export function speedBox(line: Line, text: string, count: Box | null): Box {
  const w = text.length * SIZE.indexChar;
  const h = SIZE.mapTag;
  const g = SIZE.mapTagGap;
  if (line.mid.horizontal) return { x: line.mid.x - w / 2, y: line.mid.y - h / 2 - g - h, w, h };
  const left = count ? count.x + count.w : line.mid.x;
  return { x: left + g, y: line.mid.y - h / 2, w, h };
}

const CELL = 64;

/** The boxes placed on the map so far, for a test of overlap. */
export class Collider {
  private cells = new Map<string, Box[]>();

  private each(b: Box, f: (k: string) => boolean): boolean {
    const c0 = Math.floor(b.x / CELL);
    const c1 = Math.floor((b.x + b.w) / CELL);
    const r0 = Math.floor(b.y / CELL);
    const r1 = Math.floor((b.y + b.h) / CELL);
    for (let r = r0; r <= r1; r++) for (let c = c0; c <= c1; c++) if (f(`${c}:${r}`)) return true;
    return false;
  }

  /** Whether a box overlaps a placed box. */
  hits(b: Box): boolean {
    return this.each(b, (k) => (this.cells.get(k) ?? []).some((o) => b.x < o.x + o.w && o.x < b.x + b.w && b.y < o.y + o.h && o.y < b.y + b.h));
  }

  add(b: Box): void {
    this.each(b, (k) => {
      const l = this.cells.get(k);
      if (l) l.push(b);
      else this.cells.set(k, [b]);
      return false;
    });
  }

  /** Places a box when it overlaps no placed box; true when placed. */
  place(b: Box): boolean {
    if (this.hits(b)) return false;
    this.add(b);
    return true;
  }
}

/** One row of the list of links of a card in the panel. */
export interface PanelLink {
  /** The id of the card at the other end. */
  far: string;
  farLabel: string;
  /** The port at the card, or the source of a tunnel. */
  near: string | null;
  /** The port at the far card, or the peer address of a tunnel. */
  farPort: string | null;
  /** The speed of a link in Mbit/s, or the VNIs of a tunnel as text. */
  speed: number | null;
  vnis: string | null;
}

/** The rows of the links of a card in a layer: one row for each link or tunnel, by the name of the far card, with no row for an `endpoints` card. */
export function panelLinks(g: MapGraph, id: string, layer: Layer): PanelLink[] {
  const out: PanelLink[] = [];
  for (const c of linksOf(g, id, layer)) {
    if (g.node.get(c.far)?.kind === "endpoints") continue;
    const farLabel = g.node.get(c.far)?.label ?? c.far;
    if (layer === "overlay") {
      for (const t of c.pair.tunnels) {
        out.push({ far: c.far, farLabel, near: t.source || null, farPort: t.peer || null, speed: null, vnis: t.vnis.length ? t.vnis.join(", ") : null });
      }
      if (c.pair.tunnels.length === 0) out.push({ far: c.far, farLabel, near: null, farPort: null, speed: null, vnis: null });
      continue;
    }
    for (const l of c.links) out.push({ far: c.far, farLabel, near: l.near.port, farPort: l.far.port, speed: l.near.speedMbps ?? l.far.speedMbps, vnis: null });
    if (c.links.length === 0) out.push({ far: c.far, farLabel, near: null, farPort: null, speed: null, vnis: null });
  }
  return out;
}

/** The speed of a panel row as text, or null when it is not known. */
export function speedOf(row: PanelLink): string | null {
  return row.speed === null ? null : speedText(row.speed);
}

/** One endpoint of a device in the panel: a row of the table `attachments`. */
export interface EndpointRow {
  host: string | null;
  address: string | null;
  interface: string | null;
}

/** The rows of an answer of the table `attachments`. */
export function endpointRowsOf(t: { columns: string[]; rows: unknown[][] }): EndpointRow[] {
  const at = (c: string) => t.columns.indexOf(c);
  const [h, a, i] = [at("host"), at("address"), at("interface")];
  const text = (v: unknown) => (v === null || v === undefined || v === "" ? null : String(v));
  return t.rows.map((r) => ({ host: h < 0 ? null : text(r[h]), address: a < 0 ? null : text(r[a]), interface: i < 0 ? null : text(r[i]) }));
}

/** The query parameters of the options of the Device field: the devices whose name starts with the text, `limit` of them. */
export function devicePickParams(text: string, limit: number): Record<string, string> {
  const p: Record<string, string> = { columns: "device,vendor", sort: "device", limit: String(limit) };
  const t = text.trim();
  if (t) p["device.prefix"] = t;
  return p;
}

/** The options of the Device field from an answer of the table `devices`: the name and the vendor, each name once. */
export function devicePicks(t: { columns: string[]; rows: unknown[][] }): { name: string; vendor: string | null }[] {
  const d = t.columns.indexOf("device");
  const v = t.columns.indexOf("vendor");
  const seen = new Set<string>();
  const out: { name: string; vendor: string | null }[] = [];
  for (const r of t.rows) {
    const name = r[d];
    if (typeof name !== "string" || seen.has(name)) continue;
    seen.add(name);
    const vendor = v < 0 ? null : r[v];
    out.push({ name, vendor: typeof vendor === "string" && vendor ? vendor : null });
  }
  return out;
}

/** The vendor of each device from an answer of the table `devices`. */
export function vendorsOf(t: { columns: string[]; rows: unknown[][] }): Map<string, string> {
  const out = new Map<string, string>();
  for (const p of devicePicks(t)) if (p.vendor) out.set(p.name, p.vendor);
  return out;
}

/** The file forms of the topology of the API, with the name of each and the extension of its file. */
export const EXPORTS = [
  { format: "graphml", label: "GraphML", ext: "graphml" },
  { format: "mermaid", label: "Mermaid", ext: "mmd" },
  { format: "d2", label: "D2", ext: "d2" },
] as const;

/** The query parameters of the export of the scope of the map in a file form. */
export function exportParams(scope: Scope, devices: readonly string[], format: string): Record<string, string> {
  if (scope.kind === "twin") return { format };
  if (scope.kind === "device") return { around: scope.device, hops: String(scope.hops), format };
  return { device: [...devices].sort(natural).join(","), format };
}

/** The drag of the map in screen pixels for an arrow key, or null for another key. */
export function panKey(key: string): [number, number] | null {
  const s = SIZE.mapPanStep;
  if (key === "ArrowLeft") return [s, 0];
  if (key === "ArrowRight") return [-s, 0];
  if (key === "ArrowUp") return [0, s];
  if (key === "ArrowDown") return [0, -s];
  return null;
}

/** The pixels of one line of a wheel event in line mode. */
const WHEEL_LINE = 16;
/** The wheel pixels of one zoom step. */
const WHEEL_STEP = 100;

/** The zoom factor of a wheel event: one zoom step for each 100 pixels, in for a scroll up. */
export function wheelFactor(deltaY: number, deltaMode: number): number {
  const px = deltaMode === 1 ? deltaY * WHEEL_LINE : deltaY;
  return Math.pow(ZOOM_STEP, -px / WHEEL_STEP);
}

/** The path data of the points of a line. */
export function pathData(pts: readonly number[]): string {
  let d = "";
  for (let i = 0; i < pts.length; i += 2) d += `${i === 0 ? "M" : "L"}${pts[i]} ${pts[i + 1]}`;
  return d;
}

/** The fact names of the panel by the column of the table `devices`. */
export const FACT_LABELS: Record<string, string> = {
  vendor: "vendor",
  platform: "platform",
  os_version: "OS version",
  serial: "serial",
  management_address: "address",
  collected_at: "manifest time",
  store_device: "store device",
};

/** The smallest zoom at which a card shows its text. */
export const TEXT_ZOOM = SIZE.mapTextMin / TYPE.value.size;

/**
 * The view of a map when it opens: the whole map when its text shows at
 * that zoom; else the cards `focus`, or the whole map with no such card, at
 * the zoom that fits them and at least the zoom at which text shows,
 * centred.
 */
export function openView(layout: MapLayout, focus: readonly string[], w: number, h: number): MapView {
  const whole = fitView(layout, w, h);
  if (showsText(whole.zoom)) return whole;
  const cards = focus.map((id) => layout.card.get(id)).filter((c) => c !== undefined);
  let r = { x: 0, y: 0, w: layout.width, h: layout.height };
  if (cards.length > 0) {
    const m = SIZE.mapMargin;
    const x0 = Math.min(...cards.map((c) => c.x)) - m;
    const y0 = Math.min(...cards.map((c) => c.y)) - m;
    const x1 = Math.max(...cards.map((c) => c.x + c.w)) + m;
    const y1 = Math.max(...cards.map((c) => c.y + c.h)) + m;
    r = { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  }
  const zoom = Math.max(TEXT_ZOOM, Math.min(1, w / Math.max(1, r.w), h / Math.max(1, r.h)));
  // A rectangle wider or higher than the window starts at its left or top edge.
  const x = r.w * zoom > w ? r.x : r.x + r.w / 2 - w / 2 / zoom;
  const y = r.h * zoom > h ? r.y : r.y + r.h / 2 - h / 2 / zoom;
  return { zoom, x, y };
}
