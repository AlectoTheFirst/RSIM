// The selection of the map: the lines of the selected card and of the card
// under the pointer, the links of a card for the panel, and the facts of a
// device from the table `devices`.
import { type Layer, type LinkEnd, type MapGraph, type Pair, linkCount, natural, speedsOf } from "./graph";

/** The keys of the lines of a layer that touch the cards `ids`: the lines in `action-ink`. */
export function activeLines(g: MapGraph, ids: readonly (string | null)[], layer: Layer): Set<string> {
  const out = new Set<string>();
  for (const id of ids) {
    if (id === null) continue;
    for (const k of g.pairsOf.get(id) ?? []) if (g.pair.get(k)!.layer === layer) out.add(k);
  }
  return out;
}

/** One link of a card for the panel: the port at the card and the port and the speed at each end. */
export interface LinkRow {
  near: LinkEnd;
  far: LinkEnd;
}

/** The lines of a card in a layer for the panel: the far card, the number of links and each link from the side of the card. */
export interface CardLinks {
  pair: Pair;
  /** The id of the card at the other end. */
  far: string;
  count: number;
  speeds: number[];
  links: LinkRow[];
}

/** The lines of a card in a layer, ordered by the name of the far card. */
export function linksOf(g: MapGraph, id: string, layer: Layer): CardLinks[] {
  const out: CardLinks[] = [];
  for (const k of g.pairsOf.get(id) ?? []) {
    const p = g.pair.get(k)!;
    if (p.layer !== layer) continue;
    const near = p.a === id;
    out.push({
      pair: p,
      far: near ? p.b : p.a,
      count: linkCount(p),
      speeds: speedsOf(p),
      links: p.links.map((l) => (near ? { near: l.a, far: l.b } : { near: l.b, far: l.a })),
    });
  }
  const label = (x: string) => g.node.get(x)?.label ?? x;
  return out.sort((x, y) => natural(label(x.far), label(y.far)) || (x.far < y.far ? -1 : 1));
}

/** The facts of a device in the order of the panel, with the column of the table `devices` that gives each. */
export const DEVICE_FACTS = ["vendor", "platform", "os_version", "serial", "management_address", "collected_at", "store_device"] as const;
export type DeviceFact = (typeof DEVICE_FACTS)[number];

export interface FactValue {
  fact: DeviceFact;
  /** The value, or null when the twin does not know it. */
  value: string | null;
  /** The reason of a null value: `not_collected` or `not_read`; null with a value or with no reason column. */
  reason: string | null;
}

/** The query parameters of the row of a device in the table `devices`. */
export function deviceFactsParams(device: string): Record<string, string> {
  return { device, limit: "1" };
}

/** The facts of the first row of an answer of the table `devices`, or null with no row. */
export function deviceFacts(columns: readonly string[], rows: readonly unknown[][]): FactValue[] | null {
  const row = rows[0];
  if (!row) return null;
  const at = (c: string) => {
    const i = columns.indexOf(c);
    return i < 0 ? undefined : row[i];
  };
  return DEVICE_FACTS.map((fact) => {
    const v = at(fact);
    const r = at(`${fact}_reason`);
    const value = v === null || v === undefined ? null : String(v);
    return { fact, value, reason: value === null && typeof r === "string" ? r : null };
  });
}

/** The query parameters of one page of the attachment records of a device, for the list of its endpoints. */
export function endpointsParams(device: string, limit: number, cursor: string | null): Record<string, string> {
  const p: Record<string, string> = { device, limit: String(limit) };
  if (cursor) p["cursor"] = cursor;
  return p;
}

/** The entry point of a card for "Use as entry point": the device, or the device and the port of a single link to the selected line. */
export function entryPoint(device: string, port: string | null = null): string {
  return port ? `${device}/${port}` : device;
}
