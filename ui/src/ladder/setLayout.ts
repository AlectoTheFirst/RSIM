// The layout of the ladder of a set query: one column for each part, with
// a band from the first row to the function that decides the part.
import type { Answer, Branch, PacketSet, TraceStep, Verdict } from "../api/types";
import {
  type End,
  FIELDS,
  type Field,
  type Lane,
  type Level,
  type Rib,
  fieldText,
  functionLabel,
  groupSource,
  lanesOf,
  mostSpecific,
  ribOfGroup,
  type Shown,
  spanLabel,
} from "./layout";

/** The value of a field in the original header over the members of a set. */
export function originalValue(ps: PacketSet, f: Field): Shown | null {
  if (ps.members.length === 0) return null;
  const key = f === "network.transport" ? "network.iana_number" : f;
  const all = ps.members.map((m) => fieldText((m.original as unknown as Record<string, never>)[key] ?? "unknown", f));
  const texts = [...new Set(all.map((s) => s.text))];
  return { known: texts.length === 1 && all.every((s) => s.known), text: texts.join(" or ") };
}

/** The head of a part column: the fields in which the parts differ. */
export function partHeads(branches: readonly Branch[]): [Field, string][][] {
  const values = branches.map((b) => FIELDS.map((f) => originalValue(b.packets, f)?.text ?? ""));
  const differ = FIELDS.filter((_, i) => new Set(values.map((v) => v[i])).size > 1);
  return values.map((v) => differ.map((f) => [f, v[FIELDS.indexOf(f)]!] as [Field, string]));
}

/**
 * The cell of a part in a row: `band` while the part goes on, `end` at the
 * function that decides it, `apart` where its path leaves the rows, and
 * `none` after it.
 */
export type PartCell =
  | { kind: "band" }
  | { kind: "end"; end: End; verdict: Verdict }
  | { kind: "apart"; step: number }
  | { kind: "none" };

export interface SetRow {
  key: string;
  label: string;
  fn: string;
  lane: number;
  reason: string;
  rib: Rib;
  source: string;
  enterFrom: number | null;
  start: boolean;
  /** The number of parts on the row. */
  parts: number;
  cells: PartCell[];
  group: boolean;
}

export interface SetLadder {
  lanes: Lane[];
  heads: [Field, string][][];
  rows: SetRow[];
}

function endOf(v: Verdict): End {
  return v.kind === "deliver" || v.kind === "exit" || v.kind === "drop" ? v.kind : "unknown";
}

/**
 * The rows follow the longest branch. A part goes on in a row while its
 * step there is the function of the row.
 */
export function setLadder(a: Answer, level: Level): SetLadder {
  const branches = a.branches;
  const spine = branches.reduce<Branch | null>((m, b) => (!m || b.steps.length > m.steps.length ? b : m), null);
  const devs = (b: Branch) => {
    const out: (string | null)[] = [];
    for (const s of b.steps) if (out[out.length - 1] !== (s.device ?? null)) out.push(s.device ?? null);
    return out;
  };
  const lanes = lanesOf(branches.map(devs));
  if (!spine) return { lanes, heads: [], rows: [] };
  // The last step index at which each part is on the rows of the spine.
  const reach = branches.map((b) => {
    let i = 0;
    while (i < b.steps.length && i < spine.steps.length && b.steps[i]!.function === spine.steps[i]!.function) i += 1;
    return i;
  });
  const groups: TraceStep[][] = [];
  for (const s of spine.steps) {
    const last = groups[groups.length - 1];
    if (level === "device" && last && last[0]!.device === s.device) last.push(s);
    else groups.push([s]);
  }
  const laneOf = (d: string | null | undefined) => Math.max(0, lanes.findIndex((l) => l.device === (d ?? null)));
  let prev: number | null = null;
  const rows = groups.map((g, gi) => {
    const first = g[0]!;
    const last = g[g.length - 1]!;
    const lo = first.index;
    const hi = last.index;
    const cells: PartCell[] = branches.map((b, bi) => {
      const n = b.steps.length;
      const r = reach[bi]!;
      if (r === n && n - 1 >= lo && n - 1 <= hi) return { kind: "end", end: endOf(b.verdict), verdict: b.verdict };
      if (r < n && r >= lo && r <= hi) return { kind: "apart", step: r };
      if (Math.min(r, n) - 1 >= hi) return { kind: "band" };
      return { kind: "none" };
    });
    const lane = laneOf(first.device);
    const s = mostSpecific(first.provenance);
    const row: SetRow = {
      key: `s.${lo}`,
      label: g.length === 1 ? String(lo) : `${lo}-${hi}`,
      fn: g.length === 1 ? functionLabel(first) : `${g.length} functions`,
      lane,
      reason: last.reason.detail,
      rib: ribOfGroup(g.map((x) => x.rib_guard)),
      source: g.length === 1 ? (s ? spanLabel(s, first.device) : "") : groupSource(g, first.device),
      enterFrom: prev !== null && prev !== lane ? prev : null,
      start: gi === 0,
      parts: cells.filter((c) => c.kind !== "none").length,
      cells,
      group: g.length > 1,
    };
    prev = lane;
    return row;
  });
  return { lanes, heads: partHeads(branches), rows };
}
