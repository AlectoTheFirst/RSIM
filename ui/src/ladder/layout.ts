// The layout of the ladder: the lanes, the rows and the content of each
// cell, from a query answer in the full form. No drawing code.
import type {
  Answer,
  Branch,
  FieldValue,
  Header,
  PacketSet,
  Qos,
  Span,
  TraceStep,
  Verdict,
} from "../api/types";

/** The header field columns of the path query page. */
export const FIELDS = [
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "network.transport",
] as const;
export type Field = (typeof FIELDS)[number];

/** The protocol names of the engine. */
const TRANSPORT: Record<number, string> = { 1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6" };

/** A field value as the UI shows it: its text, and whether the twin knows it. */
export interface Shown {
  known: boolean;
  text: string;
}

function rawValue(h: Header, f: Field): FieldValue {
  const key = f === "network.transport" ? "network.iana_number" : f;
  return (h as unknown as Record<string, FieldValue>)[key] ?? "unknown";
}

function one(x: unknown, f: Field | null): string {
  if (f === "network.transport" && typeof x === "number") return TRANSPORT[x] ?? String(x);
  return String(x);
}

/** The text of one field value. A range or a list of values is not known. */
export function fieldText(v: FieldValue, f: Field | null): Shown {
  if (v === "absent") return { known: true, text: "absent" };
  if (v === "unknown" || v === "original") return { known: false, text: v };
  if ("known" in v) return { known: true, text: one(v.known, f) };
  const parts = v.in.map((r) => {
    if (Array.isArray(r) && r.length === 2) {
      return r[0] === r[1] ? one(r[0], f) : `${one(r[0], f)}-${one(r[1], f)}`;
    }
    return one(r, f);
  });
  return { known: false, text: parts.join(",") };
}

/** The value of a field in the current header of one member. */
export function memberValue(m: { original: Header; current: Header }, f: Field): Shown {
  let v = rawValue(m.current, f);
  if (v === "original") v = rawValue(m.original, f);
  return fieldText(v, f);
}

/**
 * The value of a field over the members of a packet set: known only if
 * each member knows the same value. An empty set has no value.
 */
export function setValue(ps: PacketSet, f: Field): Shown | null {
  if (ps.members.length === 0) return null;
  const all = ps.members.map((m) => memberValue(m, f));
  const texts = [...new Set(all.map((s) => s.text))];
  return { known: texts.length === 1 && all.every((s) => s.known), text: texts.join(" or ") };
}

/**
 * One header cell. `value` prints a value, `changed` prints the value that
 * the function wrote, `same` is the hairline of a value that stays, and
 * `hatch` is a value that the twin does not know.
 */
export type Cell =
  | { kind: "value"; text: string }
  | { kind: "changed"; text: string }
  | { kind: "same" }
  | { kind: "hatch"; text: string };

/**
 * The cell of a row from the value before and after its functions. The
 * first row of a path prints each value; a later row prints a value only
 * where it changes.
 */
export function cell(before: Shown | null, after: Shown | null, first: boolean): Cell {
  const a = before ?? after;
  const b = after ?? before;
  if (!a || !b) return { kind: "hatch", text: "no packets" };
  if (a.text !== b.text || a.known !== b.known) {
    return b.known ? { kind: "changed", text: b.text } : { kind: "hatch", text: b.text };
  }
  if (!a.known) return { kind: "hatch", text: a.text };
  return first ? { kind: "value", text: a.text } : { kind: "same" };
}

/** The RIB guard cell. */
export type Rib = "none" | "hatch" | "matches" | "differs";

export function ribOf(guard: string): Rib {
  switch (guard) {
    case "not_checked":
      return "hatch";
    case "matches_collected":
      return "matches";
    case "differs_from_collected":
      return "differs";
    default:
      return "none";
  }
}

const RIB_ORDER: Rib[] = ["none", "matches", "hatch", "differs"];

/** The RIB cell of a group of steps: the strongest of its steps. */
export function ribOfGroup(guards: string[]): Rib {
  let r: Rib = "none";
  for (const g of guards) {
    const x = ribOf(g);
    if (RIB_ORDER.indexOf(x) > RIB_ORDER.indexOf(r)) r = x;
  }
  return r;
}

/** The span with the fewest lines; the first of equal spans. */
export function mostSpecific(spans: readonly Span[]): Span | null {
  let best: Span | null = null;
  for (const s of spans) {
    if (!best || s.last_line - s.first_line < best.last_line - best.first_line) best = s;
  }
  return best;
}

/** The file of a span with the device prefix that the lane gives left out. */
export function fileLabel(file: string, device: string | null | undefined): string {
  return device && file.startsWith(`${device}.`) ? file.slice(device.length + 1) : file;
}

export function spanLabel(s: Span, device: string | null | undefined): string {
  const f = fileLabel(s.file, device);
  return s.first_line === s.last_line ? `${f}:${s.first_line}` : `${f}:${s.first_line}-${s.last_line}`;
}

/**
 * The source of a group of steps: the most used file of their most
 * specific spans, from its first line to its last line.
 */
export function groupSource(steps: readonly TraceStep[], device: string | null | undefined): string {
  const byFile = new Map<string, { n: number; first: number; last: number }>();
  for (const st of steps) {
    const s = mostSpecific(st.provenance);
    if (!s) continue;
    const e = byFile.get(s.file);
    if (e) {
      e.n += 1;
      e.first = Math.min(e.first, s.first_line);
      e.last = Math.max(e.last, s.last_line);
    } else {
      byFile.set(s.file, { n: 1, first: s.first_line, last: s.last_line });
    }
  }
  let best: [string, { n: number; first: number; last: number }] | null = null;
  for (const e of byFile) if (!best || e[1].n > best[1].n) best = e;
  if (!best) return "";
  return spanLabel({ file: best[0], first_line: best[1].first, last_line: best[1].last }, device);
}

/** The function name with the device prefix that the lane gives left out. */
export function functionLabel(st: TraceStep): string {
  const d = st.device;
  return d && st.function.startsWith(`${d}/`) ? st.function.slice(d.length + 1) : st.function;
}

export type Dir = "forward" | "reply";
export type Level = "device" | "function";
export type End = "deliver" | "drop" | "unknown";

/** The path of a row: a forward branch, or a branch of the reply of one. */
export interface PathRef {
  replyOf: number | null;
  branch: number;
}

export interface Lane {
  device: string | null;
  name: string;
}

export interface StepRow {
  type: "step";
  key: string;
  dir: Dir;
  path: PathRef;
  /** The trace steps of the row, in order. */
  steps: TraceStep[];
  label: string;
  fn: string;
  lane: number;
  reason: string;
  cells: Cell[];
  rib: Rib;
  source: string;
  /** The lane of the row above when the path steps across at this row. */
  enterFrom: number | null;
  start: boolean;
  end: End | null;
  /** A device-level row with more than one function. */
  group: boolean;
}

export interface SectionRow {
  type: "section";
  key: string;
  dir: Dir;
  text: string;
  verdict: Verdict | null;
  note: string | null;
}

export type Row = StepRow | SectionRow;

export interface Ladder {
  lanes: Lane[];
  rows: Row[];
}

function endOf(v: Verdict): End {
  return v.kind === "deliver" ? "deliver" : v.kind === "drop" ? "drop" : "unknown";
}

/** The device sequence of a branch, with each run of one device once. */
function devicesOf(b: Branch): (string | null)[] {
  const out: (string | null)[] = [];
  for (const s of b.steps) {
    const d = s.device ?? null;
    if (out.length === 0 || out[out.length - 1] !== d) out.push(d);
  }
  return out;
}

/** Each branch of an answer and of its replies, forward first. */
export function allBranches(a: Answer): Branch[] {
  const out = [...a.branches];
  for (const r of a.replies) if (r.answer) out.push(...r.answer.branches);
  return out;
}

/**
 * The lanes in path order. A device that a later path adds goes before the
 * next device of that path that has a lane, so that equal-cost paths keep
 * their devices side by side.
 */
export function lanesOf(paths: readonly (readonly (string | null)[])[]): Lane[] {
  const lanes: (string | null)[] = [];
  for (const seq of paths) {
    seq.forEach((d, i) => {
      if (lanes.includes(d)) return;
      const next = seq.slice(i + 1).find((x) => lanes.includes(x));
      const at = next === undefined ? lanes.length : lanes.indexOf(next);
      lanes.splice(at, 0, d);
    });
  }
  return lanes.map((d) => ({ device: d, name: d ?? "no device" }));
}

/** The groups of steps of one row each at a level. */
function groups(steps: readonly TraceStep[], level: Level): TraceStep[][] {
  const out: TraceStep[][] = [];
  for (const s of steps) {
    const last = out[out.length - 1];
    if (level === "device" && last && last[0]!.device === s.device) last.push(s);
    else out.push([s]);
  }
  return out;
}

/** The rows of one path. */
export function pathRows(
  b: Branch,
  path: PathRef,
  dir: Dir,
  level: Level,
  lanes: readonly Lane[],
): StepRow[] {
  const gs = groups(b.steps, level);
  const laneOf = (d: string | null | undefined) =>
    Math.max(0, lanes.findIndex((l) => l.device === (d ?? null)));
  const prefix = `${path.replyOf === null ? "f" : `r${path.replyOf}`}.${path.branch}`;
  let prevLane: number | null = null;
  return gs.map((g, gi) => {
    const first = g[0]!;
    const last = g[g.length - 1]!;
    const lane = laneOf(first.device);
    const row: StepRow = {
      type: "step",
      key: `${prefix}.${first.index}`,
      dir,
      path,
      steps: g,
      label: g.length === 1 ? String(first.index) : `${first.index}-${last.index}`,
      fn: g.length === 1 ? functionLabel(first) : `${g.length} functions`,
      lane,
      reason: last.reason.detail,
      cells: FIELDS.map((f) => cell(setValue(first.input, f), setValue(last.output, f), gi === 0)),
      rib: ribOfGroup(g.map((s) => s.rib_guard)),
      source:
        g.length === 1
          ? (() => {
              const s = mostSpecific(first.provenance);
              return s ? spanLabel(s, first.device) : "";
            })()
          : groupSource(g, first.device),
      enterFrom: prevLane !== null && prevLane !== lane ? prevLane : null,
      start: gi === 0,
      end: gi === gs.length - 1 ? endOf(b.verdict) : null,
      group: g.length > 1,
    };
    prevLane = lane;
    return row;
  });
}

/** The ladder of a path query answer: the forward branches, then the replies. */
export function ladder(a: Answer, level: Level): Ladder {
  const lanes = lanesOf(allBranches(a).map(devicesOf));
  const rows: Row[] = [];
  const multi = a.branches.length > 1;
  for (const b of a.branches) {
    if (multi) {
      rows.push({ type: "section", key: `f.${b.index}`, dir: "forward", text: `branch ${b.index}`, verdict: b.verdict, note: null });
    }
    rows.push(...pathRows(b, { replyOf: null, branch: b.index }, "forward", level, lanes));
  }
  for (const r of a.replies) {
    const fb = r.forward_branch;
    if (!r.ran || !r.answer) {
      rows.push({ type: "section", key: `r${fb}`, dir: "reply", text: `reply of branch ${fb}`, verdict: null, note: r.not_run_reason ?? null });
      continue;
    }
    const rmulti = r.answer.branches.length > 1;
    for (const b of r.answer.branches) {
      rows.push({
        type: "section",
        key: `r${fb}.${b.index}`,
        dir: "reply",
        text: rmulti ? `reply of branch ${fb}, branch ${b.index}` : `reply of branch ${fb}`,
        verdict: b.verdict,
        note: null,
      });
      rows.push(...pathRows(b, { replyOf: fb, branch: b.index }, "reply", level, lanes));
    }
  }
  return { lanes, rows };
}

/** The number of functions with no delay data and of links with no delay data. */
export function delayGaps(b: Pick<Branch, "delay">): { functions: number; links: number } {
  const fns = new Set<string>();
  let links = 0;
  for (const m of b.delay.missing) {
    if (m.kind === "link") links += 1;
    else fns.add(m.function);
  }
  return { functions: fns.size, links };
}

/** The number of route lookups of the answer that no collected RIB checks. */
export function ribNotChecked(a: Answer): number {
  return allBranches(a).reduce((n, b) => n + b.steps.filter((s) => s.rib_guard === "not_checked").length, 0);
}

/** The devices of a branch in order, each once. */
export function devicesOnPath(b: Branch): string[] {
  return [...new Set(b.steps.map((s) => s.device).filter((d): d is string => !!d))];
}

/** The engine word of a verdict kind, in the case of the engine. */
export function verdictWord(kind: string): string {
  return kind.length ? kind[0]!.toUpperCase() + kind.slice(1) : kind;
}

/** The destination of a verdict, if any. */
export function destinationOf(v: Verdict): string | null {
  return v.destination?.endpoint ?? v.destination?.device ?? null;
}

/** The query fields that the query does not state. */
export function notStated(echo: Record<string, unknown>): string[] {
  const skip = new Set(["topology", "ingress", "reply", "network.iana_number", "network.transport"]);
  const stated = echo["network.transport"] != null || echo["network.iana_number"] != null;
  const out = Object.keys(echo).filter((k) => !skip.has(k) && echo[k] == null);
  if (!stated) out.push("network.transport");
  return out;
}

/** Whether the engine knows an outcome kind: `deliver` and `drop` have a colour, each other kind the hatch. */
export function outcomeKnown(kind: string): boolean {
  return kind === "deliver" || kind === "drop";
}

/** The parts of a set answer by result: each part counts once. */
export function partCounts(parts: readonly { result: { kind: string; verdict?: Verdict | null; verdict_kind?: string | null } }[]): {
  deliver: number;
  drop: number;
  unknown: number;
  dependsOnPath: number;
} {
  const out = { deliver: 0, drop: 0, unknown: 0, dependsOnPath: 0 };
  for (const p of parts) {
    if (p.result.kind === "depends_on_path") {
      out.dependsOnPath += 1;
      continue;
    }
    const k = p.result.verdict_kind ?? p.result.verdict?.kind;
    if (k === "deliver" || k === "drop" || k === "unknown") out[k] += 1;
  }
  return out;
}

/** The text of a QoS value. A range, a value that varies or an unknown value is not known. */
export function qosShown(v: Qos[keyof Qos]): Shown {
  if (typeof v === "string") return { known: v === "unset" || v === "none", text: v };
  if ("value" in v) return fieldText(v.value, null);
  return { known: true, text: String(v.known) };
}

/** The delay of a step. A delay with no data for some functions or links is a lower bound and not known. */
export function delayShown(d: Branch["delay"]): Shown {
  if (!d.lower_bound) return { known: true, text: `${d.known_ns} ns` };
  const g = delayGaps({ delay: d });
  return {
    known: false,
    text: `at least ${d.known_ns} ns: ${g.functions} functions and ${g.links} links have no delay data`,
  };
}

/** The rate condition of a step: its exceed action, then its rate, which is not known with no rate. */
export function rateShown(rc: NonNullable<TraceStep["rate_condition"]>): { action: string; rate: Shown } {
  return {
    action: rc.exceed_action,
    rate: rc.rate_bps == null ? { known: false, text: "rate not known" } : { known: true, text: `${rc.rate_bps} bps` },
  };
}

/** A source span of the opened row with its label and a key. */
export interface DetailSource {
  key: string;
  label: string;
  span: Span;
}

/**
 * The source spans of the steps of a row, each once: the most specific
 * span first, then the others in the order of the steps.
 */
export function detailSources(steps: readonly TraceStep[]): DetailSource[] {
  const out: DetailSource[] = [];
  for (const st of steps) {
    for (const p of st.provenance) {
      const key = `${p.file}:${p.first_line}-${p.last_line}`;
      if (!out.some((e) => e.key === key)) out.push({ key, label: spanLabel(p, st.device), span: p });
    }
  }
  const best = mostSpecific(out.map((e) => e.span));
  const i = out.findIndex((e) => e.span === best);
  if (i > 0) out.unshift(...out.splice(i, 1));
  return out;
}

