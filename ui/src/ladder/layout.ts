// The layout of the ladder: the lanes, the rows and the content of each
// cell of one path of a query answer in the full form. No drawing code.
import type { Answer, Branch, FieldValue, Header, PacketSet, Qos, Span, TraceStep, Verdict } from "../api/types";
import { SIZE } from "../theme";

/** The header fields of the path strip and of the deciding step. */
export const FIELDS = ["source.ip", "source.port", "destination.ip", "destination.port", "network.transport"] as const;
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

/**
 * The text of one field value. A range or a list of values is not known in
 * a path query, and known in a set query, whose packets are each value.
 */
export function fieldText(v: FieldValue, f: Field | null, set = false): Shown {
  if (v === "absent") return { known: true, text: "absent" };
  if (v === "unknown" || v === "original") return { known: false, text: v };
  if ("known" in v) return { known: true, text: one(v.known, f) };
  const parts = v.in.map((r) => {
    if (Array.isArray(r) && r.length === 2) {
      return r[0] === r[1] ? one(r[0], f) : `${one(r[0], f)}-${one(r[1], f)}`;
    }
    return one(r, f);
  });
  return { known: set, text: parts.join(",") };
}

/** The value of a field in the current header of one member. */
export function memberValue(m: { original: Header; current: Header }, f: Field, set = false): Shown {
  let v = rawValue(m.current, f);
  if (v === "original") v = rawValue(m.original, f);
  return fieldText(v, f, set);
}

/**
 * The value of a field over the members of a packet set: known only if
 * each member knows the same value. An empty set has no value.
 */
export function setValue(ps: PacketSet, f: Field, set = false): Shown | null {
  if (ps.members.length === 0) return null;
  const all = ps.members.map((m) => memberValue(m, f, set));
  const texts = [...new Set(all.map((s) => s.text))];
  return { known: texts.length === 1 && all.every((s) => s.known), text: texts.join(" or ") };
}

/** The name of a header key in the UI: the protocol number shows as the transport. */
export function fieldName(key: string): string {
  return key === "network.iana_number" ? "network.transport" : key;
}

/** The text of the encapsulation of a header: the kind and the VNI or label of each level, or absent. */
function encapText(h: Header): Shown {
  const list = h.encap ?? [];
  if (list.length === 0) return { known: true, text: "absent" };
  let known = true;
  const parts = list.map((e) => {
    const id = e.vni ?? e.label;
    if (id === null || id === undefined) return e.kind;
    const t = fieldText(id as FieldValue, null);
    if (!t.known) known = false;
    return `${e.kind} ${t.text}`;
  });
  return { known, text: parts.join(",") };
}

/** The value of one header key of a member, with `original` taken from the original header. */
function keyValue(m: { original: Header; current: Header }, key: string, set: boolean): Shown {
  if (key === "encap") return encapText(m.current);
  const cur = m.current as unknown as Record<string, FieldValue | null | undefined>;
  const org = m.original as unknown as Record<string, FieldValue | null | undefined>;
  let v = cur[key];
  if (v === "original") v = org[key];
  if (v === null || v === undefined) return { known: true, text: "absent" };
  return fieldText(v, fieldName(key) === "network.transport" ? "network.transport" : null, set);
}

/** The keys of the headers of a set, in the order of the header; the inner header is no key. */
function headerKeys(ps: PacketSet): string[] {
  const out: string[] = [];
  for (const m of ps.members) for (const k of Object.keys(m.current)) if (k !== "inner" && !out.includes(k)) out.push(k);
  return out;
}

/** The value of one header key over the members of a set, or null for an empty set. */
export function keyShown(ps: PacketSet, key: string, set = false): Shown | null {
  if (ps.members.length === 0) return null;
  const all = ps.members.map((m) => keyValue(m, key, set));
  const texts = [...new Set(all.map((s) => s.text))];
  return { known: texts.length === 1 && all.every((s) => s.known), text: texts.join(" or ") };
}

/** A header field that the functions of a row write: its value before and after. */
export interface Rewrite {
  field: string;
  before: Shown;
  after: Shown;
}

/**
 * The header fields that a group of steps writes: each field whose value
 * over the packets after the last step differs from its value before the
 * first step. A step with no packets after it writes nothing.
 */
export function rewritesOf(steps: readonly TraceStep[], set = false): Rewrite[] {
  const first = steps[0];
  const last = steps[steps.length - 1];
  if (!first || !last || last.output.members.length === 0 || first.input.members.length === 0) return [];
  const keys = headerKeys(first.input);
  for (const k of headerKeys(last.output)) if (!keys.includes(k)) keys.push(k);
  const out: Rewrite[] = [];
  for (const k of keys) {
    const before = keyShown(first.input, k, set)!;
    const after = keyShown(last.output, k, set)!;
    if (before.text !== after.text || before.known !== after.known) out.push({ field: fieldName(k), before, after });
  }
  return out;
}

/** The RIB guard of a step: none, matches, differs or not checked. */
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

/** The RIB guard of a group of steps: the strongest of its steps. */
export function ribOfGroup(guards: string[]): Rib {
  let r: Rib = "none";
  for (const g of guards) {
    const x = ribOf(g);
    if (RIB_ORDER.indexOf(x) > RIB_ORDER.indexOf(r)) r = x;
  }
  return r;
}

/** The span with the fewest lines; the last of equal spans. */
export function mostSpecific(spans: readonly Span[]): Span | null {
  let best: Span | null = null;
  for (const s of spans) {
    if (!best || s.last_line - s.first_line <= best.last_line - best.first_line) best = s;
  }
  return best;
}

/**
 * The kind of the file of a span: its name after the last `/`, with the
 * device prefix that the lane gives and the content hash after `@` left out.
 */
export function fileLabel(file: string, device: string | null | undefined): string {
  let f = file.slice(file.lastIndexOf("/") + 1);
  const at = f.indexOf("@");
  if (at > 0) f = f.slice(0, at);
  return device && f.startsWith(`${device}.`) && f.length > device.length + 1 ? f.slice(device.length + 1) : f;
}

/** Whether a span names the rows of a collected table, not lines of a text. */
export function isRowSpan(s: Span): boolean {
  return s.file.endsWith("#row");
}

export function spanLabel(s: Span, device: string | null | undefined): string {
  const f = fileLabel(s.file, device);
  if (isRowSpan(s)) return s.first_line === s.last_line ? `${f} row ${s.first_line}` : `${f} rows ${s.first_line}-${s.last_line}`;
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

/** The space at the right of a function name in its column, in px. */
export const FUNCTION_PAD = SIZE.buttonPad;

/**
 * The width of the function column in px: the longest name at `charPx` px
 * for each character, from `SIZE.colFunction` to `SIZE.colFunctionMax`.
 */
export function functionWidth(names: readonly string[], charPx: number = SIZE.valueChar): number {
  const longest = names.reduce((n, s) => Math.max(n, s.length), 0);
  const w = Math.ceil(longest * charPx) + FUNCTION_PAD;
  return Math.min(SIZE.colFunctionMax, Math.max(SIZE.colFunction, w));
}

/** The function names of each step of an answer and of its replies, with no device prefix. */
export function functionNames(a: Answer): string[] {
  return allBranches(a).flatMap((b) => b.steps.map(functionLabel));
}

const NBSP = " ";

/**
 * The parts of a name between its line breaks: a part ends after each `/`.
 * A part that fits in a column of `width` px keeps its spaces from breaking,
 * so the name breaks after a `/` first, then at a space, then at the edge.
 */
export function nameParts(name: string, width: number, charPx: number = SIZE.valueChar): string[] {
  const chars = Math.floor((width - FUNCTION_PAD) / charPx);
  const parts: string[] = [];
  let start = 0;
  for (let i = 0; i < name.length; i++) {
    if (name[i] === "/") {
      parts.push(name.slice(start, i + 1));
      start = i + 1;
    }
  }
  if (start < name.length) parts.push(name.slice(start));
  return parts.map((p) => (p.length <= chars ? p.replace(/ /g, NBSP) : p));
}

export type Dir = "forward" | "reply";
export type Level = "device" | "function";
export type End = "deliver" | "exit" | "drop" | "unknown";

/** The path of a row: a forward branch, or a branch of the reply of one. */
export interface PathRef {
  replyOf: number | null;
  branch: number;
}

export function samePath(a: PathRef, b: PathRef): boolean {
  return a.replyOf === b.replyOf && a.branch === b.branch;
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
  rewrites: Rewrite[];
  source: string;
  /** The lane from which the path steps across at the top of this row: the lane of the row above. */
  enterFrom: number | null;
  start: boolean;
  end: End | null;
  /** A device-level row with more than one function. */
  group: boolean;
}

export interface Ladder {
  lanes: Lane[];
  rows: StepRow[];
}

export function endOf(v: Verdict): End {
  return v.kind === "deliver" || v.kind === "exit" || v.kind === "drop" ? v.kind : "unknown";
}

/** The device sequence of a branch, with each run of one device once. */
export function devicesOf(b: Branch): (string | null)[] {
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

/** The branch of a path of an answer, or null. */
export function branchOf(a: Answer, p: PathRef): Branch | null {
  if (p.replyOf === null) return a.branches.find((b) => b.index === p.branch) ?? null;
  const r = a.replies.find((x) => x.forward_branch === p.replyOf);
  return r?.answer?.branches.find((b) => b.index === p.branch) ?? null;
}

/**
 * The lanes in path order: the devices, each once. A device that a later
 * sequence adds goes before the next device of that sequence that has a
 * lane.
 */
export function lanesOf(paths: readonly (readonly (string | null)[])[]): Lane[] {
  const lanes: (string | null)[] = [];
  for (const seq of paths) {
    const before = new Set(lanes);
    seq.forEach((d, i) => {
      if (lanes.includes(d)) return;
      const next = seq.slice(i + 1).find((x) => before.has(x));
      const at = next === undefined ? lanes.length : lanes.indexOf(next);
      lanes.splice(at, 0, d);
    });
  }
  return lanes.map((d) => ({ device: d, name: d ?? "no device" }));
}

/** The index of the lane of a device. */
export function laneIndex(lanes: readonly Lane[], d: string | null): number {
  return lanes.findIndex((l) => l.device === d);
}

/** The endpoint that a verdict delivers to, if it names one. */
export function endpointOf(v: Verdict): string | null {
  return v.kind === "deliver" ? (v.destination?.endpoint ?? null) : null;
}

/**
 * The endpoint at the start of each forward branch: the endpoint to which
 * its reply delivers.
 */
export function sourceEndpoints(a: Answer): Map<number, string> {
  const out = new Map<number, string>();
  for (const r of a.replies) {
    const ends = [...new Set((r.answer?.branches ?? []).map((b) => endpointOf(b.verdict)))];
    if (ends.length === 1 && ends[0]) out.set(r.forward_branch, ends[0]);
  }
  return out;
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

/** The key of the rows of a path. */
export function pathKey(p: PathRef): string {
  return `${p.replyOf === null ? "f" : `r${p.replyOf}`}.${p.branch}`;
}

/** The rows of one path. */
export function pathRows(b: Branch, path: PathRef, level: Level, lanes: readonly Lane[], set = false): StepRow[] {
  const gs = groups(b.steps, level);
  const dir: Dir = path.replyOf === null ? "forward" : "reply";
  const laneOf = (d: string | null | undefined) => Math.max(0, laneIndex(lanes, d ?? null));
  const prefix = pathKey(path);
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
      rewrites: rewritesOf(g, set),
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

/**
 * The ladder of one path of a path query answer, or of one part of a set
 * query answer with `set`: a lane for each device of the path in path
 * order, and a row for each function or each device.
 */
export function ladder(a: Answer, level: Level, path: PathRef, set = false): Ladder {
  const b = branchOf(a, path);
  if (!b) return { lanes: [], rows: [] };
  const lanes = lanesOf([devicesOf(b)]);
  return { lanes, rows: pathRows(b, path, level, lanes, set) };
}

/** The number of route lookups of the answer that no collected RIB checks. */
export function ribNotChecked(a: Answer): number {
  return allBranches(a).reduce((n, b) => n + b.steps.filter((s) => s.rib_guard === "not_checked").length, 0);
}

/** The engine word of a verdict kind, in the case of the engine. */
export function verdictWord(kind: string): string {
  return kind.length ? kind[0]!.toUpperCase() + kind.slice(1) : kind;
}

/** The destination of a verdict, if any. */
export function destinationOf(v: Verdict): string | null {
  return v.destination?.endpoint ?? v.destination?.device ?? null;
}

/** The short label of a note of an answer: its text before the first colon. */
export function noteLabel(note: string): string {
  const at = note.indexOf(":");
  return at < 0 ? note : note.slice(0, at);
}

/** The notes of an answer: a path answer names the defaults that its unstated fields took. */
export function answerNotes(out: { kind: string; notes?: string[] | null }): string[] {
  return out.kind === "set_answer" ? [] : (out.notes ?? []);
}

/**
 * The query fields of a path query with `unstated` `defaults` that take a
 * default value when the query does not state them. The layer 2 priority
 * takes its default only with no VLAN tag.
 */
const DEFAULTED = ["dscp", "ecn", "network.vlan.id", "fragment", "tcp_flags", "icmp_type", "icmp_code", "source.port"];

/** The fields of the TPIDs and of the inner tag: not stated, they have a value in each setting of `unstated`. */
const TAG_FIELDS = ["network.vlan.tpid", "network.inner.vlan.id", "inner_l2_priority", "network.inner.vlan.tpid"];

/** The query fields that the query does not state and that have no default value. */
export function notStated(echo: Record<string, unknown>): string[] {
  const skip = new Set(["topology", "ingress", "reply", "unstated", "network.iana_number", "network.transport", ...TAG_FIELDS]);
  if (echo["unstated"] === "defaults") {
    for (const k of DEFAULTED) skip.add(k);
    if (echo["network.vlan.id"] == null) skip.add("l2_priority");
  }
  const stated = echo["network.transport"] != null || echo["network.iana_number"] != null;
  const out = Object.keys(echo).filter((k) => !skip.has(k) && echo[k] == null);
  if (!stated) out.push("network.transport");
  return out;
}

/** Whether the engine knows an outcome kind: `deliver`, `exit` and `drop` have a colour, each other kind the hatch. */
export function outcomeKnown(kind: string): boolean {
  return kind === "deliver" || kind === "exit" || kind === "drop";
}

/** The parts of a set answer by result: each part counts once. */
export function partCounts(parts: readonly { result: { kind: string; verdict?: Verdict | null; verdict_kind?: string | null } }[]): {
  deliver: number;
  exit: number;
  drop: number;
  unknown: number;
  dependsOnPath: number;
} {
  const out = { deliver: 0, exit: 0, drop: 0, unknown: 0, dependsOnPath: 0 };
  for (const p of parts) {
    if (p.result.kind === "depends_on_path") {
      out.dependsOnPath += 1;
      continue;
    }
    const k = p.result.verdict_kind ?? p.result.verdict?.kind;
    if (k === "deliver" || k === "exit" || k === "drop" || k === "unknown") out[k] += 1;
  }
  return out;
}

/**
 * Whether the names of the lanes stand upright: when a name is wider than
 * its lane at `charWidth` px for each character.
 */
export function upright(names: readonly string[], lane: number, charWidth: number): boolean {
  return names.some((n) => n.length * charWidth > lane);
}

/** The text of a QoS value. A range, a value that varies or an unknown value is not known. */
export function qosShown(v: Qos[keyof Qos]): Shown {
  if (typeof v === "string") return { known: v === "unset" || v === "none", text: v };
  if ("value" in v) return fieldText(v.value, null);
  return { known: true, text: String(v.known) };
}

/** The text of the DSCP or the ECN of a step: the one value of the packets, else not available. */
export function headerQosShown(v: Qos["dscp"]): Shown {
  if (typeof v !== "string" && "value" in v && typeof v.value !== "string" && "known" in v.value) {
    return { known: true, text: String(v.value.known) };
  }
  return { known: false, text: "not available" };
}

/** The delay of a step. A delay with no data for some functions or links is a lower bound and not known. */
export function delayShown(d: Branch["delay"]): Shown {
  if (!d.lower_bound) return { known: true, text: `${d.known_ns} ns` };
  return { known: false, text: `at least ${d.known_ns} ns` };
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
 * span of text first, else the most specific row span, then the others in
 * the order of the steps.
 */
export function detailSources(steps: readonly TraceStep[]): DetailSource[] {
  const out: DetailSource[] = [];
  for (const st of steps) {
    for (const p of st.provenance) {
      const key = `${p.file}:${p.first_line}-${p.last_line}`;
      if (!out.some((e) => e.key === key)) out.push({ key, label: spanLabel(p, st.device), span: p });
    }
  }
  const text = out.filter((e) => !isRowSpan(e.span));
  const best = mostSpecific((text.length > 0 ? text : out).map((e) => e.span));
  const i = out.findIndex((e) => e.span === best);
  if (i > 0) out.unshift(...out.splice(i, 1));
  return out;
}

/**
 * The span whose lines the step panel opens first: the smallest span of
 * text of the same file that holds the most specific span, else the most
 * specific span. Null with no span of text.
 */
export function openSpan(sources: readonly DetailSource[]): DetailSource | null {
  const best = sources[0];
  if (!best || isRowSpan(best.span)) return null;
  let out = best;
  for (const e of sources) {
    const s = e.span;
    if (e === best || isRowSpan(s) || s.file !== best.span.file) continue;
    if (s.first_line > best.span.first_line || s.last_line < best.span.last_line) continue;
    if (out === best || s.last_line - s.first_line < out.span.last_line - out.span.first_line) out = e;
  }
  return out;
}

/** The lines of `shown` that the mark of the most specific span `best` covers, or null. */
export function markedLines(shown: Span, best: Span | null): [number, number] | null {
  if (!best || best.file !== shown.file) return null;
  const a = Math.max(shown.first_line, best.first_line);
  const b = Math.min(shown.last_line, best.last_line);
  return a <= b ? [a, b] : null;
}

/** The step that decides the verdict of a path, with the reason of the verdict. */
export interface DecidingStep {
  path: PathRef;
  step: TraceStep;
  reason: string;
}

/**
 * The step that decides a path that does not deliver: the last step whose
 * outcome is not `forward`, else the last step, for a verdict that the
 * executor gives, such as a loop. The reason is the reason of the verdict,
 * else the reason of the step. A delivered path has no deciding step.
 */
export function decidingStep(b: Branch, path: PathRef = { replyOf: null, branch: b.index }): DecidingStep | null {
  if (b.verdict.kind === "deliver" || b.steps.length === 0) return null;
  let step = b.steps[b.steps.length - 1]!;
  for (let i = b.steps.length - 1; i >= 0; i--) {
    if (b.steps[i]!.outcome.kind !== "forward") {
      step = b.steps[i]!;
      break;
    }
  }
  return { path, step, reason: b.verdict.reason?.detail ?? step.reason.detail };
}

/** The key of the row of a ladder that holds a step of a path. */
export function rowKeyOfStep(rows: readonly StepRow[], path: PathRef, step: number): string | null {
  for (const r of rows) {
    if (!samePath(r.path, path)) continue;
    if (r.steps.some((s) => s.index === step)) return r.key;
  }
  return null;
}

/**
 * The step that a new answer selects and opens: for an answer whose one
 * verdict, or whose one verdict kind, is Unknown or Drop, the deciding step
 * of its first forward branch of that kind.
 */
export function autoStep(a: Answer): DecidingStep | null {
  const s = a.summary;
  const kind = s.length === 1 ? (s[0]!.result.verdict?.kind ?? s[0]!.result.verdict_kind ?? null) : null;
  if (kind !== "unknown" && kind !== "drop") return null;
  const b = a.branches.find((x) => x.verdict.kind === kind);
  return b ? decidingStep(b) : null;
}

/** The entry point of an answer as `<device>/<interface>`, if its runs found one and the same one. */
export function ingressHint(a: Pick<Answer, "ingress">): string | null {
  const found = [
    ...new Set(a.ingress.filter((i) => i.found && i.device && i.interface).map((i) => `${i.device}/${i.interface}`)),
  ];
  return found.length === 1 ? found[0]! : null;
}

/** Whether a run of an answer found no entry point, so that its packets are Unknown. */
export function noIngress(a: Pick<Answer, "ingress">): boolean {
  return a.ingress.some((i) => !i.found);
}
