// The layout of the answer of a set query: one row for each part, with the
// fields in which the part differs from the query, its outcome and the
// tunnel of an outer packet. No drawing code.
import type { Answer, Branch, FieldValue, Header, PacketSet, TraceStep } from "../api/types";
import { type DecidingStep, decidingStep, destinationOf, fieldText, functionLabel } from "./layout";

/** The header fields of a packet that are no field values. */
const NOT_FIELDS = new Set(["encap", "inner"]);

/** The name of a header field in the UI: the protocol number shows as the transport. */
function fieldName(k: string): string {
  return k === "network.iana_number" ? "network.transport" : k;
}

/**
 * The value of each header field over the members of a set, in the order
 * of the header: the values of the members, each once, joined by " or ".
 */
export function headerValues(ps: PacketSet): Map<string, string> {
  const texts = new Map<string, string[]>();
  for (const m of ps.members) {
    const h = m.original as unknown as Record<string, FieldValue>;
    for (const k of Object.keys(h)) {
      if (NOT_FIELDS.has(k)) continue;
      const name = fieldName(k);
      const t = fieldText(h[k]!, name === "network.transport" ? "network.transport" : null).text;
      const list = texts.get(name) ?? [];
      if (!list.includes(t)) list.push(t);
      texts.set(name, list);
    }
  }
  return new Map([...texts].map(([k, v]) => [k, v.join(" or ")]));
}

/** The fields in which the packets of a part differ from the packets of the query, with the values of the part. */
export function partFields(query: PacketSet, part: PacketSet): [string, string][] {
  const q = headerValues(query);
  return [...headerValues(part)].filter(([k, v]) => q.get(k) !== v);
}

/** The names of the encapsulation kinds. */
const ENCAP_NAMES: Record<string, string> = { wireguard: "WireGuard", vxlan: "VXLAN", gre: "GRE", mpls: "MPLS" };

function encapOf(h: Header): Header["encap"] {
  return h.encap ?? [];
}

function encapsulated(ps: PacketSet): boolean {
  return ps.members.some((m) => encapOf(m.current).length > 0);
}

/**
 * The tunnel of the outer packet at the end of a branch: the encapsulation
 * kind and the name of the function that encapsulates, or the VNI of a
 * VXLAN header. Null for a branch that ends with no encapsulation.
 */
export function tunnelOf(b: Branch): string | null {
  const last = b.steps[b.steps.length - 1];
  if (!last || !encapsulated(last.output.members.length ? last.output : last.input)) return null;
  const at = b.steps.find((s: TraceStep) => encapsulated(s.output) && !encapsulated(s.input));
  if (!at) return null;
  const e = at.output.members.map((m) => encapOf(m.current)[0]).find((x) => x !== undefined)!;
  const kind = ENCAP_NAMES[e.kind] ?? e.kind;
  if (e.vni && typeof e.vni !== "string" && "known" in e.vni) return `${kind} ${e.vni.known}`;
  const fn = functionLabel(at);
  return `${kind} ${fn.slice(fn.lastIndexOf("/") + 1)}`;
}

/** One part of a set answer. */
export interface PartRow {
  /** The index of the branch of the part. */
  branch: number;
  /** The fields in which the part differs from the query, with the values of the part. */
  fields: [string, string][];
  kind: string;
  /** The exit or the destination, or null. */
  place: string | null;
  /** The step that decides a part that does not deliver. */
  at: DecidingStep | null;
  /** The reason of a Drop or an Unknown. */
  reason: string | null;
  /** The tunnel of an outer packet that exits or is delivered. */
  tunnel: string | null;
}

/** The outcome of a branch: its place, its deciding step, its reason and its tunnel. */
export function outcomeOf(b: Branch): Omit<PartRow, "branch" | "fields"> {
  const v = b.verdict;
  const ends = v.kind === "exit" || v.kind === "deliver";
  return {
    kind: v.kind,
    place: v.kind === "exit" ? (v.reason?.detail ?? null) : v.kind === "deliver" ? destinationOf(v) : null,
    at: decidingStep(b),
    reason: ends ? null : (v.reason?.detail ?? null),
    tunnel: ends ? tunnelOf(b) : null,
  };
}

/** The parts of a set answer, one for each branch, in branch order. */
export function partList(a: Answer): PartRow[] {
  return a.branches.map((b) => ({ branch: b.index, fields: partFields(a.input, b.packets), ...outcomeOf(b) }));
}

/** The answer of one part: its branch with its replies, for the ladder of the part. */
export function partAnswer(a: Answer, branch: number): Answer {
  return {
    ...a,
    branches: a.branches.filter((b) => b.index === branch),
    replies: a.replies.filter((r) => r.forward_branch === branch),
  };
}
