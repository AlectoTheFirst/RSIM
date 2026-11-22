// The paths of an answer: one item for each forward branch and each branch
// of a reply, the outcomes that occur with their counts, and the path strip
// of one path. No drawing code.
import type { Answer, Branch, Verdict } from "../api/types";
import {
  type DecidingStep,
  type Dir,
  type End,
  type PathRef,
  branchOf,
  decidingStep,
  devicesOf,
  endOf,
  endpointOf,
  keyShown,
  samePath,
  sourceEndpoints,
} from "./layout";
import { tunnelOf } from "./setLayout";

/** One path of an answer. */
export interface PathItem {
  ref: PathRef;
  dir: Dir;
  /** The number of the path: from 1, and `<forward path>.<reply path>` for a path of a reply. */
  number: string;
  /** The devices in path order, each run of one device once. */
  devices: string[];
  verdict: Verdict;
  /** The step that decides a path that does not deliver. */
  at: DecidingStep | null;
  /** The tunnel of an outer packet that exits or is delivered. */
  tunnel: string | null;
}

function item(b: Branch, ref: PathRef, number: string): PathItem {
  const ends = b.verdict.kind === "exit" || b.verdict.kind === "deliver";
  return {
    ref,
    dir: ref.replyOf === null ? "forward" : "reply",
    number,
    devices: devicesOf(b).filter((d): d is string => d !== null),
    verdict: b.verdict,
    at: decidingStep(b, ref),
    tunnel: ends ? tunnelOf(b) : null,
  };
}

/** The forward paths of an answer, in the order of the answer. */
export function forwardPaths(a: Answer): PathItem[] {
  return a.branches.map((b) => item(b, { replyOf: null, branch: b.index }, String(b.index + 1)));
}

/** The paths of the reply of one forward path, or of each forward path with `fwd` null, in the order of the answer. */
export function replyPaths(a: Answer, fwd: number | null = null): PathItem[] {
  const out: PathItem[] = [];
  for (const r of a.replies) {
    if (fwd !== null && r.forward_branch !== fwd) continue;
    for (const b of r.answer?.branches ?? []) {
      out.push(item(b, { replyOf: r.forward_branch, branch: b.index }, `${r.forward_branch + 1}.${b.index + 1}`));
    }
  }
  return out;
}

/** The reply of a forward path: its paths, the reason why it did not run, no reply, or nothing to show. */
export type ReplyState =
  | { kind: "paths"; paths: PathItem[] }
  | { kind: "not_run"; reason: string }
  | { kind: "no_reply" }
  | { kind: "none" };

/**
 * The reply of forward path `fwd` of an answer whose query asks for the
 * reply when `asks`: its paths, or the reason why it did not run, or no
 * reply for a path that does not deliver.
 */
export function replyState(a: Answer, fwd: number, asks: boolean): ReplyState {
  if (!asks) return { kind: "none" };
  const r = a.replies.find((x) => x.forward_branch === fwd);
  if (r && !r.ran) return { kind: "not_run", reason: r.not_run_reason ?? "not run" };
  const paths = replyPaths(a, fwd);
  if (paths.length) return { kind: "paths", paths };
  const b = a.branches.find((x) => x.index === fwd);
  return b && b.verdict.kind !== "deliver" ? { kind: "no_reply" } : { kind: "none" };
}

const KIND_ORDER = ["deliver", "exit", "drop", "unknown"];

/**
 * The outcome kinds that occur in a list of paths, each with the number of
 * its paths, in the order deliver, exit, drop, unknown, then each other
 * kind in name order.
 */
export function tally(kinds: readonly string[]): [string, number][] {
  const n = new Map<string, number>();
  for (const k of kinds) n.set(k, (n.get(k) ?? 0) + 1);
  const rank = (k: string) => {
    const i = KIND_ORDER.indexOf(k);
    return i < 0 ? KIND_ORDER.length : i;
  };
  return [...n].sort((x, y) => rank(x[0]) - rank(y[0]) || (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
}

/** The paths with an outcome kind, or each path with no kind. */
export function withKind<T extends { verdict: { kind: string } }>(list: readonly T[], kind: string | null): T[] {
  return kind === null ? [...list] : list.filter((p) => p.verdict.kind === kind);
}

/** The index of a path in a list, or -1. */
export function pathIndex(list: readonly PathItem[], ref: PathRef): number {
  return list.findIndex((p) => samePath(p.ref, ref));
}

/**
 * The selected path of a list: `ref` when the list holds it, else the
 * first path of the list, else null.
 */
export function selectedPath(list: readonly PathItem[], ref: PathRef | null): PathRef | null {
  if (ref && pathIndex(list, ref) >= 0) return ref;
  return list[0]?.ref ?? null;
}

/** One place of the path strip: an endpoint with its address, or a device. */
export type StripNode = { kind: "endpoint"; name: string; address: string | null; end: boolean } | { kind: "device"; name: string; site: string | null };

/**
 * The site of a device of the twin: the site of the inventory device of
 * the same name, else of the store device of the twin device, else null.
 */
export function deviceSite(device: string, sites: ReadonlyMap<string, string>, storeDevices: ReadonlyMap<string, string>): string | null {
  const own = sites.get(device);
  if (own !== undefined) return own;
  const store = storeDevices.get(device);
  return store === undefined ? null : (sites.get(store) ?? null);
}

/** The path strip of a path: its places in path order and the outcome of its end. */
export interface Strip {
  nodes: StripNode[];
  end: End;
  /** Whether the path ends at an endpoint of the strip. */
  atEndpoint: boolean;
}

/** An endpoint node from its name and its address, or null when neither is known. */
function endpointNode(name: string | null, address: string | null, end: boolean): StripNode | null {
  if (name) return { kind: "endpoint", name, address: address && address !== name ? address : null, end };
  if (address) return { kind: "endpoint", name: address, address: null, end };
  return null;
}

/**
 * The path strip of a path: the source endpoint, each device of the path
 * in path order, and the endpoint that the path delivers to. The source of
 * a forward path is the endpoint to which its reply delivers, and the
 * source of a reply is the endpoint to which its forward path delivers;
 * the address of an endpoint is the address of the packets where they
 * enter and where they end, when the twin knows it. `siteOf` gives the
 * site of a device.
 */
export function stripOf(a: Answer, ref: PathRef, siteOf: (device: string) => string | null = () => null): Strip | null {
  const b = branchOf(a, ref);
  if (!b) return null;
  let start: string | null;
  if (ref.replyOf === null) start = sourceEndpoints(a).get(ref.branch) ?? null;
  else {
    const fwd = a.branches.find((x) => x.index === ref.replyOf);
    start = fwd ? endpointOf(fwd.verdict) : null;
  }
  const known = (s: { known: boolean; text: string } | null) => (s && s.known ? s.text : null);
  const nodes: StripNode[] = [];
  const entry = b.steps[0];
  const first = endpointNode(start, entry ? known(keyShown(entry.input, "source.ip")) : null, false);
  if (first) nodes.push(first);
  for (const d of devicesOf(b)) if (d !== null) nodes.push({ kind: "device", name: d, site: siteOf(d) });
  const endName = endpointOf(b.verdict);
  const last = b.steps[b.steps.length - 1];
  const destination = last ? known(keyShown(last.output.members.length ? last.output : last.input, "destination.ip")) : null;
  const tail = endName ? endpointNode(endName, destination, true) : null;
  if (tail) nodes.push(tail);
  return { nodes, end: endOf(b.verdict), atEndpoint: tail !== null };
}
