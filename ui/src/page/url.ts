// The view and the twin in the URL of the page. A URL with no view is the
// Trace view, so a link of a query stays as it is.
import type { TwinRef } from "../api/client";
import type { View } from "./Parts";

const PARAM: Partial<Record<View, string>> = { Tables: "tables", Coverage: "coverage", Inventory: "inventory", Tokens: "tokens" };

export function viewOf(search: string): View {
  const v = new URLSearchParams(search).get("view");
  if (v === "tables") return "Tables";
  if (v === "coverage") return "Coverage";
  if (v === "inventory") return "Inventory";
  if (v === "tokens") return "Tokens";
  return "Trace";
}

export function twinOf(search: string): string | null {
  return new URLSearchParams(search).get("twin");
}

/**
 * The URL of a view of a twin, with the table of the Tables view kept, and
 * for the Trace view the query `qid` of the shown answer.
 */
export function viewSearch(view: View, twin: string, from = "", qid: string | null = null): string {
  const u = new URLSearchParams();
  const p = PARAM[view];
  if (p) u.set("view", p);
  if (twin) u.set("twin", twin);
  if (view === "Trace" && twin && qid) u.set("q", qid);
  const table = new URLSearchParams(from).get("table");
  if (view === "Tables" && table && viewOf(from) === "Tables") u.set("table", table);
  const q = u.toString();
  return q ? `?${q}` : "";
}

/**
 * The URL after a change of the twin: the same view and table with the
 * filters, and no query, page or opened device, which belong to one twin.
 */
export function withTwin(search: string, twin: string): string {
  const u = new URLSearchParams(search);
  u.set("twin", twin);
  for (const k of ["q", "at", "device"]) u.delete(k);
  return `?${u.toString()}`;
}

/**
 * The mark of the twin selector for a store whose newest snapshot does not
 * build or whose HEAD cannot be read: its text and its title, or null.
 */
export function reloadMark(twins: readonly TwinRef[]): { text: string; title: string } | null {
  const store = twins.find((t) => t.id === "store");
  const e = store?.reload_error;
  if (!e) return null;
  const held = store?.held ? `, ${store.held} answers` : "";
  const what = e.snapshot ? `${e.snapshot} does not build` : "store HEAD not read";
  return { text: `${what}${held}`, title: e.detail };
}

/** The cycle of a snapshot identifier `snap-<cycle>`, or null. */
function cycleOf(id: string | null | undefined): number | null {
  const m = id ? /^snap-(\d+)$/.exec(id) : null;
  return m ? Number(m[1]) : null;
}

/**
 * The run that a page pins for a twin: the newest built snapshot for the
 * alias `store`, else the twin itself.
 */
export function pinnedRun(twins: readonly TwinRef[], twin: string): string {
  if (twin !== "store") return twin;
  return twins.find((t) => t.id === "store")?.held ?? twin;
}

/** The newest built snapshot when the page shows an older run of the store, or null. */
export function newerRun(twins: readonly TwinRef[], twin: string): string | null {
  const held = twins.find((t) => t.id === "store")?.held ?? null;
  const page = cycleOf(twin);
  const newest = cycleOf(held);
  return page !== null && newest !== null && newest > page ? held : null;
}

/**
 * The option of the twin selector for a twin: the twin itself, or `store`
 * for a snapshot `snap-<cycle>` when the list names the store `store`.
 */
export function twinOption(ids: readonly string[], twin: string): string {
  if (ids.includes(twin)) return twin;
  if (/^snap-\d+$/.test(twin) && ids.includes("store")) return "store";
  return twin;
}
