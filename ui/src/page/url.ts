// The view and the twin in the URL of the page. A URL with no view is the
// Trace view.
import type { TwinRef } from "../api/client";
import type { View } from "./frame";

const PARAM: Partial<Record<View, string>> = { Topology: "topology", Tables: "tables", Coverage: "coverage", Inventory: "inventory", Tokens: "tokens" };

export function viewOf(search: string): View {
  const v = new URLSearchParams(search).get("view");
  if (v === "topology") return "Topology";
  if (v === "tables") return "Tables";
  if (v === "coverage") return "Coverage";
  if (v === "inventory") return "Inventory";
  if (v === "tokens") return "Tokens";
  return "Trace";
}

/** The query id of a URL, or null. */
export function queryOf(search: string): string | null {
  return new URLSearchParams(search).get("q");
}

/** The URL of the Topology view with the paths of the query `qid`. */
export function topologySearch(twin: string, qid: string): string {
  return `?${new URLSearchParams({ view: "topology", twin, q: qid }).toString()}`;
}

/** The URL of the Tables view on the table `functions` of a device. */
export function functionsSearch(twin: string, device: string): string {
  const u = new URLSearchParams({ view: "tables", twin, table: "functions", "f.device": device });
  return `?${u.toString()}`;
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

/**
 * Whether a twin can answer: `none` while the server has no twin, `empty`
 * for the alias `store` of a store with no snapshot, else `ready`.
 */
export function twinState(twins: readonly TwinRef[] | null, twin: string): "loading" | "none" | "empty" | "ready" {
  if (twins === null) return "loading";
  if (twins.length === 0) return "none";
  if (twin !== "store") return "ready";
  const store = twins.find((t) => t.id === "store");
  return store && store.held == null && store.newest == null ? "empty" : "ready";
}

/** The label of a twin that cannot answer, with its cause as the title, or null. */
export function twinStateText(state: ReturnType<typeof twinState>): { text: string; title: string } | null {
  if (state === "none") return { text: "no store", title: "rsim-api has no --store" };
  if (state === "empty") return { text: "no snapshot", title: "empty store" };
  return null;
}

/** True for a snapshot name `snapshot-YYYY-MM-DD-HHMMSS`, which sorts by its UTC second. */
export function isSnapshot(id: string | null | undefined): id is string {
  return id != null && /^snapshot-\d{4}-\d{2}-\d{2}-\d{6}$/.test(id);
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
  return isSnapshot(twin) && isSnapshot(held) && held > twin ? held : null;
}
