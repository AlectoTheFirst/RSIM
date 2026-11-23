// The frame of the page as data: the views of the rail, the time and the
// state of the run of the top bar, and the age of the last cycle.
import type { TwinRef } from "../api/client";
import { isSnapshot, newerRun } from "./url";

export const VIEWS = ["Trace", "Topology", "Tables", "Coverage", "Inventory", "Tokens"] as const;
export type View = (typeof VIEWS)[number];

/** The views at the top of the rail, in order. */
export const RAIL_TOP: readonly View[] = ["Trace", "Topology", "Tables", "Coverage"];

/** The views at the bottom of the rail. The view Tokens opens from the account menu. */
export const RAIL_BOTTOM: readonly View[] = ["Inventory"];

/** The time of a snapshot name `snapshot-YYYY-MM-DD-HHMMSS` in ms since the epoch, or null. */
export function snapshotTime(name: string | null | undefined): number | null {
  if (!isSnapshot(name)) return null;
  const m = /^snapshot-(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})$/.exec(name)!;
  const t = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  return Number.isNaN(t) ? null : t;
}

/** A time as `YYYY-MM-DD HH:MM:SS UTC`. */
export function utcText(ms: number): string {
  return `${new Date(ms).toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

/**
 * The time of the run of a twin: the snapshot time of the twin, else the
 * time of its snapshot name, else null.
 */
export function runTime(twin: string, snapshot: unknown): number | null {
  if (typeof snapshot === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(snapshot)) {
    const t = Date.parse(snapshot);
    if (!Number.isNaN(t)) return t;
  }
  return snapshotTime(twin);
}

/**
 * The state of the run of the page: `newest` for the newest built run of
 * the store, `older` for an older run, else null.
 */
export function runState(twins: readonly TwinRef[], twin: string): "newest" | "older" | null {
  if (newerRun(twins, twin)) return "older";
  const held = twins.find((t) => t.id === "store")?.held ?? null;
  if (held !== null && (twin === held || twin === "store")) return "newest";
  return null;
}

/** True for the alias `store` and for a run of the store. */
export function ofStore(twins: readonly TwinRef[], twin: string): boolean {
  if (twin === "store" || isSnapshot(twin)) return true;
  const s = twins.find((t) => t.id === "store");
  return !!s && (s.held === twin || s.previous === twin || s.newest === twin);
}

/** An option of the snapshot selector. */
export interface RunOption {
  id: string;
  /** The time of the snapshot in ms since the epoch, or null for a twin that is not a snapshot. */
  time: number | null;
  state: "newest" | "older" | null;
}

/**
 * The options of the snapshot selector and the chosen option: the held
 * snapshot and the previous snapshot of the store, then each twin that is
 * not the store. The alias `store` is an option only before its first build.
 */
export function runOptions(twins: readonly TwinRef[], twin: string): { options: RunOption[]; chosen: string } {
  const options: RunOption[] = [];
  const s = twins.find((t) => t.id === "store");
  if (s) {
    if (s.held) options.push({ id: s.held, time: snapshotTime(s.held), state: "newest" });
    else options.push({ id: "store", time: null, state: null });
    if (s.previous && s.previous !== s.held) options.push({ id: s.previous, time: snapshotTime(s.previous), state: "older" });
  }
  for (const t of twins) if (t.id !== "store") options.push({ id: t.id, time: snapshotTime(t.id), state: null });
  const chosen = twin === "store" && s?.held ? s.held : twin;
  return { options, chosen };
}

/** The time of the last cycle of the store: the time of its newest snapshot, or null. */
export function lastCycle(twins: readonly TwinRef[]): number | null {
  return snapshotTime(twins.find((t) => t.id === "store")?.newest ?? null);
}

/** An age in whole seconds, minutes, hours or days. */
export function ageText(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s} s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} d ago`;
}

/** The focus index of a menu after a key, or null for a key that the menu does not take. */
export function menuMove(key: string, at: number, count: number): number | null {
  if (count <= 0) return null;
  switch (key) {
    case "ArrowDown":
      return at < 0 ? 0 : (at + 1) % count;
    case "ArrowUp":
      return at < 0 ? count - 1 : (at - 1 + count) % count;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return null;
  }
}
