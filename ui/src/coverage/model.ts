// The layout of the coverage report: its columns, the row of a device, the
// sums of a page and the URL state. No drawing code.
import { DEFAULT_LIMIT } from "../tables/model";

/** The report of one device. */
export interface CoverageRow {
  device: string;
  lines: number;
  handled: number;
  irrelevant: number;
  unhandled: number;
  paths: number;
  stanzas: number;
}

type Key = Exclude<keyof CoverageRow, "device"> | "device";

/** The columns of the view, with the key of the row that each prints. */
export const COVERAGE_COLUMNS: { name: string; key: Key; right: boolean; hatch: boolean; title: string }[] = [
  { name: "device", key: "device", right: false, hatch: false, title: "The device." },
  { name: "lines", key: "lines", right: true, hatch: false, title: "The config lines of the device that the classification counts." },
  { name: "handled", key: "handled", right: true, hatch: false, title: "The lines that a handler reads." },
  { name: "known-irrelevant", key: "irrelevant", right: true, hatch: false, title: "The lines that have no effect on the twin." },
  { name: "unhandled", key: "unhandled", right: true, hatch: true, title: "The lines that no handler reads; the functions that they can change give Unknown." },
  { name: "unhandled share", key: "unhandled", right: true, hatch: false, title: "The share of the lines that are unhandled." },
  { name: "unhandled paths", key: "paths", right: true, hatch: false, title: "The number of paths of unhandled stanzas." },
  { name: "unhandled stanzas", key: "stanzas", right: true, hatch: false, title: "The number of unhandled stanzas." },
];

const num = (v: unknown): number => (typeof v === "number" ? v : 0);

/** The row of a device from a row of the API, by the column names of the API. */
export function coverageRow(columns: readonly string[], r: readonly unknown[]): CoverageRow {
  const at = (n: string) => r[columns.indexOf(n)];
  const handled = num(at("handled"));
  const irrelevant = num(at("irrelevant"));
  const unhandled = num(at("unhandled"));
  return {
    device: String(at("device") ?? ""),
    lines: handled + irrelevant + unhandled,
    handled,
    irrelevant,
    unhandled,
    paths: num(at("unhandled_paths")),
    stanzas: num(at("unhandled_stanzas")),
  };
}

/** The share of the unhandled lines of a device in percent, with one decimal. */
export function shareText(r: CoverageRow): string {
  if (!r.lines) return "0.0%";
  return `${((100 * r.unhandled) / r.lines).toFixed(1)}%`;
}

/** The sums of a page, and the number of its devices with unhandled lines. */
export function coverageSums(rows: readonly CoverageRow[]): { handled: number; irrelevant: number; unhandled: number; devices: number } {
  const out = { handled: 0, irrelevant: 0, unhandled: 0, devices: 0 };
  for (const r of rows) {
    out.handled += r.handled;
    out.irrelevant += r.irrelevant;
    out.unhandled += r.unhandled;
    if (r.unhandled) out.devices += 1;
  }
  return out;
}

export interface CoverageState {
  cursor: string | null;
  limit: number;
  /** The device of the opened row. */
  device: string | null;
}

export function readCoverage(search: string): CoverageState {
  const u = new URLSearchParams(search);
  const limit = Number(u.get("limit"));
  return {
    cursor: u.get("at"),
    limit: Number.isInteger(limit) && limit > 0 ? limit : DEFAULT_LIMIT,
    device: u.get("device"),
  };
}

export function writeCoverage(s: CoverageState, base: Record<string, string> = {}): string {
  const u = new URLSearchParams(base);
  if (s.limit !== DEFAULT_LIMIT) u.set("limit", String(s.limit));
  if (s.cursor) u.set("at", s.cursor);
  if (s.device) u.set("device", s.device);
  const q = u.toString();
  return q ? `?${q}` : "";
}
