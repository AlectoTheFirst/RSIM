// The state of the Tables view and the layout of a table: the URL state,
// the parameters of the API, the filters of a column, the pages, the
// hairline cells, the virtual rows and the column widths. No drawing code.
import type { Column, TableDef } from "../api/types";
import { shellWord } from "../page/query";

/** The verbs of the Tables view: the verbs of the API and `describe`. */
export const VERBS = ["show", "summarize", "unique", "top", "lpm", "describe"] as const;
export type Verb = (typeof VERBS)[number];

/** The ops of a typed filter of the API, and `=` for an equality filter. */
export const OPS = ["=", "contains", "prefix", "gt", "lt", "in_prefix"] as const;
export type Op = (typeof OPS)[number];

export interface Filter {
  column: string;
  op: Op;
  value: string;
}

/** The number of rows of a page when the URL does not give one. */
export const DEFAULT_LIMIT = 200;
export const LIMITS: readonly number[] = [100, 200, 500, 1000];

/** The page sizes of the page size control: `LIMITS` and the current size, in order. */
export function limitOptions(limit: number): number[] {
  return LIMITS.includes(limit) ? [...LIMITS] : [...LIMITS, limit].sort((a, b) => a - b);
}

/**
 * The place of the focus for a key of a view: `text` in a field that takes
 * the keys, `control` on a button or a link, which takes Enter and Space,
 * and `page` elsewhere.
 */
export type KeyPlace = "text" | "control" | "page";

export function keyPlace(t: { tagName?: string; isContentEditable?: boolean } | null): KeyPlace {
  if (!t) return "page";
  if (t.isContentEditable) return "text";
  switch (t.tagName) {
    case "INPUT":
    case "SELECT":
    case "TEXTAREA":
      return "text";
    case "BUTTON":
    case "A":
    case "SUMMARY":
      return "control";
    default:
      return "page";
  }
}

/** True when the view leaves a key to the focused element. */
export function keyForElement(place: KeyPlace, key: string): boolean {
  return place === "text" || (place === "control" && (key === "Enter" || key === " "));
}

/** The value of an answer when it is the answer of the request `key`, else null. */
export function answerOf<T>(answer: { key: string; value: T } | null, key: string): T | null {
  return answer && answer.key === key ? answer.value : null;
}

export interface TablesState {
  table: string;
  verb: Verb;
  filters: Filter[];
  sort: string[];
  limit: number;
  /** The cursor of the page, as the API gave it; null for the first page. */
  cursor: string | null;
  /** The columns of `unique`, or the one column of `top`. */
  by: string[];
  /** The number of rows of `top`. */
  count: number;
  ascending: boolean;
  /** The address of `lpm`. */
  address: string;
}

export const EMPTY: TablesState = {
  table: "",
  verb: "show",
  filters: [],
  sort: [],
  limit: DEFAULT_LIMIT,
  cursor: null,
  by: [],
  count: 5,
  ascending: false,
  address: "",
};

const list = (v: string | null): string[] => (v ? v.split(",").filter((x) => x !== "") : []);

/** The prefix of a filter parameter in the URL of the page. */
const FILTER = "f.";

/**
 * The state of the URL of the page. A filter is `f.<column>=v1,v2` or
 * `f.<column>.<op>=v`, so a column name never meets a parameter of the page.
 * A later filter with the same column and op takes the place of an earlier
 * one, as in the API.
 */
export function readState(search: string): TablesState {
  const u = new URLSearchParams(search);
  const filters: Filter[] = [];
  for (const [k, v] of u) {
    if (!k.startsWith(FILTER)) continue;
    const rest = k.slice(FILTER.length);
    const dot = rest.lastIndexOf(".");
    const op = dot > 0 ? rest.slice(dot + 1) : "";
    const f: Filter =
      dot > 0 && (OPS as readonly string[]).includes(op) && op !== "="
        ? { column: rest.slice(0, dot), op: op as Op, value: v }
        : { column: rest, op: "=", value: v };
    const at = filters.findIndex((x) => x.column === f.column && x.op === f.op);
    if (at >= 0) filters.splice(at, 1);
    filters.push(f);
  }
  const verb = u.get("verb");
  const limit = Number(u.get("limit"));
  const count = Number(u.get("count"));
  return {
    table: u.get("table") ?? "",
    verb: (VERBS as readonly string[]).includes(verb ?? "") ? (verb as Verb) : "show",
    filters,
    sort: list(u.get("sort")),
    limit: Number.isInteger(limit) && limit > 0 ? limit : DEFAULT_LIMIT,
    cursor: u.get("at"),
    by: list(u.get("by")),
    count: Number.isInteger(count) && count > 0 ? count : 5,
    ascending: u.get("ascending") === "true",
    address: u.get("address") ?? "",
  };
}

/** The URL parameters of a state, with each default left out. */
export function writeState(s: TablesState, base: Record<string, string> = {}): string {
  const u = new URLSearchParams(base);
  if (s.table) u.set("table", s.table);
  if (s.verb !== "show") u.set("verb", s.verb);
  for (const f of s.filters) u.append(f.op === "=" ? `${FILTER}${f.column}` : `${FILTER}${f.column}.${f.op}`, f.value);
  if (s.sort.length) u.set("sort", s.sort.join(","));
  if (s.limit !== DEFAULT_LIMIT) u.set("limit", String(s.limit));
  if (s.cursor) u.set("at", s.cursor);
  if (s.by.length) u.set("by", s.by.join(","));
  if (s.count !== 5) u.set("count", String(s.count));
  if (s.ascending) u.set("ascending", "true");
  if (s.address) u.set("address", s.address);
  const q = u.toString();
  return q ? `?${q}` : "";
}

/** The API name of a filter: `<column>` or `<column>.<op>`. */
export const filterKey = (f: Filter): string => (f.op === "=" ? f.column : `${f.column}.${f.op}`);

/** The API path of a verb. */
export function verbPath(v: Verb): string | null {
  switch (v) {
    case "show":
      return "rows";
    case "summarize":
      return "summary";
    case "describe":
      return null;
    default:
      return v;
  }
}

/** The parameters of the API request of a state, in a fixed order. */
export function apiParams(s: TablesState, def: TableDef | null): [string, string][] {
  const out: [string, string][] = s.filters.map((f) => [filterKey(f), f.value]);
  switch (s.verb) {
    case "show":
      if (s.sort.length) out.push(["sort", s.sort.join(",")]);
      out.push(["limit", String(s.limit)]);
      if (s.cursor) out.push(["cursor", s.cursor]);
      break;
    case "unique":
      out.push(["columns", (s.by.length ? s.by : defaultBy(def, "unique")).join(",")]);
      break;
    case "top":
      out.push(["column", (s.by.length ? s.by : defaultBy(def, "top"))[0] ?? ""]);
      out.push(["count", String(s.count)]);
      if (s.ascending) out.push(["ascending", "true"]);
      break;
    case "lpm": {
      out.push(["address", s.address]);
      const c = prefixColumn(def);
      if (c) out.push(["column", c]);
      break;
    }
    default:
      break;
  }
  return out;
}

/** The first prefix column of a table, the column of `lpm`. */
export function prefixColumn(def: TableDef | null): string | null {
  return def?.columns.find((c) => c.type === "prefix")?.name ?? null;
}

/** The columns of `unique` or `top` when the state names none. */
export function defaultBy(def: TableDef | null, verb: "unique" | "top"): string[] {
  if (!def) return [];
  if (verb === "top") {
    const c = def.columns.find((x) => x.type === "integer") ?? def.columns[0];
    return c ? [c.name] : [];
  }
  return def.key[0] ? [def.key[0]] : [];
}

/** The URL of the API request of a state. */
export function apiUrl(twin: string, s: TablesState, def: TableDef | null): string | null {
  const p = verbPath(s.verb);
  if (!p || !s.table) return null;
  const q = new URLSearchParams(apiParams(s, def)).toString();
  return `/v1/twins/${encodeURIComponent(twin)}/tables/${encodeURIComponent(s.table)}/${p}${q ? `?${q}` : ""}`;
}

/** The request of a state as an rsim command. */
export function tableCommand(topology: string, s: TablesState, def: TableDef | null): string {
  const args = ["rsim", topology, s.table, s.verb];
  if (s.verb === "describe") return args.join(" ");
  if (s.verb === "lpm") args.push(shellWord(s.address));
  for (const [k, v] of apiParams(s, def)) {
    if (s.verb === "lpm" && k === "address") continue;
    if (k === "ascending") args.push("--ascending");
    else args.push(`--${k}`, shellWord(v));
  }
  return args.join(" ");
}

/**
 * The filters of one column from the text of its filter cell: parts
 * separated by `;`, each `<values>` for equality or `<op> <value>`. A later
 * part with the same op takes the place of an earlier one, as in the API.
 */
export function parseFilterCell(column: string, text: string): Filter[] {
  const out: Filter[] = [];
  for (const raw of text.split(";")) {
    const part = raw.trim();
    if (!part) continue;
    const m = /^(=|contains|prefix|gt|lt|in_prefix)(?:\s+|$)(.*)$/.exec(part);
    const f: Filter = m ? { column, op: m[1] as Op, value: m[2]!.trim() } : { column, op: "=", value: part };
    if (!f.value) continue;
    const at = out.findIndex((x) => x.op === f.op);
    if (at >= 0) out.splice(at, 1);
    out.push(f);
  }
  return out;
}

/** The text of the filter cell of one column. */
export function filterCellText(column: string, filters: readonly Filter[]): string {
  return filters
    .filter((f) => f.column === column)
    .map((f) => (f.op === "=" ? f.value : `${f.op} ${f.value}`))
    .join("; ");
}

/** The filters with those of one column replaced. */
export function setColumnFilters(filters: readonly Filter[], column: string, text: string): Filter[] {
  return [...filters.filter((f) => f.column !== column), ...parseFilterCell(column, text)];
}

/** The ops that a column type offers, for the hint of its filter cell. */
export function opsOf(c: Column): Op[] {
  switch (c.type) {
    case "integer":
      return ["=", "gt", "lt"];
    case "boolean":
      return ["="];
    case "address":
    case "prefix":
      return ["=", "in_prefix", "prefix", "contains"];
    default:
      return ["=", "contains", "prefix"];
  }
}

/** The order after a click on the head of a column: up, down, then none. */
export function nextSort(sort: readonly string[], column: string, add: boolean): string[] {
  const at = sort.findIndex((s) => s === column || s === `-${column}`);
  const cur = at < 0 ? null : sort[at]!.startsWith("-") ? "down" : "up";
  const next = cur === null ? column : cur === "up" ? `-${column}` : null;
  if (!add) return next ? [next] : [];
  const out = [...sort];
  if (at >= 0) {
    if (next) out[at] = next;
    else out.splice(at, 1);
  } else if (next) out.push(next);
  return out;
}

/** The direction and the place of a column in the order. */
export function sortOf(sort: readonly string[], column: string): { dir: "up" | "down"; n: number } | null {
  const at = sort.findIndex((s) => s === column || s === `-${column}`);
  if (at < 0) return null;
  return { dir: sort[at]!.startsWith("-") ? "down" : "up", n: at + 1 };
}

/**
 * The pages that the view has passed: the cursor of each page before the
 * current one. The cursor is opaque. A page that a deep link opens has no
 * known pages before it, so its first row is not known.
 */
export interface Pages {
  cursor: string | null;
  back: (string | null)[];
  /** The index of the first row of the page, or null after a deep link. */
  offset: number | null;
}

export const FIRST_PAGE: Pages = { cursor: null, back: [], offset: 0 };

export function openPage(cursor: string | null): Pages {
  return cursor === null ? FIRST_PAGE : { cursor, back: [], offset: null };
}

export function nextPage(p: Pages, next: string, rows: number): Pages {
  return { cursor: next, back: [...p.back, p.cursor], offset: p.offset === null ? null : p.offset + rows };
}

export function previousPage(p: Pages, limit: number): Pages {
  if (!p.back.length) return p;
  const back = p.back.slice(0, -1);
  const cursor = p.back[p.back.length - 1]!;
  const offset = cursor === null ? 0 : p.offset === null ? null : Math.max(0, p.offset - limit);
  return { cursor, back, offset };
}

/**
 * The pages for the cursor of the URL: the same pages, the page before
 * after a step back in the history, or a page that a deep link opens.
 */
export function syncPages(p: Pages | null, cursor: string | null, limit: number): Pages {
  if (p && p.cursor === cursor) return p;
  if (p && p.back.length && p.back[p.back.length - 1] === cursor) return previousPage(p, limit);
  return openPage(cursor);
}

/** The words of the place of a page: "rows 201 to 400 of 1000". */
export function pageWords(p: Pages, rows: number, total: number): string {
  if (rows === 0) return `no rows of ${total}`;
  if (p.offset === null) return `${rows} rows of ${total}, after the cursor ${p.cursor}`;
  return `rows ${p.offset + 1} to ${p.offset + rows} of ${total}`;
}

const same = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

/**
 * The number of leading cells of each row that repeat the row above: the
 * cells from the left while each value equals the value above. These cells
 * have a hairline. The first row of a page, and a row after an opened row,
 * print each value.
 */
export function repeats(rows: readonly (readonly unknown[])[], opened: number | null = null): number[] {
  return rows.map((r, i) => {
    if (i === 0 || opened === i - 1) return 0;
    const above = rows[i - 1]!;
    let n = 0;
    while (n < r.length - 1 && same(r[n], above[n])) n += 1;
    return n;
  });
}

/** A cell as the view prints it. */
export interface CellText {
  /** False for a value that the twin does not know: the cell has the hatch. */
  known: boolean;
  text: string;
  /** Why the value is not known. */
  why?: string;
}

/**
 * The text of a cell. A null or an empty list is not known when the
 * `<name>_reason` column of the same row gives a reason; a null is not
 * known in a boolean column. Elsewhere a null is no value.
 */
export function cellText(v: unknown, col: Column | undefined, reason?: unknown): CellText {
  const empty = v === null || v === undefined || (Array.isArray(v) && v.length === 0);
  if (empty && typeof reason === "string" && reason) return { known: false, text: "", why: reason };
  if (v === null || v === undefined) {
    if (col?.type === "boolean") return { known: false, text: "", why: "not known" };
    return { known: true, text: "" };
  }
  if (Array.isArray(v)) return { known: true, text: v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(", ") };
  if (typeof v === "string") return { known: true, text: v };
  return { known: true, text: typeof v === "object" ? JSON.stringify(v) : String(v) };
}

/** The index of the reason column of each column, or -1. */
export function reasonColumns(columns: readonly string[]): number[] {
  return columns.map((c) => columns.indexOf(`${c}_reason`));
}

/** True for a column whose values align right. */
export const alignsRight = (c: Column | undefined): boolean => c?.type === "integer";

/** The widths of the columns in characters of the value font. */
export function columnWidths(
  columns: readonly string[],
  rows: readonly (readonly unknown[])[],
  min = 4,
  max = 48,
): number[] {
  return columns.map((name, i) => {
    let w = name.length;
    for (const r of rows) {
      const v = r[i];
      const t = v === null || v === undefined ? "" : Array.isArray(v) ? v.map(String).join(", ") : String(v);
      if (t.length > w) w = t.length;
      if (w >= max) break;
    }
    return Math.max(min, Math.min(max, w));
  });
}

/** The rows of a virtual table that the view draws, and the space around them. */
export interface RowWindow {
  first: number;
  /** One past the last row. */
  end: number;
  padTop: number;
  padBottom: number;
}

/**
 * The window of rows in view. The rows have the height `h`; the opened
 * row adds `openH` below it. `top` is the scroll offset from the first row
 * and `height` the height of the view.
 */
export function rowWindow(p: {
  top: number;
  height: number;
  h: number;
  count: number;
  open: number | null;
  openH: number;
  overscan?: number;
}): RowWindow {
  const { h, count, open } = p;
  const extra = open === null || open >= count ? 0 : p.openH;
  const total = count * h + extra;
  if (count === 0) return { first: 0, end: 0, padTop: 0, padBottom: 0 };
  const at = (y: number): number => {
    if (y <= 0) return 0;
    if (open === null || open >= count || y < (open + 1) * h) return Math.min(count - 1, Math.floor(y / h));
    if (y < (open + 1) * h + extra) return open;
    return Math.min(count - 1, Math.floor((y - extra) / h));
  };
  const over = p.overscan ?? 8;
  const first = Math.max(0, at(p.top) - over);
  const end = Math.min(count, at(p.top + p.height) + 1 + over);
  return { first, end, padTop: rowTop(first, h, open, extra), padBottom: total - rowTop(end, h, open, extra) };
}

/** The offset of the top of row `i`, with the opened row above it. */
export function rowTop(i: number, h: number, open: number | null, openH: number): number {
  return i * h + (open !== null && i > open ? openH : 0);
}

/** The scroll offset that brings row `i` into a view of `height`, or null. */
export function scrollFor(i: number, top: number, height: number, h: number, open: number | null, openH: number): number | null {
  const y = rowTop(i, h, open, openH);
  if (y < top) return y;
  if (y + h > top + height) return y + h - height;
  return null;
}
