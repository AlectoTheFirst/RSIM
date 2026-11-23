// The layout of the coverage report and the view state in the URL.
import { describe, expect, it } from "vitest";
import type { TableOut } from "../src/api/types";
import {
  type PathsState,
  coverageKey,
  coverageRow,
  cellText,
  columnChars,
  COVERAGE_COLUMNS,
  openedDevice,
  pathParts,
  pathsStep,
  readCoverage,
  shareText,
  stepRow,
  writeCoverage,
} from "../src/coverage/model";
import { newerRun, pinnedRun, reloadMark, twinState, twinStateText, viewOf, viewSearch, withTwin } from "../src/page/url";
import { answerOf, nextPage, pageWords, previousPage, syncPages } from "../src/tables/model";

const COLUMNS = ["device", "handled", "irrelevant", "unhandled", "unhandled_paths", "unhandled_stanzas"];

describe("coverage report", () => {
  const rows = [
    coverageRow(COLUMNS, ["r1", 80, 15, 5, 2, 3]),
    coverageRow(COLUMNS, ["site1", 40, 0, 0, 0, 0]),
  ];

  it("reads a row by the column names of the API", () => {
    expect(rows[0]).toEqual({ device: "r1", lines: 100, handled: 80, irrelevant: 15, unhandled: 5, paths: 2, stanzas: 3 });
    expect(coverageRow(["unhandled", "device"], [7, "x"]).unhandled).toBe(7);
  });

  it("gives the unhandled share", () => {
    expect(shareText(rows[0]!)).toBe("5.0%");
    expect(shareText(coverageRow(COLUMNS, ["e", 0, 0, 0, 0, 0]))).toBe("0.0%");
  });

  it("gives the text of each cell and the width of each column in characters", () => {
    expect(COVERAGE_COLUMNS.map((c) => cellText(rows[0]!, c))).toEqual(["r1", "100", "80", "15", "5", "5.0%", "2", "3"]);
    const long = coverageRow(COLUMNS, ["distribution-switch-0042", 1234567, 0, 0, 0, 0]);
    expect(columnChars([...rows, long])).toEqual([24, 7, 7, 16, 9, 15, 15, 17]);
    expect(columnChars([])).toEqual(COVERAGE_COLUMNS.map((c) => c.name.length));
  });

  it("breaks a path after each slash", () => {
    expect(pathParts("networks/*/is_nat")).toEqual(["networks/", "*/", "is_nat"]);
    expect(pathParts("interface */ip address ..")).toEqual(["interface */", "ip address .."]);
    expect(pathParts("system/")).toEqual(["system/"]);
  });

  it("moves the current row with j and k inside the page", () => {
    expect(stepRow("j", null, 3)).toBe(0);
    expect(stepRow("j", 1, 3)).toBe(2);
    expect(stepRow("j", 2, 3)).toBe(2);
    expect(stepRow("k", 0, 3)).toBe(0);
    expect(stepRow("k", 2, 3)).toBe(1);
    expect(stepRow("j", null, 0)).toBeNull();
    expect(stepRow("x", 1, 3)).toBeNull();
  });

  it("keeps the page and the opened device in the URL", () => {
    const s = { cursor: "o200", limit: 200, device: "r1" };
    const search = writeCoverage(s, { view: "coverage", twin: "snapshot-2026-11-22-140503" });
    expect(readCoverage(search)).toEqual(s);
    expect(viewOf(search)).toBe("Coverage");
    expect(writeCoverage({ cursor: null, limit: 200, device: null })).toBe("");
  });
});

describe("reload of the store", () => {
  it("marks a newest snapshot that does not build, with the held snapshot", () => {
    const base = { id: "store", href: "/v1/twins/store", held: "snapshot-2026-11-22-140504", newest: "snapshot-2026-11-22-140505" };
    expect(reloadMark([{ ...base, reload_error: null }])).toBeNull();
    expect(reloadMark([{ id: "builtin.ecmp", href: "/v1/twins/builtin.ecmp" }])).toBeNull();
    expect(reloadMark([{ ...base, reload_error: { snapshot: "snapshot-2026-11-22-140505", detail: "the twin does not build" } }])).toEqual({
      text: "snapshot-2026-11-22-140505 does not build, snapshot-2026-11-22-140504 answers",
      title: "the twin does not build",
    });
    expect(reloadMark([{ ...base, reload_error: { snapshot: null, detail: "HEAD: no such file" } }])).toEqual({
      text: "store HEAD not read, snapshot-2026-11-22-140504 answers",
      title: "HEAD: no such file",
    });
    expect(reloadMark([{ ...base, loading: "snapshot-2026-11-22-140505", reload_error: null }])).toBeNull();
  });

  it("pins the newest built run and offers a newer run", () => {
    const twins = [{ id: "store", href: "/v1/twins/store", held: "snapshot-2026-11-22-140512", previous: "snapshot-2026-11-22-140511" }];
    expect(pinnedRun(twins, "store")).toBe("snapshot-2026-11-22-140512");
    expect(pinnedRun(twins, "snapshot-2026-11-22-140511")).toBe("snapshot-2026-11-22-140511");
    expect(pinnedRun([{ id: "store", href: "/v1/twins/store", held: null }], "store")).toBe("store");
    expect(newerRun(twins, "snapshot-2026-11-22-140511")).toBe("snapshot-2026-11-22-140512");
    expect(newerRun(twins, "snapshot-2026-11-22-140512")).toBeNull();
    expect(newerRun(twins, "store")).toBeNull();
    // A name of a later day is newer, and the old form is not a snapshot.
    expect(newerRun(twins, "snapshot-2026-11-21-235959")).toBe("snapshot-2026-11-22-140512");
    expect(newerRun(twins, "snap-11")).toBeNull();
  });

  it("answers only for a twin with a snapshot, and names the state of the others", () => {
    const store = (held: string | null, newest: string | null) => [{ id: "store", href: "/v1/twins/store", held, newest }];
    const s3 = "snapshot-2026-11-22-140503";
    expect(twinState(null, "")).toBe("loading");
    expect(twinState([], "")).toBe("none");
    expect(twinState(store(null, null), "store")).toBe("empty");
    expect(twinState(store(null, s3), "store")).toBe("ready");
    expect(twinState(store(s3, s3), "store")).toBe("ready");
    expect(twinState(store(null, null), "snapshot-2026-11-22-140503")).toBe("ready");
    expect(twinStateText("empty")).toEqual({ text: "no snapshot", title: "empty store" });
    expect(twinStateText("none")).toEqual({ text: "no store", title: "rsim-api has no --store" });
    expect(twinStateText("ready")).toBeNull();
  });
});

describe("views in the URL", () => {
  it("takes a URL with no view as Trace", () => {
    expect(viewOf("?twin=builtin.leaf-spine&q=abc")).toBe("Trace");
    expect(viewOf("?view=tables")).toBe("Tables");
    expect(viewOf("?view=admin")).toBe("Trace");
  });

  it("keeps the table when the view stays Tables and drops it elsewhere", () => {
    expect(viewSearch("Tables", "t1", "?view=tables&table=fib&f.device=r1")).toBe("?view=tables&twin=t1&table=fib");
    expect(viewSearch("Coverage", "t1", "?view=tables&table=fib")).toBe("?view=coverage&twin=t1");
    expect(viewSearch("Trace", "t1")).toBe("?twin=t1");
  });

  it("keeps the query of the shown answer only for the Trace view", () => {
    expect(viewSearch("Trace", "t1", "?view=tables&twin=t1", "qabc")).toBe("?twin=t1&q=qabc");
    expect(viewSearch("Tables", "t1", "", "qabc")).toBe("?view=tables&twin=t1");
  });

  it("drops the query, the page and the opened device for another twin", () => {
    expect(withTwin("?view=tables&twin=a&table=fib&f.device=r1&at=o200", "b")).toBe("?view=tables&twin=b&table=fib&f.device=r1");
    expect(withTwin("?view=coverage&twin=a&device=r1", "b")).toBe("?view=coverage&twin=b");
  });
});

describe("report of the current request", () => {
  const st = readCoverage("?view=coverage&twin=builtin.a");
  it("draws no rows of another twin or another page while a request runs", () => {
    const answer = { key: coverageKey("builtin.a", st), value: "rows of a" };
    expect(answerOf(answer, coverageKey("builtin.a", st))).toBe("rows of a");
    expect(answerOf(answer, coverageKey("builtin.b", st))).toBeNull();
    expect(answerOf(answer, coverageKey("builtin.a", { ...st, cursor: "o200" }))).toBeNull();
    expect(answerOf(answer, coverageKey("builtin.a", { ...st, limit: 500 }))).toBeNull();
  });
});

describe("opened device in the URL", () => {
  const COLS = ["device", "handled", "irrelevant", "unhandled", "unhandled_paths", "unhandled_stanzas"];
  const rows = ["r1", "r2", "r3"].map((d) => coverageRow(COLS, [d, 1, 0, 0, 0, 0]));
  const url = (selected: number | null, open: boolean) =>
    writeCoverage({ cursor: null, limit: 200, device: openedDevice(rows, selected, open) }, { view: "coverage", twin: "snapshot-2026-11-22-140503" });

  it("names the device of the opened row after j, k and Escape", () => {
    expect(readCoverage(url(0, true)).device).toBe("r1");
    expect(readCoverage(url(1, true)).device).toBe("r2");
    expect(readCoverage(url(1, false)).device).toBeNull();
    expect(readCoverage(url(null, true)).device).toBeNull();
    expect(openedDevice(rows, 7, true)).toBeNull();
  });
});

describe("unhandled paths of a device", () => {
  const page = (first: number, n: number, total: number, next: string | null): TableOut =>
    ({
      columns: ["path", "stanzas", "lines"],
      rows: Array.from({ length: n }, (_, i) => [`p${first + i}`, 1, 1]),
      total,
      next_cursor: next,
    }) as unknown as TableOut;
  const start: PathsState = { want: syncPages(null, null, 200), shown: null, problem: null };

  it("shows the paths again after a failed page and gives the words of the rows on screen", () => {
    let s = pathsStep(start, { kind: "done", at: start.want, out: page(0, 200, 450, "o200") });
    const p1 = s.want;
    const p2 = nextPage(p1, "o200", 200);
    s = pathsStep(s, { kind: "go", to: p2 });
    // While page 2 loads, the rows on screen are those of page 1, with their own place.
    expect(s.shown!.at).toBe(p1);
    expect(pageWords(s.shown!.at, s.shown!.out.rows.length, 450)).toBe("rows 1 to 200 of 450");
    s = pathsStep(s, { kind: "failed", at: p2, problem: "The server is down." });
    expect(s.problem).toBe("The server is down.");
    const back = previousPage(s.want, 200);
    expect(back.cursor).toBeNull();
    s = pathsStep(s, { kind: "go", to: back });
    expect(s.problem).toBeNull();
    s = pathsStep(s, { kind: "done", at: back, out: page(0, 200, 450, "o200") });
    expect(s.problem).toBeNull();
    expect(s.shown!.at).toBe(s.want);
    expect(pageWords(s.shown!.at, s.shown!.out.rows.length, 450)).toBe("rows 1 to 200 of 450");
  });

  it("drops the answer of a page that the view does not ask for", () => {
    const p2 = nextPage(start.want, "o200", 200);
    const s = pathsStep(start, { kind: "go", to: p2 });
    expect(pathsStep(s, { kind: "done", at: start.want, out: page(0, 200, 450, "o200") })).toBe(s);
    expect(pathsStep(s, { kind: "failed", at: start.want, problem: "x" })).toBe(s);
  });
});
