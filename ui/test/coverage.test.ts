// The layout of the coverage report and the view state in the URL.
import { describe, expect, it } from "vitest";
import { coverageRow, coverageSums, readCoverage, shareText, writeCoverage } from "../src/coverage/model";
import { viewOf, viewSearch, withTwin } from "../src/page/url";

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

  it("gives the unhandled share and the sums of a page", () => {
    expect(shareText(rows[0]!)).toBe("5.0%");
    expect(shareText(coverageRow(COLUMNS, ["e", 0, 0, 0, 0, 0]))).toBe("0.0%");
    expect(coverageSums(rows)).toEqual({ handled: 120, irrelevant: 15, unhandled: 5, devices: 1 });
  });

  it("keeps the page and the opened device in the URL", () => {
    const s = { cursor: "o200", limit: 200, device: "r1" };
    const search = writeCoverage(s, { view: "coverage", twin: "snap-3" });
    expect(readCoverage(search)).toEqual(s);
    expect(viewOf(search)).toBe("Coverage");
    expect(writeCoverage({ cursor: null, limit: 200, device: null })).toBe("");
  });
});

describe("views in the URL", () => {
  it("takes a URL with no view as Trace, so a query link stays as it is", () => {
    expect(viewOf("?twin=builtin.leaf-spine&q=abc")).toBe("Trace");
    expect(viewOf("?view=tables")).toBe("Tables");
    expect(viewOf("?view=admin")).toBe("Trace");
  });

  it("keeps the table when the view stays Tables and drops it elsewhere", () => {
    expect(viewSearch("Tables", "t1", "?view=tables&table=fib&f.device=r1")).toBe("?view=tables&twin=t1&table=fib");
    expect(viewSearch("Coverage", "t1", "?view=tables&table=fib")).toBe("?view=coverage&twin=t1");
    expect(viewSearch("Trace", "t1")).toBe("?twin=t1");
  });

  it("drops the query, the page and the opened device for another twin", () => {
    expect(withTwin("?view=tables&twin=a&table=fib&f.device=r1&at=o200", "b")).toBe("?view=tables&twin=b&table=fib&f.device=r1");
    expect(withTwin("?view=coverage&twin=a&device=r1", "b")).toBe("?view=coverage&twin=b");
  });
});
