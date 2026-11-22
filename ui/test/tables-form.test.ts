// The forms, the hidden columns, the filter chips, the function names,
// the source spans and the row panel of the Tables view.
import { describe, expect, it } from "vitest";
import type { Column, TableDef } from "../src/api/types";
import {
  EMPTY,
  FORM_LABELS,
  cellLabel,
  cellText,
  chipValue,
  filterColumns,
  formsOf,
  nameParts,
  parseSpan,
  readState,
  rowSpans,
  rowTitle,
  rowsForm,
  sortBy,
  spanCellLabel,
  stepRow,
  toggleHidden,
  visibleColumns,
  withoutFilter,
  writeState,
} from "../src/tables/model";

const col = (name: string, type: Column["type"], semantic = name): Column => ({ name, type, semantic, description: "" });

const FIB: TableDef = {
  name: "fib",
  description: "",
  key: ["device", "vrf", "prefix", "function"],
  columns: [
    col("device", "text", "device"),
    col("vrf", "text"),
    col("prefix", "prefix"),
    col("function", "text", "function"),
    col("next_hops", "list"),
    col("provenance", "list", "source_span"),
  ],
  verbs: ["show", "summarize", "unique", "top", "lpm"],
  needs: "the twin",
};

describe("forms", () => {
  it("gives a tab for each verb of the table and the tab Columns", () => {
    expect(formsOf(FIB).map((v) => FORM_LABELS[v])).toEqual(["Rows", "Summary", "Distinct", "Top", "Longest match", "Columns"]);
    expect(formsOf({ ...FIB, verbs: ["show", "summarize"] }).map((v) => FORM_LABELS[v])).toEqual(["Rows", "Summary", "Columns"]);
    expect(formsOf(null)).toEqual([]);
  });

  it("opens the row panel only for the forms whose rows are rows of the table", () => {
    expect((["show", "summarize", "unique", "top", "lpm", "describe"] as const).filter(rowsForm)).toEqual(["show", "top", "lpm"]);
  });
});

describe("hidden columns", () => {
  const cols = ["device", "serial", "serial_reason", "provenance"];

  it("draws the source spans and hides the reason columns and the hidden columns", () => {
    expect(visibleColumns(cols, [])).toEqual([0, 1, 3]);
    expect(visibleColumns(cols, ["serial"])).toEqual([0, 3]);
  });

  it("hides and shows a column", () => {
    expect(toggleHidden([], "vrf")).toEqual(["vrf"]);
    expect(toggleHidden(["vrf", "kind"], "vrf")).toEqual(["kind"]);
  });

  it("keeps the hidden columns through the URL", () => {
    const s = { ...EMPTY, table: "fib", hide: ["vrf", "next_hops"] };
    expect(readState(writeState(s))).toEqual(s);
    expect(readState("").hide).toEqual([]);
  });
});

describe("order of the column menu", () => {
  it("sorts by the column alone or takes it out of the order", () => {
    expect(sortBy(["device", "-prefix"], "kind", "up")).toEqual(["kind"]);
    expect(sortBy(["device"], "prefix", "down")).toEqual(["-prefix"]);
    expect(sortBy(["device", "-prefix"], "prefix", null)).toEqual(["device"]);
  });
});

describe("filter chips", () => {
  const filters = [
    { column: "prefix", op: "=" as const, value: "192.0.2.0/24,198.51.100.0/24" },
    { column: "prefix", op: "in_prefix" as const, value: "203.0.113.0/24" },
  ];

  it("prints the values, or the op and the value", () => {
    expect(filters.map(chipValue)).toEqual(["192.0.2.0/24,198.51.100.0/24", "in_prefix 203.0.113.0/24"]);
  });

  it("removes one filter of a column and keeps the other", () => {
    expect(withoutFilter(filters, filters[1]!)).toEqual([filters[0]]);
  });

  it("offers each column except a reason column of another column", () => {
    const def = { ...FIB, columns: [col("device", "text"), col("serial", "text"), col("serial_reason", "text"), col("drop_reason", "text")] };
    expect(filterColumns(def)).toEqual(["device", "serial", "drop_reason"]);
  });
});

describe("function names", () => {
  it("breaks a name after each slash", () => {
    expect(nameParts("core-01/in/Ethernet1/1")).toEqual(["core-01/", "in/", "Ethernet1/", "1"]);
    expect(nameParts("route")).toEqual(["route"]);
    expect(nameParts("core-01/route").join("")).toBe("core-01/route");
  });
});

describe("source spans", () => {
  it("reads a line range, one line and a row span", () => {
    expect(parseSpan("core-01/config@ab12:10-20")).toEqual({ file: "core-01/config@ab12", first_line: 10, last_line: 20 });
    expect(parseSpan("core-01/config@ab12:7")).toEqual({ file: "core-01/config@ab12", first_line: 7, last_line: 7 });
    expect(parseSpan("core-01/routes@cd34#row:3-3")).toEqual({ file: "core-01/routes@cd34#row", first_line: 3, last_line: 3 });
    expect(parseSpan("no span")).toBeNull();
  });

  it("labels a span by its section and its lines or rows", () => {
    expect(spanCellLabel("core-01/config@ab12:10-20")).toBe("config:10-20");
    expect(spanCellLabel("core-01/config@ab12:7-7")).toBe("config:7");
    expect(spanCellLabel("core-01/routes@cd34#row:3-3")).toBe("routes row 3");
    expect(spanCellLabel("core-01/routes@cd34#row:3-5")).toBe("routes rows 3-5");
  });

  it("prints the labels in a column of spans and the value in another column", () => {
    const spans = ["core-01/config@ab12:1-2", "core-01/routes@cd34#row:4-4"];
    expect(cellLabel(cellText(spans, FIB.columns[5]), FIB.columns[5], spans)).toBe("config:1-2, routes row 4");
    expect(cellLabel(cellText(["x"], FIB.columns[4]), FIB.columns[4], ["x"])).toBe("x");
  });

  it("lists the spans of a row with the span of each", () => {
    const row = ["core-01", "default", "192.0.2.0/24", "core-01/route", ["192.0.2.1@eth0"], ["core-01/config@ab12:1-2", "core-01/routes@cd34#row:4-4"]];
    const cols = FIB.columns.map((c) => c.name);
    expect(rowSpans(cols, FIB.columns, row).map((e) => [e.text, e.span?.first_line])).toEqual([
      ["core-01/config@ab12:1-2", 1],
      ["core-01/routes@cd34#row:4-4", 4],
    ]);
  });
});

describe("row panel", () => {
  const cols = FIB.columns.map((c) => c.name);

  it("names a row by the values of the key columns of the table", () => {
    expect(rowTitle(FIB, cols, ["core-01", "default", "192.0.2.0/24", "core-01/route", [], []])).toBe("core-01 default 192.0.2.0/24 core-01/route");
    expect(rowTitle(null, ["column", "type"], ["device", "text"])).toBe("device");
  });

  it("steps to the row before and after, and stops at the ends", () => {
    expect(stepRow(0, -1, 3)).toBeNull();
    expect(stepRow(0, 1, 3)).toBe(1);
    expect(stepRow(2, 1, 3)).toBeNull();
    expect(stepRow(null, 1, 3)).toBeNull();
  });
});
