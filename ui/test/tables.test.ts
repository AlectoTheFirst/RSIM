// The state and the layout of the Tables view: the URL, the parameters of
// the API, the filters of a column, the pages, the hairlines and the
// virtual rows.
import { describe, expect, it } from "vitest";
import type { Column, TableDef } from "../src/api/types";
import {
  EMPTY,
  LIMITS,
  answerOf,
  keyForElement,
  keyPlace,
  limitOptions,
  FIRST_PAGE,
  apiParams,
  apiUrl,
  cellText,
  columnWidths,
  deviceFunctions,
  filterCellText,
  nextPage,
  nextSort,
  pageWords,
  parseFilterCell,
  previousPage,
  readState,
  repeats,
  rowTop,
  rowWindow,
  scrollFor,
  setColumnFilters,
  syncPages,
  tableCommand,
  writeState,
} from "../src/tables/model";

const col = (name: string, type: Column["type"]): Column => ({ name, type, semantic: name, description: "" });

const FIB: TableDef = {
  name: "fib",
  description: "",
  key: ["device", "vrf", "prefix", "function"],
  columns: [
    col("device", "text"),
    col("vrf", "text"),
    col("prefix", "prefix"),
    col("kind", "text"),
    col("function", "text"),
    col("next_hops", "list"),
    col("provenance", "list"),
  ],
  verbs: ["show", "summarize", "unique", "top", "lpm"],
  needs: "the twin",
};

/** Column names of the catalog, with those that are also words of a URL or a verb. */
const NAMES = [
  "device", "functions", "function", "kind", "provenance", "endpoint", "addresses", "address", "interface", "host",
  "networks", "vrf", "prefix", "next_hops", "path", "stanzas", "lines", "peer", "source", "range", "local_asn",
  "peer_asn_reason", "shutdown", "state", "established", "outcome", "in_scope", "view", "twin", "q", "table", "verb",
  "sort", "limit", "at", "by", "count", "ascending", "columns", "cursor", "column",
];

describe("URL state", () => {
  it("gives the empty state for an empty URL and writes nothing for it", () => {
    expect(readState("")).toEqual(EMPTY);
    expect(writeState(EMPTY)).toBe("");
  });

  it("keeps each filter of each column name through a round trip", () => {
    for (const name of NAMES) {
      const s = {
        ...EMPTY,
        table: "fib",
        filters: [
          { column: name, op: "=" as const, value: "a,b" },
          { column: name, op: "in_prefix" as const, value: "10.0.0.0/8" },
        ],
      };
      const search = writeState(s, { view: "tables", twin: "builtin.leaf-spine" });
      expect(readState(search), name).toEqual(s);
      const u = new URLSearchParams(search);
      expect(u.get("view")).toBe("tables");
      expect(u.get("twin")).toBe("builtin.leaf-spine");
    }
  });

  it("keeps the verb, the order, the page and the parameters of the verbs", () => {
    const s = {
      ...EMPTY,
      table: "fib",
      verb: "top" as const,
      sort: ["device", "-prefix"],
      limit: 500,
      cursor: "o500",
      by: ["kind"],
      count: 9,
      ascending: true,
      address: "10.0.0.7",
    };
    expect(readState(writeState(s))).toEqual(s);
  });

  it("takes an unknown verb or a bad number as the default", () => {
    const s = readState("?verb=drop&limit=-3&count=x");
    expect([s.verb, s.limit, s.count]).toEqual(["show", 200, 5]);
  });
});

describe("API parameters", () => {
  const base = { ...EMPTY, table: "fib", filters: [{ column: "device", op: "=" as const, value: "r1,r2" }] };

  it("always sends a limit with the rows, and the cursor of the page", () => {
    expect(apiParams({ ...base, cursor: "o200", sort: ["-prefix"] }, FIB)).toEqual([
      ["device", "r1,r2"],
      ["sort", "-prefix"],
      ["limit", "200"],
      ["cursor", "o200"],
    ]);
    expect(apiUrl("builtin.leaf-spine", base, FIB)).toBe("/v1/twins/builtin.leaf-spine/tables/fib/rows?device=r1%2Cr2&limit=200");
  });

  it("gives each verb its parameters and the path of its route", () => {
    expect(apiUrl("t", { ...base, verb: "summarize" }, FIB)).toBe("/v1/twins/t/tables/fib/summary?device=r1%2Cr2");
    expect(apiParams({ ...base, verb: "unique" }, FIB)).toEqual([["device", "r1,r2"], ["columns", "device"]]);
    expect(apiParams({ ...base, verb: "top", by: ["kind"], ascending: true }, FIB)).toEqual([
      ["device", "r1,r2"],
      ["column", "kind"],
      ["count", "5"],
      ["ascending", "true"],
    ]);
    expect(apiParams({ ...base, verb: "lpm", address: "10.0.0.7" }, FIB)).toEqual([
      ["device", "r1,r2"],
      ["address", "10.0.0.7"],
      ["column", "prefix"],
    ]);
    expect(apiUrl("t", { ...base, verb: "describe" }, FIB)).toBeNull();
  });

  it("writes the request as an rsim command", () => {
    expect(tableCommand("leaf-spine", { ...base, verb: "lpm", address: "10.0.0.7" }, FIB)).toBe(
      "rsim leaf-spine fib lpm 10.0.0.7 --device r1,r2 --column prefix",
    );
    expect(tableCommand("leaf-spine", { ...base, verb: "top", ascending: true }, FIB)).toBe(
      "rsim leaf-spine fib top --device r1,r2 --column device --count 5 --ascending",
    );
  });
});

describe("filters of a column", () => {
  it("reads equality values and the typed ops", () => {
    expect(parseFilterCell("prefix", "10.0.0.0/24,10.0.1.0/24")).toEqual([{ column: "prefix", op: "=", value: "10.0.0.0/24,10.0.1.0/24" }]);
    expect(parseFilterCell("lines", "gt 5; lt 10")).toEqual([
      { column: "lines", op: "gt", value: "5" },
      { column: "lines", op: "lt", value: "10" },
    ]);
    expect(parseFilterCell("kind", "= contains")).toEqual([{ column: "kind", op: "=", value: "contains" }]);
    expect(parseFilterCell("kind", "  ;  ")).toEqual([]);
  });

  it("keeps the last filter of an op, as the API does", () => {
    expect(parseFilterCell("lines", "gt 5; gt 7")).toEqual([{ column: "lines", op: "gt", value: "7" }]);
  });

  it("writes the text of a cell back and replaces only its own column", () => {
    const f = setColumnFilters([{ column: "device", op: "=", value: "r1" }], "lines", "gt 5; lt 10");
    expect(filterCellText("lines", f)).toBe("gt 5; lt 10");
    expect(filterCellText("device", f)).toBe("r1");
    expect(setColumnFilters(f, "lines", "")).toEqual([{ column: "device", op: "=", value: "r1" }]);
  });
});

describe("order", () => {
  it("goes rising, falling, then none, and shift adds a column", () => {
    expect(nextSort([], "prefix", false)).toEqual(["prefix"]);
    expect(nextSort(["prefix"], "prefix", false)).toEqual(["-prefix"]);
    expect(nextSort(["-prefix"], "prefix", false)).toEqual([]);
    expect(nextSort(["device"], "prefix", true)).toEqual(["device", "prefix"]);
    expect(nextSort(["device", "-prefix"], "prefix", true)).toEqual(["device"]);
    expect(nextSort(["device", "prefix"], "kind", false)).toEqual(["kind"]);
  });
});

describe("pages", () => {
  it("goes forward and back with the cursors of the API", () => {
    const p2 = nextPage(FIRST_PAGE, "o200", 200);
    const p3 = nextPage(p2, "o400", 200);
    expect(p3).toEqual({ cursor: "o400", back: [null, "o200"], offset: 400 });
    expect(pageWords(p3, 100, 500)).toBe("rows 401 to 500 of 500");
    const back = previousPage(p3, 200);
    expect(back).toEqual(p2);
    expect(previousPage(back, 200)).toEqual(FIRST_PAGE);
    expect(previousPage(FIRST_PAGE, 200)).toEqual(FIRST_PAGE);
  });

  it("does not know the first row of a page that a deep link opens", () => {
    const p = syncPages(null, "o600", 200);
    expect(p).toEqual({ cursor: "o600", back: [], offset: null });
    expect(pageWords(p, 200, 1000)).toBe("200 rows of 1000, after the cursor o600");
    expect(pageWords(FIRST_PAGE, 0, 0)).toBe("no rows of 0");
  });

  it("follows a step back in the history", () => {
    const p3 = nextPage(nextPage(FIRST_PAGE, "o200", 200), "o400", 200);
    expect(syncPages(p3, "o400", 200)).toBe(p3);
    expect(syncPages(p3, "o200", 200)).toEqual({ cursor: "o200", back: [null], offset: 200 });
    expect(syncPages(p3, null, 200)).toEqual(FIRST_PAGE);
  });
});

describe("hairline cells", () => {
  const rows = [
    ["r1", "default", "10.0.0.0/24", "static"],
    ["r1", "default", "10.0.1.0/24", "static"],
    ["r1", "blue", "10.0.1.0/24", "static"],
    ["r2", "blue", "10.0.1.0/24", "static"],
  ];

  it("draws a hairline in the leading cells that repeat the row above", () => {
    expect(repeats(rows)).toEqual([0, 2, 1, 0]);
  });

  it("prints each value in the first row and below an opened row", () => {
    expect(repeats(rows, 0)).toEqual([0, 0, 1, 0]);
  });

  it("prints the last cell even when the whole row repeats", () => {
    expect(repeats([["a", "b"], ["a", "b"]])).toEqual([0, 1]);
  });

  it("compares lists and nulls by value", () => {
    expect(repeats([[["x"], null, 1], [["x"], null, 2]])).toEqual([0, 2]);
  });
});

describe("cells", () => {
  it("has the hatch for a null with a reason and for a null boolean", () => {
    expect(cellText(null, col("peer_asn", "integer"), "the peer group is not defined")).toEqual({
      known: false,
      text: "",
      why: "the peer group is not defined",
    });
    expect(cellText(null, col("established", "boolean")).known).toBe(false);
    expect(cellText([], col("local_asn", "list"), "asn not resolved").known).toBe(false);
    expect(cellText([], col("next_hops", "list"))).toEqual({ known: true, text: "" });
    expect(cellText(null, col("range", "prefix"))).toEqual({ known: true, text: "" });
  });

  it("joins a list and prints a number and a boolean", () => {
    expect(cellText(["a", "b"], col("x", "list")).text).toBe("a, b");
    expect(cellText(65000, col("x", "integer")).text).toBe("65000");
    expect(cellText(false, col("x", "boolean")).text).toBe("false");
  });

  it("gives each column the width of its longest value within the bounds", () => {
    expect(columnWidths(["device", "x", "prefix"], [["r1", 12345, "2001:db8::/32"], ["router-01", 1, null]])).toEqual([9, 5, 13]);
    expect(columnWidths(["p"], [["x".repeat(100)]])).toEqual([48]);
  });

  it("gives a cell that the twin does not know the width of the hatch square and the words", () => {
    const rows = [["r1", null, "not_collected"]];
    const known = (_: number, j: number) => j !== 1;
    expect(columnWidths(["device", "serial", "serial_reason"], rows, 4, 48, known)).toEqual([6, 12, 13]);
  });
});

describe("device rows", () => {
  it("opens the functions table filtered to the device of the row", () => {
    expect(deviceFunctions(["device", "vendor"], ["leaf1", "nxos"])).toEqual([{ column: "device", op: "=", value: "leaf1" }]);
    expect(deviceFunctions(["vendor"], ["nxos"])).toBeNull();
  });
});

describe("virtual rows", () => {
  const base = { h: 18, count: 1000, open: null, openH: 0, overscan: 0 };

  it("draws only the rows in view, with the space of the others", () => {
    const w = rowWindow({ ...base, top: 180, height: 90 });
    expect(w).toEqual({ first: 10, end: 16, padTop: 180, padBottom: (1000 - 16) * 18 });
  });

  it("adds the height of the opened row below it", () => {
    const p = { ...base, open: 5, openH: 100 };
    expect(rowTop(6, 18, 5, 100)).toBe(6 * 18 + 100);
    // The view starts in the opened row: row 5 is the first row drawn.
    expect(rowWindow({ ...p, top: 6 * 18 + 10, height: 18 }).first).toBe(5);
    // Below the opened row the rows move down by its height.
    const w = rowWindow({ ...p, top: 20 * 18 + 100, height: 36 });
    expect(w.first).toBe(20);
    expect(w.padTop + w.padBottom + (w.end - w.first) * 18).toBe(1000 * 18 + 100);
  });

  it("keeps the opened row in the space above when it is above the view", () => {
    const w = rowWindow({ ...base, open: 2, openH: 50, top: 500 * 18 + 50, height: 18 });
    expect(w.padTop).toBe(500 * 18 + 50);
  });

  it("gives no rows for an empty table", () => {
    expect(rowWindow({ ...base, count: 0, top: 0, height: 100 })).toEqual({ first: 0, end: 0, padTop: 0, padBottom: 0 });
  });

  it("scrolls a row into view only when it is outside", () => {
    expect(scrollFor(10, 0, 90, 18, null, 0)).toBe(11 * 18 - 90);
    expect(scrollFor(2, 0, 90, 18, null, 0)).toBeNull();
    expect(scrollFor(2, 100, 90, 18, null, 0)).toBe(36);
  });
});

describe("repeated filters in the URL", () => {
  it("keeps the later filter of the same column and op, as the API does", () => {
    const s = readState("?table=fib&f.device=r1&f.vrf=red&f.device=r2&f.prefix.contains=10.0&f.prefix.contains=10.1&f.prefix.gt=1");
    expect(s.filters).toEqual([
      { column: "vrf", op: "=", value: "red" },
      { column: "device", op: "=", value: "r2" },
      { column: "prefix", op: "contains", value: "10.1" },
      { column: "prefix", op: "gt", value: "1" },
    ]);
    expect(filterCellText("device", s.filters)).toBe("r2");
    const sent = apiParams(s, FIB).filter(([k]) => k === "device" || k.startsWith("prefix."));
    expect(sent).toEqual([
      ["device", "r2"],
      ["prefix.contains", "10.1"],
      ["prefix.gt", "1"],
    ]);
  });
});

describe("page size control", () => {
  it("offers the page size of the URL with the usual sizes", () => {
    expect(limitOptions(200)).toEqual([...LIMITS]);
    expect(limitOptions(50)).toEqual([50, 100, 200, 500, 1000]);
    expect(limitOptions(300)).toEqual([100, 200, 300, 500, 1000]);
    expect(limitOptions(5000)).toEqual([100, 200, 500, 1000, 5000]);
    expect(readState("?limit=50").limit).toBe(50);
  });
});

describe("keys of a view", () => {
  it("leaves each key to a text field and Enter and Space to a button or a link", () => {
    for (const tag of ["INPUT", "SELECT", "TEXTAREA"]) {
      for (const k of ["j", "Enter", "Escape", "n"]) expect(keyForElement(keyPlace({ tagName: tag }), k), `${tag} ${k}`).toBe(true);
    }
    expect(keyPlace({ tagName: "DIV", isContentEditable: true })).toBe("text");
    for (const tag of ["BUTTON", "A", "SUMMARY"]) {
      expect(keyForElement(keyPlace({ tagName: tag }), "Enter"), tag).toBe(true);
      expect(keyForElement(keyPlace({ tagName: tag }), " "), tag).toBe(true);
      for (const k of ["j", "k", "n", "p", "Escape", "y", "/"]) expect(keyForElement(keyPlace({ tagName: tag }), k), `${tag} ${k}`).toBe(false);
    }
    for (const t of [null, { tagName: "BODY" }, { tagName: "DIV" }]) {
      expect(keyForElement(keyPlace(t), "Enter")).toBe(false);
    }
  });
});

describe("answer of a request", () => {
  it("gives the answer of the current request only", () => {
    const a = { key: "/v1/twins/a/tables/fib/rows", value: 1 };
    expect(answerOf(a, a.key)).toBe(1);
    expect(answerOf(a, "/v1/twins/b/tables/fib/rows")).toBeNull();
    expect(answerOf(null, a.key)).toBeNull();
  });
});
