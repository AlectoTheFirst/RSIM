/// <reference types="node" />
// The layout of the ladder on the stored answers of the CLI tests.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { PathAnswer } from "../src/api/types";
import {
  cell,
  fieldText,
  fileLabel,
  ladder,
  lanesOf,
  mostSpecific,
  notStated,
  ribNotChecked,
  ribOfGroup,
  spanLabel,
  type StepRow,
} from "../src/ladder/layout";

function golden(name: string): PathAnswer {
  const url = new URL(`../../crates/rsim-cli/tests/golden/${name}.json`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as PathAnswer;
}

const steps = (rows: ReturnType<typeof ladder>["rows"]) =>
  rows.filter((r): r is StepRow => r.type === "step");

describe("field values", () => {
  it("prints a known value, a protocol name and an absent header", () => {
    expect(fieldText({ known: "10.0.0.1" }, "source.ip")).toEqual({ known: true, text: "10.0.0.1" });
    expect(fieldText({ known: 17 }, "network.transport")).toEqual({ known: true, text: "udp" });
    expect(fieldText("absent", "source.port")).toEqual({ known: true, text: "absent" });
  });

  it("does not know a range, a list or an unknown value", () => {
    expect(fieldText({ in: [[0, 1023]] }, "source.port")).toEqual({ known: false, text: "0-1023" });
    expect(fieldText({ in: [[53, 53], [80, 80]] }, "destination.port")).toEqual({ known: false, text: "53,80" });
    expect(fieldText("unknown", "source.ip").known).toBe(false);
  });
});

describe("cells", () => {
  const k = (text: string) => ({ known: true, text });
  const u = (text: string) => ({ known: false, text });

  it("prints each value on the first row", () => {
    expect(cell(k("53"), k("53"), true)).toEqual({ kind: "value", text: "53" });
  });

  it("has a hairline where a later row keeps the value", () => {
    expect(cell(k("53"), k("53"), false)).toEqual({ kind: "same" });
  });

  it("prints the value that a function writes", () => {
    expect(cell(k("172.31.10.20"), k("10.20.0.254"), false)).toEqual({ kind: "changed", text: "10.20.0.254" });
    expect(cell(k("1"), k("2"), true)).toEqual({ kind: "changed", text: "2" });
  });

  it("has a hatch for a value that the twin does not know, on each row", () => {
    expect(cell(u("0-65535"), u("0-65535"), true)).toEqual({ kind: "hatch", text: "0-65535" });
    expect(cell(u("0-65535"), u("0-65535"), false)).toEqual({ kind: "hatch", text: "0-65535" });
    expect(cell(k("53"), u("unknown"), false)).toEqual({ kind: "hatch", text: "unknown" });
  });

  it("keeps the input of a function with no output packets", () => {
    expect(cell(k("53"), null, false)).toEqual({ kind: "same" });
  });
});

describe("sources and the RIB guard", () => {
  it("takes the span with the fewest lines and leaves out the device of the lane", () => {
    const spans = [
      { file: "fra01-fgt-01.conf", first_line: 60, last_line: 64 },
      { file: "fra01-fgt-01.conf", first_line: 60, last_line: 60 },
    ];
    expect(spanLabel(mostSpecific(spans)!, "fra01-fgt-01")).toBe("conf:60");
    expect(spanLabel(spans[0]!, "fra01-fgt-01")).toBe("conf:60-64");
    expect(fileLabel("topology/links.yaml", "leaf1")).toBe("topology/links.yaml");
  });

  it("marks a group by its strongest guard", () => {
    expect(ribOfGroup(["not_applicable", "not_checked"])).toBe("hatch");
    expect(ribOfGroup(["matches_collected", "differs_from_collected"])).toBe("differs");
    expect(ribOfGroup(["not_applicable"])).toBe("none");
  });
});

describe("lanes", () => {
  it("keeps the devices of equal-cost paths side by side", () => {
    const lanes = lanesOf([
      ["leaf1", "spine1", "leaf2"],
      ["leaf1", "spine2", "leaf2"],
      ["leaf2", "spine1", "leaf1"],
    ]);
    expect(lanes.map((l) => l.name)).toEqual(["leaf1", "spine1", "spine2", "leaf2"]);
  });
});

describe("the ladder of mini-enterprise", () => {
  const a = golden("mini-enterprise").answer;
  const l = ladder(a, "function");
  const rows = steps(l.rows);
  const fwd = rows.filter((r) => r.dir === "forward");
  const rep = rows.filter((r) => r.dir === "reply");

  it("has a lane for each device in path order", () => {
    expect(l.lanes.map((x) => x.name)).toEqual(["fra01-fgt-01", "fra01-ips-01", "fra01-core-01"]);
  });

  it("prints each value on the first row only", () => {
    expect(fwd[0]!.cells).toEqual([
      { kind: "value", text: "172.31.10.20" },
      { kind: "value", text: "40000" },
      { kind: "value", text: "10.20.0.53" },
      { kind: "value", text: "53" },
      { kind: "value", text: "udp" },
    ]);
    expect(fwd[1]!.cells.every((c) => c.kind === "same")).toBe(true);
  });

  it("prints the source address at the source NAT and a hairline elsewhere", () => {
    const changed = fwd.filter((r) => r.cells.some((c) => c.kind !== "same"));
    expect(changed.map((r) => r.fn)).toEqual(["in/port2", "snat"]);
    expect(fwd.find((r) => r.fn === "snat")!.cells[0]).toEqual({ kind: "changed", text: "10.20.0.254" });
  });

  it("prints the reason of the engine unchanged and the most specific source", () => {
    const dnat = fwd.find((r) => r.fn === "dnat")!;
    expect(dnat.reason).toBe("not translated · destination NAT fgt:root:vip default action");
    expect(fwd.find((r) => r.fn === "route")!.source).toBe("conf:60");
  });

  it("has a hatch in the RIB column of each route lookup that is not checked", () => {
    expect(fwd.filter((r) => r.rib === "hatch").map((r) => r.steps[0]!.function)).toEqual([
      "fra01-fgt-01/route",
      "fra01-core-01/route",
    ]);
    expect(ribNotChecked(a)).toBe(rows.filter((r) => r.rib === "hatch").length);
  });

  it("starts, steps across at each link and ends in deliver", () => {
    expect(fwd[0]!.start).toBe(true);
    expect(fwd.filter((r) => r.enterFrom !== null).map((r) => [r.enterFrom, r.lane])).toEqual([
      [0, 1],
      [1, 2],
    ]);
    expect(fwd[fwd.length - 1]!.end).toBe("deliver");
    expect(fwd.slice(0, -1).every((r) => r.end === null)).toBe(true);
  });

  it("puts the reply under the row reply of branch 0", () => {
    const sec = l.rows.find((r) => r.type === "section");
    expect(sec && sec.type === "section" && sec.text).toBe("reply of branch 0");
    expect(rep[0]!.start).toBe(true);
    expect(rep[0]!.cells[0]).toEqual({ kind: "value", text: "10.20.0.53" });
  });

  it("makes one row of the functions of a device at the device level", () => {
    const d = steps(ladder(a, "device").rows).filter((r) => r.dir === "forward");
    expect(d.map((r) => [r.label, r.fn, r.lane])).toEqual([
      ["0-11", "12 functions", 0],
      ["12-14", "3 functions", 1],
      ["15-20", "6 functions", 2],
    ]);
    expect(d[0]!.cells[0]).toEqual({ kind: "changed", text: "10.20.0.254" });
    expect(d[1]!.cells.every((c) => c.kind === "same")).toBe(true);
    expect(d[0]!.rib).toBe("hatch");
    expect(d[0]!.reason).toBe("leave on port1 to fra01-ips-01/in/1b");
  });
});

describe("the ladder of leaf-spine", () => {
  const a = golden("leaf-spine").answer;
  const l = ladder(a, "function");

  it("keeps both spines between the leaves", () => {
    expect(l.lanes.map((x) => x.name)).toEqual(["leaf1", "spine1", "spine2", "leaf2"]);
  });

  it("has a section for each branch and for each reply branch", () => {
    const secs = l.rows.filter((r) => r.type === "section").map((r) => r.type === "section" && r.text);
    expect(secs).toEqual([
      "branch 0",
      "branch 1",
      "reply of branch 0, branch 0",
      "reply of branch 0, branch 1",
      "reply of branch 1, branch 0",
      "reply of branch 1, branch 1",
    ]);
  });

  it("prints the outer header at the encapsulation and the inner header at the decapsulation", () => {
    const b0 = steps(l.rows).filter((r) => r.dir === "forward" && r.path.branch === 0);
    const encap = b0.find((r) => r.fn === "vxlan-encap")!;
    expect(encap.cells).toEqual([
      { kind: "changed", text: "192.0.2.1" },
      { kind: "hatch", text: "unknown" },
      { kind: "changed", text: "192.0.2.2" },
      { kind: "changed", text: "4789" },
      { kind: "changed", text: "udp" },
    ]);
    const decap = b0.find((r) => r.fn === "vxlan-decap")!;
    expect(decap.cells).toEqual([
      { kind: "changed", text: "10.1.0.10" },
      { kind: "changed", text: "40000" },
      { kind: "changed", text: "10.2.0.10" },
      { kind: "changed", text: "22" },
      { kind: "changed", text: "tcp" },
    ]);
    expect(b0.filter((r) => r.cells.some((c) => c.kind === "changed")).map((r) => r.fn)).toEqual([
      "vxlan-encap",
      "vxlan-decap",
    ]);
  });
});

describe("the query fields", () => {
  it("lists the fields that the query does not state", () => {
    const q = golden("mini-enterprise").query as unknown as Record<string, unknown>;
    const n = notStated(q);
    expect(n).not.toContain("source.ip");
    expect(n).not.toContain("network.transport");
    expect(n).toContain("dscp");
  });
});
