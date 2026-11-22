/// <reference types="node" />
// The layout of the ladder on the stored answers of the CLI tests.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { PathAnswer } from "../src/api/types";
import type { TraceStep } from "../src/api/types";
import {
  FUNCTION_PAD,
  fieldText,
  fileLabel,
  functionLabel,
  functionNames,
  functionWidth,
  ladder,
  lanesOf,
  mostSpecific,
  nameParts,
  notStated,
  answerNotes,
  noteLabel,
  rewritesOf,
  ribNotChecked,
  ribOfGroup,
  spanLabel,
} from "../src/ladder/layout";
import { SIZE } from "../src/theme";

function golden(name: string): PathAnswer {
  const url = new URL(`../../crates/rsim-cli/tests/golden/${name}.json`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as PathAnswer;
}

const FWD = { replyOf: null, branch: 0 };

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

describe("rewrites", () => {
  const a = golden("mini-enterprise").answer;
  const steps = a.branches[0]!.steps;

  it("are the fields whose value after the functions differs from the value before them", () => {
    const snat = steps.find((s) => s.function.endsWith("/snat"))!;
    expect(rewritesOf([snat])).toEqual([
      { field: "source.ip", before: { known: true, text: "172.31.10.20" }, after: { known: true, text: "10.20.0.254" } },
    ]);
    const route = steps.find((s) => s.function.endsWith("/route"))!;
    expect(rewritesOf([route])).toEqual([]);
  });

  it("cover each function of a group", () => {
    expect(rewritesOf(steps.slice(0, 12)).map((r) => r.field)).toEqual(["source.ip"]);
  });

  it("are none for a function with no packets after it", () => {
    const s = steps[0]!;
    expect(rewritesOf([{ ...s, output: { members: [] } } as TraceStep])).toEqual([]);
  });
});

describe("sources and the RIB guard", () => {
  it("takes the span with the fewest lines, the last of equal spans, and leaves out the device of the lane", () => {
    const spans = [
      { file: "fra01-fgt-01.conf", first_line: 60, last_line: 64 },
      { file: "fra01-fgt-01.conf", first_line: 60, last_line: 60 },
    ];
    expect(spanLabel(mostSpecific(spans)!, "fra01-fgt-01")).toBe("conf:60");
    expect(spanLabel(spans[0]!, "fra01-fgt-01")).toBe("conf:60-64");
    const tie = [
      { file: "fra01-fgt-01.conf", first_line: 150, last_line: 150 },
      { file: "fra01-fgt-01.arp", first_line: 1, last_line: 1 },
    ];
    expect(spanLabel(mostSpecific(tie)!, "fra01-fgt-01")).toBe("arp:1");
  });

  it("labels a span by the kind of its file and its lines", () => {
    expect(fileLabel("topology/links.yaml", "leaf1")).toBe("links.yaml");
    expect(spanLabel({ file: "core1/config@b156ff45a077", first_line: 37, last_line: 47 }, "core1")).toBe("config:37-47");
    expect(spanLabel({ file: "unifi-default/devices@5224cb10", first_line: 120, last_line: 131 }, "sw1")).toBe(
      "devices:120-131",
    );
    expect(fileLabel("leaf1", "leaf1")).toBe("leaf1");
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

  it("keeps path order for a path that visits a device twice", () => {
    const lanes = lanesOf([["a", "b", "c", "b", "d"]]);
    expect(lanes.map((l) => l.name)).toEqual(["a", "b", "c", "d"]);
  });
});

describe("the ladder of mini-enterprise", () => {
  const a = golden("mini-enterprise").answer;
  const l = ladder(a, "function", FWD);
  const fwd = l.rows;
  const rep = ladder(a, "function", { replyOf: 0, branch: 0 }).rows;

  it("has a lane for each device of the path in path order, and none for an endpoint", () => {
    expect(l.lanes.map((x) => x.name)).toEqual(["fra01-fgt-01", "fra01-ips-01", "fra01-core-01"]);
  });

  it("prints the source address at the source NAT and no rewrite elsewhere", () => {
    expect(fwd.filter((r) => r.rewrites.length > 0).map((r) => r.fn)).toEqual(["snat"]);
    expect(fwd.find((r) => r.fn === "snat")!.rewrites[0]!.after).toEqual({ known: true, text: "10.20.0.254" });
  });

  it("prints the reason of the engine unchanged and the most specific source", () => {
    const dnat = fwd.find((r) => r.fn === "dnat")!;
    expect(dnat.reason).toBe("not translated, destination NAT fgt:root:vip default action");
    expect(fwd.find((r) => r.fn === "route")!.source).toBe("conf:60");
  });

  it("keeps the RIB guard of each route lookup in its steps", () => {
    expect(fwd.filter((r) => r.steps.some((s) => s.rib_guard === "not_checked")).map((r) => r.steps[0]!.function)).toEqual([
      "fra01-fgt-01/route",
      "fra01-core-01/route",
    ]);
    expect(ribNotChecked(a)).toBeGreaterThanOrEqual(2);
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

  it("draws the reply as its own path in its own lanes", () => {
    const r = ladder(a, "function", { replyOf: 0, branch: 0 });
    expect(r.lanes.map((x) => x.name)).toEqual(["fra01-core-01", "fra01-ips-01", "fra01-fgt-01"]);
    expect(rep[0]!.start).toBe(true);
    expect(rep.every((x) => x.dir === "reply")).toBe(true);
    expect(rep[0]!.key.startsWith("r0.0.")).toBe(true);
  });

  it("makes one row of the functions of a device at the device level", () => {
    const d = ladder(a, "device", FWD).rows;
    expect(d.map((r) => [r.label, r.fn, r.lane])).toEqual([
      ["0-11", "12 functions", 0],
      ["12-14", "3 functions", 1],
      ["15-20", "6 functions", 2],
    ]);
    expect(d[0]!.rewrites.map((r) => [r.field, r.after.text])).toEqual([["source.ip", "10.20.0.254"]]);
    expect(d[1]!.rewrites).toEqual([]);
    expect(d[0]!.reason).toBe("leave on port1 to fra01-ips-01/in/1b");
  });
});

describe("the ladder of leaf-spine", () => {
  const a = golden("leaf-spine").answer;

  it("has the lanes of the selected path only", () => {
    expect(ladder(a, "function", FWD).lanes.map((x) => x.name)).toEqual(["leaf1", "spine1", "leaf2"]);
    expect(ladder(a, "function", { replyOf: null, branch: 1 }).lanes.map((x) => x.name)).toEqual(["leaf1", "spine2", "leaf2"]);
  });

  it("prints the outer header at the encapsulation and the inner header at the decapsulation", () => {
    const rows = ladder(a, "function", FWD).rows;
    const known = (fn: string) =>
      rows
        .find((r) => r.fn === fn)!
        .rewrites.filter((r) => r.after.known)
        .map((r) => [r.field, r.after.text]);
    expect(known("vxlan-encap")).toEqual(
      expect.arrayContaining([
        ["source.ip", "192.0.2.1"],
        ["destination.ip", "192.0.2.2"],
        ["destination.port", "4789"],
        ["network.transport", "udp"],
      ]),
    );
    expect(rows.find((r) => r.fn === "vxlan-encap")!.rewrites.find((r) => r.field === "source.port")!.after.known).toBe(false);
    expect(known("vxlan-decap")).toEqual(
      expect.arrayContaining([
        ["source.ip", "10.1.0.10"],
        ["source.port", "40000"],
        ["destination.ip", "10.2.0.10"],
        ["destination.port", "22"],
        ["network.transport", "tcp"],
      ]),
    );
    expect(rows.filter((r) => r.rewrites.length > 0).map((r) => r.fn)).toEqual(["vxlan-encap", "vxlan-decap"]);
  });
});

describe("the function column", () => {
  // An invented SSID of 32 characters.
  const SSID = "Example Corp Guest WiFi Floor 02";
  const name = `host/wlan/${SSID}/wlan-3`;

  it("is as wide as the longest name of the answer, from 168px to 264px", () => {
    expect(SSID.length).toBe(32);
    expect(functionWidth(["route", "in/eth0"])).toBe(SIZE.colFunction);
    expect(functionWidth([name])).toBe(SIZE.colFunctionMax);
    const mid = "x".repeat(26);
    expect(functionWidth([mid])).toBe(Math.ceil(26 * SIZE.valueChar) + FUNCTION_PAD);
    expect(functionNames(golden("mini-enterprise").answer)).toContain("snat");
  });

  it("breaks a name after each slash, then at a space, and keeps each character", () => {
    const step = { function: `ap-01/${name}`, device: "ap-01" } as TraceStep;
    const label = functionLabel(step);
    expect(label).toBe(name);
    const wide = nameParts(label, SIZE.colFunctionMax);
    expect(wide).toEqual(["host/", "wlan/", `${SSID.replace(/ /g, "\u00a0")}/`, "wlan-3"]);
    expect(wide.join("").replace(/\u00a0/g, " ")).toBe(label);
    const narrow = nameParts(label, SIZE.colFunction);
    expect(narrow[2]).toBe(`${SSID}/`);
    expect(narrow.join("")).toBe(label);
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

  it("leaves out the fields that take a default value with unstated defaults", () => {
    const q = golden("mini-enterprise").query as unknown as Record<string, unknown>;
    const all = notStated({ ...q, unstated: "all" });
    expect(all).toEqual(notStated(q));
    const n = notStated({ ...q, unstated: "defaults" });
    for (const k of ["dscp", "ecn", "network.vlan.id", "l2_priority", "fragment", "tcp_flags", "icmp_type", "icmp_code", "source.port", "unstated"]) {
      expect(n, k).not.toContain(k);
    }
    expect(n).toContain("source.mac");
    expect(notStated({ ...q, unstated: "defaults", "network.vlan.id": 10 })).toContain("l2_priority");
  });
});

describe("answer notes", () => {
  it("gives the notes of a path answer as they are, and none for a set answer or a path answer with no notes", () => {
    const a = golden("mini-enterprise");
    expect(answerNotes(a)).toEqual([]);
    expect(answerNotes({ ...a, notes: ["defaults: dscp 0, ecn 0, no VLAN"] })).toEqual(["defaults: dscp 0, ecn 0, no VLAN"]);
    expect(answerNotes({ kind: "set_answer", notes: ["x"] })).toEqual([]);
  });
});

describe("note label", () => {
  it("is the word before the colon, and the whole note goes in the title", () => {
    expect(noteLabel("defaults: dscp 0, ecn 0, no VLAN, tcp syn, source.port 49152-65535")).toBe("defaults");
    expect(noteLabel("no colon")).toBe("no colon");
  });
});
