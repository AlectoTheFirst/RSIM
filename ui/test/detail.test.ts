/// <reference types="node" />
// The result line counts, the outcome words and the values of the opened row.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { SetAnswer, TraceStep } from "../src/api/types";
import { serverTiming } from "../src/api/client";
import { delayShown, detailSpans, outcomeKnown, partCounts, qosShown, rateShown } from "../src/ladder/layout";

describe("server timing", () => {
  it("reads the engine time and a cache hit of the Server-Timing header", () => {
    expect(serverTiming("engine;dur=4.5")).toEqual({ engineMs: 4.5, cacheHit: false });
    expect(serverTiming("cache;desc=hit")).toEqual({ engineMs: null, cacheHit: true });
    expect(serverTiming('db;dur=1, engine;desc="run";dur=12')).toEqual({ engineMs: 12, cacheHit: false });
    expect(serverTiming(null)).toEqual({ engineMs: null, cacheHit: false });
  });
});

describe("set result line", () => {
  it("counts a same_kind part once, by its kind, and only depends_on_path parts as depending on the path", () => {
    const parts = [
      { result: { kind: "same_kind", verdict: null, verdict_kind: "drop" } },
      { result: { kind: "same", verdict: { kind: "deliver" } as never, verdict_kind: "deliver" } },
      { result: { kind: "same_kind", verdict_kind: "unknown" } },
      { result: { kind: "depends_on_path", verdict: null, verdict_kind: null } },
    ];
    expect(partCounts(parts)).toEqual({ deliver: 1, drop: 1, unknown: 1, dependsOnPath: 1 });
  });

  it("counts the parts of the stored set answer of mini-enterprise", () => {
    const url = new URL("../../crates/rsim-cli/tests/golden/set-mini-enterprise.json", import.meta.url);
    const a = (JSON.parse(readFileSync(url, "utf8")) as SetAnswer).answer;
    expect(partCounts(a.summary)).toEqual({ deliver: 1, drop: 2, unknown: 0, dependsOnPath: 0 });
  });
});

describe("outcome words", () => {
  it("gives a colour to deliver and drop and the hatch to each other kind", () => {
    expect(outcomeKnown("deliver")).toBe(true);
    expect(outcomeKnown("drop")).toBe(true);
    expect(outcomeKnown("unknown")).toBe(false);
    expect(outcomeKnown("loop")).toBe(false);
  });
});

describe("QoS values", () => {
  it("knows a known value, unset and none, and not an unknown, varying, original or range value", () => {
    expect(qosShown({ known: 3 })).toEqual({ known: true, text: "3" });
    expect(qosShown("unset")).toEqual({ known: true, text: "unset" });
    expect(qosShown("none")).toEqual({ known: true, text: "none" });
    expect(qosShown({ value: { known: 46 } })).toEqual({ known: true, text: "46" });
    expect(qosShown("unknown").known).toBe(false);
    expect(qosShown("varies").known).toBe(false);
    expect(qosShown({ value: "unknown" }).known).toBe(false);
    expect(qosShown({ value: "original" }).known).toBe(false);
    expect(qosShown({ value: { in: [[0, 63]] } })).toEqual({ known: false, text: "0-63" });
  });
});

describe("delay and rate", () => {
  it("shows a lower bound of the delay as not known, with its gaps", () => {
    expect(delayShown({ known_ns: 1200, lower_bound: false, missing: [] })).toEqual({ known: true, text: "1200 ns" });
    const d = delayShown({
      known_ns: 1200,
      lower_bound: true,
      missing: [
        { kind: "function", function: "r1/acl" },
        { kind: "link", function: "r1/out" },
      ],
    });
    expect(d).toEqual({ known: false, text: "at least 1200 ns: 1 functions and 1 links have no delay data" });
  });

  it("shows a rate condition with no rate as not known", () => {
    const rc = { function: "r1/policer", exceed_action: "drop", evaluated: false };
    expect(rateShown({ ...rc, rate_bps: null })).toEqual({ action: "drop", rate: { known: false, text: "rate not known" } });
    expect(rateShown({ ...rc, rate_bps: 1000 })).toEqual({ action: "drop", rate: { known: true, text: "1000 bps" } });
  });
});

describe("source spans of the opened row", () => {
  it("lists each span once, with the device prefix left out", () => {
    const step = (spans: [number, number][]) =>
      ({
        device: "leaf1",
        provenance: spans.map(([a, b]) => ({ file: "leaf1.conf", first_line: a, last_line: b })),
      }) as unknown as TraceStep;
    expect(detailSpans([step([[100, 108], [12, 12]]), step([[100, 108]])])).toEqual(["conf:100-108", "conf:12"]);
  });
});
