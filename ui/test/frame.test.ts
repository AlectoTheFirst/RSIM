// The frame of the page: the views of the rail, the run of the top bar,
// the toast and the window of the virtual rows.
import { afterEach, describe, expect, it } from "vitest";
import type { TwinRef } from "../src/api/client";
import { RAIL_BOTTOM, RAIL_TOP, ageText, lastCycle, menuMove, ofStore, runOptions, runState, runTime, snapshotTime, utcText } from "../src/page/frame";
import { dismiss, subscribe, toast, type ToastNote } from "../src/page/notes";
import { functionsSearch, queryOf, topologySearch, viewOf, viewSearch } from "../src/page/url";
import { indexAt, measuredWindow, moveCurrent, offsetsOf, rowWindow, scrollForOffsets } from "../src/page/virtual";

const store = (over: Partial<TwinRef> = {}): TwinRef => ({ id: "store", href: "/v1/twins/store", ...over });

describe("the views of the rail", () => {
  it("lists Trace, Topology, Tables and Coverage at the top and Inventory at the bottom", () => {
    expect(RAIL_TOP).toEqual(["Trace", "Topology", "Tables", "Coverage"]);
    expect(RAIL_BOTTOM).toEqual(["Inventory"]);
  });

  it("keeps the query for the view Trace only", () => {
    expect(viewSearch("Trace", "t1", "", "qabc")).toBe("?twin=t1&q=qabc");
    expect(viewSearch("Topology", "t1", "", "qabc")).toBe("?view=topology&twin=t1");
  });

  it("reads and writes the view topology with the query of Show in topology", () => {
    expect(viewOf("?view=topology&twin=t1")).toBe("Topology");
    expect(topologySearch("t1", "qabc")).toBe("?view=topology&twin=t1&q=qabc");
    expect(viewSearch("Topology", "t1")).toBe("?view=topology&twin=t1");
    expect(queryOf("?view=topology&twin=t1&q=qabc")).toBe("qabc");
    expect(queryOf("?view=topology")).toBeNull();
  });

  it("opens the table functions of a device", () => {
    expect(functionsSearch("t1", "core-01")).toBe("?view=tables&twin=t1&table=functions&f.device=core-01");
  });
});

describe("the run of the top bar", () => {
  it("reads the UTC second of a snapshot name", () => {
    expect(snapshotTime("snapshot-2026-11-02-081500")).toBe(Date.UTC(2026, 10, 2, 8, 15, 0));
    expect(snapshotTime("snap-4")).toBeNull();
    expect(snapshotTime(null)).toBeNull();
  });

  it("prints a time in UTC to the second", () => {
    expect(utcText(Date.UTC(2026, 10, 2, 8, 15, 9))).toBe("2026-11-02 08:15:09 UTC");
  });

  it("takes the snapshot time of the twin before the time of its name", () => {
    expect(runTime("snapshot-2026-11-02-081500", "2026-11-02T08:15:00Z")).toBe(Date.UTC(2026, 10, 2, 8, 15, 0));
    expect(runTime("snapshot-2026-11-02-081500", null)).toBe(Date.UTC(2026, 10, 2, 8, 15, 0));
    expect(runTime("builtin.leaf-spine", null)).toBeNull();
    expect(runTime("snap-4", 670)).toBeNull();
  });

  it("marks the newest built run and an older run", () => {
    const twins = [store({ held: "snapshot-2026-11-02-090000" })];
    expect(runState(twins, "snapshot-2026-11-02-090000")).toBe("newest");
    expect(runState(twins, "store")).toBe("newest");
    expect(runState(twins, "snapshot-2026-11-02-080000")).toBe("older");
    expect(runState(twins, "builtin.leaf-spine")).toBeNull();
    expect(runState([store()], "store")).toBeNull();
  });

  it("offers the held and the previous snapshot of the store and the other twins", () => {
    const twins = [store({ held: "snapshot-2026-11-02-090000", previous: "snapshot-2026-11-02-080000" }), { id: "builtin.leaf-spine", href: "" }];
    const { options, chosen } = runOptions(twins, "store");
    expect(options).toEqual([
      { id: "snapshot-2026-11-02-090000", time: Date.UTC(2026, 10, 2, 9, 0, 0), state: "newest" },
      { id: "snapshot-2026-11-02-080000", time: Date.UTC(2026, 10, 2, 8, 0, 0), state: "older" },
      { id: "builtin.leaf-spine", time: null, state: null },
    ]);
    expect(chosen).toBe("snapshot-2026-11-02-090000");
    expect(runOptions(twins, "snapshot-2026-11-02-080000").chosen).toBe("snapshot-2026-11-02-080000");
  });

  it("offers the alias store before the first build", () => {
    expect(runOptions([store()], "store")).toEqual({ options: [{ id: "store", time: null, state: null }], chosen: "store" });
  });

  it("names a run of the store a snapshot", () => {
    const twins = [store({ held: "run-2", previous: "run-1" }), { id: "builtin.leaf-spine", href: "" }];
    expect(["store", "run-2", "run-1", "snapshot-2026-11-02-090000", "builtin.leaf-spine"].map((t) => ofStore(twins, t))).toEqual([true, true, true, true, false]);
  });

  it("takes the time of the last cycle from the newest snapshot of the store", () => {
    expect(lastCycle([store({ newest: "snapshot-2026-11-02-090000" })])).toBe(Date.UTC(2026, 10, 2, 9, 0, 0));
    expect(lastCycle([store({ newest: "snap-7" })])).toBeNull();
    expect(lastCycle([])).toBeNull();
  });

  it("prints an age in seconds, minutes, hours or days", () => {
    expect(ageText(57_400)).toBe("57 s ago");
    expect(ageText(-5_000)).toBe("0 s ago");
    expect(ageText(12 * 60_000)).toBe("12 min ago");
    expect(ageText(3 * 3_600_000)).toBe("3 h ago");
    expect(ageText(72 * 3_600_000)).toBe("3 d ago");
  });

  it("moves the focus of a menu round its items", () => {
    expect(menuMove("ArrowDown", -1, 3)).toBe(0);
    expect(menuMove("ArrowDown", 2, 3)).toBe(0);
    expect(menuMove("ArrowUp", 0, 3)).toBe(2);
    expect(menuMove("End", 0, 3)).toBe(2);
    expect(menuMove("a", 0, 3)).toBeNull();
    expect(menuMove("ArrowDown", -1, 0)).toBeNull();
  });
});

describe("the toast", () => {
  let stop: (() => void) | null = null;
  afterEach(() => stop?.());

  it("shows the newest note, and the end of an older note leaves the newest note", () => {
    const seen: (ToastNote | null)[] = [];
    stop = subscribe((n) => seen.push(n));
    const a = toast("row copied");
    const b = toast("rsim command copied");
    dismiss(a.id);
    expect(seen.at(-1)?.text).toBe("rsim command copied");
    dismiss(b.id);
    expect(seen.at(-1)).toBeNull();
  });
});

describe("the virtual rows", () => {
  it("draws the rows in view of 50,000 rows of a fixed height with the overscan", () => {
    const w = rowWindow({ top: 32 * 25_000, height: 320, h: 32, count: 50_000, open: null, openH: 0, overscan: 2 });
    expect([w.first, w.end]).toEqual([24_998, 25_013]);
    expect(w.padTop).toBe(24_998 * 32);
    expect(w.padTop + (w.end - w.first) * 32 + w.padBottom).toBe(50_000 * 32);
  });

  it("places measured rows by their heights and the others by the estimate", () => {
    const heights = new Map([
      [0, 20],
      [1, 60],
    ]);
    const o = offsetsOf(4, (i) => heights.get(i), 32);
    expect([...o]).toEqual([0, 20, 80, 112, 144]);
    expect(indexAt(o, 0)).toBe(0);
    expect(indexAt(o, 79)).toBe(1);
    expect(indexAt(o, 80)).toBe(2);
    expect(indexAt(o, 1000)).toBe(3);
    const w = measuredWindow({ top: 30, height: 40, offsets: o, overscan: 0 });
    expect([w.first, w.end, w.padTop, w.padBottom]).toEqual([1, 2, 20, 64]);
    const v = measuredWindow({ top: 30, height: 60, offsets: o, overscan: 0 });
    expect([v.first, v.end, v.padTop, v.padBottom]).toEqual([1, 3, 20, 32]);
  });

  it("gives no rows for an empty list", () => {
    expect(measuredWindow({ top: 0, height: 100, offsets: offsetsOf(0, () => undefined, 32) })).toEqual({ first: 0, end: 0, padTop: 0, padBottom: 0 });
  });

  it("scrolls a measured row into view, its top first when it is higher than the view", () => {
    const o = offsetsOf(3, (i) => [20, 200, 20][i], 32);
    expect(scrollForOffsets(0, 0, 100, o)).toBeNull();
    expect(scrollForOffsets(1, 0, 100, o)).toBe(20);
    expect(scrollForOffsets(2, 0, 100, o)).toBe(140);
    expect(scrollForOffsets(0, 50, 100, o)).toBe(0);
  });

  it("moves the current row by one, by a view and to the ends", () => {
    expect(moveCurrent("ArrowDown", null, 10, 4)).toBe(0);
    expect(moveCurrent("ArrowUp", null, 10, 4)).toBe(9);
    expect(moveCurrent("ArrowDown", 9, 10, 4)).toBe(9);
    expect(moveCurrent("PageDown", 2, 10, 4)).toBe(6);
    expect(moveCurrent("PageUp", 2, 10, 4)).toBe(0);
    expect(moveCurrent("End", 0, 10, 4)).toBe(9);
    expect(moveCurrent("Home", 5, 10, 4)).toBe(0);
    expect(moveCurrent("j", 5, 10, 4)).toBeNull();
    expect(moveCurrent("ArrowDown", null, 0, 4)).toBeNull();
  });
});
