/// <reference types="node" />
// The paths of an answer: the card Paths on the stored answers with
// equal-cost paths, on a generated answer with 64 paths and on a flood of
// 500 copies, the outcomes with their counts, the filter and the path strip.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Answer, Branch, PathAnswer, TraceStep } from "../src/api/types";
import { ladder } from "../src/ladder/layout";
import { deviceSite, forwardPaths, pathIndex, replyPaths, selectedPath, stripOf, tally, withKind } from "../src/ladder/paths";

function golden(name: string): PathAnswer {
  const url = new URL(`../../crates/rsim-cli/tests/golden/${name}.json`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as PathAnswer;
}

/** The steps of a branch moved to other devices: `rename` gives the new name of each device. */
function moved(steps: readonly TraceStep[], rename: (d: string) => string): TraceStep[] {
  return steps.map((s) => {
    const d = s.device ?? null;
    if (!d) return s;
    const n = rename(d);
    return { ...s, device: n, function: `${n}${s.function.slice(d.length)}` };
  });
}

/**
 * An answer with `n` equal-cost paths over the middle device of the first
 * path of the stored answer ecmp: path i goes over `spine-<i>`, and each
 * fourth path drops.
 */
function wide(n: number): Answer {
  const a = golden("ecmp").answer;
  const base = a.branches[0]!;
  const drop = a.branches[1]!;
  const branches: Branch[] = Array.from({ length: n }, (_, i) => {
    const spine = `spine-${String(i + 1).padStart(2, "0")}`;
    const b = i % 4 === 3 ? drop : base;
    return { ...b, index: i, steps: moved(b.steps, (d) => (d === "r2" || d === "r3" ? spine : d)) };
  });
  return { ...a, branches, replies: [], summary: [{ ...a.summary[0]!, result: { kind: "depends_on_path", verdict: null, verdict_kind: null } }] };
}

/** An answer whose one forward path floods to `n` ports of a switch, each copy a branch. */
function flood(n: number): Answer {
  const a = golden("ecmp").answer;
  const base = a.branches[0]!;
  const branches: Branch[] = Array.from({ length: n }, (_, i) => {
    const steps = base.steps.map((s, j) =>
      j === base.steps.length - 1 ? { ...s, flood_copy: { flood: "sw-01/flood", port: `port/${i + 1}`, index: i, count: n } } : s,
    );
    return { ...base, index: i, steps, verdict: { kind: "deliver", destination: { endpoint: `host-${i + 1}`, device: null }, reason: null } };
  });
  return { ...a, branches, replies: [] };
}

describe("the paths of ecmp", () => {
  const a = golden("ecmp").answer;
  const p = forwardPaths(a);

  it("has one path for each branch, numbered from 1, with its devices in path order and its outcome", () => {
    expect(p.map((x) => [x.number, x.devices, x.verdict.kind])).toEqual([
      ["1", ["r1", "r2", "r4"], "deliver"],
      ["2", ["r1", "r3"], "drop"],
    ]);
    expect(p[1]!.at?.step.device).toBe("r3");
  });

  it("counts each outcome that occurs, and a click on one filters the paths", () => {
    expect(tally(p.map((x) => x.verdict.kind))).toEqual([
      ["deliver", 1],
      ["drop", 1],
    ]);
    expect(withKind(p, "drop").map((x) => x.number)).toEqual(["2"]);
    expect(withKind(p, null)).toHaveLength(2);
  });

  it("selects path 1, and the first path that the filter keeps", () => {
    expect(selectedPath(p, null)).toEqual({ replyOf: null, branch: 0 });
    expect(selectedPath(withKind(p, "drop"), { replyOf: null, branch: 0 })).toEqual({ replyOf: null, branch: 1 });
    expect(selectedPath([], null)).toBeNull();
  });

  it("draws the lanes and the strip of the selected path", () => {
    expect(ladder(a, "function", p[1]!.ref).lanes.map((l) => l.name)).toEqual(["r1", "r3"]);
    const s = stripOf(a, p[1]!.ref)!;
    expect(s.nodes.map((x) => x.name)).toEqual(["10.1.0.10", "r1", "r3"]);
    expect(s.end).toBe("drop");
    expect(s.atEndpoint).toBe(false);
  });

  it("gives each device of the strip its site", () => {
    const s = stripOf(a, p[1]!.ref, (d) => (d === "r1" ? "site-a" : null))!;
    expect(s.nodes.filter((x) => x.kind === "device")).toEqual([
      { kind: "device", name: "r1", site: "site-a" },
      { kind: "device", name: "r3", site: null },
    ]);
  });
});

describe("the site of a device", () => {
  const sites = new Map([
    ["core-01", "site-a"],
    ["console-01", "site-b"],
  ]);
  const store = new Map([["ap-01", "console-01"]]);

  it("takes the inventory device of the same name, else of the store device", () => {
    expect(deviceSite("core-01", sites, store)).toBe("site-a");
    expect(deviceSite("ap-01", sites, store)).toBe("site-b");
    expect(deviceSite("edge-01", sites, store)).toBeNull();
  });
});

describe("the paths of leaf-spine", () => {
  const a = golden("leaf-spine").answer;

  it("has a path over each spine and the reply paths of each forward path", () => {
    expect(forwardPaths(a).map((x) => x.devices)).toEqual([
      ["leaf1", "spine1", "leaf2"],
      ["leaf1", "spine2", "leaf2"],
    ]);
    expect(replyPaths(a, 1).map((x) => [x.number, x.ref])).toEqual([
      ["2.1", { replyOf: 1, branch: 0 }],
      ["2.2", { replyOf: 1, branch: 1 }],
    ]);
    expect(replyPaths(a)).toHaveLength(4);
  });

  it("starts the strip at the source endpoint and ends it at the destination endpoint, with their addresses", () => {
    const s = stripOf(a, { replyOf: null, branch: 0 })!;
    expect(s.nodes).toEqual([
      { kind: "endpoint", name: "host1", address: "10.1.0.10", end: false },
      { kind: "device", name: "leaf1", site: null },
      { kind: "device", name: "spine1", site: null },
      { kind: "device", name: "leaf2", site: null },
      { kind: "endpoint", name: "host2", address: "10.2.0.10", end: true },
    ]);
    const r = stripOf(a, { replyOf: 0, branch: 1 })!;
    expect(r.nodes.map((x) => x.name)).toEqual(["host2", "leaf2", "spine2", "leaf1", "host1"]);
  });
});

describe("an answer with 64 paths", () => {
  const a = wide(64);
  const p = forwardPaths(a);

  it("has 64 paths in the order of the answer, each with its own devices", () => {
    expect(p).toHaveLength(64);
    expect(p[63]!.number).toBe("64");
    expect(p[63]!.devices).toEqual(["r1", "spine-64"]);
    expect(new Set(p.map((x) => x.devices[1])).size).toBe(64);
  });

  it("counts 48 paths that deliver and 16 that drop, and filters to the 16", () => {
    expect(tally(p.map((x) => x.verdict.kind))).toEqual([
      ["deliver", 48],
      ["drop", 16],
    ]);
    const drops = withKind(p, "drop");
    expect(drops.map((x) => x.number).slice(0, 2)).toEqual(["4", "8"]);
    expect(pathIndex(drops, { replyOf: null, branch: 7 })).toBe(1);
  });

  it("has the lanes of the selected path only", () => {
    expect(ladder(a, "function", p[40]!.ref).lanes.map((l) => l.name)).toEqual(["r1", "spine-41", "r4"]);
  });
});

describe("a flood of 500 copies", () => {
  const a = flood(500);
  const p = forwardPaths(a);

  it("has one row for each copy, with the endpoint of the copy", () => {
    expect(p).toHaveLength(500);
    expect(p[499]!.verdict.destination?.endpoint).toBe("host-500");
    expect(tally(p.map((x) => x.verdict.kind))).toEqual([["deliver", 500]]);
    expect(a.branches[499]!.steps.at(-1)!.flood_copy).toEqual({ flood: "sw-01/flood", port: "port/500", index: 499, count: 500 });
  });
});
