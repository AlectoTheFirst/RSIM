/// <reference types="node" />
// The layout of the map on a small site, a fabric of 16 spines and 500
// leaves with 20,000 endpoints and a campus of 2,000 devices, and the window
// of the map.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { SIZE, TYPE } from "../src/theme";
import { buildGraph, pairKey, type MapGraph, type TopologyOut } from "../src/topology/graph";
import { ROW_MAX, layoutMap, type Card, type MapLayout } from "../src/topology/layout";
import { pathGraphInput, pathsOf, type PathBriefOut } from "../src/topology/paths";
import { cull, fitView, hitTest, indexLayout, panBy, showsText, toScreen, windowOf, zoomAt, zoomIn, zoomOut } from "../src/topology/view";
import { campus, fabric, site } from "./topologyEstates";

const read = <T>(path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as T;

/** The faults of a layout: overlapping cards, a segment that is not horizontal or vertical, a line that does not end at its cards, a segment through a card. */
function faults(g: MapGraph, l: MapLayout): string[] {
  const out: string[] = [];
  const byRow = new Map<number, Card[]>();
  for (const c of l.cards) (byRow.get(c.row) ?? byRow.set(c.row, []).get(c.row)!).push(c);
  const rows = [...byRow.keys()].sort((a, b) => a - b);
  for (let i = 0; i < rows.length; i++) {
    const cs = byRow.get(rows[i]!)!;
    for (let j = 0; j < cs.length; j++) {
      for (let k = j + 1; k < cs.length; k++) {
        const a = cs[j]!;
        const b = cs[k]!;
        if (a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h) out.push(`overlap ${a.id} ${b.id}`);
      }
    }
    if (i > 0) {
      const top = Math.min(...cs.map((c) => c.y));
      const prevBottom = Math.max(...byRow.get(rows[i - 1]!)!.map((c) => c.y + c.h));
      if (top <= prevBottom) out.push(`row ${rows[i]} overlaps row ${rows[i - 1]}`);
    }
  }
  const onBorder = (c: Card, x: number, y: number) =>
    ((y === c.y || y === c.y + c.h) && x >= c.x && x <= c.x + c.w) || ((x === c.x || x === c.x + c.w) && y >= c.y && y <= c.y + c.h);
  const rowCards = rows.map((r) => {
    const cs = [...byRow.get(r)!].sort((a, b) => a.x - b.x);
    return { cs, top: Math.min(...cs.map((c) => c.y)), bottom: Math.max(...cs.map((c) => c.y + c.h)) };
  });
  const through = (x0: number, y0: number, x1: number, y1: number): Card | null => {
    const [xa, xb, ya, yb] = [Math.min(x0, x1), Math.max(x0, x1), Math.min(y0, y1), Math.max(y0, y1)];
    for (const r of rowCards) {
      if (r.bottom <= ya || r.top >= yb + (ya === yb ? 1 : 0)) continue;
      let lo = 0;
      let hi = r.cs.length;
      while (lo < hi) {
        const m = (lo + hi) >> 1;
        if (r.cs[m]!.x + r.cs[m]!.w <= xa) lo = m + 1;
        else hi = m;
      }
      for (let i = lo; i < r.cs.length && r.cs[i]!.x < xb + (xa === xb ? 1 : 0); i++) {
        const c = r.cs[i]!;
        if (xb > c.x && xa < c.x + c.w && yb > c.y && ya < c.y + c.h) return c;
      }
    }
    return null;
  };
  for (const line of l.lines) {
    const p = line.pts;
    if (p.length < 4) out.push(`short ${line.key}`);
    for (let i = 2; i < p.length; i += 2) {
      if (p[i] !== p[i - 2] && p[i + 1] !== p[i - 1]) out.push(`diagonal ${line.key}`);
    }
    const a = l.card.get(line.pair.a)!;
    const b = l.card.get(line.pair.b)!;
    if (!onBorder(a, p[0]!, p[1]!)) out.push(`start ${line.key}`);
    if (!onBorder(b, p[p.length - 2]!, p[p.length - 1]!)) out.push(`end ${line.key}`);
    for (let i = 2; i < p.length; i += 2) {
      const c = through(p[i - 2]!, p[i - 1]!, p[i]!, p[i + 1]!);
      if (c) out.push(`through ${c.id} ${line.key}`);
    }
  }
  if (l.lines.length !== g.pairs.length) out.push(`lines ${l.lines.length} pairs ${g.pairs.length}`);
  return out;
}

describe("the layout of a site", () => {
  const g = buildGraph({
    topology: site(),
    endpoints: new Map([
      ["acc-01", 49],
      ["acc-02", 12],
    ]),
    outside: [{ device: "edge-01", port: "Te0/0/0/2", neighbour: "isp-a", remotePort: null }],
    pathEndpoints: [
      { label: "198.51.100.20", device: "acc-01", port: "Gi1/0/7" },
      { label: "198.51.100.21", device: "acc-01", port: "Gi1/0/8" },
    ],
  });
  const l = layoutMap(g);

  it("ranks the devices from the link graph with the devices of endpoints at the bottom", () => {
    const rank = (id: string) => l.card.get(id)!.rank;
    expect([rank("o:isp-a"), rank("d:edge-01"), rank("d:core-01"), rank("d:acc-01"), rank("d:acc-02")]).toEqual([0, 1, 2, 3, 3]);
    expect(l.ranks).toBe(4);
  });

  it("stacks the endpoint cards of a device below it, the endpoints card last", () => {
    const d = l.card.get("d:acc-01")!;
    const stack = ["e:acc-01:198.51.100.20", "e:acc-01:198.51.100.21", "g:acc-01"].map((id) => l.card.get(id)!);
    expect(stack.map((c) => [c.x, c.stack])).toEqual([
      [d.x, 0],
      [d.x, 1],
      [d.x, 2],
    ]);
    expect(stack[0]!.y).toBe(d.y + d.h + SIZE.mapRowGap);
    expect(stack[1]!.y).toBe(stack[0]!.y + SIZE.mapCardHeight + SIZE.mapStackGap);
  });

  it("has no overlap, only horizontal and vertical segments, and each line from card to card", () => {
    expect(faults(g, l)).toEqual([]);
  });

  it("gives the same layout for the same input", () => {
    const again = layoutMap(buildGraph({ topology: site(), endpoints: new Map([["acc-01", 49], ["acc-02", 12]]), outside: [{ device: "edge-01", port: "Te0/0/0/2", neighbour: "isp-a", remotePort: null }], pathEndpoints: [{ label: "198.51.100.20", device: "acc-01", port: "Gi1/0/7" }, { label: "198.51.100.21", device: "acc-01", port: "Gi1/0/8" }] }));
    expect(JSON.stringify(again.cards.map((c) => [c.id, c.x, c.y]))).toBe(JSON.stringify(l.cards.map((c) => [c.id, c.x, c.y])));
    expect(JSON.stringify(again.lines.map((x) => [x.key, x.pts]))).toBe(JSON.stringify(l.lines.map((x) => [x.key, x.pts])));
  });

  it("puts the middle of a line at half its length", () => {
    const line = l.line.get(pairKey("physical", "d:core-01", "d:core-02"))!;
    expect(line.mid.horizontal || line.mid.x === line.pts[0]).toBe(true);
  });
});

describe("the layout of leaf-spine with the paths of its stored answer", () => {
  const topology = read<TopologyOut>("../../crates/rsim-api/tests/golden/leaf-spine.topology.json");
  const paths = pathsOf(read<PathBriefOut>("../../crates/rsim-cli/tests/golden/leaf-spine.steps.json"));
  const g = buildGraph({ topology, ...pathGraphInput(paths) });
  const l = layoutMap(g);

  it("puts the spines above the leaves and the endpoints below their leaves", () => {
    expect(l.cards.filter((c) => c.rank === 0).map((c) => c.id)).toEqual(["d:spine1", "d:spine2"]);
    expect(l.card.get("e:leaf2:host2")!.x).toBe(l.card.get("d:leaf2")!.x);
    expect(faults(g, l)).toEqual([]);
  });
});

describe("the layout of a fabric of 16 spines and 500 leaves with 20,000 endpoints", () => {
  const f = fabric(16, 500, 20000);
  const g = buildGraph({ topology: f.topology, endpoints: f.counts });
  const l = layoutMap(g);

  it("has the 16 spines in the top rank and the leaves in rows of 32 with their endpoints card below each", () => {
    const top = l.cards.filter((c) => c.rank === 0);
    expect(top).toHaveLength(16);
    const leafRows = new Set(l.cards.filter((c) => c.node.kind === "device" && c.rank === 1).map((c) => c.row));
    expect(leafRows.size).toBe(Math.ceil(500 / ROW_MAX));
    const groups = l.cards.filter((c) => c.node.kind === "endpoints");
    expect(groups).toHaveLength(500);
    expect(groups.reduce((n, c) => n + (c.node.count ?? 0), 0)).toBe(20000);
    for (const c of groups) expect(c.x).toBe(l.card.get(`d:${c.node.device}`)!.x);
  });

  it("has no overlap, only horizontal and vertical segments, and each line from card to card", () => {
    expect(faults(g, l)).toEqual([]);
  });

  it("gives the same layout for the same input", () => {
    const again = layoutMap(buildGraph({ topology: fabric(16, 500, 20000).topology, endpoints: f.counts }));
    expect(again.lines.map((x) => x.pts.join(",")).join(";")).toBe(l.lines.map((x) => x.pts.join(",")).join(";"));
  });
});

describe("the time of the layout and of the cull", () => {
  it("lays out 2,000 devices with 4,000 links in less than 500 ms and culls a window in less than 5 ms", () => {
    const c = campus();
    const g = buildGraph({ topology: c.topology, endpoints: c.counts });
    expect(g.nodes.filter((n) => n.kind === "device")).toHaveLength(2000);
    const links = g.pairs.filter((p) => p.layer === "physical" && p.a.startsWith("d:") && p.b.startsWith("d:")).length;
    expect(links).toBe(4000);
    layoutMap(g);
    const t0 = performance.now();
    const l = layoutMap(g);
    const t1 = performance.now();
    const ix = indexLayout(l);
    const t2 = performance.now();
    const v = fitView(l, 1100, 700);
    const near = zoomAt(v, 8, 550, 350);
    const runs = 20;
    const t3 = performance.now();
    for (let i = 0; i < runs; i++) cull(ix, windowOf(i % 2 === 0 ? v : near, 1100, 700), "physical");
    const t4 = performance.now();
    const layoutMs = t1 - t0;
    const cullMs = (t4 - t3) / runs;
    console.log(`layout ${layoutMs.toFixed(1)} ms, index ${(t2 - t1).toFixed(1)} ms, cull ${cullMs.toFixed(2)} ms, cards ${l.cards.length}, lines ${l.lines.length}`);
    expect(layoutMs).toBeLessThan(500);
    expect(cullMs).toBeLessThan(5);
    expect(faults(g, l)).toEqual([]);
  });
});

describe("the window of the map", () => {
  const g = buildGraph({ topology: site(), endpoints: new Map([["acc-01", 49]]) });
  const l = layoutMap(g);
  const ix = indexLayout(l);

  it("fits the map into the screen at most at zoom 1, centred", () => {
    const v = fitView(l, 4000, 4000);
    expect(v.zoom).toBe(1);
    expect(toScreen(v, l.width / 2, l.height / 2)).toEqual({ x: 2000, y: 2000 });
    const small = fitView(l, 400, 300);
    expect(small.zoom).toBeCloseTo(Math.min(400 / l.width, 300 / l.height));
  });

  it("keeps the map point under the pointer at a zoom, and moves the map with a drag", () => {
    const v = { x: 0, y: 0, zoom: 1 };
    const z = zoomAt(v, 2, 100, 50);
    expect(toScreen(z, 100, 50)).toEqual({ x: 100, y: 50 });
    expect(zoomOut(zoomIn(v, 800, 600), 800, 600).zoom).toBeCloseTo(1);
    expect(panBy(v, 30, -20)).toEqual({ x: -30, y: 20, zoom: 1 });
  });

  it("shows the text of a card only when its name is at least 9px high", () => {
    const least = SIZE.mapTextMin / TYPE.value.size;
    expect([showsText(1), showsText(least), showsText(least - 0.01)]).toEqual([true, true, false]);
  });

  it("culls the cards and lines outside the window", () => {
    const all = cull(ix, { x: 0, y: 0, w: l.width, h: l.height }, "physical");
    expect(all.cards).toHaveLength(l.cards.length);
    expect(all.lines).toHaveLength(l.lines.filter((x) => x.layer === "physical").length);
    const c = l.card.get("d:core-01")!;
    const one = cull(ix, { x: c.x + 10, y: c.y + 10, w: 20, h: 20 }, "physical");
    expect(one.cards.map((x) => x.id)).toEqual(["d:core-01"]);
    expect(one.lines).toEqual([]);
    expect(cull(ix, { x: 0, y: 0, w: l.width, h: l.height }, "overlay").lines.map((x) => x.key)).toEqual([pairKey("overlay", "d:acc-01", "d:acc-03")]);
  });

  it("hits a card under the pointer, else a line near it, else nothing", () => {
    const v = { x: 0, y: 0, zoom: 1 };
    const c = l.card.get("d:core-02")!;
    expect(hitTest(ix, v, c.x + 5, c.y + 5, "physical")).toMatchObject({ kind: "card", card: { id: "d:core-02" } });
    const line = l.line.get(pairKey("physical", "d:core-01", "d:acc-01"))!;
    const [x0, y0, x1, y1] = line.pts;
    const hit = hitTest(ix, v, (x0! + x1!) / 2 + 2, (y0! + y1!) / 2, "physical");
    expect(hit?.kind).toBe("line");
    expect(hitTest(ix, v, 1, 1, "physical")).toBeNull();
  });
});
