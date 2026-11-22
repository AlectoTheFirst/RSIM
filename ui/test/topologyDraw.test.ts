// The parts of the map drawing with no drawing code.
import { describe, expect, it } from "vitest";
import { SIZE } from "../src/theme";
import {
  CARD_LINES,
  TEXT_ZOOM,
  Collider,
  cardLines,
  countBox,
  devicePickParams,
  devicePicks,
  endpointRowsOf,
  exportParams,
  openView,
  panKey,
  panelLinks,
  pathData,
  speedBox,
  tagBox,
  textInset,
  wheelFactor,
  wrapName,
} from "../src/topology/draw";
import { type MapNode, buildGraph, deviceId, outsideId } from "../src/topology/graph";
import { type Line, layoutMap } from "../src/topology/layout";
import { ZOOM_STEP } from "../src/topology/view";
import { site } from "./topologyEstates";

const device = (label: string): MapNode => ({ id: deviceId(label), kind: "device", label, device: label, count: null, functions: 1, hatch: false });

describe("wrapName", () => {
  it("keeps a short name on one line", () => {
    expect(wrapName("core-01", 16)).toEqual(["core-01"]);
  });

  it("breaks after a separator and keeps each character", () => {
    const name = "dc1-fabric-leaf-0001.example";
    const lines = wrapName(name, 16);
    expect(lines.join("")).toBe(name);
    expect(lines.every((l) => l.length <= 16)).toBe(true);
    expect(lines[0]).toBe("dc1-fabric-leaf-");
  });

  it("breaks a name with no separator at the width", () => {
    expect(wrapName("abcdefghij", 4)).toEqual(["abcd", "efgh", "ij"]);
  });
});

describe("cardLines", () => {
  it("gives the name and the vendor of a device", () => {
    expect(cardLines(device("core-01"), "nxos")).toEqual([
      { text: "core-01", kind: "name" },
      { text: "nxos", kind: "sub" },
    ]);
  });

  it("leaves the vendor out when the name fills the card", () => {
    const long = "a".repeat(60);
    const lines = cardLines(device(long), "nxos");
    expect(lines.some((l) => l.kind === "sub")).toBe(false);
    expect(lines.map((l) => l.text).join("")).toBe(long);
  });

  it("fits each line of a name inside the card", () => {
    const n = { ...device("x".repeat(40)), hatch: true };
    const room = SIZE.mapCard - textInset(n) - SIZE.mapCardPad;
    for (const l of cardLines(n, null)) expect(l.text.length * SIZE.valueChar).toBeLessThanOrEqual(room);
  });

  it("gives the number of an endpoints card", () => {
    const n: MapNode = { id: "g:leaf-01", kind: "endpoints", label: "", device: "leaf-01", count: 40, functions: null, hatch: false };
    expect(cardLines(n, null)).toEqual([{ text: "40 endpoints", kind: "name" }]);
    expect(cardLines({ ...n, count: 1 }, null)).toEqual([{ text: "1 endpoint", kind: "name" }]);
  });

  it("has room for the lines of a card", () => {
    expect(CARD_LINES * SIZE.mapCardLine).toBeLessThanOrEqual(SIZE.mapCardHeight);
  });
});

describe("tagBox", () => {
  it("puts a tag below a bottom end and above a top end, outside the card", () => {
    const below = tagBox({ x: 100, y: 48, side: "bottom" }, "Te1/0/1");
    expect(below.y).toBeGreaterThanOrEqual(48);
    const above = tagBox({ x: 100, y: 200, side: "top" }, "Te1/0/1");
    expect(above.y + above.h).toBeLessThanOrEqual(200);
    const left = tagBox({ x: 100, y: 24, side: "left" }, "eth0");
    expect(left.x + left.w).toBeLessThanOrEqual(100);
  });
});

describe("Collider", () => {
  it("places a box only where it overlaps no placed box", () => {
    const c = new Collider();
    expect(c.place({ x: 0, y: 0, w: 50, h: 18 })).toBe(true);
    expect(c.place({ x: 40, y: 10, w: 50, h: 18 })).toBe(false);
    expect(c.place({ x: 51, y: 0, w: 50, h: 18 })).toBe(true);
    expect(c.place({ x: 1000, y: 1000, w: 10, h: 10 })).toBe(true);
  });
});

describe("the labels at the middle of a line", () => {
  const line = (horizontal: boolean) => ({ mid: { x: 300, y: 200, horizontal } }) as unknown as Line;

  it("centres the number of links on the middle", () => {
    const b = countBox(line(false), 12);
    expect(b.x + b.w / 2).toBe(300);
    expect(b.y + b.h / 2).toBe(200);
  });

  it("puts the speed above a horizontal segment and at the right of a vertical one, clear of the number", () => {
    const up = speedBox(line(true), "10 Gbit/s", null);
    expect(up.y + up.h).toBeLessThan(200);
    const n = countBox(line(false), 4);
    const right = speedBox(line(false), "10 Gbit/s", n);
    expect(right.x).toBeGreaterThan(n.x + n.w);
  });
});

describe("panelLinks", () => {
  const g = buildGraph({ topology: site(), outside: [{ device: "edge-01", port: "Te0/0/0/9", neighbour: "isp-a", remotePort: null }] });

  it("gives one row for each link with the ports from the side of the card", () => {
    const rows = panelLinks(g, deviceId("core-01"), "physical");
    const toCore2 = rows.filter((r) => r.far === deviceId("core-02"));
    expect(toCore2.map((r) => [r.near, r.farPort, r.speed])).toEqual([
      ["Te1/0/47", "Te1/0/47", 10000],
      ["Te1/0/48", "Te1/0/48", 10000],
    ]);
    const toAcc1 = rows.find((r) => r.far === deviceId("acc-01"))!;
    expect(toAcc1.speed).toBeNull();
  });

  it("gives the tunnels of the overlay layer", () => {
    const rows = panelLinks(g, deviceId("acc-01"), "overlay");
    expect(rows.length).toBe(2);
    expect(rows.every((r) => r.far === deviceId("acc-03") && r.vnis === "50001")).toBe(true);
  });

  it("gives the links of a neighbour outside the twin", () => {
    const rows = panelLinks(g, outsideId("isp-a"), "physical");
    expect(rows).toEqual([{ far: deviceId("edge-01"), farLabel: "edge-01", near: null, farPort: "Te0/0/0/9", speed: null, vnis: null }]);
  });
});

describe("the requests", () => {
  it("asks the devices that start with the text of the Device field", () => {
    expect(devicePickParams(" leaf ", 50)).toEqual({ columns: "device,vendor", sort: "device", limit: "50", "device.prefix": "leaf" });
    expect(devicePickParams("", 100)["device.prefix"]).toBeUndefined();
  });

  it("reads each device once with its vendor", () => {
    const t = { columns: ["device", "vendor"], rows: [["leaf-01", "nxos"], ["leaf-01", "nxos"], ["leaf-02", null]] };
    expect(devicePicks(t)).toEqual([
      { name: "leaf-01", vendor: "nxos" },
      { name: "leaf-02", vendor: null },
    ]);
  });

  it("reads the endpoint rows by their columns", () => {
    const t = { columns: ["address", "host", "interface"], rows: [["192.0.2.10", "host-a", "Ethernet1/1"], ["192.0.2.11", null, ""]] };
    expect(endpointRowsOf(t)).toEqual([
      { host: "host-a", address: "192.0.2.10", interface: "Ethernet1/1" },
      { host: null, address: "192.0.2.11", interface: null },
    ]);
  });

  it("exports the scope of the map", () => {
    expect(exportParams({ kind: "twin" }, [], "graphml")).toEqual({ format: "graphml" });
    expect(exportParams({ kind: "device", device: "core-01", hops: 2 }, [], "d2")).toEqual({ around: "core-01", hops: "2", format: "d2" });
    expect(exportParams({ kind: "paths" }, ["leaf-10", "leaf-2"], "mermaid")).toEqual({ device: "leaf-2,leaf-10", format: "mermaid" });
  });
});

describe("the keys and the wheel", () => {
  it("pans by one step for each arrow key and ignores other keys", () => {
    expect(panKey("ArrowRight")).toEqual([-SIZE.mapPanStep, 0]);
    expect(panKey("ArrowUp")).toEqual([0, SIZE.mapPanStep]);
    expect(panKey("Enter")).toBeNull();
  });

  it("zooms one step in for 100 pixels up and out for 100 pixels down", () => {
    expect(wheelFactor(-100, 0)).toBeCloseTo(ZOOM_STEP);
    expect(wheelFactor(100, 0)).toBeCloseTo(1 / ZOOM_STEP);
    expect(wheelFactor(0, 0)).toBe(1);
  });
});

describe("pathData", () => {
  it("draws the points of a line", () => {
    expect(pathData([0, 0, 0, 40, 120, 40])).toBe("M0 0L0 40L120 40");
  });

  it("gives each line of a layout as horizontal and vertical segments", () => {
    const l = layoutMap(buildGraph({ topology: site() }));
    for (const line of l.lines) {
      for (let i = 2; i < line.pts.length; i += 2) {
        const dx = line.pts[i]! - line.pts[i - 2]!;
        const dy = line.pts[i + 1]! - line.pts[i - 1]!;
        expect(dx === 0 || dy === 0).toBe(true);
      }
    }
  });
});

describe("openView", () => {
  const layout = layoutMap(buildGraph({ topology: site() }));

  it("fits the whole map when its text shows", () => {
    const v = openView(layout, [], 4000, 4000);
    expect(v.zoom).toBeGreaterThanOrEqual(TEXT_ZOOM);
    expect(v.zoom).toBeLessThanOrEqual(1);
  });

  it("keeps the zoom at which text shows and centres the focus cards in a small window", () => {
    const id = deviceId("core-01");
    const c = layout.card.get(id)!;
    const v = openView(layout, [id], 300, 200);
    expect(v.zoom).toBeGreaterThanOrEqual(TEXT_ZOOM);
    const cx = (c.x + c.w / 2 - v.x) * v.zoom;
    const cy = (c.y + c.h / 2 - v.y) * v.zoom;
    expect(cx).toBeCloseTo(150);
    expect(cy).toBeCloseTo(100);
  });

  it("starts at the left and top edges of a map wider and higher than the window", () => {
    const v = openView(layout, [], 120, 80);
    expect(v.zoom).toBe(TEXT_ZOOM);
    expect(v.x).toBe(0);
    expect(v.y).toBe(0);
  });
});
