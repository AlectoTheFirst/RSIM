/// <reference types="node" />
// The layout of the set ladder on the stored set answer of the CLI tests.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { SetAnswer } from "../src/api/types";
import { setLadder } from "../src/ladder/setLayout";

const url = new URL("../../crates/rsim-cli/tests/golden/set-mini-enterprise.json", import.meta.url);
const a = (JSON.parse(readFileSync(url, "utf8")) as SetAnswer).answer;

describe("the set ladder of mini-enterprise", () => {
  const l = setLadder(a, "function");

  it("heads each part column with the fields in which the parts differ", () => {
    expect(l.heads).toEqual([
      [
        ["source.port", "0-1023"],
        ["destination.port", "53"],
      ],
      [
        ["source.port", "1024-65535"],
        ["destination.port", "53"],
      ],
      [
        ["source.port", "0-65535"],
        ["destination.port", "80"],
      ],
    ]);
  });

  it("follows the longest branch", () => {
    expect(l.rows.length).toBe(21);
    expect(l.rows[0]!.start).toBe(true);
  });

  it("ends each part at the function that decides it", () => {
    const ends = l.rows.flatMap((r, i) =>
      r.cells.map((c, p) => (c.kind === "end" ? [p, i, c.end] : null)).filter((x) => x !== null),
    );
    expect(ends).toEqual([
      [2, 7, "drop"],
      [0, 13, "drop"],
      [1, 20, "deliver"],
    ]);
  });

  it("has a band before the end and nothing after it", () => {
    expect(l.rows[6]!.cells.map((c) => c.kind)).toEqual(["band", "band", "band"]);
    expect(l.rows[8]!.cells.map((c) => c.kind)).toEqual(["band", "band", "none"]);
    expect(l.rows[14]!.cells.map((c) => c.kind)).toEqual(["none", "band", "none"]);
  });

  it("counts the parts of each row for the width of the path line", () => {
    expect([l.rows[0]!.parts, l.rows[8]!.parts, l.rows[14]!.parts]).toEqual([3, 2, 1]);
  });

  it("ends the parts of a device in the row of the device at the device level", () => {
    const d = setLadder(a, "device");
    expect(d.rows.map((r) => r.label)).toEqual(["0-11", "12-14", "15-20"]);
    expect(d.rows.map((r) => r.cells.map((c) => c.kind))).toEqual([
      ["band", "band", "end"],
      ["end", "band", "none"],
      ["none", "end", "none"],
    ]);
  });
});
