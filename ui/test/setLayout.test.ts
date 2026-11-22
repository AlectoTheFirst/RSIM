/// <reference types="node" />
// The parts of a set answer on the stored set answer of the CLI tests, the
// ladder of one part, the tunnel of an outer packet, the counts of the
// result line and the upright lane names.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Branch, Header, SetAnswer, TraceStep } from "../src/api/types";
import { ladder, upright } from "../src/ladder/layout";
import { outcomeOf, partAnswer, partFields, partList, tunnelOf } from "../src/ladder/setLayout";

const url = new URL("../../crates/rsim-cli/tests/golden/set-mini-enterprise.json", import.meta.url);
const a = (JSON.parse(readFileSync(url, "utf8")) as SetAnswer).answer;

describe("the parts of mini-enterprise", () => {
  const parts = partList(a);

  it("has one part for each branch, with each field in which it differs from the query", () => {
    expect(parts.map((p) => [p.branch, p.fields])).toEqual([
      [
        0,
        [
          ["source.port", "0-1023"],
          ["destination.port", "53"],
        ],
      ],
      [
        1,
        [
          ["source.port", "1024-65535"],
          ["destination.port", "53"],
        ],
      ],
      [2, [["destination.port", "80"]]],
    ]);
  });

  it("gives the outcome of each part: the destination, or the deciding step and the reason", () => {
    expect(parts.map((p) => [p.kind, p.place, p.at?.step.function ?? null, p.tunnel])).toEqual([
      ["drop", null, "fra01-ips-01/filter-1b-1a", null],
      ["deliver", "fra01-dns", null, null],
      ["drop", null, "fra01-fgt-01/policy", null],
    ]);
    expect(parts[0]!.reason).toBe(a.branches[0]!.verdict.reason!.detail);
    expect(parts[1]!.reason).toBeNull();
  });

  it("compares each header field over the members, the DSCP included", () => {
    const b = a.branches[1]!;
    const members = b.packets.members.map((m) => ({ ...m, original: { ...m.original, dscp: { known: 46 } } as Header }));
    expect(partFields(a.input, { members })).toContainEqual(["dscp", "46"]);
  });
});

describe("the ladder of one part", () => {
  const one = partAnswer(a, 1);

  it("holds the branch of the part with its index and its reply", () => {
    expect(one.branches.map((b) => b.index)).toEqual([1]);
    expect(one.replies.map((r) => r.forward_branch)).toEqual([1]);
  });

  it("prints a range as a value, with no hatch, at the function where the part splits off", () => {
    const l = ladder(one, "function", { replyOf: null, branch: 1 }, true);
    expect(l.rows[0]!.key).toBe(`f.1.${one.branches[0]!.steps[0]!.index}`);
    const split = l.rows.flatMap((r) => r.rewrites).find((w) => w.field === "source.port");
    expect(split?.after).toEqual({ known: true, text: "1024-65535" });
    const path = ladder(one, "function", { replyOf: null, branch: 1 });
    const p = path.rows.flatMap((r) => r.rewrites).find((w) => w.field === "source.port");
    expect(p?.after.known).toBe(false);
  });
});

/** A branch whose packets go into a WireGuard tunnel at step 2 and exit as outer packets. */
function wireguardBranch(): Branch {
  const base = a.branches[1]!;
  const wg = { kind: "wireguard", src: { known: "198.51.100.1" }, dst: { known: "203.0.113.9" }, vni: null, label: null };
  const withEncap = (ps: TraceStep["input"]) => ({
    members: ps.members.map((m) => ({ ...m, current: { ...m.current, encap: [wg] } as unknown as Header })),
  });
  const steps = base.steps.slice(0, 4).map((s, i) => ({
    ...s,
    device: "core1",
    function: i === 2 ? "core1/wireguard/wg44" : s.function,
    input: i > 2 ? withEncap(s.input) : s.input,
    output: i >= 2 ? withEncap(s.output) : s.output,
  }));
  return { ...base, steps, verdict: { kind: "exit", destination: null, reason: { code: "exited", detail: "core1 pppoe0" } } };
}

describe("tunnel of an outer packet", () => {
  it("names the encapsulation kind and the function that encapsulates", () => {
    const b = wireguardBranch();
    expect(tunnelOf(b)).toBe("WireGuard wg44");
    expect(outcomeOf(b)).toMatchObject({ kind: "exit", place: "core1 pppoe0", tunnel: "WireGuard wg44", reason: null });
  });

  it("is absent for a branch with no encapsulation at its end", () => {
    expect(tunnelOf(a.branches[1]!)).toBeNull();
  });
});

describe("lane names", () => {
  it("stand upright when a name is wider than its lane", () => {
    expect(upright(["core1", "unifi-01"], 52, 5)).toBe(false);
    expect(upright(["edge-sw-0012", "core1", "unifi-01"], 52, 5)).toBe(true);
  });
});
