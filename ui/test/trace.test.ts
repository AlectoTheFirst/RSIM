/// <reference types="node" />
// The deciding step of a path, the line in the place of a missing reply,
// the endpoint picker and the rule of the keys of a view.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Answer, Branch, PathAnswer } from "../src/api/types";
import { autoStep, decidingStep, ingressHint, ladder, rowKeyOfStep, type SectionRow } from "../src/ladder/layout";
import { keyForElement, keyPlace } from "../src/tables/model";
import {
  type EndpointRow,
  PICKER_CLOSED,
  endpointAddresses,
  endpointRows,
  matchEndpoints,
  pickerKey,
  pickerQuery,
  placesByHost,
  recordsOf,
} from "../src/page/pick";

function golden(name: string): PathAnswer {
  const url = new URL(`../../crates/rsim-cli/tests/golden/${name}.json`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as PathAnswer;
}

/** A forward branch whose last function gives Unknown. */
function unknownBranch(): Branch {
  const base = golden("mini-enterprise").answer.branches[0]!;
  const steps = base.steps.slice(0, 3).map((s, i) => ({ ...s, outcome: { kind: i === 2 ? "unknown" : "forward" } }));
  const reason = { code: "incomplete_table", detail: "198.51.100.7 is not in the ARP table of r1 on eth1; the collected table is incomplete" };
  steps[2] = { ...steps[2]!, reason };
  return { ...base, steps, verdict: { kind: "unknown", reason } };
}

function withBranch(a: Answer, b: Branch): Answer {
  return { ...a, branches: [b], replies: [], summary: [{ ...a.summary[0]!, result: { kind: "same", verdict: b.verdict } as never }] };
}

describe("deciding step", () => {
  it("is the step that gives Unknown, with its reason", () => {
    const b = unknownBranch();
    const d = decidingStep(b)!;
    expect(d.step.index).toBe(b.steps[2]!.index);
    expect(d.reason).toBe("198.51.100.7 is not in the ARP table of r1 on eth1; the collected table is incomplete");
    expect(d.path).toEqual({ replyOf: null, branch: b.index });
  });

  it("is the step that drops", () => {
    const b = golden("leaf-spine-no-route").answer.branches[0]!;
    const d = decidingStep(b)!;
    expect(d.step.function).toBe("spine1/route");
    expect(d.reason).toBe("no route in VRF default");
  });

  it("is the last step with the reason of the verdict for a loop", () => {
    const b = golden("routing-loop").answer.branches[0]!;
    const d = decidingStep(b)!;
    expect(d.step.index).toBe(b.steps[b.steps.length - 1]!.index);
    expect(d.reason).toBe("loop · r2/vrf");
  });

  it("does not exist for a path that delivers", () => {
    expect(decidingStep(golden("mini-enterprise").answer.branches[0]!)).toBeNull();
  });

  it("is selected for a new answer with one verdict of Unknown or Drop, at each level", () => {
    const a = withBranch(golden("mini-enterprise").answer, unknownBranch());
    const d = autoStep(a)!;
    expect(d.step.outcome.kind).toBe("unknown");
    for (const level of ["function", "device"] as const) {
      const key = rowKeyOfStep(ladder(a, level).rows, d.path, d.step.index);
      const row = ladder(a, level).rows.find((r) => r.type === "step" && r.key === key);
      expect(row && row.type === "step" && row.steps.some((s) => s.index === d.step.index)).toBe(true);
    }
    expect(autoStep(golden("routing-loop").answer)?.reason).toBe("loop · r2/vrf");
  });

  it("is selected for an answer whose branches have one verdict kind with different reasons", () => {
    const a = withBranch(golden("mini-enterprise").answer, unknownBranch());
    const same = { ...a, summary: [{ ...a.summary[0]!, result: { kind: "same_kind", verdict: null, verdict_kind: "unknown" } as never }] };
    expect(autoStep(same)?.step.outcome.kind).toBe("unknown");
  });

  it("is not selected for an answer that delivers or has more than one verdict", () => {
    expect(autoStep(golden("mini-enterprise").answer)).toBeNull();
    expect(autoStep(golden("leaf-spine-no-route").answer)).toBeNull();
  });
});

describe("no reply", () => {
  const sections = (a: Answer, reply = true) =>
    ladder(a, "function", reply).rows.filter((r): r is SectionRow => r.type === "section");

  it("says why in one muted line in the place of the reply", () => {
    const s = sections(golden("routing-loop").answer);
    expect(s).toEqual([
      expect.objectContaining({ dir: "reply", text: "no reply: the forward path does not deliver", muted: true, verdict: null, note: null }),
    ]);
  });

  it("names the branch of an answer with more than one branch, before the reply of a later branch", () => {
    const s = sections(golden("leaf-spine-no-route").answer).map((r) => r.text);
    expect(s).toEqual([
      "branch 0",
      "branch 1",
      "no reply of branch 0: the forward path does not deliver",
      "reply of branch 1, branch 0",
      "reply of branch 1, branch 1",
    ]);
  });

  it("has no line for a path that delivers or a query with no reply", () => {
    expect(sections(golden("mini-enterprise").answer).some((r) => r.muted)).toBe(false);
    expect(sections(golden("routing-loop").answer, false)).toEqual([]);
  });
});

describe("ingress hint", () => {
  it("is the one entry point that the runs found", () => {
    expect(ingressHint(golden("leaf-spine").answer)).toBe("leaf1/eth9");
    expect(ingressHint({ ingress: [] })).toBeNull();
  });
});

describe("endpoint picker", () => {
  const rows: EndpointRow[] = [
    { name: "web-02", addresses: ["192.0.2.12", "2001:db8::12"], places: [] },
    { name: "web-01", addresses: ["192.0.2.11"], places: [] },
    { name: "Printer", addresses: ["198.51.100.40"], places: [] },
    { name: "192.0.2.99-host", addresses: [], places: [] },
  ];

  it("matches a prefix of the name or of an address with no regard to case, in name order", () => {
    expect(matchEndpoints(rows, "web").map((s) => [s.name, s.address])).toEqual([
      ["web-01", "192.0.2.11"],
      ["web-02", "192.0.2.12"],
    ]);
    expect(matchEndpoints(rows, "printer").map((s) => s.name)).toEqual(["Printer"]);
    expect(matchEndpoints(rows, "2001:db8").map((s) => [s.name, s.address])).toEqual([["web-02", "2001:db8::12"]]);
    expect(matchEndpoints(rows, "192.0.2.1").map((s) => s.name)).toEqual(["web-01", "web-02"]);
  });

  it("leaves out an endpoint with no address, and a text that is a list, a prefix or empty", () => {
    expect(matchEndpoints(rows, "192.0.2.99")).toEqual([]);
    expect(matchEndpoints(rows, " ")).toEqual([]);
    expect(pickerQuery("192.0.2.0/24")).toBeNull();
    expect(pickerQuery("192.0.2.1,192.0.2.2")).toBeNull();
    expect(pickerQuery(" web ")).toBe("web");
  });

  it("shows at most 10 endpoints", () => {
    const many = Array.from({ length: 25 }, (_, i) => ({ name: `h${String(i).padStart(2, "0")}`, addresses: [`192.0.2.${i}`], places: [] }));
    const got = matchEndpoints(many, "h");
    expect(got.length).toBe(10);
    expect(got[0]!.name).toBe("h00");
  });

  it("reads the rows of the tables endpoints and attachments, each endpoint once", () => {
    const ep = recordsOf({
      columns: ["endpoint", "addresses"],
      rows: [
        ["web-01", ["192.0.2.11"]],
        ["web-01", ["192.0.2.11"]],
      ],
    });
    expect(endpointRows(ep)).toEqual([{ name: "web-01", addresses: ["192.0.2.11"], places: [] }]);
    const att = recordsOf({
      columns: ["host", "device", "interface"],
      rows: [
        ["web-01", "sw1", "eth3"],
        ["web-01", "sw1", "eth3"],
        ["web-01", "sw2", "eth4"],
        [null, "sw3", "eth5"],
      ],
    });
    expect([...placesByHost(att)]).toEqual([["web-01", ["sw1/eth3", "sw2/eth4"]]]);
  });

  it("moves through the list with the arrows, chooses with Enter and closes with Escape", () => {
    let s = { open: true, active: -1 };
    let r = pickerKey(s, "ArrowDown", 3);
    expect(r).toEqual({ state: { open: true, active: 0 }, action: "none", handled: true });
    s = r.state;
    s = pickerKey(s, "ArrowDown", 3).state;
    s = pickerKey(s, "ArrowDown", 3).state;
    s = pickerKey(s, "ArrowDown", 3).state;
    expect(s.active).toBe(2);
    s = pickerKey(s, "ArrowUp", 3).state;
    expect(s.active).toBe(1);
    r = pickerKey(s, "Enter", 3);
    expect(r).toEqual({ state: PICKER_CLOSED, action: "choose", handled: true });
    expect(pickerKey(s, "Escape", 3)).toEqual({ state: PICKER_CLOSED, action: "none", handled: true });
  });

  it("leaves Enter with no active proposal, Escape of a closed list and other keys to the field", () => {
    expect(pickerKey({ open: true, active: -1 }, "Enter", 3).handled).toBe(false);
    expect(pickerKey(PICKER_CLOSED, "Escape", 3).handled).toBe(false);
    expect(pickerKey({ open: true, active: 0 }, "Enter", 0).handled).toBe(false);
    expect(pickerKey({ open: true, active: 0 }, "a", 3).handled).toBe(false);
    expect(pickerKey(PICKER_CLOSED, "ArrowUp", 3).handled).toBe(false);
    expect(pickerKey(PICKER_CLOSED, "ArrowDown", 3).state).toEqual({ open: true, active: 0 });
  });
});

describe("keys of a view", () => {
  it("leaves each key to a text field", () => {
    for (const tagName of ["INPUT", "SELECT", "TEXTAREA"]) {
      for (const key of ["j", "Enter", " ", "Escape", "/"]) expect(keyForElement(keyPlace({ tagName }), key)).toBe(true);
    }
    expect(keyForElement(keyPlace({ tagName: "DIV", isContentEditable: true }), "j")).toBe(true);
  });

  it("leaves Enter and Space to a button, a link or a summary, and gives the other keys to the view", () => {
    for (const tagName of ["BUTTON", "A", "SUMMARY"]) {
      expect(keyForElement(keyPlace({ tagName }), "Enter")).toBe(true);
      expect(keyForElement(keyPlace({ tagName }), " ")).toBe(true);
      expect(keyForElement(keyPlace({ tagName }), "j")).toBe(false);
      expect(keyForElement(keyPlace({ tagName }), "Escape")).toBe(false);
    }
  });

  it("gives each key to the view with no focused control", () => {
    expect(keyPlace(null)).toBe("page");
    expect(keyForElement(keyPlace({ tagName: "DIV" }), "Enter")).toBe(false);
    expect(keyForElement(keyPlace({ tagName: "BODY" }), "j")).toBe(false);
  });
});

describe("endpoint row of the Tables view", () => {
  it("gives the addresses of the column addresses", () => {
    expect(endpointAddresses(["endpoint", "addresses"], ["web-01", ["192.0.2.11", "2001:db8::11"]])).toEqual([
      "192.0.2.11",
      "2001:db8::11",
    ]);
    expect(endpointAddresses(["endpoint"], ["web-01"])).toEqual([]);
  });
});
