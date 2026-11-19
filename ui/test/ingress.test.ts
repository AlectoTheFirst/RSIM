/// <reference types="node" />
// The entry point picker of the ingress field: the stage of a text, the
// device list with the found entry point first, the entry interfaces of a
// device, the table requests, and the answer whose ingress is not found.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { PathAnswer } from "../src/api/types";
import { ingressHint, noIngress } from "../src/ladder/layout";
import { BASE_FIELDS } from "../src/page/fields";
import {
  FOUND,
  PICKER_CLOSED,
  deviceOptions,
  ingressRequest,
  ingressStage,
  interfaceOptions,
  pickerKey,
} from "../src/page/pick";

function golden(name: string): PathAnswer {
  const url = new URL(`../../crates/rsim-cli/tests/golden/${name}.json`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as PathAnswer;
}

const DEVICES = [{ device: "r1", vendor: "vyos" }, { device: "r2" }, { device: "sw1", vendor: "nxos" }];

const FUNCTIONS = [
  { function: "r1/in/eth0" },
  { function: "r1/in/eth1" },
  { function: "r1/in/ge-0/0/1" },
  { function: "r1/out/eth0" },
  { function: "r1/route" },
  { function: "r10/in/eth0" },
  { function: "r1/in/eth0" },
];

describe("ingress field", () => {
  it("is not a base field, so it shows only from Add field, a value or the button", () => {
    expect(BASE_FIELDS.has("ingress")).toBe(false);
  });
});

describe("ingress stage", () => {
  it("is the device list for a text with no slash", () => {
    expect(ingressStage("")).toEqual({ stage: "device", text: "" });
    expect(ingressStage(" r1 ")).toEqual({ stage: "device", text: "r1" });
  });

  it("is the interface list of the device before the first slash", () => {
    expect(ingressStage("r1/")).toEqual({ stage: "interface", device: "r1", text: "" });
    expect(ingressStage("r1/ge-0/0")).toEqual({ stage: "interface", device: "r1", text: "ge-0/0" });
  });
});

describe("device list", () => {
  it("has the found entry point first, labelled found, then each device with its vendor", () => {
    const list = deviceOptions(DEVICES, "r2/eth3", "");
    expect(list.map((o) => [o.name, o.detail, o.value, o.done])).toEqual([
      ["r2/eth3", FOUND, "r2/eth3", true],
      ["r1", "vyos", "r1/", false],
      ["r2", "", "r2/", false],
      ["sw1", "nxos", "sw1/", false],
    ]);
    expect(FOUND).toBe("found");
  });

  it("filters by a prefix of the name with no regard to case, the found entry point too", () => {
    expect(deviceOptions(DEVICES, "r2/eth3", "S").map((o) => o.name)).toEqual(["sw1"]);
    expect(deviceOptions(DEVICES, "r2/eth3", "r2").map((o) => o.name)).toEqual(["r2/eth3", "r2"]);
  });

  it("has no found item when the answer found none, and each device once, at most max", () => {
    expect(deviceOptions([...DEVICES, { device: "r1" }], null, "").map((o) => o.name)).toEqual(["r1", "r2", "sw1"]);
    expect(deviceOptions(DEVICES, null, "", 2)).toHaveLength(2);
  });
});

describe("interface list", () => {
  it("is the part after <device>/in/ of the functions of the device, each once, in name order", () => {
    const list = interfaceOptions(FUNCTIONS, "r1/");
    expect(list.map((o) => o.name)).toEqual(["eth0", "eth1", "ge-0/0/1"]);
    expect(list.map((o) => o.value)).toEqual(["r1/eth0", "r1/eth1", "r1/ge-0/0/1"]);
    expect(list.every((o) => o.done && o.detail === "")).toBe(true);
  });

  it("filters by the text after the slash, and an interface name keeps its slashes", () => {
    expect(interfaceOptions(FUNCTIONS, "r1/ge").map((o) => o.value)).toEqual(["r1/ge-0/0/1"]);
    expect(interfaceOptions(FUNCTIONS, "r1/ge-0/0").map((o) => o.value)).toEqual(["r1/ge-0/0/1"]);
  });

  it("is empty in the device stage", () => {
    expect(interfaceOptions(FUNCTIONS, "r1")).toEqual([]);
  });
});

describe("ingress table request", () => {
  it("asks for the devices by prefix, or the first page with no text", () => {
    expect(ingressRequest(ingressStage(""), 10)).toEqual({ table: "devices", params: { limit: "10" } });
    expect(ingressRequest(ingressStage("fra"), 10)).toEqual({ table: "devices", params: { "device.prefix": "fra", limit: "10" } });
  });

  it("asks for the functions of the device by the prefix <device>/in/<text>", () => {
    expect(ingressRequest(ingressStage("r1/ge"), 10)).toEqual({
      table: "functions",
      params: { device: "r1", "function.prefix": "r1/in/ge", columns: "function", limit: "10" },
    });
  });
});

describe("keys of the entry point list", () => {
  it("move down and up, choose with Enter and close with Escape, as in the endpoint picker", () => {
    let s = pickerKey(PICKER_CLOSED, "ArrowDown", 3).state;
    expect(s).toEqual({ open: true, active: 0 });
    s = pickerKey(s, "ArrowDown", 3).state;
    expect(s.active).toBe(1);
    const enter = pickerKey(s, "Enter", 3);
    expect(enter.action).toBe("choose");
    expect(pickerKey({ open: true, active: 0 }, "Escape", 3).state).toEqual(PICKER_CLOSED);
  });
});

describe("no ingress", () => {
  it("is false for an answer whose runs found their entry point", () => {
    const a = golden("mini-enterprise").answer;
    expect(noIngress(a)).toBe(false);
    expect(ingressHint(a)).not.toBeNull();
  });

  it("is true for an answer with a run whose ingress is not found", () => {
    const a = golden("mini-enterprise").answer;
    const missing = {
      ...a.ingress[0]!,
      found: false,
      device: null,
      interface: null,
      function: null,
      resolved_by: null,
      reason: { code: "unknown_attribute", detail: "no ingress: no attachment record and no edge network holds the source address" },
    };
    const b = { ...a, ingress: [missing] };
    expect(noIngress(b)).toBe(true);
    expect(ingressHint(b)).toBeNull();
    expect(noIngress({ ...a, ingress: [...a.ingress, missing] })).toBe(true);
  });
});
