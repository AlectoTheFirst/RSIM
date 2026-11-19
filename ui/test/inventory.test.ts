// The Inventory page as data, on a hand-built inventory with documentation
// addresses.
import { describe, expect, it } from "vitest";
import {
  type Inventory,
  type ResolvedDevice,
  type Vendors,
  ageText,
  arrange,
  cellState,
  counts,
  credentialGroups,
  deviceCount,
  deviceSsh,
  devicesHave,
  factsByName,
  groupSsh,
  groupTrust,
  hops,
  lastCycle,
  moveBody,
  nameTaken,
  newDeviceBody,
  newRouteBody,
  overrides,
  routeCredentials,
  secretFrom,
  seenRows,
  siteBody,
  storedDevice,
  usedByRoutes,
} from "../src/inventory/model";
import { viewOf, viewSearch } from "../src/page/url";

const VENDORS: Vendors = {
  vendors: [
    { vendor: "nxos", transport: "ssh" },
    { vendor: "unifi", transport: "https" },
    { vendor: "vyos", transport: "ssh" },
  ],
};

const INV: Inventory = {
  version: 7,
  credentials: [
    { name: "cred-a", source: "env", key: "CRED_A" },
    { name: "cred-hop", source: "env", key: "HOP" },
    { name: "cred-proxy", source: "env-url", key: "PROXY_URL" },
  ],
  jump_hosts: [
    { name: "hop-1", address: "198.51.100.10", credential: "cred-hop", ssh_algorithms: "modern" },
    { name: "hop-2", address: "198.51.100.11:2222", credential: "cred-hop", ssh_algorithms: "modern" },
  ],
  routes: [
    { name: "direct-1", jumps: [] },
    { name: "via-hop", jumps: ["hop-1"] },
    { name: "via-proxy", proxy: "socks5://198.51.100.20:1080", proxy_credential: "cred-proxy", jumps: ["hop-2", "hop-1"] },
  ],
  groups: [
    { name: "g-vyos", vendor: "vyos", settings: { credential: "cred-a", route: "via-hop" } },
    { name: "g-other", vendor: "othervendor", settings: {} },
    { name: "g-empty", vendor: "nxos", settings: { ssh_algorithms: "legacy" } },
  ],
  devices: [
    { name: "r2", group: "g-vyos", address: "192.0.2.2", settings: { ssh_algorithms: "legacy", ssh_mode: "shell" } },
    { name: "r1", group: "g-vyos", address: "192.0.2.1", site: "s1", location: "Lab A", settings: {} },
    { name: "x1", group: "g-other", address: "203.0.113.10", site: "s2", settings: { credential: "cred-a" } },
  ],
  bindings: { fabric_ports: [], edge_devices: [] },
};

const r = <T>(value: T, origin: "device" | "group" | "default") => ({ value, origin });

function resolved(name: string, group: string, vendor: string, s: Partial<ResolvedDevice["settings"]>, site?: string): ResolvedDevice {
  const base: ResolvedDevice["settings"] = {
    credential: r(null, "default"),
    route: r(null, "default"),
    ssh_algorithms: r("modern", "default"),
    ssh_mode: r("exec", "default"),
    ssh_channels: r(1, "default"),
    nxos_json: r("plain", "default"),
    tls_trust: r("pin", "default"),
    tls_ca_file: r(null, "default"),
    capture_bgp: r("sessions", "default"),
    timeout_seconds: r(45, "default"),
    section_timeout_seconds: r(20, "default"),
    request_timeout_seconds: r(60, "default"),
    paged_section_timeout_seconds: r(300, "default"),
    retries: r(0, "default"),
    ha: r("none", "default"),
  };
  return { name, group, vendor, address: "192.0.2.99", site: site ?? null, settings: { ...base, ...s } };
}

const R1 = resolved("r1", "g-vyos", "vyos", { credential: r("cred-a", "group"), route: r("via-hop", "group") }, "s1");
const R2 = resolved("r2", "g-vyos", "vyos", {
  credential: r("cred-a", "group"),
  route: r("via-hop", "group"),
  ssh_algorithms: r("legacy", "device"),
  ssh_mode: r("shell", "device"),
});
const X1 = resolved("x1", "g-other", "othervendor", { credential: r("cred-a", "device") }, "s2");
const DEVICES = [R2, X1, R1];

describe("arrangement", () => {
  it("gives each group in name order with its devices, a group with no device included", () => {
    const s = arrange(INV, DEVICES, "device group");
    expect(s.map((x) => [x.key, x.devices.map((d) => d.name)])).toEqual([
      ["g-empty", []],
      ["g-other", ["x1"]],
      ["g-vyos", ["r1", "r2"]],
    ]);
    expect(s[2]!.group?.vendor).toBe("vyos");
  });

  it("gives each site with the devices with no site last", () => {
    const s = arrange(INV, DEVICES, "site");
    expect(s.map((x) => [x.key, x.devices.map((d) => d.name)])).toEqual([
      ["s1", ["r1"]],
      ["s2", ["x1"]],
      [null, ["r2"]],
    ]);
    expect(s.every((x) => x.group === null)).toBe(true);
  });

  it("gives each resolved credential", () => {
    const none = resolved("n1", "g-empty", "nxos", {});
    const s = arrange(INV, [...DEVICES, none], "credential");
    expect(s.map((x) => [x.key, x.devices.map((d) => d.name)])).toEqual([
      ["cred-a", ["r1", "r2", "x1"]],
      [null, ["n1"]],
    ]);
  });

  it("counts the devices of a group row", () => {
    expect(deviceCount(1)).toBe("1 device");
    expect(deviceCount(2)).toBe("2 devices");
  });
});

describe("cells of the settings", () => {
  it("draws a hairline for an inherited value under its group row", () => {
    expect(cellState("cred-a", "group", true)).toEqual({ kind: "inherit" });
    expect(cellState(null, "default", true)).toEqual({ kind: "inherit" });
  });

  it("prints an override in each arrangement", () => {
    expect(cellState("cred-a", "device", true)).toEqual({ kind: "override", text: "cred-a" });
    expect(cellState("cred-a", "device", false)).toEqual({ kind: "override", text: "cred-a" });
  });

  it("prints an inherited value with no group row, and a hatch for no value", () => {
    expect(cellState("cred-a", "group", false)).toEqual({ kind: "value", text: "cred-a" });
    expect(cellState(null, "default", false)).toEqual({ kind: "none" });
  });

  it("gives the SSH words, an override when the device sets one of them", () => {
    expect(deviceSsh(VENDORS, R2, true)).toEqual({ kind: "override", text: "Legacy, shell" });
    expect(deviceSsh(VENDORS, R1, true)).toEqual({ kind: "inherit" });
    expect(deviceSsh(VENDORS, R1, false)).toEqual({ kind: "value", text: "Modern, exec" });
  });

  it("leaves the SSH cell empty for a vendor with no SSH collector", () => {
    expect(deviceSsh(VENDORS, X1, true)).toBeNull();
    expect(deviceSsh(VENDORS, resolved("u1", "g-u", "unifi", {}), true)).toBeNull();
    expect(groupSsh(VENDORS, INV.groups[1]!)).toBeNull();
    expect(groupSsh(VENDORS, INV.groups[0]!)).toBe("Modern, exec");
    expect(groupSsh(VENDORS, INV.groups[2]!)).toBe("Legacy, exec");
  });

  it("names the settings that a device overrides", () => {
    expect(overrides(R2)).toEqual(["ssh_algorithms", "ssh_mode"]);
    expect(overrides(R1)).toEqual([]);
  });
});

describe("trust of a group", () => {
  it("gives the TLS trust over HTTPS, not known over SSH and none with no collector", () => {
    expect(groupTrust(VENDORS, { name: "u", vendor: "unifi", settings: {} })).toEqual({ kind: "value", text: "Pin" });
    expect(groupTrust(VENDORS, { name: "u", vendor: "unifi", settings: { tls_trust: "ca" } })).toEqual({ kind: "value", text: "CA" });
    expect(groupTrust(VENDORS, INV.groups[0]!)).toEqual({ kind: "not known" });
    expect(groupTrust(VENDORS, INV.groups[1]!)).toBeNull();
  });
});

describe("result line", () => {
  it("counts the devices, the groups, the devices with no site or no collector, and the names seen", () => {
    const seen = seenRows(
      ["device", "port", "neighbour", "remote_port", "protocol", "provenance"],
      [
        ["r1", "eth1", "n-out", "e1", "lldp", []],
        ["r2", "eth1", "n-out", "e2", "cdp", []],
        ["r1", "eth2", "r2", "eth1", "lldp", []],
      ],
      INV.devices.map((d) => d.name),
    );
    expect(counts(INV, VENDORS, seen)).toEqual({ devices: 3, groups: 3, noSite: 1, noCollector: 1, seen: 1 });
    expect(devicesHave(1)).toBe("1 device has");
    expect(devicesHave(4)).toBe("4 devices have");
  });

  it("counts no device with no collector when the vendors are not known", () => {
    expect(counts(INV, null, []).noCollector).toBe(0);
  });
});

describe("devices seen by the twin", () => {
  it("keeps one row for each name that is not a device of the inventory", () => {
    const rows = seenRows(
      ["protocol", "neighbour", "device", "port"],
      [
        ["cdp", "n-b", "r1", "eth3"],
        ["lldp", "n-b", "r2", "eth3"],
        ["lldp", "r1", "r2", "eth4"],
      ],
      ["r1", "r2"],
    );
    expect(rows).toEqual([{ name: "n-b", device: "r1", port: "eth3", protocol: "cdp" }]);
  });
});

describe("facts of the twin", () => {
  const columns = ["device", "vendor", "platform", "platform_reason", "serial", "serial_reason", "collected_at", "store_device"];
  const facts = factsByName(columns, [
    ["r1", "vyos", "model-a", null, "SN-0001", null, "2026-01-01T00:00:00Z", "r1"],
    ["r3", "vyos", null, "not_read", null, "not_read", "2026-01-01T00:00:00Z", "r3"],
    ["ap-1", "unifi", null, "not_read", null, "not_read", "2026-01-01T00:01:00Z", "console-1"],
    ["sw-1", "unifi", null, "not_read", null, "not_read", "2026-01-01T00:00:30Z", "console-1"],
  ]);

  it("joins the facts by the device name", () => {
    expect(facts.get("r1")).toEqual({ serial: "SN-0001", serialReason: null, platform: "model-a", platformReason: null, collectedAt: "2026-01-01T00:00:00Z" });
    expect(facts.get("r3")?.serialReason).toBe("not_read");
    expect(facts.has("r2")).toBe(false);
  });

  it("gives a store device with no row of its own the newest time of its rows", () => {
    expect(facts.get("console-1")).toEqual({ serial: null, serialReason: null, platform: null, platformReason: null, collectedAt: "2026-01-01T00:01:00Z" });
    expect(facts.get("ap-1")?.collectedAt).toBe("2026-01-01T00:01:00Z");
  });

  it("gives the age of the last cycle, not known with no facts row, and a hatch with no collector", () => {
    const now = Date.parse("2026-01-01T00:02:30Z");
    expect(lastCycle(VENDORS, R1, facts.get("r1"), now)).toEqual({ kind: "age", text: "2 min ago" });
    expect(lastCycle(VENDORS, R2, facts.get("r2"), now)).toEqual({ kind: "not known" });
    expect(lastCycle(VENDORS, X1, undefined, now)).toEqual({ kind: "no collector", vendor: "othervendor" });
  });

  it("writes an age in seconds, minutes, hours and days", () => {
    const t = "2026-01-01T00:00:00Z";
    const at = (s: number) => Date.parse(t) + s * 1000;
    expect(ageText(t, at(5))).toBe("5 s ago");
    expect(ageText(t, at(3600 * 3))).toBe("3 h ago");
    expect(ageText(t, at(86400 * 2))).toBe("2 d ago");
    expect(ageText("no time", at(0))).toBeNull();
  });
});

describe("credentials and routes", () => {
  it("gives the groups whose devices use a credential", () => {
    expect(credentialGroups(INV, "cred-a")).toEqual(["g-other", "g-vyos"]);
    expect(credentialGroups(INV, "cred-hop")).toEqual([]);
    expect(usedByRoutes(INV, "cred-hop")).toBe(true);
    expect(usedByRoutes(INV, "cred-proxy")).toBe(true);
    expect(usedByRoutes(INV, "cred-a")).toBe(false);
  });

  it("names the source of a credential", () => {
    expect(secretFrom(INV.credentials[0]!)).toBe("env file, key");
    expect(secretFrom(INV.credentials[2]!)).toBe("env URL, key");
  });

  it("gives the hops of a route and its credentials", () => {
    expect(hops(INV, INV.routes[0]!)).toEqual([]);
    expect(hops(INV, INV.routes[1]!)).toEqual([{ words: "jump host", value: "198.51.100.10" }]);
    expect(hops(INV, INV.routes[2]!)).toEqual([
      { words: "SOCKS5 proxy", value: "198.51.100.20:1080" },
      { words: ", then jump host", value: "198.51.100.11:2222" },
      { words: ", then jump host", value: "198.51.100.10" },
    ]);
    expect(routeCredentials(INV, INV.routes[2]!)).toEqual(["cred-proxy", "cred-hop"]);
  });
});

describe("writes", () => {
  it("keeps the stored settings of a device and adds no inherited value", () => {
    const r2 = storedDevice(INV, "r2")!;
    expect(siteBody(r2, " s9 ", "")).toEqual({ ...r2, site: "s9", location: null });
    expect(moveBody(r2, "g-empty")).toEqual({ ...r2, group: "g-empty" });
    expect(moveBody(r2, "g-empty").settings).toEqual({ ssh_algorithms: "legacy", ssh_mode: "shell" });
    const r1 = storedDevice(INV, "r1")!;
    expect(moveBody(r1, "g-empty").settings).toEqual({});
  });

  it("makes the bodies of a new device and a new route", () => {
    expect(newDeviceBody({ name: "n1", address: "192.0.2.50", group: "g-vyos", site: "", location: "" })).toEqual({
      name: "n1",
      group: "g-vyos",
      address: "192.0.2.50",
      site: null,
      location: null,
      settings: {},
    });
    expect(newRouteBody({ name: "r", proxy: "", proxyCredential: "cred-proxy", jumps: ["hop-1"] })).toEqual({ name: "r", jumps: ["hop-1"] });
    expect(newRouteBody({ name: "r", proxy: "http://198.51.100.30:3128", proxyCredential: "cred-proxy", jumps: [] })).toEqual({
      name: "r",
      jumps: [],
      proxy: "http://198.51.100.30:3128",
      proxy_credential: "cred-proxy",
    });
  });
});

describe("names of new records", () => {
  it("finds a name in use after the trim", () => {
    expect(nameTaken(INV.groups, " g-vyos ")).toBe(true);
    expect(nameTaken(INV.credentials, "cred-a")).toBe(true);
    expect(nameTaken(INV.routes, "via-hop")).toBe(true);
    expect(nameTaken(INV.routes, "via")).toBe(false);
  });
});

describe("view in the URL", () => {
  it("reads and writes the Inventory view", () => {
    expect(viewOf("?view=inventory&twin=store")).toBe("Inventory");
    expect(viewSearch("Inventory", "store")).toBe("?view=inventory&twin=store");
  });
});
