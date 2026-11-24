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
  sshState,
  sshText,
  trustState,
  trustText,
  collectionChecked,
  credentialGroups,
  credentialBody,
  credentialFields,
  deviceCount,
  factsByName,
  hops,
  lastCycle,
  nameTaken,
  newDeviceBody,
  newRouteBody,
  routeCredentials,
  secretFrom,
  seenRows,
  storedDevice,
  usedByRoutes,
  SETTING_FIELDS,
  deviceBody,
  deviceDraft,
  groupBody,
  groupDraft,
  inherited,
  settingDefaults,
  jumpHostBody,
  jumpHostRoutes,
  newDeviceChecked,
  newGroupChecked,
  newJumpHostBody,
  usedSetting,
  fallbackOf,
  parseSetting,
  rebase,
  routeBody,
  routeFields,
  sameRecord,
  columnChars,
  deviceMatches,
  draftOrigin,
  factNames,
  foldKey,
  listRows,
  seenChars,
  MIN_CHARS,
} from "../src/inventory/model";
import { viewOf, viewSearch } from "../src/page/url";

const VENDORS: Vendors = {
  vendors: [
    { vendor: "equinix", transport: "https" },
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
  collection: { history_days: 30 },
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
    interval_seconds: r(60, "default"),
    orchestrator_release: r(null, "default"),
    api_base: r(null, "default"),
    concurrency: r(4, "default"),
    refresh_seconds: r(1800, "default"),
    network_edge: r("off", "default"),
    page_size: r(100, "default"),
    collection: r("auto", "default"),
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

  it("gives the SSH algorithms and mode and the TLS trust, with the defaults for none", () => {
    expect(sshText(null, undefined)).toBe("modern exec");
    expect(sshText("legacy", "shell")).toBe("legacy shell");
    expect(trustText(null, "unifi")).toBe("pin");
    expect(trustText(null, "velocloud")).toBe("public");
    expect(trustText("ca", "velocloud")).toBe("ca");
  });

  it("prints the SSH cell of a device as an override when the device sets one of its 2 settings", () => {
    expect(sshState(R2.settings, true)).toEqual({ kind: "override", text: "legacy shell" });
    expect(sshState(R1.settings, true)).toEqual({ kind: "inherit" });
    expect(sshState(R1.settings, false)).toEqual({ kind: "value", text: "modern exec" });
    expect(trustState(R1.settings, true)).toEqual({ kind: "inherit" });
    expect(trustState(resolved("h1", "g-https", "unifi", { tls_trust: r("ca", "device") }).settings, true)).toEqual({ kind: "override", text: "ca" });
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

describe("edits of the settings", () => {
  const field = (k: string) => SETTING_FIELDS.find((f) => f.key === k)!;

  it("checks a number against the range of the database, an empty text inheriting", () => {
    const retries = field("retries");
    const timeout = field("timeout_seconds");
    expect(parseSetting(retries, "0")).toEqual({ ok: true, value: 0 });
    expect(parseSetting(retries, "10")).toEqual({ ok: true, value: 10 });
    expect(parseSetting(retries, "11").ok).toBe(false);
    expect(parseSetting(timeout, "0").ok).toBe(false);
    expect(parseSetting(timeout, "1")).toEqual({ ok: true, value: 1 });
    expect(parseSetting(timeout, "86400")).toEqual({ ok: true, value: 86400 });
    expect(parseSetting(timeout, "86401")).toEqual({ ok: false, problem: { title: "device time limit out of range", detail: "device time limit from 1 to 86400" } });
    expect(parseSetting(timeout, "")).toEqual({ ok: true, value: null });
    expect(parseSetting(timeout, " ")).toEqual({ ok: true, value: null });
    const interval = field("interval_seconds");
    expect(parseSetting(interval, "59").ok).toBe(false);
    expect(parseSetting(interval, "60")).toEqual({ ok: true, value: 60 });
    expect(parseSetting(interval, "86400")).toEqual({ ok: true, value: 86400 });
    expect(parseSetting(interval, "86401").ok).toBe(false);
    expect(parseSetting(timeout, "1.5")).toEqual({ ok: false, problem: { title: "device time limit not a whole number", detail: "device time limit from 1 to 86400" } });
    expect(parseSetting(timeout, "-1").ok).toBe(false);
    expect(parseSetting(field("ssh_channels"), "0").ok).toBe(false);
    expect(parseSetting(field("ssh_channels"), "2147483648").ok).toBe(false);
    expect(parseSetting(field("ssh_mode"), "telnet").ok).toBe(false);
  });

  it("hides the settings that the collector of the vendor does not read, and shows each with no collector", () => {
    expect(usedSetting(field("tls_trust"), VENDORS, "vyos")).toBe(false);
    expect(usedSetting(field("ssh_mode"), VENDORS, "unifi")).toBe(false);
    expect(usedSetting(field("nxos_json"), VENDORS, "vyos")).toBe(false);
    expect(usedSetting(field("nxos_json"), VENDORS, "nxos")).toBe(true);
    expect(usedSetting(field("timeout_seconds"), VENDORS, "unifi")).toBe(true);
    expect(usedSetting(field("retries"), VENDORS, "vyos")).toBe(false);
    expect(usedSetting(field("request_timeout_seconds"), VENDORS, "unifi")).toBe(true);
    expect(usedSetting(field("retries"), VENDORS, "unifi")).toBe(false);
    expect(usedSetting(field("retries"), VENDORS, "equinix")).toBe(true);
    expect(usedSetting(field("tls_trust"), VENDORS, "othervendor")).toBe(true);
    expect(usedSetting(field("paged_section_timeout_seconds"), VENDORS, "equinix")).toBe(true);
    expect(usedSetting(field("paged_section_timeout_seconds"), VENDORS, "unifi")).toBe(false);
    expect(usedSetting(field("section_timeout_seconds"), VENDORS, "equinix")).toBe(false);
    expect(fallbackOf(field("interval_seconds"), "equinix")).toBe("900");
    expect(usedSetting(field("network_edge"), VENDORS, "equinix")).toBe(true);
    expect(usedSetting(field("page_size"), VENDORS, "unifi")).toBe(false);
    expect(usedSetting(field("tls_trust"), null, "vyos")).toBe(true);
  });

  it("gives the inherited value of an empty setting: the group, else the default", () => {
    expect(inherited(field("ssh_algorithms"), INV.groups[2]!.settings)).toEqual({ from: "group", text: "legacy" });
    expect(inherited(field("timeout_seconds"), INV.groups[2]!.settings)).toEqual({ from: "default", text: "45" });
    expect(inherited(field("route"), null)).toEqual({ from: "default", text: "direct" });
  });

  it("takes the default of an empty setting from the resolved devices", () => {
    const devices = [
      resolved("r1", "g-vyos", "vyos", { timeout_seconds: r(30, "device"), section_timeout_seconds: r(25, "group") }),
      resolved("r2", "g-vyos", "vyos", { timeout_seconds: r(90, "default") }),
    ];
    const d = settingDefaults(devices);
    expect(d.timeout_seconds).toBe("90");
    expect(d.section_timeout_seconds).toBe("20");
    expect(d.credential).toBeUndefined();
    expect(inherited(field("timeout_seconds"), INV.groups[2]!.settings, d)).toEqual({ from: "default", text: "90" });
    expect(inherited(field("ssh_algorithms"), INV.groups[2]!.settings, d)).toEqual({ from: "group", text: "legacy" });
    expect(inherited(field("credential"), null, d)).toEqual({ from: "default", text: "none" });
    expect(settingDefaults([])).toEqual({});
    const vco = [resolved("v1", "g-vco", "velocloud", { tls_trust: r("public", "default") })];
    expect(settingDefaults(vco).tls_trust).toBeUndefined();
    expect(inherited(field("tls_trust"), null, settingDefaults(vco), "velocloud")).toEqual({ from: "default", text: "public" });
    expect(inherited(field("tls_trust"), null, settingDefaults(vco), "unifi")).toEqual({ from: "default", text: "pin" });
  });

  it("clears a setting of a device to inherit, with no other field changed", () => {
    const r2 = storedDevice(INV, "r2")!;
    const b = deviceBody(r2, { ...deviceDraft(r2), ssh_mode: "" });
    expect(b).toEqual({ ok: true, body: { ...r2, settings: { ssh_algorithms: "legacy" } } });
  });

  it("writes 2 edited fields of one stored record and keeps the others", () => {
    const r1 = storedDevice(INV, "r1")!;
    const b = deviceBody(r1, { ...deviceDraft(r1), location: "", timeout_seconds: "30", address: " 192.0.2.101 " });
    expect(b).toEqual({ ok: true, body: { name: "r1", group: "g-vyos", address: "192.0.2.101", site: "s1", settings: { timeout_seconds: 30 } } });
    expect(deviceBody(r1, deviceDraft(r1))).toEqual({ ok: true, body: r1 });
    expect(sameRecord(r1, { ...r1, console_site: null })).toBe(true);
  });

  it("refuses a body with a number out of range or an empty address", () => {
    const r1 = storedDevice(INV, "r1")!;
    expect(deviceBody(r1, { ...deviceDraft(r1), retries: "11" }).ok).toBe(false);
    expect(deviceBody(r1, { ...deviceDraft(r1), address: " " }).ok).toBe(false);
  });

  it("edits the vendor, the description and the settings of a group", () => {
    const g = INV.groups[0]!;
    const b = groupBody(g, { ...groupDraft(g), description: "Lab routers", credential: "", capture_bgp: "all" });
    expect(b).toEqual({ ok: true, body: { name: "g-vyos", vendor: "vyos", description: "Lab routers", settings: { route: "via-hop", capture_bgp: "all" } } });
    expect(groupBody(g, { ...groupDraft(g), vendor: "" }).ok).toBe(false);
  });

  it("keeps an edit that is not written when the stored record changes", () => {
    const before = { address: "192.0.2.1", site: "s1" };
    const next = { address: "192.0.2.9", site: "s1" };
    expect(rebase({ address: "192.0.2.1", site: "s7" }, before, next)).toEqual({ address: "192.0.2.9", site: "s7" });
  });

  it("makes the bodies of a new device and a new group with the settings of the panel", () => {
    expect(newDeviceChecked({ name: "n1", address: "192.0.2.50", group: "g-vyos", site: "", location: "" }, { console_site: "default", retries: "2", ha: "" })).toEqual({
      ok: true,
      body: { name: "n1", group: "g-vyos", address: "192.0.2.50", site: null, location: null, console_site: "default", settings: { retries: 2 } },
    });
    expect(newDeviceChecked({ name: "n1", address: "192.0.2.50", group: "g-vyos", site: "", location: "" }, { retries: "x" }).ok).toBe(false);
    expect(newGroupChecked({ name: "g", vendor: "nxos", credential: "cred-a", route: "" }, { nxos_json: "native", description: "" })).toEqual({
      ok: true,
      body: { name: "g", vendor: "nxos", settings: { credential: "cred-a", nxos_json: "native" } },
    });
  });
});

describe("edits of routes and jump hosts", () => {
  it("clears the proxy and its login together", () => {
    const r = INV.routes[2]!;
    expect(routeBody(r, { ...routeFields(r), proxy: " " })).toEqual({ name: "via-proxy", jumps: ["hop-2", "hop-1"] });
  });

  it("changes the order of the jump hosts and keeps the proxy", () => {
    const r = INV.routes[2]!;
    expect(routeBody(r, { ...routeFields(r), jumps: ["hop-1"] })).toEqual({ ...r, jumps: ["hop-1"] });
    expect(routeBody(r, routeFields(r))).toEqual(r);
  });

  it("adds a proxy login only with a proxy", () => {
    const r = INV.routes[1]!;
    expect(routeBody(r, { proxy: "http://198.51.100.30:3128", proxyCredential: "cred-proxy", jumps: [] })).toEqual({
      name: "via-hop",
      jumps: [],
      proxy: "http://198.51.100.30:3128",
      proxy_credential: "cred-proxy",
    });
  });

  it("makes the bodies of a jump host and names the routes that use it", () => {
    expect(newJumpHostBody({ name: " hop-3 ", address: " 198.51.100.12:22 ", credential: "cred-hop", ssh_algorithms: "legacy" })).toEqual({
      name: "hop-3",
      address: "198.51.100.12:22",
      credential: "cred-hop",
      ssh_algorithms: "legacy",
    });
    const j = INV.jump_hosts[0]!;
    expect(jumpHostBody(j, { address: "198.51.100.13", credential: "cred-a", ssh_algorithms: "modern" })).toEqual({ ...j, address: "198.51.100.13", credential: "cred-a" });
    expect(jumpHostRoutes(INV, "hop-1")).toEqual(["via-hop", "via-proxy"]);
    expect(jumpHostRoutes(INV, "hop-9")).toEqual([]);
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

describe("the credential form", () => {
  const managed = { name: "lab", source: "managed" as const, kind: "password" as const, user: "ro", description: "lab routers", secret_revision: 2 };
  const PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";

  it("names a managed source by its kind", () => {
    expect(secretFrom(managed)).toBe("managed password");
    expect(secretFrom({ ...managed, kind: "api-key", user: null })).toBe("managed API key");
  });

  it("needs the secret of a new managed credential and keeps a stored one", () => {
    const f = { ...credentialFields(), user: "ro" };
    const fresh = credentialBody(undefined, " lab ", f);
    expect(fresh.ok).toBe(false);
    if (!fresh.ok) expect(fresh.problem.title).toBe("secret empty");
    const set = credentialBody(undefined, "lab", { ...f, secret: "p" });
    expect(set).toEqual({
      ok: true,
      body: { name: "lab", source: "managed", key: null, kind: "password", user: "ro", description: null, secret_revision: null, secret: { value: "p", passphrase: null } },
    });
    const kept = credentialBody(managed, "lab", { ...credentialFields(managed), user: "admin" });
    expect(kept.ok && kept.body).toMatchObject({ user: "admin", description: "lab routers", secret: null });
    expect(credentialBody(managed, "lab", { ...credentialFields(managed), kind: "api-key" }).ok).toBe(false);
  });

  it("checks the user, the private key and the env key", () => {
    expect(credentialBody(undefined, "k", { ...credentialFields(), user: "", secret: "p" }).ok).toBe(false);
    const key = { ...credentialFields(), kind: "ssh-key" as const, user: "ro", passphrase: "pp" };
    expect(credentialBody(undefined, "k", { ...key, secret: "not a key" }).ok).toBe(false);
    const ok = credentialBody(undefined, "k", { ...key, secret: PEM });
    expect(ok.ok && ok.body.secret).toEqual({ value: PEM, passphrase: "pp" });
    const api = credentialBody(undefined, "k", { ...credentialFields(), kind: "api-key", user: "ignored", secret: "abc" });
    expect(api.ok && api.body).toMatchObject({ kind: "api-key", user: null, secret: { value: "abc", passphrase: null } });
    expect(credentialBody(undefined, "e", { ...credentialFields(), source: "env", key: "lower" }).ok).toBe(false);
    const env = credentialBody(managed, "lab", { ...credentialFields(managed), source: "env", key: "LAB" });
    expect(env.ok && env.body).toMatchObject({ source: "env", key: "LAB", kind: null, user: null, secret: null });
  });
});

describe("the history of the store", () => {
  it("takes a whole number of days from 1 to 3650", () => {
    expect(collectionChecked(" 7 ")).toEqual({ ok: true, body: { history_days: 7 } });
    expect(collectionChecked("3650").ok).toBe(true);
    for (const bad of ["0", "3651", "", "7.5", "-1", "x"]) expect(collectionChecked(bad).ok, bad).toBe(false);
    const out = collectionChecked("0");
    expect(!out.ok && out.problem.title).toBe("history out of range");
  });
});

describe("the device list", () => {
  const sections = () => arrange(INV, DEVICES, "device group");

  it("finds a device by its name, its address or its site, in any case", () => {
    expect(deviceMatches(R1, "R1")).toBe(true);
    expect(deviceMatches(R1, "192.0.2.99")).toBe(true);
    expect(deviceMatches(R1, " S1 ")).toBe(true);
    expect(deviceMatches(R1, "x1")).toBe(false);
    expect(deviceMatches(R2, "")).toBe(true);
  });

  it("gives a group row and its device rows for each section", () => {
    const rows = listRows(sections(), new Set(), "");
    expect(rows.map((r) => (r.kind === "group" ? `group ${r.section.key} ${r.count}` : `device ${r.device.name}`))).toEqual([
      "group g-empty 0",
      "group g-other 1",
      "device x1",
      "group g-vyos 2",
      "device r1",
      "device r2",
    ]);
    expect(rows.every((r) => r.kind === "group" || r.underGroup)).toBe(true);
  });

  it("leaves out the devices of a folded group and keeps its count", () => {
    const vyos = sections().find((s) => s.key === "g-vyos")!;
    const rows = listRows(sections(), new Set([foldKey(vyos)]), "");
    const g = rows.find((r) => r.kind === "group" && r.section.key === "g-vyos");
    expect(g).toMatchObject({ folded: true, count: 2 });
    expect(rows.some((r) => r.kind === "device" && r.device.group === "g-vyos")).toBe(false);
  });

  it("keeps only the sections with a matching device under a filter, with the count of the matches", () => {
    const rows = listRows(sections(), new Set(), "s1");
    expect(rows.map((r) => (r.kind === "group" ? `group ${r.section.key} ${r.count}` : `device ${r.device.name}`))).toEqual(["group g-vyos 1", "device r1"]);
  });

  it("gives a section with no key its own fold key", () => {
    const bySite = arrange(INV, DEVICES, "site");
    expect(bySite.map(foldKey)).toEqual(["=s1", "=s2", ""]);
  });

  it("draws 10,000 devices in 40 groups as 10,040 rows", () => {
    const groups = Array.from({ length: 40 }, (_, i) => ({ name: `g-${String(i).padStart(2, "0")}`, vendor: "vyos", settings: {} }));
    const devices = Array.from({ length: 10_000 }, (_, i) => resolved(`d-${i}`, groups[i % 40]!.name, "vyos", {}));
    const inv: Inventory = { ...INV, groups, devices: [] };
    expect(listRows(arrange(inv, devices, "device group"), new Set(), "").length).toBe(10_040);
  });

  it("sizes each text column by its longest text, with a floor", () => {
    const long = resolved("core-switch-with-a-long-name", "g-vyos", "vyos", {});
    const inv: Inventory = { ...INV, devices: [] };
    const w = columnChars(arrange(inv, [long, R1], "device group"), "device group");
    expect(w.device).toBe("core-switch-with-a-long-name".length);
    expect(w.address).toBe(MIN_CHARS);
    expect(w.credential).toBe(MIN_CHARS);
  });

  it("sizes the columns of the devices that the twin sees", () => {
    expect(seenChars([{ name: "ap-lobby-north-wing", device: "sw1", port: "GigabitEthernet1/0/24", protocol: "lldp" }])).toEqual({
      name: "ap-lobby-north-wing".length,
      device: MIN_CHARS,
      port: "GigabitEthernet1/0/24".length,
    });
  });

  it("asks for the facts of each name one time, with no name that a comma list cannot hold", () => {
    expect(factNames(["r2", "r1", "r2", "", "a,b"])).toEqual(["r1", "r2"]);
  });
});

describe("origins of the settings in a panel", () => {
  const field = (k: string) => SETTING_FIELDS.find((f) => f.key === k)!;

  it("gives the device for a set text, else the group, else the default", () => {
    const group = { credential: "cred-a" };
    expect(draftOrigin(field("credential"), { credential: "cred-hop" }, group, "device")).toBe("device");
    expect(draftOrigin(field("credential"), { credential: " " }, group, "device")).toBe("group");
    expect(draftOrigin(field("ssh_mode"), {}, group, "device")).toBe("default");
  });

  it("gives the group for a set text of a group, else the default", () => {
    expect(draftOrigin(field("interval_seconds"), { interval_seconds: "300" }, null, "group")).toBe("group");
    expect(draftOrigin(field("interval_seconds"), { interval_seconds: "" }, null, "group")).toBe("default");
  });
});
