// The Inventory page as data: the arrangement of the devices, the state of
// each inherited cell, the counts of the result line, the join with the
// device facts of the twin, the usage of the credentials, the hops of the
// routes and the bodies of the writes.
import type { components } from "../api/schema";

type S = components["schemas"];

export type Inventory = S["Inventory"];
export type Group = S["Group"];
export type Device = S["Device"];
export type Settings = S["Settings"];
export type Credential = S["Credential"];
export type Route = S["Route"];
export type JumpHost = S["JumpHost"];
export type ResolvedDevice = S["ResolvedDevice"];
export type Origin = S["Origin"];
export type Vendors = S["VendorsOut"];
export type Transport = S["CollectorTransport"];

export const ARRANGEMENTS = ["device group", "site", "credential"] as const;
export type Arrange = (typeof ARRANGEMENTS)[number];

/** One section of the device table: a group row and its devices. */
export interface Section {
  /** The key of the section: the group, the site or the credential; null for no site or no credential. */
  key: string | null;
  /** The group of the section in the arrangement by device group. */
  group: Group | null;
  devices: ResolvedDevice[];
}

const byName = (a: { name: string }, b: { name: string }) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

/**
 * The sections of the devices. By device group, each group in name order,
 * a group with no device included. By site or credential, each key in
 * order, and the devices with none last.
 */
export function arrange(inv: Inventory, devices: readonly ResolvedDevice[], by: Arrange): Section[] {
  const sorted = [...devices].sort(byName);
  if (by === "device group") {
    return [...inv.groups].sort(byName).map((g) => ({ key: g.name, group: g, devices: sorted.filter((d) => d.group === g.name) }));
  }
  const keyOf = (d: ResolvedDevice): string | null => (by === "site" ? (d.site ?? null) : (d.settings.credential.value ?? null));
  const keys = [...new Set(sorted.map(keyOf))].sort((a, b) => (a === null ? 1 : b === null ? -1 : a < b ? -1 : a > b ? 1 : 0));
  return keys.map((k) => ({ key: k, group: null, devices: sorted.filter((d) => keyOf(d) === k) }));
}

/** The count of a group row: "1 device", "2 devices". */
export function deviceCount(n: number): string {
  return `${n} ${n === 1 ? "device" : "devices"}`;
}

/**
 * The state of a cell of a setting of a device. Under its group row, a
 * value that the device inherits is a hairline and a value that it sets is
 * an override. In the other arrangements, the value prints, an override in
 * the parameter colour, and a missing value is a hatch.
 */
export type CellState =
  | { kind: "inherit" }
  | { kind: "override"; text: string }
  | { kind: "value"; text: string }
  | { kind: "none" };

export function cellState(text: string | null, origin: Origin, underGroup: boolean): CellState {
  if (origin === "device") return text === null ? { kind: "none" } : { kind: "override", text };
  if (underGroup) return { kind: "inherit" };
  return text === null ? { kind: "none" } : { kind: "value", text };
}

const ALGORITHMS: Record<string, string> = { modern: "Modern", legacy: "Legacy" };

/** The SSH words of a group or a device: "Modern, exec". */
export function sshText(algorithms: string, mode: string): string {
  return `${ALGORITHMS[algorithms] ?? algorithms}, ${mode}`;
}

/** The transport of the collector of a vendor, or null for a vendor with no collector. */
export function transportOf(vendors: Vendors | null, vendor: string): Transport | null {
  return vendors?.vendors.find((v) => v.vendor === vendor)?.transport ?? null;
}

/** True when the collector of the vendor is known not to exist. */
export function noCollector(vendors: Vendors | null, vendor: string): boolean {
  return vendors !== null && transportOf(vendors, vendor) === null;
}

/** The SSH cell of a device: empty for a vendor that is not collected over SSH. */
export function deviceSsh(vendors: Vendors | null, d: ResolvedDevice, underGroup: boolean): CellState | null {
  if (transportOf(vendors, d.vendor) !== "ssh") return null;
  const a = d.settings.ssh_algorithms;
  const m = d.settings.ssh_mode;
  const origin: Origin = a.origin === "device" || m.origin === "device" ? "device" : a.origin === "group" || m.origin === "group" ? "group" : "default";
  return cellState(sshText(a.value, m.value), origin, underGroup);
}

/** The SSH words of a group row, with the defaults; null for a vendor that is not collected over SSH. */
export function groupSsh(vendors: Vendors | null, g: Group): string | null {
  if (transportOf(vendors, g.vendor) !== "ssh") return null;
  return sshText(g.settings.ssh_algorithms ?? "modern", g.settings.ssh_mode ?? "exec");
}

const TLS_TRUST: Record<string, string> = { pin: "Pin", ca: "CA", none: "None" };

/**
 * The trust policy of a group: the TLS trust of a vendor collected over
 * HTTPS, with its default; "not known" for a vendor collected over SSH,
 * whose pin policy the inventory does not hold; null for a vendor with no
 * collector.
 */
export function groupTrust(vendors: Vendors | null, g: Group): { kind: "value"; text: string } | { kind: "not known" } | null {
  const t = transportOf(vendors, g.vendor);
  if (t === "https") {
    const v = g.settings.tls_trust ?? "pin";
    return { kind: "value", text: TLS_TRUST[v] ?? v };
  }
  return t === "ssh" ? { kind: "not known" } : null;
}

/** The names of the settings that a device sets in place of its group, in the order of the settings. */
export function overrides(d: ResolvedDevice): string[] {
  return Object.entries(d.settings)
    .filter(([, r]) => (r as { origin: Origin }).origin === "device")
    .map(([k]) => k);
}

/** The counts of the result line. */
export interface Counts {
  devices: number;
  groups: number;
  noSite: number;
  noCollector: number;
  seen: number;
}

export function counts(inv: Inventory, vendors: Vendors | null, seen: readonly SeenRow[]): Counts {
  const vendorOf = new Map(inv.groups.map((g) => [g.name, g.vendor]));
  return {
    devices: inv.devices.length,
    groups: inv.groups.length,
    noSite: inv.devices.filter((d) => !d.site).length,
    noCollector: inv.devices.filter((d) => noCollector(vendors, vendorOf.get(d.group) ?? "")).length,
    seen: new Set(seen.map((s) => s.name)).size,
  };
}

/** A count with its noun: "1 device has", "2 devices have". */
export function devicesHave(n: number): string {
  return n === 1 ? "1 device has" : `${n} devices have`;
}

/** The facts of a device that the collector reads, from the table `devices` of the twin. */
export interface Facts {
  serial: string | null;
  serialReason: string | null;
  platform: string | null;
  platformReason: string | null;
  collectedAt: string | null;
}

/**
 * The facts of each device by name, from the rows of the table `devices`.
 * A device of the store with no row of its own, such as a UniFi console,
 * takes the newest time of the rows of its manifest, with no other fact.
 */
export function factsByName(columns: readonly string[], rows: readonly (readonly unknown[])[]): Map<string, Facts> {
  const at = (n: string) => columns.indexOf(n);
  const text = (r: readonly unknown[], n: string): string | null => {
    const i = at(n);
    const v = i < 0 ? null : r[i];
    return typeof v === "string" && v !== "" ? v : null;
  };
  const out = new Map<string, Facts>();
  for (const r of rows) {
    const name = text(r, "device");
    if (!name) continue;
    out.set(name, {
      serial: text(r, "serial"),
      serialReason: text(r, "serial_reason"),
      platform: text(r, "platform"),
      platformReason: text(r, "platform_reason"),
      collectedAt: text(r, "collected_at"),
    });
  }
  const consoles = new Map<string, string>();
  for (const r of rows) {
    const store = text(r, "store_device");
    const at = text(r, "collected_at");
    if (!store || !at || out.has(store)) continue;
    const prev = consoles.get(store);
    if (!prev || at > prev) consoles.set(store, at);
  }
  for (const [store, at] of consoles) {
    out.set(store, { serial: null, serialReason: null, platform: null, platformReason: null, collectedAt: at });
  }
  return out;
}

/** The age of a time `YYYY-MM-DDTHH:MM:SSZ` at the time `now` in ms: "2 min ago". */
export function ageText(at: string, now: number): string | null {
  const t = Date.parse(at);
  if (Number.isNaN(t)) return null;
  const s = Math.max(0, Math.floor((now - t) / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

/** The cell "last cycle" of a device. */
export type CycleCell = { kind: "no collector"; vendor: string } | { kind: "age"; text: string } | { kind: "not known" };

export function lastCycle(vendors: Vendors | null, d: ResolvedDevice, facts: Facts | undefined, now: number): CycleCell {
  if (noCollector(vendors, d.vendor)) return { kind: "no collector", vendor: d.vendor };
  const age = facts?.collectedAt ? ageText(facts.collectedAt, now) : null;
  return age ? { kind: "age", text: age } : { kind: "not known" };
}

/** An LLDP or CDP record of the twin that names a neighbour with no device. */
export interface SeenRow {
  name: string;
  device: string;
  port: string;
  protocol: string;
}

/** The rows of the table `neighbours` whose neighbour is not a device of the inventory, one for each name. */
export function seenRows(columns: readonly string[], rows: readonly (readonly unknown[])[], inventory: readonly string[]): SeenRow[] {
  const at = (n: string) => columns.indexOf(n);
  const names = new Set(inventory);
  const out: SeenRow[] = [];
  const done = new Set<string>();
  for (const r of rows) {
    const s = (n: string) => String(r[at(n)] ?? "");
    const name = s("neighbour");
    if (!name || names.has(name) || done.has(name)) continue;
    done.add(name);
    out.push({ name, device: s("device"), port: s("port"), protocol: s("protocol") });
  }
  return out;
}

/** "LLDP" or "CDP" for the protocol word of the table. */
export function protocolWord(p: string): string {
  return p.toUpperCase();
}

/** The device groups whose devices use a credential, in name order. */
export function credentialGroups(inv: Inventory, credential: string): string[] {
  const out = new Set<string>();
  for (const g of inv.groups) if (g.settings.credential === credential) out.add(g.name);
  for (const d of inv.devices) if (d.settings.credential === credential) out.add(d.group);
  return [...out].sort();
}

/** True when a credential is the login of a jump host or of a proxy. */
export function usedByRoutes(inv: Inventory, credential: string): boolean {
  return inv.jump_hosts.some((j) => j.credential === credential) || inv.routes.some((r) => r.proxy_credential === credential);
}

/** The words of the source of a credential: "env file, key", "env URL, key". */
export function secretFrom(c: Credential): string {
  return c.source === "env" ? "env file, key" : "env URL, key";
}

/** One hop of a route: its words and its value. */
export interface Hop {
  words: string;
  value: string;
}

const SCHEMES: Record<string, string> = { http: "HTTP", socks5: "SOCKS5", socks5h: "SOCKS5h" };

/** The hops of a route: the proxy, then each jump host. An empty list is a direct connection. */
export function hops(inv: Inventory, r: Route): Hop[] {
  const out: Hop[] = [];
  if (r.proxy) {
    const m = /^([a-z0-9]+):\/\/(.*)$/i.exec(r.proxy);
    const scheme = m ? (SCHEMES[m[1]!.toLowerCase()] ?? m[1]!) : "";
    out.push({ words: `${scheme} proxy`.trim(), value: m ? m[2]! : r.proxy });
  }
  for (const name of r.jumps) {
    const j = inv.jump_hosts.find((x) => x.name === name);
    out.push({ words: out.length ? ", then jump host" : "jump host", value: j?.address ?? name });
  }
  return out;
}

/** The credentials of a route: the login of the proxy and of each jump host, each one time, in order. */
export function routeCredentials(inv: Inventory, r: Route): string[] {
  const out: string[] = [];
  const add = (c: string | null | undefined) => {
    if (c && !out.includes(c)) out.push(c);
  };
  add(r.proxy_credential);
  for (const name of r.jumps) add(inv.jump_hosts.find((x) => x.name === name)?.credential);
  return out;
}

/** The stored record of a device, which a write replaces whole. */
export function storedDevice(inv: Inventory, name: string): Device | null {
  return inv.devices.find((d) => d.name === name) ?? null;
}

/** An optional text of an input: null when empty. */
export function optional(text: string): string | null {
  const t = text.trim();
  return t === "" ? null : t;
}

/** The body of a write of the site and the location of a stored device. */
export function siteBody(stored: Device, site: string, location: string): Device {
  return { ...stored, site: optional(site), location: optional(location) };
}

/** The body of a write that moves a stored device to another group; its own settings stay. */
export function moveBody(stored: Device, group: string): Device {
  return { ...stored, group };
}

/** True when a trimmed name is the name of one of the records. */
export function nameTaken(records: readonly { name: string }[], name: string): boolean {
  const n = name.trim();
  return records.some((r) => r.name === n);
}

/** The body of a new device. */
export function newDeviceBody(f: { name: string; address: string; group: string; site: string; location: string }): Device {
  return {
    name: f.name.trim(),
    group: f.group,
    address: f.address.trim(),
    site: optional(f.site),
    location: optional(f.location),
    settings: {},
  };
}

/** The body of a new group. */
export function newGroupBody(f: { name: string; vendor: string; credential: string; route: string }): Group {
  const settings: Settings = {};
  if (f.credential) settings.credential = f.credential;
  if (f.route) settings.route = f.route;
  return { name: f.name.trim(), vendor: f.vendor.trim(), settings };
}

/** The body of a new credential reference. */
export function newCredentialBody(f: { name: string; source: Credential["source"]; key: string }): Credential {
  return { name: f.name.trim(), source: f.source, key: f.key.trim() };
}

/** The body of a new route. */
export function newRouteBody(f: { name: string; proxy: string; proxyCredential: string; jumps: readonly string[] }): Route {
  const r: Route = { name: f.name.trim(), jumps: [...f.jumps] };
  const proxy = optional(f.proxy);
  if (proxy) {
    r.proxy = proxy;
    if (f.proxyCredential) r.proxy_credential = f.proxyCredential;
  }
  return r;
}
