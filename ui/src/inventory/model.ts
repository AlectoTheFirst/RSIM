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
export type CredentialPut = S["CredentialPut"];
export type CredentialKind = S["CredentialKind"];
export type SecretKeyOut = S["SecretKeyOut"];
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


/** The SSH words of a group or a device: "modern, exec". */
export function sshText(algorithms: string, mode: string): string {
  return `${algorithms}, ${mode}`;
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

const TLS_TRUST: Record<string, string> = { pin: "pin", ca: "CA", none: "none" };

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
  if (c.source === "managed") return `managed ${KIND_WORDS[c.kind ?? "password"]}`;
  return c.source === "env" ? "env file, key" : "env URL, key";
}

/** The words of the kind of a managed credential. */
export const KIND_WORDS: Record<CredentialKind, string> = { password: "password", "ssh-key": "SSH key", "api-key": "API key" };

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

/** The body of a new device with the console site and the settings of a draft. */
export function newDeviceChecked(f: Parameters<typeof newDeviceBody>[0], draft: Draft): Checked<Device> {
  const base = newDeviceBody(f);
  const settings = settingsBody({}, draft);
  if (!settings.ok) return settings;
  const out: Device = { ...base, settings: settings.body };
  setOptional(out, "console_site", optional(draft.console_site ?? ""));
  return { ok: true, body: out };
}

/** The body of a new group. */
export function newGroupBody(f: { name: string; vendor: string; credential: string; route: string }): Group {
  const settings: Settings = {};
  if (f.credential) settings.credential = f.credential;
  if (f.route) settings.route = f.route;
  return { name: f.name.trim(), vendor: f.vendor.trim(), settings };
}

/** The body of a new group with the description and the other settings of a draft. */
export function newGroupChecked(f: Parameters<typeof newGroupBody>[0], draft: Draft): Checked<Group> {
  const base = newGroupBody(f);
  const settings = settingsBody(base.settings, draft);
  if (!settings.ok) return settings;
  const out: Group = { ...base, settings: settings.body };
  setOptional(out, "description", optional(draft.description ?? ""));
  return { ok: true, body: out };
}

/** The body of a new credential reference. */
export function newCredentialBody(f: { name: string; source: Credential["source"]; key: string }): Credential {
  return { name: f.name.trim(), source: f.source, key: f.key.trim() };
}

/** The fields of the form of a credential. An empty secret keeps the stored secret. */
export interface CredentialFields {
  source: Credential["source"];
  key: string;
  kind: CredentialKind;
  user: string;
  secret: string;
  passphrase: string;
}

/** The fields of a stored credential, or of a new one; the secret is always empty. */
export function credentialFields(c?: Credential): CredentialFields {
  return {
    source: c?.source ?? "managed",
    key: c?.key ?? "",
    kind: c?.kind ?? "password",
    user: c?.user ?? "",
    secret: "",
    passphrase: "",
  };
}

/**
 * The PUT body of a credential from its form: the stored record, if any,
 * with the fields of the form. A managed credential needs a secret when it
 * is new, when it was not managed and when its kind changes.
 */
export function credentialBody(stored: Credential | undefined, name: string, f: CredentialFields): Checked<CredentialPut> {
  const n = name.trim();
  const refuse = (title: string, detail: string): Checked<CredentialPut> => ({ ok: false, problem: { title, detail } });
  const body: CredentialPut = { name: n, source: f.source, key: null, kind: null, user: null, description: stored?.description ?? null, secret_revision: null, secret: null };
  if (f.source !== "managed") {
    const key = f.key.trim();
    if (!/^[A-Z0-9_]+$/.test(key)) return refuse("key not valid", `the key of ${n}: upper-case letters, digits and _`);
    body.key = key;
    return { ok: true, body };
  }
  body.kind = f.kind;
  if (f.kind !== "api-key") {
    const user = f.user.trim();
    if (!user) return refuse("user empty", `${n} needs a user`);
    body.user = user;
  }
  const keeps = stored?.source === "managed" && stored.kind === f.kind;
  if (f.secret) {
    if (f.kind === "ssh-key" && !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(f.secret)) {
      return refuse("private key not valid", `${n}: not OpenSSH or PEM`);
    }
    body.secret = { value: f.secret, passphrase: f.kind === "ssh-key" && f.passphrase ? f.passphrase : null };
  } else if (!keeps) {
    return refuse("secret empty", `${n} needs its ${KIND_WORDS[f.kind]}`);
  }
  return { ok: true, body };
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

/** The text of a refused write or of a check before a write: a title, with the detail as the title of its element. */
export interface Problem {
  title: string;
  detail: string;
}

/** A body of a write, or the problem of a check that refuses it. */
export type Checked<T> = { ok: true; body: T } | { ok: false; problem: Problem };

export type SettingKey = keyof Settings & string;

/** How a setting is edited and checked, its default, its transport and whether the collector reads it. */
export interface SettingField {
  key: SettingKey;
  /** The name of the setting in the UI. */
  label: string;
  kind: "credential" | "route" | "choice" | "number" | "text";
  /** The values of a choice. */
  choices?: readonly string[];
  /** The range of a number. */
  min?: number;
  max?: number;
  /** The text of the default: "none" or "direct" for a setting with no default value. */
  fallback: string;
  /** The transport of the setting; null for each transport. */
  transport: Transport | null;
  /** The vendors of the setting; absent for each vendor of the transport. */
  vendors?: readonly string[];
  /** True for a setting that the collector does not read. */
  unread?: boolean;
}

/** The largest number that the inventory database stores. */
const I32_MAX = 2147483647;

/** The settings of a group or a device, in the order of the settings. */
export const SETTING_FIELDS: readonly SettingField[] = [
  { key: "credential", label: "credential", kind: "credential", fallback: "none", transport: null },
  { key: "route", label: "route", kind: "route", fallback: "direct", transport: null },
  { key: "ssh_algorithms", label: "SSH algorithms", kind: "choice", choices: ["modern", "legacy"], fallback: "modern", transport: "ssh" },
  { key: "ssh_mode", label: "SSH mode", kind: "choice", choices: ["exec", "shell", "connection"], fallback: "exec", transport: "ssh" },
  { key: "ssh_channels", label: "SSH channels", kind: "number", min: 1, max: I32_MAX, fallback: "1", transport: "ssh", vendors: ["nxos", "iosxr", "iosxe"] },
  { key: "nxos_json", label: "NX-OS JSON", kind: "choice", choices: ["plain", "native"], fallback: "plain", transport: "ssh", vendors: ["nxos"] },
  { key: "tls_trust", label: "TLS trust", kind: "choice", choices: ["pin", "ca", "none"], fallback: "pin", transport: "https" },
  { key: "tls_ca_file", label: "TLS CA file", kind: "text", fallback: "none", transport: "https" },
  { key: "capture_bgp", label: "BGP sections", kind: "choice", choices: ["off", "sessions", "all"], fallback: "sessions", transport: null },
  { key: "timeout_seconds", label: "device time limit", kind: "number", min: 1, max: 86400, fallback: "45", transport: null },
  { key: "section_timeout_seconds", label: "section time limit", kind: "number", min: 1, max: 86400, fallback: "20", transport: null },
  { key: "request_timeout_seconds", label: "request time limit", kind: "number", min: 1, max: 86400, fallback: "60", transport: "https", unread: true },
  { key: "paged_section_timeout_seconds", label: "paged section time limit", kind: "number", min: 1, max: 86400, fallback: "300", transport: "https", unread: true },
  { key: "retries", label: "retries", kind: "number", min: 0, max: 10, fallback: "0", transport: null, unread: true },
  { key: "ha", label: "HA", kind: "choice", choices: ["none", "all", "one"], fallback: "none", transport: null, unread: true },
];

/** The text of a stored value in an input: empty for none. */
export function valueText(v: unknown): string {
  return v === null || v === undefined ? "" : String(v);
}

/** The value of the text of a setting: null for an empty text, which inherits. */
export function parseSetting(f: SettingField, text: string): { ok: true; value: string | number | null } | { ok: false; problem: Problem } {
  const t = text.trim();
  if (t === "") return { ok: true, value: null };
  if (f.kind === "number") {
    const range = `${f.key} from ${f.min} to ${f.max}`;
    if (!/^\d+$/.test(t)) return { ok: false, problem: { title: `${f.key} not a whole number`, detail: range } };
    const n = Number(t);
    if (n < f.min! || n > f.max!) return { ok: false, problem: { title: `${f.key} out of range`, detail: range } };
    return { ok: true, value: n };
  }
  if (f.kind === "choice" && !f.choices!.includes(t)) {
    return { ok: false, problem: { title: `${f.key} not known`, detail: `${f.key} is one of ${f.choices!.join(", ")}` } };
  }
  return { ok: true, value: t };
}

/**
 * Whether the collector reads a setting of a device of the vendor: null
 * when it does or when the vendor has no collector, else the words of the
 * reason.
 */
export function notUsed(f: SettingField, vendors: Vendors | null, vendor: string): string | null {
  const t = transportOf(vendors, vendor);
  if (t === null) return null;
  if (f.transport !== null && f.transport !== t) return `not used over ${t.toUpperCase()}`;
  if (f.vendors && !f.vendors.includes(vendor)) return `not used by ${vendor}`;
  return f.unread ? "not read by the collector" : null;
}

/** The value that an empty setting takes: the value of the group, else the default. */
export function inherited(f: SettingField, group: Settings | null): { from: "group" | "default"; text: string } {
  const v = group?.[f.key];
  return v === null || v === undefined ? { from: "default", text: f.fallback } : { from: "group", text: String(v) };
}

/** The texts of an edit of a record: one text for each field, an empty text for none. */
export type Draft = Record<string, string>;

/** The texts of the settings. */
export function settingsDraft(s: Settings): Draft {
  const out: Draft = {};
  for (const f of SETTING_FIELDS) out[f.key] = valueText(s[f.key]);
  return out;
}

/** The texts of the fields of a stored device and of its settings. */
export function deviceDraft(d: Device): Draft {
  return {
    address: d.address,
    group: d.group,
    site: valueText(d.site),
    location: valueText(d.location),
    console_site: valueText(d.console_site),
    ...settingsDraft(d.settings),
  };
}

/** The texts of the fields of a stored group and of its settings. */
export function groupDraft(g: Group): Draft {
  return { vendor: g.vendor, description: valueText(g.description), ...settingsDraft(g.settings) };
}

/** The draft with the texts of `next`, except each text that differs from `before`: an edit that is not written stays. */
export function rebase(draft: Draft, before: Draft, next: Draft): Draft {
  const out: Draft = { ...next };
  for (const [k, v] of Object.entries(draft)) if (v !== before[k]) out[k] = v;
  return out;
}

/** Sets an optional field, or removes it for null. */
function setOptional<T extends object>(o: T, key: string, value: unknown): void {
  const r = o as Record<string, unknown>;
  if (value === null || value === undefined) delete r[key];
  else r[key] = value;
}

/** The stored settings with each setting of the draft whose text differs from the stored text. */
export function settingsBody(stored: Settings, draft: Draft): Checked<Settings> {
  const out: Settings = { ...stored };
  for (const f of SETTING_FIELDS) {
    const text = draft[f.key];
    if (text === undefined || text.trim() === valueText(stored[f.key])) continue;
    const p = parseSetting(f, text);
    if (!p.ok) return p;
    setOptional(out, f.key, p.value);
  }
  return { ok: true, body: out };
}

/** The stored record with each optional text field of the draft whose text differs. */
function optionalFields<T extends object>(out: T, stored: T, draft: Draft, keys: readonly string[]): void {
  const s = stored as Record<string, unknown>;
  for (const k of keys) {
    const text = draft[k];
    if (text === undefined || text.trim() === valueText(s[k])) continue;
    setOptional(out, k, optional(text));
  }
}

/** The body of a write of a stored device: the stored record with only the fields of the draft that differ. */
export function deviceBody(stored: Device, draft: Draft): Checked<Device> {
  const settings = settingsBody(stored.settings, draft);
  if (!settings.ok) return settings;
  const out: Device = { ...stored, settings: settings.body };
  if (draft.address !== undefined && draft.address.trim() !== stored.address) {
    const a = draft.address.trim();
    if (a === "") return { ok: false, problem: { title: "address empty", detail: `${stored.name} needs an address` } };
    out.address = a;
  }
  if (draft.group !== undefined && draft.group !== stored.group) out.group = draft.group;
  optionalFields(out, stored, draft, ["site", "location", "console_site"]);
  return { ok: true, body: out };
}

/** The body of a write of a stored group: the stored record with only the fields of the draft that differ. */
export function groupBody(stored: Group, draft: Draft): Checked<Group> {
  const settings = settingsBody(stored.settings, draft);
  if (!settings.ok) return settings;
  const out: Group = { ...stored, settings: settings.body };
  if (draft.vendor !== undefined && draft.vendor.trim() !== stored.vendor) {
    const v = draft.vendor.trim();
    if (v === "") return { ok: false, problem: { title: "vendor empty", detail: `${stored.name} needs a vendor` } };
    out.vendor = v;
  }
  optionalFields(out, stored, draft, ["description"]);
  return { ok: true, body: out };
}

/** True when 2 bodies are the same record. */
export function sameRecord(a: unknown, b: unknown): boolean {
  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
}

/** A value with its keys in order and with no null field. */
function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) {
      const x = (v as Record<string, unknown>)[k];
      if (x !== null && x !== undefined) out[k] = canonical(x);
    }
    return out;
  }
  return v;
}

/** The fields of a route in an add row or an edit. */
export interface RouteFields {
  proxy: string;
  proxyCredential: string;
  jumps: readonly string[];
}

/** The fields of a stored route. */
export function routeFields(r: Route): RouteFields {
  return { proxy: valueText(r.proxy), proxyCredential: valueText(r.proxy_credential), jumps: [...r.jumps] };
}

/** The body of a write of a stored route; with no proxy, the route has no proxy login. */
export function routeBody(stored: Route, f: RouteFields): Route {
  const out: Route = { ...stored, jumps: [...f.jumps] };
  const proxy = optional(f.proxy);
  setOptional(out, "proxy", proxy);
  setOptional(out, "proxy_credential", proxy ? optional(f.proxyCredential) : null);
  return out;
}

/** The fields of a jump host in an add row or an edit. */
export interface JumpHostFields {
  address: string;
  credential: string;
  ssh_algorithms: JumpHost["ssh_algorithms"];
}

/** The body of a new jump host. */
export function newJumpHostBody(f: JumpHostFields & { name: string }): JumpHost {
  return { name: f.name.trim(), address: f.address.trim(), credential: f.credential, ssh_algorithms: f.ssh_algorithms };
}

/** The body of a write of a stored jump host. */
export function jumpHostBody(stored: JumpHost, f: JumpHostFields): JumpHost {
  return { ...stored, address: f.address.trim(), credential: f.credential, ssh_algorithms: f.ssh_algorithms };
}

/** The routes that name a jump host. */
export function jumpHostRoutes(inv: Inventory, name: string): string[] {
  return inv.routes.filter((r) => r.jumps.includes(name)).map((r) => r.name);
}
