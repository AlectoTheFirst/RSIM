// The endpoint picker of the query bar: the endpoints of the twin that
// match the text of an address field, and the state of the keys of its list.

/** The most endpoints that the list shows. */
export const PICKER_MAX = 10;

/** One endpoint of the twin: its name, its addresses and where it attaches. */
export interface EndpointRow {
  name: string;
  addresses: string[];
  /** The places as `<device>/<interface>`, from the attachment records. */
  places: string[];
}

/** One proposal of the list: an endpoint and the address that a choice fills in. */
export interface Suggestion extends EndpointRow {
  address: string;
}

/** The rows of a table answer as records by column name. */
export function recordsOf(t: { columns: string[]; rows: unknown[][] }): Record<string, unknown>[] {
  return t.rows.map((r) => Object.fromEntries(t.columns.map((c, i) => [c, r[i]])));
}

const text = (v: unknown): string => (v === null || v === undefined ? "" : String(v));
const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(text) : v == null ? [] : [text(v)]);

/** The endpoints of rows of the table `endpoints`, each once. */
export function endpointRows(records: Record<string, unknown>[]): EndpointRow[] {
  const out = new Map<string, EndpointRow>();
  for (const r of records) {
    const name = text(r["endpoint"]);
    if (name && !out.has(name)) out.set(name, { name, addresses: list(r["addresses"]), places: [] });
  }
  return [...out.values()];
}

/** The places of each host, from rows of the table `attachments`. */
export function placesByHost(records: Record<string, unknown>[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const r of records) {
    const host = text(r["host"]);
    if (!host) continue;
    const place = `${text(r["device"])}/${text(r["interface"])}`;
    const ps = out.get(host) ?? [];
    if (!ps.includes(place)) ps.push(place);
    out.set(host, ps);
  }
  return out;
}

/** The text of a field that the picker looks up, or null for a text it does not look up. */
export function pickerQuery(value: string): string | null {
  const q = value.trim();
  if (q === "" || /[,/\s]/.test(q)) return null;
  return q;
}

/**
 * The endpoints that match a text: by a prefix of the name or of an
 * address, with no regard to case. An endpoint with no address is left
 * out, because a choice fills in an address. The order is by name, and the
 * list has at most `max` endpoints.
 */
export function matchEndpoints(rows: readonly EndpointRow[], value: string, max = PICKER_MAX): Suggestion[] {
  const q = pickerQuery(value)?.toLowerCase();
  if (!q) return [];
  const out: Suggestion[] = [];
  for (const r of [...rows].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    if (r.addresses.length === 0) continue;
    const byAddress = r.addresses.find((a) => a.toLowerCase().startsWith(q));
    if (!byAddress && !r.name.toLowerCase().startsWith(q)) continue;
    if (out.some((s) => s.name === r.name)) continue;
    out.push({ ...r, address: byAddress ?? r.addresses[0]! });
    if (out.length === max) break;
  }
  return out;
}

/** The state of the list: open or closed, and the index of the active proposal, or -1. */
export interface PickerState {
  open: boolean;
  active: number;
}

export const PICKER_CLOSED: PickerState = { open: false, active: -1 };

/** What a key does to the list: `choose` fills in the active proposal. */
export type PickerAction = "none" | "choose";

/**
 * The effect of a key on a list of `count` proposals. `handled` is false
 * for a key that the list leaves to the field, for example Enter with no
 * active proposal, which runs the query.
 */
export function pickerKey(
  s: PickerState,
  key: string,
  count: number,
): { state: PickerState; action: PickerAction; handled: boolean } {
  const shown = s.open && count > 0;
  switch (key) {
    case "ArrowDown":
      if (count === 0) return { state: s, action: "none", handled: false };
      return { state: { open: true, active: shown ? Math.min(count - 1, s.active + 1) : 0 }, action: "none", handled: true };
    case "ArrowUp":
      if (!shown) return { state: s, action: "none", handled: false };
      return { state: { open: true, active: Math.max(0, s.active - 1) }, action: "none", handled: true };
    case "Enter":
      if (!shown || s.active < 0 || s.active >= count) return { state: s, action: "none", handled: false };
      return { state: PICKER_CLOSED, action: "choose", handled: true };
    case "Escape":
      if (!shown) return { state: s, action: "none", handled: false };
      return { state: PICKER_CLOSED, action: "none", handled: true };
    default:
      return { state: s, action: "none", handled: false };
  }
}

/** The addresses of a row of the table `endpoints`, from its column `addresses`. */
export function endpointAddresses(columns: readonly string[], row: readonly unknown[]): string[] {
  const j = columns.indexOf("addresses");
  return j < 0 ? [] : list(row[j]).filter((a) => a !== "");
}

// The entry point picker of the ingress field: a list of the devices of the
// twin, then a list of the entry interfaces of the chosen device.

/** The stage of the entry point list for a text of the ingress field. */
export type IngressStage = { stage: "device"; text: string } | { stage: "interface"; device: string; text: string };

/**
 * The stage of a text: with no `/`, the list of devices filtered by the
 * text; with a `/`, the list of the entry interfaces of the device before
 * it, filtered by the text after it.
 */
export function ingressStage(value: string): IngressStage {
  const v = value.trim();
  const at = v.indexOf("/");
  return at < 0 ? { stage: "device", text: v } : { stage: "interface", device: v.slice(0, at), text: v.slice(at + 1) };
}

/** One item of the entry point list: its name, the text after it, the value of the field after a choice, and whether the choice ends the list. */
export interface EntryOption {
  name: string;
  detail: string;
  value: string;
  done: boolean;
}

/** The word after the entry point of the shown answer. */
export const FOUND = "found";

const startsWith = (s: string, t: string) => s.toLowerCase().startsWith(t.toLowerCase());

/**
 * The device list: the entry point of the shown answer first, then the
 * devices of rows of the table `devices` that start with the text, each
 * once, with the vendor when the table has it. A choice of a device
 * fills in `<device>/`, and a choice of the entry point fills it in whole.
 */
export function deviceOptions(
  records: readonly Record<string, unknown>[],
  found: string | null,
  value: string,
  max = PICKER_MAX,
): EntryOption[] {
  const q = value.trim();
  const out: EntryOption[] = [];
  if (found && startsWith(found, q)) out.push({ name: found, detail: FOUND, value: found, done: true });
  const seen = new Set<string>();
  for (const r of records) {
    const name = text(r["device"]);
    if (!name || seen.has(name) || !startsWith(name, q)) continue;
    seen.add(name);
    out.push({ name, detail: text(r["vendor"]), value: `${name}/`, done: false });
    if (seen.size === max) break;
  }
  return out;
}

/**
 * The forms of the name of an entry function of a device: `<device>/in/<interface>`
 * for an interface of a router or a routed port, and `<device>/host/<port>`
 * for a switch port or a wireless network with hosts behind it.
 */
export const ENTRY_FORMS = ["in", "host"] as const;

/** The entry interface of a function of `device`, or null for a name of another form. */
export function entryInterface(device: string, fn: string): string | null {
  for (const form of ENTRY_FORMS) {
    const prefix = `${device}/${form}/`;
    if (fn.startsWith(prefix) && fn.length > prefix.length) return fn.slice(prefix.length);
  }
  return null;
}

/**
 * The interface list of a device: the entry interface of each function of
 * rows of the table `functions` of that device, each once, in name order,
 * that starts with the text after the `/`.
 */
export function interfaceOptions(records: readonly Record<string, unknown>[], value: string, max = PICKER_MAX): EntryOption[] {
  const s = ingressStage(value);
  if (s.stage !== "interface") return [];
  const names = new Set<string>();
  for (const r of records) {
    const n = entryInterface(s.device, text(r["function"]));
    if (n !== null) names.add(n);
  }
  return [...names]
    .filter((n) => startsWith(n, s.text))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    .slice(0, max)
    .map((n) => ({ name: n, detail: "", value: `${s.device}/${n}`, done: true }));
}

/** A table request: the table and its parameters. */
export interface TableRequest {
  table: string;
  params: Record<string, string>;
}

/**
 * The table requests of the list of a stage: the devices, or one request
 * for each form of the entry functions of the device, by the prefix
 * `<device>/<form>/<text>`.
 */
export function ingressRequests(s: IngressStage, max = PICKER_MAX): TableRequest[] {
  const limit = String(max);
  if (s.stage === "device") return [{ table: "devices", params: s.text ? { "device.prefix": s.text, limit } : { limit } }];
  return ENTRY_FORMS.map((form) => ({
    table: "functions",
    params: { device: s.device, kind: "ingress", "function.prefix": `${s.device}/${form}/${s.text}`, columns: "function", limit },
  }));
}
