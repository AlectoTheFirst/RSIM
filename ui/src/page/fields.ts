// The fields of the query bar: their order, their labels and help text,
// the names that a field takes, the check of the form of a value and the
// query type that the values give. The
// number ranges and the names come from the OpenAPI document; the checks
// follow the argument parser of the server.
import { FIELD_SCHEMA, type FieldName } from "../api/fields";

/** The query type: a path query or a set query. */
export type Mode = "path" | "set";

/** The fields of the query bar, in order. */
export const QUERY_FIELDS = [
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "network.transport",
  "ingress",
  "network.iana_number",
  "tcp_flags",
  "icmp_type",
  "icmp_code",
  "fragment",
  "dscp",
  "ecn",
  "source.mac",
  "destination.mac",
  "network.vlan.id",
  "l2_priority",
  "network.vlan.tpid",
  "network.inner.vlan.id",
  "inner_l2_priority",
  "network.inner.vlan.tpid",
  "reply",
  "unstated",
] as const satisfies readonly FieldName[];
export type QueryField = (typeof QUERY_FIELDS)[number];

/** Whether a query type takes a field: a set query does not take the fields of a path query only. */
export function takes(mode: Mode, k: QueryField): boolean {
  return mode === "path" || FIELD_SCHEMA[k].set !== null;
}

/**
 * The value of `unstated` that leaves the query as it is: an unstated
 * field has all values. The request, the commands and the MCP call leave
 * the field out with this value.
 */
export const UNSTATED_ALL = "all";

/** The fields that show while the query bar is edited. Each other field shows when it has a value or is added. */
export const BASE_FIELDS: ReadonlySet<QueryField> = new Set([
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "network.transport",
]);

/** The form of the values of a field. */
export type Kind = "address" | "mac" | "ingress" | "number" | "names" | "icmp" | "flags" | "boolean";

export function kindOf(k: QueryField): Kind {
  const s = FIELD_SCHEMA[k];
  if (s.type === "boolean") return "boolean";
  if (k === "ingress") return "ingress";
  if (k.endsWith(".ip")) return "address";
  if (k.endsWith(".mac")) return "mac";
  if (s.type === "list") return "flags";
  if (s.type === "integer") return s.values.length ? "icmp" : "number";
  return "names";
}

/** The largest number of a field, or null. */
export function maxOf(k: QueryField): number | null {
  return FIELD_SCHEMA[k].maximum;
}

/**
 * The width of the value of each field in characters: room for a normal
 * value, so that a value that is typed does not move the fields after it.
 */
export const FIELD_CHARS: Partial<Record<QueryField, number>> = {
  "source.ip": 15,
  "destination.ip": 15,
  "source.port": 5,
  "destination.port": 5,
  "network.transport": 6,
  ingress: 18,
  "source.mac": 17,
  "destination.mac": 17,
  tcp_flags: 7,
  "network.vlan.tpid": 5,
  "network.inner.vlan.tpid": 5,
};

/** The label of each field in the UI: a short noun phrase. */
export const FIELD_LABELS: Record<QueryField, string> = {
  "source.ip": "source address",
  "source.port": "source port",
  "destination.ip": "destination address",
  "destination.port": "destination port",
  "network.transport": "transport protocol",
  ingress: "entry point",
  "network.iana_number": "IP protocol number",
  tcp_flags: "TCP flags",
  icmp_type: "ICMP type",
  icmp_code: "ICMP code",
  fragment: "fragment state",
  dscp: "DSCP",
  ecn: "ECN",
  "source.mac": "source MAC",
  "destination.mac": "destination MAC",
  "network.vlan.id": "VLAN tag",
  l2_priority: "layer 2 priority",
  "network.vlan.tpid": "VLAN TPID",
  "network.inner.vlan.id": "inner VLAN tag",
  inner_l2_priority: "inner tag priority",
  "network.inner.vlan.tpid": "inner VLAN TPID",
  reply: "reply run",
  unstated: "unstated fields",
};

export function labelOf(k: QueryField): string {
  return FIELD_LABELS[k];
}

const names = (vs: readonly string[]) => vs.join(", ");

/**
 * The form of a value of a field, as a short phrase. A comma separates the
 * values of a list, and + joins the TCP flags of one packet.
 */
export function formOf(k: QueryField): string {
  const max = maxOf(k);
  const vs = FIELD_SCHEMA[k].values;
  switch (kindOf(k)) {
    case "address":
      return "addresses and prefixes, comma list";
    case "mac":
      return "MAC addresses, comma list";
    case "ingress":
      return "<device>/<interface>";
    case "boolean":
      return "true or false";
    case "number":
      return `0 to ${max} and ranges a-b, comma list`;
    case "icmp":
      return `0 to ${max}, ${names(vs)}, ranges a-b, comma list`;
    case "names":
      return k === "unstated" ? names(vs) : `${names(vs)}, comma list`;
    case "flags":
      return "flags with +, 0 to 255, ranges a-b, comma list";
  }
}

// The forms of the values, as the parser of the server reads them.

function ipv4Bits(s: string): bigint | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let v = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p[0] === "0") || Number(p) > 255) return null;
    v = (v << 8n) | BigInt(p);
  }
  return v;
}

/** The 16-bit groups of a part of an IPv6 address, or null. */
function v6Groups(s: string, lastMayBeV4: boolean): number[] | null {
  if (s === "") return [];
  const parts = s.split(":");
  const out: number[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]!;
    if (lastMayBeV4 && i === parts.length - 1 && p.includes(".")) {
      const v4 = ipv4Bits(p);
      if (v4 === null) return null;
      out.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
    } else if (/^[0-9a-fA-F]{1,4}$/.test(p)) {
      out.push(parseInt(p, 16));
    } else {
      return null;
    }
  }
  return out;
}

function ipv6Bits(s: string): bigint | null {
  const at = s.indexOf("::");
  let groups: number[] | null;
  if (at < 0) {
    groups = v6Groups(s, true);
    if (!groups || groups.length !== 8) return null;
  } else {
    if (s.indexOf("::", at + 1) >= 0) return null;
    const head = v6Groups(s.slice(0, at), false);
    const tail = v6Groups(s.slice(at + 2), true);
    if (!head || !tail || head.length + tail.length > 7) return null;
    groups = [...head, ...new Array<number>(8 - head.length - tail.length).fill(0), ...tail];
  }
  return groups.reduce((v, g) => (v << 16n) | BigInt(g), 0n);
}

/** An IP address: its bits and its length in bits, or null. */
export function parseIp(s: string): { bits: bigint; width: number } | null {
  const v4 = ipv4Bits(s);
  if (v4 !== null) return { bits: v4, width: 32 };
  const v6 = ipv6Bits(s);
  return v6 === null ? null : { bits: v6, width: 128 };
}

/** An unsigned integer as Rust reads it: digits with an optional `+`. */
function uint(s: string): number | null {
  return /^\+?\d+$/.test(s) ? Number(s) : null;
}

/** A prefix: an address with an optional length and no host bits. */
function isPrefix(s: string): boolean {
  const slash = s.indexOf("/");
  const ip = parseIp(slash < 0 ? s : s.slice(0, slash));
  if (!ip) return false;
  if (slash < 0) return true;
  const len = uint(s.slice(slash + 1));
  if (len === null || len > ip.width) return false;
  const host = (1n << BigInt(ip.width - len)) - 1n;
  return (ip.bits & host) === 0n;
}

/** One address of a path query: an address, or its host prefix. */
function hostAddressError(s: string): string | null {
  const slash = s.indexOf("/");
  const ip = parseIp(slash < 0 ? s : s.slice(0, slash));
  if (ip && (slash < 0 || s.slice(slash + 1) === String(ip.width))) return null;
  if (ip || s.includes("/")) return `prefix in a path query: ${s}`;
  return `not an IP address: ${s}`;
}

function isMac(s: string): boolean {
  const parts = s.split(":");
  return parts.length === 6 && parts.every((p) => /^[0-9a-fA-F]{2}$/.test(p));
}

/** The protocol numbers that have a name. */
const NAMED_PROTOCOLS = new Set([1, 6, 17, 58]);

function isTransport(s: string): boolean {
  const n = uint(s);
  if (n !== null) return NAMED_PROTOCOLS.has(n);
  return (FIELD_SCHEMA["network.transport"].values as readonly string[]).includes(s.toLowerCase());
}

/** A number or a range `a-b` from 0 to `max`. */
function isRange(s: string, max: number): boolean {
  const dash = s.indexOf("-");
  const lo = uint(dash < 0 ? s : s.slice(0, dash));
  const hi = dash < 0 ? lo : uint(s.slice(dash + 1));
  return lo !== null && hi !== null && lo <= hi && hi <= max;
}

/** The items of a comma list, each with its spaces trimmed. */
export function listItems(v: string): string[] {
  return v.split(",").map((x) => x.trim());
}

/**
 * The message for a value of a field that the server refuses by its form
 * in a query type, or null. An empty value is not stated and has no
 * message. The rules between fields stay with the server.
 */
export function checkIn(mode: Mode, k: QueryField, value: string): string | null {
  const v = value.trim();
  if (v === "") return null;
  const max = maxOf(k) ?? 0;
  const vs = FIELD_SCHEMA[k].values as readonly string[];
  const each = (ok: (item: string) => boolean, what: string): string | null => {
    const bad = listItems(v).find((x) => !ok(x));
    return bad === undefined ? null : `not ${what}: ${bad === "" ? "empty item" : bad}`;
  };
  const single = (ok: boolean, what: string) => (ok ? null : `not ${what}: ${v}`);
  const flagSet = (x: string) => x.split("+").every((f) => vs.includes(f.trim()));
  switch (kindOf(k)) {
    case "ingress": {
      const slash = v.indexOf("/");
      return single(slash > 0 && slash < v.length - 1, "<device>/<interface>");
    }
    case "boolean":
      return single(v === "true" || v === "false", "true or false");
    case "address":
      return mode === "path" ? hostAddressError(v) : each(isPrefix, "an address or a prefix");
    case "mac":
      return mode === "path" ? single(isMac(v), "6 hex bytes with colons") : each(isMac, "6 hex bytes with colons");
    case "number":
      if (mode === "path") {
        const n = /^\d+$/.test(v) ? Number(v) : null;
        return single(n !== null && n <= max, `0 to ${max}`);
      }
      return each((x) => isRange(x, max), `0 to ${max} or a range a-b`);
    case "icmp":
      if (mode === "path") {
        const n = /^\d+$/.test(v) ? Number(v) : null;
        return single((n !== null && n <= max) || vs.includes(v), `0 to ${max}, ${vs.join(" or ")}`);
      }
      return each((x) => isRange(x, max), `0 to ${max} or a range a-b`);
    case "names":
      if (k === "network.transport") {
        return mode === "path" ? single(isTransport(v), `one of ${names(vs)}`) : each(isTransport, `one of ${names(vs)}`);
      }
      return mode === "path" ? single(vs.includes(v), `one of ${names(vs)}`) : each((x) => vs.includes(x), `one of ${names(vs)}`);
    case "flags":
      if (mode === "path") return single(flagSet(v), "flags with +");
      return each((x) => (/^[A-Za-z]/.test(x) ? flagSet(x) : isRange(x, 255)), "0 to 255, a range a-b or flags with +");
  }
}

/**
 * The message for a value of a field that neither query type takes, or
 * null. An ICMP name is a value of a path query, and a list, a range or a
 * prefix a value of a set query.
 */
export function checkValue(k: QueryField, value: string): string | null {
  if (checkIn("path", k, value) === null) return null;
  const set = checkIn("set", k, value);
  if (set === null || kindOf(k) !== "icmp") return set;
  const vs = FIELD_SCHEMA[k].values as readonly string[];
  const bad = listItems(value.trim()).find((x) => !vs.includes(x) && !isRange(x, maxOf(k) ?? 0));
  return `not 0 to ${maxOf(k)}, ${vs.join(", ")} or a range a-b: ${bad === "" || bad === undefined ? "empty item" : bad}`;
}

/** Whether only a set query takes a value: a list, a range, a prefix or a number of TCP flags. */
export function setOnly(k: QueryField, value: string): boolean {
  return value.trim() !== "" && checkIn("path", k, value) !== null && checkIn("set", k, value) === null;
}

/**
 * The query type of the fields: a set query when a stated field has a
 * value of a set query only, else a path query.
 */
export function queryMode(fields: Partial<Record<QueryField, string>>): Mode {
  return QUERY_FIELDS.some((k) => takes("set", k) && setOnly(k, fields[k] ?? "")) ? "set" : "path";
}

/**
 * The first stated field whose value has a wrong form, with its message:
 * a value that neither query type takes, then a value that the query type
 * of the fields does not take, such as an ICMP name in a set query.
 */
export function firstError(fields: Partial<Record<QueryField, string>>): { field: QueryField; message: string } | null {
  for (const k of QUERY_FIELDS) {
    const message = checkValue(k, fields[k] ?? "");
    if (message) return { field: k, message };
  }
  const mode = queryMode(fields);
  for (const k of QUERY_FIELDS) {
    if (!takes(mode, k)) continue;
    const message = checkIn(mode, k, fields[k] ?? "");
    if (message) return { field: k, message };
  }
  return null;
}

// The names that a field takes, for the list of values.

/** The names that the list of a field proposes. */
export function valuesOf(k: QueryField): readonly string[] {
  switch (kindOf(k)) {
    case "names":
    case "flags":
    case "icmp":
      return FIELD_SCHEMA[k].values;
    case "boolean":
      return ["true", "false"];
    default:
      return [];
  }
}

/** The characters that separate the items of a value of a field. */
function separators(k: QueryField): string {
  const kind = kindOf(k);
  if (kind === "flags") return ",+";
  if (kind === "boolean" || kind === "ingress") return "";
  return ",";
}

/** The index where the item that is typed starts: after the last separator and the spaces after it. */
function tokenStart(k: QueryField, value: string): number {
  let at = 0;
  for (const c of separators(k)) at = Math.max(at, value.lastIndexOf(c) + 1);
  while (at < value.length && value[at] === " ") at++;
  return at;
}

/** The item of a value that the list filters by: the text after the last separator. */
export function valueToken(k: QueryField, value: string): string {
  return value.slice(tokenStart(k, value)).trim();
}

/** The names that contain a text, with no regard to case; the names that start with it come first. */
export function filterValues(values: readonly string[], token: string): string[] {
  const t = token.trim().toLowerCase();
  const starts = values.filter((v) => v.toLowerCase().startsWith(t));
  const contains = values.filter((v) => !v.toLowerCase().startsWith(t) && v.toLowerCase().includes(t));
  return [...starts, ...contains];
}

/** The value after a choice from the list: the choice in the place of the item that is typed. */
export function insertValue(k: QueryField, value: string, choice: string): string {
  return value.slice(0, tokenStart(k, value)) + choice;
}
