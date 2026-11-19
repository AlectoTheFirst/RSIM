// The fields of the query bar: their order, their labels and help text,
// the names that a field takes, and the check of the form of a value. The
// number ranges and the names come from the OpenAPI document; the checks
// follow the argument parser of the server.
import { FIELD_SCHEMA, type FieldName } from "../api/fields";

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
  "reply",
] as const satisfies readonly FieldName[];
export type QueryField = (typeof QUERY_FIELDS)[number];

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

/** One example value of each field in each mode. */
const EXAMPLES: Record<QueryField, { path: string; set: string }> = {
  "source.ip": { path: "192.0.2.10", set: "192.0.2.0/24,198.51.100.7" },
  "source.port": { path: "40000", set: "1024-65535" },
  "destination.ip": { path: "198.51.100.20", set: "203.0.113.0/24" },
  "destination.port": { path: "443", set: "53,80,443" },
  "network.transport": { path: "udp", set: "tcp,udp" },
  ingress: { path: "r1/eth0", set: "r1/eth0" },
  "network.iana_number": { path: "6", set: "6,17" },
  tcp_flags: { path: "syn,ack", set: "syn,syn+ack" },
  icmp_type: { path: "echo-request", set: "0,8" },
  icmp_code: { path: "0", set: "0-3" },
  fragment: { path: "first", set: "unfragmented,first" },
  dscp: { path: "46", set: "0,46" },
  ecn: { path: "0", set: "0-3" },
  "source.mac": { path: "00:00:5e:00:53:01", set: "00:00:5e:00:53:01,00:00:5e:00:53:02" },
  "destination.mac": { path: "00:00:5e:00:53:02", set: "00:00:5e:00:53:02" },
  "network.vlan.id": { path: "10", set: "10-20" },
  l2_priority: { path: "5", set: "0-7" },
  reply: { path: "false", set: "false" },
};

export function exampleOf(mode: Mode, k: QueryField): string {
  return EXAMPLES[k][mode];
}

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
  reply: "reply run",
};

export function labelOf(k: QueryField): string {
  return FIELD_LABELS[k];
}

const names = (vs: readonly string[]) => vs.join(", ");

/** The form of a value of a field for a mode, as a short phrase. */
export function formOf(mode: Mode, k: QueryField): string {
  const max = maxOf(k);
  const vs = FIELD_SCHEMA[k].values;
  switch (kindOf(k)) {
    case "address":
      return mode === "path" ? "address, no prefix" : "addresses and prefixes, comma list";
    case "mac":
      return mode === "path" ? "6 hex bytes with colons" : "MAC addresses, comma list";
    case "ingress":
      return "<device>/<interface>";
    case "boolean":
      return "true or false";
    case "number":
      return mode === "path" ? `0 to ${max}` : `0 to ${max} and ranges a-b, comma list`;
    case "icmp":
      return mode === "path" ? `0 to ${max}, ${names(vs)}` : `0 to ${max} and ranges a-b, comma list`;
    case "names":
      return mode === "path" ? names(vs) : `${names(vs)}, comma list`;
    case "flags":
      return mode === "path" ? `flags set, comma list` : `flag sets with +, 0 to 255, ranges a-b, comma list`;
  }
}

/** The value of a field that a query does not state, in a mode. */
export function notStatedNote(mode: Mode): string {
  return mode === "set" ? "not stated: all values" : "not stated: not known";
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
 * The message for a value of a field that the server refuses by its
 * form, or null. An empty value is not stated and has no message. The
 * rules between fields stay with the server.
 */
export function checkValue(mode: Mode, k: QueryField, value: string): string | null {
  const v = value.trim();
  if (v === "") return null;
  const max = maxOf(k) ?? 0;
  const vs = FIELD_SCHEMA[k].values as readonly string[];
  const each = (ok: (item: string) => boolean, what: string): string | null => {
    const bad = listItems(v).find((x) => !ok(x));
    return bad === undefined ? null : `not ${what}: ${bad === "" ? "empty item" : bad}`;
  };
  const single = (ok: boolean, what: string) => (ok ? null : `not ${what}: ${v}`);
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
      if (mode === "path") return each((x) => vs.includes(x), `a TCP flag, ${names(vs)}`);
      return each(
        (x) => (/^[A-Za-z]/.test(x) ? x.split("+").every((f) => vs.includes(f)) : isRange(x, 255)),
        "0 to 255, a range a-b or flags with +",
      );
  }
}

/**
 * The value of a field after a change of the mode, or null when the value
 * has no form in the new mode. The TCP flags of a path query are a comma
 * list of the flags of one packet, and those of a set query are a comma
 * list of flag sets with the flags of a set joined by +: "syn,ack" of a
 * path query is "syn+ack" of a set query. A set value with more than one
 * flag set has no path form. Each other value stays as it is.
 */
export function modeValue(from: Mode, to: Mode, k: QueryField, value: string): string | null {
  const v = value.trim();
  if (from === to || kindOf(k) !== "flags" || v === "") return value;
  const vs = FIELD_SCHEMA[k].values as readonly string[];
  const items = listItems(v);
  if (to === "set") {
    return items.every((x) => vs.includes(x)) ? items.join("+") : value;
  }
  if (checkValue("set", k, v) !== null) return value;
  if (items.length > 1) return null;
  const parts = (items[0] ?? "").split("+").map((x) => x.trim());
  return parts.every((x) => vs.includes(x)) ? parts.join(",") : value;
}

/** The first stated field of the shown fields whose value has a wrong form, with its message. */
export function firstError(mode: Mode, fields: Partial<Record<QueryField, string>>): { field: QueryField; message: string } | null {
  for (const k of QUERY_FIELDS) {
    const message = checkValue(mode, k, fields[k] ?? "");
    if (message) return { field: k, message };
  }
  return null;
}

// The names that a field takes, for the list of values.

/** The names that the list of a field proposes in a mode. */
export function valuesOf(mode: Mode, k: QueryField): readonly string[] {
  switch (kindOf(k)) {
    case "names":
    case "flags":
      return FIELD_SCHEMA[k].values;
    case "icmp":
      return mode === "path" ? FIELD_SCHEMA[k].values : [];
    case "boolean":
      return ["true", "false"];
    default:
      return [];
  }
}

/** The characters that separate the items of a value of a field. */
function separators(mode: Mode, k: QueryField): string {
  const kind = kindOf(k);
  if (kind === "flags") return mode === "set" ? ",+" : ",";
  if (mode === "set" && kind !== "boolean" && kind !== "ingress") return ",";
  return "";
}

/** The index where the item that is typed starts: after the last separator and the spaces after it. */
function tokenStart(mode: Mode, k: QueryField, value: string): number {
  let at = 0;
  for (const c of separators(mode, k)) at = Math.max(at, value.lastIndexOf(c) + 1);
  while (at < value.length && value[at] === " ") at++;
  return at;
}

/** The item of a value that the list filters by: the text after the last separator. */
export function valueToken(mode: Mode, k: QueryField, value: string): string {
  return value.slice(tokenStart(mode, k, value)).trim();
}

/** The names that contain a text, with no regard to case; the names that start with it come first. */
export function filterValues(values: readonly string[], token: string): string[] {
  const t = token.trim().toLowerCase();
  const starts = values.filter((v) => v.toLowerCase().startsWith(t));
  const contains = values.filter((v) => !v.toLowerCase().startsWith(t) && v.toLowerCase().includes(t));
  return [...starts, ...contains];
}

/** The value after a choice from the list: the choice in the place of the item that is typed. */
export function insertValue(mode: Mode, k: QueryField, value: string, choice: string): string {
  return value.slice(0, tokenStart(mode, k, value)) + choice;
}
