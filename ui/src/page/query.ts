// The query of the query bar: its fields, its request body, and its forms
// as an rsim command and as an MCP tool call.
import { type Mode, QUERY_FIELDS, type QueryField, kindOf, listItems } from "./fields";

export { type Mode, QUERY_FIELDS, type QueryField } from "./fields";
export type Fields = Partial<Record<QueryField, string>>;

/** The stated fields, in the order of the query bar. */
export function stated(f: Fields): [QueryField, string][] {
  return QUERY_FIELDS.map((k) => [k, (f[k] ?? "").trim()] as [QueryField, string]).filter(([, v]) => v !== "");
}

/**
 * The JSON value of a field. A path query takes a number for a number
 * field and for an ICMP type number, and a list for the TCP flags; both
 * modes take true or false for the reply. Each other value is its text.
 */
export function jsonValue(mode: Mode, k: QueryField, v: string): string | number | boolean | string[] {
  const kind = kindOf(k);
  if (kind === "boolean" && (v === "true" || v === "false")) return v === "true";
  if (mode === "set") return v;
  if ((kind === "number" || kind === "icmp") && /^\d+$/.test(v)) return Number(v);
  if (kind === "flags") return listItems(v);
  return v;
}

/**
 * The flags of a command for the stated fields. A reply that is false is
 * the flag --no-reply, and the TCP flags of a path query are a comma list
 * with no spaces.
 */
function commandArgs(mode: Mode, f: Fields): string[] {
  return stated(f).flatMap(([k, v]) => {
    const kind = kindOf(k);
    if (kind === "boolean" && (v === "true" || v === "false")) return v === "false" ? [`--no-${k}`] : [];
    if (kind === "flags" && mode === "path") return [`--${k}`, shellWord(listItems(v).join(","))];
    return [`--${k}`, shellWord(v)];
  });
}

/** The body of `POST /v1/twins/{twin}/queries`. */
export function requestBody(mode: Mode, f: Fields): Record<string, unknown> {
  const body: Record<string, unknown> = mode === "set" ? { mode: "set" } : {};
  for (const [k, v] of stated(f)) body[k] = jsonValue(mode, k, v);
  return body;
}

/** The topology argument of the CLI and of the MCP tools for a twin. */
export function topologyOf(twin: string): string {
  return twin.startsWith("builtin.") ? twin.slice("builtin.".length) : "store";
}

/** A shell word, quoted when it has a character that the shell reads. */
export function shellWord(s: string): string {
  return /^[A-Za-z0-9_./:,@%+=-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/** The topology argument of an rsim command for a twin. */
export function cliTopology(twin: string): string {
  return twin.startsWith("builtin.") ? topologyOf(twin) : "store:<data folder>";
}

/** The query as an rsim command. */
export function rsimCommand(mode: Mode, twin: string, f: Fields): string {
  return ["rsim", mode, cliTopology(twin), ...commandArgs(mode, f)].join(" ");
}

/** The command that explains one trace step of the query. */
export function explainCommand(
  mode: Mode,
  twin: string,
  f: Fields,
  branch: number,
  step: number,
  replyOf: number | null,
): string {
  const verb = mode === "set" ? "explain-set" : "explain";
  const args = commandArgs(mode, f);
  const at = ["--branch", String(branch), "--step", String(step)];
  if (replyOf !== null) at.push("--reply-of", String(replyOf));
  return ["rsim", verb, cliTopology(twin), ...args, ...at].join(" ");
}

/** The query as an MCP tool call. */
export function mcpCall(mode: Mode, twin: string, f: Fields): string {
  const args: Record<string, unknown> = { topology: topologyOf(twin) };
  for (const [k, v] of stated(f)) args[k] = jsonValue(mode, k, v);
  return JSON.stringify({ name: mode === "set" ? "set_query" : "path_query", arguments: args });
}

/**
 * The fields of the query bar from the query of an answer. The echo of a
 * path query gives the protocol number with each protocol name; the field
 * of the number stays empty when the name is there.
 */
export function fieldsOf(echo: Record<string, unknown>): Fields {
  const out: Fields = {};
  for (const k of QUERY_FIELDS) {
    const v = echo[k];
    if (v === null || v === undefined) continue;
    if (k === "network.iana_number" && typeof v === "number" && echo["network.transport"] != null) continue;
    out[k] = Array.isArray(v) ? v.map(String).join(",") : String(v);
  }
  return out;
}
