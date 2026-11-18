// The query of the query bar: its fields, its request body, and its forms
// as an rsim command and as an MCP tool call.

export type Mode = "path" | "set";

/** The fields of the query bar, in order. */
export const QUERY_FIELDS = [
  "source.ip",
  "source.port",
  "destination.ip",
  "destination.port",
  "network.transport",
  "ingress",
] as const;
export type QueryField = (typeof QUERY_FIELDS)[number];
export type Fields = Partial<Record<QueryField, string>>;

const NUMBERS = new Set<QueryField>(["source.port", "destination.port"]);

/** The stated fields, in the order of the query bar. */
export function stated(f: Fields): [QueryField, string][] {
  return QUERY_FIELDS.map((k) => [k, (f[k] ?? "").trim()] as [QueryField, string]).filter(([, v]) => v !== "");
}

/** The JSON value of a field: a number for a port of a path query. */
function jsonValue(mode: Mode, k: QueryField, v: string): string | number {
  if (mode === "path" && NUMBERS.has(k) && /^\d+$/.test(v)) return Number(v);
  return v;
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
  const args = stated(f).flatMap(([k, v]) => [`--${k}`, shellWord(v)]);
  return ["rsim", mode, cliTopology(twin), ...args].join(" ");
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
  const args = stated(f).flatMap(([k, v]) => [`--${k}`, shellWord(v)]);
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

/** The fields of the query bar from the query of an answer. */
export function fieldsOf(echo: Record<string, unknown>): Fields {
  const out: Fields = {};
  for (const k of QUERY_FIELDS) {
    const v = echo[k];
    if (v !== null && v !== undefined) out[k] = String(v);
  }
  return out;
}
