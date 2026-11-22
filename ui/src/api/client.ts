// The calls of the UI to the REST API of rsim-api, on the origin of the page.
import type { Collection, Credential, CredentialPut, Device, Group, Inventory, JumpHost, ResolvedDevice, Route, SecretKeyOut, Vendors } from "../inventory/model";
import type { Me, NewToken, PathAnswer, SetAnswer, SetupState, SourceText, Span, TableOut, TablesOut, TokenIn, TokenInfo, Twin } from "./types";

/** A refused request: the problem object of RFC 9457. */
export class ApiProblem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail: string,
    /** The title of the problem: a fixed text for each code. */
    readonly title: string = detail,
    /** The seconds of the `Retry-After` header, or null with none. */
    readonly retryAfter: number | null = null,
  ) {
    super(detail);
  }
}

/** The seconds of a `Retry-After` header, or null for no header or a date. */
export function retryAfterSeconds(header: string | null): number | null {
  if (header === null || !/^\s*\d+\s*$/.test(header)) return null;
  return Number(header);
}

async function problem(r: Response): Promise<ApiProblem> {
  const wait = retryAfterSeconds(r.headers.get("retry-after"));
  try {
    const p = (await r.json()) as { code?: string; detail?: string; title?: string };
    const detail = p.detail ?? p.title ?? r.statusText;
    return new ApiProblem(r.status, p.code ?? "", detail, p.title ?? detail, wait);
  } catch {
    return new ApiProblem(r.status, "", r.statusText, r.statusText, wait);
  }
}

/** The handler of a 401 answer: the page goes back to the sign-in. */
let unauthorized: (() => void) | null = null;

/** Sets the handler of a 401 answer of a request, or removes it with null. */
export function onUnauthorized(handler: (() => void) | null): void {
  unauthorized = handler;
}

/** The handler of a snapshot that a newer snapshot replaced. */
let replacedRun: (() => void) | null = null;

/**
 * Sets the handler of a request whose snapshot a newer snapshot replaced
 * (`snapshot_replaced`), or removes it with null.
 */
export function onReplaced(handler: (() => void) | null): void {
  replacedRun = handler;
}

/**
 * The path of a request on the alias `store` in place of a replaced
 * snapshot, or null for a path that must stay on its snapshot: a trace step
 * and source lines belong to the answer of that snapshot.
 */
export function onNewestRun(path: string): string | null {
  const m = /^\/v1\/twins\/snap-\d+(\/.*)?$/.exec(path);
  if (!m) return null;
  const rest = m[1] ?? "";
  if (/\/(steps|sources)(\/|\?|$)/.test(rest)) return null;
  return `/v1/twins/store${rest}`;
}

/**
 * Sends a request on the origin of the page with the session cookie. A
 * refused request throws its problem; a 401 also calls the handler of
 * `onUnauthorized`, except with `expect401`, where a 401 is an answer. A
 * replaced snapshot calls the handler of `onReplaced`, and the request is
 * sent again on the newest run when `onNewestRun` gives a path.
 */
async function send(path: string, init: RequestInit = {}, expect401 = false): Promise<Response> {
  const r = await fetch(path, { credentials: "same-origin", ...init });
  if (r.ok) return r;
  if (r.status === 401 && !expect401) unauthorized?.();
  const p = await problem(r);
  if (p.code !== "snapshot_replaced") throw p;
  replacedRun?.();
  const again = onNewestRun(path);
  if (again === null) throw p;
  return send(again, init, expect401);
}

const JSON_HEADERS = { "content-type": "application/json", accept: "application/json" };

async function getJson<T>(path: string): Promise<T> {
  const r = await send(path, { headers: { accept: "application/json" } });
  return (await r.json()) as T;
}

/** Sends a JSON body and reads the JSON answer. */
async function sendJson<T>(method: string, path: string, body: unknown, expect401 = false): Promise<T> {
  const r = await send(path, { method, headers: JSON_HEADERS, body: JSON.stringify(body) }, expect401);
  return (await r.json()) as T;
}

/** Whether the server has sign-in, and whether its setup can make the first admin. */
export async function getSetup(): Promise<SetupState> {
  return getJson("/v1/auth/setup");
}

/** Makes the first admin and signs it in. */
export async function setUp(name: string, password: string): Promise<Me> {
  return sendJson("POST", "/v1/auth/setup", { name, password }, true);
}

/** Signs in and sets the session cookie. */
export async function signIn(name: string, password: string): Promise<Me> {
  return sendJson("POST", "/v1/auth/login", { name, password }, true);
}

/** Ends the session of the cookie. */
export async function signOut(): Promise<void> {
  await send("/v1/auth/logout", { method: "POST", headers: { accept: "application/json" } }, true);
}

/** The user of the session; a 401 throws its problem with no call of the handler. */
export async function getMe(): Promise<Me> {
  const r = await send("/v1/auth/me", { headers: { accept: "application/json" } }, true);
  return (await r.json()) as Me;
}

/** The API tokens of the user of the session. */
export async function listTokens(): Promise<TokenInfo[]> {
  const body = await getJson<{ tokens: TokenInfo[] }>("/v1/auth/tokens");
  return body.tokens;
}

/** Makes an API token; the answer holds its text one time only. */
export async function createToken(body: TokenIn): Promise<NewToken> {
  return sendJson("POST", "/v1/auth/tokens", body);
}

/** Revokes an API token of the user of the session. */
export async function revokeToken(id: number): Promise<void> {
  await send(`/v1/auth/tokens/${id}`, { method: "DELETE", headers: { accept: "application/json" } });
}

export interface TwinRef {
  id: string;
  href: string;
  /** For the alias `store`: the newest built snapshot, or null before the first build. */
  held?: string | null;
  /** For the alias `store`: the cycle of the newest snapshot of the store, or null when not known. */
  newest_cycle?: number | null;
  /** For the alias `store`: the snapshot before the held snapshot that the server keeps, or null. */
  previous?: string | null;
  /** For the alias `store`: the snapshot whose twin builds now in the background, or null. */
  loading?: string | null;
  /**
   * For the alias `store`: the newest snapshot that does not build, or the
   * HEAD of the store that cannot be read with the snapshot null; else null.
   */
  reload_error?: { snapshot: string | null; detail: string } | null;
}

export async function listTwins(): Promise<TwinRef[]> {
  const body = await getJson<{ twins: TwinRef[] }>("/v1/twins");
  return body.twins;
}

export async function getTwin(id: string): Promise<{ twin: Twin; topology: string }> {
  return getJson(`/v1/twins/${encodeURIComponent(id)}`);
}

/**
 * Makes the query resource of a query. The server answers 303 and the
 * browser follows it, so the URL of the response names the query.
 */
export async function createQuery(
  twin: string,
  body: Record<string, unknown>,
): Promise<{ twin: string; qid: string }> {
  const r = await send(`/v1/twins/${encodeURIComponent(twin)}/queries`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
  const m = /^\/v1\/twins\/([^/]+)\/queries\/([^/]+)$/.exec(new URL(r.url).pathname);
  if (!m) throw new ApiProblem(r.status, "", `no query resource: ${r.url}`);
  return { twin: decodeURIComponent(m[1]!), qid: decodeURIComponent(m[2]!) };
}

/** The engine time of a response, from its `Server-Timing` header. */
export interface ServerTiming {
  /** The engine time in ms, or null with no `engine` metric. */
  engineMs: number | null;
  /** Whether the answer came from the cache of the server. */
  cacheHit: boolean;
}

/** Reads the metrics `engine;dur=<ms>` and `cache;desc=hit` of a `Server-Timing` header. */
export function serverTiming(header: string | null): ServerTiming {
  const out: ServerTiming = { engineMs: null, cacheHit: false };
  for (const metric of (header ?? "").split(",")) {
    const [name, ...params] = metric.split(";").map((x) => x.trim());
    const param = (k: string) => {
      const p = params.find((x) => x.toLowerCase().startsWith(`${k}=`));
      return p ? p.slice(k.length + 1).replace(/^"|"$/g, "") : null;
    };
    if (name === "engine") {
      const d = Number(param("dur"));
      if (Number.isFinite(d)) out.engineMs = d;
    } else if (name === "cache" && param("desc") === "hit") {
      out.cacheHit = true;
    }
  }
  return out;
}

/** The full form of a query answer, with the server timing of the response. */
export async function getQuery(twin: string, qid: string): Promise<{ out: PathAnswer | SetAnswer; timing: ServerTiming }> {
  const r = await send(`/v1/twins/${encodeURIComponent(twin)}/queries/${encodeURIComponent(qid)}?form=full`, {
    headers: { accept: "application/json" },
  });
  const out = (await r.json()) as PathAnswer | SetAnswer;
  return { out, timing: serverTiming(r.headers.get("server-timing")) };
}

/** The URL of the resource of one trace step. */
export function stepUrl(
  twin: string,
  qid: string,
  branch: number,
  step: number,
  replyOf: number | null,
): string {
  const base = `/v1/twins/${encodeURIComponent(twin)}/queries/${encodeURIComponent(qid)}/branches/${branch}/steps/${step}`;
  return replyOf === null ? base : `${base}?reply_of=${replyOf}`;
}

/** The URL of the masked source lines of a span of a twin. */
export function sourceUrl(twin: string, span: Span): string {
  const file = encodeURIComponent(span.file);
  return `/v1/twins/${encodeURIComponent(twin)}/sources?file=${file}&lines=${span.first_line}-${span.last_line}`;
}

/** The masked source lines of a span of a twin. */
export async function getSourceLines(twin: string, span: Span): Promise<SourceText> {
  const body = await getJson<{ source: SourceText }>(sourceUrl(twin, span));
  return body.source;
}

/** The catalog of the tables. */
export async function getCatalog(): Promise<TablesOut> {
  return getJson("/v1/tables");
}

/** The answer of a table request, by its path and query below the origin. */
export async function getTable<T>(path: string): Promise<T> {
  return getJson(path);
}

/** One page of the coverage report of a twin. */
export async function getCoverage(twin: string, limit: number, cursor: string | null): Promise<TableOut> {
  const q = new URLSearchParams({ limit: String(limit) });
  if (cursor) q.set("cursor", cursor);
  return getJson(`/v1/twins/${encodeURIComponent(twin)}/coverage?${q.toString()}`);
}

/** One page of the unhandled paths of one device, from the table coverage. */
export async function getUnhandled(twin: string, device: string, limit: number, cursor: string | null): Promise<TableOut> {
  const q = new URLSearchParams({ device, limit: String(limit) });
  if (cursor) q.set("cursor", cursor);
  return getJson(`/v1/twins/${encodeURIComponent(twin)}/tables/coverage/rows?${q.toString()}`);
}

/** One page of rows of a table, with the filters, columns and limit as query parameters. */
export async function tableRows(twin: string, table: string, params: Record<string, string>): Promise<TableOut> {
  const q = new URLSearchParams(params).toString();
  return getJson(`/v1/twins/${encodeURIComponent(twin)}/tables/${encodeURIComponent(table)}/rows?${q}`);
}

/** The whole inventory as stored. */
export async function getInventory(): Promise<Inventory> {
  return getJson("/v1/inventory");
}

/** The devices of the inventory with the settings of their groups resolved. */
export async function getResolvedDevices(): Promise<ResolvedDevice[]> {
  const body = await getJson<{ devices: ResolvedDevice[] }>("/v1/inventory/devices");
  return body.devices;
}

/** Whether the server has the secret key of the managed credentials, and its id. */
export async function getSecretKey(): Promise<SecretKeyOut> {
  return getJson("/v1/inventory/secret-key");
}

/** The vendors that have a collector, with their transport. */
export async function getVendors(): Promise<Vendors> {
  return getJson("/v1/inventory/vendors");
}

/** Makes or replaces a record of the inventory; the answer is the inventory version. */
async function put(path: string, body: unknown): Promise<number> {
  return (await sendJson<{ version: number }>("PUT", path, body)).version;
}

export const putDevice = (d: Device) => put(`/v1/inventory/devices/${encodeURIComponent(d.name)}`, d);
export const putGroup = (g: Group) => put(`/v1/inventory/groups/${encodeURIComponent(g.name)}`, g);
export const putCredential = (c: Credential | CredentialPut) => put(`/v1/inventory/credentials/${encodeURIComponent(c.name)}`, c);
export const putRoute = (r: Route) => put(`/v1/inventory/routes/${encodeURIComponent(r.name)}`, r);
export const putJumpHost = (j: JumpHost) => put(`/v1/inventory/jump-hosts/${encodeURIComponent(j.name)}`, j);
export const putCollection = (c: Collection) => put("/v1/inventory/collection", c);

/** Removes a record of the inventory; the answer is the inventory version. */
async function del(path: string): Promise<number> {
  const r = await send(path, { method: "DELETE", headers: { accept: "application/json" } });
  return ((await r.json()) as { version: number }).version;
}

export const deleteDevice = (name: string) => del(`/v1/inventory/devices/${encodeURIComponent(name)}`);
export const deleteGroup = (name: string) => del(`/v1/inventory/groups/${encodeURIComponent(name)}`);
export const deleteCredential = (name: string) => del(`/v1/inventory/credentials/${encodeURIComponent(name)}`);
export const deleteRoute = (name: string) => del(`/v1/inventory/routes/${encodeURIComponent(name)}`);
export const deleteJumpHost = (name: string) => del(`/v1/inventory/jump-hosts/${encodeURIComponent(name)}`);

/** All rows of a table of a twin, page after page. */
export async function allRows(twin: string, table: string): Promise<{ columns: string[]; rows: unknown[][] }> {
  const rows: unknown[][] = [];
  let columns: string[] = [];
  let cursor: string | null = null;
  do {
    const params: Record<string, string> = { limit: "1000" };
    if (cursor) params["cursor"] = cursor;
    const page = await tableRows(twin, table, params);
    columns = page.columns;
    rows.push(...page.rows);
    cursor = page.next_cursor ?? null;
  } while (cursor);
  return { columns, rows };
}
