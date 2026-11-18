// The calls of the UI to the REST API of rsim-api, on the origin of the page.
import type { PathAnswer, SetAnswer, TableOut, TablesOut, Twin } from "./types";

/** A refused request: the problem object of RFC 9457. */
export class ApiProblem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail: string,
  ) {
    super(detail);
  }
}

async function problem(r: Response): Promise<ApiProblem> {
  try {
    const p = (await r.json()) as { code?: string; detail?: string; title?: string };
    return new ApiProblem(r.status, p.code ?? "", p.detail ?? p.title ?? r.statusText);
  } catch {
    return new ApiProblem(r.status, "", r.statusText);
  }
}

async function getJson<T>(path: string): Promise<T> {
  const r = await fetch(path, { headers: { accept: "application/json" } });
  if (!r.ok) throw await problem(r);
  return (await r.json()) as T;
}

export interface TwinRef {
  id: string;
  href: string;
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
  const r = await fetch(`/v1/twins/${encodeURIComponent(twin)}/queries`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw await problem(r);
  const m = /^\/v1\/twins\/([^/]+)\/queries\/([^/]+)$/.exec(new URL(r.url).pathname);
  if (!m) throw new ApiProblem(r.status, "", `the answer has no query resource: ${r.url}`);
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
  const r = await fetch(`/v1/twins/${encodeURIComponent(twin)}/queries/${encodeURIComponent(qid)}?form=full`, {
    headers: { accept: "application/json" },
  });
  if (!r.ok) throw await problem(r);
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
