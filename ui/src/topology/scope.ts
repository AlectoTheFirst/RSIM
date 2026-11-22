// The scope of the map and its requests: the twin, a site of the inventory,
// the paths of the query with the neighbours of their devices, or one device
// with its neighbours up to 3 hops. A scope of more than 300 devices does
// not draw.
import { ApiProblem, allRows, getQuerySteps, getTopology, tableRows, tableUnique } from "../api/client";
import { type OutsideNeighbour, type TopologyOut, countsOf, natural, neighboursOf } from "./graph";
import { type MapPath, pathDevices, pathsOf } from "./paths";
import { pickerLimit } from "../page/pick";

/** The most devices of a scope that the map draws. */
export const MAX_DRAWN = 300;

export const HOPS = [1, 2, 3] as const;
export type Hops = (typeof HOPS)[number];

export type Scope =
  | { kind: "twin" }
  | { kind: "site"; site: string }
  | { kind: "paths" }
  | { kind: "device"; device: string; hops: Hops };

/** The URL parameters of the scope: `device` with `hops`, else `site`. */
export const SCOPE_PARAMS = ["device", "hops", "site"] as const;

function hopsOf(v: string | null): Hops {
  const n = Number(v);
  return n === 2 || n === 3 ? n : 1;
}

/** The scope of a URL: the device of `device`, else the site of `site`, else the paths of the query `q`, else the twin. */
export function scopeOf(search: string): Scope {
  const u = new URLSearchParams(search);
  const device = u.get("device");
  if (device) return { kind: "device", device, hops: hopsOf(u.get("hops")) };
  const site = u.get("site");
  if (site) return { kind: "site", site };
  if (u.get("q")) return { kind: "paths" };
  return { kind: "twin" };
}

/** The URL with the parameters of a scope; the other parameters stay. */
export function scopeSearch(search: string, scope: Scope): string {
  const u = new URLSearchParams(search);
  for (const k of SCOPE_PARAMS) u.delete(k);
  if (scope.kind === "device") {
    u.set("device", scope.device);
    if (scope.hops !== 1) u.set("hops", String(scope.hops));
  } else if (scope.kind === "site") {
    u.set("site", scope.site);
  }
  const q = u.toString();
  return q ? `?${q}` : "";
}

/** The sites of the inventory devices, each once, by name. */
export function sitesOf(devices: readonly { site?: string | null }[]): string[] {
  const s = new Set<string>();
  for (const d of devices) if (d.site) s.add(d.site);
  return [...s].sort(natural);
}

/** The sites that start with a text, with no regard to case: at most the options of `pages` pages, and whether more match. */
export function siteOptions(sites: readonly string[], text: string, pages: number): { list: string[]; more: boolean } {
  const q = text.trim().toLowerCase();
  const limit = pickerLimit(pages);
  const list: string[] = [];
  let more = false;
  for (const s of sites) {
    if (!s.toLowerCase().startsWith(q)) continue;
    if (list.length === limit) {
      more = true;
      break;
    }
    list.push(s);
  }
  return { list, more };
}

/** The reads of a scope from the API, one object for each twin. */
export interface ScopeApi {
  /** The number of devices of the twin. */
  deviceTotal(): Promise<number>;
  /** The twin devices named by a column of the table `devices` (`device` or `store_device`), at most `limit`, and the number of all. */
  devicesWhere(column: "device" | "store_device", values: readonly string[], limit: number): Promise<{ devices: string[]; total: number }>;
  topology(params: Record<string, string>): Promise<TopologyOut>;
  /** The endpoints of each device: the counts of the table `attachments` by device. */
  endpointCounts(devices: readonly string[]): Promise<Map<string, number>>;
  /** The rows of the table `neighbours` of the devices. */
  outside(devices: readonly string[]): Promise<OutsideNeighbour[]>;
  /** The paths of a query answer. */
  paths(qid: string): Promise<MapPath[]>;
}

/** The reads of a scope through the client of the API. */
export function scopeApi(twin: string): ScopeApi {
  return {
    async deviceTotal() {
      return (await tableRows(twin, "devices", { columns: "device", limit: "1" })).total;
    },
    async devicesWhere(column, values, limit) {
      const out = await tableRows(twin, "devices", { [column]: values.join(","), columns: "device", limit: String(limit) });
      const i = out.columns.indexOf("device");
      return { devices: out.rows.map((r) => r[i]).filter((d): d is string => typeof d === "string"), total: out.total };
    },
    topology: (params) => getTopology(twin, params),
    async endpointCounts(devices) {
      if (devices.length === 0) return new Map();
      const out = await tableUnique(twin, "attachments", { columns: "device", device: devices.join(",") });
      return countsOf(out.columns, out.rows);
    },
    async outside(devices) {
      if (devices.length === 0) return [];
      const { columns, rows } = await allRows(twin, "neighbours", { device: devices.join(",") });
      return neighboursOf(columns, rows);
    },
    async paths(qid) {
      return pathsOf(await getQuerySteps(twin, qid));
    },
  };
}

export type ScopeResult =
  | {
      state: "draw";
      topology: TopologyOut;
      /** The devices of the scope. */
      devices: string[];
      /** For the scope `paths`: whether the neighbours of the path devices are on the map; false when they make more than 300 devices. */
      neighbours: boolean;
    }
  /** More than 300 devices: the map asks for a device. The count is null when the API does not give it. */
  | { state: "too-many"; count: number | null }
  /** No device: a site with no device of the twin, or a query with no device on its paths. */
  | { state: "none" };

/** The number of devices of a refused view of more than the largest number of nodes of one response. */
export function tooManyNodes(e: unknown): number | null | undefined {
  if (!(e instanceof ApiProblem) || e.code !== "invalid_filter") return undefined;
  const m = /the view has (\d+) nodes/.exec(e.detail);
  return m ? Number(m[1]) : /more than \d+/.test(e.detail) ? null : undefined;
}

/** The parallel reads of the neighbours of the path devices. */
const PARALLEL = 4;

/**
 * Reads a scope: the number of its devices with no read of the whole
 * topology, then the topology of those devices when there are at most 300.
 * `inventory` gives the site of each device of the store; `paths` gives the
 * paths of the query for the scope `paths`.
 */
export async function resolveScope(
  scope: Scope,
  api: ScopeApi,
  inventory: readonly { name: string; site?: string | null }[] | null,
  paths: readonly MapPath[] | null,
): Promise<ScopeResult> {
  const byList = async (devices: string[]): Promise<ScopeResult> => {
    if (devices.length === 0) return { state: "none" };
    if (devices.length > MAX_DRAWN) return { state: "too-many", count: devices.length };
    const topology = await api.topology({ device: devices.join(",") });
    return { state: "draw", topology, devices: topology.nodes.map((n) => n.device ?? n.id), neighbours: true };
  };
  switch (scope.kind) {
    case "twin": {
      const total = await api.deviceTotal();
      if (total === 0) return { state: "none" };
      if (total > MAX_DRAWN) return { state: "too-many", count: total };
      const topology = await api.topology({});
      return { state: "draw", topology, devices: topology.nodes.map((n) => n.device ?? n.id), neighbours: true };
    }
    case "site": {
      const names = (inventory ?? []).filter((d) => d.site === scope.site).map((d) => d.name);
      if (names.length === 0) return { state: "none" };
      if (names.length > MAX_DRAWN) return { state: "too-many", count: names.length };
      const [own, behind] = await Promise.all([
        api.devicesWhere("device", names, MAX_DRAWN + 1),
        api.devicesWhere("store_device", names, MAX_DRAWN + 1),
      ]);
      const all = new Set([...own.devices, ...behind.devices]);
      if (behind.total > MAX_DRAWN || all.size > MAX_DRAWN) return { state: "too-many", count: Math.max(behind.total, all.size) };
      return byList([...all].sort(natural));
    }
    case "device": {
      let topology: TopologyOut;
      try {
        topology = await api.topology({ around: scope.device, hops: String(scope.hops) });
      } catch (e) {
        const n = tooManyNodes(e);
        if (n === undefined) throw e;
        return { state: "too-many", count: n };
      }
      if (topology.nodes.length > MAX_DRAWN) return { state: "too-many", count: topology.nodes.length };
      return { state: "draw", topology, devices: topology.nodes.map((n) => n.device ?? n.id), neighbours: true };
    }
    case "paths": {
      const own = pathDevices(paths ?? []);
      if (own.length === 0) return { state: "none" };
      if (own.length > MAX_DRAWN) return { state: "too-many", count: own.length };
      const all = new Set(own);
      let fits = true;
      for (let i = 0; i < own.length && fits; i += PARALLEL) {
        const batch = own.slice(i, i + PARALLEL);
        const views = await Promise.all(
          batch.map((d) =>
            api.topology({ around: d, hops: "1", layer: "physical" }).catch((e: unknown) => {
              if (tooManyNodes(e) === undefined) throw e;
              return null;
            }),
          ),
        );
        for (const v of views) {
          if (v === null) {
            fits = false;
            break;
          }
          for (const n of v.nodes) all.add(n.device ?? n.id);
        }
        if (all.size > MAX_DRAWN) fits = false;
      }
      const r = await byList(fits ? [...all] : own);
      return r.state === "draw" ? { ...r, neighbours: fits } : r;
    }
  }
}

/** The endpoint counts and the neighbours outside the twin of the devices of a scope. */
export async function scopeExtras(api: ScopeApi, devices: readonly string[]): Promise<{ endpoints: Map<string, number>; outside: OutsideNeighbour[] }> {
  const [endpoints, outside] = await Promise.all([api.endpointCounts(devices), api.outside(devices)]);
  return { endpoints, outside };
}
