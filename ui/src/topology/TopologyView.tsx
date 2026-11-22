// The Topology view: the map of one scope with the paths of the query on
// it, its controls, and the panel of the selected card.
import { useEffect, useMemo, useState } from "preact/hooks";
import { ApiProblem, getInventory, getPathDrawing, tableRows, topologyFileUrl } from "../api/client";
import { Card, Empty, PageHead, PanelLayout } from "../page/Card";
import { Icon } from "../page/Icon";
import { MenuButton } from "../page/Menu";
import { Segmented } from "../page/Segmented";
import { toast } from "../page/notes";
import { DeviceField, SiteField } from "./DeviceField";
import { EXPORTS, exportParams, vendorsOf } from "./draw";
import { LAYERS, type Layer, type MapGraph, buildGraph } from "./graph";
import { type MapLayout, layoutMap } from "./layout";
import { type CentreOn, MapCanvas } from "./MapCanvas";
import { MapPanel } from "./MapPanel";
import { type MapPath, overlayOf, pathGraphInput, pathMarks } from "./paths";
import { HOPS, type Hops, type Scope, resolveScope, scopeApi, scopeExtras, scopeOf, scopeSearch, sitesOf } from "./scope";
import { type MapIndex, indexLayout } from "./view";

export interface TopologyProps {
  /** The twin of the page, empty while it cannot answer. */
  twin: string;
  /** The query id of the page, or null. */
  qid: string | null;
  /** The search part of the URL of the page. */
  search: string;
  /** Opens the URL with a new search part. */
  navigate: (search: string) => void;
  /** Opens the table `functions` for a device. */
  onFunctions: (device: string) => void;
  /** Sets the entry point of the query, `<device>` or `<device>/<interface>`, and opens the Trace view. */
  onEntryPoint: (ingress: string) => void;
}

interface Drawn {
  state: "draw";
  key: string;
  graph: MapGraph;
  layout: MapLayout;
  index: MapIndex;
  layers: Layer[];
  devices: string[];
  vendors: Map<string, string>;
}

type Shown = Drawn | { state: "too-many"; key: string; count: number | null } | { state: "none"; key: string } | { state: "problem"; key: string; text: string };

function problemText(e: unknown): string {
  if (e instanceof ApiProblem) return e.title;
  return e instanceof Error ? e.message : String(e);
}

/** The vendors of the devices of a scope, from the table `devices`. */
async function vendorsOfDevices(twin: string, devices: readonly string[]): Promise<Map<string, string>> {
  if (devices.length === 0) return new Map();
  try {
    const t = await tableRows(twin, "devices", { device: devices.join(","), columns: "device,vendor", limit: String(devices.length) });
    return vendorsOf(t);
  } catch {
    return new Map();
  }
}

/** Saves the topology of the scope in a file form of the API. */
function saveFile(url: string, name: string) {
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
}

export function TopologyView(props: TopologyProps) {
  const { twin, qid } = props;
  const scope = useMemo(() => scopeOf(props.search), [props.search]);
  const scopeKey = JSON.stringify(scope);
  const [inventory, setInventory] = useState<{ name: string; site?: string | null }[] | null | undefined>(undefined);
  const [paths, setPaths] = useState<{ key: string; list: MapPath[] } | null>(null);
  const [shown, setShown] = useState<Shown | null>(null);
  const [layer, setLayer] = useState<Layer>("physical");
  const [overlay, setOverlay] = useState<{ key: string; map: Map<number, string[]> } | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [centre, setCentre] = useState<CentreOn | null>(null);
  const [ports, setPorts] = useState(true);
  const [speeds, setSpeeds] = useState(true);

  const pathKey = `${twin}\u0000${qid ?? ""}`;
  const drawKey = `${pathKey}\u0000${scopeKey}`;

  useEffect(() => {
    let live = true;
    getInventory()
      .then((inv) => {
        if (live) setInventory(inv.devices.map((d) => ({ name: d.name, site: d.site ?? null })));
      })
      .catch(() => {
        if (live) setInventory(null);
      });
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    if (!twin || !qid) {
      setPaths(null);
      return;
    }
    let live = true;
    scopeApi(twin)
      .paths(qid)
      .then((list) => {
        if (live) setPaths({ key: pathKey, list });
      })
      .catch((e: unknown) => {
        if (!live) return;
        setPaths({ key: pathKey, list: [] });
        toast(problemText(e));
      });
    return () => {
      live = false;
    };
  }, [pathKey]);

  const pathList = paths && paths.key === pathKey ? paths.list : null;
  const waiting = !twin || (qid !== null && pathList === null) || (scope.kind === "site" && inventory === undefined);

  useEffect(() => {
    if (waiting) return;
    let live = true;
    const api = scopeApi(twin);
    (async (): Promise<Shown> => {
      const r = await resolveScope(scope, api, inventory ?? null, pathList);
      if (r.state !== "draw") return r.state === "too-many" ? { state: "too-many", key: drawKey, count: r.count } : { state: "none", key: drawKey };
      const [extras, vendors] = await Promise.all([scopeExtras(api, r.devices), vendorsOfDevices(twin, r.devices)]);
      const graph = buildGraph({ topology: r.topology, ...extras, ...(pathList ? pathGraphInput(pathList) : {}) });
      const layout = layoutMap(graph);
      const layers = LAYERS.filter((l) => r.topology.layers.includes(l));
      return { state: "draw", key: drawKey, graph, layout, index: indexLayout(layout), layers, devices: r.devices, vendors };
    })()
      .then((s) => {
        if (live) setShown(s);
      })
      .catch((e: unknown) => {
        if (live) setShown({ state: "problem", key: drawKey, text: problemText(e) });
      });
    return () => {
      live = false;
    };
  }, [drawKey, waiting]);

  const current = shown && shown.key === drawKey ? shown : null;
  const drawn = current?.state === "draw" ? current : null;
  const shownLayer: Layer = drawn && !drawn.layers.includes(layer) ? (drawn.layers[0] ?? "physical") : layer;

  useEffect(() => {
    if (selected !== null && drawn && !drawn.graph.node.has(selected)) setSelected(null);
  }, [drawn]);

  useEffect(() => {
    if (shownLayer !== "overlay" || !twin || !qid || !pathList || pathList.length === 0 || overlay?.key === pathKey) return;
    let live = true;
    getPathDrawing(twin, qid)
      .then((d) => {
        if (live) setOverlay({ key: pathKey, map: overlayOf(d) });
      })
      .catch((e: unknown) => {
        if (live) toast(problemText(e));
      });
    return () => {
      live = false;
    };
  }, [shownLayer, pathKey, pathList]);

  const marks = useMemo(
    () => (drawn ? pathMarks(drawn.graph, pathList ?? [], null, shownLayer, overlay?.key === pathKey ? overlay.map : null) : null),
    [drawn, pathList, shownLayer, overlay, pathKey],
  );

  const setScope = (s: Scope) => props.navigate(scopeSearch(props.search, s));
  const sites = useMemo(() => (inventory ? sitesOf(inventory) : []), [inventory]);
  const site = scope.kind === "site" ? scope.site : "";
  const device = scope.kind === "device" ? scope.device : "";
  const onDevice = (name: string) => {
    if (name === "") setScope({ kind: "twin" });
    else setScope({ kind: "device", device: name, hops: scope.kind === "device" ? scope.hops : 1 });
  };
  const deviceField = <DeviceField twin={twin} device={device} onDevice={onDevice} autoFocus={current?.state === "too-many"} />;

  const controls = (
    <span class="map-controls">
      {sites.length > 0 ? <SiteField sites={sites} site={site} onSite={(v) => setScope(v ? { kind: "site", site: v } : { kind: "twin" })} /> : null}
      {drawn && drawn.layers.length > 1 ? (
        <span class="map-field">
          <span class="t-label">Layer</span>
          <Segmented<Layer> label="Layer" value={shownLayer} options={drawn.layers} onChange={setLayer} />
        </span>
      ) : null}
      {current?.state !== "too-many" ? deviceField : null}
      {scope.kind === "device" ? (
        <span class="map-field">
          <span class="t-label">Hops</span>
          <Segmented<Hops> label="Hops" value={scope.hops} options={HOPS} onChange={(h) => setScope({ ...scope, hops: h })} />
        </span>
      ) : null}
      <label class="map-check">
        <input type="checkbox" checked={ports} onChange={() => setPorts(!ports)} />
        Port names
      </label>
      <label class="map-check">
        <input type="checkbox" checked={speeds} onChange={() => setSpeeds(!speeds)} />
        Link speed
      </label>
    </span>
  );

  const exportMenu = drawn ? (
    <MenuButton
      kind="menu"
      label="Export"
      align="end"
      button={
        <span class="with-icon map-export">
          Export
          <Icon name="menu" />
        </span>
      }
    >
      {(close) =>
        EXPORTS.map((x) => (
          <button
            type="button"
            class="menu-item"
            role="menuitem"
            tabIndex={-1}
            onClick={() => {
              saveFile(topologyFileUrl(twin, exportParams(scope, drawn.devices, x.format)), `${twin}-topology.${x.ext}`);
              close();
            }}
          >
            {x.label}
          </button>
        ))
      }
    </MenuButton>
  ) : null;

  let body;
  if (!current) body = null;
  else if (current.state === "too-many") {
    body = (
      <div class="map-state">
        {deviceField}
      </div>
    );
  } else if (current.state === "none") {
    body = (
      <div class="map-state">
        <Empty>no device</Empty>
      </div>
    );
  } else if (current.state === "problem") {
    body = (
      <div class="map-state">
        <Empty problem>{current.text}</Empty>
      </div>
    );
  } else if (marks) {
    body = (
      <MapCanvas
        graph={current.graph}
        layout={current.layout}
        index={current.index}
        layer={shownLayer}
        marks={marks}
        selected={selected}
        onSelect={setSelected}
        vendors={current.vendors}
        ports={ports}
        speeds={speeds}
        centre={centre}
      />
    );
  }

  const panel =
    drawn && selected !== null ? (
      <MapPanel
        twin={twin}
        graph={drawn.graph}
        layer={shownLayer}
        id={selected}
        onClose={() => setSelected(null)}
        onShow={(id) => {
          setSelected(id);
          setCentre((c) => ({ id, n: (c?.n ?? 0) + 1 }));
        }}
        onFunctions={props.onFunctions}
        onEntryPoint={props.onEntryPoint}
      />
    ) : null;

  return (
    <>
      <PageHead tabs={controls} actions={exportMenu} />
      <PanelLayout fill panel={panel}>
        <Card flush fill>
          {body}
        </Card>
      </PanelLayout>
    </>
  );
}
