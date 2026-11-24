// The panel of the selected card of the map: the facts of a device, its
// links and its endpoints, and the actions of the device.
import { useEffect, useState } from "preact/hooks";
import { tableRows } from "../api/client";
import { HatchText } from "../page/Hatch";
import { Panel } from "../page/Panel";
import { VirtualRows } from "../page/VirtualRows";
import { utcText } from "../page/frame";
import { SIZE } from "../theme";
import { type EndpointRow, FACT_LABELS, type PanelLink, endpointRowsOf, panelLinks, speedOf } from "./draw";
import { type Layer, type MapGraph, deviceId, groupId, isTwinDevice } from "./graph";
import { type FactValue, deviceFacts, deviceFactsParams, endpointsParams, entryPoint } from "./select";

/** The endpoints that one request reads. */
const PAGE = 100;

const NOT_KNOWN = "not known";

function Value(props: { v: string | null; title?: string | null }) {
  return props.v === null ? <HatchText title={props.title ?? undefined}>{NOT_KNOWN}</HatchText> : <span class="t-value">{props.v}</span>;
}

function factText(f: FactValue): string | null {
  if (f.value !== null && f.fact === "collected_at") {
    const t = Date.parse(f.value);
    return Number.isNaN(t) ? f.value : utcText(t);
  }
  return f.value;
}

function Facts(props: { twin: string; device: string }) {
  const [facts, setFacts] = useState<{ device: string; list: FactValue[] | null } | null>(null);
  useEffect(() => {
    let live = true;
    tableRows(props.twin, "devices", deviceFactsParams(props.device))
      .then((t) => {
        if (live) setFacts({ device: props.device, list: deviceFacts(t.columns, t.rows) });
      })
      .catch(() => {
        if (live) setFacts({ device: props.device, list: null });
      });
    return () => {
      live = false;
    };
  }, [props.twin, props.device]);
  if (!facts || facts.device !== props.device || facts.list === null) return null;
  const shown = facts.list.filter((f) => f.fact !== "store_device" || (f.value !== null && f.value !== props.device));
  return (
    <div class="map-facts">
      {shown.map((f) => (
        <>
          <span class="t-label">{FACT_LABELS[f.fact] ?? f.fact}</span>
          <Value v={factText(f)} title={f.reason} />
        </>
      ))}
    </div>
  );
}

function Links(props: { rows: PanelLink[]; layer: Layer; resetKey: string; onShow: (id: string) => void }) {
  const [current, setCurrent] = useState<number | null>(null);
  useEffect(() => setCurrent(null), [props.resetKey]);
  const overlay = props.layer === "overlay";
  const head = overlay ? ["peer", "source", "vni"] : ["port", "peer", "speed"];
  return (
    <section class="map-section">
      <h3 class="t-section">Links</h3>
      <VirtualRows
        id="map-links"
        label="Links"
        class="map-list map-links"
        count={props.rows.length}
        estimate={SIZE.button}
        current={current}
        onCurrent={setCurrent}
        onActivate={(i) => props.onShow(props.rows[i]!.far)}
        resetKey={props.resetKey}
        headHeight={SIZE.button}
        head={
          <div class="map-row head">
            {head.map((h) => (
              <span class="t-label">{h}</span>
            ))}
          </div>
        }
        row={(i) => {
          const r = props.rows[i]!;
          return overlay ? (
            <div class="map-row">
              <span class="t-value">
                {r.farLabel}
                {r.farPort ? ` ${r.farPort}` : ""}
              </span>
              <Value v={r.near} />
              <Value v={r.vnis} />
            </div>
          ) : (
            <div class="map-row">
              <Value v={r.near} />
              <span class="t-value">
                {r.farLabel}
                {r.farPort ? ` ${r.farPort}` : ""}
              </span>
              <Value v={speedOf(r)} />
            </div>
          );
        }}
      />
    </section>
  );
}

interface Page {
  device: string;
  rows: EndpointRow[];
  cursor: string | null;
  busy: boolean;
}

function Endpoints(props: { twin: string; device: string }) {
  const [page, setPage] = useState<Page>({ device: "", rows: [], cursor: null, busy: false });
  const [current, setCurrent] = useState<number | null>(null);

  const load = (device: string, cursor: string | null, rows: EndpointRow[]) => {
    setPage({ device, rows, cursor, busy: true });
    tableRows(props.twin, "attachments", { ...endpointsParams(device, PAGE, cursor), columns: "host,address,interface", sort: "host,address" })
      .then((t) => setPage((p) => (p.device === device ? { device, rows: [...rows, ...endpointRowsOf(t)], cursor: t.next_cursor ?? null, busy: false } : p)))
      .catch(() => setPage((p) => (p.device === device ? { ...p, cursor: null, busy: false } : p)));
  };

  useEffect(() => {
    setCurrent(null);
    load(props.device, null, []);
  }, [props.twin, props.device]);

  const rows = page.device === props.device ? page.rows : [];
  return (
    <section class="map-section fill">
      <h3 class="t-section">Endpoints</h3>
      <VirtualRows
        id="map-endpoints"
        label="Endpoints"
        class="map-list map-endpoints"
        count={rows.length}
        estimate={SIZE.button}
        current={current}
        onCurrent={setCurrent}
        resetKey={props.device}
        onEnd={page.cursor && !page.busy ? () => load(page.device, page.cursor, page.rows) : undefined}
        headHeight={SIZE.button}
        head={
          <div class="map-row map-endpoint head">
            <span class="t-label">host</span>
            <span class="t-label">address</span>
            <span class="t-label">interface</span>
          </div>
        }
        row={(i) => {
          const r = rows[i]!;
          return (
            <div class="map-row map-endpoint">
              <span class="map-host">
                <Value v={r.host} />
              </span>
              <Value v={r.address} />
              <Value v={r.interface} />
            </div>
          );
        }}
      />
    </section>
  );
}

/** The panel of a card: a device, the endpoints of a device, an endpoint of a path, or a neighbour outside the twin. */
export function MapPanel(props: {
  twin: string;
  graph: MapGraph;
  layer: Layer;
  id: string;
  onClose: () => void;
  onShow: (id: string) => void;
  onFunctions: (device: string) => void;
  onEntryPoint: (ingress: string) => void;
  /** The action that adds the neighbours of a device to the scope, or null when the scope has them. */
  onExpand: (device: string) => (() => void) | null;
  returnFocus?: { current: HTMLElement | null };
}) {
  const n = props.graph.node.get(props.id);
  if (!n) return null;
  const device = n.device;
  const hasEndpoints = device !== null && (props.graph.node.get(groupId(device))?.count ?? 0) > 0;
  const twinDevice = isTwinDevice(n);
  const expand = twinDevice && device !== null ? props.onExpand(device) : null;
  const deviceFoot =
    device !== null ? (
      <>
        {expand ? (
          <button type="button" onClick={expand}>
            Show neighbours
          </button>
        ) : null}
        <button type="button" onClick={() => props.onFunctions(device)}>
          View functions
        </button>
        <button type="button" onClick={() => props.onEntryPoint(entryPoint(device))}>
          Use as entry point
        </button>
      </>
    ) : undefined;

  if (twinDevice && device !== null) {
    return (
      <Panel title={<span class="t-value strong">{device}</span>} label={device} onClose={props.onClose} foot={deviceFoot} returnFocus={props.returnFocus} class="map-panel">
        <Facts twin={props.twin} device={device} />
        <Links rows={panelLinks(props.graph, props.id, props.layer)} layer={props.layer} resetKey={`${props.id}|${props.layer}`} onShow={props.onShow} />
        {hasEndpoints ? <Endpoints twin={props.twin} device={device} /> : null}
      </Panel>
    );
  }
  if (n.kind === "endpoints" && device !== null) {
    return (
      <Panel title={<span class="t-value strong">{device}</span>} label={device} onClose={props.onClose} foot={deviceFoot} returnFocus={props.returnFocus} class="map-panel">
        <Endpoints twin={props.twin} device={device} />
      </Panel>
    );
  }
  if (n.kind === "endpoint" && device !== null) {
    const row = panelLinks(props.graph, props.id, "physical").find((r) => r.far === deviceId(device));
    const port = row?.farPort ?? null;
    return (
      <Panel
        title={<span class="t-value strong">{n.label}</span>}
        label={n.label}
        onClose={props.onClose}
        returnFocus={props.returnFocus}
        class="map-panel"
        foot={
          <button type="button" onClick={() => props.onEntryPoint(entryPoint(device, port))}>
            Use as entry point
          </button>
        }
      >
        <div class="map-facts">
          <span class="t-label">device</span>
          <span class="t-value">{device}</span>
          <span class="t-label">interface</span>
          <Value v={port} />
        </div>
      </Panel>
    );
  }
  return (
    <Panel title={<span class="t-value strong">{n.label}</span>} label={n.label} onClose={props.onClose} returnFocus={props.returnFocus} class="map-panel">
      <Links rows={panelLinks(props.graph, props.id, props.layer)} layer={props.layer} resetKey={`${props.id}|${props.layer}`} onShow={props.onShow} />
    </Panel>
  );
}
