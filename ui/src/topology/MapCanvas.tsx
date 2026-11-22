// The map: the cards and the lines inside the window as SVG, with pan by
// drag and arrow keys, zoom by the wheel and the buttons, and the hit test
// of a click.
import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { hatchLines } from "../page/Hatch";
import { Icon } from "../page/Icon";
import { SIZE } from "../theme";
import { type Layer, type MapGraph, type MapNode, type Pair, linkCount, speedText, speedsOf } from "./graph";
import type { Card, Line, MapLayout } from "./layout";
import type { PathMarks } from "./paths";
import { activeLines } from "./select";
import { type Box, Collider, cardLines, openView, countBox, panKey, pathData, speedBox, tagBox, textInset, wheelFactor } from "./draw";
import { type MapIndex, type MapView, centreOn, cull, fitView, hitTest, panBy, showsText, windowOf, zoomAt, zoomIn, zoomOut } from "./view";

const W = SIZE.mapCard;
const H = SIZE.mapCardHeight;
const STRIP = hatchLines(SIZE.hatchSquare, H);

/** The rounded ends of an endpoint, an endpoints card and a network outside the twin. */
const roundEnds = (n: MapNode) => n.kind !== "device";
const radiusOf = (n: MapNode) => (roundEnds(n) ? H / 2 : SIZE.cardRadius);

/** A request to bring a card to the centre; `n` makes each request new. */
export interface CentreOn {
  id: string;
  n: number;
}

export function MapCanvas(props: {
  graph: MapGraph;
  layout: MapLayout;
  index: MapIndex;
  layer: Layer;
  marks: PathMarks;
  selected: string | null;
  onSelect: (id: string | null) => void;
  vendors: ReadonlyMap<string, string>;
  ports: boolean;
  speeds: boolean;
  centre: CentreOn | null;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [view, setView] = useState<MapView | null>(null);
  const fitted = useRef<MapLayout | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [focus, setFocus] = useState<string | null>(null);
  const drag = useRef<{ x: number; y: number; view: MapView; moved: boolean; id: number } | null>(null);
  const live = useRef({ view, size, index: props.index, layer: props.layer });
  live.current = { view, size, index: props.index, layer: props.layer };

  useLayoutEffect(() => {
    const b = box.current;
    if (!b) return;
    const read = () => setSize((s) => (s.w === b.clientWidth && s.h === b.clientHeight ? s : { w: b.clientWidth, h: b.clientHeight }));
    read();
    const ro = new ResizeObserver(read);
    ro.observe(b);
    return () => ro.disconnect();
  }, []);

  useLayoutEffect(() => {
    if (size.w === 0 || size.h === 0 || fitted.current === props.layout) return;
    fitted.current = props.layout;
    setView(openView(props.layout, [...props.marks.cards], size.w, size.h));
  }, [props.layout, size.w, size.h]);

  useEffect(() => {
    const b = box.current;
    if (!b) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const r = b.getBoundingClientRect();
      const f = wheelFactor(e.deltaY, e.deltaMode);
      setView((v) => (v ? zoomAt(v, f, e.clientX - r.left, e.clientY - r.top) : v));
    };
    b.addEventListener("wheel", onWheel, { passive: false });
    return () => b.removeEventListener("wheel", onWheel);
  }, []);

  useEffect(() => {
    const c = props.centre;
    if (!c) return;
    const card = props.layout.card.get(c.id);
    const { size: s } = live.current;
    if (card && s.w > 0) setView((v) => (v ? centreOn(v, card, s.w, s.h) : v));
  }, [props.centre]);

  const point = (e: PointerEvent) => {
    const r = box.current!.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  };

  const onDown = (e: PointerEvent) => {
    if (e.button !== 0 || !view) return;
    if ((e.target as Element).closest(".map-zoom")) return;
    drag.current = { x: e.clientX, y: e.clientY, view, moved: false, id: e.pointerId };
  };

  const onMove = (e: PointerEvent) => {
    const d = drag.current;
    if (d && d.id === e.pointerId) {
      const dx = e.clientX - d.x;
      const dy = e.clientY - d.y;
      if (!d.moved && Math.hypot(dx, dy) < SIZE.mapDrag) return;
      if (!d.moved) {
        d.moved = true;
        box.current?.setPointerCapture(e.pointerId);
      }
      setView(panBy(d.view, dx, dy));
      return;
    }
    const { view: v, index, layer } = live.current;
    if (!v) return;
    const p = point(e);
    const hit = hitTest(index, v, p.x, p.y, layer);
    const id = hit?.kind === "card" ? hit.card.id : null;
    if (id !== hover) setHover(id);
  };

  const onUp = (e: PointerEvent) => {
    const d = drag.current;
    drag.current = null;
    if (!d || d.id !== e.pointerId) return;
    if (d.moved) {
      box.current?.releasePointerCapture(e.pointerId);
      return;
    }
    if ((e.target as Element).closest(".map-zoom")) return;
    const { view: v, index, layer } = live.current;
    if (!v) return;
    const p = point(e);
    const hit = hitTest(index, v, p.x, p.y, layer);
    if (hit?.kind === "card") props.onSelect(hit.card.id);
    else if (hit === null) props.onSelect(null);
  };

  const zoomBy = (f: (v: MapView, w: number, h: number) => MapView) => setView((v) => (v ? f(v, size.w, size.h) : v));

  let drawing = null;
  if (view && size.w > 0) {
    drawing = (
      <MapLayers
        {...props}
        view={view}
        w={size.w}
        h={size.h}
        hover={hover}
        focus={focus}
        onFocusCard={setFocus}
      />
    );
  }

  return (
    <div
      ref={box}
      class="map"
      tabIndex={0}
      role="group"
      aria-label="Map"
      onPointerDown={onDown}
      onPointerMove={onMove}
      onPointerUp={onUp}
      onPointerCancel={() => {
        drag.current = null;
      }}
      onPointerLeave={() => {
        if (!drag.current) setHover(null);
      }}
      onKeyDown={(e) => {
        const d = panKey(e.key);
        if (!d || (e.target as Element).closest(".map-zoom")) return;
        e.preventDefault();
        setView((v) => (v ? panBy(v, d[0], d[1]) : v));
      }}
    >
      {drawing}
      <span class="map-zoom" role="group" aria-label="Zoom">
        <button type="button" class="icon" aria-label="Zoom in" onClick={() => zoomBy(zoomIn)}>
          <Icon name="zoom-in" />
        </button>
        <button type="button" class="icon" aria-label="Zoom out" onClick={() => zoomBy(zoomOut)}>
          <Icon name="zoom-out" />
        </button>
        <button type="button" class="icon" aria-label="Fit the map" onClick={() => setView(fitView(props.layout, size.w, size.h))}>
          <Icon name="fit" />
        </button>
      </span>
    </div>
  );
}

/** The SVG of the map in a window. */
function MapLayers(props: {
  graph: MapGraph;
  layout: MapLayout;
  index: MapIndex;
  layer: Layer;
  marks: PathMarks;
  selected: string | null;
  onSelect: (id: string | null) => void;
  vendors: ReadonlyMap<string, string>;
  ports: boolean;
  speeds: boolean;
  view: MapView;
  w: number;
  h: number;
  hover: string | null;
  focus: string | null;
  onFocusCard: (id: string | null) => void;
}) {
  const { view, w, h, layer, marks, graph } = props;
  const z = view.zoom;
  const { cards, lines } = cull(props.index, windowOf(view, w, h), layer);
  const active = activeLines(graph, [props.selected, props.hover], layer);
  const text = showsText(z);

  // The lines in the order of their weight: plain, then the paths, then the lines of the selected card and of the card under the pointer.
  const plain: Line[] = [];
  const onPath: Line[] = [];
  const lit: Line[] = [];
  for (const l of lines) {
    if (active.has(l.key)) lit.push(l);
    else if (marks.pairs.has(l.key)) onPath.push(l);
    else plain.push(l);
  }
  const lineEl = (l: Line, cls: string) => {
    const p = l.pair;
    const c = `map-line ${cls}${p.dashed ? " dashed" : ""}${marks.pairs.has(l.key) ? " path" : ""}`;
    return <path key={l.key} class={c} d={pathData(l.pts)} />;
  };

  const labels: preact.JSX.Element[] = [];
  if (text && (props.ports || props.speeds)) {
    const placed = new Collider();
    for (const c of cards) placed.add({ x: c.x, y: c.y, w: c.w, h: c.h });
    for (const l of [...lit, ...onPath, ...plain]) labels.push(...lineLabels(l, l.pair, props.ports, props.speeds, placed));
  }

  return (
    <svg class="map-svg" width={w} height={h}>
      <defs>
        <clipPath id="map-strip">
          <rect width={SIZE.hatchSquare} height={H} />
        </clipPath>
        <clipPath id="map-shape-card">
          <rect width={W} height={H} rx={SIZE.cardRadius} />
        </clipPath>
        <clipPath id="map-shape-round">
          <rect width={W} height={H} rx={H / 2} />
        </clipPath>
      </defs>
      <g transform={`translate(${-view.x * z} ${-view.y * z}) scale(${z})`}>
        <g class="map-lines">
          {plain.map((l) => lineEl(l, ""))}
          {onPath.map((l) => lineEl(l, ""))}
          {lit.map((l) => lineEl(l, "active"))}
        </g>
        <g class="map-labels">{labels}</g>
        <g class="map-cards">
          {cards.map((c) => (
            <CardEl
              key={c.id}
              card={c}
              text={text}
              vendor={c.node.device !== null && c.node.kind === "device" ? (props.vendors.get(c.node.device) ?? null) : null}
              path={marks.cards.has(c.id)}
              end={marks.ends.get(c.id) ?? null}
              selected={props.selected === c.id}
              hover={props.hover === c.id}
              focus={props.focus === c.id}
              onSelect={props.onSelect}
              onFocusCard={props.onFocusCard}
            />
          ))}
        </g>
      </g>
    </svg>
  );
}

/** The port tags at the ends of a line of one link, and the number of links and the speed at its middle, each where it overlaps no placed box. */
function lineLabels(l: Line, p: Pair, ports: boolean, speeds: boolean, placed: Collider): preact.JSX.Element[] {
  const out: preact.JSX.Element[] = [];
  const tag = (b: Box, t: string, k: string, cls: string) => {
    if (!placed.place(b)) return;
    out.push(
      <g key={k} class={cls}>
        <rect x={b.x} y={b.y} width={b.w} height={b.h} rx={SIZE.mapTagRadius} />
        <text x={b.x + b.w / 2} y={b.y + b.h / 2}>
          {t}
        </text>
      </g>,
    );
  };
  if (ports && p.layer === "physical" && p.links.length === 1) {
    const link = p.links[0]!;
    if (link.a.port) tag(tagBox(l.ends[0], link.a.port), link.a.port, `${l.key}|a`, "map-tag");
    if (link.b.port) tag(tagBox(l.ends[1], link.b.port), link.b.port, `${l.key}|b`, "map-tag");
  }
  const n = linkCount(p);
  let count: Box | null = null;
  if (n > 1) {
    const b = countBox(l, n);
    if (placed.place(b)) {
      count = b;
      out.push(
        <g key={`${l.key}|n`} class="map-count">
          <rect x={b.x} y={b.y} width={b.w} height={b.h} rx={SIZE.mapTagRadius} />
          <text x={b.x + b.w / 2} y={b.y + b.h / 2}>
            {n}
          </text>
        </g>,
      );
    }
  }
  if (speeds && p.layer === "physical" && p.links.length > 0 && p.a.startsWith("d:") && p.b.startsWith("d:")) {
    const s = speedsOf(p);
    if (s.length > 0) {
      const t = s.map(speedText).join(", ");
      const b = speedBox(l, t, count);
      if (placed.place(b)) {
        out.push(
          <text key={`${l.key}|s`} class="map-speed" x={b.x + b.w / 2} y={b.y + b.h / 2}>
            {t}
          </text>,
        );
      }
    } else {
      const q = SIZE.hatchSquare;
      const b = speedBox(l, "", count);
      const x = l.mid.horizontal ? l.mid.x - q / 2 : b.x;
      const box = { x, y: b.y + (b.h - q) / 2, w: q, h: q };
      if (placed.place(box)) {
        out.push(
          <g key={`${l.key}|s`} class="map-unknown" transform={`translate(${box.x} ${box.y})`}>
            <title>not known</title>
            <rect width={q} height={q} />
            {hatchLines(q, q).map(([x1, y1, x2, y2], i) => (
              <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} clip-path="url(#map-strip)" />
            ))}
          </g>,
        );
      }
    }
  }
  return out;
}

/** The name of a card for assistive technology. */
function cardName(n: MapNode): string {
  return n.kind === "endpoints" ? `Endpoints ${n.device ?? ""}` : n.label;
}

function CardEl(props: {
  card: Card;
  text: boolean;
  vendor: string | null;
  path: boolean;
  end: string | null;
  selected: boolean;
  hover: boolean;
  focus: boolean;
  onSelect: (id: string | null) => void;
  onFocusCard: (id: string | null) => void;
}) {
  const { card: c } = props;
  const n = c.node;
  const r = radiusOf(n);
  const cls = [
    "map-card",
    `kind-${n.kind}`,
    props.path ? "path" : "",
    props.end ? `end-${props.end}` : "",
    props.hover ? "hover" : "",
    n.hatch ? "outside" : "",
  ]
    .filter(Boolean)
    .join(" ");
  const lines = props.text ? cardLines(n, props.vendor) : [];
  const centred = n.kind === "endpoint" || n.kind === "endpoints";
  const x = centred ? W / 2 : textInset(n);
  const top = (H - lines.length * SIZE.mapCardLine) / 2;
  const ring = SIZE.mapRing;
  const off = SIZE.focusOffset;
  return (
    <g
      class={cls}
      transform={`translate(${c.x} ${c.y})`}
      tabIndex={0}
      role="button"
      aria-label={cardName(n)}
      aria-pressed={props.selected}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          props.onSelect(c.id);
        }
      }}
      onFocus={(e) => props.onFocusCard((e.currentTarget as Element).matches(":focus-visible") ? c.id : null)}
      onBlur={() => props.onFocusCard(null)}
    >
      {props.selected ? <rect class="map-ring" x={-ring} y={-ring} width={W + 2 * ring} height={H + 2 * ring} rx={r + ring} /> : null}
      {props.focus ? <rect class="map-focus" x={-off} y={-off} width={W + 2 * off} height={H + 2 * off} rx={r + off} /> : null}
      <rect class="map-box" width={W} height={H} rx={r} />
      {n.hatch || props.end === "unknown" ? (
        <g clip-path={`url(#${roundEnds(n) ? "map-shape-round" : "map-shape-card"})`}>
          <g class="map-hatch" clip-path="url(#map-strip)">
            {STRIP.map(([x1, y1, x2, y2], i) => (
              <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} />
            ))}
          </g>
        </g>
      ) : null}
      {lines.map((l, i) => (
        <text key={i} class={l.kind === "name" ? "map-name" : "map-sub"} x={x} y={top + (i + 0.5) * SIZE.mapCardLine} text-anchor={centred ? "middle" : "start"}>
          {l.text}
        </text>
      ))}
    </g>
  );
}
