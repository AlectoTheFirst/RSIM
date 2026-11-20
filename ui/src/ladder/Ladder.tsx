// The ladder of a path query: one row for each function, or for each
// device at the level device, with the forward path and the replies.
import type { JSX } from "preact";
import type { Answer, SourceText, Span, TraceStep, Verdict } from "../api/types";
import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { Hatch, HatchMark } from "../page/Hatch";
import { SIZE } from "../theme";
import { LaneNames, Lanes, laneX } from "./Lanes";
import {
  type Cell,
  type DecidingStep,
  delayShown,
  type DetailSource,
  destinationOf,
  detailSources,
  functionLabel,
  isRowSpan,
  type Ladder as LadderModel,
  type Rib,
  outcomeKnown,
  headerQosShown,
  qosShown,
  rateShown,
  type SectionRow,
  type Shown,
  type StepRow,
  verdictWord,
} from "./layout";

/**
 * The columns of a ladder: step, lanes, function, reason, the given
 * columns, rib, source lines, and the spare width at the end. The reason
 * takes the width of its longest text where the page has room, so that the
 * columns after it follow it directly.
 */
export function ladderColumns(lanes: number, fields: number[], reasonMin: number): { columns: string; min: number } {
  const lw = Math.max(1, lanes) * SIZE.lane;
  const fixed = [SIZE.colStep, lw, SIZE.colFunction, ...fields, SIZE.colRib, SIZE.colSource];
  return {
    columns: [
      `${SIZE.colStep}px`,
      `${lw}px`,
      `${SIZE.colFunction}px`,
      `minmax(${reasonMin}px, max-content)`,
      ...fields.map((f) => `${f}px`),
      `${SIZE.colRib}px`,
      `${SIZE.colSource}px`,
      "minmax(0, 1fr)",
    ].join(" "),
    min: fixed.reduce((a, b) => a + b, 0) + reasonMin,
  };
}

const FIELD_WIDTHS = [SIZE.colIp, SIZE.colPort, SIZE.colIp, SIZE.colPort, SIZE.colTransport];
const IS_NUMBER = [false, true, false, true, false];

/** The word of an outcome kind: with its colour if the engine knows it, else in a hatch mark. */
export function OutcomeWord(props: { kind: string; headline?: boolean }) {
  const { kind } = props;
  const known = outcomeKnown(kind);
  const word = (
    <span class={`${props.headline ? "t-headline" : "strong"}${known ? ` c-${kind}` : ""}`}>{verdictWord(kind)}</span>
  );
  return known ? word : <HatchMark>{word}</HatchMark>;
}

/** A value of the detail: plain if the twin knows it, else in a hatch mark with no colour. */
function ShownValue(props: { s: Shown }) {
  const v = <span class="t-value">{props.s.text}</span>;
  return props.s.known ? v : <HatchMark>{v}</HatchMark>;
}

/**
 * A verdict: its outcome word, its destination and its reason. With the
 * deciding step, the reason follows the device and the function of that
 * step, which a click selects and opens.
 */
export function VerdictText(props: {
  v: Verdict;
  headline?: boolean;
  at?: DecidingStep | null;
  onStep?: (d: DecidingStep) => void;
}) {
  const { v, at } = props;
  const dest = destinationOf(v);
  const reason = at ? at.reason : v.reason?.detail;
  return (
    <>
      <OutcomeWord kind={v.kind} headline={props.headline} />
      {dest ? (
        <>
          {" to "}
          <span class="t-value">{dest}</span>
        </>
      ) : null}
      {at ? (
        <>
          {" at "}
          <button type="button" class="link t-value" title="Open step" onClick={() => props.onStep?.(at)}>
            {at.step.device ? `${at.step.device} ${functionLabel(at.step)}` : at.step.function}
          </button>
          {reason ? ":" : ""}
        </>
      ) : null}
      {reason ? <span class="muted"> {reason}</span> : null}
    </>
  );
}

function CellView(props: { c: Cell; dir: StepRow["dir"]; i: number; h: number }) {
  const { c, dir, i, h } = props;
  const num = IS_NUMBER[i] ? " num" : "";
  switch (c.kind) {
    case "value":
      return <span class={`cell t-value${num}`}>{c.text}</span>;
    case "changed":
      return <span class={`cell t-value-changed c-${dir}${num}`}>{c.text}</span>;
    case "same":
      return <span class="cell same" />;
    case "hatch":
      return (
        <span class="cell hatched">
          <Hatch w={FIELD_WIDTHS[i]! - 2 * SIZE.cellPad} h={h - SIZE.ribPadY * 2} title={`not known: ${c.text}`} />
        </span>
      );
  }
}

export function RibCell(props: { rib: Rib; h: number }) {
  switch (props.rib) {
    case "hatch":
      return (
        <span class="rib hatched">
          <Hatch w={SIZE.colRib - 2 * SIZE.ribPadX} h={props.h - SIZE.ribPadY * 2} title="no RIB check" />
        </span>
      );
    case "matches":
      return <span class="rib t-value c-deliver" title="matches the collected RIB">matches</span>;
    case "differs":
      return <span class="rib t-value c-drop" title="differs from the collected RIB">differs</span>;
    default:
      return <span class="rib" />;
  }
}

export function SectionLine(props: { row: SectionRow; lanes: number; h: number }) {
  const { row, lanes, h } = props;
  return (
    <div class="ladder-row ladder-section" role="row">
      <span />
      <span class="lanes">
        <Lanes lanes={lanes} h={h} marks={null} />
      </span>
      <span class={row.muted ? "title t-body muted" : `title c-${row.dir}`}>
        {row.text}
        {row.verdict ? (
          <span class="t-body">
            {"  "}
            <VerdictText v={row.verdict} />
          </span>
        ) : null}
        {row.note ? <span class="t-body muted"> {row.note}</span> : null}
      </span>
    </div>
  );
}

/** Facts as label and value; facts with the same value share one row. */
function Facts(props: { rows: [string, Shown | JSX.Element | null][] }) {
  const out: [string[], Shown | JSX.Element][] = [];
  for (const [k, v] of props.rows) {
    if (v === null) continue;
    const prev = out[out.length - 1];
    const same =
      prev && !isElement(v) && !isElement(prev[1]) && prev[1].text === v.text && prev[1].known === v.known;
    if (same) prev[0].push(k);
    else out.push([[k], v]);
  }
  return (
    <div class="facts">
      {out.map(([k, v]) => (
        <>
          <span class="muted">{k.join(", ")}</span>
          <span>{isElement(v) ? v : <ShownValue s={v} />}</span>
        </>
      ))}
    </div>
  );
}

function isElement(v: Shown | JSX.Element): v is JSX.Element {
  return !("known" in v && "text" in v);
}

export interface DetailActions {
  copyExplain: (row: StepRow) => void;
  copyUrl: (row: StepRow) => void;
  /** The masked lines of a span; absent for a twin with no source text. */
  sourceLines?: (span: Span) => Promise<SourceText>;
}

/** The numbered lines of a span, with the note of the cut lines. */
function CodeLines(props: { t: SourceText }) {
  return (
    <div class="code t-value">
      {props.t.lines.map((l) => (
        <>
          <span class="ln">{l.number}</span>
          <span class="tx">{l.text}</span>
        </>
      ))}
      {props.t.note ? <span class="note muted">{props.t.note}</span> : null}
    </div>
  );
}

/**
 * The source spans of the opened row by file: the lines of the open span,
 * first the most specific one, and the other spans as labels that open
 * their lines. A row span, a span whose lines the API refuses, or a twin
 * with no source text, shows the label only.
 */
function SourceLines(props: { steps: readonly TraceStep[]; load: DetailActions["sourceLines"] }) {
  const { load } = props;
  const sources = detailSources(props.steps);
  const files: [string, DetailSource[]][] = [];
  for (const e of sources) {
    const f = files.find(([file]) => file === e.span.file);
    if (f) f[1].push(e);
    else files.push([e.span.file, [e]]);
  }
  const [open, setOpen] = useState<string | null>(sources.find((e) => !isRowSpan(e.span))?.key ?? null);
  const [text, setText] = useState<Record<string, SourceText | null>>({});
  const asked = useRef(new Set<string>());
  useEffect(() => {
    const s = sources.find((e) => e.key === open);
    if (!load || !s || asked.current.has(s.key)) return;
    asked.current.add(s.key);
    load(s.span).then(
      (t) => setText((m) => ({ ...m, [s.key]: t })),
      () => setText((m) => ({ ...m, [s.key]: null })),
    );
  }, [open, load]);
  return (
    <div>
      {files.map(([file, spans]) => (
        <>
          <div class="muted head">
            Source <span class="t-value">{file}</span>
          </div>
          {spans.map((e) => {
            const t = e.key === open ? text[e.key] : null;
            if (t) return <CodeLines t={t} />;
            return load && !isRowSpan(e.span) ? (
              <button type="button" class="plain span-label t-value" onClick={() => setOpen(e.key)}>
                {e.label}
              </button>
            ) : (
              <span class="span-label t-value">{e.label}</span>
            );
          })}
        </>
      ))}
    </div>
  );
}

function Detail(props: { row: StepRow; lanes: number; actions: DetailActions }) {
  const { row, lanes, actions } = props;
  const last: TraceStep = row.steps[row.steps.length - 1]!;
  const w = Math.max(1, lanes) * SIZE.lane;
  const x = laneX(row.lane);
  const cls = row.dir === "forward" ? "path-forward" : "path-reply";
  const rate = last.rate_condition ? rateShown(last.rate_condition) : null;
  const v = (t: string) => <span class="t-value">{t}</span>;
  // The full reason, only where the row cuts it.
  const [cut, setCut] = useState(false);
  useLayoutEffect(() => {
    const el = document.querySelector(`[id="row-${row.key}"] > .reason`);
    setCut(!!el && el.scrollWidth > el.clientWidth);
  });
  return (
    <div class="ladder-detail" role="row">
      <span />
      <span class="lanes">
        <svg width={w} aria-hidden="true">
          {Array.from({ length: lanes }, (_, i) => (
            <line class="lane-guide" x1={laneX(i)} y1="0" x2={laneX(i)} y2="100%" />
          ))}
          {row.end ? null : <rect class={cls} x={x - SIZE.pathLine / 2} y="0" width={SIZE.pathLine} height="100%" />}
        </svg>
      </span>
      <div class="detail">
        <SourceLines key={row.key} steps={row.steps} load={actions.sourceLines} />
        <div>
          <div class="muted head">
            Parameters of <span class="t-value">{last.function}</span>
          </div>
          <Facts
            rows={[
              ["reason", cut ? <span class="t-body">{row.reason}</span> : null],
              ["kind", v(last.kind)],
              ["delay", delayShown(last.delay)],
              ["alternative", last.alternative ? v(`${last.alternative.index + 1} of ${last.alternative.count}: ${last.alternative.label}`) : null],
              ["flood copy", last.flood_copy ? v(`${last.flood_copy.index + 1} of ${last.flood_copy.count} to ${last.flood_copy.port}`) : null],
              [
                "rate",
                rate ? (
                  <span>
                    {v(rate.action)} <ShownValue s={rate.rate} />
                  </span>
                ) : null,
              ],
            ]}
          />
        </div>
        <div>
          <div class="muted head">QoS at this function</div>
          <Facts
            rows={[
              ["dscp", headerQosShown(last.qos.dscp)],
              ["ecn", headerQosShown(last.qos.ecn)],
              ["traffic class", qosShown(last.qos.traffic_class)],
              ["drop precedence", qosShown(last.qos.drop_precedence)],
              ["queue", qosShown(last.qos.queue)],
            ]}
          />
          <div class="group actions">
            <button type="button" onClick={() => actions.copyExplain(row)}>
              Copy as rsim explain
            </button>
            <button type="button" onClick={() => actions.copyUrl(row)}>
              Copy step URL
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export function LadderHead(props: { model: Pick<LadderModel, "lanes">; fieldHeads: JSX.Element[]; reason: string }) {
  return (
    <div class="ladder-row ladder-head t-label" role="row">
      <span />
      <span class="lanes head">
        <LaneNames lanes={props.model.lanes} />
      </span>
      <span>function</span>
      <span>{props.reason}</span>
      {props.fieldHeads}
      <span>rib</span>
      <span>source lines</span>
    </div>
  );
}

export function pathFieldHeads(): JSX.Element[] {
  const two = (a: string, b: string, num = false) => (
    <span class={`cell${num ? " num" : ""}`}>
      {a || " "}
      <br />
      {b}
    </span>
  );
  return [two("source", "ip"), two("", "port", true), two("destination", "ip"), two("", "port", true), two("", "transport")];
}

export function PathLadder(props: {
  answer: Answer;
  model: LadderModel;
  h: number;
  selected: string | null;
  open: boolean;
  onSelect: (key: string) => void;
  actions: DetailActions;
}) {
  const { model, h, selected, open, onSelect, actions } = props;
  const n = model.lanes.length;
  const grid = ladderColumns(n, FIELD_WIDTHS, SIZE.colReason);
  return (
    <div class="ladder" role="table" style={{ "--ladder-columns": grid.columns, minWidth: `${grid.min}px` }}>
      <LadderHead model={model} fieldHeads={pathFieldHeads()} reason="reason" />
      {model.rows.map((row) => {
        if (row.type === "section") return <SectionLine key={row.key} row={row} lanes={n} h={h} />;
        const sel = row.key === selected;
        return (
          <>
            <div
              key={row.key}
              id={`row-${row.key}`}
              class={`ladder-row step${sel ? " selected" : ""}`}
              role="row"
              aria-selected={sel}
              onClick={() => onSelect(row.key)}
            >
              <span class="ix t-index">{row.label}</span>
              <span class="lanes">
                <Lanes lanes={n} h={h} marks={row} />
              </span>
              <span class="t-value">{row.fn}</span>
              <span class="t-body reason" title={row.reason}>
                {row.reason}
              </span>
              {row.cells.map((c, i) => (
                <CellView c={c} dir={row.dir} i={i} h={h} />
              ))}
              <RibCell rib={row.rib} h={h} />
              <span class="t-value muted" title={row.steps.flatMap((s) => s.provenance.map((p) => `${p.file}:${p.first_line}-${p.last_line}`)).join("\n")}>
                {row.source}
              </span>
            </div>
            {sel && open ? <Detail row={row} lanes={n} actions={actions} /> : null}
          </>
        );
      })}
    </div>
  );
}
