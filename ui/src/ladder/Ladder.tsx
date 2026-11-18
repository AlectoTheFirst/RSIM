// The ladder of a path query: one row for each function, or for each
// device at the level device, with the forward path and the replies.
import type { JSX } from "preact";
import type { Answer, TraceStep, Verdict } from "../api/types";
import { Hatch, HatchMark } from "../page/Hatch";
import { SIZE, TYPE } from "../theme";
import { LaneNames, Lanes, laneX } from "./Lanes";
import {
  type Cell,
  delayShown,
  destinationOf,
  detailSpans,
  type Ladder as LadderModel,
  type Rib,
  outcomeKnown,
  qosShown,
  rateShown,
  type SectionRow,
  type Shown,
  type StepRow,
  verdictWord,
} from "./layout";

export function ladderColumns(lanes: number, fields: string[]): string {
  return [
    `${SIZE.colStep}px`,
    `${Math.max(1, lanes) * SIZE.lane}px`,
    `${SIZE.colFunction}px`,
    `minmax(${SIZE.colReason}px, 1fr)`,
    ...fields,
    `${SIZE.colRib}px`,
    `${SIZE.colSource}px`,
  ].join(" ");
}

const FIELD_COLUMNS = [
  `${SIZE.colIp}px`,
  `${SIZE.colPort}px`,
  `${SIZE.colIp}px`,
  `${SIZE.colPort}px`,
  `${SIZE.colTransport}px`,
];
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

export function VerdictText(props: { v: Verdict; headline?: boolean }) {
  const { v } = props;
  const dest = destinationOf(v);
  return (
    <>
      <OutcomeWord kind={v.kind} headline={props.headline} />
      {dest ? (
        <>
          {" to "}
          <span class="t-value">{dest}</span>
        </>
      ) : null}
      {v.reason ? <span class="muted"> {v.reason.detail}</span> : null}
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
          <Hatch w={FIELD_WIDTHS[i]! - 2 * SIZE.buttonPad} h={h - SIZE.buttonGap * 2} title={`not known: ${c.text}`} />
        </span>
      );
  }
}

export function RibCell(props: { rib: Rib; h: number }) {
  switch (props.rib) {
    case "hatch":
      return (
        <span class="cell hatched">
          <Hatch w={SIZE.colRib - 2 * SIZE.buttonPad} h={props.h - SIZE.buttonGap * 2} title="not checked against a collected RIB" />
        </span>
      );
    case "matches":
      return <span class="cell t-value c-deliver">matches</span>;
    case "differs":
      return <span class="cell t-value c-drop">differs</span>;
    default:
      return <span class="cell" />;
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
      <span class={`title c-${row.dir}`}>
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

function Facts(props: { rows: [string, JSX.Element | string | null][] }) {
  return (
    <div class="facts">
      {props.rows
        .filter(([, v]) => v !== null && v !== "")
        .map(([k, v]) => (
          <>
            <span class="t-label">{k}</span>
            <span>{v}</span>
          </>
        ))}
    </div>
  );
}

export interface DetailActions {
  copyExplain: (row: StepRow) => void;
  copyUrl: (row: StepRow) => void;
}

function Detail(props: { row: StepRow; lanes: number; actions: DetailActions }) {
  const { row, lanes, actions } = props;
  const last: TraceStep = row.steps[row.steps.length - 1]!;
  const w = Math.max(1, lanes) * SIZE.lane;
  const x = laneX(row.lane);
  const cls = row.dir === "forward" ? "path-forward" : "path-reply";
  const spans = detailSpans(row.steps);
  const rate = last.rate_condition ? rateShown(last.rate_condition) : null;
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
        <div>
          <div class="t-label">source lines</div>
          <ul class="spans">
            {spans.map((l) => (
              <li class="t-value">{l}</li>
            ))}
          </ul>
          <div class="muted">The API does not serve the text of the source lines.</div>
        </div>
        <div>
          <div class="t-label">function</div>
          <Facts
            rows={[
              ["function", <span class="t-value">{last.function}</span>],
              ["kind", <span class="t-value">{last.kind}</span>],
              ["outcome", <span class="t-value">{last.outcome.kind}{last.outcome.next ? ` to ${last.outcome.next}` : ""}</span>],
              ["reason", <span class="t-value">{last.reason.code}</span>],
              ["delay", <ShownValue s={delayShown(last.delay)} />],
              ["alternative", last.alternative ? <span class="t-value">{`${last.alternative.index + 1} of ${last.alternative.count}: ${last.alternative.label}`}</span> : null],
              ["flood copy", last.flood_copy ? <span class="t-value">{`${last.flood_copy.index + 1} of ${last.flood_copy.count} to ${last.flood_copy.port}`}</span> : null],
              [
                "rate",
                rate ? (
                  <span>
                    <span class="t-value">{rate.action}</span> <ShownValue s={rate.rate} />
                  </span>
                ) : null,
              ],
              ["rib guard", <span class="t-value">{last.rib_guard}</span>],
            ]}
          />
        </div>
        <div>
          <div class="t-label">QoS at this function</div>
          <Facts
            rows={[
              ["dscp", <ShownValue s={qosShown(last.qos.dscp)} />],
              ["ecn", <ShownValue s={qosShown(last.qos.ecn)} />],
              ["traffic class", <ShownValue s={qosShown(last.qos.traffic_class)} />],
              ["drop precedence", <ShownValue s={qosShown(last.qos.drop_precedence)} />],
              ["queue", <ShownValue s={qosShown(last.qos.queue)} />],
            ]}
          />
          <div class="group actions">
            <button type="button" onClick={() => actions.copyExplain(row)}>
              Copy as rsim explain
            </button>
            <button type="button" onClick={() => actions.copyUrl(row)}>
              Copy the step URL
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export function LadderHead(props: { model: LadderModel; fieldHeads: JSX.Element[] }) {
  const { model } = props;
  return (
    <div class="ladder-row ladder-head t-label" role="row">
      <span />
      <span class="lanes head">
        <LaneNames lanes={model.lanes} line={TYPE.index.line} />
      </span>
      <span>function</span>
      <span>reason</span>
      {props.fieldHeads}
      <span class="cell">rib</span>
      <span>source lines</span>
    </div>
  );
}

export function pathFieldHeads(): JSX.Element[] {
  const two = (a: string, b: string, num = false) => (
    <span class={`cell${num ? " num" : ""}`}>
      {a}
      <br />
      {b}
    </span>
  );
  return [two("source", "ip"), two("", "port", true), two("destination", "ip"), two("", "port", true), two("network", "transport")];
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
  return (
    <div class="ladder" role="table" style={{ "--ladder-columns": ladderColumns(n, FIELD_COLUMNS) }}>
      <LadderHead model={model} fieldHeads={pathFieldHeads()} />
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
              <span class="t-body">{row.reason}</span>
              {row.cells.map((c, i) => (
                <CellView c={c} dir={row.dir} i={i} h={h} />
              ))}
              <RibCell rib={row.rib} h={h} />
              <span class="t-value muted">{row.source}</span>
            </div>
            {sel && open ? <Detail row={row} lanes={n} actions={actions} /> : null}
          </>
        );
      })}
    </div>
  );
}
