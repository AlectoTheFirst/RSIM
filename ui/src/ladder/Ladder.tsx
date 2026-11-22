// The ladder of one path: a lane for each device, and a row for each
// function, or for each device at the level device.
import type { Verdict } from "../api/types";
import { HatchText } from "../page/Hatch";
import { Icon } from "../page/Icon";
import { SIZE } from "../theme";
import { LaneNames, Lanes } from "./Lanes";
import {
  type DecidingStep,
  type Ladder as LadderModel,
  type Rewrite,
  type StepRow,
  destinationOf,
  functionLabel,
  nameParts,
  outcomeKnown,
  verdictWord,
} from "./layout";

/**
 * The columns of a ladder: step, lanes, function, reason, rewrite and
 * source lines. The reason takes the rest of the width.
 */
export function ladderColumns(lanes: number, fn: number): { columns: string; min: number } {
  const lw = Math.max(1, lanes) * SIZE.lane;
  return {
    columns: [
      `${SIZE.colStep}px`,
      `${lw}px`,
      `${fn}px`,
      `minmax(${SIZE.colReason}px, 1fr)`,
      `${SIZE.colRewrite}px`,
      `${SIZE.colSource}px`,
    ].join(" "),
    min: SIZE.colStep + lw + fn + SIZE.colReason + SIZE.colRewrite + SIZE.colSource,
  };
}

/** The word of an outcome kind: with its colour if the engine knows it, else in a hatch mark. */
export function OutcomeWord(props: { kind: string }) {
  const { kind } = props;
  const known = outcomeKnown(kind);
  const word = <span class={`strong${known ? ` c-${kind}` : ""}`}>{verdictWord(kind)}</span>;
  return known ? word : <HatchText>{word}</HatchText>;
}

/** The symbol of an outcome kind in its colour, before its word. An outcome that the engine does not know has the hatch of its word and no symbol. */
export function OutcomeSymbol(props: { kind: string }) {
  const k = props.kind;
  if (k !== "deliver" && k !== "drop" && k !== "exit") return null;
  return (
    <span class={`outcome-mark c-${k}`} aria-hidden="true">
      <Icon name={k} size={SIZE.outcomeIcon} />
    </span>
  );
}

/** A name that breaks after each `/`, then at a space, then at the edge of a column of `width` px. */
export function BrokenName(props: { name: string; width: number; class?: string }) {
  const parts = nameParts(props.name, props.width);
  return (
    <span class={props.class}>
      {parts.map((p, i) => (
        <>
          {i ? <wbr /> : null}
          {p}
        </>
      ))}
    </span>
  );
}

/**
 * A verdict: its outcome word, then the destination of a Deliver, the
 * device and the interface of an Exit with the tunnel of its outer packet,
 * or the deciding step and the reason of a Drop or an Unknown. A click on
 * the deciding step selects and opens that step.
 */
export function VerdictText(props: {
  v: Verdict;
  at?: DecidingStep | null;
  onStep?: (d: DecidingStep) => void;
  tunnel?: string | null;
}) {
  const { v, at } = props;
  const dest = destinationOf(v);
  const exit = v.kind === "exit";
  const reason = exit ? null : at ? at.reason : v.reason?.detail;
  const step = (label: string) =>
    at && props.onStep ? (
      <button type="button" class="link t-value" onClick={() => props.onStep?.(at)}>
        {label}
      </button>
    ) : (
      <span class="t-value">{label}</span>
    );
  return (
    <span class="verdict">
      <OutcomeWord kind={v.kind} />
      {dest ? (
        <>
          {" to "}
          <span class="t-value">{dest}</span>
        </>
      ) : null}
      {exit && v.reason ? <> {step(v.reason.detail)}</> : null}
      {!exit && at ? (
        <>
          {" at "}
          {step(at.step.device ? `${at.step.device} ${functionLabel(at.step)}` : at.step.function)}
          {reason ? "," : ""}
        </>
      ) : null}
      {props.tunnel ? <span class="t-value">, {props.tunnel}</span> : null}
      {reason ? <span class="muted"> {reason}</span> : null}
    </span>
  );
}

/** The fields to which the functions of a row write a known value, each with its new value in the colour of the direction. */
function RewriteCell(props: { list: readonly Rewrite[]; dir: StepRow["dir"] }) {
  return (
    <span class="rewrites">
      {props.list
        .filter((r) => r.after.known)
        .map((r) => (
          <span class="rewrite">
            <span class="t-value muted">{r.field}</span> <span class={`t-value-changed c-${props.dir}`}>{r.after.text}</span>
          </span>
        ))}
    </span>
  );
}

export function LadderHead(props: { model: Pick<LadderModel, "lanes"> }) {
  return (
    <div class="ladder-row ladder-head t-label" role="row">
      <span role="columnheader" />
      <span class="lanes head" role="columnheader" aria-label="lanes">
        <LaneNames lanes={props.model.lanes} />
      </span>
      <span role="columnheader">function</span>
      <span role="columnheader">reason</span>
      <span role="columnheader">rewrite</span>
      <span role="columnheader">source lines</span>
    </div>
  );
}

/** The id of the element of a ladder row. */
export const rowId = (key: string) => `row-${key}`;

/**
 * The ladder of one path. A click on a row selects it and opens its step
 * panel; Arrow up and Arrow down move the selection, and Enter opens the
 * panel of the selected row.
 */
export function PathLadder(props: {
  model: LadderModel;
  /** The width of the function column in px. */
  fnWidth: number;
  h: number;
  selected: string | null;
  onSelect: (key: string, open: boolean) => void;
}) {
  const { model, h, selected, onSelect, fnWidth } = props;
  const n = model.lanes.length;
  const grid = ladderColumns(n, fnWidth);
  const at = model.rows.findIndex((r) => r.key === selected);
  const move = (by: number) => {
    const next = model.rows[Math.max(0, Math.min(model.rows.length - 1, (at < 0 ? (by > 0 ? -1 : model.rows.length) : at) + by))];
    if (!next) return;
    onSelect(next.key, false);
    document.getElementById(rowId(next.key))?.focus();
  };
  return (
    <div
      class="ladder"
      role="table"
      aria-label="Ladder"
      style={{ "--ladder-columns": grid.columns, minWidth: `${grid.min}px` }}
      onKeyDown={(e) => {
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          move(e.key === "ArrowDown" ? 1 : -1);
        }
      }}
    >
      <LadderHead model={model} />
      {model.rows.map((row, i) => {
        const sel = row.key === selected;
        return (
          <div
            key={row.key}
            id={rowId(row.key)}
            class={`ladder-row step${sel ? " selected" : ""}`}
            role="row"
            aria-selected={sel}
            tabIndex={sel || (at < 0 && i === 0) ? 0 : -1}
            onClick={() => onSelect(row.key, true)}
            onKeyDown={(e) => {
              if (e.key !== "Enter" || e.target !== e.currentTarget) return;
              e.preventDefault();
              e.stopPropagation();
              onSelect(row.key, true);
            }}
          >
            <span class="ix t-index" role="cell">
              {row.label}
            </span>
            <span class="lanes" role="cell">
              <Lanes lanes={n} h={h} marks={row} />
            </span>
            <span class="fn t-value" role="cell">
              <BrokenName name={row.fn} width={fnWidth} />
            </span>
            <span class="t-body reason" role="cell">
              {row.reason}
            </span>
            <span role="cell">
              <RewriteCell list={row.rewrites} dir={row.dir} />
            </span>
            <span class="t-value muted src" role="cell">
              {row.source}
            </span>
          </div>
        );
      })}
    </div>
  );
}
