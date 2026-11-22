// The step panel: the detail of the selected row of the ladder at the
// right of the ladder card.
import type { JSX } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import type { SourceText, Span, TraceStep } from "../api/types";
import { CodeList } from "../page/CodeList";
import { HatchText } from "../page/Hatch";
import { Icon } from "../page/Icon";
import { Panel } from "../page/Panel";
import {
  type DetailSource,
  type Shown,
  type StepRow,
  delayShown,
  detailSources,
  functionLabel,
  headerQosShown,
  isRowSpan,
  markedLines,
  openSpan,
  qosShown,
  rateShown,
  ribOfGroup,
} from "./layout";

export interface StepActions {
  copyExplain: (row: StepRow) => void;
  copyUrl: (row: StepRow) => void;
  /** The masked lines of a span; absent for a twin with no source text. */
  sourceLines?: (span: Span) => Promise<SourceText>;
}

/** A value: plain if the twin knows it, else with the hatch and no colour. */
function ShownValue(props: { s: Shown }) {
  const v = <span class="t-value">{props.s.text}</span>;
  return props.s.known ? v : <HatchText>{v}</HatchText>;
}

function isElement(v: Shown | JSX.Element): v is JSX.Element {
  return !("known" in v && "text" in v);
}

/** Facts as label and value; facts with the same value share one row. */
function Facts(props: { rows: [string, Shown | JSX.Element | null][] }) {
  const out: [string[], Shown | JSX.Element][] = [];
  for (const [k, v] of props.rows) {
    if (v === null) continue;
    const prev = out[out.length - 1];
    const same = prev && !isElement(v) && !isElement(prev[1]) && prev[1].text === v.text && prev[1].known === v.known;
    if (same) prev[0].push(k);
    else out.push([[k], v]);
  }
  return (
    <div class="facts">
      {out.map(([k, v]) => (
        <>
          <span class="t-label">{k.join(", ")}</span>
          <span>{isElement(v) ? v : <ShownValue s={v} />}</span>
        </>
      ))}
    </div>
  );
}

/** The numbered lines of a span, with the lines of the most specific span marked, and the note of the cut lines. */
function CodeLines(props: { t: SourceText; mark: [number, number] | null }) {
  const { t, mark } = props;
  const on = (n: number) => mark !== null && n >= mark[0] && n <= mark[1];
  return (
    <>
      <CodeList
        label={t.file}
        values={t.lines.map((l) => l.text)}
        lineNumbers={t.lines.map((l) => l.number)}
        code
        marked={(i) => on(t.lines[i]!.number)}
      />
      {t.note ? <span class="code-note muted">{t.note}</span> : null}
    </>
  );
}

/**
 * The source spans of the row by file: the lines of the open span, first
 * the smallest span that holds the most specific span, with the lines of
 * the most specific span marked, and the other spans as buttons that open
 * their lines. A row span, a span whose lines the API refuses, or a twin
 * with no source text, shows the label only.
 */
function SourceLines(props: { steps: readonly TraceStep[]; load: StepActions["sourceLines"] }) {
  const { load } = props;
  const sources = detailSources(props.steps);
  const best = sources[0] && !isRowSpan(sources[0].span) ? sources[0].span : null;
  const files: [string, DetailSource[]][] = [];
  for (const e of sources) {
    const f = files.find(([file]) => file === e.span.file);
    if (f) f[1].push(e);
    else files.push([e.span.file, [e]]);
  }
  const [open, setOpen] = useState<string | null>(openSpan(sources)?.key ?? null);
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
  if (sources.length === 0) return null;
  return (
    <section class="step-part">
      <h3 class="t-section">Source</h3>
      {files.map(([file, spans]) => (
        <>
          <span class="t-value muted file">{file}</span>
          {spans.map((e) => {
            const t = e.key === open ? text[e.key] : null;
            if (t) return <CodeLines t={t} mark={markedLines(e.span, best)} />;
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
    </section>
  );
}

/** The RIB guard of a route lookup: matches, differs, or the hatch for a lookup that no collected RIB checks. */
function RibGuard(props: { guards: string[] }) {
  switch (ribOfGroup(props.guards)) {
    case "matches":
      return <span class="t-value c-deliver">matches the collected RIB</span>;
    case "differs":
      return <span class="t-value c-drop">differs from the collected RIB</span>;
    case "hatch":
      return <HatchText>not checked</HatchText>;
    default:
      return null;
  }
}

/** The step panel of a row of the ladder. */
export function StepPanel(props: {
  row: StepRow;
  actions: StepActions;
  onPrevious: (() => void) | null;
  onNext: (() => void) | null;
  onClose: () => void;
  returnFocus: { current: HTMLElement | null };
}) {
  const { row, actions } = props;
  const first: TraceStep = row.steps[0]!;
  const last: TraceStep = row.steps[row.steps.length - 1]!;
  const rate = last.rate_condition ? rateShown(last.rate_condition) : null;
  const v = (t: string) => <span class="t-value">{t}</span>;
  const guards = row.steps.map((s) => s.rib_guard);
  const rib = ribOfGroup(guards) !== "none" ? <RibGuard guards={guards} /> : null;
  return (
    <Panel
      label="Step"
      title={
        <span class="step-title">
          <span class="t-index step-no">{row.label}</span>
          <span class="step-name">
            <span class="t-value strong">{row.group ? row.fn : functionLabel(first)}</span>
            {first.device ? <span class="t-value muted">{first.device}</span> : null}
          </span>
        </span>
      }
      buttons={
        <>
          <button type="button" class="icon" aria-label="Previous step" disabled={!props.onPrevious} onClick={() => props.onPrevious?.()}>
            <Icon name="previous" />
          </button>
          <button type="button" class="icon" aria-label="Next step" disabled={!props.onNext} onClick={() => props.onNext?.()}>
            <Icon name="next" />
          </button>
        </>
      }
      foot={
        <>
          <button type="button" onClick={() => actions.copyExplain(row)}>
            <span class="with-icon">
              <Icon name="copy" />
              Copy as rsim explain
            </span>
          </button>
          <button type="button" onClick={() => actions.copyUrl(row)}>
            <span class="with-icon">
              <Icon name="copy" />
              Copy step URL
            </span>
          </button>
        </>
      }
      onClose={props.onClose}
      returnFocus={props.returnFocus}
    >
      <p class="t-body step-reason">{last.reason.detail}</p>
      {row.rewrites.length ? (
        <section class="step-part">
          <h3 class="t-section">Rewrite</h3>
          <div class="rewrite-table" role="table" aria-label="Rewrite">
            <span class="t-label" role="columnheader">
              field
            </span>
            <span class="t-label" role="columnheader">
              before
            </span>
            <span class="t-label" role="columnheader">
              after
            </span>
            {row.rewrites.map((r) => (
              <>
                <span class="t-value" role="cell">
                  {r.field}
                </span>
                <span role="cell">
                  <ShownValue s={r.before} />
                </span>
                <span role="cell">
                  {r.after.known ? <span class={`t-value-changed c-${row.dir}`}>{r.after.text}</span> : <ShownValue s={r.after} />}
                </span>
              </>
            ))}
          </div>
        </section>
      ) : null}
      <SourceLines key={row.key} steps={row.steps} load={actions.sourceLines} />
      <section class="step-part">
        <h3 class="t-section">Parameters</h3>
        <Facts
          rows={[
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
            ["RIB guard", rib],
          ]}
        />
      </section>
      <section class="step-part">
        <h3 class="t-section">QoS</h3>
        <Facts
          rows={[
            ["dscp", headerQosShown(last.qos.dscp)],
            ["ecn", headerQosShown(last.qos.ecn)],
            ["traffic class", qosShown(last.qos.traffic_class)],
            ["drop precedence", qosShown(last.qos.drop_precedence)],
            ["queue", qosShown(last.qos.queue)],
          ]}
        />
      </section>
    </Panel>
  );
}
