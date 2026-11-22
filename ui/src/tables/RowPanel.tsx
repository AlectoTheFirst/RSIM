// The row panel of the Tables view: each value of the row in full, the
// source lines of its spans, and the actions of the row.
import { useEffect, useRef, useState } from "preact/hooks";
import type { Column, SourceText, Span } from "../api/types";
import { CodeList } from "../page/CodeList";
import { HatchText } from "../page/Hatch";
import { Icon } from "../page/Icon";
import { Panel } from "../page/Panel";
import { SIZE } from "../theme";
import { type CellText, NOT_KNOWN, SPAN_SEMANTIC, isReasonOf, isRowSpan, rowSpans } from "./model";

/** The value of a fact: the text, each item of a list, or the hatch with the reason. */
function FactValue(props: { name: string; c: CellText; v: unknown }) {
  const { c, v } = props;
  if (!c.known) {
    return (
      <span class="row-unknown">
        <HatchText title={c.why}>{NOT_KNOWN}</HatchText>
        {c.why ? <span class="t-value muted">{c.why}</span> : null}
      </span>
    );
  }
  if (Array.isArray(v)) {
    const values = v.map((x) => (typeof x === "string" ? x : JSON.stringify(x)));
    return values.length > 1 ? <CodeList label={props.name} values={values} /> : <span class="t-value">{values[0]}</span>;
  }
  return <span class="t-value">{c.text}</span>;
}

/** The source spans of the row: the lines of the open span, and each other span as a button that opens it. */
function SourceLines(props: { spans: { text: string; span: Span | null }[]; load: (s: Span) => Promise<SourceText> }) {
  const { spans, load } = props;
  const loadable = (s: Span | null): s is Span => s !== null && !isRowSpan(s);
  const [open, setOpen] = useState<number | null>(() => {
    const i = spans.findIndex((e) => loadable(e.span));
    return i < 0 ? null : i;
  });
  const [text, setText] = useState<Record<number, SourceText | null>>({});
  const asked = useRef(new Set<number>());
  useEffect(() => {
    if (open === null || asked.current.has(open)) return;
    const s = spans[open]?.span;
    if (!loadable(s ?? null)) return;
    asked.current.add(open);
    load(s!).then(
      (t) => setText((m) => ({ ...m, [open]: t })),
      () => setText((m) => ({ ...m, [open]: null })),
    );
  }, [open]);
  if (!spans.length) return null;
  const shown = open === null ? null : text[open];
  return (
    <div class="row-section">
      <h3 class="t-section">Source lines</h3>
      {spans.map((e, i) =>
        loadable(e.span) ? (
          <button type="button" class="plain span-button t-value" aria-pressed={i === open} onClick={() => setOpen(i)}>
            {e.text}
          </button>
        ) : (
          <span class="span-text t-value">{e.text}</span>
        ),
      )}
      {shown ? (
        <>
          <CodeList label={shown.file} values={shown.lines.map((l) => l.text)} lineNumbers={shown.lines.map((l) => l.number)} code />
          {shown.note ? <span class="muted">{shown.note}</span> : null}
        </>
      ) : null}
    </div>
  );
}

export function RowPanel(props: {
  title: string;
  columns: readonly string[];
  defs: readonly (Column | undefined)[];
  row: readonly unknown[];
  cell: (j: number) => CellText;
  onClose: () => void;
  onPrevious: (() => void) | null;
  onNext: (() => void) | null;
  /** The masked lines of a span. */
  load: (s: Span) => Promise<SourceText>;
  actions: preact.ComponentChildren;
  returnFocus?: { current: HTMLElement | null };
}) {
  const { columns, defs, row } = props;
  const spans = rowSpans(columns, defs, row);
  return (
    <Panel
      title={<span class="t-value strong">{props.title}</span>}
      label="Row"
      class="row-panel"
      onClose={props.onClose}
      returnFocus={props.returnFocus}
      buttons={
        <>
          <button type="button" class="icon" aria-label="Previous row" disabled={!props.onPrevious} onClick={() => props.onPrevious?.()}>
            <Icon name="previous" size={SIZE.iconSmall} />
          </button>
          <button type="button" class="icon" aria-label="Next row" disabled={!props.onNext} onClick={() => props.onNext?.()}>
            <Icon name="next" size={SIZE.iconSmall} />
          </button>
        </>
      }
      foot={props.actions}
    >
      <div class="facts row-facts">
        {columns.map((c, j) => {
          if (defs[j]?.semantic === SPAN_SEMANTIC || isReasonOf(columns, c)) return null;
          return (
            <>
              <span class="t-label">{c}</span>
              <FactValue name={c} c={props.cell(j)} v={row[j]} />
            </>
          );
        })}
      </div>
      <SourceLines key={spans.map((e) => e.text).join(" ")} spans={spans} load={props.load} />
    </Panel>
  );
}
