// A table with virtual rows of measured height: the column heads, which
// sort and open the column menu, and the rows in view, whose cells print
// each value in full and wrap.
import type { ComponentChildren } from "preact";
import { useLayoutEffect } from "preact/hooks";
import { HatchText } from "../page/Hatch";
import { useVirtualRows } from "../page/VirtualRows";
import { moveCurrent } from "../page/virtual";
import { SIZE } from "../theme";
import { type CellText, NOT_KNOWN, nameParts } from "./model";

export interface TableColumn {
  name: string;
  /** The track of the column in the grid template. */
  track: string;
  right: boolean;
  /** True for function names, which wrap after a `/`. */
  functionName: boolean;
  /** The content of the head; the name if not given. */
  head?: ComponentChildren;
}

/** A cell of the table: its value in full, or the hatch and the words "not known". */
function Cell(props: { c: CellText; text: string; col: TableColumn; same: boolean; title?: string }) {
  const { c, col } = props;
  const cls = `tcell${col.right ? " num" : ""}${props.same ? " same" : ""}`;
  if (props.same) return <span class={cls} />;
  if (!c.known) {
    return (
      <span class={cls}>
        <HatchText title={c.why}>
          <span class="muted">{NOT_KNOWN}</span>
        </HatchText>
      </span>
    );
  }
  if (col.functionName) {
    const parts = nameParts(props.text);
    return (
      <span class={cls}>
        {parts.map((p, i) => (i ? [<wbr />, p] : p))}
      </span>
    );
  }
  return (
    <span class={cls} title={props.title}>
      {props.text}
    </span>
  );
}

export function Table(props: {
  /** The id of the list of rows; row `i` has the id `<id>-<i>`. */
  id: string;
  label: string;
  columns: TableColumn[];
  count: number;
  cell: (row: number, col: number) => { c: CellText; text: string; title?: string };
  /** True for a cell that repeats the row above, which has a hairline. */
  same: (row: number, col: number) => boolean;
  rowHeight: number;
  current: number | null;
  onCurrent: (i: number) => void;
  onActivate?: (i: number) => void;
  resetKey: unknown;
}) {
  const { columns, count, current } = props;
  const v = useVirtualRows({ count, estimate: props.rowHeight, head: SIZE.tablesHead, resetKey: props.resetKey });
  const { first, end, padTop, padBottom } = v.window;

  useLayoutEffect(() => {
    if (current !== null && current < count) v.scrollTo(current);
  }, [current]);

  const tracks = [...columns.map((c) => c.track), "1fr"].join(" ");
  const rows: preact.JSX.Element[] = [];
  for (let i = first; i < end; i++) {
    const cur = i === current;
    rows.push(
      <div
        key={i}
        ref={v.measure(i)}
        id={`${props.id}-${i}`}
        class={cur ? "trow vrow current" : "trow vrow"}
        role="option"
        aria-selected={cur}
        aria-posinset={i + 1}
        aria-setsize={count}
        onClick={(e) => {
          (e.currentTarget.parentElement as HTMLElement | null)?.focus({ preventScroll: true });
          props.onCurrent(i);
          props.onActivate?.(i);
        }}
      >
        {columns.map((c, k) => {
          const x = props.cell(i, k);
          return <Cell c={x.c} text={x.text} title={x.title} col={c} same={props.same(i, k)} />;
        })}
      </div>,
    );
  }

  return (
    <div class="tgrid-box" ref={v.boxRef} onScroll={v.onScroll}>
      <div class="tgrid t-value" style={{ "--tgrid-columns": tracks }}>
        <div class="thead" role="group" aria-label="Column heads">
          {columns.map((c) => (
            <span class={`thead-cell t-label${c.right ? " num" : ""}`}>
              {c.head ?? c.name}
            </span>
          ))}
        </div>
        <div
          class="tgrid-rows"
          tabIndex={0}
          role="listbox"
          aria-label={props.label}
          aria-activedescendant={current !== null && current < count ? `${props.id}-${current}` : undefined}
          onKeyDown={(e) => {
            if (e.target !== e.currentTarget) return;
            if (e.key === "Enter" && current !== null) {
              e.preventDefault();
              props.onActivate?.(current);
              return;
            }
            const next = moveCurrent(e.key, current, count, v.pageRows);
            if (next === null) return;
            e.preventDefault();
            props.onCurrent(next);
          }}
        >
          <div style={{ height: `${padTop}px` }} />
          {rows}
          <div style={{ height: `${padBottom}px` }} />
        </div>
      </div>
    </div>
  );
}
