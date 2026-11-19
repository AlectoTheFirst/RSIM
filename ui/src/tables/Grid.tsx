// A dense table with virtual rows: the column heads, an optional filter
// row, the rows in view, and the opened row in place below its row.
import type { ComponentChildren, JSX } from "preact";
import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { Hatch } from "../page/Hatch";
import { SIZE } from "../theme";
import "./tables.css";
import { type CellText, NOT_KNOWN, repeats, rowWindow, scrollFor } from "./model";

export interface GridColumn {
  name: string;
  /** The width in characters of the value font. */
  width: number;
  right: boolean;
  /** The head of the column, the name if not given. */
  head?: ComponentChildren;
  title?: string;
}

/** The text of the grid columns, in characters of the value font. */
export function gridTemplate(cols: readonly GridColumn[]): string {
  // A last track with no cells takes the rest of the width, so each column
  // keeps its own width.
  return [...cols.map((c) => `calc(${c.width}ch + 2 * var(--button-pad))`), "1fr"].join(" ");
}

/**
 * A cell of a value: the text, or, when the twin does not know it, a hatch
 * square and the words "not known" with the reason as the title.
 */
export function ValueCell(props: { c: CellText; right: boolean; same: boolean; h: number }) {
  const { c, right, same, h } = props;
  if (same) return <span class="cell same" role="cell" aria-label="same as above" />;
  if (!c.known) {
    const s = h - 2 * SIZE.buttonGap;
    return (
      <span class="cell hatched" role="cell" title={c.why} aria-label={`${NOT_KNOWN}: ${c.why ?? ""}`}>
        <Hatch w={s} h={s} />
        <span class="not-known">{NOT_KNOWN}</span>
      </span>
    );
  }
  return (
    <span class={`cell${right ? " num" : ""}`} role="cell" title={c.text.length > 24 ? c.text : undefined}>
      {c.text}
    </span>
  );
}

export function Grid(props: {
  label: string;
  columns: GridColumn[];
  rows: readonly (readonly unknown[])[];
  /** The text of a cell. */
  cell: (row: number, col: number) => CellText;
  /** A cell drawn by the caller in place of its text. */
  custom?: (row: number, col: number) => JSX.Element | null;
  h: number;
  selected: number | null;
  open: boolean;
  onSelect: (i: number) => void;
  detail?: (i: number) => ComponentChildren;
  filters?: ComponentChildren;
  /** True to draw hairlines in the cells that repeat the row above. */
  hairlines?: boolean;
}) {
  const { columns, rows, h, selected, open } = props;
  const box = useRef<HTMLDivElement>(null);
  const start = useRef<HTMLDivElement>(null);
  const detailRef = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ top: 0, height: 600, head: 0 });
  const [openH, setOpenH] = useState(0);
  const opened = open && selected !== null && selected < rows.length ? selected : null;

  const measure = () => {
    const b = box.current;
    if (!b) return;
    const head = start.current?.offsetTop ?? 0;
    setView((v) =>
      v.top === b.scrollTop && v.height === b.clientHeight && v.head === head
        ? v
        : { top: b.scrollTop, height: b.clientHeight, head },
    );
  };

  useEffect(() => {
    const b = box.current;
    if (!b) return;
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(b);
    return () => ro.disconnect();
  }, []);

  useLayoutEffect(() => {
    const d = detailRef.current;
    if (!d) {
      setOpenH(0);
      return;
    }
    const set = () => setOpenH(d.offsetHeight);
    set();
    const ro = new ResizeObserver(set);
    ro.observe(d);
    return () => ro.disconnect();
  }, [opened, rows]);

  useEffect(() => {
    if (box.current) box.current.scrollTop = 0;
    measure();
  }, [rows]);

  useEffect(() => {
    const b = box.current;
    if (!b || selected === null) return;
    // The sticky heads cover the top of the box, so the rows in view start
    // at the scroll offset in the coordinates of the rows.
    const y = scrollFor(selected, b.scrollTop, b.clientHeight - view.head, h, opened, openH);
    if (y !== null) b.scrollTop = y;
  }, [selected]);

  const win = rowWindow({
    top: view.top,
    height: view.height - view.head,
    h,
    count: rows.length,
    open: opened,
    openH,
  });
  const same = props.hairlines ? repeats(rows, opened) : null;
  const cols = gridTemplate(columns);
  const out: JSX.Element[] = [];
  for (let i = win.first; i < win.end; i++) {
    const sel = i === selected;
    out.push(
      <div
        key={`r${i}`}
        class={`grid-row step${sel ? " selected" : ""}`}
        role="row"
        aria-rowindex={i + 2}
        aria-selected={sel}
        onClick={() => props.onSelect(i)}
      >
        {columns.map((c, j) => {
          const own = props.custom?.(i, j);
          if (own) return own;
          return <ValueCell c={props.cell(i, j)} right={c.right} same={!!same && j < same[i]!} h={h} />;
        })}
      </div>,
    );
    if (i === opened && props.detail) {
      out.push(
        <div key={`d${i}`} class="grid-detail" role="row" ref={detailRef}>
          <div class="detail" role="cell">
            {props.detail(i)}
          </div>
        </div>,
      );
    }
  }

  return (
    <div class="grid-box" ref={box} onScroll={measure}>
      <div
        class="grid t-value"
        role="table"
        aria-label={props.label}
        aria-rowcount={rows.length + 1}
        style={{ "--grid-columns": cols, "--row": `${h}px` }}
      >
        <div class="grid-row grid-head" role="row">
          {columns.map((c) => (
            <span class={`cell t-label${c.right ? " num" : ""}`} role="columnheader" title={c.title}>
              {c.head ?? c.name}
            </span>
          ))}
        </div>
        {props.filters ? (
          <div class="grid-row grid-filters" role="row">
            {props.filters}
          </div>
        ) : null}
        <div ref={start} style={{ height: `${win.padTop}px` }} />
        {out}
        <div style={{ height: `${win.padBottom}px` }} />
      </div>
    </div>
  );
}

/** The buttons of the pages of a table. */
export function PageButtons(props: {
  onFirst: () => void;
  onPrevious: () => void;
  onNext: () => void;
  first: boolean;
  previous: boolean;
  next: boolean;
}) {
  return (
    <span class="group" role="group" aria-label="Pages">
      <button type="button" disabled={!props.first} onClick={props.onFirst}>
        First page
      </button>
      <button type="button" disabled={!props.previous} onClick={props.onPrevious}>
        Previous page
      </button>
      <button type="button" disabled={!props.next} onClick={props.onNext}>
        Next page
      </button>
    </span>
  );
}
