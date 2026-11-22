// A list with virtual rows: only the rows in view are in the document. The
// rows have one fixed height, or each row is measured after it draws.
import type { ComponentChildren } from "preact";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "preact/hooks";
import { type RowWindow, measuredWindow, moveCurrent, offsetsOf, rowWindow, scrollFor, scrollForOffsets } from "./virtual";

export interface VirtualRowsState {
  /** The scroll box: give it to the element that scrolls. */
  boxRef: { current: HTMLDivElement | null };
  /** The scroll handler of the scroll box. */
  onScroll: () => void;
  /** The rows to draw and the space above and below them. */
  window: RowWindow;
  /** The ref of the element of row `i`, which measures its height. */
  measure: (i: number) => (el: HTMLElement | null) => void;
  /** Brings row `i` into view. */
  scrollTo: (i: number) => void;
  /** The number of rows in the height of the view. */
  pageRows: number;
}

/**
 * The rows in view of a scroll box. With `rowHeight`, each row has that
 * height. With no `rowHeight`, each row drawn is measured, and a row not
 * yet drawn counts as `estimate`. `head` is the height of a sticky head
 * inside the box above the first row. A change of `resetKey` scrolls to
 * the top and forgets the measured heights.
 */
export function useVirtualRows(p: {
  count: number;
  rowHeight?: number;
  estimate?: number;
  head?: number;
  overscan?: number;
  resetKey?: unknown;
}): VirtualRowsState {
  const boxRef = useRef<HTMLDivElement | null>(null);
  const [view, setView] = useState({ top: 0, height: 0 });
  const heights = useRef(new Map<number, number>());
  const [version, setVersion] = useState(0);
  const elements = useRef(new Map<number, HTMLElement>());
  const observer = useRef<ResizeObserver | null>(null);
  const head = p.head ?? 0;
  const fixed = p.rowHeight;
  const estimate = p.estimate ?? fixed ?? 1;

  const read = () => {
    const b = boxRef.current;
    if (!b) return;
    setView((v) => (v.top === b.scrollTop && v.height === b.clientHeight ? v : { top: b.scrollTop, height: b.clientHeight }));
  };

  useEffect(() => {
    const b = boxRef.current;
    if (!b) return;
    read();
    const ro = new ResizeObserver(read);
    ro.observe(b);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    heights.current.clear();
    if (boxRef.current) boxRef.current.scrollTop = 0;
    setVersion((n) => n + 1);
    read();
  }, [p.resetKey]);

  useEffect(() => {
    if (fixed !== undefined) return;
    const ro = new ResizeObserver((entries) => {
      let changed = false;
      for (const e of entries) {
        const el = e.target as HTMLElement;
        const i = Number(el.dataset["index"]);
        const h = el.offsetHeight;
        if (Number.isInteger(i) && heights.current.get(i) !== h) {
          heights.current.set(i, h);
          changed = true;
        }
      }
      if (changed) setVersion((n) => n + 1);
    });
    observer.current = ro;
    for (const el of elements.current.values()) ro.observe(el);
    return () => {
      ro.disconnect();
      observer.current = null;
    };
  }, [fixed]);

  const offsets = useMemo(
    () => (fixed === undefined ? offsetsOf(p.count, (i) => heights.current.get(i), estimate) : null),
    [fixed, p.count, estimate, version],
  );

  const inView = Math.max(0, view.height - head);
  const top = Math.max(0, view.top);
  const win = offsets
    ? measuredWindow({ top, height: inView, offsets, overscan: p.overscan })
    : rowWindow({ top, height: inView, h: fixed!, count: p.count, open: null, openH: 0, overscan: p.overscan });

  const refs = useRef(new Map<number, (el: HTMLElement | null) => void>());
  const measure = (i: number) => {
    let f = refs.current.get(i);
    if (!f) {
      f = (el: HTMLElement | null) => {
        const old = elements.current.get(i);
        if (old === el) return;
        if (old) observer.current?.unobserve(old);
        if (el) {
          el.dataset["index"] = String(i);
          elements.current.set(i, el);
          observer.current?.observe(el);
        } else {
          elements.current.delete(i);
          refs.current.delete(i);
        }
      };
      refs.current.set(i, f);
    }
    return f;
  };

  const scrollTo = (i: number) => {
    const b = boxRef.current;
    if (!b) return;
    const h = Math.max(0, b.clientHeight - head);
    const y = offsets ? scrollForOffsets(i, b.scrollTop, h, offsets) : scrollFor(i, b.scrollTop, h, fixed!, null, 0);
    if (y !== null) b.scrollTop = y;
  };

  return { boxRef, onScroll: read, window: win, measure, scrollTo, pageRows: Math.max(1, Math.floor(inView / estimate)) };
}

/**
 * A list with virtual rows and a current row. The list takes the focus;
 * the arrow keys, Page Up, Page Down, Home and End move the current row,
 * and Enter activates it. A click makes a row current and activates it.
 * The height of the list comes from the CSS of `class`.
 */
export function VirtualRows(props: {
  /** The id of the list; row `i` has the id `<id>-<i>`. */
  id: string;
  label: string;
  count: number;
  /** The fixed row height in px; with none, each row is measured. */
  rowHeight?: number;
  /** The height in px of a row that is not measured yet. */
  estimate?: number;
  current: number | null;
  onCurrent: (i: number) => void;
  onActivate?: (i: number) => void;
  /** The content of row `i`. */
  row: (i: number, current: boolean) => ComponentChildren;
  /** A head that stays at the top of the list, and its height in px. */
  head?: ComponentChildren;
  headHeight?: number;
  class?: string;
  resetKey?: unknown;
  /** Called when the last row is drawn, to read the next page. */
  onEnd?: () => void;
}) {
  const v = useVirtualRows({
    count: props.count,
    rowHeight: props.rowHeight,
    estimate: props.estimate,
    head: props.head ? (props.headHeight ?? 0) : 0,
    resetKey: props.resetKey,
  });
  const { first, end, padTop, padBottom } = v.window;

  useLayoutEffect(() => {
    if (props.current !== null) v.scrollTo(props.current);
  }, [props.current]);

  useEffect(() => {
    if (props.onEnd && props.count > 0 && end >= props.count) props.onEnd();
  }, [end, props.count, props.onEnd]);

  const rows: preact.JSX.Element[] = [];
  for (let i = first; i < end; i++) {
    const cur = i === props.current;
    rows.push(
      <div
        key={i}
        ref={props.rowHeight === undefined ? v.measure(i) : undefined}
        id={`${props.id}-${i}`}
        class={cur ? "vrow current" : "vrow"}
        role="option"
        aria-selected={cur}
        aria-posinset={i + 1}
        aria-setsize={props.count}
        onClick={() => {
          props.onCurrent(i);
          props.onActivate?.(i);
        }}
      >
        {props.row(i, cur)}
      </div>,
    );
  }

  return (
    <div
      ref={v.boxRef}
      class={props.class ? `vrows ${props.class}` : "vrows"}
      onScroll={v.onScroll}
      tabIndex={0}
      role="listbox"
      aria-label={props.label}
      aria-activedescendant={props.current !== null && props.current < props.count ? `${props.id}-${props.current}` : undefined}
      onKeyDown={(e) => {
        if (e.key === "Enter" && props.current !== null) {
          e.preventDefault();
          props.onActivate?.(props.current);
          return;
        }
        const next = moveCurrent(e.key, props.current, props.count, v.pageRows);
        if (next === null) return;
        e.preventDefault();
        props.onCurrent(next);
      }}
    >
      {props.head ? <div class="vrows-head">{props.head}</div> : null}
      <div style={{ height: `${padTop}px` }} />
      {rows}
      <div style={{ height: `${padBottom}px` }} />
    </div>
  );
}
