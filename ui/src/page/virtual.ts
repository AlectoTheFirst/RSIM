// The window of a list with virtual rows: the rows in view of a list of a
// fixed row height or of measured row heights, the scroll offset that
// brings a row into view, and the keys that move the current row.

/** The rows of a virtual list that the view draws, and the space around them. */
export interface RowWindow {
  first: number;
  /** One past the last row. */
  end: number;
  padTop: number;
  padBottom: number;
}

export const NO_ROWS: RowWindow = { first: 0, end: 0, padTop: 0, padBottom: 0 };

/** The rows drawn above and below the rows in view. */
export const OVERSCAN = 8;

/**
 * The window of rows in view. The rows have the height `h`; the opened
 * row adds `openH` below it. `top` is the scroll offset from the first row
 * and `height` the height of the view.
 */
export function rowWindow(p: {
  top: number;
  height: number;
  h: number;
  count: number;
  open: number | null;
  openH: number;
  overscan?: number;
}): RowWindow {
  const { h, count, open } = p;
  const extra = open === null || open >= count ? 0 : p.openH;
  const total = count * h + extra;
  if (count === 0) return NO_ROWS;
  const at = (y: number): number => {
    if (y <= 0) return 0;
    if (open === null || open >= count || y < (open + 1) * h) return Math.min(count - 1, Math.floor(y / h));
    if (y < (open + 1) * h + extra) return open;
    return Math.min(count - 1, Math.floor((y - extra) / h));
  };
  const over = p.overscan ?? OVERSCAN;
  const first = Math.max(0, at(p.top) - over);
  const end = Math.min(count, at(p.top + p.height) + 1 + over);
  return { first, end, padTop: rowTop(first, h, open, extra), padBottom: total - rowTop(end, h, open, extra) };
}

/** The offset of the top of row `i`, with the opened row above it. */
export function rowTop(i: number, h: number, open: number | null, openH: number): number {
  return i * h + (open !== null && i > open ? openH : 0);
}

/** The scroll offset that brings row `i` into a view of `height`, or null. */
export function scrollFor(i: number, top: number, height: number, h: number, open: number | null, openH: number): number | null {
  const y = rowTop(i, h, open, openH);
  if (y < top) return y;
  if (y + h > top + height) return y + h - height;
  return null;
}

/**
 * The top of each row and the end of the list: `count + 1` offsets. A row
 * with no measured height takes `estimate`.
 */
export function offsetsOf(count: number, heightOf: (i: number) => number | undefined, estimate: number): Float64Array {
  const out = new Float64Array(count + 1);
  for (let i = 0; i < count; i++) out[i + 1] = out[i]! + (heightOf(i) ?? estimate);
  return out;
}

/** The row at the offset `y`: the last row whose top is at or above `y`. */
export function indexAt(offsets: Float64Array, y: number): number {
  const count = offsets.length - 1;
  if (count <= 0 || y <= 0) return 0;
  let lo = 0;
  let hi = count - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (offsets[mid]! <= y) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/** The window of rows in view of a list of measured row heights. */
export function measuredWindow(p: { top: number; height: number; offsets: Float64Array; overscan?: number }): RowWindow {
  const count = p.offsets.length - 1;
  if (count <= 0) return NO_ROWS;
  const over = p.overscan ?? OVERSCAN;
  const first = Math.max(0, indexAt(p.offsets, p.top) - over);
  const end = Math.min(count, indexAt(p.offsets, p.top + p.height) + 1 + over);
  return { first, end, padTop: p.offsets[first]!, padBottom: p.offsets[count]! - p.offsets[end]! };
}

/** The scroll offset that brings row `i` of a list of measured rows into a view of `height`, or null. */
export function scrollForOffsets(i: number, top: number, height: number, offsets: Float64Array): number | null {
  const y = offsets[i];
  const bottom = offsets[i + 1];
  if (y === undefined || bottom === undefined) return null;
  if (y < top) return y;
  if (bottom > top + height) return Math.min(y, bottom - height);
  return null;
}

/**
 * The current row after a key: the arrow keys move by one row, Page Up
 * and Page Down by the rows of a view, Home and End to the ends. Null for
 * a key that does not move the current row. With no current row, a move
 * down starts at the first row and a move up at the last row.
 */
export function moveCurrent(key: string, current: number | null, count: number, pageRows: number): number | null {
  if (count <= 0) return null;
  const last = count - 1;
  const page = Math.max(1, pageRows);
  switch (key) {
    case "ArrowDown":
      return current === null ? 0 : Math.min(last, current + 1);
    case "ArrowUp":
      return current === null ? last : Math.max(0, current - 1);
    case "PageDown":
      return current === null ? Math.min(last, page - 1) : Math.min(last, current + page);
    case "PageUp":
      return current === null ? 0 : Math.max(0, current - page);
    case "Home":
      return 0;
    case "End":
      return last;
    default:
      return null;
  }
}
