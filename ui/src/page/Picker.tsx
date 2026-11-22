// The pickers of the query card: the options under a field, with virtual
// rows, one page at a time.
import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { allRows, tableRows } from "../api/client";
import {
  type EndpointRow,
  type EntryOption,
  type Suggestion,
  deviceOptions,
  endpointRows,
  hasMore,
  ingressRequests,
  ingressStage,
  interfaceOptions,
  matchEndpoints,
  pickerLimit,
  pickerQuery,
  placesByHost,
  recordsOf,
} from "./pick";
import { useVirtualRows } from "./VirtualRows";

/** The wait after the last key before the picker asks the API, in ms. */
const PICKER_WAIT_MS = 150;

/** The options of a picker and whether the API can give more. */
export interface Options<T> {
  list: T[];
  more: boolean;
  /** The number of pages that the list holds. */
  pages: number;
}

/**
 * The endpoints of a twin that match a text: at most `limit` rows by a name
 * prefix and as many by an address prefix, then each place of the matches
 * from the attachment records.
 */
async function findEndpoints(twin: string, q: string, pages: number): Promise<Options<Suggestion>> {
  const limit = pickerLimit(pages);
  const n = String(limit);
  const [byName, byAddress] = await Promise.all([
    tableRows(twin, "endpoints", { "endpoint.prefix": q, limit: n }),
    tableRows(twin, "endpoints", { "addresses.prefix": q, limit: n }),
  ]);
  const rows: EndpointRow[] = endpointRows([...recordsOf(byName), ...recordsOf(byAddress)]);
  const found = matchEndpoints(rows, q, Number.POSITIVE_INFINITY);
  const more = hasMore(byName, limit) || hasMore(byAddress, limit);
  if (found.length === 0) return { list: found, more, pages };
  try {
    const att = await allRows(twin, "attachments", {
      host: found.map((s) => s.name).join(","),
      columns: "host,device,interface",
      sort: "host,device,interface",
    });
    const places = placesByHost(recordsOf(att));
    return { list: found.map((s) => ({ ...s, places: places.get(s.name) ?? [] })), more, pages };
  } catch {
    return { list: found, more, pages };
  }
}

/**
 * The proposals for the text of a field while `active`, `pages` pages of
 * them. A text that changes before its answer arrives drops that answer.
 */
export function useEndpoints(twin: string, value: string, active: boolean, pages = 1): Options<Suggestion> {
  const [out, setOut] = useState<Options<Suggestion>>({ list: [], more: false, pages: 0 });
  useEffect(() => {
    const q = pickerQuery(value);
    if (!active || !twin || q === null) {
      setOut({ list: [], more: false, pages: 0 });
      return;
    }
    let live = true;
    const timer = setTimeout(() => {
      findEndpoints(twin, q, pages)
        .then((s) => {
          if (live) setOut(s);
        })
        .catch(() => {
          if (live) setOut({ list: [], more: false, pages });
        });
    }, PICKER_WAIT_MS);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [twin, value, active, pages]);
  return out;
}

/**
 * Calls `onAsk` each time `count` changes. The count at the mount is not a
 * new request, so a view that mounts again with the same count calls nothing.
 */
export function useAsk(count: number, onAsk: () => void): void {
  const asked = useRef(count);
  useEffect(() => {
    if (count === asked.current) return;
    asked.current = count;
    onAsk();
  }, [count]);
}

/**
 * The entry point list of the ingress field while `active`, `pages` pages
 * of it: the devices, or the entry interfaces of the device of the text,
 * with `found` first in the device list. The rows of another twin or
 * another stage do not show.
 */
export function useEntryList(twin: string, value: string, active: boolean, found: string | null, pages = 1): Options<EntryOption> {
  const stage = ingressStage(value);
  const key = `${twin} ${stage.stage === "device" ? "device" : `interface ${stage.device}`}`;
  const limit = pickerLimit(pages);
  const [rows, setRows] = useState<{ key: string; records: Record<string, unknown>[]; more: boolean; pages: number }>({
    key: "",
    records: [],
    more: false,
    pages: 0,
  });
  useEffect(() => {
    if (!active || !twin) return;
    let live = true;
    const reqs = ingressRequests(ingressStage(value), limit);
    const timer = setTimeout(() => {
      Promise.all(reqs.map((r) => tableRows(twin, r.table, r.params)))
        .then((ts) => {
          if (live) setRows({ key, records: ts.flatMap(recordsOf), more: ts.some((t) => hasMore(t, limit)), pages });
        })
        .catch(() => {
          if (live) setRows({ key, records: [], more: false, pages });
        });
    }, PICKER_WAIT_MS);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [twin, value, active, limit]);
  const records = rows.key === key ? rows.records : [];
  const list = stage.stage === "device" ? deviceOptions(records, found, value, limit) : interfaceOptions(records, value, limit);
  return { list, more: rows.key === key && rows.more, pages: rows.key === key ? rows.pages : 0 };
}

/**
 * The list of a picker under its field, with virtual rows. The focus stays
 * in the field, which names the active option; a press on an option
 * chooses it. When the list shows its last row and the API has more,
 * `onMore` asks for the next page.
 */
export function OptionList(props: {
  id: string;
  label: string;
  count: number;
  active: number;
  /** The height in px of a row that is not measured yet. */
  estimate: number;
  /** The class of the columns of a row. */
  columns: "one" | "two" | "three";
  option: (i: number) => ComponentChildren;
  onChoose: (i: number) => void;
  onMore?: () => void;
}) {
  const v = useVirtualRows({ count: props.count, estimate: props.estimate });
  const { first, end, padTop, padBottom } = v.window;
  useEffect(() => {
    if (props.active >= 0) v.scrollTo(props.active);
  }, [props.active]);
  useEffect(() => {
    if (props.onMore && props.count > 0 && end >= props.count) props.onMore();
  }, [end, props.count, props.onMore]);
  const rows = [];
  for (let i = first; i < end; i++) {
    rows.push(
      <div
        key={i}
        ref={v.measure(i)}
        id={`${props.id}-${i}`}
        class={`pick-option ${props.columns}`}
        role="option"
        aria-selected={i === props.active}
        aria-posinset={i + 1}
        aria-setsize={props.count}
        // A press keeps the focus in the field and the list open.
        onMouseDown={(e) => {
          e.preventDefault();
          props.onChoose(i);
        }}
      >
        {props.option(i)}
      </div>,
    );
  }
  return (
    <div class="pick" id={props.id} role="listbox" aria-label={props.label} ref={v.boxRef} onScroll={v.onScroll}>
      <div style={{ height: `${padTop}px` }} />
      {rows}
      <div style={{ height: `${padBottom}px` }} />
    </div>
  );
}
