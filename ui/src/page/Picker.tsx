// The list of the endpoint picker under an address field of the query bar.
import { useEffect, useRef, useState } from "preact/hooks";
import { tableRows } from "../api/client";
import {
  type EndpointRow,
  type EntryOption,
  PICKER_MAX,
  type Suggestion,
  deviceOptions,
  endpointRows,
  ingressRequests,
  ingressStage,
  interfaceOptions,
  matchEndpoints,
  pickerQuery,
  placesByHost,
  recordsOf,
} from "./pick";

/** The wait after the last key before the picker asks the API, in ms. */
const PICKER_WAIT_MS = 150;

/**
 * The endpoints of a twin that match a text: one page of at most
 * `PICKER_MAX` rows by a name prefix and one by an address prefix, then the
 * places of the matches from the attachment records.
 */
async function findEndpoints(twin: string, q: string): Promise<Suggestion[]> {
  const limit = String(PICKER_MAX);
  const [byName, byAddress] = await Promise.all([
    tableRows(twin, "endpoints", { "endpoint.prefix": q, limit }),
    tableRows(twin, "endpoints", { "addresses.prefix": q, limit }),
  ]);
  const rows: EndpointRow[] = endpointRows([...recordsOf(byName), ...recordsOf(byAddress)]);
  const found = matchEndpoints(rows, q);
  if (found.length === 0) return found;
  try {
    const att = await tableRows(twin, "attachments", {
      host: found.map((s) => s.name).join(","),
      columns: "host,device,interface",
      limit: String(PICKER_MAX * 4),
    });
    const places = placesByHost(recordsOf(att));
    return found.map((s) => ({ ...s, places: places.get(s.name) ?? [] }));
  } catch {
    return found;
  }
}

/**
 * The proposals for the text of a field while `active`. A text that
 * changes before its answer arrives drops that answer.
 */
export function useEndpoints(twin: string, value: string, active: boolean): Suggestion[] {
  const [list, setList] = useState<Suggestion[]>([]);
  useEffect(() => {
    const q = pickerQuery(value);
    if (!active || !twin || q === null) {
      setList([]);
      return;
    }
    let live = true;
    const timer = setTimeout(() => {
      findEndpoints(twin, q)
        .then((s) => {
          if (live) setList(s);
        })
        .catch(() => {
          if (live) setList([]);
        });
    }, PICKER_WAIT_MS);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [twin, value, active]);
  return list;
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
 * The entry point list of the ingress field while `active`: the devices,
 * or the entry interfaces of the device of the text, with `found` first in
 * the device list. The rows of another twin or another stage do not show.
 */
export function useEntryPoints(twin: string, value: string, active: boolean, found: string | null): EntryOption[] {
  const stage = ingressStage(value);
  const key = `${twin} ${stage.stage === "device" ? "device" : `interface ${stage.device}`}`;
  const [rows, setRows] = useState<{ key: string; records: Record<string, unknown>[] }>({ key: "", records: [] });
  useEffect(() => {
    if (!active || !twin) return;
    let live = true;
    const reqs = ingressRequests(ingressStage(value));
    const timer = setTimeout(() => {
      Promise.all(reqs.map((r) => tableRows(twin, r.table, r.params)))
        .then((ts) => {
          if (live) setRows({ key, records: ts.flatMap(recordsOf) });
        })
        .catch(() => {
          if (live) setRows({ key, records: [] });
        });
    }, PICKER_WAIT_MS);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [twin, value, active]);
  const records = rows.key === key ? rows.records : [];
  return stage.stage === "device" ? deviceOptions(records, found, value) : interfaceOptions(records, value);
}

export function PickerList(props: {
  id: string;
  list: Suggestion[];
  active: number;
  onChoose: (s: Suggestion) => void;
}) {
  return (
    <div class="picker" id={props.id} role="listbox" aria-label="Endpoints of the twin">
      {props.list.map((s, i) => (
        <div
          id={`${props.id}-${i}`}
          class="option"
          role="option"
          aria-selected={i === props.active}
          // A press keeps the focus in the field, so that the query bar stays open.
          onMouseDown={(e) => {
            e.preventDefault();
            props.onChoose(s);
          }}
        >
          <span class="t-value">{s.name}</span>
          <span class="t-value">{s.address}</span>
          <span class="t-value muted">{s.places.join(", ")}</span>
        </div>
      ))}
    </div>
  );
}

/** A list of names under a control of the query bar, in the look of the endpoint picker. */
export function NameList(props: {
  id: string;
  label: string;
  names: readonly string[];
  /** The text after each name, or none. */
  detail?: (name: string) => string;
  active: number;
  onChoose: (name: string) => void;
}) {
  return (
    <div class={props.detail ? "picker two" : "picker one"} id={props.id} role="listbox" aria-label={props.label}>
      {props.names.map((n, i) => (
        <div
          id={`${props.id}-${i}`}
          class="option"
          role="option"
          aria-selected={i === props.active}
          // A press keeps the focus where it is, so that the query bar stays open.
          onMouseDown={(e) => {
            e.preventDefault();
            props.onChoose(n);
          }}
        >
          <span class="t-value">{n}</span>
          {props.detail ? <span class="muted">{props.detail(n)}</span> : null}
        </div>
      ))}
    </div>
  );
}
