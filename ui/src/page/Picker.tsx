// The list of the endpoint picker under an address field of the query bar.
import { useEffect, useState } from "preact/hooks";
import { tableRows } from "../api/client";
import {
  type EndpointRow,
  PICKER_MAX,
  type Suggestion,
  endpointRows,
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
