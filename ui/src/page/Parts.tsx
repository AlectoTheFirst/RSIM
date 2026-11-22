// The query card of the Trace view, the values of the Level control and the
// page buttons of a table.
import { type ComponentChildren, Fragment } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { Level } from "../ladder/layout";
import { SIZE } from "../theme";
import {
  BASE_FIELDS,
  FIELD_CHARS,
  QUERY_FIELDS,
  checkValue,
  filterValues,
  firstError,
  formOf,
  insertValue,
  labelOf,
  valueToken,
  valuesOf,
} from "./fields";
import { Hatch } from "./Hatch";
import { Icon } from "./Icon";
import { OptionList, useAsk, useEndpoints, useEntryList } from "./Picker";
import { PICKER_CLOSED, type PickerState, ingressStage, pickerKey } from "./pick";
import { type Fields, type QueryField, swapped } from "./query";

/** The fields whose value the endpoint picker proposes. */
const PICKED = new Set<QueryField>(["source.ip", "destination.ip"]);

/** The id of the input of a field of the query card. */
const inputId = (k: QueryField) => `q-${k.replace(/\./g, "-")}`;

/** The pages of a picker: one more each time its list shows its last row while the API has more. */
function usePages(reset: unknown): [number, (more: boolean, held: number) => void] {
  const [pages, setPages] = useState(1);
  useEffect(() => setPages(1), [reset]);
  const more = (more: boolean, held: number) => {
    if (more && held === pages) setPages(pages + 1);
  };
  return [pages, more];
}

/**
 * One field of the query card: its name above its input, and the message
 * of a wrong value below it. A base field that the query does not state
 * has the hatch mark "not stated". An address field proposes the endpoints
 * of the twin while it is edited, a field with names proposes its names
 * while it has the focus, and the ingress field proposes the devices of
 * the twin, with `found` first, then the entry interfaces of the chosen
 * device.
 */
function QueryValue(props: {
  twin: string;
  name: QueryField;
  value: string;
  found?: string | null;
  /** The message of a wrong value, or null. */
  error: string | null;
  row: number;
  onInput: (v: string) => void;
  onRun: () => void;
  onBlur: () => void;
  inputRef?: { current: HTMLInputElement | null };
}) {
  const endpoints = PICKED.has(props.name);
  const entry = props.name === "ingress";
  const names = valuesOf(props.name);
  const picks = endpoints || entry || names.length > 0;
  const [edited, setEdited] = useState(false);
  const [state, setState] = useState<PickerState>(PICKER_CLOSED);
  const [pages, onMore] = usePages(`${props.twin} ${props.value}`);
  const found = useEndpoints(props.twin, props.value, endpoints && edited, pages);
  const entries = useEntryList(props.twin, props.value, entry && state.open, entry ? (props.found ?? null) : null, pages);
  const named = names.length ? filterValues(names, valueToken(props.name, props.value)) : [];
  const count = endpoints ? found.list.length : entry ? entries.list.length : named.length;
  const open = state.open && count > 0;
  const id = `pick-${props.name.replace(/\./g, "-")}`;
  useEffect(() => {
    setState((s) => (s.active >= count ? { ...s, active: count - 1 } : s));
  }, [count]);
  const choose = (i: number) => {
    if (endpoints) {
      props.onInput(found.list[i]!.address);
      setEdited(false);
      setState(PICKER_CLOSED);
    } else if (entry) {
      // A device keeps the list open on its interfaces; an interface or the found entry point closes it.
      const o = entries.list[i]!;
      props.onInput(o.value);
      setState(o.done ? PICKER_CLOSED : { open: true, active: -1 });
    } else {
      props.onInput(insertValue(props.name, props.value, named[i]!));
      setState(PICKER_CLOSED);
    }
  };
  const stage = entry ? ingressStage(props.value) : null;
  const base = BASE_FIELDS.has(props.name);
  const unstated = base && props.value.trim() === "";
  const box = ["qinput", unstated ? "unstated" : "", props.error ? "invalid" : ""].filter(Boolean).join(" ");
  const errorId = `${inputId(props.name)}-error`;
  let list: ComponentChildren = null;
  if (open && endpoints) {
    list = (
      <OptionList
        id={id}
        label="Endpoints"
        count={count}
        active={state.active}
        estimate={props.row}
        columns="three"
        onChoose={choose}
        onMore={() => onMore(found.more, found.pages)}
        option={(i) => {
          const s = found.list[i]!;
          return (
            <>
              <span class="t-value">{s.name}</span>
              <span class="t-value">{s.address}</span>
              <span class="pick-places">
                {s.places.map((p) => (
                  <span class="t-value muted">{p}</span>
                ))}
              </span>
            </>
          );
        }}
      />
    );
  } else if (open && entry) {
    list = (
      <OptionList
        id={id}
        label={stage?.stage === "interface" ? `Entry interfaces of ${stage.device}` : "Devices"}
        count={count}
        active={state.active}
        estimate={props.row}
        columns="two"
        onChoose={choose}
        onMore={() => onMore(entries.more, entries.pages)}
        option={(i) => {
          const o = entries.list[i]!;
          return (
            <>
              <span class="t-value">{o.name}</span>
              <span class="muted">{o.detail}</span>
            </>
          );
        }}
      />
    );
  } else if (open) {
    list = (
      <OptionList
        id={id}
        label={`Values of ${props.name}`}
        count={count}
        active={state.active}
        estimate={props.row}
        columns="one"
        onChoose={choose}
        option={(i) => <span class="t-value">{named[i]}</span>}
      />
    );
  }
  return (
    <div class="qfield">
      <label class="t-label" for={inputId(props.name)}>
        {props.name}
      </label>
      <span class={box}>
        {unstated ? <Hatch w={SIZE.hatchSquare} h={SIZE.hatchSquare} /> : null}
        <span class="autosize t-query" data-value={props.value || (unstated ? "not stated" : "")} style={{ "--chars": String(FIELD_CHARS[props.name] ?? 8) }}>
          <input
            ref={props.inputRef}
            id={inputId(props.name)}
            class="t-query"
            size={1}
            value={props.value}
            placeholder={unstated ? "not stated" : undefined}
            title={formOf(props.name)}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={props.error ? true : undefined}
            aria-describedby={props.error ? errorId : undefined}
            role={picks ? "combobox" : undefined}
            aria-autocomplete={picks ? "list" : undefined}
            aria-expanded={picks ? open : undefined}
            aria-controls={picks && open ? id : undefined}
            aria-activedescendant={open && state.active >= 0 ? `${id}-${state.active}` : undefined}
            onInput={(e) => {
              props.onInput(e.currentTarget.value);
              if (picks) {
                setEdited(true);
                setState({ open: true, active: -1 });
              }
            }}
            onFocus={() => {
              if (names.length || entry) setState({ open: true, active: -1 });
            }}
            onClick={() => {
              if (entry && !state.open) setState({ open: true, active: -1 });
            }}
            onBlur={() => {
              setState(PICKER_CLOSED);
              props.onBlur();
            }}
            onKeyDown={(e) => {
              if (picks) {
                const r = pickerKey(state, e.key, count);
                if (r.handled) {
                  e.preventDefault();
                  setState(r.state);
                  if (r.action === "choose") choose(state.active);
                  return;
                }
              }
              if (e.key === "Enter") {
                e.preventDefault();
                setState(PICKER_CLOSED);
                props.onRun();
              }
            }}
          />
        </span>
      </span>
      {props.error ? (
        <span class="qerror t-label" id={errorId}>
          {props.error}
        </span>
      ) : null}
      {list}
    </div>
  );
}

/** The button "Add field" and its list of the fields that do not show. */
function AddField(props: { fields: readonly QueryField[]; row: number; onAdd: (k: QueryField) => void }) {
  const [state, setState] = useState<PickerState>(PICKER_CLOSED);
  const open = state.open && props.fields.length > 0;
  const id = "pick-field";
  const choose = (i: number) => {
    setState(PICKER_CLOSED);
    props.onAdd(props.fields[i]!);
  };
  return (
    <span class="qadd">
      <button
        type="button"
        class="ghost"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        aria-activedescendant={open && state.active >= 0 ? `${id}-${state.active}` : undefined}
        onClick={() => setState((s) => (s.open ? PICKER_CLOSED : { open: true, active: -1 }))}
        onBlur={() => setState(PICKER_CLOSED)}
        onKeyDown={(e) => {
          const r = pickerKey(state, e.key, props.fields.length);
          if (!r.handled) return;
          e.preventDefault();
          setState(r.state);
          if (r.action === "choose") choose(state.active);
        }}
      >
        <span class="with-icon">
          <Icon name="add" />
          Add field
        </span>
      </button>
      {open ? (
        <OptionList
          id={id}
          label="Fields"
          count={props.fields.length}
          active={state.active}
          estimate={props.row}
          columns="two"
          onChoose={choose}
          option={(i) => {
            const k = props.fields[i]!;
            return (
              <>
                <span class="t-value">{k}</span>
                <span class="muted">{labelOf(k)}</span>
              </>
            );
          }}
        />
      ) : null}
    </span>
  );
}

/**
 * The query card: each field of the query as an input below its name, the
 * button "Swap source and destination" between the source and the
 * destination fields, "Add field" and "Run".
 */
export function QueryBar(props: {
  twin: string;
  fields: Fields;
  /** The entry point that the shown answer found, or null. */
  found: string | null;
  /** A count that shows the ingress field and opens its list each time it changes while the card shows. */
  askIngress: number;
  /** The row height of the preferences, in px. */
  row: number;
  onField: (k: QueryField, v: string) => void;
  onFields: (f: Fields) => void;
  onRun: () => void;
  firstInput: { current: HTMLInputElement | null };
}) {
  const [added, setAdded] = useState<ReadonlySet<QueryField>>(new Set());
  const [checked, setChecked] = useState<ReadonlySet<QueryField>>(new Set());
  const [focusNext, setFocusNext] = useState<QueryField | null>(null);
  useAsk(props.askIngress, () => {
    setAdded((a) => new Set(a).add("ingress"));
    setFocusNext("ingress");
  });
  useEffect(() => {
    if (!focusNext) return;
    document.getElementById(inputId(focusNext))?.focus();
    setFocusNext(null);
  }, [focusNext]);
  const value = (k: QueryField) => props.fields[k] ?? "";
  // `unstated` takes its value from the echo of an answer only.
  const ofMode = QUERY_FIELDS.filter((k) => k !== "unstated");
  const shown = ofMode.filter((k) => BASE_FIELDS.has(k) || value(k) !== "" || added.has(k));
  const hidden = ofMode.filter((k) => !shown.includes(k));
  const errorOf = (k: QueryField) => (checked.has(k) ? checkValue(k, value(k)) : null);
  const mark = (k: QueryField) => setChecked((c) => (c.has(k) ? c : new Set(c).add(k)));
  // A value with a wrong form stops the run: its field gets the focus and
  // its message shows below it.
  const run = () => {
    const bad = firstError(props.fields);
    if (bad) {
      mark(bad.field);
      setFocusNext(bad.field);
      return;
    }
    props.onRun();
  };
  return (
    <form
      class="query"
      aria-label="Query"
      onSubmit={(e) => {
        e.preventDefault();
        run();
      }}
    >
      {shown.map((k, i) => (
        <Fragment key={k}>
          {k === "destination.ip" ? (
            <button type="button" class="icon swap" aria-label="Swap source and destination" onClick={() => props.onFields(swapped(props.fields))}>
              <Icon name="swap" />
            </button>
          ) : null}
          <QueryValue
            twin={props.twin}
            name={k}
            value={value(k)}
            found={k === "ingress" ? props.found : null}
            error={errorOf(k)}
            row={props.row}
            onInput={(v) => props.onField(k, v)}
            onRun={run}
            onBlur={() => {
              if (value(k).trim() !== "") mark(k);
            }}
            inputRef={i === 0 ? props.firstInput : undefined}
          />
        </Fragment>
      ))}
      {hidden.length ? (
        <AddField
          fields={hidden}
          row={props.row}
          onAdd={(k) => {
            setAdded((a) => new Set(a).add(k));
            setFocusNext(k);
          }}
        />
      ) : null}
      <span class="grow" />
      <button type="submit">Run</button>
    </form>
  );
}

export const LEVELS: readonly Level[] = ["device", "function"];

/** The buttons of the pages of a table. The button "First page" shows when `onFirst` is given. */
export function PageButtons(props: { onFirst?: () => void; onPrevious: () => void; onNext: () => void; first?: boolean; previous: boolean; next: boolean }) {
  return (
    <span class="group" role="group" aria-label="Pages">
      {props.onFirst ? (
        <button type="button" disabled={!props.first} onClick={props.onFirst}>
          First page
        </button>
      ) : null}
      <button type="button" disabled={!props.previous} onClick={props.onPrevious}>
        Previous page
      </button>
      <button type="button" disabled={!props.next} onClick={props.onNext}>
        Next page
      </button>
    </span>
  );
}
