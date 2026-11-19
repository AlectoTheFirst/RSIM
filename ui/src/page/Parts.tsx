// The parts of a page: the top bar, the query bar, the result line and the
// key line.
import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import type { TwinRef } from "../api/client";
import type { Twin } from "../api/types";
import type { Level } from "../ladder/layout";
import { type ColourPref, type Prefs, ROW_HEIGHTS, type RowHeight, type ThemePref } from "../theme";
import { HatchMark } from "./Hatch";
import {
  BASE_FIELDS,
  checkValue,
  descriptionOf,
  exampleOf,
  filterValues,
  firstError,
  formOf,
  insertValue,
  modeHelp,
  valueToken,
  valuesOf,
} from "./fields";
import { NameList, PickerList, useEndpoints } from "./Picker";
import { PICKER_CLOSED, type PickerState, type Suggestion, pickerKey } from "./pick";
import { type Fields, type Mode, QUERY_FIELDS, type QueryField } from "./query";
import { twinOption } from "./url";

export const VIEWS = ["Trace", "Tables", "Coverage", "Compare", "Inventory", "Admin"] as const;
export type View = (typeof VIEWS)[number];

/** The views of this build. */
export const BUILT: readonly View[] = ["Trace", "Tables", "Coverage"];

/** The user of the page. The server has no sign-in on loopback. */
const USER = { name: "Local user", initials: "LU", how: "no sign-in on a loopback address" };

function Choice<T extends string | number>(props: {
  value: T;
  options: readonly T[];
  label?: (v: T) => string;
  onChange: (v: T) => void;
}) {
  return (
    <span class="group">
      {props.options.map((o) => (
        <button type="button" aria-pressed={o === props.value} onClick={() => props.onChange(o)}>
          {props.label ? props.label(o) : String(o)}
        </button>
      ))}
    </span>
  );
}

function AccountMenu(props: { prefs: Prefs; onPrefs: (p: Prefs) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);
  const p = props.prefs;
  return (
    <span class="account" ref={ref}>
      <button
        type="button"
        aria-label={`Account of ${USER.name}`}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {USER.initials}
      </button>
      {open ? (
        <div class="menu" role="menu">
          <div>
            <span class="strong">{USER.name}</span>
            <br />
            <span class="muted">{USER.how}</span>
          </div>
          <hr />
          <div class="settings">
            <span class="t-label">Theme</span>
            <Choice<ThemePref> value={p.theme} options={["dark", "light", "system"]} onChange={(theme) => props.onPrefs({ ...p, theme })} />
            <span class="t-label">Colours</span>
            <Choice<ColourPref>
              value={p.colours}
              options={["standard", "blue-orange"]}
              label={(c) => (c === "standard" ? "standard" : "blue and orange")}
              onChange={(colours) => props.onPrefs({ ...p, colours })}
            />
            <span class="t-label">Row height</span>
            <Choice<RowHeight> value={p.row} options={ROW_HEIGHTS} onChange={(row) => props.onPrefs({ ...p, row })} />
          </div>
          <div class="muted">Blue and orange take the place of the colours of Deliver and Drop.</div>
        </div>
      ) : null}
    </span>
  );
}

export function TopBar(props: {
  twins: TwinRef[];
  twin: string;
  info: Twin | null;
  onTwin: (id: string) => void;
  view: View;
  onView: (v: View) => void;
  prefs: Prefs;
  onPrefs: (p: Prefs) => void;
}) {
  const info = props.info;
  return (
    <header class="bar top">
      <span class="t-wordmark">RSIM</span>
      <select class="t-value twin" aria-label="Twin" value={twinOption(props.twins.map((t) => t.id), props.twin)} onChange={(e) => props.onTwin(e.currentTarget.value)}>
        {props.twins.map((t) => (
          <option value={t.id}>{t.id}</option>
        ))}
      </select>
      {info ? (
        <span class="muted">
          {info.snapshot == null ? "no snapshot" : `snapshot ${info.snapshot}`}, {info.layers.length} what-if layers
        </span>
      ) : null}
      <span class="grow" />
      <nav class="group" aria-label="Views">
        {VIEWS.map((v) =>
          BUILT.includes(v) ? (
            <button type="button" aria-current={v === props.view ? "page" : undefined} onClick={() => props.onView(v)}>
              {v}
            </button>
          ) : (
            <button type="button" disabled title="Not in this build">
              {v}
            </button>
          ),
        )}
      </nav>
      <AccountMenu prefs={props.prefs} onPrefs={props.onPrefs} />
    </header>
  );
}

/** The fields whose value the endpoint picker proposes. */
const PICKED = new Set<QueryField>(["source.ip", "destination.ip"]);

/** The id of the input of a field of the query bar. */
const inputId = (k: QueryField) => `q-${k.replace(/\./g, "-")}`;

/** The id of the help line of the query bar. */
const HELP_ID = "query-help";

/** True for an element whose focus keeps the query bar in its edit state. */
const edits = (el: EventTarget | null) => el instanceof HTMLElement && el.dataset["edit"] !== undefined;

/**
 * One field of the query bar: its name and its value, which a click edits
 * in place. The input takes the width of its text. An address field
 * proposes the endpoints of the twin while it is edited, and a field with
 * names proposes its names while it has the focus; `hint` shows in an
 * empty field and is not part of the query.
 */
function QueryValue(props: {
  twin: string;
  mode: Mode;
  name: QueryField;
  value: string;
  hint?: string | null;
  invalid: boolean;
  onInput: (v: string) => void;
  onRun: () => void;
  onFocus: () => void;
  onBlur: () => void;
  inputRef?: { current: HTMLInputElement | null };
}) {
  const shown = props.value || props.hint || "";
  const endpoints = PICKED.has(props.name);
  const names = valuesOf(props.mode, props.name);
  const picks = endpoints || names.length > 0;
  const [edited, setEdited] = useState(false);
  const [state, setState] = useState<PickerState>(PICKER_CLOSED);
  const found = useEndpoints(props.twin, props.value, endpoints && edited);
  const named = names.length ? filterValues(names, valueToken(props.mode, props.name, props.value)) : [];
  const count = endpoints ? found.length : named.length;
  const open = state.open && count > 0;
  const id = `pick-${props.name.replace(/\./g, "-")}`;
  useEffect(() => {
    setState((s) => (s.active >= count ? { ...s, active: count - 1 } : s));
  }, [count]);
  const chooseEndpoint = (sg: Suggestion) => {
    props.onInput(sg.address);
    setEdited(false);
    setState(PICKER_CLOSED);
  };
  const chooseName = (n: string) => {
    props.onInput(insertValue(props.mode, props.name, props.value, n));
    setState(PICKER_CLOSED);
  };
  const classes = ["autosize", "t-query", props.value ? "" : "empty", props.invalid ? "invalid" : ""].filter(Boolean).join(" ");
  return (
    <label class="qfield">
      <span class="muted">{props.name} </span>
      <span class={classes} data-value={shown}>
        <input
          ref={props.inputRef}
          id={inputId(props.name)}
          data-edit=""
          class="t-query"
          size={1}
          value={props.value}
          placeholder={props.hint ?? undefined}
          spellcheck={false}
          autocomplete="off"
          aria-invalid={props.invalid || undefined}
          aria-describedby={HELP_ID}
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
            props.onFocus();
            if (names.length) setState({ open: true, active: -1 });
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
                if (r.action === "choose") {
                  if (endpoints) chooseEndpoint(found[state.active]!);
                  else chooseName(named[state.active]!);
                }
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
      {open && endpoints ? <PickerList id={id} list={found} active={state.active} onChoose={chooseEndpoint} /> : null}
      {open && !endpoints ? (
        <NameList id={id} label={`Values of ${props.name}`} names={named} active={state.active} onChoose={chooseName} />
      ) : null}
    </label>
  );
}

/** The first sentence of a text. */
const firstSentence = (s: string) => {
  const at = s.indexOf(". ");
  return at < 0 ? s : s.slice(0, at + 1);
};

/** The button "Add field" and its list of the fields that do not show. */
function AddField(props: {
  mode: Mode;
  fields: readonly QueryField[];
  onAdd: (k: QueryField) => void;
  onFocus: () => void;
  onBlur: () => void;
}) {
  const [state, setState] = useState<PickerState>(PICKER_CLOSED);
  const open = state.open && props.fields.length > 0;
  const id = "pick-field";
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setState(PICKER_CLOSED);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);
  const choose = (k: QueryField) => {
    setState(PICKER_CLOSED);
    props.onAdd(k);
  };
  return (
    <span class="qadd" ref={ref}>
      <button
        type="button"
        data-edit=""
        // A press keeps the focus in the field that has it, so that the query bar stays open.
        onMouseDown={(e) => {
          if (document.activeElement && edits(document.activeElement)) e.preventDefault();
        }}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        aria-activedescendant={open && state.active >= 0 ? `${id}-${state.active}` : undefined}
        aria-describedby={HELP_ID}
        onClick={() => setState((s) => (s.open ? PICKER_CLOSED : { open: true, active: -1 }))}
        onFocus={props.onFocus}
        onBlur={() => {
          setState(PICKER_CLOSED);
          props.onBlur();
        }}
        onKeyDown={(e) => {
          const r = pickerKey(state, e.key, props.fields.length);
          if (!r.handled) return;
          e.preventDefault();
          setState(r.state);
          if (r.action === "choose") choose(props.fields[state.active]!);
        }}
      >
        Add field
      </button>
      {open ? (
        <NameList
          id={id}
          label="Fields of the query"
          names={props.fields}
          detail={(k) => firstSentence(descriptionOf(props.mode, k as QueryField))}
          active={state.active}
          onChoose={(k) => choose(k as QueryField)}
        />
      ) : null}
    </span>
  );
}

/**
 * The help line of the query bar. For the field that has the focus: the
 * message of a value with a wrong form, the description, the form of a
 * value in the mode and an example. With no field in focus: the message
 * of the first shown field whose value has a wrong form.
 */
function HelpLine(props: { mode: Mode; focus: QueryField | "add" | null; error: { field: QueryField; message: string } | null }) {
  const { mode, focus, error } = props;
  if (focus === "add") {
    return (
      <div class="qhelp" id={HELP_ID}>
        <span class="t-label">Add field</span> {modeHelp(mode)}
      </div>
    );
  }
  const k = focus ?? error?.field ?? null;
  if (!k) return <div class="qhelp" id={HELP_ID} hidden />;
  const message = error && error.field === k ? error.message : null;
  return (
    <div class="qhelp" id={HELP_ID}>
      <span class="t-label">{k}</span> {message ? <span class="c-drop">{message}. </span> : null}
      {focus ? (
        <>
          {descriptionOf(mode, k)} {formOf(mode, k)} Example: <span class="t-query">{exampleOf(mode, k)}</span>
        </>
      ) : null}
    </div>
  );
}

export function QueryBar(props: {
  twin: string;
  mode: Mode;
  fields: Fields;
  ingressHint: string | null;
  notStated: number | null;
  onMode: (m: Mode) => void;
  onField: (k: QueryField, v: string) => void;
  onRun: () => void;
  onCopyCommand: () => void;
  onCopyMcp: () => void;
  firstInput: { current: HTMLInputElement | null };
}) {
  const [editing, setEditing] = useState(false);
  const [added, setAdded] = useState<ReadonlySet<QueryField>>(new Set());
  const [focus, setFocus] = useState<QueryField | "add" | null>(null);
  const [checked, setChecked] = useState<ReadonlySet<QueryField>>(new Set());
  const [focusNext, setFocusNext] = useState<QueryField | null>(null);
  useEffect(() => {
    if (!focusNext) return;
    document.getElementById(inputId(focusNext))?.focus();
    setFocusNext(null);
  }, [focusNext]);
  // A base field shows when it has a value or the bar is being edited; with
  // no stated field, each base field of a query shows so that a click can
  // edit it. Each other field shows when it has a value or is added. An
  // empty ingress field shows the entry point of the last answer while the
  // bar is being edited.
  const value = (k: QueryField) => props.fields[k] ?? "";
  const none = QUERY_FIELDS.every((k) => value(k).trim() === "");
  const shown = QUERY_FIELDS.filter(
    (k) => value(k) !== "" || added.has(k) || (BASE_FIELDS.has(k) && (editing || (k !== "ingress" && none))),
  );
  const hidden = QUERY_FIELDS.filter((k) => !shown.includes(k));
  const hintOf = (k: QueryField) => (k === "ingress" ? props.ingressHint : null);
  const errorOf = (k: QueryField) => (checked.has(k) ? checkValue(props.mode, k, value(k)) : null);
  const focused = focus && focus !== "add" ? focus : null;
  let shownError: { field: QueryField; message: string } | null = null;
  for (const k of focused ? [focused] : shown) {
    const message = errorOf(k);
    if (message) {
      shownError = { field: k, message };
      break;
    }
  }
  const mark = (k: QueryField) => setChecked((c) => (c.has(k) ? c : new Set(c).add(k)));
  // A value with a wrong form stops the run: its field gets the focus and
  // the help line gives the message.
  const run = () => {
    const bad = firstError(props.mode, props.fields);
    if (bad) {
      mark(bad.field);
      setFocusNext(bad.field);
      return;
    }
    props.onRun();
  };
  return (
    <form
      class="bar query"
      aria-label="Query"
      onSubmit={(e) => {
        e.preventDefault();
        run();
      }}
      onFocusIn={(e) => setEditing(edits(e.target))}
      onFocusOut={(e) => {
        const next = e.relatedTarget as Node | null;
        if (!next || !e.currentTarget.contains(next) || !edits(next)) {
          setEditing(false);
          setFocus(null);
        }
      }}
    >
      <Choice<Mode> value={props.mode} options={["path", "set"]} onChange={props.onMode} />
      {shown.map((k, i) => (
        <QueryValue
          twin={props.twin}
          mode={props.mode}
          name={k}
          value={value(k)}
          hint={hintOf(k)}
          invalid={errorOf(k) !== null}
          onInput={(v) => props.onField(k, v)}
          onRun={run}
          onFocus={() => setFocus(k)}
          onBlur={() => {
            if (value(k).trim() !== "") mark(k);
          }}
          inputRef={i === 0 ? props.firstInput : undefined}
        />
      ))}
      {hidden.length ? (
        <AddField
          mode={props.mode}
          fields={hidden}
          onAdd={(k) => {
            setAdded((a) => new Set(a).add(k));
            setFocusNext(k);
          }}
          onFocus={() => setFocus("add")}
          onBlur={() => setFocus((f) => (f === "add" ? null : f))}
        />
      ) : null}
      {props.mode === "set" ? (
        <span class="muted">Fields not stated have all values.</span>
      ) : props.notStated ? (
        <HatchMark>{props.notStated} fields not stated, so not known</HatchMark>
      ) : null}
      <span class="grow" />
      <button type="button" onClick={props.onCopyCommand}>
        Copy as rsim command
      </button>
      <button type="button" onClick={props.onCopyMcp}>
        Copy as MCP call
      </button>
      <HelpLine mode={props.mode} focus={focus} error={shownError} />
    </form>
  );
}

export const LEVELS: readonly Level[] = ["device", "function"];

export function LevelControl(props: { level: Level; onLevel: (l: Level) => void }) {
  return (
    <span class="group" role="group" aria-label="Level">
      <span class="muted">Level</span>
      {(["estate", "site"] as const).map((l) => (
        <button type="button" disabled title="Not in this build">
          {l}
        </button>
      ))}
      {LEVELS.map((l) => (
        <button type="button" aria-pressed={l === props.level} onClick={() => props.onLevel(l)}>
          {l}
        </button>
      ))}
    </span>
  );
}

/** The result line. The Level control shows on the views that have levels. */
export function ResultLine(props: { children: ComponentChildren; level?: Level; onLevel?: (l: Level) => void }) {
  return (
    <div class="bar result" aria-live="polite">
      {props.children}
      <span class="grow" />
      {props.level && props.onLevel ? <LevelControl level={props.level} onLevel={props.onLevel} /> : null}
    </div>
  );
}

export function KeyLine(props: { keys: [string, string][]; timing?: string | null }) {
  return (
    <footer class="keyline t-index" aria-label="Keys">
      {props.keys.map(([k, what]) => (
        <span>
          {k} {what}
        </span>
      ))}
      {props.timing ? <span class="timing">{props.timing}</span> : null}
    </footer>
  );
}
