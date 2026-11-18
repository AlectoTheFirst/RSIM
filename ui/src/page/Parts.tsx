// The parts of a page: the top bar, the query bar, the result line and the
// key line.
import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import type { TwinRef } from "../api/client";
import type { Twin } from "../api/types";
import type { Level } from "../ladder/layout";
import { type ColourPref, type Prefs, ROW_HEIGHTS, type RowHeight, type ThemePref } from "../theme";
import { HatchMark } from "./Hatch";
import { PickerList, useEndpoints } from "./Picker";
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

/** The title of a field of the query bar. */
const FIELD_TITLES: Partial<Record<QueryField, string>> = {
  ingress: "Where the packet enters, as <device>/<interface>. Empty: rsim finds it from the source address.",
};

/**
 * One field of the query bar: its name and its value, which a click edits
 * in place. The input takes the width of its text. An address field
 * proposes the endpoints of the twin while it is edited; `hint` shows in
 * an empty field and is not part of the query.
 */
function QueryValue(props: {
  twin: string;
  name: QueryField;
  value: string;
  hint?: string | null;
  onInput: (v: string) => void;
  onRun: () => void;
  inputRef?: { current: HTMLInputElement | null };
}) {
  const shown = props.value || props.hint || "not stated";
  const picks = PICKED.has(props.name);
  const [edited, setEdited] = useState(false);
  const [state, setState] = useState<PickerState>(PICKER_CLOSED);
  const list = useEndpoints(props.twin, props.value, picks && edited);
  const open = state.open && list.length > 0;
  const id = `pick-${props.name.replace(".", "-")}`;
  useEffect(() => {
    setState((s) => (s.active >= list.length ? { ...s, active: list.length - 1 } : s));
  }, [list]);
  const choose = (sg: Suggestion) => {
    props.onInput(sg.address);
    setEdited(false);
    setState(PICKER_CLOSED);
  };
  return (
    <label class="qfield" title={FIELD_TITLES[props.name]}>
      <span class="muted">{props.name} </span>
      <span class="autosize t-query" data-value={shown}>
        <input
          ref={props.inputRef}
          class="t-query"
          size={1}
          value={props.value}
          placeholder={props.hint || "not stated"}
          spellcheck={false}
          autocomplete="off"
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
          onBlur={() => setState(PICKER_CLOSED)}
          onKeyDown={(e) => {
            if (picks) {
              const r = pickerKey(state, e.key, list.length);
              if (r.handled) {
                e.preventDefault();
                setState(r.state);
                if (r.action === "choose") choose(list[state.active]!);
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
      {open ? <PickerList id={id} list={list} active={state.active} onChoose={choose} /> : null}
    </label>
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
  // A field shows when it has a value or the bar is being edited; with no
  // stated field, each field of a query shows so that a click can edit it.
  // An empty ingress field shows the entry point of the last answer while
  // the bar is being edited.
  const none = QUERY_FIELDS.every((k) => (props.fields[k] ?? "").trim() === "");
  const hintOf = (k: QueryField) => (k === "ingress" ? props.ingressHint : null);
  return (
    <form
      class="bar query"
      aria-label="Query"
      onSubmit={(e) => {
        e.preventDefault();
        props.onRun();
      }}
      onFocusIn={(e) => setEditing((e.target as HTMLElement).tagName === "INPUT")}
      onFocusOut={(e) => {
        const next = e.relatedTarget as Node | null;
        if (!next || !e.currentTarget.contains(next) || (next as HTMLElement).tagName !== "INPUT") setEditing(false);
      }}
    >
      <Choice<Mode> value={props.mode} options={["path", "set"]} onChange={props.onMode} />
      {QUERY_FIELDS.filter((k) => editing || (props.fields[k] ?? "") !== "" || (k !== "ingress" && none)).map(
        (k, i) => (
          <QueryValue
            twin={props.twin}
            name={k}
            value={props.fields[k] ?? ""}
            hint={hintOf(k)}
            onInput={(v) => props.onField(k, v)}
            onRun={props.onRun}
            inputRef={i === 0 ? props.firstInput : undefined}
          />
        ),
      )}
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
