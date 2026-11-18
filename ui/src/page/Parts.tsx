// The parts of a page: the top bar, the query bar, the result line and the
// key line.
import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import type { TwinRef } from "../api/client";
import type { Twin } from "../api/types";
import type { Level } from "../ladder/layout";
import { type ColourPref, type Prefs, ROW_HEIGHTS, type RowHeight, type ThemePref } from "../theme";
import { HatchMark } from "./Hatch";
import { type Fields, type Mode, QUERY_FIELDS, type QueryField } from "./query";

const VIEWS = ["Trace", "Tables", "Coverage", "Compare", "Inventory", "Admin"];

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
        class="t-index"
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
  prefs: Prefs;
  onPrefs: (p: Prefs) => void;
}) {
  const info = props.info;
  return (
    <header class="bar">
      <span class="t-wordmark">RSIM</span>
      <select class="t-value" aria-label="Twin" value={props.twin} onChange={(e) => props.onTwin(e.currentTarget.value)}>
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
          v === "Trace" ? (
            <button type="button" aria-current="page">
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

export function QueryBar(props: {
  mode: Mode;
  fields: Fields;
  notStated: number | null;
  onMode: (m: Mode) => void;
  onField: (k: QueryField, v: string) => void;
  onRun: () => void;
  onCopyCommand: () => void;
  onCopyMcp: () => void;
  firstInput: { current: HTMLInputElement | null };
}) {
  return (
    <form
      class="bar"
      aria-label="Query"
      onSubmit={(e) => {
        e.preventDefault();
        props.onRun();
      }}
    >
      <Choice<Mode> value={props.mode} options={["path", "set"]} onChange={props.onMode} />
      {QUERY_FIELDS.map((k, i) => (
        <label class="field">
          <span class="t-label">{k}</span>
          <input
            ref={i === 0 ? props.firstInput : undefined}
            class={`t-query${k.endsWith("port") || k === "network.transport" ? " short" : ""}`}
            value={props.fields[k] ?? ""}
            spellcheck={false}
            autocomplete="off"
            onInput={(e) => props.onField(k, e.currentTarget.value)}
          />
        </label>
      ))}
      <button type="submit">Run the query</button>
      {props.mode === "set" ? (
        <span class="muted">Fields not stated have all values.</span>
      ) : props.notStated ? (
        <HatchMark>{props.notStated} fields not stated, so not known</HatchMark>
      ) : null}
      <span class="grow" />
      <span class="group">
        <button type="button" onClick={props.onCopyCommand}>
          Copy as rsim command
        </button>
        <button type="button" onClick={props.onCopyMcp}>
          Copy as MCP call
        </button>
      </span>
    </form>
  );
}

export const LEVELS: readonly Level[] = ["device", "function"];

export function LevelControl(props: { level: Level; onLevel: (l: Level) => void }) {
  return (
    <span class="group" role="group" aria-label="Level">
      <span class="t-label">Level</span>
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

export function ResultLine(props: { children: ComponentChildren; level: Level; onLevel: (l: Level) => void }) {
  return (
    <div class="bar result" aria-live="polite">
      {props.children}
      <span class="grow" />
      <LevelControl level={props.level} onLevel={props.onLevel} />
    </div>
  );
}

export function KeyLine(props: { keys: [string, string][] }) {
  return (
    <footer class="keyline t-index" aria-label="Keys">
      {props.keys.map(([k, what]) => (
        <span>
          {k} {what}
        </span>
      ))}
    </footer>
  );
}
