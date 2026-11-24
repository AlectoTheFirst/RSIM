// The fields of an edit of a device or a group in its panel: the text
// fields and the choices of the record, and each setting with the value
// that it takes when it is empty and the origin of its value.
import { useEffect, useRef } from "preact/hooks";
import { Pill } from "../page/Pill";
import type { Inventory, Origin, SettingDefaults, SettingField, SettingKey, Settings, Vendors } from "./model";
import { type Draft, SETTING_FIELDS, draftOrigin, inherited, usedSetting } from "./model";

/** The handlers of the fields of an edit: a text change, a choice and the keys of each field. */
export interface FieldHandlers {
  onInput: (k: string, v: string) => void;
  onPick: (k: string, v: string) => void;
  keys: (k: string) => (e: KeyboardEvent) => void;
}

/** One text field of a record: the name above the input. */
export function TextField(props: {
  id: string;
  k: string;
  label: string;
  draft: Draft;
  h: FieldHandlers;
  mono?: boolean;
  list?: string;
  autoFocus?: boolean;
}) {
  const { id, k, h } = props;
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (props.autoFocus) input.current?.focus();
  }, []);
  return (
    <label class="inv-field" for={`${id}-${k}`}>
      <span class="t-label muted">{props.label}</span>
      <input
        ref={input}
        id={`${id}-${k}`}
        class={props.mono === false ? "" : "t-value"}
        value={props.draft[k] ?? ""}
        list={props.list}
        spellcheck={false}
        autoComplete="off"
        onInput={(e) => h.onInput(k, e.currentTarget.value)}
        onKeyDown={h.keys(k)}
      />
    </label>
  );
}

/** One choice of a record: the name above the select. */
export function PickField(props: { id: string; k: string; label: string; draft: Draft; h: FieldHandlers; options: readonly { value: string; text: string }[] }) {
  const { id, k, h } = props;
  return (
    <label class="inv-field" for={`${id}-${k}`}>
      <span class="t-label muted">{props.label}</span>
      <select id={`${id}-${k}`} class="t-value" value={props.draft[k] ?? ""} onChange={(e) => h.onPick(k, e.currentTarget.value)} onKeyDown={h.keys(k)}>
        {props.options.map((o) => (
          <option value={o.value}>{o.text}</option>
        ))}
      </select>
    </label>
  );
}

/** The choices of a setting: first the inherited value, then each value, with the current value when no record has it. */
function choices(f: SettingField, inv: Inventory, inherit: string, current: string): { value: string; text: string }[] {
  const values = f.kind === "credential" ? inv.credentials.map((c) => c.name) : f.kind === "route" ? inv.routes.map((r) => r.name) : [...(f.choices ?? [])];
  if (current && !values.includes(current)) values.push(current);
  return [{ value: "", text: inherit }, ...values.map((v) => ({ value: v, text: v }))];
}

/** The pill of the origin of a setting: the record in the parameter colour, the group or the default muted. */
export function OriginPill(props: { origin: Origin; own: "device" | "group" }) {
  return <Pill tone={props.origin === props.own ? "parameter" : "muted"}>{props.origin}</Pill>;
}

/**
 * The settings of a device or a group. An empty setting inherits: for a
 * device the value of its group, else the default that `defaults` gives.
 * A setting that the collector of the vendor does not read is not shown.
 */
export function SettingsEditor(props: {
  id: string;
  inv: Inventory;
  draft: Draft;
  /** The settings of the group of a device; null for a group, whose empty settings take the default. */
  group: Settings | null;
  /** The default of each setting from the resolved devices. */
  defaults: SettingDefaults;
  /** The record of the edit: a device or a group. */
  own: "device" | "group";
  vendor: string;
  vendors: Vendors | null;
  omit?: readonly SettingKey[];
  h: FieldHandlers;
}) {
  const { id, h, draft } = props;
  return (
    <div class="inv-settings">
      {SETTING_FIELDS.filter((f) => !props.omit?.includes(f.key) && usedSetting(f, props.vendors, props.vendor)).map((f) => {
        const i = inherited(f, props.group, props.defaults, props.vendor);
        const origin = draftOrigin(f, draft, props.group, props.own);
        const set = origin === props.own;
        const value = draft[f.key] ?? "";
        const fid = `${id}-${f.key}`;
        return (
          <div class="inv-setting">
            <label class="t-label muted" for={fid}>
              {f.label}
            </label>
            <OriginPill origin={origin} own={props.own} />
            {f.kind === "number" || f.kind === "text" ? (
              <span class="inv-control">
                <input
                  id={fid}
                  class={`t-value${f.kind === "number" ? " inv-number" : ""}${set ? " param" : ""}`}
                  value={value}
                  placeholder={i.text}
                  spellcheck={false}
                  autoComplete="off"
                  onInput={(e) => h.onInput(f.key, e.currentTarget.value)}
                  onKeyDown={h.keys(f.key)}
                />
                {f.unit ? <span class="t-label muted">{f.unit}</span> : null}
              </span>
            ) : (
              <select id={fid} class={`t-value${set ? " param" : ""}`} value={value} onChange={(e) => h.onPick(f.key, e.currentTarget.value)} onKeyDown={h.keys(f.key)}>
                {choices(f, props.inv, i.text, value).map((o) => (
                  <option value={o.value}>{o.text}</option>
                ))}
              </select>
            )}
          </div>
        );
      })}
    </div>
  );
}
