// The fields of an edit of a device or a group: the text fields and the
// choices of the record, and each setting with the value that it inherits
// when it is empty and the collectors that do not read it.
import type { Inventory, SettingField, SettingKey, Settings, Vendors } from "./model";
import { type Draft, SETTING_FIELDS, inherited, notUsed } from "./model";

/** The handlers of the fields of an edit: a text change, a choice, the keys and the end of the focus of each field. */
export interface FieldHandlers {
  onInput: (k: string, v: string) => void;
  onPick: (k: string, v: string) => void;
  keys: (k: string) => (e: KeyboardEvent) => void;
  onBlur?: (k: string) => void;
}

/** One text field of a record, in the grid of an edit. */
export function TextRow(props: {
  id: string;
  k: string;
  label: string;
  draft: Draft;
  h: FieldHandlers;
  mono?: boolean;
  placeholder?: string;
  list?: string;
  note?: string | null;
  autoFocus?: boolean;
}) {
  const { id, k, h } = props;
  const value = props.draft[k] ?? "";
  return (
    <>
      <label class={value ? "c-parameter" : "muted"} for={`${id}-${k}`}>
        {props.label}
      </label>
      <input
        id={`${id}-${k}`}
        class={props.mono === false ? "param" : "t-value param"}
        value={value}
        placeholder={props.placeholder}
        list={props.list}
        spellcheck={false}
        autoFocus={props.autoFocus}
        onInput={(e) => h.onInput(k, e.currentTarget.value)}
        onKeyDown={h.keys(k)}
        onBlur={() => h.onBlur?.(k)}
      />
      <span class="muted">{props.note ?? ""}</span>
    </>
  );
}

/** One choice of a record, in the grid of an edit. */
export function PickRow(props: {
  id: string;
  k: string;
  label: string;
  draft: Draft;
  h: FieldHandlers;
  options: readonly { value: string; text: string }[];
  note?: string | null;
}) {
  const { id, k, h } = props;
  const value = props.draft[k] ?? "";
  return (
    <>
      <label class={value ? "c-parameter" : "muted"} for={`${id}-${k}`}>
        {props.label}
      </label>
      <select id={`${id}-${k}`} class={value ? "t-value param" : "t-value muted"} value={value} onChange={(e) => h.onPick(k, e.currentTarget.value)} onKeyDown={h.keys(k)}>
        {props.options.map((o) => (
          <option value={o.value}>{o.text}</option>
        ))}
      </select>
      <span class="muted">{props.note ?? ""}</span>
    </>
  );
}

/** The choices of a setting: first the inherited value, then each value, with the current value when no record has it. */
function choices(f: SettingField, inv: Inventory, inherit: string, current: string): { value: string; text: string }[] {
  const values = f.kind === "credential" ? inv.credentials.map((c) => c.name) : f.kind === "route" ? inv.routes.map((r) => r.name) : [...(f.choices ?? [])];
  if (current && !values.includes(current)) values.push(current);
  return [{ value: "", text: inherit }, ...values.map((v) => ({ value: v, text: v }))];
}

/**
 * The settings of a device or a group. An empty setting inherits: for a
 * device the value of its group, else the default. A setting that the
 * collector of the vendor does not read keeps its value and names why.
 */
export function SettingsEditor(props: {
  id: string;
  inv: Inventory;
  draft: Draft;
  /** The settings of the group of a device; null for a group, whose empty settings take the default. */
  group: Settings | null;
  vendor: string;
  vendors: Vendors | null;
  omit?: readonly SettingKey[];
  h: FieldHandlers;
}) {
  return (
    <div class="inv-settings">
      {SETTING_FIELDS.filter((f) => !props.omit?.includes(f.key)).map((f) => {
        const i = inherited(f, props.group);
        const inherit = `${i.from}: ${i.text}`;
        const note = notUsed(f, props.vendors, props.vendor);
        const common = { id: props.id, k: f.key, label: f.label, draft: props.draft, h: props.h, note: note ?? f.unit ?? null };
        return f.kind === "number" || f.kind === "text" ? (
          <TextRow {...common} placeholder={inherit} />
        ) : (
          <PickRow {...common} options={choices(f, props.inv, inherit, props.draft[f.key] ?? "")} />
        );
      })}
    </div>
  );
}
