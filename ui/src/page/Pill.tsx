// A pill: a state or an outcome in a line of text. A chip: a filter with
// its button "Remove filter".
import type { ComponentChildren } from "preact";
import { SIZE } from "../theme";
import { Hatch } from "./Hatch";
import { Icon } from "./Icon";

export type PillTone = "deliver" | "drop" | "exit" | "forward" | "reply" | "parameter" | "action" | "muted" | "unknown";

/** A pill. The tone `unknown` has the hatch and no colour. */
export function Pill(props: { tone: PillTone; children: ComponentChildren; title?: string }) {
  return (
    <span class={`pill pill-${props.tone}`} title={props.title}>
      {props.tone === "unknown" ? <Hatch w={SIZE.iconSmall} h={SIZE.iconSmall} /> : null}
      {props.children}
    </span>
  );
}

/** A filter: the column, the value and the button "Remove filter". */
export function Chip(props: { column: string; value: string; onRemove: () => void; title?: string }) {
  return (
    <span class="chip" title={props.title}>
      <span class="t-label">{props.column}</span>
      <span class="t-value chip-value">{props.value}</span>
      <button type="button" class="icon small" aria-label={`Remove filter ${props.column}`} onClick={props.onRemove}>
        <Icon name="remove" size={SIZE.iconSmall} />
      </button>
    </span>
  );
}
