// The panel at the right of the content: the detail of the selection.
import type { ComponentChildren } from "preact";
import { useEffect, useRef } from "preact/hooks";
import { SIZE } from "../theme";
import { Icon } from "./Icon";

/** True for an element that takes Escape itself: a text field. */
function takesEscape(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false;
  return t.isContentEditable || t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT";
}

/**
 * A panel with its title, the buttons of its head and the button "Close".
 * Escape outside a text field closes it. When the panel closes, the focus
 * goes back to the element that had it when the panel opened, or to
 * `returnFocus`.
 */
export function Panel(props: {
  title: ComponentChildren;
  /** The name of the panel for assistive technology. */
  label: string;
  onClose: () => void;
  /** Content of the head between the title and the buttons, such as a pill. */
  head?: ComponentChildren;
  /** Buttons of the head before the button "Close", such as "Previous step" and "Next step". */
  buttons?: ComponentChildren;
  /** A row of actions at the foot. */
  foot?: ComponentChildren;
  returnFocus?: { current: HTMLElement | null };
  class?: string;
  children?: ComponentChildren;
}) {
  const opener = useRef<HTMLElement | null>(null);
  const close = useRef(props.onClose);
  close.current = props.onClose;
  const ret = props.returnFocus;

  useEffect(() => {
    opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented || takesEscape(e.target)) return;
      e.preventDefault();
      close.current();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      const to = ret?.current ?? opener.current;
      if (to && to.isConnected) to.focus();
    };
  }, []);

  return (
    <aside class={props.class ? `panel ${props.class}` : "panel"} aria-label={props.label}>
      <div class="panel-head">
        <span class="panel-title t-section">{props.title}</span>
        {props.head ?? null}
        <span class="panel-buttons">
          {props.buttons ?? null}
          <button type="button" class="icon" aria-label="Close" onClick={props.onClose}>
            <Icon name="close" size={SIZE.iconSmall} />
          </button>
        </span>
      </div>
      <div class="panel-body">{props.children}</div>
      {props.foot ? <div class="panel-foot group">{props.foot}</div> : null}
    </aside>
  );
}
