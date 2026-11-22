// A button that opens an overlay below it: a menu of actions or a small
// form. A click outside or Escape closes it, and the focus goes back to
// the button.
import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { menuMove } from "./frame";

const ITEMS = '[role="menuitem"], [role="menuitemradio"], [role="menuitemcheckbox"]';
const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex="0"]';

export function MenuButton(props: {
  /** `menu` for a list of actions, `dialog` for a group of controls. */
  kind: "menu" | "dialog";
  /** The name of the overlay. */
  label: string;
  /** The content of the button. */
  button: ComponentChildren;
  /** The name of the button when it has no words. */
  buttonLabel?: string;
  buttonClass?: string;
  /** The side of the button at which the overlay aligns. */
  align?: "start" | "end";
  class?: string;
  /** The content of the overlay; `close` closes it and puts the focus on the button. */
  children: (close: () => void) => ComponentChildren;
}) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLSpanElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const box = useRef<HTMLDivElement>(null);

  const close = () => {
    setOpen(false);
    button.current?.focus();
  };

  useEffect(() => {
    if (!open) return;
    const first = box.current?.querySelector<HTMLElement>(props.kind === "menu" ? ITEMS : `[aria-pressed="true"], ${FOCUSABLE}`);
    first?.focus();
    const outside = (e: MouseEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", outside);
    return () => document.removeEventListener("mousedown", outside);
  }, [open]);

  return (
    <span class="menu-wrap" ref={wrap}>
      <button
        ref={button}
        type="button"
        class={props.buttonClass}
        aria-label={props.buttonLabel}
        aria-haspopup={props.kind === "menu" ? "menu" : "dialog"}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {props.button}
      </button>
      {open ? (
        <div
          ref={box}
          class={`overlay ${props.align === "start" ? "at-start" : "at-end"}${props.class ? ` ${props.class}` : ""}`}
          role={props.kind}
          aria-label={props.label}
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              close();
              return;
            }
            if (e.key === "Tab" && props.kind === "menu") {
              setOpen(false);
              return;
            }
            if (props.kind !== "menu") return;
            const items = [...(box.current?.querySelectorAll<HTMLElement>(ITEMS) ?? [])];
            const next = menuMove(e.key, items.indexOf(document.activeElement as HTMLElement), items.length);
            if (next === null) return;
            e.preventDefault();
            items[next]?.focus();
          }}
          onFocusOut={(e) => {
            const to = e.relatedTarget as Node | null;
            if (to && !wrap.current?.contains(to)) setOpen(false);
          }}
        >
          {props.children(close)}
        </div>
      ) : null}
    </span>
  );
}
