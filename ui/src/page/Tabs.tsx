// The tabs of the parts of a page or of the forms of a table.
import { useRef } from "preact/hooks";

export interface Tab<T extends string> {
  id: T;
  label: string;
}

/**
 * A row of tabs. The current tab has the line below it. The arrow keys,
 * Home and End move to a tab and select it.
 */
export function Tabs<T extends string>(props: { label: string; tabs: readonly Tab<T>[]; current: T; onSelect: (id: T) => void }) {
  const list = useRef<HTMLDivElement>(null);
  const go = (i: number) => {
    const t = props.tabs[i];
    if (!t) return;
    props.onSelect(t.id);
    list.current?.querySelectorAll<HTMLElement>('[role="tab"]')[i]?.focus();
  };
  return (
    <div
      class="tabs"
      role="tablist"
      aria-label={props.label}
      ref={list}
      onKeyDown={(e) => {
        const at = props.tabs.findIndex((t) => t.id === props.current);
        const n = props.tabs.length;
        let next: number | null = null;
        if (e.key === "ArrowRight") next = (at + 1) % n;
        else if (e.key === "ArrowLeft") next = (at - 1 + n) % n;
        else if (e.key === "Home") next = 0;
        else if (e.key === "End") next = n - 1;
        if (next === null) return;
        e.preventDefault();
        go(next);
      }}
    >
      {props.tabs.map((t) => {
        const cur = t.id === props.current;
        return (
          <button type="button" class="tab" role="tab" aria-selected={cur} tabIndex={cur ? 0 : -1} onClick={() => props.onSelect(t.id)}>
            {t.label}
          </button>
        );
      })}
    </div>
  );
}
