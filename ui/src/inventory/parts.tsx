// The parts that the sections of the Inventory view share: the keys of an add row or an edit, the delete button with its confirm
// state and the draft of an edit of one record.
import { useEffect, useRef, useState } from "preact/hooks";
import { ApiProblem } from "../api/client";
import { type Draft, type Problem, rebase } from "./model";

/** A write, then the inventory again; a refused write shows the title of its problem. */
export type Write = (run: () => Promise<number>) => Promise<boolean>;
/** The write of a new record, refused when its name is in use. */
export type WriteNew = (records: readonly { name: string }[], name: string, run: () => Promise<number>) => Promise<boolean>;
/** Shows the problem of a check before a write. */
export type Refuse = (p: Problem) => void;

/** A list of names, each kept on one line, with a comma between 2 names. */
export function Names(props: { names: readonly string[] }) {
  return (
    <span class="t-value inv-uses">
      {props.names.map((n, i) => (
        <>
          <span class="inv-name">{n}</span>
          {i < props.names.length - 1 ? ", " : ""}
        </>
      ))}
    </span>
  );
}

export function problemOf(e: unknown): Problem {
  if (e instanceof ApiProblem) return { title: e.title, detail: e.detail };
  const t = String(e instanceof Error ? e.message : e);
  return { title: t, detail: t };
}

/** The keys of an add row or an edit: Enter commits, Escape cancels. */
export function addKeys(add: () => void, cancel: () => void) {
  return (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      add();
    } else if (e.key === "Escape") {
      e.preventDefault();
      cancel();
    }
  };
}

/**
 * The button that removes a record: the first press arms it, the second
 * press removes the record, and Escape or a move of the focus cancels. With
 * `named`, the button names the record before the first press:
 * "Delete core-01", then "Confirm delete core-01"; else "Delete", then
 * "Delete core-01".
 */
export function DeleteButton(props: { name: string; named?: boolean; onDelete: () => Promise<boolean> }) {
  const [armed, setArmed] = useState(false);
  const text = props.named ? (armed ? `Confirm delete ${props.name}` : `Delete ${props.name}`) : armed ? `Delete ${props.name}` : "Delete";
  return (
    <button
      type="button"
      class="danger"
      aria-pressed={armed}
      onClick={(e) => {
        e.stopPropagation();
        if (!armed) {
          e.currentTarget.focus();
          setArmed(true);
        } else {
          setArmed(false);
          void props.onDelete();
        }
      }}
      onKeyDown={(e) => {
        if (e.key === "Escape" && armed) {
          e.preventDefault();
          e.stopPropagation();
          setArmed(false);
        }
      }}
      onBlur={() => setArmed(false)}
    >
      {text}
    </button>
  );
}

/**
 * The draft of an edit of a stored record. When the stored record changes,
 * each text that the edit has not changed takes the stored text, and each
 * changed text stays. `reset` sets each text to the stored text.
 */
export function useDraft(stored: Draft): [Draft, (k: string, v: string) => Draft, (k: string) => void, () => void] {
  const [draft, setDraft] = useState(stored);
  const before = useRef(stored);
  const key = JSON.stringify(stored);
  useEffect(() => {
    const old = before.current;
    if (JSON.stringify(old) === key) return;
    setDraft((d) => rebase(d, old, stored));
    before.current = stored;
  }, [key]);
  const set = (k: string, v: string) => {
    const next = { ...draft, [k]: v };
    setDraft(next);
    return next;
  };
  const revert = (k: string) => setDraft((d) => ({ ...d, [k]: before.current[k] ?? "" }));
  const reset = () => setDraft(before.current);
  return [draft, set, revert, reset];
}
