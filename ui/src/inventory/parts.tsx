// The parts that the sections of the Inventory view share: the hatch cell,
// the keys of an add row or an edit, the delete button with its confirm
// state and the draft of an edit of one record.
import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { ApiProblem } from "../api/client";
import { Hatch } from "../page/Hatch";
import { SIZE } from "../theme";
import { type Draft, type Problem, rebase } from "./model";

/** A write, then the inventory again; a refused write shows the title of its problem. */
export type Write = (run: () => Promise<number>) => Promise<boolean>;
/** The write of a new record, refused when its name is in use. */
export type WriteNew = (records: readonly { name: string }[], name: string, run: () => Promise<number>) => Promise<boolean>;
/** Shows the problem of a check before a write in the result line. */
export type Refuse = (p: Problem) => void;

/** A hatch square of a cell and its words. */
export function HatchCell(props: { children: ComponentChildren; title?: string }) {
  return (
    <span class="hc" title={props.title}>
      <Hatch w={SIZE.invHatch} h={SIZE.invHatch} />
      <span>{props.children}</span>
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

/** Runs `add` each time the count `submit` changes after the first render. */
export function useSubmit(submit: number, add: () => void) {
  const first = useRef(submit);
  useEffect(() => {
    if (submit !== first.current) add();
  }, [submit]);
}

/**
 * The button that removes a record: the first press names the record, the
 * second press removes it, and Escape or a move of the focus cancels.
 */
export function DeleteButton(props: { name: string; onDelete: () => Promise<boolean> }) {
  const [armed, setArmed] = useState(false);
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
      {armed ? `Delete ${props.name}` : "Delete"}
    </button>
  );
}

/**
 * The draft of an edit of a stored record. When the stored record changes,
 * each text that the edit has not changed takes the stored text, and each
 * changed text stays.
 */
export function useDraft(stored: Draft): [Draft, (k: string, v: string) => Draft, (k: string) => void] {
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
  return [draft, set, revert];
}
