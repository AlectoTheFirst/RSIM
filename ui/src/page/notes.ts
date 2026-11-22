// The note of the last action of the page. Each view calls `toast`, and the
// frame shows the newest note for TOAST_TIME.

export interface ToastNote {
  id: number;
  text: string;
}

type Listener = (note: ToastNote | null) => void;

let seq = 0;
let current: ToastNote | null = null;
const listeners = new Set<Listener>();

function emit() {
  for (const l of listeners) l(current);
}

/** Shows `text` as the note of the last action, in place of the note before it. */
export function toast(text: string): ToastNote {
  current = { id: ++seq, text };
  emit();
  return current;
}

/** Removes the note `id` when it is still the shown note. */
export function dismiss(id: number): void {
  if (current?.id !== id) return;
  current = null;
  emit();
}

/** Calls `l` with the shown note now and after each change; gives the function that stops it. */
export function subscribe(l: Listener): () => void {
  listeners.add(l);
  l(current);
  return () => {
    listeners.delete(l);
  };
}
