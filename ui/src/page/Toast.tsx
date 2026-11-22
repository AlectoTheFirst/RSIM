// The toast: the note of the last action, for TOAST_TIME.
import { useEffect, useState } from "preact/hooks";
import { TOAST_TIME } from "../theme";
import { type ToastNote, dismiss, subscribe } from "./notes";

export function ToastHost() {
  const [note, setNote] = useState<ToastNote | null>(null);
  useEffect(() => subscribe(setNote), []);
  useEffect(() => {
    if (!note) return;
    const t = window.setTimeout(() => dismiss(note.id), TOAST_TIME);
    return () => window.clearTimeout(t);
  }, [note]);
  return (
    <div class="toast-place" role="status" aria-live="polite">
      {note ? (
        <span class="toast" key={note.id}>
          {note.text}
        </span>
      ) : null}
    </div>
  );
}
