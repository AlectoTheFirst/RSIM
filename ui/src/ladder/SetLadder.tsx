// The parts of the answer of a set query: one row for each part, which a
// click selects for the ladder of the part below the list.
import { OutcomeWord } from "./Ladder";
import { functionLabel } from "./layout";
import type { PartRow } from "./setLayout";

/** The outcome of a part: the outcome word, its place or deciding step, the tunnel and the reason. */
function PartOutcome(props: { p: PartRow }) {
  const { p } = props;
  const at = p.at && p.kind !== "exit" ? (p.at.step.device ? `${p.at.step.device} ${functionLabel(p.at.step)}` : p.at.step.function) : null;
  const facts = [p.kind === "deliver" && p.place ? `to ${p.place}` : p.place, at ? `at ${at}` : null, p.tunnel].filter((x): x is string => !!x);
  return (
    <span class="part-outcome">
      <OutcomeWord kind={p.kind} /> <span class="t-value">{facts.join(", ")}</span>
      {p.reason ? <span class="muted">{facts.length ? ", " : " "}{p.reason}</span> : null}
    </span>
  );
}

/**
 * The list of the parts. Arrow up and arrow down move the selection; the
 * selected part has `aria-selected`.
 */
export function PartList(props: { parts: readonly PartRow[]; selected: number | null; onSelect: (branch: number) => void }) {
  const { parts, selected, onSelect } = props;
  const move = (from: number, by: number) => {
    const at = parts.findIndex((p) => p.branch === from);
    const next = parts[Math.max(0, Math.min(parts.length - 1, at + by))];
    if (!next) return;
    onSelect(next.branch);
    document.getElementById(`part-${next.branch}`)?.focus();
  };
  return (
    <div class="parts" role="listbox" aria-label="Parts">
      <div class="parts-head t-label" aria-hidden="true">
        <span />
        <span>packets</span>
        <span>outcome</span>
      </div>
      {parts.map((p) => {
        const sel = p.branch === selected;
        return (
          <div
            key={p.branch}
            id={`part-${p.branch}`}
            class={`part-row${sel ? " selected" : ""}`}
            role="option"
            aria-selected={sel}
            tabIndex={sel ? 0 : -1}
            onClick={() => onSelect(p.branch)}
            onKeyDown={(e) => {
              if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
              e.preventDefault();
              move(p.branch, e.key === "ArrowDown" ? 1 : -1);
            }}
          >
            <span class="ix t-index">{p.branch}</span>
            <span class="part-fields">
              {p.fields.length === 0 ? (
                <span class="muted">all packets</span>
              ) : (
                p.fields.map(([k, v]) => (
                  <span class="part-field">
                    <span class="muted">{k}</span> <span class="t-value">{v}</span>
                  </span>
                ))
              )}
            </span>
            <PartOutcome p={p} />
          </div>
        );
      })}
    </div>
  );
}
