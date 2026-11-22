// The lists of the Trace view with virtual rows: the paths of a query with
// more than one path, and the parts of the answer of a set query. A click
// selects a row; the ladder below shows the selected path or part.
import { VirtualRows } from "../page/VirtualRows";
import { SIZE } from "../theme";
import { OutcomeWord, VerdictText } from "./Ladder";
import { functionLabel } from "./layout";
import type { PathItem } from "./paths";
import type { PartRow } from "./setLayout";

/** The outcome of a part: the outcome word, its place or deciding step, the tunnel and the reason. */
function PartOutcome(props: { p: PartRow }) {
  const { p } = props;
  const at = p.at && p.kind !== "exit" ? (p.at.step.device ? `${p.at.step.device} ${functionLabel(p.at.step)}` : p.at.step.function) : null;
  const facts = [p.kind === "deliver" && p.place ? `to ${p.place}` : p.place, at ? `at ${at}` : null, p.tunnel].filter((x): x is string => !!x);
  return (
    <span class="list-outcome">
      <OutcomeWord kind={p.kind} /> <span class="t-value">{facts.join(", ")}</span>
      {p.reason ? (
        <span class="muted">
          {facts.length ? ", " : " "}
          {p.reason}
        </span>
      ) : null}
    </span>
  );
}

function Head(props: { middle: string }) {
  return (
    <div class="list-row list-head t-label">
      <span />
      <span>{props.middle}</span>
      <span>outcome</span>
    </div>
  );
}

/** The parts of a set answer. Arrow up and Arrow down select the part above or below. */
export function PartList(props: { parts: readonly PartRow[]; selected: number | null; onSelect: (branch: number) => void; row: number }) {
  const { parts, selected, onSelect } = props;
  const at = parts.findIndex((p) => p.branch === selected);
  return (
    <VirtualRows
      id="part"
      label="Parts"
      class="trace-list"
      count={parts.length}
      estimate={props.row}
      current={at < 0 ? null : at}
      onCurrent={(i) => onSelect(parts[i]!.branch)}
      head={<Head middle="packets" />}
      headHeight={SIZE.button}
      row={(i) => {
        const p = parts[i]!;
        return (
          <div class="list-row">
            <span class="ix t-index">{p.branch + 1}</span>
            <span class="list-fields">
              {p.fields.length === 0 ? (
                <span class="muted">all packets</span>
              ) : (
                p.fields.map(([k, v]) => (
                  <span class="list-field">
                    <span class="t-value muted">{k}</span> <span class="t-value">{v}</span>
                  </span>
                ))
              )}
            </span>
            <PartOutcome p={p} />
          </div>
        );
      }}
    />
  );
}

/** The paths of a query with more than one path. Arrow up and Arrow down select the path above or below. */
export function PathList(props: { paths: readonly PathItem[]; selected: number | null; onSelect: (i: number) => void; row: number }) {
  return (
    <VirtualRows
      id="path"
      label="Paths"
      class="trace-list"
      count={props.paths.length}
      estimate={props.row}
      current={props.selected}
      onCurrent={props.onSelect}
      head={<Head middle="devices" />}
      headHeight={SIZE.button}
      resetKey={props.paths}
      row={(i) => {
        const p = props.paths[i]!;
        return (
          <div class="list-row">
            <span class="ix t-index">{p.number}</span>
            <span class={`list-devices hops-${p.dir}`}>
              {p.devices.map((d, j) => (
                <>
                  {j ? <span class="hop" aria-hidden="true" /> : null}
                  <span class="t-value">{d}</span>
                </>
              ))}
            </span>
            <span class="list-outcome">
              <VerdictText v={p.verdict} at={p.at} tunnel={p.tunnel} />
            </span>
          </div>
        );
      }}
    />
  );
}
