// A list of values with virtual rows: the items of a list value, or the
// numbered source lines of a span with the marked lines.
import { useState } from "preact/hooks";
import { TYPE } from "../theme";
import { VirtualRows } from "./VirtualRows";

let lists = 0;

export function CodeList(props: {
  label: string;
  values: readonly string[];
  code?: boolean;
  lineNumbers?: readonly number[];
  /** Whether row `i` is a line of the marked span. */
  marked?: (i: number) => boolean;
}) {
  const [id] = useState(() => `code-list-${++lists}`);
  const [current, setCurrent] = useState<number | null>(null);
  return (
    <VirtualRows
      id={id}
      label={props.label}
      count={props.values.length}
      rowHeight={TYPE.value.line}
      current={current}
      onCurrent={setCurrent}
      class={props.code ? "row-list row-code t-value" : "row-list t-value"}
      row={(i) => {
        const m = props.marked?.(i) ? " marked" : "";
        return props.lineNumbers ? (
          <>
            <span class={`ln t-index${m}`}>{props.lineNumbers[i]}</span>
            <span class={`tx${m}`}>{props.values[i]}</span>
          </>
        ) : (
          <span class={`tx${m}`}>{props.values[i]}</span>
        );
      }}
    />
  );
}
