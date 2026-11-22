// A segmented control.

/** A segmented control: a choice of 2 to 4 values. */
export function Segmented<T extends string | number>(props: {
  label: string;
  value: T;
  options: readonly T[];
  text?: (v: T) => string;
  onChange: (v: T) => void;
}) {
  return (
    <span class="seg" role="group" aria-label={props.label}>
      {props.options.map((o) => (
        <button type="button" aria-pressed={o === props.value} onClick={() => props.onChange(o)}>
          {props.text ? props.text(o) : String(o)}
        </button>
      ))}
    </span>
  );
}
