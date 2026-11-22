// The hatch of what the twin does not know: lines at 135 degrees, clipped
// to a rectangle.
import { useMemo } from "preact/hooks";
import { SIZE } from "../theme";

let next = 0;

/** The lines of a hatch of `w` by `h` px, at the pitch of the theme. */
export function hatchLines(w: number, h: number): [number, number, number, number][] {
  const step = SIZE.hatchPitch * Math.SQRT2;
  const out: [number, number, number, number][] = [];
  for (let x = -h; x < w; x += step) out.push([x, h, x + h, 0]);
  return out;
}

export function Hatch(props: { w: number; h: number; title?: string }) {
  const id = useMemo(() => `hatch-${++next}`, []);
  const { w, h, title } = props;
  return (
    <svg class="hatch" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role={title ? "img" : undefined} aria-label={title} aria-hidden={title ? undefined : "true"}>
      {title ? <title>{title}</title> : null}
      <defs>
        <clipPath id={id}>
          <rect width={w} height={h} />
        </clipPath>
      </defs>
      <g clip-path={`url(#${id})`}>
        {hatchLines(w, h).map(([x1, y1, x2, y2]) => (
          <line x1={x1} y1={y1} x2={x2} y2={y2} />
        ))}
      </g>
    </svg>
  );
}

/** A hatch mark in a line of text: a hatch square of 12px before its text, with an optional `title`. */
export function HatchText(props: { children: preact.ComponentChildren; title?: string }) {
  return (
    <span class="hatch-text" title={props.title}>
      <Hatch w={SIZE.hatchSquare} h={SIZE.hatchSquare} />
      <span>{props.children}</span>
    </span>
  );
}

/** A hatch mark in the head of a card: a hatch square and its text in a dashed border, with an optional `title`. */
export function HatchMark(props: { children: preact.ComponentChildren; title?: string }) {
  const s = SIZE.hatchMark - 2 * SIZE.hairline;
  return (
    <span class="mark" title={props.title}>
      <Hatch w={s} h={s} />
      <span>{props.children}</span>
    </span>
  );
}
