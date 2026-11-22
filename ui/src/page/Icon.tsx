// The icons: line drawings on a grid of 20 by 20 with the stroke of the
// theme, no fill, in the colour of their text.
import { SIZE } from "../theme";

/** The drawing of each icon: path data, and circles as centre x, centre y and radius. */
const DRAWINGS = {
  trace: { d: "M6.5 5H12a3.5 3.5 0 0 1 3.5 3.5V13", c: [[4.5, 5, 2], [15.5, 15, 2]] },
  topology: { d: "M7.5 2.5h5v4h-5zM2.5 13.5h5v4h-5zM12.5 13.5h5v4h-5zM10 6.5V10M5 13.5V10h10v3.5" },
  tables: { d: "M4 3.5h12a1.5 1.5 0 0 1 1.5 1.5v10a1.5 1.5 0 0 1-1.5 1.5H4A1.5 1.5 0 0 1 2.5 15V5A1.5 1.5 0 0 1 4 3.5zM2.5 8h15M2.5 12h15M8 8v8.5" },
  coverage: { d: "M10 3v7l5 5", c: [[10, 10, 7]] },
  inventory: { d: "M4.5 3.5h11a1.5 1.5 0 0 1 0 5h-11a1.5 1.5 0 0 1 0-5zM4.5 11.5h11a1.5 1.5 0 0 1 0 5h-11a1.5 1.5 0 0 1 0-5zM6 6h.01M6 14h.01" },
  deliver: { d: "m5 10.5 3.5 3.5L15 7" },
  drop: { d: "m6 6 8 8M14 6l-8 8" },
  exit: { d: "M4 10h11M11 6l4 4-4 4" },
  search: { d: "m12.5 12.5 4.5 4.5", c: [[8.5, 8.5, 5]] },
  copy: { d: "M8.5 7.5h7a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1zM12.5 4.5H5a1.5 1.5 0 0 0-1.5 1.5v7.5" },
  add: { d: "M10 4v12M4 10h12" },
  menu: { d: "m5.5 8 4.5 4.5L14.5 8" },
  swap: { d: "M3 7h13M13 4l3 3-3 3M17 13H4M7 10l-3 3 3 3" },
  close: { d: "m5 5 10 10M15 5 5 15" },
  previous: { d: "m5.5 12.5 4.5-4.5 4.5 4.5" },
  next: { d: "m5.5 7.5 4.5 4.5 4.5-4.5" },
  sort: { d: "M7 16V4M4 7l3-3 3 3M13 4v12M10 13l3 3 3-3" },
  "column-menu": { d: "", c: [[10, 5, 1], [10, 10, 1], [10, 15, 1]] },
  remove: { d: "m6 6 8 8M14 6l-8 8" },
  preferences: { d: "M3 6h8M15 6h2M3 14h2M9 14h8", c: [[13, 6, 2], [7, 14, 2]] },
  "zoom-in": { d: "m12.5 12.5 4.5 4.5M8.5 6v5M6 8.5h5", c: [[8.5, 8.5, 5]] },
  "zoom-out": { d: "m12.5 12.5 4.5 4.5M6 8.5h5", c: [[8.5, 8.5, 5]] },
  fit: { d: "M3 7V3h4M13 3h4v4M17 13v4h-4M7 17H3v-4" },
} as const satisfies Record<string, { d: string; c?: readonly (readonly [number, number, number])[] }>;

export type IconName = keyof typeof DRAWINGS;

/** An icon of `size` px, hidden from assistive technology; the control that holds it carries the words. */
export function Icon(props: { name: IconName; size?: number; class?: string }) {
  const s = props.size ?? SIZE.icon;
  const g: { d: string; c?: readonly (readonly [number, number, number])[] } = DRAWINGS[props.name];
  return (
    <svg
      class={props.class ? `icon ${props.class}` : "icon"}
      width={s}
      height={s}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      stroke-width={SIZE.iconStroke}
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {g.d ? <path d={g.d} vector-effect="non-scaling-stroke" /> : null}
      {(g.c ?? []).map(([cx, cy, r]) => (
        <circle cx={cx} cy={cy} r={r} vector-effect="non-scaling-stroke" />
      ))}
    </svg>
  );
}
