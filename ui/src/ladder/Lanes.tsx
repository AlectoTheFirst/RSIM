// The lane drawing of one ladder row: the lane guides, the path line with
// its ring, the step across at a link, and the start and end squares.
import { SIZE } from "../theme";
import type { Dir, End, Lane } from "./layout";
import { upright } from "./layout";
import { hatchLines } from "../page/Hatch";
import { useMemo } from "preact/hooks";

/** The centre of a lane, on a pixel centre. */
export const laneX = (i: number) => i * SIZE.lane + SIZE.lane / 2 + SIZE.hairline / 2;

let next = 0;

export interface LaneMarks {
  dir: Dir;
  lane: number;
  enterFrom: number | null;
  start: boolean;
  end: End | null;
  group: boolean;
}

/**
 * The lanes of one row. The drawing takes the height of the row, which
 * grows with a reason or a name that wraps: the marks of the row sit in
 * its first `h` px, and the path line of a row with no end runs to the
 * bottom of the row.
 */
export function Lanes(props: { lanes: number; h: number; marks: LaneMarks }) {
  const { lanes, h, marks } = props;
  const w = lanes * SIZE.lane;
  const id = useMemo(() => `end-${++next}`, []);
  const cls = marks.dir === "forward" ? "path-forward" : "path-reply";
  const x = laneX(marks.lane);
  const lw = SIZE.pathLine;
  const sq = SIZE.endSquare;
  const parts = [
    marks.end ? (
      <rect class={cls} x={x - lw / 2} y={0} width={lw} height={Math.max(0, h - sq / 2)} />
    ) : (
      <rect class={cls} x={x - lw / 2} y={0} width={lw} height="100%" />
    ),
  ];
  if (marks.enterFrom !== null) {
    const a = laneX(marks.enterFrom);
    const x0 = Math.min(a, x) - lw / 2;
    parts.push(<rect class={cls} x={x0} y={0} width={Math.abs(a - x) + lw} height={lw} />);
  }
  if (marks.group) {
    const s = SIZE.deviceSquare;
    parts.push(<rect class={cls} x={x - s / 2} y={h / 2 - s / 2} width={s} height={s} />);
  } else {
    parts.push(<circle class={`${cls} ring`} cx={x} cy={h / 2} r={SIZE.ring} />);
  }
  if (marks.start) {
    parts.push(<rect class={cls} x={x - sq / 2} y={-sq / 3} width={sq} height={sq} />);
  }
  if (marks.end) {
    const y = h - (2 * sq) / 3;
    if (marks.end === "unknown") {
      parts.push(
        <g>
          <defs>
            <clipPath id={id}>
              <rect x={x - sq / 2} y={y} width={sq} height={sq} />
            </clipPath>
          </defs>
          <rect class="end-ground" x={x - sq / 2} y={y} width={sq} height={sq} />
          <g class="hatch" clip-path={`url(#${id})`}>
            {hatchLines(sq, sq).map(([x1, y1, x2, y2]) => (
              <line x1={x - sq / 2 + x1} y1={y + y1} x2={x - sq / 2 + x2} y2={y + y2} />
            ))}
          </g>
          <rect class="end-unknown" x={x - sq / 2} y={y} width={sq} height={sq} />
        </g>,
      );
    } else {
      parts.push(<rect class={`end-${marks.end}`} x={x - sq / 2} y={y} width={sq} height={sq} />);
    }
  }
  return (
    <svg width={w} height="100%" aria-hidden="true">
      {Array.from({ length: lanes }, (_, i) => (
        <line class="lane-guide" x1={laneX(i)} y1={0} x2={laneX(i)} y2="100%" />
      ))}
      {parts}
    </svg>
  );
}

/**
 * The names of the lanes, centred over each lane. When a name is wider
 * than its lane, each name stands upright.
 */
export function LaneNames(props: { lanes: readonly Lane[] }) {
  const names = props.lanes.map((l) => l.name);
  const up = upright(names, SIZE.lane, SIZE.indexChar);
  return (
    <span class={`lane-names t-index${up ? " upright" : ""}`}>
      {props.lanes.map((l) => (
        <span class="lane-name">{l.name}</span>
      ))}
    </span>
  );
}
