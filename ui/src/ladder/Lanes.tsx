// The lane drawing of one ladder row: the lane guides, the path line with
// its ring, the step across at a link, and the start and end squares.
import { SIZE } from "../theme";
import type { Dir, End, Lane } from "./layout";
import { laneGroups, upright } from "./layout";
import { hatchLines } from "../page/Hatch";
import { useMemo } from "preact/hooks";

/** The centre of a lane, on a pixel centre so that a hairline is sharp. */
export const laneX = (i: number) => i * SIZE.lane + SIZE.lane / 2 + SIZE.hairline / 2;

let next = 0;

export interface LaneMarks {
  dir: Dir;
  lane: number;
  enterFrom: number | null;
  start: boolean;
  end: End | null;
  /** The lane of the end square, if it is not the lane of the row. */
  endLane?: number | null;
  group: boolean;
  /** The width of the path line. */
  line?: number;
  /** Only the line, with no ring: the row below a selected row. */
  through?: boolean;
}

/**
 * The lanes of one row. The drawing takes the height of the row, which
 * grows with a reason or a value that wraps: the marks of the row sit in
 * its first `h` px, and the path line of a row with no end runs to the
 * bottom of the row.
 */
export function Lanes(props: { lanes: number; h: number; marks: LaneMarks | null }) {
  const { lanes, h, marks } = props;
  const w = lanes * SIZE.lane;
  const id = useMemo(() => `end-${++next}`, []);
  const guides = Array.from({ length: lanes }, (_, i) => (
    <line class="lane-guide" x1={laneX(i)} y1={0} x2={laneX(i)} y2="100%" />
  ));
  if (!marks) {
    return (
      <svg width={w} height="100%" aria-hidden="true">
        {guides}
      </svg>
    );
  }
  const cls = marks.dir === "forward" ? "path-forward" : "path-reply";
  const x = laneX(marks.lane);
  const lw = marks.line ?? SIZE.pathLine;
  const sq = SIZE.endSquare;
  const endLane = marks.endLane ?? null;
  const parts = [
    marks.end ? (
      <rect class={cls} x={x - lw / 2} y={0} width={lw} height={Math.max(0, endLane === null ? h - sq / 2 : h)} />
    ) : (
      <rect class={cls} x={x - lw / 2} y={0} width={lw} height="100%" />
    ),
  ];
  if (marks.enterFrom !== null) {
    const a = laneX(marks.enterFrom);
    const x0 = Math.min(a, x) - lw / 2;
    parts.push(<rect class={cls} x={x0} y={0} width={Math.abs(a - x) + lw} height={lw} />);
  }
  if (!marks.through) {
    if (marks.group) {
      const s = SIZE.deviceSquare;
      parts.push(<rect class={cls} x={x - s / 2} y={h / 2 - s / 2} width={s} height={s} />);
    } else {
      parts.push(<circle class={`${cls} ring`} cx={x} cy={h / 2} r={SIZE.ring} />);
    }
  }
  if (marks.start) {
    const sx = laneX(marks.enterFrom ?? marks.lane);
    parts.push(<rect class={cls} x={sx - sq / 2} y={-sq / 3} width={sq} height={sq} />);
  }
  if (marks.end) {
    const y = h - (2 * sq) / 3;
    let x = laneX(marks.lane);
    if (endLane !== null) {
      const b = laneX(endLane);
      parts.push(<rect class={cls} x={Math.min(b, x) - lw / 2} y={h - lw} width={Math.abs(b - x) + lw} height={lw} />);
      x = b;
    }
    if (marks.end === "unknown") {
      parts.push(
        <g>
          <defs>
            <clipPath id={id}>
              <rect x={x - sq / 2} y={y} width={sq} height={sq} />
            </clipPath>
          </defs>
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
      {guides}
      {parts}
    </svg>
  );
}

/**
 * The names of the lanes, centred over each lane, with the full name as
 * the title. A site header above a group of lanes of one site gives the
 * site, and the lanes of the group have no site prefix. When a name is
 * wider than its lane, each name stands upright.
 */
export function LaneNames(props: { lanes: readonly Lane[] }) {
  const { groups, names } = laneGroups(props.lanes);
  const up = upright(names, SIZE.lane, SIZE.indexChar);
  return (
    <span class={`lane-names t-index${up ? " upright" : ""}`} aria-label={`lanes: ${props.lanes.map((l) => l.name).join(", ")}`}>
      {groups.map((g) =>
        g.site ? (
          <span class="lane-site" style={{ gridColumn: `${g.first + 1} / span ${g.count}` }}>
            {g.site}
          </span>
        ) : null,
      )}
      {props.lanes.map((l, i) => (
        <span class={names[i] === l.name ? "lane-name whole" : "lane-name"} style={{ gridColumn: `${i + 1}`, gridRow: "2" }} title={l.name}>
          {names[i]}
        </span>
      ))}
    </span>
  );
}
