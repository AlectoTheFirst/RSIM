// The ladder of a set query: the header fields give place to one column
// for each part.
import type { Answer, Reply, Verdict } from "../api/types";
import { SIZE } from "../theme";
import { Hatch } from "../page/Hatch";
import { Lanes } from "./Lanes";
import { LadderHead, RibCell, ladderColumns } from "./Ladder";
import { type End, type Level, endpointOf, laneIndex, verdictWord } from "./layout";
import { type PartCell, setLadder } from "./setLayout";

function endOf(v: Verdict): End {
  return v.kind === "deliver" ? "deliver" : v.kind === "drop" ? "drop" : "unknown";
}

/** The end of a part: its outcome word and its reason or destination, in the outcome colour. */
function PartEnd(props: { verdict: Verdict; h: number; margin: string }) {
  const { verdict, h } = props;
  const end = endOf(verdict);
  const sq = h - 2 * SIZE.buttonGap;
  const dest = verdict.destination?.endpoint ?? verdict.destination?.device ?? null;
  return (
    <span class={`part end ${end}${end === "unknown" ? "" : ` c-${end}`}`} style={{ margin: props.margin }} title={verdict.reason?.detail ?? dest ?? ""}>
      {end === "unknown" ? (
        <span class="verdict-unknown">
          <Hatch w={sq} h={sq} />
          <span>{verdictWord(verdict.kind)}</span>
        </span>
      ) : (
        <span>{verdictWord(verdict.kind)}</span>
      )}{" "}
      {verdict.reason ? <span>{verdict.reason.detail}</span> : dest ? <span class="t-value">{dest}</span> : null}
    </span>
  );
}

/**
 * The margins of a part cell: none toward a neighbour band, so that the
 * bands of the parts that go on together are one block.
 */
function margins(cells: readonly PartCell[], i: number): string {
  const band = (j: number) => cells[j]?.kind === "band";
  const left = i === 0 || band(i - 1) ? 0 : SIZE.partGap;
  const right = band(i + 1) ? 0 : SIZE.partGap;
  return `0 ${right}px 0 ${left}px`;
}

function PartView(props: { cells: readonly PartCell[]; i: number; h: number }) {
  const c = props.cells[props.i]!;
  const m = margins(props.cells, props.i);
  switch (c.kind) {
    case "band":
      return <span class="part band" style={{ margin: m }} />;
    case "end":
      return <PartEnd verdict={c.verdict} h={props.h} margin={m} />;
    case "apart":
      return (
        <span class="part muted" style={{ margin: m }}>
          takes another path from step {c.step}
        </span>
      );
    case "none":
      return <span class="part" />;
  }
}

/** The row of the reply of one part: the reply in brief, its end in the column of its part. */
function ReplyRow(props: { answer: Answer; rep: Reply; lanes: ReturnType<typeof setLadder>["lanes"]; h: number; notRun: Map<number, string> }) {
  const { answer, rep, lanes, h, notRun } = props;
  const n = lanes.length;
  const bs = rep.answer?.branches ?? [];
  const steps = bs.reduce((m, b) => Math.max(m, b.steps.length), 0);
  const b0 = bs[0];
  const fwd = answer.branches.find((b) => b.index === rep.forward_branch);
  const startEp = fwd ? endpointOf(fwd.verdict) : null;
  const firstDev = b0?.steps[0]?.device ?? null;
  const from = startEp ? laneIndex(lanes, { endpoint: startEp }) : Math.max(0, laneIndex(lanes, firstDev));
  const endEp = b0 && bs.length === 1 ? endpointOf(b0.verdict) : null;
  const lastDev = b0?.steps[b0.steps.length - 1]?.device ?? null;
  const to = endEp ? laneIndex(lanes, { endpoint: endEp }) : Math.max(0, laneIndex(lanes, lastDev));
  const lw = SIZE.pathLine;
  const sq = SIZE.endSquare;
  const ends = new Set(bs.map((b) => endOf(b.verdict)));
  const end = ends.size === 1 ? [...ends][0]! : "unknown";
  const x0 = (i: number) => i * SIZE.lane + SIZE.lane / 2 + SIZE.hairline / 2;
  const cols = answer.branches.map((b) => b.index);
  const lastStep = b0?.steps[b0.steps.length - 1];
  return (
    <div class="ladder-row ladder-reply" role="row">
      <span class="ix t-index">{steps ? `0-${steps - 1}` : ""}</span>
      <span class="lanes">
        <svg width={Math.max(1, n) * SIZE.lane} height={h} aria-hidden="true">
          {Array.from({ length: n }, (_, i) => (
            <line class="lane-guide" x1={x0(i)} y1={0} x2={x0(i)} y2={h} />
          ))}
          <rect class="path-reply" x={Math.min(x0(from), x0(to)) - lw / 2} y={h / 2 - lw / 2} width={Math.abs(x0(to) - x0(from)) + lw} height={lw} />
          <rect class={end === "unknown" ? "end-unknown" : `end-${end}`} x={x0(to) - sq / 2} y={h / 2 - sq / 2} width={sq} height={sq} />
        </svg>
      </span>
      <span class="title c-reply">{bs.length > 1 ? `reply, ${bs.length} branches` : `reply, ${steps} functions`}</span>
      <span class="t-body reason" title={lastStep?.reason.detail}>
        {lastStep?.reason.detail ?? ""}
      </span>
      {cols.map((ix, i) => {
        if (ix === rep.forward_branch) {
          return b0 && bs.length === 1 ? <PartEnd verdict={b0.verdict} h={h} margin={`0 ${SIZE.partGap}px 0 ${i === 0 ? 0 : SIZE.partGap}px`} /> : <span />;
        }
        const why = notRun.get(ix);
        return <span class="part muted">{why ?? ""}</span>;
      })}
      <span />
      <span />
    </div>
  );
}

export function SetLadder(props: { answer: Answer; level: Level; h: number }) {
  const { answer, level, h } = props;
  const l = setLadder(answer, level);
  const n = l.lanes.length;
  const grid = ladderColumns(
    n,
    l.heads.map(() => SIZE.partColumn),
    SIZE.colReasonSet,
  );
  const width = (parts: number) => SIZE.partLine[Math.min(parts, SIZE.partLine.length) - 1] ?? SIZE.pathLine;
  const notRun = new Map(answer.replies.filter((r) => !r.ran).map((r) => [r.forward_branch, r.not_run_reason ?? "no reply runs"]));
  const ran = answer.replies.filter((r) => r.ran && r.answer);
  const heads = l.heads.map((head) => (
    <span class="part-head">
      {head.length === 0
        ? "all packets"
        : head.map(([f, v], i) => (
            <>
              {i ? <br /> : null}
              {f} <span class="t-value ink">{v}</span>
            </>
          ))}
    </span>
  ));
  return (
    <div class="ladder" role="table" style={{ "--ladder-columns": grid.columns, minWidth: `${grid.min}px` }}>
      <LadderHead model={l} fieldHeads={heads} reason="reason for the packets that go on" />
      {l.rows.map((r) => (
        <div class="ladder-row" role="row" key={r.key}>
          <span class="ix t-index">{r.label}</span>
          <span class="lanes">
            <Lanes
              lanes={n}
              h={h}
              marks={{ dir: "forward", lane: r.lane, enterFrom: r.enterFrom, start: r.start, end: r.end, endLane: r.endLane, group: r.group, line: width(r.parts) }}
            />
          </span>
          <span class="t-value">{r.fn}</span>
          <span class="t-body reason" title={r.reason}>
            {r.reason}
          </span>
          {r.cells.map((_, i) => (
            <PartView cells={r.cells} i={i} h={h} />
          ))}
          <RibCell rib={r.rib} h={h} />
          <span class="t-value muted">{r.source}</span>
        </div>
      ))}
      {ran.map((rep) => (
        <ReplyRow key={`r${rep.forward_branch}`} answer={answer} rep={rep} lanes={l.lanes} h={h} notRun={notRun} />
      ))}
    </div>
  );
}
