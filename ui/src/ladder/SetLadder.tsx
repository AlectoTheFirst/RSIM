// The ladder of a set query: the header fields give place to one column
// for each part.
import type { Answer } from "../api/types";
import { SIZE, TYPE } from "../theme";
import { LaneNames, Lanes } from "./Lanes";
import { RibCell, SectionLine, ladderColumns } from "./Ladder";
import { type Level, verdictWord } from "./layout";
import { type PartCell, setLadder } from "./setLayout";

function PartView(props: { c: PartCell }) {
  const c = props.c;
  switch (c.kind) {
    case "band":
      return <span class="part band" />;
    case "end":
      return (
        <span class={`part end ${c.end}`}>
          <span class={`strong${c.end === "unknown" ? "" : ` c-${c.end}`}`}>{verdictWord(c.verdict.kind)}</span>{" "}
          <span class="t-value">{c.verdict.reason?.detail ?? c.verdict.destination?.endpoint ?? c.verdict.destination?.device ?? ""}</span>
        </span>
      );
    case "apart":
      return <span class="part muted">takes another path from step {c.step}</span>;
    case "none":
      return <span class="part" />;
  }
}

export function SetLadder(props: { answer: Answer; level: Level; h: number }) {
  const { answer, level, h } = props;
  const l = setLadder(answer, level);
  const n = l.lanes.length;
  const cols = l.heads.map(() => `${SIZE.partColumn}px`);
  const width = (parts: number) => SIZE.partLine[Math.min(parts, SIZE.partLine.length) - 1] ?? SIZE.pathLine;
  return (
    <div class="ladder" role="table" style={{ "--ladder-columns": ladderColumns(n, cols) }}>
      <div class="ladder-row ladder-head t-label" role="row">
        <span />
        <span class="lanes head">
          <LaneNames lanes={l.lanes} line={TYPE.index.line} />
        </span>
        <span>function</span>
        <span>reason for the packets that go on</span>
        {l.heads.map((head) => (
          <span class="part-head">
            {head.length === 0
              ? "all packets"
              : head.map(([f, v]) => (
                  <>
                    {f} <span class="t-value">{v}</span>
                    <br />
                  </>
                ))}
          </span>
        ))}
        <span class="cell">rib</span>
        <span>source lines</span>
      </div>
      {l.rows.map((r) => (
        <div class="ladder-row" role="row" key={r.key}>
          <span class="ix t-index">{r.label}</span>
          <span class="lanes">
            <Lanes
              lanes={n}
              h={h}
              marks={{ dir: "forward", lane: r.lane, enterFrom: r.enterFrom, start: r.start, end: null, group: r.group, line: width(r.parts) }}
            />
          </span>
          <span class="t-value">{r.fn}</span>
          <span class="t-body">{r.reason}</span>
          {r.cells.map((c) => (
            <PartView c={c} />
          ))}
          <RibCell rib={r.rib} h={h} />
          <span class="t-value muted">{r.source}</span>
        </div>
      ))}
      {answer.replies.map((rep) => (
        <SectionLine
          key={`r${rep.forward_branch}`}
          row={{
            type: "section",
            key: `r${rep.forward_branch}`,
            dir: "reply",
            text: `reply of branch ${rep.forward_branch}`,
            verdict: rep.answer?.branches.length === 1 ? rep.answer.branches[0]!.verdict : null,
            note: rep.ran ? (rep.answer && rep.answer.branches.length > 1 ? `${rep.answer.branches.length} branches` : null) : (rep.not_run_reason ?? null),
          }}
          lanes={n}
          h={h}
        />
      ))}
    </div>
  );
}
