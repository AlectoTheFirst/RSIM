// The view Trace: the query card, the outcome card with the path strip,
// the list of the paths or of the parts, the ladder of the selected path
// and the step panel.
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { getInventory, stepUrl, tableRows } from "../api/client";
import type { Answer, PathAnswer, SetAnswer, SourceText, Span } from "../api/types";
import { Card, PanelLayout } from "../page/Card";
import { Hatch, HatchMark } from "../page/Hatch";
import { LEVELS, QueryBar } from "../page/Parts";
import { Chip } from "../page/Pill";
import { type Fields, explainCommand, fieldsOf, queryMode, rsimCommand } from "../page/query";
import { Segmented } from "../page/Segmented";
import { keyForElement, keyPlace } from "../tables/model";
import { SIZE } from "../theme";
import { OutcomeSymbol, OutcomeWord, PathLadder, VerdictText, rowId } from "./Ladder";
import {
  type DecidingStep,
  type Dir,
  type Level,
  type PathRef,
  type StepRow,
  answerNotes,
  autoStep,
  destinationOf,
  functionLabel,
  functionNames,
  functionWidth,
  ingressHint,
  ladder,
  noIngress,
  noteLabel,
  rowKeyOfStep,
  verdictWord,
} from "./layout";
import { type PathItem, type Strip, deviceSite, forwardPaths, pathIndex, replyPaths, replyState, selectedPath, stripOf, tally, withKind } from "./paths";
import { PartList, PathList } from "./SetLadder";
import { partAnswer, partList } from "./setLayout";
import { StepPanel } from "./StepPanel";

/** An answer of the view with its twin and its query id. */
export interface TraceResult {
  twin: string;
  qid: string;
  out: PathAnswer | SetAnswer;
}

const DIRS: readonly Dir[] = ["forward", "reply"];

/** Whether the query of an answer asks for the reply. */
const asksReply = (out: PathAnswer | SetAnswer) => (out.query as { reply?: boolean | null }).reply !== false;

/** The outcomes that occur with their counts; a click filters the list of the paths or the parts. */
function Tally(props: { kinds: readonly string[]; filter: string | null; label: string; onFilter: (k: string | null) => void }) {
  return (
    <span class="group" role="group" aria-label={props.label}>
      {tally(props.kinds).map(([k, n]) => (
        <button type="button" class="tally" aria-pressed={props.filter === k} onClick={() => props.onFilter(props.filter === k ? null : k)}>
          <OutcomeWord kind={k} /> <span class="t-value">{n}</span>
        </button>
      ))}
    </span>
  );
}

/** The outcome word of one reply path, then its destination, or its deciding step and reason. */
function ReplyOutcome(props: { p: PathItem; onStep: (d: DecidingStep) => void }) {
  const { p } = props;
  const v = p.verdict;
  const dest = destinationOf(v);
  return (
    <span class="verdict">
      <OutcomeWord kind={v.kind} />
      {dest ? (
        <>
          {" to "}
          <span class="t-value">{dest}</span>
        </>
      ) : null}
      {v.kind === "exit" && v.reason ? <span class="t-value"> {v.reason.detail}</span> : null}
      {v.kind !== "exit" && p.at ? (
        <>
          {" at "}
          <button type="button" class="link t-value" onClick={() => props.onStep(p.at!)}>
            {p.at.step.device ? `${p.at.step.device} ${functionLabel(p.at.step)}` : p.at.step.function}
          </button>
          <span class="muted">, {p.at.reason}</span>
        </>
      ) : null}
      {p.tunnel ? <span class="t-value">, {p.tunnel}</span> : null}
    </span>
  );
}

/** The path strip: the source endpoint, each device of the path and the destination endpoint, joined by a line in the colour of the direction. */
function PathStrip(props: { strip: Strip; dir: Dir }) {
  const { strip, dir } = props;
  const items = strip.nodes.map((n) =>
    n.kind === "endpoint" ? (
      <span class="strip-node">
        <span class={`strip-dot ${n.end ? `dot-${strip.end}` : `dot-${dir}`}`} aria-hidden="true" />
        <span class="strip-name">
          <span class="t-value strong">{n.name}</span>
          {n.address ? <span class="t-index muted">{n.address}</span> : null}
        </span>
      </span>
    ) : (
      <span class="strip-node">
        <span class="strip-name">
          <span class="t-value strong">{n.name}</span>
          {n.site ? <span class="t-index muted">{n.site}</span> : null}
        </span>
      </span>
    ),
  );
  return (
    <div class="strip" role="group" aria-label="Path">
      {items.map((it, i) => (
        <>
          {i ? <span class={`strip-line line-${dir}`} aria-hidden="true" /> : null}
          {it}
        </>
      ))}
      {strip.atEndpoint ? null : (
        <>
          <span class={`strip-line line-${dir}`} aria-hidden="true" />
          <span class={`strip-end end-${strip.end}`} aria-hidden="true">
            {strip.end === "unknown" ? <Hatch w={SIZE.endSquare} h={SIZE.endSquare} /> : null}
          </span>
        </>
      )}
    </div>
  );
}

const NO_DEVICES: ReadonlyMap<string, string> = new Map();

/** The sites of the inventory devices by name, or an empty map with no inventory. */
function useInventorySites(): ReadonlyMap<string, string> {
  const [sites, setSites] = useState<ReadonlyMap<string, string>>(NO_DEVICES);
  useEffect(() => {
    let live = true;
    getInventory()
      .then((inv) => {
        if (live) setSites(new Map(inv.devices.flatMap((d) => (d.site ? [[d.name, d.site] as const] : []))));
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);
  return sites;
}

/** The store devices of the twin devices with no inventory device of their name, from the table `devices`. */
function useStoreDevices(twin: string, devices: readonly string[], sites: ReadonlyMap<string, string>): ReadonlyMap<string, string> {
  const [store, setStore] = useState<{ key: string; map: ReadonlyMap<string, string> }>({ key: "", map: NO_DEVICES });
  const wanted = sites.size ? devices.filter((d) => !sites.has(d)) : [];
  const key = `${twin}\u0000${wanted.join(",")}`;
  useEffect(() => {
    if (!twin || wanted.length === 0 || store.key === key) return;
    let live = true;
    tableRows(twin, "devices", { device: wanted.join(","), columns: "device,store_device", limit: String(wanted.length) })
      .then((t) => {
        const d = t.columns.indexOf("device");
        const s = t.columns.indexOf("store_device");
        const map = new Map<string, string>();
        for (const r of t.rows) if (typeof r[d] === "string" && typeof r[s] === "string") map.set(r[d], r[s]);
        if (live) setStore({ key, map });
      })
      .catch(() => {
        if (live) setStore({ key, map: NO_DEVICES });
      });
    return () => {
      live = false;
    };
  }, [key]);
  return store.key === key ? store.map : NO_DEVICES;
}

/** The view Trace of a path query or a set query. */
export function TraceView(props: {
  twin: string;
  fields: Fields;
  onFields: (f: Fields) => void;
  result: TraceResult | null;
  problem: string | null;
  busy: boolean;
  /** The text of the time of the query, or null. */
  timing: string | null;
  /** The row height of the preferences, in px. */
  row: number;
  onRun: () => void;
  copy: (text: string, what: string) => void;
  sourceLines?: (span: Span) => Promise<SourceText>;
}) {
  const { result, fields, twin, copy } = props;
  const [level, setLevel] = useState<Level>("function");
  const [dir, setDir] = useState<Dir>("forward");
  const [fwdSel, setFwdSel] = useState<PathRef | null>(null);
  const [repSel, setRepSel] = useState<PathRef | null>(null);
  const [filter, setFilter] = useState<{ forward: string | null; reply: string | null }>({ forward: null, reply: null });
  const [part, setPart] = useState<number | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [askIngress, setAskIngress] = useState(0);
  const firstInput = useRef<HTMLInputElement | null>(null);
  const autoOpen = useRef(false);
  const returnFocus = useRef<HTMLElement | null>(null);

  const out = result?.out ?? null;
  const answer: Answer | null = out?.answer ?? null;
  const setMode = out?.kind === "set_answer";
  const reply = out ? asksReply(out) : true;

  useEffect(() => {
    setDir("forward");
    setFwdSel(null);
    setRepSel(null);
    setFilter({ forward: null, reply: null });
    setPart(answer && setMode ? (answer.branches[0]?.index ?? null) : null);
    setSelected(null);
    setOpen(false);
    autoOpen.current = true;
  }, [result]);

  const parts = useMemo(() => (answer && setMode ? partList(answer) : []), [answer, setMode]);
  const partsShown = useMemo(() => withKind(parts.map((p) => ({ ...p, verdict: { kind: p.kind } })), setMode ? filter.forward : null), [parts, filter.forward, setMode]);
  const partSel = partsShown.some((p) => p.branch === part) ? part : (partsShown[0]?.branch ?? null);
  // The answer of the ladder: the path answer, or the selected part of a set answer.
  const shown = useMemo(() => (answer && setMode ? (partSel === null ? null : partAnswer(answer, partSel)) : answer), [answer, setMode, partSel]);

  const fwdAll = useMemo(() => (shown ? forwardPaths(shown) : []), [shown]);
  const fwdList = useMemo(() => withKind(fwdAll, setMode ? null : filter.forward), [fwdAll, filter.forward, setMode]);
  const fwd = selectedPath(fwdList, fwdSel);
  const repAll = useMemo(() => (shown && fwd ? replyPaths(shown, fwd.branch) : []), [shown, fwd?.branch]);
  const repList = useMemo(() => withKind(repAll, filter.reply), [repAll, filter.reply]);
  const rep = selectedPath(repList, repSel);
  const hasReply = repAll.length > 0;
  const d: Dir = dir === "reply" && hasReply ? "reply" : "forward";
  const path = d === "forward" ? fwd : rep;
  const list = d === "forward" ? fwdList : repList;
  const all = d === "forward" ? fwdAll : repAll;

  const model = useMemo(() => (shown && path ? ladder(shown, level, path, setMode) : null), [shown, level, path?.branch, path?.replyOf, setMode]);
  const fnWidth = useMemo(() => (answer ? functionWidth(functionNames(answer)) : SIZE.colFunction), [answer]);
  const sites = useInventorySites();
  const pathDevices = useMemo(() => (path ? (list.find((p) => p.ref.branch === path.branch && p.ref.replyOf === path.replyOf)?.devices ?? []) : []), [list, path?.branch, path?.replyOf]);
  const storeDevices = useStoreDevices(twin, pathDevices, sites);
  const strip = useMemo(
    () => (shown && path ? stripOf(shown, path, (dev) => deviceSite(dev, sites, storeDevices)) : null),
    [shown, path?.branch, path?.replyOf, sites, storeDevices],
  );
  const rows = model?.rows ?? [];
  const at = rows.findIndex((r) => r.key === selected);
  const current: StepRow | null = at >= 0 ? rows[at]! : null;

  /** Selects the deciding step of a path and opens its panel. */
  function openStep(s: DecidingStep) {
    if (!shown) return;
    if (s.path.replyOf === null) {
      setDir("forward");
      setFwdSel(s.path);
    } else {
      setDir("reply");
      setRepSel(s.path);
    }
    const key = rowKeyOfStep(ladder(shown, level, s.path, setMode).rows, s.path, s.step.index);
    if (!key) return;
    setSelected(key);
    setOpen(true);
  }

  // A new answer or part that does not deliver opens the step that decides it.
  useEffect(() => {
    if (!autoOpen.current || !shown) return;
    autoOpen.current = false;
    const s = autoStep(shown);
    if (s) openStep(s);
  }, [shown]);

  useEffect(() => {
    if (selected) document.getElementById(rowId(selected))?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  function resetRow() {
    setSelected(null);
    setOpen(false);
  }

  function selectPart(branch: number) {
    if (branch === partSel) return;
    setPart(branch);
    setFwdSel(null);
    setRepSel(null);
    setFilter((f) => ({ ...f, reply: null }));
    resetRow();
    autoOpen.current = true;
  }

  function selectPath(p: PathRef) {
    if (p.replyOf === null) setFwdSel(p);
    else setRepSel(p);
    resetRow();
  }

  function setDirection(x: Dir) {
    if (x === d) return;
    setDir(x);
    resetRow();
  }

  function setKind(which: Dir, k: string | null) {
    setFilter((f) => ({ ...f, [which]: k }));
    if (which !== d) setDir(which);
    resetRow();
  }

  function selectRow(key: string, openIt: boolean) {
    if (openIt && key === selected && open) setOpen(false);
    else {
      setSelected(key);
      if (openIt) setOpen(true);
    }
  }

  const copyExplain = (row: StepRow) => {
    const st = row.steps[row.steps.length - 1]!;
    if (!result) return;
    // The step of an answer opens through the query type of its query.
    const sent = fieldsOf(result.out.query as unknown as Record<string, unknown>);
    copy(explainCommand(setMode ? "set" : "path", result.twin, sent, row.path.branch, st.index, row.path.replyOf), "rsim explain command");
  };
  const copyUrl = (row: StepRow) => {
    if (!result) return;
    const st = row.steps[row.steps.length - 1]!;
    copy(new URL(stepUrl(result.twin, result.qid, row.path.branch, st.index, row.path.replyOf), window.location.href).href, "step URL");
  };
  const copyCommand = () => copy(rsimCommand(queryMode(fields), twin, fields), "rsim command");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      const place = keyPlace(t);
      if (keyForElement(place, e.key)) {
        if (place === "text" && e.key === "Escape") t?.blur();
        return;
      }
      switch (e.key) {
        case "j":
          if (rows.length) setSelected(rows[Math.min(rows.length - 1, at + 1)]!.key);
          break;
        case "k":
          if (rows.length) setSelected(rows[Math.max(0, at - 1)]!.key);
          break;
        case "Enter":
          if (selected) setOpen(!open);
          else return;
          break;
        case "Escape":
          setOpen(false);
          break;
        case "[":
        case "]": {
          const i = LEVELS.indexOf(level) + (e.key === "]" ? 1 : -1);
          if (i >= 0 && i < LEVELS.length) setLevel(LEVELS[i]!);
          break;
        }
        case "/":
          firstInput.current?.focus();
          break;
        case "r":
          if (hasReply) setDirection("reply");
          break;
        case "y":
          if (current) copyExplain(current);
          else copyCommand();
          break;
        default:
          return;
      }
      e.preventDefault();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });

  returnFocus.current = selected ? document.getElementById(rowId(selected)) : null;
  const panel =
    open && current ? (
      <StepPanel
        row={current}
        actions={{ copyExplain, copyUrl, sourceLines: props.sourceLines }}
        onPrevious={at > 0 ? () => setSelected(rows[at - 1]!.key) : null}
        onNext={at < rows.length - 1 ? () => setSelected(rows[at + 1]!.key) : null}
        onClose={() => setOpen(false)}
        returnFocus={returnFocus}
      />
    ) : null;

  const notes = out ? answerNotes(out) : [];
  const fwdItem = fwd ? fwdAll[pathIndex(fwdAll, fwd)] : undefined;

  let headline = null;
  if (answer && !setMode) {
    if (fwdAll.length === 1 && fwdItem) {
      headline = (
        <>
          <OutcomeSymbol kind={fwdItem.verdict.kind} />
          <VerdictText v={fwdItem.verdict} at={fwdItem.at} onStep={openStep} tunnel={fwdItem.tunnel} />
        </>
      );
    } else {
      const s = answer.summary[0]?.result;
      const kind = s?.verdict?.kind ?? s?.verdict_kind ?? null;
      headline = (
        <>
          {kind ? <OutcomeSymbol kind={kind} /> : null}
          {s?.verdict ? (
            <VerdictText v={s.verdict} />
          ) : kind ? (
            <OutcomeWord kind={kind} />
          ) : (
            <span class="strong">{s?.kind === "depends_on_path" ? "depends on path" : (s?.kind ?? "")}</span>
          )}
          <Tally kinds={fwdAll.map((p) => p.verdict.kind)} filter={filter.forward} label="Outcomes" onFilter={(k) => setKind("forward", k)} />
        </>
      );
    }
  } else if (answer && setMode) {
    headline = <Tally kinds={parts.map((p) => p.kind)} filter={filter.forward} label="Outcomes" onFilter={(k) => setKind("forward", k)} />;
  }

  let replyLine = null;
  const rs = shown && fwdItem ? replyState(shown, fwdItem.ref.branch, reply) : { kind: "none" as const };
  if (rs.kind === "not_run") replyLine = <span class="muted">{rs.reason}</span>;
  else if (rs.kind === "no_reply") replyLine = <span class="muted">no reply</span>;
  else if (rs.kind === "paths" && rs.paths.length === 1) {
    replyLine = (
      <>
        <OutcomeSymbol kind={rs.paths[0]!.verdict.kind} />
        <ReplyOutcome p={rs.paths[0]!} onStep={openStep} />
      </>
    );
  }
  else if (rs.kind === "paths") {
    replyLine = <Tally kinds={rs.paths.map((p) => p.verdict.kind)} filter={filter.reply} label="Reply outcomes" onFilter={(k) => setKind("reply", k)} />;
  }

  const filterChip = (which: Dir) =>
    filter[which] ? <Chip column="outcome" value={verdictWord(filter[which]!)} onRemove={() => setKind(which, null)} /> : undefined;

  return (
    <div class="page">
      <Card label="Query" class="query-card">
        <QueryBar
          twin={twin}
          fields={fields}
          found={answer && !props.busy ? ingressHint(answer) : null}
          askIngress={askIngress}
          row={props.row}
          onField={(k, v) => props.onFields({ ...fields, [k]: v })}
          onFields={props.onFields}
          onRun={props.onRun}
          firstInput={firstInput}
        />
      </Card>
      <Card label="Outcome" class="outcome-card">
        <div class="outcome" aria-live="polite">
          <div class="outcome-main">
            {props.busy ? (
              <span class="muted">running</span>
            ) : props.problem ? (
              <span>{props.problem}</span>
            ) : answer ? (
              <>
                <div class="outcome-line">
                  {replyLine ? <span class="t-label muted outcome-dir">forward</span> : null}
                  {headline}
                </div>
                {replyLine ? (
                  <div class="outcome-line">
                    <span class="t-label muted outcome-dir">reply</span>
                    {replyLine}
                  </div>
                ) : null}
                {notes.length || noIngress(answer) ? (
                  <div class="outcome-line">
                    {notes.map((n) => (
                      <HatchMark title={n}>{noteLabel(n)}</HatchMark>
                    ))}
                    {noIngress(answer) ? (
                      <button type="button" onClick={() => setAskIngress((n) => n + 1)}>
                        Select entry point
                      </button>
                    ) : null}
                  </div>
                ) : null}
              </>
            ) : (
              <span class="muted">no query</span>
            )}
          </div>
          {answer && !props.busy && !props.problem ? (
            <span class="group outcome-controls">
              {props.timing ? <span class="t-index muted">{props.timing}</span> : null}
              {hasReply ? <Segmented<Dir> label="Direction" value={d} options={DIRS} onChange={setDirection} /> : null}
              <Segmented<Level> label="Level" value={level} options={LEVELS} onChange={setLevel} />
            </span>
          ) : null}
        </div>
        {strip && !props.busy && !props.problem ? <PathStrip strip={strip} dir={d} /> : null}
      </Card>
      {answer && !props.busy ? (
        <PanelLayout panel={panel}>
          {setMode ? (
            <Card title="Parts" head={filterChip("forward")} flush>
              <PartList parts={partsShown} selected={partSel} onSelect={selectPart} row={props.row} />
            </Card>
          ) : null}
          {all.length > 1 ? (
            <Card title="Paths" head={filterChip(d)} flush>
              <PathList paths={list} selected={path ? pathIndex(list, path) : null} onSelect={(i) => selectPath(list[i]!.ref)} row={props.row} />
            </Card>
          ) : null}
          {model && model.rows.length ? (
            <Card label="Ladder" flush>
              <PathLadder model={model} fnWidth={fnWidth} h={props.row} selected={selected} onSelect={selectRow} />
            </Card>
          ) : null}
        </PanelLayout>
      ) : null}
    </div>
  );
}

