// The Trace view: the query bar, the result line and the ladder of the
// answer of a path query or a set query.
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { ApiProblem, type ServerTiming, type TwinRef, createQuery, getCatalog, getQuery, getSourceLines, getTwin, listTwins, stepUrl } from "./api/client";
import type { Answer, PathAnswer, SetAnswer, Span, TableDef, Twin } from "./api/types";
import { CoverageView } from "./coverage/CoverageView";
import { OutcomeWord, PathLadder, VerdictText } from "./ladder/Ladder";
import { SetLadder } from "./ladder/SetLadder";
import {
  type DecidingStep,
  type Level,
  type StepRow,
  autoStep,
  decidingStep,
  delayGaps,
  devicesOnPath,
  ingressHint,
  ladder,
  noIngress,
  notStated,
  partCounts,
  ribNotChecked,
  rowKeyOfStep,
  verdictWord,
} from "./ladder/layout";
import { HatchMark } from "./page/Hatch";
import { keyForElement, keyPlace } from "./tables/model";
import { KeyLine, LEVELS, QueryBar, ResultLine, TopBar } from "./page/Parts";
import { viewOf, viewSearch, withTwin } from "./page/url";
import { type Fields, type Mode, explainCommand, fieldsOf, mcpCall, requestBody, rsimCommand } from "./page/query";
import { QUERY_FIELDS, modeValue } from "./page/fields";
import { TablesView } from "./tables/TablesView";
import { type Prefs, applyTheme, loadPrefs, savePrefs } from "./theme";

interface Result {
  twin: string;
  qid: string;
  out: PathAnswer | SetAnswer;
  /** The round trip of the query in ms, and the timing that the server gives. */
  ms: number;
  timing: ServerTiming;
}

/** The time of a query: the round trip, then the engine time or a cache hit. */
export function timingText(ms: number, t: ServerTiming): string {
  const fmt = (x: number) => (x < 10 ? x.toFixed(1) : String(Math.round(x)));
  const server = t.engineMs !== null ? ` · engine ${fmt(t.engineMs)} ms` : t.cacheHit ? " · from the cache" : "";
  return `answered in ${fmt(ms)} ms${server}`;
}

const isSet = (out: PathAnswer | SetAnswer) => out.kind === "set_answer";

/** Whether the query of an answer asks for the reply. */
const asksReply = (out: PathAnswer | SetAnswer) => (out.query as { reply?: boolean | null }).reply !== false;

function PathFacts(props: { a: Answer; onStep: (d: DecidingStep) => void }) {
  const a = props.a;
  const s = a.summary;
  const multi = a.branches.length > 1;
  const one = s.length === 1 && s[0]!.result.verdict ? s[0]!.result.verdict : null;
  const b0 = a.branches[0];
  const rib = ribNotChecked(a);
  return (
    <>
      <span>
        {one ? (
          <VerdictText v={one} headline at={b0 && !multi ? decidingStep(b0) : null} onStep={props.onStep} />
        ) : (
          <span class="t-headline">{s[0]?.result.kind ?? "no answer"}</span>
        )}
        {!multi && b0 && b0.steps.length ? (
          <span class="muted">
            , {b0.steps.length} functions on {devicesOnPath(b0).length} devices
          </span>
        ) : null}
      </span>
      {multi
        ? a.branches.map((b) => (
            <span>
              <span class="muted">branch {b.index} </span>
              <VerdictText v={b.verdict} at={decidingStep(b)} onStep={props.onStep} />
            </span>
          ))
        : null}
      {a.replies.map((r) => {
        const label = multi ? `reply of branch ${r.forward_branch}` : "reply";
        if (!r.ran || !r.answer) {
          return (
            <span>
              <span class="c-reply">{label}</span> <span class="muted">{r.not_run_reason ?? "not run"}</span>
            </span>
          );
        }
        const kinds = [...new Set(r.answer.branches.map((b) => b.verdict.kind))];
        return (
          <span>
            <span class="c-reply">{label}</span>{" "}
            {kinds.length === 1 && r.answer.branches[0] ? (
              <VerdictText v={r.answer.branches[0].verdict} />
            ) : (
              kinds.map((k, i) => (
                <>
                  {i ? ", " : ""}
                  <OutcomeWord kind={k} />
                </>
              ))
            )}
          </span>
        );
      })}
      {a.branches.map((b) => {
        if (!b.delay.lower_bound) return null;
        const g = delayGaps(b);
        return (
          <HatchMark>
            {multi ? `branch ${b.index}: ` : ""}delay at least {b.delay.known_ns} ns: {g.functions} functions and {g.links} links have
            no delay data
          </HatchMark>
        );
      })}
      {rib ? <HatchMark>{rib} route lookups not checked against a collected RIB</HatchMark> : null}
    </>
  );
}

function SetFacts(props: { a: Answer }) {
  const parts = props.a.summary;
  const n = partCounts(parts);
  return (
    <>
      <span class="t-headline">{parts.length} parts</span>
      <span>
        <OutcomeWord kind="deliver" /> {n.deliver}
      </span>
      {n.exit ? (
        <span>
          <OutcomeWord kind="exit" /> {n.exit}
        </span>
      ) : null}
      <span>
        <OutcomeWord kind="drop" /> {n.drop}
      </span>
      <span>
        <span class="strong">{verdictWord("unknown")}</span> {n.unknown}
      </span>
      {n.dependsOnPath ? <span class="muted">{n.dependsOnPath} parts depend on the path</span> : null}
    </>
  );
}

function readUrl(): { twin: string | null; q: string | null } {
  const u = new URLSearchParams(window.location.search);
  return { twin: u.get("twin"), q: u.get("q") };
}

export function App() {
  const [prefs, setPrefs] = useState<Prefs>(loadPrefs);
  const [twins, setTwins] = useState<TwinRef[]>([]);
  const [twin, setTwin] = useState<string>(readUrl().twin ?? "");
  const [info, setInfo] = useState<Twin | null>(null);
  const [mode, setMode] = useState<Mode>("path");
  const [fields, setFields] = useState<Fields>({});
  const [result, setResult] = useState<Result | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [level, setLevel] = useState<Level>("function");
  const [selected, setSelected] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  // A count that the button "Select entry point" raises.
  const [askIngress, setAskIngress] = useState(0);
  const firstInput = useRef<HTMLInputElement | null>(null);
  // Whether the next ladder opens the deciding step of its answer.
  const autoOpen = useRef(false);
  // The view of the URL: Trace with no view parameter, else Tables or Coverage.
  const [search, setSearch] = useState(window.location.search);
  const [catalog, setCatalog] = useState<TableDef[] | null>(null);
  const view = viewOf(search);

  useEffect(() => {
    if (view === "Trace" || catalog) return;
    getCatalog()
      .then((c) => setCatalog(c.tables))
      .catch((e: unknown) => setProblem(String(e instanceof Error ? e.message : e)));
  }, [view]);

  function navigate(next: string) {
    if (next === window.location.search) return;
    window.history.pushState(null, "", next || "/");
    setSearch(next);
  }

  useEffect(() => {
    applyTheme(prefs);
    savePrefs(prefs);
    if (prefs.theme !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const on = () => applyTheme(prefs);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [prefs]);

  useEffect(() => {
    listTwins()
      .then((list) => {
        setTwins(list);
        setTwin((t) => t || list[0]?.id || "");
      })
      .catch((e: unknown) => setProblem(String(e instanceof Error ? e.message : e)));
  }, []);

  useEffect(() => {
    if (!twin) return;
    getTwin(twin)
      .then((t) => setInfo(t.twin))
      .catch(() => setInfo(null));
  }, [twin]);

  async function load(t: string, qid: string, since: number = performance.now()) {
    setBusy(true);
    setProblem(null);
    try {
      const { out, timing } = await getQuery(t, qid);
      setResult({ twin: t, qid, out, ms: performance.now() - since, timing });
      setFields(fieldsOf(out.query as unknown as Record<string, unknown>));
      setMode(isSet(out) ? "set" : "path");
      setSelected(null);
      setOpen(false);
      autoOpen.current = true;
    } catch (e) {
      setResult(null);
      setProblem(e instanceof ApiProblem ? `The query is refused: ${e.detail}` : String(e));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const { twin: t, q } = readUrl();
    if (t && q) void load(t, q);
    const onPop = () => {
      setSearch(window.location.search);
      const u = readUrl();
      if (u.twin) setTwin(u.twin);
      if (u.twin && u.q) void load(u.twin, u.q);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  /** A change of the mode, with each value in the form of the new mode. */
  function changeMode(next: Mode) {
    const out: Fields = { ...fields };
    const cleared: string[] = [];
    for (const k of QUERY_FIELDS) {
      const v = fields[k];
      if (v === undefined) continue;
      const w = modeValue(mode, next, k, v);
      if (w === null) cleared.push(k);
      out[k] = w ?? "";
    }
    setFields(out);
    setMode(next);
    setNotice(cleared.length ? `${cleared.join(", ")} is cleared: a path query takes the flags of one packet.` : null);
  }

  async function run() {
    if (!twin) return;
    setBusy(true);
    setProblem(null);
    const since = performance.now();
    try {
      const made = await createQuery(twin, requestBody(mode, fields));
      const search = `?twin=${encodeURIComponent(twin)}&q=${encodeURIComponent(made.qid)}`;
      window.history.pushState(null, "", search);
      await load(made.twin, made.qid, since);
    } catch (e) {
      setResult(null);
      setProblem(e instanceof ApiProblem ? `The query is refused: ${e.detail}` : String(e));
      setBusy(false);
    }
  }

  const answer = result?.out.answer ?? null;
  const setMode_ = result ? isSet(result.out) : false;
  const reply = result ? asksReply(result.out) : true;
  const model = useMemo(() => (answer && !setMode_ ? ladder(answer, level, reply) : null), [answer, level, setMode_, reply]);
  // A new answer that does not deliver opens the step that decides it, in
  // the ladder of the current level.
  useEffect(() => {
    if (!autoOpen.current || !model || !answer) return;
    autoOpen.current = false;
    const d = autoStep(answer);
    const key = d ? rowKeyOfStep(model.rows, d.path, d.step.index) : null;
    if (!key) return;
    setSelected(key);
    setOpen(true);
  }, [model]);
  const stepRows = useMemo(() => (model ? model.rows.filter((r): r is StepRow => r.type === "step") : []), [model]);

  function copy(text: string, what: string) {
    navigator.clipboard
      .writeText(text)
      .then(() => setNotice(`Copied the ${what}.`))
      .catch(() => setNotice(`The browser did not copy the ${what}.`));
  }

  const sourceTwin = result && !result.twin.startsWith("builtin.") ? result.twin : null;
  const sourceLines = useMemo(
    () => (sourceTwin ? (span: Span) => getSourceLines(sourceTwin, span) : undefined),
    [sourceTwin],
  );
  const actions = {
    sourceLines,
    copyExplain: (row: StepRow) => {
      const st = row.steps[row.steps.length - 1]!;
      copy(explainCommand(mode, result?.twin ?? twin, fields, row.path.branch, st.index, row.path.replyOf), "rsim explain command");
    },
    copyUrl: (row: StepRow) => {
      if (!result) return;
      const st = row.steps[row.steps.length - 1]!;
      copy(new URL(stepUrl(result.twin, result.qid, row.path.branch, st.index, row.path.replyOf), window.location.href).href, "step URL");
    },
  };

  function openStep(d: DecidingStep) {
    const key = model ? rowKeyOfStep(model.rows, d.path, d.step.index) : null;
    if (!key) return;
    setSelected(key);
    setOpen(true);
  }

  function select(key: string) {
    if (key === selected) setOpen(!open);
    else {
      setSelected(key);
      setOpen(true);
    }
  }

  useEffect(() => {
    if (selected) document.getElementById(`row-${selected}`)?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (view !== "Trace") return;
      const t = e.target as HTMLElement | null;
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      const place = keyPlace(t);
      if (keyForElement(place, e.key)) {
        if (place === "text" && e.key === "Escape") t?.blur();
        return;
      }
      const at = stepRows.findIndex((r) => r.key === selected);
      switch (e.key) {
        case "j":
          if (stepRows.length) setSelected(stepRows[Math.min(stepRows.length - 1, at + 1)]!.key);
          break;
        case "k":
          if (stepRows.length) setSelected(stepRows[Math.max(0, at - 1)]!.key);
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
        case "r": {
          const r = stepRows.find((x) => x.dir === "reply");
          if (r) setSelected(r.key);
          break;
        }
        case "y": {
          const r = stepRows[at];
          if (r) actions.copyExplain(r);
          else copy(rsimCommand(mode, twin, fields), "rsim command");
          break;
        }
        default:
          return;
      }
      e.preventDefault();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });

  const echo = result ? (result.out.query as unknown as Record<string, unknown>) : null;
  const keys: [string, string][] = setMode_
    ? [
        ["[ ]", "level"],
        ["/", "query"],
        ["y", "copy"],
      ]
    : [
        ["j k", "step"],
        ["enter", "open"],
        ["[ ]", "level"],
        ["/", "query"],
        ["r", "reply"],
        ["y", "copy"],
      ];

  return (
    <>
      <TopBar
        twins={twins}
        twin={twin}
        info={info}
        onTwin={(t) => {
          setTwin(t);
          setResult(null);
          if (view === "Trace") window.history.pushState(null, "", `?twin=${encodeURIComponent(t)}`);
          else navigate(withTwin(search, t));
        }}
        view={view}
        onView={(v) => navigate(viewSearch(v, twin, search, result?.qid ?? null))}
        prefs={prefs}
        onPrefs={setPrefs}
      />
      {view === "Tables" ? (
        <div class="grid-page">
          <TablesView
            twin={twin}
            row={prefs.row}
            catalog={catalog}
            search={search}
            navigate={navigate}
            onUseAddress={(k, a) => {
              setFields((f) => ({ ...f, [k]: a }));
              navigate(viewSearch("Trace", twin));
            }}
          />
        </div>
      ) : view === "Coverage" ? (
        <div class="grid-page">
          <CoverageView twin={twin} row={prefs.row} catalog={catalog} search={search} navigate={navigate} />
        </div>
      ) : (
      <>
      <QueryBar
        twin={twin}
        mode={mode}
        fields={fields}
        found={answer && !busy ? ingressHint(answer) : null}
        askIngress={askIngress}
        notStated={echo && !setMode_ ? notStated(echo) : null}
        onMode={changeMode}
        onField={(k, v) => setFields({ ...fields, [k]: v })}
        onRun={() => void run()}
        onCopyCommand={() => copy(rsimCommand(mode, twin, fields), "rsim command")}
        onCopyMcp={() => copy(mcpCall(mode, twin, fields), "MCP call")}
        firstInput={firstInput}
      />
      <ResultLine level={level} onLevel={setLevel}>
        {busy ? (
          <span class="muted">The query runs.</span>
        ) : problem ? (
          <span>{problem}</span>
        ) : answer ? (
          <>
            {setMode_ ? <SetFacts a={answer} /> : <PathFacts a={answer} onStep={openStep} />}
            {noIngress(answer) ? (
              <button type="button" onClick={() => setAskIngress((n) => n + 1)}>
                Select entry point
              </button>
            ) : null}
          </>
        ) : (
          <span class="muted">State the fields of a query and run it.</span>
        )}
      </ResultLine>
      <main class="body">
        {answer && model ? (
          <PathLadder
            answer={answer}
            model={model}
            h={prefs.row}
            selected={selected}
            open={open}
            onSelect={select}
            actions={actions}
          />
        ) : answer && setMode_ ? (
          <SetLadder answer={answer} level={level} h={prefs.row} />
        ) : null}
      </main>
      <KeyLine keys={notice ? [...keys, ["", notice]] : keys} timing={result && !busy ? timingText(result.ms, result.timing) : null} />
      </>
      )}
    </>
  );
}
