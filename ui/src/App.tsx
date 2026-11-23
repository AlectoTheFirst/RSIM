// The page: the frame with the rail and the top bar, and the views. The
// page holds the query of the Trace view and its answer.
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { ApiProblem, type ServerTiming, type TwinRef, createQuery, getCatalog, getQuery, getSourceLines, getTwin, listTwins, onReplaced } from "./api/client";
import type { Me, PathAnswer, SetAnswer, Span, TableDef, Twin } from "./api/types";
import { TokensView } from "./auth/TokensView";
import { CoverageView } from "./coverage/CoverageView";
import { InventoryView } from "./inventory/InventoryView";
import { TraceView } from "./ladder/Trace";
import type { View } from "./page/frame";
import { Rail } from "./page/Rail";
import { ToastHost } from "./page/Toast";
import { toast } from "./page/notes";
import { TopBar } from "./page/TopBar";
import { functionsSearch, isSnapshot, newerRun, pinnedRun, queryOf, topologySearch, twinState, twinStateText, viewOf, viewSearch, withTwin } from "./page/url";
import { type Fields, fieldsOf, requestBody } from "./page/query";
import { TablesView } from "./tables/TablesView";
import { TopologyView } from "./topology/TopologyView";
import { type Prefs, applyTheme, loadPrefs, savePrefs } from "./theme";

interface Result {
  twin: string;
  qid: string;
  out: PathAnswer | SetAnswer;
  /** The round trip of the query in ms, and the timing that the server gives. */
  ms: number;
  timing: ServerTiming;
}

/** The time between 2 reads of the twin list, for a newer run of the store. */
const TWINS_POLL_MS = 60_000;

/** Sets the twin of the URL of the page and keeps its other parameters. */
function replaceUrlTwin(id: string) {
  const u = new URLSearchParams(window.location.search);
  u.set("twin", id);
  window.history.replaceState(null, "", `?${u.toString()}`);
}

/** True for the problem of a snapshot that a newer snapshot replaced. */
function replaced(e: unknown): boolean {
  return e instanceof ApiProblem && e.code === "snapshot_replaced";
}

/** The time of a query: the round trip, then the engine time or a cache hit. */
export function timingText(ms: number, t: ServerTiming): string {
  const fmt = (x: number) => (x < 10 ? x.toFixed(1) : String(Math.round(x)));
  const server = t.engineMs !== null ? `, engine ${fmt(t.engineMs)} ms` : t.cacheHit ? ", cache hit" : "";
  return `round trip ${fmt(ms)} ms${server}`;
}

function readUrl(): { twin: string | null; q: string | null } {
  const u = new URLSearchParams(window.location.search);
  return { twin: u.get("twin"), q: u.get("q") };
}

/**
 * The views of the page. `user` is the signed-in user, or null on a server
 * with no sign-in, which has no view Tokens.
 */
export function App(props: { user?: Me | null; onSignOut?: () => void } = {}) {
  const user = props.user ?? null;
  const [prefs, setPrefs] = useState<Prefs>(loadPrefs);
  const [twins, setTwins] = useState<TwinRef[]>([]);
  // Whether the first list of the twins came.
  const [listed, setListed] = useState(false);
  const [twin, setTwin] = useState<string>(readUrl().twin ?? "");
  const [info, setInfo] = useState<Twin | null>(null);
  const [fields, setFields] = useState<Fields>({});
  const [result, setResult] = useState<Result | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const rerunning = useRef(false);
  // The view of the URL: Trace with no view parameter, else the view of the parameter `view`.
  const [search, setSearch] = useState(window.location.search);
  const [catalog, setCatalog] = useState<TableDef[] | null>(null);
  const urlView = viewOf(search);
  const view: View = urlView === "Tokens" && !user ? "Trace" : urlView;
  // The twin when it can answer, else empty, and the text of a twin that cannot.
  const state = twinState(listed ? twins : null, twin);
  const usable = state === "ready" ? twin : "";
  const stateText = twinStateText(state);

  useEffect(() => {
    if (view === "Trace" || view === "Tokens" || view === "Topology" || catalog) return;
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
        setListed(true);
        setTwin((t) => t || list[0]?.id || "");
      })
      .catch((e: unknown) => setProblem(String(e instanceof Error ? e.message : e)));
  }, []);

  useEffect(() => {
    if (!usable) return;
    getTwin(usable)
      .then((t) => setInfo(t.twin))
      .catch(() => setInfo(null));
  }, [usable]);

  async function load(t: string, qid: string, since: number = performance.now()) {
    setBusy(true);
    setProblem(null);
    try {
      const { out, timing } = await getQuery(t, qid);
      // The result holds the snapshot that the answer names; its steps and
      // source lines read that snapshot.
      setResult({ twin: out.twin.id, qid, out, ms: performance.now() - since, timing });
      // A query on the store pins the page to the run of its answer.
      if (out.twin.id !== t) {
        setTwin(out.twin.id);
        replaceUrlTwin(out.twin.id);
      }
      setFields(fieldsOf(out.query as unknown as Record<string, unknown>));
    } catch (e) {
      if (replaced(e) && t !== "store") {
        await rerun(t, qid, since);
        return;
      }
      setResult(null);
      setProblem(e instanceof ApiProblem ? `query refused: ${e.detail}` : String(e));
    } finally {
      setBusy(false);
    }
  }

  /** Reads the twin list again, for the mark of the twin selector. */
  function refreshTwins() {
    listTwins()
      .then(setTwins)
      .catch(() => undefined);
  }

  /** Runs the query again on the newest snapshot after its snapshot is replaced. */
  async function rerun(old: string, qid: string, since: number = performance.now()) {
    if (rerunning.current) return;
    rerunning.current = true;
    toast(`${old} replaced`);
    refreshTwins();
    try {
      await load("store", qid, since);
    } finally {
      rerunning.current = false;
    }
  }

  useEffect(() => {
    // A page whose run is replaced moves to the newest built run.
    onReplaced(() => {
      listTwins()
        .then((list) => {
          setTwins(list);
          setTwin((t) => (isSnapshot(t) ? pinnedRun(list, "store") : t));
        })
        .catch(() => undefined);
    });
    const poll = window.setInterval(refreshTwins, TWINS_POLL_MS);
    return () => {
      onReplaced(null);
      window.clearInterval(poll);
    };
  }, []);

  useEffect(() => {
    // The alias `store` pins the page to the newest built run.
    const run = pinnedRun(twins, twin);
    if (run === twin) return;
    setTwin(run);
    replaceUrlTwin(run);
  }, [twin, twins]);

  /** Moves the page to the newest built run, with the query of its answer. */
  function loadLatest(run: string) {
    setTwin(run);
    if (result && view === "Trace") {
      window.history.pushState(null, "", `?twin=${encodeURIComponent(run)}&q=${encodeURIComponent(result.qid)}`);
      void load(run, result.qid);
    } else if (view === "Trace") {
      window.history.pushState(null, "", `?twin=${encodeURIComponent(run)}`);
    } else {
      navigate(withTwin(search, run));
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

  async function run() {
    if (!twin) return;
    setBusy(true);
    setProblem(null);
    const since = performance.now();
    try {
      const made = await createQuery(twin, requestBody(fields));
      // The answer of a query on the store pins the page to its run.
      if (made.twin !== twin) setTwin(made.twin);
      refreshTwins();
      const search = `?twin=${encodeURIComponent(made.twin)}&q=${encodeURIComponent(made.qid)}`;
      window.history.pushState(null, "", search);
      await load(made.twin, made.qid, since);
    } catch (e) {
      setResult(null);
      setProblem(e instanceof ApiProblem ? `query refused: ${e.detail}` : String(e));
      setBusy(false);
    }
  }

  function copy(text: string, what: string) {
    navigator.clipboard
      .writeText(text)
      .then(() => toast(`${what} copied`))
      .catch(() => toast(`${what} not copied`));
  }

  const sourceTwin = result ? result.twin : null;
  const sourceLines = useMemo(
    () =>
      sourceTwin && result
        ? (span: Span) =>
            getSourceLines(sourceTwin, span).catch((e: unknown) => {
              if (replaced(e)) void rerun(sourceTwin, result.qid);
              throw e;
            })
        : undefined,
    [sourceTwin, result?.qid],
  );
  const onTwin = (t: string) => {
    setTwin(t);
    setResult(null);
    if (view === "Trace") window.history.pushState(null, "", `?twin=${encodeURIComponent(t)}`);
    else navigate(withTwin(search, t));
  };

  const timing = result && !busy ? timingText(result.ms, result.timing) : null;

  let content;
  if (view === "Tokens" && user) {
    content = (
      <div class="page fill">
        <TokensView user={user} />
      </div>
    );
  } else if (view === "Inventory") {
    content = (
      <div class="page fill">
        <InventoryView twin={usable} row={prefs.row} />
      </div>
    );
  } else if (stateText) {
    content = null;
  } else if (view === "Topology") {
    content = (
      <div class="page fill">
        <TopologyView
          twin={usable}
          qid={queryOf(search)}
          search={search}
          navigate={navigate}
          onFunctions={(device) => navigate(functionsSearch(twin, device))}
          onEntryPoint={(ingress) => {
            setFields((f) => ({ ...f, ingress }));
            navigate(viewSearch("Trace", twin));
          }}
        />
      </div>
    );
  } else if (view === "Tables") {
    content = (
      <div class="page fill">
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
    );
  } else if (view === "Coverage") {
    content = (
      <div class="page fill">
        <CoverageView twin={twin} row={prefs.row} search={search} navigate={navigate} />
      </div>
    );
  } else {
    content = (
      <TraceView
        twin={twin}
        fields={fields}
        onFields={setFields}
        result={result}
        problem={problem}
        busy={busy}
        timing={timing}
        row={prefs.row}
        onRun={() => void run()}
        onTopology={(qid) => navigate(topologySearch(twin, qid))}
        copy={copy}
        sourceLines={sourceLines}
      />
    );
  }

  return (
    <div class="frame">
      <Rail
        view={view}
        href={(v) => viewSearch(v, twin, search, result?.qid ?? null) || "/"}
        onView={(v) => navigate(viewSearch(v, twin, search, result?.qid ?? null))}
      />
      <div class="frame-main">
        <TopBar
          twins={twins}
          twin={twin}
          info={info}
          latest={newerRun(twins, twin)}
          onLatest={loadLatest}
          onTwin={onTwin}
          prefs={prefs}
          onPrefs={(p) => {
            savePrefs(p);
            setPrefs(p);
          }}
          user={user}
          onTokens={() => navigate(viewSearch("Tokens", twin, search))}
          onSignOut={props.onSignOut}
          state={stateText}
        />
        <main class="content" id="content">
          {content}
        </main>
      </div>
      <ToastHost />
    </div>
  );
}
