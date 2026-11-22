// The Coverage view: the config lines of each device that the ingestion
// handles, that have no effect on the twin and that it does not handle, in
// a table card, with the unhandled paths of the selected device in the panel.
import { useEffect, useMemo, useState } from "preact/hooks";
import { ApiProblem, getCoverage, getUnhandled } from "../api/client";
import type { TableOut } from "../api/types";
import { Card, Empty, PanelLayout } from "../page/Card";
import { Hatch } from "../page/Hatch";
import { Panel } from "../page/Panel";
import { PageButtons } from "../page/Parts";
import { VirtualRows } from "../page/VirtualRows";
import { type Pages, answerOf, keyForElement, keyPlace, nextPage, pageWords, previousPage, syncPages } from "../tables/model";
import { SIZE, type RowHeight } from "../theme";
import {
  COVERAGE_COLUMNS,
  type CoverageRow,
  type PathsState,
  cellText,
  columnChars,
  coverageKey,
  coverageRow,
  openedDevice,
  pathParts,
  pathsStep,
  readCoverage,
  stepRow,
  writeCoverage,
} from "./model";

/** The page size of the unhandled paths of one device. */
const PATHS_LIMIT = 200;

/** A count of unhandled config: the number, with a hatch square when it is not 0. */
function UnhandledCount(props: { n: string }) {
  if (props.n === "0") return <span class="num">0</span>;
  return (
    <span class="num unhandled">
      <Hatch w={SIZE.hatchSquare} h={SIZE.hatchSquare} />
      <span>{props.n}</span>
    </span>
  );
}

/** The grid columns of the report: each column as wide as its longest text on the page. */
function template(rows: readonly CoverageRow[]): string {
  const chars = columnChars(rows);
  return COVERAGE_COLUMNS.map((c, j) => {
    const mark = c.hatch ? " + var(--hatch-square) + var(--mark-gap)" : "";
    return `calc(${chars[j]!} * 1ch + 2 * var(--cell-pad)${mark})`;
  })
    .concat("1fr")
    .join(" ");
}

function Paths(props: { twin: string; device: string; onClose: () => void; onTables: () => void }) {
  const [st, setSt] = useState<PathsState>(() => ({ want: syncPages(null, null, PATHS_LIMIT), shown: null, problem: null }));
  const [current, setCurrent] = useState<number | null>(null);
  const want = st.want;
  useEffect(() => {
    let live = true;
    getUnhandled(props.twin, props.device, PATHS_LIMIT, want.cursor)
      .then((out) => live && setSt((s) => pathsStep(s, { kind: "done", at: want, out })))
      .catch((e: unknown) => live && setSt((s) => pathsStep(s, { kind: "failed", at: want, problem: e instanceof ApiProblem ? e.detail : String(e) })));
    return () => {
      live = false;
    };
  }, [props.twin, props.device, want]);
  const go = (to: Pages) => {
    setCurrent(null);
    setSt((s) => pathsStep(s, { kind: "go", to }));
  };
  const problem = st.problem;
  const out: TableOut | null = st.shown?.out ?? null;
  // The answer of the page that the view asks for, which gives the next page.
  const asked = st.shown && st.shown.at === want ? st.shown.out : null;
  const col = (n: string) => out?.columns.indexOf(n) ?? -1;
  const paged = !!st.shown && st.shown.out.total > st.shown.out.rows.length;
  return (
    <Panel
      title={<span class="t-value strong">{props.device}</span>}
      label="Unhandled paths"
      onClose={props.onClose}
      class="cov-panel"
      foot={
        <>
          {paged ? (
            <>
              <span class="muted cov-place">{problem ? null : asked ? pageWords(want, asked.rows.length, asked.total) : "loading"}</span>
              <PageButtons
                onPrevious={() => go(previousPage(want, PATHS_LIMIT))}
                onNext={() => asked?.next_cursor && go(nextPage(want, asked.next_cursor, asked.rows.length))}
                previous={want.back.length > 0}
                next={!!asked?.next_cursor}
              />
            </>
          ) : null}
          <button type="button" onClick={props.onTables}>
            Show in Tables
          </button>
        </>
      }
    >
      {problem ? (
        <Empty problem>{problem}</Empty>
      ) : !out ? (
        <Empty>loading</Empty>
      ) : out.rows.length === 0 ? (
        <Empty>no unhandled stanzas</Empty>
      ) : (
        <VirtualRows
          id="cov-path"
          label="Unhandled paths"
          class="cov-paths"
          count={out.rows.length}
          estimate={SIZE.button}
          current={current}
          onCurrent={setCurrent}
          resetKey={want}
          headHeight={SIZE.button}
          head={
            <div class="cov-path t-label">
              <span>path</span>
              <span class="num">stanzas</span>
              <span class="num">lines</span>
            </div>
          }
          row={(i) => {
            const r = out.rows[i]!;
            return (
              <div class="cov-path t-value">
                <span class="unhandled">
                  <Hatch w={SIZE.hatchSquare} h={SIZE.hatchSquare} />
                  <span>
                    {pathParts(String(r[col("path")])).map((part, k) => (
                      <>
                        {k ? <wbr /> : null}
                        {part}
                      </>
                    ))}
                  </span>
                </span>
                <span class="num">{String(r[col("stanzas")])}</span>
                <span class="num">{String(r[col("lines")])}</span>
              </div>
            );
          }}
        />
      )}
    </Panel>
  );
}

export function CoverageView(props: { twin: string; row: RowHeight; search: string; navigate: (search: string) => void }) {
  const { twin, search, navigate } = props;
  const st = readCoverage(search);
  const [pages, setPages] = useState<Pages>(() => syncPages(null, st.cursor, st.limit));
  // The answer and the problem, each with the key of the request that gave it.
  const [answer, setAnswer] = useState<{ key: string; value: TableOut } | null>(null);
  const [refusal, setRefusal] = useState<{ key: string; value: string } | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [open, setOpen] = useState(false);
  const key = coverageKey(twin, st);
  const out = answerOf(answer, key);
  const problem = answerOf(refusal, key);
  const busy = !!twin && !out && !problem;

  useEffect(() => {
    setPages((p) => syncPages(p, st.cursor, st.limit));
  }, [st.cursor, st.limit]);

  useEffect(() => {
    setSelected(null);
    setOpen(false);
    if (!twin) return;
    let live = true;
    getCoverage(twin, st.limit, st.cursor)
      .then((o) => {
        if (!live) return;
        setAnswer({ key, value: o });
        const at = st.device ? o.rows.findIndex((r) => r[o.columns.indexOf("device")] === st.device) : -1;
        setSelected(at >= 0 ? at : null);
        setOpen(at >= 0);
      })
      .catch((e: unknown) => {
        if (!live) return;
        setRefusal({ key, value: e instanceof ApiProblem ? `request refused: ${e.detail}` : String(e) });
      });
    return () => {
      live = false;
    };
  }, [key]);

  const rows: CoverageRow[] = useMemo(() => (out ? out.rows.map((r) => coverageRow(out.columns, r)) : []), [out]);
  const columns = useMemo(() => template(rows), [rows]);

  const go = (cursor: string | null, device: string | null) => {
    const base: Record<string, string> = { view: "coverage" };
    if (twin) base.twin = twin;
    navigate(writeCoverage({ ...st, cursor, device }, base));
  };
  const goNext = () => {
    if (!out?.next_cursor) return;
    setPages(nextPage(pages, out.next_cursor, out.rows.length));
    go(out.next_cursor, null);
  };
  const goPrevious = () => {
    if (!pages.back.length) return;
    const p = previousPage(pages, st.limit);
    setPages(p);
    go(p.cursor, null);
  };

  const select = (i: number) => {
    setOpen(i === selected ? !open : true);
    setSelected(i);
  };

  // The URL holds the device of the opened row of the report on screen.
  const device = out ? openedDevice(rows, selected, open) : null;
  useEffect(() => {
    if (!out) return;
    const next = writeCoverage({ ...st, device }, twin ? { view: "coverage", twin } : { view: "coverage" });
    if (next !== window.location.search) window.history.replaceState(null, "", next);
  }, [out, device]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      if (keyForElement(keyPlace(e.target as HTMLElement | null), e.key)) return;
      const step = stepRow(e.key, selected, rows.length);
      if (step !== null) setSelected(step);
      else if (e.key === "Enter" && selected !== null && !(e.target instanceof HTMLElement && e.target.closest(".vrows"))) select(selected);
      else if (e.key === "n") goNext();
      else if (e.key === "p") goPrevious();
      else return;
      e.preventDefault();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });

  const opened = open && selected !== null ? (rows[selected] ?? null) : null;
  const report = out && out.total > 0;
  const paged = !!out && out.total > out.rows.length;

  return (
    <>
      <PanelLayout
        fill
        panel={
          opened ? (
            <Paths
              key={opened.device}
              twin={twin}
              device={opened.device}
              onClose={() => setOpen(false)}
              onTables={() => navigate(`?view=tables&twin=${encodeURIComponent(twin)}&table=coverage&f.device=${encodeURIComponent(opened.device)}`)}
            />
          ) : null
        }
      >
        <Card
          label="Devices"
          flush
          fill
          foot={
            paged ? (
              <>
                <span class="muted cov-place">{pageWords(pages, out.rows.length, out.total)}</span>
                <PageButtons
                  onFirst={() => go(null, null)}
                  onPrevious={goPrevious}
                  onNext={goNext}
                  first={st.cursor !== null}
                  previous={pages.back.length > 0}
                  next={!!out.next_cursor}
                />
              </>
            ) : undefined
          }
        >
          {busy ? (
            <Empty>loading</Empty>
          ) : problem ? (
            <Empty problem>{problem}</Empty>
          ) : !out ? (
            <Empty>no twin</Empty>
          ) : !report ? (
            <Empty>no coverage report</Empty>
          ) : (
            <div class="cov-table" style={{ "--cov-columns": columns }}>
              <VirtualRows
                id="cov-device"
                label="Devices"
                class="cov-list"
                count={rows.length}
                rowHeight={props.row}
                headHeight={props.row}
                current={selected}
                onCurrent={setSelected}
                onActivate={select}
                resetKey={key}
                head={
                  <div class="cov-row cov-head t-label" aria-hidden="true">
                    {COVERAGE_COLUMNS.map((c) => (
                      <span class={c.right ? "num" : undefined} title={c.title || undefined}>
                        {c.name}
                      </span>
                    ))}
                  </div>
                }
                row={(i) => {
                  const r = rows[i]!;
                  return (
                    <div class="cov-row t-value">
                      {COVERAGE_COLUMNS.map((c) =>
                        c.hatch ? <UnhandledCount n={cellText(r, c)} /> : <span class={c.right ? "num" : undefined}>{cellText(r, c)}</span>,
                      )}
                    </div>
                  );
                }}
              />
            </div>
          )}
        </Card>
      </PanelLayout>
    </>
  );
}
