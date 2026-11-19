// The Coverage view: the config lines of each device that the ingestion
// handles, that have no effect on the twin and that it does not handle,
// with the unhandled paths of a device in its opened row.
import { useEffect, useMemo, useState } from "preact/hooks";
import { ApiProblem, getCoverage, getUnhandled } from "../api/client";
import type { TableDef, TableOut } from "../api/types";
import { Hatch, HatchMark } from "../page/Hatch";
import { KeyLine, ResultLine } from "../page/Parts";
import { type Pages, answerOf, keyForElement, keyPlace, nextPage, pageWords, previousPage, syncPages } from "../tables/model";
import { Grid, type GridColumn, PageButtons } from "../tables/Grid";
import { SIZE, type RowHeight } from "../theme";
import {
  COVERAGE_COLUMNS,
  type CoverageRow,
  type PathsState,
  coverageKey,
  coverageRow,
  coverageSums,
  openedDevice,
  pathsStep,
  readCoverage,
  shareText,
  writeCoverage,
} from "./model";

/** The page size of the unhandled paths of one device. */
const PATHS_LIMIT = 200;

/** A count of unhandled config: the number with a hatch square when it is not 0. */
function UnhandledCount(props: { n: number; h: number }) {
  if (!props.n) return <span class="cell num">0</span>;
  const s = props.h - 2 * SIZE.buttonGap;
  return (
    <span class="cell num unhandled" title="functions from these lines: Unknown">
      <Hatch w={s} h={s} />
      <span>{props.n}</span>
    </span>
  );
}

function Paths(props: { twin: string; device: string; onTables: () => void }) {
  const [st, setSt] = useState<PathsState>(() => ({ want: syncPages(null, null, PATHS_LIMIT), shown: null, problem: null }));
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
  const go = (to: Pages) => setSt((s) => pathsStep(s, { kind: "go", to }));
  const problem = st.problem;
  const out = st.shown?.out ?? null;
  // The answer of the page that the view asks for, which gives the next page.
  const current = st.shown && st.shown.at === want ? st.shown.out : null;
  const col = (n: string) => out?.columns.indexOf(n) ?? -1;
  return (
    <>
      <div>
        <div class="t-label">unhandled paths</div>
        {problem ? (
          <div>{problem}</div>
        ) : !out ? (
          <div class="muted">loading</div>
        ) : out.rows.length === 0 ? (
          <div class="muted">no unhandled stanzas</div>
        ) : (
          <table class="paths">
            <thead class="t-label">
              <tr>
                <th>path</th>
                <th class="num">stanzas</th>
                <th class="num">lines</th>
              </tr>
            </thead>
            <tbody class="t-value">
              {out.rows.map((r) => (
                <tr>
                  <td>
                    <span class="unhandled">
                      <Hatch w={SIZE.hatchMark / 2} h={SIZE.hatchMark / 2} />
                      <span>{String(r[col("path")])}</span>
                    </span>
                  </td>
                  <td class="num">{String(r[col("stanzas")])}</td>
                  <td class="num">{String(r[col("lines")])}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {st.shown && st.shown.out.total > st.shown.out.rows.length ? (
          <div class="group actions">
            <span class="muted">{problem ? null : current ? pageWords(want, current.rows.length, current.total) : "loading"}</span>
            <button type="button" disabled={!want.back.length} onClick={() => go(previousPage(want, PATHS_LIMIT))}>
              Previous page
            </button>
            <button
              type="button"
              disabled={!current?.next_cursor}
              onClick={() => current?.next_cursor && go(nextPage(want, current.next_cursor, current.rows.length))}
            >
              Next page
            </button>
          </div>
        ) : null}
      </div>
      <div>
        <div class="t-label">paths</div>
        <p class="note">
          <span class="t-value">*</span> key of the classification table · secrets masked · counts, no line numbers
        </p>
        <div class="group actions">
          <button type="button" onClick={props.onTables}>
            Show in Tables
          </button>
        </div>
      </div>
    </>
  );
}

export function CoverageView(props: {
  twin: string;
  row: RowHeight;
  catalog: TableDef[] | null;
  search: string;
  navigate: (search: string) => void;
}) {
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
  const grid = useMemo(() => rows.map((r) => COVERAGE_COLUMNS.map((c) => (c.name === "unhandled share" ? shareText(r) : r[c.key]))), [rows]);
  const sums = coverageSums(rows);

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
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (keyForElement(keyPlace(e.target as HTMLElement | null), e.key)) return;
      const n = rows.length;
      switch (e.key) {
        case "j":
          if (n) setSelected((s) => (s === null ? 0 : Math.min(n - 1, s + 1)));
          break;
        case "k":
          if (n) setSelected((s) => (s === null ? 0 : Math.max(0, s - 1)));
          break;
        case "Enter":
          if (selected === null) return;
          select(selected);
          break;
        case "Escape":
          setOpen(false);
          break;
        case "n":
          goNext();
          break;
        case "p":
          goPrevious();
          break;
        default:
          return;
      }
      e.preventDefault();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });

  const needs = props.catalog?.find((t) => t.name === "coverage")?.needs;
  const more = !!out && out.total > out.rows.length;
  const onPage = more ? " on this page" : "";

  const columns: GridColumn[] = COVERAGE_COLUMNS.map((c, j) => ({
    name: c.name,
    width: Math.max(c.name.length, ...grid.map((r) => String(r[j] ?? "").length + (c.hatch ? 3 : 0))),
    right: c.right,
    title: c.title,
  }));

  return (
    <>
      <ResultLine>
        {busy ? (
          <span class="muted">loading</span>
        ) : problem ? (
          <span>{problem}</span>
        ) : !out ? (
          <span class="muted">no twin</span>
        ) : out.total === 0 ? (
          <>
            <span class="t-headline">No coverage report</span>
            {needs ? <span class="muted">needs {needs}</span> : null}
          </>
        ) : (
          <>
            <span class="t-headline">{out.total} devices</span>
            <span>{pageWords(pages, out.rows.length, out.total)}</span>
            <span>
              <span class="t-value">{sums.handled}</span> lines handled{onPage}
            </span>
            <span>
              <span class="t-value">{sums.irrelevant}</span> lines known-irrelevant{onPage}
            </span>
            {sums.unhandled ? (
              <HatchMark>
                {sums.unhandled} lines unhandled in {sums.devices} devices{onPage}
              </HatchMark>
            ) : (
              <span>no unhandled lines{onPage}</span>
            )}
            <PageButtons
              onFirst={() => go(null, null)}
              onPrevious={goPrevious}
              onNext={goNext}
              first={st.cursor !== null}
              previous={pages.back.length > 0}
              next={!!out.next_cursor}
            />
          </>
        )}
      </ResultLine>
      <main class="body grid-body">
        {out && out.total > 0 ? (
          <Grid
            label="coverage"
            columns={columns}
            rows={grid}
            cell={(i, j) => ({ known: true, text: String(grid[i]![j] ?? "") })}
            custom={(i, j) => (COVERAGE_COLUMNS[j]!.hatch ? <UnhandledCount n={Number(grid[i]![j])} h={props.row} /> : null)}
            h={props.row}
            selected={selected}
            open={open}
            onSelect={select}
            detail={(i) => (
              <Paths
                key={rows[i]!.device}
                twin={twin}
                device={rows[i]!.device}
                onTables={() => navigate(`?view=tables&twin=${encodeURIComponent(twin)}&table=coverage&f.device=${encodeURIComponent(rows[i]!.device)}`)}
              />
            )}
          />
        ) : null}
      </main>
      <KeyLine
        keys={[
          ["j k", "device"],
          ["enter", "open"],
          ["n p", "page"],
        ]}
      />
    </>
  );
}
