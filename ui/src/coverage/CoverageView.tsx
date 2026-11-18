// The Coverage view: the config lines of each device that the ingestion
// handles, that have no effect on the twin and that it does not handle,
// with the unhandled paths of a device in its opened row.
import { useEffect, useMemo, useState } from "preact/hooks";
import { ApiProblem, getCoverage, getUnhandled } from "../api/client";
import type { TableDef, TableOut } from "../api/types";
import { Hatch, HatchMark } from "../page/Hatch";
import { KeyLine, ResultLine } from "../page/Parts";
import { type Pages, nextPage, pageWords, previousPage, syncPages } from "../tables/model";
import { Grid, type GridColumn, PageButtons } from "../tables/Grid";
import { SIZE, type RowHeight } from "../theme";
import { COVERAGE_COLUMNS, type CoverageRow, coverageRow, coverageSums, readCoverage, shareText, writeCoverage } from "./model";

/** The page size of the unhandled paths of one device. */
const PATHS_LIMIT = 200;

/** A count of unhandled config: the number with a hatch square when it is not 0. */
function UnhandledCount(props: { n: number; h: number }) {
  if (!props.n) return <span class="cell num">0</span>;
  const s = props.h - 2 * SIZE.buttonGap;
  return (
    <span class="cell num unhandled" title="Functions from these lines give Unknown">
      <Hatch w={s} h={s} />
      <span>{props.n}</span>
    </span>
  );
}

function Paths(props: { twin: string; device: string; onTables: () => void }) {
  const [pages, setPages] = useState<Pages>(syncPages(null, null, PATHS_LIMIT));
  const [out, setOut] = useState<TableOut | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    getUnhandled(props.twin, props.device, PATHS_LIMIT, pages.cursor)
      .then((o) => live && setOut(o))
      .catch((e: unknown) => live && setProblem(e instanceof ApiProblem ? e.detail : String(e)));
    return () => {
      live = false;
    };
  }, [props.twin, props.device, pages.cursor]);
  const col = (n: string) => out?.columns.indexOf(n) ?? -1;
  return (
    <>
      <div>
        <div class="t-label">unhandled paths</div>
        {problem ? (
          <div>{problem}</div>
        ) : !out ? (
          <div class="muted">The paths load.</div>
        ) : out.rows.length === 0 ? (
          <div class="muted">The device has no unhandled stanzas.</div>
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
        {out && out.total > out.rows.length ? (
          <div class="group actions">
            <span class="muted">{pageWords(pages, out.rows.length, out.total)}</span>
            <button type="button" disabled={!pages.back.length} onClick={() => setPages(previousPage(pages, PATHS_LIMIT))}>
              Previous page
            </button>
            <button type="button" disabled={!out.next_cursor} onClick={() => out.next_cursor && setPages(nextPage(pages, out.next_cursor, out.rows.length))}>
              Next page
            </button>
          </div>
        ) : null}
      </div>
      <div>
        <div class="t-label">about the report</div>
        <p class="note">
          A path has <span class="t-value">*</span> in place of each key that the classification table matches, and each key goes through the
          mask of the secrets. The report gives the paths and their counts; it has no line numbers.
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
  const [out, setOut] = useState<TableOut | null>(null);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    setPages((p) => syncPages(p, st.cursor, st.limit));
  }, [st.cursor, st.limit]);

  useEffect(() => {
    if (!twin) return;
    let live = true;
    setBusy(true);
    setProblem(null);
    getCoverage(twin, st.limit, st.cursor)
      .then((o) => {
        if (!live) return;
        setOut(o);
        const at = st.device ? o.rows.findIndex((r) => r[o.columns.indexOf("device")] === st.device) : -1;
        setSelected(at >= 0 ? at : null);
        setOpen(at >= 0);
      })
      .catch((e: unknown) => {
        if (!live) return;
        setOut(null);
        setProblem(e instanceof ApiProblem ? `The request is refused: ${e.detail}` : String(e));
      })
      .finally(() => live && setBusy(false));
    return () => {
      live = false;
    };
  }, [twin, st.cursor, st.limit]);

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
    const same = i === selected;
    const nowOpen = same ? !open : true;
    setSelected(i);
    setOpen(nowOpen);
    window.history.replaceState(null, "", writeCoverage({ ...st, device: nowOpen ? rows[i]!.device : null }, twin ? { view: "coverage", twin } : { view: "coverage" }));
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (t && (t.tagName === "INPUT" || t.tagName === "SELECT" || t.tagName === "TEXTAREA")) return;
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
          <span class="muted">The report loads.</span>
        ) : problem ? (
          <span>{problem}</span>
        ) : !out ? (
          <span class="muted">Choose a twin.</span>
        ) : out.total === 0 ? (
          <>
            <span class="t-headline">No coverage report</span>
            {needs ? <span class="muted">The report needs {needs}.</span> : null}
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
