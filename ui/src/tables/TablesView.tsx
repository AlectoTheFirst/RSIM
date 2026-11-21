// The Tables view: one table of the twin with its filters, its order, its
// pages and its verbs, and the row that opens in place.
import type { JSX } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { ApiProblem, getTable } from "../api/client";
import type { Column, SummarizeOut, TableDef, TableOut, UniqueOut } from "../api/types";
import { HatchMark } from "../page/Hatch";
import { endpointAddresses } from "../page/pick";
import { KeyLine, ResultLine } from "../page/Parts";
import { cliTopology } from "../page/query";
import type { RowHeight } from "../theme";
import { Grid, type GridColumn, PageButtons } from "./Grid";
import {
  type CellText,
  keyForElement,
  keyPlace,
  limitOptions,
  type Pages,
  type TablesState,
  VERBS,
  type Verb,
  alignsRight,
  apiUrl,
  cellText,
  columnWidths,
  defaultBy,
  deviceFunctions,
  filterCellText,
  filterCells,
  filterWords,
  hiddenSelection,
  nextPage,
  nextSort,
  opsOf,
  pageWords,
  prefixColumn,
  previousPage,
  readState,
  isReasonOf,
  reasonColumns,
  SPAN_SEMANTIC,
  setColumnFilters,
  shownColumns,
  sortOf,
  syncPages,
  tableCommand,
  writeState,
} from "./model";

type Body =
  | { verb: "show" | "top" | "lpm"; out: TableOut }
  | { verb: "summarize"; out: SummarizeOut }
  | { verb: "unique"; out: UniqueOut };

/** The rows of the verb `describe`: the columns of the catalog entry. */
function describeRows(def: TableDef): unknown[][] {
  return def.columns.map((c) => [
    c.name,
    c.type,
    c.semantic,
    c.unit ?? null,
    c.refers_to ? `${c.refers_to[0]}.${c.refers_to[1]}` : null,
    def.key.includes(c.name),
    c.description,
  ]);
}

const DESCRIBE_COLUMNS = ["column", "type", "semantic", "unit", "refers_to", "key", "description"];
const SUMMARY_COLUMNS = ["column", "type", "distinct", "nulls", "most frequent"];

function summaryRows(out: SummarizeOut, def: TableDef | null): unknown[][] {
  return out.columns.map((c) => [
    c.column,
    def?.columns.find((x) => x.name === c.column)?.type ?? null,
    c.distinct,
    c.nulls,
    c.top.map(([v, n]) => `${typeof v === "string" ? v : JSON.stringify(v)} (${n})`),
  ]);
}

function FilterCell(props: { col: Column | undefined; name: string; text: string; onApply: (t: string) => void; first: boolean; inputRef: { current: HTMLInputElement | null } }) {
  const [v, setV] = useState(props.text);
  useEffect(() => setV(props.text), [props.text]);
  const ops = props.col ? opsOf(props.col).filter((o) => o !== "=") : [];
  return (
    <span class="cell filter" role="cell">
      <input
        ref={props.first ? props.inputRef : undefined}
        class="t-value"
        aria-label={`filter of ${props.name}`}
        title={ops.length ? `values, comma list · op and value: ${ops.join(", ")} · parts separated by ;` : "values, comma list"}
        value={v}
        spellcheck={false}
        autocomplete="off"
        onInput={(e) => setV(e.currentTarget.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") props.onApply(v);
        }}
        onBlur={() => {
          if (v !== props.text) props.onApply(v);
        }}
      />
    </span>
  );
}

function Detail(props: {
  columns: string[];
  defs: (Column | undefined)[];
  row: readonly unknown[];
  cell: (j: number) => CellText;
  onRefer: (table: string, column: string, value: string) => void;
  onCopy: () => void;
  /** The addresses of an endpoint row, which the Trace view can take as its source or destination. */
  addresses?: string[];
  onUse?: (field: "source.ip" | "destination.ip", address: string) => void;
  /** Opens the functions table of the device of a device row. */
  onFunctions?: () => void;
}) {
  const { columns, defs, row } = props;
  const addresses = props.addresses ?? [];
  const one = addresses.length === 1;
  const spans = columns.flatMap((_, j) => (defs[j]?.semantic === SPAN_SEMANTIC && Array.isArray(row[j]) ? (row[j] as string[]) : []));
  const refers = columns
    .map((c, j) => ({ c, d: defs[j], v: row[j] }))
    .filter((x) => x.d?.refers_to && typeof x.v === "string" && x.v !== "");
  return (
    <>
      <div>
        <div class="t-label">row</div>
        <div class="facts">
          {columns.map((c, j) => {
            if (defs[j]?.semantic === SPAN_SEMANTIC || isReasonOf(columns, c)) return null;
            const t = props.cell(j);
            const v = row[j];
            return (
              <>
                <span class="t-label">{c}</span>
                {!t.known ? (
                  <span>
                    <HatchMark>
                      <span class="t-value">not known: {t.why}</span>
                    </HatchMark>
                  </span>
                ) : Array.isArray(v) ? (
                  <div>
                    {v.map((x) => (
                      <div class="t-value">{typeof x === "string" ? x : JSON.stringify(x)}</div>
                    ))}
                  </div>
                ) : (
                  <span class="t-value">{t.text}</span>
                )}
              </>
            );
          })}
        </div>
      </div>
      <div>
        <div class="t-label">source lines</div>
        {spans.length ? (
          <>
            <div>
              {spans.map((l) => (
                <div class="t-value">{l}</div>
              ))}
            </div>
            <div class="muted">no source text</div>
          </>
        ) : (
          <div class="muted">no source lines</div>
        )}
        <div class="group actions wrap">
          {props.onFunctions ? (
            <button type="button" onClick={props.onFunctions}>
              View functions
            </button>
          ) : null}
          {refers.map((x) => (
            <button type="button" onClick={() => props.onRefer(x.d!.refers_to![0], x.d!.refers_to![1], x.v as string)}>
              Show {x.v as string} in {x.d!.refers_to![0]}
            </button>
          ))}
          {props.onUse
            ? addresses.flatMap((a) => [
                <button type="button" onClick={() => props.onUse!("source.ip", a)}>
                  {one ? "Use as source" : `Use ${a} as source`}
                </button>,
                <button type="button" onClick={() => props.onUse!("destination.ip", a)}>
                  {one ? "Use as destination" : `Use ${a} as destination`}
                </button>,
              ])
            : null}
          <button type="button" onClick={props.onCopy}>
            Copy row as JSON
          </button>
        </div>
      </div>
    </>
  );
}

export function TablesView(props: {
  twin: string;
  row: RowHeight;
  catalog: TableDef[] | null;
  search: string;
  navigate: (search: string) => void;
  /** Opens the Trace view with an address of an endpoint as a field of the query. */
  onUseAddress?: (field: "source.ip" | "destination.ip", address: string) => void;
}) {
  const { twin, catalog, search, navigate } = props;
  const url = readState(search);
  const st: TablesState = { ...url, table: url.table || catalog?.[0]?.name || "" };
  const def = catalog?.find((t) => t.name === st.table) ?? null;
  const [pages, setPages] = useState<Pages>(() => syncPages(null, st.cursor, st.limit));
  // The answer and the request that gave it.
  const [answer, setAnswer] = useState<{ url: string; body: Body } | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [draft, setDraft] = useState({ by: "", count: "", address: "" });
  const firstFilter = useRef<HTMLInputElement | null>(null);

  const request = def ? apiUrl(twin, st, def) : null;

  useEffect(() => {
    setPages((p) => syncPages(p, st.cursor, st.limit));
  }, [st.cursor, st.limit]);

  useEffect(() => {
    setDraft({ by: st.by.join(","), count: String(st.count), address: st.address });
  }, [st.table, st.verb, st.by.join(","), st.count, st.address]);

  useEffect(() => {
    setSelected(null);
    setOpen(false);
    if (!twin || !request || (st.verb === "lpm" && !st.address)) {
      setAnswer(null);
      setProblem(null);
      return;
    }
    let live = true;
    setProblem(null);
    getTable<TableOut | SummarizeOut | UniqueOut>(request)
      .then((out) => {
        if (!live) return;
        setAnswer({ url: request, body: { verb: st.verb, out } as Body });
      })
      .catch((e: unknown) => {
        if (!live) return;
        setAnswer(null);
        setProblem(e instanceof ApiProblem ? `request refused: ${e.detail}` : String(e));
      })
    return () => {
      live = false;
    };
  }, [twin, request]);

  // Only the answer of the current request is drawn; the answer of an
  // earlier request does not fit the columns of the current table.
  const body = answer && answer.url === request ? answer.body : null;
  const busy = !!request && !body && !problem && !(st.verb === "lpm" && !st.address);

  /** Moves to a new state; a change other than the page starts at the first page. */
  function go(next: Partial<TablesState>, keepPage = false) {
    const s = { ...st, ...next };
    if (!keepPage) s.cursor = null;
    const base: Record<string, string> = { view: "tables" };
    if (twin) base.twin = twin;
    navigate(writeState(s, base));
  }

  function copy(text: string, what: string) {
    navigator.clipboard
      .writeText(text)
      .then(() => setNotice(`${what} copied`))
      .catch(() => setNotice(`${what} not copied`));
  }

  // The grid of the body: its columns, rows and cells.
  const grid = useMemo(() => {
    if (st.verb === "describe") {
      if (!def) return null;
      const rows = describeRows(def);
      return { columns: DESCRIBE_COLUMNS, defs: [] as (Column | undefined)[], rows, hairlines: false };
    }
    if (!body) return null;
    if (body.verb === "summarize") {
      return { columns: SUMMARY_COLUMNS, defs: [] as (Column | undefined)[], rows: summaryRows(body.out, def), hairlines: false };
    }
    const out = body.out as TableOut | UniqueOut;
    const defs = out.columns.map((c) => def?.columns.find((x) => x.name === c));
    return { columns: out.columns, defs, rows: out.rows, hairlines: body.verb !== "unique" };
  }, [body, def, st.verb]);

  const reasons = useMemo(() => (grid ? reasonColumns(grid.columns) : []), [grid]);
  const cellOf = (i: number, j: number): CellText => {
    const r = grid!.rows[i]!;
    const k = reasons[j]!;
    return cellText(r[j], grid!.defs[j], k >= 0 ? r[k] : undefined);
  };
  const unknownCells = useMemo(() => {
    if (!grid) return 0;
    let n = 0;
    for (let i = 0; i < grid.rows.length; i++) for (let j = 0; j < grid.columns.length; j++) if (!cellOf(i, j).known) n += 1;
    return n;
  }, [grid]);

  const tableOut = body && (body.verb === "show" || body.verb === "top" || body.verb === "lpm") ? body.out : null;
  const shown = useMemo(() => (grid ? shownColumns(grid.columns, grid.defs, tableOut !== null) : []), [grid, tableOut]);
  const shownRows = useMemo(() => (grid ? grid.rows.map((r) => shown.map((j) => r[j])) : []), [grid, shown]);
  const widths = useMemo(() => (grid ? columnWidths(grid.columns, grid.rows, 4, 48, (i, j) => cellOf(i, j).known) : []), [grid]);
  const sortable = st.verb === "show";
  const gridColumns: GridColumn[] = grid
    ? shown.map((j) => {
        const name = grid.columns[j]!;
        const d = grid.defs[j];
        const s = sortable ? sortOf(st.sort, name) : null;
        const right = d ? alignsRight(d) : name === "distinct" || name === "nulls" || name === "count";
        const head = sortable ? (
          <button
            type="button"
            class="plain head"
            title={`${d?.description ?? ""} · click: sort · shift-click: add to the sort`}
            onClick={(e) => go({ sort: nextSort(st.sort, name, e.shiftKey) })}
          >
            {name}
            {s ? <span class="t-index">{` ${s.dir === "up" ? "rising" : "falling"}${st.sort.length > 1 ? ` ${s.n}` : ""}`}</span> : null}
          </button>
        ) : undefined;
        return { name, width: widths[j]! + (s ? 9 : 0), right, head, title: d?.description };
      })
    : [];

  const filterable = grid && (st.verb === "show" || st.verb === "top" || st.verb === "lpm");
  const filters = filterable
    ? filterCells(grid.columns, grid.defs, shown).map(({ name, col, first }) => (
        <FilterCell
          col={col}
          name={name}
          text={filterCellText(name, st.filters)}
          first={first}
          inputRef={firstFilter}
          onApply={(t) => go({ filters: setColumnFilters(st.filters, name, t) })}
        />
      ))
    : null;

  const hidden = grid ? hiddenSelection(grid.columns, shown, st.filters, st.sort) : { filters: [], sort: [] };

  const next = body?.verb === "show" ? (body.out.next_cursor ?? null) : null;

  const goNext = () => {
    if (!next || !tableOut) return;
    setPages(nextPage(pages, next, tableOut.rows.length));
    go({ cursor: next }, true);
  };
  const goPrevious = () => {
    if (!pages.back.length) return;
    const p = previousPage(pages, st.limit);
    setPages(p);
    go({ cursor: p.cursor }, true);
  };
  const goFirst = () => go({ cursor: null });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const place = keyPlace(t);
      if (keyForElement(place, e.key)) {
        if (place === "text" && e.key === "Escape") t?.blur();
        return;
      }
      const n = grid?.rows.length ?? 0;
      switch (e.key) {
        case "j":
          if (n) setSelected((s) => (s === null ? 0 : Math.min(n - 1, s + 1)));
          break;
        case "k":
          if (n) setSelected((s) => (s === null ? 0 : Math.max(0, s - 1)));
          break;
        case "Enter":
          if (selected === null) return;
          setOpen(!open);
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
        case "/":
          firstFilter.current?.focus();
          break;
        case "y":
          copy(tableCommand(cliTopology(twin), st, def), "rsim command");
          break;
        default:
          return;
      }
      e.preventDefault();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });

  const select = (i: number) => {
    if (i === selected) setOpen(!open);
    else {
      setSelected(i);
      setOpen(true);
    }
  };

  const runParams = (e: Event) => {
    e.preventDefault();
    const by = draft.by
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
    const count = Number(draft.count);
    go({ by, count: Number.isInteger(count) && count > 0 ? count : 5, address: draft.address.trim() });
  };

  const verbs: Verb[] = def ? VERBS.filter((v) => v === "describe" || def.verbs.includes(v)) : [];

  let facts: JSX.Element;
  if (!catalog) facts = <span class="muted">loading catalog</span>;
  else if (!def) facts = <span>not a table: {st.table}</span>;
  else if (busy) facts = <span class="muted">running</span>;
  else if (problem) facts = <span>{problem}</span>;
  else {
    const parts: JSX.Element[] = [<span class="t-headline">{def.name}</span>];
    if (st.verb === "describe") {
      parts.push(<span>{def.description}</span>);
      parts.push(
        <span>
          <span class="t-label">key </span>
          <span class="t-value">{def.key.join(", ")}</span>
        </span>,
      );
      parts.push(<span class="muted">needs {def.needs}</span>);
    } else if (st.verb === "lpm" && !st.address) {
      parts.push(<span class="muted">no address</span>);
      parts.push(<span class="muted">longest prefix match on {prefixColumn(def)}</span>);
    } else if (body?.verb === "show") {
      parts.push(<span>{pageWords(pages, body.out.rows.length, body.out.total)}</span>);
      if (body.out.total === 0) parts.push(<span class="muted">needs {def.needs}</span>);
    } else if (body?.verb === "summarize") {
      parts.push(<span>{body.out.total} rows</span>);
    } else if (body?.verb === "unique") {
      parts.push(<span>{body.out.rows.length} distinct values</span>);
    } else if (body) {
      parts.push(<span>{body.out.rows.length} rows</span>);
    }
    if (st.verb !== "show" && st.verb !== "describe" && st.filters.length && !filterable) {
      parts.push(
        <span>
          <span class="t-label">filters </span>
          <span class="t-value">{filterWords(st.filters)}</span>
        </span>,
      );
    }
    if (filterable && hidden.filters.length) {
      parts.push(
        <span>
          <span class="t-label">hidden filters </span>
          <span class="t-value">{filterWords(hidden.filters)}</span>{" "}
          <button type="button" class="plain" onClick={() => go({ filters: st.filters.filter((f) => !hidden.filters.includes(f)) })}>
            Clear
          </button>
        </span>,
      );
    }
    if (sortable && hidden.sort.length) {
      parts.push(
        <span>
          <span class="t-label">hidden order </span>
          <span class="t-value">{hidden.sort.join(",")}</span>{" "}
          <button type="button" class="plain" onClick={() => go({ sort: st.sort.filter((x) => !hidden.sort.includes(x)) })}>
            Clear
          </button>
        </span>,
      );
    }
    if (unknownCells) parts.push(<HatchMark>{unknownCells} cells not known</HatchMark>);
    facts = <>{parts}</>;
  }

  return (
    <>
      <form class="bar" aria-label="Table" onSubmit={runParams}>
        <label class="field">
          <span class="t-label">table</span>
          <select class="t-value" value={st.table} onChange={(e) => go({ table: e.currentTarget.value, filters: [], sort: [], by: [], verb: st.verb === "lpm" ? "show" : st.verb })}>
            {(catalog ?? []).map((t) => (
              <option value={t.name}>{t.name}</option>
            ))}
          </select>
        </label>
        <span class="group" role="group" aria-label="Verb">
          {verbs.map((v) => (
            <button type="button" aria-pressed={v === st.verb} onClick={() => go({ verb: v })}>
              {v}
            </button>
          ))}
        </span>
        {st.verb === "unique" || st.verb === "top" ? (
          <label class="field">
            <span class="t-label">{st.verb === "unique" ? "columns" : "column"}</span>
            <input
              class="t-query"
              value={draft.by}
              placeholder={defaultBy(def, st.verb).join(",")}
              spellcheck={false}
              autocomplete="off"
              onInput={(e) => setDraft({ ...draft, by: e.currentTarget.value })}
            />
          </label>
        ) : null}
        {st.verb === "top" ? (
          <>
            <label class="field">
              <span class="t-label">count</span>
              <input class="t-query short" value={draft.count} spellcheck={false} onInput={(e) => setDraft({ ...draft, count: e.currentTarget.value })} />
            </label>
            <button type="button" aria-pressed={st.ascending} onClick={() => go({ ascending: !st.ascending })}>
              smallest first
            </button>
          </>
        ) : null}
        {st.verb === "lpm" ? (
          <label class="field">
            <span class="t-label">address</span>
            <input
              class="t-query"
              value={draft.address}
              spellcheck={false}
              autocomplete="off"
              onInput={(e) => setDraft({ ...draft, address: e.currentTarget.value })}
            />
          </label>
        ) : null}
        {st.verb === "unique" || st.verb === "top" || st.verb === "lpm" ? <button type="submit">Run</button> : null}
        <span class="grow" />
        {st.verb === "show" ? (
          <label class="field">
            <span class="t-label">rows per page</span>
            <select class="t-value" value={String(st.limit)} onChange={(e) => go({ limit: Number(e.currentTarget.value) })}>
              {limitOptions(st.limit).map((l) => (
                <option value={String(l)}>{l}</option>
              ))}
            </select>
          </label>
        ) : null}
        <span class="group">
          <button type="button" disabled={!def} onClick={() => copy(tableCommand(cliTopology(twin), st, def), "rsim command")}>
            Copy as rsim command
          </button>
          <button
            type="button"
            disabled={!request}
            onClick={() => request && copy(new URL(request, window.location.href).href, "API URL")}
          >
            Copy API URL
          </button>
        </span>
      </form>
      <ResultLine>
        {facts}
        {st.verb === "show" && body?.verb === "show" ? (
          <PageButtons
            onFirst={goFirst}
            onPrevious={goPrevious}
            onNext={goNext}
            first={st.cursor !== null}
            previous={pages.back.length > 0}
            next={next !== null}
          />
        ) : null}
      </ResultLine>
      <main class="body grid-body">
        {grid ? (
          <Grid
            label={st.table}
            columns={gridColumns}
            rows={shownRows}
            cell={(i, k) => cellOf(i, shown[k]!)}
            h={props.row}
            selected={selected}
            open={open}
            onSelect={select}
            filters={filters}
            hairlines={grid.hairlines}
            detail={
              tableOut
                ? (i) => (
                    <Detail
                      columns={grid.columns}
                      defs={grid.defs}
                      row={grid.rows[i]!}
                      cell={(j) => cellOf(i, j)}
                      addresses={st.table === "endpoints" ? endpointAddresses(grid.columns, grid.rows[i]!) : []}
                      onUse={props.onUseAddress}
                      onFunctions={(() => {
                        const f = st.table === "devices" ? deviceFunctions(grid.columns, grid.rows[i]!) : null;
                        return f ? () => go({ table: "functions", verb: "show", filters: f, sort: [], by: [] }) : undefined;
                      })()}
                      onRefer={(table, column, value) =>
                        go({ table, verb: "show", filters: [{ column, op: "=", value }], sort: [], by: [] })
                      }
                      onCopy={() => {
                        const o: Record<string, unknown> = {};
                        grid.columns.forEach((c, j) => (o[c] = grid.rows[i]![j]));
                        copy(JSON.stringify(o), "row");
                      }}
                    />
                  )
                : undefined
            }
          />
        ) : null}
      </main>
      <KeyLine
        keys={[
          ["j k", "row"],
          ["enter", "open"],
          ["/", "filter"],
          ["n p", "page"],
          ["y", "copy"],
          ...(notice ? ([["", notice]] as [string, string][]) : []),
        ]}
      />
    </>
  );
}
