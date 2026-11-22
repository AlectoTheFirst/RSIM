// The Tables view: the table list, the table card with the forms of the
// table, its filters, its order, its columns and its pages, and the row
// panel of the selected row.
import type { JSX } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { ApiProblem, getSourceLines, getTable } from "../api/client";
import type { Column, SummarizeOut, TableDef, TableOut, UniqueOut } from "../api/types";
import { Card, PanelLayout } from "../page/Card";
import { Icon } from "../page/Icon";
import { MenuButton } from "../page/Menu";
import { PageButtons } from "../page/Parts";
import { Chip } from "../page/Pill";
import { Tabs } from "../page/Tabs";
import { toast } from "../page/notes";
import { endpointAddresses } from "../page/pick";
import { cliTopology } from "../page/query";
import { type RowHeight, SIZE } from "../theme";
import { RowPanel } from "./RowPanel";
import { Table, type TableColumn } from "./Table";
import {
  type CellText,
  FORM_LABELS,
  type Pages,
  type TablesState,
  type Verb,
  alignsRight,
  apiUrl,
  cellLabel,
  cellText,
  chipValue,
  columnWidths,
  defaultBy,
  deviceFunctions,
  filterCellText,
  filterColumns,
  formsOf,
  hiddenSelection,
  isFunctionColumn,
  keyForElement,
  keyPlace,
  limitOptions,
  nextPage,
  nextSort,
  pageWords,
  prefixColumn,
  previousPage,
  readState,
  reasonColumns,
  repeats,
  rowTitle,
  rowsForm,
  setColumnFilters,
  sortBy,
  sortOf,
  stepRow,
  syncPages,
  tableCommand,
  toggleHidden,
  visibleColumns,
  withoutFilter,
  writeState,
} from "./model";

type Body =
  | { verb: "show" | "top" | "lpm"; out: TableOut }
  | { verb: "summarize"; out: SummarizeOut }
  | { verb: "unique"; out: UniqueOut };

/** The rows of the form Columns: the columns of the catalog entry. */
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

/** The table list: a search field and the name of each table. */
function TableList(props: { catalog: TableDef[] | null; current: string; onSelect: (name: string) => void }) {
  const [text, setText] = useState("");
  const t = text.trim().toLowerCase();
  const tables = (props.catalog ?? []).filter((d) => !t || d.name.toLowerCase().includes(t));
  return (
    <Card label="Tables" class="table-list">
      <label class="table-search">
        <Icon name="search" />
        <input
          type="search"
          aria-label="Find a table"
          placeholder="Find a table"
          value={text}
          spellcheck={false}
          autocomplete="off"
          onInput={(e) => setText(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && tables[0]) props.onSelect(tables[0].name);
          }}
        />
      </label>
      <nav class="table-names t-value" aria-label="Tables">
        {tables.map((d) => (
          <button
            type="button"
            class="table-name"
            aria-current={d.name === props.current ? "page" : undefined}
            title={d.description}
            onClick={() => props.onSelect(d.name)}
          >
            {d.name}
          </button>
        ))}
      </nav>
    </Card>
  );
}

/** The editor of the filters of one column: the column and the text of its filters. */
function FilterEditor(props: {
  columns: string[];
  column: string;
  text: (column: string) => string;
  onApply: (column: string, text: string) => void;
  onCancel: () => void;
}) {
  const [column, setColumn] = useState(props.column);
  const [value, setValue] = useState(() => props.text(props.column));
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => input.current?.focus(), []);
  const keys = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      props.onCancel();
    }
  };
  return (
    <span class="filter-edit group" role="group" aria-label="Filter" onKeyDown={keys}>
      <select
        class="t-value"
        aria-label="Filter column"
        value={column}
        onChange={(e) => {
          const c = e.currentTarget.value;
          setColumn(c);
          setValue(props.text(c));
        }}
      >
        {props.columns.map((c) => (
          <option value={c}>{c}</option>
        ))}
      </select>
      <input
        ref={input}
        class="t-value"
        aria-label="Filter values"
        value={value}
        spellcheck={false}
        autocomplete="off"
        onInput={(e) => setValue(e.currentTarget.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            props.onApply(column, value);
          }
        }}
      />
      <button type="button" class="primary" onClick={() => props.onApply(column, value)}>
        Apply
      </button>
      <button type="button" onClick={props.onCancel}>
        Cancel
      </button>
    </span>
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
  const [draft, setDraft] = useState({ by: "", count: "", address: "" });
  // The column of the open filter editor, and the control that opened it.
  const [editing, setEditing] = useState<string | null>(null);
  const editOpener = useRef<HTMLElement | null>(null);
  const rowsRef = useRef<HTMLElement | null>(null);

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
      });
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

  const openTable = (table: string, filters: TablesState["filters"] = []) =>
    go({ table, verb: "show", filters, sort: [], by: [], hide: [] });

  function copy(text: string, what: string) {
    navigator.clipboard
      .writeText(text)
      .then(() => toast(`${what} copied`))
      .catch(() => toast(`${what} not copied`));
  }

  // The grid of the form: its columns, rows and cells.
  const grid = useMemo(() => {
    if (st.verb === "describe") {
      if (!def) return null;
      return { columns: DESCRIBE_COLUMNS, defs: [] as (Column | undefined)[], rows: describeRows(def), hairlines: false };
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
  const labelOf = (i: number, j: number): string => cellLabel(cellOf(i, j), grid!.defs[j], grid!.rows[i]![j]);

  const tableOut = body && rowsForm(body.verb) ? (body.out as TableOut) : null;
  const tableColumns = tableOut !== null;
  const shown = useMemo(
    () => (grid ? (tableColumns ? visibleColumns(grid.columns, st.hide) : grid.columns.map((_, j) => j)) : []),
    [grid, tableColumns, st.hide.join(",")],
  );
  const shownRows = useMemo(() => (grid ? grid.rows.map((r) => shown.map((j) => r[j])) : []), [grid, shown]);
  const same = useMemo(() => (grid?.hairlines ? repeats(shownRows) : null), [grid, shownRows]);
  const widths = useMemo(
    () => (grid ? columnWidths(grid.columns, grid.rows, 4, 48, (i, j) => cellOf(i, j).known, labelOf) : []),
    [grid],
  );
  const sortable = st.verb === "show";
  const filterable = st.verb !== "describe" && !!def;
  const names = filterColumns(def);

  function startFilter(column: string) {
    editOpener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setEditing(column);
  }
  function endFilter() {
    setEditing(null);
    const to = editOpener.current;
    if (to && to.isConnected) to.focus();
  }

  const columns: TableColumn[] = grid
    ? shown.map((j) => {
        const name = grid.columns[j]!;
        const d = grid.defs[j];
        const s = sortable ? sortOf(st.sort, name) : null;
        const right = d ? alignsRight(d) : name === "distinct" || name === "nulls" || name === "count";
        const fn = isFunctionColumn(d);
        const extra = tableColumns && d ? " + var(--chip-button) + var(--button-gap)" : "";
        const ch = `calc(${widths[j]! + (s ? 10 : 0)}ch + 2 * var(--cell-pad)${extra})`;
        const track = fn ? `min(${ch}, var(--col-function-max))` : ch;
        const menu =
          tableColumns && d ? (
            <MenuButton kind="menu" label={`Column menu of ${name}`} button={<Icon name="column-menu" size={SIZE.iconSmall} />} buttonLabel={`Column menu of ${name}`} buttonClass="icon small" align="start">
              {(close) => (
                <>
                  {sortable ? (
                    <>
                      <button type="button" class="menu-item" role="menuitem" tabIndex={-1} onClick={() => (close(), go({ sort: sortBy(st.sort, name, "up") }))}>
                        Sort rising
                      </button>
                      <button type="button" class="menu-item" role="menuitem" tabIndex={-1} onClick={() => (close(), go({ sort: sortBy(st.sort, name, "down") }))}>
                        Sort falling
                      </button>
                      {s ? (
                        <button type="button" class="menu-item" role="menuitem" tabIndex={-1} onClick={() => (close(), go({ sort: sortBy(st.sort, name, null) }))}>
                          Remove from sort
                        </button>
                      ) : null}
                    </>
                  ) : null}
                  {names.includes(name) ? (
                    <button type="button" class="menu-item" role="menuitem" tabIndex={-1} onClick={() => (close(), startFilter(name))}>
                      Filter
                    </button>
                  ) : null}
                  <button type="button" class="menu-item" role="menuitem" tabIndex={-1} onClick={() => (close(), go({ hide: toggleHidden(st.hide, name) }, true))}>
                    Hide
                  </button>
                </>
              )}
            </MenuButton>
          ) : null;
        const head = (
          <>
            {sortable ? (
              <button type="button" class="plain head" title={d?.description} onClick={(e) => go({ sort: nextSort(st.sort, name, e.shiftKey) })}>
                {name}
                {s ? <span class="sort-word t-index">{`${s.dir === "up" ? "rising" : "falling"}${st.sort.length > 1 ? ` ${s.n}` : ""}`}</span> : null}
              </button>
            ) : (
              <span class="head" title={d?.description}>
                {name}
              </span>
            )}
            {menu}
          </>
        );
        return { name, track, right, functionName: fn, head };
      })
    : [];

  const hidden = grid && tableColumns ? hiddenSelection(grid.columns, shown, [], st.sort) : { filters: [], sort: [] };
  const next = body?.verb === "show" ? (body.out.next_cursor ?? null) : null;
  const count = grid?.rows.length ?? 0;
  const opened = open && tableOut && selected !== null && selected < count ? selected : null;

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
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      const t = e.target as HTMLElement | null;
      if (keyForElement(keyPlace(t), e.key)) return;
      switch (e.key) {
        case "j":
          if (count) setSelected((s) => (s === null ? 0 : Math.min(count - 1, s + 1)));
          break;
        case "k":
          if (count) setSelected((s) => (s === null ? 0 : Math.max(0, s - 1)));
          break;
        case "Enter":
          if (selected === null || !tableOut) return;
          setOpen(!open);
          break;
        case "n":
          goNext();
          break;
        case "p":
          goPrevious();
          break;
        case "/":
          if (!filterable || !names.length) return;
          startFilter(editing ?? names[0]!);
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

  const runParams = (e: Event) => {
    e.preventDefault();
    const by = draft.by
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
    const n = Number(draft.count);
    go({ by, count: Number.isInteger(n) && n > 0 ? n : 5, address: draft.address.trim() });
  };

  const forms: Verb[] = formsOf(def);

  let facts: JSX.Element;
  if (!catalog) facts = <span class="muted">loading catalog</span>;
  else if (!def) facts = <span>not a table: {st.table}</span>;
  else if (busy) facts = <span class="muted">running</span>;
  else if (problem) facts = <span>{problem}</span>;
  else {
    const parts: JSX.Element[] = [];
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
    } else if (body?.verb === "show") {
      parts.push(<span>{pageWords(pages, body.out.rows.length, body.out.total)}</span>);
    } else if (body?.verb === "summarize") {
      parts.push(<span>{body.out.total} rows</span>);
    } else if (body?.verb === "unique") {
      parts.push(<span>{body.out.rows.length} distinct values</span>);
    } else if (body) {
      parts.push(<span>{body.out.rows.length} rows</span>);
    }
    facts = <>{parts}</>;
  }

  const params =
    st.verb === "unique" || st.verb === "top" || st.verb === "lpm" ? (
      <form class="bar table-params" aria-label="Parameters" onSubmit={runParams}>
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
          <>
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
            <span class="field">
              <span class="t-label">column</span>
              <span class="t-value">{prefixColumn(def)}</span>
            </span>
          </>
        ) : null}
        <button type="submit">Run</button>
      </form>
    ) : null;

  const tools = filterable ? (
    <div class="table-tools">
      <span class="group wrap">
        {st.filters.map((f) => (
          <Chip column={f.column} value={chipValue(f)} onRemove={() => go({ filters: withoutFilter(st.filters, f) })} />
        ))}
        {editing !== null ? (
          <FilterEditor
            columns={names}
            column={editing}
            text={(c) => filterCellText(c, st.filters)}
            onApply={(c, t) => {
              endFilter();
              go({ filters: setColumnFilters(st.filters, c, t) });
            }}
            onCancel={endFilter}
          />
        ) : (
          <button type="button" class="ghost" disabled={!names.length} onClick={() => startFilter(names[0]!)}>
            <span class="with-icon">
              <Icon name="add" />
              Add filter
            </span>
          </button>
        )}
      </span>
      <span class="grow" />
      {hidden.sort.length ? (
        <span class="field">
          <span class="t-label">hidden order</span>
          <span class="t-value">{hidden.sort.join(",")}</span>
          <button type="button" class="ghost" onClick={() => go({ sort: st.sort.filter((x) => !hidden.sort.includes(x)) })}>
            Clear
          </button>
        </span>
      ) : null}
      {tableColumns && grid ? (
        <MenuButton kind="menu" label="Show columns" button="Show columns" align="end">
          {() =>
            visibleColumns(grid.columns, []).map((j) => {
              const name = grid.columns[j]!;
              const on = !st.hide.includes(name);
              return (
                <button
                  type="button"
                  class="menu-item"
                  role="menuitemcheckbox"
                  aria-checked={on}
                  tabIndex={-1}
                  onClick={() => go({ hide: toggleHidden(st.hide, name) }, true)}
                >
                  {name}
                </button>
              );
            })
          }
        </MenuButton>
      ) : null}
    </div>
  ) : null;

  const foot = (
    <>
      <span class="table-facts">{facts}</span>
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
      {st.verb === "show" && body?.verb === "show" ? (
        <PageButtons onFirst={goFirst} onPrevious={goPrevious} onNext={goNext} first={st.cursor !== null} previous={pages.back.length > 0} next={next !== null} />
      ) : null}
    </>
  );

  let panel: JSX.Element | null = null;
  if (opened !== null && grid && tableOut) {
    const row = grid.rows[opened]!;
    const device = st.table === "devices" ? deviceFunctions(grid.columns, row) : null;
    const addresses = st.table === "endpoints" ? endpointAddresses(grid.columns, row) : [];
    const one = addresses.length === 1;
    const refers = grid.columns
      .map((c, j) => ({ c, d: grid.defs[j], v: row[j] }))
      .filter((x) => x.d?.refers_to && typeof x.v === "string" && x.v !== "");
    const prev = stepRow(opened, -1, count);
    const after = stepRow(opened, 1, count);
    panel = (
      <RowPanel
        title={rowTitle(def, grid.columns, row)}
        columns={grid.columns}
        defs={grid.defs}
        row={row}
        cell={(j) => cellOf(opened, j)}
        onClose={() => setOpen(false)}
        onPrevious={prev === null ? null : () => setSelected(prev)}
        onNext={after === null ? null : () => setSelected(after)}
        load={(s) => getSourceLines(twin, s)}
        returnFocus={rowsRef}
        actions={
          <>
            {device ? (
              <button type="button" onClick={() => openTable("functions", device)}>
                View functions
              </button>
            ) : null}
            {refers.map((x) => (
              <button type="button" onClick={() => openTable(x.d!.refers_to![0], [{ column: x.d!.refers_to![1], op: "=", value: x.v as string }])}>
                Show {x.v as string} in {x.d!.refers_to![0]}
              </button>
            ))}
            {props.onUseAddress
              ? addresses.flatMap((a) => [
                  <button type="button" onClick={() => props.onUseAddress!("source.ip", a)}>
                    {one ? "Use as source" : `Use ${a} as source`}
                  </button>,
                  <button type="button" onClick={() => props.onUseAddress!("destination.ip", a)}>
                    {one ? "Use as destination" : `Use ${a} as destination`}
                  </button>,
                ])
              : null}
            <button
              type="button"
              onClick={() => {
                const o: Record<string, unknown> = {};
                grid.columns.forEach((c, j) => (o[c] = row[j]));
                copy(JSON.stringify(o), "row");
              }}
            >
              <span class="with-icon">
                <Icon name="copy" />
                Copy row as JSON
              </span>
            </button>
          </>
        }
      />
    );
  }

  return (
    <>
      <div class="tables-layout">
        <TableList catalog={catalog} current={st.table} onSelect={(t) => t !== st.table && go({ table: t, filters: [], sort: [], by: [], hide: [], verb: st.verb === "lpm" ? "show" : st.verb })} />
        <PanelLayout fill panel={panel}>
          <Card label={st.table || "Table"} flush fill foot={foot} class="table-card">
            <div class="table-bars">
              {forms.length ? (
                <div class="table-tabs">
                  <Tabs<Verb> label="Form" tabs={forms.map((v) => ({ id: v, label: FORM_LABELS[v] }))} current={st.verb} onSelect={(v) => go({ verb: v })} />
                </div>
              ) : null}
              {tools}
              <span class="grow" />
              <MenuButton
                kind="menu"
                label="Copy"
                buttonClass="ghost"
                button={
                  <span class="with-icon">
                    <Icon name="copy" />
                    Copy
                  </span>
                }
                align="end"
              >
                {(close) => (
                  <>
                    <button
                      type="button"
                      class="menu-item"
                      role="menuitem"
                      tabIndex={-1}
                      disabled={!def}
                      onClick={() => {
                        close();
                        copy(tableCommand(cliTopology(twin), st, def), "rsim command");
                      }}
                    >
                      rsim command
                    </button>
                    <button
                      type="button"
                      class="menu-item"
                      role="menuitem"
                      tabIndex={-1}
                      disabled={!request}
                      onClick={() => {
                        close();
                        if (request) copy(new URL(request, window.location.href).href, "API URL");
                      }}
                    >
                      API URL
                    </button>
                  </>
                )}
              </MenuButton>
            </div>
            {params}
            {grid ? (
              <span class="table-rows" ref={(el) => {
                  rowsRef.current = el?.querySelector<HTMLElement>(".tgrid-rows") ?? null;
                }}>
                <Table
                  id="table-row"
                  label={st.table}
                  columns={columns}
                  count={count}
                  cell={(i, k) => {
                    const j = shown[k]!;
                    const text = labelOf(i, j);
                    return { c: cellOf(i, j), text, title: text !== cellOf(i, j).text ? cellOf(i, j).text : undefined };
                  }}
                  same={(i, k) => !!same && k < same[i]!}
                  rowHeight={props.row}
                  current={selected}
                  onCurrent={setSelected}
                  onActivate={
                    tableOut
                      ? (i) => {
                          setSelected(i);
                          setOpen(true);
                        }
                      : undefined
                  }
                  resetKey={grid}
                />
              </span>
            ) : null}
          </Card>
        </PanelLayout>
      </div>
    </>
  );
}
