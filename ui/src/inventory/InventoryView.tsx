// The Inventory view: the parts Devices, Credentials, Routes and Collection
// as tabs. Devices holds the device groups with their devices as virtual
// rows, the devices that the twin sees and the inventory does not have, and
// the panel of the opened device or group. Each write is a write of one
// record of the inventory, and each delete removes one record.
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { ApiProblem, getInventory, getResolvedDevices, getVendors, putDevice, putGroup, tableRows } from "../api/client";
import { Card, Empty, PageHead, PanelLayout } from "../page/Card";
import { HatchMark, HatchText } from "../page/Hatch";
import { Icon } from "../page/Icon";
import { Segmented } from "../page/Segmented";
import { Tabs } from "../page/Tabs";
import { VirtualRows } from "../page/VirtualRows";
import { toast } from "../page/notes";
import { CollectionSettings } from "./Collection";
import { Credentials } from "./Credentials";
import {
  ARRANGEMENTS,
  type Arrange,
  type CellState,
  type Draft,
  type Facts,
  type Inventory,
  type ListRow,
  type Problem,
  type ResolvedDevice,
  type SeenRow,
  type Vendors,
  arrange,
  cellState,
  columnChars,
  deviceCount,
  factNames,
  factsByName,
  lastCycle,
  listRows,
  nameTaken,
  newDeviceChecked,
  newGroupChecked,
  protocolWord,
  sectionText,
  seenChars,
  seenRows,
  settingDefaults,
  sshState,
  sshText,
  storedDevice,
  transportOf,
  trustState,
  trustText,
} from "./model";
import { problemOf } from "./parts";
import { type DeviceFields, DevicePanel, type GroupFields, GroupPanel, NewDevicePanel, NewGroupPanel, VENDOR_LIST } from "./Records";
import { JumpHosts, Routes } from "./Routes";
import "./inventory.css";

type Part = "devices" | "credentials" | "routes" | "collection";

const PARTS: readonly { id: Part; label: string }[] = [
  { id: "devices", label: "Devices" },
  { id: "credentials", label: "Credentials" },
  { id: "routes", label: "Routes" },
  { id: "collection", label: "Collection" },
];

type Adding = "credential" | "jump host" | "route" | null;

/** The record of the panel: a stored device or group, or a new one. */
type Opened = { kind: "device"; name: string } | { kind: "group"; name: string } | { kind: "new device"; name: string } | { kind: "new group" } | null;

/** The most rows that the list of the devices that the twin sees shows before it scrolls. */
const SEEN_ROWS = 5;

/** The rows of one read of the table `neighbours`. */
const SEEN_PAGE = 50;

/** The rows of the table `neighbours` read so far, and the cursor of the next page. */
type SeenTable = { columns: string[]; rows: unknown[][]; cursor: string | null };

const NO_SEEN: SeenTable = { columns: [], rows: [], cursor: null };

/** The time in ms after a scroll before the facts of the rows in view are read. */
const FACTS_WAIT = 120;

/** The columns of the table `devices` that the view reads. */
const FACT_COLUMNS = "device,serial,serial_reason,platform,platform_reason,collected_at,store_device";

/** The most rows of one read of the facts. */
const FACT_LIMIT = 1000;

/**
 * The facts of the named devices from the table `devices` of the twin: the
 * row of each device, and the rows whose store device it is. A name with
 * no row gives null.
 */
async function readFacts(twin: string, names: readonly string[]): Promise<Map<string, Facts | null>> {
  const list = names.join(",");
  const [own, store] = await Promise.all([
    tableRows(twin, "devices", { device: list, columns: FACT_COLUMNS, limit: String(FACT_LIMIT) }),
    tableRows(twin, "devices", { store_device: list, columns: FACT_COLUMNS, limit: String(FACT_LIMIT) }),
  ]);
  const at = (cols: readonly string[]) => FACT_COLUMNS.split(",").map((c) => cols.indexOf(c));
  const pick = (cols: readonly string[], rows: readonly (readonly unknown[])[]) => {
    const idx = at(cols);
    return rows.map((r) => idx.map((i) => (i < 0 ? null : r[i])));
  };
  const facts = factsByName(FACT_COLUMNS.split(","), [...pick(own.columns, own.rows), ...pick(store.columns, store.rows)]);
  return new Map(names.map((n) => [n, facts.get(n) ?? null]));
}

/** A cell of a setting: a hairline, an override in the parameter colour, a value or a hatch. */
function SettingCell(props: { s: CellState; words?: boolean; none?: string }) {
  const s = props.s;
  if (s.kind === "inherit") return <span class="same" aria-label="from the group" />;
  if (s.kind === "none") return <HatchText>{props.none ?? "none"}</HatchText>;
  const cls = [props.words ? "t-label" : "", s.kind === "override" ? "c-parameter" : ""].filter(Boolean).join(" ");
  return <span class={cls}>{s.text}</span>;
}

function HeadRow() {
  return (
    <div class="inv-row inv-head t-label" aria-hidden="true">
      <span />
      <span>device</span>
      <span>address</span>
      <span>vendor</span>
      <span>site</span>
      <span>credential</span>
      <span>route</span>
      <span>SSH</span>
      <span>trust</span>
      <span>last cycle</span>
      <span>serial</span>
      <span />
    </div>
  );
}

function GroupRow(props: { r: Extract<ListRow, { kind: "group" }>; by: Arrange; vendors: Vendors | null; onEdit: (name: string) => void }) {
  const { section: s } = props.r;
  const g = s.group;
  const transport = g ? transportOf(props.vendors, g.vendor) : null;
  return (
    <div class={`inv-row inv-group${props.r.folded ? " folded" : ""}`}>
      <span />
      <span>
        {s.key === null ? <HatchText>{sectionText(s, props.by)}</HatchText> : <span class="strong">{s.key}</span>} <span class="t-label muted">{deviceCount(props.r.count)}</span>
      </span>
      <span />
      <span>{g ? g.vendor : ""}</span>
      <span />
      {g ? g.settings.credential ? <span>{g.settings.credential}</span> : <HatchText>none</HatchText> : <span />}
      {g ? g.settings.route ? <span>{g.settings.route}</span> : <span class="t-label">direct</span> : <span />}
      {transport === "ssh" ? <span>{sshText(g!.settings.ssh_algorithms, g!.settings.ssh_mode)}</span> : <span />}
      {transport === "https" ? <span>{trustText(g!.settings.tls_trust)}</span> : transport === "ssh" ? <HatchText>not known</HatchText> : <span />}
      <span />
      <span />
      {g ? (
        <span class="inv-action">
          <button
            type="button"
            class="ghost"
            aria-label={`Edit ${g.name}`}
            onClick={(e) => {
              e.stopPropagation();
              props.onEdit(g.name);
            }}
          >
            Edit
          </button>
        </span>
      ) : (
        <span />
      )}
    </div>
  );
}

function DeviceRow(props: { d: ResolvedDevice; underGroup: boolean; vendors: Vendors | null; facts: Facts | null | undefined; now: number }) {
  const { d, underGroup, facts } = props;
  const st = d.settings;
  const cycle = facts === undefined ? null : lastCycle(props.vendors, d, facts ?? undefined, props.now);
  const noCollector = lastCycle(props.vendors, d, undefined, props.now).kind === "no collector";
  const transport = transportOf(props.vendors, d.vendor);
  return (
    <div class="inv-row inv-device">
      <span />
      <span>{d.name}</span>
      <span>{d.address}</span>
      {underGroup ? <span class="same" aria-label="from the group" /> : <span>{d.vendor}</span>}
      {d.site ? <span>{d.site}</span> : <HatchText>no site</HatchText>}
      <SettingCell s={cellState(st.credential.value ?? null, st.credential.origin, underGroup)} />
      <SettingCell s={cellState(st.route.value ?? "direct", st.route.origin, underGroup)} words={st.route.value == null} />
      {transport === "ssh" ? <SettingCell s={sshState(st, underGroup)} /> : <span />}
      {transport === "https" ? <SettingCell s={trustState(st, underGroup)} /> : transport === "ssh" ? <HatchText>not known</HatchText> : <span />}
      {noCollector ? (
        <HatchText>no collector</HatchText>
      ) : cycle === null ? (
        <span />
      ) : cycle.kind === "age" ? (
        <span class="t-label">{cycle.text}</span>
      ) : (
        <HatchText>not known</HatchText>
      )}
      {facts === undefined ? <span /> : facts?.serial ? <span>{facts.serial}</span> : <HatchText title={facts?.serialReason ?? undefined}>not known</HatchText>}
      <span />
    </div>
  );
}

function SeenCard(props: { seen: readonly SeenRow[]; row: number; canAdd: boolean; onAdd: (name: string) => void; onMore?: () => void }) {
  const [current, setCurrent] = useState<number | null>(null);
  const shown = Math.min(props.seen.length, SEEN_ROWS);
  const w = useMemo(() => seenChars(props.seen), [props.seen]);
  return (
    <Card title="Neighbours" flush>
      <div
        class="inv-seen"
        style={{
          "--inv-seen-rows": String(shown),
          "--inv-w-neighbour": String(w.name),
          "--inv-w-neighbour-device": String(w.device),
          "--inv-w-port": String(w.port),
        }}
      >
        <VirtualRows
          id="inv-seen"
          label="Neighbours"
          count={props.seen.length}
          rowHeight={props.row}
          current={current}
          onCurrent={setCurrent}
          onActivate={(i) => props.canAdd && props.onAdd(props.seen[i]!.name)}
          class="inv-seen-list"
          onEnd={props.onMore}
          head={
            <div class="inv-row seen inv-head t-label" aria-hidden="true">
              <span />
              <span>neighbour</span>
              <span>protocol</span>
              <span>device</span>
              <span>port</span>
              <span />
            </div>
          }
          headHeight={props.row}
          row={(i) => {
            const s = props.seen[i]!;
            return (
              <div class="inv-row seen">
                <span />
                <span>{s.name}</span>
                <span class="t-label">{protocolWord(s.protocol)}</span>
                <span>{s.device}</span>
                <span>{s.port}</span>
                {props.canAdd ? (
                  <span class="inv-action">
                    <button
                      type="button"
                      class="ghost"
                      aria-label={`Add ${s.name} to a group`}
                      onClick={(e) => {
                        e.stopPropagation();
                        props.onAdd(s.name);
                      }}
                    >
                      Add to a group
                    </button>
                  </span>
                ) : (
                  <span />
                )}
              </div>
            );
          }}
        />
      </div>
    </Card>
  );
}

export function InventoryView(props: { twin: string; row: number }) {
  const [inv, setInv] = useState<Inventory | null>(null);
  const [devices, setDevices] = useState<ResolvedDevice[]>([]);
  const [vendors, setVendors] = useState<Vendors | null>(null);
  const [absent, setAbsent] = useState(false);
  const [loadProblem, setLoadProblem] = useState<Problem | null>(null);
  const [seenTable, setSeenTable] = useState<SeenTable>(NO_SEEN);
  const [part, setPart] = useState<Part>("devices");
  const [by, setBy] = useState<Arrange>("device group");
  const [filter, setFilter] = useState("");
  const [folded, setFolded] = useState<ReadonlySet<string>>(new Set());
  const [current, setCurrent] = useState<number | null>(null);
  const [opened, setOpened] = useState<Opened>(null);
  const [adding, setAdding] = useState<Adding>(null);
  const [now, setNow] = useState(() => Date.now());
  // The facts of each device whose row the list drew: null for no row of the twin.
  const facts = useRef(new Map<string, Facts | null>());
  const [, setFactsVersion] = useState(0);
  const wanted = useRef(new Set<string>());
  const asked = useRef(new Set<string>());
  const timer = useRef<number | null>(null);
  const opener = useRef<HTMLElement | null>(null);
  const twinNow = useRef(props.twin);
  twinNow.current = props.twin;
  const seenGen = useRef(0);
  const seenBusy = useRef(false);

  /** Reads the next page of the table `neighbours`, sorted by the neighbour. */
  function readSeen(cursor: string | null) {
    const twin = twinNow.current;
    if (!twin || seenBusy.current) return;
    const gen = seenGen.current;
    seenBusy.current = true;
    tableRows(twin, "neighbours", { limit: String(SEEN_PAGE), sort: "neighbour", ...(cursor ? { cursor } : {}) })
      .then((t) => {
        if (gen !== seenGen.current) return;
        seenBusy.current = false;
        setSeenTable((x) => ({ columns: t.columns, rows: cursor ? [...x.rows, ...t.rows] : t.rows, cursor: t.next_cursor ?? null }));
      })
      .catch(() => {
        if (gen !== seenGen.current) return;
        seenBusy.current = false;
        setSeenTable((x) => (cursor ? { ...x, cursor: null } : NO_SEEN));
      });
  }

  async function reload() {
    try {
      const [i, d] = await Promise.all([getInventory(), getResolvedDevices()]);
      setInv(i);
      setDevices(d);
      setAbsent(false);
    } catch (e) {
      if (e instanceof ApiProblem && e.code === "no_inventory") setAbsent(true);
      else setLoadProblem(problemOf(e));
    }
  }

  useEffect(() => {
    void reload();
    getVendors()
      .then(setVendors)
      .catch(() => setVendors(null));
  }, []);

  useEffect(() => {
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = null;
    facts.current = new Map();
    asked.current = new Set();
    wanted.current = new Set();
    setFactsVersion((n) => n + 1);
    seenGen.current++;
    seenBusy.current = false;
    setSeenTable(NO_SEEN);
    readSeen(null);
  }, [props.twin]);

  /** Reads the facts of the devices that the last render drew and that no read has asked for. */
  useEffect(() => {
    if (!props.twin || wanted.current.size === 0 || timer.current !== null) return;
    timer.current = window.setTimeout(() => {
      timer.current = null;
      const twin = twinNow.current;
      if (!twin) return;
      const names = factNames(wanted.current).filter((n) => !asked.current.has(n));
      wanted.current = new Set();
      if (!names.length) return;
      for (const n of names) asked.current.add(n);
      readFacts(twin, names)
        .then((m) => {
          if (twin !== twinNow.current) return;
          for (const [n, f] of m) facts.current.set(n, f);
        })
        .catch(() => {
          if (twin !== twinNow.current) return;
          for (const n of names) facts.current.set(n, null);
        })
        .finally(() => {
          setNow(Date.now());
          setFactsVersion((n) => n + 1);
        });
    }, FACTS_WAIT);
  });

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    },
    [],
  );

  /** The facts of a device, or undefined while no read has given them. */
  const factsOf = (name: string): Facts | null | undefined => {
    if (facts.current.has(name)) return facts.current.get(name);
    if (props.twin && !asked.current.has(name)) wanted.current.add(name);
    return props.twin ? undefined : null;
  };

  const refuse = (p: Problem) => toast(p.title);

  /** A write, then the inventory again; a refused write shows the title of its problem. */
  async function write(run: () => Promise<number>): Promise<boolean> {
    try {
      await run();
      await reload();
      return true;
    } catch (e) {
      refuse(problemOf(e));
      return false;
    }
  }

  /** The write of a new record, refused when its name is in use. */
  async function writeNew(records: readonly { name: string }[], name: string, run: () => Promise<number>): Promise<boolean> {
    if (nameTaken(records, name)) {
      toast(`${name.trim()} in use`);
      return false;
    }
    return write(run);
  }

  /** The write of a new record whose fields pass the checks of the UI. */
  function writeChecked<T extends { name: string }>(records: readonly { name: string }[], c: { ok: true; body: T } | { ok: false; problem: Problem }, put: (b: T) => Promise<number>): Promise<boolean> {
    if (!c.ok) {
      refuse(c.problem);
      return Promise.resolve(false);
    }
    return writeNew(records, c.body.name, () => put(c.body));
  }

  const seen: SeenRow[] = useMemo(() => (inv ? seenRows(seenTable.columns, seenTable.rows, inv.devices.map((d) => d.name)) : []), [inv, seenTable]);
  // Reads the next page while the card has fewer rows than SEEN_ROWS.
  useEffect(() => {
    if (inv && seenTable.cursor && seen.length < SEEN_ROWS) readSeen(seenTable.cursor);
  }, [inv, seen, seenTable.cursor]);
  const sections = useMemo(() => (inv ? arrange(inv, devices, by) : []), [inv, devices, by]);
  const defaults = useMemo(() => settingDefaults(devices), [devices]);
  const rows = useMemo(() => listRows(sections, folded, filter), [sections, folded, filter]);
  const chars = useMemo(() => columnChars(sections, by), [sections, by]);

  if (absent) {
    return (
      <Card>
        <HatchMark>no inventory database</HatchMark>
      </Card>
    );
  }
  if (!inv) {
    return loadProblem ? (
      <Card>
        <Empty problem>
          <span title={loadProblem.detail}>{loadProblem.title}</span>
        </Empty>
      </Card>
    ) : null;
  }

  const open = (o: Opened) => {
    const a = document.activeElement;
    opener.current = a instanceof HTMLElement && a !== document.body ? a : document.querySelector<HTMLElement>(".inv-list");
    setOpened(o);
  };
  const close = () => setOpened(null);
  const fold = (key: string) =>
    setFolded((f) => {
      const next = new Set(f);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const activate = (i: number) => {
    const r = rows[i];
    if (!r) return;
    if (r.kind === "group") fold(r.fold);
    else open({ kind: "device", name: r.device.name });
  };

  let panel = null;
  if (opened?.kind === "device") {
    const stored = storedDevice(inv, opened.name);
    const d = devices.find((x) => x.name === opened.name);
    if (stored && d) {
      panel = (
        <DevicePanel
          key={`device:${stored.name}`}
          stored={stored}
          vendor={d.vendor}
          inv={inv}
          vendors={vendors}
          defaults={defaults}
          facts={factsOf(stored.name)}
          write={write}
          refuse={refuse}
          onClose={close}
          returnFocus={opener}
        />
      );
    }
  } else if (opened?.kind === "group") {
    const g = inv.groups.find((x) => x.name === opened.name);
    if (g) panel = <GroupPanel key={`group:${g.name}`} g={g} inv={inv} vendors={vendors} defaults={defaults} write={write} refuse={refuse} onClose={close} returnFocus={opener} />;
  } else if (opened?.kind === "new device") {
    panel = (
      <NewDevicePanel
        key={`new:${opened.name}`}
        inv={inv}
        vendors={vendors}
        defaults={defaults}
        name={opened.name}
        onAdd={(f: DeviceFields, d: Draft) => writeChecked(inv.devices, newDeviceChecked(f, d), putDevice)}
        onClose={close}
        returnFocus={opener}
      />
    );
  } else if (opened?.kind === "new group") {
    panel = <NewGroupPanel inv={inv} vendors={vendors} defaults={defaults} onAdd={(f: GroupFields, d: Draft) => writeChecked(inv.groups, newGroupChecked(f, d), putGroup)} onClose={close} returnFocus={opener} />;
  }

  const toggleAdd = (what: Exclude<Adding, null>) => setAdding((a) => (a === what ? null : what));
  const empty = !inv.groups.length && !inv.devices.length;

  const devicesPart = (
    <PanelLayout fill panel={panel}>
      <Card
        label="Devices"
        flush
        fill
        head={
          <>
            <label class="inv-filter">
              <Icon name="search" />
              <input type="search" aria-label="Filter" placeholder="Filter" value={filter} spellcheck={false} autoComplete="off" onInput={(e) => setFilter(e.currentTarget.value)} />
            </label>
            <span class="inv-grow" />
            {inv.devices.length ? (
              <span class="group">
                <span class="t-label muted">Arrange by</span>
                <Segmented label="Arrange by" value={by} options={ARRANGEMENTS} onChange={setBy} />
              </span>
            ) : null}
          </>
        }
      >
        {empty ? (
          <Empty>no device group</Empty>
        ) : rows.length === 0 ? (
          <Empty>no device</Empty>
        ) : (
          <div
            class="inv-devices"
            style={{
              "--inv-w-device": String(chars.device),
              "--inv-w-address": String(chars.address),
              "--inv-w-vendor": String(chars.vendor),
              "--inv-w-site": String(chars.site),
              "--inv-w-credential": String(chars.credential),
              "--inv-w-route": String(chars.route),
              "--inv-w-ssh": String(chars.ssh),
              "--inv-w-trust": String(chars.trust),
            }}
          >
            <VirtualRows
              id="inv-devices"
              label="Devices"
              count={rows.length}
              rowHeight={props.row}
              current={current !== null && current < rows.length ? current : null}
              onCurrent={setCurrent}
              onActivate={activate}
              head={<HeadRow />}
              headHeight={props.row}
              class="inv-list"
              resetKey={`${by}\n${filter}`}
              row={(i) => {
                const r = rows[i]!;
                if (r.kind === "group") return <GroupRow r={r} by={by} vendors={vendors} onEdit={(name) => open({ kind: "group", name })} />;
                return <DeviceRow d={r.device} underGroup={r.underGroup} vendors={vendors} facts={factsOf(r.device.name)} now={now} />;
              }}
            />
          </div>
        )}
      </Card>
      {seen.length ? <SeenCard
          seen={seen}
          row={props.row}
          canAdd={inv.groups.length > 0}
          onAdd={(name) => open({ kind: "new device", name })}
          onMore={seenTable.cursor ? () => readSeen(seenTable.cursor) : undefined}
        /> : null}
    </PanelLayout>
  );

  return (
    <>
      <PageHead
        tabs={<Tabs label="Inventory parts" tabs={PARTS} current={part} onSelect={setPart} />}
        actions={
          part === "devices" ? (
            <>
              <button type="button" onClick={() => open({ kind: "new group" })}>
                Add group
              </button>
              <button type="button" class="primary" disabled={!inv.groups.length} onClick={() => open({ kind: "new device", name: "" })}>
                <span class="with-icon">
                  <Icon name="add" />
                  Add device
                </span>
              </button>
            </>
          ) : null
        }
      />
      {part === "devices" ? devicesPart : null}
      {part === "credentials" ? (
        <Credentials inv={inv} adding={adding === "credential"} onAdding={() => toggleAdd("credential")} onClose={() => setAdding(null)} writeNew={writeNew} write={write} refuse={refuse} />
      ) : null}
      {part === "routes" ? (
        <>
          <Routes inv={inv} adding={adding === "route"} onAdding={() => toggleAdd("route")} onClose={() => setAdding(null)} writeNew={writeNew} write={write} />
          <JumpHosts inv={inv} adding={adding === "jump host"} onAdding={() => toggleAdd("jump host")} onClose={() => setAdding(null)} writeNew={writeNew} write={write} />
        </>
      ) : null}
      {part === "collection" ? <CollectionSettings inv={inv} write={write} refuse={refuse} /> : null}
      <datalist id={VENDOR_LIST}>
        {(vendors?.vendors ?? []).map((v) => (
          <option value={v.vendor} />
        ))}
      </datalist>
    </>
  );
}
