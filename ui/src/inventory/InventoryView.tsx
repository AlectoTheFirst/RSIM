// The Inventory view: the device groups with their devices, the devices
// that the twin sees and the inventory does not have, the credential
// references and the routes. Each edit is a write of one record of the
// inventory.
import type { ComponentChildren } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { ApiProblem, allRows, getInventory, getResolvedDevices, getVendors, putCredential, putDevice, putGroup, putRoute } from "../api/client";
import { Hatch, HatchMark } from "../page/Hatch";
import { ResultLine } from "../page/Parts";
import { ROW_HEIGHTS, SIZE } from "../theme";
import {
  ARRANGEMENTS,
  type Arrange,
  type CellState,
  type Credential,
  type Facts,
  type Inventory,
  type ResolvedDevice,
  type SeenRow,
  type Vendors,
  arrange,
  cellState,
  counts,
  credentialGroups,
  deviceCount,
  deviceSsh,
  devicesHave,
  factsByName,
  groupSsh,
  groupTrust,
  hops,
  lastCycle,
  moveBody,
  nameTaken,
  newCredentialBody,
  newDeviceBody,
  newGroupBody,
  newRouteBody,
  overrides,
  protocolWord,
  routeCredentials,
  secretFrom,
  seenRows,
  siteBody,
  storedDevice,
  transportOf,
  usedByRoutes,
} from "./model";
import "./inventory.css";

/** A hatch square of a cell and its words. */
function HatchCell(props: { children: ComponentChildren; title?: string }) {
  return (
    <span class="hc" title={props.title}>
      <Hatch w={SIZE.invHatch} h={SIZE.invHatch} />
      <span>{props.children}</span>
    </span>
  );
}

/** A cell of a setting: a hairline, an override in the parameter colour, a value or a hatch. */
function SettingCell(props: { s: CellState | null; mono?: boolean; none?: string }) {
  const s = props.s;
  if (!s) return <span />;
  if (s.kind === "inherit") return <span class="same" aria-label="from the group" />;
  if (s.kind === "none") return <HatchCell>{props.none ?? "none"}</HatchCell>;
  const cls = [props.mono ? "t-value" : "", s.kind === "override" ? "c-parameter" : ""].filter(Boolean).join(" ");
  return <span class={cls}>{s.text}</span>;
}

/** The text of a problem of a write: its title, with its detail as the title of the element. */
interface Problem {
  title: string;
  detail: string;
}

function problemOf(e: unknown): Problem {
  if (e instanceof ApiProblem) return { title: e.title, detail: e.detail };
  const t = String(e instanceof Error ? e.message : e);
  return { title: t, detail: t };
}

/** The keys of an add row: Enter adds, Escape cancels. */
function addKeys(add: () => void, cancel: () => void) {
  return (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      add();
    } else if (e.key === "Escape") {
      e.preventDefault();
      cancel();
    }
  };
}

type Adding = "device" | "group" | "credential" | "route" | null;

/** Runs `add` each time the count `submit` changes after the first render. */
function useSubmit(submit: number, add: () => void) {
  const first = useRef(submit);
  useEffect(() => {
    if (submit !== first.current) add();
  }, [submit]);
}

export function InventoryView(props: { twin: string }) {
  const [inv, setInv] = useState<Inventory | null>(null);
  const [devices, setDevices] = useState<ResolvedDevice[]>([]);
  const [vendors, setVendors] = useState<Vendors | null>(null);
  const [absent, setAbsent] = useState(false);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [facts, setFacts] = useState<Map<string, Facts>>(new Map());
  const [seenTable, setSeenTable] = useState<{ columns: string[]; rows: unknown[][] }>({ columns: [], rows: [] });
  const [now, setNow] = useState(() => Date.now());
  const [by, setBy] = useState<Arrange>("device group");
  const [opened, setOpened] = useState<string | null>(null);
  const [adding, setAdding] = useState<Adding>(null);
  // A count that a press of the button of an open add row raises: the row then adds its record.
  const [submit, setSubmit] = useState(0);

  async function reload() {
    try {
      const [i, d] = await Promise.all([getInventory(), getResolvedDevices()]);
      setInv(i);
      setDevices(d);
      setAbsent(false);
    } catch (e) {
      if (e instanceof ApiProblem && e.code === "no_inventory") setAbsent(true);
      else setProblem(problemOf(e));
    }
  }

  useEffect(() => {
    void reload();
    getVendors()
      .then(setVendors)
      .catch(() => setVendors(null));
  }, []);

  useEffect(() => {
    if (!props.twin) return;
    let live = true;
    allRows(props.twin, "devices")
      .then((t) => {
        if (!live) return;
        setFacts(factsByName(t.columns, t.rows));
        setNow(Date.now());
      })
      .catch(() => live && setFacts(new Map()));
    allRows(props.twin, "neighbours")
      .then((t) => live && setSeenTable(t))
      .catch(() => live && setSeenTable({ columns: [], rows: [] }));
    return () => {
      live = false;
    };
  }, [props.twin]);

  /** The write of a new record, refused when its name is in use. */
  async function writeNew(records: readonly { name: string }[], name: string, run: () => Promise<number>): Promise<boolean> {
    if (nameTaken(records, name)) {
      const n = name.trim();
      setProblem({ title: "name in use", detail: `${n} is in use` });
      return false;
    }
    return write(run);
  }

  /** A write, then the inventory again; a refused write shows the title of its problem. */
  async function write(run: () => Promise<number>): Promise<boolean> {
    try {
      await run();
      setProblem(null);
      await reload();
      return true;
    } catch (e) {
      setProblem(problemOf(e));
      return false;
    }
  }

  const seen: SeenRow[] = useMemo(
    () => (inv ? seenRows(seenTable.columns, seenTable.rows, inv.devices.map((d) => d.name)) : []),
    [inv, seenTable],
  );
  const sections = useMemo(() => (inv ? arrange(inv, devices, by) : []), [inv, devices, by]);

  if (absent) {
    return (
      <ResultLine>
        <span class="t-headline">Inventory</span>
        <HatchMark>no inventory database</HatchMark>
      </ResultLine>
    );
  }
  if (!inv) {
    return (
      <ResultLine>
        <span class="t-headline">Inventory</span>
        {problem ? <span title={problem.detail}>{problem.title}</span> : null}
      </ResultLine>
    );
  }

  const n = counts(inv, vendors, seen);
  const toggleAdd = (what: Exclude<Adding, null>) => setAdding((a) => (a === what ? null : what));
  const addOrSubmit = (what: "device" | "group") => (adding === what ? setSubmit((x) => x + 1) : setAdding(what));
  return (
    <>
      <ResultLine>
        <span>
          <span class="t-headline">Inventory</span> {deviceCount(n.devices)} in {n.groups} {n.groups === 1 ? "group" : "groups"}
        </span>
        {n.noCollector ? <HatchMark>{devicesHave(n.noCollector)} no collector</HatchMark> : null}
        {n.noSite ? <HatchMark>{devicesHave(n.noSite)} no site</HatchMark> : null}
        {n.seen ? <HatchMark>{deviceCount(n.seen)} seen, not in the inventory</HatchMark> : null}
        {problem ? <span title={problem.detail}>{problem.title}</span> : null}
        <span class="grow" />
        <span class="group" role="group" aria-label="Arrange by">
          <span class="muted">Arrange by</span>
          {ARRANGEMENTS.map((a) => (
            <button type="button" aria-pressed={a === by} onClick={() => setBy(a)}>
              {a}
            </button>
          ))}
        </span>
        <span class="group">
          {inv.groups.length ? (
            <button type="button" aria-pressed={adding === "device"} onClick={() => addOrSubmit("device")}>
              Add device
            </button>
          ) : null}
          <button type="button" aria-pressed={adding === "group"} onClick={() => addOrSubmit("group")}>
            Add group
          </button>
        </span>
      </ResultLine>
      <main class="body inv-page">
        <div class="inv" role="table" aria-label="Devices">
          <div class="inv-row inv-head" role="row">
            <span />
            <span>device</span>
            <span>address</span>
            <span>vendor</span>
            <span>site</span>
            <span>location</span>
            <span>credential</span>
            <span>route</span>
            <span>ssh</span>
            <span>trust</span>
            <span>last cycle</span>
            <span>serial, collected</span>
          </div>
          {adding === "device" ? (
            <AddDevice inv={inv} submit={submit} onAdd={(f) => writeNew(inv.devices, f.name, () => putDevice(newDeviceBody(f)))} onClose={() => setAdding(null)} />
          ) : null}
          {adding === "group" ? (
            <AddGroup inv={inv} submit={submit} onAdd={(f) => writeNew(inv.groups, f.name, () => putGroup(newGroupBody(f)))} onClose={() => setAdding(null)} />
          ) : null}
          {sections.map((sec) => (
            <>
              {sec.group ? (
                <div class="inv-row inv-group" role="row">
                  <span />
                  <span class="span2 t-value">
                    {sec.group.name} <span class="muted t-body">{deviceCount(sec.devices.length)}</span>
                  </span>
                  <span class="t-value">{sec.group.vendor}</span>
                  <span />
                  <span />
                  {sec.group.settings.credential ? <span class="t-value">{sec.group.settings.credential}</span> : <HatchCell>none</HatchCell>}
                  {sec.group.settings.route ? <span class="t-value">{sec.group.settings.route}</span> : <span>direct</span>}
                  <span>{groupSsh(vendors, sec.group) ?? ""}</span>
                  <GroupTrustCell t={groupTrust(vendors, sec.group)} />
                  <span />
                  <span />
                </div>
              ) : (
                <div class="inv-row inv-group" role="row">
                  <span />
                  <span class="span2">
                    {sec.key !== null ? <span class="t-value">{sec.key}</span> : <HatchCell>{by === "site" ? "no site" : "none"}</HatchCell>}{" "}
                    <span class="muted">{deviceCount(sec.devices.length)}</span>
                  </span>
                </div>
              )}
              {sec.devices.map((d) => (
                <DeviceRows
                  key={d.name}
                  d={d}
                  inv={inv}
                  vendors={vendors}
                  facts={facts.get(d.name)}
                  now={now}
                  underGroup={sec.group !== null}
                  opened={opened === d.name}
                  onOpen={() => setOpened((o) => (o === d.name ? null : d.name))}
                  write={write}
                />
              ))}
            </>
          ))}
          {seen.length ? <SeenBand seen={seen} inv={inv} write={write} /> : null}
        </div>
        <div class="inv-tables">
          <Credentials inv={inv} adding={adding === "credential"} onAdding={() => toggleAdd("credential")} onClose={() => setAdding(null)} writeNew={writeNew} />
          <Routes inv={inv} adding={adding === "route"} onAdding={() => toggleAdd("route")} onClose={() => setAdding(null)} writeNew={writeNew} />
        </div>
      </main>
    </>
  );
}

type Write = (run: () => Promise<number>) => Promise<boolean>;
type WriteNew = (records: readonly { name: string }[], name: string, run: () => Promise<number>) => Promise<boolean>;

function GroupTrustCell(props: { t: ReturnType<typeof groupTrust> }) {
  if (!props.t) return <span />;
  if (props.t.kind === "not known") return <HatchCell>not known</HatchCell>;
  return <span>{props.t.text}</span>;
}

function DeviceRows(props: {
  d: ResolvedDevice;
  inv: Inventory;
  vendors: Vendors | null;
  facts: Facts | undefined;
  now: number;
  underGroup: boolean;
  opened: boolean;
  onOpen: () => void;
  write: Write;
}) {
  const { d, inv, vendors, facts, underGroup } = props;
  const st = d.settings;
  const cycle = lastCycle(vendors, d, facts, props.now);
  return (
    <>
      <div
        class={`inv-row inv-device${props.opened ? " opened" : ""}`}
        role="row"
        tabIndex={0}
        aria-expanded={props.opened}
        onClick={props.onOpen}
        onKeyDown={(e) => {
          if (e.key === "Enter" && e.target === e.currentTarget) {
            e.preventDefault();
            props.onOpen();
          }
        }}
      >
        <span />
        <span class="t-value">{d.name}</span>
        <span class="t-value">{d.address}</span>
        {underGroup ? <span class="same" aria-label="from the group" /> : <span class="t-value">{d.vendor}</span>}
        {d.site ? <span class="t-value">{d.site}</span> : <HatchCell>no site</HatchCell>}
        <span>{d.location ?? ""}</span>
        <SettingCell s={cellState(st.credential.value ?? null, st.credential.origin, underGroup)} mono />
        <SettingCell s={cellState(st.route.value ?? "direct", st.route.origin, underGroup)} mono={st.route.value != null} />
        <SettingCell s={deviceSsh(vendors, d, underGroup)} />
        {cycle.kind === "no collector" ? <span class="muted">no contact</span> : <HatchCell>not known</HatchCell>}
        {cycle.kind === "age" ? (
          <span>{cycle.text}</span>
        ) : cycle.kind === "no collector" ? (
          <HatchCell>no collector for {cycle.vendor}</HatchCell>
        ) : (
          <HatchCell>not known</HatchCell>
        )}
        {facts?.serial ? (
          <span class="t-value">{facts.serial}</span>
        ) : (
          <HatchCell title={facts?.serialReason ?? undefined}>not known</HatchCell>
        )}
      </div>
      {props.opened ? <Opened d={d} inv={inv} vendors={vendors} facts={facts} write={props.write} /> : null}
    </>
  );
}

function Fact(props: { value: string | null | undefined; reason: string | null | undefined }) {
  return props.value ? (
    <span class="t-value">{props.value}</span>
  ) : (
    <span class="muted" title={props.reason ?? undefined}>
      not known
    </span>
  );
}

function Opened(props: { d: ResolvedDevice; inv: Inventory; vendors: Vendors | null; facts: Facts | undefined; write: Write }) {
  const { d, inv, facts } = props;
  const stored = storedDevice(inv, d.name);
  const [site, setSite] = useState(d.site ?? "");
  const [location, setLocation] = useState(d.location ?? "");
  const [moving, setMoving] = useState(false);
  const pending = useRef(false);
  useEffect(() => {
    setSite(d.site ?? "");
    setLocation(d.location ?? "");
  }, [d.site, d.location]);
  const commit = () => {
    if (pending.current || !stored || (site === (d.site ?? "") && location === (d.location ?? ""))) return;
    pending.current = true;
    void props.write(() => putDevice(siteBody(stored, site, location))).finally(() => {
      pending.current = false;
    });
  };
  const keys = (e: KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      commit();
    } else if (e.key === "Escape") {
      setSite(d.site ?? "");
      setLocation(d.location ?? "");
    }
  };
  const own = overrides(d);
  const ssh = transportOf(props.vendors, d.vendor) === "ssh";
  const others = inv.groups.filter((g) => g.name !== d.group);
  return (
    <div class="inv-detail" role="row">
      <div class="cols">
        <div>
          <div class="head">Asset facts that the collector reads</div>
          <div class="kv">
            <span class="muted">serial</span>
            <Fact value={facts?.serial} reason={facts?.serialReason} />
            <span class="muted">platform</span>
            <Fact value={facts?.platform} reason={facts?.platformReason} />
          </div>
        </div>
        <div>
          <div class="head">Site and location</div>
          <div class="kv">
            <label class="c-parameter" for={`site-${d.name}`}>
              site
            </label>
            <input
              id={`site-${d.name}`}
              class="t-value param site"
              value={site}
              spellcheck={false}
              onInput={(e) => setSite(e.currentTarget.value)}
              onKeyDown={keys}
              onBlur={commit}
            />
            <label class="c-parameter" for={`location-${d.name}`}>
              location
            </label>
            <input
              id={`location-${d.name}`}
              class="param location"
              value={location}
              onInput={(e) => setLocation(e.currentTarget.value)}
              onKeyDown={keys}
              onBlur={commit}
            />
            <span class="muted">from</span>
            <span>entered here</span>
          </div>
        </div>
        <div>
          <div class="head">Overrides of the group</div>
          <div class="kv">
            <span class="muted">overrides</span>
            {own.length ? (
              <span class="t-value c-parameter">{own.join(", ")}</span>
            ) : (
              <span>
                none; {ssh ? "credential, route and ssh" : "credential and route"} come from <span class="t-value">{d.group}</span>
              </span>
            )}
          </div>
          {stored && others.length ? (
            <div class="group actions">
              {moving ? (
                <select
                  class="t-value"
                  aria-label="Group"
                  value=""
                  autoFocus
                  onChange={(e) => {
                    const g = e.currentTarget.value;
                    setMoving(false);
                    if (g) void props.write(() => putDevice(moveBody(stored, g)));
                  }}
                  onBlur={() => setMoving(false)}
                  onKeyDown={(e) => e.key === "Escape" && setMoving(false)}
                >
                  <option value="" />
                  {others.map((g) => (
                    <option value={g.name}>{g.name}</option>
                  ))}
                </select>
              ) : (
                <button type="button" onClick={() => setMoving(true)}>
                  Move to a group
                </button>
              )}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function GroupSelect(props: { inv: Inventory; value: string; onChange: (g: string) => void; onKeyDown?: (e: KeyboardEvent) => void }) {
  return (
    <select class="t-value" aria-label="group" value={props.value} onChange={(e) => props.onChange(e.currentTarget.value)} onKeyDown={props.onKeyDown}>
      {props.inv.groups.map((g) => (
        <option value={g.name}>{g.name}</option>
      ))}
    </select>
  );
}

function AddDevice(props: { inv: Inventory; submit: number; onAdd: (f: Parameters<typeof newDeviceBody>[0]) => Promise<boolean>; onClose: () => void }) {
  const [f, setF] = useState({ name: "", address: "", group: props.inv.groups[0]?.name ?? "", site: "", location: "" });
  const add = () => void props.onAdd(f).then((ok) => ok && props.onClose());
  useSubmit(props.submit, add);
  const keys = addKeys(add, props.onClose);
  const field = (k: "name" | "address" | "site" | "location", label: string, mono = true) => (
    <span class="edit">
      <input
        class={mono ? "t-value" : ""}
        aria-label={label}
        value={f[k]}
        spellcheck={false}
        autoFocus={k === "name"}
        onInput={(e) => setF({ ...f, [k]: e.currentTarget.value })}
        onKeyDown={keys}
      />
    </span>
  );
  return (
    <div class="inv-row" role="row" aria-label="New device">
      <span />
      {field("name", "device")}
      {field("address", "address")}
      <span class="edit">
        <GroupSelect inv={props.inv} value={f.group} onChange={(group) => setF({ ...f, group })} onKeyDown={keys} />
      </span>
      {field("site", "site")}
      {field("location", "location", false)}
    </div>
  );
}

function AddGroup(props: { inv: Inventory; submit: number; onAdd: (f: Parameters<typeof newGroupBody>[0]) => Promise<boolean>; onClose: () => void }) {
  const [f, setF] = useState({ name: "", vendor: "", credential: "", route: "" });
  const add = () => void props.onAdd(f).then((ok) => ok && props.onClose());
  useSubmit(props.submit, add);
  const keys = addKeys(add, props.onClose);
  return (
    <div class="inv-row inv-group" role="row" aria-label="New group">
      <span />
      <span class="span2 edit">
        <input
          class="t-value"
          aria-label="group"
          value={f.name}
          spellcheck={false}
          autoFocus
          onInput={(e) => setF({ ...f, name: e.currentTarget.value })}
          onKeyDown={keys}
        />
      </span>
      <span class="edit">
        <input class="t-value" aria-label="vendor" value={f.vendor} spellcheck={false} onInput={(e) => setF({ ...f, vendor: e.currentTarget.value })} onKeyDown={keys} />
      </span>
      <span />
      <span />
      <span class="edit">
        <select class="t-value" aria-label="credential" value={f.credential} onChange={(e) => setF({ ...f, credential: e.currentTarget.value })} onKeyDown={keys}>
          <option value="">none</option>
          {props.inv.credentials.map((c) => (
            <option value={c.name}>{c.name}</option>
          ))}
        </select>
      </span>
      <span class="edit">
        <select class="t-value" aria-label="route" value={f.route} onChange={(e) => setF({ ...f, route: e.currentTarget.value })} onKeyDown={keys}>
          <option value="">direct</option>
          {props.inv.routes.map((r) => (
            <option value={r.name}>{r.name}</option>
          ))}
        </select>
      </span>
    </div>
  );
}

function SeenBand(props: { seen: readonly SeenRow[]; inv: Inventory; write: Write }) {
  const [adding, setAdding] = useState<string | null>(null);
  const [address, setAddress] = useState("");
  const [chosen, setGroup] = useState("");
  // The chosen group while it is a group of the inventory, else the first group.
  const group = props.inv.groups.some((g) => g.name === chosen) ? chosen : (props.inv.groups[0]?.name ?? "");
  const canAdd = props.inv.groups.length > 0;
  const add = (name: string) =>
    void props
      .write(() => putDevice(newDeviceBody({ name, address, group, site: "", location: "" })))
      .then((ok) => ok && setAdding(null));
  return (
    <>
      <div class="inv-row inv-group inv-band" role="row">
        <span class="inv-band-mark">
          <Hatch w={SIZE.invMark} h={Math.max(...ROW_HEIGHTS)} />
        </span>
        <span class="span-all">Seen by the twin, not in the inventory</span>
      </div>
      {props.seen.map((s) => {
        const on = adding === s.name;
        const keys = addKeys(
          () => add(s.name),
          () => setAdding(null),
        );
        return (
          <div class="inv-row inv-band" role="row">
            <span />
            <span class="t-value">{s.name}</span>
            {on ? (
              <span class="edit">
                <input class="t-value" aria-label="address" value={address} spellcheck={false} autoFocus onInput={(e) => setAddress(e.currentTarget.value)} onKeyDown={keys} />
              </span>
            ) : (
              <span class="muted">not known</span>
            )}
            {on ? (
              <span class="edit">
                <GroupSelect inv={props.inv} value={group} onChange={setGroup} onKeyDown={keys} />
              </span>
            ) : (
              <span class="muted">not known</span>
            )}
            <span class="text">
              {protocolWord(s.protocol)} neighbour of <span class="t-value">{s.device}</span> on <span class="t-value">{s.port}</span>
            </span>
            {canAdd ? (
              <span class="group">
                <button
                  type="button"
                  aria-pressed={on}
                  onClick={() => {
                    if (on) add(s.name);
                    else {
                      setAddress("");
                      setAdding(s.name);
                    }
                  }}
                >
                  Add to a group
                </button>
              </span>
            ) : (
              <span />
            )}
            <span />
          </div>
        );
      })}
    </>
  );
}

function Credentials(props: { inv: Inventory; adding: boolean; onAdding: () => void; onClose: () => void; writeNew: WriteNew }) {
  const { inv } = props;
  const [f, setF] = useState<{ name: string; source: Credential["source"]; key: string }>({ name: "", source: "env", key: "" });
  const add = () =>
    void props.writeNew(inv.credentials, f.name, () => putCredential(newCredentialBody(f))).then((ok) => {
      if (!ok) return;
      setF({ name: "", source: "env", key: "" });
      props.onClose();
    });
  const keys = addKeys(add, props.onClose);
  return (
    <div>
      <div class="inv-sec">
        Credentials <span class="muted">RSIM keeps the reference. The secret stays in its source.</span>
      </div>
      <div class="inv-t cred inv-head" role="row">
        <span>name</span>
        <span>secret from</span>
        <span>device groups</span>
      </div>
      {inv.credentials.map((c) => {
        const groups = credentialGroups(inv, c.name);
        return (
          <div class="inv-t cred" role="row">
            <span class="t-value">{c.name}</span>
            <span>
              {secretFrom(c)} <span class="t-value">{c.key}</span>
            </span>
            {groups.length ? (
              <span class="t-value">{groups.join(", ")}</span>
            ) : usedByRoutes(inv, c.name) ? (
              <span class="muted">routes only</span>
            ) : (
              <span />
            )}
          </div>
        );
      })}
      {props.adding ? (
        <div class="inv-t cred" role="row" aria-label="New credential">
          <span class="edit">
            <input class="t-value" aria-label="name" value={f.name} spellcheck={false} autoFocus onInput={(e) => setF({ ...f, name: e.currentTarget.value })} onKeyDown={keys} />
          </span>
          <span class="group edit">
            <select aria-label="secret from" value={f.source} onChange={(e) => setF({ ...f, source: e.currentTarget.value as Credential["source"] })} onKeyDown={keys}>
              <option value="env">env file</option>
              <option value="env-url">env URL</option>
            </select>
            <input class="t-value" aria-label="key" value={f.key} spellcheck={false} onInput={(e) => setF({ ...f, key: e.currentTarget.value })} onKeyDown={keys} />
          </span>
          <span />
        </div>
      ) : null}
      <div class="actions">
        <button type="button" aria-pressed={props.adding} onClick={() => (props.adding ? add() : props.onAdding())}>
          Add credential
        </button>
      </div>
    </div>
  );
}

function Routes(props: { inv: Inventory; adding: boolean; onAdding: () => void; onClose: () => void; writeNew: WriteNew }) {
  const { inv } = props;
  const empty = { name: "", proxy: "", proxyCredential: "", jumps: [] as string[] };
  const [f, setF] = useState(empty);
  const add = () =>
    void props.writeNew(inv.routes, f.name, () => putRoute(newRouteBody(f))).then((ok) => {
      if (!ok) return;
      setF(empty);
      props.onClose();
    });
  const keys = addKeys(add, props.onClose);
  return (
    <div>
      <div class="inv-sec">
        Routes <span class="muted">A jump host never gets the device credential.</span>
      </div>
      <div class="inv-t route inv-head" role="row">
        <span>name</span>
        <span>hops</span>
        <span>credential</span>
      </div>
      {inv.routes.map((r) => {
        const h = hops(inv, r);
        return (
          <div class="inv-t route" role="row">
            <span class="t-value">{r.name}</span>
            <span>
              {h.length
                ? h.map((x) => (
                    <>
                      {x.words} <span class="t-value">{x.value}</span>
                    </>
                  ))
                : "direct"}
            </span>
            <span class="t-value">{routeCredentials(inv, r).join(", ")}</span>
          </div>
        );
      })}
      {props.adding ? (
        <div class="inv-t route" role="row" aria-label="New route">
          <span class="edit">
            <input class="t-value" aria-label="name" value={f.name} spellcheck={false} autoFocus onInput={(e) => setF({ ...f, name: e.currentTarget.value })} onKeyDown={keys} />
          </span>
          <span class="group edit">
            <input class="t-value" aria-label="proxy" value={f.proxy} spellcheck={false} onInput={(e) => setF({ ...f, proxy: e.currentTarget.value })} onKeyDown={keys} />
            {f.jumps.map((j) => (
              <span class="t-value">{j}</span>
            ))}
            {inv.jump_hosts.length ? (
              <select
                class="t-value"
                aria-label="jump host"
                value=""
                onChange={(e) => {
                  const j = e.currentTarget.value;
                  if (j) setF({ ...f, jumps: [...f.jumps, j] });
                }}
                onKeyDown={keys}
              >
                <option value="" />
                {inv.jump_hosts.map((j) => (
                  <option value={j.name}>{j.name}</option>
                ))}
              </select>
            ) : null}
          </span>
          {f.proxy.trim() ? (
            <span class="edit">
              <select class="t-value" aria-label="credential" value={f.proxyCredential} onChange={(e) => setF({ ...f, proxyCredential: e.currentTarget.value })} onKeyDown={keys}>
                <option value="">none</option>
                {inv.credentials.map((c) => (
                  <option value={c.name}>{c.name}</option>
                ))}
              </select>
            </span>
          ) : (
            <span />
          )}
        </div>
      ) : null}
      <div class="actions">
        <button type="button" aria-pressed={props.adding} onClick={() => (props.adding ? add() : props.onAdding())}>
          Add route
        </button>
      </div>
    </div>
  );
}
