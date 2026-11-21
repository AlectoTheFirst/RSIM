// The Inventory view: the device groups with their devices, the devices
// that the twin sees and the inventory does not have, the credential
// references, the jump hosts and the routes. Each edit is a write of one
// record of the inventory, and each delete removes one record.
import { useEffect, useMemo, useState } from "preact/hooks";
import { Credentials } from "./Credentials";
import { ApiProblem, allRows, getInventory, getResolvedDevices, getVendors, putDevice, putGroup } from "../api/client";
import { Hatch, HatchMark } from "../page/Hatch";
import { ResultLine } from "../page/Parts";
import { ROW_HEIGHTS, SIZE } from "../theme";
import {
  ARRANGEMENTS,
  type Arrange,
  type CellState,
  type Draft,
  type Facts,
  type Inventory,
  type Problem,
  type ResolvedDevice,
  type SeenRow,
  type Vendors,
  arrange,
  cellState,
  counts,
  deviceCount,
  deviceSsh,
  devicesHave,
  factsByName,
  groupSsh,
  groupTrust,
  lastCycle,
  nameTaken,
  newDeviceBody,
  newDeviceChecked,
  newGroupChecked,
  protocolWord,
  seenRows,
} from "./model";
import { HatchCell, type Write, addKeys, problemOf } from "./parts";
import { AddDevice, AddGroup, type DeviceFields, DeviceDetail, GroupDetail, type GroupFields, GroupSelect, VENDOR_LIST } from "./Records";
import { JumpHosts, Routes } from "./Routes";
import "./inventory.css";

type Adding = "device" | "group" | "credential" | "jump host" | "route" | null;

/** A cell of a setting: a hairline, an override in the parameter colour, a value or a hatch. */
function SettingCell(props: { s: CellState | null; mono?: boolean; none?: string }) {
  const s = props.s;
  if (!s) return <span />;
  if (s.kind === "inherit") return <span class="same" aria-label="from the group" />;
  if (s.kind === "none") return <HatchCell>{props.none ?? "none"}</HatchCell>;
  const cls = [props.mono ? "t-value" : "", s.kind === "override" ? "c-parameter" : ""].filter(Boolean).join(" ");
  return <span class={cls}>{s.text}</span>;
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
  // The opened row: `device:<name>` or `group:<name>`.
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

  /** The write of a new record whose fields pass the checks of the UI. */
  function writeChecked<T extends { name: string }>(records: readonly { name: string }[], c: { ok: true; body: T } | { ok: false; problem: Problem }, put: (b: T) => Promise<number>): Promise<boolean> {
    if (!c.ok) {
      setProblem(c.problem);
      return Promise.resolve(false);
    }
    return writeNew(records, c.body.name, () => put(c.body));
  }

  const toggleOpen = (key: string) => setOpened((o) => (o === key ? null : key));

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
  const empty = !inv.groups.length && !inv.devices.length;
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
        {inv.devices.length ? (
          <span class="group" role="group" aria-label="Arrange by">
            <span class="muted">Arrange by</span>
            {ARRANGEMENTS.map((a) => (
              <button type="button" aria-pressed={a === by} onClick={() => setBy(a)}>
                {a}
              </button>
            ))}
          </span>
        ) : null}
      </ResultLine>
      <main class="body inv-page">
        <div class="inv-sec">Devices</div>
        <div class="inv" role="table" aria-label="Devices">
          {empty ? (
            <div class="inv-empty" role="row">
              <HatchCell>no device group</HatchCell>
            </div>
          ) : (
          <div class="inv-row inv-head" role="row">
            <span />
            <span>device</span>
            <span>address</span>
            <span>vendor</span>
            <span>site</span>
            <span>location</span>
            <span>credential</span>
            <span>route</span>
            <span>SSH</span>
            <span>trust</span>
            <span>last cycle</span>
            <span title="from the twin">serial</span>
          </div>
          )}
          {sections.map((sec) => (
            <>
              {sec.group ? (
                <div
                  class={`inv-row inv-group inv-open${opened === `group:${sec.group.name}` ? " opened" : ""}`}
                  role="row"
                  tabIndex={0}
                  aria-expanded={opened === `group:${sec.group.name}`}
                  onClick={() => toggleOpen(`group:${sec.group!.name}`)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && e.target === e.currentTarget) {
                      e.preventDefault();
                      toggleOpen(`group:${sec.group!.name}`);
                    }
                  }}
                >
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
              {sec.group && opened === `group:${sec.group.name}` ? (
                <GroupDetail key={sec.group.name} g={sec.group} inv={inv} vendors={vendors} write={write} refuse={setProblem} onDeleted={() => setOpened(null)} />
              ) : null}
              {sec.devices.map((d) => (
                <DeviceRows
                  key={d.name}
                  d={d}
                  inv={inv}
                  vendors={vendors}
                  facts={facts.get(d.name)}
                  now={now}
                  underGroup={sec.group !== null}
                  opened={opened === `device:${d.name}`}
                  onOpen={() => toggleOpen(`device:${d.name}`)}
                  write={write}
                  refuse={setProblem}
                  onDeleted={() => setOpened(null)}
                />
              ))}
            </>
          ))}
          {seen.length ? <SeenBand seen={seen} inv={inv} write={write} /> : null}
        </div>
        {adding === "device" ? (
          <AddDevice
            inv={inv}
            vendors={vendors}
            submit={submit}
            onAdd={(f: DeviceFields, d: Draft) => writeChecked(inv.devices, newDeviceChecked(f, d), putDevice)}
            onClose={() => setAdding(null)}
          />
        ) : null}
        {adding === "group" ? (
          <AddGroup
            inv={inv}
            vendors={vendors}
            submit={submit}
            onAdd={(f: GroupFields, d: Draft) => writeChecked(inv.groups, newGroupChecked(f, d), putGroup)}
            onClose={() => setAdding(null)}
          />
        ) : null}
        <div class="actions">
          <button type="button" aria-pressed={adding === "group"} onClick={() => addOrSubmit("group")}>
            Add group
          </button>
          <button
            type="button"
            aria-pressed={adding === "device"}
            disabled={!inv.groups.length}
            title={inv.groups.length ? undefined : "needs a device group"}
            onClick={() => addOrSubmit("device")}
          >
            Add device
          </button>
          {adding === "device" || adding === "group" ? (
            <button type="button" onClick={() => setAdding(null)}>
              Cancel
            </button>
          ) : null}
        </div>
        <div class="inv-tables">
          <Credentials inv={inv} adding={adding === "credential"} onAdding={() => toggleAdd("credential")} onClose={() => setAdding(null)} writeNew={writeNew} write={write} refuse={setProblem} />
          <JumpHosts inv={inv} adding={adding === "jump host"} onAdding={() => toggleAdd("jump host")} onClose={() => setAdding(null)} writeNew={writeNew} write={write} />
          <Routes inv={inv} adding={adding === "route"} onAdding={() => toggleAdd("route")} onClose={() => setAdding(null)} writeNew={writeNew} write={write} />
        </div>
        <datalist id={VENDOR_LIST}>
          {(vendors?.vendors ?? []).map((v) => (
            <option value={v.vendor} />
          ))}
        </datalist>
      </main>
    </>
  );
}

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
  refuse: (p: Problem) => void;
  onDeleted: () => void;
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
      {props.opened ? <DeviceDetail d={d} inv={inv} vendors={vendors} facts={facts} write={props.write} refuse={props.refuse} onDeleted={props.onDeleted} /> : null}
    </>
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

