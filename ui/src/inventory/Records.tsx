// The panels of a device and of a group: each field of the record and each
// setting, with "Save", "Cancel", "Collect now" and the delete; and the panels of a new
// device and a new group.
import { useState } from "preact/hooks";
import { collectDevice, collectGroup, deleteDevice, deleteGroup, putDevice, putGroup } from "../api/client";
import { toast } from "../page/notes";
import { HatchText } from "../page/Hatch";
import { Panel } from "../page/Panel";
import {
  type Device,
  type Draft,
  type Facts,
  type Group,
  type Inventory,
  type Problem,
  type SettingDefaults,
  type Vendors,
  deviceBody,
  deviceDraft,
  groupBody,
  groupDraft,
  newDeviceBody,
  newGroupBody,
  sameRecord,
} from "./model";
import { DeleteButton, type Refuse, type Write, problemOf, useDraft } from "./parts";
import { type FieldHandlers, PickField, SettingsEditor, TextField } from "./SettingsEditor";

/** The element that takes the focus when a panel closes. */
type Focus = { current: HTMLElement | null };

/** The id of the list of the vendors with a collector, for the vendor field of a group. */
export const VENDOR_LIST = "inv-vendors";

/** The handlers of the fields of a panel: each field changes the draft, Enter saves, Escape in a field reverts it. */
function panelHandlers(set: (k: string, v: string) => void, save: () => void, revert: (k: string) => void): FieldHandlers {
  return {
    onInput: set,
    onPick: set,
    keys: (k) => (e: KeyboardEvent) => {
      if (e.key === "Enter" && !(e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault();
        save();
      } else if (e.key === "Escape") {
        e.preventDefault();
        revert(k);
      }
    },
  };
}

/** The write of the body of a panel, or the problem of its check. */
function saveBody<T>(c: { ok: true; body: T } | { ok: false; problem: Problem }, stored: T, put: (b: T) => Promise<number>, write: Write, refuse: Refuse): void {
  if (!c.ok) {
    refuse(c.problem);
    return;
  }
  if (sameRecord(c.body, stored)) return;
  void write(() => put(c.body));
}

/** The button that requests a collection of a device or of the devices of a group now. */
function CollectButton(props: { run: () => Promise<string[]>; refuse: Refuse }) {
  const [busy, setBusy] = useState(false);
  const press = () => {
    setBusy(true);
    props
      .run()
      .then((devices) => toast(devices.length ? `collection requested for ${devices.join(", ")}` : "no device to collect"))
      .catch((e) => props.refuse(problemOf(e)))
      .finally(() => setBusy(false));
  };
  return (
    <button type="button" onClick={press} disabled={busy}>
      Collect now
    </button>
  );
}

function Fact(props: { label: string; value: string | null | undefined; reason: string | null | undefined }) {
  return (
    <>
      <span class="t-label muted">{props.label}</span>
      {props.value ? <span class="t-value">{props.value}</span> : <HatchText title={props.reason ?? undefined}>not known</HatchText>}
    </>
  );
}

/** The panel of a stored device. */
export function DevicePanel(props: {
  stored: Device;
  vendor: string;
  inv: Inventory;
  vendors: Vendors | null;
  defaults: SettingDefaults;
  facts: Facts | null | undefined;
  write: Write;
  refuse: Refuse;
  onClose: () => void;
  returnFocus?: Focus;
}) {
  const { stored, inv } = props;
  const [draft, set, revert, reset] = useDraft(deviceDraft(stored));
  const save = () => saveBody(deviceBody(stored, draft), stored, putDevice, props.write, props.refuse);
  const h = panelHandlers((k, v) => void set(k, v), save, revert);
  const id = `dev-${stored.name}`;
  const group = inv.groups.find((g) => g.name === draft.group) ?? null;
  const vendor = group?.vendor ?? props.vendor;
  return (
    <Panel
      title={<span class="t-value strong">{stored.name}</span>}
      label={`Device ${stored.name}`}
      onClose={props.onClose}
      returnFocus={props.returnFocus}
      foot={
        <>
          <button type="button" class="primary" onClick={save}>
            Save
          </button>
          <button
            type="button"
            onClick={() => {
              reset();
              props.onClose();
            }}
          >
            Cancel
          </button>
          <CollectButton run={() => collectDevice(stored.name)} refuse={props.refuse} />
          <span class="inv-grow" />
          <DeleteButton
            name={stored.name}
            named
            onDelete={() =>
              props.write(() => deleteDevice(stored.name)).then((ok) => {
                if (ok) props.onClose();
                return ok;
              })
            }
          />
        </>
      }
    >
      <div class="inv-fields">
        <TextField id={id} k="address" label="address" draft={draft} h={h} />
        <PickField id={id} k="group" label="device group" draft={draft} h={h} options={inv.groups.map((g) => ({ value: g.name, text: g.name }))} />
        <TextField id={id} k="site" label="site" draft={draft} h={h} />
        <TextField id={id} k="location" label="location" draft={draft} h={h} mono={false} />
        <TextField id={id} k="console_site" label="console site" draft={draft} h={h} />
      </div>
      <div class="inv-part">
        <span class="t-section">Asset facts</span>
        <div class="inv-facts">
          <Fact label="serial" value={props.facts?.serial} reason={props.facts?.serialReason} />
          <Fact label="platform" value={props.facts?.platform} reason={props.facts?.platformReason} />
        </div>
      </div>
      <div class="inv-part">
        <span class="t-section">Settings</span>
        <SettingsEditor id={id} inv={inv} draft={draft} group={group?.settings ?? null} defaults={props.defaults} own="device" vendor={vendor} vendors={props.vendors} h={h} />
      </div>
    </Panel>
  );
}

/** The panel of a stored group. */
export function GroupPanel(props: { g: Group; inv: Inventory; vendors: Vendors | null; defaults: SettingDefaults; write: Write; refuse: Refuse; onClose: () => void; returnFocus?: Focus }) {
  const { g, inv } = props;
  const [draft, set, revert, reset] = useDraft(groupDraft(g));
  const save = () => saveBody(groupBody(g, draft), g, putGroup, props.write, props.refuse);
  const h = panelHandlers((k, v) => void set(k, v), save, revert);
  const id = `grp-${g.name}`;
  return (
    <Panel
      title={<span class="t-value strong">{g.name}</span>}
      label={`Device group ${g.name}`}
      onClose={props.onClose}
      returnFocus={props.returnFocus}
      foot={
        <>
          <button type="button" class="primary" onClick={save}>
            Save
          </button>
          <button
            type="button"
            onClick={() => {
              reset();
              props.onClose();
            }}
          >
            Cancel
          </button>
          <CollectButton run={() => collectGroup(g.name)} refuse={props.refuse} />
          <span class="inv-grow" />
          <DeleteButton
            name={g.name}
            named
            onDelete={() =>
              props.write(() => deleteGroup(g.name)).then((ok) => {
                if (ok) props.onClose();
                return ok;
              })
            }
          />
        </>
      }
    >
      <div class="inv-fields">
        <TextField id={id} k="vendor" label="vendor" draft={draft} h={h} list={VENDOR_LIST} />
        <TextField id={id} k="description" label="description" draft={draft} h={h} mono={false} />
      </div>
      <div class="inv-part">
        <span class="t-section">Settings</span>
        <SettingsEditor id={id} inv={inv} draft={draft} group={null} defaults={props.defaults} own="group" vendor={(draft.vendor ?? g.vendor).trim()} vendors={props.vendors} h={h} />
      </div>
    </Panel>
  );
}

export type DeviceFields = Parameters<typeof newDeviceBody>[0];
export type GroupFields = Parameters<typeof newGroupBody>[0];

/** The panel of a new device; `name` fills its name, as for a device that the twin sees. */
export function NewDevicePanel(props: {
  inv: Inventory;
  vendors: Vendors | null;
  defaults: SettingDefaults;
  name?: string;
  onAdd: (f: DeviceFields, draft: Draft) => Promise<boolean>;
  onClose: () => void;
  returnFocus?: Focus;
}) {
  const [f, setF] = useState<DeviceFields & Draft>({ name: props.name ?? "", address: "", group: props.inv.groups[0]?.name ?? "", site: "", location: "" });
  const [draft, setDraft] = useState<Draft>({});
  const add = () => void props.onAdd(f, draft).then((ok) => ok && props.onClose());
  const record = panelHandlers((k, v) => setF((x) => ({ ...x, [k]: v })), add, () => {});
  const settings = panelHandlers((k, v) => setDraft((x) => ({ ...x, [k]: v })), add, () => {});
  const group = props.inv.groups.find((g) => g.name === f.group) ?? null;
  return (
    <Panel
      title="New device"
      label="New device"
      onClose={props.onClose}
      returnFocus={props.returnFocus}
      foot={
        <>
          <button type="button" class="primary" onClick={add}>
            Add device
          </button>
          <button type="button" onClick={props.onClose}>
            Cancel
          </button>
        </>
      }
    >
      <div class="inv-fields">
        <TextField id="new-device" k="name" label="name" draft={f} h={record} autoFocus={!props.name} />
        <TextField id="new-device" k="address" label="address" draft={f} h={record} autoFocus={!!props.name} />
        <PickField id="new-device" k="group" label="device group" draft={f} h={record} options={props.inv.groups.map((g) => ({ value: g.name, text: g.name }))} />
        <TextField id="new-device" k="site" label="site" draft={f} h={record} />
        <TextField id="new-device" k="location" label="location" draft={f} h={record} mono={false} />
        <TextField id="new-device" k="console_site" label="console site" draft={draft} h={settings} />
      </div>
      <div class="inv-part">
        <span class="t-section">Settings</span>
        <SettingsEditor id="new-device" inv={props.inv} draft={draft} group={group?.settings ?? null} defaults={props.defaults} own="device" vendor={group?.vendor ?? ""} vendors={props.vendors} h={settings} />
      </div>
    </Panel>
  );
}

/** The panel of a new group. */
export function NewGroupPanel(props: {
  inv: Inventory;
  vendors: Vendors | null;
  defaults: SettingDefaults;
  onAdd: (f: GroupFields, draft: Draft) => Promise<boolean>;
  onClose: () => void;
  returnFocus?: Focus;
}) {
  const [f, setF] = useState<GroupFields & Draft>({ name: "", vendor: "", credential: "", route: "" });
  const [draft, setDraft] = useState<Draft>({});
  const add = () => void props.onAdd(f, draft).then((ok) => ok && props.onClose());
  const record = panelHandlers((k, v) => setF((x) => ({ ...x, [k]: v })), add, () => {});
  const settings = panelHandlers((k, v) => setDraft((x) => ({ ...x, [k]: v })), add, () => {});
  return (
    <Panel
      title="New device group"
      label="New device group"
      onClose={props.onClose}
      returnFocus={props.returnFocus}
      foot={
        <>
          <button type="button" class="primary" onClick={add}>
            Add group
          </button>
          <button type="button" onClick={props.onClose}>
            Cancel
          </button>
        </>
      }
    >
      <div class="inv-fields">
        <TextField id="new-group" k="name" label="name" draft={f} h={record} autoFocus />
        <TextField id="new-group" k="vendor" label="vendor" draft={f} h={record} list={VENDOR_LIST} />
        <PickField id="new-group" k="credential" label="credential" draft={f} h={record} options={[{ value: "", text: "none" }, ...props.inv.credentials.map((c) => ({ value: c.name, text: c.name }))]} />
        <PickField id="new-group" k="route" label="route" draft={f} h={record} options={[{ value: "", text: "direct" }, ...props.inv.routes.map((x) => ({ value: x.name, text: x.name }))]} />
        <TextField id="new-group" k="description" label="description" draft={draft} h={settings} mono={false} />
      </div>
      <div class="inv-part">
        <span class="t-section">Settings</span>
        <SettingsEditor id="new-group" inv={props.inv} draft={draft} group={null} defaults={props.defaults} own="group" vendor={f.vendor.trim()} vendors={props.vendors} omit={["credential", "route"]} h={settings} />
      </div>
    </Panel>
  );
}
