// The edits of a device and of a group: the opened row of each, with each
// field of the record and each setting, and the add rows with the panel of
// the fields that the row does not hold.
import { useRef, useState } from "preact/hooks";
import { deleteDevice, deleteGroup, putDevice, putGroup } from "../api/client";
import {
  type Device,
  type Draft,
  type Facts,
  type Group,
  type Inventory,
  type ResolvedDevice,
  type Vendors,
  deviceBody,
  deviceDraft,
  groupBody,
  groupDraft,
  newDeviceBody,
  newGroupBody,
  sameRecord,
  storedDevice,
} from "./model";
import { DeleteButton, type Refuse, type Write, addKeys, useDraft, useSubmit } from "./parts";
import { type FieldHandlers, PickRow, SettingsEditor, TextRow } from "./SettingsEditor";

/** The id of the list of the vendors with a collector, for the vendor field of a group. */
export const VENDOR_LIST = "inv-vendors";

/**
 * The commit of an edit of a stored record: the body from the stored record
 * and the draft, one write at a time; a commit during a write runs after it
 * with the newest draft.
 */
function useCommit<T>(body: (d: Draft) => { ok: true; body: T } | { ok: false; problem: { title: string; detail: string } }, stored: T, put: (b: T) => Promise<number>, write: Write, refuse: Refuse) {
  const pending = useRef(false);
  const again = useRef<Draft | null>(null);
  const latest = useRef<(d: Draft) => void>(() => {});
  const commit = (d: Draft) => {
    const b = body(d);
    if (!b.ok) {
      refuse(b.problem);
      return;
    }
    if (sameRecord(b.body, stored)) return;
    if (pending.current) {
      again.current = d;
      return;
    }
    pending.current = true;
    void write(() => put(b.body)).finally(() => {
      pending.current = false;
      const next = again.current;
      again.current = null;
      if (next) latest.current(next);
    });
  };
  latest.current = commit;
  return commit;
}

/** The handlers of an edit of a stored record: a choice commits, Enter and the end of the focus commit, Escape reverts the field. */
function editHandlers(draft: Draft, set: (k: string, v: string) => Draft, revert: (k: string) => void, commit: (d: Draft) => void): FieldHandlers {
  return {
    onInput: (k, v) => void set(k, v),
    onPick: (k, v) => commit(set(k, v)),
    keys: (k) => (e: KeyboardEvent) => {
      if (e.key === "Enter") {
        e.preventDefault();
        commit(draft);
      } else if (e.key === "Escape") {
        e.preventDefault();
        revert(k);
      }
    },
    onBlur: () => commit(draft),
  };
}

/** The handlers of the panel of an add row: each field changes the draft, Enter adds, Escape cancels. */
function draftHandlers(setDraft: (f: (d: Draft) => Draft) => void, add: () => void, cancel: () => void): FieldHandlers {
  const set = (k: string, v: string) => setDraft((d) => ({ ...d, [k]: v }));
  const keys = addKeys(add, cancel);
  return { onInput: set, onPick: set, keys: () => keys };
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

/** The opened row of a device. */
export function DeviceDetail(props: {
  d: ResolvedDevice;
  inv: Inventory;
  vendors: Vendors | null;
  facts: Facts | undefined;
  write: Write;
  refuse: Refuse;
  onDeleted: () => void;
}) {
  const stored = storedDevice(props.inv, props.d.name);
  return (
    <div class="inv-detail" role="row">
      <div class="cols">
        <div>
          <div class="head">Asset facts</div>
          <div class="kv">
            <span class="muted">serial</span>
            <Fact value={props.facts?.serial} reason={props.facts?.serialReason} />
            <span class="muted">platform</span>
            <Fact value={props.facts?.platform} reason={props.facts?.platformReason} />
          </div>
        </div>
        {stored ? <DeviceEdit {...props} stored={stored} /> : null}
      </div>
    </div>
  );
}

function DeviceEdit(props: { d: ResolvedDevice; stored: Device; inv: Inventory; vendors: Vendors | null; write: Write; refuse: Refuse; onDeleted: () => void }) {
  const { stored, inv } = props;
  const [draft, set, revert] = useDraft(deviceDraft(stored));
  const commit = useCommit((d) => deviceBody(stored, d), stored, putDevice, props.write, props.refuse);
  const h = editHandlers(draft, set, revert, commit);
  const id = `dev-${stored.name}`;
  const group = inv.groups.find((g) => g.name === stored.group) ?? null;
  return (
    <>
      <div>
        <div class="head">Device</div>
        <div class="inv-settings">
          <TextRow id={id} k="address" label="address" draft={draft} h={h} />
          <PickRow id={id} k="group" label="group" draft={draft} h={h} options={inv.groups.map((g) => ({ value: g.name, text: g.name }))} />
          <TextRow id={id} k="site" label="site" draft={draft} h={h} />
          <TextRow id={id} k="location" label="location" draft={draft} h={h} mono={false} />
          <TextRow id={id} k="console_site" label="console site" draft={draft} h={h} />
        </div>
        <div class="group actions">
          <DeleteButton
            name={stored.name}
            onDelete={() =>
              props.write(() => deleteDevice(stored.name)).then((ok) => {
                if (ok) props.onDeleted();
                return ok;
              })
            }
          />
        </div>
      </div>
      <div>
        <div class="head">
          <span>Settings</span>
        </div>
        <SettingsEditor id={id} inv={inv} draft={draft} group={group?.settings ?? null} vendor={props.d.vendor} vendors={props.vendors} h={h} />
      </div>
    </>
  );
}

/** The opened row of a group. */
export function GroupDetail(props: { g: Group; inv: Inventory; vendors: Vendors | null; write: Write; refuse: Refuse; onDeleted: () => void }) {
  const { g, inv } = props;
  const [draft, set, revert] = useDraft(groupDraft(g));
  const commit = useCommit((d) => groupBody(g, d), g, putGroup, props.write, props.refuse);
  const h = editHandlers(draft, set, revert, commit);
  const id = `grp-${g.name}`;
  return (
    <div class="inv-detail" role="row">
      <div class="cols">
        <div>
          <div class="head">Device group</div>
          <div class="inv-settings">
            <TextRow id={id} k="vendor" label="vendor" draft={draft} h={h} list={VENDOR_LIST} />
            <TextRow id={id} k="description" label="description" draft={draft} h={h} mono={false} />
          </div>
          <div class="group actions">
            <DeleteButton
              name={g.name}
              onDelete={() =>
                props.write(() => deleteGroup(g.name)).then((ok) => {
                  if (ok) props.onDeleted();
                  return ok;
                })
              }
            />
          </div>
        </div>
        <div class="span2">
          <div class="head">
            Settings
          </div>
          <SettingsEditor id={id} inv={inv} draft={draft} group={null} vendor={g.vendor} vendors={props.vendors} h={h} />
        </div>
      </div>
    </div>
  );
}

export function GroupSelect(props: { inv: Inventory; value: string; onChange: (g: string) => void; onKeyDown?: (e: KeyboardEvent) => void }) {
  return (
    <select class="t-value" aria-label="group" value={props.value} onChange={(e) => props.onChange(e.currentTarget.value)} onKeyDown={props.onKeyDown}>
      {props.inv.groups.map((g) => (
        <option value={g.name}>{g.name}</option>
      ))}
    </select>
  );
}

export type DeviceFields = Parameters<typeof newDeviceBody>[0];
export type GroupFields = Parameters<typeof newGroupBody>[0];

/** The handlers of the fields of an add panel that are not settings: each field changes the record, Enter adds, Escape cancels. */
function recordHandlers<T extends Draft>(set: (f: (x: T) => T) => void, keys: (e: KeyboardEvent) => void): FieldHandlers {
  const put = (k: string, v: string) => set((x) => ({ ...x, [k]: v }));
  return { onInput: put, onPick: put, keys: () => keys };
}

export function AddDevice(props: {
  inv: Inventory;
  vendors: Vendors | null;
  submit: number;
  onAdd: (f: DeviceFields, draft: Draft) => Promise<boolean>;
  onClose: () => void;
}) {
  const [f, setF] = useState({ name: "", address: "", group: props.inv.groups[0]?.name ?? "", site: "", location: "" });
  const [draft, setDraft] = useState<Draft>({});
  const add = () => void props.onAdd(f, draft).then((ok) => ok && props.onClose());
  useSubmit(props.submit, add);
  const keys = addKeys(add, props.onClose);
  const h = draftHandlers(setDraft, add, props.onClose);
  const r = recordHandlers(setF, keys);
  const group = props.inv.groups.find((g) => g.name === f.group) ?? null;
  return (
    <div class="inv-detail inv-form" role="group" aria-label="New device">
      <div class="cols">
        <div>
          <div class="head">New device</div>
          <div class="inv-settings">
            <TextRow id="new-device" k="name" label="name" draft={f} h={r} autoFocus />
            <TextRow id="new-device" k="address" label="address" draft={f} h={r} />
            <PickRow id="new-device" k="group" label="device group" draft={f} h={r} options={props.inv.groups.map((g) => ({ value: g.name, text: g.name }))} />
            <TextRow id="new-device" k="site" label="site" draft={f} h={r} />
            <TextRow id="new-device" k="location" label="location" draft={f} h={r} mono={false} />
            <TextRow id="new-device" k="console_site" label="console site" draft={draft} h={h} />
          </div>
        </div>
        <div class="span2">
          <div class="head">
            Settings
          </div>
          <SettingsEditor id="new-device" inv={props.inv} draft={draft} group={group?.settings ?? null} vendor={group?.vendor ?? ""} vendors={props.vendors} h={h} />
        </div>
      </div>
    </div>
  );
}

export function AddGroup(props: {
  inv: Inventory;
  vendors: Vendors | null;
  submit: number;
  onAdd: (f: GroupFields, draft: Draft) => Promise<boolean>;
  onClose: () => void;
}) {
  const [f, setF] = useState({ name: "", vendor: "", credential: "", route: "" });
  const [draft, setDraft] = useState<Draft>({});
  const add = () => void props.onAdd(f, draft).then((ok) => ok && props.onClose());
  useSubmit(props.submit, add);
  const keys = addKeys(add, props.onClose);
  const h = draftHandlers(setDraft, add, props.onClose);
  const r = recordHandlers(setF, keys);
  return (
    <div class="inv-detail inv-form" role="group" aria-label="New group">
      <div class="cols">
        <div>
          <div class="head">New device group</div>
          <div class="inv-settings">
            <TextRow id="new-group" k="name" label="name" draft={f} h={r} autoFocus />
            <TextRow id="new-group" k="vendor" label="vendor" draft={f} h={r} list={VENDOR_LIST} />
            <PickRow id="new-group" k="credential" label="credential" draft={f} h={r} options={[{ value: "", text: "none" }, ...props.inv.credentials.map((c) => ({ value: c.name, text: c.name }))]} />
            <PickRow id="new-group" k="route" label="route" draft={f} h={r} options={[{ value: "", text: "direct" }, ...props.inv.routes.map((x) => ({ value: x.name, text: x.name }))]} />
            <TextRow id="new-group" k="description" label="description" draft={draft} h={h} mono={false} />
          </div>
        </div>
        <div class="span2">
          <div class="head">
            Settings
          </div>
          <SettingsEditor id="new-group" inv={props.inv} draft={draft} group={null} vendor={f.vendor.trim()} vendors={props.vendors} omit={["credential", "route"]} h={h} />
        </div>
      </div>
    </div>
  );
}
