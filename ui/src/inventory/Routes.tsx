// The tables Routes and Jump hosts of the Inventory view, each with its add
// row, the edit of a row and the delete of a row.
import { useState } from "preact/hooks";
import { deleteJumpHost, deleteRoute, putJumpHost, putRoute } from "../api/client";
import {
  type Inventory,
  type JumpHost,
  type JumpHostFields,
  type Route,
  type RouteFields,
  hops,
  jumpHostBody,
  jumpHostRoutes,
  newJumpHostBody,
  newRouteBody,
  routeBody,
  routeCredentials,
  routeFields,
} from "./model";
import { DeleteButton, type Write, type WriteNew, addKeys } from "./parts";

/** The proxy, the jump hosts in order and the proxy login of a route in an add row or an edit. */
function RouteEdit(props: { inv: Inventory; f: RouteFields; onChange: (f: RouteFields) => void; keys: (e: KeyboardEvent) => void; autoFocus?: boolean }) {
  const { inv, f, keys } = props;
  const set = (x: Partial<RouteFields>) => props.onChange({ ...f, ...x });
  return (
    <>
      <span class="group edit">
        <input
          class="t-value"
          aria-label="proxy"
          placeholder="no proxy"
          value={f.proxy}
          spellcheck={false}
          autoFocus={props.autoFocus}
          onInput={(e) => set({ proxy: e.currentTarget.value })}
          onKeyDown={keys}
        />
        {f.jumps.map((j, i) => (
          <button type="button" class="t-value" title={`Remove ${j}`} aria-label={`Remove ${j}`} onClick={() => set({ jumps: f.jumps.filter((_, k) => k !== i) })} onKeyDown={keys}>
            {j}
          </button>
        ))}
        {inv.jump_hosts.length ? (
          <select
            class="t-value"
            aria-label="jump host"
            value=""
            onChange={(e) => {
              const j = e.currentTarget.value;
              if (j) set({ jumps: [...f.jumps, j] });
            }}
            onKeyDown={keys}
          >
            <option value="">add jump host</option>
            {inv.jump_hosts.map((j) => (
              <option value={j.name}>{j.name}</option>
            ))}
          </select>
        ) : null}
      </span>
      {f.proxy.trim() ? (
        <span class="edit">
          <select class="t-value" aria-label="credential" value={f.proxyCredential} onChange={(e) => set({ proxyCredential: e.currentTarget.value })} onKeyDown={keys}>
            <option value="">none</option>
            {inv.credentials.map((c) => (
              <option value={c.name}>{c.name}</option>
            ))}
          </select>
        </span>
      ) : (
        <span />
      )}
    </>
  );
}

function RouteRow(props: { inv: Inventory; r: Route; editing: boolean; onEdit: (on: boolean) => void; write: Write }) {
  const { inv, r } = props;
  const [f, setF] = useState<RouteFields>(() => routeFields(r));
  const save = () => void props.write(() => putRoute(routeBody(r, f))).then((ok) => ok && props.onEdit(false));
  const cancel = () => props.onEdit(false);
  const keys = addKeys(save, cancel);
  const h = hops(inv, r);
  return (
    <div class="inv-t route" role="row">
      <span class="t-value">{r.name}</span>
      {props.editing ? (
        <RouteEdit inv={inv} f={f} onChange={setF} keys={keys} autoFocus />
      ) : (
        <>
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
        </>
      )}
      <span class="group">
        <button
          type="button"
          aria-pressed={props.editing}
          onClick={() => {
            if (props.editing) save();
            else {
              setF(routeFields(r));
              props.onEdit(true);
            }
          }}
          onKeyDown={(e) => props.editing && e.key === "Escape" && cancel()}
        >
          Edit
        </button>
        <DeleteButton name={r.name} onDelete={() => props.write(() => deleteRoute(r.name))} />
      </span>
    </div>
  );
}

export function Routes(props: { inv: Inventory; adding: boolean; onAdding: () => void; onClose: () => void; writeNew: WriteNew; write: Write }) {
  const { inv } = props;
  const empty = { name: "", proxy: "", proxyCredential: "", jumps: [] as string[] };
  const [f, setF] = useState(empty);
  const [editing, setEditing] = useState<string | null>(null);
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
        Routes
      </div>
      <div class="inv-t route inv-head" role="row">
        <span>name</span>
        <span>hops</span>
        <span>credential</span>
        <span />
      </div>
      {inv.routes.map((r) => (
        <RouteRow key={r.name} inv={inv} r={r} editing={editing === r.name} onEdit={(on) => setEditing(on ? r.name : null)} write={props.write} />
      ))}
      {props.adding ? (
        <div class="inv-t route" role="row" aria-label="New route">
          <span class="edit">
            <input class="t-value" aria-label="name" value={f.name} spellcheck={false} autoFocus onInput={(e) => setF({ ...f, name: e.currentTarget.value })} onKeyDown={keys} />
          </span>
          <RouteEdit inv={inv} f={f} onChange={(x) => setF({ ...f, ...x, jumps: [...x.jumps] })} keys={keys} />
          <span />
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

/** The address, the credential and the SSH algorithms of a jump host in an add row or an edit. */
function JumpHostEdit(props: { inv: Inventory; f: JumpHostFields; onChange: (f: JumpHostFields) => void; keys: (e: KeyboardEvent) => void; autoFocus?: boolean }) {
  const { inv, f, keys } = props;
  const set = (x: Partial<JumpHostFields>) => props.onChange({ ...f, ...x });
  return (
    <>
      <span class="edit">
        <input
          class="t-value"
          aria-label="address"
          placeholder="host:port"
          value={f.address}
          spellcheck={false}
          autoFocus={props.autoFocus}
          onInput={(e) => set({ address: e.currentTarget.value })}
          onKeyDown={keys}
        />
      </span>
      <span class="edit">
        <select class="t-value" aria-label="credential" value={f.credential} onChange={(e) => set({ credential: e.currentTarget.value })} onKeyDown={keys}>
          {inv.credentials.some((c) => c.name === f.credential) ? null : <option value={f.credential}>{f.credential}</option>}
          {inv.credentials.map((c) => (
            <option value={c.name}>{c.name}</option>
          ))}
        </select>
      </span>
      <span class="edit">
        <select class="t-value" aria-label="ssh_algorithms" value={f.ssh_algorithms} onChange={(e) => set({ ssh_algorithms: e.currentTarget.value as JumpHostFields["ssh_algorithms"] })} onKeyDown={keys}>
          <option value="modern">modern</option>
          <option value="legacy">legacy</option>
        </select>
      </span>
    </>
  );
}

const jumpFields = (j: JumpHost): JumpHostFields => ({ address: j.address, credential: j.credential, ssh_algorithms: j.ssh_algorithms });

function JumpHostRow(props: { inv: Inventory; j: JumpHost; editing: boolean; onEdit: (on: boolean) => void; write: Write }) {
  const { inv, j } = props;
  const [f, setF] = useState<JumpHostFields>(() => jumpFields(j));
  const save = () => void props.write(() => putJumpHost(jumpHostBody(j, f))).then((ok) => ok && props.onEdit(false));
  const cancel = () => props.onEdit(false);
  const keys = addKeys(save, cancel);
  const routes = jumpHostRoutes(inv, j.name);
  return (
    <div class="inv-t jump" role="row">
      <span class="t-value">{j.name}</span>
      {props.editing ? (
        <JumpHostEdit inv={inv} f={f} onChange={setF} keys={keys} autoFocus />
      ) : (
        <>
          <span class="t-value">{j.address}</span>
          <span class="t-value">{j.credential}</span>
          <span>{j.ssh_algorithms}</span>
        </>
      )}
      <span class="t-value">{routes.join(", ")}</span>
      <span class="group">
        <button
          type="button"
          aria-pressed={props.editing}
          onClick={() => {
            if (props.editing) save();
            else {
              setF(jumpFields(j));
              props.onEdit(true);
            }
          }}
          onKeyDown={(e) => props.editing && e.key === "Escape" && cancel()}
        >
          Edit
        </button>
        <DeleteButton name={j.name} onDelete={() => props.write(() => deleteJumpHost(j.name))} />
      </span>
    </div>
  );
}

export function JumpHosts(props: { inv: Inventory; adding: boolean; onAdding: () => void; onClose: () => void; writeNew: WriteNew; write: Write }) {
  const { inv } = props;
  const empty = (): JumpHostFields & { name: string } => ({ name: "", address: "", credential: inv.credentials[0]?.name ?? "", ssh_algorithms: "modern" });
  const [f, setF] = useState(empty);
  const [editing, setEditing] = useState<string | null>(null);
  const add = () =>
    void props.writeNew(inv.jump_hosts, f.name, () => putJumpHost(newJumpHostBody(f))).then((ok) => {
      if (!ok) return;
      setF(empty());
      props.onClose();
    });
  const keys = addKeys(add, props.onClose);
  return (
    <div>
      <div class="inv-sec">
        Jump hosts
      </div>
      <div class="inv-t jump inv-head" role="row">
        <span>name</span>
        <span>address</span>
        <span>credential</span>
        <span>ssh_algorithms</span>
        <span>routes</span>
        <span />
      </div>
      {inv.jump_hosts.map((j) => (
        <JumpHostRow key={j.name} inv={inv} j={j} editing={editing === j.name} onEdit={(on) => setEditing(on ? j.name : null)} write={props.write} />
      ))}
      {props.adding ? (
        <div class="inv-t jump" role="row" aria-label="New jump host">
          <span class="edit">
            <input class="t-value" aria-label="name" value={f.name} spellcheck={false} autoFocus onInput={(e) => setF({ ...f, name: e.currentTarget.value })} onKeyDown={keys} />
          </span>
          <JumpHostEdit inv={inv} f={f} onChange={(x) => setF({ ...f, ...x })} keys={keys} />
          <span />
          <span />
        </div>
      ) : null}
      <div class="actions">
        <button type="button" aria-pressed={props.adding} onClick={() => (props.adding ? add() : props.onAdding())}>
          Add jump host
        </button>
      </div>
    </div>
  );
}
