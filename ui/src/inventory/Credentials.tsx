// The Credentials section of the Inventory view: the credentials of the env
// file and the managed credentials, whose secret goes to the server once and
// comes back never. An empty secret field keeps the stored secret.
import { useEffect, useState } from "preact/hooks";
import { deleteCredential, getSecretKey, putCredential } from "../api/client";
import {
  type Credential,
  type CredentialFields,
  type CredentialKind,
  type Inventory,
  type SecretKeyOut,
  KIND_WORDS,
  credentialBody,
  credentialFields,
  credentialGroups,
  secretFrom,
  usedByRoutes,
} from "./model";
import { DeleteButton, HatchCell, type Refuse, type Write, type WriteNew, addKeys } from "./parts";

const SOURCES: readonly [Credential["source"], string][] = [
  ["managed", "managed"],
  ["env", "env file"],
  ["env-url", "env URL"],
];

const KINDS: readonly CredentialKind[] = ["password", "ssh-key", "api-key"];

/** The fields of the source of a credential, with the secret of a managed credential. */
function CredentialEdit(props: {
  f: CredentialFields;
  stored?: Credential;
  keyPresent: boolean;
  onChange: (f: Partial<CredentialFields>) => void;
  keys: (e: KeyboardEvent) => void;
  autoFocus?: boolean;
}) {
  const { f, stored } = props;
  const keeps = stored?.source === "managed" && stored.kind === f.kind;
  const secretHint = keeps ? "unchanged" : KIND_WORDS[f.kind];
  return (
    <span class="cred-edit edit">
      <select aria-label="source" value={f.source} autoFocus={props.autoFocus} onChange={(e) => props.onChange({ source: e.currentTarget.value as Credential["source"] })} onKeyDown={props.keys}>
        {SOURCES.map(([v, w]) => (
          <option value={v} disabled={v === "managed" && !props.keyPresent && f.source !== "managed"}>
            {v === "managed" && !props.keyPresent ? "managed, no secret key" : w}
          </option>
        ))}
      </select>
      {f.source !== "managed" ? (
        <input class="t-value" aria-label="key" placeholder="KEY" value={f.key} spellcheck={false} onInput={(e) => props.onChange({ key: e.currentTarget.value })} onKeyDown={props.keys} />
      ) : (
        <>
          <select aria-label="kind" value={f.kind} onChange={(e) => props.onChange({ kind: e.currentTarget.value as CredentialKind })} onKeyDown={props.keys}>
            {KINDS.map((k) => (
              <option value={k}>{KIND_WORDS[k]}</option>
            ))}
          </select>
          {f.kind !== "api-key" ? (
            <input class="t-value" aria-label="user" placeholder="user" value={f.user} spellcheck={false} autoComplete="off" onInput={(e) => props.onChange({ user: e.currentTarget.value })} onKeyDown={props.keys} />
          ) : null}
          {f.kind === "ssh-key" ? (
            <>
              <textarea
                class="t-value cred-key"
                aria-label="private key"
                placeholder={keeps ? secretHint : "-----BEGIN OPENSSH PRIVATE KEY-----"}
                value={f.secret}
                rows={4}
                spellcheck={false}
                autoComplete="off"
                onInput={(e) => props.onChange({ secret: e.currentTarget.value })}
                onKeyDown={(e) => e.key === "Escape" && props.keys(e)}
              />
              <input class="t-value" type="password" aria-label="passphrase" placeholder="passphrase" value={f.passphrase} autoComplete="new-password" onInput={(e) => props.onChange({ passphrase: e.currentTarget.value })} onKeyDown={props.keys} />
            </>
          ) : (
            <input class="t-value" type="password" aria-label={KIND_WORDS[f.kind]} placeholder={secretHint} value={f.secret} autoComplete="new-password" onInput={(e) => props.onChange({ secret: e.currentTarget.value })} onKeyDown={props.keys} />
          )}
        </>
      )}
    </span>
  );
}

/** The source of a stored credential: the key of the env file, or the kind, the user and the revision of the secret. */
function SourceCell(props: { c: Credential }) {
  const { c } = props;
  if (c.source !== "managed") {
    return (
      <span>
        {secretFrom(c)} <span class="t-value">{c.key}</span>
      </span>
    );
  }
  return (
    <span>
      {secretFrom(c)}
      {c.user ? (
        <>
          {" "}
          <span class="t-value">{c.user}</span>
        </>
      ) : null}
      <span class="muted">, secret {c.secret_revision ?? "not known"}</span>
    </span>
  );
}

function CredentialRow(props: { inv: Inventory; c: Credential; keyPresent: boolean; editing: boolean; onEdit: (on: boolean) => void; write: Write; refuse: Refuse }) {
  const { inv, c } = props;
  const [f, setF] = useState<CredentialFields>(() => credentialFields(c));
  const save = () => {
    const r = credentialBody(c, c.name, f);
    if (!r.ok) return props.refuse(r.problem);
    void props.write(() => putCredential(r.body)).then((ok) => ok && props.onEdit(false));
  };
  const cancel = () => props.onEdit(false);
  const keys = addKeys(save, cancel);
  const groups = credentialGroups(inv, c.name);
  return (
    <div class="inv-t cred" role="row">
      <span class="t-value">{c.name}</span>
      {props.editing ? (
        <CredentialEdit f={f} stored={c} keyPresent={props.keyPresent} onChange={(x) => setF({ ...f, ...x })} keys={keys} autoFocus />
      ) : (
        <>
          <SourceCell c={c} />
          {groups.length ? <span class="t-value">{groups.join(", ")}</span> : usedByRoutes(inv, c.name) ? <span class="muted">routes only</span> : <span />}
        </>
      )}
      <span class="group">
        <button
          type="button"
          aria-pressed={props.editing}
          onClick={() => {
            if (props.editing) save();
            else {
              setF(credentialFields(c));
              props.onEdit(true);
            }
          }}
          onKeyDown={(e) => props.editing && e.key === "Escape" && cancel()}
        >
          Edit
        </button>
        <DeleteButton name={c.name} onDelete={() => props.write(() => deleteCredential(c.name))} />
      </span>
    </div>
  );
}

export function Credentials(props: { inv: Inventory; adding: boolean; onAdding: () => void; onClose: () => void; writeNew: WriteNew; write: Write; refuse: Refuse }) {
  const { inv } = props;
  const [key, setKey] = useState<SecretKeyOut | null>(null);
  useEffect(() => {
    getSecretKey()
      .then(setKey)
      .catch(() => setKey(null));
  }, []);
  const keyPresent = key?.present === true;
  const empty = (): CredentialFields & { name: string } => ({ name: "", ...credentialFields(), source: keyPresent ? "managed" : "env" });
  const [f, setF] = useState(empty);
  const [editing, setEditing] = useState<string | null>(null);
  useEffect(() => {
    if (!f.name && !f.key && !f.secret) setF(empty());
  }, [keyPresent]);
  const add = () => {
    const r = credentialBody(undefined, f.name, f);
    if (!r.ok) return props.refuse(r.problem);
    void props.writeNew(inv.credentials, f.name, () => putCredential(r.body)).then((ok) => {
      if (!ok) return;
      setF(empty());
      props.onClose();
    });
  };
  const keys = addKeys(add, props.onClose);
  return (
    <div>
      <div class="inv-sec">
        Credentials{" "}
        {keyPresent ? (
          <span class="muted">secret key <span class="t-value">{key?.id}</span></span>
        ) : (
          <HatchCell title="rsim-api has no --secret-key-file">no secret key: env file only</HatchCell>
        )}
      </div>
      <div class="inv-t cred inv-head" role="row">
        <span>name</span>
        <span>source</span>
        <span>device groups</span>
        <span />
      </div>
      {inv.credentials.map((c) => (
        <CredentialRow key={c.name} inv={inv} c={c} keyPresent={keyPresent} editing={editing === c.name} onEdit={(on) => setEditing(on ? c.name : null)} write={props.write} refuse={props.refuse} />
      ))}
      {props.adding ? (
        <div class="inv-t cred" role="row" aria-label="New credential">
          <span class="edit">
            <input class="t-value" aria-label="name" value={f.name} spellcheck={false} autoFocus onInput={(e) => setF({ ...f, name: e.currentTarget.value })} onKeyDown={keys} />
          </span>
          <CredentialEdit f={f} keyPresent={keyPresent} onChange={(x) => setF({ ...f, ...x })} keys={keys} />
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
