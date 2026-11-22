// The Tokens view: the API tokens of the signed-in user, the form of a new
// token with the scopes of the role of the user, the text of a new token
// one time, and the revoke of a token.
import { useEffect, useState } from "preact/hooks";
import { createToken, listTokens, revokeToken } from "../api/client";
import type { Me, NewToken, TokenInfo } from "../api/types";
import { Card, Empty } from "../page/Card";
import { Icon } from "../page/Icon";
import { Pill } from "../page/Pill";
import { useVirtualRows } from "../page/VirtualRows";
import { toast } from "../page/notes";
import { SIZE } from "../theme";
import { chosenScopes, daysValue, isoSeconds, problemText, timeText, tokenState } from "./model";

type FormProblem = { at: "days" | "scopes" | "form"; text: string } | null;

function NewTokenForm(props: { user: Me; onMade: (t: NewToken) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<Set<string>>(() => new Set(props.user.scopes));
  const [days, setDays] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<FormProblem>(null);
  const toggle = (s: string) => {
    setProblem(null);
    setScopes((cur) => {
      const next = new Set(cur);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };
  const submit = (e: Event) => {
    e.preventDefault();
    const d = daysValue(days);
    if (d === "invalid") {
      setProblem({ at: "days", text: "days not valid" });
      return;
    }
    const chosen = chosenScopes(props.user.scopes, scopes);
    if (!chosen.length) {
      setProblem({ at: "scopes", text: "no scope" });
      return;
    }
    setBusy(true);
    setProblem(null);
    createToken({ name: name.trim(), scopes: chosen, expires_days: d })
      .then(props.onMade)
      .catch((x: unknown) => setProblem({ at: "form", text: problemText(x) }))
      .finally(() => setBusy(false));
  };
  const message = (at: "days" | "scopes" | "form", id: string) =>
    problem?.at === at ? (
      <span id={id} class="auth-message" role="alert">
        {problem.text}
      </span>
    ) : null;
  return (
    <Card title="New token">
      <form class="token-form" aria-label="New token" onSubmit={submit}>
        <div class="auth-field">
          <label class="t-label" for="token-name">
            name
          </label>
          <input
            id="token-name"
            type="text"
            class="t-query"
            value={name}
            spellcheck={false}
            autoFocus
            required
            aria-invalid={problem?.at === "form" ? true : undefined}
            aria-describedby={problem?.at === "form" ? "token-form-message" : undefined}
            onInput={(e) => {
              setName(e.currentTarget.value);
              if (problem?.at === "form") setProblem(null);
            }}
          />
          {message("form", "token-form-message")}
        </div>
        <div class="auth-field">
          <span class="t-label" id="token-scopes-label">
            scopes
          </span>
          <span class="scopes" role="group" aria-labelledby="token-scopes-label" aria-describedby={problem?.at === "scopes" ? "token-scopes-message" : undefined}>
            {props.user.scopes.map((s) => (
              <label>
                <input type="checkbox" checked={scopes.has(s)} onChange={() => toggle(s)} />
                <span class="t-value">{s}</span>
              </label>
            ))}
          </span>
          {message("scopes", "token-scopes-message")}
        </div>
        <div class="auth-field">
          <label class="t-label" for="token-days">
            expiry
          </label>
          <span class="group">
            <input
              id="token-days"
              type="text"
              inputMode="numeric"
              class="t-query token-days"
              value={days}
              placeholder="no expiry"
              aria-invalid={problem?.at === "days" ? true : undefined}
              aria-describedby={problem?.at === "days" ? "token-days-message" : undefined}
              onInput={(e) => {
                setDays(e.currentTarget.value);
                if (problem?.at === "days") setProblem(null);
              }}
            />
            <span class="muted">days</span>
          </span>
          {message("days", "token-days-message")}
        </div>
        <span class="group token-actions">
          <button type="submit" disabled={busy}>
            Add token
          </button>
          <button type="button" onClick={props.onCancel}>
            Cancel
          </button>
        </span>
      </form>
    </Card>
  );
}

/**
 * The button that revokes a token: the first press names the token, the
 * second press revokes it, and Escape or a move of the focus cancels.
 */
function RevokeButton(props: { name: string; onRevoke: () => void }) {
  const [armed, setArmed] = useState(false);
  return (
    <button
      type="button"
      class="danger"
      aria-pressed={armed}
      aria-label={`Revoke ${props.name}`}
      onClick={(e) => {
        if (!armed) {
          e.currentTarget.focus();
          setArmed(true);
        } else {
          setArmed(false);
          props.onRevoke();
        }
      }}
      onKeyDown={(e) => {
        if (e.key === "Escape" && armed) {
          e.preventDefault();
          e.stopPropagation();
          setArmed(false);
        }
      }}
      onBlur={() => setArmed(false)}
    >
      {armed ? `Revoke ${props.name}` : "Revoke"}
    </button>
  );
}

const HEADS = ["name", "scopes", "created", "expires", "last used", "state", ""];

/** The tokens as a table with virtual rows, each row measured. */
function TokenTable(props: { tokens: TokenInfo[]; now: string; onRevoke: (t: TokenInfo) => void }) {
  const v = useVirtualRows({ count: props.tokens.length, estimate: SIZE.button + 2 * SIZE.buttonGap, head: SIZE.button });
  const { first, end, padTop, padBottom } = v.window;
  const rows: preact.JSX.Element[] = [];
  for (let i = first; i < end; i++) {
    const t = props.tokens[i]!;
    const state = tokenState(t, props.now);
    rows.push(
      <div key={t.id} ref={v.measure(i)} class="token-row" role="row" aria-rowindex={i + 2}>
        <span class="t-value" role="cell">
          {t.name}
        </span>
        <span class="t-value" role="cell">
          {t.scopes.join(", ")}
        </span>
        <span class="t-value" role="cell">
          {timeText(t.created_at, "")}
        </span>
        <span class={t.expires_at ? "t-value" : "muted"} role="cell">
          {timeText(t.expires_at, "never")}
        </span>
        <span class={t.last_used_at ? "t-value" : "muted"} role="cell">
          {timeText(t.last_used_at, "never")}
        </span>
        <span role="cell">{state === "active" ? <Pill tone="deliver">active</Pill> : <span class="muted">{state}</span>}</span>
        <span role="cell">{state === "active" ? <RevokeButton name={t.name} onRevoke={() => props.onRevoke(t)} /> : null}</span>
      </div>,
    );
  }
  return (
    <div ref={v.boxRef} class="token-box" onScroll={v.onScroll} role="table" aria-label="API tokens" aria-rowcount={props.tokens.length + 1}>
      <div class="token-row token-head t-label" role="row" aria-rowindex={1}>
        {HEADS.map((h) => (
          <span role="columnheader">{h}</span>
        ))}
      </div>
      <div style={{ height: `${padTop}px` }} />
      {rows}
      <div style={{ height: `${padBottom}px` }} />
    </div>
  );
}

export function TokensView(props: { user: Me }) {
  const [tokens, setTokens] = useState<TokenInfo[] | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [made, setMade] = useState<NewToken | null>(null);

  const reload = () =>
    listTokens()
      .then((t) => {
        setTokens(t);
        setProblem(null);
      })
      .catch((e: unknown) => setProblem(problemText(e)));

  useEffect(() => {
    void reload();
  }, []);

  const revoke = (t: TokenInfo) => {
    revokeToken(t.id)
      .then(() => {
        toast(`${t.name} revoked`);
        return reload();
      })
      .catch((e: unknown) => toast(problemText(e)));
  };

  const copy = (text: string) =>
    navigator.clipboard
      .writeText(text)
      .then(() => toast("token copied"))
      .catch(() => toast("token not copied"));

  const now = isoSeconds(Date.now());
  return (
    <>
      {made ? (
        <Card
          title={made.info.name}
          foot={
            <>
              <button type="button" onClick={() => copy(made.token)}>
                <span class="with-icon">
                  <Icon name="copy" />
                  Copy token
                </span>
              </button>
              <button type="button" onClick={() => setMade(null)}>
                Hide token
              </button>
            </>
          }
        >
          <span class="t-value token-text">{made.token}</span>
        </Card>
      ) : null}
      {adding ? (
        <NewTokenForm
          user={props.user}
          onCancel={() => setAdding(false)}
          onMade={(t) => {
            setMade(t);
            setAdding(false);
            void reload();
          }}
        />
      ) : null}
      <Card
        title="My API tokens"
        head={
          <span class="page-actions">
            <button type="button" aria-pressed={adding} onClick={() => setAdding(!adding)}>
              <span class="with-icon">
                <Icon name="add" />
                Add token
              </span>
            </button>
          </span>
        }
        flush
        fill
        class="token-card"
      >
        {problem ? (
          <Empty problem>{problem}</Empty>
        ) : !tokens ? (
          <Empty>loading</Empty>
        ) : !tokens.length ? (
          <Empty>no token</Empty>
        ) : (
          <TokenTable tokens={tokens} now={now} onRevoke={revoke} />
        )}
      </Card>
    </>
  );
}
