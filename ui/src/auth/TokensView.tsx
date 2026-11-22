// The Tokens view: the API tokens of the signed-in user, the form of a new
// token with the scopes of the role of the user, the text of a new token
// one time, and the revoke of a token.
import { useEffect, useState } from "preact/hooks";
import { createToken, listTokens, revokeToken } from "../api/client";
import type { Me, NewToken, TokenInfo } from "../api/types";
import { ResultLine } from "../page/Parts";
import { chosenScopes, daysValue, isoSeconds, problemText, timeText, tokenState } from "./model";
import "./auth.css";

function NewTokenForm(props: { user: Me; onMade: (t: NewToken) => void; onCancel: () => void; onProblem: (p: string | null) => void }) {
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<Set<string>>(() => new Set(props.user.scopes));
  const [days, setDays] = useState("");
  const [busy, setBusy] = useState(false);
  const toggle = (s: string) =>
    setScopes((cur) => {
      const next = new Set(cur);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  const submit = (e: Event) => {
    e.preventDefault();
    const d = daysValue(days);
    if (d === "invalid") {
      props.onProblem("days not valid");
      return;
    }
    const chosen = chosenScopes(props.user.scopes, scopes);
    if (!chosen.length) {
      props.onProblem("no scope");
      return;
    }
    setBusy(true);
    props.onProblem(null);
    createToken({ name: name.trim(), scopes: chosen, expires_days: d })
      .then(props.onMade)
      .catch((x: unknown) => props.onProblem(problemText(x)))
      .finally(() => setBusy(false));
  };
  return (
    <form class="auth-form" aria-label="New token" onSubmit={submit}>
      <label class="label" for="token-name">
        name
      </label>
      <input id="token-name" type="text" class="t-value" value={name} spellcheck={false} autoFocus required onInput={(e) => setName(e.currentTarget.value)} />
      <span class="label">scopes</span>
      <span class="scopes" role="group" aria-label="scopes">
        {props.user.scopes.map((s) => (
          <label>
            <input type="checkbox" checked={scopes.has(s)} onChange={() => toggle(s)} />
            <span class="t-value">{s}</span>
          </label>
        ))}
      </span>
      <label class="label" for="token-days">
        days
      </label>
      <input
        id="token-days"
        type="text"
        inputMode="numeric"
        class="t-value"
        value={days}
        placeholder="no expiry"
        title="Days to expiry"
        onInput={(e) => setDays(e.currentTarget.value)}
      />
      <span class="span2 group">
        <button type="submit" disabled={busy}>
          Make token
        </button>
        <button type="button" onClick={props.onCancel}>
          Cancel
        </button>
      </span>
    </form>
  );
}

export function TokensView(props: { user: Me }) {
  const [tokens, setTokens] = useState<TokenInfo[] | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [made, setMade] = useState<NewToken | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const reload = () =>
    listTokens()
      .then(setTokens)
      .catch((e: unknown) => setProblem(problemText(e)));

  useEffect(() => {
    void reload();
  }, []);

  const revoke = (t: TokenInfo) => {
    setProblem(null);
    revokeToken(t.id)
      .then(reload)
      .catch((e: unknown) => setProblem(problemText(e)));
  };

  const copy = (text: string) =>
    navigator.clipboard
      .writeText(text)
      .then(() => setNotice("token copied"))
      .catch(() => setNotice("token not copied"));

  const now = isoSeconds(Date.now());
  const active = tokens ? tokens.filter((t) => tokenState(t, now) === "active").length : 0;
  return (
    <>
      <ResultLine>
        <span>
          <span class="t-title">API tokens</span>
          {tokens ? <span class="muted"> {active} active</span> : null}
        </span>
        {problem ? <span>{problem}</span> : null}
        <span class="grow" />
        <button
          type="button"
          aria-pressed={adding}
          onClick={() => {
            setAdding(!adding);
            setProblem(null);
          }}
        >
          New token
        </button>
      </ResultLine>
      <main class="body auth-page">
        {made ? (
          <div>
            <div class="auth-sec">
              New token <span class="muted">shown one time</span>
            </div>
            <div class="tok-new">
              <span class="t-value" aria-label="token text">
                {made.token}
              </span>
              <span class="group">
                <button type="button" onClick={() => copy(made.token)}>
                  Copy token
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMade(null);
                    setNotice(null);
                  }}
                >
                  Hide token
                </button>
              </span>
              {notice ? <span class="muted">{notice}</span> : null}
            </div>
          </div>
        ) : null}
        {adding ? (
          <NewTokenForm
            user={props.user}
            onProblem={setProblem}
            onCancel={() => {
              setAdding(false);
              setProblem(null);
            }}
            onMade={(t) => {
              setMade(t);
              setNotice(null);
              setAdding(false);
              void reload();
            }}
          />
        ) : null}
        <div class="tok" role="table" aria-label="API tokens">
          {tokens && !tokens.length ? (
            <div class="muted note">no token</div>
          ) : (
            <div class="tok-t tok-head" role="row">
              <span>name</span>
              <span>scopes</span>
              <span>created</span>
              <span>expires</span>
              <span>last used</span>
              <span>state</span>
              <span />
            </div>
          )}
          {(tokens ?? []).map((t) => {
            const state = tokenState(t, now);
            return (
              <div class="tok-t" role="row">
                <span class="t-value" title={t.name}>
                  {t.name}
                </span>
                <span class="t-value" title={t.scopes.join(", ")}>
                  {t.scopes.join(", ")}
                </span>
                <span class="t-value">{timeText(t.created_at, "")}</span>
                <span class={t.expires_at ? "t-value" : "muted"}>{timeText(t.expires_at, "never")}</span>
                <span class={t.last_used_at ? "t-value" : "muted"}>{timeText(t.last_used_at, "never")}</span>
                <span class={state === "active" ? "" : "muted"}>{state}</span>
                <span>
                  {state === "active" ? (
                    <button type="button" aria-label={`Revoke ${t.name}`} onClick={() => revoke(t)}>
                      Revoke
                    </button>
                  ) : null}
                </span>
              </div>
            );
          })}
        </div>
      </main>
    </>
  );
}
