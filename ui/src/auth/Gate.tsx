// The sign-in of the page: the one-time setup of the first admin, the
// sign-in form, and the views of the signed-in user. On a server with no
// sign-in, the page shows the views with no user.
import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { App } from "../App";
import { ApiProblem, getMe, getSetup, onUnauthorized, setUp, signIn, signOut } from "../api/client";
import type { Me } from "../api/types";
import { ResultLine } from "../page/Parts";
import { problemText, secondsLeft, waitDetail, waitUntil } from "./model";
import "./auth.css";

type Phase =
  | { kind: "loading" }
  | { kind: "off" }
  | { kind: "setup" }
  | { kind: "signin" }
  | { kind: "in"; user: Me }
  | { kind: "failed"; text: string };

/** The state of the page from the answers of `/v1/auth/setup` and `/v1/auth/me`. */
async function readPhase(): Promise<Phase> {
  let setup;
  try {
    setup = await getSetup();
  } catch (e) {
    if (e instanceof ApiProblem && e.status === 404) return { kind: "off" };
    return { kind: "failed", text: problemText(e) };
  }
  if (!setup.sign_in) return { kind: "off" };
  if (setup.open) return { kind: "setup" };
  try {
    return { kind: "in", user: await getMe() };
  } catch (e) {
    if (e instanceof ApiProblem && e.status === 401) return { kind: "signin" };
    return { kind: "failed", text: problemText(e) };
  }
}

/** A problem with the wait of a 429 counted down to 0. */
function useProblem(): [string | null, boolean, (e: unknown) => void, () => void] {
  const [problem, setProblem] = useState<{ detail: string; until: number | null } | null>(null);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!problem?.until) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [problem]);
  const left = problem?.until ? secondsLeft(problem.until, now) : 0;
  const text = problem ? (problem.until ? (left ? waitDetail(problem.detail, left) : null) : problem.detail) : null;
  const set = (e: unknown) => {
    const t = Date.now();
    setNow(t);
    setProblem({ detail: problemText(e), until: waitUntil(e, t) });
  };
  return [text, left > 0, set, () => setProblem(null)];
}

function Frame(props: { headline: string; problem: string | null; children?: ComponentChildren }) {
  return (
    <>
      <header class="bar top">
        <span class="t-wordmark">RSIM</span>
      </header>
      <ResultLine>
        <span class="t-headline">{props.headline}</span>
        {props.problem ? <span>{props.problem}</span> : null}
      </ResultLine>
      <main class="body auth-page">{props.children}</main>
    </>
  );
}

const NAME_HINT = "lower-case letters, digits, . _ @ -, at most 64";
const PASSWORD_HINT = "12 to 1024 characters";

function SignInPage(props: { onIn: (u: Me) => void }) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, waiting, setProblem, clear] = useProblem();
  const submit = (e: Event) => {
    e.preventDefault();
    setBusy(true);
    clear();
    signIn(name.trim(), password)
      .then(props.onIn)
      .catch((x: unknown) => {
        setProblem(x);
        setPassword("");
      })
      .finally(() => setBusy(false));
  };
  return (
    <Frame headline="Sign in" problem={problem}>
      <form class="auth-form" aria-label="Sign in" onSubmit={submit}>
        <label class="label" for="signin-name">
          name
        </label>
        <input id="signin-name" type="text" class="t-value" autoComplete="username" autoFocus required spellcheck={false} value={name} onInput={(e) => setName(e.currentTarget.value)} />
        <label class="label" for="signin-password">
          password
        </label>
        <input id="signin-password" type="password" autoComplete="current-password" required value={password} onInput={(e) => setPassword(e.currentTarget.value)} />
        <span class="span2">
          <button type="submit" disabled={busy || waiting}>
            Sign in
          </button>
        </span>
      </form>
    </Frame>
  );
}

function SetupPage(props: { onIn: (u: Me) => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, waiting, setProblem, clear] = useProblem();
  const submit = (e: Event) => {
    e.preventDefault();
    if (password !== again) {
      setProblem(new Error("passwords differ"));
      return;
    }
    setBusy(true);
    clear();
    setUp(name.trim(), password)
      .then(props.onIn)
      .catch((x: unknown) => {
        if (x instanceof ApiProblem && x.status === 409) props.onDone();
        else setProblem(x);
      })
      .finally(() => setBusy(false));
  };
  return (
    <Frame headline="First admin" problem={problem}>
      <form class="auth-form" aria-label="First admin" onSubmit={submit}>
        <label class="label" for="setup-name">
          name
        </label>
        <input id="setup-name" type="text" class="t-value" autoComplete="username" autoFocus required spellcheck={false} title={NAME_HINT} value={name} onInput={(e) => setName(e.currentTarget.value)} />
        <label class="label" for="setup-password">
          password
        </label>
        <input id="setup-password" type="password" autoComplete="new-password" required title={PASSWORD_HINT} value={password} onInput={(e) => setPassword(e.currentTarget.value)} />
        <label class="label" for="setup-again">
          password again
        </label>
        <input id="setup-again" type="password" autoComplete="new-password" required value={again} onInput={(e) => setAgain(e.currentTarget.value)} />
        <span class="span2 muted">
          name: {NAME_HINT}; password: {PASSWORD_HINT}
        </span>
        <span class="span2">
          <button type="submit" disabled={busy || waiting}>
            Make admin
          </button>
        </span>
      </form>
    </Frame>
  );
}

/** The page: the setup, the sign-in or the views, by the state of the server. */
export function Root() {
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const reread = () => void readPhase().then(setPhase);

  useEffect(reread, []);

  useEffect(() => {
    if (phase.kind !== "in") return;
    onUnauthorized(() => setPhase({ kind: "signin" }));
    return () => onUnauthorized(null);
  }, [phase.kind]);

  switch (phase.kind) {
    case "loading":
      return (
        <header class="bar top">
          <span class="t-wordmark">RSIM</span>
        </header>
      );
    case "off":
      return <App />;
    case "failed":
      return <Frame headline="Sign in" problem={phase.text} />;
    case "setup":
      return <SetupPage onIn={(user) => setPhase({ kind: "in", user })} onDone={reread} />;
    case "signin":
      return <SignInPage onIn={(user) => setPhase({ kind: "in", user })} />;
    case "in":
      return (
        <App
          user={phase.user}
          onSignOut={() =>
            void signOut()
              .catch(() => undefined)
              .finally(reread)
          }
        />
      );
  }
}
