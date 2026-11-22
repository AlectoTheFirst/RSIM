// The sign-in of the page: the one-time setup of the first admin, the
// sign-in form, and the views of the signed-in user. On a server with no
// sign-in, the page shows the views with no user.
import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { App } from "../App";
import { ApiProblem, getMe, getSetup, onUnauthorized, setUp, signIn, signOut } from "../api/client";
import type { Me } from "../api/types";
import { Card } from "../page/Card";
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

/** A field of a sign-in form: its name above the input, and the message of a refusal below it. */
function Field(props: {
  id: string;
  name: string;
  type: "text" | "password";
  value: string;
  onInput: (v: string) => void;
  autoComplete: string;
  autoFocus?: boolean;
  title?: string;
  message?: string | null;
}) {
  const msg = props.message ? `${props.id}-message` : undefined;
  const attrs = {
    id: props.id,
    autoComplete: props.autoComplete,
    autoFocus: props.autoFocus,
    required: true,
    spellcheck: false,
    title: props.title,
    "aria-invalid": props.message ? true : undefined,
    "aria-describedby": msg,
    value: props.value,
    onInput: (e: { currentTarget: HTMLInputElement }) => props.onInput(e.currentTarget.value),
  };
  return (
    <div class="auth-field">
      <label class="t-label" for={props.id}>
        {props.name}
      </label>
      {props.type === "password" ? <input type="password" {...attrs} /> : <input type="text" class="t-query" {...attrs} />}
      {props.message ? (
        <span id={msg} class="auth-message" role="alert">
          {props.message}
        </span>
      ) : null}
    </div>
  );
}

/** The ground of a page with no frame, and its one card with the wordmark and the title. */
function AuthCard(props: { title: string; children?: ComponentChildren }) {
  return (
    <main class="auth-ground">
      <Card label={props.title} class="auth-card">
        <span class="t-wordmark">RSIM</span>
        <h1 class="t-title">{props.title}</h1>
        {props.children}
      </Card>
    </main>
  );
}

const NAME_RULE = "lower-case letters, digits, . _ @ -, at most 64";
const PASSWORD_RULE = "12 to 1024 characters";

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
    <AuthCard title="Sign in">
      <form class="auth-form" aria-label="Sign in" onSubmit={submit}>
        <Field id="signin-name" name="name" type="text" autoComplete="username" autoFocus value={name} onInput={setName} />
        <Field id="signin-password" name="password" type="password" autoComplete="current-password" value={password} onInput={setPassword} message={problem} />
        <button type="submit" disabled={busy || waiting}>
          Sign in
        </button>
      </form>
    </AuthCard>
  );
}

function SetupPage(props: { onIn: (u: Me) => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [differ, setDiffer] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problem, waiting, setProblem, clear] = useProblem();
  const submit = (e: Event) => {
    e.preventDefault();
    clear();
    if (password !== again) {
      setDiffer(true);
      return;
    }
    setDiffer(false);
    setBusy(true);
    setUp(name.trim(), password)
      .then(props.onIn)
      .catch((x: unknown) => {
        if (x instanceof ApiProblem && x.status === 409) props.onDone();
        else setProblem(x);
      })
      .finally(() => setBusy(false));
  };
  return (
    <AuthCard title="First admin">
      <form class="auth-form" aria-label="First admin" onSubmit={submit}>
        <Field id="setup-name" name="name" type="text" autoComplete="username" autoFocus title={NAME_RULE} value={name} onInput={setName} />
        <Field id="setup-password" name="password" type="password" autoComplete="new-password" title={PASSWORD_RULE} value={password} onInput={setPassword} />
        <Field
          id="setup-again"
          name="password again"
          type="password"
          autoComplete="new-password"
          value={again}
          onInput={(v) => {
            setAgain(v);
            setDiffer(false);
          }}
          message={differ ? "passwords differ" : problem}
        />
        <button type="submit" disabled={busy || waiting}>
          Make admin
        </button>
      </form>
    </AuthCard>
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
      return <main class="auth-ground" />;
    case "off":
      return <App />;
    case "failed":
      return (
        <AuthCard title="Sign in">
          <span class="auth-message" role="alert">
            {phase.text}
          </span>
        </AuthCard>
      );
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
