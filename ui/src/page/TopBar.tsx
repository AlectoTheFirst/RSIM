// The top bar: the snapshot selector, the age of the last cycle, the
// preferences and the account menu.
import { useEffect, useState } from "preact/hooks";
import type { TwinRef } from "../api/client";
import type { Me, Twin } from "../api/types";
import { initials } from "../auth/model";
import { type ColourPref, type Prefs, ROW_HEIGHTS, type RowHeight, SIZE, THEMES, type ThemePref } from "../theme";
import { ageText, lastCycle, ofStore, runOptions, runState, runTime, utcText } from "./frame";
import { HatchMark } from "./Hatch";
import { Icon } from "./Icon";
import { MenuButton } from "./Menu";
import { Pill } from "./Pill";
import { Segmented } from "./Segmented";
import { reloadMark } from "./url";

/** The current time in ms, read again each second. */
function useNow(on: boolean): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!on) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [on]);
  return now;
}

function SnapshotSelector(props: { twins: TwinRef[]; twin: string; info: Twin | null; onTwin: (id: string) => void }) {
  const { options, chosen } = runOptions(props.twins, props.twin);
  const time = runTime(props.twin, props.info?.id === props.twin ? props.info.snapshot : null);
  const state = runState(props.twins, props.twin);
  const run = ofStore(props.twins, props.twin);
  return (
    <MenuButton
      kind="menu"
      label={run ? "Snapshot" : "Twin"}
      align="start"
      buttonClass="selector"
      button={
        <>
          <span class="t-label">{run ? "Snapshot" : "Twin"}</span>
          <span class="t-value strong" title={time !== null ? props.twin : undefined}>
            {time !== null ? utcText(time) : props.twin}
          </span>
          {state === "newest" ? <Pill tone="deliver">newest</Pill> : state === "older" ? <Pill tone="parameter">older</Pill> : null}
          <Icon name="menu" size={SIZE.iconSmall} />
        </>
      }
    >
      {(close) =>
        options.map((o) => (
          <button
            type="button"
            class="menu-item t-value run-option"
            role="menuitemradio"
            aria-checked={o.id === chosen}
            title={o.time !== null ? o.id : undefined}
            tabIndex={-1}
            onClick={() => {
              close();
              if (o.id !== chosen) props.onTwin(o.id);
            }}
          >
            <span>{o.time !== null ? utcText(o.time) : o.id}</span>
            {o.state === "newest" ? <Pill tone="deliver">newest</Pill> : o.state === "older" ? <Pill tone="parameter">older</Pill> : null}
          </button>
        ))
      }
    </MenuButton>
  );
}

function Preferences(props: { prefs: Prefs; onPrefs: (p: Prefs) => void }) {
  const p = props.prefs;
  return (
    <MenuButton kind="dialog" label="Preferences" buttonLabel="Preferences" buttonClass="icon" button={<Icon name="preferences" />}>
      {() => (
        <div class="prefs">
          <span class="t-label">Theme</span>
          <Segmented<ThemePref> label="Theme" value={p.theme} options={THEMES} onChange={(theme) => props.onPrefs({ ...p, theme })} />
          <span class="t-label">Colours</span>
          <Segmented<ColourPref>
            label="Colours"
            value={p.colours}
            options={["standard", "blue-orange"]}
            text={(c) => (c === "standard" ? "standard" : "blue and orange")}
            onChange={(colours) => props.onPrefs({ ...p, colours })}
          />
          <span class="t-label">Row height</span>
          <Segmented<RowHeight> label="Row height" value={p.row} options={ROW_HEIGHTS} onChange={(row) => props.onPrefs({ ...p, row })} />
        </div>
      )}
    </MenuButton>
  );
}

function Account(props: { user: Me; onTokens: () => void; onSignOut?: () => void }) {
  const u = props.user;
  return (
    <MenuButton
      kind="menu"
      label="Account"
      buttonClass="account"
      button={
        <>
          <span class="account-mark" aria-hidden="true">
            {initials(u.name)}
          </span>
          <span class="account-name">
            <span class="strong">{u.name}</span>
            <span class="t-label">{u.role}</span>
          </span>
          <Icon name="menu" size={SIZE.iconSmall} />
        </>
      }
    >
      {(close) => (
        <>
          <button
            type="button"
            class="menu-item"
            role="menuitem"
            tabIndex={-1}
            onClick={() => {
              close();
              props.onTokens();
            }}
          >
            My API tokens
          </button>
          {props.onSignOut ? (
            <button type="button" class="menu-item" role="menuitem" tabIndex={-1} onClick={props.onSignOut}>
              Sign out
            </button>
          ) : null}
        </>
      )}
    </MenuButton>
  );
}

export function TopBar(props: {
  twins: TwinRef[];
  twin: string;
  info: Twin | null;
  /** The newest built run of the store when the page shows an older run, or null. */
  latest: string | null;
  onLatest: (run: string) => void;
  onTwin: (id: string) => void;
  prefs: Prefs;
  onPrefs: (p: Prefs) => void;
  /** The signed-in user, or null on a server with no sign-in. */
  user: Me | null;
  onTokens: () => void;
  onSignOut?: () => void;
  /** The label of a twin that cannot answer, with its cause as the title, or null. */
  state: { text: string; title: string } | null;
}) {
  const reload = reloadMark(props.twins);
  const cycle = lastCycle(props.twins);
  const now = useNow(cycle !== null);
  const layers = props.info?.id === props.twin ? props.info.layers.length : 0;
  return (
    <header class="topbar">
      <SnapshotSelector twins={props.twins} twin={props.twin} info={props.info} onTwin={props.onTwin} />
      {props.latest ? (
        <button type="button" title={props.latest} onClick={() => props.onLatest(props.latest!)}>
          Load newest snapshot
        </button>
      ) : null}
      {layers ? <span class="muted">{layers} what-if layers</span> : null}
      {props.state ? <HatchMark title={props.state.title}>{props.state.text}</HatchMark> : null}
      {reload ? <HatchMark title={reload.title}>{reload.text}</HatchMark> : null}
      <span class="topbar-end">
        {cycle !== null ? (
          <span class="cycle" title={utcText(cycle)}>
            <span class="t-label">last cycle</span> {ageText(now - cycle)}
          </span>
        ) : null}
        <Preferences prefs={props.prefs} onPrefs={props.onPrefs} />
        {props.user ? (
          <>
            <span class="topbar-divider" aria-hidden="true" />
            <Account user={props.user} onTokens={props.onTokens} onSignOut={props.onSignOut} />
          </>
        ) : null}
      </span>
    </header>
  );
}
