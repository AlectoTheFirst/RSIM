// The theme: the colour, type and size tokens of the UI, and the user
// preferences that select among them. Each widget takes its colours and
// sizes from here, through the CSS custom properties that `applyTheme` sets
// or through the numbers that the drawings read.

export type Scheme = "light" | "dark" | "darcula" | "mono";
export type ThemePref = Scheme | "system";
export type ColourPref = "standard" | "blue-orange";
export type RowHeight = 24 | 28 | 32;

export const SCHEMES: readonly Scheme[] = ["light", "dark", "darcula", "mono"];
export const THEMES: readonly ThemePref[] = [...SCHEMES, "system"];
export const ROW_HEIGHTS: readonly RowHeight[] = [24, 28, 32];

/** The colour tokens of each scheme. */
export const COLOURS = {
  light: {
    ground: "#F4F5F8",
    surface: "#FFFFFF",
    raise: "#F8F9FB",
    selected: "#EEF3FF",
    rule: "#E3E6EB",
    control: "#858E9C",
    ink: "#15191F",
    "ink-muted": "#5B6472",
    forward: "#006C78",
    reply: "#6B3FB0",
    parameter: "#7A5A00",
    deliver: "#2F6B00",
    drop: "#B3261E",
    "deliver-alt": "#1F5FAE",
    "drop-alt": "#96400A",
    action: "#2F5BEA",
    "on-action": "#FFFFFF",
    "action-ink": "#2A52D6",
    rail: "#101828",
    "rail-ink": "#FFFFFF",
    "rail-muted": "#A7B0C0",
  },
  dark: {
    ground: "#0F1318",
    surface: "#161B22",
    raise: "#1D242D",
    selected: "#1E2B4A",
    rule: "#2A323D",
    control: "#6E7987",
    ink: "#E8ECF0",
    "ink-muted": "#9AA4B0",
    forward: "#5FD0D8",
    reply: "#C9A0F5",
    parameter: "#F0CE4E",
    deliver: "#B9E36A",
    drop: "#FF8D75",
    "deliver-alt": "#7DB4EE",
    "drop-alt": "#F2A65A",
    action: "#3565E0",
    "on-action": "#FFFFFF",
    "action-ink": "#8FB4FF",
    rail: "#0A0E13",
    "rail-ink": "#FFFFFF",
    "rail-muted": "#9AA4B0",
  },
  darcula: {
    ground: "#2B2B2B",
    surface: "#313335",
    raise: "#3C3F41",
    selected: "#27374F",
    rule: "#515557",
    control: "#8B9095",
    ink: "#D5D8DD",
    "ink-muted": "#A9ADB2",
    forward: "#8AC0E8",
    reply: "#C7ACE2",
    parameter: "#FFC66D",
    deliver: "#A9C766",
    drop: "#FF9C97",
    "deliver-alt": "#8CC4F2",
    "drop-alt": "#F2AC66",
    action: "#365880",
    "on-action": "#FFFFFF",
    "action-ink": "#92BFEC",
    rail: "#232425",
    "rail-ink": "#FFFFFF",
    "rail-muted": "#A9ADB2",
  },
  mono: {
    ground: "#F5F5F5",
    surface: "#FFFFFF",
    raise: "#FAFAFA",
    selected: "#E6E6E6",
    rule: "#DDDDDD",
    control: "#878787",
    ink: "#111111",
    "ink-muted": "#595959",
    forward: "#111111",
    reply: "#606060",
    parameter: "#111111",
    deliver: "#111111",
    drop: "#111111",
    "deliver-alt": "#111111",
    "drop-alt": "#111111",
    action: "#111111",
    "on-action": "#FFFFFF",
    "action-ink": "#111111",
    rail: "#111111",
    "rail-ink": "#FFFFFF",
    "rail-muted": "#B8B8B8",
  },
} as const;

export type ColourToken = keyof (typeof COLOURS)["light"];

/** The schemes with a dark ground. */
const DARK: ReadonlySet<Scheme> = new Set<Scheme>(["dark", "darcula"]);

const SANS = "Inter, system-ui, sans-serif";
const MONO = '"JetBrains Mono", ui-monospace, monospace';

/** The type styles: family, size, line height, weight and letter spacing. */
export const TYPE = {
  title: { family: SANS, size: 18, line: 24, weight: 600, spacing: "normal" },
  section: { family: SANS, size: 13, line: 16, weight: 600, spacing: "normal" },
  wordmark: { family: SANS, size: 11, line: 16, weight: 700, spacing: "0.1em" },
  body: { family: SANS, size: 12, line: 16, weight: 400, spacing: "normal" },
  label: { family: SANS, size: 11, line: 16, weight: 400, spacing: "normal" },
  value: { family: MONO, size: 11, line: 16, weight: 400, spacing: "normal" },
  "value-changed": { family: MONO, size: 11, line: 16, weight: 600, spacing: "normal" },
  query: { family: MONO, size: 12, line: 16, weight: 500, spacing: "normal" },
  index: { family: MONO, size: 10, line: 16, weight: 400, spacing: "normal" },
} as const;

export type TypeStyle = keyof typeof TYPE;

/** The sizes in px. */
export const SIZE = {
  // Frame and controls
  railWidth: 72,
  railItemPad: 10,
  railIcon: 20,
  topBar: 48,
  topBarDivider: 20,
  margin: 16,
  pageTop: 12,
  cardGap: 12,
  cardPad: 12,
  cardRadius: 8,
  panel: 352,
  button: 28,
  buttonRadius: 6,
  buttonPad: 10,
  input: 28,
  inputPanel: 28,
  inputRadius: 6,
  inputPad: 8,
  buttonGap: 4,
  groupGap: 8,
  icon: 16,
  iconSmall: 12,
  iconStroke: 1.5,
  chip: 22,
  chipButton: 18,
  pill: 18,
  pillRadius: 9,
  pillPad: 8,
  tabLine: 2,
  factGap: 24,
  account: 24,
  accountRadius: 12,
  hairline: 1,
  hatchPitch: 5,
  hatchLine: 1,
  hatchMark: 22,
  hatchSquare: 12,
  markGap: 6,
  selectedBar: 3,
  focusRing: 2,
  focusOffset: 2,
  topBarPad: 12,
  topBarGap: 16,
  resultPad: 12,
  lineGap: 6,
  menu: 420,
  menuMin: 200,
  dash: 2,
  // Trace
  lane: 44,
  /** The advance of a character of the type `index`, rounded up. */
  indexChar: 6,
  pathLine: 3,
  endSquare: 9,
  deviceSquare: 12,
  ring: 3.75,
  ringStroke: 2.5,
  queryBarGap: 12,
  colStep: 32,
  colFunction: 152,
  colFunctionMax: 248,
  colReason: 200,
  colRewrite: 160,
  colSource: 128,
  /** The advance of a character of the type `value`. */
  valueChar: 6.6,
  outcomeIcon: 16,
  outcomeDir: 48,
  stripNode: 12,
  stripLine: 2,
  stripLineMin: 24,
  stripGap: 12,
  listMax: 320,
  pickerList: 320,
  pickName: 160,
  pickAddress: 136,
  cellPad: 10,
  factLabel: 128,
  codeNumber: 40,
  // Tables
  tablesList: 184,
  tablesHead: 28,
  tablesPanelList: 240,
  tablesFilterInput: 240,
  // Inventory
  invMark: 16,
  invCycle: 120,
  invSerial: 160,
  invGroupAction: 72,
  invFilter: 240,
  invSettingLabel: 128,
  invNumber: 128,
  invSeenProtocol: 72,
  invSeenAction: 136,
  // Coverage
  covPathCount: 72,
  // Sign-in and tokens
  authCard: 360,
  tokenDays: 96,
  tokenName: 160,
  tokenScopes: 250,
  tokenTime: 144,
  tokenState: 76,
  // Topology
  mapCard: 144,
  mapCardHeight: 48,
  mapColGap: 128,
  mapRowGap: 80,
  mapStackGap: 16,
  mapMargin: 48,
  mapTrack: 4,
  mapTextMin: 9,
  mapHit: 6,
  mapCardPad: 10,
  mapCardLine: 14,
  mapTag: 18,
  mapTagPad: 4,
  mapTagGap: 4,
  mapTagRadius: 4,
  mapRing: 4,
  mapPanStep: 64,
  mapDrag: 4,
  mapPanelList: 240,
  mapFactLabel: 112,
  mapLine: 2,
  mapDash: 6,
  mapDeviceField: 200,
  mapHalo: 3,
} as const;

/** The font weights of the controls: a button, a column head and a strong word. */
export const WEIGHT = { regular: 400, control: 500, strong: 600 } as const;

/** The share of a colour in its tint on `surface`. */
export const TINT_SHARE = "14%";

/** The share of `drop` in the border of a destructive button. */
export const DANGER_LINE_SHARE = "40%";

/** The time of an open, a close and a change of state. */
export const MOTION = "120ms";

/** The time that a toast shows, in ms. */
export const TOAST_TIME = 4_000;

/** The share of `ink` in the ground of the primary button under the pointer. */
export const HOVER_SHARE = "14%";

/** The share of `rail-ink` in the ground of the current view of the rail. */
export const RAIL_CURRENT_SHARE = "8%";

/** The colours that have a tint. */
const TINTED: readonly ColourToken[] = ["forward", "reply", "parameter", "deliver", "drop", "action", "ink"];

/** The shadow of a card, of a panel, and of a menu and a toast. */
const SHADOWS = {
  card: "0 1px 2px rgba(16, 24, 40, 0.05)",
  panel: "0 4px 12px rgba(16, 24, 40, 0.08)",
  menu: "0 12px 32px rgba(16, 24, 40, 0.18)",
} as const;

export interface Prefs {
  theme: ThemePref;
  colours: ColourPref;
  row: RowHeight;
}

export const DEFAULT_PREFS: Prefs = { theme: "system", colours: "standard", row: 24 };

const STORE_KEY = "rsim.prefs";

/** The preferences of the store, each value that the store does not hold as its default. */
export function prefsOf(p: Partial<Prefs>): Prefs {
  return {
    theme: THEMES.includes(p.theme as ThemePref) ? (p.theme as ThemePref) : DEFAULT_PREFS.theme,
    colours: p.colours === "blue-orange" ? "blue-orange" : "standard",
    row: ROW_HEIGHTS.includes(p.row as RowHeight) ? (p.row as RowHeight) : DEFAULT_PREFS.row,
  };
}

export function loadPrefs(): Prefs {
  try {
    return prefsOf(JSON.parse(localStorage.getItem(STORE_KEY) ?? "{}") as Partial<Prefs>);
  } catch {
    return DEFAULT_PREFS;
  }
}

export function savePrefs(p: Prefs): void {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(p));
  } catch {
    // The preferences then last for this page only.
  }
}

export function scheme(pref: ThemePref): Scheme {
  if (pref !== "system") return pref;
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

/** The CSS custom properties of a scheme and the preferences. */
export function properties(s: Scheme, p: Prefs): Record<string, string> {
  const c = COLOURS[s];
  const dark = DARK.has(s);
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(c)) out[`--${k}`] = v;
  if (p.colours === "blue-orange") {
    out["--deliver"] = c["deliver-alt"];
    out["--drop"] = c["drop-alt"];
  }
  for (const [name, t] of Object.entries(TYPE)) {
    out[`--${name}-family`] = t.family;
    out[`--${name}-size`] = `${t.size}px`;
    out[`--${name}-line`] = `${t.line}px`;
    out[`--${name}-weight`] = String(t.weight);
    if (t.spacing !== "normal") out[`--${name}-spacing`] = t.spacing;
  }
  for (const [k, v] of Object.entries(SIZE)) {
    if (typeof v === "number") out[`--${kebab(k)}`] = `${v}px`;
  }
  for (const k of TINTED) out[`--${k}-tint`] = `color-mix(in srgb, var(--${k}) ${TINT_SHARE}, var(--surface))`;
  for (const [k, v] of Object.entries(WEIGHT)) out[`--weight-${k}`] = String(v);
  out["--action-hover"] = `color-mix(in srgb, var(--ink) ${HOVER_SHARE}, var(--action))`;
  out["--rail-current"] = `color-mix(in srgb, var(--rail-ink) ${RAIL_CURRENT_SHARE}, var(--rail))`;
  out["--danger-line"] = `color-mix(in srgb, var(--drop) ${DANGER_LINE_SHARE}, var(--surface))`;
  for (const [k, v] of Object.entries(SHADOWS)) out[`--shadow-${k}`] = v;
  out["--motion"] = MOTION;
  out["--row"] = `${p.row}px`;
  out["color-scheme"] = dark ? "dark" : "light";
  return out;
}

function kebab(s: string): string {
  return s.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
}

/** Sets the tokens on the root element. */
export function applyTheme(p: Prefs): Scheme {
  const s = scheme(p.theme);
  const root = document.documentElement;
  for (const [k, v] of Object.entries(properties(s, p))) root.style.setProperty(k, v);
  root.dataset.scheme = s;
  return s;
}
