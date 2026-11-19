// The theme: the colour, type and size tokens of the UI, and the user
// preferences that select among them. Each widget takes its colours and
// sizes from here, through the CSS custom properties that `applyTheme` sets
// or through the numbers that the drawings read.

export type Scheme = "dark" | "light";
export type ThemePref = Scheme | "system";
export type ColourPref = "standard" | "blue-orange";
export type RowHeight = 18 | 22 | 26;

export const ROW_HEIGHTS: readonly RowHeight[] = [18, 22, 26];

/** The colour tokens of each scheme. */
export const COLOURS = {
  dark: {
    ground: "#252A31",
    raise: "#2E343C",
    rule: "#414954",
    control: "#7B8592",
    ink: "#E9ECEF",
    "ink-muted": "#A6AEB8",
    forward: "#5FD0D8",
    reply: "#C9A0F5",
    parameter: "#F0CE4E",
    deliver: "#B9E36A",
    drop: "#FF8D75",
    "deliver-alt": "#7DB4EE",
    "drop-alt": "#F2A65A",
  },
  light: {
    ground: "#EEF0F2",
    raise: "#FFFFFF",
    rule: "#B9C0C8",
    control: "#6E7782",
    ink: "#14181D",
    "ink-muted": "#56606B",
    forward: "#006C78",
    reply: "#6B3FB0",
    parameter: "#7A5A00",
    deliver: "#2F6B00",
    drop: "#B3261E",
    "deliver-alt": "#1F5FAE",
    "drop-alt": "#96400A",
  },
} as const;

export type ColourToken = keyof (typeof COLOURS)["dark"];

const SANS = '"Instrument Sans", system-ui, sans-serif';
const MONO = '"Martian Mono", ui-monospace, monospace';

/** The type styles: family, size, line height, weight and width. */
export const TYPE = {
  headline: { family: SANS, size: 20, line: 24, weight: 700, stretch: "88%", spacing: "normal" },
  section: { family: SANS, size: 14, line: 18, weight: 700, stretch: "88%", spacing: "normal" },
  wordmark: { family: SANS, size: 15, line: 18, weight: 700, stretch: "88%", spacing: "0.08em" },
  body: { family: SANS, size: 12, line: 18, weight: 400, stretch: "88%", spacing: "normal" },
  label: { family: SANS, size: 11, line: 18, weight: 400, stretch: "88%", spacing: "normal" },
  value: { family: MONO, size: 11, line: 18, weight: 400, stretch: "75%", spacing: "normal" },
  "value-changed": { family: MONO, size: 11, line: 18, weight: 600, stretch: "75%", spacing: "normal" },
  query: { family: MONO, size: 13, line: 18, weight: 400, stretch: "75%", spacing: "normal" },
  index: { family: MONO, size: 10, line: 18, weight: 400, stretch: "75%", spacing: "normal" },
} as const;

export type TypeStyle = keyof typeof TYPE;

/** The sizes in px. */
export const SIZE = {
  margin: 16,
  button: 24,
  buttonRadius: 2,
  buttonPad: 8,
  input: 22,
  inputRadius: 2,
  inputPad: 6,
  buttonGap: 4,
  factGap: 22,
  lane: 52,
  pathLine: 3,
  partLine: [3, 5, 7],
  partColumn: 176,
  endSquare: 9,
  deviceSquare: 12,
  ring: 3.75,
  ringStroke: 2.5,
  account: 24,
  accountRadius: 12,
  hairline: 1,
  hatchPitch: 5,
  hatchLine: 1,
  hatchMark: 22,
  markGap: 6,
  selectedBar: 3,
  focusRing: 2,
  focusOffset: 2,
  topBarPad: 8,
  topBarGap: 20,
  queryBarPad: 10,
  queryBarGap: 18,
  resultPad: 12,
  lineGap: 6,
  colStep: 30,
  colFunction: 150,
  colReason: 280,
  colReasonSet: 260,
  colIp: 104,
  colPort: 52,
  colTransport: 64,
  colRib: 30,
  colSource: 132,
  cellPad: 10,
  ribPadX: 6,
  ribPadY: 2,
  partGap: 5,
  partPad: 6,
  detailGap: 28,
  factLabel: 120,
  codeNumber: 34,
  menu: 288,
  dash: 2,
  invMark: 28,
  invDevice: 150,
  invAddress: 104,
  invVendor: 124,
  invSite: 76,
  invLocation: 150,
  invCredential: 104,
  invRoute: 112,
  invSsh: 104,
  invTrust: 86,
  invCycle: 230,
  invSerial: 150,
  invHatch: 12,
  invKvLabel: 130,
  invDetailGap: 32,
  invDetailBottom: 14,
  invSiteInput: 120,
  invLocationInput: 220,
  invColumnsGap: 40,
  credName: 110,
  credSecret: 200,
  routeName: 110,
  routeCredential: 110,
} as const;

/** The share of the direction colour in the band of a part of a set query. */
export const BAND_SHARE = "26%";

/** The share of `rule` in the lane guides. */
export const GUIDE_SHARE = "55%";

export interface Prefs {
  theme: ThemePref;
  colours: ColourPref;
  row: RowHeight;
}

export const DEFAULT_PREFS: Prefs = { theme: "system", colours: "standard", row: 18 };

const STORE_KEY = "rsim.prefs";

export function loadPrefs(): Prefs {
  try {
    const p = JSON.parse(localStorage.getItem(STORE_KEY) ?? "{}") as Partial<Prefs>;
    return {
      theme: p.theme === "dark" || p.theme === "light" ? p.theme : "system",
      colours: p.colours === "blue-orange" ? "blue-orange" : "standard",
      row: ROW_HEIGHTS.includes(p.row as RowHeight) ? (p.row as RowHeight) : 18,
    };
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
    out[`--${name}-stretch`] = t.stretch;
    out[`--${name}-spacing`] = t.spacing;
  }
  for (const [k, v] of Object.entries(SIZE)) {
    if (typeof v === "number") out[`--${kebab(k)}`] = `${v}px`;
  }
  out["--band"] = `color-mix(in srgb, ${c.forward} ${BAND_SHARE}, transparent)`;
  out["--guide"] = `color-mix(in srgb, ${c.rule} ${GUIDE_SHARE}, transparent)`;
  out["--row"] = `${p.row}px`;
  out["color-scheme"] = s;
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
