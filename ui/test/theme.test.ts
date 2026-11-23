import { describe, expect, it, vi } from "vitest";
import { COLOURS, type ColourToken, DEFAULT_PREFS, SCHEMES, SIZE, type Scheme, loadPrefs, prefsOf, properties, savePrefs } from "../src/theme";

const channel = (c: number) => {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};

const rgb = (hex: string) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as [number, number, number];

const luminance = (hex: string) => {
  const [r, g, b] = rgb(hex).map(channel) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};

/** The WCAG contrast ratio of 2 colours. */
const contrast = (a: string, b: string) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
};

/** A colour at `share` on a ground, as `color-mix` in sRGB gives it. */
const mix = (colour: string, ground: string, share: number) => {
  const g = rgb(ground);
  return `#${rgb(colour)
    .map((c, i) => Math.round(c * share + g[i]! * (1 - share)).toString(16).padStart(2, "0"))
    .join("")}`;
};

const GROUNDS: ColourToken[] = ["ground", "surface", "raise", "selected"];
const TEXT: ColourToken[] = ["ink", "ink-muted", "forward", "reply", "parameter", "deliver", "drop", "deliver-alt", "drop-alt", "action-ink"];
const TINTED: ColourToken[] = ["forward", "reply", "parameter", "deliver", "drop", "deliver-alt", "drop-alt"];

describe.each(SCHEMES)("the colours of the scheme %s", (name: Scheme) => {
  const c = COLOURS[name];

  it.each(GROUNDS)("each text colour has 4.5:1 on %s", (ground) => {
    for (const t of TEXT) expect(contrast(c[t], c[ground]), `${t} on ${ground}`).toBeGreaterThanOrEqual(4.5);
  });

  it("each tinted colour has 4.5:1 on its tint", () => {
    for (const t of TINTED) expect(contrast(c[t], mix(c[t], c.surface, 0.14)), t).toBeGreaterThanOrEqual(4.5);
  });

  it("the control border has 3:1 on the ground and on a surface", () => {
    expect(contrast(c.control, c.ground)).toBeGreaterThanOrEqual(3);
    expect(contrast(c.control, c.surface)).toBeGreaterThanOrEqual(3);
  });

  it("the text of the primary button and of the rail has 4.5:1", () => {
    expect(contrast(c["on-action"], c.action)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(c["rail-ink"], c.rail)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(c["rail-muted"], c.rail)).toBeGreaterThanOrEqual(4.5);
  });
});

describe("the properties of a scheme", () => {
  it("sets each colour token and the scheme of the browser controls", () => {
    const p = properties("darcula", DEFAULT_PREFS);
    expect(p["--surface"]).toBe(COLOURS.darcula.surface);
    expect(p["color-scheme"]).toBe("dark");
    expect(properties("mono", DEFAULT_PREFS)["color-scheme"]).toBe("light");
  });

  it("gives deliver and drop their second colours with the colours blue and orange", () => {
    const p = properties("light", { ...DEFAULT_PREFS, colours: "blue-orange" });
    expect(p["--deliver"]).toBe(COLOURS.light["deliver-alt"]);
    expect(p["--drop"]).toBe(COLOURS.light["drop-alt"]);
  });

  it("gives no size the name of a colour", () => {
    const colours = new Set(Object.keys(COLOURS.light).map((k) => `--${k}`));
    const sizes = Object.keys(SIZE).map((k) => `--${k.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`);
    expect(sizes.filter((k) => colours.has(k))).toEqual([]);
  });

  it("sets the row height of the preferences", () => {
    expect(properties("light", { ...DEFAULT_PREFS, row: 28 })["--row"]).toBe("28px");
  });
});

describe("the stored preferences", () => {
  it("keeps each scheme and the theme system", () => {
    expect(prefsOf({ theme: "darcula" }).theme).toBe("darcula");
    expect(prefsOf({ theme: "mono" }).theme).toBe("mono");
    expect(prefsOf({ theme: "system" }).theme).toBe("system");
  });

  it("gives the default for a value that is not a preference", () => {
    expect(prefsOf({ theme: "sepia" as never, row: 18 as never, colours: "red" as never })).toEqual(DEFAULT_PREFS);
    expect(prefsOf({})).toEqual(DEFAULT_PREFS);
  });
});

describe("the store of the preferences", () => {
  function fakeStore(init: Record<string, string>) {
    const m = new Map(Object.entries(init));
    vi.stubGlobal("localStorage", { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) });
    return m;
  }

  it("keeps the theme and the colours of the old store and gives the default row height", () => {
    fakeStore({ "rsim.prefs": JSON.stringify({ theme: "darcula", colours: "blue-orange", row: 32 }) });
    expect(loadPrefs()).toEqual({ theme: "darcula", colours: "blue-orange", row: DEFAULT_PREFS.row });
    vi.unstubAllGlobals();
  });

  it("reads back a saved row height", () => {
    const m = fakeStore({ "rsim.prefs": JSON.stringify({ row: 24 }) });
    savePrefs({ ...DEFAULT_PREFS, row: 32 });
    expect(m.get("rsim.prefs.v2")).toBeDefined();
    expect(loadPrefs().row).toBe(32);
    vi.unstubAllGlobals();
  });
});
