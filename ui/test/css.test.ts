// The CSS files take each colour, size and weight from the theme.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_PREFS, ROW_HEIGHTS, SCHEMES, properties } from "../src/theme";

const SRC = join(__dirname, "../src");

function filesOf(dir: string, ext: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return filesOf(p, ext);
    return e.name.endsWith(ext) ? [p] : [];
  });
}

const uncomment = (css: string) => css.replace(/\/\*[\s\S]*?\*\//g, "");

/** The CSS of each file with no comments and no @font-face block. */
const CSS = filesOf(SRC, ".css").map((f) => ({
  file: f.slice(SRC.length + 1),
  css: uncomment(readFileSync(f, "utf8")).replace(/@font-face\s*{[^}]*}/g, ""),
}));

/** The properties that the theme sets in each scheme and with each preference. */
const THEME = new Set(
  SCHEMES.flatMap((s) =>
    (["standard", "blue-orange"] as const).flatMap((colours) =>
      ROW_HEIGHTS.flatMap((row) => Object.keys(properties(s, { ...DEFAULT_PREFS, colours, row }))),
    ),
  ),
);

/** The properties that a TSX file sets in a style object. */
const INLINE = new Set(
  filesOf(SRC, ".tsx").flatMap((f) => [...readFileSync(f, "utf8").matchAll(/"(--[a-z0-9-]+)"\s*:/g)].map((m) => m[1]!)),
);

const NAMED_COLOURS = ["white", "black", "red", "green", "blue", "gray", "grey", "silver", "orange", "yellow", "purple", "navy", "teal", "maroon"];

describe.each(CSS)("the CSS of $file", ({ css }) => {
  it("uses only the properties that the theme sets or that a TSX style sets", () => {
    const used = [...css.matchAll(/var\(\s*(--[a-z0-9-]+)/g)].map((m) => m[1]!);
    expect(used.filter((v) => !THEME.has(v) && !INLINE.has(v))).toEqual([]);
  });

  it("has no colour literal", () => {
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) ?? []).toEqual([]);
    expect(css.match(/\b(rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(/g) ?? []).toEqual([]);
    const named = new RegExp(`:[^;{}]*\\b(${NAMED_COLOURS.join("|")})\\b`, "g");
    expect(css.match(named) ?? []).toEqual([]);
  });

  it("has no length literal: a length is a custom property, 0, a percentage, fr, 1ch or 100 of a viewport unit", () => {
    const lengths = [...css.matchAll(/(?<![\w-])(\d*\.?\d+)(px|em|rem|pt|pc|cm|mm|in|ex|lh|ch|vw|vh|dvh|svh|lvh|vmin|vmax)\b/g)].map((m) => m[0]);
    expect(lengths.filter((l) => l !== "1ch" && !/^100(vw|vh|dvh|svh|lvh)$/.test(l))).toEqual([]);
  });

  it("has no font weight literal", () => {
    expect(css.match(/font-weight:\s*\d+/g) ?? []).toEqual([]);
  });
});
