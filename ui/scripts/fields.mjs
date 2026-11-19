// Writes src/api/fields.ts from crates/rsim-api/openapi.json: the fields
// of a path query and of a set query, with their descriptions, their
// number ranges and their names. A field of a path query only has the
// set description null. With --check, it writes nothing and
// fails if the file is not current.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SOURCE = resolve(here, "../../crates/rsim-api/openapi.json");
const TARGET = resolve(here, "../src/api/fields.ts");

/** The arguments of a query that are not fields of the query bar. */
const LEFT_OUT = new Set(["topology", "form"]);

const doc = JSON.parse(readFileSync(SOURCE, "utf8"));
const schemas = doc.components.schemas;

const oneLine = (s) => (s ?? "").replace(/\s+/g, " ").trim();

function deref(s) {
  while (s && s.$ref) s = schemas[s.$ref.replace("#/components/schemas/", "")];
  return s;
}

/**
 * The value form of a path query argument: its JSON type, the largest
 * number and the names that it takes.
 */
function valueForm(schema) {
  const out = { type: null, maximum: null, values: [] };
  const visit = (s) => {
    s = deref(s);
    if (!s) return;
    for (const m of [...(s.anyOf ?? []), ...(s.oneOf ?? [])]) visit(m);
    if (s.const !== undefined) out.values.push(String(s.const));
    for (const v of s.enum ?? []) out.values.push(String(v));
    const types = (Array.isArray(s.type) ? s.type : s.type ? [s.type] : []).filter((t) => t !== "null");
    for (const t of types) {
      if (t === "array") {
        out.type = "list";
        visit(s.items);
      } else if (t === "integer") {
        if (out.type !== "list") out.type = "integer";
        if (s.maximum !== undefined) out.maximum = s.maximum;
      } else if (out.type === null) {
        out.type = t;
      }
    }
  };
  visit(schema);
  if (out.type === null && out.values.length) out.type = "string";
  return out;
}

const path = schemas.PathQueryArgs.properties;
const set = schemas.SetQueryArgs.properties;
const names = Object.keys(path).filter((k) => !LEFT_OUT.has(k));
const setNames = Object.keys(set).filter((k) => !LEFT_OUT.has(k));
if (setNames.join() !== names.filter((k) => setNames.includes(k)).join()) {
  throw new Error(`SetQueryArgs has a field that PathQueryArgs does not have, or another order: ${names} / ${setNames}`);
}

const fields = {};
for (const k of names) {
  const f = valueForm(path[k]);
  if (f.type === null) throw new Error(`the field ${k} has no type`);
  fields[k] = {
    path: oneLine(path[k].description),
    set: set[k] ? oneLine(set[k].description) : null,
    type: f.type,
    maximum: f.maximum,
    values: f.values,
  };
}

const text = `// The fields of a query, from crates/rsim-api/openapi.json.
// scripts/fields.mjs writes this file: \`npm run api\`. Do not edit it.

/** The description of a set argument. */
export const SET_SYNTAX = ${JSON.stringify(oneLine(schemas.SetArg.description))};

/** The description of the fields of a path query and of a set query. */
export const MODE_TEXT = ${JSON.stringify(
  { path: oneLine(schemas.PathQueryArgs.description), set: oneLine(schemas.SetQueryArgs.description) },
  null,
  2,
)} as const;

/**
 * Each field of a path query and of a set query: the description of each
 * mode, null for a mode that does not take the field, the JSON type of
 * the path query value, its largest number, and its names.
 */
export const FIELD_SCHEMA = ${JSON.stringify(fields, null, 2)} as const;

export type FieldName = keyof typeof FIELD_SCHEMA;
`;

if (process.argv.includes("--check")) {
  let now = "";
  try {
    now = readFileSync(TARGET, "utf8");
  } catch {
    now = "";
  }
  if (now !== text) {
    console.error("src/api/fields.ts is not current. Run npm run api.");
    process.exit(1);
  }
} else {
  writeFileSync(TARGET, text);
}
