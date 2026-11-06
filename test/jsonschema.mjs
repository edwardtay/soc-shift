// A small JSON Schema validator for the schemas under test/schemas/. No dependencies.
// It implements the keywords those schemas use (draft 2020-12 semantics) and throws on any other keyword,
// so a schema that needs a feature this file lacks fails loudly instead of passing silently.
//   const v = createValidator(); const errors = v.validate(value, "/abs/path/schema.json");
import fs from "node:fs";
import path from "node:path";

const ANNOTATIONS = new Set(["$schema", "$id", "$comment", "title", "description", "default", "examples", "definitions", "$defs", "deprecated", "readOnly", "writeOnly"]);
const KEYWORDS = new Set(["$ref", "type", "enum", "const", "pattern", "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
  "minItems", "maxItems", "uniqueItems", "items", "contains", "required", "properties", "patternProperties", "additionalProperties", "propertyNames",
  "minProperties", "maxProperties", "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "format"]);
// "format" asserts for the formats below; JSON Schema 2020-12 treats it as an annotation by default, so this is stricter.
const FORMATS = {
  "date-time": (s) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i.test(s) && !Number.isNaN(Date.parse(s)),
  uri: (s) => /^[a-z][a-z0-9+.-]*:[^\s]*$/i.test(s),
  binary: () => true
};

function typeOf(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}
function typeMatches(v, t) { const a = typeOf(v); return a === t || (t === "number" && a === "integer"); }
function equal(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
// Unicode-aware length, as JSON Schema counts code points.
function len(s) { return [...s].length; }

export function createValidator() {
  const files = new Map(), regex = new Map();
  const load = (file) => { if (!files.has(file)) files.set(file, JSON.parse(fs.readFileSync(file, "utf8"))); return files.get(file); };
  // ECMA-262 patterns: Unicode mode first, then plain mode for patterns written with identity escapes such as "\\-"
  const re = (p) => { if (!regex.has(p)) { let r; try { r = new RegExp(p, "u"); } catch (e) { r = new RegExp(p); } regex.set(p, r); } return regex.get(p); };
  function pointer(doc, frag) {
    if (!frag || frag === "/") return doc;
    return frag.split("/").slice(1).reduce((o, k) => {
      const key = decodeURIComponent(k).replace(/~1/g, "/").replace(/~0/g, "~");
      if (o == null || !(key in o)) throw new Error("unresolvable JSON pointer #" + frag);
      return o[key];
    }, doc);
  }
  function resolve(ref, file) {
    const [p, frag] = ref.split("#");
    const target = p ? path.resolve(path.dirname(file), p) : file;
    return { schema: pointer(load(target), frag || ""), file: target };
  }

  function check(v, s, file, at, errs) {
    if (s === true) return;
    if (s === false) { errs.push(at + ": no value is allowed here"); return; }
    for (const k of Object.keys(s)) if (!ANNOTATIONS.has(k) && !KEYWORDS.has(k)) throw new Error("unsupported JSON Schema keyword '" + k + "' in " + file);
    const sub = (val, schema, where) => { const e = []; check(val, schema, file, where, e); return e; };

    if (s.$ref !== undefined) { const r = resolve(s.$ref, file); check(v, r.schema, r.file, at, errs); }
    if (s.type !== undefined) { const ts = [].concat(s.type); if (!ts.some((t) => typeMatches(v, t))) errs.push(at + ": is " + typeOf(v) + ", expected " + ts.join(" or ")); }
    if (s.enum !== undefined && !s.enum.some((x) => equal(x, v))) errs.push(at + ": " + JSON.stringify(v) + " is not one of " + JSON.stringify(s.enum));
    if (s.const !== undefined && !equal(s.const, v)) errs.push(at + ": must equal " + JSON.stringify(s.const));

    if (typeof v === "string") {
      if (s.pattern !== undefined && !re(s.pattern).test(v)) errs.push(at + ": " + JSON.stringify(v) + " does not match /" + s.pattern + "/");
      if (s.minLength !== undefined && len(v) < s.minLength) errs.push(at + ": shorter than " + s.minLength);
      if (s.maxLength !== undefined && len(v) > s.maxLength) errs.push(at + ": longer than " + s.maxLength);
      if (s.format !== undefined) { const f = FORMATS[s.format]; if (!f) throw new Error("unsupported format '" + s.format + "' in " + file); if (!f(v)) errs.push(at + ": not a valid " + s.format); }
    }
    if (typeof v === "number") {
      if (s.minimum !== undefined && v < s.minimum) errs.push(at + ": below " + s.minimum);
      if (s.maximum !== undefined && v > s.maximum) errs.push(at + ": above " + s.maximum);
      if (s.exclusiveMinimum !== undefined && v <= s.exclusiveMinimum) errs.push(at + ": not above " + s.exclusiveMinimum);
      if (s.exclusiveMaximum !== undefined && v >= s.exclusiveMaximum) errs.push(at + ": not below " + s.exclusiveMaximum);
    }
    if (Array.isArray(v)) {
      if (s.minItems !== undefined && v.length < s.minItems) errs.push(at + ": fewer than " + s.minItems + " items");
      if (s.maxItems !== undefined && v.length > s.maxItems) errs.push(at + ": more than " + s.maxItems + " items");
      if (s.uniqueItems && new Set(v.map((x) => JSON.stringify(x))).size !== v.length) errs.push(at + ": items are not unique");
      if (s.items !== undefined) v.forEach((x, i) => check(x, s.items, file, at + "[" + i + "]", errs));
      if (s.contains !== undefined && !v.some((x, i) => !sub(x, s.contains, at + "[" + i + "]").length)) errs.push(at + ": no item matches 'contains'");
    }
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const keys = Object.keys(v);
      for (const r of s.required || []) if (!(r in v)) errs.push(at + ": missing required property '" + r + "'");
      if (s.minProperties !== undefined && keys.length < s.minProperties) errs.push(at + ": fewer than " + s.minProperties + " properties");
      if (s.maxProperties !== undefined && keys.length > s.maxProperties) errs.push(at + ": more than " + s.maxProperties + " properties");
      for (const k of keys) {
        let known = false;
        if (s.properties && Object.prototype.hasOwnProperty.call(s.properties, k)) { known = true; check(v[k], s.properties[k], file, at + "." + k, errs); }
        for (const [p, ps] of Object.entries(s.patternProperties || {})) if (re(p).test(k)) { known = true; check(v[k], ps, file, at + "." + k, errs); }
        if (!known && s.additionalProperties !== undefined) {
          if (s.additionalProperties === false) errs.push(at + ": unknown property '" + k + "'");
          else check(v[k], s.additionalProperties, file, at + "." + k, errs);
        }
        if (s.propertyNames !== undefined) check(k, s.propertyNames, file, at + "{" + k + "}", errs);
      }
    }
    if (s.allOf) s.allOf.forEach((x, i) => check(v, x, file, at, errs));
    if (s.anyOf && !s.anyOf.some((x) => !sub(v, x, at).length)) errs.push(at + ": matches none of anyOf (" + s.anyOf.length + ")");
    if (s.oneOf) { const n = s.oneOf.filter((x) => !sub(v, x, at).length).length; if (n !== 1) errs.push(at + ": matches " + n + " of oneOf, expected exactly 1"); }
    if (s.not !== undefined && !sub(v, s.not, at).length) errs.push(at + ": matches a schema it must not match");
    if (s.if !== undefined) {
      const ok = !sub(v, s.if, at).length;
      if (ok && s.then !== undefined) check(v, s.then, file, at, errs);
      if (!ok && s.else !== undefined) check(v, s.else, file, at, errs);
    }
  }

  return {
    validate(value, schemaFile) { const errs = []; check(value, load(schemaFile), schemaFile, "$", errs); return errs; },
    // every keyword in every loaded schema is one this validator implements, across the whole file including branches a value never visits
    audit(schemaFile) {
      const doc = load(schemaFile), bad = [];
      const walk = (s, where) => {
        if (Array.isArray(s)) return s.forEach((x, i) => walk(x, where + "[" + i + "]"));
        if (!s || typeof s !== "object") return;
        for (const [k, x] of Object.entries(s)) {
          if (!ANNOTATIONS.has(k) && !KEYWORDS.has(k)) bad.push(where + "." + k);
          if (["properties", "patternProperties", "definitions", "$defs"].includes(k)) for (const [n, y] of Object.entries(x)) walk(y, where + "." + k + "." + n);
          else if (["enum", "const", "examples", "default", "required"].includes(k)) continue;
          else if (typeof x === "object") walk(x, where + "." + k);
        }
      };
      walk(doc, path.basename(schemaFile));
      return bad;
    },
    loaded() { return [...files.keys()]; }
  };
}
