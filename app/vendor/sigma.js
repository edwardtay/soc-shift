/* sigma.js: a Sigma rule engine for the browser (and node, for tests).
 *
 * parse()    YAML text -> rule object (needs js-yaml, vendored next to this file)
 * compile()  rule -> AST with every search identifier inlined into the condition
 * match()    AST + event -> { match, ids } where ids are the identifiers that were true
 * lint()     rule -> errors and warnings, including the mistakes AI drafts tend to make
 * convert()  AST -> Splunk SPL, Microsoft Sentinel KQL, Elastic Lucene, Athena / CloudTrail Lake SQL
 *
 * Covers the Sigma 2.0 detection spec: field maps and lists, keyword lists, wildcards with
 * backslash escapes, null and empty values, and the modifiers contains, startswith, endswith,
 * all, re (i, m, s), cased, exists, cidr, gt, gte, lt, lte, fieldref, windash, base64,
 * base64offset, wide / utf16le, utf16be, utf16. Conditions support and, or, not, brackets,
 * "1 of x*", "all of x*" and "them". Correlation rules and the old "| count()" pipes are
 * reported as unsupported rather than guessed at.
 */
(function (root) {
  "use strict";

  var KNOWN_MODS = ["contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cased", "exists", "cidr", "gt", "gte", "lt", "lte",
    "fieldref", "windash", "base64", "base64offset", "wide", "utf16le", "utf16be", "utf16", "expand", "neq"];
  // Modifiers AI drafts and old rule packs invent. Each maps to what was meant.
  var WRONG_MODS = { contain: "contains", icontains: "contains", regex: "re", regexp: "re", startwith: "startswith", beginswith: "startswith",
    endwith: "endswith", equals: "(no modifier)", eq: "(no modifier)", in: "(a YAML list)", any: "(a YAML list)", like: "contains", wildcard: "(plain value with *)",
    gte_: "gte", lowercase: "(nothing: matching is case-insensitive by default)", nocase: "(nothing: matching is case-insensitive by default)" };
  var LEVELS = ["informational", "low", "medium", "high", "critical"];
  var STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"];
  var TACTICS = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "stealth", "defense-impairment",
    "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"];
  var DASHES = ["-", "/", "\u2013", "\u2014", "\u2015"];

  function SigmaError(msg) { this.message = msg; }
  SigmaError.prototype = Object.create(Error.prototype);

  /* ---------------- parsing ---------------- */

  function yaml() {
    var y = root.jsyaml || (typeof require === "function" ? require("./js-yaml.min.js") : null);
    if (!y) throw new SigmaError("YAML parser not loaded");
    return y;
  }
  function parse(text) {
    var docs;
    try { docs = yaml().loadAll(String(text || "")); } catch (e) { throw new SigmaError("YAML error: " + (e.reason || e.message) + (e.mark ? " (line " + (e.mark.line + 1) + ")" : "")); }
    docs = docs.filter(function (d) { return d && typeof d === "object"; });
    if (!docs.length) throw new SigmaError("No rule found. A Sigma rule is a YAML document with a detection block.");
    // A file can hold detection rules, correlation rules and filters (Sigma 2.0), split by ---.
    var rules = docs.filter(function (d) { return d.detection; }), corr = docs.filter(function (d) { return d.correlation; }), filt = docs.filter(function (d) { return d.filter && !d.detection; });
    if (!rules.length) {
      if (corr.length) throw new SigmaError("This correlation rule needs its base rules in the same text. Paste them above it, each as its own YAML document separated by ---.");
      if (filt.length) throw new SigmaError("This is a Sigma filter. Paste the rule it applies to in the same text, separated by ---.");
      throw new SigmaError("No detection block found.");
    }
    rules.forEach(function (r) { applyFilters(r, filt); });
    var rule = rules[0];
    rule.__extraDocs = docs.length - rules.length - corr.length - filt.length + (corr.length ? 0 : rules.length - 1);
    // non-enumerable: the rule object is serialised by callers, and __rules holds the rule itself
    hide(rule, "__rules", rules); hide(rule, "__correlations", corr); hide(rule, "__filters", filt);
    return rule;
  }
  function hide(o, k, v) { Object.defineProperty(o, k, { value: v, enumerable: false, configurable: true, writable: true }); }
  // Sigma filters: extra conditions ANDed into the rules they name (by id or name; no list means every rule).
  function applyFilters(rule, filters) {
    filters.forEach(function (f, n) {
      var fl = f.filter || {}, targets = [].concat(fl.rules || []);
      if (targets.length && targets.indexOf(rule.id) < 0 && targets.indexOf(rule.name) < 0) return;
      if (f.logsource && rule.logsource && ["product", "category", "service"].some(function (k) { return f.logsource[k] && rule.logsource[k] && String(f.logsource[k]).toLowerCase() !== String(rule.logsource[k]).toLowerCase(); })) return;
      var det = Object.assign({}, rule.detection), cond = fl.condition;
      if (!cond) return;
      var prefix = "_filter" + (n + 1) + "_";
      Object.keys(fl).forEach(function (k) { if (k !== "rules" && k !== "condition") det[prefix + k] = fl[k]; });
      var fc = [].concat(cond).map(function (c) { return String(c).replace(/[A-Za-z0-9_*\-.]+/g, function (w) { return /^(and|or|not|of|all|them|\d+)$/i.test(w) || fl[w.replace(/\*$/, "")] === undefined && !/\*/.test(w) ? w : prefix + w; }); });
      var orig = [].concat(det.condition);
      det.condition = "(" + (orig.length > 1 ? orig.map(function (c) { return "(" + c + ")"; }).join(" or ") : orig[0]) + ") and (" + fc.join(") and (") + ")";
      rule.detection = det;
      hide(rule, "__filtered", (rule.__filtered || []).concat(f.title || "filter " + (n + 1)));
    });
  }

  /* ---------------- values and patterns ---------------- */

  // Sigma escapes: \* \? \\ are literals; any other backslash is itself.
  // Returns tokens: {t:"lit", v} | {t:"star"} | {t:"q"}
  function tokens(str) {
    var out = [], buf = "";
    for (var i = 0; i < str.length; i++) {
      var c = str[i];
      if (c === "\\" && i + 1 < str.length && (str[i + 1] === "*" || str[i + 1] === "?" || str[i + 1] === "\\")) { buf += str[i + 1]; i++; continue; }
      if (c === "*" || c === "?") { if (buf) out.push({ t: "lit", v: buf }); buf = ""; out.push({ t: c === "*" ? "star" : "q" }); continue; }
      buf += c;
    }
    if (buf) out.push({ t: "lit", v: buf });
    // merge runs of stars
    return out.filter(function (tk, i) { return !(tk.t === "star" && out[i - 1] && out[i - 1].t === "star"); });
  }
  function litTokens(str) { return str === "" ? [] : [{ t: "lit", v: str }]; }
  function reEsc(s) { return s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&"); }

  // Classify a token list for converters: eq / contains / startswith / endswith / wildcard
  function shape(tk) {
    var lits = tk.filter(function (x) { return x.t === "lit"; });
    var hasQ = tk.some(function (x) { return x.t === "q"; });
    if (!hasQ) {
      if (tk.length === 0) return { op: "eq", v: "" };
      if (tk.length === 1 && tk[0].t === "star") return { op: "any" };
      if (tk.length === 1 && lits.length === 1) return { op: "eq", v: lits[0].v };
      if (tk.length === 3 && tk[0].t === "star" && tk[1].t === "lit" && tk[2].t === "star") return { op: "contains", v: tk[1].v };
      if (tk.length === 2 && tk[0].t === "lit" && tk[1].t === "star") return { op: "startswith", v: tk[0].v };
      if (tk.length === 2 && tk[0].t === "star" && tk[1].t === "lit") return { op: "endswith", v: tk[1].v };
    }
    return { op: "wildcard" };
  }

  function utf16(s, be) {
    var out = "";
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i), lo = String.fromCharCode(c & 255), hi = String.fromCharCode(c >> 8);
      out += be ? hi + lo : lo + hi;
    }
    return out;
  }
  function utf8bytes(s) { return unescape(encodeURIComponent(s)); }
  function b64(bin) { return typeof btoa === "function" ? btoa(bin) : Buffer.from(bin, "binary").toString("base64"); }
  function base64offset(bin) {
    var starts = [0, 2, 3], ends = [null, -3, -2], out = [];
    for (var i = 0; i < 3; i++) {
      var enc = b64(new Array(i + 1).join(" ") + bin), end = ends[(bin.length + i) % 3];
      out.push(end === null ? enc.slice(starts[i]) : enc.slice(starts[i], end));
    }
    return out;
  }

  /* ---------------- compile ---------------- */

  function splitKey(key) {
    var parts = String(key).split("|");
    return { field: parts[0], mods: parts.slice(1).map(function (m) { return m.trim().toLowerCase(); }) };
  }

  // One field (or keyword) item -> leaf node
  function leaf(field, mods, rawValues, ctx, idName) {
    var unknown = mods.filter(function (m) { return KNOWN_MODS.indexOf(m) < 0; });
    if (unknown.length) {
      unknown.forEach(function (m) {
        ctx.errors.push("Unknown modifier |" + m + (WRONG_MODS[m] ? ", did you mean " + WRONG_MODS[m] + "?" : "") + " in " + idName + ".");
      });
    }
    var has = function (m) { return mods.indexOf(m) >= 0; };
    if (has("expand")) ctx.unsupported.push("|expand placeholders (" + (field || "keyword") + ") need a pipeline that fills %placeholders%; that value never matches here.");
    var values = Array.isArray(rawValues) ? rawValues : [rawValues];
    if (!values.length) ctx.errors.push("Empty value list for " + (field || "keywords") + " in " + idName + ".");
    var node = { type: "leaf", field: field || null, mods: mods, all: has("all"), id: idName, specs: [] };
    var cased = has("cased");

    values.forEach(function (v) {
      // YAML 1.1 booleans (yes/no/on/off) are how pySigma reads them; js-yaml 1.2 leaves them as strings
      if (has("exists")) { node.specs.push({ op: "exists", v: v === true || /^(true|yes|on|y)$/i.test(String(v)) }); return; }
      if (v === null) { node.specs.push({ op: "null" }); return; }
      if (has("gt") || has("gte") || has("lt") || has("lte")) {
        var num = Number(v); if (isNaN(num)) ctx.errors.push("Non-numeric value for |gt/|lt on " + field + ".");
        node.specs.push({ op: has("gt") ? "gt" : has("gte") ? "gte" : has("lt") ? "lt" : "lte", v: num }); return;
      }
      if (has("cidr")) { var c = parseCidr(String(v)); if (!c) ctx.errors.push("Bad CIDR " + v + " on " + field + "."); node.specs.push({ op: "cidr", v: String(v), cidr: c }); return; }
      if (has("fieldref")) {
        node.specs.push({ op: "fieldref", v: String(v), sub: has("contains") ? "contains" : has("startswith") ? "startswith" : has("endswith") ? "endswith" : "eq", cased: cased }); return;
      }
      if (has("re")) {
        var flags = (has("i") ? "i" : "") + (has("m") ? "m" : "") + (has("s") ? "s" : "");
        var src = String(v), rx = null;
        try { rx = new RegExp(src.replace(/^\(\?([ims]+)\)/, function (_, f) { flags += f.replace(/[^ims]/g, ""); return ""; }), Array.from(new Set(flags.split(""))).join("")); }
        catch (e) { ctx.errors.push("Regex does not compile in " + idName + ": " + e.message); }
        node.specs.push({ op: "re", v: src, flags: flags, rx: rx }); return;
      }
      // plain string path
      var s = String(v), isNum = typeof v === "number" && !mods.some(function (m) { return /^(contains|startswith|endswith|windash|base64|base64offset|wide|utf16le|utf16be|utf16|cased)$/.test(m); });
      var variants = [s];
      if (has("windash")) variants = windash(s);
      var transformed = has("base64") || has("base64offset") || has("wide") || has("utf16le") || has("utf16be") || has("utf16");
      variants.forEach(function (sv) {
        var tk;
        if (transformed) {
          var bin = has("wide") || has("utf16le") ? utf16(sv, false) : has("utf16be") ? utf16(sv, true) : has("utf16") ? "\xff\xfe" + utf16(sv, false) : utf8bytes(sv);
          var encs = has("base64offset") ? base64offset(bin) : has("base64") ? [b64(bin)] : [bin];
          encs.forEach(function (enc) { pushPlain(node, litTokens(enc), mods, true); });
          return;
        }
        tk = tokens(sv);
        pushPlain(node, tk, mods, cased);
        if (isNum) node.specs[node.specs.length - 1].num = v;
      });
    });
    return node;
  }
  function pushPlain(node, tk, mods, cased) {
    var has = function (m) { return mods.indexOf(m) >= 0; };
    if (has("contains")) tk = [{ t: "star" }].concat(tk, [{ t: "star" }]);
    else if (has("startswith")) tk = tk.concat([{ t: "star" }]);
    else if (has("endswith")) tk = [{ t: "star" }].concat(tk);
    tk = tk.filter(function (x, i) { return !(x.t === "star" && tk[i - 1] && tk[i - 1].t === "star"); });
    var body = tk.map(function (x) { return x.t === "lit" ? reEsc(x.v) : x.t === "star" ? "[\\s\\S]*" : "[\\s\\S]"; }).join("");
    var sh = shape(tk);
    node.specs.push({ op: "pattern", tk: tk, shape: sh, cased: !!cased, rx: new RegExp("^" + body + "$", cased ? "" : "i"), keywordRx: new RegExp(body.replace(/^(\[\\s\\S\]\*)?/, "").replace(/(\[\\s\\S\]\*)?$/, ""), cased ? "" : "i") });
  }
  function windash(s) {
    var out = {};
    DASHES.forEach(function (d) { out[s.replace(/(^|\s)[-\/\u2013\u2014\u2015]/g, "$1" + d)] = 1; });
    return Object.keys(out);
  }

  function compileIdentifier(name, def, ctx) {
    if (def === null || def === undefined) { ctx.errors.push("Search identifier " + name + " is empty."); return { type: "or", children: [] }; }
    if (Array.isArray(def)) {
      if (def.every(function (x) { return x === null || typeof x !== "object"; })) {
        // keyword list
        return { type: "or", children: [leaf(null, [], def, ctx, name)], keyword: true };
      }
      return { type: "or", children: def.map(function (item) { return typeof item === "object" && item !== null ? compileMap(name, item, ctx) : leaf(null, [], [item], ctx, name); }) };
    }
    if (typeof def === "object") return compileMap(name, def, ctx);
    return leaf(null, [], [def], ctx, name);
  }
  function compileMap(name, map, ctx) {
    var keys = Object.keys(map);
    if (!keys.length) ctx.errors.push("Search identifier " + name + " has no fields.");
    return {
      type: "and", children: keys.map(function (k) {
        var sk = splitKey(k);
        ctx.fields[sk.field] = 1;
        var neq = sk.mods.indexOf("neq") >= 0;
        var n = leaf(sk.field, neq ? sk.mods.filter(function (m) { return m !== "neq"; }) : sk.mods, map[k], ctx, name);
        if (sk.mods.indexOf("fieldref") >= 0) [].concat(map[k]).forEach(function (f) { ctx.fields[String(f)] = 1; });
        // |neq: the field matches none of the values (a missing field counts as not equal)
        return neq ? { type: "not", children: [n], neq: true } : n;
      })
    };
  }

  /* condition parser */
  function lexCond(s) {
    var out = [], re = /\s*(\(|\)|[A-Za-z0-9_*\-.]+|\|.*$)/g, m, pos = 0;
    s = String(s);
    while (pos < s.length) {
      re.lastIndex = pos;
      m = re.exec(s);
      if (!m || m.index !== pos) {
        if (/^\s+$/.test(s.slice(pos))) break;
        throw new SigmaError("Cannot read the condition near: " + s.slice(pos, pos + 20));
      }
      out.push(m[1]); pos = re.lastIndex;
    }
    return out;
  }
  function parseCondition(cond, ids, ctx) {
    var pipe = cond.indexOf("|");
    if (pipe >= 0) {
      ctx.unsupported.push("The aggregation \"" + cond.slice(pipe).trim() + "\" is deprecated Sigma syntax; only the part before | is evaluated. Rewrite it as a correlation rule.");
      cond = cond.slice(0, pipe);
    }
    var tk = lexCond(cond), i = 0;
    function peek() { return tk[i] && tk[i].toLowerCase(); }
    function expr() { var n = and(); var kids = [n]; while (peek() === "or") { i++; kids.push(and()); } return kids.length > 1 ? { type: "or", children: kids } : n; }
    function and() { var n = not(); var kids = [n]; while (peek() === "and") { i++; kids.push(not()); } return kids.length > 1 ? { type: "and", children: kids } : n; }
    function not() { if (peek() === "not") { i++; return { type: "not", children: [not()] }; } return prim(); }
    function prim() {
      var t = tk[i];
      if (t === undefined) throw new SigmaError("The condition ends too early.");
      if (t === "(") { i++; var n = expr(); if (tk[i] !== ")") throw new SigmaError("A bracket in the condition is not closed."); i++; return n; }
      if (/^(\d+|all|any)$/i.test(t) && tk[i + 1] && tk[i + 1].toLowerCase() === "of") {
        var q = t.toLowerCase(); i += 2;
        var pat = tk[i++];
        if (!pat) throw new SigmaError("\"" + q + " of\" needs a pattern or them.");
        var names = pat.toLowerCase() === "them" ? ids.filter(function (x) { return x[0] !== "_"; }) : ids.filter(globMatch(pat));
        if (!names.length) ctx.errors.push("\"" + q + " of " + pat + "\" matches no search identifier.");
        names.forEach(function (x) { ctx.used[x] = 1; });
        var kids = names.map(function (x) { return { type: "id", name: x }; });
        if (q === "all") return { type: "and", children: kids, of: q + " of " + pat };
        var nq = q === "any" ? 1 : parseInt(q, 10);
        if (nq === 1) return { type: "or", children: kids, of: q + " of " + pat };
        return { type: "nof", n: nq, children: kids, of: q + " of " + pat };
      }
      if (/^(and|or|not|\))$/i.test(t)) throw new SigmaError("Unexpected \"" + t + "\" in the condition.");
      i++;
      if (ids.indexOf(t) < 0) { ctx.errors.push("The condition uses " + t + ", which is not defined in detection."); return { type: "id", name: t, missing: true }; }
      ctx.used[t] = 1;
      return { type: "id", name: t };
    }
    var n = expr();
    if (i < tk.length) throw new SigmaError("Unexpected \"" + tk[i] + "\" in the condition.");
    return n;
  }
  function globMatch(pat) {
    var rx = new RegExp("^" + pat.split("*").map(reEsc).join(".*") + "$");
    return function (x) { return rx.test(x); };
  }

  function compile(rule) {
    var ctx = { errors: [], unsupported: [], used: {}, fields: {} };
    var det = rule.detection || {};
    var ids = Object.keys(det).filter(function (k) { return k !== "condition" && k !== "timeframe"; });
    var defs = {};
    ids.forEach(function (k) { defs[k] = compileIdentifier(k, det[k], ctx); });
    if (det.timeframe) ctx.unsupported.push("timeframe: " + det.timeframe + " belongs to the deprecated aggregation syntax and is ignored.");
    var conds = det.condition;
    if (conds === undefined || conds === null || conds === "") { ctx.errors.push("detection has no condition."); conds = []; }
    conds = Array.isArray(conds) ? conds : [conds];
    var trees = [];
    conds.forEach(function (c) {
      try { trees.push(parseCondition(String(c), ids, ctx)); } catch (e) { ctx.errors.push(e.message); }
    });
    var tree = trees.length === 1 ? trees[0] : { type: "or", children: trees };
    // inline identifiers
    function inline(n) {
      if (n.type === "id") return { type: "id", name: n.name, missing: n.missing, child: defs[n.name] || { type: "or", children: [] } };
      if (n.children) return Object.assign({}, n, { children: n.children.map(inline) });
      return n;
    }
    var ast = inline(tree);
    var unused = ids.filter(function (k) { return !ctx.used[k]; });
    return { rule: rule, ast: ast, defs: defs, ids: ids, unused: unused, errors: ctx.errors, unsupported: ctx.unsupported, fields: Object.keys(ctx.fields).filter(Boolean) };
  }

  /* ---------------- matching ---------------- */

  // All values at a dotted path. Exact flat key first, then nested walk; arrays fan out.
  function getValues(ev, path) {
    if (ev == null || typeof ev !== "object") return [];
    if (Object.prototype.hasOwnProperty.call(ev, path)) return flat(ev[path]);
    var lower = path.toLowerCase();
    for (var k in ev) if (k.toLowerCase() === lower) return flat(ev[k]);
    var parts = path.split("."), cur = [ev];
    for (var p = 0; p < parts.length; p++) {
      // try joining the remaining parts as one flat key at this level
      var rest = parts.slice(p).join("."), next = [];
      cur.forEach(function (o) {
        if (o == null || typeof o !== "object") return;
        if (Array.isArray(o)) { o.forEach(function (x) { next.push(x); }); return; }
        var key = findKey(o, parts[p]);
        if (key !== null) next.push(o[key]);
      });
      cur = [];
      next.forEach(function (x) { if (Array.isArray(x)) x.forEach(function (y) { cur.push(y); }); else cur.push(x); });
      if (!cur.length) return [];
    }
    return cur.filter(function (x) { return x !== undefined; });
  }
  function findKey(o, k) {
    if (Object.prototype.hasOwnProperty.call(o, k)) return k;
    var l = k.toLowerCase();
    for (var x in o) if (x.toLowerCase() === l) return x;
    return null;
  }
  function flat(v) { return Array.isArray(v) ? v : [v]; }
  function str(v) { return v === null || v === undefined ? null : typeof v === "object" ? JSON.stringify(v) : String(v); }
  function allStrings(ev, out) {
    out = out || [];
    if (ev === null || ev === undefined) return out;
    if (typeof ev === "object") { for (var k in ev) if (k !== "_expect") allStrings(ev[k], out); }
    else out.push(String(ev));
    return out;
  }

  function specMatch(spec, vals, ev, keyword) {
    switch (spec.op) {
      case "null": return !vals.length || vals.every(function (v) { return v === null || v === undefined; });
      case "exists": var ex = vals.some(function (v) { return v !== null && v !== undefined; }); return spec.v ? ex : !ex;
      case "gt": case "gte": case "lt": case "lte":
        return vals.some(function (v) { var n = Number(v); if (v === null || v === "" || isNaN(n)) return false; return spec.op === "gt" ? n > spec.v : spec.op === "gte" ? n >= spec.v : spec.op === "lt" ? n < spec.v : n <= spec.v; });
      case "cidr": return !!spec.cidr && vals.some(function (v) { return inCidr(str(v), spec.cidr); });
      case "re": return !!spec.rx && vals.some(function (v) { var s = str(v); return s !== null && spec.rx.test(s); });
      case "fieldref":
        var refs = getValues(ev, spec.v).map(str).filter(function (x) { return x !== null; });
        return vals.some(function (v) {
          var s = str(v); if (s === null) return false;
          return refs.some(function (r) {
            var a = spec.cased ? s : s.toLowerCase(), b = spec.cased ? r : r.toLowerCase();
            return spec.sub === "contains" ? a.indexOf(b) >= 0 : spec.sub === "startswith" ? a.indexOf(b) === 0 : spec.sub === "endswith" ? a.slice(-b.length) === b : a === b;
          });
        });
      case "pattern":
        var rx = keyword ? spec.keywordRx : spec.rx;
        return vals.some(function (v) { var s = str(v); return s !== null && rx.test(s); });
    }
    return false;
  }
  function leafMatch(n, ev) {
    var vals = n.field === null ? allStrings(ev) : getValues(ev, n.field);
    var keyword = n.field === null;
    if (n.all) return n.specs.every(function (sp) { return specMatch(sp, vals, ev, keyword); });
    return n.specs.some(function (sp) { return specMatch(sp, vals, ev, keyword); });
  }
  function evalNode(n, ev, hits) {
    switch (n.type) {
      case "leaf": return leafMatch(n, ev);
      case "and": return n.children.every(function (c) { return evalNode(c, ev, hits); });
      case "or": return n.children.some(function (c) { return evalNode(c, ev, hits); });
      case "not": return !evalNode(n.children[0], ev, null);
      case "nof": var k = 0; n.children.forEach(function (c) { if (evalNode(c, ev, hits)) k++; }); return k >= n.n;
      case "id": var r = evalNode(n.child, ev, null); if (hits && r) hits[n.name] = 1; return r;
    }
    return false;
  }
  function match(compiled, ev) {
    var hits = {};
    var ok = evalNode(compiled.ast, ev, hits);
    // which identifiers are true at all, for the evidence view (negated filters included)
    var truth = {};
    compiled.ids.forEach(function (k) { truth[k] = evalNode(compiled.defs[k], ev, null); });
    return { match: ok, ids: Object.keys(hits), truth: truth };
  }

  /* ---------------- CIDR ---------------- */
  function parseIp(s) {
    s = String(s || "").trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
      var p = s.split(".").map(Number); if (p.some(function (x) { return x > 255; })) return null;
      return { v: 4, b: p };
    }
    if (s.indexOf(":") >= 0) {
      var m = s.match(/^(.*):(\d{1,3}(?:\.\d{1,3}){3})$/), tail = [];
      if (m) { var v4 = parseIp(m[2]); if (!v4) return null; s = m[1] + ":0:0"; tail = v4.b; }
      var halves = s.split("::"); if (halves.length > 2) return null;
      var head = halves[0] ? halves[0].split(":") : [], back = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
      var fill = 8 - head.length - back.length; if (halves.length === 1 && fill !== 0) return null;
      var words = head.concat(new Array(Math.max(fill, 0) + 1).join("0,").split(",").slice(0, Math.max(fill, 0)), back).map(function (h) { return parseInt(h || "0", 16); });
      if (words.length !== 8 || words.some(isNaN)) return null;
      var bytes = []; words.forEach(function (w) { bytes.push(w >> 8, w & 255); });
      if (tail.length) { bytes[12] = tail[0]; bytes[13] = tail[1]; bytes[14] = tail[2]; bytes[15] = tail[3]; }
      return { v: 6, b: bytes };
    }
    return null;
  }
  function parseCidr(s) {
    var parts = s.split("/"), ip = parseIp(parts[0]); if (!ip) return null;
    var bits = parts.length > 1 ? parseInt(parts[1], 10) : ip.b.length * 8;
    if (isNaN(bits) || bits < 0 || bits > ip.b.length * 8) return null;
    return { ip: ip, bits: bits };
  }
  function inCidr(s, c) {
    var ip = parseIp(s); if (!ip || ip.v !== c.ip.v) return false;
    for (var i = 0; i < c.bits; i++) {
      var byte = i >> 3, mask = 128 >> (i & 7);
      if ((ip.b[byte] & mask) !== (c.ip.b[byte] & mask)) return false;
    }
    return true;
  }

  /* ---------------- lint ---------------- */

  // Field dictionaries for log sources where a wrong field name silently never matches.
  var SCHEMAS = {
    "aws/cloudtrail": { label: "AWS CloudTrail record", prefix: ["userIdentity.", "requestParameters.", "responseElements.", "additionalEventData.", "tlsDetails.", "resources.", "serviceEventDetails.", "insightDetails."],
      fields: ["eventVersion", "userIdentity", "eventTime", "eventSource", "eventName", "awsRegion", "sourceIPAddress", "userAgent", "errorCode", "errorMessage", "requestParameters", "responseElements", "additionalEventData", "requestID", "eventID", "readOnly", "resources", "eventType", "apiVersion", "managementEvent", "recipientAccountId", "serviceEventDetails", "sharedEventID", "vpcEndpointId", "vpcEndpointAccountId", "eventCategory", "tlsDetails", "sessionCredentialFromConsole", "edgeDeviceDetails", "insightDetails"] },
    "okta/okta": { label: "Okta System Log event", prefix: ["actor.", "client.", "outcome.", "target.", "transaction.", "debugContext.", "authenticationContext.", "securityContext.", "request."],
      fields: ["uuid", "published", "eventType", "version", "severity", "legacyEventType", "displayMessage", "actor", "client", "outcome", "target", "transaction", "debugContext", "authenticationContext", "securityContext", "request"] },
    "windows/process_creation": { label: "Windows process creation event", prefix: [],
      fields: ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "OriginalFileName", "User", "IntegrityLevel", "CurrentDirectory", "Hashes", "Product", "Company", "Description", "FileVersion", "ProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid", "LogonId", "LogonGuid", "ParentUser", "TerminalSessionId", "UtcTime", "RuleName", "md5", "sha1", "sha256", "Imphash", "Provider_Name", "EventID"] },
    "github/audit": { label: "GitHub audit log event", prefix: ["config.", "actor_location.", "data."],
      fields: ["action", "actor", "actor_id", "actor_location", "org", "org_id", "repo", "repository", "repository_public", "user", "user_id", "created_at", "@timestamp", "_document_id", "business", "business_id", "operation_type", "public_repo", "visibility", "name", "hook_id", "config", "events", "team", "permission", "transport_protocol_name", "transport_protocol", "external_identity_nameid", "external_identity_username", "hashed_token", "programmatic_access_type", "token_scopes", "token_id", "reason", "user_agent", "request_id", "data"] }
  };
  function schemaFor(ls) {
    if (!ls) return null;
    var p = String(ls.product || "").toLowerCase(), s = String(ls.service || "").toLowerCase(), c = String(ls.category || "").toLowerCase();
    if (p === "aws" && s === "cloudtrail") return SCHEMAS["aws/cloudtrail"];
    if (p === "okta") return SCHEMAS["okta/okta"];
    if (p === "windows" && c === "process_creation") return SCHEMAS["windows/process_creation"];
    if (p === "github" && s === "audit") return SCHEMAS["github/audit"];
    return null;
  }
  function fieldKnown(sc, f) {
    if (sc.fields.some(function (x) { return x.toLowerCase() === f.toLowerCase(); })) return true;
    return sc.prefix.some(function (p) { return f.toLowerCase().indexOf(p.toLowerCase()) === 0; });
  }

  function lint(text) {
    var out = { errors: [], warnings: [], info: [], rule: null, compiled: null };
    var rule;
    try { rule = parse(text); } catch (e) { out.errors.push(e.message); return out; }
    out.rule = rule;
    var c = compile(rule); out.compiled = c;
    c.errors.forEach(function (e) { out.errors.push(e); });
    c.unsupported.forEach(function (e) { out.warnings.push(e); });
    if (rule.__extraDocs > 0) out.info.push("Only the first rule in this file is used; " + rule.__extraDocs + " more YAML document(s) were skipped.");
    (rule.__filtered || []).forEach(function (t) { out.info.push("Filter \"" + t + "\" is applied: its condition is ANDed into the rule."); });
    (rule.__correlations || []).forEach(function (cr) { lintCorrelation(cr, rule.__rules, out); });
    // with a correlation in the text, the correlation carries the metadata that ships
    var md = (rule.__correlations && rule.__correlations[0]) || rule;
    if (!md.title) out.warnings.push("title is missing.");
    else if (String(md.title).length > 110) out.warnings.push("title is longer than 110 characters, the SigmaHQ limit.");
    if (!md.id) out.warnings.push("id is missing. Every rule needs a UUID so it can be versioned and referenced.");
    else if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(md.id))) out.warnings.push("id is not a UUID.");
    if (!md.status) out.warnings.push("status is missing (experimental, test or stable).");
    else if (STATUSES.indexOf(String(md.status)) < 0) out.warnings.push("status \"" + md.status + "\" is not one of " + STATUSES.join(", ") + ".");
    if (!md.level) out.warnings.push("level is missing.");
    else if (LEVELS.indexOf(String(md.level)) < 0) out.warnings.push("level \"" + md.level + "\" is not one of " + LEVELS.join(", ") + ".");
    if (!md.description) out.warnings.push("description is missing. Analysts read it first when the alert fires.");
    if (!rule.logsource || typeof rule.logsource !== "object") out.errors.push("logsource is missing, so no backend knows where to run the rule.");
    else if (!rule.logsource.product && !rule.logsource.category && !rule.logsource.service) out.errors.push("logsource needs at least one of product, category or service.");
    if (!md.falsepositives) out.warnings.push("falsepositives is missing. Name the benign activity that looks like this, or write Unknown.");
    if (md.date && !/^\d{4}-\d{2}-\d{2}$/.test(String(md.date instanceof Date ? md.date.toISOString().slice(0, 10) : md.date))) out.warnings.push("date should be YYYY-MM-DD.");
    if (md.modified && !/^\d{4}-\d{2}-\d{2}$/.test(String(md.modified instanceof Date ? md.modified.toISOString().slice(0, 10) : md.modified))) out.warnings.push("modified should be YYYY-MM-DD.");
    var tags = Array.isArray(md.tags) ? md.tags : md.tags ? [md.tags] : [];
    var attack = tags.filter(function (t) { return /^attack\./i.test(t); });
    if (!attack.length) out.warnings.push("No attack.* tags, so the rule counts for nothing in ATT&CK coverage.");
    tags.forEach(function (t) {
      t = String(t);
      if (/^attack\./i.test(t)) {
        var rest = t.slice(7);
        if (t !== t.toLowerCase()) out.warnings.push("Tag " + t + " should be lowercase.");
        else if (!/^(t\d{4}(\.\d{3})?|g\d{4}|s\d{4}|ta\d{4})$/.test(rest) && TACTICS.indexOf(rest) < 0) out.warnings.push("Tag " + t + " is neither a technique id nor an ATT&CK tactic name.");
      }
    });
    if (attack.length && !attack.some(function (t) { return /^attack\.t\d{4}/i.test(t); })) out.warnings.push("The ATT&CK tags name a tactic but no technique id.");
    c.unused.forEach(function (k) { out.warnings.push("Search identifier " + k + " is defined but the condition never uses it."); });
    // filters swallowed by "them"
    (function walk(n) {
      if (!n) return;
      if (n.of && /them$/.test(n.of) && n.children.some(function (k) { return /^filter/i.test(k.name); })) out.errors.push("\"" + n.of + "\" includes the filter identifiers, so the filters select events instead of excluding them.");
      (n.children || []).forEach(walk);
    })(c.ast);
    // value smells
    Object.keys(c.defs).forEach(function (k) {
      (function walk(n) {
        if (n.type === "leaf") {
          if (n.mods.indexOf("contains") >= 0 && n.specs.some(function (s) { return s.tk && s.tk.length >= 3 && s.tk[1].t === "star"; })) out.warnings.push(k + ": " + n.field + "|contains already wraps the value in wildcards; the extra * is redundant.");
          if (n.specs.some(function (s) { return s.shape && s.shape.op === "any"; })) out.warnings.push(k + ": " + (n.field || "keyword") + " is \"*\", which matches any value. Use |exists: true to say the field must be present.");
          if (n.all && n.specs.length < 2) out.warnings.push(k + ": |all with a single value does nothing.");
          if (n.field && /\s$/.test(n.field)) out.errors.push(k + ": field name \"" + n.field + "\" ends in a space.");
          if (n.mods.indexOf("re") >= 0 && n.specs.some(function (s) { return /^\.\*|\.\*$/.test(s.v); })) out.info.push(k + ": a leading or trailing .* in a regex is unnecessary; |re matches anywhere in the value.");
        }
        (n.children || []).forEach(walk);
      })(c.defs[k]);
    });
    var sc = schemaFor(rule.logsource);
    if (sc) {
      var bad = c.fields.filter(function (f) { return !fieldKnown(sc, f); });
      bad.forEach(function (f) { out.warnings.push("Field " + f + " is not in the " + sc.label + " schema, so it will never match raw logs. Check the spelling or the field mapping."); });
      if (!bad.length) out.info.push("Every field exists in the " + sc.label + " schema.");
    } else if (rule.logsource) out.info.push("No field dictionary for this log source, so field names were not checked.");
    return out;
  }

  /* ---------------- correlation rules (Sigma 2.0) ---------------- */

  var CORR_TYPES = ["event_count", "value_count", "temporal", "temporal_ordered"];
  function spanMs(ts) {
    var m = /^(\d+)\s*([smhdwMy])$/.exec(String(ts || "").trim());
    if (!m) return null;
    return Number(m[1]) * { s: 1e3, m: 6e4, h: 36e5, d: 864e5, w: 6048e5, M: 2592e6, y: 31536e6 }[m[2]];
  }
  function corrCondition(cr) {
    var c = cr.correlation.condition;
    if (c && typeof c === "object" && !Array.isArray(c)) {
      var op = ["gt", "gte", "lt", "lte", "eq", "neq"].filter(function (k) { return c[k] !== undefined; })[0];
      return op ? { op: op, n: Number(c[op]), field: c.field } : null;
    }
    return null;
  }
  // base rules of a correlation, by name or id; the extended temporal form names them in its condition
  function corrRuleRefs(cr) {
    var c = cr.correlation, refs = [].concat(c.rules || []);
    if (!refs.length && typeof c.condition === "string") refs = (c.condition.match(/[A-Za-z0-9_\-.]+/g) || []).filter(function (w) { return !/^(and|or|not)$/i.test(w); });
    return refs;
  }
  function lintCorrelation(cr, rules, out) {
    var c = cr.correlation || {}, t = cr.title || "correlation";
    if (CORR_TYPES.indexOf(c.type) < 0) out.errors.push("Correlation \"" + t + "\": type must be one of " + CORR_TYPES.join(", ") + ".");
    if (!spanMs(c.timespan)) out.errors.push("Correlation \"" + t + "\": timespan must look like 30s, 5m, 1h or 1d.");
    corrRuleRefs(cr).forEach(function (r) { if (!rules.some(function (x) { return x.name === r || x.id === r; })) out.errors.push("Correlation \"" + t + "\" names rule " + r + ", which is not in this text. Give the base rule that name: or id:."); });
    if (!corrRuleRefs(cr).length) out.errors.push("Correlation \"" + t + "\" lists no rules.");
    var cond = corrCondition(cr);
    if ((c.type === "event_count" || c.type === "value_count") && !cond) out.errors.push("Correlation \"" + t + "\": condition needs gt, gte, lt, lte or eq with a number.");
    if (c.type === "value_count" && cond && !cond.field) out.errors.push("Correlation \"" + t + "\": value_count needs condition.field, the field whose distinct values are counted.");
    if (!out.errors.length) out.info.push("Correlation \"" + t + "\" (" + c.type + ", " + c.timespan + (c["group-by"] ? ", by " + [].concat(c["group-by"]).join(", ") : "") + ") is evaluated over the log set in the Test tab and converted for Splunk, Sentinel and SQL.");
  }
  function evTime(ev) {
    var t = entities(ev).time;
    if (t === undefined) return null;
    var n = Date.parse(t);
    return isNaN(n) ? null : n;
  }
  // Runs every correlation in the text over a log set. Sliding windows: a window opens at each
  // matching event and spans the timespan. Returns one result per group that meets the condition.
  function correlate(rule, events) {
    var rules = rule.__rules || [rule], out = [];
    var compiled = rules.map(function (r) { return compile(r); });
    (rule.__correlations || []).forEach(function (cr) {
      var c = cr.correlation, refs = corrRuleRefs(cr), span = spanMs(c.timespan), cond = corrCondition(cr), groupBy = [].concat(c["group-by"] || []), aliases = c.aliases || {};
      var hits = [], noTime = 0;
      events.forEach(function (ev, i) {
        refs.forEach(function (ref) {
          var k = rules.findIndex(function (x) { return x.name === ref || x.id === ref; });
          if (k < 0 || !match(compiled[k], ev).match) return;
          var t = evTime(ev); if (t === null) { noTime++; t = 0; }
          var key = groupBy.map(function (g) { var f = aliases[g] && aliases[g][ref] ? aliases[g][ref] : g; var v = getValues(ev, f); return v.length ? str(v[0]) : null; });
          hits.push({ i: i, t: t, rule: ref, key: JSON.stringify(key), group: key, ev: ev });
        });
      });
      var groups = {};
      hits.forEach(function (h) { (groups[h.key] = groups[h.key] || []).push(h); });
      var test = function (n) { if (!cond) return true; return cond.op === "gt" ? n > cond.n : cond.op === "gte" ? n >= cond.n : cond.op === "lt" ? n < cond.n : cond.op === "lte" ? n <= cond.n : cond.op === "neq" ? n !== cond.n : n === cond.n; };
      Object.keys(groups).forEach(function (gk) {
        var hs = groups[gk].sort(function (a, b) { return a.t - b.t || a.i - b.i; }), best = null;
        for (var a = 0; a < hs.length; a++) {
          var win = hs.filter(function (h) { return h.t >= hs[a].t && h.t <= hs[a].t + span; }), val, ok;
          if (c.type === "event_count") { val = win.length; ok = test(val); }
          else if (c.type === "value_count") { var seen = {}; win.forEach(function (h) { getValues(h.ev, cond.field).forEach(function (v) { seen[str(v)] = 1; }); }); val = Object.keys(seen).length; ok = test(val); }
          else {
            var present = {}; win.forEach(function (h) { present[h.rule] = present[h.rule] || h.t; });
            if (typeof c.condition === "string") ok = boolOverRules(c.condition, present);
            else ok = refs.every(function (r) { return present[r] !== undefined; });
            if (ok && c.type === "temporal_ordered") {
              var tcur = -Infinity; ok = refs.every(function (r) { var nx = win.filter(function (h) { return h.rule === r && h.t >= tcur; })[0]; if (!nx) return false; tcur = nx.t; return true; });
            }
            val = Object.keys(present).length;
          }
          if (ok && (!best || val > best.value)) best = { value: val, start: hs[a].t, end: win[win.length - 1].t, events: win.map(function (h) { return h.i; }) };
          if (ok && c.type !== "event_count" && c.type !== "value_count") break;
        }
        if (best) out.push({ correlation: cr.title || "correlation", type: c.type, group: groupBy.reduce(function (o, g, j) { o[g] = hs[0].group[j]; return o; }, {}), value: best.value, start: best.start ? new Date(best.start).toISOString() : null, end: best.end ? new Date(best.end).toISOString() : null, events: best.events });
      });
      if (noTime) out.unshift({ correlation: cr.title || "correlation", warning: noTime + " matching event(s) have no timestamp, so they were placed at time 0." });
    });
    return out;
  }
  function boolOverRules(expr, present) {
    var tk = String(expr).match(/\(|\)|[A-Za-z0-9_\-.]+/g) || [], i = 0;
    function or() { var v = and(); while (/^or$/i.test(tk[i] || "")) { i++; v = and() || v; } return v; }
    function and() { var v = not(); while (/^and$/i.test(tk[i] || "")) { i++; v = not() && v; } return v; }
    function not() { if (/^not$/i.test(tk[i] || "")) { i++; return !not(); } if (tk[i] === "(") { i++; var v = or(); i++; return v; } return present[tk[i++]] !== undefined; }
    return or();
  }

  /* ---------------- entities and structured alerts ---------------- */

  var ENTITY_FIELDS = {
    user: ["userIdentity.arn", "userIdentity.userName", "actor.alternateId", "userPrincipalName", "UserPrincipalName", "User", "user", "actor", "protoPayload.authenticationInfo.principalEmail", "data.protoPayload.authenticationInfo.principalEmail", "Initiated By", "InitiatedBy.user.userPrincipalName"],
    ip: ["sourceIPAddress", "client.ipAddress", "ipAddress", "IPAddress", "src_ip", "SourceIp", "actor_ip", "protoPayload.requestMetadata.callerIp", "data.protoPayload.requestMetadata.callerIp"],
    host: ["Computer", "Hostname", "host.name", "hostname", "ComputerName"],
    process: ["Image", "process.executable"],
    commandLine: ["CommandLine", "process.command_line"],
    cloudAccount: ["recipientAccountId", "userIdentity.accountId", "org"],
    region: ["awsRegion"],
    time: ["eventTime", "published", "createdDateTime", "TimeGenerated", "UtcTime", "@timestamp", "created_at", "timestamp"]
  };
  function entities(ev) {
    var out = {};
    Object.keys(ENTITY_FIELDS).forEach(function (k) {
      for (var i = 0; i < ENTITY_FIELDS[k].length; i++) {
        var v = getValues(ev, ENTITY_FIELDS[k][i]).filter(function (x) { return x !== null && x !== undefined && typeof x !== "object"; });
        if (v.length) { out[k] = k === "time" && typeof v[0] === "number" ? new Date(v[0] * (v[0] < 1e12 ? 1000 : 1)).toISOString() : String(v[0]); break; }
      }
    });
    return out;
  }
  function fieldsOfId(def) {
    var out = [];
    (function walk(n) { if (n.type === "leaf" && n.field) out.push(n.field); (n.children || []).forEach(walk); })(def);
    return out;
  }
  function alert(compiled, ev, res, index) {
    var r = compiled.rule, tags = [].concat(r.tags || []);
    var ev2 = {};
    res.ids.forEach(function (k) { fieldsOfId(compiled.defs[k]).forEach(function (f) { var v = getValues(ev, f); if (v.length) ev2[f] = v.length === 1 ? v[0] : v; }); });
    return {
      rule: { id: r.id || null, title: r.title || null, level: r.level || null, status: r.status || null },
      attack: tags.filter(function (t) { return /^attack\.t\d{4}/i.test(t); }).map(function (t) { return t.slice(7).toUpperCase(); }),
      tactics: tags.filter(function (t) { return TACTICS.indexOf(String(t).slice(7)) >= 0; }).map(function (t) { return t.slice(7); }),
      event_index: index,
      entities: entities(ev),
      matched: res.ids,
      evidence: ev2,
      falsepositives: [].concat(r.falsepositives || []),
      references: [].concat(r.references || [])
    };
  }

  /* ---------------- conversion ---------------- */

  // Microsoft Defender XDR advanced hunting tables (the field maps follow pySigma's
  // microsoft_xdr pipeline so both tools write the same column names).
  var XDR = {
    DeviceProcessEvents: { ProcessId: "ProcessId", Image: "FolderPath", FileVersion: "ProcessVersionInfoProductVersion", Description: "ProcessVersionInfoFileDescription", Product: "ProcessVersionInfoProductName", Company: "ProcessVersionInfoCompanyName", OriginalFileName: "ProcessVersionInfoOriginalFileName", CommandLine: "ProcessCommandLine", User: "AccountName", LogonId: "LogonId", IntegrityLevel: "ProcessIntegrityLevel", sha1: "SHA1", sha256: "SHA256", md5: "MD5", ParentProcessId: "InitiatingProcessId", ParentImage: "InitiatingProcessFolderPath", ParentCommandLine: "InitiatingProcessCommandLine", ParentUser: "InitiatingProcessAccountName", GrandParentImage: "InitiatingProcessParentFileName" },
    DeviceImageLoadEvents: { ProcessId: "InitiatingProcessId", Image: "InitiatingProcessFolderPath", ImageLoaded: "FolderPath", FileVersion: "InitiatingProcessVersionInfoProductVersion", Description: "InitiatingProcessVersionInfoFileDescription", Product: "InitiatingProcessVersionInfoProductName", Company: "InitiatingProcessVersionInfoCompanyName", OriginalFileName: "InitiatingProcessVersionInfoOriginalFileName", sha1: "SHA1", sha256: "SHA256", md5: "MD5", User: "InitiatingProcessAccountName" },
    DeviceFileEvents: { ProcessId: "InitiatingProcessId", Image: "InitiatingProcessFolderPath", TargetFilename: "FolderPath", User: "RequestAccountName", sha1: "SHA1", sha256: "SHA256", md5: "MD5", ObjectName: "FolderPath", IntegrityLevel: "InitiatingProcessIntegrityLevel" },
    DeviceNetworkEvents: { ProcessId: "InitiatingProcessId", Image: "InitiatingProcessFolderPath", User: "InitiatingProcessAccountName", Protocol: "Protocol", SourceIp: "LocalIP", SourceHostname: "DeviceName", SourcePort: "LocalPort", DestinationIp: "RemoteIP", DestinationHostname: "RemoteUrl", DestinationPort: "RemotePort" },
    DeviceRegistryEvents: { EventType: "ActionType", ProcessId: "InitiatingProcessId", Image: "InitiatingProcessFolderPath", TargetObject: "RegistryKey", Details: "RegistryValueData", User: "InitiatingProcessAccountName", ObjectName: "RegistryKey" }
  };
  var XDR_GENERIC = { EventType: "ActionType", User: "InitiatingProcessAccountName", CommandLine: "InitiatingProcessCommandLine", Image: "InitiatingProcessFolderPath", ProcessName: "InitiatingProcessFolderPath", SourceImage: "InitiatingProcessFolderPath", ProcessId: "InitiatingProcessId", md5: "InitiatingProcessMD5", sha1: "InitiatingProcessSHA1", sha256: "InitiatingProcessSHA256", ParentProcessId: "InitiatingProcessParentId", ParentCommandLine: "InitiatingProcessParentCommandLine", Company: "InitiatingProcessVersionInfoCompanyName", Description: "InitiatingProcessVersionInfoFileDescription", OriginalFileName: "InitiatingProcessVersionInfoOriginalFileName", Product: "InitiatingProcessVersionInfoProductName" };
  var XDR_CATEGORY = { process_creation: "DeviceProcessEvents", image_load: "DeviceImageLoadEvents", file_access: "DeviceFileEvents", file_change: "DeviceFileEvents", file_delete: "DeviceFileEvents", file_event: "DeviceFileEvents", file_rename: "DeviceFileEvents", registry_add: "DeviceRegistryEvents", registry_delete: "DeviceRegistryEvents", registry_event: "DeviceRegistryEvents", registry_set: "DeviceRegistryEvents", network_connection: "DeviceNetworkEvents" };

  var SENTINEL = {
    "aws/cloudtrail": { table: "AWSCloudTrail", map: { eventName: "EventName", eventSource: "EventSource", sourceIPAddress: "SourceIpAddress", userAgent: "UserAgent", errorCode: "ErrorCode", errorMessage: "ErrorMessage", awsRegion: "AWSRegion", recipientAccountId: "RecipientAccountId", eventType: "EventTypeName", readOnly: "ReadOnly", "userIdentity.type": "UserIdentityType", "userIdentity.arn": "UserIdentityArn", "userIdentity.userName": "UserIdentityUserName", "userIdentity.accountId": "UserIdentityAccountId", "userIdentity.principalId": "UserIdentityPrincipalid", "userIdentity.accessKeyId": "UserIdentityAccessKeyId", "userIdentity.invokedBy": "UserIdentityInvokedBy", "userIdentity.sessionContext.sessionIssuer.userName": "SessionIssuerUserName", "userIdentity.sessionContext.attributes.mfaAuthenticated": "SessionMfaAuthenticated", requestParameters: "RequestParameters", responseElements: "ResponseElements", additionalEventData: "AdditionalEventData" }, json: { requestParameters: "RequestParameters", responseElements: "ResponseElements", additionalEventData: "AdditionalEventData" } },
    "azure/signinlogs": { table: "SigninLogs", map: {} },
    "azure/auditlogs": { table: "AuditLogs", map: {} },
    "azure/activitylogs": { table: "AzureActivity", map: {} },
    "m365/threat_management": { table: "OfficeActivity", map: {} },
    "okta/okta": { table: "OktaV2_CL", map: {} }
  };
  // EventID -> table when the rule names no category (pySigma kusto_common EVENTID_CATEGORIES)
  var XDR_EVENTID = [["DeviceProcessEvents", [1, 5, 10, 25, 4688, 4689, 4696]], ["DeviceLogonEvents", [4624, 4625, 4634, 4647, 4648, 4778, 4779, 4800, 4801, 4802, 4803]],
    ["DeviceRegistryEvents", [4656, 4657, 4658, 4659, 4660, 4661, 4662, 4663, 12, 13, 14]], ["DeviceFileEvents", [2, 11, 15, 23, 26, 27, 28, 29]],
    ["DeviceNetworkEvents", [3, 22, 5140, 5145, 5156, 5157, 5158, 5159]], ["DeviceImageLoadEvents", [7]], ["DeviceEvents", [17, 18, 19, 20, 21]]];
  var XDR_COLUMNS = {};
  Object.keys(XDR).forEach(function (t) { Object.keys(XDR[t]).forEach(function (k) { XDR_COLUMNS[XDR[t][k]] = 1; }); });
  Object.keys(XDR_GENERIC).forEach(function (k) { XDR_COLUMNS[XDR_GENERIC[k]] = 1; });
  ["RegistryKey", "PreviousRegistryKey", "RegistryValueName", "PreviousRegistryValueName", "PreviousRegistryValueData", "ActionType", "FileName", "FolderPath", "AccountDomain", "AccountSid", "InitiatingProcessAccountDomain", "RequestAccountDomain",
    "InitiatingProcessFileName", "InitiatingProcessParentFileName", "DeviceName", "LogonType", "RemoteIPType", "InitiatingProcessIntegrityLevel", "InitiatingProcessTokenElevation", "ProcessTokenElevation", "FileOriginUrl", "FileOriginReferrerUrl"].forEach(function (c) { XDR_COLUMNS[c] = 1; });
  function xdrTableFromEventId(det) {
    var ids = [];
    (function walk(v, k) {
      if (Array.isArray(v)) v.forEach(function (x) { walk(x, k); });
      else if (v && typeof v === "object") Object.keys(v).forEach(function (kk) { walk(v[kk], kk.split("|")[0]); });
      else if (k === "EventID" && !isNaN(Number(v))) ids.push(Number(v));
    })(det, null);
    for (var i = 0; i < ids.length; i++) for (var j = 0; j < XDR_EVENTID.length; j++) if (XDR_EVENTID[j][1].indexOf(ids[i]) >= 0) return XDR_EVENTID[j][0];
    return null;
  }
  Object.keys(XDR_CATEGORY).forEach(function (c) { SENTINEL["windows/" + c] = { table: XDR_CATEGORY[c], map: XDR[XDR_CATEGORY[c]], xdr: true }; });
  function sentinelFor(ls) {
    ls = ls || {};
    var p = String(ls.product || "").toLowerCase(), s = String(ls.service || "").toLowerCase(), c = String(ls.category || "").toLowerCase();
    return SENTINEL[p + "/" + s] || SENTINEL[p + "/" + c] || null;
  }

  // Leaves built by a pipeline step (new field, new values) reuse the compiler.
  function mkLeaf(field, mods, values, base) {
    var n = leaf(field, mods, values, { errors: [], unsupported: [], fields: {} }, base ? base.id : "pipeline");
    n.mapped = true;
    return n;
  }
  function plainValue(sp) { return sp.op === "pattern" && sp.tk.every(function (x) { return x.t === "lit"; }) ? sp.tk.map(function (x) { return x.v; }).join("") : null; }
  function leafMods(n) { return n.mods.filter(function (m) { return m !== "all"; }); }

  // Defender XDR pipeline: table field maps, then the value fixes pySigma's microsoft_xdr pipeline makes
  // (Sysmon registry hive abbreviations, EventType names, DOMAIN\user, Hashes, ParentImage outside DeviceProcessEvents).
  function xdrRewrite(ast, table, notes, warn) {
    var map = XDR[table] || {};
    var DOMAIN = { AccountName: "AccountDomain", RequestAccountName: "RequestAccountDomain", InitiatingProcessAccountName: "InitiatingProcessAccountDomain" };
    var ACTION = { createkey: ["RegistryKeyCreated"], deletekey: ["RegistryKeyDeleted", "RegistryValueDeleted"], setvalue: ["RegistryValueSet"], renamekey: ["RegistryValueSet", "RegistryKeyCreated"] };
    function walk(n) {
      if (n.type === "id") { var ch = walk(n.child); return ch === null ? null : Object.assign({}, n, { child: ch }); }
      if (n.type !== "leaf") {
        if (!n.children) return n;
        var kids0 = n.children.map(walk);
        // an alternative with nothing searchable drops out of an OR; anywhere else the rule cannot be kept
        if (n.type === "or" && kids0.some(function (k) { return k !== null; })) { if (kids0.some(function (k) { return k === null; })) warn.push("Hash types with no " + table + " column (such as IMPHASH) were left out of an OR."); return Object.assign({}, n, { children: kids0.filter(function (k) { return k !== null; }) }); }
        if (kids0.some(function (k) { return k === null; })) return null;
        return Object.assign({}, n, { children: kids0 });
      }
      if (n.field === null) return n;
      var f = n.field;
      if (/^(EventID|EventCode|ObjectType)$/.test(f)) { notes.push(f + " has no column in " + table + ", so that condition was dropped; the table already selects the event type."); return { type: "and", children: [], dropped: true }; }
      if (f === "Hashes") {
        var kids = [];
        n.specs.forEach(function (sp) {
          var raw = sp.op === "pattern" ? sp.tk.filter(function (x) { return x.t === "lit"; }).map(function (x) { return x.v; }).join("") : String(sp.v || "");
          var m = raw.split("|"); if (m.length === 1) m = raw.split("=");
          var algo = "", val = raw;
          if (m.length === 2) { algo = m[0].replace(/^\*/, "").toUpperCase(); val = m[1]; }
          else algo = val.length === 32 ? "MD5" : val.length === 40 ? "SHA1" : val.length === 64 ? "SHA256" : "";
          if (/^(MD5|SHA1|SHA256)$/.test(algo)) kids.push(mkLeaf(algo, [], [val], n));
        });
        if (!kids.length) { warn.push("Hashes has no MD5, SHA1 or SHA256 value, and those are the only hash columns in " + table + "."); return null; }
        return kids.length === 1 ? kids[0] : { type: "or", children: kids };
      }
      var col = map[f] || (table !== "DeviceProcessEvents" && f === "ParentImage" ? "InitiatingProcessParentFileName" : XDR_GENERIC[f]) || (XDR_COLUMNS[f] ? f : null);
      if (!col) { warn.push("No " + table + " column for " + f + "; it is used as written."); return n; }
      var out = Object.assign({}, n, { field: col, mapped: true });
      if (col === "InitiatingProcessParentFileName" && f === "ParentImage") {
        // only the file name exists in these tables: a path value keeps what follows its last separator
        out = mkLeaf(col, [], [""], n); out.specs = []; out.mods = [];
        n.specs.forEach(function (sp) {
          if (sp.op !== "pattern") { out.specs.push(sp); return; }
          var tk = sp.tk, cut = -1;
          for (var j = tk.length - 1; j >= 0 && cut < 0; j--) if (tk[j].t === "lit" && /[\\\/]/.test(tk[j].v)) cut = j;
          if (cut < 0) { out.specs.push(sp); return; }
          var rest = tk[cut].v.split(/[\\\/]/).pop();
          pushPlain(out, (rest ? [{ t: "lit", v: rest }] : []).concat(tk.slice(cut + 1)), [], sp.cased);
        });
      }
      if (col === "RegistryKey" || col === "PreviousRegistryKey") {
        out = Object.assign({}, out, { specs: n.specs.map(function (sp) {
          if (sp.op !== "pattern" || !sp.tk.length || sp.tk[0].t !== "lit") return sp;
          var v0 = sp.tk[0].v, v1 = v0.replace(/^HKLM\\SYSTEM\\CurrentControlSet/i, "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001").replace(/^HKLM/i, "HKEY_LOCAL_MACHINE").replace(/^HKU/i, "HKEY_USERS").replace(/^HKCR/i, "HKEY_LOCAL_MACHINE\\CLASSES");
          if (v1 === v0) return sp;
          var tmp = mkLeaf(col, [], [""], n), tk = [{ t: "lit", v: v1 }].concat(sp.tk.slice(1));
          pushPlain(tmp, tk, [], sp.cased); return tmp.specs[tmp.specs.length - 1];
        }) });
      }
      if (col === "ActionType") {
        var vals = [], other = false;
        n.specs.forEach(function (sp) { var pv = plainValue(sp); if (pv !== null && ACTION[pv.toLowerCase()]) vals = vals.concat(ACTION[pv.toLowerCase()]); else other = true; });
        if (!other && vals.length) {
          var per = n.specs.map(function (sp) { var a = ACTION[plainValue(sp).toLowerCase()]; return mkLeaf(col, [], a, n); });
          return per.length === 1 ? per[0] : { type: "or", children: per };
        }
      }
      // DOMAIN\user values: Defender keeps the domain in its own column
      var isDU = function (sp) { var pv = plainValue(sp); return pv !== null && pv.split("\\").length === 2; };
      if (DOMAIN[col] && !n.all && n.mods.length === 0 && n.specs.some(isDU)) {
        var kids2 = n.specs.map(function (sp) {
          if (!isDU(sp)) return Object.assign({}, out, { specs: [sp] });
          var parts = plainValue(sp).split("\\");
          return { type: "and", children: [mkLeaf(col, [], [parts[1]], n), mkLeaf(DOMAIN[col], [], [parts[0]], n)] };
        });
        return kids2.length === 1 ? kids2[0] : { type: "or", children: kids2 };
      }
      return out;
    }
    return walk(ast);
  }

  // Sigma (PCRE-style, search anywhere) -> Lucene / Elasticsearch regex (whole value, no anchors).
  // Returns { re } or { err }. Lucene 9 (Elasticsearch 8) knows \d \s \w and their negations.
  var LUCENE_RX_RESERVED = ".?+*|{}[]()\"\\#@&<>~";
  function luceneRegex(src, flags) {
    var ic = /i/.test(flags || ""), i = 0;
    if (/m/.test(flags || "")) return { err: "Lucene regex has no multi-line mode (|re|m)." };
    var lead = /^\(\?([a-z]+)\)/.exec(src);
    if (lead) {
      if (/[^is]/.test(lead[1])) return { err: "Lucene regex has no (?" + lead[1] + ") mode." };
      if (/i/.test(lead[1])) ic = true;
      src = src.slice(lead[0].length);
    }
    function fail(msg) { throw new SigmaError(msg); }
    // parse into { alts: [[item]] }, item = {k: "lit"|"esc"|"cls"|"dot"|"grp"|"bol"|"eol", ...q}
    function parseAlts(closing) {
      var alts = [[]];
      while (i < src.length) {
        var c = src[i];
        if (c === ")") { if (closing) { i++; return alts; } fail("Unbalanced ) in the regex."); }
        if (c === "|") { alts.push([]); i++; continue; }
        var it;
        if (c === "(") {
          i++;
          if (src[i] === "?") {
            if (src[i + 1] === ":") i += 2;
            else fail("Lucene regex has no lookarounds, named groups or inline flags (" + src.slice(i - 1, i + 3) + ").");
          }
          it = { k: "grp", alts: parseAlts(true) };
        } else if (c === "[") it = parseClass();
        else if (c === "\\") {
          var n = src[i + 1]; i += 2;
          if (n === undefined) fail("The regex ends in a backslash.");
          if (/[dswDSW]/.test(n)) it = { k: "esc", v: "\\" + n };
          else if (/[bBAzZGnrtfvx0-9upPkcQE]/.test(n)) fail("Lucene regex cannot express \\" + n + ".");
          else it = { k: "lit", v: n };
        } else if (c === "^") { i++; it = { k: "bol" }; }
        else if (c === "$") { i++; it = { k: "eol" }; }
        else if (c === ".") { i++; it = { k: "dot" }; }
        else { i++; it = { k: "lit", v: c }; }
        // quantifier
        var q = /^(\*|\+|\?|\{(\d+)(,(\d*))?\})/.exec(src.slice(i));
        if (!q && src[i] === "{" && /^\{,\d+\}/.test(src.slice(i))) fail("Lucene regex has no {,n} quantifier.");
        if (q && (it.k === "bol" || it.k === "eol")) fail("A quantifier on an anchor cannot be translated.");
        if (q) {
          it.q = q[1]; i += q[1].length;
          if (src[i] === "+") fail("Lucene regex has no possessive quantifiers.");
          if (src[i] === "?") i++; // lazy and greedy select the same values
        }
        alts[alts.length - 1].push(it);
      }
      if (closing) fail("A ( in the regex is not closed.");
      return alts;
    }
    function parseClass() {
      i++;
      var neg = false, mem = [];
      if (src[i] === "^") { neg = true; i++; }
      var first = true;
      while (i < src.length && (src[i] !== "]" || first)) {
        first = false;
        var a = readClassChar();
        if (src[i] === "-" && src[i + 1] !== "]" && i + 1 < src.length) {
          i++; var b = readClassChar();
          if (a.esc || b.esc) fail("A class range with an escaped end cannot be translated.");
          mem.push({ r: [a.v, b.v] });
        } else mem.push(a);
      }
      if (src[i] !== "]") fail("A [ in the regex is not closed.");
      i++;
      return { k: "cls", neg: neg, mem: mem };
    }
    function readClassChar() {
      var c = src[i];
      if (c === "\\") {
        var n = src[i + 1]; i += 2;
        if (/[dswDSW]/.test(n)) return { v: "\\" + n, esc: true, cls: true };
        if (/[bBnrtfvx0-9upP]/.test(n)) fail("Lucene regex cannot express \\" + n + " in a class.");
        return { v: n, esc: true };
      }
      i++; return { v: c };
    }
    function letterCase(ch) {
      var lo = ch.toLowerCase(), up = ch.toUpperCase();
      if (lo === up) return null;
      if (!/[A-Za-z]/.test(ch) || lo.length !== 1 || up.length !== 1) fail("Case-insensitive matching of \"" + ch + "\" cannot be translated to Lucene.");
      return ch === lo ? up : lo;
    }
    function escLit(ch) { return LUCENE_RX_RESERVED.indexOf(ch) >= 0 || ch === "$" || ch === "^" ? "\\" + ch : ch; }
    function escCls(ch) { return /[\]\[\\^\-"]/.test(ch) ? "\\" + ch : ch; }
    function emitItem(it) {
      var s;
      if (it.k === "lit") {
        var o = ic ? letterCase(it.v) : null;
        s = o ? "[" + it.v.toLowerCase() + it.v.toUpperCase() + "]" : escLit(it.v);
      } else if (it.k === "esc") s = it.v;
      else if (it.k === "dot") s = ".";
      else if (it.k === "cls") {
        s = "[" + (it.neg ? "^" : "") + it.mem.map(function (m) {
          if (m.r) {
            var r = escCls(m.r[0]) + "-" + escCls(m.r[1]);
            if (!ic) return r;
            var a = m.r[0], b = m.r[1];
            if (/[a-z]/.test(a) && /[a-z]/.test(b)) return r + a.toUpperCase() + "-" + b.toUpperCase();
            if (/[A-Z]/.test(a) && /[A-Z]/.test(b)) return r + a.toLowerCase() + "-" + b.toLowerCase();
            var lo = a.charCodeAt(0), hi = b.charCodeAt(0);
            if (hi >= 65 && lo <= 122) fail("Case-insensitive class range " + a + "-" + b + " cannot be translated to Lucene.");
            return r;
          }
          if (m.cls) return m.v;
          var o2 = ic ? letterCase(m.v) : null;
          return escCls(m.v) + (o2 ? escCls(o2) : "");
        }).join("") + "]";
      } else if (it.k === "grp") s = "(" + it.alts.map(emitSeq).join("|") + ")";
      else fail("An anchor in the middle of the regex cannot be translated.");
      return s + (it.q || "");
    }
    function emitSeq(seq) { return seq.length ? seq.map(emitItem).join("") : "()"; }
    function unbounded(it) { return it && it.k === "dot" && it.q && (it.q === "*" || it.q === "+" || /,\}$/.test(it.q)); }
    function anchoredGroup(it, kind) { return it && it.k === "grp" && !it.q && it.alts.some(function (a) { return kind === "bol" ? a[0] && a[0].k === "bol" : a.length && a[a.length - 1].k === "eol"; }); }
    // one alternative of the whole pattern -> Lucene text
    function emitAlt(seq) {
      seq = seq.slice();
      var pre = ".*", suf = ".*", head = "", tail = "";
      if (seq[0] && seq[0].k === "bol") { pre = ""; seq.shift(); }
      else if (anchoredGroup(seq[0], "bol")) {
        var g = seq.shift(); pre = "";
        head = "(" + g.alts.map(function (a) { a = a.slice(); var p = ".*"; if (a[0] && a[0].k === "bol") { p = ""; a.shift(); } return p + "(" + (a.length ? emitSeq(a) : "") + ")"; }).join("|") + ")";
      }
      if (seq.length && seq[seq.length - 1].k === "eol") { suf = ""; seq.pop(); }
      else if (anchoredGroup(seq[seq.length - 1], "eol")) {
        var g2 = seq.pop(); suf = "";
        tail = "(" + g2.alts.map(function (a) { a = a.slice(); var s2 = ".*"; if (a.length && a[a.length - 1].k === "eol") { s2 = ""; a.pop(); } return "(" + (a.length ? emitSeq(a) : "") + ")" + s2; }).join("|") + ")";
      }
      if (!head && pre && unbounded(seq[0])) pre = "";
      if (!tail && suf && unbounded(seq[seq.length - 1])) suf = "";
      return pre + head + (seq.length || (!head && !tail) ? "(" + emitSeq(seq) + ")" : "") + tail + suf;
    }
    function lift(alts) {
      // an alternative that is one bare group is replaced by that group's alternatives
      var out = [];
      alts.forEach(function (a) { if (a.length === 1 && a[0].k === "grp" && !a[0].q) out = out.concat(lift(a[0].alts)); else out.push(a); });
      return out;
    }
    try {
      var alts = lift(parseAlts(false));
      var re = alts.length === 1 ? emitAlt(alts[0]) : alts.map(function (a) { return "(" + emitAlt(a) + ")"; }).join("|");
      return { re: re };
    } catch (e) { return { err: e.message }; }
  }

  function q(s) { return '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"'; }
  function rq(s) { return '"' + String(s).replace(/"/g, '\\"') + '"'; }
  function kv(s) { return '@"' + String(s).replace(/"/g, '""') + '"'; }
  function sq(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }
  var LUCENE_SPECIAL = /([\s+\-=&|><!(){}\[\]^"~*?:\\\/])/g;
  function lucEsc(s) { return String(s).replace(LUCENE_SPECIAL, "\\$1"); }

  function convert(compiled, target, opts) {
    opts = opts || {};
    if (!opts.base && compiled.rule.__correlations && compiled.rule.__correlations.length) return convertCorrelation(compiled.rule, target, opts);
    var warn = [], notes = [];
    var ls = compiled.rule.logsource || {};
    var sentinel = target === "kql" && opts.mapFields !== false ? sentinelFor(ls) : null;
    if (target === "kql" && opts.mapFields !== false && !sentinel && String(ls.product || "").toLowerCase() === "windows") {
      var byId = xdrTableFromEventId(compiled.rule.detection);
      if (byId) { sentinel = { table: byId, map: XDR[byId] || {}, xdr: true }; notes.push("The rule names no category; its EventID picks the Defender XDR table " + byId + "."); }
    }
    var ast = compiled.ast;
    if (sentinel && sentinel.xdr) {
      ast = xdrRewrite(ast, sentinel.table, notes, warn);
      if (ast === null) return { ok: false, query: "", warnings: uniq(warn), notes: uniq(notes) };
    }
    function fname(f, mapped) {
      if (target === "kql" && sentinel && !mapped && !sentinel.xdr) {
        if (sentinel.map[f]) return sentinel.map[f];
        var top = f.split(".")[0];
        if (sentinel.json && sentinel.json[top]) return "parse_json(" + sentinel.json[top] + ")" + f.slice(top.length).split(".").map(function (x) { return x ? "." + x : ""; }).join("");
        if (Object.keys(sentinel.map).length) warn.push("No " + sentinel.table + " column for " + f + "; it is used as written.");
      }
      if (target === "sql") return f.split(".").map(function (p) { return /^[A-Za-z_][A-Za-z0-9_]*$/.test(p) ? p : '"' + p.replace(/"/g, '""') + '"'; }).join(".");
      if (target === "kql" && !/^[A-Za-z_][A-Za-z0-9_.]*$/.test(f)) return "['" + f.replace(/'/g, "\\'") + "']";
      if (target === "lucene") return lucEsc(f);
      if (target === "spl" && /[\s"=]/.test(f)) return '"' + f.replace(/"/g, '\\"') + '"';
      return f;
    }
    var pipes = []; // SPL: top-level regex / fieldref go after the search
    var rex = [], rexNames = {}; // SPL: regexes inside OR / NOT become rex + eval conditions

    function patText(tk, kind) {
      return tk.map(function (x) {
        if (x.t === "star") return kind === "sql" ? "%" : "*";
        if (x.t === "q") { if (kind === "spl") { warn.push("SPL has no single-character wildcard; ? became *."); return "*"; } return kind === "sql" ? "_" : "?"; }
        if (kind === "lucene") return lucEsc(x.v);
        if (kind === "sql") return x.v.replace(/([\\%_])/g, "\\$1");
        if (kind === "spl" && /\*/.test(x.v)) warn.push("SPL cannot match a literal * inside a value.");
        return x.v;
      }).join("");
    }
    function tkRegex(tk) { return tk.map(function (x) { return x.t === "lit" ? reEsc(x.v) : x.t === "star" ? ".*" : "."; }).join(""); }
    function isNum(sp) { return sp.op === "pattern" && sp.num !== undefined && typeof sp.num === "number"; }
    function lucValue(sp) {
      var sh = sp.shape;
      if (sh.op === "eq") return sh.v === "" ? '""' : /\s/.test(sh.v) ? q(sh.v) : lucEsc(sh.v);
      return patText(sp.tk, "lucene");
    }

    function specExpr(field, sp, keyword, top, mapped) {
      var f = field === null ? null : fname(field, mapped);
      var o = sp.op;
      if (keyword) {
        if (o !== "pattern") { warn.push("Keyword searches only support plain values here."); return null; }
        var core = sp.tk.filter(function (x, i) { return !(x.t === "star" && (i === 0 || i === sp.tk.length - 1)); });
        if (target === "spl") return q("*" + patText(core, "spl") + "*");
        if (target === "kql") { warn.push("KQL * has \"term\" matches whole terms, so this keyword search is narrower than Sigma's substring match."); return "* has " + q(patText(core, "kql")); }
        if (target === "lucene") return "*" + patText(core, "lucene") + "*";
        warn.push("Keyword (full-text) search has no SQL equivalent; name the field instead."); return null;
      }
      // Lucene: a bare NOT inside OR turns the whole group into must-not, so negations are always bracketed
      if (o === "null") return target === "spl" ? "NOT " + f + "=*" : target === "kql" ? "isempty(" + f + ")" : target === "lucene" ? "(NOT _exists_:" + f + ")" : f + " IS NULL";
      if (o === "exists") {
        var e = target === "spl" ? f + "=*" : target === "kql" ? "isnotempty(" + f + ")" : target === "lucene" ? "_exists_:" + f : f + " IS NOT NULL";
        if (sp.v) return e;
        return target === "kql" ? "isempty(" + f + ")" : target === "sql" ? f + " IS NULL" : target === "lucene" ? "(NOT " + e + ")" : "NOT " + e;
      }
      if (/^(gt|gte|lt|lte)$/.test(o)) {
        var sym = { gt: ">", gte: ">=", lt: "<", lte: "<=" }[o];
        return target === "lucene" ? f + ":" + sym + sp.v : f + sym + sp.v;
      }
      if (o === "cidr") {
        if (target === "spl") return f + "=" + q(sp.v);
        if (target === "kql") return (sp.cidr && sp.cidr.ip.v === 6 ? "ipv6_is_in_range(" : "ipv4_is_in_range(") + f + ", " + q(sp.v) + ")";
        if (target === "lucene") return f + ":" + lucEsc(sp.v);
        return "contains(" + sq(sp.v) + ", CAST(" + f + " AS IPADDRESS))";
      }
      if (o === "re") {
        var flagsPrefix = sp.flags.indexOf("i") >= 0 && !/^\(\?[a-z]*i[a-z]*\)/.test(sp.v) ? "(?i)" : "";
        if (target === "spl") {
          // SPL strings unescape \\ before PCRE sees them, so regex backslashes are doubled (as pySigma does)
          if (top) { pipes.push("| regex " + f + "=" + q(flagsPrefix + sp.v)); return ""; }
          // pySigma's form: rex sets a named group, eval turns it into a condition field
          var base = String(field).split(".").pop().replace(/[^A-Za-z0-9_]/g, "_"), k = (rexNames[base] = (rexNames[base] || 0) + 1), sfx = k > 1 ? String(k) : "";
          rex.push("| rex field=" + f + " " + q(flagsPrefix + "(?<" + base + "Match" + sfx + ">" + sp.v + ")"));
          rex.push("| eval " + base + "Condition" + sfx + "=if(isnotnull(" + base + "Match" + sfx + "), \"true\", \"false\")");
          return "\u0001" + base + "Condition" + sfx + "=\"true\"";
        }
        if (target === "kql") return f + " matches regex " + kv(flagsPrefix + sp.v);
        if (target === "lucene") {
          var lr = luceneRegex(sp.v, sp.flags);
          if (lr.err) { warn.push(lr.err); return null; }
          return f + ":/" + lr.re.replace(/\//g, "\\/") + "/";
        }
        return "regexp_like(" + f + ", " + sq(flagsPrefix + sp.v) + ")";
      }
      if (o === "fieldref") {
        var g = fname(sp.v);
        if (target === "spl") {
          if (!top) { warn.push("A field comparison inside OR or NOT cannot be written as one SPL search."); return null; }
          var ef = "'" + field.replace(/'/g, "\\'") + "'", eg = "'" + sp.v.replace(/'/g, "\\'") + "'";
          pipes.push("| where " + (sp.sub === "eq" ? "lower(" + ef + ")=lower(" + eg + ")" : "like(lower(" + ef + "), \"" + (sp.sub === "startswith" ? "" : "%") + "\".lower(" + eg + ").\"" + (sp.sub === "endswith" ? "" : "%") + "\")")); return "";
        }
        // Kusto reads a missing column as empty, and two empty values would compare equal
        if (target === "kql") return "(isnotempty(" + f + ") and isnotempty(" + g + ") and " + (sp.sub === "eq" ? f + " =~ " + g : sp.sub === "contains" ? "indexof(tolower(" + f + "), tolower(" + g + ")) >= 0" : sp.sub === "startswith" ? "indexof(tolower(" + f + "), tolower(" + g + ")) == 0" : "tolower(" + f + ") endswith tolower(" + g + ")") + ")";
        if (target === "lucene") { warn.push("Lucene cannot compare one field with another."); return null; }
        return sp.sub === "eq" ? "lower(" + f + ") = lower(" + g + ")" : sp.sub === "contains" ? "strpos(lower(" + f + "), lower(" + g + ")) > 0" : sp.sub === "startswith" ? "starts_with(lower(" + f + "), lower(" + g + "))" : "lower(" + f + ") LIKE ('%' || lower(" + g + "))";
      }
      // pattern
      var sh = sp.shape, cs = sp.cased;
      if (target === "spl") {
        if (cs) warn.push("SPL search is case-insensitive; |cased is not preserved.");
        if (sh.op === "any") return f + "=*";
        if (isNum(sp)) return f + "=" + sp.num;
        return f + "=" + q(patText(sp.tk, "spl"));
      }
      if (target === "kql") {
        if (sh.op === "any") return "isnotempty(" + f + ")";
        if (isNum(sp)) return f + " == " + sp.num;
        if (sh.op === "eq") return f + (cs ? " == " : " =~ ") + q(sh.v);
        if (sh.op === "contains") return f + (cs ? " contains_cs " : " contains ") + q(sh.v);
        if (sh.op === "startswith") return f + (cs ? " startswith_cs " : " startswith ") + q(sh.v);
        if (sh.op === "endswith") return f + (cs ? " endswith_cs " : " endswith ") + q(sh.v);
        return f + " matches regex " + kv((cs ? "" : "(?i)") + "^" + tkRegex(sp.tk) + "$");
      }
      if (target === "lucene") {
        if (sh.op === "any") return "_exists_:" + f;
        if (cs === false) notes.push("Elastic keyword fields match case-sensitively unless the mapping normalises them.");
        return f + ":" + lucValue(sp);
      }
      // sql
      if (sh.op === "any") return f + " IS NOT NULL";
      var lf = cs ? f : "lower(" + f + ")";
      var low = function (s) { return cs ? s : s.toLowerCase(); };
      if (sh.op === "eq") return lf + " = " + sq(low(sh.v));
      return lf + " LIKE " + sq(low(patText(sp.tk, "sql"))) + " ESCAPE '\\'";
    }

    function leafExpr(n, top) {
      var keyword = n.field === null;
      var exprs = [];
      var multi = !keyword && !n.all && n.specs.length > 1;
      // lists of plain values fold into IN (SPL, KQL) or a field group (Lucene)
      if (multi && (target === "spl" || target === "kql" || target === "lucene")) {
        var f = fname(n.field, n.mapped);
        var plain = n.specs.filter(function (s) { return s.op === "pattern" && !s.cased && s.shape.op !== "any"; });
        if (target === "spl" && plain.length === n.specs.length) return { s: f + " IN (" + plain.map(function (s) { return isNum(s) ? String(s.num) : q(patText(s.tk, "spl")); }).join(", ") + ")", list: true };
        if (target === "lucene" && plain.length === n.specs.length) return { s: f + ":(" + plain.map(lucValue).join(" OR ") + ")", list: true };
        if (target === "kql") {
          var eqs = plain.filter(function (s) { return s.shape.op === "eq"; });
          if (eqs.length >= 2) {
            var allNum = eqs.every(isNum);
            var inExpr = f + (allNum ? " in (" : " in~ (") + eqs.map(function (s) { return allNum ? String(s.num) : q(s.shape.v); }).join(", ") + ")";
            var rest = n.specs.filter(function (s) { return eqs.indexOf(s) < 0; }).map(function (s) { return specExpr(n.field, s, false, false, n.mapped); });
            if (rest.some(function (e) { return e === null; })) return null;
            if (!rest.length) return { s: inExpr, list: true };
            return { s: "(" + [inExpr].concat(rest).join(" or ") + ")" };
          }
        }
      }
      var single = n.specs.length === 1 || n.all;
      n.specs.forEach(function (s) { var e = specExpr(n.field, s, keyword, top && single, n.mapped); if (e === null) exprs.push(null); else if (e !== "") exprs.push(e); });
      if (exprs.some(function (e) { return e === null; })) return null;
      if (!exprs.length) return "";
      return exprs.length === 1 ? exprs[0] : "(" + exprs.join(n.all ? AND : OR) + ")";
    }
    var AND = target === "kql" ? " and " : target === "spl" ? " " : " AND ", OR = target === "kql" ? " or " : " OR ";
    function str(x) { return x && typeof x === "object" ? x.s : x; }
    // strip id wrappers and single-child groups
    function core(n) { while (n && (n.type === "id" || ((n.type === "and" || n.type === "or") && n.children.length === 1))) n = n.type === "id" ? n.child : n.children[0]; return n; }
    function nodeExpr(n, top) {
      switch (n.type) {
        case "leaf": return leafExpr(n, top);
        case "id": return nodeExpr(n.child, top);
        case "and":
          var a = n.children.map(function (c) {
            // SPL: "selection and not filter" where the filter is one regex or field comparison becomes a pipe
            if (target === "spl" && top && c.type === "not") {
              var lf = singleLeaf(c.children[0]);
              if (lf && (lf.specs[0].op === "re" || lf.specs[0].op === "fieldref")) {
                var sp = lf.specs[0], f = fname(lf.field, lf.mapped);
                if (sp.op === "re") { pipes.push("| regex " + f + "!=" + q((sp.flags.indexOf("i") >= 0 && !/^\(\?[a-z]*i[a-z]*\)/.test(sp.v) ? "(?i)" : "") + sp.v)); return ""; }
                // eval comparisons with a missing field are null, and where drops null rows; Sigma keeps them
                var keep = pipes.length; specExpr(lf.field, sp, false, true, lf.mapped); var w = pipes.splice(keep, 1)[0];
                pipes.push("| where isnull('" + lf.field.replace(/'/g, "\\'") + "') OR isnull('" + sp.v.replace(/'/g, "\\'") + "') OR NOT (" + w.slice(8) + ")"); return "";
              }
            }
            return nodeExpr(c, top);
          });
          if (a.some(function (x) { return x === null; })) return null;
          a = a.filter(function (x) { return x !== ""; });
          if (!a.length) return "";
          if (a.length === 1) return a[0];
          // a value list inside AND is grouped, as pySigma writes it
          return "(" + a.map(function (x) { return x && typeof x === "object" && x.list ? "(" + x.s + ")" : target === "kql" && /^not\(/.test(str(x)) ? "(" + str(x) + ")" : str(x); }).join(AND) + ")";
        case "or":
          var o = n.children.map(function (c) { return nodeExpr(c, false); });
          if (o.some(function (x) { return x === null || x === ""; })) return o.some(function (x) { return x === null; }) ? null : "";
          if (!o.length) return target === "sql" ? "FALSE" : target === "kql" ? "false" : "NOT *";
          return o.length === 1 ? o[0] : "(" + o.map(str).join(OR) + ")";
        case "not":
          var inner = core(n.children[0]);
          if (inner && inner.type === "not") return nodeExpr(inner.children[0], top); // not not x
          if (inner && inner.type === "leaf" && inner.specs.length === 1 && inner.field !== null && (inner.specs[0].op === "null" || inner.specs[0].op === "exists")) {
            var sp0 = inner.specs[0];
            return specExpr(inner.field, sp0.op === "null" ? { op: "exists", v: true } : { op: "exists", v: !sp0.v }, false, false, inner.mapped);
          }
          var ie = nodeExpr(n.children[0], false);
          if (ie === null || ie === "") return null;
          var is = str(ie);
          if (target === "kql") return "not(" + stripParens(is) + ")";
          if (target === "sql") return "NOT COALESCE((" + stripParens(is) + "), FALSE)"; // a missing field makes the filter false, not NULL
          if (target === "lucene") return { s: "(NOT " + is + ")", neg: true };
          return "NOT " + (/^\(/.test(is) || !/\s/.test(is) || /^[^\s]+=("[^"]*"|\S+)$/.test(is) || /^\S+ IN \(/.test(is) ? is : "(" + is + ")");
        case "nof":
          warn.push("\"" + n.of + "\" needs at least " + n.n + " identifiers to match; this backend gets an OR, which is broader.");
          return nodeExpr({ type: "or", children: n.children }, false);
      }
      return null;
    }
    function stripParens(s) { return /^\(.*\)$/.test(s) && balanced(s.slice(1, -1)) ? s.slice(1, -1) : s; }
    function singleLeaf(n) {
      while (n && n.type !== "leaf") {
        if (n.type === "id") n = n.child;
        else if ((n.type === "and" || n.type === "or") && n.children.length === 1) n = n.children[0];
        else return null;
      }
      return n && n.specs.length === 1 && n.field ? n : null;
    }
    var expr = nodeExpr(ast, true);
    if (expr === null) return { ok: false, query: "", warnings: uniq(warn), notes: uniq(notes) };
    expr = str(expr);
    if (target === "lucene") expr = String(expr).replace(/^\(NOT ([\s\S]*)\)$/, function (m, x) { return balanced(x) ? "NOT " + x : m; });
    expr = stripParens(String(expr));
    var query;
    if (target === "spl") {
      if (rex.length) {
        // split the top-level AND: parts without a rex condition stay in the base search
        var parts = splitTop(expr), base = parts.filter(function (p) { return p.indexOf("\u0001") < 0; }), rest = parts.filter(function (p) { return p.indexOf("\u0001") >= 0; });
        query = (base.join(" ") || "*") + "\n" + rex.join("\n") + "\n| search " + rest.join(" ").replace(/\u0001/g, "") + (pipes.length ? "\n" + pipes.join("\n") : "");
      } else query = (expr || "*") + (pipes.length ? "\n" + pipes.join("\n") : "");
      // rule "fields:" become the table columns, as pySigma writes them
      var rf = [].concat(compiled.rule.fields || []).filter(function (x) { return typeof x === "string" && x; });
      if (rf.length && !opts.base) query += (pipes.length || rex.length ? "\n| table " : " | table ") + rf.map(function (x) { return fname(x); }).join(",");
    } else if (target === "kql") {
      var table = sentinel ? sentinel.table : "<table>";
      if (!sentinel && opts.mapFields !== false) notes.push("No Microsoft Sentinel table is mapped for this log source; replace <table> and check field names.");
      query = table + "\n| where " + (expr || "true");
      if (sentinel && sentinel.table === "AWSCloudTrail") notes.push("Field names were mapped to the AWSCloudTrail table. Nested request and response fields are read with parse_json().");
      if (sentinel && !sentinel.xdr && !Object.keys(sentinel.map).length) notes.push("Table name only: field names are kept as the rule writes them, so check them against your " + sentinel.table + " schema.");
      if (sentinel && sentinel.xdr) notes.push("Field names were mapped to Defender XDR " + sentinel.table + " (the column names pySigma's microsoft_xdr pipeline uses).");
    } else if (target === "lucene") query = expr || "*";
    else {
      var aws = String(ls.product || "").toLowerCase() === "aws";
      query = "SELECT *\nFROM " + (aws ? "$EDS_ID" : "<table>") + "\nWHERE " + (expr || "TRUE");
      if (aws) notes.push("Written for CloudTrail Lake (replace $EDS_ID with your event data store ID). The same WHERE clause runs in Athena over a CloudTrail table.");
      else notes.push("Trino / Athena SQL. Replace <table> with your table.");
    }
    return { ok: true, query: query, warnings: uniq(warn), notes: uniq(notes) };
  }
  // Correlation rules: each base rule converts on its own, then the target's aggregation is added.
  // SPL follows pySigma's splunk output (bin, stats, search); KQL uses summarize; SQL uses GROUP BY.
  function convertCorrelation(rule, target, opts) {
    var cr = rule.__correlations[0], c = cr.correlation, refs = corrRuleRefs(cr), span = String(c.timespan), ms = spanMs(span), cond = corrCondition(cr);
    var groupBy = [].concat(c["group-by"] || []), aliases = c.aliases || {}, warn = [], notes = [];
    if (rule.__correlations.length > 1) notes.push("Only the first of " + rule.__correlations.length + " correlations in this text is converted.");
    if (target === "lucene") return { ok: false, query: "", warnings: ["A Lucene query string cannot count or group events. Use ES|QL or EQL for this correlation."], notes: [] };
    var bases = refs.map(function (ref) {
      var r = (rule.__rules || []).filter(function (x) { return x.name === ref || x.id === ref; })[0];
      if (!r) return null;
      var out = convert(compile(r), target, Object.assign({}, opts, { base: true }));
      out.warnings.forEach(function (w) { warn.push(w); });
      return out.ok ? { ref: ref, q: out.query, rule: r } : null;
    });
    if (!bases.length || bases.some(function (b) { return b === null; })) return { ok: false, query: "", warnings: uniq(warn.concat(["A base rule of this correlation is missing or does not convert."])), notes: [] };
    var OPS = { gt: ">", gte: ">=", lt: "<", lte: "<=", eq: "=", neq: "!=" };
    var temporal = c.type === "temporal" || c.type === "temporal_ordered", ext = temporal && typeof c.condition === "string";
    if (c.type === "temporal_ordered") warn.push("The order of events is not checked by this " + target.toUpperCase() + " query, so it is broader than temporal_ordered.");
    var metric = c.type === "event_count" ? "event_count" : c.type === "value_count" ? "value_count" : ext ? "event_types" : "event_type_count";
    var thr = temporal ? { op: "gte", n: refs.length } : cond;
    var renames = function (ref) { return Object.keys(aliases).filter(function (a) { return aliases[a] && aliases[a][ref]; }).map(function (a) { return [aliases[a][ref], a]; }); };
    var q;
    if (target === "spl") {
      var src = bases.length === 1 && !temporal ? bases[0].q : "| multisearch\n" + bases.map(function (b) {
        return "[ search " + b.q.replace(/^\*\n/, "* ") + ' | eval event_type="' + b.ref + '"' + renames(b.ref).map(function (r) { return " | rename " + r[0] + " as " + r[1]; }).join("") + " ]";
      }).join("\n");
      var agg = c.type === "event_count" ? "count as event_count" : c.type === "value_count" ? "dc(" + cond.field + ") as value_count" : ext ? "values(event_type) as event_types" : "dc(event_type) as event_type_count";
      var test = ext ? c.condition.replace(/[A-Za-z0-9_\-.]+/g, function (w) { return /^(and|or|not)$/i.test(w) ? (/^not$/i.test(w) ? "NOT" : /^or$/i.test(w) ? "OR" : "") : 'event_types="' + w + '"'; }).replace(/\s+/g, " ").trim()
        : metric + " " + OPS[thr.op] + " " + thr.n;
      // base rules' fields: carry through the aggregation, as pySigma does
      var keepF = []; bases.forEach(function (b) { [].concat(b.rule.fields || []).forEach(function (f) { if (typeof f === "string" && keepF.indexOf(f) < 0) keepF.push(f); }); });
      if (keepF.length) agg += " " + keepF.map(function (f) { return "values(" + f + ") as " + f; }).join(" ");
      q = src + "\n| bin _time span=" + span + "\n| stats " + agg + " by _time" + (groupBy.length ? " " + groupBy.join(" ") : "") + "\n| search " + test;
    } else if (target === "kql") {
      var tcol = bases.some(function (b) { return /^Device\w+Events\n/.test(b.q); }) ? "Timestamp" : "TimeGenerated";
      var srcK = bases.length === 1 && !temporal ? bases[0].q : "union\n" + bases.map(function (b) {
        return "  (" + b.q.replace(/\n/g, " ") + ' | extend event_type = "' + b.ref + '"' + renames(b.ref).map(function (r) { return " | extend " + r[1] + " = " + r[0]; }).join("") + ")";
      }).join(",\n");
      var aggK = c.type === "event_count" ? "event_count = count()" : c.type === "value_count" ? "value_count = dcount(" + cond.field + ")" : ext ? "event_types = make_set(event_type)" : "event_type_count = dcount(event_type)";
      var testK = ext ? c.condition.replace(/[A-Za-z0-9_\-.]+/g, function (w) { return /^(and|or|not)$/i.test(w) ? w.toLowerCase() : 'set_has_element(event_types, "' + w + '")'; }).replace(/not (set_has_element\([^)]*\))/g, "not($1)")
        : metric + " " + (thr.op === "eq" ? "==" : OPS[thr.op]) + " " + thr.n;
      q = srcK + "\n| summarize " + aggK + " by bin(" + tcol + ", " + span + ")" + groupBy.map(function (g) { return ", " + g; }).join("") + "\n| where " + testK;
      notes.push("Windows are fixed " + span + " bins on " + tcol + ", as Splunk's bin does; a burst that straddles two bins can be split.");
    } else {
      var aws = String((rule.logsource || {}).product || "").toLowerCase() === "aws", tc = aws ? "eventTime" : '"timestamp"', secs = Math.round(ms / 1000);
      if (!aws) notes.push("Replace \"timestamp\" with your table's event time column.");
      var win = "from_unixtime(floor(to_unixtime(" + tc + ") / " + secs + ") * " + secs + ")";
      var gcols = groupBy.map(function (g) { return g.split(".").map(function (p) { return /^[A-Za-z_][A-Za-z0-9_]*$/.test(p) ? p : '"' + p + '"'; }).join("."); });
      var aggS = c.type === "event_count" ? "COUNT(*)" : c.type === "value_count" ? "COUNT(DISTINCT " + cond.field + ")" : "COUNT(DISTINCT event_type)";
      var from = bases.length === 1 && !temporal ? bases[0].q.replace(/^SELECT \*\n/, "") : "(\n" + bases.map(function (b) { return b.q.replace(/^SELECT \*/, "SELECT *, '" + b.ref + "' AS event_type"); }).join("\nUNION ALL\n") + "\n) AS matched";
      if (ext) warn.push("The extended temporal condition is checked as \"every rule seen\" in SQL, which is broader when it uses not.");
      q = "SELECT " + gcols.map(function (g) { return g + ", "; }).join("") + win + " AS window_start, " + aggS + " AS " + (temporal ? "event_type_count" : metric) + "\n" + (bases.length === 1 && !temporal ? from : "FROM " + from) + "\nGROUP BY " + gcols.concat([win]).join(", ") + "\nHAVING " + aggS + " " + (thr.op === "eq" ? "=" : thr.op === "neq" ? "<>" : OPS[thr.op]) + " " + thr.n;
    }
    notes.push("Correlation \"" + (cr.title || "correlation") + "\": " + c.type + " over " + span + (groupBy.length ? " by " + groupBy.join(", ") : "") + ".");
    return { ok: true, query: q, warnings: uniq(warn), notes: uniq(notes) };
  }

  // split an SPL expression on its top-level implicit AND; an expression with a top-level OR stays whole
  function splitTop(s) {
    var out = [], d = 0, inq = false, cur = "";
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (c === '"' && s[i - 1] !== "\\") inq = !inq;
      if (!inq) { if (c === "(") d++; else if (c === ")") d--; }
      if (!inq && d === 0 && c === " ") {
        if (/^OR /.test(s.slice(i + 1))) return [s];
        if (/(^|\s)NOT$/.test(cur)) { cur += c; continue; }
        if (cur) out.push(cur);
        cur = ""; continue;
      }
      cur += c;
    }
    if (cur) out.push(cur);
    return out;
  }
  function balanced(s) {
    var d = 0, inq = false;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (c === '"' && s[i - 1] !== "\\") inq = !inq;
      if (inq) continue;
      if (c === "(") d++; else if (c === ")") { d--; if (d < 0) return false; }
    }
    return d === 0;
  }
  function uniq(a) { return a.filter(function (x, i) { return a.indexOf(x) === i; }); }

  /* ---------------- log input ---------------- */

  // EVTX exported as JSON (evtx_dump, Chainsaw, python-evtx): {"Event": {"System": {...}, "EventData": {...}}}.
  // Sigma rules name the EventData fields directly, the way Sysmon and THOR present them, so they are
  // lifted to the top level (spaces removed from names, as in "New Value") with EventID, Channel,
  // Computer and Provider_Name from System.
  function isEvtx(ev) { return !!(ev && typeof ev === "object" && ev.Event && typeof ev.Event === "object" && ev.Event.System); }
  function flattenEvtx(raw) {
    var E = raw.Event || raw, sys = E.System || {}, out = {};
    var txt = function (v) { return v && typeof v === "object" && !Array.isArray(v) && "#text" in v ? v["#text"] : v; };
    function put(o) {
      if (!o || typeof o !== "object") return;
      if (Array.isArray(o.Data)) { o.Data.forEach(function (d) { if (d && d["#attributes"] && d["#attributes"].Name) out[d["#attributes"].Name] = d["#text"] === undefined ? "" : d["#text"]; }); return; }
      Object.keys(o).forEach(function (k) { if (k !== "#attributes") out[k.replace(/\s+/g, "")] = txt(o[k]); });
    }
    put(E.EventData);
    if (E.UserData && typeof E.UserData === "object") Object.keys(E.UserData).forEach(function (k) { put(E.UserData[k]); });
    out.EventID = txt(sys.EventID); out.Channel = sys.Channel; out.Computer = sys.Computer;
    if (sys.Provider && sys.Provider["#attributes"]) out.Provider_Name = sys.Provider["#attributes"].Name;
    if (sys.TimeCreated && sys.TimeCreated["#attributes"] && !out.UtcTime) out.UtcTime = sys.TimeCreated["#attributes"].SystemTime;
    return out;
  }
  // JSON array, NDJSON, a single object, or a wrapper like {"Records":[...]} / {"value":[...]}.
  function parseLogs(text) {
    var r = parseLogsRaw(text);
    if (r.events.length && r.events.every(isEvtx)) { r.events = r.events.map(flattenEvtx); r.format += ", EVTX JSON flattened"; }
    return r;
  }
  function parseLogsRaw(text) {
    text = String(text || "").trim();
    if (!text) return { events: [], format: "empty" };
    try {
      var v = JSON.parse(text);
      if (Array.isArray(v)) return { events: v, format: "JSON array" };
      if (v && typeof v === "object") {
        var wrap = ["Records", "records", "value", "events", "Events", "data", "hits"];
        for (var i = 0; i < wrap.length; i++) if (Array.isArray(v[wrap[i]])) return { events: v[wrap[i]], format: "JSON " + wrap[i] + " array" };
        if (v.hits && Array.isArray(v.hits.hits)) return { events: v.hits.hits.map(function (h) { return h._source || h; }), format: "Elasticsearch hits" };
        return { events: [v], format: "single JSON object" };
      }
    } catch (e) { /* fall through to NDJSON */ }
    var lines = text.split(/\r?\n/).filter(function (l) { return l.trim(); }), events = [], bad = 0, firstBad = 0;
    lines.forEach(function (l, i) {
      try { var o = JSON.parse(l); if (o && typeof o === "object") events.push(o); else { bad++; firstBad = firstBad || i + 1; } }
      catch (e) { bad++; firstBad = firstBad || i + 1; }
    });
    if (!events.length) return { events: [], format: "unreadable", error: "Logs must be JSON: an array, one object per line, or a {\"Records\": [...]} export." };
    return { events: events, format: "NDJSON", skipped: bad, firstBad: firstBad };
  }

  /* ---------------- SigmaHQ live index ---------------- */

  var SIGMAHQ = { list: "https://data.jsdelivr.com/v1/packages/gh/SigmaHQ/sigma@master?structure=flat", raw: "https://cdn.jsdelivr.net/gh/SigmaHQ/sigma@master/", web: "https://github.com/SigmaHQ/sigma/blob/master/" };
  var _index = null;
  function sigmahqIndex() {
    if (_index) return _index;
    _index = fetch(SIGMAHQ.list).then(function (r) { if (!r.ok) throw new Error("SigmaHQ list HTTP " + r.status); return r.json(); }).then(function (d) {
      return d.files.map(function (f) { return f.name.replace(/^\//, ""); }).filter(function (p) { return /^rules[^/]*\/.*\.ya?ml$/.test(p); });
    }).catch(function (e) { _index = null; throw e; });
    return _index;
  }
  function sigmahqRule(path) {
    // jsDelivr's listing can run ahead of its file cache; GitHub raw is the fallback.
    return fetch(SIGMAHQ.raw + path).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.text(); })
      .catch(function () { return fetch("https://raw.githubusercontent.com/SigmaHQ/sigma/master/" + path).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status + " for " + path); return r.text(); }); });
  }


  /* ---------------- autofix ---------------- */

  // Text-level repairs for the lint findings that have one right answer. Edits keep the
  // author's layout and comments; anything that needs judgement is left alone.
  function uuid() {
    if (root.crypto && root.crypto.randomUUID) return root.crypto.randomUUID();
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) { var r = Math.random() * 16 | 0; return (c === "x" ? r : (r & 3 | 8)).toString(16); });
  }
  function fix(text, today) {
    var out = String(text), applied = [], rule;
    try { rule = parse(out); } catch (e) { return { text: out, applied: [] }; }
    // 1. misspelled modifiers inside keys
    Object.keys(WRONG_MODS).forEach(function (bad) {
      var good = WRONG_MODS[bad];
      if (/^[a-z]+$/.test(good)) {
        var rx = new RegExp("\\|" + bad + "(?=[|:])", "g");
        if (rx.test(out)) { out = out.replace(rx, "|" + good); applied.push("|" + bad + " became |" + good); }
      } else if (bad === "lowercase" || bad === "nocase" || bad === "equals" || bad === "eq") {
        var rx2 = new RegExp("\\|" + bad + "(?=[|:])", "g");
        if (rx2.test(out)) { out = out.replace(rx2, ""); applied.push("Removed |" + bad + ", which Sigma does not have"); }
      }
    });
    // 2. field name case against the known schema
    var sc = schemaFor(rule.logsource);
    if (sc) {
      var c0 = compile(rule);
      c0.fields.forEach(function (f) {
        if (fieldKnown(sc, f)) {
          var exact = sc.fields.filter(function (x) { return x.toLowerCase() === f.toLowerCase(); })[0];
          if (exact && exact !== f) {
            var rx3 = new RegExp("^(\\s+)" + reEsc(f) + "(?=[|:])", "gm");
            out = out.replace(rx3, "$1" + exact); applied.push(f + " became " + exact + ", the field's real spelling");
          }
        }
      });
    }
    // several YAML documents (base rules, correlations, filters): text edits that insert or rewrite
    // lines could land in the wrong document, so only the in-place renames above and the tag case below run
    var multi = (rule.__rules || []).length > 1 || (rule.__correlations || []).length || (rule.__filters || []).length;
    // 3. "1 of them" that swallows filters
    var det = multi ? {} : rule.detection || {}, cond = typeof det.condition === "string" ? det.condition : null;
    if (cond && /\b(1|any|all) of them\b/.test(cond)) {
      var ids = Object.keys(det).filter(function (k) { return k !== "condition" && k !== "timeframe"; });
      var filters = ids.filter(function (k) { return /^filter/i.test(k); }), sels = ids.filter(function (k) { return !/^filter/i.test(k); });
      if (filters.length && sels.length) {
        var q = cond.match(/\b(1|any|all) of them\b/)[1];
        var selPart = sels.length === 1 ? sels[0] : (q === "all" ? "all of " : "1 of ") + commonGlob(sels);
        var nc = cond.replace(/\b(1|any|all) of them\b/, selPart + " and not " + (filters.length === 1 ? filters[0] : "1 of " + commonGlob(filters)));
        out = out.replace(/^(\s*condition:\s*)(['"]?)(.*?)\2\s*$/m, function (m, pre) { return pre + nc; });
        applied.push("Condition rewritten to \"" + nc + "\" so the filters exclude");
      }
    }
    // 4. attack tags in upper case
    out = out.replace(/^(\s*-\s*)(attack\.[A-Za-z0-9.\-]+)\s*$/gm, function (m, pre, tag) {
      if (tag !== tag.toLowerCase()) { applied.push(tag + " became " + tag.toLowerCase()); return pre + tag.toLowerCase(); }
      return m;
    });
    if (multi) return { text: out, applied: applied };
    // 5. missing metadata, inserted after the title line
    var add = [];
    if (!rule.id) { add.push("id: " + uuid()); applied.push("Added a new id"); }
    if (!rule.status) { add.push("status: experimental"); applied.push("Added status: experimental"); }
    if (!rule.description) { add.push("description: " + JSON.stringify("Detects " + String(rule.title || "this activity").replace(/^detects?\s+/i, ""))); applied.push("Added a placeholder description to edit"); }
    if (!rule.date) { add.push("date: " + (today || new Date().toISOString().slice(0, 10))); applied.push("Added today's date"); }
    if (add.length) {
      if (/^title:.*$/m.test(out)) out = out.replace(/^title:.*$/m, function (m) { return m + "\n" + add.join("\n"); });
      else out = add.join("\n") + "\n" + out;
    }
    if (!rule.level) { out = out.replace(/\s*$/, "\nlevel: medium\n"); applied.push("Added level: medium"); }
    if (!rule.falsepositives) { out = out.replace(/\s*$/, "\nfalsepositives:\n  - Unknown\n"); applied.push("Added falsepositives: Unknown"); }
    return { text: out, applied: applied };
  }
  function commonGlob(names) {
    var p = names[0];
    names.forEach(function (n) { while (n.indexOf(p) !== 0) p = p.slice(0, -1); });
    return p ? p + "*" : "them";
  }

  /* ---------------- draft a rule from an event ---------------- */

  function leaves(ev, prefix, out) {
    out = out || [];
    Object.keys(ev || {}).forEach(function (k) {
      if (k === "_expect") return;
      var v = ev[k], path = prefix ? prefix + "." + k : k;
      if (v !== null && typeof v === "object" && !Array.isArray(v)) leaves(v, path, out);
      else if (Array.isArray(v)) { if (v.length && typeof v[0] !== "object") out.push({ path: path, value: v[0] }); }
      else if (v !== null && v !== undefined && v !== "") out.push({ path: path, value: v });
    });
    return out;
  }
  function guessLogsource(ev) {
    if ("eventSource" in ev && "eventName" in ev) return { product: "aws", service: "cloudtrail" };
    if ("eventType" in ev && "actor" in ev) return { product: "okta", service: "okta" };
    if ("Image" in ev && "CommandLine" in ev) return { product: "windows", category: "process_creation" };
    if ("action" in ev && ("org" in ev || "actor" in ev)) return { product: "github", service: "audit" };
    if ("userPrincipalName" in ev || "UserPrincipalName" in ev) return { product: "azure", service: "signinlogs" };
    return { product: "your_product" };
  }
  function yq(v) {
    var s = String(v);
    return /^[A-Za-z0-9_.@\-\/]+$/.test(s) && !/^(true|false|null|yes|no|on|off|~|\d+(\.\d+)?)$/i.test(s) ? s : "'" + s.replace(/\\(?=[*?\\])/g, "\\\\").replace(/([*?])/g, "\\$1").replace(/'/g, "''") + "'";
  }
  // picks: [{path, value, mode: "eq"|"contains"|"startswith"|"endswith"}]
  function draft(ev, picks, meta) {
    meta = meta || {};
    var ls = guessLogsource(ev), lines = [];
    lines.push("title: " + (meta.title || "Draft rule"), "id: " + uuid(), "status: experimental",
      "description: " + JSON.stringify(meta.description || "Drafted from one event. Generalise the values before it ships."),
      "author: " + (meta.author || "you"), "date: " + new Date().toISOString().slice(0, 10), "logsource:");
    Object.keys(ls).forEach(function (k) { lines.push("  " + k + ": " + ls[k]); });
    lines.push("detection:", "  selection:");
    picks.forEach(function (p) {
      var v = p.mode === "eq" ? p.value : String(p.value);
      lines.push("    " + p.path + (p.mode && p.mode !== "eq" ? "|" + p.mode : "") + ": " + yq(v));
    });
    lines.push("  condition: selection", "falsepositives:", "  - Unknown", "level: medium");
    return lines.join("\n") + "\n";
  }

  // Shared convert path for every page that converts (Sigma tester Convert tab,
  // the Sigma Converter entry page, the Detection Workbench). One target list,
  // one default option set, so the pages cannot drift apart.
  var TARGETS = [
    { k: "spl", name: "Splunk SPL", short: "Splunk" },
    { k: "kql", name: "Microsoft Sentinel KQL", short: "Sentinel" },
    { k: "lucene", name: "Elastic Lucene", short: "Elastic" },
    { k: "sql", name: "Athena / CloudTrail Lake SQL", short: "SQL" }
  ];
  function convertOpts(opts) { opts = opts || {}; return { mapFields: opts.mapFields !== false }; }
  function convertTo(compiled, target, opts) { return convert(compiled, target, convertOpts(opts)); }
  function convertAll(compiled, opts) { return TARGETS.map(function (t) { return { t: t, out: convertTo(compiled, t.k, opts) }; }); }

  var api = { TARGETS: TARGETS, convertTo: convertTo, convertAll: convertAll, fix: fix, draft: draft, leaves: leaves, guessLogsource: guessLogsource, parse: parse, compile: compile, match: match, lint: lint, convert: convert, parseLogs: parseLogs, entities: entities, alert: alert, getValues: getValues,
    correlate: correlate, spanMs: spanMs, flattenEvtx: flattenEvtx,
    sigmahqIndex: sigmahqIndex, sigmahqRule: sigmahqRule, SIGMAHQ: SIGMAHQ, schemaFor: schemaFor, sentinelFor: sentinelFor, SENTINEL: SENTINEL, XDR: XDR, luceneRegex: luceneRegex, SigmaError: SigmaError, _inCidr: function (ip, c) { return inCidr(ip, parseCidr(c)); } };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.Sigma = api;
})(typeof window !== "undefined" ? window : globalThis);
