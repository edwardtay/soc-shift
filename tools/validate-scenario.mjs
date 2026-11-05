#!/usr/bin/env node
// Validate a SOC Shift scenario folder. No dependencies.
//   node tools/validate-scenario.mjs app/scenarios/kestrel-ledger
//   node tools/validate-scenario.mjs app/scenarios/kestrel-ledger --seed 7 --seed 12345   # also check seeded variants
// Exit code 0 when every check passes, 1 otherwise. The format is documented in docs/SCENARIOS.md.
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import fs from "node:fs";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const APP = path.join(ROOT, "app");

globalThis.jsyaml = require(path.join(APP, "vendor/js-yaml.min.js"));
globalThis.Sigma = require(path.join(APP, "vendor/sigma.js"));
const SOC = require(path.join(APP, "js/engine.js"));
const ATTACK = JSON.parse(fs.readFileSync(path.join(APP, "vendor/attack.json"), "utf8"));

// Address space a scenario may use without listing it as a real-world anchor.
const SYNTHETIC_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];
const EXAMPLE_DOMAIN = /(^|\.)(example|test|invalid|localhost)$|(^|\.)example\.(com|org|net)$/i;

function ipToInt(ip) { return ip.split(".").reduce((a, o) => a * 256 + +o, 0); }
function inCidr(ip, cidr) { const [base, bits] = cidr.split("/"); const size = 2 ** (32 - +bits); const b = ipToInt(base); const v = ipToInt(ip); return v >= b && v < b + size; }
function luhn(d) { let s = 0, alt = false; for (let i = d.length - 1; i >= 0; i--) { let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9; } s += n; alt = !alt; } return s % 10 === 0; }

export function validate(dir, opts = {}) {
  const seed = Math.floor(+opts.seed || 0);
  const results = [];
  const ok = (cond, msg) => { results.push({ ok: !!cond, msg }); return !!cond; };
  const abs = path.resolve(dir);
  const file = path.join(abs, "scenario.js");
  if (!ok(fs.existsSync(file), "scenario.js exists in " + dir)) return results;

  delete require.cache[file];
  let scn;
  try { scn = require(file); } catch (e) { ok(false, "scenario.js loads: " + e.message); return results; }
  ok(scn && typeof scn === "object", "scenario.js exports an object (module.exports in node)");
  const src = fs.readFileSync(file, "utf8");
  const src0 = JSON.stringify(scn);

  // ---- shape
  ok(scn.schema === 1, "schema is 1");
  ok(scn.id === path.basename(abs), "id '" + scn.id + "' matches the folder name '" + path.basename(abs) + "'");
  ok(/^[a-z0-9][a-z0-9-]*$/.test(scn.id || ""), "id is lowercase letters, digits and hyphens");
  ok(typeof scn.title === "string" && scn.title.length > 0, "title is set");
  const sh = scn.estate && scn.estate.shift;
  ok(sh && /^\d{4}-\d{2}-\d{2}$/.test(sh.date) && /^\d{2}:\d{2}$/.test(sh.startUtc) && /^\d{2}:\d{2}$/.test(sh.endUtc) && sh.name && sh.from && sh.to, "estate.shift has date, startUtc, endUtc, name, from and to");
  ok(sh && sh.startUtc < sh.endUtc, "shift ends after it starts on the same UTC date");
  ok(Array.isArray(scn.events) && scn.events.length > 0, "events is a non-empty list (" + (scn.events || []).length + ")");
  ok(Array.isArray(scn.rules), "rules is a list");

  // ---- optional blocks: alert delays, observable defaults, seeded variants
  const PLATFORMS = new Set([...(scn.rules || []), ...(scn.correlations || [])].map((r) => r.platform));
  if (scn.alertDelayMinutes !== undefined) {
    const d = scn.alertDelayMinutes;
    ok(d && typeof d === "object" && Object.entries(d).every(([k, v]) => Number.isFinite(v) && v >= 0 && v <= 120), "alertDelayMinutes maps platforms to 0 to 120 minutes");
    ok(Object.keys(d || {}).every((k) => PLATFORMS.has(k)), "alertDelayMinutes names only platforms the rules use (" + [...PLATFORMS].join(", ") + ")");
  }
  for (const r of scn.rules || []) if (r.delayMinutes !== undefined) ok(Number.isFinite(r.delayMinutes) && r.delayMinutes >= 0 && r.delayMinutes <= 120, r.id + " delayMinutes is 0 to 120");
  if (scn.observables !== undefined) {
    const o = scn.observables || {};
    ok(!o.notIoc || (Array.isArray(o.notIoc) && o.notIoc.every((x) => typeof x === "string" && x)), "observables.notIoc is a list of values");
    for (const side of ["external", "internal"]) if (o[side]) ok(SOC.TLP[o[side].tlp] !== undefined && SOC.PAP[o[side].pap] !== undefined, "observables." + side + " has a TLP 2.0 level (" + Object.keys(SOC.TLP).join(", ") + ") and a PAP level (" + Object.keys(SOC.PAP).join(", ") + ")");
  }
  if (scn.variants !== undefined) {
    const v = scn.variants || {};
    const cidrOk = (c) => /^\d{1,3}(\.\d{1,3}){3}\/(\d|[12]\d|2[0-9])$/.test(c) && SOC.inCidr(c.split("/")[0], c) && +c.split("/")[1] <= 29;
    ok(Array.isArray(v.ipPools || []) && (v.ipPools || []).every(cidrOk), "variants.ipPools are IPv4 CIDR ranges of /29 or wider");
    ok((v.ipPools || []).every((c) => SYNTHETIC_V4.some((s) => SOC.inCidr(c.split("/")[0], s))), "variants.ipPools sit inside private or documentation ranges");
    ok(Array.isArray(v.idPools || []) && (v.idPools || []).every((p) => Array.isArray(p.prefixes) && p.prefixes.length && p.prefixes.every((x) => typeof x === "string" && x) && Number.isInteger(p.digits) && p.digits >= 2 && p.digits <= 9), "variants.idPools have prefixes and 2 to 9 digits");
    const anchorIps = ((scn.anchors || {}).ips) || [];
    ok(!anchorIps.some((ip) => (v.ipPools || []).some((c) => SOC.inCidr(ip, c))), "no real-world anchor sits inside a variant pool");
  }

  // ---- events: timestamps and order as authored
  const tsRe = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
  const badTs = (scn.events || []).filter((e) => !tsRe.test(e._t || ""));
  ok(!badTs.length, "every event has _t as UTC ISO time ending in Z" + (badTs.length ? " (first bad: " + JSON.stringify(badTs[0]._t) + ")" : ""));
  ok((scn.events || []).every((e) => typeof e._src === "string" && e._src), "every event has a _src log source");
  let sorted = true; for (let i = 1; i < (scn.events || []).length; i++) if (scn.events[i]._t < scn.events[i - 1]._t) { sorted = false; ok(false, "timeline sorted: event " + i + " (" + scn.events[i]._t + ") comes before the one above it"); break; }
  if (sorted) ok(true, "timeline is sorted by _t");
  ok((scn.events || []).some((e) => sh && e._t.slice(0, 10) === sh.date && e._t.slice(11, 16) >= sh.startUtc), "at least one event falls inside the shift");

  // ---- rules, correlations and hunts compile
  const ids = new Set();
  for (const r of scn.rules || []) {
    ok(r.id && !ids.has(r.id), "rule id unique: " + r.id); ids.add(r.id);
    ok(r.platform, r.id + " has a platform");
    try { const c = SOC.compileYaml(String(r.yaml).replace(/^\s*\n/, "")); ok(c.rule && c.rule.title && !(c.errors || []).length, r.id + " compiles" + ((c.errors || []).length ? ": " + c.errors.join(" ") : "")); ok(["informational", "low", "medium", "high", "critical"].includes(c.rule.level), r.id + " has a Sigma level"); }
    catch (e) { ok(false, r.id + " compiles: " + e.message); }
  }
  for (const c of scn.correlations || []) {
    ok(c.id && !ids.has(c.id), "correlation id unique: " + c.id); ids.add(c.id);
    ok(SOC.CORRELATORS[c.type], c.id + " uses a known correlation type (" + c.type + "; known: " + Object.keys(SOC.CORRELATORS).join(", ") + ")");
    ok(c.title && c.level && Array.isArray(c.attack) && c.attack.length, c.id + " has title, level and attack");
    if (c.select) { try { const k = SOC.compileYaml("title: x\nlogsource: { category: any }\n" + String(c.select).replace(/^\s*\n/, "")); ok(!(k.errors || []).length, c.id + " select compiles"); } catch (e) { ok(false, c.id + " select compiles: " + e.message); } }
  }
  const huntIds = new Set();
  for (const h of scn.hunts || []) {
    ok(h.id && !huntIds.has(h.id), "hunt id unique: " + h.id); huntIds.add(h.id);
    try { const c = SOC.compileYaml(String(h.yaml).replace(/^\s*\n/, "")); ok(!(c.errors || []).length, h.id + " compiles"); } catch (e) { ok(false, h.id + " compiles: " + e.message); }
  }

  // ---- ATT&CK ids exist in the bundled snapshot
  const T = new Set(ATTACK.techniques.map((t) => t[0]));
  const tagIds = (y) => (String(y).match(/attack\.t\d{4}(\.\d{3})?/gi) || []).map((t) => t.slice(7).toUpperCase());
  const used = [];
  (scn.rules || []).forEach((r) => tagIds(r.yaml).forEach((t) => used.push([r.id, t])));
  (scn.hunts || []).forEach((r) => tagIds(r.yaml).forEach((t) => used.push([r.id, t])));
  (scn.correlations || []).forEach((c) => (c.attack || []).forEach((t) => used.push([c.id, t])));
  const missing = used.filter(([, t]) => !T.has(t));
  ok(!missing.length, used.length + " ATT&CK technique references exist in the bundled ATT&CK v" + ATTACK.version + (missing.length ? "; missing: " + missing.map((m) => m.join(" ")).join(", ") : ""));
  (scn.rules || []).forEach((r) => ok(tagIds(r.yaml).length > 0, r.id + " maps to at least one ATT&CK technique"));

  // ---- detections against the answer key
  let data, alerts = [], authored = scn;
  if (seed) {
    if (!ok(scn.variants, "seed " + seed + ": the scenario has a variants block")) return results;
    const v = SOC.variant(scn, seed), map = v.variantMap || {};
    const vals = Object.values(map), origText = JSON.stringify(Object.assign({}, scn, { variants: null }));
    ok(vals.length > 0, "seed " + seed + ": re-draws " + vals.length + " values");
    ok(new Set(vals).size === vals.length && vals.every((x) => !Object.prototype.hasOwnProperty.call(map, x)), "seed " + seed + ": the re-draw is one to one and lands on new values");
    ok(Object.entries(map).every(([a, b]) => SOC.isIp(a) ? (scn.variants.ipPools || []).some((c) => SOC.inCidr(a, c) && SOC.inCidr(b, c)) : a.slice(0, a.search(/\d+$/)) === b.slice(0, b.search(/\d+$/))), "seed " + seed + ": addresses stay in their range and ids keep their prefix");
    const vText = JSON.stringify(Object.assign({}, v, { variants: null, variantMap: null }));
    const left = Object.keys(map).filter((k) => SOC.remapText(vText, { [k]: "\u0000" }) !== vText);
    ok(!left.length, "seed " + seed + ": no original value is left in the variant" + (left.length ? ": " + left.join(", ") : ""));
    ok(((scn.anchors || {}).ips || []).every((ip) => origText.includes(ip) === vText.includes(ip)), "seed " + seed + ": real-world anchors stay");
    ok(JSON.stringify(scn) === src0, "seed " + seed + ": the authored scenario is not changed");
    authored = v;
  }
  try { data = SOC.load(authored); SOC.indexEntities(data); alerts = SOC.runDetections(data); ok(true, "detections run (" + alerts.length + " alerts" + (seed ? ", seed " + seed : "") + ")"); }
  catch (e) { ok(false, "detections run: " + e.message); return results; }
  const answers = authored.answers || {};
  scn = authored;
  for (const k of Object.keys(answers)) ok(alerts.some((a) => a.id === k), "answer key alert is raised: " + k);
  for (const a of alerts) ok(answers[a.id], "raised alert has an answer key entry: " + a.id);
  for (const [k, v] of Object.entries(answers)) {
    ok(SOC.VERDICTS.includes(v.verdict), k + " verdict is one of " + SOC.VERDICTS.join(", "));
    ok(SOC.SEVS.includes(v.sev), k + " severity is one of " + SOC.SEVS.join(", "));
    ok(typeof v.why === "string" && v.why.length >= 15, k + " has a reason (why)");
    if (v.verdict === "tp" || v.verdict === "escalate") ok(v.incident || SOC.LEVEL_RANK[v.sev] < 2, k + " is " + v.verdict + " at " + v.sev + " and names an incident");
  }
  for (const a of alerts) ok(a.attack.length > 0 && a.at >= a.first, "alert " + a.id + " has ATT&CK ids and arrives after its first event");
  const shiftEnd = sh.date + "T" + sh.endUtc + ":00Z";
  for (const a of alerts) ok(SOC.normTime(a.at) <= shiftEnd, "alert " + a.id + " arrives before the shift ends (" + a.at + ")");

  // ---- hunts find what the key says
  const alerted = new Set(alerts.flatMap((a) => a.events));
  for (const [hid, x] of Object.entries(scn.huntAnswers || {})) {
    const h = (scn.hunts || []).find((y) => y.id === hid);
    if (!ok(h, "hunt answer " + hid + " matches a hunt")) continue;
    const note = typeof x === "string" ? x : x.note;
    ok(note && note.length > 15, hid + " answer has a note");
    if (typeof x === "object" && x.expectHits != null) {
      const c = SOC.compileYaml(String(h.yaml).replace(/^\s*\n/, ""));
      const hits = data.events.filter((e) => Sigma.match(c, e).match);
      ok(hits.length === x.expectHits, hid + " finds " + x.expectHits + " events (found " + hits.length + ")");
      if (x.unalerted) ok(hits.every((e) => !alerted.has(e._id)), hid + " hits are not covered by any alert");
    }
  }

  // ---- tuning: with answer-key verdicts, a proposal drops the noise and keeps every confirmed alert
  const verdicts = {}; for (const [k, v] of Object.entries(answers)) verdicts[k] = { verdict: v.verdict };
  for (const rid of scn.tuningChecks || []) {
    const rule = data.rules.find((r) => r.id === rid);
    if (!ok(rule, "tuning check " + rid + " names a rule")) continue;
    const p = SOC.proposeTuning(rule, alerts, verdicts, data);
    ok(p && !p.error, "tuning proposal for " + rid + (p && p.error ? ": " + p.error : ""));
    if (p && !p.error) { ok(p.lostTp.length === 0, rid + " tuning loses no true positive"); ok(p.removed.length === p.noisy.length, rid + " tuning removes every noisy alert (" + p.removed.length + "/" + p.noisy.length + ")"); }
  }

  // ---- a shift that follows the answer key grades full marks and lints clean
  const st = SOC.answerKeyState(data, alerts);
  const g = SOC.grade(st, alerts, data);
  ok(g.score === g.total, "answer-key shift grades " + g.score + "/" + g.total);
  const endMin = SOC.hhmmToMin(sh.endUtc) - 20, lateHHMM = String(Math.floor(endMin / 60)).padStart(2, "0") + ":" + String(endMin % 60).padStart(2, "0");
  const lint = SOC.lintHandover(st, alerts, lateHHMM, data);
  ok(lint.length === 0, "answer-key shift lints clean" + (lint.length ? ": " + lint.map((i) => i.msg).join(" | ") : ""));
  if (scn.handoverIn) {
    const H = scn.handoverIn;
    ok(Array.isArray(H.items) && H.items.every((i) => ["case", "watch"].includes(i.kind)), "handoverIn items have kind 'case' or 'watch'");
    ok(H.from === sh.from, "handoverIn.from matches estate.shift.from");
  }
  for (const gs of scn.goodShift || []) ok(gs.id && SOC.SEVS.includes(gs.sev) && gs.text, "goodShift entry " + gs.id + " has id, sev and text");

  // ---- no real-looking personal data
  const text = src;
  const emails = text.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || [];
  const realEmail = emails.filter((e) => !EXAMPLE_DOMAIN.test(e.split("@")[1]));
  ok(!realEmail.length, "email addresses use reserved example domains" + (realEmail.length ? "; found: " + [...new Set(realEmail)].join(", ") : ""));
  const anchorsIp = new Set(((scn.anchors || {}).ips) || []);
  const ips = [...new Set(text.match(/(?<![\d.])\d{1,3}(\.\d{1,3}){3}(?![\d.])/g) || [])].filter((ip) => ip.split(".").every((o) => +o <= 255));
  const realIps = ips.filter((ip) => !anchorsIp.has(ip) && !SYNTHETIC_V4.some((c) => inCidr(ip, c)));
  ok(!realIps.length, ips.length + " IPv4 addresses are private, documentation or listed anchors" + (realIps.length ? "; unlisted: " + realIps.join(", ") : ""));
  const keys = (text.match(/\b(AKIA|ASIA)[A-Z0-9]{12,}\b/g) || []).filter((k) => !/EXAMPLE/.test(k));
  ok(!keys.length, "AWS access key ids contain EXAMPLE" + (keys.length ? "; found: " + keys.join(", ") : ""));
  const cards = (text.match(/\b\d{13,19}\b/g) || []).filter(luhn);
  ok(!cards.length, "no Luhn-valid card-like numbers" + (cards.length ? "; found: " + cards.join(", ") : ""));
  const phones = text.match(/\+\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}/g) || [];
  ok(!phones.length, "no phone numbers" + (phones.length ? "; found: " + phones.join(", ") : ""));
  ok(!/[\u2013\u2014]/.test(text), "no em or en dashes");

  // ---- listed in the catalog the page reads
  const catalog = path.join(path.dirname(abs), "index.js");
  if (fs.existsSync(catalog)) ok(new RegExp('id:\\s*"' + scn.id + '"').test(fs.readFileSync(catalog, "utf8")), "listed in " + path.relative(ROOT, catalog));
  return results;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const args = process.argv.slice(2), dirs = [], seeds = [0];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--seed") { const n = +args[++i]; if (!Number.isInteger(n) || n < 0) { console.error("--seed takes a whole number"); process.exit(2); } if (n) seeds.push(n); }
    else dirs.push(args[i]);
  }
  if (!dirs.length) { console.error("usage: node tools/validate-scenario.mjs <scenario dir> [more dirs] [--seed N ...]"); process.exit(2); }
  let bad = 0;
  for (const d of dirs) for (const seed of seeds) {
    const r = validate(d, { seed });
    const fails = r.filter((x) => !x.ok);
    fails.forEach((x) => console.log("FAIL " + x.msg));
    if (process.env.VERBOSE) r.filter((x) => x.ok).forEach((x) => console.log("ok   " + x.msg));
    console.log(d + (seed ? " (seed " + seed + ")" : "") + ": " + (r.length - fails.length) + "/" + r.length + " checks passed");
    bad += fails.length;
  }
  process.exit(bad ? 1 : 0);
}
