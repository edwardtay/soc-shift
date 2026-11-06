#!/usr/bin/env node
// Grade a learner's verdicts export (NDJSON from the Handover out tab) against a scenario's answer key. No dependencies.
//   node tools/grade-verdicts.mjs app/scenarios/larkspur-metrics --seed 4021 verdicts.ndjson [more.ndjson ...]
// The seed must be the one the learner worked (?seed=N in their URL, 0 or omitted for the original shift),
// because a seeded variant re-draws the addresses and host numbers inside the alert ids.
// Prints one line per file: score, alerts left untriaged, verdicts without a usable reason, and each miss.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
globalThis.jsyaml = require(path.join(ROOT, "app/vendor/js-yaml.min.js"));
globalThis.Sigma = require(path.join(ROOT, "app/vendor/sigma.js"));
const SOC = require(path.join(ROOT, "app/js/engine.js"));

export function gradeNdjson(scenarioDir, seed, text) {
  const scn = require(path.join(path.resolve(scenarioDir), "scenario.js"));
  const data = SOC.load(SOC.variant(scn, seed || 0));
  SOC.indexEntities(data);
  const alerts = SOC.runDetections(data);
  const st = SOC.newState(), unknown = [];
  String(text).split("\n").filter((l) => l.trim()).forEach((l) => {
    const o = JSON.parse(l);
    if (!alerts.some((a) => a.id === o.alert_id)) { unknown.push(o.alert_id); return; }
    st.verdicts[o.alert_id] = { verdict: o.verdict, sev: o.severity, reason: o.reason || "", incident: o.incident || null };
  });
  const g = SOC.grade(st, alerts, data);
  return {
    score: g.score, total: g.total, unknown,
    untriaged: g.rows.filter((r) => !r.mine).map((r) => r.alert.id),
    misses: g.rows.filter((r) => r.mine && !r.ok).map((r) => r.alert.id + ": " + r.mine.verdict + ", key " + r.key.verdict),
    noReason: g.rows.filter((r) => r.mine && r.mine.reason.length < 15).map((r) => r.alert.id)
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), files = [];
  let dir = null, seed = 0;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--seed") { seed = +args[++i]; if (!Number.isInteger(seed) || seed < 0) { console.error("--seed takes a whole number"); process.exit(2); } }
    else if (!dir) dir = args[i]; else files.push(args[i]);
  }
  if (!dir || !files.length) { console.error("usage: node tools/grade-verdicts.mjs <scenario dir> [--seed N] <verdicts.ndjson> [more files]"); process.exit(2); }
  for (const f of files) {
    const r = gradeNdjson(dir, seed, fs.readFileSync(f, "utf8"));
    console.log(f + ": " + r.score + "/" + r.total + (r.untriaged.length ? ", " + r.untriaged.length + " untriaged" : "") + (r.noReason.length ? ", " + r.noReason.length + " without a reason" : "") + (r.unknown.length ? ", " + r.unknown.length + " alert ids not in this scenario and seed (wrong seed?)" : ""));
    r.misses.forEach((m) => console.log("  miss  " + m));
    r.untriaged.forEach((m) => console.log("  open  " + m));
    r.noReason.forEach((m) => console.log("  reason " + m));
  }
}
