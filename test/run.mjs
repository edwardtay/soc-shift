// npm test: engine checks against the Kestrel Ledger answer key, the verdict export, every scenario
// through the validator, and repository hygiene. Node 18+, no dependencies.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { validate } from "../tools/validate-scenario.mjs";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const P = (...f) => path.join(ROOT, ...f);
globalThis.jsyaml = require(P("app/vendor/js-yaml.min.js"));
globalThis.Sigma = require(P("app/vendor/sigma.js"));
const SOC = require(P("app/js/engine.js"));
const scn = require(P("app/scenarios/kestrel-ledger/scenario.js"));
const attack = JSON.parse(fs.readFileSync(P("app/vendor/attack.json"), "utf8"));

let n = 0, failed = 0;
function ok(cond, msg) { n++; if (!cond) { failed++; console.log("FAIL " + msg); } }
const section = (s) => { if (process.env.VERBOSE) console.log("# " + s); };

section("vendored engines");
["parse", "compile", "match"].forEach((f) => ok(typeof Sigma[f] === "function", "sigma.js exports " + f));
ok(typeof jsyaml.load === "function", "js-yaml loads");
ok(attack.version === "19.2" && attack.techniques.length > 600, "ATT&CK snapshot is v19.2 with its techniques");
const intel = require(P("app/vendor/intel.js"));
["rdapIp", "rdapDomain", "doh", "torStatus", "osvPackage", "kev"].forEach((f) => ok(typeof intel[f] === "function", "intel.js exports " + f));

section("loader");
const data = SOC.load(scn);
ok(data !== scn && data.events !== scn.events, "load() works on a copy");
ok(data.events.every((e, i) => e._id === "ev" + String(i + 1).padStart(3, "0")), "events are numbered in time order");
ok(data.events.every((e, i) => i === 0 || data.events[i - 1]._t <= e._t), "loaded timeline is sorted");
ok(data.estate.shift.team === "APAC SOC" && data.estate.shift.nextTeam === "EMEA SOC (next shift)", "shift team names derive from the shift");
ok(data.estate.shift.startMin === 0 && data.estate.shift.endMin === 540, "shift minutes parse");

section("detections");
SOC.indexEntities(data);
const alerts = SOC.runDetections(data);
ok(alerts.length === Object.keys(scn.answers).length, "alert count matches the answer key (" + alerts.length + ")");
for (const k of Object.keys(scn.answers)) ok(alerts.some((a) => a.id === k), "alert present " + k);
ok(alerts.filter((a) => a.kind === "correlation").length === 2, "both correlations fire");
const cwaf = alerts.find((a) => a.id === "C-WAF-001|cust-58812");
ok(cwaf && cwaf.facts[0] === "8 source IPs in AS64501 (synthetic residential proxy pool)" && /200 for cust-58812 from 198\.51\.100\.77 \(password seen in breach\)/.test(cwaf.facts[2]), "stuffing correlation facts read as before");
const cidp = alerts.find((a) => a.id === "C-IDP-001|l.chen");
ok(cidp && cidp.at.slice(11, 16) === "04:10" && cidp.events.length === 3, "session replay correlation keys on the second network");
ok(data.events.filter((e) => e._t < SOC.shiftStart(data)).every((e) => !alerts.some((a) => a.kind === "sigma" && a.events.includes(e._id))), "events before the shift raise no Sigma alert");
let threw = false; try { SOC.runDetections(Object.assign({}, data, { correlations: [{ id: "C-X", type: "nope", attack: [] }] })); } catch (e) { threw = /Unknown correlation type/.test(e.message); }
ok(threw, "an unknown correlation type is an error");

section("pivots");
const evmap = SOC.byId(data);
const rel = SOC.relatedAlerts(alerts.find((a) => a.id === "R-EDR-001|KL-MBP-0142"), alerts, evmap, data.estate.users, data.noisyEntities);
ok(rel.some((r) => r.alert.id === "R-EDR-004|KL-MBP-0142") && rel.some((r) => r.alert.id === "R-EDR-002|KL-MBP-0142"), "the take-home alerts link to each other");
ok(!rel.some((r) => r.alert.id === "R-WAF-001|10.20.0.15"), "noisy entities do not link unrelated alerts");
const tl = SOC.timeline({ type: "package", value: "ethersscan-api" }, data, SOC.indexEntities(data), evmap);
ok(tl.length === 1 && tl[0].PackageName === "ethersscan-api", "package pivot finds the install");

section("hunts");
const hits = (id) => { const h = data.hunts.find((x) => x.id === id); const c = SOC.compileYaml(h.yaml); return data.events.filter((e) => Sigma.match(c, e).match); };
ok(hits("H-01").length === 4 && hits("H-01").every((e) => e.sourceIPAddress === "149.28.17.9"), "H-01 finds the VPS key use only");
ok(hits("H-03").length === 1, "H-03 finds the cracked installer");
ok(hits("H-04").length === 3, "H-04 finds 3 port-1224 records");

section("tuning");
const verdicts = {}; for (const [k, v] of Object.entries(scn.answers)) verdicts[k] = { verdict: v.verdict };
const pw = SOC.proposeTuning(data.rules.find((r) => r.id === "R-WAF-001"), alerts, verdicts, data);
ok(pw.filter.ClientIP && pw.filter.ClientIP.join() === "10.20.0.15" && /CHG-2291/.test(pw.yaml), "WAF tuning filters the scanner and carries the change note");
const bad = Object.assign({}, verdicts, { "R-WAF-001|198.51.100.203": { verdict: "fp" } });
const pb = SOC.proposeTuning(data.rules.find((r) => r.id === "R-WAF-001"), alerts, bad, data);
ok(pb.removed.length === 2 && pb.lostTp.length === 0, "closing both WAF alerts as noise suppresses both");
const keepOne = Object.assign({}, verdicts, { "R-EDR-003|LIS-WIN-0021": { verdict: "tp" } });
const pk = SOC.proposeTuning(data.rules.find((r) => r.id === "R-EDR-003"), alerts, keepOne, data);
ok(pk.error && /No field separates/.test(pk.error), "tuning refuses when no field separates noise from a confirmed alert");
ok(SOC.proposeTuning(data.rules.find((r) => r.id === "R-EDR-001"), alerts, verdicts, data) === null, "no proposal for a rule with no noise");

section("handover");
const st = SOC.newState();
ok(SOC.lintHandover(st, alerts, "08:40", data).some((i) => /untriaged/.test(i.msg)), "lint flags untriaged alerts");
ok(SOC.lintHandover(st, alerts, "08:40", data).some((i) => /AMER handover was never acknowledged/.test(i.msg)), "lint flags an unacknowledged handover");
const ack = SOC.acknowledge(SOC.newState(), data, "2026-11-05T00:05:00Z");
ok(ack.incidents["CASE-1187"] && ack.incidents["CASE-1187"].owner === "APAC SOC" && ack.incidents["CASE-1187"].carried, "acknowledging takes CASE-1187");
ok(ack.actions.length === 1 && ack.actions[0].status === "pending" && ack.actions[0].owner === "IT operations", "the IT-5521 reset carries in as pending");
ok(ack.watch.length === 2, "the watch list carries in");
ack.incidents["CASE-1187"].next = "watch the user";
ok(SOC.lintHandover(ack, [], "08:40", data).some((i) => /came in with IT-5521 pending/.test(i.msg)), "lint flags a carried ticket dropped from the next action");
ack.incidents["CASE-1187"].next = "chase IT-5521"; ack.incidents["CASE-1187"].due = "02:00 UTC";
ok(SOC.lintHandover(ack, [], "08:40", data).some((i) => /was due at 02:00 UTC and APAC SOC still owns it/.test(i.msg)), "lint flags an overdue item the shift still owns");
const done = SOC.answerKeyState(data, alerts);
const lint = SOC.lintHandover(done, alerts, "08:40", data);
ok(lint.length === 0, "an answer-key shift lints clean: " + JSON.stringify(lint));
ok(SOC.grade(done, alerts, data).score === alerts.length, "answer-key shift grades full marks");
const md = SOC.buildHandover(done, alerts, data);
ok(/^# Shift handover: APAC → EMEA, 2026-11-05/.test(md) && /## Open incidents/.test(md) && /## Pending actions/.test(md) && /## Untriaged alerts\nNone\./.test(md), "handover note has its sections");
const rec = SOC.applyAction(SOC.newState(), "INC-1", { type: "cloudkey", value: "k" }, SOC.actionsFor({ type: "cloudkey" }, data)[0], "2026-11-05T03:00:00Z", "APAC SOC");
ok(rec.status === "pending" && rec.owner === "Cloud platform", "an action owned by another team stays pending");

section("grading");
const g1 = SOC.newState(); g1.verdicts["R-SSE-001|j.okafor"] = { verdict: "tp" }; g1.verdicts["C-IDP-001|l.chen"] = { verdict: "escalate" }; g1.verdicts["R-WAF-001|10.20.0.15"] = { verdict: "tp" };
const gr = SOC.grade(g1, alerts, data);
ok(gr.score === 2, "tp and escalate count as the same call both ways; a wrong call does not count");

section("verdict export");
ok(SOC.verdictExport(SOC.newState(), alerts).trim() === "", "no verdicts, empty export");
const lines = SOC.verdictExport(done, alerts).trim().split("\n").map((l) => JSON.parse(l));
ok(lines.length === alerts.length, "one NDJSON line per closed alert (" + lines.length + ")");
const want = { true_positive: 0, false_positive: 0, benign_true_positive: 0 };
alerts.forEach((a) => { want[SOC.DISPOSITION[scn.answers[a.id].verdict]]++; });
const got = { true_positive: 0, false_positive: 0, benign_true_positive: 0 }; lines.forEach((l) => { got[l.disposition]++; });
ok(JSON.stringify(got) === JSON.stringify(want), "dispositions survive the export " + JSON.stringify(got));
ok(lines.every((l) => Date.parse(l.event_time) <= Date.parse(l.alert_time) && Date.parse(l.alert_time) <= Date.parse(l.close_time)), "event, alert and close times parse in order");
ok(lines.every((l) => l.technique && l.rule && l.entity), "rule, technique and entity survive the export");

section("scenarios");
const scnDir = P("app/scenarios");
const folders = fs.readdirSync(scnDir).filter((f) => fs.statSync(path.join(scnDir, f)).isDirectory());
for (const f of folders) {
  const r = validate(path.join(scnDir, f));
  r.filter((x) => !x.ok).forEach((x) => ok(false, f + ": " + x.msg));
  ok(r.length > 50 && r.every((x) => x.ok), "validator passes on " + f + " (" + r.length + " checks)");
}
// the validator catches a broken scenario
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "soc-shift-"));
const brokenDir = path.join(tmp, "broken-one"); fs.mkdirSync(brokenDir);
let srcText = fs.readFileSync(P("app/scenarios/kestrel-ledger/scenario.js"), "utf8").replace('id: "kestrel-ledger"', 'id: "broken-one"');
srcText = srcText.replace('"R-EDR-003|HCM-WIN-0450"', '"R-EDR-003|NO-SUCH-HOST"').replace("attack.t1571]", "attack.t9999]").replace('"dst_ip":"140.82.112.4"', '"dst_ip":"8.8.4.4"').replace('j.okafor@kestrel.example', 'j.okafor@gmail.com');
fs.writeFileSync(path.join(brokenDir, "scenario.js"), srcText);
const br = validate(brokenDir).filter((x) => !x.ok).map((x) => x.msg).join("\n");
ok(/answer key alert is raised: R-EDR-003\|NO-SUCH-HOST/.test(br), "validator flags an answer key alert that never fires");
ok(/raised alert has an answer key entry: R-EDR-003\|HCM-WIN-0450/.test(br), "validator flags an alert with no answer");
ok(/missing: .*T9999/.test(br), "validator flags an unknown ATT&CK id");
ok(/unlisted: 8\.8\.4\.4/.test(br), "validator flags a public IP that is not a listed anchor");
ok(/gmail\.com/.test(br), "validator flags a real-looking email domain");
const unsorted = srcText.replace('"_t":"2026-11-05T08:20:00Z"', '"_t":"2026-11-05T00:00:01Z"');
fs.writeFileSync(path.join(brokenDir, "scenario.js"), unsorted);
ok(validate(brokenDir).some((x) => !x.ok && /timeline sorted/.test(x.msg)), "validator flags an unsorted timeline");
fs.rmSync(tmp, { recursive: true, force: true });

section("app wiring");
const page = fs.readFileSync(P("app/index.html"), "utf8");
const refs = [...page.matchAll(/(?:src|href)="([^"#:]+)"/g)].map((m) => m[1]).filter((r) => r !== "./");
ok(refs.length >= 7 && refs.every((r) => fs.existsSync(P("app", r))), "every local file the page references exists (" + refs.length + ")");
ok(!/umami|feedback-widget|application\/ld\+json|fonts\.googleapis|(src|href)="\/tools\//.test(page), "no analytics, feedback widget, JSON-LD, web fonts or pwnsy paths in the page");
const appJs = fs.readFileSync(P("app/js/app.js"), "utf8");
ok(!/pwnsyIp|vpn\.pwnsy|\/tools\/|alert-budget|pwnsy-detect/.test(appJs), "the app uses no pwnsy-only endpoint or storage key");
ok(/N\.torStatus\(/.test(appJs), "Tor lookups use Onionoo");
ok(/"soc-shift:" \+ DATA\.id/.test(appJs), "storage key is per scenario");
const catalog = fs.readFileSync(P("app/scenarios/index.js"), "utf8");
for (const f of folders) ok(catalog.includes('id: "' + f + '"'), "catalog lists " + f);

section("repository");
const pkg = JSON.parse(fs.readFileSync(P("package.json"), "utf8"));
ok(!pkg.dependencies && !pkg.devDependencies, "package.json has no dependencies");
const pages = fs.readFileSync(P(".github/workflows/pages.yml"), "utf8");
ok(/path:\s*app\b/.test(pages) && fs.existsSync(P("app/index.html")), "Pages workflow uploads the app folder");
for (const wf of ["test.yml", "pages.yml"]) {
  const y = fs.readFileSync(P(".github/workflows", wf), "utf8");
  const uses = [...y.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
  ok(uses.length && uses.every((u) => /@[0-9a-f]{40}$/.test(u)), wf + " pins every action to a commit SHA");
}
function walk(d, out = []) {
  for (const f of fs.readdirSync(d)) {
    if ([".git", "node_modules", ".src"].includes(f)) continue;
    const full = path.join(d, f), s = fs.statSync(full);
    if (s.isDirectory()) walk(full, out); else if (/\.(js|mjs|cjs|json|css|html|md|yml|yaml|svg|txt|py|sh)$|^(LICENSE|NOTICE|\.gitignore)$/.test(f)) out.push(full);
  }
  return out;
}
const files = walk(ROOT);
const dashed = files.filter((f) => /[\u2013\u2014]/.test(fs.readFileSync(f, "utf8")));
ok(!dashed.length, "no em or en dashes in " + files.length + " text files" + (dashed.length ? ": " + dashed.map((f) => path.relative(ROOT, f)).join(", ") : ""));
const trace = /teth[e]r|job[ -]applic[a]tion|work sampl[e]|r[e]sum[eé]\b|cover not[e]|hiring manag[e]r|workers\.d[e]v|pages\.d[e]v|lever[l]abs|lever-l[a]bs|\/api\/int[e]l|edwardtay\.c[o]m/i;
const traced = files.filter((f) => !/\.min\.js$/.test(f) && trace.test(fs.readFileSync(f, "utf8")));
ok(!traced.length, "no private-context traces (employers, applications, personal sites)" + (traced.length ? ": " + traced.map((f) => path.relative(ROOT, f)).join(", ") : ""));
const appFiles = files.filter((f) => f.startsWith(P("app")) && !f.includes(path.sep + "vendor" + path.sep));
ok(!appFiles.some((f) => /edward tay/i.test(fs.readFileSync(f, "utf8"))), "the app itself names no person");
const prose = files.filter((f) => /\.md$/.test(f) || f.endsWith("index.html"));
const anti = prose.filter((f) => /\bnot just\b|\bnot only\b|it is not about/i.test(fs.readFileSync(f, "utf8")));
ok(!anti.length, "no 'not just' or 'not only' in docs and the page" + (anti.length ? ": " + anti.map((f) => path.relative(ROOT, f)).join(", ") : ""));

console.log((n - failed) + "/" + n + " checks passed (" + scn.rules.length + " Sigma rules, " + scn.correlations.length + " correlations, " + alerts.length + " alerts, " + scn.hunts.length + " hunts, " + folders.length + " scenario" + (folders.length > 1 ? "s" : "") + ")");
process.exit(failed ? 1 : 0);
