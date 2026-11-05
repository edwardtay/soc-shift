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

section("alert delays");
const LAT = scn.alertDelayMinutes;
ok(LAT && LAT.EDR === 1 && LAT.WAF === 1 && LAT.SSE === 2 && LAT.SIEM === 5, "the scenario sets per-platform alert delays");
for (const a of alerts.filter((x) => x.kind === "sigma")) ok(Date.parse(a.at) - Date.parse(a.first) === LAT[a.platform] * 60000, "pipeline delay " + a.platform + " on " + a.id);
for (const a of alerts.filter((x) => x.kind === "correlation")) ok(a.at === a.at && Date.parse(a.at) >= Date.parse(a.first), "correlation " + a.id + " arrives at the event that completes it");
{
  const d0 = SOC.load(Object.assign({}, scn, { alertDelayMinutes: undefined })); SOC.indexEntities(d0);
  ok(SOC.runDetections(d0).filter((a) => a.kind === "sigma").every((a) => a.at === a.first), "no alertDelayMinutes, no delay");
  const d1 = SOC.load(Object.assign({}, scn, { rules: scn.rules.map((r) => r.id === "R-EDR-001" ? Object.assign({}, r, { delayMinutes: 7 }) : r) })); SOC.indexEntities(d1);
  const a1 = SOC.runDetections(d1).find((a) => a.id === "R-EDR-001|KL-MBP-0142");
  ok(Date.parse(a1.at) - Date.parse(a1.first) === 7 * 60000, "a rule's delayMinutes overrides its platform delay");
}

section("shift timing");
const s3 = JSON.parse(JSON.stringify(done));
alerts.forEach((a) => { s3.acks[a.id] = new Date(Date.parse(a.at) + 4 * 60000).toISOString(); s3.verdicts[a.id].at = new Date(Date.parse(a.at) + 15 * 60000).toISOString(); });
const sm = SOC.shiftMetrics(s3, alerts);
ok(sm.mtta.n === alerts.length && sm.mtta.mean === 4 && sm.mtta.median === 4, "MTTA = mean of first-open time minus alert time (" + JSON.stringify(sm.mtta) + ")");
ok(sm.mttr.n === alerts.length && sm.mttr.mean === 15 && sm.mttr.p90 === 15, "MTTR = mean of verdict time minus alert time");
const ttds = alerts.map((a) => (Date.parse(a.at) - Date.parse(a.first)) / 60000).sort((x, y) => x - y);
ok(Math.abs(sm.mttd.mean - Math.round(ttds.reduce((t, x) => t + x, 0) / ttds.length * 10) / 10) < 1e-9 && sm.mttd.median === ttds[Math.ceil(ttds.length / 2) - 1], "MTTD = mean and nearest-rank median of alert time minus first event time");
ok(SOC.shiftMetrics(SOC.newState(), alerts).mtta.n === 0 && SOC.shiftMetrics(SOC.newState(), alerts).mtta.mean === null, "no acknowledgements, no MTTA (blank, never zero)");
ok(sm.incidents.length === Object.keys(s3.incidents).length && sm.mttrespond.n > 0, "time to first response per incident");
ok(SOC.newState().acks && SOC.newState().obs && SOC.newState().seed === 0, "a new shift carries acks, observable overrides and its seed");

section("observables");
const incs = Object.values(s3.incidents);
const incA = s3.incidents["INC-A"];
const pkgEv = data.events.find((e) => e.PackageName === "ethersscan-api");
ok(!SOC.observables(s3, incA, alerts, data).some((o) => o.type === "package"), "the package is in no alert's events");
incA.extra = [pkgEv._id];
const obsA = SOC.observables(s3, incA, alerts, data);
const ob = (t, v) => obsA.find((o) => o.type === t && o.value === v);
ok(ob("ip", "203.0.113.47") && ob("ip", "203.0.113.47").ioc && ob("ip", "203.0.113.47").tlp === "GREEN" && ob("ip", "203.0.113.47").pap === "AMBER", "C2 address is an IOC at TLP:GREEN, PAP:AMBER");
ok(ob("package", "ethersscan-api") && ob("package", "ethersscan-api").ioc && ob("package", "ethersscan-api").alerts.length === 0, "a hunt hit added to the incident brings the npm package in as an IOC");
ok(ob("host", "KL-MBP-0142") && !ob("host", "KL-MBP-0142").ioc && ob("host", "KL-MBP-0142").tlp === "AMBER+STRICT" && ob("host", "KL-MBP-0142").pap === "RED", "internal host is no IOC, TLP:AMBER+STRICT, PAP:RED");
const allObs = incs.flatMap((i) => SOC.observables(s3, i, alerts, data));
ok(!allObs.some((o) => o.ioc && /^(github\.com|bitbucket\.org|www\.linkedin\.com|drive\.google\.com|140\.82\.112\.4|104\.192\.141\.1|13\.107\.42\.14|100\.64\.|Q3_reserve)/.test(o.value)), "observables.notIoc, corporate egress and internal documents are never IOCs");
ok(!allObs.some((o) => data.noisyEntities.includes(o.value)), "noisy entities are left out");
s3.obs = { "ip:203.0.113.47": { tlp: "RED", pap: "RED", ioc: false } };
{ const o = SOC.observables(s3, incA, alerts, data).find((x) => x.value === "203.0.113.47"); ok(o.tlp === "RED" && o.pap === "RED" && o.ioc === false, "analyst IOC, TLP and PAP overrides stick"); }
s3.obs = {};
{
  const d2 = SOC.load(Object.assign({}, scn, { observables: { notIoc: [], external: { tlp: "CLEAR", pap: "GREEN" }, internal: { tlp: "RED", pap: "RED" } } })); SOC.indexEntities(d2);
  const o2 = SOC.observables(s3, incA, SOC.runDetections(d2), d2);
  ok(o2.find((o) => o.value === "203.0.113.47").tlp === "CLEAR" && o2.find((o) => o.value === "KL-MBP-0142").tlp === "RED", "observable defaults come from the scenario");
}

section("exports");
// Key sets from thehive4py 2.x TypedDicts (InputAlert, InputCase, InputObservable, InputTask, InputProcedure).
const HIVE_ALERT = { req: ["type", "source", "sourceRef", "title", "description"], opt: ["externalLink", "severity", "date", "tags", "flag", "tlp", "pap", "customFields", "summary", "status", "assignee", "caseTemplate", "observables", "procedures"] };
const HIVE_CASE = { req: ["title", "description"], opt: ["severity", "startDate", "endDate", "tags", "flag", "tlp", "pap", "status", "summary", "assignee", "access", "customFields", "caseTemplate", "tasks", "pages", "sharingParameters", "taskRule", "observableRule"] };
const HIVE_OBS = { req: ["dataType"], opt: ["data", "message", "startDate", "attachment", "tlp", "pap", "tags", "ioc", "sighted", "sightedAt", "ignoreSimilarity", "isZip", "zipPassword"] };
const HIVE_TASK = { req: ["title"], opt: ["group", "description", "status", "flag", "startDate", "endDate", "order", "dueDate", "assignee", "mandatory"] };
const HIVE_PROC = { req: ["occurDate", "patternId"], opt: ["tactic", "description"] };
const shape = (o, sp, what) => { ok(sp.req.every((k) => o[k] !== undefined), what + " has " + sp.req.join(", ")); ok(Object.keys(o).every((k) => sp.req.includes(k) || sp.opt.includes(k)), what + " has no unknown keys: " + Object.keys(o).filter((k) => !sp.req.includes(k) && !sp.opt.includes(k)).join(",")); };
const HIVE_TYPES = ["autonomous-system", "domain", "file", "filename", "fqdn", "hash", "hostname", "ip", "mail", "mail_subject", "other", "regexp", "registry", "uri_path", "url", "user-agent"];
const T = new Set(attack.techniques.map((t) => t[0]));
incs.forEach((i) => {
  const x = SOC.theHiveCase(s3, i, alerts, data);
  shape(x.case, HIVE_CASE, "TheHive case " + i.id);
  ok(Number.isInteger(x.case.severity) && x.case.severity >= 1 && x.case.severity <= 4 && [0, 1, 2, 3, 4].includes(x.case.tlp) && [0, 1, 2, 3].includes(x.case.pap), "TheHive case enums " + i.id);
  ok(x.case.startDate === undefined || (Number.isInteger(x.case.startDate) && x.case.startDate > 1.7e12), "TheHive case startDate is epoch ms " + i.id);
  x.case.tasks.forEach((t) => { shape(t, HIVE_TASK, "TheHive task"); ok(["Waiting", "InProgress", "Completed", "Cancel"].includes(t.status), "task status " + t.status); });
  x.observables.forEach((o) => { shape(o, HIVE_OBS, "TheHive observable " + o.data); ok(HIVE_TYPES.includes(o.dataType), "TheHive default dataType " + o.dataType); ok(typeof o.ioc === "boolean" && Number.isInteger(o.sightedAt) && [0, 1, 2, 3, 4].includes(o.tlp) && [0, 1, 2, 3].includes(o.pap), "observable flags typed " + o.data); });
  x.alerts.forEach((a) => { shape(a, HIVE_ALERT, "TheHive alert " + a.sourceRef); ok(Number.isInteger(a.date) && a.date > 1.7e12, "alert date is epoch ms"); a.procedures.forEach((p) => { shape(p, HIVE_PROC, "TheHive procedure"); ok(T.has(p.patternId), "procedure technique exists " + p.patternId); }); });
  ok(x.procedures.every((p) => T.has(p.patternId)), "case procedures name ATT&CK techniques " + i.id);
});
// Column names from iris-backend app/models/alerts.py; IOC and asset fields from IocSchema and CaseAssetsSchema.
const IRIS_KEYS = ["alert_title", "alert_description", "alert_source", "alert_source_ref", "alert_source_link", "alert_source_content", "alert_severity_id", "alert_status_id", "alert_context", "alert_source_event_time", "alert_note", "alert_tags", "alert_customer_id", "alert_classification_id", "alert_iocs", "alert_assets"];
alerts.forEach((a) => {
  const x = SOC.irisAlert(s3, a, data, allObs);
  ok(["alert_title", "alert_severity_id", "alert_status_id", "alert_customer_id", "alert_source_event_time"].every((k) => x[k] !== undefined) && Object.keys(x).every((k) => IRIS_KEYS.includes(k)), "IRIS alert columns " + a.id);
  ok(x.alert_severity_id >= 1 && x.alert_severity_id <= 6 && x.alert_status_id >= 1 && x.alert_status_id <= 8 && typeof x.alert_tags === "string", "IRIS ids and comma-string tags " + a.id);
  x.alert_iocs.forEach((i) => ok(i.ioc_value && i.ioc_type_id >= 1 && i.ioc_type_id <= 160 && i.ioc_tlp_id >= 1 && i.ioc_tlp_id <= 5, "IRIS IOC " + i.ioc_value));
  x.alert_assets.forEach((s) => ok(s.asset_name && Number.isInteger(s.asset_type_id), "IRIS asset " + s.asset_name));
});
{ const x = SOC.irisAlert(s3, alerts.find((a) => a.id === "R-EDR-001|KL-MBP-0142"), data, allObs); ok(x.alert_assets.find((s) => s.asset_name === "KL-MBP-0142").asset_type_id === 6 && x.alert_assets.find((s) => s.asset_name === "a.rahman").asset_type_id === 1, "IRIS asset type follows the host's OS (macOS) and accounts"); }
{ const x = SOC.irisAlert(s3, alerts.find((a) => a.id === "R-EDR-002|SG-WIN-0311"), data, allObs); ok(x.alert_assets.find((s) => s.asset_name === "SG-WIN-0311").asset_type_id === 9, "IRIS asset type for a Windows host"); }
const names = {}; attack.techniques.forEach((t) => (names[t[0]] = t[1]));
const bundle = SOC.stixBundle(s3, alerts, data, names);
const v4 = /^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const stixTs = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
ok(bundle.type === "bundle" && v4.test(bundle.id), "STIX bundle id");
ok(bundle.objects.every((o) => v4.test(o.id) && o.spec_version === "2.1" && stixTs.test(o.created) && stixTs.test(o.modified)), "every STIX object has a v4-form id, spec_version 2.1, created and modified");
ok(new Set(bundle.objects.map((o) => o.id)).size === bundle.objects.length, "STIX ids are unique");
const byIdS = {}; bundle.objects.forEach((o) => (byIdS[o.id] = o));
ok(bundle.objects.filter((o) => o.type === "sighting").every((s) => byIdS[s.sighting_of_ref] && byIdS[s.sighting_of_ref].type === "indicator" && s.where_sighted_refs.every((r) => byIdS[r]) && s.first_seen <= s.last_seen && s.count >= 1), "sightings point at indicators and the SOC identity");
ok(bundle.objects.filter((o) => o.type === "relationship").every((r) => byIdS[r.source_ref] && byIdS[r.target_ref] && r.relationship_type === "indicates"), "relationships resolve");
ok(bundle.objects.filter((o) => o.type === "attack-pattern").every((p) => T.has(p.external_references[0].external_id) && p.name === names[p.external_references[0].external_id]), "attack-patterns carry ATT&CK ids and names");
{ const badP = bundle.objects.filter((o) => o.type === "indicator").filter((i) => !/^\[[a-z0-9-]+:[a-z_.'A-Z0-9-]+ = '.+'\]$/.test(i.pattern) || i.pattern_type !== "stix" || !stixTs.test(i.valid_from)); ok(!badP.length, "indicator patterns are STIX patterns " + badP.map((i) => i.pattern).join(" ")); }
ok(bundle.objects.some((o) => o.type === "indicator" && o.pattern === "[ipv4-addr:value = '203.0.113.47']"), "C2 address exported as an indicator");
ok(bundle.objects.some((o) => o.type === "indicator" && o.pattern === "[software:name = 'ethersscan-api']"), "hunt-added npm package exported as an indicator");
ok(!bundle.objects.some((o) => o.type === "indicator" && /KL-MBP|a\.rahman|140\.82\.112\.4/.test(o.pattern)), "internal values and notIoc services never become indicators");
ok(JSON.stringify(SOC.stixBundle(s3, alerts, data, names)) === JSON.stringify(bundle), "the bundle is deterministic");
const layer = SOC.navigatorLayer(s3, alerts, data, attack.version);
ok(layer.versions.layer === "4.5" && layer.domain === "enterprise-attack" && layer.versions.attack === "19", "Navigator layer 4.5 for enterprise ATT&CK 19");
ok(layer.techniques.every((t) => T.has(t.techniqueID) && Number.isInteger(t.score) && /^#[0-9a-f]{6}$/.test(t.color)) && layer.techniques.length === new Set(alerts.flatMap((a) => a.attack)).size, "one layer entry per alerted technique, all in v" + attack.version);
ok(layer.techniques.find((t) => t.techniqueID === "T1059.001").color === "#94a3b8" && layer.techniques.find((t) => t.techniqueID === "T1105").color === "#c2410c", "layer colours follow the verdicts");
ok([bundle, layer, SOC.theHiveCase(s3, incA, alerts, data)].every((x) => JSON.parse(JSON.stringify(x)) && !JSON.stringify(x).includes("undefined")), "every export serialises to clean JSON");
ok(!/pwnsy/i.test(JSON.stringify([bundle, layer, SOC.theHiveCase(s3, incA, alerts, data), SOC.irisAlert(s3, alerts[0], data, allObs)])), "exports carry no pwnsy names");

section("seeded variants");
const raw = JSON.stringify(scn);
ok(SOC.variant(scn, 0) === scn, "seed 0 is the original shift");
ok(SOC.variant(Object.assign({}, scn, { variants: undefined }), 7).seed === undefined, "a scenario without variants ignores the seed");
const keys = new Set();
for (const seed of [7, 12345, 31337]) {
  const v = SOC.load(SOC.variant(scn, seed)); SOC.indexEntities(v);
  const m = v.variantMap;
  const va = SOC.runDetections(v);
  ok(va.length === alerts.length && va.every((a) => v.answers[a.id]), "seed " + seed + ": every alert has an answer");
  ok(m["203.0.113.47"] && m["203.0.113.47"] !== "203.0.113.47" && /^203\.0\.113\.\d+$/.test(m["203.0.113.47"]), "seed " + seed + ": the C2 address moves inside 203.0.113.0/24");
  ok(/^KL-MBP-\d{4}$/.test(m["KL-MBP-0142"]) && /^cust-\d{5}$/.test(m["cust-58812"]), "seed " + seed + ": host numbers and the customer id are re-drawn");
  ok(new Set(Object.values(m)).size === Object.keys(m).length, "seed " + seed + ": the re-draw is one to one");
  const vt = JSON.stringify(v);
  ok(vt.includes("149.28.17.9") && vt.includes("ethersscan-api") && vt.includes("10.20.0.15") && vt.includes("nkbihfbeogaeaoehlefnkodbefgpgknn"), "seed " + seed + ": real anchors and internal addresses stay");
  ok(v.variants.ipPools.join() === scn.variants.ipPools.join(), "seed " + seed + ": the pool definitions are not rewritten");
  ok(v.answers["R-EDR-004|" + m["KL-MBP-0142"]].why.includes(m["203.0.113.47"]), "seed " + seed + ": answer-key text follows the re-draw");
  ok(v.handoverIn.watch[0].startsWith(m["192.0.2.66"] + ":") && v.goodShift.some((g) => g.text.includes(m["cust-58812"])), "seed " + seed + ": the handover and good-shift text follow");
  const vst = SOC.answerKeyState(v, va);
  ok(SOC.grade(vst, va, v).score === va.length && SOC.lintHandover(vst, va, "08:40", v).length === 0, "seed " + seed + ": an answer-key shift grades full marks and lints clean");
  ok(SOC.stixBundle(vst, va, v, names).objects.some((o) => o.pattern === "[ipv4-addr:value = '" + m["203.0.113.47"] + "']"), "seed " + seed + ": exports carry the variant's addresses");
  const vr = validate(P("app/scenarios/kestrel-ledger"), { seed });
  vr.filter((x) => !x.ok).forEach((x) => ok(false, "seed " + seed + ": " + x.msg));
  ok(vr.length > 50 && vr.every((x) => x.ok), "validator passes on seed " + seed + " (" + vr.length + " checks)");
  keys.add(m["203.0.113.47"] + m["KL-MBP-0142"]);
}
ok(keys.size === 3, "three seeds give three different keys");
ok(JSON.stringify(SOC.variant(scn, 7)) === JSON.stringify(SOC.variant(scn, 7)), "a seed always gives the same variant");
ok(JSON.stringify(scn) === raw, "variants do not change the authored scenario");

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
{
  const bad2 = srcText.replace("alertDelayMinutes: { EDR: 1,", "alertDelayMinutes: { EDR: -1, XDR: 3,").replace('external: { tlp: "GREEN"', 'external: { tlp: "ORANGE"').replace('ipPools: ["192.0.2.0/24"', 'ipPools: ["8.8.8.0/24", "192.0.2.0/24"');
  fs.writeFileSync(path.join(brokenDir, "scenario.js"), bad2);
  const b2 = validate(brokenDir).filter((x) => !x.ok).map((x) => x.msg).join("\n");
  ok(/alertDelayMinutes maps platforms to 0 to 120/.test(b2) && /alertDelayMinutes names only platforms/.test(b2), "validator flags a bad alert delay and an unknown platform");
  ok(/observables\.external has a TLP 2\.0 level/.test(b2), "validator flags an unknown TLP level");
  ok(/variants\.ipPools sit inside private or documentation ranges/.test(b2), "validator flags a variant pool over public addresses");
  const noVar = srcText.replace(/\n    variants: \{[\s\S]*?\n    \},\n/, "\n");
  fs.writeFileSync(path.join(brokenDir, "scenario.js"), noVar);
  ok(validate(brokenDir, { seed: 7 }).some((x) => !x.ok && /has a variants block/.test(x.msg)), "validator refuses a seed for a scenario without variants");
}
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
ok(/"soc-shift:" \+ SCN\.id/.test(appJs), "storage key is per scenario");
ok(/state\.acks\[ui\.sel\] = simIso\(\)/.test(appJs), "opening an alert in the queue acknowledges it on the shift clock");
ok(/SOC\.variant\(SCN, state\.seed\)/.test(appJs) && /get\("seed"\)/.test(appJs), "?seed=N loads a seeded variant");
ok(["theHiveCase", "irisAlert", "stixBundle", "navigatorLayer", "shiftMetrics", "verdictExport"].every((f) => appJs.includes("SOC." + f + "(")), "the page offers every export and the shift timing");
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
