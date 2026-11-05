/* SOC Shift engine: scenario loading, detections, correlations, pivots, response, tuning, handover, grading.
   Pure functions over a loaded scenario + Sigma (vendor/sigma.js). Runs in the browser (window.SOC)
   and in node (require), so the tests and the scenario validator use the same code as the page. */
(function (root) {
  "use strict";
  var Sigma = root.Sigma || (typeof require === "function" ? require("../vendor/sigma.js") : null);

  var LEVEL_RANK = { informational: 0, info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  var SEVS = ["info", "low", "medium", "high", "critical"];
  var VERDICTS = ["tp", "benign", "fp", "escalate"];

  function get(o, path) {
    var cur = o; String(path).split(".").forEach(function (p) { cur = cur == null ? undefined : cur[p]; }); return cur;
  }
  function stripDomain(u) { return u ? String(u).replace(/@.*$/, "") : u; }
  function hostOf(url) { if (!url) return null; var m = String(url).match(/^(?:https?:\/\/)?([^\/:?#]+)/); return m ? m[1] : null; }
  function isIp(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(s || "")); }
  function hhmmToMin(s) { var m = String(s || "").match(/^(\d{1,2}):(\d{2})/); return m ? +m[1] * 60 + +m[2] : null; }
  function normTime(t) { t = String(t); return /Z$|[+-]\d{2}:?\d{2}$/.test(t) ? t : t + "Z"; }

  /* ---------- scenario loading ---------- */
  // Turns an authored scenario into the working data set: times normalised to UTC "Z",
  // events sorted (stable) and numbered, defaults filled in. The authored object is not changed.
  function load(scn) {
    var d = JSON.parse(JSON.stringify(scn));
    d.events = (d.events || []).map(function (e, i) { e._t = normTime(e._t); e._order = i; return e; });
    d.events.sort(function (a, b) { return a._t < b._t ? -1 : a._t > b._t ? 1 : a._order - b._order; });
    d.events.forEach(function (e, i) { e._id = "ev" + String(i + 1).padStart(3, "0"); delete e._order; });
    d.rules = d.rules || []; d.correlations = d.correlations || []; d.hunts = d.hunts || [];
    d.rules.forEach(function (r) { r.yaml = String(r.yaml).replace(/^\s*\n/, ""); });
    d.hunts.forEach(function (r) { r.yaml = String(r.yaml).replace(/^\s*\n/, ""); });
    d.correlations.forEach(function (c) { if (c.select) c.select = String(c.select).replace(/^\s*\n/, ""); });
    d.answers = d.answers || {}; d.huntAnswers = d.huntAnswers || {};
    var s = d.estate.shift;
    s.team = s.team || s.name + " SOC";
    s.nextTeam = s.nextTeam || s.to + " SOC (next shift)";
    s.startMin = hhmmToMin(s.startUtc); s.endMin = hhmmToMin(s.endUtc);
    d.owners = d.owners || [s.team, s.nextTeam, "IR lead", "IT operations"];
    d.noisyEntities = d.noisyEntities || [];
    d.handoverIn = d.handoverIn || null;
    return d;
  }

  /* ---------- entities ---------- */
  function entitiesOf(ev) {
    var out = [];
    function add(type, v) { if (v === undefined || v === null || v === "") return; v = String(v); if (!out.some(function (e) { return e.type === type && e.value === v; })) out.push({ type: type, value: v }); }
    add("user", stripDomain(ev.AccountName !== "SYSTEM" ? ev.AccountName : null));
    add("user", stripDomain(get(ev, "actor.alternateId")));
    add("user", stripDomain(ev.user));
    add("user", get(ev, "userIdentity.userName"));
    add("host", ev.DeviceName);
    ["RemoteIP", "ClientIP", "sourceIPAddress", "dst_ip"].forEach(function (k) { if (isIp(ev[k])) add("ip", ev[k]); });
    if (isIp(get(ev, "client.ipAddress"))) add("ip", get(ev, "client.ipAddress"));
    var url = ev.url || null;
    add("domain", ev.RemoteUrl || null);
    add("domain", ev.ClientRequestHost);
    if (url && !isIp(hostOf(url))) add("domain", hostOf(url));
    add("package", ev.PackageName);
    add("customer", ev.CustomerId);
    add("session", get(ev, "authenticationContext.externalSessionId"));
    add("cloudkey", get(ev, "userIdentity.accessKeyId"));
    add("file", ev.filename);
    return out;
  }

  // One-line summaries for the built-in log shapes. An event can carry its own _summary.
  function summarize(ev) {
    if (ev._summary) return ev._summary;
    switch (ev._src) {
      case "edr":
        if (ev.ActionType === "ProcessCreated") return (ev.InitiatingProcessFileName || "?") + " → " + (ev.ProcessCommandLine || ev.FileName);
        if (ev.ActionType === "FileRead") return (ev.InitiatingProcessFileName || ev.FileName) + " read " + ev.TargetFilePath;
        if (ev.ActionType === "FileCreated") return "created " + ev.FolderPath;
        if (ev.ActionType === "ConnectionSuccess") return ev.InitiatingProcessFileName + " → " + ev.RemoteIP + ":" + ev.RemotePort + (ev.BytesSent ? " (" + fmtBytes(ev.BytesSent) + " sent)" : "");
        return ev.ActionType + " " + (ev.Note || "");
      case "sse": return ev.action + " " + ev.url + (ev.filename ? " [" + ev.filename + "]" : "") + (ev.bytes_out > 100000 ? " (" + fmtBytes(ev.bytes_out) + " out)" : "");
      case "waf": return ev.SecurityAction + " " + ev.ClientRequestMethod + " " + ev.ClientRequestHost + decodeSafe(ev.ClientRequestPath) + " → " + ev.EdgeResponseStatus + (ev.RequestCount > 1 ? " ×" + ev.RequestCount : "");
      case "idp": return ev.eventType + " " + get(ev, "outcome.result") + (ev.target ? " → " + ev.target[0].displayName : "") + " from " + get(ev, "client.ipAddress") + " (" + get(ev, "securityContext.asOrg") + ")";
      case "cloud": return ev.eventName + (ev.requestParameters ? " " + ev.requestParameters.bucketName + "/" + ev.requestParameters.key : "") + (ev.errorCode ? " [" + ev.errorCode + "]" : "") + " from " + ev.sourceIPAddress;
    }
    return Object.keys(ev).filter(function (k) { return k[0] !== "_"; }).slice(0, 6).map(function (k) { var v = ev[k]; return k + "=" + (typeof v === "object" ? JSON.stringify(v) : v); }).join(" ");
  }
  function decodeSafe(s) { try { return decodeURIComponent(s); } catch (e) { return s; } }
  function fmtBytes(b) { return b > 1048576 ? (b / 1048576).toFixed(1) + " MB" : b > 1024 ? Math.round(b / 1024) + " KB" : b + " B"; }

  /* ---------- detections ---------- */
  function compileYaml(yaml) {
    var parsed = Sigma.parse(yaml), c = Sigma.compile(parsed.rule || parsed);
    return c;
  }
  function compileRules(rules) {
    return rules.map(function (r) { var c = compileYaml(r.yaml); return { def: r, compiled: c, rule: c.rule }; });
  }
  function groupKey(def, ev) {
    if (def.groupBy) return stripDomain(get(ev, def.groupBy));
    var platform = def.platform;
    if (platform === "EDR") return ev.DeviceName;
    if (platform === "WAF") return ev.ClientIP;
    if (platform === "SSE") return stripDomain(ev.user);
    if (platform === "SIEM") return stripDomain(get(ev, "actor.alternateId") || get(ev, "userIdentity.userName"));
    return "-";
  }
  function attackOf(tags) {
    return [].concat(tags || []).filter(function (t) { return /^attack\.t\d{4}/i.test(t); }).map(function (t) { return t.slice(7).toUpperCase(); });
  }
  function shiftStart(data) { return data.estate.shift.date + "T" + data.estate.shift.startUtc; }

  function runDetections(data, opts) {
    opts = opts || {};
    var compiled = compileRules(opts.rules || data.rules), alerts = {}, from = opts.from == null ? shiftStart(data) : opts.from;
    data.events.forEach(function (ev) {
      if (ev._t < from) return; // only this shift's events raise alerts; earlier ones are context
      compiled.forEach(function (c) {
        var res = Sigma.match(c.compiled, ev);
        if (!res.match) return;
        var gk = groupKey(c.def, ev), key = c.def.id + "|" + gk;
        var a = alerts[key] || (alerts[key] = { id: key, ruleId: c.def.id, platform: c.def.platform, key: gk, title: c.rule.title, level: c.rule.level, attack: attackOf(c.rule.tags), description: c.rule.description, falsepositives: [].concat(c.rule.falsepositives || []), events: [], first: ev._t, last: ev._t, at: ev._t, kind: "sigma" });
        a.events.push(ev._id); if (ev._t < a.first) a.first = ev._t; if (ev._t > a.last) a.last = ev._t;
      });
    });
    correlate(data, from).forEach(function (a) { alerts[a.id] = a; });
    return Object.keys(alerts).map(function (k) { return alerts[k]; }).sort(function (a, b) { return a.at < b.at ? -1 : a.at > b.at ? 1 : a.id < b.id ? -1 : 1; });
  }

  /* ---------- correlations: built-in types, parameters come from the scenario ---------- */
  function selector(c) {
    if (!c.select) return function () { return true; };
    var comp = compileYaml("title: " + c.id + " selection\nlogsource: { category: any }\n" + c.select);
    return function (e) { return Sigma.match(comp, e).match; };
  }
  function corrAlert(c, key, events, first, last, at, facts) {
    return { id: c.id + "|" + key, ruleId: c.id, platform: c.platform, key: key, title: c.title, level: c.level, attack: c.attack.slice(), description: c.description,
      falsepositives: [].concat(c.falsepositives || []), events: events, first: first, last: last, at: at, kind: "correlation", facts: facts };
  }
  var CORRELATORS = {
    // Many failed attempts from many sources in one group, then a success inside the window.
    // The alert keys on the success's subject and pulls in every later event on that subject.
    burst_then_success: function (c, inShift, all) {
      var out = [], pick = selector(c), L = c.labels || {};
      var attempts = inShift.filter(pick), byGroup = {};
      attempts.forEach(function (e) { var g = get(e, c.groupBy); (byGroup[g] = byGroup[g] || []).push(e); });
      Object.keys(byGroup).forEach(function (g) {
        var list = byGroup[g];
        var isWin = function (e) { return get(e, c.success.field) === c.success.equals; };
        var fails = list.filter(function (e) { return !isWin(e); });
        if (!fails.length) return;
        var count = c.countField ? fails.reduce(function (s, e) { return s + (+get(e, c.countField) || 0); }, 0) : fails.length;
        var srcs = {}; fails.forEach(function (e) { srcs[get(e, c.sourceField)] = 1; });
        if (count < (c.minCount || 0) || Object.keys(srcs).length < (c.minSources || 0)) return;
        var t0 = Date.parse(fails[0]._t), win = (c.windowMinutes || 15) * 60000;
        list.filter(function (e) { return isWin(e) && get(e, c.subjectField) && Date.parse(e._t) - t0 < win; }).forEach(function (w) {
          var subj = get(w, c.subjectField), follow = inShift.filter(function (e) { return get(e, c.subjectField) === subj; });
          var ids = fails.map(function (e) { return e._id; }).concat(follow.map(function (e) { return e._id; }));
          out.push(corrAlert(c, subj, ids, fails[0]._t, follow[follow.length - 1]._t, w._t, [
            fails.length + " " + (L.sources || "sources in") + " " + g,
            count + " " + (L.count || "attempts"),
            c.success.equals + " for " + subj + " from " + get(w, c.sourceField) + (w.LeakedCredentialCheck ? " (" + String(w.LeakedCredentialCheck).replace(/_/g, " ") + ")" : ""),
            (follow.length - 1) + " " + (L.followOn || "follow-on events on the same subject")]));
        });
      });
      return out;
    },
    // One key (a session id, a token) seen with several values of another field (ASN, country, device).
    same_key_many_values: function (c, inShift, all, from) {
      var out = [], pick = selector(c), L = c.labels || {}, byKey = {};
      var pool = c.includeEarlier ? inShift.concat(all.filter(function (e) { return e._t < from; })) : inShift;
      pool.filter(pick).forEach(function (e) { var k = get(e, c.keyField); if (k != null && k !== "") (byKey[k] = byKey[k] || []).push(e); });
      Object.keys(byKey).forEach(function (k) {
        var list = byKey[k].sort(function (a, b) { return a._t < b._t ? -1 : 1; }), vals = {};
        list.forEach(function (e) { vals[get(e, c.valueField)] = 1; });
        if (Object.keys(vals).length < (c.minValues || 2)) return;
        var subj = stripDomain(get(list[0], c.subjectField)), firstVal = get(list[0], c.valueField);
        var at = list.filter(function (e) { return get(e, c.valueField) !== firstVal; })[0]._t;
        if (at < from) return;
        out.push(corrAlert(c, subj, list.map(function (e) { return e._id; }), list[0]._t, list[list.length - 1]._t, at, [
          (L.key || "key") + " " + k + " from: " + Object.keys(vals).join(" and "), list.length + " " + (L.events || "events with that key")]));
      });
      return out;
    }
  };
  function correlate(data, from) {
    var inShift = data.events.filter(function (e) { return e._t >= from; }), out = [];
    data.correlations.forEach(function (c) {
      var fn = CORRELATORS[c.type];
      if (!fn) throw new Error("Unknown correlation type '" + c.type + "' in " + c.id);
      out = out.concat(fn(c, inShift, data.events, from));
    });
    return out;
  }

  /* ---------- pivots ---------- */
  function indexEntities(data) {
    var idx = {};
    data.events.forEach(function (ev) {
      ev._ents = entitiesOf(ev);
      ev._ents.forEach(function (e) { var k = e.type + ":" + e.value; (idx[k] = idx[k] || []).push(ev._id); });
    });
    return idx;
  }
  function byId(data) { var m = {}; data.events.forEach(function (e) { m[e._id] = e; }); return m; }

  function alertEntities(alert, evmap) {
    var seen = {}, out = [];
    alert.events.forEach(function (id) { (evmap[id]._ents || entitiesOf(evmap[id])).forEach(function (e) { var k = e.type + ":" + e.value; if (!seen[k]) { seen[k] = 1; out.push(e); } }); });
    return out;
  }
  function relatedAlerts(alert, alerts, evmap, users, noisy) {
    var NOISY = {}; (noisy || []).forEach(function (v) { NOISY[v] = 1; });
    var mine = alertEntities(alert, evmap).filter(function (e) { return !NOISY[e.value]; });
    var expand = mine.slice(); // a user's own host links too
    mine.forEach(function (e) { if (e.type === "user" && users[e.value]) expand.push({ type: "host", value: users[e.value].host }); });
    var keys = {}; expand.forEach(function (e) { keys[e.type + ":" + e.value] = e; });
    return alerts.filter(function (a) { return a.id !== alert.id; }).map(function (a) {
      var shared = alertEntities(a, evmap).filter(function (e) { return keys[e.type + ":" + e.value]; });
      if (!shared.length) shared = alertEntities(a, evmap).filter(function (e) { return e.type === "user" && users[e.value] && keys["host:" + users[e.value].host]; });
      return { alert: a, shared: shared };
    }).filter(function (r) { return r.shared.length; });
  }

  function timeline(entity, data, idx, evmap) {
    return (idx[entity.type + ":" + entity.value] || []).map(function (id) { return evmap[id]; }).sort(function (a, b) { return a._t < b._t ? -1 : 1; });
  }

  /* ---------- response actions ---------- */
  // self: the SOC can do it now. Otherwise it goes to the owner and stays pending.
  // A scenario can replace the list for an entity type with its own "actions" map.
  var ACTIONS = {
    host: [
      { id: "isolate", label: "Isolate host", platform: "EDR", self: true, effect: "Network contained except to the EDR cloud." },
      { id: "triage-pkg", label: "Collect triage package", platform: "EDR", self: true, effect: "Process tree, persistence, browser artefacts collected." }
    ],
    ip: [
      { id: "block-sse", label: "Block on SSE", platform: "SSE", self: true, effect: "Destination blocked for all users." },
      { id: "block-waf", label: "Block on WAF", platform: "WAF", self: true, effect: "Custom rule: block source on customer hosts." }
    ],
    domain: [{ id: "block-domain", label: "Block domain on SSE", platform: "SSE", self: true, effect: "Category override: blocked." }],
    user: [
      { id: "revoke", label: "Revoke all sessions", platform: "IdP", self: true, effect: "All IdP and downstream SSO sessions killed." },
      { id: "disable", label: "Disable account", platform: "IdP", self: true, effect: "Sign-in blocked until IT re-enables." },
      { id: "reset", label: "Force password + MFA reset", platform: "IdP", owner: "IT operations", effect: "Ticket raised; IT confirms with the user out of band." }
    ],
    cloudkey: [{ id: "deactivate-key", label: "Deactivate access key", platform: "AWS", owner: "Cloud platform", effect: "Needs the Cloud team: key is used by a deploy script." }],
    customer: [
      { id: "lock-customer", label: "Lock customer account + hold withdrawals", platform: "Back office", owner: "Fraud / Customer support", effect: "Needs Fraud to apply and contact the customer." }
    ],
    package: [{ id: "block-package", label: "Block package in registry proxy", platform: "Artifact proxy", self: true, effect: "Package and version denied for every build." }],
    file: [{ id: "dlp-case", label: "Open DLP case", platform: "SSE", owner: "Data protection", effect: "Data protection contacts the user's manager." }],
    session: [{ id: "revoke-session", label: "Revoke this session", platform: "IdP", self: true, effect: "Session id invalidated." }]
  };
  function actionsFor(entity, data) { var o = data && data.actions; return (o && o[entity.type]) || ACTIONS[entity.type] || []; }
  function applyAction(state, caseId, entity, action, nowIso, team) {
    var rec = { at: nowIso, caseId: caseId, entity: entity.type + ":" + entity.value, action: action.id, label: action.label, platform: action.platform,
      status: action.self ? "done" : "pending", owner: action.self ? (team || "SOC") : action.owner, effect: action.effect };
    state.actions.push(rec);
    return rec;
  }

  /* ---------- tuning ---------- */
  // Fields tried, per platform, when looking for what separates noise from confirmed alerts.
  var PREFERRED = { EDR: ["InitiatingProcessFolderPath", "InitiatingProcessSigner"], WAF: ["ClientIP", "ClientRequestHost"], SSE: ["user"], SIEM: ["client.ipAddress"] };
  function proposeTuning(ruleDef, alerts, verdicts, data) {
    var evmap = byId(data);
    var mine = alerts.filter(function (a) { return a.ruleId === ruleDef.id; });
    var noisy = mine.filter(function (a) { var v = verdicts[a.id]; return v && (v.verdict === "fp" || v.verdict === "benign"); });
    var keep = mine.filter(function (a) { var v = verdicts[a.id]; return v && (v.verdict === "tp" || v.verdict === "escalate"); });
    if (!noisy.length) return null;
    var fields = ruleDef.tuningFields || PREFERRED[ruleDef.platform] || [];
    var filter = {};
    fields.forEach(function (f) {
      var vals = {};
      noisy.forEach(function (a) { a.events.forEach(function (id) { var v = get(evmap[id], f); if (v !== undefined && v !== "") vals[v] = 1; }); });
      var keepVals = {};
      keep.forEach(function (a) { a.events.forEach(function (id) { var v = get(evmap[id], f); if (v !== undefined) keepVals[v] = 1; }); });
      var list = Object.keys(vals).filter(function (v) { return !keepVals[v]; });
      if (list.length) filter[f] = list;
    });
    if (!Object.keys(filter).length) return { rule: ruleDef, noisy: noisy, keep: keep, error: "No field separates the noisy alerts from the confirmed ones. Tune by hand." };
    var lines = ruleDef.yaml.replace(/\s+$/, "").split("\n"), out = [], inDet = false, condIdx = -1;
    lines.forEach(function (l) { out.push(l); if (/^detection:/.test(l)) inDet = true; if (inDet && /^\s+condition:/.test(l)) condIdx = out.length - 1; });
    var add = ["  filter_tuned:"];
    Object.keys(filter).forEach(function (f) { add.push("    " + f + ": [" + filter[f].map(function (v) { return "'" + String(v).replace(/'/g, "''") + "'"; }).join(", ") + "]"); });
    var cond = out[condIdx].replace(/condition:\s*(.*)$/, function (_, c) { return "condition: (" + c + ") and not filter_tuned"; });
    out.splice(condIdx, 1, add.join("\n"), cond);
    var yaml = out.join("\n") + "\n" + (ruleDef.tuningNote || "# review in 30 days");
    // regression check: re-run the tuned rule over the lake
    var tunedRules = data.rules.map(function (r) { return r.id === ruleDef.id ? { id: r.id, platform: r.platform, groupBy: r.groupBy, yaml: yaml } : r; });
    var after = runDetections(data, { rules: tunedRules }).filter(function (a) { return a.ruleId === ruleDef.id; });
    var afterIds = {}; after.forEach(function (a) { afterIds[a.id] = 1; });
    var lostTp = keep.filter(function (a) { return !afterIds[a.id]; });
    var removed = noisy.filter(function (a) { return !afterIds[a.id]; });
    return { rule: ruleDef, yaml: yaml, filter: filter, noisy: noisy, keep: keep, removed: removed, lostTp: lostTp, before: mine.length, after: after.length };
  }

  /* ---------- handover in ---------- */
  // Acknowledging the incoming handover makes its cases, pending actions and watch items yours.
  function acknowledge(state, data, nowIso) {
    var H = data.handoverIn, s = data.estate.shift;
    state.ackIn = nowIso;
    if (!H) return state;
    H.items.filter(function (i) { return i.kind === "case"; }).forEach(function (c) {
      state.incidents[c.case] = { id: c.case, title: c.title, severity: c.severity, status: "open", summary: c.done, next: c.next, owner: s.team, due: c.due, alerts: [], extra: [], irNotified: false, carried: true, ticket: c.ticket || null };
      if (c.pendingAction) { var p = c.pendingAction; state.actions.push({ at: nowIso, caseId: c.case, entity: p.entity, action: p.action, label: p.label, platform: p.platform, status: "pending", owner: p.owner, effect: "Carried in from " + H.from + "." }); }
    });
    (H.watch || []).forEach(function (w) { if (state.watch.indexOf(w) < 0) state.watch.push(w); });
    return state;
  }

  /* ---------- handover out ---------- */
  function buildHandover(state, alerts, data) {
    var s = data.estate.shift, v = state.verdicts, inc = state.incidents;
    var count = { alerts: alerts.length, tp: 0, fp: 0, benign: 0, escalate: 0, open: 0 };
    alerts.forEach(function (a) { var x = v[a.id]; if (!x) count.open++; else count[x.verdict] = (count[x.verdict] || 0) + 1; });
    var L = [];
    L.push("# Shift handover: " + s.name + " → " + s.to + ", " + s.date + " (" + s.startUtc + " to " + s.endUtc + " UTC)");
    L.push("");
    L.push("**Carried in from " + s.from + ":** " + (state.ackIn ? "acknowledged at " + state.ackIn.slice(11, 16) + " UTC" : "NOT acknowledged"));
    L.push("**Alerts:** " + count.alerts + " in, " + (count.alerts - count.open) + " triaged (" + count.tp + " true positive, " + count.benign + " benign, " + count.fp + " false positive, " + count.escalate + " escalated), " + count.open + " untriaged");
    L.push("");
    L.push("## Open incidents");
    var openInc = Object.keys(inc).map(function (k) { return inc[k]; }).filter(function (i) { return i.status !== "closed"; });
    if (!openInc.length) L.push("None.");
    openInc.forEach(function (i) {
      L.push("### " + i.id + " [" + i.severity.toUpperCase() + ", " + i.status + "] " + i.title);
      L.push("- What happened: " + (i.summary || "(missing)"));
      var acts = state.actions.filter(function (a) { return a.caseId === i.id; });
      L.push("- Done: " + (acts.filter(function (a) { return a.status === "done"; }).map(function (a) { return a.label + " on " + a.entity + " (" + a.at.slice(11, 16) + ")"; }).join("; ") || "no response actions yet"));
      var pend = acts.filter(function (a) { return a.status === "pending"; });
      if (pend.length) L.push("- Waiting on: " + pend.map(function (a) { return a.label + " on " + a.entity + " (" + a.owner + ")"; }).join("; "));
      L.push("- Next action: " + (i.next || "(missing)"));
      L.push("- Owner: " + (i.owner || "(missing)") + " · Due: " + (i.due || "(missing)"));
      L.push("- Alerts: " + i.alerts.join(", "));
    });
    L.push("");
    L.push("## Pending actions with other teams");
    var pend = state.actions.filter(function (a) { return a.status === "pending"; });
    L.push(pend.length ? pend.map(function (a) { return "- " + a.label + " on " + a.entity + ": " + a.owner + " (raised " + a.at.slice(11, 16) + " UTC, " + a.caseId + ")"; }).join("\n") : "None.");
    L.push("");
    L.push("## Watch list");
    L.push(state.watch.length ? state.watch.map(function (w) { return "- " + w; }).join("\n") : "None.");
    L.push("");
    L.push("## Detection tuning requests");
    L.push(state.tuning.length ? state.tuning.map(function (t) { return "- " + t.ruleId + ": " + t.summary; }).join("\n") : "None.");
    L.push("");
    L.push("## Untriaged alerts");
    var un = alerts.filter(function (a) { return !v[a.id]; });
    L.push(un.length ? un.map(function (a) { return "- " + a.id + " (" + a.level + ") " + a.title; }).join("\n") : "None.");
    return L.join("\n");
  }

  function lintHandover(state, alerts, nowHHMM, data) {
    var issues = [], s = data.estate.shift, H = data.handoverIn;
    if (H && !state.ackIn) issues.push({ sev: "high", msg: "The " + H.from + " handover was never acknowledged." });
    if (H) H.items.filter(function (it) { return it.kind === "case" && it.ticket; }).forEach(function (it) {
      var c = state.incidents[it.case];
      if (c && c.status !== "closed" && (c.next || "").indexOf(it.ticket) < 0) issues.push({ sev: "medium", msg: it.case + " came in with " + it.ticket + " pending; the next action does not mention it." });
    });
    Object.keys(state.incidents).forEach(function (k) {
      var i = state.incidents[k];
      if (i.status === "closed") return;
      if (!i.next) issues.push({ sev: "high", msg: i.id + " has no next action." });
      if (!i.owner) issues.push({ sev: "high", msg: i.id + " has no owner." });
      if (!i.due) issues.push({ sev: "medium", msg: i.id + " has no due time." });
      else if (nowHHMM && /^\d{2}:\d{2}/.test(i.due) && i.due.slice(0, 5) < nowHHMM && i.owner === s.team) issues.push({ sev: "medium", msg: i.id + " was due at " + i.due + " and " + s.team + " still owns it: update the due time or hand it to " + s.to + "." });
      if (!i.summary) issues.push({ sev: "medium", msg: i.id + " has no one-line summary of what happened." });
      var acts = state.actions.filter(function (a) { return a.caseId === i.id; });
      if ((i.severity === "high" || i.severity === "critical") && !acts.length) issues.push({ sev: "high", msg: i.id + " is " + i.severity + " with no response action taken." });
      if (i.severity === "critical" && !i.irNotified) issues.push({ sev: "high", msg: i.id + " is critical and the IR lead is not marked as notified." });
    });
    alerts.forEach(function (a) {
      var v = state.verdicts[a.id];
      if (!v) issues.push({ sev: LEVEL_RANK[a.level] >= 3 ? "high" : "low", msg: a.id + " (" + a.level + ") is untriaged." });
      else if (!v.reason || v.reason.length < 15) issues.push({ sev: "low", msg: a.id + " was closed as " + v.verdict + " without a reason the next shift can check." });
      else if ((v.verdict === "tp" || v.verdict === "escalate") && !v.incident && LEVEL_RANK[v.sev] >= 2) issues.push({ sev: "medium", msg: a.id + " is " + v.verdict + " but not linked to an incident." });
    });
    state.actions.filter(function (a) { return a.status === "pending"; }).forEach(function (a) {
      if (!state.incidents[a.caseId] || state.incidents[a.caseId].status === "closed") issues.push({ sev: "medium", msg: "Pending action '" + a.label + "' belongs to a closed or missing case." });
    });
    var rank = { high: 0, medium: 1, low: 2 };
    return issues.sort(function (a, b) { return rank[a.sev] - rank[b.sev]; });
  }

  /* ---------- grading ---------- */
  // A verdict matches when it equals the key. Escalate and true positive count as the same call.
  function verdictMatches(key, mine) { return key.verdict === mine.verdict || (key.verdict === "escalate" && mine.verdict === "tp") || (key.verdict === "tp" && mine.verdict === "escalate"); }
  function grade(state, alerts, data) {
    var rows = alerts.map(function (a) {
      var key = data.answers[a.id], mine = state.verdicts[a.id];
      return { alert: a, key: key || null, mine: mine || null, ok: key && mine ? verdictMatches(key, mine) : false };
    });
    var hunts = Object.keys(data.huntAnswers).map(function (h) { var x = data.huntAnswers[h]; return { id: h, ran: state.huntsRun[h] !== undefined, note: typeof x === "string" ? x : x.note }; });
    return { rows: rows, score: rows.filter(function (r) { return r.ok; }).length, total: rows.length, hunts: hunts };
  }

  // The state a shift that follows the answer key ends with. Used by the tests and the validator.
  function answerKeyState(data, alerts) {
    var s = data.estate.shift, st = newState(), d = s.date, end = s.endMin - 20;
    var hhmm = function (m) { return String(Math.floor(m / 60)).padStart(2, "0") + ":" + String(m % 60).padStart(2, "0"); };
    acknowledge(st, data, d + "T" + hhmm(s.startMin + 5) + ":00Z");
    alerts.forEach(function (a) {
      var k = data.answers[a.id]; if (!k) return;
      st.verdicts[a.id] = { verdict: k.verdict, sev: k.sev, reason: k.why, incident: k.incident || null, at: d + "T" + hhmm(end) + ":00Z" };
      if (!k.incident) return;
      var i = st.incidents[k.incident] || (st.incidents[k.incident] = { id: k.incident, title: k.incident, severity: k.sev, status: "open", summary: "", next: "", owner: "", due: "", alerts: [], extra: [], irNotified: false });
      if (SEVS.indexOf(k.sev) > SEVS.indexOf(i.severity)) i.severity = k.sev;
      i.alerts.push(a.id);
      i.summary = i.summary || k.why; i.next = i.next || "Continue response; see the alert reasons.";
      i.owner = s.nextTeam; i.due = hhmm(Math.min(s.endMin + 60, 1439)) + " UTC"; i.irNotified = true;
      if (!st.actions.some(function (x) { return x.caseId === i.id && x.status === "done"; })) st.actions.push({ caseId: i.id, status: "done", label: "Answer-key response", entity: a.id, at: d + "T" + hhmm(end) + ":00Z", owner: s.team });
    });
    st.actions.forEach(function (x) { if (x.status === "pending") x.status = "done"; });
    return st;
  }

  /* ---------- verdict export ---------- */
  // One NDJSON line per alert with a verdict, in a generic alert shape (rule, disposition, times)
  // that alert-quality tools can read.
  var DISPOSITION = { tp: "true_positive", escalate: "true_positive", benign: "benign_true_positive", fp: "false_positive" };
  function verdictExport(state, alerts) {
    return alerts.filter(function (a) { return state.verdicts[a.id]; }).map(function (a) {
      var v = state.verdicts[a.id];
      return JSON.stringify({ alert_id: a.id, rule: a.ruleId + " " + a.title, title: a.title, technique: a.attack.join(","), severity: v.sev || a.level, platform: a.platform, entity: a.key,
        event_time: normTime(a.first), alert_time: normTime(a.at), close_time: v.at ? normTime(v.at) : null, disposition: DISPOSITION[v.verdict], verdict: v.verdict, incident: v.incident || null, reason: v.reason || "" });
    }).join("\n") + "\n";
  }

  function newState() {
    return { verdicts: {}, incidents: {}, actions: [], watch: [], tuning: [], huntsRun: {}, ackIn: null, enrich: {} };
  }

  var api = { load: load, entitiesOf: entitiesOf, summarize: summarize, runDetections: runDetections, correlate: correlate, CORRELATORS: CORRELATORS, indexEntities: indexEntities, byId: byId,
    alertEntities: alertEntities, relatedAlerts: relatedAlerts, timeline: timeline, actionsFor: actionsFor, applyAction: applyAction, ACTIONS: ACTIONS,
    proposeTuning: proposeTuning, acknowledge: acknowledge, buildHandover: buildHandover, lintHandover: lintHandover, grade: grade, verdictMatches: verdictMatches, answerKeyState: answerKeyState,
    newState: newState, SEVS: SEVS, VERDICTS: VERDICTS, LEVEL_RANK: LEVEL_RANK, verdictExport: verdictExport, DISPOSITION: DISPOSITION, fmtBytes: fmtBytes, decodeSafe: decodeSafe,
    get: get, isIp: isIp, hhmmToMin: hhmmToMin, compileRules: compileRules, compileYaml: compileYaml, shiftStart: shiftStart };
  if (typeof module === "object" && module.exports) module.exports = api; else root.SOC = api;
})(typeof window !== "undefined" ? window : globalThis);
