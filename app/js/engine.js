/* SOC Shift engine: scenario loading, seeded variants, detections, correlations, pivots, response, tuning, handover,
   grading, shift metrics and case exports (TheHive, DFIR-IRIS, STIX 2.1, ATT&CK Navigator).
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
    // Microsoft shapes: Entra ID sign-in and audit logs, the Microsoft 365 unified audit log, Defender for Office 365 email events
    add("user", stripDomain(ev.UserPrincipalName));
    add("user", stripDomain(ev.UserId));
    add("user", stripDomain(ev.AccountUpn));
    add("user", stripDomain(get(ev, "InitiatedBy.user.userPrincipalName")));
    add("host", get(ev, "DeviceDetail.displayName"));
    ["IPAddress", "SenderIPv4"].forEach(function (k) { if (isIp(ev[k])) add("ip", ev[k]); });
    if (isIp(get(ev, "InitiatedBy.user.ipAddress"))) add("ip", get(ev, "InitiatedBy.user.ipAddress"));
    add("session", ev.SessionId);
    add("session", get(ev, "AppAccessContext.AADSessionId"));
    add("app", ev.ClientAppId);
    var tr = (ev.TargetResources || [])[0];
    if (tr && tr.type === "ServicePrincipal") {
      var spn = (tr.modifiedProperties || []).filter(function (p) { return p.displayName === "TargetId.ServicePrincipalNames"; })[0];
      add("app", spn ? String(spn.newValue).replace(/"/g, "").split(";")[0] : tr.id);
    }
    if (ev._src === "email") {
      var inbound = ev.EmailDirection !== "Outbound";
      add("user", stripDomain(inbound ? ev.RecipientEmailAddress : ev.SenderFromAddress));
      add("email", inbound ? ev.SenderFromAddress : ev.RecipientEmailAddress);
      add("domain", inbound ? ev.SenderFromDomain : ev.RecipientEmailAddress && ev.RecipientEmailAddress.split("@")[1]);
      add("file", ev.FileName);
      if (ev.Url && !isIp(hostOf(ev.Url))) add("domain", hostOf(ev.Url));
    }
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
      case "signin": return "sign-in " + (+ev.ResultType === 0 ? "success" : "failure " + ev.ResultType) + " → " + ev.AppDisplayName + " from " + ev.IPAddress + " (AS" + ev.AutonomousSystemNumber + ")" + (ev.ClientAppUsed && ev.ClientAppUsed !== "Browser" ? " via " + ev.ClientAppUsed : "") + (/claim in the token/.test(JSON.stringify(ev.AuthenticationDetails || "")) ? ", MFA from token claim" : "");
      case "entraaudit": return ev.OperationName + " " + (ev.Result || "") + ((ev.TargetResources || [])[0] && ev.TargetResources[0].type === "ServicePrincipal" ? " → " + ev.TargetResources[0].displayName : "") + " by " + (get(ev, "InitiatedBy.user.userPrincipalName") || "?") + " from " + (get(ev, "InitiatedBy.user.ipAddress") || "?") + (ev.ResultReason ? " (" + ev.ResultReason + ")" : "");
      case "o365": return ev.Operation + (ev.Operation === "MailItemsAccessed" ? " " + (ev.MailAccessType || "") + " (" + (ev.OperationCount || 1) + " items)" : "") + (get(ev, "Item.Subject") ? ' "' + ev.Item.Subject + '"' : "") + " by " + ev.UserId + " from " + ev.ClientIP + (ev.ClientAppId ? " via app " + ev.ClientAppId : "");
      case "email": return ev.EmailDirection + " " + ev.DeliveryAction + ": " + ev.SenderFromAddress + " → " + ev.RecipientEmailAddress + ' "' + ev.Subject + '"' + (ev.FileName ? " [" + ev.FileName + "]" : "");
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
    if (platform === "SIEM") return stripDomain(get(ev, "actor.alternateId") || get(ev, "userIdentity.userName") || ev.UserPrincipalName || ev.UserId || get(ev, "InitiatedBy.user.userPrincipalName"));
    if (platform === "EMAIL") return stripDomain(ev.RecipientEmailAddress);
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
    // Pipeline latency: a Sigma alert lands after its first event by its platform's delay from the scenario
    // (alertDelayMinutes, or delayMinutes on the rule). Correlations fire at the event that completes them.
    var delays = data.alertDelayMinutes || {}, defs = {};
    compiled.forEach(function (c) { defs[c.def.id] = c.def; });
    Object.keys(alerts).forEach(function (k) {
      var a = alerts[k], r = defs[a.ruleId] || {}, d = r.delayMinutes != null ? +r.delayMinutes : +(delays[a.platform] || 0);
      if (d > 0) a.at = new Date(Date.parse(normTime(a.first)) + d * 60000).toISOString().replace(".000Z", "Z");
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
    session: [{ id: "revoke-session", label: "Revoke this session", platform: "IdP", self: true, effect: "Session id invalidated." }],
    app: [{ id: "disable-app", label: "Revoke grants and disable the app", platform: "Entra ID", self: true, effect: "OAuth grants removed and the service principal disabled." }],
    email: [{ id: "block-sender", label: "Block sender and purge their mail", platform: "Email", self: true, effect: "Sender on the tenant block list; delivered copies removed." }]
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
  var PREFERRED = { EDR: ["InitiatingProcessFolderPath", "InitiatingProcessSigner"], WAF: ["ClientIP", "ClientRequestHost"], SSE: ["user"], SIEM: ["client.ipAddress"], EMAIL: ["SenderFromDomain"] };
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

  /* ---------- shift timing: MTTD, MTTA, MTTR ----------
     Per alert, from the shift's own timestamps:
       time to detect      = alert time - first matching event time
       time to acknowledge = first time the alert was opened in the queue - alert time
       time to resolve     = verdict time - alert time
     Per incident: time to first response = first completed response action - earliest linked alert time.
     Means and nearest-rank medians are over the alerts that have both timestamps. */
  function mins(a, b) { if (!a || !b) return null; var d = (Date.parse(normTime(b)) - Date.parse(normTime(a))) / 60000; return isFinite(d) ? Math.max(0, d) : null; }
  function summary(list) {
    var s = list.filter(function (x) { return x !== null; }).sort(function (a, b) { return a - b; });
    if (!s.length) return { n: 0, mean: null, median: null, p90: null };
    var mean = s.reduce(function (t, x) { return t + x; }, 0) / s.length;
    return { n: s.length, mean: Math.round(mean * 10) / 10, median: s[Math.ceil(0.5 * s.length) - 1], p90: s[Math.ceil(0.9 * s.length) - 1] };
  }
  function shiftMetrics(state, alerts) {
    var acks = state.acks || {}, byAlert = {};
    alerts.forEach(function (a) { byAlert[a.id] = a; });
    var rows = alerts.map(function (a) {
      var v = state.verdicts[a.id];
      return { id: a.id, ttd: mins(a.first, a.at), tta: mins(a.at, acks[a.id]), ttr: v ? mins(a.at, v.at) : null };
    });
    var incidents = Object.keys(state.incidents).map(function (k) {
      var i = state.incidents[k], first = null;
      i.alerts.forEach(function (id) { var a = byAlert[id]; if (a && (!first || a.at < first)) first = a.at; });
      var done = state.actions.filter(function (x) { return x.caseId === i.id && x.status === "done"; }).map(function (x) { return x.doneAt || x.at; }).sort()[0] || null;
      return { id: i.id, ttrespond: first && done ? mins(first, done) : null };
    });
    return { rows: rows, mttd: summary(rows.map(function (r) { return r.ttd; })), mtta: summary(rows.map(function (r) { return r.tta; })), mttr: summary(rows.map(function (r) { return r.ttr; })),
      incidents: incidents, mttrespond: summary(incidents.map(function (r) { return r.ttrespond; })) };
  }

  /* ---------- observables with IOC flag, TLP and PAP ----------
     TLP 2.0 and PAP levels as TheHive 5 stores them (0 CLEAR, 1 GREEN, 2 AMBER, 3 RED; TLP 4 AMBER+STRICT).
     Defaults come from the scenario's "observables" block: attacker-side values are IOCs at TLP:GREEN / PAP:AMBER,
     internal people, hosts, sessions and keys are TLP:AMBER+STRICT / PAP:RED and never IOCs. */
  var TLP = { CLEAR: 0, GREEN: 1, AMBER: 2, RED: 3, "AMBER+STRICT": 4 };
  var PAP = { CLEAR: 0, GREEN: 1, AMBER: 2, RED: 3 };
  var OBS_DEFAULTS = { external: { tlp: "GREEN", pap: "AMBER" }, internal: { tlp: "AMBER+STRICT", pap: "RED" } };
  // TheHive 5 default observable types; DFIR-IRIS default IOC and asset type ids (a fresh install; check yours under Manage).
  var HIVE_TYPE = { ip: "ip", domain: "domain", host: "hostname", user: "other", customer: "other", session: "other", cloudkey: "other", package: "other", app: "other", file: "filename", url: "url", hash: "hash", email: "mail" };
  var IRIS_IOC = { ip: { id: 79, name: "ip-src" }, domain: { id: 20, name: "domain" }, file: { id: 37, name: "filename" }, url: { id: 141, name: "url" }, hash: { id: 113, name: "sha256" }, package: { id: 96, name: "other" }, app: { id: 96, name: "other" }, email: { id: 31, name: "email-src" } };
  var IRIS_ASSET = { account: 1, linux: 4, mac: 6, windows: 9 };
  var IRIS_TLP = { RED: 1, AMBER: 2, GREEN: 3, CLEAR: 4, "AMBER+STRICT": 5 };
  function ipInt(ip) { return String(ip).split(".").reduce(function (n, o) { return n * 256 + +o; }, 0); }
  function inCidr(ip, cidr) { var p = String(cidr).split("/"), size = Math.pow(2, 32 - +(p[1] || 32)), b = ipInt(p[0]), v = ipInt(ip); return v >= b && v < b + size; }
  function isInternalIp(ip, data) {
    if (["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8"].some(function (c) { return inCidr(ip, c); })) return true;
    return (data.estate.corpEgress || []).some(function (c) { return inCidr(ip, c); });
  }
  // Attacker-side by default; observables.notIoc lists well-known services and internal documents that are never IOCs.
  function isExternal(e, data) {
    var known = (data.observables && data.observables.notIoc) || [];
    if (known.some(function (k) { return e.value === k || (e.type === "domain" && e.value.slice(-k.length - 1) === "." + k); })) return false;
    if (e.type === "ip") return !isInternalIp(e.value, data);
    if (e.type === "domain") return !(data.estate.apps || {})[e.value];
    if (e.type === "email") { var dom = e.value.split("@")[1] || ""; return !known.some(function (k) { return dom === k || dom.slice(-k.length - 1) === "." + k; }); }
    return e.type === "package" || e.type === "file" || e.type === "url" || e.type === "hash" || e.type === "app";
  }
  function observables(state, incident, alerts, data) {
    var evmap = byId(data), seen = {}, out = [], over = state.obs || {}, NOISY = {}, cfg = data.observables || {};
    (data.noisyEntities || []).forEach(function (v) { NOISY[v] = 1; });
    var ext = cfg.external || OBS_DEFAULTS.external, inn = cfg.internal || OBS_DEFAULTS.internal;
    var byAlert = {}; alerts.forEach(function (a) { byAlert[a.id] = a; });
    function make(e, first, last, count, alertIds) {
      var x = isExternal(e, data), o = over[e.type + ":" + e.value] || {}, d = x ? ext : inn;
      return { type: e.type, value: e.value, ioc: o.ioc !== undefined ? !!o.ioc : x, tlp: o.tlp || d.tlp, pap: o.pap || d.pap, first: first, last: last, count: count, alerts: alertIds };
    }
    incident.alerts.forEach(function (id) {
      var a = byAlert[id]; if (!a) return;
      alertEntities(a, evmap).forEach(function (e) {
        var k = e.type + ":" + e.value; if (seen[k] || NOISY[e.value]) return;
        var times = a.events.map(function (x) { return evmap[x]; }).filter(function (ev) { return (ev._ents || entitiesOf(ev)).some(function (y) { return y.type === e.type && y.value === e.value; }); }).map(function (ev) { return ev._t; }).sort();
        seen[k] = make(e, times[0] || a.first, times[times.length - 1] || a.last, times.length, [a.id]);
        out.push(seen[k]);
      });
    });
    // Events the analyst attached from a hunt (incident.extra) carry observables too.
    (incident.extra || []).forEach(function (eid) {
      var ev = evmap[eid]; if (!ev) return;
      (ev._ents || entitiesOf(ev)).forEach(function (e) {
        var k = e.type + ":" + e.value, o = seen[k];
        if (NOISY[e.value]) return;
        if (o) { o.count++; if (ev._t < o.first) o.first = ev._t; if (ev._t > o.last) o.last = ev._t; return; }
        seen[k] = make(e, ev._t, ev._t, 1, []);
        out.push(seen[k]);
      });
    });
    incident.alerts.forEach(function (id) {
      var a = byAlert[id]; if (!a) return;
      var ents = alertEntities(a, evmap);
      out.forEach(function (o) { if (o.alerts.indexOf(id) < 0 && ents.some(function (e) { return e.type === o.type && e.value === o.value; })) o.alerts.push(id); });
    });
    return out;
  }

  /* ---------- case exports ---------- */
  function ms(t) { return Date.parse(normTime(t)); }
  var HIVE_SEV = { info: 1, low: 1, medium: 2, high: 3, critical: 4 };
  function tagsOf(o) { return ["soc-shift:entity=" + o.type].concat(o.alerts.map(function (a) { return "soc-shift:alert=" + a; })); }
  function hiveObservable(o) {
    return { dataType: HIVE_TYPE[o.type] || "other", data: o.value, message: o.type + " seen in " + o.count + " event" + (o.count === 1 ? "" : "s") + ", first " + normTime(o.first),
      tlp: TLP[o.tlp], pap: PAP[o.pap], ioc: !!o.ioc, sighted: true, sightedAt: ms(o.first), tags: tagsOf(o) };
  }
  // TheHive 5 InputAlert (POST /api/v1/alert) for one alert, and InputCase (POST /api/v1/case) with its observables, alerts and
  // ATT&CK procedures for one incident. Field names and types follow thehive4py 2.x types/alert.py, case.py, observable.py, task.py, procedure.py.
  function theHiveAlert(state, alert, data, obs) {
    var v = state.verdicts[alert.id] || {};
    return { type: "soc-shift", source: alert.platform, sourceRef: alert.id, title: alert.title + " on " + alert.key, description: (alert.description || alert.title) + (v.reason ? "\n\nAnalyst: " + v.reason : ""),
      severity: HIVE_SEV[v.sev || alert.level] || 2, date: ms(alert.at), tags: ["rule:" + alert.ruleId].concat(alert.attack.map(function (t) { return "mitre:" + t; })), tlp: TLP.AMBER, pap: PAP.AMBER,
      observables: (obs || []).filter(function (o) { return o.alerts.indexOf(alert.id) >= 0; }).map(hiveObservable),
      procedures: alert.attack.map(function (t) { return { patternId: t, occurDate: ms(alert.first), description: alert.title }; }) };
  }
  function theHiveCase(state, incident, alerts, data) {
    var obs = observables(state, incident, alerts, data), linked = alerts.filter(function (a) { return incident.alerts.indexOf(a.id) >= 0; });
    var start = linked.map(function (a) { return a.first; }).sort()[0];
    var acts = state.actions.filter(function (x) { return x.caseId === incident.id; });
    var c = { title: incident.id + " " + incident.title, description: (incident.summary || incident.title) + (incident.next ? "\n\nNext action: " + incident.next : "") + (incident.owner ? "\nOwner: " + incident.owner + (incident.due ? ", due " + incident.due : "") : ""),
      severity: HIVE_SEV[incident.severity] || 2, tags: ["soc-shift:incident=" + incident.id, "soc-shift:scenario=" + data.id], tlp: TLP.AMBER, pap: PAP.AMBER, flag: incident.severity === "critical",
      tasks: acts.map(function (x, i) { return { title: x.label + " on " + x.entity, group: x.platform || "response", description: x.effect || "", status: x.status === "done" ? "Completed" : "Waiting", order: i }; }) };
    if (start) c.startDate = ms(start);
    return { "case": c, observables: obs.map(hiveObservable), alerts: linked.map(function (a) { return theHiveAlert(state, a, data, obs); }),
      procedures: [].concat.apply([], linked.map(function (a) { return a.attack.map(function (t) { return { patternId: t, occurDate: ms(a.first), description: a.id }; }); })) };
  }
  // DFIR-IRIS alert (POST /api/v2/alerts, formerly /alerts/add) per alert. Column names from iris-backend app/models/alerts.py,
  // IOC and asset fields from IocSchema and CaseAssetsSchema (ioc_value required; asset_name and asset_type_id required).
  var IRIS_SEV = { info: 2, low: 3, medium: 4, high: 5, critical: 6 };
  function irisAssetType(o, data) {
    if (o.type === "user") return IRIS_ASSET.account;
    var os = String(((data.estate.hosts || {})[o.value] || {}).os || "");
    return /mac/i.test(os) ? IRIS_ASSET.mac : /linux/i.test(os) ? IRIS_ASSET.linux : IRIS_ASSET.windows;
  }
  function irisAlert(state, alert, data, obs, customerId) {
    var v = state.verdicts[alert.id] || {}, mine = (obs || []).filter(function (o) { return o.alerts.indexOf(alert.id) >= 0; });
    return { alert_title: alert.title + " on " + alert.key, alert_description: alert.description || alert.title, alert_source: alert.platform, alert_source_ref: alert.id,
      alert_source_event_time: normTime(alert.first), alert_severity_id: IRIS_SEV[v.sev || alert.level] || 4, alert_status_id: v.verdict ? 6 : 2, alert_customer_id: customerId || 1,
      alert_note: v.reason || "", alert_tags: ["rule:" + alert.ruleId].concat(alert.attack).join(","),
      alert_context: { rule: alert.ruleId, techniques: alert.attack, verdict: v.verdict || null, incident: v.incident || null, events: alert.events.length },
      alert_iocs: mine.filter(function (o) { return o.ioc && IRIS_IOC[o.type]; }).map(function (o) { return { ioc_value: o.value, ioc_type_id: IRIS_IOC[o.type].id, ioc_tlp_id: IRIS_TLP[o.tlp], ioc_description: o.type + " (" + IRIS_IOC[o.type].name + "), " + o.count + " events", ioc_tags: tagsOf(o).join(",") }; }),
      alert_assets: mine.filter(function (o) { return o.type === "host" || o.type === "user"; }).map(function (o) { return { asset_name: o.value, asset_type_id: irisAssetType(o, data), asset_description: o.type, asset_tags: "soc-shift:entity=" + o.type }; }) };
  }
  // STIX 2.1 bundle: the SOC as an identity, one indicator and one sighting per IOC observable, ATT&CK attack-patterns with
  // "indicates" relationships. Ids are deterministic in UUIDv4 form (STIX 2.1 asks for v4 on SDOs and SROs), hashed from content.
  function hex(str) { var h2 = 0x01000193, out = ""; for (var r = 0; r < 4; r++) { var x = 0x811c9dc5 ^ r; for (var i = 0; i < str.length; i++) { x ^= str.charCodeAt(i); x = Math.imul(x, h2) >>> 0; } out += ("00000000" + x.toString(16)).slice(-8); } return out; }
  function sid(type, key) { var x = hex(type + "|" + key); return type + "--" + x.slice(0, 8) + "-" + x.slice(8, 12) + "-4" + x.slice(13, 16) + "-" + ((parseInt(x[16], 16) & 3) | 8).toString(16) + x.slice(17, 20) + "-" + x.slice(20, 32); }
  function stixTime(t) { return new Date(ms(t)).toISOString().replace(/\.\d{3}Z$/, ".000Z"); }
  function stixPattern(o) {
    var q = String(o.value).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
    if (o.type === "ip") return "[ipv4-addr:value = '" + q + "']";
    if (o.type === "domain") return "[domain-name:value = '" + q + "']";
    if (o.type === "url") return "[url:value = '" + q + "']";
    if (o.type === "file") return "[file:name = '" + q + "']";
    if (o.type === "hash") return "[file:hashes.'SHA-256' = '" + q + "']";
    if (o.type === "package") return "[software:name = '" + q + "']";
    if (o.type === "email") return "[email-addr:value = '" + q + "']";
    return null;
  }
  function stixBundle(state, alerts, data, attackNames) {
    var s = data.estate.shift, created = stixTime(s.date + "T" + s.endUtc + ":00Z"), org = sid("identity", data.estate.company);
    var objs = [{ type: "identity", spec_version: "2.1", id: org, created: created, modified: created, name: data.estate.company + " SOC", identity_class: "organization" }];
    var ap = {}, ind = {}, rel = {}, byAlert = {};
    alerts.forEach(function (a) { byAlert[a.id] = a; });
    Object.keys(state.incidents).forEach(function (k) {
      var inc = state.incidents[k];
      observables(state, inc, alerts, data).filter(function (o) { return o.ioc && stixPattern(o); }).forEach(function (o) {
        var key = o.type + ":" + o.value;
        if (!ind[key]) {
          ind[key] = { type: "indicator", spec_version: "2.1", id: sid("indicator", key), created: created, modified: created, created_by_ref: org, name: o.type + " " + o.value,
            description: "Seen during the " + s.name + " shift " + s.date + " in " + inc.id + ".", indicator_types: ["malicious-activity"],
            pattern: stixPattern(o), pattern_type: "stix", valid_from: stixTime(o.first), labels: ["tlp:" + o.tlp.toLowerCase(), "pap:" + o.pap.toLowerCase()] };
          objs.push(ind[key]);
          objs.push({ type: "sighting", spec_version: "2.1", id: sid("sighting", key), created: created, modified: created, created_by_ref: org, first_seen: stixTime(o.first), last_seen: stixTime(o.last),
            count: o.count, sighting_of_ref: ind[key].id, where_sighted_refs: [org], description: o.alerts.length ? "Alerts: " + o.alerts.join(", ") : "Added from a hunt." });
        }
        o.alerts.forEach(function (aid) {
          var a = byAlert[aid]; if (!a) return;
          a.attack.forEach(function (t) {
            if (!ap[t]) { ap[t] = { type: "attack-pattern", spec_version: "2.1", id: sid("attack-pattern", t), created: created, modified: created, name: (attackNames && attackNames[t]) || t,
              external_references: [{ source_name: "mitre-attack", external_id: t }] }; objs.push(ap[t]); }
            var rid = sid("relationship", key + ">" + t);
            if (!rel[rid]) { rel[rid] = 1; objs.push({ type: "relationship", spec_version: "2.1", id: rid, created: created, modified: created, relationship_type: "indicates", source_ref: ind[key].id, target_ref: ap[t].id }); }
          });
        });
      });
    });
    return { type: "bundle", id: sid("bundle", data.id + "|" + s.date + "|" + objs.map(function (o) { return o.id; }).join(",")), objects: objs };
  }
  // ATT&CK Navigator layer (layer format 4.5) of the shift: score = alerts on the technique, colour by what the analyst concluded.
  function navigatorLayer(state, alerts, data, attackVersion) {
    var t = {}, s = data.estate.shift;
    alerts.forEach(function (a) {
      var v = state.verdicts[a.id];
      a.attack.forEach(function (id) {
        var x = t[id] || (t[id] = { score: 0, tp: 0, fp: 0, alerts: [] });
        x.score++; x.alerts.push(a.id);
        if (v && (v.verdict === "tp" || v.verdict === "escalate")) x.tp++;
        if (v && (v.verdict === "fp" || v.verdict === "benign")) x.fp++;
      });
    });
    var techniques = Object.keys(t).sort().map(function (id) {
      var x = t[id];
      return { techniqueID: id, score: x.score, color: x.tp ? "#c2410c" : x.fp ? "#94a3b8" : "#f59e0b", comment: x.tp + " true positive, " + x.fp + " false or benign, " + (x.score - x.tp - x.fp) + " untriaged: " + x.alerts.join(", "),
        enabled: true, showSubtechniques: false, metadata: [{ name: "alerts", value: String(x.score) }, { name: "true positives", value: String(x.tp) }] };
    });
    var max = techniques.reduce(function (m, x) { return Math.max(m, x.score); }, 1);
    return { name: s.name + " shift " + s.date, versions: { attack: String(attackVersion || "19").split(".")[0], navigator: "5.1.0", layer: "4.5" }, domain: "enterprise-attack",
      description: "Techniques behind the alerts of one SOC Shift (" + data.id + (data.seed ? ", variant " + data.seed : "") + "). Orange: a confirmed true positive. Grey: only false or benign. Amber: not yet triaged.",
      techniques: techniques, gradient: { colors: ["#fde68a", "#c2410c"], minValue: 0, maxValue: max },
      legendItems: [{ label: "true positive on the shift", color: "#c2410c" }, { label: "false or benign only", color: "#94a3b8" }, { label: "untriaged", color: "#f59e0b" }],
      hideDisabled: false, selectTechniquesAcrossTactics: true, selectSubtechniquesWithParent: false, sorting: 3, layout: { layout: "side", showID: true, showName: true } };
  }

  /* ---------- seeded variants ----------
     variant(scenario, seed) re-draws the values the scenario's "variants" block lists: every IPv4 address inside variants.ipPools
     moves to another address in the same range, and every id that starts with a variants.idPools prefix gets new digits.
     Answer keys, handover text and hunts follow because the whole scenario is rewritten. Values outside the pools (real-world
     anchors, internal ranges) stay. Seed 0, or a scenario without "variants", returns the scenario unchanged. */
  function rng(seed) { var x = (seed >>> 0) || 1; return function () { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x / 4294967296; }; }
  function escRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
  function intIp(n) { return [n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255].join("."); }
  function variantMap(scn, seed, pools) {
    var cfg = pools || scn.variants || {}, r = rng(seed), map = {}, used = {}, text = JSON.stringify(scn);
    var ips = (text.match(/(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/g) || []);
    var ids = [];
    (cfg.idPools || []).forEach(function (p) {
      var rx = new RegExp("\\b(?:" + p.prefixes.map(escRe).join("|") + ")\\d{" + p.digits + "}\\b", "g");
      (text.match(rx) || []).forEach(function (v) { ids.push([v, p.digits]); });
    });
    ips.concat(ids.map(function (x) { return x[0]; })).forEach(function (v) { used[v] = 1; });
    ips.forEach(function (ip) {
      if (map[ip]) return;
      var pool = (cfg.ipPools || []).filter(function (c) { return inCidr(ip, c); })[0]; if (!pool) return;
      var p = pool.split("/"), size = Math.pow(2, 32 - +p[1]), base = ipInt(p[0]), n, tries = 0;
      if (size < 8 || ipInt(ip) === base || ipInt(ip) === base + size - 1) return; // network and broadcast addresses stay
      do { n = intIp(base + 2 + Math.floor(r() * (size - 4))); } while (used[n] && ++tries < 1000);
      if (used[n]) return;
      used[n] = 1; map[ip] = n;
    });
    ids.forEach(function (x) {
      var v = x[0], d = x[1]; if (map[v]) return;
      var pre = v.slice(0, v.length - d), lo = Math.pow(10, d - 1), n, tries = 0;
      do { n = pre + String(lo + Math.floor(r() * (Math.pow(10, d) - lo))); } while (used[n] && ++tries < 1000);
      if (used[n]) return;
      used[n] = 1; map[v] = n;
    });
    return map;
  }
  function remapText(s, map) {
    var keys = Object.keys(map || {}).sort(function (a, b) { return b.length - a.length; });
    if (!keys.length) return s;
    var rx = new RegExp("(?<![\\w.])(" + keys.map(escRe).join("|") + ")(?![\\w]|\\.\\d)", "g");
    return String(s).replace(rx, function (m) { return map[m]; });
  }
  function variant(scn, seed) {
    seed = Math.floor(+seed || 0);
    if (!seed || !scn.variants) return scn;
    var body = Object.assign({}, scn); delete body.variants; // the pool definitions themselves are not rewritten
    var map = variantMap(body, seed, scn.variants), out = JSON.parse(remapText(JSON.stringify(body), map));
    out.variants = scn.variants; out.seed = seed; out.variantMap = map;
    return out;
  }

  function newState() {
    return { verdicts: {}, incidents: {}, actions: [], watch: [], tuning: [], huntsRun: {}, ackIn: null, enrich: {}, acks: {}, obs: {}, seed: 0 };
  }

  var api = { load: load, entitiesOf: entitiesOf, summarize: summarize, runDetections: runDetections, correlate: correlate, CORRELATORS: CORRELATORS, indexEntities: indexEntities, byId: byId,
    alertEntities: alertEntities, relatedAlerts: relatedAlerts, timeline: timeline, actionsFor: actionsFor, applyAction: applyAction, ACTIONS: ACTIONS,
    proposeTuning: proposeTuning, acknowledge: acknowledge, buildHandover: buildHandover, lintHandover: lintHandover, grade: grade, verdictMatches: verdictMatches, answerKeyState: answerKeyState,
    newState: newState, SEVS: SEVS, VERDICTS: VERDICTS, LEVEL_RANK: LEVEL_RANK, verdictExport: verdictExport, DISPOSITION: DISPOSITION, fmtBytes: fmtBytes, decodeSafe: decodeSafe,
    get: get, isIp: isIp, hhmmToMin: hhmmToMin, compileRules: compileRules, compileYaml: compileYaml, shiftStart: shiftStart, normTime: normTime,
    shiftMetrics: shiftMetrics, observables: observables, isExternal: isExternal, inCidr: inCidr, TLP: TLP, PAP: PAP, OBS_DEFAULTS: OBS_DEFAULTS,
    theHiveAlert: theHiveAlert, theHiveCase: theHiveCase, irisAlert: irisAlert, stixBundle: stixBundle, navigatorLayer: navigatorLayer,
    variant: variant, variantMap: variantMap, remapText: remapText };
  if (typeof module === "object" && module.exports) module.exports = api; else root.SOC = api;
})(typeof window !== "undefined" ? window : globalThis);
