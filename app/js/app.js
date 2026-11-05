/* SOC Shift UI. Scenario in scenarios/<id>/scenario.js, logic in js/engine.js, rule engine vendor/sigma.js.
   State stays in this browser's localStorage, one key per scenario. Exports are built and downloaded in the browser. */
(function () {
  "use strict";
  var SOC = window.SOC, S = window.Sigma;
  var CATALOG = window.SOC_SCENARIO_CATALOG || [];

  /* ---------- scenario loader: ?scenario=<id> picks a folder under scenarios/ ---------- */
  function pickId() {
    var want = null;
    try { want = new URLSearchParams(location.search).get("scenario"); } catch (e) {}
    var ok = CATALOG.some(function (c) { return c.id === want; });
    return ok ? want : (CATALOG[0] && CATALOG[0].id);
  }
  function fail(msg) { var m = document.getElementById("main"); if (m) m.innerHTML = '<div class="empty">' + msg + "</div>"; }
  var SID = pickId();
  if (!SID) { fail("No scenario is listed in scenarios/index.js."); return; }
  var tag = document.createElement("script");
  tag.src = "scenarios/" + encodeURIComponent(SID) + "/scenario.js";
  tag.onload = function () { var scn = (window.SOC_SCENARIOS || {})[SID]; if (!scn) { fail("scenarios/" + SID + "/scenario.js loaded but did not register a scenario with id " + SID + "."); return; } boot(scn); };
  tag.onerror = function () { fail("Could not load scenarios/" + SID + "/scenario.js."); };
  document.head.appendChild(tag);

  function boot(SCN) {
  var KEY = "soc-shift:" + SCN.id, state, ui = { tab: "in", sel: null, huntSel: (SCN.hunts && SCN.hunts[0] || {}).id || "H-custom", tuneOut: {}, showKey: false, raw: {} };
  var START = SOC.hhmmToMin(SCN.estate.shift.startUtc);
  function fresh(seed) { var s = SOC.newState(); s.sim = START + 5; s.huntYaml = {}; s.seed = seed || 0; return s; }
  function load() { try { state = JSON.parse(localStorage.getItem(KEY)); } catch (e) { state = null; } if (!state || !state.verdicts) state = fresh(0); state.acks = state.acks || {}; state.obs = state.obs || {}; state.seed = state.seed || 0; }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {} }
  load();
  // ?seed=N opens a seeded variant: the scenario's variant pools (attacker addresses, host numbers, customer ids) are re-drawn
  // and the answer key follows. Seed 0 is the original. A different seed starts a fresh shift.
  var qSeed = null; try { qSeed = new URLSearchParams(location.search).get("seed"); } catch (e) {}
  if (qSeed !== null && /^\d{1,9}$/.test(qSeed) && +qSeed !== state.seed && (SCN.variants || +qSeed === 0)) { state = fresh(+qSeed); save(); }
  if (!SCN.variants) state.seed = 0;
  var DATA = SOC.load(SOC.variant(SCN, state.seed)), SHIFT = DATA.estate.shift;
  var DAY = SHIFT.date;
  var IDX = SOC.indexEntities(DATA), EVMAP = SOC.byId(DATA);
  var ALL = SOC.runDetections(DATA);
  var ATT = {}, ATT_VER = "";
  // ATT&CK names come from the bundled snapshot. Browsers block fetch() on file://, so opened that way only the ids show.
  if (location.protocol !== "file:") fetch("vendor/attack.json").then(function (r) { return r.json(); }).then(function (d) { ATT_VER = d.version; d.techniques.forEach(function (t) { ATT[t[0]] = t[1]; }); render(); }).catch(function () {});

  renderStatic();

  /* ---------- helpers ---------- */
  function h(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function $(s, r) { return (r || document).querySelector(s); }
  function $$(s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); }
  function hhmm(m) { return String(Math.floor(m / 60)).padStart(2, "0") + ":" + String(m % 60).padStart(2, "0"); }
  function simIso() { return DAY + "T" + hhmm(state.sim) + ":00Z"; }
  function t5(iso) { return iso.slice(0, 10) === DAY ? iso.slice(11, 19) : iso.slice(5, 10) + " " + iso.slice(11, 16); }
  function visible() { var n = simIso(); return ALL.filter(function (a) { return a.at <= n; }); }
  function visEvents(ids) { var n = simIso(); return ids.map(function (id) { return EVMAP[id]; }).filter(function (e) { return e._t <= n; }); }
  function plural(n, w) { return n + " " + w + (n === 1 ? "" : "s"); }
  function sev(l) { return '<span class="sev ' + h(l) + '">' + h(l) + "</span>"; }
  function srcb(s) { return '<span class="srcb src-' + s + '">' + { edr: "EDR", sse: "SSE", waf: "WAF", idp: "SIEM·IdP", cloud: "SIEM·Cloud" }[s] + "</span>"; }
  function att(id) { return '<span class="sd-tag att" title="MITRE ATT&CK' + (ATT_VER ? " v" + h(ATT_VER) : "") + '">' + h(id) + (ATT[id] ? " " + h(ATT[id]) : "") + "</span>"; }
  function vtag(v) { return v ? '<span class="sd-tag v-' + v.verdict + '">' + { tp: "True positive", fp: "False positive", benign: "Benign TP", escalate: "Escalated" }[v.verdict] + "</span>" : '<span class="sd-tag">Untriaged</span>'; }
  function toast(msg) { var t = $("#toast"); t.textContent = msg; t.classList.add("on"); clearTimeout(t._h); t._h = setTimeout(function () { t.classList.remove("on"); }, 2600); }
  function incList() { return Object.keys(state.incidents).map(function (k) { return state.incidents[k]; }); }
  function nextIncId() { var n = 1; while (state.incidents["INC-" + String(n).padStart(3, "0")]) n++; return "INC-" + String(n).padStart(3, "0"); }
  var OWNERS = DATA.owners;
  var ENT_LABEL = { user: "user", host: "host", ip: "ip", domain: "domain", package: "npm", customer: "customer", session: "session", cloudkey: "aws key", file: "file" };
  function entChip(e) { return '<button class="ent" data-ent="' + h(e.type) + "|" + h(e.value) + '"><span class="k">' + h(ENT_LABEL[e.type] || e.type) + '</span><span class="v">' + h(e.value) + "</span></button>"; }

  /* ---------- chrome ---------- */
  function renderChrome() {
    $("#simNow").textContent = hhmm(state.sim);
    var vis = visible(), un = vis.filter(function (a) { return !state.verdicts[a.id]; }).length;
    var open = incList().filter(function (i) { return i.status !== "closed"; }).length;
    var pend = state.actions.filter(function (a) { return a.status === "pending"; }).length;
    var mins = SHIFT.endMin - state.sim;
    $("#counters").innerHTML =
      '<div class="counter' + (un ? " warn" : "") + '"><b>' + un + "</b><span>untriaged</span></div>" +
      '<div class="counter"><b>' + open + "</b><span>open incidents</span></div>" +
      '<div class="counter"><b>' + pend + "</b><span>pending actions</span></div>" +
      '<div class="counter' + (mins <= 30 ? " warn" : "") + '"><b>' + (mins > 0 ? hhmm(mins) : "00:00") + "</b><span>to handover</span></div>";
    $("#bQueue").textContent = un || "";
    $("#bInc").textContent = open || "";
    var lint = SOC.lintHandover(state, vis, hhmm(state.sim), DATA).filter(function (i) { return i.sev === "high"; }).length;
    $("#bOut").textContent = lint || "";
    $$("#tabs button").forEach(function (b) { b.classList.toggle("on", b.dataset.tab === ui.tab); });
  }

  function render() {
    renderChrome();
    var m = $("#main");
    ({ in: renderIn, queue: renderQueue, inc: renderInc, hunt: renderHunt, tune: renderTune, enrich: renderEnrich, out: renderOut, key: renderKey })[ui.tab](m);
  }

  /* ---------- static page parts filled from the scenario ---------- */
  function renderStatic() {
    document.title = DATA.title + " · SOC Shift";
    $("#scnTitle").textContent = DATA.title;
    $("#scnSub").textContent = (DATA.subtitle || "") + (DATA.seed ? (DATA.subtitle ? " · " : "") + "variant " + DATA.seed : "");
    $("#shiftName").textContent = SHIFT.name + " shift";
    $("#shiftHours").textContent = SHIFT.startUtc + " to " + SHIFT.endUtc + " UTC";
    $("#jumpEnd").textContent = "Jump to " + hhmm(SHIFT.endMin - 20);
    $("#tabOut").firstChild.textContent = "7 · Handover to " + SHIFT.to + " ";
    $("#scnNotes").textContent = (DATA.anchors && DATA.anchors.notes) || "";
    var pick = $("#scnPick");
    if (pick && CATALOG.length > 1) {
      pick.innerHTML = CATALOG.map(function (c) { return '<option value="' + h(c.id) + '"' + (c.id === DATA.id ? " selected" : "") + ">" + h(c.title) + "</option>"; }).join("");
      pick.parentNode.hidden = false;
      pick.onchange = function () { location.search = "?scenario=" + encodeURIComponent(pick.value); };
    }
  }

  /* ---------- 1. handover in ---------- */
  function renderIn(m) {
    var H = DATA.handoverIn;
    if (!H) { m.innerHTML = '<h2>Handover in</h2><p class="lead">This scenario starts with no handover from a previous shift.</p><div class="row"><button class="btn" data-go="queue">Go to the queue</button><button class="btn danger" id="reset">Reset the shift</button></div>' + variantCard(); bindCommon(); bindReset(); bindVariant(); return; }
    var items = H.items.map(function (i) {
      return '<div class="sd-card"><div class="inc-head"><div class="row">' + sev(i.severity) + " <b>" + h(i.case) + "</b> " + h(i.title) + '</div><span class="sd-tag">' + h(i.status) + "</span></div>" +
        '<dl class="kv" style="margin-top:8px"><dt>Done</dt><dd>' + h(i.done) + "</dd><dt>Next</dt><dd>" + h(i.next) + "</dd><dt>Owner</dt><dd>" + h(i.owner) + "</dd><dt>Due</dt><dd>" + h(i.due) + "</dd>" + (i.pending ? "<dt>Waiting on</dt><dd>" + h(i.pending) + "</dd>" : "") + "</dl></div>";
    }).join("");
    m.innerHTML = '<h2>Handover in from ' + h(H.from) + "</h2>" +
      '<p class="lead">Start of the ' + h(SHIFT.name) + " shift (" + h(SHIFT.startUtc) + " UTC). Read what " + h(H.from) + ' left open and acknowledge it: the cases and watch list become yours. Then move the shift clock and work the queue.</p>' +
      '<div class="sd-card"><dl class="kv"><dt>From</dt><dd>' + h(H.analyst) + ", sent " + h(t5(H.at)) + " UTC</dd><dt>Summary</dt><dd>" + h(H.summary) + "</dd><dt>" + h(H.from) + " metrics</dt><dd>" + H.metrics.alerts + " alerts, " + H.metrics.tp + " TP, " + H.metrics.fp + " FP, " + H.metrics.benign + " benign</dd></dl>" +
      '<div class="row" style="margin-top:10px">' + (state.ackIn ? '<span class="sd-tag v-benign">Acknowledged at ' + h(state.ackIn.slice(11, 16)) + " UTC</span>" : '<button class="btn pri" id="ack">Acknowledge and take ownership</button>') +
      '<button class="btn" data-go="queue">Go to the queue</button><button class="btn danger" id="reset">Reset the shift</button></div></div>' + items + variantCard() +
      '<div class="sd-card"><h3 style="margin-top:0">How this desk works</h3><ol class="facts"><li>Advance the shift clock. Alerts arrive at the time their condition was met.</li><li>Open an alert: read the evidence, click any entity to pivot across EDR, SSE, WAF and SIEM, run live lookups.</li><li>Record a verdict with a reason the next shift can check, and link true positives to an incident.</li><li>Take response actions from the entity panel. Actions owned by other teams stay pending and carry into the handover.</li><li>Hunt for what no alert caught, propose tuning for noisy rules (each proposal is re-run against confirmed true positives), then hand over to ' + h(SHIFT.to) + '.</li><li>Check your shift against the answer key.</li></ol></div>';
    var ack = $("#ack");
    if (ack) ack.onclick = function () {
      SOC.acknowledge(state, DATA, simIso());
      var cases = H.items.filter(function (i) { return i.kind === "case"; }).map(function (i) { return i.case; });
      save(); toast("Handover acknowledged." + (cases.length ? " " + cases.join(", ") + (cases.length > 1 ? " are" : " is") + " now yours." : "")); render();
    };
    bindReset(); bindVariant(); bindCommon();
  }
  function variantCard() {
    if (!DATA.variants) return "";
    return '<div class="sd-card"><h3 style="margin-top:0">Shift variant</h3><p class="dim">' + (DATA.seed ? "Variant " + DATA.seed + ": attacker addresses, host numbers and customer ids differ from the original shift, so the answer key does too. The attack chains are the same." : "The original shift. A variant re-draws attacker addresses, host numbers and customer ids, so the answer key changes and has to be worked out again.") +
      '</p><div class="row" style="margin-top:8px"><button class="btn" id="variant">Start a new variant</button>' + (DATA.seed ? '<a class="btn" href="' + h(seedHref(0)) + '">Back to the original</a>' : "") + "</div></div>";
  }
  function seedHref(n) { var q; try { q = new URLSearchParams(location.search); } catch (e) { return "?seed=" + n; } q.set("seed", String(n)); return "?" + q.toString(); }
  function bindVariant() { var b = $("#variant"); if (b) b.onclick = function () { if (confirm("Start a new variant? This clears the current shift.")) location.search = seedHref(1 + Math.floor(Math.random() * 999999)); }; }
  function bindReset() { $("#reset").onclick = function () { if (confirm("Clear every verdict, incident and action and start the shift again?")) { var keep = state.seed; try { localStorage.removeItem(KEY); } catch (e) {} state = fresh(keep); save(); ui.sel = null; ui.tuneOut = {}; render(); } }; }

  /* ---------- 2. queue ---------- */
  function renderQueue(m) {
    var vis = visible();
    if (!vis.length) { m.innerHTML = '<div class="empty">No alerts yet at ' + hhmm(state.sim) + " UTC. Advance the shift clock.</div>"; return; }
    if (!ui.sel || !vis.some(function (a) { return a.id === ui.sel; })) ui.sel = (vis.filter(function (a) { return !state.verdicts[a.id]; })[0] || vis[0]).id;
    if (!state.acks[ui.sel]) { state.acks[ui.sel] = simIso(); save(); } // first open on the shift clock acknowledges the alert (MTTA)
    var list = vis.slice().reverse().map(function (a) {
      var v = state.verdicts[a.id];
      return '<button class="qitem' + (a.id === ui.sel ? " on" : "") + (v ? "" : " new") + '" data-sel="' + h(a.id) + '"><span class="t">' + h(a.title) + '</span><span class="m">' + sev(v && v.sev ? v.sev : a.level) + '<span class="sd-tag">' + h(a.platform) + "</span><span class=mono>" + h(a.at.slice(11, 16)) + "</span>" + h(a.key) + " " + vtag(v) + "</span></button>";
    }).join("");
    m.innerHTML = '<div class="grid2"><div><h2>Queue</h2><p class="lead">' + vis.length + " alerts so far this shift, newest first.</p><div class=qlist>" + list + "</div></div><div>" + alertDetail(ALL.filter(function (a) { return a.id === ui.sel; })[0]) + "</div></div>";
    bindAlert();
  }

  function alertDetail(a) {
    var v = state.verdicts[a.id] || {}, evs = visEvents(a.events);
    var ents = SOC.alertEntities({ events: evs.map(function (e) { return e._id; }) }, EVMAP);
    var rel = SOC.relatedAlerts(a, visible(), EVMAP, DATA.estate.users, DATA.noisyEntities);
    var rule = DATA.rules.filter(function (r) { return r.id === a.ruleId; })[0];
    var corr = DATA.correlations.filter(function (r) { return r.id === a.ruleId; })[0];
    var rows = evs.map(function (e) {
      return "<tr><td class=mono>" + h(t5(e._t)) + "</td><td>" + srcb(e._src) + '</td><td class=mono>' + h(SOC.summarize(e)) +
        (ui.raw[e._id] ? '<div class="raw">' + h(JSON.stringify(stripMeta(e), null, 2)) + "</div>" : "") + '</td><td><button class="btn sm" data-raw="' + e._id + '">' + (ui.raw[e._id] ? "hide" : "raw") + "</button></td></tr>";
    }).join("");
    var incs = incList().filter(function (i) { return i.status !== "closed"; });
    return '<div class="sd-card"><div class="inc-head"><div class="row">' + sev(a.level) + '<span class="sd-tag">' + h(a.platform) + '</span><span class="sd-tag">' + (a.kind === "correlation" ? "Correlation" : "Sigma") + " · " + h(a.ruleId) + "</span></div>" + vtag(state.verdicts[a.id]) + "</div>" +
      '<h2 style="margin-top:8px">' + h(a.title) + "</h2><p class=dim>Raised " + h(a.at.slice(11, 19)) + " UTC on <b>" + h(a.key) + "</b>. " + h(a.description) + "</p>" +
      '<div class="row" style="margin-top:6px">' + a.attack.map(att).join("") + "</div>" +
      (a.facts ? '<ul class="facts">' + a.facts.map(function (f) { return "<li>" + h(f) + "</li>"; }).join("") + "</ul>" : "") +
      "<h3>Evidence (" + plural(evs.length, "event") + ")</h3><div class=tablewrap><table class=ev><colgroup><col style=width:92px><col style=width:84px><col><col style=width:56px></colgroup><thead><tr><th>UTC</th><th>Source</th><th>Event</th><th></th></tr></thead><tbody>" + rows + "</tbody></table></div>" +
      "<h3>Entities: click to pivot, enrich or respond</h3><div class=row>" + ents.map(entChip).join("") + "</div>" +
      (rel.length ? "<h3>Related alerts</h3><div class=qlist>" + rel.map(function (r) { return '<button class="qitem" data-sel="' + h(r.alert.id) + '"><span class=t>' + h(r.alert.title) + '</span><span class=m>' + sev(r.alert.level) + h(r.alert.key) + " · shares " + r.shared.map(function (s) { return h(s.type + " " + s.value); }).join(", ") + " " + vtag(state.verdicts[r.alert.id]) + "</span></button>"; }).join("") + "</div>" : "") +
      "<details style='margin-top:10px'><summary class=dim>Detection logic and known false positives</summary>" + (rule ? '<pre class="raw">' + h(rule.yaml) + "</pre>" : '<p class="raw">' + h(corr.description) + "</p>") + "<p class=dim>Known false positives: " + h(a.falsepositives.join("; ")) + "</p></details></div>" +
      '<div class="sd-card" id="vform"><h3 style="margin-top:0">Verdict</h3><div class="verdict">' +
      ["tp", "benign", "fp", "escalate"].map(function (k) { return '<button data-v="' + k + '" class="' + k + (v.verdict === k ? " on" : "") + '">' + { tp: "True positive", benign: "Benign TP", fp: "False positive", escalate: "Escalate" }[k] + "</button>"; }).join("") + "</div>" +
      '<div class="two"><div><label class=f>Severity</label><select id=vsev>' + SOC.SEVS.map(function (s) { return "<option" + ((v.sev || a.level) === s ? " selected" : "") + ">" + s + "</option>"; }).join("") + "</select></div>" +
      "<div><label class=f>Incident</label><select id=vinc><option value=''>None</option>" + incs.map(function (i) { return '<option value="' + h(i.id) + '"' + (v.incident === i.id ? " selected" : "") + ">" + h(i.id + " " + i.title) + "</option>"; }).join("") + '<option value="__new">New incident…</option></select></div></div>' +
      '<div id=newinc style="display:none"><label class=f>New incident title</label><input type=text id=vnewt value="' + h(a.title + " on " + a.key) + '"></div>' +
      "<label class=f>Reason (what the next shift needs to check this call)</label><textarea id=vreason placeholder='What you checked, what it showed, why this verdict'>" + h(v.reason || "") + "</textarea>" +
      '<div class="row" style="margin-top:8px"><button class="btn pri" id=vsave>Save verdict</button>' + (v.at ? '<span class=dim>Saved at ' + h(v.at.slice(11, 16)) + " UTC</span>" : "") + "</div></div>";
  }
  function stripMeta(e) { var o = {}; Object.keys(e).forEach(function (k) { if (k[0] !== "_") o[k] = e[k]; }); return o; }

  function bindAlert() {
    var picked = (state.verdicts[ui.sel] || {}).verdict || null;
    $$("[data-v]").forEach(function (b) { b.onclick = function () { picked = b.dataset.v; $$("[data-v]").forEach(function (x) { x.classList.toggle("on", x === b); }); if ((picked === "tp" || picked === "escalate") && !$("#vinc").value) { $("#vinc").value = "__new"; $("#newinc").style.display = "block"; } }; });
    var vinc = $("#vinc"); if (vinc) vinc.onchange = function () { $("#newinc").style.display = vinc.value === "__new" ? "block" : "none"; };
    var vs = $("#vsave");
    if (vs) vs.onclick = function () {
      if (!picked) { toast("Pick a verdict first."); return; }
      var reason = $("#vreason").value.trim(), incId = $("#vinc").value, a = ALL.filter(function (x) { return x.id === ui.sel; })[0], sv = $("#vsev").value;
      if (incId === "__new") {
        incId = nextIncId();
        state.incidents[incId] = { id: incId, title: $("#vnewt").value.trim() || a.title, severity: sv, status: "open", summary: "", next: "", owner: "", due: "", alerts: [], extra: [], irNotified: false };
      }
      var prev = state.verdicts[a.id];
      if (prev && prev.incident && prev.incident !== incId && state.incidents[prev.incident]) state.incidents[prev.incident].alerts = state.incidents[prev.incident].alerts.filter(function (x) { return x !== a.id; });
      if (incId) { var inc = state.incidents[incId]; if (inc.alerts.indexOf(a.id) < 0) inc.alerts.push(a.id); if (SOC.SEVS.indexOf(sv) > SOC.SEVS.indexOf(inc.severity)) inc.severity = sv; }
      state.verdicts[a.id] = { verdict: picked, sev: sv, reason: reason, incident: incId || null, at: simIso() };
      save(); toast("Verdict saved" + (incId ? " and linked to " + incId : "") + "."); render();
    };
    bindCommon();
  }

  function bindCommon() {
    $$("[data-sel]").forEach(function (b) { b.onclick = function () { ui.sel = b.dataset.sel; ui.tab = "queue"; render(); toDesk(); }; });
    $$("[data-raw]").forEach(function (b) { b.onclick = function () { ui.raw[b.dataset.raw] = !ui.raw[b.dataset.raw]; render(); }; });
    $$("[data-ent]").forEach(function (b) { b.onclick = function () { var p = b.dataset.ent.split("|"); openEntity({ type: p[0], value: p.slice(1).join("|") }); }; });
    $$("[data-go]").forEach(function (b) { b.onclick = function () { ui.tab = b.dataset.go; render(); }; });
  }

  /* ---------- entity drawer: pivot, enrich, respond ---------- */
  function openEntity(ent) {
    var d = $("#drawer"), n = simIso();
    var tl = SOC.timeline(ent, DATA, IDX, EVMAP).filter(function (e) { return e._t <= n; });
    var incs = incList().filter(function (i) { return i.status !== "closed"; });
    var acts = SOC.actionsFor(ent, DATA), done = state.actions.filter(function (a) { return a.entity === ent.type + ":" + ent.value; });
    var ctx = "";
    if (ent.type === "user" && DATA.estate.users[ent.value]) { var u = DATA.estate.users[ent.value]; ctx = '<dl class=kv><dt>Name</dt><dd>' + h(u.name) + "</dd><dt>Team</dt><dd>" + h(u.dept) + (u.privileged ? " (privileged)" : "") + "</dd><dt>Device</dt><dd>" + h(u.host) + " · " + h(u.os) + "</dd><dt>Usual network</dt><dd>" + h(u.usualAsn) + ", " + h(u.region) + "</dd></dl>"; }
    if (ent.type === "host" && DATA.estate.hosts[ent.value]) { var o = DATA.estate.hosts[ent.value]; ctx = '<dl class=kv><dt>Owner</dt><dd>' + h(o.owner) + "</dd><dt>Role</dt><dd>" + h(o.role) + "</dd><dt>OS</dt><dd>" + h(o.os) + "</dd><dt>EDR</dt><dd>" + (state.actions.some(function (a) { return a.entity === "host:" + ent.value && a.action === "isolate"; }) ? "<b class=bad>isolated</b>" : h(o.edr)) + "</dd></dl>"; }
    var canEnrich = ["ip", "domain", "package"].indexOf(ent.type) >= 0;
    $("#drawerIn").innerHTML = '<div class="inc-head"><div>' + entChip(ent) + '</div><button class="btn" id=dclose>Close</button></div>' + ctx +
      (canEnrich ? '<h3>Live enrichment</h3><div id=denrich>' + enrichHtml(ent) + '</div><button class="btn sm" id=drun>Run live lookups</button>' : "") +
      "<h3>Response actions</h3>" + (acts.length ? '<label class=f>Log against incident</label><select id=dcase>' + (incs.length ? incs.map(function (i) { var cur = (state.verdicts[ui.sel] || {}).incident; return '<option value="' + h(i.id) + '"' + (cur === i.id ? " selected" : "") + ">" + h(i.id + " " + i.title) + "</option>"; }).join("") : "<option value=''>No open incident: create one from a verdict first</option>") + '</select><div class="row" style="margin-top:6px">' +
        acts.map(function (a) { var did = done.some(function (x) { return x.action === a.id; }); return '<button class="btn' + (a.self ? "" : "") + '" data-act="' + h(a.id) + '"' + (did ? " disabled" : "") + ">" + h(a.label) + (a.self ? "" : " (needs " + h(a.owner) + ")") + (did ? " ✓" : "") + "</button>"; }).join("") + "</div>" : "<p class=dim>No direct action for this entity type.</p>") +
      (done.length ? '<ul class=facts>' + done.map(function (a) { return "<li>" + h(a.at.slice(11, 16)) + " UTC " + h(a.label) + " · " + h(a.status) + " (" + h(a.owner) + ")</li>"; }).join("") + "</ul>" : "") +
      '<div class=row style="margin-top:6px"><button class="btn sm" id=dwatch>Add to watch list</button></div>' +
      "<h3>Timeline across all sources (" + plural(tl.length, "event") + " up to " + hhmm(state.sim) + " UTC)</h3><div class=tablewrap><table class=ev><colgroup><col style=width:92px><col style=width:84px><col></colgroup><tbody>" +
      tl.map(function (e) { var more = (e._ents || []).filter(function (x) { return !(x.type === ent.type && x.value === ent.value); }); return "<tr><td class=mono>" + h(t5(e._t)) + "</td><td>" + srcb(e._src) + "</td><td class=mono>" + h(SOC.summarize(e)) + (more.length ? '<div class=row style="margin-top:3px">' + more.map(entChip).join("") + "</div>" : "") + "</td></tr>"; }).join("") + "</tbody></table></div>";
    d.classList.add("open"); d.setAttribute("aria-hidden", "false");
    $("#dclose").onclick = closeDrawer;
    $$("#drawer [data-ent]").forEach(function (b) { b.onclick = function () { var p = b.dataset.ent.split("|"); openEntity({ type: p[0], value: p.slice(1).join("|") }); $("#drawer").scrollTop = 0; }; });
    var dr = $("#drun"); if (dr) dr.onclick = function () { dr.disabled = true; dr.textContent = "Looking up…"; enrich(ent).then(function () { openEntity(ent); }); };
    $$("[data-act]").forEach(function (b) { b.onclick = function () {
      var caseId = $("#dcase").value; if (!caseId) { toast("Create an incident first (record a true-positive verdict)."); return; }
      var a = acts.filter(function (x) { return x.id === b.dataset.act; })[0], rec = SOC.applyAction(state, caseId, ent, a, simIso(), SHIFT.team);
      save(); toast(rec.status === "done" ? a.label + ": done on " + a.platform + "." : a.label + ": request sent to " + a.owner + ", pending."); openEntity(ent); renderChrome(); if (ui.tab === "inc") render();
    }; });
    $("#dwatch").onclick = function () { var w = ent.value + " (" + ent.type + "), added " + hhmm(state.sim) + " UTC"; if (!state.watch.some(function (x) { return x.indexOf(ent.value + " (") === 0; })) { state.watch.push(w); save(); toast("Added to the watch list."); } };
  }
  // keep the tabs in view without jumping back above the desk
  function toDesk() { var d = $("#desk"); if (!d) return; var y = d.getBoundingClientRect().top + window.scrollY; if (window.scrollY > y) window.scrollTo(0, y); }
  function closeDrawer() { var d = $("#drawer"); d.classList.remove("open"); d.setAttribute("aria-hidden", "true"); }
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeDrawer(); });

  /* ---------- live enrichment ---------- */
  function detectType(v) {
    v = v.trim();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(v)) return "ip";
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return "cve";
    if (/^(@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(v) && v.indexOf(".") < 0) return "package";
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return "domain";
    return null;
  }
  // Lookups go through vendor/intel.js (timeouts, dedup, cache, RDAP bootstrap
  // routing). Tor status comes from the Tor Project's Onionoo API. The KEV
  // catalogue is CISA's own kev-data repository on GitHub, fetched once per page
  // load. Every lookup is optional: offline, it fails on its own card and the
  // rest of the shift keeps working.
  var N = window.PwnsyIntel;
  function rec(src, fn) {
    var url = "";
    return fn(function (r) { url = r.url || url; return r; }).then(function (r) { return Object.assign({ src: src, url: url, at: new Date().toISOString() }, r); })
      .catch(function (e) { return { src: src, url: (e && e.url) || url, at: new Date().toISOString(), err: String(e.message || e) }; });
  }
  function enrich(ent) {
    var v = ent.value, t = ent.type, jobs = [];
    if (t === "ip") {
      jobs.push(rec("RDAP (network owner)", function (seen) { return N.rdapIp(v).then(seen).then(function (r) {
        var j = r.raw, orgs = [];
        (j.entities || []).forEach(function (e) { var fn = ((e.vcardArray || [])[1] || []).filter(function (x) { return x[0] === "fn"; })[0]; if (fn) orgs.push(fn[3] + " (" + (e.roles || []).join(",") + ")"); });
        var reserved = /RESERVED|IANA|documentation/i.test(JSON.stringify(j.remarks || "") + (j.name || ""));
        return { lines: [["Network", (j.name || "?") + " · " + (j.handle || "")], ["Range", (j.startAddress || "") + " to " + (j.endAddress || "")], ["Country", j.country || "n/a"], ["Registrant", orgs.slice(0, 3).join("; ") || "n/a"]], verdict: reserved ? "Reserved or documentation range (stands in for attacker infrastructure here)" : /vultr|choopa|constant|digitalocean|ovh|hetzner|linode|amazon|google|microsoft/i.test(JSON.stringify(orgs) + j.name) ? "Hosting provider: unusual for a staff sign-in" : null };
      }, function (e) { seen({ url: e.url }); if (e.code === "notfound") return { lines: [["RDAP", "no record (404)"]] }; throw e; }); }));
      jobs.push(rec("Tor relays (Tor Project Onionoo)", function (seen) { return N.torStatus(v).then(seen).then(function (r) { var j = r.data; return { lines: [["Tor relay", j.relay ? "yes (" + j.relays + ")" : "no"], ["Tor exit", j.exit ? "YES" : "no"]].concat(j.nicknames.length ? [["Nicknames", j.nicknames.join(", ")]] : []).concat(j.published ? [["Relay list", j.published + " UTC"]] : []), verdict: j.exit ? "Current Tor exit" : j.relay ? "Tor relay (not an exit)" : null }; }); }));
    }
    if (t === "domain") {
      ["A", "NS"].forEach(function (q) { jobs.push(rec("DNS " + q + " (Cloudflare DoH)", function (seen) { return N.doh(v, q).then(seen).then(function (r) { var a = (r.raw.Answer || []).map(function (x) { return x.data; }); return { lines: [[q, a.join(", ") || (r.data.nx ? "NXDOMAIN" : "no answer")]], verdict: r.data.nx ? "Does not resolve" : null }; }); })); });
      jobs.push(rec("RDAP (registration)", function (seen) { return N.rdapDomain(v).then(seen).then(function (r) { var ev = (r.raw.events || []).filter(function (e) { return e.eventAction === "registration"; })[0]; return { lines: [["Registered", ev ? ev.eventDate.slice(0, 10) : "n/a"], ["Status", (r.raw.status || []).join(", ")]], verdict: ev && Date.now() - Date.parse(ev.eventDate) < 30 * 864e5 ? "Registered in the last 30 days" : null }; }, function (e) { seen({ url: e.url }); if (e.code === "notfound") return { lines: [["RDAP", "no record (404)"]] }; throw e; }); }));
    }
    if (t === "package") {
      jobs.push(rec("OSV (malicious packages + advisories)", function (seen) { return N.osvPackage("npm", v).then(seen).then(function (r) { var vs = r.raw.vulns || []; return { lines: vs.length ? vs.map(function (x) { return [x.id + " (" + (x.published || "").slice(0, 10) + ")", (x.summary || "") + ". " + (x.details || "").split("\n")[0].slice(0, 260)]; }) : [["Result", "No OSV record for npm/" + v]], verdict: r.data.hasMalicious ? "Known malicious package: treat the host as fully compromised and rotate every secret on it" : null }; }); }));
    }
    if (t === "cve") {
      jobs.push(rec("CISA KEV (cisagov/kev-data)", function (seen) { return N.kev(v).then(seen).then(function (r) { var e = r.data.entry; return { lines: e ? [["In KEV", "yes, added " + e.dateAdded], ["Product", e.vendorProject + " " + e.product], ["Ransomware use", e.knownRansomwareCampaignUse], ["Action due", e.dueDate]] : [["In KEV", "no (catalog " + r.data.catalogVersion + ", " + r.data.count + " entries)"]], verdict: e ? "Exploited in the wild (CISA KEV)" : null }; }); }));
    }
    if (!N) return Promise.resolve(fallback("vendor/intel.js did not load"));
    return Promise.all(jobs).then(function (res) { state.enrich[t + ":" + v] = res; save(); return res; });
  }
  function fallback(why) { return [{ src: "Live lookups", url: "", at: new Date().toISOString(), err: why }]; }
  function offlineHint(r) { return r.length && r.every(function (x) { return x.err; }) ? '<p class=dim>Every lookup failed. Live lookups need a network connection; the rest of the shift works offline.</p>' : "";
  }
  function enrichHtml(ent) {
    var r = state.enrich[ent.type + ":" + ent.value];
    if (!r) return "<p class=dim>Not looked up yet. Lookups are live calls from your browser: OSV, RDAP, Cloudflare DoH, Tor Project Onionoo and CISA's kev-data repository. Only the indicator is sent.</p>";
    return offlineHint(r) + r.map(function (x) {
      return '<div class=live><div class=h><span>' + h(x.src) + "</span>" + (x.err ? '<span class=bad>failed: ' + h(x.err) + "</span>" : x.verdict ? '<span class=bad>' + h(x.verdict) + "</span>" : '<span class=ok>no flag</span>') + "</div>" +
        (x.lines ? '<dl class=kv style="margin-top:4px">' + x.lines.map(function (l) { return "<dt>" + h(l[0]) + "</dt><dd>" + h(l[1]) + "</dd>"; }).join("") + "</dl>" : "") +
        '<div class=src>' + h(x.url || "no request made") + " · fetched " + h(x.at.slice(0, 19).replace("T", " ")) + " UTC (real time)</div></div>";
    }).join("");
  }

  /* ---------- 3. incidents ---------- */
  function renderInc(m) {
    var incs = incList();
    if (!incs.length) { m.innerHTML = '<div class="empty">No incidents yet. ' + (DATA.handoverIn ? "Acknowledge the " + h(DATA.handoverIn.from) + " handover, or record" : "Record") +  ' a true-positive verdict and link it to a new incident.</div>'; return; }
    m.innerHTML = "<h2>Incidents</h2><p class=lead>Every open incident needs a one-line summary, a next action, an owner and a due time before " + h(SHIFT.endUtc) + " UTC, or the handover check flags it.</p>" + incs.map(function (i) {
      var evIds = [];
      i.alerts.forEach(function (aid) { var a = ALL.filter(function (x) { return x.id === aid; })[0]; if (a) evIds = evIds.concat(a.events); });
      evIds = evIds.concat(i.extra || []);
      var seen = {}, evs = visEvents(evIds.filter(function (x) { if (seen[x]) return false; seen[x] = 1; return true; })).sort(function (a, b) { return a._t < b._t ? -1 : 1; });
      var ents = SOC.alertEntities({ events: evs.map(function (e) { return e._id; }) }, EVMAP);
      var acts = state.actions.filter(function (a) { return a.caseId === i.id; });
      var f = function (k, label, ph) { return "<label class=f>" + label + '</label><input type=text data-inc="' + h(i.id) + '" data-k="' + k + '" value="' + h(i[k] || "") + '" placeholder="' + h(ph) + '">'; };
      return '<div class="sd-card"><div class="inc-head"><div class="row">' + sev(i.severity) + " <b>" + h(i.id) + "</b> " + h(i.title) + (i.carried ? ' <span class="sd-tag">carried in from ' + h(SHIFT.from) + "</span>" : "") + "</div><div class=row>" +
        '<select data-inc="' + h(i.id) + '" data-k="status" style="width:auto">' + ["open", "contained", "monitoring", "closed"].map(function (s) { return "<option" + (i.status === s ? " selected" : "") + ">" + s + "</option>"; }).join("") + "</select>" +
        '<select data-inc="' + h(i.id) + '" data-k="severity" style="width:auto">' + SOC.SEVS.map(function (s) { return "<option" + (i.severity === s ? " selected" : "") + ">" + s + "</option>"; }).join("") + "</select></div></div>" +
        "<label class=f>What happened (one line)</label><textarea data-inc=\"" + h(i.id) + "\" data-k=summary placeholder='Who, what, how far it got'>" + h(i.summary || "") + "</textarea>" +
        f("next", "Next action", "The very next thing the next shift does") +
        '<div class=two><div><label class=f>Owner</label><select data-inc="' + h(i.id) + '" data-k="owner"><option value="">Unassigned</option>' + OWNERS.map(function (o) { return "<option" + (i.owner === o ? " selected" : "") + ">" + o + "</option>"; }).join("") + "</select></div><div>" + f("due", "Due (UTC)", "e.g. 10:00 UTC") + "</div></div>" +
        '<label class=f style="display:flex;gap:6px;align-items:center"><input type=checkbox data-inc="' + h(i.id) + '" data-k="irNotified"' + (i.irNotified ? " checked" : "") + "> IR lead notified</label>" +
        "<h3>Alerts</h3><div class=row>" + (i.alerts.length ? i.alerts.map(function (aid) { return '<button class="sd-tag" data-sel="' + h(aid) + '">' + h(aid) + "</button>"; }).join("") : "<span class=dim>none linked</span>") + "</div>" +
        "<h3>Entities</h3><div class=row>" + ents.map(entChip).join("") + "</div>" + obsTable(i) +
        "<h3>Response log</h3>" + (acts.length ? '<div class=tablewrap><table class=ev><colgroup><col style=width:70px><col><col style=width:120px><col style=width:170px></colgroup><thead><tr><th>UTC</th><th>Action</th><th>Status</th><th>Owner</th></tr></thead><tbody>' + acts.map(function (a, ix) { return "<tr><td class=mono>" + h(a.at.slice(11, 16)) + "</td><td>" + h(a.label) + " · <span class=mono>" + h(a.entity) + "</span></td><td>" + (a.status === "pending" ? '<button class="btn sm" data-done="' + state.actions.indexOf(a) + '">pending: mark done</button>' : '<span class=ok>done</span>') + "</td><td>" + h(a.owner) + "</td></tr>"; }).join("") + "</tbody></table></div>" : "<p class=dim>No actions yet. Open an entity to act.</p>") +
        "<h3>Timeline (" + plural(evs.length, "event") + ")</h3><div class=tablewrap><table class=ev><colgroup><col style=width:92px><col style=width:84px><col></colgroup><tbody>" + evs.map(function (e) { return "<tr><td class=mono>" + h(t5(e._t)) + "</td><td>" + srcb(e._src) + "</td><td class=mono>" + h(SOC.summarize(e)) + "</td></tr>"; }).join("") + "</tbody></table></div></div>";
    }).join("");
    $$("[data-inc]").forEach(function (el) {
      el.onchange = function () { var i = state.incidents[el.dataset.inc]; i[el.dataset.k] = el.type === "checkbox" ? el.checked : el.value; save(); renderChrome(); if (el.tagName === "SELECT") render(); };
    });
    $$("[data-obs]").forEach(function (el) { el.onchange = function () { var k = el.dataset.obs, o = state.obs[k] || (state.obs[k] = {}); o[el.dataset.f] = el.type === "checkbox" ? el.checked : el.value; save(); }; });
    $$("[data-xp]").forEach(function (b) { b.onclick = function () { exportCase(b.dataset.xp, b.dataset.inc); }; });
    $$("[data-done]").forEach(function (b) { b.onclick = function () { var a = state.actions[+b.dataset.done]; a.status = "done"; a.doneAt = simIso(); save(); toast(a.label + " confirmed by " + a.owner + "."); render(); }; });
    bindCommon();
  }

  /* ---------- observables and case exports ---------- */
  var TLPS = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"], PAPS = ["CLEAR", "GREEN", "AMBER", "RED"];
  function arrived() { return visible(); }
  function obsTable(i) {
    var obs = SOC.observables(state, i, arrived(), DATA), cfg = DATA.observables || {}, ex = cfg.external || SOC.OBS_DEFAULTS.external, inn = cfg.internal || SOC.OBS_DEFAULTS.internal;
    var buttons = '<div class="row" style="margin-top:8px"><button class="btn sm" data-xp="hive" data-inc="' + h(i.id) + '">TheHive case JSON</button><button class="btn sm" data-xp="iris" data-inc="' + h(i.id) + '">DFIR-IRIS alerts JSON</button><button class="btn sm" data-xp="stix" data-inc="' + h(i.id) + '">STIX 2.1 bundle</button></div>';
    if (!obs.length) return "<h3>Observables</h3><p class=dim>None yet. Link an alert or add hunt hits to this incident.</p>" + buttons;
    var sel = function (k, f, list, v) { return '<select data-obs="' + h(k) + '" data-f="' + f + '" aria-label="' + f.toUpperCase() + " for " + h(k) + '">' + list.map(function (x) { return "<option" + (x === v ? " selected" : "") + ">" + x + "</option>"; }).join("") + "</select>"; };
    return "<h3>Observables (" + obs.length + ")</h3><p class=dim>The IOC flag, TLP and PAP go out with every export. Defaults: attacker infrastructure is an IOC at TLP:" + h(ex.tlp) + ", PAP:" + h(ex.pap) + "; internal people, hosts, sessions and keys stay TLP:" + h(inn.tlp) + ", PAP:" + h(inn.pap) + ".</p>" +
      '<div class=tablewrap><table class="ev obs"><colgroup><col style="width:34%"><col style="width:10%"><col style="width:21%"><col style="width:16%"><col style="width:19%"></colgroup><thead><tr><th>Observable</th><th>IOC</th><th>TLP</th><th>PAP</th><th>Seen</th></tr></thead><tbody>' +
      obs.map(function (o) { var k = o.type + ":" + o.value; return '<tr><td><span class="sd-tag">' + h(ENT_LABEL[o.type] || o.type) + '</span> <span class="mono">' + h(o.value) + '</span></td><td><input type=checkbox data-obs="' + h(k) + '" data-f="ioc"' + (o.ioc ? " checked" : "") + ' aria-label="IOC: ' + h(k) + '"></td><td>' + sel(k, "tlp", TLPS, o.tlp) + "</td><td>" + sel(k, "pap", PAPS, o.pap) + "</td><td>" + plural(o.count, "event") + ", first <span class=mono>" + h(t5(o.first)) + "</span></td></tr>"; }).join("") + "</tbody></table></div>" + buttons;
  }
  function json(obj, name) { download(JSON.stringify(obj, null, 2) + "\n", name, "application/json"); }
  function tag() { return DATA.id + (DATA.seed ? "-v" + DATA.seed : ""); }
  function exportCase(kind, id) {
    var al = arrived(), inc = state.incidents[id];
    if (kind === "hive") json(SOC.theHiveCase(state, inc, al, DATA), "thehive-" + tag() + "-" + id + ".json");
    if (kind === "iris") { var obs = SOC.observables(state, inc, al, DATA); json(al.filter(function (a) { return inc.alerts.indexOf(a.id) >= 0; }).map(function (a) { return SOC.irisAlert(state, a, DATA, obs, 1); }), "dfir-iris-" + tag() + "-" + id + ".json"); }
    if (kind === "stix") { var one = JSON.parse(JSON.stringify(state)); Object.keys(one.incidents).forEach(function (k) { if (k !== id) delete one.incidents[k]; }); json(SOC.stixBundle(one, al, DATA, ATT), "stix-" + tag() + "-" + id + ".json"); }
    toast("Downloaded.");
  }

  /* ---------- 4. hunt ---------- */
  function renderHunt(m) {
    var hs = DATA.hunts.concat([{ id: "H-custom", title: "Write your own", why: "Any Sigma rule; it runs over every event in the lake up to the shift clock.", yaml: "title: My hunt\nlogsource: { category: any }\ndetection:\n  selection:\n    InitiatingProcessFileName: node\n  condition: selection\nlevel: medium" }]);
    var cur = hs.filter(function (x) { return x.id === ui.huntSel; })[0] || hs[0];
    var yaml = (state.huntYaml || {})[cur.id] || cur.yaml;
    m.innerHTML = '<div class=grid2><div><h2>Hunt</h2><p class=lead>Hypothesis-driven queries over the whole event lake, for what no alert caught. Sigma rules run in your browser on sigma.js.</p><div class=qlist>' +
      hs.map(function (x) { return '<button class="qitem' + (x.id === cur.id ? " on" : "") + '" data-hunt="' + x.id + '"><span class=t>' + h(x.id + " · " + x.title) + "</span><span class=m>" + h(x.why) + (state.huntsRun[x.id] !== undefined ? ' <span class="sd-tag">ran: ' + state.huntsRun[x.id] + " hits</span>" : "") + "</span></button>"; }).join("") +
      "</div></div><div><div class=sd-card><h3 style='margin-top:0'>" + h(cur.title) + "</h3><p class=dim>" + h(cur.why) + "</p><label class=f>Sigma</label><textarea class=yaml id=hy spellcheck=false>" + h(yaml) + '</textarea><div class=row style="margin-top:8px"><button class="btn pri" id=hrun>Run hunt</button><button class=btn id=hreset>Reset query</button></div><div id=hout></div></div></div></div>';
    $$("[data-hunt]").forEach(function (b) { b.onclick = function () { ui.huntSel = b.dataset.hunt; render(); }; });
    $("#hreset").onclick = function () { delete state.huntYaml[cur.id]; save(); render(); };
    $("#hrun").onclick = function () {
      var y = $("#hy").value, out = $("#hout"); state.huntYaml[cur.id] = y;
      var c;
      try { var p = S.parse(y); c = S.compile(p.rule || p); if (c.errors && c.errors.length) throw new Error(c.errors.join(" ")); } catch (e) { out.innerHTML = '<p class=bad style="margin-top:8px">Rule error: ' + h(e.message || e) + "</p>"; return; }
      var n = simIso(), hits = DATA.events.filter(function (e) { return e._t <= n && S.match(c, e).match; });
      state.huntsRun[cur.id] = hits.length; save();
      var alerted = {}; ALL.forEach(function (a) { a.events.forEach(function (id) { alerted[id] = a.id; }); });
      var incs = incList().filter(function (i) { return i.status !== "closed"; });
      out.innerHTML = "<h3>" + plural(hits.length, "hit") + " up to " + hhmm(state.sim) + " UTC</h3>" + (hits.length ? '<div class=tablewrap><table class=ev><colgroup><col style=width:92px><col style=width:84px><col><col style=width:150px></colgroup><thead><tr><th>UTC</th><th>Source</th><th>Event</th><th>Already alerted?</th></tr></thead><tbody>' +
        hits.map(function (e) { return "<tr><td class=mono>" + h(t5(e._t)) + "</td><td>" + srcb(e._src) + "</td><td class=mono>" + h(SOC.summarize(e)) + "</td><td>" + (alerted[e._id] ? '<span class=dim>' + h(alerted[e._id]) + "</span>" : "<b class=bad>no alert</b>") + "</td></tr>"; }).join("") + "</tbody></table></div>" +
        (incs.length ? '<div class=row style="margin-top:8px"><select id=hinc style="width:auto">' + incs.map(function (i) { return '<option value="' + h(i.id) + '">' + h(i.id + " " + i.title) + "</option>"; }).join("") + '</select><button class=btn id=hadd>Add hits to incident timeline</button></div>' : "<p class=dim>Create an incident to attach these hits.</p>") : "");
      var ha = $("#hadd"); if (ha) ha.onclick = function () { var i = state.incidents[$("#hinc").value]; hits.forEach(function (e) { if (i.extra.indexOf(e._id) < 0) i.extra.push(e._id); }); save(); toast(hits.length + " events added to " + i.id + "."); };
      renderChrome();
    };
  }

  /* ---------- 5. tuning ---------- */
  function renderTune(m) {
    var vis = visible();
    var rows = DATA.rules.concat(DATA.correlations.map(function (c) { return { id: c.id, platform: c.platform, title: c.title, corr: true }; })).map(function (r) {
      var mine = vis.filter(function (a) { return a.ruleId === r.id; }), c = { tp: 0, noisy: 0, un: 0 };
      mine.forEach(function (a) { var v = state.verdicts[a.id]; if (!v) c.un++; else if (v.verdict === "fp" || v.verdict === "benign") c.noisy++; else c.tp++; });
      var title = r.title || (r.yaml.match(/^title: (.*)$/m) || [])[1];
      return { r: r, title: title, n: mine.length, c: c };
    });
    m.innerHTML = "<h2>Detection tuning</h2><p class=lead>Your verdicts feed this table. A proposal adds a filter built from the fields that separate your false and benign positives from your confirmed ones, then re-runs the rule over the lake to prove no true positive is lost.</p>" +
      '<div class="sd-card tablewrap"><table class=ev style="min-width:640px"><colgroup><col style="width:34%"><col style="width:10%"><col style="width:9%"><col style="width:9%"><col style="width:12%"><col style="width:10%"><col style="width:16%"></colgroup><thead><tr><th>Rule</th><th>Platform</th><th>Alerts</th><th>TP</th><th>FP + benign</th><th>Untriaged</th><th></th></tr></thead><tbody>' +
      rows.map(function (x) { return "<tr><td><b>" + h(x.r.id) + "</b> " + h(x.title) + "</td><td>" + h(x.r.platform) + "</td><td>" + x.n + "</td><td>" + x.c.tp + "</td><td>" + x.c.noisy + "</td><td>" + x.c.un + "</td><td>" + (x.r.corr ? '<span class=dim>correlation</span>' : '<button class="btn sm" data-tune="' + x.r.id + '"' + (x.c.noisy ? "" : " disabled") + ">Propose tuning</button>") + "</td></tr>"; }).join("") + "</tbody></table></div>" +
      Object.keys(ui.tuneOut).map(function (id) { return tuneCard(ui.tuneOut[id]); }).join("") +
      (state.tuning.length ? "<div class=sd-card><h3 style='margin-top:0'>Filed requests (go into the handover)</h3><ul class=facts>" + state.tuning.map(function (t) { return "<li><b>" + h(t.ruleId) + "</b>: " + h(t.summary) + "</li>"; }).join("") + "</ul></div>" : "");
    $$("[data-tune]").forEach(function (b) { b.onclick = function () { var r = DATA.rules.filter(function (x) { return x.id === b.dataset.tune; })[0]; ui.tuneOut[r.id] = SOC.proposeTuning(r, visible(), state.verdicts, DATA); render(); }; });
    $$("[data-file]").forEach(function (b) { b.onclick = function () { var p = ui.tuneOut[b.dataset.file]; var summ = "add filter_tuned on " + Object.keys(p.filter).map(function (k) { return k + " = " + p.filter[k].join(" / "); }).join("; ") + ". Lab re-run: " + p.before + " → " + p.after + " alerts, " + p.lostTp.length + " true positives lost."; state.tuning = state.tuning.filter(function (t) { return t.ruleId !== p.rule.id; }); state.tuning.push({ ruleId: p.rule.id, summary: summ }); save(); toast("Tuning request filed for " + p.rule.id + "."); render(); }; });
  }
  function tuneCard(p) {
    if (!p) return "";
    if (p.error) return '<div class=sd-card><b>' + h(p.rule.id) + "</b>: " + h(p.error) + "</div>";
    var lines = p.yaml.split("\n").map(function (l) { var add = /filter_tuned|and not filter_tuned|^# /.test(l) || /^    [A-Za-z.]+: \[/.test(l) && p.yaml.indexOf(l) > p.yaml.indexOf("filter_tuned"); return '<div class="' + (add ? "add" : "") + '">' + (add ? "+ " : "  ") + h(l) + "</div>"; }).join("");
    return '<div class=sd-card><div class=inc-head><b>Proposal for ' + h(p.rule.id) + '</b><span class="' + (p.lostTp.length ? "bad" : "ok") + '">' + (p.lostTp.length ? p.lostTp.length + " true positives would be lost: do not ship" : "0 true positives lost") + "</span></div>" +
      '<p class=dim>Re-run over the lake: ' + p.before + " alerts before, " + p.after + " after. Removes: " + p.removed.map(function (a) { return h(a.id); }).join(", ") + ". Keeps: " + (p.keep.map(function (a) { return h(a.id); }).join(", ") || "none confirmed yet") + ".</p>" +
      '<pre class="raw diff">' + lines + '</pre><div class=row style="margin-top:8px"><button class="btn pri" data-file="' + h(p.rule.id) + '"' + (p.lostTp.length ? " disabled" : "") + ">File tuning request</button></div></div>";
  }

  /* ---------- 6. enrich ---------- */
  function renderEnrich(m) {
    var ex = DATA.enrichExamples || [];
    m.innerHTML = "<h2>Enrich an indicator</h2><p class=lead>IP, domain, npm package or CVE. Every lookup is a live call made now, with its source and time.</p><div class=sd-card><div class=row><input type=text id=eq placeholder='IP, domain, npm package or CVE' style='flex:1;min-width:220px'><button class='btn pri' id=ego>Look up</button></div><div class=row style='margin-top:8px'><span class=dim>Try:</span>" + ex.map(function (x) { return '<button class="btn sm" data-ex="' + h(x) + '">' + h(x) + "</button>"; }).join("") + "</div><div id=eout style='margin-top:10px'></div></div>";
    function go(v) {
      var t = detectType(v); if (!t) { $("#eout").innerHTML = "<p class=bad>Not an IP, domain, npm package or CVE.</p>"; return; }
      $("#eout").innerHTML = "<p class=dim>Looking up " + h(v) + " as " + h(t) + "…</p>";
      enrich({ type: t, value: v.trim() }).then(function () { $("#eout").innerHTML = enrichHtml({ type: t, value: v.trim() }); });
    }
    $("#ego").onclick = function () { go($("#eq").value); };
    $("#eq").onkeydown = function (e) { if (e.key === "Enter") go($("#eq").value); };
    $$("[data-ex]").forEach(function (b) { b.onclick = function () { $("#eq").value = b.dataset.ex; go(b.dataset.ex); }; });
  }

  /* ---------- 7. handover out ---------- */
  function renderOut(m) {
    var vis = visible(), md = SOC.buildHandover(state, vis, DATA), lint = SOC.lintHandover(state, vis, hhmm(state.sim), DATA);
    m.innerHTML = "<h2>Handover to " + h(SHIFT.to) + "</h2><p class=lead>Built from your verdicts, incidents, actions, watch list and tuning requests. The check below lists what would make the next shift lose time or lose an item.</p>" +
      '<div class=sd-card><h3 style="margin-top:0">Handover check: ' + (lint.length ? lint.length + " issues" : '<span class=ok>clean</span>') + "</h3>" + (lint.length ? '<ul class=lint>' + lint.map(function (i) { return '<li class="' + i.sev + '">' + h(i.sev) + ": " + h(i.msg) + "</li>"; }).join("") + "</ul>" : "<p class=ok>Every open item has an owner, a next action and a due time.</p>") + "</div>" +
      metricsCard(vis) +
      '<div class=sd-card><div class=inc-head><h3 style="margin-top:0">Handover note</h3><div class=row><button class=btn id=ocopy>Copy</button><button class=btn id=odl>Download .md</button><button class="btn" id=onds>Download verdicts (.ndjson)</button><button class=btn id=onav>ATT&amp;CK Navigator layer</button><button class=btn id=ostix>STIX 2.1 bundle</button></div></div><pre class=md>' + h(md) + "</pre></div>";
    $("#ocopy").onclick = function () { if (!navigator.clipboard) { toast("Copy is not available in this browser."); return; } navigator.clipboard.writeText(md).then(function () { toast("Copied."); }, function () { toast("Copy was blocked."); }); };
    $("#onds").onclick = function () { var nd = SOC.verdictExport(state, ALL); if (!nd.trim()) { toast("Record a verdict on at least one alert first."); return; } download(nd, "verdicts-" + DATA.id + "-" + DAY + ".ndjson", "application/x-ndjson"); };
    $("#odl").onclick = function () { download(md, "handover-" + SHIFT.name + "-" + DAY + ".md", "text/markdown"); };
    $("#onav").onclick = function () { json(SOC.navigatorLayer(state, visible(), DATA, ATT_VER || "19"), "attack-layer-" + tag() + "-" + DAY + ".json"); toast("Downloaded. Open it in ATT&CK Navigator."); };
    $("#ostix").onclick = function () { json(SOC.stixBundle(state, visible(), DATA, ATT), "stix-shift-" + tag() + "-" + DAY + ".json"); toast("Downloaded."); };
  }
  function fm(x) { return x === null ? "n/a" : x < 60 ? (Math.round(x * 10) / 10) + " min" : (Math.round(x / 6) / 10) + " h"; }
  function metricsCard(vis) {
    var mt = SOC.shiftMetrics(state, vis);
    var cell = function (label, s, how) { return '<div class=counter><b>' + fm(s.mean) + "</b><span>" + label + " (median " + fm(s.median) + ", n " + s.n + ")</span><span class=dim>" + how + "</span></div>"; };
    return '<div class=sd-card><h3 style="margin-top:0">Shift timing</h3><div class="counters mt">' + cell("MTTD", mt.mttd, "alert time minus first event") + cell("MTTA", mt.mtta, "first opened minus alert time") + cell("MTTR", mt.mttr, "verdict time minus alert time") + cell("Time to first response", mt.mttrespond, "first completed action minus first alert, per incident") +
      "</div><p class=dim style=\"margin-top:8px\">On the shift clock. Means and nearest-rank medians over alerts that have both times.</p></div>";
  }
  function download(text, name, type) { var a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type: type })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); }

  /* ---------- 8. answer key ---------- */
  function renderKey(m) {
    if (!ui.showKey) { m.innerHTML = '<div class=sd-card><h2>Answer key</h2><p class=lead>What a good shift concludes for every alert and hunt, and how your verdicts compare. Try the shift first.</p><button class="btn pri" id=kshow>Show the answer key</button></div>'; $("#kshow").onclick = function () { ui.showKey = true; render(); }; return; }
    var g = SOC.grade(state, ALL, DATA), n = simIso();
    m.innerHTML = "<h2>Answer key</h2><p class=lead>Your verdicts match on " + g.score + " of " + g.total + " alerts. Escalating something the key calls a true positive counts; so does calling an escalation a true positive.</p>" +
      '<div class="sd-card tablewrap"><table class=ev style="min-width:760px"><colgroup><col style="width:24%"><col style="width:12%"><col style="width:12%"><col style="width:52%"></colgroup><thead><tr><th>Alert</th><th>You</th><th>Key</th><th>Why</th></tr></thead><tbody>' +
      g.rows.map(function (r) { return "<tr><td><b>" + h(r.alert.id) + "</b><br><span class=dim>" + h(r.alert.at.slice(11, 16)) + " UTC" + (r.alert.at > n ? " (not arrived yet)" : "") + "</span></td><td>" + vtag(r.mine) + "</td><td>" + (r.key ? vtag({ verdict: r.key.verdict }) + " " + sev(r.key.sev) : "") + (r.mine ? (r.ok ? " <b class=ok>✓</b>" : " <b class=bad>✗</b>") : "") + "</td><td>" + h(r.key ? r.key.why : "") + (r.key && r.key.incident ? " <span class=sd-tag>" + h(r.key.incident) + "</span>" : "") + "</td></tr>"; }).join("") + "</tbody></table></div>" +
      "<div class=sd-card><h3 style='margin-top:0'>Hunts</h3><ul class=facts>" + g.hunts.map(function (x) { return "<li><b>" + h(x.id) + "</b> " + (x.ran ? '<span class=ok>ran</span>' : '<span class=bad>not run</span>') + ": " + h(x.note) + "</li>"; }).join("") + "</ul>" +
      ((DATA.goodShift || []).length ? "<h3>Incidents a good shift ends with</h3><ul class=facts>" + DATA.goodShift.map(function (g) { return "<li><b>" + h(g.id) + "</b> (" + h(g.sev) + "): " + h(g.text) + "</li>"; }).join("") + "</ul>" : "") + "</div>";
  }

  /* ---------- events ---------- */
  $$("#tabs button").forEach(function (b) { b.onclick = function () { ui.tab = b.dataset.tab; closeDrawer(); render(); toDesk(); }; });
  $$("[data-adv]").forEach(function (b) { b.onclick = function () {
    var before = visible().length;
    state.sim = b.dataset.adv === "end" ? Math.max(state.sim, SHIFT.endMin - 20) : Math.min(SHIFT.endMin, state.sim + (+b.dataset.adv));
    save(); var add = visible().length - before; if (add > 0) toast(add + " new alert" + (add > 1 ? "s" : "") + " in the queue."); render();
  }; });
  render();
  }
})();
