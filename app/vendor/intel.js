/* intel.js: shared public-lookup adapters for the pwnsy tools.
   Browser: window.PwnsyIntel. Node: require("./intel.js").

   One fetch stack for the lookups several tools make: RDAP (with IANA
   bootstrap routing), DNS over HTTPS, the Tor relay list, OSV, CISA KEV,
   EPSS, CVE records and RIPEstat ASN data. Every adapter resolves to
     { data, raw, source, url, fetchedAt }
   where data is a small normalised view, raw is the upstream JSON (so a tool
   can keep its own parser), url is the request that answered and fetchedAt is
   an ISO timestamp. Failures reject with an Error carrying code, status, url
   and source. Identical requests share one in-flight promise and a short
   in-memory cache; a failure is never cached.

   Verdicts and presentation stay in each tool. Nothing here decides whether a
   result is good or bad, except where a field is the upstream's own flag. */
(function (root, factory) {
  var api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PwnsyIntel = api;
})(typeof window !== "undefined" ? window : this, function () {
  "use strict";

  var MIN = 60000;
  var cfg = { fetch: null, timeout: 20000, now: function () { return Date.now(); } };
  var CACHE = {};

  /* ---------------- errors ---------------- */
  function fail(code, message, extra) {
    var e = new Error(message);
    e.name = "IntelError";
    e.code = code;
    if (extra) Object.keys(extra).forEach(function (k) { e[k] = extra[k]; });
    return e;
  }

  /* ---------------- fetch with timeout ---------------- */
  // Messages match the wording the tools already showed: "timed out",
  // "network error", "no record (404)", "rate limited (429)", "HTTP 500".
  function request(url, opts) {
    opts = opts || {};
    var f = cfg.fetch || (typeof fetch === "function" ? fetch : null);
    if (!f) return Promise.reject(fail("unsupported", "fetch is not available", { url: url, source: opts.source }));
    var ctl = typeof AbortController === "function" ? new AbortController() : null;
    var ms = opts.timeout || cfg.timeout;
    var timedOut = false;
    var timer = setTimeout(function () { timedOut = true; if (ctl) ctl.abort(); }, ms);
    var init = { method: opts.method || "GET", headers: opts.headers, body: opts.body, mode: "cors", credentials: "omit", redirect: "follow" };
    if (opts.cache) init.cache = opts.cache;
    if (ctl) init.signal = ctl.signal;
    var meta = { url: url, source: opts.source || "" };
    return new Promise(function (resolve, reject) {
      // A fetch that ignores the abort signal still times out.
      var guard = setTimeout(function () { reject(fail("timeout", "timed out", meta)); }, ms + 50);
      Promise.resolve().then(function () { return f(url, init); }).then(function (r) {
        meta.status = r.status;
        if (opts.allow404 && r.status === 404) return { status: 404, json: null, finalUrl: r.url || url };
        if (!r.ok) {
          var code = r.status === 404 ? "notfound" : r.status === 429 ? "ratelimit" : "http";
          var msg = r.status === 404 ? "no record (404)" : r.status === 429 ? "rate limited (429)" : "HTTP " + r.status;
          throw fail(code, msg, meta);
        }
        if (opts.text) return r.text().then(function (t) { return { status: r.status, json: t, finalUrl: r.url || url }; });
        return r.json().then(function (j) { return { status: r.status, json: j, finalUrl: r.url || url }; },
          function () { throw fail("parse", "the answer was not JSON", meta); });
      }).then(function (v) { clearTimeout(guard); resolve(v); }, function (e) {
        clearTimeout(guard);
        if (e && e.name === "IntelError") return reject(e);
        if (timedOut || (e && e.name === "AbortError")) return reject(fail("timeout", "timed out", meta));
        reject(fail("network", e && e.message && e.message !== "Failed to fetch" && !/NetworkError|Load failed/.test(e.message) ? e.message : "network error", meta));
      });
    }).then(function (v) { clearTimeout(timer); return v; }, function (e) { clearTimeout(timer); throw e; });
  }

  /* ---------------- dedup + cache ---------------- */
  // ttl: how long a success is reused. fresh: skip the cache for this call.
  function once(key, ttl, opts, fn) {
    var now = cfg.now();
    var hit = CACHE[key];
    if (hit && !(opts && opts.fresh) && (hit.pending || now - hit.at < ttl)) return hit.p;
    var entry = { pending: true, at: now, p: null };
    entry.p = Promise.resolve().then(fn).then(function (v) {
      entry.pending = false; entry.at = cfg.now();
      return v;
    }, function (e) {
      if (CACHE[key] === entry) delete CACHE[key];
      throw e;
    });
    CACHE[key] = entry;
    return entry.p;
  }
  function wrap(source, url, raw, data) {
    return { data: data, raw: raw, source: source, url: url, fetchedAt: new Date(cfg.now()).toISOString() };
  }

  /* ---------------- address helpers ---------------- */
  function v4num(ip) { return ip.split(".").reduce(function (a, o) { return a * 256 + +o; }, 0); }
  function expand6(s) {
    s = String(s).toLowerCase();
    var v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (v4) { var n = v4num(v4[1]); s = s.slice(0, -v4[1].length) + (n >>> 16).toString(16) + ":" + (n & 65535).toString(16); }
    var halves = s.split("::"), a = halves[0] ? halves[0].split(":") : [], b = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
    var mid = halves.length > 1 ? new Array(8 - a.length - b.length + 1).join("0,").split(",").slice(0, 8 - a.length - b.length) : [];
    return a.concat(mid, b).map(function (g) { return ("0000" + (g || "0")).slice(-4); }).join("");
  }
  function bits(type, ip) {
    if (type === "v4") return ("00000000000000000000000000000000" + v4num(ip).toString(2)).slice(-32);
    return expand6(ip).split("").map(function (h) { return ("000" + parseInt(h, 16).toString(2)).slice(-4); }).join("");
  }
  function ipKind(ip) { return String(ip).indexOf(":") > -1 ? "ipv6" : "ipv4"; }

  /* ---------------- RDAP ---------------- */
  // Finds the registry RDAP server for a TLD or address block from the IANA
  // bootstrap files, so a lookup goes straight to the registry.
  function bootstrapUrl(boot, kind, value) {
    if (!boot || !Array.isArray(boot.services)) return null;
    var best = null, bestLen = -1;
    var ipBits = kind === "ipv4" ? bits("v4", value) : kind === "ipv6" ? bits("v6", value) : null;
    boot.services.forEach(function (svc) {
      var urls = (svc[1] || []).filter(function (u) { return /^https:/.test(u); });
      if (!urls.length) return;
      svc[0].forEach(function (entry) {
        var len = -1;
        if (kind === "domain") { var tld = value.split(".").pop(); if (entry.toLowerCase() === tld) len = 1; }
        else {
          var m = /^([^/]+)\/(\d+)$/.exec(entry); if (!m) return;
          var pl = +m[2], net = kind === "ipv4" ? bits("v4", m[1].split(".").concat(["0", "0", "0"]).slice(0, 4).join(".")) : bits("v6", m[1]);
          if (net.slice(0, pl) === ipBits.slice(0, pl)) len = pl;
        }
        if (len > bestLen) { bestLen = len; best = urls[0]; }
      });
    });
    if (!best) return null;
    return best.replace(/\/?$/, "/") + (kind === "domain" ? "domain/" : "ip/") + value;
  }
  var BOOT = { domain: "dns", ipv4: "ipv4", ipv6: "ipv6" };
  function bootstrap(kind) {
    return once("boot|" + kind, 6 * 60 * MIN, null, function () {
      return request("https://data.iana.org/rdap/" + BOOT[kind] + ".json", { timeout: 20000, source: "IANA RDAP bootstrap" }).then(function (r) { return r.json; });
    });
  }
  function wait(ms) { return new Promise(function (res) { setTimeout(res, ms); }); }
  // rdap.org (a redirector with a rate limit) is the fallback when the
  // bootstrap file does not load, and the second try when the registry fails.
  function rdapFetch(kind, value, opts) {
    var fallback = "https://rdap.org/" + (kind === "domain" ? "domain/" : "ip/") + value;
    var o = { headers: { accept: "application/rdap+json" }, timeout: opts.timeout || 20000, source: "RDAP" };
    var start = opts.via === "rdap.org" ? Promise.resolve(fallback) : bootstrap(kind).then(function (b) {
      var u = bootstrapUrl(b, kind, value);
      if (!u) throw fail("unsupported", kind === "domain" ? "the ." + value.split(".").pop() + " registry publishes no RDAP service" : "no RDAP service for this block", { source: "RDAP", url: "" });
      return u;
    }, function () { return fallback; });
    return start.then(function (url) {
      return request(url, o).catch(function (e) {
        if (e.code === "notfound" || opts.retry === false) throw e;
        var next = url === fallback ? url : fallback;
        return wait(opts.retryDelay == null ? 1500 : opts.retryDelay).then(function () { return request(next, o); });
      });
    });
  }
  function vcardAll(e, field) {
    var arr = (e && e.vcardArray && e.vcardArray[1]) || [];
    return arr.filter(function (x) { return x[0] === field; }).map(function (x) { return String(x[3] == null ? "" : x[3]).trim(); }).filter(Boolean);
  }
  function walk(ents, fn) { (ents || []).forEach(function (e) { fn(e); walk(e.entities, fn); }); }
  function events(j) { var ev = {}; (j.events || []).forEach(function (e) { if (!ev[e.eventAction]) ev[e.eventAction] = e.eventDate; }); return ev; }
  function selfLink(j) { var l = (j.links || []).filter(function (x) { return x.rel === "self" && /^https?:/.test(x.href || ""); })[0]; return l ? l.href : null; }
  function rirOf(u, port43) {
    return /arin\.net/.test(u) ? "ARIN" : /ripe\.net/.test(u) ? "RIPE NCC" : /apnic\.net/.test(u) ? "APNIC"
      : /lacnic\.net|registro\.br/.test(u) ? "LACNIC" : /afrinic\.net/.test(u) ? "AFRINIC" : (port43 || "");
  }
  function pushU(list, v) { if (v && list.indexOf(v) < 0) list.push(v); }
  function normRdapIp(j, url) {
    if (!j || j.objectClassName !== "ip network") return null;
    var abuse = [], abuseNames = [], registrants = [];
    walk(j.entities, function (e) {
      var roles = e.roles || [];
      if (roles.indexOf("abuse") > -1) { vcardAll(e, "email").forEach(function (m) { pushU(abuse, m); }); vcardAll(e, "fn").forEach(function (n) { pushU(abuseNames, n); }); }
      if (roles.indexOf("registrant") > -1) vcardAll(e, "fn").forEach(function (n) { pushU(registrants, n); });
    });
    var ev = events(j), self = selfLink(j) || url || "";
    return {
      handle: j.handle || null, name: j.name || null, type: j.type || null, country: j.country || null,
      start: j.startAddress || null, end: j.endAddress || null,
      cidr: (j.cidr0_cidrs || []).map(function (c) { return (c.v4prefix || c.v6prefix) + "/" + c.length; }),
      asns: (j.arin_originas0_originautnums || []).map(String),
      abuse: abuse, abuseNames: abuseNames, registrants: registrants,
      registered: ev.registration || null, changed: ev["last changed"] || null,
      rir: rirOf(self, j.port43), url: self
    };
  }
  function normRdapDomain(j, url) {
    if (!j || j.objectClassName !== "domain") return null;
    var registrar = "", abuse = [];
    walk(j.entities, function (e) {
      var roles = e.roles || [];
      if (roles.indexOf("registrar") > -1 && !registrar) registrar = vcardAll(e, "fn")[0] || (e.publicIds && e.publicIds[0] && e.publicIds[0].identifier) || "";
      if (roles.indexOf("abuse") > -1) vcardAll(e, "email").forEach(function (m) { pushU(abuse, m); });
    });
    var ev = events(j);
    return {
      name: String(j.ldhName || "").toLowerCase(), registrar: registrar, abuse: abuse,
      registered: ev.registration || null, expires: ev.expiration || null, changed: ev["last changed"] || null,
      status: (j.status || []).map(String),
      ns: (j.nameservers || []).map(function (n) { return String(n.ldhName || "").toLowerCase().replace(/\.$/, ""); }).filter(Boolean),
      dnssec: j.secureDNS ? !!j.secureDNS.delegationSigned : null,
      url: selfLink(j) || url || ""
    };
  }
  /* rdapIp(ip, { timeout, via: "rdap.org", fresh }) */
  function rdapIp(ip, opts) {
    opts = opts || {};
    ip = String(ip).trim().toLowerCase();
    return once("rdap|ip|" + ip + "|" + (opts.via || ""), 10 * MIN, opts, function () {
      return rdapFetch(ipKind(ip), ip, opts).then(function (r) { return wrap("RDAP", r.finalUrl, r.json, normRdapIp(r.json, r.finalUrl)); });
    });
  }
  /* rdapDomain(domain, opts): same options as rdapIp. */
  function rdapDomain(domain, opts) {
    opts = opts || {};
    domain = String(domain).trim().toLowerCase().replace(/\.$/, "");
    return once("rdap|domain|" + domain + "|" + (opts.via || ""), 10 * MIN, opts, function () {
      return rdapFetch("domain", domain, opts).then(function (r) { return wrap("RDAP", r.finalUrl, r.json, normRdapDomain(r.json, r.finalUrl)); });
    });
  }

  /* ---------------- DNS over HTTPS ---------------- */
  var DNS_TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DS: 43, DNSKEY: 48, HTTPS: 65, CAA: 257 };
  var DOH = {
    cloudflare: { label: "Cloudflare DoH", url: function (n, t) { return "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(n) + "&type=" + encodeURIComponent(t); } },
    google: { label: "Google DoH", url: function (n, t) { return "https://dns.google/resolve?name=" + encodeURIComponent(n) + "&type=" + encodeURIComponent(t); } }
  };
  /* doh(name, type, { provider: "cloudflare" | "google", timeout, fresh })
     data: { status, nx, answers: [data of the asked type], cname: [] } */
  function doh(name, type, opts) {
    opts = opts || {};
    type = String(type || "A").toUpperCase();
    var p = DOH[opts.provider] ? opts.provider : "cloudflare";
    var url = DOH[p].url(name, type);
    return once("doh|" + url, (opts.ttl == null ? 2 * MIN : opts.ttl), opts, function () {
      return request(url, { headers: { accept: "application/dns-json" }, timeout: opts.timeout, source: DOH[p].label, cache: "no-store" }).then(function (r) {
        var j = r.json;
        if (!j || typeof j.Status !== "number") throw fail("parse", "the DNS answer had no status", { url: url, source: DOH[p].label });
        var code = DNS_TYPES[type];
        var strip = function (a) { return String(a.data).replace(/\.$/, ""); };
        return wrap(DOH[p].label, url, j, {
          status: j.Status, nx: j.Status === 3,
          answers: (j.Answer || []).filter(function (a) { return a.type === code; }).map(strip),
          cname: (j.Answer || []).filter(function (a) { return a.type === 5; }).map(strip)
        });
      });
    });
  }
  function reverseName(ip) {
    if (ip.indexOf(":") > -1) return expand6(ip).split("").reverse().join(".") + ".ip6.arpa";
    return ip.split(".").reverse().join(".") + ".in-addr.arpa";
  }

  /* ---------------- Tor (Onionoo) ---------------- */
  // A relay is any Tor node published at this address. An exit is a relay that
  // lets traffic out to the internet from it: the address is one of its exit
  // addresses, or the relay carries the Exit flag. Matching is exact; a search
  // for 1.2.3.4 also returns 1.2.3.45 and those are dropped.
  function bare(a) {
    a = String(a).toLowerCase();
    var m = /^\[([^\]]+)\](?::\d+)?$/.exec(a);
    if (m) return m[1];
    return a.split(":").length === 2 ? a.replace(/:\d+$/, "") : a;
  }
  function sameAddr(a, b) {
    if (a.indexOf(":") > -1 && b.indexOf(":") > -1) return expand6(a) === expand6(b);
    return a === b;
  }
  function normOnionoo(j, ip) {
    if (!j || !Array.isArray(j.relays)) return null;
    ip = String(ip).toLowerCase();
    var relays = [], exits = [];
    j.relays.forEach(function (r) {
      var ors = (r.or_addresses || []).map(bare);
      var ex = (r.exit_addresses || []).map(bare);
      var atOr = ors.some(function (a) { return sameAddr(a, ip); }), atExit = ex.some(function (a) { return sameAddr(a, ip); });
      if (!atOr && !atExit) return;
      relays.push(r);
      if (atExit || ((r.flags || []).indexOf("Exit") > -1 && atOr)) exits.push(r);
    });
    return {
      relay: relays.length > 0, exit: exits.length > 0, relays: relays.length, exits: exits.length,
      nicknames: relays.map(function (r) { return r.nickname; }).filter(Boolean).slice(0, 4),
      exitNicknames: exits.map(function (r) { return r.nickname; }).filter(Boolean).slice(0, 4),
      flags: relays.reduce(function (a, r) { (r.flags || []).forEach(function (f) { pushU(a, f); }); return a; }, []),
      published: j.relays_published || ""
    };
  }
  /* torStatus(ip, { timeout, fresh }) */
  function torStatus(ip, opts) {
    opts = opts || {};
    ip = String(ip).trim().toLowerCase();
    var q = ip.indexOf(":") > -1 ? "[" + ip + "]" : ip;
    var url = "https://onionoo.torproject.org/details?search=" + encodeURIComponent(q) + "&fields=nickname,or_addresses,exit_addresses,flags";
    return once("tor|" + ip, 10 * MIN, opts, function () {
      return request(url, { timeout: opts.timeout, source: "Tor Project Onionoo" }).then(function (r) { return wrap("Tor Project Onionoo", url, r.json, normOnionoo(r.json, ip)); });
    });
  }

  /* ---------------- OSV ---------------- */
  var ECO = { npm: "npm", pypi: "PyPI", PyPI: "PyPI" };
  /* osvPackage(ecosystem, name, version?, { maxPages = 5, timeout, fresh })
     data: { vulns, malicious: [MAL- entries], advisories: [the rest], hasMalicious }
     withdrawn records are dropped from data and kept in raw. */
  function osvPackage(eco, name, version, opts) {
    opts = opts || {};
    var ecosystem = ECO[eco] || eco;
    var url = "https://api.osv.dev/v1/query";
    return once("osv|" + ecosystem + "|" + name + "|" + (version || ""), 10 * MIN, opts, function () {
      var all = [], pages = 0, max = opts.maxPages || 5;
      function page(token) {
        var body = { package: { name: name, ecosystem: ecosystem } };
        if (version) body.version = version;
        if (token) body.page_token = token;
        return request(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), timeout: opts.timeout, source: "OSV" }).then(function (r) {
          all = all.concat((r.json && r.json.vulns) || []);
          var next = r.json && r.json.next_page_token;
          return next && ++pages < max ? page(next) : null;
        });
      }
      return page(null).then(function () {
        var live = all.filter(function (v) { return !v.withdrawn; });
        var mal = live.filter(function (v) { return /^MAL-/.test(v.id); });
        return wrap("OSV", url, { vulns: all }, {
          ecosystem: ecosystem, name: name, version: version || "",
          vulns: live, malicious: mal, advisories: live.filter(function (v) { return !/^MAL-/.test(v.id); }), hasMalicious: mal.length > 0
        });
      });
    });
  }

  /* ---------------- CISA KEV ---------------- */
  var KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";
  function kevCatalog(opts) {
    opts = opts || {};
    return once("kev", 60 * MIN, opts, function () {
      return request(KEV_URL, { timeout: opts.timeout || 40000, source: "CISA KEV" }).then(function (r) {
        var j = r.json || {};
        if (!Array.isArray(j.vulnerabilities)) throw fail("parse", "the KEV catalogue had no entries", { url: KEV_URL, source: "CISA KEV" });
        return wrap("CISA KEV", KEV_URL, j, { catalogVersion: j.catalogVersion || "", dateReleased: j.dateReleased || "", count: j.vulnerabilities.length });
      });
    });
  }
  /* kev(cveId?, opts): with an id, data.entry is that KEV entry or null. */
  function kev(id, opts) {
    if (id && typeof id === "object") { opts = id; id = null; }
    return kevCatalog(opts).then(function (c) {
      if (!id) return c;
      var want = String(id).toUpperCase(), entry = null;
      for (var i = 0; i < c.raw.vulnerabilities.length; i++) if (c.raw.vulnerabilities[i].cveID === want) { entry = c.raw.vulnerabilities[i]; break; }
      return { data: { catalogVersion: c.data.catalogVersion, dateReleased: c.data.dateReleased, count: c.data.count, entry: entry }, raw: c.raw, source: c.source, url: c.url, fetchedAt: c.fetchedAt };
    });
  }

  /* ---------------- EPSS ---------------- */
  /* epss(id | [ids], opts): up to 100 ids per call.
     data: { "CVE-...": { epss, percentile, date } } */
  function epss(ids, opts) {
    opts = opts || {};
    var list = (Array.isArray(ids) ? ids : [ids]).map(function (x) { return String(x).toUpperCase(); }).slice(0, 100);
    var url = "https://api.first.org/data/v1/epss?cve=" + list.join(",");
    return once("epss|" + list.join(","), 60 * MIN, opts, function () {
      return request(url, { timeout: opts.timeout, source: "FIRST EPSS" }).then(function (r) {
        var out = {};
        ((r.json && r.json.data) || []).forEach(function (row) { out[row.cve] = { epss: +row.epss, percentile: +row.percentile, date: row.date || "" }; });
        return wrap("FIRST EPSS", url, r.json, out);
      });
    });
  }

  /* ---------------- CVE record (CVE.org) ---------------- */
  function cvss(metrics) {
    var hit = null;
    (metrics || []).forEach(function (m) {
      var k = ["cvssV4_0", "cvssV3_1", "cvssV3_0"].filter(function (x) { return m[x]; })[0];
      if (k && !hit) hit = { score: m[k].baseScore, severity: m[k].baseSeverity || "", version: m[k].version || k.replace("cvssV", "").replace("_", ".") };
    });
    return hit;
  }
  /* cveRecord(id, opts) data: { id, state, title, description, published, assigner, cvss } */
  function cveRecord(id, opts) {
    opts = opts || {};
    id = String(id).toUpperCase();
    var url = "https://cveawg.mitre.org/api/cve/" + id;
    return once("cve|" + id, 30 * MIN, opts, function () {
      return request(url, { timeout: opts.timeout, source: "CVE.org" }).then(function (r) {
        var j = r.json || {}, cna = (j.containers || {}).cna || {};
        var score = cvss(cna.metrics);
        if (!score) ((j.containers || {}).adp || []).forEach(function (a) { if (!score) score = cvss(a.metrics); });
        var desc = (cna.descriptions || []).filter(function (d) { return /^en/i.test(d.lang || "en"); })[0] || (cna.descriptions || [])[0];
        var rej = (cna.rejectedReasons || [])[0];
        var md = j.cveMetadata || {};
        return wrap("CVE.org", url, j, {
          id: md.cveId || id, state: md.state || "", title: cna.title || "", description: desc ? desc.value : (rej ? rej.value : ""),
          published: md.datePublished || "", assigner: md.assignerShortName || "", cvss: score
        });
      });
    });
  }

  /* ---------------- ASN (RIPEstat) ---------------- */
  /* asn(ip, { sourceapp, timeout, fresh }) data: { asn, holder, prefix } or
     null when no AS announces the address. The holder lookup is best effort. */
  function asn(ip, opts) {
    opts = opts || {};
    var app = opts.sourceapp || "pwnsy";
    var url = "https://stat.ripe.net/data/network-info/data.json?sourceapp=" + encodeURIComponent(app) + "&resource=" + encodeURIComponent(ip);
    return once("asn|" + app + "|" + ip, 10 * MIN, opts, function () {
      return request(url, { timeout: opts.timeout, source: "RIPEstat" }).then(function (r) {
        var d = (r.json && r.json.data) || {}, n = (d.asns || [])[0];
        if (!n) return wrap("RIPEstat", url, r.json, null);
        return holder(n, app, opts).then(function (h) { return wrap("RIPEstat", url, r.json, { asn: String(n), holder: h, prefix: d.prefix || "" }); });
      });
    });
  }
  function holder(n, app, opts) {
    var url = "https://stat.ripe.net/data/as-overview/data.json?sourceapp=" + encodeURIComponent(app) + "&resource=AS" + n;
    return once("asholder|" + n, 60 * MIN, null, function () {
      return request(url, { timeout: opts.timeout, source: "RIPEstat" }).then(function (x) { return ((x.json && x.json.data) || {}).holder || ""; });
    }).catch(function () { return ""; });
  }

  /* ---------------- pwnsy exit-IP API ---------------- */
  // vpn.pwnsy.com answers CORS only for https://pwnsy.com. It reports the
  // network, hosting flags and Tor bulk exit list membership for an address.
  function pwnsyIp(ip, opts) {
    opts = opts || {};
    var base = opts.base || "https://vpn.pwnsy.com";
    var url = base + "/api/ip/" + encodeURIComponent(ip);
    return once("pwnsyip|" + url, 5 * MIN, opts, function () {
      return request(url, { timeout: opts.timeout, source: "pwnsy exit-IP API" }).then(function (r) {
        if (r.json && r.json.error) throw fail("http", r.json.error, { url: url, source: "pwnsy exit-IP API" });
        return wrap("pwnsy exit-IP API", url, r.json, r.json);
      });
    });
  }

  return {
    rdapIp: rdapIp, rdapDomain: rdapDomain, doh: doh, torStatus: torStatus, osvPackage: osvPackage,
    kev: kev, epss: epss, cveRecord: cveRecord, asn: asn, pwnsyIp: pwnsyIp,
    get: function (url, opts) { return request(url, opts || {}); },
    bootstrapUrl: bootstrapUrl, reverseName: reverseName, expand6: expand6, sameAddr: sameAddr,
    normalize: { rdapIp: normRdapIp, rdapDomain: normRdapDomain, onionoo: normOnionoo },
    DNS_TYPES: DNS_TYPES, KEV_URL: KEV_URL,
    configure: function (o) { Object.keys(o || {}).forEach(function (k) { cfg[k] = o[k]; }); },
    clearCache: function () { CACHE = {}; }
  };
});
