# SOC Shift

[![test](https://github.com/edwardtay/soc-shift/actions/workflows/test.yml/badge.svg)](https://github.com/edwardtay/soc-shift/actions/workflows/test.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/edwardtay/soc-shift/badge)](https://scorecard.dev/viewer/?uri=github.com/edwardtay/soc-shift)
[![Licence: MIT](https://img.shields.io/github/license/edwardtay/soc-shift)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/edwardtay/soc-shift)](https://github.com/edwardtay/soc-shift/releases/latest)

Work a fictional SOC shift in your browser: take the handover, triage Sigma and correlation alerts, pivot, respond, hunt, tune with a regression check, and hand over.

- **Try it:** [edwardtay.github.io/soc-shift](https://edwardtay.github.io/soc-shift/) (this repository on GitHub Pages)
- **Also live at:** [pwnsy.com/tools/detect/soc-desk](https://pwnsy.com/tools/detect/soc-desk/) (the version this repository was extracted from)
- **Teaching with it:** [docs/INSTRUCTORS.md](docs/INSTRUCTORS.md) has a session plan, per-learner seeds, a rubric and discussion questions

![A shift in SOC Shift: handover in, a true-positive verdict, a pivot to the npm package with a live OSV hit, the tuning regression check, incident observables with TLP and PAP, the handover check and shift timing](docs/media/soc-shift.gif)

For SOC students who want reps on analyst decisions, instructors who want a shift they can set and grade, and SOC leads who want to see how someone triages and hands over. There is nothing to install, no account and no server: the page is static files, and the shift is saved in your browser.

## Scenarios

Each scenario is a nine-hour shift with an incoming handover, an event lake, original Sigma rules, correlations, hunts and a full answer key. Pick one from the header, or open the link.

| Scenario | Open | Estate | What happens | Sources | Detections |
| --- | --- | --- | --- | --- | --- |
| Kestrel Ledger, APAC shift | [`?scenario=kestrel-ledger`](https://edwardtay.github.io/soc-shift/?scenario=kestrel-ledger) | Crypto custody firm: 5 staff, macOS and Windows endpoints, a customer portal | A fake take-home test drops an infostealer on a developer laptop and its AWS key is used from a VPS; credential stuffing takes over a customer account; a cracked installer leads to session replay; a confidential file goes to personal storage | EDR, web proxy, WAF, Okta, CloudTrail (65 events) | 7 rules, 2 correlations, 12 alerts, 4 hunts |
| Larkspur Metrics, EMEA shift | [`?scenario=larkspur-metrics`](https://edwardtay.github.io/soc-shift/?scenario=larkspur-metrics) | SaaS company on Microsoft 365 and Entra ID: 6 staff and a service account, Windows laptops | An adversary-in-the-middle phish steals a session; the attacker adds an MFA method, hides replies with an inbox rule, gets an OAuth app consented for mail, and sends fake bank details to customers. Noise from a printer, a traveller, a new joiner and an approved admin consent | Entra sign-in and audit logs, Microsoft 365 unified audit log, Defender for Office 365 email, Defender for Endpoint (49 events) | 6 rules, 1 correlation, 15 alerts, 4 hunts |

In both, at least one hunt finds what no alert raised, a carried-in ticket is still pending with another team, and a noisy rule leaves something to tune behind the regression check.

## What you do in a shift

| Tab | What you do |
| --- | --- |
| 1 · Handover in | Read what the previous shift left open and acknowledge it. The open case, its pending ticket and the watch list become yours. |
| 2 · Alert queue | Move the shift clock. Alerts arrive after their platform's pipeline delay (about a minute for EDR and WAF, two for email, five for scheduled SIEM searches), and opening one acknowledges it. Read the evidence, open the raw events, record a verdict (true positive, benign, false positive, escalate) with severity and a reason, and link it to an incident. |
| 3 · Incidents | Keep each incident's one-line summary, next action, owner, due time and IR notification current. See its response log and merged timeline. Set the IOC flag, TLP 2.0 level (including AMBER+STRICT) and PAP on each observable, then export the incident as a TheHive case, DFIR-IRIS alerts or a STIX 2.1 bundle. |
| 4 · Hunt | Run Sigma hunts over the whole event lake for what no alert caught, or write your own. Hits show whether an alert already covered them and can be added to an incident. |
| 5 · Tuning | Propose a filter for a noisy rule. The proposal is built from the fields that separate your false and benign positives from your confirmed alerts, then the rule is re-run over the lake and blocked if it would drop a true positive. |
| 6 · Enrich IOC | Look up an IP, domain, npm package or CVE against public sources. |
| 7 · Handover out | A handover note built from your verdicts, incidents, pending actions, watch list and tuning requests, and a check that lists what the next shift would lose time on. Shift timing shows MTTD, MTTA, MTTR and time to first response from the shift clock. Copy the note, download it as Markdown, or download the shift as NDJSON verdicts, an ATT&CK Navigator layer or a STIX 2.1 bundle. |
| 8 · Answer key | Compare your verdicts with the key, see what each hunt should find, and read the incidents a good shift ends with. |

Click any entity (user, host, IP, domain, email address, OAuth app, npm package, customer, session, cloud key, file) to open its timeline across every source, run live lookups and take response actions. Actions the SOC can do itself complete at once; actions owned by another team (password reset, key deactivation, app removal, account lock, DLP case) stay pending and carry into the handover.

### Exports and shift timing

| Export | Where | What it holds |
| --- | --- | --- |
| TheHive case JSON | Incidents | The case (TheHive 5 `InputCase`) with response actions as tasks, observables with IOC, TLP and PAP, each linked alert as an `InputAlert`, and ATT&CK procedures |
| DFIR-IRIS alerts JSON | Incidents | One alert per linked alert, with IOCs, assets (hosts by OS, accounts), severity and status ids |
| STIX 2.1 bundle | Incidents, Handover out | The SOC as an identity, an indicator and a sighting per IOC, ATT&CK attack-patterns and `indicates` relationships. Ids are deterministic, so the same shift exports the same bundle |
| ATT&CK Navigator layer | Handover out | Layer format 4.5: one entry per alerted technique, scored by alert count and coloured by your verdicts |
| Verdicts NDJSON | Handover out | One line per closed alert: rule, technique, disposition, reason, event, alert and close times |

| Metric | Measured as |
| --- | --- |
| MTTD | alert time minus the alert's first event |
| MTTA | the time you first opened the alert minus alert time |
| MTTR | verdict time minus alert time |
| Time to first response | first completed response action minus the incident's first alert |

All times are on the shift clock. Each metric shows the mean, the nearest-rank median and how many alerts or incidents it covers, and stays blank until there is something to measure.

DFIR-IRIS type ids are a fresh install's defaults, so check yours under Manage before importing.

### Seeded variants

`?seed=N` (or **Start a new variant** on the Handover in tab) re-draws the attacker addresses and host numbers, and in Kestrel Ledger the customer id, from seed `N`. The attack chains stay the same, the answer key follows the new values, and the shift starts fresh. `?seed=0` is the original. Give each learner a different seed and copied notes stop matching. The scenario's `variants` block decides what is re-drawn (see [docs/SCENARIOS.md](docs/SCENARIOS.md)).

## Why trust the content

| Claim | How it is checked |
| --- | --- |
| Every scenario is consistent | `npm run validate` runs [`tools/validate-scenario.mjs`](tools/validate-scenario.mjs) on both scenarios and on seeds 7, 12345 and 31337: every rule compiles, every answer-key alert fires and every fired alert has an answer with a reason, every alert arrives inside the shift, each hunt returns the number of events its answer states, and a shift that follows the key scores full marks and passes the handover check |
| Tuning advice is safe | For each rule listed in `tuningChecks`, the validator builds the tuning proposal from the answer key and confirms it removes every noisy alert and keeps every true positive |
| Exports match their formats | `npm test` validates every export for both scenarios and all four seeds against JSON schemas: the official OASIS STIX 2.1 schemas, and schemas written from the ATT&CK Navigator 4.5 layer specification, thehive4py 2.1.0's input types and iris-web 2.4.29's models. Sources, commits and licences are in [test/schemas/README.md](test/schemas/README.md). The validator is [`test/jsonschema.mjs`](test/jsonschema.mjs), dependency-free, and fails on any schema keyword it does not implement |
| Detections are original | Every Sigma rule, correlation and hunt was written for this project. No SigmaHQ rules are bundled |
| ATT&CK ids are real | Every technique id in rules, hunts and correlations is checked against the bundled MITRE ATT&CK v19.2 snapshot, reproduced under MITRE's licence |
| The data is synthetic | The validator rejects email addresses outside reserved example domains, public IPv4 addresses that are not listed anchors, AWS key ids without `EXAMPLE`, Luhn-valid card numbers and phone numbers |
| The supply chain is small | No npm dependencies. Every GitHub Action is pinned to a full commit SHA, a test fails if one is not, Dependabot proposes updates weekly, and OpenSSF Scorecard and CodeQL run on the default branch |

Limits: the estates are small and every event is hand-written, so SOC Shift trains judgement and handover. Field names follow each vendor's published log schema, and detections run on sigma.js in the browser.

## Quick start

Open `app/index.html` in a browser. Everything works from `file://` except ATT&CK technique names, which need the page served because browsers block `fetch()` on local files.

To serve it:

```sh
npx serve app
# or
python3 -m http.server 8080 --directory app
```

Run the checks (Node 18 or later, no dependencies to install):

```sh
npm test            # engine, exports against their schemas, every scenario, repository hygiene
npm run validate    # both scenarios and seeds 7, 12345, 31337
node tools/grade-verdicts.mjs app/scenarios/larkspur-metrics --seed 1007 verdicts.ndjson   # grade a learner's export
```

## How grading works

- Each alert id is `<rule id>|<group key>`, for example `R-EDR-001|KL-MBP-0142`. The group key is the host for EDR rules, the source IP for WAF rules, the user for SSE and SIEM rules, the recipient for email rules, and the subject for correlations. A rule can set its own `groupBy`.
- The scenario's answer key gives the verdict, severity, incident and reason a good shift reaches for every alert. Your score is the number of alerts where your verdict matches. True positive and escalate count as the same call.
- Hunts are marked as run or not run, with what each should find.
- The handover check is a separate signal. It flags an unacknowledged incoming handover, carried tickets dropped from the next action, open incidents without a summary, next action, owner or due time, high or critical incidents with no response action, critical incidents with no IR notification, untriaged alerts, verdicts without a reason the next shift can check, and items past due that the current shift still owns.
- A shift that follows the answer key scores full marks and passes the handover check, on the original shift and on seeded variants. `npm test` proves both.

[docs/INSTRUCTORS.md](docs/INSTRUCTORS.md) covers what to grade beyond the score.

## Write your own scenario

A scenario is a folder under `app/scenarios/` holding one `scenario.js`: the estate, the incoming handover, the event lake, Sigma rules, correlations, hunts and the answer key. Add its id to `app/scenarios/index.js` and open the page with `?scenario=<id>`.

[docs/SCENARIOS.md](docs/SCENARIOS.md) has the schema, the log shapes the desk understands (Defender for Endpoint, a web proxy, a WAF, Okta, CloudTrail, Entra sign-in and audit logs, the Microsoft 365 unified audit log, Defender for Office 365 email), the correlation types, how answer keys and grading work, and how to validate:

```sh
node tools/validate-scenario.mjs app/scenarios/<your-scenario> --seed 7
```

## How it compares

These tools are good at what they do. The table is here to help you pick, and the descriptions come from each project's own documentation.

| Tool | What it is for | Input | Output | Setup |
| --- | --- | --- | --- | --- |
| **SOC Shift** | Practising analyst decisions across one shift: triage, response, hunting, tuning and handover, graded against an answer key | Two bundled synthetic scenarios, with seeded variants | TheHive case JSON, DFIR-IRIS alert JSON, STIX 2.1, ATT&CK Navigator layer, NDJSON verdicts; MTTD, MTTA and MTTR from the shift clock | None: a static page in the browser |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Fast search and Sigma-based hunting over Windows forensic artefacts | Windows event logs (EVTX), MFT and other artefacts | Terminal tables, CSV or JSON | Command-line binary |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Sigma-based threat hunting and fast forensics timelines | Windows event logs | CSV or JSON timelines | Command-line binary |
| [Zircolite](https://github.com/wagga40/Zircolite) | Running Sigma rules over logs without a SIEM | EVTX, Sysmon for Linux, Auditd, JSON and other log formats | JSON or CSV, and templates for other tools | Python tool or binary |
| [TheHive](https://github.com/TheHive-Project/TheHive) | Case management and collaboration for real incident response | Alerts and observables from your stack | Cases through its API, MISP export, dashboards | Server deployment |
| [DFIR-IRIS](https://github.com/dfir-iris/iris-web) | Collaborative incident response case management | Your investigations and evidence | Cases through its API, report templates | Server deployment (Docker) |
| [Security Onion](https://github.com/Security-Onion-Solutions/securityonion) | Network and host monitoring, log management and threat hunting for real environments | Live network and host telemetry | Dashboards, alerts and cases | A Linux platform install with dedicated hardware |
| [Boss of the SOC (BOTS)](https://github.com/splunk/botsv3) | Capture-the-flag style blue team investigations over large recorded datasets | Pre-indexed Splunk datasets | Answers to scored questions | A Splunk instance |

SOC Shift uses synthetic data and a small estate, so it trains judgement and handover quality. Its exports let you carry a practice case into a TheHive or DFIR-IRIS lab, a threat intel platform that reads STIX, or ATT&CK Navigator. Use the tools above for real logs, real cases and real networks.

## Privacy

The shift, your verdicts, your notes, your observable settings and the variant seed stay in your browser's `localStorage`, one key per scenario. Nothing is uploaded and there is no analytics. Every export (TheHive, DFIR-IRIS, STIX, Navigator, NDJSON, Markdown) is built in the page and saved as a download; none of them is sent anywhere.

Live lookups run only when you press **Run live lookups** or **Look up**, and each sends only the indicator you chose, straight from your browser:

| Lookup | Service | Sends |
| --- | --- | --- |
| npm package | OSV (`api.osv.dev`) | the package name |
| IP owner | RDAP: the IANA bootstrap file (`data.iana.org`), then the regional registry it names (for example `rdap.arin.net`), with `rdap.org` as fallback | the IP address |
| Domain registration | RDAP, routed the same way | the domain |
| DNS A and NS | Cloudflare DNS over HTTPS (`cloudflare-dns.com`) | the domain |
| Tor relay or exit | Tor Project Onionoo (`onionoo.torproject.org`) | the IP address |
| CVE | CISA KEV catalogue from `raw.githubusercontent.com/cisagov/kev-data` | nothing: the whole catalogue is downloaded and searched locally |

Offline, each lookup fails on its own card and the rest of the shift keeps working.

### Which lookups return real data

Every person, host, customer and event in both scenarios is invented. Attacker infrastructure uses the documentation ranges `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`, internal and office addresses use `10.0.0.0/8` and `100.64.0.0/10`, and domains end in `.example`.

Kestrel Ledger keeps a few real public facts on purpose, so its live lookups return true answers:

- `ethersscan-api` is a real malicious npm package, [OSV MAL-2024-8847](https://osv.dev/vulnerability/MAL-2024-8847) (BeaverTail).
- `149.28.17.9` and `45.32.101.18` sit in a VPS provider's address space; RDAP shows the real network owner. The activity attributed to them is invented.
- The GitHub, LinkedIn and Bitbucket addresses in the baseline traffic are those services' public addresses.
- `nkbihfbeogaeaoehlefnkodbefgpgknn` is MetaMask's real Chrome Web Store extension id.

Larkspur Metrics has no real-world anchors. An RDAP lookup on its attacker addresses returns IANA's documentation reservation, which is the true answer for those ranges. Its autonomous system numbers come from the documentation range AS64496 to AS64511, and its application and session ids are invented.

## Repository layout

```
app/                          the static site GitHub Pages serves (no build)
  index.html
  css/desk.css
  js/engine.js                detections, correlations, pivots, tuning, handover, grading, variants, metrics, exports (browser and node)
  js/app.js                   the UI
  scenarios/index.js          scenario catalog
  scenarios/kestrel-ledger/scenario.js
  scenarios/larkspur-metrics/scenario.js
  vendor/                     js-yaml, sigma.js, intel.js, ATT&CK snapshot (versions in vendor/README.md)
docs/SCENARIOS.md             scenario authoring guide
docs/INSTRUCTORS.md           running a session, rubric, discussion questions, collecting results
docs/media/                   README media and the social preview image
test/run.mjs                  npm test
test/jsonschema.mjs           dependency-free JSON Schema validator
test/schemas/                 export schemas with their sources
tools/validate-scenario.mjs   scenario validator
tools/grade-verdicts.mjs      grades a learner's NDJSON export
tools/record-gif.py           records docs/media/soc-shift.gif with Playwright
tools/social-preview.py       renders docs/media/social-preview.png with Playwright
tools/sync-from-pwnsy.sh      refreshes the vendored files from a pwnsy checkout
```

## Roadmap

- A smaller scenario for first-time analysts (one log source, one true positive, clear noise).
- A scenario that crosses midnight UTC (the shift clock currently assumes one UTC date).
- More correlation types: threshold over a window, sequence of two rules on one entity.
- Scoring for incident fields and response actions, beside the verdict score.
- An in-page instructor view that loads learners' exports (`tools/grade-verdicts.mjs` does the verdict part from the command line).
- Optional Sigma rules from SigmaHQ in a scenario, with DRL 1.1 attribution.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md). Report security issues as described in [SECURITY.md](SECURITY.md). To cite SOC Shift, use [CITATION.cff](CITATION.cff).

## Licence and credits

MIT, see [LICENSE](LICENSE). Third-party notices are in [THIRD_PARTY.md](THIRD_PARTY.md).

- [js-yaml](https://github.com/nodeca/js-yaml) 4.1.0 (MIT) parses the Sigma YAML.
- MITRE ATT&CK® v19.2 technique names, © The MITRE Corporation, reproduced under MITRE's licence.
- sigma.js (the Sigma rule engine) and intel.js (the lookup adapters) come from [pwnsy.com](https://pwnsy.com) by the same author and are covered by this repository's MIT licence.
- The scenarios' Sigma rules are original to this project. No SigmaHQ rules are bundled.
- The OASIS STIX 2.1 JSON schemas in `test/schemas/stix2.1/` are BSD 3-Clause and used only by the tests.
- Lookups use public services run by OSV, IANA and the regional internet registries, Cloudflare, the Tor Project and CISA.
