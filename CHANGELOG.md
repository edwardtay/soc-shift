# Changelog

## 0.3.0 (2026-11-06)

- Second scenario, Larkspur Metrics (EMEA shift on Microsoft 365 and Entra ID): an adversary-in-the-middle phish steals a session, then a new MFA method, an inbox rule that hides replies, an OAuth consent for mail and fake bank-detail mail to two customers. 49 events, 6 original Sigma rules, 1 correlation, 15 alerts, 4 hunts, full answer key, carried-in case with a pending ticket, seeded variants. No real-world anchors.
- Engine: four new log shapes with summaries and entity extraction (Entra ID sign-in logs, Entra ID audit logs, the Microsoft 365 unified audit log, Defender for Office 365 email events), an `EMAIL` platform, and `email` and `app` (OAuth application) entities with built-in actions and TheHive, DFIR-IRIS and STIX mappings.
- Export validation in `npm test`: every STIX bundle, Navigator layer, TheHive case and DFIR-IRIS alert for both scenarios and seeds 0, 7, 12345 and 31337 is checked against JSON schemas in `test/schemas/` (the OASIS STIX 2.1 schemas, and schemas written from the Navigator 4.5 specification, thehive4py 2.1.0 and iris-web 2.4.29), with a dependency-free validator in `test/jsonschema.mjs`.
- `tools/grade-verdicts.mjs` grades a learner's NDJSON verdict export against the answer key for their seed.
- docs/INSTRUCTORS.md: session plan, seeds per learner, rubric, discussion questions per scenario, collecting results.
- Repository: code of conduct (Contributor Covenant 2.1), CITATION.cff, pull request template, Dependabot for GitHub Actions, OpenSSF Scorecard and CodeQL workflows pinned to full commit SHAs, least-privilege permissions on every workflow (Pages write scopes moved to the deploy job), and a test that checks all of it.
- `npm run validate` covers both scenarios and seeds 7, 12345 and 31337. The page's scenario picker lists both scenarios.
- README: badges, scenarios table, "Why trust the content", and a social preview image in docs/media.

## 0.2.0 (2026-11-06)

Ported from the SOC Shift Desk on pwnsy.com (pwnsy commits de87469 and 1619a01) into this repository's scenario format.

- Observables per incident with an IOC flag, TLP 2.0 (including AMBER+STRICT) and PAP, editable and saved with the shift.
- Incident exports: TheHive 5 case JSON (case, tasks, observables, alerts, ATT&CK procedures), DFIR-IRIS alert JSON (IOCs and assets) and a STIX 2.1 bundle (identity, indicators, sightings, attack-patterns, relationships, deterministic ids).
- Shift exports: an ATT&CK Navigator layer (format 4.5) and a STIX 2.1 bundle, beside the NDJSON verdicts and the Markdown handover.
- Shift timing on the Handover out tab: MTTD, MTTA, MTTR and time to first response from the shift clock. Opening an alert in the queue acknowledges it.
- Alert delays per platform, so Sigma alerts arrive after their first event the way a real pipeline delivers them.
- Seeded variants: `?seed=N` re-draws attacker addresses, workstation numbers and the customer id; the answer key follows.
- Scenario format: new optional `alertDelayMinutes` (and per-rule `delayMinutes`), `observables` and `variants` blocks, documented in docs/SCENARIOS.md.
- Validator: checks the new blocks, that every alert arrives inside the shift, and with `--seed N` that a variant re-draws one to one inside its pools and still passes every check.
- `npm test`: export shape checks against the thehive4py 2.x input types and the iris-backend schemas, STIX id, reference and pattern checks, Navigator layer checks, metric arithmetic, and seeds 7, 12345 and 31337 end to end.
- Vendored sigma.js updated to pwnsy 1619a01: Sigma 2.0 correlations and filters, backend conversion fixes, ATT&CK v19 tactics.

## 0.1.0 (2026-11-06)

First public release, extracted from the SOC Shift Desk on pwnsy.com.

- Eight-tab shift: handover in, alert queue, incidents, hunt, tuning with a regression check, IOC enrichment, handover out with a handover check, answer key.
- Kestrel Ledger scenario: 65 synthetic events over EDR, SSE, WAF, IdP and CloudTrail style sources, 7 Sigma rules, 2 correlations, 4 hunts, 12 alerts with an answer key.
- Scenario format: one folder per scenario with a catalog and a `?scenario=` switch; correlations are built-in types with parameters.
- `tools/validate-scenario.mjs`: rules compile, answer key matches the raised alerts, ATT&CK ids exist, timeline sorted, no real-looking personal data.
- Live lookups: OSV, RDAP, Cloudflare DNS over HTTPS, Tor Project Onionoo, CISA KEV. Each degrades on its own when offline.
- Verdict export as NDJSON.
- `npm test` with no dependencies; GitHub Actions for tests and GitHub Pages.
