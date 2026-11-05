# Changelog

## 0.1.0 (2026-11-06)

First public release, extracted from the SOC Shift Desk on pwnsy.com.

- Eight-tab shift: handover in, alert queue, incidents, hunt, tuning with a regression check, IOC enrichment, handover out with a handover check, answer key.
- Kestrel Ledger scenario: 65 synthetic events over EDR, SSE, WAF, IdP and CloudTrail style sources, 7 Sigma rules, 2 correlations, 4 hunts, 12 alerts with an answer key.
- Scenario format: one folder per scenario with a catalog and a `?scenario=` switch; correlations are built-in types with parameters.
- `tools/validate-scenario.mjs`: rules compile, answer key matches the raised alerts, ATT&CK ids exist, timeline sorted, no real-looking personal data.
- Live lookups: OSV, RDAP, Cloudflare DNS over HTTPS, Tor Project Onionoo, CISA KEV. Each degrades on its own when offline.
- Verdict export as NDJSON.
- `npm test` with no dependencies; GitHub Actions for tests and GitHub Pages.
