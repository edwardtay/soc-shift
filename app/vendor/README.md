# Vendored files

Served as they are. No build step, no package manager.

| File | Version | Source | Licence |
| --- | --- | --- | --- |
| js-yaml.min.js | 4.1.0 | https://github.com/nodeca/js-yaml | MIT |
| sigma.js | pwnsy commit 1619a01 (2026-11-06) | pwnsy.com tools/detect/sigma.js, same author | MIT (this repository) |
| intel.js | pwnsy commit 1619a01 (2026-11-06) | pwnsy.com tools/lib/intel.js, same author | MIT (this repository) |
| attack.json | MITRE ATT&CK v19.2 (modified 2026-07-31) | derived from https://github.com/mitre-attack/attack-stix-data | MITRE ATT&CK terms, see THIRD_PARTY.md |

intel.js exposes `window.PwnsyIntel`. SOC Shift uses its RDAP, DNS over HTTPS, Onionoo, OSV and KEV adapters. Its `pwnsyIp` adapter calls an API that answers only pwnsy.com, so SOC Shift does not use it.

Refresh with `tools/sync-from-pwnsy.sh <path to a pwnsy checkout>`.
