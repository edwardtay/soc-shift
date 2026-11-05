# Third-party notices

SOC Shift is MIT licensed (see LICENSE). It bundles or uses the following.

## js-yaml 4.1.0

`app/vendor/js-yaml.min.js`, from https://github.com/nodeca/js-yaml. Used unmodified to parse Sigma YAML.

```
(The MIT License)

Copyright (C) 2011-2015 by Vitaly Puzrin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## MITRE ATT&CK® v19.2

`app/vendor/attack.json` holds technique and tactic ids and names derived from MITRE ATT&CK v19.2 (Enterprise), from https://github.com/mitre-attack/attack-stix-data. ATT&CK® is a registered trademark of The MITRE Corporation. The terms below are reproduced from that repository's LICENSE.txt.

```
License
-------
The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research,
development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce
MITRE's copyright designation and this license in any such copy.

"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

Disclaimers
-----------
MITRE does not claim ATT&CK enumerates all possibilities for the types of actions and behaviors documented as part
of its adversary model and framework of techniques. Using the information contained within ATT&CK to address or cover
full categories of techniques will not guarantee full defensive coverage as there may be undisclosed techniques or
variations on existing techniques not documented by ATT&CK.

ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE
ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS,
AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT
THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR
FITNESS FOR A PARTICULAR PURPOSE.
```

## sigma.js and intel.js

`app/vendor/sigma.js` (Sigma rule engine) and `app/vendor/intel.js` (public lookup adapters) are the author's own work from pwnsy.com, included here under this repository's MIT licence.

## Sigma rules

The Sigma rules, correlations and hunts in `app/scenarios/` are original to this project and MIT licensed with it. No rules from the SigmaHQ repository are bundled, so the Detection Rule License (DRL) does not apply. A scenario that adds SigmaHQ rules must keep their DRL 1.1 attribution (author and rule link) in the rule and list them here.

## Public services

Live lookups call public services from the user's browser: OSV (api.osv.dev), IANA RDAP bootstrap files and the regional internet registries' RDAP servers (with rdap.org as fallback), Cloudflare DNS over HTTPS, the Tor Project's Onionoo API, and CISA's Known Exploited Vulnerabilities catalogue from the cisagov/kev-data repository. Their data stays under their own terms.
