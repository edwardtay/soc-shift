# Export schemas

`npm test` validates every export SOC Shift builds (STIX 2.1 bundle, ATT&CK Navigator layer, TheHive case, DFIR-IRIS alerts) for every scenario on the original shift and on seeds 7, 12345 and 31337. The validator is `test/jsonschema.mjs`: dependency-free, draft 2020-12 semantics, only the keywords these files use. It throws on any other keyword, so a schema it cannot fully check fails the test.

| Folder | What it checks | Source | Version | Licence |
| --- | --- | --- | --- | --- |
| `stix2.1/` | The STIX 2.1 bundle against `common/bundle.json`, which resolves every SDO, SRO and SCO schema it references | [oasis-open/cti-stix2-json-schemas](https://github.com/oasis-open/cti-stix2-json-schemas), the `schemas/` folder copied unchanged | commit `9af1db41b7b86c06324f899649ae83480134f66e` (master, 2026-01-19) | BSD 3-Clause, kept in `stix2.1/LICENSE` |
| `navigator-layer-4.5/` | The ATT&CK Navigator layer | Written for this project from the property tables in [`layers/spec/v4.5/layerformat.md`](https://github.com/mitre-attack/attack-navigator/blob/734a1caba29fcd51f20b9ca239ce652b3354a47e/layers/spec/v4.5/layerformat.md) of mitre-attack/attack-navigator. MITRE publishes the layer format as a Markdown table and no JSON Schema | commit `734a1caba29fcd51f20b9ca239ce652b3354a47e` (2026-09-10) | MIT with this project. The specification it follows is Apache 2.0 |
| `thehive5/` | The TheHive case export: `InputCase` with tasks, `InputObservable`, `InputAlert`, `InputProcedure` | Written for this project from the TypedDicts in `thehive4py/types/` of [TheHive-Project/TheHive4py](https://github.com/TheHive-Project/TheHive4py) 2.1.0. TheHive publishes no JSON Schema. Severity, TLP and PAP codes follow TheHive 5's API documentation | tag `2.1.0`, commit `6a4765c39a65c328032343923de866ab4ad10127` | MIT with this project. thehive4py is MIT |
| `dfir-iris/` | Each DFIR-IRIS alert with its IOCs and assets | Written for this project from [dfir-iris/iris-web](https://github.com/dfir-iris/iris-web) v2.4.29: `source/app/models/alerts.py`, `source/app/models/models.py`, `source/app/schema/marshables.py`, and the default ids in `source/app/post_init.py`. DFIR-IRIS publishes no JSON Schema | tag `v2.4.29`, commit `340ce04080806a83837b713d01ea70632ee2b3f7` | MIT with this project. iris-web is LGPL 3.0; no iris-web code is copied |

The three written schemas reject properties their source does not define, so a misspelt field fails the test. Each records its source in a `$comment`.

To refresh the STIX schemas, copy `schemas/` from a newer commit of cti-stix2-json-schemas into `stix2.1/`, update the commit here, and run `npm test`.
