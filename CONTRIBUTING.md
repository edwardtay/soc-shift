# Contributing

Scenarios, fixes and new correlation types are welcome.

1. Run `npm test` before opening a pull request. It needs Node 18 or later and nothing else.
2. A new scenario is a folder under `app/scenarios/` plus one line in `app/scenarios/index.js`. Follow [docs/SCENARIOS.md](docs/SCENARIOS.md) and run `node tools/validate-scenario.mjs app/scenarios/<id>`.
3. Keep every event synthetic. Use documentation IP ranges and `.example` domains, and list any real public indicator in `anchors` with a note on what around it is invented.
4. Sigma rules you write are MIT licensed with the project. If you add a SigmaHQ rule, keep its DRL 1.1 attribution and list it in THIRD_PARTY.md.
5. UI changes: light theme, 2px borders on cards and controls, text wraps at spaces (no truncation), and check the page at 1440 px and 390 px wide with no horizontal scroll.
6. Copy: plain and short. No em or en dashes (`npm test` checks).

`app/vendor/` is refreshed with `tools/sync-from-pwnsy.sh`; send engine fixes for `sigma.js` or `intel.js` as an issue so they land upstream too.
