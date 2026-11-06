# Contributing

Scenarios, fixes and new correlation types are welcome. Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

1. Run `npm test` and `npm run validate` before opening a pull request. They need Node 18 or later and nothing else. The pull request template lists the rest of the checks.
2. A new scenario is a folder under `app/scenarios/` plus one line in `app/scenarios/index.js`, a row in the README scenarios table and its folder in the `validate` script. Follow [docs/SCENARIOS.md](docs/SCENARIOS.md) and run `node tools/validate-scenario.mjs app/scenarios/<id> --seed 7 --seed 12345 --seed 31337`.
3. Keep every event synthetic. Use documentation IP ranges and `.example` domains, and list any real public indicator in `anchors` with a note on what around it is invented.
4. Sigma rules you write are MIT licensed with the project. If you add a SigmaHQ rule, keep its DRL 1.1 attribution and list it in THIRD_PARTY.md.
5. UI changes: light theme, 2px borders on cards and controls, text wraps at spaces (no truncation), and check the page at 1440 px and 390 px wide with no horizontal scroll.
6. Copy: plain and short. No em or en dashes (`npm test` checks).
7. GitHub Actions are pinned to full commit SHAs with the release in a comment (`npm test` checks). Dependabot proposes updates.

`app/vendor/` is refreshed with `tools/sync-from-pwnsy.sh`; send engine fixes for `sigma.js` or `intel.js` as an issue so they land upstream too.
