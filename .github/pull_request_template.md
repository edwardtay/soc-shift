## What this changes

<!-- One or two lines. Link the issue if there is one. -->

## Checks

- [ ] `npm test` passes (Node 18 or later)
- [ ] `npm run validate` passes, or the new scenario passes `node tools/validate-scenario.mjs app/scenarios/<id> --seed 7 --seed 12345 --seed 31337`
- [ ] Events are synthetic: documentation or private addresses, `.example` domains, and any real public indicator listed in `anchors` with a note
- [ ] Sigma rules are original, or a SigmaHQ rule keeps its DRL 1.1 attribution and is listed in THIRD_PARTY.md
- [ ] UI changes checked at 1440 px and 390 px: light theme, 2px borders, text wraps at spaces, no horizontal scroll
- [ ] CHANGELOG.md updated under the next version

## For a new scenario

- [ ] Listed in `app/scenarios/index.js` and in the README scenarios table
- [ ] At least one hunt finds something no alert raised
- [ ] The answer key gives a reason for every alert
