# Security

SOC Shift is a static page. It has no server, no accounts and no stored secrets. The shift lives in the browser's localStorage, and live lookups send only the indicator the user chooses to public services listed in the README.

To report a vulnerability (for example script injection through a scenario field, or a lookup that sends more than the indicator), open a private advisory at https://github.com/edwardtay/soc-shift/security/advisories/new. Please include the browser, the steps and what you saw.

The scenario data is fictional. The few real indicators (an npm package flagged as malicious by OSV, two VPS addresses) are public facts used so lookups return true answers. Do not install the package.
