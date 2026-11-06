# Running SOC Shift with a class

SOC Shift is a static page, so a class needs only a browser and the link. Each learner's shift stays in their own browser. Nothing reaches you unless they download an export and hand it in.

## Pick a scenario

| Scenario | Link | Estate and story | Alerts | Good for |
| --- | --- | --- | --- | --- |
| Kestrel Ledger | `?scenario=kestrel-ledger` | Crypto custody firm: macOS and Windows endpoints, a web proxy, a WAF, Okta and AWS CloudTrail. A fake take-home test drops an infostealer, a customer account is taken over, a session is replayed, a file goes to personal storage | 12 | Mixed telemetry, cloud keys, customer fraud, a carried MFA-fatigue case |
| Larkspur Metrics | `?scenario=larkspur-metrics` | SaaS company on Microsoft 365, Entra ID and Windows laptops. An adversary-in-the-middle phish steals a session, then an inbox rule, a new MFA method and an OAuth consent set up business email compromise | 15 | Identity-first incidents, Microsoft log fields, what survives a password reset |

Both start at the beginning of a nine-hour shift and carry in a handover with one open case and one pending ticket owned by another team.

## Give each learner a different seed

Add `&seed=N` to the link. The seed re-draws attacker addresses and host numbers (and the customer id in Kestrel Ledger), and the answer key follows. The attack and the right calls stay the same, but a learner who copies a neighbour's notes copies the wrong addresses.

- Use any whole number from 1 to 999999999. `seed=0` is the original shift.
- The same seed always gives the same variant, so keep a list of who had which seed. You need it to grade.
- A simple scheme: seed = 1000 + the learner's number on your roster.

Example: `https://edwardtay.github.io/soc-shift/?scenario=larkspur-metrics&seed=1007`

## Session plan

A 2-hour slot works for one scenario.

| Time | What happens |
| --- | --- |
| 0:00 to 0:10 | Brief. The company, the shift hours, the tabs. Tell them the answer key tab exists and that opening it before the end costs them the debrief |
| 0:10 to 0:20 | Handover in. Each learner reads the incoming handover and acknowledges it. Ask one person to say what is pending and who owns it |
| 0:20 to 1:20 | The shift. Learners move the clock themselves with +15 min and +1 h. Suggest they stay off **Jump to end** for the first 40 minutes so alerts arrive in order |
| 1:20 to 1:30 | Handover out. Each learner fixes what the handover check lists, then downloads their exports (below) |
| 1:30 to 1:40 | Answer key. Learners open tab 8 and compare |
| 1:40 to 2:00 | Debrief with the discussion questions below |

For a 90-minute slot, cut the shift to 45 minutes and tell learners which hunts to run.

## What to grade beyond the score

The score counts verdicts that match the key. True positive and escalate count as the same call. It says nothing about the work a SOC lead cares about most, so grade these too.

- **Handover quality.** Read the Markdown handover. Can the next shift act on each open incident without asking? Each one needs a one-line summary, a next action, an owner and a due time. Carried tickets stay named in the next action.
- **Verdict reasons.** A reason names the evidence: the field, the value and the time. "Looks fine" fails. "Parent is Intune AgentExecutor.exe signed by Microsoft, same script on two hosts in the same second" passes.
- **Tuning safety.** A tuning request must pass the regression check, which re-runs the rule over the lake and blocks any filter that drops a true positive. A good request also carries an expiry or a ticket. Credit a learner who leaves a rule untuned on purpose and says why.
- **Response order and ownership.** Actions the SOC owns are taken during the shift. Actions another team owns stay pending and appear in the handover with the owner named.
- **Hunting.** Each scenario has a hunt that finds what no alert raised. A learner who found it and added the hits to an incident has done the most valuable thing on the shift.

## Rubric

Score each row 0, 1 or 2. Total out of 14, beside the verdict score.

| Area | 0 | 1 | 2 |
| --- | --- | --- | --- |
| Verdicts | Under half match the key | Most match; a true positive missed or closed as noise | All true positives found; at most one noise call differs, with a sound reason |
| Reasons | Missing or generic | Name the evidence on some alerts | Every closed alert names the field, value and time that decided it |
| Incidents | Alerts not grouped, or one incident per alert | Grouped, some fields missing | Grouped by attack, each with summary, next action, owner, due time; the carried case is updated |
| Response | No actions, or wrong entity | Main actions taken, ownership unclear | Containment in a sensible order; other teams' actions pending with owners; IR lead notified for critical |
| Hunting | No hunt run | Hunts run, hits left unlinked | The unalerted finding added to an incident and reflected in the handover |
| Tuning | A filter that drops a true positive, or none considered | A safe filter without expiry or reason | A safe filter with a ticket or expiry, or a stated reason to leave a rule alone |
| Handover | Handover check shows high items | Medium or low items remain | Check is clean and a reader could take over in five minutes |

## Collecting results

Ask each learner to download from the **Handover out** tab and hand in:

1. **Handover (Markdown)**: what you read for the rubric.
2. **Verdicts (NDJSON)**: one JSON line per closed alert, with verdict, severity, reason, incident and close time.
3. Optional: the **ATT&CK Navigator layer** and the **STIX 2.1 bundle**, and from the Incidents tab the **TheHive case** or **DFIR-IRIS alerts** if your course goes on to a case-management lab.

Name files `<name>-<seed>-verdicts.ndjson` and `<name>-<seed>-handover.md` so the seed travels with the work.

Grade the verdict files from a clone of this repository (Node 18 or later, nothing to install):

```sh
node tools/grade-verdicts.mjs app/scenarios/larkspur-metrics --seed 1007 alex-1007-verdicts.ndjson
```

It prints the score, each miss with the key's verdict, alerts left untriaged, and verdicts without a usable reason. If it reports alert ids it does not know, the seed is wrong. Every learner with a different seed needs their own run.

To compare a class on one question, for example who closed the session replay as benign, merge the NDJSON files:

```sh
cat *-verdicts.ndjson | grep '"C-ENT-001|' | node -e 'require("readline").createInterface({input:process.stdin}).on("line",l=>{const o=JSON.parse(l);console.log(o.alert_id,o.verdict,o.reason)})'
```

## Discussion questions

### Kestrel Ledger

1. The npm package alert came from a take-home test sent over LinkedIn. Which secrets on the laptop do you rotate first, and who owns each one?
2. H-01 found the stolen AWS key used from a VPS, and no alert fired. What rule would catch it, and what noise would that rule bring?
3. l.chen changed the password at 04:12 and the stolen session kept working. What ends a session, and where is that action in the desk?
4. The scanner exception is scoped to a change window. What goes wrong with a permanent allowlist for 10.20.0.15?
5. The customer takeover needs Fraud and Support. What does the SOC hand them, and what stays with the SOC?
6. CASE-1187 came in with IT-5521 pending and the push source attacked again. How should the handover have been written to make that obvious?

### Larkspur Metrics

1. APAC asked for the block and purge (MSG-118) at 05:50 and it was still pending when the second wave landed at 07:48. What should the 07:00 check have done?
2. Put the containment steps for d.moreau in order: revoke sessions, block sign-in, reset the password, remove the attacker's authenticator, remove the inbox rule, revoke the app grant. Which of these does a password reset alone leave in place?
3. s.ito's session and d.moreau's session each appeared from two networks. Which fields make one benign and the other a theft?
4. The HTML-attachment rule cannot be tuned automatically because the bank's secure message and the lure look the same to it. How would you change the rule?
5. A user could consent to Mail.ReadWrite and Mail.Send. Which tenant setting allowed it, who owns that change, and how do you raise it in a handover?
6. H-01 shows mail sent to two customers asking them to pay a new account. Who calls them, how soon, and what do you tell Legal?
7. a.lindqvist opened the lure and reached the proxy, and no sign-in followed. Is a password reset still worth it? What else would you check?
