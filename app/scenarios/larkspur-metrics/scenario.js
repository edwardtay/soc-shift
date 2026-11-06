/* Scenario: Larkspur Metrics, EMEA shift, 2026-11-12.
   Larkspur Metrics is a fictional SaaS company and every event below is synthetic.
   No real-world anchors: attacker addresses use the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
   internal and office addresses use 100.64.0.0/10, autonomous system numbers use the documentation range (AS64496 to AS64511),
   every domain ends in .example and every GUID is invented.
   Field names follow the published schemas of Microsoft Entra ID sign-in and audit logs, the Microsoft 365 unified audit log,
   Defender for Office 365 email events and Defender for Endpoint device events.
   Format: docs/SCENARIOS.md. Check with: node tools/validate-scenario.mjs app/scenarios/larkspur-metrics */
(function (root) {
  "use strict";

  var scenario = {
    schema: 1,
    id: "larkspur-metrics",
    title: "Larkspur Metrics SOC",
    subtitle: "Sample estate (fictional): 7 accounts, 6 Windows laptops, Microsoft 365 and Entra ID, 5 log sources",
    summary: "A nine-hour EMEA shift at a fictional SaaS company on Microsoft 365: an adversary-in-the-middle phish steals a session, then an inbox rule, a new MFA method and an OAuth consent set up business email compromise. Noise from a printer, a traveller, a new joiner and an approved admin consent.",
    level: "intermediate",

    estate: {
      company: "Larkspur Metrics (fictional)",
      shift: { name: "EMEA", startUtc: "06:00", endUtc: "15:00", local: "07:00 to 16:00 CET", from: "APAC", to: "AMER", date: "2026-11-12" },
      corpEgress: ["100.64.40.0/24", "100.64.41.0/24"],
      users: {
        "d.moreau": { name: "D. Moreau", dept: "Accounts receivable", host: "LM-WIN-0217", os: "Windows 11", region: "Amsterdam", usualAsn: "AS64497 (Amsterdam office)" },
        "k.osei": { name: "K. Osei", dept: "Head of finance", host: "LM-WIN-0188", os: "Windows 11", region: "Amsterdam", usualAsn: "AS64497 (Amsterdam office)" },
        "a.lindqvist": { name: "A. Lindqvist", dept: "Marketing", host: "LM-WIN-0230", os: "Windows 11", region: "Manchester", usualAsn: "AS64498 (Manchester office)" },
        "s.ito": { name: "S. Ito", dept: "Sales", host: "LM-WIN-0144", os: "Windows 11", region: "London, travels", usualAsn: "AS64499 (home broadband)" },
        "r.varga": { name: "R. Varga", dept: "IT operations (Entra administrator)", host: "LM-WIN-0009", os: "Windows 11", region: "Amsterdam", usualAsn: "AS64497 (Amsterdam office)", privileged: true },
        "n.adeyemi": { name: "N. Adeyemi", dept: "Customer success (starts today)", host: "LM-WIN-0301", os: "Windows 11", region: "Manchester", usualAsn: "AS64498 (Manchester office)" },
        "svc-scan": { name: "Scan-to-email service account", dept: "Manchester office printer", host: "MAN-MFP-02", os: "Printer firmware", region: "Manchester", usualAsn: "AS64498 (Manchester office)" }
      },
      hosts: {
        "LM-WIN-0217": { owner: "d.moreau", os: "Windows 11 24H2", role: "Finance laptop", edr: "online" },
        "LM-WIN-0188": { owner: "k.osei", os: "Windows 11 24H2", role: "Finance laptop", edr: "online" },
        "LM-WIN-0230": { owner: "a.lindqvist", os: "Windows 11 24H2", role: "Marketing laptop", edr: "online" },
        "LM-WIN-0144": { owner: "s.ito", os: "Windows 11 24H2", role: "Sales laptop", edr: "online" },
        "LM-WIN-0009": { owner: "r.varga", os: "Windows 11 24H2", role: "IT admin laptop", edr: "online" },
        "LM-WIN-0301": { owner: "n.adeyemi", os: "Windows 11 24H2", role: "Customer success laptop (new)", edr: "online" },
        "MAN-MFP-02": { owner: "svc-scan", os: "Printer firmware", role: "Multifunction printer, scan to email", edr: "not supported" }
      },
      apps: { "larkspur.example": "Corporate domain and mail", "app.larkspur.example": "Larkspur Metrics product (SaaS)" }
    },

    /* teams an incident or a pending action can be handed to */
    owners: ["EMEA SOC", "AMER SOC (next shift)", "APAC SOC", "IR lead", "IT service desk", "Identity and access", "Messaging team", "Finance", "Legal and privacy"],

    /* office egress addresses every user shares: too common to link alerts on */
    noisyEntities: ["100.64.40.10", "100.64.41.10", "larkspur.example"],

    /* no real-world anchors in this scenario */
    anchors: {
      ips: [],
      notes: "Every person, company, domain, address, application id and event at Larkspur Metrics is invented. Attacker addresses sit in documentation ranges, so an RDAP lookup on them returns the IANA reservation. Log fields follow Microsoft's published schemas."
    },

    /* minutes from an alert's first event to the queue: streaming EDR in a minute, Defender for Office 365 in two,
       scheduled SIEM analytics on a five-minute cadence. Correlations arrive at the event that completes them. */
    alertDelayMinutes: { EDR: 1, EMAIL: 2, SIEM: 5 },

    /* response actions for this tenant: Entra ID and Exchange Online, some owned by other teams */
    actions: {
      user: [
        { id: "revoke", label: "Revoke sign-in sessions (Entra)", platform: "Entra ID", self: true, effect: "Refresh tokens and session cookies invalidated; the user signs in again." },
        { id: "disable", label: "Block sign-in", platform: "Entra ID", self: true, effect: "Account blocked until the service desk re-enables it." },
        { id: "inbox-rules", label: "Export and remove inbox rules", platform: "Exchange Online", self: true, effect: "Rules exported to the case, then removed." },
        { id: "reset", label: "Reset password and remove MFA methods", platform: "Entra ID", owner: "IT service desk", effect: "Service desk verifies the user on a video call, resets the password and re-registers MFA." }
      ],
      app: [{ id: "disable-app", label: "Revoke grants and disable the app", platform: "Entra ID", owner: "Identity and access", effect: "OAuth grants removed and the service principal disabled tenant-wide." }],
      email: [{ id: "block-sender", label: "Block sender and purge the campaign", platform: "Exchange Online", self: true, effect: "Sender and domain on the tenant block list; delivered copies removed." }],
      ip: [{ id: "block-ca", label: "Block in Conditional Access", platform: "Entra ID", self: true, effect: "Address added to a blocked named location." }],
      session: [{ id: "revoke-session", label: "Revoke this session", platform: "Entra ID", self: true, effect: "Session invalidated." }]
    },

    /* observable defaults for the case exports: values that are never IOCs */
    observables: {
      notIoc: ["larkspur.example", "harbourbank.example", "harborline.example", "quillmart.example", "fenwick-audit.example", "trendwire.example", "1b9e4c7d-6a2f-4d38-b5e1-0c7f2a9d4e63", "SecureMessage.html"],
      external: { tlp: "GREEN", pap: "AMBER" },
      internal: { tlp: "AMBER+STRICT", pap: "RED" }
    },

    /* ?seed=N re-draws these: attacker and traveller addresses inside the documentation ranges, and laptop numbers */
    variants: {
      ipPools: ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
      idPools: [{ prefixes: ["LM-WIN-"], digits: 4 }]
    },

    enrichExamples: ["203.0.113.90", "198.51.100.61", "auth.larkspur-docs.example", "northpay-remit.example"],

    /* the carried-in handover from the previous shift */
    handoverIn: {
      from: "APAC", analyst: "APAC analyst on duty", at: "2026-11-12T05:58:00Z",
      summary: "Quiet shift. One phish reported by a user, block and purge requested from the Messaging team. A change and a new joiner land on your shift.",
      items: [
        { case: "CASE-2093", kind: "case", title: "Remittance-advice phish reported by s.ito", severity: "medium", status: "open",
          done: "s.ito reported 'Remittance advice 88231 for Larkspur Metrics' from billing@northpay-remit.example (192.0.2.140) at 05:31. HTML attachment pointing at auth.larkspur-docs.example. s.ito did not open it. Requested a tenant block and a campaign purge from the Messaging team as MSG-118 at 05:50.",
          next: "Confirm MSG-118 (block and purge) is done before EMEA staff log in. Check for other recipients.",
          owner: "EMEA", due: "07:00 UTC", pending: "MSG-118 block and purge (Messaging team)",
          ticket: "MSG-118",
          pendingAction: { entity: "email:billing@northpay-remit.example", action: "block-sender", label: "Tenant block and campaign purge (MSG-118)", platform: "Exchange Online", owner: "Messaging team" } },
        { case: "WATCH", kind: "watch", title: "Admin consent for Brightdesk Scheduler (CHG-4410)", severity: "info", status: "watch",
          done: "CHG-4410 approved: r.varga grants tenant-wide consent to Brightdesk Scheduler between 09:00 and 10:00 UTC.",
          next: "Expect one admin consent from r.varga from the Amsterdam office in that window. Any other consent is not covered.", owner: "EMEA", due: "10:00 UTC" },
        { case: "WATCH", kind: "watch", title: "New joiner n.adeyemi starts today (HR-5120)", severity: "info", status: "watch",
          done: "Account created by IT, temporary access pass issued.",
          next: "Expect a first sign-in and MFA registration from the Manchester office this morning.", owner: "EMEA", due: "12:00 UTC" }
      ],
      watch: [
        "192.0.2.140 and northpay-remit.example: phish sender in CASE-2093",
        "svc-scan (Manchester printer) fails SMTP sign-in every 30 minutes since its password expired; IT-7713 open",
        "CHG-4410: r.varga admin consent to Brightdesk Scheduler, 09:00 to 10:00 UTC only",
        "s.ito travels to Dublin today for a customer visit"
      ],
      metrics: { alerts: 9, tp: 1, fp: 5, benign: 3, escalated: 0 }
    },

    /* event lake: one record per line, sorted by _t. _src picks the log shape, _t is the UTC time. */
    events: [
    {"_src":"email","_t":"2026-11-05T06:40:12Z","Timestamp":"2026-11-05T06:40:12Z","EmailDirection":"Inbound","DeliveryAction":"Delivered","DeliveryLocation":"Inbox/folder","SenderFromAddress":"securemail@notify.harbourbank.example","SenderFromDomain":"notify.harbourbank.example","SenderIPv4":"198.51.100.20","RecipientEmailAddress":"k.osei@larkspur.example","Subject":"Secure message from Harbour Bank","AuthenticationDetails":"{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\"}","ThreatTypes":"","AttachmentCount":1,"FileName":"SecureMessage.html","FileType":"html","Url":"https://securemail.harbourbank.example/open"},
    {"_src":"signin","_t":"2026-11-12T05:05:02Z","TimeGenerated":"2026-11-12T05:05:02Z","UserPrincipalName":"svc-scan@larkspur.example","AppDisplayName":"Office 365 Exchange Online","ClientAppUsed":"Authenticated SMTP","IPAddress":"100.64.41.10","AutonomousSystemNumber":64498,"Location":"GB","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"email","_t":"2026-11-12T05:12:04Z","Timestamp":"2026-11-12T05:12:04Z","EmailDirection":"Inbound","DeliveryAction":"Delivered","DeliveryLocation":"Inbox/folder","SenderFromAddress":"billing@northpay-remit.example","SenderFromDomain":"northpay-remit.example","SenderIPv4":"192.0.2.140","RecipientEmailAddress":"s.ito@larkspur.example","Subject":"Remittance advice 88231 for Larkspur Metrics","AuthenticationDetails":"{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\"}","ThreatTypes":"","AttachmentCount":1,"FileName":"Remittance_88231.html","FileType":"html","Url":"https://auth.larkspur-docs.example/common/oauth2/v2.0/authorize"},
    {"_src":"signin","_t":"2026-11-12T05:35:02Z","TimeGenerated":"2026-11-12T05:35:02Z","UserPrincipalName":"svc-scan@larkspur.example","AppDisplayName":"Office 365 Exchange Online","ClientAppUsed":"Authenticated SMTP","IPAddress":"100.64.41.10","AutonomousSystemNumber":64498,"Location":"GB","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T05:40:11Z","TimeGenerated":"2026-11-12T05:40:11Z","UserPrincipalName":"s.ito@larkspur.example","AppDisplayName":"OfficeHome","ClientAppUsed":"Browser","IPAddress":"192.0.2.30","AutonomousSystemNumber":64499,"Location":"GB","ResultType":0,"ResultDescription":"","SessionId":"4e7b2c19-8d3a-4f61-b0c5-91a2e6d7f308","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0","AuthenticationRequirement":"multiFactorAuthentication","AuthenticationDetails":[{"authenticationMethod":"Password","succeeded":true},{"authenticationMethod":"Mobile app notification","succeeded":true,"authenticationStepResultDetail":"MFA successfully completed"}],"ConditionalAccessStatus":"success","DeviceDetail":{"displayName":"LM-WIN-0144","deviceId":"0b6d2e81-4f3c-4a97-8e25-c1d9a7f03b64","operatingSystem":"Windows10","browser":"Edge 130.0","isCompliant":true,"trustType":"Azure AD joined"},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:05:02Z","TimeGenerated":"2026-11-12T06:05:02Z","UserPrincipalName":"svc-scan@larkspur.example","AppDisplayName":"Office 365 Exchange Online","ClientAppUsed":"Authenticated SMTP","IPAddress":"100.64.41.10","AutonomousSystemNumber":64498,"Location":"GB","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:12:31Z","TimeGenerated":"2026-11-12T06:12:31Z","UserPrincipalName":"d.moreau@larkspur.example","AppDisplayName":"OfficeHome","ClientAppUsed":"Browser","IPAddress":"100.64.40.10","AutonomousSystemNumber":64497,"Location":"NL","ResultType":0,"ResultDescription":"","SessionId":"a1c95e40-7f2b-4d86-9e13-5b0d8c2f4a71","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0","AuthenticationRequirement":"multiFactorAuthentication","AuthenticationDetails":[{"authenticationMethod":"Password","succeeded":true},{"authenticationMethod":"Mobile app notification","succeeded":true,"authenticationStepResultDetail":"MFA successfully completed"}],"ConditionalAccessStatus":"success","DeviceDetail":{"displayName":"LM-WIN-0217","deviceId":"7a3c9e15-2b8d-4f60-a4e7-d05b1c8f9e23","operatingSystem":"Windows10","browser":"Edge 130.0","isCompliant":true,"trustType":"Azure AD joined"},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:18:44Z","TimeGenerated":"2026-11-12T06:18:44Z","UserPrincipalName":"k.osei@larkspur.example","AppDisplayName":"OfficeHome","ClientAppUsed":"Browser","IPAddress":"100.64.40.10","AutonomousSystemNumber":64497,"Location":"NL","ResultType":0,"ResultDescription":"","SessionId":"2f8d4a61-c93e-4b07-a5d2-7e1b0c9f6384","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0","AuthenticationRequirement":"multiFactorAuthentication","AuthenticationDetails":[{"authenticationMethod":"Password","succeeded":true},{"authenticationMethod":"Mobile app notification","succeeded":true,"authenticationStepResultDetail":"MFA successfully completed"}],"ConditionalAccessStatus":"success","DeviceDetail":{"displayName":"LM-WIN-0188","deviceId":"c84f1d07-9e6a-4b23-b5c8-2a7e0f3d91b6","operatingSystem":"Windows10","browser":"Edge 130.0","isCompliant":true,"trustType":"Azure AD joined"},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:24:09Z","TimeGenerated":"2026-11-12T06:24:09Z","UserPrincipalName":"a.lindqvist@larkspur.example","AppDisplayName":"OfficeHome","ClientAppUsed":"Browser","IPAddress":"100.64.41.10","AutonomousSystemNumber":64498,"Location":"GB","ResultType":0,"ResultDescription":"","SessionId":"9b3e7d25-1a4c-4f98-8c06-d2e5f7a1b490","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0","AuthenticationRequirement":"multiFactorAuthentication","AuthenticationDetails":[{"authenticationMethod":"Password","succeeded":true},{"authenticationMethod":"Mobile app notification","succeeded":true,"authenticationStepResultDetail":"MFA successfully completed"}],"ConditionalAccessStatus":"success","DeviceDetail":{"displayName":"LM-WIN-0230","deviceId":"5e2a8c46-0d7f-4b91-9a3e-f61c4b8d2075","operatingSystem":"Windows10","browser":"Edge 130.0","isCompliant":true,"trustType":"Azure AD joined"},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:30:05Z","TimeGenerated":"2026-11-12T06:30:05Z","UserPrincipalName":"k.osei@larkspur.example","AppDisplayName":"Microsoft Office","ClientAppUsed":"Mobile Apps and Desktop clients","IPAddress":"192.0.2.201","AutonomousSystemNumber":64510,"Location":"BR","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","UserAgent":"python-requests/2.32","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:31:40Z","TimeGenerated":"2026-11-12T06:31:40Z","UserPrincipalName":"r.varga@larkspur.example","AppDisplayName":"Microsoft Office","ClientAppUsed":"Mobile Apps and Desktop clients","IPAddress":"192.0.2.201","AutonomousSystemNumber":64510,"Location":"BR","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","UserAgent":"python-requests/2.32","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:33:12Z","TimeGenerated":"2026-11-12T06:33:12Z","UserPrincipalName":"d.moreau@larkspur.example","AppDisplayName":"Microsoft Office","ClientAppUsed":"Mobile Apps and Desktop clients","IPAddress":"192.0.2.201","AutonomousSystemNumber":64510,"Location":"BR","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","UserAgent":"python-requests/2.32","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:34:50Z","TimeGenerated":"2026-11-12T06:34:50Z","UserPrincipalName":"a.lindqvist@larkspur.example","AppDisplayName":"Microsoft Office","ClientAppUsed":"Mobile Apps and Desktop clients","IPAddress":"192.0.2.201","AutonomousSystemNumber":64510,"Location":"BR","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","UserAgent":"python-requests/2.32","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:35:02Z","TimeGenerated":"2026-11-12T06:35:02Z","UserPrincipalName":"svc-scan@larkspur.example","AppDisplayName":"Office 365 Exchange Online","ClientAppUsed":"Authenticated SMTP","IPAddress":"100.64.41.10","AutonomousSystemNumber":64498,"Location":"GB","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:36:21Z","TimeGenerated":"2026-11-12T06:36:21Z","UserPrincipalName":"s.ito@larkspur.example","AppDisplayName":"Microsoft Office","ClientAppUsed":"Mobile Apps and Desktop clients","IPAddress":"192.0.2.201","AutonomousSystemNumber":64510,"Location":"BR","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","UserAgent":"python-requests/2.32","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:38:02Z","TimeGenerated":"2026-11-12T06:38:02Z","UserPrincipalName":"n.adeyemi@larkspur.example","AppDisplayName":"Microsoft Office","ClientAppUsed":"Mobile Apps and Desktop clients","IPAddress":"192.0.2.201","AutonomousSystemNumber":64510,"Location":"BR","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","UserAgent":"python-requests/2.32","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T06:40:27Z","TimeGenerated":"2026-11-12T06:40:27Z","UserPrincipalName":"r.varga@larkspur.example","AppDisplayName":"OfficeHome","ClientAppUsed":"Browser","IPAddress":"100.64.40.10","AutonomousSystemNumber":64497,"Location":"NL","ResultType":0,"ResultDescription":"","SessionId":"71d4f0a8-5e93-4c2b-9f61-a8b3d7e0c215","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0","AuthenticationRequirement":"multiFactorAuthentication","AuthenticationDetails":[{"authenticationMethod":"Password","succeeded":true},{"authenticationMethod":"FIDO2 security key","succeeded":true,"authenticationStepResultDetail":"MFA successfully completed"}],"ConditionalAccessStatus":"success","DeviceDetail":{"displayName":"LM-WIN-0009","deviceId":"f3b07c92-6e1d-4a58-8b24-9d6c2e5a0f17","operatingSystem":"Windows10","browser":"Edge 130.0","isCompliant":true,"trustType":"Azure AD joined"},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"email","_t":"2026-11-12T06:41:15Z","Timestamp":"2026-11-12T06:41:15Z","EmailDirection":"Inbound","DeliveryAction":"Delivered","DeliveryLocation":"Inbox/folder","SenderFromAddress":"securemail@notify.harbourbank.example","SenderFromDomain":"notify.harbourbank.example","SenderIPv4":"198.51.100.20","RecipientEmailAddress":"k.osei@larkspur.example","Subject":"Secure message from Harbour Bank","AuthenticationDetails":"{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\"}","ThreatTypes":"","AttachmentCount":1,"FileName":"SecureMessage.html","FileType":"html","Url":"https://securemail.harbourbank.example/open"},
    {"_src":"edr","_t":"2026-11-12T06:52:08Z","Timestamp":"2026-11-12T06:52:08","DeviceName":"LM-WIN-0188","AccountName":"k.osei","ActionType":"ProcessCreated","FileName":"msedge.exe","FolderPath":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","ProcessCommandLine":"\"msedge.exe\" --single-argument C:\\Users\\k.osei\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\R4T7NB2C\\SecureMessage.html","InitiatingProcessFileName":"OUTLOOK.EXE","InitiatingProcessFolderPath":"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE","InitiatingProcessSigner":"Microsoft Corporation"},
    {"_src":"signin","_t":"2026-11-12T07:05:02Z","TimeGenerated":"2026-11-12T07:05:02Z","UserPrincipalName":"svc-scan@larkspur.example","AppDisplayName":"Office 365 Exchange Online","ClientAppUsed":"Authenticated SMTP","IPAddress":"100.64.41.10","AutonomousSystemNumber":64498,"Location":"GB","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T07:35:02Z","TimeGenerated":"2026-11-12T07:35:02Z","UserPrincipalName":"svc-scan@larkspur.example","AppDisplayName":"Office 365 Exchange Online","ClientAppUsed":"Authenticated SMTP","IPAddress":"100.64.41.10","AutonomousSystemNumber":64498,"Location":"GB","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"email","_t":"2026-11-12T07:48:10Z","Timestamp":"2026-11-12T07:48:10Z","EmailDirection":"Inbound","DeliveryAction":"Delivered","DeliveryLocation":"Inbox/folder","SenderFromAddress":"billing@northpay-remit.example","SenderFromDomain":"northpay-remit.example","SenderIPv4":"192.0.2.140","RecipientEmailAddress":"d.moreau@larkspur.example","Subject":"Remittance advice 88231 for Larkspur Metrics","AuthenticationDetails":"{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\"}","ThreatTypes":"","AttachmentCount":1,"FileName":"Remittance_88231.html","FileType":"html","Url":"https://auth.larkspur-docs.example/common/oauth2/v2.0/authorize"},
    {"_src":"email","_t":"2026-11-12T07:48:11Z","Timestamp":"2026-11-12T07:48:11Z","EmailDirection":"Inbound","DeliveryAction":"Delivered","DeliveryLocation":"Inbox/folder","SenderFromAddress":"billing@northpay-remit.example","SenderFromDomain":"northpay-remit.example","SenderIPv4":"192.0.2.140","RecipientEmailAddress":"a.lindqvist@larkspur.example","Subject":"Remittance advice 88231 for Larkspur Metrics","AuthenticationDetails":"{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\"}","ThreatTypes":"","AttachmentCount":1,"FileName":"Remittance_88231.html","FileType":"html","Url":"https://auth.larkspur-docs.example/common/oauth2/v2.0/authorize"},
    {"_src":"email","_t":"2026-11-12T07:48:12Z","Timestamp":"2026-11-12T07:48:12Z","EmailDirection":"Inbound","DeliveryAction":"Delivered","DeliveryLocation":"Inbox/folder","SenderFromAddress":"billing@northpay-remit.example","SenderFromDomain":"northpay-remit.example","SenderIPv4":"192.0.2.140","RecipientEmailAddress":"k.osei@larkspur.example","Subject":"Remittance advice 88231 for Larkspur Metrics","AuthenticationDetails":"{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\"}","ThreatTypes":"","AttachmentCount":1,"FileName":"Remittance_88231.html","FileType":"html","Url":"https://auth.larkspur-docs.example/common/oauth2/v2.0/authorize"},
    {"_src":"edr","_t":"2026-11-12T08:01:30Z","Timestamp":"2026-11-12T08:01:30","DeviceName":"LM-WIN-0217","AccountName":"d.moreau","ActionType":"ProcessCreated","FileName":"msedge.exe","FolderPath":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","ProcessCommandLine":"\"msedge.exe\" --single-argument C:\\Users\\d.moreau\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\8K2QX1ZP\\Remittance_88231.html","InitiatingProcessFileName":"OUTLOOK.EXE","InitiatingProcessFolderPath":"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE","InitiatingProcessSigner":"Microsoft Corporation"},
    {"_src":"edr","_t":"2026-11-12T08:01:36Z","Timestamp":"2026-11-12T08:01:36","DeviceName":"LM-WIN-0217","AccountName":"d.moreau","ActionType":"ConnectionSuccess","FileName":"msedge.exe","InitiatingProcessFileName":"msedge.exe","RemoteIP":"203.0.113.90","RemotePort":443,"RemoteUrl":"auth.larkspur-docs.example","BytesSent":5120},
    {"_src":"signin","_t":"2026-11-12T08:03:40Z","TimeGenerated":"2026-11-12T08:03:40Z","UserPrincipalName":"d.moreau@larkspur.example","AppDisplayName":"OfficeHome","ClientAppUsed":"Browser","IPAddress":"203.0.113.90","AutonomousSystemNumber":64505,"Location":"NL","ResultType":0,"ResultDescription":"","SessionId":"c7e21f9a-3b64-4d0e-8a52-f19d06b7e3c4","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0","AuthenticationRequirement":"multiFactorAuthentication","AuthenticationDetails":[{"authenticationMethod":"Password","succeeded":true},{"authenticationMethod":"Mobile app notification","succeeded":true,"authenticationStepResultDetail":"MFA successfully completed"}],"ConditionalAccessStatus":"success","DeviceDetail":{"operatingSystem":"Windows10","browser":"Edge 130.0","isCompliant":false},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T08:04:10Z","TimeGenerated":"2026-11-12T08:04:10Z","UserPrincipalName":"n.adeyemi@larkspur.example","AppDisplayName":"My Signins","ClientAppUsed":"Browser","IPAddress":"100.64.41.10","AutonomousSystemNumber":64498,"Location":"GB","ResultType":0,"ResultDescription":"","SessionId":"e05c8b37-6d21-4a9f-b7e4-3c1f9a2d8056","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0","AuthenticationRequirement":"multiFactorAuthentication","AuthenticationDetails":[{"authenticationMethod":"Temporary Access Pass","succeeded":true,"authenticationStepResultDetail":"MFA successfully completed"}],"ConditionalAccessStatus":"success","DeviceDetail":{"displayName":"LM-WIN-0301","deviceId":"18e6a4c3-7b2f-4d09-a5e1-6c3d8f0b2a97","operatingSystem":"Windows10","browser":"Edge 130.0","isCompliant":true,"trustType":"Azure AD joined"},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"signin","_t":"2026-11-12T08:05:02Z","TimeGenerated":"2026-11-12T08:05:02Z","UserPrincipalName":"svc-scan@larkspur.example","AppDisplayName":"Office 365 Exchange Online","ClientAppUsed":"Authenticated SMTP","IPAddress":"100.64.41.10","AutonomousSystemNumber":64498,"Location":"GB","ResultType":50126,"ResultDescription":"Invalid username or password or Invalid on-premise username or password.","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"notApplied","DeviceDetail":{},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"entraaudit","_t":"2026-11-12T08:05:30Z","TimeGenerated":"2026-11-12T08:05:30Z","OperationName":"User registered security info","Category":"UserManagement","Result":"success","ResultReason":"User registered Authenticator App with Notification and Code","LoggedByService":"Authentication Methods","InitiatedBy":{"user":{"userPrincipalName":"n.adeyemi@larkspur.example","ipAddress":"100.64.41.10"}},"TargetResources":[{"type":"User","displayName":"N. Adeyemi","userPrincipalName":"n.adeyemi@larkspur.example"}]},
    {"_src":"signin","_t":"2026-11-12T08:09:15Z","TimeGenerated":"2026-11-12T08:09:15Z","UserPrincipalName":"d.moreau@larkspur.example","AppDisplayName":"OfficeHome","ClientAppUsed":"Browser","IPAddress":"198.51.100.61","AutonomousSystemNumber":64508,"Location":"US","ResultType":0,"ResultDescription":"","SessionId":"c7e21f9a-3b64-4d0e-8a52-f19d06b7e3c4","UserAgent":"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0","AuthenticationRequirement":"multiFactorAuthentication","AuthenticationDetails":[{"authenticationMethod":"Previously satisfied","succeeded":true,"authenticationStepResultDetail":"MFA requirement satisfied by claim in the token"}],"ConditionalAccessStatus":"success","DeviceDetail":{"operatingSystem":"Linux","browser":"Firefox 131.0","isCompliant":false},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"entraaudit","_t":"2026-11-12T08:12:02Z","TimeGenerated":"2026-11-12T08:12:02Z","OperationName":"User registered security info","Category":"UserManagement","Result":"success","ResultReason":"User registered Authenticator App with Notification and Code","LoggedByService":"Authentication Methods","InitiatedBy":{"user":{"userPrincipalName":"d.moreau@larkspur.example","ipAddress":"198.51.100.61"}},"TargetResources":[{"type":"User","displayName":"D. Moreau","userPrincipalName":"d.moreau@larkspur.example"}]},
    {"_src":"o365","_t":"2026-11-12T08:16:44Z","CreationTime":"2026-11-12T08:16:44","Workload":"Exchange","RecordType":"ExchangeAdmin","Operation":"New-InboxRule","ResultStatus":"True","UserId":"d.moreau@larkspur.example","ClientIP":"198.51.100.61","Parameters":"[{\"Name\":\"Name\",\"Value\":\".\"},{\"Name\":\"SubjectOrBodyContainsWords\",\"Value\":\"bank;payment;remittance;invoice;wire\"},{\"Name\":\"MoveToFolder\",\"Value\":\"RSS Feeds\"},{\"Name\":\"MarkAsRead\",\"Value\":\"True\"},{\"Name\":\"StopProcessingRules\",\"Value\":\"True\"}]","AppAccessContext":{"AADSessionId":"c7e21f9a-3b64-4d0e-8a52-f19d06b7e3c4"}},
    {"_src":"entraaudit","_t":"2026-11-12T08:21:09Z","TimeGenerated":"2026-11-12T08:21:09Z","OperationName":"Consent to application","Category":"ApplicationManagement","Result":"success","LoggedByService":"Core Directory","InitiatedBy":{"user":{"userPrincipalName":"d.moreau@larkspur.example","ipAddress":"198.51.100.61"}},"TargetResources":[{"type":"ServicePrincipal","displayName":"DocuSafe Viewer","id":"d41e7b90-2c6a-4f83-9e15-7a0c4b2d6f38","modifiedProperties":[{"displayName":"ConsentContext.IsAdminConsent","newValue":"\"False\""},{"displayName":"ConsentContext.OnBehalfOfAll","newValue":"\"False\""},{"displayName":"ConsentAction.Permissions","newValue":"\"ConsentType: Principal, Scope: Mail.ReadWrite Mail.Send offline_access User.Read\""},{"displayName":"TargetId.ServicePrincipalNames","newValue":"\"8c1f6e2a-4b7d-4e19-a2c5-3f9d0b6e71a4\""}]}]},
    {"_src":"o365","_t":"2026-11-12T08:24:30Z","CreationTime":"2026-11-12T08:24:30","Workload":"Exchange","RecordType":"ExchangeItemAggregated","Operation":"MailItemsAccessed","ResultStatus":"Succeeded","UserId":"d.moreau@larkspur.example","ClientIP":"198.51.100.61","ClientAppId":"8c1f6e2a-4b7d-4e19-a2c5-3f9d0b6e71a4","MailAccessType":"Sync","OperationCount":412},
    {"_src":"edr","_t":"2026-11-12T08:31:12Z","Timestamp":"2026-11-12T08:31:12","DeviceName":"LM-WIN-0230","AccountName":"a.lindqvist","ActionType":"ProcessCreated","FileName":"msedge.exe","FolderPath":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","ProcessCommandLine":"\"msedge.exe\" --single-argument C:\\Users\\a.lindqvist\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\Q9WD3M6T\\Remittance_88231.html","InitiatingProcessFileName":"OUTLOOK.EXE","InitiatingProcessFolderPath":"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE","InitiatingProcessSigner":"Microsoft Corporation"},
    {"_src":"edr","_t":"2026-11-12T08:31:18Z","Timestamp":"2026-11-12T08:31:18","DeviceName":"LM-WIN-0230","AccountName":"a.lindqvist","ActionType":"ConnectionSuccess","FileName":"msedge.exe","InitiatingProcessFileName":"msedge.exe","RemoteIP":"203.0.113.90","RemotePort":443,"RemoteUrl":"auth.larkspur-docs.example","BytesSent":4870},
    {"_src":"o365","_t":"2026-11-12T09:10:05Z","CreationTime":"2026-11-12T09:10:05","Workload":"Exchange","RecordType":"ExchangeItemAggregated","Operation":"MailItemsAccessed","ResultStatus":"Succeeded","UserId":"d.moreau@larkspur.example","ClientIP":"198.51.100.61","ClientAppId":"8c1f6e2a-4b7d-4e19-a2c5-3f9d0b6e71a4","MailAccessType":"Bind","OperationCount":37},
    {"_src":"entraaudit","_t":"2026-11-12T09:18:40Z","TimeGenerated":"2026-11-12T09:18:40Z","OperationName":"Consent to application","Category":"ApplicationManagement","Result":"success","LoggedByService":"Core Directory","InitiatedBy":{"user":{"userPrincipalName":"r.varga@larkspur.example","ipAddress":"100.64.40.10"}},"TargetResources":[{"type":"ServicePrincipal","displayName":"Brightdesk Scheduler","id":"5c2a9f13-8e7d-4b60-a1f4-d93b0e6c7a28","modifiedProperties":[{"displayName":"ConsentContext.IsAdminConsent","newValue":"\"True\""},{"displayName":"ConsentContext.OnBehalfOfAll","newValue":"\"True\""},{"displayName":"ConsentAction.Permissions","newValue":"\"ConsentType: AllPrincipals, Scope: Calendars.ReadWrite Mail.Send User.Read\""},{"displayName":"TargetId.ServicePrincipalNames","newValue":"\"1b9e4c7d-6a2f-4d38-b5e1-0c7f2a9d4e63\""}]}]},
    {"_src":"o365","_t":"2026-11-12T09:35:20Z","CreationTime":"2026-11-12T09:35:20","Workload":"Exchange","RecordType":"ExchangeItem","Operation":"Send","ResultStatus":"Succeeded","UserId":"d.moreau@larkspur.example","ClientIP":"198.51.100.61","ClientAppId":"8c1f6e2a-4b7d-4e19-a2c5-3f9d0b6e71a4","Item":{"Subject":"Updated bank details for Larkspur Metrics invoices"}},
    {"_src":"email","_t":"2026-11-12T09:35:21Z","Timestamp":"2026-11-12T09:35:21Z","EmailDirection":"Outbound","DeliveryAction":"Delivered","DeliveryLocation":"External","SenderFromAddress":"d.moreau@larkspur.example","SenderFromDomain":"larkspur.example","SenderIPv4":"100.64.0.25","RecipientEmailAddress":"ap@harborline.example","Subject":"Updated bank details for Larkspur Metrics invoices","AuthenticationDetails":"","ThreatTypes":"","AttachmentCount":0},
    {"_src":"o365","_t":"2026-11-12T09:37:02Z","CreationTime":"2026-11-12T09:37:02","Workload":"Exchange","RecordType":"ExchangeItem","Operation":"Send","ResultStatus":"Succeeded","UserId":"d.moreau@larkspur.example","ClientIP":"198.51.100.61","ClientAppId":"8c1f6e2a-4b7d-4e19-a2c5-3f9d0b6e71a4","Item":{"Subject":"Updated bank details for Larkspur Metrics invoices"}},
    {"_src":"email","_t":"2026-11-12T09:37:03Z","Timestamp":"2026-11-12T09:37:03Z","EmailDirection":"Outbound","DeliveryAction":"Delivered","DeliveryLocation":"External","SenderFromAddress":"d.moreau@larkspur.example","SenderFromDomain":"larkspur.example","SenderIPv4":"100.64.0.25","RecipientEmailAddress":"payables@quillmart.example","Subject":"Updated bank details for Larkspur Metrics invoices","AuthenticationDetails":"","ThreatTypes":"","AttachmentCount":0},
    {"_src":"signin","_t":"2026-11-12T09:40:00Z","TimeGenerated":"2026-11-12T09:40:00Z","UserPrincipalName":"s.ito@larkspur.example","AppDisplayName":"OfficeHome","ClientAppUsed":"Browser","IPAddress":"192.0.2.33","AutonomousSystemNumber":64502,"Location":"IE","ResultType":0,"ResultDescription":"","SessionId":"4e7b2c19-8d3a-4f61-b0c5-91a2e6d7f308","UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0","AuthenticationRequirement":"multiFactorAuthentication","AuthenticationDetails":[{"authenticationMethod":"Previously satisfied","succeeded":true,"authenticationStepResultDetail":"MFA requirement satisfied by claim in the token"}],"ConditionalAccessStatus":"success","DeviceDetail":{"displayName":"LM-WIN-0144","deviceId":"0b6d2e81-4f3c-4a97-8e25-c1d9a7f03b64","operatingSystem":"Windows10","browser":"Edge 130.0","isCompliant":true,"trustType":"Azure AD joined"},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]},
    {"_src":"email","_t":"2026-11-12T10:05:44Z","Timestamp":"2026-11-12T10:05:44Z","EmailDirection":"Inbound","DeliveryAction":"Delivered","DeliveryLocation":"Inbox/folder","SenderFromAddress":"ap@harborline.example","SenderFromDomain":"harborline.example","SenderIPv4":"198.51.100.144","RecipientEmailAddress":"d.moreau@larkspur.example","Subject":"RE: Updated bank details for Larkspur Metrics invoices","AuthenticationDetails":"{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\"}","ThreatTypes":"","AttachmentCount":0},
    {"_src":"o365","_t":"2026-11-12T10:30:15Z","CreationTime":"2026-11-12T10:30:15","Workload":"Exchange","RecordType":"ExchangeAdmin","Operation":"New-InboxRule","ResultStatus":"True","UserId":"a.lindqvist@larkspur.example","ClientIP":"100.64.41.10","Parameters":"[{\"Name\":\"Name\",\"Value\":\"Newsletters\"},{\"Name\":\"From\",\"Value\":\"news@trendwire.example\"},{\"Name\":\"MoveToFolder\",\"Value\":\"Newsletters\"},{\"Name\":\"MarkAsRead\",\"Value\":\"True\"}]","AppAccessContext":{"AADSessionId":"9b3e7d25-1a4c-4f98-8c06-d2e5f7a1b490"}},
    {"_src":"email","_t":"2026-11-12T11:12:30Z","Timestamp":"2026-11-12T11:12:30Z","EmailDirection":"Outbound","DeliveryAction":"Delivered","DeliveryLocation":"External","SenderFromAddress":"k.osei@larkspur.example","SenderFromDomain":"larkspur.example","SenderIPv4":"100.64.0.25","RecipientEmailAddress":"audit@fenwick-audit.example","Subject":"Bank details confirmation for the 2026 audit","AuthenticationDetails":"","ThreatTypes":"","AttachmentCount":1,"FileName":"Bank_confirmation_2026.pdf","FileType":"pdf"},
    {"_src":"o365","_t":"2026-11-12T11:40:22Z","CreationTime":"2026-11-12T11:40:22","Workload":"Exchange","RecordType":"ExchangeItemAggregated","Operation":"MailItemsAccessed","ResultStatus":"Succeeded","UserId":"d.moreau@larkspur.example","ClientIP":"198.51.100.61","ClientAppId":"8c1f6e2a-4b7d-4e19-a2c5-3f9d0b6e71a4","MailAccessType":"Sync","OperationCount":58},
    {"_src":"signin","_t":"2026-11-12T13:02:48Z","TimeGenerated":"2026-11-12T13:02:48Z","UserPrincipalName":"k.osei@larkspur.example","AppDisplayName":"Microsoft Teams","ClientAppUsed":"Mobile Apps and Desktop clients","IPAddress":"100.64.40.10","AutonomousSystemNumber":64497,"Location":"NL","ResultType":0,"ResultDescription":"","SessionId":"2f8d4a61-c93e-4b07-a5d2-7e1b0c9f6384","UserAgent":"Microsoft Teams","AuthenticationRequirement":"singleFactorAuthentication","ConditionalAccessStatus":"success","DeviceDetail":{"displayName":"LM-WIN-0188","deviceId":"c84f1d07-9e6a-4b23-b5c8-2a7e0f3d91b6","operatingSystem":"Windows10","browser":"","isCompliant":true,"trustType":"Azure AD joined"},"RiskLevelDuringSignIn":"none","RiskEventTypes_V2":[]}
    ],

    /* single-event detections: Sigma YAML, run with sigma.js */
    rules: [
      { id: "R-MAIL-001", platform: "EMAIL", groupBy: "SenderFromDomain", yaml: `
title: HTML attachment delivered from an external sender
id: 3f6a9d2e-5b1c-4e7a-8d40-000000000101
status: test
description: An inbound message with an HTML, HTM or SVG attachment reached a mailbox. An HTML file that opens a sign-in page is a common start of adversary-in-the-middle phishing.
logsource: { product: m365, service: defender_email }
detection:
  selection:
    EmailDirection: Inbound
    DeliveryAction: Delivered
    FileName|endswith: ['.html', '.htm', '.shtml', '.svg']
  condition: selection
falsepositives:
  - Encrypted-mail portals that deliver each message as an HTML file
level: medium
tags: [attack.initial-access, attack.t1566.001]` },
      { id: "R-EDR-101", platform: "EDR", yaml: `
title: Outlook opens a local HTML attachment in a browser
id: 3f6a9d2e-5b1c-4e7a-8d40-000000000102
status: test
description: A browser started by OUTLOOK.EXE with an HTML file from the Outlook attachment cache. The user opened an HTML attachment.
logsource: { product: windows, category: process_creation }
detection:
  selection:
    ActionType: ProcessCreated
    InitiatingProcessFileName: OUTLOOK.EXE
    FileName: [msedge.exe, chrome.exe, firefox.exe]
    ProcessCommandLine|contains: '\\Content.Outlook'
    ProcessCommandLine|endswith: ['.html', '.htm', '.shtml', '.svg']
  condition: selection
falsepositives:
  - Encrypted-mail portals and some HR or payroll systems send HTML attachments
level: medium
tags: [attack.execution, attack.t1204.002, attack.initial-access, attack.t1566.001]` },
      { id: "R-ENT-002", platform: "SIEM", yaml: `
title: OAuth consent granting mail access
id: 3f6a9d2e-5b1c-4e7a-8d40-000000000103
status: test
description: A user or an administrator consented to an application with permission to read, change or send mail. Consent phishing turns one stolen session into access that survives a password reset.
logsource: { product: azure, service: auditlogs }
detection:
  selection:
    OperationName: Consent to application
    Result: success
  mail_scopes:
    TargetResources.modifiedProperties.newValue|contains: [Mail.Read, Mail.Send, MailboxSettings.ReadWrite, full_access_as_user, EWS.AccessAsUser.All]
  condition: selection and mail_scopes
falsepositives:
  - Approved admin consent to a business application during a change window
level: high
tags: [attack.credential-access, attack.t1528]` },
      { id: "R-ENT-003", platform: "SIEM", yaml: `
title: New MFA method registered
id: 3f6a9d2e-5b1c-4e7a-8d40-000000000104
status: test
description: A user registered security info (an authenticator app, phone or key). After a session theft the attacker adds their own method to keep access.
logsource: { product: azure, service: auditlogs }
detection:
  selection:
    OperationName: User registered security info
    Result: success
  condition: selection
falsepositives:
  - New joiners and replaced phones
level: medium
tags: [attack.persistence, attack.t1098.005]` },
      { id: "R-M365-001", platform: "SIEM", yaml: `
title: Inbox rule that hides, deletes or marks mail as read
id: 3f6a9d2e-5b1c-4e7a-8d40-000000000105
status: test
description: An inbox rule moves mail to a folder users rarely open, deletes it, or marks it read. Business email compromise uses these rules to hide replies from the real mailbox owner.
logsource: { product: m365, service: exchange }
detection:
  selection:
    Operation: [New-InboxRule, Set-InboxRule, UpdateInboxRules]
  hides:
    Parameters|contains: ['"DeleteMessage"', 'RSS Feeds', 'RSS Subscriptions', 'Conversation History', '"MarkAsRead","Value":"True"']
  condition: selection and hides
falsepositives:
  - Users filing newsletters and notifications as read
level: high
tags: [attack.stealth, attack.t1564.008]` },
      { id: "R-ENT-004", platform: "SIEM", groupBy: "IPAddress", tuningFields: ["UserPrincipalName", "ClientAppUsed"],
        tuningNote: "# until IT-7713 resets the svc-scan password on the Manchester printer; review 2026-12-12", yaml: `
title: Wrong-password sign-in over a non-browser client
id: 3f6a9d2e-5b1c-4e7a-8d40-000000000106
status: test
description: Entra ID rejected a password (50126) on a client other than a browser. Sprays use scripted clients; people mistyping use the browser.
logsource: { product: azure, service: signinlogs }
detection:
  selection:
    ResultType: 50126
  filter_browser:
    ClientAppUsed: Browser
  condition: selection and not filter_browser
falsepositives:
  - Devices and service accounts with an expired password
level: low
tags: [attack.credential-access, attack.t1110.003, attack.initial-access, attack.t1078.004]` }
    ],

    /* multi-event detection Sigma single-event rules cannot express. It reuses a built-in type (see docs/SCENARIOS.md). */
    correlations: [
      { id: "C-ENT-001", platform: "SIEM", type: "same_key_many_values", title: "Same Entra session used from two networks", level: "high", attack: ["T1557", "T1539", "T1550.004"],
        description: "One Entra SessionId seen from two autonomous systems. After adversary-in-the-middle phishing, the stolen session cookie is replayed from the attacker's own network with MFA satisfied by the token.",
        falsepositives: ["A managed laptop that moves between networks keeps its session"],
        select: `
detection:
  selection:
    ResultType: 0
    SessionId|exists: true
  condition: selection`,
        keyField: "SessionId", valueField: "AutonomousSystemNumber", subjectField: "UserPrincipalName",
        minValues: 2, includeEarlier: true,
        labels: { key: "session", events: "sign-ins on that session" } }
    ],

    /* hunts: Sigma queries over the whole lake, for what no alert covered */
    hunts: [
      { id: "H-01", title: "Outbound mail about changed bank or payment details", why: "Business email compromise ends in a payment request. No rule watches outbound mail.", yaml: `
title: Outbound mail about bank or payment details
logsource: { product: m365, service: defender_email }
detection:
  selection:
    EmailDirection: Outbound
    Subject|contains: ['bank details', 'payment details', 'banking details', 'remittance account']
  condition: selection
level: high
tags: [attack.impact, attack.t1657]` },
      { id: "H-02", title: "Mailbox reads by an app from outside the offices", why: "A consented app keeps reading mail after the session is revoked. MailItemsAccessed has no rule today.", yaml: `
title: Mailbox reads by a third-party app from outside corporate egress
logsource: { product: m365, service: exchange }
detection:
  selection:
    Operation: MailItemsAccessed
    ClientAppId|exists: true
  filter_corp:
    ClientIP|cidr: ['100.64.40.0/24', '100.64.41.0/24']
  condition: selection and not filter_corp
level: high
tags: [attack.collection, attack.t1114.002]` },
      { id: "H-03", title: "Sign-ins and browser connections through the phishing proxy", why: "Anyone who reached the proxy may have handed over a session. Sweep both sources for its address.", yaml: `
title: Activity involving the adversary-in-the-middle proxy address
logsource: { category: any }
detection:
  signin:
    IPAddress: 203.0.113.90
  endpoint:
    RemoteIP: 203.0.113.90
  condition: signin or endpoint
level: high
tags: [attack.credential-access, attack.t1557]` },
      { id: "H-04", title: "Every recipient of the remittance phish", why: "Purge and scope need the whole recipient list, including mail delivered before this shift.", yaml: `
title: Inbound mail from the remittance phish sender domain
logsource: { product: m365, service: defender_email }
detection:
  selection:
    EmailDirection: Inbound
    SenderFromDomain: northpay-remit.example
  condition: selection
level: medium
tags: [attack.initial-access, attack.t1566.001]` }
    ],

    /* answer key: what a good shift concludes. Keys are alert ids: "<rule id>|<group key>". */
    answers: {
      "R-ENT-004|100.64.41.10": { verdict: "fp", sev: "info", why: "svc-scan, the Manchester printer's scan-to-email account, fails SMTP AUTH every 30 minutes since its password expired (IT-7713, in the handover). Tune with a filter on that account and protocol that ends when IT-7713 closes." },
      "R-ENT-004|192.0.2.201": { verdict: "tp", sev: "low", why: "One wrong password each for six staff accounts from 192.0.2.201 in eight minutes over a scripted client. Password spray with no success and no lockout. Block the address in Conditional Access; no incident." },
      "R-MAIL-001|notify.harbourbank.example": { verdict: "benign", sev: "low", why: "Harbour Bank's encrypted-mail portal sends k.osei a SecureMessage.html each week (last one 2026-11-05) and SPF, DKIM and DMARC pass. Benign. Keep the rule as it is: an HTML attachment is this campaign's lure." },
      "R-EDR-101|LM-WIN-0188": { verdict: "benign", sev: "low", why: "k.osei opened the Harbour Bank SecureMessage.html from that benign mail. No field separates it from the lure (same Outlook, same Edge), so tune by hand or leave the rule alone." },
      "R-MAIL-001|northpay-remit.example": { verdict: "tp", sev: "high", incident: "CASE-2093", why: "Second wave of the phish APAC reported: three more mailboxes got Remittance_88231.html at 07:48 because MSG-118 was still pending. Purge it, block the sender and domain, and find who opened it (H-03, H-04)." },
      "R-EDR-101|LM-WIN-0217": { verdict: "tp", sev: "high", incident: "INC-1", why: "Outlook opened Remittance_88231.html in Edge on d.moreau's laptop at 08:01 and Edge connected to auth.larkspur-docs.example (203.0.113.90). Her sign-in came through that address two minutes later." },
      "C-ENT-001|d.moreau": { verdict: "tp", sev: "critical", incident: "INC-1", why: "Session c7e21f9a created through 203.0.113.90 (AS64505) at 08:03, then replayed from 198.51.100.61 (AS64508) at 08:09 on Linux Firefox with no device id and MFA satisfied by the token claim. Adversary-in-the-middle session theft: revoke sessions and block sign-in." },
      "R-ENT-003|n.adeyemi": { verdict: "benign", sev: "info", why: "New joiner n.adeyemi (HR-5120, in the handover) registered an authenticator app from the Manchester office after a temporary access pass sign-in. Benign." },
      "R-ENT-003|d.moreau": { verdict: "tp", sev: "high", incident: "INC-1", why: "An authenticator app was registered on d.moreau from 198.51.100.61, the replay address, three minutes after the session was stolen. Attacker persistence: a password reset alone leaves it in place, so the service desk must remove it." },
      "R-M365-001|d.moreau": { verdict: "tp", sev: "critical", incident: "INC-1", why: "Rule '.' moves any mail with bank, payment, remittance, invoice or wire to RSS Feeds and marks it read, created from the replay address. Business email compromise hiding rule: export it to the case, then remove it." },
      "R-ENT-002|d.moreau": { verdict: "tp", sev: "critical", incident: "INC-1", why: "d.moreau consented to DocuSafe Viewer for Mail.ReadWrite, Mail.Send and offline_access from the replay address. The grant survives a password reset and session revocation: revoke it and disable the app." },
      "R-ENT-002|r.varga": { verdict: "benign", sev: "low", why: "Admin consent to Brightdesk Scheduler by r.varga from the Amsterdam office at 09:18, inside the CHG-4410 window from the handover. Benign. Leave the rule untuned: every grant with mail scopes deserves a look." },
      "C-ENT-001|s.ito": { verdict: "benign", sev: "low", why: "s.ito's session from home broadband (AS64499) continued from a Dublin hotel (AS64502) on the same compliant laptop LM-WIN-0144 and the same browser. The Dublin trip is in the handover. Benign." },
      "R-M365-001|a.lindqvist": { verdict: "benign", sev: "info", why: "a.lindqvist's 'Newsletters' rule files mail from news@trendwire.example and marks it read, made from the Manchester office. Benign. Suggest the rule require a keyword match or a hidden folder before MarkAsRead alone fires it." },
      "R-EDR-101|LM-WIN-0230": { verdict: "tp", sev: "medium", incident: "CASE-2093", why: "a.lindqvist opened the same lure at 08:31 and her browser reached 203.0.113.90, but no sign-in came through the proxy for her. Real exposure, contained: keep it in CASE-2093 and reset her password as a precaution." }
    },
    huntAnswers: {
      "H-01": { expectHits: 3, unalerted: true, note: "Finds the two mails sent as d.moreau through DocuSafe Viewer at 09:35 and 09:37 asking harborline.example and quillmart.example to pay a new account, and k.osei's legitimate audit mail. No alert covers outbound mail. This is the business impact: Finance must call both customers before they pay." },
      "H-02": { expectHits: 3, unalerted: true, note: "Finds DocuSafe Viewer reading d.moreau's mailbox from 198.51.100.61 at 08:24, 09:10 and 11:40. The consent alert fired once and the reads raised nothing. Revoking sessions does not stop them; revoking the grant does." },
      "H-03": { expectHits: 3, note: "Finds d.moreau's sign-in through the proxy and two browser connections to it, d.moreau's and a.lindqvist's. No sign-in through the proxy followed for a.lindqvist." },
      "H-04": { expectHits: 4, note: "Four recipients: s.ito at 05:12 (reported to APAC), then d.moreau, a.lindqvist and k.osei at 07:48 because MSG-118 had not been applied. Purge all four and confirm the block." }
    },
    /* rules whose answer-key tuning must drop every noisy alert and keep every confirmed one */
    tuningChecks: ["R-ENT-004"],
    goodShift: [
      { id: "INC-1", sev: "critical", text: "Adversary-in-the-middle session theft on d.moreau, then business email compromise. Revoke sessions and block sign-in, have the service desk reset the password and remove the attacker's authenticator, export and remove the RSS Feeds rule, revoke and disable DocuSafe Viewer (Identity and access). H-01 shows fake bank-detail mail to two customers at 09:35: Finance calls them before they pay, Legal decides on notice. IR lead notified." },
      { id: "CASE-2093", sev: "high", text: "Carried in: the campaign. MSG-118 was still pending when the second wave landed at 07:48. Purge all four recipients (H-04), block the sender and domain, reset a.lindqvist as a precaution (she reached the proxy, H-03)." },
      { id: "POLICY", sev: "medium", text: "Raise with Identity and access: users can consent to Mail.ReadWrite and Mail.Send. Move to the admin consent workflow, and add a rule on MailItemsAccessed by new apps (H-02)." }
    ]
  };

  if (typeof module === "object" && module.exports) module.exports = scenario;
  else (root.SOC_SCENARIOS = root.SOC_SCENARIOS || {})[scenario.id] = scenario;
})(typeof window !== "undefined" ? window : globalThis);
