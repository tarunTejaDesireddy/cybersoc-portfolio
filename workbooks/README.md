# sentinel-workbooks

Microsoft Sentinel workbooks built for the personal SOC lab in [sentinel-soc-lab](https://github.com/TaruntejaDesireddy/sentinel-soc-lab).

## Hunt & Investigate (`hunt-and-investigate.json`)

Two-tab workbook:

- **🎯 Live Hunt** — a KPI overview strip (auth failures, sensitive ops, risky sign-ins, TI indicators, open incidents) up top, then SSH brute-force sources (remote IPs regex-extracted from Syslog auth-failure messages), sensitive Azure control-plane operations, sign-in anomalies, and a threat-intel-by-feed breakdown.
- **🔎 IP Investigation** — paste an IP, get: one-click pivot **buttons** to 10 OSINT tools (VirusTotal, AbuseIPDB, Shodan, OTX, GreyNoise, Censys, IPinfo, Talos, Spur, X-Force), an at-a-glance tile summary, a time-series activity chart, and rate-burst peak detection (1s/1m/1h buckets).

Built against this lab's actual connected tables (`Syslog`, `AzureActivity`, `SigninLogs`, `ThreatIntelIndicators`) — not a generic template. Color-coded throughout (severity/status thresholds), icon-anchored section headers, and card-bordered layout for scannability.

## SOC Overview (`soc-overview.json`)

Operational health dashboard — companion to Hunt & Investigate, not a duplicate. Covers what that one doesn't:

- **💰 Ingestion & cost** — daily GB by table, charted against the workspace's 1 GB/day cap, plus a today's-ingestion breakdown table. Built because silently-dropped ingestion past the cap looks exactly like a broken rule if you're not watching this.
- **💓 Data source health** — Heartbeat status per onboarded source (Syslog VM, this PC via Arc), color-coded Online/Delayed/Offline by minutes since last check-in.
- **🚨 Incidents & alerts** — `SecurityIncident` by severity/status, `SecurityAlert` by severity/provider.
- **🪪 Identity activity** — combined `SigninLogs` + `AADNonInteractiveUserSignInLogs` success/failure trend.
- **📝 Audit & Azure activity** — top `AuditLogs` operations by actor, top `AzureActivity` operations by status.
- **📡 Syslog volume** — events per hour by facility.

### Import

Sentinel portal → Workbooks → New → Advanced Editor (`</>`) → paste the JSON → Apply → Save, and point it at your workspace.
