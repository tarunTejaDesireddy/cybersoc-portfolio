[← Back to index](README.md) | Tier 1 — Must master

# Phase 11 — Microsoft Sentinel (Q256–290)

## 256. What is Microsoft Sentinel?
Microsoft's cloud-native **SIEM and SOAR** platform, built on Azure Log Analytics. Collects and correlates security data from across cloud and on-premises sources, detects threats with analytics rules (KQL), and automates response with playbooks (Logic Apps). Scales elastically, priced by data ingestion and retention.

## 257. SIEM vs SOAR?

| | SIEM | SOAR |
|---|---|---|
| Purpose | Collect, normalize, correlate, and **detect** across log sources | **Orchestrate and automate** the response |
| Output | Alerts/incidents | Executed actions — enrichment, notification, containment |
| Question answered | "What happened?" | "What do we do about it, automatically?" |
| In Sentinel | Log Analytics + analytics rules | Automation rules + playbooks (Logic Apps) |

Sentinel is both in one product, which is a large part of its appeal.

## 258. What is a Log Analytics workspace?
The underlying Azure resource that stores the log data — the container Sentinel is enabled on top of. It defines the data retention period, access control boundary (RBAC), region/data residency, and the cost model. Design decisions here (one workspace vs. many, retention tiers) drive both cost and investigation experience.

## 259. How does Sentinel collect logs?
- **Native/service-to-service connectors** — Entra ID, Azure Activity, Microsoft 365, Defender XDR: configuration-only, no agent.
- **Azure Monitor Agent (AMA)** with **Data Collection Rules (DCRs)** — Windows Event Logs, Linux syslog, custom text logs from VMs.
- **Common Event Format (CEF) / Syslog** via a forwarder VM — most firewalls and network appliances.
- **Codeless Connector Platform / API-based** — SaaS products polled via API.
- **Logstash / Logic Apps / Azure Functions** — custom pipelines.
- **Direct ingestion via the Logs Ingestion API** for custom sources.

## 260. What is a data connector?
The configured integration that brings a specific data source into the workspace — it handles authentication, defines which tables the data lands in, and often ships accompanying analytics rule templates, workbooks, and hunting queries for that source.

## 261. What is an analytics rule?
A detection rule that runs a KQL query against ingested data on a schedule (or in near real time) and generates alerts/incidents when it returns results. Configuration includes: the query, frequency and lookback period, threshold, **entity mapping**, severity, MITRE tactic/technique mapping, incident grouping settings, and automated response actions.

Rule types: **Scheduled**, **Near-Real-Time (NRT)**, **Microsoft Security** (pass through alerts from Defender products), **Fusion** (ML-based multi-stage attack detection), **Anomaly**, and **Threat Intelligence** (match ingested indicators against data).

## 262. Scheduled analytics rule vs NRT rule?

| | Scheduled | Near-Real-Time (NRT) |
|---|---|---|
| Frequency | Configurable — 5 minutes to 14 days | Fixed, runs every minute |
| Query complexity | Full KQL, joins, unions, multiple tables | **Restricted** — single table, no joins/unions |
| Lookback | Configurable window | Fixed, previous minute |
| Use for | Most detections, correlation logic | Time-critical single-source detections |

The tradeoff to state: NRT buys latency at the cost of query expressiveness.

## 263. What is an incident?
In Sentinel, a container grouping one or more related **alerts**, with its own status (New/Active/Closed), severity, owner, tasks, comments, and investigation graph. Incidents are what analysts actually work — the queue is a queue of incidents, not alerts.

## 264. Alert vs incident in Sentinel?
An **alert** is a single detection firing. An **incident** is the case object grouping one or more alerts (plus their entities) for investigation. Multiple alerts can group into one incident via **incident grouping** settings, and alerts from Defender XDR can be correlated into Sentinel incidents.

## 265. What is entity mapping?
Configuring an analytics rule to map columns of its query output to recognized **entity types** (Account, Host, IP, URL, File hash, Azure resource, Mailbox). This is what makes an incident investigable rather than just a row of text:
- Entities appear in the investigation graph for pivoting.
- Playbooks can act on them (e.g., pass the IP to an enrichment API — as in this repo's `la-ip-enrichment` playbook).
- Incident grouping and UEBA correlation work on them.
- Analysts can pivot to all other activity involving that entity.

**An analytics rule without entity mapping produces an incident nobody can pivot from** — worth saying, because it's a common real-world gap.

## 266. What is incident grouping?
Rule-level settings controlling whether alerts from the same rule create separate incidents or are grouped into one, over a configurable time window (up to 7 days), and on what basis: all alerts together, alerts sharing **all** mapped entities, or alerts sharing **selected** entities. Grouping is how you stop a noisy rule from generating 500 separate incidents for one attack — but grouping too aggressively can hide genuinely separate incidents.

## 267. What is an automation rule?
Sentinel's lightweight orchestration layer — triggers on incident creation/update or alert creation, evaluates conditions (severity, rule name, title, entity properties, tags), and executes actions: change status/severity, assign an owner, add tags, or **run a playbook**. Also the mechanism for suppressing known-benign incidents automatically and for centrally managing playbook triggers across many rules.

## 268. What is a playbook?
An automated response workflow, implemented as an Azure **Logic App**, triggered by a Sentinel incident/alert (or manually by an analyst). Typical uses: enrich entities against threat intel, post findings back as incident comments, notify via email/Teams, create a ticket, or take containment action (disable an account, isolate a device, block an IP).

## 269. What is Logic Apps?
Azure's low-code workflow/integration service — a designer-based sequence of triggers and actions with hundreds of prebuilt connectors (Microsoft Graph, ServiceNow, Teams, VirusTotal, HTTP). Sentinel playbooks *are* Logic Apps; the terms are used almost interchangeably in practice.

## 270. How does Sentinel integrate with Logic Apps?
Via dedicated Sentinel connectors and triggers:
- **Triggers** — "When a Sentinel incident creation rule is triggered," "When a Sentinel alert is triggered," or "When a response to an incident is triggered" (manual run by an analyst).
- **Actions** — add a comment to the incident, update incident properties, add entities to a threat intel indicator, run a playbook on entities.
- The Logic App needs an identity (preferably a **managed identity**) with `Microsoft Sentinel Responder`/`Contributor` permissions on the workspace to write back to incidents.

Security point worth making, and it maps directly to the design choice in this repo's own `la-user-containment` playbook: automated **containment** actions require broad standing permissions (e.g., Graph `User.ReadWrite.All`), so many mature SOCs deliberately have playbooks *recommend* containment via an incident comment and require a human to approve the action, rather than granting an unattended identity tenant-wide write access.

## 271. What is a workbook?
An interactive, visual report/dashboard built on KQL queries — parameterized, with charts, grids, and tiles. Used for SOC dashboards (queue health, incident volume, MTTA/MTTR), investigation pivot views, and connector/ingestion health monitoring.

## 272. What is a watchlist?
An imported reference dataset (CSV) stored in Sentinel and queryable from KQL via `_GetWatchlist('name')`. Used for correlation and enrichment without re-ingesting data: VIP/high-value user lists, asset criticality/owner mappings, approved admin accounts, known-good IP ranges for exclusions, terminated employee lists, or a list of IOCs from an investigation.

## 273. What is UEBA?
User and Entity Behavior Analytics — Sentinel builds behavioral baselines per user/host/IP (typical sign-in locations, devices, working hours, resources accessed, peer group behavior) and scores deviations from them. Surfaces things static rules miss — "this account has never accessed this resource, never signed in from this country, and none of its peers do either" — and enriches investigations with a per-entity risk picture. Tables: `BehaviorAnalytics`, `UserPeerAnalytics`, `IdentityInfo`.

## 274. What is threat intelligence?
In Sentinel, ingested indicators (IPs, domains, URLs, file hashes) stored in `ThreatIntelligenceIndicator` (or the newer TI tables), brought in via TAXII feeds, the Threat Intelligence Upload API, MISP, or platform integrations. Used by built-in TI-matching analytics rules and for enrichment during investigation. (See [phase-19](phase-19-threat-intelligence.md) for the analytical side.)

## 275. What is a custom detection?
A detection rule you author yourself for your environment, rather than using a gallery template — necessary because vendor templates can't know your naming conventions, your critical assets, your baselines, or your specific threat model. Custom detections are also how you close gaps found during incidents.

## 276. What is a hunting query?
A saved KQL query used for **proactive** investigation rather than automated alerting — it doesn't generate incidents; an analyst runs it deliberately. Sentinel ships hundreds mapped to MITRE tactics, and you can bookmark interesting results and promote them into an investigation.

## 277. Hunting vs analytics rule?

| | Hunting query | Analytics rule |
|---|---|---|
| Execution | Manual, on demand | Automatic, scheduled |
| Output | Results for an analyst to review; bookmarks | Alerts/incidents in the queue |
| Tolerance for noise | High — an analyst is filtering results | Low — noise creates alert fatigue |
| Purpose | Explore a hypothesis, find unknown threats | Reliably catch known-bad patterns |

Natural lifecycle worth mentioning: **a hunting query that proves consistently high-fidelity gets promoted into an analytics rule.**

## 278. What is a data table?
The schema-defined container for a specific log type in the workspace — `SecurityEvent` (Windows events), `SigninLogs`, `AuditLogs`, `AzureActivity`, `Syslog`, `CommonSecurityLog` (CEF), `DeviceProcessEvents` (Defender), `EmailEvents`, `Heartbeat`. KQL queries always start by naming a table.

## 279. What is a data source?
The origin system producing the logs (a firewall, a domain controller, Entra ID, an EDR agent). One data source may populate multiple tables, and one table may receive data from many sources.

## 280. What is a connector health issue?
Any condition where a configured connector stops delivering data correctly: agent down, credentials/API key expired, permissions changed, network path blocked, DCR misconfigured, quota/throttling limits hit, or a schema change upstream. The dangerous part is that it's **silent** — dashboards look fine, rules run without error, and nothing alerts, because zero results looks identical to "nothing bad happened." That's why detection-health monitoring matters (Q290).

## 281. How do you troubleshoot missing logs?
1. **Confirm the gap precisely** — which table, which source, from what time? `Heartbeat | where TimeGenerated > ago(24h) | summarize max(TimeGenerated) by Computer` shows which agents stopped reporting.
2. **Check whether it's all sources or one** — narrows it to a platform problem vs. a device problem.
3. **Check the connector status page** in Sentinel for last-received timestamps.
4. **Check the agent/forwarder** — is the AMA/syslog forwarder running, is the VM up, is disk full?
5. **Check the DCR** — is the source still in scope, and are the required event IDs/facilities still selected?
6. **Check the source device** — is it still configured to send, and to the right destination/port?
7. **Check network path** — firewall rules between source and collector.
8. **Check permissions/credentials** — expired API keys, rotated secrets, changed service principal permissions.
9. **Check ingestion limits** — daily cap reached (this one silently stops ingestion until the next day, and catches people out), or throttling.
10. **Verify the fix** by confirming new records arrive, and then **create a detection-health alert** so the same gap alerts next time.

## 282. How do you troubleshoot a Sentinel analytics rule?
1. **Run the rule's KQL manually** in Logs over the same lookback window — does it return results at all?
2. **If no results:** is the underlying data present (query the raw table)? Has a field name or schema changed? Is the time window/lookback wrong? Are filters too narrow?
3. **If results but no incidents:** check the rule's threshold, its enabled state, event grouping, alert suppression settings, and whether an automation rule is auto-closing the incidents.
4. **Check the rule's execution history** for failures — query errors, timeouts, or exceeded result limits.
5. **Check entity mapping** — mapping to a column that no longer exists causes problems.
6. **Check incident grouping** — aggressive grouping can make new alerts fold silently into an existing incident.
7. **Check for a data delay** — if ingestion lags behind the rule's lookback window, the rule queries a window the data hasn't landed in yet. Fix by adding lookback buffer, and use `ingestion_time()` rather than `TimeGenerated` where appropriate.

## 283. How do you reduce false positives?
- **Baseline first** — understand what normal looks like before writing the exclusion.
- **Exclude known-good precisely** — specific service accounts, specific source hosts, specific approved processes — rather than broadening the rule until it stops firing (which also stops it detecting).
- **Add corroborating conditions** — require two signals rather than one (e.g., failed logons *and* a subsequent success; PowerShell *and* an outbound connection).
- **Use watchlists** for exclusions so they're maintainable without editing rule logic.
- **Tune thresholds** to the environment's actual volume.
- **Add time/context awareness** — activity normal in a maintenance window, abnormal at 3am.
- **Track FP rate per rule** and prioritize the worst offenders.
- **Never suppress without understanding why it fired** — that's how real detections get silently disabled.

## 284. How do you tune an analytics rule?
1. **Measure** — how many incidents does it generate, and what proportion are TP/FP/BP?
2. **Categorize the FPs** — find the common denominator (one scanner, one service account, one legitimate application).
3. **Choose the narrowest fix** that removes that class: an exclusion, an added condition, a threshold change, or a scope restriction.
4. **Test the change** against historical data before deploying — run the modified query over the past 30 days and confirm it still catches the true positives you know about.
5. **Document the change and the reason** in the rule description (so the next analyst knows why the exclusion exists).
6. **Monitor after deployment** and iterate.
7. **Re-validate periodically** — exclusions rot as environments change, and an exclusion added two years ago may now be hiding real activity.

## 285. How do you onboard a new log source?
1. **Define the use case first** — which detections will this enable? (Ingesting data you never query is pure cost.)
2. **Identify the connector method** and prerequisites (agent, forwarder, permissions, network).
3. **Estimate volume and cost** — GB/day at the current pricing tier; decide on a commitment tier if it's large.
4. **Deploy in a test scope first**, verify data lands in the expected table with the expected schema.
5. **Validate data quality** — timestamps correct and in UTC, fields parsed, no truncation, and the fields your detections need actually populated.
6. **Filter at the source/DCR** — don't ingest what you'll never query; this is the single biggest cost lever.
7. **Deploy detections, workbooks, and hunting queries** for the source.
8. **Set retention** appropriately (hot vs. archive tier).
9. **Add ingestion-health monitoring** so a silent failure alerts.
10. **Document** the source, its owner, its schema, and its detections.

## 286. How do you create an analytics rule?
1. **Start from a threat, not a query** — what technique am I trying to detect, and what evidence would it leave?
2. **Confirm the data exists** to detect it (and if not, that's a log-source gap, not a rule).
3. **Write and iterate the KQL** in Logs against real historical data.
4. **Validate against known true positives** — historical incidents, or a controlled test/simulation (Atomic Red Team).
5. **Assess noise** — run it over 30 days and count how many incidents it *would* have created.
6. **Configure** frequency, lookback (with buffer for ingestion delay), threshold, and severity.
7. **Map entities** — always ([Q265](#265-what-is-entity-mapping)).
8. **Map MITRE tactic/technique.**
9. **Write a description that a 3am analyst can act on** — what it detects, why it matters, numbered triage steps, and known false positives with the tuning lever.
10. **Configure incident grouping and any automation.**
11. **Deploy, monitor, and tune.** Ideally store the rule definition in source control (as this repo does) so changes are reviewable and deployment is repeatable.

## 287. How do you automate incident response?
Layer it by risk:
- **Always automate enrichment** — IP/domain/hash reputation, user and asset context, related incident lookup, geolocation. Zero risk, huge time saving.
- **Automate triage support** — auto-assign by rule type, auto-tag, auto-set severity from asset criticality, auto-close known-benign patterns with a documented condition.
- **Automate notification** — Teams/email to the right owner, ticket creation.
- **Be deliberate about automated containment** — disabling accounts or isolating machines automatically is powerful and dangerous. Restrict it to very high-confidence detections, require an approval step for anything broad, and always leave an audit trail and a rollback path.

## 288. How would you design a Sentinel SOC from scratch?
Structure the answer as: **requirements → architecture → detections → operations.**
1. **Define scope and requirements** — what's being protected, threat model, compliance/data-residency obligations, budget, team size and shift coverage.
2. **Workspace architecture** — region (data residency matters in government contexts), single vs. multiple workspaces, RBAC model (least privilege per team), retention strategy (hot vs. archive by table).
3. **Prioritize log sources by detection value** — identity first (Entra/AD), then endpoint (EDR), then email, then network/firewall, then cloud control plane. Filter at source; don't ingest what you won't use.
4. **Detection strategy** — start with high-fidelity built-ins, then build custom detections mapped to MITRE, prioritizing the techniques most relevant to your threat model. Track coverage as a gap map.
5. **Entity and asset context** — watchlists for critical assets, VIP users, and approved admin accounts, plus UEBA if licensed.
6. **Automation** — enrichment playbooks first, notification second, containment last and cautiously.
7. **Operational processes** — triage runbooks per alert type, severity/SLA definitions, escalation path, shift handover, documentation standard.
8. **Measurement and health** — MTTA/MTTR, FP rate per rule, detection coverage, and ingestion-health monitoring.
9. **Cost governance** — commitment tiers, daily caps with alerting, and periodic review of unused tables.
10. **Continuous improvement** — post-incident detection gaps become tickets; purple-team exercises validate coverage.

## 289. How would you control Sentinel costs?
Cost is ingestion + retention, so:
- **Filter at the source** — DCRs collecting only security-relevant event IDs/facilities, not everything.
- **Don't ingest what you won't query** — every table should map to a detection, an investigation need, or a compliance requirement.
- **Use the right table tier** — **Basic/Auxiliary logs** for high-volume, low-value data you only need for occasional search (much cheaper, limited query features) vs. Analytics tier for data your detections run on.
- **Commitment tiers** — significant discount over pay-as-you-go once volume is predictable.
- **Retention strategy** — short interactive retention plus cheap **archive** tier for compliance, with search jobs when you need old data.
- **Free data sources** — Azure Activity, Office 365 audit, Entra ID (some), and Defender XDR alerts are free to ingest.
- **Daily cap with alerting** — but understand the tradeoff: a cap that's hit means you stop ingesting and go blind, so alert on approaching it rather than relying on it.
- **Review regularly** — `Usage | summarize sum(Quantity) by DataType` to find the tables driving cost, then ask whether each is earning its keep.

## 290. How would you monitor Sentinel health?
- **Ingestion health** — `Heartbeat` for agent liveness; per-table volume trends with alerts on sudden drops (a 90% drop in firewall logs is an outage, and nothing else will tell you).
- **Connector health** — the `SentinelHealth` table for connector and playbook failures.
- **Analytics rule health** — rule execution failures, and rules that have produced **zero** alerts for an unusually long period (a rule that never fires is either perfectly tuned or silently broken — investigate which).
- **Playbook/automation health** — Logic App run failures.
- **Cost/quota** — daily cap proximity, unexpected volume spikes.
- **Queue health** — incident volume, age of open incidents, MTTA/MTTR trends.

Build all of this into a workbook plus a small set of analytics rules that alert on detection-health problems — the principle being that **a SOC must monitor its own visibility, because a broken pipeline looks exactly like a quiet day.**

---
[← Back to index](README.md) · [← Phase 10](phase-10-mitre-attack.md) · [Next: Phase 12 — KQL →](phase-12-kql.md)
