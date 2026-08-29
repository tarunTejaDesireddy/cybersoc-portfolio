[← Back to index](README.md) | Tier 3 — Know the concepts

# Phase 18 — SOC Operations (Q421–435)

## 421. How do you handle 20 incidents simultaneously?
1. **Triage the whole queue before working any single one** — spend the first few minutes scanning all 20 for severity and whether the threat is active, rather than starting at the top.
2. **Look for correlation first** — 20 "separate" incidents are often one attack. Grouping them saves enormous time and gives a truer picture of severity.
3. **Rank by impact and activity** — active/progressing incidents on critical assets first; static, contained, or low-confidence ones last.
4. **Quick-close the obvious** — known false positives and duplicates come out of the queue immediately.
5. **Escalate and delegate** — if the volume genuinely exceeds capacity, say so early and get help; hiding a backlog is worse than reporting one.
6. **Timebox** — don't sink an hour into a P4 while P1s wait.
7. **Communicate status** — keep the team lead informed on what's being worked and what's queued, so priorities can be reset with full information.
8. **Document as you go** — with 20 in flight, undocumented work is lost work.

## 422. How do you prioritize P1/P2/P3/P4 incidents?

| Priority | Typical definition | Examples |
|---|---|---|
| **P1 — Critical** | Active, severe business/mission impact; immediate response | Ransomware in progress, DC compromise, active data exfiltration, critical system down |
| **P2 — High** | Confirmed compromise, significant risk, not yet catastrophic | Confirmed malware on a server, credential compromise of a privileged account, active lateral movement |
| **P3 — Medium** | Suspicious activity needing investigation, limited/contained impact | Single-host malware blocked by AV, phishing click with no credential entry, policy violations |
| **P4 — Low** | Informational, minimal risk | Blocked scan attempts, low-confidence alerts, benign policy findings |

Priority = **impact × urgency**, with asset criticality and whether the attack is *still progressing* as the main modifiers. Say that formula rather than reciting a table — and note that priority isn't static: new evidence can and should re-prioritize an incident in either direction.

## 423. What is SLA?
Service Level Agreement — the committed timeframes the SOC operates to, usually defined per priority. Typically covers **time to acknowledge**, **time to begin investigation**, **time to contain**, and **time to resolve/close** — e.g., P1 acknowledged in 15 minutes, P4 within 8 hours. SLAs make performance measurable and set expectations with the business, but they also create a real risk worth naming: analysts optimizing for closing tickets fast rather than investigating properly.

## 424. What is MTTA?
**Mean Time To Acknowledge** — average elapsed time from alert generation to an analyst picking it up. Measures queue responsiveness and staffing adequacy. A rising MTTA usually means alert volume has outgrown the team, or the queue is full of noise.

## 425. What is MTTR?
**Mean Time To Respond** (or Resolve/Remediate — clarify which definition is in use, since organizations differ). Average time from detection to the incident being contained or fully resolved. The headline measure of SOC effectiveness, because it directly correlates with how much damage an attacker can do.

Caveat worth raising: MTTR is easily gamed by closing tickets quickly, and it's skewed by a few complex incidents — always read it alongside quality measures.

## 426. What SOC metrics would you monitor?

| Category | Metrics |
|---|---|
| **Speed** | MTTA, MTTD (mean time to detect), MTTR, dwell time |
| **Volume** | Alerts/day, incidents/day, incidents per analyst, escalation rate |
| **Quality** | False positive rate (overall and per rule), true positive rate, incidents reopened, incidents missed and found later |
| **Coverage** | MITRE ATT&CK technique coverage, log source coverage, endpoint agent deployment % |
| **Health** | Ingestion volume trends, connector/agent failures, rules producing zero alerts |
| **Operational** | SLA compliance, backlog age, shift handover completeness |

## 427. How do you measure SOC effectiveness?
Not by alert volume — a SOC that closes 10,000 alerts and misses the one real intrusion has failed. Measure it by:
- **Detection quality** — are real threats being caught, and how quickly (MTTD, dwell time)?
- **Response quality** — MTTR, and whether containment actually stopped the attack.
- **Coverage** — what fraction of relevant ATT&CK techniques do we have detections for, and are those detections actually working?
- **Validated capability** — purple team exercises, breach-and-attack simulation, and detection testing prove coverage rather than assuming it. This is the strongest answer: *"the only way to know your detections work is to test them."*
- **Learning loop** — do post-incident reviews produce new detections and closed gaps?
- **Missed detections** — incidents discovered by someone other than the SOC (a user, a third party, an audit) are the most honest failure metric there is.

## 428. How do you reduce alert fatigue?
- **Tune aggressively and continuously** — track FP rate per rule and fix the worst offenders ([phase-11 Q284](phase-11-microsoft-sentinel.md#284-how-do-you-tune-an-analytics-rule)).
- **Retire detections that don't earn their place** — a rule with 500 alerts and zero true positives in a year is negative value.
- **Enrich automatically** so analysts get context instead of doing five lookups per alert.
- **Group related alerts into single incidents** rather than presenting them individually.
- **Automate the mechanical work** — enrichment, known-benign auto-closure with documented conditions, ticket creation.
- **Prioritize the queue properly** so analysts aren't wading through P4s.
- **Rotate work** — sustained triage-only shifts burn people out; mix in hunting and detection work.
- **Fix the source** — sometimes the answer is a configuration change on the noisy system, not a SIEM-side exclusion.

## 429. How do you improve detection quality?
- **Prioritize by threat model** — build detections for the techniques your adversaries actually use, not everything in the matrix.
- **Detect behaviors (IOAs), not just indicators (IOCs)** — behavior survives the attacker changing hash/IP/domain.
- **Validate every detection against real or simulated attacks** (Atomic Red Team, purple teaming) before trusting it.
- **Measure per-rule TP/FP rates** and iterate.
- **Feed every incident back into detection** — each investigation reveals either a gap (write a new rule) or a delay (tune an existing one).
- **Layer detections** so one evasion doesn't blind you — endpoint, network, and identity signals for the same technique.
- **Version-control and peer-review rule changes**, so detections are engineered rather than accumulated.

## 430. How do you document an investigation?
Write it so someone with no context can pick it up cold and reach the same conclusion:
- **What triggered it** — alert, rule, time, source.
- **Entities involved** — users, hosts, IPs, hashes.
- **Investigation steps taken**, in order, including **what you checked and found nothing** (negative findings prevent duplicated work).
- **Evidence** — query results, log excerpts, screenshots, with links and timestamps.
- **Timeline** of the attacker activity, normalized to UTC.
- **Analysis and conclusion**, with confidence level and explicitly-stated assumptions.
- **Actions taken**, by whom and when.
- **MITRE mapping.**
- **Outcome/classification** and any follow-up items (tuning, detection gaps, remediation owed by another team).

Write it *during* the investigation, not after — reconstruction loses detail and is where mistakes get baked in.

## 431. What makes a good incident report?
- **Accurate and evidence-based** — every claim traceable to a source, inference clearly labelled as inference.
- **Clear timeline** in UTC.
- **Complete but readable** — an executive summary in business language for management, technical detail below for engineers.
- **Answers the questions people will ask**: what happened, how did they get in, what did they access, is it contained, what's the impact, could it happen again?
- **States what is unknown** and why, rather than papering over gaps.
- **Actionable recommendations** with owners.
- **Objective tone** — no blame, no speculation dressed as fact.

## 432. How do you perform incident handover between shifts?
1. **Update all tickets before handover** — current status, findings so far, next steps.
2. **Do a live verbal walkthrough** of anything active — written notes alone lose nuance on complex incidents.
3. **Prioritize explicitly** — say what needs attention first, not just what exists.
4. **Flag anything time-sensitive** — pending actions, awaiting responses, scheduled containment, SLA clocks running.
5. **Confirm receipt** — handover isn't complete until the incoming analyst acknowledges and has had a chance to ask questions.
6. **Stay reachable briefly** for follow-up questions on a complex incident.

## 433. What information should be included in shift handover?
- **Active incidents** — status, severity, what's been done, immediate next steps, and who owns them.
- **Pending actions** — awaiting a user response, a vendor, an approval, a scheduled task.
- **Escalations in flight** and who's engaged.
- **Environmental context** — outages, maintenance windows, known noisy alerts, planned pen tests or scans (this one prevents a whole shift being wasted investigating your own red team).
- **Tooling issues** — connectors down, agents failing, degraded log sources.
- **Threat context** — active campaigns, new IOCs, anything relevant from threat intel.
- **Anything unusual you noticed but haven't resolved** — even without a ticket.

## 434. How do you handle an incident when the required team is unavailable?
1. **Do what's within your authority** to limit damage now — containment actions you're authorized for shouldn't wait.
2. **Follow the escalation path** — on-call rotations, secondary contacts, management escalation. There's usually a documented path; use it rather than waiting.
3. **Document everything** you're doing and everything you can't do, so the arriving team starts with a complete picture.
4. **Preserve evidence** so their options aren't reduced by the delay.
5. **Continue monitoring** the situation rather than parking it.
6. **Communicate upward** — management needs to know a needed team is unreachable during an active incident; that's a decision for them, not something to absorb silently.
7. **Afterwards, raise the coverage gap** as a process finding.

## 435. What would you do if another analyst incorrectly closed a serious alert?
Handle it as a professional, not a confrontation.
1. **Verify first** — re-check the evidence yourself before raising anything; you may be missing context they had.
2. **Reopen and investigate immediately** if it's genuinely serious — the incident matters more than the etiquette.
3. **Speak to them directly and privately** — they may have had a reason, and if it was a genuine mistake, most people would rather hear it from a colleague than from their manager.
4. **Escalate to the team lead** if it's high-severity, if the impact is significant, or if it's part of a pattern — not to blame, but because the risk needs visibility.
5. **Look for the systemic cause** — was the runbook unclear, the alert poorly described, the training inadequate, or the analyst overloaded? Fixing that prevents recurrence better than correcting one person.
6. **Document the reopening and the rationale** properly.

Frame it in the interview as: *"the goal is the incident being handled correctly and the process improving — not proving a colleague wrong."*

---
[← Back to index](README.md) · [← Phase 17](phase-17-advanced-l2-investigation.md) · [Next: Phase 19 — Threat Intelligence →](phase-19-threat-intelligence.md)
