[← Back to index](README.md) | Tier 2 — Strong knowledge

# Phase 22 — Detection Engineering (Q476–490)

Every "how would you detect X" answer should follow the same shape: **the behavior → the data source → the logic → the false positives → the tuning lever.** If you name the false positives unprompted, you sound like someone who has actually deployed detections rather than just written queries.

## 476. How would you create a detection for password spraying?
- **Behavior:** one source, few attempts each, across many distinct accounts.
- **Data source:** `SigninLogs` (cloud) / `SecurityEvent` 4625 (on-prem).
- **Logic:** group by source IP in a time window; count **distinct** targeted accounts; alert when distinct accounts exceed a threshold and attempts-per-account stays low.
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize TargetedAccounts = dcount(UserPrincipalName),
            Attempts = count(),
            Accounts = make_set(UserPrincipalName, 50)
    by IPAddress, bin(TimeGenerated, 15m)
| where TargetedAccounts >= 10 and (Attempts * 1.0 / TargetedAccounts) < 5
```
- **False positives:** a misconfigured application with stale credentials hitting many service accounts, a security scanner, a NAT gateway aggregating many legitimate users behind one IP (this last one is the big one — a corporate egress IP always looks like one source).
- **Tuning:** exclude known corporate egress and scanner IPs via a watchlist, and raise the threshold to match your environment's baseline.
- **Uplift:** alert with much higher severity if any of the sprayed accounts subsequently **succeeded** from the same source.

## 477. How would you create a detection for brute force?
- **Behavior:** many attempts against **one** account.
- **Logic:** group by account (and source), count failures in a window, threshold, and — most importantly — check for a subsequent success:
```kql
let failures = SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType != 0
    | summarize Failures = count(), LastFail = max(TimeGenerated) by UserPrincipalName, IPAddress
    | where Failures >= 20;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| join kind=inner failures on UserPrincipalName, IPAddress
| where TimeGenerated > LastFail
| project TimeGenerated, UserPrincipalName, IPAddress, Failures
```
- **False positives:** a user with a cached old password on a phone/mail client (extremely common), an expired service account credential, a broken application retry loop.
- **Tuning:** threshold to your environment; treat "failures only" as low severity and **"failures then success"** as high.

## 478. How would you detect suspicious PowerShell?
- **Data sources:** `DeviceProcessEvents` (command lines), Event 4104 (script block, de-obfuscated), 4688 with command-line auditing.
- **Logic:** match on obfuscation and download-cradle indicators, **plus** anomalous parent process — the combination is what makes it high-fidelity:
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String",
        "DownloadString", "DownloadFile", "IEX", "Invoke-Expression",
        "-w hidden", "-nop", "bypass", "Net.WebClient")
      or InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe",
        "mshta.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```
- **False positives:** SCCM/Intune and other management tooling routinely run encoded PowerShell; legitimate admin scripts; some vendor installers.
- **Tuning:** exclude management agents **by parent process and signed path**, not by the command-line pattern (excluding the pattern would blind the detection entirely). This distinction is a good one to raise — it shows you tune without breaking the rule.

## 479. How would you detect a new administrator account?
- **Data:** 4720 (account created) + 4728/4732 (added to privileged group), `AuditLogs` for Entra.
- **Logic:** alert on any account creation followed shortly by addition to a privileged group, or on any addition to a privileged group at all (these are rare enough to alert on unconditionally in most environments).
```kql
SecurityEvent
| where EventID in (4728, 4732, 4756)
| where TargetAccount has_any ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| project TimeGenerated, Computer, Group = TargetAccount, Member = MemberName, Actor = SubjectAccount
```
- **False positives:** legitimate provisioning by IT, automated onboarding pipelines.
- **Tuning:** correlate against the change-management system if it's queryable; exclude approved provisioning service accounts by name; alert at higher severity outside business hours.

## 480. How would you detect privilege escalation?
Layer multiple detections rather than one:
- **Windows:** 4672 (special privileges), 4728/4732 (group additions), 4697/7045 (service running as SYSTEM), token manipulation alerts from EDR, UAC bypass patterns.
- **AD-specific:** ACL changes on privileged objects, delegation changes, GPO modification, DCSync (4662).
- **Azure/Entra:** role assignment writes at subscription scope, PIM activation anomalies, Global Admin elevation to Azure resources, credentials added to privileged service principals ([phase-20 Q463](phase-20-cloud-security.md#463-how-would-you-detect-privilege-escalation-in-azure)).
- **Linux:** SUID changes, sudoers modification, UID 0 account creation.
- **False positives:** legitimate admin work, automated provisioning, scheduled maintenance.
- **Tuning:** the highest-value refinement is **context, not thresholds** — same action, different severity depending on whether the actor is a known admin, from a known admin workstation, within a change window.

## 481. How would you detect lateral movement?
- **Logic:** one account authenticating to an unusual number of distinct hosts in a short window ([phase-12 Q318](phase-12-kql.md#318-how-do-you-identify-lateral-movement)), plus remote execution artifacts (7045 service creation across hosts, `wsmprovhost.exe` children, WMI process creation), plus 4648 explicit credential use.
- **Best signal:** deviation from the account's own baseline — comparing to a 30-day per-account host set beats any fixed threshold, because "5 hosts" is normal for an admin and alarming for a receptionist.
- **False positives:** administrators doing legitimate multi-host work, vulnerability scanners, backup and monitoring agents, software deployment tools.
- **Tuning:** exclude service accounts and scanners **by name**, and baseline per-account rather than globally.

## 482. How would you detect credential dumping?
- **Highest-fidelity signal:** **process access to `lsass.exe`** with memory-read rights from a process outside a small allow-list. This is one of the best detections in all of endpoint security — high true-positive rate, low volume.
```kql
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "csrss.exe", "wininit.exe", "services.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
- **Also detect:** `comsvcs.dll` MiniDump via rundll32, `procdump` against lsass, registry hive exports (`reg save hklm\sam`), `ntdsutil`/NTDS.dit copy on a DC, and DCSync (4662 replication from a non-DC).
- **False positives:** AV/EDR agents, backup software, and some monitoring tools legitimately open LSASS handles.
- **Tuning:** maintain an explicit allow-list of legitimate accessors — and review it periodically, because attackers masquerade as these very processes.

## 483. How would you detect C2?
- **Beaconing** — low standard deviation in connection intervals to the same destination ([phase-12 Q323](phase-12-kql.md#323-how-do-you-investigate-possible-c2-traffic-using-kql)).
- **Newly registered domains** — connections to domains registered in the last 30 days.
- **DNS anomalies** — high unique-subdomain counts under one parent, high-entropy names (DGA), unusual record types, high NXDOMAIN rates.
- **TI matching** — known C2 IPs/domains, and JA3/JA3S TLS fingerprints of known frameworks.
- **Protocol mismatch** — non-TLS traffic on 443, non-DNS traffic on 53.
- **Rare-destination analysis** — a destination contacted by exactly one host in the whole estate is inherently more interesting than one contacted by hundreds.
- **False positives:** software update checks, telemetry, monitoring agents, and legitimate SaaS polling all beacon.
- **Tuning:** allow-list known-good beaconing processes/destinations by **process + destination pair**, and weight severity by process reputation and destination age.

## 484. How would you detect data exfiltration?
- **Volume anomalies** — outbound bytes far above the host's or user's baseline, particularly off-hours.
- **Destination-based** — uploads to personal cloud storage, file-sharing sites, or newly-seen external destinations.
- **Staging behavior** — large archive creation (`.7z`, `.zip`, `.rar`) in temp directories, often the best *early* signal because it precedes the transfer.
- **Mass file access** — one account reading an unusual number of files from a share in a short period.
- **Protocol abuse** — DNS query volume spikes, ICMP tunneling, unusual outbound protocols.
- **Email-based** — large attachments or bulk forwarding to external addresses.
- **False positives:** legitimate large backups, cloud sync clients, video conferencing, software distribution, and developers pushing large artifacts.
- **Tuning:** baseline per host/user role rather than a single global threshold, and exclude sanctioned services explicitly.

## 485. How would you detect ransomware?
Detect the **precursors**, not the encryption — by the time files are encrypting, you've lost.
- **Highest-value, earliest signal:** shadow copy and backup deletion —
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin delete shadows", "wmic shadowcopy delete",
        "wbadmin delete catalog", "bcdedit /set {default} recoveryenabled no",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures")
```
These run minutes before encryption and are almost never legitimate.
- **Mass file modification** — one process modifying/renaming hundreds of files in minutes.
- **Ransom note creation** — the same new filename appearing across many directories.
- **Known extension patterns** and known family hashes.
- **Earlier still:** the credential dumping and lateral movement that precede deployment — catching those is catching ransomware days early, which is the answer that impresses.
- **False positives:** legitimate backup software deleting old shadow copies, mass file operations by archiving/migration tools, encryption software.
- **Tuning:** allow-list the specific backup product by signed path, and keep the shadow-copy-deletion detection at high severity regardless — the false positive rate is low enough to justify it.

## 486. How do you tune a detection?
Covered in [phase-11 Q284](phase-11-microsoft-sentinel.md#284-how-do-you-tune-an-analytics-rule). The sequence: measure the FP rate → categorize the FPs to find the common cause → apply the **narrowest** fix that removes that class → test against historical data to confirm true positives still fire → document the change and its reason in the rule → monitor → re-validate periodically because exclusions rot.

The principle to state: **tune the exclusion, not the detection.** Broadening the rule until it goes quiet is how detections get silently disabled.

## 487. How do you test a detection?
1. **Historical validation** — run the logic over past data and confirm it would have caught known true positives.
2. **Controlled simulation** — execute the technique safely in a lab or an approved test window: **Atomic Red Team** (per-technique test scripts), Caldera, or a purple-team exercise. Name Atomic Red Team specifically; it signals you've done this.
3. **End-to-end verification** — confirm not just that the query returns rows, but that the alert fires, the incident is created, entities map correctly, and any automation runs.
4. **Negative testing** — confirm it doesn't fire on the benign equivalent of the same activity.
5. **Volume testing** — run over 30 days to estimate how many incidents it will generate before you deploy it.
6. **Re-test after changes** — to the rule, the data source, or the environment.

## 488. How do you measure detection effectiveness?
- **True positive rate and false positive rate per rule** — the basic scorecard.
- **Time to detect (MTTD)** and dwell time — did it catch things quickly?
- **Coverage validated by testing**, not assumed — what percentage of the techniques you claim to cover actually fire when simulated?
- **Missed detections** — incidents found by someone else (a user, another team, an external party) that a detection should have caught. The most honest metric there is.
- **Alert-to-incident conversion rate** — how much of what a rule produces is worth an analyst's time?
- **Rules producing zero alerts** — investigate whether they're perfectly tuned or silently broken.

## 489. What is detection coverage?
The measure of which adversary techniques your detections can actually catch, typically mapped against the **MITRE ATT&CK matrix** and visualized as a heat map (e.g., with the ATT&CK Navigator).

The important nuances to raise, because they separate a thoughtful answer from a naive one:
- Coverage is **not** binary per technique — you might detect one sub-technique or one implementation and miss others.
- **Claimed coverage ≠ validated coverage.** A rule that exists but doesn't work is worse than no rule, because it creates false confidence. Only testing turns claimed coverage into real coverage.
- **Prioritize by threat model** — full-matrix coverage is neither achievable nor sensible; cover what your adversaries actually do first.
- Coverage depends on **data sources** — you cannot detect what you don't log, so gaps in the heat map are often log-source gaps, not rule gaps.

## 490. How would you map detections to MITRE ATT&CK?
1. **Tag every rule** with its tactic(s) and technique/sub-technique ID at creation time — Sentinel has fields for this, so it flows into reporting automatically.
2. **Map by what the rule actually detects**, not by what it's named — a rule detecting `vssadmin delete shadows` is T1490 (Inhibit System Recovery), not T1486 (Data Encrypted for Impact), even though it's a ransomware rule.
3. **Be honest about partial coverage** — mark whether you detect a technique fully or only one specific implementation.
4. **Build the heat map** (ATT&CK Navigator) to visualize coverage, weighted by the techniques relevant to your threat model.
5. **Feed incidents back in** — every incident's technique chain shows which steps you detected and which you missed; each miss becomes a detection backlog item.
6. **Review periodically** — ATT&CK is updated regularly, and new sub-techniques can turn "covered" into "partially covered."

---
[← Back to index](README.md) · [← Phase 21](phase-21-l2-troubleshooting.md) · [Next: Phase 23 — Automation / SOAR →](phase-23-automation-soar.md)
