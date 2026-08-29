[← Back to index](README.md) | Tier 2 — Strong knowledge

# Phase 13 — Defender XDR / EDR (Q325–340)

## 325. What is EDR?
Endpoint Detection and Response — an agent on each endpoint that continuously records detailed behavioral telemetry (processes, files, registry, network, logons), detects malicious behavior against that telemetry, and gives analysts remote response capability (isolate the machine, kill a process, collect an investigation package, run a live-response script).

## 326. EDR vs antivirus?

| | Traditional AV | EDR |
|---|---|---|
| Detection basis | Signatures/hashes of known malware | **Behavior** and patterns, plus signatures |
| Catches unknown threats | Poorly | Yes — behavioral detection catches novel malware and fileless attacks |
| Telemetry retained | Minimal — a detection event | Rich, continuous, historical (weeks/months) |
| Investigation | Almost none — "found X, cleaned it" | Full process trees, timelines, hunting |
| Response | Quarantine/delete a file | Isolate host, kill process, remediate, live response |
| Fileless attacks | Largely blind | Detects (LOLBins, injection, in-memory execution) |

Modern products bundle both (Defender for Endpoint contains next-gen AV *and* EDR).

## 327. EDR vs XDR?
**EDR** covers endpoints only. **XDR** (Extended Detection and Response) correlates signals across endpoints **plus** identity, email, cloud apps, and cloud workloads into a single incident. The value is correlation: XDR can link the phishing email, the endpoint execution, and the subsequent identity compromise into one incident automatically, where EDR alone would only show you the endpoint piece and leave you to find the rest manually.

## 328. What is Microsoft Defender for Endpoint?
Microsoft's EDR (MDE) — combines next-gen antivirus, EDR, attack surface reduction rules, threat and vulnerability management, and automated investigation and response. Feeds Defender XDR and Sentinel, and is queried via **Advanced Hunting** in KQL.

## 329. What telemetry does EDR provide?
Process creation with full command lines and hashes, parent-child lineage, file create/modify/delete, registry modifications, network connections per process, logon events, loaded modules/DLLs, script content, WMI activity, driver loads, and detected alerts — retained historically so you can investigate what happened last week, not just what's happening now.

## 330. What is the Advanced Hunting table?
Advanced Hunting is Defender's KQL query interface over the raw telemetry (typically 30 days). "Tables" are the schema-defined datasets you query — `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceEvents`, plus identity (`IdentityLogonEvents`) and email (`EmailEvents`, `UrlClickEvents`) tables in Defender XDR.

## 331. What is DeviceProcessEvents?
Process creation telemetry. Key columns: `Timestamp`, `DeviceName`, `AccountName`, `FileName`, `FolderPath`, `ProcessCommandLine`, `SHA256`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `InitiatingProcessParentFileName`. **The most-used table in endpoint investigation** — it's where process-lineage analysis happens.

## 332. What is DeviceNetworkEvents?
Network connection telemetry **attributed to the process that made it** — which is what firewall logs can't give you. Key columns: `RemoteIP`, `RemotePort`, `RemoteUrl`, `LocalPort`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `ActionType`. Used for C2/beaconing detection and for answering "what process talked to that IP?".

## 333. What is DeviceLogonEvents?
Logon activity on endpoints: `AccountName`, `AccountDomain`, `LogonType` (Interactive, RemoteInteractive, Network, Batch, Service), `ActionType` (LogonSuccess/LogonFailed), `RemoteIP`, `RemoteDeviceName`, `IsLocalAdmin`. The lateral-movement table.

## 334. What is DeviceFileEvents?
File create/modify/rename/delete events: `FileName`, `FolderPath`, `SHA256`, `ActionType`, `InitiatingProcessFileName`, and `FileOriginUrl`/`FileOriginReferrerUrl` for downloaded files (which tells you where a file came from — very useful). Used for tracking payload drops, staged archives, and ransomware file modification.

## 335. How would you investigate a suspicious process in Defender?
1. **Open the device timeline** or query `DeviceProcessEvents` for the process.
2. **Build the full ancestry** — walk `InitiatingProcessFileName` upward until you reach a legitimate origin:
```kql
DeviceProcessEvents
| where DeviceName == "WKS-01" and Timestamp between (ago(2h) .. now())
| project Timestamp, AccountName, InitiatingProcessParentFileName,
          InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256, FolderPath
| sort by Timestamp asc
```
3. **Examine the command line** and the file path (unusual locations = suspicious).
4. **Check the hash** — signature status and reputation.
5. **Check what it did** — join to `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents` filtered on the same process/time window.
6. **Check persistence** created around the same time.
7. **Scope** — hunt the hash and command-line pattern across all devices.
8. **Decide** — contain or close, with reasoning.

## 336. How would you investigate suspicious network connections?
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName == "WKS-01"
| where ipv4_is_private(RemoteIP) == false
| summarize
    Connections = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Ports = make_set(RemotePort, 10)
    by RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Connections desc
```
Then assess: which process, destination reputation and domain age, port (standard or unusual), whether the pattern is periodic (beaconing — see [phase-12 Q323](phase-12-kql.md#323-how-do-you-investigate-possible-c2-traffic-using-kql)), data volume, and whether other devices contact the same destination.

## 337. How would you isolate a machine?
In the Defender portal: select the device → **Isolate device** (full isolation cuts all network communication except the Defender agent's connection to the service, so you retain visibility and control; **selective isolation** allows Outlook/Teams/Skype so the user can still be contacted). Also available via API/Graph for automation, and via a Sentinel playbook.

Always: document the reason, notify the user and system owner, and remember **isolation is reversible — powering off is not, and destroys memory evidence.**

## 338. When should you isolate an endpoint?
See [phase-17 Q417](phase-17-advanced-l2-investigation.md#417-when-would-you-isolate-a-machine). Isolate for: active ransomware encryption, confirmed C2/active attacker session, confirmed credential dumping, active lateral movement from the host, or confirmed malware execution not fully blocked. Weigh more carefully for: critical production servers (consider targeted containment and involve the owner), weak/single low-confidence signals, and cases where isolation would destroy evidence you need.

## 339. What is endpoint remediation?
The actions that remove the threat and restore the host to a trustworthy state: quarantine/delete malicious files, kill and block the malicious process, remove persistence (services, scheduled tasks, registry autoruns, WMI subscriptions), block the file hash tenant-wide, reset credentials that were exposed on the host, patch the exploited vulnerability, and verify the host is clean before releasing isolation. For confirmed deep compromise (rootkit, or an attacker with SYSTEM for an extended period), **rebuild from known-good rather than clean in place** — say this, because trusting a cleaned box after a serious compromise is a common junior mistake.

Defender also has **Automated Investigation and Response (AIR)**, which can perform much of this automatically at configurable automation levels.

## 340. How would you investigate a ransomware incident using EDR?
1. **Isolate affected devices immediately** — encryption is ongoing damage.
2. **Identify the encrypting process:**
```kql
DeviceFileEvents
| where Timestamp > ago(6h)
| where DeviceName == "SRV-01"
| where ActionType in ("FileModified", "FileRenamed")
| summarize FilesTouched = count(), Extensions = make_set(tostring(split(FileName,".")[-1]), 10)
    by InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, 5m)
| where FilesTouched > 100
| sort by FilesTouched desc
```
Mass file modification by a single process in a short window is the encryption signature.
3. **Check for the recovery-inhibition precursors** — these often precede encryption by minutes and are the highest-value detection point:
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("vssadmin delete shadows", "wbadmin delete",
        "bcdedit /set", "recoveryenabled no", "wmic shadowcopy delete")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```
4. **Trace back to initial access** — walk the process ancestry and the device timeline backwards, often days.
5. **Look for the pre-encryption stages** — credential dumping (LSASS access), lateral movement (`DeviceLogonEvents`), and **data staging/exfiltration** (large archives created, big outbound transfers) — double extortion means a data breach may have already occurred.
6. **Determine the deployment mechanism** — how did it reach all the hosts (GPO, PsExec, scheduled task, a compromised admin account)?
7. **Scope** — every device with the ransomware binary hash or the same behavioral pattern.
8. **Escalate** to IR/management immediately, and preserve evidence.

---
[← Back to index](README.md) · [← Phase 12](phase-12-kql.md) · [Next: Phase 14 — Network Security / Firewalls →](phase-14-firewalls-network-security.md)
