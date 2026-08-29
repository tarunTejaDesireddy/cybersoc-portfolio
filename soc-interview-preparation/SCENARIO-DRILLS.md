[← Back to index](README.md) | **Practice file — use this the night before**

# Scenario Drills — rapid-fire practice

[Phase 16](phase-16-incident-response-scenarios.md) has the full worked answers. **This file is for practice**: cover the answer, say yours out loud, then check.

Speaking the answers out loud matters more than reading them. An answer you've only read collapses under a follow-up; one you've said three times doesn't.

---

## How to use this in 45 minutes

1. **Round 1 (20 min)** — work through the 15 drills below. Answer out loud, 60-90 seconds each, without looking first.
2. **Round 2 (15 min)** — redo the ones you fumbled, this time adding a scope step and an ATT&CK mapping to each.
3. **Round 3 (10 min)** — pick any 5 and hit yourself with three probes from the [probe list](#the-probe-list) after each.

**Score yourself.** A good answer contains: (a) a validation step, (b) at least three specific evidence sources named, (c) a scope step, (d) a decision with a reason, (e) the false-positive path acknowledged. Miss the scope step or the FP path and it's an L1 answer — do it again.

---

## Drill 1 — "You see `winword.exe → powershell.exe`. Walk me through it."

<details><summary>Answer skeleton</summary>

Suspicious, not proven — Word has no legitimate reason to spawn a shell, but I'd prove it before acting.

**Evidence chain:** decoded PowerShell command line + script block (4104) → which document was opened → where that document came from (email / download / share) → any further children (cmd, rundll32, mshta) → network callouts and downloads → persistence created → did the user authenticate elsewhere afterwards.
**Scope:** same hash/domain/IP or the same parent-child pattern on other hosts; all other recipients of that email.
**ATT&CK:** T1566 → T1204 → T1059.001.
**Decision:** obfuscated command + unfamiliar domain + persistence = isolate, treat as confirmed. A legitimate enterprise macro = benign positive, tune and document.

[Full answer](phase-16-incident-response-scenarios.md#378-winwordexe--powershellexe-appears-on-a-workstation-is-it-malicious-how-do-you-investigate)
</details>

## Drill 2 — "500 failed logins, then one success on the same account."

<details><summary>Answer skeleton</summary>

**Characterize the failures:** one account or many? One source or many? (One account, many attempts = brute force.)
**The success is the key:** timestamp, source IP/ASN, device, MFA satisfied?, logon type.
**Critical fork:** did the success come from the *same source* as the failures (brute-force success) or a *different trusted source* (probably the legitimate user, coincidence)? Rule this out explicitly — it's the false-positive path.
**Then:** what did the account do after? Is it privileged?
**Decision:** same-source success → disable/reset, revoke sessions, scope for lateral movement. MFA held and the success is the real user → document attempted brute force, block the source, verify MFA coverage.

[Full answer](phase-16-incident-response-scenarios.md#373-one-account-has-500-failed-logins-followed-by-a-successful-login-investigate)
</details>

## Drill 3 — "Impossible travel: Qatar and another country, 10 minutes apart."

<details><summary>Answer skeleton</summary>

**Lead with: this is frequently benign.** Rule out corporate VPN egress, cloud/proxy IPs, mobile carrier NAT, and a second device left behind.
**Compare both sign-ins:** IP, **ASN type** (datacenter vs. residential vs. carrier), device ID (registered/compliant?), user agent, application, MFA state on each.
**Then:** any follow-on activity from the suspicious one — inbox rules, mass downloads, app consents, role changes?
**Verify with the user — and independently.**
**Decision:** unfamiliar device + hosting ASN + follow-on activity = compromise (revoke sessions, reset, scope). Explained by VPN/roaming = benign positive, tune with named locations.

[Full answer](phase-16-incident-response-scenarios.md#374-one-account-successfully-authenticates-from-qatar-and-another-country-within-10-minutes-investigate)
</details>

## Drill 4 — "A host beacons to the same external IP every 60 seconds."

<details><summary>Answer skeleton</summary>

**Say it immediately: that's beaconing — classic C2.** Then justify and rule out benign polling.
**Check:** which process (signed? known?), regularity/jitter, destination reputation + **domain age** + ASN + certificate, payload size consistency, and when it started (correlate with a phishing click or a software install).
**Scope:** other hosts contacting the same destination.
**Decision:** unknown process + newly registered domain + fixed interval = isolate, block at the perimeter, find the implant and its persistence, hunt the initial access.
**FP path:** update checkers, monitoring agents, and telemetry all beacon — which is why process identity matters more than the interval alone.

[Full answer](phase-16-incident-response-scenarios.md#383-a-machine-makes-periodic-connections-to-the-same-external-ip-every-60-seconds-what-does-this-suggest)
</details>

## Drill 5 — "A user is added to Domain Admins."

<details><summary>Answer skeleton</summary>

**Critical until proven authorized.**
**Get:** Event 4728 — who did it, from where, when. **Verify against change management directly**, not just from the log.
**If unauthorized, remove the membership immediately** — one of the few actions justified before the investigation completes, because standing Domain Admin is catastrophic.
**Then:** how did the actor obtain the rights to do this, is the actor itself compromised, what has the added account done since (DC logons, DCSync, credential dumping), and what *parallel* persistence exists (other new accounts, services, GPO changes)?
**Escalate** — and raise the krbtgt double-reset question if DC compromise is suspected.

[Full answer](phase-16-incident-response-scenarios.md#389-a-user-is-added-to-domain-admins-what-do-you-do)
</details>

## Drill 6 — "The Windows event log was cleared on a server."

<details><summary>Answer skeleton</summary>

**Anti-forensics — treat as malicious until proven otherwise (T1070.001).**
**Get Event 1102:** who cleared it, which host, when, which channel, and what time window is now missing.
**Key move — pivot to sources the attacker can't reach:** SIEM-forwarded copies already off the box, EDR telemetry, Sysmon (separate channel), network/firewall/proxy/DNS logs, DC-side authentication records.
**Then:** investigate the account that cleared it, and look hard at what happened *immediately before* the clear — that window is exactly what they wanted hidden.
**Decision:** escalate. Legitimate log clearing is rare and always tied to documented maintenance.

[Full answer](phase-16-incident-response-scenarios.md#390-windows-event-log-was-cleared-what-does-that-indicate)
</details>

## Drill 7 — "LSASS access from an unknown process."

<details><summary>Answer skeleton</summary>

**Credential dumping until proven otherwise (T1003.001) — one of the highest-fidelity signals in endpoint security.**
**Check:** the accessing process (path, hash, signature, parent, command line), the **access mask** (memory-read rights vs. a harmless handle), and whether it's on the legitimate-accessor allow-list (AV/EDR, backup tools do touch LSASS).
**Look for:** a dump file written to disk around the same time, and any exfiltration of it.
**Assume every credential with a session on that host is compromised.**
**Then:** check for immediate reuse — authentication from that host to others right after (Pass-the-Hash/Ticket).
**Decision:** isolate, reset every account that had a session there (privileged first), scope for lateral movement, escalate.

[Full answer](phase-16-incident-response-scenarios.md#396-you-discover-lsass-access-from-an-unknown-process)
</details>

## Drill 8 — "A workstation scans hundreds of internal IPs."

<details><summary>Answer skeleton</summary>

**Internal reconnaissance — a workstation has no legitimate reason to port-scan.**
**Rule out first:** an authorized vulnerability scanner or asset-discovery tool. This is the #1 false positive — check the source against known scanner infrastructure before anything else.
**Characterize:** which process is scanning, which ports (445/3389/22 focus = lateral-movement targeting), sequential vs. randomized, speed.
**Then:** how did the host get this capability (what was downloaded/executed), did any connections succeed, did authentication follow on scanned hosts?
**Decision:** unauthorized internal scanning = isolate (recon means the attacker is actively working right now), then hunt backwards for initial access. ATT&CK T1046.

[Full answer](phase-16-incident-response-scenarios.md#386-one-workstation-scans-hundreds-of-internal-ip-addresses-investigate)
</details>

## Drill 9 — "A user entered credentials into a phishing page."

<details><summary>Answer skeleton</summary>

**Confirmed credential compromise — contain first, investigate second.**
1. Reset the password **AND revoke all sessions/refresh tokens** — *a reset alone does not kill a stolen token.* (Say this explicitly; it's the most commonly missed step.)
2. Check sign-in logs for attacker use already: unfamiliar IPs/ASNs, countries, devices.
3. Check MFA: was it satisfied? Was a **new MFA method registered** by the attacker?
4. Check mailbox persistence: new inbox rules (auto-forward/delete), delegate permissions, OAuth consents.
5. Check for lateral action — SharePoint/OneDrive access, outbound mail, on-prem authentication.
6. Scope: who else received the phish and submitted?

[Full answer](phase-16-incident-response-scenarios.md#372-a-user-entered-credentials-into-a-phishing-page-what-do-you-do)
</details>

## Drill 10 — "Several machines start encrypting files simultaneously."

<details><summary>Answer skeleton</summary>

**Ransomware outbreak — declare a major incident and escalate immediately.**
**Priority order (this ordering is what's being tested):**
1. Contain **broadly, not host-by-host** — at outbreak speed, per-host isolation loses the race. Consider segment-level blocking and disabling the propagating account domain-wide.
2. **Protect DCs, backup infrastructure, and file servers first** — attackers target backups deliberately.
3. Identify and cut the propagation mechanism (compromised privileged account + SMB/PsExec/GPO/scheduled task).
4. *Then* patient zero, entry vector, and — critically — whether data was **exfiltrated before encryption** (double extortion = a data breach with its own obligations).
5. Verify backup integrity; preserve evidence throughout.

**Say the reasoning:** *"during an active outbreak, containment and backup protection outrank root cause analysis — you can investigate a contained environment, but you can't decrypt one."*

[Full answer](phase-16-incident-response-scenarios.md#394-several-machines-begin-encrypting-files-simultaneously)
</details>

## Drill 11 — "Lateral movement from one workstation to 20 servers."

<details><summary>Answer skeleton</summary>

**Major incident — escalate while you investigate.**
**Identify:** the source workstation and the **credential** being used (usually one compromised privileged account is the enabler).
**Identify the technique:** SMB/PsExec (7045 service creation), WMI, WinRM (5985/5986, `wsmprovhost.exe` children), RDP (4624 type 10), or scheduled tasks.
**Build the timeline:** which server first, in what order, and what happened on each afterwards (data staged? more persistence? more credential dumping? ransomware precursors?).
**Contain:** disable the credential (coordinate if it's a service account with production dependencies), isolate the source and the most critical targets.
**Scope beyond the 20** — assume the list is incomplete until you've queried that credential's authentication across the whole estate.
**Then:** initial access on the source workstation — that's the gap that has to close.

[Full answer](phase-16-incident-response-scenarios.md#398-you-detect-lateral-movement-from-one-workstation-to-20-servers-investigate)
</details>

## Drill 12 — "A server connects outbound to an unknown IP on port 4444."

<details><summary>Answer skeleton</summary>

**Port 4444 = Metasploit default listener. A server doing this is worse than a workstation** (higher value, usually tighter egress policy).
**Check:** the process and its full lineage; whether the connection succeeded; whether it's **beaconing or a sustained session** (sustained = interactive reverse shell = attacker hands on keyboard *right now*).
**Destination:** reputation, ASN, geolocation, first-seen date.
**How did it get there:** recently written binary? Web shell on an internet-facing app? Exploited service? Check web server logs if applicable.
**Also check:** credential access on the server (it holds service-account credentials), and lateral movement outward.
**Decision:** isolate/network-contain — but on a *critical* server, weigh business impact, coordinate with the owner, and consider targeted containment (block the destination, kill the process) instead. Preserve memory. Escalate.

[Full answer](phase-16-incident-response-scenarios.md#392-a-server-suddenly-starts-communicating-with-an-unknown-external-ip-over-port-4444)
</details>

## Drill 13 — "DNS traffic spikes dramatically from one host."

<details><summary>Answer skeleton</summary>

**Prime suspect: DNS tunneling** (exfiltration or C2 over DNS).
**Check the queries themselves:** long, high-entropy, random-looking subdomains under one parent domain is the signature. Unusual record types (TXT, NULL). One parent domain receiving thousands of unique subdomain queries is the giveaway.
**Identify the querying process** on the host.
**Rule out benign:** a misconfigured app in a retry loop, a security scanner, an AV reputation-lookup service, a broken DNS cache.
**Decision:** confirmed tunneling → isolate, block the domain, treat as active exfiltration/C2 with full scoping.

[Full answer](phase-16-incident-response-scenarios.md#385-dns-traffic-suddenly-increases-dramatically-from-one-host-investigate)
</details>

## Drill 14 — "A new administrator account appeared unexpectedly."

<details><summary>Answer skeleton</summary>

**Get:** 4720 (created) + 4728/4732 (added to admin group) — who created it, from which host, when.
**Verify:** was there an approved change request? (Fastest resolution either way.) Is the *creator* account itself compromised?
**Look at the name:** attackers mimic service accounts (`svc_backup`, `admin_helpdesk`) or near-copies of real admins.
**Check:** what the new account has done since; and **parallel persistence** — new services, scheduled tasks, or other accounts created around the same timestamp (attackers rarely plant just one).
**Decision:** no matching change request → **disable it** (cheap to reverse, expensive to leave), **preserve rather than delete** for evidence, escalate as confirmed privilege escalation/persistence.

[Full answer](phase-16-incident-response-scenarios.md#388-a-new-administrator-account-is-created-unexpectedly-investigate)
</details>

## Drill 15 — "A critical production server is compromised. What now?"

<details><summary>Answer skeleton</summary>

**The word "critical" changes everything — this tests business judgment, not just technical instinct.**
1. **Escalate and engage stakeholders immediately** — IR, the system owner, management. You don't unilaterally take a critical server offline.
2. **Assess:** what access does the attacker have, what's the evidence, is it still active?
3. **Present containment options with risk** — full isolation vs. targeted containment (block the C2 destination, kill the process, disable the compromised account) that preserves service availability. **Give options, don't just ask permission.**
4. **Preserve evidence before remediation** — memory and disk image; rebuilding destroys the trail.
5. **Determine data exposure** — drives regulatory/notification obligations.
6. **Scope laterally** — service accounts on that server are now suspect everywhere they're used.
7. **Eradication:** for confirmed compromise, rebuild from known-good rather than clean in place, plus credential rotation.

[Full answer](phase-16-incident-response-scenarios.md#399-a-critical-server-is-compromised-what-is-your-response)
</details>

---

## The probe list

After every answer, have someone (or yourself) ask three of these. Full worked responses in [phase 25](phase-25-l2-thinking-questions.md).

1. *"You say it's malicious. Prove it."*
2. *"What evidence do you actually have — and what's inference?"*
3. *"What would you check next?"*
4. *"What if that log isn't available?"*
5. *"What if the user says they did it legitimately?"*
6. *"How do you know it wasn't a false positive?"*
7. *"What's your hypothesis? What's the competing one?"*
8. *"How would you scope this?"*
9. *"How do you know the attacker didn't move laterally?"*
10. *"How do you know they didn't steal credentials?"*
11. *"What would make you escalate?"*
12. *"What would you do first?"*
13. *"Would you isolate it immediately? Why?"*
14. *"What's the business impact of that containment action?"*
15. *"What additional evidence would you need?"*

---

## Three sentences that never lose you points

1. *"The log shows X. From that I infer Y — but that's inference, and Z is what would confirm it."*
2. *"I can't prove a negative, but here's exactly what I checked, and here's what would change my answer."*
3. *"I'm not certain — here's how I'd find out."*

---
[← Back to index](README.md) · [Cram sheet](00-CRAM-SHEET.md) · [Full scenario answers](phase-16-incident-response-scenarios.md)
