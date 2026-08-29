[← Back to index](README.md) | **Tier 1 — These decide the interview**

# Phase 25 — Questions Designed to Test L2 Thinking (Q521–535)

These aren't knowledge questions. They're **follow-ups** — the interviewer will drop them on you *after* you answer a scenario, to see whether your answer was memorized or reasoned. Expect to be interrupted mid-answer with one of these.

**The meta-rule:** every one of these questions is asking the same thing — *"can you separate what you know from what you assume?"* An L1 analyst defends their conclusion. An L2 analyst explains the evidence, states their confidence level, and names what would change their mind.

---

## 521. "You say this is malicious. Prove it."
Don't get defensive and don't restate the alert. Lay out the evidence chain, strongest first, and name your confidence.

> *"I'd base it on several independent indicators rather than one. First, the process lineage — winword.exe spawned PowerShell, which has no legitimate business reason. Second, the command line was base64-encoded with `-w hidden -nop`, which is obfuscation, not administration. Third, it made an outbound connection to a domain registered four days ago with no reputation history. Fourth, it wrote a binary to `%APPDATA%` and created a scheduled task pointing at it — that's persistence. Any one of those alone I'd call suspicious; together, and in that sequence, they match a known ATT&CK chain — T1566 into T1059.001 into T1053. That's what makes me call it malicious rather than unusual."*

The structure: **multiple independent indicators + the sequence they occurred in + a named technique mapping.** One indicator is a suspicion; a correlated chain is a conclusion.

## 522. "What evidence do you have?"
Distinguish the three tiers explicitly — this is what makes you sound rigorous:

| Tier | Meaning | Example |
|---|---|---|
| **Direct evidence** | Logged facts, not interpretation | 4688 shows this command line executed at 14:32:07 |
| **Corroborating evidence** | Independent sources agreeing | Firewall log confirms the outbound connection the EDR recorded |
| **Inference** | Reasoning from the above | Because the credential was dumped at 14:35 and used on another host at 14:41, the attacker likely reused it |

> *"I have direct evidence of X and Y from the endpoint and firewall logs. From those I infer Z, but I want to be clear that Z is inference — the log that would confirm it is [specific log], and here's whether we have it."*

## 523. "What would you check next?"
Never answer "nothing" or freeze. There is always a next check. Have a default ladder ready:

1. **Broaden the same entity** — full activity of this host/account across the whole retention window, not just the alert window.
2. **Pivot to a new entity** — the hash, the domain, the IP, the parent process, the user's other sessions.
3. **Check the other direction in time** — what happened *before* (initial access) and what's happened *since* (is it ongoing)?
4. **Check a different telemetry layer** — if I've been in endpoint data, go to network/identity/email.
5. **Check the negative** — what would I expect to see if this *were* benign, and is it there?

> *"Next I'd check whether this same hash appears anywhere else in the estate, because that turns a single-host finding into a campaign — and that changes the response."*

## 524. "What if that log isn't available?"
Never say "then I couldn't investigate." Name the substitute immediately (full mapping in [phase-17 Q408](phase-17-advanced-l2-investigation.md#408-what-would-you-do-if-logs-are-missing)):

> *"Then I'd pivot to a source that records the same event from a different vantage point. If I lost endpoint process logs, I'd use the SIEM-forwarded copy — it's already off the host, so an attacker clearing local logs doesn't remove it. If that's gone too, DNS and firewall logs still show me the network side, and forensic artifacts on disk — prefetch, AmCache, scheduled tasks, registry autoruns — still show execution. I'd also document the visibility gap as a finding, because if I can't see it during an incident, we can't detect it during the next one."*

That last sentence — turning the gap into a detection-engineering action item — is a strong L2 signal.

## 525. "What if the user says they did it legitimately?"
The trap: the naive answer is "then I close it as a false positive." **A user's statement is a data point to verify, not a verdict** — and if the account is compromised, the "user" telling you it was them may be the attacker, or the real user may not know their account was used.

> *"I'd take it seriously, but I'd verify it independently rather than close on the statement alone. I'd check whether the technical evidence matches their account of events — if they say they ran a script, does the command line match what they describe, from their normal device, at the time they say? If the details align, that's a benign positive and I'd document it and tune the rule. If they say they ran a script but the command was base64-encoded and originated from a Word document, then either they're mistaken about what they did or their session was used by someone else — and either way the alert stands."*

Also worth adding: *"and I'd confirm I'm talking to the actual user through a known channel, not replying to whoever contacted me."*

## 526. "How do you know this wasn't a false positive?"
Answer by describing what you **ruled out**, not what you found — that's the difference between a conclusion and a guess.

> *"Because I tested the benign explanations explicitly. The obvious ones here were: a sanctioned admin action, an enterprise management tool, or a scheduled job. I checked the change management system — no ticket in this window. I checked whether the parent process was a known management agent — it wasn't, it was a user-launched Office application. I checked whether this user or host has a baseline of similar activity — they don't, it's the first occurrence in 90 days. And I checked whether the destination is a known-good service — it's a domain registered four days ago. When every benign explanation fails and the malicious one fits all the evidence, I treat it as a true positive."*

## 527. "What is your hypothesis?"
They want to see structured thinking, not certainty. Give a **primary hypothesis with confidence, plus an alternative**, and what would distinguish them.

> *"My working hypothesis is initial access via a malicious email attachment, leading to PowerShell execution and a C2 callback — I'd put that at moderate-to-high confidence based on the process lineage and the network callout. The main competing hypothesis is a drive-by download from web browsing rather than email, which would fit the same endpoint evidence. What separates them is the email gateway logs and the proxy history in the ten minutes before execution — that's what I'd check to confirm which one it is."*

## 528. "How would you scope this incident?"
Answer with the **pivot loop**, not a vague "I'd check other machines":

> *"I'd pivot on every indicator I have and keep looping until nothing new comes back. On the file side: the hash, the filename, the write path. On the network side: the IP, the domain, and the TLS fingerprint. On the identity side: everywhere that account authenticated in the relevant window, and any credentials that had a session on the affected host. On the behavioral side: the same command-line pattern or parent-child relationship anywhere else. Every new host I find gets the same treatment, because each one may carry indicators the first didn't. Scope isn't established until a full pivot cycle returns nothing new — and I'd state the time window I searched, because scope is only as good as the retention behind it."*

## 529. "How do you know the attacker didn't move laterally?"
The honest and correct answer distinguishes "I found no evidence" from "it didn't happen."

> *"I don't know it with certainty — what I can say is what I checked and what I found. I checked authentication events for the compromised account across all hosts in the window, network connections from the affected host to internal systems, remote service creation and scheduled task creation on other machines, and RDP and SMB sessions originating from it. None of those showed movement. But the strength of that conclusion depends on my visibility — if some segment isn't logging to the SIEM, I'd say so explicitly rather than claim the environment is clean. And because credentials were exposed on that host, I'd reset them regardless, since the cost of doing so is low and the cost of being wrong is high."*

## 530. "How do you know the attacker didn't steal credentials?"
> *"Again, I'd frame it as what I verified. I checked for LSASS access from unexpected processes, for registry hive exports of SAM and SYSTEM, for credential-dumping tool signatures, and for any dump files written to disk. I checked whether the malicious process ran with the privileges needed to dump credentials at all — if it never had SYSTEM or admin rights, memory dumping was outside its reach, which is meaningful negative evidence. I also checked browser credential stores and any credential files in the user profile, because infostealers go there rather than LSASS. If the process had elevated rights and I have gaps in endpoint telemetry, I'd treat the credentials as potentially exposed and reset them anyway — assume-breach is cheaper than being wrong."*

## 531. "What would make you escalate this incident?"
Have concrete triggers ready, not "if it's serious":
- Confirmed compromise of a domain controller, privileged account, or critical/national-infrastructure system.
- Evidence the attacker is **currently active** (interactive session, live C2).
- Ransomware or any destructive activity.
- Confirmed data exfiltration or exposure of sensitive/regulated data.
- Lateral movement across segments or to more than a handful of hosts.
- Any containment action needed that exceeds my authority or has major business impact.
- Requirement for forensic imaging, memory analysis, or malware reverse engineering.
- **And: when the evidence is beyond what I can resolve with the tools and time I have.** Say this one — willingness to escalate early is treated as maturity, not weakness.

## 532. "What would you do first?"
The interviewer is testing prioritization instinct. The right first move depends on whether the threat is **active**:

> *"It depends on whether the activity is still ongoing. If there's an active, confirmed threat — encryption running, a live C2 session, an attacker moving between hosts — my first action is containment, because every minute of investigation costs more damage. If the activity has already stopped or is uncertain, my first action is validation and scoping, because containing on incomplete information can disrupt the business and can also tip off the attacker before I know how far they've reached."*

That conditional structure is the answer. A flat "I'd isolate the machine" or a flat "I'd investigate first" both read as L1.

## 533. "Would you isolate the machine immediately? Why?"
Never answer with an unqualified yes or no.

> *"For confirmed ransomware encryption or an active interactive C2 session — yes, immediately, because the damage is ongoing and compounding, and the cost of one machine being offline is trivially less than the cost of the spread. For a single low-confidence alert on a critical production server — no, not unilaterally. I'd validate first, look at whether targeted containment gets me most of the benefit (blocking the C2 destination at the firewall, killing the process, disabling the account), and involve the system owner in the decision. Either way I'd isolate rather than power off, so I keep memory and EDR visibility."*

## 534. "What would be the business impact of your containment action?"
They're checking whether you think past the security boundary.

> *"Isolating that host means whatever it serves is unavailable — so before I act I'd want to know what it does and who depends on it. On a user workstation the impact is one person's productivity, and I'd act without hesitation. On a domain controller, a database server, or a system supporting an operational or public-facing service, isolation could interrupt authentication or service delivery for a large number of users, so I'd present the risk and the options to the system owner and management rather than deciding alone. Disabling an account has the same shape — for a user it's one person, but for a service account it could take down a production dependency, so I'd map the dependencies first unless the compromise is severe enough that the outage is clearly the lesser cost."*

## 535. "What additional evidence would you need?"
Be specific — name the log source and what it would prove.

> *"Three things would materially change my confidence. First, the email gateway logs for the ten minutes before execution — that would confirm or rule out email as the initial access vector. Second, full script block logs from that host, because the command line was encoded and I want the de-obfuscated content to know exactly what it did. Third, network telemetry showing whether the outbound connection actually completed and how much data moved — that's the difference between an attempted callback and active exfiltration, which changes the severity and the response. If I can't get any of them, I'd document what remains unproven and give my confidence level rather than presenting inference as fact."*

---

## Drill this before you walk in

Take any scenario from [phase 16](phase-16-incident-response-scenarios.md), answer it out loud, and then hit yourself with three of these follow-ups. If your answer survives "prove it," "what if that log isn't available," and "how do you know it wasn't a false positive," you're interviewing at L2.

**Three habits that will carry you through anything they invent:**
1. **Separate fact from inference, out loud.** "The log shows X. From that I infer Y, but I'd confirm with Z."
2. **Never claim certainty you don't have — claim a method instead.** "I can't prove a negative, but here's exactly what I checked and what would change my answer."
3. **Always name the next step.** Even when you don't know the answer: *"I'm not certain — here's how I'd find out."* That sentence never loses you points, and "I don't know" alone always does.

---
[← Back to index](README.md) · [← Phase 24](phase-24-behavioral-questions.md)
