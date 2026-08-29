[← Back to index](README.md)

# The Cram Sheet — read this last before you walk in

Everything highest-yield in one place. If you only read one file, read this one. Re-read it the morning of the interview and nothing else.

---

## 1. The answer structure that wins every scenario question

```
1. Validate  — is this real? What exactly fired and why?
2. Investigate — evidence chain: process tree → command line → network → persistence
3. Scope    — same hash/domain/IP/account anywhere else?
4. Decide   — contain / escalate / close, and WHY
5. Act      — least disruptive action that actually contains it
6. Document — timeline, ATT&CK mapping, what changed afterwards
```

**The universal opener** (use it whenever you need a second to think):
> *"First I'd confirm the alert is real and understand exactly what fired — then I'd scope it before taking containment action, because containing on a false positive has a business cost and containing too narrowly lets the attacker keep moving."*

**The one conditional that makes you sound senior:**
> *"It depends on whether the threat is still active. If it's active — encryption running, live C2, attacker moving — I contain first. If it's stopped or uncertain, I validate and scope first."*

---

## 2. Windows Event IDs — memorize this table

| ID | Meaning | Why it matters |
|---:|---|---|
| **4624** | Successful logon | **Check Logon Type**: 2=interactive, 3=network/SMB, 10=RDP |
| **4625** | Failed logon | Many per account = brute force; few across many accounts = **spraying** |
| 4634 / 4647 | Logoff / user-initiated logoff | Session end |
| **4648** | Logon with explicit credentials | **Lateral movement / runas / PsExec signature** |
| **4672** | Special privileges assigned | Admin-level logon |
| **4688** | Process created | Needs command-line auditing enabled to be useful |
| **4697 / 7045** | Service installed (Security / System log) | **Persistence + PsExec lateral movement** |
| **4720** | User account created | New account = persistence |
| **4728 / 4732** | Added to global / local security group | **Privilege escalation** |
| 4740 | Account locked out | Correlate with 4625 bursts |
| **4768** | Kerberos TGT requested | AS-REQ; AS-REP Roasting signal |
| **4769** | Kerberos service ticket requested | **Burst across many SPNs + RC4 = Kerberoasting** |
| 4771 | Kerberos pre-auth failed | Kerberos failed logon |
| **4662** | Directory object access | **Replication GUIDs from non-DC = DCSync** |
| **1102** | **Audit log cleared** | **Huge red flag — anti-forensics, escalate** |

**Logon types:** 2 = interactive (at the console), 3 = network (SMB/share), 4 = batch, 5 = service, **10 = RemoteInteractive (RDP)**, 11 = cached.

**Investigation groupings:**
- Account compromise → 4625 → 4624 → 4768/4769 → 4672
- Privilege escalation → 4728/4732 → 4720 → 4672 → 4697/7045
- Lateral movement → 4624 (type 3/10) → **4648** → 4697/7045
- Persistence → 4697/7045 → 4720 → 4728/4732 → 1102

---

## 3. Ports — the ones that come up

| Port | Service | Attack relevance |
|---|---|---|
| 21/20 | FTP | Plaintext creds |
| **22** | SSH | Brute force target |
| 23 | Telnet | Plaintext — any use is a finding |
| 25 | SMTP | Phishing/spam relay |
| **53** | DNS (UDP/TCP) | **Tunneling, exfil, C2** |
| 80 / **443** | HTTP / HTTPS | Most C2 hides in 443 |
| 135 | RPC | Windows lateral movement |
| 139 / **445** | NetBIOS / **SMB** | **PsExec, ransomware spread, NTLM relay** |
| 389 / **636** | LDAP / LDAPS | AD recon |
| 1433 | MSSQL | Lateral movement, xp_cmdshell |
| 3268/3269 | AD Global Catalog | Forest-wide recon |
| **3389** | **RDP** | **Ransomware initial access + lateral movement** |
| **5985/5986** | **WinRM** | PowerShell remoting lateral movement |
| **4444** | *(no legit service)* | **Metasploit default — treat as C2** |

**RFC1918 private ranges:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

---

## 4. Suspicious process trees — the instant red flags

**Normal:** `smss → wininit → services → svchost` | `winlogon → userinit → explorer → user apps`
- `lsass.exe` parent must be **wininit.exe** — anything else is masquerading
- `svchost.exe` parent must be **services.exe**

**Always suspicious:**
```
winword.exe / excel.exe / outlook.exe  →  powershell.exe / cmd.exe / wscript.exe
browser  →  powershell.exe
Any Office app  →  mshta / rundll32 / regsvr32 / certutil
Unknown process  →  handle to lsass.exe    (= credential dumping)
```

**LOLBins to name:** `rundll32`, `regsvr32`, `mshta`, `certutil`, `wscript`/`cscript`, `bitsadmin`, `msbuild`, `wmic`, `powershell`

**Malicious PowerShell flags:** `-enc` / `-EncodedCommand`, `-w hidden`, `-nop`, `-ExecutionPolicy Bypass`, `DownloadString`, `IEX`, `FromBase64String`, `Net.WebClient`

---

## 5. AD attacks — one line each

| Attack | What it is | Detection |
|---|---|---|
| **Password spray** | 1 password → many accounts | Many 4625, **many distinct accounts, one source IP** |
| **Kerberoasting** | Request TGS for SPN accounts, crack offline | **4769 burst, many SPNs, RC4 (0x17)** |
| **AS-REP Roasting** | Target accounts with pre-auth disabled | 4768 for pre-auth-disabled accounts |
| **Pass-the-Hash** | Reuse NTLM hash without cracking | 4624 type 3 with NTLM, unusual source |
| **Pass-the-Ticket** | Reuse a stolen Kerberos ticket | Ticket used from a different host than issued |
| **Golden Ticket** | Forged TGT using **krbtgt hash** | Odd ticket lifetimes, 4769 with no 4768 → **fix = reset krbtgt TWICE** |
| **Silver Ticket** | Forged service ticket | **Never touches the DC** — check target host logs |
| **DCSync** | Fake DC requesting password replication | **4662 replication GUIDs from a non-DC** |
| **PsExec** | Remote exec via SMB + service creation | **7045/4697** + ADMIN$ write + named pipe |

---

## 6. The five KQL queries to have ready

```kql
// 1. Failed logons
SecurityEvent | where EventID == 4625
| summarize count() by Account, IpAddress

// 2. Password spraying — the key is dcount of ACCOUNTS by SOURCE
SigninLogs | where ResultType != 0
| summarize Accounts = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 15m)
| where Accounts >= 10

// 3. Office spawning a shell
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe")

// 4. Lateral movement — one account, many hosts
DeviceLogonEvents | where ActionType == "LogonSuccess"
| summarize Hosts = dcount(DeviceName) by AccountName
| where Hosts >= 5

// 5. Scope a hash across the estate
DeviceProcessEvents | where SHA256 == "<hash>" | distinct DeviceName
```

**`contains` vs `has`:** `has` matches whole terms and uses the index — **faster, prefer it**. `contains` matches any substring — slower, use only for partial matches.

**Optimize a slow query:** narrow the time range → filter before joins/aggregations → `has` not `contains` → `project` early → smaller table on the left of a join.

---

## 7. MITRE ATT&CK — the tactic order

```
Recon → Resource Dev → Initial Access → Execution → Persistence → Priv Esc →
Defense Evasion → Credential Access → Discovery → Lateral Movement →
Collection → C2 → Exfiltration → Impact
```

**Techniques worth naming by ID:** T1566 Phishing · T1059.001 PowerShell · T1003.001 LSASS Memory · T1021.001 RDP / .002 SMB · T1550.002 Pass-the-Hash · T1558.003 Kerberoasting · T1070.001 Clear Event Logs · T1053.005 Scheduled Task · T1486 Data Encrypted for Impact · **T1490 Inhibit System Recovery** (shadow copy deletion — best early ransomware signal)

**Cyber Kill Chain (7, strictly sequential):** Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives

---

## 8. Incident response lifecycle

**Preparation → Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned** (cyclical)

**Containment thresholds:**
- **Isolate immediately:** ransomware encrypting, live C2 session, confirmed credential dumping, active lateral movement
- **Weigh carefully:** critical production server (use targeted containment — block the C2 IP, kill the process, disable the account — and involve the system owner)
- **Always: isolate, don't power off** — preserves memory and EDR visibility

**Escalate to L3/IR when:** DC or privileged account compromise · attacker actively on keyboard · ransomware · confirmed exfiltration · wide scope · action beyond your authority · you're stuck

---

## 9. The things people forget (say these and you stand out)

1. **A password reset does NOT kill a stolen session token — you must revoke sessions/refresh tokens.**
2. **Golden Ticket fix = reset krbtgt password TWICE** (AD keeps the previous key).
3. **FP vs BP:** false positive = the *detection* was wrong; benign positive = the activity really happened but was authorized.
4. **Blocked vs allowed connection** changes severity completely — establish it early.
5. **A user saying "that was me" is a data point to verify, not a verdict** — a compromised account produces exactly that answer.
6. **Detection order ≠ compromise order** — the host that alerted first is often not patient zero.
7. **Shadow copy deletion (`vssadmin delete shadows`) precedes ransomware encryption by minutes** — best early detection there is.
8. **Scope isn't established until a full pivot cycle returns nothing new.**
9. **Log clearing (1102) is itself evidence** — pivot to SIEM-forwarded copies the attacker can't reach.
10. **"I don't know, but here's how I'd find out"** always beats guessing.

---

## 10. Sentinel one-liners

- **Entity mapping** — maps query columns to Account/Host/IP/File entities; without it the incident can't be pivoted or fed to playbooks
- **Scheduled vs NRT rule** — NRT runs every minute but can't do joins/unions or multiple tables
- **Automation rule** = lightweight triggers/conditions/actions · **Playbook** = a Logic App doing the work
- **Hunting query** = manual, exploratory, noise-tolerant · **Analytics rule** = automatic, creates incidents, must be high-fidelity
- **Cost control** — filter at the DCR, use Basic/Auxiliary tier for high-volume low-value data, commitment tiers, archive retention
- **Missing logs** — check `Heartbeat`, connector status, agent, DCR, network path, credentials, daily cap
- **Rule stopped firing** — run the query manually; usually the *data* stopped, not the rule

---

## 11. Behavioral — the two answers to have word-perfect

**"Tell me about yourself"** — 90 seconds: present role → how you grew into L2 work → why this role specifically.

**"Why Lekhwiya?"** — national security mission, not commercial: the systems protected are national infrastructure and government services, so the cost of a miss is public impact rather than business loss; the adversaries are state-level and APT rather than commodity; and you're committed to building your career in Qatar long-term.

**STAR** — Situation, Task, **Action (60% of your answer)**, Result. Say **"I"**, not "we". Always finish with **what changed afterwards** (a tuned rule, a new detection, an updated runbook).

Have **four incidents** ready: (1) most complex, (2) a false positive you tuned, (3) high-pressure, (4) a mistake you owned.

---

## 12. If they interrupt you with a probe

| They ask | You answer |
|---|---|
| *"Prove it."* | Multiple independent indicators + the sequence + the ATT&CK mapping |
| *"What evidence?"* | Separate **direct evidence** from **inference**, out loud |
| *"What next?"* | Broaden the entity → pivot to a new entity → check a different telemetry layer |
| *"What if that log's gone?"* | Name the substitute source, then flag it as a visibility gap to fix |
| *"User says it was them."* | Verify independently — does the technical evidence match their account? |
| *"How do you know it's not an FP?"* | Describe what you **ruled out**, not what you found |
| *"Would you isolate it?"* | Never unqualified yes/no — depends on active-vs-static and asset criticality |
| *"Business impact?"* | Name who's affected and offer targeted containment as the alternative |

---

**Last thing before you walk in:** they are not testing whether you memorized definitions. They're testing whether you can reason from evidence to a decision and justify it. When in doubt, slow down, say what you'd check and why, and name what would change your mind.

Good luck.

---
[← Back to index](README.md) · [Scenario drills →](SCENARIO-DRILLS.md)
