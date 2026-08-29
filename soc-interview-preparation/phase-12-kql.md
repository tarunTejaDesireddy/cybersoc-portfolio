[← Back to index](README.md) | Tier 1 — Must master

# Phase 12 — KQL (Q291–324)

Expect to be asked to **write or explain a query on a whiteboard**. The queries below are the patterns that cover most of what gets asked. Learn the shapes, not the exact syntax — an interviewer cares that you know `summarize ... by` is how you find spraying, not that you remember every argument.

## 291. What is KQL?
Kusto Query Language — the read-only query language for Azure Data Explorer, Log Analytics, Sentinel, and Defender Advanced Hunting. Pipeline-based: data flows left to right through operators separated by `|`, each transforming the result of the previous one.

## 292. Explain the KQL pipeline.
```kql
SecurityEvent                                   // 1. Start with a table
| where TimeGenerated > ago(24h)                // 2. Filter early (performance)
| where EventID == 4625                         // 3. Filter more
| summarize FailCount = count() by Account, IpAddress   // 4. Aggregate
| where FailCount > 10                          // 5. Filter the aggregate
| sort by FailCount desc                        // 6. Order
| take 100                                      // 7. Limit
```
The golden rule to state out loud: **filter as early and as narrowly as possible** — time range first, then table-specific filters — because every subsequent operator processes less data.

## Core operators (293–307)

| # | Operator | What it does | Example |
|---:|---|---|---|
| 293 | `where` | Filters rows by condition | `\| where EventID == 4625` |
| 294 | `project` | Selects/renames columns (`project-away` removes) | `\| project TimeGenerated, Account, IpAddress` |
| 295 | `summarize` | Aggregates rows into groups | `\| summarize count() by Account` |
| 296 | `extend` | Creates a calculated column | `\| extend Hour = datetime_part("hour", TimeGenerated)` |
| 297 | `join` | Combines two tables on a shared key | `\| join kind=inner (Table2) on Account` |
| 298 | `union` | Stacks rows from multiple tables | `union SigninLogs, AuditLogs` |
| 299 | `parse` | Extracts values from a string by pattern | `\| parse Msg with "user=" User " ip=" IP` |
| 300 | `parse_json()` | Parses a JSON string into a dynamic object you can index | `\| extend d = parse_json(Payload) \| extend u = d.user` |
| 301 | `distinct` | Returns unique combinations of the given columns | `\| distinct Account, Computer` |
| 302 | `count()` | Counts rows (inside `summarize`); `count` alone counts the result set | `\| summarize count() by Account` |
| 303 | `bin()` | Rounds values into buckets — the basis of all time-series | `\| summarize count() by bin(TimeGenerated, 1h)` |
| 304 | `ago()` | Relative time from now | `\| where TimeGenerated > ago(7d)` |
| 305 | `between` | Inclusive range filter | `\| where TimeGenerated between (datetime(2026-01-01) .. datetime(2026-01-02))` |
| 306 | `has` | Matches a whole **term/word** (indexed, fast) | `\| where CommandLine has "mimikatz"` |
| 307 | `contains` vs `has` | `contains` matches any substring (slower, not indexed); `has` matches whole terms (much faster) | `has "net"` matches "net user" but not "network"; `contains "net"` matches both |

**Q307 is a favorite interview question.** The answer: *"prefer `has` — it uses the term index so it's far faster on large datasets. Use `contains` only when you genuinely need a partial-word match, like matching inside a URL or a filename fragment."* Also mention `has_any` for lists and `=~` for case-insensitive equality.

---

## Investigation queries (308–324)

### 308. How do you search for failed logins?
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress, LogonTypeName, SubStatus
| sort by TimeGenerated desc
```
Cloud equivalent:
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0            // 0 = success; anything else is a failure
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription, AppDisplayName
```

### 309. How do you find successful logins after multiple failures?
The classic brute-force-success pattern — a `join` between failures and successes:
```kql
let failures = SecurityEvent
    | where TimeGenerated > ago(24h)
    | where EventID == 4625
    | summarize FailCount = count(), FirstFail = min(TimeGenerated), LastFail = max(TimeGenerated)
        by Account, IpAddress
    | where FailCount >= 10;
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| join kind=inner failures on Account, IpAddress
| where TimeGenerated > LastFail          // success came AFTER the failures
| project SuccessTime = TimeGenerated, Account, IpAddress, Computer, FailCount, FirstFail, LastFail
```

### 310. How do you detect password spraying?
The distinguishing feature is **many distinct accounts from one source**, not many failures per account:
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize
    TargetedAccounts = dcount(UserPrincipalName),
    AccountList = make_set(UserPrincipalName, 50),
    Attempts = count()
    by IPAddress, bin(TimeGenerated, 15m)
| where TargetedAccounts >= 10                  // many accounts...
| extend AttemptsPerAccount = Attempts * 1.0 / TargetedAccounts
| where AttemptsPerAccount < 5                  // ...but few tries each = spraying
| sort by TargetedAccounts desc
```
The `dcount(UserPrincipalName)` grouped by source is the whole detection — explain that line if asked.

### 311. How do you identify a user logging in from multiple countries?
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| summarize
    Countries = dcount(Location),
    CountryList = make_set(Location),
    IPs = make_set(IPAddress, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName
| where Countries > 1
| extend WindowMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| sort by Countries desc, WindowMinutes asc
```

### 312. How do you identify unusual sign-in locations?
Compare against the user's own 30-day baseline — anomaly detection rather than a static list:
```kql
let lookback = 30d;
let baseline = SigninLogs
    | where TimeGenerated between (ago(lookback) .. ago(1d))
    | where ResultType == 0
    | summarize KnownLocations = make_set(Location) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| join kind=leftouter baseline on UserPrincipalName
| where isnotempty(Location) and KnownLocations !has Location
| project TimeGenerated, UserPrincipalName, Location, IPAddress, AppDisplayName, KnownLocations
```

### 313. How do you search for a malicious IP?
Search everywhere it could appear, not just one table:
```kql
let maliciousIP = "203.0.113.45";
union isfuzzy=true
    (SigninLogs | where IPAddress == maliciousIP
        | project TimeGenerated, Table="SigninLogs", Entity=UserPrincipalName, Detail=AppDisplayName),
    (SecurityEvent | where IpAddress == maliciousIP
        | project TimeGenerated, Table="SecurityEvent", Entity=Account, Detail=tostring(EventID)),
    (CommonSecurityLog | where SourceIP == maliciousIP or DestinationIP == maliciousIP
        | project TimeGenerated, Table="Firewall", Entity=DeviceName, Detail=DeviceAction),
    (DeviceNetworkEvents | where RemoteIP == maliciousIP
        | project TimeGenerated, Table="EDR", Entity=DeviceName, Detail=InitiatingProcessFileName)
| sort by TimeGenerated desc
```
`isfuzzy=true` means the query still runs if one of those tables doesn't exist in the workspace — a practical detail worth mentioning.

### 314. How do you search for a malicious hash?
```kql
let badHash = "a1b2c3...";
union isfuzzy=true
    (DeviceFileEvents | where SHA256 == badHash or MD5 == badHash
        | project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName),
    (DeviceProcessEvents | where SHA256 == badHash
        | project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName),
    (EmailAttachmentInfo | where SHA256 == badHash
        | project TimeGenerated, FileName, SenderFromAddress = "", RecipientEmailAddress = "")
| sort by TimeGenerated desc
```
Then `| summarize by DeviceName` to get the scoped host list immediately.

### 315. How do you search for a suspicious process?
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "wscript.exe", "cscript.exe")
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp desc
```
This one query is the `winword.exe → LOLBin` detection from [phase-16 Q378](phase-16-incident-response-scenarios.md#378-winwordexe--powershellexe-appears-on-a-workstation-is-it-malicious-how-do-you-investigate) — good one to have ready.

### 316. How do you investigate PowerShell execution using KQL?
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any (
    "-enc", "-EncodedCommand", "-w hidden", "-windowstyle hidden",
    "-nop", "-NoProfile", "bypass", "DownloadString", "DownloadFile",
    "IEX", "Invoke-Expression", "FromBase64String", "Net.WebClient")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine
| sort by Timestamp desc
```
Pair with script block logs for the de-obfuscated content:
```kql
SecurityEvent
| where EventID == 4104
| where EventData has_any ("DownloadString", "FromBase64String", "Invoke-Mimikatz")
| project TimeGenerated, Computer, EventData
```

### 317. How do you correlate authentication and process activity?
Join a logon to what the account then did on that host — the core L2 correlation pattern:
```kql
let suspiciousLogons = DeviceLogonEvents
    | where Timestamp > ago(24h)
    | where LogonType in ("RemoteInteractive", "Network")
    | where ActionType == "LogonSuccess"
    | project LogonTime = Timestamp, DeviceName, AccountName, RemoteIP;
DeviceProcessEvents
| where Timestamp > ago(24h)
| join kind=inner suspiciousLogons on DeviceName, AccountName
| where Timestamp between (LogonTime .. (LogonTime + 1h))   // processes within 1h of logon
| project LogonTime, ProcessTime = Timestamp, DeviceName, AccountName, RemoteIP,
          InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by ProcessTime asc
```

### 318. How do you identify lateral movement?
One account authenticating to an unusual number of distinct hosts:
```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive")
| summarize
    DistinctHosts = dcount(DeviceName),
    HostList = make_set(DeviceName, 50),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountName, RemoteIP
| where DistinctHosts >= 5
| extend DurationMin = datetime_diff('minute', LastSeen, FirstSeen)
| extend HostsPerMinute = DistinctHosts * 1.0 / iff(DurationMin == 0, 1, DurationMin)
| sort by DistinctHosts desc
```
`HostsPerMinute` distinguishes machine-speed movement from an admin working through hosts manually — a nice detail to point out.

### 319. How do you identify an account creating a new user?
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4720                        // user account created
| project TimeGenerated, Computer,
          NewAccount = TargetAccount,
          CreatedBy = SubjectAccount
| sort by TimeGenerated desc
```
Cloud equivalent:
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add user"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend NewUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, Actor, NewUser, Result
```

### 320. How do you find privileged group changes?
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)          // added to global/local/universal group
| where TargetAccount has_any ("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins")
| project TimeGenerated, Computer,
          Group = TargetAccount,
          MemberAdded = MemberName,
          PerformedBy = SubjectAccount
| sort by TimeGenerated desc
```

### 321. How do you investigate RDP activity using KQL?
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where LogonType == 10                        // RemoteInteractive = RDP
| summarize
    SessionCount = count(),
    SourceIPs = make_set(IpAddress, 20),
    Targets = make_set(Computer, 20)
    by Account, bin(TimeGenerated, 1d)
| sort by SessionCount desc
```
Add `| where ipv4_is_private(IpAddress) == false` to surface RDP from external addresses specifically.

### 322. How do you investigate suspicious DNS queries?
DNS tunneling indicators — long, high-entropy subdomains and high query volume to one parent domain:
```kql
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "DnsQueryResponse"
| extend QueryName = tostring(AdditionalFields.DnsQueryString)
| extend SubdomainLength = strlen(split(QueryName, ".")[0])
| extend ParentDomain = strcat(split(QueryName, ".")[-2], ".", split(QueryName, ".")[-1])
| summarize
    UniqueSubdomains = dcount(QueryName),
    QueryCount = count(),
    MaxSubdomainLength = max(SubdomainLength)
    by DeviceName, ParentDomain
| where UniqueSubdomains > 100 and MaxSubdomainLength > 30
| sort by UniqueSubdomains desc
```

### 323. How do you investigate possible C2 traffic using KQL?
Beaconing detection — look for **low variance in the interval** between connections:
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where isnotempty(RemoteIP)
| where ipv4_is_private(RemoteIP) == false
| sort by DeviceName, RemoteIP, Timestamp asc
| extend PrevTime = prev(Timestamp), PrevIP = prev(RemoteIP), PrevDevice = prev(DeviceName)
| where RemoteIP == PrevIP and DeviceName == PrevDevice
| extend IntervalSec = datetime_diff('second', Timestamp, PrevTime)
| summarize
    Connections = count(),
    AvgInterval = avg(IntervalSec),
    StdDevInterval = stdev(IntervalSec)
    by DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
| where Connections > 20 and StdDevInterval < 10      // very regular = beaconing
| sort by StdDevInterval asc
```
The `stdev` filter is the insight — regular intervals mean machine-driven, not human-driven. Explain that if asked.

### 324. How do you optimize a slow KQL query?
1. **Narrow the time range first** — the single biggest lever, always.
2. **Filter before you aggregate or join** — reduce rows as early in the pipeline as possible.
3. **Use `has` instead of `contains`** — term-indexed vs. full substring scan.
4. **`project` only the columns you need**, and do it early to reduce data carried through the pipeline.
5. **Avoid `search *` and wildcard table scans** — always name the table.
6. **Optimize joins** — put the **smaller table on the left**, use the narrowest `kind` (`innerunique` is the default and cheapest), and filter both sides before joining.
7. **Use `summarize` instead of `distinct`** on very large sets where appropriate.
8. **Replace joins with `union` + `summarize`** when you're only correlating on one key.
9. **Materialize repeated subqueries** with `let x = materialize(...)` so they're computed once.
10. **Avoid unnecessary `sort`** — it's expensive; use `top N by` instead of `sort` + `take`.
11. **Case-sensitive operators are faster** — `==` beats `=~`, `has_cs` beats `has`, when you know the casing.

---

## The five queries to memorize if you memorize nothing else

1. **Failed logons** — `SecurityEvent | where EventID == 4625 | summarize count() by Account, IpAddress`
2. **Password spray** — `SigninLogs | where ResultType != 0 | summarize dcount(UserPrincipalName) by IPAddress | where dcount_ > 10`
3. **Suspicious process ancestry** — `DeviceProcessEvents | where InitiatingProcessFileName in~ ("winword.exe","excel.exe") | where FileName in~ ("powershell.exe","cmd.exe")`
4. **Lateral movement** — `DeviceLogonEvents | summarize dcount(DeviceName) by AccountName | where dcount_DeviceName >= 5`
5. **Hash scoping** — `DeviceProcessEvents | where SHA256 == "<hash>" | distinct DeviceName`

If you can write those five on a whiteboard, you can talk your way through any KQL question they ask.

---
[← Back to index](README.md) · [← Phase 11](phase-11-microsoft-sentinel.md) · [Next: Phase 13 — Defender XDR / EDR →](phase-13-defender-xdr-edr.md)
