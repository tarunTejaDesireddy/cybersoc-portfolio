[← Back to index](README.md) | Tier 2 — Strong knowledge

# Phase 21 — L2 Troubleshooting (Q466–475)

These are operational scenario questions. They test whether you can keep the SOC's own machinery running — an L2 responsibility that L1 usually escalates. Answer every one with a **structured, narrowing sequence**, not a list of guesses.

## 466. Sentinel stopped receiving logs from a firewall. How do you troubleshoot?
Work outward from the destination to the source:
1. **Confirm and scope the gap** — exactly when did it stop, and is it all firewall logs or only some event types?
```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| summarize LastLog = max(TimeGenerated), Count = count() by DeviceName
| sort by LastLog asc
```
2. **Is it this one firewall or all of them?** All = collector/platform problem. One = device or path problem.
3. **Check the log forwarder VM** (the CEF/syslog collector) — is it running, is the `rsyslog`/`syslog-ng` daemon up, is the AMA agent healthy, and is the disk full? (Full disk silently stops syslog collection and is a classic cause.)
```bash
systemctl status rsyslog
df -h
tail -f /var/log/syslog
```
4. **Is the forwarder receiving anything at all?** `tcpdump -i any port 514` tells you in seconds whether traffic is arriving — this single check splits the problem cleanly into "network/source side" or "collector side."
5. **Check the network path** — firewall/NSG rules between the device and the collector; did someone change a rule?
6. **Check the source firewall's own config** — is it still configured to send syslog, to the right IP and port, and is its logging enabled? Check its own system log for send failures.
7. **Check the DCR** — is the data collection rule still associated with the collector and still selecting the right facilities/severities?
8. **Check ingestion limits** — daily cap reached, or workspace throttling.
9. **After fixing, add a detection-health alert** so the next silent failure is caught automatically rather than noticed weeks later.

## 467. A data connector suddenly stopped sending logs. What do you check?
1. **Connector status page** in Sentinel — last data received timestamp.
2. **Expired or rotated credentials** — the most common cause for API-based connectors: an expired client secret, a rotated API key, or a certificate past its expiry.
3. **Permission changes** — was the service principal's role removed, or did a Conditional Access policy start blocking it?
4. **Source-side changes** — was the integration disabled, licensing changed, or the API version deprecated at the provider?
5. **Agent health** — for agent-based connectors, check `Heartbeat`.
6. **API throttling/quota** — are you being rate-limited?
7. **Schema/API changes** upstream that broke ingestion.
8. **Recent changes** generally — check `AzureActivity` for who modified what around the time it stopped. "What changed?" resolves most of these faster than any other question.

## 468. An analytics rule stopped generating alerts. What do you investigate?
The dangerous part: a rule that stops firing looks identical to a quiet environment.
1. **Run the rule's query manually** over the same window — does it return rows?
2. **If no rows: is the underlying data still arriving?** Query the raw table. This is usually the answer — the rule is fine, the data stopped ([Q466/467](#466-sentinel-stopped-receiving-logs-from-a-firewall-how-do-you-troubleshoot)).
3. **Did the schema change?** A renamed or removed column silently breaks the query, and cloud vendors do change schemas.
4. **Check the rule's execution history** for failures, timeouts, or exceeded result limits.
5. **Is the rule still enabled?** And was it modified recently — check who changed it and what.
6. **Check automation rules** — is something auto-closing the incidents so they never appear in the queue?
7. **Check incident grouping** — are new alerts folding silently into one long-running incident?
8. **Check suppression settings** on the rule.
9. **Consider that it may be correct** — a rule that fired because of one misconfigured system may legitimately go quiet when that system is fixed. Verify by simulating the activity it should detect.

## 469. A playbook isn't executing. How do you troubleshoot it?
1. **Determine whether it's being triggered at all** — check the Logic App's **run history**. No runs = a trigger problem; failed runs = a logic/permissions problem.
2. **If no runs:** check the automation rule or analytics rule that should invoke it — is it enabled, do its conditions actually match, and is the playbook correctly attached?
3. **Check permissions on the trigger side** — Sentinel needs the `Microsoft Sentinel Automation Contributor` role on the playbook's resource group to run it.
4. **If runs are failing:** open the failed run and read the specific action that errored — Logic Apps shows you the exact input/output of each step, which usually names the problem outright.
5. **Common failure causes:** the managed identity lacks permission on the target (Sentinel Responder for incident comments, Key Vault Secrets User for secrets, Graph permissions for identity actions), an expired API connection needing re-authorization, an API rate limit, a malformed input from an entity that wasn't mapped, or a null value where the flow expected data.
6. **Check the Logic App is enabled** and not disabled/throttled.
7. **Test in isolation** — run it manually with a sample payload to separate the playbook's logic from the trigger path.

## 470. A Logic App failed during incident automation. What do you check?
1. **Open the specific failed run** and identify the failing action — Logic Apps gives you inputs, outputs, and the error per step.
2. **Read the error code** — `401/403` (permissions/authentication), `404` (target not found — often an entity that doesn't exist), `429` (throttling), `500` (downstream service failure), or a timeout.
3. **Check the managed identity's role assignments** against what the failing action needs.
4. **Check API connections** — OAuth connections expire and need re-consent; this is a very common cause of a playbook that "used to work."
5. **Check the input data** — did the incident have the entity the playbook expected? A playbook that assumes an IP entity fails on an incident that has none. **This is the most common real-world cause**, and the fix is defensive: add conditions to handle missing entities gracefully rather than assuming they're present.
6. **Check for transient failures** — if it's intermittent, add retry policies.
7. **Resubmit the run** after fixing, and confirm success.

## 471. KQL query returns no results. What do you check?
1. **Time range** — the most common cause by far. Is the window right, and does the data exist in it?
2. **Does the table have any data at all?** `TableName | take 10` — start there before debugging your logic.
3. **Remove filters one at a time** to find which one eliminates everything.
4. **Case sensitivity** — `==` is case-sensitive; try `=~`, or `has` instead of `contains`.
5. **Column names** — did the schema change, or is the column named differently than you assumed? `TableName | getschema`.
6. **Data type mismatches** — comparing a string to a number, or a `dynamic` field that needs `tostring()`/`parse_json()` first.
7. **Join type** — an `inner` join returns nothing when keys don't match; check the key values on both sides actually align (trailing spaces, case, domain-qualified vs. bare usernames are classic culprits).
8. **Ingestion delay** — the data may not have landed yet for very recent windows.
9. **Permissions** — do you have access to that table/workspace? RBAC can silently hide data.

## 472. KQL query is taking too long. How do you optimize it?
See [phase-12 Q324](phase-12-kql.md#324-how-do-you-optimize-a-slow-kql-query) for the full list. The priority order: **narrow the time range**, **filter before aggregating or joining**, use `has` over `contains`, `project` only needed columns early, put the smaller table on the left of a join, avoid unnecessary `sort`, and `materialize()` any subquery used more than once.

## 473. An alert suddenly generates 10,000 incidents. What do you do?
An alert storm — handle the flood first, then the cause.
1. **Stop the flood** — disable the rule immediately (or enable aggressive incident grouping). Leaving it running buries every other incident in the queue, which is itself a security risk.
2. **Determine whether it's a real event or a rule/data problem** — this is the critical fork, and getting it backwards is dangerous. **Look at a sample of the incidents before dismissing them:** 10,000 incidents could genuinely be a worm, a mass password spray, or a ransomware outbreak. Never disable-and-forget without checking.
3. **If it's a data/rule problem:** find what changed — new log source onboarded, schema change, a misconfigured device flooding logs, a rule edit, or a threshold that no longer suits the volume.
4. **If it's a real event:** escalate immediately as a major incident and switch to response mode.
5. **Bulk-close** the false incidents once you're certain, with a documented reason.
6. **Fix the root cause** — tune the rule, fix the source device, or adjust grouping.
7. **Re-enable and monitor** closely.
8. **Check ingestion cost impact** — an alert storm often comes with a log volume spike that can blow through the daily cap and cause a *second*, worse problem: blindness.

## 474. An important detection stopped triggering. How would you identify the problem?
Same diagnostic tree as [Q468](#468-an-analytics-rule-stopped-generating-alerts-what-do-you-investigate), but emphasize the **verification** step, because "important" means you cannot assume it's fine:
1. Query the rule's logic manually; check the underlying data is present.
2. Check schema changes, rule modifications, enabled state, and execution failures.
3. Check automation rules and grouping aren't hiding the incidents.
4. **Then prove it works** — simulate the activity the detection is supposed to catch (in a controlled way, e.g. Atomic Red Team or a safe test in a lab), and confirm the alert fires end to end.
5. Add a **detection-health monitor** for it: alert when a critical rule produces zero results for longer than its normal interval. Saying this unprompted is a strong L2 signal — it's the difference between fixing one rule and fixing the class of problem.

## 475. A firewall is sending duplicate logs. How would you investigate?
1. **Confirm true duplication** — are they byte-identical records with the same timestamp and session ID, or genuinely separate events that look similar (e.g., the same session logged at start and end, or logged by two rules)?
```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| summarize Count = count() by DeviceEventClassID, SourceIP, DestinationIP, DestinationPort, TimeGenerated
| where Count > 1
```
2. **Check for multiple forwarding paths** — the most common cause: the firewall is configured to send to two collectors that both forward to the same workspace, or the device was added to a new collector without removing the old one.
3. **Check for duplicate DCR associations** — the same data collected twice by overlapping Data Collection Rules.
4. **Check the collector configuration** — a syslog daemon configured to both write locally and forward, with the local file also being ingested.
5. **Check whether it's an HA pair** — both firewall nodes logging the same traffic is expected behavior, not a fault; you may need to filter by node.
6. **Check the device's own logging config** — the same event logged by multiple rules or at multiple stages of the policy.
7. **Fix and quantify the impact** — duplicates inflate ingestion cost (real money), can skew detection thresholds and cause double-counting in aggregations, and produce duplicate incidents. Mention the **cost** angle; it's the one people forget, and it's what management cares about.

---
[← Back to index](README.md) · [← Phase 20](phase-20-cloud-security.md) · [Next: Phase 22 — Detection Engineering →](phase-22-detection-engineering.md)
