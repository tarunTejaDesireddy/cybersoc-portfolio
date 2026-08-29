[← Back to index](README.md) | Tier 2 — Strong knowledge

# Phase 14 — Network Security / Firewalls (Q341–357)

## 341. How does a firewall work?
It evaluates each packet/connection against an ordered rule set and takes the action of the **first matching rule** (allow, deny, or drop). Modern stateful firewalls track connection state, so return traffic for an established session is permitted automatically. Next-generation firewalls add application identification, user identity awareness, TLS inspection, and integrated IPS.

Two details interviewers probe: rules are evaluated **top-down, first match wins** (so rule order matters enormously), and there is an implicit **deny-all** at the bottom.

## 342. What is a firewall rule?
A policy entry specifying match criteria and an action. Typical fields: source (IP/subnet/zone/user), destination (IP/subnet/zone), service/port, protocol, application (on NGFW), action (allow/deny/drop), logging setting, and schedule.

Worth noting: **deny vs. drop** — deny sends a rejection (RST/ICMP unreachable) so the sender knows immediately; drop silently discards, which slows down attackers scanning you but also makes legitimate troubleshooting harder.

## 343. Inbound vs outbound traffic?
**Inbound** = originating outside, destined for internal resources — the traditional focus, protecting exposed services. **Outbound** = originating internally, going out.

The SOC-relevant point: **outbound is where compromise shows itself.** Once an attacker is inside, everything they do — C2 beaconing, tool downloads, data exfiltration — is outbound. Many organizations still have tight inbound rules and permissive outbound rules, which is exactly backwards for detecting an active intrusion. Egress filtering (allowing outbound only to what's needed, via approved proxies) is the control that closes it.

## 344. What is deny-by-default?
The principle that anything not explicitly permitted is denied — the implicit final rule in any well-built policy. The alternative (allow-by-default with a blocklist) fails because you can only block what you already know is bad. Deny-by-default is the foundation of zero-trust network design.

## 345. What is a firewall NAT rule?
A rule translating addresses as traffic passes through: **source NAT/PAT** (internal private IPs → one public IP for outbound), **destination NAT** (a public IP:port → an internal server, i.e. port forwarding for published services), or static one-to-one NAT.

SOC relevance: to attribute an external connection back to a specific internal host, you need the NAT translation log (source IP, source port, translated port, timestamp) — without it, all you know is "someone behind that public IP." This is a classic investigation blocker worth naming.

## 346. What is an IPS signature?
A pattern definition the IPS matches traffic against — byte sequences, protocol anomalies, or behavioral thresholds — mapping to a known exploit, malware C2 protocol, or attack technique. Each has an ID, severity, and configurable action (alert, block, drop). Signature quality varies: generic signatures produce heavy false positives, which is why signature tuning is ongoing work.

## 347. What is a network intrusion?
Unauthorized access to or activity within a network — exploiting an exposed service, using stolen credentials over a remote access service, or an attacker moving laterally after an initial foothold.

## 348. How would you investigate an IPS alert?
1. **Read the signature** — what exactly does it detect, and how specific is it? Generic signatures ("Suspicious HTTP request") warrant more skepticism than precise ones ("CVE-2024-XXXX exploit attempt").
2. **Determine the action taken** — was it **blocked or only alerted**? This drives severity: a blocked exploit attempt is a nuisance; an allowed one may have succeeded.
3. **Identify source and destination** — external → internal (attack attempt), internal → external (possible compromise, much more serious), or internal → internal (lateral movement, most serious).
4. **Check the target's exposure** — is the destination actually running the vulnerable service and version, and is it patched? An IIS exploit against a Linux box is noise.
5. **Look at the payload** if captured — does it contain a real exploit or is it a scanner probe?
6. **Check the source's history** — one-off, or part of a sustained scan/attack pattern? Known-bad reputation?
7. **Check for success indicators on the target** — new processes, outbound connections, new accounts, unusual authentication, in the minutes after the alert.
8. **Decide** — if blocked and unsuccessful: document, block the source if warranted, and tune if it's noisy. If potentially successful: escalate to host-level investigation immediately.

## 349. How do you determine whether an IDS/IPS alert is legitimate?
- **Does the target actually exist and run the targeted software/version?** (Vulnerability data and asset inventory answer this fastest.)
- **Does the traffic match the signature's real intent**, or is it a coincidental byte-pattern match?
- **Was there a response from the target** consistent with success (versus a connection reset or an error)?
- **Is there corroborating evidence on the endpoint** — new processes, files, network connections?
- **Is the source known-bad**, or a known scanner/vulnerability-management tool of your own?
- **Does the alert recur constantly** from the same internal source at the same time? That pattern usually means a misconfigured application or an authorized scanner, not an attack.
- **Was it blocked?** If the IPS dropped it, the attack didn't complete.

## 350. How would you investigate port scanning?
1. **Characterize the scan** — source IP, how many destination IPs and ports, over what time, in what order, and which ports specifically.
2. **Internal or external source?** External scanning of your perimeter is constant background noise on the internet and usually low priority. **Internal** scanning is a serious finding — a workstation has no reason to scan.
3. **Rule out authorized scanning** — your own vulnerability scanner, asset discovery, or network monitoring tooling. Check the source against known scanner IPs first; this is the most common resolution.
4. **Check what ports were targeted** — 445/3389/22 focus suggests lateral-movement targeting rather than general reconnaissance.
5. **Check for successful connections** — did anything respond and get connected to, and was there authentication afterwards?
6. **If internal**: identify the process doing the scanning on that host, and investigate how it got there — recon means the attacker is already inside and actively working.
7. **Decide** — unauthorized internal scanning justifies isolating the host and hunting for the initial compromise.

## 351. How would you investigate brute-force traffic?
1. **Determine the pattern** — many attempts against one account (brute force) or few attempts across many accounts (spraying)? Group the logs by source and by target to see which.
2. **Identify the targeted service** — RDP, SSH, VPN, web login, SMB — each has different exposure implications.
3. **Determine whether anything succeeded** — this is the critical question; failures alone are noise, a success is an incident.
4. **Check the source** — external IP reputation and geolocation, or internal (which would suggest an already-compromised host attacking internally).
5. **Check whether the service should be internet-exposed at all** — internet-facing RDP is itself a finding to remediate.
6. **Check MFA** — was it enforced, and did it hold?
7. **Respond** — block the source IP, confirm account lockout policies are effective, reset credentials for any account that was successfully accessed, and remediate the exposure (put the service behind VPN/Conditional Access).

## 352. How would you investigate C2 communication?
1. **Identify the internal host and the process** making the connections (EDR gives you the process; firewall logs alone won't).
2. **Characterize the pattern** — periodicity and jitter, connection duration, payload sizes, and consistency ([phase-12 Q323](phase-12-kql.md#323-how-do-you-investigate-possible-c2-traffic-using-kql)).
3. **Profile the destination** — IP/domain reputation, domain registration age, hosting ASN, certificate details, whether it resolves to many IPs (fast flux), and whether it's a legitimate service being abused.
4. **Check whether connections succeeded** and how much data moved in each direction — large outbound volumes shift this from C2 to exfiltration.
5. **Correlate to the host's activity** — what ran just before the connections started, and what persistence exists?
6. **Scope** — every host contacting the same infrastructure.
7. **Contain** — block the destination at the perimeter (protects everyone immediately), isolate confirmed hosts, and remove the implant and its persistence.

## 353. How would you investigate suspicious outbound traffic?
1. **Define what makes it suspicious** — unusual destination, unusual port, unusual volume, unusual timing, or a new destination never seen before?
2. **Identify the source host and process.**
3. **Assess the destination** — reputation, category, age, geography, and whether the organization has any business relationship with it.
4. **Assess volume and direction** — sustained large outbound transfer is potential exfiltration and raises severity sharply.
5. **Assess timing** — off-hours transfers from a workstation nobody is using are a strong signal.
6. **Check the protocol/port mismatch** — traffic on port 443 that isn't TLS, or DNS traffic that isn't DNS-shaped, indicates tunneling.
7. **Correlate with endpoint activity** and check whether other hosts do the same.
8. **Decide** — block and isolate if malicious; if it turns out to be a legitimate business service nobody baselined, document it and add it to the known-good list so it stops generating alerts.

## 354. What firewall logs are important for SOC analysts?
- **Connection/traffic logs** — source/destination IP and port, protocol, action (allow/deny), bytes sent/received, session duration, and the rule that matched.
- **NAT translation logs** — essential for attributing external connections to internal hosts ([Q345](#345-what-is-a-firewall-nat-rule)).
- **Threat/IPS logs** — signature matches and actions.
- **URL filtering / web logs** — destinations and categories.
- **VPN logs** — user, source IP, connect/disconnect times, duration.
- **Admin/configuration change logs** — who changed which rule and when. Attackers with firewall access open paths for themselves, and unexplained rule changes are a serious finding.
- **System/health logs** — so you know when the firewall stopped logging.

## 355. What is a blocked connection vs allowed connection?
**Blocked** = policy denied it; the communication did not happen. **Allowed** = it was permitted and the session proceeded.

Investigative significance: a **blocked** connection to a malicious destination means your controls worked — still worth investigating *why the host tried*, because something on it is trying to reach attacker infrastructure — but the immediate risk is lower. An **allowed** connection to a malicious destination means the communication succeeded, and you must assume whatever it was going to do, it did. Severity, urgency, and containment decisions hinge on this distinction, so establish it early in any network investigation.

## 356. How can firewall logs help investigate phishing?
- Confirm whether hosts actually **connected** to the phishing URL's IP (and whether it was allowed or blocked), which tells you who was genuinely exposed versus who merely received the mail.
- Establish **timing** — connection time versus email delivery time confirms causation.
- **Scope** by finding every internal host that contacted the phishing infrastructure, including users who never reported it.
- Detect **follow-on activity** — connections to second-stage payload servers or C2 after the click.
- Identify **data submission** indirectly (an established session with meaningful outbound bytes suggests more than a page view).
- Serve as a fallback when there's no proxy or EDR ([phase-08 Q214](phase-08-email-phishing.md#214-what-logs-would-you-check-if-you-dont-have-edr)).

## 357. How can proxy logs help investigate credential theft?
Proxy logs are richer than firewall logs for web activity because they see full URLs, HTTP methods, user identity, and user agents:
- **Full URL paths** — the exact phishing page hit, not just the domain.
- **HTTP method** — a `POST` to the phishing URL suggests a form submission (credentials), where a `GET` alone is just a page view. This is often the closest thing to direct evidence of credential submission you'll get.
- **Authenticated user identity** — proxies typically log the user, so you get who, not just which IP.
- **Referrer** — shows how the user arrived (from a mail client, a redirect chain).
- **Response codes and bytes** — whether the page loaded and how much was exchanged.
- **Uploads to unusual destinations** — exfiltration of credential dumps or staged data to file-sharing services.
- **User agent anomalies** — a non-browser user agent hitting a login page suggests scripted/automated credential use rather than a human.

---
[← Back to index](README.md) · [← Phase 13](phase-13-defender-xdr-edr.md) · [Next: Phase 15 — Linux →](phase-15-linux.md)
