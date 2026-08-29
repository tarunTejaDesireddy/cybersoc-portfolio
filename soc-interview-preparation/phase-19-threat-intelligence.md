[← Back to index](README.md) | Tier 2 — Strong knowledge

# Phase 19 — Threat Intelligence (Q436–446)

## 436. What is threat intelligence?
Evidence-based knowledge about existing or emerging threats — actors, their capabilities, infrastructure, and TTPs — that has been collected, processed, and analyzed so it can **inform decisions**. The distinction that matters: raw data (a list of IPs) is not intelligence; intelligence is data plus context, analysis, and relevance to *your* environment.

## 437. Strategic vs tactical vs operational threat intelligence?

| Type | Audience | Content | Time horizon |
|---|---|---|---|
| **Strategic** | Executives, board, CISO | Threat landscape, actor motivations, geopolitical risk, industry targeting trends — drives budget and policy | Long-term |
| **Operational** | SOC managers, IR leads, threat hunters | Specific campaigns, actor TTPs, attack patterns targeting your sector — drives detection priorities and hunting | Medium-term |
| **Tactical** | SOC analysts, engineers | IOCs — IPs, domains, hashes, URLs, YARA/Sigma rules — directly consumable by tooling | Short-lived |

Some models split TTP-level intelligence out as its own tier. The interview-relevant point: **tactical intel expires fast; TTP and strategic intel age slowly**, which is why building detections on behavior beats building them on indicator lists.

## 438. What is an IOC feed?
A stream of indicators delivered continuously from a provider — commercial (Recorded Future, Mandiant), open-source (abuse.ch, AlienVault OTX, AbuseIPDB), government/sector (national CERT, ISAC), or internal (indicators from your own past incidents — often the highest-value feed you have, because they're contextually relevant by definition). Usually delivered via STIX/TAXII, API, or CSV.

## 439. What is IP reputation?
A scored assessment of whether an IP is associated with malicious activity, based on history (spam, malware hosting, C2, scanning), hosting type (residential vs. datacenter vs. anonymizer), ASN reputation, and observed behavior. Weakness worth naming: IPs are **shared and reassigned** — a cloud IP that hosted C2 last month may be a legitimate customer today, and blocking a shared CDN or cloud IP can take down legitimate services.

## 440. What is domain reputation?
The same for domains, factoring registration date, registrar, WHOIS privacy, hosting infrastructure, certificate details, DNS behavior, and past malicious use. **Domain age is the strongest single signal** — newly registered domains (<30 days) are disproportionately malicious, and many organizations block or heavily scrutinize them as a category.

## 441. What is URL reputation?
Per-URL assessment — more granular than domain reputation, which matters because a legitimate compromised site may host one malicious path while the rest of the domain is fine (blocking the whole domain would be wrong). Factors: sandbox detonation results, page content analysis, redirect chains, and hosting reputation.

## 442. How do you validate an IOC?
1. **Check the source and its confidence rating** — who reported it, when, and based on what evidence?
2. **Check freshness** — when was it first and last seen malicious? ([Q444](#444-what-is-ioc-aging))
3. **Corroborate across multiple independent sources** — one feed flagging something is weaker than three.
4. **Understand the context** — malicious *for what*? An IP flagged for spam is not evidence of C2.
5. **Check what it actually is** — is it a shared hosting IP, a CDN edge, a cloud provider range, a Tor exit node, or a dedicated attacker server? This changes everything about how you act on it.
6. **Check for internal relevance** — has anything in your environment interacted with it, and in what way?
7. **Assess collateral risk before blocking** — would blocking break a legitimate service?

## 443. Why shouldn't you automatically block every malicious IOC?
Several strong reasons, and this question is really testing operational judgment:
- **False positives break the business** — blocking a shared cloud/CDN IP can take down legitimate services, and blocking a Microsoft or Google range can be catastrophic.
- **Indicators are shared and reassigned** — the malicious tenant on that IP left months ago.
- **Indicators age out** ([Q444](#444-what-is-ioc-aging)) — blocklists grow indefinitely, degrading firewall performance and becoming unmaintainable.
- **You lose visibility** — sometimes you *want* to observe the communication to understand scope before tipping the attacker off that you've detected them.
- **Attackers rotate infrastructure cheaply** — blocking one IP has near-zero cost to them, so it's not a substitute for behavior-based detection.
- **Volume** — feeds deliver millions of indicators; blocking indiscriminately is neither feasible nor sensible.

The right approach: **risk-tier your indicators** — auto-block high-confidence, high-specificity ones (a dedicated malware C2 domain); alert-and-investigate medium-confidence ones; use low-confidence ones for enrichment context only.

## 444. What is IOC aging?
The reality that indicators lose value over time — malicious infrastructure is taken down, abandoned, or reassigned to legitimate users, and hashes become obsolete as malware recompiles. IOC aging is the practice of **assigning a lifespan/decay score to indicators** and expiring or de-prioritizing them automatically.

Rough guidance to cite: IPs age fastest (days to weeks), domains somewhat slower (weeks to months), file hashes stay valid indefinitely as identifiers but become useless as *detection* once the sample stops being used. **TTPs effectively never age** — which is the argument for behavior-based detection.

## 445. How would you enrich an IP during an investigation?
1. **Reputation** — VirusTotal, AbuseIPDB, AlienVault OTX, internal TI, and your own historical incident data.
2. **Ownership** — WHOIS/RDAP: who owns the range, and the abuse contact.
3. **ASN and hosting type** — datacenter/VPS, residential ISP, mobile carrier, cloud provider, CDN, or anonymizer. This is often the most decisive signal.
4. **Geolocation** — with the caveat that it's approximate and easily defeated by VPN/proxy.
5. **Passive DNS** — which domains resolve or have resolved to it (reveals infrastructure sharing and campaign links).
6. **Open ports/services** — Shodan/Censys: what's running there (a C2 panel? an open directory?).
7. **Certificate data** — shared certificates link infrastructure together.
8. **Internal context** — have we communicated with it before, how often, from which hosts, and was it allowed or blocked? Is it in an allow-list, or an established business partner?

## 446. How would you determine whether an IP belongs to an attacker, VPN, cloud provider, CDN, or legitimate service?

| Signal | What it tells you |
|---|---|
| **WHOIS / ASN owner** | The organization name usually names it outright — AWS, Azure, Cloudflare, a commercial VPN provider, a residential ISP |
| **Reverse DNS (PTR)** | Cloud and CDN providers have distinctive PTR naming (`ec2-...compute.amazonaws.com`, `...cloudfront.net`) |
| **Published IP ranges** | Major providers publish their ranges — Microsoft, AWS, Google, Cloudflare all do; check membership directly |
| **Tor exit node lists** | Publicly published and easy to check |
| **VPN provider lists** | Commercial VPN ranges are catalogued by TI providers |
| **Passive DNS** | Many unrelated domains resolving to it = shared hosting/CDN; one domain = likely dedicated infrastructure |
| **Open ports (Shodan/Censys)** | A C2 panel, an open directory, or a self-signed certificate on an odd port suggests attacker infrastructure; a standard web stack suggests hosting |
| **Certificate** | Legitimate services have CA-issued certs matching real domains; attacker infra often has self-signed or newly-issued certs |
| **Traffic pattern in your environment** | Many internal hosts contacting it routinely over a long period = probably legitimate; one host, recently, on an odd port = suspicious |
| **Age/history** | Long, clean history vs. first seen last week |

The practical judgment to state: **a cloud provider IP is the hardest case, because both attackers and legitimate services use AWS/Azure.** For those, ownership tells you nothing — you have to judge by the specific service running, the domain/certificate, and the behavior of the traffic in your environment. And note the operational consequence: you generally **cannot** blanket-block a cloud provider or CDN range, so containment for those has to happen at the domain, URL, or process level instead.

---
[← Back to index](README.md) · [← Phase 18](phase-18-soc-operations.md) · [Next: Phase 20 — Cloud Security →](phase-20-cloud-security.md)
