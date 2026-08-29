[← Back to index](README.md) | Tier 1 — Must master

# Phase 3 — Ports & Protocols (Q61–84)

The interviewer isn't testing memorization for its own sake — every port below is a service that shows up constantly in firewall/proxy/EDR logs, and recognizing it instantly is what lets you read a log line at speed during a live investigation.

## 61–81. Port reference table

| # | Port | Proto | Service | Security relevance |
|---:|---|---|---|---|
| 61 | 20/21 | TCP | FTP | Plaintext credentials and data by default; still found on legacy file transfer; watch for it on hosts that shouldn't run it |
| 62 | 22 | TCP | SSH | Remote admin access to Linux/network gear; #1 target for brute force/credential stuffing from the internet |
| 63 | 23 | TCP | Telnet | Plaintext remote admin — any use at all on modern infra is a finding; common on old network/IoT devices |
| 64 | 25 | TCP | SMTP | Mail transfer between servers; abused for spam relay, phishing infrastructure, and internal recon of mail flow |
| 65 | 53 | TCP | DNS | Zone transfers and large DNS responses; TCP fallback |
| 66 | 53 | UDP | DNS | Standard DNS queries; near-universal outbound allow makes it a favorite for tunneling/C2/exfil |
| 67 | 80 | TCP | HTTP | Plaintext web traffic — full visibility in proxy/packet logs, common malware download/C2 vector |
| 68 | 110 | TCP | POP3 | Legacy mail retrieval; plaintext by default (POP3S = 995) |
| 69 | 135 | TCP | RPC (endpoint mapper) | Windows remote procedure calls — used by legitimate admin tools **and** lateral movement/exploits (e.g., historic RPC exploits, WMI) |
| 70 | 139 | TCP | NetBIOS Session | Legacy Windows file/printer sharing; relevant to SMB relay attacks |
| 71 | 143 | TCP/UDP | IMAP | Mail retrieval, keeps mail on server; plaintext by default (IMAPS = 993) |
| 72 | 443 | TCP | HTTPS | Encrypted web — the majority of both legitimate traffic and modern C2/exfil hides here |
| 73 | 500 | UDP | IKE (IPsec) | VPN tunnel negotiation; relevant to site-to-site VPN investigations |
| 74 | 514 | UDP | Syslog | Centralized logging feed — often unauthenticated/unencrypted UDP, a common Sentinel/SIEM ingestion source |
| 75 | 636 | TCP | LDAPS | Encrypted directory queries against AD; legitimate admin/app auth traffic, also reconnaissance target |
| 76 | 1433 | TCP | MSSQL | SQL Server; target for SQLi pivoting, credential attacks, and lateral movement via `xp_cmdshell` |
| 77 | 1812 | UDP | RADIUS | Centralized AAA (auth for VPN, Wi-Fi, network devices); compromise here is credential-access-critical |
| 78 | 3268/3269 | TCP | Global Catalog (AD) | Forest-wide directory search (3269 = LDAPS version); used in AD reconnaissance |
| 79 | 3389 | TCP | RDP | Windows remote desktop — a top ransomware initial-access and lateral-movement vector; internet-exposed RDP is a critical finding |
| 80 | 5985/5986 | TCP | WinRM (HTTP/HTTPS) | PowerShell remoting — legitimate admin tool, and a common lateral movement technique once credentials are stolen |
| 81 | 8080 | TCP | HTTP alt / proxy | Common alternate web port, proxy services, and a very common **C2 listener port** for malware frameworks |

## 82. What ports are commonly abused by attackers?
- **3389 (RDP)** — brute force, credential stuffing, ransomware initial access and lateral movement.
- **22 (SSH)** — brute force against internet-facing Linux hosts.
- **445 (SMB)** — lateral movement (PsExec, EternalBlue-style exploits), ransomware propagation.
- **135/445/5985 (RPC/SMB/WinRM)** — the classic Windows lateral-movement trio.
- **4444, 8080, 8443** — extremely common default listener ports for C2 frameworks (Metasploit's default is 4444) and reverse shells.
- **53 (DNS)** — tunneling/exfiltration hidden in "normal" traffic.
- **80/443** — blend malicious C2 into the largest, hardest-to-baseline traffic category.
Any of these seen on a host/port combination it has no business using is worth a second look.

## 83. How would you investigate an unusual outbound connection to port 4444?
Port 4444 is the historical Metasploit default — an automatic reason to take this seriously, but never convict on port number alone.
1. **Identify the source process** (EDR/Sysmon Event ID 3 / DeviceNetworkEvents) — what binary made the connection, and its full command line and parent process.
2. **Check the destination** — IP reputation, geolocation, ASN, hosting provider, first-seen date, any threat intel hits.
3. **Check connection pattern** — one-off vs. periodic beaconing (regular interval = classic C2 behavior).
4. **Correlate with process ancestry** — is this process a child of something suspicious (e.g., spawned from PowerShell, a macro-enabled document, an unsigned binary)?
5. **Check for related host activity** — new scheduled tasks/services, credential access attempts (LSASS touches), file writes to unusual paths around the same time.
6. **Check breadth** — does the same destination or the same parent-process pattern appear on other hosts (scope)?
7. **Decision** — if the process is unsigned/unknown and the pattern is periodic beaconing, this is a high-confidence C2 indicator: isolate the host, block the IP/domain at the firewall, and begin scoping.

## 84. How would you investigate unexpected RDP traffic?
1. **Confirm the "unexpected" part** — is this port 3389 to/from a host that has no legitimate reason for RDP (e.g., a workstation-to-workstation RDP session, or inbound RDP from the internet)?
2. **Pull the authentication logs** on the destination host (Event ID **4624** Logon Type 10 = RemoteInteractive) — who authenticated, from where, at what time.
3. **Check source** — internal host or external IP? If external, is RDP supposed to be internet-facing at all (it usually shouldn't be)?
4. **Check for failed attempts first** (Event ID **4625**) — a spray/brute-force pattern preceding a success is a major red flag.
5. **Correlate the account** — is it a service account, admin account, or a regular user account that has no business using RDP to that host?
6. **Check what happened after logon** — new processes, tool downloads, lateral movement to further hosts (chained RDP hops are a classic lateral movement pattern).
7. **Decision** — unauthorized/external RDP with a successful logon is treated as likely compromise: reset the account's credentials, review for further lateral movement, and consider isolating the destination host pending investigation.

---
[← Back to index](README.md) · [← Phase 2](phase-02-networking.md) · [Next: Phase 4 — Windows Security →](phase-04-windows-security.md)
