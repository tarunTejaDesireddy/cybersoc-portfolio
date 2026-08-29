[← Back to index](README.md) | Tier 1 — Must master

# Phase 7 — Identity & Entra ID (Q171–194)

Identity is the modern perimeter — in a Microsoft-stack SOC, more incidents start here than anywhere else. Questions 190-194 are scenario questions and carry the most weight.

## 171. What is Microsoft Entra ID?
Microsoft's cloud identity and access management service (formerly Azure AD) — handles authentication and authorization for Microsoft 365, Azure, and thousands of SaaS applications. It's the identity provider behind SSO, MFA, and Conditional Access in a Microsoft environment.

## 172. Entra ID vs Active Directory?

| | Active Directory (on-prem) | Entra ID (cloud) |
|---|---|---|
| Protocols | Kerberos, NTLM, LDAP | OAuth 2.0, OpenID Connect, SAML, WS-Fed |
| Structure | Hierarchical — forests, domains, OUs, GPOs | Flat — tenant with users, groups, roles |
| Manages | Domain-joined Windows machines, file/print services | Cloud apps, SaaS, device registration, modern auth |
| Access control | GPOs, ACLs, security groups | Conditional Access, RBAC roles, app permissions |
| Auth artifact | Kerberos tickets | OAuth tokens (access/refresh/ID) |
| Key attacks | Kerberoasting, Golden Ticket, DCSync, Pass-the-Hash | Token theft, illicit consent, MFA fatigue, password spray |

They're commonly **hybrid** — synced via Entra Connect — which is important in investigations: a compromise on one side can propagate to the other, and you must check both.

## 173. What is Conditional Access?
Entra's policy engine implementing "if X, then require Y" access decisions at sign-in time. **Signals** (user/group, application, device compliance, location/IP, sign-in risk, user risk, client app) drive **controls** (block, require MFA, require compliant/hybrid-joined device, require approved app, force session limits). It's the primary preventive identity control in a Microsoft environment — and in an investigation, the first thing to check is whether a policy gap allowed the compromise (e.g., legacy authentication not blocked).

## 174. What is MFA?
Multi-Factor Authentication — requiring two or more of: something you **know** (password), something you **have** (phone, token, certificate), something you **are** (biometric). Defeats password-only compromise, which is why nearly every credential-based attack now includes an MFA-bypass component.

## 175. What is MFA fatigue?
Also called push bombing/MFA spamming: the attacker, already holding valid credentials, repeatedly triggers MFA push notifications until the user approves one out of annoyance, confusion, or to stop the notifications (often at 3am). **The key insight for an interview: an MFA fatigue alert means the password is already compromised** — that's the incident, regardless of whether a push was approved. Mitigation: number matching, push challenge context, and phishing-resistant MFA (FIDO2/certificate-based).

## 176. What is passwordless authentication?
Authenticating without a password at all — Windows Hello for Business, FIDO2 security keys, certificate-based auth, or Microsoft Authenticator passwordless sign-in. Uses cryptographic key pairs bound to a device and unlocked by biometric/PIN. Security value: eliminates phishing of passwords, password spraying, credential stuffing, and password reuse in one move — the credential can't be typed into a fake page because there's nothing to type.

## 177. What is OAuth?
An **authorization** framework (not authentication) that lets an application access resources on a user's behalf without receiving their password, via scoped access tokens. The security-relevant part for SOC: **consent** — a user can grant an application permissions, and an attacker who tricks a user into consenting to a malicious app gains persistent, token-based access to their data that survives password resets.

## 178. What is OpenID Connect?
An **authentication** layer built on top of OAuth 2.0 — adds an **ID token** (a JWT) carrying identity claims about the authenticated user. Shorthand: OAuth answers "what can this app do?", OIDC answers "who is this user?". OIDC is what powers modern SSO sign-in flows.

## 179. What is SAML?
Security Assertion Markup Language — an XML-based standard for exchanging authentication/authorization data between an identity provider (IdP) and a service provider (SP). Older than OIDC, still very common in enterprise SSO. Attack relevance: **Golden SAML** — an attacker who steals the IdP's token-signing certificate can forge SAML assertions for any user, the cloud equivalent of a Golden Ticket.

## 180. What is SSO?
Single Sign-On — authenticate once with the identity provider, then access many applications without re-entering credentials. Security tradeoff worth stating in an interview: it **reduces** password fatigue and reuse and centralizes MFA enforcement and logging, but it **concentrates risk** — compromise of the SSO identity means access to everything behind it.

## 181. What is an enterprise application?
In Entra, the **local instance** of an application in your tenant (technically the service principal) — where you configure who can use it, what permissions it holds in your tenant, and its SSO settings. In investigations, this is where you look to see which third-party apps have access to your data.

## 182. What is an application registration?
The **definition** of an application in the tenant that owns/publishes it — its identity, redirect URIs, requested permissions, credentials (secrets/certificates). Rough distinction: **app registration = the blueprint/global definition; enterprise application (service principal) = the instance with permissions in a specific tenant.**

## 183. What is a service principal?
The **local identity object** an application uses to authenticate and be authorized within a tenant — effectively "the account the app logs in as." SOC relevance: service principals can hold high privileges, authenticate non-interactively without MFA, and are a favored persistence mechanism — an attacker who adds a credential (secret/certificate) to an existing service principal has durable access that no password reset touches.

## 184. What is a managed identity?
An Entra identity automatically created and managed by Azure for a resource (VM, App Service, Logic App, Function), so the resource can authenticate to other Azure services **without any stored credentials**. Two types: **system-assigned** (tied to one resource's lifecycle) and **user-assigned** (standalone, shareable). Security benefit: no secrets in code or config to leak. Risk to check in investigations: an over-permissioned managed identity on a compromised resource gives the attacker whatever that identity can reach.

## 185. User identity vs workload identity?
**User identity** = a human, authenticates interactively, can be subject to MFA and Conditional Access, has predictable behavioral patterns. **Workload identity** = an application/service/managed identity, authenticates non-interactively (often with secrets or certificates), typically **not** covered by MFA, and historically less monitored. That last point is the interview-relevant one: workload identities are increasingly targeted precisely because MFA doesn't apply and their activity is under-baselined. Entra has Workload Identity Premium features (Conditional Access for workload identities, risk detection) to address this.

## 186. What is impossible travel?
A detection that fires when one account signs in from two geographic locations too far apart for the elapsed time to be physically possible. **High false-positive rate** — VPNs, cloud proxies, mobile carrier NAT, and roaming all produce it legitimately. Always investigate rather than auto-remediate (worked investigation in [phase-16 Q374](phase-16-incident-response-scenarios.md#374-one-account-successfully-authenticates-from-qatar-and-another-country-within-10-minutes-investigate)).

## 187. What is a risky sign-in?
Entra ID Protection's assessment that a *specific sign-in attempt* has an elevated probability of not being the legitimate user — based on signals like anonymous IP (Tor/VPN), atypical travel, malware-linked IP, unfamiliar sign-in properties, admin-confirmed compromise, or token anomalies. Scored Low/Medium/High and usable as a Conditional Access signal.

## 188. What is a risky user?
An assessment of the *account overall* rather than one sign-in — aggregating risky sign-ins and offline detections such as leaked credentials found in public breach dumps or threat-intelligence matches. A user can be flagged risky without a single risky sign-in (e.g., their credentials appeared in a breach dump).

## 189. What is token theft?
Stealing an already-issued OAuth access or refresh token (via infostealer malware, adversary-in-the-middle phishing proxies like Evilginx, or session cookie theft) and replaying it to access resources — **bypassing both the password and MFA entirely**, because the token already represents a completed authentication.

**Critical operational consequence, and a favorite interview probe: a password reset does not invalidate a stolen token.** You must explicitly **revoke sessions/refresh tokens** (`Revoke-MgUserSignInSession` / "Revoke sessions" in the portal). Detection: sign-ins with the same token from anomalous IPs/devices, impossible travel with matching device/session IDs, and unfamiliar user-agent or client-app combinations.

---

## Scenario questions

### 190. How would you investigate a compromised Entra ID account?
1. **Confirm the compromise indicator** — which alert/signal fired (risky sign-in, impossible travel, user report, MFA fatigue)?
2. **Review sign-in logs** (`SigninLogs`) for the account — every sign-in in the relevant window: IP, ASN, location, device ID, OS, browser, application, conditional access result, MFA status, and the risk level assigned to each.
3. **Separate legitimate from suspicious** sign-ins by device familiarity and ASN type (corporate egress vs. residential vs. hosting provider vs. anonymizer).
4. **Check audit logs** (`AuditLogs`) for what the account *did* — this is where attacker persistence shows up:
   - **New MFA method registered** (attacker securing their own access)
   - **Password changed** by the attacker
   - **New inbox rules** (auto-forward/delete — hiding responses and stealing mail)
   - **New OAuth application consents**
   - **Role assignments / group memberships added**
   - **Device registration**
5. **Check mailbox activity** — mass downloads, sent items the user doesn't recognize, forwarding rules.
6. **Check data access** — SharePoint/OneDrive file access and downloads, Teams activity.
7. **Check for on-prem correlation** if hybrid — did the same account authenticate on-premises?
8. **Contain** — reset password, **revoke all sessions/tokens**, remove attacker-added MFA methods and inbox rules, revoke malicious app consents, and re-enable proper MFA registration.
9. **Determine the entry vector** — phishing, password spray, infostealer on their endpoint, credential reuse.
10. **Scope** — other accounts hit by the same campaign/source IP.

### 191. How would you investigate a suspicious OAuth application?
Illicit consent grants are a durable, password-reset-proof persistence mechanism — treat them seriously.
1. **Identify the app** — display name, application ID, publisher, and whether the publisher is **verified**.
2. **Review the permissions it holds** — especially `Mail.Read`, `Mail.Send`, `Files.ReadWrite.All`, `User.Read.All`, and anything with `.All` scope or application-level (not delegated) permissions.
3. **Check who consented and when** — was it an individual user, or did an **admin grant tenant-wide consent** (much larger blast radius)?
4. **Check how many users consented** — one user or a campaign?
5. **Check the app's activity** — what has it actually accessed? Sign-in logs for the service principal, and any mass data access.
6. **Check the reply URL / redirect URI** — pointing to a suspicious or unrelated domain is a strong signal.
7. **Check app age** — recently registered apps requesting broad mail permissions are a classic consent-phishing pattern.
8. **Contain** — revoke the consent, disable the service principal, remove any credentials added to it, and revoke user tokens issued to it.
9. **Harden** — restrict user consent to verified publishers with low-impact permissions, and enable admin consent workflow.

### 192. How would you investigate MFA abuse?
1. **Determine the abuse type** — fatigue/push bombing, SIM swap, MFA method registered by an attacker, or a bypass via legacy authentication.
2. **Review the MFA event history** — how many prompts, over what period, from which IPs, and were any approved?
3. **Check the sign-in logs** for the paired credential use — the attacker has a valid password, so establish how they got it.
4. **Check `AuditLogs` for MFA method changes** — a new phone number or authenticator added is attacker persistence; note exactly when and from where.
5. **Check whether legacy authentication protocols** (IMAP/POP/SMTP AUTH, older Exchange protocols) were used — these bypass MFA entirely and are a common gap.
6. **Contain** — reset the password, revoke sessions, remove attacker-registered MFA methods, and have the user re-register MFA from a trusted device.
7. **Harden** — enable number matching, block legacy authentication via Conditional Access, and consider phishing-resistant MFA for privileged users.

### 193. What would you do if an admin account was compromised?
Highest severity — a compromised Global Administrator can grant themselves anything and establish persistence that survives most remediation.
1. **Escalate immediately** — this is an incident-command-level event, not routine triage.
2. **Contain fast**: reset the password, **revoke all sessions/tokens**, and consider disabling the account if attacker activity is ongoing (coordinating so you don't lock out legitimate admin access — make sure another break-glass admin account is available first).
3. **Enumerate everything the account did** via `AuditLogs`: role assignments granted, users created, applications registered, **credentials/secrets added to service principals**, Conditional Access policies modified or disabled, MFA settings changed, domains added to the tenant (a federation-level persistence trick).
4. **Reverse the attacker's persistence** — this is the part people miss: removing the attacker from the account isn't enough if they created a second admin, added a certificate to an app registration, or added a federated domain.
5. **Check Azure resource plane too** — RBAC role assignments, new resources, Key Vault access, and anything created in subscriptions the admin could reach.
6. **Check for downstream compromise** — did the admin's access get used to reach other accounts or on-prem systems?
7. **Review Conditional Access** for policies the attacker weakened or excluded themselves from.
8. **Post-incident**: review privileged access model — PIM/just-in-time elevation, break-glass account procedures, and admin workstation hygiene.

### 194. How would you determine whether an account was actually compromised or the alert was a false positive?
This is the [phase-25](phase-25-l2-thinking-questions.md) discipline applied to identity — answer by describing what you'd **rule out**:

| Check | Points to compromise | Points to false positive |
|---|---|---|
| **Device** | Unknown/unregistered device ID | Known, compliant, previously-used device |
| **IP/ASN** | Hosting provider, anonymizer/Tor, unexpected country with no travel record | Corporate VPN egress, known office IP, user's home ISP, mobile carrier |
| **MFA** | MFA not satisfied, or a new method registered around the sign-in | MFA satisfied normally from the usual method |
| **Behavior after sign-in** | Inbox rules, mass downloads, app consents, role changes | Normal application usage matching the user's pattern |
| **User confirmation** | User denies the activity, or was phished/prompted unexpectedly | User confirms travel/VPN — **verify independently, don't close on the statement alone** |
| **Pattern** | First-ever occurrence of this pattern for this user | Recurs regularly in their 90-day baseline |
| **Correlation** | Same source IP hitting multiple accounts | Isolated to one user with a benign explanation |

Then state your conclusion with a confidence level and what would change it. And note the asymmetry out loud: *"if I can't resolve it confidently, I take the low-cost protective action — reset and revoke sessions — because the cost of that is minutes of user inconvenience and the cost of being wrong is a live account compromise."*

---
[← Back to index](README.md) · [← Phase 6](phase-06-ad-attacks.md) · [Next: Phase 8 — Email & Phishing →](phase-08-email-phishing.md)
