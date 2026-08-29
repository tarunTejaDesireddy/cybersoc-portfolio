[← Back to index](README.md) | Tier 2 — Strong knowledge

# Phase 20 — Cloud Security (Q447–465)

## 447. What is cloud security?
Protecting cloud-hosted data, applications, and infrastructure — spanning identity and access management, network controls, data protection, workload security, logging/monitoring, and compliance. Governed by the **shared responsibility model**: the provider secures the cloud infrastructure itself, and the customer secures what they put in it — configuration, identities, data, and access. Most real cloud breaches are customer-side misconfigurations, not provider failures.

## 448. IaaS vs PaaS vs SaaS?

| | IaaS | PaaS | SaaS |
|---|---|---|---|
| You get | Virtual machines, storage, networking | A managed application platform | A finished application |
| You manage | OS, patching, runtime, apps, data | Your application code and data | Just your data and access config |
| Provider manages | Physical infra, hypervisor | Everything below your code, including OS | Everything |
| Example | Azure VM, EC2 | Azure App Service, Azure Functions | Microsoft 365, Salesforce |
| SOC focus | OS-level telemetry, EDR on the VM, patching | App logs, platform diagnostics, identity | Identity, audit logs, data access, app consents |

The higher up the stack, the less endpoint telemetry you have and the more your detection depends on **identity and audit logs**.

## 449. Azure VM vs Azure App Service?
**Azure VM (IaaS)** — a full virtual machine you control and are responsible for: OS patching, agents, EDR, and OS-level logging. **App Service (PaaS)** — a managed hosting platform for web apps; you deploy code, Microsoft manages the OS and runtime. Security consequence: on a VM you can install an EDR agent and get process-level telemetry; on App Service you cannot, so detection relies on application logs, platform diagnostics, and identity signals.

## 450. What is NSG?
Network Security Group — Azure's basic, stateful L3/L4 packet filter applied to subnets or network interfaces. Rules match on source/destination (IP, service tag, or application security group), port, protocol, and direction, with a priority order and default rules at the bottom. Free, distributed, and simple — but no application awareness, no threat intelligence, and no deep inspection. **NSG flow logs** are the key SOC data source it produces.

## 451. NSG vs Azure Firewall?

| | NSG | Azure Firewall |
|---|---|---|
| Layer | L3/L4 only | L3-L7 (FQDN filtering, app rules, TLS inspection on Premium) |
| Scope | Subnet or NIC | Centralized, whole-VNet/hub |
| Threat intelligence | No | Yes — TI-based filtering |
| IDPS | No | Yes (Premium) |
| Logging | Flow logs | Rich application/network rule logs |
| Cost | Free | Charged hourly + per GB |

They're complementary, not alternatives: NSGs for micro-segmentation close to the workload, Azure Firewall for centralized egress control and inspection at the hub.

## 452. What is Azure Firewall?
A managed, cloud-native, stateful firewall-as-a-service with built-in high availability and scaling. Provides network rules (L3/L4), application rules (FQDN-based filtering), NAT rules, threat-intelligence-based filtering, and — in the Premium tier — TLS inspection, IDPS, and URL filtering. Typically deployed in a hub VNet to control egress for all spokes, which also makes it the single best place to see and log outbound traffic.

## 453. What is Defender for Cloud?
Microsoft's **CSPM + CWPP** platform: **Cloud Security Posture Management** (continuously assesses configuration against security benchmarks, produces a Secure Score, and recommends fixes) plus **Cloud Workload Protection** (threat detection for VMs, storage, SQL, containers, App Service, Key Vault, and more). Its alerts flow into Defender XDR and Sentinel. In an interview, the crisp framing is: *"CSPM tells you what's misconfigured; CWPP tells you what's being attacked."*

## 454. What is Microsoft Entra ID?
Covered fully in [phase-07 Q171](phase-07-identity-entra-id.md#171-what-is-microsoft-entra-id) — Microsoft's cloud identity and access management service, the authentication and authorization control plane for Microsoft 365, Azure, and integrated SaaS. In a cloud security context, it's the **primary security perimeter**: in the cloud, identity compromise is the equivalent of network perimeter breach.

## 455. What is Azure Key Vault?
A managed service for storing and controlling access to secrets, keys, and certificates, backed by HSMs at the premium tier. Removes credentials from code and config files. SOC relevance: **Key Vault access logs are high-value** — an identity suddenly enumerating or bulk-retrieving secrets is a strong credential-access signal, and it's one of the first things an attacker does after compromising a cloud identity or a workload with a managed identity.

## 456. What is RBAC?
Role-Based Access Control — permissions granted by assigning **roles** (collections of permissions) to **security principals** (user, group, service principal, managed identity) at a defined **scope** (management group, subscription, resource group, or individual resource). Permissions inherit downward. Azure built-ins include Owner, Contributor, Reader, and hundreds of service-specific roles. The principle to state: least privilege at the narrowest workable scope.

## 457. Azure RBAC vs Entra roles?
A very commonly confused pair, and a good one to be crisp on:

| | Azure RBAC | Entra ID roles |
|---|---|---|
| Controls access to | **Azure resources** — VMs, storage, networks, Key Vault | **Entra ID / tenant objects** — users, groups, apps, directory settings |
| Scope | Management group → subscription → resource group → resource | The tenant (or administrative units) |
| Example roles | Owner, Contributor, Reader, Storage Blob Data Reader | Global Administrator, User Administrator, Security Reader |
| Managed in | Azure portal — subscription/resource IAM | Entra ID — Roles and administrators |

The critical security note: a **Global Administrator can elevate themselves to gain Azure RBAC access** to all subscriptions in the tenant (via the "Access management for Azure resources" toggle), so the two planes aren't fully separate — that elevation event is worth alerting on.

## 458. What is a managed identity?
Covered in [phase-07 Q184](phase-07-identity-entra-id.md#184-what-is-a-managed-identity) — an Azure-managed Entra identity assigned to a resource so it can authenticate to other services with no stored credentials. System-assigned (tied to one resource) or user-assigned (standalone, reusable). Investigation angle: if a VM or Logic App is compromised, **whatever its managed identity can access is now reachable by the attacker**, and there's no password to reset — you remediate by removing role assignments. Always check what roles a compromised resource's managed identity holds.

## 459. What is Azure Activity Log?
The subscription-level **control plane** log — records management operations performed *on* resources: who created, modified, or deleted what, when, from which IP, and whether it succeeded. It does **not** contain data plane activity (it shows that someone accessed a storage account's configuration, not that they read a blob). Free to ingest into Sentinel, and one of the highest-value cloud log sources for detecting attacker activity in Azure.

## 460. What is Azure Resource Log?
Per-resource **data plane** logs, emitted by individual services and enabled via **diagnostic settings** on each resource (not on by default — a common gap). Examples: Key Vault secret access, Storage blob read/write operations, SQL audit events, NSG flow logs, App Service HTTP logs, Azure Firewall rule hits. This is where you see what was actually *done inside* a resource.

The interview-ready distinction: **Activity Log = operations on the resource; Resource Logs = operations within the resource.**

---

## Scenario questions

### 461. How would you investigate suspicious activity against an Azure VM?
1. **Check the control plane** — `AzureActivity`: who created/modified/accessed the VM, changed its NSG, attached disks, or ran commands. Watch specifically for **Run Command** and **custom script extension** operations, which are a common attacker path to code execution on a VM without any credentials to the OS.
2. **Check network exposure** — is it public-facing, and are management ports (22/3389) open to the internet? Review NSG rules and any recent changes to them.
3. **Check NSG flow logs** — inbound connection attempts, brute force patterns, and unexpected outbound connections.
4. **Check the guest OS** — EDR telemetry, and Windows Security/Linux auth logs for authentication and process activity.
5. **Check the VM's managed identity** — what roles does it hold, and has it been used to access other resources (Key Vault, storage)?
6. **Check Defender for Cloud alerts** for that resource.
7. **Contain** — tighten or remove the NSG rules, isolate the VM's network, revoke the managed identity's role assignments if it was used, and rotate any credentials stored on the VM.

### 462. How would you investigate a compromised Azure identity?
Combines [phase-07 Q190](phase-07-identity-entra-id.md#190-how-would-you-investigate-a-compromised-entra-id-account) with the resource plane:
1. **Sign-in logs** — IPs, locations, devices, apps, MFA status, Conditional Access results.
2. **Entra audit logs** — what the identity changed in the directory (new users, role assignments, app registrations, credentials added to service principals, MFA method changes).
3. **`AzureActivity`** — what it did to Azure resources: created resources (cryptomining is a common motive), modified NSGs/firewalls, accessed Key Vault, exported data, deleted resources or logs.
4. **Check for privilege escalation** — new role assignments, especially Owner/Contributor at subscription scope, or the Global Admin → Azure resource elevation toggle.
5. **Check Key Vault access logs** — were secrets retrieved? If so, everything those secrets protect is now compromised.
6. **Check for persistence** — new service principals, credentials added to existing app registrations, new federated domains, Conditional Access policies weakened.
7. **Contain** — reset credentials, **revoke sessions/tokens**, remove attacker-added role assignments and credentials, and rotate any secrets that were accessed.

### 463. How would you detect privilege escalation in Azure?
Monitor `AzureActivity` and `AuditLogs` for:
- **Role assignment creation** (`Microsoft.Authorization/roleAssignments/write`), especially Owner, Contributor, or User Access Administrator at subscription or management group scope.
- **Custom role definition changes** — an attacker widening an existing role's permissions is subtler than granting Owner.
- **Global Administrator elevating to Azure resource access** (the tenant-root elevation toggle).
- **Entra role assignments** to privileged directory roles.
- **PIM activations** outside normal patterns, or PIM policy changes reducing approval requirements.
- **Credentials added to service principals/app registrations** — a highly privileged app plus an attacker-added secret is durable, MFA-free access.
- **Group membership changes** where the group is used for role assignment.

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, Properties
```

### 464. How would you investigate an exposed storage account?
1. **Confirm the exposure** — is public/anonymous blob access enabled, is there a permissive network rule (allow from all networks), or was an over-permissive **SAS token** issued?
2. **Determine what data is in it** and its sensitivity — this drives the whole severity assessment.
3. **Check access logs** (storage diagnostic/resource logs) — was the data actually accessed, by which IPs, how much, and over what period? Anonymous reads from unknown external IPs mean an actual data breach, not just a misconfiguration.
4. **Check how it became exposed** — `AzureActivity` for the configuration change: who made it, when, was it authorized, and was the account making the change itself compromised?
5. **Check for SAS token abuse** — SAS tokens are a blind spot because they grant access without an identity; look at the storage logs for SAS-authenticated requests and their scope/expiry.
6. **Contain** — disable public access, restrict network rules to required sources, revoke SAS tokens (rotate the account keys, which invalidates all SAS signed with them), and enable Defender for Storage.
7. **Assess breach notification obligations** if data was accessed — in a government/regulated context this is a mandatory-reporting question, not just a technical one.

### 465. How would you investigate suspicious Azure resource creation?
Unexpected resource creation most often means **cryptomining** (expensive VM SKUs) or **attacker infrastructure** (a VM for persistence/pivoting, or storage for exfiltration staging).
1. **`AzureActivity`** — who created it, when, from what IP, using what identity (user, service principal, or managed identity).
2. **Assess the resource** — type, size/SKU, region (resources created in a region you never use is a strong signal), and cost profile. Large GPU or compute-optimized VMs in an unusual region is the cryptomining signature.
3. **Check the creating identity for compromise** — sign-in anomalies, and what else it did around the same time.
4. **Check the resource's activity** — outbound network connections (mining pools), managed identity usage, data movement.
5. **Check for accompanying changes** — NSG rules opened, new role assignments, diagnostic settings disabled (attackers turn off logging).
6. **Check whether it was authorized** — change requests, IaC pipelines, autoscaling. This is the most common benign explanation and should be ruled out early.
7. **Contain** — delete or isolate the resource (preserving evidence first), contain the identity, and review the RBAC assignments that permitted the creation.

Prevention angle worth adding: **Azure Policy** to restrict which regions, resource types, and SKUs can be deployed, plus budget alerts — these turn an incident into a blocked deployment.

---
[← Back to index](README.md) · [← Phase 19](phase-19-threat-intelligence.md) · [Next: Phase 21 — L2 Troubleshooting →](phase-21-l2-troubleshooting.md)
