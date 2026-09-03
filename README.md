# cybersoc-portfolio

Personal Microsoft Sentinel SOC lab — deployed and configured end-to-end from scratch to close hands-on gaps (Sentinel deployment, connector configuration, SOAR automation) alongside 4+ years of SOC L2/L3 analyst experience.

## Architecture

- **Log Analytics workspace** (`law-soc-lab`) with Microsoft Sentinel enabled — 90-day retention (free tier via Sentinel), 1 GB/day ingestion cap for cost control
- **Data connectors**: Azure Activity Log, Entra ID sign-in/audit logs, Syslog (dedicated Ubuntu VM running Azure Monitor Agent, filtered via a custom Data Collection Rule to security-relevant facilities/severities only), and a custom threat intel pipeline pulling AbuseIPDB's high-confidence IP blacklist into Sentinel Threat Intelligence
- **RBAC tiering**: owner account (Sentinel Contributor), 3 simulated Tier-1 analyst accounts (Sentinel Reader — view incidents/hunt/workbooks, no write access)

## Analytics Rules (`/analytics-rules`)

60 custom-authored scheduled rules — no gallery templates. Every rule was written against a table confirmed to be ingesting in this workspace, because a rule that cannot fire is worse than no rule: it creates the appearance of coverage.

| Category | Rules | Data source |
|---|---:|---|
| Azure control plane | 20 | AzureActivity |
| Identity and authentication | 20 | SigninLogs, AADNonInteractiveUserSignInLogs |
| Entra ID directory | 12 | AuditLogs |
| Linux endpoint | 5 | Syslog |
| Detection health and correlation | 3 | Heartbeat, Usage, AzureActivity |

30 High, 25 Medium, 5 Low. Entity mappings on 59 of 60, custom details on all 60, and dynamic alert titles on 44 so incident names carry the actual user, IP, or resource rather than a static string.

Each rule description documents its own detection logic, MITRE mapping, numbered triage steps, known false positives with the specific tuning lever, and source table — so triage does not depend on tribal knowledge.

See [`analytics-rules/README.md`](analytics-rules/README.md) for the full index and the three rules that need environment-specific tuning before production use.

## Playbooks (`/playbooks`)

Logic App workflow definitions, exported as ARM templates. Secrets (API keys) live in Azure Key Vault and are read at runtime via the playbook's system-assigned Managed Identity — never passed as deployment parameters, never stored in the workflow itself.

| Playbook | Trigger | Purpose | Status |
|---|---|---|---|
| `la-ip-enrichment.json` | HTTP (called from Sentinel incident) | Multi-source IP enrichment — queries both VirusTotal and AlienVault OTX in parallel, posts a combined summary (engine detection counts, threat-pulse count, reputation, ASN) as an incident comment. Each source degrades independently: if one is rate-limited or errors, the comment still posts with the other source's data rather than failing outright. | Live |
| `la-user-containment.json` | HTTP (called from Sentinel incident) | On High-severity incidents, posts an incident comment recommending the associated account be disabled. Does **not** disable the account itself. | Live |
| `la-email-alert.json` | HTTP (called from Sentinel incident) | Sends a formatted incident alert email via Azure Communication Services Email, then comments on the incident | Reference implementation — not currently deployed |

### Why the containment playbook recommends rather than acts

The first version of this playbook disabled the Entra ID account directly via `PATCH /users/{id}` over Microsoft Graph. That requires the `User.ReadWrite.All` application permission: unattended, tenant-wide, and capable of modifying *any* user, not just the one named in the incident. A single false-positive High-severity incident — not a rare event in an under-tuned environment — would silently lock out a real user with no human in the loop.

The playbook now posts a clear, actionable recommendation and stops. A human approves the actual containment action. This trades a small amount of automation for removing a standing, broad-scope Graph grant from an unattended identity — the kind of tradeoff a mature SOC makes deliberately rather than defaulting to "automate everything."

## Workbooks (`/workbooks`)

Sentinel workbook definitions, exported as JSON and built against real lab telemetry rather than
sample data.

| Workbook | Purpose |
|---|---|
| `hunt-and-investigate.json` | Pivot view for working a single indicator — IP, account, or host — across the tables that carry it |
| `soc-overview.json` | Queue health at a glance: incident volume, rule firing rates, ingestion freshness |

Details in [`workbooks/README.md`](workbooks/README.md).

## Data Health Dashboard (`/data-health-dashboard`)

A standalone Streamlit app, separate from the Workbooks above: table freshness across the whole
workspace (not just `Heartbeat`-based source health the way `soc-overview.json`'s health section
does), plus analytics rules grouped by the table each one actually reads — a relationship that
isn't a structured field anywhere in Sentinel's data model, so this parses it out of each rule's
raw KQL. Built in Streamlit specifically for that last piece; see
[`data-health-dashboard/README.md`](data-health-dashboard/README.md) for why, the exact heuristics
used, and the required (separately-scoped) service principal.

## Infrastructure (`/infrastructure`)

Bicep IaC for standing the workspace up from nothing — Log Analytics workspace, Sentinel
onboarding, and the Data Collection Rules that feed it.

| File | What it does |
|---|---|
| `bicep/main.bicep` | Workspace + Sentinel onboarding |
| `bicep/dcr-syslog.bicep` | Data Collection Rule for Linux syslog facilities |
| `bicep/dcr-windows-events.bicep` | Data Collection Rule for Windows Security events |
| `deploy-syslog-vm.sh` / `teardown-syslog-vm.sh` | Stand up and tear down the syslog source VM |

Setup walkthrough in [`infrastructure/SETUP.md`](infrastructure/SETUP.md).

## Deploying

Prerequisite: an Azure Key Vault holding secrets `VirusTotalApiKey` and `OTXApiKey`, with `Key Vault Secrets User` granted to whichever principal will run `la-ip-enrichment`.

```bash
az deployment group create --resource-group <rg> --template-file playbooks/la-ip-enrichment.json --parameters KeyVaultName=<your-vault-name>
az deployment group create --resource-group <rg> --template-file playbooks/la-user-containment.json
az deployment group create --resource-group <rg> --template-file playbooks/la-email-alert.json
```

After deployment:

1. Enable each Logic App's system-assigned managed identity
2. Grant `la-ip-enrichment`'s identity `Key Vault Secrets User` on your vault
3. Grant every playbook's identity `Microsoft Sentinel Contributor` on your workspace (needed to post incident comments)

No Graph permissions are required by any playbook in this repo.

Analytics rules deploy from their JSON definitions:

```bash
./deploy-rules.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -WorkspaceName <workspace>
```

Add `-WhatIf` to preview without writing. Each rule carries a fixed GUID, so the script is idempotent — re-running updates in place rather than creating duplicates.
