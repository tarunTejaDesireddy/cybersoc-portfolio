# Build Log: Personal Sentinel SOC Lab, Step by Step

This is the actual sequence used to build this lab from a completely empty Azure subscription — including the real errors hit and how they were resolved, not a cleaned-up happy path. Reproduce it yourself with the commands below, or read it as a build log.

## Prerequisites

- An Azure subscription (Free Trial or Pay-As-You-Go — a bare "Default Directory" tenant with zero M365/Entra licenses is enough for everything except the M365 Defender connector)
- Azure CLI ([https://aka.ms/installazurecliwindows](https://aka.ms/installazurecliwindows) on Windows)
- `gh` (GitHub CLI), if you want to push artifacts as you go

## 1. Azure CLI login

```bash
az login --use-device-code
```

Device-code flow avoids needing a browser in the same session. If you hit `AADSTS50076` (MFA required) or `No subscriptions found`, that means either conditional access needs a different auth method, or there's genuinely no active subscription on the account yet — activate one at [azure.microsoft.com/free](https://azure.microsoft.com/free) first.

## 2. Resource group + Log Analytics workspace + Sentinel

```bash
az group create --name rg-soc-lab-doha --location uaenorth

az monitor log-analytics workspace create \
  --resource-group rg-soc-lab-doha --workspace-name law-soc-lab \
  --location uaenorth --retention-time 90 --quota 1
```

`--quota` is the **daily ingestion cap in GB** — set this deliberately low for a personal lab (minimum is `0.023`). 90-day retention is free once Sentinel is enabled on the workspace, so there's no tradeoff there.

Enable Sentinel (no dedicated `az sentinel workspace create` in the CLI — done via the ARM REST API directly):

```bash
az rest --method put \
  --url "https://management.azure.com/subscriptions/<sub>/resourceGroups/rg-soc-lab-doha/providers/Microsoft.OperationalInsights/workspaces/law-soc-lab/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01" \
  --body '{"properties":{"customerManagedKey":false}}'
```

Grant yourself RBAC on the workspace:

```bash
az role assignment create --assignee <your-object-id> --role "Microsoft Sentinel Contributor" --scope <workspace-resource-id>
az role assignment create --assignee <your-object-id> --role "Microsoft Sentinel Reader" --scope <workspace-resource-id>
```

## 3. Data connectors

**Azure Activity Log** (subscription-level, free, no new resources):

```bash
az monitor diagnostic-settings subscription create --name "activitylog-to-sentinel" \
  --location uaenorth --workspace <workspace-resource-id> \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true}, ...]'
```

**Entra ID sign-in/audit logs** (tenant-level — no dedicated CLI command, use the ARM REST API against `microsoft.aadiam`):

```bash
az rest --method put \
  --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/entraid-to-sentinel?api-version=2017-04-01" \
  --body '{"properties":{"workspaceId":"<workspace-resource-id>","logs":[{"category":"SignInLogs","enabled":true},{"category":"AuditLogs","enabled":true}, ...]}}'
```

Basic sign-in/audit logs export regardless of license tier; risk-based categories (`RiskyUsers`, `UserRiskEvents`) need Entra ID P2 to actually populate — the diagnostic setting still creates fine without it.

**Syslog** (dedicated VM):

```bash
az vm create --resource-group rg-soc-lab-doha --name vm-syslog-01 \
  --image Ubuntu2204 --size Standard_B1s --admin-username socadmin --generate-ssh-keys --public-ip-sku Standard
```

⚠️ **Gotcha #1**: `az vm create` gives the VM a public IP with SSH open to `*` by default. Lock it down immediately:

```bash
az network nsg rule update --resource-group rg-soc-lab-doha --nsg-name vm-syslog-01NSG \
  --name default-allow-ssh --source-address-prefixes <your-ip>/32
```

Set auto-shutdown to control cost on a VM that doesn't need to run 24/7:

```bash
az vm auto-shutdown --resource-group rg-soc-lab-doha --name vm-syslog-01 --time 2100
```

Install the AMA extension:

```bash
az vm extension set --resource-group rg-soc-lab-doha --vm-name vm-syslog-01 \
  --name AzureMonitorLinuxAgent --publisher Microsoft.Azure.Monitor --enable-auto-upgrade true
```

⚠️ **Gotcha #2 — the expensive one**: if the VM has no Managed Identity, AMA can install and run but will silently fail to authenticate to the ingestion endpoint. Nothing shows in `Heartbeat` or the target table, no error surfaces anywhere in the portal — the only place it shows up is `/var/opt/microsoft/azuremonitoragent/log/mdsd.err` on the box itself, repeating `Failed to get MSI token from IMDS endpoint` every ~6 minutes. Fix:

```bash
az vm identity assign --resource-group rg-soc-lab-doha --name vm-syslog-01
```

Then restart the agent (`sudo systemctl restart azuremonitoragent walinuxagent`) so it picks up the new identity.

Create a filtered DCR (see `bicep/dcr-syslog.bicep`) rather than forwarding the full firehose — a tight daily quota makes this non-optional, not just tidy.

**Custom threat intel** (AbuseIPDB blacklist → Sentinel Threat Intelligence):

```bash
curl -H "Key: <your-abuseipdb-key>" "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=50"
```

Then `PUT` each IP as a STIX indicator via the `createIndicator` action:

```
POST .../workspaces/law-soc-lab/providers/Microsoft.SecurityInsights/threatIntelligence/main/createIndicator?api-version=2024-01-01-preview
```

⚠️ Indicators created this way can take 15–30 minutes to actually appear in the `ThreatIntelIndicators` table — the API call succeeding doesn't mean the table updates immediately.

## 4. Analytics rules

No dedicated `az sentinel` alert-rule create command exists in the stable CLI extension — deploy from templates via REST:

1. List templates: `GET .../alertRuleTemplates?api-version=2024-01-01-preview`
2. Filter to templates whose `requiredDataConnectors` match what you've actually connected — deploying a template for a connector you don't have just creates a rule that will never fire
3. `PUT` a new rule under `.../alertRules/<new-guid>`, copying the template's `query`, `severity`, `tactics`, `entityMappings`, etc., plus `alertRuleTemplateName` (the template's own ID) and `templateVersion`

⚠️ **Gotcha #3**: including `templateVersion` without `alertRuleTemplateName` in the same request fails with `templateVersion can only be used if alertRuleTemplateName is not empty` — include both or neither.

## 5. SOAR playbooks

Logic Apps, deployed via `az logic workflow create --definition <file> --mi-system-assigned true`.

⚠️ **Gotcha #4**: `az logic workflow create --definition` expects the file to have the workflow schema wrapped in an outer `{"definition": {...}}` key, not the raw definition JSON — it errors with `--definition does not contain a 'definition' key` otherwise.

⚠️ **Gotcha #5**: an `ApiConnection`-type action (e.g. calling a managed connector like Azure Communication Services Email) needs:
```json
"host": { "connection": { "name": "@parameters('$connections')['<connector>']['connectionId']" } }
```
not `"referenceName"` — the latter looks plausible but fails with `API connection name must be provided`.

Each playbook posts back to the Sentinel incident via `PUT .../incidents/{id}/comments/{guid}?api-version=2024-01-01-preview`, authenticated with `"authentication": {"type": "ManagedServiceIdentity"}` — no stored credentials anywhere.

For the containment playbook (disables an Entra ID account via Graph), grant the **narrowest possible** Graph app role, not `User.ReadWrite.All`:

```bash
az rest --method post --url "https://graph.microsoft.com/v1.0/servicePrincipals/<msi-object-id>/appRoleAssignments" \
  --body '{"principalId":"<msi-object-id>","resourceId":"<graph-sp-object-id>","appRoleId":"<role-id>"}'
```

⚠️ **Gotcha #6**: `User.EnableDisableAccount.All` alone returns `Authorization_RequestDenied` on a plain `PATCH /users/{id}`. Microsoft's own docs confirm the least-privileged working combination is `User.EnableDisableAccount.All` **+** `User.Read.All`.

⚠️ **Gotcha #7**: Managed Identity tokens are cached for up to ~1 hour. After granting a new Graph app role, the identity will keep failing with the *same* `Authorization_RequestDenied` error until the cached token expires — this looks identical to a missing-permission error and cost real debugging time. If the role assignment is confirmed correct via `GET /servicePrincipals/{id}/appRoleAssignments` and it's still failing, it's very likely just token cache — wait and retry rather than re-checking the permission.

## 6. RBAC tiering

Simulated a real SOC team structure — owner (Contributor) plus 3 Tier-1 analyst accounts (Reader only):

```bash
az ad user create --display-name "soc-analyst1 (Tier 1 Analyst)" --password <random> \
  --user-principal-name soc-analyst1@<tenant>.onmicrosoft.com --force-change-password-next-sign-in true
az role assignment create --assignee <new-user-object-id> --role "Microsoft Sentinel Reader" --scope <workspace-resource-id>
```

## 7. Onboarding a non-Azure endpoint (Azure Arc)

To bring a physical/on-prem machine's logs into the same workspace:

```bash
azcmagent connect --resource-group <rg> --tenant-id <tenant> --subscription-id <sub> \
  --location <region> --resource-name <machine-name> --cloud AzureCloud --use-device-code
```

⚠️ Requires an elevated (administrator) shell — fails with `AZCM0018: Admin Privileges Needed` otherwise, with no fallback prompt.

Then install AMA the Arc way (different command family from the VM extension path):

```bash
az connectedmachine extension create --machine-name <name> --resource-group <rg> \
  --name AzureMonitorWindowsAgent --publisher Microsoft.Azure.Monitor --type AzureMonitorWindowsAgent
```

Filter what you forward — an actual daily-driver machine produces far more Windows Security Event volume than a lab VM. This lab forwards only 9 specific event IDs (logon success/fail, explicit-credential logon, special privilege use, process creation, account/group changes, scheduled task/service install) via `xPathQueries` in the DCR, not the full Security log.

## Recurring theme across all of the above

Several `az` command groups (`logic`, `monitor data-collection rule`, `communication`, `connectedmachine`, `sentinel`) require a CLI extension that isn't installed by default. The auto-install prompt (`Do you want to install it now? (Y/n)`) hangs forever in a non-interactive shell — always run `az extension add -n <name>` explicitly first rather than letting a command trigger the prompt.
