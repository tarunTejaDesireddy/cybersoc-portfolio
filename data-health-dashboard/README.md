# data-health-dashboard

A Streamlit dashboard answering three operational questions about `law-soc-lab` that none of this
repo's other tooling covers on its own: **which tables are actually receiving data, when did each
one last see a log, and which analytics rules read from which table.**

## Why a logical grouping, not just the connector gallery

The obvious approach — enumerate `Microsoft.SecurityInsights/dataConnectors` and list the tables
under each — doesn't work for this lab, because most of its real data sources aren't gallery
connectors at all:

| Source | How it actually ingests | Shows up in `dataConnectors`? |
|---|---|---|
| Azure Activity Log | Subscription-level diagnostic setting | No |
| Entra ID sign-in/audit | Tenant-level diagnostic setting (`microsoft.aadiam`) | No |
| Syslog | DCR + Azure Monitor Agent on `vm-syslog-01` | Maybe, version-dependent |
| Windows Security Events | DCR + AMA via Azure Arc | Maybe, version-dependent |
| Custom threat intel (AbuseIPDB) | A script calling the Threat Intelligence Indicators API directly | No |

(See `infrastructure/SETUP.md` at the repo root — every one of these was stood up with
`az rest`/`az monitor diagnostic-settings`/a DCR, never `az sentinel data-connector create`.)

So this dashboard queries `Microsoft.SecurityInsights/dataConnectors` and shows whatever comes
back (useful, but likely sparse for this environment — that sparsity is expected, not a bug), and
**separately** groups actual table freshness under a hand-maintained logical mapping
(`CONNECTOR_TABLES` in `app.py`) that reflects the architecture as documented, not as the connector
API happens to model it. Table freshness itself never depends on that mapping being complete — an
unrecognized table still shows up, just under "Unmapped / other table," rather than being dropped.

## Table health

`union withsource=SourceTable * | summarize LastLog=max(TimeGenerated), RowCount=count() by SourceTable`
over the last `FRESHNESS_WINDOW_DAYS` (30) days, left-joined onto the full known-table list —
deliberately, so a table that has gone completely silent still shows a row ("No data in 30d")
instead of just vanishing from the result the way a plain `union` would leave it. Status per table:

| Status | Meaning |
|---|---|
| 🟢 Healthy | Logged within the last `STALE_AFTER_HOURS` (26 hours) |
| 🟡 Stale | Has data in the 30-day window, but not in the last 26 hours |
| 🔴 No data in 30d | Nothing at all in the window — connector likely broken, or genuinely never configured |

26 hours, not 24, deliberately — a source that logs once a day with some jitter shouldn't flip to
Stale over ordinary timing variance.

**Cost note:** `union *` scans every table in the workspace. This lab's own ingestion is capped at
1 GB/day (repo root README), so even a 30-day window stays cheap here. A larger workspace should
shrink `FRESHNESS_WINDOW_DAYS` or scope the union to a specific table list instead of `*`.

## Analytics rules by table (heuristic)

There's no structured "which tables does this rule read" field anywhere in the ARM model — a
rule's `query` is just a KQL string. This dashboard fetches every rule via
`Microsoft.SecurityInsights/alertRules`, then string-matches each known table name as a whole word
against that rule's raw query text.

**What this gets right:** every rule in this repo's own `analytics-rules/` was written directly
against a raw table name (per that folder's own design principles — no saved functions, no views),
so for the 60 rules actually deployed here, detection should be exact.

**What it would miss in general:** a rule that reaches a table only through a function or a saved
view, rather than naming the table directly. **What it could false-positive on:** a table name
that appears in a comment or a string literal rather than an actual table reference. Neither
applies to this repo's rules today, but if you add a rule that queries through a function, verify
its table mapping here manually rather than trusting the badge.

## Secrets setup

This is a **separate credential from `ip-threat-dashboard`'s** — same shape, different, more
privileged scope (it reads Sentinel resources, not just log data), so it gets its own
narrowly-scoped service principal rather than widening that one's.

**Fastest path:** `./setup-service-principal.sh <subscription-id>` — creates the service
principal, grants both roles below, and prints a ready-to-paste secrets block. Needs your own
`az login` session; it writes real resources to your subscription, so read it before running it.
Everything below is what that script does and why, for when you want to do it by hand instead.

```toml
[azure]
tenant_id = "<directory (tenant) ID>"
client_id = "<application (client) ID>"
client_secret = "<client secret value>"
workspace_id = "<Log Analytics workspace customerId GUID -- for the KQL query>"
subscription_id = "<subscription ID -- for building ARM resource paths>"
resource_group = "rg-soc-lab-doha"
workspace_name = "law-soc-lab"
```

`workspace_id` (the KQL-query GUID) and `workspace_name` (the ARM resource name) are **different
values for the same workspace** — this repo's `ip-threat-dashboard` sibling already documents this
exact gotcha; it applies here too, now for a second reason (ARM paths need the name, not the GUID).

For local development, put the same block in `.streamlit/secrets.toml` (gitignored at the repo
root).

### RBAC the service principal needs

Both roles, scoped to the `law-soc-lab` workspace — the same role this repo already grants its
Tier-1 analyst accounts (see `infrastructure/SETUP.md` §6), just for a new principal:

```bash
az role assignment create --assignee <app-id> --role "Microsoft Sentinel Reader" --scope <workspace-resource-id>
az role assignment create --assignee <app-id> --role "Log Analytics Reader" --scope <workspace-resource-id>
```

Sentinel Reader covers the `alertRules`/`dataConnectors` ARM calls; Log Analytics Reader is a
separate RBAC surface needed for the KQL table-freshness query — both are required, neither
substitutes for the other.

## Run it locally

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

## Deploy it

[share.streamlit.io](https://share.streamlit.io) → sign in with GitHub → deploy from
`TaruntejaDesireddy/cybersoc-portfolio`, branch `main`, main file
`data-health-dashboard/app.py`.
