#!/usr/bin/env bash
# Creates the service principal this dashboard needs, grants it the two
# required roles on law-soc-lab, and prints a ready-to-paste secrets.toml
# block. Run this yourself -- it needs your own `az login` session and
# writes real resources (an app registration, a service principal, a role
# assignment) to your actual subscription.
#
# Deliberately a separate principal from whatever ip-threat-dashboard uses --
# this one needs broader read access (Sentinel resources, not just log data),
# so it gets its own narrowly-scoped identity rather than widening that one's.
set -euo pipefail

SUBSCRIPTION_ID="${1:?Usage: $0 <subscription-id> [resource-group] [workspace-name]}"
RESOURCE_GROUP="${2:-rg-soc-lab-doha}"
WORKSPACE_NAME="${3:-law-soc-lab}"
SP_NAME="sp-data-health-dashboard"

az account set --subscription "$SUBSCRIPTION_ID"

WORKSPACE_RESOURCE_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RESOURCE_GROUP" --workspace-name "$WORKSPACE_NAME" \
  --query id -o tsv)

WORKSPACE_GUID=$(az monitor log-analytics workspace show \
  --resource-group "$RESOURCE_GROUP" --workspace-name "$WORKSPACE_NAME" \
  --query customerId -o tsv)

echo "Creating service principal '$SP_NAME'..." >&2
read -r TENANT_ID APP_ID CLIENT_SECRET <<< "$(az ad sp create-for-rbac --name "$SP_NAME" \
  --query '[tenant, appId, password]' -o tsv)"

echo "Granting Microsoft Sentinel Reader + Log Analytics Reader on $WORKSPACE_NAME..." >&2
az role assignment create --assignee "$APP_ID" --role "Microsoft Sentinel Reader" --scope "$WORKSPACE_RESOURCE_ID"
az role assignment create --assignee "$APP_ID" --role "Log Analytics Reader" --scope "$WORKSPACE_RESOURCE_ID"

cat <<EOF

Done. RBAC can take a few minutes to propagate -- if the dashboard 403s
immediately, wait and retry before assuming something's wrong (see the
ip-threat-dashboard README's "Debugging a 403" note, same root cause here).

Paste this into Streamlit Cloud -> App settings -> Secrets
(or .streamlit/secrets.toml for local development -- already gitignored):

[azure]
tenant_id = "$TENANT_ID"
client_id = "$APP_ID"
client_secret = "$CLIENT_SECRET"
workspace_id = "$WORKSPACE_GUID"
subscription_id = "$SUBSCRIPTION_ID"
resource_group = "$RESOURCE_GROUP"
workspace_name = "$WORKSPACE_NAME"
EOF
