#!/usr/bin/env bash
# On-demand deploy of the Linux syslog endpoint for law-soc-lab.
#
# This VM is intentionally NOT kept running permanently. Deploy it when you
# want to test or demonstrate the 5 Linux Sentinel rules (SSH brute force,
# sudo escalation, account changes, logging-service-stopped), generate the
# telemetry you need, then run teardown-syslog-vm.sh to bring cost back to $0.
#
# Prerequisites: az cli logged in, jq installed.
# Usage: ./deploy-syslog-vm.sh <your-ip-address>

set -euo pipefail

RG="rg-soc-lab-doha"
LOCATION="uaenorth"
VM_NAME="vm-syslog-01"
DCR_NAME="dcr-syslog-soc-lab"
YOUR_IP="${1:?Usage: ./deploy-syslog-vm.sh <your-ip-address>}"

echo "== 1/5: Creating VM =="
az vm create \
  --resource-group "$RG" \
  --name "$VM_NAME" \
  --image "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest" \
  --size Standard_B1s \
  --admin-username socadmin \
  --generate-ssh-keys \
  --public-ip-sku Standard \
  --location "$LOCATION"

echo "== 2/5: Locking SSH to $YOUR_IP/32 =="
az network nsg rule update \
  --resource-group "$RG" \
  --nsg-name "${VM_NAME}NSG" \
  --name default-allow-ssh \
  --source-address-prefixes "${YOUR_IP}/32"

echo "== 3/5: Downgrading OS disk to Standard HDD (skip Premium entirely this time) =="
DISK_NAME=$(az vm show --resource-group "$RG" --name "$VM_NAME" --query "storageProfile.osDisk.name" -o tsv)
az vm deallocate --resource-group "$RG" --name "$VM_NAME"
az disk update --resource-group "$RG" --name "$DISK_NAME" --sku Standard_LRS
az vm start --resource-group "$RG" --name "$VM_NAME"

echo "== 4/5: Assigning managed identity (required - AMA silently fails without it) =="
az vm identity assign --resource-group "$RG" --name "$VM_NAME"

echo "== 5/5: Installing AMA and reattaching the DCR =="
az vm extension set \
  --resource-group "$RG" --vm-name "$VM_NAME" \
  --name AzureMonitorLinuxAgent --publisher Microsoft.Azure.Monitor \
  --enable-auto-upgrade true

VM_ID=$(az vm show --resource-group "$RG" --name "$VM_NAME" --query id -o tsv)
DCR_ID=$(az resource show --resource-group "$RG" --resource-type "Microsoft.Insights/dataCollectionRules" --name "$DCR_NAME" --query id -o tsv)

az rest --method put \
  --url "https://management.azure.com${VM_ID}/providers/Microsoft.Insights/dataCollectionRuleAssociations/${DCR_NAME}-assoc?api-version=2022-06-01" \
  --body "{\"properties\":{\"dataCollectionRuleId\":\"${DCR_ID}\"}}"

echo ""
echo "Done. Give it 15-30 minutes, then check Heartbeat and Syslog for vm-syslog-01 in law-soc-lab."
echo "When you're finished testing, run: ./teardown-syslog-vm.sh"
