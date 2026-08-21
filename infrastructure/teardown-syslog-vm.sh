#!/usr/bin/env bash
# Tears down the Linux syslog endpoint completely - VM, disk, NIC, public IP,
# NSG, and its auto-shutdown schedule if one exists. Brings this component's
# cost to $0 until the next deploy-syslog-vm.sh run.
#
# Does NOT delete dcr-syslog-soc-lab - that's reusable across redeployments
# and costs nothing to leave in place.

set -euo pipefail

RG="rg-soc-lab-doha"
VM_NAME="vm-syslog-01"

echo "== 1/5: Deleting VM =="
az vm delete --resource-group "$RG" --name "$VM_NAME" --yes

echo "== 2/5: Deleting OS disk =="
DISK_NAME=$(az disk list --resource-group "$RG" --query "[?starts_with(name, '${VM_NAME}_OsDisk')].name" -o tsv)
if [ -n "$DISK_NAME" ]; then
  az disk delete --resource-group "$RG" --name "$DISK_NAME" --yes
fi

echo "== 3/5: Deleting NIC =="
az network nic delete --resource-group "$RG" --name "${VM_NAME}VMNic" || true

echo "== 4/5: Deleting public IP =="
az network public-ip delete --resource-group "$RG" --name "${VM_NAME}PublicIP" || true

echo "== 5/5: Deleting NSG =="
az network nsg delete --resource-group "$RG" --name "${VM_NAME}NSG" || true

echo "Deleting auto-shutdown schedule, if present..."
az resource delete --resource-group "$RG" --resource-type "Microsoft.DevTestLab/schedules" --name "shutdown-computevm-${VM_NAME}" 2>/dev/null || true

echo ""
echo "Done. dcr-syslog-soc-lab left in place for the next deploy."
