// Personal Microsoft Sentinel SOC lab - one-command deployment
// Deploy: az deployment group create --resource-group <rg> --template-file main.bicep --parameters adminObjectId=<your-aad-object-id>

@description('Log Analytics workspace name')
param workspaceName string = 'law-soc-lab'

@description('Azure region')
param location string = resourceGroup().location

@description('Daily ingestion cap in GB - keep low for personal lab cost control')
param dailyQuotaGb int = 1

@description('Data retention in days (free up to 90 with Sentinel enabled)')
param retentionInDays int = 90

@description('AAD object ID to grant Sentinel Contributor - your own account')
param adminObjectId string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
  }
}

resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2023-02-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

resource sentinelContributorRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(workspace.id, adminObjectId, 'Sentinel Contributor')
  scope: workspace
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ab8e14d6-4a74-4a29-9ba8-549422addade')
    principalId: adminObjectId
  }
}

output workspaceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId
