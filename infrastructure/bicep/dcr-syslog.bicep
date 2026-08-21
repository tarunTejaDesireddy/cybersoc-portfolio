// Data Collection Rule: Syslog, filtered to security-relevant facilities/severities only
// Keeps ingestion volume down against a tight daily quota - only auth/authpriv/cron/daemon/kern/syslog/user
// facilities at warning severity or above are forwarded.

@description('Workspace resource ID to send data to')
param workspaceResourceId string

@description('Azure region')
param location string = resourceGroup().location

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-syslog-soc-lab'
  location: location
  properties: {
    dataSources: {
      syslog: [
        {
          name: 'syslogDataSource'
          streams: ['Microsoft-Syslog']
          facilityNames: ['auth', 'authpriv', 'cron', 'daemon', 'kern', 'syslog', 'user']
          logLevels: ['Warning', 'Error', 'Critical', 'Alert', 'Emergency']
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceResourceId
          name: 'law-soc-lab-dest'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-Syslog']
        destinations: ['law-soc-lab-dest']
        transformKql: 'source | where SeverityLevel in (\'warning\',\'err\',\'crit\',\'alert\',\'emerg\') | where Facility in (\'auth\',\'authpriv\',\'cron\',\'daemon\',\'kern\',\'syslog\',\'user\')'
        outputStream: 'Microsoft-Syslog'
      }
    ]
  }
}

output dcrId string = dcr.id
