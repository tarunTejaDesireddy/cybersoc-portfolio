// Data Collection Rule: Windows Security Events, filtered to high-value event IDs
// 4624/4625 logon success/fail, 4648 explicit creds, 4672 special privileges,
// 4688 process creation, 4720/4732 account/group changes, 4698/4697 scheduled task/service install

@description('Workspace resource ID to send data to')
param workspaceResourceId string

@description('Azure region')
param location string = resourceGroup().location

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-windows-security-events'
  location: location
  properties: {
    dataSources: {
      windowsEventLogs: [
        {
          name: 'securityEventsDataSource'
          streams: ['Microsoft-SecurityEvent']
          xPathQueries: [
            'Security!*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4720 or EventID=4732 or EventID=4698 or EventID=4697)]]'
          ]
        }
      ]
      performanceCounters: [
        {
          name: 'heartbeatDataSource'
          streams: ['Microsoft-Perf']
          samplingFrequencyInSeconds: 60
          counterSpecifiers: ['\\Processor(_Total)\\% Processor Time']
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
        streams: ['Microsoft-SecurityEvent']
        destinations: ['law-soc-lab-dest']
      }
      {
        streams: ['Microsoft-Perf']
        destinations: ['law-soc-lab-dest']
      }
    ]
  }
}

output dcrId string = dcr.id
