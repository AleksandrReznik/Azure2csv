resource r1 'microsoft.network/publicipaddresses@2024-05-01' = {
  name: 'pip-app01'
  location: resourceGroup().location
}

resource r2 'microsoft.compute/disks@2024-05-01' = {
  name: 'disk-orphan'
  location: resourceGroup().location
}

resource r3 'microsoft.storage/storageaccounts@2024-05-01' = {
  name: 'stcontosodata'
  location: resourceGroup().location
}

resource r4 'microsoft.keyvault/vaults@2024-05-01' = {
  name: 'kv-contoso'
  location: resourceGroup().location
}

resource r5 'microsoft.sql/servers@2024-05-01' = {
  name: 'sql-contoso'
  location: resourceGroup().location
}

resource r6 'microsoft.sql/servers/databases@2024-05-01' = {
  name: 'appdb'
  location: resourceGroup().location
}

resource r7 'microsoft.sql/servers/databases@2024-05-01' = {
  name: 'master'
  location: resourceGroup().location
}

resource r8 'microsoft.recoveryservices/vaults@2024-05-01' = {
  name: 'rsv-contoso'
  location: resourceGroup().location
}

resource r9 'microsoft.operationalinsights/workspaces@2024-05-01' = {
  name: 'law-contoso'
  location: resourceGroup().location
}

resource r10 'microsoft.datafactory/factories@2024-05-01' = {
  name: 'adf-contoso'
  location: resourceGroup().location
}

resource r11 'microsoft.streamanalytics/streamingjobs@2024-05-01' = {
  name: 'asa-telemetry'
  location: resourceGroup().location
}

resource r12 'microsoft.operationsmanagement/solutions@2024-05-01' = {
  name: 'SecurityInsights(law-contoso)'
  location: resourceGroup().location
}
