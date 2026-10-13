resource r1 'microsoft.network/networkinterfaces@2024-05-01' = {
  name: 'nic-legacy01'
  location: resourceGroup().location
}

resource r2 'microsoft.network/publicipaddresses@2024-05-01' = {
  name: 'pip-basic'
  location: resourceGroup().location
}

resource r3 'microsoft.network/loadbalancers@2024-05-01' = {
  name: 'lb-basic'
  location: resourceGroup().location
}

resource r4 'microsoft.network/applicationgateways@2024-05-01' = {
  name: 'agw-v1'
  location: resourceGroup().location
}

resource r5 'microsoft.compute/virtualmachines@2024-05-01' = {
  name: 'vm-legacy01'
  location: resourceGroup().location
}

resource r6 'microsoft.compute/virtualmachines/extensions@2024-05-01' = {
  name: 'OmsAgentForLinux'
  location: resourceGroup().location
}

resource r7 'microsoft.compute/availabilitysets@2024-05-01' = {
  name: 'avset-empty'
  location: resourceGroup().location
}

resource r8 'microsoft.storage/storageaccounts@2024-05-01' = {
  name: 'stlegacyvhds'
  location: resourceGroup().location
}

resource r9 'microsoft.sqlvirtualmachine/sqlvirtualmachines@2024-05-01' = {
  name: 'vm-legacy01'
  location: resourceGroup().location
}
