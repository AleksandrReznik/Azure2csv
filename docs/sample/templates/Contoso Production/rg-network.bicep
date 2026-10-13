resource r1 'microsoft.network/virtualnetworks@2024-05-01' = {
  name: 'vnet-hub'
  location: resourceGroup().location
}

resource r2 'microsoft.network/virtualnetworks@2024-05-01' = {
  name: 'vnet-spoke'
  location: resourceGroup().location
}

resource r3 'microsoft.network/networksecuritygroups@2024-05-01' = {
  name: 'nsg-app'
  location: resourceGroup().location
}

resource r4 'microsoft.network/networksecuritygroups@2024-05-01' = {
  name: 'nsg-unused'
  location: resourceGroup().location
}

resource r5 'microsoft.network/routetables@2024-05-01' = {
  name: 'rt-app'
  location: resourceGroup().location
}

resource r6 'microsoft.network/routetables@2024-05-01' = {
  name: 'rt-unused'
  location: resourceGroup().location
}

resource r7 'microsoft.network/applicationsecuritygroups@2024-05-01' = {
  name: 'asg-web'
  location: resourceGroup().location
}

resource r8 'microsoft.network/networkinterfaces@2024-05-01' = {
  name: 'nic-app01'
  location: resourceGroup().location
}

resource r9 'microsoft.network/networkinterfaces@2024-05-01' = {
  name: 'nic-orphan'
  location: resourceGroup().location
}

resource r10 'microsoft.network/natgateways@2024-05-01' = {
  name: 'ng-unused'
  location: resourceGroup().location
}

resource r11 'microsoft.network/privatednszones@2024-05-01' = {
  name: 'privatelink.blob.core.windows.net'
  location: resourceGroup().location
}

resource r12 'microsoft.network/privatednszones/virtualnetworklinks@2024-05-01' = {
  name: 'link-hub'
  location: resourceGroup().location
}

resource r13 'microsoft.network/privatednszones@2024-05-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: resourceGroup().location
}

resource r14 'microsoft.network/privateendpoints@2024-05-01' = {
  name: 'pe-stcontosodata'
  location: resourceGroup().location
}

resource r15 'microsoft.resources/templatespecs@2024-05-01' = {
  name: 'ts-network'
  location: resourceGroup().location
}
