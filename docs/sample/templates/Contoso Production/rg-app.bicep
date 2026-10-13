resource r1 'microsoft.compute/virtualmachines@2024-05-01' = {
  name: 'vm-app01'
  location: resourceGroup().location
}

resource r2 'microsoft.compute/virtualmachines/extensions@2024-05-01' = {
  name: 'AzureMonitorWindowsAgent'
  location: resourceGroup().location
}

resource r3 'microsoft.compute/disks@2024-05-01' = {
  name: 'vm-app01_OsDisk'
  location: resourceGroup().location
}

resource r4 'microsoft.compute/disks@2024-05-01' = {
  name: 'vm-app01_data0'
  location: resourceGroup().location
}

resource r5 'microsoft.web/serverfarms@2024-05-01' = {
  name: 'asp-empty'
  location: resourceGroup().location
}

resource r6 'microsoft.web/serverfarms@2024-05-01' = {
  name: 'asp-web'
  location: resourceGroup().location
}

resource r7 'microsoft.web/sites@2024-05-01' = {
  name: 'app-contoso'
  location: resourceGroup().location
}

resource r8 'microsoft.automation/automationaccounts@2024-05-01' = {
  name: 'aa-contoso'
  location: resourceGroup().location
}

resource r9 'microsoft.automation/automationaccounts/runbooks@2024-05-01' = {
  name: 'Start-VMs'
  location: resourceGroup().location
}

resource r10 'microsoft.automation/automationaccounts/runbooks@2024-05-01' = {
  name: 'Cleanup'
  location: resourceGroup().location
}

resource r11 'microsoft.containerservice/managedclusters@2024-05-01' = {
  name: 'aks-contoso'
  location: resourceGroup().location
}

resource r12 'microsoft.managedidentity/userassignedidentities@2024-05-01' = {
  name: 'uai-app'
  location: resourceGroup().location
}

resource r13 'microsoft.visualstudio/account@2024-05-01' = {
  name: 'contoso-ado'
  location: resourceGroup().location
}

resource r14 'microsoft.visualstudio/account@2024-05-01' = {
  name: 'fabrikam-old'
  location: resourceGroup().location
}

resource r15 'microsoft.visualstudio/account@2024-05-01' = {
  name: 'a0a0a0a0-0000-0000-0000-000000000009'
  location: resourceGroup().location
}

resource r16 'microsoft.logic/workflows@2024-05-01' = {
  name: 'la-orders'
  location: resourceGroup().location
}

resource r17 'microsoft.resources/deploymentscripts@2024-05-01' = {
  name: 'ds-seed'
  location: resourceGroup().location
}

resource r18 'microsoft.insights/workbooks@2024-05-01' = {
  name: '0e0e0e0e-0000-0000-0000-000000000001'
  location: resourceGroup().location
}

resource r19 'microsoft.portal/dashboards@2024-05-01' = {
  name: 'dash-ops'
  location: resourceGroup().location
}

resource r20 'microsoft.insights/scheduledqueryrules@2024-05-01' = {
  name: 'alert-errors'
  location: resourceGroup().location
}

resource r21 'microsoft.apimanagement/service@2024-05-01' = {
  name: 'apim-contoso'
  location: resourceGroup().location
}
