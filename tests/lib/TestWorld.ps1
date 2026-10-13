# Fictional "Contoso" tenant used by the offline tests and the sample report. ASCII-only source:
# non-ASCII test strings are built with [char] codes.

$global:TW_Tenant = 'aaaaaaaa-1111-2222-3333-444444444444'
$global:TW_S1 = '11111111-aaaa-bbbb-cccc-000000000001'
$global:TW_S2 = '22222222-aaaa-bbbb-cccc-000000000002'
$global:TW_S3 = '33333333-aaaa-bbbb-cccc-000000000003'
$global:TW_S4 = '44444444-aaaa-bbbb-cccc-000000000004'
$global:TW_OtherTenant = 'bbbbbbbb-9999-8888-7777-666666666666'

# Non-ASCII samples: "Vilniaus saltinis" with s-caron, "Aerzte" with a-umlaut, Tokyo in kanji
$global:TW_Lt = 'Vilniaus ' + [char]0x0161 + 'altinis'
$global:TW_De = [char]0x00C4 + 'rzte'
$global:TW_Jp = [string][char]0x6771 + [char]0x4EAC

function New-TWId {
    param([string] $Sub, [string] $Rg, [string] $Type, [string] $Name)
    $types = $Type.Split('/')
    $names = $Name.Split('/')
    $s = '/subscriptions/{0}/resourceGroups/{1}/providers/{2}' -f $Sub, $Rg, $types[0]
    for ($i = 1; $i -lt $types.Count; $i++) { $s += '/' + $types[$i] + '/' + $names[$i - 1] }
    return $s
}

function New-TWRes {
    param([string] $Sub, [string] $Rg, [string] $Type, [string] $Name, $Props = @{}, [string] $Location = 'westeurope',
        $Sku = $null, $Tags = $null, $Kind = $null, $Identity = $null, $Zones = $null, $ManagedBy = $null, [string] $State = 'Succeeded')
    $id = New-TWId -Sub $Sub -Rg $Rg -Type $Type -Name $Name
    $leaf = $Name.Split('/')[-1]
    if ($null -eq $Props) { $Props = @{} }
    if ($State -and $Props -is [System.Collections.IDictionary] -and -not $Props.Contains('provisioningState')) { $Props['provisioningState'] = $State }
    return [ordered]@{
        id = $id; name = $leaf; type = $Type.ToLowerInvariant(); location = $Location; resourceGroup = $Rg.ToLowerInvariant()
        subscriptionId = $Sub; kind = $Kind; managedBy = $ManagedBy; sku = $Sku; plan = $null; identity = $Identity; tags = $Tags
        zones = $Zones; extendedLocation = $null; apiVersion = '2024-05-01'; provisioningState = $State
        tagsJson = $(if ($null -ne $Tags) { ConvertTo-Json -InputObject $Tags -Depth 5 -Compress } else { $null })
        propertiesJson = (ConvertTo-Json -InputObject $Props -Depth 30 -Compress)
    }
}

function New-TWTemplateResult {
    # The answer of exportTemplate as the text Azure sends (never through ConvertTo-Json): template expressions with
    # single quotes, a date with seven decimals and a 20-digit number must reach the file unchanged.
    param([string] $Sub, [string] $Rg, $Ids, [string] $Format)
    $all = @($global:TW.Resources | Where-Object { $_['subscriptionId'] -eq $Sub -and $_['resourceGroup'] -eq $Rg.ToLowerInvariant() })
    $ids = @($Ids)
    if (-not ($ids.Count -eq 1 -and $ids[0] -eq '*')) { $all = @($all | Where-Object { $ids -contains $_['id'] }) }
    $issues = ''
    if ($Rg -eq 'rg-app') {
        $issues = ',"error":{"code":"ExportTemplateCompletedWithErrors","message":"Export template operation completed with errors. Some resources were not exported. Please see details for more information.",' +
            '"details":[{"code":"ExportTemplateProviderError","target":"Microsoft.Web/sites/config","message":"Could not get resources of the type ''Microsoft.Web/sites/config''. Resources of this type will not be exported."}]}'
    }
    if ($Format -eq 'Bicep') {
        $n = 0
        $lines = @($all | ForEach-Object { $n++; ("resource r{0} '{1}@2024-05-01' = {{`n  name: '{2}'`n  location: resourceGroup().location`n}}" -f $n, $_['type'], $_['name']) })
        return ('{"output":' + (ConvertTo-A2CJsonLiteral ([string]::Join("`n`n", $lines) + "`n")) + $issues + '}')
    }
    $res = @($all | ForEach-Object {
            '{"type":"' + $_['type'] + '","apiVersion":"2024-05-01","name":"' + $_['name'] + '","location":"[resourceGroup().location]",' +
            '"dependsOn":["[resourceId(''Microsoft.Network/virtualNetworks'', ''vnet-hub'')]"],"properties":{"createdOn":"2024-01-01T00:00:00.0000000Z","big":12345678901234567890,"ratio":1.0}}' })
    return ('{"template":{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","contentVersion":"1.0.0.0","parameters":{},"variables":{},' +
        '"resources":[' + [string]::Join(',', $res) + ']}' + $issues + '}')
}

function New-TWPage {
    # ARM list page with nextLink paging via &twSkip=N
    param($Items, [string] $Path, [int] $PageSize = 20)
    $all = @($Items)
    $offset = 0
    if ($Path -match 'twSkip=(\d+)') { $offset = [int]$Matches[1] }
    $end = [math]::Min($all.Count, $offset + $PageSize) - 1
    $slice = @()
    if ($offset -le $end) { $slice = @($all[$offset..$end]) }
    $obj = [ordered]@{ value = $slice }
    if ($end + 1 -lt $all.Count) {
        $base = ($Path -replace '&twSkip=\d+', '')
        $obj['nextLink'] = 'https://management.azure.com' + $base + '&twSkip=' + ($end + 1)
    }
    return $obj
}

function New-TWGraphPage {
    param($Items, [string] $Path, [int] $PageSize = 3)
    $all = @($Items)
    $offset = 0
    if ($Path -match 'twSkip=(\d+)') { $offset = [int]$Matches[1] }
    $end = [math]::Min($all.Count, $offset + $PageSize) - 1
    $slice = @()
    if ($offset -le $end) { $slice = @($all[$offset..$end]) }
    $obj = [ordered]@{ value = $slice }
    if ($end + 1 -lt $all.Count) {
        $base = ($Path -replace '[&?]twSkip=\d+', '')
        $sep = '?'; if ($base -match '\?') { $sep = '&' }
        $obj['@odata.nextLink'] = 'https://graph.microsoft.com' + $base + $sep + 'twSkip=' + ($end + 1)
    }
    return $obj
}

function New-TWWorld {
    $T = $global:TW_Tenant; $S1 = $global:TW_S1; $S2 = $global:TW_S2
    $w = @{
        Tenant = $T
        Context = [pscustomobject]@{
            Account = [pscustomobject]@{ Id = 'alex.admin@contoso.onmicrosoft.com' }
            Tenant = [pscustomobject]@{ Id = $T }
            Environment = [pscustomobject]@{ ResourceManagerUrl = 'https://management.azure.com/'; ExtendedProperties = @{ MicrosoftGraphUrl = 'https://graph.microsoft.com' } }
        }
        Arg = @{}; ArgPageSize = 7; ArmPageSize = 20; ArmRoutes = [System.Collections.Generic.List[object]]::new()
        GraphRoutes = [System.Collections.Generic.List[object]]::new(); Throttle = [System.Collections.Generic.List[object]]::new()
        Fail = [System.Collections.Generic.List[object]]::new(); ConnectError = ''; AdoRoutes = [System.Collections.Generic.List[object]]::new()
        CanPrompt = $true; SignInWorks = $true; SignInCalls = [System.Collections.Generic.List[object]]::new(); FreeSpace = [long]1TB
        Web = @{}; KuduDenied = $false; WebZips = @{}; SignatureValid = $true; ArtifactToolFails = @(); DownloadSizes = @{}; MissingTables = @()
    }

    # ---- subscriptions (ARM) -------------------------------------------------------------------------
    $w.Subscriptions = @(
        [ordered]@{ id = ('/subscriptions/' + $S1); subscriptionId = $S1; displayName = 'Contoso Production'; state = 'Enabled'; tenantId = $T; authorizationSource = 'RoleBased'
            subscriptionPolicies = [ordered]@{ quotaId = 'EnterpriseAgreement_2014-09-01'; spendingLimit = 'Off' }; tags = [ordered]@{ env = 'prod'; costcenter = 'CC-100' } }
        [ordered]@{ id = ('/subscriptions/' + $S2); subscriptionId = $S2; displayName = 'Contoso Development'; state = 'Enabled'; tenantId = $T; authorizationSource = 'RoleBased'
            subscriptionPolicies = [ordered]@{ quotaId = 'MSDN_2014-09-01'; spendingLimit = 'On' }; tags = [ordered]@{ env = 'dev' } }
        [ordered]@{ subscriptionId = $global:TW_S3; displayName = 'Contoso Legacy'; state = 'Disabled'; tenantId = $T; authorizationSource = 'RoleBased'
            subscriptionPolicies = [ordered]@{ quotaId = 'PayAsYouGo_2014-09-01'; spendingLimit = 'Off' } }
        [ordered]@{ subscriptionId = $global:TW_S4; displayName = 'Fabrikam Customer'; state = 'Enabled'; tenantId = $global:TW_OtherTenant; authorizationSource = 'RoleBased'
            subscriptionPolicies = [ordered]@{ quotaId = 'EnterpriseAgreement_2014-09-01'; spendingLimit = 'Off' } }
    )

    # ---- management groups and containers (Resource Graph) -------------------------------------------
    $mgRootId = '/providers/Microsoft.Management/managementGroups/' + $T
    $w.Arg['managementGroups'] = @(
        [ordered]@{ id = $mgRootId; name = $T; tenantId = $T; propertiesJson = (ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{ displayName = 'Tenant Root Group'; details = [ordered]@{ parent = $null } })) }
        [ordered]@{ id = '/providers/Microsoft.Management/managementGroups/mg-contoso'; name = 'mg-contoso'; tenantId = $T; propertiesJson = (ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{ displayName = 'Contoso'; details = [ordered]@{ parent = [ordered]@{ id = $mgRootId; name = $T } } })) }
        [ordered]@{ id = '/providers/Microsoft.Management/managementGroups/mg-landingzones'; name = 'mg-landingzones'; tenantId = $T; propertiesJson = (ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{ displayName = 'Landing Zones'; details = [ordered]@{ parent = [ordered]@{ id = '/providers/Microsoft.Management/managementGroups/mg-contoso'; name = 'mg-contoso' } } })) }
        [ordered]@{ id = '/providers/Microsoft.Management/managementGroups/mg-sandbox'; name = 'mg-sandbox'; tenantId = $T; propertiesJson = (ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{ displayName = 'Sandbox'; details = [ordered]@{ parent = [ordered]@{ id = '/providers/Microsoft.Management/managementGroups/mg-contoso'; name = 'mg-contoso' } } })) }
    )
    $chain1 = @([ordered]@{ name = 'mg-landingzones'; displayName = 'Landing Zones' }, [ordered]@{ name = 'mg-contoso'; displayName = 'Contoso' }, [ordered]@{ name = $T; displayName = 'Tenant Root Group' })
    $chain2 = @([ordered]@{ name = 'mg-sandbox'; displayName = 'Sandbox' }, [ordered]@{ name = 'mg-contoso'; displayName = 'Contoso' }, [ordered]@{ name = $T; displayName = 'Tenant Root Group' })
    $containers = [System.Collections.Generic.List[object]]::new()
    $containers.Add([ordered]@{ id = '/subscriptions/' + $S1; name = 'Contoso Production'; type = 'microsoft.resources/subscriptions'; location = ''; subscriptionId = $S1; tags = [ordered]@{ env = 'prod'; costcenter = 'CC-100' }; managedBy = ''; propertiesJson = (ConvertTo-Json -Compress -Depth 6 -InputObject ([ordered]@{ state = 'Enabled'; managementGroupAncestorsChain = $chain1 })) })
    $containers.Add([ordered]@{ id = '/subscriptions/' + $S2; name = 'Contoso Development'; type = 'microsoft.resources/subscriptions'; location = ''; subscriptionId = $S2; tags = [ordered]@{ env = 'dev' }; managedBy = ''; propertiesJson = (ConvertTo-Json -Compress -Depth 6 -InputObject ([ordered]@{ state = 'Enabled'; managementGroupAncestorsChain = $chain2 })) })
    foreach ($rg in @(@($S1, 'rg-app', 'westeurope', [ordered]@{ app = 'contoso-web'; owner = $global:TW_Lt }), @($S1, 'rg-network', 'westeurope', $null), @($S1, 'rg-data', 'westeurope', [ordered]@{ app = 'contoso-web' }),
            @($S1, 'rg-empty', 'northeurope', $null), @($S1, 'rg-legacy', 'westeurope', [ordered]@{ owner = $global:TW_De }), @($S2, 'rg-dev', 'westeurope', $null), @($S2, 'NetworkWatcherRG', 'westeurope', $null))) {
        $containers.Add([ordered]@{ id = ('/subscriptions/{0}/resourceGroups/{1}' -f $rg[0], $rg[1]); name = $rg[1]; type = 'microsoft.resources/subscriptions/resourcegroups'; location = $rg[2]; subscriptionId = $rg[0]; tags = $rg[3]; managedBy = ''; propertiesJson = '{"provisioningState":"Succeeded"}' })
    }
    $w.Arg['containers'] = $containers.ToArray()
    $w.Arg['mgSubscriptions'] = @([ordered]@{ id = '/subscriptions/' + $S1; subscriptionId = $S1 })

    # ---- resources (Resource Graph) ------------------------------------------------------------------
    $id = { param($s, $g, $t, $n) New-TWId -Sub $s -Rg $g -Type $t -Name $n }
    $vnetHub = & $id $S1 'rg-network' 'Microsoft.Network/virtualNetworks' 'vnet-hub'
    $vnetSpoke = & $id $S1 'rg-network' 'Microsoft.Network/virtualNetworks' 'vnet-spoke'
    $snetApp = $vnetHub + '/subnets/snet-app'
    $snetData = $vnetHub + '/subnets/snet-data'
    $snetWeb = $vnetSpoke + '/subnets/snet-web'
    $nsgApp = & $id $S1 'rg-network' 'Microsoft.Network/networkSecurityGroups' 'nsg-app'
    $rtApp = & $id $S1 'rg-network' 'Microsoft.Network/routeTables' 'rt-app'
    $nicApp = & $id $S1 'rg-network' 'Microsoft.Network/networkInterfaces' 'nic-app01'
    $nicLegacy = & $id $S1 'rg-legacy' 'Microsoft.Network/networkInterfaces' 'nic-legacy01'
    $pipApp = & $id $S1 'rg-data' 'Microsoft.Network/publicIPAddresses' 'pip-app01'
    $asgWeb = & $id $S1 'rg-network' 'Microsoft.Network/applicationSecurityGroups' 'asg-web'
    $vmApp = & $id $S1 'rg-app' 'Microsoft.Compute/virtualMachines' 'vm-app01'
    $vmLegacy = & $id $S1 'rg-legacy' 'Microsoft.Compute/virtualMachines' 'vm-legacy01'
    $diskOs = & $id $S1 'rg-app' 'Microsoft.Compute/disks' 'vm-app01_OsDisk'
    $diskData = & $id $S1 'rg-app' 'Microsoft.Compute/disks' 'vm-app01_data0'
    $stData = & $id $S1 'rg-data' 'Microsoft.Storage/storageAccounts' 'stcontosodata'
    $aspWeb = & $id $S1 'rg-app' 'Microsoft.Web/serverFarms' 'asp-web'
    $uai = & $id $S1 'rg-app' 'Microsoft.ManagedIdentity/userAssignedIdentities' 'uai-app'
    $w.Ids = @{ VmApp = $vmApp; VmLegacy = $vmLegacy; NicApp = $nicApp; PipApp = $pipApp; VnetHub = $vnetHub; StData = $stData; Uai = $uai; NsgApp = $nsgApp }

    $res = [System.Collections.Generic.List[object]]::new()
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/virtualNetworks' 'vnet-hub' ([ordered]@{
                    addressSpace = [ordered]@{ addressPrefixes = @('10.0.0.0/16') }; dhcpOptions = [ordered]@{ dnsServers = @('10.0.0.4', '10.0.0.5') }; enableDdosProtection = $false
                    subnets = @(
                        [ordered]@{ id = $snetApp; name = 'snet-app'; properties = [ordered]@{ addressPrefix = '10.0.1.0/24'; networkSecurityGroup = [ordered]@{ id = $nsgApp }; routeTable = [ordered]@{ id = $rtApp }
                                serviceEndpoints = @([ordered]@{ service = 'Microsoft.Storage'; locations = @('westeurope') }); ipConfigurations = @([ordered]@{ id = $nicApp + '/ipConfigurations/ipconfig1' }); privateEndpointNetworkPolicies = 'Disabled' } }
                        [ordered]@{ id = $snetData; name = 'snet-data'; properties = [ordered]@{ addressPrefix = '10.0.2.0/24'; delegations = @([ordered]@{ name = 'sqlmi'; properties = [ordered]@{ serviceName = 'Microsoft.Sql/managedInstances' } }); defaultOutboundAccess = $false } }
                        [ordered]@{ id = $vnetHub + '/subnets/GatewaySubnet'; name = 'GatewaySubnet'; properties = [ordered]@{ addressPrefix = '10.0.255.0/27' } }
                    )
                    virtualNetworkPeerings = @([ordered]@{ name = 'hub-to-spoke'; properties = [ordered]@{ remoteVirtualNetwork = [ordered]@{ id = $vnetSpoke }; peeringState = 'Connected'; peeringSyncLevel = 'FullyInSync'
                                allowVirtualNetworkAccess = $true; allowForwardedTraffic = $true; allowGatewayTransit = $true; useRemoteGateways = $false; remoteAddressSpace = [ordered]@{ addressPrefixes = @('10.1.0.0/16') } } })
                })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/virtualNetworks' 'vnet-spoke' ([ordered]@{
                    addressSpace = [ordered]@{ addressPrefixes = @('10.1.0.0/16') }; dhcpOptions = [ordered]@{ dnsServers = @() }
                    subnets = @([ordered]@{ id = $snetWeb; name = 'snet-web'; properties = [ordered]@{ addressPrefix = '10.1.1.0/24' } })
                    virtualNetworkPeerings = @([ordered]@{ name = 'spoke-to-hub'; properties = [ordered]@{ remoteVirtualNetwork = [ordered]@{ id = $vnetHub }; peeringState = 'Connected'; peeringSyncLevel = 'FullyInSync'
                                allowVirtualNetworkAccess = $true; allowForwardedTraffic = $false; allowGatewayTransit = $false; useRemoteGateways = $true; remoteAddressSpace = [ordered]@{ addressPrefixes = @('10.0.0.0/16') } } })
                })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/networkSecurityGroups' 'nsg-app' ([ordered]@{
                    securityRules = @(
                        [ordered]@{ name = 'Allow-RDP-Internet'; properties = [ordered]@{ priority = 100; direction = 'Inbound'; access = 'Allow'; protocol = 'Tcp'; sourceAddressPrefix = 'Internet'; sourcePortRange = '*'; destinationAddressPrefix = '*'; destinationPortRange = '3389' } }
                        [ordered]@{ name = 'Allow-HTTPS'; properties = [ordered]@{ priority = 110; direction = 'Inbound'; access = 'Allow'; protocol = 'Tcp'; sourceAddressPrefix = '*'; sourcePortRange = '*'; destinationAddressPrefixes = @('10.0.1.4', '10.0.1.5'); destinationPortRanges = @('443', '8443'); description = '=HYPERLINK("http://evil")' } }
                    )
                    defaultSecurityRules = @([ordered]@{ name = 'AllowVnetInBound'; properties = [ordered]@{ priority = 65000; direction = 'Inbound'; access = 'Allow'; protocol = '*'; sourceAddressPrefix = 'VirtualNetwork'; sourcePortRange = '*'; destinationAddressPrefix = 'VirtualNetwork'; destinationPortRange = '*'; description = 'Allow inbound traffic from all VMs in VNET' } })
                    subnets = @([ordered]@{ id = $snetApp })
                })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/networkSecurityGroups' 'nsg-unused' ([ordered]@{ securityRules = @(); defaultSecurityRules = @() })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/routeTables' 'rt-app' ([ordered]@{ disableBgpRoutePropagation = $true
                    routes = @([ordered]@{ name = 'default-to-fw'; properties = [ordered]@{ addressPrefix = '0.0.0.0/0'; nextHopType = 'VirtualAppliance'; nextHopIpAddress = '10.0.0.4' } })
                    subnets = @([ordered]@{ id = $snetApp }) })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/routeTables' 'rt-unused' ([ordered]@{ routes = @() })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/applicationSecurityGroups' 'asg-web' ([ordered]@{})))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/networkInterfaces' 'nic-app01' ([ordered]@{
                    ipConfigurations = @([ordered]@{ id = $nicApp + '/ipConfigurations/ipconfig1'; name = 'ipconfig1'; properties = [ordered]@{ privateIPAddress = '10.0.1.4'; primary = $true
                                subnet = [ordered]@{ id = $snetApp }; publicIPAddress = [ordered]@{ id = $pipApp }; applicationSecurityGroups = @([ordered]@{ id = $asgWeb }) } })
                    dnsSettings = [ordered]@{ dnsServers = @('1.1.1.1') }; virtualMachine = [ordered]@{ id = $vmApp }
                })))
    $res.Add((New-TWRes $S1 'rg-legacy' 'Microsoft.Network/networkInterfaces' 'nic-legacy01' ([ordered]@{
                    ipConfigurations = @([ordered]@{ id = $nicLegacy + '/ipConfigurations/ipconfig1'; name = 'ipconfig1'; properties = [ordered]@{ privateIPAddress = '10.1.1.10'; primary = $true; subnet = [ordered]@{ id = $snetWeb } } })
                    dnsSettings = [ordered]@{ dnsServers = @() }; virtualMachine = [ordered]@{ id = $vmLegacy }
                })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/networkInterfaces' 'nic-orphan' ([ordered]@{
                    ipConfigurations = @([ordered]@{ id = 'x'; name = 'ipconfig1'; properties = [ordered]@{ privateIPAddress = '10.0.1.99'; subnet = [ordered]@{ id = $snetApp } } }); hostedWorkloads = @()
                })))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.Network/publicIPAddresses' 'pip-app01' ([ordered]@{ ipAddress = '20.50.60.70'; publicIPAllocationMethod = 'Static'; publicIPAddressVersion = 'IPv4'
                    ipConfiguration = [ordered]@{ id = $nicApp + '/ipConfigurations/ipconfig1' }; dnsSettings = [ordered]@{ fqdn = 'contoso-app.westeurope.cloudapp.azure.com' } }) -Sku ([ordered]@{ name = 'Standard'; tier = 'Regional' }) -Zones @('1', '2', '3')))
    $res.Add((New-TWRes $S1 'rg-legacy' 'Microsoft.Network/publicIPAddresses' 'pip-basic' ([ordered]@{ publicIPAllocationMethod = 'Dynamic'; publicIPAddressVersion = 'IPv4' }) -Sku ([ordered]@{ name = 'Basic'; tier = 'Regional' })))
    $res.Add((New-TWRes $S1 'rg-legacy' 'Microsoft.Network/loadBalancers' 'lb-basic' ([ordered]@{ backendAddressPools = @(); inboundNatRules = @(); frontendIPConfigurations = @() }) -Sku ([ordered]@{ name = 'Basic'; tier = 'Regional' })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/natGateways' 'ng-unused' ([ordered]@{ idleTimeoutInMinutes = 4 }) -Sku ([ordered]@{ name = 'Standard' })))
    $res.Add((New-TWRes $S1 'rg-legacy' 'Microsoft.Network/applicationGateways' 'agw-v1' ([ordered]@{ sku = [ordered]@{ name = 'Standard_Medium'; tier = 'Standard'; capacity = 2 } })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/privateDnsZones' 'privatelink.blob.core.windows.net' ([ordered]@{ numberOfRecordSets = 3; numberOfVirtualNetworkLinks = 1; numberOfVirtualNetworkLinksWithRegistration = 0 }) -Location 'global'))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/privateDnsZones/virtualNetworkLinks' 'privatelink.blob.core.windows.net/link-hub' ([ordered]@{ virtualNetwork = [ordered]@{ id = $vnetHub }; registrationEnabled = $false; virtualNetworkLinkState = 'Completed' }) -Location 'global'))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/privateDnsZones' 'privatelink.vaultcore.azure.net' ([ordered]@{ numberOfRecordSets = 1; numberOfVirtualNetworkLinks = 0 }) -Location 'global'))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Network/privateEndpoints' 'pe-stcontosodata' ([ordered]@{
                    subnet = [ordered]@{ id = $snetApp }
                    privateLinkServiceConnections = @([ordered]@{ name = 'pe-conn'; properties = [ordered]@{ privateLinkServiceId = $stData; groupIds = @('blob'); privateLinkServiceConnectionState = [ordered]@{ status = 'Approved' } } })
                    customDnsConfigs = @([ordered]@{ fqdn = 'stcontosodata.blob.core.windows.net'; ipAddresses = @('10.0.1.10') })
                })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Compute/virtualMachines' 'vm-app01' ([ordered]@{
                    hardwareProfile = [ordered]@{ vmSize = 'Standard_D4s_v5' }; licenseType = 'Windows_Server'; priority = 'Regular'
                    storageProfile = [ordered]@{ osDisk = [ordered]@{ osType = 'Windows'; name = 'vm-app01_OsDisk'; managedDisk = [ordered]@{ id = $diskOs }; diskSizeGB = 128 }
                        dataDisks = @([ordered]@{ lun = 0; name = 'vm-app01_data0'; managedDisk = [ordered]@{ id = $diskData }; diskSizeGB = 512 })
                        imageReference = [ordered]@{ publisher = 'MicrosoftWindowsServer'; offer = 'WindowsServer'; sku = '2019-datacenter-gensecond'; version = 'latest'; exactVersion = '17763.4252.230404' } }
                    osProfile = [ordered]@{ computerName = 'vm-app01' }
                    networkProfile = [ordered]@{ networkInterfaces = @([ordered]@{ id = $nicApp }) }
                    securityProfile = [ordered]@{ securityType = 'TrustedLaunch' }; diagnosticsProfile = [ordered]@{ bootDiagnostics = [ordered]@{ enabled = $true } }
                    extended = [ordered]@{ instanceView = [ordered]@{ powerState = [ordered]@{ code = 'PowerState/running' }; osName = 'Windows Server 2019 Datacenter'; osVersion = '10.0.17763'; hyperVGeneration = 'V2' } }
                    timeCreated = '2023-05-01T10:00:00Z'
                }) -Zones @('1') -Identity ([ordered]@{ type = 'SystemAssigned, UserAssigned'; principalId = 'eeeeeeee-0000-0000-0000-000000000001'; tenantId = $T; userAssignedIdentities = [ordered]@{ $uai = [ordered]@{ principalId = 'eeeeeeee-0000-0000-0000-000000000009'; clientId = 'ffffffff-0000-0000-0000-000000000009' } } }) -Tags ([ordered]@{ app = 'contoso-web'; owner = $global:TW_Lt })))
    $res.Add((New-TWRes $S1 'rg-legacy' 'Microsoft.Compute/virtualMachines' 'vm-legacy01' ([ordered]@{
                    hardwareProfile = [ordered]@{ vmSize = 'Standard_DS2_v2' }
                    storageProfile = [ordered]@{ osDisk = [ordered]@{ osType = 'Linux'; name = 'vm-legacy01-os'; vhd = [ordered]@{ uri = 'https://stlegacyvhds.blob.core.windows.net/vhds/vm-legacy01.vhd' }; diskSizeGB = 30 }; dataDisks = @()
                        imageReference = [ordered]@{ publisher = 'Canonical'; offer = 'UbuntuServer'; sku = '16.04-LTS'; version = 'latest' } }
                    networkProfile = [ordered]@{ networkInterfaces = @([ordered]@{ id = $nicLegacy }) }
                    extended = [ordered]@{ instanceView = [ordered]@{ powerState = [ordered]@{ code = 'PowerState/stopped' } } }
                }) -Location 'westeurope'))
    $res.Add((New-TWRes $S1 'rg-legacy' 'Microsoft.Compute/virtualMachines/extensions' 'vm-legacy01/OmsAgentForLinux' ([ordered]@{ publisher = 'Microsoft.EnterpriseCloud.Monitoring'; type = 'OmsAgentForLinux'; typeHandlerVersion = '1.14' })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Compute/virtualMachines/extensions' 'vm-app01/AzureMonitorWindowsAgent' ([ordered]@{ publisher = 'Microsoft.Azure.Monitor'; type = 'AzureMonitorWindowsAgent'; typeHandlerVersion = '1.10' })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Compute/disks' 'vm-app01_OsDisk' ([ordered]@{ diskSizeGB = 128; diskState = 'Attached'; osType = 'Windows'; timeCreated = '2023-05-01T10:00:00Z'; encryption = [ordered]@{ type = 'EncryptionAtRestWithPlatformKey' }; networkAccessPolicy = 'AllowAll' }) -Sku ([ordered]@{ name = 'Premium_LRS'; tier = 'Premium' }) -ManagedBy $vmApp -Zones @('1')))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Compute/disks' 'vm-app01_data0' ([ordered]@{ diskSizeGB = 512; diskState = 'Attached'; encryption = [ordered]@{ type = 'EncryptionAtRestWithPlatformKey' } }) -Sku ([ordered]@{ name = 'Premium_LRS'; tier = 'Premium' }) -ManagedBy $vmApp -Zones @('1')))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.Compute/disks' 'disk-orphan' ([ordered]@{ diskSizeGB = 256; diskState = 'Unattached'; encryption = [ordered]@{ type = 'EncryptionAtRestWithPlatformKey' } }) -Sku ([ordered]@{ name = 'Standard_LRS'; tier = 'Standard' }) -ManagedBy ''))
    $res.Add((New-TWRes $S1 'rg-legacy' 'Microsoft.Compute/availabilitySets' 'avset-empty' ([ordered]@{ virtualMachines = @(); platformFaultDomainCount = 2 }) -Sku ([ordered]@{ name = 'Aligned' })))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.Storage/storageAccounts' 'stcontosodata' ([ordered]@{
                    minimumTlsVersion = 'TLS1_0'; supportsHttpsTrafficOnly = $true; networkAcls = [ordered]@{ defaultAction = 'Allow' }; encryption = [ordered]@{ keySource = 'Microsoft.Storage' }
                    isHnsEnabled = $false; accessTier = 'Hot'; creationTime = '2022-01-10T08:00:00Z'; primaryLocation = 'westeurope'; secondaryLocation = 'northeurope'; statusOfPrimary = 'available'
                    privateEndpointConnections = @([ordered]@{ id = 'pec1' })
                }) -Kind 'StorageV2' -Sku ([ordered]@{ name = 'Standard_GRS'; tier = 'Standard' }) -Tags ([ordered]@{ owner = $global:TW_Lt; dept = $global:TW_De; site = $global:TW_Jp })))
    $res.Add((New-TWRes $S1 'rg-legacy' 'Microsoft.Storage/storageAccounts' 'stlegacyvhds' ([ordered]@{ minimumTlsVersion = 'TLS1_2'; supportsHttpsTrafficOnly = $true; allowBlobPublicAccess = $true; allowSharedKeyAccess = $true; networkAcls = [ordered]@{ defaultAction = 'Allow' } }) -Kind 'Storage' -Sku ([ordered]@{ name = 'Standard_LRS'; tier = 'Standard' })))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.KeyVault/vaults' 'kv-contoso' ([ordered]@{ tenantId = $T; enableRbacAuthorization = $false; enableSoftDelete = $true; softDeleteRetentionInDays = 90
                    accessPolicies = @([ordered]@{ tenantId = $T; objectId = 'dddddddd-0000-0000-0000-000000000001' }, [ordered]@{ tenantId = $T; objectId = 'dddddddd-0000-0000-0000-000000000002' })
                    publicNetworkAccess = 'Enabled'; networkAcls = [ordered]@{ defaultAction = 'Allow' }; vaultUri = 'https://kv-contoso.vault.azure.net/'; sku = [ordered]@{ family = 'A'; name = 'standard' } })))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.Sql/servers' 'sql-contoso' ([ordered]@{ version = '12.0'; fullyQualifiedDomainName = 'sql-contoso.database.windows.net'; publicNetworkAccess = 'Enabled'; minimalTlsVersion = '1.0'; state = 'Ready'
                    administrators = [ordered]@{ administratorType = 'ActiveDirectory'; login = 'sql-admins'; azureADOnlyAuthentication = $false; tenantId = $T } }) -Kind 'v12.0'))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.Sql/servers/databases' 'sql-contoso/appdb' ([ordered]@{ maxSizeBytes = 34359738368; zoneRedundant = $false; licenseType = 'LicenseIncluded'; currentBackupStorageRedundancy = 'Geo'; status = 'Online'; creationDate = '2022-02-01T00:00:00Z' }) -Sku ([ordered]@{ name = 'GP_Gen5'; tier = 'GeneralPurpose'; capacity = 2; family = 'Gen5' }) -Kind 'v12.0,user,vcore'))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.Sql/servers/databases' 'sql-contoso/master' ([ordered]@{ maxSizeBytes = 34359738368; status = 'Online' }) -Sku ([ordered]@{ name = 'System'; tier = 'System' }) -Kind 'v12.0,system'))
    $res.Add((New-TWRes $S1 'rg-legacy' 'Microsoft.SqlVirtualMachine/sqlVirtualMachines' 'vm-legacy01' ([ordered]@{ virtualMachineResourceId = $vmLegacy; sqlImageOffer = 'SQL2014SP3-WS2012R2'; sqlImageSku = 'Standard'; sqlServerLicenseType = 'PAYG'; sqlManagement = 'LightWeight' })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Web/serverFarms' 'asp-empty' ([ordered]@{ numberOfSites = 0; reserved = $false; maximumNumberOfWorkers = 30 }) -Kind 'app' -Sku ([ordered]@{ name = 'P1v3'; tier = 'PremiumV3'; capacity = 1 })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Web/serverFarms' 'asp-web' ([ordered]@{ numberOfSites = 1; reserved = $true; zoneRedundant = $false }) -Kind 'linux' -Sku ([ordered]@{ name = 'S1'; tier = 'Standard'; capacity = 2 })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Web/sites' 'app-contoso' ([ordered]@{ serverFarmId = $aspWeb; state = 'Running'; defaultHostName = 'app-contoso.azurewebsites.net'; httpsOnly = $false; publicNetworkAccess = 'Enabled'
                    virtualNetworkSubnetId = ('/subscriptions/{0}/resourceGroups/rg-old/providers/Microsoft.Network/virtualNetworks/vnet-old/subnets/snet-integration' -f $S1) }) -Kind 'app,linux' -Identity ([ordered]@{ type = 'SystemAssigned'; principalId = 'eeeeeeee-0000-0000-0000-000000000003'; tenantId = $T })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Automation/automationAccounts' 'aa-contoso' ([ordered]@{ state = 'Ok'; publicNetworkAccess = $true; sku = [ordered]@{ name = 'Basic' } })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Automation/automationAccounts/runbooks' 'aa-contoso/Start-VMs' ([ordered]@{ runbookType = 'PowerShell72'; state = 'Published'; lastModifiedTime = '2024-03-01T09:00:00Z'; description = 'Starts VMs' })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Automation/automationAccounts/runbooks' 'aa-contoso/Cleanup' ([ordered]@{ runbookType = 'Python2'; state = 'Published'; lastModifiedTime = '2021-06-01T09:00:00Z' })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.ContainerService/managedClusters' 'aks-contoso' ([ordered]@{ kubernetesVersion = '1.27.3'; currentKubernetesVersion = '1.27.3'
                    agentPoolProfiles = @([ordered]@{ name = 'system'; count = 3; vmSize = 'Standard_D4s_v5'; osType = 'Linux'; mode = 'System'; orchestratorVersion = '1.27.3' }, [ordered]@{ name = 'user'; count = 2; vmSize = 'Standard_D8s_v5'; osType = 'Linux'; mode = 'User' })
                    networkProfile = [ordered]@{ networkPlugin = 'azure'; networkPolicy = 'calico' }; apiServerAccessProfile = [ordered]@{ enablePrivateCluster = $false }
                    aadProfile = [ordered]@{ managed = $true; enableAzureRBAC = $true; tenantID = $T }; powerState = [ordered]@{ code = 'Running' } }) -Sku ([ordered]@{ name = 'Base'; tier = 'Free' }) -Identity ([ordered]@{ type = 'SystemAssigned'; principalId = 'eeeeeeee-0000-0000-0000-000000000004'; tenantId = $T })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.ManagedIdentity/userAssignedIdentities' 'uai-app' ([ordered]@{ principalId = 'eeeeeeee-0000-0000-0000-000000000009'; clientId = 'ffffffff-0000-0000-0000-000000000009'; tenantId = $T })))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.RecoveryServices/vaults' 'rsv-contoso' ([ordered]@{ provisioningState = 'Succeeded' }) -Sku ([ordered]@{ name = 'RS0'; tier = 'Standard' })))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.OperationalInsights/workspaces' 'law-contoso' ([ordered]@{ retentionInDays = 30; sku = [ordered]@{ name = 'PerGB2018' } })))
    # subscription 2
    $vnetDev = & $id $S2 'rg-dev' 'Microsoft.Network/virtualNetworks' 'vnet-dev'
    $nicDev = & $id $S2 'rg-dev' 'Microsoft.Network/networkInterfaces' 'nic-dev01'
    $vmDev = & $id $S2 'rg-dev' 'Microsoft.Compute/virtualMachines' 'vm-dev01'
    $diskDev = & $id $S2 'rg-dev' 'Microsoft.Compute/disks' 'vm-dev01_OsDisk'
    $w.Ids['VmDev'] = $vmDev
    $res.Add((New-TWRes $S2 'rg-dev' 'Microsoft.Network/virtualNetworks' 'vnet-dev' ([ordered]@{ addressSpace = [ordered]@{ addressPrefixes = @('10.1.0.0/16') }; dhcpOptions = [ordered]@{ dnsServers = @() }
                    subnets = @([ordered]@{ id = $vnetDev + '/subnets/snet-default'; name = 'snet-default'; properties = [ordered]@{ addressPrefix = '10.1.0.0/24' } }) })))
    $res.Add((New-TWRes $S2 'rg-dev' 'Microsoft.Network/networkInterfaces' 'nic-dev01' ([ordered]@{
                    ipConfigurations = @([ordered]@{ id = $nicDev + '/ipConfigurations/ipconfig1'; name = 'ipconfig1'; properties = [ordered]@{ privateIPAddress = '10.1.0.4'; primary = $true; subnet = [ordered]@{ id = $vnetDev + '/subnets/snet-default' } } })
                    virtualMachine = [ordered]@{ id = $vmDev } })))
    $res.Add((New-TWRes $S2 'rg-dev' 'Microsoft.Compute/virtualMachines' 'vm-dev01' ([ordered]@{
                    hardwareProfile = [ordered]@{ vmSize = 'Standard_B2s' }
                    storageProfile = [ordered]@{ osDisk = [ordered]@{ osType = 'Linux'; name = 'vm-dev01_OsDisk'; managedDisk = [ordered]@{ id = $diskDev }; diskSizeGB = 30 }; dataDisks = @()
                        imageReference = [ordered]@{ publisher = 'Canonical'; offer = '0001-com-ubuntu-server-jammy'; sku = '22_04-lts-gen2'; version = 'latest' } }
                    networkProfile = [ordered]@{ networkInterfaces = @([ordered]@{ id = $nicDev }) }
                    extended = [ordered]@{ instanceView = [ordered]@{ powerState = [ordered]@{ code = 'PowerState/deallocated' } } } })))
    $res.Add((New-TWRes $S2 'rg-dev' 'Microsoft.Compute/disks' 'vm-dev01_OsDisk' ([ordered]@{ diskSizeGB = 30; diskState = 'Reserved' }) -Sku ([ordered]@{ name = 'StandardSSD_LRS'; tier = 'Standard' }) -ManagedBy $vmDev))
    $res.Add((New-TWRes $S2 'rg-dev' 'Microsoft.Network/publicIPAddresses' 'pip-app01' ([ordered]@{ ipAddress = '52.1.1.99'; publicIPAllocationMethod = 'Static' }) -Sku ([ordered]@{ name = 'Standard'; tier = 'Regional' })))
    $res.Add((New-TWRes $S2 'NetworkWatcherRG' 'Microsoft.Network/networkWatchers' 'NetworkWatcher_westeurope' ([ordered]@{})))
    # Azure DevOps organizations billed to S1 (organization data: Add-TWAdoFixtures)
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.VisualStudio/account' 'contoso-ado' ([ordered]@{ AccountURL = 'https://contoso-ado.visualstudio.com/' }) -Location 'global'))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.VisualStudio/account' 'fabrikam-old' ([ordered]@{ AccountURL = 'https://fabrikam-old.visualstudio.com/' }) -Location 'global'))
    # named after the organization ID, AccountURL empty: resolved through the tenant organization list
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.VisualStudio/account' 'a0a0a0a0-0000-0000-0000-000000000009' ([ordered]@{ AccountURL = '' }) -Location 'global'))
    Add-TWCodeFixtures $w $res
    $w.Resources = $res.ToArray()
    $w.Arg['resources'] = $w.Resources

    # ---- created/changed times (ARM list per subscription) ---------------------------------------------
    $w.Times = @{}
    foreach ($r in $w.Resources) {
        $sub = $r.subscriptionId
        if (-not $w.Times.ContainsKey($sub)) { $w.Times[$sub] = [System.Collections.Generic.List[object]]::new() }
        $w.Times[$sub].Add([ordered]@{ id = $r.id; createdTime = '2023-05-01T10:00:00.1234567Z'; changedTime = '2026-09-01T12:30:00Z' })
    }
    # ---- backup, App Service config (Resource Graph) and VM sizes (ARM) ------------------------------------
    $w.Arg['backupItems'] = @(
        [ordered]@{ id = ('/subscriptions/{0}/resourceGroups/rg-data/providers/Microsoft.RecoveryServices/vaults/rsv-contoso/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;rg-app;vm-app01/protectedItems/VM;iaasvmcontainerv2;rg-app;vm-app01' -f $S1)
            name = 'VM;iaasvmcontainerv2;rg-app;vm-app01'; type = 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'; resourceGroup = 'rg-data'; subscriptionId = $S1; location = 'westeurope'
            propertiesJson = (ConvertTo-Json -Compress -InputObject ([ordered]@{ friendlyName = 'vm-app01'; backupManagementType = 'AzureIaasVM'; workloadType = 'VM'; protectionState = 'Protected'
                        protectionStatus = 'Healthy'; healthStatus = 'Passed'; lastBackupStatus = 'Completed'; lastBackupTime = '2026-09-28T22:00:00Z'; policyName = 'DefaultPolicy'; sourceResourceId = $vmApp })) }
    )
    # the other Resource Graph tables (Snapshot and the reports built on them): a private DNS record, the rule collection
    # group of a firewall policy, a backup policy, App Service configuration; tables without a fixture answer empty
    $graphRow = { param($Sub, $Rg, $Type, $Name, $Props)
        [ordered]@{ id = (& $id $Sub $Rg $Type $Name); name = $Name.Split('/')[-1]; type = ($Type.Split('/')[0] + '/' + (@($Type.Split('/') | Select-Object -Skip 1) -join '/')).ToLowerInvariant()
            location = 'westeurope'; resourceGroup = $Rg.ToLowerInvariant(); subscriptionId = $Sub; kind = $null; tags = $null; tagsJson = $null
            propertiesJson = (ConvertTo-Json -InputObject $Props -Depth 30 -Compress) } }
    $w.Arg['table_dnsresources'] = @(
        (& $graphRow $S1 'rg-network' 'Microsoft.Network/privateDnsZones/A' 'privatelink.blob.core.windows.net/stcontosodata' ([ordered]@{ fqdn = 'stcontosodata.privatelink.blob.core.windows.net.'; ttl = 10; records = @([ordered]@{ ipv4Address = '10.0.2.5' }); isAutoRegistered = $false }))
        (& $graphRow $S1 'rg-network' 'Microsoft.Network/privateDnsZones/SOA' 'privatelink.blob.core.windows.net/@' ([ordered]@{ fqdn = 'privatelink.blob.core.windows.net.'; ttl = 3600; records = @([ordered]@{ host = 'azureprivatedns.net'; email = 'azureprivatedns-host.microsoft.com' }) })))
    $w.Arg['table_networkresources'] = @(
        (& $graphRow $S1 'rg-network' 'Microsoft.Network/firewallPolicies/ruleCollectionGroups' 'fwpol-hub/DefaultNetworkRuleCollectionGroup' ([ordered]@{ priority = 200; ruleCollections = @([ordered]@{ name = 'allow-dns'; priority = 100
                            ruleCollectionType = 'FirewallPolicyFilterRuleCollection'; action = [ordered]@{ type = 'Allow' }; rules = @([ordered]@{ name = 'dns-out'; ruleType = 'NetworkRule'; ipProtocols = @('UDP', 'TCP')
                                    sourceAddresses = @('10.0.0.0/16'); destinationAddresses = @('168.63.129.16'); destinationPorts = @('53') }) }) })))
    $w.Arg['table_recoveryservicesresources'] = @(
        (& $graphRow $S1 'rg-data' 'Microsoft.RecoveryServices/vaults/backupPolicies' 'rsv-contoso/DailyPolicy' ([ordered]@{ backupManagementType = 'AzureIaasVM'; instantRpRetentionRangeInDays = 2
                    schedulePolicy = [ordered]@{ schedulePolicyType = 'SimpleSchedulePolicy'; scheduleRunFrequency = 'Daily'; scheduleRunTimes = @('2026-01-01T22:00:00Z') }
                    retentionPolicy = [ordered]@{ retentionPolicyType = 'LongTermRetentionPolicy'; dailySchedule = [ordered]@{ retentionDuration = [ordered]@{ count = 30; durationType = 'Days' } } } })))
    $w.Arg['table_appserviceresources'] = @(
        (& $graphRow $S1 'rg-app' 'Microsoft.Web/sites/config' 'app-contoso/web' ([ordered]@{ LinuxFxVersion = 'NODE|18-lts'; MinTlsVersion = '1.2'; FtpsState = 'AllAllowed'; AlwaysOn = $false; HealthCheckPath = '/health' })))
    $w.Arg['appServiceConfig'] = @(
        [ordered]@{ id = (& $id $S1 'rg-app' 'Microsoft.Web/sites' 'app-contoso') + '/config/web'; subscriptionId = $S1
            propertiesJson = (ConvertTo-Json -Compress -InputObject ([ordered]@{ LinuxFxVersion = 'NODE|18-lts'; MinTlsVersion = '1.2'; FtpsState = 'AllAllowed'; AlwaysOn = $false })) }
    )
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/[^/]+/providers/Microsoft\.Compute/skus\?'; Handler = {
            param($path, $body, $m)
            [ordered]@{ value = @(
                    [ordered]@{ resourceType = 'virtualMachines'; name = 'Standard_D4s_v5'; capabilities = @([ordered]@{ name = 'vCPUs'; value = '4' }, [ordered]@{ name = 'MemoryGB'; value = '16' }) }
                    [ordered]@{ resourceType = 'virtualMachines'; name = 'Standard_DS2_v2'; capabilities = @([ordered]@{ name = 'vCPUs'; value = '2' }, [ordered]@{ name = 'MemoryGB'; value = '7' }) }
                    [ordered]@{ resourceType = 'virtualMachines'; name = 'Standard_B2s'; capabilities = @([ordered]@{ name = 'vCPUs'; value = '2' }, [ordered]@{ name = 'MemoryGB'; value = '4' }) }
                    [ordered]@{ resourceType = 'disks'; name = 'Premium_LRS'; capabilities = @() }
                ) }
        } })
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions\?api-version='; Handler = { param($path, $body, $m) New-TWPage $global:TW.Subscriptions $path $global:TW.ArmPageSize } })
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/resources\?api-version=.*createdTime'; Handler = { param($path, $body, $m) New-TWPage $global:TW.Times[$m[1]] $path 20 } })

    # ---- diagnostic settings (ARM) -------------------------------------------------------------------------
    $law = & $id $S1 'rg-data' 'Microsoft.OperationalInsights/workspaces' 'law-contoso'
    $stLegacy = & $id $S1 'rg-legacy' 'Microsoft.Storage/storageAccounts' 'stlegacyvhds'
    $w.Diag = @{}
    $w.Diag[('/subscriptions/' + $S1).ToLowerInvariant()] = @([ordered]@{ name = 'activitylog-to-law'; properties = [ordered]@{ workspaceId = $law; logs = @([ordered]@{ category = 'Administrative'; enabled = $true }, [ordered]@{ category = 'Security'; enabled = $true }, [ordered]@{ category = 'Alert'; enabled = $false }) } })
    $w.Diag[$vmApp.ToLowerInvariant()] = @([ordered]@{ name = 'vm-diag'; properties = [ordered]@{ workspaceId = $law; metrics = @([ordered]@{ category = 'AllMetrics'; enabled = $true }) } })
    $w.Diag[($stData + '/blobServices/default').ToLowerInvariant()] = @([ordered]@{ name = 'blob-logs'; properties = [ordered]@{ storageAccountId = $stLegacy; logs = @([ordered]@{ categoryGroup = 'allLogs'; enabled = $true }) } })
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '/providers/Microsoft\.Insights/diagnosticSettings\?api-version='; Handler = {
            param($path, $body, $m)
            $rid = ($path -replace '/providers/Microsoft\.Insights/diagnosticSettings\?api-version=.*$', '').ToLowerInvariant()
            if ($global:TW.Diag.ContainsKey($rid)) { return [ordered]@{ value = @($global:TW.Diag[$rid]) } }
            if ($rid -match '/natgateways/') { return (New-TWError 400 'ResourceTypeNotSupported' "The resource type 'microsoft.network/natgateways' does not support diagnostic settings.") }
            return [ordered]@{ value = @() }
        } })

    # ---- locks (ARM) ------------------------------------------------------------------------------------------
    $kv = & $id $S1 'rg-data' 'Microsoft.KeyVault/vaults' 'kv-contoso'
    $w.Locks = @{}
    $w.Locks[$S1] = @(
        [ordered]@{ id = ('/subscriptions/{0}/resourceGroups/rg-network/providers/Microsoft.Authorization/locks/lock-network' -f $S1); name = 'lock-network'; properties = [ordered]@{ level = 'CanNotDelete'; notes = 'Hub network - do not delete' } }
        [ordered]@{ id = $kv + '/providers/Microsoft.Authorization/locks/kv-readonly'; name = 'kv-readonly'; properties = [ordered]@{ level = 'ReadOnly' } }
    )
    $w.Locks[$S2] = @()
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/locks\?'; Handler = { param($path, $body, $m) [ordered]@{ value = @($global:TW.Locks[$m[1]]) } } })

    # ---- RBAC (ARM) and directory objects (Graph) ------------------------------------------------------------
    $roleIds = @{ Owner = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; Contributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'; Reader = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'; UAA = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'; Custom = 'c0c0c0c0-1111-2222-3333-444444444444' }
    $w.RoleIds = $roleIds
    $mkRole = { param($guid, $name, $type, $actions, $scopes) [ordered]@{ id = '/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/' + $guid; name = $guid; type = 'Microsoft.Authorization/roleDefinitions'
            properties = [ordered]@{ roleName = $name; type = $type; description = $name + ' role'; assignableScopes = $scopes; permissions = @([ordered]@{ actions = $actions; notActions = @(); dataActions = @(); notDataActions = @() }) } } }
    $w.RoleDefsBuiltIn = @(
        (& $mkRole $roleIds.Owner 'Owner' 'BuiltInRole' @('*') @('/'))
        (& $mkRole $roleIds.Contributor 'Contributor' 'BuiltInRole' @('*') @('/'))
        (& $mkRole $roleIds.Reader 'Reader' 'BuiltInRole' @('*/read') @('/'))
        (& $mkRole $roleIds.UAA 'User Access Administrator' 'BuiltInRole' @('*/read', 'Microsoft.Authorization/*') @('/'))
    )
    $w.RoleDefsCustom = @{ $S1 = @((& $mkRole $roleIds.Custom 'Contoso VM Operator' 'CustomRole' @('Microsoft.Compute/virtualMachines/*', 'Microsoft.Compute/virtualMachines/start/action') @('/subscriptions/' + $S1))); $S2 = @() }
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/roleDefinitions\?'; Handler = {
            param($path, $body, $m)
            $custom = @($global:TW.RoleDefsCustom[$m[1]])
            if ($path -match 'CustomRole') { return [ordered]@{ value = $custom } }
            return [ordered]@{ value = @($global:TW.RoleDefsBuiltIn) + $custom }
        } })
    $dir = @{
        U1 = '0a000000-0000-0000-0000-0000000000a1'; U2 = '0a000000-0000-0000-0000-0000000000a2'; G1 = '0a000000-0000-0000-0000-0000000000b1'
        SP1 = '0a000000-0000-0000-0000-0000000000c1'; MI1 = 'eeeeeeee-0000-0000-0000-000000000001'; Deleted = '0a000000-0000-0000-0000-0000000000ff'
    }
    $w.DirIds = $dir
    $w.DirObjects = @{
        $dir.U1  = [ordered]@{ '@odata.type' = '#microsoft.graph.user'; id = $dir.U1; displayName = 'Alex Admin'; userPrincipalName = 'alex.admin@contoso.onmicrosoft.com' }
        $dir.U2  = [ordered]@{ '@odata.type' = '#microsoft.graph.user'; id = $dir.U2; displayName = 'Pat Partner'; userPrincipalName = 'pat_fabrikam.com#EXT#@contoso.onmicrosoft.com' }
        $dir.G1  = [ordered]@{ '@odata.type' = '#microsoft.graph.group'; id = $dir.G1; displayName = 'g-app-admins' }
        $dir.SP1 = [ordered]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = $dir.SP1; displayName = 'sp-monitoring'; appId = 'abababab-0000-0000-0000-0000000000c1'; servicePrincipalType = 'Application' }
        $dir.MI1 = [ordered]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = $dir.MI1; displayName = 'vm-app01'; appId = 'abababab-0000-0000-0000-0000000000e1'; servicePrincipalType = 'ManagedIdentity' }
    }
    $mkRa = { param($sub, $scope, $role, $principal, $ptype, $name) [ordered]@{ id = $scope + '/providers/Microsoft.Authorization/roleAssignments/' + $name; name = $name; type = 'Microsoft.Authorization/roleAssignments'
            properties = [ordered]@{ roleDefinitionId = '/subscriptions/' + $sub + '/providers/Microsoft.Authorization/roleDefinitions/' + $role; principalId = $principal; principalType = $ptype; scope = $scope; createdOn = '2024-01-15T10:00:00Z'; createdBy = $dir.U1 } } }
    $mgScope = '/providers/Microsoft.Management/managementGroups/mg-contoso'
    $w.RoleAssignments = @{
        $S1 = @(
            (& $mkRa $S1 ('/subscriptions/' + $S1) $roleIds.Owner $dir.U1 'User' 'ra-0001')
            (& $mkRa $S1 ('/subscriptions/' + $S1 + '/resourceGroups/rg-app') $roleIds.Contributor $dir.G1 'Group' 'ra-0002')
            (& $mkRa $S1 ('/subscriptions/' + $S1) $roleIds.Reader $dir.SP1 'ServicePrincipal' 'ra-0003')
            (& $mkRa $S1 ('/subscriptions/' + $S1) $roleIds.UAA $dir.Deleted 'User' 'ra-0004')
            (& $mkRa $S1 $mgScope $roleIds.Owner $dir.U2 'User' 'ra-0005')
            (& $mkRa $S1 ('/subscriptions/' + $S1 + '/resourceGroups/rg-data') $roleIds.Contributor $dir.MI1 'ServicePrincipal' 'ra-0006')
            (& $mkRa $S1 ('/subscriptions/' + $S1) $roleIds.Custom $dir.G1 'Group' 'ra-0007')
        )
        $S2 = @(
            (& $mkRa $S2 $mgScope $roleIds.Owner $dir.U2 'User' 'ra-0005')
            (& $mkRa $S2 ('/subscriptions/' + $S2) $roleIds.Contributor $dir.U1 'User' 'ra-0008')
        )
    }
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/roleAssignments\?'; Handler = { param($path, $body, $m) New-TWPage $global:TW.RoleAssignments[$m[1]] $path 4 } })
    $w.GraphRoutes.Add(@{ Method = 'POST'; Pattern = '^/v1\.0/directoryObjects/getByIds'; Handler = {
            param($path, $body, $m)
            $req = ConvertFrom-Json $body
            [ordered]@{ value = @(foreach ($x in @($req.ids)) { if ($global:TW.DirObjects.ContainsKey($x)) { $global:TW.DirObjects[$x] } }) }
        } })

    # ---- Azure Policy (ARM + Resource Graph) -----------------------------------------------------------------
    $aBase = $mgScope + '/providers/Microsoft.Authorization/policyAssignments/alz-baseline'
    $setId = $mgScope + '/providers/Microsoft.Authorization/policySetDefinitions/contoso-baseline'
    $a2 = '/subscriptions/' + $S1 + '/providers/Microsoft.Authorization/policyAssignments/allowed-vm-skus'
    $a3 = '/subscriptions/' + $S1 + '/resourceGroups/rg-app/providers/Microsoft.Authorization/policyAssignments/require-tag'
    $reqTagDef = '/subscriptions/' + $S1 + '/providers/Microsoft.Authorization/policyDefinitions/require-app-tag'
    $skuDef = '/providers/Microsoft.Authorization/policyDefinitions/cccc23c7-8427-4f53-ad12-b6a63eb452b3'
    $w.PolicyIds = @{ Baseline = $aBase; Skus = $a2; ReqTag = $a3; Set = $setId }
    $pa = @{
        Base   = [ordered]@{ id = $aBase; name = 'alz-baseline'; location = 'westeurope'; identity = [ordered]@{ type = 'SystemAssigned'; principalId = 'eeeeeeee-0000-0000-0000-0000000000aa' }
            properties = [ordered]@{ displayName = 'Contoso baseline'; scope = $mgScope; policyDefinitionId = $setId; enforcementMode = 'Default'; parameters = [ordered]@{ allowedLocations = [ordered]@{ value = @('westeurope', 'northeurope') } }
                nonComplianceMessages = @([ordered]@{ message = 'Contact the platform team' }); metadata = [ordered]@{ createdOn = '2023-01-01T00:00:00Z'; createdBy = $dir.U1 } } }
        Skus   = [ordered]@{ id = $a2; name = 'allowed-vm-skus'; properties = [ordered]@{ displayName = 'Allowed VM sizes'; scope = '/subscriptions/' + $S1; policyDefinitionId = $skuDef; enforcementMode = 'DoNotEnforce'
                parameters = [ordered]@{ listOfAllowedSKUs = [ordered]@{ value = @('Standard_D4s_v5', 'Standard_B2s') } } } }
        ReqTag = [ordered]@{ id = $a3; name = 'require-tag'; properties = [ordered]@{ displayName = 'Require app tag'; scope = '/subscriptions/' + $S1 + '/resourceGroups/rg-app'; policyDefinitionId = $reqTagDef; enforcementMode = 'Default' } }
    }
    $w.PolicyAssignments = @{ $S1 = @($pa.Base, $pa.Skus, $pa.ReqTag); $S2 = @($pa.Base) }
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/policyAssignments\?'; Handler = { param($path, $body, $m) [ordered]@{ value = @($global:TW.PolicyAssignments[$m[1]]) } } })
    $customDefs = @(
        [ordered]@{ id = $reqTagDef; name = 'require-app-tag'; type = 'Microsoft.Authorization/policyDefinitions'; properties = [ordered]@{ displayName = 'Require app tag on resources'; policyType = 'Custom'; mode = 'Indexed'
                metadata = [ordered]@{ category = 'Tags' }; parameters = [ordered]@{ effect = [ordered]@{ type = 'String'; defaultValue = 'Audit' } }; policyRule = [ordered]@{ if = [ordered]@{ field = 'tags.app'; exists = 'false' }; then = [ordered]@{ effect = "[parameters('effect')]" } } } }
        [ordered]@{ id = ('/subscriptions/' + $S1 + '/providers/Microsoft.Authorization/policyDefinitions/old-unused-policy'); name = 'old-unused-policy'; type = 'Microsoft.Authorization/policyDefinitions'
            properties = [ordered]@{ displayName = 'Old unused policy'; policyType = 'Custom'; mode = 'All'; metadata = [ordered]@{ category = 'General'; deprecated = $true }; policyRule = [ordered]@{ then = [ordered]@{ effect = 'Deny' } } } }
    )
    $customSets = @(
        [ordered]@{ id = $setId; name = 'contoso-baseline'; type = 'Microsoft.Authorization/policySetDefinitions'; properties = [ordered]@{ displayName = 'Contoso baseline initiative'; policyType = 'Custom'; metadata = [ordered]@{ category = 'General' }
                parameters = [ordered]@{ allowedLocations = [ordered]@{ type = 'Array'; defaultValue = @('westeurope') } }
                policyDefinitions = @(
                    [ordered]@{ policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c'; policyDefinitionReferenceId = 'allowed-locations'; parameters = [ordered]@{ listOfAllowedLocations = [ordered]@{ value = "[parameters('allowedLocations')]" } } }
                    [ordered]@{ policyDefinitionId = $reqTagDef; policyDefinitionReferenceId = 'require-tag' }
                ) } }
    )
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/policyDefinitions\?'; Handler = { param($path, $body, $m) if ($m[1] -eq $global:TW_S1) { [ordered]@{ value = $customDefs } } else { [ordered]@{ value = @() } } }.GetNewClosure() })
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/policySetDefinitions\?'; Handler = { param($path, $body, $m) [ordered]@{ value = $customSets } }.GetNewClosure() })
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/providers/Microsoft\.Authorization/policyDefinitions/cccc23c7-8427-4f53-ad12-b6a63eb452b3\?'; Handler = {
            param($path, $body, $m)
            [ordered]@{ id = '/providers/Microsoft.Authorization/policyDefinitions/cccc23c7-8427-4f53-ad12-b6a63eb452b3'; name = 'cccc23c7-8427-4f53-ad12-b6a63eb452b3'; type = 'Microsoft.Authorization/policyDefinitions'
                properties = [ordered]@{ displayName = 'Allowed virtual machine size SKUs'; policyType = 'BuiltIn'; mode = 'Indexed'; metadata = [ordered]@{ category = 'Compute'; version = '1.0.1' }; policyRule = [ordered]@{ then = [ordered]@{ effect = 'Deny' } } } }
        } })
    $w.Exemptions = @{
        $S1 = @(
            [ordered]@{ id = ('/subscriptions/{0}/resourceGroups/rg-legacy/providers/Microsoft.Authorization/policyExemptions/legacy-waiver' -f $S1); name = 'legacy-waiver'
                properties = [ordered]@{ displayName = 'Legacy waiver'; policyAssignmentId = $aBase; exemptionCategory = 'Waiver'; expiresOn = '2026-01-01T00:00:00Z'; policyDefinitionReferenceIds = @('allowed-locations') } }
            [ordered]@{ id = ('/subscriptions/{0}/providers/Microsoft.Authorization/policyExemptions/sku-mitigated' -f $S1); name = 'sku-mitigated'
                properties = [ordered]@{ displayName = 'SKU mitigated'; policyAssignmentId = $a2; exemptionCategory = 'Mitigated'; expiresOn = '2026-10-09T00:00:00Z' } }
        )
        $S2 = @()
    }
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/policyExemptions\?'; Handler = { param($path, $body, $m) [ordered]@{ value = @($global:TW.Exemptions[$m[1]]) } } })
    $w.Arg['policyByAssignment'] = @(
        [ordered]@{ id = $aBase.ToLowerInvariant(); NonCompliant = 3; Compliant = 20; Exempt = 1; Total = 24 }
        [ordered]@{ id = $a3.ToLowerInvariant(); NonCompliant = 1; Compliant = 5; Exempt = 0; Total = 6 }
    )
    $nc = [System.Collections.Generic.List[object]]::new()
    $n = 0
    foreach ($pair in @(@($stData, $aBase, 'e56962a6-4747-49cd-b67b-bf8b01975c4c'), @($vmLegacy, $aBase, 'e56962a6-4747-49cd-b67b-bf8b01975c4c'), @($vmLegacy, $aBase, 'require-app-tag'), @($vmApp, $a3, 'require-app-tag'))) {
        $n++
        $nc.Add([ordered]@{ id = 'ps-' + $n; subscriptionId = $S1; resourceId = $pair[0]; resourceType = (($pair[0] -split '/providers/')[1] -replace '/[^/]+$', '').ToLowerInvariant()
                assignmentId = $pair[1]; definitionId = $(if ($pair[2] -eq 'require-app-tag') { $reqTagDef } else { '/providers/Microsoft.Authorization/policyDefinitions/' + $pair[2] })
                definitionRef = ''; setDefinitionId = $(if ($pair[1] -eq $aBase) { $setId } else { '' }); action = 'audit'; timestamp = '2026-09-28T03:00:00Z' })
    }
    $w.Arg['policyNonCompliant'] = $nc.ToArray()

    # ---- Advisor (Resource Graph) ----------------------------------------------------------------------------
    $lbBasic = & $id $S1 'rg-legacy' 'Microsoft.Network/loadBalancers' 'lb-basic'
    $mkAdv = { param($n, $cat, $impact, $problem, $solution, $rid, $ext) [ordered]@{ id = ('/subscriptions/{0}/providers/Microsoft.Advisor/recommendations/{1}' -f $S1, $n); subscriptionId = $S1; resourceGroup = ''
            propertiesJson = (ConvertTo-Json -Compress -Depth 6 -InputObject ([ordered]@{ category = $cat; impact = $impact; shortDescription = [ordered]@{ problem = $problem; solution = $solution }
                        resourceMetadata = [ordered]@{ resourceId = $rid }; impactedField = 'Microsoft.Network/loadBalancers'; impactedValue = (($rid -split '/')[-1]); lastUpdated = '2026-09-27T05:00:00Z'; recommendationTypeId = 'type-' + $n; extendedProperties = $ext })) } }
    $w.Arg['advisor'] = @(
        (& $mkAdv 'rec1' 'HighAvailability' 'High' 'Upgrade Basic Load Balancer' 'Migrate to Standard Load Balancer' $lbBasic ([ordered]@{ recommendationSubCategory = 'ServiceUpgradeAndRetirement'; retirementFeatureName = 'Basic Load Balancer'; retirementDate = '2025-09-30' }))
        (& $mkAdv 'rec2' 'Cost' 'Medium' 'Right-size or shutdown underutilized virtual machines' 'Shut down or resize' $vmLegacy ([ordered]@{ savingsAmount = '50.5'; annualSavingsAmount = '606'; savingsCurrency = 'EUR' }))
        (& $mkAdv 'rec3' 'Security' 'High' 'Storage accounts should restrict network access' 'Configure network rules' $stData ([ordered]@{}))
        (& $mkAdv 'rec4' 'HighAvailability' 'Medium' 'Classic metrics for storage are retiring' 'Move to Azure Monitor metrics' $stData ([ordered]@{ recommendationSubCategory = 'ServiceUpgradeAndRetirement'; retirementFeatureName = 'Storage classic metrics'; retirementDate = '2026-12-31' }))
    )

    # ---- cost (ARM POST, 429 then two pages for S1; unsupported offer for S2) ---------------------------------
    $w.Throttle.Add(@{ Pattern = ('/subscriptions/{0}/providers/Microsoft\.CostManagement/query' -f $S1); Remaining = 1; RetryAfter = 3 })
    $w.ArmRoutes.Add(@{ Method = 'POST'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.CostManagement/query'; Handler = {
            param($path, $body, $m)
            if ($m[1] -eq $global:TW_S2) { return (New-TWError 400 'BadRequest' 'Offer MS-AZR-0063P is not supported for this query.') }
            $cols = @([ordered]@{ name = 'Cost'; type = 'Number' }, [ordered]@{ name = 'ResourceId'; type = 'String' }, [ordered]@{ name = 'Currency'; type = 'String' })
            if ($path -notmatch 'page2') {
                return [ordered]@{ properties = [ordered]@{ nextLink = 'https://management.azure.com' + $path + '&page2=1'; columns = $cols
                        rows = @(@(123.456, $global:TW.Ids.VmApp.ToLowerInvariant(), 'EUR'), @(40.0, $global:TW.Ids.StData.ToLowerInvariant(), 'EUR')) } }
            }
            return [ordered]@{ properties = [ordered]@{ nextLink = $null; columns = $cols; rows = @(@(30.25, $global:TW.Ids.VmLegacy.ToLowerInvariant(), 'EUR'), @(5.0, '', 'EUR')) } }
        } })

    # ---- ARM template export (ARM POST exportTemplate) ---------------------------------------------------------
    # rg-app: one resource type Azure could not export; rg-network: 202 Accepted, then the result from the Location;
    # rg-dev: no permission; NetworkWatcherRG: no Bicep. TemplateLimitGroups: resource groups that answer "more than
    # 200 resources" unless resource IDs are named; TemplateLimit: more IDs than this in one call are refused;
    # TemplateOldApi: a cloud with the 2021 API only; TemplateDeniedSubs: subscriptions that refuse the export;
    # TemplateNoBicep: the outputFormat is ignored.
    $w.TemplateOldApi = $false; $w.TemplateDeniedSubs = @(); $w.TemplateNoBicep = $false; $w.TemplateLimit = 0; $w.TemplatePolls = @{}; $w.TemplateLimitGroups = @()
    $w.ArmRoutes.Add(@{ Method = 'POST'; Pattern = '^/subscriptions/([^/]+)/resourcegroups/([^/]+)/exportTemplate\?api-version=([^&]+)'; Handler = {
            param($path, $body, $m)
            $sub = $m[1]; $rg = [uri]::UnescapeDataString($m[2]); $api = $m[3]
            if ($global:TW.TemplateOldApi -and $api -ne '2021-04-01') {
                return (New-TWError 400 'InvalidApiVersionParameter' ("The api-version '" + $api + "' is invalid. The supported versions are '2021-04-01,2020-10-01'."))
            }
            if (@($global:TW.TemplateDeniedSubs) -contains $sub -or $rg -eq 'rg-dev') {
                return (New-TWError 403 'AuthorizationFailed' ("The client does not have authorization to perform action 'Microsoft.Resources/subscriptions/resourcegroups/exportTemplate/action' over scope '/subscriptions/" + $sub + '/resourcegroups/' + $rg + "'."))
            }
            $b = ConvertFrom-Json $body
            $ids = @($b.resources)
            $star = ($ids.Count -eq 1 -and $ids[0] -eq '*')
            if ((@($global:TW.TemplateLimitGroups) -contains $rg -and $star) -or ($global:TW.TemplateLimit -gt 0 -and -not $star -and $ids.Count -gt $global:TW.TemplateLimit)) {
                return (New-TWError 400 'ExportTemplateResourcesLimitExceeded' 'Export template is not supported for resource groups with more than 200 resources.')
            }
            $fmt = 'Json'
            if ([string]$b.outputFormat -eq 'Bicep' -and $api -ne '2021-04-01' -and -not $global:TW.TemplateNoBicep) { $fmt = 'Bicep' }
            if ($fmt -eq 'Bicep' -and $rg -eq 'NetworkWatcherRG') { return (New-TWError 400 'InvalidTemplate' 'The template could not be converted to Bicep.') }
            if ($rg -eq 'rg-network') {
                return @{ StatusCode = 202; Content = ''; Headers = @{ Location = ('https://management.azure.com/subscriptions/{0}/operationresults/twexport-{1}-{2}?api-version={3}' -f $sub, $rg, $fmt, $api); 'Retry-After' = '7' } }
            }
            return (New-TWResponse -Obj (New-TWTemplateResult $sub $rg $ids $fmt))
        } })
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/operationresults/twexport-(.+)-(Json|Bicep)\?'; Handler = {
            param($path, $body, $m)
            # the first poll is still 202 (and names no new Location), the second holds the result
            $n = [int]$global:TW.TemplatePolls[$path] + 1
            $global:TW.TemplatePolls[$path] = $n
            if ($n -lt 2) { return @{ StatusCode = 202; Content = ''; Headers = @{ 'Retry-After' = '3' } } }
            return (New-TWResponse -Obj (New-TWTemplateResult $m[1] $m[2] @('*') $m[3]))
        } })

    # ---- runbook content (ARM) --------------------------------------------------------------------------------
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '/runbooks/([^/]+)/content\?'; Handler = {
            param($path, $body, $m)
            if ($m[1] -eq 'Cleanup') { return (New-TWResponse -Obj ("import azure`n# connection = get_automation_connection('AzureRunAsConnection')`nprint('cleanup')")) }
            return (New-TWResponse -Obj ("Connect-AzAccount -Identity`nGet-AzVM | Start-AzVM"))
        } })

    # ---- Entra ID (Graph) -------------------------------------------------------------------------------------
    $graphApp = '00000003-0000-0000-c000-000000000000'
    $graphSp = '0a000000-0000-0000-0000-00000000f001'
    $webSp = '0a000000-0000-0000-0000-00000000d001'
    $roleDirRw = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'
    $w.SignInAllowed = $false
    $w.Users = @(
        [ordered]@{ id = $dir.U1; displayName = 'Alex Admin'; userPrincipalName = 'alex.admin@contoso.onmicrosoft.com'; mail = 'alex@contoso.com'; userType = 'Member'; accountEnabled = $true
            createdDateTime = '2020-01-01T00:00:00Z'; onPremisesSyncEnabled = $null; usageLocation = 'LT'; assignedLicenses = @([ordered]@{ skuId = 's1' }, [ordered]@{ skuId = 's2' })
            signInActivity = [ordered]@{ lastSignInDateTime = '2026-09-28T08:00:00Z'; lastNonInteractiveSignInDateTime = '2026-09-28T09:00:00Z' } }
        [ordered]@{ id = $dir.U2; displayName = 'Pat Partner'; userPrincipalName = 'pat_fabrikam.com#EXT#@contoso.onmicrosoft.com'; mail = 'pat@fabrikam.com'; userType = 'Guest'; accountEnabled = $true
            createdDateTime = '2025-01-01T00:00:00Z'; externalUserState = 'PendingAcceptance'; creationType = 'Invitation'; assignedLicenses = @(); signInActivity = $null }
        [ordered]@{ id = '0a000000-0000-0000-0000-0000000000a3'; displayName = $global:TW_Lt; userPrincipalName = 'jonas@contoso.com'; userType = 'Member'; accountEnabled = $true
            createdDateTime = '2021-03-01T00:00:00Z'; onPremisesSyncEnabled = $true; department = 'Finance'; assignedLicenses = @([ordered]@{ skuId = 's1' })
            signInActivity = [ordered]@{ lastSignInDateTime = '2026-06-01T08:00:00Z' } }
        [ordered]@{ id = '0a000000-0000-0000-0000-0000000000a4'; displayName = 'Former Employee'; userPrincipalName = 'former@contoso.com'; userType = 'Member'; accountEnabled = $false
            createdDateTime = '2019-01-01T00:00:00Z'; assignedLicenses = @([ordered]@{ skuId = 's1' }); signInActivity = [ordered]@{ lastSignInDateTime = '2025-01-01T08:00:00Z' } }
        [ordered]@{ id = '0a000000-0000-0000-0000-0000000000a5'; displayName = 'svc-backup'; userPrincipalName = 'svc-backup@contoso.com'; userType = 'Member'; accountEnabled = $true
            createdDateTime = '2022-01-01T00:00:00Z'; assignedLicenses = @(); signInActivity = [ordered]@{ lastSignInDateTime = '2025-06-01T08:00:00Z' } }
    )
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/organization'; Handler = { param($path, $body, $m) [ordered]@{ value = @([ordered]@{ id = $global:TW_Tenant; displayName = 'Contoso'; countryLetterCode = 'LT'; tenantType = 'AAD'
                            createdDateTime = '2015-05-05T00:00:00Z'; onPremisesSyncEnabled = $true; onPremisesLastSyncDateTime = '2026-09-28T23:30:00Z'; technicalNotificationMails = @('it@contoso.com')
                            verifiedDomains = @([ordered]@{ name = 'contoso.com'; isDefault = $true; isInitial = $false }, [ordered]@{ name = 'contoso.onmicrosoft.com'; isDefault = $false; isInitial = $true }) }) } } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/domains'; Handler = { param($path, $body, $m) [ordered]@{ value = @(
                    [ordered]@{ id = 'contoso.com'; authenticationType = 'Federated'; isDefault = $true; isInitial = $false; isVerified = $true; isRoot = $true; supportedServices = @('Email', 'OfficeCommunicationsOnline') }
                    [ordered]@{ id = 'contoso.onmicrosoft.com'; authenticationType = 'Managed'; isDefault = $false; isInitial = $true; isVerified = $true; isRoot = $true; supportedServices = @('Email') }) } } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/subscribedSkus'; Handler = { param($path, $body, $m) [ordered]@{ value = @(
                    [ordered]@{ skuPartNumber = 'ENTERPRISEPACK'; skuId = '6fd2c87f-b296-42f0-b197-1e91e994b900'; appliesTo = 'User'; capabilityStatus = 'Enabled'; consumedUnits = 87; prepaidUnits = [ordered]@{ enabled = 100; suspended = 0; warning = 0 } }
                    [ordered]@{ skuPartNumber = 'AAD_PREMIUM_P2'; skuId = 'eec0eb4f-6444-4f95-aba0-50c24d67f998'; appliesTo = 'User'; capabilityStatus = 'Enabled'; consumedUnits = 20; prepaidUnits = [ordered]@{ enabled = 25; suspended = 0; warning = 0 } }) } } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/users\?'; Handler = {
            param($path, $body, $m)
            if ($path -match 'signInActivity' -and -not $global:TW.SignInAllowed) { return (New-TWError 403 'Authorization_RequestDenied' 'Insufficient privileges to complete the operation.') }
            $items = $global:TW.Users
            if ($path -notmatch 'signInActivity') { $items = @($global:TW.Users | ForEach-Object { $c = [ordered]@{}; foreach ($k in $_.Keys) { if ($k -ne 'signInActivity') { $c[$k] = $_[$k] } }; $c }) }
            New-TWGraphPage $items $path 3
        } })
    $w.Groups = @(
        [ordered]@{ id = $dir.G1; displayName = 'g-app-admins'; securityEnabled = $true; mailEnabled = $false; groupTypes = @(); isAssignableToRole = $false; createdDateTime = '2021-01-01T00:00:00Z'
            owners = @([ordered]@{ '@odata.type' = '#microsoft.graph.user'; id = $dir.U1; displayName = 'Alex Admin'; userPrincipalName = 'alex.admin@contoso.onmicrosoft.com' }) }
        [ordered]@{ id = '0a000000-0000-0000-0000-0000000000b2'; displayName = 'All Staff'; mail = 'allstaff@contoso.com'; securityEnabled = $false; mailEnabled = $true; groupTypes = @('Unified'); visibility = 'Private' }
        [ordered]@{ id = '0a000000-0000-0000-0000-0000000000b3'; displayName = 'Dynamic Devs'; securityEnabled = $true; mailEnabled = $false; groupTypes = @('DynamicMembership'); membershipRule = '(user.department -eq "Dev")' }
        [ordered]@{ id = '0a000000-0000-0000-0000-0000000000b4'; displayName = 'Tier0 Admins'; securityEnabled = $true; mailEnabled = $false; groupTypes = @(); isAssignableToRole = $true; onPremisesSyncEnabled = $true }
    )
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/groups\?'; Handler = { param($path, $body, $m) New-TWGraphPage $global:TW.Groups $path 3 } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/beta/groups/([^/]+)/members'; Handler = {
            param($path, $body, $m)
            if ($m[1] -eq $global:TW.DirIds.G1) { return [ordered]@{ value = @($global:TW.DirObjects[$global:TW.DirIds.U1], $global:TW.DirObjects[$global:TW.DirIds.SP1]) } }
            return [ordered]@{ value = @() }
        } })
    $w.Apps = @(
        [ordered]@{ id = '0a000000-0000-0000-0000-00000000e001'; appId = 'aa000000-0000-0000-0000-000000000001'; displayName = 'Contoso Web App'; signInAudience = 'AzureADMyOrg'; createdDateTime = '2023-02-01T00:00:00Z'
            passwordCredentials = @([ordered]@{ displayName = 'prod-secret'; keyId = '11110000-0000-0000-0000-000000000001'; startDateTime = '2025-10-09T00:00:00Z'; endDateTime = '2026-10-09T00:00:00Z' })
            keyCredentials = @([ordered]@{ displayName = 'CN=old-cert'; keyId = '11110000-0000-0000-0000-000000000002'; startDateTime = '2024-01-01T00:00:00Z'; endDateTime = '2026-01-01T00:00:00Z' })
            requiredResourceAccess = @([ordered]@{ resourceAppId = $graphApp; resourceAccess = @([ordered]@{ id = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d'; type = 'Scope' }, [ordered]@{ id = $roleDirRw; type = 'Role' }) })
            web = [ordered]@{ redirectUris = @('https://app.contoso.com/signin-oidc') }; owners = @([ordered]@{ '@odata.type' = '#microsoft.graph.user'; id = $dir.U1; displayName = 'Alex Admin'; userPrincipalName = 'alex.admin@contoso.onmicrosoft.com' }) }
        [ordered]@{ id = '0a000000-0000-0000-0000-00000000e002'; appId = 'aa000000-0000-0000-0000-000000000002'; displayName = 'Legacy Integration'; signInAudience = 'AzureADMultipleOrgs'; createdDateTime = '2018-02-01T00:00:00Z'
            passwordCredentials = @([ordered]@{ displayName = 'forever'; keyId = '11110000-0000-0000-0000-000000000003'; startDateTime = '2024-01-01T00:00:00Z'; endDateTime = '2027-01-01T00:00:00Z' })
            keyCredentials = @(); requiredResourceAccess = @(); owners = @(); notes = 'Owned by the former integration team' }
    )
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/applications\?'; Handler = { param($path, $body, $m) New-TWGraphPage $global:TW.Apps $path 3 } })
    $w.SPs = @(
        [ordered]@{ id = $webSp; appId = 'aa000000-0000-0000-0000-000000000001'; displayName = 'Contoso Web App'; servicePrincipalType = 'Application'; accountEnabled = $true; appOwnerOrganizationId = $T; tags = @('WindowsAzureActiveDirectoryIntegratedApp')
            appRoles = @([ordered]@{ id = 'ad000000-0000-0000-0000-000000000001'; value = 'Orders.Admin'; displayName = 'Orders administrator' }) }
        [ordered]@{ id = $dir.SP1; appId = 'abababab-0000-0000-0000-0000000000c1'; displayName = 'sp-monitoring'; servicePrincipalType = 'Application'; accountEnabled = $true; appOwnerOrganizationId = 'cccccccc-0000-0000-0000-000000000000'; publisherName = 'Monitoring Vendor' }
        [ordered]@{ id = $graphSp; appId = $graphApp; displayName = 'Microsoft Graph'; servicePrincipalType = 'Application'; accountEnabled = $true; appOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; publisherName = 'Microsoft Services' }
        [ordered]@{ id = $dir.MI1; appId = 'abababab-0000-0000-0000-0000000000e1'; displayName = 'vm-app01'; servicePrincipalType = 'ManagedIdentity'; alternativeNames = @('isExplicit=False', $vmApp) }
        [ordered]@{ id = 'eeeeeeee-0000-0000-0000-000000000009'; appId = 'ffffffff-0000-0000-0000-000000000009'; displayName = 'uai-app'; servicePrincipalType = 'ManagedIdentity'; alternativeNames = @('isExplicit=True', $uai) }
        [ordered]@{ id = 'eeeeeeee-0000-0000-0000-0000000000dd'; appId = 'ffffffff-0000-0000-0000-0000000000dd'; displayName = 'vm-deleted'; servicePrincipalType = 'ManagedIdentity'
            alternativeNames = @('isExplicit=False', ('/subscriptions/{0}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-deleted' -f $S1)) }
    )
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = "^/v1\.0/servicePrincipals\(appId='([^']+)'\)"; Handler = {
            param($path, $body, $m)
            if ($m[1] -ne '00000003-0000-0000-c000-000000000000') {
                # another API of the tenant (an app registration can ask for its app roles)
                $own = @($global:TW.SPs | Where-Object { $_['appId'] -eq $m[1] -and $_.Contains('appRoles') })
                if ($own.Count -eq 0) { return (New-TWError 404 'Request_ResourceNotFound' 'not found') }
                return [ordered]@{ id = $own[0]['id']; appId = $m[1]; displayName = $own[0]['displayName']; appRoles = $own[0]['appRoles'] }
            }
            [ordered]@{ id = '0a000000-0000-0000-0000-00000000f001'; appId = $m[1]; displayName = 'Microsoft Graph'
                appRoles = @([ordered]@{ id = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'; value = 'Directory.ReadWrite.All' }, [ordered]@{ id = 'df021288-bdef-4463-88db-98f22de89214'; value = 'User.Read.All' }) }
        } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/servicePrincipals/([^/]+)/appRoleAssignedTo'; Handler = { param($path, $body, $m)
            # who is assigned to an enterprise application (EntraAppAssignments); below: the applications granted Graph permissions
            if ($m[1] -eq '0a000000-0000-0000-0000-00000000d001') {
                return [ordered]@{ value = @(
                        [ordered]@{ id = 'ara-0001'; principalId = $global:TW.DirIds.U1; principalDisplayName = 'Alex Admin'; principalType = 'User'; appRoleId = '00000000-0000-0000-0000-000000000000'; createdDateTime = '2024-03-01T00:00:00Z' }
                        [ordered]@{ id = 'ara-0002'; principalId = $global:TW.DirIds.G1; principalDisplayName = 'g-app-admins'; principalType = 'Group'; appRoleId = 'ad000000-0000-0000-0000-000000000001'; createdDateTime = '2024-03-02T00:00:00Z' }
                        [ordered]@{ id = 'ara-0003'; principalId = $global:TW.DirIds.SP1; principalDisplayName = 'sp-monitoring'; principalType = 'ServicePrincipal'; appRoleId = 'ad000000-0000-0000-0000-000000000001'; createdDateTime = '2024-03-03T00:00:00Z' }) }
            }
            if ($m[1] -ne '0a000000-0000-0000-0000-00000000f001') { return [ordered]@{ value = @() } }
            [ordered]@{ value = @(
                    [ordered]@{ principalId = '0a000000-0000-0000-0000-00000000d001'; principalDisplayName = 'Contoso Web App'; principalType = 'ServicePrincipal'; appRoleId = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'; createdDateTime = '2023-02-02T00:00:00Z' }
                    [ordered]@{ principalId = $global:TW.DirIds.SP1; principalDisplayName = 'sp-monitoring'; principalType = 'ServicePrincipal'; appRoleId = 'df021288-bdef-4463-88db-98f22de89214'; createdDateTime = '2024-02-02T00:00:00Z' }) } } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/servicePrincipals\?'; Handler = { param($path, $body, $m) New-TWGraphPage $global:TW.SPs $path 3 } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/oauth2PermissionGrants'; Handler = { param($path, $body, $m) [ordered]@{ value = @(
                    [ordered]@{ clientId = '0a000000-0000-0000-0000-00000000d001'; consentType = 'AllPrincipals'; principalId = $null; resourceId = '0a000000-0000-0000-0000-00000000f001'; scope = 'User.Read Mail.ReadWrite offline_access' }
                    [ordered]@{ clientId = $global:TW.DirIds.SP1; consentType = 'Principal'; principalId = '0a000000-0000-0000-0000-0000000000a4'; resourceId = '0a000000-0000-0000-0000-00000000f001'; scope = 'Files.Read.All' }) } } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/roleManagement/directory/roleDefinitions'; Handler = { param($path, $body, $m) [ordered]@{ value = @(
                    [ordered]@{ id = '62e90394-69f5-4237-9190-012177145e10'; displayName = 'Global Administrator'; isBuiltIn = $true; templateId = '62e90394-69f5-4237-9190-012177145e10' }
                    [ordered]@{ id = '5d6b6bb7-de71-4623-b4af-96380a352509'; displayName = 'Security Reader'; isBuiltIn = $true; templateId = '5d6b6bb7-de71-4623-b4af-96380a352509' }
                    [ordered]@{ id = 'c7000000-0000-0000-0000-000000000001'; displayName = 'Helpdesk Lite'; description = 'Reset passwords only'; isBuiltIn = $false; isEnabled = $true; templateId = 'c7000000-0000-0000-0000-000000000001'
                        resourceScopes = @('/'); rolePermissions = @([ordered]@{ allowedResourceActions = @('microsoft.directory/users/password/update', 'microsoft.directory/users/basic/update') }) }) } } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/roleManagement/directory/roleAssignments'; Handler = { param($path, $body, $m) [ordered]@{ value = @(
                    [ordered]@{ principalId = $global:TW.DirIds.U1; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; directoryScopeId = '/'; principal = $global:TW.DirObjects[$global:TW.DirIds.U1] }
                    [ordered]@{ principalId = $global:TW.DirIds.U2; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; directoryScopeId = '/'; principal = $global:TW.DirObjects[$global:TW.DirIds.U2] }
                    [ordered]@{ principalId = $global:TW.DirIds.SP1; roleDefinitionId = '5d6b6bb7-de71-4623-b4af-96380a352509'; directoryScopeId = '/'; principal = $global:TW.DirObjects[$global:TW.DirIds.SP1] }) } } })

    # ---- synthetic move-support markdown (format of Microsoft Learn, content invented) -------------------
    $w.Web['move'] = @'
---
title: synthetic test file
---
# Test move support

## Microsoft.Compute

> [!div class="mx-tableFixed"]
> | Resource type | Resource group | Subscription | Region move |
> | ------------- | ----------- | ---------- | ----------- |
> | availabilitysets | **Yes** | **Yes** |  **Yes** <br/><br/> Use [Azure Resource Mover](../x.md) to move availability sets. |
> | disks | **Yes** | **Yes** | **Yes** |
> | snapshots | **Yes** - Full <br> No - Incremental | **Yes** - Full <br> No - Incremental | No - Full <br> No - Incremental |
> | virtualmachines | **Yes** | **Yes** | **Yes** <br/><br/> Use [Azure Resource Mover](../y.md) to move Azure Virtual Machines. |
> | virtualmachines / extensions | **Yes** | **Yes** | No |

## microsoft.network

> [!div class="mx-tableFixed"]
> | Resource type | Resource group | Subscription | Region move |
> | ------------- | ----------- | ---------- | ----------- |
> | loadbalancers | **Yes** - Basic SKU<br> **Yes** - Standard SKU | **Yes** - Basic SKU<br>No - Standard SKU | **Yes** <br/><br/> Use Azure Resource Mover to move internal and external load balancers. |
> | natgateways | No | No | No |
> | networkinterfaces | **Yes** | **Yes** | **Yes** |
> | networksecuritygroups | **Yes** | **Yes** | **Yes** |
> | privatednszones | **Yes** | **Yes** | No |
> | publicipaddresses | **Yes** | **Yes** - see [Public IP address limitations](../z.md) | **Yes** |
> | virtualnetworks | **Yes** | **Yes** | No |

## Microsoft.ContainerService

> [!div class="mx-tableFixed"]
> | Resource type | Resource group | Subscription | Region move |
> | ------------- | ----------- | ---------- | ----------- |
> | managedclusters | No | No | No |

## Microsoft.Web

> [!div class="mx-tableFixed"]
> | Resource type | Resource group | Subscription | Region move |
> | ------------- | ----------- | ---------- | ----------- |
> | serverfarms | **Yes** | **Yes** | pending |
> | sites | **Yes** | **Yes** | Manual steps support this. See the relocation guide. |

## Microsoft.Cache

> [!div class="mx-tableFixed"]
> | Resource type | Resource group | Subscription | Region move |
> | ------------- | ----------- | ---------- | ----------- |
> | redisenterprise (Azure Managed Redis) | No | No | No |

## Third-party services

> | Resource type | Resource group | Subscription | Region move |
> | ------------- | ----------- | ---------- | ----------- |
> | somethingelse | No | No | No |
'@
    Add-TWGovernanceFixtures $w
    Add-TWChildFixtures $w
    Add-TWAdoFixtures $w
    return $w
}

function Add-TWGovernanceFixtures {
    # Deny assignments, PIM for Azure resources, objects at management groups (MgObjects), Defender plans, Lighthouse,
    # and the Entra lists added with them: administrative units, directory settings, policies (PolicyReadAllowed).
    param($w)
    $S1 = $global:TW_S1; $S2 = $global:TW_S2
    $dir = $w.DirIds
    $w.DenyAssignments = @{
        $S1 = @([ordered]@{ id = ('/subscriptions/{0}/resourceGroups/rg-app/providers/Microsoft.Authorization/denyAssignments/da-0001' -f $S1); name = 'da-0001'; type = 'Microsoft.Authorization/denyAssignments'
                properties = [ordered]@{ denyAssignmentName = 'Deny delete by managed application'; description = 'Created by Azure for a managed application'; scope = ('/subscriptions/{0}/resourceGroups/rg-app' -f $S1)
                    permissions = @([ordered]@{ actions = @('*/delete'); notActions = @('Microsoft.Storage/*/delete'); dataActions = @(); notDataActions = @() })
                    principals = @([ordered]@{ id = '00000000-0000-0000-0000-000000000000'; type = 'SystemDefined' }); excludePrincipals = @([ordered]@{ id = $dir.SP1; type = 'ServicePrincipal' })
                    doNotApplyToChildScopes = $false; isSystemProtected = $true; createdOn = '2024-02-01T00:00:00Z' } })
        $S2 = @()
    }
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/denyAssignments\?'; Handler = { param($path, $body, $m) [ordered]@{ value = @($global:TW.DenyAssignments[$m[1]]) } } })
    # PIM: Pat Partner is eligible for Owner; the Reader assignment of sp-monitoring was activated and ends
    $ownerDef = '/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f $S1, $w.RoleIds.Owner
    $w.PimEnabled = $true
    $w.PimEligible = @{
        $S1 = @([ordered]@{ id = ('/subscriptions/{0}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/pe-0001' -f $S1); name = 'pe-0001'
                properties = [ordered]@{ scope = '/subscriptions/' + $S1; roleDefinitionId = $ownerDef; principalId = $dir.U2; principalType = 'User'; status = 'Provisioned'
                    startDateTime = '2026-01-01T00:00:00Z'; endDateTime = '2026-12-31T00:00:00Z'; memberType = 'Direct'; createdOn = '2026-01-01T00:00:00Z'
                    expandedProperties = [ordered]@{ principal = [ordered]@{ id = $dir.U2; displayName = 'Pat Partner'; email = 'pat@fabrikam.com'; type = 'User' }
                        roleDefinition = [ordered]@{ id = $ownerDef; displayName = 'Owner'; type = 'BuiltInRole' }; scope = [ordered]@{ id = '/subscriptions/' + $S1; displayName = 'Contoso Production'; type = 'subscription' } } } })
        $S2 = @()
    }
    $ra = '/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignments/' -f $S1
    $w.PimActive = @{
        $S1 = @(
            [ordered]@{ id = ('/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances/pa-0001' -f $S1); name = 'pa-0001'
                properties = [ordered]@{ scope = '/subscriptions/' + $S1; originRoleAssignmentId = $ra + 'ra-0001'; assignmentType = 'Assigned'; memberType = 'Direct'; endDateTime = $null } }
            [ordered]@{ id = ('/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances/pa-0003' -f $S1); name = 'pa-0003'
                properties = [ordered]@{ scope = '/subscriptions/' + $S1; originRoleAssignmentId = $ra + 'ra-0003'; assignmentType = 'Activated'; memberType = 'Direct'; endDateTime = '2026-09-29T08:00:00Z' } })
        $S2 = @()
    }
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers/Microsoft\.Authorization/(roleEligibilityScheduleInstances|roleAssignmentScheduleInstances)\?'; Handler = {
            param($path, $body, $m)
            if (-not $global:TW.PimEnabled) { return (New-TWError 400 'InsufficientPermissions' 'The tenant has not onboarded to PIM for Azure resources.') }
            if ($m[2] -eq 'roleEligibilityScheduleInstances') { return [ordered]@{ value = @($global:TW.PimEligible[$m[1]]) } }
            return [ordered]@{ value = @($global:TW.PimActive[$m[1]]) }
        } })
    # objects at a management group: MgObjects = @{ <management group> = @{ roleAssignments = @(...); policyAssignments = @(...) } }
    $w.MgObjects = @{}; $w.MgDenied = @()
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/providers/Microsoft\.Management/managementGroups/([^/]+)/providers/Microsoft\.Authorization/(roleAssignments|roleDefinitions|policyAssignments|policyDefinitions|policySetDefinitions|policyExemptions)\?'; Handler = {
            param($path, $body, $m)
            if (@($global:TW.MgDenied) -contains $m[1]) { return (New-TWError 403 'AuthorizationFailed' 'The client does not have authorization to read at this management group.') }
            $o = $global:TW.MgObjects[$m[1]]
            if ($null -ne $o -and $o.ContainsKey($m[2])) { return [ordered]@{ value = @($o[$m[2]]) } }
            return [ordered]@{ value = @() }
        } })
    # Defender for Cloud plans and Lighthouse (Resource Graph)
    $plan = { param($Sub, $Name, $Tier, $SubPlan, $Ext) [ordered]@{ id = ('/subscriptions/{0}/providers/Microsoft.Security/pricings/{1}' -f $Sub, $Name); name = $Name; type = 'microsoft.security/pricings'; subscriptionId = $Sub
            propertiesJson = (ConvertTo-Json -Compress -Depth 6 -InputObject ([ordered]@{ pricingTier = $Tier; subPlan = $SubPlan; enablementTime = '2024-03-01T00:00:00Z'; extensions = @($Ext) })) } }
    $w.Arg['defenderPlans'] = @(
        (& $plan $S1 'VirtualMachines' 'Standard' 'P2' @([ordered]@{ name = 'AgentlessVmScanning'; isEnabled = 'True' }, [ordered]@{ name = 'MdeDesignatedSubscription'; isEnabled = 'False' }))
        (& $plan $S1 'StorageAccounts' 'Standard' 'DefenderForStorageV2' @([ordered]@{ name = 'OnUploadMalwareScanning'; isEnabled = 'True' }, [ordered]@{ name = 'SensitiveDataDiscovery'; isEnabled = 'True' }))
        (& $plan $S1 'KeyVaults' 'Free' $null @())
        (& $plan $S2 'VirtualMachines' 'Free' $null @()))
    $lhDef = '/subscriptions/{0}/providers/Microsoft.ManagedServices/registrationDefinitions/1d000000-0000-0000-0000-000000000001' -f $S2
    $w.Arg['lighthouse'] = @(
        [ordered]@{ id = $lhDef; name = '1d000000-0000-0000-0000-000000000001'; type = 'microsoft.managedservices/registrationdefinitions'; subscriptionId = $S2
            propertiesJson = (ConvertTo-Json -Compress -Depth 6 -InputObject ([ordered]@{ registrationDefinitionName = 'Fabrikam Managed Services'; description = 'Operations 24x7'; managedByTenantId = $global:TW_OtherTenant
                        managedByTenantName = 'Fabrikam'; authorizations = @([ordered]@{ principalId = '0b000000-0000-0000-0000-0000000000a1'; principalIdDisplayName = 'Fabrikam Operators'; roleDefinitionId = $w.RoleIds.Contributor }); eligibleAuthorizations = @() })) }
        [ordered]@{ id = ('/subscriptions/{0}/resourceGroups/rg-dev/providers/Microsoft.ManagedServices/registrationAssignments/1a000000-0000-0000-0000-000000000001' -f $S2); name = '1a000000-0000-0000-0000-000000000001'
            type = 'microsoft.managedservices/registrationassignments'; subscriptionId = $S2; propertiesJson = (ConvertTo-Json -Compress -InputObject ([ordered]@{ registrationDefinitionId = $lhDef; provisioningState = 'Succeeded' })) })
    # Entra: administrative units and directory settings are readable; the policies need Policy.Read.All (PolicyReadAllowed)
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/directory/administrativeUnits'; Handler = { param($path, $body, $m) [ordered]@{ value = @(
                    [ordered]@{ id = '0a000000-0000-0000-0000-0000000000d1'; displayName = 'AU Vilnius'; description = 'Vilnius office'; visibility = $null; membershipType = 'Dynamic'; membershipRule = '(user.country -eq "LT")' }) } } })
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/groupSettings'; Handler = { param($path, $body, $m) [ordered]@{ value = @(
                    [ordered]@{ id = '0a000000-0000-0000-0000-0000000000d2'; displayName = 'Group.Unified'; templateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'
                        values = @([ordered]@{ name = 'EnableGroupCreation'; value = 'false' }, [ordered]@{ name = 'PrefixSuffixNamingRequirement'; value = 'GRP-[GroupName]' }) }) } } })
    $w.PolicyReadAllowed = $false
    $w.GraphRoutes.Add(@{ Method = 'GET'; Pattern = '^/v1\.0/(identity/conditionalAccess/policies|identity/conditionalAccess/namedLocations|policies/[A-Za-z/]+)'; Handler = {
            param($path, $body, $m)
            if (-not $global:TW.PolicyReadAllowed) { return (New-TWError 403 'Authorization_RequestDenied' 'Insufficient privileges to complete the operation.') }
            $d = $global:TW.DirIds
            switch ($m[1]) {
                'identity/conditionalAccess/policies' {
                    return [ordered]@{ value = @([ordered]@{ id = 'ca000000-0000-0000-0000-000000000001'; displayName = 'Require MFA for admins'; state = 'enabled'; createdDateTime = '2024-05-01T00:00:00Z'; modifiedDateTime = '2025-01-01T00:00:00Z'
                                conditions = [ordered]@{ users = [ordered]@{ includeUsers = @(); includeGroups = @($d.G1); includeRoles = @('62e90394-69f5-4237-9190-012177145e10', '194ae4cb-b126-40b2-bd5b-6091b380977d'); excludeUsers = @($d.U1); excludeGroups = @(); excludeRoles = @() }
                                    applications = [ordered]@{ includeApplications = @('All'); excludeApplications = @('Office365') }; clientAppTypes = @('all'); platforms = $null
                                    locations = [ordered]@{ includeLocations = @('All'); excludeLocations = @('AllTrusted') }; userRiskLevels = @(); signInRiskLevels = @('high', 'medium') }
                                grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa', 'compliantDevice'); termsOfUse = @(); customAuthenticationFactors = @() }
                                sessionControls = [ordered]@{ signInFrequency = [ordered]@{ value = 4; type = 'hours'; isEnabled = $true }; persistentBrowser = $null } }) }
                }
                'identity/conditionalAccess/namedLocations' {
                    return [ordered]@{ value = @(
                            [ordered]@{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; id = 'ca000000-0000-0000-0000-0000000000b1'; displayName = 'Vilnius office'; isTrusted = $true; ipRanges = @([ordered]@{ '@odata.type' = '#microsoft.graph.iPv4CidrRange'; cidrAddress = '203.0.113.0/24' }); createdDateTime = '2024-01-01T00:00:00Z' }
                            [ordered]@{ '@odata.type' = '#microsoft.graph.countryNamedLocation'; id = 'ca000000-0000-0000-0000-0000000000b2'; displayName = 'Baltics'; countriesAndRegions = @('LT', 'LV', 'EE'); includeUnknownCountriesAndRegions = $false }) }
                }
                'policies/authorizationPolicy' {
                    return [ordered]@{ id = 'authorizationPolicy'; displayName = 'Authorization Policy'; allowInvitesFrom = 'adminsAndGuestInviters'; guestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
                        defaultUserRolePermissions = [ordered]@{ allowedToCreateApps = $false; allowedToCreateSecurityGroups = $true; permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low') } }
                }
                'policies/identitySecurityDefaultsEnforcementPolicy' { return [ordered]@{ id = '00000000-0000-0000-0000-000000000005'; displayName = 'Security Defaults'; isEnabled = $false } }
                'policies/authenticationStrengthPolicies' {
                    return [ordered]@{ value = @([ordered]@{ id = '00000000-0000-0000-0000-000000000002'; displayName = 'Multifactor authentication'; policyType = 'builtIn'; allowedCombinations = @('password,sms') }
                            [ordered]@{ id = 'ca000000-0000-0000-0000-0000000000c1'; displayName = 'Admins: phishing resistant'; policyType = 'custom'; allowedCombinations = @('fido2', 'windowsHelloForBusiness') }) }
                }
                'policies/authenticationMethodsPolicy' { return (New-TWError 403 'Authorization_RequestDenied' 'Insufficient privileges to complete the operation.') }
                'policies/crossTenantAccessPolicy/partners' { return [ordered]@{ value = @() } }
                default { return [ordered]@{ isEnabled = $true } }
            }
        } })
}

function Add-TWChildFixtures {
    # Resource providers (ARM, one list per subscription) and child resources (ARM lists below a resource). The last
    # route answers every other list below a resource with an empty list and every single object with 404, like Azure
    # does for a resource that has none. ChildRefuse: a pattern of paths that answer 403.
    param($w)
    $S1 = $global:TW_S1
    $rt = { param($Name, $Versions) [ordered]@{ resourceType = $Name; locations = @('West Europe'); apiVersions = @($Versions) } }
    $w.Providers = @(
        [ordered]@{ namespace = 'Microsoft.Storage'; resourceTypes = @((& $rt 'storageAccounts' @('2025-01-01', '2024-01-01', '2023-05-01')), (& $rt 'storageAccounts/blobServices' @('2025-06-01-preview', '2023-05-01', '2024-01-01'))) }
        [ordered]@{ namespace = 'Microsoft.Sql'; resourceTypes = @((& $rt 'servers' @('2023-08-01', '2021-11-01', '2014-04-01')), (& $rt 'servers/firewallRules' @('2014-04-01', '2023-08-01', '2021-11-01'))) }
        [ordered]@{ namespace = 'Microsoft.Network'; resourceTypes = @((& $rt 'virtualNetworks' @('2024-05-01')), (& $rt 'privateEndpoints' @('2024-05-01', '2023-11-01'))) }
        [ordered]@{ namespace = 'Microsoft.Compute'; resourceTypes = @((& $rt 'virtualMachines' @('2024-07-01'))) }
        [ordered]@{ namespace = 'Microsoft.KeyVault'; resourceTypes = @((& $rt 'vaults' @('2024-12-01-preview', '2024-11-01', '2023-07-01'))) }
        [ordered]@{ namespace = 'Microsoft.Quantum'; resourceTypes = @((& $rt 'workspaces' @('2023-11-13-preview'))) }
    )
    $w.ProviderStates = @{
        $S1            = @{ 'Microsoft.Storage' = 'Registered'; 'Microsoft.Sql' = 'Registered'; 'Microsoft.Network' = 'Registered'; 'Microsoft.Compute' = 'Registered'; 'Microsoft.KeyVault' = 'Registering' }
        $global:TW_S2 = @{ 'Microsoft.Network' = 'Registered'; 'Microsoft.Compute' = 'Registered' }
    }
    $w.ProvidersDenied = @(); $w.ChildRefuse = ''
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/([^/]+)/providers\?api-version='; Handler = {
            param($path, $body, $m)
            if (@($global:TW.ProvidersDenied) -contains $m[1]) { return (New-TWError 403 'AuthorizationFailed' 'The client does not have authorization to perform action Microsoft.Resources/subscriptions/providers/read.') }
            $states = $global:TW.ProviderStates[$m[1]]
            [ordered]@{ value = @($global:TW.Providers | ForEach-Object {
                        $state = 'NotRegistered'
                        if ($null -ne $states -and $states.ContainsKey($_['namespace'])) { $state = $states[$_['namespace']] }
                        [ordered]@{ id = ('/subscriptions/' + $m[1] + '/providers/' + $_['namespace']); namespace = $_['namespace']; resourceTypes = $_['resourceTypes']; registrationState = $state; registrationPolicy = 'RegistrationRequired' }
                    }) }
        } })
    $child = { param($Pattern, [scriptblock] $Handler) $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = $Pattern; Handler = $Handler }) }
    # storage account stcontosodata: blob service and three containers on two pages, a file share, a lifecycle policy
    & $child '/storageAccounts/stcontosodata/blobServices\?' { param($path, $body, $m) [ordered]@{ value = @([ordered]@{ id = $global:TW.Ids.StData + '/blobServices/default'; name = 'default'; type = 'Microsoft.Storage/storageAccounts/blobServices'
                    properties = [ordered]@{ isVersioningEnabled = $true; deleteRetentionPolicy = [ordered]@{ enabled = $true; days = 14 }; cors = [ordered]@{ corsRules = @() } } }) } }
    & $child '/storageAccounts/stcontosodata/blobServices/default/containers\?' {
        param($path, $body, $m)
        $base = $global:TW.Ids.StData + '/blobServices/default/containers/'
        $type = 'Microsoft.Storage/storageAccounts/blobServices/containers'
        New-TWPage @(
            [ordered]@{ id = $base + 'backups'; name = 'backups'; type = $type; properties = [ordered]@{ publicAccess = 'None'; hasImmutabilityPolicy = $false; leaseState = 'Available' } }
            [ordered]@{ id = $base + 'public-assets'; name = 'public-assets'; type = $type; properties = [ordered]@{ publicAccess = 'Blob'; hasImmutabilityPolicy = $false } }
            [ordered]@{ id = $base + '$web'; name = '$web'; type = $type; properties = [ordered]@{ publicAccess = 'None' } }) $path 2
    }
    & $child '/storageAccounts/stcontosodata/fileServices\?' { param($path, $body, $m) [ordered]@{ value = @([ordered]@{ id = $global:TW.Ids.StData + '/fileServices/default'; name = 'default'; type = 'Microsoft.Storage/storageAccounts/fileServices'
                    properties = [ordered]@{ shareDeleteRetentionPolicy = [ordered]@{ enabled = $true; days = 7 } } }) } }
    & $child '/storageAccounts/stcontosodata/fileServices/default/shares\?' { param($path, $body, $m) [ordered]@{ value = @([ordered]@{ id = $global:TW.Ids.StData + '/fileServices/default/shares/profiles'; name = 'profiles'
                    type = 'Microsoft.Storage/storageAccounts/fileServices/shares'; properties = [ordered]@{ shareQuota = 100; accessTier = 'TransactionOptimized'; enabledProtocols = 'SMB' } }) } }
    & $child '/storageAccounts/stcontosodata/managementPolicies/default\?' { param($path, $body, $m) [ordered]@{ id = $global:TW.Ids.StData + '/managementPolicies/default'; name = 'DefaultManagementPolicy'
            type = 'Microsoft.Storage/storageAccounts/managementPolicies'; properties = [ordered]@{ policy = [ordered]@{ rules = @([ordered]@{ name = 'move-to-cool'; enabled = $true; type = 'Lifecycle' }) } } } }
    # SQL firewall rules: only the 2021 version works, the answer names the versions (the provider list is ahead)
    & $child '/servers/sql-contoso/firewallRules\?api-version=([^&]+)' {
        param($path, $body, $m)
        if ($m[1] -ne '2021-11-01') {
            return (New-TWError 400 'NoRegisteredProviderFound' ("No registered resource provider found for location 'westeurope' and API version '" + $m[1] + "' for type 'servers/firewallRules'. The supported api-versions are '2014-04-01, 2021-11-01, 2022-05-01-preview'. The supported locations are 'westeurope'."))
        }
        $base = '/subscriptions/' + $global:TW_S1 + '/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql-contoso/firewallRules/'
        [ordered]@{ value = @(
                [ordered]@{ id = $base + 'AllowAllWindowsAzureIps'; name = 'AllowAllWindowsAzureIps'; type = 'Microsoft.Sql/servers/firewallRules'; properties = [ordered]@{ startIpAddress = '0.0.0.0'; endIpAddress = '0.0.0.0' } }
                [ordered]@{ id = $base + 'office'; name = 'office'; type = 'Microsoft.Sql/servers/firewallRules'; properties = [ordered]@{ startIpAddress = '203.0.113.10'; endIpAddress = '203.0.113.20' } }) }
    }
    # Key Vault through ARM: names and expiry, never a value
    & $child '/vaults/kv-contoso/secrets\?' { param($path, $body, $m) $kv = '/subscriptions/' + $global:TW_S1 + '/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv-contoso'
        [ordered]@{ value = @([ordered]@{ id = $kv + '/secrets/sql-admin-login'; name = 'sql-admin-login'; type = 'Microsoft.KeyVault/vaults/secrets'
                    properties = [ordered]@{ attributes = [ordered]@{ enabled = $true; exp = 1798761600 }; contentType = 'text/plain'; secretUri = 'https://kv-contoso.vault.azure.net/secrets/sql-admin-login' } }) } }
    # API Management: a backend with a literal credential and a subscription with keys (older API versions return them)
    & $child '/service/apim-contoso/backends\?' { param($path, $body, $m) $apim = '/subscriptions/' + $global:TW_S1 + '/resourceGroups/rg-app/providers/Microsoft.ApiManagement/service/apim-contoso'
        [ordered]@{ value = @([ordered]@{ id = $apim + '/backends/orders-backend'; name = 'orders-backend'; type = 'Microsoft.ApiManagement/service/backends'
                    properties = [ordered]@{ url = 'https://orders.internal.contoso.com'; protocol = 'http'; credentials = [ordered]@{ header = [ordered]@{ 'x-api-key' = @('LITERAL-BACKEND-KEY-1') } } } }) } }
    & $child '/service/apim-contoso/subscriptions\?' { param($path, $body, $m) $apim = '/subscriptions/' + $global:TW_S1 + '/resourceGroups/rg-app/providers/Microsoft.ApiManagement/service/apim-contoso'
        [ordered]@{ value = @([ordered]@{ id = $apim + '/subscriptions/master'; name = 'master'; type = 'Microsoft.ApiManagement/service/subscriptions'
                    properties = [ordered]@{ scope = $apim + '/'; state = 'active'; displayName = 'Built-in all-access subscription'; primaryKey = 'APIM-PRIMARY-KEY-2'; secondaryKey = 'APIM-SECONDARY-KEY-3' } }) } }
    # every other list below a resource: empty; every other single object: not found
    $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^?]+\?api-version='; Handler = {
            param($path, $body, $m)
            $p = ($path -replace '\?.*$', '')
            if ($global:TW.ChildRefuse -and $p -match $global:TW.ChildRefuse) { return (New-TWError 403 'AuthorizationFailed' 'The client does not have authorization to perform this action.') }
            $tail = @($p.Substring($p.LastIndexOf('/providers/') + 11).Split('/'))
            if ((($tail.Count - 1) % 2) -eq 1) { return [ordered]@{ value = @() } }
            return (New-TWError 404 'ResourceNotFound' 'The resource was not found.')
        } })
}

function Add-TWCodeFixtures {
    # Resources that hold code (AzureCode report) and their ARM answers; Kudu answers for app-contoso (AppCode).
    param($w, $res)
    $S1 = $global:TW_S1
    $law = New-TWId -Sub $S1 -Rg 'rg-data' -Type 'Microsoft.OperationalInsights/workspaces' -Name 'law-contoso'
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Logic/workflows' 'la-orders' ([ordered]@{ state = 'Enabled' })))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.DataFactory/factories' 'adf-contoso' ([ordered]@{ publicNetworkAccess = 'Enabled' })))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.StreamAnalytics/streamingjobs' 'asa-telemetry' ([ordered]@{ jobState = 'Running' })))
    $res.Add((New-TWRes $S1 'rg-network' 'Microsoft.Resources/templateSpecs' 'ts-network' ([ordered]@{ description = 'Hub network' })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Resources/deploymentScripts' 'ds-seed' ([ordered]@{ provisioningState = 'Succeeded' }) -Kind 'AzurePowerShell'))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Insights/workbooks' '0e0e0e0e-0000-0000-0000-000000000001' ([ordered]@{ displayName = 'Ops workbook' })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Portal/dashboards' 'dash-ops' ([ordered]@{ lenses = @() }) -Tags ([ordered]@{ 'hidden-title' = 'Operations' })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.Insights/scheduledQueryRules' 'alert-errors' ([ordered]@{ severity = 2; enabled = $true
                    criteria = [ordered]@{ allOf = @([ordered]@{ query = 'AppExceptions | summarize count() by bin(TimeGenerated, 5m)'; timeAggregation = 'Count' }) } })))
    $res.Add((New-TWRes $S1 'rg-data' 'Microsoft.OperationsManagement/solutions' 'SecurityInsights(law-contoso)' ([ordered]@{ workspaceResourceId = $law })))
    $res.Add((New-TWRes $S1 'rg-app' 'Microsoft.ApiManagement/service' 'apim-contoso' ([ordered]@{ gatewayUrl = 'https://apim-contoso.azure-api.net' }) -Sku ([ordered]@{ name = 'Developer'; capacity = 1 })))

    $w.KuduRoutes = [System.Collections.Generic.List[object]]::new()
    $w.WebRoutes = @{ 'apimstore\.blob\.core\.windows\.net/export/orders\.json' = '{"openapi":"3.0.1","info":{"title":"Orders API","version":"1"},"paths":{}}' }
    $arm = { param($Pattern, [scriptblock] $Handler) $w.ArmRoutes.Add(@{ Method = 'GET'; Pattern = $Pattern; Handler = $Handler }) }
    & $arm '/automationAccounts/aa-contoso/configurations\?' { param($path, $body, $m) [ordered]@{ value = @([ordered]@{ name = 'WebServer'; properties = [ordered]@{ state = 'Published' } }) } }
    & $arm '/automationAccounts/aa-contoso/configurations/WebServer/content\?' { param($path, $body, $m) New-TWResponse -Obj "Configuration WebServer {`n    Node localhost { WindowsFeature IIS { Ensure = 'Present'; Name = 'Web-Server' } }`n}`n" }
    & $arm '/providers/Microsoft\.Logic/workflows/la-orders\?' { param($path, $body, $m) [ordered]@{ name = 'la-orders'; type = 'Microsoft.Logic/workflows'; location = 'westeurope'
            properties = [ordered]@{ state = 'Enabled'; definition = [ordered]@{ '$schema' = 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
                    triggers = [ordered]@{ manual = [ordered]@{ type = 'Request'; kind = 'Http' } }; actions = [ordered]@{ reply = [ordered]@{ type = 'Response'; inputs = [ordered]@{ statusCode = 200 } } }; outputs = [ordered]@{} }; parameters = [ordered]@{} } } }
    & $arm '/factories/adf-contoso/(pipelines|dataflows|datasets|linkedservices|triggers)\?' {
        param($path, $body, $m)
        switch ($m[1]) {
            'pipelines' { [ordered]@{ value = @([ordered]@{ name = 'CopySales'; properties = [ordered]@{ activities = @([ordered]@{ name = 'Copy'; type = 'Copy' }) } }) } }
            'linkedservices' { [ordered]@{ value = @([ordered]@{ name = 'ls-sql'; properties = [ordered]@{ type = 'AzureSqlDatabase'; typeProperties = [ordered]@{ connectionString = '**********' } } }) } }
            default { [ordered]@{ value = @() } }
        }
    }
    & $arm '/streamingjobs/asa-telemetry\?\$expand=' { param($path, $body, $m) [ordered]@{ name = 'asa-telemetry'; properties = [ordered]@{ transformation = [ordered]@{ name = 'main'; properties = [ordered]@{ query = 'SELECT * INTO [out] FROM [in]' } } } } }
    & $arm '/templateSpecs/ts-network/versions\?' { param($path, $body, $m) [ordered]@{ value = @([ordered]@{ name = '1.0' }) } }
    & $arm '/templateSpecs/ts-network/versions/1\.0\?' { param($path, $body, $m) [ordered]@{ name = '1.0'; properties = [ordered]@{ mainTemplate = [ordered]@{ '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'; contentVersion = '1.0.0.0'; resources = @() } } } }
    & $arm '/deploymentScripts/ds-seed\?' { param($path, $body, $m) [ordered]@{ name = 'ds-seed'; kind = 'AzurePowerShell'; properties = [ordered]@{ scriptContent = 'Write-Output "seed data loaded"'; azPowerShellVersion = '11.0' } } }
    & $arm '/workbooks/0e0e0e0e-0000-0000-0000-000000000001\?canFetchContent=true' { param($path, $body, $m) [ordered]@{ properties = [ordered]@{ displayName = 'Ops workbook'; serializedData = '{"version":"Notebook/1.0","items":[]}' } } }
    & $arm '/dashboards/dash-ops\?' { param($path, $body, $m) [ordered]@{ name = 'dash-ops'; properties = [ordered]@{ lenses = @() } } }
    & $arm '/workspaces/law-contoso/providers/Microsoft\.SecurityInsights/alertRules\?' { param($path, $body, $m) [ordered]@{ value = @([ordered]@{ name = 'r1'; kind = 'Scheduled'; properties = [ordered]@{ displayName = 'Brute force'; query = 'SigninLogs | where ResultType != 0' } }) } }
    & $arm '/service/apim-contoso/policies/policy\?format=rawxml' { param($path, $body, $m) [ordered]@{ properties = [ordered]@{ format = 'rawxml'; value = '<policies><inbound><base /></inbound></policies>' } } }
    & $arm '/service/apim-contoso/apis\?' { param($path, $body, $m) [ordered]@{ value = @([ordered]@{ name = 'orders-api' }, [ordered]@{ name = 'orders-api;rev=2' }, [ordered]@{ name = 'soap-api' }) } }
    & $arm '/service/apim-contoso/apis/orders-api/policies/policy\?format=rawxml' { param($path, $body, $m) [ordered]@{ properties = [ordered]@{ value = '<policies><inbound><rate-limit calls="10" renewal-period="60" /></inbound></policies>' } } }
    & $arm '/service/apim-contoso/apis/orders-api\?format=openapi' { param($path, $body, $m) [ordered]@{ format = 'openapi+json-link'; value = [ordered]@{ link = 'https://apimstore.blob.core.windows.net/export/orders.json?sv=2021&sig=SECRETSAS' } } }
    & $arm '/service/apim-contoso/apis/soap-api\?format=openapi' { param($path, $body, $m) New-TWError 400 'ValidationError' 'Export of SOAP APIs to OpenAPI is not supported.' }
    $w.KuduRoutes.Add(@{ Method = 'GET'; Pattern = '^app-contoso\.scm\.azurewebsites\.net/api/zip/site/wwwroot/'; Handler = {
                param($path, $body, $m)
                if ($global:TW.KuduDenied) { return (New-TWError 403 'Forbidden' 'The client does not have authorization to perform action Microsoft.Web/sites/publish/Action.') }
                @{ StatusCode = 200; Content = ''; Headers = @{}; Zip = [ordered]@{ 'index.js' = 'module.exports = async () => 42;'; 'host.json' = '{"version":"2.0"}' } }
            } })
}

function Select-TWAdoPage {
    # honors $top/$skip of Azure DevOps list calls
    param($Items, [string] $Path)
    $all = @($Items | Where-Object { $null -ne $_ })
    $top = $all.Count; $skip = 0
    if ($Path -match '[?&]\$top=(\d+)') { $top = [int]$Matches[1] }
    if ($Path -match '[?&]\$skip=(\d+)') { $skip = [int]$Matches[1] }
    return @($all | Select-Object -Skip $skip -First $top)
}

function New-TWAdoList {
    param($Items, $Headers = $null)
    $v = @($Items | Where-Object { $null -ne $_ })
    return (New-TWResponse -Obj ([ordered]@{ count = $v.Count; value = $v }) -Headers $Headers)
}

function Add-TWAdoFixtures {
    # Azure DevOps organization "contoso-ado" (billed to S1); "fabrikam-old" is billed too but denies access.
    param($w)
    $T = $global:TW_Tenant
    $P1 = 'b1b1b1b1-0000-0000-0000-000000000001'; $P2 = 'b1b1b1b1-0000-0000-0000-000000000002'
    $E1 = 'd1d1d1d1-0000-0000-0000-000000000001'
    $a = [ordered]@{}
    $a.Projects = @(
        [ordered]@{ id = $P1; name = 'Web Shop'; description = 'Online shop of Contoso'; visibility = 'private'; state = 'wellFormed'; lastUpdateTime = '2026-09-01T00:00:00Z'
            capabilities = [ordered]@{ processTemplate = [ordered]@{ templateName = 'Contoso Agile' }; versioncontrol = [ordered]@{ sourceControlType = 'Git'; gitEnabled = 'True'; tfvcEnabled = 'False' } } }
        [ordered]@{ id = $P2; name = 'Legacy App'; description = ''; visibility = 'public'; state = 'wellFormed'; lastUpdateTime = '2021-01-01T00:00:00Z'
            capabilities = [ordered]@{ processTemplate = [ordered]@{ templateName = 'Agile' }; versioncontrol = [ordered]@{ sourceControlType = 'Tfvc'; gitEnabled = 'True'; tfvcEnabled = 'True' } } })
    $a.Repos = @(
        [ordered]@{ id = 'c1c1c1c1-0000-0000-0000-000000000001'; name = 'webshop'; project = [ordered]@{ id = $P1; name = 'Web Shop' }; defaultBranch = 'refs/heads/main'; size = 52428800; isDisabled = $false; isFork = $false }
        [ordered]@{ id = 'c1c1c1c1-0000-0000-0000-000000000002'; name = 'webshop-infra'; project = [ordered]@{ id = $P1; name = 'Web Shop' }; defaultBranch = 'refs/heads/main'; size = 1048576; isDisabled = $false; isFork = $false }
        [ordered]@{ id = 'c1c1c1c1-0000-0000-0000-000000000003'; name = 'legacy-code'; project = [ordered]@{ id = $P2; name = 'Legacy App' }; defaultBranch = 'refs/heads/master'; size = 2048; isDisabled = $true; isFork = $false })
    $a.Commits = @{ 'c1c1c1c1-0000-0000-0000-000000000001' = '2026-09-20T00:00:00Z'; 'c1c1c1c1-0000-0000-0000-000000000002' = '2025-08-01T00:00:00Z' }
    $a.RepoZips = @{
        'c1c1c1c1-0000-0000-0000-000000000001' = [ordered]@{ 'README.md' = '# Web Shop'; 'src/app.cs' = 'class App {}'; 'azure-pipelines.yml' = 'trigger: none' }
        'c1c1c1c1-0000-0000-0000-000000000002' = [ordered]@{ 'main.bicep' = 'param location string' }
    }
    $a.Policies = @{ $P1 = @(
            [ordered]@{ isEnabled = $true; isBlocking = $true; type = [ordered]@{ id = 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd'; displayName = 'Minimum approval count' }
                settings = [ordered]@{ minimumApproverCount = 2; scope = @([ordered]@{ repositoryId = 'c1c1c1c1-0000-0000-0000-000000000001'; refName = 'refs/heads/main'; matchKind = 'Exact' }) } }
            [ordered]@{ isEnabled = $true; isBlocking = $true; type = [ordered]@{ id = '0609b952-1397-4640-95ec-e00a01b2c241'; displayName = 'Build' }; settings = [ordered]@{ scope = @([ordered]@{ repositoryId = $null; refName = $null; matchKind = 'DefaultBranch' }) } }) }
    $a.Pipelines = @{ $P1 = @(
            [ordered]@{ id = 11; name = 'webshop-ci'; path = '\'; queueStatus = 'enabled'; process = [ordered]@{ type = 2; yamlFilename = '/azure-pipelines.yml' }
                repository = [ordered]@{ type = 'TfsGit'; name = 'webshop'; id = 'c1c1c1c1-0000-0000-0000-000000000001'; defaultBranch = 'refs/heads/main' }
                queue = [ordered]@{ name = 'Azure Pipelines'; pool = [ordered]@{ name = 'Azure Pipelines' } }
                latestCompletedBuild = [ordered]@{ finishTime = '2026-09-28T00:00:00Z'; result = 'succeeded' }; createdDate = '2024-01-10T00:00:00Z'; authoredBy = [ordered]@{ displayName = 'Alex Admin' } }
            [ordered]@{ id = 12; name = 'webshop-classic'; path = '\Legacy'; queueStatus = 'disabled'; process = [ordered]@{ type = 1 }
                repository = [ordered]@{ type = 'GitHub'; name = 'contoso/webshop' }; queue = [ordered]@{ name = 'Default'; pool = [ordered]@{ name = 'Default' } }
                latestBuild = [ordered]@{ finishTime = '2025-03-01T00:00:00Z'; result = 'failed' }; createdDate = '2020-05-01T00:00:00Z'; authoredBy = [ordered]@{ displayName = 'Former Dev' } }) }
    # TFVC in Legacy App: branch Trunk/Main with child branch Trunk/Dev; a classic pipeline maps Main and cloaks its docs
    $a.Pipelines[$P2] = @([ordered]@{ id = 13; name = 'legacy-build'; path = '\'; queueStatus = 'enabled'; process = [ordered]@{ type = 1 }
            repository = [ordered]@{ type = 'TfsVersionControl'; name = 'Legacy App'; defaultBranch = '$/Legacy App/Trunk/Main'
                properties = [ordered]@{ tfvcMapping = '{"mappings":[{"serverPath":"$/Legacy App/Trunk/Main","mappingType":"map","localPath":"\\"},{"serverPath":"$/Legacy App/Trunk/Main/docs","mappingType":"cloak","localPath":"\\docs"}]}' } }
            queue = [ordered]@{ name = 'Default'; pool = [ordered]@{ name = 'Default' } }
            latestCompletedBuild = [ordered]@{ finishTime = '2023-05-11T00:00:00Z'; result = 'succeeded' }; createdDate = '2018-01-01T00:00:00Z'; authoredBy = [ordered]@{ displayName = 'Former Dev' } })
    $a.TfvcBranches = @{ $P2 = @([ordered]@{ path = '$/Legacy App/Trunk/Main'; description = 'Main line'; owner = [ordered]@{ displayName = 'Former Dev' }; createdDate = '2015-03-01T00:00:00Z'; isDeleted = $false
                children = @([ordered]@{ path = '$/Legacy App/Trunk/Dev'; description = ''; owner = [ordered]@{ displayName = 'Former Dev' }; createdDate = '2016-01-01T00:00:00Z'; isDeleted = $false; children = @()
                        parent = [ordered]@{ path = '$/Legacy App/Trunk/Main' } }) }) }
    $a.TfvcItems = @{
        '$/Legacy App/Trunk/Main' = @(@('App.sln', 1048576), @('src/Program.cs', 2621440), @('docs/notes.txt', 100))
        '$/Legacy App/Trunk/Dev' = @(, @('App.sln', 524288))
    }
    $a.TfvcChangesets = @{
        '$/Legacy App/Trunk/Main' = [ordered]@{ changesetId = 120; createdDate = '2023-05-10T00:00:00Z'; author = [ordered]@{ displayName = 'Former Dev' }; comment = 'last fix' }
        '$/Legacy App/Trunk/Dev' = [ordered]@{ changesetId = 95; createdDate = '2022-01-01T00:00:00Z'; author = [ordered]@{ displayName = 'Former Dev' }; comment = 'dev work' }
    }
    $a.Releases = @{ $P1 = @([ordered]@{ id = 5; name = 'webshop-release'; path = '\'; environments = @([ordered]@{ name = 'Dev' }, [ordered]@{ name = 'Prod' })
                lastRelease = [ordered]@{ name = 'Release-42'; createdOn = '2026-06-01T00:00:00Z' }; createdBy = [ordered]@{ displayName = 'Alex Admin' }; modifiedOn = '2026-06-01T00:00:00Z'; isDisabled = $false }) }
    $wif = [ordered]@{ id = $E1; name = 'Contoso Prod (WIF)'; type = 'azurerm'; url = 'https://management.azure.com/'; isShared = $true; isReady = $true
        authorization = [ordered]@{ scheme = 'WorkloadIdentityFederation'; parameters = [ordered]@{ tenantid = $T; serviceprincipalid = 'abababab-0000-0000-0000-0000000000c1'
                workloadIdentityFederationIssuer = ('https://login.microsoftonline.com/{0}/v2.0' -f $T); workloadIdentityFederationSubject = ('/eid1/c/pub/t/xyz/a/abc/sc/a0a0a0a0-0000-0000-0000-000000000001/' + $E1) } }
        data = [ordered]@{ subscriptionId = $global:TW_S1; subscriptionName = 'Contoso Production'; creationMode = 'Automatic'; scopeLevel = 'Subscription' }; createdBy = [ordered]@{ displayName = 'Alex Admin' } }
    $a.Endpoints = @{
        $P1 = @($wif, [ordered]@{ id = 'd1d1d1d1-0000-0000-0000-000000000003'; name = 'contoso-github'; type = 'github'; url = 'https://github.com'; isShared = $false; isReady = $true
                authorization = [ordered]@{ scheme = 'InstallationToken'; parameters = [ordered]@{} }; data = [ordered]@{}; createdBy = [ordered]@{ displayName = 'Alex Admin' } })
        $P2 = @($wif, [ordered]@{ id = 'd1d1d1d1-0000-0000-0000-000000000002'; name = 'Legacy SPN'; type = 'azurerm'; url = 'https://management.azure.com/'; isShared = $false; isReady = $true
                authorization = [ordered]@{ scheme = 'ServicePrincipal'; parameters = [ordered]@{ tenantid = $T; serviceprincipalid = 'aa000000-0000-0000-0000-000000000002'; authenticationType = 'spnKey'; serviceprincipalkey = $null } }
                data = [ordered]@{ subscriptionId = $global:TW_S2; subscriptionName = 'Contoso Development'; creationMode = 'Manual'; scopeLevel = 'Subscription' }; createdBy = [ordered]@{ displayName = 'Former Dev' } })
    }
    $a.Pools = @(
        [ordered]@{ id = 1; name = 'Azure Pipelines'; isHosted = $true; poolType = 'automation'; size = 0 }
        [ordered]@{ id = 2; name = 'Default'; isHosted = $false; poolType = 'automation'; size = 2; autoProvision = $true; createdOn = '2019-01-01T00:00:00Z'; owner = [ordered]@{ displayName = 'Alex Admin' } }
        [ordered]@{ id = 3; name = 'Scale Agents'; isHosted = $false; poolType = 'automation'; size = 0; createdOn = '2024-01-01T00:00:00Z' }
        [ordered]@{ id = 4; name = 'Deploy Pool'; isHosted = $false; poolType = 'deployment'; size = 1 })
    $a.ElasticPools = @([ordered]@{ poolId = 3; azureId = ('/subscriptions/{0}/resourceGroups/rg-build/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-agents' -f $global:TW_S1); maxCapacity = 4; desiredIdle = 0; osType = 'linux'; state = 'online' })
    $a.Agents = @{ '2' = @(
            [ordered]@{ id = 21; name = 'build01'; version = '3.236.1'; osDescription = 'Microsoft Windows 10.0.20348'; status = 'online'; enabled = $true; createdOn = '2023-01-01T00:00:00Z'
                systemCapabilities = [ordered]@{ 'Agent.ComputerName' = 'vm-app01'; 'Agent.OS' = 'Windows_NT'; 'BUILD_SECRET' = 'do-not-export' }; lastCompletedRequest = [ordered]@{ finishTime = '2026-09-28T09:00:00Z'; result = 'succeeded' } }
            [ordered]@{ id = 22; name = 'oldagent'; version = '2.217.2'; osDescription = 'Linux'; status = 'offline'; enabled = $true; createdOn = '2020-01-01T00:00:00Z'
                systemCapabilities = [ordered]@{ 'Agent.ComputerName' = 'buildbox-old' }; lastCompletedRequest = [ordered]@{ finishTime = '2024-11-01T00:00:00Z'; result = 'failed' } }) }
    $a.Extensions = @(
        [ordered]@{ publisherId = 'ms'; publisherName = 'Microsoft'; extensionId = 'vss-code-search'; extensionName = 'Code Search'; version = '19.0.0'; flags = 'builtIn, trusted'; installState = [ordered]@{ flags = 'none' }; lastPublished = '2025-01-01T00:00:00Z' }
        [ordered]@{ publisherId = 'sonarsource'; publisherName = 'SonarSource'; extensionId = 'sonarqube'; extensionName = 'SonarQube'; version = '6.0.0'; flags = 'none'; installState = [ordered]@{ flags = 'none' }; scopes = @('vso.build', 'vso.code'); lastPublished = '2026-05-01T00:00:00Z' })
    $a.Hooks = @([ordered]@{ id = 'h1'; publisherId = 'tfs'; eventType = 'git.push'; consumerId = 'webHooks'; consumerActionId = 'httpRequest'; status = 'enabled'
            consumerInputs = [ordered]@{ url = 'https://hooks.slack.com/services/T000/B000/SECRETTOKEN42' }; publisherInputs = [ordered]@{ projectId = $P1 }; createdBy = [ordered]@{ displayName = 'Alex Admin' }; modifiedDate = '2026-01-01T00:00:00Z' })
    # feeds: contoso-packages (organization, npmjs upstream) and webshop-feed (project Web Shop)
    $F1 = 'f1f1f1f1-0000-0000-0000-000000000001'; $F2 = 'f1f1f1f1-0000-0000-0000-000000000002'; $UP = 'e1e1e1e1-0000-0000-0000-000000000001'
    # as Azure DevOps answers: false/null properties left out, obsolete isCachedVersion absent (directUpstreamSourceId
    # marks versions saved from an upstream), protocolType in mixed case, the organization list includes project feeds
    $webshopFeed = [ordered]@{ id = $F2; name = 'webshop-feed'; project = [ordered]@{ id = $P1; name = 'Web Shop'; visibility = 'private' }; upstreamEnabled = $false; upstreamSources = @() }
    $a.OrgFeeds = @([ordered]@{ id = $F1; name = 'contoso-packages'; project = $null; upstreamEnabled = $true
            upstreamSources = @([ordered]@{ id = $UP; name = 'npmjs'; protocol = 'npm'; location = 'https://registry.npmjs.org/'; upstreamSourceType = 'public' }) }, $webshopFeed)
    $a.ProjectFeeds = @{ $P1 = @($webshopFeed) }
    $ver = { param($Id, $Version, $Latest, $Date, [string[]] $Views, $Upstream)
        $v = [ordered]@{ id = ('a8a8a8a8-0000-0000-0000-00000000000' + $Id); version = $Version; normalizedVersion = $Version; isListed = $true
            publishDate = $Date; views = @($Views | Where-Object { $_ } | ForEach-Object { [ordered]@{ id = 'view-' + $_; name = $_; url = $null; type = 'implicit' } }) }
        if ($Latest) { $v['isLatest'] = $true }
        if ($Upstream) { $v['directUpstreamSourceId'] = $Upstream }
        $v }
    $pkg = { param($Id, $Name, $Protocol, $Versions) [ordered]@{ id = ('a7a7a7a7-0000-0000-0000-00000000000' + $Id); name = $Name; normalizedName = $Name.ToLowerInvariant(); protocolType = $Protocol; versions = @($Versions) } }
    $a.FeedPackages = @{
        $F1 = @(
            (& $pkg 1 'Contoso.Core' 'NuGet' @((& $ver 1 '1.0.0' $false '2025-01-15T00:00:00Z' @('Local')), (& $ver 2 '1.1.0' $true '2026-06-01T00:00:00Z' @('Release', 'Local'))))
            (& $pkg 2 '@contoso/ui' 'Npm' @(& $ver 3 '2.0.0' $true '2026-07-01T00:00:00Z' @('Local')))
            (& $pkg 3 'left-pad' 'Npm' @(& $ver 4 '1.3.0' $true '2018-04-09T00:00:00Z' @() $UP))
            (& $pkg 4 'contoso-tools' 'UPack' @(& $ver 5 '0.1.0' $true '2026-03-01T00:00:00Z' @('Local'))))
        $F2 = @(
            (& $pkg 5 'com.contoso:webshop-lib' 'maven' @(& $ver 6 '3.2.1' $true '2026-08-01T00:00:00Z' @('Local')))
            (& $pkg 6 'contoso-utils' 'PyPI' @(& $ver 7 '0.9.0' $true '2026-05-01T00:00:00Z' @('Local')))
            (& $pkg 7 'contoso-rs' 'Cargo' @(& $ver 8 '0.2.0' $true '2026-04-01T00:00:00Z' @('Local')))
            (& $pkg 8 'webshop-assets' 'UPack' @(& $ver 9 '1.0.0' $true '2026-02-01T00:00:00Z' @('Local'))))
    }
    $a.VersionFiles = @{ 'a8a8a8a8-0000-0000-0000-000000000006' = @('webshop-lib-3.2.1.jar', 'webshop-lib-3.2.1.jar.sha1', 'webshop-lib-3.2.1.pom', 'webshop-lib-3.2.1.pom.md5')
        'a8a8a8a8-0000-0000-0000-000000000007' = @('contoso_utils-0.9.0-py3-none-any.whl') }
    $a.PackageMetrics = @{
        'a7a7a7a7-0000-0000-0000-000000000001' = [ordered]@{ downloadCount = 42; downloadUniqueUsers = 5; lastDownloaded = '2026-09-20T00:00:00Z' }
        'a7a7a7a7-0000-0000-0000-000000000003' = [ordered]@{ downloadCount = 7; downloadUniqueUsers = 2; lastDownloaded = '2026-09-01T00:00:00Z' }
        'a7a7a7a7-0000-0000-0000-000000000005' = [ordered]@{ downloadCount = 0; downloadUniqueUsers = 0; lastDownloaded = $null }
    }
    $a.Retention = @{ $F1 = [ordered]@{ countLimit = 20; daysToKeepRecentlyDownloadedPackages = 30 } }
    $a.UpackSizes = @{ 'contoso-tools' = [long]2048; 'webshop-assets' = [long]3GB }
    $w.DownloadSizes['/nuget/packages/Contoso\.Core/'] = [long]3MB   # size before download (-AdoPackageMaxSizeMB); others 2 KB
    # Microsoft ArtifactTool (Universal Packages): the release Azure DevOps offers and its zip on blob storage
    $w.WebZips['vsassets\.io/artifacttool/'] = [ordered]@{ 'artifacttool.exe' = 'MZ fake ArtifactTool'; 'artifacttool' = '#!/bin/sh'; 'native\amd64\librocksdb.so' = 'native library' }
    $a.FeedPermissions = @{ $F1 = @(
            [ordered]@{ role = 'administrator'; displayName = '[contoso-ado]\Project Collection Administrators'; identityDescriptor = 'Microsoft.TeamFoundation.Identity;S-1-9-1551374245-1'; identityId = 'c9c9c9c9-0000-0000-0000-000000000001'; isInheritedRole = $false }
            [ordered]@{ role = 'contributor'; displayName = 'Project Collection Build Service (contoso-ado)'; identityDescriptor = 'Microsoft.TeamFoundation.ServiceIdentity;build:1'; identityId = 'c9c9c9c9-0000-0000-0000-000000000002'; isInheritedRole = $false }
            [ordered]@{ role = 'reader'; displayName = 'Pat Partner'; identityDescriptor = 'Microsoft.IdentityModel.Claims.ClaimsIdentity;pat@fabrikam.com'; identityId = 'c9c9c9c9-0000-0000-0000-000000000003'; isInheritedRole = $true }
            # no display name, descriptor as an object
            [ordered]@{ role = 'collaborator'; identityDescriptor = [ordered]@{ identityType = 'Microsoft.TeamFoundation.Identity'; identifier = 'S-1-9-1551374245-4' }; identityId = 'c9c9c9c9-0000-0000-0000-000000000004' }) }
    $never = '0001-01-01T00:00:00Z'
    $mkUser = { param($Upn, $Name, $Origin, $Meta, $LicType, $LicName, $Source, $Last, $Created)
        [ordered]@{ id = [guid]::NewGuid().ToString(); user = [ordered]@{ principalName = $Upn; displayName = $Name; origin = $Origin; metaType = $Meta; subjectKind = 'user' }
            accessLevel = [ordered]@{ accountLicenseType = $LicType; licenseDisplayName = $LicName; licensingSource = $Source; status = 'active' }; lastAccessedDate = $Last; dateCreated = $Created } }
    $a.Users1 = @((& $mkUser 'alex.admin@contoso.onmicrosoft.com' 'Alex Admin' 'aad' 'member' 'express' 'Basic' 'account' '2026-09-28T00:00:00Z' '2019-01-01T00:00:00Z'),
        (& $mkUser 'former.dev@contoso.com' 'Former Dev' 'aad' 'member' 'express' 'Basic' 'account' '2026-02-01T00:00:00Z' '2020-01-01T00:00:00Z'))
    $a.Users2 = @((& $mkUser 'pat@fabrikam.com' 'Pat Partner' 'aad' 'guest' 'stakeholder' 'Stakeholder' 'account' $never '2025-01-01T00:00:00Z'),
        (& $mkUser 'someone@outlook.com' 'Someone Private' 'msa' '' 'advanced' 'Basic + Test Plans' 'account' $never '2026-09-20T00:00:00Z'))
    $a.Groups = @(
        [ordered]@{ descriptor = 'vssgp.pca'; displayName = 'Project Collection Administrators'; principalName = '[contoso-ado]\Project Collection Administrators'; origin = 'vsts'; subjectKind = 'group' }
        [ordered]@{ descriptor = 'vssgp.pa1'; displayName = 'Project Administrators'; principalName = '[Web Shop]\Project Administrators'; origin = 'vsts'; subjectKind = 'group' }
        [ordered]@{ descriptor = 'vssgp.contrib'; displayName = 'Contributors'; principalName = '[Web Shop]\Contributors'; origin = 'vsts'; subjectKind = 'group' }
        [ordered]@{ descriptor = 'aadgp.admins'; displayName = 'g-app-admins'; principalName = '[TEAM FOUNDATION]\g-app-admins'; origin = 'aad'; subjectKind = 'group' })
    $a.GraphUsers = @([ordered]@{ descriptor = 'aad.alex'; displayName = 'Alex Admin'; principalName = 'alex.admin@contoso.onmicrosoft.com'; origin = 'aad'; subjectKind = 'user' })
    $a.Memberships = @{ 'vssgp.pca' = @('aad.alex', 'aadgp.admins'); 'vssgp.pa1' = @('aad.alex', 'aadsp.pipeline') }
    $a.WorkItems = @(
        [ordered]@{ Project = [ordered]@{ ProjectName = 'Web Shop' }; WorkItemType = 'User Story'; Count = 120 }
        [ordered]@{ Project = [ordered]@{ ProjectName = 'Web Shop' }; WorkItemType = 'Bug'; Count = 45 }
        [ordered]@{ Project = [ordered]@{ ProjectName = 'Legacy App' }; WorkItemType = 'Task'; Count = 10 })
    $a.Processes = @(
        [ordered]@{ typeId = 'adcc42ab-9882-485e-a3ed-7678f01f66bc'; name = 'Agile'; customizationType = 'system'; parentProcessTypeId = '00000000-0000-0000-0000-000000000000'; isDefault = $false; isEnabled = $true; projects = @([ordered]@{ name = 'Legacy App' }) }
        [ordered]@{ typeId = 'e0e0e0e0-0000-0000-0000-000000000001'; name = 'Contoso Agile'; customizationType = 'inherited'; parentProcessTypeId = 'adcc42ab-9882-485e-a3ed-7678f01f66bc'; isDefault = $true; isEnabled = $true; projects = @([ordered]@{ name = 'Web Shop' }) })
    $a.Environments = @{ $P1 = @([ordered]@{ id = 1; name = 'Production'; createdOn = '2024-01-01T00:00:00Z'; lastModifiedOn = '2026-01-01T00:00:00Z' }) }
    $a.EnvDetail = @{ '1' = [ordered]@{ id = 1; name = 'Production'; resources = @([ordered]@{ id = 1; name = 'webshop-ns'; type = 'kubernetes' }) } }
    $a.Checks = @{ '1' = @([ordered]@{ id = 1; type = [ordered]@{ name = 'Approval' } }, [ordered]@{ id = 2; type = [ordered]@{ name = 'Task Check' } }) }
    $a.DeploymentGroups = @{ $P1 = @([ordered]@{ id = 1; name = 'dg-web'; machineCount = 1; machines = @([ordered]@{ agent = [ordered]@{ name = 'vm-app01'; status = 'online'; version = '3.236.1' }; tags = @('web') }) }) }
    $a.VariableGroups = @{ $P1 = @(
            [ordered]@{ id = 1; name = 'webshop-settings'; type = 'Vsts'; variables = [ordered]@{ ApiUrl = [ordered]@{ value = 'https://api.webshop.example/v1-secretish' }; DbPassword = [ordered]@{ isSecret = $true; value = $null } }
                createdBy = [ordered]@{ displayName = 'Alex Admin' }; modifiedOn = '2026-08-01T00:00:00Z' }
            [ordered]@{ id = 2; name = 'kv-secrets'; type = 'AzureKeyVault'; providerData = [ordered]@{ serviceEndpointId = $E1; vault = 'kv-contoso' }; variables = [ordered]@{ 'sql-password' = [ordered]@{ isSecret = $true } }
                createdBy = [ordered]@{ displayName = 'Alex Admin' }; modifiedOn = '2026-08-01T00:00:00Z' }) }
    $a.SecureFiles = @{ $P1 = @([ordered]@{ id = 's1'; name = 'signing.pfx'; createdBy = [ordered]@{ displayName = 'Alex Admin' }; createdOn = '2025-01-01T00:00:00Z'; modifiedOn = '2025-01-01T00:00:00Z' }) }
    $w.Ado = $a

    $org = '^(?:[a-z]+\.)?dev\.azure\.com/contoso-ado/'
    $proj = '([0-9a-f-]{36})/'
    $add = { param($Pattern, [scriptblock] $Handler) $w.AdoRoutes.Add(@{ Method = 'GET'; Pattern = $Pattern; Handler = $Handler }) }
    & $add '^(?:[a-z]+\.)?dev\.azure\.com/fabrikam-old/' { param($path, $body, $m) New-TWResponse -Obj ([ordered]@{ message = 'TF400813: The user is not authorized to access this resource.'; typeKey = 'UnauthorizedRequestException' }) -Status 401 -Headers @{ 'X-VSS-ResourceTenant' = $global:TW_OtherTenant } }
    & $add '^(?:[a-z]+\.)?dev\.azure\.com/contoso-sandbox/' { param($path, $body, $m) New-TWResponse -Obj ([ordered]@{ message = "TF400813: The user 'alex.admin@contoso.onmicrosoft.com' is not authorized to access this resource."; typeKey = 'UnauthorizedRequestException' }) -Status 401 }
    & $add '^dev\.azure\.com/public-org/_apis/connectionData' { param($path, $body, $m) [ordered]@{ instanceId = 'a0a0a0a0-0000-0000-0000-00000000000b'; authenticatedUser = [ordered]@{ id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; descriptor = 'System:PublicAccess;aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; providerDisplayName = 'Anonymous' } } }
    & $add '^vsaex\.dev\.azure\.com/_apis/EnterpriseCatalog/Organizations\?tenantId=' {
        param($path, $body, $m)
        New-TWResponse -Obj ([string][char]0xFEFF + '"Organization Id","Organization Name","Url","Owner","Exception Type","Error Message"' + "`r`n" +
            '"a0a0a0a0-0000-0000-0000-000000000001","contoso-ado","https://dev.azure.com/contoso-ado/","alex.admin@contoso.onmicrosoft.com","",""' + "`r`n" +
            '"a0a0a0a0-0000-0000-0000-000000000009","contoso-sandbox","https://dev.azure.com/contoso-sandbox/","alex.admin@contoso.onmicrosoft.com","",""' + "`r`n" +
            '"a0a0a0a0-0000-0000-0000-00000000000a","contoso-archive","https://dev.azure.com/contoso-archive/","former.dev@contoso.com","",""' + "`r`n")
    }
    & $add ($org + '_apis/projects\?') {
        param($path, $body, $m)
        New-TWAdoList (Select-TWAdoPage @($global:TW.Ado.Projects | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; visibility = $_.visibility } }) $path)
    }
    & $add ($org + '_apis/projects/([0-9a-f-]{36})\?includeCapabilities') { param($path, $body, $m) @($global:TW.Ado.Projects | Where-Object { $_.id -eq $m[1] })[0] }
    & $add ($org + '_apis/connectionData') { param($path, $body, $m) [ordered]@{ instanceId = 'a0a0a0a0-0000-0000-0000-000000000001'; authenticatedUser = [ordered]@{ id = '0a000000-0000-0000-0000-0000000000a1'; descriptor = 'aad.alex'; providerDisplayName = 'Alex Admin' } } }
    & $add ($org + '_apis/git/repositories\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Repos }
    & $add ($org + $proj + '_apis/git/repositories/([0-9a-f-]{36})/commits\?') { param($path, $body, $m) $d = $global:TW.Ado.Commits[$m[2]]; if ($d) { New-TWAdoList @([ordered]@{ commitId = 'abc'; committer = [ordered]@{ date = $d } }) } else { New-TWAdoList @() } }
    & $add ($org + $proj + '_apis/git/repositories/([0-9a-f-]{36})/items\?.*\$format=zip') {
        param($path, $body, $m)
        $files = $global:TW.Ado.RepoZips[$m[2]]
        if ($null -eq $files -or $path -notmatch 'versionDescriptor\.version=main') { return (New-TWError 404 'GitItemNotFoundException' 'The item does not exist.') }
        @{ StatusCode = 200; Content = ''; Headers = @{}; Zip = $files }
    }
    & $add ($org + $proj + '_apis/git/repositories/([0-9a-f-]{36})/items\?') {
        param($path, $body, $m)
        if ($path -match 'path=%2Fazure-pipelines\.yml' -and $path -match 'versionDescriptor\.version=main') {
            return [ordered]@{ path = '/azure-pipelines.yml'; content = "trigger:`n- main`npool:`n  vmImage: ubuntu-latest`nsteps:`n- script: dotnet build`n" }
        }
        New-TWError 404 'GitItemNotFoundException' 'The item does not exist.'
    }
    & $add ($org + $proj + '_apis/release/definitions/(\d+)\?') {
        param($path, $body, $m)
        [ordered]@{ id = [int]$m[2]; name = 'webshop-release'; path = '\'; environments = @([ordered]@{ name = 'Dev'; rank = 1 }, [ordered]@{ name = 'Prod'; rank = 2 })
            artifacts = @([ordered]@{ alias = '_webshop-ci'; type = 'Build' }); variables = [ordered]@{ Region = [ordered]@{ value = 'westeurope' } } }
    }
    & $add ($org + $proj + '_apis/policy/configurations\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Policies[$m[1]] }
    & $add ($org + $proj + '_apis/build/definitions\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Pipelines[$m[1]] }
    & $add ($org + $proj + '_apis/release/definitions\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Releases[$m[1]] }
    & $add ($org + $proj + '_apis/serviceendpoint/endpoints\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Endpoints[$m[1]] }
    & $add ($org + '_apis/distributedtask/pools\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Pools }
    & $add ($org + '_apis/distributedtask/elasticpools\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.ElasticPools }
    & $add ($org + '_apis/distributedtask/pools/(\d+)/agents\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Agents[$m[1]] }
    & $add ($org + $proj + '_apis/distributedtask/deploymentgroups\?') { param($path, $body, $m) New-TWAdoList @($global:TW.Ado.DeploymentGroups[$m[1]] | Where-Object { $null -ne $_ } | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; machineCount = $_.machineCount } }) }
    & $add ($org + $proj + '_apis/distributedtask/deploymentgroups/(\d+)/targets\?') { param($path, $body, $m) New-TWAdoList @($global:TW.Ado.DeploymentGroups[$m[1]] | Where-Object { $null -ne $_ -and [string]$_.id -eq $m[2] } | ForEach-Object { $_.machines }) }
    & $add ($org + $proj + '_apis/distributedtask/environments\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Environments[$m[1]] }
    & $add ($org + $proj + '_apis/distributedtask/environments/(\d+)\?') { param($path, $body, $m) $global:TW.Ado.EnvDetail[$m[2]] }
    & $add ($org + $proj + '_apis/pipelines/checks/configurations\?') { param($path, $body, $m) if ($path -match 'resourceId=(\d+)') { New-TWAdoList $global:TW.Ado.Checks[$Matches[1]] } else { New-TWAdoList @() } }
    & $add ($org + $proj + '_apis/distributedtask/variablegroups\?') { param($path, $body, $m) $from = 0; if ($path -match 'continuationToken=(\d+)') { $from = [int]$Matches[1] }; New-TWAdoList (Select-TWAdoPage @($global:TW.Ado.VariableGroups[$m[1]] | Where-Object { $null -ne $_ -and [int]$_.id -ge $from } | Sort-Object { [int]$_.id }) $path) }
    & $add ($org + $proj + '_apis/distributedtask/securefiles\?') {
        param($path, $body, $m)
        if ($m[1] -eq 'b1b1b1b1-0000-0000-0000-000000000002') { return (New-TWError 403 'Forbidden' 'VS800075: The project does not allow access to secure files.') }
        New-TWAdoList $global:TW.Ado.SecureFiles[$m[1]]
    }
    & $add ($org + '_apis/extensionmanagement/installedextensions\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Extensions }
    & $add ($org + '_apis/hooks/subscriptions\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Hooks }
    $feed = $org + '(?:' + $proj + ')?_apis/packaging/Feeds/([0-9a-f-]{36})/'
    & $add ($feed + 'packages\?') {
        param($path, $body, $m)
        # all versions only with includeAllVersions=true (otherwise the latest one)
        $all = @($global:TW.Ado.FeedPackages[$m[2]] | Where-Object { $null -ne $_ })
        if ($path -notmatch 'includeAllVersions=true') { $all = @($all | ForEach-Object { $c = [ordered]@{}; foreach ($k in $_.Keys) { $c[$k] = $_[$k] }; $c['versions'] = @($_.versions | Where-Object { $_.isLatest }); $c }) }
        New-TWAdoList (Select-TWAdoPage $all $path)
    }
    & $add ($feed + 'Packages/([0-9a-f-]{36})/versions/([0-9a-f-]{36})\?') {
        param($path, $body, $m)
        $v = @($global:TW.Ado.FeedPackages[$m[2]] | Where-Object { $null -ne $_ -and $_.id -eq $m[3] } | ForEach-Object { $_.versions } | Where-Object { $_.id -eq $m[4] })
        if ($v.Count -eq 0) { return (New-TWResponse -Obj ([ordered]@{ message = 'VS403280: The package version was not found.'; typeKey = 'PackageVersionNotFoundException' }) -Status 404) }
        $d = [ordered]@{}; foreach ($k in $v[0].Keys) { $d[$k] = $v[0][$k] }
        $d['files'] = @($global:TW.Ado.VersionFiles[$m[4]] | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = $_; protocolMetadata = [ordered]@{ schemaVersion = 1 } } })
        $d
    }
    $w.AdoRoutes.Add(@{ Method = 'POST'; Pattern = ($feed + 'packagemetricsbatch\?'); Handler = {
                param($path, $body, $m)
                $ids = @((ConvertFrom-Json $body).packageIds)
                New-TWAdoList @($ids | Where-Object { $global:TW.Ado.PackageMetrics.ContainsKey($_) } | ForEach-Object { $x = [ordered]@{ packageId = $_ }; foreach ($k in $global:TW.Ado.PackageMetrics[$_].Keys) { $x[$k] = $global:TW.Ado.PackageMetrics[$_][$k] }; $x })
            } })
    & $add ($feed + 'views\?') { param($path, $body, $m) New-TWAdoList @('Release', 'Local', 'Prerelease' | ForEach-Object { [ordered]@{ id = 'view-' + $_; name = $_; type = 'release'; visibility = 'private' } }) }
    & $add ($feed + 'retentionpolicies\?') {
        param($path, $body, $m)
        # no policy: HTTP 200 with the body null
        $rp = $global:TW.Ado.Retention[$m[2]]
        if ($null -eq $rp) { return (New-TWResponse -Obj 'null') }
        $rp
    }
    & $add ($feed + 'permissions\?') {
        param($path, $body, $m)
        $pm = $global:TW.Ado.FeedPermissions[$m[2]]
        if ($null -eq $pm) { return (New-TWResponse -Obj ([ordered]@{ message = 'VS403352: You need Administer permissions on the feed to see its permissions.'; typeKey = 'FeedNeedsPermissionsException' }) -Status 403) }
        New-TWAdoList $pm
    }
    & $add '^vsblob\.dev\.azure\.com/contoso-ado/_apis/clienttools/ArtifactTool/release\?osName=' {
        param($path, $body, $m)
        [ordered]@{ name = 'ArtifactTool'; rid = 'win-x64'; version = '0.2.574'
            uri = 'https://08wvsblobprodsu6weus73.vsblob.vsassets.io/artifacttool/artifacttool-win-x64-Release_0.2.574.zip?sv=2019-07-07&sr=b&sig=SASSIGNATURE42&sp=r' }
    }
    & $add ('^pkgs\.dev\.azure\.com/contoso-ado/(?:' + $proj + ')?_packaging/([0-9a-f-]{36})/upack/packages/([^/]+)/versions/([^?]+)\?api-version=7\.1-preview\.1') {
        param($path, $body, $m)
        [ordered]@{ description = ''; manifestId = 'manifest'; packageSize = [long]$global:TW.Ado.UpackSizes[[uri]::UnescapeDataString($m[3])]; superRootId = 'root'; version = $m[4] }
    }
    # TFVC (Legacy App): branches with children, the file list of a path, its last changeset, and a folder zip whose
    # entries sit below the branch's own folder name
    & $add ($org + $proj + '_apis/tfvc/branches\?') { param($path, $body, $m) New-TWAdoList @($global:TW.Ado.TfvcBranches[$m[1]] | Where-Object { $null -ne $_ }) }
    & $add ($org + $proj + '_apis/tfvc/items\?scopePath=([^&]+)&recursionLevel=Full') {
        param($path, $body, $m)
        $sp = [uri]::UnescapeDataString($m[2])
        $files = $global:TW.Ado.TfvcItems[$sp]
        if ($null -eq $files) { return (New-TWResponse -Obj ([ordered]@{ message = "TF401174: The item '$sp' could not be found in the repository."; typeKey = 'ItemNotFoundException' }) -Status 404) }
        $v = [System.Collections.Generic.List[object]]::new()
        $v.Add([ordered]@{ version = 120; changeDate = '2023-05-10T00:00:00Z'; path = $sp; isFolder = $true; isBranch = $true })
        foreach ($f in $files) { $v.Add([ordered]@{ version = 100; changeDate = '2023-01-01T00:00:00Z'; path = $sp + '/' + $f[0]; size = [long]$f[1]; hashValue = 'aGFzaA==' }) }
        New-TWAdoList $v
    }
    & $add ($org + $proj + '_apis/tfvc/changesets\?searchCriteria\.itemPath=([^&]+)') { param($path, $body, $m) New-TWAdoList @($global:TW.Ado.TfvcChangesets[[uri]::UnescapeDataString($m[2])] | Where-Object { $null -ne $_ }) }
    # like Azure DevOps: a single path with a recursionLevel is refused
    & $add ($org + $proj + '_apis/tfvc/items\?path=[^&]+&(.*&)?recursionLevel=') {
        param($path, $body, $m)
        New-TWResponse -Obj ([ordered]@{ message = 'Cannot specify a "recursionLevel" other than "None" when providing a single item "path". Use the "scopePath" query parameter filter instead to get a collection of items.'; typeKey = 'ArgumentException' }) -Status 400
    }
    & $add ($org + $proj + '_apis/tfvc/items\?path=([^&]+)&download=true&%24format=zip&api-version=7\.1-preview\.1') {
        param($path, $body, $m)
        $sp = [uri]::UnescapeDataString($m[2])
        $files = $global:TW.Ado.TfvcItems[$sp]
        if ($null -eq $files) { return (New-TWResponse -Obj ([ordered]@{ message = "TF401174: The item '$sp' could not be found in the repository."; typeKey = 'ItemNotFoundException' }) -Status 404) }
        $leaf = @($sp -split '/')[-1]
        $entries = [ordered]@{}
        foreach ($f in $files) { $entries[$leaf + '/' + $f[0]] = 'tfvc ' + $leaf + '/' + $f[0] }
        @{ StatusCode = 200; Content = ''; Headers = @{}; Zip = $entries }
    }
    # package downloads (pkgs.dev.azure.com): a small text file per requested file; NuGet, Maven and PyPI accept only the
    # preview api-version, like Azure DevOps
    & $add ('^pkgs\.dev\.azure\.com/contoso-ado/(?:' + $proj + ')?_apis/packaging/feeds/([0-9a-f-]{36})/(nuget|npm|maven|pypi|cargo)/(.+)/(?:content|download)\?') {
        param($path, $body, $m)
        if ($m[3] -match '^(nuget|maven|pypi)$' -and $path -notmatch 'api-version=7\.1-preview\.1') {
            return (New-TWResponse -Obj ([ordered]@{ message = 'The requested version "7.1" of the resource is under preview. The -preview flag must be supplied in the api-version for such requests.'; typeKey = 'VssInvalidPreviewVersionException' }) -Status 400)
        }
        @{ StatusCode = 200; Content = ''; Headers = @{}; File = ('{0} file {1}' -f $m[3], [uri]::UnescapeDataString($m[4])) }
    }
    & $add ($org + '_apis/packaging/feeds\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.OrgFeeds }
    & $add ($org + $proj + '_apis/packaging/feeds\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.ProjectFeeds[$m[1]] }
    & $add ($org + '_apis/userentitlements\?') {
        param($path, $body, $m)
        if ($path -notmatch 'continuationToken=') { return [ordered]@{ members = @($global:TW.Ado.Users1); continuationToken = 'users2' } }
        return [ordered]@{ members = @($global:TW.Ado.Users2); continuationToken = $null }
    }
    & $add ($org + '_apis/graph/groups\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Groups }
    & $add ($org + '_apis/graph/users\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.GraphUsers }
    & $add ($org + '_apis/graph/memberships/([^?]+)\?direction=down') { param($path, $body, $m) New-TWAdoList @($global:TW.Ado.Memberships[$m[1]] | ForEach-Object { [ordered]@{ containerDescriptor = $m[1]; memberDescriptor = $_ } }) }
    & $add ($org + '_odata/') { param($path, $body, $m) [ordered]@{ '@odata.context' = 'x'; value = @($global:TW.Ado.WorkItems) } }
    & $add ($org + '_apis/work/processes\?') { param($path, $body, $m) New-TWAdoList $global:TW.Ado.Processes }
}
