<#
.SYNOPSIS
  Looping through selected Azure subscriptions and inventory resources to CSV file . Additionally 
  creates following reports:
    tag report, 
    RBAC roles report, 
    RBAC role assignments reports, 
    private DNS report
.DESCRIPTION
  Loop through Azure subscriptions and collects Azure resources data using Get-AzResource.
  Export collected data to CSV file.
  Can loop all subscriptions or defined set of them (comma separated list).
.PARAMETER $tenantID_param
    Tenant ID within which we looping subscriptons through
.PARAMETER $subID_Param
    "" means - loop through all subscriptions you have access to in the tennant specified
    if comma separated list of subscription ID is specified - will traverse only these subscriptions
    if just one subscription ID is specified - will use only this subscription 
.PARAMETER $pathToSaveFiles
    folder where to save csv files, by default (if not specified) will use same folder the script is run from
.PARAMETER $createAllResourcesReport
    $true or $false
.PARAMETER $createRBACreports
    $true or $false
.PARAMETER $createPrivateDNSreport
    $true or $false
.INPUTS
  None
.OUTPUTS
  <yyyyMMdd-HHmmss>__<tenantID>__allResources.csv" - file containing all resources (with addition of 
  subscriptions and resource groups) from subscriptions selected by $subID_param
  <yyyyMMdd-HHmmss>__<tenantID>__RBAC_role_assignments.csv" - file with RBAC role assignments collected
  <yyyyMMdd-HHmmss>__<tenantID>__RBAC_roles.csv" - file with RBAC roles collected
  <yyyyMMdd-HHmmss>__<tenantID>__tagListJson.json" - list of tags collected trough all subscriptions. 
  Contains all tag names with all values (distinct)
  
.NOTES
  Version:        1.0
  Author:         Aleksandr Reznik (aleksandr@reznik.lt)
  Creation Date:  2021.10.14
  Purpose/Change: Azure resource inventory
  
.EXAMPLE
  open powershell prompt. CD to dirctory where the script is saved.
    .\azure2csv.ps1 -tenantID_Param  "tenant_ID_here" 
    - this will iterate all subscriptions in tenant, as $subID_Param is not specified

    .\azure2csv.ps1 -tenantID_Param  "tenant_ID_here" -subID_Param "sub1_ID,sub2_ID"
    - will process only sub1_ID and sub2_ID subscription

    .\azure2csv.ps1 -tenantID_Param  "tenant_ID_here" -createAllResourcesReport $false 
        -createRBACreports $true -createPrivateDNSreport $false


#>
param(
    [string]$tenantID_Param = "",
    [string]$subID_Param = "",
    [string]$pathToSaveFiles=$PSScriptRoot +"\", #by default equals to currently run script directory
    [bool]$createAllResourcesReport = $true,
    [bool]$createRBACreports = $true,
    [bool]$createPrivateDNSreport = $true 
    )

$global:vNet2privDNS_HT = @{} #nested hashtable - will have vnets on first level, and Priv dns zones linked to it on second level
$global:privDNSZones_PSO = @() #private DNS PSO, will hold all tenant's private DNS zones
$global:RBACroles_PSO = @()
$global:RBACroleAssignments_PSO = @()
$global:allResources_PSO= @()
$global:runTimeStats_PSO = @() 
$multiLineDelimiter = "`n" #if using "`n" - make sure you perform "AutoFit row height" if opened with excel

#list known to me resource types which doesn't have Diagnostic settings to save time by not performing Get-AzDiagnosticSetting on them
$arrayOfResourcetypesWithoutDiagnsettings =@(
        "microsoft.alertsmanagement/actionrules",
        "microsoft.insights/metricalerts",
        "microsoft.sqlvirtualmachine/sqlvirtualmachines",
        "microsoft.compute/snapshots",
        "microsoft.network/applicationsecuritygroups",
        "microsoft.migrate/assessmentprojects",
        "microsoft.migrate/migrateprojects",
        "microsoft.offazure/importsites",
        "microsoft.offazure/serversites",
        "microsoft.network/networkwatchers",
        "microsoft.network/networkwatchers/flowlogs",
        "microsoft.compute/availabilitysets",
        "microsoft.compute/proximityplacementgroups",
        "microsoft.offazure/mastersites",
        "microsoft.offazure/vmwaresites",
        "microsoft.insights/workbooks",
        "microsoft.network/applicationgatewaywebapplicationfirewallpolicies",
        "microsoft.compute/restorepointcollections",
        "microsoft.alertsmanagement/smartdetectoralertrules",
        "microsoft.insights/actiongroups",
        "microsoft.automation/automationaccounts/runbooks",
        "microsoft.compute/virtualmachines/extensions",
        "microsoft.insights/scheduledqueryrules",
        "microsoft.operationsmanagement/solutions",
        "microsoft.portal/dashboards",
        "microsoft.web/connections",
        "microsoft.compute/galleries",
        "microsoft.containerregistry/registries/webhooks",
        "microsoft.devtestlab/schedules",
        "microsoft.insights/activitylogalerts",
        "microsoft.insights/datacollectionrules",
        "microsoft.managedidentity/userassignedidentities",
        "microsoft.migrate/movecollections",
        "microsoft.network/privatednszones/virtualnetworklinks",
        "microsoft.servicefabricmesh/gateways",
        "microsoft.servicefabricmesh/networks",
        "microsoft.network/routetables"
    )

function deleteLastSemicolon( $s ){
    if($s){
        if ($s.substring($s.Length-1,1) -eq " ") {
            $s=$s.Substring(0,$s.Length-1)
            }
        if ($s.substring($s.Length-1,1) -eq ";") {
            $s=$s.Substring(0,$s.Length-1)
            }
        }
        return $s
    }

function processTags($tags){
    $tags.GetEnumerator() | Foreach-Object {
                    
        $tags_STR += $_.Key + "=" + $_.Value + "; " 
        if($globalTagList.count -eq 0){
            $globalTagList.Add($_.Key,@{$_.Value =""})
        }
        else{
            if($globalTagList.ContainsKey($_.Key)){
                if(-not ($globalTagList[$_.Key].ContainsKey($_.Value))){#if key exists, but there was no such value
                    $globalTagList[$_.Key].Add($_.Value,"")
                }
            }
            else{ 
                $globalTagList.Add($_.Key,@{$_.Value = ""})
            }
        }
    }
    return deleteLastSemicolon $tags_STR
}

function process_RBAC_for_Subscription($subscrID, $subscrName, $filePathRoles, $filePathRoleAssignment){
    write-host "Starting collecting RBAC roles"
    $roles = Get-AzRoleDefinition  
    write-host "Subscr id: $subscrID nr of roles: $($roles.count)"

    #$rolesPSO = @()
    foreach ($currRole in $roles){
        $ReportLine = [pscustomobject]@{
            'SubscriptionID'    = $subscrID
            'SubscriptionName'  = $subscrName
            'RoleName'          = $currRole.Name
            'roleID'            = $currRole.Id
            'IsCustom'          = $currRole.IsCustom.ToString()
            'Descr'             = $currRole.Description
            'Actions'           = $currRole.Actions -join "; "
            'NotActions'        = $currRole.NotActions -join "; "
            'DataActions'       = $currRole.DataActions -join "; "
            'NotDataActions'    = $currRole.NotDataActions -join "; "
            'AssignableScopes'  = $currRole.AssignableScopes -join "; "
        }
        $global:RBACroles_PSO += $ReportLine
    }
    write-host "Finished collecting roles"
    

    write-host "Starting collecting role assignments"
    $rolesAssignment = Get-AzRoleAssignment
    write-host "Subscr id: $subscrID nr of role assign: $($rolesAssignment.count)"
    $roleAssignPSO = @()
    foreach ($currRoleAssignment in $rolesAssignment){
        $ReportLine = [pscustomobject]@{
            'SubscriptionID'    = $subscrID
            'SubscriptionName'  = $subscrName
            'RoleAssignmentId'  = $currRoleAssignment.RoleAssignmentId
            'Scope'             = $currRoleAssignment.Scope
            'DisplayName'       = $currRoleAssignment.DisplayName
            'SignInName'        = $currRoleAssignment.SignInName
            'RoleDefinitionName'= $currRoleAssignment.RoleDefinitionName
            'RoleDefinitionId'  = $currRoleAssignment.RoleDefinitionId
            'ObjectId'          = $currRoleAssignment.ObjectId
            'ObjectType'        = $currRoleAssignment.ObjectType
            'CanDelegate'       = $currRoleAssignment.CanDelegate.ToString()
        }
        $global:RBACroleAssignments_PSO += $ReportLine
    }
    write-host "Finished collecting role assignments"
    write-host ""
}

function parseNetworkProfile($Nics){
    #defining struture for output
    $returnValue = "" | Select-Object -Property PrivIPstr,PublicIPstr,vnet,subnet,vNicNSG,subnIDList,subnNSG,vnicASG,vnetDNS,vnicDNS
    $subnIDList = ""
    foreach($nic in $NICs) {
            $CurrNICName = $nic.Id.Split('/') | select -Last 1 
            $NicName = $NicName + $CurrNICName +  "; "
            $netInterf= Get-AzNetworkInterface -ResourceGroupName $resourceLine.ResourceGroupName -Name $CurrNICName
                
    #vNIC ASG        
            $vm_asg = "none"            
            $vnicASG = ""
            if($netInterf.IpConfigurations.ApplicationSecurityGroups){
                foreach($asg in $netInterf.IpConfigurations.ApplicationSecurityGroups){
                    $vm_asg = $asg.id.split('/')|select -last 1
                    $vnicASG = $vnicASG +  $vm_asg+ "; "
                    }
                $vnicASG = $CurrNICName + ":"+ $vm_asg
            }

    #vNIC NSG                
            if($netInterf.NetworkSecurityGroup -ne $null){
                if($netInterf.NetworkSecurityGroup.id -ne ""){
                    $currNSG = $netInterf.NetworkSecurityGroup.id.split('/')|select -last 1
                    $vNicNSG = $vNicNSG  + $CurrNICName+":"+ $currNSG + "; "
                }
            else{
                $vNicNSG ="NA"
                }

            }
    #Subn NSG
            $subnConfig= @()
            if ($netInterf.IpConfigurations -and $netInterf.IpConfigurations.subnet -and $netInterf.IpConfigurations.subnet.id){
                $subnIDList = $subnIDList + $netInterf.IpConfigurations.subnet.id + ";"
                $subnIDArray=$netInterf.IpConfigurations.subnet.id.split('/')
                if ($subnIDArray.count -gt 0){
                        $currVnet = $subnIDArray[$subnIDArray.count-3]
                        $currSubn = $subnIDArray[$subnIDArray.count-1]
                        $vnet=$vnet + $CurrNICName+":" + $currVnet + ";"
                        $subnet=$subnet + $CurrNICName + ":"+ $currSubn+ ";"
                        $vNetRGname= $subnIDArray[$subnIDArray.count-7]
                        $vNetvar = get-azVirtualNetwork -name $CurrVnet -ResourceGroupName $vNetRGname
                        $vnetDNS = $vNetvar.DhcpOptions.DnsServersText -replace "`n",", " -replace "`r",", " -replace "`r`n",", "
                        if (-not $vnetDNS){
                            $vnetDNS = "NA"
                        }
                        $subnConfig=Get-AzVirtualNetworkSubnetConfig -name $CurrSubnet -VirtualNetwork $vNetvar
                        if($subnConfig.NetworkSecurityGroup -ne $null){
                            if($subnConfig.NetworkSecurityGroup.id){
                                $currSubnNSG = $subnConfig.NetworkSecurityGroup.id.split('/')|select -last 1
                                $subnNSG = $subnNSG + $CurrNICName + ":" + $currSubnNSG + "; "
                            }
                        }
                    }
                }
            else{
                $vnet="NA"
                $subnet="NA"
                }
        
    #PublicIPs                
            $currPublicIPstr= ""
            $currPrivIPstr= ""
            $pubIPnames=$netInterf.IpConfigurations.PublicIpAddress
            if (!$pubIPnames) { 
                $currPublicIPstr = 'none' }
            else {
                if($pubIPnames){
                    foreach($PubIP in $pubIPnames){
                        if($PubIP){
                            $PublicIPname=$PubIP.id.Split("/")|select -last 1
                            $PublicIP =Get-AzPublicIpAddress -Name $PublicIPname 
                            $currPublicIPstr =   $currPublicIPstr + $PublicIP.IpAddress + '; '
                        }
                    } #for
                    if($currPublicIPstr -eq ""){
                        $currPublicIPstr="none"
                    }
                } 
                $currPublicIPstr = deleteLastSemicolon $currPublicIPstr
            }

    #PrivIPs
            $privIpNames =  $netInterf.IpConfigurations.PrivateIpAddress
            if (!$privIpNames) { 
                $currPrivIPstr = 'none' 
                }
            else {
                foreach($PrivIP in $privIpNames){
                    $currPrivIPstr =   $currPrivIPstr + $PrivIP+'; '
                    }
                $currPrivIPstr = deleteLastSemicolon $currPrivIPstr 
            }

    #dns            
            if($netInterf.DnsSettingsText){
                $vnicDNS = $netInterf.DnsSettingsText -replace "`n",", " -replace "`r",", " -replace "`r`n",", "
                
            }

            $PrivIPstr=$PrivIPstr+$CurrNICName+":"+$currPrivIPstr+"; "
            $PublicIPstr=$PublicIPstr + $CurrNICName+":"+$currPublicIPstr+"; "
                                
        }
        $returnValue.PrivIPstr= deleteLastSemicolon $PrivIPstr 
        $returnValue.PublicIPstr = deleteLastSemicolon $PublicIPstr
        $returnValue.vnet = deleteLastSemicolon $vnet
        $returnValue.subnet = deleteLastSemicolon $subnet
        $returnValue.vNicNSG = deleteLastSemicolon $vNicNSG 
        $returnValue.subnNSG = deleteLastSemicolon $subnNSG
        $returnValue.vnicASG = deleteLastSemicolon $vnicASG 
        $returnValue.subnIDList = deleteLastSemicolon $subnIDList
        $returnValue.vnetDNS = $vnetDNS
        $returnValue.vnicDNS = $vnicDNS
        return $returnValue
}
function getPrivDNSfromVNETid($vNETid){
    #assuming $global:vNet2privDNS_HT is populated previosly
    $linkedPrivDNSzones=""
    if($global:vNet2privDNS_HT.contains($vNETid)){ #if vnet is linked to some private DNS zones
        foreach($privDNS in $global:vNet2privDNS_HT[$vNETid].Keys){
            $linkedPrivDNSzones += "$($privDNS)`n" 
        }
    }
    return $linkedPrivDNSzones
}


#**********************************************************************************************************************************
#**********************************************************  MAIN BODY   **********************************************************
#**********************************************************************************************************************************

    $CurrDateTimeStr=[DateTime]::Now.ToString("yyyyMMdd-HHmmss")
    $tenantFirst4symbols = $tenantID_Param.Substring(0,4)
    $allResources_reportFilePath            = "$($pathToSaveFiles)$($CurrDateTimeStr)__$($tenantID_Param)__allResources.csv"
    $privateDNSzones_reportFilePath         = "$($pathToSaveFiles)$($CurrDateTimeStr)__$($tenantID_Param)__privateDNSzones_combinedAllSubscr.csv"
    $RBAC_roles_reportFilePath              = "$($pathToSaveFiles)$($CurrDateTimeStr)__$($tenantID_Param)__RBAC_roles.csv"
    $RBAC_roleAssignment_reportFilePath     = "$($pathToSaveFiles)$($CurrDateTimeStr)__$($tenantID_Param)__RBAC_role_assignments.csv"
    $tagList_reportFilePath_json            = "$($pathToSaveFiles)$($CurrDateTimeStr)__$($tenantID_Param)__tagListJson.json"

    $scriptStartTime = Get-Date

    $currentAZContext = Get-AzContext
    if ($currentAZContext.Tenant.id -ne $tenantID_param){
        write-host "This script is not authenticated to needed tenant. Runnng authentication"
        Connect-AzAccount  -TenantId $tenantID_param
    }
    else{
        write-host "This script is already authenticated to needed tenant - reusing authentication."
    }
    
    $subs= @()
    $globalTagList = @{}

#populating $subs variable, this variable will hold all selected subscription list
    $subID_Param = $subID_Param -replace '\s',''  #removing spaces (if any)
    if($subID_Param -eq "") { #empty string means all subscriptions linked to this tenant
        $subs = Get-AzSubscription -TenantId $tenantID_param       #get all subscriptions to variable
        }
    else{
        if ($subID_Param.IndexOf(',') -eq -1){ #if "," not present  - only one subscriprion is specified
            $subs = Get-AzSubscription -TenantId $tenantID_param   -SubscriptionId $subID_Param
        }
        else{ #if several comma separated subscriptions in parameter
            $subsArray = $subID_Param  -split ","
            foreach($subsArrayElement in $subsArray){
                $currTempSub = Get-AzSubscription -TenantId $tenantID_param   -SubscriptionId $subsArrayElement
                $subs += $currTempSub
            }
        }
    }

    $numberOfSubscriptions = $subs.Count    
    $currSubscrNumber = 1

#privateDNS collection
    if($createAllResourcesReport -or $createPrivateDNSreport){
        #processing privDNS for all subscription before main sub loop - to get data to global privateDNS variables
        write-host "Starting process of Private DNS from all selected subscriptions"
        foreach($sub in $subs){#iterating selected subscriptions
            Set-AzContext -subscriptionId $sub.Id -Tenant $tenantID_param
            $currSubPrivDNSs = Get-AzPrivateDnsZone
            foreach($currPrivDNSZone in $currSubPrivDNSs){#iterating priv DNS zones in each subscription
                write-host "  Private DNS zone name: $($currPrivDNSZone.Name)"
                $vNETlinks = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $currPrivDNSZone.ResourceGroupName -ZoneName $currPrivDNSZone.Name
                foreach($currVNETlink in $vNETlinks){ #iterating private dns links in private dns zone
                    write-host "    vNet link inside: $($currVNETlink.VirtualNetworkId)"
                    #adding found vnets to vNet2privDNS_HT hash table - to have data structure searchable by vnetID
                    if($global:vNet2privDNS_HT.contains($currVNETlink.VirtualNetworkId)){
                        if (-not $global:vNet2privDNS_HT[$currVNETlink.VirtualNetworkId].containsKey($currPrivDNSZone.ResourceId)){
                            $global:vNet2privDNS_HT[$currVNETlink.VirtualNetworkId].add($currPrivDNSZone.ResourceId,"" ) #adding new priv dns to current vnet
                        }
                    }
                    else{ #if new vnet found - adding it
                        $global:vNet2privDNS_HT.add($currVNETlink.VirtualNetworkId,@{$currPrivDNSZone.ResourceId = ""})
                    }
                }
                if($createPrivateDNSreport){
                    #filling data to PSO object, will be exported to CSV later
                    $vNETlinksCombinedTXT = ($vNETlinks| select -expand name) -join $multiLineDelimiter
                    $vNETlinksCombinedTXTResIDs = ($vNETlinks| select -expand ResourceId) -join $multiLineDelimiter
                    $linked_VNET_IDs =  ($vNETlinks| select -expand VirtualNetworkId) -join $multiLineDelimiter
                    $ReportLine = [pscustomobject]@{
                        'SubscriptionID'    = $sub.id
                        'SubscriptionName'  = $sub.Name
                        'privateDNSzoneName' = $currPrivDNSZone.Name
                        'privateDNSzoneRG'   = $currPrivDNSZone.ResourceGroupName
                        'NumberOfRecordSets' = $currPrivDNSZone.NumberOfRecordSets
                        'NumberOfVNETLinks'  = $vNETlinks.Length
                        'VNETlinks' =  $vNETlinksCombinedTXT
                        'VNETsLinksIDs' =  $vNETlinksCombinedTXTResIDs
                        'linked_VNET_IDs' = $linked_VNET_IDs
                    }
                    $global:privDNSZones_PSO += $ReportLine
                }
            }
        }
        write-host "Finished process of Private DNS"
        write-host
    }
    
    foreach($currSub in $subs){
        Set-AzContext -subscriptionId $currSub.id -Tenant $tenantID_param
        if (! $?){
            write-host "Error occured during Set-AzContext. Error message: $($error[0].Exception.InnerException.Message)"
            write-host "trying to discconect and reconnect"
            Disconnect-AzAccount
            Connect-AzAccount  -TenantId $tenantID_param -SubscriptionId  $subscriptionID
        }
        write-host "Switching subscription to: $($currSub.id). Subscription nr $($currSubscrNumber) of $numberOfSubscriptions"
        $currSubscrNumber++

        if ($createRBACreports){
                    process_RBAC_for_Subscription $currSub.id $currSub.Name $CSV_RBAC_roles_path $CSV_RBAC_roleAssignment_path
                }

        if ($createAllResourcesReport){
            Write-host "getting resources start at $(Get-Date)"
            $getAzResourceStartTime = Get-Date
            $curr_SUB_Azure_resources = get-AzResource -ExpandProperties | select-object *
            $getAzResourceEndTime = Get-Date
            #$curr_SUB_Azure_resources = get-AzResource -ExpandProperties -Name "w2016" |select-object *
            $curr_SUB_ResourceGroups = Get-AzResourceGroup
            Write-host "done at $(Get-Date)"
            $curr_SUB_Azure_resources_unique = $curr_SUB_Azure_resources|select-object ResourceType -Unique| Select-Object @{Name='SubscriptionName';Expression={$sub.name}},@{Name='SubID';Expression={$sub.id}},*
            
            #adding record for subscription as it does not included in get-Azresource
            $tags_STR=""
            $currTags = Get-AzTag -ResourceId "/subscriptions/$($currSub.Id)"
            if (($null -ne $currTags) -and ($null -ne $currTags.Properties.TagsProperty)){
                $tags_STR = processTags $currTags.Properties.TagsProperty
            }
            $ReportLine = [pscustomobject]@{
                'SubscriptionName'=$currSub.Name
                'SubscriptionId'=$currSub.id
                'ResourceId'= "subscription"
                'Id'= "subscription"
                'Identity'= "subscription"
                'Kind'= "subscription"
                'Location'=  "subscription"
                'ManagedBy'=  "subscription"
                'ResourceName'= "subscription"
                'Name'= "subscription"
                'ExtensionResourceName'= "subscription"
                'ParentResource'= "subscription"
                'PrivateIP'= "subscription"
                'PublicIP'= "subscription"
                'vnetDNS' = "subscription"
                'vnicDNS' = "subscription"
                'linkedPrivDNSzones' = "subscription"
                'vnet'= "subscription"
                'subnet'= "subscription"
                'Plan'=  "subscription"
                'Properties'=  "subscription"
                'ResourceGroupName'=  "subscription"
                'Type'=  "subscription"
                'ResourceType'= "subscription"
                'DiagnosticSettings' = "subscription"
                'ExtensionResourceType'= "subscription"
                'Sku.Name'= "subscription"
                'Sku.Tier'= "subscription"
                'Sku.Size'= "subscription"
                'Sku.Model'= "subscription"
                'Sku.Capacity'= "subscription"
                'Tags'=  $tags_STR
                'CreatedTime'=  "subscription"
                'ChangedTime'= "subscription"
                'ETag'=  "subscription"
            }
            $global:allResources_PSO+=$ReportLine
            
            $resourceLoopStartTime = Get-Date
            $currResourceNumber = 1
            $currSubResourceCount = 0
            if($null -ne $curr_SUB_Azure_resources){
                $currSubResourceCount = $curr_SUB_Azure_resources.count
            }
            foreach($resourceLine in $curr_SUB_Azure_resources){
                write-host "$($currResourceNumber) of $($currSubResourceCount): processing $($resourceLine.ResourceName) Resource type $($resourceLine.ResourceType)" 
                $currResourceNumber++
                if(-not ($arrayOfResourcetypesWithoutDiagnsettings -contains ($resourceLine.ResourceType.ToLower()))){
#if resourcetype has diagnostic settings
                    try{
                        $diagnSettingsTxt = ""
                        $diagnSettingsObj = Get-AzDiagnosticSetting -ResourceId $resourceLine.ResourceId -ErrorAction Stop 3> $null
                        $diagnSettingsTxt = $diagnSettingsObj|ConvertTo-JSON 
                        if ($diagnSettingsTxt -eq ""){
                            $diagnSettingsTxt = "diagnsetting get sucesfull but empty"
                        }
                    }
                    catch {
                        write-host "      Diagn setting get is unsucesfull"
                        $diagnSettingsTxt = "diagnsetting unsucesfull"
                    }
                }

#network profile                
                $PrivIPstr = ""
                $PublicIPstr = ""
                $vnet = ""
                $subnIDList = ""
                $subn = ""
                $vnetDNS  = ""
                $vnicDNS = ""
                if ($resourceLine.properties){
                    if($resourceLine.properties.networkprofile){
                        $NICs = $resourceLine.properties.networkprofile.networkInterfaces
                        if($Nics){
                            $netwProfile = parseNetworkprofile($NICs)
                            $PrivIPstr=$netwProfile.PrivIPstr
                            $PublicIPstr=$netwProfile.PublicIPstr
                            $vnet = $netwProfile.vnet
                            $subnIDList = $netwProfile.subnIDList
                            $subn = $netwProfile.subnet
                            $vnetDNS  = $netwProfile.vnetDNS
                            $vnicDNS = $netwProfile.vnicDNS
                        }
                    }
                }

#private DNS zones
                $linkedPrivDNSzones = ""
                if(($resourceLine.ResourceType -eq "Microsoft.Compute/virtualMachines") -or ($resourceLine.ResourceType -eq "Microsoft.Network/virtualNetworks")){
                    #if vm or vnet - check if private dns is linked
                    if ($resourceLine.ResourceType -eq "Microsoft.Compute/virtualMachines"){
                        $subnIDArray = $subnIDList.split(";")
                        foreach($subnID in $subnIDArray){
                            $subnIDarray =$subnID.Split("/")
                            $vnetArray = $subnIDarray[1..($subnIDarray.count-3)]
                            $vnetID = $vnetArray -join '/'
                            $vnetID = "/" + $vnetID
                            $linkedPrivDNSzones = $linkedPrivDNSzones + (getPrivDNSfromVNETid $vnetID) +";"
                        }
                    }
                    if ($resourceLine.ResourceType -eq "Microsoft.Network/virtualNetworks"){
                        $linkedPrivDNSzones = getPrivDNSfromVNETid($resourceLine.ResourceId)
                    }
                }
                $linkedPrivDNSzones = deleteLastSemicolon $linkedPrivDNSzones
                $tags_STR=""
                if ($resourceLine.Tags -ne $null){
                    $tags_STR = processTags $resourceLine.Tags
                }
                $identity=""
                if($null -ne $resourceLine.Identity){
                    $identity = $resourceLine.Identity.PrincipalId
                }
                $plan = ""
                if($null -ne $resourceLine.plan){
                    $plan = $resourceLine.plan.Name
                }
                $SKUname = ""
                $SKUtier = ""
                $SKUsize = ""
                $SKUfamily = ""
                $SKUmodel= ""
                $SKUcapacity = ""
                if($null -ne $resourceLine.Sku){
                    $SKUname = $resourceLine.Sku.Name
                    $SKUtier = $resourceLine.Sku.Tier
                    $SKUsize = $resourceLine.Sku.Size
                    $SKUfamily = $resourceLine.Sku.Family
                    $SKUmodel= $resourceLine.Sku.Model
                    $SKUcapacity = $resourceLine.Sku.Capacity
                }
                $ReportLine = [pscustomobject]@{
                            'SubscriptionName'=$currSub.Name
                            'SubscriptionId'=$currSub.id
                            'ResourceId'= $resourceLine.ResourceId
                            'Id'=  $resourceLine.Id
                            'Identity'=   $identity
                            'Kind'=  $resourceLine.Kind
                            'Location'=  $resourceLine.Location
                            'ManagedBy'=  $resourceLine.ManagedBy
                            'ResourceName'=  $resourceLine.ResourceName
                            'Name'=  $resourceLine.Name
                            'ExtensionResourceName'=  $resourceLine.ExtensionResourceName
                            'ParentResource'=  $resourceLine.ParentResource
                            'PrivateIP'= $PrivIPstr
                            'PublicIP'=  $PublicIPstr
                            'vnetDNS' = $vnetDNS
                            'vnicDNS' = $vnicDNS
                            'linkedPrivDNSzones' = $linkedPrivDNSzones
                            'vnet'=$vnet
                            'subnet'=$subn
                            'Plan'=  $plan
                            'Properties'=  $resourceLine.Properties
                            'ResourceGroupName'=  $resourceLine.ResourceGroupName
                            'Type'=  $resourceLine.Type
                            'ResourceType'= $resourceLine.ResourceType
                            'DiagnosticSettings' = $diagnSettingsTxt
                            'ExtensionResourceType'= $resourceLine.ExtensionResourceType
                            'Sku.Name'= $SKUname
                            'Sku.Tier'=  $SKUtier
                            'Sku.Size'=  $SKUsize
                            'Sku.Model'= $SKUmodel
                            'Sku.Capacity'= $SKUcapacity
                            'Tags'=     $tags_STR  
                            'CreatedTime'=  $resourceLine.CreatedTime
                            'ChangedTime'=  $resourceLine.ChangedTime
                            'ETag'=  $resourceLine.ETag
                        }
                $global:allResources_PSO+=$ReportLine
                $tags_STR = ""
            }#for each resourceline
            $resourceLoopEndTime = Get-Date
            
            #as resourceGroups doesn't included in get-azResource, processing them additionally
            foreach($currRG in $curr_SUB_ResourceGroups){
                Write-Host "  Starting proceess of $($currRG.ResourceGroupName) resource group"
                $tags_STR=""
                $currTags = Get-AzTag -ResourceId $currRG.ResourceId
                if (($null -ne $currTags) -and ($null -ne $currTags.Properties.TagsProperty)){
                    $tags_STR = processTags $currTags.Properties.TagsProperty
                }
                $ReportLine = [pscustomobject]@{
                        'SubscriptionName'=$currSub.Name
                        'SubscriptionId'=$currSub.id
                        'ResourceId'= $currRG.ResourceId
                        'Id'= "NA"
                        'Identity'= "NA"
                        'Kind'= "NA"
                        'Location'=  $currRG.Location
                        'ManagedBy'=  "NA"
                        'ResourceName'= "NA"
                        'Name'= $currRG.ResourceGroupName
                        'ExtensionResourceName'= "NA"
                        'ParentResource'= "NA"
                        'PrivateIP'= "NA"
                        'PublicIP'= "NA"
                        'vnetDNS' = "NA"
                        'vnicDNS' = "NA"
                        'linkedPrivDNSzones' = "NA"
                        'vnet'= "NA"
                        'subnet'= "NA"
                        'Plan'=  "NA"
                        'Properties'=  "NA"
                        'ResourceGroupName'=  "NA"
                        'Type'=  "NA"
                        'ResourceType'= "NA"
                        'DiagnosticSettings' = "NA"
                        'ExtensionResourceType'= "NA"
                        'Sku.Name'= "NA"
                        'Sku.Tier'= "NA"
                        'Sku.Size'= "NA"
                        'Sku.Model'= "NA"
                        'Sku.Capacity'= "NA"
                        'Tags'=  $tags_STR
                        'CreatedTime'=  "NA"
                        'ChangedTime'= "NA"
                        'ETag'=  "NA"
                        }
                    #$global:allResources_PSO =[Array]$reportLines + $reportLine
                    $global:allResources_PSO+=$ReportLine
                    
                }
                if ($reportLine) {Clear-Variable reportLine}
            
        }

        write-host
        #adding run time stats
        $timeStatsLine = [pscustomobject]@{
            'SubscriptionName'=$currSub.Name
            'SubscriptionId'=$currSub.id
            'numberOfResources' = $currSubResourceCount
            'getAzResourceDuration' = $getAzResourceEndTime - $getAzResourceStartTime
            'resourceLoopDuration' = $resourceLoopEndTime - $resourceLoopStartTime 
        }
        $global:runTimeStats_PSO += $timeStatsLine
    }#end foreach sub

    Write-Host
    $scriptEndTime = Get-Date
    $totalRunTime = $scriptEndTime - $scriptStartTime
    write-host "Total run time: $totalRunTime"

    Write-host "Time stats per subscription:"
    $global:runTimeStats_PSO


    

    if ($createPrivateDNSreport){
        $global:privDNSZones_PSO| Export-Csv $privateDNSzones_reportFilePath -NoTypeInformation -append  -force
        write-host "All subscriptions Combined private DNS zones is written to $($privateDNSzones_reportFilePath)"
        write-host "Take into account: this file can have multiline values in rows."
        write-host "If opened with excel please do: Home -> Format -> AutoFit row height"
        write-host
    }

    if($createRBACreports){
        $global:RBACroles_PSO | export-CSV    $RBAC_roles_reportFilePath -NoTypeInformation -append  -force
        Write-Host "all RBAC roles are written to $RBAC_roles_reportFilePath"
        $global:RBACroleAssignments_PSO | export-CSV  $RBAC_roleAssignment_reportFilePath -NoTypeInformation -append  -force
        Write-Host "all RBAC role assignments are written to $RBAC_roleAssignment_reportFilePath"
        write-host
    }

    if($createAllResourcesReport){
        $globalTagListJson = $globalTagList |ConvertTo-Json -depth 5
        $globalTagListJson | Out-File $tagList_reportFilePath_json  
        write-host "tags stats was written to $tagList_reportFilePath_json file"
        Write-Host

        $global:allResources_PSO|export-CSV  $allResources_reportFilePath -NoTypeInformation -append  -force
        write-host "All resources CSV file created at $($allResources_reportFilePath)"
        write-host "Take into account: this file can have multiline values in rows."
        write-host "If opened with excel please do: Home -> Format -> AutoFit row height"
    }
