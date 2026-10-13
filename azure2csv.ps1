<#PSScriptInfo
.VERSION 2.0.0
.GUID 5439c558-8570-4b37-ac13-9e93b40ab2aa
.AUTHOR Aleksandr Reznik
.COMPANYNAME it4it.solutions
.COPYRIGHT (c) 2021-2026 Aleksandr Reznik. Released under the MIT License.
.TAGS Azure Inventory Migration Assessment ResourceGraph EntraID RBAC Policy CSV Excel Report Governance
.LICENSEURI https://github.com/AleksandrReznik/Azure2csv/blob/main/LICENSE
.PROJECTURI https://github.com/AleksandrReznik/Azure2csv
.ICONURI
.EXTERNALMODULEDEPENDENCIES Az.Accounts
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
2.0.0 - Rewritten on Azure Resource Graph + REST: only Az.Accounts is required, minutes instead of hours.
        61 selectable reports (profiles Quick/Standard/Full/Migration/Security/Governance), Entra ID export,
        Azure Policy, move support, tenant-transfer impact, retirements, orphaned resources, cost,
        optional configuration snapshot (JSON per resource, ARM templates and Bicep, child resources),
        self-contained HTML summary, optional Excel workbook, -Mask for safe sharing. All v1 bugs fixed.
.PRIVATEDATA
#>

#Requires -Version 5.1

<#
.SYNOPSIS
    azure2csv - inventory a whole Azure tenant to CSV/Excel/HTML: resources, networking, RBAC, Azure Policy,
    Entra ID, diagnostic settings, backup, retirements, orphaned resources and migration readiness.

.DESCRIPTION
    azure2csv collects data with Azure Resource Graph and the Azure REST APIs (only the Az.Accounts module is
    required), so even large tenants are inventoried in minutes. Every report is a CSV file that opens in Excel;
    a self-contained summary.html dashboard lists KPIs and findings (retirements, orphaned resources, expiring
    secrets, migration blockers, policy restrictions) and, when the ImportExcel module is installed, all reports
    are also combined into one Excel workbook.

    Choose what to collect with -Profile (Quick, Standard, Full, Migration, Security, Governance) or name the
    reports exactly with -Reports; adjust a profile with -AddReports / -SkipReports. Run -ListReports to see
    every report with its files, speed and required permissions.

    Three opt-in reports write a configuration snapshot: Snapshot (one JSON file per resource and object),
    ArmTemplates (Azure's template export of every resource group as ARM JSON and Bicep) and ChildResources (what
    Resource Graph does not list: storage containers, SQL firewall rules, queues, DNS records...). They document an
    environment and are a starting point for rebuilding it. They are not a backup: no data and no secret values.

    The script only READS from Azure and Entra ID. It never changes anything.

    Required permissions: Reader on the subscriptions (Reader on the root management group for full coverage).
    Entra ID reports use your sign-in: a normal member user can read users, groups and applications; the
    Global Reader role gives full coverage (sign-in activity also needs Entra ID P1 and Reports Reader).
    The Cost report needs Cost Management Reader.

    Written by Aleksandr Reznik - https://it4it.solutions - aleksandr@reznik.lt
    Need help with an Azure migration or a tenant-to-tenant move? Get in touch.

.PARAMETER TenantId
    Tenant (directory) ID to inventory. Default: the tenant of the current Az context (Connect-AzAccount).
    Alias: tenantID_Param (v1 name).

.PARAMETER SubscriptionId
    One or more subscription IDs (array or comma-separated string). Default: all enabled subscriptions you can
    read in the tenant. Alias: subID_Param (v1 name).

.PARAMETER ExcludeSubscriptionId
    Subscription IDs to leave out.

.PARAMETER ManagementGroupId
    Inventory only the subscriptions below this management group (ID/name of the management group).

.PARAMETER OutputPath
    Folder where the run folder azure2csv_<timestamp>_<tenant> is created. Default: current directory.
    In Azure Cloud Shell use ~/clouddrive so the results persist. Alias: pathToSaveFiles (v1 name).

.PARAMETER Profile
    Ready-made report set: Quick, Standard (default), Full, Migration, Security, Governance.

.PARAMETER Reports
    Run exactly these reports and/or groups (the profile is ignored). Use -ListReports to see the names.

.PARAMETER AddReports
    Reports and/or groups to add to the selected profile, e.g. -AddReports Cost, EntraGroupMembers.

.PARAMETER SkipReports
    Reports and/or groups to remove from the selection, e.g. -SkipReports DiagnosticSettings, Entra.

.PARAMETER ListReports
    Print the report catalog (or, together with -Profile/-Reports/-AddReports/-SkipReports, the resolved
    selection) and exit without contacting Azure.

.PARAMETER CostDays
    Number of past days for the Cost report (default 30).

.PARAMETER Mask
    Pseudonymize names, IDs, UPNs, public IPs and tag values in all outputs so the results can be shared safely
    (for example with a consultant). The mapping file needed to re-identify objects is written OUTSIDE the run
    folder and is never included in the zip. Implies -Zip.

.PARAMETER MaskMapPath
    Where to write the private mask mapping file (default: next to the run folder).

.PARAMETER Zip
    Also create azure2csv_<run>.zip of the run folder.

.PARAMETER NoExcel
    Do not create the Excel workbook even if the ImportExcel module is installed.

.PARAMETER NoHtml
    Do not create summary.html.

.PARAMETER MoveSupportFile
    Local copy (or URL) of Microsoft's move-support-resources.md, for offline environments.

.PARAMETER UseDeviceAuthentication
    Use device-code sign-in when a new Connect-AzAccount is needed.

.PARAMETER AdoOrganization
    Azure DevOps organizations to inventory (names or https://dev.azure.com/<name> URLs), in addition to the ones
    billed to the scanned subscriptions (Microsoft.VisualStudio/account resources). Used by the AzureDevOps report.

.PARAMETER AdoRepoMaxSizeMB
    AzureDevOpsRepos report: repositories larger than this (MB, as reported by Azure DevOps) are skipped.
    Default 1024; 0 = no limit.

.PARAMETER AdoPackageVersions
    AzureDevOpsPackages report: Latest (default) downloads the latest version of every package, All downloads every
    version. Only versions published to the feed are downloaded, not the ones cached from upstream sources.

.PARAMETER AdoPackagesMaxMB
    AzureDevOpsPackages report: stop downloading package files after this many MB in total. Default 5120; 0 = no limit.

.PARAMETER AdoPackageMaxSizeMB
    AzureDevOpsPackages report: skip package versions larger than this many MB. The size is asked before the download
    (a small request per file, headers only). Default 0 = no limit.

.PARAMETER AdoPackageTypes
    AzureDevOpsPackages report: the package types to download (NuGet, npm, Maven, PyPI, Cargo, Universal). Default: all.
    The other versions are still listed in packages.csv.

.PARAMETER ArtifactToolPath
    AzureDevOpsPackages report: Microsoft's ArtifactTool for Universal Packages (they have no REST download): the
    executable or its folder. Use it for a copy you trust or when downloads are blocked.
    By default the script gets ArtifactTool from Azure DevOps, the way Azure CLI does, and keeps it under
    <LocalAppData>\azure2csv\ArtifactTool.

.PARAMETER TemplateFormat
    ArmTemplates report: Both (default) exports every resource group as an ARM template (.json) and as Bicep, with two
    calls per resource group; Json or Bicep exports one of them with one call.

.PARAMETER PropertiesMaxChars
    Maximum characters per CSV cell (default 32000, below Excel's cell limit).

.PARAMETER Delimiter
    CSV delimiter: comma (default), semicolon or tab.

.PARAMETER createAllResourcesReport
    v1 compatibility: $false is the same as -SkipReports Resources, Tags.

.PARAMETER createRBACreports
    v1 compatibility: $false is the same as -SkipReports RBAC.

.PARAMETER createPrivateDNSreport
    v1 compatibility: $false is the same as -SkipReports PrivateDNS.

.EXAMPLE
    .\azure2csv.ps1
    Standard profile for all subscriptions of the current tenant.

.EXAMPLE
    .\azure2csv.ps1 -Profile Quick -OutputPath ~/clouddrive -Zip
    Fast first look (Resource Graph based reports only), good for Azure Cloud Shell.

.EXAMPLE
    .\azure2csv.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -Reports RBAC, Policy, ManagementGroups
    Governance reports only.

.EXAMPLE
    .\azure2csv.ps1 -Profile Migration -AddReports Cost -SkipReports Entra
    Migration assessment with cost, without Entra ID.

.EXAMPLE
    .\azure2csv.ps1 -Reports VMs, Disks, Backup -SubscriptionId 11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222

.EXAMPLE
    .\azure2csv.ps1 -Reports AzureDevOps -AdoOrganization contoso, https://dev.azure.com/fabrikam
    Azure DevOps inventory (ADO\ folder) for the organizations billed to the subscriptions plus two named ones.

.EXAMPLE
    pwsh -File .\azure2csv.ps1 -Reports RBAC, Policy -SkipReports Locks
    Started from cmd, a scheduler or with -File, lists work the same way (with or without spaces after the commas).

.EXAMPLE
    .\azure2csv.ps1 -AddReports Snapshot, ArmTemplates, ChildResources
    The Standard profile plus the configuration snapshot: JSON per resource, templates per resource group, child resources.

.EXAMPLE
    .\azure2csv.ps1 -Profile Full -Mask
    Everything, anonymized for sharing; the private mapping file stays next to the run folder.

.EXAMPLE
    .\azure2csv.ps1 -tenantID_Param "tenant_ID_here" -subID_Param "sub1_ID,sub2_ID" -createRBACreports $false
    v1 syntax still works.

.NOTES
    Version : 2.0.0 (2026)
    Author  : Aleksandr Reznik - aleksandr@reznik.lt - https://it4it.solutions
    License : MIT
    History : v1.0 published 2021-10-15, https://it4it.solutions/2021/10/15/inventory-all-azure-resources-to-csv-file/

.LINK
    https://github.com/AleksandrReznik/Azure2csv

.LINK
    https://it4it.solutions
#>
# Report names and package types are checked by the script, not by ValidateSet: a list also arrives as one text
# ("RBAC,Policy") or cut into words (RBAC, Policy) when the script is started with pwsh -File, from cmd or a scheduler.
# Positional binding is off so that such words never land in -TenantId; they are collected in RemainingArguments.
[CmdletBinding(PositionalBinding = $false)]
param(
    [Alias('tenantID_Param')]
    [string] $TenantId,

    [Alias('subID_Param')]
    [string[]] $SubscriptionId,

    [string[]] $ExcludeSubscriptionId,

    [string] $ManagementGroupId,

    [Alias('pathToSaveFiles')]
    [string] $OutputPath,

    [Alias('Profile')]
    [ValidateSet('Quick', 'Standard', 'Full', 'Migration', 'Security', 'Governance')]
    [string] $ReportProfile = 'Standard',

    [ArgumentCompleter({ $a2cWord = [string]$args[2]; @('All', 'Inventory', 'Network', 'Compute', 'Data', 'Operations', 'Governance', 'Entra',
        'Resources', 'Tags', 'DiagnosticSettings', 'MoveSupport', 'CrossReferences', 'Locks', 'Snapshot', 'ArmTemplates', 'ChildResources',
        'VirtualNetworks', 'NetworkSecurity', 'Routing', 'PublicIPs', 'PrivateEndpoints', 'PrivateDNS',
        'NetworkInterfaces', 'LoadBalancers', 'AppGateways', 'Firewalls', 'Gateways', 'DnsRecords',
        'VMs', 'Disks', 'AKS', 'AppService', 'ScaleSets', 'ContainerRegistries', 'ContainerApps', 'Storage', 'SQL', 'KeyVault', 'Databases', 'Messaging',
        'Monitoring', 'Backup', 'Automation', 'AzureCode', 'AppCode', 'Advisor', 'Retirements', 'Orphans', 'Cost', 'AzureDevOps', 'AzureDevOpsPipelines', 'AzureDevOpsRepos', 'AzureDevOpsPackages',
        'ManagementGroups', 'Policy', 'RBAC', 'Defender', 'Lighthouse', 'ResourceProviders', 'TenantTransfer',
        'EntraTenant', 'EntraUsers', 'EntraGroups', 'EntraGroupMembers', 'EntraApps', 'EntraAppAssignments', 'EntraRoles', 'EntraPolicies') | Where-Object { $_ -like ($a2cWord + '*') } })]
    [string[]] $Reports,

    [ArgumentCompleter({ $a2cWord = [string]$args[2]; @('All', 'Inventory', 'Network', 'Compute', 'Data', 'Operations', 'Governance', 'Entra',
        'Resources', 'Tags', 'DiagnosticSettings', 'MoveSupport', 'CrossReferences', 'Locks', 'Snapshot', 'ArmTemplates', 'ChildResources',
        'VirtualNetworks', 'NetworkSecurity', 'Routing', 'PublicIPs', 'PrivateEndpoints', 'PrivateDNS',
        'NetworkInterfaces', 'LoadBalancers', 'AppGateways', 'Firewalls', 'Gateways', 'DnsRecords',
        'VMs', 'Disks', 'AKS', 'AppService', 'ScaleSets', 'ContainerRegistries', 'ContainerApps', 'Storage', 'SQL', 'KeyVault', 'Databases', 'Messaging',
        'Monitoring', 'Backup', 'Automation', 'AzureCode', 'AppCode', 'Advisor', 'Retirements', 'Orphans', 'Cost', 'AzureDevOps', 'AzureDevOpsPipelines', 'AzureDevOpsRepos', 'AzureDevOpsPackages',
        'ManagementGroups', 'Policy', 'RBAC', 'Defender', 'Lighthouse', 'ResourceProviders', 'TenantTransfer',
        'EntraTenant', 'EntraUsers', 'EntraGroups', 'EntraGroupMembers', 'EntraApps', 'EntraAppAssignments', 'EntraRoles', 'EntraPolicies') | Where-Object { $_ -like ($a2cWord + '*') } })]
    [string[]] $AddReports,

    [ArgumentCompleter({ $a2cWord = [string]$args[2]; @('All', 'Inventory', 'Network', 'Compute', 'Data', 'Operations', 'Governance', 'Entra',
        'Resources', 'Tags', 'DiagnosticSettings', 'MoveSupport', 'CrossReferences', 'Locks', 'Snapshot', 'ArmTemplates', 'ChildResources',
        'VirtualNetworks', 'NetworkSecurity', 'Routing', 'PublicIPs', 'PrivateEndpoints', 'PrivateDNS',
        'NetworkInterfaces', 'LoadBalancers', 'AppGateways', 'Firewalls', 'Gateways', 'DnsRecords',
        'VMs', 'Disks', 'AKS', 'AppService', 'ScaleSets', 'ContainerRegistries', 'ContainerApps', 'Storage', 'SQL', 'KeyVault', 'Databases', 'Messaging',
        'Monitoring', 'Backup', 'Automation', 'AzureCode', 'AppCode', 'Advisor', 'Retirements', 'Orphans', 'Cost', 'AzureDevOps', 'AzureDevOpsPipelines', 'AzureDevOpsRepos', 'AzureDevOpsPackages',
        'ManagementGroups', 'Policy', 'RBAC', 'Defender', 'Lighthouse', 'ResourceProviders', 'TenantTransfer',
        'EntraTenant', 'EntraUsers', 'EntraGroups', 'EntraGroupMembers', 'EntraApps', 'EntraAppAssignments', 'EntraRoles', 'EntraPolicies') | Where-Object { $_ -like ($a2cWord + '*') } })]
    [string[]] $SkipReports,

    [switch] $ListReports,

    [ValidateRange(1, 365)]
    [int] $CostDays = 30,

    [switch] $Mask,

    [string] $MaskMapPath,

    [switch] $Zip,

    [switch] $NoExcel,

    [switch] $NoHtml,

    [string] $MoveSupportFile,

    [switch] $UseDeviceAuthentication,

    [Alias('AzureDevOpsOrganization')]
    [string[]] $AdoOrganization,

    [ValidateRange(0, 1048576)]
    [int] $AdoRepoMaxSizeMB = 1024,

    [ValidateSet('Latest', 'All')]
    [string] $AdoPackageVersions = 'Latest',

    [ValidateRange(0, 1048576)]
    [int] $AdoPackagesMaxMB = 5120,

    [ValidateRange(0, 1048576)]
    [int] $AdoPackageMaxSizeMB = 0,

    [ArgumentCompleter({ $a2cWord = [string]$args[2]; @('NuGet', 'npm', 'Maven', 'PyPI', 'Cargo', 'Universal') | Where-Object { $_ -like ($a2cWord + '*') } })]
    [string[]] $AdoPackageTypes,

    [string] $ArtifactToolPath,

    [ValidateSet('Both', 'Json', 'Bicep')]
    [string] $TemplateFormat = 'Both',

    [ValidateRange(1000, 32000)]
    [int] $PropertiesMaxChars = 32000,

    [ValidateSet(',', ';', "`t")]
    [string] $Delimiter = ',',

    # v1 compatibility (deprecated): map onto -SkipReports
    [bool] $createAllResourcesReport = $true,
    [bool] $createRBACreports = $true,
    [bool] $createPrivateDNSreport = $true,

    # words of a list that cmd or pwsh -File passed separately (see Resolve-A2CListArguments)
    [Parameter(ValueFromRemainingArguments = $true, DontShow = $true)]
    [string[]] $RemainingArguments
)

#region ============================== TABLE OF CONTENTS ===============================================
#  1. Constants and catalogs .... report catalog, profiles, datasets, api-versions, branding
#  2. Utilities ................. logging, progress, JSON, dates, IDs, CSV writer, coverage
#  3. Transport ................. Invoke-A2CHttp (single I/O seam), retry, ARM, Resource Graph, Graph
#  4. Context and scope ......... sign-in, endpoints, subscriptions
#  5. Datasets (collectors) ..... one Get-A2CDataset* function per dataset
#  6. Enrichment ................ VM networking, move support, joins
#  7. Report builders ........... one New-A2CReport* function per report, schemas next to them
#  8. Findings .................. rules evaluated on collected data
#  9. Output .................... HTML summary, Excel, mask, zip, <yyyyMMdd-HHmmss>__run.json
# 10. Main ...................... orchestration; skipped when the file is dot-sourced (tests)
#endregion

Set-StrictMode -Version 1.0

#region ============================== 1. CONSTANTS AND CATALOGS ======================================

$script:A2CVersion = '2.0.0'
$script:A2CBrand = [ordered]@{
    Tool    = 'azure2csv'
    Author  = 'Aleksandr Reznik'
    Site    = 'https://it4it.solutions'
    Email   = 'aleksandr@reznik.lt'
    Repo    = 'https://github.com/AleksandrReznik/Azure2csv'
    Post    = 'https://it4it.solutions/2021/10/15/inventory-all-azure-resources-to-csv-file/'
    Tagline = 'Need help with an Azure migration, a tenant-to-tenant move or a landing zone? Get in touch.'
}

$script:A2CApi = @{
    Subscriptions     = '2022-12-01'
    ResourceGraph     = '2024-04-01'
    ResourcesList     = '2021-04-01'
    DiagSettings      = '2021-05-01-preview'
    RoleAssignments   = '2022-04-01'
    RoleDefinitions   = '2022-04-01'
    Locks             = '2020-05-01'
    Policy            = '2023-04-01'
    PolicyExemptions  = '2022-07-01-preview'
    ComputeSkus       = '2021-07-01'
    Automation        = '2023-11-01'
    CostManagement    = '2023-11-01'
    ExportTemplate    = '2025-04-01'
    ExportTemplateOld = '2021-04-01'   # clouds without the current version (JSON only, no Bicep output)
    Providers         = '2021-04-01'
    Pim               = '2020-10-01'
    DenyAssignments   = '2022-04-01'
    # AzureCode export
    Logic             = '2019-05-01'
    DataFactory       = '2018-06-01'
    StreamAnalytics   = '2020-03-01'
    TemplateSpecs     = '2022-02-01'
    DeploymentScripts = '2023-08-01'
    Workbooks         = '2022-04-01'
    Dashboards        = '2020-09-01-preview'
    Sentinel          = '2023-02-01'
    ApiManagement     = '2022-08-01'
}

$script:A2CMoveSupportUrl = 'https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/main/articles/azure-resource-manager/management/move-support-resources.md'

# ---- Report catalog: the single source of truth for -ListReports, profiles, selection and README --------
# Needs = datasets (see $A2CDatasetCatalog). Speed: Fast = Resource Graph, Medium = one call per subscription
# or per page, Slow = one call per resource/object.
$script:A2CReportCatalog = @(
    @{ Name = 'Resources';          Group = 'Inventory';  Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'allResources.csv, subscriptions.csv, resourceTypes.csv'
       Needs = @('Subscriptions', 'Containers', 'Resources', 'ResourceTimes')
       Desc  = 'Every resource plus subscription and resource-group rows (v1 allResources.csv columns first), VM IPs/VNet/DNS' }
    @{ Name = 'Tags';               Group = 'Inventory';  Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'tags.csv, tagList.json'
       Needs = @('Subscriptions', 'Containers', 'Resources')
       Desc  = 'Tag names and values with usage counts (subscriptions, resource groups, resources)' }
    @{ Name = 'DiagnosticSettings'; Group = 'Inventory';  Speed = 'Slow';   OptIn = $false; Perm = 'Reader'
       Files = 'diagnosticSettings.csv (+ DiagStatus/DiagnosticSettings columns)'
       Needs = @('Subscriptions', 'Resources', 'Diagnostics')
       Desc  = 'Diagnostic settings of every resource and the subscription activity log' }
    @{ Name = 'MoveSupport';        Group = 'Inventory';  Speed = 'Fast';   OptIn = $false; Perm = '-'
       Files = 'moveSupport.csv (+ CanMoveTo* columns)'
       Needs = @('Subscriptions', 'Resources', 'MoveData')
       Desc  = 'Can each resource type move to another resource group / subscription / region (Microsoft Learn data)' }
    @{ Name = 'CrossReferences';    Group = 'Inventory';  Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'crossReferences.csv'
       Needs = @('Subscriptions', 'Containers', 'Resources')
       Desc  = 'Resources that reference resources in another resource group or subscription (move blockers)' }
    @{ Name = 'Locks';              Group = 'Inventory';  Speed = 'Medium'; OptIn = $false; Perm = 'Reader'
       Files = 'locks.csv'
       Needs = @('Subscriptions', 'Locks')
       Desc  = 'Management locks (CanNotDelete/ReadOnly) on subscriptions, resource groups and resources' }
    @{ Name = 'Snapshot';           Group = 'Inventory';  Speed = 'Medium'; OptIn = $true;  Perm = 'Reader'
       Files = 'snapshot\ folder: one JSON file per resource and object, snapshot\index.csv'
       Needs = @('Subscriptions', 'Containers', 'Resources', 'GraphTables')
       Desc  = 'Configuration snapshot: every resource as a JSON file with its properties uncut (a CSV cell is cut), firewall rules, DNS records, backup policies and other items of the other Resource Graph tables, plus the role, policy, lock, diagnostic, child resource and Entra objects the selected reports collected - opt-in, never with -Mask' }
    @{ Name = 'ArmTemplates';       Group = 'Inventory';  Speed = 'Slow';   OptIn = $true;  Perm = 'Reader'
       Files = 'templates\ folder: an ARM template (.json) and a Bicep file per resource group, templates\index.csv, templates\notExported.csv'
       Needs = @('Subscriptions', 'Containers', 'Resources', 'ArmTemplates')
       Desc  = 'Azure''s own template export of every resource group as ARM JSON and Bicep (-TemplateFormat), with the list of what Azure could not export. A starting point for infrastructure as code, not a tested deployment - opt-in, never with -Mask' }
    @{ Name = 'ChildResources';     Group = 'Inventory';  Speed = 'Slow';   OptIn = $true;  Perm = 'Reader'
       Files = 'childResources.csv, childResourceTypes.csv, storageContainers.csv, storageFileShares.csv, sqlFirewallRules.csv, keyVaultObjects.csv, serviceBusEntities.csv, eventHubs.csv, privateEndpointDnsZoneGroups.csv (+ the items as JSON in snapshot\ with the Snapshot report)'
       Needs = @('Subscriptions', 'Resources', 'Providers', 'ChildResources')
       Desc  = 'What Resource Graph does not list: storage containers and file shares, SQL firewall rules and retention, Service Bus queues and topics, Event Hubs, Cosmos DB databases and containers, Automation schedules and variables, DNS records, private endpoint DNS zone groups, Key Vault key and secret names (never values) and more - several calls per resource, opt-in' }
    @{ Name = 'VirtualNetworks';    Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'vnets.csv, subnets.csv, peerings.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'VNets (address space, DNS), subnets (NSG, route table, service endpoints, delegations), peerings' }
    @{ Name = 'NetworkSecurity';    Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'nsgs.csv, nsgRules.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'NSGs with associations and every rule (one row per rule, default rules included)' }
    @{ Name = 'Routing';            Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'routeTables.csv, routes.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Route tables with associated subnets and every route' }
    @{ Name = 'PublicIPs';          Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'publicIps.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Public IP addresses, SKU, allocation and what they are attached to' }
    @{ Name = 'PrivateEndpoints';   Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'privateEndpoints.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Private endpoints, target resources, IPs and DNS names' }
    @{ Name = 'PrivateDNS';         Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'privateDnsZones.csv, privateDnsLinks.csv (+ linkedPrivDNSzones column)'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Private DNS zones with their VNet links (v1 report)' }
    @{ Name = 'NetworkInterfaces';  Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'networkInterfaces.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Network interfaces: IP addresses, subnets, NSG, application security groups, load balancer pools, DNS servers, accelerated networking' }
    @{ Name = 'LoadBalancers';      Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'loadBalancers.csv, loadBalancerFrontends.csv, loadBalancerRules.csv, loadBalancerProbes.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Load balancers with their frontends, load-balancing rules and health probes' }
    @{ Name = 'AppGateways';        Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'applicationGateways.csv, applicationGatewayListeners.csv, applicationGatewayRules.csv, applicationGatewayBackends.csv, applicationGatewayBackendSettings.csv, wafPolicies.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Application gateways with listeners, routing rules, backend pools and settings; web application firewall policies' }
    @{ Name = 'Firewalls';          Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'firewalls.csv, firewallPolicies.csv, firewallRules.csv, ipGroups.csv'
       Needs = @('Subscriptions', 'Resources', 'GraphTables')
       Desc  = 'Azure Firewalls, firewall policies with every rule (one row per rule) and IP groups' }
    @{ Name = 'Gateways';           Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'virtualNetworkGateways.csv, localNetworkGateways.csv, connections.csv, expressRouteCircuits.csv, virtualWans.csv, virtualHubs.csv, natGateways.csv, bastionHosts.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'VPN and ExpressRoute gateways, local network gateways, connections, ExpressRoute circuits, Virtual WAN and hubs, NAT gateways, Bastion' }
    @{ Name = 'DnsRecords';         Group = 'Network';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'dnsRecords.csv'
       Needs = @('Subscriptions', 'GraphTables')
       Desc  = 'Every record set of the public and private DNS zones' }
    @{ Name = 'VMs';                Group = 'Compute';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'vms.csv'
       Needs = @('Subscriptions', 'Resources', 'ComputeSkus', 'BackupItems')
       Desc  = 'VM migration profile: size, vCPU/RAM, OS, image, power state, disks, IPs, agents, backup' }
    @{ Name = 'Disks';              Group = 'Compute';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'disks.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Managed disks: SKU, size, state, owner VM, encryption, network access' }
    @{ Name = 'AKS';                Group = 'Compute';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'aks.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'AKS clusters: version, tier, node pools, network, Entra integration' }
    @{ Name = 'AppService';         Group = 'Compute';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'appServicePlans.csv, appServiceApps.csv'
       Needs = @('Subscriptions', 'Resources', 'AppServiceConfig')
       Desc  = 'App Service plans and web/function apps with runtime stacks and TLS settings' }
    @{ Name = 'ScaleSets';          Group = 'Compute';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'vmScaleSets.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Virtual machine scale sets: size, capacity, image, disks, subnets, load balancer pools, upgrade and scale-in policy' }
    @{ Name = 'ContainerRegistries'; Group = 'Compute';   Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'containerRegistries.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Container registries: SKU, admin user, network rules, retention, encryption' }
    @{ Name = 'ContainerApps';      Group = 'Compute';    Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'containerApps.csv, containerAppEnvironments.csv, containerInstances.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Container Apps with ingress, images, scale and secret names; their environments; container instances' }
    @{ Name = 'Storage';            Group = 'Data';       Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'storageAccounts.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Storage accounts: kind, SKU, TLS, public/shared-key access, network rules, encryption' }
    @{ Name = 'SQL';                Group = 'Data';       Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'sqlServers.csv, sqlDatabases.csv, sqlManagedInstances.csv, sqlVirtualMachines.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Azure SQL servers, databases, managed instances and SQL Server on VMs (versions, editions, licensing)' }
    @{ Name = 'KeyVault';           Group = 'Data';       Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'keyVaults.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Key Vaults: RBAC vs access policies, soft delete, purge protection, network access' }
    @{ Name = 'Databases';          Group = 'Data';       Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'cosmosDbAccounts.csv, postgresFlexibleServers.csv, mysqlFlexibleServers.csv, redisCaches.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Cosmos DB accounts, PostgreSQL and MySQL flexible servers, Azure Cache for Redis: version, size, high availability, backup, network access' }
    @{ Name = 'Messaging';          Group = 'Data';       Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'serviceBusNamespaces.csv, eventHubNamespaces.csv, eventGridTopics.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Service Bus and Event Hubs namespaces, Event Grid topics and domains' }
    @{ Name = 'Monitoring';         Group = 'Operations'; Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'logAnalyticsWorkspaces.csv, applicationInsights.csv, alertRules.csv, actionGroups.csv, dataCollectionRules.csv, autoscaleSettings.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Log Analytics workspaces, Application Insights, alert rules with their action groups, data collection rules, autoscale settings' }
    @{ Name = 'Backup';             Group = 'Operations'; Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'backupItems.csv'
       Needs = @('Subscriptions', 'Resources', 'BackupItems')
       Desc  = 'Protected items of Recovery Services and Backup vaults (VMs, SQL, SAP HANA, files, disks, blobs)' }
    @{ Name = 'Automation';         Group = 'Operations'; Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'automationAccounts.csv, runbooks.csv'
       Needs = @('Subscriptions', 'Resources')
       Desc  = 'Automation accounts and runbooks (type, state, runtime)' }
    @{ Name = 'AzureCode';          Group = 'Operations'; Speed = 'Slow';   OptIn = $true;  Perm = 'Reader'
       Files = 'code\ folder, code\index.csv (+ UsesAzureRM/UsesRunAs/ExportedFile columns in runbooks.csv)'
       Needs = @('Subscriptions', 'Resources', 'RunbookContent', 'PolicyDefinitions', 'RoleDefinitions', 'AzureCode')
       Desc  = 'Export code stored in Azure: runbooks, DSC, Logic Apps, Data Factory, Stream Analytics, template specs, deployment scripts, custom policies and roles, workbooks, dashboards, alert queries, Sentinel rules, API Management (may contain secrets - opt-in, never with -Mask)' }
    @{ Name = 'AppCode';            Group = 'Operations'; Speed = 'Slow';   OptIn = $true;  Explicit = $true; Perm = 'Website Contributor (publish rights) on the apps'
       Files = 'code\<subscription>\<resource group>\<app>\wwwroot\ (+ code\index.csv)'
       Needs = @('Subscriptions', 'Resources', 'AppCode')
       Desc  = 'Download the files of every Function App and Web App (Kudu zip of wwwroot) - only when named, needs publish rights, never with -Mask' }
    @{ Name = 'Advisor';            Group = 'Operations'; Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'advisor.csv'
       Needs = @('Subscriptions', 'Advisor')
       Desc  = 'Azure Advisor recommendations (cost, security, reliability, performance, operations)' }
    @{ Name = 'Retirements';        Group = 'Operations'; Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'retirements.csv'
       Needs = @('Subscriptions', 'Resources', 'Advisor')
       Desc  = 'Resources affected by Azure retirements (built-in rules + Advisor), with dates and actions' }
    @{ Name = 'Orphans';            Group = 'Operations'; Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'orphans.csv'
       Needs = @('Subscriptions', 'Containers', 'Resources')
       Desc  = 'Orphaned/unused resources: unattached disks, unused public IPs, NICs, NSGs, empty resource groups...' }
    @{ Name = 'Cost';               Group = 'Operations'; Speed = 'Slow';   OptIn = $true;  Perm = 'Cost Management Reader'
       Files = 'cost.csv (+ Cost column)'
       Needs = @('Subscriptions', 'Resources', 'Cost')
       Desc  = 'Actual cost per resource for the last -CostDays days (Cost Management API)' }
    @{ Name = 'AzureDevOps';        Group = 'Operations'; Speed = 'Slow';   OptIn = $false; Perm = 'Member of the Azure DevOps organization'
       Files = 'ADO\ folder: organizations, projects, repositories, pipelines, service connections, agents, users...'
       Needs = @('Subscriptions', 'Resources', 'AzureDevOps')
       Desc  = 'Azure DevOps organizations billed to the subscriptions or named with -AdoOrganization: projects, Git and TFVC repos, pipelines, service connections, agents, users, feeds and packages, integrations, work items' }
    @{ Name = 'AzureDevOpsPipelines'; Group = 'Operations'; Speed = 'Slow'; OptIn = $true;  Perm = 'Member of the Azure DevOps organization (code read for YAML files)'
       Files = 'ADO\<organization>\<project>\pipelines\ folder (+ ExportedFile columns)'
       Needs = @('Subscriptions', 'Resources', 'AzureDevOps', 'AzureDevOpsPipelines')
       Desc  = 'Export every Azure DevOps pipeline: YAML files from Azure Repos, pipeline and release definitions as JSON (settings included - opt-in, never with -Mask)' }
    @{ Name = 'AzureDevOpsRepos';   Group = 'Operations'; Speed = 'Slow';   OptIn = $true;  Explicit = $true; Perm = 'Member of the Azure DevOps organization (code read)'
       Files = 'ADO\<organization>\<project>\repos\ folder (+ ExportedTo columns)'
       Needs = @('Subscriptions', 'Resources', 'AzureDevOps', 'AzureDevOpsRepos')
       Desc  = 'Export the default branch of every Azure DevOps Git repository and every TFVC branch (files, no history; up to -AdoRepoMaxSizeMB each) - only when named, never with -Mask' }
    @{ Name = 'AzureDevOpsPackages'; Group = 'Operations'; Speed = 'Slow'; OptIn = $true;  Explicit = $true; Perm = 'Reader on the Azure Artifacts feeds'
       Files = 'ADO\<organization>\<project>\feeds\ folder (+ ExportedTo column in packages.csv)'
       Needs = @('Subscriptions', 'Resources', 'AzureDevOps', 'AzureDevOpsPackages')
       Desc  = 'Download the packages published to Azure Artifacts feeds, Universal Packages with Microsoft ArtifactTool (latest versions, or all with -AdoPackageVersions All; up to -AdoPackagesMaxMB) - only when named, never with -Mask' }
    @{ Name = 'ManagementGroups';   Group = 'Governance'; Speed = 'Fast';   OptIn = $false; Perm = 'Reader (management groups)'
       Files = 'managementGroups.csv'
       Needs = @('Subscriptions', 'Containers', 'ManagementGroups')
       Desc  = 'Management group hierarchy and where every subscription sits' }
    @{ Name = 'Policy';             Group = 'Governance'; Speed = 'Medium'; OptIn = $false; Perm = 'Reader'
       Files = 'policyAssignments.csv, policyDefinitions.csv, policySetDefinitions.csv, policyExemptions.csv, policyCompliance.csv'
       Needs = @('Subscriptions', 'PolicyAssignments', 'PolicyExemptions', 'PolicyDefinitions', 'ManagementGroupScope', 'PolicyStates')
       Desc  = 'Azure Policy assignments (incl. inherited and at management groups without subscriptions), definitions, initiatives, exemptions and compliance' }
    @{ Name = 'RBAC';               Group = 'Governance'; Speed = 'Medium'; OptIn = $false; Perm = 'Reader (+ directory read for names)'
       Files = 'RBAC_role_assignments.csv, RBAC_roles.csv, RBAC_eligible_assignments.csv, RBAC_deny_assignments.csv'
       Needs = @('Subscriptions', 'RoleDefinitions', 'RoleAssignments', 'Pim', 'ManagementGroupScope', 'Principals')
       Desc  = 'Role assignments with resolved principals (orphaned, guests), time-bound and eligible assignments (PIM), deny assignments, custom/used role definitions' }
    @{ Name = 'Defender';           Group = 'Governance'; Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'defenderPlans.csv'
       Needs = @('Subscriptions', 'DefenderPlans')
       Desc  = 'Microsoft Defender for Cloud plans of every subscription: tier, sub-plan and extensions' }
    @{ Name = 'Lighthouse';         Group = 'Governance'; Speed = 'Fast';   OptIn = $false; Perm = 'Reader'
       Files = 'lighthouse.csv'
       Needs = @('Subscriptions', 'Lighthouse')
       Desc  = 'Azure Lighthouse: subscriptions and resource groups delegated to another tenant, with the roles given' }
    @{ Name = 'ResourceProviders';  Group = 'Governance'; Speed = 'Medium'; OptIn = $false; Perm = 'Reader'
       Files = 'resourceProviders.csv'
       Needs = @('Subscriptions', 'Providers')
       Desc  = 'Resource providers registered in every subscription, with the number of resources that use them' }
    @{ Name = 'TenantTransfer';     Group = 'Governance'; Speed = 'Medium'; OptIn = $false; Perm = 'Reader'
       Files = 'tenantTransferImpact.csv'
       Needs = @('Subscriptions', 'Resources', 'RoleDefinitions', 'RoleAssignments', 'PolicyAssignments', 'PolicyExemptions', 'PolicyDefinitions')
       Desc  = 'What breaks when a subscription moves to another Entra tenant (identities, Key Vault, RBAC, policy...)' }
    @{ Name = 'EntraTenant';        Group = 'Entra';      Speed = 'Fast';   OptIn = $false; Perm = 'Directory read'
       Files = 'entraTenant.csv, entraDomains.csv, entraLicenses.csv, entraAdministrativeUnits.csv, entraSettings.csv'
       Needs = @('EntraTenant')
       Desc  = 'Tenant information, domains (managed/federated), license SKUs, administrative units and directory settings (group creation, naming, guest access)' }
    @{ Name = 'EntraUsers';         Group = 'Entra';      Speed = 'Medium'; OptIn = $false; Perm = 'Directory read (+ Reports Reader, P1 for sign-ins)'
       Files = 'entraUsers.csv'
       Needs = @('EntraUsers')
       Desc  = 'Users and guests: enabled, sync, licenses, last sign-in (when permitted)' }
    @{ Name = 'EntraGroups';        Group = 'Entra';      Speed = 'Medium'; OptIn = $false; Perm = 'Directory read'
       Files = 'entraGroups.csv'
       Needs = @('EntraGroups')
       Desc  = 'Groups: type, dynamic rules, role-assignable, sync, use in Azure RBAC' }
    @{ Name = 'EntraGroupMembers';  Group = 'Entra';      Speed = 'Slow';   OptIn = $true;  Perm = 'Directory read'
       Files = 'entraGroupMembers.csv'
       Needs = @('EntraGroups', 'EntraGroupMembers')
       Desc  = 'Membership of every group (users, groups, service principals) - one call per group' }
    @{ Name = 'EntraApps';          Group = 'Entra';      Speed = 'Medium'; OptIn = $false; Perm = 'Directory read'
       Files = 'entraApplications.csv, entraServicePrincipals.csv, managedIdentities.csv, credentials.csv, appPermissions.csv'
       Needs = @('EntraApps', 'EntraServicePrincipals', 'EntraAppPermissions')
       Desc  = 'App registrations, enterprise apps, managed identities, secret/certificate expiry, API permissions' }
    @{ Name = 'EntraAppAssignments'; Group = 'Entra';     Speed = 'Slow';   OptIn = $true;  Perm = 'Directory read'
       Files = 'entraAppAssignments.csv'
       Needs = @('EntraServicePrincipals', 'EntraAppAssignments')
       Desc  = 'Users, groups and applications assigned to every enterprise application - one call per application' }
    @{ Name = 'EntraRoles';         Group = 'Entra';      Speed = 'Medium'; OptIn = $false; Perm = 'Directory read'
       Files = 'directoryRoles.csv, entraRoleDefinitions.csv'
       Needs = @('EntraDirectoryRoles')
       Desc  = 'Entra ID directory role assignments (active; PIM eligibility is not readable with the Az token) and custom role definitions' }
    @{ Name = 'EntraPolicies';      Group = 'Entra';      Speed = 'Fast';   OptIn = $false; Perm = 'Microsoft Graph Policy.Read.All (not in the sign-in of a user: a service principal with that permission)'
       Files = 'entraConditionalAccess.csv, entraNamedLocations.csv, entraPolicySettings.csv'
       Needs = @('EntraPolicies')
       Desc  = 'Conditional Access policies, named locations and tenant-wide policies (authorization, security defaults, authentication methods, cross-tenant access) when the sign-in may read them' }
)

$script:A2CReportGroups = @('Inventory', 'Network', 'Compute', 'Data', 'Operations', 'Governance', 'Entra')

$script:A2CProfiles = [ordered]@{
    Quick      = @('Resources', 'Tags', 'MoveSupport', 'CrossReferences', 'VirtualNetworks', 'NetworkSecurity', 'Routing',
                   'PublicIPs', 'PrivateEndpoints', 'PrivateDNS', 'NetworkInterfaces', 'LoadBalancers', 'AppGateways', 'Firewalls', 'Gateways', 'DnsRecords',
                   'VMs', 'Disks', 'AKS', 'AppService', 'ScaleSets', 'ContainerRegistries', 'ContainerApps', 'Storage', 'SQL', 'KeyVault', 'Databases', 'Messaging',
                   'Monitoring', 'Backup', 'Automation', 'Advisor', 'Retirements', 'Orphans', 'ManagementGroups', 'Defender', 'Lighthouse')
    Standard   = @('Resources', 'Tags', 'MoveSupport', 'CrossReferences', 'VirtualNetworks', 'NetworkSecurity', 'Routing',
                   'PublicIPs', 'PrivateEndpoints', 'PrivateDNS', 'NetworkInterfaces', 'LoadBalancers', 'AppGateways', 'Firewalls', 'Gateways', 'DnsRecords',
                   'VMs', 'Disks', 'AKS', 'AppService', 'ScaleSets', 'ContainerRegistries', 'ContainerApps', 'Storage', 'SQL', 'KeyVault', 'Databases', 'Messaging',
                   'Monitoring', 'Backup', 'Automation', 'Advisor', 'Retirements', 'Orphans', 'ManagementGroups',
                   'DiagnosticSettings', 'Locks', 'Policy', 'RBAC', 'Defender', 'Lighthouse', 'ResourceProviders', 'TenantTransfer',
                   'EntraTenant', 'EntraUsers', 'EntraGroups', 'EntraApps', 'EntraRoles', 'EntraPolicies', 'AzureDevOps')
    Full       = @('All')
    Migration  = @('Resources', 'Tags', 'MoveSupport', 'CrossReferences', 'Locks', 'VirtualNetworks', 'NetworkSecurity',
                   'Routing', 'PublicIPs', 'PrivateEndpoints', 'PrivateDNS', 'NetworkInterfaces', 'LoadBalancers', 'AppGateways', 'Firewalls', 'Gateways', 'DnsRecords',
                   'VMs', 'Disks', 'AKS', 'AppService', 'ScaleSets', 'ContainerRegistries', 'ContainerApps', 'Storage',
                   'SQL', 'KeyVault', 'Databases', 'Messaging', 'Monitoring', 'Backup', 'Automation', 'Retirements', 'Orphans', 'ManagementGroups', 'Policy',
                   'RBAC', 'Defender', 'Lighthouse', 'ResourceProviders', 'TenantTransfer', 'EntraApps', 'AzureDevOps')
    Security   = @('RBAC', 'Defender', 'Lighthouse', 'EntraTenant', 'EntraUsers', 'EntraGroups', 'EntraApps', 'EntraRoles', 'EntraPolicies',
                   'NetworkSecurity', 'PublicIPs', 'PrivateEndpoints', 'AppGateways', 'Firewalls', 'Gateways', 'Storage', 'SQL', 'KeyVault', 'DiagnosticSettings', 'Policy',
                   'Advisor', 'Locks', 'Retirements', 'AzureDevOps')
    Governance = @('ManagementGroups', 'Policy', 'RBAC', 'Defender', 'Lighthouse', 'ResourceProviders', 'Locks', 'Tags', 'DiagnosticSettings', 'Advisor')
}

# ---- Datasets: what is collected. Order = execution order (dependencies first). -----------------------
$script:A2CDatasetCatalog = [ordered]@{
    Subscriptions          = @{ Needs = @();                                   Desc = 'Subscriptions in scope (ARM)' }
    Containers             = @{ Needs = @('Subscriptions');                    Desc = 'Subscription tags/management group chain and resource groups (Resource Graph)' }
    ManagementGroups       = @{ Needs = @('Subscriptions');                    Desc = 'Management groups (Resource Graph)' }
    Resources              = @{ Needs = @('Subscriptions');                    Desc = 'All resources with properties (Resource Graph)' }
    GraphTables            = @{ Needs = @('Subscriptions');                    Desc = 'Other Resource Graph tables: DNS records, firewall rules, backup policies, App Service configuration...' }
    ResourceTimes          = @{ Needs = @('Subscriptions');                    Desc = 'Created/changed time of resources (ARM, one call per subscription page)' }
    MoveData               = @{ Needs = @();                                   Desc = 'Microsoft Learn move-support table' }
    Diagnostics            = @{ Needs = @('Subscriptions', 'Resources');       Desc = 'Diagnostic settings (ARM, one call per resource)' }
    Locks                  = @{ Needs = @('Subscriptions');                    Desc = 'Management locks (ARM)' }
    RoleDefinitions        = @{ Needs = @('Subscriptions');                    Desc = 'Role definitions (ARM)' }
    RoleAssignments        = @{ Needs = @('Subscriptions', 'RoleDefinitions'); Desc = 'Role assignments and deny assignments (ARM)' }
    Pim                    = @{ Needs = @('Subscriptions');                    Desc = 'PIM for Azure resources: eligible and time-bound role assignments (ARM)' }
    PolicyAssignments      = @{ Needs = @('Subscriptions');                    Desc = 'Policy assignments incl. inherited (ARM)' }
    PolicyExemptions       = @{ Needs = @('Subscriptions');                    Desc = 'Policy exemptions (ARM)' }
    PolicyDefinitions      = @{ Needs = @('Subscriptions', 'PolicyAssignments'); Desc = 'Custom and assigned policy/initiative definitions (ARM)' }
    ManagementGroupScope   = @{ Needs = @('Subscriptions', 'Containers', 'ManagementGroups'); Desc = 'Role and policy objects at management groups that no subscription in scope is below (ARM)' }
    Principals             = @{ Needs = @('RoleAssignments');                  Desc = 'Names of RBAC principals (Microsoft Graph getByIds)' }
    DefenderPlans          = @{ Needs = @('Subscriptions');                    Desc = 'Defender for Cloud plans (Resource Graph)' }
    Lighthouse             = @{ Needs = @('Subscriptions');                    Desc = 'Azure Lighthouse delegations (Resource Graph)' }
    PolicyStates           = @{ Needs = @('Subscriptions');                    Desc = 'Policy compliance states (Resource Graph)' }
    BackupItems            = @{ Needs = @('Subscriptions');                    Desc = 'Backup protected items (Resource Graph)' }
    AppServiceConfig       = @{ Needs = @('Subscriptions');                    Desc = 'App Service site configuration (Resource Graph)' }
    Advisor                = @{ Needs = @('Subscriptions');                    Desc = 'Advisor recommendations (Resource Graph)' }
    ComputeSkus            = @{ Needs = @('Subscriptions', 'Resources');       Desc = 'VM size capabilities per region (ARM)' }
    RunbookContent         = @{ Needs = @('Subscriptions', 'Resources');       Desc = 'Published runbook code (ARM, one call per runbook)' }
    AzureCode              = @{ Needs = @('Subscriptions', 'Resources', 'PolicyDefinitions', 'RoleDefinitions'); Desc = 'Code and definitions stored in Azure resources (ARM)' }
    AppCode                = @{ Needs = @('Subscriptions', 'Resources');       Desc = 'Function App and Web App files (Kudu)' }
    ArmTemplates           = @{ Needs = @('Subscriptions', 'Containers', 'Resources'); Desc = 'ARM template and Bicep export of every resource group (ARM, one or two calls per resource group)' }
    Providers              = @{ Needs = @('Subscriptions');                    Desc = 'Resource providers: registration state and API versions (ARM, one call per subscription)' }
    ChildResources         = @{ Needs = @('Subscriptions', 'Resources', 'Providers'); Desc = 'Child resources that Resource Graph does not list (ARM, several calls per resource)' }
    Cost                   = @{ Needs = @('Subscriptions');                    Desc = 'Actual cost per resource (Cost Management)' }
    AzureDevOps            = @{ Needs = @('Subscriptions', 'Resources');       Desc = 'Azure DevOps organizations (Azure DevOps REST with the Az sign-in)' }
    AzureDevOpsPipelines   = @{ Needs = @('AzureDevOps');                      Desc = 'Azure DevOps pipeline export (YAML files and definitions)' }
    AzureDevOpsRepos       = @{ Needs = @('AzureDevOps');                      Desc = 'Azure DevOps repository export (default branch files)' }
    AzureDevOpsPackages    = @{ Needs = @('AzureDevOps');                      Desc = 'Azure Artifacts package download (versions published to the feeds)' }
    EntraTenant            = @{ Needs = @();                                   Desc = 'Organization, domains, licenses (Graph)' }
    EntraUsers             = @{ Needs = @();                                   Desc = 'Users (Graph)' }
    EntraGroups            = @{ Needs = @();                                   Desc = 'Groups (Graph)' }
    EntraGroupMembers      = @{ Needs = @('EntraGroups');                      Desc = 'Group members (Graph, one call per group)' }
    EntraApps              = @{ Needs = @();                                   Desc = 'App registrations (Graph)' }
    EntraServicePrincipals = @{ Needs = @();                                   Desc = 'Service principals incl. managed identities (Graph)' }
    EntraAppPermissions    = @{ Needs = @('EntraApps', 'EntraServicePrincipals'); Desc = 'Application permissions and delegated consents (Graph)' }
    EntraAppAssignments    = @{ Needs = @('EntraServicePrincipals');           Desc = 'Users and groups assigned to enterprise applications (Graph, one call per application)' }
    EntraDirectoryRoles    = @{ Needs = @();                                   Desc = 'Directory role definitions and assignments (Graph)' }
    EntraPolicies          = @{ Needs = @();                                   Desc = 'Conditional Access, named locations and tenant-wide policies, when the sign-in may read them (Graph)' }
}

# Resource types known not to support diagnostic settings (seed of the per-type cache; lower case).
$script:A2CDiagUnsupportedSeed = @(
    'microsoft.alertsmanagement/actionrules', 'microsoft.insights/metricalerts', 'microsoft.sqlvirtualmachine/sqlvirtualmachines',
    'microsoft.compute/snapshots', 'microsoft.network/applicationsecuritygroups', 'microsoft.migrate/assessmentprojects',
    'microsoft.migrate/migrateprojects', 'microsoft.offazure/importsites', 'microsoft.offazure/serversites',
    'microsoft.network/networkwatchers', 'microsoft.network/networkwatchers/flowlogs', 'microsoft.compute/availabilitysets',
    'microsoft.compute/proximityplacementgroups', 'microsoft.offazure/mastersites', 'microsoft.offazure/vmwaresites',
    'microsoft.insights/workbooks', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies',
    'microsoft.compute/restorepointcollections', 'microsoft.alertsmanagement/smartdetectoralertrules',
    'microsoft.insights/actiongroups', 'microsoft.automation/automationaccounts/runbooks',
    'microsoft.compute/virtualmachines/extensions', 'microsoft.insights/scheduledqueryrules',
    'microsoft.operationsmanagement/solutions', 'microsoft.portal/dashboards', 'microsoft.web/connections',
    'microsoft.compute/galleries', 'microsoft.containerregistry/registries/webhooks', 'microsoft.devtestlab/schedules',
    'microsoft.insights/activitylogalerts', 'microsoft.insights/datacollectionrules',
    'microsoft.managedidentity/userassignedidentities', 'microsoft.migrate/movecollections',
    'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.servicefabricmesh/gateways',
    'microsoft.servicefabricmesh/networks', 'microsoft.network/routetables', 'microsoft.compute/disks',
    'microsoft.compute/sshpublickeys', 'microsoft.compute/images', 'microsoft.compute/galleries/images',
    'microsoft.compute/galleries/images/versions', 'microsoft.network/privatednszones', 'microsoft.network/dnszones',
    'microsoft.insights/components/analyticsitems', 'microsoft.resources/templatespecs',
    'microsoft.resources/templatespecs/versions', 'microsoft.portal/tenantconfigurations',
    'microsoft.hybridcompute/machines/extensions', 'microsoft.compute/virtualmachinescalesets/extensions',
    'microsoft.maintenance/maintenanceconfigurations', 'microsoft.network/ipgroups', 'microsoft.network/firewallpolicies',
    'microsoft.saas/resources', 'microsoft.web/certificates', 'microsoft.compute/diskencryptionsets'
)

#endregion

#region ============================== 2. UTILITIES ====================================================

$script:A2C = $null   # run context (created by New-A2CRunContext)

function New-A2CRunContext {
    param([Parameter(Mandatory)] $Options)
    $script:A2C = [pscustomobject]@{
        Options        = $Options
        Now            = $Options.Now
        StartedUtc     = [DateTime]::UtcNow
        OutDir         = ''
        RunName        = ''
        RunStamp       = ''                        # yyyyMMdd-HHmmss of the run folder (names the general log)
        TenantId       = ''
        Account        = ''
        Log            = [System.Collections.Generic.List[string]]::new()
        LogPath        = ''                        # general log file, appended line by line once the run folder exists
        Coverage       = [System.Collections.Generic.List[object]]::new()
        Files          = [System.Collections.Generic.List[object]]::new()
        Out            = @{}                       # file name -> List of rows (kept for HTML/Excel/findings)
        Data           = @{}                       # dataset name -> collected data
        DatasetStatus  = @{}                       # dataset name -> Collected/Partial/Skipped/Failed
        Selected       = @()                       # selected report names
        Datasets       = @()                       # datasets to collect
        Stages         = [System.Collections.Generic.List[object]]::new()
        Stats          = @{ arm = 0; arg = 0; graph = 0; web = 0; ado = 0; kudu = 0; Retries = 0; Throttled = 0; SleepSec = 0.0 }
        Tokens         = @{}                       # resource -> access token cache (Get-A2CBearerToken: Azure DevOps, Kudu)
        SignInFailed   = @{}                       # API kind -> sign-in error (later calls of that kind fail at once)
        SignInRetried  = @{}                       # API kind -> $true once the user was asked to sign in again
        Warnings       = [System.Collections.Generic.List[string]]::new()
        Errors         = [System.Collections.Generic.List[string]]::new()
        Findings       = [System.Collections.Generic.List[object]]::new()
        Env            = @{}
        SchemaWarnings = @{}
    }
    $script:A2CPropCache = @{}
    return $script:A2C
}

$script:A2CUtf8Bom = New-Object System.Text.UTF8Encoding $true

function Add-A2CLogLine {
    # Adds a line to the run log (not to the screen). Once the run folder exists every line is also appended to the
    # general log file at once, so the file is complete even when the window closes or the run stops on an error.
    param([string] $Level, [string] $Message)
    if ($null -eq $script:A2C) { return }
    $line = '[{0}] {1,-7} {2}' -f ([DateTime]::Now.ToString('HH:mm:ss')), $Level.ToUpperInvariant(), $Message
    $script:A2C.Log.Add($line)
    if ($script:A2C.LogPath) {
        try { [IO.File]::AppendAllText($script:A2C.LogPath, $line + "`r`n", $script:A2CUtf8Bom) }
        catch {
            $script:A2C.LogPath = ''
            Write-Host ('   WARNING: the general log can no longer be written: ' + $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

function Get-A2CStackText {
    # Where an error happened, for the log: "Func, azure2csv.ps1: line 12 <- Caller, azure2csv.ps1: line 34" (no folders).
    param($ErrorRecord)
    $s = [string]$ErrorRecord.ScriptStackTrace
    if (-not $s) { return '' }
    $frames = @($s -split "`r?`n") | Where-Object { $_ } | Select-Object -First 6 |
        ForEach-Object { ($_ -replace '^at ', '') -replace ', [^,]*[\\/]([^\\/,]+): line', ', $1: line' }
    return (@($frames) -join ' <- ')
}

function Write-A2CLog {
    param(
        [Parameter(Position = 0)] [string] $Message,
        [ValidateSet('Info', 'Step', 'Ok', 'Notice', 'Warn', 'Error', 'Verbose', 'Detail')] [string] $Level = 'Info'
    )
    # Notice = shown in yellow but not counted as a warning (e.g. a retry that may still succeed)
    Add-A2CLogLine -Level $Level -Message $Message
    switch ($Level) {
        'Verbose' { Write-Verbose $Message; return }
        'Step'    { Write-Host ''; Write-Host ('== ' + $Message) -ForegroundColor Cyan }
        'Ok'      { Write-Host ('   ' + $Message) -ForegroundColor Green }
        'Notice'  { Write-Host ('   ' + $Message) -ForegroundColor Yellow }
        'Warn'    { Write-Host ('   WARNING: ' + $Message) -ForegroundColor Yellow; if ($null -ne $script:A2C) { $script:A2C.Warnings.Add($Message) } }
        'Error'   { Write-Host ('   ERROR: ' + $Message) -ForegroundColor Red; if ($null -ne $script:A2C) { $script:A2C.Errors.Add($Message) } }
        'Detail'  { Write-Host ('     ' + $Message) -ForegroundColor DarkGray }
        default   { Write-Host ('   ' + $Message) }
    }
}

function Write-A2CProgress {
    param([string] $Activity, [int] $Current, [int] $Total, [datetime] $Started, [string] $Item = '', [switch] $Completed)
    if ($Completed) { Write-Progress -Activity $Activity -Completed; return }
    if ($Total -le 0) { return }
    $pct = [math]::Min(100, [int](100 * $Current / $Total))
    $status = '{0} of {1}' -f $Current, $Total
    $secs = -1
    if ($Current -gt 0) {
        $elapsed = ([DateTime]::Now - $Started).TotalSeconds
        $secs = [int](($elapsed / $Current) * ($Total - $Current))
    }
    if ($Item) { $status = $status + ' - ' + $Item }
    Write-Progress -Activity $Activity -Status $status -PercentComplete $pct -SecondsRemaining $secs
}

function Start-A2CSleep {
    param([double] $Seconds)
    if ($Seconds -le 0) { return }
    if ($null -ne $script:A2C) { $script:A2C.Stats.SleepSec += $Seconds }
    Start-Sleep -Milliseconds ([int]($Seconds * 1000))
}

function Add-A2CCoverage {
    param(
        [string] $Area,
        [ValidateSet('Collected', 'Partial', 'Skipped', 'Failed', 'NotSelected', 'Info')] [string] $Status,
        [string] $Detail = '',
        [int] $Items = -1
    )
    $script:A2C.Coverage.Add([ordered]@{ Area = $Area; Status = $Status; Items = $(if ($Items -ge 0) { $Items } else { $null }); Detail = $Detail })
}

# ---- JSON --------------------------------------------------------------------------------------------
$script:A2CJss = $null

function ConvertTo-A2CCaseInsensitive {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $Value.Keys) { if ([string]$k -ne '') { $h[[string]$k] = ConvertTo-A2CCaseInsensitive $Value[$k] } }
        return [pscustomobject]$h
    }
    if ($Value -is [System.Collections.IList] -and -not ($Value -is [string])) {
        $l = [System.Collections.Generic.List[object]]::new()
        foreach ($x in $Value) { $l.Add((ConvertTo-A2CCaseInsensitive $x)) }
        return , $l.ToArray()
    }
    return $Value
}

function ConvertFrom-A2CJson {
    param([string] $Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    try {
        return (ConvertFrom-Json -InputObject $Json -ErrorAction Stop)
    }
    catch {
        # Windows PowerShell 5.1 refuses keys that differ only by case; fall back to JavaScriptSerializer.
        if ($PSVersionTable.PSEdition -eq 'Core') { throw }
        if ($null -eq $script:A2CJss) {
            Add-Type -AssemblyName System.Web.Extensions
            $script:A2CJss = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $script:A2CJss.MaxJsonLength = [int]::MaxValue
            $script:A2CJss.RecursionLimit = 1000
        }
        return (ConvertTo-A2CCaseInsensitive ($script:A2CJss.DeserializeObject($Json)))
    }
}

function ConvertTo-A2CJsonString {
    # Compact JSON for CSV cells; never throws.
    param($Value, [int] $Depth = 20)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    try { return (ConvertTo-Json -InputObject $Value -Depth $Depth -Compress) } catch { return [string]$Value }
}

function ConvertTo-A2CJsonLiteral {
    # JSON string literal (with quotes) for building request bodies.
    param([string] $Value)
    if ($null -eq $Value) { return 'null' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '"'  { [void]$sb.Append('\"') }
            '\'  { [void]$sb.Append('\\') }
            "`n" { [void]$sb.Append('\n') }
            "`r" { [void]$sb.Append('\r') }
            "`t" { [void]$sb.Append('\t') }
            default {
                if ([int]$ch -lt 32) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) } else { [void]$sb.Append($ch) }
            }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# ---- Secret-like values --------------------------------------------------------------------------------
# Azure returns a few secrets to a reader inside the properties of a resource (ExpressRoute authorization keys, the
# shared key of some connections). Their values are replaced wherever properties are stored; the names stay.
$script:A2CSecretMark = '(not exported)'
$script:A2CSecretNames = 'authorizationKey|sharedKey|radiusServerSecret|adminPassword|administratorLoginPassword|password|primaryKey|secondaryKey|' +
    'primaryMasterKey|secondaryMasterKey|primaryReadonlyMasterKey|secondaryReadonlyMasterKey|primaryConnectionString|secondaryConnectionString|' +
    'primarySharedKey|secondarySharedKey|clientSecret|storageAccountAccessKey|storageAccountKey|accountKey|accessKey|sasToken|sasUrl|sasUri'
$script:A2CSecretJsonRx = New-Object System.Text.RegularExpressions.Regex(('"(' + $script:A2CSecretNames + ')"(\s*:\s*)"((?:[^"\\]|\\.)+)"'), ([System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled'))
$script:A2CSecretBicepRx = New-Object System.Text.RegularExpressions.Regex(('(?m)^(\s*(?:' + $script:A2CSecretNames + ')\s*:\s*)''((?:[^''\\]|\\.)+)'''), ([System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled'))

function Protect-A2CSecretText {
    # JSON text (or Bicep) with the values of well-known secret properties replaced. -Template: template expressions
    # ("[parameters('x')]") are kept, they hold no value.
    param([string] $Text, [switch] $Bicep, [switch] $Template)
    if (-not $Text) { return $Text }
    $rx = $script:A2CSecretJsonRx
    if ($Bicep) { $rx = $script:A2CSecretBicepRx }
    if (-not $rx.IsMatch($Text)) { return $Text }
    $keepExpressions = [bool]$Template
    $isBicep = [bool]$Bicep
    return $rx.Replace($Text, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $v = $m.Groups[$m.Groups.Count - 1].Value
            if ($v -eq $script:A2CSecretMark -or ($keepExpressions -and $v.StartsWith('[') -and -not $v.StartsWith('[['))) { return $m.Value }
            if ($null -ne $script:A2C) { $script:A2C.Stats['SecretsHidden'] = [int]$script:A2C.Stats['SecretsHidden'] + 1 }
            if ($isBicep) { return ($m.Groups[1].Value + "'" + $script:A2CSecretMark + "'") }
            return ('"' + $m.Groups[1].Value + '"' + $m.Groups[2].Value + '"' + $script:A2CSecretMark + '"')
        })
}

function Get-A2CProps {
    # Parsed "properties" of a Resource Graph row (parsed once, cached).
    param($Row)
    if ($null -eq $Row) { return $null }
    $key = [string]$Row.id
    if ($script:A2CPropCache.ContainsKey($key)) { return $script:A2CPropCache[$key] }
    $p = $null
    $json = $Row.propertiesJson
    if ($json) { try { $p = ConvertFrom-A2CJson $json } catch { $p = $null } }
    if ($null -eq $p) { $p = New-Object psobject }
    $script:A2CPropCache[$key] = $p
    return $p
}

# ---- Dates -------------------------------------------------------------------------------------------
function ConvertTo-A2CUtc {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $s = [string]$Value
    if ($s -eq '') { return $null }
    $dto = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) {
        return $dto.UtcDateTime
    }
    return $null
}

function Format-A2CDate {
    param($Value, [switch] $DateOnly)
    if ($null -eq $Value) { return '' }
    $dt = ConvertTo-A2CUtc $Value
    if ($null -eq $dt) { return [string]$Value }
    if ($DateOnly) { return $dt.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
    return $dt.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-A2CDaysUntil {
    param($Value)
    $dt = ConvertTo-A2CUtc $Value
    if ($null -eq $dt) { return $null }
    return [int][math]::Floor(($dt - $script:A2C.Now).TotalDays)
}

function ConvertTo-A2CSeconds {
    param($Value)
    if ($null -eq $Value) { return 0 }
    $s = ([string]$Value).Trim()
    $d = 0.0
    if ([double]::TryParse($s, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    $ts = [TimeSpan]::Zero
    if ([TimeSpan]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [ref]$ts)) { return $ts.TotalSeconds }
    $dt = ConvertTo-A2CUtc $s
    if ($null -ne $dt) { return [math]::Max(0, ($dt - [DateTime]::UtcNow).TotalSeconds) }
    return 0
}

# ---- Strings, lists and ARM IDs ----------------------------------------------------------------------
function Join-A2C {
    param($Items, [string] $Separator = '; ')
    if ($null -eq $Items) { return '' }
    if ($Items -is [string]) { return $Items }
    $l = [System.Collections.Generic.List[string]]::new()
    foreach ($i in $Items) {
        if ($null -eq $i) { continue }
        $s = [string]$i
        if ($s -ne '') { $l.Add($s) }
    }
    return [string]::Join($Separator, $l)
}

function Get-A2CUnique {
    # Distinct non-empty strings, first occurrence order, case-insensitive.
    param($Items)
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $l = [System.Collections.Generic.List[string]]::new()
    foreach ($i in $Items) {
        if ($null -eq $i) { continue }
        $s = [string]$i
        if ($s -ne '' -and $seen.Add($s)) { $l.Add($s) }
    }
    return , $l.ToArray()
}

function Get-A2CCount {
    param($Items)
    if ($null -eq $Items) { return 0 }
    if ($Items -is [string]) { return 1 }
    return @($Items).Count
}

function Get-A2CNameFromId {
    param([string] $Id)
    if (-not $Id) { return '' }
    $p = $Id.TrimEnd('/').Split('/')
    return $p[$p.Count - 1]
}

function Get-A2CIdSegment {
    # Value that follows the given key segment in an ARM ID, e.g. -After resourceGroups.
    param([string] $Id, [string] $After)
    if (-not $Id) { return '' }
    $p = $Id.Trim('/').Split('/')
    for ($i = 0; $i -lt $p.Count - 1; $i++) { if ($p[$i] -ieq $After) { return $p[$i + 1] } }
    return ''
}

function Get-A2CSubIdFromId { param([string] $Id) return (Get-A2CIdSegment -Id $Id -After 'subscriptions').ToLowerInvariant() }
function Get-A2CRgFromId { param([string] $Id) return (Get-A2CIdSegment -Id $Id -After 'resourceGroups') }

function Get-A2CTopLevelId {
    # /subscriptions/s/resourceGroups/r/providers/ns/type/name[/child/...] -> the top-level resource ID.
    param([string] $Id)
    if (-not $Id) { return '' }
    $p = $Id.Trim('/').Split('/')
    for ($i = 0; $i -lt $p.Count; $i++) {
        if ($p[$i] -ieq 'providers' -and ($i + 3) -lt $p.Count) {
            return '/' + [string]::Join('/', $p[0..($i + 3)])
        }
    }
    return '/' + $Id.Trim('/')
}

function Get-A2CTypeFromId {
    # Resource type (namespace/type[/childType...]) of an ARM ID, lower case.
    param([string] $Id)
    if (-not $Id) { return '' }
    $p = $Id.Trim('/').Split('/')
    $last = -1
    for ($i = 0; $i -lt $p.Count; $i++) { if ($p[$i] -ieq 'providers') { $last = $i } }
    if ($last -lt 0) {
        if ($p.Count -eq 2 -and $p[0] -ieq 'subscriptions') { return 'microsoft.resources/subscriptions' }
        if ($p.Count -eq 4 -and $p[2] -ieq 'resourceGroups') { return 'microsoft.resources/subscriptions/resourcegroups' }
        return ''
    }
    $ns = $p[$last + 1]
    $types = [System.Collections.Generic.List[string]]::new()
    for ($j = $last + 2; $j -lt $p.Count; $j += 2) { $types.Add($p[$j]) }
    return ($ns + '/' + [string]::Join('/', $types)).ToLowerInvariant()
}

function Get-A2CScopeType {
    param([string] $Scope)
    if (-not $Scope -or $Scope -eq '/') { return 'Root' }
    if ($Scope -match '(?i)^/providers/Microsoft\.Management/managementGroups/[^/]+$') { return 'ManagementGroup' }
    if ($Scope -match '(?i)^/subscriptions/[^/]+$') { return 'Subscription' }
    if ($Scope -match '(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 'ResourceGroup' }
    if ($Scope -match '(?i)^/subscriptions/') { return 'Resource' }
    return 'Other'
}

function Get-A2CSubName {
    param([string] $SubscriptionId)
    if (-not $SubscriptionId) { return '' }
    $s = $script:A2C.Data['SubById']
    if ($null -ne $s) { $x = $s[$SubscriptionId.ToLowerInvariant()]; if ($null -ne $x) { return $x.Name } }
    return ''
}

function ConvertTo-A2CTagString {
    param($Tags)
    if ($null -eq $Tags) { return '' }
    $l = [System.Collections.Generic.List[string]]::new()
    if ($Tags -is [System.Collections.IDictionary]) {
        foreach ($k in $Tags.Keys) { $l.Add(('{0}={1}' -f $k, $Tags[$k])) }
    }
    else {
        foreach ($p in $Tags.PSObject.Properties) { $l.Add(('{0}={1}' -f $p.Name, $p.Value)) }
    }
    return [string]::Join('; ', $l)
}

function Get-A2CTagPairs {
    # Tags as a list of @(key, value) pairs.
    param($Tags)
    $l = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Tags) { return , $l }
    if ($Tags -is [System.Collections.IDictionary]) { foreach ($k in $Tags.Keys) { $l.Add(@([string]$k, [string]$Tags[$k])) } }
    else { foreach ($p in $Tags.PSObject.Properties) { $l.Add(@([string]$p.Name, [string]$p.Value)) } }
    return , $l
}

function Test-A2CPrivateIp {
    param([string] $Ip)
    if (-not $Ip) { return $false }
    $a = $Ip.Split('/')[0]
    if ($a -match '^10\.' -or $a -match '^192\.168\.' -or $a -match '^172\.(1[6-9]|2[0-9]|3[01])\.' -or
        $a -match '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.' -or $a -match '^169\.254\.' -or $a -match '^127\.' -or
        $a -match '(?i)^f[cd][0-9a-f]{2}:' -or $a -match '(?i)^fe80:') { return $true }
    return $false
}

# ---- Report rows and CSV writer ----------------------------------------------------------------------
$script:A2CSchemas = @{}

function Register-A2CSchema {
    # Spec: space separated Column:kind tokens; kind drives -Mask (default p = keep).
    param([string] $File, [string] $Spec)
    $cols = [System.Collections.Generic.List[object]]::new()
    foreach ($tok in ($Spec -split '\s+')) {
        if (-not $tok) { continue }
        $i = $tok.LastIndexOf(':')
        if ($i -gt 0) { $n = $tok.Substring(0, $i); $k = $tok.Substring($i + 1) } else { $n = $tok; $k = 'p' }
        $cols.Add([pscustomobject]@{ Name = $n; Kind = $k })
    }
    $script:A2CSchemas[$File] = $cols
}

function Format-A2CCell {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { if ($Value) { return 'True' } else { return 'False' } }
    if ($Value -is [DateTime] -or $Value -is [DateTimeOffset]) { return (Format-A2CDate $Value) }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject]) {
        return (ConvertTo-A2CJsonString $Value)
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $l = [System.Collections.Generic.List[string]]::new()
        foreach ($x in $Value) { $l.Add((Format-A2CCell $x)) }
        return [string]::Join('; ', $l)
    }
    if ($Value -is [IFormattable]) { return $Value.ToString($null, [Globalization.CultureInfo]::InvariantCulture) }
    return [string]$Value
}

function ConvertTo-A2CCsvField {
    param([string] $Text, [int] $Max)
    $s = $Text
    if ($null -eq $s) { $s = '' }
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max - 20) + '...[truncated]' }
    if ($s.IndexOf([char]10) -ge 0 -or $s.IndexOf([char]13) -ge 0) { $s = ($s -replace "`r`n|`r|`n", ' ') }
    if ($s.Length -gt 0) {
        $c = $s[0]
        if ($c -eq '=' -or $c -eq '+' -or $c -eq '-' -or $c -eq '@' -or $c -eq [char]9) {
            $d = 0.0
            if (-not [double]::TryParse($s, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $s = "'" + $s }
        }
    }
    return '"' + $s.Replace('"', '""') + '"'
}

function Add-A2CRows {
    # Store report rows (ordered dictionaries) for writing and later use (HTML/Excel/findings).
    param([string] $File, $Rows)
    if (-not $script:A2C.Out.ContainsKey($File)) { $script:A2C.Out[$File] = [System.Collections.Generic.List[object]]::new() }
    foreach ($r in $Rows) { if ($null -ne $r) { $script:A2C.Out[$File].Add($r) } }
}

$script:A2CSplitBy = @{}   # file -> column: one file per value, in a subfolder named after it (ADO/<organization>/projects.csv)

function Get-A2CSafePathSegment {
    # A file or folder name that cannot escape its folder ("..") and is valid on Windows.
    param([string] $Name)
    $s = (Get-A2CSafeFileName $Name).TrimEnd('.', ' ')
    if (-not $s -or $s -match '^\.+$') { return '_' }
    return $s
}

function Get-A2CSplitFolders {
    # Folders that get every split file (header only when empty): each collected Azure DevOps organization.
    param([string] $File)
    if ($File -notlike 'ADO/*') { return @() }
    return @((Get-A2COutputRows 'ADO/organizations.csv') | Where-Object { $_['Status'] -eq 'Collected' } | ForEach-Object { [string]$_['Organization'] })
}

function Save-A2CCsv {
    # Writes a registered report file (UTF-8 with BOM, all fields quoted, formula-injection guard). A file in
    # $A2CSplitBy is written once per value of its column, into a subfolder named after the (masked) value.
    param([string] $File)
    $schema = $script:A2CSchemas[$File]
    if ($null -eq $schema) { throw "No schema registered for $File" }
    $rows = Get-A2COutputRows $File
    $by = $script:A2CSplitBy[$File]
    if (-not $by) { Write-A2CCsvFile -File $File -Schema $schema -Rows $rows -SchemaKey $File; return }
    $groups = [ordered]@{}
    foreach ($n in (Get-A2CSplitFolders $File)) { $groups[$n] = [System.Collections.Generic.List[object]]::new() }
    foreach ($row in $rows) {
        $k = [string]$row[$by]
        if (-not $groups.Contains($k)) { $groups[$k] = [System.Collections.Generic.List[object]]::new() }
        $groups[$k].Add($row)
    }
    $dir = [IO.Path]::GetDirectoryName($File)
    $leaf = [IO.Path]::GetFileName($File)
    foreach ($k in $groups.Keys) {
        Write-A2CCsvFile -File ($dir + '/' + (Get-A2CSafePathSegment $k) + '/' + $leaf) -Schema $schema -Rows $groups[$k] -SchemaKey $File
    }
}

function Write-A2CCsvFile {
    param([string] $File, $Schema, $Rows, [string] $SchemaKey)
    $schema = $Schema
    $rows = $Rows
    $max = [int]$script:A2C.Options.PropertiesMaxChars
    $sep = [string]$script:A2C.Options.Delimiter
    $path = [IO.Path]::Combine($script:A2C.OutDir, $File)
    $dir = [IO.Path]::GetDirectoryName($path)
    if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }   # e.g. ADO/
    $colNames = @($schema | ForEach-Object { $_.Name })
    $known = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $colNames) { [void]$known.Add($n) }
    $sw = New-Object System.IO.StreamWriter($path, $false, (New-Object System.Text.UTF8Encoding $true))
    try {
        $sw.Write([string]::Join($sep, @($colNames | ForEach-Object { ConvertTo-A2CCsvField -Text $_ -Max $max })))
        $sw.Write("`r`n")
        foreach ($row in $rows) {
            $fields = [System.Collections.Generic.List[string]]::new()
            foreach ($n in $colNames) {
                $v = $null
                if ($row.Contains($n)) { $v = $row[$n] }
                $fields.Add((ConvertTo-A2CCsvField -Text (Format-A2CCell $v) -Max $max))
            }
            $sw.Write([string]::Join($sep, $fields))
            $sw.Write("`r`n")
            if (-not $script:A2C.SchemaWarnings.ContainsKey($SchemaKey)) {
                foreach ($k in $row.Keys) {
                    if (-not $known.Contains([string]$k)) {
                        $script:A2C.SchemaWarnings[$SchemaKey] = $true
                        Write-A2CLog -Level Verbose ('Schema of {0} has no column "{1}"' -f $SchemaKey, $k)
                        break
                    }
                }
            }
        }
    }
    finally { $sw.Dispose() }
    $script:A2C.Files.Add([pscustomobject]@{ File = $File; Rows = $rows.Count; Path = $path })
}

function Save-A2CText {
    param([string] $File, [string] $Text, [switch] $NoBom)
    $path = [IO.Path]::Combine($script:A2C.OutDir, $File)
    $enc = New-Object System.Text.UTF8Encoding (-not $NoBom)
    [IO.File]::WriteAllText($path, $Text, $enc)
    return $path
}

function Get-A2CRawRows {
    param([string] $File)
    $r = $script:A2C.Out[$File]
    if ($null -eq $r) { return , ([System.Collections.Generic.List[object]]::new()) }
    return , $r
}

function Get-A2CRows {
    # Report rows; while findings are evaluated under -Mask the masked rows are returned so details never leak names.
    param([string] $File)
    if ($script:A2C.Data['FindingsMasked']) { return , (Get-A2COutputRows $File) }
    return , (Get-A2CRawRows $File)
}

function Test-A2CSelected {
    param([string] $Report)
    return ($script:A2C.Selected -contains $Report)
}

function Test-A2CDataset {
    # True when a dataset was collected (fully or partially).
    param([string] $Name)
    $s = $script:A2C.DatasetStatus[$Name]
    return ($s -eq 'Collected' -or $s -eq 'Partial')
}

#endregion

#region ============================== 3. TRANSPORT =====================================================

$script:A2CArmBase = 'https://management.azure.com'
$script:A2CGraphBase = 'https://graph.microsoft.com'

function Invoke-A2CHttp {
    # The single network seam (tests replace this function). Never throws.
    # Returns @{ StatusCode = int (0 = transport error); Content = string; Headers = case-insensitive hashtable }
    # -OutFile (Azure DevOps downloads): the response body is written to that file instead of returned as Content
    param([string] $Method = 'GET', [Parameter(Mandatory)] [string] $Uri, [string] $Body, [string] $Kind = 'arm', [string] $OutFile)
    if ($Kind -eq 'web') {
        # public downloads (move-support table, ArtifactTool zip): never with a token
        try {
            if ($OutFile) {
                Invoke-WebRequest -Uri $Uri -Method $Method -UseBasicParsing -TimeoutSec 3600 -OutFile $OutFile -ErrorAction Stop
                return @{ StatusCode = 200; Content = ''; Headers = @{} }
            }
            $r = Invoke-WebRequest -Uri $Uri -Method $Method -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
            $c = $r.Content
            if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c) }   # e.g. a blob served as application/octet-stream
            return @{ StatusCode = [int]$r.StatusCode; Content = [string]$c; Headers = @{} }
        }
        catch {
            $code = 0
            try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
            return @{ StatusCode = $code; Content = [string]$_.Exception.Message; Headers = @{} }
        }
    }
    if ($Kind -eq 'ado') { return (Invoke-A2CTokenHttp -Resource $script:A2CAdoResource -AzureDevOps -Method $Method -Uri $Uri -Body $Body -OutFile $OutFile) }
    if ($Kind -eq 'kudu') { return (Invoke-A2CTokenHttp -Resource ($script:A2CArmBase + '/') -Method $Method -Uri $Uri -Body $Body -OutFile $OutFile) }
    $p = @{ Method = $Method; Uri = $Uri; ErrorAction = 'Stop' }
    if ($Body) { $p['Payload'] = $Body }
    try { $r = Invoke-AzRestMethod @p }
    catch { return @{ StatusCode = 0; Content = [string]$_.Exception.Message; Headers = @{} } }
    $h = @{}
    try { foreach ($kv in $r.Headers) { $h[[string]$kv.Key] = [string]::Join(',', @($kv.Value)) } } catch { Write-Verbose ('Response headers not readable: ' + $_.Exception.Message) }
    return @{ StatusCode = [int]$r.StatusCode; Content = [string]$r.Content; Headers = $h }
}

$script:A2CAdoResource = '499b84ac-1321-427f-aa17-267ca6975798'   # Azure DevOps (Entra resource / app ID)

function Get-A2CBearerToken {
    # Entra access token for a resource (Azure DevOps, Azure Resource Manager for Kudu) from the Az sign-in - no PAT
    # or publishing password - cached until 5 minutes before it expires.
    param([string] $Resource)
    $c = $script:A2C.Tokens[$Resource]
    if ($null -ne $c -and $c.ExpiresOn -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) { return $c.Token }
    $p = @{ ResourceUrl = $Resource; ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    if ($script:A2C.TenantId) { $p['TenantId'] = $script:A2C.TenantId }
    if ((Get-Command Get-AzAccessToken).Parameters.ContainsKey('AsSecureString')) { $p['AsSecureString'] = $true }
    $t = Get-AzAccessToken @p
    $token = $t.Token
    if ($token -is [securestring]) { $token = [System.Net.NetworkCredential]::new('', $token).Password }
    $expires = [DateTimeOffset]::UtcNow.AddMinutes(30)
    if ($null -ne $t.ExpiresOn) { $expires = [DateTimeOffset]$t.ExpiresOn }
    $script:A2C.Tokens[$Resource] = [pscustomobject]@{ Token = [string]$token; ExpiresOn = $expires }
    return [string]$token
}

function Test-A2CHtmlFile {
    # A downloaded file that is an HTML page (a sign-in page instead of the zip or package).
    param([string] $Path)
    try {
        $fs = [IO.File]::OpenRead($Path)
        try { $buf = New-Object byte[] 256; $n = $fs.Read($buf, 0, 256) } finally { $fs.Dispose() }
        return ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -match '^(?i)\s*<(!DOCTYPE html|html)')
    }
    catch { return $false }
}

function Invoke-A2CTokenHttp {
    # A request with an Entra bearer token (Azure DevOps, Kudu); part of the network seam (only Invoke-A2CHttp calls
    # it). -OutFile streams the body to a file (zip downloads). Never throws.
    param([string] $Resource, [switch] $AzureDevOps, [string] $Method, [string] $Uri, [string] $Body, [string] $OutFile)
    try { $token = Get-A2CBearerToken $Resource }
    catch { return @{ StatusCode = 0; Content = [string]$_.Exception.Message; Headers = @{} } }
    $p = @{ Uri = $Uri; Method = $Method; UseBasicParsing = $true; TimeoutSec = 120; ErrorAction = 'Stop'
        Headers = @{ Authorization = 'Bearer ' + $token; Accept = 'application/json' } }
    # Azure DevOps: without X-TFS-FedAuthRedirect a refused token is redirected to a sign-in page instead of HTTP 401
    if ($AzureDevOps) { $p['Headers']['X-TFS-FedAuthRedirect'] = 'Suppress' }
    if ($Body) { $p['Body'] = $Body; $p['ContentType'] = 'application/json' }
    if ($OutFile) {
        # a download (zip, package file): streamed to disk, so it never passes through a string. Package downloads can
        # redirect to blob storage; Invoke-WebRequest drops the Authorization header on such redirects.
        $p['OutFile'] = $OutFile
        $p['TimeoutSec'] = 3600
        $p['Headers']['Accept'] = 'application/zip, */*'
    }
    try {
        $r = Invoke-WebRequest @p
        if ($OutFile) {
            if ($AzureDevOps -and (Test-A2CHtmlFile $OutFile)) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
                return @{ StatusCode = 401; Content = 'Azure DevOps returned its sign-in page (no access with this account)'; Headers = @{} }
            }
            return @{ StatusCode = 200; Content = ''; Headers = @{} }
        }
        $h = @{}
        foreach ($k in $r.Headers.Keys) { $h[[string]$k] = [string]::Join(',', @($r.Headers[$k])) }
        $code = [int]$r.StatusCode
        # without access Azure DevOps can answer with its sign-in page instead of JSON
        if ($code -eq 203 -or [string]$h['Content-Type'] -like 'text/html*') {
            return @{ StatusCode = 401; Content = 'Azure DevOps returned its sign-in page (no access with this account)'; Headers = $h }
        }
        $content = $r.Content
        if ($content -is [byte[]]) { $content = [Text.Encoding]::UTF8.GetString($content) }   # e.g. CSV on Windows PowerShell
        return @{ StatusCode = $code; Content = [string]$content; Headers = $h }
    }
    catch {
        $code = 0
        $content = [string]$_.Exception.Message
        $h = @{}
        $resp = $_.Exception.Response
        if ($null -ne $resp) {
            try { $code = [int]$resp.StatusCode } catch { $code = 0 }
            # Retry-After for throttling; X-VSS-ResourceTenant names the tenant of an organization that refused the token
            foreach ($hn in @('Retry-After', 'X-VSS-ResourceTenant')) {
                try {
                    $hv = $null
                    if ($resp -is [System.Net.HttpWebResponse]) { $hv = $resp.Headers[$hn] }
                    else { $vals = $null; if ($resp.Headers.TryGetValues($hn, [ref]$vals)) { $hv = @($vals)[0] } }
                    if ($hv) { $h[$hn] = [string]$hv }
                }
                catch { Write-Verbose ('Header not readable: ' + $hn) }
            }
        }
        if ($null -ne $_.ErrorDetails -and $_.ErrorDetails.Message) { $content = [string]$_.ErrorDetails.Message }
        return @{ StatusCode = $code; Content = $content; Headers = $h }
    }
}

function Get-A2CRetryDelay {
    param($Response, [int] $Attempt)
    $h = $Response.Headers
    $wait = 0.0
    foreach ($n in @('Retry-After', 'x-ms-ratelimit-microsoft.costmanagement-qpu-retry-after',
            'x-ms-ratelimit-microsoft.costmanagement-entity-retry-after', 'x-ms-ratelimit-microsoft.costmanagement-tenant-retry-after',
            'x-ms-ratelimit-microsoft.costmanagement-client-retry-after', 'x-ms-user-quota-resets-after')) {
        if ($null -ne $h -and $h.ContainsKey($n)) { $s = ConvertTo-A2CSeconds $h[$n]; if ($s -gt $wait) { $wait = $s } }
    }
    if ($wait -le 0) { $wait = [math]::Min(60, [math]::Pow(2, $Attempt)) }
    $jitter = (Get-Random -Minimum 0 -Maximum 1000) / 1000.0
    return [math]::Min(120, $wait + $jitter)
}

function Get-A2CShortText {
    param([string] $Text, [int] $Max = 300)
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

function Test-A2CSignInError {
    # A transport error (no HTTP status) caused by an expired or blocked Azure sign-in: retrying cannot fix it.
    param([string] $Message)
    return ($Message -match 'Connect-AzAccount|AADSTS\d+|Authentication failed|interaction is required|interaction_required|credentials have not been set up|refresh token has expired')
}

function Invoke-A2CRequest {
    # One request with retries on 429/5xx/transport errors; retries are shown so a slow call never looks like a hang.
    # A sign-in error opens the sign-in once per API kind; if that does not help, it is reported and later calls of
    # that kind fail at once.
    param([string] $Method = 'GET', [string] $Uri, [string] $Body, [string] $Kind = 'arm', [int] $MaxRetries = 6, [string] $OutFile)
    $signInError = $script:A2C.SignInFailed[$Kind]
    if ($signInError) { return @{ StatusCode = 0; Content = $signInError; Headers = @{} } }
    $attempt = 0
    while ($true) {
        $script:A2C.Stats[$Kind] = [int]$script:A2C.Stats[$Kind] + 1
        $r = Invoke-A2CHttp -Method $Method -Uri $Uri -Body $Body -Kind $Kind -OutFile $OutFile
        $code = [int]$r.StatusCode
        if ($code -eq 0 -and (Test-A2CSignInError ([string]$r.Content))) {
            # once per API kind: let the user sign in again (expired session, MFA) and repeat the call
            if (-not $script:A2C.SignInRetried[$Kind] -and (Test-A2CCanPrompt)) {
                $script:A2C.SignInRetried[$Kind] = $true
                if (Request-A2CSignIn -ErrorText ([string]$r.Content)) { continue }
            }
            $script:A2C.SignInFailed[$Kind] = [string]$r.Content
            $fix = 'Connect-AzAccount'
            if ($script:A2C.TenantId) { $fix += ' -TenantId ' + $script:A2C.TenantId }
            Write-A2CLog -Level Error ('Azure sign-in failed ({0} calls): {1}  ->  sign in again with  {2}  and start the script again.' -f $Kind, (Get-A2CShortText $r.Content), $fix)
            return $r
        }
        $retryable = ($code -eq 0 -or $code -eq 429 -or $code -eq 500 -or $code -eq 502 -or $code -eq 503 -or $code -eq 504)
        if (-not $retryable -or $attempt -ge $MaxRetries) { return $r }
        $attempt++
        $delay = Get-A2CRetryDelay -Response $r -Attempt $attempt
        $script:A2C.Stats.Retries++
        if ($code -eq 429) { $script:A2C.Stats.Throttled++ }
        $why = 'HTTP ' + $code
        if ($code -eq 0) { $why = 'No response (' + (Get-A2CShortText $r.Content) + ')' }
        elseif ($code -eq 429) { $why = 'Throttled by Azure (HTTP 429)' }
        $msg = '{0}: {1} {2} - retry {3} of {4} in {5:N0}s' -f $why, $Kind, (Get-A2CShortUri $Uri), $attempt, $MaxRetries, $delay
        # short throttling pauses are routine on big tenants and stay in the log only
        if ($code -eq 429 -and $delay -lt 10) { Write-A2CLog -Level Verbose $msg } else { Write-A2CLog -Level Notice $msg }
        Start-A2CSleep -Seconds $delay
    }
}

function Get-A2CShortUri {
    param([string] $Uri)
    if (-not $Uri) { return '' }
    $u = ($Uri -replace '^https?://[^/]+', '') -replace '([?&]sig=)[^&]*', '$1***'   # storage links carry a signature
    if ($u.Length -gt 140) { $u = $u.Substring(0, 140) + '...' }
    return $u
}

function Get-A2CError {
    param($Response)
    $code = ''; $msg = ''
    try {
        $j = ConvertFrom-A2CJson $Response.Content
        if ($null -ne $j) {
            if ($null -ne $j.error) { $code = [string]$j.error.code; $msg = [string]$j.error.message }
            elseif ($null -ne $j.code) { $code = [string]$j.code; $msg = [string]$j.message }
            elseif ($null -ne $j.message) { $code = [string]$j.typeKey; $msg = [string]$j.message }   # Azure DevOps
        }
    }
    catch { Write-Verbose 'Error response body is not JSON' }
    if (-not $msg) { $msg = [string]$Response.Content }
    if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }
    return [pscustomobject]@{ Status = [int]$Response.StatusCode; Code = $code; Message = $msg }
}

function Get-A2CErrorText {
    param($ErrorInfo)
    if ($null -eq $ErrorInfo) { return '' }
    $t = 'HTTP ' + $ErrorInfo.Status
    if ($ErrorInfo.Code) { $t += ' ' + $ErrorInfo.Code }
    if ($ErrorInfo.Message) { $t += ': ' + $ErrorInfo.Message }
    return $t
}

function Invoke-A2CArm {
    # Single ARM call. Returns @{ Ok; Status; Json; Content; Error }
    param([string] $Path, [string] $Method = 'GET', [string] $Body)
    $uri = $Path
    if ($uri -notmatch '^https?://') { $uri = $script:A2CArmBase + $Path }
    $r = Invoke-A2CRequest -Method $Method -Uri $uri -Body $Body -Kind 'arm'
    $ok = ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300)
    $json = $null
    if ($ok -and $r.Content) { try { $json = ConvertFrom-A2CJson $r.Content } catch { $json = $null } }
    $err = $null
    if (-not $ok) { $err = Get-A2CError $r }
    return [pscustomobject]@{ Ok = $ok; Status = [int]$r.StatusCode; Json = $json; Content = [string]$r.Content; Error = $err; Headers = $r.Headers }
}

function Invoke-A2CArmList {
    # ARM GET with nextLink paging. Returns @{ Ok; Items; Error }
    param([string] $Path)
    $items = [System.Collections.Generic.List[object]]::new()
    $uri = $Path
    if ($uri -notmatch '^https?://') { $uri = $script:A2CArmBase + $Path }
    $guard = 0
    while ($uri -and $guard -lt 10000) {
        $guard++
        $r = Invoke-A2CArm -Path $uri
        if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Items = $items; Error = $r.Error } }
        $j = $r.Json
        $next = $null
        if ($null -ne $j) {
            foreach ($v in @($j.value)) { if ($null -ne $v) { $items.Add($v) } }
            $next = $j.nextLink
        }
        $uri = [string]$next
    }
    return [pscustomobject]@{ Ok = $true; Items = $items; Error = $null }
}

function Invoke-A2CArg {
    # Azure Resource Graph via REST: subscription batches of 200, 1000-row pages with $skipToken,
    # quota back-off, adaptive page size. Returns @{ Ok; Items; Errors }
    param(
        [Parameter(Mandatory)] [string] $Query,
        [string[]] $Subscriptions,
        [string[]] $ManagementGroups,
        [switch] $TenantScope
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()
    $batches = [System.Collections.Generic.List[object]]::new()
    if ($TenantScope -or $ManagementGroups) { $batches.Add($null) }
    else {
        $subs = @($Subscriptions)
        if ($subs.Count -eq 0) { return [pscustomobject]@{ Ok = $true; Items = $items; Errors = $errors } }
        for ($i = 0; $i -lt $subs.Count; $i += 200) { $batches.Add(@($subs[$i..([math]::Min($i + 199, $subs.Count - 1))])) }
    }
    $uri = '{0}/providers/Microsoft.ResourceGraph/resources?api-version={1}' -f $script:A2CArmBase, $script:A2CApi.ResourceGraph
    foreach ($batch in $batches) {
        $skip = $null
        $top = 1000
        $guard = 0
        do {
            $guard++
            $scope = ''
            if ($null -ne $batch) { $scope = ',"subscriptions":[' + [string]::Join(',', @($batch | ForEach-Object { '"' + $_ + '"' })) + ']' }
            elseif ($ManagementGroups) { $scope = ',"managementGroups":[' + [string]::Join(',', @($ManagementGroups | ForEach-Object { '"' + $_ + '"' })) + ']' }
            $opt = '"$top":' + $top + ',"resultFormat":"objectArray"'
            if ($skip) { $opt += ',"$skipToken":' + (ConvertTo-A2CJsonLiteral $skip) }
            $body = '{"query":' + (ConvertTo-A2CJsonLiteral $Query) + $scope + ',"options":{' + $opt + '}}'
            $r = Invoke-A2CRequest -Method 'POST' -Uri $uri -Body $body -Kind 'arg'
            if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) {
                $e = Get-A2CError $r
                if ($top -gt 50 -and ($e.Message -match '(?i)too large|payload|response size|timeout|timed out')) {
                    $top = [math]::Max(50, [int]($top / 4))
                    Write-A2CLog -Level Verbose ('Resource Graph response too large; retrying with page size {0}' -f $top)
                    continue
                }
                $errors.Add($e)
                break
            }
            $j = $null
            try { $j = ConvertFrom-A2CJson $r.Content } catch { $errors.Add([pscustomobject]@{ Status = $r.StatusCode; Code = 'ParseError'; Message = $_.Exception.Message }); break }
            if ($null -eq $j) { break }
            foreach ($row in @($j.data)) { if ($null -ne $row) { $items.Add($row) } }
            $skip = $j.'$skipToken'
            $remaining = $r.Headers['x-ms-user-quota-remaining']
            if ($null -ne $remaining -and "$remaining" -match '^\d+$' -and [int]$remaining -le 1) {
                $wait = ConvertTo-A2CSeconds $r.Headers['x-ms-user-quota-resets-after']
                if ($wait -le 0) { $wait = 5 }
                Start-A2CSleep -Seconds ([math]::Min(60, $wait + 0.5))
            }
        } while ($skip -and $guard -lt 100000)
    }
    return [pscustomobject]@{ Ok = ($errors.Count -eq 0); Items = $items; Errors = $errors }
}

function Invoke-A2CGraph {
    # Single Microsoft Graph call. $Path starts with /v1.0/ or /beta/.
    param([string] $Path, [string] $Method = 'GET', [string] $Body)
    $uri = $Path
    if ($uri -notmatch '^https?://') { $uri = $script:A2CGraphBase + $Path }
    $r = Invoke-A2CRequest -Method $Method -Uri $uri -Body $Body -Kind 'graph'
    $ok = ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300)
    $json = $null
    if ($ok -and $r.Content) { try { $json = ConvertFrom-A2CJson $r.Content } catch { $json = $null } }
    $err = $null
    if (-not $ok) { $err = Get-A2CError $r }
    return [pscustomobject]@{ Ok = $ok; Status = [int]$r.StatusCode; Json = $json; Error = $err }
}

function Invoke-A2CGraphList {
    # Graph GET with @odata.nextLink paging. Returns @{ Ok; Items; Error }
    param([string] $Path, [int] $MaxItems = 0)
    $items = [System.Collections.Generic.List[object]]::new()
    $uri = $Path
    $guard = 0
    while ($uri -and $guard -lt 100000) {
        $guard++
        $r = Invoke-A2CGraph -Path $uri
        if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Items = $items; Error = $r.Error } }
        $j = $r.Json
        $next = $null
        if ($null -ne $j) {
            foreach ($v in @($j.value)) { if ($null -ne $v) { $items.Add($v) } }
            $next = $j.'@odata.nextLink'
        }
        if ($MaxItems -gt 0 -and $items.Count -ge $MaxItems) { break }
        $uri = [string]$next
    }
    return [pscustomobject]@{ Ok = $true; Items = $items; Error = $null }
}

function Invoke-A2CAdo {
    # Single Azure DevOps call. Returns @{ Ok; Status; Json; Error; Headers }
    param([string] $Uri, [string] $Method = 'GET', [string] $Body)
    $r = Invoke-A2CRequest -Method $Method -Uri $Uri -Body $Body -Kind 'ado'
    $ok = ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300)
    $json = $null
    if ($ok -and $r.Content) { try { $json = ConvertFrom-A2CJson $r.Content } catch { $json = $null } }
    $err = $null
    if (-not $ok) { $err = Get-A2CError $r }
    return [pscustomobject]@{ Ok = $ok; Status = [int]$r.StatusCode; Json = $json; Content = [string]$r.Content; Error = $err; Headers = $r.Headers }
}

function Set-A2CQueryParam {
    param([string] $Uri, [string] $Name, [string] $Value)
    $enc = [uri]::EscapeDataString($Value)
    $rx = '([?&])' + [regex]::Escape($Name) + '=[^&]*'
    if ($Uri -match $rx) { return [regex]::Replace($Uri, $rx, ('$1' + $Name + '=' + $enc.Replace('$', '$$'))) }
    if ($Uri.Contains('?')) { return $Uri + '&' + $Name + '=' + $enc }
    return $Uri + '?' + $Name + '=' + $enc
}

function Invoke-A2CAdoList {
    # Azure DevOps GET with paging: items in value/members/items; the next page comes from the x-ms-continuationtoken
    # header, a continuationToken in the body or an @odata.nextLink. Returns @{ Ok; Items; Error }
    param([string] $Uri, [int] $MaxItems = 0)
    $items = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $next = $Uri
    while ($next -and $seen.Count -lt 1000 -and $seen.Add($next)) {
        $r = Invoke-A2CAdo $next
        if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Items = $items; Error = $r.Error } }
        $j = $r.Json
        $token = [string]$r.Headers['x-ms-continuationtoken']
        $link = ''
        if ($null -ne $j) {
            foreach ($n in @('value', 'members', 'items')) {
                if ($null -ne $j.PSObject.Properties[$n]) { foreach ($v in @($j.$n)) { if ($null -ne $v) { $items.Add($v) } }; break }
            }
            if (-not $token -and $null -ne $j.PSObject.Properties['continuationToken']) { $token = [string]$j.continuationToken }
            if ($null -ne $j.PSObject.Properties['@odata.nextLink']) { $link = [string]$j.'@odata.nextLink' }
        }
        if ($MaxItems -gt 0 -and $items.Count -ge $MaxItems) { break }
        if ($link) { $next = $link }
        elseif ($token) { $next = Set-A2CQueryParam $Uri 'continuationToken' $token }
        else { $next = '' }
    }
    return [pscustomobject]@{ Ok = $true; Items = $items; Error = $null }
}

function Get-A2CGraphSkipReason {
    param($ErrorInfo, [string] $Needs)
    if ($null -eq $ErrorInfo) { return 'unknown error' }
    if ($ErrorInfo.Status -eq 403 -or $ErrorInfo.Status -eq 401) { return ('access denied - needs {0} ({1})' -f $Needs, (Get-A2CErrorText $ErrorInfo)) }
    return (Get-A2CErrorText $ErrorInfo)
}

#endregion

#region ============================== 4. CONTEXT AND SCOPE =============================================

function Get-A2CAzContext {
    try { return (Get-AzContext -ErrorAction Stop) } catch { return $null }
}

function Assert-A2CPrerequisites {
    $m = Get-Module -ListAvailable -Name Az.Accounts | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $m) {
        throw 'The Az.Accounts module is required. Install it with:  Install-Module Az.Accounts -Scope CurrentUser'
    }
    if ($m.Version -lt [version]'2.7.0') {
        throw ('Az.Accounts {0} is too old; 2.7.0 or newer is required:  Update-Module Az.Accounts' -f $m.Version)
    }
    Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    $loaded = Get-Module Az.Accounts | Sort-Object Version -Descending | Select-Object -First 1
    return [string]$loaded.Version
}

function Connect-A2CAzure {
    param($Options)
    $ctx = Get-A2CAzContext
    $need = ($null -eq $ctx -or $null -eq $ctx.Account)
    if (-not $need -and $Options.TenantId -and $ctx.Tenant -and ($ctx.Tenant.Id -ne $Options.TenantId)) { $need = $true }
    if ($need) {
        Write-A2CLog 'Signing in to Azure (Connect-AzAccount)...'
        $p = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
        if ($Options.TenantId) { $p['TenantId'] = $Options.TenantId }
        if ($Options.UseDeviceAuthentication) { $p['UseDeviceAuthentication'] = $true }
        Invoke-A2CConnectAzAccount -Params $p
        $ctx = Get-A2CAzContext
    }
    else {
        Write-A2CLog ('Reusing the current Az sign-in ({0})' -f $ctx.Account.Id)
    }
    if ($null -eq $ctx) { throw 'No Azure context after sign-in.' }
    return $ctx
}

function Invoke-A2CConnectAzAccount {
    # The only place that calls Connect-AzAccount (tests replace it).
    param([hashtable] $Params)
    Connect-AzAccount @Params | Out-Null
}

function Test-A2CCanPrompt {
    # An interactive sign-in is possible: a user session not started with -NonInteractive (scheduled task, CI).
    return ([Environment]::UserInteractive -and [Environment]::CommandLine -notmatch '\s-noni')
}

function Request-A2CSignIn {
    # The saved sign-in expired or needs MFA again: open the Microsoft sign-in (a device code in Cloud Shell or with
    # -UseDeviceAuthentication) so the run can continue, with the -AuthScope that Az recommends in its error.
    # Returns $true when the sign-in succeeded.
    param([string] $ErrorText)
    $p = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    if ($script:A2C.TenantId) { $p['TenantId'] = $script:A2C.TenantId }
    if ($script:A2C.Options.UseDeviceAuthentication -or $script:A2C.Env['CloudShell']) { $p['UseDeviceAuthentication'] = $true }
    if ($ErrorText -match '-AuthScope\s+([^''"\s]+)') { $p['AuthScope'] = $Matches[1].TrimEnd('.') }
    Write-A2CLog -Level Notice 'The Azure sign-in has expired or needs MFA again: opening the Microsoft sign-in (the window may open behind this one).'
    Write-A2CLog -Level Notice 'If Azure asks you to pick a subscription, any choice is fine - the script reads every subscription you can access.'
    try {
        Invoke-A2CConnectAzAccount -Params $p
        $ctx = Get-A2CAzContext
        $who = ''
        if ($null -ne $ctx -and $null -ne $ctx.Account) { $who = ' as ' + $ctx.Account.Id }
        Write-A2CLog -Level Ok ('Signed in again{0} - continuing.' -f $who)
        return $true
    }
    catch {
        Write-A2CLog -Level Error ('The sign-in did not complete: ' + (Get-A2CShortText $_.Exception.Message))
        return $false
    }
}

function Initialize-A2CEndpoints {
    param($Context)
    $arm = 'https://management.azure.com'
    $graph = 'https://graph.microsoft.com'
    try { if ($Context.Environment.ResourceManagerUrl) { $arm = [string]$Context.Environment.ResourceManagerUrl } } catch { Write-Verbose 'ResourceManagerUrl not in the context - using the public cloud' }
    try {
        $ep = $Context.Environment.ExtendedProperties
        if ($null -ne $ep -and $ep.ContainsKey('MicrosoftGraphUrl') -and $ep['MicrosoftGraphUrl']) { $graph = [string]$ep['MicrosoftGraphUrl'] }
    }
    catch { Write-Verbose 'MicrosoftGraphUrl not in the context - using the public cloud' }
    $script:A2CArmBase = $arm.TrimEnd('/')
    $script:A2CGraphBase = $graph.TrimEnd('/')
}

function Get-A2CHostInfo {
    $cloudShell = [bool]($env:AZUREPS_HOST_ENVIRONMENT -like 'cloud-shell*' -or $env:ACC_CLOUD)
    $os = 'Windows'
    if ($PSVersionTable.PSEdition -eq 'Core') {
        if ($IsLinux) { $os = 'Linux' } elseif ($IsMacOS) { $os = 'macOS' }
    }
    return @{
        PSEdition  = [string]$PSVersionTable.PSEdition
        PSVersion  = [string]$PSVersionTable.PSVersion
        OS         = $os
        CloudShell = $cloudShell
        ClouddriveExists = ($cloudShell -and (Test-Path (Join-Path $HOME 'clouddrive')))
    }
}

#endregion

#region ============================== 5. DATASETS (COLLECTORS) ========================================

function Get-A2CInScopeSubIds {
    return , @($script:A2C.Data['Subscriptions'] | ForEach-Object { $_.Id })
}

function Get-A2CDatasetSubscriptions {
    $o = $script:A2C.Options
    $r = Invoke-A2CArmList ('/subscriptions?api-version=' + $script:A2CApi.Subscriptions)
    if (-not $r.Ok) { throw ('Cannot list subscriptions: ' + (Get-A2CErrorText $r.Error)) }
    $mgSubs = $null
    if ($o.ManagementGroupId) {
        $q = "// a2c:mgSubscriptions`nresourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project id, subscriptionId"
        $a = Invoke-A2CArg -Query $q -ManagementGroups @($o.ManagementGroupId)
        if (-not $a.Ok) { throw ('Cannot list the subscriptions of management group {0}: {1}' -f $o.ManagementGroupId, (Get-A2CErrorText $a.Errors[0])) }
        $mgSubs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($x in $a.Items) { [void]$mgSubs.Add([string]$x.subscriptionId) }
    }
    $wanted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($o.SubscriptionId)) { if ($x) { [void]$wanted.Add($x) } }
    $excluded = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($o.ExcludeSubscriptionId)) { if ($x) { [void]$excluded.Add($x) } }

    $inScope = [System.Collections.Generic.List[object]]::new()
    $skipped = [System.Collections.Generic.List[object]]::new()
    $byId = @{}
    $found = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $r.Items) {
        $id = ([string]$s.subscriptionId).ToLowerInvariant()
        $quota = ''; $spending = ''
        if ($null -ne $s.subscriptionPolicies) { $quota = [string]$s.subscriptionPolicies.quotaId; $spending = [string]$s.subscriptionPolicies.spendingLimit }
        $sub = [pscustomobject]@{
            Id = $id; Name = [string]$s.displayName; State = [string]$s.state; TenantId = ([string]$s.tenantId).ToLowerInvariant()
            QuotaId = $quota; SpendingLimit = $spending; Tags = $s.tags; AuthorizationSource = [string]$s.authorizationSource
            ManagedByTenants = (Join-A2C @($s.managedByTenants | ForEach-Object { $_.tenantId })); MgChain = @(); SkipReason = ''
        }
        $byId[$id] = $sub
        [void]$found.Add($id)
        if ($wanted.Count -gt 0 -and -not $wanted.Contains($id)) { continue }
        if ($null -ne $mgSubs -and -not $mgSubs.Contains($id)) { continue }
        $reason = ''
        if ($script:A2C.TenantId -and $sub.TenantId -and $sub.TenantId -ne $script:A2C.TenantId) { $reason = 'Belongs to another tenant (' + $sub.TenantId + '), e.g. Azure Lighthouse' }
        elseif ($excluded.Contains($id)) { $reason = 'Excluded by -ExcludeSubscriptionId' }
        elseif (@('Enabled', 'Warned', 'PastDue') -notcontains $sub.State) { $reason = 'Subscription state ' + $sub.State }
        if ($reason) { $sub.SkipReason = $reason; $skipped.Add($sub) } else { $inScope.Add($sub); Add-A2CRaw 'subscriptions' $s }
    }
    foreach ($w in $wanted) {
        if (-not $found.Contains($w)) {
            $skipped.Add([pscustomobject]@{ Id = $w; Name = ''; State = 'NotFound'; TenantId = ''; QuotaId = ''; SpendingLimit = ''; Tags = $null; AuthorizationSource = ''; ManagedByTenants = ''; MgChain = @(); SkipReason = 'Not found or no access' })
        }
    }
    $script:A2C.Data['Subscriptions'] = $inScope
    $script:A2C.Data['SubscriptionsSkipped'] = $skipped
    $script:A2C.Data['SubById'] = $byId
    foreach ($s in $skipped) { Write-A2CLog -Level Warn ('Subscription {0} {1} skipped: {2}' -f $s.Id, $s.Name, $s.SkipReason) }
    Write-A2CLog -Level Ok ('{0} subscription(s) in scope, {1} skipped' -f $inScope.Count, $skipped.Count)
    if ($inScope.Count -eq 0) { throw 'No readable, enabled subscriptions in scope.' }
    Add-A2CCoverage -Area 'Subscriptions' -Status Collected -Items $inScope.Count -Detail ('{0} skipped' -f $skipped.Count)
    return New-A2CDatasetResult
}

function Get-A2CDatasetContainers {
    $q = @'
// a2c:containers
resourcecontainers
| where type in~ ('microsoft.resources/subscriptions', 'microsoft.resources/subscriptions/resourcegroups')
| project id, name, type, location, subscriptionId, tags, managedBy, tagsJson = tostring(tags), propertiesJson = tostring(properties)
'@
    $a = Invoke-A2CArg -Query $q -Subscriptions (Get-A2CInScopeSubIds)
    $rgs = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $a.Items) {
        if ([string]$row.type -ieq 'microsoft.resources/subscriptions') {
            $sub = $script:A2C.Data['SubById'][([string]$row.subscriptionId).ToLowerInvariant()]
            if ($null -eq $sub) { continue }
            if ($null -eq $sub.Tags -and $null -ne $row.tags) { $sub.Tags = $row.tags }
            $p = Get-A2CProps $row
            $chain = [System.Collections.Generic.List[object]]::new()
            foreach ($m in @($p.managementGroupAncestorsChain)) {
                if ($null -ne $m) { $chain.Add([pscustomobject]@{ Name = [string]$m.name; DisplayName = [string]$m.displayName }) }
            }
            $sub.MgChain = $chain.ToArray()
        }
        else { $rgs.Add($row) }
    }
    $script:A2C.Data['ResourceGroups'] = $rgs
    $status = 'Collected'; $note = ''
    if (-not $a.Ok) { $status = 'Partial'; $note = Get-A2CErrorText $a.Errors[0] }
    Add-A2CCoverage -Area 'Resource groups and subscription details (Resource Graph)' -Status $status -Items $rgs.Count -Detail $note
    Write-A2CLog -Level Ok ('{0} resource groups' -f $rgs.Count)
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetManagementGroups {
    $q = @'
// a2c:managementGroups
resourcecontainers
| where type =~ 'microsoft.management/managementgroups'
| project id, name, tenantId, propertiesJson = tostring(properties)
'@
    $a = Invoke-A2CArg -Query $q -TenantScope
    $script:A2C.Data['ManagementGroupRows'] = $a.Items
    $mgs = [System.Collections.Generic.List[object]]::new()
    $byName = @{}
    foreach ($row in $a.Items) {
        $p = Get-A2CProps $row
        $parentId = ''; $parentName = ''
        if ($null -ne $p.details -and $null -ne $p.details.parent) { $parentId = [string]$p.details.parent.id; $parentName = [string]$p.details.parent.name }
        $mg = [pscustomobject]@{ Id = [string]$row.id; Name = [string]$row.name; DisplayName = [string]$p.displayName; ParentId = $parentId; ParentName = $parentName; Source = 'ResourceGraph' }
        $mgs.Add($mg); $byName[$mg.Name.ToLowerInvariant()] = $mg
    }
    # Management groups visible only through subscription ancestor chains (no MG read permission)
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        $chain = @($s.MgChain)
        for ($i = 0; $i -lt $chain.Count; $i++) {
            $n = [string]$chain[$i].Name
            if (-not $n -or $byName.ContainsKey($n.ToLowerInvariant())) { continue }
            $parent = ''
            if ($i + 1 -lt $chain.Count) { $parent = [string]$chain[$i + 1].Name }
            $mg = [pscustomobject]@{ Id = '/providers/Microsoft.Management/managementGroups/' + $n; Name = $n; DisplayName = [string]$chain[$i].DisplayName
                ParentId = $(if ($parent) { '/providers/Microsoft.Management/managementGroups/' + $parent } else { '' }); ParentName = $parent; Source = 'SubscriptionAncestorChain' }
            $mgs.Add($mg); $byName[$n.ToLowerInvariant()] = $mg
        }
    }
    $script:A2C.Data['ManagementGroups'] = $mgs
    $script:A2C.Data['MgByName'] = $byName
    $status = 'Collected'; $note = ''
    if (-not $a.Ok) { $status = 'Partial'; $note = 'Management groups not readable (' + (Get-A2CErrorText $a.Errors[0]) + '); hierarchy taken from subscription ancestor chains' }
    elseif ($a.Items.Count -eq 0 -and $mgs.Count -gt 0) { $status = 'Partial'; $note = 'No read access to management groups; hierarchy taken from subscription ancestor chains' }
    Add-A2CCoverage -Area 'Management groups (Resource Graph)' -Status $status -Items $mgs.Count -Detail $note
    Write-A2CLog -Level Ok ('{0} management groups' -f $mgs.Count)
    return New-A2CDatasetResult -Status $status -Note $note
}

function Add-A2CRaw {
    # Keeps an object as Azure returned it, for the snapshot (the reports work on trimmed copies).
    param([string] $Kind, $Item)
    if ($null -eq $Item -or -not $Item.id) { return }
    $m = $script:A2C.Data['Raw']
    if ($null -eq $m) { $m = [ordered]@{}; $script:A2C.Data['Raw'] = $m }
    if (-not $m.Contains($Kind)) { $m[$Kind] = [ordered]@{} }
    $k = ([string]$Item.id).ToLowerInvariant()
    if (-not $m[$Kind].Contains($k)) { $m[$Kind][$k] = $Item }
}

function Add-A2CRawEntra {
    # Keeps an Entra object (Microsoft Graph) for the snapshot; only when the Snapshot report is selected.
    param([string] $Kind, $Item)
    if ($null -eq $Item -or -not $Item.id -or -not (Test-A2CSelected 'Snapshot')) { return }
    $m = $script:A2C.Data['RawEntra']
    if ($null -eq $m) { $m = [ordered]@{}; $script:A2C.Data['RawEntra'] = $m }
    if (-not $m.Contains($Kind)) { $m[$Kind] = [ordered]@{} }
    $k = ([string]$Item.id).ToLowerInvariant()
    if (-not $m[$Kind].Contains($k)) { $m[$Kind][$k] = $Item }
}

function Get-A2CDatasetResources {
    # tagsJson and propertiesJson are the text Azure returned: the snapshot writes them without parsing
    $cols = 'id, name, type, location, resourceGroup, subscriptionId, kind, managedBy, sku, plan, identity, tags, zones, extendedLocation, {0}' +
        'provisioningState = tostring(properties.provisioningState), tagsJson = tostring(tags), propertiesJson = tostring(properties)'
    $a = Invoke-A2CArg -Query ("// a2c:resources`nresources`n| project " + ($cols -f 'apiVersion, ')) -Subscriptions (Get-A2CInScopeSubIds)
    if (-not $a.Ok -and $a.Items.Count -eq 0 -and (Get-A2CErrorText $a.Errors[0]) -match '(?i)apiVersion') {
        # a cloud whose resources table has no apiVersion column
        $a = Invoke-A2CArg -Query ("// a2c:resources`nresources`n| project " + ($cols -f '')) -Subscriptions (Get-A2CInScopeSubIds)
    }
    $byId = @{}
    $byType = @{}
    foreach ($row in $a.Items) {
        if ($row.propertiesJson) { $row.propertiesJson = Protect-A2CSecretText ([string]$row.propertiesJson) }
        $id = ([string]$row.id).ToLowerInvariant()
        $byId[$id] = $row
        $t = ([string]$row.type).ToLowerInvariant()
        if (-not $byType.ContainsKey($t)) { $byType[$t] = [System.Collections.Generic.List[object]]::new() }
        $byType[$t].Add($row)
    }
    $script:A2C.Data['Resources'] = $a.Items
    $script:A2C.Data['ResById'] = $byId
    $script:A2C.Data['ResByType'] = $byType
    $status = 'Collected'; $note = ''
    if (-not $a.Ok) { $status = 'Partial'; $note = Get-A2CErrorText $a.Errors[0] }
    Add-A2CCoverage -Area 'Resources (Resource Graph)' -Status $status -Items $a.Items.Count -Detail $note
    Write-A2CLog -Level Ok ('{0} resources, {1} resource types' -f $a.Items.Count, $byType.Count)
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CResourcesOfType {
    param([string[]] $Type)
    $l = [System.Collections.Generic.List[object]]::new()
    $bt = $script:A2C.Data['ResByType']
    if ($null -eq $bt) { return , $l }
    foreach ($t in $Type) { $x = $bt[$t.ToLowerInvariant()]; if ($null -ne $x) { $l.AddRange($x) } }
    return , $l
}

function Get-A2CResource {
    param([string] $Id)
    if (-not $Id) { return $null }
    $m = $script:A2C.Data['ResById']
    if ($null -eq $m) { return $null }
    return $m[$Id.ToLowerInvariant()]
}

function Get-A2CDatasetResourceTimes {
    $times = @{}
    $subs = @($script:A2C.Data['Subscriptions'])
    $failed = [System.Collections.Generic.List[string]]::new()
    $i = 0; $t0 = [DateTime]::Now
    foreach ($s in $subs) {
        $i++
        Write-A2CProgress -Activity 'Created/changed times' -Current $i -Total $subs.Count -Started $t0 -Item $s.Name
        $path = '/subscriptions/{0}/resources?api-version={1}&$expand=createdTime,changedTime&$top=1000' -f $s.Id, $script:A2CApi.ResourcesList
        $r = Invoke-A2CArmList $path
        if (-not $r.Ok) { $failed.Add($s.Name + ': ' + (Get-A2CErrorText $r.Error)); continue }
        foreach ($x in $r.Items) { $times[([string]$x.id).ToLowerInvariant()] = @($x.createdTime, $x.changedTime) }
    }
    Write-A2CProgress -Activity 'Created/changed times' -Completed
    $script:A2C.Data['ResourceTimes'] = $times
    $status = 'Collected'; $note = ''
    if ($failed.Count -gt 0) { $status = 'Partial'; $note = [string]::Join(' | ', $failed) }
    Add-A2CCoverage -Area 'Created/changed times (ARM)' -Status $status -Items $times.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetComputeSkus {
    # vCPU / memory of VM sizes, one call per region that has VMs (sizes are cached across regions).
    $caps = @{}
    $locs = Get-A2CUnique @(foreach ($vm in (Get-A2CResourcesOfType 'microsoft.compute/virtualmachines')) { ([string]$vm.location).ToLowerInvariant() })
    $subs = @($script:A2C.Data['Subscriptions'])
    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($loc in $locs) {
        $filter = [uri]::EscapeDataString(("location eq '{0}'" -f $loc))
        $r = Invoke-A2CArmList ('/subscriptions/{0}/providers/Microsoft.Compute/skus?api-version={1}&$filter={2}' -f $subs[0].Id, $script:A2CApi.ComputeSkus, $filter)
        if (-not $r.Ok) { $failed.Add($loc + ': ' + (Get-A2CErrorText $r.Error)); continue }
        foreach ($s in $r.Items) {
            if ([string]$s.resourceType -ne 'virtualMachines') { continue }
            $n = ([string]$s.name).ToLowerInvariant()
            if ($caps.ContainsKey($n)) { continue }
            $v = $null; $m = $null
            foreach ($c in @($s.capabilities)) {
                if ($null -eq $c) { continue }
                if ($c.name -eq 'vCPUs') { $v = $c.value }
                elseif ($c.name -eq 'MemoryGB') { $m = $c.value }
            }
            $caps[$n] = [pscustomobject]@{ vCPUs = $v; MemoryGB = $m }
        }
    }
    $script:A2C.Data['VmSizes'] = $caps
    $status = 'Collected'; $note = ''
    if ($failed.Count -gt 0) { $status = 'Partial'; $note = [string]::Join(' | ', $failed) }
    Add-A2CCoverage -Area 'VM size capabilities (ARM)' -Status $status -Items $caps.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetBackupItems {
    $q = @'
// a2c:backupItems
recoveryservicesresources
| where type in~ ('microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems', 'microsoft.dataprotection/backupvaults/backupinstances')
| project id, name, type, resourceGroup, subscriptionId, location, propertiesJson = tostring(properties)
'@
    $a = Invoke-A2CArg -Query $q -Subscriptions (Get-A2CInScopeSubIds)
    $items = [System.Collections.Generic.List[object]]::new()
    $bySource = @{}
    foreach ($row in $a.Items) {
        $p = Get-A2CProps $row
        $isRsv = ([string]$row.type) -like 'microsoft.recoveryservices/*'
        $vault = $(if ($isRsv) { Get-A2CIdSegment -Id ([string]$row.id) -After 'vaults' } else { Get-A2CIdSegment -Id ([string]$row.id) -After 'backupVaults' })
        $src = [string](Get-A2CFirst $p @('sourceResourceId', 'dataSourceInfo.resourceID', 'virtualMachineId'))
        $item = [pscustomobject]@{
            Id = [string]$row.id; SubscriptionId = [string]$row.subscriptionId; Vault = $vault
            VaultType = $(if ($isRsv) { 'Recovery Services vault' } else { 'Backup vault' })
            ItemName = [string](Get-A2CFirst $p @('friendlyName', 'dataSourceInfo.resourceName')); SourceResourceId = $src
            WorkloadType = [string](Get-A2CFirst $p @('workloadType', 'dataSourceInfo.datasourceType'))
            BackupManagementType = [string](Get-A2CFirst $p @('backupManagementType', 'dataSourceSetInfo.datasourceType'))
            ProtectionState = [string](Get-A2CFirst $p @('protectionState', 'currentProtectionState'))
            ProtectionStatus = [string](Get-A2CFirst $p @('protectionStatus', 'protectionStatus.status'))
            HealthStatus = [string](Get-A2CFirst $p @('healthStatus'))
            LastBackupStatus = [string](Get-A2CFirst $p @('lastBackupStatus'))
            LastBackupTime = (Get-A2CFirst $p @('lastBackupTime', 'lastRecoveryPoint'))
            Policy = [string](Get-A2CFirst $p @('policyName', 'policyInfo.policyId'))
        }
        if ($item.Policy -match '/') { $item.Policy = Get-A2CNameFromId $item.Policy }
        $items.Add($item)
        if ($src) { $bySource[$src.ToLowerInvariant()] = $item }
    }
    $script:A2C.Data['BackupItems'] = $items
    $script:A2C.Data['BackupBySource'] = $bySource
    $status = 'Collected'; $note = ''
    if (-not $a.Ok) { $status = 'Partial'; $note = Get-A2CErrorText $a.Errors[0] }
    Add-A2CCoverage -Area 'Backup protected items (Resource Graph)' -Status $status -Items $items.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

$script:A2CGraphTables = @('appserviceresources', 'dnsresources', 'networkresources', 'recoveryservicesresources', 'insightsresources',
    'computeresources', 'kubernetesconfigurationresources', 'desktopvirtualizationresources', 'batchresources', 'kustoresources',
    'managedservicesresources', 'featureresources', 'deploymentresources', 'maintenanceresources')

function Get-A2CDatasetGraphTables {
    # The other Resource Graph tables that hold configuration and not state: firewall policy rule collections, DNS
    # records, backup policies, App Service configuration, data collection rule associations, Lighthouse... One query
    # per table, no call per resource. A table a cloud does not have is noted, not an error.
    $rows = [System.Collections.Generic.List[object]]::new()
    $byType = @{}
    $counts = [System.Collections.Generic.List[string]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()
    $subs = Get-A2CInScopeSubIds
    foreach ($t in $script:A2CGraphTables) {
        $q = "// a2c:table_{0}`n{0}`n| project id, name, type, location, resourceGroup, subscriptionId, kind, tags, tagsJson = tostring(tags), propertiesJson = tostring(properties)" -f $t
        $a = Invoke-A2CArg -Query $q -Subscriptions $subs
        if (-not $a.Ok -and $a.Items.Count -eq 0) {
            # fewer columns: not every table has kind, location or tags
            $q = "// a2c:table_{0}`n{0}`n| project id, name, type, subscriptionId, propertiesJson = tostring(properties)" -f $t
            $a = Invoke-A2CArg -Query $q -Subscriptions $subs
        }
        if (-not $a.Ok -and $a.Items.Count -eq 0) {
            $missing.Add($t)
            Write-A2CLog -Level Verbose ('Resource Graph table {0} not readable: {1}' -f $t, (Get-A2CShortText (Get-A2CErrorText $a.Errors[0]) 200))
            continue
        }
        foreach ($row in $a.Items) {
            if ($row.propertiesJson) { $row.propertiesJson = Protect-A2CSecretText ([string]$row.propertiesJson) }
            $row | Add-Member -NotePropertyName 'graphTable' -NotePropertyValue $t -Force
            $rows.Add($row)
            $k = ([string]$row.type).ToLowerInvariant()
            if (-not $byType.ContainsKey($k)) { $byType[$k] = [System.Collections.Generic.List[object]]::new() }
            $byType[$k].Add($row)
        }
        if ($a.Items.Count -gt 0) { $counts.Add(('{0} {1}' -f $t, $a.Items.Count)) }
    }
    $script:A2C.Data['GraphRows'] = $rows
    $script:A2C.Data['GraphByType'] = $byType
    $note = Join-A2C $counts ', '
    if ($missing.Count -gt 0) { $note += ' | not readable: ' + (Join-A2C $missing ', ') }
    $status = $(if ($missing.Count -eq $script:A2CGraphTables.Count) { 'Failed' } elseif ($missing.Count -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'Other Resource Graph tables (DNS records, firewall rules, backup policies...)' -Status $status -Items $rows.Count -Detail $note
    Write-A2CLog -Level Ok ('{0} items from {1} other Resource Graph tables' -f $rows.Count, ($script:A2CGraphTables.Count - $missing.Count))
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CGraphRowsOfType {
    # Rows of the other Resource Graph tables by type (lower case), e.g. microsoft.network/firewallpolicies/rulecollectiongroups
    param([string[]] $Type)
    $l = [System.Collections.Generic.List[object]]::new()
    $bt = $script:A2C.Data['GraphByType']
    if ($null -eq $bt) { return , $l }
    foreach ($t in $Type) { $x = $bt[$t.ToLowerInvariant()]; if ($null -ne $x) { $l.AddRange($x) } }
    return , $l
}

function Get-A2CDatasetAppServiceConfig {
    # sites/config and sites/slots/config: without the second one deployment slots lose their runtime and TLS columns
    $q = @'
// a2c:appServiceConfig
appserviceresources
| where type in~ ('microsoft.web/sites/config', 'microsoft.web/sites/slots/config')
| project id, subscriptionId, propertiesJson = tostring(properties)
'@
    $a = Invoke-A2CArg -Query $q -Subscriptions (Get-A2CInScopeSubIds)
    $bySite = @{}
    foreach ($row in $a.Items) {
        $site = (Get-A2CParentId ([string]$row.id)).ToLowerInvariant()
        $bySite[$site] = Get-A2CProps $row
    }
    $script:A2C.Data['AppConfigBySite'] = $bySite
    $status = 'Collected'; $note = ''
    if (-not $a.Ok) { $status = 'Partial'; $note = Get-A2CErrorText $a.Errors[0] }
    Add-A2CCoverage -Area 'App Service configuration (Resource Graph)' -Status $status -Items $bySite.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function Format-A2CDiagSetting {
    param($Setting, [string] $Prefix = '')
    $p = $Setting.properties
    $dest = [System.Collections.Generic.List[string]]::new()
    if ($p.workspaceId) { $dest.Add('LA:' + (Get-A2CNameFromId ([string]$p.workspaceId))) }
    if ($p.storageAccountId) { $dest.Add('SA:' + (Get-A2CNameFromId ([string]$p.storageAccountId))) }
    if ($p.eventHubAuthorizationRuleId) {
        $eh = 'EH:' + (Get-A2CIdSegment -Id ([string]$p.eventHubAuthorizationRuleId) -After 'namespaces')
        if ($p.eventHubName) { $eh += '/' + [string]$p.eventHubName }
        $dest.Add($eh)
    }
    if ($p.marketplacePartnerId) { $dest.Add('Partner:' + (Get-A2CNameFromId ([string]$p.marketplacePartnerId))) }
    $logs = @(foreach ($l in @($p.logs)) { if ($null -ne $l -and $l.enabled) { if ($l.categoryGroup) { [string]$l.categoryGroup } else { [string]$l.category } } })
    $groups = @(foreach ($l in @($p.logs)) { if ($null -ne $l -and $l.enabled -and $l.categoryGroup) { [string]$l.categoryGroup } })
    $mets = @(foreach ($m in @($p.metrics)) { if ($null -ne $m -and $m.enabled) { [string]$m.category } })
    Add-A2CRaw 'diagnosticSettings' $Setting
    $name = [string]$Setting.name
    $text = '{0}{1} -> {2}' -f $Prefix, $name, (Join-A2C $dest ', ')
    $cats = [System.Collections.Generic.List[string]]::new()
    if ($logs.Count) { $cats.Add('logs: ' + (Join-A2C $logs ', ')) }
    if ($mets.Count) { $cats.Add('metrics: ' + (Join-A2C $mets ', ')) }
    if ($cats.Count) { $text += ' [' + [string]::Join('; ', $cats) + ']' }
    return [pscustomobject]@{
        Name = $name; Text = $text; Logs = (Join-A2C $logs ', '); Metrics = (Join-A2C $mets ', ')
        WorkspaceId = [string]$p.workspaceId; StorageAccountId = [string]$p.storageAccountId
        EventHub = $(if ($p.eventHubAuthorizationRuleId) { (Get-A2CIdSegment -Id ([string]$p.eventHubAuthorizationRuleId) -After 'namespaces') + '/' + [string]$p.eventHubName } else { '' })
        Partner = [string]$p.marketplacePartnerId; DestinationType = [string]$p.logAnalyticsDestinationType
        # what is needed to create the setting again: the full rule ID, the hub name, category groups apart from categories
        EventHubRuleId = [string]$p.eventHubAuthorizationRuleId; EventHubName = [string]$p.eventHubName; LogCategoryGroups = (Join-A2C $groups ', ')
        ServiceBusRuleId = [string]$p.serviceBusRuleId; Id = [string]$Setting.id
    }
}

function Test-A2CDiagUnsupported {
    param($ErrorInfo)
    if ($null -eq $ErrorInfo) { return $false }
    if (@(400, 404, 405) -notcontains [int]$ErrorInfo.Status) { return $false }
    return ([string]$ErrorInfo.Code -match '(?i)NotSupported' -or [string]$ErrorInfo.Message -match '(?i)not support|does not support|is not a supported')
}

function Get-A2CDatasetDiagnostics {
    $diag = @{}
    $details = [System.Collections.Generic.List[object]]::new()
    $unsupported = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($t in $script:A2CDiagUnsupportedSeed) { [void]$unsupported.Add($t) }
    $learned = [System.Collections.Generic.List[string]]::new()
    $noInsights = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $errorCount = 0
    $api = $script:A2CApi.DiagSettings
    $addDetail = {
        param($R, [string] $Target, $Fmt)
        $details.Add([ordered]@{
                SubscriptionName = Get-A2CSubName ([string]$R.subscriptionId); SubscriptionId = [string]$R.subscriptionId
                ResourceGroup = Get-A2CRgFromId ([string]$R.id); ResourceName = [string]$R.name; ResourceType = Get-A2CTypeCased -Id ([string]$R.id) -Fallback ([string]$R.type)
                Target = $Target; SettingName = $Fmt.Name; Workspace = Get-A2CNameFromId $Fmt.WorkspaceId; WorkspaceId = $Fmt.WorkspaceId
                StorageAccount = Get-A2CNameFromId $Fmt.StorageAccountId; StorageAccountId = $Fmt.StorageAccountId; EventHub = $Fmt.EventHub
                PartnerSolution = Get-A2CNameFromId $Fmt.Partner; LogCategories = $Fmt.Logs; MetricCategories = $Fmt.Metrics
                LogAnalyticsDestinationType = $Fmt.DestinationType; ResourceId = [string]$R.id
                LogCategoryGroups = $Fmt.LogCategoryGroups; EventHubAuthorizationRuleId = $Fmt.EventHubRuleId; EventHubName = $Fmt.EventHubName
                PartnerSolutionId = $Fmt.Partner; SettingId = $Fmt.Id
            })
    }
    # 1) subscription activity log
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        $sid = '/subscriptions/' + $s.Id
        $r = Invoke-A2CArm ('{0}/providers/Microsoft.Insights/diagnosticSettings?api-version={1}' -f $sid, $api)
        $fake = [pscustomobject]@{ id = $sid; name = $s.Name; type = 'microsoft.resources/subscriptions'; subscriptionId = $s.Id }
        if ($r.Ok) {
            $fm = @(foreach ($v in @($r.Json.value)) { if ($null -ne $v) { Format-A2CDiagSetting $v } })
            foreach ($f in $fm) { & $addDetail $fake 'activity log' $f }
            $diag[$sid.ToLowerInvariant()] = [pscustomobject]@{ Status = $(if ($fm.Count) { 'Configured' } else { 'NotConfigured' }); Summary = (Join-A2C @($fm | ForEach-Object { 'activity log: ' + $_.Text }) ' | '); Count = $fm.Count }
        }
        else { $diag[$sid.ToLowerInvariant()] = [pscustomobject]@{ Status = 'Error: ' + (Get-A2CErrorText $r.Error); Summary = ''; Count = 0 }; $errorCount++ }
    }
    # 2) resources
    $targets = [System.Collections.Generic.List[object]]::new()
    $storage = 0
    foreach ($r in $script:A2C.Data['Resources']) {
        if ($unsupported.Contains([string]$r.type)) { continue }
        $targets.Add($r)
        if ([string]$r.type -eq 'microsoft.storage/storageaccounts') { $storage++ }
    }
    $calls = $targets.Count + 4 * $storage
    $estMin = [math]::Round($calls * 0.2 / 60, 1)
    Write-A2CLog ('Diagnostic settings: about {0} calls, estimated {1} min (skip with -SkipReports DiagnosticSettings)' -f $calls, $estMin)
    if ($script:A2C.Env.CloudShell -and $estMin -gt 15) { Write-A2CLog -Level Warn 'Cloud Shell closes idle sessions after 20 minutes - for large tenants run locally or use -Profile Quick.' }
    $i = 0; $t0 = [DateTime]::Now
    foreach ($r in $targets) {
        $i++
        if ($i % 10 -eq 1) { Write-A2CProgress -Activity 'Diagnostic settings' -Current $i -Total $targets.Count -Started $t0 -Item ([string]$r.name) }
        $type = [string]$r.type
        $lid = ([string]$r.id).ToLowerInvariant()
        if ($unsupported.Contains($type)) { $diag[$lid] = [pscustomobject]@{ Status = 'NotSupported'; Summary = ''; Count = 0 }; continue }
        if ($noInsights.Contains([string]$r.subscriptionId)) { $diag[$lid] = [pscustomobject]@{ Status = 'NotConfigured'; Summary = 'Microsoft.Insights not registered'; Count = 0 }; continue }
        $ids = [System.Collections.Generic.List[object]]::new()
        $ids.Add(@([string]$r.id, ''))
        if ($type -eq 'microsoft.storage/storageaccounts') {
            foreach ($svc in @('blob', 'file', 'queue', 'table')) { $ids.Add(@(([string]$r.id + '/' + $svc + 'Services/default'), ($svc + ': '))) }
        }
        $fmts = [System.Collections.Generic.List[object]]::new()
        $status = ''
        foreach ($t in $ids) {
            $resp = Invoke-A2CArm ('{0}/providers/Microsoft.Insights/diagnosticSettings?api-version={1}' -f $t[0], $api)
            if ($resp.Ok) {
                foreach ($v in @($resp.Json.value)) {
                    if ($null -eq $v) { continue }
                    $f = Format-A2CDiagSetting $v -Prefix $t[1]
                    $fmts.Add($f)
                    & $addDetail $r $(if ($t[1]) { $t[1].TrimEnd(':', ' ') } else { 'resource' }) $f
                }
                if (-not $status) { $status = 'ok' }
                continue
            }
            $e = $resp.Error
            if ($t[1]) { continue }   # storage sub-service not available - ignore
            if (Test-A2CDiagUnsupported $e) { if ($unsupported.Add($type)) { $learned.Add($type) }; $status = 'NotSupported'; break }
            if ([string]$e.Code -match '(?i)MissingSubscriptionRegistration' -or [string]$e.Message -match '(?i)not registered to use namespace') {
                [void]$noInsights.Add([string]$r.subscriptionId); $status = 'NotConfigured'; break
            }
            $status = 'Error: ' + (Get-A2CErrorText $e); $errorCount++; break
        }
        if ($status -eq 'ok') { $status = $(if ($fmts.Count -gt 0) { 'Configured' } else { 'NotConfigured' }) }
        $diag[$lid] = [pscustomobject]@{ Status = $status; Summary = (Join-A2C @($fmts | ForEach-Object { $_.Text }) ' | '); Count = $fmts.Count }
    }
    Write-A2CProgress -Activity 'Diagnostic settings' -Completed
    foreach ($r in $script:A2C.Data['Resources']) {
        $lid = ([string]$r.id).ToLowerInvariant()
        if (-not $diag.ContainsKey($lid)) { $diag[$lid] = [pscustomobject]@{ Status = 'NotSupported'; Summary = ''; Count = 0 } }
    }
    $script:A2C.Data['Diag'] = $diag
    $script:A2C.Data['DiagDetails'] = $details
    $note = ''
    if ($learned.Count) { $note = 'Types without diagnostic settings (learned): ' + [string]::Join(', ', $learned) }
    if ($noInsights.Count) { $note += ' | Microsoft.Insights not registered in ' + $noInsights.Count + ' subscription(s)' }
    $status = 'Collected'
    if ($errorCount -gt 0) { $status = 'Partial'; $note = ('{0} errors. ' -f $errorCount) + $note }
    Add-A2CCoverage -Area 'Diagnostic settings (ARM)' -Status $status -Items $details.Count -Detail $note
    Write-A2CLog -Level Ok ('{0} diagnostic settings on {1} checked resources' -f $details.Count, $targets.Count)
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetLocks {
    $locks = @{}
    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        $r = Invoke-A2CArmList ('/subscriptions/{0}/providers/Microsoft.Authorization/locks?api-version={1}' -f $s.Id, $script:A2CApi.Locks)
        if (-not $r.Ok) { $failed.Add($s.Name + ': ' + (Get-A2CErrorText $r.Error)); continue }
        foreach ($l in $r.Items) {
            $id = [string]$l.id
            $k = $id.ToLowerInvariant()
            if ($locks.ContainsKey($k)) { continue }
            $ix = $id.IndexOf('/providers/Microsoft.Authorization/locks/', [StringComparison]::OrdinalIgnoreCase)
            $scope = $(if ($ix -gt 0) { $id.Substring(0, $ix) } else { '' })
            $locks[$k] = [pscustomobject]@{ SubscriptionId = $s.Id; Id = $id; Name = [string]$l.name; Level = [string]$l.properties.level
                Notes = [string]$l.properties.notes; Scope = $scope; Owners = (Join-A2C @($l.properties.owners | ForEach-Object { $_.applicationId }) ', ') }
            Add-A2CRaw 'locks' $l
        }
    }
    $script:A2C.Data['Locks'] = @($locks.Values)
    $status = 'Collected'; $note = ''
    if ($failed.Count) { $status = 'Partial'; $note = [string]::Join(' | ', $failed) }
    Add-A2CCoverage -Area 'Locks (ARM)' -Status $status -Items $locks.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function ConvertTo-A2CRoleDefinition {
    param($D)
    $p = $D.properties
    $act = [System.Collections.Generic.List[string]]::new(); $nact = [System.Collections.Generic.List[string]]::new()
    $dact = [System.Collections.Generic.List[string]]::new(); $ndact = [System.Collections.Generic.List[string]]::new()
    foreach ($perm in @($p.permissions)) {
        if ($null -eq $perm) { continue }
        foreach ($x in @($perm.actions)) { if ($x) { $act.Add([string]$x) } }
        foreach ($x in @($perm.notActions)) { if ($x) { $nact.Add([string]$x) } }
        foreach ($x in @($perm.dataActions)) { if ($x) { $dact.Add([string]$x) } }
        foreach ($x in @($perm.notDataActions)) { if ($x) { $ndact.Add([string]$x) } }
    }
    return [pscustomobject]@{ Guid = ([string]$D.name).ToLowerInvariant(); Id = [string]$D.id; RoleName = [string]$p.roleName; Type = [string]$p.type; Description = [string]$p.description
        Actions = $act; NotActions = $nact; DataActions = $dact; NotDataActions = $ndact; AssignableScopes = @($p.assignableScopes)
        Subscriptions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
}

function Get-A2CDatasetRoleDefinitions {
    $defs = @{}
    $failed = [System.Collections.Generic.List[string]]::new()
    $haveBuiltIns = $false
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        # atScopeAndBelow: also custom roles that are assignable only at a resource group; built-in roles once
        $base = '/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions?api-version={1}&$filter=' -f $s.Id, $script:A2CApi.RoleDefinitions
        $r = $null
        if ($haveBuiltIns) { $r = Invoke-A2CArmList ($base + [uri]::EscapeDataString("atScopeAndBelow() and type eq 'CustomRole'")) }
        if ($null -eq $r -or -not $r.Ok) { $r = Invoke-A2CArmList ($base + [uri]::EscapeDataString('atScopeAndBelow()')) }
        if (-not $r.Ok) { $failed.Add($s.Name + ': ' + (Get-A2CErrorText $r.Error)); continue }
        $haveBuiltIns = $true
        foreach ($d in $r.Items) {
            $g = ([string]$d.name).ToLowerInvariant()
            if (-not $defs.ContainsKey($g)) { $defs[$g] = ConvertTo-A2CRoleDefinition $d }
            if ([string]$d.properties.type -eq 'CustomRole') { [void]$defs[$g].Subscriptions.Add($s.Id); Add-A2CRaw 'roleDefinitions' $d }
        }
    }
    $script:A2C.Data['RoleDefs'] = $defs
    $status = 'Collected'; $note = ''
    if ($failed.Count) { $status = 'Partial'; $note = [string]::Join(' | ', $failed) }
    if (-not $haveBuiltIns) { $status = 'Failed' }
    Add-A2CCoverage -Area 'Role definitions (ARM)' -Status $status -Items $defs.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function ConvertTo-A2CRoleAssignment {
    # $SubscriptionId: the subscription it was listed for ('' = read at a management group no subscription is below)
    param($A, [string] $SubscriptionId)
    $p = $A.properties
    return [pscustomobject]@{
        SubscriptionId = $SubscriptionId; Id = [string]$A.id; Name = [string]$A.name; Scope = [string]$p.scope; RoleDefinitionId = [string]$p.roleDefinitionId
        RoleGuid = (Get-A2CNameFromId ([string]$p.roleDefinitionId)).ToLowerInvariant(); PrincipalId = ([string]$p.principalId).ToLowerInvariant()
        PrincipalType = [string]$p.principalType; Condition = [string]$p.condition; Description = [string]$p.description
        CreatedOn = $p.createdOn; CreatedBy = [string]$p.createdBy; DelegatedMI = [string]$p.delegatedManagedIdentityResourceId
        ConditionVersion = [string]$p.conditionVersion; UpdatedOn = $p.updatedOn
    }
}

function Get-A2CDatasetRoleAssignments {
    $rows = [System.Collections.Generic.List[object]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        $r = Invoke-A2CArmList ('/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignments?api-version={1}' -f $s.Id, $script:A2CApi.RoleAssignments)
        if (-not $r.Ok) { $failed.Add($s.Name + ': ' + (Get-A2CErrorText $r.Error)); continue }
        foreach ($a in $r.Items) {
            $rows.Add((ConvertTo-A2CRoleAssignment $a $s.Id))
            Add-A2CRaw 'roleAssignments' $a
        }
    }
    $script:A2C.Data['RoleAssignments'] = $rows
    # deny assignments (created by Azure for managed applications, deployment stacks and blueprints)
    $deny = [System.Collections.Generic.List[object]]::new()
    $denyFailed = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        $r = Invoke-A2CArmList ('/subscriptions/{0}/providers/Microsoft.Authorization/denyAssignments?api-version={1}' -f $s.Id, $script:A2CApi.DenyAssignments)
        if (-not $r.Ok) { $denyFailed.Add($s.Name + ': ' + (Get-A2CErrorText $r.Error)); if ($deny.Count -eq 0 -and $denyFailed.Count -ge 3) { break }; continue }
        foreach ($d in $r.Items) { $deny.Add([pscustomobject]@{ SubscriptionId = $s.Id; Item = $d }); Add-A2CRaw 'denyAssignments' $d }
    }
    $script:A2C.Data['DenyAssignments'] = $deny
    Add-A2CCoverage -Area 'Deny assignments (ARM)' -Status $(if ($denyFailed.Count -gt 0) { 'Partial' } else { 'Collected' }) -Items $deny.Count -Detail (Join-A2C @($denyFailed | Select-Object -First 3) ' | ')
    $status = 'Collected'; $note = ''
    if ($failed.Count) { $status = 'Partial'; $note = [string]::Join(' | ', $failed) }
    Add-A2CCoverage -Area 'Role assignments (ARM)' -Status $status -Items $rows.Count -Detail $note
    Write-A2CLog -Level Ok ('{0} role assignments' -f $rows.Count)
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetPim {
    # Privileged Identity Management for Azure resources: who is eligible for a role, and which active assignments
    # are time-bound or activated. Two calls per subscription. A tenant that does not use PIM answers with empty
    # lists or an error; after three subscriptions without an answer the others are not asked.
    $eligible = [System.Collections.Generic.List[object]]::new()
    $active = @{}
    $failed = [System.Collections.Generic.List[string]]::new()
    $answered = 0
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        $base = '/subscriptions/{0}/providers/Microsoft.Authorization/' -f $s.Id
        $r = Invoke-A2CArmList ($base + 'roleEligibilityScheduleInstances?api-version=' + $script:A2CApi.Pim)
        if (-not $r.Ok) {
            $failed.Add($s.Name + ': ' + (Get-A2CErrorText $r.Error))
            if ($answered -eq 0 -and $failed.Count -ge 3) { break }
            continue
        }
        $answered++
        foreach ($x in $r.Items) { $eligible.Add([pscustomobject]@{ SubscriptionId = $s.Id; Item = $x }); Add-A2CRaw 'roleEligibilityScheduleInstances' $x }
        $r = Invoke-A2CArmList ($base + 'roleAssignmentScheduleInstances?api-version=' + $script:A2CApi.Pim)
        if (-not $r.Ok) { $failed.Add($s.Name + ' (active): ' + (Get-A2CErrorText $r.Error)); continue }
        foreach ($x in $r.Items) {
            $origin = ([string]$x.properties.originRoleAssignmentId).ToLowerInvariant()
            if ($origin) { $active[$origin] = $x }
            if ($x.properties.endDateTime -or [string]$x.properties.assignmentType -eq 'Activated') { Add-A2CRaw 'roleAssignmentScheduleInstances' $x }
        }
    }
    $script:A2C.Data['PimEligible'] = $eligible
    $script:A2C.Data['PimActive'] = $active
    $status = 'Collected'
    if ($answered -eq 0 -and $failed.Count -gt 0) { $status = 'Skipped' } elseif ($failed.Count -gt 0) { $status = 'Partial' }
    $note = Join-A2C @($failed | Select-Object -First 3) ' | '
    Add-A2CCoverage -Area 'PIM for Azure resources (ARM)' -Status $status -Items $eligible.Count -Detail $(if ($note) { $note } else { ('{0} eligible assignments' -f $eligible.Count) })
    Write-A2CLog -Level Ok ('{0} eligible role assignments (PIM)' -f $eligible.Count)
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetPrincipals {
    # Resolve RBAC principal IDs with Microsoft Graph directoryObjects/getByIds (1000 per call).
    $ids = Get-A2CUnique @($script:A2C.Data['RoleAssignments'] | ForEach-Object { $_.PrincipalId })
    $map = @{}
    $reason = ''
    for ($i = 0; $i -lt $ids.Count; $i += 1000) {
        $chunk = @($ids[$i..([math]::Min($i + 999, $ids.Count - 1))])
        $body = '{"ids":[' + [string]::Join(',', @($chunk | ForEach-Object { '"' + $_ + '"' })) + '],"types":["user","group","servicePrincipal"]}'
        $r = Invoke-A2CGraph -Path '/v1.0/directoryObjects/getByIds' -Method 'POST' -Body $body
        if (-not $r.Ok) { $reason = Get-A2CGraphSkipReason $r.Error 'directory read access'; break }
        foreach ($o in @($r.Json.value)) {
            if ($null -eq $o) { continue }
            $t = ([string]$o.'@odata.type') -replace '^#microsoft\.graph\.', ''
            $upn = [string]$o.userPrincipalName
            $map[([string]$o.id).ToLowerInvariant()] = [pscustomobject]@{
                Type = $t; DisplayName = [string]$o.displayName; UPN = $upn; AppId = [string]$o.appId; SpType = [string]$o.servicePrincipalType
                IsGuest = ($upn -match '#EXT#' -or [string]$o.userType -eq 'Guest')
            }
        }
    }
    $script:A2C.Data['Principals'] = $map
    $script:A2C.Data['PrincipalsResolved'] = (-not $reason)
    if ($reason) {
        Write-A2CLog -Level Warn ('RBAC principal names not resolved: ' + $reason)
        Add-A2CCoverage -Area 'RBAC principal names (Microsoft Graph)' -Status Skipped -Detail $reason
        return New-A2CDatasetResult -Status 'Skipped' -Note $reason
    }
    Add-A2CCoverage -Area 'RBAC principal names (Microsoft Graph)' -Status Collected -Items $map.Count -Detail ('{0} of {1} principals found' -f $map.Count, $ids.Count)
    return New-A2CDatasetResult
}

function ConvertTo-A2CPolicyAssignment {
    param($A)
    $p = $A.properties
    return [pscustomobject]@{
        Id = [string]$A.id; Name = [string]$A.name; DisplayName = [string]$p.displayName; Description = [string]$p.description
        Scope = [string]$p.scope; ScopeType = Get-A2CScopeType ([string]$p.scope); DefinitionId = [string]$p.policyDefinitionId
        IsInitiative = ([string]$p.policyDefinitionId -match '(?i)/policySetDefinitions/'); EnforcementMode = [string]$p.enforcementMode
        Parameters = $p.parameters; NotScopes = @($p.notScopes | Where-Object { $_ }); IdentityType = [string]$A.identity.type
        IdentityPrincipalId = [string]$A.identity.principalId; Location = [string]$A.location
        NonComplianceMessage = (Join-A2C @($p.nonComplianceMessages | ForEach-Object { $_.message }) ' | ')
        MessagesByReference = (Join-A2C @($p.nonComplianceMessages | Where-Object { $null -ne $_ -and $_.policyDefinitionReferenceId } | ForEach-Object { [string]$_.policyDefinitionReferenceId + ': ' + [string]$_.message }) ' | ')
        DefinitionVersion = [string]$p.definitionVersion; Overrides = $p.overrides; ResourceSelectors = $p.resourceSelectors
        UserAssignedIdentity = (Join-A2C @(if ($null -ne $A.identity -and $null -ne $A.identity.userAssignedIdentities) { $A.identity.userAssignedIdentities.PSObject.Properties | ForEach-Object { $_.Name } }))
        CreatedOn = $p.metadata.createdOn; CreatedBy = [string]$p.metadata.createdBy
        AppliesTo = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
}

function Get-A2CDatasetPolicyAssignments {
    $map = [ordered]@{}
    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        $r = Invoke-A2CArmList ('/subscriptions/{0}/providers/Microsoft.Authorization/policyAssignments?api-version={1}' -f $s.Id, $script:A2CApi.Policy)
        if (-not $r.Ok) { $failed.Add($s.Name + ': ' + (Get-A2CErrorText $r.Error)); continue }
        foreach ($a in $r.Items) {
            $k = ([string]$a.id).ToLowerInvariant()
            if (-not $map.Contains($k)) { $map[$k] = ConvertTo-A2CPolicyAssignment $a }
            [void]$map[$k].AppliesTo.Add($s.Id)
            Add-A2CRaw 'policyAssignments' $a
        }
    }
    $script:A2C.Data['PolicyAssignments'] = @($map.Values)
    $status = 'Collected'; $note = ''
    if ($failed.Count) { $status = 'Partial'; $note = [string]::Join(' | ', $failed) }
    Add-A2CCoverage -Area 'Policy assignments (ARM)' -Status $status -Items $map.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function ConvertTo-A2CPolicyExemption {
    param($E)
    $p = $E.properties
    $id = [string]$E.id
    $ix = $id.IndexOf('/providers/Microsoft.Authorization/policyExemptions/', [StringComparison]::OrdinalIgnoreCase)
    return [pscustomobject]@{
        Id = $id; Name = [string]$E.name; DisplayName = [string]$p.displayName; Description = [string]$p.description
        Scope = $(if ($ix -gt 0) { $id.Substring(0, $ix) } else { '' }); AssignmentId = [string]$p.policyAssignmentId
        Category = [string]$p.exemptionCategory; ExpiresOn = $p.expiresOn; RefIds = (Join-A2C @($p.policyDefinitionReferenceIds) ', ')
        CreatedOn = (Get-A2CFirst $E @('systemData.createdAt')); CreatedBy = [string](Get-A2CFirst $E @('systemData.createdBy'))
        AssignmentScopeValidation = [string]$p.assignmentScopeValidation; ResourceSelectors = $p.resourceSelectors
    }
}

function Get-A2CDatasetPolicyExemptions {
    $map = [ordered]@{}
    $failed = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        $r = Invoke-A2CArmList ('/subscriptions/{0}/providers/Microsoft.Authorization/policyExemptions?api-version={1}' -f $s.Id, $script:A2CApi.PolicyExemptions)
        if (-not $r.Ok) { $failed.Add($s.Name + ': ' + (Get-A2CErrorText $r.Error)); continue }
        foreach ($e in $r.Items) {
            $k = ([string]$e.id).ToLowerInvariant()
            if ($map.Contains($k)) { continue }
            $map[$k] = ConvertTo-A2CPolicyExemption $e
            Add-A2CRaw 'policyExemptions' $e
        }
    }
    $script:A2C.Data['PolicyExemptions'] = @($map.Values)
    $status = 'Collected'; $note = ''
    if ($failed.Count) { $status = 'Partial'; $note = [string]::Join(' | ', $failed) }
    Add-A2CCoverage -Area 'Policy exemptions (ARM)' -Status $status -Items $map.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function ConvertTo-A2CPolicyDefinition {
    param($D)
    $p = $D.properties
    $isSet = ([string]$D.id -match '(?i)/policySetDefinitions/') -or ($null -ne $p.policyDefinitions)
    $effect = ''
    if (-not $isSet) {
        $effect = [string]$p.policyRule.then.effect
        if ($effect -match "\[parameters\('([^']+)'\)\]") {
            $pn = $Matches[1]
            $dv = $null
            if ($null -ne $p.parameters -and $null -ne $p.parameters.$pn) { $dv = $p.parameters.$pn.defaultValue }
            $effect = $(if ($dv) { [string]$dv + ' (parameter)' } else { 'parameter' })
        }
    }
    $members = [System.Collections.Generic.List[object]]::new()
    if ($isSet) {
        foreach ($m in @($p.policyDefinitions)) { if ($null -ne $m) { $members.Add([pscustomobject]@{ DefinitionId = [string]$m.policyDefinitionId; RefId = [string]$m.policyDefinitionReferenceId; Parameters = $m.parameters }) } }
    }
    $id = [string]$D.id
    $ix = $id.IndexOf('/providers/Microsoft.Authorization/', [StringComparison]::OrdinalIgnoreCase)
    $definedAt = $(if ($ix -gt 0) { $id.Substring(0, $ix) } else { 'Built-in' })
    $pnames = @()
    if ($null -ne $p.parameters) { $pnames = @($p.parameters.PSObject.Properties | ForEach-Object { $_.Name }) }
    return [pscustomobject]@{
        Id = $id; Name = [string]$D.name; DisplayName = [string]$p.displayName; PolicyType = [string]$p.policyType; Mode = [string]$p.mode
        Category = [string]$p.metadata.category; Version = [string](Get-A2CFirst $p @('version', 'metadata.version'))
        Deprecated = [bool]$p.metadata.deprecated; Preview = [bool]$p.metadata.preview; Effect = $effect; ParameterNames = (Join-A2C $pnames ', ')
        Description = [string]$p.description; IsSet = $isSet; Members = $members; SetParameters = $p.parameters; DefinedAt = $definedAt; Raw = $D
    }
}

function Get-A2CDatasetPolicyDefinitions {
    $defs = @{}
    $failed = [System.Collections.Generic.List[string]]::new()
    $filter = '&$filter=' + [uri]::EscapeDataString("policyType eq 'Custom'")
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        foreach ($kind in @('policyDefinitions', 'policySetDefinitions')) {
            $r = Invoke-A2CArmList (('/subscriptions/{0}/providers/Microsoft.Authorization/{1}?api-version={2}' -f $s.Id, $kind, $script:A2CApi.Policy) + $filter)
            if (-not $r.Ok) { $failed.Add($s.Name + ' ' + $kind + ': ' + (Get-A2CErrorText $r.Error)); continue }
            foreach ($d in $r.Items) { $k = ([string]$d.id).ToLowerInvariant(); if (-not $defs.ContainsKey($k)) { $defs[$k] = ConvertTo-A2CPolicyDefinition $d; Add-A2CRaw $kind $d } }
        }
    }
    foreach ($a in @($script:A2C.Data['PolicyAssignments'])) {
        if ($null -eq $a -or -not $a.DefinitionId) { continue }
        $k = $a.DefinitionId.ToLowerInvariant()
        if ($defs.ContainsKey($k)) { continue }
        $r = Invoke-A2CArm ('{0}?api-version={1}' -f $a.DefinitionId, $script:A2CApi.Policy)
        if ($r.Ok -and $null -ne $r.Json) { $defs[$k] = ConvertTo-A2CPolicyDefinition $r.Json; Add-A2CRaw $(if ($k -like '*/policysetdefinitions/*') { 'policySetDefinitions' } else { 'policyDefinitions' }) $r.Json }
        else { $failed.Add((Get-A2CNameFromId $a.DefinitionId) + ': ' + (Get-A2CErrorText $r.Error)) }
    }
    $script:A2C.Data['PolicyDefs'] = $defs
    $status = 'Collected'; $note = ''
    if ($failed.Count) { $status = 'Partial'; $note = [string]::Join(' | ', @($failed | Select-Object -First 5)) }
    Add-A2CCoverage -Area 'Policy definitions and initiatives (ARM)' -Status $status -Items $defs.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetManagementGroupScope {
    # Role and policy objects at management groups that no subscription in scope is below (an empty management group,
    # or one whose subscriptions are not in scope). The other management groups need no call: a subscription lists
    # everything it inherits. Adds to what the role and policy datasets of this run collected.
    $covered = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $script:A2C.Data['Subscriptions']) { foreach ($m in @($s.MgChain)) { if ($null -ne $m -and $m.Name) { [void]$covered.Add([string]$m.Name) } } }
    $mgs = @($script:A2C.Data['ManagementGroups'] | Where-Object { $null -ne $_ -and $_.Name -and -not $covered.Contains([string]$_.Name) })
    if ($mgs.Count -eq 0) {
        Add-A2CCoverage -Area 'Management groups without a subscription in scope (ARM)' -Status Collected -Items 0 -Detail 'Every management group has a subscription in scope below it'
        return New-A2CDatasetResult
    }
    $n = @{ MG = 0; RoleAssignments = 0; CustomRoles = 0; PolicyAssignments = 0; PolicyDefinitions = 0; PolicyExemptions = 0 }
    $failed = [System.Collections.Generic.List[string]]::new()
    $seenRa = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($script:A2C.Data['RoleAssignments'])) { if ($null -ne $a) { [void]$seenRa.Add($a.Id) } }
    $seenPa = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($script:A2C.Data['PolicyAssignments'])) { if ($null -ne $a) { [void]$seenPa.Add($a.Id) } }
    $seenPe = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($script:A2C.Data['PolicyExemptions'])) { if ($null -ne $a) { [void]$seenPe.Add($a.Id) } }
    $newPa = [System.Collections.Generic.List[object]]::new()
    $newPe = [System.Collections.Generic.List[object]]::new()
    $atScope = '&$filter=' + [uri]::EscapeDataString('atScope()')
    $custom = '&$filter=' + [uri]::EscapeDataString("policyType eq 'Custom'")
    $list = {
        # one list at a management group; a refusal is noted once per management group
        param([string] $Mg, [string] $What, [string] $Query)
        $r = Invoke-A2CArmList ('/providers/Microsoft.Management/managementGroups/{0}/providers/Microsoft.Authorization/{1}' -f [uri]::EscapeDataString($Mg), $Query)
        if (-not $r.Ok) { $failed.Add($Mg + ' ' + $What + ': ' + (Get-A2CErrorText $r.Error)); return @() }
        return @($r.Items)
    }
    $refused = 0
    foreach ($mg in $mgs) {
        $before = $failed.Count
        $name = [string]$mg.Name
        if (Test-A2CDataset 'RoleAssignments') {
            foreach ($a in (& $list $name 'role assignments' ('roleAssignments?api-version=' + $script:A2CApi.RoleAssignments + $atScope))) {
                if ($seenRa.Add([string]$a.id)) { $script:A2C.Data['RoleAssignments'].Add((ConvertTo-A2CRoleAssignment $a '')); Add-A2CRaw 'roleAssignments' $a; $n.RoleAssignments++ }
            }
        }
        if (Test-A2CDataset 'RoleDefinitions') {
            foreach ($d in (& $list $name 'custom roles' ('roleDefinitions?api-version=' + $script:A2CApi.RoleDefinitions + '&$filter=' + [uri]::EscapeDataString("type eq 'CustomRole'")))) {
                $g = ([string]$d.name).ToLowerInvariant()
                if (-not $script:A2C.Data['RoleDefs'].ContainsKey($g)) { $script:A2C.Data['RoleDefs'][$g] = ConvertTo-A2CRoleDefinition $d; Add-A2CRaw 'roleDefinitions' $d; $n.CustomRoles++ }
            }
        }
        if (Test-A2CDataset 'PolicyAssignments') {
            foreach ($a in (& $list $name 'policy assignments' ('policyAssignments?api-version=' + $script:A2CApi.Policy + $atScope))) {
                if ($seenPa.Add([string]$a.id)) { $newPa.Add((ConvertTo-A2CPolicyAssignment $a)); Add-A2CRaw 'policyAssignments' $a; $n.PolicyAssignments++ }
            }
        }
        if (Test-A2CDataset 'PolicyDefinitions') {
            foreach ($kind in @('policyDefinitions', 'policySetDefinitions')) {
                foreach ($d in (& $list $name $kind ($kind + '?api-version=' + $script:A2CApi.Policy + $custom))) {
                    $k = ([string]$d.id).ToLowerInvariant()
                    if (-not $script:A2C.Data['PolicyDefs'].ContainsKey($k)) { $script:A2C.Data['PolicyDefs'][$k] = ConvertTo-A2CPolicyDefinition $d; Add-A2CRaw $kind $d; $n.PolicyDefinitions++ }
                }
            }
        }
        if (Test-A2CDataset 'PolicyExemptions') {
            foreach ($e in (& $list $name 'policy exemptions' ('policyExemptions?api-version=' + $script:A2CApi.PolicyExemptions + $atScope))) {
                if ($seenPe.Add([string]$e.id)) { $newPe.Add((ConvertTo-A2CPolicyExemption $e)); Add-A2CRaw 'policyExemptions' $e; $n.PolicyExemptions++ }
            }
        }
        if ($failed.Count -eq $before) { $n.MG++ } else { $refused++ }
        if ($n.MG -eq 0 -and $refused -ge 3) { break }   # no read access at management groups
    }
    if ($newPa.Count -gt 0) {
        $script:A2C.Data['PolicyAssignments'] = @($script:A2C.Data['PolicyAssignments']) + $newPa.ToArray()
        # the definitions these assignments use (built-in ones are read one by one, like for the subscriptions)
        if (Test-A2CDataset 'PolicyDefinitions') {
            foreach ($a in $newPa) {
                $k = ([string]$a.DefinitionId).ToLowerInvariant()
                if (-not $k -or $script:A2C.Data['PolicyDefs'].ContainsKey($k)) { continue }
                $r = Invoke-A2CArm ('{0}?api-version={1}' -f $a.DefinitionId, $script:A2CApi.Policy)
                if ($r.Ok -and $null -ne $r.Json) { $script:A2C.Data['PolicyDefs'][$k] = ConvertTo-A2CPolicyDefinition $r.Json }
            }
        }
    }
    if ($newPe.Count -gt 0) { $script:A2C.Data['PolicyExemptions'] = @($script:A2C.Data['PolicyExemptions']) + $newPe.ToArray() }
    $total = $n.RoleAssignments + $n.CustomRoles + $n.PolicyAssignments + $n.PolicyDefinitions + $n.PolicyExemptions
    $note = '{0} of {1} management groups read: {2} role assignments, {3} custom roles, {4} policy assignments, {5} policy definitions, {6} exemptions that no subscription in scope inherits' -f
        $n.MG, $mgs.Count, $n.RoleAssignments, $n.CustomRoles, $n.PolicyAssignments, $n.PolicyDefinitions, $n.PolicyExemptions
    if ($failed.Count -gt 0) { $note += ' | ' + (Join-A2C @($failed | Select-Object -First 3) ' | ') }
    $status = $(if ($n.MG -eq 0) { 'Skipped' } elseif ($failed.Count -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'Management groups without a subscription in scope (ARM)' -Status $status -Items $total -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetDefenderPlans {
    # Microsoft Defender for Cloud plans of every subscription (one Resource Graph query)
    $q = @'
// a2c:defenderPlans
securityresources
| where type =~ 'microsoft.security/pricings'
| project id, name, type, subscriptionId, propertiesJson = tostring(properties)
'@
    $a = Invoke-A2CArg -Query $q -Subscriptions (Get-A2CInScopeSubIds)
    $script:A2C.Data['DefenderPlans'] = $a.Items
    $status = 'Collected'; $note = ''
    if (-not $a.Ok) { $status = $(if ($a.Items.Count -gt 0) { 'Partial' } else { 'Failed' }); $note = Get-A2CErrorText $a.Errors[0] }
    Add-A2CCoverage -Area 'Defender for Cloud plans (Resource Graph)' -Status $status -Items $a.Items.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetLighthouse {
    # Azure Lighthouse: the offers (registration definitions) and what was delegated (registration assignments)
    $q = @'
// a2c:lighthouse
managedservicesresources
| where type in~ ('microsoft.managedservices/registrationdefinitions', 'microsoft.managedservices/registrationassignments')
| project id, name, type, subscriptionId, propertiesJson = tostring(properties)
'@
    $a = Invoke-A2CArg -Query $q -Subscriptions (Get-A2CInScopeSubIds)
    $script:A2C.Data['Lighthouse'] = $a.Items
    $status = 'Collected'; $note = ''
    if (-not $a.Ok) { $status = $(if ($a.Items.Count -gt 0) { 'Partial' } else { 'Failed' }); $note = Get-A2CErrorText $a.Errors[0] }
    Add-A2CCoverage -Area 'Azure Lighthouse delegations (Resource Graph)' -Status $status -Items $a.Items.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetPolicyStates {
    $subs = Get-A2CInScopeSubIds
    $q1 = @'
// a2c:policyByAssignment
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend state = tostring(properties.complianceState), rid = tolower(tostring(properties.resourceId)), aid = tolower(tostring(properties.policyAssignmentId))
| extend w = case(state =~ 'NonCompliant', 3, state =~ 'Compliant', 2, state =~ 'Exempt', 1, 0)
| summarize w = max(w) by aid, rid
| summarize NonCompliant = countif(w == 3), Compliant = countif(w == 2), Exempt = countif(w == 1), Total = count() by id = aid
'@
    $q2 = @'
// a2c:policyNonCompliant
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| where tostring(properties.complianceState) =~ 'NonCompliant'
| project id, subscriptionId, resourceId = tostring(properties.resourceId), resourceType = tostring(properties.resourceType), assignmentId = tostring(properties.policyAssignmentId), definitionId = tostring(properties.policyDefinitionId), definitionRef = tostring(properties.policyDefinitionReferenceId), setDefinitionId = tostring(properties.policySetDefinitionId), action = tostring(properties.policyDefinitionAction), timestamp = tostring(properties.timestamp)
'@
    $a1 = Invoke-A2CArg -Query $q1 -Subscriptions $subs
    $byAssignment = @{}
    foreach ($x in $a1.Items) { $byAssignment[([string]$x.id).ToLowerInvariant()] = $x }
    $a2 = Invoke-A2CArg -Query $q2 -Subscriptions $subs
    $byResource = @{}
    foreach ($x in $a2.Items) { $k = ([string]$x.resourceId).ToLowerInvariant(); $byResource[$k] = [int]$byResource[$k] + 1 }
    $script:A2C.Data['PolicyByAssignment'] = $byAssignment
    $script:A2C.Data['PolicyNonCompliant'] = $a2.Items
    $script:A2C.Data['PolicyNcByResource'] = $byResource
    $status = 'Collected'; $note = ''
    if (-not $a1.Ok -or -not $a2.Ok) { $status = 'Partial'; $note = Get-A2CErrorText (@($a1.Errors) + @($a2.Errors))[0] }
    Add-A2CCoverage -Area 'Policy compliance (Resource Graph)' -Status $status -Items $a2.Items.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

$script:A2CMoveMinRows = 400

function ConvertTo-A2CMoveValue {
    # One cell of the Microsoft move-support table -> @(value, note); value: Yes, No, Partial, Pending, Manual, Unknown
    param([string] $Cell)
    $clean = ($Cell -replace '\*\*', '' -replace '<br\s*/?>', ' ' -replace '\[([^\]]*)\]\([^)]*\)', '$1' -replace '\s+', ' ').Trim()
    if (-not $clean) { return @('Unknown', '') }
    $v = 'Manual'
    if ($clean -match '^(?i)yes\b') { $v = $(if ($clean -cmatch '\bNo\b') { 'Partial' } else { 'Yes' }) }
    elseif ($clean -match '^(?i)no\b') { $v = $(if ($clean -cmatch '\bYes\b') { 'Partial' } else { 'No' }) }
    elseif ($clean -match '^(?i)pending') { $v = 'Pending' }
    $note = $clean
    if ($v -eq 'Yes' -or $v -eq 'No') { $note = ($clean -replace '^(?i)(yes|no)[\s;.,:-]*', '').Trim() }
    if ($v -eq 'Pending') { $note = '' }
    return @($v, $note)
}

function ConvertFrom-A2CMoveMarkdown {
    # Parses Microsoft Learn "move-support-resources.md" into type -> @{ RG; Sub; Region; Notes }
    param([string] $Text)
    $idx = @{}
    $ns = $null
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*#{2,3}\s+(.+?)\s*$') {
            $h = $Matches[1].Trim()
            $ns = $(if ($h -match '^[A-Za-z0-9]+\.[A-Za-z0-9.]+$') { $h.ToLowerInvariant() } else { $null })
            continue
        }
        if (-not $ns -or $line -notmatch '^\s*>?\s*\|') { continue }
        $cells = @(($line -replace '^\s*>?\s*\|', '') -split '\|')
        if ($cells.Count -lt 4) { continue }
        $t = $cells[0].Trim()
        if ($t -match '^(?i)resource type$' -or $t -match '^-+$') { continue }
        $t = ($t -replace '\*\*', '' -replace '\s*\(.*$', '' -replace '\s*/\s*', '/').Trim().ToLowerInvariant()
        if (-not $t -or $t -notmatch '^[a-z0-9./-]+$') { continue }
        $rg = ConvertTo-A2CMoveValue $cells[1]; $sub = ConvertTo-A2CMoveValue $cells[2]; $reg = ConvertTo-A2CMoveValue $cells[3]
        $notes = [System.Collections.Generic.List[string]]::new()
        if ($rg[1]) { $notes.Add('Resource group: ' + $rg[1]) }
        if ($sub[1]) { $notes.Add('Subscription: ' + $sub[1]) }
        if ($reg[1]) { $notes.Add('Region: ' + $reg[1]) }
        $idx[$ns + '/' + $t] = [pscustomobject]@{ RG = $rg[0]; Sub = $sub[0]; Region = $reg[0]; Notes = [string]::Join('; ', $notes) }
    }
    return $idx
}

function Get-A2CDatasetMoveData {
    $src = [string]$script:A2C.Options.MoveSupportFile
    $text = $null
    $origin = $script:A2CMoveSupportUrl
    if ($src -and $src -notmatch '^https?://') {
        if (-not (Test-Path -LiteralPath $src)) { throw ('MoveSupportFile not found: ' + $src) }
        $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $src).ProviderPath)
        $origin = $src
    }
    else {
        if ($src) { $origin = $src }
        $r = Invoke-A2CRequest -Method 'GET' -Uri $origin -Kind 'web' -MaxRetries 2
        if ($r.StatusCode -eq 200) { $text = $r.Content }
    }
    if (-not $text) {
        $note = 'Could not download ' + $origin + ' - move columns are empty. Offline? Use -MoveSupportFile with a local copy.'
        Write-A2CLog -Level Warn $note
        Add-A2CCoverage -Area 'Move support data (Microsoft Learn)' -Status Skipped -Detail $note
        return New-A2CDatasetResult -Status 'Skipped' -Note $note
    }
    $idx = ConvertFrom-A2CMoveMarkdown $text
    if ($idx.Count -lt $script:A2CMoveMinRows) {
        $note = ('Only {0} resource types parsed from {1} - the page format may have changed; move columns left empty' -f $idx.Count, $origin)
        Write-A2CLog -Level Warn $note
        Add-A2CCoverage -Area 'Move support data (Microsoft Learn)' -Status Failed -Detail $note
        return New-A2CDatasetResult -Status 'Failed' -Note $note
    }
    $script:A2C.Data['MoveIndex'] = $idx
    $script:A2C.Data['MoveSource'] = $origin
    Add-A2CCoverage -Area 'Move support data (Microsoft Learn)' -Status Collected -Items $idx.Count -Detail ('Source: ' + $origin + ' (CC BY 4.0)')
    return New-A2CDatasetResult
}

function Get-A2CDatasetAdvisor {
    $q = @'
// a2c:advisor
advisorresources
| where type =~ 'microsoft.advisor/recommendations'
| project id, subscriptionId, resourceGroup, propertiesJson = tostring(properties)
'@
    $a = Invoke-A2CArg -Query $q -Subscriptions (Get-A2CInScopeSubIds)
    $recs = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $a.Items) {
        $p = Get-A2CProps $row
        $ext = $p.extendedProperties
        $recs.Add([pscustomobject]@{
                Id = [string]$row.id; SubscriptionId = [string]$row.subscriptionId; Category = [string]$p.category; Impact = [string]$p.impact
                Problem = [string]$p.shortDescription.problem; Solution = [string]$p.shortDescription.solution
                ResourceId = [string]$p.resourceMetadata.resourceId; ImpactedField = [string]$p.impactedField; ImpactedValue = [string]$p.impactedValue
                LastUpdated = $p.lastUpdated; TypeId = [string]$p.recommendationTypeId
                Savings = $(if ($null -ne $ext) { $ext.savingsAmount } else { $null }); AnnualSavings = $(if ($null -ne $ext) { $ext.annualSavingsAmount } else { $null })
                Currency = $(if ($null -ne $ext) { [string]$ext.savingsCurrency } else { '' })
                SubCategory = $(if ($null -ne $ext) { [string]$ext.recommendationSubCategory } else { '' })
                RetirementFeature = $(if ($null -ne $ext) { [string]$ext.retirementFeatureName } else { '' })
                RetirementDate = $(if ($null -ne $ext) { [string]$ext.retirementDate } else { '' })
            })
    }
    $script:A2C.Data['Advisor'] = $recs
    $status = 'Collected'; $note = ''
    if (-not $a.Ok) { $status = 'Partial'; $note = Get-A2CErrorText $a.Errors[0] }
    Add-A2CCoverage -Area 'Advisor recommendations (Resource Graph)' -Status $status -Items $recs.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetCost {
    $days = [int]$script:A2C.Options.CostDays
    $to = $script:A2C.Now.Date.AddDays(-1)
    $from = $script:A2C.Now.Date.AddDays(-$days)
    $fmtFrom = $from.ToString('yyyy-MM-dd') + 'T00:00:00Z'
    $fmtTo = $to.ToString('yyyy-MM-dd') + 'T23:59:59Z'
    $byRes = @{}
    $bySub = @{}
    $unavailable = [System.Collections.Generic.List[string]]::new()
    $first = $true
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        if (-not $first) { Start-A2CSleep 1 }
        $first = $false
        $total = 0.0; $currency = ''; $status = 'Collected'
        foreach ($costCol in @('Cost', 'PreTaxCost')) {
            $body = '{"type":"ActualCost","timeframe":"Custom","timePeriod":{"from":"' + $fmtFrom + '","to":"' + $fmtTo + '"},"dataset":{"granularity":"None","aggregation":{"totalCost":{"name":"' + $costCol + '","function":"Sum"}},"grouping":[{"type":"Dimension","name":"ResourceId"}]}}'
            $uri = '/subscriptions/{0}/providers/Microsoft.CostManagement/query?api-version={1}' -f $s.Id, $script:A2CApi.CostManagement
            $retryCol = $false
            $guard = 0
            while ($uri -and $guard -lt 1000) {
                $guard++
                $r = Invoke-A2CArm -Path $uri -Method 'POST' -Body $body
                if ($r.Status -eq 204) { break }
                if (-not $r.Ok) {
                    if ($costCol -eq 'Cost' -and $r.Status -eq 400 -and ([string]$r.Error.Message -match "(?i)'Cost'|\bcolumn\b|aggregation")) { $retryCol = $true; break }
                    $status = 'Unavailable: ' + (Get-A2CErrorText $r.Error)
                    break
                }
                $cols = @($r.Json.properties.columns)
                $ci = -1; $ri = -1; $cui = -1
                for ($i = 0; $i -lt $cols.Count; $i++) {
                    $n = [string]$cols[$i].name
                    if ($ci -lt 0 -and @('Cost', 'PreTaxCost', 'CostUSD') -contains $n) { $ci = $i }
                    elseif ($n -eq 'ResourceId') { $ri = $i }
                    elseif ($n -eq 'Currency') { $cui = $i }
                }
                foreach ($row in @($r.Json.properties.rows)) {
                    if ($null -eq $row -or $ci -lt 0) { continue }
                    $v = [double]$row[$ci]
                    $rid = $(if ($ri -ge 0) { ([string]$row[$ri]).ToLowerInvariant() } else { '' })
                    if (-not $rid) { $rid = '(unassigned)' }
                    if ($cui -ge 0 -and $row[$cui]) { $currency = [string]$row[$cui] }
                    if (-not $byRes.ContainsKey($rid)) { $byRes[$rid] = [pscustomobject]@{ Cost = 0.0; Currency = $currency; SubscriptionId = $s.Id } }
                    $byRes[$rid].Cost = $byRes[$rid].Cost + $v
                    $total += $v
                }
                $uri = [string]$r.Json.properties.nextLink
            }
            if (-not $retryCol) { break }
        }
        foreach ($k in @($byRes.Keys)) { $x = $byRes[$k]; if ($x.SubscriptionId -eq $s.Id) { $x.Cost = [math]::Round($x.Cost, 2); if (-not $x.Currency) { $x.Currency = $currency } } }
        $bySub[$s.Id] = [pscustomobject]@{ Total = [math]::Round($total, 2); Currency = $currency; Status = $status }
        if ($status -ne 'Collected') { $unavailable.Add($s.Name + ': ' + $status) }
    }
    $script:A2C.Data['CostByResource'] = $byRes
    $script:A2C.Data['CostBySub'] = $bySub
    $script:A2C.Data['CostPeriod'] = @($from, $to)
    $st = 'Collected'; $note = ('{0} to {1}' -f $from.ToString('yyyy-MM-dd'), $to.ToString('yyyy-MM-dd'))
    if ($unavailable.Count -gt 0) { $st = $(if ($unavailable.Count -eq @($script:A2C.Data['Subscriptions']).Count) { 'Failed' } else { 'Partial' }); $note += '; ' + [string]::Join(' | ', $unavailable) }
    Add-A2CCoverage -Area 'Cost (Cost Management)' -Status $st -Items $byRes.Count -Detail $note
    return New-A2CDatasetResult -Status $st -Note $note
}

function Get-A2CSafeFileName {
    param([string] $Name)
    return (($Name -replace '[\\/:*?"<>|]', '_').Trim())
}

function Get-A2CDatasetRunbookContent {
    if ($script:A2C.Options.Mask) {
        Add-A2CCoverage -Area 'Runbook content export' -Status Skipped -Detail 'Disabled with -Mask (runbook code can contain names and secrets)'
        return New-A2CDatasetResult -Status 'Skipped' -Note 'Disabled with -Mask'
    }
    $map = @{}
    $failed = 0
    $rbs = Get-A2CResourcesOfType 'microsoft.automation/automationaccounts/runbooks'
    $i = 0; $t0 = [DateTime]::Now
    foreach ($rb in $rbs) {
        $i++
        Write-A2CProgress -Activity 'Runbook export' -Current $i -Total $rbs.Count -Started $t0 -Item ([string]$rb.name)
        $p = Get-A2CProps $rb
        $r = Invoke-A2CArm ('{0}/content?api-version={1}' -f [string]$rb.id, $script:A2CApi.Automation)
        if (-not $r.Ok) { $failed++ }
        if (-not $r.Ok) { Add-A2CCodeItem -Type 'Runbook' -Resource $rb -Item ([string]$rb.name) -Status 'Failed' -Detail (Get-A2CErrorText $r.Error); continue }
        $type = [string]$p.runbookType
        $ext = '.ps1'
        if ($type -like 'Python*') { $ext = '.py' } elseif ($type -like 'Graph*') { $ext = '.graphrunbook' }
        # code/<subscription>/<resource group>/<automation account>/runbooks/<runbook>
        $acct = Get-A2CIdSegment -Id ([string]$rb.id) -After 'automationAccounts'
        $file = '{0}/runbooks/{1}{2}' -f (Get-A2CCodeDir ([string]$rb.subscriptionId) (Get-A2CRgFromId ([string]$rb.id)) $acct), (Get-A2CSafePathSegment ([string]$rb.name)), $ext
        Save-A2CExportFile $file ([string]$r.Content) -Bom
        Add-A2CCodeItem -Type 'Runbook' -Resource $rb -Item ([string]$rb.name) -File $file
        $c = [string]$r.Content
        $map[([string]$rb.id).ToLowerInvariant()] = [pscustomobject]@{
            File = $file; UsesAzureRM = ($c -match '(?i)\bAzureRM\b|-AzureRm[A-Za-z]|AzureRm[A-Z][a-z]+-'); UsesRunAs = ($c -match '(?i)AzureRunAsConnection|AzureRunAsCertificate')
        }
    }
    Write-A2CProgress -Activity 'Runbook export' -Completed
    $script:A2C.Data['RunbookContent'] = $map
    $status = $(if ($failed -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'Runbook content export' -Status $status -Items $map.Count -Detail $(if ($failed) { "$failed runbook(s) without published content" } else { 'code\ folder' })
    return New-A2CDatasetResult -Status $status
}

# ---- Code stored in Azure (AzureCode, AppCode): code/<subscription>/<resource group>/<resource>/ --------------
function Get-A2CCodeDir {
    param([string] $SubscriptionId, [string] $ResourceGroup, [string] $Name)
    return ('code/{0}/{1}/{2}' -f (Get-A2CSafePathSegment (Get-A2CSubName $SubscriptionId)), (Get-A2CSafePathSegment $ResourceGroup), (Get-A2CSafePathSegment $Name))
}

function Get-A2CCodeDirOf {
    # The code folder of a resource; a display name can replace a resource name that is a GUID (workbooks, dashboards).
    param($Resource, [string] $DisplayName)
    $n = [string]$Resource.name
    if ($DisplayName) { $n = $DisplayName }
    return (Get-A2CCodeDir ([string]$Resource.subscriptionId) (Get-A2CRgFromId ([string]$Resource.id)) $n)
}

function Get-A2CUniqueFile {
    # A path not written yet in this run: "name.json" -> "name (2).json"
    param([string] $File)
    $f = $File; $n = 1
    while (Test-Path -LiteralPath ([IO.Path]::Combine($script:A2C.OutDir, $f))) { $n++; $f = $File -replace '(\.[^./]+)$', (' (' + $n + ')$1') }
    return $f
}

function Add-A2CCodeItem {
    # One row of code/index.csv: what was exported where, or why not.
    param([string] $Type, $Resource, [string] $Item, [string] $File = '', [string] $Status = 'Exported', [string] $Detail = '')
    $l = $script:A2C.Data['CodeIndex']
    if ($null -eq $l) { $l = [System.Collections.Generic.List[object]]::new(); $script:A2C.Data['CodeIndex'] = $l }
    $sub = [string]$Resource.subscriptionId
    $l.Add([ordered]@{ Type = $Type; SubscriptionName = $(if ($sub) { Get-A2CSubName $sub } else { '' }); ResourceGroup = Get-A2CRgFromId ([string]$Resource.id)
            Resource = [string]$Resource.name; Item = $Item; File = $File; Status = $Status; Detail = $Detail; ResourceId = [string]$Resource.id })
}

function Format-A2CJson {
    # Indents JSON text without parsing it again, so every string, number and date stays exactly as Azure returned it.
    param([string] $Json)
    if (-not $Json) { return $Json }
    $sb = [System.Text.StringBuilder]::new($Json.Length * 2)
    $indent = 0; $inString = $false; $escape = $false
    foreach ($ch in $Json.ToCharArray()) {
        if ($inString) {
            [void]$sb.Append($ch)
            if ($escape) { $escape = $false } elseif ($ch -eq '\') { $escape = $true } elseif ($ch -eq '"') { $inString = $false }
            continue
        }
        if ($ch -eq '"') { $inString = $true; [void]$sb.Append($ch) }
        elseif ($ch -eq '{' -or $ch -eq '[') { $indent++; [void]$sb.Append($ch).Append("`n").Append('  ' * $indent) }
        elseif ($ch -eq '}' -or $ch -eq ']') { $indent--; [void]$sb.Append("`n").Append('  ' * [math]::Max(0, $indent)).Append($ch) }
        elseif ($ch -eq ',') { [void]$sb.Append($ch).Append("`n").Append('  ' * $indent) }
        elseif ($ch -eq ':') { [void]$sb.Append(': ') }
        elseif (-not [char]::IsWhiteSpace($ch)) { [void]$sb.Append($ch) }
    }
    # empty objects/arrays back on one line (raw newlines never occur inside JSON strings)
    return [regex]::Replace($sb.ToString(), '([\[{])\n\s*([\]}])', '$1$2')
}

function ConvertTo-A2CCodeJson {
    # An object from a list call as indented JSON. Windows PowerShell writes the characters ' < > & as unicode escapes
    # (backslash u0027 and so on): they are put back, so policy rules and template expressions stay readable and both
    # editions write the same text.
    param($Object)
    $json = ConvertTo-Json -InputObject $Object -Depth 60 -Compress
    if ($json.IndexOf('\u00') -ge 0) {
        $json = [regex]::Replace($json, '\\\\|\\u00(27|3[cCeE]|26)', { param($m) if ($m.Value -eq '\\') { '\\' } else { [string][char][Convert]::ToInt32($m.Groups[1].Value, 16) } })
    }
    return (Format-A2CJson $json)
}

function Get-A2CJsonValueAt {
    # The text of the JSON value that starts at $Start (object, array, string or scalar).
    param([string] $Json, [int] $Start)
    $n = $Json.Length
    $ch = $Json[$Start]
    $i = $Start
    if ($ch -eq '{' -or $ch -eq '[') {
        $depth = 0
        while ($i -lt $n) {
            $c = $Json[$i]
            if ($c -eq '"') { $i++; while ($i -lt $n) { if ($Json[$i] -eq '\') { $i += 2; continue }; if ($Json[$i] -eq '"') { break }; $i++ } }
            elseif ($c -eq '{' -or $c -eq '[') { $depth++ }
            elseif ($c -eq '}' -or $c -eq ']') { $depth--; if ($depth -eq 0) { return $Json.Substring($Start, $i - $Start + 1) } }
            $i++
        }
        return $null
    }
    if ($ch -eq '"') {
        $i++
        while ($i -lt $n) { if ($Json[$i] -eq '\') { $i += 2; continue }; if ($Json[$i] -eq '"') { break }; $i++ }
        return $Json.Substring($Start, [math]::Min($n, $i + 1) - $Start)
    }
    while ($i -lt $n -and $Json[$i] -ne ',' -and $Json[$i] -ne '}' -and $Json[$i] -ne ']') { $i++ }
    return $Json.Substring($Start, $i - $Start).Trim()
}

function Get-A2CJsonMember {
    # The text of a top-level member of a JSON object exactly as it is in the text ($null when missing). An exported
    # template is written without parsing it, so every value and expression stays as Azure returned it.
    param([string] $Json, [string] $Name)
    if (-not $Json) { return $null }
    $n = $Json.Length
    $depth = 0; $i = 0
    while ($i -lt $n) {
        $ch = $Json[$i]
        if ($ch -eq '"') {
            $j = $i + 1
            while ($j -lt $n) { if ($Json[$j] -eq '\') { $j += 2; continue }; if ($Json[$j] -eq '"') { break }; $j++ }
            if ($depth -eq 1) {
                $k = $j + 1
                while ($k -lt $n -and [char]::IsWhiteSpace($Json[$k])) { $k++ }
                if ($k -lt $n -and $Json[$k] -eq ':' -and $Json.Substring($i + 1, $j - $i - 1) -ceq $Name) {
                    $k++
                    while ($k -lt $n -and [char]::IsWhiteSpace($Json[$k])) { $k++ }
                    if ($k -ge $n) { return $null }
                    return (Get-A2CJsonValueAt $Json $k)
                }
            }
            $i = $j + 1
            continue
        }
        if ($ch -eq '{' -or $ch -eq '[') { $depth++ } elseif ($ch -eq '}' -or $ch -eq ']') { $depth-- }
        $i++
    }
    return $null
}

function Save-A2CCodeFile {
    param([string] $Type, $Resource, [string] $Item, [string] $File, [string] $Text)
    Save-A2CExportFile $File $Text
    Add-A2CCodeItem -Type $Type -Resource $Resource -Item $Item -File $File
}

function Get-A2CArmOrThrow {
    param([string] $Path)
    $r = Invoke-A2CArm $Path
    if (-not $r.Ok) { throw (Get-A2CErrorText $r.Error) }
    return $r
}

function Export-A2CDscConfigurations {
    param($R)
    $l = Invoke-A2CArmList ('{0}/configurations?api-version={1}' -f $R.id, $script:A2CApi.Automation)
    if (-not $l.Ok) { throw (Get-A2CErrorText $l.Error) }
    foreach ($c in $l.Items) {
        $x = Invoke-A2CArm ('{0}/configurations/{1}/content?api-version={2}' -f $R.id, [uri]::EscapeDataString([string]$c.name), $script:A2CApi.Automation)
        if (-not $x.Ok) { Add-A2CCodeItem -Type 'DSC configuration' -Resource $R -Item ([string]$c.name) -Status 'Failed' -Detail (Get-A2CErrorText $x.Error); continue }
        Save-A2CCodeFile 'DSC configuration' $R ([string]$c.name) ('{0}/dsc/{1}.ps1' -f (Get-A2CCodeDirOf $R), (Get-A2CSafePathSegment ([string]$c.name))) ([string]$x.Content)
    }
}

function Export-A2CLogicApp {
    param($R)
    $x = Get-A2CArmOrThrow ('{0}?api-version={1}' -f $R.id, $script:A2CApi.Logic)
    Save-A2CCodeFile 'Logic App' $R 'workflow' ((Get-A2CCodeDirOf $R) + '/workflow.json') (Format-A2CJson $x.Content)
}

function Export-A2CDataFactory {
    param($R)
    $dir = Get-A2CCodeDirOf $R
    foreach ($k in @(@('pipelines', 'pipelines'), @('dataflows', 'dataflows'), @('datasets', 'datasets'), @('linkedservices', 'linkedServices'), @('triggers', 'triggers'))) {
        $l = Invoke-A2CArmList ('{0}/{1}?api-version={2}' -f $R.id, $k[0], $script:A2CApi.DataFactory)
        if (-not $l.Ok) { Add-A2CCodeItem -Type 'Data Factory' -Resource $R -Item $k[1] -Status 'Failed' -Detail (Get-A2CErrorText $l.Error); continue }
        foreach ($x in $l.Items) {
            Save-A2CCodeFile 'Data Factory' $R ($k[1] + '/' + [string]$x.name) ('{0}/{1}/{2}.json' -f $dir, $k[1], (Get-A2CSafePathSegment ([string]$x.name))) (ConvertTo-A2CCodeJson $x)
        }
    }
}

function Export-A2CStreamAnalytics {
    param($R)
    $x = Get-A2CArmOrThrow ('{0}?$expand=inputs,outputs,transformation,functions&api-version={1}' -f $R.id, $script:A2CApi.StreamAnalytics)
    $dir = Get-A2CCodeDirOf $R
    $q = [string](Get-A2CFirst $x.Json @('properties.transformation.properties.query'))
    if ($q) { Save-A2CCodeFile 'Stream Analytics' $R 'query' ($dir + '/query.asaql') $q }
    Save-A2CCodeFile 'Stream Analytics' $R 'job' ($dir + '/job.json') (Format-A2CJson $x.Content)
}

function Export-A2CTemplateSpec {
    param($R)
    $l = Invoke-A2CArmList ('{0}/versions?api-version={1}' -f $R.id, $script:A2CApi.TemplateSpecs)
    if (-not $l.Ok) { throw (Get-A2CErrorText $l.Error) }
    $dir = Get-A2CCodeDirOf $R
    foreach ($v in $l.Items) {
        $vn = [string]$v.name
        $x = Invoke-A2CArm ('{0}/versions/{1}?api-version={2}' -f $R.id, [uri]::EscapeDataString($vn), $script:A2CApi.TemplateSpecs)
        if (-not $x.Ok -or $null -eq $x.Json) { Add-A2CCodeItem -Type 'Template spec' -Resource $R -Item $vn -Status 'Failed' -Detail (Get-A2CErrorText $x.Error); continue }
        # the template itself, deployable as it is; linked templates and UI definition next to it
        Save-A2CCodeFile 'Template spec' $R $vn ('{0}/{1}.json' -f $dir, (Get-A2CSafePathSegment $vn)) (ConvertTo-A2CCodeJson $x.Json.properties.mainTemplate)
        if (@($x.Json.properties.linkedTemplates | Where-Object { $null -ne $_ }).Count -gt 0 -or $null -ne $x.Json.properties.uiFormDefinition) {
            Save-A2CCodeFile 'Template spec' $R ($vn + ' (full)') ('{0}/{1}.version.json' -f $dir, (Get-A2CSafePathSegment $vn)) (Format-A2CJson $x.Content)
        }
    }
}

function Export-A2CDeploymentScript {
    param($R)
    $x = Get-A2CArmOrThrow ('{0}?api-version={1}' -f $R.id, $script:A2CApi.DeploymentScripts)
    $dir = Get-A2CCodeDirOf $R
    $p = $x.Json.properties
    if ($p.scriptContent) { Save-A2CCodeFile 'Deployment script' $R 'script' ($dir + $(if ([string]$x.Json.kind -eq 'AzureCLI') { '/script.sh' } else { '/script.ps1' })) ([string]$p.scriptContent) }
    elseif ($p.primaryScriptUri) { Add-A2CCodeItem -Type 'Deployment script' -Resource $R -Item 'script' -Status 'Reference' -Detail ('External script: ' + ([string]$p.primaryScriptUri -replace '\?.*$', '')) }
    Save-A2CCodeFile 'Deployment script' $R 'definition' ($dir + '/deploymentScript.json') (Format-A2CJson $x.Content)
}

function Export-A2CWorkbook {
    param($R)
    $x = Get-A2CArmOrThrow ('{0}?canFetchContent=true&api-version={1}' -f $R.id, $script:A2CApi.Workbooks)
    $name = [string]$x.Json.properties.displayName
    Save-A2CCodeFile 'Workbook' $R $name (Get-A2CUniqueFile ((Get-A2CCodeDirOf $R $name) + '/workbook.json')) (Format-A2CJson ([string]$x.Json.properties.serializedData))
}

function Export-A2CDashboard {
    param($R)
    $x = Get-A2CArmOrThrow ('{0}?api-version={1}' -f $R.id, $script:A2CApi.Dashboards)
    $title = ''
    if ($null -ne $R.tags -and $null -ne $R.tags.PSObject.Properties['hidden-title']) { $title = [string]$R.tags.'hidden-title' }
    Save-A2CCodeFile 'Dashboard' $R $title (Get-A2CUniqueFile ((Get-A2CCodeDirOf $R $title) + '/dashboard.json')) (Format-A2CJson $x.Content)
}

function Export-A2CLogAlert {
    # scheduled query (log search) alert rules: the KQL and the rule; from the Resource Graph data (no call)
    param($R)
    $p = Get-A2CProps $R
    $queries = @($p.criteria.allOf | Where-Object { $null -ne $_ -and $_.query } | ForEach-Object { [string]$_.query })
    if ($queries.Count -eq 0 -and $null -ne $p.source -and $p.source.query) { $queries = @([string]$p.source.query) }   # 2018 API shape
    $dir = Get-A2CCodeDirOf $R
    if ($queries.Count -gt 0) { Save-A2CCodeFile 'Log alert rule' $R 'query' ($dir + '/query.kql') ([string]::Join("`n`n", $queries)) }
    Save-A2CCodeFile 'Log alert rule' $R 'rule' ($dir + '/rule.json') (Format-A2CJson ([string]$R.propertiesJson))
}

function Export-A2CSentinelRules {
    # analytics rules of a Microsoft Sentinel workspace; $R is its SecurityInsights(<workspace>) solution
    param($R)
    $ws = [string](Get-A2CProps $R).workspaceResourceId
    if (-not $ws) { return }
    $l = Invoke-A2CArmList ('{0}/providers/Microsoft.SecurityInsights/alertRules?api-version={1}' -f $ws, $script:A2CApi.Sentinel)
    if (-not $l.Ok) { throw (Get-A2CErrorText $l.Error) }
    $wsRes = [pscustomobject]@{ id = $ws; name = (Get-A2CNameFromId $ws); subscriptionId = (Get-A2CSubIdFromId $ws) }
    $dir = (Get-A2CCodeDirOf $wsRes) + '/sentinel/'
    foreach ($x in $l.Items) {
        $name = [string]$x.properties.displayName
        if (-not $name) { $name = [string]$x.name }
        $json = Get-A2CUniqueFile ($dir + (Get-A2CSafePathSegment $name) + '.json')
        Save-A2CCodeFile 'Sentinel analytics rule' $wsRes $name $json (ConvertTo-A2CCodeJson $x)
        if ($x.properties.query) { Save-A2CCodeFile 'Sentinel analytics rule' $wsRes ($name + ' query') ($json -replace '\.json$', '.kql') ([string]$x.properties.query) }
    }
}

function Export-A2CApiManagement {
    # the global policy, and per API its policy and OpenAPI definition
    param($R)
    $dir = Get-A2CCodeDirOf $R
    $api = $script:A2CApi.ApiManagement
    $g = Invoke-A2CArm ('{0}/policies/policy?format=rawxml&api-version={1}' -f $R.id, $api)
    if ($g.Ok -and $null -ne $g.Json) { Save-A2CCodeFile 'API Management' $R 'global policy' ($dir + '/policy.xml') ([string]$g.Json.properties.value) }
    $l = Invoke-A2CArmList ('{0}/apis?api-version={1}' -f $R.id, $api)
    if (-not $l.Ok) { throw (Get-A2CErrorText $l.Error) }
    foreach ($a in $l.Items) {
        $an = [string]$a.name
        if ($an -like '*;rev=*') { continue }   # older revisions of an API
        $adir = '{0}/apis/{1}' -f $dir, (Get-A2CSafePathSegment $an)
        $ap = Invoke-A2CArm ('{0}/apis/{1}/policies/policy?format=rawxml&api-version={2}' -f $R.id, [uri]::EscapeDataString($an), $api)
        if ($ap.Ok -and $null -ne $ap.Json) { Save-A2CCodeFile 'API Management' $R ($an + ' policy') ($adir + '/policy.xml') ([string]$ap.Json.properties.value) }
        # the export returns a short-lived download link
        $ex = Invoke-A2CArm ('{0}/apis/{1}?format=openapi%2Bjson-link&export=true&api-version={2}' -f $R.id, [uri]::EscapeDataString($an), $api)
        $link = ''
        if ($ex.Ok -and $null -ne $ex.Json) { $link = [string](Get-A2CFirst $ex.Json @('value.link', 'properties.value.link')) }
        $d = $null
        if ($link) { $d = Invoke-A2CRequest -Method GET -Uri $link -Kind 'web' }
        if ($null -ne $d -and $d.StatusCode -eq 200) { Save-A2CCodeFile 'API Management' $R ($an + ' OpenAPI') ($adir + '/openapi.json') (Format-A2CJson ([string]$d.Content)) }
        else { Add-A2CCodeItem -Type 'API Management' -Resource $R -Item ($an + ' OpenAPI') -Status 'Failed' -Detail 'No OpenAPI export (SOAP, GraphQL and WebSocket APIs have none)' }
    }
}

function Export-A2CPolicyCode {
    # custom policy definitions and initiatives -> code/policy/definitions|initiatives/<display name>.json
    foreach ($d in @($script:A2C.Data['PolicyDefs'].Values)) {
        if ($null -eq $d -or $d.PolicyType -ne 'Custom' -or $null -eq $d.Raw) { continue }
        $name = $d.DisplayName
        if (-not $name) { $name = $d.Name }
        $res = [pscustomobject]@{ id = $d.Id; name = $d.Name; subscriptionId = (Get-A2CSubIdFromId $d.Id) }
        $file = Get-A2CUniqueFile ('code/policy/{0}/{1}.json' -f $(if ($d.IsSet) { 'initiatives' } else { 'definitions' }), (Get-A2CSafePathSegment $name))
        Save-A2CCodeFile $(if ($d.IsSet) { 'Policy initiative' } else { 'Policy definition' }) $res $name $file (ConvertTo-A2CCodeJson $d.Raw)
    }
}

function Export-A2CRoleCode {
    # custom RBAC roles in the input format of New-AzRoleDefinition -> code/roles/<role>.json
    foreach ($rd in @($script:A2C.Data['RoleDefs'].Values)) {
        if ($null -eq $rd -or $rd.Type -ne 'CustomRole') { continue }
        $o = [ordered]@{ Name = $rd.RoleName; Id = $rd.Guid; IsCustom = $true; Description = $rd.Description; Actions = @($rd.Actions); NotActions = @($rd.NotActions)
            DataActions = @($rd.DataActions); NotDataActions = @($rd.NotDataActions); AssignableScopes = @($rd.AssignableScopes) }
        $res = [pscustomobject]@{ id = $rd.Id; name = $rd.RoleName; subscriptionId = '' }
        Save-A2CCodeFile 'Custom role' $res $rd.RoleName (Get-A2CUniqueFile ('code/roles/{0}.json' -f (Get-A2CSafePathSegment $rd.RoleName))) (ConvertTo-A2CCodeJson $o)
    }
}

function Get-A2CDatasetAzureCode {
    # Code and definitions stored in Azure resources (read-only calls); runbooks come from the RunbookContent dataset.
    if ($script:A2C.Options.Mask) {
        Add-A2CCoverage -Area 'Code export' -Status Skipped -Detail 'Disabled with -Mask (code and definitions contain names and settings)'
        return New-A2CDatasetResult -Status 'Skipped' -Note 'Disabled with -Mask'
    }
    $steps = @(
        @('DSC configuration', 'microsoft.automation/automationaccounts', 'Export-A2CDscConfigurations'),
        @('Logic App', 'microsoft.logic/workflows', 'Export-A2CLogicApp'),
        @('Data Factory', 'microsoft.datafactory/factories', 'Export-A2CDataFactory'),
        @('Stream Analytics', 'microsoft.streamanalytics/streamingjobs', 'Export-A2CStreamAnalytics'),
        @('Template spec', 'microsoft.resources/templatespecs', 'Export-A2CTemplateSpec'),
        @('Deployment script', 'microsoft.resources/deploymentscripts', 'Export-A2CDeploymentScript'),
        @('Workbook', 'microsoft.insights/workbooks', 'Export-A2CWorkbook'),
        @('Dashboard', 'microsoft.portal/dashboards', 'Export-A2CDashboard'),
        @('Log alert rule', 'microsoft.insights/scheduledqueryrules', 'Export-A2CLogAlert'),
        @('Sentinel analytics rule', 'microsoft.operationsmanagement/solutions', 'Export-A2CSentinelRules'),
        @('API Management', 'microsoft.apimanagement/service', 'Export-A2CApiManagement'))
    $work = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $steps) {
        foreach ($r in (Get-A2CResourcesOfType $s[1])) {
            if ($s[2] -eq 'Export-A2CSentinelRules' -and [string]$r.name -notlike 'SecurityInsights(*') { continue }
            $work.Add([pscustomobject]@{ Step = $s; Resource = $r })
        }
    }
    $i = 0; $t0 = [DateTime]::Now
    foreach ($w in $work) {
        $i++
        Write-A2CProgress -Activity 'Code export' -Current $i -Total $work.Count -Started $t0 -Item ([string]$w.Resource.name)
        try { & $w.Step[2] $w.Resource }
        catch { Add-A2CCodeItem -Type $w.Step[0] -Resource $w.Resource -Item '' -Status 'Failed' -Detail (Get-A2CShortText $_.Exception.Message 200) }
    }
    Write-A2CProgress -Activity 'Code export' -Completed
    Export-A2CPolicyCode
    Export-A2CRoleCode
    $items = @($script:A2C.Data['CodeIndex'] | Where-Object { $null -ne $_ })
    $ok = @($items | Where-Object { $_['Status'] -eq 'Exported' }).Count
    $bad = @($items | Where-Object { $_['Status'] -eq 'Failed' })
    $byType = Get-A2CTopText @($items | Where-Object { $_['Status'] -eq 'Exported' } | ForEach-Object { $_['Type'] }) 20
    foreach ($b in $bad) { Write-A2CLog -Level Verbose ('Code export failed: {0} {1} {2}: {3}' -f $b['Type'], $b['Resource'], $b['Item'], $b['Detail']) }
    $status = $(if ($bad.Count -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'Code export' -Status $status -Items $ok -Detail ($byType + $(if ($bad.Count) { ('; {0} not exported (code\index.csv)' -f $bad.Count) } else { '' }))
    Write-A2CLog -Level Ok ('Code export: {0} files ({1}), {2} not exported' -f $ok, $byType, $bad.Count)
    return New-A2CDatasetResult -Status $status
}

function Get-A2CDatasetAppCode {
    # Files of every Function App and Web App: the Kudu zip of site/wwwroot -> code/<subscription>/<rg>/<app>/wwwroot/.
    # Kudu needs publish rights (Website Contributor or more); without them each app is listed as not exported.
    if ($script:A2C.Options.Mask) {
        Add-A2CCoverage -Area 'App code export' -Status Skipped -Detail 'Disabled with -Mask (application code)'
        return New-A2CDatasetResult -Status 'Skipped' -Note 'Disabled with -Mask'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [IO.Path]::Combine($script:A2C.OutDir, '.cache-app.zip')
    $apps = Get-A2CResourcesOfType 'microsoft.web/sites'
    $done = 0; $failed = 0
    $i = 0; $t0 = [DateTime]::Now
    foreach ($r in $apps) {
        $i++
        Write-A2CProgress -Activity 'App code export' -Current $i -Total $apps.Count -Started $t0 -Item ([string]$r.name)
        $p = Get-A2CProps $r
        $scm = @($p.hostNameSslStates | Where-Object { $null -ne $_ -and [string]$_.hostType -eq 'Repository' } | ForEach-Object { [string]$_.name })
        $scmHost = $(if ($scm.Count -gt 0) { $scm[0] } else { [string]$r.name + '.scm.azurewebsites.net' })
        $free = Get-A2CFreeSpace $script:A2C.OutDir
        if ($null -ne $free -and $free -lt 1GB) { Add-A2CCodeItem -Type 'App code' -Resource $r -Item 'wwwroot' -Status 'Skipped' -Detail 'Less than 1 GB free disk space'; continue }
        $dir = (Get-A2CCodeDirOf $r) + '/wwwroot'
        try {
            $x = Invoke-A2CRequest -Method GET -Uri ('https://{0}/api/zip/site/wwwroot/' -f $scmHost) -Kind 'kudu' -OutFile $zip
            if ($x.StatusCode -lt 200 -or $x.StatusCode -ge 300) {
                $why = Get-A2CErrorText (Get-A2CError $x)
                if ($x.StatusCode -eq 401 -or $x.StatusCode -eq 403) { $why = 'Needs publish rights (Website Contributor) on the app - ' + $why }
                throw $why
            }
            $full = [IO.Path]::Combine($script:A2C.OutDir, $dir)
            [void][IO.Directory]::CreateDirectory($full)
            [IO.Compression.ZipFile]::ExtractToDirectory($zip, $full)
            Add-A2CCodeItem -Type 'App code' -Resource $r -Item 'wwwroot' -File $dir
            $done++
        }
        catch { Add-A2CCodeItem -Type 'App code' -Resource $r -Item 'wwwroot' -Status 'Failed' -Detail (Get-A2CShortText $_.Exception.Message 200); $failed++ }
        finally { if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue } }
    }
    Write-A2CProgress -Activity 'App code export' -Completed
    $status = $(if ($failed -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'App code export' -Status $status -Items $done -Detail $(if ($failed) { ('{0} app(s) not exported (code\index.csv)' -f $failed) } else { '' })
    Write-A2CLog -Level Ok ('App code: {0} app(s) exported, {1} not exported' -f $done, $failed)
    return New-A2CDatasetResult -Status $status
}

# ---- ARM templates (ArmTemplates): Azure's own template export of every resource group -> templates/ ----------
$script:A2CTemplateBatch = 200                            # Azure exports at most 200 resources in one call
$script:A2CTemplateMinBatch = 25                          # a batch Azure still refuses is halved down to this size
$script:A2CTemplateOptions = 'SkipAllParameterization'    # names and values stay where they are used (no parameters)

function Invoke-A2CArmLongRunning {
    # An ARM POST that can answer 202 Accepted: the result is then read from the Location URL until it is ready.
    # Returns the object of Invoke-A2CArm (Ok = $false when the operation did not finish in time).
    param([string] $Path, [string] $Body, [int] $MaxWaitSec = 900)
    $r = Invoke-A2CArm -Path $Path -Method 'POST' -Body $Body
    $next = ''
    $waited = 0.0
    while ($r.Status -eq 202) {
        $loc = [string]$r.Headers['Location']
        if ($loc) { $next = $loc }
        $why = ''
        if (-not $next) { $why = 'Accepted (HTTP 202) without a Location to read the result from' }
        elseif ($waited -ge $MaxWaitSec) { $why = 'No result after {0} seconds' -f [int]$waited }
        if ($why) {
            return [pscustomobject]@{ Ok = $false; Status = 202; Json = $null; Content = ''; Error = [pscustomobject]@{ Status = 202; Code = 'NotFinished'; Message = $why }; Headers = @{} }
        }
        $delay = ConvertTo-A2CSeconds $r.Headers['Retry-After']
        if ($delay -le 0) { $delay = 5 }
        $delay = [math]::Min(60, $delay)
        Start-A2CSleep -Seconds $delay
        $waited += $delay
        $r = Invoke-A2CArm -Path $next
    }
    return $r
}

function Export-A2CTemplate {
    # One exportTemplate call for a resource group. Returns Ok, Format, Text (the template exactly as Azure returned
    # it, or the Bicep text), Resources (number of resources in the template, -1 = unknown), Issues (what Azure did
    # not export) and Error.
    param([string] $Path, [string] $ApiVersion, [string[]] $Resources, [string] $Format = 'Json')
    $ids = [string]::Join(',', @($Resources | ForEach-Object { ConvertTo-A2CJsonLiteral $_ }))
    $body = '{"resources":[' + $ids + '],"options":"' + $script:A2CTemplateOptions + '"'
    if ($Format -eq 'Bicep') { $body += ',"outputFormat":"Bicep"' }
    $body += '}'
    $r = Invoke-A2CArmLongRunning -Path ('{0}/exportTemplate?api-version={1}' -f $Path, $ApiVersion) -Body $body
    $out = [pscustomobject]@{ Ok = $false; Format = $Format; Text = ''; Resources = -1; Issues = [System.Collections.Generic.List[object]]::new(); Error = $null }
    if (-not $r.Ok) { $out.Error = $r.Error; return $out }
    # error.details names every resource type Azure could not export; the call itself still answers 200
    $e = $null
    $errText = Get-A2CJsonMember $r.Content 'error'
    if ($errText -and $errText -ne 'null') { try { $e = ConvertFrom-A2CJson $errText } catch { $e = $null } }
    if ($null -ne $e) {
        foreach ($d in @($e.details)) {
            if ($null -ne $d) { $out.Issues.Add([pscustomobject]@{ Code = [string]$d.code; Target = [string]$d.target; Message = [string]$d.message }) }
        }
    }
    if ($Format -eq 'Bicep') {
        if ($null -ne $r.Json -and $r.Json.output) { $out.Text = [string]$r.Json.output }
        elseif (Get-A2CJsonMember $r.Content 'template') {
            $out.Error = [pscustomobject]@{ Status = [int]$r.Status; Code = 'BicepNotSupported'; Message = 'Azure answered with a JSON template: no Bicep output here' }
            return $out
        }
    }
    else {
        $t = Get-A2CJsonMember $r.Content 'template'
        if ($t -and $t -ne 'null') {
            $out.Text = $t
            if ($null -ne $r.Json -and $null -ne $r.Json.template) { $out.Resources = @($r.Json.template.resources | Where-Object { $null -ne $_ }).Count }
        }
    }
    if (-not $out.Text) {
        $code = 'NoTemplate'
        $msg = 'The answer holds no ' + $(if ($Format -eq 'Bicep') { 'Bicep output' } else { 'template' })
        if ($null -ne $e -and ($e.code -or $e.message)) { $code = [string]$e.code; $msg = [string]$e.message }
        $out.Error = [pscustomobject]@{ Status = [int]$r.Status; Code = $code; Message = $msg }
        return $out
    }
    $out.Ok = $true
    return $out
}

function Export-A2CResourceGroupTemplates {
    # Exports one resource group and returns its row of templates/index.csv. $State holds what the run has learned:
    # the API version in use, whether Bicep is available, subscriptions that refuse the export.
    param($Rg, $Rows, $State)
    $sub = ([string]$Rg.subscriptionId).ToLowerInvariant()
    $subName = Get-A2CSubName $sub
    if (-not $subName) { $subName = $sub }
    $name = [string]$Rg.name
    $row = [ordered]@{ SubscriptionName = $subName; ResourceGroup = $name; Location = [string]$Rg.location; Resources = $(if ($State.HaveResources) { $Rows.Count } else { $null })
        Status = 'Not exported'; TemplateResources = $null; JsonFile = ''; BicepFile = ''; NotExported = $null; NotExportedTypes = ''; Detail = ''; ResourceGroupId = [string]$Rg.id }
    if ($State.HaveResources -and $Rows.Count -eq 0) { $row.Status = 'Empty'; $row.Detail = 'No resources in this resource group'; return $row }
    if ($State.Denied.ContainsKey($sub)) { $row.Detail = $State.Denied[$sub]; return $row }
    $path = '/subscriptions/{0}/resourcegroups/{1}' -f $sub, [uri]::EscapeDataString($name)
    $base = 'templates/{0}/{1}' -f (Get-A2CSafePathSegment $subName), (Get-A2CSafePathSegment $name)
    $parts = [System.Collections.Generic.List[object]]::new()
    $parts.Add(@('*'))
    $split = $false
    $notes = [System.Collections.Generic.List[string]]::new()
    $issues = [System.Collections.Generic.List[object]]::new()
    $files = @{ Json = [System.Collections.Generic.List[string]]::new(); Bicep = [System.Collections.Generic.List[string]]::new() }
    $count = 0; $countKnown = $true; $failed = 0; $stop = $false
    for ($i = 0; $i -lt $parts.Count -and -not $stop; $i++) {
        $suffix = ''
        if ($split -and $parts.Count -gt 1) { $suffix = ' (part {0})' -f ($i + 1) }
        $redo = $false; $partIssues = $false; $jsonTried = $false
        foreach ($f in @('Json', 'Bicep')) {
            $fmt = $f
            if (-not $State.$fmt) { continue }
            $x = Export-A2CTemplate -Path $path -ApiVersion $State.Api -Resources $parts[$i] -Format $fmt
            if (-not $x.Ok -and $State.Api -ne $script:A2CApi.ExportTemplateOld -and [int]$x.Error.Status -eq 400 -and ([string]$x.Error.Code + ' ' + [string]$x.Error.Message) -match '(?i)api-?version|NoRegisteredProviderFound') {
                # a cloud without the current API version: the older one answers with JSON only
                $State.Notes.Add(('API version {0} is not available here; {1} was used, which has no Bicep output' -f $State.Api, $script:A2CApi.ExportTemplateOld))
                $State.Api = $script:A2CApi.ExportTemplateOld
                $State.Bicep = $false; $State.Json = $true
                $fmt = 'Json'
                $x = Export-A2CTemplate -Path $path -ApiVersion $State.Api -Resources $parts[$i] -Format $fmt
            }
            if (-not $x.Ok -and ([string]$x.Error.Code + ' ' + [string]$x.Error.Message) -match '(?i)ResourcesLimitExceeded|more than 200 resources') {
                # too many resources for one call: the resources are exported in batches, each batch its own template
                $ids = @($parts[$i])
                $size = [int][math]::Ceiling($ids.Count / 2)
                if (-not $split) { $ids = @($Rows | Sort-Object { [string]$_.type }, { [string]$_.name } | ForEach-Object { [string]$_.id }); $size = $script:A2CTemplateBatch }
                if ($ids.Count -ge 2 -and ($ids.Count -gt $script:A2CTemplateMinBatch -or -not $split)) {
                    $chunks = [System.Collections.Generic.List[object]]::new()
                    for ($k = 0; $k -lt $ids.Count; $k += $size) { $chunks.Add(@($ids[$k..([math]::Min($k + $size, $ids.Count) - 1)])) }
                    $parts.RemoveAt($i)
                    $parts.InsertRange($i, $chunks)
                    $split = $true; $redo = $true
                    break
                }
            }
            if (-not $x.Ok -and $fmt -eq 'Bicep' -and [string]$x.Error.Code -eq 'BicepNotSupported') {
                # the outputFormat was ignored: JSON templates for the rest of the run
                $State.Bicep = $false; $State.Json = $true
                $State.Notes.Add('Azure did not return Bicep here; JSON templates only')
                if ($jsonTried) { continue }
                $fmt = 'Json'
                $x = Export-A2CTemplate -Path $path -ApiVersion $State.Api -Resources $parts[$i] -Format $fmt
            }
            if ($fmt -eq 'Json') { $jsonTried = $true }
            if (-not $x.Ok) {
                $failed++
                $st = [int]$x.Error.Status
                $notes.Add(('{0}{1}: {2}' -f $fmt, $suffix, (Get-A2CShortText (Get-A2CErrorText $x.Error) 220)))
                if ($st -eq 401 -or $st -eq 403) {
                    $State.Refused[$sub] = [int]$State.Refused[$sub] + 1
                    if ($State.Refused[$sub] -ge 3 -and -not $State.Worked.Contains($sub)) {
                        $State.Denied[$sub] = 'No permission to export templates in this subscription (three resource groups refused, the others were not tried)'
                    }
                }
                # no permission, or the resource group is gone: the other format and the other parts get the same answer
                if ($st -eq 401 -or $st -eq 403 -or $st -eq 404) { $stop = $true; break }
                continue
            }
            $file = $base + $suffix + $(if ($fmt -eq 'Bicep') { '.bicep' } else { '.json' })
            try { Save-A2CExportFile $file $(if ($fmt -eq 'Bicep') { Protect-A2CSecretText $x.Text -Bicep } else { Format-A2CJson (Protect-A2CSecretText $x.Text -Template) }) }
            catch { $failed++; $notes.Add(('{0}{1}: file not written - {2}' -f $fmt, $suffix, (Get-A2CShortText $_.Exception.Message 160))); continue }
            $files[$fmt].Add($file)
            [void]$State.Worked.Add($sub)
            if ($fmt -eq 'Json') { if ($x.Resources -ge 0) { $count += $x.Resources } else { $countKnown = $false } }
            # both formats report the same gaps: they are listed once per part
            if (-not $partIssues) { $partIssues = $true; foreach ($d in $x.Issues) { $issues.Add($d) } }
        }
        if ($redo) { $i-- }
    }
    $row.JsonFile = Join-A2C $files.Json
    $row.BicepFile = Join-A2C $files.Bicep
    if ($files.Json.Count -gt 0 -and $countKnown) { $row.TemplateResources = $count }
    if ($files.Json.Count + $files.Bicep.Count -gt 0) {
        $row.NotExported = $issues.Count
        $row.NotExportedTypes = Join-A2C (Get-A2CUnique @($issues | ForEach-Object { $_.Target }))
        $row.Status = $(if ($failed -gt 0 -or $issues.Count -gt 0) { 'Partial' } else { 'Exported' })
        if ($split) { $notes.Insert(0, ('Too many resources for one export call: exported by resource ID in {0} part(s)' -f $parts.Count)) }
        foreach ($d in $issues) {
            $State.Issues.Add([ordered]@{ SubscriptionName = $subName; ResourceGroup = $name; Target = $d.Target; Code = $d.Code; Message = $d.Message })
        }
    }
    $row.Detail = Join-A2C $notes ' | '
    return $row
}

function Get-A2CDatasetArmTemplates {
    # Azure's own template export ("Export template" in the portal) for every resource group: the ARM template as JSON
    # and as Bicep, written the way Azure returned it, plus the list of what Azure did not export. It is a starting
    # point for infrastructure as code and not a tested deployment: secrets and some resource types are never in it.
    if ($script:A2C.Options.Mask) {
        Add-A2CCoverage -Area 'ARM template export' -Status Skipped -Detail 'Disabled with -Mask (complete resource definitions)'
        return New-A2CDatasetResult -Status 'Skipped' -Note 'Disabled with -Mask'
    }
    $format = [string]$script:A2C.Options.TemplateFormat
    $state = [pscustomobject]@{ Api = $script:A2CApi.ExportTemplate; Json = ($format -ne 'Bicep'); Bicep = ($format -ne 'Json'); HaveResources = (Test-A2CDataset 'Resources')
        Denied = @{}; Refused = @{}; Worked = [System.Collections.Generic.HashSet[string]]::new()
        Notes = [System.Collections.Generic.List[string]]::new(); Issues = [System.Collections.Generic.List[object]]::new() }
    # the resources of every resource group (Resource Graph): empty groups are not asked for, large ones go in parts
    $byRg = @{}
    foreach ($r in @($script:A2C.Data['Resources'])) {
        if ($null -eq $r) { continue }
        $k = ((Get-A2CSubIdFromId ([string]$r.id)) + '/' + (Get-A2CRgFromId ([string]$r.id))).ToLowerInvariant()
        if (-not $byRg.ContainsKey($k)) { $byRg[$k] = [System.Collections.Generic.List[object]]::new() }
        $byRg[$k].Add($r)
    }
    $rgs = @($script:A2C.Data['ResourceGroups'] | Where-Object { $null -ne $_ } | Sort-Object { Get-A2CSubName ([string]$_.subscriptionId) }, { [string]$_.name })
    $index = [System.Collections.Generic.List[object]]::new()
    $i = 0; $t0 = [DateTime]::Now
    foreach ($rg in $rgs) {
        $i++
        Write-A2CProgress -Activity 'ARM template export' -Current $i -Total $rgs.Count -Started $t0 -Item ([string]$rg.name)
        $rows = $byRg[(([string]$rg.subscriptionId) + '/' + [string]$rg.name).ToLowerInvariant()]
        if ($null -eq $rows) { $rows = [System.Collections.Generic.List[object]]::new() }
        try { $row = Export-A2CResourceGroupTemplates -Rg $rg -Rows $rows -State $state }
        catch {
            $row = [ordered]@{ SubscriptionName = (Get-A2CSubName ([string]$rg.subscriptionId)); ResourceGroup = [string]$rg.name; Location = [string]$rg.location; Resources = $rows.Count
                Status = 'Not exported'; Detail = (Get-A2CShortText $_.Exception.Message 220); ResourceGroupId = [string]$rg.id }
        }
        $index.Add($row)
        if ($row['Status'] -eq 'Not exported') { Write-A2CLog -Level Verbose ('ARM template not exported: {0} / {1}: {2}' -f $row['SubscriptionName'], $row['ResourceGroup'], $row['Detail']) }
    }
    Write-A2CProgress -Activity 'ARM template export' -Completed
    $script:A2C.Data['TemplateIndex'] = $index
    $script:A2C.Data['TemplateIssues'] = $state.Issues
    $done = @($index | Where-Object { $_['Status'] -eq 'Exported' -or $_['Status'] -eq 'Partial' }).Count
    $gaps = @($index | Where-Object { $_['Status'] -eq 'Partial' }).Count
    $bad = @($index | Where-Object { $_['Status'] -eq 'Not exported' }).Count
    $empty = @($index | Where-Object { $_['Status'] -eq 'Empty' }).Count
    foreach ($n in (Get-A2CUnique $state.Notes)) { Write-A2CLog -Level Notice ('ARM template export: ' + $n) }
    foreach ($s in @($state.Denied.Keys)) { Write-A2CLog -Level Warn ('ARM template export: no permission in subscription {0} ({1}); its resource groups were not exported' -f (Get-A2CSubName $s), $s) }
    $note = '{0} of {1} resource groups exported' -f $done, $rgs.Count
    if ($gaps -gt 0) { $note += ', {0} with gaps (templates\notExported.csv lists what Azure did not export)' -f $gaps }
    if ($bad -gt 0) { $note += ', {0} not exported (templates\index.csv)' -f $bad }
    if ($empty -gt 0) { $note += ', {0} empty' -f $empty }
    if ($state.Notes.Count -gt 0) { $note += ' | ' + (Join-A2C (Get-A2CUnique $state.Notes) ' | ') }
    $status = 'Collected'
    if ($done -eq 0 -and $bad -gt 0) { $status = 'Failed' } elseif ($bad -gt 0 -or $gaps -gt 0) { $status = 'Partial' }
    Add-A2CCoverage -Area 'ARM template export' -Status $status -Items $done -Detail $note
    Write-A2CLog -Level Ok ('ARM templates: {0} resource groups exported ({1} with gaps), {2} not exported, {3} empty -> templates folder' -f $done, $gaps, $bad, $empty)
    return New-A2CDatasetResult -Status $status -Note $note
}

# ---- Resource providers (Providers): registration state and the API versions of every resource type -------------
function Get-A2CStableApiVersion {
    # The newest API version of a list, a released one when there is any ("2024-05-01" before "2024-07-01-preview").
    param($Versions)
    $all = @($Versions | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Sort-Object -Descending)
    if ($all.Count -eq 0) { return '' }
    $stable = @($all | Where-Object { $_ -match '^\d{4}-\d{2}-\d{2}$' })
    if ($stable.Count -gt 0) { return $stable[0] }
    return $all[0]
}

function Get-A2CApiVersionFromError {
    # "The supported api-versions are '2021-06-01, 2023-01-01, ...'" -> the newest released one ('' when none is named)
    param([string] $Text)
    # in the raw answer the quotes can be written as a unicode escape (backslash u0027)
    $t = $Text -replace ('\\' + 'u0027'), "'"
    if ($t -match "(?i)supported (?:api-)?versions are '([^']+)'") { return (Get-A2CStableApiVersion @($Matches[1] -split '\s*,\s*')) }
    return ''
}

function Get-A2CApiVersionFor {
    # The API version to read a resource type with: the one learned from an error of this run, else the newest
    # released version the provider lists for the type or its nearest parent type, else the given default.
    param([string] $Type, [string] $Default = '')
    $t = $Type.ToLowerInvariant()
    $cache = $script:A2C.Data['ApiVersionCache']
    if ($null -eq $cache) { $cache = @{}; $script:A2C.Data['ApiVersionCache'] = $cache }
    if ($cache.ContainsKey($t)) { return $cache[$t] }
    $v = ''
    $map = $script:A2C.Data['ProviderApi']
    if ($null -ne $map) {
        $k = $t
        while ($k -and -not $v) {
            if ($map.ContainsKey($k)) { $v = Get-A2CStableApiVersion $map[$k] }
            $cut = $k.LastIndexOf('/')
            if ($cut -le $k.IndexOf('/')) { break }   # namespace/type is the last one to try
            $k = $k.Substring(0, $cut)
        }
    }
    if (-not $v) { $v = $Default }
    $cache[$t] = $v
    return $v
}

function Get-A2CDatasetProviders {
    # One call per subscription. The API versions are the same in every subscription of a cloud, so they are taken
    # from the first answer; without the ResourceProviders report that one subscription is all that is asked.
    $subs = @($script:A2C.Data['Subscriptions'])
    $everySub = Test-A2CSelected 'ResourceProviders'
    $api = @{}
    $rows = [System.Collections.Generic.List[object]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()
    $answered = 0
    $i = 0; $t0 = [DateTime]::Now
    foreach ($s in $subs) {
        $i++
        Write-A2CProgress -Activity 'Resource providers' -Current $i -Total $subs.Count -Started $t0 -Item $s.Name
        $r = Invoke-A2CArmList ('/subscriptions/{0}/providers?api-version={1}' -f $s.Id, $script:A2CApi.Providers)
        if (-not $r.Ok) { $failed.Add($s.Name + ': ' + (Get-A2CErrorText $r.Error)); continue }
        $answered++
        foreach ($p in $r.Items) {
            $ns = [string]$p.namespace
            if (-not $ns) { continue }
            $types = @($p.resourceTypes | Where-Object { $null -ne $_ })
            if ($answered -eq 1) { foreach ($rt in $types) { $api[($ns + '/' + [string]$rt.resourceType).ToLowerInvariant()] = $rt.apiVersions } }
            if ([string]$p.registrationState -and [string]$p.registrationState -ne 'NotRegistered') {
                $rows.Add([pscustomobject]@{ SubscriptionId = $s.Id; Namespace = $ns; State = [string]$p.registrationState; Policy = [string]$p.registrationPolicy; Types = $types.Count })
            }
        }
        if (-not $everySub) { break }
    }
    Write-A2CProgress -Activity 'Resource providers' -Completed
    $script:A2C.Data['ProviderApi'] = $api
    $script:A2C.Data['ProviderRows'] = $rows
    $status = 'Collected'; $note = ''
    if ($answered -eq 0) { $status = 'Failed' } elseif ($failed.Count -gt 0) { $status = 'Partial' }
    if ($failed.Count -gt 0) { $note = Join-A2C $failed ' | ' }
    Add-A2CCoverage -Area 'Resource providers (ARM)' -Status $status -Items $rows.Count -Detail $(if ($note) { $note } else { ('API versions of {0} resource types' -f $api.Count) })
    Write-A2CLog -Level Ok ('{0} provider registrations in {1} subscription(s), API versions of {2} resource types' -f $rows.Count, $answered, $api.Count)
    return New-A2CDatasetResult -Status $status -Note $note
}

# ---- Child resources (ChildResources): what Resource Graph does not list - containers, shares, firewall rules,
# queues, databases, schedules... read with one list call per parent and child type. Table-driven: Path is the list
# below the parent ("a > b" also lists b below every a; "type/name" reads one object), When limits it to some parents,
# Keep to some items, Drop names members that can hold a secret. Api is used when the provider list names no version.
function Get-A2CCosmosApi {
    param($R)
    if ([string]$R.kind -eq 'MongoDB') { return 'Mongo' }
    $caps = @((Get-A2CProps $R).capabilities | ForEach-Object { [string]$_.name })
    foreach ($c in @('Cassandra', 'Gremlin', 'Table', 'Mongo')) { if ($caps -contains ('Enable' + $c)) { return $c } }
    return 'Sql'
}

$script:A2CChildSpecs = @(
    @{ Parent = 'microsoft.storage/storageaccounts'; Api = '2023-05-01'; Lists = @(
            @{ Path = 'blobServices > containers'; When = { param($r) [string]$r.kind -ne 'FileStorage' } }
            @{ Path = 'fileServices > shares'; When = { param($r) @('Storage', 'StorageV2', 'FileStorage') -contains [string]$r.kind } }
            @{ Path = 'queueServices > queues'; When = { param($r) @('Storage', 'StorageV2') -contains [string]$r.kind } }
            @{ Path = 'tableServices > tables'; When = { param($r) @('Storage', 'StorageV2') -contains [string]$r.kind } }
            'managementPolicies/default', 'inventoryPolicies', 'objectReplicationPolicies', 'encryptionScopes', 'localUsers') }
    @{ Parent = 'microsoft.sql/servers'; Api = '2021-11-01'; Lists = @('firewallRules', 'ipv6FirewallRules', 'virtualNetworkRules', 'outboundFirewallRules',
            'failoverGroups', 'administrators', 'azureADOnlyAuthentications', 'auditingSettings', 'securityAlertPolicies', 'encryptionProtector', 'keys',
            'dnsAliases', 'connectionPolicies') }
    @{ Parent = 'microsoft.sql/servers/databases'; Api = '2021-11-01'; When = { param($r) [string]$r.name -ne 'master' }
        Lists = @('transparentDataEncryption', 'backupShortTermRetentionPolicies', 'backupLongTermRetentionPolicies', 'auditingSettings') }
    @{ Parent = 'microsoft.sql/managedinstances'; Api = '2021-11-01'; Lists = @('administrators', 'azureADOnlyAuthentications', 'encryptionProtector', 'startStopSchedules') }
    @{ Parent = 'microsoft.sql/managedinstances/databases'; Api = '2021-11-01'; Lists = @('backupShortTermRetentionPolicies', 'backupLongTermRetentionPolicies') }
    @{ Parent = 'microsoft.servicebus/namespaces'; Api = '2021-11-01'; Lists = @('queues > authorizationRules', 'authorizationRules', 'networkRuleSets', 'disasterRecoveryConfigs'
            @{ Path = 'topics > subscriptions > rules'; When = { param($r) [string]$r.sku.name -ne 'Basic' } }
            @{ Path = 'topics > authorizationRules'; When = { param($r) [string]$r.sku.name -ne 'Basic' } }) }
    @{ Parent = 'microsoft.eventhub/namespaces'; Api = '2021-11-01'; Lists = @('eventhubs > consumergroups', 'eventhubs > authorizationRules', 'authorizationRules',
            'networkRuleSets', 'disasterRecoveryConfigs', 'schemagroups', 'applicationGroups') }
    @{ Parent = 'microsoft.eventgrid/topics'; Api = '2022-06-15'; Lists = @('providers/Microsoft.EventGrid/eventSubscriptions') }
    @{ Parent = 'microsoft.eventgrid/domains'; Api = '2022-06-15'; Lists = @('topics > providers/Microsoft.EventGrid/eventSubscriptions', 'providers/Microsoft.EventGrid/eventSubscriptions') }
    @{ Parent = 'microsoft.eventgrid/systemtopics'; Api = '2022-06-15'; Lists = @('eventSubscriptions') }
    @{ Parent = 'microsoft.eventgrid/partnertopics'; Api = '2022-06-15'; Lists = @('eventSubscriptions') }
    @{ Parent = 'microsoft.eventgrid/namespaces'; Api = '2025-02-15'; Lists = @('topics > eventSubscriptions') }
    @{ Parent = 'microsoft.documentdb/databaseaccounts'; Api = '2023-04-15'; Lists = @(
            @{ Path = 'sqlDatabases > containers > throughputSettings/default'; When = { param($r) (Get-A2CCosmosApi $r) -eq 'Sql' } }
            @{ Path = 'sqlDatabases > throughputSettings/default'; When = { param($r) (Get-A2CCosmosApi $r) -eq 'Sql' } }
            @{ Path = 'sqlRoleDefinitions'; When = { param($r) (Get-A2CCosmosApi $r) -eq 'Sql' } }
            @{ Path = 'sqlRoleAssignments'; When = { param($r) (Get-A2CCosmosApi $r) -eq 'Sql' } }
            @{ Path = 'mongodbDatabases > collections > throughputSettings/default'; When = { param($r) (Get-A2CCosmosApi $r) -eq 'Mongo' } }
            @{ Path = 'mongodbDatabases > throughputSettings/default'; When = { param($r) (Get-A2CCosmosApi $r) -eq 'Mongo' } }
            @{ Path = 'cassandraKeyspaces > tables'; When = { param($r) (Get-A2CCosmosApi $r) -eq 'Cassandra' } }
            @{ Path = 'gremlinDatabases > graphs'; When = { param($r) (Get-A2CCosmosApi $r) -eq 'Gremlin' } }
            @{ Path = 'tables'; When = { param($r) (Get-A2CCosmosApi $r) -eq 'Table' } }) }
    @{ Parent = 'microsoft.dbforpostgresql/flexibleservers'; Api = '2022-12-01'; Lists = @('databases', 'firewallRules', 'administrators'
            @{ Path = 'configurations'; Keep = { param($x) [string]$x.properties.source -eq 'user-override' } }) }
    @{ Parent = 'microsoft.dbformysql/flexibleservers'; Api = '2021-05-01'; Lists = @('databases', 'firewallRules', 'administrators'
            @{ Path = 'configurations'; Keep = { param($x) [string]$x.properties.source -eq 'user-override' } }) }
    @{ Parent = 'microsoft.cache/redis'; Api = '2023-08-01'; Lists = @('firewallRules', 'patchSchedules', 'linkedServers', 'accessPolicies', 'accessPolicyAssignments') }
    @{ Parent = 'microsoft.automation/automationaccounts'; Api = '2023-11-01'; Lists = @('variables', 'schedules', 'jobSchedules', 'credentials', 'connections',
            'certificates', 'hybridRunbookWorkerGroups', 'webhooks', 'sourceControls', 'python3Packages', 'powerShell72Modules', 'runtimeEnvironments'
            @{ Path = 'modules'; Keep = { param($x) -not $x.properties.isGlobal } }) }
    @{ Parent = 'microsoft.operationalinsights/workspaces'; Api = '2020-08-01'; Lists = @('savedSearches', 'linkedServices', 'dataExports', 'linkedStorageAccounts'
            # every workspace has hundreds of built-in tables: kept are custom tables and tables with their own plan or retention
            @{ Path = 'tables'; Api = '2022-10-01'; Keep = { param($x) $p = $x.properties
                    ($p.retentionInDaysAsDefault -eq $false) -or ($p.totalRetentionInDaysAsDefault -eq $false) -or ([string]$p.plan -and [string]$p.plan -ne 'Analytics') -or
                    ([string]$x.name -like '*_CL') -or ([string]$p.schema.tableType -and [string]$p.schema.tableType -ne 'Microsoft') } }) }
    @{ Parent = 'microsoft.apimanagement/service'; Api = '2022-08-01'; Lists = @('products', 'subscriptions', 'namedValues', 'diagnostics', 'certificates',
            'apiVersionSets', 'policyFragments', 'groups', 'gateways', 'authorizationServers', 'openidConnectProviders', 'identityProviders'
            @{ Path = 'apis'; Keep = { param($x) [string]$x.name -notlike '*;rev=*' } }
            @{ Path = 'backends'; Drop = @('properties.credentials', 'properties.proxy.password') }
            @{ Path = 'loggers'; Drop = @('properties.credentials') }) }
    @{ Parent = 'microsoft.cdn/profiles'; Api = '2023-05-01'; Lists = @(
            @{ Path = 'afdEndpoints > routes'; When = { param($r) [string]$r.sku.name -like '*AzureFrontDoor' } }
            @{ Path = 'originGroups > origins'; When = { param($r) [string]$r.sku.name -like '*AzureFrontDoor' } }
            @{ Path = 'ruleSets > rules'; When = { param($r) [string]$r.sku.name -like '*AzureFrontDoor' } }
            @{ Path = 'customDomains'; When = { param($r) [string]$r.sku.name -like '*AzureFrontDoor' } }
            @{ Path = 'securityPolicies'; When = { param($r) [string]$r.sku.name -like '*AzureFrontDoor' } }
            @{ Path = 'secrets'; When = { param($r) [string]$r.sku.name -like '*AzureFrontDoor' } }
            @{ Path = 'endpoints > customDomains'; When = { param($r) [string]$r.sku.name -notlike '*AzureFrontDoor' } }
            @{ Path = 'endpoints > originGroups'; When = { param($r) [string]$r.sku.name -notlike '*AzureFrontDoor' } }
            @{ Path = 'endpoints > origins'; When = { param($r) [string]$r.sku.name -notlike '*AzureFrontDoor' } }) }
    @{ Parent = 'microsoft.cognitiveservices/accounts'; Api = '2023-05-01'; When = { param($r) @('OpenAI', 'AIServices') -contains [string]$r.kind }; Lists = @('deployments', 'raiPolicies') }
    @{ Parent = 'microsoft.containerservice/managedclusters'; Api = '2024-02-01'; Lists = @('maintenanceConfigurations', 'trustedAccessRoleBindings') }
    @{ Parent = 'microsoft.web/sites'; Api = '2023-12-01'; Lists = @('hostNameBindings', 'config/authsettingsV2', 'config/slotConfigNames', 'basicPublishingCredentialsPolicies',
            'virtualNetworkConnections', 'hybridConnectionRelays', 'publicCertificates'
            @{ Path = 'functions'; When = { param($r) [string]$r.kind -like '*functionapp*' } }) }
    @{ Parent = 'microsoft.web/sites/slots'; Api = '2023-12-01'; Lists = @('hostNameBindings', 'config/authsettingsV2', 'basicPublishingCredentialsPolicies') }
    @{ Parent = 'microsoft.web/staticsites'; Api = '2023-12-01'; Lists = @('customDomains', 'linkedBackends') }
    @{ Parent = 'microsoft.web/hostingenvironments'; Api = '2023-12-01'; Lists = @('configurations/networking') }
    @{ Parent = 'microsoft.network/privateendpoints'; Api = '2023-11-01'; Lists = @('privateDnsZoneGroups') }
    @{ Parent = 'microsoft.network/virtualhubs'; Api = '2023-11-01'; Lists = @('hubVirtualNetworkConnections', 'hubRouteTables', 'routingIntent', 'routeMaps', 'bgpConnections', 'ipConfigurations') }
    @{ Parent = 'microsoft.network/virtualnetworkgateways'; Api = '2023-11-01'; Lists = @('natRules') }
    @{ Parent = 'microsoft.network/dnsforwardingrulesets'; Api = '2022-07-01'; Lists = @('forwardingRules', 'virtualNetworkLinks') }
    @{ Parent = 'microsoft.network/dnszones'; Api = '2018-05-01'; Lists = @('all') }
    @{ Parent = 'microsoft.network/privatednszones'; Api = '2020-06-01'; Lists = @('ALL') }
    @{ Parent = 'microsoft.datafactory/factories'; Api = '2018-06-01'; Lists = @('integrationRuntimes', 'managedVirtualNetworks > managedPrivateEndpoints', 'credentials', 'globalParameters') }
    @{ Parent = 'microsoft.containerregistry/registries'; Api = '2023-07-01'; Lists = @('scopeMaps', 'tokens', 'cacheRules', 'credentialSets', 'connectedRegistries') }
    @{ Parent = 'microsoft.app/managedenvironments'; Api = '2024-03-01'; Lists = @('storages', 'daprComponents', 'certificates') }
    @{ Parent = 'microsoft.app/containerapps'; Api = '2024-03-01'; Lists = @('authConfigs', 'sourcecontrols') }
    # Key Vault through Azure Resource Manager: names, types and expiry dates only - this API never returns a value
    @{ Parent = 'microsoft.keyvault/vaults'; Api = '2023-07-01'; Lists = @('keys', 'secrets') }
    @{ Parent = 'microsoft.recoveryservices/vaults'; Api = '2023-04-01'; Lists = @('backupconfig/vaultconfig', 'backupstorageconfig/vaultstorageconfig') }
    @{ Parent = 'microsoft.synapse/workspaces'; Api = '2021-06-01'; Lists = @('firewallRules', 'integrationRuntimes') }
    @{ Parent = 'microsoft.kusto/clusters'; Api = '2023-08-15'; Lists = @('principalAssignments', 'attachedDatabaseConfigurations', 'managedPrivateEndpoints') }
    @{ Parent = 'microsoft.managedidentity/userassignedidentities'; Api = '2023-01-31'; Lists = @('federatedIdentityCredentials') }
    @{ Parent = 'microsoft.search/searchservices'; Api = '2023-11-01'; Lists = @('sharedPrivateLinkResources') }
)

function Set-A2CMember {
    # Replaces the value at a dotted path of an object ("properties.credentials") when it is there.
    param($Object, [string] $Path, $Value)
    $o = $Object
    $names = @($Path.Split('.'))
    for ($i = 0; $i -lt $names.Count - 1; $i++) {
        if ($null -eq $o -or $null -eq $o.PSObject.Properties[$names[$i]]) { return }
        $o = $o.($names[$i])
    }
    $leaf = $names[$names.Count - 1]
    if ($null -ne $o -and $null -ne $o.PSObject.Properties[$leaf] -and $null -ne $o.$leaf) { $o.$leaf = $Value }
}

function Read-A2CChildren {
    # One step of a chain below $BaseId: a list, or one object when the step ends with a name. The items are kept and
    # the next step is read below each of them.
    param($State, $Resource, [string] $BaseId, [string] $BaseType, $Chain, [string[]] $Steps, [int] $Index, [string] $DefaultApi)
    $seg = $Steps[$Index]
    $parts = @($seg.Split('/'))
    # the type: below the base type, or a type of another provider ("providers/Microsoft.EventGrid/eventSubscriptions")
    $first = 0; $type = $BaseType
    if ($parts[0] -ieq 'providers' -and $parts.Count -ge 3) { $first = 2; $type = $parts[1] }
    for ($k = $first; $k -lt $parts.Count; $k += 2) { $type += '/' + $parts[$k] }
    $single = ((($parts.Count - $first) % 2) -eq 0)
    $key = $type.ToLowerInvariant()
    $st = $State.Types[$key]
    if ($null -eq $st) {
        $st = [pscustomobject]@{ ParentType = $State.ParentType; Type = $type; Api = ''; Calls = 0; Answered = 0; Items = 0; None = 0; NotApplicable = 0; Refused = 0; Failed = 0; Stopped = ''; Sample = '' }
        $State.Types[$key] = $st
    }
    if ($st.Stopped) { return }
    $url = $BaseId + '/' + $seg
    $items = $State.Memo[$url]
    $known = ($null -ne $items)
    $err = $null
    if (-not $known) {
        for ($try = 0; $try -lt 2; $try++) {
            $api = Get-A2CApiVersionFor $type $(if ($Chain.Api) { [string]$Chain.Api } else { $DefaultApi })
            $st.Api = $api
            $st.Calls++
            $r = Invoke-A2CArm ($url + '?api-version=' + $api)
            if ($r.Ok) {
                $json = $r.Json
                # the values of well-known secret properties are replaced before anything is kept
                if ($script:A2CSecretJsonRx.IsMatch([string]$r.Content)) { try { $json = ConvertFrom-A2CJson (Protect-A2CSecretText ([string]$r.Content)) } catch { $json = $r.Json } }
                $l = [System.Collections.Generic.List[object]]::new()
                if ([string]$r.Content -match '^\s*\[') { foreach ($v in @($json)) { if ($null -ne $v) { $l.Add($v) } } }   # a few lists answer with a bare array
                elseif ($single) { if ($null -ne $json) { $l.Add($json) } }
                else {
                    foreach ($v in @($json.value)) { if ($null -ne $v) { $l.Add($v) } }
                    $next = [string]$json.nextLink
                    if ($next) {
                        $more = Invoke-A2CArmList $next
                        foreach ($v in $more.Items) { $l.Add($v) }
                        if (-not $more.Ok) { $st.Failed++; if (-not $st.Sample) { $st.Sample = 'A later page: ' + (Get-A2CShortText (Get-A2CErrorText $more.Error) 200) } }
                    }
                }
                $items = $l
                break
            }
            $err = $r.Error
            # the version is not one this type has: the answer names the versions that are
            $better = ''
            if ($try -eq 0 -and ([string]$err.Code + ' ' + [string]$r.Content) -match '(?i)NoRegisteredProviderFound|InvalidApiVersion|UnsupportedApiVersion|api-?version') { $better = Get-A2CApiVersionFromError ([string]$r.Content) }
            if (-not $better -or $better -eq $api) { break }
            $script:A2C.Data['ApiVersionCache'][$key] = $better
        }
        if ($null -eq $items) {
            $code = [int]$err.Status
            # one object that is not there (no lifecycle policy, no own throughput), or a parent that is gone
            if ($code -eq 404 -and ($single -or [string]$err.Code -match '(?i)^(ResourceNotFound|ParentResourceNotFound|ResourceGroupNotFound|NotFound)$')) { $st.None++; return }
            if ($code -eq 401 -or $code -eq 403) { $st.Refused++ }
            elseif ($code -eq 400 -or $code -eq 404 -or $code -eq 405 -or $code -eq 409 -or $code -eq 501) { $st.NotApplicable++ }
            else { $st.Failed++ }
            if (-not $st.Sample) { $st.Sample = Get-A2CShortText (Get-A2CErrorText $err) 200 }
            # a type that never answered is not asked for again: no permission, or a list this cloud does not have
            if ($st.Answered -eq 0 -and ($st.Refused -ge 3 -or ($st.Refused + $st.NotApplicable + $st.Failed) -ge 10)) { $st.Stopped = 'Not asked again after {0} calls without an answer' -f $st.Calls }
            return
        }
        $st.Answered++
        $State.Memo[$url] = $items
    }
    $last = ($Index -eq $Steps.Count - 1)
    foreach ($it in $items) {
        if (-not $known) {
            if ($last -and $null -ne $Chain.Keep -and -not (& $Chain.Keep $it)) { continue }
            if (-not $it.id) { $it | Add-Member -NotePropertyName 'id' -NotePropertyValue $(if ($single) { $url } else { $url + '/' + [string]$it.name }) -Force }
            if ($last) { foreach ($d in @($Chain.Drop)) { if ($d) { Set-A2CMember $it ([string]$d) $script:A2CSecretMark } } }
            $st.Items++
            $rec = [pscustomobject]@{ Resource = $Resource; Type = $type; Item = $it }
            $State.Items.Add($rec)
            if (-not $State.ByType.ContainsKey($key)) { $State.ByType[$key] = [System.Collections.Generic.List[object]]::new() }
            $State.ByType[$key].Add($rec)
            Add-A2CRaw 'child resources' $it
        }
        if (-not $last -and $it.id) {
            Read-A2CChildren -State $State -Resource $Resource -BaseId ([string]$it.id) -BaseType $type -Chain $Chain -Steps $Steps -Index ($Index + 1) -DefaultApi $DefaultApi
        }
    }
}

function Get-A2CChildrenOfType {
    # The child resources of a type read by the ChildResources dataset: objects with Resource (the parent row of the
    # resources table), Type and Item (the object as Azure returned it).
    param([string] $Type)
    $l = [System.Collections.Generic.List[object]]::new()
    $m = $script:A2C.Data['ChildByType']
    if ($null -ne $m) { $x = $m[$Type.ToLowerInvariant()]; if ($null -ne $x) { $l.AddRange($x) } }
    return , $l
}

function Get-A2CDatasetChildResources {
    $work = [System.Collections.Generic.List[object]]::new()
    $least = 0
    foreach ($spec in $script:A2CChildSpecs) {
        foreach ($r in (Get-A2CResourcesOfType $spec.Parent)) {
            if ($null -ne $spec.When -and -not (& $spec.When $r)) { continue }
            $work.Add(@($spec, $r))
            $least += @($spec.Lists).Count
        }
    }
    $state = [pscustomobject]@{ Types = [ordered]@{}; Items = [System.Collections.Generic.List[object]]::new(); ByType = @{}; Memo = @{}; ParentType = '' }
    if ($null -eq $script:A2C.Data['ApiVersionCache']) { $script:A2C.Data['ApiVersionCache'] = @{} }
    Write-A2CLog ('{0} resources with child resources to read: at least {1} calls' -f $work.Count, $least)
    $i = 0; $t0 = [DateTime]::Now
    foreach ($w in $work) {
        $i++
        $spec = $w[0]; $r = $w[1]
        Write-A2CProgress -Activity 'Child resources' -Current $i -Total $work.Count -Started $t0 -Item ([string]$r.name)
        $state.Memo.Clear()
        $state.ParentType = Get-A2CTypeCased -Id ([string]$r.id) -Fallback ([string]$r.type)
        foreach ($c in @($spec.Lists)) {
            $chain = $c
            if ($chain -is [string]) { $chain = @{ Path = $chain } }
            if ($null -ne $chain.When -and -not (& $chain.When $r)) { continue }
            try {
                Read-A2CChildren -State $state -Resource $r -BaseId ([string]$r.id) -BaseType $state.ParentType -Chain $chain -Steps @([string]$chain.Path -split '\s*>\s*') -Index 0 -DefaultApi ([string]$spec.Api)
            }
            catch { Write-A2CLog -Level Verbose ('Child resources of {0} ({1}): {2}' -f $r.name, $chain.Path, (Get-A2CShortText $_.Exception.Message 200)) }
        }
    }
    Write-A2CProgress -Activity 'Child resources' -Completed
    $types = @($state.Types.Values)
    $script:A2C.Data['ChildItems'] = $state.Items
    $script:A2C.Data['ChildByType'] = $state.ByType
    $script:A2C.Data['ChildTypes'] = $types
    $calls = 0
    foreach ($t in $types) { $calls += $t.Calls }
    $bad = @($types | Where-Object { $_.Refused -gt 0 -or $_.Failed -gt 0 -or $_.Stopped })
    foreach ($t in $bad) { Write-A2CLog -Level Verbose ('Child resources {0}: {1} refused, {2} failed{3} - {4}' -f $t.Type, $t.Refused, $t.Failed, $(if ($t.Stopped) { ', ' + $t.Stopped } else { '' }), $t.Sample) }
    $note = '{0} items of {1} types below {2} resources, {3} calls' -f $state.Items.Count, @($types | Where-Object { $_.Items -gt 0 }).Count, $work.Count, $calls
    if ($bad.Count -gt 0) {
        $note += ' | not fully read: ' + (Join-A2C @($bad | Select-Object -First 6 | ForEach-Object { ($_.Type -replace '^[^/]+/', '') }) ', ')
        if ($bad.Count -gt 6) { $note += (' and {0} more' -f ($bad.Count - 6)) }
        $note += ' (childResourceTypes.csv)'
    }
    $status = $(if ($bad.Count -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'Child resources (ARM)' -Status $status -Items $state.Items.Count -Detail $note
    Write-A2CLog -Level Ok ('Child resources: ' + $note)
    return New-A2CDatasetResult -Status $status -Note $note
}

# ---- Entra ID (Microsoft Graph with the Az sign-in token) ----------------------------------------------
$script:A2CMicrosoftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
$script:A2CPermissionApis = [ordered]@{
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API'
}

function Add-A2CEntraCoverage {
    param([string] $Area, $Result, [string] $Needs, [int] $Items)
    if ($Result.Ok) { Add-A2CCoverage -Area $Area -Status Collected -Items $Items; return 'Collected' }
    $reason = Get-A2CGraphSkipReason $Result.Error $Needs
    Write-A2CLog -Level Warn ($Area + ' skipped: ' + $reason)
    Add-A2CCoverage -Area $Area -Status Skipped -Detail $reason
    return 'Skipped'
}

function Get-A2CDatasetEntraTenant {
    $org = Invoke-A2CGraphList '/v1.0/organization'
    $script:A2C.Data['EntraOrg'] = $org.Items
    [void](Add-A2CEntraCoverage 'Entra tenant (organization)' $org 'directory read access' $org.Items.Count)
    $dom = Invoke-A2CGraphList '/v1.0/domains'
    $script:A2C.Data['EntraDomains'] = $dom.Items
    [void](Add-A2CEntraCoverage 'Entra domains' $dom 'Domain.Read.All or a directory role' $dom.Items.Count)
    $sku = Invoke-A2CGraphList '/v1.0/subscribedSkus'
    $script:A2C.Data['EntraSkus'] = $sku.Items
    [void](Add-A2CEntraCoverage 'Entra licenses (subscribedSkus)' $sku 'LicenseAssignment.Read.All or a directory role' $sku.Items.Count)
    foreach ($x in $org.Items) { Add-A2CRawEntra 'organization' $x }
    foreach ($x in $dom.Items) { Add-A2CRawEntra 'domains' $x }
    # administrative units and the directory settings (group creation, naming policy, guest access...): small lists;
    # when the sign-in may not read them it is a note, not a warning
    foreach ($extra in @(@('EntraAdminUnits', 'Entra administrative units', '/v1.0/directory/administrativeUnits?$top=999', 'administrativeUnits'),
            @('EntraGroupSettings', 'Entra directory settings', '/v1.0/groupSettings', 'groupSettings'))) {
        $x = Invoke-A2CGraphList $extra[2]
        $script:A2C.Data[$extra[0]] = $x.Items
        if ($x.Ok) { Add-A2CCoverage -Area $extra[1] -Status Collected -Items $x.Items.Count; foreach ($i in $x.Items) { Add-A2CRawEntra $extra[3] $i } }
        else { Add-A2CCoverage -Area $extra[1] -Status Skipped -Detail (Get-A2CGraphSkipReason $x.Error 'Directory.Read.All or a directory role') }
    }
    if (-not $org.Ok -and -not $dom.Ok -and -not $sku.Ok) { return New-A2CDatasetResult -Status 'Skipped' -Note 'no directory access' }
    if (-not ($org.Ok -and $dom.Ok -and $sku.Ok)) { return New-A2CDatasetResult -Status 'Partial' }
    return New-A2CDatasetResult
}

function Get-A2CDatasetEntraUsers {
    $sel = 'id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,creationType,externalUserState,onPremisesSyncEnabled,department,jobTitle,companyName,usageLocation,assignedLicenses'
    $r = Invoke-A2CGraphList ('/v1.0/users?$select=' + $sel + ',signInActivity&$top=500')
    $signIn = $true
    $note = ''
    if (-not $r.Ok) {
        $signIn = $false
        $note = 'Sign-in activity not available (' + (Get-A2CGraphSkipReason $r.Error 'AuditLog.Read.All + Reports Reader/Global Reader + Entra ID P1') + ')'
        Write-A2CLog -Level Warn $note
        $r = Invoke-A2CGraphList ('/v1.0/users?$select=' + $sel + '&$top=999')
    }
    $script:A2C.Data['EntraUsers'] = $r.Items
    $script:A2C.Data['EntraSignIn'] = $signIn
    if (-not $r.Ok) { $st = Add-A2CEntraCoverage 'Entra users' $r 'User.Read.All (any member user can read users by default)' 0; return New-A2CDatasetResult -Status $st }
    Add-A2CCoverage -Area 'Entra users' -Status $(if ($signIn) { 'Collected' } else { 'Partial' }) -Items $r.Items.Count -Detail $note
    return New-A2CDatasetResult -Status $(if ($signIn) { 'Collected' } else { 'Partial' }) -Note $note
}

function Get-A2CDatasetEntraGroups {
    # with the owners; the complete objects when the snapshot is written
    $sel = '$select=id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,membershipRule,membershipRuleProcessingState,isAssignableToRole,onPremisesSyncEnabled,createdDateTime,visibility&'
    if (Test-A2CSelected 'Snapshot') { $sel = '' }
    $r = Invoke-A2CGraphList ('/v1.0/groups?' + $sel + '$expand=owners($select=id,displayName,userPrincipalName)&$top=100')
    $owners = $true
    if (-not $r.Ok -and $r.Error.Status -eq 400) { $owners = $false; $r = Invoke-A2CGraphList ('/v1.0/groups?' + $sel + '$top=999') }
    $script:A2C.Data['EntraGroupOwners'] = $owners
    foreach ($g in $r.Items) { Add-A2CRawEntra 'groups' $g }
    $script:A2C.Data['EntraGroups'] = $r.Items
    return New-A2CDatasetResult -Status (Add-A2CEntraCoverage 'Entra groups' $r 'Group.Read.All (any member user can read groups by default)' $r.Items.Count)
}

function Get-A2CDatasetEntraGroupMembers {
    $groups = @($script:A2C.Data['EntraGroups'])
    $rows = [System.Collections.Generic.List[object]]::new()
    $failed = 0
    $i = 0; $t0 = [DateTime]::Now
    foreach ($g in $groups) {
        if ($null -eq $g) { continue }
        $i++
        Write-A2CProgress -Activity 'Group members' -Current $i -Total $groups.Count -Started $t0 -Item ([string]$g.displayName)
        # beta: v1.0 /members does not return service principals
        $r = Invoke-A2CGraphList ('/beta/groups/{0}/members?$select=id,displayName,userPrincipalName,appId&$top=999' -f $g.id)
        if (-not $r.Ok) { $failed++; continue }
        foreach ($m in $r.Items) { $rows.Add([pscustomobject]@{ GroupId = [string]$g.id; GroupName = [string]$g.displayName; Member = $m }) }
    }
    Write-A2CProgress -Activity 'Group members' -Completed
    $script:A2C.Data['EntraGroupMembers'] = $rows
    $st = $(if ($failed -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'Entra group members' -Status $st -Items $rows.Count -Detail $(if ($failed) { "$failed group(s) failed" } else { '' })
    return New-A2CDatasetResult -Status $st
}

function Get-A2CDatasetEntraApps {
    # the complete objects (app roles, exposed scopes, redirect URIs, optional claims...) when the snapshot is written
    $sel = '$select=id,appId,displayName,createdDateTime,signInAudience,publisherDomain,identifierUris,requiredResourceAccess,passwordCredentials,keyCredentials,web,spa,publicClient,notes&'
    if (Test-A2CSelected 'Snapshot') { $sel = '' }
    $r = Invoke-A2CGraphList ('/v1.0/applications?' + $sel + '$expand=owners($select=id,displayName,userPrincipalName)&$top=100')
    $owners = $true
    if (-not $r.Ok -and $r.Error.Status -eq 400) { $owners = $false; $r = Invoke-A2CGraphList ('/v1.0/applications?' + $sel + '$top=999') }
    foreach ($a in $r.Items) { Add-A2CRawEntra 'applications' $a }
    $script:A2C.Data['EntraApps'] = $r.Items
    $script:A2C.Data['EntraAppOwners'] = $owners
    return New-A2CDatasetResult -Status (Add-A2CEntraCoverage 'Entra app registrations' $r 'Application.Read.All (any member user by default)' $r.Items.Count)
}

function Get-A2CDatasetEntraServicePrincipals {
    $sel = '$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,publisherName,appRoleAssignmentRequired,tags,passwordCredentials,keyCredentials,alternativeNames,preferredSingleSignOnMode,signInAudience,appRoles&'
    if (Test-A2CSelected 'Snapshot') { $sel = '' }
    $r = Invoke-A2CGraphList ('/v1.0/servicePrincipals?' + $sel + '$top=999')
    $script:A2C.Data['EntraSPs'] = $r.Items
    $byId = @{}
    foreach ($s in $r.Items) {
        $byId[([string]$s.id).ToLowerInvariant()] = $s
        # the snapshot keeps the enterprise applications of the tenant, not Microsoft's own and not managed identities
        if ([string]$s.servicePrincipalType -ne 'ManagedIdentity' -and $script:A2CMicrosoftTenants -notcontains [string]$s.appOwnerOrganizationId) { Add-A2CRawEntra 'servicePrincipals' $s }
    }
    $script:A2C.Data['EntraSPById'] = $byId
    return New-A2CDatasetResult -Status (Add-A2CEntraCoverage 'Entra service principals and managed identities' $r 'Application.Read.All (any member user by default)' $r.Items.Count)
}

function Get-A2CDatasetEntraAppPermissions {
    $rows = [System.Collections.Generic.List[object]]::new()
    $problems = [System.Collections.Generic.List[string]]::new()
    # the well-known APIs, and every other API an app registration of this tenant asks permissions for
    $apis = [ordered]@{}
    foreach ($appId in $script:A2CPermissionApis.Keys) { $apis[$appId] = $script:A2CPermissionApis[$appId] }
    foreach ($app in @($script:A2C.Data['EntraApps'])) {
        foreach ($rra in @($app.requiredResourceAccess)) {
            $id = ([string]$rra.resourceAppId).ToLowerInvariant()
            if ($id -and -not $apis.Contains($id) -and $apis.Count -lt 100) { $apis[$id] = '' }
        }
    }
    foreach ($appId in @($apis.Keys)) {
        $sp = Invoke-A2CGraph ("/v1.0/servicePrincipals(appId='{0}')?`$select=id,appId,displayName,appRoles" -f $appId)
        if (-not $sp.Ok) { if ($sp.Status -ne 404 -and $apis[$appId]) { $problems.Add($apis[$appId] + ': ' + (Get-A2CErrorText $sp.Error)) }; continue }
        $apiName = [string]$apis[$appId]
        if (-not $apiName) { $apiName = [string]$sp.Json.displayName }
        $roles = @{}
        foreach ($ar in @($sp.Json.appRoles)) { if ($null -ne $ar) { $roles[([string]$ar.id).ToLowerInvariant()] = [string]$ar.value } }
        if ($roles.Count -eq 0) { continue }   # an API without application permissions
        $r = Invoke-A2CGraphList ('/v1.0/servicePrincipals/{0}/appRoleAssignedTo?$top=999' -f $sp.Json.id)
        if (-not $r.Ok) { $problems.Add($apiName + ' app role assignments: ' + (Get-A2CErrorText $r.Error)); continue }
        foreach ($a in $r.Items) {
            if ([string]$a.principalType -and [string]$a.principalType -ne 'ServicePrincipal') { continue }   # users and groups assigned to an app are no API permission
            $rows.Add([pscustomobject]@{ Type = 'Application'; ClientId = ([string]$a.principalId).ToLowerInvariant(); ClientName = [string]$a.principalDisplayName
                    PrincipalType = [string]$a.principalType; ResourceAppId = $appId; ResourceName = $apiName
                    Permission = $(if ($roles.ContainsKey(([string]$a.appRoleId).ToLowerInvariant())) { $roles[([string]$a.appRoleId).ToLowerInvariant()] } else { [string]$a.appRoleId })
                    ConsentType = 'Admin consent (application)'; PrincipalId = ''; Created = $a.createdDateTime })
        }
    }
    $g = Invoke-A2CGraphList '/v1.0/oauth2PermissionGrants?$top=999'
    if ($g.Ok) {
        $byId = $script:A2C.Data['EntraSPById']; if ($null -eq $byId) { $byId = @{} }
        foreach ($x in $g.Items) {
            $client = $byId[([string]$x.clientId).ToLowerInvariant()]
            $res = $byId[([string]$x.resourceId).ToLowerInvariant()]
            foreach ($scope in ([string]$x.scope -split '\s+')) {
                if (-not $scope) { continue }
                $rows.Add([pscustomobject]@{ Type = 'Delegated'; ClientId = ([string]$x.clientId).ToLowerInvariant(); ClientName = $(if ($null -ne $client) { [string]$client.displayName } else { '' })
                        PrincipalType = 'ServicePrincipal'; ResourceAppId = $(if ($null -ne $res) { [string]$res.appId } else { '' })
                        ResourceName = $(if ($null -ne $res) { [string]$res.displayName } else { [string]$x.resourceId }); Permission = $scope
                        ConsentType = $(if ($x.consentType -eq 'AllPrincipals') { 'Admin consent (all users)' } else { 'User consent' }); PrincipalId = [string]$x.principalId; Created = $null })
            }
        }
    }
    else { $problems.Add('Delegated permission grants: ' + (Get-A2CGraphSkipReason $g.Error 'Directory Readers / Global Reader role')) }
    $script:A2C.Data['EntraPermissions'] = $rows
    $st = 'Collected'
    if ($problems.Count -gt 0) { $st = 'Partial'; foreach ($p in $problems) { Write-A2CLog -Level Warn ('App permissions: ' + $p) } }
    Add-A2CCoverage -Area 'Entra API permissions (application + delegated)' -Status $st -Items $rows.Count -Detail ([string]::Join(' | ', $problems))
    return New-A2CDatasetResult -Status $st
}

$script:A2CEntraPolicyCalls = @(
    @{ Kind = 'Conditional Access policy';       Path = '/v1.0/identity/conditionalAccess/policies'; List = $true }
    @{ Kind = 'Named location';                  Path = '/v1.0/identity/conditionalAccess/namedLocations'; List = $true }
    @{ Kind = 'Authentication strength';         Path = '/v1.0/policies/authenticationStrengthPolicies'; List = $true }
    @{ Kind = 'Authorization policy';            Path = '/v1.0/policies/authorizationPolicy' }
    @{ Kind = 'Security defaults';               Path = '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' }
    @{ Kind = 'Authentication methods policy';   Path = '/v1.0/policies/authenticationMethodsPolicy' }
    @{ Kind = 'Admin consent request policy';    Path = '/v1.0/policies/adminConsentRequestPolicy' }
    @{ Kind = 'Cross-tenant access (default)';   Path = '/v1.0/policies/crossTenantAccessPolicy/default' }
    @{ Kind = 'Cross-tenant access (partner)';   Path = '/v1.0/policies/crossTenantAccessPolicy/partners'; List = $true }
)

function Get-A2CDatasetEntraPolicies {
    # Conditional Access, named locations and the tenant-wide policies. They need the Microsoft Graph permission
    # Policy.Read.All, which the Azure PowerShell sign-in of a user does not carry: then every call is refused and
    # the report says so. A service principal with that application permission reads them.
    $items = [System.Collections.Generic.List[object]]::new()
    $read = [System.Collections.Generic.List[string]]::new()
    $refused = [System.Collections.Generic.List[string]]::new()
    $why = ''
    foreach ($c in $script:A2CEntraPolicyCalls) {
        $got = @()
        $ok = $false; $err = $null
        if ($c.List) { $r = Invoke-A2CGraphList $c.Path; $ok = $r.Ok; $err = $r.Error; $got = @($r.Items) }
        else { $r = Invoke-A2CGraph $c.Path; $ok = $r.Ok; $err = $r.Error; if ($ok -and $null -ne $r.Json) { $got = @($r.Json) } }
        if (-not $ok) {
            $refused.Add($c.Kind)
            if (-not $why) { $why = Get-A2CErrorText $err }
            Write-A2CLog -Level Verbose ('Entra policies - {0} not readable: {1}' -f $c.Kind, (Get-A2CErrorText $err))
            continue
        }
        $read.Add(('{0} {1}' -f $c.Kind, $got.Count))
        foreach ($x in $got) {
            if ($null -eq $x) { continue }
            if (-not $x.id) { $x | Add-Member -NotePropertyName 'id' -NotePropertyValue ($c.Path -replace '^.*/', '') -Force }
            $items.Add([pscustomobject]@{ Kind = $c.Kind; Item = $x })
            Add-A2CRawEntra ($c.Path -replace '^/v1\.0/', '') $x
        }
    }
    $script:A2C.Data['EntraPolicies'] = $items
    $status = 'Collected'; $note = Join-A2C $read ', '
    if ($read.Count -eq 0) {
        $status = 'Skipped'
        $note = 'This sign-in may not read Conditional Access and the tenant policies (needs the Microsoft Graph permission Policy.Read.All, for example a service principal with that application permission) - ' + $why
    }
    elseif ($refused.Count -gt 0) { $status = 'Partial'; $note += ' | not readable: ' + (Join-A2C $refused ', ') + ' (' + $why + ')' }
    Add-A2CCoverage -Area 'Entra policies (Conditional Access, named locations, tenant policies)' -Status $status -Items $items.Count -Detail $note
    if ($status -eq 'Skipped') { Write-A2CLog 'Conditional Access and tenant policies: not readable with this sign-in (needs Policy.Read.All)' }
    else { Write-A2CLog -Level Ok ('{0} Entra policy objects' -f $items.Count) }
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetEntraAppAssignments {
    # Who is assigned to the enterprise applications of the tenant (users, groups, other applications): one call per
    # application. Microsoft's own applications and managed identities are left out.
    $sps = @($script:A2C.Data['EntraSPs'] | Where-Object { $null -ne $_ -and [string]$_.servicePrincipalType -eq 'Application' -and $script:A2CMicrosoftTenants -notcontains [string]$_.appOwnerOrganizationId })
    $rows = [System.Collections.Generic.List[object]]::new()
    $failed = 0; $why = ''
    $i = 0; $t0 = [DateTime]::Now
    foreach ($sp in $sps) {
        $i++
        Write-A2CProgress -Activity 'Application assignments' -Current $i -Total $sps.Count -Started $t0 -Item ([string]$sp.displayName)
        $r = Invoke-A2CGraphList ('/v1.0/servicePrincipals/{0}/appRoleAssignedTo?$top=999' -f $sp.id)
        if (-not $r.Ok) {
            $failed++
            if (-not $why) { $why = Get-A2CErrorText $r.Error }
            if ($failed -ge 5 -and $rows.Count -eq 0 -and $failed -eq $i) { break }   # no access at all
            continue
        }
        $roles = @{}
        foreach ($ar in @($sp.appRoles)) { if ($null -ne $ar) { $roles[([string]$ar.id).ToLowerInvariant()] = $(if ($ar.displayName) { [string]$ar.displayName } else { [string]$ar.value }) } }
        foreach ($a in $r.Items) {
            $rid = ([string]$a.appRoleId).ToLowerInvariant()
            $role = $(if ($roles.ContainsKey($rid)) { $roles[$rid] } elseif ($rid -match '^0{8}-') { 'Default access' } else { $rid })
            $rows.Add([pscustomobject]@{ App = [string]$sp.displayName; AppId = [string]$sp.appId; SpId = [string]$sp.id; PrincipalName = [string]$a.principalDisplayName
                    PrincipalType = [string]$a.principalType; PrincipalId = [string]$a.principalId; Role = $role; Created = $a.createdDateTime })
            Add-A2CRawEntra 'appRoleAssignments' $a
        }
    }
    Write-A2CProgress -Activity 'Application assignments' -Completed
    $script:A2C.Data['EntraAppAssignments'] = $rows
    $status = $(if ($failed -gt 0 -and $rows.Count -eq 0) { 'Skipped' } elseif ($failed -gt 0) { 'Partial' } else { 'Collected' })
    $note = $(if ($failed -gt 0) { ('{0} application(s) not readable: {1}' -f $failed, $why) } else { ('{0} applications asked' -f $sps.Count) })
    Add-A2CCoverage -Area 'Entra application assignments' -Status $status -Items $rows.Count -Detail $note
    return New-A2CDatasetResult -Status $status -Note $note
}

function Get-A2CDatasetEntraDirectoryRoles {
    $rows = [System.Collections.Generic.List[object]]::new()
    $defs = Invoke-A2CGraphList '/v1.0/roleManagement/directory/roleDefinitions?$top=999'
    $script:A2C.Data['EntraRoleDefs'] = $defs.Items
    $ra = $null
    if ($defs.Ok) { $ra = Invoke-A2CGraphList '/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$top=999' }
    if ($defs.Ok -and $ra.Ok) {
        $dn = @{}
        foreach ($d in $defs.Items) { $dn[([string]$d.id).ToLowerInvariant()] = $d; if ($d.isBuiltIn -eq $false) { Add-A2CRawEntra 'roleDefinitions' $d } }
        foreach ($a in $ra.Items) { Add-A2CRawEntra 'roleAssignments' $a }
        foreach ($a in $ra.Items) {
            $d = $dn[([string]$a.roleDefinitionId).ToLowerInvariant()]
            $p = $a.principal
            $rows.Add([pscustomobject]@{ RoleName = $(if ($null -ne $d) { [string]$d.displayName } else { [string]$a.roleDefinitionId }); IsBuiltIn = $(if ($null -ne $d) { [bool]$d.isBuiltIn } else { $null })
                    PrincipalId = ([string]$a.principalId).ToLowerInvariant(); PrincipalType = $(if ($null -ne $p) { ([string]$p.'@odata.type') -replace '^#microsoft\.graph\.', '' } else { '' })
                    PrincipalName = $(if ($null -ne $p) { [string]$p.displayName } else { '' }); PrincipalUPN = $(if ($null -ne $p) { [string]$p.userPrincipalName } else { '' })
                    PrincipalAppId = $(if ($null -ne $p) { [string]$p.appId } else { '' }); Scope = [string]$a.directoryScopeId; Source = 'roleManagement' })
        }
        $script:A2C.Data['EntraDirRoles'] = $rows
        Add-A2CCoverage -Area 'Entra directory roles' -Status Collected -Items $rows.Count -Detail 'Active assignments; PIM eligible assignments are not readable with the Az sign-in token'
        return New-A2CDatasetResult
    }
    # fallback: activated directory roles and their members
    $roles = Invoke-A2CGraphList '/v1.0/directoryRoles'
    if (-not $roles.Ok) {
        $script:A2C.Data['EntraDirRoles'] = $rows
        return New-A2CDatasetResult -Status (Add-A2CEntraCoverage 'Entra directory roles' $roles 'RoleManagement.Read.Directory or a directory role' 0)
    }
    foreach ($role in $roles.Items) {
        $m = Invoke-A2CGraphList ('/v1.0/directoryRoles/{0}/members?$select=id,displayName,userPrincipalName,appId' -f $role.id)
        foreach ($p in $m.Items) {
            $rows.Add([pscustomobject]@{ RoleName = [string]$role.displayName; IsBuiltIn = $true; PrincipalId = ([string]$p.id).ToLowerInvariant()
                    PrincipalType = (([string]$p.'@odata.type') -replace '^#microsoft\.graph\.', ''); PrincipalName = [string]$p.displayName
                    PrincipalUPN = [string]$p.userPrincipalName; PrincipalAppId = [string]$p.appId; Scope = '/'; Source = 'directoryRoles' })
        }
    }
    $script:A2C.Data['EntraDirRoles'] = $rows
    Add-A2CCoverage -Area 'Entra directory roles' -Status Partial -Items $rows.Count -Detail 'roleManagement API not accessible - used activated directoryRoles (tenant scope only, no PIM)'
    return New-A2CDatasetResult -Status 'Partial'
}

function Get-A2CFirst {
    # First non-empty value of several dotted property paths, e.g. 'dataSourceInfo.resourceID'.
    param($Object, [string[]] $Paths)
    if ($null -eq $Object) { return $null }
    foreach ($path in $Paths) {
        $cur = $Object
        foreach ($seg in $path.Split('.')) {
            if ($null -eq $cur) { break }
            $cur = $cur.$seg
        }
        if ($null -ne $cur -and [string]$cur -ne '') { return $cur }
    }
    return $null
}

# ---- Azure DevOps (REST with an Entra token from the Az sign-in; read-only) ------------------------------
$script:A2CAdoApi = @{
    Core = '7.1'; Checks = '7.1-preview.1'; SecureFiles = '7.2-preview.1'; ElasticPools = '7.1'; Catalog = '7.1-preview.1'
    Download = '7.1-preview.1'   # NuGet, Maven and PyPI downloads are preview-only (7.1 answers HTTP 400)
    Extensions = '7.1-preview.1'; Graph = '7.1-preview.1'; Entitlements = '7.1-preview.3'; Analytics = 'v4.0-preview'
}

function Get-A2CAdoOrgSources {
    # Organizations the scanned subscriptions point to - billing links (Microsoft.VisualStudio/account), Managed DevOps
    # Pools and pipeline agent VM extensions - plus the ones named with -AdoOrganization. $Catalog (the tenant's
    # organization list) resolves billing resources that carry the organization ID instead of its name.
    param($Catalog)
    $list = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    $addOrg = {
        param([string] $OrgName, [string] $OrgSource, $BillingResource)
        if (-not $OrgName -or $seen.ContainsKey($OrgName)) { return }
        $seen[$OrgName] = $true
        $list.Add([pscustomobject]@{ Name = $OrgName; Source = $OrgSource; Billing = $BillingResource })
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.visualstudio/account')) {
        $n = [string]$r.name
        $url = [string](Get-A2CProps $r).AccountURL   # often empty
        if ($url) { $u = @(ConvertTo-A2CAdoOrgList $url); if ($u.Count -gt 0) { $n = $u[0] } }
        & $addOrg (Resolve-A2CAdoOrgName $n $Catalog) 'Azure billing' $r
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.devopsinfrastructure/pools')) {
        $op = (Get-A2CProps $r).organizationProfile
        if ($null -eq $op -or [string]$op.kind -ne 'AzureDevOps') { continue }
        foreach ($o in @($op.organizations)) { if ($null -ne $o) { foreach ($n in @(ConvertTo-A2CAdoOrgList ([string]$o.url))) { & $addOrg $n 'Managed DevOps Pool' $null } } }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.compute/virtualmachines/extensions')) {
        $p = Get-A2CProps $r
        if ([string]$p.publisher -ne 'Microsoft.VisualStudio.Services' -or $null -eq $p.settings) { continue }
        foreach ($n in @(ConvertTo-A2CAdoOrgList ([string]$p.settings.VSTSAccountName))) { & $addOrg $n 'Pipeline agent VM extension' $null }
    }
    foreach ($n in @($script:A2C.Options.AdoOrganization)) { & $addOrg $n 'Named (AdoOrganization)' $null }
    return , $list
}

function Resolve-A2CAdoOrgName {
    # A billing resource can carry the organization ID instead of its name: look it up in the tenant organization list.
    param([string] $Name, $Catalog)
    if ($null -eq $Catalog -or $Name -notmatch '^[0-9a-fA-F]{8}-?([0-9a-fA-F]{4}-?){3}[0-9a-fA-F]{12}$') { return $Name }
    $hit = @($Catalog | Where-Object { ([string]$_.'Organization Id' -replace '-', '') -eq ($Name -replace '-', '') })
    if ($hit.Count -gt 0) { return [string]$hit[0].'Organization Name' }
    return $Name
}

function Get-A2CAdoCatalog {
    # All organizations connected to the tenant: the list behind "Organization settings > Microsoft Entra > Download"
    # (CSV). Not a documented API - $null when it cannot be read.
    if (-not $script:A2C.TenantId) { return $null }
    $r = Invoke-A2CAdo ('https://vsaex.dev.azure.com/_apis/EnterpriseCatalog/Organizations?tenantId={0}&api-version={1}' -f $script:A2C.TenantId, $script:A2CAdoApi.Catalog)
    if (-not $r.Ok -or [string]$r.Content -notmatch 'Organization Id') {
        Add-A2CCoverage -Area 'Azure DevOps tenant organization list' -Status Skipped -Detail $(if ($r.Ok) { 'unexpected response' } else { Get-A2CErrorText $r.Error })
        return $null
    }
    $rows = @(([string]$r.Content).TrimStart([char]0xFEFF) -split "`r?`n" | Where-Object { $_ } | ConvertFrom-Csv)
    Add-A2CCoverage -Area 'Azure DevOps tenant organization list' -Status Collected -Items $rows.Count
    return , $rows
}

function New-A2CAdoOrg {
    param($Source)
    $o = [ordered]@{ Name = [string]$Source.Name; Source = [string]$Source.Source; Billing = $Source.Billing
        Url = 'https://dev.azure.com/' + $Source.Name; Id = ''; User = ''; Owner = ''; Status = 'Not collected'; Detail = ''; LastCommit = @{} }
    foreach ($k in @('Problems', 'Projects', 'Repos', 'Policies', 'Pipelines', 'Releases', 'Endpoints', 'Pools', 'ElasticPools', 'Agents',
            'DeploymentGroups', 'Environments', 'VariableGroups', 'SecureFiles', 'Extensions', 'Hooks', 'Feeds', 'Tfvc', 'Users', 'Admins',
            'WorkItems', 'Processes')) { $o[$k] = [System.Collections.Generic.List[object]]::new() }
    return [pscustomobject]$o
}

function New-A2CAdoFeed {
    # A feed ($Project $null = organization-scoped) and what is read about it.
    param($Project, $Item)
    return [pscustomobject]@{ Project = $Project; Item = $Item; Packages = $null; Capped = $false; Items = $null; Metrics = @{}
        Views = $null; Retention = $null; Permissions = $null }
}

function Get-A2CAdoIdentityName {
    # Name of a feed permission holder: "[Web Shop]\Contributors" -> Name Contributors, Scope Web Shop. Without a
    # display name: the identifier of the descriptor ("type;identifier" text or an object).
    param($Permission)
    $n = [string]$Permission.displayName
    if (-not $n) {
        $idd = $Permission.identityDescriptor
        if ($null -ne $idd -and $idd -isnot [string] -and $null -ne $idd.identifier) { $n = [string]$idd.identifier }
        else { $n = ([string]$idd -replace '^[^;]*;', '') }
    }
    if ($n -match '^\[([^\]]+)\]\\(.+)$') { return [pscustomobject]@{ Name = $Matches[2]; Scope = $Matches[1] } }
    return [pscustomobject]@{ Name = $n; Scope = '' }
}

$script:A2CAdoNoDownloads = [pscustomobject]@{ downloadCount = 0; downloadUniqueUsers = 0; lastDownloaded = $null }
$script:A2CAdoProtocols = @{ nuget = 'NuGet'; npm = 'npm'; maven = 'Maven'; pypi = 'PyPI'; cargo = 'Cargo'; upack = 'Universal'; universal = 'Universal' }

function Get-A2CAdoProtocolName {
    # protocolType comes in mixed case (NuGet, Npm, maven, PyPI): one spelling per protocol
    param([string] $Protocol)
    $k = $Protocol.ToLowerInvariant()
    if ($script:A2CAdoProtocols.ContainsKey($k)) { return $script:A2CAdoProtocols[$k] }
    return $Protocol
}

function Test-A2CAdoFromUpstream {
    # A package version saved from an upstream source (npmjs, another feed...) rather than published to the feed.
    # directUpstreamSourceId is only present on those; isCachedVersion is obsolete.
    param($Version)
    $up = [string]$Version.directUpstreamSourceId
    return ([bool]$Version.isCachedVersion -or ($up -and $up -ne '00000000-0000-0000-0000-000000000000'))
}

function Get-A2CAdoFeedScope {
    # "<organization>" or "<organization>/<project id>" in feed URLs
    param([string] $Org, $Feed)
    $s = [uri]::EscapeDataString($Org)
    if ($null -ne $Feed.Project) { $s += '/' + [string]$Feed.Project.id }
    return $s
}

function Get-A2CAdoTfvc {
    # The TFVC content of a project: every branch with its child branches; without branches the whole $/<project> when
    # TFVC is the project's source control or a pipeline uses TFVC. Files, size and the last changeset of each.
    # Every step is logged (TFVC is easy to miss): what was found on screen, the API answers in the log file.
    param($Project, [string] $ProjectUri, [string] $SourceControl, [bool] $UsedByPipelines)
    $v = $script:A2CAdoApi
    $pn = [string]$Project.name
    $root = '$/' + $pn
    $list = [System.Collections.Generic.List[object]]::new()
    $r = Invoke-A2CAdoList ('{0}/_apis/tfvc/branches?includeChildren=true&includeDeleted=false&api-version={1}' -f $ProjectUri, $v.Core)
    if (-not $r.Ok) { Write-A2CLog -Level Verbose ('TFVC {0}: branch list not readable - {1}' -f $pn, (Get-A2CErrorText $r.Error)) }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($x in @($r.Items)) { if ($null -ne $x) { $queue.Enqueue(@($x, '')) } }
    while ($queue.Count -gt 0) {
        $e = $queue.Dequeue()
        $x = $e[0]
        $path = ([string]$x.path).TrimEnd('/')
        foreach ($c in @($x.children)) { if ($null -ne $c) { $queue.Enqueue(@($c, $path)) } }
        if ($x.isDeleted -or -not $path -or -not (Test-A2CAdoTfvcPathOverlap $path $root) -or -not $seen.Add($path)) { continue }
        $owner = ''; if ($null -ne $x.owner) { $owner = [string]$x.owner.displayName }
        $list.Add([pscustomobject]@{ Project = $Project; Path = $path; IsBranch = $true; Parent = $e[1]; Owner = $owner; Created = $x.createdDate
                Files = $null; Bytes = $null; Capped = $false; LastChangeset = $null; LastChange = $null; LastChangeBy = '' })
    }
    Write-A2CLog -Level Verbose ('TFVC {0}: source control {1}, used by pipelines {2}, branch list: {3} answer(s), {4} branch(es) under {5}' -f $pn, $(if ($SourceControl) { $SourceControl } else { 'unknown' }), $UsedByPipelines, @($r.Items).Count, $list.Count, $root)
    if ($list.Count -eq 0) {
        if ($SourceControl -ne 'Tfvc' -and -not $UsedByPipelines) { return , $list }
        # no branches: the whole TFVC folder of the project
        $list.Add([pscustomobject]@{ Project = $Project; Path = $root; IsBranch = $false; Parent = ''; Owner = ''; Created = $null
                Files = $null; Bytes = $null; Capped = $false; LastChangeset = $null; LastChange = $null; LastChangeBy = '' })
    }
    foreach ($b in @($list)) {
        $enc = [uri]::EscapeDataString($b.Path)
        $t0 = [DateTime]::Now
        $items = Invoke-A2CAdo ('{0}/_apis/tfvc/items?scopePath={1}&recursionLevel=Full&api-version={2}' -f $ProjectUri, $enc, $v.Core)
        if ($items.Ok -and $null -ne $items.Json) {
            $files = 0; $bytes = [long]0; $sized = 0
            foreach ($i in @($items.Json.value)) { if ($null -ne $i -and -not $i.isFolder) { $files++; if ($null -ne $i.size) { $sized++; $bytes += [long]$i.size } } }
            $b.Files = $files
            if ($sized -gt 0 -or $files -eq 0) { $b.Bytes = $bytes }
            Write-A2CLog -Level Verbose ('TFVC {0}: {1} items listed in {2:N0} s' -f $b.Path, @($items.Json.value).Count, ([DateTime]::Now - $t0).TotalSeconds)
        }
        else { Write-A2CLog -Level Detail ('TFVC {0}: file list not readable - {1}' -f $b.Path, (Get-A2CShortText (Get-A2CErrorText $items.Error) 200)) }
        if (-not $b.IsBranch -and -not $b.Files) {
            Write-A2CLog -Level Detail ('TFVC {0}: no branches and no files - nothing to inventory' -f $b.Path)
            [void]$list.Remove($b)
            continue
        }
        $cs = Invoke-A2CAdo ('{0}/_apis/tfvc/changesets?searchCriteria.itemPath={1}&$top=1&api-version={2}' -f $ProjectUri, $enc, $v.Core)
        if ($cs.Ok -and $null -ne $cs.Json) {
            $last = @($cs.Json.value | Where-Object { $null -ne $_ })
            if ($last.Count -gt 0) {
                $b.LastChangeset = [int]$last[0].changesetId; $b.LastChange = $last[0].createdDate
                if ($null -ne $last[0].author) { $b.LastChangeBy = [string]$last[0].author.displayName }
            }
        }
        else { Write-A2CLog -Level Verbose ('TFVC {0}: last changeset not readable - {1}' -f $b.Path, (Get-A2CErrorText $cs.Error)) }
        Write-A2CLog -Level Detail ('TFVC {0}{1}: {2} files, {3} MB, last changeset {4}' -f $b.Path, $(if ($b.IsBranch) { '' } else { ' (no branches: whole folder)' }),
            $(if ($null -ne $b.Files) { $b.Files } else { '?' }), $(if ($null -ne $b.Bytes) { [math]::Round($b.Bytes / 1MB, 1) } else { '?' }), $(if ($b.LastChangeset) { $b.LastChangeset } else { '?' }))
    }
    return , $list
}

function Invoke-A2CAdoArea {
    # One collection area of an organization: a failure is noted and the other areas continue.
    # (Parameter names are unusual on purpose: the area scriptblocks read the caller's variables.)
    param($AdoOrgData, [string] $AdoAreaName, [scriptblock] $AdoAreaBody)
    try { & $AdoAreaBody }
    catch { $AdoOrgData.Problems.Add(('{0}: {1}' -f $AdoAreaName, (Get-A2CShortText $_.Exception.Message 200))) }
}

function Get-A2CAdoItems {
    # All items of an Azure DevOps list call; throws with the error text when it fails.
    param([string] $Uri)
    $r = Invoke-A2CAdoList -Uri $Uri
    if (-not $r.Ok) { throw (Get-A2CErrorText $r.Error) }
    return , $r.Items
}

$script:A2CAdoPageSize = 100   # $top of Azure DevOps lists that page with $skip or ids instead of a continuation token

function Get-A2CAdoPagedItems {
    # Azure DevOps GET paged with $top/$skip (projects, packages): until a short page or MaxPages.
    # Returns @{ Items; Capped }; throws with the error text when a call fails.
    param([string] $Uri, [int] $MaxPages = 100)
    $items = [System.Collections.Generic.List[object]]::new()
    $size = $script:A2CAdoPageSize
    $full = $true
    for ($page = 0; $page -lt $MaxPages -and $full; $page++) {
        $r = Invoke-A2CAdo (Set-A2CQueryParam (Set-A2CQueryParam $Uri '$top' ([string]$size)) '$skip' ([string]($page * $size)))
        if (-not $r.Ok) { throw (Get-A2CErrorText $r.Error) }
        $v = @()
        if ($null -ne $r.Json) { $v = @($r.Json.value | Where-Object { $null -ne $_ }) }
        foreach ($x in $v) { $items.Add($x) }
        $full = ($v.Count -ge $size)
    }
    return [pscustomobject]@{ Items = $items; Capped = $full }
}

function Get-A2CAdoVariableGroups {
    # Variable groups page by id: continuationToken = the first id of the next page (queryOrder IdAscending).
    param([string] $ProjectUri)
    $items = [System.Collections.Generic.List[object]]::new()
    $size = $script:A2CAdoPageSize
    $next = 0
    for ($page = 0; $page -lt 100; $page++) {
        $u = '{0}/_apis/distributedtask/variablegroups?queryOrder=IdAscending&$top={1}&api-version={2}' -f $ProjectUri, $size, $script:A2CAdoApi.Core
        if ($next -gt 0) { $u += '&continuationToken=' + $next }
        $r = Invoke-A2CAdo $u
        if (-not $r.Ok) { throw (Get-A2CErrorText $r.Error) }
        $v = @()
        if ($null -ne $r.Json) { $v = @($r.Json.value | Where-Object { $null -ne $_ }) }
        foreach ($x in $v) { $items.Add($x) }
        if ($v.Count -lt $size) { break }
        $next = [int]$v[$v.Count - 1].id + 1
    }
    return , $items
}

$script:A2CAdoPolicyTypes = @{ MinReviewers = 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd'; Build = '0609b952-1397-4640-95ec-e00a01b2c241' }
$script:A2CAdoAnonymousId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'

function Get-A2CAdoOrgData {
    # Everything the report needs from one organization. connectionData tells who we are: a refused token is HTTP 401
    # (X-VSS-ResourceTenant names the organization's tenant) and an organization with public projects answers
    # "Anonymous" - both mean no access.
    param($Source)
    $d = New-A2CAdoOrg $Source
    $v = $script:A2CAdoApi
    $orgEnc = [uri]::EscapeDataString($d.Name)
    $dev = 'https://dev.azure.com/' + $orgEnc
    $cd = Invoke-A2CAdo ($dev + '/_apis/connectionData')
    $who = $null
    if ($cd.Ok -and $null -ne $cd.Json) { $who = $cd.Json.authenticatedUser }
    $denied = ''
    if (-not $cd.Ok) {
        $denied = Get-A2CErrorText $cd.Error
        $rt = [string]$cd.Headers['X-VSS-ResourceTenant']
        if ($rt -and $script:A2C.TenantId -and $rt -notmatch [regex]::Escape($script:A2C.TenantId)) {
            $denied = 'Connected to another Entra tenant (' + $rt + ') - sign in to that tenant to inventory it'
        }
    }
    elseif ($null -eq $who -or [string]$who.id -eq $script:A2CAdoAnonymousId -or [string]$who.descriptor -like 'System:PublicAccess*') {
        $denied = 'Only anonymous access to public projects - your sign-in is not accepted by this organization'
    }
    $projects = $null
    if (-not $denied) {
        try { $projects = (Get-A2CAdoPagedItems ($dev + '/_apis/projects?api-version=' + $v.Core)).Items }
        catch { $denied = $_.Exception.Message }
    }
    if ($denied) {
        $d.Status = 'No access'
        $d.Detail = $denied
        Write-A2CLog -Level Warn ('Azure DevOps {0}: no access - {1}' -f $d.Name, (Get-A2CShortText $d.Detail 200))
        return $d
    }
    $d.Status = 'Collected'
    $d.Id = [string]$cd.Json.instanceId
    $d.User = [string]$who.providerDisplayName
    Write-A2CLog -Level Ok ('Azure DevOps {0}: connected as {1}, {2} project(s)' -f $d.Name, $d.User, $projects.Count)

    # ---- organization level
    Invoke-A2CAdoArea $d 'repositories' {
        foreach ($x in (Get-A2CAdoItems ($dev + '/_apis/git/repositories?includeHidden=true&api-version=' + $v.Core))) { $d.Repos.Add($x) }
    }
    Invoke-A2CAdoArea $d 'agent pools' {
        foreach ($x in (Get-A2CAdoItems ($dev + '/_apis/distributedtask/pools?api-version=' + $v.Core))) { $d.Pools.Add($x) }
    }
    Invoke-A2CAdoArea $d 'scale set agent pools' {
        foreach ($x in (Get-A2CAdoItems ($dev + '/_apis/distributedtask/elasticpools?api-version=' + $v.ElasticPools))) { $d.ElasticPools.Add($x) }
    }
    foreach ($pool in @($d.Pools | Where-Object { -not $_.isHosted -and [string]$_.poolType -ne 'deployment' })) {
        Invoke-A2CAdoArea $d ('agents of pool ' + $pool.name) {
            $u = '{0}/_apis/distributedtask/pools/{1}/agents?includeCapabilities=true&includeLastCompletedRequest=true&api-version={2}' -f $dev, $pool.id, $v.Core
            foreach ($x in (Get-A2CAdoItems $u)) { $d.Agents.Add([pscustomobject]@{ Pool = $pool; Item = $x }) }
        }
    }
    Invoke-A2CAdoArea $d 'extensions' {
        $u = 'https://extmgmt.dev.azure.com/{0}/_apis/extensionmanagement/installedextensions?includeDisabledExtensions=true&api-version={1}' -f $orgEnc, $v.Extensions
        foreach ($x in (Get-A2CAdoItems $u)) { $d.Extensions.Add($x) }
    }
    Invoke-A2CAdoArea $d 'service hooks' {
        foreach ($x in (Get-A2CAdoItems ($dev + '/_apis/hooks/subscriptions?api-version=' + $v.Core))) { $d.Hooks.Add($x) }
    }
    Invoke-A2CAdoArea $d 'feeds' {
        $u = 'https://feeds.dev.azure.com/{0}/_apis/packaging/feeds?api-version={1}' -f $orgEnc, $v.Core
        foreach ($x in (Get-A2CAdoItems $u)) {
            # the organization list can include project feeds: their URLs need the project
            $fp = $null
            if ($null -ne $x.project -and $x.project.id) { $fp = $x.project }
            $d.Feeds.Add((New-A2CAdoFeed $fp $x))
        }
    }
    Invoke-A2CAdoArea $d 'users' {
        $u = 'https://vsaex.dev.azure.com/{0}/_apis/userentitlements?api-version={1}' -f $orgEnc, $v.Entitlements
        foreach ($x in (Get-A2CAdoItems $u)) { $d.Users.Add($x) }
    }
    Invoke-A2CAdoArea $d 'administrators' {
        $vssps = 'https://vssps.dev.azure.com/' + $orgEnc + '/_apis/graph/'
        $groups = Get-A2CAdoItems ($vssps + 'groups?api-version=' + $v.Graph)
        $users = Get-A2CAdoItems ($vssps + 'users?api-version=' + $v.Graph)
        $byDescriptor = @{}
        foreach ($x in (@($groups) + @($users))) { if ($null -ne $x -and $x.descriptor) { $byDescriptor[[string]$x.descriptor] = $x } }
        foreach ($g in $groups) {
            if ([string]$g.principalName -notmatch '\\(Project Collection Administrators|Project Administrators)$') { continue }
            foreach ($m in (Get-A2CAdoItems ('{0}Memberships/{1}?direction=down&api-version={2}' -f $vssps, $g.descriptor, $v.Graph))) {
                $d.Admins.Add([pscustomobject]@{ Group = $g; Member = $byDescriptor[[string]$m.memberDescriptor]; Descriptor = [string]$m.memberDescriptor })
            }
        }
    }
    Invoke-A2CAdoArea $d 'work items (Analytics)' {
        $u = 'https://analytics.dev.azure.com/{0}/_odata/{1}/WorkItems?$apply=groupby((Project/ProjectName,WorkItemType),aggregate($count%20as%20Count))' -f $orgEnc, $v.Analytics
        $all = Invoke-A2CAdoList $u
        if ($all.Ok) { foreach ($x in $all.Items) { $d.WorkItems.Add($x) }; return }
        # an organization-wide query needs access to every project: count project by project instead
        $failed = 0
        foreach ($p in $projects) {
            $pu = 'https://analytics.dev.azure.com/{0}/{1}/_odata/{2}/WorkItems?$apply=groupby((WorkItemType),aggregate($count%20as%20Count))' -f $orgEnc, [uri]::EscapeDataString([string]$p.name), $v.Analytics
            $one = Invoke-A2CAdoList $pu
            if (-not $one.Ok) { $failed++; continue }
            foreach ($x in $one.Items) { $d.WorkItems.Add([pscustomobject]@{ Project = [pscustomobject]@{ ProjectName = [string]$p.name }; WorkItemType = $x.WorkItemType; Count = $x.Count }) }
        }
        if ($failed -gt 0) { throw ('{0} of {1} project(s) not readable ({2})' -f $failed, $projects.Count, (Get-A2CErrorText $all.Error)) }
    }
    Invoke-A2CAdoArea $d 'processes' {
        foreach ($x in (Get-A2CAdoItems ($dev + '/_apis/work/processes?$expand=projects&api-version=' + $v.Core))) { $d.Processes.Add($x) }
    }

    # ---- per project
    $endpointIndex = @{}
    $groupIndex = @{}
    $i = 0; $t0 = [DateTime]::Now
    foreach ($p in $projects) {
        $i++
        Write-A2CProgress -Activity ('Azure DevOps ' + $d.Name) -Current $i -Total $projects.Count -Started $t0 -Item ([string]$p.name)
        $projId = [string]$p.id
        $pdev = $dev + '/' + $projId
        $detail = Invoke-A2CAdo ('{0}/_apis/projects/{1}?includeCapabilities=true&api-version={2}' -f $dev, $projId, $v.Core)
        if ($detail.Ok -and $null -ne $detail.Json) { $d.Projects.Add($detail.Json) } else { $d.Projects.Add($p) }
        Invoke-A2CAdoArea $d ('branch policies of ' + $p.name) {
            foreach ($x in (Get-A2CAdoItems ('{0}/_apis/policy/configurations?api-version={1}' -f $pdev, $v.Core))) { $d.Policies.Add([pscustomobject]@{ ProjectId = $projId; Item = $x }) }
        }
        Invoke-A2CAdoArea $d ('pipelines of ' + $p.name) {
            $u = '{0}/_apis/build/definitions?includeAllProperties=true&includeLatestBuilds=true&queryOrder=definitionNameAscending&$top=500&api-version={1}' -f $pdev, $v.Core
            foreach ($x in (Get-A2CAdoItems $u)) { $d.Pipelines.Add([pscustomobject]@{ Project = $p; Item = $x }) }
        }
        Invoke-A2CAdoArea $d ('release pipelines of ' + $p.name) {
            $u = 'https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?$expand=environments,lastRelease&$top=500&api-version={2}' -f $orgEnc, $projId, $v.Core
            foreach ($x in (Get-A2CAdoItems $u)) { $d.Releases.Add([pscustomobject]@{ Project = $p; Item = $x }) }
        }
        Invoke-A2CAdoArea $d ('service connections of ' + $p.name) {
            foreach ($x in (Get-A2CAdoItems ('{0}/_apis/serviceendpoint/endpoints?includeFailed=true&api-version={1}' -f $pdev, $v.Core))) {
                $k = [string]$x.id
                if (-not $endpointIndex.ContainsKey($k)) {
                    $endpointIndex[$k] = [pscustomobject]@{ Item = $x; Projects = [System.Collections.Generic.List[string]]::new() }
                    $d.Endpoints.Add($endpointIndex[$k])
                }
                $endpointIndex[$k].Projects.Add([string]$p.name)
            }
        }
        Invoke-A2CAdoArea $d ('deployment groups of ' + $p.name) {
            foreach ($x in (Get-A2CAdoItems ('{0}/_apis/distributedtask/deploymentgroups?api-version={1}' -f $pdev, $v.Core))) {
                $targets = Get-A2CAdoItems ('{0}/_apis/distributedtask/deploymentgroups/{1}/targets?api-version={2}' -f $pdev, $x.id, $v.Core)
                $d.DeploymentGroups.Add([pscustomobject]@{ Project = $p; Item = $x; Targets = $targets })
            }
        }
        Invoke-A2CAdoArea $d ('environments of ' + $p.name) {
            foreach ($x in (Get-A2CAdoItems ('{0}/_apis/distributedtask/environments?$top=500&api-version={1}' -f $pdev, $v.Core))) {
                $res = Invoke-A2CAdo ('{0}/_apis/distributedtask/environments/{1}?expands=resourceReferences&api-version={2}' -f $pdev, $x.id, $v.Core)
                $chk = Invoke-A2CAdoList ('{0}/_apis/pipelines/checks/configurations?resourceType=environment&resourceId={1}&api-version={2}' -f $pdev, $x.id, $v.Checks)
                $d.Environments.Add([pscustomobject]@{ Project = $p; Item = $x
                        Resources = $(if ($res.Ok -and $null -ne $res.Json) { @($res.Json.resources | Where-Object { $null -ne $_ }) } else { $null })
                        Checks = $(if ($chk.Ok) { $chk.Items } else { $null }) })
            }
        }
        Invoke-A2CAdoArea $d ('variable groups of ' + $p.name) {
            foreach ($x in (Get-A2CAdoVariableGroups $pdev)) {
                $k = [string]$x.id
                if (-not $groupIndex.ContainsKey($k)) {
                    $groupIndex[$k] = [pscustomobject]@{ Item = $x; Projects = [System.Collections.Generic.List[string]]::new() }
                    $d.VariableGroups.Add($groupIndex[$k])
                }
                $groupIndex[$k].Projects.Add([string]$p.name)
            }
        }
        Invoke-A2CAdoArea $d ('secure files of ' + $p.name) {
            foreach ($x in (Get-A2CAdoItems ('{0}/_apis/distributedtask/securefiles?api-version={1}' -f $pdev, $v.SecureFiles))) { $d.SecureFiles.Add([pscustomobject]@{ Project = $p; Item = $x }) }
        }
        Invoke-A2CAdoArea $d ('feeds of ' + $p.name) {
            $u = 'https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/feeds?api-version={2}' -f $orgEnc, $projId, $v.Core
            foreach ($x in (Get-A2CAdoItems $u)) { $d.Feeds.Add((New-A2CAdoFeed $p $x)) }
        }
    }
    Write-A2CProgress -Activity ('Azure DevOps ' + $d.Name) -Completed

    # ---- TFVC, after all pipelines are known (a pipeline can map TFVC paths of another project). Checked when TFVC is
    # the project's source control or enabled in it, a pipeline maps a path in it, or its capabilities are unknown.
    $tfvcMapped = [System.Collections.Generic.List[string]]::new()
    foreach ($w in $d.Pipelines) { foreach ($x in (Get-A2CAdoTfvcPaths $w.Item)) { $tfvcMapped.Add($x) } }
    foreach ($p in $d.Projects) {
        $vc = $null
        if ($null -ne $p.capabilities) { $vc = $p.capabilities.versioncontrol }
        $scType = ''; $tfvcOn = ''
        if ($null -ne $vc) { $scType = [string]$vc.sourceControlType; $tfvcOn = [string]$vc.tfvcEnabled }
        $tfvcRoot = '$/' + [string]$p.name
        $tfvcUsed = (@($tfvcMapped | Where-Object { Test-A2CAdoTfvcPathOverlap $_ $tfvcRoot }).Count -gt 0)
        if ($scType -eq 'Tfvc' -or $tfvcOn -eq 'True' -or $tfvcUsed -or -not $scType) {
            Invoke-A2CAdoArea $d ('TFVC of ' + $p.name) {
                foreach ($x in (Get-A2CAdoTfvc $p ($dev + '/' + [string]$p.id) $scType $tfvcUsed)) { $d.Tfvc.Add($x) }
            }
        }
        else { Write-A2CLog -Level Verbose ('TFVC {0}: not checked - source control {1}, TFVC not enabled, no pipeline maps {2}' -f $p.name, $scType, $tfvcRoot) }
    }
    if ($d.Tfvc.Count -gt 0) { Write-A2CLog -Level Ok ('Azure DevOps {0}: TFVC in {1} project(s), {2} branch(es) or folder(s)' -f $d.Name, @($d.Tfvc | ForEach-Object { [string]$_.Project.id } | Select-Object -Unique).Count, $d.Tfvc.Count) }
    else { Write-A2CLog -Level Detail ('Azure DevOps {0}: no TFVC found ({1} TFVC path(s) mapped by pipelines)' -f $d.Name, $tfvcMapped.Count) }

    # ---- feeds (one entry per feed, project-scoped wins) with package counts (up to 100 pages)
    $feedIndex = [ordered]@{}
    foreach ($f in $d.Feeds) { $k = [string]$f.Item.id; if (-not $feedIndex.Contains($k) -or $null -ne $f.Project) { $feedIndex[$k] = $f } }
    $d.Feeds.Clear()
    $permDenied = [System.Collections.Generic.List[string]]::new()   # feed permissions are readable by feed owners
    foreach ($f in $feedIndex.Values) {
        $d.Feeds.Add($f)
        $feedUri = 'https://feeds.dev.azure.com/{0}/_apis/packaging/Feeds/{1}' -f (Get-A2CAdoFeedScope $d.Name $f), [string]$f.Item.id
        Invoke-A2CAdoArea $d ('packages of feed ' + $f.Item.name) {
            $pk = Get-A2CAdoPagedItems ($feedUri + '/packages?includeAllVersions=true&includeUrls=false&api-version=' + $v.Core)
            $f.Packages = $pk.Items.Count
            $f.Capped = $pk.Capped
            $f.Items = $pk.Items
            # download count and last download per package: a read-only query for 200 packages at a time; packages that
            # were never downloaded are left out of the answer
            $ids = @($pk.Items | ForEach-Object { [string]$_.id })
            $metricsError = ''
            for ($b = 0; $b -lt $ids.Count; $b += 200) {
                $batch = @($ids[$b..([math]::Min($ids.Count, $b + 200) - 1)])
                $body = '{"packageIds":[' + ((@($batch | ForEach-Object { ConvertTo-A2CJsonLiteral $_ })) -join ',') + ']}'
                $m = Invoke-A2CAdo -Uri ($feedUri + '/packagemetricsbatch?api-version=' + $v.Core) -Method POST -Body $body
                if (-not $m.Ok) { $metricsError = Get-A2CErrorText $m.Error; continue }
                if ($null -ne $m.Json) { foreach ($x in @($m.Json.value)) { if ($null -ne $x) { $f.Metrics[[string]$x.packageId] = $x } } }
                foreach ($id in $batch) { if (-not $f.Metrics.ContainsKey($id)) { $f.Metrics[$id] = $script:A2CAdoNoDownloads } }
            }
            if ($metricsError) { throw ('download counts: ' + $metricsError) }
        }
        Invoke-A2CAdoArea $d ('settings of feed ' + $f.Item.name) {
            $vw = Invoke-A2CAdoList ($feedUri + '/views?api-version=' + $v.Core)
            if ($vw.Ok) { $f.Views = @($vw.Items | ForEach-Object { [string]$_.name } | Sort-Object) }
            # no retention policy: HTTP 200 with the body null
            $rp = Invoke-A2CAdo ($feedUri + '/retentionpolicies?api-version=' + $v.Core)
            if ($rp.Ok -and $null -ne $rp.Json) { $f.Retention = $rp.Json }
            $pm = Invoke-A2CAdoList ($feedUri + '/permissions?includeIds=true&api-version=' + $v.Core)
            if ($pm.Ok) { $f.Permissions = $pm.Items }
            elseif ($pm.Error.Status -eq 401 -or $pm.Error.Status -eq 403) { $permDenied.Add([string]$f.Item.name) }
            else { throw ('permissions: ' + (Get-A2CErrorText $pm.Error)) }
        }
    }
    if ($permDenied.Count -gt 0) {
        $d.Problems.Add(('feed permissions: not readable for {0} of {1} feed(s) with your feed role - feed owners can read them ({2})' -f $permDenied.Count, $d.Feeds.Count, (Join-A2C ($permDenied | Select-Object -First 5))))
    }

    # ---- last commit of every repository with content (one call per repository)
    $repos = @($d.Repos | Where-Object { -not $_.isDisabled -and [long]$_.size -gt 0 -and $_.defaultBranch })
    $i = 0; $t0 = [DateTime]::Now
    foreach ($repo in $repos) {
        $i++
        Write-A2CProgress -Activity ('Azure DevOps ' + $d.Name + ': last commits') -Current $i -Total $repos.Count -Started $t0 -Item ([string]$repo.name)
        $branch = [uri]::EscapeDataString(((([string]$repo.defaultBranch) -replace '^refs/heads/', '')))
        $r = Invoke-A2CAdo ('{0}/{1}/_apis/git/repositories/{2}/commits?searchCriteria.$top=1&searchCriteria.itemVersion.version={3}&api-version={4}' -f $dev, $repo.project.id, $repo.id, $branch, $v.Core)
        if ($r.Ok -and $null -ne $r.Json) {
            $c = @($r.Json.value | Where-Object { $null -ne $_ })
            if ($c.Count -gt 0) { $d.LastCommit[[string]$repo.id] = $c[0].committer.date }
        }
    }
    Write-A2CProgress -Activity ('Azure DevOps ' + $d.Name + ': last commits') -Completed
    return $d
}

function Save-A2CExportFile {
    # An exported file below the run folder: UTF-8 without BOM, as YAML and JSON tools expect; -Bom for PowerShell
    # scripts (Windows PowerShell 5.1 reads BOM-less non-ASCII scripts as ANSI).
    param([string] $File, [string] $Text, [switch] $Bom)
    $path = [IO.Path]::Combine($script:A2C.OutDir, $File)
    $dir = [IO.Path]::GetDirectoryName($path)
    if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
    [IO.File]::WriteAllText($path, $Text, (New-Object System.Text.UTF8Encoding ([bool]$Bom)))
}

function Get-A2CAdoProjectDir {
    # ADO/<organization>/<project>: exported pipelines and repositories of a project
    param([string] $Org, [string] $Project)
    return ('ADO/{0}/{1}' -f (Get-A2CSafePathSegment $Org), (Get-A2CSafePathSegment $Project))
}

function Get-A2CAdoExportDir {
    # ADO/<organization>/<project>/pipelines/<pipeline folder>, safe names ("\Team\Build" -> Team/Build)
    param([string] $Org, [string] $Project, [string] $Folder)
    $parts = @((Get-A2CAdoProjectDir $Org $Project), 'pipelines') +
        @(([string]$Folder).Split('\') | Where-Object { $_ } | ForEach-Object { Get-A2CSafePathSegment $_ })
    return ($parts -join '/')
}

function Get-A2CAdoYaml {
    # The YAML file of a pipeline from its Azure Repos repository, on the branch the definition uses. $null if unreadable.
    param($Org, $Pipeline)
    $x = $Pipeline.Item
    $repoId = [string]$x.repository.id
    $path = [string]$x.process.yamlFilename
    if (-not $repoId -or -not $path) { return $null }
    if (-not $path.StartsWith('/')) { $path = '/' + $path }
    $u = 'https://dev.azure.com/{0}/{1}/_apis/git/repositories/{2}/items?path={3}&includeContent=true&$format=json&api-version={4}' -f
        [uri]::EscapeDataString($Org.Name), [string]$Pipeline.Project.id, $repoId, [uri]::EscapeDataString($path), $script:A2CAdoApi.Core
    $branch = ([string]$x.repository.defaultBranch) -replace '^refs/heads/', ''
    if ($branch) { $u += '&versionDescriptor.versionType=branch&versionDescriptor.version=' + [uri]::EscapeDataString($branch) }
    $r = Invoke-A2CAdo $u
    if (-not $r.Ok -or $null -eq $r.Json) { return $null }
    return [string]$r.Json.content
}

function Get-A2CFreeSpace {
    # Free bytes on the drive of a path; $null when unknown.
    param([string] $Path)
    try { return [long]([IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path)))).AvailableFreeSpace }
    catch { return $null }
}

function Get-A2CAdoTfvcDir {
    # ADO/<organization>/<project>/repos/TFVC/<path below $/<project>>: $/Shop/Trunk/Main -> .../repos/TFVC/Trunk/Main
    param([string] $Org, $Entry)
    $segs = @(([string]$Entry.Path -split '/') | Where-Object { $_ -and $_ -ne '$' })
    $rel = (Get-A2CAdoProjectDir $Org ([string]$Entry.Project.name)) + '/repos/TFVC'
    for ($i = 1; $i -lt $segs.Count; $i++) { $rel += '/' + (Get-A2CSafePathSegment $segs[$i]) }
    return $rel
}

function Test-A2CZipFile {
    # '' when the file is a zip; otherwise the start of its text (Azure DevOps answers errors as JSON)
    param([string] $Path)
    try {
        $fs = [IO.File]::OpenRead($Path)
        try { $buf = New-Object byte[] 600; $n = $fs.Read($buf, 0, 600) } finally { $fs.Dispose() }
        if ($n -ge 4 -and $buf[0] -eq 0x50 -and $buf[1] -eq 0x4B -and ($buf[2] -eq 3 -or $buf[2] -eq 5)) { return '' }
        $s = Get-A2CShortText ([Text.Encoding]::UTF8.GetString($buf, 0, $n)) 300
        if (-not $s) { $s = 'an empty file' }
        return $s
    }
    catch { return $_.Exception.Message }
}

function Get-A2CTfvcZipRoot {
    # The folder of an unpacked TFVC zip that holds the content: the zip may wrap it in folders named like the server
    # path ($, project, branch). The layout found is logged.
    param([string] $Dir, [string] $ServerPath)
    $segs = @(($ServerPath -split '/') | Where-Object { $_ })
    $cur = $Dir
    $hops = [System.Collections.Generic.List[string]]::new()
    while ($true) {
        $e = @(Get-ChildItem -LiteralPath $cur -Force)
        if ($e.Count -ne 1 -or -not $e[0].PSIsContainer -or $segs -notcontains $e[0].Name) { break }
        $hops.Add($e[0].Name)
        $cur = $e[0].FullName
    }
    $top = @(Get-ChildItem -LiteralPath $cur -Force | Select-Object -First 8 | ForEach-Object { $_.Name })
    Write-A2CLog -Level Verbose ('TFVC {0}: zip content{1}: {2}' -f $ServerPath, $(if ($hops.Count -gt 0) { ' below ' + ($hops -join '/') } else { '' }), ($top -join ', '))
    return $cur
}

function Get-A2CDatasetAzureDevOpsRepos {
    # Exports the default branch of every Git repository to ADO/<organization>/<project>/repos/<repository>/ and every TFVC
    # branch to .../repos/TFVC/<branch path> (files, no
    # history), through the same zip download as "Download as Zip" in Azure DevOps. Skips repositories above
    # -AdoRepoMaxSizeMB and those that would not fit on the disk.
    if ($script:A2C.Options.Mask) {
        Add-A2CCoverage -Area 'Azure DevOps repository export' -Status Skipped -Detail 'Disabled with -Mask (source code)'
        return New-A2CDatasetResult -Status 'Skipped' -Note 'Disabled with -Mask'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $max = [long]$script:A2C.Options.AdoRepoMaxSizeMB * 1MB
    $done = @{}
    $skipped = [System.Collections.Generic.List[string]]::new()
    $failed = [System.Collections.Generic.List[string]]::new()
    $zip = [IO.Path]::Combine($script:A2C.OutDir, '.cache-repository.zip')
    foreach ($o in @($script:A2C.Data['Ado'] | Where-Object { $null -ne $_ -and $_.Status -eq 'Collected' })) {
        $i = 0; $t0 = [DateTime]::Now
        foreach ($repo in $o.Repos) {
            $i++
            Write-A2CProgress -Activity ('Repository export ' + $o.Name) -Current $i -Total $o.Repos.Count -Started $t0 -Item ([string]$repo.name)
            $label = [string]$repo.project.name + '/' + [string]$repo.name
            $size = [long]$repo.size
            if ($repo.isDisabled) { $skipped.Add($label + ' (disabled)'); continue }
            if (-not $repo.defaultBranch -or $size -le 0) { $skipped.Add($label + ' (empty)'); continue }
            if ($max -gt 0 -and $size -gt $max) { $skipped.Add(('{0} ({1:N0} MB, above -AdoRepoMaxSizeMB)' -f $label, ($size / 1MB))); continue }
            $free = Get-A2CFreeSpace $script:A2C.OutDir
            if ($null -ne $free -and $free -lt ($size * 3 + 200MB)) { $skipped.Add($label + ' (not enough free disk space)'); continue }
            $rel = (Get-A2CAdoProjectDir $o.Name ([string]$repo.project.name)) + '/repos/' + (Get-A2CSafePathSegment ([string]$repo.name))
            $branch = [uri]::EscapeDataString(((([string]$repo.defaultBranch) -replace '^refs/heads/', '')))
            $u = 'https://dev.azure.com/{0}/{1}/_apis/git/repositories/{2}/items?path=%2F&versionDescriptor.versionType=branch&versionDescriptor.version={3}&$format=zip&download=true&api-version={4}' -f
                [uri]::EscapeDataString($o.Name), [string]$repo.project.id, [string]$repo.id, $branch, $script:A2CAdoApi.Core
            try {
                $r = Invoke-A2CRequest -Method GET -Uri $u -Kind 'ado' -OutFile $zip
                if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) { throw (Get-A2CErrorText (Get-A2CError $r)) }
                $dir = [IO.Path]::Combine($script:A2C.OutDir, $rel)
                [void][IO.Directory]::CreateDirectory($dir)
                [IO.Compression.ZipFile]::ExtractToDirectory($zip, $dir)
                $done[$o.Name + '|' + [string]$repo.id] = $rel
                Write-A2CLog -Level Verbose ('Repository exported: {0} -> {1}' -f $label, $rel)
            }
            catch { $failed.Add($label + ': ' + (Get-A2CShortText $_.Exception.Message 160)) }
            finally { if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue } }
        }
        Write-A2CProgress -Activity ('Repository export ' + $o.Name) -Completed
        # TFVC: the latest version of every branch (or of $/<project> when it has no branches), as a zip like the web UI
        if ($o.Tfvc.Count -eq 0) { Write-A2CLog -Level Detail ('TFVC export {0}: no TFVC branches or folders were found in the inventory' -f $o.Name) }
        foreach ($tb in $o.Tfvc) {
            $label = 'TFVC ' + $tb.Path
            if ($tb.Files -eq 0 -and $null -ne $tb.Files) { $skipped.Add($label + ' (empty)'); Write-A2CLog -Level Detail ($label + ': not exported - no files'); continue }
            $size = [long]$tb.Bytes
            if ($max -gt 0 -and $size -gt $max) {
                $skipped.Add(('{0} ({1:N0} MB, above -AdoRepoMaxSizeMB)' -f $label, ($size / 1MB)))
                Write-A2CLog -Level Detail ('{0}: not exported - {1:N0} MB is above -AdoRepoMaxSizeMB {2}' -f $label, ($size / 1MB), $script:A2C.Options.AdoRepoMaxSizeMB)
                continue
            }
            $free = Get-A2CFreeSpace $script:A2C.OutDir
            if ($null -ne $free -and $free -lt ($size * 3 + 200MB)) { $skipped.Add($label + ' (not enough free disk space)'); Write-A2CLog -Level Detail ($label + ': not exported - not enough free disk space'); continue }
            $rel = Get-A2CAdoTfvcDir $o.Name $tb
            # a single path as a zip: always the whole folder; recursionLevel is refused with path (HTTP 400 ArgumentException)
            $u = 'https://dev.azure.com/{0}/{1}/_apis/tfvc/items?path={2}&download=true&%24format=zip&api-version={3}' -f
                [uri]::EscapeDataString($o.Name), [string]$tb.Project.id, [uri]::EscapeDataString($tb.Path), $script:A2CAdoApi.Download
            Write-A2CLog -Level Detail ('{0}: downloading ({1} files, {2} MB) -> {3}' -f $label, $(if ($null -ne $tb.Files) { $tb.Files } else { '?' }), $(if ($null -ne $tb.Bytes) { [math]::Round($tb.Bytes / 1MB, 1) } else { '?' }), $rel)
            $tmp = [IO.Path]::Combine($script:A2C.OutDir, '.cache-tfvc')
            try {
                $t0 = [DateTime]::Now
                $r = Invoke-A2CRequest -Method GET -Uri $u -Kind 'ado' -OutFile $zip
                if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) { throw (Get-A2CErrorText (Get-A2CError $r)) }
                $bad = Test-A2CZipFile $zip
                if ($bad) { throw ('Azure DevOps did not return a zip: ' + $bad) }
                Write-A2CLog -Level Verbose ('{0}: zip of {1:N1} MB in {2:N0} s' -f $label, ((New-Object IO.FileInfo $zip).Length / 1MB), ([DateTime]::Now - $t0).TotalSeconds)
                if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
                Expand-A2CZip -Zip $zip -Dir $tmp
                $content = Get-A2CTfvcZipRoot $tmp $tb.Path
                $dir = [IO.Path]::Combine($script:A2C.OutDir, $rel)
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dir))
                if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
                [IO.Directory]::Move($content, $dir)
                $n = @(Get-ChildItem -LiteralPath $dir -Recurse -File).Count
                $done[$o.Name + '|tfvc|' + $tb.Path] = $rel
                Write-A2CLog -Level Detail ('{0}: exported {1} files' -f $label, $n)
                if ($null -ne $tb.Files -and $n -ne $tb.Files) { Write-A2CLog -Level Notice ('{0}: the zip had {1} files, the file list {2}' -f $label, $n, $tb.Files) }
            }
            catch {
                $msg = Get-A2CShortText $_.Exception.Message 200
                if ($msg -match '(?i)path.*too long|PathTooLong|260') { $msg += ' - use PowerShell 7 or a short -OutputPath such as C:\a2c' }
                $failed.Add($label + ': ' + $msg)
                Write-A2CLog -Level Detail ('{0}: not exported - {1}' -f $label, $msg)
            }
            finally {
                if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
                if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
            }
        }
    }
    $script:A2C.Data['AdoRepoFolders'] = $done
    foreach ($f in $failed) { Write-A2CLog -Level Warn ('Repository export failed: ' + $f) }
    foreach ($s in $skipped) { Write-A2CLog -Level Verbose ('Repository not exported: ' + $s) }
    $notes = [System.Collections.Generic.List[string]]::new()
    if ($skipped.Count -gt 0) { $notes.Add(('{0} skipped: {1}' -f $skipped.Count, (Join-A2C ($skipped | Select-Object -First 10)))) }
    if ($failed.Count -gt 0) { $notes.Add(('{0} failed (see the log)' -f $failed.Count)) }
    $status = $(if ($failed.Count -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'Azure DevOps repository export' -Status $status -Items $done.Count -Detail (Join-A2C $notes)
    $tfvcDone = @($done.Keys | Where-Object { $_ -like '*|tfvc|*' }).Count
    Write-A2CLog -Level Ok ('{0} Git repositories and {1} TFVC branch(es) exported, {2} skipped, {3} failed' -f ($done.Count - $tfvcDone), $tfvcDone, $skipped.Count, $failed.Count)
    return New-A2CDatasetResult -Status $status
}

function Get-A2CAdoFeedDir {
    # ADO/<organization>/<project>/feeds/<feed>; organization-scoped feeds: ADO/<organization>/feeds/<feed>
    param([string] $Org, $Feed)
    $base = 'ADO/' + (Get-A2CSafePathSegment $Org)
    if ($null -ne $Feed.Project) { $base = Get-A2CAdoProjectDir $Org ([string]$Feed.Project.name) }
    return ($base + '/feeds/' + (Get-A2CSafePathSegment ([string]$Feed.Item.name)))
}

function Get-A2CAdoPackageDir {
    # <feed folder>/<protocol>/<package>/<version>: "@scope/name" (npm) and "group:artifact" (Maven) become two folders
    param([string] $FeedDir, $Package, $Version)
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add($FeedDir)
    $parts.Add((Get-A2CAdoProtocolName ([string]$Package.protocolType)).ToLowerInvariant())
    foreach ($s in ([string]$Package.name -split '[/:]')) { if ($s) { $parts.Add((Get-A2CSafePathSegment $s)) } }
    $parts.Add((Get-A2CSafePathSegment ([string]$Version.version)))
    return ($parts -join '/')
}

function Select-A2CAdoPackageVersions {
    # Versions to download: published to the feed (not cached from an upstream source); the latest one unless -All.
    param($Package, [switch] $All)
    $own = @($Package.versions | Where-Object { $null -ne $_ -and -not (Test-A2CAdoFromUpstream $_) -and -not $_.isDeleted })
    if ($All -or $own.Count -le 1) { return , $own }
    $latest = @($own | Where-Object { $_.isLatest })
    if ($latest.Count -gt 0) { return , @($latest[0]) }
    return , @($own | Sort-Object -Property @{ Expression = { ConvertTo-A2CUtc $_.publishDate } } -Descending | Select-Object -First 1)
}

function ConvertTo-A2CProcessArgument {
    # One command-line argument, quoted the way .NET and CommandLineToArgvW split them (spaces, quotes, backslashes).
    param([string] $Value)
    if ($Value -and $Value -notmatch '[\s"]') { return $Value }
    $s = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $s = [regex]::Replace($s, '(\\+)$', '$1$1')
    return '"' + $s + '"'
}

function Invoke-A2CArtifactTool {
    # Runs ArtifactTool (tests replace this function). $Environment adds variables to the child process only ($null
    # removes one): the token never goes on the command line or into this session's environment, and it is masked in
    # the output. Returns @{ ExitCode; Output (stderr: JSON log lines); Result (stdout) }.
    param([string] $Path, [string[]] $Arguments, [hashtable] $Environment, [int] $TimeoutSec = 7200)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Path
    $psi.Arguments = (@($Arguments | ForEach-Object { ConvertTo-A2CProcessArgument $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($k in @($Environment.Keys)) {
        if ($null -eq $Environment[$k]) { $psi.EnvironmentVariables.Remove($k) } else { $psi.EnvironmentVariables[$k] = [string]$Environment[$k] }
    }
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        # both streams are read in the background, so a full pipe cannot block the tool
        $out = $proc.StandardOutput.ReadToEndAsync()
        $err = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
            try { $proc.Kill() } catch { Write-Verbose 'ArtifactTool already ended' }
            return @{ ExitCode = -1; Output = ('timed out after {0} s' -f $TimeoutSec); Result = '' }
        }
        $proc.WaitForExit()
        $o = [string]$out.Result; $e = [string]$err.Result
        foreach ($v in @($Environment.Values)) { if ([string]$v -and ([string]$v).Length -gt 16) { $o = $o.Replace([string]$v, '***'); $e = $e.Replace([string]$v, '***') } }
        return @{ ExitCode = $proc.ExitCode; Output = $e; Result = $o }
    }
    catch { return @{ ExitCode = -1; Output = $_.Exception.Message; Result = '' } }
}

function Get-A2CArtifactToolError {
    # The error of an ArtifactTool run. Its log lines are JSON (Serilog: @l level, @m message); other text (a crash of
    # the .NET runtime) is used as it is.
    param([string] $Output)
    $msgs = [System.Collections.Generic.List[string]]::new()
    $last = ''
    foreach ($line in ($Output -split "`r?`n")) {
        $s = $line.Trim()
        if (-not $s) { continue }
        $last = $s
        if ($s[0] -ne '{') { continue }
        try { $j = ConvertFrom-Json -InputObject $s -ErrorAction Stop } catch { continue }
        if (@('Error', 'Fatal', 'Critical') -contains [string]$j.'@l' -and $j.'@m') { $msgs.Add([string]$j.'@m') }
    }
    if ($msgs.Count -gt 0) { return [string]::Join(' | ', $msgs) }
    return $last
}

$script:A2CToolsRoot = [IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'), 'azure2csv')
$script:A2CArtifactToolVariable = 'AZURE2CSV_ARTIFACTTOOL_TOKEN'

function Get-A2CArtifactToolPlatform {
    # Executable name and the osName/arch queries of the clienttools release API, spelled the way Azure CLI sends them.
    # On ARM64 the native build is asked for first, then x64 (Windows and macOS run x64 builds emulated).
    $q = [System.Collections.Generic.List[string]]::new()
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $q.Add('osName=Windows&arch=ARM64') }
        $q.Add('osName=Windows&arch=AMD64')
        return @{ Windows = $true; Exe = 'artifacttool.exe'; Queries = $q }
    }
    $os = 'Linux'
    if ($IsMacOS) { $os = 'Darwin' }
    if ([string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { $q.Add('osName=' + $os + '&arch=arm64') }
    if ($os -eq 'Darwin' -or $q.Count -eq 0) { $q.Add('osName=' + $os + '&arch=x86_64') }
    return @{ Windows = $false; Exe = 'artifacttool'; Queries = $q }
}

function Expand-A2CZip {
    # Unpacks a zip into $Dir. Entry names with backslashes (older ArtifactTool zips) become folders, and no entry may
    # land outside $Dir.
    param([string] $Zip, [string] $Dir)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $sep = [IO.Path]::DirectorySeparatorChar
    $full = [IO.Path]::GetFullPath($Dir).TrimEnd($sep) + $sep
    $z = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        foreach ($entry in $z.Entries) {
            $rel = $entry.FullName.Replace('\', '/')
            if (-not $rel -or $rel.EndsWith('/')) { continue }
            $dest = [IO.Path]::GetFullPath([IO.Path]::Combine($full, $rel))
            if (-not $dest.StartsWith($full, [StringComparison]::OrdinalIgnoreCase)) { throw ('zip entry outside the folder: ' + $entry.FullName) }
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest))
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
        }
    }
    finally { $z.Dispose() }
}

function Install-A2CArtifactTool {
    # Downloads an ArtifactTool release zip (a short-lived storage link - no token is sent) and unpacks it into $Dir;
    # older versions next to it are removed. Returns '' or why it failed.
    param([string] $Uri, [string] $Dir, [string] $Exe)
    $root = [IO.Path]::GetDirectoryName($Dir)
    $id = [guid]::NewGuid().ToString('N')
    $zip = [IO.Path]::Combine($root, $id + '.zip')
    $tmp = [IO.Path]::Combine($root, $id)
    try {
        [void][IO.Directory]::CreateDirectory($root)
        $r = Invoke-A2CRequest -Method GET -Uri $Uri -Kind 'web' -OutFile $zip
        if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300 -or -not (Test-Path -LiteralPath $zip)) { return ('ArtifactTool download failed (HTTP {0}: {1})' -f $r.StatusCode, (Get-A2CShortText $r.Content 160)) }
        Expand-A2CZip -Zip $zip -Dir $tmp
        if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($tmp, $Exe)) -PathType Leaf)) { return ('the ArtifactTool zip has no ' + $Exe) }
        if (Test-Path -LiteralPath $Dir) { Remove-Item -LiteralPath $Dir -Recurse -Force }
        [IO.Directory]::Move($tmp, $Dir)
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { & chmod 'a+x' ([IO.Path]::Combine($Dir, $Exe)) }
        foreach ($old in @(Get-ChildItem -LiteralPath $root -Directory | Where-Object { $_.Name -like 'ArtifactTool_*' -and $_.FullName -ne $Dir })) {
            try { Remove-Item -LiteralPath $old.FullName -Recurse -Force -ErrorAction Stop } catch { Write-Verbose ('Old ArtifactTool kept: ' + $old.FullName) }
        }
        return ''
    }
    catch { return ('ArtifactTool could not be installed: ' + (Get-A2CShortText $_.Exception.Message 160)) }
    finally {
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Get-A2CArtifactTool {
    # ArtifactTool for Universal Packages, which have no REST download: -ArtifactToolPath (the executable or its
    # folder), or the release Azure DevOps offers for this platform - the download Azure CLI makes for
    # az artifacts universal download - kept in <LocalAppData>/azure2csv/ArtifactTool/ArtifactTool_<rid>_<version>.
    # On Windows a downloaded copy runs only with a valid Microsoft signature. Returns @{ Path; Source; Note } -
    # Note says why there is no tool.
    param([string] $Org)
    $plat = Get-A2CArtifactToolPlatform
    $own = [string]$script:A2C.Options.ArtifactToolPath
    if ($own) {
        $p = $own
        if (Test-Path -LiteralPath $own -PathType Container) { $p = [IO.Path]::Combine($own, $plat.Exe) }
        if (Test-Path -LiteralPath $p -PathType Leaf) { return @{ Path = (Resolve-Path -LiteralPath $p).ProviderPath; Source = '-ArtifactToolPath'; Note = '' } }
        return @{ Path = ''; Source = ''; Note = 'ArtifactTool not found at -ArtifactToolPath ' + $own }
    }
    # the current release for this platform, asked on every run like Azure CLI does (organizations can get different ones)
    $rel = $null; $why = ''
    foreach ($q in $plat.Queries) {
        $r = Invoke-A2CAdo ('https://vsblob.dev.azure.com/{0}/_apis/clienttools/ArtifactTool/release?{1}&api-version=5.0-preview' -f [uri]::EscapeDataString($Org), $q)
        if ($r.Ok -and $null -ne $r.Json -and [string]$r.Json.uri -match '^https://' -and $r.Json.version) { $rel = $r.Json; break }
        $why = $(if ($r.Ok) { 'unexpected answer' } else { Get-A2CErrorText $r.Error })
    }
    if ($null -eq $rel) { return @{ Path = ''; Source = ''; Note = 'ArtifactTool is not available from Azure DevOps for this platform (' + $why + ')' } }
    $dir = [IO.Path]::Combine($script:A2CToolsRoot, 'ArtifactTool', (Get-A2CSafePathSegment ('ArtifactTool_{0}_{1}' -f $rel.rid, $rel.version)))
    $exe = [IO.Path]::Combine($dir, $plat.Exe)
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        $failure = Install-A2CArtifactTool -Uri ([string]$rel.uri) -Dir $dir -Exe $plat.Exe
        if ($failure) { return @{ Path = ''; Source = ''; Note = $failure } }
    }
    if ($plat.Windows -and -not (Test-A2CMicrosoftSignature $exe)) {
        return @{ Path = ''; Source = ''; Note = ('ArtifactTool {0} has no valid Microsoft signature, so it was not run ({1}); to run it anyway, pass it with -ArtifactToolPath' -f $rel.version, $exe) }
    }
    return @{ Path = $exe; Source = 'version ' + $rel.version + ' from Azure DevOps'; Note = '' }
}

function Save-A2CUniversalPackage {
    # One Universal Package version through ArtifactTool into <run folder>/$Rel. Returns @{ Saved; Failed; Bytes; Note }.
    # The size is asked first (a preview API) so that a package larger than -AdoPackageMaxSizeMB ($MaxBytes), the rest of
    # -AdoPackagesMaxMB ($Budget; 0 = no limit) or the free disk space is skipped before it is downloaded.
    param([string] $Org, $Feed, $Package, $Version, [string] $Rel, [long] $Budget, [long] $MaxBytes)
    $res = @{ Saved = $false; Failed = $false; Bytes = [long]0; Note = '' }
    if ($script:A2C.OutDir -match '^\\\\') { $res.Note = 'Not downloaded: ArtifactTool can write empty files to network shares - use a local -OutputPath'; return $res }
    $tool = $script:A2C.Data['ArtifactTool']
    if ($null -eq $tool) {
        $tool = Get-A2CArtifactTool $Org
        $script:A2C.Data['ArtifactTool'] = $tool
        if ($tool.Path) { Write-A2CLog -Level Ok ('Universal Packages: Microsoft ArtifactTool {0} - {1}' -f $tool.Source, $tool.Path) }
        else { Write-A2CLog -Level Warn ('Universal Packages are not downloaded: ' + $tool.Note) }
    }
    if (-not $tool.Path) { $res.Failed = $true; $res.Note = 'Not downloaded: ' + $tool.Note; return $res }
    $scope = Get-A2CAdoFeedScope $Org $Feed
    $m = Invoke-A2CAdo ('https://pkgs.dev.azure.com/{0}/_packaging/{1}/upack/packages/{2}/versions/{3}?api-version={4}' -f $scope, [string]$Feed.Item.id,
        [uri]::EscapeDataString([string]$Package.name), [uri]::EscapeDataString([string]$Version.version), $script:A2CAdoApi.Download)
    $size = [long]0
    if ($m.Ok -and $null -ne $m.Json -and $null -ne $m.Json.packageSize) { $size = [long]$m.Json.packageSize }
    if ($size -gt 0) {
        $mb = [math]::Ceiling($size / 1MB)
        if ($MaxBytes -gt 0 -and $size -gt $MaxBytes) { $res.Note = ('Not downloaded: {0} MB, above -AdoPackageMaxSizeMB {1}' -f $mb, $script:A2C.Options.AdoPackageMaxSizeMB); return $res }
        if ($Budget -gt 0 -and $size -gt $Budget) { $res.Note = ('Not downloaded: {0} MB, more than what is left of -AdoPackagesMaxMB' -f $mb); return $res }
        $free = Get-A2CFreeSpace $script:A2C.OutDir
        if ($null -ne $free -and $free - $size -lt 1GB) { $res.Note = ('Not downloaded: not enough free disk space for {0} MB' -f $mb); return $res }
    }
    try { $token = Get-A2CBearerToken $script:A2CAdoResource }
    catch { $res.Failed = $true; $res.Note = 'Failed: ' + (Get-A2CShortText $_.Exception.Message 160); return $res }
    $dir = [IO.Path]::Combine($script:A2C.OutDir, $Rel)
    $toolArgs = [System.Collections.Generic.List[string]]::new()
    foreach ($a in @('universal', 'download', '--service', ('https://dev.azure.com/' + $Org + '/'), '--patvar', $script:A2CArtifactToolVariable,
            '--feed', [string]$Feed.Item.id, '--package-name', [string]$Package.name, '--package-version', [string]$Version.version, '--path', $dir, '--verbosity', 'Warning')) { $toolArgs.Add($a) }
    if ($null -ne $Feed.Project) { $toolArgs.Add('--project'); $toolArgs.Add([string]$Feed.Project.id) }
    $envVars = @{ $script:A2CArtifactToolVariable = $token; ARTIFACTTOOL_CACHEDIRECTORY = $null }   # no content cache outside the run folder
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $envVars['DOTNET_SYSTEM_GLOBALIZATION_INVARIANT'] = '1' }   # runs without ICU
    $r = Invoke-A2CArtifactTool -Path $tool.Path -Arguments $toolArgs.ToArray() -Environment $envVars
    if ($r.ExitCode -ne 0) {
        if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
        $res.Failed = $true
        $res.Note = ('Failed: ArtifactTool exit code {0}: {1}' -f $r.ExitCode, (Get-A2CShortText (Get-A2CArtifactToolError $r.Output) 200))
        return $res
    }
    $res.Saved = $true
    if (Test-Path -LiteralPath $dir) { $res.Bytes = [long](@(Get-ChildItem -LiteralPath $dir -Recurse -File) | Measure-Object -Property Length -Sum).Sum }
    return $res
}

function Get-A2CDownloadSize {
    # Size in bytes of an Azure DevOps download without downloading it (tests replace this function); -1 when unknown.
    # Only response headers are read. Azure DevOps answers with a redirect to blob storage, which is asked without the
    # token, or with the content itself.
    param([string] $Uri)
    $script:A2C.Stats['ado'] = [int]$script:A2C.Stats['ado'] + 1
    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(120)
        try {
            $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Uri)
            $req.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', (Get-A2CBearerToken $script:A2CAdoResource))
            [void]$req.Headers.TryAddWithoutValidation('X-TFS-FedAuthRedirect', 'Suppress')
            $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            try {
                $code = [int]$resp.StatusCode
                if ($code -ge 300 -and $code -lt 400 -and $null -ne $resp.Headers.Location) {
                    $loc = $resp.Headers.Location
                    if (-not $loc.IsAbsoluteUri) { $loc = New-Object System.Uri((New-Object System.Uri($Uri)), $loc) }
                    $resp2 = $client.SendAsync((New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $loc)), [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                    try { if ($resp2.IsSuccessStatusCode -and $null -ne $resp2.Content.Headers.ContentLength) { return [long]$resp2.Content.Headers.ContentLength }; $code = [int]$resp2.StatusCode }
                    finally { $resp2.Dispose() }
                }
                elseif ($resp.IsSuccessStatusCode -and $null -ne $resp.Content.Headers.ContentLength) { return [long]$resp.Content.Headers.ContentLength }
                Write-A2CLog -Level Verbose ('Download size unknown (HTTP {0}): {1}' -f $code, (Get-A2CShortUri $Uri))
                return [long]-1
            }
            finally { $resp.Dispose() }
        }
        finally { $client.Dispose() }
    }
    catch {
        Write-A2CLog -Level Verbose ('Download size unknown: {0} - {1}' -f (Get-A2CShortUri $Uri), (Get-A2CShortText $_.Exception.Message 160))
        return [long]-1
    }
}

function Test-A2CMicrosoftSignature {
    # $true when a file carries a valid Authenticode signature of Microsoft (Windows; tests replace this function).
    param([string] $Path)
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return ($sig.Status -eq 'Valid' -and $null -ne $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
    }
    catch { return $false }
}

function Get-A2CAdoPackageFiles {
    # The files of one package version with their download URLs: @{ Files = @(@{ Name; Uri }); Note }. Every download
    # answers with a redirect to blob storage. Maven and PyPI versions list their files (Maven checksum files are left
    # out, publishing creates them again). Universal Packages have no REST download: see Save-A2CUniversalPackage.
    param([string] $Org, $Feed, $Package, $Version)
    $scope = Get-A2CAdoFeedScope $Org $Feed
    $feedId = [string]$Feed.Item.id
    $base = 'https://pkgs.dev.azure.com/{0}/_apis/packaging/feeds/{1}/' -f $scope, $feedId
    $preview = '/content?api-version=' + $script:A2CAdoApi.Download   # NuGet, Maven, PyPI
    $released = '?api-version=' + $script:A2CAdoApi.Core               # npm, Cargo
    $name = [string]$Package.name
    $ver = [string]$Version.version
    $n = [uri]::EscapeDataString($name)
    $vn = [uri]::EscapeDataString($ver)
    $proto = Get-A2CAdoProtocolName ([string]$Package.protocolType)
    $files = [System.Collections.Generic.List[object]]::new()
    switch ($proto) {
        'NuGet' {
            # NuGet addresses versions in their normalized form (1.0 -> 1.0.0)
            if ($Version.normalizedVersion) { $ver = [string]$Version.normalizedVersion; $vn = [uri]::EscapeDataString($ver) }
            $files.Add(@{ Name = ('{0}.{1}.nupkg' -f $name, $ver); Uri = ('{0}nuget/packages/{1}/versions/{2}{3}' -f $base, $n, $vn, $preview); Size = [long]-1 })
        }
        'npm' {
            $leaf = $name; $path = $n
            if ($name -match '^@([^/]+)/(.+)$') { $leaf = $Matches[2]; $path = '@' + [uri]::EscapeDataString($Matches[1]) + '/' + [uri]::EscapeDataString($Matches[2]) }
            $files.Add(@{ Name = ('{0}-{1}.tgz' -f $leaf, $ver); Uri = ('{0}npm/packages/{1}/versions/{2}/content{3}' -f $base, $path, $vn, $released); Size = [long]-1 })
        }
        # not in the REST reference: the released download resource of Cargo feeds
        'Cargo' { $files.Add(@{ Name = ('{0}-{1}.crate' -f $name, $ver); Uri = ('{0}cargo/packages/{1}/versions/{2}/download{3}' -f $base, $n, $vn, $released); Size = [long]-1 }) }
        { $_ -eq 'Maven' -or $_ -eq 'PyPI' } {
            $d = Invoke-A2CAdo ('https://feeds.dev.azure.com/{0}/_apis/packaging/Feeds/{1}/Packages/{2}/versions/{3}?api-version={4}' -f $scope, $feedId, [string]$Package.id, [string]$Version.id, $script:A2CAdoApi.Core)
            if (-not $d.Ok -or $null -eq $d.Json) { return @{ Files = $files; Note = 'Failed: file list not readable (' + (Get-A2CErrorText $d.Error) + ')' } }
            foreach ($fo in @($d.Json.files | Where-Object { $null -ne $_ -and $_.name })) {
                $fn = [string]$fo.name
                if ($proto -eq 'Maven' -and $fn -match '\.(md5|sha1|sha256|sha512)$') { continue }
                # PyPI files carry their size
                $fsize = [long]-1
                if ($null -ne $fo.protocolMetadata -and $null -ne $fo.protocolMetadata.data -and $null -ne $fo.protocolMetadata.data.size) { $fsize = [long]$fo.protocolMetadata.data.size }
                $fe = [uri]::EscapeDataString($fn)
                if ($proto -eq 'PyPI') { $u = '{0}pypi/packages/{1}/versions/{2}/{3}{4}' -f $base, $n, $vn, $fe, $preview }
                else {
                    $ga = $name.Split(':')
                    $u = '{0}maven/{1}/{2}/{3}/{4}{5}' -f $base, [uri]::EscapeDataString($ga[0]), [uri]::EscapeDataString($ga[$ga.Count - 1]), $vn, $fe, $preview
                }
                $files.Add(@{ Name = $fn; Uri = $u; Size = $fsize })
            }
            if ($files.Count -eq 0) { return @{ Files = $files; Note = 'No files listed for this version' } }
        }
        default { return @{ Files = $files; Note = ('{0} package: no download API' -f $proto) } }
    }
    return @{ Files = $files; Note = '' }
}

function Get-A2CDatasetAzureDevOpsPackages {
    # Downloads the package versions published to every feed (not the ones cached from upstream sources) to
    # <feed folder>/<protocol>/<package>/<version>/: the latest version of every package, or all of them with
    # -AdoPackageVersions All. Stops after -AdoPackagesMaxMB in total, or when less than 1 GB of disk space is left.
    # Universal Packages go through Microsoft's ArtifactTool (Save-A2CUniversalPackage).
    if ($script:A2C.Options.Mask) {
        Add-A2CCoverage -Area 'Azure Artifacts package download' -Status Skipped -Detail 'Disabled with -Mask (package files)'
        return New-A2CDatasetResult -Status 'Skipped' -Note 'Disabled with -Mask'
    }
    $all = ([string]$script:A2C.Options.AdoPackageVersions -eq 'All')
    $max = [long]$script:A2C.Options.AdoPackagesMaxMB * 1MB
    $limit = [long]$script:A2C.Options.AdoPackageMaxSizeMB * 1MB   # per version, 0 = none
    $types = @($script:A2C.Options.AdoPackageTypes | Where-Object { $_ })
    Write-A2CLog -Level Detail ('Package download: {0} version of each package, types: {1}, per version: {2}, in total: {3}' -f $(if ($all) { 'every' } else { 'the latest' }),
        $(if ($types.Count -gt 0) { $types -join ', ' } else { 'all' }), $(if ($limit -gt 0) { 'up to ' + $script:A2C.Options.AdoPackageMaxSizeMB + ' MB' } else { 'no limit' }),
        $(if ($max -gt 0) { 'up to ' + $script:A2C.Options.AdoPackagesMaxMB + ' MB' } else { 'no limit' }))
    $done = @{}
    $bytes = [long]0
    $count = 0; $failed = 0; $skipped = 0; $noApi = 0; $tooLarge = 0; $otherType = 0; $capped = $false
    foreach ($o in @($script:A2C.Data['Ado'] | Where-Object { $null -ne $_ -and $_.Status -eq 'Collected' })) {
        foreach ($f in $o.Feeds) {
            $feedDir = Get-A2CAdoFeedDir $o.Name $f
            $feedLabel = 'Feed ' + [string]$f.Item.name + $(if ($null -ne $f.Project) { ' (project ' + [string]$f.Project.name + ')' } else { ' (organization)' })
            if ($null -eq $f.Items) { Write-A2CLog -Level Detail ($feedLabel + ': package list not readable - see the Detail column of organizations.csv'); continue }
            $work = [System.Collections.Generic.List[object]]::new()
            $versions = 0; $fromUpstream = 0
            foreach ($pk in @($f.Items | Where-Object { $null -ne $_ })) {
                foreach ($pv in @($pk.versions | Where-Object { $null -ne $_ })) { $versions++; if (Test-A2CAdoFromUpstream $pv) { $fromUpstream++ } }
                foreach ($pv in (Select-A2CAdoPackageVersions $pk -All:$all)) { $work.Add(@($pk, $pv)) }
            }
            Write-A2CLog -Level Detail ('{0}: {1} version(s), {2} from upstream sources (not downloaded), {3} to download -> {4}' -f $feedLabel, $versions, $fromUpstream, $work.Count, $feedDir)
            if ($work.Count -eq 0) { continue }
            $before = @($count, $tooLarge, $otherType, ($skipped + $noApi), $failed)
            $activity = 'Package download ' + $o.Name + '/' + [string]$f.Item.name
            $i = 0; $t0 = [DateTime]::Now
            foreach ($w in $work) {
                $pk = $w[0]; $pv = $w[1]
                $i++
                $label = [string]$pk.name + ' ' + [string]$pv.version
                Write-A2CProgress -Activity $activity -Current $i -Total $work.Count -Started $t0 -Item $label
                $key = $o.Name + '|' + [string]$f.Item.id + '|' + [string]$pv.id
                if ($max -gt 0 -and $bytes -ge $max) {
                    if (-not $capped) { Write-A2CLog -Level Warn ('Package download: -AdoPackagesMaxMB {0} reached, the remaining packages are listed but not downloaded' -f $script:A2C.Options.AdoPackagesMaxMB) }
                    $capped = $true
                    $done[$key] = @{ Path = ''; Note = 'Not downloaded: -AdoPackagesMaxMB reached' }; $skipped++; continue
                }
                $free = Get-A2CFreeSpace $script:A2C.OutDir
                if ($null -ne $free -and $free -lt 1GB) { $done[$key] = @{ Path = ''; Note = 'Not downloaded: less than 1 GB free disk space' }; $skipped++; continue }
                $proto = Get-A2CAdoProtocolName ([string]$pk.protocolType)
                if ($types.Count -gt 0 -and $types -notcontains $proto) { $done[$key] = @{ Path = ''; Note = ('Not downloaded: {0} is not in -AdoPackageTypes' -f $proto) }; $otherType++; continue }
                if ($proto -eq 'Universal') {
                    $rel = Get-A2CAdoPackageDir $feedDir $pk $pv
                    $u = Save-A2CUniversalPackage -Org $o.Name -Feed $f -Package $pk -Version $pv -Rel $rel -Budget $(if ($max -gt 0) { $max - $bytes } else { 0 }) -MaxBytes $limit
                    if ($u.Saved) { $done[$key] = @{ Path = $rel; Note = '' }; $bytes += $u.Bytes; $count++; continue }
                    $done[$key] = @{ Path = ''; Note = $u.Note }
                    if ($u.Failed) { $failed++; if ($u.Note -notlike 'Not downloaded*') { Write-A2CLog -Level Warn ('Package download failed: {0} - {1}' -f $label, $u.Note) } }
                    elseif ($u.Note -like '*-AdoPackageMaxSizeMB*') { $tooLarge++ } else { $skipped++ }
                    continue
                }
                $plan = Get-A2CAdoPackageFiles $o.Name $f $pk $pv
                if ($plan.Note) {
                    $done[$key] = @{ Path = ''; Note = $plan.Note }
                    if ($plan.Note -like 'Failed*') { $failed++; Write-A2CLog -Level Warn ('Package download failed: {0} - {1}' -f $label, $plan.Note) } else { $noApi++ }
                    continue
                }
                if ($limit -gt 0) {
                    # the size before the download: known from the version (PyPI) or asked with a headers-only request
                    $total = [long]0; $known = $true
                    foreach ($file in $plan.Files) {
                        $fs = [long]$file.Size
                        if ($fs -lt 0) { $fs = [long](Get-A2CDownloadSize $file.Uri) }
                        if ($fs -lt 0) { $known = $false; break }
                        $total += $fs
                    }
                    if ($known -and $total -gt $limit) {
                        $done[$key] = @{ Path = ''; Note = ('Not downloaded: {0} MB, above -AdoPackageMaxSizeMB {1}' -f [math]::Ceiling($total / 1MB), $script:A2C.Options.AdoPackageMaxSizeMB) }
                        $tooLarge++
                        Write-A2CLog -Level Verbose ('Package not downloaded: {0} ({1:N1} MB)' -f $label, ($total / 1MB))
                        continue
                    }
                    if (-not $known) { Write-A2CLog -Level Verbose ('Package size not available before the download: ' + $label) }
                }
                $rel = Get-A2CAdoPackageDir $feedDir $pk $pv
                $dir = [IO.Path]::Combine($script:A2C.OutDir, $rel)
                [void][IO.Directory]::CreateDirectory($dir)
                $got = 0; $err = ''
                foreach ($file in $plan.Files) {
                    $target = [IO.Path]::Combine($dir, (Get-A2CSafePathSegment $file.Name))
                    $r = Invoke-A2CRequest -Method GET -Uri $file.Uri -Kind 'ado' -OutFile $target
                    if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300 -or -not (Test-Path -LiteralPath $target)) {
                        $err = Get-A2CErrorText (Get-A2CError $r)
                        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue }
                        break
                    }
                    $bytes += (New-Object IO.FileInfo $target).Length
                    $got++
                }
                if (-not $err) { $done[$key] = @{ Path = $rel; Note = '' }; $count++; continue }
                $failed++
                Write-A2CLog -Level Warn ('Package download failed: {0} - {1}' -f $label, (Get-A2CShortText $err 200))
                if ($got -gt 0) { $done[$key] = @{ Path = $rel; Note = 'Incomplete: ' + (Get-A2CShortText $err 160) } }
                else {
                    $done[$key] = @{ Path = ''; Note = 'Failed: ' + (Get-A2CShortText $err 160) }
                    if (@([IO.Directory]::GetFileSystemEntries($dir)).Count -eq 0) { [IO.Directory]::Delete($dir) }
                }
            }
            Write-A2CProgress -Activity $activity -Completed
            Write-A2CLog -Level Detail ('{0}: {1} downloaded, {2} above -AdoPackageMaxSizeMB, {3} of other types, {4} not downloaded (total limit, disk space, no download API), {5} failed - see ExportNote in packages.csv' -f
                $feedLabel, ($count - $before[0]), ($tooLarge - $before[1]), ($otherType - $before[2]), (($skipped + $noApi) - $before[3]), ($failed - $before[4]))
        }
    }
    $script:A2C.Data['AdoPackageFiles'] = $done
    $notes = [System.Collections.Generic.List[string]]::new()
    $notes.Add(('{0} version(s), {1:N1} MB' -f $count, ($bytes / 1MB)))
    if ($noApi -gt 0) { $notes.Add(('{0} not downloadable (no download API for the protocol)' -f $noApi)) }
    if ($otherType -gt 0) { $notes.Add(('{0} of types not in -AdoPackageTypes' -f $otherType)) }
    if ($tooLarge -gt 0) { $notes.Add(('{0} above -AdoPackageMaxSizeMB' -f $tooLarge)) }
    if ($skipped -gt 0) { $notes.Add(('{0} not downloaded (-AdoPackagesMaxMB or disk space)' -f $skipped)) }
    if ($failed -gt 0) { $notes.Add(('{0} failed (see the log)' -f $failed)) }
    $status = $(if ($failed -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'Azure Artifacts package download' -Status $status -Items $count -Detail (Join-A2C $notes)
    Write-A2CLog -Level Ok ('{0} package version(s) downloaded ({1:N1} MB), {2} not downloaded ({3} too large, {4} other types), {5} failed' -f $count, ($bytes / 1MB), ($skipped + $noApi + $tooLarge + $otherType), $tooLarge, $otherType, $failed)
    return New-A2CDatasetResult -Status $status
}

function Get-A2CDatasetAzureDevOpsPipelines {
    # Exports the pipelines of every collected organization to ADO/<organization>/<project>/pipelines/<folder>/:
    # <name>.json (the definition - Azure DevOps never returns secret values), <name>.yml (the YAML file, for pipelines
    # in Azure Repos) and releases/<name>.json (classic release pipelines).
    if ($script:A2C.Options.Mask) {
        Add-A2CCoverage -Area 'Azure DevOps pipeline export' -Status Skipped -Detail 'Disabled with -Mask (pipeline definitions contain names and settings)'
        return New-A2CDatasetResult -Status 'Skipped' -Note 'Disabled with -Mask'
    }
    $files = @{}
    $count = 0; $failed = 0; $external = 0
    foreach ($o in @($script:A2C.Data['Ado'] | Where-Object { $null -ne $_ -and $_.Status -eq 'Collected' })) {
        $total = $o.Pipelines.Count + $o.Releases.Count
        $i = 0; $t0 = [DateTime]::Now
        foreach ($w in $o.Pipelines) {
            $i++
            Write-A2CProgress -Activity ('Pipeline export ' + $o.Name) -Current $i -Total $total -Started $t0 -Item ([string]$w.Item.name)
            $x = $w.Item
            $dir = Get-A2CAdoExportDir $o.Name $w.Project.name $x.path
            $name = Get-A2CSafePathSegment ([string]$x.name)
            # the definition without the run summaries that includeLatestBuilds adds
            $def = $x | Select-Object -Property * -ExcludeProperty latestBuild, latestCompletedBuild
            Save-A2CExportFile ($dir + '/' + $name + '.json') (ConvertTo-Json -InputObject $def -Depth 60)
            $main = $dir + '/' + $name + '.json'
            if ($null -ne $x.process -and [int]$x.process.type -eq 2) {
                if ([string]$x.repository.type -eq 'TfsGit') {
                    $yaml = Get-A2CAdoYaml $o $w
                    if ($null -ne $yaml) { Save-A2CExportFile ($dir + '/' + $name + '.yml') $yaml; $main = $dir + '/' + $name + '.yml' } else { $failed++ }
                }
                else { $external++ }   # YAML in GitHub/Bitbucket: only the definition
            }
            $files[$o.Name + '|build|' + [string]$x.id] = $main
            $count++
        }
        foreach ($w in $o.Releases) {
            $i++
            $x = $w.Item
            Write-A2CProgress -Activity ('Pipeline export ' + $o.Name) -Current $i -Total $total -Started $t0 -Item ([string]$x.name)
            $r = Invoke-A2CAdo ('https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions/{2}?api-version={3}' -f [uri]::EscapeDataString($o.Name), [string]$w.Project.id, $x.id, $script:A2CAdoApi.Core)
            if (-not $r.Ok -or $null -eq $r.Json) { $failed++; continue }
            $file = (Get-A2CAdoExportDir $o.Name $w.Project.name ('releases\' + [string]$x.path)) + '/' + (Get-A2CSafePathSegment ([string]$x.name)) + '.json'
            Save-A2CExportFile $file (ConvertTo-Json -InputObject $r.Json -Depth 60)
            $files[$o.Name + '|release|' + [string]$x.id] = $file
            $count++
        }
        Write-A2CProgress -Activity ('Pipeline export ' + $o.Name) -Completed
    }
    $script:A2C.Data['AdoPipelineFiles'] = $files
    $notes = [System.Collections.Generic.List[string]]::new()
    if ($failed -gt 0) { $notes.Add(('{0} YAML file(s) or release definition(s) not readable' -f $failed)) }
    if ($external -gt 0) { $notes.Add(('{0} YAML pipeline(s) in GitHub/Bitbucket: definition only' -f $external)) }
    $status = $(if ($failed -gt 0) { 'Partial' } else { 'Collected' })
    Add-A2CCoverage -Area 'Azure DevOps pipeline export' -Status $status -Items $count -Detail (Join-A2C $notes)
    return New-A2CDatasetResult -Status $status
}

function Get-A2CDatasetAzureDevOps {
    $orgs = [System.Collections.Generic.List[object]]::new()
    $script:A2C.Data['Ado'] = $orgs
    if ((Get-A2CAdoOrgSources $null).Count -eq 0) {
        $note = 'No Azure DevOps organization in the scanned subscriptions (billing link, Managed DevOps Pool, agent VM extension) and no -AdoOrganization'
        Add-A2CCoverage -Area 'Azure DevOps' -Status Skipped -Detail $note
        return New-A2CDatasetResult -Status 'Skipped' -Note $note
    }
    $catalog = Get-A2CAdoCatalog
    $sources = Get-A2CAdoOrgSources $catalog
    foreach ($s in $sources) {
        $o = Get-A2CAdoOrgData $s
        $orgs.Add($o)
        if ($o.Status -ne 'Collected') { Add-A2CCoverage -Area ('Azure DevOps ' + $o.Name) -Status Skipped -Detail ('No access with this account: ' + $o.Detail); continue }
        foreach ($pb in $o.Problems) { Write-A2CLog -Level Warn ('Azure DevOps {0}: {1}' -f $o.Name, $pb) }
        $st = $(if ($o.Problems.Count -gt 0) { 'Partial' } else { 'Collected' })
        Add-A2CCoverage -Area ('Azure DevOps ' + $o.Name) -Status $st -Items $o.Projects.Count -Detail (Join-A2C $o.Problems)
    }
    # the other organizations connected to the tenant are listed, not inventoried
    foreach ($c in @($catalog)) {
        if ($null -eq $c) { continue }
        $n = [string]$c.'Organization Name'
        $known = @($orgs | Where-Object { $_.Name -eq $n -or ($_.Id -and $_.Id -eq [string]$c.'Organization Id') })
        if ($known.Count -gt 0) { foreach ($k in $known) { $k.Owner = [string]$c.Owner; if (-not $k.Id) { $k.Id = [string]$c.'Organization Id' } }; continue }
        if (-not $n) { continue }
        $l = New-A2CAdoOrg ([pscustomobject]@{ Name = $n; Source = 'Connected to the tenant'; Billing = $null })
        $l.Status = 'Listed only'
        $l.Id = [string]$c.'Organization Id'
        $l.Owner = [string]$c.Owner
        $l.Detail = 'Not linked to the scanned subscriptions - add -AdoOrganization ' + $n + ' to inventory it'
        $orgs.Add($l)
    }
    $ok = @($orgs | Where-Object { $_.Status -eq 'Collected' })
    if ($ok.Count -eq 0) { return New-A2CDatasetResult -Status 'Skipped' -Note 'no access to any Azure DevOps organization' }
    if (@($orgs | Where-Object { $_.Status -eq 'No access' }).Count -gt 0 -or @($ok | Where-Object { $_.Problems.Count -gt 0 }).Count -gt 0) { return New-A2CDatasetResult -Status 'Partial' }
    return New-A2CDatasetResult
}

#endregion

#region ============================== 6. ENRICHMENT ===================================================

function Get-A2CTypeCased {
    # Resource type with the casing used in the resource ID, e.g. Microsoft.Compute/virtualMachines.
    param([string] $Id, [string] $Fallback)
    if (-not $Id) { return $Fallback }
    $p = $Id.Trim('/').Split('/')
    $last = -1
    for ($i = 0; $i -lt $p.Count; $i++) { if ($p[$i] -ieq 'providers') { $last = $i } }
    if ($last -lt 0 -or ($last + 2) -ge $p.Count) { return $Fallback }
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add($p[$last + 1])
    for ($j = $last + 2; $j -lt $p.Count; $j += 2) { $parts.Add($p[$j]) }
    return [string]::Join('/', $parts)
}

function Get-A2CParentPath {
    # "servers/srv1" for .../providers/Microsoft.Sql/servers/srv1/databases/db1 (v1 ParentResource column)
    param([string] $Id)
    if (-not $Id) { return '' }
    $p = $Id.Trim('/').Split('/')
    $last = -1
    for ($i = 0; $i -lt $p.Count; $i++) { if ($p[$i] -ieq 'providers') { $last = $i } }
    if ($last -lt 0) { return '' }
    $rest = $p.Count - ($last + 2)
    if ($rest -le 2) { return '' }
    return [string]::Join('/', $p[($last + 2)..($p.Count - 3)])
}

function Get-A2CParentId {
    param([string] $Id)
    if (-not $Id) { return '' }
    $p = $Id.Trim('/').Split('/')
    if ($p.Count -le 2) { return '' }
    return '/' + [string]::Join('/', $p[0..($p.Count - 3)])
}

function Initialize-A2CNetIndex {
    # In-memory network graph built from Resource Graph rows; lookups by resource ID in any RG/subscription.
    if ($null -ne $script:A2C.Data['Net']) { return $script:A2C.Data['Net'] }
    $net = @{ Nic = @{}; Pip = @{}; Subnet = @{}; Vnet = @{}; ZonesByVnet = @{}; LinksByZone = @{}; SubnetByIpConfig = @{} }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/networkinterfaces')) {
        $p = Get-A2CProps $r
        $cfgs = [System.Collections.Generic.List[object]]::new()
        foreach ($c in @($p.ipConfigurations)) {
            if ($null -eq $c) { continue }
            $cp = $c.properties
            $asg = @(foreach ($a in @($cp.applicationSecurityGroups)) { if ($null -ne $a) { [string]$a.id } })
            $cfgs.Add([pscustomobject]@{ Id = [string]$c.id; PrivateIp = [string]$cp.privateIPAddress; SubnetId = [string]$cp.subnet.id
                    PipId = [string]$cp.publicIPAddress.id; AsgIds = $asg; Primary = [bool]$cp.primary })
        }
        $net.Nic[([string]$r.id).ToLowerInvariant()] = [pscustomobject]@{
            Id = [string]$r.id; Name = [string]$r.name; Configs = $cfgs; NsgId = [string]$p.networkSecurityGroup.id
            Dns = @(foreach ($d in @($p.dnsSettings.dnsServers)) { if ($d) { [string]$d } }); VmId = [string]$p.virtualMachine.id
            PeId = [string]$p.privateEndpoint.id; PlsId = [string]$p.privateLinkService.id
        }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/publicipaddresses')) {
        $p = Get-A2CProps $r
        $net.Pip[([string]$r.id).ToLowerInvariant()] = [pscustomobject]@{
            Id = [string]$r.id; Name = [string]$r.name; Ip = [string]$p.ipAddress; Allocation = [string]$p.publicIPAllocationMethod
            Sku = [string]$r.sku.name; Tier = [string]$r.sku.tier; ConfigId = [string]$p.ipConfiguration.id; NatGatewayId = [string]$p.natGateway.id
            Fqdn = [string]$p.dnsSettings.fqdn; Version = [string]$p.publicIPAddressVersion; PrefixId = [string]$p.publicIPPrefix.id
        }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/virtualnetworks')) {
        $p = Get-A2CProps $r
        $vid = ([string]$r.id).ToLowerInvariant()
        $net.Vnet[$vid] = [pscustomobject]@{
            Id = [string]$r.id; Name = [string]$r.name; Row = $r
            Dns = @(foreach ($d in @($p.dhcpOptions.dnsServers)) { if ($d) { [string]$d } })
            Prefixes = @(foreach ($d in @($p.addressSpace.addressPrefixes)) { if ($d) { [string]$d } })
        }
        foreach ($sn in @($p.subnets)) {
            if ($null -eq $sn) { continue }
            $sp = $sn.properties
            $prefixes = [System.Collections.Generic.List[string]]::new()
            if ($sp.addressPrefix) { $prefixes.Add([string]$sp.addressPrefix) }
            foreach ($x in @($sp.addressPrefixes)) { if ($x -and -not $prefixes.Contains([string]$x)) { $prefixes.Add([string]$x) } }
            $sid = ([string]$sn.id).ToLowerInvariant()
            $net.Subnet[$sid] = [pscustomobject]@{
                Id = [string]$sn.id; Name = [string]$sn.name; VnetId = [string]$r.id; VnetName = [string]$r.name; Prefixes = $prefixes.ToArray()
                NsgId = [string]$sp.networkSecurityGroup.id; RouteTableId = [string]$sp.routeTable.id; NatGatewayId = [string]$sp.natGateway.id
                Props = $sp; SubscriptionId = [string]$r.subscriptionId
            }
        }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/privatednszones/virtualnetworklinks')) {
        $p = Get-A2CProps $r
        $vnetId = ([string]$p.virtualNetwork.id).ToLowerInvariant()
        $zone = Get-A2CIdSegment -Id ([string]$r.id) -After 'privateDnsZones'
        $zoneId = (Get-A2CParentId ([string]$r.id)).ToLowerInvariant()
        if ($vnetId) {
            if (-not $net.ZonesByVnet.ContainsKey($vnetId)) { $net.ZonesByVnet[$vnetId] = [System.Collections.Generic.List[string]]::new() }
            if (-not $net.ZonesByVnet[$vnetId].Contains($zone)) { $net.ZonesByVnet[$vnetId].Add($zone) }
        }
        if (-not $net.LinksByZone.ContainsKey($zoneId)) { $net.LinksByZone[$zoneId] = [System.Collections.Generic.List[object]]::new() }
        $net.LinksByZone[$zoneId].Add([pscustomobject]@{
                Id = [string]$r.id; Name = [string]$r.name; VnetId = [string]$p.virtualNetwork.id; Registration = [bool]$p.registrationEnabled
                State = [string]$p.virtualNetworkLinkState; ResolutionPolicy = [string]$p.resolutionPolicy
            })
    }
    $script:A2C.Data['Net'] = $net
    return $net
}

function Get-A2CNetColumns {
    # VM / NIC / VNet networking columns in the v1 format ("nicName:value; nicName2:value").
    param($Row, $Net)
    $res = [ordered]@{ PrivateIP = ''; PublicIP = ''; vnetDNS = ''; vnicDNS = ''; linkedPrivDNSzones = ''; vnet = ''; subnet = ''
        NicNSG = ''; SubnetNSG = ''; ASG = ''; RouteTable = '' }
    $type = ([string]$Row.type).ToLowerInvariant()
    $nicIds = @()
    if ($type -eq 'microsoft.compute/virtualmachines') {
        $p = Get-A2CProps $Row
        $nicIds = @(foreach ($n in @($p.networkProfile.networkInterfaces)) { if ($null -ne $n -and $n.id) { [string]$n.id } })
    }
    elseif ($type -eq 'microsoft.network/networkinterfaces') { $nicIds = @([string]$Row.id) }
    elseif ($type -eq 'microsoft.network/virtualnetworks') {
        $v = $Net.Vnet[([string]$Row.id).ToLowerInvariant()]
        if ($null -ne $v) {
            $res.vnetDNS = $(if ($v.Dns.Count -gt 0) { [string]::Join(', ', $v.Dns) } else { 'Azure-provided' })
            $z = $Net.ZonesByVnet[$v.Id.ToLowerInvariant()]
            if ($null -ne $z) { $res.linkedPrivDNSzones = [string]::Join('; ', $z) }
        }
        return $res
    }
    else { return $res }
    if ($nicIds.Count -eq 0) { return $res }
    $priv = [System.Collections.Generic.List[string]]::new(); $pub = [System.Collections.Generic.List[string]]::new()
    $vn = [System.Collections.Generic.List[string]]::new(); $sn = [System.Collections.Generic.List[string]]::new()
    $vdns = [System.Collections.Generic.List[string]]::new(); $ndns = [System.Collections.Generic.List[string]]::new()
    $zones = [System.Collections.Generic.List[string]]::new(); $nnsg = [System.Collections.Generic.List[string]]::new()
    $snsg = [System.Collections.Generic.List[string]]::new(); $asg = [System.Collections.Generic.List[string]]::new()
    $rt = [System.Collections.Generic.List[string]]::new()
    foreach ($nid in $nicIds) {
        $nic = $Net.Nic[$nid.ToLowerInvariant()]
        $nname = Get-A2CNameFromId $nid
        if ($null -eq $nic) { $priv.Add($nname + ':(NIC not in scope)'); continue }
        $ips = [System.Collections.Generic.List[string]]::new(); $pips = [System.Collections.Generic.List[string]]::new()
        $vnets = [System.Collections.Generic.List[string]]::new(); $subnets = [System.Collections.Generic.List[string]]::new()
        $snNsgs = [System.Collections.Generic.List[string]]::new(); $asgs = [System.Collections.Generic.List[string]]::new()
        $rts = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $nic.Configs) {
            if ($c.PrivateIp) { $ips.Add($c.PrivateIp) }
            if ($c.PipId) {
                $pip = $Net.Pip[$c.PipId.ToLowerInvariant()]
                if ($null -ne $pip) { $pips.Add($(if ($pip.Ip) { $pip.Ip } else { $pip.Name + '(no IP allocated)' })) }
                else { $pips.Add((Get-A2CNameFromId $c.PipId) + '(not in scope)') }
            }
            if ($c.SubnetId) {
                $s = $Net.Subnet[$c.SubnetId.ToLowerInvariant()]
                $vnName = Get-A2CIdSegment -Id $c.SubnetId -After 'virtualNetworks'
                $snName = Get-A2CNameFromId $c.SubnetId
                if (-not $vnets.Contains($vnName)) { $vnets.Add($vnName) }
                if (-not $subnets.Contains($snName)) { $subnets.Add($snName) }
                $vnetId = (Get-A2CParentId $c.SubnetId).ToLowerInvariant()
                $v = $Net.Vnet[$vnetId]
                if ($null -ne $v) {
                    $d = $(if ($v.Dns.Count -gt 0) { [string]::Join(', ', $v.Dns) } else { 'Azure-provided' })
                    if (-not $vdns.Contains($d)) { $vdns.Add($d) }
                    $z = $Net.ZonesByVnet[$vnetId]
                    if ($null -ne $z) { foreach ($zz in $z) { if (-not $zones.Contains($zz)) { $zones.Add($zz) } } }
                }
                if ($null -ne $s) {
                    if ($s.NsgId) { $x = Get-A2CNameFromId $s.NsgId; if (-not $snNsgs.Contains($x)) { $snNsgs.Add($x) } }
                    if ($s.RouteTableId) { $x = Get-A2CNameFromId $s.RouteTableId; if (-not $rts.Contains($x)) { $rts.Add($x) } }
                }
            }
            foreach ($a in $c.AsgIds) { $x = Get-A2CNameFromId $a; if ($x -and -not $asgs.Contains($x)) { $asgs.Add($x) } }
        }
        $priv.Add($nic.Name + ':' + $(if ($ips.Count) { [string]::Join(', ', $ips) } else { 'none' }))
        $pub.Add($nic.Name + ':' + $(if ($pips.Count) { [string]::Join(', ', $pips) } else { 'none' }))
        if ($vnets.Count) { $vn.Add($nic.Name + ':' + [string]::Join(', ', $vnets)) }
        if ($subnets.Count) { $sn.Add($nic.Name + ':' + [string]::Join(', ', $subnets)) }
        if ($nic.Dns.Count) { $ndns.Add($nic.Name + ':' + [string]::Join(', ', $nic.Dns)) }
        if ($nic.NsgId) { $nnsg.Add($nic.Name + ':' + (Get-A2CNameFromId $nic.NsgId)) }
        if ($snNsgs.Count) { $snsg.Add($nic.Name + ':' + [string]::Join(', ', $snNsgs)) }
        if ($asgs.Count) { $asg.Add($nic.Name + ':' + [string]::Join(', ', $asgs)) }
        if ($rts.Count) { $rt.Add($nic.Name + ':' + [string]::Join(', ', $rts)) }
    }
    $res.PrivateIP = [string]::Join('; ', $priv); $res.PublicIP = [string]::Join('; ', $pub)
    $res.vnet = [string]::Join('; ', $vn); $res.subnet = [string]::Join('; ', $sn)
    $res.vnetDNS = [string]::Join('; ', $vdns); $res.vnicDNS = [string]::Join('; ', $ndns)
    $res.linkedPrivDNSzones = [string]::Join('; ', $zones)
    $res.NicNSG = [string]::Join('; ', $nnsg); $res.SubnetNSG = [string]::Join('; ', $snsg)
    $res.ASG = [string]::Join('; ', $asg); $res.RouteTable = [string]::Join('; ', $rt)
    return $res
}

# Lookups used by several reports; they return empty values when the dataset was not collected.
function Get-A2CDiagInfo {
    param([string] $Id)
    $d = $script:A2C.Data['Diag']
    if ($null -ne $d) { $x = $d[$Id.ToLowerInvariant()]; if ($null -ne $x) { return $x } }
    return [pscustomobject]@{ Status = ''; Summary = ''; Count = 0 }
}

function Get-A2CMoveInfo {
    param([string] $Type)
    $m = $script:A2C.Data['MoveIndex']
    if ($null -ne $m -and $Type) {
        $t = $Type.ToLowerInvariant()
        while ($t -match '/') {
            $x = $m[$t]
            if ($null -ne $x) { return $x }
            $t = $t.Substring(0, $t.LastIndexOf('/'))
            if ($t -notmatch '/') { break }
        }
        return [pscustomobject]@{ RG = 'Unknown'; Sub = 'Unknown'; Region = 'Unknown'; Notes = 'Type not listed in Microsoft move-support table' }
    }
    return [pscustomobject]@{ RG = ''; Sub = ''; Region = ''; Notes = '' }
}

function Get-A2CPolicyNcCount {
    param([string] $Id)
    $m = $script:A2C.Data['PolicyNcByResource']
    if ($null -eq $m) { return $null }
    $x = $m[$Id.ToLowerInvariant()]
    if ($null -eq $x) { return 0 }
    return $x
}

function Get-A2CCostInfo {
    param([string] $Id)
    $m = $script:A2C.Data['CostByResource']
    if ($null -eq $m) { return $null }
    return $m[$Id.ToLowerInvariant()]
}

#endregion

#region ============================== 7. REPORT BUILDERS ==============================================

# Column kinds (used by -Mask): p=plain, num, date, bool, guid, sub=subscription name, rg=resource group name,
# name=resource name, id=ARM ID, idList, path=type/name path, pairs="nic:value; ...", list="a; b", ip, ipList,
# tags="k=v; ...", upn, dn=directory display name, fqdn, url, mg=management group name, note=our text (GUIDs masked),
# text=free text (dropped), json (dropped)

# ---- Resources ------------------------------------------------------------------------------------------
Register-A2CSchema 'allResources.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceId:id Id:id Identity:guid Kind ' +
    'Location ManagedBy:id ResourceName:name Name:name ExtensionResourceName:name ParentResource:path PrivateIP:pairs PublicIP:pairs ' +
    'vnetDNS:ipList vnicDNS:pairs linkedPrivDNSzones:list vnet:pairs subnet:pairs Plan Properties:json ResourceGroupName:rg Type ' +
    'ResourceType DiagnosticSettings:text ExtensionResourceType Sku.Name Sku.Tier Sku.Size Sku.Model Sku.Capacity Tags:tags ' +
    'CreatedTime:date ChangedTime:date ETag RowType Zones IdentityType UserAssignedIdentities:list ProvisioningState ' +
    'CanMoveToOtherRG CanMoveToOtherSubscription CanMoveToOtherRegion MoveNotes DiagStatus NicNSG:pairs SubnetNSG:pairs ' +
    'ASG:pairs RouteTable:pairs PolicyNonCompliant:num Cost:num CostCurrency ' +
    'PlanPublisher PlanProduct ExtendedLocation UserAssignedIdentityIds:idList Sku.Family ApiVersion')

Register-A2CSchema 'subscriptions.csv'('SubscriptionId:guid SubscriptionName:sub State InScope SkipReason:note TenantId:guid ' +
    'QuotaId SpendingLimit AuthorizationSource ManagedByTenants:list ParentManagementGroup:mg ManagementGroupPath:list ' +
    'ResourceGroups:num Resources:num Tags:tags Cost:num CostCurrency')

Register-A2CSchema 'resourceTypes.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceType Count:num CanMoveToOtherRG ' +
    'CanMoveToOtherSubscription CanMoveToOtherRegion MoveNotes')

function Get-A2CSortedSubs {
    return , @($script:A2C.Data['Subscriptions'] | Sort-Object Name)
}

function Group-A2CBySubscription {
    param($Items, [string] $Property = 'subscriptionId')
    $h = @{}
    foreach ($x in $Items) {
        $k = ([string]$x.$Property).ToLowerInvariant()
        if (-not $h.ContainsKey($k)) { $h[$k] = [System.Collections.Generic.List[object]]::new() }
        $h[$k].Add($x)
    }
    return $h
}

function New-A2CResourceRow {
    param($R, $Sub, $Net, $Times)
    $id = [string]$R.id
    $lid = $id.ToLowerInvariant()
    $type = [string]$R.type
    $row = [ordered]@{}
    $row['SubscriptionName'] = $Sub.Name
    $row['SubscriptionId'] = [string]$R.subscriptionId
    $row['ResourceId'] = $id
    $row['Id'] = $id
    $ident = $R.identity
    $row['Identity'] = $(if ($null -ne $ident) { [string]$ident.principalId } else { '' })
    $row['Kind'] = [string]$R.kind
    $row['Location'] = [string]$R.location
    $row['ManagedBy'] = [string]$R.managedBy
    $row['ResourceName'] = [string]$R.name
    $row['Name'] = [string]$R.name
    $row['ParentResource'] = Get-A2CParentPath $id
    if ($type -eq 'microsoft.compute/virtualmachines' -or $type -eq 'microsoft.network/networkinterfaces' -or $type -eq 'microsoft.network/virtualnetworks') {
        $nc = Get-A2CNetColumns -Row $R -Net $Net
        foreach ($k in $nc.Keys) { $row[$k] = $nc[$k] }
    }
    $row['Plan'] = $(if ($null -ne $R.plan) { [string]$R.plan.name } else { '' })
    $row['Properties'] = [string]$R.propertiesJson
    $row['ResourceGroupName'] = Get-A2CRgFromId $id
    $cased = Get-A2CTypeCased -Id $id -Fallback $type
    $row['Type'] = $cased
    $row['ResourceType'] = $cased
    $diag = Get-A2CDiagInfo $lid
    $row['DiagnosticSettings'] = $diag.Summary
    $sku = $R.sku
    if ($null -ne $sku) {
        $row['Sku.Name'] = [string]$sku.name; $row['Sku.Tier'] = [string]$sku.tier; $row['Sku.Size'] = [string]$sku.size
        $row['Sku.Model'] = [string]$sku.model; $row['Sku.Capacity'] = [string]$sku.capacity
    }
    $row['Tags'] = ConvertTo-A2CTagString $R.tags
    $t = $Times[$lid]
    if ($null -ne $t) { $row['CreatedTime'] = Format-A2CDate $t[0]; $row['ChangedTime'] = Format-A2CDate $t[1] }
    $row['RowType'] = 'Resource'
    $row['Zones'] = Join-A2C $R.zones ', '
    if ($null -ne $ident) {
        $row['IdentityType'] = [string]$ident.type
        if ($null -ne $ident.userAssignedIdentities) {
            $row['UserAssignedIdentities'] = Join-A2C @(foreach ($pp in $ident.userAssignedIdentities.PSObject.Properties) { Get-A2CNameFromId $pp.Name })
        }
    }
    $row['ProvisioningState'] = [string]$R.provisioningState
    $mv = Get-A2CMoveInfo $type
    $row['CanMoveToOtherRG'] = $mv.RG; $row['CanMoveToOtherSubscription'] = $mv.Sub; $row['CanMoveToOtherRegion'] = $mv.Region; $row['MoveNotes'] = $mv.Notes
    $row['DiagStatus'] = $diag.Status
    $row['PolicyNonCompliant'] = Get-A2CPolicyNcCount $lid
    $c = Get-A2CCostInfo $lid
    if ($null -ne $c) { $row['Cost'] = $c.Cost; $row['CostCurrency'] = $c.Currency }
    # what is needed to create the resource again: the marketplace plan, the edge location, identities by ID
    if ($null -ne $R.plan) { $row['PlanPublisher'] = [string]$R.plan.publisher; $row['PlanProduct'] = [string]$R.plan.product }
    if ($null -ne $R.extendedLocation -and $R.extendedLocation.name) { $row['ExtendedLocation'] = ('{0} ({1})' -f [string]$R.extendedLocation.name, [string]$R.extendedLocation.type) }
    if ($null -ne $ident -and $null -ne $ident.userAssignedIdentities) { $row['UserAssignedIdentityIds'] = Join-A2C @($ident.userAssignedIdentities.PSObject.Properties | ForEach-Object { $_.Name }) }
    if ($null -ne $sku) { $row['Sku.Family'] = [string]$sku.family }
    $row['ApiVersion'] = [string]$R.apiVersion
    return $row
}

function New-A2CReportResources {
    $net = Initialize-A2CNetIndex
    $times = $script:A2C.Data['ResourceTimes']
    if ($null -eq $times) { $times = @{} }
    $rgBySub = Group-A2CBySubscription $script:A2C.Data['ResourceGroups']
    $resBySub = Group-A2CBySubscription $script:A2C.Data['Resources']
    $rows = [System.Collections.Generic.List[object]]::new()
    $typeRows = [System.Collections.Generic.List[object]]::new()
    $subCost = @{}
    foreach ($s in (Get-A2CSortedSubs)) {
        $subRes = $resBySub[$s.Id]
        if ($null -eq $subRes) { $subRes = [System.Collections.Generic.List[object]]::new() }
        $subRgs = $rgBySub[$s.Id]
        if ($null -eq $subRgs) { $subRgs = [System.Collections.Generic.List[object]]::new() }
        $rgCost = @{}
        $resRows = [System.Collections.Generic.List[object]]::new()
        foreach ($r in @($subRes | Sort-Object { [string]$_.id })) {
            $row = New-A2CResourceRow -R $r -Sub $s -Net $net -Times $times
            $resRows.Add($row)
            if ($null -ne $row['Cost'] -and $row['Cost'] -ne '') {
                $rgk = ([string]$row['ResourceGroupName']).ToLowerInvariant()
                $rgCost[$rgk] = [double]$rgCost[$rgk] + [double]$row['Cost']
                $subCost[$s.Id] = [double]$subCost[$s.Id] + [double]$row['Cost']
            }
        }
        $currency = ''
        foreach ($rr in $resRows) { if ($rr['CostCurrency']) { $currency = $rr['CostCurrency']; break } }
        # subscription row
        $sid = '/subscriptions/' + $s.Id
        $sd = Get-A2CDiagInfo $sid
        $srow = [ordered]@{
            SubscriptionName = $s.Name; SubscriptionId = $s.Id; ResourceId = $sid; Id = $sid; ResourceName = $s.Name; Name = $s.Name
            Type = 'Microsoft.Resources/subscriptions'; ResourceType = 'Microsoft.Resources/subscriptions'; Tags = (ConvertTo-A2CTagString $s.Tags)
            RowType = 'Subscription'; DiagnosticSettings = $sd.Summary; DiagStatus = $sd.Status
            Properties = (ConvertTo-A2CJsonString ([ordered]@{ state = $s.State; quotaId = $s.QuotaId; spendingLimit = $s.SpendingLimit; managementGroupAncestors = @($s.MgChain | ForEach-Object { $_.Name }) }))
        }
        $cbs = $script:A2C.Data['CostBySub']
        if ($null -ne $cbs -and $null -ne $cbs[$s.Id] -and $cbs[$s.Id].Status -eq 'Collected') {
            # subscription total from Cost Management (includes costs not tied to a resource)
            $subCost[$s.Id] = [double]$cbs[$s.Id].Total
            $srow['Cost'] = $cbs[$s.Id].Total; $srow['CostCurrency'] = $cbs[$s.Id].Currency
        }
        elseif ($subCost.ContainsKey($s.Id)) { $srow['Cost'] = [math]::Round($subCost[$s.Id], 2); $srow['CostCurrency'] = $currency }
        $rows.Add($srow)
        foreach ($rg in @($subRgs | Sort-Object { [string]$_.name })) {
            $rp = Get-A2CProps $rg
            $rgrow = [ordered]@{
                SubscriptionName = $s.Name; SubscriptionId = $s.Id; ResourceId = [string]$rg.id; Id = [string]$rg.id
                ResourceName = [string]$rg.name; Name = [string]$rg.name; ResourceGroupName = [string]$rg.name; Location = [string]$rg.location
                ManagedBy = [string]$rg.managedBy; Type = 'Microsoft.Resources/resourceGroups'; ResourceType = 'Microsoft.Resources/resourceGroups'
                Tags = (ConvertTo-A2CTagString $rg.tags); RowType = 'ResourceGroup'; ProvisioningState = [string]$rp.provisioningState
            }
            $k = ([string]$rg.name).ToLowerInvariant()
            if ($rgCost.ContainsKey($k)) { $rgrow['Cost'] = [math]::Round($rgCost[$k], 2); $rgrow['CostCurrency'] = $currency }
            $rows.Add($rgrow)
        }
        $rows.AddRange($resRows)
        # resource types of this subscription
        $counts = @{}
        foreach ($rr in $resRows) { $t = [string]$rr['ResourceType']; $counts[$t] = [int]$counts[$t] + 1 }
        foreach ($t in @($counts.Keys | Sort-Object)) {
            $mv = Get-A2CMoveInfo $t
            $typeRows.Add([ordered]@{ SubscriptionName = $s.Name; SubscriptionId = $s.Id; ResourceType = $t; Count = $counts[$t]
                    CanMoveToOtherRG = $mv.RG; CanMoveToOtherSubscription = $mv.Sub; CanMoveToOtherRegion = $mv.Region; MoveNotes = $mv.Notes })
        }
    }
    Add-A2CRows 'allResources.csv' $rows
    Add-A2CRows 'resourceTypes.csv' $typeRows
    # subscriptions.csv
    $subRows = [System.Collections.Generic.List[object]]::new()
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $script:A2C.Data['Subscriptions']) { $all.Add($s) }
    foreach ($s in $script:A2C.Data['SubscriptionsSkipped']) { $all.Add($s) }
    foreach ($s in @($all | Sort-Object Name)) {
        $inScope = -not $s.SkipReason
        $chain = @($s.MgChain)
        $row = [ordered]@{
            SubscriptionId = $s.Id; SubscriptionName = $s.Name; State = $s.State; InScope = $inScope; SkipReason = $s.SkipReason
            TenantId = $s.TenantId; QuotaId = $s.QuotaId; SpendingLimit = $s.SpendingLimit; AuthorizationSource = $s.AuthorizationSource
            ManagedByTenants = $s.ManagedByTenants
            ParentManagementGroup = $(if ($chain.Count -gt 0) { $chain[0].Name } else { '' })
            ManagementGroupPath = [string]::Join('; ', @($chain | ForEach-Object { $_.Name }))
            Tags = (ConvertTo-A2CTagString $s.Tags)
        }
        if ($inScope) {
            $row['ResourceGroups'] = Get-A2CCount $rgBySub[$s.Id]
            $row['Resources'] = Get-A2CCount $resBySub[$s.Id]
            if ($subCost.ContainsKey($s.Id)) { $row['Cost'] = [math]::Round($subCost[$s.Id], 2) }
        }
        $subRows.Add($row)
    }
    Add-A2CRows 'subscriptions.csv' $subRows
}

# ---- Tags -----------------------------------------------------------------------------------------------
Register-A2CSchema 'tags.csv' 'TagName TagValue:tagvalue Subscriptions:num ResourceGroups:num Resources:num Total:num'

function New-A2CReportTags {
    $stats = @{}      # "name`nvalue" -> counters
    $list = @{}       # v1 tagList.json: name -> { value -> "" }
    $add = {
        param($Tags, [string] $Kind)
        foreach ($pair in (Get-A2CTagPairs $Tags)) {
            $key = $pair[0].ToLowerInvariant() + [char]10 + $pair[1]
            if (-not $stats.ContainsKey($key)) { $stats[$key] = [ordered]@{ TagName = $pair[0]; TagValue = $pair[1]; Subscriptions = 0; ResourceGroups = 0; Resources = 0; Total = 0 } }
            $stats[$key][$Kind] = [int]$stats[$key][$Kind] + 1
            $stats[$key]['Total'] = [int]$stats[$key]['Total'] + 1
            if (-not $list.ContainsKey($pair[0])) { $list[$pair[0]] = [ordered]@{} }
            if (-not $list[$pair[0]].Contains($pair[1])) { $list[$pair[0]][$pair[1]] = '' }
        }
    }
    foreach ($s in $script:A2C.Data['Subscriptions']) { & $add $s.Tags 'Subscriptions' }
    foreach ($rg in $script:A2C.Data['ResourceGroups']) { & $add $rg.tags 'ResourceGroups' }
    foreach ($r in $script:A2C.Data['Resources']) { & $add $r.tags 'Resources' }
    $rows = @($stats.Values | Sort-Object @{ Expression = { $_.TagName } }, @{ Expression = { -1 * $_.Total } })
    Add-A2CRows 'tags.csv' $rows
    $script:A2C.Data['TagList'] = $list
}

# ---- shared helpers for typed reports -------------------------------------------------------------------
function New-A2CBaseRow {
    param($R, [switch] $NoLocation)
    $row = [ordered]@{}
    $row['SubscriptionName'] = Get-A2CSubName ([string]$R.subscriptionId)
    $row['SubscriptionId'] = [string]$R.subscriptionId
    $row['ResourceGroup'] = Get-A2CRgFromId ([string]$R.id)
    $row['Name'] = [string]$R.name
    if (-not $NoLocation) { $row['Location'] = [string]$R.location }
    return $row
}

function Get-A2CSortedResources {
    param([string[]] $Type)
    $list = Get-A2CResourcesOfType $Type
    if ($list.Count -eq 0) { return , @() }
    return , @($list | Sort-Object { [string]$_.subscriptionId }, { [string]$_.id })
}

function ConvertTo-A2CYesNo {
    param($Value, [string] $NullText = '')
    if ($null -eq $Value -or [string]$Value -eq '') { return $NullText }
    if ($Value -is [bool]) { if ($Value) { return 'True' } else { return 'False' } }
    return [string]$Value
}

function Get-A2CPeCount {
    param($Props)
    return (Get-A2CCount @($Props.privateEndpointConnections | Where-Object { $null -ne $_ }))
}

# ---- Network --------------------------------------------------------------------------------------------
Register-A2CSchema 'vnets.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location AddressSpace:ipList DnsServers:ipList ' +
    'Subnets:num Peerings:num DdosProtection ConnectedDevices:num Tags:tags Id:id')
Register-A2CSchema 'subnets.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg VNet:name Subnet:name AddressPrefix:ipList NSG:name ' +
    'RouteTable:name NatGateway:name ServiceEndpoints Delegations PrivateEndpointNetworkPolicies PrivateLinkServiceNetworkPolicies ' +
    'DefaultOutboundAccess ConnectedDevices:num Id:id NsgId:id RouteTableId:id NatGatewayId:id ServiceEndpointPolicies:idList')
Register-A2CSchema 'peerings.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg VNet:name Peering:name RemoteVNet:name RemoteVNetId:id ' +
    'RemoteSubscriptionId:guid RemoteInScope State SyncLevel AllowVirtualNetworkAccess AllowForwardedTraffic AllowGatewayTransit ' +
    'UseRemoteGateways RemoteAddressSpace:ipList')

function New-A2CReportVirtualNetworks {
    $vnets = [System.Collections.Generic.List[object]]::new()
    $subnets = [System.Collections.Generic.List[object]]::new()
    $peerings = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.network/virtualnetworks')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $dns = @($p.dhcpOptions.dnsServers | Where-Object { $_ })
        $row['AddressSpace'] = Join-A2C @($p.addressSpace.addressPrefixes) ', '
        $row['DnsServers'] = $(if ($dns.Count -gt 0) { Join-A2C $dns ', ' } else { 'Azure-provided' })
        $sns = @($p.subnets | Where-Object { $null -ne $_ })
        $pes = @($p.virtualNetworkPeerings | Where-Object { $null -ne $_ })
        $row['Subnets'] = $sns.Count
        $row['Peerings'] = $pes.Count
        $row['DdosProtection'] = ConvertTo-A2CYesNo $p.enableDdosProtection 'False'
        $devices = 0
        foreach ($sn in $sns) {
            $sp = $sn.properties
            $cnt = (Get-A2CCount @($sp.ipConfigurations | Where-Object { $null -ne $_ }))
            $devices += $cnt
            $prefixes = [System.Collections.Generic.List[string]]::new()
            if ($sp.addressPrefix) { $prefixes.Add([string]$sp.addressPrefix) }
            foreach ($x in @($sp.addressPrefixes)) { if ($x -and -not $prefixes.Contains([string]$x)) { $prefixes.Add([string]$x) } }
            $subnets.Add([ordered]@{
                    SubscriptionName = $row['SubscriptionName']; SubscriptionId = $row['SubscriptionId']; ResourceGroup = $row['ResourceGroup']
                    VNet = [string]$r.name; Subnet = [string]$sn.name; AddressPrefix = Join-A2C $prefixes ', '
                    NSG = Get-A2CNameFromId ([string]$sp.networkSecurityGroup.id); RouteTable = Get-A2CNameFromId ([string]$sp.routeTable.id)
                    NatGateway = Get-A2CNameFromId ([string]$sp.natGateway.id)
                    ServiceEndpoints = Join-A2C @($sp.serviceEndpoints | ForEach-Object { if ($null -ne $_) { $_.service } }) ', '
                    Delegations = Join-A2C @($sp.delegations | ForEach-Object { if ($null -ne $_) { $_.properties.serviceName } }) ', '
                    PrivateEndpointNetworkPolicies = [string]$sp.privateEndpointNetworkPolicies
                    PrivateLinkServiceNetworkPolicies = [string]$sp.privateLinkServiceNetworkPolicies
                    DefaultOutboundAccess = ConvertTo-A2CYesNo $sp.defaultOutboundAccess 'Not set (enabled)'
                    ConnectedDevices = $cnt; Id = [string]$sn.id
                    NsgId = [string]$sp.networkSecurityGroup.id; RouteTableId = [string]$sp.routeTable.id; NatGatewayId = [string]$sp.natGateway.id
                    ServiceEndpointPolicies = Join-A2C @($sp.serviceEndpointPolicies | ForEach-Object { if ($null -ne $_) { [string]$_.id } })
                })
        }
        $row['ConnectedDevices'] = $devices
        $row['Tags'] = ConvertTo-A2CTagString $r.tags
        $row['Id'] = [string]$r.id
        $vnets.Add($row)
        foreach ($pe in $pes) {
            $pp = $pe.properties
            $remote = [string]$pp.remoteVirtualNetwork.id
            $remoteSub = Get-A2CSubIdFromId $remote
            $peerings.Add([ordered]@{
                    SubscriptionName = $row['SubscriptionName']; SubscriptionId = $row['SubscriptionId']; ResourceGroup = $row['ResourceGroup']
                    VNet = [string]$r.name; Peering = [string]$pe.name; RemoteVNet = Get-A2CNameFromId $remote; RemoteVNetId = $remote
                    RemoteSubscriptionId = $remoteSub; RemoteInScope = ($null -ne (Get-A2CResource $remote))
                    State = [string]$pp.peeringState; SyncLevel = [string]$pp.peeringSyncLevel
                    AllowVirtualNetworkAccess = ConvertTo-A2CYesNo $pp.allowVirtualNetworkAccess; AllowForwardedTraffic = ConvertTo-A2CYesNo $pp.allowForwardedTraffic
                    AllowGatewayTransit = ConvertTo-A2CYesNo $pp.allowGatewayTransit; UseRemoteGateways = ConvertTo-A2CYesNo $pp.useRemoteGateways
                    RemoteAddressSpace = Join-A2C @($pp.remoteAddressSpace.addressPrefixes) ', '
                })
        }
    }
    Add-A2CRows 'vnets.csv' $vnets
    Add-A2CRows 'subnets.csv' $subnets
    Add-A2CRows 'peerings.csv' $peerings
}

Register-A2CSchema 'nsgs.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location CustomRules:num AssociatedSubnets:list ' +
    'AssociatedNICs:list Unused RiskyInboundRules:num Tags:tags Id:id')
Register-A2CSchema 'nsgRules.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg NSG:name Rule:name IsDefault Direction Priority:num ' +
    'Access Protocol Source:ipList SourcePorts Destination:ipList DestinationPorts Description:text Risk SourceAsgIds:idList DestinationAsgIds:idList NsgId:id')

$script:A2CMgmtPorts = @(21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5985, 5986, 6379, 27017)

function Get-A2CMember {
    # Value of a property whose name is built at run time (case-insensitive); $null when missing.
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Get-A2CRuleEndpoint {
    param($RuleProps, [string] $Which)
    $l = [System.Collections.Generic.List[string]]::new()
    $single = Get-A2CMember $RuleProps ($Which + 'AddressPrefix')
    if ($single) { $l.Add([string]$single) }
    foreach ($x in @(Get-A2CMember $RuleProps ($Which + 'AddressPrefixes'))) { if ($x) { $l.Add([string]$x) } }
    foreach ($a in @(Get-A2CMember $RuleProps ($Which + 'ApplicationSecurityGroups'))) { if ($null -ne $a -and $a.id) { $l.Add('ASG:' + (Get-A2CNameFromId ([string]$a.id))) } }
    return (Join-A2C $l ', ')
}

function Get-A2CRulePorts {
    param($RuleProps, [string] $Which)
    $l = [System.Collections.Generic.List[string]]::new()
    $single = Get-A2CMember $RuleProps ($Which + 'PortRange')
    if ($single) { $l.Add([string]$single) }
    foreach ($x in @(Get-A2CMember $RuleProps ($Which + 'PortRanges'))) { if ($x) { $l.Add([string]$x) } }
    return (Join-A2C $l ', ')
}

function Get-A2CNsgRuleRisk {
    param([string] $Direction, [string] $Access, [string] $Source, [string] $Ports)
    if ($Direction -ne 'Inbound' -or $Access -ne 'Allow') { return '' }
    $open = $false
    foreach ($s in ($Source -split ',\s*')) { if (@('*', 'Internet', '0.0.0.0/0', 'Any', '::/0') -contains $s) { $open = $true } }
    if (-not $open) { return '' }
    $hits = [System.Collections.Generic.List[string]]::new()
    foreach ($t in ($Ports -split ',\s*')) {
        if ($t -eq '*') { return 'High: all ports open to the Internet' }
        $lo = 0; $hi = 0
        if ($t -match '^(\d+)-(\d+)$') { $lo = [int]$Matches[1]; $hi = [int]$Matches[2] }
        elseif ($t -match '^\d+$') { $lo = [int]$t; $hi = $lo }
        else { continue }
        foreach ($m in $script:A2CMgmtPorts) { if ($m -ge $lo -and $m -le $hi -and -not $hits.Contains([string]$m)) { $hits.Add([string]$m) } }
    }
    if ($hits.Count -gt 0) { return ('High: port {0} open to the Internet' -f [string]::Join('/', $hits)) }
    return 'Medium: open to the Internet'
}

function New-A2CReportNetworkSecurity {
    $nsgs = [System.Collections.Generic.List[object]]::new()
    $rules = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.network/networksecuritygroups')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $custom = @($p.securityRules | Where-Object { $null -ne $_ })
        $defaults = @($p.defaultSecurityRules | Where-Object { $null -ne $_ })
        $sn = @(foreach ($x in @($p.subnets)) { if ($null -ne $x -and $x.id) { (Get-A2CIdSegment -Id ([string]$x.id) -After 'virtualNetworks') + '/' + (Get-A2CNameFromId ([string]$x.id)) } })
        $nics = @(foreach ($x in @($p.networkInterfaces)) { if ($null -ne $x -and $x.id) { Get-A2CNameFromId ([string]$x.id) } })
        $risky = 0
        foreach ($set in @(@{ Rules = $custom; Default = $false }, @{ Rules = $defaults; Default = $true })) {
            foreach ($rule in $set.Rules) {
                $rp = $rule.properties
                $src = Get-A2CRuleEndpoint $rp 'source'
                $dstPorts = Get-A2CRulePorts $rp 'destination'
                $risk = Get-A2CNsgRuleRisk -Direction ([string]$rp.direction) -Access ([string]$rp.access) -Source $src -Ports $dstPorts
                if ($risk) { $risky++ }
                $rules.Add([ordered]@{
                        SubscriptionName = $row['SubscriptionName']; SubscriptionId = $row['SubscriptionId']; ResourceGroup = $row['ResourceGroup']
                        NSG = [string]$r.name; Rule = [string]$rule.name; IsDefault = $set.Default; Direction = [string]$rp.direction
                        Priority = $rp.priority; Access = [string]$rp.access; Protocol = [string]$rp.protocol; Source = $src
                        SourcePorts = Get-A2CRulePorts $rp 'source'; Destination = Get-A2CRuleEndpoint $rp 'destination'
                        DestinationPorts = $dstPorts; Description = [string]$rp.description; Risk = $risk
                        SourceAsgIds = Join-A2C @($rp.sourceApplicationSecurityGroups | ForEach-Object { if ($null -ne $_) { [string]$_.id } })
                        DestinationAsgIds = Join-A2C @($rp.destinationApplicationSecurityGroups | ForEach-Object { if ($null -ne $_) { [string]$_.id } }); NsgId = [string]$r.id
                    })
            }
        }
        $row['CustomRules'] = $custom.Count
        $row['AssociatedSubnets'] = Join-A2C $sn
        $row['AssociatedNICs'] = Join-A2C $nics
        $row['Unused'] = ($sn.Count -eq 0 -and $nics.Count -eq 0)
        $row['RiskyInboundRules'] = $risky
        $row['Tags'] = ConvertTo-A2CTagString $r.tags
        $row['Id'] = [string]$r.id
        $nsgs.Add($row)
    }
    Add-A2CRows 'nsgs.csv' $nsgs
    Add-A2CRows 'nsgRules.csv' $rules
}

Register-A2CSchema 'routeTables.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Routes:num ' +
    'DisableBgpRoutePropagation AssociatedSubnets:list Tags:tags Id:id')
Register-A2CSchema 'routes.csv' 'SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg RouteTable:name Route:name AddressPrefix:ipList NextHopType NextHopIp:ip'

function New-A2CReportRouting {
    $rts = [System.Collections.Generic.List[object]]::new()
    $routes = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.network/routetables')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $rs = @($p.routes | Where-Object { $null -ne $_ })
        foreach ($x in $rs) {
            $routes.Add([ordered]@{ SubscriptionName = $row['SubscriptionName']; SubscriptionId = $row['SubscriptionId']; ResourceGroup = $row['ResourceGroup']
                    RouteTable = [string]$r.name; Route = [string]$x.name; AddressPrefix = [string]$x.properties.addressPrefix
                    NextHopType = [string]$x.properties.nextHopType; NextHopIp = [string]$x.properties.nextHopIpAddress })
        }
        $row['Routes'] = $rs.Count
        $row['DisableBgpRoutePropagation'] = ConvertTo-A2CYesNo $p.disableBgpRoutePropagation 'False'
        $row['AssociatedSubnets'] = Join-A2C @(foreach ($x in @($p.subnets)) { if ($null -ne $x -and $x.id) { (Get-A2CIdSegment -Id ([string]$x.id) -After 'virtualNetworks') + '/' + (Get-A2CNameFromId ([string]$x.id)) } })
        $row['Tags'] = ConvertTo-A2CTagString $r.tags
        $row['Id'] = [string]$r.id
        $rts.Add($row)
    }
    Add-A2CRows 'routeTables.csv' $rts
    Add-A2CRows 'routes.csv' $routes
}

Register-A2CSchema 'publicIps.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location IpAddress:ip Version Allocation ' +
    'Sku Tier Zones AttachedTo:name AttachedToType AttachedVm:name Fqdn:fqdn Unused Tags:tags Id:id')

function Get-A2CAttachment {
    # Resource that owns an ipConfiguration / reference ID: @{ Name; Type; Id; Vm }
    param([string] $RefId)
    if (-not $RefId) { return $null }
    $top = Get-A2CTopLevelId $RefId
    $vm = ''
    $res = Get-A2CResource $top
    if ($null -ne $res -and ([string]$res.type) -eq 'microsoft.network/networkinterfaces') {
        $np = Get-A2CProps $res
        if ($np.virtualMachine.id) { $vm = Get-A2CNameFromId ([string]$np.virtualMachine.id) }
    }
    return [pscustomobject]@{ Name = Get-A2CNameFromId $top; Type = Get-A2CTypeCased -Id $top -Fallback ''; Id = $top; Vm = $vm }
}

function New-A2CReportPublicIPs {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.network/publicipaddresses')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $att = Get-A2CAttachment ([string]$p.ipConfiguration.id)
        if ($null -eq $att -and $p.natGateway.id) { $att = Get-A2CAttachment ([string]$p.natGateway.id) }
        $row['IpAddress'] = [string]$p.ipAddress
        $row['Version'] = [string]$p.publicIPAddressVersion
        $row['Allocation'] = [string]$p.publicIPAllocationMethod
        $row['Sku'] = [string]$r.sku.name
        $row['Tier'] = [string]$r.sku.tier
        $row['Zones'] = Join-A2C $r.zones ', '
        if ($null -ne $att) { $row['AttachedTo'] = $att.Name; $row['AttachedToType'] = $att.Type; $row['AttachedVm'] = $att.Vm }
        $row['Fqdn'] = [string]$p.dnsSettings.fqdn
        $row['Unused'] = ($null -eq $att -and -not $p.publicIPPrefix.id)
        $row['Tags'] = ConvertTo-A2CTagString $r.tags
        $row['Id'] = [string]$r.id
        $rows.Add($row)
    }
    Add-A2CRows 'publicIps.csv' $rows
}

Register-A2CSchema 'privateEndpoints.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location VNet:name Subnet:name ' +
    'TargetResource:name TargetResourceType TargetResourceId:id GroupIds ConnectionState PrivateIPs:ipList Fqdns:fqdn Id:id ' +
    'SubnetId:id TargetResourceIds:idList DnsRecords:pairs ManualApproval NetworkInterfaces:idList')

function New-A2CReportPrivateEndpoints {
    $net = Initialize-A2CNetIndex
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.network/privateendpoints')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $sid = [string]$p.subnet.id
        $row['VNet'] = Get-A2CIdSegment -Id $sid -After 'virtualNetworks'
        $row['Subnet'] = Get-A2CNameFromId $sid
        $conns = @(@($p.privateLinkServiceConnections) + @($p.manualPrivateLinkServiceConnections) | Where-Object { $null -ne $_ })
        $targets = @(foreach ($c in $conns) { [string]$c.properties.privateLinkServiceId })
        $t0 = $(if ($targets.Count -gt 0) { $targets[0] } else { '' })
        $row['TargetResource'] = Get-A2CNameFromId $t0
        $row['TargetResourceType'] = Get-A2CTypeCased -Id $t0 -Fallback ''
        $row['TargetResourceId'] = $t0
        $row['GroupIds'] = Join-A2C @(foreach ($c in $conns) { $c.properties.groupIds }) ', '
        $row['ConnectionState'] = Join-A2C @(foreach ($c in $conns) { $c.properties.privateLinkServiceConnectionState.status }) ', '
        $ips = [System.Collections.Generic.List[string]]::new()
        $fqdns = [System.Collections.Generic.List[string]]::new()
        foreach ($d in @($p.customDnsConfigs)) {
            if ($null -eq $d) { continue }
            if ($d.fqdn) { $fqdns.Add([string]$d.fqdn) }
            foreach ($ip in @($d.ipAddresses)) { if ($ip -and -not $ips.Contains([string]$ip)) { $ips.Add([string]$ip) } }
        }
        if ($ips.Count -eq 0) {
            foreach ($n in @($p.networkInterfaces)) {
                if ($null -eq $n) { continue }
                $nic = $net.Nic[([string]$n.id).ToLowerInvariant()]
                if ($null -ne $nic) { foreach ($c in $nic.Configs) { if ($c.PrivateIp) { $ips.Add($c.PrivateIp) } } }
            }
        }
        $row['PrivateIPs'] = Join-A2C $ips ', '
        $row['Fqdns'] = Join-A2C $fqdns ', '
        $row['Id'] = [string]$r.id
        # everything needed to create it again: the subnet by ID, every target, which name resolves to which address
        $row['SubnetId'] = $sid
        $row['TargetResourceIds'] = Join-A2C (Get-A2CUnique $targets)
        $row['DnsRecords'] = Join-A2C @($p.customDnsConfigs | Where-Object { $null -ne $_ -and $_.fqdn } | ForEach-Object { [string]$_.fqdn + ':' + (Join-A2C $_.ipAddresses ', ') })
        $row['ManualApproval'] = (@($p.manualPrivateLinkServiceConnections | Where-Object { $null -ne $_ }).Count -gt 0)
        $row['NetworkInterfaces'] = Join-A2C @($p.networkInterfaces | ForEach-Object { if ($null -ne $_) { [string]$_.id } })
        $rows.Add($row)
    }
    Add-A2CRows 'privateEndpoints.csv' $rows
}

Register-A2CSchema 'privateDnsZones.csv' ('SubscriptionID:guid SubscriptionName:sub privateDNSzoneName:fqdn privateDNSzoneRG:rg NumberOfRecordSets:num ' +
    'NumberOfVNETLinks:num VNETlinks:list VNETsLinksIDs:idList linked_VNET_IDs:idList LinkedVNetNames:list RegistrationEnabledLinks:list Id:id')

function New-A2CReportPrivateDNS {
    $net = Initialize-A2CNetIndex
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.network/privatednszones')) {
        $p = Get-A2CProps $r
        $links = $net.LinksByZone[([string]$r.id).ToLowerInvariant()]
        if ($null -eq $links) { $links = [System.Collections.Generic.List[object]]::new() }
        $rows.Add([ordered]@{
                SubscriptionID = [string]$r.subscriptionId; SubscriptionName = Get-A2CSubName ([string]$r.subscriptionId)
                privateDNSzoneName = [string]$r.name; privateDNSzoneRG = Get-A2CRgFromId ([string]$r.id)
                NumberOfRecordSets = $p.numberOfRecordSets; NumberOfVNETLinks = $links.Count
                VNETlinks = Join-A2C @($links | ForEach-Object { $_.Name }); VNETsLinksIDs = Join-A2C @($links | ForEach-Object { $_.Id })
                linked_VNET_IDs = Join-A2C @($links | ForEach-Object { $_.VnetId }); LinkedVNetNames = Join-A2C @($links | ForEach-Object { Get-A2CNameFromId $_.VnetId })
                RegistrationEnabledLinks = Join-A2C @($links | Where-Object { $_.Registration } | ForEach-Object { $_.Name }); Id = [string]$r.id
            })
    }
    Add-A2CRows 'privateDnsZones.csv' $rows
    # one row per virtual network link (the lists above pair only by position)
    $linkRows = [System.Collections.Generic.List[object]]::new()
    foreach ($l in (Get-A2CSortedResources 'microsoft.network/privatednszones/virtualnetworklinks')) {
        $lp = Get-A2CProps $l
        $vnet = [string]$lp.virtualNetwork.id
        $linkRows.Add([ordered]@{ SubscriptionName = Get-A2CSubName ([string]$l.subscriptionId); ResourceGroup = Get-A2CRgFromId ([string]$l.id)
                Zone = Get-A2CIdSegment -Id ([string]$l.id) -After 'privateDnsZones'; Link = Get-A2CNameFromId ([string]$l.id); VNet = Get-A2CNameFromId $vnet; VNetId = $vnet
                VNetSubscriptionId = Get-A2CSubIdFromId $vnet; VNetInScope = ($null -ne (Get-A2CResource $vnet)); RegistrationEnabled = $lp.registrationEnabled
                State = [string]$lp.virtualNetworkLinkState; ResolutionPolicy = [string]$lp.resolutionPolicy; Id = [string]$l.id })
    }
    Add-A2CRows 'privateDnsLinks.csv' $linkRows
}
Register-A2CSchema 'privateDnsLinks.csv' 'SubscriptionName:sub ResourceGroup:rg Zone:fqdn Link:name VNet:name VNetId:id VNetSubscriptionId:guid VNetInScope RegistrationEnabled State ResolutionPolicy Id:id'

# ---- Compute --------------------------------------------------------------------------------------------
Register-A2CSchema 'vms.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Zones Size vCPUs:num MemoryGB:num ' +
    'OsType OsName OsVersion ImagePublisher ImageOffer ImageSku ImageVersion ImageId:id PowerState ProvisioningState LicenseType HybridBenefit ' +
    'Priority SecurityType ComputerName:name OsDiskName:name OsDiskType OsDiskSizeGB:num DataDisks:num DataDisksTotalGB:num UnmanagedDisks ' +
    'AvailabilitySet:name ScaleSet:name ProximityPlacementGroup:name BootDiagnostics Extensions LegacyMonitoringAgent AzureMonitorAgent ' +
    'BackupProtected BackupVault:name BackupPolicy:name LastBackup:date NICs:list PrivateIPs:pairs PublicIPs:pairs VNets:pairs Subnets:pairs ' +
    'IdentityType Tags:tags CreatedTime:date Id:id OsDiskCaching DataDiskLayout:text AvailabilitySetId:id ScaleSetId:id ProximityPlacementGroupId:id ' +
    'DiskEncryptionSetId:id HostId:id CapacityReservationGroupId:id NicIds:list PlanName PlanPublisher PlanProduct AdminUsername:name PatchMode ' +
    'PasswordAuthenticationDisabled SecureBoot VTpm EncryptionAtHost')

function Get-A2CVmExtensions {
    # VM ID (lower) -> list of extension property objects
    if ($null -ne $script:A2C.Data['VmExt']) { return $script:A2C.Data['VmExt'] }
    $m = @{}
    foreach ($e in (Get-A2CResourcesOfType 'microsoft.compute/virtualmachines/extensions')) {
        $vm = (Get-A2CParentId ([string]$e.id)).ToLowerInvariant()
        if (-not $m.ContainsKey($vm)) { $m[$vm] = [System.Collections.Generic.List[object]]::new() }
        $ep = Get-A2CProps $e
        $m[$vm].Add([pscustomobject]@{ Name = [string]$e.name; Publisher = [string]$ep.publisher; Type = [string]$ep.type; Version = [string]$ep.typeHandlerVersion })
    }
    $script:A2C.Data['VmExt'] = $m
    return $m
}

function New-A2CReportVMs {
    $net = Initialize-A2CNetIndex
    $sizes = $script:A2C.Data['VmSizes']; if ($null -eq $sizes) { $sizes = @{} }
    $backup = $script:A2C.Data['BackupBySource']
    $times = $script:A2C.Data['ResourceTimes']; if ($null -eq $times) { $times = @{} }
    $ext = Get-A2CVmExtensions
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.compute/virtualmachines')) {
        $p = Get-A2CProps $r
        $lid = ([string]$r.id).ToLowerInvariant()
        $row = New-A2CBaseRow $r
        $row['Zones'] = Join-A2C $r.zones ', '
        $size = [string]$p.hardwareProfile.vmSize
        $row['Size'] = $size
        $cap = $sizes[$size.ToLowerInvariant()]
        if ($null -ne $cap) { $row['vCPUs'] = $cap.vCPUs; $row['MemoryGB'] = $cap.MemoryGB }
        $sp = $p.storageProfile
        $iv = $p.extended.instanceView
        $row['OsType'] = [string]$sp.osDisk.osType
        $row['OsName'] = [string]$iv.osName
        $row['OsVersion'] = [string]$iv.osVersion
        $img = $sp.imageReference
        $row['ImagePublisher'] = [string]$img.publisher; $row['ImageOffer'] = [string]$img.offer; $row['ImageSku'] = [string]$img.sku
        $row['ImageVersion'] = [string](Get-A2CFirst $img @('exactVersion', 'version')); $row['ImageId'] = [string]$img.id
        $ps = [string]$iv.powerState.code
        $row['PowerState'] = ($ps -replace '^PowerState/', '')
        $row['ProvisioningState'] = [string]$r.provisioningState
        $row['LicenseType'] = [string]$p.licenseType
        $row['HybridBenefit'] = (@('Windows_Server', 'Windows_Client', 'RHEL_BYOS', 'SLES_BYOS') -contains [string]$p.licenseType)
        $row['Priority'] = [string]$p.priority
        $row['SecurityType'] = [string]$p.securityProfile.securityType
        $row['ComputerName'] = [string](Get-A2CFirst $p @('osProfile.computerName', 'extended.instanceView.computerName'))
        $os = $sp.osDisk
        $row['OsDiskName'] = [string]$os.name
        $unmanaged = [bool]($os.vhd.uri)
        $osDiskRes = $null
        if ($os.managedDisk.id) { $osDiskRes = Get-A2CResource ([string]$os.managedDisk.id) }
        if ($null -ne $osDiskRes) { $row['OsDiskType'] = [string]$osDiskRes.sku.name; $row['OsDiskSizeGB'] = (Get-A2CProps $osDiskRes).diskSizeGB }
        else { $row['OsDiskType'] = $(if ($unmanaged) { 'Unmanaged (VHD)' } else { [string]$os.managedDisk.storageAccountType }); $row['OsDiskSizeGB'] = $os.diskSizeGB }
        $dd = @($sp.dataDisks | Where-Object { $null -ne $_ })
        $total = 0
        foreach ($d in $dd) {
            if ($d.vhd.uri) { $unmanaged = $true }
            $gb = $d.diskSizeGB
            if (-not $gb -and $d.managedDisk.id) { $dr = Get-A2CResource ([string]$d.managedDisk.id); if ($null -ne $dr) { $gb = (Get-A2CProps $dr).diskSizeGB } }
            if ($gb) { $total += [int]$gb }
        }
        $row['DataDisks'] = $dd.Count
        $row['DataDisksTotalGB'] = $total
        $row['UnmanagedDisks'] = $unmanaged
        $row['AvailabilitySet'] = Get-A2CNameFromId ([string]$p.availabilitySet.id)
        $row['ScaleSet'] = Get-A2CNameFromId ([string]$p.virtualMachineScaleSet.id)
        $row['ProximityPlacementGroup'] = Get-A2CNameFromId ([string]$p.proximityPlacementGroup.id)
        $row['BootDiagnostics'] = ConvertTo-A2CYesNo $p.diagnosticsProfile.bootDiagnostics.enabled 'False'
        $exts = $ext[$lid]
        if ($null -ne $exts) {
            $row['Extensions'] = Join-A2C @($exts | ForEach-Object { $_.Type }) ', '
            $row['LegacyMonitoringAgent'] = (@($exts | Where-Object { @('MicrosoftMonitoringAgent', 'OmsAgentForLinux') -contains $_.Type }).Count -gt 0)
            $row['AzureMonitorAgent'] = (@($exts | Where-Object { @('AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent') -contains $_.Type }).Count -gt 0)
        }
        else { $row['LegacyMonitoringAgent'] = $false; $row['AzureMonitorAgent'] = $false }
        if ($null -ne $backup) {
            $b = $backup[$lid]
            $row['BackupProtected'] = ($null -ne $b)
            if ($null -ne $b) { $row['BackupVault'] = $b.Vault; $row['BackupPolicy'] = $b.Policy; $row['LastBackup'] = Format-A2CDate $b.LastBackupTime }
        }
        $nc = Get-A2CNetColumns -Row $r -Net $net
        $row['NICs'] = Join-A2C @(foreach ($n in @($p.networkProfile.networkInterfaces)) { if ($null -ne $n) { Get-A2CNameFromId ([string]$n.id) } })
        $row['PrivateIPs'] = $nc.PrivateIP; $row['PublicIPs'] = $nc.PublicIP; $row['VNets'] = $nc.vnet; $row['Subnets'] = $nc.subnet
        $row['IdentityType'] = $(if ($null -ne $r.identity) { [string]$r.identity.type } else { '' })
        $row['Tags'] = ConvertTo-A2CTagString $r.tags
        $t = $times[$lid]
        $row['CreatedTime'] = Format-A2CDate $(if ($null -ne $t -and $t[0]) { $t[0] } else { $p.timeCreated })
        $row['Id'] = [string]$r.id
        # what is needed to build the VM again: disk layout, the references by ID, the marketplace plan
        $row['OsDiskCaching'] = [string]$os.caching
        $row['DataDiskLayout'] = Join-A2C @($dd | Sort-Object { [int]$_.lun } | ForEach-Object { 'LUN {0}: {1}, {2} GB, caching {3}' -f $_.lun, [string]$_.name, $_.diskSizeGB, $(if ($_.caching) { [string]$_.caching } else { 'None' }) })
        $row['AvailabilitySetId'] = [string]$p.availabilitySet.id; $row['ScaleSetId'] = [string]$p.virtualMachineScaleSet.id
        $row['ProximityPlacementGroupId'] = [string]$p.proximityPlacementGroup.id
        $row['DiskEncryptionSetId'] = [string](Get-A2CFirst $os @('managedDisk.diskEncryptionSet.id'))
        $row['HostId'] = [string]$p.host.id; $row['CapacityReservationGroupId'] = [string]$p.capacityReservation.capacityReservationGroup.id
        $row['NicIds'] = Join-A2C @(foreach ($n in @($p.networkProfile.networkInterfaces)) { if ($null -ne $n) { [string]$n.id + $(if ($n.properties.primary) { '(primary)' } else { '' }) } })
        if ($null -ne $r.plan) { $row['PlanName'] = [string]$r.plan.name; $row['PlanPublisher'] = [string]$r.plan.publisher; $row['PlanProduct'] = [string]$r.plan.product }
        $row['AdminUsername'] = [string]$p.osProfile.adminUsername
        $row['PatchMode'] = [string](Get-A2CFirst $p @('osProfile.windowsConfiguration.patchSettings.patchMode', 'osProfile.linuxConfiguration.patchSettings.patchMode'))
        $row['PasswordAuthenticationDisabled'] = $p.osProfile.linuxConfiguration.disablePasswordAuthentication
        $row['SecureBoot'] = $p.securityProfile.uefiSettings.secureBootEnabled; $row['VTpm'] = $p.securityProfile.uefiSettings.vTpmEnabled
        $row['EncryptionAtHost'] = $p.securityProfile.encryptionAtHost
        $rows.Add($row)
    }
    Add-A2CRows 'vms.csv' $rows
}

Register-A2CSchema 'disks.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Zones Sku Tier SizeGB:num DiskState ' +
    'OsType AttachedTo:name AttachedToId:id Encryption DiskEncryptionSet:name NetworkAccessPolicy PublicNetworkAccess TimeCreated:date ' +
    'Unattached Tags:tags Id:id')

function New-A2CReportDisks {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.compute/disks')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $row['Zones'] = Join-A2C $r.zones ', '
        $row['Sku'] = [string]$r.sku.name; $row['Tier'] = [string](Get-A2CFirst $p @('tier')) ; if (-not $row['Tier']) { $row['Tier'] = [string]$r.sku.tier }
        $row['SizeGB'] = $p.diskSizeGB
        $row['DiskState'] = [string]$p.diskState
        $row['OsType'] = [string]$p.osType
        $row['AttachedTo'] = Get-A2CNameFromId ([string]$r.managedBy)
        $row['AttachedToId'] = [string]$r.managedBy
        $row['Encryption'] = [string]$p.encryption.type
        $row['DiskEncryptionSet'] = Get-A2CNameFromId ([string]$p.encryption.diskEncryptionSetId)
        $row['NetworkAccessPolicy'] = [string]$p.networkAccessPolicy
        $row['PublicNetworkAccess'] = [string]$p.publicNetworkAccess
        $row['TimeCreated'] = Format-A2CDate $p.timeCreated
        $row['Unattached'] = (-not $r.managedBy -and [string]$p.diskState -ne 'ActiveSAS')
        $row['Tags'] = ConvertTo-A2CTagString $r.tags
        $row['Id'] = [string]$r.id
        $rows.Add($row)
    }
    Add-A2CRows 'disks.csv' $rows
}

Register-A2CSchema 'aks.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location KubernetesVersion Tier NodePools:num ' +
    'Nodes:num NodeSizes PoolDetails NetworkPlugin NetworkPolicy PrivateCluster EntraIntegration AzureRBAC LocalAccountsDisabled IdentityType ' +
    'PowerState Tags:tags Id:id')

function New-A2CReportAKS {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.containerservice/managedclusters')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $pools = @($p.agentPoolProfiles | Where-Object { $null -ne $_ })
        $nodes = 0
        foreach ($x in $pools) { if ($x.count) { $nodes += [int]$x.count } }
        $row['KubernetesVersion'] = [string](Get-A2CFirst $p @('currentKubernetesVersion', 'kubernetesVersion'))
        $row['Tier'] = [string]$r.sku.tier
        $row['NodePools'] = $pools.Count
        $row['Nodes'] = $nodes
        $row['NodeSizes'] = Join-A2C (Get-A2CUnique @($pools | ForEach-Object { $_.vmSize })) ', '
        $row['PoolDetails'] = Join-A2C @($pools | ForEach-Object { '{0}:{1}x{2}({3},{4})' -f $_.name, $_.count, $_.vmSize, $_.osType, $_.mode })
        $row['NetworkPlugin'] = [string]$p.networkProfile.networkPlugin
        $row['NetworkPolicy'] = [string]$p.networkProfile.networkPolicy
        $row['PrivateCluster'] = ConvertTo-A2CYesNo $p.apiServerAccessProfile.enablePrivateCluster 'False'
        $row['EntraIntegration'] = ($null -ne $p.aadProfile)
        $row['AzureRBAC'] = ConvertTo-A2CYesNo $p.aadProfile.enableAzureRBAC 'False'
        $row['LocalAccountsDisabled'] = ConvertTo-A2CYesNo $p.disableLocalAccounts 'False'
        $row['IdentityType'] = $(if ($null -ne $r.identity) { [string]$r.identity.type } else { '' })
        $row['PowerState'] = [string]$p.powerState.code
        $row['Tags'] = ConvertTo-A2CTagString $r.tags
        $row['Id'] = [string]$r.id
        $rows.Add($row)
    }
    Add-A2CRows 'aks.csv' $rows
}

Register-A2CSchema 'appServicePlans.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Kind Sku Tier Workers:num ' +
    'OS Apps:num ZoneRedundant Tags:tags Id:id')
Register-A2CSchema 'appServiceApps.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Kind State Plan:name ' +
    'DefaultHostName:fqdn Runtime HttpsOnly MinTlsVersion FtpsState AlwaysOn PublicNetworkAccess VNetIntegration:name IdentityType ' +
    'ClientCertEnabled Tags:tags Id:id PlanId:id VNetIntegrationSubnetId:id HostNames:list UserAssignedIdentityIds:idList KeyVaultReferenceIdentity:id ' +
    'VnetRouteAll StartupCommand:text HealthCheckPath Http20 Workers:num Use32BitWorker WebSockets AccessRestrictions:text ScmAccessRestrictions:num ' +
    'ScmUsesMainRestrictions')

function Get-A2CAppRuntime {
    param($Config)
    if ($null -eq $Config) { return '' }
    foreach ($k in @('linuxFxVersion', 'windowsFxVersion')) { $v = [string]$Config.$k; if ($v -and $v -ne ' ') { return $v } }
    $l = [System.Collections.Generic.List[string]]::new()
    foreach ($k in @('netFrameworkVersion', 'phpVersion', 'pythonVersion', 'nodeVersion', 'javaVersion', 'powerShellVersion')) {
        $v = [string]$Config.$k
        if ($v -and $v -ne ' ') { $l.Add(($k -replace 'Version$', '') + ' ' + $v) }
    }
    return (Join-A2C $l ', ')
}

function New-A2CReportAppService {
    $cfg = $script:A2C.Data['AppConfigBySite']; if ($null -eq $cfg) { $cfg = @{} }
    $plans = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.web/serverfarms')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $row['Kind'] = [string]$r.kind; $row['Sku'] = [string]$r.sku.name; $row['Tier'] = [string]$r.sku.tier
        $row['Workers'] = $(if ($null -ne $r.sku.capacity) { $r.sku.capacity } else { $p.currentNumberOfWorkers })
        $row['OS'] = $(if ($p.reserved) { 'Linux' } else { 'Windows' })
        $row['Apps'] = $p.numberOfSites
        $row['ZoneRedundant'] = ConvertTo-A2CYesNo $p.zoneRedundant 'False'
        $row['Tags'] = ConvertTo-A2CTagString $r.tags; $row['Id'] = [string]$r.id
        $plans.Add($row)
    }
    $apps = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources @('microsoft.web/sites', 'microsoft.web/sites/slots'))) {
        $p = Get-A2CProps $r
        $c = $cfg[([string]$r.id).ToLowerInvariant()]
        $row = New-A2CBaseRow $r
        $row['Kind'] = [string]$r.kind; $row['State'] = [string]$p.state; $row['Plan'] = Get-A2CNameFromId ([string]$p.serverFarmId)
        $row['DefaultHostName'] = [string]$p.defaultHostName; $row['Runtime'] = Get-A2CAppRuntime $c
        $row['HttpsOnly'] = ConvertTo-A2CYesNo $p.httpsOnly 'False'
        if ($null -ne $c) { $row['MinTlsVersion'] = [string]$c.minTlsVersion; $row['FtpsState'] = [string]$c.ftpsState; $row['AlwaysOn'] = ConvertTo-A2CYesNo $c.alwaysOn }
        $row['PublicNetworkAccess'] = [string]$p.publicNetworkAccess
        $row['VNetIntegration'] = Get-A2CNameFromId ([string]$p.virtualNetworkSubnetId)
        $row['IdentityType'] = $(if ($null -ne $r.identity) { [string]$r.identity.type } else { '' })
        $row['ClientCertEnabled'] = ConvertTo-A2CYesNo $p.clientCertEnabled
        $row['Tags'] = ConvertTo-A2CTagString $r.tags; $row['Id'] = [string]$r.id
        # references by ID, host names with their certificates, and what the site configuration adds
        $row['PlanId'] = [string]$p.serverFarmId; $row['VNetIntegrationSubnetId'] = [string]$p.virtualNetworkSubnetId
        $row['HostNames'] = Join-A2C @($p.hostNameSslStates | Where-Object { $null -ne $_ -and [string]$_.hostType -ne 'Repository' } | ForEach-Object { [string]$_.name + $(if ([string]$_.sslState -and [string]$_.sslState -ne 'Disabled') { '(' + [string]$_.sslState + ')' } else { '' }) })
        $row['UserAssignedIdentityIds'] = $(if ($null -ne $r.identity -and $null -ne $r.identity.userAssignedIdentities) { Join-A2C @($r.identity.userAssignedIdentities.PSObject.Properties | ForEach-Object { $_.Name }) } else { '' })
        $row['KeyVaultReferenceIdentity'] = [string]$p.keyVaultReferenceIdentity
        $row['VnetRouteAll'] = $p.vnetRouteAllEnabled
        if ($null -ne $c) {
            $row['StartupCommand'] = [string]$c.appCommandLine; $row['HealthCheckPath'] = [string]$c.healthCheckPath; $row['Http20'] = $c.http20Enabled
            $row['Workers'] = $c.numberOfWorkers; $row['Use32BitWorker'] = $c.use32BitWorkerProcess; $row['WebSockets'] = $c.webSocketsEnabled
            $row['AccessRestrictions'] = Join-A2C @($c.ipSecurityRestrictions | Where-Object { $null -ne $_ } | ForEach-Object {
                    $what = [string]$_.ipAddress
                    if (-not $what) { $what = [string]$_.vnetSubnetResourceId }
                    ('{0} {1} {2} ({3})' -f $_.priority, [string]$_.action, $what, [string]$_.name) })
            $row['ScmAccessRestrictions'] = @($c.scmIpSecurityRestrictions | Where-Object { $null -ne $_ }).Count
            $row['ScmUsesMainRestrictions'] = $c.scmIpSecurityRestrictionsUseMain
        }
        $apps.Add($row)
    }
    Add-A2CRows 'appServicePlans.csv' $plans
    Add-A2CRows 'appServiceApps.csv' $apps
}

# ---- Data -----------------------------------------------------------------------------------------------
Register-A2CSchema 'storageAccounts.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Kind Sku AccessTier ' +
    'HierarchicalNamespace HttpsOnly MinimumTlsVersion AllowBlobPublicAccess AllowSharedKeyAccess PublicNetworkAccess NetworkDefaultAction ' +
    'PrivateEndpoints:num EncryptionKeySource InfrastructureEncryption LargeFileShares PrimaryLocation SecondaryLocation StatusOfPrimary ' +
    'CreationTime:date Tags:tags Id:id')

function New-A2CReportStorage {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.storage/storageaccounts')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $row['Kind'] = [string]$r.kind; $row['Sku'] = [string]$r.sku.name; $row['AccessTier'] = [string]$p.accessTier
        $row['HierarchicalNamespace'] = ConvertTo-A2CYesNo $p.isHnsEnabled 'False'
        $row['HttpsOnly'] = ConvertTo-A2CYesNo $p.supportsHttpsTrafficOnly
        $row['MinimumTlsVersion'] = $(if ($p.minimumTlsVersion) { [string]$p.minimumTlsVersion } else { 'Not set (TLS1_0)' })
        $row['AllowBlobPublicAccess'] = ConvertTo-A2CYesNo $p.allowBlobPublicAccess 'Not set (allowed)'
        $row['AllowSharedKeyAccess'] = ConvertTo-A2CYesNo $p.allowSharedKeyAccess 'Not set (allowed)'
        $row['PublicNetworkAccess'] = $(if ($p.publicNetworkAccess) { [string]$p.publicNetworkAccess } else { 'Not set (Enabled)' })
        $row['NetworkDefaultAction'] = [string]$p.networkAcls.defaultAction
        $row['PrivateEndpoints'] = Get-A2CPeCount $p
        $row['EncryptionKeySource'] = [string]$p.encryption.keySource
        $row['InfrastructureEncryption'] = ConvertTo-A2CYesNo $p.encryption.requireInfrastructureEncryption 'False'
        $row['LargeFileShares'] = [string]$p.largeFileSharesState
        $row['PrimaryLocation'] = [string]$p.primaryLocation; $row['SecondaryLocation'] = [string]$p.secondaryLocation
        $row['StatusOfPrimary'] = [string]$p.statusOfPrimary; $row['CreationTime'] = Format-A2CDate $p.creationTime
        $row['Tags'] = ConvertTo-A2CTagString $r.tags; $row['Id'] = [string]$r.id
        $rows.Add($row)
    }
    Add-A2CRows 'storageAccounts.csv' $rows
}

Register-A2CSchema 'sqlServers.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Version Fqdn:fqdn State ' +
    'PublicNetworkAccess MinimalTlsVersion EntraAdmin:dn EntraOnlyAuth IdentityType Databases:num ElasticPools:num PrivateEndpoints:num Tags:tags Id:id')
Register-A2CSchema 'sqlDatabases.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Server:name Name:name Location Sku Tier ' +
    'Capacity:num Family MaxSizeGB:num ElasticPool:name ZoneRedundant LicenseType BackupStorageRedundancy AutoPauseDelay Status ' +
    'CreationDate:date Tags:tags Id:id')
Register-A2CSchema 'sqlManagedInstances.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Sku Tier VCores:num ' +
    'StorageSizeGB:num LicenseType Subnet:name ZoneRedundant PublicDataEndpoint MinimalTlsVersion ProxyOverride Tags:tags Id:id')
Register-A2CSchema 'sqlVirtualMachines.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name VirtualMachine:name SqlVersion ' +
    'SqlEdition SqlImageOffer SqlImageSku LicenseType Management SupportStatus Tags:tags Id:id')

# SQL Server end of extended support (Microsoft lifecycle)
$script:A2CSqlLifecycle = [ordered]@{
    '2008' = '2019-07-09'; '2012' = '2022-07-12'; '2014' = '2024-07-09'; '2016' = '2026-07-14'; '2017' = '2027-10-12'; '2019' = '2030-01-08'; '2022' = '2033-01-11'
}

function Get-A2CSqlSupport {
    param([string] $Offer)
    if ($Offer -notmatch '(?i)SQL(\d{4})') { return @('', '') }
    $ver = $Matches[1]
    $end = $script:A2CSqlLifecycle[$ver]
    if (-not $end) { return @(('SQL Server ' + $ver), '') }
    $days = Get-A2CDaysUntil $end
    $status = $(if ($days -lt 0) { 'Out of extended support since ' + $end } elseif ($days -le 365) { 'Extended support ends ' + $end } else { 'Supported until ' + $end })
    return @(('SQL Server ' + $ver), $status)
}

function New-A2CReportSQL {
    $servers = [System.Collections.Generic.List[object]]::new()
    $dbs = [System.Collections.Generic.List[object]]::new()
    $dbCount = @{}; $poolCount = @{}
    foreach ($d in (Get-A2CResourcesOfType 'microsoft.sql/servers/databases')) { $k = (Get-A2CParentId ([string]$d.id)).ToLowerInvariant(); if ([string]$d.name -ne 'master') { $dbCount[$k] = [int]$dbCount[$k] + 1 } }
    foreach ($d in (Get-A2CResourcesOfType 'microsoft.sql/servers/elasticpools')) { $k = (Get-A2CParentId ([string]$d.id)).ToLowerInvariant(); $poolCount[$k] = [int]$poolCount[$k] + 1 }
    foreach ($r in (Get-A2CSortedResources 'microsoft.sql/servers')) {
        $p = Get-A2CProps $r
        $k = ([string]$r.id).ToLowerInvariant()
        $row = New-A2CBaseRow $r
        $row['Version'] = [string]$p.version; $row['Fqdn'] = [string]$p.fullyQualifiedDomainName; $row['State'] = [string]$p.state
        $row['PublicNetworkAccess'] = [string]$p.publicNetworkAccess; $row['MinimalTlsVersion'] = [string]$p.minimalTlsVersion
        $row['EntraAdmin'] = [string]$p.administrators.login; $row['EntraOnlyAuth'] = ConvertTo-A2CYesNo $p.administrators.azureADOnlyAuthentication
        $row['IdentityType'] = $(if ($null -ne $r.identity) { [string]$r.identity.type } else { '' })
        $row['Databases'] = [int]$dbCount[$k]; $row['ElasticPools'] = [int]$poolCount[$k]; $row['PrivateEndpoints'] = Get-A2CPeCount $p
        $row['Tags'] = ConvertTo-A2CTagString $r.tags; $row['Id'] = [string]$r.id
        $servers.Add($row)
    }
    foreach ($r in (Get-A2CSortedResources 'microsoft.sql/servers/databases')) {
        if ([string]$r.name -eq 'master') { continue }
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r -NoLocation
        $row.Remove('Name')
        $row['Server'] = Get-A2CIdSegment -Id ([string]$r.id) -After 'servers'
        $row['Name'] = [string]$r.name; $row['Location'] = [string]$r.location
        $row['Sku'] = [string]$r.sku.name; $row['Tier'] = [string]$r.sku.tier; $row['Capacity'] = $r.sku.capacity; $row['Family'] = [string]$r.sku.family
        if ($p.maxSizeBytes) { $row['MaxSizeGB'] = [math]::Round([double]$p.maxSizeBytes / 1GB, 1) }
        $row['ElasticPool'] = Get-A2CNameFromId ([string]$p.elasticPoolId); $row['ZoneRedundant'] = ConvertTo-A2CYesNo $p.zoneRedundant
        $row['LicenseType'] = [string]$p.licenseType; $row['BackupStorageRedundancy'] = [string]$p.currentBackupStorageRedundancy
        $row['AutoPauseDelay'] = [string]$p.autoPauseDelay; $row['Status'] = [string]$p.status; $row['CreationDate'] = Format-A2CDate $p.creationDate
        $row['Tags'] = ConvertTo-A2CTagString $r.tags; $row['Id'] = [string]$r.id
        $dbs.Add($row)
    }
    $mis = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.sql/managedinstances')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $row['Sku'] = [string]$r.sku.name; $row['Tier'] = [string]$r.sku.tier; $row['VCores'] = $p.vCores; $row['StorageSizeGB'] = $p.storageSizeInGB
        $row['LicenseType'] = [string]$p.licenseType; $row['Subnet'] = Get-A2CNameFromId ([string]$p.subnetId); $row['ZoneRedundant'] = ConvertTo-A2CYesNo $p.zoneRedundant
        $row['PublicDataEndpoint'] = ConvertTo-A2CYesNo $p.publicDataEndpointEnabled; $row['MinimalTlsVersion'] = [string]$p.minimalTlsVersion
        $row['ProxyOverride'] = [string]$p.proxyOverride; $row['Tags'] = ConvertTo-A2CTagString $r.tags; $row['Id'] = [string]$r.id
        $mis.Add($row)
    }
    $sqlvms = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.sqlvirtualmachine/sqlvirtualmachines')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r -NoLocation
        $sup = Get-A2CSqlSupport ([string]$p.sqlImageOffer)
        $row['VirtualMachine'] = Get-A2CNameFromId ([string]$p.virtualMachineResourceId)
        $row['SqlVersion'] = $sup[0]; $row['SqlEdition'] = [string]$p.sqlImageSku; $row['SqlImageOffer'] = [string]$p.sqlImageOffer
        $row['SqlImageSku'] = [string]$p.sqlImageSku; $row['LicenseType'] = [string]$p.sqlServerLicenseType; $row['Management'] = [string]$p.sqlManagement
        $row['SupportStatus'] = $sup[1]; $row['Tags'] = ConvertTo-A2CTagString $r.tags; $row['Id'] = [string]$r.id
        $sqlvms.Add($row)
    }
    Add-A2CRows 'sqlServers.csv' $servers
    Add-A2CRows 'sqlDatabases.csv' $dbs
    Add-A2CRows 'sqlManagedInstances.csv' $mis
    Add-A2CRows 'sqlVirtualMachines.csv' $sqlvms
}

Register-A2CSchema 'keyVaults.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Sku TenantId:guid PermissionModel ' +
    'AccessPolicies:num SoftDelete SoftDeleteRetentionDays:num PurgeProtection PublicNetworkAccess NetworkDefaultAction PrivateEndpoints:num ' +
    'EnabledForDeployment EnabledForDiskEncryption EnabledForTemplateDeployment VaultUri:url Tags:tags Id:id')

function New-A2CReportKeyVault {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.keyvault/vaults')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $row['Sku'] = [string]$p.sku.name; $row['TenantId'] = [string]$p.tenantId
        $row['PermissionModel'] = $(if ($p.enableRbacAuthorization) { 'Azure RBAC' } else { 'Access policies' })
        $row['AccessPolicies'] = (Get-A2CCount @($p.accessPolicies | Where-Object { $null -ne $_ }))
        $row['SoftDelete'] = ConvertTo-A2CYesNo $p.enableSoftDelete 'True (default)'
        $row['SoftDeleteRetentionDays'] = $p.softDeleteRetentionInDays
        $row['PurgeProtection'] = ConvertTo-A2CYesNo $p.enablePurgeProtection 'False'
        $row['PublicNetworkAccess'] = $(if ($p.publicNetworkAccess) { [string]$p.publicNetworkAccess } else { 'Enabled' })
        $row['NetworkDefaultAction'] = [string]$p.networkAcls.defaultAction
        $row['PrivateEndpoints'] = Get-A2CPeCount $p
        $row['EnabledForDeployment'] = ConvertTo-A2CYesNo $p.enabledForDeployment 'False'
        $row['EnabledForDiskEncryption'] = ConvertTo-A2CYesNo $p.enabledForDiskEncryption 'False'
        $row['EnabledForTemplateDeployment'] = ConvertTo-A2CYesNo $p.enabledForTemplateDeployment 'False'
        $row['VaultUri'] = [string]$p.vaultUri
        $row['Tags'] = ConvertTo-A2CTagString $r.tags; $row['Id'] = [string]$r.id
        $rows.Add($row)
    }
    Add-A2CRows 'keyVaults.csv' $rows
}

# ---- Operations: backup and automation ------------------------------------------------------------------
Register-A2CSchema 'backupItems.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Vault:name VaultType ItemName:name WorkloadType ' +
    'BackupManagementType SourceResource:name SourceResourceId:id ProtectionState ProtectionStatus HealthStatus LastBackupStatus ' +
    'LastBackupTime:date Policy:name Id:id')

function New-A2CReportBackup {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($b in @($script:A2C.Data['BackupItems'] | Sort-Object SubscriptionId, Vault, ItemName)) {
        if ($null -eq $b) { continue }
        $rows.Add([ordered]@{
                SubscriptionName = Get-A2CSubName $b.SubscriptionId; SubscriptionId = $b.SubscriptionId; ResourceGroup = Get-A2CRgFromId $b.Id
                Vault = $b.Vault; VaultType = $b.VaultType; ItemName = $b.ItemName; WorkloadType = $b.WorkloadType; BackupManagementType = $b.BackupManagementType
                SourceResource = Get-A2CNameFromId $b.SourceResourceId; SourceResourceId = $b.SourceResourceId; ProtectionState = $b.ProtectionState
                ProtectionStatus = $b.ProtectionStatus; HealthStatus = $b.HealthStatus; LastBackupStatus = $b.LastBackupStatus
                LastBackupTime = Format-A2CDate $b.LastBackupTime; Policy = $b.Policy; Id = $b.Id
            })
    }
    Add-A2CRows 'backupItems.csv' $rows
}

Register-A2CSchema 'automationAccounts.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Location Sku State ' +
    'PublicNetworkAccess IdentityType Runbooks:num Tags:tags Id:id')
Register-A2CSchema 'runbooks.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg AutomationAccount:name Runbook:name RunbookType State ' +
    'RuntimeEnvironment LastModified:date Description:text RetiringRuntime UsesAzureRM UsesRunAs ExportedFile Id:id')

function Get-A2CRunbookRetirement {
    param([string] $Type, [string] $Runtime)
    switch -Regex ($Type) {
        '^Python2$'        { return 'Python 2.7 - retires 2026-09-30' }
        '^PowerShell72$'   { return 'PowerShell 7.2 - retires 2026-09-30' }
        '^Python3$'        { if (-not $Runtime) { return 'Check: Python 3.8 retires 2026-09-30' } }
    }
    if ($Runtime -match '(?i)python-?3\.8|powershell-?7\.[12]') { return ($Runtime + ' - retires 2026-09-30') }
    return ''
}

function New-A2CReportAutomation {
    $rbCount = @{}
    foreach ($rb in (Get-A2CResourcesOfType 'microsoft.automation/automationaccounts/runbooks')) { $k = (Get-A2CParentId ([string]$rb.id)).ToLowerInvariant(); $rbCount[$k] = [int]$rbCount[$k] + 1 }
    $accounts = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.automation/automationaccounts')) {
        $p = Get-A2CProps $r
        $row = New-A2CBaseRow $r
        $row['Sku'] = [string]$p.sku.name; $row['State'] = [string]$p.state; $row['PublicNetworkAccess'] = ConvertTo-A2CYesNo $p.publicNetworkAccess
        $row['IdentityType'] = $(if ($null -ne $r.identity) { [string]$r.identity.type } else { '' })
        $row['Runbooks'] = [int]$rbCount[([string]$r.id).ToLowerInvariant()]
        $row['Tags'] = ConvertTo-A2CTagString $r.tags; $row['Id'] = [string]$r.id
        $accounts.Add($row)
    }
    $content = $script:A2C.Data['RunbookContent']
    $rbs = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-A2CSortedResources 'microsoft.automation/automationaccounts/runbooks')) {
        $p = Get-A2CProps $r
        $type = [string]$p.runbookType
        $rt = [string](Get-A2CFirst $p @('runtimeEnvironment', 'runtime'))
        $row = [ordered]@{
            SubscriptionName = Get-A2CSubName ([string]$r.subscriptionId); SubscriptionId = [string]$r.subscriptionId; ResourceGroup = Get-A2CRgFromId ([string]$r.id)
            AutomationAccount = Get-A2CIdSegment -Id ([string]$r.id) -After 'automationAccounts'; Runbook = [string]$r.name; RunbookType = $type
            State = [string]$p.state; RuntimeEnvironment = $rt; LastModified = Format-A2CDate $p.lastModifiedTime; Description = [string]$p.description
            RetiringRuntime = Get-A2CRunbookRetirement -Type $type -Runtime $rt; Id = [string]$r.id
        }
        if ($null -ne $content) {
            $c = $content[([string]$r.id).ToLowerInvariant()]
            if ($null -ne $c) { $row['UsesAzureRM'] = $c.UsesAzureRM; $row['UsesRunAs'] = $c.UsesRunAs; $row['ExportedFile'] = $c.File }
        }
        $rbs.Add($row)
    }
    Add-A2CRows 'automationAccounts.csv' $accounts
    Add-A2CRows 'runbooks.csv' $rbs
}

# ---- Inventory: diagnostic settings and locks -----------------------------------------------------------
Register-A2CSchema 'diagnosticSettings.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg ResourceName:name ResourceType Target ' +
    'SettingName:name Workspace:name WorkspaceId:id StorageAccount:name StorageAccountId:id EventHub:path PartnerSolution:name ' +
    'LogCategories MetricCategories LogAnalyticsDestinationType ResourceId:id ' +
    'LogCategoryGroups EventHubAuthorizationRuleId:id EventHubName:name PartnerSolutionId:id SettingId:id')

function New-A2CReportDiagnosticSettings {
    Add-A2CRows 'diagnosticSettings.csv' $script:A2C.Data['DiagDetails']
}

Register-A2CSchema 'locks.csv' ('SubscriptionName:sub SubscriptionId:guid Scope:id ScopeType ResourceGroup:rg Resource:name ResourceType ' +
    'LockName:name Level Notes:text Owners Id:id')

function New-A2CReportLocks {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($l in @($script:A2C.Data['Locks'] | Sort-Object SubscriptionId, Scope)) {
        if ($null -eq $l) { continue }
        $st = Get-A2CScopeType $l.Scope
        $rows.Add([ordered]@{
                SubscriptionName = Get-A2CSubName $l.SubscriptionId; SubscriptionId = $l.SubscriptionId; Scope = $l.Scope; ScopeType = $st
                ResourceGroup = Get-A2CRgFromId $l.Scope; Resource = $(if ($st -eq 'Resource') { Get-A2CNameFromId $l.Scope } else { '' })
                ResourceType = $(if ($st -eq 'Resource') { Get-A2CTypeCased -Id $l.Scope -Fallback '' } else { '' })
                LockName = $l.Name; Level = $l.Level; Notes = $l.Notes; Owners = $l.Owners; Id = $l.Id
            })
    }
    Add-A2CRows 'locks.csv' $rows
}

# ---- Governance: RBAC -----------------------------------------------------------------------------------
Register-A2CSchema 'RBAC_role_assignments.csv' ('SubscriptionID:guid SubscriptionName:sub RoleAssignmentId:id Scope:id DisplayName:dn ' +
    'SignInName:upn RoleDefinitionName:role RoleDefinitionId:id ObjectId:guid ObjectType CanDelegate ScopeType Inherited PrincipalStatus ' +
    'UserType AppId:guid ServicePrincipalType IsPrivilegedRole Condition:text Description:text CreatedOn:date CreatedBy:guid ' +
    'ConditionVersion DelegatedManagedIdentity:id UpdatedOn:date AssignmentType MemberType EndDateTime:date')
Register-A2CSchema 'RBAC_eligible_assignments.csv' ('SubscriptionID:guid SubscriptionName:sub Scope:id ScopeType Inherited DisplayName:dn SignInName:upn ' +
    'ObjectType RoleDefinitionName:role RoleDefinitionId:id ObjectId:guid IsPrivilegedRole MemberType Status StartDateTime:date EndDateTime:date ' +
    'Condition:text CreatedOn:date Id:id')
Register-A2CSchema 'RBAC_deny_assignments.csv' ('SubscriptionID:guid SubscriptionName:sub Name:known Scope:id ScopeType Description:text ' +
    'Principals:list ExcludePrincipals:list Actions NotActions DataActions NotDataActions DoNotApplyToChildScopes IsSystemProtected CreatedOn:date Id:id')
Register-A2CSchema 'RBAC_roles.csv' ('RoleName:role roleID:guid RoleType IsCustom Descr:text Actions NotActions DataActions NotDataActions ' +
    'AssignableScopes:idList AssignmentCount:num Subscriptions:num HasWildcardActions')

$script:A2CPrivilegedRoles = @('Owner', 'Contributor', 'User Access Administrator', 'Role Based Access Control Administrator')

function Test-A2CPrivilegedRole {
    param($Def)
    if ($null -eq $Def) { return $false }
    if ($script:A2CPrivilegedRoles -contains $Def.RoleName) { return $true }
    foreach ($a in $Def.Actions) { if ($a -eq '*' -or $a -like 'Microsoft.Authorization/*') { return $true } }
    return $false
}

function New-A2CReportRBAC {
    $defs = $script:A2C.Data['RoleDefs']; if ($null -eq $defs) { $defs = @{} }
    $pr = $script:A2C.Data['Principals']; if ($null -eq $pr) { $pr = @{} }
    $resolved = [bool]$script:A2C.Data['PrincipalsResolved']
    $counts = @{}
    $rows = [System.Collections.Generic.List[object]]::new()
    $pim = $script:A2C.Data['PimActive']; if ($null -eq $pim) { $pim = @{} }
    $havePim = Test-A2CDataset 'Pim'
    foreach ($a in @($script:A2C.Data['RoleAssignments'] | Sort-Object SubscriptionId, Scope, RoleGuid)) {
        if ($null -eq $a) { continue }
        $def = $defs[$a.RoleGuid]
        # PIM: an activated or time-bound assignment has an instance with an end; without one it is permanent
        $inst = $pim[$a.Id.ToLowerInvariant()]
        $atype = ''; $mtype = ''; $end = ''
        if ($null -ne $inst) { $atype = [string]$inst.properties.assignmentType; $mtype = [string]$inst.properties.memberType; $end = Format-A2CDate $inst.properties.endDateTime }
        elseif ($havePim) { $atype = 'Assigned' }
        $counts[$a.RoleGuid] = [int]$counts[$a.RoleGuid] + 1
        $p = $pr[$a.PrincipalId]
        $status = $(if ($null -ne $p) { 'Resolved' } elseif ($resolved) { 'NotFound (deleted principal?)' } else { 'Unresolved (no directory access)' })
        $otype = $(if ($null -ne $p) { $p.Type.Substring(0, 1).ToUpperInvariant() + $p.Type.Substring(1) } else { $a.PrincipalType })
        $userType = ''
        if ($null -ne $p -and $p.Type -eq 'user') { $userType = $(if ($p.IsGuest) { 'Guest' } else { 'Member' }) }
        $rows.Add([ordered]@{
                SubscriptionID = $a.SubscriptionId; SubscriptionName = Get-A2CSubName $a.SubscriptionId; RoleAssignmentId = $a.Id; Scope = $a.Scope
                DisplayName = $(if ($null -ne $p) { $p.DisplayName } else { '' }); SignInName = $(if ($null -ne $p) { $p.UPN } else { '' })
                RoleDefinitionName = $(if ($null -ne $def) { $def.RoleName } else { 'Unknown role ' + $a.RoleGuid }); RoleDefinitionId = $a.RoleDefinitionId
                ObjectId = $a.PrincipalId; ObjectType = $otype; CanDelegate = ''
                ScopeType = Get-A2CScopeType $a.Scope
                Inherited = $(if ($a.SubscriptionId) { -not ($a.Scope -like ('/subscriptions/' + $a.SubscriptionId + '*')) } else { '' })
                PrincipalStatus = $status; UserType = $userType; AppId = $(if ($null -ne $p) { $p.AppId } else { '' })
                ServicePrincipalType = $(if ($null -ne $p) { $p.SpType } else { '' }); IsPrivilegedRole = (Test-A2CPrivilegedRole $def)
                Condition = $a.Condition; Description = $a.Description; CreatedOn = Format-A2CDate $a.CreatedOn; CreatedBy = $a.CreatedBy
                ConditionVersion = $a.ConditionVersion; DelegatedManagedIdentity = $a.DelegatedMI; UpdatedOn = Format-A2CDate $a.UpdatedOn
                AssignmentType = $atype; MemberType = $mtype; EndDateTime = $end
            })
    }
    Add-A2CRows 'RBAC_role_assignments.csv' $rows
    # eligible assignments (PIM): not active until the principal activates them, so they are in no other list
    $elig = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @($script:A2C.Data['PimEligible'] | Where-Object { $null -ne $_ } | Sort-Object SubscriptionId)) {
        $x = $e.Item; $xp = $x.properties; $ep = $xp.expandedProperties
        $guid = (Get-A2CNameFromId ([string]$xp.roleDefinitionId)).ToLowerInvariant()
        $def = $defs[$guid]
        $roleName = [string]$ep.roleDefinition.displayName
        if (-not $roleName -and $null -ne $def) { $roleName = $def.RoleName }
        $elig.Add([ordered]@{
                SubscriptionID = $e.SubscriptionId; SubscriptionName = Get-A2CSubName $e.SubscriptionId; Scope = [string]$xp.scope; ScopeType = Get-A2CScopeType ([string]$xp.scope)
                Inherited = -not ([string]$xp.scope -like ('/subscriptions/' + $e.SubscriptionId + '*')); DisplayName = [string]$ep.principal.displayName
                SignInName = [string]$ep.principal.email; ObjectType = [string]$xp.principalType; RoleDefinitionName = $roleName; RoleDefinitionId = [string]$xp.roleDefinitionId
                ObjectId = ([string]$xp.principalId).ToLowerInvariant(); IsPrivilegedRole = (Test-A2CPrivilegedRole $def); MemberType = [string]$xp.memberType; Status = [string]$xp.status
                StartDateTime = Format-A2CDate $xp.startDateTime; EndDateTime = Format-A2CDate $xp.endDateTime; Condition = [string]$xp.condition
                CreatedOn = Format-A2CDate $xp.createdOn; Id = [string]$x.id
            })
    }
    Add-A2CRows 'RBAC_eligible_assignments.csv' $elig
    $deny = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @($script:A2C.Data['DenyAssignments'] | Where-Object { $null -ne $_ } | Sort-Object SubscriptionId)) {
        $x = $d.Item; $xp = $x.properties
        $perm = @($xp.permissions | Where-Object { $null -ne $_ })
        $deny.Add([ordered]@{
                SubscriptionID = $d.SubscriptionId; SubscriptionName = Get-A2CSubName $d.SubscriptionId; Name = [string]$xp.denyAssignmentName; Scope = [string]$xp.scope
                ScopeType = Get-A2CScopeType ([string]$xp.scope); Description = [string]$xp.description
                Principals = Join-A2C @($xp.principals | ForEach-Object { [string]$_.id + $(if ($_.type) { '(' + [string]$_.type + ')' } else { '' }) })
                ExcludePrincipals = Join-A2C @($xp.excludePrincipals | ForEach-Object { [string]$_.id + $(if ($_.type) { '(' + [string]$_.type + ')' } else { '' }) })
                Actions = Join-A2C @($perm | ForEach-Object { $_.actions }); NotActions = Join-A2C @($perm | ForEach-Object { $_.notActions })
                DataActions = Join-A2C @($perm | ForEach-Object { $_.dataActions }); NotDataActions = Join-A2C @($perm | ForEach-Object { $_.notDataActions })
                DoNotApplyToChildScopes = $xp.doNotApplyToChildScopes; IsSystemProtected = $xp.isSystemProtected; CreatedOn = Format-A2CDate $xp.createdOn; Id = [string]$x.id
            })
    }
    Add-A2CRows 'RBAC_deny_assignments.csv' $deny
    $roles = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @($defs.Values | Sort-Object @{ Expression = { $_.Type } }, @{ Expression = { $_.RoleName } })) {
        $isCustom = ($d.Type -eq 'CustomRole')
        $n = [int]$counts[$d.Guid]
        if (-not $isCustom -and $n -eq 0) { continue }
        $roles.Add([ordered]@{
                RoleName = $d.RoleName; roleID = $d.Guid; RoleType = $d.Type; IsCustom = $isCustom; Descr = $d.Description
                Actions = Join-A2C $d.Actions; NotActions = Join-A2C $d.NotActions; DataActions = Join-A2C $d.DataActions; NotDataActions = Join-A2C $d.NotDataActions
                AssignableScopes = Join-A2C $d.AssignableScopes; AssignmentCount = $n; Subscriptions = $d.Subscriptions.Count
                HasWildcardActions = (@($d.Actions | Where-Object { $_.Contains('*') }).Count -gt 0)
            })
    }
    Add-A2CRows 'RBAC_roles.csv' $roles
}

# ---- Governance: management groups ----------------------------------------------------------------------
Register-A2CSchema 'managementGroups.csv' ('Level:num ManagementGroup:mg DisplayName:dn Parent:mg Path:list DirectSubscriptions:num ' +
    'TotalSubscriptions:num Subscriptions:list Source Id:id')

function New-A2CReportManagementGroups {
    $mgs = @($script:A2C.Data['ManagementGroups'])
    $byName = $script:A2C.Data['MgByName']; if ($null -eq $byName) { $byName = @{} }
    $subs = @($script:A2C.Data['Subscriptions'])
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $mgs) {
        if ($null -eq $m) { continue }
        $path = [System.Collections.Generic.List[string]]::new()
        $cur = $m; $guard = 0
        while ($null -ne $cur -and $guard -lt 20) {
            $guard++
            $path.Insert(0, $(if ($cur.DisplayName) { $cur.DisplayName } else { $cur.Name }))
            if (-not $cur.ParentName) { break }
            $cur = $byName[$cur.ParentName.ToLowerInvariant()]
        }
        $direct = @($subs | Where-Object { @($_.MgChain).Count -gt 0 -and $_.MgChain[0].Name -ieq $m.Name })
        $total = @($subs | Where-Object { @($_.MgChain | Where-Object { $_.Name -ieq $m.Name }).Count -gt 0 })
        $rows.Add([ordered]@{
                Level = $path.Count - 1; ManagementGroup = $m.Name; DisplayName = $m.DisplayName; Parent = $m.ParentName
                Path = [string]::Join(' / ', $path); DirectSubscriptions = $direct.Count; TotalSubscriptions = $total.Count
                Subscriptions = Join-A2C @($direct | ForEach-Object { $_.Name }); Source = $m.Source; Id = $m.Id
            })
    }
    Add-A2CRows 'managementGroups.csv' @($rows | Sort-Object { $_['Path'] })
}

# ---- Governance: Azure Policy ---------------------------------------------------------------------------
$script:A2CRestrictivePolicies = @{
    'e56962a6-4747-49cd-b67b-bf8b01975c4c' = @{ Name = 'Allowed locations'; Param = 'listOfAllowedLocations' }
    'e765b5de-1225-4ba3-bd56-1ac6695af988' = @{ Name = 'Allowed locations for resource groups'; Param = 'listOfAllowedLocations' }
    'a08ec900-254a-4555-9bf5-e42af04b5c5c' = @{ Name = 'Allowed resource types'; Param = 'listOfResourceTypesAllowed' }
    '6c112d4e-5bc7-47ae-a041-ea2d9dccd749' = @{ Name = 'Not allowed resource types'; Param = 'listOfResourceTypesNotAllowed' }
    'cccc23c7-8427-4f53-ad12-b6a63eb452b3' = @{ Name = 'Allowed virtual machine size SKUs'; Param = 'listOfAllowedSKUs' }
}

Register-A2CSchema 'policyAssignments.csv' ('Name:known DisplayName:known Scope:id ScopeType AppliesToSubscriptions:num DefinitionType ' +
    'Definition:known DefinitionName:known PolicyType Category EnforcementMode Effect Restricts Parameters:json NotScopes:idList IdentityType ' +
    'IdentityPrincipalId:guid Location NonComplianceMessage:text NonCompliantResources:num CompliantResources:num ExemptResources:num ' +
    'CreatedOn:date CreatedBy:guid Id:id ' +
    'Description:text DefinitionId:id DefinitionVersion Overrides:json ResourceSelectors:json MessagesByReference:text UserAssignedIdentity:idList')
Register-A2CSchema 'policyDefinitions.csv' ('Name:known DisplayName:known PolicyType Mode Category Version Deprecated Preview Effect DefinedAt:id ' +
    'AssignmentCount:num Parameters Description:text Id:id')
Register-A2CSchema 'policySetDefinitions.csv' ('Name:known DisplayName:known PolicyType Category Version Deprecated Preview PolicyCount:num ' +
    'DefinedAt:id AssignmentCount:num Parameters Description:text Id:id')
Register-A2CSchema 'policyExemptions.csv' ('Name:known DisplayName:known Scope:id ScopeType Assignment:known AssignmentId:id Category ExpiresOn:date ' +
    'Status DaysToExpiry:num PolicyDefinitionReferenceIds Description:text CreatedOn:date Id:id AssignmentScopeValidation ResourceSelectors:json')
Register-A2CSchema 'policyCompliance.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Resource:name ResourceType Assignment:known ' +
    'Definition:known DefinitionReferenceId Initiative:known Effect Timestamp:date ResourceId:id AssignmentId:id')

function Get-A2CParamValue {
    param($Params, [string] $Name)
    if ($null -eq $Params -or -not $Name) { return $null }
    $x = $Params.$Name
    if ($null -eq $x) { return $null }
    return $x.value
}

function Get-A2CPolicyRestrictions {
    # Location / resource type / VM size restrictions of an assignment, also when wrapped in an initiative.
    param($Assignment, $Defs)
    $out = [System.Collections.Generic.List[object]]::new()
    if ($Assignment.IsInitiative) {
        $set = $Defs[$Assignment.DefinitionId.ToLowerInvariant()]
        if ($null -eq $set) { return , $out }
        foreach ($m in $set.Members) {
            $rp = $script:A2CRestrictivePolicies[(Get-A2CNameFromId $m.DefinitionId).ToLowerInvariant()]
            if ($null -eq $rp) { continue }
            $expr = $null
            if ($null -ne $m.Parameters -and $null -ne $m.Parameters.($rp.Param)) { $expr = $m.Parameters.($rp.Param).value }
            $vals = $null
            if ($expr -is [string] -and $expr -match "^\[parameters\('([^']+)'\)\]$") {
                $sp = $Matches[1]
                $vals = Get-A2CParamValue $Assignment.Parameters $sp
                if ($null -eq $vals -and $null -ne $set.SetParameters -and $null -ne $set.SetParameters.$sp) { $vals = $set.SetParameters.$sp.defaultValue }
            }
            elseif ($null -ne $expr) { $vals = $expr }
            $out.Add([pscustomobject]@{ Policy = $rp.Name; Values = (Join-A2C $vals ', '); Via = $set.DisplayName })
        }
    }
    else {
        $rp = $script:A2CRestrictivePolicies[(Get-A2CNameFromId $Assignment.DefinitionId).ToLowerInvariant()]
        if ($null -ne $rp) { $out.Add([pscustomobject]@{ Policy = $rp.Name; Values = (Join-A2C (Get-A2CParamValue $Assignment.Parameters $rp.Param) ', '); Via = '' }) }
    }
    return , $out
}

function New-A2CReportPolicy {
    $defs = $script:A2C.Data['PolicyDefs']; if ($null -eq $defs) { $defs = @{} }
    $byA = $script:A2C.Data['PolicyByAssignment']; if ($null -eq $byA) { $byA = @{} }
    $assignCount = @{}
    $restrictions = [System.Collections.Generic.List[object]]::new()
    $rows = [System.Collections.Generic.List[object]]::new()
    $assignById = @{}
    foreach ($a in @($script:A2C.Data['PolicyAssignments'] | Sort-Object ScopeType, Scope, DisplayName)) {
        if ($null -eq $a) { continue }
        $assignById[$a.Id.ToLowerInvariant()] = $a
        $dk = $a.DefinitionId.ToLowerInvariant()
        $assignCount[$dk] = [int]$assignCount[$dk] + 1
        $d = $defs[$dk]
        $st = $byA[$a.Id.ToLowerInvariant()]
        $restr = Get-A2CPolicyRestrictions -Assignment $a -Defs $defs
        foreach ($x in $restr) { $restrictions.Add([pscustomobject]@{ Assignment = $a; Policy = $x.Policy; Values = $x.Values; Via = $x.Via }) }
        $rows.Add([ordered]@{
                Name = $a.Name; DisplayName = $a.DisplayName; Scope = $a.Scope; ScopeType = $a.ScopeType; AppliesToSubscriptions = $a.AppliesTo.Count
                DefinitionType = $(if ($a.IsInitiative) { 'Initiative' } else { 'Policy' })
                Definition = $(if ($null -ne $d) { $d.DisplayName } else { '' }); DefinitionName = Get-A2CNameFromId $a.DefinitionId
                PolicyType = $(if ($null -ne $d) { $d.PolicyType } else { '' }); Category = $(if ($null -ne $d) { $d.Category } else { '' })
                EnforcementMode = $(if ($a.EnforcementMode) { $a.EnforcementMode } else { 'Default' })
                Effect = $(if ($null -ne $d) { $d.Effect } else { '' })
                Restricts = Join-A2C @($restr | ForEach-Object { $_.Policy + ': ' + $_.Values }) ' | '
                Parameters = ConvertTo-A2CJsonString $a.Parameters; NotScopes = Join-A2C $a.NotScopes
                IdentityType = $a.IdentityType; IdentityPrincipalId = $a.IdentityPrincipalId; Location = $a.Location; NonComplianceMessage = $a.NonComplianceMessage
                NonCompliantResources = $(if ($null -ne $st) { $st.NonCompliant } else { $null }); CompliantResources = $(if ($null -ne $st) { $st.Compliant } else { $null })
                ExemptResources = $(if ($null -ne $st) { $st.Exempt } else { $null }); CreatedOn = Format-A2CDate $a.CreatedOn; CreatedBy = $a.CreatedBy; Id = $a.Id
                Description = $a.Description; DefinitionId = $a.DefinitionId; DefinitionVersion = $a.DefinitionVersion
                Overrides = $(if ($null -ne $a.Overrides) { ConvertTo-A2CJsonString $a.Overrides } else { '' }); ResourceSelectors = $(if ($null -ne $a.ResourceSelectors) { ConvertTo-A2CJsonString $a.ResourceSelectors } else { '' })
                MessagesByReference = $a.MessagesByReference; UserAssignedIdentity = $a.UserAssignedIdentity
            })
    }
    $script:A2C.Data['PolicyRestrictions'] = $restrictions
    Add-A2CRows 'policyAssignments.csv' $rows
    $pd = [System.Collections.Generic.List[object]]::new(); $ps = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @($defs.Values | Sort-Object PolicyType, DisplayName)) {
        $n = [int]$assignCount[$d.Id.ToLowerInvariant()]
        $row = [ordered]@{ Name = $d.Name; DisplayName = $d.DisplayName; PolicyType = $d.PolicyType; Category = $d.Category; Version = $d.Version
            Deprecated = $d.Deprecated; Preview = $d.Preview; DefinedAt = $d.DefinedAt; AssignmentCount = $n; Parameters = $d.ParameterNames; Description = $d.Description; Id = $d.Id }
        if ($d.IsSet) { $row['PolicyCount'] = $d.Members.Count; $ps.Add($row) }
        else { $row['Mode'] = $d.Mode; $row['Effect'] = $d.Effect; $pd.Add($row) }
    }
    Add-A2CRows 'policyDefinitions.csv' $pd
    Add-A2CRows 'policySetDefinitions.csv' $ps
    $ex = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @($script:A2C.Data['PolicyExemptions'] | Sort-Object Scope)) {
        if ($null -eq $e) { continue }
        $days = Get-A2CDaysUntil $e.ExpiresOn
        $a = $assignById[$e.AssignmentId.ToLowerInvariant()]
        $status = $(if ($null -eq $days) { 'No expiry' } elseif ($days -lt 0) { 'Expired' } elseif ($days -le 30) { 'Expires within 30 days' } else { 'Active' })
        $ex.Add([ordered]@{
                Name = $e.Name; DisplayName = $e.DisplayName; Scope = $e.Scope; ScopeType = Get-A2CScopeType $e.Scope
                Assignment = $(if ($null -ne $a) { $a.DisplayName } else { Get-A2CNameFromId $e.AssignmentId }); AssignmentId = $e.AssignmentId
                Category = $e.Category; ExpiresOn = Format-A2CDate $e.ExpiresOn; Status = $status; DaysToExpiry = $days
                PolicyDefinitionReferenceIds = $e.RefIds; Description = $e.Description; CreatedOn = Format-A2CDate $e.CreatedOn; Id = $e.Id
                AssignmentScopeValidation = $e.AssignmentScopeValidation; ResourceSelectors = $(if ($null -ne $e.ResourceSelectors) { ConvertTo-A2CJsonString $e.ResourceSelectors } else { '' })
            })
    }
    Add-A2CRows 'policyExemptions.csv' $ex
    $comp = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($script:A2C.Data['PolicyNonCompliant'])) {
        if ($null -eq $s) { continue }
        $a = $assignById[([string]$s.assignmentId).ToLowerInvariant()]
        $d = $defs[([string]$s.definitionId).ToLowerInvariant()]
        $set = $defs[([string]$s.setDefinitionId).ToLowerInvariant()]
        $comp.Add([ordered]@{
                SubscriptionName = Get-A2CSubName ([string]$s.subscriptionId); SubscriptionId = [string]$s.subscriptionId
                ResourceGroup = Get-A2CRgFromId ([string]$s.resourceId); Resource = Get-A2CNameFromId ([string]$s.resourceId); ResourceType = [string]$s.resourceType
                Assignment = $(if ($null -ne $a) { $a.DisplayName } else { Get-A2CNameFromId ([string]$s.assignmentId) })
                Definition = $(if ($null -ne $d) { $d.DisplayName } else { Get-A2CNameFromId ([string]$s.definitionId) })
                DefinitionReferenceId = [string]$s.definitionRef; Initiative = $(if ($null -ne $set) { $set.DisplayName } else { '' })
                Effect = [string]$s.action; Timestamp = Format-A2CDate $s.timestamp; ResourceId = [string]$s.resourceId; AssignmentId = [string]$s.assignmentId
            })
    }
    Add-A2CRows 'policyCompliance.csv' $comp
}

# ---- Governance: tenant transfer impact -----------------------------------------------------------------
Register-A2CSchema 'tenantTransferImpact.csv' ('Category Impact SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Name:name Type ' +
    'Detail:note Action:note ResourceId:id')

$script:A2CTransferRecreate = @{
    'microsoft.containerservice/managedclusters' = 'AKS cluster: tenant transfer is not supported - redeploy the cluster in the new tenant'
    'microsoft.databricks/workspaces'            = 'Azure Databricks: not supported - recreate the workspace'
    'microsoft.aad/domainservices'               = 'Microsoft Entra Domain Services: cannot be transferred - recreate'
    'microsoft.servicefabric/clusters'           = 'Service Fabric: recreate the cluster'
    'microsoft.servicefabric/managedclusters'    = 'Service Fabric managed cluster: recreate'
    'microsoft.devcenter/devcenters'             = 'Dev Box / Deployment Environments: recreate'
    'microsoft.devcenter/projects'               = 'Dev Box / Deployment Environments: recreate'
    'microsoft.synapse/workspaces'               = 'Synapse workspace: update the tenant ID after the transfer'
}

function New-A2CReportTenantTransfer {
    $rows = [System.Collections.Generic.List[object]]::new()
    $add = {
        param([string] $Category, [string] $Impact, $R, [string] $Detail, [string] $Action)
        $rows.Add([ordered]@{
                Category = $Category; Impact = $Impact; SubscriptionName = Get-A2CSubName ([string]$R.subscriptionId); SubscriptionId = [string]$R.subscriptionId
                ResourceGroup = Get-A2CRgFromId ([string]$R.id); Name = [string]$R.name; Type = Get-A2CTypeCased -Id ([string]$R.id) -Fallback ([string]$R.type)
                Detail = $Detail; Action = $Action; ResourceId = [string]$R.id
            })
    }
    foreach ($r in $script:A2C.Data['Resources']) {
        $t = [string]$r.type
        $p = $null
        if ($script:A2CTransferRecreate.ContainsKey($t)) { & $add 'Not transferable' 'High' $r $script:A2CTransferRecreate[$t] 'Plan a redeployment in the target tenant' }
        if ($t -eq 'microsoft.managedidentity/userassignedidentities') {
            & $add 'Managed identity' 'High' $r 'User-assigned managed identity' 'Delete, recreate and re-attach after the transfer; recreate its role assignments'
            continue
        }
        if ($null -ne $r.identity -and ([string]$r.identity.type) -match '(?i)SystemAssigned') {
            & $add 'Managed identity' 'High' $r 'System-assigned managed identity' 'Disable and re-enable the identity after the transfer; recreate its role assignments'
        }
        if ($t -eq 'microsoft.keyvault/vaults') {
            $p = Get-A2CProps $r
            $ap = Get-A2CCount @($p.accessPolicies | Where-Object { $null -ne $_ })
            & $add 'Key Vault' 'High' $r ('Tenant ID bound; {0} access policies; permission model {1}' -f $ap, $(if ($p.enableRbacAuthorization) { 'Azure RBAC' } else { 'access policies' })) 'Update the vault tenant ID, then recreate access policies / role assignments'
            continue
        }
        if ($t -eq 'microsoft.sql/servers') {
            $p = Get-A2CProps $r
            if ($p.administrators.login -or $p.administrators.azureADOnlyAuthentication) { & $add 'Entra authentication' 'High' $r 'Microsoft Entra admin configured on SQL server' 'Remove Entra admin / Entra-only auth before the transfer and reconfigure after' }
            continue
        }
        if ($t -like 'microsoft.dbforpostgresql/flexibleservers' -or $t -like 'microsoft.dbformysql/flexibleservers') {
            & $add 'Entra authentication' 'Medium' $r 'Flexible server (Entra auth / customer-managed keys block the transfer)' 'Disable Entra authentication and CMK before the transfer'
        }
        if ($t -eq 'microsoft.storage/storageaccounts') {
            $p = Get-A2CProps $r
            if ([string]$p.encryption.keySource -eq 'Microsoft.Keyvault') { & $add 'Encryption' 'High' $r 'Customer-managed key from Key Vault' 'Make sure the key stays accessible; reconfigure the identity used for the key' }
            if ($p.isHnsEnabled) { & $add 'ACLs' 'Medium' $r 'Data Lake Storage Gen2 (POSIX ACLs reference Entra object IDs)' 'Re-create ACLs for the new tenant principals' }
            if ($null -ne $p.azureFilesIdentityBasedAuthentication -and [string]$p.azureFilesIdentityBasedAuthentication.directoryServiceOptions -ne 'None') {
                & $add 'Entra authentication' 'Medium' $r 'Azure Files identity-based authentication' 'Re-enable Entra Kerberos / AD DS auth and re-assign share permissions'
            }
            continue
        }
        if ($t -eq 'microsoft.compute/diskencryptionsets') { & $add 'Encryption' 'High' $r 'Disk encryption set (customer-managed keys)' 'Re-enable the managed identity and re-grant Key Vault access immediately after the transfer' }
        if ($t -eq 'microsoft.compute/virtualmachines/extensions') {
            $p = Get-A2CProps $r
            if ([string]$p.type -like 'AzureDiskEncryption*') { & $add 'Encryption' 'High' $r 'Azure Disk Encryption extension' 'Verify Key Vault access for ADE after the transfer' }
        }
        if ($t -eq 'microsoft.operationsmanagement/solutions' -and [string]$r.name -like 'SecurityInsights(*') {
            & $add 'Security' 'Medium' $r 'Microsoft Sentinel workspace' 'Re-onboard Microsoft Sentinel within 90 days after the transfer'
        }
    }
    # per subscription: RBAC, custom roles, policy
    $ra = @($script:A2C.Data['RoleAssignments'])
    $defs = $script:A2C.Data['RoleDefs']
    foreach ($s in $script:A2C.Data['Subscriptions']) {
        $fake = [pscustomobject]@{ id = '/subscriptions/' + $s.Id; name = $s.Name; type = 'microsoft.resources/subscriptions'; subscriptionId = $s.Id }
        if (Test-A2CDataset 'RoleAssignments') {
            $direct = @($ra | Where-Object { $_.SubscriptionId -eq $s.Id -and $_.Scope -like ('/subscriptions/' + $s.Id + '*') }).Count
            if ($direct -gt 0) { & $add 'RBAC' 'High' $fake ('{0} role assignments at subscription/resource group/resource scope' -f $direct) 'All role assignments are deleted by the transfer - export RBAC_role_assignments.csv and recreate them for the new principals' }
        }
        if ($null -ne $defs) {
            $custom = @($defs.Values | Where-Object { $_.Type -eq 'CustomRole' -and $_.Subscriptions.Contains($s.Id) })
            foreach ($c in $custom) {
                $croleRow = [pscustomobject]@{ id = [string]$c.Id; name = $c.RoleName; type = 'microsoft.authorization/roledefinitions'; subscriptionId = $s.Id }
                & $add 'RBAC' 'High' $croleRow 'Custom role definition' 'Custom roles are deleted - recreate the definition in the new tenant'
            }
        }
        if (Test-A2CDataset 'PolicyAssignments') {
            $pa = @($script:A2C.Data['PolicyAssignments'] | Where-Object { $_.Scope -like ('/subscriptions/' + $s.Id + '*') })
            if ($pa.Count -gt 0) { & $add 'Policy' 'Medium' $fake ('{0} policy assignments at subscription scope or below' -f $pa.Count) 'Export and re-create the assignments (and their managed identities) in the new tenant' }
            $mg = @($script:A2C.Data['PolicyAssignments'] | Where-Object { $_.ScopeType -eq 'ManagementGroup' -and $_.AppliesTo.Contains($s.Id) })
            if ($mg.Count -gt 0) { & $add 'Policy' 'Medium' $fake ('{0} policy assignments inherited from management groups will no longer apply' -f $mg.Count) 'Re-create equivalent governance in the target management group hierarchy' }
        }
    }
    # Azure DevOps service connections to subscriptions of this inventory use identities and role assignments of this tenant
    $subById = $script:A2C.Data['SubById']
    foreach ($o in @($script:A2C.Data['Ado'] | Where-Object { $null -ne $_ -and $_.Status -eq 'Collected' })) {
        foreach ($e in $o.Endpoints) {
            $x = $e.Item
            $sid = ([string](Get-A2CFirst $x.data @('subscriptionId'))).ToLowerInvariant()
            if (-not $sid -or $null -eq $subById -or -not $subById.ContainsKey($sid)) { continue }
            $conn = [pscustomobject]@{ id = ''; name = [string]$x.name; type = 'Azure DevOps service connection'; subscriptionId = $sid }
            & $add 'Azure DevOps' 'High' $conn ('Service connection of Azure DevOps organization {0} ({1})' -f $o.Name, [string]$x.authorization.scheme) 'Recreate its app registration or managed identity (and federated credential) in the target tenant, grant the roles again and update the service connection'
        }
    }
    Add-A2CRows 'tenantTransferImpact.csv' @($rows | Sort-Object @{ Expression = { @{ High = 0; Medium = 1; Low = 2 }[$_['Impact']] } }, @{ Expression = { $_['Category'] } })
}

# ---- Inventory: move support and cross references -------------------------------------------------------
Register-A2CSchema 'moveSupport.csv' ('ResourceType Resources:num Subscriptions:num CanMoveToOtherRG CanMoveToOtherSubscription ' +
    'CanMoveToOtherRegion MoveNotes')

function New-A2CReportMoveSupport {
    $counts = @{}
    foreach ($r in $script:A2C.Data['Resources']) {
        $t = Get-A2CTypeCased -Id ([string]$r.id) -Fallback ([string]$r.type)
        $k = $t.ToLowerInvariant()
        if (-not $counts.ContainsKey($k)) { $counts[$k] = [pscustomobject]@{ Type = $t; Count = 0; Subs = [System.Collections.Generic.HashSet[string]]::new() } }
        $counts[$k].Count++
        [void]$counts[$k].Subs.Add([string]$r.subscriptionId)
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($c in @($counts.Values | Sort-Object Type)) {
        $mv = Get-A2CMoveInfo $c.Type
        $rows.Add([ordered]@{ ResourceType = $c.Type; Resources = $c.Count; Subscriptions = $c.Subs.Count; CanMoveToOtherRG = $mv.RG
                CanMoveToOtherSubscription = $mv.Sub; CanMoveToOtherRegion = $mv.Region; MoveNotes = $mv.Notes })
    }
    Add-A2CRows 'moveSupport.csv' $rows
}

Register-A2CSchema 'crossReferences.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Resource:name ResourceType ' +
    'TargetSubscriptionId:guid TargetResourceGroup:rg TargetResource:name TargetType Relation TargetExists ResourceId:id TargetId:id')

function New-A2CReportCrossReferences {
    $rx = [regex]'(?i)/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/resourceGroups/([^/"\\]+)/providers/([^/"\\]+)/([^/"\\]+)/([^/"\\]+)'
    $inScope = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $script:A2C.Data['Subscriptions']) { [void]$inScope.Add($s.Id) }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $script:A2C.Data['Resources']) {
        $json = [string]$r.propertiesJson
        if (-not $json -or $json.IndexOf('/subscriptions/', [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $srcId = [string]$r.id
        $srcSub = ([string]$r.subscriptionId).ToLowerInvariant()
        $srcRg = Get-A2CRgFromId $srcId
        $self = (Get-A2CTopLevelId $srcId).ToLowerInvariant()
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($m in $rx.Matches($json)) {
            $tSub = $m.Groups[1].Value.ToLowerInvariant()
            $tRg = $m.Groups[2].Value
            if ($tSub -eq $srcSub -and $tRg -ieq $srcRg) { continue }
            $target = '/subscriptions/{0}/resourceGroups/{1}/providers/{2}/{3}/{4}' -f $m.Groups[1].Value, $tRg, $m.Groups[3].Value, $m.Groups[4].Value, $m.Groups[5].Value
            if ($target.ToLowerInvariant() -eq $self -or -not $seen.Add($target)) { continue }
            $exists = $(if (-not $inScope.Contains($tSub)) { 'Out of scope' } elseif ($null -ne (Get-A2CResource $target)) { 'Yes' } else { 'No (dangling reference)' })
            $rows.Add([ordered]@{
                    SubscriptionName = Get-A2CSubName $srcSub; SubscriptionId = $srcSub; ResourceGroup = $srcRg; Resource = [string]$r.name
                    ResourceType = Get-A2CTypeCased -Id $srcId -Fallback ([string]$r.type); TargetSubscriptionId = $tSub; TargetResourceGroup = $tRg
                    TargetResource = $m.Groups[5].Value; TargetType = $m.Groups[3].Value + '/' + $m.Groups[4].Value
                    Relation = $(if ($tSub -ne $srcSub) { 'CrossSubscription' } else { 'CrossResourceGroup' }); TargetExists = $exists; ResourceId = $srcId; TargetId = $target
                })
        }
    }
    Add-A2CRows 'crossReferences.csv' $rows
}

# ---- Operations: Advisor, retirements, orphans, cost ----------------------------------------------------
Register-A2CSchema 'advisor.csv' ('SubscriptionName:sub SubscriptionId:guid Category Impact Problem Solution ResourceType Resource:name ' +
    'ResourceGroup:rg ImpactedField ImpactedValue:name SavingsAmount:num AnnualSavings:num Currency LastUpdated:date RecommendationTypeId ResourceId:id')

function New-A2CReportAdvisor {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($a in @($script:A2C.Data['Advisor'] | Sort-Object Category, Impact, Problem)) {
        if ($null -eq $a) { continue }
        $rows.Add([ordered]@{
                SubscriptionName = Get-A2CSubName $a.SubscriptionId; SubscriptionId = $a.SubscriptionId; Category = $a.Category; Impact = $a.Impact
                Problem = $a.Problem; Solution = $a.Solution; ResourceType = Get-A2CTypeCased -Id $a.ResourceId -Fallback $a.ImpactedField
                Resource = Get-A2CNameFromId $a.ResourceId; ResourceGroup = Get-A2CRgFromId $a.ResourceId; ImpactedField = $a.ImpactedField
                ImpactedValue = $a.ImpactedValue; SavingsAmount = $a.Savings; AnnualSavings = $a.AnnualSavings; Currency = $a.Currency
                LastUpdated = Format-A2CDate $a.LastUpdated; RecommendationTypeId = $a.TypeId; ResourceId = $a.ResourceId
            })
    }
    Add-A2CRows 'advisor.csv' $rows
}

Register-A2CSchema 'retirements.csv' ('Source RuleId Feature RetirementDate:date Status DaysLeft:num SubscriptionName:sub SubscriptionId:guid ' +
    'ResourceGroup:rg Resource:name ResourceType Detail:note Action:note LearnMore:url ResourceId:id')

# Retirement rules: Types = resource types to test. Test = scriptblock returning $true or a detail string; it is invoked
# from New-A2CReportRetirements and reads that function's $r (Resource Graph row) and $p (parsed properties).
$script:A2CRetirementRules = @(
    @{ Id = 'R01'; Feature = 'Basic SKU public IP addresses'; Date = '2025-09-30'; Types = @('microsoft.network/publicipaddresses')
       Test = { [string]$r.sku.name -eq 'Basic' }; Action = 'Upgrade to Standard SKU public IP'; Url = 'https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-basic-upgrade-guidance' }
    @{ Id = 'R02'; Feature = 'Basic Load Balancer'; Date = '2025-09-30'; Types = @('microsoft.network/loadbalancers')
       Test = { [string]$r.sku.name -eq 'Basic' }; Action = 'Upgrade to Standard Load Balancer'; Url = 'https://learn.microsoft.com/azure/load-balancer/load-balancer-basic-upgrade-guidance' }
    @{ Id = 'R03'; Feature = 'Unmanaged (VHD) disks'; Date = '2026-03-31'; Types = @('microsoft.compute/virtualmachines')
       Test = { ($null -ne $p.storageProfile.osDisk.vhd) -or (@($p.storageProfile.dataDisks | Where-Object { $null -ne $_ -and $null -ne $_.vhd }).Count -gt 0) }
       Action = 'Migrate the VM to managed disks'; Url = 'https://learn.microsoft.com/azure/virtual-machines/unmanaged-disks-deprecation' }
    @{ Id = 'R04'; Feature = 'Classic (ASM) resources'; Date = '2024-08-31'; Types = @('*classic*')
       Test = { $true }; Action = 'Migrate to Azure Resource Manager'; Url = 'https://learn.microsoft.com/azure/virtual-machines/classic-vm-deprecation' }
    @{ Id = 'R05'; Feature = 'App Service Environment v1/v2'; Date = '2024-08-31'; Types = @('microsoft.web/hostingenvironments')
       Test = { [string]$r.kind -notmatch '(?i)ASEV3' }; Action = 'Migrate to App Service Environment v3'; Url = 'https://learn.microsoft.com/azure/app-service/environment/migrate' }
    @{ Id = 'R06'; Feature = 'TLS 1.0/1.1 on storage accounts'; Date = '2026-02-03'; Types = @('microsoft.storage/storageaccounts')
       Test = { @('TLS1_0', 'TLS1_1', '') -contains [string]$p.minimumTlsVersion }; Action = 'Set the minimum TLS version to TLS1_2 (check old clients first)'; Url = 'https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version' }
    @{ Id = 'R07'; Feature = 'General-purpose v1 and legacy Blob storage accounts'; Date = '2026-10-13'; Types = @('microsoft.storage/storageaccounts')
       Test = { @('Storage', 'BlobStorage') -contains [string]$r.kind }; Action = 'Upgrade to general-purpose v2 (check transaction costs)'; Url = 'https://learn.microsoft.com/azure/storage/common/general-purpose-version-1-account-migration-overview' }
    @{ Id = 'R08'; Feature = 'Log Analytics agent (MMA/OMS)'; Date = '2024-08-31'; Types = @('microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.hybridcompute/machines/extensions')
       Test = { @('MicrosoftMonitoringAgent', 'OmsAgentForLinux') -contains [string]$p.type }; Action = 'Migrate to Azure Monitor Agent (AMA) and data collection rules'; Url = 'https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-migration' }
    @{ Id = 'R09'; Feature = 'Automation runtimes Python 2.7/3.8 and PowerShell 7.1/7.2'; Date = '2026-09-30'; Types = @('microsoft.automation/automationaccounts/runbooks')
       Test = { @('Python2', 'PowerShell72') -contains [string]$p.runbookType }; Action = 'Move the runbook to PowerShell 7.4 / Python 3.10 runtime environments'; Url = 'https://learn.microsoft.com/azure/automation/automation-runbook-types' }
    @{ Id = 'R10'; Feature = 'Application Gateway v1 (Standard/WAF)'; Date = '2026-04-28'; Types = @('microsoft.network/applicationgateways')
       Test = { @('Standard', 'WAF') -contains [string]$p.sku.tier }; Action = 'Migrate to Application Gateway v2'; Url = 'https://learn.microsoft.com/azure/application-gateway/v1-retirement' }
    @{ Id = 'R11'; Feature = 'Azure Cache for Redis Enterprise / Enterprise Flash'; Date = '2027-03-31'; Types = @('microsoft.cache/redisenterprise')
       Test = { [string]$r.sku.name -like 'Enterprise*' }; Action = 'Migrate to Azure Managed Redis'; Url = 'https://learn.microsoft.com/azure/azure-cache-for-redis/retirement-faq' }
    @{ Id = 'R12'; Feature = 'Azure Cache for Redis (Basic/Standard/Premium)'; Date = '2028-09-30'; Types = @('microsoft.cache/redis')
       Test = { $true }; Action = 'Plan the move to Azure Managed Redis'; Url = 'https://learn.microsoft.com/azure/azure-cache-for-redis/retirement-faq' }
    @{ Id = 'R13'; Feature = 'Azure Front Door (classic)'; Date = '2027-03-31'; Types = @('microsoft.network/frontdoors')
       Test = { $true }; Action = 'Migrate to Azure Front Door Standard/Premium'; Url = 'https://learn.microsoft.com/azure/frontdoor/classic-retirement-faq' }
    @{ Id = 'R14'; Feature = 'Azure CDN Standard from Microsoft (classic)'; Date = '2027-09-30'; Types = @('microsoft.cdn/profiles')
       Test = { [string]$r.sku.name -eq 'Standard_Microsoft' }; Action = 'Migrate to Azure Front Door Standard/Premium'; Url = 'https://learn.microsoft.com/azure/cdn/classic-cdn-retirement-faq' }
    @{ Id = 'R15'; Feature = 'Cloud Services (extended support)'; Date = '2027-03-31'; Types = @('microsoft.compute/cloudservices')
       Test = { $true }; Action = 'Migrate to Virtual Machine Scale Sets or App Service'; Url = 'https://learn.microsoft.com/azure/cloud-services-extended-support/overview' }
    @{ Id = 'R16'; Feature = 'VPN Gateway Standard/High Performance SKUs'; Date = '2026-06-30'; Types = @('microsoft.network/virtualnetworkgateways')
       Test = { @('Standard', 'HighPerformance') -contains [string]$p.sku.name }; Action = 'Migrate to a VpnGw*AZ SKU'; Url = 'https://learn.microsoft.com/azure/vpn-gateway/gateway-sku-consolidation' }
    @{ Id = 'R17'; Feature = 'Azure Database for PostgreSQL Single Server'; Date = '2025-03-28'; Types = @('microsoft.dbforpostgresql/servers')
       Test = { $true }; Action = 'Migrate to PostgreSQL Flexible Server'; Url = 'https://learn.microsoft.com/azure/postgresql/migrate/whats-happening-to-postgresql-single-server' }
    @{ Id = 'R18'; Feature = 'Azure Database for MySQL Single Server'; Date = '2024-09-16'; Types = @('microsoft.dbformysql/servers')
       Test = { $true }; Action = 'Migrate to MySQL Flexible Server'; Url = 'https://learn.microsoft.com/azure/mysql/migrate/whats-happening-to-mysql-single-server' }
    @{ Id = 'R19'; Feature = 'Azure Database for MariaDB'; Date = '2025-09-19'; Types = @('microsoft.dbformariadb/servers')
       Test = { $true }; Action = 'Migrate to MySQL Flexible Server'; Url = 'https://learn.microsoft.com/azure/mariadb/whats-happening-to-mariadb' }
    @{ Id = 'R20'; Feature = 'D/DS/Dv2/DSv2/Ls VM series'; Date = '2028-05-01'; Types = @('microsoft.compute/virtualmachines')
       Test = { $s = [string]$p.hardwareProfile.vmSize; if ($s -match '^(?i)Standard_(D\d+|DS\d+|D\d+_v2(_Promo)?|DS\d+_v2(_Promo)?|L\d+s)$') { 'Size ' + $s } else { $false } }
       Action = 'Resize to a current VM series (for example Dv5/Dsv5/Lsv3)'; Url = 'https://learn.microsoft.com/azure/virtual-machines/sizes/retirement/retired-sizes-list' }
    @{ Id = 'R21'; Feature = 'Standard HDD OS disks'; Date = '2028-09-08'; Types = @('microsoft.compute/disks')
       Test = { [string]$r.sku.name -eq 'Standard_LRS' -and [string]$p.osType -ne '' }; Action = 'Convert OS disks to Standard SSD or Premium SSD'; Url = 'https://learn.microsoft.com/azure/virtual-machines/disks-types' }
    @{ Id = 'R22'; Feature = 'Azure Disk Encryption'; Date = '2028-09-15'; Types = @('microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachinescalesets/extensions')
       Test = { [string]$p.type -like 'AzureDiskEncryption*' }; Action = 'Move to encryption at host / server-side encryption with customer-managed keys'; Url = 'https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview' }
    @{ Id = 'R23'; Feature = 'NSG flow logs'; Date = '2027-09-30'; Types = @('microsoft.network/networkwatchers/flowlogs')
       Test = { [string]$p.targetResourceId -match '(?i)/networkSecurityGroups/' }; Action = 'Migrate to virtual network flow logs'; Url = 'https://learn.microsoft.com/azure/network-watcher/nsg-flow-logs-migrate' }
    @{ Id = 'R24'; Feature = 'Classic Application Insights (not workspace-based)'; Date = '2024-02-29'; Types = @('microsoft.insights/components')
       Test = { -not $p.WorkspaceResourceId }; Action = 'Migrate to workspace-based Application Insights'; Url = 'https://learn.microsoft.com/azure/azure-monitor/app/convert-classic-resource' }
    @{ Id = 'R25'; Feature = 'SQL Server out of extended support (SQL on Azure VM)'; Date = ''; Types = @('microsoft.sqlvirtualmachine/sqlvirtualmachines')
       Test = { $s = Get-A2CSqlSupport ([string]$p.sqlImageOffer); if ($s[1] -like 'Out of extended support*' -or $s[1] -like 'Extended support ends*') { $s[0] + ': ' + $s[1] } else { $false } }
       Action = 'Upgrade SQL Server or enable Extended Security Updates'; Url = 'https://learn.microsoft.com/lifecycle/products/?terms=sql%20server' }
)

function Get-A2CRetirementStatus {
    param([string] $Date)
    if (-not $Date) { return @('Check', $null) }
    $d = Get-A2CDaysUntil $Date
    if ($null -eq $d) { return @('Check', $null) }
    if ($d -lt 0) { return @('Retired', $d) }
    if ($d -le 90) { return @('Due within 90 days', $d) }
    if ($d -le 365) { return @('Due within 1 year', $d) }
    return @('Later', $d)
}

function New-A2CReportRetirements {
    # $r and $p are read by the rule Test scriptblocks (dynamic scope), which the analyzer cannot see
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'p')]
    param()
    $rows = [System.Collections.Generic.List[object]]::new()
    $bt = $script:A2C.Data['ResByType']; if ($null -eq $bt) { $bt = @{} }
    foreach ($rule in $script:A2CRetirementRules) {
        $cands = [System.Collections.Generic.List[object]]::new()
        foreach ($t in $rule.Types) {
            if ($t -like '*`**') { foreach ($k in $bt.Keys) { if ($k -like $t) { $cands.AddRange($bt[$k]) } } }
            elseif ($bt.ContainsKey($t)) { $cands.AddRange($bt[$t]) }
        }
        foreach ($r in $cands) {
            $p = Get-A2CProps $r
            $res = $null
            try { $res = & $rule.Test } catch { $res = $false }
            if (-not $res) { continue }
            $date = $rule.Date
            $detail = $(if ($res -is [string]) { $res } else { '' })
            if ($rule.Id -eq 'R25' -and $detail -match '(\d{4}-\d{2}-\d{2})') { $date = $Matches[1] }
            $st = Get-A2CRetirementStatus $date
            $rows.Add([ordered]@{
                    Source = 'Rule'; RuleId = $rule.Id; Feature = $rule.Feature; RetirementDate = $date; Status = $st[0]; DaysLeft = $st[1]
                    SubscriptionName = Get-A2CSubName ([string]$r.subscriptionId); SubscriptionId = [string]$r.subscriptionId; ResourceGroup = Get-A2CRgFromId ([string]$r.id)
                    Resource = [string]$r.name; ResourceType = Get-A2CTypeCased -Id ([string]$r.id) -Fallback ([string]$r.type); Detail = $detail
                    Action = $rule.Action; LearnMore = $rule.Url; ResourceId = [string]$r.id
                })
        }
    }
    # runbook code using AzureRM / Run As accounts (only when RunbookContent was exported)
    $content = $script:A2C.Data['RunbookContent']
    if ($null -ne $content) {
        foreach ($rb in (Get-A2CResourcesOfType 'microsoft.automation/automationaccounts/runbooks')) {
            $c = $content[([string]$rb.id).ToLowerInvariant()]
            if ($null -eq $c) { continue }
            foreach ($x in @(@{ On = $c.UsesAzureRM; Id = 'R26'; F = 'AzureRM PowerShell modules'; D = '2024-02-29'; A = 'Migrate the runbook to the Az modules'; U = 'https://learn.microsoft.com/powershell/azure/migrate-from-azurerm-to-az' },
                    @{ On = $c.UsesRunAs; Id = 'R27'; F = 'Automation Run As accounts'; D = '2023-09-30'; A = 'Use a managed identity'; U = 'https://learn.microsoft.com/azure/automation/migrate-run-as-accounts-managed-identity' })) {
                if (-not $x.On) { continue }
                $st = Get-A2CRetirementStatus $x.D
                $rows.Add([ordered]@{ Source = 'Rule'; RuleId = $x.Id; Feature = $x.F; RetirementDate = $x.D; Status = $st[0]; DaysLeft = $st[1]
                        SubscriptionName = Get-A2CSubName ([string]$rb.subscriptionId); SubscriptionId = [string]$rb.subscriptionId; ResourceGroup = Get-A2CRgFromId ([string]$rb.id)
                        Resource = [string]$rb.name; ResourceType = 'Microsoft.Automation/automationAccounts/runbooks'; Detail = 'Found in exported runbook code'
                        Action = $x.A; LearnMore = $x.U; ResourceId = [string]$rb.id })
            }
        }
    }
    $ruleKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in $rows) { [void]$ruleKeys.Add([string]$x['ResourceId'] + '|' + [string]$x['RetirementDate']) }
    foreach ($a in @($script:A2C.Data['Advisor'])) {
        if ($null -eq $a -or -not $a.RetirementFeature) { continue }
        $date = ''
        $dt = ConvertTo-A2CUtc $a.RetirementDate
        if ($null -ne $dt) { $date = $dt.ToString('yyyy-MM-dd') }
        if ($ruleKeys.Contains($a.ResourceId + '|' + $date)) { continue }   # already reported by a built-in rule
        $st = Get-A2CRetirementStatus $date
        $rows.Add([ordered]@{ Source = 'Advisor'; RuleId = $a.TypeId; Feature = $a.RetirementFeature; RetirementDate = $date; Status = $st[0]; DaysLeft = $st[1]
                SubscriptionName = Get-A2CSubName $a.SubscriptionId; SubscriptionId = $a.SubscriptionId; ResourceGroup = Get-A2CRgFromId $a.ResourceId
                Resource = Get-A2CNameFromId $a.ResourceId; ResourceType = Get-A2CTypeCased -Id $a.ResourceId -Fallback ''; Detail = $a.Problem
                Action = $a.Solution; LearnMore = ''; ResourceId = $a.ResourceId })
    }
    Add-A2CRows 'retirements.csv' @($rows | Sort-Object @{ Expression = { if ($null -eq $_['DaysLeft']) { 99999 } else { [int]$_['DaysLeft'] } } }, @{ Expression = { $_['Feature'] } })
}

Register-A2CSchema 'orphans.csv' ('Category Reason:note SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Resource:name ResourceType ' +
    'Location Sku Detail:note Cost:num CostCurrency ResourceId:id')

function New-A2CReportOrphans {
    $rows = [System.Collections.Generic.List[object]]::new()
    $add = {
        param([string] $Category, [string] $Reason, $R, [string] $Detail)
        $c = Get-A2CCostInfo ([string]$R.id)
        $rows.Add([ordered]@{
                Category = $Category; Reason = $Reason; SubscriptionName = Get-A2CSubName ([string]$R.subscriptionId); SubscriptionId = [string]$R.subscriptionId
                ResourceGroup = Get-A2CRgFromId ([string]$R.id); Resource = [string]$R.name; ResourceType = Get-A2CTypeCased -Id ([string]$R.id) -Fallback ([string]$R.type)
                Location = [string]$R.location; Sku = $(if ($null -ne $R.sku) { [string]$R.sku.name } else { '' }); Detail = $Detail
                Cost = $(if ($null -ne $c) { $c.Cost } else { $null }); CostCurrency = $(if ($null -ne $c) { $c.Currency } else { '' }); ResourceId = [string]$R.id
            })
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.compute/disks')) {
        $p = Get-A2CProps $r
        if ($r.managedBy -or [string]$p.diskState -eq 'ActiveSAS') { continue }
        $n = [string]$r.name
        $tags = ConvertTo-A2CTagString $r.tags
        if ($n -like '*-ASRReplica' -or $n -like 'ms-asr-*' -or $n -like 'asrseeddisk-*' -or $tags -match 'kubernetes\.io-created-for-pvc|ASR-ReplicaDisk|asrseeddisk|RSVaultBackup') { continue }
        & $add 'Unattached disk' 'Managed disk not attached to any VM (still billed)' $r ('{0} GB {1}' -f $p.diskSizeGB, $r.sku.name)
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/publicipaddresses')) {
        $p = Get-A2CProps $r
        if ($null -eq $p.ipConfiguration -and $null -eq $p.natGateway -and $null -eq $p.publicIPPrefix) { & $add 'Unused public IP' 'Public IP not associated with any resource' $r ([string]$p.ipAddress) }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/networkinterfaces')) {
        $p = Get-A2CProps $r
        if ($null -eq $p.virtualMachine -and $null -eq $p.privateEndpoint -and $null -eq $p.privateLinkService -and @($p.hostedWorkloads | Where-Object { $_ }).Count -eq 0) {
            & $add 'Orphaned NIC' 'Network interface not attached to a VM or private endpoint' $r ''
        }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/networksecuritygroups')) {
        $p = Get-A2CProps $r
        if (@($p.subnets | Where-Object { $null -ne $_ }).Count -eq 0 -and @($p.networkInterfaces | Where-Object { $null -ne $_ }).Count -eq 0) { & $add 'Unused NSG' 'NSG not associated with a subnet or NIC' $r '' }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/routetables')) {
        $p = Get-A2CProps $r
        if (@($p.subnets | Where-Object { $null -ne $_ }).Count -eq 0) { & $add 'Unused route table' 'Route table not associated with a subnet' $r '' }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.web/serverfarms')) {
        $p = Get-A2CProps $r
        if ($null -ne $p.numberOfSites -and [int]$p.numberOfSites -eq 0) { & $add 'Empty App Service plan' 'App Service plan without apps (still billed)' $r ([string]$r.sku.name) }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/loadbalancers')) {
        $p = Get-A2CProps $r
        if (@($p.backendAddressPools | Where-Object { $null -ne $_ }).Count -eq 0 -and @($p.inboundNatRules | Where-Object { $null -ne $_ }).Count -eq 0) { & $add 'Idle load balancer' 'Load balancer without backend pools or NAT rules' $r ([string]$r.sku.name) }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.compute/availabilitysets')) {
        $p = Get-A2CProps $r
        if (@($p.virtualMachines | Where-Object { $null -ne $_ }).Count -eq 0 -and [string]$r.name -notlike '*-asr') { & $add 'Empty availability set' 'Availability set without VMs' $r '' }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/natgateways')) {
        $p = Get-A2CProps $r
        if (@($p.subnets | Where-Object { $null -ne $_ }).Count -eq 0) { & $add 'Unused NAT gateway' 'NAT gateway not associated with a subnet (still billed)' $r '' }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/privatednszones')) {
        $p = Get-A2CProps $r
        if ($null -ne $p.numberOfVirtualNetworkLinks -and [int]$p.numberOfVirtualNetworkLinks -eq 0) { & $add 'Unlinked private DNS zone' 'Private DNS zone without VNet links' $r ('{0} record sets' -f $p.numberOfRecordSets) }
    }
    $pools = @{}
    foreach ($d in (Get-A2CResourcesOfType 'microsoft.sql/servers/databases')) { $pp = Get-A2CProps $d; if ($pp.elasticPoolId) { $pools[([string]$pp.elasticPoolId).ToLowerInvariant()] = $true } }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.sql/servers/elasticpools')) {
        if (-not $pools.ContainsKey(([string]$r.id).ToLowerInvariant())) { & $add 'Empty SQL elastic pool' 'Elastic pool without databases (still billed)' $r ([string]$r.sku.name) }
    }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.compute/virtualmachines')) {
        $p = Get-A2CProps $r
        if ([string]$p.extended.instanceView.powerState.code -eq 'PowerState/stopped') { & $add 'Stopped VM (not deallocated)' 'VM is stopped from inside the OS but not deallocated - compute is still billed' $r ([string]$p.hardwareProfile.vmSize) }
    }
    # empty resource groups
    $used = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $script:A2C.Data['Resources']) { [void]$used.Add(([string]$r.subscriptionId) + '/' + (Get-A2CRgFromId ([string]$r.id))) }
    foreach ($rg in @($script:A2C.Data['ResourceGroups'])) {
        if ($null -eq $rg) { continue }
        if (-not $used.Contains(([string]$rg.subscriptionId) + '/' + [string]$rg.name)) {
            $fake = [pscustomobject]@{ id = [string]$rg.id; name = [string]$rg.name; type = 'microsoft.resources/subscriptions/resourcegroups'; subscriptionId = [string]$rg.subscriptionId; location = [string]$rg.location; sku = $null }
            & $add 'Empty resource group' 'Resource group without resources' $fake ''
        }
    }
    Add-A2CRows 'orphans.csv' @($rows | Sort-Object @{ Expression = { $_['Category'] } }, @{ Expression = { $_['Resource'] } })
}

Register-A2CSchema 'cost.csv' ('SubscriptionName:sub SubscriptionId:guid ResourceGroup:rg Resource:name ResourceType Cost:num Currency From:date ' +
    'To:date InInventory ResourceId:id')

function New-A2CReportCost {
    $byRes = $script:A2C.Data['CostByResource']; if ($null -eq $byRes) { return }
    $period = $script:A2C.Data['CostPeriod']
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($k in @($byRes.Keys)) {
        $c = $byRes[$k]
        $res = Get-A2CResource $k
        $id = $(if ($null -ne $res) { [string]$res.id } else { $k })
        $rows.Add([ordered]@{
                SubscriptionName = Get-A2CSubName $c.SubscriptionId; SubscriptionId = $c.SubscriptionId; ResourceGroup = Get-A2CRgFromId $id
                Resource = $(if ($k -eq '(unassigned)') { '(unassigned)' } else { Get-A2CNameFromId $id }); ResourceType = Get-A2CTypeCased -Id $id -Fallback ''
                Cost = $c.Cost; Currency = $c.Currency; From = $period[0].ToString('yyyy-MM-dd'); To = $period[1].ToString('yyyy-MM-dd')
                InInventory = ($null -ne $res); ResourceId = $id
            })
    }
    Add-A2CRows 'cost.csv' @($rows | Sort-Object @{ Expression = { -1 * [double]$_['Cost'] } })
}

# ---- Entra ID -------------------------------------------------------------------------------------------
$script:A2CRiskyPermissions = @{
    Critical = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory',
        'Policy.ReadWrite.ConditionalAccess', 'UserAuthenticationMethod.ReadWrite.All', 'PrivilegedAccess.ReadWrite.AzureAD', 'full_access_as_app',
        'Sites.FullControl.All', 'Mail.ReadWrite', 'Directory.AccessAsUser.All', 'Exchange.ManageAsApp', 'EWS.AccessAsUser.All')
    High     = @('Mail.Read', 'Mail.Send', 'Files.ReadWrite.All', 'Files.Read.All', 'Sites.ReadWrite.All', 'Sites.Read.All', 'User.ReadWrite.All',
        'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Domain.ReadWrite.All', 'MailboxSettings.ReadWrite', 'Calendars.ReadWrite',
        'Contacts.ReadWrite', 'Chat.Read.All', 'ChannelMessage.Read.All', 'User.Export.All', 'AuditLog.Read.All')
}
$script:A2CPrivilegedDirectoryRoles = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'Exchange Administrator', 'SharePoint Administrator', 'User Administrator', 'Application Administrator',
    'Cloud Application Administrator', 'Conditional Access Administrator', 'Authentication Administrator', 'Hybrid Identity Administrator',
    'Intune Administrator', 'Partner Tier2 Support', 'Helpdesk Administrator', 'Groups Administrator')

function Get-A2CPermissionRisk {
    param([string] $Permission)
    if ($script:A2CRiskyPermissions.Critical -contains $Permission) { return 'Critical' }
    if ($script:A2CRiskyPermissions.High -contains $Permission) { return 'High' }
    return ''
}

function Get-A2CRbacPrincipalSet {
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($script:A2C.Data['RoleAssignments'])) { if ($null -ne $a) { [void]$set.Add($a.PrincipalId) } }
    return , $set
}

function Get-A2CCredentialStatus {
    param($Days)
    if ($null -eq $Days) { return '' }
    if ($Days -lt 0) { return 'Expired' }
    if ($Days -le 30) { return 'Expires within 30 days' }
    if ($Days -le 90) { return 'Expires within 90 days' }
    return 'OK'
}

function Get-A2CSpPublisher {
    param($Sp)
    if ([string]$Sp.servicePrincipalType -eq 'ManagedIdentity') { return 'Managed identity' }
    $o = ([string]$Sp.appOwnerOrganizationId).ToLowerInvariant()
    if ($script:A2CMicrosoftTenants -contains $o) { return 'Microsoft' }
    if ($o -and $o -eq $script:A2C.TenantId) { return 'This tenant' }
    if ($o) { return 'Third party' }
    return ''
}

Register-A2CSchema 'entraTenant.csv' ('TenantId:guid DisplayName:dn DefaultDomain:fqdn InitialDomain:fqdn Country CreatedDateTime:date TenantType ' +
    'OnPremisesSyncEnabled LastDirectorySync:date VerifiedDomains:num TechnicalNotificationMails:list')
Register-A2CSchema 'entraDomains.csv' 'Domain:fqdn AuthenticationType IsDefault IsInitial IsVerified IsRoot SupportedServices PasswordValidityDays:num'
Register-A2CSchema 'entraLicenses.csv' 'SkuPartNumber SkuId:guid AppliesTo CapabilityStatus Enabled:num Consumed:num Available:num Suspended:num Warning:num'

function New-A2CReportEntraTenant {
    $orgRows = [System.Collections.Generic.List[object]]::new()
    foreach ($o in @($script:A2C.Data['EntraOrg'])) {
        if ($null -eq $o) { continue }
        $vd = @($o.verifiedDomains | Where-Object { $null -ne $_ })
        $orgRows.Add([ordered]@{
                TenantId = [string]$o.id; DisplayName = [string]$o.displayName
                DefaultDomain = Join-A2C @($vd | Where-Object { $_.isDefault } | ForEach-Object { $_.name }); InitialDomain = Join-A2C @($vd | Where-Object { $_.isInitial } | ForEach-Object { $_.name })
                Country = [string]$o.countryLetterCode; CreatedDateTime = Format-A2CDate $o.createdDateTime; TenantType = [string]$o.tenantType
                OnPremisesSyncEnabled = ConvertTo-A2CYesNo $o.onPremisesSyncEnabled 'False'; LastDirectorySync = Format-A2CDate $o.onPremisesLastSyncDateTime
                VerifiedDomains = $vd.Count; TechnicalNotificationMails = Join-A2C $o.technicalNotificationMails
            })
    }
    Add-A2CRows 'entraTenant.csv' $orgRows
    $dom = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @($script:A2C.Data['EntraDomains'] | Sort-Object { [string]$_.id })) {
        if ($null -eq $d) { continue }
        $dom.Add([ordered]@{ Domain = [string]$d.id; AuthenticationType = [string]$d.authenticationType; IsDefault = ConvertTo-A2CYesNo $d.isDefault; IsInitial = ConvertTo-A2CYesNo $d.isInitial
                IsVerified = ConvertTo-A2CYesNo $d.isVerified; IsRoot = ConvertTo-A2CYesNo $d.isRoot; SupportedServices = Join-A2C $d.supportedServices ', '; PasswordValidityDays = $d.passwordValidityPeriodInDays })
    }
    Add-A2CRows 'entraDomains.csv' $dom
    $sk = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($script:A2C.Data['EntraSkus'] | Sort-Object { [string]$_.skuPartNumber })) {
        if ($null -eq $s) { continue }
        $en = [int]$s.prepaidUnits.enabled
        $sk.Add([ordered]@{ SkuPartNumber = [string]$s.skuPartNumber; SkuId = [string]$s.skuId; AppliesTo = [string]$s.appliesTo; CapabilityStatus = [string]$s.capabilityStatus
                Enabled = $en; Consumed = [int]$s.consumedUnits; Available = $en - [int]$s.consumedUnits; Suspended = [int]$s.prepaidUnits.suspended; Warning = [int]$s.prepaidUnits.warning })
    }
    Add-A2CRows 'entraLicenses.csv' $sk
    $au = [System.Collections.Generic.List[object]]::new()
    foreach ($x in @($script:A2C.Data['EntraAdminUnits'] | Where-Object { $null -ne $_ } | Sort-Object { [string]$_.displayName })) {
        $au.Add([ordered]@{ DisplayName = [string]$x.displayName; Description = [string]$x.description; Visibility = [string]$x.visibility
                MembershipType = $(if ($x.membershipType) { [string]$x.membershipType } else { 'Assigned' }); MembershipRule = [string]$x.membershipRule; Id = [string]$x.id })
    }
    Add-A2CRows 'entraAdministrativeUnits.csv' $au
    # directory settings: one row per value (group creation, naming policy, guest access, password protection...)
    $st = [System.Collections.Generic.List[object]]::new()
    foreach ($x in @($script:A2C.Data['EntraGroupSettings'] | Where-Object { $null -ne $_ } | Sort-Object { [string]$_.displayName })) {
        foreach ($v in @($x.values | Where-Object { $null -ne $_ })) {
            $st.Add([ordered]@{ Setting = [string]$x.displayName; Name = [string]$v.name; Value = [string]$v.value; TemplateId = [string]$x.templateId; Id = [string]$x.id })
        }
    }
    Add-A2CRows 'entraSettings.csv' $st
}

Register-A2CSchema 'entraUsers.csv' ('DisplayName:dn UserPrincipalName:upn Mail:upn UserType AccountEnabled CreatedDateTime:date CreationType ' +
    'ExternalUserState OnPremisesSync Department:text JobTitle:text CompanyName:text UsageLocation Licenses:num LastSignIn:date ' +
    'LastNonInteractiveSignIn:date DaysSinceLastSignIn:num SignInDataAvailable HasDirectoryRole HasAzureRBAC Id:guid')

function New-A2CReportEntraUsers {
    $rbac = Get-A2CRbacPrincipalSet
    $roles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($script:A2C.Data['EntraDirRoles'])) { if ($null -ne $x) { [void]$roles.Add($x.PrincipalId) } }
    $signIn = [bool]$script:A2C.Data['EntraSignIn']
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @($script:A2C.Data['EntraUsers'] | Sort-Object { [string]$_.userPrincipalName })) {
        if ($null -eq $u) { continue }
        $id = ([string]$u.id).ToLowerInvariant()
        $last = $null; $lastNi = $null; $days = $null
        if ($signIn -and $null -ne $u.signInActivity) {
            $last = ConvertTo-A2CUtc $u.signInActivity.lastSignInDateTime
            $lastNi = ConvertTo-A2CUtc $u.signInActivity.lastNonInteractiveSignInDateTime
            $latest = $last
            if ($null -ne $lastNi -and ($null -eq $latest -or $lastNi -gt $latest)) { $latest = $lastNi }
            if ($null -ne $latest) { $days = [int][math]::Floor(($script:A2C.Now - $latest).TotalDays) }
        }
        $rows.Add([ordered]@{
                DisplayName = [string]$u.displayName; UserPrincipalName = [string]$u.userPrincipalName; Mail = [string]$u.mail
                UserType = [string]$u.userType; AccountEnabled = ConvertTo-A2CYesNo $u.accountEnabled; CreatedDateTime = Format-A2CDate $u.createdDateTime
                CreationType = [string]$u.creationType; ExternalUserState = [string]$u.externalUserState; OnPremisesSync = ConvertTo-A2CYesNo $u.onPremisesSyncEnabled 'False'
                Department = [string]$u.department; JobTitle = [string]$u.jobTitle; CompanyName = [string]$u.companyName; UsageLocation = [string]$u.usageLocation
                Licenses = (Get-A2CCount @($u.assignedLicenses | Where-Object { $null -ne $_ })); LastSignIn = Format-A2CDate $last
                LastNonInteractiveSignIn = Format-A2CDate $lastNi; DaysSinceLastSignIn = $days; SignInDataAvailable = $signIn
                HasDirectoryRole = $(if ($null -ne $script:A2C.Data['EntraDirRoles']) { $roles.Contains($id) } else { $null })
                HasAzureRBAC = $(if ($null -ne $script:A2C.Data['RoleAssignments']) { $rbac.Contains($id) } else { $null }); Id = $id
            })
    }
    Add-A2CRows 'entraUsers.csv' $rows
}

Register-A2CSchema 'entraGroups.csv' ('DisplayName:dn Description:text Mail:upn GroupType Dynamic MembershipRule:text SecurityEnabled MailEnabled ' +
    'RoleAssignable OnPremisesSync Visibility CreatedDateTime:date Members:num UsedInAzureRBAC Id:guid Owners:list OwnerCount:num')
Register-A2CSchema 'entraGroupMembers.csv' 'GroupName:dn GroupId:guid MemberName:dn MemberType MemberUPN:upn MemberAppId:guid MemberId:guid'

function New-A2CReportEntraGroups {
    $rbac = Get-A2CRbacPrincipalSet
    $members = @{}
    foreach ($m in @($script:A2C.Data['EntraGroupMembers'])) { if ($null -ne $m) { $members[$m.GroupId] = [int]$members[$m.GroupId] + 1 } }
    $haveMembers = ($null -ne $script:A2C.Data['EntraGroupMembers'])
    $haveOwners = [bool]$script:A2C.Data['EntraGroupOwners']
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($g in @($script:A2C.Data['EntraGroups'] | Sort-Object { [string]$_.displayName })) {
        if ($null -eq $g) { continue }
        $types = @($g.groupTypes)
        $type = $(if ($types -contains 'Unified') { 'Microsoft 365' } elseif ($g.securityEnabled -and -not $g.mailEnabled) { 'Security' } elseif ($g.securityEnabled) { 'Mail-enabled security' } else { 'Distribution' })
        $rows.Add([ordered]@{
                DisplayName = [string]$g.displayName; Description = [string]$g.description; Mail = [string]$g.mail; GroupType = $type
                Dynamic = ($types -contains 'DynamicMembership'); MembershipRule = [string]$g.membershipRule; SecurityEnabled = ConvertTo-A2CYesNo $g.securityEnabled
                MailEnabled = ConvertTo-A2CYesNo $g.mailEnabled; RoleAssignable = ConvertTo-A2CYesNo $g.isAssignableToRole 'False'
                OnPremisesSync = ConvertTo-A2CYesNo $g.onPremisesSyncEnabled 'False'; Visibility = [string]$g.visibility; CreatedDateTime = Format-A2CDate $g.createdDateTime
                Members = $(if ($haveMembers) { [int]$members[[string]$g.id] } else { $null })
                UsedInAzureRBAC = $(if ($null -ne $script:A2C.Data['RoleAssignments']) { $rbac.Contains(([string]$g.id).ToLowerInvariant()) } else { $null }); Id = [string]$g.id
                Owners = $(if ($haveOwners) { Join-A2C @($g.owners | Where-Object { $null -ne $_ } | ForEach-Object { $(if ($_.userPrincipalName) { [string]$_.userPrincipalName } else { [string]$_.displayName }) }) } else { '' })
                OwnerCount = $(if ($haveOwners) { @($g.owners | Where-Object { $null -ne $_ }).Count } else { $null })
            })
    }
    Add-A2CRows 'entraGroups.csv' $rows
}

function New-A2CReportEntraGroupMembers {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($m in @($script:A2C.Data['EntraGroupMembers'])) {
        if ($null -eq $m) { continue }
        $x = $m.Member
        $rows.Add([ordered]@{ GroupName = $m.GroupName; GroupId = $m.GroupId; MemberName = [string]$x.displayName
                MemberType = (([string]$x.'@odata.type') -replace '^#microsoft\.graph\.', ''); MemberUPN = [string]$x.userPrincipalName; MemberAppId = [string]$x.appId; MemberId = [string]$x.id })
    }
    Add-A2CRows 'entraGroupMembers.csv' $rows
}

Register-A2CSchema 'entraApplications.csv' ('DisplayName:known AppId:guid ObjectId:guid CreatedDateTime:date SignInAudience MultiTenant ' +
    'PublisherDomain:fqdn Owners:list OwnerCount:num Secrets:num Certificates:num NextCredentialExpiry:date CredentialStatus ' +
    'RequiredApiPermissions:num RedirectUris:num IdentifierUris:list Notes:text')
Register-A2CSchema 'entraServicePrincipals.csv' ('DisplayName:known AppId:guid ObjectId:guid Type Publisher PublisherName:known Enabled ' +
    'AppRoleAssignmentRequired SsoMode Secrets:num Certificates:num NextCredentialExpiry:date HasAzureRBAC HighRiskPermissions:num Tags')
Register-A2CSchema 'managedIdentities.csv' ('DisplayName:name Kind AppId:guid ObjectId:guid AzureResourceId:id ResourceType ResourceExists ' +
    'RoleAssignments:num')
Register-A2CSchema 'credentials.csv' ('OwnerType OwnerName:known AppId:guid ObjectId:guid CredentialType CredentialName:text KeyId:guid ' +
    'StartDateTime:date EndDateTime:date DaysToExpiry:num Status LifetimeDays:num')
Register-A2CSchema 'appPermissions.csv' ('ClientName:known ClientAppId:guid ClientObjectId:guid ClientPublisher PermissionType ResourceName ' +
    'ResourceAppId Permission ConsentType GrantedTo:dn Risk CreatedDateTime:date')

function Get-A2CCredentialInfo {
    # Rows for credentials.csv + summary for one application / service principal.
    param($Obj, [string] $OwnerType, $Rows)
    $next = $null; $secrets = 0; $certs = 0; $expired = 0
    foreach ($set in @(@{ L = @($Obj.passwordCredentials); T = 'Secret' }, @{ L = @($Obj.keyCredentials); T = 'Certificate' })) {
        foreach ($c in $set.L) {
            if ($null -eq $c) { continue }
            if ($set.T -eq 'Secret') { $secrets++ } else { $certs++ }
            $end = ConvertTo-A2CUtc $c.endDateTime
            $start = ConvertTo-A2CUtc $c.startDateTime
            $days = Get-A2CDaysUntil $end
            if ($null -ne $days -and $days -lt 0) { $expired++ }
            if ($null -ne $days -and $days -ge 0 -and ($null -eq $next -or $end -lt $next)) { $next = $end }
            $Rows.Add([ordered]@{
                    OwnerType = $OwnerType; OwnerName = [string]$Obj.displayName; AppId = [string]$Obj.appId; ObjectId = [string]$Obj.id; CredentialType = $set.T
                    CredentialName = [string]$c.displayName; KeyId = [string]$c.keyId; StartDateTime = Format-A2CDate $start; EndDateTime = Format-A2CDate $end
                    DaysToExpiry = $days; Status = Get-A2CCredentialStatus $days
                    LifetimeDays = $(if ($null -ne $start -and $null -ne $end) { [int][math]::Round(($end - $start).TotalDays) } else { $null })
                })
        }
    }
    $status = 'No credentials'
    if ($secrets + $certs -gt 0) { $status = $(if ($null -eq $next) { 'Expired' } else { Get-A2CCredentialStatus (Get-A2CDaysUntil $next) }) }
    return [pscustomobject]@{ Secrets = $secrets; Certificates = $certs; Next = $next; Status = $status; Expired = $expired }
}

function New-A2CReportEntraApps {
    $rbac = Get-A2CRbacPrincipalSet
    $creds = [System.Collections.Generic.List[object]]::new()
    $apps = [System.Collections.Generic.List[object]]::new()
    $haveOwners = [bool]$script:A2C.Data['EntraAppOwners']
    foreach ($a in @($script:A2C.Data['EntraApps'] | Sort-Object { [string]$_.displayName })) {
        if ($null -eq $a) { continue }
        $ci = Get-A2CCredentialInfo -Obj $a -OwnerType 'Application' -Rows $creds
        $own = @($a.owners | Where-Object { $null -ne $_ })
        $redirects = @($a.web.redirectUris) + @($a.spa.redirectUris) + @($a.publicClient.redirectUris) | Where-Object { $_ }
        $perm = 0
        foreach ($rra in @($a.requiredResourceAccess)) { if ($null -ne $rra) { $perm += @($rra.resourceAccess | Where-Object { $null -ne $_ }).Count } }
        $apps.Add([ordered]@{
                DisplayName = [string]$a.displayName; AppId = [string]$a.appId; ObjectId = [string]$a.id; CreatedDateTime = Format-A2CDate $a.createdDateTime
                SignInAudience = [string]$a.signInAudience; MultiTenant = ([string]$a.signInAudience -ne 'AzureADMyOrg' -and [string]$a.signInAudience -ne '')
                PublisherDomain = [string]$a.publisherDomain; Owners = $(if ($haveOwners) { Join-A2C @($own | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) } else { 'n/a' })
                OwnerCount = $(if ($haveOwners) { $own.Count } else { $null }); Secrets = $ci.Secrets; Certificates = $ci.Certificates
                NextCredentialExpiry = Format-A2CDate $ci.Next; CredentialStatus = $ci.Status; RequiredApiPermissions = $perm
                RedirectUris = @($redirects).Count; IdentifierUris = Join-A2C $a.identifierUris; Notes = [string]$a.notes
            })
    }
    Add-A2CRows 'entraApplications.csv' $apps
    # service principals and managed identities
    $perms = @($script:A2C.Data['EntraPermissions'])
    $risky = @{}
    foreach ($p in $perms) { if ($null -ne $p -and (Get-A2CPermissionRisk $p.Permission)) { $risky[$p.ClientId] = [int]$risky[$p.ClientId] + 1 } }
    $sps = [System.Collections.Generic.List[object]]::new()
    $mis = [System.Collections.Generic.List[object]]::new()
    $raCount = @{}
    foreach ($x in @($script:A2C.Data['RoleAssignments'])) { if ($null -ne $x) { $raCount[$x.PrincipalId] = [int]$raCount[$x.PrincipalId] + 1 } }
    $inScope = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in @($script:A2C.Data['Subscriptions'])) { if ($null -ne $s) { [void]$inScope.Add($s.Id) } }
    foreach ($sp in @($script:A2C.Data['EntraSPs'] | Sort-Object { [string]$_.displayName })) {
        if ($null -eq $sp) { continue }
        $id = ([string]$sp.id).ToLowerInvariant()
        if ([string]$sp.servicePrincipalType -eq 'ManagedIdentity') {
            $alt = @($sp.alternativeNames)
            $rid = [string](@($alt | Where-Object { [string]$_ -like '/subscriptions/*' }) | Select-Object -First 1)
            $exists = 'Unknown'
            if ($rid) {
                $sub = Get-A2CSubIdFromId $rid
                if ($null -eq $script:A2C.Data['ResById']) { $exists = 'Unknown (resources not collected)' }
                elseif (-not $inScope.Contains($sub)) { $exists = 'Out of scope' }
                elseif ($null -ne (Get-A2CResource $rid)) { $exists = 'Yes' }
                elseif ((Get-A2CTypeFromId $rid) -and $null -ne $script:A2C.Data['ResById']) { $exists = 'No (resource deleted?)' }
            }
            $mis.Add([ordered]@{
                    DisplayName = [string]$sp.displayName; Kind = $(if ($alt -contains 'isExplicit=True') { 'User-assigned' } else { 'System-assigned' })
                    AppId = [string]$sp.appId; ObjectId = $id; AzureResourceId = $rid; ResourceType = Get-A2CTypeCased -Id $rid -Fallback ''
                    ResourceExists = $exists; RoleAssignments = $(if ($null -ne $script:A2C.Data['RoleAssignments']) { [int]$raCount[$id] } else { $null })
                })
            continue
        }
        $ci = Get-A2CCredentialInfo -Obj $sp -OwnerType 'ServicePrincipal' -Rows $creds
        $sps.Add([ordered]@{
                DisplayName = [string]$sp.displayName; AppId = [string]$sp.appId; ObjectId = $id; Type = [string]$sp.servicePrincipalType
                Publisher = Get-A2CSpPublisher $sp; PublisherName = [string]$sp.publisherName; Enabled = ConvertTo-A2CYesNo $sp.accountEnabled
                AppRoleAssignmentRequired = ConvertTo-A2CYesNo $sp.appRoleAssignmentRequired; SsoMode = [string]$sp.preferredSingleSignOnMode
                Secrets = $ci.Secrets; Certificates = $ci.Certificates; NextCredentialExpiry = Format-A2CDate $ci.Next
                HasAzureRBAC = $(if ($null -ne $script:A2C.Data['RoleAssignments']) { $rbac.Contains($id) } else { $null })
                HighRiskPermissions = [int]$risky[$id]; Tags = Join-A2C $sp.tags ', '
            })
    }
    Add-A2CRows 'entraServicePrincipals.csv' $sps
    Add-A2CRows 'managedIdentities.csv' $mis
    Add-A2CRows 'credentials.csv' @($creds | Sort-Object @{ Expression = { if ($null -eq $_['DaysToExpiry']) { 99999 } else { [int]$_['DaysToExpiry'] } } })
    $spById = $script:A2C.Data['EntraSPById']; if ($null -eq $spById) { $spById = @{} }
    $userById = @{}
    foreach ($u in @($script:A2C.Data['EntraUsers'])) { if ($null -ne $u) { $userById[([string]$u.id).ToLowerInvariant()] = $u } }
    $pr = [System.Collections.Generic.List[object]]::new()
    foreach ($p in @($perms | Sort-Object Type, ClientName, Permission)) {
        if ($null -eq $p) { continue }
        $client = $spById[$p.ClientId]
        $grantee = ''
        if ($p.PrincipalId) {
            $u = $userById[([string]$p.PrincipalId).ToLowerInvariant()]
            $grantee = $(if ($null -ne $u) { [string]$u.userPrincipalName } else { $p.PrincipalId })
        }
        $pr.Add([ordered]@{
                ClientName = $(if ($p.ClientName) { $p.ClientName } elseif ($null -ne $client) { [string]$client.displayName } else { '' })
                ClientAppId = $(if ($null -ne $client) { [string]$client.appId } else { '' }); ClientObjectId = $p.ClientId
                ClientPublisher = $(if ($null -ne $client) { Get-A2CSpPublisher $client } else { '' }); PermissionType = $p.Type
                ResourceName = $p.ResourceName; ResourceAppId = $p.ResourceAppId; Permission = $p.Permission; ConsentType = $p.ConsentType
                GrantedTo = $grantee; Risk = Get-A2CPermissionRisk $p.Permission; CreatedDateTime = Format-A2CDate $p.Created
            })
    }
    Add-A2CRows 'appPermissions.csv' $pr
}

Register-A2CSchema 'directoryRoles.csv' ('RoleName IsBuiltIn IsPrivilegedRole PrincipalName:dn PrincipalType PrincipalUPN:upn PrincipalAppId:guid ' +
    'PrincipalId:guid IsGuest Scope:note AssignmentType Source')

function New-A2CReportEntraRoles {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($x in @($script:A2C.Data['EntraDirRoles'] | Sort-Object RoleName, PrincipalName)) {
        if ($null -eq $x) { continue }
        $rows.Add([ordered]@{
                RoleName = $x.RoleName; IsBuiltIn = $x.IsBuiltIn; IsPrivilegedRole = ($script:A2CPrivilegedDirectoryRoles -contains $x.RoleName)
                PrincipalName = $x.PrincipalName; PrincipalType = $x.PrincipalType; PrincipalUPN = $x.PrincipalUPN; PrincipalAppId = $x.PrincipalAppId
                PrincipalId = $x.PrincipalId; IsGuest = ([string]$x.PrincipalUPN -match '#EXT#'); Scope = $x.Scope; AssignmentType = 'Active'; Source = $x.Source
            })
    }
    Add-A2CRows 'directoryRoles.csv' $rows
    # custom directory roles with what they allow (the built-in roles are the same in every tenant)
    $n = @{}
    foreach ($x in @($script:A2C.Data['EntraDirRoles'])) { if ($null -ne $x) { $n[[string]$x.RoleName] = [int]$n[[string]$x.RoleName] + 1 } }
    $defs = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @($script:A2C.Data['EntraRoleDefs'] | Where-Object { $null -ne $_ -and $_.isBuiltIn -eq $false } | Sort-Object { [string]$_.displayName })) {
        $defs.Add([ordered]@{ DisplayName = [string]$d.displayName; Description = [string]$d.description; IsEnabled = $d.isEnabled
                Permissions = Join-A2C @($d.rolePermissions | ForEach-Object { $_.allowedResourceActions }); AssignableScopes = Join-A2C @($d.resourceScopes)
                Assignments = [int]$n[[string]$d.displayName]; TemplateId = [string]$d.templateId; Id = [string]$d.id })
    }
    Add-A2CRows 'entraRoleDefinitions.csv' $defs
}

# ---- Entra ID: administrative units, directory settings, policies, application assignments ------------------
Register-A2CSchema 'entraRoleDefinitions.csv' 'DisplayName:known Description:text IsEnabled Permissions AssignableScopes Assignments:num TemplateId:guid Id:guid'
Register-A2CSchema 'entraAdministrativeUnits.csv' 'DisplayName:dn Description:text Visibility MembershipType MembershipRule:text Id:guid'
Register-A2CSchema 'entraSettings.csv' 'Setting Name Value:text TemplateId:guid Id:guid'
Register-A2CSchema 'entraConditionalAccess.csv' ('DisplayName:known State IncludeUsers:note ExcludeUsers:note IncludeApplications:note ExcludeApplications:note ' +
    'ClientAppTypes Platforms Locations:note UserRisk SignInRisk GrantControls SessionControls CreatedDateTime:date ModifiedDateTime:date Id:guid')
Register-A2CSchema 'entraNamedLocations.csv' 'DisplayName:known Type IsTrusted IpRanges:ipList Countries IncludeUnknownCountries CreatedDateTime:date ModifiedDateTime:date Id:guid'
Register-A2CSchema 'entraPolicySettings.csv' 'Policy Name:known Setting Value:text'
Register-A2CSchema 'entraAppAssignments.csv' 'Application:known AppId:guid PrincipalName:dn PrincipalType AppRole AssignedOn:date PrincipalId:guid ApplicationObjectId:guid'

function Add-A2CSettingRows {
    # Flattens an object into Setting/Value rows with dotted names ("defaultUserRolePermissions.allowedToCreateApps").
    # Lists of plain values are joined; lists of objects are numbered, or named by their id.
    param($Rows, [string] $Policy, [string] $Name, $Value, [string] $Prefix = '', [int] $Depth = 0)
    if ($null -eq $Value) { return }
    if ($Value -is [string] -or $Value -is [valuetype]) { $Rows.Add([ordered]@{ Policy = $Policy; Name = $Name; Setting = $Prefix; Value = (Format-A2CCell $Value) }); return }
    if ($Depth -ge 6) { $Rows.Add([ordered]@{ Policy = $Policy; Name = $Name; Setting = $Prefix; Value = (ConvertTo-A2CJsonString $Value) }); return }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [System.Collections.IDictionary])) {
        $list = @($Value)
        if (@($list | Where-Object { $null -ne $_ -and -not ($_ -is [string] -or $_ -is [valuetype]) }).Count -eq 0) {
            if ($list.Count -gt 0) { $Rows.Add([ordered]@{ Policy = $Policy; Name = $Name; Setting = $Prefix; Value = (Join-A2C $list ', ') }) }
            return
        }
        $i = 0
        foreach ($x in $list) {
            $i++
            $key = [string]$i
            if ($null -ne $x -and $null -ne $x.PSObject.Properties['id'] -and $x.id) { $key = [string]$x.id }
            Add-A2CSettingRows $Rows $Policy $Name $x ($Prefix + '[' + $key + ']') ($Depth + 1)
        }
        return
    }
    foreach ($p in $Value.PSObject.Properties) {
        if ($p.Name -like '@odata.*' -or ($Depth -eq 0 -and @('id', 'displayName', 'description') -contains $p.Name)) { continue }
        Add-A2CSettingRows $Rows $Policy $Name $p.Value $(if ($Prefix) { $Prefix + '.' + $p.Name } else { $p.Name }) ($Depth + 1)
    }
}

function Get-A2CCaTargetText {
    # "All", or how many users, groups, roles (applications) a Conditional Access policy names; the IDs are in the snapshot
    param($Target, [string] $Prefix)
    if ($null -eq $Target) { return '' }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($k in @('Users', 'Groups', 'Roles', 'Applications', 'UserActions')) {
        $member = $Target.PSObject.Properties[$Prefix + $k]
        $v = @($(if ($null -ne $member) { $member.Value }) | Where-Object { $_ })
        if ($v.Count -eq 0) { continue }
        $named = @($v | Where-Object { $_ -notmatch '^[0-9a-fA-F]{8}-' })
        if ($named.Count -gt 0) { $parts.Add((Join-A2C $named ', ')) }
        $ids = $v.Count - $named.Count
        if ($ids -gt 0) { $parts.Add(('{0} {1}' -f $ids, $k.ToLowerInvariant())) }
    }
    $guests = $Target.PSObject.Properties[$Prefix + 'GuestsOrExternalUsers']
    if ($null -ne $guests -and $null -ne $guests.Value) { $parts.Add('guests or external users') }
    return (Join-A2C $parts '; ')
}

function New-A2CReportEntraPolicies {
    $ca = [System.Collections.Generic.List[object]]::new()
    $loc = [System.Collections.Generic.List[object]]::new()
    $set = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @($script:A2C.Data['EntraPolicies'])) {
        if ($null -eq $e) { continue }
        $x = $e.Item
        if ($e.Kind -eq 'Conditional Access policy') {
            $c = $x.conditions; $g = $x.grantControls; $s = $x.sessionControls
            $grant = ''
            if ($null -ne $g) {
                $what = @(@($g.builtInControls) + @($(if ($null -ne $g.authenticationStrength) { 'authentication strength: ' + [string]$g.authenticationStrength.displayName })) +
                    @($(if (@($g.termsOfUse | Where-Object { $_ }).Count -gt 0) { 'terms of use' })) + @($g.customAuthenticationFactors) | Where-Object { $_ })
                $grant = Join-A2C $what (' ' + [string]$g.operator + ' ')
            }
            $session = ''
            if ($null -ne $s) { $session = Join-A2C @($s.PSObject.Properties | Where-Object { $null -ne $_.Value -and $_.Name -notlike '@odata*' } | ForEach-Object { $_.Name }) ', ' }
            $ca.Add([ordered]@{ DisplayName = [string]$x.displayName; State = [string]$x.state
                    IncludeUsers = Get-A2CCaTargetText $c.users 'include'; ExcludeUsers = Get-A2CCaTargetText $c.users 'exclude'
                    IncludeApplications = Get-A2CCaTargetText $c.applications 'include'; ExcludeApplications = Get-A2CCaTargetText $c.applications 'exclude'
                    ClientAppTypes = Join-A2C $c.clientAppTypes ', '
                    Platforms = $(if ($null -ne $c.platforms) { Join-A2C $c.platforms.includePlatforms ', ' } else { '' })
                    Locations = $(if ($null -ne $c.locations) { 'include: ' + (Join-A2C $c.locations.includeLocations ', ') + $(if (@($c.locations.excludeLocations | Where-Object { $_ }).Count) { '; exclude: ' + (Join-A2C $c.locations.excludeLocations ', ') } else { '' }) } else { '' })
                    UserRisk = Join-A2C $c.userRiskLevels ', '; SignInRisk = Join-A2C $c.signInRiskLevels ', '; GrantControls = $grant; SessionControls = $session
                    CreatedDateTime = Format-A2CDate $x.createdDateTime; ModifiedDateTime = Format-A2CDate $x.modifiedDateTime; Id = [string]$x.id })
        }
        elseif ($e.Kind -eq 'Named location') {
            $isIp = ([string]$x.'@odata.type' -match 'ipNamedLocation') -or ($null -ne $x.ipRanges)
            $loc.Add([ordered]@{ DisplayName = [string]$x.displayName; Type = $(if ($isIp) { 'IP ranges' } else { 'Countries' }); IsTrusted = $x.isTrusted
                    IpRanges = Join-A2C @($x.ipRanges | ForEach-Object { [string]$_.cidrAddress }); Countries = Join-A2C $x.countriesAndRegions ', '
                    IncludeUnknownCountries = $x.includeUnknownCountriesAndRegions; CreatedDateTime = Format-A2CDate $x.createdDateTime
                    ModifiedDateTime = Format-A2CDate $x.modifiedDateTime; Id = [string]$x.id })
        }
        else {
            if ($e.Kind -eq 'Authentication strength' -and [string]$x.policyType -eq 'builtIn') { continue }
            $name = [string]$x.displayName
            if (-not $name) { $name = [string]$x.id }
            Add-A2CSettingRows $set $e.Kind $name $x
        }
    }
    Add-A2CRows 'entraConditionalAccess.csv' $ca
    Add-A2CRows 'entraNamedLocations.csv' $loc
    Add-A2CRows 'entraPolicySettings.csv' $set
}

function New-A2CReportEntraAppAssignments {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($a in @($script:A2C.Data['EntraAppAssignments'] | Where-Object { $null -ne $_ } | Sort-Object App, PrincipalName)) {
        $rows.Add([ordered]@{ Application = $a.App; AppId = $a.AppId; PrincipalName = $a.PrincipalName; PrincipalType = $a.PrincipalType; AppRole = $a.Role
                AssignedOn = Format-A2CDate $a.Created; PrincipalId = $a.PrincipalId; ApplicationObjectId = $a.SpId })
    }
    Add-A2CRows 'entraAppAssignments.csv' $rows
}

# ---- Governance: Defender for Cloud plans, Azure Lighthouse --------------------------------------------------
Register-A2CSchema 'defenderPlans.csv' 'SubscriptionName:sub Plan Tier SubPlan Extensions EnabledOn:date FreeTrialRemaining Deprecated ReplacedBy Id:id'
Register-A2CSchema 'lighthouse.csv' ('SubscriptionName:sub Scope:id ScopeType Offer:known ManagedByTenantId:guid ManagedByTenantName:dn Authorizations:text ' +
    'EligibleAuthorizations:text ProvisioningState DefinitionId:id Id:id')

function New-A2CReportDefender {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($x in @($script:A2C.Data['DefenderPlans'] | Where-Object { $null -ne $_ } | Sort-Object { Get-A2CSubName ([string]$_.subscriptionId) }, { [string]$_.name })) {
        $p = Get-A2CProps $x
        $rows.Add([ordered]@{ SubscriptionName = Get-A2CSubName ([string]$x.subscriptionId); Plan = [string]$x.name; Tier = [string]$p.pricingTier; SubPlan = [string]$p.subPlan
                Extensions = Join-A2C @($p.extensions | Where-Object { $null -ne $_ -and [string]$_.isEnabled -eq 'True' } | ForEach-Object { [string]$_.name }) ', '
                EnabledOn = Format-A2CDate $p.enablementTime; FreeTrialRemaining = [string]$p.freeTrialRemainingTime; Deprecated = $p.deprecated
                ReplacedBy = Join-A2C $p.replacedBy ', '; Id = [string]$x.id })
    }
    Add-A2CRows 'defenderPlans.csv' $rows
}

function New-A2CReportLighthouse {
    $roleDefs = $script:A2C.Data['RoleDefs']
    $defs = @{}
    $all = @($script:A2C.Data['Lighthouse'] | Where-Object { $null -ne $_ })
    foreach ($x in $all) { if ([string]$x.type -like '*registrationdefinitions') { $defs[([string]$x.id).ToLowerInvariant()] = $x } }
    $text = {
        # "name (principal ID): role"; the role name when the RBAC report collected the role definitions
        param($List)
        Join-A2C @($List | Where-Object { $null -ne $_ } | ForEach-Object {
                $g = ([string]$_.roleDefinitionId).ToLowerInvariant()
                $rd = $null
                if ($null -ne $roleDefs) { $rd = $roleDefs[$g] }
                ('{0} ({1}): {2}' -f [string]$_.principalIdDisplayName, [string]$_.principalId, $(if ($null -ne $rd) { $rd.RoleName } else { $g }))
            })
    }
    $used = [System.Collections.Generic.HashSet[string]]::new()
    $rows = [System.Collections.Generic.List[object]]::new()
    $row = {
        param($Item, $Def, [string] $State)
        $id = [string]$Item.id
        $ix = $id.IndexOf('/providers/Microsoft.ManagedServices/', [StringComparison]::OrdinalIgnoreCase)
        $scope = $(if ($ix -gt 0) { $id.Substring(0, $ix) } else { '' })
        $dp = $(if ($null -ne $Def) { Get-A2CProps $Def } else { $null })
        [ordered]@{ SubscriptionName = Get-A2CSubName ([string]$Item.subscriptionId); Scope = $scope; ScopeType = Get-A2CScopeType $scope
            Offer = $(if ($null -ne $dp) { [string]$dp.registrationDefinitionName } else { '' }); ManagedByTenantId = $(if ($null -ne $dp) { [string]$dp.managedByTenantId } else { '' })
            ManagedByTenantName = $(if ($null -ne $dp) { [string]$dp.managedByTenantName } else { '' })
            Authorizations = $(if ($null -ne $dp) { & $text $dp.authorizations } else { '' }); EligibleAuthorizations = $(if ($null -ne $dp) { & $text $dp.eligibleAuthorizations } else { '' })
            ProvisioningState = $State; DefinitionId = $(if ($null -ne $Def) { [string]$Def.id } else { '' }); Id = $id }
    }
    foreach ($x in $all) {
        if ([string]$x.type -notlike '*registrationassignments') { continue }
        $p = Get-A2CProps $x
        $k = ([string]$p.registrationDefinitionId).ToLowerInvariant()
        [void]$used.Add($k)
        $rows.Add((& $row $x $defs[$k] ([string]$p.provisioningState)))
    }
    foreach ($k in $defs.Keys) { if (-not $used.Contains($k)) { $rows.Add((& $row $defs[$k] $defs[$k] 'Definition without an assignment in scope')) } }
    Add-A2CRows 'lighthouse.csv' $rows
}

# ---- Typed reports from a table ($A2CSpecReports) ---------------------------------------------------------------
# One entry per CSV file. Rows: every resource of the types in Type; with Each one row per element of that list of
# the resource; with Child the child resources of that type (read by the ChildResources dataset). Every file starts
# with SubscriptionName, ResourceGroup, [the parent], Name, [Location] and ends with Id.
# Columns: 'Name[:kind]=path[|how]'. The path is below "properties"; "@" starts at the object itself (@sku.name,
# @zones), "^" at the properties of the parent resource of an element ("^@" at the parent itself). Lists on the way
# are walked through and the values joined. how: name (last segment of an ID), count, json, keys, any.
# A file is written only when it has rows.
function Get-A2CPathValues {
    param($Object, [string] $Path)
    $cur = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Object) { $cur.Add($Object) }
    foreach ($name in $Path.Split('.')) {
        $next = [System.Collections.Generic.List[object]]::new()
        foreach ($o in $cur) {
            if ($null -eq $o -or $o -is [string] -or $o -is [valuetype]) { continue }
            $v = $o.$name
            if ($null -eq $v) { continue }
            if ($v -is [array] -or $v -is [System.Collections.IList]) { foreach ($x in $v) { if ($null -ne $x) { $next.Add($x) } } } else { $next.Add($v) }
        }
        $cur = $next
        if ($cur.Count -eq 0) { break }
    }
    return , $cur
}

function ConvertTo-A2CSpecColumn {
    param([string] $Token)
    $eq = $Token.IndexOf('=')
    $head = $Token.Substring(0, $eq); $path = $Token.Substring($eq + 1)
    $name = $head; $kind = 'p'
    $c = $head.IndexOf(':')
    if ($c -gt 0) { $name = $head.Substring(0, $c); $kind = $head.Substring($c + 1) }
    $how = ''
    $bar = $path.LastIndexOf('|')
    if ($bar -gt 0) { $how = $path.Substring($bar + 1); $path = $path.Substring(0, $bar) }
    $scope = ''
    if ($path.StartsWith('^@')) { $scope = '^@'; $path = $path.Substring(2) }
    elseif ($path.StartsWith('^')) { $scope = '^'; $path = $path.Substring(1) }
    elseif ($path.StartsWith('@')) { $scope = '@'; $path = $path.Substring(1) }
    return [pscustomobject]@{ Name = $name; Kind = $kind; Path = $path; How = $how; Scope = $scope }
}

function Get-A2CSpecValue {
    param($Col, $Root, $Props, $ParentRoot, $ParentProps)
    $from = $Props
    switch ($Col.Scope) { '@' { $from = $Root } '^' { $from = $ParentProps } '^@' { $from = $ParentRoot } }
    $v = Get-A2CPathValues $from $Col.Path
    switch ($Col.How) {
        'count' { return $v.Count }
        'any' { return ($v.Count -gt 0) }
        'name' { return (Join-A2C @($v | ForEach-Object { Get-A2CNameFromId ([string]$_) })) }
        'json' { if ($v.Count -eq 0) { return '' } elseif ($v.Count -eq 1) { return (ConvertTo-A2CJsonString $v[0]) } else { return (ConvertTo-A2CJsonString $v.ToArray()) } }
        'keys' { return (Join-A2C @($v | ForEach-Object { $_.PSObject.Properties | Where-Object { $null -ne $_.Value -and @($_.Value).Count -gt 0 } | ForEach-Object { $_.Name } }) ', ') }
    }
    if ($v.Count -eq 0) { return '' }
    if ($v.Count -eq 1 -and ($v[0] -is [string] -or $v[0] -is [valuetype])) { return $v[0] }
    return (Join-A2C @($v | ForEach-Object { if ($_ -is [string] -or $_ -is [valuetype]) { Format-A2CCell $_ } else { ConvertTo-A2CJsonString $_ } }))
}

$script:A2CSpecReports = @(
    # ---- load balancers ----
    @{ Report = 'LoadBalancers'; File = 'loadBalancers.csv'; Type = 'microsoft.network/loadbalancers'; Columns = @('Sku=@sku.name', 'Tier=@sku.tier', 'Frontends:num=frontendIPConfigurations|count',
            'PrivateIPs:ipList=frontendIPConfigurations.properties.privateIPAddress', 'PublicIPs:list=frontendIPConfigurations.properties.publicIPAddress.id|name',
            'Subnets:idList=frontendIPConfigurations.properties.subnet.id', 'BackendPools:list=backendAddressPools.name', 'Rules:num=loadBalancingRules|count', 'InboundNatRules:num=inboundNatRules|count',
            'OutboundRules:num=outboundRules|count', 'Probes:list=probes.name', 'Zones=frontendIPConfigurations.zones') }
    @{ Report = 'LoadBalancers'; File = 'loadBalancerFrontends.csv'; Type = 'microsoft.network/loadbalancers'; Each = 'frontendIPConfigurations'; Parent = 'LoadBalancer'; Columns = @('PrivateIP:ip=privateIPAddress',
            'Allocation=privateIPAllocationMethod', 'Subnet:id=subnet.id', 'PublicIP:id=publicIPAddress.id', 'PublicIPPrefix:id=publicIPPrefix.id', 'Zones=@zones', 'Rules:list=loadBalancingRules.id|name', 'Sku=^@sku.name') }
    @{ Report = 'LoadBalancers'; File = 'loadBalancerRules.csv'; Type = 'microsoft.network/loadbalancers'; Each = 'loadBalancingRules'; Parent = 'LoadBalancer'; Columns = @('Protocol=protocol', 'FrontendPort:num=frontendPort',
            'BackendPort:num=backendPort', 'Frontend:name=frontendIPConfiguration.id|name', 'BackendPool:name=backendAddressPool.id|name', 'Probe:name=probe.id|name', 'IdleTimeoutMinutes:num=idleTimeoutInMinutes',
            'FloatingIP=enableFloatingIP', 'TcpReset=enableTcpReset', 'LoadDistribution=loadDistribution', 'DisableOutboundSnat=disableOutboundSnat') }
    @{ Report = 'LoadBalancers'; File = 'loadBalancerProbes.csv'; Type = 'microsoft.network/loadbalancers'; Each = 'probes'; Parent = 'LoadBalancer'; Columns = @('Protocol=protocol', 'Port:num=port', 'RequestPath=requestPath',
            'IntervalSeconds:num=intervalInSeconds', 'NumberOfProbes:num=numberOfProbes', 'ProbeThreshold:num=probeThreshold') }
    # ---- application gateways and WAF policies ----
    @{ Report = 'AppGateways'; File = 'applicationGateways.csv'; Type = 'microsoft.network/applicationgateways'; Columns = @('Sku=sku.name', 'Tier=sku.tier', 'Capacity:num=sku.capacity', 'AutoscaleMin:num=autoscaleConfiguration.minCapacity',
            'AutoscaleMax:num=autoscaleConfiguration.maxCapacity', 'Zones=@zones', 'Subnet:id=gatewayIPConfigurations.properties.subnet.id', 'PrivateIPs:ipList=frontendIPConfigurations.properties.privateIPAddress',
            'PublicIPs:idList=frontendIPConfigurations.properties.publicIPAddress.id', 'WafEnabled=webApplicationFirewallConfiguration.enabled', 'WafMode=webApplicationFirewallConfiguration.firewallMode',
            'WafPolicy:id=firewallPolicy.id', 'Http2=enableHttp2', 'SslPolicy=sslPolicy.policyName', 'MinTlsVersion=sslPolicy.minProtocolVersion', 'SslCertificates:list=sslCertificates.name',
            'Listeners:num=httpListeners|count', 'Rules:num=requestRoutingRules|count', 'BackendPools:num=backendAddressPools|count', 'OperationalState=operationalState', 'IdentityType=@identity.type') }
    @{ Report = 'AppGateways'; File = 'applicationGatewayListeners.csv'; Type = 'microsoft.network/applicationgateways'; Each = 'httpListeners'; Parent = 'ApplicationGateway'; Columns = @('Protocol=protocol', 'HostName:fqdn=hostName',
            'HostNames:fqdn=hostNames', 'Port:name=frontendPort.id|name', 'Frontend:name=frontendIPConfiguration.id|name', 'SslCertificate:name=sslCertificate.id|name', 'RequireSni=requireServerNameIndication',
            'WafPolicy:id=firewallPolicy.id') }
    @{ Report = 'AppGateways'; File = 'applicationGatewayRules.csv'; Type = 'microsoft.network/applicationgateways'; Each = 'requestRoutingRules'; Parent = 'ApplicationGateway'; Columns = @('RuleType=ruleType', 'Priority:num=priority',
            'Listener:name=httpListener.id|name', 'BackendPool:name=backendAddressPool.id|name', 'BackendSettings:name=backendHttpSettings.id|name', 'UrlPathMap:name=urlPathMap.id|name',
            'Redirect:name=redirectConfiguration.id|name', 'RewriteRuleSet:name=rewriteRuleSet.id|name') }
    @{ Report = 'AppGateways'; File = 'applicationGatewayBackends.csv'; Type = 'microsoft.network/applicationgateways'; Each = 'backendAddressPools'; Parent = 'ApplicationGateway'; Columns = @('Fqdns:fqdn=backendAddresses.fqdn',
            'IpAddresses:ipList=backendAddresses.ipAddress', 'NetworkInterfaces:num=backendIPConfigurations|count') }
    @{ Report = 'AppGateways'; File = 'applicationGatewayBackendSettings.csv'; Type = 'microsoft.network/applicationgateways'; Each = 'backendHttpSettingsCollection'; Parent = 'ApplicationGateway'; Columns = @('Protocol=protocol',
            'Port:num=port', 'CookieAffinity=cookieBasedAffinity', 'RequestTimeoutSeconds:num=requestTimeout', 'HostName:fqdn=hostName', 'PickHostNameFromBackend=pickHostNameFromBackendAddress', 'Path=path',
            'Probe:name=probe.id|name', 'ConnectionDrainingSeconds:num=connectionDraining.drainTimeoutInSec') }
    @{ Report = 'AppGateways'; File = 'wafPolicies.csv'; Type = 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies'; Columns = @('State=policySettings.state', 'Mode=policySettings.mode',
            'RequestBodyCheck=policySettings.requestBodyCheck', 'ManagedRuleSets=managedRules.managedRuleSets.ruleSetType', 'RuleSetVersions=managedRules.managedRuleSets.ruleSetVersion', 'Exclusions:num=managedRules.exclusions|count',
            'CustomRules:list=customRules.name', 'ApplicationGateways:list=applicationGateways.id|name', 'Listeners:list=httpListeners.id|name') }
    # ---- firewalls ----
    @{ Report = 'Firewalls'; File = 'firewalls.csv'; Type = 'microsoft.network/azurefirewalls'; Columns = @('Sku=sku.name', 'Tier=sku.tier', 'ThreatIntelMode=threatIntelMode', 'Policy:id=firewallPolicy.id',
            'PrivateIPs:ipList=ipConfigurations.properties.privateIPAddress', 'PublicIPs:idList=ipConfigurations.properties.publicIPAddress.id', 'Subnet:id=ipConfigurations.properties.subnet.id',
            'ManagementSubnet:id=managementIpConfiguration.properties.subnet.id', 'VirtualHub:id=virtualHub.id', 'HubPrivateIP:ip=hubIPAddresses.privateIPAddress', 'Zones=@zones',
            'ClassicNetworkRuleCollections:num=networkRuleCollections|count', 'ClassicApplicationRuleCollections:num=applicationRuleCollections|count', 'ClassicNatRuleCollections:num=natRuleCollections|count') }
    @{ Report = 'Firewalls'; File = 'firewallPolicies.csv'; Type = 'microsoft.network/firewallpolicies'; Columns = @('Tier=sku.tier', 'ThreatIntelMode=threatIntelMode', 'BasePolicy:id=basePolicy.id', 'DnsProxy=dnsSettings.enableProxy',
            'DnsServers:ipList=dnsSettings.servers', 'IntrusionDetection=intrusionDetection.mode', 'TlsInspection=transportSecurity|any', 'Snat=snat.privateRanges', 'RuleCollectionGroups:list=ruleCollectionGroups.id|name',
            'Firewalls:list=firewalls.id|name', 'ChildPolicies:list=childPolicies.id|name') }
    @{ Report = 'Firewalls'; File = 'ipGroups.csv'; Type = 'microsoft.network/ipgroups'; Columns = @('Addresses:num=ipAddresses|count', 'IpAddresses:ipList=ipAddresses', 'Firewalls:list=firewalls.id|name',
            'FirewallPolicies:list=firewallPolicies.id|name') }
    # ---- gateways, connections, ExpressRoute, Virtual WAN, NAT gateways, Bastion ----
    @{ Report = 'Gateways'; File = 'virtualNetworkGateways.csv'; Type = 'microsoft.network/virtualnetworkgateways'; Columns = @('GatewayType=gatewayType', 'VpnType=vpnType', 'Sku=sku.name', 'Generation=vpnGatewayGeneration',
            'ActiveActive=activeActive', 'EnableBgp=enableBgp', 'Asn:num=bgpSettings.asn', 'BgpPeeringAddresses:ipList=bgpSettings.bgpPeeringAddress', 'Subnet:id=ipConfigurations.properties.subnet.id',
            'PublicIPs:idList=ipConfigurations.properties.publicIPAddress.id', 'P2SAddressPool:ipList=vpnClientConfiguration.vpnClientAddressPool.addressPrefixes', 'P2SProtocols=vpnClientConfiguration.vpnClientProtocols',
            'P2SAuthentication=vpnClientConfiguration.vpnAuthenticationTypes', 'NatRules:list=natRules.name', 'PrivateIPAddress=enablePrivateIpAddress') }
    @{ Report = 'Gateways'; File = 'localNetworkGateways.csv'; Type = 'microsoft.network/localnetworkgateways'; Columns = @('GatewayIpAddress:ip=gatewayIpAddress', 'Fqdn:fqdn=fqdn',
            'AddressPrefixes:ipList=localNetworkAddressSpace.addressPrefixes', 'Asn:num=bgpSettings.asn', 'BgpPeeringAddress:ip=bgpSettings.bgpPeeringAddress') }
    @{ Report = 'Gateways'; File = 'connections.csv'; Type = 'microsoft.network/connections'; Columns = @('ConnectionType=connectionType', 'Protocol=connectionProtocol', 'Status=connectionStatus',
            'VirtualNetworkGateway1:id=virtualNetworkGateway1.id', 'VirtualNetworkGateway2:id=virtualNetworkGateway2.id', 'LocalNetworkGateway:id=localNetworkGateway2.id', 'ExpressRouteCircuit:id=peer.id',
            'RoutingWeight:num=routingWeight', 'EnableBgp=enableBgp', 'PolicyBasedTrafficSelectors=usePolicyBasedTrafficSelectors', 'IpsecPolicies=ipsecPolicies|json', 'ConnectionMode=connectionMode',
            'DpdTimeoutSeconds:num=dpdTimeoutSeconds', 'EgressBytes:num=egressBytesTransferred', 'IngressBytes:num=ingressBytesTransferred') }
    @{ Report = 'Gateways'; File = 'expressRouteCircuits.csv'; Type = 'microsoft.network/expressroutecircuits'; Columns = @('Sku=@sku.name', 'Tier=@sku.tier', 'Family=@sku.family',
            'ServiceProvider=serviceProviderProperties.serviceProviderName', 'PeeringLocation=serviceProviderProperties.peeringLocation', 'BandwidthMbps:num=serviceProviderProperties.bandwidthInMbps',
            'CircuitState=circuitProvisioningState', 'ProviderState=serviceProviderProvisioningState', 'Peerings=peerings.name', 'PeeringAddressPrefixes:ipList=peerings.properties.primaryPeerAddressPrefix',
            'PeerAsn=peerings.properties.peerASN', 'VlanIds=peerings.properties.vlanId', 'Authorizations:num=authorizations|count', 'GlobalReach=globalReachEnabled', 'ExpressRoutePort:id=expressRoutePort.id') }
    @{ Report = 'Gateways'; File = 'virtualHubs.csv'; Type = 'microsoft.network/virtualhubs'; Columns = @('VirtualWan:id=virtualWan.id', 'AddressPrefix:ip=addressPrefix', 'Sku=sku', 'RoutingState=routingState',
            'VpnGateway:id=vpnGateway.id', 'ExpressRouteGateway:id=expressRouteGateway.id', 'P2SVpnGateway:id=p2SVpnGateway.id', 'AzureFirewall:id=azureFirewall.id', 'HubRoutingPreference=hubRoutingPreference',
            'VirtualRouterAsn:num=virtualRouterAsn', 'VirtualRouterIps:ipList=virtualRouterIps', 'AllowBranchToBranch=allowBranchToBranchTraffic') }
    @{ Report = 'Gateways'; File = 'virtualWans.csv'; Type = 'microsoft.network/virtualwans'; Columns = @('WanType=type', 'AllowBranchToBranch=allowBranchToBranchTraffic', 'AllowVnetToVnet=allowVnetToVnetTraffic',
            'Hubs:list=virtualHubs.id|name', 'VpnSites:list=vpnSites.id|name', 'Office365Breakout=office365LocalBreakoutCategory') }
    @{ Report = 'Gateways'; File = 'natGateways.csv'; Type = 'microsoft.network/natgateways'; Columns = @('Sku=@sku.name', 'IdleTimeoutMinutes:num=idleTimeoutInMinutes', 'PublicIPs:idList=publicIpAddresses.id',
            'PublicIPPrefixes:idList=publicIpPrefixes.id', 'Subnets:idList=subnets.id', 'Zones=@zones') }
    @{ Report = 'Gateways'; File = 'bastionHosts.csv'; Type = 'microsoft.network/bastionhosts'; Columns = @('Sku=@sku.name', 'Subnet:id=ipConfigurations.properties.subnet.id', 'PublicIP:id=ipConfigurations.properties.publicIPAddress.id',
            'DnsName:fqdn=dnsName', 'ScaleUnits:num=scaleUnits', 'NativeClient=enableTunneling', 'IpConnect=enableIpConnect', 'ShareableLink=enableShareableLink', 'CopyPasteDisabled=disableCopyPaste', 'Zones=@zones') }
    # ---- network interfaces ----
    @{ Report = 'NetworkInterfaces'; File = 'networkInterfaces.csv'; Type = 'microsoft.network/networkinterfaces'; Columns = @('VirtualMachine:id=virtualMachine.id', 'PrivateEndpoint:id=privateEndpoint.id',
            'Primary=primary', 'PrivateIPs:ipList=ipConfigurations.properties.privateIPAddress', 'Allocation=ipConfigurations.properties.privateIPAllocationMethod', 'Subnets:idList=ipConfigurations.properties.subnet.id',
            'PublicIPs:idList=ipConfigurations.properties.publicIPAddress.id', 'Nsg:id=networkSecurityGroup.id', 'Asgs:idList=ipConfigurations.properties.applicationSecurityGroups.id',
            'LoadBalancerPools:idList=ipConfigurations.properties.loadBalancerBackendAddressPools.id', 'AppGatewayPools:idList=ipConfigurations.properties.applicationGatewayBackendAddressPools.id',
            'AcceleratedNetworking=enableAcceleratedNetworking', 'IpForwarding=enableIPForwarding', 'DnsServers:ipList=dnsSettings.dnsServers', 'InternalDnsNameLabel:name=dnsSettings.internalDnsNameLabel',
            'MacAddress:text=macAddress', 'NicType=nicType') }
    # ---- scale sets, container registries, container apps ----
    @{ Report = 'ScaleSets'; File = 'vmScaleSets.csv'; Type = 'microsoft.compute/virtualmachinescalesets'; Columns = @('Sku=@sku.name', 'Capacity:num=@sku.capacity', 'Tier=@sku.tier', 'OrchestrationMode=orchestrationMode',
            'UpgradeMode=upgradePolicy.mode', 'Zones=@zones', 'Overprovision=overprovision', 'SinglePlacementGroup=singlePlacementGroup', 'FaultDomains:num=platformFaultDomainCount',
            'OsType=virtualMachineProfile.storageProfile.osDisk.osType', 'ImagePublisher=virtualMachineProfile.storageProfile.imageReference.publisher', 'ImageOffer=virtualMachineProfile.storageProfile.imageReference.offer',
            'ImageSku=virtualMachineProfile.storageProfile.imageReference.sku', 'ImageVersion=virtualMachineProfile.storageProfile.imageReference.version', 'ImageId:id=virtualMachineProfile.storageProfile.imageReference.id',
            'OsDiskType=virtualMachineProfile.storageProfile.osDisk.managedDisk.storageAccountType', 'OsDiskSizeGB:num=virtualMachineProfile.storageProfile.osDisk.diskSizeGB',
            'DataDisks:num=virtualMachineProfile.storageProfile.dataDisks|count', 'Subnets:idList=virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.ipConfigurations.properties.subnet.id',
            'LoadBalancerPools:idList=virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.ipConfigurations.properties.loadBalancerBackendAddressPools.id',
            'AppGatewayPools:idList=virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.ipConfigurations.properties.applicationGatewayBackendAddressPools.id',
            'Extensions:list=virtualMachineProfile.extensionProfile.extensions.name', 'Priority=virtualMachineProfile.priority', 'EvictionPolicy=virtualMachineProfile.evictionPolicy',
            'LicenseType=virtualMachineProfile.licenseType', 'ScaleInPolicy=scaleInPolicy.rules', 'AutomaticRepairs=automaticRepairsPolicy.enabled', 'IdentityType=@identity.type',
            'UserAssignedIdentities:idList=@identity.userAssignedIdentities|keys') }
    @{ Report = 'ContainerRegistries'; File = 'containerRegistries.csv'; Type = 'microsoft.containerregistry/registries'; Columns = @('Sku=@sku.name', 'LoginServer:fqdn=loginServer', 'AdminUserEnabled=adminUserEnabled',
            'PublicNetworkAccess=publicNetworkAccess', 'NetworkDefaultAction=networkRuleSet.defaultAction', 'IpRules:ipList=networkRuleSet.ipRules.value', 'NetworkRuleBypass=networkRuleBypassOptions',
            'ZoneRedundancy=zoneRedundancy', 'AnonymousPull=anonymousPullEnabled', 'DataEndpoints=dataEndpointEnabled', 'Encryption=encryption.status', 'EncryptionKey:url=encryption.keyVaultProperties.keyIdentifier',
            'RetentionDays:num=policies.retentionPolicy.days', 'RetentionPolicy=policies.retentionPolicy.status', 'ContentTrust=policies.trustPolicy.status', 'SoftDelete=policies.softDeletePolicy.status',
            'QuarantinePolicy=policies.quarantinePolicy.status', 'ExportPolicy=policies.exportPolicy.status', 'PrivateEndpoints:num=privateEndpointConnections|count', 'IdentityType=@identity.type') }
    @{ Report = 'ContainerApps'; File = 'containerApps.csv'; Type = 'microsoft.app/containerapps'; Columns = @('Environment:id=managedEnvironmentId', 'WorkloadProfile=workloadProfileName',
            'RevisionMode=configuration.activeRevisionsMode', 'IngressExternal=configuration.ingress.external', 'TargetPort:num=configuration.ingress.targetPort', 'Transport=configuration.ingress.transport',
            'Fqdn:fqdn=configuration.ingress.fqdn', 'AllowInsecure=configuration.ingress.allowInsecure', 'CustomDomains:fqdn=configuration.ingress.customDomains.name', 'IpRestrictions:num=configuration.ingress.ipSecurityRestrictions|count',
            'Images:text=template.containers.image', 'Cpu=template.containers.resources.cpu', 'Memory=template.containers.resources.memory', 'MinReplicas:num=template.scale.minReplicas',
            'MaxReplicas:num=template.scale.maxReplicas', 'ScaleRules:list=template.scale.rules.name', 'Registries:fqdn=configuration.registries.server', 'SecretNames:list=configuration.secrets.name',
            'Dapr=configuration.dapr.enabled', 'DaprAppId:name=configuration.dapr.appId', 'Volumes:list=template.volumes.name', 'LatestRevision:name=latestRevisionName', 'IdentityType=@identity.type') }
    @{ Report = 'ContainerApps'; File = 'containerAppEnvironments.csv'; Type = 'microsoft.app/managedenvironments'; Columns = @('Subnet:id=vnetConfiguration.infrastructureSubnetId', 'Internal=vnetConfiguration.internal',
            'StaticIp:ip=staticIp', 'DefaultDomain:fqdn=defaultDomain', 'ZoneRedundant=zoneRedundant', 'WorkloadProfiles=workloadProfiles.name', 'WorkloadProfileTypes=workloadProfiles.workloadProfileType',
            'LogDestination=appLogsConfiguration.destination', 'LogAnalyticsCustomerId:guid=appLogsConfiguration.logAnalyticsConfiguration.customerId', 'MutualTls=peerAuthentication.mtls.enabled',
            'InfrastructureResourceGroup:rg=infrastructureResourceGroup') }
    @{ Report = 'ContainerApps'; File = 'containerInstances.csv'; Type = 'microsoft.containerinstance/containergroups'; Columns = @('OsType=osType', 'Sku=sku', 'RestartPolicy=restartPolicy', 'Images:text=containers.properties.image',
            'Cpu=containers.properties.resources.requests.cpu', 'MemoryGB=containers.properties.resources.requests.memoryInGB', 'IpType=ipAddress.type', 'Ip:ip=ipAddress.ip', 'Fqdn:fqdn=ipAddress.fqdn',
            'Ports=ipAddress.ports.port', 'Subnets:idList=subnetIds.id', 'Volumes:list=volumes.name', 'Zones=@zones', 'IdentityType=@identity.type') }
    # ---- databases other than Azure SQL ----
    @{ Report = 'Databases'; File = 'cosmosDbAccounts.csv'; Type = 'microsoft.documentdb/databaseaccounts'; Columns = @('Kind=@kind', 'Capabilities=capabilities.name', 'OfferType=databaseAccountOfferType',
            'Consistency=consistencyPolicy.defaultConsistencyLevel', 'Locations=locations.locationName', 'WriteLocations=writeLocations.locationName', 'ZoneRedundantLocations=locations.isZoneRedundant',
            'MultiRegionWrites=enableMultipleWriteLocations', 'AutomaticFailover=enableAutomaticFailover', 'FreeTier=enableFreeTier', 'BackupType=backupPolicy.type', 'BackupTier=backupPolicy.continuousModeProperties.tier',
            'PublicNetworkAccess=publicNetworkAccess', 'IpRules:ipList=ipRules.ipAddressOrRange', 'VnetFilter=isVirtualNetworkFilterEnabled', 'VnetRules:idList=virtualNetworkRules.id',
            'DisableLocalAuth=disableLocalAuth', 'DisableKeyBasedMetadataWrite=disableKeyBasedMetadataWriteAccess', 'MinimalTlsVersion=minimalTlsVersion', 'AnalyticalStorage=enableAnalyticalStorage',
            'KeyVaultKeyUri:url=keyVaultKeyUri', 'TotalThroughputLimit:num=capacity.totalThroughputLimit', 'PrivateEndpoints:num=privateEndpointConnections|count', 'Endpoint:url=documentEndpoint', 'IdentityType=@identity.type') }
    @{ Report = 'Databases'; File = 'postgresFlexibleServers.csv'; Type = 'microsoft.dbforpostgresql/flexibleservers'; Columns = @('Version=version', 'Sku=@sku.name', 'Tier=@sku.tier', 'StorageGB:num=storage.storageSizeGB',
            'StorageAutoGrow=storage.autoGrow', 'StorageTier=storage.tier', 'HighAvailability=highAvailability.mode', 'StandbyZone=highAvailability.standbyAvailabilityZone', 'Zone=availabilityZone',
            'BackupRetentionDays:num=backup.backupRetentionDays', 'GeoRedundantBackup=backup.geoRedundantBackup', 'PublicNetworkAccess=network.publicNetworkAccess', 'DelegatedSubnet:id=network.delegatedSubnetResourceId',
            'PrivateDnsZone:id=network.privateDnsZoneArmResourceId', 'EntraAuth=authConfig.activeDirectoryAuth', 'PasswordAuth=authConfig.passwordAuth', 'AdministratorLogin:name=administratorLogin',
            'Fqdn:fqdn=fullyQualifiedDomainName', 'State=state', 'ReplicationRole=replicationRole', 'SourceServer:id=sourceServerResourceId', 'MaintenanceWindow=maintenanceWindow.customWindow',
            'DataEncryption=dataEncryption.type', 'IdentityType=@identity.type') }
    @{ Report = 'Databases'; File = 'mysqlFlexibleServers.csv'; Type = 'microsoft.dbformysql/flexibleservers'; Columns = @('Version=version', 'Sku=@sku.name', 'Tier=@sku.tier', 'StorageGB:num=storage.storageSizeGB',
            'Iops:num=storage.iops', 'StorageAutoGrow=storage.autoGrow', 'HighAvailability=highAvailability.mode', 'StandbyZone=highAvailability.standbyAvailabilityZone', 'Zone=availabilityZone',
            'BackupRetentionDays:num=backup.backupRetentionDays', 'GeoRedundantBackup=backup.geoRedundantBackup', 'PublicNetworkAccess=network.publicNetworkAccess', 'DelegatedSubnet:id=network.delegatedSubnetResourceId',
            'PrivateDnsZone:id=network.privateDnsZoneResourceId', 'AdministratorLogin:name=administratorLogin', 'Fqdn:fqdn=fullyQualifiedDomainName', 'State=state', 'ReplicationRole=replicationRole',
            'SourceServer:id=sourceServerResourceId', 'DataEncryption=dataEncryption.type', 'IdentityType=@identity.type') }
    @{ Report = 'Databases'; File = 'redisCaches.csv'; Type = 'microsoft.cache/redis'; Columns = @('Sku=sku.name', 'Family=sku.family', 'Capacity:num=sku.capacity', 'RedisVersion=redisVersion', 'NonSslPort=enableNonSslPort',
            'MinimumTlsVersion=minimumTlsVersion', 'PublicNetworkAccess=publicNetworkAccess', 'Subnet:id=subnetId', 'StaticIP:ip=staticIP', 'ShardCount:num=shardCount', 'ReplicasPerPrimary:num=replicasPerPrimary',
            'Zones=@zones', 'HostName:fqdn=hostName', 'EntraAuth=redisConfiguration.aad-enabled', 'MaxMemoryPolicy=redisConfiguration.maxmemory-policy', 'RdbBackup=redisConfiguration.rdb-backup-enabled',
            'DisableAccessKeys=disableAccessKeyAuthentication', 'PrivateEndpoints:num=privateEndpointConnections|count') }
    # ---- messaging ----
    @{ Report = 'Messaging'; File = 'serviceBusNamespaces.csv'; Type = 'microsoft.servicebus/namespaces'; Columns = @('Sku=@sku.name', 'Capacity:num=@sku.capacity', 'ZoneRedundant=zoneRedundant',
            'PublicNetworkAccess=publicNetworkAccess', 'MinimumTlsVersion=minimumTlsVersion', 'DisableLocalAuth=disableLocalAuth', 'PremiumPartitions:num=premiumMessagingPartitions', 'Endpoint:url=serviceBusEndpoint',
            'PrivateEndpoints:num=privateEndpointConnections|count', 'Status=status', 'IdentityType=@identity.type') }
    @{ Report = 'Messaging'; File = 'eventHubNamespaces.csv'; Type = 'microsoft.eventhub/namespaces'; Columns = @('Sku=@sku.name', 'Capacity:num=@sku.capacity', 'AutoInflate=isAutoInflateEnabled',
            'MaxThroughputUnits:num=maximumThroughputUnits', 'Kafka=kafkaEnabled', 'ZoneRedundant=zoneRedundant', 'PublicNetworkAccess=publicNetworkAccess', 'MinimumTlsVersion=minimumTlsVersion',
            'DisableLocalAuth=disableLocalAuth', 'Endpoint:url=serviceBusEndpoint', 'Cluster:id=clusterArmId', 'PrivateEndpoints:num=privateEndpointConnections|count', 'Status=status', 'IdentityType=@identity.type') }
    @{ Report = 'Messaging'; File = 'eventGridTopics.csv'; Type = @('microsoft.eventgrid/topics', 'microsoft.eventgrid/domains', 'microsoft.eventgrid/systemtopics', 'microsoft.eventgrid/namespaces'); TypeColumn = $true
        Columns = @('Source:id=source', 'TopicType=topicType', 'InputSchema=inputSchema', 'PublicNetworkAccess=publicNetworkAccess', 'DisableLocalAuth=disableLocalAuth', 'MinimumTlsVersion=minimumTlsVersionAllowed',
            'Endpoint:url=endpoint', 'PrivateEndpoints:num=privateEndpointConnections|count', 'IdentityType=@identity.type') }
    # ---- monitoring ----
    @{ Report = 'Monitoring'; File = 'logAnalyticsWorkspaces.csv'; Type = 'microsoft.operationalinsights/workspaces'; Columns = @('Sku=sku.name', 'CapacityReservationGB:num=sku.capacityReservationLevel',
            'RetentionDays:num=retentionInDays', 'DailyQuotaGB:num=workspaceCapping.dailyQuotaGb', 'PublicIngestion=publicNetworkAccessForIngestion', 'PublicQuery=publicNetworkAccessForQuery',
            'CustomerId:guid=customerId', 'DisableLocalAuth=features.disableLocalAuth', 'ResourcePermissions=features.enableLogAccessUsingOnlyResourcePermissions', 'Cluster:id=features.clusterResourceId',
            'DefaultDataCollectionRule:id=defaultDataCollectionRuleResourceId') }
    @{ Report = 'Monitoring'; File = 'applicationInsights.csv'; Type = 'microsoft.insights/components'; Columns = @('Kind=@kind', 'ApplicationType=Application_Type', 'Workspace:id=WorkspaceResourceId',
            'RetentionDays:num=RetentionInDays', 'IngestionMode=IngestionMode', 'SamplingPercentage:num=SamplingPercentage', 'PublicIngestion=publicNetworkAccessForIngestion', 'PublicQuery=publicNetworkAccessForQuery',
            'DisableLocalAuth=DisableLocalAuth', 'DisableIpMasking=DisableIpMasking', 'AppId:guid=AppId') }
    @{ Report = 'Monitoring'; File = 'alertRules.csv'; Type = 'microsoft.insights/metricalerts'; Kind = 'Metric alert'; Columns = @('Enabled=enabled', 'Severity=severity', 'Description:text=description', 'Scopes:idList=scopes',
            'Frequency=evaluationFrequency', 'Window=windowSize', 'TargetType=targetResourceType', 'Criteria=criteria|json', 'ActionGroups:idList=actions.actionGroupId', 'AutoMitigate=autoMitigate') }
    @{ Report = 'Monitoring'; File = 'alertRules.csv'; Type = 'microsoft.insights/scheduledqueryrules'; Kind = 'Log search alert'; Columns = @('Enabled=enabled', 'Severity=severity', 'Description:text=description', 'Scopes:idList=scopes',
            'Frequency=evaluationFrequency', 'Window=windowSize', 'TargetType=targetResourceTypes', 'Criteria=criteria|json', 'ActionGroups:idList=actions.actionGroups', 'AutoMitigate=autoMitigate') }
    @{ Report = 'Monitoring'; File = 'alertRules.csv'; Type = 'microsoft.insights/activitylogalerts'; Kind = 'Activity log alert'; Columns = @('Enabled=enabled', 'Severity=severity', 'Description:text=description', 'Scopes:idList=scopes',
            'Frequency=evaluationFrequency', 'Window=windowSize', 'TargetType=targetResourceType', 'Criteria=condition|json', 'ActionGroups:idList=actions.actionGroups.actionGroupId', 'AutoMitigate=autoMitigate') }
    @{ Report = 'Monitoring'; File = 'actionGroups.csv'; Type = 'microsoft.insights/actiongroups'; Columns = @('ShortName:name=groupShortName', 'Enabled=enabled', 'Emails:upn=emailReceivers.emailAddress',
            'SmsReceivers:num=smsReceivers|count', 'Webhooks:list=webhookReceivers.name', 'LogicApps:idList=logicAppReceivers.resourceId', 'Functions:idList=azureFunctionReceivers.functionAppResourceId',
            'AutomationRunbooks:idList=automationRunbookReceivers.automationAccountId', 'ArmRoles=armRoleReceivers.roleId', 'EventHubs:list=eventHubReceivers.eventHubName', 'ItsmReceivers:num=itsmReceivers|count') }
    @{ Report = 'Monitoring'; File = 'dataCollectionRules.csv'; Type = 'microsoft.insights/datacollectionrules'; Columns = @('Kind=@kind', 'DataSources=dataSources|keys', 'Streams=dataFlows.streams',
            'LogAnalyticsWorkspaces:idList=destinations.logAnalytics.workspaceResourceId', 'OtherDestinations=destinations|keys', 'Endpoint:id=dataCollectionEndpointId', 'Description:text=description') }
    @{ Report = 'Monitoring'; File = 'autoscaleSettings.csv'; Type = 'microsoft.insights/autoscalesettings'; Columns = @('Enabled=enabled', 'Target:id=targetResourceUri', 'Profiles=profiles.name',
            'Minimum=profiles.capacity.minimum', 'Maximum=profiles.capacity.maximum', 'Default=profiles.capacity.default', 'Rules:num=profiles.rules|count', 'Notifications:num=notifications|count') }
    # ---- child resources as typed files (written by the ChildResources report) ----
    @{ Report = 'ChildResources'; File = 'storageContainers.csv'; Child = 'microsoft.storage/storageaccounts/blobservices/containers'; Parent = 'StorageAccount'; Columns = @('PublicAccess=publicAccess',
            'ImmutabilityPolicy=hasImmutabilityPolicy', 'LegalHold=hasLegalHold', 'VersionLevelImmutability=immutableStorageWithVersioning.enabled', 'DefaultEncryptionScope=defaultEncryptionScope',
            'LeaseState=leaseState', 'Deleted=deleted', 'LastModified:date=lastModifiedTime') }
    @{ Report = 'ChildResources'; File = 'storageFileShares.csv'; Child = 'microsoft.storage/storageaccounts/fileservices/shares'; Parent = 'StorageAccount'; Columns = @('QuotaGB:num=shareQuota', 'AccessTier=accessTier',
            'Protocols=enabledProtocols', 'RootSquash=rootSquash', 'LeaseState=leaseState', 'LastModified:date=lastModifiedTime') }
    @{ Report = 'ChildResources'; File = 'sqlFirewallRules.csv'; Child = 'microsoft.sql/servers/firewallrules'; Parent = 'SqlServer'; Columns = @('StartIpAddress:ip=startIpAddress', 'EndIpAddress:ip=endIpAddress') }
    @{ Report = 'ChildResources'; File = 'keyVaultObjects.csv'; Child = @('microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults/keys'); Parent = 'KeyVault'; TypeColumn = $true
        Columns = @('Enabled=attributes.enabled', 'Expires=attributes.exp', 'NotBefore=attributes.nbf', 'Created=attributes.created', 'Updated=attributes.updated', 'ContentType=contentType', 'KeyType=kty',
            'KeySize:num=keySize', 'Managed=managed') }
    @{ Report = 'ChildResources'; File = 'serviceBusEntities.csv'; Child = @('microsoft.servicebus/namespaces/queues', 'microsoft.servicebus/namespaces/topics', 'microsoft.servicebus/namespaces/topics/subscriptions'); Parent = 'Namespace'
        TypeColumn = $true; Columns = @('MaxSizeMB:num=maxSizeInMegabytes', 'LockDuration=lockDuration', 'MessageTimeToLive=defaultMessageTimeToLive', 'MaxDeliveryCount:num=maxDeliveryCount',
            'RequiresSession=requiresSession', 'DuplicateDetection=requiresDuplicateDetection', 'DeadLetterOnExpiration=deadLetteringOnMessageExpiration', 'Partitioning=enablePartitioning',
            'ForwardTo:name=forwardTo', 'AutoDeleteOnIdle=autoDeleteOnIdle', 'Status=status') }
    @{ Report = 'ChildResources'; File = 'eventHubs.csv'; Child = 'microsoft.eventhub/namespaces/eventhubs'; Parent = 'Namespace'; Columns = @('Partitions:num=partitionCount', 'RetentionDays:num=messageRetentionInDays',
            'RetentionHours:num=retentionDescription.retentionTimeInHours', 'CleanupPolicy=retentionDescription.cleanupPolicy', 'CaptureEnabled=captureDescription.enabled',
            'CaptureDestination:id=captureDescription.destination.properties.storageAccountResourceId', 'Status=status') }
    @{ Report = 'ChildResources'; File = 'privateEndpointDnsZoneGroups.csv'; Child = 'microsoft.network/privateendpoints/privatednszonegroups'; Parent = 'PrivateEndpoint'
        Columns = @('PrivateDnsZones:idList=privateDnsZoneConfigs.properties.privateDnsZoneId', 'RecordFqdns:fqdn=privateDnsZoneConfigs.properties.recordSets.fqdn',
            'RecordIps:ipList=privateDnsZoneConfigs.properties.recordSets.ipAddresses') }
)

foreach ($a2cSpec in $script:A2CSpecReports) {
    $a2cSpec['Parsed'] = @($a2cSpec.Columns | ForEach-Object { ConvertTo-A2CSpecColumn $_ })
    if (-not $script:A2CSchemas.ContainsKey($a2cSpec.File)) {
        $a2cLead = 'SubscriptionName:sub ResourceGroup:rg '
        if ($a2cSpec.Each -or $a2cSpec.Child) { $a2cLead += $(if ($a2cSpec.Parent) { [string]$a2cSpec.Parent } else { 'Parent' }) + ':name Name:name ' } else { $a2cLead += 'Name:name Location ' }
        if ($a2cSpec.Kind) { $a2cLead += 'Kind ' }
        if ($a2cSpec.TypeColumn) { $a2cLead += 'Type ' }
        Register-A2CSchema $a2cSpec.File ($a2cLead + (Join-A2C @($a2cSpec.Parsed | ForEach-Object { $_.Name + ':' + $_.Kind }) ' ') + ' Id:id')
    }
}

function Add-A2CSpecRows {
    param($Spec)
    $rows = [System.Collections.Generic.List[object]]::new()
    $parentCol = $(if ($Spec.Parent) { [string]$Spec.Parent } else { 'Parent' })
    $add = {
        param($Res, $Lead, $Root, $Props, $ParentRoot, $ParentProps, [string] $Id)
        $row = [ordered]@{ SubscriptionName = Get-A2CSubName ([string]$Res.subscriptionId); ResourceGroup = Get-A2CRgFromId ([string]$Res.id) }
        foreach ($k in $Lead.Keys) { $row[$k] = $Lead[$k] }
        if ($Spec.Kind) { $row['Kind'] = [string]$Spec.Kind }
        if ($Spec.TypeColumn) { $row['Type'] = (Get-A2CTypeCased -Id $Id -Fallback ([string]$Root.type)) }
        foreach ($c in $Spec.Parsed) { $row[$c.Name] = Get-A2CSpecValue $c $Root $Props $ParentRoot $ParentProps }
        $row['Id'] = $Id
        $rows.Add($row)
    }
    if ($Spec.Child) {
        foreach ($t in @($Spec.Child)) {
            foreach ($c in (Get-A2CChildrenOfType $t)) {
                $it = $c.Item
                $props = $it.properties
                if ($null -eq $props) { $props = $it }
                & $add $c.Resource ([ordered]@{ $parentCol = [string]$c.Resource.name; Name = [string]$it.name }) $it $props $c.Resource (Get-A2CProps $c.Resource) ([string]$it.id)
            }
        }
    }
    else {
        foreach ($r in (Get-A2CResourcesOfType @($Spec.Type))) {
            $p = Get-A2CProps $r
            if (-not $Spec.Each) { & $add $r ([ordered]@{ Name = [string]$r.name; Location = [string]$r.location }) $r $p $null $null ([string]$r.id); continue }
            foreach ($el in (Get-A2CPathValues $p ([string]$Spec.Each))) {
                $ep = $el.properties
                if ($null -eq $ep) { $ep = $el }
                $id = [string]$el.id
                if (-not $id) { $id = [string]$r.id }
                & $add $r ([ordered]@{ $parentCol = [string]$r.name; Name = [string]$el.name }) $el $ep $r $p $id
            }
        }
    }
    if ($rows.Count -gt 0) { Add-A2CRows $Spec.File $rows }
}

function New-A2CSpecReport {
    param([string] $Report)
    foreach ($s in $script:A2CSpecReports) { if ($s.Report -eq $Report) { Add-A2CSpecRows $s } }
}

function New-A2CReportLoadBalancers { New-A2CSpecReport 'LoadBalancers' }
function New-A2CReportAppGateways { New-A2CSpecReport 'AppGateways' }
function New-A2CReportGateways { New-A2CSpecReport 'Gateways' }
function New-A2CReportNetworkInterfaces { New-A2CSpecReport 'NetworkInterfaces' }
function New-A2CReportScaleSets { New-A2CSpecReport 'ScaleSets' }
function New-A2CReportContainerRegistries { New-A2CSpecReport 'ContainerRegistries' }
function New-A2CReportContainerApps { New-A2CSpecReport 'ContainerApps' }
function New-A2CReportDatabases { New-A2CSpecReport 'Databases' }
function New-A2CReportMessaging { New-A2CSpecReport 'Messaging' }
function New-A2CReportMonitoring { New-A2CSpecReport 'Monitoring' }

# ---- Firewall rules and DNS records: from the other Resource Graph tables ------------------------------------
Register-A2CSchema 'firewallRules.csv' ('SubscriptionName:sub ResourceGroup:rg FirewallPolicy:name RuleCollectionGroup:name GroupPriority:num RuleCollection:name CollectionPriority:num ' +
    'CollectionType Action Rule:name RuleType Protocols SourceAddresses:ipList SourceIpGroups:idList DestinationAddresses:ipList DestinationIpGroups:idList DestinationFqdns:fqdn ' +
    'TargetFqdns:fqdn FqdnTags WebCategories TargetUrls:text DestinationPorts TranslatedAddress:ip TranslatedFqdn:fqdn TranslatedPort TerminateTls Description:text Id:id')
Register-A2CSchema 'dnsRecords.csv' 'SubscriptionName:sub ResourceGroup:rg ZoneType Zone:fqdn Name:name RecordType Ttl:num Records:text Fqdn:fqdn AutoRegistered TargetResource:id Id:id'

function New-A2CReportFirewalls {
    New-A2CSpecReport 'Firewalls'
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($g in (Get-A2CGraphRowsOfType 'microsoft.network/firewallpolicies/rulecollectiongroups')) {
        $gp = Get-A2CProps $g
        $policy = Get-A2CIdSegment -Id ([string]$g.id) -After 'firewallPolicies'
        foreach ($col in @($gp.ruleCollections | Where-Object { $null -ne $_ })) {
            foreach ($rule in @($col.rules | Where-Object { $null -ne $_ })) {
                $protocols = Join-A2C @(@($rule.ipProtocols) + @($rule.protocols | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_.protocolType + ':' + [string]$_.port }) | Where-Object { $_ }) ', '
                $rows.Add([ordered]@{ SubscriptionName = Get-A2CSubName ([string]$g.subscriptionId); ResourceGroup = Get-A2CRgFromId ([string]$g.id); FirewallPolicy = $policy
                        RuleCollectionGroup = [string]$g.name; GroupPriority = $gp.priority; RuleCollection = [string]$col.name; CollectionPriority = $col.priority
                        CollectionType = ([string]$col.ruleCollectionType -replace '^FirewallPolicy|RuleCollection$', ''); Action = [string]$col.action.type; Rule = [string]$rule.name; RuleType = [string]$rule.ruleType
                        Protocols = $protocols; SourceAddresses = Join-A2C $rule.sourceAddresses; SourceIpGroups = Join-A2C $rule.sourceIpGroups
                        DestinationAddresses = Join-A2C $rule.destinationAddresses; DestinationIpGroups = Join-A2C $rule.destinationIpGroups; DestinationFqdns = Join-A2C $rule.destinationFqdns ', '
                        TargetFqdns = Join-A2C $rule.targetFqdns ', '; FqdnTags = Join-A2C $rule.fqdnTags ', '; WebCategories = Join-A2C $rule.webCategories ', '; TargetUrls = Join-A2C $rule.targetUrls ', '
                        DestinationPorts = Join-A2C $rule.destinationPorts ', '; TranslatedAddress = [string]$rule.translatedAddress; TranslatedFqdn = [string]$rule.translatedFqdn
                        TranslatedPort = [string]$rule.translatedPort; TerminateTls = $rule.terminateTLS; Description = [string]$rule.description; Id = [string]$g.id })
            }
        }
    }
    if ($rows.Count -gt 0) { Add-A2CRows 'firewallRules.csv' $rows }
}

function New-A2CReportDnsRecords {
    # every record set of the public and private DNS zones (dnsresources table): one row per record set
    $rows = [System.Collections.Generic.List[object]]::new()
    $byType = $script:A2C.Data['GraphByType']
    if ($null -eq $byType) { return }
    foreach ($t in @($byType.Keys | Sort-Object)) {
        if ($t -notmatch '^microsoft\.network/(dnszones|privatednszones)/([^/]+)$' -or $Matches[2] -eq 'virtualnetworklinks') { continue }
        $private = ($Matches[1] -eq 'privatednszones')
        $typeName = $Matches[2]
        foreach ($r in $byType[$t]) {
            $p = Get-A2CProps $r
            $seg = @(([string]$r.id).Trim('/').Split('/'))
            $recType = $(if ($seg.Count -ge 2) { $seg[$seg.Count - 2] } else { $typeName })
            # a record is an object with one or more values (ipv4Address; exchange + preference; ...): written as "value value"
            $values = [System.Collections.Generic.List[string]]::new()
            foreach ($rec in @($p.records | Where-Object { $null -ne $_ })) {
                if ($rec -is [string] -or $rec -is [valuetype]) { $values.Add([string]$rec); continue }
                $values.Add((Join-A2C @($rec.PSObject.Properties | ForEach-Object { $(if ($_.Value -is [array]) { Join-A2C $_.Value '' } else { Format-A2CCell $_.Value }) }) ' '))
            }
            $rows.Add([ordered]@{ SubscriptionName = Get-A2CSubName ([string]$r.subscriptionId); ResourceGroup = Get-A2CRgFromId ([string]$r.id); ZoneType = $(if ($private) { 'Private' } else { 'Public' })
                    Zone = $(if ($private) { Get-A2CIdSegment -Id ([string]$r.id) -After 'privateDnsZones' } else { Get-A2CIdSegment -Id ([string]$r.id) -After 'dnszones' }); Name = [string]$r.name
                    RecordType = $recType.ToUpperInvariant(); Ttl = $p.ttl; Records = Join-A2C $values; Fqdn = ([string]$p.fqdn).TrimEnd('.'); AutoRegistered = $p.isAutoRegistered
                    TargetResource = [string]$p.targetResource.id; Id = [string]$r.id })
        }
    }
    if ($rows.Count -gt 0) { Add-A2CRows 'dnsRecords.csv' $rows }
}

# ---- Code export (the files are written by the RunbookContent, AzureCode and AppCode datasets) ----------------
Register-A2CSchema 'code/index.csv' 'Type SubscriptionName:sub ResourceGroup:rg Resource:name Item:name File:path Status Detail:note ResourceId:id'

function Save-A2CCodeIndex {
    # code/index.csv: every exported item, and what was not exported and why
    $l = $script:A2C.Data['CodeIndex']
    if ($null -eq $l -or $l.Count -eq 0) { return }
    $script:A2C.Out['code/index.csv'] = [System.Collections.Generic.List[object]]::new($l)
}

function New-A2CReportAzureCode {
    # runbook flags (UsesAzureRM/UsesRunAs/ExportedFile) appear in runbooks.csv of the Automation report
    Save-A2CCodeIndex
}

function New-A2CReportAppCode {
    Save-A2CCodeIndex
}

# ---- Configuration snapshot (snapshot/ folder): every object as JSON, in a path that mirrors its ARM ID ---------
Register-A2CSchema 'snapshot/index.csv' 'Source Type Name:name SubscriptionName:sub ResourceGroup:rg File:path ApiVersion Id:id'

function Get-A2CSnapshotPath {
    # The file of an ARM ID: snapshot/<subscription>/<resource group>/<namespace>/<type>/<name>[/<type>/<name>...].json
    # Without a resource group: <subscription>/_subscription/...; management group scope: _managementGroups/<name>/...;
    # tenant scope: _tenant/...
    param([string] $Id)
    $p = @($Id.Trim('/').Split('/') | Where-Object { $_ })
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add('snapshot')
    $i = 0
    if ($p.Count -ge 2 -and $p[0] -ieq 'subscriptions') {
        $sub = Get-A2CSubName $p[1]
        if (-not $sub) { $sub = $p[1] }
        $parts.Add($sub)
        $i = 2
        if ($p.Count -ge 4 -and $p[2] -ieq 'resourceGroups') { $parts.Add($p[3]); $i = 4 } else { $parts.Add('_subscription') }
    }
    elseif ($p.Count -ge 4 -and $p[0] -ieq 'providers' -and $p[1] -ieq 'Microsoft.Management' -and $p[2] -ieq 'managementGroups') {
        $parts.Add('_managementGroups'); $parts.Add($p[3]); $i = 4
    }
    elseif ($p.Count -eq 0 -or $p[0] -ne '_entra') { $parts.Add('_tenant') }
    for (; $i -lt $p.Count; $i++) { if ($p[$i] -ine 'providers') { $parts.Add($p[$i]) } }
    # safe names; a name Windows reserves for a device (con, nul, com1...) gets an underscore
    $safe = @(foreach ($x in $parts) { $s = Get-A2CSafePathSegment $x; if ($s -match '^(?i)(con|prn|aux|nul|com\d|lpt\d)$') { '_' + $s } else { $s } })
    return ([string]::Join('/', $safe) + '.json')
}

function ConvertTo-A2CSnapshotJson {
    # A Resource Graph row as the JSON of the resource. properties and tags are spliced in as the text Azure returned
    # (never parsed), so nothing is rounded, reformatted or cut.
    param($Row)
    $head = [ordered]@{ id = [string]$Row.id; name = [string]$Row.name; type = (Get-A2CTypeCased -Id ([string]$Row.id) -Fallback ([string]$Row.type)) }
    foreach ($k in @('apiVersion', 'location', 'kind', 'managedBy')) { if ([string]$Row.$k) { $head[$k] = [string]$Row.$k } }
    foreach ($k in @('sku', 'plan', 'identity', 'zones', 'extendedLocation')) { if ($null -ne $Row.$k) { $head[$k] = $Row.$k } }
    $json = ConvertTo-Json -InputObject $head -Depth 20 -Compress
    $tail = ''
    $tags = [string]$Row.tagsJson
    if (-not $tags -and $null -ne $Row.tags) { $tags = ConvertTo-Json -InputObject $Row.tags -Depth 5 -Compress }
    if ($tags -and $tags -ne 'null') { $tail += ',"tags":' + $tags }
    $props = [string]$Row.propertiesJson
    if ($props -and $props -ne 'null') { $tail += ',"properties":' + $props }
    return (Format-A2CJson ($json.Substring(0, $json.Length - 1) + $tail + '}'))
}

function Save-A2CSnapshotItem {
    # Writes one object of the snapshot and adds it to snapshot/index.csv. An ID is written once: the first source wins.
    param([string] $Source, [string] $Id, [string] $Type, [string] $Name, [string] $Json, [string] $ApiVersion = '')
    $st = $script:A2C.Data['SnapshotState']
    if (-not $Id -or -not $st.Seen.Add($Id)) { return }
    $file = Get-A2CSnapshotPath $Id
    try { Save-A2CExportFile $file (Protect-A2CSecretText $Json) }
    catch {
        $st.Failed++
        if ($st.Failed -le 10) { Write-A2CLog -Level Verbose ('Snapshot file not written: {0} - {1}' -f $file, (Get-A2CShortText $_.Exception.Message 160)) }
        $file = ''
    }
    $sub = Get-A2CSubIdFromId $Id
    $st.Index.Add([ordered]@{ Source = $Source; Type = $Type; Name = $Name; SubscriptionName = $(if ($sub) { Get-A2CSubName $sub } else { '' })
            ResourceGroup = Get-A2CRgFromId $Id; File = $file; ApiVersion = $ApiVersion; Id = $Id })
}

function New-A2CReportSnapshot {
    # snapshot/: the complete JSON of everything the selected reports collected - resources (not cut like a CSV cell),
    # the other Resource Graph tables, child resources, role and policy objects, locks, diagnostic settings, Entra
    # objects. It documents the configuration; it holds no secrets, keys or data.
    if ($script:A2C.Options.Mask) {
        Add-A2CCoverage -Area 'Configuration snapshot' -Status Skipped -Detail 'Disabled with -Mask (complete resource definitions)'
        return
    }
    $st = [pscustomobject]@{ Seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Index = [System.Collections.Generic.List[object]]::new(); Failed = 0 }
    $script:A2C.Data['SnapshotState'] = $st
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($x in @($script:A2C.Data['ManagementGroupRows'])) { if ($null -ne $x) { $rows.Add(@('Resource Graph', $x)) } }
    foreach ($x in @($script:A2C.Data['ResourceGroups'])) { if ($null -ne $x) { $rows.Add(@('Resource Graph', $x)) } }
    foreach ($x in @($script:A2C.Data['Resources'])) { if ($null -ne $x) { $rows.Add(@('Resource Graph', $x)) } }
    foreach ($x in @($script:A2C.Data['GraphRows'])) { if ($null -ne $x) { $rows.Add(@(('Resource Graph: ' + [string]$x.graphTable), $x)) } }
    foreach ($x in @($script:A2C.Data['DefenderPlans'])) { if ($null -ne $x) { $rows.Add(@('Resource Graph: securityresources', $x)) } }
    foreach ($x in @($script:A2C.Data['Lighthouse'])) { if ($null -ne $x) { $rows.Add(@('Resource Graph: managedservicesresources', $x)) } }
    $i = 0; $t0 = [DateTime]::Now
    foreach ($pair in $rows) {
        $i++
        $r = $pair[1]
        if ($i % 200 -eq 1) { Write-A2CProgress -Activity 'Configuration snapshot' -Current $i -Total $rows.Count -Started $t0 -Item ([string]$r.name) }
        Save-A2CSnapshotItem -Source $pair[0] -Id ([string]$r.id) -Type (Get-A2CTypeCased -Id ([string]$r.id) -Fallback ([string]$r.type)) -Name ([string]$r.name) -Json (ConvertTo-A2CSnapshotJson $r) -ApiVersion ([string]$r.apiVersion)
    }
    Write-A2CProgress -Activity 'Configuration snapshot' -Completed
    # objects read with ARM list calls: child resources, role and policy objects, locks, diagnostic settings
    $raw = $script:A2C.Data['Raw']
    if ($null -ne $raw) {
        foreach ($kind in @($raw.Keys)) {
            foreach ($x in @($raw[$kind].Values)) {
                Save-A2CSnapshotItem -Source ('ARM: ' + $kind) -Id ([string]$x.id) -Type (Get-A2CTypeCased -Id ([string]$x.id) -Fallback ([string]$x.type)) -Name ([string]$x.name) -Json (ConvertTo-A2CCodeJson $x)
            }
        }
    }
    # Entra objects (Microsoft Graph): snapshot/_entra/<kind>/<name>.json
    $entra = $script:A2C.Data['RawEntra']
    if ($null -ne $entra) {
        foreach ($kind in @($entra.Keys)) {
            foreach ($x in @($entra[$kind].Values)) {
                $label = [string]$x.displayName
                if (-not $label) { $label = [string]$x.id }
                $label = $label -replace '[\\/]', '_'
                Save-A2CSnapshotItem -Source ('Microsoft Graph: ' + $kind) -Id ('/_entra/' + $kind + '/' + $label + ' ' + [string]$x.id) -Type $kind -Name $label -Json (ConvertTo-A2CCodeJson $x)
            }
        }
    }
    Add-A2CRows 'snapshot/index.csv' $st.Index
    $note = Get-A2CTopText @($st.Index | ForEach-Object { $_['Source'] }) 8
    if ($st.Failed -gt 0) { $note += (' | {0} file(s) not written (path too long? use a short -OutputPath)' -f $st.Failed) }
    Add-A2CCoverage -Area 'Configuration snapshot' -Status $(if ($st.Failed -gt 0) { 'Partial' } else { 'Collected' }) -Items ($st.Index.Count - $st.Failed) -Detail $note
    Write-A2CLog -Level Ok ('Snapshot: {0} objects as JSON -> snapshot folder' -f ($st.Index.Count - $st.Failed))
}

# ---- ARM templates (templates/ folder; the files are written by the ArmTemplates dataset) ----------------------
Register-A2CSchema 'templates/index.csv' ('SubscriptionName:sub ResourceGroup:rg Location Resources:num Status TemplateResources:num JsonFile:path ' +
    'BicepFile:path NotExported:num NotExportedTypes:text Detail:note ResourceGroupId:id')
Register-A2CSchema 'templates/notExported.csv' 'SubscriptionName:sub ResourceGroup:rg Target:text Code Message:note'

function New-A2CReportArmTemplates {
    # templates/index.csv: every resource group with its files, or why it was not exported; templates/notExported.csv:
    # what Azure itself reported as missing from a template
    $l = $script:A2C.Data['TemplateIndex']
    if ($null -eq $l -or $l.Count -eq 0) { return }
    Add-A2CRows 'templates/index.csv' $l
    Add-A2CRows 'templates/notExported.csv' @($script:A2C.Data['TemplateIssues'])
}

# ---- Child resources: every item in one file, and what was asked with which API version ----------------------
Register-A2CSchema 'childResources.csv' 'SubscriptionName:sub ResourceGroup:rg Parent:name ParentType Type Name:name Properties:json Id:id'
Register-A2CSchema 'childResourceTypes.csv' ('ParentType Type ApiVersion Calls:num Answered:num Items:num NotFound:num NotApplicable:num Refused:num ' +
    'Failed:num Note:note')

function Get-A2CChildJson {
    # The settings of a child resource as compact JSON: its properties, or the object itself when it has none.
    param($Item)
    $p = $Item.properties
    if ($null -eq $p) { $p = $Item }
    return (Protect-A2CSecretText (ConvertTo-A2CJsonString $p 30))
}

function New-A2CReportChildResources {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($c in @($script:A2C.Data['ChildItems'])) {
        if ($null -eq $c) { continue }
        $r = $c.Resource
        $type = [string]$c.Item.type
        if (-not $type) { $type = $c.Type }
        $rows.Add([ordered]@{ SubscriptionName = Get-A2CSubName ([string]$r.subscriptionId); ResourceGroup = Get-A2CRgFromId ([string]$r.id); Parent = [string]$r.name
                ParentType = (Get-A2CTypeCased -Id ([string]$r.id) -Fallback ([string]$r.type)); Type = $type; Name = [string]$c.Item.name
                Properties = (Get-A2CChildJson $c.Item); Id = [string]$c.Item.id })
    }
    Add-A2CRows 'childResources.csv' $rows
    $types = [System.Collections.Generic.List[object]]::new()
    foreach ($t in @($script:A2C.Data['ChildTypes'])) {
        if ($null -eq $t) { continue }
        $note = $t.Sample
        if ($t.Stopped) { $note = $t.Stopped + $(if ($t.Sample) { ': ' + $t.Sample } else { '' }) }
        $types.Add([ordered]@{ ParentType = $t.ParentType; Type = $t.Type; ApiVersion = $t.Api; Calls = $t.Calls; Answered = $t.Answered; Items = $t.Items; NotFound = $t.None
                NotApplicable = $t.NotApplicable; Refused = $t.Refused; Failed = $t.Failed; Note = $note })
    }
    Add-A2CRows 'childResourceTypes.csv' $types
    # the most asked-for child resources as files of their own (see $A2CSpecReports)
    New-A2CSpecReport 'ChildResources'
}

# ---- Resource providers ---------------------------------------------------------------------------------------
Register-A2CSchema 'resourceProviders.csv' 'SubscriptionName:sub Namespace RegistrationState RegistrationPolicy ResourceTypes:num Resources:num'

function New-A2CReportResourceProviders {
    # Resources: how many resources of the subscription belong to the provider (empty when resources were not collected)
    $used = @{}
    $haveResources = Test-A2CDataset 'Resources'
    if ($haveResources) {
        foreach ($r in @($script:A2C.Data['Resources'])) {
            if ($null -eq $r) { continue }
            $k = ([string]$r.subscriptionId + '|' + ([string]$r.type).Split('/')[0]).ToLowerInvariant()
            $used[$k] = [int]$used[$k] + 1
        }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($p in @($script:A2C.Data['ProviderRows'] | Where-Object { $null -ne $_ } | Sort-Object { Get-A2CSubName $_.SubscriptionId }, Namespace)) {
        $n = $null
        if ($haveResources) { $n = [int]$used[($p.SubscriptionId + '|' + $p.Namespace).ToLowerInvariant()] }
        $rows.Add([ordered]@{ SubscriptionName = Get-A2CSubName $p.SubscriptionId; Namespace = $p.Namespace; RegistrationState = $p.State; RegistrationPolicy = $p.Policy
                ResourceTypes = $p.Types; Resources = $n })
    }
    Add-A2CRows 'resourceProviders.csv' $rows
}

# ---- Azure DevOps (ADO/ folder) ---------------------------------------------------------------------------
Register-A2CSchema 'ADO/organizations.csv'('Organization:name Status Detail:note Source OrganizationId:guid Owner:name SignedInAs:name Url:text ' +
    'BillingSubscription:sub BillingSubscriptionId:guid BillingResourceGroup:rg BillingResourceId:id Projects:num Repositories:num ' +
    'Pipelines:num ReleasePipelines:num ServiceConnections:num SelfHostedAgents:num Users:num PaidUsers:num Extensions:num Feeds:num WorkItems:num')
Register-A2CSchema 'ADO/projects.csv' ('Organization:name Project:name ProjectId:guid Visibility State Process:known ProcessType SourceControl ' +
    'LastUpdate:date Repositories:num Pipelines:num ReleasePipelines:num ServiceConnections:num WorkItems:num Description:text')
Register-A2CSchema 'ADO/repositories.csv' ('Organization:name Project:name Repository:name RepositoryId:guid SizeMB:num DefaultBranch ' +
    'LastCommit:date DaysSinceLastCommit:num Disabled Fork BranchPolicies:num MinReviewers:num BuildValidation ExportedTo:path')
Register-A2CSchema 'ADO/pipelines.csv' ('Organization:name Project:name Pipeline:name PipelineId:num Folder:name Type YamlFile:path ' +
    'RepositoryType Repository:name AgentPool:known Status LastRun:date DaysSinceLastRun:num LastResult Modified:date ModifiedBy:name ExportedFile:path')
Register-A2CSchema 'ADO/releasePipelines.csv' ('Organization:name Project:name ReleasePipeline:name ReleasePipelineId:num Folder:name ' +
    'Stages:list StageCount:num LastRelease:name LastReleaseDate:date DaysSinceLastRelease:num CreatedBy:name ModifiedOn:date ExportedFile:path')
Register-A2CSchema 'ADO/serviceConnections.csv' ('Organization:name Projects:list ServiceConnection:name ServiceConnectionId:guid Type ' +
    'AuthScheme SecretBased CreationMode ScopeLevel AzureSubscription:sub AzureSubscriptionId:guid InThisInventory ManagementGroupId:mg ' +
    'TenantId:guid AppId:guid AppName:known SecretExpires:date AzureRoles:note Shared Ready CreatedBy:name Issuer:text Subject:text Url:url')
Register-A2CSchema 'ADO/agentPools.csv' ('Organization:name Pool:known PoolId:num Kind PoolType Agents:num Online:num AutoProvision ' +
    'CreatedOn:date Owner:name AzureResourceId:id MaxCapacity:num')
Register-A2CSchema 'ADO/agents.csv' ('Organization:name Pool:known Agent:name ComputerName:name Version MajorVersion:num Outdated OS Status ' +
    'Enabled LastJob:date DaysSinceLastJob:num LastJobResult CreatedOn:date AzureVmId:id')
Register-A2CSchema 'ADO/users.csv' ('Organization:name User:upn DisplayName:name Origin UserType License LicenseSource Status Paid ' +
    'LastAccess:date DaysSinceLastAccess:num DateAdded:date')
Register-A2CSchema 'ADO/admins.csv' 'Organization:name Group Scope Project:name Member:name MemberUpn:upn MemberType Origin'
Register-A2CSchema 'ADO/variableGroups.csv' ('Organization:name Projects:list VariableGroup:name VariableGroupId:num Type KeyVault:name ' +
    'ServiceConnection:name Variables:num SecretVariables:num VariableNames:list CreatedBy:name ModifiedOn:date')
Register-A2CSchema 'ADO/secureFiles.csv' 'Organization:name Project:name SecureFile:name CreatedBy:name CreatedOn:date ModifiedOn:date'
Register-A2CSchema 'ADO/environments.csv' ('Organization:name Project:name Environment:name EnvironmentId:num Resources:num ResourceTypes ' +
    'Approvals:num Checks:num CheckTypes CreatedOn:date LastModifiedOn:date')
Register-A2CSchema 'ADO/deploymentGroups.csv' 'Organization:name Project:name DeploymentGroup:name Machine:name AgentStatus AgentVersion Tags:list AzureVmId:id'
Register-A2CSchema 'ADO/extensions.csv' 'Organization:name Publisher PublisherId Extension ExtensionId Version Source BuiltIn Disabled Scopes LastPublished:date'
Register-A2CSchema 'ADO/serviceHooks.csv' 'Organization:name Project:name Event Consumer Action TargetHost:fqdn Status CreatedBy:name ModifiedDate:date'
Register-A2CSchema 'ADO/feeds.csv' ('Organization:name Project:name Scope Feed:name FeedId:guid Packages:num PublishedPackages:num CachedPackages:num ' +
    'Versions:num PackagesCapped Protocols LastPublished:date UpstreamSources:list UpstreamEnabled Views:list MaxVersions:num KeepDownloadedDays:num ' +
    'Permissions:num')
Register-A2CSchema 'ADO/packages.csv' ('Organization:name Project:name Feed:name Protocol Package:known Version IsLatest Listed Views:list Source ' +
    'Upstream:list PublishDate:date PackageDownloads:num PackageLastDownloaded:date ExportedTo:path ExportNote:note PackageId:guid')
Register-A2CSchema 'ADO/feedPermissions.csv' 'Organization:name Project:name Scope Feed:name FeedId:guid Identity:dn IdentityScope:name Role Inherited IdentityId:guid'
Register-A2CSchema 'ADO/tfvc.csv' ('Organization:name Project:name Path:tfvc IsBranch Parent:tfvc Owner:dn Created:date LastChangeset:num LastChange:date ' +
    'DaysSinceLastChange:num LastChangeBy:dn Files:num SizeMB:num FilesCapped Pipelines:num ExportedTo:path')
Register-A2CSchema 'ADO/workItems.csv' 'Organization:name Project:name WorkItemType Count:num'
Register-A2CSchema 'ADO/processes.csv' 'Organization:name Process:known Type Parent:known IsDefault Enabled Projects:num ProjectNames:list'

$script:A2CAdoFiles = @('organizations', 'projects', 'repositories', 'pipelines', 'releasePipelines', 'serviceConnections', 'agentPools',
    'agents', 'users', 'admins', 'variableGroups', 'secureFiles', 'environments', 'deploymentGroups', 'extensions', 'serviceHooks', 'feeds',
    'packages', 'feedPermissions', 'tfvc', 'workItems', 'processes')
# ADO/organizations.csv lists every organization; the other files go to ADO/<organization>/ (one folder per organization)
foreach ($f in $script:A2CAdoFiles) { if ($f -ne 'organizations') { $script:A2CSplitBy['ADO/' + $f + '.csv'] = 'Organization' } }

function Format-A2CAdoDate {
    # Azure DevOps uses 0001-01-01 for "never"
    param($Value)
    $dt = ConvertTo-A2CUtc $Value
    if ($null -eq $dt -or $dt.Year -lt 2000) { return '' }
    return (Format-A2CDate $dt)
}

function Get-A2CAdoDaysSince {
    param($Value)
    $dt = ConvertTo-A2CUtc $Value
    if ($null -eq $dt -or $dt.Year -lt 2000) { return $null }
    return [int][math]::Floor(($script:A2C.Now - $dt).TotalDays)
}

function Get-A2CAdoFolder {
    # "\Team\Build" -> "Team\Build"; the root "\" -> ""
    param($Path)
    return ([string]$Path).Trim('\')
}

function Get-A2CAdoLicense {
    # License name, and whether it is bought in Azure DevOps (Basic, Basic + Test Plans). Stakeholders and Visual
    # Studio subscribers (licensingSource msdn) are not paid there.
    param($AccessLevel)
    if ($null -eq $AccessLevel) { return [pscustomobject]@{ Name = ''; Paid = $false } }
    $type = [string]$AccessLevel.accountLicenseType
    $name = [string]$AccessLevel.licenseDisplayName
    if (-not $name) { $name = $type }
    $paid = ([string]$AccessLevel.licensingSource -eq 'account' -and @('express', 'advanced', 'professional') -contains $type)
    return [pscustomobject]@{ Name = $name; Paid = $paid }
}

function Get-A2CAdoTfvcPaths {
    # TFVC server paths a classic pipeline uses: its mappings (repository.properties.tfvcMapping, cloaked paths left
    # out) and its default branch
    param($Definition)
    $paths = [System.Collections.Generic.List[string]]::new()
    $repo = $Definition.repository
    if ($null -eq $repo -or [string]$repo.type -ne 'TfsVersionControl') { return , $paths }
    if ($repo.defaultBranch) { $paths.Add([string]$repo.defaultBranch) }
    $raw = $null
    if ($null -ne $repo.properties) { $raw = [string]$repo.properties.tfvcMapping }
    if ($raw) {
        try {
            foreach ($x in @((ConvertFrom-Json -InputObject $raw -ErrorAction Stop).mappings)) {
                # "$/P/Folder/*" maps one level of the folder
                if ($null -ne $x -and $x.serverPath -and [string]$x.mappingType -ne 'cloak') { $paths.Add(([string]$x.serverPath -replace '/\*$', '')) }
            }
        }
        catch { Write-Verbose 'tfvcMapping is not JSON' }
    }
    return , $paths
}

function Test-A2CAdoTfvcPathOverlap {
    # $true when one TFVC path is the other or contains it (TFVC paths are case-insensitive)
    param([string] $A, [string] $B)
    $x = $A.TrimEnd('/'); $y = $B.TrimEnd('/')
    return ($x -ieq $y -or $x.StartsWith($y + '/', [StringComparison]::OrdinalIgnoreCase) -or $y.StartsWith($x + '/', [StringComparison]::OrdinalIgnoreCase))
}

function Get-A2CAdoBranchPolicy {
    # Enabled policies that apply to the default branch of a repository.
    param($Org, $Repo)
    $count = 0; $min = $null; $build = $false
    $ref = [string]$Repo.defaultBranch
    foreach ($w in $Org.Policies) {
        if ($w.ProjectId -ne [string]$Repo.project.id) { continue }
        $c = $w.Item
        if (-not $c.isEnabled) { continue }
        $applies = $false
        foreach ($sc in @($c.settings.scope)) {
            if ($null -eq $sc) { continue }
            $repoOk = (-not $sc.repositoryId -or [string]$sc.repositoryId -eq [string]$Repo.id)
            $kind = [string]$sc.matchKind
            $refOk = ($kind -eq 'DefaultBranch' -or -not $sc.refName -or ($kind -eq 'Exact' -and [string]$sc.refName -eq $ref) -or
                ($kind -eq 'Prefix' -and $ref.StartsWith([string]$sc.refName, [StringComparison]::OrdinalIgnoreCase)))
            if ($repoOk -and $refOk) { $applies = $true; break }
        }
        if (-not $applies) { continue }
        $count++
        # policy types by id: display names differ ("Minimum approval count" / "Minimum number of reviewers")
        $tid = [string]$c.type.id
        $tname = [string]$c.type.displayName
        if ($tid -eq $script:A2CAdoPolicyTypes.MinReviewers -or $tname -eq 'Minimum number of reviewers') { $n = [int]$c.settings.minimumApproverCount; if ($null -eq $min -or $n -gt $min) { $min = $n } }
        if ($tid -eq $script:A2CAdoPolicyTypes.Build -or $tname -eq 'Build') { $build = $true }
    }
    return [pscustomobject]@{ Count = $count; MinReviewers = $min; Build = $build }
}

$script:A2CAdoRepoTypes = @{ TfsGit = 'Azure Repos Git'; TfsVersionControl = 'TFVC'; GitHub = 'GitHub'; GitHubEnterprise = 'GitHub Enterprise'
    Bitbucket = 'Bitbucket Cloud'; Git = 'Other Git'; Svn = 'Subversion' }
$script:A2CAdoOrigins = @{ aad = 'Entra ID'; msa = 'Microsoft account'; ad = 'Active Directory'; vsts = 'Azure DevOps' }

function New-A2CReportAzureDevOpsRepos {
    # The files are written by the AzureDevOpsRepos dataset; the ExportedTo column appears in the AzureDevOps report.
    $m = $script:A2C.Data['AdoRepoFolders']
    if ($null -ne $m) { Write-A2CLog -Level Ok ('{0} Azure DevOps repositories exported to ADO\<organization>\<project>\repos' -f $m.Count) }
}

function New-A2CReportAzureDevOpsPackages {
    # The files are written by the AzureDevOpsPackages dataset; ExportedTo and ExportNote appear in packages.csv.
    $m = $script:A2C.Data['AdoPackageFiles']
    if ($null -ne $m) { Write-A2CLog -Level Ok ('{0} package version(s) downloaded to the feeds folders under ADO\<organization>' -f @($m.Values | Where-Object { $_.Path }).Count) }
}

function New-A2CReportAzureDevOpsPipelines {
    # The files are written by the AzureDevOpsPipelines dataset; ExportedFile columns appear in the AzureDevOps report.
    $m = $script:A2C.Data['AdoPipelineFiles']
    if ($null -ne $m) { Write-A2CLog -Level Ok ('{0} Azure DevOps pipelines exported to ADO\<organization>\<project>\pipelines' -f $m.Count) }
}

function New-A2CReportAzureDevOps {
    $orgs = @($script:A2C.Data['Ado'] | Where-Object { $null -ne $_ })
    if ($orgs.Count -eq 0) { return }
    $rows = @{}
    foreach ($f in $script:A2CAdoFiles) { $rows[$f] = [System.Collections.Generic.List[object]]::new() }
    # joins with the Azure and Entra inventory
    $vmByComputer = @{}
    foreach ($vm in (Get-A2CResourcesOfType 'microsoft.compute/virtualmachines')) {
        $vp = Get-A2CProps $vm
        foreach ($n in @([string](Get-A2CFirst $vp @('osProfile.computerName', 'extended.instanceView.computerName')), [string]$vm.name)) { if ($n -and -not $vmByComputer.ContainsKey($n)) { $vmByComputer[$n] = [string]$vm.id } }
    }
    $mdpByName = @{}
    foreach ($x in (Get-A2CResourcesOfType 'microsoft.devopsinfrastructure/pools')) { $mdpByName[[string]$x.name] = [string]$x.id }
    $appByAppId = @{}
    foreach ($a in @($script:A2C.Data['EntraApps'])) { if ($null -ne $a -and $a.appId) { $appByAppId[([string]$a.appId).ToLowerInvariant()] = $a } }
    $spByAppId = @{}
    foreach ($s in @($script:A2C.Data['EntraSPs'])) { if ($null -ne $s -and $s.appId) { $spByAppId[([string]$s.appId).ToLowerInvariant()] = $s } }
    $defs = $script:A2C.Data['RoleDefs']
    $rolesByPrincipal = @{}
    foreach ($ra in @($script:A2C.Data['RoleAssignments'])) {
        if ($null -eq $ra) { continue }
        $role = [string]$ra.RoleGuid
        if ($null -ne $defs -and $defs.ContainsKey($role)) { $role = $defs[$role].RoleName }
        if (-not $rolesByPrincipal.ContainsKey($ra.PrincipalId)) { $rolesByPrincipal[$ra.PrincipalId] = [System.Collections.Generic.List[string]]::new() }
        $rolesByPrincipal[$ra.PrincipalId].Add(('{0} @ {1}' -f $role, $ra.Scope))
    }
    $entraUserType = @{}
    foreach ($u in @($script:A2C.Data['EntraUsers'])) { if ($null -ne $u -and $u.userPrincipalName) { $entraUserType[[string]$u.userPrincipalName] = [string]$u.userType } }
    $subById = $script:A2C.Data['SubById']
    if ($null -eq $subById) { $subById = @{} }
    $exported = $script:A2C.Data['AdoPipelineFiles']   # AzureDevOpsPipelines report: "<org>|build|<id>" -> file
    if ($null -eq $exported) { $exported = @{} }
    $repoFolders = $script:A2C.Data['AdoRepoFolders']   # AzureDevOpsRepos report: "<org>|<repository id>" -> folder
    if ($null -eq $repoFolders) { $repoFolders = @{} }
    $packageFiles = $script:A2C.Data['AdoPackageFiles']   # AzureDevOpsPackages report: "<org>|<feed id>|<version id>" -> @{ Path; Note }
    if ($null -eq $packageFiles) { $packageFiles = @{} }

    foreach ($o in $orgs) {
        $on = $o.Name
        $b = $o.Billing
        $bSub = ''; if ($null -ne $b) { $bSub = [string]$b.subscriptionId }
        $paid = @($o.Users | Where-Object { (Get-A2CAdoLicense $_.accessLevel).Paid }).Count
        $wiTotal = 0; $wiByProject = @{}
        foreach ($w in $o.WorkItems) { $pn = [string]$w.Project.ProjectName; $wiByProject[$pn] = [int]$wiByProject[$pn] + [int]$w.Count; $wiTotal += [int]$w.Count }
        $ok = ($o.Status -eq 'Collected')
        $rows['organizations'].Add([ordered]@{
                Organization = $on; Status = $o.Status; Detail = $(if ($ok) { Join-A2C $o.Problems } else { $o.Detail }); Source = $o.Source
                OrganizationId = $o.Id; Owner = $o.Owner; SignedInAs = $o.User; Url = $o.Url
                BillingSubscription = $(if ($bSub) { Get-A2CSubName $bSub } else { '' }); BillingSubscriptionId = $bSub
                BillingResourceGroup = $(if ($null -ne $b) { Get-A2CRgFromId ([string]$b.id) } else { '' }); BillingResourceId = $(if ($null -ne $b) { [string]$b.id } else { '' })
                Projects = $(if ($ok) { $o.Projects.Count } else { $null }); Repositories = $(if ($ok) { $o.Repos.Count } else { $null })
                Pipelines = $(if ($ok) { $o.Pipelines.Count } else { $null }); ReleasePipelines = $(if ($ok) { $o.Releases.Count } else { $null })
                ServiceConnections = $(if ($ok) { $o.Endpoints.Count } else { $null }); SelfHostedAgents = $(if ($ok) { $o.Agents.Count } else { $null })
                Users = $(if ($ok) { $o.Users.Count } else { $null }); PaidUsers = $(if ($ok) { $paid } else { $null })
                Extensions = $(if ($ok) { $o.Extensions.Count } else { $null }); Feeds = $(if ($ok) { $o.Feeds.Count } else { $null })
                WorkItems = $(if ($ok) { $wiTotal } else { $null })
            })
        if (-not $ok) { continue }

        $procType = @{}
        foreach ($x in $o.Processes) { $procType[[string]$x.name] = [string]$x.customizationType }
        $projName = @{}
        foreach ($p in $o.Projects) {
            $projName[([string]$p.id).ToLowerInvariant()] = [string]$p.name
            $process = ''; $sc = ''
            if ($null -ne $p.capabilities) {
                if ($null -ne $p.capabilities.processTemplate) { $process = [string]$p.capabilities.processTemplate.templateName }
                if ($null -ne $p.capabilities.versioncontrol) { $sc = [string]$p.capabilities.versioncontrol.sourceControlType }
            }
            $projId = [string]$p.id
            $rows['projects'].Add([ordered]@{
                    Organization = $on; Project = [string]$p.name; ProjectId = $projId; Visibility = [string]$p.visibility; State = [string]$p.state
                    Process = $process; ProcessType = [string]$procType[$process]; SourceControl = $sc; LastUpdate = Format-A2CAdoDate $p.lastUpdateTime
                    Repositories = @($o.Repos | Where-Object { [string]$_.project.id -eq $projId }).Count
                    Pipelines = @($o.Pipelines | Where-Object { [string]$_.Project.id -eq $projId }).Count
                    ReleasePipelines = @($o.Releases | Where-Object { [string]$_.Project.id -eq $projId }).Count
                    ServiceConnections = @($o.Endpoints | Where-Object { $_.Projects -contains [string]$p.name }).Count
                    WorkItems = [int]$wiByProject[[string]$p.name]; Description = [string]$p.description
                })
        }
        foreach ($r in $o.Repos) {
            $pol = Get-A2CAdoBranchPolicy $o $r
            $lc = $o.LastCommit[[string]$r.id]
            $rows['repositories'].Add([ordered]@{
                    Organization = $on; Project = [string]$r.project.name; Repository = [string]$r.name; RepositoryId = [string]$r.id
                    SizeMB = [math]::Round([double]$r.size / 1MB, 1); DefaultBranch = (([string]$r.defaultBranch) -replace '^refs/heads/', '')
                    LastCommit = Format-A2CAdoDate $lc; DaysSinceLastCommit = Get-A2CAdoDaysSince $lc; Disabled = [bool]$r.isDisabled; Fork = [bool]$r.isFork
                    BranchPolicies = $pol.Count; MinReviewers = $pol.MinReviewers; BuildValidation = $pol.Build
                    ExportedTo = [string]$repoFolders[$on + '|' + [string]$r.id]
                })
        }
        foreach ($w in $o.Pipelines) {
            $x = $w.Item
            # process.type: 1 designer (classic), 2 YAML, 3 Docker
            $type = 'Classic'; $yaml = ''
            if ($null -ne $x.process -and [int]$x.process.type -eq 2) { $type = 'YAML'; $yaml = [string]$x.process.yamlFilename }
            elseif ($null -ne $x.process -and [int]$x.process.type -eq 3) { $type = 'Docker' }
            $last = $x.latestCompletedBuild
            if ($null -eq $last) { $last = $x.latestBuild }
            $pool = ''
            if ($null -ne $x.queue) { $pool = [string]$x.queue.name; if ($null -ne $x.queue.pool -and $x.queue.pool.name) { $pool = [string]$x.queue.pool.name } }
            $rt = [string]$x.repository.type
            if ($script:A2CAdoRepoTypes.ContainsKey($rt)) { $rt = $script:A2CAdoRepoTypes[$rt] }
            $rows['pipelines'].Add([ordered]@{
                    Organization = $on; Project = [string]$w.Project.name; Pipeline = [string]$x.name; PipelineId = [int]$x.id; Folder = Get-A2CAdoFolder $x.path
                    Type = $type; YamlFile = $yaml; RepositoryType = $rt; Repository = [string]$x.repository.name; AgentPool = $pool; Status = [string]$x.queueStatus
                    LastRun = Format-A2CAdoDate $last.finishTime; DaysSinceLastRun = Get-A2CAdoDaysSince $last.finishTime; LastResult = [string]$last.result
                    Modified = Format-A2CAdoDate $x.createdDate; ModifiedBy = [string]$x.authoredBy.displayName   # the date/author of the current revision
                    ExportedFile = [string]$exported[$on + '|build|' + [string]$x.id]
                })
        }
        foreach ($w in $o.Releases) {
            $x = $w.Item
            $stages = @($x.environments | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_.name })
            $lr = $x.lastRelease
            $rows['releasePipelines'].Add([ordered]@{
                    Organization = $on; Project = [string]$w.Project.name; ReleasePipeline = [string]$x.name; ReleasePipelineId = [int]$x.id
                    Folder = Get-A2CAdoFolder $x.path; Stages = Join-A2C $stages; StageCount = $stages.Count; LastRelease = [string]$lr.name
                    LastReleaseDate = Format-A2CAdoDate $lr.createdOn; DaysSinceLastRelease = Get-A2CAdoDaysSince $lr.createdOn
                    CreatedBy = [string]$x.createdBy.displayName; ModifiedOn = Format-A2CAdoDate $x.modifiedOn
                    ExportedFile = [string]$exported[$on + '|release|' + [string]$x.id]
                })
        }
        foreach ($e in $o.Endpoints) {
            $x = $e.Item
            $ap = $null
            if ($null -ne $x.authorization) { $ap = $x.authorization.parameters }
            $scheme = [string]$x.authorization.scheme
            $appId = ([string](Get-A2CFirst $ap @('serviceprincipalid'))).ToLowerInvariant()
            $subId = ([string](Get-A2CFirst $x.data @('subscriptionId'))).ToLowerInvariant()
            $app = $appByAppId[$appId]
            $sp = $spByAppId[$appId]
            $appName = ''
            if ($null -ne $app) { $appName = [string]$app.displayName } elseif ($null -ne $sp) { $appName = [string]$sp.displayName }
            $secretExp = ''
            if ($null -ne $app) {
                $ends = @($app.passwordCredentials | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-A2CUtc $_.endDateTime } | Where-Object { $null -ne $_ } | Sort-Object)
                if ($ends.Count -gt 0) { $secretExp = Format-A2CDate $ends[$ends.Count - 1] }
            }
            $roles = ''
            if ($null -ne $sp) { $l = $rolesByPrincipal[([string]$sp.id).ToLowerInvariant()]; if ($null -ne $l) { $roles = Join-A2C $l } }
            $rows['serviceConnections'].Add([ordered]@{
                    Organization = $on; Projects = Join-A2C (Get-A2CUnique $e.Projects); ServiceConnection = [string]$x.name; ServiceConnectionId = [string]$x.id
                    Type = [string]$x.type; AuthScheme = $scheme
                    SecretBased = ($scheme -eq 'ServicePrincipal' -and [string](Get-A2CFirst $ap @('authenticationType')) -ne 'spnCertificate')
                    CreationMode = [string](Get-A2CFirst $x.data @('creationMode')); ScopeLevel = [string](Get-A2CFirst $x.data @('scopeLevel'))
                    AzureSubscription = [string](Get-A2CFirst $x.data @('subscriptionName')); AzureSubscriptionId = $subId
                    InThisInventory = [bool]($subId -and $subById.ContainsKey($subId)); ManagementGroupId = [string](Get-A2CFirst $x.data @('managementGroupId'))
                    TenantId = [string](Get-A2CFirst $ap @('tenantid')); AppId = $appId; AppName = $appName; SecretExpires = $secretExp; AzureRoles = $roles
                    Shared = [bool]$x.isShared; Ready = [bool]$x.isReady; CreatedBy = [string]$x.createdBy.displayName
                    Issuer = [string](Get-A2CFirst $ap @('workloadIdentityFederationIssuer')); Subject = [string](Get-A2CFirst $ap @('workloadIdentityFederationSubject'))
                    Url = [string]$x.url
                })
        }
        $elastic = @{}
        foreach ($x in $o.ElasticPools) { $elastic[[string]$x.poolId] = $x }
        foreach ($pool in $o.Pools) {
            $pa = @($o.Agents | Where-Object { [string]$_.Pool.id -eq [string]$pool.id })
            $kind = 'Self-hosted'; $azId = ''; $maxCap = $null
            if ($pool.isHosted) { $kind = 'Microsoft-hosted' }
            elseif ([string]$pool.poolType -eq 'deployment') { $kind = 'Deployment pool' }
            elseif ($elastic.ContainsKey([string]$pool.id)) { $kind = 'Scale set (VMSS)'; $azId = [string]$elastic[[string]$pool.id].azureId; $maxCap = $elastic[[string]$pool.id].maxCapacity }
            elseif ($mdpByName.ContainsKey([string]$pool.name)) { $kind = 'Managed DevOps Pool'; $azId = $mdpByName[[string]$pool.name] }
            $rows['agentPools'].Add([ordered]@{
                    Organization = $on; Pool = [string]$pool.name; PoolId = [int]$pool.id; Kind = $kind; PoolType = [string]$pool.poolType
                    Agents = $(if ($pool.isHosted) { $null } else { [int]$pool.size }); Online = $(if ($pool.isHosted) { $null } else { @($pa | Where-Object { [string]$_.Item.status -eq 'online' }).Count })
                    AutoProvision = [bool]$pool.autoProvision; CreatedOn = Format-A2CAdoDate $pool.createdOn; Owner = [string]$pool.owner.displayName
                    AzureResourceId = $azId; MaxCapacity = $maxCap
                })
        }
        foreach ($w in $o.Agents) {
            $a = $w.Item
            $cn = ''
            if ($null -ne $a.systemCapabilities) { $cn = [string]$a.systemCapabilities.'Agent.ComputerName' }
            $major = 0
            if ([string]$a.version -match '^(\d+)\.') { $major = [int]$Matches[1] }
            $last = $a.lastCompletedRequest
            $rows['agents'].Add([ordered]@{
                    Organization = $on; Pool = [string]$w.Pool.name; Agent = [string]$a.name; ComputerName = $cn; Version = [string]$a.version; MajorVersion = $major
                    Outdated = ($major -gt 0 -and $major -lt 3); OS = [string]$a.osDescription; Status = [string]$a.status; Enabled = [bool]$a.enabled
                    LastJob = Format-A2CAdoDate $last.finishTime; DaysSinceLastJob = Get-A2CAdoDaysSince $last.finishTime; LastJobResult = [string]$last.result
                    CreatedOn = Format-A2CAdoDate $a.createdOn; AzureVmId = $(if ($cn -and $vmByComputer.ContainsKey($cn)) { $vmByComputer[$cn] } else { '' })
                })
        }
        foreach ($u in $o.Users) {
            $usr = $u.user
            $upn = [string]$usr.principalName
            $lic = Get-A2CAdoLicense $u.accessLevel
            $utype = [string]$usr.metaType
            if (-not $utype -and $entraUserType.ContainsKey($upn)) { $utype = $entraUserType[$upn] }
            $origin = [string]$usr.origin
            if ($script:A2CAdoOrigins.ContainsKey($origin)) { $origin = $script:A2CAdoOrigins[$origin] }
            $rows['users'].Add([ordered]@{
                    Organization = $on; User = $upn; DisplayName = [string]$usr.displayName; Origin = $origin; UserType = $utype
                    License = $lic.Name; LicenseSource = [string]$u.accessLevel.licensingSource; Status = [string]$u.accessLevel.status; Paid = $lic.Paid
                    LastAccess = Format-A2CAdoDate $u.lastAccessedDate; DaysSinceLastAccess = Get-A2CAdoDaysSince $u.lastAccessedDate; DateAdded = Format-A2CAdoDate $u.dateCreated
                })
        }
        foreach ($w in $o.Admins) {
            $g = $w.Group
            $m = $w.Member
            $isOrg = ([string]$g.principalName -like '*\Project Collection Administrators')
            $scopeName = ''
            if ([string]$g.principalName -match '^\[([^\]]+)\]\\') { $scopeName = $Matches[1] }
            $mtype = 'Unknown'; $mname = ''; $mupn = ''; $morigin = ''
            if ($null -ne $m) {
                $mname = [string]$m.displayName
                $morigin = [string]$m.origin
                if ($script:A2CAdoOrigins.ContainsKey($morigin)) { $morigin = $script:A2CAdoOrigins[$morigin] }
                if ([string]$m.subjectKind -eq 'group') { $mtype = 'Group' } else { $mtype = 'User'; $mupn = [string]$m.principalName }
            }
            elseif ($w.Descriptor -like 'aadsp.*' -or $w.Descriptor -like 'svc.*') { $mtype = 'Service principal' }
            $rows['admins'].Add([ordered]@{
                    Organization = $on; Group = $(if ($isOrg) { 'Project Collection Administrators' } else { 'Project Administrators' })
                    Scope = $(if ($isOrg) { 'Organization' } else { 'Project' }); Project = $(if ($isOrg) { '' } else { $scopeName })
                    Member = $mname; MemberUpn = $mupn; MemberType = $mtype; Origin = $morigin
                })
        }
        foreach ($w in $o.VariableGroups) {
            $x = $w.Item
            $names = [System.Collections.Generic.List[string]]::new()
            $secret = 0
            if ($null -ne $x.variables) {
                # names and secret flags only - values are never read
                foreach ($vp in $x.variables.PSObject.Properties) { $names.Add([string]$vp.Name); if ($null -ne $vp.Value -and $vp.Value.isSecret) { $secret++ } }
            }
            $isKv = ([string]$x.type -eq 'AzureKeyVault')
            $kv = ''; $scName = ''
            if ($isKv -and $null -ne $x.providerData) {
                $kv = [string]$x.providerData.vault
                $ep = @($o.Endpoints | Where-Object { [string]$_.Item.id -eq [string]$x.providerData.serviceEndpointId })
                if ($ep.Count -gt 0) { $scName = [string]$ep[0].Item.name }
            }
            $rows['variableGroups'].Add([ordered]@{
                    Organization = $on; Projects = Join-A2C (Get-A2CUnique $w.Projects); VariableGroup = [string]$x.name; VariableGroupId = [int]$x.id
                    Type = $(if ($isKv) { 'Key Vault' } else { 'Library' }); KeyVault = $kv; ServiceConnection = $scName; Variables = $names.Count
                    SecretVariables = $secret; VariableNames = Join-A2C $names; CreatedBy = [string]$x.createdBy.displayName; ModifiedOn = Format-A2CAdoDate $x.modifiedOn
                })
        }
        foreach ($w in $o.SecureFiles) {
            $x = $w.Item
            $rows['secureFiles'].Add([ordered]@{ Organization = $on; Project = [string]$w.Project.name; SecureFile = [string]$x.name
                    CreatedBy = [string]$x.createdBy.displayName; CreatedOn = Format-A2CAdoDate $x.createdOn; ModifiedOn = Format-A2CAdoDate $x.modifiedOn })
        }
        foreach ($w in $o.Environments) {
            $x = $w.Item
            $res = @($w.Resources | Where-Object { $null -ne $_ })
            $chk = @($w.Checks | Where-Object { $null -ne $_ })
            $ctypes = @($chk | ForEach-Object { [string]$_.type.name })
            $rows['environments'].Add([ordered]@{
                    Organization = $on; Project = [string]$w.Project.name; Environment = [string]$x.name; EnvironmentId = [int]$x.id
                    Resources = $(if ($null -eq $w.Resources) { $null } else { $res.Count }); ResourceTypes = Join-A2C (Get-A2CUnique @($res | ForEach-Object { [string]$_.type }))
                    Approvals = @($ctypes | Where-Object { $_ -eq 'Approval' }).Count; Checks = $(if ($null -eq $w.Checks) { $null } else { $chk.Count })
                    CheckTypes = Join-A2C (Get-A2CUnique $ctypes); CreatedOn = Format-A2CAdoDate $x.createdOn; LastModifiedOn = Format-A2CAdoDate $x.lastModifiedOn
                })
        }
        foreach ($w in $o.DeploymentGroups) {
            $x = $w.Item
            $machines = @($w.Targets | Where-Object { $null -ne $_ })
            if ($null -eq $w.Targets) { $machines = @($x.machines | Where-Object { $null -ne $_ }) }
            if ($machines.Count -eq 0) { $machines = @($null) }
            foreach ($m in $machines) {
                $an = ''
                if ($null -ne $m -and $null -ne $m.agent) { $an = [string]$m.agent.name }
                $rows['deploymentGroups'].Add([ordered]@{
                        Organization = $on; Project = [string]$w.Project.name; DeploymentGroup = [string]$x.name; Machine = $an
                        AgentStatus = $(if ($an) { [string]$m.agent.status } else { '' }); AgentVersion = $(if ($an) { [string]$m.agent.version } else { '' })
                        Tags = $(if ($null -ne $m) { Join-A2C @($m.tags) } else { '' }); AzureVmId = $(if ($an -and $vmByComputer.ContainsKey($an)) { $vmByComputer[$an] } else { '' })
                    })
            }
        }
        foreach ($x in $o.Extensions) {
            $pub = [string]$x.publisherId
            $state = ''
            if ($null -ne $x.installState) { $state = [string]$x.installState.flags }
            $rows['extensions'].Add([ordered]@{
                    Organization = $on; Publisher = [string]$x.publisherName; PublisherId = $pub; Extension = [string]$x.extensionName; ExtensionId = [string]$x.extensionId
                    Version = [string]$x.version; Source = $(if ($pub -eq 'ms' -or $pub -like 'ms-*' -or $pub -eq 'microsoft') { 'Microsoft' } else { 'Third-party' })
                    BuiltIn = ([string]$x.flags -match 'builtIn'); Disabled = ($state -match 'disabled'); Scopes = Join-A2C @($x.scopes)
                    LastPublished = Format-A2CAdoDate $x.lastPublished
                })
        }
        foreach ($x in $o.Hooks) {
            # only the host of the target URL: hook URLs can carry credentials or tokens
            $target = ''
            $url = [string](Get-A2CFirst $x.consumerInputs @('url'))
            if ($url -match '^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?([^/:?#]+)') { $target = $Matches[1] }
            $hp = ([string](Get-A2CFirst $x.publisherInputs @('projectId'))).ToLowerInvariant()
            $rows['serviceHooks'].Add([ordered]@{
                    Organization = $on; Project = $(if ($hp) { [string]$projName[$hp] } else { '' }); Event = [string]$x.eventType; Consumer = [string]$x.consumerId
                    Action = [string]$x.consumerActionId; TargetHost = $target; Status = [string]$x.status; CreatedBy = [string]$x.createdBy.displayName
                    ModifiedDate = Format-A2CAdoDate $x.modifiedDate
                })
        }
        foreach ($w in $o.Feeds) {
            $x = $w.Item
            $proj = ''; $scope = 'Organization'
            if ($null -ne $w.Project) { $proj = [string]$w.Project.name; $scope = 'Project' }
            $upstream = @{}
            foreach ($us in @($x.upstreamSources)) { if ($null -ne $us) { $upstream[([string]$us.id).ToLowerInvariant()] = [string]$us.name } }
            $published = 0; $cachedOnly = 0; $versions = 0; $lastPublished = $null
            $protocols = [System.Collections.Generic.List[string]]::new()
            foreach ($pk in @($w.Items | Where-Object { $null -ne $_ })) {
                $proto = Get-A2CAdoProtocolName ([string]$pk.protocolType)
                if ($proto -and -not $protocols.Contains($proto)) { $protocols.Add($proto) }
                $vers = @($pk.versions | Where-Object { $null -ne $_ })
                if (@($vers | Where-Object { -not (Test-A2CAdoFromUpstream $_) }).Count -gt 0) { $published++ } elseif ($vers.Count -gt 0) { $cachedOnly++ }
                $met = $w.Metrics[[string]$pk.id]
                foreach ($pv in $vers) {
                    $versions++
                    $cached = Test-A2CAdoFromUpstream $pv
                    $pd = ConvertTo-A2CUtc $pv.publishDate
                    if (-not $cached -and $null -ne $pd -and ($null -eq $lastPublished -or $pd -gt $lastPublished)) { $lastPublished = $pd }
                    $ex = $packageFiles[$on + '|' + [string]$x.id + '|' + [string]$pv.id]
                    $rows['packages'].Add([ordered]@{
                            Organization = $on; Project = $proj; Feed = [string]$x.name; Protocol = $proto; Package = [string]$pk.name; Version = [string]$pv.version
                            IsLatest = [bool]$pv.isLatest; Listed = [bool]$pv.isListed
                            Views = Join-A2C @($pv.views | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_.name } | Sort-Object)
                            Source = $(if ($cached) { 'Upstream cache' } else { 'Published' })
                            Upstream = $(if ($cached) { [string]$upstream[([string]$pv.directUpstreamSourceId).ToLowerInvariant()] } else { '' })
                            PublishDate = Format-A2CAdoDate $pv.publishDate
                            PackageDownloads = $(if ($null -ne $met) { [long]$met.downloadCount } else { $null })
                            PackageLastDownloaded = $(if ($null -ne $met) { Format-A2CAdoDate $met.lastDownloaded } else { '' })
                            ExportedTo = $(if ($null -ne $ex) { [string]$ex.Path } else { '' }); ExportNote = $(if ($null -ne $ex) { [string]$ex.Note } else { '' })
                            PackageId = [string]$pk.id
                        })
                }
            }
            $read = ($null -ne $w.Items)
            $rp = $w.Retention
            $rows['feeds'].Add([ordered]@{
                    Organization = $on; Project = $proj; Scope = $scope; Feed = [string]$x.name; FeedId = [string]$x.id; Packages = $w.Packages
                    PublishedPackages = $(if ($read) { $published } else { $null }); CachedPackages = $(if ($read) { $cachedOnly } else { $null })
                    Versions = $(if ($read) { $versions } else { $null }); PackagesCapped = [bool]$w.Capped; Protocols = Join-A2C $protocols
                    LastPublished = $(if ($null -ne $lastPublished) { Format-A2CDate $lastPublished } else { '' })
                    UpstreamSources = Join-A2C @($x.upstreamSources | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_.name }); UpstreamEnabled = [bool]$x.upstreamEnabled
                    Views = $(if ($null -ne $w.Views) { Join-A2C $w.Views } else { '' })
                    MaxVersions = $(if ($null -ne $rp -and $null -ne $rp.countLimit) { [int]$rp.countLimit } else { $null })
                    KeepDownloadedDays = $(if ($null -ne $rp -and $null -ne $rp.daysToKeepRecentlyDownloadedPackages) { [int]$rp.daysToKeepRecentlyDownloadedPackages } else { $null })
                    Permissions = $(if ($null -ne $w.Permissions) { @($w.Permissions).Count } else { $null })
                })
            foreach ($pm in @($w.Permissions | Where-Object { $null -ne $_ })) {
                $idn = Get-A2CAdoIdentityName $pm
                $rows['feedPermissions'].Add([ordered]@{
                        Organization = $on; Project = $proj; Scope = $scope; Feed = [string]$x.name; FeedId = [string]$x.id
                        Identity = $idn.Name; IdentityScope = $idn.Scope; Role = [string]$pm.role; Inherited = [bool]$pm.isInheritedRole
                        IdentityId = [string]$pm.identityId
                    })
            }
        }
        # the TFVC paths of each pipeline (one array per pipeline)
        $tfvcUse = @(foreach ($w in $o.Pipelines) { $pl = Get-A2CAdoTfvcPaths $w.Item; if ($pl.Count -gt 0) { , $pl.ToArray() } })
        foreach ($tb in $o.Tfvc) {
            $used = @($tfvcUse | Where-Object { $mapped = $_; @($mapped | Where-Object { Test-A2CAdoTfvcPathOverlap $_ $tb.Path }).Count -gt 0 }).Count
            $rows['tfvc'].Add([ordered]@{
                    Organization = $on; Project = [string]$tb.Project.name; Path = $tb.Path; IsBranch = [bool]$tb.IsBranch; Parent = [string]$tb.Parent
                    Owner = [string]$tb.Owner; Created = Format-A2CAdoDate $tb.Created; LastChangeset = $tb.LastChangeset; LastChange = Format-A2CAdoDate $tb.LastChange
                    DaysSinceLastChange = Get-A2CAdoDaysSince $tb.LastChange; LastChangeBy = [string]$tb.LastChangeBy; Files = $tb.Files
                    SizeMB = $(if ($null -ne $tb.Bytes) { [math]::Round([double]$tb.Bytes / 1MB, 1) } else { $null }); FilesCapped = [bool]$tb.Capped
                    Pipelines = $used; ExportedTo = [string]$repoFolders[$on + '|tfvc|' + $tb.Path]
                })
        }
        foreach ($x in $o.WorkItems) {
            $rows['workItems'].Add([ordered]@{ Organization = $on; Project = [string]$x.Project.ProjectName; WorkItemType = [string]$x.WorkItemType; Count = [int]$x.Count })
        }
        $procById = @{}
        foreach ($x in $o.Processes) { $procById[([string]$x.typeId).ToLowerInvariant()] = $x }
        foreach ($x in $o.Processes) {
            $parent = ''
            $pt = ([string]$x.parentProcessTypeId).ToLowerInvariant()
            if ($pt -and $procById.ContainsKey($pt) -and $pt -ne ([string]$x.typeId).ToLowerInvariant()) { $parent = [string]$procById[$pt].name }
            $projs = @($x.projects | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_.name })
            $rows['processes'].Add([ordered]@{
                    Organization = $on; Process = [string]$x.name; Type = [string]$x.customizationType; Parent = $parent; IsDefault = [bool]$x.isDefault
                    Enabled = [bool]$x.isEnabled; Projects = $projs.Count; ProjectNames = Join-A2C $projs
                })
        }
    }
    # with no accessible organization only organizations.csv is written
    $collected = @($orgs | Where-Object { $_.Status -eq 'Collected' }).Count
    foreach ($f in $script:A2CAdoFiles) {
        if ($f -ne 'organizations' -and $collected -eq 0) { continue }
        Add-A2CRows ('ADO/' + $f + '.csv') $rows[$f]
    }
    Write-A2CLog -Level Ok ('Azure DevOps: {0} of {1} organization(s) collected -> ADO folder' -f $collected, $orgs.Count)
    # the project folders come from the export reports: say which ones did not run
    if ($collected -gt 0) {
        $missing = [System.Collections.Generic.List[string]]::new()
        foreach ($x in @(@('AzureDevOpsPipelines', 'pipelines'), @('AzureDevOpsRepos', 'Git and TFVC repositories'), @('AzureDevOpsPackages', 'packages'))) {
            if (-not (Test-A2CSelected $x[0])) { $missing.Add(('{0} (add {1} to -Reports)' -f $x[1], $x[0])) }
        }
        if ($missing.Count -gt 0) { Write-A2CLog -Level Detail ('Not exported in this run: ' + [string]::Join(', ', $missing)) }
    }
}

#endregion

#region ============================== 8. FINDINGS =====================================================

Register-A2CSchema 'findings.csv' 'Id Severity Category Title:note Count:num AffectedFile Recommendation:note LearnMore:url Detail:note'

$script:A2CFindingRules = [System.Collections.Generic.List[object]]::new()
$script:A2CSeverityOrder = @{ High = 0; Medium = 1; Low = 2; Info = 3 }

function Register-A2CFinding {
    # Evaluate returns $null/0 (nothing found) or @{ Count = n; Detail = '...' }.
    param([string] $Id, [ValidateSet('High', 'Medium', 'Low', 'Info')] [string] $Severity,
        [ValidateSet('Migration', 'Retirement', 'Cost', 'Security', 'Operations', 'Governance')] [string] $Category,
        [string] $Title, [string[]] $Needs, [string] $File, [string] $Recommendation, [string] $Url, [scriptblock] $Evaluate)
    $script:A2CFindingRules.Add([pscustomobject]@{ Id = $Id; Severity = $Severity; Category = $Category; Title = $Title; Needs = $Needs
            File = $File; Recommendation = $Recommendation; Url = $Url; Evaluate = $Evaluate })
}

function Invoke-A2CFindings {
    $notEvaluated = 0
    foreach ($rule in $script:A2CFindingRules) {
        $ok = $true
        foreach ($n in $rule.Needs) {
            if ($n -like 'Report:*') { if (-not (Test-A2CSelected $n.Substring(7))) { $ok = $false; break } }
            elseif (-not (Test-A2CDataset $n)) { $ok = $false; break }
        }
        if (-not $ok) { $notEvaluated++; continue }
        try {
            $res = & $rule.Evaluate
            if ($null -eq $res) { continue }
            $count = [int]$res.Count
            if ($count -le 0) { continue }
            $title = $rule.Title
            $script:A2C.Findings.Add([ordered]@{
                    Id = $rule.Id; Severity = $rule.Severity; Category = $rule.Category; Title = $title; Count = $count
                    AffectedFile = $rule.File; Recommendation = $rule.Recommendation; LearnMore = $rule.Url; Detail = [string]$res.Detail
                })
        }
        catch { Write-A2CLog -Level Warn ('Finding {0} could not be evaluated: {1}' -f $rule.Id, $_.Exception.Message) }
    }
    $sorted = @($script:A2C.Findings | Sort-Object @{ Expression = { $script:A2CSeverityOrder[$_.Severity] } }, @{ Expression = { $_.Category } }, @{ Expression = { -1 * $_.Count } })
    $script:A2C.Findings.Clear()
    foreach ($f in $sorted) { $script:A2C.Findings.Add($f) }
    $high = @($sorted | Where-Object { $_.Severity -eq 'High' }).Count
    Write-A2CLog -Level Ok ('{0} findings ({1} high); {2} rules not evaluated because their data was not selected' -f $sorted.Count, $high, $notEvaluated)
    $script:A2C.Data['FindingsNotEvaluated'] = $notEvaluated
}

function Get-A2CTopText {
    # "a (3), b (2), ..." from a list of strings
    param($Items, [int] $Top = 5)
    $h = @{}
    foreach ($i in $Items) { if ($i) { $h[[string]$i] = [int]$h[[string]$i] + 1 } }
    $parts = @($h.GetEnumerator() | Sort-Object @{ Expression = { -1 * $_.Value } }, @{ Expression = { $_.Key } } | Select-Object -First $Top | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value })
    $t = [string]::Join(', ', $parts)
    if ($h.Count -gt $Top) { $t += ', ...' }
    return $t
}

function New-A2CFindingResult {
    param([int] $Count, [string] $Detail = '')
    if ($Count -le 0) { return $null }
    return [pscustomobject]@{ Count = $Count; Detail = $Detail }
}

function ConvertTo-A2CIpRange {
    # IPv4 CIDR -> @(start, end) as UInt32; $null for IPv6/invalid
    param([string] $Cidr)
    if ($Cidr -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$') { return $null }
    $ip = ([uint32]$Matches[1] -shl 24) + ([uint32]$Matches[2] -shl 16) + ([uint32]$Matches[3] -shl 8) + [uint32]$Matches[4]
    $bits = [int]$Matches[5]
    $size = [math]::Pow(2, 32 - $bits)
    $start = [double]([math]::Floor($ip / $size) * $size)
    return @($start, ($start + $size - 1))
}

# ---- Retirement ----
Register-A2CFinding -Id 'RET-01' -Severity High -Category Retirement -Title 'Resources on services or features that are already retired' -Needs @('Report:Retirements') -File 'retirements.csv' `
    -Recommendation 'Migrate these resources first - retired features lose support and SLA and can stop working at any time.' -Url 'https://learn.microsoft.com/azure/advisor/advisor-how-to-use-service-upgrade-retirement-recommendations' `
    -Evaluate { $r = @((Get-A2CRows 'retirements.csv') | Where-Object { $_['Status'] -eq 'Retired' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Feature'] })) }
Register-A2CFinding -Id 'RET-02' -Severity Medium -Category Retirement -Title 'Resources affected by retirements in the next 12 months' -Needs @('Report:Retirements') -File 'retirements.csv' `
    -Recommendation 'Plan and budget the upgrades now; many of these are forced migrations with fixed dates.' -Url 'https://learn.microsoft.com/azure/advisor/advisor-workbook-service-retirement' `
    -Evaluate { $r = @((Get-A2CRows 'retirements.csv') | Where-Object { $_['Status'] -like 'Due within*' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { '{0} {1}' -f $_['Feature'], $_['RetirementDate'] })) }
Register-A2CFinding -Id 'RET-03' -Severity Low -Category Retirement -Title 'Resources affected by later announced retirements' -Needs @('Report:Retirements') -File 'retirements.csv' `
    -Recommendation 'Include these in the modernization roadmap.' -Url '' `
    -Evaluate { $r = @((Get-A2CRows 'retirements.csv') | Where-Object { $_['Status'] -eq 'Later' -or $_['Status'] -eq 'Check' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Feature'] })) }

# ---- Migration ----
Register-A2CFinding -Id 'MIG-01' -Severity High -Category Migration -Title 'Resources whose type cannot be moved to another subscription' -Needs @('Report:MoveSupport', 'MoveData') -File 'moveSupport.csv' `
    -Recommendation 'These resources must be redeployed (not moved) when you restructure subscriptions - plan the rebuild effort.' -Url 'https://learn.microsoft.com/azure/azure-resource-manager/management/move-support-resources' `
    -Evaluate { $r = @((Get-A2CRows 'moveSupport.csv') | Where-Object { $_['CanMoveToOtherSubscription'] -eq 'No' }); $n = 0; foreach ($x in $r) { $n += [int]$x['Resources'] }; New-A2CFindingResult $n ([string]::Join(', ', @($r | Sort-Object { -1 * [int]$_['Resources'] } | Select-Object -First 6 | ForEach-Object { '{0} ({1})' -f $_['ResourceType'], $_['Resources'] }))) }
Register-A2CFinding -Id 'MIG-02' -Severity Medium -Category Migration -Title 'Resources that reference resources in other resource groups or subscriptions' -Needs @('Report:CrossReferences') -File 'crossReferences.csv' `
    -Recommendation 'Dependent resources must move together (same move operation) - group them into migration waves.' -Url 'https://learn.microsoft.com/azure/azure-resource-manager/management/move-resource-group-and-subscription' `
    -Evaluate { $r = @((Get-A2CRows 'crossReferences.csv')); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Relation'] })) }
Register-A2CFinding -Id 'MIG-03' -Severity Medium -Category Migration -Title 'References to resources that no longer exist' -Needs @('Report:CrossReferences') -File 'crossReferences.csv' `
    -Recommendation 'Clean up dangling references before moving resources; they often make move validation fail.' -Url '' `
    -Evaluate { $r = @((Get-A2CRows 'crossReferences.csv') | Where-Object { $_['TargetExists'] -like 'No*' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['TargetType'] })) }
Register-A2CFinding -Id 'MIG-04' -Severity High -Category Migration -Title 'Items that break when a subscription moves to another Entra tenant' -Needs @('Report:TenantTransfer') -File 'tenantTransferImpact.csv' `
    -Recommendation 'Required reading before an M&A or tenant-to-tenant move: identities, Key Vaults, RBAC and Entra-integrated services must be prepared.' -Url 'https://learn.microsoft.com/azure/role-based-access-control/transfer-subscription' `
    -Evaluate { $r = @((Get-A2CRows 'tenantTransferImpact.csv') | Where-Object { $_['Impact'] -eq 'High' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Category'] })) }
Register-A2CFinding -Id 'MIG-05' -Severity Medium -Category Migration -Title 'Azure Policy restricts regions, resource types or VM sizes' -Needs @('Report:Policy') -File 'policyAssignments.csv' `
    -Recommendation 'Check the target regions and SKUs of the migration against these policies (or plan exemptions).' -Url 'https://learn.microsoft.com/azure/governance/policy/samples/built-in-policies' `
    -Evaluate { $r = @($script:A2C.Data['PolicyRestrictions']); New-A2CFindingResult $r.Count ([string]::Join(' | ', @($r | Select-Object -First 4 | ForEach-Object { '{0}: {1}' -f $_.Policy, $_.Values }))) }
Register-A2CFinding -Id 'MIG-06' -Severity Medium -Category Migration -Title 'Overlapping VNet address spaces' -Needs @('Resources') -File 'vnets.csv' `
    -Recommendation 'Overlapping ranges prevent peering and hybrid connectivity - re-address before consolidating networks.' -Url 'https://learn.microsoft.com/azure/virtual-network/virtual-network-peering-overview' `
    -Evaluate {
        $ranges = [System.Collections.Generic.List[object]]::new()
        foreach ($v in (Get-A2CResourcesOfType 'microsoft.network/virtualnetworks')) {
            foreach ($c in @((Get-A2CProps $v).addressSpace.addressPrefixes)) { $x = ConvertTo-A2CIpRange ([string]$c); if ($null -ne $x) { $ranges.Add([pscustomobject]@{ Vnet = [string]$v.name; Id = [string]$v.id; Cidr = [string]$c; S = $x[0]; E = $x[1] }) } }
        }
        $pairs = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt $ranges.Count; $i++) { for ($j = $i + 1; $j -lt $ranges.Count; $j++) {
                $a = $ranges[$i]; $b = $ranges[$j]
                if ($a.Id -ne $b.Id -and $a.S -le $b.E -and $b.S -le $a.E) { $pairs.Add(('{0} {1} / {2} {3}' -f (Get-A2CMaskedName 'name' $a.Vnet), $a.Cidr, (Get-A2CMaskedName 'name' $b.Vnet), $b.Cidr)) } } }
        New-A2CFindingResult $pairs.Count ([string]::Join('; ', @($pairs | Select-Object -First 4)))
    }
Register-A2CFinding -Id 'MIG-07' -Severity Medium -Category Migration -Title 'VMs not protected by Azure Backup' -Needs @('Report:VMs', 'BackupItems') -File 'vms.csv' `
    -Recommendation 'Protect workloads before migration waves and verify restore points exist.' -Url 'https://learn.microsoft.com/azure/backup/backup-azure-vms-introduction' `
    -Evaluate { $r = @((Get-A2CRows 'vms.csv') | Where-Object { $_['BackupProtected'] -eq $false }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'MIG-08' -Severity Low -Category Migration -Title 'Resources not in a Succeeded provisioning state' -Needs @('Resources') -File 'allResources.csv' `
    -Recommendation 'Resources in Failed/Updating state block moves - fix them first.' -Url 'https://learn.microsoft.com/azure/azure-resource-manager/management/move-resource-group-and-subscription' `
    -Evaluate { $r = @($script:A2C.Data['Resources'] | Where-Object { $_.provisioningState -and @('Succeeded', 'Ready', 'Running', 'Completed') -notcontains [string]$_.provisioningState }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_.provisioningState })) }
Register-A2CFinding -Id 'MIG-09' -Severity Low -Category Migration -Title 'Management locks (block moves and deletions)' -Needs @('Report:Locks') -File 'locks.csv' `
    -Recommendation 'Plan to remove and re-apply locks around move operations.' -Url 'https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources' `
    -Evaluate { $r = @((Get-A2CRows 'locks.csv')); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Level'] })) }

# ---- Security ----
Register-A2CFinding -Id 'SEC-01' -Severity High -Category Security -Title 'NSG rules expose management ports to the Internet' -Needs @('Report:NetworkSecurity') -File 'nsgRules.csv' `
    -Recommendation 'Close RDP/SSH/database ports to the Internet; use Azure Bastion, VPN or just-in-time access.' -Url 'https://learn.microsoft.com/azure/bastion/bastion-overview' `
    -Evaluate { $r = @((Get-A2CRows 'nsgRules.csv') | Where-Object { $_['Risk'] -like 'High*' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Risk'] -replace '^High: ', '' })) }
Register-A2CFinding -Id 'SEC-02' -Severity Medium -Category Security -Title 'NSG rules allow other inbound traffic from the Internet' -Needs @('Report:NetworkSecurity') -File 'nsgRules.csv' `
    -Recommendation 'Confirm these rules are intended (web front ends) and protected by a WAF/firewall.' -Url '' `
    -Evaluate { $r = @((Get-A2CRows 'nsgRules.csv') | Where-Object { $_['Risk'] -like 'Medium*' }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'SEC-03' -Severity High -Category Security -Title 'Role assignments of deleted identities (orphaned RBAC)' -Needs @('Report:RBAC', 'Principals') -File 'RBAC_role_assignments.csv' `
    -Recommendation 'Remove orphaned assignments - they clutter access reviews and complicate tenant moves.' -Url 'https://learn.microsoft.com/azure/role-based-access-control/troubleshooting' `
    -Evaluate { $r = @((Get-A2CRows 'RBAC_role_assignments.csv') | Where-Object { $_['PrincipalStatus'] -like 'NotFound*' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['RoleDefinitionName'] })) }
Register-A2CFinding -Id 'SEC-04' -Severity High -Category Security -Title 'Guest accounts with privileged Azure roles (Owner, Contributor, UAA)' -Needs @('Report:RBAC', 'Principals') -File 'RBAC_role_assignments.csv' `
    -Recommendation 'Review external accounts with write or access-management rights; prefer PIM with approval.' -Url 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure' `
    -Evaluate { $r = @((Get-A2CRows 'RBAC_role_assignments.csv') | Where-Object { $_['UserType'] -eq 'Guest' -and $_['IsPrivilegedRole'] -eq $true }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['RoleDefinitionName'] })) }
Register-A2CFinding -Id 'SEC-05' -Severity Medium -Category Security -Title 'Custom roles with wildcard (*) actions' -Needs @('Report:RBAC') -File 'RBAC_roles.csv' `
    -Recommendation 'Replace wildcards with explicit actions to follow least privilege.' -Url 'https://learn.microsoft.com/azure/role-based-access-control/custom-roles' `
    -Evaluate { $r = @((Get-A2CRows 'RBAC_roles.csv') | Where-Object { $_['IsCustom'] -eq $true -and $_['HasWildcardActions'] -eq $true }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'SEC-06' -Severity High -Category Security -Title 'Expired app secrets or certificates' -Needs @('Report:EntraApps') -File 'credentials.csv' `
    -Recommendation 'Remove expired credentials and check the apps still work; move to certificates or workload identity federation.' -Url 'https://learn.microsoft.com/entra/workload-id/workload-identity-federation' `
    -Evaluate { $r = @((Get-A2CRows 'credentials.csv') | Where-Object { $_['Status'] -eq 'Expired' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['OwnerName'] })) }
Register-A2CFinding -Id 'SEC-07' -Severity Medium -Category Security -Title 'App secrets or certificates expiring within 30 days' -Needs @('Report:EntraApps') -File 'credentials.csv' `
    -Recommendation 'Renew before expiry to avoid outages; automate rotation (Key Vault) where possible.' -Url '' `
    -Evaluate { $r = @((Get-A2CRows 'credentials.csv') | Where-Object { $_['Status'] -eq 'Expires within 30 days' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['OwnerName'] })) }
Register-A2CFinding -Id 'SEC-08' -Severity High -Category Security -Title 'Non-Microsoft apps with critical API permissions' -Needs @('Report:EntraApps') -File 'appPermissions.csv' `
    -Recommendation 'Review apps that can read all mail, change the directory or grant themselves permissions.' -Url 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions' `
    -Evaluate { $r = @((Get-A2CRows 'appPermissions.csv') | Where-Object { $_['Risk'] -eq 'Critical' -and $_['ClientPublisher'] -ne 'Microsoft' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Permission'] })) }
Register-A2CFinding -Id 'SEC-09' -Severity High -Category Security -Title 'Guest accounts with Entra directory roles' -Needs @('Report:EntraRoles') -File 'directoryRoles.csv' `
    -Recommendation 'External accounts should not hold directory roles - use dedicated member admin accounts.' -Url 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
    -Evaluate { $r = @((Get-A2CRows 'directoryRoles.csv') | Where-Object { $_['IsGuest'] -eq $true }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['RoleName'] })) }
Register-A2CFinding -Id 'SEC-10' -Severity Medium -Category Security -Title 'More than 4 Global Administrators' -Needs @('Report:EntraRoles') -File 'directoryRoles.csv' `
    -Recommendation 'Microsoft recommends fewer than five Global Administrators (plus break-glass accounts).' -Url 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
    -Evaluate { $r = @((Get-A2CRows 'directoryRoles.csv') | Where-Object { $_['RoleName'] -eq 'Global Administrator' }); if ($r.Count -gt 4) { New-A2CFindingResult $r.Count '' } }
Register-A2CFinding -Id 'SEC-11' -Severity Medium -Category Security -Title 'Storage accounts that allow anonymous blob access' -Needs @('Report:Storage') -File 'storageAccounts.csv' `
    -Recommendation 'Set AllowBlobPublicAccess to false unless a public container is really needed.' -Url 'https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent' `
    -Evaluate { $r = @((Get-A2CRows 'storageAccounts.csv') | Where-Object { $_['AllowBlobPublicAccess'] -ne 'False' }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'SEC-12' -Severity Medium -Category Security -Title 'Services accepting TLS older than 1.2' -Needs @('Resources') -File 'storageAccounts.csv, sqlServers.csv, appServiceApps.csv' `
    -Recommendation 'Enforce TLS 1.2+ (storage, SQL, App Service); TLS 1.0/1.1 is being retired across Azure.' -Url 'https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version' `
    -Evaluate {
        $n = 0; $l = [System.Collections.Generic.List[string]]::new()
        foreach ($r in (Get-A2CResourcesOfType 'microsoft.storage/storageaccounts')) { if (@('TLS1_0', 'TLS1_1', '') -contains [string](Get-A2CProps $r).minimumTlsVersion) { $n++; $l.Add('storage') } }
        foreach ($r in (Get-A2CResourcesOfType 'microsoft.sql/servers')) { if (@('1.0', '1.1') -contains [string](Get-A2CProps $r).minimalTlsVersion) { $n++; $l.Add('SQL') } }
        $cfg = $script:A2C.Data['AppConfigBySite']
        if ($null -ne $cfg) { foreach ($c in $cfg.Values) { if (@('1.0', '1.1') -contains [string]$c.minTlsVersion) { $n++; $l.Add('App Service') } } }
        New-A2CFindingResult $n (Get-A2CTopText $l)
    }
Register-A2CFinding -Id 'SEC-13' -Severity Medium -Category Security -Title 'Key Vaults without purge protection' -Needs @('Report:KeyVault') -File 'keyVaults.csv' `
    -Recommendation 'Enable purge protection so deleted keys and secrets cannot be destroyed during the retention period.' -Url 'https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview' `
    -Evaluate { $r = @((Get-A2CRows 'keyVaults.csv') | Where-Object { $_['PurgeProtection'] -ne 'True' }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'SEC-14' -Severity Low -Category Security -Title 'Resources without diagnostic settings' -Needs @('Diagnostics') -File 'allResources.csv (DiagStatus)' `
    -Recommendation 'Send logs and metrics of important resources to Log Analytics (use Azure Policy to enforce it).' -Url 'https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings' `
    -Evaluate { $d = $script:A2C.Data['Diag']; $r = @($script:A2C.Data['Resources'] | Where-Object { $x = $d[([string]$_.id).ToLowerInvariant()]; $null -ne $x -and $x.Status -eq 'NotConfigured' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { Get-A2CTypeCased -Id ([string]$_.id) -Fallback ([string]$_.type) })) }
Register-A2CFinding -Id 'SEC-15' -Severity Medium -Category Security -Title 'Subscriptions without activity log export' -Needs @('Diagnostics') -File 'allResources.csv (subscription rows)' `
    -Recommendation 'Export the activity log of every subscription to a central Log Analytics workspace.' -Url 'https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log' `
    -Evaluate { $d = $script:A2C.Data['Diag']; $r = @($script:A2C.Data['Subscriptions'] | Where-Object { $x = $d[('/subscriptions/' + $_.Id)]; $null -ne $x -and $x.Status -eq 'NotConfigured' }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'SEC-16' -Severity Medium -Category Security -Title 'Enabled users without sign-in for 90+ days' -Needs @('Report:EntraUsers') -File 'entraUsers.csv' `
    -Recommendation 'Disable or remove stale accounts (Microsoft suggests a 90-180 day window).' -Url 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
    -Evaluate { $r = @((Get-A2CRows 'entraUsers.csv') | Where-Object { $_['SignInDataAvailable'] -eq $true -and $_['AccountEnabled'] -eq 'True' -and $null -ne $_['DaysSinceLastSignIn'] -and [int]$_['DaysSinceLastSignIn'] -ge 90 }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'SEC-17' -Severity Low -Category Security -Title 'Guest invitations never accepted' -Needs @('Report:EntraUsers') -File 'entraUsers.csv' `
    -Recommendation 'Remove pending guest invitations that are no longer needed.' -Url '' `
    -Evaluate { $r = @((Get-A2CRows 'entraUsers.csv') | Where-Object { $_['ExternalUserState'] -eq 'PendingAcceptance' }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'SEC-18' -Severity Medium -Category Security -Title 'App registrations without owners' -Needs @('Report:EntraApps') -File 'entraApplications.csv' `
    -Recommendation 'Assign at least two owners so every app has an accountable team.' -Url '' `
    -Evaluate { $r = @((Get-A2CRows 'entraApplications.csv') | Where-Object { $null -ne $_['OwnerCount'] -and [int]$_['OwnerCount'] -eq 0 }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['DisplayName'] })) }
Register-A2CFinding -Id 'SEC-19' -Severity Medium -Category Security -Title 'Web apps that allow HTTP or unencrypted FTP' -Needs @('Report:AppService') -File 'appServiceApps.csv' `
    -Recommendation 'Enable HTTPS only and set FTP to FTPS only or disabled.' -Url 'https://learn.microsoft.com/azure/app-service/overview-security' `
    -Evaluate { $r = @((Get-A2CRows 'appServiceApps.csv') | Where-Object { $_['HttpsOnly'] -eq 'False' -or $_['FtpsState'] -eq 'AllAllowed' }); New-A2CFindingResult $r.Count '' }

# ---- Cost ----
Register-A2CFinding -Id 'COST-01' -Severity Medium -Category Cost -Title 'Orphaned or unused resources' -Needs @('Report:Orphans') -File 'orphans.csv' `
    -Recommendation 'Delete or deallocate what is not needed - less cost and less to migrate.' -Url 'https://github.com/dolevshor/azure-orphan-resources' `
    -Evaluate {
        $r = @((Get-A2CRows 'orphans.csv'))
        $cost = 0.0; foreach ($x in $r) { if ($x['Cost']) { $cost += [double]$x['Cost'] } }
        $d = Get-A2CTopText @($r | ForEach-Object { $_['Category'] }) 6
        if ($cost -gt 0) { $d = ('{0:N2} cost in the period; ' -f $cost) + $d }
        New-A2CFindingResult $r.Count $d
    }
Register-A2CFinding -Id 'COST-02' -Severity Medium -Category Cost -Title 'Azure Advisor cost recommendations' -Needs @('Advisor') -File 'advisor.csv' `
    -Recommendation 'Review right-sizing, reservations and shutdown recommendations.' -Url 'https://learn.microsoft.com/azure/advisor/advisor-cost-recommendations' `
    -Evaluate {
        $r = @($script:A2C.Data['Advisor'] | Where-Object { $_.Category -eq 'Cost' })
        $s = 0.0; $cur = ''; foreach ($x in $r) { if ($x.AnnualSavings) { $s += [double]$x.AnnualSavings; $cur = $x.Currency } }
        New-A2CFindingResult $r.Count $(if ($s -gt 0) { ('Estimated annual savings {0:N0} {1}' -f $s, $cur) } else { '' })
    }
Register-A2CFinding -Id 'COST-03' -Severity Info -Category Cost -Title 'Windows VMs without Azure Hybrid Benefit' -Needs @('Report:VMs') -File 'vms.csv' `
    -Recommendation 'If you own Windows Server licenses with Software Assurance, Azure Hybrid Benefit cuts compute cost significantly.' -Url 'https://learn.microsoft.com/azure/virtual-machines/windows/hybrid-use-benefit-licensing' `
    -Evaluate { $r = @((Get-A2CRows 'vms.csv') | Where-Object { $_['OsType'] -eq 'Windows' -and $_['HybridBenefit'] -eq $false }); New-A2CFindingResult $r.Count '' }

# ---- Governance ----
Register-A2CFinding -Id 'GOV-01' -Severity Medium -Category Governance -Title 'Policy exemptions expired or expiring within 30 days' -Needs @('Report:Policy') -File 'policyExemptions.csv' `
    -Recommendation 'Renew or remove exemptions; expired exemptions hide nothing but clutter compliance data.' -Url 'https://learn.microsoft.com/azure/governance/policy/concepts/exemption-structure' `
    -Evaluate { $r = @((Get-A2CRows 'policyExemptions.csv') | Where-Object { $_['Status'] -eq 'Expired' -or $_['Status'] -like 'Expires*' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Status'] })) }
Register-A2CFinding -Id 'GOV-02' -Severity Medium -Category Governance -Title 'Resources non-compliant with Azure Policy' -Needs @('Report:Policy', 'PolicyStates') -File 'policyCompliance.csv' `
    -Recommendation 'Remediate or exempt; top assignments by non-compliance are in policyAssignments.csv.' -Url 'https://learn.microsoft.com/azure/governance/policy/how-to/get-compliance-data' `
    -Evaluate { $r = @((Get-A2CRows 'policyCompliance.csv')); $u = Get-A2CUnique @($r | ForEach-Object { $_['ResourceId'] }); New-A2CFindingResult $u.Count (Get-A2CTopText @($r | ForEach-Object { $_['Assignment'] }) 3) }
Register-A2CFinding -Id 'GOV-03' -Severity Low -Category Governance -Title 'Policy assignments in DoNotEnforce mode' -Needs @('Report:Policy') -File 'policyAssignments.csv' `
    -Recommendation 'Decide whether these should be enforced.' -Url '' `
    -Evaluate { $r = @((Get-A2CRows 'policyAssignments.csv') | Where-Object { $_['EnforcementMode'] -eq 'DoNotEnforce' }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'GOV-04' -Severity Low -Category Governance -Title 'Custom policy definitions or initiatives that are not assigned' -Needs @('Report:Policy') -File 'policyDefinitions.csv' `
    -Recommendation 'Remove unused custom definitions to simplify governance.' -Url '' `
    -Evaluate { $r = @(@((Get-A2CRows 'policyDefinitions.csv')) + @((Get-A2CRows 'policySetDefinitions.csv')) | Where-Object { $_['PolicyType'] -eq 'Custom' -and [int]$_['AssignmentCount'] -eq 0 }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'GOV-05' -Severity Medium -Category Governance -Title 'Deprecated policy definitions still assigned' -Needs @('Report:Policy') -File 'policyDefinitions.csv' `
    -Recommendation 'Replace deprecated policies with their current versions.' -Url '' `
    -Evaluate { $r = @((Get-A2CRows 'policyDefinitions.csv') | Where-Object { $_['Deprecated'] -eq $true -and [int]$_['AssignmentCount'] -gt 0 }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'GOV-06' -Severity Low -Category Governance -Title 'Subscriptions directly under the tenant root management group' -Needs @('Containers') -File 'subscriptions.csv' `
    -Recommendation 'Place subscriptions in a management group hierarchy (landing zones) to apply governance consistently.' -Url 'https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/design-area/resource-org-management-groups' `
    -Evaluate { $r = @($script:A2C.Data['Subscriptions'] | Where-Object { @($_.MgChain).Count -gt 0 -and $_.MgChain[0].Name -eq $script:A2C.TenantId }); New-A2CFindingResult $r.Count '' }
Register-A2CFinding -Id 'GOV-07' -Severity Low -Category Governance -Title 'Resources without any tags' -Needs @('Resources') -File 'allResources.csv' `
    -Recommendation 'Tag owner, application and cost center - it speeds up migration planning and cost allocation.' -Url 'https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging' `
    -Evaluate { $all = @($script:A2C.Data['Resources']); $r = @($all | Where-Object { $null -eq $_.tags -or @($_.tags.PSObject.Properties).Count -eq 0 }); if ($all.Count -gt 0) { New-A2CFindingResult $r.Count ('{0:P0} of resources' -f ($r.Count / $all.Count)) } }

# ---- Azure DevOps ----
Register-A2CFinding -Id 'ADO-01' -Severity High -Category Security -Title 'Public Azure DevOps projects' -Needs @('Report:AzureDevOps') -File 'ADO/projects.csv' `
    -Recommendation 'Make the projects private unless they are meant to be public: anyone can read the code, pipelines and work items of a public project.' -Url 'https://learn.microsoft.com/azure/devops/organizations/projects/make-project-public' `
    -Evaluate { $r = @((Get-A2CRows 'ADO/projects.csv') | Where-Object { $_['Visibility'] -eq 'public' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Organization'] })) }
Register-A2CFinding -Id 'ADO-02' -Severity Medium -Category Security -Title 'Azure DevOps service connections that sign in with a service principal secret' -Needs @('Report:AzureDevOps') -File 'ADO/serviceConnections.csv' `
    -Recommendation 'Convert them to workload identity federation: there is no secret to leak, expire or renew.' -Url 'https://learn.microsoft.com/azure/devops/pipelines/release/configure-workload-identity' `
    -Evaluate { $r = @((Get-A2CRows 'ADO/serviceConnections.csv') | Where-Object { $_['SecretBased'] -eq $true }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['Type'] })) }
Register-A2CFinding -Id 'ADO-03' -Severity Medium -Category Cost -Title 'Azure DevOps users with a Basic (or Basic + Test Plans) license and no sign-in for 90 days' -Needs @('Report:AzureDevOps') -File 'ADO/users.csv' `
    -Recommendation 'Change them to Stakeholder or remove them: beyond the free users, these licenses are billed every month.' -Url 'https://learn.microsoft.com/azure/devops/organizations/billing/buy-basic-access-add-users' `
    -Evaluate {
        $r = @((Get-A2CRows 'ADO/users.csv') | Where-Object {
                $days = "$($_['DaysSinceLastAccess'])"
                $_['Paid'] -eq $true -and (($days -ne '' -and [int]$days -ge 90) -or ($days -eq '' -and [int](Get-A2CAdoDaysSince $_['DateAdded']) -ge 90))
            })
        New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { $_['License'] }))
    }
Register-A2CFinding -Id 'ADO-04' -Severity Medium -Category Operations -Title 'Self-hosted Azure DevOps agents that are offline or on agent version 2' -Needs @('Report:AzureDevOps') -File 'ADO/agents.csv' `
    -Recommendation 'Remove agents whose machines are gone and upgrade old agents to the current version.' -Url 'https://learn.microsoft.com/azure/devops/pipelines/agents/agents' `
    -Evaluate { $r = @((Get-A2CRows 'ADO/agents.csv') | Where-Object { $_['Status'] -ne 'online' -or $_['Outdated'] -eq $true }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { if ($_['Outdated'] -eq $true) { 'agent version 2' } else { [string]$_['Status'] } })) }
Register-A2CFinding -Id 'ADO-05' -Severity Low -Category Migration -Title 'Classic Azure DevOps pipelines (classic build and release pipelines)' -Needs @('Report:AzureDevOps') -File 'ADO/pipelines.csv' `
    -Recommendation 'Plan their move to YAML pipelines: classic pipelines are not versioned with the code and take more work to migrate.' -Url 'https://learn.microsoft.com/azure/devops/pipelines/release/from-classic-pipelines' `
    -Evaluate { $b = @((Get-A2CRows 'ADO/pipelines.csv') | Where-Object { $_['Type'] -eq 'Classic' }).Count; $rl = (Get-A2CRows 'ADO/releasePipelines.csv').Count; New-A2CFindingResult ($b + $rl) ('{0} classic build, {1} classic release' -f $b, $rl) }
Register-A2CFinding -Id 'ADO-07' -Severity Medium -Category Migration -Title 'Azure DevOps projects that still use TFVC (Team Foundation Version Control)' -Needs @('Report:AzureDevOps') -File 'ADO/tfvc.csv' `
    -Recommendation 'Plan the move to Git: decide which branches and how much history to keep and remove large binaries first. The Azure DevOps import takes one branch with up to 180 days of history.' -Url 'https://learn.microsoft.com/azure/devops/repos/git/import-from-tfvc' `
    -Evaluate { $r = @(Get-A2CRows 'ADO/tfvc.csv'); $prj = @($r | ForEach-Object { [string]$_['Organization'] + '/' + [string]$_['Project'] } | Select-Object -Unique); New-A2CFindingResult $prj.Count ('branches per project: ' + (Get-A2CTopText @($r | ForEach-Object { $_['Project'] }))) }
Register-A2CFinding -Id 'ADO-06' -Severity Medium -Category Security -Title 'Personal Microsoft accounts and guests in Azure DevOps organizations' -Needs @('Report:AzureDevOps') -File 'ADO/users.csv' `
    -Recommendation 'Review them: personal Microsoft accounts are outside your Entra ID controls (MFA, Conditional Access, offboarding).' -Url 'https://learn.microsoft.com/azure/devops/organizations/accounts/access-with-azure-ad' `
    -Evaluate { $r = @((Get-A2CRows 'ADO/users.csv') | Where-Object { $_['Origin'] -eq 'Microsoft account' -or $_['UserType'] -eq 'guest' }); New-A2CFindingResult $r.Count (Get-A2CTopText @($r | ForEach-Object { if ($_['Origin'] -eq 'Microsoft account') { 'Microsoft account' } else { 'guest' } })) }

#endregion

#region ============================== 9. OUTPUT =======================================================

Register-A2CSchema 'coverage.csv' 'Area:note Status Items:num Detail:note'

function Test-A2CModuleAvailable {
    param([string] $Name)
    return [bool](Get-Module -ListAvailable -Name $Name)
}

function Get-A2COutputRows {
    # Rows as written to files: masked copies under -Mask (cached), originals otherwise.
    param([string] $File)
    if ($script:A2C.Options.Mask) {
        if ($null -eq $script:A2C.Data['MaskedOut']) { $script:A2C.Data['MaskedOut'] = @{} }
        $c = $script:A2C.Data['MaskedOut'][$File]
        if ($null -eq $c) { $c = Protect-A2CRows -File $File -Rows (Get-A2CRawRows $File); $script:A2C.Data['MaskedOut'][$File] = $c }
        return , $c
    }
    return , (Get-A2CRawRows $File)
}

function Save-A2CExtraFiles {
    Add-A2CRows 'findings.csv' $script:A2C.Findings
    Save-A2CCsv -File 'findings.csv'
    Add-A2CRows 'coverage.csv' $script:A2C.Coverage
    Save-A2CCsv -File 'coverage.csv'
    $tl = $script:A2C.Data['TagList']
    if ($null -ne $tl) {
        if ($script:A2C.Options.Mask) { $tl = Protect-A2CTagList $tl }
        [void](Save-A2CText -File 'tagList.json' -Text (ConvertTo-Json -InputObject $tl -Depth 5) -NoBom)
        $script:A2C.Files.Add([pscustomobject]@{ File = 'tagList.json'; Rows = $tl.Count; Path = [IO.Path]::Combine($script:A2C.OutDir, 'tagList.json') })
    }
}

function Save-A2CRunInfo {
    $o = $script:A2C.Options
    $mask = [bool]$o.Mask
    $fin = [DateTime]::UtcNow
    $tenant = $script:A2C.TenantId
    if ($mask -and $tenant) { $tenant = Get-A2CMaskGuid $tenant }
    $skipped = [System.Collections.Generic.List[object]]::new()
    $skList = $script:A2C.Data['SubscriptionsSkipped']
    if ($null -ne $skList) {
        foreach ($s in $skList) {
            $sid = [string]$s.Id
            $reason = [string]$s.SkipReason
            if ($mask) { $sid = Get-A2CMaskGuid $sid; $reason = Protect-A2CValue -Kind 'note' -Value $reason }
            $skipped.Add([ordered]@{ id = $sid; reason = $reason })
        }
    }
    $findingCounts = [ordered]@{}
    foreach ($sev in @('High', 'Medium', 'Low', 'Info')) { $findingCounts[$sev] = @($script:A2C.Findings | Where-Object { $_.Severity -eq $sev }).Count }
    $coverage = $script:A2C.Coverage
    if ($mask) { $coverage = Get-A2COutputRows 'coverage.csv' }
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $script:A2C.Errors) { if ($mask) { $errors.Add('[masked]') } else { $errors.Add($e) } }
    $files = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $script:A2C.Files) { $files.Add([ordered]@{ file = $f.File; rows = $f.Rows }) }
    $stages = [System.Collections.Generic.List[object]]::new()
    foreach ($st in $script:A2C.Stages) {
        $c = [ordered]@{}
        foreach ($k in $st.Keys) { $c[$k] = $st[$k] }
        if ($mask -and $c['Note']) { $c['Note'] = Protect-A2CNote ([string]$c['Note']) }
        $stages.Add($c)
    }
    $account = $script:A2C.Account
    if ($mask) { $account = '[masked]' }
    $info = [ordered]@{
        tool          = 'azure2csv'
        version       = $script:A2CVersion
        startedUtc    = Format-A2CDate $script:A2C.StartedUtc
        finishedUtc   = Format-A2CDate $fin
        durationSec   = [math]::Round(($fin - $script:A2C.StartedUtc).TotalSeconds, 1)
        host          = $script:A2C.Env
        tenantId      = $tenant
        account       = $account
        options       = [ordered]@{
            profile = $o.Profile; reports = @($o.Reports); addReports = @($o.AddReports); skipReports = @($o.SkipReports)
            selected = @($script:A2C.Selected); datasets = @($script:A2C.Datasets); costDays = $o.CostDays; mask = $mask; zip = [bool]$o.Zip
            noExcel = [bool]$o.NoExcel; noHtml = [bool]$o.NoHtml; subscriptionFilter = @($o.SubscriptionId).Count; managementGroupFilter = [bool]$o.ManagementGroupId
        }
        subscriptions = [ordered]@{ inScope = @($script:A2C.Data['Subscriptions']).Count; skipped = $skipped.ToArray() }
        stages        = $stages.ToArray()
        apiCalls      = $script:A2C.Stats
        files         = $files.ToArray()
        findings      = $findingCounts
        coverage      = @($coverage)
        warnings      = $script:A2C.Warnings.Count
        errors        = $errors.ToArray()
    }
    [void](Save-A2CText -File ($script:A2C.RunStamp + '__run.json') -Text (ConvertTo-Json -InputObject $info -Depth 8) -NoBom)
}

function Open-A2CGeneralLog {
    # <yyyyMMdd-HHmmss>__general_log.txt in the run folder (same time stamp as the folder), starting with the lines
    # logged before the folder existed. With -Mask the log holds real names, so it is kept next to the shareable
    # folder instead, as <yyyyMMdd-HHmmss>__general_log.PRIVATE.txt.
    $run = $script:A2C
    $path = [IO.Path]::Combine($run.OutDir, $run.RunStamp + '__general_log.txt')
    if ($run.Options.Mask) { $path = [IO.Path]::Combine($run.Env['OutputBase'], $run.RunStamp + '__general_log.PRIVATE.txt') }
    $text = ''
    if ($run.Log.Count -gt 0) { $text = [string]::Join("`r`n", $run.Log) + "`r`n" }
    [IO.File]::WriteAllText($path, $text, $script:A2CUtf8Bom)
    $run.LogPath = $path
}

function Save-A2CEarlyLog {
    # The run stopped before its folder was created (e.g. Az.Accounts or sign-in): keep the log where the folder would be.
    $run = $script:A2C
    $name = $run.StartedUtc.ToLocalTime().ToString('yyyyMMdd-HHmmss') + '__general_log'
    if ($run.Options.Mask) { $name += '.PRIVATE.txt' } else { $name += '.txt' }
    $path = [IO.Path]::Combine((Get-A2COutputBase), $name)
    [IO.File]::WriteAllText($path, [string]::Join("`r`n", $run.Log) + "`r`n", $script:A2CUtf8Bom)
    $run.LogPath = $path
}

# ---- Mask (-Mask) -------------------------------------------------------------------------------------------
$script:A2CMask = $null
$script:A2CMaskAbbr = @{
    'microsoft.compute/virtualmachines' = 'vm'; 'microsoft.compute/disks' = 'disk'; 'microsoft.network/networkinterfaces' = 'nic'
    'microsoft.network/publicipaddresses' = 'pip'; 'microsoft.network/virtualnetworks' = 'vnet'; 'microsoft.network/networksecuritygroups' = 'nsg'
    'microsoft.network/routetables' = 'rt'; 'microsoft.storage/storageaccounts' = 'st'; 'microsoft.keyvault/vaults' = 'kv'
    'microsoft.recoveryservices/vaults' = 'rsv'; 'microsoft.sql/servers' = 'sql'; 'microsoft.sql/servers/databases' = 'sqldb'
    'microsoft.web/sites' = 'app'; 'microsoft.web/serverfarms' = 'plan'; 'microsoft.containerservice/managedclusters' = 'aks'
    'microsoft.network/loadbalancers' = 'lb'; 'microsoft.network/applicationgateways' = 'agw'; 'microsoft.network/privateendpoints' = 'pe'
    'microsoft.operationalinsights/workspaces' = 'law'; 'microsoft.automation/automationaccounts' = 'aa'; 'microsoft.automation/automationaccounts/runbooks' = 'rb'
    'microsoft.managedidentity/userassignedidentities' = 'id'; 'microsoft.network/natgateways' = 'ng'; 'microsoft.compute/availabilitysets' = 'avail'
    'microsoft.network/applicationsecuritygroups' = 'asg'; 'microsoft.network/virtualnetworkgateways' = 'vgw'; 'microsoft.network/azurefirewalls' = 'afw'
    'microsoft.containerregistry/registries' = 'acr'; 'microsoft.insights/components' = 'appi'; 'microsoft.dbforpostgresql/flexibleservers' = 'psql'
    'microsoft.dbformysql/flexibleservers' = 'mysql'; 'microsoft.cache/redis' = 'redis'; 'microsoft.documentdb/databaseaccounts' = 'cosmos'
}
$script:A2CMaskKeepPatterns = @('^(?i)(GatewaySubnet|AzureFirewallSubnet|AzureFirewallManagementSubnet|AzureBastionSubnet|RouteServerSubnet|default|master|ipconfig\d*|web)$',
    '^(?i)NetworkWatcherRG$', '^(?i)NetworkWatcher_[a-z0-9]+$', '^(?i)DefaultResourceGroup-[A-Z0-9]+$', '^(?i)AzureBackupRG_[a-z0-9]+_\d+$',
    '^(?i)MC_.+', '^(?i)privatelink\..+', '^(?i)(Azure-provided|none|NA|Internet|VirtualNetwork|AzureLoadBalancer|AzureCloud(\.[a-z0-9]+)?|Any|\*)$',
    '^(?i)(0\.0\.0\.0/0|::/0|168\.63\.129\.16|1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9)$',
    # everyday Azure DevOps names (pools, environments, branches) identify nobody; masking them would also garble notes
    '^(?i)(Azure Pipelines|Hosted( .+)?|Production|Prod|Staging|Test|Testing|Dev|Development|QA|UAT|Main|Develop)$',
    # feed views and public upstream sources of Azure Artifacts
    '^(?i)@?(Local|Prerelease|Release)$', '^(?i)(npmjs|NuGet Gallery|nuget\.org|PyPI|Maven Central|Google Maven Repository|Gradle Plugins|JitPack|crates\.io|PowerShell Gallery)$',
    # everyday TFVC folder names
    '^(?i)(Trunk|Branches|Releases|Features?|Hotfix(es)?|Integration|Source|Src)$',
    # built-in Azure DevOps security groups (feed permissions)
    '^(?i)(Project Collection (Administrators|Build Administrators|Build Service Accounts|Proxy Service Accounts|Service Accounts|Test Service Accounts|Valid Users)|Project-Scoped Users|Security Service Group|Project Administrators|Build Administrators|Release Administrators|Contributors|Readers|Project Valid Users|Endpoint Administrators|Endpoint Creators)$')
$script:A2CMaskDnsSuffixes = @('blob.core.windows.net', 'file.core.windows.net', 'queue.core.windows.net', 'table.core.windows.net', 'dfs.core.windows.net',
    'web.core.windows.net', 'core.windows.net', 'database.windows.net', 'vault.azure.net', 'scm.azurewebsites.net', 'azurewebsites.net',
    'cloudapp.azure.com', 'cloudapp.net', 'azurecr.io', 'servicebus.windows.net', 'azure-api.net', 'azurefd.net', 'trafficmanager.net',
    'documents.azure.com', 'redis.cache.windows.net', 'onmicrosoft.com', 'azure.com', 'windows.net', 'azure.net', 'microsoft.com', 'github.com')

function Initialize-A2CMask {
    $key = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    $script:A2CMask = [pscustomobject]@{
        Hmac  = [Security.Cryptography.HMACSHA256]::new($key)
        Map   = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        Kinds = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        Used  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Allow = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Ip    = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        IpNext = 0; Residue = 0; Multi = @()
    }
    # fixed words: 'Azure' is also the backup fabric segment of backup item IDs (masking it would garble every note)
    foreach ($t in @('subscriptions', 'resourceGroups', 'providers', 'managementGroups', 'n/a', 'Unknown', 'True', 'False', 'Yes', 'No', 'Azure')) { [void]$script:A2CMask.Allow.Add($t) }
}

function Get-A2CMaskHex {
    param([string] $Kind, [string] $Value, [int] $Length = 10)
    $b = $script:A2CMask.Hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Kind + [char]31 + $Value.ToLowerInvariant()))
    return ([BitConverter]::ToString($b).Replace('-', '').ToLowerInvariant()).Substring(0, $Length)
}

function Add-A2CMaskEntry {
    # Registers original -> pseudonym (first registration wins); returns the pseudonym.
    param([string] $Kind, [string] $Original, [string] $Prefix)
    if (-not $Original) { return $Original }
    $m = $script:A2CMask
    $existing = $null
    if ($m.Map.TryGetValue($Original, [ref]$existing)) { return $existing }
    $p = $Prefix + (Get-A2CMaskHex $Kind $Original 10)
    if ($m.Used.Contains($p)) { $p = $Prefix + (Get-A2CMaskHex $Kind $Original 16) }
    $m.Map[$Original] = $p
    $m.Kinds[$Original] = $Kind
    [void]$m.Used.Add($p)
    return $p
}

function Get-A2CMaskGuid {
    param([string] $Value)
    if (-not $Value -or $null -eq $script:A2CMask) { return $Value }
    if ($script:A2CMask.Allow.Contains($Value)) { return $Value }
    $existing = $null
    if ($script:A2CMask.Map.TryGetValue($Value, [ref]$existing)) { return $existing }
    $b = $script:A2CMask.Hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes('guid' + [char]31 + $Value.ToLowerInvariant()))
    $g = New-Object byte[] 16
    [Array]::Copy($b, $g, 16)
    $g[7] = ($g[7] -band 0x0F) -bor 0x40
    $g[8] = ($g[8] -band 0x3F) -bor 0x80
    $p = ([guid]::new($g)).ToString()
    $script:A2CMask.Map[$Value] = $p
    $script:A2CMask.Kinds[$Value] = 'guid'
    [void]$script:A2CMask.Used.Add($p)
    return $p
}

function Test-A2CMaskKeep {
    param([string] $Value)
    if (-not $Value) { return $true }
    if ($script:A2CMask.Allow.Contains($Value)) { return $true }
    foreach ($p in $script:A2CMaskKeepPatterns) { if ($Value -match $p) { return $true } }
    return $false
}

function Protect-A2CIp {
    # Returns the masked IP/CIDR, or $null when the value is not an IP address.
    param([string] $Value)
    $addr = $Value; $suffix = ''
    $i = $Value.IndexOf('/')
    if ($i -gt 0) { $addr = $Value.Substring(0, $i); $suffix = $Value.Substring($i) }
    $ipObj = $null
    if ($addr -notmatch '^[0-9a-fA-F:.]+$' -or $addr -notmatch '[.:]' -or -not [System.Net.IPAddress]::TryParse($addr, [ref]$ipObj)) { return $null }
    if ((Test-A2CPrivateIp $addr) -or (Test-A2CMaskKeep $Value) -or (Test-A2CMaskKeep $addr)) { return $Value }
    $m = $script:A2CMask
    $existing = $null
    if (-not $m.Ip.TryGetValue($addr, [ref]$existing)) {
        $n = $m.IpNext; $m.IpNext = $n + 1
        $blocks = @('192.0.2.', '198.51.100.', '203.0.113.')
        if ($n -lt 762) { $existing = $blocks[[int][math]::Floor($n / 254)] + (($n % 254) + 1) } else { $existing = 'pip-' + (Get-A2CMaskHex 'ip' $addr 10) }
        $m.Ip[$addr] = $existing
        $m.Map[$addr] = $existing; $m.Kinds[$addr] = 'ip'
    }
    return $existing + $suffix
}

function Protect-A2CFqdn {
    param([string] $Value)
    if (-not $Value -or (Test-A2CMaskKeep $Value)) { return $Value }
    $existing = $null
    if ($script:A2CMask.Map.TryGetValue($Value, [ref]$existing)) { return $existing }
    $suffix = ''
    foreach ($s in $script:A2CMaskDnsSuffixes) { if ($Value.EndsWith('.' + $s, [StringComparison]::OrdinalIgnoreCase)) { $suffix = $s; break } }
    $head = $Value
    if ($suffix) { $head = $Value.Substring(0, $Value.Length - $suffix.Length - 1) }
    else {
        # custom domain: a registered domain suffix keeps its pseudonym
        foreach ($k in @($script:A2CMask.Kinds.Keys)) {
            if ($script:A2CMask.Kinds[$k] -eq 'domain' -and $Value.EndsWith('.' + $k, [StringComparison]::OrdinalIgnoreCase)) {
                $h = $Value.Substring(0, $Value.Length - $k.Length - 1)
                return ((@($h.Split('.') | ForEach-Object { Protect-A2CAtom -Kind 'name' -Value $_ }) -join '.') + '.' + $script:A2CMask.Map[$k])
            }
        }
        return (Add-A2CMaskEntry 'domain' $Value 'd-') + '.example'
    }
    $labels = @($head.Split('.') | ForEach-Object { if ($script:A2CMask.Map.ContainsKey($_) -or -not (Test-A2CMaskKeep $_)) { Protect-A2CAtom -Kind 'name' -Value $_ } else { $_ } })
    return ([string]::Join('.', $labels) + '.' + $suffix)
}

function Protect-A2CAtom {
    # One token: allowlisted -> kept, registered -> pseudonym, GUID -> GUID, IP -> IP, else fail-safe hash.
    param([string] $Kind, [string] $Value)
    if (-not $Value) { return $Value }
    $existing = $null
    if ($script:A2CMask.Map.TryGetValue($Value, [ref]$existing)) { return $existing }
    if (Test-A2CMaskKeep $Value) { return $Value }
    if ($Value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return (Get-A2CMaskGuid $Value) }
    $ip = Protect-A2CIp $Value
    if ($null -ne $ip) { return $ip }
    $prefix = switch ($Kind) { 'sub' { 'sub-' } 'rg' { 'rg-' } 'mg' { 'mg-' } 'dn' { 'Name-' } 'tv' { 'tv-' } 'upn' { 'u-' } default { 'x-' } }
    return (Add-A2CMaskEntry $Kind $Value $prefix)
}

function Protect-A2CId {
    param([string] $Value)
    if (-not $Value -or $Value[0] -ne '/') { return (Protect-A2CAtom -Kind 'name' -Value $Value) }
    $p = $Value.Split('/')
    $state = 'start'   # start | ns | type | name
    $lastType = ''
    for ($i = 0; $i -lt $p.Count; $i++) {
        $s = $p[$i]
        if (-not $s) { continue }
        $prev = $(if ($i -gt 0) { $p[$i - 1] } else { '' })
        if ($s -ieq 'providers') { $state = 'ns'; continue }
        if ($state -eq 'ns') { $state = 'type'; continue }
        if ($state -eq 'type') { $lastType = $s; $state = 'name'; continue }
        if ($state -eq 'name') {
            if ($lastType -ieq 'managementGroups') { $p[$i] = $(if ($s -match '^[0-9a-fA-F-]{36}$') { Get-A2CMaskGuid $s } else { Protect-A2CAtom -Kind 'mg' -Value $s }) }
            else { $p[$i] = Protect-A2CAtom -Kind 'name' -Value $s }
            $state = 'type'; continue
        }
        if ($prev -ieq 'subscriptions') { $p[$i] = Get-A2CMaskGuid $s; continue }
        if ($prev -ieq 'resourceGroups') { $p[$i] = Protect-A2CAtom -Kind 'rg' -Value $s; continue }
    }
    return [string]::Join('/', $p)
}

function Protect-A2CUpn {
    param([string] $Value)
    $at = $Value.LastIndexOf('@')
    if ($at -lt 1) { return (Protect-A2CAtom -Kind 'upn' -Value $Value) }
    $local = $Value.Substring(0, $at); $domain = $Value.Substring($at + 1)
    $ext = ''
    if ($local -match '(?i)^(.*)(#EXT#)$') { $local = $Matches[1]; $ext = '#EXT#' }
    return ((Add-A2CMaskEntry 'upn' $local 'u-') + $ext + '@' + (Protect-A2CFqdn $domain))
}

function Protect-A2CValue {
    param([string] $Kind, $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [DateTime]) { return $Value }
    $s = Format-A2CCell $Value
    if ($s -eq '' -or $Kind -eq 'p' -or $Kind -eq 'num' -or $Kind -eq 'date') { return $Value }
    switch ($Kind) {
        'text'     { return '[masked]' }
        'json'     { return '[masked]' }
        'guid'     { return (Get-A2CMaskGuid $s) }
        'id'       { return (Protect-A2CId $s) }
        'idList'   { return [string]::Join('; ', @($s -split '; ' | ForEach-Object { Protect-A2CId $_ })) }
        'upn'      { return [string]::Join('; ', @($s -split '; ' | ForEach-Object { Protect-A2CUpn $_ })) }
        'fqdn'     { return [string]::Join(', ', @($s -split ',\s*' | ForEach-Object { Protect-A2CFqdn $_ })) }
        'ip'       { $x = Protect-A2CIp $s; if ($null -ne $x) { return $x } else { return (Protect-A2CAtom -Kind 'name' -Value $s) } }
        'known'    { $e = $null; if ($script:A2CMask.Map.TryGetValue($s, [ref]$e)) { return $e } else { return $s } }
        'role'     { $e = $null; if ($script:A2CMask.Map.TryGetValue($s, [ref]$e)) { return $e } elseif (Test-A2CMaskKeep $s) { return $s } else { return (Protect-A2CAtom -Kind 'name' -Value $s) } }
        'tagvalue' { return (Protect-A2CAtom -Kind 'tv' -Value $s) }
        'tags'     { return [string]::Join('; ', @($s -split '; ' | ForEach-Object { $j = $_.IndexOf('='); if ($j -ge 0) { $_.Substring(0, $j + 1) + (Protect-A2CAtom -Kind 'tv' -Value $_.Substring($j + 1)) } else { $_ } })) }
        'url'      {
            if ($s -match '^(https?://)([^/:]+)(.*)$') {
                $h = $Matches[2]; $rest = $Matches[3]; $scheme = $Matches[1]
                foreach ($x in @('microsoft.com', 'github.com', 'it4it.solutions')) { if ($h -ieq $x -or $h.EndsWith('.' + $x, [StringComparison]::OrdinalIgnoreCase)) { return $s } }
                return ($scheme + (Protect-A2CFqdn $h) + $rest)
            }
            return (Protect-A2CAtom -Kind 'name' -Value $s)
        }
        'note'     { return (Protect-A2CNote $s) }
        'path'     { return [string]::Join('/', @($s -split '/' | ForEach-Object { if ($script:A2CMask.Allow.Contains($_)) { $_ } else { Protect-A2CAtom -Kind 'name' -Value $_ } })) }
        'tfvc'     { return [string]::Join('/', @($s -split '/' | ForEach-Object { if (-not $_ -or $_ -eq '$') { $_ } else { Protect-A2CAtom -Kind 'name' -Value $_ } })) }
        'list'     { return [string]::Join('; ', @($s -split '; ' | ForEach-Object { Protect-A2CListItem $_ })) }
        'ipList'   { return [string]::Join('; ', @($s -split '; ' | ForEach-Object { [string]::Join(', ', @($_ -split ',\s*' | ForEach-Object { Protect-A2CListItem $_ })) })) }
        'pairs'    {
            return [string]::Join('; ', @($s -split '; ' | ForEach-Object {
                        $j = $_.IndexOf(':')
                        if ($j -gt 0) { (Protect-A2CAtom -Kind 'name' -Value $_.Substring(0, $j)) + ':' + [string]::Join(', ', @($_.Substring($j + 1) -split ',\s*' | ForEach-Object { Protect-A2CListItem $_ })) }
                        else { Protect-A2CListItem $_ }
                    }))
        }
        'sub'      { return (Protect-A2CAtom -Kind 'sub' -Value $s) }
        'rg'       { return (Protect-A2CAtom -Kind 'rg' -Value $s) }
        'mg'       { if ($s -match '^[0-9a-fA-F-]{36}$') { return (Get-A2CMaskGuid $s) } else { return (Protect-A2CAtom -Kind 'mg' -Value $s) } }
        'dn'       { return (Protect-A2CAtom -Kind 'dn' -Value $s) }
        default    { return (Protect-A2CAtom -Kind 'name' -Value $s) }
    }
}

function Protect-A2CListItem {
    # A list element: path "vnet/subnet", "ASG:name", "name(note)", IP/CIDR, service tag or name.
    param([string] $Value)
    if (-not $Value) { return $Value }
    if (Test-A2CMaskKeep $Value) { return $Value }
    $ip = Protect-A2CIp $Value
    if ($null -ne $ip) { return $ip }
    if ($Value -match '^(ASG):(.+)$') { return 'ASG:' + (Protect-A2CAtom -Kind 'name' -Value $Matches[2]) }
    if ($Value -match '^([^()]+)(\(.*\))$') { return (Protect-A2CListItem $Matches[1]) + $Matches[2] }
    if ($Value.StartsWith('/')) { return (Protect-A2CId $Value) }
    if ($Value -match '^[^/\s]+/[^/\s]+$') { return [string]::Join('/', @($Value.Split('/') | ForEach-Object { Protect-A2CAtom -Kind 'name' -Value $_ })) }
    if ($Value -match '@') { return (Protect-A2CUpn $Value) }
    if ($Value -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+){2,}$') { return (Protect-A2CFqdn $Value) }
    return (Protect-A2CAtom -Kind 'name' -Value $Value)
}

function Remove-A2CMaskResidue {
    # Safety net: replaces any registered original that is still present as a token.
    param([string] $Text)
    if (-not $Text -or $Text.Length -lt 4) { return $Text }
    $out = $Text
    foreach ($tok in [regex]::Split($Text, '[\s"'',;/=:@|()\[\]{}<>]+')) {
        if ($tok.Length -lt 4) { continue }
        $e = $null
        if ($script:A2CMask.Map.TryGetValue($tok, [ref]$e) -and $e -ne $tok -and -not (Test-A2CMaskKeep $tok)) {
            $out = [regex]::Replace($out, '(?<![A-Za-z0-9_.-])' + [regex]::Escape($tok) + '(?![A-Za-z0-9_-])', $e.Replace('$', '$$'), [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $script:A2CMask.Residue++
        }
    }
    return $out
}

function Protect-A2CNote {
    # Our own text: mask GUIDs, public IPs and multi-word names (subscriptions, roles, policies, management groups).
    param([string] $Text)
    $s = [regex]::Replace($Text, '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', { param($mm) Get-A2CMaskGuid $mm.Value })
    $s = [regex]::Replace($s, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', { param($mm) $x = Protect-A2CIp $mm.Value; if ($null -ne $x) { $x } else { $mm.Value } })
    foreach ($m in $script:A2CMask.Multi) {
        if ($s.IndexOf($m, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $s = [regex]::Replace($s, [regex]::Escape($m), $script:A2CMask.Map[$m].Replace('$', '$$'), [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $script:A2CMask.Residue++
        }
    }
    return $s
}

function Protect-A2CRows {
    param([string] $File, $Rows)
    $schema = $script:A2CSchemas[$File]
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $n = [ordered]@{}
        foreach ($c in $schema) {
            if (-not $row.Contains($c.Name)) { continue }
            $v = Protect-A2CValue -Kind $c.Kind -Value $row[$c.Name]
            if ($v -is [string] -and $c.Kind -ne 'p' -and $c.Kind -ne 'known') { $v = Remove-A2CMaskResidue $v }
            $n[$c.Name] = $v
        }
        $out.Add($n)
    }
    return , $out
}

function Protect-A2CTagList {
    param($TagList)
    $n = [ordered]@{}
    foreach ($k in $TagList.Keys) {
        $vals = [ordered]@{}
        foreach ($v in $TagList[$k].Keys) { $vals[(Protect-A2CAtom -Kind 'tv' -Value ([string]$v))] = '' }
        $n[$k] = $vals
    }
    return $n
}

function Complete-A2CMaskDictionary {
    # Registers every customer-specific name from the collected data before anything is written.
    $d = $script:A2C.Data
    $allow = $script:A2CMask.Allow
    foreach ($r in @($d['Resources'])) {
        if ($null -eq $r) { continue }
        [void]$allow.Add([string]$r.location)
        if ($null -ne $r.sku -and $r.sku.name) { [void]$allow.Add([string]$r.sku.name) }
        $tt = Get-A2CTypeCased -Id ([string]$r.id) -Fallback ''
        foreach ($seg in $tt.Split('/')) { if ($seg) { [void]$allow.Add($seg) } }
    }
    foreach ($ext in @(Get-A2CResourcesOfType @('microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachinescalesets/extensions'))) { [void]$allow.Add([string]$ext.name) }
    foreach ($rd in @($d['RoleDefs'].Values)) { if ($null -ne $rd -and $rd.Type -eq 'BuiltInRole') { [void]$allow.Add($rd.RoleName); [void]$allow.Add($rd.Guid) } }
    foreach ($pd in @($d['PolicyDefs'].Values)) { if ($null -ne $pd -and $pd.PolicyType -ne 'Custom') { [void]$allow.Add($pd.Name) } }
    foreach ($sp in @($d['EntraSPs'])) {
        if ($null -eq $sp) { continue }
        if ((Get-A2CSpPublisher $sp) -eq 'Microsoft') { [void]$allow.Add([string]$sp.appId); [void]$allow.Add([string]$sp.displayName) }
    }
    foreach ($a in $script:A2CPermissionApis.Keys) { [void]$allow.Add($a) }
    # subscriptions and management groups
    foreach ($s in @(@($d['Subscriptions']) + @($d['SubscriptionsSkipped']))) {
        if ($null -eq $s) { continue }
        [void](Get-A2CMaskGuid $s.Id)
        if ($s.Name) { [void](Add-A2CMaskEntry 'sub' $s.Name 'sub-') }
        foreach ($m in @($s.MgChain)) { if ($null -ne $m) { if ($m.Name -notmatch '^[0-9a-fA-F-]{36}$') { [void](Add-A2CMaskEntry 'mg' $m.Name 'mg-') }; if ($m.DisplayName) { [void](Add-A2CMaskEntry 'mgdn' $m.DisplayName 'MG ') } } }
    }
    foreach ($m in @($d['ManagementGroups'])) {
        if ($null -eq $m) { continue }
        if ($m.Name -notmatch '^[0-9a-fA-F-]{36}$') { [void](Add-A2CMaskEntry 'mg' $m.Name 'mg-') }
        if ($m.DisplayName -and $m.DisplayName -ne 'Tenant Root Group') { [void](Add-A2CMaskEntry 'mgdn' $m.DisplayName 'MG ') }
    }
    # resource groups, resources and their child names
    foreach ($rg in @($d['ResourceGroups'])) { if ($null -ne $rg -and -not (Test-A2CMaskKeep ([string]$rg.name))) { [void](Add-A2CMaskEntry 'rg' ([string]$rg.name) 'rg-') } }
    foreach ($r in @($d['Resources'])) {
        if ($null -eq $r) { continue }
        $t = ([string]$r.type).ToLowerInvariant()
        $rg = Get-A2CRgFromId ([string]$r.id)
        if ($rg -and -not (Test-A2CMaskKeep $rg)) { [void](Add-A2CMaskEntry 'rg' $rg 'rg-') }
        $n = [string]$r.name
        if ($t -like 'microsoft.compute/virtualmachines/extensions' -or $t -like '*/extensions') { continue }
        if ($t -eq 'microsoft.network/privatednszones') { if (-not (Test-A2CMaskKeep $n)) { [void](Add-A2CMaskEntry 'domain' $n 'd-') }; continue }
        if (-not (Test-A2CMaskKeep $n)) {
            $abbr = $script:A2CMaskAbbr[$t]; if (-not $abbr) { $abbr = 'res' }
            [void](Add-A2CMaskEntry 'name' $n ($abbr + '-'))
        }
        # parent names of child resources
        $pp = Get-A2CParentPath ([string]$r.id)
        if ($pp) { $segs = $pp.Split('/'); for ($i = 1; $i -lt $segs.Count; $i += 2) { if (-not (Test-A2CMaskKeep $segs[$i])) { [void](Add-A2CMaskEntry 'name' $segs[$i] 'res-') } } }
        foreach ($tp in (Get-A2CTagPairs $r.tags)) { if ($tp[1]) { [void](Add-A2CMaskEntry 'tv' $tp[1] 'tv-') } }
        $p = $null
        if ($t -eq 'microsoft.network/virtualnetworks') {
            $p = Get-A2CProps $r
            foreach ($sn in @($p.subnets)) { if ($null -ne $sn -and -not (Test-A2CMaskKeep ([string]$sn.name))) { [void](Add-A2CMaskEntry 'name' ([string]$sn.name) 'snet-') } }
            foreach ($pe in @($p.virtualNetworkPeerings)) { if ($null -ne $pe) { [void](Add-A2CMaskEntry 'name' ([string]$pe.name) 'peer-') } }
        }
        elseif ($t -eq 'microsoft.network/networksecuritygroups') {
            $p = Get-A2CProps $r
            foreach ($x in @($p.securityRules)) { if ($null -ne $x) { [void](Add-A2CMaskEntry 'name' ([string]$x.name) 'rule-') } }
        }
        elseif ($t -eq 'microsoft.network/routetables') {
            $p = Get-A2CProps $r
            foreach ($x in @($p.routes)) { if ($null -ne $x) { [void](Add-A2CMaskEntry 'name' ([string]$x.name) 'route-') } }
        }
        elseif ($t -eq 'microsoft.compute/virtualmachines') {
            $p = Get-A2CProps $r
            $cn = [string](Get-A2CFirst $p @('osProfile.computerName', 'extended.instanceView.computerName'))
            if ($cn -and -not $script:A2CMask.Map.ContainsKey($cn)) { [void](Add-A2CMaskEntry 'name' $cn 'host-') }
            foreach ($x in @($p.storageProfile.osDisk, @($p.storageProfile.dataDisks))) { if ($null -ne $x -and $x.name) { [void](Add-A2CMaskEntry 'name' ([string]$x.name) 'disk-') } }
        }
    }
    foreach ($s in @($d['Subscriptions'])) { foreach ($tp in (Get-A2CTagPairs $s.Tags)) { if ($tp[1]) { [void](Add-A2CMaskEntry 'tv' $tp[1] 'tv-') } } }
    foreach ($rg in @($d['ResourceGroups'])) { if ($null -ne $rg) { foreach ($tp in (Get-A2CTagPairs $rg.tags)) { if ($tp[1]) { [void](Add-A2CMaskEntry 'tv' $tp[1] 'tv-') } } } }
    # governance objects
    foreach ($l in @($d['Locks'])) { if ($null -ne $l) { [void](Add-A2CMaskEntry 'name' $l.Name 'lock-') } }
    foreach ($x in @($d['DiagDetails'])) { if ($null -ne $x) { [void](Add-A2CMaskEntry 'name' $x['SettingName'] 'diag-') } }
    foreach ($rd in @($d['RoleDefs'].Values)) { if ($null -ne $rd -and $rd.Type -ne 'BuiltInRole') { [void](Add-A2CMaskEntry 'role' $rd.RoleName 'Role ') } }
    foreach ($a in @($d['PolicyAssignments'])) { if ($null -ne $a) { [void](Add-A2CMaskEntry 'policy' $a.Name 'pol-'); if ($a.DisplayName) { [void](Add-A2CMaskEntry 'policydn' $a.DisplayName 'Policy ') } } }
    foreach ($pd in @($d['PolicyDefs'].Values)) { if ($null -ne $pd -and $pd.PolicyType -eq 'Custom') { [void](Add-A2CMaskEntry 'policy' $pd.Name 'pol-'); if ($pd.DisplayName) { [void](Add-A2CMaskEntry 'policydn' $pd.DisplayName 'Policy ') } } }
    foreach ($e in @($d['PolicyExemptions'])) { if ($null -ne $e) { [void](Add-A2CMaskEntry 'policy' $e.Name 'pol-'); if ($e.DisplayName) { [void](Add-A2CMaskEntry 'policydn' $e.DisplayName 'Policy ') } } }
    foreach ($b in @($d['BackupItems'])) { if ($null -ne $b -and $b.Policy -and $b.Policy -notmatch '^(?i)DefaultPolicy$') { [void](Add-A2CMaskEntry 'name' $b.Policy 'bkpol-') } }
    # Entra ID
    foreach ($o in @($d['EntraOrg'])) { if ($null -ne $o -and $o.displayName) { [void](Add-A2CMaskEntry 'dn' ([string]$o.displayName) 'Tenant ') } }
    foreach ($dm in @($d['EntraDomains'])) {
        if ($null -eq $dm) { continue }
        $name = [string]$dm.id
        if ($name -like '*.onmicrosoft.com') { [void](Add-A2CMaskEntry 'name' ($name -replace '\.onmicrosoft\.com$', '') 'h-') }
        else { [void](Add-A2CMaskEntry 'domain' $name 'd-') }
    }
    foreach ($u in @($d['EntraUsers'])) { if ($null -ne $u) { [void](Add-A2CMaskEntry 'dn' ([string]$u.displayName) 'User ') } }
    foreach ($g in @($d['EntraGroups'])) { if ($null -ne $g) { [void](Add-A2CMaskEntry 'dn' ([string]$g.displayName) 'Group ') } }
    foreach ($a in @($d['EntraApps'])) { if ($null -ne $a) { [void](Add-A2CMaskEntry 'dn' ([string]$a.displayName) 'App ') } }
    foreach ($sp in @($d['EntraSPs'])) { if ($null -ne $sp -and (Get-A2CSpPublisher $sp) -ne 'Microsoft' -and [string]$sp.servicePrincipalType -ne 'ManagedIdentity') { [void](Add-A2CMaskEntry 'dn' ([string]$sp.displayName) 'App '); if ($sp.publisherName) { [void](Add-A2CMaskEntry 'dn' ([string]$sp.publisherName) 'Publisher ') } } }
    foreach ($p in @($d['Principals'].Values)) { if ($null -ne $p -and $p.DisplayName -and -not $allow.Contains($p.DisplayName)) { [void](Add-A2CMaskEntry 'dn' $p.DisplayName $(if ($p.Type -eq 'group') { 'Group ' } elseif ($p.Type -eq 'user') { 'User ' } else { 'App ' })) } }
    foreach ($x in @($d['EntraDirRoles'])) { if ($null -ne $x -and $x.PrincipalName -and -not $allow.Contains($x.PrincipalName)) { [void](Add-A2CMaskEntry 'dn' $x.PrincipalName 'Name ') } }
    foreach ($x in @($d['EntraGroupMembers'])) { if ($null -ne $x -and $x.Member.displayName -and -not $allow.Contains([string]$x.Member.displayName)) { [void](Add-A2CMaskEntry 'dn' ([string]$x.Member.displayName) 'Name ') } }
    foreach ($r in (Get-A2CResourcesOfType 'microsoft.network/publicipaddresses')) { $ip = [string](Get-A2CProps $r).ipAddress; if ($ip) { [void](Protect-A2CIp $ip) } }
    # Azure DevOps (adodn = names that can contain spaces)
    foreach ($o in @($d['Ado'])) {
        if ($null -eq $o) { continue }
        [void](Add-A2CMaskEntry 'name' $o.Name 'ado-')
        if ($o.User) { [void](Add-A2CMaskEntry 'dn' $o.User 'User ') }
        $named = @(
            @{ L = $o.Projects; P = 'Project '; K = 'adodn' }, @{ L = $o.Repos; P = 'repo-'; K = 'name' }, @{ L = $o.Feeds; P = 'feed-'; K = 'name'; W = $true }
            @{ L = $o.Pipelines; P = 'Pipeline '; K = 'adodn'; W = $true }, @{ L = $o.Releases; P = 'Release '; K = 'adodn'; W = $true }
            @{ L = $o.Endpoints; P = 'Connection '; K = 'adodn'; W = $true }, @{ L = $o.VariableGroups; P = 'Variables '; K = 'adodn'; W = $true }
            @{ L = $o.SecureFiles; P = 'file-'; K = 'name'; W = $true }, @{ L = $o.Environments; P = 'Environment '; K = 'adodn'; W = $true }
            @{ L = $o.DeploymentGroups; P = 'Deployment group '; K = 'adodn'; W = $true }, @{ L = $o.Agents; P = 'agent-'; K = 'name'; W = $true })
        foreach ($set in $named) {
            foreach ($x in $set.L) {
                if ($null -eq $x) { continue }
                $obj = $x
                if ($set.W) { $obj = $x.Item }
                $n = [string]$obj.name
                if ($n -and -not (Test-A2CMaskKeep $n)) { [void](Add-A2CMaskEntry $set.K $n $set.P) }
            }
        }
        foreach ($x in $o.Pools) { if (-not $x.isHosted -and -not (Test-A2CMaskKeep ([string]$x.name))) { [void](Add-A2CMaskEntry 'adodn' ([string]$x.name) 'Pool ') } }
        foreach ($x in $o.Processes) { if ([string]$x.customizationType -ne 'system') { [void](Add-A2CMaskEntry 'adodn' ([string]$x.name) 'Process ') } }
        foreach ($w in $o.Agents) {
            $cn = ''
            if ($null -ne $w.Item.systemCapabilities) { $cn = [string]$w.Item.systemCapabilities.'Agent.ComputerName' }
            if ($cn -and -not $script:A2CMask.Map.ContainsKey($cn)) { [void](Add-A2CMaskEntry 'name' $cn 'host-') }
        }
        foreach ($u in $o.Users) { if ($null -ne $u.user -and $u.user.displayName) { [void](Add-A2CMaskEntry 'dn' ([string]$u.user.displayName) 'User ') } }
        foreach ($w in $o.Admins) { if ($null -ne $w.Member -and $w.Member.displayName -and -not $allow.Contains([string]$w.Member.displayName)) { [void](Add-A2CMaskEntry 'dn' ([string]$w.Member.displayName) 'Name ') } }
        foreach ($w in $o.Feeds) {
            # package names - except the ones only cached from public upstream sources (npmjs, NuGet Gallery...), which are public
            $public = @{}
            foreach ($us in @($w.Item.upstreamSources)) { if ($null -ne $us -and [string]$us.upstreamSourceType -eq 'public') { $public[([string]$us.id).ToLowerInvariant()] = $true } }
            foreach ($pk in @($w.Items | Where-Object { $null -ne $_ })) {
                $n = [string]$pk.name
                if (-not $n -or (Test-A2CMaskKeep $n)) { continue }
                $vers = @($pk.versions | Where-Object { $null -ne $_ })
                $own = @($vers | Where-Object { -not (Test-A2CAdoFromUpstream $_) -or -not $public.ContainsKey(([string]$_.directUpstreamSourceId).ToLowerInvariant()) })
                if ($vers.Count -eq 0 -or $own.Count -gt 0) { [void](Add-A2CMaskEntry 'name' $n 'pkg-') }
            }
            foreach ($pm in @($w.Permissions | Where-Object { $null -ne $_ })) {
                $idn = Get-A2CAdoIdentityName $pm
                if ($idn.Name -and -not (Test-A2CMaskKeep $idn.Name) -and -not $allow.Contains($idn.Name)) { [void](Add-A2CMaskEntry 'dn' $idn.Name 'Name ') }
            }
        }
    }
    # names that can contain spaces are also searched as substrings in free-form notes
    $script:A2CMask.Multi = @($script:A2CMask.Kinds.Keys | Where-Object { @('sub', 'mgdn', 'role', 'policydn', 'adodn') -contains $script:A2CMask.Kinds[$_] -and $_.Length -ge 4 } | Sort-Object { -1 * $_.Length })
    Write-A2CLog -Level Ok ('Mask: {0} names registered' -f $script:A2CMask.Map.Count)
}

function Test-A2CMaskResidue {
    $n = $script:A2CMask.Residue
    Add-A2CCoverage -Area 'Mask self-check' -Status Info -Items $n -Detail $(if ($n -eq 0) { 'No original names left in the outputs' } else { "$n remaining original names were replaced by the safety net" })
}

function Save-A2CMaskMap {
    $path = $script:A2C.Options.MaskMapPath
    if (-not $path) { $path = [IO.Path]::Combine($script:A2C.Env['OutputBase'], $script:A2C.RunName + '.PRIVATE-maskmap.csv') }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('"Kind","Original","Pseudonym"' + "`r`n")
    foreach ($k in @($script:A2CMask.Map.Keys | Sort-Object)) {
        [void]$sb.AppendFormat('{0},{1},{2}' + "`r`n", (ConvertTo-A2CCsvField -Text $script:A2CMask.Kinds[$k] -Max 32000), (ConvertTo-A2CCsvField -Text $k -Max 32000), (ConvertTo-A2CCsvField -Text $script:A2CMask.Map[$k] -Max 32000))
    }
    [IO.File]::WriteAllText($path, $sb.ToString(), (New-Object System.Text.UTF8Encoding $true))
    $script:A2C.Data['MaskMapPath'] = $path
    Write-A2CLog -Level Warn ('Mask map written to {0} - keep it private, it re-identifies the masked report.' -f $path)
}

function New-A2CZip {
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zipPath = [IO.Path]::Combine($script:A2C.Env['OutputBase'], $script:A2C.RunName + '.zip')
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    $root = $script:A2C.OutDir
    $zip = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File)) {
            $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
            if ($script:A2C.Options.Mask -and ($rel -like '*general_log*' -or $rel -like '.cache*')) { continue }
            $entry = $script:A2C.RunName + '/' + ($rel -replace '\\', '/')
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $entry, [IO.Compression.CompressionLevel]::Optimal)
        }
    }
    finally { $zip.Dispose() }
    return $zipPath
}

function Export-A2CExcel {
    Import-Module ImportExcel -ErrorAction Stop
    $path = [IO.Path]::Combine($script:A2C.OutDir, $script:A2C.RunName + '.xlsx')
    $order = [System.Collections.Generic.List[string]]::new()
    $order.Add('findings.csv')
    # one sheet per report (Azure DevOps: all organizations together), Azure DevOps sheets last
    foreach ($f in @($script:A2C.Out.Keys | Where-Object { $_ -like '*.csv' -and $_ -ne 'findings.csv' -and $_ -ne 'coverage.csv' } |
                Sort-Object @{ Expression = { $_ -like 'ADO/*' } }, @{ Expression = { $_ } })) { $order.Add($f) }
    $order.Add('coverage.csv')
    $pkg = $null
    $max = [int]$script:A2C.Options.PropertiesMaxChars
    $used = @{}
    foreach ($file in $order) {
        $rows = Get-A2COutputRows $file
        if ($rows.Count -eq 0) { continue }
        $schema = $script:A2CSchemas[$file]
        $objs = [System.Collections.Generic.List[object]]::new()
        foreach ($row in $rows) {
            $o = [ordered]@{}
            foreach ($c in $schema) {
                $v = $null
                if ($row.Contains($c.Name)) { $v = $row[$c.Name] }
                if ($c.Kind -eq 'num' -and $null -ne $v -and "$v" -ne '') {
                    $d = 0.0
                    if ([double]::TryParse([string](Format-A2CCell $v), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $o[$c.Name] = $d; continue }
                }
                $s = Format-A2CCell $v
                if ($s.Length -gt $max) { $s = $s.Substring(0, $max - 20) + '...[truncated]' }
                $o[$c.Name] = $s
            }
            $objs.Add([pscustomobject]$o)
        }
        $ws = ($file -replace '\.csv$', '') -replace '[\\/]', ' '   # ADO/projects.csv -> sheet "ADO projects"
        if ($ws.Length -gt 31) { $ws = $ws.Substring(0, 31) }
        if ($used.ContainsKey($ws)) { continue }
        $used[$ws] = $true
        $p = @{ WorksheetName = $ws; TableName = ('t_' + ($ws -replace '[^A-Za-z0-9_]', '_')); TableStyle = 'Medium2'; FreezeTopRow = $true
            BoldTopRow = $true; NoNumberConversion = '*'; PassThru = $true }
        if ($objs.Count -le 5000) { $p['AutoSize'] = $true; $p['MaxAutoSizeRows'] = 1000 }
        if ($null -eq $pkg) { $p['Path'] = $path } else { $p['ExcelPackage'] = $pkg }
        $pkg = $objs | Export-Excel @p
    }
    if ($null -ne $pkg) { Close-ExcelPackage $pkg }
    $script:A2C.Files.Add([pscustomobject]@{ File = [IO.Path]::GetFileName($path); Rows = $used.Count; Path = $path })
    Write-A2CLog -Level Ok ('Excel workbook: ' + $path)
}

# ---- HTML summary report ----------------------------------------------------------------------------------
function ConvertTo-A2CHtmlText {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode((Format-A2CCell $Value))
}

function Get-A2CMaskedName {
    # For HTML aggregates built from datasets: masks a value when -Mask is used.
    param([string] $Kind, [string] $Value)
    if ($script:A2C.Options.Mask) { return (Protect-A2CValue -Kind $Kind -Value $Value) }
    return $Value
}

function New-A2CHtmlBars {
    param($Items, [int] $Max = 15, [string] $Unit = '')
    $list = @($Items | Sort-Object @{ Expression = { -1 * [double]$_.Value } }, @{ Expression = { $_.Label } } | Select-Object -First $Max)
    if ($list.Count -eq 0) { return '<p class="muted">No data.</p>' }
    $top = [double]($list | Measure-Object -Property Value -Maximum).Maximum
    if ($top -le 0) { $top = 1 }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<div class="bars">')
    foreach ($i in $list) {
        $pct = [math]::Round(100 * [double]$i.Value / $top, 1)
        $val = $(if ($Unit) { '{0:N2} {1}' -f [double]$i.Value, $Unit } else { '{0:N0}' -f [double]$i.Value })
        [void]$sb.AppendFormat('<div class="row"><span class="lbl" title="{0}">{0}</span><span class="track"><span class="fill" style="width:{1}%"></span></span><span class="val">{2}</span></div>', (ConvertTo-A2CHtmlText $i.Label), $pct.ToString([Globalization.CultureInfo]::InvariantCulture), (ConvertTo-A2CHtmlText $val))
    }
    [void]$sb.Append('</div>')
    return $sb.ToString()
}

function New-A2CHtmlTable {
    # Columns: @{ Key; Header; Num; Render (scriptblock row -> encoded html) }
    param([string] $Id, $Columns, $Rows, [int] $Max = 200, [string] $File = '', [switch] $Filter)
    $all = @($Rows)
    if ($all.Count -eq 0) { return '<p class="muted">Nothing found.</p>' }
    $sb = [System.Text.StringBuilder]::new()
    if ($Filter -and $all.Count -gt 10) { [void]$sb.AppendFormat('<input class="filter" type="search" placeholder="Filter..." data-filter="{0}" aria-label="Filter table">', $Id) }
    [void]$sb.AppendFormat('<div class="tw"><table class="sortable" id="{0}"><thead><tr>', $Id)
    foreach ($c in $Columns) { [void]$sb.AppendFormat('<th{0}>{1}</th>', $(if ($c.Num) { ' class="num"' } else { '' }), (ConvertTo-A2CHtmlText $c.Header)) }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in @($all | Select-Object -First $Max)) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            if ($null -ne $c.Render) { [void]$sb.Append('<td>' + (& $c.Render $r) + '</td>'); continue }
            $v = $null
            if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($c.Key)) { $v = $r[$c.Key] } } else { $v = $r.($c.Key) }
            if ($c.Num) {
                $d = 0.0
                $s = Format-A2CCell $v
                $dv = $(if ([double]::TryParse($s, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $d.ToString([Globalization.CultureInfo]::InvariantCulture) } else { '0' })
                [void]$sb.AppendFormat('<td class="num" data-v="{0}">{1}</td>', $dv, (ConvertTo-A2CHtmlText $s))
            }
            else { [void]$sb.Append('<td>' + (ConvertTo-A2CHtmlText $v) + '</td>') }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($all.Count -gt $Max) { [void]$sb.AppendFormat('<p class="muted">Showing {0} of {1} rows - full data in {2}.</p>', $Max, $all.Count, (ConvertTo-A2CHtmlText $File)) }
    elseif ($File) { [void]$sb.AppendFormat('<p class="muted">Source: {0}</p>', (ConvertTo-A2CHtmlText $File)) }
    return $sb.ToString()
}

function Get-A2CCountBy {
    param($Items, [scriptblock] $Key, [scriptblock] $Value)
    $h = @{}
    foreach ($i in $Items) {
        if ($null -eq $i) { continue }
        $k = [string](& $Key $i)
        if (-not $k) { continue }
        $v = 1.0
        if ($null -ne $Value) { $v = [double](& $Value $i) }
        $h[$k] = [double]$h[$k] + $v
    }
    return , @($h.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Label = $_.Key; Value = $_.Value } })
}

$script:A2CHtmlCss = @'
:root{color-scheme:light;--bg:#f5f6f8;--panel:#fff;--text:#1c2330;--muted:#5d6676;--border:#dde2ea;--accent:#0f6cbd;--high:#c4314b;--med:#b86e00;--low:#2b7a0b;--info:#667085;--track:#edf0f4;--fill:#0f6cbd}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#0f1217;--panel:#161b22;--text:#e6e9ef;--muted:#9aa4b5;--border:#2a313c;--accent:#58a6ff;--high:#ff6b81;--med:#f0a53a;--low:#5fcf6a;--info:#9aa4b5;--track:#222a35;--fill:#58a6ff}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#0f1217;--panel:#161b22;--text:#e6e9ef;--muted:#9aa4b5;--border:#2a313c;--accent:#58a6ff;--high:#ff6b81;--med:#f0a53a;--low:#5fcf6a;--info:#9aa4b5;--track:#222a35;--fill:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent)}header{background:var(--panel);border-bottom:1px solid var(--border);padding:20px 24px}
header h1{margin:0 0 4px;font-size:22px}header .meta{color:var(--muted);font-size:13px}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
nav{position:sticky;top:0;z-index:2;background:var(--panel);border-bottom:1px solid var(--border);padding:8px 24px;overflow-x:auto;white-space:nowrap}
nav a{margin-right:16px;text-decoration:none;font-size:13px}
main{max-width:1320px;margin:0 auto;padding:12px 16px 40px}
section{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin:16px 0}
section h2{margin:0 0 12px;font-size:18px}section h3{margin:18px 0 8px;font-size:15px}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.kpi{border:1px solid var(--border);border-radius:8px;padding:10px 12px}.kpi .v{font-size:24px;font-weight:650;font-variant-numeric:tabular-nums}
.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px}
.tw{overflow-x:auto;max-height:640px;overflow-y:auto;border:1px solid var(--border);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{cursor:pointer;user-select:none;color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--panel)}
th[aria-sort="ascending"]::after{content:" \25B2"}th[aria-sort="descending"]::after{content:" \25BC"}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.sev{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff}
.sev.High{background:var(--high)}.sev.Medium{background:var(--med)}.sev.Low{background:var(--low)}.sev.Info{background:var(--info)}
.bars .row{display:grid;grid-template-columns:minmax(120px,280px) 1fr 90px;gap:8px;align-items:center;margin:3px 0}
.bars .lbl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.bars .val{text-align:right;font-variant-numeric:tabular-nums;color:var(--muted)}
.bars .track{background:var(--track);border-radius:4px;height:12px;display:block}.bars .fill{background:var(--fill);border-radius:4px;height:12px;display:block}
.muted{color:var(--muted);font-size:12px}.filter{margin:0 0 8px;padding:6px 8px;width:260px;max-width:100%;border:1px solid var(--border);border-radius:6px;background:var(--panel);color:var(--text)}
.banner{background:#fff4ce;color:#5c4400;border:1px solid #f1d27a;border-radius:8px;padding:8px 12px;margin:12px 0}
.tree div{padding:2px 0}.tree .mg{font-weight:600}.pill{display:inline-block;border:1px solid var(--border);border-radius:10px;padding:0 8px;font-size:12px;color:var(--muted);margin-left:6px}
button#themeToggle{border:1px solid var(--border);background:var(--panel);color:var(--text);border-radius:6px;padding:6px 10px;cursor:pointer}
footer{max-width:1320px;margin:0 auto;padding:16px 24px 40px;color:var(--muted);font-size:13px;border-top:1px solid var(--border)}
footer .cta{font-size:15px;color:var(--text);margin-bottom:6px}
@media print{nav,.filter,button#themeToggle{display:none}.tw{max-height:none}section{break-inside:avoid}}
@media (max-width:640px){header,nav{padding-left:16px;padding-right:16px}main{padding:8px}section{padding:12px}.bars .row{grid-template-columns:110px 1fr 70px}}
'@

$script:A2CHtmlJs = @'
(function(){var root=document.documentElement;try{var t=localStorage.getItem('a2c-theme');if(t){root.setAttribute('data-theme',t);}}catch(e){}
var tb=document.getElementById('themeToggle');if(tb){tb.addEventListener('click',function(){var cur=root.getAttribute('data-theme');var dark=cur?cur==='dark':(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);var n=dark?'light':'dark';root.setAttribute('data-theme',n);try{localStorage.setItem('a2c-theme',n);}catch(e){}});}
Array.prototype.forEach.call(document.querySelectorAll('table.sortable'),function(tbl){Array.prototype.forEach.call(tbl.tHead.rows[0].cells,function(th,i){th.addEventListener('click',function(){var body=tbl.tBodies[0];var rows=Array.prototype.slice.call(body.rows);var asc=th.getAttribute('aria-sort')!=='ascending';Array.prototype.forEach.call(tbl.tHead.rows[0].cells,function(x){x.removeAttribute('aria-sort');});th.setAttribute('aria-sort',asc?'ascending':'descending');rows.sort(function(a,b){var x=a.cells[i],y=b.cells[i];var xv=x.getAttribute('data-v'),yv=y.getAttribute('data-v');var r=(xv!==null&&yv!==null)?(parseFloat(xv)-parseFloat(yv)):x.textContent.localeCompare(y.textContent);return asc?r:-r;});rows.forEach(function(r){body.appendChild(r);});});});});
Array.prototype.forEach.call(document.querySelectorAll('input[data-filter]'),function(inp){inp.addEventListener('input',function(){var q=inp.value.toLowerCase();var t=document.getElementById(inp.getAttribute('data-filter'));Array.prototype.forEach.call(t.tBodies[0].rows,function(r){r.style.display=r.textContent.toLowerCase().indexOf(q)>=0?'':'none';});});});})();
'@

function New-A2CHtmlReport {
    $run = $script:A2C
    $mask = [bool]$run.Options.Mask
    $sections = [System.Collections.Generic.List[object]]::new()
    $addSection = { param([string] $Id, [string] $Title, [string] $Html) if ($Html) { $sections.Add([pscustomobject]@{ Id = $Id; Title = $Title; Html = $Html }) } }
    $res = @($run.Data['Resources'])
    $haveRes = Test-A2CDataset 'Resources'

    # ---- header data
    $tenantName = ''
    $org = @($run.Data['EntraOrg'])
    if ($org.Count -gt 0 -and $null -ne $org[0]) { $tenantName = [string]$org[0].displayName }
    $tenantId = $run.TenantId
    if ($mask) { $tenantId = Get-A2CMaskGuid $tenantId; $tenantName = $(if ($tenantName) { Protect-A2CValue -Kind 'dn' -Value $tenantName } else { '' }) }
    $title = $(if ($tenantName) { 'Azure estate report - ' + $tenantName } else { 'Azure estate report' })

    # ---- KPIs
    $kpi = [System.Collections.Generic.List[object]]::new()
    $addKpi = { param($Label, $Value) if ($null -ne $Value -and "$Value" -ne '') { $kpi.Add(@($Label, $Value)) } }
    & $addKpi 'Subscriptions' (@($run.Data['Subscriptions']).Count)
    if (Test-A2CDataset 'Containers') { & $addKpi 'Resource groups' (@($run.Data['ResourceGroups']).Count) }
    if ($haveRes) {
        & $addKpi 'Resources' $res.Count
        & $addKpi 'Resource types' $run.Data['ResByType'].Count
        $vms = Get-A2CResourcesOfType 'microsoft.compute/virtualmachines'
        & $addKpi 'Virtual machines' $vms.Count
        $running = @($vms | Where-Object { [string](Get-A2CProps $_).extended.instanceView.powerState.code -eq 'PowerState/running' }).Count
        & $addKpi 'VMs running' $running
        & $addKpi 'Storage accounts' (Get-A2CResourcesOfType 'microsoft.storage/storageaccounts').Count
        & $addKpi 'SQL databases' @((Get-A2CResourcesOfType 'microsoft.sql/servers/databases') | Where-Object { [string]$_.name -ne 'master' }).Count
        & $addKpi 'Public IPs' (Get-A2CResourcesOfType 'microsoft.network/publicipaddresses').Count
        & $addKpi 'Regions' (Get-A2CUnique @($res | ForEach-Object { $_.location })).Count
    }
    $vmRows = Get-A2CRows 'vms.csv'
    if ($vmRows.Count -gt 0) { $cpu = 0; foreach ($v in $vmRows) { if ($v['vCPUs']) { $cpu += [int]$v['vCPUs'] } }; & $addKpi 'VM vCPUs' $cpu }
    if (Test-A2CDataset 'Cost') {
        $tot = 0.0; $cur = ''
        foreach ($s in $run.Data['CostBySub'].Values) { $tot += [double]$s.Total; if ($s.Currency) { $cur = $s.Currency } }
        & $addKpi ('Cost last {0} days' -f $run.Options.CostDays) ('{0:N0} {1}' -f $tot, $cur)
    }
    if (Test-A2CDataset 'EntraUsers') { & $addKpi 'Entra users' @($run.Data['EntraUsers']).Count }
    if (Test-A2CDataset 'EntraApps') { & $addKpi 'App registrations' @($run.Data['EntraApps']).Count }
    $fh = @($run.Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $fm = @($run.Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    & $addKpi 'High findings' $fh
    & $addKpi 'Medium findings' $fm
    $kh = [System.Text.StringBuilder]::new()
    [void]$kh.Append('<div class="kpis">')
    foreach ($k in $kpi) { [void]$kh.AppendFormat('<div class="kpi"><div class="v">{0}</div><div class="l">{1}</div></div>', (ConvertTo-A2CHtmlText $k[1]), (ConvertTo-A2CHtmlText $k[0])) }
    [void]$kh.Append('</div>')
    & $addSection 'overview' 'Overview' $kh.ToString()

    # ---- findings
    $fRows = Get-A2COutputRows 'findings.csv'
    if ($fRows.Count -eq 0) { $fRows = $run.Findings }
    $fcols = @(
        @{ Key = 'Severity'; Header = 'Severity'; Render = { param($r) '<span class="sev ' + (ConvertTo-A2CHtmlText $r['Severity']) + '">' + (ConvertTo-A2CHtmlText $r['Severity']) + '</span>' } }
        @{ Key = 'Category'; Header = 'Category' }, @{ Key = 'Title'; Header = 'Finding' }, @{ Key = 'Count'; Header = 'Count'; Num = $true }
        @{ Key = 'Detail'; Header = 'Detail' }, @{ Key = 'Recommendation'; Header = 'Recommendation' }
        @{ Key = 'AffectedFile'; Header = 'File'; Render = { param($r) $u = [string]$r['LearnMore']; $f = ConvertTo-A2CHtmlText $r['AffectedFile']; if ($u -match '^https://') { $f + '<br><a href="' + (ConvertTo-A2CHtmlText $u) + '" target="_blank" rel="noopener">Learn more</a>' } else { $f } } }
    )
    $fh2 = New-A2CHtmlTable -Id 'tFindings' -Columns $fcols -Rows $fRows -File 'findings.csv'
    $ne = [int]$run.Data['FindingsNotEvaluated']
    if ($ne -gt 0) { $fh2 += ('<p class="muted">{0} further checks were not run because their data was not selected (see Coverage).</p>' -f $ne) }
    & $addSection 'findings' 'Findings' $fh2

    # ---- inventory charts
    if ($haveRes) {
        $byType = Get-A2CCountBy $res { param($x) Get-A2CTypeCased -Id ([string]$x.id) -Fallback ([string]$x.type) }
        $byLoc = Get-A2CCountBy $res { param($x) [string]$x.location }
        $bySub = Get-A2CCountBy $res { param($x) Get-A2CMaskedName 'sub' (Get-A2CSubName ([string]$x.subscriptionId)) }
        $inv = '<div class="grid2"><div><h3>Top resource types</h3>' + (New-A2CHtmlBars $byType 15) + '</div><div><h3>Resources by region</h3>' + (New-A2CHtmlBars $byLoc 15) + '</div></div>' +
        '<h3>Resources by subscription</h3>' + (New-A2CHtmlBars $bySub 25)
        & $addSection 'inventory' 'Inventory' $inv
    }

    # ---- migration readiness
    $mig = [System.Text.StringBuilder]::new()
    if ((Test-A2CDataset 'MoveData') -and $haveRes) {
        $subMove = Get-A2CCountBy $res { param($x) (Get-A2CMoveInfo ([string]$x.type)).Sub }
        $regMove = Get-A2CCountBy $res { param($x) (Get-A2CMoveInfo ([string]$x.type)).Region }
        [void]$mig.Append('<div class="grid2"><div><h3>Can move to another subscription</h3>' + (New-A2CHtmlBars $subMove 8) + '</div><div><h3>Can move to another region</h3>' + (New-A2CHtmlBars $regMove 8) + '</div></div>')
        [void]$mig.Append('<p class="muted">Per resource type, from Microsoft Learn <a href="https://learn.microsoft.com/azure/azure-resource-manager/management/move-support-resources" target="_blank" rel="noopener">Azure resource types for move operations</a> (CC BY 4.0). Details: moveSupport.csv and the CanMoveTo* columns of allResources.csv.</p>')
    }
    $tt = Get-A2COutputRows 'tenantTransferImpact.csv'
    if ($tt.Count -gt 0) {
        [void]$mig.Append('<h3>Tenant transfer impact (subscription moved to another Entra tenant)</h3>' + (New-A2CHtmlBars (Get-A2CCountBy $tt { param($x) $x['Category'] + ' (' + $x['Impact'] + ')' }) 12))
    }
    $pr = @($run.Data['PolicyRestrictions'])
    if ($pr.Count -gt 0 -and $null -ne $pr[0]) {
        $prRows = @(foreach ($x in $pr) { [ordered]@{ Policy = $x.Policy; Values = $x.Values; Assignment = (Get-A2CMaskedName 'known' $x.Assignment.DisplayName); Scope = (Get-A2CMaskedName 'id' $x.Assignment.Scope); Via = (Get-A2CMaskedName 'known' $x.Via) } })
        [void]$mig.Append('<h3>Policies that restrict migration targets</h3>' + (New-A2CHtmlTable -Id 'tRestr' -Columns @(@{ Key = 'Policy'; Header = 'Policy' }, @{ Key = 'Values'; Header = 'Allowed / blocked values' }, @{ Key = 'Assignment'; Header = 'Assignment' }, @{ Key = 'Via'; Header = 'Initiative' }, @{ Key = 'Scope'; Header = 'Scope' }) -Rows $prRows -File 'policyAssignments.csv'))
    }
    $xr = Get-A2COutputRows 'crossReferences.csv'
    if ($xr.Count -gt 0) { [void]$mig.Append(('<p>{0} references to resources in other resource groups/subscriptions (crossReferences.csv) - dependent resources must move together.</p>' -f $xr.Count)) }
    & $addSection 'migration' 'Migration readiness' $mig.ToString()

    # ---- retirements
    $ret = Get-A2COutputRows 'retirements.csv'
    if ($ret.Count -gt 0) {
        $grp = @{}
        foreach ($r in $ret) {
            $k = $r['Feature'] + '|' + $r['RetirementDate']
            if (-not $grp.ContainsKey($k)) { $grp[$k] = [ordered]@{ Feature = $r['Feature']; RetirementDate = $r['RetirementDate']; Status = $r['Status']; DaysLeft = $r['DaysLeft']; Resources = 0; Action = $r['Action'] } }
            $grp[$k]['Resources'] = [int]$grp[$k]['Resources'] + 1
        }
        $rows = @($grp.Values | Sort-Object @{ Expression = { if ($null -eq $_['DaysLeft'] -or "$($_['DaysLeft'])" -eq '') { 99999 } else { [int]$_['DaysLeft'] } } })
        & $addSection 'retirements' 'Retirements' (New-A2CHtmlTable -Id 'tRet' -Columns @(@{ Key = 'Feature'; Header = 'Service / feature' }, @{ Key = 'RetirementDate'; Header = 'Date' }, @{ Key = 'Status'; Header = 'Status' }, @{ Key = 'DaysLeft'; Header = 'Days left'; Num = $true }, @{ Key = 'Resources'; Header = 'Resources'; Num = $true }, @{ Key = 'Action'; Header = 'Action' }) -Rows $rows -File 'retirements.csv')
    }

    # ---- Azure DevOps
    $aorg = Get-A2COutputRows 'ADO/organizations.csv'
    if ($aorg.Count -gt 0) {
        $ado = [System.Text.StringBuilder]::new()
        $sum = { param($Column) $t = 0; foreach ($x in $aorg) { $t += [int]$x[$Column] }; $t }
        $conn = Get-A2COutputRows 'ADO/serviceConnections.csv'
        $st = [ordered]@{ 'Organizations collected' = ('{0} of {1}' -f @($aorg | Where-Object { $_['Status'] -eq 'Collected' }).Count, $aorg.Count)
            'Projects' = (& $sum 'Projects'); 'Repositories' = (& $sum 'Repositories'); 'Pipelines' = ((& $sum 'Pipelines') + (& $sum 'ReleasePipelines'))
            'Service connections' = $conn.Count; 'Secret-based connections' = @($conn | Where-Object { $_['SecretBased'] -eq $true }).Count
            'Self-hosted agents' = (& $sum 'SelfHostedAgents'); 'Users (Basic or better)' = (& $sum 'PaidUsers') }
        [void]$ado.Append('<div class="kpis">')
        foreach ($k in $st.Keys) { [void]$ado.AppendFormat('<div class="kpi"><div class="v">{0}</div><div class="l">{1}</div></div>', (ConvertTo-A2CHtmlText $st[$k]), (ConvertTo-A2CHtmlText $k)) }
        [void]$ado.Append('</div>')
        [void]$ado.Append('<h3>Organizations</h3>' + (New-A2CHtmlTable -Id 'tAdoOrg' -Columns @(@{ Key = 'Organization'; Header = 'Organization' }, @{ Key = 'Status'; Header = 'Status' }, @{ Key = 'Projects'; Header = 'Projects'; Num = $true }, @{ Key = 'Repositories'; Header = 'Repos'; Num = $true }, @{ Key = 'Pipelines'; Header = 'Pipelines'; Num = $true }, @{ Key = 'ServiceConnections'; Header = 'Service connections'; Num = $true }, @{ Key = 'Users'; Header = 'Users'; Num = $true }, @{ Key = 'BillingSubscription'; Header = 'Billed to' }) -Rows $aorg -File 'ADO/organizations.csv'))
        $az = @($conn | Where-Object { $_['Type'] -eq 'azurerm' })
        if ($az.Count -gt 0) { [void]$ado.Append('<h3>Service connections to Azure</h3>' + (New-A2CHtmlTable -Id 'tAdoConn' -Columns @(@{ Key = 'ServiceConnection'; Header = 'Service connection' }, @{ Key = 'Organization'; Header = 'Organization' }, @{ Key = 'AuthScheme'; Header = 'Authentication' }, @{ Key = 'AzureSubscription'; Header = 'Subscription' }, @{ Key = 'AppName'; Header = 'Identity' }, @{ Key = 'SecretExpires'; Header = 'Secret expires' }, @{ Key = 'AzureRoles'; Header = 'Azure roles' }) -Rows $az -File 'ADO/serviceConnections.csv' -Filter)) }
        [void]$ado.Append('<p class="muted">The files are in the ADO folder of the run: organizations.csv, and one folder per organization with its projects, repositories, pipelines, agents, users and licenses, administrators, variable groups (names only), environments, extensions, service hooks, feeds, work items and processes.</p>')
        & $addSection 'devops' 'Azure DevOps' $ado.ToString()
    }

    # ---- security
    $sec = [System.Text.StringBuilder]::new()
    $ra = Get-A2COutputRows 'RBAC_role_assignments.csv'
    if ($ra.Count -gt 0) {
        $st = [ordered]@{ 'Role assignments' = $ra.Count; 'Privileged (Owner/Contributor/UAA)' = @($ra | Where-Object { $_['IsPrivilegedRole'] -eq $true }).Count
            'Guest assignments' = @($ra | Where-Object { $_['UserType'] -eq 'Guest' }).Count; 'Orphaned (deleted principal)' = @($ra | Where-Object { $_['PrincipalStatus'] -like 'NotFound*' }).Count
            'Inherited from management groups' = @($ra | Where-Object { $_['Inherited'] -eq $true }).Count }
        [void]$sec.Append('<h3>Azure RBAC</h3><div class="kpis">')
        foreach ($k in $st.Keys) { [void]$sec.AppendFormat('<div class="kpi"><div class="v">{0}</div><div class="l">{1}</div></div>', $st[$k], (ConvertTo-A2CHtmlText $k)) }
        [void]$sec.Append('</div>')
    }
    $nr = @((Get-A2COutputRows 'nsgRules.csv') | Where-Object { $_['Risk'] })
    if ($nr.Count -gt 0) { [void]$sec.Append('<h3>Inbound NSG rules open to the Internet</h3>' + (New-A2CHtmlTable -Id 'tNsg' -Columns @(@{ Key = 'Risk'; Header = 'Risk' }, @{ Key = 'NSG'; Header = 'NSG' }, @{ Key = 'Rule'; Header = 'Rule' }, @{ Key = 'Priority'; Header = 'Priority'; Num = $true }, @{ Key = 'Source'; Header = 'Source' }, @{ Key = 'DestinationPorts'; Header = 'Ports' }, @{ Key = 'SubscriptionName'; Header = 'Subscription' }) -Rows $nr -File 'nsgRules.csv' -Filter)) }
    $cr = @((Get-A2COutputRows 'credentials.csv') | Where-Object { $_['Status'] -and $_['Status'] -ne 'OK' })
    if ($cr.Count -gt 0) { [void]$sec.Append('<h3>App secrets and certificates: expired or expiring</h3>' + (New-A2CHtmlTable -Id 'tCred' -Columns @(@{ Key = 'Status'; Header = 'Status' }, @{ Key = 'OwnerName'; Header = 'Application' }, @{ Key = 'OwnerType'; Header = 'Object' }, @{ Key = 'CredentialType'; Header = 'Type' }, @{ Key = 'EndDateTime'; Header = 'Expires' }, @{ Key = 'DaysToExpiry'; Header = 'Days'; Num = $true }) -Rows $cr -File 'credentials.csv' -Filter)) }
    $ap = @((Get-A2COutputRows 'appPermissions.csv') | Where-Object { $_['Risk'] })
    if ($ap.Count -gt 0) { [void]$sec.Append('<h3>High-risk API permissions</h3>' + (New-A2CHtmlTable -Id 'tPerm' -Columns @(@{ Key = 'Risk'; Header = 'Risk' }, @{ Key = 'ClientName'; Header = 'Application' }, @{ Key = 'ClientPublisher'; Header = 'Publisher' }, @{ Key = 'PermissionType'; Header = 'Type' }, @{ Key = 'Permission'; Header = 'Permission' }, @{ Key = 'ResourceName'; Header = 'API' }, @{ Key = 'ConsentType'; Header = 'Consent' }) -Rows $ap -File 'appPermissions.csv' -Filter)) }
    & $addSection 'security' 'Security' $sec.ToString()

    # ---- governance
    $gov = [System.Text.StringBuilder]::new()
    $mg = Get-A2COutputRows 'managementGroups.csv'
    if ($mg.Count -gt 0) {
        [void]$gov.Append('<h3>Management group hierarchy</h3><div class="tree">')
        foreach ($m in @($mg | Sort-Object { $_['Path'] })) {
            $pad = [int]$m['Level'] * 22
            [void]$gov.AppendFormat('<div style="padding-left:{0}px"><span class="mg">{1}</span><span class="pill">{2} sub(s)</span> <span class="muted">{3}</span></div>', $pad, (ConvertTo-A2CHtmlText $(if ($m['DisplayName']) { $m['DisplayName'] } else { $m['ManagementGroup'] })), $m['TotalSubscriptions'], (ConvertTo-A2CHtmlText $m['Subscriptions']))
        }
        [void]$gov.Append('</div>')
    }
    $pa = Get-A2COutputRows 'policyAssignments.csv'
    if ($pa.Count -gt 0) {
        [void]$gov.Append('<h3>Policy assignments</h3>' + (New-A2CHtmlTable -Id 'tPol' -Columns @(@{ Key = 'DisplayName'; Header = 'Assignment' }, @{ Key = 'ScopeType'; Header = 'Scope' }, @{ Key = 'DefinitionType'; Header = 'Type' }, @{ Key = 'EnforcementMode'; Header = 'Mode' }, @{ Key = 'NonCompliantResources'; Header = 'Non-compliant'; Num = $true }, @{ Key = 'CompliantResources'; Header = 'Compliant'; Num = $true }, @{ Key = 'Restricts'; Header = 'Restricts' }) -Rows @($pa | Sort-Object @{ Expression = { -1 * [double]("0" + $_['NonCompliantResources']) } }) -File 'policyAssignments.csv' -Filter))
    }
    $ex = @((Get-A2COutputRows 'policyExemptions.csv') | Where-Object { $_['Status'] -ne 'Active' })
    if ($ex.Count -gt 0) { [void]$gov.Append('<h3>Policy exemptions to review</h3>' + (New-A2CHtmlTable -Id 'tEx' -Columns @(@{ Key = 'DisplayName'; Header = 'Exemption' }, @{ Key = 'Status'; Header = 'Status' }, @{ Key = 'ExpiresOn'; Header = 'Expires' }, @{ Key = 'Category'; Header = 'Category' }, @{ Key = 'Assignment'; Header = 'Assignment' }) -Rows $ex -File 'policyExemptions.csv')) }
    & $addSection 'governance' 'Governance' $gov.ToString()

    # ---- cost
    $cost = Get-A2COutputRows 'cost.csv'
    if ($cost.Count -gt 0) {
        $cs = [System.Text.StringBuilder]::new()
        $cur = [string]$cost[0]['Currency']
        [void]$cs.Append('<div class="grid2"><div><h3>Cost by subscription</h3>' + (New-A2CHtmlBars (Get-A2CCountBy $cost { param($x) $x['SubscriptionName'] } { param($x) $x['Cost'] }) 20 $cur) + '</div>')
        [void]$cs.Append('<div><h3>Cost by resource type</h3>' + (New-A2CHtmlBars (Get-A2CCountBy $cost { param($x) $x['ResourceType'] } { param($x) $x['Cost'] }) 12 $cur) + '</div></div>')
        [void]$cs.Append('<h3>Top resources by cost</h3>' + (New-A2CHtmlTable -Id 'tCost' -Columns @(@{ Key = 'Resource'; Header = 'Resource' }, @{ Key = 'ResourceType'; Header = 'Type' }, @{ Key = 'ResourceGroup'; Header = 'Resource group' }, @{ Key = 'SubscriptionName'; Header = 'Subscription' }, @{ Key = 'Cost'; Header = 'Cost'; Num = $true }, @{ Key = 'Currency'; Header = 'Currency' }) -Rows $cost -Max 25 -File 'cost.csv'))
        & $addSection 'cost' 'Cost' $cs.ToString()
    }

    # ---- Entra
    if ((Test-A2CDataset 'EntraUsers') -or (Test-A2CDataset 'EntraApps') -or (Test-A2CDataset 'EntraDirectoryRoles')) {
        $e = [ordered]@{}
        $u = @($run.Data['EntraUsers'])
        if (Test-A2CDataset 'EntraUsers') {
            $e['Users'] = $u.Count; $e['Guests'] = @($u | Where-Object { $_.userType -eq 'Guest' }).Count
            $e['Disabled'] = @($u | Where-Object { $_.accountEnabled -eq $false }).Count
            $e['Synced from AD'] = @($u | Where-Object { $_.onPremisesSyncEnabled -eq $true }).Count
        }
        if (Test-A2CDataset 'EntraGroups') { $e['Groups'] = @($run.Data['EntraGroups']).Count }
        if (Test-A2CDataset 'EntraApps') { $e['App registrations'] = @($run.Data['EntraApps']).Count }
        if (Test-A2CDataset 'EntraServicePrincipals') {
            $sps = @($run.Data['EntraSPs'])
            $e['Managed identities'] = @($sps | Where-Object { $_.servicePrincipalType -eq 'ManagedIdentity' }).Count
            $e['Enterprise apps (3rd party)'] = @($sps | Where-Object { $_.servicePrincipalType -ne 'ManagedIdentity' -and (Get-A2CSpPublisher $_) -eq 'Third party' }).Count
        }
        $dr = Get-A2COutputRows 'directoryRoles.csv'
        if ($dr.Count -gt 0) { $e['Privileged role holders'] = (Get-A2CUnique @($dr | Where-Object { $_['IsPrivilegedRole'] -eq $true } | ForEach-Object { $_['PrincipalId'] })).Count }
        $eh = [System.Text.StringBuilder]::new()
        [void]$eh.Append('<div class="kpis">')
        foreach ($k in $e.Keys) { [void]$eh.AppendFormat('<div class="kpi"><div class="v">{0}</div><div class="l">{1}</div></div>', $e[$k], (ConvertTo-A2CHtmlText $k)) }
        [void]$eh.Append('</div>')
        if ($dr.Count -gt 0) { [void]$eh.Append('<h3>Privileged directory roles</h3>' + (New-A2CHtmlTable -Id 'tDir' -Columns @(@{ Key = 'RoleName'; Header = 'Role' }, @{ Key = 'PrincipalName'; Header = 'Principal' }, @{ Key = 'PrincipalType'; Header = 'Type' }, @{ Key = 'IsGuest'; Header = 'Guest' }) -Rows @($dr | Where-Object { $_['IsPrivilegedRole'] -eq $true }) -File 'directoryRoles.csv')) }
        & $addSection 'entra' 'Entra ID' $eh.ToString()
    }

    # ---- coverage and files
    $cov = Get-A2COutputRows 'coverage.csv'
    if ($cov.Count -eq 0) { $cov = $run.Coverage }
    $covHtml = New-A2CHtmlTable -Id 'tCov' -Columns @(@{ Key = 'Area'; Header = 'Area' }, @{ Key = 'Status'; Header = 'Status' }, @{ Key = 'Items'; Header = 'Items'; Num = $true }, @{ Key = 'Detail'; Header = 'Detail' }) -Rows @($cov | Where-Object { $_['Status'] -ne 'NotSelected' }) -Filter
    $nsel = @($cov | Where-Object { $_['Status'] -eq 'NotSelected' } | ForEach-Object { ([string]$_['Area']) -replace '^Report ', '' })
    if ($nsel.Count -gt 0) { $covHtml += '<p class="muted">Reports not selected in this run: ' + (ConvertTo-A2CHtmlText ([string]::Join(', ', $nsel))) + '. Use -Profile Full or -AddReports to include them.</p>' }
    $files = @($run.Files | Sort-Object File | ForEach-Object { [ordered]@{ File = $_.File; Rows = $_.Rows } })
    $covHtml += '<h3>Files in this folder</h3>' + (New-A2CHtmlTable -Id 'tFiles' -Columns @(@{ Key = 'File'; Header = 'File' }, @{ Key = 'Rows'; Header = 'Rows'; Num = $true }) -Rows $files -Max 500)
    & $addSection 'coverage' 'Coverage' $covHtml

    # ---- assemble
    $hash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($script:A2CHtmlJs)))
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.AppendFormat('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; script-src ''sha256-{0}''; img-src data:">', $hash)
    [void]$sb.AppendFormat('<title>{0}</title><style>{1}</style></head><body>', (ConvertTo-A2CHtmlText $title), $script:A2CHtmlCss)
    $when = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm')
    [void]$sb.AppendFormat('<header><div class="top"><div><h1>{0}</h1><div class="meta">Tenant {1} &middot; {2} subscription(s) &middot; generated {3} &middot; profile {4} &middot; azure2csv {5}</div></div><button id="themeToggle" type="button">Light / dark</button></div>',
        (ConvertTo-A2CHtmlText $title), (ConvertTo-A2CHtmlText $tenantId), @($run.Data['Subscriptions']).Count, $when, (ConvertTo-A2CHtmlText $(if (@($run.Options.Reports).Count) { 'custom' } else { $run.Options.Profile })), $script:A2CVersion)
    if ($mask) { [void]$sb.Append('<div class="banner">Masked report: names, IDs, IPs and tag values are pseudonymized. Only the owner of the report holds the mapping.</div>') }
    [void]$sb.Append('</header><nav>')
    foreach ($s in $sections) { [void]$sb.AppendFormat('<a href="#{0}">{1}</a>', $s.Id, (ConvertTo-A2CHtmlText $s.Title)) }
    [void]$sb.Append('</nav><main>')
    foreach ($s in $sections) { [void]$sb.AppendFormat('<section id="{0}"><h2>{1}</h2>{2}</section>', $s.Id, (ConvertTo-A2CHtmlText $s.Title), $s.Html) }
    [void]$sb.Append('</main><footer>')
    [void]$sb.AppendFormat('<div class="cta">{0} <a href="mailto:{1}">{1}</a></div>', (ConvertTo-A2CHtmlText $script:A2CBrand.Tagline), $script:A2CBrand.Email)
    [void]$sb.AppendFormat('<div>Generated by <a href="{0}" target="_blank" rel="noopener">azure2csv</a> {1} &middot; free and open source (MIT) by {2} &middot; <a href="{3}" target="_blank" rel="noopener">it4it.solutions</a></div>', $script:A2CBrand.Repo, $script:A2CVersion, (ConvertTo-A2CHtmlText $script:A2CBrand.Author), $script:A2CBrand.Site)
    [void]$sb.Append('<div class="muted">Read-only inventory: the script does not change anything in Azure or Entra ID. Findings are indicators to review, not a formal audit.</div>')
    [void]$sb.AppendFormat('</footer><script>{0}</script></body></html>', $script:A2CHtmlJs)
    $path = Save-A2CText -File 'summary.html' -Text $sb.ToString() -NoBom
    $script:A2C.Files.Add([pscustomobject]@{ File = 'summary.html'; Rows = $sections.Count; Path = $path })
    return $path
}

function Write-A2CSummary {
    param([string] $ZipPath)
    $run = $script:A2C
    $dur = [DateTime]::UtcNow - $run.StartedUtc
    $resCount = @($run.Data['Resources']).Count
    $high = @($run.Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $done = 'Done in {0:hh\:mm\:ss}: {1} subscription(s), {2} resources, {3} files, {4} findings ({5} high).' -f $dur, @($run.Data['Subscriptions']).Count, $resCount, $run.Files.Count, $run.Findings.Count, $high
    Add-A2CLogLine -Level Ok $done
    Write-Host ''
    Write-Host $done -ForegroundColor Green
    Write-Host ('Results: ' + $run.OutDir) -ForegroundColor Green
    if ($ZipPath) {
        Write-Host ('Zip    : ' + $ZipPath) -ForegroundColor Green
        if ($run.Env.CloudShell) { Write-Host '         In Cloud Shell use "Manage files > Download" to get it.' -ForegroundColor DarkGray }
    }
    if ($run.Options.Mask -and $run.Data['MaskMapPath']) {
        Write-Host ('Mask map (keep private, NOT for sharing): ' + $run.Data['MaskMapPath']) -ForegroundColor Yellow
    }
    if ($run.LogPath) { Write-Host ('Log    : ' + $run.LogPath) -ForegroundColor DarkGray }
    if ($run.Errors.Count -gt 0) { Write-Host ('{0} error(s) - see the log and coverage.csv' -f $run.Errors.Count) -ForegroundColor Yellow }
    Write-Host ''
    Write-Host ('azure2csv by {0} - {1}' -f $script:A2CBrand.Author, $script:A2CBrand.Site) -ForegroundColor Cyan
    Write-Host ($script:A2CBrand.Tagline + '  ' + $script:A2CBrand.Email) -ForegroundColor Cyan
    Write-Host ''
}

#endregion

#region ============================== 10. MAIN ========================================================

function Split-A2CIdList {
    # Accepts arrays and/or comma/semicolon/space separated strings (v1 style "sub1,sub2").
    param($Value)
    $l = [System.Collections.Generic.List[string]]::new()
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        foreach ($p in ([string]$v -split '[,;\s]+')) { if ($p) { $l.Add($p.Trim().ToLowerInvariant()) } }
    }
    return , (Get-A2CUnique $l)
}

function ConvertTo-A2CAdoOrgList {
    # Azure DevOps organization names from names, https://dev.azure.com/<org> or https://<org>.visualstudio.com URLs.
    param($Value)
    $names = foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        foreach ($p in ([string]$v -split '[,;\s]+')) {
            if (-not $p) { continue }
            if ($p -match '^https?://dev\.azure\.com/([^/?#]+)') { $Matches[1] }
            elseif ($p -match '^https?://([^./]+)\.visualstudio\.com') { $Matches[1] }
            else { $p.Trim('/') }
        }
    }
    return , (Get-A2CUnique $names)
}

$script:A2CListParameters = @('Reports', 'AddReports', 'SkipReports', 'SubscriptionId', 'ExcludeSubscriptionId', 'AdoOrganization', 'AdoPackageTypes')
$script:A2CPackageTypes = @('NuGet', 'npm', 'Maven', 'PyPI', 'Cargo', 'Universal')

function Split-A2CNameList {
    # Names from arrays and/or comma, semicolon or space separated text ("RBAC, Policy")
    param($Value)
    $l = [System.Collections.Generic.List[string]]::new()
    foreach ($v in @($Value)) { if ($null -ne $v) { foreach ($p in ([string]$v -split '[,;\s]+')) { if ($p) { $l.Add($p) } } } }
    return , $l.ToArray()
}

function Resolve-A2CListArguments {
    # Started with pwsh -File, from cmd or by a scheduler, "-Reports RBAC, Policy" arrives as "RBAC," for -Reports plus
    # the loose word "Policy". The loose words are in RemainingArguments, in command-line order like the bound
    # parameters, so a list whose last value ends with a comma takes the next ones. Returns the parameters without
    # RemainingArguments; any other loose word is an error.
    param([System.Collections.IDictionary] $Params)
    $out = [ordered]@{}
    $rest = [System.Collections.Generic.Queue[string]]::new()
    foreach ($x in @($Params['RemainingArguments'])) { if ($null -ne $x -and [string]$x -ne '') { $rest.Enqueue([string]$x) } }
    foreach ($k in @($Params.Keys)) {
        if ($k -eq 'RemainingArguments') { continue }
        $v = $Params[$k]
        if ($script:A2CListParameters -contains $k) {
            $vals = [System.Collections.Generic.List[string]]::new()
            foreach ($x in @($v)) { if ($null -ne $x) { $vals.Add([string]$x) } }
            while ($rest.Count -gt 0 -and $vals.Count -gt 0 -and $vals[$vals.Count - 1].TrimEnd().EndsWith(',')) { $vals.Add($rest.Dequeue()) }
            $v = $vals.ToArray()
        }
        $out[$k] = $v
    }
    if ($rest.Count -gt 0) {
        throw ('Unexpected argument(s): {0}. Lists are written with commas, for example -Reports RBAC,Policy' -f [string]::Join(' ', $rest.ToArray()))
    }
    return $out
}

function New-A2COptions {
    param([System.Collections.IDictionary] $Params)
    $o = [ordered]@{
        TenantId = ''; SubscriptionId = @(); ExcludeSubscriptionId = @(); ManagementGroupId = ''; OutputPath = ''
        Profile = 'Standard'; Reports = @(); AddReports = @(); SkipReports = @(); ListReports = $false
        SelectionSpecified = $false
        CostDays = 30; Mask = $false; MaskMapPath = ''; Zip = $false; NoExcel = $false; NoHtml = $false
        MoveSupportFile = ''; UseDeviceAuthentication = $false; AdoOrganization = @(); AdoRepoMaxSizeMB = 1024; AdoPackageVersions = 'Latest'; AdoPackagesMaxMB = 5120; AdoPackageMaxSizeMB = 0; AdoPackageTypes = @(); ArtifactToolPath = ''; TemplateFormat = 'Both'; PropertiesMaxChars = 32000; Delimiter = ','
        V1 = @{}; Now = [DateTime]::UtcNow
    }
    if ($null -eq $Params) { $Params = @{} }
    $Params = Resolve-A2CListArguments $Params
    foreach ($k in @($Params.Keys)) {
        $v = $Params[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { $v = $v.IsPresent }
        switch ($k) {
            'ReportProfile'            { $o.Profile = [string]$v; $o.SelectionSpecified = $true }
            'Profile'                  { $o.Profile = [string]$v; $o.SelectionSpecified = $true }
            'Reports'                  { $o.Reports = @($v); $o.SelectionSpecified = $true }
            'AddReports'               { $o.AddReports = @($v); $o.SelectionSpecified = $true }
            'SkipReports'              { $o.SkipReports = @($v); $o.SelectionSpecified = $true }
            'createAllResourcesReport' { $o.V1['createAllResourcesReport'] = [bool]$v }
            'createRBACreports'        { $o.V1['createRBACreports'] = [bool]$v }
            'createPrivateDNSreport'   { $o.V1['createPrivateDNSreport'] = [bool]$v }
            default                    { if ($o.Contains($k)) { $o[$k] = $v } }
        }
    }
    $o.SubscriptionId = Split-A2CIdList $o.SubscriptionId
    $o.ExcludeSubscriptionId = Split-A2CIdList $o.ExcludeSubscriptionId
    $o.AdoOrganization = ConvertTo-A2CAdoOrgList $o.AdoOrganization
    # names are checked here instead of by ValidateSet (see the param block); unknown ones stop the run before the sign-in
    foreach ($k in @('Reports', 'AddReports', 'SkipReports')) { $o[$k] = Split-A2CNameList $o[$k] }
    [void](Expand-A2CReportNames (@($o.Reports) + @($o.AddReports) + @($o.SkipReports)) -IncludeOptIn)
    $types = [System.Collections.Generic.List[string]]::new()
    foreach ($n in (Split-A2CNameList $o.AdoPackageTypes)) {
        $hit = @($script:A2CPackageTypes | Where-Object { $_ -ieq $n })
        if ($hit.Count -eq 0) { throw ("Unknown package type '{0}'. Valid types: {1}." -f $n, [string]::Join(', ', $script:A2CPackageTypes)) }
        if (-not $types.Contains($hit[0])) { $types.Add($hit[0]) }
    }
    $o.AdoPackageTypes = $types.ToArray()
    if ($o.TenantId) { $o.TenantId = ([string]$o.TenantId).Trim().ToLowerInvariant() }
    if ($o.Mask) { $o.Zip = $true }
    if (-not $script:A2CProfiles.Contains([string]$o.Profile)) { throw ("Unknown profile '{0}'" -f $o.Profile) }
    return [pscustomobject]$o
}

function Expand-A2CReportNames {
    # Report and group names -> report names. Group names add opt-in reports only with -IncludeOptIn.
    param($Names, [switch] $IncludeOptIn)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($n in @($Names)) {
        if (-not $n) { continue }
        # All (and -Profile Full) leaves out Explicit reports such as the repository export: they run only when named
        if ($n -ieq 'All') { foreach ($r in $script:A2CReportCatalog) { if (-not $r.Explicit -or $IncludeOptIn) { $out.Add($r.Name) } }; continue }
        if ($script:A2CReportGroups -contains $n) {
            foreach ($r in $script:A2CReportCatalog) { if ($r.Group -ieq $n -and ((-not $r.OptIn) -or $IncludeOptIn)) { $out.Add($r.Name) } }
            continue
        }
        $rep = $null
        foreach ($r in $script:A2CReportCatalog) { if ($r.Name -ieq $n) { $rep = $r; break } }
        if ($null -eq $rep) { throw ("Unknown report or group '{0}'. Run -ListReports to see valid names." -f $n) }
        $out.Add($rep.Name)
    }
    return , $out.ToArray()
}

function Resolve-A2CSelection {
    param($Options)
    if (@($Options.Reports).Count -gt 0) { $base = Expand-A2CReportNames $Options.Reports }
    else { $base = Expand-A2CReportNames $script:A2CProfiles[[string]$Options.Profile] }
    $add = Expand-A2CReportNames $Options.AddReports
    $skipList = [System.Collections.Generic.List[string]]::new()
    foreach ($s in (Expand-A2CReportNames $Options.SkipReports -IncludeOptIn)) { $skipList.Add($s) }
    if ($Options.V1.ContainsKey('createAllResourcesReport') -and -not $Options.V1['createAllResourcesReport']) { $skipList.Add('Resources'); $skipList.Add('Tags') }
    if ($Options.V1.ContainsKey('createRBACreports') -and -not $Options.V1['createRBACreports']) { $skipList.Add('RBAC') }
    if ($Options.V1.ContainsKey('createPrivateDNSreport') -and -not $Options.V1['createPrivateDNSreport']) { $skipList.Add('PrivateDNS') }
    $want = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $base) { [void]$want.Add($n) }
    foreach ($n in $add) { [void]$want.Add($n) }
    foreach ($n in $skipList) { [void]$want.Remove($n) }
    $sel = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $script:A2CReportCatalog) { if ($want.Contains($r.Name)) { $sel.Add($r.Name) } }
    return , $sel.ToArray()
}

function Resolve-A2CDatasets {
    # Selected reports -> datasets to collect (transitive dependencies), in execution order.
    param([string[]] $Reports)
    $need = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($rn in $Reports) {
        foreach ($r in $script:A2CReportCatalog) { if ($r.Name -eq $rn) { foreach ($d in $r.Needs) { [void]$need.Add($d) } } }
    }
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($d in @($need)) { foreach ($dep in $script:A2CDatasetCatalog[$d].Needs) { if ($need.Add($dep)) { $changed = $true } } }
    }
    $ordered = [System.Collections.Generic.List[string]]::new()
    foreach ($k in $script:A2CDatasetCatalog.Keys) { if ($need.Contains($k)) { $ordered.Add($k) } }
    return , $ordered.ToArray()
}

function Show-A2CReportList {
    param($Options)
    Write-Host ''
    Write-Host ('azure2csv {0} - report catalog' -f $script:A2CVersion) -ForegroundColor Cyan
    $profiles = @($script:A2CProfiles.Keys)
    $selected = @()
    if ($Options.SelectionSpecified) { $selected = Resolve-A2CSelection $Options }
    $rows = foreach ($r in $script:A2CReportCatalog) {
        $inProfiles = @(foreach ($p in $profiles) {
                $members = Expand-A2CReportNames $script:A2CProfiles[$p]
                if ($members -contains $r.Name) { $p }
            })
        $o = [ordered]@{}
        if ($Options.SelectionSpecified) { $o['Run'] = $(if ($selected -contains $r.Name) { 'yes' } else { '' }) }
        $o['Group'] = $r.Group
        $o['Report'] = $r.Name + $(if ($r.Explicit) { ' **' } elseif ($r.OptIn) { ' *' } else { '' })
        $o['Speed'] = $r.Speed
        $o['Profiles'] = [string]::Join(',', $inProfiles)
        $o['Files'] = $r.Files
        [pscustomobject]$o
    }
    if ($Options.SelectionSpecified) {
        $desc = if (@($Options.Reports).Count -gt 0) { '-Reports ' + [string]::Join(', ', @($Options.Reports)) } else { '-Profile ' + $Options.Profile }
        if (@($Options.AddReports).Count -gt 0) { $desc += ' -AddReports ' + [string]::Join(', ', @($Options.AddReports)) }
        if (@($Options.SkipReports).Count -gt 0) { $desc += ' -SkipReports ' + [string]::Join(', ', @($Options.SkipReports)) }
        Write-Host ('Selection: {0}  ->  {1} reports' -f $desc, @($selected).Count) -ForegroundColor Cyan
        $rows = @($rows | Where-Object { $_.Run -eq 'yes' })
    }
    Write-Host ($rows | Format-Table -AutoSize -Wrap | Out-String -Width 220)
    if ($Options.SelectionSpecified) {
        $ds = Resolve-A2CDatasets $selected
        Write-Host ('Data collected: ' + [string]::Join(', ', $ds))
        $slow = @($script:A2CReportCatalog | Where-Object { $selected -contains $_.Name -and $_.Speed -eq 'Slow' } | ForEach-Object { $_.Name })
        if ($slow.Count -gt 0) {
            Write-Host ('Slow reports in this selection (one call per resource/object): ' + [string]::Join(', ', $slow)) -ForegroundColor Yellow
        }
        else { Write-Host 'No slow reports in this selection.' -ForegroundColor Green }
    }
    else {
        Write-Host '* = opt-in: only in -Profile Full or when named in -Reports/-AddReports.'
        Write-Host '** = only when named in -Reports/-AddReports (not in -Profile Full).'
        Write-Host ('Groups: ' + [string]::Join(', ', $script:A2CReportGroups) + ', All')
        Write-Host 'Examples:  -Profile Migration   -Reports RBAC,Policy   -AddReports Cost   -SkipReports DiagnosticSettings,Entra'
    }
    Write-Host ''
}

function Invoke-A2CDataset {
    param([string] $Name)
    $info = $script:A2CDatasetCatalog[$Name]
    Write-A2CLog -Level Step ('{0}: {1}' -f $Name, $info.Desc)
    $t0 = [DateTime]::UtcNow
    $status = 'Collected'
    $note = ''
    try {
        $res = & ('Get-A2CDataset' + $Name)
        if ($null -ne $res -and $res.PSObject.Properties['Status']) { $status = [string]$res.Status; $note = [string]$res.Note }
    }
    catch {
        $status = 'Failed'
        $note = $_.Exception.Message
        Write-A2CLog -Level Error ('{0} failed: {1}' -f $Name, $note)
        Add-A2CLogLine -Level Detail ('at ' + (Get-A2CStackText $_))
        Add-A2CCoverage -Area $Name -Status Failed -Detail $note
    }
    $script:A2C.DatasetStatus[$Name] = $status
    $script:A2C.Stages.Add([ordered]@{ Stage = 'Dataset:' + $Name; Status = $status; DurationSec = [math]::Round(([DateTime]::UtcNow - $t0).TotalSeconds, 1); Note = $note })
}

function New-A2CDatasetResult {
    param([string] $Status = 'Collected', [string] $Note = '')
    return [pscustomobject]@{ Status = $Status; Note = $Note }
}

function Invoke-A2CReportBuilder {
    param([string] $Name)
    $t0 = [DateTime]::UtcNow
    $status = 'Built'
    $note = ''
    try {
        & ('New-A2CReport' + $Name)
    }
    catch {
        $status = 'Failed'
        $note = $_.Exception.Message + ' @ ' + $_.InvocationInfo.ScriptLineNumber
        Write-A2CLog -Level Error ('Report {0} failed: {1}' -f $Name, $note)
        Add-A2CLogLine -Level Detail ('at ' + (Get-A2CStackText $_))
        Add-A2CCoverage -Area ('Report ' + $Name) -Status Failed -Detail $note
    }
    $script:A2C.Stages.Add([ordered]@{ Stage = 'Report:' + $Name; Status = $status; DurationSec = [math]::Round(([DateTime]::UtcNow - $t0).TotalSeconds, 1); Note = $note })
}

function Get-A2COutputBase {
    $base = $script:A2C.Options.OutputPath
    if (-not $base) { $base = (Get-Location).ProviderPath }
    if (-not (Test-Path -LiteralPath $base)) { New-Item -ItemType Directory -Path $base -Force | Out-Null }
    return (Resolve-Path -LiteralPath $base).ProviderPath
}

function Initialize-A2COutputFolder {
    $o = $script:A2C.Options
    $base = Get-A2COutputBase
    $tenant8 = ''
    if ($script:A2C.TenantId) { $tenant8 = $script:A2C.TenantId.Substring(0, [math]::Min(8, $script:A2C.TenantId.Length)) }
    if ($o.Mask -and $script:A2C.TenantId) { $tenant8 = (Get-A2CMaskGuid $script:A2C.TenantId).Substring(0, 8) }
    $ts = [DateTime]::Now.ToString('yyyyMMdd-HHmmss')
    $name = 'azure2csv_{0}_{1}' -f $ts, $tenant8
    $dir = [IO.Path]::Combine($base, $name)
    $n = 1
    while (Test-Path -LiteralPath $dir) { $n++; $name = 'azure2csv_{0}_{1}-{2}' -f $ts, $tenant8, $n; $dir = [IO.Path]::Combine($base, $name) }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $script:A2C.OutDir = $dir
    $script:A2C.RunName = $name
    $script:A2C.RunStamp = $ts
    if ($n -gt 1) { $script:A2C.RunStamp = $ts + '-' + $n }
    $script:A2C.Env['OutputBase'] = $base
    Open-A2CGeneralLog
}

function Invoke-A2CRun {
    param($Options)
    $run = New-A2CRunContext -Options $Options
    $run.Selected = Resolve-A2CSelection $Options
    $run.Datasets = Resolve-A2CDatasets $run.Selected
    if (@($run.Selected).Count -eq 0) { throw 'No reports selected. Run -ListReports to see the report names.' }

    $banner = 'azure2csv {0}  -  {1}  -  {2}' -f $script:A2CVersion, $script:A2CBrand.Site, $script:A2CBrand.Email
    $reports = 'Reports ({0}): {1}' -f @($run.Selected).Count, [string]::Join(', ', $run.Selected)
    Write-Host ''
    Write-Host $banner -ForegroundColor Cyan
    Write-Host $reports -ForegroundColor DarkGray
    Add-A2CLogLine -Level Info $banner
    Add-A2CLogLine -Level Info $reports

    $run.Env = Get-A2CHostInfo
    if ($run.Env.PSEdition -ne 'Core') {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { Write-Verbose ('TLS 1.2 could not be enabled: ' + $_.Exception.Message) }
    }
    $run.Env['AzAccounts'] = Assert-A2CPrerequisites
    $psName = $(if ($run.Env.PSEdition -eq 'Core') { 'PowerShell' } else { 'Windows PowerShell' })
    $where = $(if ($run.Env.CloudShell) { ' in Cloud Shell' } else { '' })
    Write-A2CLog ('{0} {1}{2}, Az.Accounts {3}' -f $psName, $run.Env.PSVersion, $where, $run.Env.AzAccounts)
    $az = Connect-A2CAzure -Options $Options
    Initialize-A2CEndpoints -Context $az
    $run.TenantId = [string]$Options.TenantId
    if (-not $run.TenantId -and $az.Tenant) { $run.TenantId = ([string]$az.Tenant.Id).ToLowerInvariant() }
    $run.Account = [string]$az.Account.Id
    if ($Options.Mask) { Initialize-A2CMask }
    Initialize-A2COutputFolder
    Write-A2CLog ('Tenant {0}, signed in as {1}' -f $run.TenantId, $run.Account)
    Write-A2CLog ('Output folder: {0}' -f $run.OutDir)
    if ($run.Env.CloudShell -and -not $run.Env.ClouddriveExists) {
        Write-A2CLog -Level Warn 'Cloud Shell without a clouddrive: files are lost when the session ends - download the zip before closing.'
    }

    foreach ($d in $run.Datasets) {
        Invoke-A2CDataset -Name $d
        if ($d -eq 'Subscriptions' -and $run.DatasetStatus['Subscriptions'] -eq 'Failed') { throw 'Cannot continue without the subscription list.' }
    }

    Write-A2CLog -Level Step 'Building reports'
    foreach ($rep in $run.Selected) { Invoke-A2CReportBuilder -Name $rep }
    if ([int]$run.Stats['SecretsHidden'] -gt 0) {
        $hidden = '{0} value(s) of secret properties Azure returned (authorization keys, shared keys, passwords) were replaced with {1}' -f [int]$run.Stats['SecretsHidden'], $script:A2CSecretMark
        Add-A2CCoverage -Area 'Secret values' -Status Info -Detail $hidden
        Write-A2CLog $hidden
    }
    foreach ($r in $script:A2CReportCatalog) {
        if ($run.Selected -notcontains $r.Name) { Add-A2CCoverage -Area ('Report ' + $r.Name) -Status NotSelected -Detail $r.Files }
    }

    if ($Options.Mask) { Complete-A2CMaskDictionary }

    Write-A2CLog -Level Step 'Findings'
    try {
        if ($Options.Mask) { $run.Data['FindingsMasked'] = $true }
        Invoke-A2CFindings
    }
    catch { Write-A2CLog -Level Error ('Findings failed: ' + $_.Exception.Message) }
    finally { $run.Data['FindingsMasked'] = $false }

    Write-A2CLog -Level Step 'Writing files'
    foreach ($f in @($script:A2C.Out.Keys | Sort-Object)) {
        try { Save-A2CCsv -File $f } catch { Write-A2CLog -Level Error ('Cannot write {0}: {1}' -f $f, $_.Exception.Message) }
    }
    # one line per Azure DevOps organization folder instead of one per file
    $adoFolders = [ordered]@{}
    foreach ($x in @($script:A2C.Files | Sort-Object File)) {
        if ($x.File -match '^(ADO/[^/]+)/[^/]+$') {
            if (-not $adoFolders.Contains($Matches[1])) { $adoFolders[$Matches[1]] = @(0, 0) }
            $adoFolders[$Matches[1]][0]++
            $adoFolders[$Matches[1]][1] += $x.Rows
            continue
        }
        Write-A2CLog -Level Detail ('{0,-32} {1,8} rows' -f $x.File, $x.Rows)
    }
    foreach ($k in $adoFolders.Keys) { Write-A2CLog -Level Detail ('{0,-32} {1,8} rows in {2} files' -f ($k + '/'), $adoFolders[$k][1], $adoFolders[$k][0]) }
    $excelOk = $false
    if (-not $Options.NoExcel) {
        if (Test-A2CModuleAvailable 'ImportExcel') { $excelOk = $true; Add-A2CCoverage -Area 'Excel workbook' -Status Collected -Detail ($run.RunName + '.xlsx') }
        else {
            Add-A2CCoverage -Area 'Excel workbook' -Status Skipped -Detail 'ImportExcel module not installed - Install-Module ImportExcel -Scope CurrentUser'
            Write-A2CLog 'Excel workbook skipped (ImportExcel module not installed).'
        }
    }
    if ($Options.Mask) { Test-A2CMaskResidue }
    Save-A2CExtraFiles

    if (-not $Options.NoHtml) {
        try { $h = New-A2CHtmlReport; Write-A2CLog -Level Ok ('HTML summary: ' + $h) } catch { Write-A2CLog -Level Error ('HTML report failed: ' + $_.Exception.Message + ' @ ' + $_.InvocationInfo.ScriptLineNumber) }
    }
    if ($excelOk) {
        try { Export-A2CExcel } catch { Write-A2CLog -Level Error ('Excel export failed: ' + $_.Exception.Message) }
    }
    if ($Options.Mask) {
        try { Save-A2CMaskMap } catch { Write-A2CLog -Level Error ('Mask map could not be written: ' + $_.Exception.Message) }
    }
    Save-A2CRunInfo
    $zip = ''
    if ($Options.Zip) {
        try { $zip = New-A2CZip } catch { Write-A2CLog -Level Error ('Zip failed: ' + $_.Exception.Message) }
    }
    Write-A2CSummary -ZipPath $zip
}

function Invoke-A2CMain {
    param([System.Collections.IDictionary] $BoundParameters)
    try {
        $opt = New-A2COptions -Params $BoundParameters
        if ($opt.ListReports) { Show-A2CReportList -Options $opt; return 0 }
    }
    catch {
        # a mistake in the parameters: one line, nothing was started
        Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
        return 2
    }
    try {
        Invoke-A2CRun -Options $opt
        return 0
    }
    catch {
        Write-Host ''
        Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
        if ($null -ne $script:A2C) {
            $script:A2C.Errors.Add($_.Exception.Message)
            Add-A2CLogLine -Level Error ('Run stopped: ' + $_.Exception.Message)
            Add-A2CLogLine -Level Detail ('at ' + (Get-A2CStackText $_))
            if ($script:A2C.OutDir) { try { Save-A2CRunInfo } catch { Write-Host ('Could not save the run info (__run.json): ' + $_.Exception.Message) -ForegroundColor Yellow } }
            elseif (-not $script:A2C.LogPath) { try { Save-A2CEarlyLog } catch { Write-Host ('Could not save the log: ' + $_.Exception.Message) -ForegroundColor Yellow } }
            if ($script:A2C.LogPath) { Write-Host ('Log: ' + $script:A2C.LogPath) -ForegroundColor Yellow }
        }
        return 1
    }
}

function Test-A2CStartedFromExplorer {
    # True when Windows started PowerShell only to run this script from Explorer ("Run with PowerShell", a shortcut,
    # Win+R). That window closes as soon as the script ends, so the result or the error would vanish unread.
    # Never true in an open console, a scheduled task, CI or -NonInteractive / hidden windows.
    try {
        if ($Host.Name -ne 'ConsoleHost' -or -not [Environment]::UserInteractive -or -not $PSCommandPath) { return $false }
        if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { return $false }
        $cmd = [Environment]::CommandLine
        if ($cmd -notmatch [regex]::Escape([IO.Path]::GetFileName($PSCommandPath)) -or $cmd -match '\s-noni|\s-w\w*\s+hid') { return $false }
        $me = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $PID) -ErrorAction Stop
        return ((Get-Process -Id $me.ParentProcessId -ErrorAction Stop).ProcessName -eq 'explorer')
    }
    catch { return $false }
}

if ($MyInvocation.InvocationName -ne '.' -and -not $env:AZURE2CSV_NO_MAIN) {
    $a2cBound = [ordered]@{}   # in command-line order: Resolve-A2CListArguments relies on it
    foreach ($a2cKey in $PSBoundParameters.Keys) { $a2cBound[$a2cKey] = $PSBoundParameters[$a2cKey] }
    $a2cExit = Invoke-A2CMain -BoundParameters $a2cBound
    if (Test-A2CStartedFromExplorer) { [void](Read-Host 'Press Enter to close this window') }
    if ($a2cExit -ne 0) { exit $a2cExit }
}

#endregion
