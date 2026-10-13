<#
.SYNOPSIS
    Offline tests for azure2csv.ps1 (no Azure access needed). Runs the whole pipeline against a fictional
    "Contoso" tenant served by a fake transport.
.EXAMPLE
    .\Run-OfflineTests.ps1                 # current PowerShell
    .\Run-OfflineTests.ps1 -AllEditions    # Windows PowerShell 5.1 and PowerShell 7 (when installed)
#>
param([switch] $AllEditions, [switch] $KeepOutput)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($AllEditions) {
    $fail = 0
    foreach ($exe in @('powershell.exe', 'pwsh')) {
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { Write-Host ('{0} not found - skipped' -f $exe) -ForegroundColor Yellow; continue }
        Write-Host ('===== ' + $exe + ' =====') -ForegroundColor Cyan
        & $exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here 'Run-OfflineTests.ps1')
        if ($LASTEXITCODE -ne 0) { $fail++ }
    }
    exit $fail
}

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path -Parent $here) 'azure2csv.ps1'
. $scriptPath
. (Join-Path $here 'lib\Assert.ps1')
. (Join-Path $here 'lib\TestWorld.ps1')
. (Join-Path $here 'lib\FakeTransport.ps1')

$global:TWOut = Join-Path ([IO.Path]::GetTempPath()) ('a2c-tests-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $global:TWOut -Force | Out-Null
Write-Host ('azure2csv offline tests - {0} {1} - output {2}' -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion, $global:TWOut) -ForegroundColor Cyan

$v1Columns = @('SubscriptionName', 'SubscriptionId', 'ResourceId', 'Id', 'Identity', 'Kind', 'Location', 'ManagedBy', 'ResourceName', 'Name',
    'ExtensionResourceName', 'ParentResource', 'PrivateIP', 'PublicIP', 'vnetDNS', 'vnicDNS', 'linkedPrivDNSzones', 'vnet', 'subnet', 'Plan',
    'Properties', 'ResourceGroupName', 'Type', 'ResourceType', 'DiagnosticSettings', 'ExtensionResourceType', 'Sku.Name', 'Sku.Tier', 'Sku.Size',
    'Sku.Model', 'Sku.Capacity', 'Tags', 'CreatedTime', 'ChangedTime', 'ETag')

# ------------------------------------------------------------------------------------------------------
Write-Host 'Static checks' -ForegroundColor Cyan

Test-Case 'script parses without errors' {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count (($errors | ForEach-Object { $_.Message }) -join '; ')
}

Test-Case 'script source is ASCII only (safe for Windows PowerShell 5.1 without BOM)' {
    $bytes = [IO.File]::ReadAllBytes($scriptPath)
    $bad = 0
    foreach ($b in $bytes) { if ($b -gt 127) { $bad++ } }
    Assert-Equal 0 $bad
}

if (Get-Module -ListAvailable PSScriptAnalyzer) {
    Test-Case 'PSScriptAnalyzer reports no findings (repository settings)' {
        Import-Module PSScriptAnalyzer
        $findings = @(Invoke-ScriptAnalyzer -Path $scriptPath -Settings (Join-Path (Split-Path -Parent $here) 'PSScriptAnalyzerSettings.psd1'))
        Assert-Equal 0 $findings.Count (($findings | ForEach-Object { 'L{0} {1}' -f $_.Line, $_.RuleName }) -join '; ')
    }
}
else { Write-Host '  SKIP  PSScriptAnalyzer not installed' -ForegroundColor Yellow }

Test-Case 'dot-sourcing did not run the main entry point' {
    Assert-True ($null -eq $script:A2C) 'run context exists after dot-sourcing'
}

Test-Case 'tab completion of -Reports, -AddReports and -SkipReports offers the report catalog + groups + All' {
    $cmd = Get-Command $scriptPath
    $expected = @('All') + $script:A2CReportGroups + @($script:A2CReportCatalog | ForEach-Object { $_.Name })
    foreach ($p in @('Reports', 'AddReports', 'SkipReports')) {
        $ac = $cmd.Parameters[$p].Attributes | Where-Object { $_ -is [System.Management.Automation.ArgumentCompleterAttribute] }
        Assert-True ($null -ne $ac) ($p + ' has no completer')
        Assert-Equal (($expected | Sort-Object) -join ',') ((@(& $ac.ScriptBlock 'azure2csv.ps1' $p '') | Sort-Object) -join ',') $p
        Assert-Equal 'AzureDevOps,AzureDevOpsPackages,AzureDevOpsPipelines,AzureDevOpsRepos' ((@(& $ac.ScriptBlock 'azure2csv.ps1' $p 'azuredev') | Sort-Object) -join ',') ($p + ' filtered')
        Assert-Equal 0 @($cmd.Parameters[$p].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }).Count ($p + ': ValidateSet would refuse lists from cmd')
    }
    $pt = $cmd.Parameters['AdoPackageTypes'].Attributes | Where-Object { $_ -is [System.Management.Automation.ArgumentCompleterAttribute] }
    Assert-Equal (($script:A2CPackageTypes | Sort-Object) -join ',') ((@(& $pt.ScriptBlock 'azure2csv.ps1' 'AdoPackageTypes' '') | Sort-Object) -join ',')
}

Test-Case 'lists from cmd or pwsh -File: "A,B", "A, B" and words cut apart (A, B) all work; names are checked by the script' {
    # -AddReports AzureDevOpsRepos, AzureDevOpsPackages, AppCode started from cmd: one value with a comma, the rest loose
    $o = New-A2COptions -Params ([ordered]@{ ReportProfile = 'Full'; AddReports = @('AzureDevOpsRepos,'); CostDays = 365; RemainingArguments = @('AzureDevOpsPackages,', 'AppCode') })
    Assert-Equal 'AzureDevOpsRepos,AzureDevOpsPackages,AppCode' ($o.AddReports -join ',')
    Assert-Equal @($script:A2CReportCatalog).Count (Resolve-A2CSelection $o).Count 'Full plus the three reports that run only when named = every report'
    # two cut lists: the loose words go back to their own list, in command-line order
    $o = New-A2COptions -Params ([ordered]@{ Reports = @('VMs,'); SkipReports = @('Disks,'); AdoPackageTypes = @('npm,'); RemainingArguments = @('Disks,', 'Backup', 'Locks', 'MAVEN') })
    Assert-Equal 'VMs,Disks,Backup' ($o.Reports -join ','); Assert-Equal 'Disks,Locks' ($o.SkipReports -join ','); Assert-Equal 'npm,Maven' ($o.AdoPackageTypes -join ',')
    Assert-Equal 'VMs,Backup' ((Resolve-A2CSelection $o) -join ',')
    # one text with commas, spaces or semicolons
    $o = New-A2COptions -Params @{ Reports = @('RBAC,Policy', 'Locks; tags'); SubscriptionId = 'a, b' }
    Assert-Equal 'RBAC,Policy,Locks,tags' ($o.Reports -join ','); Assert-Equal 'a,b' ($o.SubscriptionId -join ',')
    Assert-Throws { New-A2COptions -Params ([ordered]@{ Reports = @('RBAC'); RemainingArguments = @('Policy') }) } 'Unexpected argument\(s\): Policy'
    Assert-Throws { New-A2COptions -Params @{ Reports = @('RBAC', 'Polcy') } } "Unknown report or group 'Polcy'"
    Assert-Throws { New-A2COptions -Params @{ AdoPackageTypes = @('nuget', 'gems') } } "Unknown package type 'gems'"
}

Test-Case 'started with -File like from cmd: the list is put together again, a mistake is one error line with exit code 2' {
    $exe = (Get-Process -Id $PID).Path
    $out = @(& $exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -Profile Full -AddReports 'AzureDevOpsRepos,' 'AzureDevOpsPackages,' 'AppCode' -CostDays 365 -ListReports 2>&1 | ForEach-Object { "$_" })
    Assert-Equal 0 $LASTEXITCODE ($out -join ' | ')
    Assert-True (@($out | Where-Object { $_ -match ('Selection: -Profile Full -AddReports AzureDevOpsRepos, AzureDevOpsPackages, AppCode +-> +' + @($script:A2CReportCatalog).Count + ' reports') }).Count -eq 1) ($out[0..2] -join ' | ')
    $bad = @(& $exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -Reports RBAC Policy -ListReports 2>&1 | ForEach-Object { "$_" })
    Assert-Equal 2 $LASTEXITCODE
    Assert-Equal 'ERROR: Unexpected argument(s): Policy. Lists are written with commas, for example -Reports RBAC,Policy' (@($bad | Where-Object { $_ })[-1])
}

Test-Case 'every catalog report has a builder and every dataset a collector' {
    foreach ($r in $script:A2CReportCatalog) { Assert-True (Get-Command ('New-A2CReport' + $r.Name) -ErrorAction SilentlyContinue) ('missing New-A2CReport' + $r.Name) }
    foreach ($d in $script:A2CDatasetCatalog.Keys) { Assert-True (Get-Command ('Get-A2CDataset' + $d) -ErrorAction SilentlyContinue) ('missing Get-A2CDataset' + $d) }
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Report selection' -ForegroundColor Cyan

Test-Case 'profiles resolve to known reports; Full = All including opt-in' {
    foreach ($p in $script:A2CProfiles.Keys) {
        $sel = Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = $p })
        Assert-True ($sel.Count -gt 0) $p
    }
    $full = Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Full' })
    Assert-Equal (@($script:A2CReportCatalog | Where-Object { -not $_.Explicit }).Count) $full.Count
    Assert-True ($full -notcontains 'AzureDevOpsRepos') 'the repository export runs only when named'
    Assert-True ((Resolve-A2CSelection (New-A2COptions -Params @{ AddReports = @('AzureDevOpsRepos') })) -contains 'AzureDevOpsRepos') 'named with -AddReports'
    $std = Resolve-A2CSelection (New-A2COptions -Params @{})
    Assert-True ($std -notcontains 'Cost') 'Standard must not contain opt-in Cost'
    Assert-True ($std -contains 'DiagnosticSettings') 'Standard contains DiagnosticSettings (v1 parity)'
    $quick = Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Quick' })
    Assert-True ($quick -notcontains 'DiagnosticSettings') 'Quick has no slow reports'
    foreach ($q in $quick) { Assert-True (($script:A2CReportCatalog | Where-Object { $_.Name -eq $q }).Speed -ne 'Slow') $q }
}

Test-Case '-Reports is exact, groups expand without opt-in, -AddReports/-SkipReports adjust' {
    $sel = Resolve-A2CSelection (New-A2COptions -Params @{ Reports = @('RBAC', 'Policy') })
    Assert-Equal 'Policy,RBAC' (($sel | Sort-Object) -join ',')
    $sel = Resolve-A2CSelection (New-A2COptions -Params @{ Reports = @('Entra') })
    Assert-True ($sel -notcontains 'EntraGroupMembers') 'group must not add opt-in report'
    Assert-True ($sel -contains 'EntraUsers')
    $sel = Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Migration'; AddReports = @('Cost'); SkipReports = @('Entra') })
    Assert-True ($sel -contains 'Cost')
    Assert-True (@($sel | Where-Object { $_ -like 'Entra*' }).Count -eq 0)
    $sel = Resolve-A2CSelection (New-A2COptions -Params @{ Reports = @('All'); SkipReports = @('Operations') })
    Assert-True ($sel -notcontains 'AzureCode') 'skip group removes opt-in reports too'
}

Test-Case 'v1 parameters map onto the selection' {
    $sel = Resolve-A2CSelection (New-A2COptions -Params @{ createRBACreports = $false; createPrivateDNSreport = $false })
    Assert-True ($sel -notcontains 'RBAC')
    Assert-True ($sel -notcontains 'PrivateDNS')
    Assert-True ($sel -contains 'Resources')
    $sel = Resolve-A2CSelection (New-A2COptions -Params @{ createAllResourcesReport = $false })
    Assert-True ($sel -notcontains 'Resources')
    $o = New-A2COptions -Params @{ SubscriptionId = @('AAA, bbb;ccc') }
    Assert-Equal 'aaa,bbb,ccc' ($o.SubscriptionId -join ',')
}

Test-Case 'dependencies resolve transitively (VMs pulls network data, Principals pulls RBAC data)' {
    $ds = Resolve-A2CDatasets @('VMs')
    Assert-Equal 'Subscriptions,Resources,BackupItems,ComputeSkus' ($ds -join ',')
    $ds = Resolve-A2CDatasets @('RBAC')
    Assert-True ($ds -contains 'RoleDefinitions' -and $ds -contains 'Principals' -and $ds -contains 'Subscriptions')
}

Test-Case '-ListReports makes no Azure calls' {
    $global:TWRequests.Clear()
    $opt = New-A2COptions -Params @{ ListReports = $true; ReportProfile = 'Security' }
    Show-A2CReportList -Options $opt 6>$null | Out-Null
    Assert-Equal 0 $global:TWRequests.Count
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Core inventory run' -ForegroundColor Cyan

$run = Invoke-TWRun -Params @{ Reports = @('Resources', 'Tags') }

Test-Case 'Resources/Tags run completes without errors' {
    Assert-Equal 0 $run.Errors.Count ($run.Errors -join ' | ')
    foreach ($f in @('allResources.csv', 'subscriptions.csv', 'resourceTypes.csv', 'tags.csv', 'tagList.json', 'coverage.csv', 'findings.csv', ($run.RunStamp + '__run.json'), ($run.RunStamp + '__general_log.txt'))) {
        Assert-True (Test-Path ([IO.Path]::Combine($run.OutDir, $f))) $f
    }
    Assert-True (-not (Test-Path ([IO.Path]::Combine($run.OutDir, 'RBAC_roles.csv')))) 'unselected report written'
}

Test-Case 'general log yyyyMMdd-HHmmss__general_log.txt in the run folder has every log line' {
    Assert-Match $run.RunStamp '^\d{8}-\d{6}$'
    Assert-True ($run.RunName -like ('azure2csv_' + $run.RunStamp + '_*')) 'same time stamp as the run folder'
    $path = [IO.Path]::Combine($run.OutDir, $run.RunStamp + '__general_log.txt')
    Assert-Equal $path $run.LogPath
    $bytes = [IO.File]::ReadAllBytes($path)
    Assert-True ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) 'UTF-8 BOM'
    $text = [IO.File]::ReadAllText($path)
    Assert-Equal ([string]::Join("`r`n", $run.Log) + "`r`n") $text
    Assert-Match $text 'INFO +azure2csv 2\.0\.0 '
    Assert-Match $text 'INFO +Reports \(2\): Resources, Tags'
    Assert-Match $text 'OK +Done in '
}

Test-Case 'the Explorer "press Enter" pause never triggers in tests or automation' {
    Assert-False (Test-A2CStartedFromExplorer)
}

$all = Import-TWCsv $run 'allResources.csv'

Test-Case 'allResources.csv starts with the 35 v1 columns in v1 order' {
    $header = (Get-Content -LiteralPath ([IO.Path]::Combine($run.OutDir, 'allResources.csv')) -TotalCount 1 -Encoding UTF8)
    $cols = @($header.Split(',') | ForEach-Object { $_.Trim('"') })
    Assert-Equal ($v1Columns -join ',') (($cols[0..34]) -join ',')
}

Test-Case 'subscription and resource-group rows present; disabled and other-tenant subscriptions skipped' {
    $subs = @($all | Where-Object { $_.RowType -eq 'Subscription' })
    Assert-Equal 2 $subs.Count
    $rgs = @($all | Where-Object { $_.RowType -eq 'ResourceGroup' })
    Assert-Equal 7 $rgs.Count
    $sc = Import-TWCsv $run 'subscriptions.csv'
    $s3 = $sc | Where-Object { $_.SubscriptionId -eq $global:TW_S3 }
    Assert-Equal 'False' $s3.InScope
    Assert-Match $s3.SkipReason 'Disabled'
    $s4 = $sc | Where-Object { $_.SubscriptionId -eq $global:TW_S4 }
    Assert-Match $s4.SkipReason 'another tenant'
    $s1 = $sc | Where-Object { $_.SubscriptionId -eq $global:TW_S1 }
    Assert-Equal 'mg-landingzones' $s1.ParentManagementGroup
}

Test-Case 'Resource Graph paging returned every resource (page size 7)' {
    $n = @($all | Where-Object { $_.RowType -eq 'Resource' }).Count
    Assert-Equal $global:TW.Resources.Count $n
    $argCalls = @($global:TWRequests | Where-Object { $_.Kind -eq 'arg' -and $_.Body -match 'a2c:resources' }).Count
    Assert-True ($argCalls -ge 7) ('expected several pages, got ' + $argCalls)
}

Test-Case 'VM with NIC in another RG and public IP in a third RG gets correct networking (v1 bug)' {
    $vm = $all | Where-Object { $_.Name -eq 'vm-app01' }
    Assert-Equal 'nic-app01:10.0.1.4' $vm.PrivateIP
    Assert-Equal 'nic-app01:20.50.60.70' $vm.PublicIP 'must not pick the same-named public IP of subscription 2'
    Assert-Equal 'nic-app01:vnet-hub' $vm.vnet
    Assert-Equal 'nic-app01:snet-app' $vm.subnet
    Assert-Equal '10.0.0.4, 10.0.0.5' $vm.vnetDNS
    Assert-Equal 'nic-app01:1.1.1.1' $vm.vnicDNS
    Assert-Equal 'privatelink.blob.core.windows.net' $vm.linkedPrivDNSzones
    Assert-Equal 'nic-app01:nsg-app' $vm.SubnetNSG
    Assert-Equal 'nic-app01:asg-web' $vm.ASG
    Assert-Equal 'nic-app01:rt-app' $vm.RouteTable
    Assert-Equal 'eeeeeeee-0000-0000-0000-000000000001' $vm.Identity
    Assert-Equal 'uai-app' $vm.UserAssignedIdentities
    Assert-Equal 'Microsoft.Compute/virtualMachines' $vm.Type
    $legacy = $all | Where-Object { $_.Name -eq 'vm-legacy01' -and $_.Type -eq 'Microsoft.Compute/virtualMachines' }
    Assert-Equal 'nic-legacy01:none' $legacy.PublicIP
    Assert-Equal 'Azure-provided' $legacy.vnetDNS
}

Test-Case 'Properties column is JSON (not @{...}) and CreatedTime is filled' {
    $vm = $all | Where-Object { $_.Name -eq 'vm-app01' }
    Assert-Match $vm.Properties '^\{"'
    $p = ConvertFrom-Json $vm.Properties
    Assert-Equal 'Standard_D4s_v5' $p.hardwareProfile.vmSize
    Assert-Equal '2023-05-01T10:00:00Z' $vm.CreatedTime
    Assert-Equal 'servers/sql-contoso' ($all | Where-Object { $_.Name -eq 'appdb' }).ParentResource
}

Test-Case 'UTF-8 BOM and non-ASCII tag values survive' {
    $bytes = [IO.File]::ReadAllBytes([IO.Path]::Combine($run.OutDir, 'tags.csv'))
    Assert-True ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) 'BOM missing'
    $tags = Import-TWCsv $run 'tags.csv'
    Assert-True (@($tags | Where-Object { $_.TagValue -ceq $global:TW_Lt }).Count -eq 1) 'Lithuanian value'
    Assert-True (@($tags | Where-Object { $_.TagValue -ceq $global:TW_Jp }).Count -eq 1) 'Japanese value'
    $owner = $tags | Where-Object { $_.TagName -eq 'owner' -and $_.TagValue -ceq $global:TW_Lt }
    Assert-Equal '1' $owner.ResourceGroups
    Assert-Equal '2' $owner.Resources
    $json = Get-Content -Raw -Encoding UTF8 ([IO.Path]::Combine($run.OutDir, 'tagList.json')) | ConvertFrom-Json
    Assert-True ($null -ne $json.owner) 'tagList.json has owner'
}

Test-Case 'CSV formula-injection guard and cell truncation' {
    $f = ConvertTo-A2CCsvField -Text '=HYPERLINK("x")' -Max 100
    Assert-Equal '"''=HYPERLINK(""x"")"' $f
    Assert-Equal '"-5"' (ConvertTo-A2CCsvField -Text '-5' -Max 100)
    $long = ConvertTo-A2CCsvField -Text ('a' * 5000) -Max 1000
    Assert-True ($long.Length -lt 1100) 'truncated'
    Assert-Match $long 'truncated'
}

Test-Case 'yyyyMMdd-HHmmss__run.json is valid and lists files and API calls' {
    Assert-False (Test-Path ([IO.Path]::Combine($run.OutDir, 'run.json'))) 'old name run.json still written'
    $j = Get-Content -Raw -Encoding UTF8 ([IO.Path]::Combine($run.OutDir, $run.RunStamp + '__run.json')) | ConvertFrom-Json
    Assert-Equal '2.0.0' $j.version
    Assert-True ($j.apiCalls.arg -gt 0)
    Assert-True (@($j.files).Count -ge 5)
}

Test-Case '429 on the subscription list is retried after Retry-After' {
    Reset-TWState
    $global:TW.Throttle.Add(@{ Pattern = '/subscriptions\?api-version'; Remaining = 1; RetryAfter = 7 })
    $r2 = Invoke-TWRun -Params @{ Reports = @('Resources') } -KeepWorld
    Assert-Equal 0 $r2.Errors.Count ($r2.Errors -join ' | ')
    Assert-Equal 1 $r2.Stats.Retries
    Assert-Equal 1 $r2.Stats.Throttled
    $s = $global:TWSleeps | Where-Object { $_ -ge 7 -and $_ -lt 8.1 }
    Assert-True (@($s).Count -ge 1) ('sleeps: ' + ($global:TWSleeps -join ','))
}

Test-Case 'network errors are retried and shown on screen (not as warnings)' {
    Reset-TWState
    $global:TW.Fail.Add(@{ Pattern = '/subscriptions\?api-version'; Remaining = 2; Message = "No such host is known.`n(management.azure.com:443)" })
    $r3 = Invoke-TWRun -Params @{ Reports = @('Resources') } -KeepWorld
    Assert-Equal 0 $r3.Errors.Count ($r3.Errors -join ' | ')
    Assert-Equal 2 $r3.Stats.Retries
    Assert-Equal 2 @($r3.Log | Where-Object { $_ -match 'NOTICE +No response \(No such host is known\. \(management' }).Count ($r3.Log -join ' | ')
    Assert-Equal 0 @($r3.Warnings | Where-Object { $_ -match 'No response' }).Count
}

Test-Case 'expired sign-in in a non-interactive session stops at once with the Connect-AzAccount command' {
    Reset-TWState
    $global:TW.CanPrompt = $false
    $global:TW.Fail.Add(@{ Pattern = '/subscriptions\?api-version'; Remaining = 99
            Message = "Authentication failed against tenant x. User interaction is required.`nTry logging in with Connect-AzAccount and specify the tenant with -TenantId." })
    $err = ''
    try { Invoke-TWRun -Params @{ Reports = @('Resources') } -KeepWorld | Out-Null } catch { $err = $_.Exception.Message }
    Assert-Match $err 'subscription list'
    Assert-Equal 0 $script:A2C.Stats.Retries
    Assert-Equal 0 $global:TWSleeps.Count
    Assert-Equal 1 @($global:TWRequests | Where-Object { $_.Uri -match '/subscriptions\?api-version' }).Count
    Assert-Equal 1 @($script:A2C.Errors | Where-Object { $_ -match ('sign in again with  Connect-AzAccount -TenantId ' + $global:TW.Context.Tenant.Id) }).Count ($script:A2C.Errors -join ' | ')
    # the run stopped without reaching the end: the general log was written line by line
    $log = [IO.File]::ReadAllText([IO.Path]::Combine($script:A2C.OutDir, $script:A2C.RunStamp + '__general_log.txt'))
    Assert-Match $log 'ERROR +Azure sign-in failed \(arm calls\)'
    Assert-Match $log 'DETAIL +at Get-A2CDatasetSubscriptions'
    Assert-Equal 0 $global:TW.SignInCalls.Count 'no sign-in window without a user'
}

Test-Case 'expired sign-in opens the Microsoft sign-in once (AuthScope as Az recommends) and the run continues' {
    Reset-TWState
    $global:TW.Fail.Add(@{ Pattern = '/subscriptions\?api-version'; Remaining = 99
            Message = ("Your Azure credentials have not been set up or have expired, please run Connect-AzAccount to set up your Azure credentials.`n" +
                "Authentication failed against resource https://management.core.windows.net/. User interaction is required. This may be due to the " +
                "conditional access policy settings such as multi-factor authentication (MFA). Please rerun 'Connect-AzAccount' with additional " +
                "parameter '-AuthScope https://management.core.windows.net/'.") })
    $r4 = Invoke-TWRun -Params @{ Reports = @('Resources') } -KeepWorld
    Assert-Equal 0 $r4.Errors.Count ($r4.Errors -join ' | ')
    Assert-Equal 1 $global:TW.SignInCalls.Count
    $p = $global:TW.SignInCalls[0]
    Assert-Equal $global:TW.Context.Tenant.Id $p['TenantId']
    Assert-Equal 'https://management.core.windows.net/' $p['AuthScope']
    Assert-False $p.ContainsKey('UseDeviceAuthentication')
    Assert-Equal 2 @($global:TWRequests | Where-Object { $_.Uri -match '/subscriptions\?api-version' }).Count
    Assert-Equal 1 @($r4.Log | Where-Object { $_ -match 'OK +Signed in again as .+ - continuing' }).Count
    Assert-True (@(Import-TWCsv $r4 'allResources.csv').Count -gt 0) 'resources collected after the sign-in'
}

Test-Case 'a cancelled sign-in (device code) stops the run after one attempt with the Connect-AzAccount command' {
    Reset-TWState
    $global:TW.SignInWorks = $false
    $global:TW.Fail.Add(@{ Pattern = '/subscriptions\?api-version'; Remaining = 99; Message = 'Authentication failed against tenant x. User interaction is required.' })
    $err = ''
    try { Invoke-TWRun -Params @{ Reports = @('Resources'); UseDeviceAuthentication = $true } -KeepWorld | Out-Null } catch { $err = $_.Exception.Message }
    Assert-Match $err 'subscription list'
    Assert-Equal 1 $global:TW.SignInCalls.Count
    Assert-True $global:TW.SignInCalls[0]['UseDeviceAuthentication'] 'device code requested'
    Assert-False $global:TW.SignInCalls[0].ContainsKey('AuthScope')
    Assert-Equal 1 @($script:A2C.Errors | Where-Object { $_ -match 'The sign-in did not complete: User canceled' }).Count ($script:A2C.Errors -join ' | ')
    Assert-Equal 1 @($script:A2C.Errors | Where-Object { $_ -match 'sign in again with  Connect-AzAccount' }).Count ($script:A2C.Errors -join ' | ')
}

Test-Case 'a run that stops before its folder exists still leaves a general log' {
    Reset-TWState
    $global:TW.ConnectError = 'Connect-AzAccount failed: the sign-in window was closed'
    $dir = Join-Path $global:TWOut 'early-stop'
    $code = Invoke-A2CMain -BoundParameters @{ OutputPath = $dir; Reports = @('Resources'); NoHtml = $true; NoExcel = $true } 6>$null
    Assert-Equal 1 $code
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $dir -Directory).Count 'run folder created'
    $logs = @(Get-ChildItem -LiteralPath $dir -Filter '*__general_log.txt')
    Assert-Equal 1 $logs.Count
    Assert-Match $logs[0].Name '^\d{8}-\d{6}__general_log\.txt$'
    $text = [IO.File]::ReadAllText($logs[0].FullName)
    Assert-Match $text 'Reports \(1\): Resources'
    Assert-Match $text 'ERROR +Run stopped: Connect-AzAccount failed: the sign-in window was closed'
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Network, compute, data and operations reports' -ForegroundColor Cyan

$run2 = Invoke-TWRun -Params @{ Reports = @('Network', 'Compute', 'Data', 'Backup', 'Automation') }

Test-Case 'typed reports run without errors' {
    Assert-Equal 0 $run2.Errors.Count ($run2.Errors -join ' | ')
    Assert-True (-not (Test-Path ([IO.Path]::Combine($run2.OutDir, 'allResources.csv')))) 'Resources not selected but written'
}

Test-Case 'VNets, subnets and peerings' {
    $v = Import-TWCsv $run2 'vnets.csv'
    Assert-Equal '10.0.0.4, 10.0.0.5' ($v | Where-Object Name -eq 'vnet-hub').DnsServers
    Assert-Equal 'Azure-provided' ($v | Where-Object Name -eq 'vnet-spoke').DnsServers
    $s = Import-TWCsv $run2 'subnets.csv'
    $app = $s | Where-Object Subnet -eq 'snet-app'
    Assert-Equal 'nsg-app' $app.NSG
    Assert-Equal 'rt-app' $app.RouteTable
    Assert-Equal 'Microsoft.Storage' $app.ServiceEndpoints
    Assert-Equal 'Microsoft.Sql/managedInstances' ($s | Where-Object Subnet -eq 'snet-data').Delegations
    Assert-Equal 'False' ($s | Where-Object Subnet -eq 'snet-data').DefaultOutboundAccess
    $p = Import-TWCsv $run2 'peerings.csv'
    Assert-Equal 'True' ($p | Where-Object Peering -eq 'hub-to-spoke').RemoteInScope
}

Test-Case 'NSG rules flattened with risk flags; formula guard applied' {
    $rules = Import-TWCsv $run2 'nsgRules.csv'
    Assert-Equal 'High: port 3389 open to the Internet' ($rules | Where-Object Rule -eq 'Allow-RDP-Internet').Risk
    $https = $rules | Where-Object Rule -eq 'Allow-HTTPS'
    Assert-Equal '10.0.1.4, 10.0.1.5' $https.Destination
    Assert-Equal '443, 8443' $https.DestinationPorts
    Assert-Equal 'Medium: open to the Internet' $https.Risk
    Assert-Match $https.Description "^'="
    Assert-Equal 'True' ($rules | Where-Object Rule -eq 'AllowVnetInBound').IsDefault
    $n = Import-TWCsv $run2 'nsgs.csv'
    Assert-Equal 'True' ($n | Where-Object Name -eq 'nsg-unused').Unused
    Assert-Equal 'vnet-hub/snet-app' ($n | Where-Object Name -eq 'nsg-app').AssociatedSubnets
}

Test-Case 'routes, public IPs, private endpoints and private DNS zones' {
    $routes = Import-TWCsv $run2 'routes.csv'
    Assert-Equal 'VirtualAppliance' ($routes | Where-Object Route -eq 'default-to-fw').NextHopType
    $pips = Import-TWCsv $run2 'publicIps.csv'
    $pa = $pips | Where-Object { $_.Name -eq 'pip-app01' -and $_.SubscriptionId -eq $global:TW_S1 }
    Assert-Equal 'nic-app01' $pa.AttachedTo
    Assert-Equal 'vm-app01' $pa.AttachedVm
    Assert-Equal 'True' ($pips | Where-Object Name -eq 'pip-basic').Unused
    Assert-Equal 'True' ($pips | Where-Object { $_.Name -eq 'pip-app01' -and $_.SubscriptionId -eq $global:TW_S2 }).Unused
    $pe = Import-TWCsv $run2 'privateEndpoints.csv'
    Assert-Equal 'stcontosodata' $pe[0].TargetResource
    Assert-Equal '10.0.1.10' $pe[0].PrivateIPs
    Assert-Equal 'vnet-hub' $pe[0].VNet
    $z = Import-TWCsv $run2 'privateDnsZones.csv'
    $blob = $z | Where-Object privateDNSzoneName -eq 'privatelink.blob.core.windows.net'
    Assert-Equal '1' $blob.NumberOfVNETLinks
    Assert-Equal 'vnet-hub' $blob.LinkedVNetNames
    Assert-Equal '0' ($z | Where-Object privateDNSzoneName -eq 'privatelink.vaultcore.azure.net').NumberOfVNETLinks
}

Test-Case 'VM migration profile (sizes, disks, agents, backup)' {
    $vms = Import-TWCsv $run2 'vms.csv'
    $a = $vms | Where-Object Name -eq 'vm-app01'
    Assert-Equal '4' $a.vCPUs
    Assert-Equal '16' $a.MemoryGB
    Assert-Equal '128' $a.OsDiskSizeGB
    Assert-Equal 'Premium_LRS' $a.OsDiskType
    Assert-Equal '512' $a.DataDisksTotalGB
    Assert-Equal 'True' $a.BackupProtected
    Assert-Equal 'rsv-contoso' $a.BackupVault
    Assert-Equal 'True' $a.HybridBenefit
    Assert-Equal 'running' $a.PowerState
    Assert-Equal 'True' $a.AzureMonitorAgent
    Assert-Equal 'nic-app01:20.50.60.70' $a.PublicIPs
    $l = $vms | Where-Object Name -eq 'vm-legacy01'
    Assert-Equal 'True' $l.UnmanagedDisks
    Assert-Equal 'True' $l.LegacyMonitoringAgent
    Assert-Equal 'False' $l.BackupProtected
    Assert-Equal 'stopped' $l.PowerState
    $d = Import-TWCsv $run2 'disks.csv'
    Assert-Equal 'True' ($d | Where-Object Name -eq 'disk-orphan').Unattached
    Assert-Equal 'vm-app01' ($d | Where-Object Name -eq 'vm-app01_OsDisk').AttachedTo
}

Test-Case 'AKS, App Service (case-insensitive config), storage, SQL, Key Vault' {
    $aks = Import-TWCsv $run2 'aks.csv'
    Assert-Equal '5' $aks[0].Nodes
    Assert-Equal 'Free' $aks[0].Tier
    $apps = Import-TWCsv $run2 'appServiceApps.csv'
    Assert-Equal 'NODE|18-lts' $apps[0].Runtime
    Assert-Equal '1.2' $apps[0].MinTlsVersion
    Assert-Equal 'asp-web' $apps[0].Plan
    Assert-Equal '0' ((Import-TWCsv $run2 'appServicePlans.csv') | Where-Object Name -eq 'asp-empty').Apps
    $st = Import-TWCsv $run2 'storageAccounts.csv'
    $sd = $st | Where-Object Name -eq 'stcontosodata'
    Assert-Equal 'TLS1_0' $sd.MinimumTlsVersion
    Assert-Equal 'Not set (allowed)' $sd.AllowBlobPublicAccess
    Assert-Equal '1' $sd.PrivateEndpoints
    Assert-Equal '1' ((Import-TWCsv $run2 'sqlServers.csv')[0].Databases)
    $db = Import-TWCsv $run2 'sqlDatabases.csv'
    Assert-Equal 1 @($db).Count
    Assert-Equal '32' $db[0].MaxSizeGB
    $sv = Import-TWCsv $run2 'sqlVirtualMachines.csv'
    Assert-Equal 'SQL Server 2014' $sv[0].SqlVersion
    Assert-Equal 'Out of extended support since 2024-07-09' $sv[0].SupportStatus
    $kv = Import-TWCsv $run2 'keyVaults.csv'
    Assert-Equal 'Access policies' $kv[0].PermissionModel
    Assert-Equal '2' $kv[0].AccessPolicies
}

Test-Case 'backup items and automation runbooks with retiring runtimes' {
    $b = Import-TWCsv $run2 'backupItems.csv'
    Assert-Equal '2026-09-28T22:00:00Z' $b[0].LastBackupTime
    Assert-Equal 'vm-app01' $b[0].SourceResource
    $rb = Import-TWCsv $run2 'runbooks.csv'
    Assert-Equal 'PowerShell 7.2 - retires 2026-09-30' ($rb | Where-Object Runbook -eq 'Start-VMs').RetiringRuntime
    Assert-Equal 'Python 2.7 - retires 2026-09-30' ($rb | Where-Object Runbook -eq 'Cleanup').RetiringRuntime
    Assert-Equal '2' (Import-TWCsv $run2 'automationAccounts.csv')[0].Runbooks
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Governance: diagnostic settings, locks, RBAC, management groups, policy, tenant transfer' -ForegroundColor Cyan

$run3 = Invoke-TWRun -Params @{ Reports = @('Resources', 'DiagnosticSettings', 'Locks', 'Governance') }
$all3 = Import-TWCsv $run3 'allResources.csv'
$diagCalls = @($global:TWRequests | Where-Object { $_.Uri -match 'diagnosticSettings' })

Test-Case 'governance run completes without errors' {
    Assert-Equal 0 $run3.Errors.Count ($run3.Errors -join ' | ')
}

Test-Case 'diagnostic settings: configured, storage sub-services, activity log, no carry-over' {
    $vm = $all3 | Where-Object { $_.Name -eq 'vm-app01' -and $_.RowType -eq 'Resource' }
    Assert-Equal 'Configured' $vm.DiagStatus
    Assert-Equal 'vm-diag -> LA:law-contoso [metrics: AllMetrics]' $vm.DiagnosticSettings
    $st = $all3 | Where-Object Name -eq 'stcontosodata'
    Assert-Equal 'Configured' $st.DiagStatus
    Assert-Equal 'blob: blob-logs -> SA:stlegacyvhds [logs: allLogs]' $st.DiagnosticSettings
    Assert-Equal 'NotConfigured' ($all3 | Where-Object Name -eq 'nsg-app').DiagStatus
    $asg = $all3 | Where-Object Name -eq 'asg-web'
    Assert-Equal 'NotSupported' $asg.DiagStatus
    Assert-Equal '' $asg.DiagnosticSettings 'v1 carried the previous value over'
    $s1 = $all3 | Where-Object { $_.RowType -eq 'Subscription' -and $_.SubscriptionId -eq $global:TW_S1 }
    Assert-Equal 'Configured' $s1.DiagStatus
    Assert-Equal 'activity log: activitylog-to-law -> LA:law-contoso [logs: Administrative, Security]' $s1.DiagnosticSettings
    Assert-Equal 'NotConfigured' ($all3 | Where-Object { $_.RowType -eq 'Subscription' -and $_.SubscriptionId -eq $global:TW_S2 }).DiagStatus
}

Test-Case 'diagnostic settings: seeded types are never called, unsupported types are learned' {
    Assert-Equal 0 @($diagCalls | Where-Object { $_.Uri -match 'applicationSecurityGroups' }).Count 'seeded type was called'
    Assert-Equal 'NotSupported' ($all3 | Where-Object Name -eq 'ng-unused').DiagStatus
    Assert-Equal 1 @($diagCalls | Where-Object { $_.Uri -match 'natGateways' }).Count
    $cov = Import-TWCsv $run3 'coverage.csv'
    Assert-Match (($cov | Where-Object { $_.Area -like 'Diagnostic settings*' }).Detail) 'microsoft.network/natgateways'
    $d = Import-TWCsv $run3 'diagnosticSettings.csv'
    Assert-Equal 3 @($d).Count
}

Test-Case 'locks with scope types' {
    $l = Import-TWCsv $run3 'locks.csv'
    Assert-Equal 2 @($l).Count
    $n = $l | Where-Object LockName -eq 'lock-network'
    Assert-Equal 'ResourceGroup' $n.ScopeType
    Assert-Equal 'rg-network' $n.ResourceGroup
    $k = $l | Where-Object LockName -eq 'kv-readonly'
    Assert-Equal 'Resource' $k.ScopeType
    Assert-Equal 'kv-contoso' $k.Resource
    Assert-Equal 'ReadOnly' $k.Level
}

Test-Case 'RBAC assignments: v1 columns, resolved principals, orphaned, guest, inherited, managed identity' {
    $header = (Get-Content -LiteralPath ([IO.Path]::Combine($run3.OutDir, 'RBAC_role_assignments.csv')) -TotalCount 1 -Encoding UTF8)
    Assert-Match $header '^"SubscriptionID","SubscriptionName","RoleAssignmentId","Scope","DisplayName","SignInName","RoleDefinitionName","RoleDefinitionId","ObjectId","ObjectType","CanDelegate"'
    $ra = Import-TWCsv $run3 'RBAC_role_assignments.csv'
    Assert-Equal 9 @($ra).Count
    $orphan = $ra | Where-Object { $_.RoleAssignmentId -like '*ra-0004' }
    Assert-Equal 'NotFound (deleted principal?)' $orphan.PrincipalStatus
    Assert-Equal 'User Access Administrator' $orphan.RoleDefinitionName
    $guest = $ra | Where-Object { $_.RoleAssignmentId -like '*ra-0005' -and $_.SubscriptionID -eq $global:TW_S1 }
    Assert-Equal 'Pat Partner' $guest.DisplayName
    Assert-Equal 'Guest' $guest.UserType
    Assert-Equal 'True' $guest.Inherited
    Assert-Equal 'ManagementGroup' $guest.ScopeType
    Assert-Equal 'True' $guest.IsPrivilegedRole
    Assert-Equal 'ManagedIdentity' ($ra | Where-Object { $_.RoleAssignmentId -like '*ra-0006' }).ServicePrincipalType
    Assert-Equal 'Contoso VM Operator' ($ra | Where-Object { $_.RoleAssignmentId -like '*ra-0007' }).RoleDefinitionName
    Assert-Equal 'alex.admin@contoso.onmicrosoft.com' ($ra | Where-Object { $_.RoleAssignmentId -like '*ra-0001' }).SignInName
}

Test-Case 'RBAC roles: custom + used built-ins only, deduplicated across subscriptions' {
    $roles = Import-TWCsv $run3 'RBAC_roles.csv'
    Assert-Equal 5 @($roles).Count
    $c = $roles | Where-Object RoleName -eq 'Contoso VM Operator'
    Assert-Equal 'True' $c.IsCustom
    Assert-Equal 'True' $c.HasWildcardActions
    Assert-Equal '3' ($roles | Where-Object RoleName -eq 'Owner').AssignmentCount
}

Test-Case 'management group hierarchy with paths and subscription placement' {
    $mg = Import-TWCsv $run3 'managementGroups.csv'
    Assert-Equal 4 @($mg).Count
    $lz = $mg | Where-Object ManagementGroup -eq 'mg-landingzones'
    Assert-Equal '2' $lz.Level
    Assert-Equal 'Tenant Root Group / Contoso / Landing Zones' $lz.Path
    Assert-Equal 'Contoso Production' $lz.Subscriptions
    Assert-Equal '2' ($mg | Where-Object Level -eq '0').TotalSubscriptions
}

Test-Case 'policy assignments: inherited deduplicated, restrictions resolved through an initiative' {
    $pa = Import-TWCsv $run3 'policyAssignments.csv'
    Assert-Equal 3 @($pa).Count
    $b = $pa | Where-Object Name -eq 'alz-baseline'
    Assert-Equal '2' $b.AppliesToSubscriptions
    Assert-Equal 'ManagementGroup' $b.ScopeType
    Assert-Equal 'Initiative' $b.DefinitionType
    Assert-Equal 'Contoso baseline initiative' $b.Definition
    Assert-Equal 'Allowed locations: westeurope, northeurope' $b.Restricts
    Assert-Equal '3' $b.NonCompliantResources
    $s = $pa | Where-Object Name -eq 'allowed-vm-skus'
    Assert-Equal 'Allowed virtual machine size SKUs: Standard_D4s_v5, Standard_B2s' $s.Restricts
    Assert-Equal 'DoNotEnforce' $s.EnforcementMode
    Assert-Equal 'BuiltIn' $s.PolicyType
    Assert-Equal 'Audit (parameter)' ($pa | Where-Object Name -eq 'require-tag').Effect
}

Test-Case 'policy definitions, initiatives, exemptions and compliance' {
    $pd = Import-TWCsv $run3 'policyDefinitions.csv'
    Assert-Equal '1' ($pd | Where-Object Name -eq 'require-app-tag').AssignmentCount
    $old = $pd | Where-Object Name -eq 'old-unused-policy'
    Assert-Equal '0' $old.AssignmentCount
    Assert-Equal 'True' $old.Deprecated
    Assert-True ($null -ne ($pd | Where-Object Name -eq 'cccc23c7-8427-4f53-ad12-b6a63eb452b3')) 'assigned built-in definition missing'
    Assert-Equal '2' ((Import-TWCsv $run3 'policySetDefinitions.csv') | Where-Object Name -eq 'contoso-baseline').PolicyCount
    $ex = Import-TWCsv $run3 'policyExemptions.csv'
    Assert-Equal 'Expired' ($ex | Where-Object Name -eq 'legacy-waiver').Status
    $m = $ex | Where-Object Name -eq 'sku-mitigated'
    Assert-Equal 'Expires within 30 days' $m.Status
    Assert-Equal '10' $m.DaysToExpiry
    Assert-Equal 4 @(Import-TWCsv $run3 'policyCompliance.csv').Count
    Assert-Equal '2' ($all3 | Where-Object { $_.Name -eq 'vm-legacy01' -and $_.Type -eq 'Microsoft.Compute/virtualMachines' }).PolicyNonCompliant
}

Test-Case 'tenant transfer impact covers identities, Key Vault, SQL Entra auth, AKS, RBAC and policy' {
    $t = Import-TWCsv $run3 'tenantTransferImpact.csv'
    Assert-True (@($t | Where-Object { $_.Category -eq 'Not transferable' -and $_.Name -eq 'aks-contoso' }).Count -eq 1) 'AKS'
    Assert-True (@($t | Where-Object { $_.Category -eq 'Managed identity' -and $_.Name -eq 'uai-app' }).Count -eq 1) 'UAI'
    Assert-True (@($t | Where-Object { $_.Category -eq 'Managed identity' -and $_.Name -eq 'vm-app01' }).Count -eq 1) 'system MI'
    Assert-True (@($t | Where-Object { $_.Category -eq 'Key Vault' }).Count -eq 1) 'KV'
    Assert-True (@($t | Where-Object { $_.Category -eq 'Entra authentication' -and $_.Name -eq 'sql-contoso' }).Count -eq 1) 'SQL'
    $rbac = $t | Where-Object { $_.Category -eq 'RBAC' -and $_.SubscriptionId -eq $global:TW_S1 -and $_.Detail -like '*role assignments*' }
    Assert-Match $rbac.Detail '^6 role assignments'
    Assert-True (@($t | Where-Object { $_.Category -eq 'RBAC' -and $_.Name -eq 'Contoso VM Operator' }).Count -eq 1) 'custom role'
    Assert-True (@($t | Where-Object { $_.Category -eq 'Policy' -and $_.Detail -like '*inherited*' }).Count -eq 2) 'MG policy rows'
    Assert-Equal 'High' $t[0].Impact
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Migration and hygiene: move support, cross references, retirements, orphans, Advisor, cost, runbooks' -ForegroundColor Cyan

$run4 = Invoke-TWRun -Params @{ Reports = @('Resources', 'MoveSupport', 'CrossReferences', 'Retirements', 'Orphans', 'Advisor', 'Cost', 'Automation', 'AzureCode') }
$all4 = Import-TWCsv $run4 'allResources.csv'

Test-Case 'migration run completes (cost partially unavailable is not an error)' {
    Assert-Equal 0 $run4.Errors.Count ($run4.Errors -join ' | ')
}

Test-Case 'move-support markdown parsed: Yes/No/Partial/Pending/Manual/Unknown and parent fallback' {
    $mv = Import-TWCsv $run4 'moveSupport.csv'
    $vm = $mv | Where-Object ResourceType -eq 'Microsoft.Compute/virtualMachines'
    Assert-Equal 'Yes' $vm.CanMoveToOtherRegion
    Assert-Match $vm.MoveNotes 'Azure Resource Mover'
    $lb = $mv | Where-Object ResourceType -eq 'Microsoft.Network/loadBalancers'
    Assert-Equal 'Yes' $lb.CanMoveToOtherRG
    Assert-Equal 'Partial' $lb.CanMoveToOtherSubscription
    Assert-Equal 'Pending' ($mv | Where-Object ResourceType -eq 'Microsoft.Web/serverFarms').CanMoveToOtherRegion
    Assert-Equal 'Manual' ($mv | Where-Object ResourceType -eq 'Microsoft.Web/sites').CanMoveToOtherRegion
    Assert-Equal 'No' ($mv | Where-Object ResourceType -eq 'Microsoft.ContainerService/managedClusters').CanMoveToOtherSubscription
    Assert-Equal 'Unknown' ($mv | Where-Object ResourceType -eq 'Microsoft.Sql/servers/databases').CanMoveToOtherRG
    Assert-Equal 'No' ($mv | Where-Object ResourceType -eq 'Microsoft.Compute/virtualMachines/extensions').CanMoveToOtherRegion
    Assert-Equal 'Partial' ($all4 | Where-Object Name -eq 'lb-basic').CanMoveToOtherSubscription
    $idx = ConvertFrom-A2CMoveMarkdown $global:TW.Web['move']
    Assert-True ($idx.ContainsKey('microsoft.cache/redisenterprise')) 'type cell with parenthesis'
    Assert-True (-not $idx.ContainsKey('somethingelse')) 'third-party section must be skipped'
}

Test-Case 'move support: too few parsed rows (format change) leaves the columns empty with a coverage warning' {
    Reset-TWState
    $script:A2CMoveMinRows = 400
    try { $r = Invoke-TWRun -Params @{ Reports = @('MoveSupport') } -KeepWorld } finally { $script:A2CMoveMinRows = 5 }
    $cov = Import-TWCsv $r 'coverage.csv'
    Assert-Equal 'Failed' ($cov | Where-Object { $_.Area -like 'Move support data*' }).Status
    Assert-Equal '' ((Import-TWCsv $r 'moveSupport.csv') | Select-Object -First 1).CanMoveToOtherRG
}

Test-Case 'cross references: VM->NIC in another RG, NIC->public IP, private endpoint->storage; no same-RG rows' {
    $x = Import-TWCsv $run4 'crossReferences.csv'
    Assert-True (@($x | Where-Object { $_.Resource -eq 'vm-app01' -and $_.TargetResource -eq 'nic-app01' -and $_.Relation -eq 'CrossResourceGroup' }).Count -eq 1) 'vm->nic'
    Assert-True (@($x | Where-Object { $_.Resource -eq 'nic-app01' -and $_.TargetResource -eq 'pip-app01' }).Count -eq 1) 'nic->pip'
    Assert-True (@($x | Where-Object { $_.Resource -eq 'pe-stcontosodata' -and $_.TargetResource -eq 'stcontosodata' -and $_.TargetExists -eq 'Yes' }).Count -eq 1) 'pe->storage'
    Assert-Equal 0 @($x | Where-Object { $_.ResourceGroup -eq $_.TargetResourceGroup -and $_.SubscriptionId -eq $_.TargetSubscriptionId }).Count
}

Test-Case 'retirements: rules with statuses relative to the run date, plus Advisor' {
    $ret = Import-TWCsv $run4 'retirements.csv'
    $f = { param($res, $rule) @($ret | Where-Object { $_.Resource -eq $res -and $_.RuleId -eq $rule }) }
    Assert-Equal 'Retired' (& $f 'pip-basic' 'R01')[0].Status
    Assert-Equal 'Retired' (& $f 'lb-basic' 'R02')[0].Status
    Assert-Equal 'Retired' (& $f 'vm-legacy01' 'R03')[0].Status
    Assert-Equal 'Later' (& $f 'vm-legacy01' 'R20')[0].Status
    Assert-Equal 'Retired' (& $f 'stcontosodata' 'R06')[0].Status
    $gpv1 = (& $f 'stlegacyvhds' 'R07')[0]
    Assert-Equal 'Due within 90 days' $gpv1.Status
    Assert-Equal '14' $gpv1.DaysLeft
    Assert-Equal 1 @(& $f 'OmsAgentForLinux' 'R08').Count
    Assert-Equal 2 @($ret | Where-Object RuleId -eq 'R09').Count
    Assert-Equal 1 @(& $f 'agw-v1' 'R10').Count
    Assert-Match (& $f 'vm-legacy01' 'R25')[0].Detail 'SQL Server 2014'
    Assert-Equal 0 @($ret | Where-Object { $_.Source -eq 'Advisor' -and $_.Feature -eq 'Basic Load Balancer' }).Count 'Advisor duplicate of rule R02'
    $adv = @($ret | Where-Object { $_.Source -eq 'Advisor' -and $_.Feature -eq 'Storage classic metrics' })
    Assert-Equal 1 $adv.Count
    Assert-Equal 'Due within 1 year' $adv[0].Status
    Assert-Equal 1 @(& $f 'Cleanup' 'R27').Count
    Assert-Equal 'Retired' $ret[0].Status 'sorted by days left'
}

Test-Case 'orphaned resources (dolevshor rules + stopped VMs + empty resource groups)' {
    $o = Import-TWCsv $run4 'orphans.csv'
    $expect = @{ 'disk-orphan' = 'Unattached disk'; 'pip-basic' = 'Unused public IP'; 'nic-orphan' = 'Orphaned NIC'; 'nsg-unused' = 'Unused NSG'
        'rt-unused' = 'Unused route table'; 'asp-empty' = 'Empty App Service plan'; 'lb-basic' = 'Idle load balancer'; 'avset-empty' = 'Empty availability set'
        'ng-unused' = 'Unused NAT gateway'; 'privatelink.vaultcore.azure.net' = 'Unlinked private DNS zone'; 'vm-legacy01' = 'Stopped VM (not deallocated)'; 'rg-empty' = 'Empty resource group' }
    foreach ($k in $expect.Keys) { Assert-True (@($o | Where-Object { $_.Resource -eq $k -and $_.Category -eq $expect[$k] }).Count -eq 1) $k }
    Assert-True (@($o | Where-Object { $_.Resource -eq 'pip-app01' -and $_.SubscriptionId -eq $global:TW_S2 }).Count -eq 1) 'unused pip in S2'
    Assert-True (@($o | Where-Object { $_.Resource -eq 'pip-app01' -and $_.SubscriptionId -eq $global:TW_S1 }).Count -eq 0) 'attached pip reported'
    Assert-Equal '30.25' ($o | Where-Object { $_.Resource -eq 'vm-legacy01' }).Cost
}

Test-Case 'Advisor recommendations with savings' {
    $a = Import-TWCsv $run4 'advisor.csv'
    Assert-Equal 4 @($a).Count
    $c = $a | Where-Object Category -eq 'Cost'
    Assert-Equal '50.5' $c.SavingsAmount
    Assert-Equal 'vm-legacy01' $c.Resource
}

Test-Case 'cost per resource: 429 retried, nextLink paging, unsupported offer is a coverage note' {
    $c = Import-TWCsv $run4 'cost.csv'
    Assert-Equal '123.46' ($c | Where-Object Resource -eq 'vm-app01').Cost
    Assert-Equal 'EUR' ($c | Where-Object Resource -eq 'vm-app01').Currency
    Assert-True (@($c | Where-Object Resource -eq 'vm-legacy01').Count -eq 1) 'second page'
    Assert-True (@($c | Where-Object Resource -eq '(unassigned)').Count -eq 1) 'unassigned costs'
    Assert-Equal '123.46' ($all4 | Where-Object { $_.Name -eq 'vm-app01' -and $_.RowType -eq 'Resource' }).Cost
    Assert-Equal '198.71' ($all4 | Where-Object { $_.RowType -eq 'Subscription' -and $_.SubscriptionId -eq $global:TW_S1 }).Cost
    $cov = Import-TWCsv $run4 'coverage.csv'
    $cc = $cov | Where-Object { $_.Area -like 'Cost*' }
    Assert-Equal 'Partial' $cc.Status
    Assert-Match $cc.Detail 'Contoso Development'
    Assert-True ($run4.Stats.Throttled -ge 1) 'throttle not recorded'
}

Test-Case 'runbook export writes files and flags Run As usage' {
    $rb = Import-TWCsv $run4 'runbooks.csv'
    $c = $rb | Where-Object Runbook -eq 'Cleanup'
    Assert-Equal 'True' $c.UsesRunAs
    Assert-Match $c.ExportedFile '^code/[^/]+/[^/]+/aa-contoso/runbooks/Cleanup\.py$'
    Assert-True (Test-Path ([IO.Path]::Combine($run4.OutDir, $c.ExportedFile))) 'file missing'
    Assert-Equal 'False' ($rb | Where-Object Runbook -eq 'Start-VMs').UsesAzureRM
}

Test-Case 'AzureCode exports the code stored in Azure resources to code\<subscription>\<resource group>\<resource>' {
    $r = Invoke-TWRun -Params @{ Reports = @('AzureCode') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $idx = @(Import-TWCsv $r 'code/index.csv')
    $file = { param([string] $Type, [string] $Item) @($idx | Where-Object { $_.Type -eq $Type -and $_.Item -eq $Item -and $_.Status -eq 'Exported' })[0].File }
    $text = { param([string] $Type, [string] $Item) $f = & $file $Type $Item; Assert-True ([bool]$f) ('not exported: ' + $Type + ' ' + $Item); [IO.File]::ReadAllText([IO.Path]::Combine($r.OutDir, $f)) }
    Assert-Match (& $file 'Runbook' 'Start-VMs') '^code/Contoso Production/[^/]+/aa-contoso/runbooks/Start-VMs\.ps1$'
    Assert-Match (& $text 'DSC configuration' 'WebServer') 'Configuration WebServer'
    $wf = & $text 'Logic App' 'workflow'
    Assert-Match $wf '"triggers": \{'
    Assert-Match $wf '\n  "properties"' 'JSON is indented'
    Assert-Match (& $text 'Data Factory' 'pipelines/CopySales') '"activities"'
    Assert-Match (& $file 'Data Factory' 'linkedServices/ls-sql') '/adf-contoso/linkedServices/ls-sql\.json$'
    Assert-Equal 'SELECT * INTO [out] FROM [in]' (& $text 'Stream Analytics' 'query')
    Assert-Match (& $text 'Template spec' '1.0') 'deploymentTemplate\.json#'
    Assert-Equal 'Write-Output "seed data loaded"' (& $text 'Deployment script' 'script')
    Assert-Match (& $file 'Workbook' 'Ops workbook') '/Ops workbook/workbook\.json$'
    Assert-Match (& $file 'Dashboard' 'Operations') '/Operations/dashboard\.json$'
    Assert-Match (& $text 'Log alert rule' 'query') '^AppExceptions'
    Assert-Match (@($idx | Where-Object { $_.Type -eq 'Sentinel analytics rule' -and $_.File -like '*.kql' })[0].File) '/law-contoso/sentinel/Brute force\.kql$'
    Assert-Match (& $text 'API Management' 'orders-api policy') 'rate-limit'
    Assert-Match (& $text 'API Management' 'orders-api OpenAPI') '"openapi"'
    Assert-Equal 'Failed' @($idx | Where-Object { $_.Item -eq 'soap-api OpenAPI' })[0].Status
    Assert-Equal 0 @($idx | Where-Object { $_.Item -like 'orders-api;rev=*' }).Count 'older API revisions skipped'
    Assert-Match (& $file 'Policy definition' 'Require app tag on resources') '^code/policy/definitions/Require app tag on resources\.json$'
    Assert-Equal 1 @($idx | Where-Object Type -eq 'Policy initiative').Count
    $role = (& $text 'Custom role' 'Contoso VM Operator') | ConvertFrom-Json
    Assert-True ($role.IsCustom -and @($role.Actions) -contains 'Microsoft.Compute/virtualMachines/*') 'role in New-AzRoleDefinition format'
    foreach ($f in @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($r.OutDir, 'code')) -Recurse -File)) {
        Assert-True ([IO.File]::ReadAllText($f.FullName).IndexOf('SECRETSAS') -lt 0) ('SAS signature in ' + $f.Name)
    }
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Code export'
    Assert-Equal 'Partial' $cov.Status
    Assert-Match $cov.Detail '1 not exported'
}

Test-Case 'AppCode downloads wwwroot with the Kudu zip; without publish rights the app is listed as not exported' {
    $r = Invoke-TWRun -Params @{ Reports = @('AppCode') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $row = @((Import-TWCsv $r 'code/index.csv') | Where-Object { $_.Type -eq 'App code' -and $_.Resource -eq 'app-contoso' })[0]
    Assert-Equal 'Exported' $row.Status
    Assert-Match $row.File '^code/Contoso Production/[^/]+/app-contoso/wwwroot$'
    Assert-Equal 'module.exports = async () => 42;' ([IO.File]::ReadAllText([IO.Path]::Combine($r.OutDir, $row.File, 'index.js')))
    Assert-False (Test-Path ([IO.Path]::Combine($r.OutDir, '.cache-app.zip'))) 'temporary zip removed'
    Reset-TWState
    $global:TW.KuduDenied = $true
    $r2 = Invoke-TWRun -Params @{ Reports = @('AppCode') } -KeepWorld
    Assert-Equal 0 $r2.Errors.Count ($r2.Errors -join ' | ')
    $row2 = @((Import-TWCsv $r2 'code/index.csv') | Where-Object Resource -eq 'app-contoso')[0]
    Assert-Equal 'Failed' $row2.Status
    Assert-Match $row2.Detail '^Needs publish rights \(Website Contributor\)'
    Assert-Equal 'Partial' ((Import-TWCsv $r2 'coverage.csv') | Where-Object Area -eq 'App code export').Status
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Configuration snapshot' -ForegroundColor Cyan

Test-Case 'snapshot paths mirror the ARM ID: resource group, subscription, management group and tenant scope, safe names' {
    Reset-TWState
    $script:A2C = [pscustomobject]@{ Data = @{ SubById = @{ $global:TW_S1 = [pscustomobject]@{ Name = 'Contoso Production' } } } }
    $s = '/subscriptions/' + $global:TW_S1
    Assert-Equal 'snapshot/Contoso Production/rg-app/Microsoft.Network/virtualNetworks/vnet1.json' (Get-A2CSnapshotPath ($s + '/resourceGroups/rg-app/providers/Microsoft.Network/virtualNetworks/vnet1'))
    Assert-Equal 'snapshot/Contoso Production/rg-app/Microsoft.Network/virtualNetworks/vnet1/subnets/sn1.json' (Get-A2CSnapshotPath ($s + '/resourceGroups/rg-app/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/sn1'))
    Assert-Equal 'snapshot/Contoso Production/rg-app/Microsoft.Storage/storageAccounts/st1/Microsoft.Authorization/locks/keep.json' (Get-A2CSnapshotPath ($s + '/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/st1/providers/Microsoft.Authorization/locks/keep')) 'extension resource'
    Assert-Equal 'snapshot/Contoso Production/rg-app.json' (Get-A2CSnapshotPath ($s + '/resourceGroups/rg-app')) 'the resource group itself'
    Assert-Equal 'snapshot/Contoso Production/_subscription.json' (Get-A2CSnapshotPath $s) 'the subscription itself'
    Assert-Equal 'snapshot/Contoso Production/_subscription/Microsoft.Authorization/roleAssignments/abc.json' (Get-A2CSnapshotPath ($s + '/providers/Microsoft.Authorization/roleAssignments/abc'))
    Assert-Equal 'snapshot/_managementGroups/mg-contoso/Microsoft.Authorization/policyAssignments/p1.json' (Get-A2CSnapshotPath '/providers/Microsoft.Management/managementGroups/mg-contoso/providers/Microsoft.Authorization/policyAssignments/p1')
    Assert-Equal 'snapshot/_managementGroups/mg-contoso.json' (Get-A2CSnapshotPath '/providers/Microsoft.Management/managementGroups/mg-contoso')
    Assert-Equal 'snapshot/_tenant/Microsoft.Authorization/roleDefinitions/abc.json' (Get-A2CSnapshotPath '/providers/Microsoft.Authorization/roleDefinitions/abc')
    Assert-Equal 'snapshot/_entra/applications/My App 123.json' (Get-A2CSnapshotPath '/_entra/applications/My App 123')
    Assert-Equal 'snapshot/00000000-0000-0000-0000-00000000dead/rg/Microsoft.Sql/servers/_nul/databases/a_b.json' (Get-A2CSnapshotPath '/subscriptions/00000000-0000-0000-0000-00000000dead/resourceGroups/rg/providers/Microsoft.Sql/servers/nul/databases/a:b') 'unknown subscription, reserved and unsafe names'
}

Test-Case 'Snapshot writes the complete JSON of every object; the CSV cell is cut at 32,000 characters, the file is not' {
    Reset-TWState
    # a firewall policy with about 60,000 characters of properties and tags that look like dates
    $ranges = @(1..4000 | ForEach-Object { '10.{0}.{1}.0/24' -f [int][math]::Floor($_ / 250), ($_ % 250) })
    $big = New-TWRes $global:TW_S1 'rg-network' 'Microsoft.Network/firewallPolicies' 'fwpol-hub' ([ordered]@{ threatIntelMode = 'Alert'; threatIntelWhitelist = [ordered]@{ ipAddresses = $ranges }; lastSetting = 'END-OF-PROPERTIES' }) -Tags ([ordered]@{ created = '2024-01-05T10:00:00Z'; owner = 'net team' }) -Sku ([ordered]@{ tier = 'Premium' })
    $global:TW.Resources = @($global:TW.Resources) + $big
    $global:TW.Arg['resources'] = $global:TW.Resources
    $r = Invoke-TWRun -Params @{ Reports = @('Resources', 'Snapshot', 'RBAC', 'Locks') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $snap = [IO.Path]::Combine($r.OutDir, 'snapshot', 'Contoso Production')
    $file = [IO.Path]::Combine($snap, 'rg-network', 'Microsoft.Network', 'firewallPolicies', 'fwpol-hub.json')
    $text = [IO.File]::ReadAllText($file)
    Assert-True ($text.Length -gt 60000) ('file length ' + $text.Length)
    $j = $text | ConvertFrom-Json
    Assert-Equal 'END-OF-PROPERTIES' $j.properties.lastSetting 'last property present'
    Assert-Equal 4000 @($j.properties.threatIntelWhitelist.ipAddresses).Count
    Assert-Equal 'Microsoft.Network/firewallPolicies' $j.type 'type in the casing of the ID'
    Assert-Equal '2024-05-01' $j.apiVersion; Assert-Equal 'Premium' $j.sku.tier; Assert-Equal 'westeurope' $j.location
    Assert-Match $text '"created": "2024-01-05T10:00:00Z"' 'tag text exactly as returned'
    $csv = (Import-TWCsv $r 'allResources.csv') | Where-Object Name -eq 'fwpol-hub'
    Assert-True ($csv.Properties.Length -le 32000 -and $csv.Properties -match 'truncated\]$') 'the CSV cell is cut'
    # containers, the other Resource Graph tables, objects read with ARM
    Assert-Equal 'rg-network' (([IO.File]::ReadAllText([IO.Path]::Combine($snap, 'rg-network.json'))) | ConvertFrom-Json).name
    Assert-True (Test-Path ([IO.Path]::Combine($snap, '_subscription.json'))) 'subscription'
    $dns = [IO.File]::ReadAllText([IO.Path]::Combine($snap, 'rg-network', 'Microsoft.Network', 'privateDnsZones', 'privatelink.blob.core.windows.net', 'A', 'stcontosodata.json')) | ConvertFrom-Json
    Assert-Equal '10.0.2.5' $dns.properties.records[0].ipv4Address 'private DNS record from dnsresources'
    $rcg = [IO.File]::ReadAllText([IO.Path]::Combine($snap, 'rg-network', 'Microsoft.Network', 'firewallPolicies', 'fwpol-hub', 'ruleCollectionGroups', 'DefaultNetworkRuleCollectionGroup.json')) | ConvertFrom-Json
    Assert-Equal 'dns-out' $rcg.properties.ruleCollections[0].rules[0].name 'firewall rules from networkresources'
    Assert-True (Test-Path ([IO.Path]::Combine($snap, 'rg-data', 'Microsoft.RecoveryServices', 'vaults', 'rsv-contoso', 'backupPolicies', 'DailyPolicy.json'))) 'backup policy'
    $ra = @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($snap, '_subscription', 'Microsoft.Authorization', 'roleAssignments')) -Filter *.json)
    Assert-True ($ra.Count -ge 1) 'role assignments'
    Assert-True ($null -ne ([IO.File]::ReadAllText($ra[0].FullName) | ConvertFrom-Json).properties.roleDefinitionId) 'role assignment as returned by ARM'
    Assert-True (@(Get-ChildItem -LiteralPath $snap -Recurse -Filter *.json | Where-Object { $_.FullName -match 'Microsoft\.Authorization[\\/]locks' }).Count -ge 1) 'locks'
    $ix = Import-TWCsv $r 'snapshot/index.csv'
    $row = $ix | Where-Object Name -eq 'fwpol-hub'
    Assert-Equal 'snapshot/Contoso Production/rg-network/Microsoft.Network/firewallPolicies/fwpol-hub.json' $row.File
    Assert-Equal 'Resource Graph' $row.Source; Assert-Equal '2024-05-01' $row.ApiVersion
    Assert-Equal 'Resource Graph: dnsresources' ($ix | Where-Object { $_.Name -eq 'stcontosodata' -and $_.Type -eq 'Microsoft.Network/privateDnsZones/A' }).Source
    Assert-True (@($ix | Where-Object Source -eq 'ARM: roleAssignments').Count -ge 1) 'index lists the ARM objects'
    Assert-Equal @($global:TW.Resources).Count @($ix | Where-Object { $_.Source -eq 'Resource Graph' -and $_.Type -notmatch '(?i)^microsoft\.resources/subscriptions|^microsoft\.management/managementgroups$' }).Count 'every resource has a file'
    Assert-Equal @($ix).Count @($ix | Where-Object { $_.File -and (Test-Path -LiteralPath ([IO.Path]::Combine($r.OutDir, $_.File))) }).Count 'every index row points to a file'
    Assert-Equal 'Collected' ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Configuration snapshot').Status
}

Test-Case 'Snapshot: a Resource Graph table the cloud does not have is a note; never with -Mask; part of -Profile Full' {
    Reset-TWState
    $global:TW.MissingTables = @('kustoresources', 'batchresources')
    $r = Invoke-TWRun -Params @{ Reports = @('Snapshot') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object { $_.Area -like 'Other Resource Graph tables*' }
    Assert-Equal 'Partial' $cov.Status; Assert-Match $cov.Detail 'not readable: batchresources, kustoresources$'
    Assert-True (Test-Path ([IO.Path]::Combine($r.OutDir, 'snapshot', 'index.csv'))) 'snapshot still written'
    $m = Invoke-TWRun -Params @{ Reports = @('Snapshot'); Mask = $true }
    Assert-False (Test-Path ([IO.Path]::Combine($m.OutDir, 'snapshot'))) 'snapshot under -Mask'
    Assert-Equal 'Skipped' ((Import-TWCsv $m 'coverage.csv') | Where-Object Area -eq 'Configuration snapshot').Status
    Assert-True ((Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Full' })) -contains 'Snapshot') 'in Full'
    Assert-False ((Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Standard' })) -contains 'Snapshot') 'not in Standard'
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'ARM templates' -ForegroundColor Cyan

Test-Case 'JSON text helpers: a member is cut out of the text unchanged; quotes and angle brackets stay readable on both editions' {
    $j = '{"a":{"template":"inner","y":[1,{"z":"}{"}]}, "template" : {"n":1.50,"s":"q\"}","arr":[]} ,"error":null,"last":true}'
    Assert-Equal '{"n":1.50,"s":"q\"}","arr":[]}' (Get-A2CJsonMember $j 'template') 'top-level member; braces and escaped quotes inside strings'
    Assert-Equal 'null' (Get-A2CJsonMember $j 'error'); Assert-Equal 'true' (Get-A2CJsonMember $j 'last')
    Assert-True ($null -eq (Get-A2CJsonMember $j 'z')) 'a nested member is not a member of the object'
    Assert-True ($null -eq (Get-A2CJsonMember $j 'missing')); Assert-True ($null -eq (Get-A2CJsonMember '' 'x'))
    Assert-Equal '"x"' (Get-A2CJsonMember '{"template":"x"}' 'template')
    Assert-True ($null -eq (Get-A2CJsonMember '{"x":"template","y":1}' 'template')) 'a value is not a name'
    # Windows PowerShell writes ' < > & as unicode escapes; a real backslash before u0027 must stay
    $path = 'C:\dir\' + 'u0027x'
    $t = ConvertTo-A2CCodeJson ([ordered]@{ rule = "[parameters('x')]"; cmp = 'a < b && c > d'; path = $path })
    Assert-Match $t ([regex]::Escape('"rule": "[parameters(''x'')]"'))
    Assert-Match $t ([regex]::Escape('"cmp": "a < b && c > d"'))
    Assert-Equal $path ($t | ConvertFrom-Json).path
}

Test-Case 'ArmTemplates: a JSON template and a Bicep file per resource group, written as Azure returned them' {
    Reset-TWState
    $global:TW.TemplateLimitGroups = @('rg-legacy')
    $script:A2CTemplateBatch = 4
    try { $r = Invoke-TWRun -Params @{ Reports = @('ArmTemplates') } -KeepWorld } finally { $script:A2CTemplateBatch = 200 }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $dir = [IO.Path]::Combine($r.OutDir, 'templates', 'Contoso Production')
    $json = [IO.File]::ReadAllText([IO.Path]::Combine($dir, 'rg-app.json'))
    $t = $json | ConvertFrom-Json
    $inApp = @($global:TW.Resources | Where-Object { $_['subscriptionId'] -eq $global:TW_S1 -and $_['resourceGroup'] -eq 'rg-app' }).Count
    Assert-Equal '1.0.0.0' $t.contentVersion; Assert-Equal $inApp @($t.resources).Count
    Assert-Match $json ([regex]::Escape("[resourceId('Microsoft.Network/virtualNetworks', 'vnet-hub')]")) 'template expressions keep their quotes'
    Assert-Match $json '"createdOn": "2024-01-01T00:00:00\.0000000Z"' 'dates are not reformatted'
    Assert-Match $json '"big": 12345678901234567890'; Assert-Match $json '"ratio": 1\.0'
    Assert-False ($json -match 'ExportTemplateCompletedWithErrors') 'the file holds the template only'
    $bicep = [IO.File]::ReadAllText([IO.Path]::Combine($dir, 'rg-app.bicep'))
    Assert-Match $bicep "(?m)^resource r1 '[a-z.]+/[a-z/]+@2024-05-01' = \{$"; Assert-Match $bicep "(?m)^  location: resourceGroup\(\)\.location$"
    $ix = Import-TWCsv $r 'templates/index.csv'
    Assert-Equal 7 $ix.Count 'one row per resource group'
    Assert-Equal 'NetworkWatcherRG,rg-dev,rg-app,rg-data,rg-empty,rg-legacy,rg-network' (($ix | ForEach-Object { $_.ResourceGroup }) -join ',') 'by subscription, then name'
    $app = $ix | Where-Object ResourceGroup -eq 'rg-app'
    Assert-Equal 'Partial' $app.Status; Assert-Equal '1' $app.NotExported; Assert-Equal 'Microsoft.Web/sites/config' $app.NotExportedTypes
    Assert-Equal 'templates/Contoso Production/rg-app.json' $app.JsonFile; Assert-Equal 'templates/Contoso Production/rg-app.bicep' $app.BicepFile
    Assert-Equal ([string]$inApp) $app.Resources; Assert-Equal ([string]$inApp) $app.TemplateResources; Assert-Equal 'westeurope' $app.Location
    $gaps = @(Import-TWCsv $r 'templates/notExported.csv')
    Assert-Equal 1 $gaps.Count 'both formats report the same gap: listed once'
    Assert-Equal 'rg-app' $gaps[0].ResourceGroup; Assert-Equal 'ExportTemplateProviderError' $gaps[0].Code; Assert-Match $gaps[0].Message 'will not be exported'
    # 202 Accepted: the result is read from the Location, waiting as long as Retry-After says
    Assert-Equal 'Exported' ($ix | Where-Object ResourceGroup -eq 'rg-network').Status
    Assert-True (Test-Path ([IO.Path]::Combine($dir, 'rg-network.json'))); Assert-True (Test-Path ([IO.Path]::Combine($dir, 'rg-network.bicep')))
    Assert-Equal 4 @($global:TWRequests | Where-Object { $_.Method -eq 'GET' -and $_.Uri -match '/operationresults/twexport-rg-network-' }).Count 'two polls per format'
    Assert-True (($global:TWSleeps -contains 7) -and ($global:TWSleeps -contains 3)) ('Retry-After honored: ' + ($global:TWSleeps -join ','))
    # an empty resource group is not asked for
    $empty = $ix | Where-Object ResourceGroup -eq 'rg-empty'
    Assert-Equal 'Empty' $empty.Status; Assert-Equal '' $empty.JsonFile
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match '/resourcegroups/rg-empty/exportTemplate' }).Count
    # more resources than Azure exports at once: batches of resource IDs, each its own template
    $legacy = $ix | Where-Object ResourceGroup -eq 'rg-legacy'
    $calls = @($global:TWRequests | Where-Object { $_.Uri -match '/resourcegroups/rg-legacy/exportTemplate' })
    Assert-Equal 'Exported' $legacy.Status; Assert-Match $legacy.Detail '^Too many resources for one export call: exported by resource ID in 3 part\(s\)$'
    Assert-Equal 'templates/Contoso Production/rg-legacy (part 1).json; templates/Contoso Production/rg-legacy (part 2).json; templates/Contoso Production/rg-legacy (part 3).json' $legacy.JsonFile
    Assert-Equal '9' $legacy.Resources; Assert-Equal '9' $legacy.TemplateResources
    Assert-Equal 7 $calls.Count 'the refused call, then three batches in two formats'
    Assert-Equal '4,4,4,4,1,1' ((@($calls | Select-Object -Skip 1) | ForEach-Object { @(($_.Body | ConvertFrom-Json).resources).Count }) -join ',')
    Assert-Match $calls[1].Body ('"resources":\["/subscriptions/' + $global:TW_S1 + '/resourceGroups/rg-legacy/providers/')
    Assert-True (Test-Path ([IO.Path]::Combine($dir, 'rg-legacy (part 3).bicep')))
    # no permission: one call, listed as not exported, the run goes on
    $dev = $ix | Where-Object ResourceGroup -eq 'rg-dev'
    Assert-Equal 'Not exported' $dev.Status; Assert-Match $dev.Detail '^Json: HTTP 403 AuthorizationFailed: '
    Assert-Equal 1 @($global:TWRequests | Where-Object { $_.Uri -match '/resourcegroups/rg-dev/exportTemplate' }).Count 'Bicep is not tried after a refusal'
    # Bicep refused for one resource group: the JSON template is still there
    $nw = $ix | Where-Object ResourceGroup -eq 'NetworkWatcherRG'
    Assert-Equal 'Partial' $nw.Status; Assert-Equal 'templates/Contoso Development/NetworkWatcherRG.json' $nw.JsonFile; Assert-Equal '' $nw.BicepFile
    Assert-Match $nw.Detail '^Bicep: HTTP 400 InvalidTemplate: '
    $post = @($global:TWRequests | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match '/exportTemplate\?api-version=2025-04-01$' })
    Assert-Equal 0 @($post | Where-Object { $_.Body -notmatch '"options":"SkipAllParameterization"' }).Count
    Assert-True (@($post | Where-Object { $_.Body -match '"outputFormat":"Bicep"' }).Count -ge 5) 'Bicep is asked for with outputFormat'
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'ARM template export'
    Assert-Equal 'Partial' $cov.Status; Assert-Equal '5' $cov.Items
    Assert-Match $cov.Detail '^5 of 7 resource groups exported, 2 with gaps \(templates\\notExported\.csv lists what Azure did not export\), 1 not exported \(templates\\index\.csv\), 1 empty$'
}

Test-Case 'ArmTemplates: -TemplateFormat, a cloud with the older API, Bicep not offered, a subscription without permission' {
    $r = Invoke-TWRun -Params @{ Reports = @('ArmTemplates'); TemplateFormat = 'Json' }
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Body -match 'outputFormat' }).Count 'Json: no Bicep calls'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($r.OutDir, 'templates')) -Recurse -Filter *.bicep).Count
    Assert-Equal 'Exported' ((Import-TWCsv $r 'templates/index.csv') | Where-Object ResourceGroup -eq 'NetworkWatcherRG').Status
    $r = Invoke-TWRun -Params @{ Reports = @('ArmTemplates'); TemplateFormat = 'Bicep' }
    Assert-Equal 0 @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($r.OutDir, 'templates')) -Recurse -Filter *.json).Count 'Bicep: no JSON files'
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match '/exportTemplate' -and $_.Body -notmatch 'outputFormat' }).Count
    Assert-Equal 'Microsoft.Web/sites/config' ((Import-TWCsv $r 'templates/notExported.csv') | Where-Object ResourceGroup -eq 'rg-app').Target 'the gaps come with the Bicep answer too'
    Assert-Equal '' ((Import-TWCsv $r 'templates/index.csv') | Where-Object ResourceGroup -eq 'rg-app').TemplateResources 'not counted in Bicep'
    # a cloud that has only the older API version: JSON templates, even when Bicep was asked for
    Reset-TWState
    $global:TW.TemplateOldApi = $true
    $r = Invoke-TWRun -Params @{ Reports = @('ArmTemplates'); TemplateFormat = 'Bicep' } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $calls = @($global:TWRequests | Where-Object { $_.Uri -match '/exportTemplate\?' })
    Assert-Equal 1 @($calls | Where-Object { $_.Uri -match 'api-version=2025-04-01' }).Count 'the current version is tried once'
    Assert-Equal 0 @($calls | Where-Object { $_.Uri -match 'api-version=2021-04-01' -and $_.Body -match 'outputFormat' }).Count
    Assert-True (Test-Path ([IO.Path]::Combine($r.OutDir, 'templates', 'Contoso Production', 'rg-app.json')))
    Assert-Equal 0 @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($r.OutDir, 'templates')) -Recurse -Filter *.bicep).Count
    Assert-Match ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'ARM template export').Detail 'API version 2025-04-01 is not available here; 2021-04-01 was used, which has no Bicep output'
    # the outputFormat is ignored (a JSON template comes back): asked once, then JSON for the rest of the run
    Reset-TWState
    $global:TW.TemplateNoBicep = $true
    $r = Invoke-TWRun -Params @{ Reports = @('ArmTemplates') } -KeepWorld
    Assert-Equal 1 @($global:TWRequests | Where-Object { $_.Body -match 'outputFormat' }).Count
    Assert-Equal 0 @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($r.OutDir, 'templates')) -Recurse -Filter *.bicep).Count
    Assert-Match ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'ARM template export').Detail 'Azure did not return Bicep here; JSON templates only'
    Assert-Equal 'Exported' ((Import-TWCsv $r 'templates/index.csv') | Where-Object ResourceGroup -eq 'rg-network').Status
    # a subscription that refuses the export: three resource groups are tried, the others are not
    Reset-TWState
    $global:TW.TemplateDeniedSubs = @($global:TW_S1)
    $r = Invoke-TWRun -Params @{ Reports = @('ArmTemplates') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    Assert-Equal 3 @($global:TWRequests | Where-Object { $_.Uri -match ($global:TW_S1 + '/resourcegroups/[^/]+/exportTemplate') }).Count
    $ix = Import-TWCsv $r 'templates/index.csv'
    Assert-Equal 4 @($ix | Where-Object { $_.SubscriptionName -eq 'Contoso Production' -and $_.Status -eq 'Not exported' }).Count
    Assert-Match ($ix | Where-Object ResourceGroup -eq 'rg-network').Detail '^No permission to export templates in this subscription'
    Assert-True (@($r.Warnings | Where-Object { $_ -match 'ARM template export: no permission in subscription Contoso Production' }).Count -eq 1) ($r.Warnings -join ' | ')
    Assert-Equal 'Partial' ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'ARM template export').Status 'the other subscription was exported'
}

Test-Case 'ArmTemplates: a batch Azure still refuses is halved; never with -Mask; part of -Profile Full' {
    Reset-TWState
    $global:TW.TemplateLimitGroups = @('rg-legacy'); $global:TW.TemplateLimit = 4
    $script:A2CTemplateMinBatch = 2
    try { $r = Invoke-TWRun -Params @{ Reports = @('ArmTemplates'); TemplateFormat = 'Json' } -KeepWorld } finally { $script:A2CTemplateMinBatch = 25 }
    $legacy = (Import-TWCsv $r 'templates/index.csv') | Where-Object ResourceGroup -eq 'rg-legacy'
    Assert-Equal 'Exported' $legacy.Status; Assert-Equal '9' $legacy.TemplateResources
    Assert-Match $legacy.Detail 'in 3 part\(s\)$'
    $sizes = @($global:TWRequests | Where-Object { $_.Uri -match '/resourcegroups/rg-legacy/exportTemplate' } | ForEach-Object { @(($_.Body | ConvertFrom-Json).resources).Count })
    Assert-Equal '1,9,5,3,2,4' ($sizes -join ',') 'all, all by ID, a half, then its halves, then the other half'
    # without halving left, the resource group is listed as not exported
    Reset-TWState
    $global:TW.TemplateLimitGroups = @('rg-legacy'); $global:TW.TemplateLimit = 4
    $r = Invoke-TWRun -Params @{ Reports = @('ArmTemplates'); TemplateFormat = 'Json' } -KeepWorld
    $legacy = (Import-TWCsv $r 'templates/index.csv') | Where-Object ResourceGroup -eq 'rg-legacy'
    Assert-Equal 'Not exported' $legacy.Status; Assert-Match $legacy.Detail 'ExportTemplateResourcesLimitExceeded'
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $m = Invoke-TWRun -Params @{ Reports = @('ArmTemplates'); Mask = $true }
    Assert-False (Test-Path ([IO.Path]::Combine($m.OutDir, 'templates'))) 'templates under -Mask'
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match '/exportTemplate' }).Count
    Assert-Equal 'Skipped' ((Import-TWCsv $m 'coverage.csv') | Where-Object Area -eq 'ARM template export').Status
    Assert-True ((Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Full' })) -contains 'ArmTemplates') 'in Full'
    Assert-False ((Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Standard' })) -contains 'ArmTemplates') 'not in Standard'
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Child resources and resource providers' -ForegroundColor Cyan

Test-Case 'API versions: the newest released one of a list, of the type or its nearest parent, or named by an error' {
    Assert-Equal '2024-01-01' (Get-A2CStableApiVersion @('2023-05-01', '2025-06-01-preview', '2024-01-01'))
    Assert-Equal '2025-06-01-preview' (Get-A2CStableApiVersion @('2025-06-01-preview', '2024-01-01-beta')) 'only previews: the newest'
    Assert-Equal '' (Get-A2CStableApiVersion @())
    Assert-Equal '2021-11-01' (Get-A2CApiVersionFromError "No registered resource provider found for location 'x' and API version '2099-01-01' for type 'servers/firewallRules'. The supported api-versions are '2014-04-01, 2021-11-01, 2022-05-01-preview'. The supported locations are 'westeurope'.")
    Assert-Equal '2025-04-01' (Get-A2CApiVersionFromError "The api-version '2099-01-01' is invalid. The supported versions are '2025-04-01,2025-03-01,2024-11-01'.")
    Assert-Equal '' (Get-A2CApiVersionFromError 'Something else went wrong.')
    $q = '\' + 'u0027'
    Assert-Equal '2024-03-01' (Get-A2CApiVersionFromError ('{"error":{"message":"The supported api-versions are ' + $q + '2023-05-01, 2024-03-01' + $q + '."}}')) 'quotes escaped in the raw answer'
    $script:A2C = [pscustomobject]@{ Data = @{ ProviderApi = @{ 'microsoft.storage/storageaccounts' = @('2025-01-01', '2023-05-01'); 'microsoft.storage/storageaccounts/blobservices' = @('2025-06-01-preview', '2024-01-01') } } }
    Assert-Equal '2024-01-01' (Get-A2CApiVersionFor 'Microsoft.Storage/storageAccounts/blobServices' '2000-01-01')
    Assert-Equal '2024-01-01' (Get-A2CApiVersionFor 'Microsoft.Storage/storageAccounts/blobServices/containers' '2000-01-01') 'nearest parent type'
    Assert-Equal '2025-01-01' (Get-A2CApiVersionFor 'Microsoft.Storage/storageAccounts/encryptionScopes' '2000-01-01')
    Assert-Equal '2000-01-01' (Get-A2CApiVersionFor 'Microsoft.Other/things/parts' '2000-01-01') 'unknown provider: the default'
}

Test-Case 'ChildResources: lists below resources with paging, chains, single objects; a wrong API version is corrected from the answer' {
    $r = Invoke-TWRun -Params @{ Reports = @('ChildResources', 'Snapshot') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $c = Import-TWCsv $r 'childResources.csv'
    $containers = @($c | Where-Object Type -eq 'Microsoft.Storage/storageAccounts/blobServices/containers')
    Assert-Equal 'backups,public-assets,$web' (($containers | ForEach-Object { $_.Name }) -join ',') 'both pages'
    Assert-Equal 'stcontosodata' $containers[0].Parent; Assert-Equal 'Microsoft.Storage/storageAccounts' $containers[0].ParentType
    Assert-Equal 'Contoso Production' $containers[0].SubscriptionName; Assert-Equal 'rg-data' $containers[0].ResourceGroup
    Assert-Match ($containers | Where-Object Name -eq 'public-assets').Properties '"publicAccess":"Blob"'
    Assert-Match ($c | Where-Object { $_.Type -eq 'Microsoft.Storage/storageAccounts/blobServices' -and $_.Parent -eq 'stcontosodata' }).Properties '"isVersioningEnabled":true'
    Assert-Match ($c | Where-Object Name -eq 'profiles').Properties '"shareQuota":100'
    Assert-Equal 1 @($c | Where-Object Type -eq 'Microsoft.Storage/storageAccounts/managementPolicies').Count 'one object; the other account has none'
    Assert-Equal 'AllowAllWindowsAzureIps,office' ((@($c | Where-Object Type -eq 'Microsoft.Sql/servers/firewallRules') | ForEach-Object { $_.Name }) -join ',')
    Assert-Equal 2 @($c | Where-Object Type -eq 'Microsoft.ApiManagement/service/apis').Count 'older revisions of an API are left out'
    $secret = $c | Where-Object Type -eq 'Microsoft.KeyVault/vaults/secrets'
    Assert-Equal 'sql-admin-login' $secret.Name; Assert-Match $secret.Properties '"exp":1798761600'
    # which API version: the newest released one the provider lists, for the type or its nearest parent; else the default
    $t = Import-TWCsv $r 'childResourceTypes.csv'
    $type = { param($n) $t | Where-Object Type -eq $n }
    Assert-Equal '2024-01-01' (& $type 'Microsoft.Storage/storageAccounts/blobServices').ApiVersion
    Assert-Equal '2024-01-01' (& $type 'Microsoft.Storage/storageAccounts/blobServices/containers').ApiVersion
    Assert-Equal '2025-01-01' (& $type 'Microsoft.Storage/storageAccounts/encryptionScopes').ApiVersion
    Assert-Equal '2024-11-01' (& $type 'Microsoft.KeyVault/vaults/secrets').ApiVersion
    Assert-Equal '2023-11-01' (& $type 'Microsoft.Automation/automationAccounts/variables').ApiVersion 'a provider that is not in the list'
    $fw = & $type 'Microsoft.Sql/servers/firewallRules'
    Assert-Equal '2021-11-01' $fw.ApiVersion; Assert-Equal '2' $fw.Calls; Assert-Equal '1' $fw.Answered; Assert-Equal '2' $fw.Items
    Assert-Equal 1 @($global:TWRequests | Where-Object { $_.Uri -match '/firewallRules\?api-version=2023-08-01' }).Count
    $mp = & $type 'Microsoft.Storage/storageAccounts/managementPolicies'
    Assert-Equal '2' $mp.Calls; Assert-Equal '1' $mp.Items; Assert-Equal '1' $mp.NotFound; Assert-Equal '0' $mp.Failed
    Assert-Equal 'Microsoft.Storage/storageAccounts' (& $type 'Microsoft.Storage/storageAccounts/blobServices/containers').ParentType
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match '/databases/master/' }).Count 'the master database is not asked'
    Assert-Equal 1 @($global:TWRequests | Where-Object { $_.Uri -match '/subscriptions/[^/]+/providers\?api-version=' }).Count 'API versions from one subscription'
    # secrets: a member named in the table and well-known key names
    Assert-Match ($c | Where-Object Name -eq 'orders-backend').Properties '"credentials":"\(not exported\)"'
    Assert-Match ($c | Where-Object { $_.Type -eq 'Microsoft.ApiManagement/service/subscriptions' }).Properties '"primaryKey":"\(not exported\)","secondaryKey":"\(not exported\)"'
    $leaks = @(Get-ChildItem -LiteralPath $r.OutDir -Recurse -File | Where-Object { $_.Extension -in '.csv', '.json' } | Where-Object { [IO.File]::ReadAllText($_.FullName) -match 'LITERAL-BACKEND-KEY-1|APIM-PRIMARY-KEY-2|APIM-SECONDARY-KEY-3' })
    Assert-Equal 0 $leaks.Count (($leaks | ForEach-Object { $_.Name }) -join ', ')
    Assert-Match ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Secret values').Detail '^2 value\(s\)' 'each replaced value is counted once'
    # the same items as JSON files in the snapshot
    $snap = [IO.Path]::Combine($r.OutDir, 'snapshot', 'Contoso Production', 'rg-data', 'Microsoft.Storage', 'storageAccounts', 'stcontosodata')
    Assert-Equal 'None' ([IO.File]::ReadAllText([IO.Path]::Combine($snap, 'blobServices', 'default', 'containers', 'backups.json')) | ConvertFrom-Json).properties.publicAccess
    Assert-True (Test-Path -LiteralPath ([IO.Path]::Combine($snap, 'managementPolicies', 'default.json')))
    Assert-True (@((Import-TWCsv $r 'snapshot/index.csv') | Where-Object Source -eq 'ARM: child resources').Count -ge 10)
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Child resources (ARM)'
    Assert-Equal 'Collected' $cov.Status; Assert-Equal ([string]@($c).Count) $cov.Items
}

Test-Case 'ChildResources: a type that is refused three times is not asked again; ResourceProviders lists the registrations' {
    Reset-TWState
    foreach ($n in 1..4) { $global:TW.Resources = @($global:TW.Resources) + (New-TWRes $global:TW_S1 'rg-data' 'Microsoft.Storage/storageAccounts' ('stextra' + $n) ([ordered]@{ accessTier = 'Hot' }) -Kind 'BlockBlobStorage') }
    $global:TW.Arg['resources'] = $global:TW.Resources
    $global:TW.ChildRefuse = '/encryptionScopes$'
    $r = Invoke-TWRun -Params @{ Reports = @('ChildResources') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $es = (Import-TWCsv $r 'childResourceTypes.csv') | Where-Object Type -eq 'Microsoft.Storage/storageAccounts/encryptionScopes'
    Assert-Equal '3' $es.Calls; Assert-Equal '3' $es.Refused; Assert-Equal '0' $es.Answered
    Assert-Match $es.Note '^Not asked again after 3 calls without an answer: HTTP 403 AuthorizationFailed'
    Assert-Equal 3 @($global:TWRequests | Where-Object { $_.Uri -match '/encryptionScopes\?' }).Count
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Child resources (ARM)'
    Assert-Equal 'Partial' $cov.Status; Assert-Match $cov.Detail 'not fully read: storageAccounts/encryptionScopes \(childResourceTypes\.csv\)$'
    # a premium block blob account has no file shares, queues or tables: not asked for
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match '/stextra1/(fileServices|queueServices|tableServices)' }).Count
    Assert-Equal 1 @($global:TWRequests | Where-Object { $_.Uri -match '/stextra1/blobServices\?' }).Count
    # resource providers: one call per subscription, registered ones only, with the number of resources that use them
    $r = Invoke-TWRun -Params @{ Reports = @('ResourceProviders', 'Resources') }
    $p = Import-TWCsv $r 'resourceProviders.csv'
    Assert-Equal 2 @($global:TWRequests | Where-Object { $_.Uri -match '/subscriptions/[^/]+/providers\?api-version=2021-04-01' }).Count
    Assert-Equal 'Microsoft.Compute,Microsoft.Network' ((@($p | Where-Object SubscriptionName -eq 'Contoso Development') | ForEach-Object { $_.Namespace }) -join ',')
    Assert-Equal 5 @($p | Where-Object SubscriptionName -eq 'Contoso Production').Count 'not registered providers are left out'
    $st = $p | Where-Object { $_.SubscriptionName -eq 'Contoso Production' -and $_.Namespace -eq 'Microsoft.Storage' }
    Assert-Equal 'Registered' $st.RegistrationState; Assert-Equal '2' $st.ResourceTypes; Assert-Equal '2' $st.Resources
    Assert-Equal 'Registering' ($p | Where-Object Namespace -eq 'Microsoft.KeyVault').RegistrationState
    # one subscription refuses: the others are still listed
    Reset-TWState
    $global:TW.ProvidersDenied = @($global:TW_S1)
    $r = Invoke-TWRun -Params @{ Reports = @('ResourceProviders') } -KeepWorld
    Assert-Equal 2 @(Import-TWCsv $r 'resourceProviders.csv').Count
    Assert-Equal '' @(Import-TWCsv $r 'resourceProviders.csv')[0].Resources 'resources were not collected'
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Resource providers (ARM)'
    Assert-Equal 'Partial' $cov.Status; Assert-Match $cov.Detail '^Contoso Production: HTTP 403'
    foreach ($pr in @('Standard', 'Migration', 'Governance', 'Full')) { Assert-True ((Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = $pr })) -contains 'ResourceProviders') $pr }
    Assert-True ((Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Full' })) -contains 'ChildResources') 'in Full'
    Assert-False ((Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Standard' })) -contains 'ChildResources') 'not in Standard'
}

Test-Case 'secret values Azure returns inside properties are replaced in the CSV cell and the snapshot; the coverage says how many' {
    Reset-TWState
    $er = New-TWRes $global:TW_S1 'rg-network' 'Microsoft.Network/expressRouteCircuits' 'er-main' ([ordered]@{ serviceProviderProperties = [ordered]@{ serviceProviderName = 'Equinix'; bandwidthInMbps = 1000 }
            authorizations = @([ordered]@{ name = 'auth1'; properties = [ordered]@{ authorizationKey = 'ER-AUTH-KEY-123'; authorizationUseStatus = 'Available' } }); sharedKey = 'VPN-PSK-456'; passwordPolicy = 'none' })
    $global:TW.Resources = @($global:TW.Resources) + $er
    $global:TW.Arg['resources'] = $global:TW.Resources
    $r = Invoke-TWRun -Params @{ Reports = @('Resources', 'Snapshot') } -KeepWorld
    $cell = ((Import-TWCsv $r 'allResources.csv') | Where-Object Name -eq 'er-main').Properties
    Assert-Match $cell '"authorizationKey":"\(not exported\)","authorizationUseStatus":"Available"'; Assert-Match $cell '"sharedKey":"\(not exported\)"'
    Assert-Match $cell '"passwordPolicy":"none"' 'only the exact names'
    $file = [IO.File]::ReadAllText([IO.Path]::Combine($r.OutDir, 'snapshot', 'Contoso Production', 'rg-network', 'Microsoft.Network', 'expressRouteCircuits', 'er-main.json'))
    Assert-Match $file '"authorizationKey": "\(not exported\)"'; Assert-Equal 1000 ($file | ConvertFrom-Json).properties.serviceProviderProperties.bandwidthInMbps
    $leaks = @(Get-ChildItem -LiteralPath $r.OutDir -Recurse -File | Where-Object { $_.Extension -in '.csv', '.json', '.txt' } | Where-Object { [IO.File]::ReadAllText($_.FullName) -match 'ER-AUTH-KEY-123|VPN-PSK-456' })
    Assert-Equal 0 $leaks.Count (($leaks | ForEach-Object { $_.Name }) -join ', ')
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Secret values'
    Assert-Equal 'Info' $cov.Status; Assert-Match $cov.Detail '^2 value\(s\) of secret properties'
    # templates: an expression holds no value and stays; Bicep has its own notation; a second pass changes nothing
    $t = Protect-A2CSecretText '{"adminPassword":"[parameters(''p'')]","password":"abc","name":"x"}' -Template
    Assert-Equal '{"adminPassword":"[parameters(''p'')]","password":"(not exported)","name":"x"}' $t
    Assert-Equal $t (Protect-A2CSecretText $t -Template)
    Assert-Equal '{"adminPassword":"(not exported)"}' (Protect-A2CSecretText '{"adminPassword":"[parameters(''p'')]"}') 'outside a template every value is replaced'
    Assert-Equal "  authorizationKey: '(not exported)'`n  name: 'x'" (Protect-A2CSecretText "  authorizationKey: 'abc'`n  name: 'x'" -Bicep)
    Assert-Equal '{"n":"a \"quoted\" value"}' (Protect-A2CSecretText '{"n":"a \"quoted\" value"}')
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Governance and Entra additions' -ForegroundColor Cyan

Test-Case 'RBAC: eligible assignments (PIM), activated and time-bound assignments, deny assignments' {
    $r = Invoke-TWRun -Params @{ Reports = @('RBAC') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $e = @(Import-TWCsv $r 'RBAC_eligible_assignments.csv')
    Assert-Equal 1 $e.Count
    Assert-Equal 'Pat Partner' $e[0].DisplayName; Assert-Equal 'pat@fabrikam.com' $e[0].SignInName; Assert-Equal 'Owner' $e[0].RoleDefinitionName; Assert-Equal 'True' $e[0].IsPrivilegedRole
    Assert-Equal 'Subscription' $e[0].ScopeType; Assert-Equal 'False' $e[0].Inherited; Assert-Equal 'Contoso Production' $e[0].SubscriptionName; Assert-Match $e[0].EndDateTime '2026-12-31'
    $a = Import-TWCsv $r 'RBAC_role_assignments.csv'
    $act = $a | Where-Object { $_.RoleAssignmentId -like '*/ra-0003' }
    Assert-Equal 'Activated' $act.AssignmentType; Assert-Match $act.EndDateTime '2026-09-29'; Assert-Equal 'Direct' $act.MemberType
    $perm = $a | Where-Object { $_.RoleAssignmentId -like '*/ra-0001' }
    Assert-Equal 'Assigned' $perm.AssignmentType; Assert-Equal '' $perm.EndDateTime
    Assert-Equal 'Assigned' ($a | Where-Object { $_.RoleAssignmentId -like '*/ra-0002' }).AssignmentType 'no PIM instance: a permanent assignment'
    $d = @(Import-TWCsv $r 'RBAC_deny_assignments.csv')
    Assert-Equal 1 $d.Count; Assert-Equal 'Deny delete by managed application' $d[0].Name; Assert-Equal '*/delete' $d[0].Actions; Assert-Equal 'Microsoft.Storage/*/delete' $d[0].NotActions
    Assert-Equal 'ResourceGroup' $d[0].ScopeType; Assert-Equal 'True' $d[0].IsSystemProtected; Assert-Match $d[0].ExcludePrincipals ([regex]::Escape($global:TW.DirIds.SP1 + '(ServicePrincipal)'))
    # a tenant without PIM: one call per subscription, a note, the assignments stay as they were
    Reset-TWState
    $global:TW.PimEnabled = $false
    $r = Invoke-TWRun -Params @{ Reports = @('RBAC') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | '); Assert-Equal 0 @($r.Warnings | Where-Object { $_ -match 'PIM|onboarded' }).Count ($r.Warnings -join ' | ')
    Assert-Equal 2 @($global:TWRequests | Where-Object { $_.Uri -match 'ScheduleInstances' }).Count
    Assert-Equal 'Skipped' ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'PIM for Azure resources (ARM)').Status
    Assert-Equal '' ((Import-TWCsv $r 'RBAC_role_assignments.csv') | Where-Object { $_.RoleAssignmentId -like '*/ra-0001' }).AssignmentType
}

Test-Case 'management groups no subscription in scope is below: their role and policy assignments are read at the management group' {
    Reset-TWState
    $scope = '/providers/Microsoft.Management/managementGroups/mg-decom'
    $addMg = {
        $global:TW.Arg['managementGroups'] = @($global:TW.Arg['managementGroups']) + [ordered]@{ id = $scope; name = 'mg-decom'; tenantId = $global:TW_Tenant
            propertiesJson = '{"displayName":"Decommissioned","details":{"parent":{"id":"/providers/Microsoft.Management/managementGroups/mg-contoso","name":"mg-contoso"}}}' }
    }
    & $addMg
    $inherited = $global:TW.RoleAssignments[$global:TW_S1] | Where-Object { $_['name'] -eq 'ra-0005' }
    $global:TW.MgObjects['mg-decom'] = @{
        roleAssignments = @($inherited, [ordered]@{ id = $scope + '/providers/Microsoft.Authorization/roleAssignments/ra-mg01'; name = 'ra-mg01'
                properties = [ordered]@{ roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/' + $global:TW.RoleIds.Reader; principalId = $global:TW.DirIds.G1; principalType = 'Group'; scope = $scope } })
        policyAssignments = @([ordered]@{ id = $scope + '/providers/Microsoft.Authorization/policyAssignments/deny-all'; name = 'deny-all'
                properties = [ordered]@{ displayName = 'Deny everything'; scope = $scope; policyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/cccc23c7-8427-4f53-ad12-b6a63eb452b3'; enforcementMode = 'Default' } })
    }
    $r = Invoke-TWRun -Params @{ Reports = @('RBAC', 'Policy') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $ra = Import-TWCsv $r 'RBAC_role_assignments.csv'
    $mg = $ra | Where-Object { $_.RoleAssignmentId -like '*/ra-mg01' }
    Assert-Equal '' $mg.SubscriptionID; Assert-Equal 'ManagementGroup' $mg.ScopeType; Assert-Equal '' $mg.Inherited
    Assert-Equal 'Reader' $mg.RoleDefinitionName; Assert-Equal 'g-app-admins' $mg.DisplayName 'the principal is resolved like the others'
    Assert-Equal 2 @($ra | Where-Object { $_.RoleAssignmentId -like '*/ra-0005' }).Count 'what the subscriptions inherit is not listed again'
    $pa = (Import-TWCsv $r 'policyAssignments.csv') | Where-Object Name -eq 'deny-all'
    Assert-Equal '0' $pa.AppliesToSubscriptions; Assert-Equal 'ManagementGroup' $pa.ScopeType; Assert-True ([bool]$pa.DefinitionName) 'its definition was read'
    Assert-Equal 6 @($global:TWRequests | Where-Object { $_.Uri -match '/managementGroups/mg-decom/providers/Microsoft\.Authorization/' }).Count
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match '/managementGroups/mg-contoso/providers/Microsoft\.Authorization/(role|policy)Assignments\?' }).Count 'a management group with subscriptions needs no call'
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object { $_.Area -like 'Management groups without a subscription*' }
    Assert-Equal 'Collected' $cov.Status; Assert-Match $cov.Detail '^1 of 1 management groups read: 1 role assignments, 0 custom roles, 1 policy assignments'
    # no read access at the management group: a note
    Reset-TWState
    & $addMg
    $global:TW.MgDenied = @('mg-decom')
    $r = Invoke-TWRun -Params @{ Reports = @('RBAC') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    Assert-Equal 'Skipped' ((Import-TWCsv $r 'coverage.csv') | Where-Object { $_.Area -like 'Management groups without a subscription*' }).Status
}

Test-Case 'Defender for Cloud plans and Azure Lighthouse delegations (Resource Graph)' {
    $r = Invoke-TWRun -Params @{ Reports = @('Defender', 'Lighthouse', 'RBAC') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $d = Import-TWCsv $r 'defenderPlans.csv'
    Assert-Equal 4 @($d).Count
    $vm = $d | Where-Object { $_.SubscriptionName -eq 'Contoso Production' -and $_.Plan -eq 'VirtualMachines' }
    Assert-Equal 'Standard' $vm.Tier; Assert-Equal 'P2' $vm.SubPlan; Assert-Equal 'AgentlessVmScanning' $vm.Extensions 'only enabled extensions'
    Assert-Equal 'Free' ($d | Where-Object { $_.SubscriptionName -eq 'Contoso Development' }).Tier
    $l = @(Import-TWCsv $r 'lighthouse.csv')
    Assert-Equal 1 $l.Count
    Assert-Equal 'Contoso Development' $l[0].SubscriptionName; Assert-Equal 'ResourceGroup' $l[0].ScopeType; Assert-Equal 'Fabrikam Managed Services' $l[0].Offer
    Assert-Equal 'Fabrikam' $l[0].ManagedByTenantName; Assert-Equal 'Succeeded' $l[0].ProvisioningState
    Assert-Equal 'Fabrikam Operators (0b000000-0000-0000-0000-0000000000a1): Contributor' $l[0].Authorizations
    foreach ($pr in @('Quick', 'Standard', 'Security', 'Governance', 'Migration')) {
        $sel = Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = $pr })
        Assert-True (($sel -contains 'Defender') -and ($sel -contains 'Lighthouse')) $pr
    }
}

Test-Case 'Entra: group owners, administrative units, directory settings, custom directory roles' {
    $r = Invoke-TWRun -Params @{ Reports = @('EntraGroups', 'EntraTenant', 'EntraRoles') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $g = Import-TWCsv $r 'entraGroups.csv'
    $admins = $g | Where-Object DisplayName -eq 'g-app-admins'
    Assert-Equal 'alex.admin@contoso.onmicrosoft.com' $admins.Owners; Assert-Equal '1' $admins.OwnerCount
    Assert-Equal '0' ($g | Where-Object DisplayName -eq 'All Staff').OwnerCount
    $au = @(Import-TWCsv $r 'entraAdministrativeUnits.csv')
    Assert-Equal 1 $au.Count; Assert-Equal 'AU Vilnius' $au[0].DisplayName; Assert-Equal 'Dynamic' $au[0].MembershipType
    $s = Import-TWCsv $r 'entraSettings.csv'
    Assert-Equal 2 @($s).Count; Assert-Equal 'false' ($s | Where-Object Name -eq 'EnableGroupCreation').Value; Assert-Equal 'Group.Unified' @($s)[0].Setting
    $rd = @(Import-TWCsv $r 'entraRoleDefinitions.csv')
    Assert-Equal 1 $rd.Count 'custom roles only'
    Assert-Equal 'Helpdesk Lite' $rd[0].DisplayName; Assert-Equal 'microsoft.directory/users/password/update; microsoft.directory/users/basic/update' $rd[0].Permissions; Assert-Equal '0' $rd[0].Assignments
}

Test-Case 'Entra policies: refused for the sign-in of a user (a note, no warning); read when the sign-in has Policy.Read.All' {
    $r = Invoke-TWRun -Params @{ Reports = @('EntraPolicies') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | '); Assert-Equal 0 $r.Warnings.Count ($r.Warnings -join ' | ')
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object { $_.Area -like 'Entra policies*' }
    Assert-Equal 'Skipped' $cov.Status; Assert-Match $cov.Detail 'Policy\.Read\.All'
    Assert-Equal 0 @(Import-TWCsv $r 'entraConditionalAccess.csv').Count
    Reset-TWState
    $global:TW.PolicyReadAllowed = $true
    $r = Invoke-TWRun -Params @{ Reports = @('EntraPolicies', 'Snapshot') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $ca = @(Import-TWCsv $r 'entraConditionalAccess.csv')
    Assert-Equal 1 $ca.Count
    Assert-Equal 'Require MFA for admins' $ca[0].DisplayName; Assert-Equal 'enabled' $ca[0].State
    Assert-Equal '1 groups; 2 roles' $ca[0].IncludeUsers; Assert-Equal '1 users' $ca[0].ExcludeUsers
    Assert-Equal 'All' $ca[0].IncludeApplications; Assert-Equal 'Office365' $ca[0].ExcludeApplications
    Assert-Equal 'include: All; exclude: AllTrusted' $ca[0].Locations; Assert-Equal 'high, medium' $ca[0].SignInRisk
    Assert-Equal 'mfa OR compliantDevice' $ca[0].GrantControls; Assert-Equal 'signInFrequency' $ca[0].SessionControls
    $loc = Import-TWCsv $r 'entraNamedLocations.csv'
    Assert-Equal 2 @($loc).Count
    $ip = $loc | Where-Object DisplayName -eq 'Vilnius office'
    Assert-Equal 'IP ranges' $ip.Type; Assert-Equal '203.0.113.0/24' $ip.IpRanges; Assert-Equal 'True' $ip.IsTrusted
    Assert-Equal 'LT, LV, EE' ($loc | Where-Object DisplayName -eq 'Baltics').Countries
    $set = Import-TWCsv $r 'entraPolicySettings.csv'
    $v = { param($p, $s) ($set | Where-Object { $_.Policy -eq $p -and $_.Setting -eq $s }).Value }
    Assert-Equal 'adminsAndGuestInviters' (& $v 'Authorization policy' 'allowInvitesFrom')
    Assert-Equal 'False' (& $v 'Authorization policy' 'defaultUserRolePermissions.allowedToCreateApps')
    Assert-Equal 'ManagePermissionGrantsForSelf.microsoft-user-default-low' (& $v 'Authorization policy' 'defaultUserRolePermissions.permissionGrantPoliciesAssigned')
    Assert-Equal 'False' (& $v 'Security defaults' 'isEnabled')
    Assert-Equal 'fido2, windowsHelloForBusiness' (& $v 'Authentication strength' 'allowedCombinations') 'custom strengths only'
    Assert-Equal 0 @($set | Where-Object Name -eq 'Multifactor authentication').Count
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object { $_.Area -like 'Entra policies*' }
    Assert-Equal 'Partial' $cov.Status; Assert-Match $cov.Detail 'not readable: Authentication methods policy \(HTTP 403'
    Assert-True (Test-Path -LiteralPath ([IO.Path]::Combine($r.OutDir, 'snapshot', '_entra', 'identity', 'conditionalAccess', 'policies', 'Require MFA for admins ca000000-0000-0000-0000-000000000001.json'))) 'the complete policy is in the snapshot'
    foreach ($pr in @('Standard', 'Security')) { Assert-True ((Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = $pr })) -contains 'EntraPolicies') $pr }
}

Test-Case 'EntraAppAssignments: who is assigned to enterprise applications; application permissions of every API an app registration names' {
    $r = Invoke-TWRun -Params @{ Reports = @('EntraAppAssignments') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $a = Import-TWCsv $r 'entraAppAssignments.csv'
    Assert-Equal 3 @($a).Count
    Assert-Equal 'Default access' ($a | Where-Object PrincipalName -eq 'Alex Admin').AppRole
    $grp = $a | Where-Object PrincipalName -eq 'g-app-admins'
    Assert-Equal 'Orders administrator' $grp.AppRole; Assert-Equal 'Group' $grp.PrincipalType; Assert-Equal 'Contoso Web App' $grp.Application
    Assert-Equal 2 @($global:TWRequests | Where-Object { $_.Uri -match '/appRoleAssignedTo' }).Count 'the applications of the tenant; not Microsoft Graph, not managed identities'
    Assert-True ((Resolve-A2CSelection (New-A2COptions -Params @{ ReportProfile = 'Full' })) -contains 'EntraAppAssignments') 'in Full'
    Assert-False ((Resolve-A2CSelection (New-A2COptions -Params @{ Reports = @('Entra') })) -contains 'EntraAppAssignments') 'the group leaves the slow report out'
    # an app registration asks for an app role of another API of the tenant: that API is read as well
    Reset-TWState
    $global:TW.Apps[1]['requiredResourceAccess'] = @([ordered]@{ resourceAppId = 'aa000000-0000-0000-0000-000000000001'; resourceAccess = @([ordered]@{ id = 'ad000000-0000-0000-0000-000000000001'; type = 'Role' }) })
    $r = Invoke-TWRun -Params @{ Reports = @('EntraApps') } -KeepWorld
    $p = @((Import-TWCsv $r 'appPermissions.csv') | Where-Object ResourceName -eq 'Contoso Web App')
    Assert-Equal 1 $p.Count 'the application permission; users and groups assigned to the app are no API permission'
    Assert-Equal 'sp-monitoring' $p[0].ClientName; Assert-Equal 'Orders.Admin' $p[0].Permission; Assert-Equal 'Application' $p[0].PermissionType
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Typed reports from the table' -ForegroundColor Cyan

Test-Case 'the path walker and the column notation of the typed reports' {
    $o = '{"a":{"b":[{"id":"/x/y/one","n":1,"on":false},{"id":"/x/y/two","n":2,"c":{"d":"deep"}}],"s":"text"},"k":{"p":1,"q":null,"r":[]}}' | ConvertFrom-Json
    Assert-Equal '/x/y/one,/x/y/two' ((Get-A2CPathValues $o 'a.b.id') -join ',') 'lists on the way are walked through'
    Assert-Equal 'deep' ((Get-A2CPathValues $o 'a.b.c.d') -join ',')
    Assert-Equal 0 (Get-A2CPathValues $o 'a.missing.x').Count; Assert-Equal 0 (Get-A2CPathValues $null 'a').Count; Assert-Equal 0 (Get-A2CPathValues $o 'a.s.length').Count
    $v = { param($t) Get-A2CSpecValue (ConvertTo-A2CSpecColumn $t) $o $o.a $null $null }
    Assert-Equal 'one; two' (& $v 'X=b.id|name'); Assert-Equal 2 (& $v 'X:num=b|count'); Assert-Equal '1; 2' (& $v 'X=b.n'); Assert-Equal 'text' (& $v 'X=s')
    Assert-Equal $false (& $v 'X=b.on') 'a single false is a value, not empty'; Assert-Equal '' (& $v 'X=nothing'); Assert-Equal $true (& $v 'X=b.c|any')
    Assert-Equal 'p' (& $v 'X=@k|keys') 'the members that hold something'; Assert-Equal '{"d":"deep"}' (& $v 'X=b.c|json')
    $c = ConvertTo-A2CSpecColumn 'Subnet:id=^@sku.name|name'
    Assert-Equal 'Subnet' $c.Name; Assert-Equal 'id' $c.Kind; Assert-Equal '^@' $c.Scope; Assert-Equal 'sku.name' $c.Path; Assert-Equal 'name' $c.How
    foreach ($s in $script:A2CSpecReports) { Assert-True ($script:A2CSchemas.ContainsKey($s.File)) $s.File }
    foreach ($n in @($script:A2CSpecReports | ForEach-Object { $_.Report } | Sort-Object -Unique)) { Assert-True (@($script:A2CReportCatalog | Where-Object { $_.Name -eq $n }).Count -eq 1) ('report ' + $n) }
}

Test-Case 'typed reports: load balancers with frontends, rules and probes; databases, messaging, monitoring; no file without rows' {
    Reset-TWState
    $S = $global:TW_S1
    $lbId = New-TWId -Sub $S -Rg 'rg-network' -Type 'Microsoft.Network/loadBalancers' -Name 'lb-web'
    $snet = $global:TW.Ids.VnetHub + '/subnets/snet-app'
    $lb = New-TWRes $S 'rg-network' 'Microsoft.Network/loadBalancers' 'lb-web' ([ordered]@{
            frontendIPConfigurations = @(
                [ordered]@{ id = $lbId + '/frontendIPConfigurations/fe-int'; name = 'fe-int'; zones = @('1', '2'); properties = [ordered]@{ privateIPAddress = '10.0.1.50'; privateIPAllocationMethod = 'Static'; subnet = [ordered]@{ id = $snet }
                        loadBalancingRules = @([ordered]@{ id = $lbId + '/loadBalancingRules/https' }) } }
                [ordered]@{ id = $lbId + '/frontendIPConfigurations/fe-pub'; name = 'fe-pub'; properties = [ordered]@{ publicIPAddress = [ordered]@{ id = $global:TW.Ids.PipApp } } })
            backendAddressPools = @([ordered]@{ id = $lbId + '/backendAddressPools/web'; name = 'web'; properties = [ordered]@{} })
            loadBalancingRules = @([ordered]@{ id = $lbId + '/loadBalancingRules/https'; name = 'https'; properties = [ordered]@{ protocol = 'Tcp'; frontendPort = 443; backendPort = 8443; idleTimeoutInMinutes = 4
                        enableFloatingIP = $false; enableTcpReset = $true; loadDistribution = 'Default'; frontendIPConfiguration = [ordered]@{ id = $lbId + '/frontendIPConfigurations/fe-int' }
                        backendAddressPool = [ordered]@{ id = $lbId + '/backendAddressPools/web' }; probe = [ordered]@{ id = $lbId + '/probes/hp' } } })
            probes = @([ordered]@{ id = $lbId + '/probes/hp'; name = 'hp'; properties = [ordered]@{ protocol = 'Https'; port = 8443; requestPath = '/health'; intervalInSeconds = 5; numberOfProbes = 2 } })
            inboundNatRules = @(); outboundRules = @() }) -Sku ([ordered]@{ name = 'Standard'; tier = 'Regional' })
    $cosmos = New-TWRes $S 'rg-data' 'Microsoft.DocumentDB/databaseAccounts' 'cosmos-contoso' ([ordered]@{ databaseAccountOfferType = 'Standard'; consistencyPolicy = [ordered]@{ defaultConsistencyLevel = 'Session' }
            locations = @([ordered]@{ locationName = 'West Europe'; isZoneRedundant = $true }, [ordered]@{ locationName = 'North Europe'; isZoneRedundant = $false }); writeLocations = @([ordered]@{ locationName = 'West Europe' })
            capabilities = @([ordered]@{ name = 'EnableServerless' }); enableAutomaticFailover = $true; publicNetworkAccess = 'Disabled'; ipRules = @([ordered]@{ ipAddressOrRange = '203.0.113.5' })
            backupPolicy = [ordered]@{ type = 'Continuous'; continuousModeProperties = [ordered]@{ tier = 'Continuous7Days' } }; disableLocalAuth = $true }) -Kind 'GlobalDocumentDB'
    $pg = New-TWRes $S 'rg-data' 'Microsoft.DBforPostgreSQL/flexibleServers' 'pg-contoso' ([ordered]@{ version = '16'; storage = [ordered]@{ storageSizeGB = 128; autoGrow = 'Enabled' }
            highAvailability = [ordered]@{ mode = 'ZoneRedundant'; standbyAvailabilityZone = '2' }; availabilityZone = '1'; backup = [ordered]@{ backupRetentionDays = 14; geoRedundantBackup = 'Disabled' }
            network = [ordered]@{ publicNetworkAccess = 'Disabled'; delegatedSubnetResourceId = $global:TW.Ids.VnetHub + '/subnets/snet-data' }; authConfig = [ordered]@{ activeDirectoryAuth = 'Enabled'; passwordAuth = 'Disabled' }
            fullyQualifiedDomainName = 'pg-contoso.postgres.database.azure.com'; state = 'Ready' }) -Sku ([ordered]@{ name = 'Standard_D4ds_v5'; tier = 'GeneralPurpose' })
    $sb = New-TWRes $S 'rg-app' 'Microsoft.ServiceBus/namespaces' 'sb-contoso' ([ordered]@{ zoneRedundant = $true; minimumTlsVersion = '1.2'; disableLocalAuth = $false; status = 'Active' }) -Sku ([ordered]@{ name = 'Premium'; capacity = 2 })
    $global:TW.Resources = @($global:TW.Resources) + $lb + $cosmos + $pg + $sb
    $global:TW.Arg['resources'] = $global:TW.Resources
    $r = Invoke-TWRun -Params @{ Reports = @('LoadBalancers', 'Databases', 'Messaging', 'Monitoring', 'AppGateways', 'Gateways', 'NetworkInterfaces') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $l = (Import-TWCsv $r 'loadBalancers.csv') | Where-Object Name -eq 'lb-web'
    Assert-Equal 'Standard' $l.Sku; Assert-Equal '2' $l.Frontends; Assert-Equal '10.0.1.50' $l.PrivateIPs; Assert-Equal 'pip-app01' $l.PublicIPs; Assert-Equal $snet $l.Subnets
    Assert-Equal 'web' $l.BackendPools; Assert-Equal '1' $l.Rules; Assert-Equal 'hp' $l.Probes; Assert-Equal '1; 2' $l.Zones; Assert-Equal 'rg-network' $l.ResourceGroup; Assert-Equal 'westeurope' $l.Location
    Assert-Equal '0' ((Import-TWCsv $r 'loadBalancers.csv') | Where-Object Name -eq 'lb-basic').Frontends
    $fe = Import-TWCsv $r 'loadBalancerFrontends.csv'
    Assert-Equal 2 @($fe).Count
    $int = $fe | Where-Object Name -eq 'fe-int'
    Assert-Equal 'lb-web' $int.LoadBalancer; Assert-Equal '10.0.1.50' $int.PrivateIP; Assert-Equal $snet $int.Subnet; Assert-Equal '1; 2' $int.Zones; Assert-Equal 'https' $int.Rules
    Assert-Equal 'Standard' $int.Sku 'a value of the parent resource'; Assert-Equal ($lbId + '/frontendIPConfigurations/fe-int') $int.Id
    Assert-Equal $global:TW.Ids.PipApp ($fe | Where-Object Name -eq 'fe-pub').PublicIP
    $rule = @(Import-TWCsv $r 'loadBalancerRules.csv')[0]
    Assert-Equal 'https' $rule.Name; Assert-Equal 'Tcp' $rule.Protocol; Assert-Equal '443' $rule.FrontendPort; Assert-Equal '8443' $rule.BackendPort; Assert-Equal 'fe-int' $rule.Frontend
    Assert-Equal 'web' $rule.BackendPool; Assert-Equal 'hp' $rule.Probe; Assert-Equal 'True' $rule.TcpReset; Assert-Equal 'False' $rule.FloatingIP
    $probe = @(Import-TWCsv $r 'loadBalancerProbes.csv')[0]
    Assert-Equal 'Https' $probe.Protocol; Assert-Equal '8443' $probe.Port; Assert-Equal '/health' $probe.RequestPath
    $c = @(Import-TWCsv $r 'cosmosDbAccounts.csv')[0]
    Assert-Equal 'GlobalDocumentDB' $c.Kind; Assert-Equal 'EnableServerless' $c.Capabilities; Assert-Equal 'Session' $c.Consistency; Assert-Equal 'West Europe; North Europe' $c.Locations
    Assert-Equal 'True; False' $c.ZoneRedundantLocations; Assert-Equal 'Continuous7Days' $c.BackupTier; Assert-Equal '203.0.113.5' $c.IpRules; Assert-Equal 'True' $c.DisableLocalAuth
    $p = @(Import-TWCsv $r 'postgresFlexibleServers.csv')[0]
    Assert-Equal '16' $p.Version; Assert-Equal 'Standard_D4ds_v5' $p.Sku; Assert-Equal '128' $p.StorageGB; Assert-Equal 'ZoneRedundant' $p.HighAvailability; Assert-Equal 'Enabled' $p.EntraAuth
    Assert-Match $p.DelegatedSubnet '/subnets/snet-data$'
    $s = @(Import-TWCsv $r 'serviceBusNamespaces.csv')[0]
    Assert-Equal 'Premium' $s.Sku; Assert-Equal '2' $s.Capacity; Assert-Equal 'True' $s.ZoneRedundant
    Assert-Equal '30' ((Import-TWCsv $r 'logAnalyticsWorkspaces.csv') | Where-Object Name -eq 'law-contoso').RetentionDays
    $alert = (Import-TWCsv $r 'alertRules.csv') | Where-Object Name -eq 'alert-errors'
    Assert-Equal 'Log search alert' $alert.Kind; Assert-Equal '2' $alert.Severity; Assert-Equal 'True' $alert.Enabled; Assert-Match $alert.Criteria 'AppExceptions'
    $agw = (Import-TWCsv $r 'applicationGateways.csv') | Where-Object Name -eq 'agw-v1'
    Assert-Equal 'Standard_Medium' $agw.Sku; Assert-Equal '2' $agw.Capacity
    $ng = (Import-TWCsv $r 'natGateways.csv') | Where-Object Name -eq 'ng-unused'
    Assert-Equal 'Standard' $ng.Sku; Assert-Equal '4' $ng.IdleTimeoutMinutes
    $nic = (Import-TWCsv $r 'networkInterfaces.csv') | Where-Object Name -eq 'nic-app01'
    Assert-Equal $global:TW.Ids.VmApp $nic.VirtualMachine; Assert-Equal '10.0.1.4' $nic.PrivateIPs; Assert-Equal $snet $nic.Subnets; Assert-Equal $global:TW.Ids.PipApp $nic.PublicIPs
    Assert-Match $nic.Asgs '/applicationSecurityGroups/asg-web$'; Assert-Equal '1.1.1.1' $nic.DnsServers
    foreach ($f in @('expressRouteCircuits.csv', 'virtualHubs.csv', 'eventHubNamespaces.csv', 'mysqlFlexibleServers.csv', 'applicationGatewayListeners.csv')) {
        Assert-False (Test-Path -LiteralPath ([IO.Path]::Combine($r.OutDir, $f))) ($f + ': nothing to list, no file')
    }
}

Test-Case 'firewall rules and DNS records from the other Resource Graph tables; child resources as files of their own' {
    $r = Invoke-TWRun -Params @{ Reports = @('Firewalls', 'DnsRecords', 'ChildResources') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $fw = @(Import-TWCsv $r 'firewallRules.csv')
    Assert-Equal 1 $fw.Count
    Assert-Equal 'fwpol-hub' $fw[0].FirewallPolicy; Assert-Equal 'DefaultNetworkRuleCollectionGroup' $fw[0].RuleCollectionGroup; Assert-Equal '200' $fw[0].GroupPriority
    Assert-Equal 'allow-dns' $fw[0].RuleCollection; Assert-Equal '100' $fw[0].CollectionPriority; Assert-Equal 'Filter' $fw[0].CollectionType; Assert-Equal 'Allow' $fw[0].Action
    Assert-Equal 'dns-out' $fw[0].Rule; Assert-Equal 'NetworkRule' $fw[0].RuleType; Assert-Equal 'UDP, TCP' $fw[0].Protocols; Assert-Equal '10.0.0.0/16' $fw[0].SourceAddresses
    Assert-Equal '168.63.129.16' $fw[0].DestinationAddresses; Assert-Equal '53' $fw[0].DestinationPorts
    $dns = Import-TWCsv $r 'dnsRecords.csv'
    Assert-Equal 2 @($dns).Count
    $a = $dns | Where-Object RecordType -eq 'A'
    Assert-Equal 'Private' $a.ZoneType; Assert-Equal 'privatelink.blob.core.windows.net' $a.Zone; Assert-Equal 'stcontosodata' $a.Name; Assert-Equal '10' $a.Ttl; Assert-Equal '10.0.2.5' $a.Records
    Assert-Equal 'stcontosodata.privatelink.blob.core.windows.net' $a.Fqdn; Assert-Equal 'False' $a.AutoRegistered
    Assert-Equal 'azureprivatedns.net azureprivatedns-host.microsoft.com' ($dns | Where-Object RecordType -eq 'SOA').Records
    $sc = Import-TWCsv $r 'storageContainers.csv'
    Assert-Equal 3 @($sc).Count; Assert-Equal 'stcontosodata' @($sc)[0].StorageAccount; Assert-Equal 'Blob' ($sc | Where-Object Name -eq 'public-assets').PublicAccess
    Assert-Equal '100' @(Import-TWCsv $r 'storageFileShares.csv')[0].QuotaGB
    $rule = (Import-TWCsv $r 'sqlFirewallRules.csv') | Where-Object Name -eq 'office'
    Assert-Equal 'sql-contoso' $rule.SqlServer; Assert-Equal '203.0.113.10' $rule.StartIpAddress; Assert-Equal '203.0.113.20' $rule.EndIpAddress
    $kv = @(Import-TWCsv $r 'keyVaultObjects.csv')
    Assert-Equal 1 $kv.Count
    Assert-Equal 'Microsoft.KeyVault/vaults/secrets' $kv[0].Type; Assert-Equal 'sql-admin-login' $kv[0].Name; Assert-Equal 'True' $kv[0].Enabled; Assert-Equal '1798761600' $kv[0].Expires; Assert-Equal 'kv-contoso' $kv[0].KeyVault
}

Test-Case 'columns added for rebuilding: resource IDs next to names, private endpoint records, one row per private DNS link, VM and app detail' {
    $r = Invoke-TWRun -Params @{ Reports = @('VirtualNetworks', 'PrivateEndpoints', 'PrivateDNS', 'VMs', 'AppService', 'NetworkSecurity', 'Resources') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $sn = (Import-TWCsv $r 'subnets.csv') | Where-Object Subnet -eq 'snet-app'
    Assert-Equal $global:TW.Ids.NsgApp $sn.NsgId; Assert-Match $sn.RouteTableId '/resourceGroups/rg-network/providers/Microsoft\.Network/routeTables/rt-app$'; Assert-Equal '' $sn.NatGatewayId
    $pe = @(Import-TWCsv $r 'privateEndpoints.csv')[0]
    Assert-Match $pe.SubnetId '/virtualNetworks/vnet-hub/subnets/snet-app$'; Assert-Equal $global:TW.Ids.StData $pe.TargetResourceIds
    Assert-Equal 'stcontosodata.blob.core.windows.net:10.0.1.10' $pe.DnsRecords; Assert-Equal 'False' $pe.ManualApproval
    $link = @(Import-TWCsv $r 'privateDnsLinks.csv')
    Assert-Equal 1 $link.Count
    Assert-Equal 'privatelink.blob.core.windows.net' $link[0].Zone; Assert-Equal 'link-hub' $link[0].Link; Assert-Equal 'vnet-hub' $link[0].VNet; Assert-Equal $global:TW.Ids.VnetHub $link[0].VNetId
    Assert-Equal 'True' $link[0].VNetInScope; Assert-Equal 'False' $link[0].RegistrationEnabled; Assert-Equal 'Completed' $link[0].State
    $vm = (Import-TWCsv $r 'vms.csv') | Where-Object Name -eq 'vm-app01'
    Assert-Equal 'LUN 0: vm-app01_data0, 512 GB, caching None' $vm.DataDiskLayout; Assert-Equal $global:TW.Ids.NicApp $vm.NicIds
    $app = (Import-TWCsv $r 'appServiceApps.csv') | Where-Object Name -eq 'app-contoso'
    Assert-Match $app.PlanId '/serverFarms/asp-web$'; Assert-Match $app.VNetIntegrationSubnetId '/subnets/snet-integration$'
    Assert-Equal $global:TW.Ids.NsgApp ((Import-TWCsv $r 'nsgRules.csv') | Where-Object Rule -eq 'Allow-HTTPS').NsgId
    $res = (Import-TWCsv $r 'allResources.csv') | Where-Object Name -eq 'vm-app01'
    Assert-Equal $global:TW.Ids.Uai $res.UserAssignedIdentityIds; Assert-Equal '2024-05-01' $res.ApiVersion
}

Test-Case 'earlier gaps closed: slot configuration, custom roles below subscription scope, role assignment and diagnostic setting detail' {
    Reset-TWState
    $S = $global:TW_S1
    # a deployment slot: its configuration is a row of its own in Resource Graph (sites/slots/config)
    $slot = New-TWRes $S 'rg-app' 'Microsoft.Web/sites/slots' 'app-contoso/staging' ([ordered]@{ serverFarmId = (New-TWId -Sub $S -Rg 'rg-app' -Type 'Microsoft.Web/serverFarms' -Name 'asp-web'); state = 'Running' }) -Kind 'app,linux'
    $global:TW.Resources = @($global:TW.Resources) + $slot
    $global:TW.Arg['resources'] = $global:TW.Resources
    $global:TW.Arg['appServiceConfig'] = @($global:TW.Arg['appServiceConfig']) + [ordered]@{ id = $slot['id'] + '/config/web'; subscriptionId = $S
        propertiesJson = '{"LinuxFxVersion":"NODE|20-lts","MinTlsVersion":"1.3","FtpsState":"Disabled","AlwaysOn":true}' }
    # a role assignment given through Lighthouse with a condition
    $ra = $global:TW.RoleAssignments[$S] | Where-Object { $_['name'] -eq 'ra-0006' }
    $ra['properties']['delegatedManagedIdentityResourceId'] = $global:TW.Ids.Uai
    $ra['properties']['condition'] = "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'backups'"
    $ra['properties']['conditionVersion'] = '2.0'
    $r = Invoke-TWRun -Params @{ Reports = @('AppService', 'RBAC', 'DiagnosticSettings', 'Policy') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $st = (Import-TWCsv $r 'appServiceApps.csv') | Where-Object { $_.Id -like '*/slots/staging' }
    Assert-Equal 'NODE|20-lts' $st.Runtime; Assert-Equal '1.3' $st.MinTlsVersion; Assert-Equal 'Disabled' $st.FtpsState
    Assert-Match ($global:TWRequests | Where-Object { $_.Body -match 'a2c:appServiceConfig' } | Select-Object -First 1).Body 'microsoft\.web/sites/slots/config'
    Assert-True (@($global:TWRequests | Where-Object { $_.Uri -match '/roleDefinitions\?.*atScopeAndBelow' }).Count -ge 2) 'custom roles that are assignable only below the subscription'
    $row = (Import-TWCsv $r 'RBAC_role_assignments.csv') | Where-Object { $_.RoleAssignmentId -like '*/ra-0006' }
    Assert-Equal $global:TW.Ids.Uai $row.DelegatedManagedIdentity; Assert-Equal '2.0' $row.ConditionVersion; Assert-Match $row.Condition 'StringEquals'
    $diag = (Import-TWCsv $r 'diagnosticSettings.csv') | Where-Object { $_.PSObject.Properties.Value -contains 'blob-logs' }
    Assert-Equal 'allLogs' $diag.LogCategoryGroups 'category groups have a column of their own'
    $pa = @(Import-TWCsv $r 'policyAssignments.csv')
    Assert-True ($pa[0].PSObject.Properties.Name -contains 'DefinitionId' -and $pa[0].PSObject.Properties.Name -contains 'DefinitionVersion' -and $pa[0].PSObject.Properties.Name -contains 'ResourceSelectors') 'policy assignment columns'
    Assert-Equal 0 @($pa | Where-Object { -not $_.DefinitionId }).Count 'every assignment names its definition by ID'
    Assert-True (@(Import-TWCsv $r 'policyExemptions.csv')[0].PSObject.Properties.Name -contains 'AssignmentScopeValidation')
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Entra ID' -ForegroundColor Cyan

$run5 = Invoke-TWRun -Params @{ Reports = @('Entra', 'EntraGroupMembers', 'RBAC') }

Test-Case 'Entra run completes; blocked sign-in activity falls back with a coverage note' {
    Assert-Equal 0 $run5.Errors.Count ($run5.Errors -join ' | ')
    $cov = Import-TWCsv $run5 'coverage.csv'
    $u = $cov | Where-Object Area -eq 'Entra users'
    Assert-Equal 'Partial' $u.Status
    Assert-Match $u.Detail 'AuditLog\.Read\.All'
    $users = Import-TWCsv $run5 'entraUsers.csv'
    Assert-Equal 5 @($users).Count 'Graph paging (3 per page)'
    Assert-Equal 'False' $users[0].SignInDataAvailable
    Assert-True (@($users | Where-Object DisplayName -ceq $global:TW_Lt).Count -eq 1) 'non-ASCII display name'
    $alex = $users | Where-Object UserPrincipalName -eq 'alex.admin@contoso.onmicrosoft.com'
    Assert-Equal 'True' $alex.HasDirectoryRole
    Assert-Equal 'True' $alex.HasAzureRBAC
    Assert-Equal 'PendingAcceptance' ($users | Where-Object UserType -eq 'Guest').ExternalUserState
}

Test-Case 'sign-in activity when permitted: days since last sign-in' {
    Reset-TWState
    $global:TW.SignInAllowed = $true
    $r = Invoke-TWRun -Params @{ Reports = @('EntraUsers') } -KeepWorld
    $users = Import-TWCsv $r 'entraUsers.csv'
    Assert-Equal 'True' $users[0].SignInDataAvailable
    Assert-Equal '0' ($users | Where-Object UserPrincipalName -eq 'alex.admin@contoso.onmicrosoft.com').DaysSinceLastSignIn
    Assert-Equal '635' ($users | Where-Object UserPrincipalName -eq 'former@contoso.com').DaysSinceLastSignIn
}

Test-Case 'tenant, domains and licenses' {
    $t = Import-TWCsv $run5 'entraTenant.csv'
    Assert-Equal 'contoso.com' $t[0].DefaultDomain
    Assert-Equal 'contoso.onmicrosoft.com' $t[0].InitialDomain
    Assert-Equal 'Federated' ((Import-TWCsv $run5 'entraDomains.csv') | Where-Object Domain -eq 'contoso.com').AuthenticationType
    Assert-Equal '13' ((Import-TWCsv $run5 'entraLicenses.csv') | Where-Object SkuPartNumber -eq 'ENTERPRISEPACK').Available
}

Test-Case 'groups (types, dynamic, role-assignable, RBAC use) and members incl. service principals' {
    $g = Import-TWCsv $run5 'entraGroups.csv'
    Assert-Equal 'Microsoft 365' ($g | Where-Object DisplayName -eq 'All Staff').GroupType
    Assert-Equal 'True' ($g | Where-Object DisplayName -eq 'Dynamic Devs').Dynamic
    Assert-Equal 'True' ($g | Where-Object DisplayName -eq 'Tier0 Admins').RoleAssignable
    $admins = $g | Where-Object DisplayName -eq 'g-app-admins'
    Assert-Equal 'True' $admins.UsedInAzureRBAC
    Assert-Equal '2' $admins.Members
    $m = Import-TWCsv $run5 'entraGroupMembers.csv'
    Assert-True (@($m | Where-Object MemberType -eq 'servicePrincipal').Count -eq 1) 'SP member (beta endpoint)'
}

Test-Case 'app registrations and credential expiry' {
    $a = Import-TWCsv $run5 'entraApplications.csv'
    $web = $a | Where-Object DisplayName -eq 'Contoso Web App'
    Assert-Equal 'Expires within 30 days' $web.CredentialStatus
    Assert-Equal '2026-10-09T00:00:00Z' $web.NextCredentialExpiry
    Assert-Equal '1' $web.OwnerCount
    Assert-Equal '2' $web.RequiredApiPermissions
    $leg = $a | Where-Object DisplayName -eq 'Legacy Integration'
    Assert-Equal 'True' $leg.MultiTenant
    Assert-Equal '0' $leg.OwnerCount
    $c = Import-TWCsv $run5 'credentials.csv'
    Assert-Equal 'Expired' ($c | Where-Object CredentialName -eq 'CN=old-cert').Status
    $s = $c | Where-Object CredentialName -eq 'prod-secret'
    Assert-Equal '10' $s.DaysToExpiry
    Assert-Equal '1096' ($c | Where-Object CredentialName -eq 'forever').LifetimeDays
    Assert-Equal 'Expired' $c[0].Status 'sorted by expiry'
}

Test-Case 'service principals, managed identities and API permissions with risk' {
    $sp = Import-TWCsv $run5 'entraServicePrincipals.csv'
    Assert-Equal 3 @($sp).Count 'managed identities must be listed separately'
    $web = $sp | Where-Object DisplayName -eq 'Contoso Web App'
    Assert-Equal 'This tenant' $web.Publisher
    Assert-Equal '2' $web.HighRiskPermissions
    $mon = $sp | Where-Object DisplayName -eq 'sp-monitoring'
    Assert-Equal 'Third party' $mon.Publisher
    Assert-Equal 'True' $mon.HasAzureRBAC
    Assert-Equal 'Microsoft' ($sp | Where-Object DisplayName -eq 'Microsoft Graph').Publisher
    $mi = Import-TWCsv $run5 'managedIdentities.csv'
    Assert-Equal 'Unknown (resources not collected)' ($mi | Where-Object DisplayName -eq 'vm-app01').ResourceExists
    Assert-Equal 'User-assigned' ($mi | Where-Object DisplayName -eq 'uai-app').Kind
    Assert-Equal '1' ($mi | Where-Object DisplayName -eq 'vm-app01').RoleAssignments
    $p = Import-TWCsv $run5 'appPermissions.csv'
    Assert-Equal 'Critical' ($p | Where-Object { $_.Permission -eq 'Directory.ReadWrite.All' }).Risk
    Assert-Equal 'Application' ($p | Where-Object { $_.Permission -eq 'Directory.ReadWrite.All' }).PermissionType
    $mail = $p | Where-Object Permission -eq 'Mail.ReadWrite'
    Assert-Equal 'Admin consent (all users)' $mail.ConsentType
    Assert-Equal 'former@contoso.com' ($p | Where-Object Permission -eq 'Files.Read.All').GrantedTo
    Assert-Equal 6 @($p).Count
}

Test-Case 'directory roles: privileged and guest admins' {
    $d = Import-TWCsv $run5 'directoryRoles.csv'
    Assert-Equal 3 @($d).Count
    $g = $d | Where-Object { $_.RoleName -eq 'Global Administrator' -and $_.IsGuest -eq 'True' }
    Assert-Equal 'Pat Partner' $g.PrincipalName
    Assert-Equal 'True' $g.IsPrivilegedRole
    Assert-Equal 'False' ($d | Where-Object RoleName -eq 'Security Reader').IsPrivilegedRole
}

Test-Case 'managed identity of a deleted resource is detected when resources are collected' {
    $r = Invoke-TWRun -Params @{ Reports = @('EntraApps', 'Resources') }
    $mi = Import-TWCsv $r 'managedIdentities.csv'
    Assert-Equal 'Yes' ($mi | Where-Object DisplayName -eq 'vm-app01').ResourceExists
    Assert-Equal 'No (resource deleted?)' ($mi | Where-Object DisplayName -eq 'vm-deleted').ResourceExists
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Azure DevOps' -ForegroundColor Cyan

Test-Case '-AdoOrganization accepts names and URLs (case-insensitive, no duplicates)' {
    $o = New-A2COptions -Params @{ AdoOrganization = @('https://dev.azure.com/One/', 'two, https://three.visualstudio.com/x', 'ONE') }
    Assert-Equal 'One,two,three' ($o.AdoOrganization -join ',')
}

$run8 = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'EntraApps', 'RBAC', 'TenantTransfer'); AdoOrganization = @('https://dev.azure.com/named-org', 'contoso-ado', 'public-org') }

Test-Case 'Azure DevOps: organizations from Azure billing and -AdoOrganization; no access is a note, not an error' {
    Assert-Equal 0 $run8.Errors.Count ($run8.Errors -join ' | ')
    $o = Import-TWCsv $run8 'ADO/organizations.csv'
    Assert-Equal 'contoso-ado,fabrikam-old,contoso-sandbox,named-org,public-org,contoso-archive' (($o | ForEach-Object { $_.Organization }) -join ',')
    $c = $o | Where-Object Organization -eq 'contoso-ado'
    Assert-Equal 'Collected' $c.Status
    Assert-Equal 'Azure billing' $c.Source
    Assert-Equal 'rg-app' $c.BillingResourceGroup
    Assert-Equal 'a0a0a0a0-0000-0000-0000-000000000001' $c.OrganizationId
    Assert-Equal 'alex.admin@contoso.onmicrosoft.com' $c.Owner
    $sb = $o | Where-Object Organization -eq 'contoso-sandbox'
    Assert-Equal 'Azure billing' $sb.Source 'billing resource named after the organization ID resolved to its name'
    Assert-Equal 'No access' $sb.Status
    Assert-Match $sb.Detail '^HTTP 401 UnauthorizedRequestException: TF400813'
    $arch = $o | Where-Object Organization -eq 'contoso-archive'
    Assert-Equal 'Listed only' $arch.Status; Assert-Equal 'Connected to the tenant' $arch.Source; Assert-Equal 'former.dev@contoso.com' $arch.Owner
    Assert-Equal '' $arch.Projects
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match 'contoso-archive' }).Count 'listed organizations are not queried'
    foreach ($k in @{ Projects = 2; Repositories = 3; Pipelines = 3; ReleasePipelines = 1; ServiceConnections = 3; SelfHostedAgents = 2; Users = 4; PaidUsers = 3; Extensions = 2; Feeds = 2; WorkItems = 175 }.GetEnumerator()) {
        Assert-Equal $k.Value $c.($k.Key) $k.Key
    }
    Assert-Match $c.Detail 'secure files of Legacy App: HTTP 403'
    $fab = $o | Where-Object Organization -eq 'fabrikam-old'
    Assert-Equal 'No access' $fab.Status
    Assert-Match $fab.Detail ('^Connected to another Entra tenant \(' + $global:TW_OtherTenant + '\)')
    $pub = $o | Where-Object Organization -eq 'public-org'
    Assert-Equal 'No access' $pub.Status 'anonymous access to public projects is not access'
    Assert-Match $pub.Detail 'anonymous'
    Assert-Equal 'Named (AdoOrganization)' ($o | Where-Object Organization -eq 'named-org').Source
    $cov = Import-TWCsv $run8 'coverage.csv'
    Assert-Equal 'Partial' ($cov | Where-Object Area -eq 'Azure DevOps contoso-ado').Status
    Assert-Equal 'Skipped' ($cov | Where-Object Area -eq 'Azure DevOps fabrikam-old').Status
    Assert-Equal '3' ($cov | Where-Object Area -eq 'Azure DevOps tenant organization list').Items
    $adoCalls = @($global:TWRequests | Where-Object { $_.Kind -eq 'ado' } | ForEach-Object { $_.Uri })
    Assert-True (@($adoCalls | Where-Object { $_ -match 'contoso-ado/_apis/projects\?.*\$skip=1' }).Count -eq 1) 'project list paging ($top/$skip)'
    Assert-True (@($adoCalls | Where-Object { $_ -match 'variablegroups\?.*continuationToken=2' }).Count -eq 1) 'variable group paging (by id)'
    Assert-True (@($adoCalls | Where-Object { $_ -match 'commits\?.*itemVersion\.version=main' }).Count -ge 1) 'last commit on the default branch'
}

Test-Case 'Azure DevOps: projects, repositories (size, last commit, default-branch policies), pipelines, release pipelines' {
    $p = Import-TWCsv $run8 'ADO/contoso-ado/projects.csv'
    $ws = $p | Where-Object Project -eq 'Web Shop'
    Assert-Equal 'private' $ws.Visibility; Assert-Equal 'Contoso Agile' $ws.Process; Assert-Equal 'inherited' $ws.ProcessType; Assert-Equal 'Git' $ws.SourceControl
    Assert-Equal '2' $ws.Repositories; Assert-Equal '165' $ws.WorkItems; Assert-Equal '2' $ws.ServiceConnections
    Assert-Equal 'public' ($p | Where-Object Project -eq 'Legacy App').Visibility
    $r = Import-TWCsv $run8 'ADO/contoso-ado/repositories.csv'
    $main = $r | Where-Object Repository -eq 'webshop'
    Assert-Equal '50' $main.SizeMB; Assert-Equal 'main' $main.DefaultBranch; Assert-Equal '2' $main.BranchPolicies; Assert-Equal '2' $main.MinReviewers
    Assert-Equal 'True' $main.BuildValidation; Assert-Equal '9' $main.DaysSinceLastCommit
    $infra = $r | Where-Object Repository -eq 'webshop-infra'
    Assert-Equal '1' $infra.BranchPolicies; Assert-Equal '' $infra.MinReviewers; Assert-Equal '424' $infra.DaysSinceLastCommit
    Assert-Equal 'True' ($r | Where-Object Repository -eq 'legacy-code').Disabled
    $pl = Import-TWCsv $run8 'ADO/contoso-ado/pipelines.csv'
    $y = $pl | Where-Object Pipeline -eq 'webshop-ci'
    Assert-Equal 'YAML' $y.Type; Assert-Equal 'Azure Repos Git' $y.RepositoryType; Assert-Equal 'succeeded' $y.LastResult; Assert-Equal '1' $y.DaysSinceLastRun; Assert-Equal '' $y.Folder
    $cl = $pl | Where-Object Pipeline -eq 'webshop-classic'
    Assert-Equal 'Classic' $cl.Type; Assert-Equal 'GitHub' $cl.RepositoryType; Assert-Equal 'Legacy' $cl.Folder; Assert-Equal 'Default' $cl.AgentPool
    $rel = @(Import-TWCsv $run8 'ADO/contoso-ado/releasePipelines.csv')
    Assert-Equal 'Dev; Prod' $rel[0].Stages; Assert-Equal 'Release-42' $rel[0].LastRelease
}

Test-Case 'Azure DevOps: service connections joined with Entra identities, secret expiry and Azure roles; tenant transfer rows' {
    $s = Import-TWCsv $run8 'ADO/contoso-ado/serviceConnections.csv'
    $wif = $s | Where-Object ServiceConnection -eq 'Contoso Prod (WIF)'
    Assert-Equal 'WorkloadIdentityFederation' $wif.AuthScheme; Assert-Equal 'False' $wif.SecretBased; Assert-Equal 'Web Shop; Legacy App' $wif.Projects
    Assert-Equal 'sp-monitoring' $wif.AppName; Assert-Match $wif.AzureRoles ('^Reader @ /subscriptions/' + $global:TW_S1); Assert-Equal 'True' $wif.InThisInventory
    $sec = $s | Where-Object ServiceConnection -eq 'Legacy SPN'
    Assert-Equal 'True' $sec.SecretBased; Assert-Equal 'Legacy Integration' $sec.AppName; Assert-Equal '2027-01-01T00:00:00Z' $sec.SecretExpires
    Assert-Equal 'False' ($s | Where-Object ServiceConnection -eq 'contoso-github').SecretBased
    $tt = Import-TWCsv $run8 'tenantTransferImpact.csv'
    Assert-Equal 2 @($tt | Where-Object Category -eq 'Azure DevOps').Count
}

Test-Case 'Azure DevOps: agent pools (hosted, scale set, deployment), agents (offline, version 2, VM match), users, admins' {
    $pools = Import-TWCsv $run8 'ADO/contoso-ado/agentPools.csv'
    Assert-Equal 'Microsoft-hosted' ($pools | Where-Object Pool -eq 'Azure Pipelines').Kind
    $ss = $pools | Where-Object Pool -eq 'Scale Agents'
    Assert-Equal 'Scale set (VMSS)' $ss.Kind; Assert-Match $ss.AzureResourceId 'virtualMachineScaleSets/vmss-agents$'; Assert-Equal '4' $ss.MaxCapacity
    Assert-Equal 'Deployment pool' ($pools | Where-Object Pool -eq 'Deploy Pool').Kind
    Assert-Equal '1' ($pools | Where-Object Pool -eq 'Default').Online
    $ag = Import-TWCsv $run8 'ADO/contoso-ado/agents.csv'
    $b = $ag | Where-Object Agent -eq 'build01'
    Assert-Equal 'vm-app01' $b.ComputerName; Assert-Match $b.AzureVmId 'virtualMachines/vm-app01$'; Assert-Equal 'False' $b.Outdated
    $old = $ag | Where-Object Agent -eq 'oldagent'
    Assert-Equal 'True' $old.Outdated; Assert-Equal 'offline' $old.Status
    $u = Import-TWCsv $run8 'ADO/contoso-ado/users.csv'
    Assert-Equal 'Microsoft account' ($u | Where-Object User -eq 'someone@outlook.com').Origin
    $pat = $u | Where-Object User -eq 'pat@fabrikam.com'
    Assert-Equal 'guest' $pat.UserType; Assert-Equal '' $pat.LastAccess; Assert-Equal 'False' $pat.Paid
    Assert-Equal '240' ($u | Where-Object User -eq 'former.dev@contoso.com').DaysSinceLastAccess
    $ad = Import-TWCsv $run8 'ADO/contoso-ado/admins.csv'
    Assert-Equal 2 @($ad | Where-Object Group -eq 'Project Collection Administrators').Count
    Assert-Equal 'Group' ($ad | Where-Object Member -eq 'g-app-admins').MemberType
    Assert-Equal 'Web Shop' @($ad | Where-Object Group -eq 'Project Administrators')[0].Project
    Assert-Equal 1 @($ad | Where-Object MemberType -eq 'Service principal').Count
}

Test-Case 'Azure DevOps: variable groups never hold values, hooks keep only the host, agent capabilities are not exported' {
    $vg = Import-TWCsv $run8 'ADO/contoso-ado/variableGroups.csv'
    $lib = $vg | Where-Object VariableGroup -eq 'webshop-settings'
    Assert-Equal '2' $lib.Variables; Assert-Equal '1' $lib.SecretVariables; Assert-Equal 'ApiUrl; DbPassword' $lib.VariableNames
    $kv = $vg | Where-Object VariableGroup -eq 'kv-secrets'
    Assert-Equal 'Key Vault' $kv.Type; Assert-Equal 'kv-contoso' $kv.KeyVault; Assert-Equal 'Contoso Prod (WIF)' $kv.ServiceConnection
    $h = @(Import-TWCsv $run8 'ADO/contoso-ado/serviceHooks.csv')
    Assert-Equal 'hooks.slack.com' $h[0].TargetHost; Assert-Equal 'Web Shop' $h[0].Project
    foreach ($f in @(Get-ChildItem -LiteralPath $run8.OutDir -Recurse -File)) {
        $t = [IO.File]::ReadAllText($f.FullName)
        foreach ($secret in @('v1-secretish', 'SECRETTOKEN42', 'do-not-export')) { Assert-True ($t.IndexOf($secret) -lt 0) ('{0} in {1}' -f $secret, $f.Name) }
    }
}

Test-Case 'Azure DevOps: environments, deployment groups, secure files, extensions, feeds, work items, processes' {
    $e = @(Import-TWCsv $run8 'ADO/contoso-ado/environments.csv')
    Assert-Equal '1' $e[0].Resources; Assert-Equal 'kubernetes' $e[0].ResourceTypes; Assert-Equal '1' $e[0].Approvals; Assert-Equal '2' $e[0].Checks
    Assert-Match @(Import-TWCsv $run8 'ADO/contoso-ado/deploymentGroups.csv')[0].AzureVmId 'virtualMachines/vm-app01$'
    Assert-Equal 'signing.pfx' @(Import-TWCsv $run8 'ADO/contoso-ado/secureFiles.csv')[0].SecureFile
    $x = Import-TWCsv $run8 'ADO/contoso-ado/extensions.csv'
    Assert-Equal 'Third-party' ($x | Where-Object ExtensionId -eq 'sonarqube').Source; Assert-Equal 'True' ($x | Where-Object ExtensionId -eq 'vss-code-search').BuiltIn
    Assert-Equal 3 @(Import-TWCsv $run8 'ADO/contoso-ado/workItems.csv').Count
    Assert-Equal 'Agile' ((Import-TWCsv $run8 'ADO/contoso-ado/processes.csv') | Where-Object Process -eq 'Contoso Agile').Parent
}

Test-Case 'Azure DevOps feeds: package counts, protocols, views, retention; feedPermissions.csv (Owner role needed)' {
    $fd = Import-TWCsv $run8 'ADO/contoso-ado/feeds.csv'
    $org = $fd | Where-Object Feed -eq 'contoso-packages'
    Assert-Equal 'Organization' $org.Scope; Assert-Equal 'npmjs' $org.UpstreamSources; Assert-Equal 'True' $org.UpstreamEnabled
    foreach ($k in @{ Packages = '4'; PublishedPackages = '3'; CachedPackages = '1'; Versions = '5'; Protocols = 'NuGet; npm; Universal'; LastPublished = '2026-07-01T00:00:00Z'
            Views = 'Local; Prerelease; Release'; MaxVersions = '20'; KeepDownloadedDays = '30'; Permissions = '4'; PackagesCapped = 'False' }.GetEnumerator()) {
        Assert-Equal $k.Value $org.($k.Key) $k.Key
    }
    $ws = $fd | Where-Object Feed -eq 'webshop-feed'
    Assert-Equal 'Web Shop' $ws.Project; Assert-Equal '4' $ws.Packages; Assert-Equal 'Maven; PyPI; Cargo; Universal' $ws.Protocols
    Assert-Equal '' $ws.MaxVersions 'no retention policy (body null)'; Assert-Equal '' $ws.Permissions 'permissions not readable'
    Assert-Equal 2 @($fd).Count 'a project feed in the organization list is one feed'
    $pm = @(Import-TWCsv $run8 'ADO/contoso-ado/feedPermissions.csv')
    Assert-Equal 4 $pm.Count
    $pca = $pm | Where-Object Identity -eq 'Project Collection Administrators'
    Assert-Equal 'contoso-ado' $pca.IdentityScope; Assert-Equal 'administrator' $pca.Role; Assert-Equal 'False' $pca.Inherited; Assert-Equal 'contoso-packages' $pca.Feed
    Assert-Equal 'contributor' ($pm | Where-Object Identity -eq 'Project Collection Build Service (contoso-ado)').Role
    Assert-Equal 'True' ($pm | Where-Object Identity -eq 'Pat Partner').Inherited
    Assert-Equal 'collaborator' ($pm | Where-Object Identity -eq 'S-1-9-1551374245-4').Role 'no display name: identifier of the descriptor object'
    Assert-Match ((Import-TWCsv $run8 'ADO/organizations.csv') | Where-Object Organization -eq 'contoso-ado').Detail 'feed permissions: not readable for 1 of 2 feed\(s\) with your feed role - feed owners can read them \(webshop-feed\)'
}

Test-Case 'Azure DevOps packages.csv: one row per version with views, upstream source and download counts (one POST per 200 packages)' {
    $pk = @(Import-TWCsv $run8 'ADO/contoso-ado/packages.csv')
    Assert-Equal 9 $pk.Count
    $old = $pk | Where-Object { $_.Package -eq 'Contoso.Core' -and $_.Version -eq '1.0.0' }
    Assert-Equal 'False' $old.IsLatest; Assert-Equal 'Local' $old.Views; Assert-Equal 'Published' $old.Source; Assert-Equal 'NuGet' $old.Protocol
    Assert-Equal '42' $old.PackageDownloads; Assert-Equal '2026-09-20T00:00:00Z' $old.PackageLastDownloaded; Assert-Equal '' $old.ExportedTo
    Assert-Equal 'Local; Release' ($pk | Where-Object { $_.Package -eq 'Contoso.Core' -and $_.Version -eq '1.1.0' }).Views
    $lp = $pk | Where-Object Package -eq 'left-pad'
    Assert-Equal 'Upstream cache' $lp.Source; Assert-Equal 'npmjs' $lp.Upstream; Assert-Equal '7' $lp.PackageDownloads
    $mv = $pk | Where-Object Package -eq 'com.contoso:webshop-lib'
    Assert-Equal 'Web Shop' $mv.Project; Assert-Equal 'webshop-feed' $mv.Feed; Assert-Equal '0' $mv.PackageDownloads; Assert-Equal '' $mv.PackageLastDownloaded
    Assert-Equal '0' ($pk | Where-Object Package -eq 'contoso-utils').PackageDownloads 'never downloaded: left out of the metrics answer'
    Assert-Equal 'Maven|PyPI|Cargo|npm' ('{0}|{1}|{2}|{3}' -f $mv.Protocol, ($pk | Where-Object Package -eq 'contoso-utils').Protocol, ($pk | Where-Object Package -eq 'contoso-rs').Protocol, $lp.Protocol)
    $posts = @($global:TWRequests | Where-Object { $_.Method -eq 'POST' -and $_.Uri -match 'packagemetricsbatch' })
    Assert-Equal 2 $posts.Count 'one metrics call per feed'
    Assert-Match $posts[0].Body '^\{"packageIds":\["a7a7a7a7-0000-0000-0000-000000000001",'
    Assert-True (@($global:TWRequests | Where-Object { $_.Uri -match '/packages\?' -and $_.Uri -notmatch 'includeAllVersions=true' }).Count -eq 0) 'all versions requested'
}

Test-Case 'Azure DevOps TFVC: every branch with files, size, last changeset and the pipelines that use it' {
    $tv = @(Import-TWCsv $run8 'ADO/contoso-ado/tfvc.csv')
    Assert-Equal 2 $tv.Count
    $main = $tv | Where-Object Path -eq '$/Legacy App/Trunk/Main'
    Assert-Equal 'Legacy App' $main.Project; Assert-Equal 'True' $main.IsBranch; Assert-Equal '' $main.Parent; Assert-Equal 'Former Dev' $main.Owner
    Assert-Equal '2015-03-01T00:00:00Z' $main.Created; Assert-Equal '120' $main.LastChangeset; Assert-Equal '2023-05-10T00:00:00Z' $main.LastChange
    Assert-Equal 'Former Dev' $main.LastChangeBy; Assert-Equal '3' $main.Files; Assert-Equal '3.5' $main.SizeMB; Assert-Equal 'False' $main.FilesCapped
    Assert-Equal '1' $main.Pipelines 'mapped by legacy-build'; Assert-Equal '' $main.ExportedTo
    $dev = $tv | Where-Object Path -eq '$/Legacy App/Trunk/Dev'
    Assert-Equal '$/Legacy App/Trunk/Main' $dev.Parent; Assert-Equal '1' $dev.Files; Assert-Equal '0.5' $dev.SizeMB; Assert-Equal '0' $dev.Pipelines
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match '/b1b1b1b1-0000-0000-0000-000000000001/_apis/tfvc/' }).Count 'TFVC calls for the Git project'
}

Test-Case 'Azure DevOps findings ADO-01 to ADO-07' {
    $f = Import-TWCsv $run8 'findings.csv'
    foreach ($x in @(@('ADO-01', 1), @('ADO-02', 1), @('ADO-03', 1), @('ADO-04', 1), @('ADO-05', 3), @('ADO-06', 2), @('ADO-07', 1))) {
        Assert-Equal $x[1] ($f | Where-Object Id -eq $x[0]).Count $x[0]
    }
}

Test-Case 'Azure DevOps files: organizations.csv in ADO\, the other 21 in one folder per collected organization' {
    $ado = [IO.Path]::Combine($run8.OutDir, 'ADO')
    Assert-True (Test-Path ([IO.Path]::Combine($ado, 'organizations.csv'))) 'ADO\organizations.csv'
    Assert-Equal 'contoso-ado' (@(Get-ChildItem -LiteralPath $ado -Directory | ForEach-Object { $_.Name }) -join ',') 'only collected organizations get a folder'
    $files = @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($ado, 'contoso-ado')) -File -Filter *.csv)
    Assert-Equal 21 $files.Count (($files | ForEach-Object { $_.Name }) -join ',')
    Assert-False (Test-Path ([IO.Path]::Combine($ado, 'projects.csv'))) 'combined files are not written'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($ado, 'contoso-ado')) -Directory).Count 'project folders come only with the export reports'
    Assert-True (@($run8.Log | Where-Object { $_ -match 'ADO/contoso-ado/ +\d+ rows in 21 files' }).Count -eq 1) 'one summary line per organization folder'
    $hint = 'Not exported in this run: pipelines \(add AzureDevOpsPipelines to -Reports\), Git and TFVC repositories \(add AzureDevOpsRepos to -Reports\), packages \(add AzureDevOpsPackages to -Reports\)'
    Assert-True (@($run8.Log | Where-Object { $_ -match $hint }).Count -eq 1) 'hint about the export reports'
}

Test-Case 'AzureDevOpsPipelines exports YAML files and pipeline/release definitions per organization and project' {
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPipelines') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $base = [IO.Path]::Combine($r.OutDir, 'ADO', 'contoso-ado', 'Web Shop', 'pipelines')
    Assert-Match ([IO.File]::ReadAllText([IO.Path]::Combine($base, 'webshop-ci.yml'))) 'vmImage: ubuntu-latest'
    $def = Get-Content -Raw -Encoding UTF8 ([IO.Path]::Combine($base, 'webshop-ci.json')) | ConvertFrom-Json
    Assert-Equal 'webshop-ci' $def.name
    Assert-True ($null -eq $def.PSObject.Properties['latestCompletedBuild']) 'run summary removed from the definition'
    Assert-True (Test-Path ([IO.Path]::Combine($base, 'Legacy', 'webshop-classic.json'))) 'classic pipeline in its folder'
    $rel = Get-Content -Raw -Encoding UTF8 ([IO.Path]::Combine($base, 'releases', 'webshop-release.json')) | ConvertFrom-Json
    Assert-Equal '_webshop-ci' $rel.artifacts[0].alias
    $pl = Import-TWCsv $r 'ADO/contoso-ado/pipelines.csv'
    Assert-Equal 'ADO/contoso-ado/Web Shop/pipelines/webshop-ci.yml' ($pl | Where-Object Pipeline -eq 'webshop-ci').ExportedFile
    Assert-Equal 'ADO/contoso-ado/Web Shop/pipelines/Legacy/webshop-classic.json' ($pl | Where-Object Pipeline -eq 'webshop-classic').ExportedFile
    Assert-Equal 'ADO/contoso-ado/Web Shop/pipelines/releases/webshop-release.json' @(Import-TWCsv $r 'ADO/contoso-ado/releasePipelines.csv')[0].ExportedFile
    Assert-Equal '4' ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Azure DevOps pipeline export').Items
}

Test-Case 'AzureDevOpsRepos exports the default branch of each repository to <project>\repos\<repository>' {
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsRepos'); AdoRepoMaxSizeMB = 10 }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $repos = [IO.Path]::Combine($r.OutDir, 'ADO', 'contoso-ado', 'Web Shop', 'repos')
    Assert-Equal 'param location string' ([IO.File]::ReadAllText([IO.Path]::Combine($repos, 'webshop-infra', 'main.bicep')))
    Assert-False (Test-Path ([IO.Path]::Combine($repos, 'webshop'))) '50 MB repository above -AdoRepoMaxSizeMB 10'
    Assert-False (Test-Path ([IO.Path]::Combine($r.OutDir, 'ADO', 'contoso-ado', 'Legacy App', 'repos', 'legacy-code'))) 'disabled repository'
    $tfvc = [IO.Path]::Combine($r.OutDir, 'ADO', 'contoso-ado', 'Legacy App', 'repos', 'TFVC')
    Assert-Equal 'tfvc Main/src/Program.cs' ([IO.File]::ReadAllText([IO.Path]::Combine($tfvc, 'Trunk', 'Main', 'src', 'Program.cs'))) 'TFVC branch Trunk/Main'
    Assert-True (Test-Path ([IO.Path]::Combine($tfvc, 'Trunk', 'Dev', 'App.sln'))) 'TFVC branch Trunk/Dev'
    $tv = Import-TWCsv $r 'ADO/contoso-ado/tfvc.csv'
    Assert-Equal 'ADO/contoso-ado/Legacy App/repos/TFVC/Trunk/Main' ($tv | Where-Object Path -eq '$/Legacy App/Trunk/Main').ExportedTo
    Assert-False (Test-Path ([IO.Path]::Combine($r.OutDir, '.cache-repository.zip'))) 'temporary zip removed'
    $rows = Import-TWCsv $r 'ADO/contoso-ado/repositories.csv'
    Assert-Equal 'ADO/contoso-ado/Web Shop/repos/webshop-infra' ($rows | Where-Object Repository -eq 'webshop-infra').ExportedTo
    Assert-Equal '' ($rows | Where-Object Repository -eq 'webshop').ExportedTo
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Azure DevOps repository export'
    Assert-Equal '3' $cov.Items 'one Git repository and two TFVC branches'
    Assert-Match $cov.Detail 'Web Shop/webshop \(50 MB, above -AdoRepoMaxSizeMB\)'
    Assert-Match $cov.Detail 'Legacy App/legacy-code \(disabled\)'
    # default limit (1024 MB): both repositories with content, subfolders kept
    $r2 = Invoke-TWRun -Params @{ Reports = @('AzureDevOpsRepos') }
    $web = [IO.Path]::Combine($r2.OutDir, 'ADO', 'contoso-ado', 'Web Shop', 'repos', 'webshop')
    Assert-Equal '# Web Shop' ([IO.File]::ReadAllText([IO.Path]::Combine($web, 'README.md')))
    Assert-True (Test-Path ([IO.Path]::Combine($web, 'src', 'app.cs'))) 'subfolders kept'
    # not enough free disk space: skipped, not failed
    Reset-TWState
    $global:TW.FreeSpace = [long]100MB
    $r3 = Invoke-TWRun -Params @{ Reports = @('AzureDevOpsRepos') } -KeepWorld
    Assert-Equal 0 $r3.Errors.Count ($r3.Errors -join ' | ')
    Assert-Match ((Import-TWCsv $r3 'coverage.csv') | Where-Object Area -eq 'Azure DevOps repository export').Detail 'Web Shop/webshop \(not enough free disk space\)'
}

Test-Case 'AzureDevOpsPackages downloads the latest published version of every package to <project>\feeds\<feed>\<protocol>' {
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPackages') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $orgFeed = [IO.Path]::Combine($r.OutDir, 'ADO', 'contoso-ado', 'feeds', 'contoso-packages')
    $nupkg = [IO.Path]::Combine($orgFeed, 'nuget', 'Contoso.Core', '1.1.0', 'Contoso.Core.1.1.0.nupkg')
    Assert-Equal 'nuget file packages/Contoso.Core/versions/1.1.0' ([IO.File]::ReadAllText($nupkg))
    Assert-False (Test-Path ([IO.Path]::Combine($orgFeed, 'nuget', 'Contoso.Core', '1.0.0'))) 'older version (Latest only)'
    Assert-True (Test-Path ([IO.Path]::Combine($orgFeed, 'npm', '@contoso', 'ui', '2.0.0', 'ui-2.0.0.tgz'))) 'scoped npm package'
    Assert-False (Test-Path ([IO.Path]::Combine($orgFeed, 'npm', 'left-pad'))) 'versions cached from upstream sources are not downloaded'
    $prjFeed = [IO.Path]::Combine($r.OutDir, 'ADO', 'contoso-ado', 'Web Shop', 'feeds', 'webshop-feed')
    foreach ($f in @('webshop-lib-3.2.1.jar', 'webshop-lib-3.2.1.pom')) { Assert-True (Test-Path ([IO.Path]::Combine($prjFeed, 'maven', 'com.contoso', 'webshop-lib', '3.2.1', $f))) ('Maven ' + $f) }
    Assert-False (Test-Path ([IO.Path]::Combine($prjFeed, 'maven', 'com.contoso', 'webshop-lib', '3.2.1', 'webshop-lib-3.2.1.jar.sha1'))) 'Maven checksum files are not downloaded'
    Assert-True (Test-Path ([IO.Path]::Combine($prjFeed, 'pypi', 'contoso-utils', '0.9.0', 'contoso_utils-0.9.0-py3-none-any.whl'))) 'PyPI file'
    Assert-Equal 'cargo file packages/contoso-rs/versions/0.2.0' ([IO.File]::ReadAllText([IO.Path]::Combine($prjFeed, 'cargo', 'contoso-rs', '0.2.0', 'contoso-rs-0.2.0.crate')))
    $pk = Import-TWCsv $r 'ADO/contoso-ado/packages.csv'
    Assert-Equal 'ADO/contoso-ado/feeds/contoso-packages/nuget/Contoso.Core/1.1.0' ($pk | Where-Object { $_.Package -eq 'Contoso.Core' -and $_.Version -eq '1.1.0' }).ExportedTo
    Assert-Equal '' ($pk | Where-Object { $_.Package -eq 'Contoso.Core' -and $_.Version -eq '1.0.0' }).ExportedTo
    Assert-Equal 'ADO/contoso-ado/Web Shop/feeds/webshop-feed/maven/com.contoso/webshop-lib/3.2.1' ($pk | Where-Object Package -eq 'com.contoso:webshop-lib').ExportedTo
    Assert-Equal 'ADO/contoso-ado/feeds/contoso-packages/universal/contoso-tools/0.1.0' ($pk | Where-Object Package -eq 'contoso-tools').ExportedTo
    $cov = (Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Azure Artifacts package download'
    Assert-Equal 'Collected' $cov.Status; Assert-Equal '7' $cov.Items; Assert-NotMatch $cov.Detail 'not downloadable'
    Assert-True (@($r.Log | Where-Object { $_ -match 'Feed contoso-packages \(organization\): 5 version\(s\), 1 from upstream sources \(not downloaded\), 3 to download -> ADO/contoso-ado/feeds/contoso-packages$' }).Count -eq 1) 'feed line before the download'
    Assert-True (@($r.Log | Where-Object { $_ -match 'Feed webshop-feed \(project Web Shop\): 4 downloaded, 0 above -AdoPackageMaxSizeMB, 0 of other types, 0 not downloaded' }).Count -eq 1) 'feed line after the download'
    $dl = @($global:TWRequests | Where-Object { $_.Uri -match '^https://pkgs\.dev\.azure\.com/' } | ForEach-Object { $_.Uri })
    Assert-True (@($dl | Where-Object { $_ -match '/npm/packages/@contoso/ui/versions/2\.0\.0/content\?api-version=7\.1$' }).Count -eq 1) ('npm scoped URL: ' + ($dl -join ' '))
    Assert-True (@($dl | Where-Object { $_ -match '/cargo/packages/contoso-rs/versions/0\.2\.0/download\?api-version=7\.1$' }).Count -eq 1) 'Cargo download URL'
    Assert-True (@($dl | Where-Object { $_ -match '/contoso-ado/b1b1b1b1-0000-0000-0000-000000000001/_apis/packaging/feeds/f1f1f1f1-0000-0000-0000-000000000002/maven/com\.contoso/webshop-lib/3\.2\.1/webshop-lib-3\.2\.1\.jar/content\?' }).Count -eq 1) 'Maven URL with the project'
}

Test-Case 'Universal Packages: ArtifactTool from Azure DevOps (zip without token, signature checked, cached), token only in its environment' {
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPackages') }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $toolDir = [IO.Path]::Combine($script:A2CToolsRoot, 'ArtifactTool', 'ArtifactTool_win-x64_0.2.574')
    Assert-True (Test-Path ([IO.Path]::Combine($toolDir, 'native', 'amd64', 'librocksdb.so'))) 'zip entries with backslashes become folders'
    $zipCalls = @($global:TWRequests | Where-Object { $_.Uri -match 'vsassets\.io/artifacttool/' })
    Assert-Equal 1 $zipCalls.Count; Assert-Equal 'web' $zipCalls[0].Kind 'the storage link is fetched without a token'
    Assert-Equal 'ado' @($global:TWRequests | Where-Object { $_.Uri -match '^https://vsblob\.dev\.azure\.com/contoso-ado/_apis/clienttools/ArtifactTool/release\?osName=' })[0].Kind
    $calls = @($global:TWArtifactTool)
    Assert-Equal 2 $calls.Count
    $org = @($calls | Where-Object { $_.Arguments -contains 'contoso-tools' })[0]
    Assert-Equal ([IO.Path]::Combine($toolDir, 'artifacttool.exe')) $org.Path
    $dir = [IO.Path]::Combine($r.OutDir, 'ADO/contoso-ado/feeds/contoso-packages/universal/contoso-tools/0.1.0')
    Assert-Equal ('universal download --service https://dev.azure.com/contoso-ado/ --patvar AZURE2CSV_ARTIFACTTOOL_TOKEN --feed f1f1f1f1-0000-0000-0000-000000000001 ' +
        '--package-name contoso-tools --package-version 0.1.0 --path ' + $dir + ' --verbosity Warning') ($org.Arguments -join ' ')
    $token = $org.Environment['AZURE2CSV_ARTIFACTTOOL_TOKEN']
    Assert-Match $token '^eyJ0eXAiOiJKV1QifQ\.fake-entra-token\.499b84ac-1321-427f-aa17-267ca6975798$'
    Assert-True ($org.Environment.ContainsKey('ARTIFACTTOOL_CACHEDIRECTORY') -and $null -eq $org.Environment['ARTIFACTTOOL_CACHEDIRECTORY']) 'no ArtifactTool cache outside the run folder'
    Assert-True (@($calls | ForEach-Object { $_.Arguments } | Where-Object { $_ -match 'fake-entra-token' }).Count -eq 0) 'token on the command line'
    $prj = @($calls | Where-Object { $_.Arguments -contains 'webshop-assets' })[0]
    Assert-Match ($prj.Arguments -join ' ') '--project b1b1b1b1-0000-0000-0000-000000000001$'
    Assert-Equal 'universal package contoso-tools' ([IO.File]::ReadAllText([IO.Path]::Combine($dir, 'readme.txt')))
    Assert-True (Test-Path ([IO.Path]::Combine($r.OutDir, 'ADO', 'contoso-ado', 'Web Shop', 'feeds', 'webshop-feed', 'universal', 'webshop-assets', '1.0.0', 'bin', 'tool.cmd'))) 'project feed'
    Assert-True (@($r.Log | Where-Object { $_ -match 'Universal Packages: Microsoft ArtifactTool version 0\.2\.574 from Azure DevOps' }).Count -eq 1) 'tool logged once'
    Assert-True (@($r.Log | Where-Object { $_ -match 'SASSIGNATURE42|fake-entra-token' }).Count -eq 0) 'no secrets in the log'
    # the next run asks for the current release again but reuses the unpacked tool
    $null = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPackages') } -KeepWorld
    Assert-Equal 1 @($global:TWRequests | Where-Object { $_.Uri -match 'vsassets\.io/artifacttool/' }).Count 'tool downloaded again'
    Assert-Equal 4 $global:TWArtifactTool.Count
}

Test-Case 'Universal Packages: no valid signature, a failed download, too large for the disk, -ArtifactToolPath' {
    Reset-TWState
    $global:TW.SignatureValid = $false
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPackages') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $pk = Import-TWCsv $r 'ADO/contoso-ado/packages.csv'
    Assert-Match ($pk | Where-Object Package -eq 'contoso-tools').ExportNote '^Not downloaded: ArtifactTool 0\.2\.574 has no valid Microsoft signature, so it was not run .+ pass it with -ArtifactToolPath$'
    Assert-Equal 0 $global:TWArtifactTool.Count 'unsigned tool run'
    Assert-Equal 'ADO/contoso-ado/feeds/contoso-packages/nuget/Contoso.Core/1.1.0' ($pk | Where-Object { $_.Package -eq 'Contoso.Core' -and $_.Version -eq '1.1.0' }).ExportedTo 'other packages still downloaded'
    Assert-Equal 'Partial' ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Azure Artifacts package download').Status
    Assert-Equal 1 @($r.Log | Where-Object { $_ -match 'Universal Packages are not downloaded' }).Count 'one warning, not one per package'
    # a failed download is removed; a package larger than the free disk space is not started
    Reset-TWState
    $global:TW.ArtifactToolFails = @('contoso-tools')
    $global:TW.FreeSpace = [long]2GB
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPackages') } -KeepWorld
    $pk = Import-TWCsv $r 'ADO/contoso-ado/packages.csv'
    Assert-Equal "Failed: ArtifactTool exit code 18: Cannot find the package 'contoso-tools' in feed." ($pk | Where-Object Package -eq 'contoso-tools').ExportNote
    Assert-False (Test-Path ([IO.Path]::Combine($r.OutDir, 'ADO', 'contoso-ado', 'feeds', 'contoso-packages', 'universal'))) 'failed download removed'
    Assert-Equal 'Not downloaded: not enough free disk space for 3072 MB' ($pk | Where-Object Package -eq 'webshop-assets').ExportNote
    Assert-Equal 1 $global:TWArtifactTool.Count 'the large package is skipped before ArtifactTool runs'
    # -ArtifactToolPath (a folder): no release call and no download
    Reset-TWState
    $own = [IO.Path]::Combine($global:TWOut, 'own-artifacttool')
    [void][IO.Directory]::CreateDirectory($own)
    [IO.File]::WriteAllText([IO.Path]::Combine($own, 'artifacttool.exe'), 'MZ')
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPackages'); ArtifactToolPath = $own } -KeepWorld
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match 'clienttools|vsassets' }).Count 'release call or download'
    Assert-Equal ([IO.Path]::Combine($own, 'artifacttool.exe')) $global:TWArtifactTool[0].Path
    Assert-Equal 2 $global:TWArtifactTool.Count
}

Test-Case 'AzureDevOpsPackages: -AdoPackageMaxSizeMB skips large versions before the download, -AdoPackageTypes picks types' {
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPackages'); AdoPackageMaxSizeMB = 1 }
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $pk = Import-TWCsv $r 'ADO/contoso-ado/packages.csv'
    Assert-Equal 'Not downloaded: 3 MB, above -AdoPackageMaxSizeMB 1' ($pk | Where-Object { $_.Package -eq 'Contoso.Core' -and $_.Version -eq '1.1.0' }).ExportNote
    Assert-Equal 'Not downloaded: 3072 MB, above -AdoPackageMaxSizeMB 1' ($pk | Where-Object Package -eq 'webshop-assets').ExportNote
    Assert-Match ($pk | Where-Object { $_.Package -like '*@contoso/ui' }).ExportedTo 'npm/@contoso/ui/2\.0\.0$'
    Assert-Equal 'ADO/contoso-ado/feeds/contoso-packages/universal/contoso-tools/0.1.0' ($pk | Where-Object Package -eq 'contoso-tools').ExportedTo 'small Universal package'
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match '/nuget/packages/' }).Count 'the large NuGet file was requested'
    Assert-True ($global:TWSizeProbes.Count -ge 4) ('size requests: ' + $global:TWSizeProbes.Count)
    Assert-Match ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Azure Artifacts package download').Detail '2 above -AdoPackageMaxSizeMB'
    # only npm packages
    $r2 = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPackages'); AdoPackageTypes = @('npm') }
    $pk2 = Import-TWCsv $r2 'ADO/contoso-ado/packages.csv'
    Assert-Equal 'Not downloaded: NuGet is not in -AdoPackageTypes' ($pk2 | Where-Object { $_.Package -eq 'Contoso.Core' -and $_.Version -eq '1.1.0' }).ExportNote
    Assert-Match ($pk2 | Where-Object { $_.Package -like '*@contoso/ui' }).ExportedTo 'npm/@contoso/ui/2\.0\.0$'
    Assert-Equal 0 $global:TWArtifactTool.Count 'Universal packages downloaded'
    Assert-Equal 0 $global:TWSizeProbes.Count 'size requests without -AdoPackageMaxSizeMB'
    Assert-Match ((Import-TWCsv $r2 'coverage.csv') | Where-Object Area -eq 'Azure Artifacts package download').Detail '6 of types not in -AdoPackageTypes'
}

Test-Case 'AzureDevOpsPackages: -AdoPackageVersions All, the -AdoPackagesMaxMB total limit, never with -Mask' {
    Reset-TWState
    # a 1.1 MB NuGet package: after it the 1 MB limit is reached
    $global:TW.AdoRoutes.Insert(0, @{ Method = 'GET'; Pattern = '^pkgs\.dev\.azure\.com/contoso-ado/_apis/packaging/feeds/[0-9a-f-]{36}/nuget/'; Handler = { param($path, $body, $m) @{ StatusCode = 200; Content = ''; Headers = @{}; File = ('x' * 1153434) } } })
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'AzureDevOpsPackages'); AdoPackageVersions = 'All'; AdoPackagesMaxMB = 1 } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $pk = Import-TWCsv $r 'ADO/contoso-ado/packages.csv'
    Assert-Equal 'ADO/contoso-ado/feeds/contoso-packages/nuget/Contoso.Core/1.0.0' ($pk | Where-Object { $_.Package -eq 'Contoso.Core' -and $_.Version -eq '1.0.0' }).ExportedTo 'older version with All'
    Assert-Equal 'Not downloaded: -AdoPackagesMaxMB reached' ($pk | Where-Object { $_.Package -eq 'Contoso.Core' -and $_.Version -eq '1.1.0' }).ExportNote
    Assert-Equal 'Not downloaded: -AdoPackagesMaxMB reached' ($pk | Where-Object Package -eq 'contoso-utils').ExportNote
    Assert-True (@($r.Log | Where-Object { $_ -match '-AdoPackagesMaxMB 1 reached' }).Count -eq 1) 'warning once'
    $r2 = Invoke-TWRun -Params @{ Reports = @('AzureDevOpsPackages'); Mask = $true }
    Assert-Equal 'Skipped' ((Import-TWCsv $r2 'coverage.csv') | Where-Object Area -eq 'Azure Artifacts package download').Status
    Assert-Equal 0 @($global:TWRequests | Where-Object { $_.Uri -match '^https://pkgs\.' }).Count 'no downloads under -Mask'
}

Test-Case 'Azure DevOps organizations are also found through Managed DevOps Pools and pipeline agent VM extensions' {
    Reset-TWState
    $vm = @($global:TW.Resources | Where-Object { $_.type -eq 'microsoft.compute/virtualmachines' -and $_.name -eq 'vm-app01' })[0]
    $extra = @(
        (New-TWRes $global:TW_S1 'rg-build' 'Microsoft.DevOpsInfrastructure/pools' 'mdp-linux' ([ordered]@{ organizationProfile = [ordered]@{ kind = 'AzureDevOps'
                        organizations = @([ordered]@{ url = 'https://dev.azure.com/contoso-mdp'; projects = @('Web Shop'); parallelism = 2 }) } }))
        (New-TWRes $global:TW_S1 'rg-app' 'Microsoft.Compute/virtualMachines/extensions' 'vm-app01/TeamServicesAgent' ([ordered]@{ publisher = 'Microsoft.VisualStudio.Services'
                    type = 'TeamServicesAgent'; settings = [ordered]@{ VSTSAccountName = 'https://dev.azure.com/contoso-deploy/'; TeamProject = 'Web Shop'; DeploymentGroup = 'dg-web' } })))
    $global:TW.Resources = @($global:TW.Resources | Where-Object { $_.type -ne 'microsoft.visualstudio/account' }) + $extra
    $global:TW.Arg['resources'] = $global:TW.Resources
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    $o = Import-TWCsv $r 'ADO/organizations.csv'
    Assert-Equal 'Managed DevOps Pool' ($o | Where-Object Organization -eq 'contoso-mdp').Source
    Assert-Equal 'Pipeline agent VM extension' ($o | Where-Object Organization -eq 'contoso-deploy').Source
    Assert-True ($null -ne $vm) 'fixture VM'
}

Test-Case 'Azure DevOps work items: organization-wide Analytics refused -> counted per readable project' {
    Reset-TWState
    $global:TW.AdoRoutes.Insert(0, @{ Method = 'GET'; Pattern = '^analytics\.dev\.azure\.com/contoso-ado/_odata/'; Handler = { param($path, $body, $m) New-TWError 403 'Forbidden' 'TF400409: You do not have permissions to view Analytics for all projects.' } })
    $global:TW.AdoRoutes.Insert(0, @{ Method = 'GET'; Pattern = '^analytics\.dev\.azure\.com/contoso-ado/([^/]+)/_odata/'; Handler = {
                param($path, $body, $m)
                if ($m[1] -eq 'Web%20Shop') { return [ordered]@{ value = @([ordered]@{ WorkItemType = 'Bug'; Count = 5 }) } }
                New-TWError 403 'Forbidden' 'TF400409: no Analytics access'
            } })
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps') } -KeepWorld
    $wi = @(Import-TWCsv $r 'ADO/contoso-ado/workItems.csv')
    Assert-Equal 1 $wi.Count
    Assert-Equal 'Web Shop|Bug|5' ('{0}|{1}|{2}' -f $wi[0].Project, $wi[0].WorkItemType, $wi[0].Count)
    Assert-Match ((Import-TWCsv $r 'ADO/organizations.csv') | Where-Object Organization -eq 'contoso-ado').Detail 'work items \(Analytics\): 1 of 2 project\(s\) not readable'
}

Test-Case 'Azure DevOps is skipped without billing resources or -AdoOrganization (no ADO folder, no calls)' {
    Reset-TWState
    $global:TW.Resources = @($global:TW.Resources | Where-Object { $_.type -ne 'microsoft.visualstudio/account' })
    $global:TW.Arg['resources'] = $global:TW.Resources
    $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps') } -KeepWorld
    Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
    Assert-False (Test-Path ([IO.Path]::Combine($r.OutDir, 'ADO')))
    Assert-Equal 'Skipped' ((Import-TWCsv $r 'coverage.csv') | Where-Object Area -eq 'Azure DevOps').Status
    Assert-Equal 0 @($global:TWRequests | Where-Object Kind -eq 'ado').Count
}

# ------------------------------------------------------------------------------------------------------
Write-Host 'Full profile: findings, HTML, Excel fallback' -ForegroundColor Cyan

$run6 = Invoke-TWRun -Params @{ ReportProfile = 'Full'; NoHtml = $false; NoExcel = $false }

Test-Case 'full profile run completes without errors' {
    Assert-Equal 0 $run6.Errors.Count ($run6.Errors -join ' | ')
    Assert-Equal (@($script:A2CReportCatalog | Where-Object { -not $_.Explicit }).Count) @($run6.Selected).Count
}

Test-Case 'findings catalog triggers the expected findings' {
    $f = Import-TWCsv $run6 'findings.csv'
    foreach ($id in @('RET-01', 'RET-02', 'RET-03', 'MIG-01', 'MIG-02', 'MIG-03', 'MIG-04', 'MIG-05', 'MIG-06', 'MIG-07', 'MIG-09', 'SEC-01', 'SEC-02', 'SEC-03', 'SEC-04', 'SEC-05',
            'SEC-06', 'SEC-07', 'SEC-08', 'SEC-09', 'SEC-11', 'SEC-12', 'SEC-13', 'SEC-14', 'SEC-15', 'SEC-17', 'SEC-18', 'SEC-19', 'COST-01', 'COST-02',
            'GOV-01', 'GOV-02', 'GOV-03', 'GOV-04', 'GOV-07')) {
        Assert-True (@($f | Where-Object Id -eq $id).Count -eq 1) ('missing finding ' + $id)
    }
    foreach ($id in @('SEC-10', 'SEC-16', 'COST-03', 'GOV-05', 'GOV-06', 'MIG-08')) { Assert-True (@($f | Where-Object Id -eq $id).Count -eq 0) ('unexpected finding ' + $id) }
    Assert-Match ($f | Where-Object Id -eq 'RET-01').Detail 'Basic Load Balancer \(1\)' 'Advisor duplicate of a rule must be skipped'
    Assert-Equal 'High' $f[0].Severity 'sorted by severity'
    Assert-Match ($f | Where-Object Id -eq 'MIG-06').Detail 'vnet-spoke 10\.1\.0\.0/16 / vnet-dev 10\.1\.0\.0/16'
    Assert-Match ($f | Where-Object Id -eq 'MIG-05').Detail 'Allowed locations: westeurope, northeurope'
    Assert-Match ($f | Where-Object Id -eq 'COST-02').Detail '606 EUR'
}

Test-Case 'HTML summary: sections, no external loads, CSP hash matches the inline script' {
    $html = Get-Content -Raw -Encoding UTF8 ([IO.Path]::Combine($run6.OutDir, 'summary.html'))
    foreach ($s in @('id="overview"', 'id="findings"', 'id="inventory"', 'id="migration"', 'id="retirements"', 'id="security"', 'id="governance"', 'id="cost"', 'id="entra"', 'id="coverage"')) { Assert-Match $html ([regex]::Escape($s)) }
    Assert-NotMatch $html '(?i)<(script|img|iframe|embed|object|audio|video|source)\b[^>]*\bsrc\s*='
    Assert-NotMatch $html '(?i)<link\b'
    Assert-NotMatch $html '(?i)@import'
    Assert-NotMatch $html '(?i)url\(\s*[''"]?(https?:)?//'
    Assert-NotMatch $html 'fetch\(|XMLHttpRequest'
    $js = [regex]::Match($html, '<script>(.*)</script>', 'Singleline').Groups[1].Value
    $hash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($js)))
    Assert-Match $html ([regex]::Escape("script-src 'sha256-" + $hash + "'"))
    Assert-Match $html 'aleksandr@reznik\.lt'
    Assert-Match $html 'it4it\.solutions'
    Assert-Match $html 'Allowed locations'
}

Test-Case 'Excel is skipped gracefully when ImportExcel is missing' {
    Assert-True (@(Get-ChildItem -LiteralPath $run6.OutDir -Filter *.xlsx).Count -eq 0) 'xlsx written'
    $cov = Import-TWCsv $run6 'coverage.csv'
    Assert-Equal 'Skipped' ($cov | Where-Object Area -eq 'Excel workbook').Status
}

if (Get-Module -ListAvailable ImportExcel) {
    Test-Case 'Excel workbook with one sheet per report when ImportExcel is available' {
        Reset-TWState
        $global:TWImportExcel = $true
        try { $r = Invoke-TWRun -Params @{ Reports = @('VMs', 'Storage'); NoExcel = $false } -KeepWorld } finally { $global:TWImportExcel = $false }
        Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
        $x = @(Get-ChildItem -LiteralPath $r.OutDir -Filter *.xlsx)
        Assert-Equal 1 $x.Count
        Import-Module ImportExcel -WarningAction SilentlyContinue
        $sheets = @(Get-ExcelSheetInfo -Path $x[0].FullName | ForEach-Object { $_.Name })
        foreach ($s in @('findings', 'vms', 'storageAccounts', 'coverage')) { Assert-True ($sheets -contains $s) ('sheet ' + $s + ' missing: ' + ($sheets -join ',')) }
        $vms = @(Import-Excel -Path $x[0].FullName -WorksheetName 'vms')
        Assert-Equal '4' ([string]($vms | Where-Object Name -eq 'vm-app01').vCPUs)
    }

    Test-Case 'Excel: Azure DevOps files become "ADO ..." sheets after the main reports' {
        Reset-TWState
        $global:TWImportExcel = $true
        try { $r = Invoke-TWRun -Params @{ Reports = @('AzureDevOps', 'Resources'); NoExcel = $false } -KeepWorld } finally { $global:TWImportExcel = $false }
        Assert-Equal 0 $r.Errors.Count ($r.Errors -join ' | ')
        $x = @(Get-ChildItem -LiteralPath $r.OutDir -Filter *.xlsx)
        $sheets = @(Get-ExcelSheetInfo -Path $x[0].FullName | ForEach-Object { $_.Name })
        foreach ($s in @('ADO organizations', 'ADO projects', 'ADO serviceConnections', 'allResources')) { Assert-True ($sheets -contains $s) ('sheet ' + $s + ' missing: ' + ($sheets -join ',')) }
        Assert-True ([array]::IndexOf($sheets, 'allResources') -lt [array]::IndexOf($sheets, 'ADO organizations')) ('order: ' + ($sheets -join ','))
    }
}
else { Write-Host '  SKIP  Excel positive path (ImportExcel not installed)' -ForegroundColor Yellow }

# ------------------------------------------------------------------------------------------------------
Write-Host 'Mask mode' -ForegroundColor Cyan

$run7 = Invoke-TWRun -Params @{ ReportProfile = 'Full'; NoHtml = $false; Mask = $true }
$originals = @($global:TW_Tenant, $global:TW_S1, $global:TW_S2, $global:TW_S3, $global:TW_S4, 'Contoso Production', 'Contoso Development', 'Contoso Legacy',
    'rg-app', 'rg-network', 'rg-data', 'rg-legacy', 'vm-app01', 'vm-legacy01', 'nic-app01', 'stcontosodata', 'stlegacyvhds', 'kv-contoso', 'sql-contoso',
    'aks-contoso', 'vnet-hub', 'vnet-spoke', 'snet-app', 'nsg-app', 'Allow-RDP-Internet', 'pip-app01', '20.50.60.70', '52.1.1.99', 'CC-100', 'contoso-web',
    $global:TW_Lt, $global:TW_De, 'alex.admin', 'Alex Admin', 'Pat Partner', 'pat_fabrikam', 'jonas@contoso.com', 'contoso.com', 'Contoso Web App',
    'Legacy Integration', 'g-app-admins', 'Tier0 Admins', 'Contoso baseline', 'Contoso VM Operator', 'mg-contoso', 'mg-landingzones', 'Landing Zones',
    'lock-network', 'activitylog-to-law', 'law-contoso', 'aa-contoso', 'Start-VMs', 'sp-monitoring', 'Monitoring Vendor', 'uai-app', 'legacy-waiver', 'require-app-tag',
    'contoso-ado', 'fabrikam-old', 'Web Shop', 'Legacy App', 'webshop', 'legacy-code', 'Contoso Prod (WIF)', 'Legacy SPN', 'contoso-github', 'Scale Agents',
    'build01', 'oldagent', 'buildbox-old', 'former.dev', 'Former Dev', 'someone@outlook.com', 'Someone Private', 'kv-secrets', 'signing.pfx', 'dg-web',
    'contoso-packages', 'Contoso Agile', 'Release-42', 'v1-secretish', 'SECRETTOKEN42', 'do-not-export', 'hooks.slack.com', 'vmss-agents',
    'contoso-sandbox', 'contoso-archive', 'Contoso.Core', 'contoso/ui', 'webshop-lib', 'contoso-utils', 'contoso-tools', 'contoso-rs', 'webshop-assets', 'Project Collection Build Service', 'S-1-9-1551374245')

Test-Case 'mask run completes; zip created; mapping file and log outside the folder and the zip' {
    Assert-Equal 0 $run7.Errors.Count ($run7.Errors -join ' | ')
    $zip = [IO.Path]::Combine($global:TWOut, $run7.RunName + '.zip')
    Assert-True (Test-Path -LiteralPath $zip) 'zip missing'
    $map = [IO.Path]::Combine($global:TWOut, $run7.RunName + '.PRIVATE-maskmap.csv')
    Assert-True (Test-Path -LiteralPath $map) 'mask map missing'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath $run7.OutDir -Recurse -File -Filter '*general_log*').Count 'log inside the masked folder'
    Assert-True (Test-Path -LiteralPath ([IO.Path]::Combine($global:TWOut, $run7.RunStamp + '__general_log.PRIVATE.txt'))) 'private log missing'
    Assert-NotMatch $run7.RunName 'aaaaaaaa'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $z = [IO.Compression.ZipFile]::OpenRead($zip)
    try { $names = @($z.Entries | ForEach-Object { $_.FullName }) } finally { $z.Dispose() }
    Assert-True (@($names | Where-Object { $_ -match 'maskmap|general_log' }).Count -eq 0) ('private file in zip: ' + ($names -join ', '))
    Assert-True (@($names | Where-Object { $_ -like '*summary.html' }).Count -eq 1) 'summary.html not in zip'
}

Test-Case 'masked outputs contain none of the original names, IDs, IPs or tag values' {
    $leaks = [System.Collections.Generic.List[string]]::new()
    foreach ($f in @(Get-ChildItem -LiteralPath $run7.OutDir -Recurse -File)) {
        $text = [IO.File]::ReadAllText($f.FullName)
        foreach ($o in $originals) { if ($text.IndexOf($o, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $leaks.Add($f.Name + ': ' + $o) } }
    }
    Assert-Equal 0 $leaks.Count ([string]::Join(' | ', @($leaks | Select-Object -First 15)))
}

Test-Case 'masked Azure DevOps folders are named with pseudonyms and no pipelines are exported' {
    $dirs = @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($run7.OutDir, 'ADO')) -Directory -Recurse | ForEach-Object { $_.Name })
    Assert-True ($dirs.Count -ge 1) 'organization folder'
    foreach ($d in $dirs) { foreach ($o in $originals) { Assert-True ($d.IndexOf($o, [StringComparison]::OrdinalIgnoreCase) -lt 0) ('folder ' + $d + ' contains ' + $o) } }
    Assert-Equal 0 @($dirs | Where-Object { $_ -eq 'pipelines' }).Count 'pipelines exported under -Mask'
    Assert-Equal 'Skipped' ((Import-TWCsv $run7 'coverage.csv') | Where-Object Area -eq 'Azure DevOps pipeline export').Status
}

Test-Case 'masked feeds: own package names masked, public upstream packages, views and built-in groups kept' {
    $dir = @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($run7.OutDir, 'ADO')) -Directory)[0].FullName
    $pk = @(Import-Csv -LiteralPath ([IO.Path]::Combine($dir, 'packages.csv')) -Encoding UTF8)
    Assert-Equal 9 $pk.Count
    Assert-Equal 1 @($pk | Where-Object Package -eq 'left-pad').Count 'package cached from npmjs is public'
    Assert-Equal 8 @($pk | Where-Object { $_.Package -match '^(pkg|repo)-[0-9a-f]{10}$' }).Count ('own packages: ' + (($pk | ForEach-Object { $_.Package }) -join ', '))
    Assert-Equal 'Local; Release' @($pk | Where-Object { $_.Views -like '*Release*' })[0].Views
    $pm = @(Import-Csv -LiteralPath ([IO.Path]::Combine($dir, 'feedPermissions.csv')) -Encoding UTF8)
    Assert-Equal 1 @($pm | Where-Object Identity -eq 'Project Collection Administrators').Count 'built-in group name kept'
    Assert-Equal (Split-Path $dir -Leaf) ($pm | Where-Object Role -eq 'administrator').IdentityScope 'organization pseudonym'
}

Test-Case 'masking keeps the word "Azure" readable in notes and finding titles' {
    $t = @((Import-TWCsv $run7 'findings.csv') | ForEach-Object { $_.Title }) -join ' | '
    Assert-Match $t 'privileged Azure roles'
}

Test-Case 'masked outputs stay useful: consistent pseudonyms, private IPs, types and regions kept, Properties dropped' {
    $m = Import-TWCsv $run7 'allResources.csv'
    $vm = $m | Where-Object { $_.Type -eq 'Microsoft.Compute/virtualMachines' -and $_.PrivateIP -like '*10.0.1.4' }
    Assert-True ($null -ne $vm) 'VM row with private IP kept'
    Assert-Equal '[masked]' $vm.Properties
    Assert-Match $vm.Name '^vm-[0-9a-f]{10}$'
    Assert-Equal 'westeurope' $vm.Location
    $vms = Import-TWCsv $run7 'vms.csv'
    Assert-True (@($vms | Where-Object Name -eq $vm.Name).Count -eq 1) 'same pseudonym in vms.csv'
    Assert-Match $vm.PublicIP '192\.0\.2\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+'
    $zones = Import-TWCsv $run7 'privateDnsZones.csv'
    Assert-True (@($zones | Where-Object privateDNSzoneName -eq 'privatelink.blob.core.windows.net').Count -eq 1) 'privatelink zone name kept'
    $ra = Import-TWCsv $run7 'RBAC_role_assignments.csv'
    Assert-True (@($ra | Where-Object RoleDefinitionName -eq 'Owner').Count -ge 1) 'built-in role names kept'
    $cov = Import-TWCsv $run7 'coverage.csv'
    Assert-True (@($cov | Where-Object Area -eq 'Mask self-check').Count -eq 1) 'self-check row'
    $mapRows = @(Import-Csv -LiteralPath ([IO.Path]::Combine($global:TWOut, $run7.RunName + '.PRIVATE-maskmap.csv')) -Encoding UTF8)
    Assert-True (@($mapRows | Where-Object { $_.Original -eq 'vm-app01' -and $_.Pseudonym -eq $vm.Name }).Count -eq 1) 'mapping file re-identifies the VM'
    Assert-True (-not (Test-Path ([IO.Path]::Combine($run7.OutDir, 'code')))) 'code exported under -Mask'
}

# >>> TESTS <<<

$failed = Complete-Tests
if (-not $KeepOutput) { Remove-Item -LiteralPath $global:TWOut -Recurse -Force -ErrorAction SilentlyContinue }
else { Write-Host ('Output kept in ' + $global:TWOut) }
exit $failed
