# Replaces the network seam and environment functions of azure2csv.ps1 with fixture-backed fakes.
# Dot-source AFTER azure2csv.ps1 so that these definitions win.

$global:TWRequests = [System.Collections.Generic.List[object]]::new()
$global:TWArtifactTool = [System.Collections.Generic.List[object]]::new()
$global:TWSizeProbes = [System.Collections.Generic.List[string]]::new()
# never the real <LocalAppData>\azure2csv, even before the first Reset-TWState
$script:A2CToolsRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'a2c-tools-tests')
$global:TWSleeps = [System.Collections.Generic.List[double]]::new()
$global:TWImportExcel = $false

function New-TWResponse {
    param($Obj, [int] $Status = 200, $Headers = $null)
    if ($null -eq $Headers) { $Headers = @{} }
    $content = $Obj
    if (-not ($Obj -is [string])) { $content = ConvertTo-Json -InputObject $Obj -Depth 40 -Compress }
    return @{ StatusCode = $Status; Content = $content; Headers = $Headers }
}

function New-TWError {
    param([int] $Status, [string] $Code, [string] $Message)
    return (New-TWResponse -Obj ([ordered]@{ error = [ordered]@{ code = $Code; message = $Message } }) -Status $Status)
}

function Resolve-TWArg {
    param([string] $Body)
    $b = ConvertFrom-Json $Body
    $key = ''
    if ([string]$b.query -match '//\s*a2c:(\w+)') { $key = $Matches[1] }
    # the other Resource Graph tables (a2c:table_<name>) answer empty without a fixture; MissingTables: tables this cloud lacks
    if ($key -like 'table_*' -and @($global:TW.MissingTables) -contains $key.Substring(6)) { return (New-TWError 400 'InvalidQuery' ("Table '" + $key.Substring(6) + "' is invalid, unsupported or disallowed.")) }
    if (-not $global:TW.Arg.ContainsKey($key) -and $key -notlike 'table_*') { return (New-TWError 400 'NoFixture' ('No Resource Graph fixture for query ' + $key)) }
    $rows = @($global:TW.Arg[$key] | Where-Object { $null -ne $_ })
    $subs = @($b.subscriptions)
    if ($subs.Count -gt 0 -and $null -ne $subs[0]) {
        $rows = @($rows | Where-Object { -not $_.Contains('subscriptionId') -or ($subs -contains $_['subscriptionId']) })
    }
    $top = [int]$b.options.'$top'
    $size = [math]::Min($top, [int]$global:TW.ArgPageSize)
    $offset = 0
    $tok = $b.options.'$skipToken'
    if ($tok) { $offset = [int]$tok }
    $end = [math]::Min($rows.Count, $offset + $size) - 1
    $slice = @()
    if ($offset -le $end) { $slice = @($rows[$offset..$end]) }
    $next = $null
    if ($end + 1 -lt $rows.Count) { $next = [string]($end + 1) }
    $obj = [ordered]@{ totalRecords = $rows.Count; count = $slice.Count; resultTruncated = 'false'; data = $slice; '$skipToken' = $next }
    return (New-TWResponse -Obj $obj -Headers @{ 'x-ms-user-quota-remaining' = '14'; 'x-ms-user-quota-resets-after' = '00:00:05' })
}

function Resolve-TWRoute {
    param($Routes, [string] $Method, [string] $Path, [string] $Body, [string] $Kind)
    foreach ($route in $Routes) {
        if ($Method -eq $route.Method -and $Path -match $route.Pattern) {
            $m = $Matches
            $res = & $route.Handler $Path $Body $m
            if ($res -is [hashtable] -and $res.ContainsKey('StatusCode')) { return $res }
            return (New-TWResponse -Obj $res)
        }
    }
    return (New-TWError 404 'NoFixture' ('No {0} fixture for {1} {2}' -f $Kind, $Method, $Path))
}

function New-TWZip {
    # a real zip file with the given entries (relative path -> text)
    param([string] $Path, $Entries)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $z = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($k in $Entries.Keys) {
            $sw = New-Object IO.StreamWriter($z.CreateEntry($k).Open())
            try { $sw.Write([string]$Entries[$k]) } finally { $sw.Dispose() }
        }
    }
    finally { $z.Dispose() }
}

function Invoke-A2CHttp {
    param([string] $Method = 'GET', [Parameter(Mandatory)] [string] $Uri, [string] $Body, [string] $Kind = 'arm', [string] $OutFile)
    $global:TWRequests.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body; Kind = $Kind })
    foreach ($t in $global:TW.Throttle) {
        if ($Uri -match $t.Pattern -and $t.Remaining -gt 0) {
            $t.Remaining--
            return @{ StatusCode = 429; Content = '{"error":{"code":"TooManyRequests","message":"throttled"}}'; Headers = @{ 'Retry-After' = [string]$t.RetryAfter } }
        }
    }
    # transport errors: Invoke-AzRestMethod threw (network, proxy or sign-in problem)
    foreach ($t in $global:TW.Fail) {
        if ($Uri -match $t.Pattern -and $t.Remaining -gt 0) {
            $t.Remaining--
            return @{ StatusCode = 0; Content = $t.Message; Headers = @{} }
        }
    }
    switch ($Kind) {
        'arg' { return (Resolve-TWArg -Body $Body) }
        'arm' {
            $path = $Uri -replace '^https://management\.azure\.com', ''
            return (Resolve-TWRoute -Routes $global:TW.ArmRoutes -Method $Method -Path $path -Body $Body -Kind 'ARM')
        }
        'graph' {
            $path = $Uri -replace '^https://graph\.microsoft\.com', ''
            return (Resolve-TWRoute -Routes $global:TW.GraphRoutes -Method $Method -Path $path -Body $Body -Kind 'Graph')
        }
        'ado' {
            $path = $Uri -replace '^https://', ''
            $res = Resolve-TWRoute -Routes $global:TW.AdoRoutes -Method $Method -Path $path -Body $Body -Kind 'ADO'
            # downloads: a route answers with Zip = @{ path = text } or File = text and the file is written like
            # Invoke-WebRequest -OutFile
            if ($OutFile -and $res.StatusCode -eq 200 -and $res.ContainsKey('Zip')) { New-TWZip -Path $OutFile -Entries $res.Zip; return @{ StatusCode = 200; Content = ''; Headers = @{} } }
            if ($OutFile -and $res.StatusCode -eq 200 -and $res.ContainsKey('File')) { [IO.File]::WriteAllText($OutFile, [string]$res.File); return @{ StatusCode = 200; Content = ''; Headers = @{} } }
            return $res
        }
        'kudu' {
            $path = $Uri -replace '^https://', ''
            $res = Resolve-TWRoute -Routes $global:TW.KuduRoutes -Method $Method -Path $path -Body $Body -Kind 'Kudu'
            if ($OutFile -and $res.StatusCode -eq 200 -and $res.ContainsKey('Zip')) { New-TWZip -Path $OutFile -Entries $res.Zip; return @{ StatusCode = 200; Content = ''; Headers = @{} } }
            return $res
        }
        'web' {
            # downloads without a token: WebZips = @{ pattern = @{ path = text } } (the ArtifactTool zip)
            foreach ($k in @($global:TW.WebZips.Keys)) {
                if ($Uri -match $k) {
                    if (-not $OutFile) { return @{ StatusCode = 400; Content = 'zip requested without OutFile'; Headers = @{} } }
                    New-TWZip -Path $OutFile -Entries $global:TW.WebZips[$k]
                    return @{ StatusCode = 200; Content = ''; Headers = @{} }
                }
            }
            foreach ($k in @($global:TW.WebRoutes.Keys)) { if ($Uri -match $k) { return (New-TWResponse -Obj ([string]$global:TW.WebRoutes[$k])) } }
            if ($Uri -match 'move-support-resources\.md$' -and $global:TW.Web.ContainsKey('move')) { return (New-TWResponse -Obj ([string]$global:TW.Web['move'])) }
            return @{ StatusCode = 404; Content = 'not found'; Headers = @{} }
        }
    }
}

function Start-A2CSleep {
    param([double] $Seconds)
    $global:TWSleeps.Add($Seconds)
    if ($null -ne $script:A2C) { $script:A2C.Stats.SleepSec += $Seconds }
}

function Get-A2CAzContext { return $global:TW.Context }
function Connect-A2CAzure {
    param($Options)
    if ($global:TW.ConnectError) { throw $global:TW.ConnectError }
    return $global:TW.Context
}
function Assert-A2CPrerequisites { return '9.9.9-test' }
function Test-A2CCanPrompt { return [bool]$global:TW.CanPrompt }
function Get-A2CFreeSpace { param([string] $Path) return [long]$global:TW.FreeSpace }
function Invoke-A2CConnectAzAccount {
    # the user signs in again: a successful sign-in ends the injected sign-in failures
    param([hashtable] $Params)
    $global:TW.SignInCalls.Add($Params)
    if (-not $global:TW.SignInWorks) { throw 'User canceled authentication.' }
    foreach ($t in $global:TW.Fail) { $t.Remaining = 0 }
}
function Test-A2CModuleAvailable { param([string] $Name) if ($Name -eq 'ImportExcel') { return [bool]$global:TWImportExcel }; return $false }
function Test-A2CMicrosoftSignature { param([string] $Path) return [bool]$global:TW.SignatureValid }
function Get-A2CDownloadSize {
    # headers-only size request: DownloadSizes = @{ pattern = bytes }, otherwise 2 KB
    param([string] $Uri)
    $global:TWSizeProbes.Add($Uri)
    foreach ($k in @($global:TW.DownloadSizes.Keys)) { if ($Uri -match $k) { return [long]$global:TW.DownloadSizes[$k] } }
    return [long]2048
}
function Get-A2CBearerToken { param([string] $Resource) return 'eyJ0eXAiOiJKV1QifQ.fake-entra-token.' + $Resource }
function Invoke-A2CArtifactTool {
    # records the call and writes the package files into --path (ArtifactToolFails: package names that fail)
    param([string] $Path, [string[]] $Arguments, [hashtable] $Environment, [int] $TimeoutSec = 7200)
    $a = @($Arguments)
    $global:TWArtifactTool.Add([pscustomobject]@{ Path = $Path; Arguments = $a; Environment = $Environment.Clone() })
    $name = $a[[array]::IndexOf($a, '--package-name') + 1]
    if (@($global:TW.ArtifactToolFails) -contains $name) {
        return @{ ExitCode = 18; Output = ('{"@t":"2026-10-01T10:00:00Z","@l":"Error","@m":"Cannot find the package ''' + $name + ''' in feed."}' + "`n" + '{"@t":"2026-10-01T10:00:01Z","@m":"done"}'); Result = '' }
    }
    $dir = $a[[array]::IndexOf($a, '--path') + 1]
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($dir, 'bin'))
    [IO.File]::WriteAllText([IO.Path]::Combine($dir, 'bin', 'tool.cmd'), '@echo ' + $name)
    [IO.File]::WriteAllText([IO.Path]::Combine($dir, 'readme.txt'), 'universal package ' + $name)
    return @{ ExitCode = 0; Output = ''; Result = '{"Version":"0.0.1"}' }
}

function Reset-TWState {
    $global:TW = New-TWWorld
    $global:TWRequests.Clear()
    $global:TWSleeps.Clear()
    $global:TWArtifactTool.Clear()
    $global:TWSizeProbes.Clear()
    # ArtifactTool cache of this world: never the real <LocalAppData>\azure2csv
    $script:A2CToolsRoot = [IO.Path]::Combine($global:TWOut, 'tools-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $script:A2CMoveMinRows = 5
    $script:A2CAdoPageSize = 1   # page through every Azure DevOps $top/$skip list
}

function Invoke-TWRun {
    # Runs the full pipeline against the fake tenant; returns the run context.
    param([hashtable] $Params, [switch] $KeepWorld)
    if (-not $KeepWorld) { Reset-TWState }
    $p = @{ OutputPath = $global:TWOut; NoHtml = $true; NoExcel = $true }
    foreach ($k in $Params.Keys) { $p[$k] = $Params[$k] }
    $opt = New-A2COptions -Params $p
    $opt.Now = [DateTime]::SpecifyKind([DateTime]'2026-09-29T00:00:00', [DateTimeKind]::Utc)
    Invoke-A2CRun -Options $opt 6>$null | Out-Null
    return $script:A2C
}

function Import-TWCsv {
    param($Run, [string] $File)
    $path = [IO.Path]::Combine($Run.OutDir, $File)
    if (-not (Test-Path -LiteralPath $path)) { throw ('File not written: ' + $File) }
    return @(Import-Csv -LiteralPath $path -Encoding UTF8)
}
