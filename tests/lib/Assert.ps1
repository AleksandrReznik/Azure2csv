# Minimal assertion helpers (no Pester dependency; works on Windows PowerShell 5.1 and PowerShell 7).

$script:TestResults = [System.Collections.Generic.List[object]]::new()

function Test-Case {
    param([string] $Name, [scriptblock] $Body)
    try {
        & $Body
        $script:TestResults.Add([pscustomobject]@{ Name = $Name; Passed = $true; Error = '' })
        Write-Host ('  PASS  ' + $Name) -ForegroundColor Green
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.InvocationInfo) { $msg += ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')' }
        $script:TestResults.Add([pscustomobject]@{ Name = $Name; Passed = $false; Error = $msg })
        Write-Host ('  FAIL  ' + $Name + ' : ' + $msg) -ForegroundColor Red
    }
}

function Assert-True {
    param($Condition, [string] $Message = '')
    if (-not $Condition) { throw ('Assert-True failed. ' + $Message) }
}

function Assert-False {
    param($Condition, [string] $Message = '')
    if ($Condition) { throw ('Assert-False failed. ' + $Message) }
}

function Assert-Equal {
    param($Expected, $Actual, [string] $Message = '')
    if ([string]$Expected -cne [string]$Actual) { throw ('Expected [{0}] but got [{1}]. {2}' -f $Expected, $Actual, $Message) }
}

function Assert-Match {
    param([string] $Text, [string] $Pattern, [string] $Message = '')
    if ($Text -notmatch $Pattern) { throw ('Pattern [{0}] not found in [{1}]. {2}' -f $Pattern, $(if ($Text.Length -gt 300) { $Text.Substring(0, 300) + '...' } else { $Text }), $Message) }
}

function Assert-NotMatch {
    param([string] $Text, [string] $Pattern, [string] $Message = '')
    if ($Text -match $Pattern) { throw ('Pattern [{0}] unexpectedly found ({1}). {2}' -f $Pattern, $Matches[0], $Message) }
}

function Assert-Throws {
    param([scriptblock] $Script, [string] $Pattern, [string] $Message = '')
    $err = $null
    try { $null = & $Script } catch { $err = [string]$_.Exception.Message }
    if ($null -eq $err) { throw ('Expected an error matching [{0}] but nothing was thrown. {1}' -f $Pattern, $Message) }
    if ($err -notmatch $Pattern) { throw ('Expected an error matching [{0}] but got [{1}]. {2}' -f $Pattern, $err, $Message) }
}

function Complete-Tests {
    $failed = @($script:TestResults | Where-Object { -not $_.Passed })
    Write-Host ''
    $color = 'Green'
    if ($failed.Count -gt 0) { $color = 'Red' }
    Write-Host ('{0} tests, {1} passed, {2} failed  ({3} {4})' -f $script:TestResults.Count, ($script:TestResults.Count - $failed.Count), $failed.Count, $PSVersionTable.PSEdition, $PSVersionTable.PSVersion) -ForegroundColor $color
    foreach ($f in $failed) { Write-Host ('  - ' + $f.Name + ': ' + $f.Error) -ForegroundColor Red }
    return $failed.Count
}
