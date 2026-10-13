<#
.SYNOPSIS
    Generates the sample reports in docs\sample and docs\sample-masked from the fictional "Contoso" test tenant
    (no Azure access needed). Used for the README and blog screenshots.
#>
param([string] $DocsPath)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $DocsPath) { $DocsPath = Join-Path (Split-Path -Parent $here) 'docs' }
. (Join-Path (Split-Path -Parent $here) 'azure2csv.ps1')
. (Join-Path $here 'lib\Assert.ps1')
. (Join-Path $here 'lib\TestWorld.ps1')
. (Join-Path $here 'lib\FakeTransport.ps1')

$global:TWOut = Join-Path ([IO.Path]::GetTempPath()) ('a2c-sample-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $global:TWOut -Force | Out-Null

foreach ($variant in @(@{ Name = 'sample'; Mask = $false }, @{ Name = 'sample-masked'; Mask = $true })) {
    Reset-TWState
    $global:TWImportExcel = [bool](Get-Module -ListAvailable ImportExcel)
    $run = Invoke-TWRun -Params @{ ReportProfile = 'Full'; NoHtml = $false; NoExcel = $false; Mask = $variant.Mask } -KeepWorld
    $target = Join-Path $DocsPath $variant.Name
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
    Copy-Item -LiteralPath $run.OutDir -Destination $target -Recurse
    # the samples are published: replace the local temp folder (it contains the Windows user name) with a neutral path
    foreach ($f in @(Get-ChildItem -LiteralPath $target -Recurse -File -Include *.json, *.txt, *.csv, *.html)) {
        $bytes = [IO.File]::ReadAllBytes($f.FullName)
        $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
        $text = [IO.File]::ReadAllText($f.FullName)
        $new = $text.Replace($global:TWOut, 'C:\azure2csv').Replace($global:TWOut.Replace('\', '\\'), 'C:\\azure2csv')
        if ($new -ne $text) { [IO.File]::WriteAllText($f.FullName, $new, (New-Object System.Text.UTF8Encoding $bom)) }
    }
    Write-Host ('{0}: {1} files -> {2}' -f $variant.Name, @(Get-ChildItem -LiteralPath $target -Recurse -File).Count, $target) -ForegroundColor Green
}
Remove-Item -LiteralPath $global:TWOut -Recurse -Force -ErrorAction SilentlyContinue
