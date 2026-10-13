<#
.SYNOPSIS
    Regenerates the report table in README.md from the report catalog inside azure2csv.ps1, so the documentation
    and -ListReports never drift apart.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $root 'azure2csv.ps1')

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('| Group | Report | Files | Speed | In profiles | What it contains |')
$lines.Add('|---|---|---|---|---|---|')
foreach ($r in $script:A2CReportCatalog) {
    $profiles = @(foreach ($p in $script:A2CProfiles.Keys) { if ((Expand-A2CReportNames $script:A2CProfiles[$p]) -contains $r.Name) { $p } })
    $name = '`' + $r.Name + '`' + $(if ($r.Explicit) { ' \*\*' } elseif ($r.OptIn) { ' \*' } else { '' })
    $files = ($r.Files -replace '\|', '/')
    $lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $r.Group, $name, $files, $r.Speed, ([string]::Join(', ', $profiles)), $r.Desc))
}
$readme = Join-Path $root 'README.md'
$text = [IO.File]::ReadAllText($readme)
$table = [string]::Join("`n", $lines)
$new = [regex]::Replace($text, '(?s)(<!-- reports:start -->).*?(<!-- reports:end -->)', { param($m) $m.Groups[1].Value + "`n" + $table + "`n" + $m.Groups[2].Value })
[IO.File]::WriteAllText($readme, $new, (New-Object System.Text.UTF8Encoding $false))
Write-Host ('README report table updated ({0} reports)' -f $script:A2CReportCatalog.Count) -ForegroundColor Green
