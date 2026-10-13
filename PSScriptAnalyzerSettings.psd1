# PSScriptAnalyzer settings for azure2csv.
# Run:  Invoke-ScriptAnalyzer -Path .\azure2csv.ps1 -Settings .\PSScriptAnalyzerSettings.psd1
# The offline test suite runs the same check when the PSScriptAnalyzer module is available.
@{
    Severity     = @('Error', 'Warning', 'Information')
    ExcludeRules = @(
        # Internal helper names follow the report/dataset catalog (New-A2CReportVMs, Get-A2CDatasetSubscriptions...).
        'PSUseSingularNouns',
        # Write-Host is used on purpose for the colored progress output of an interactive script (PS 5+: Information stream).
        'PSAvoidUsingWriteHost',
        # New-/Start-/Remove- helpers only build objects or text in memory (no system state changes to confirm).
        'PSUseShouldProcessForStateChangingFunctions',
        # Short internal helper calls such as Get-A2CNameFromId $id are clearer without parameter names.
        'PSAvoidUsingPositionalParameters'
    )
}
