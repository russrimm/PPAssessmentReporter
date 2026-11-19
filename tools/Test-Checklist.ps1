<#
.SYNOPSIS
    Checks that PPCS-Checklist.csv is present, current and complete.

.DESCRIPTION
    Invoke-PPCSReview.ps1 reads PPCS-Checklist.csv for its manual-check list, coverage and default severities. Without
    the file the script still runs, but the report silently loses most of that. This test makes a missing or stale file
    fail loudly. It checks that:
      1. the file exists next to the review script and has the columns the script reads;
      2. its content is exactly what tools\Export-Checklist.ps1 builds from the framework document (so the CSV and the
         document cannot drift apart, and a lost file is rebuilt with one command);
      3. every check ID the review script reports exists in the checklist.
    It exits with code 1 when anything is wrong. Run it with the other checks in CONTRIBUTING.md, and it runs in CI.

.EXAMPLE
    .\tools\Test-Checklist.ps1
#>
[CmdletBinding()]
param(
    [string]$ScriptPath,
    [string]$ChecklistPath
)

$ErrorActionPreference = 'Stop'
# $PSScriptRoot is not set yet while parameter defaults are evaluated on Windows PowerShell 5.1, so defaults are resolved here.
$toolsDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = Split-Path -Parent $toolsDir
if (-not $ScriptPath) { $ScriptPath = Join-Path $repoRoot 'Invoke-PPCSReview.ps1' }
if (-not $ChecklistPath) { $ChecklistPath = Join-Path $repoRoot 'PPCS-Checklist.csv' }

$problems = New-Object System.Collections.Generic.List[string]

if (-not (Test-Path -LiteralPath $ChecklistPath)) {
    Write-Error "PPCS-Checklist.csv is missing ($ChecklistPath). Rebuild it with: .\tools\Export-Checklist.ps1, then commit it." -ErrorAction Continue
    exit 1
}

$committed = @(Import-Csv -LiteralPath $ChecklistPath)
$columns = @('Id', 'Topic', 'Feature', 'Check', 'Verify', 'Target', 'Priority')
if ($committed.Count -eq 0) { $problems.Add('The checklist has no rows.') }
else {
    foreach ($c in $columns) { if (-not $committed[0].PSObject.Properties[$c]) { $problems.Add("The checklist has no '$c' column.") } }
}

# The CSV must equal what the framework document produces.
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('ppcs-checklist-' + [guid]::NewGuid().ToString('N') + '.csv')
try {
    [void](& (Join-Path $toolsDir 'Export-Checklist.ps1') -OutputPath $tmp 3>$null)
    $fresh = @(Import-Csv -LiteralPath $tmp)
}
finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force } }

$flat = { param($r) ($columns | ForEach-Object { [string]$r.$_ }) -join [char]0x1F }
$have = @{}; foreach ($r in $committed) { $have[[string]$r.Id] = & $flat $r }
$want = @{}; foreach ($r in $fresh) { $want[[string]$r.Id] = & $flat $r }
foreach ($id in ($want.Keys | Sort-Object { [version]($_ + '.0') })) {
    if (-not $have.ContainsKey($id)) { $problems.Add("Checklist item $id is in the framework document but not in the CSV.") }
    elseif ($have[$id] -ne $want[$id]) { $problems.Add("Checklist item $id differs from the framework document.") }
}
foreach ($id in ($have.Keys | Where-Object { -not $want.ContainsKey($_) })) { $problems.Add("Checklist item $id is in the CSV but not in the framework document.") }

# Every ID the script reports must be a checklist item, or its severity falls back to Medium.
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $ScriptPath).Path, [ref]$null, [ref]$errors)
if ($errors.Count) { throw "The script has $($errors.Count) parse error(s)." }
$calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Add-Finding', 'Add-Unavailable') }, $true)
$known = @{}; foreach ($r in $committed) { $known[[string]$r.Id] = $true }
$scriptIds = @{}
foreach ($c in $calls) {
    $els = @($c.CommandElements | Select-Object -Skip 1)
    $id = $null; $positional = @()
    for ($i = 0; $i -lt $els.Count; $i++) {
        $e = $els[$i]
        if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
            $arg = $e.Argument
            if (-not $arg -and ($i + 1) -lt $els.Count -and $els[$i + 1] -isnot [System.Management.Automation.Language.CommandParameterAst]) { $arg = $els[$i + 1]; $i++ }
            if ($e.ParameterName -eq 'Id') { $id = $arg }
        }
        else { $positional += $e }
    }
    if (-not $id -and $c.GetCommandName() -eq 'Add-Unavailable' -and $positional.Count -gt 0) { $id = $positional[0] }
    if ($id -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $scriptIds[$id.Value] = $c.Extent.StartLineNumber }
}
foreach ($id in ($scriptIds.Keys | Sort-Object { [version]($_ + '.0') })) {
    if (-not $known.ContainsKey($id)) { $problems.Add("Line $($scriptIds[$id]): the script reports check ID $id, which is not in the checklist.") }
}

"Checked $($committed.Count) checklist items against the framework document and $($scriptIds.Count) script check IDs."
if ($problems.Count) {
    $problems | ForEach-Object { Write-Warning $_ }
    Write-Warning 'To rebuild the checklist from the framework document, run .\tools\Export-Checklist.ps1 and commit PPCS-Checklist.csv.'
    exit 1
}
'The checklist is present, current and complete.'
