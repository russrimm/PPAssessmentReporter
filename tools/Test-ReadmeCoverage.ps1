<#
.SYNOPSIS
    Checks that every finding raised by Invoke-PPCSReview.ps1 is listed in README.md.

.DESCRIPTION
    Parses the review script, finds each Add-Finding / Add-Unavailable call, and confirms the README check
    reference has a row for the finding's ID and mentions its title. Titles built with variables are matched on
    their fixed leading text. Calls that only
    report a step as Not verified (Add-Unavailable or -Status Unavailable) must have an ID row but their title is
    not required, because the README documents that fallback once. Run it after adding or renaming a check; it
    exits with code 1 when anything is missing.

.EXAMPLE
    .\tools\Test-ReadmeCoverage.ps1
#>
[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path $PSScriptRoot '..\Invoke-PPCSReview.ps1'),
    [string]$ReadmePath = (Join-Path $PSScriptRoot '..\README.md')
)

$ErrorActionPreference = 'Stop'
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $ScriptPath).Path, [ref]$null, [ref]$errors)
if ($errors.Count) { throw "The script has $($errors.Count) parse error(s)." }
$readme = [IO.File]::ReadAllText((Resolve-Path $ReadmePath).Path)
$rowIds = @{}
foreach ($m in [regex]::Matches($readme, '(?m)^\| (\d+\.\d+) \|')) { $rowIds[$m.Groups[1].Value] = $true }

$calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Add-Finding', 'Add-Unavailable') }, $true)
$missing = New-Object System.Collections.Generic.List[string]
$checked = 0
foreach ($c in $calls) {
    $els = @($c.CommandElements | Select-Object -Skip 1)
    $id = $null; $title = $null; $positional = @()
    for ($i = 0; $i -lt $els.Count; $i++) {
        $e = $els[$i]
        if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
            $arg = $e.Argument
            if (-not $arg -and ($i + 1) -lt $els.Count -and $els[$i + 1] -isnot [System.Management.Automation.Language.CommandParameterAst]) { $arg = $els[$i + 1]; $i++ }
            if ($e.ParameterName -eq 'Id') { $id = $arg }
            if ($e.ParameterName -eq 'Title') { $title = $arg }
        }
        else { $positional += $e }
    }
    if ($c.GetCommandName() -eq 'Add-Unavailable') {
        if (-not $id -and $positional.Count -gt 0) { $id = $positional[0] }
        if (-not $title -and $positional.Count -gt 1) { $title = $positional[1] }
    }
    if ($id -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { continue }
    $checked++
    $line = $c.Extent.StartLineNumber
    if (-not $rowIds.ContainsKey($id.Value)) { $missing.Add("Line ${line}: ID $($id.Value) has no row in the README reference."); continue }
    $text = $null
    $unverifiedOnly = $c.GetCommandName() -eq 'Add-Unavailable' -or $c.Extent.Text -match '-Status\s+Unavailable\b'
    if ($unverifiedOnly) { $title = $null }
    if ($title -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $text = $title.Value }
    elseif ($title -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { $text = ($title.Value -split '\$|\{')[0] }
    if ($text -and $text.Trim().Length -ge 6 -and $readme.IndexOf($text.Trim(), [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $missing.Add("Line ${line}: title '$($text.Trim())' (ID $($id.Value)) is not mentioned in the README.")
    }
}

"Checked $checked findings in $(@($calls).Count) calls against $($rowIds.Count) README IDs."
if ($missing.Count) {
    $missing | Sort-Object -Unique | ForEach-Object { Write-Warning $_ }
    exit 1
}
'README covers every finding.'
