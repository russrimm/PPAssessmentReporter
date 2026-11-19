<#
.SYNOPSIS
    Rebuilds PPCS-Checklist.csv from the assessment framework document.

.DESCRIPTION
    Invoke-PPCSReview.ps1 reads PPCS-Checklist.csv (next to the script) to list the framework items that automation
    cannot cover, to calculate coverage, and to give findings their default severity. The framework document
    (PowerPlatform_CopilotStudio_Security_Review_v2.docx) is the source of truth for that list, so this tool
    reads the 18 checklist tables in the document and writes the CSV from them. Run it whenever the document changes,
    or to restore the CSV if it is ever lost.

    Output columns: Id, Topic, Feature, Check, Verify, Target, Priority. Text is normalized to the repository rules:
    ASCII only and US English (typographic punctuation becomes plain punctuation, and UK spellings are converted).
    The file is written as UTF-8 with a byte order mark so Windows PowerShell 5.1 and PowerShell 7 read it the same way.
    It works on both editions and needs no Word or other modules.

.PARAMETER DocxPath
    The framework document. Default: the .docx next to the script in the repository root.

.PARAMETER OutputPath
    Where to write the CSV. Default: PPCS-Checklist.csv in the repository root, which is where the review script looks.

.EXAMPLE
    .\tools\Export-Checklist.ps1
#>
[CmdletBinding()]
param(
    [string]$DocxPath,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
# $PSScriptRoot is not set yet while parameter defaults are evaluated on Windows PowerShell 5.1, so defaults are resolved here.
$repoRoot = Split-Path -Parent $(if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path })
if (-not $DocxPath) { $DocxPath = Join-Path $repoRoot 'PowerPlatform_CopilotStudio_Security_Review_v2.docx' }
if (-not $OutputPath) { $OutputPath = Join-Path $repoRoot 'PPCS-Checklist.csv' }
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Typographic characters that appear in the framework document, written as code points so this file stays ASCII.
$punctuation = @{
    0x2018 = "'"; 0x2019 = "'"; 0x201C = '"'; 0x201D = '"'; 0x2013 = '-'; 0x2014 = '-'; 0x2026 = '...'
    0x00A0 = ' '; 0x2192 = '->'; 0x2265 = '>='; 0x2264 = '<='; 0x00D7 = 'x'; 0x2022 = '-'
}
# UK spellings the framework document uses, converted to US English (a leading capital is kept).
$spelling = [ordered]@{
    'licence' = 'license'; 'licences' = 'licenses'; 'organisation' = 'organization'; 'organisations' = 'organizations'
    'behaviour' = 'behavior'; 'colour' = 'color'; 'centre' = 'center'; 'catalogue' = 'catalog'; 'analyse' = 'analyze'
    'minimise' = 'minimize'; 'prioritise' = 'prioritize'; 'authorise' = 'authorize'; 'standardise' = 'standardize'
    'categorise' = 'categorize'; 'summarise' = 'summarize'; 'recognise' = 'recognize'; 'customise' = 'customize'
    'optimise' = 'optimize'; 'utilise' = 'utilize'; 'sanitise' = 'sanitize'; 'defence' = 'defense'; 'programme' = 'program'
    'whilst' = 'while'; 'judgement' = 'judgment'; 'artefact' = 'artifact'; 'enrol' = 'enroll'; 'cancelled' = 'canceled'
    'labelled' = 'labeled'; 'modelling' = 'modeling'; 'travelling' = 'traveling'
    'customised' = 'customized'; 'externalised' = 'externalized'; 'minimised' = 'minimized'; 'organised' = 'organized'
    'prioritised' = 'prioritized'; 'standardised' = 'standardized'; 'authorised' = 'authorized'; 'recognised' = 'recognized'
    'optimised' = 'optimized'; 'categorised' = 'categorized'; 'summarised' = 'summarized'; 'sanitised' = 'sanitized'
    'analysed' = 'analyzed'; 'utilised' = 'utilized'; 'centralised' = 'centralized'; 'normalised' = 'normalized'
    'serialised' = 'serialized'; 'visualise' = 'visualize'; 'visualised' = 'visualized'; 'finalised' = 'finalized'
}

function ConvertTo-PlainText {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $cp = [int]$ch
        if ($cp -lt 128) { [void]$sb.Append($ch) }
        elseif ($punctuation.ContainsKey($cp)) { [void]$sb.Append($punctuation[$cp]) }
        else { throw ("Unmapped character U+{0:X4} in text: {1}. Add it to the punctuation table in this tool." -f $cp, $Text) }
    }
    $out = $sb.ToString()
    foreach ($k in $spelling.Keys) {
        $us = $spelling[$k]
        $out = [regex]::Replace($out, "\b$([regex]::Escape($k))\b", { param($m) if ($m.Value[0] -cmatch '[A-Z]') { $us.Substring(0, 1).ToUpperInvariant() + $us.Substring(1) } else { $us } }, 'IgnoreCase')
    }
    return ($out -replace '\s+', ' ').Trim()
}

$docx = (Resolve-Path -LiteralPath $DocxPath).Path
$zip = [System.IO.Compression.ZipFile]::OpenRead($docx)
try {
    $reader = New-Object System.IO.StreamReader($zip.GetEntry('word/document.xml').Open(), [System.Text.Encoding]::UTF8)
    try { $xml = $reader.ReadToEnd() } finally { $reader.Dispose() }
}
finally { $zip.Dispose() }

$doc = [xml]$xml
$ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
$ns.AddNamespace('w', 'http://schemas.openxmlformats.org/wordprocessingml/2006/main')

$expectedHeader = @('#', 'Feature / area', 'What to check', 'How to verify', 'Target state and red flags', 'Priority', 'Status')
$rows = New-Object System.Collections.Generic.List[object]
$tables = 0
foreach ($tbl in $doc.SelectNodes('//w:tbl', $ns)) {
    $trs = @($tbl.SelectNodes('w:tr', $ns))
    if ($trs.Count -lt 2) { continue }
    $head = @($trs[0].SelectNodes('w:tc', $ns) | ForEach-Object { ($_.InnerText -replace '\s+', ' ').Trim() })
    if (($head -join '|') -ne ($expectedHeader -join '|')) { continue }
    $tables++
    foreach ($tr in ($trs | Select-Object -Skip 1)) {
        $cells = @($tr.SelectNodes('w:tc', $ns))
        if ($cells.Count -ne 7) { throw "A checklist row has $($cells.Count) cells instead of 7: $(($cells | ForEach-Object { $_.InnerText }) -join ' | ')" }
        $c = @($cells | Select-Object -First 6 | ForEach-Object { ConvertTo-PlainText $_.InnerText })
        if ($c[0] -notmatch '^\d+\.\d+$') { throw "Unexpected checklist ID '$($c[0])'." }
        if ($c[5] -notin @('Critical', 'High', 'Medium', 'Low')) { throw "Unexpected priority '$($c[5])' for item $($c[0])." }
        [void]$rows.Add([pscustomobject][ordered]@{
                Id = $c[0]; Topic = $c[0].Split('.')[0]; Feature = $c[1]; Check = $c[2]; Verify = $c[3]; Target = $c[4]; Priority = $c[5]
            })
    }
}

if ($tables -ne 18) { throw "Expected 18 checklist tables in the document but found $tables." }
$dupes = @($rows | Group-Object Id | Where-Object Count -gt 1)
if ($dupes.Count -gt 0) { throw "Duplicate checklist IDs: $(($dupes | ForEach-Object Name) -join ', ')" }

# Cross-check against the document's own summary table (# | Assessment area | Section | Critical | High | Medium | Total).
# An item count that differs means an item was missed, so that stops the export. A priority mix that differs is a
# discrepancy inside the document itself: the item tables are kept (they are the detailed source) and a warning names the area.
$summaryHeader = @('#', 'Assessment area', 'Section', 'Critical', 'High', 'Medium', 'Total')
$summaryChecked = $false
foreach ($tbl in $doc.SelectNodes('//w:tbl', $ns)) {
    $trs = @($tbl.SelectNodes('w:tr', $ns))
    if ($trs.Count -lt 2) { continue }
    $head = @($trs[0].SelectNodes('w:tc', $ns) | ForEach-Object { ($_.InnerText -replace '\s+', ' ').Trim() })
    if (($head -join '|') -ne ($summaryHeader -join '|')) { continue }
    $summaryChecked = $true
    foreach ($tr in ($trs | Select-Object -Skip 1)) {
        $c = @($tr.SelectNodes('w:tc', $ns) | ForEach-Object { ($_.InnerText -replace '\s+', ' ').Trim() })
        if ($c[0] -notmatch '^\d+$') { continue }
        $mine = @($rows | Where-Object { $_.Topic -eq $c[0] })
        if ($mine.Count -ne [int]$c[6]) { throw "Area $($c[0]): the summary table lists $($c[6]) items but $($mine.Count) were read from the item table." }
        $got = @('Critical', 'High', 'Medium' | ForEach-Object { $p = $_; @($mine | Where-Object Priority -eq $p).Count })
        $want = @([int]$c[3], [int]$c[4], [int]$c[5])
        if (($got -join ',') -ne ($want -join ',')) {
            Write-Warning ("Area {0}: the document's summary table counts Critical/High/Medium as {1}, but its item table has {2}. The item table is used. Fix whichever is wrong in the document." -f $c[0], ($want -join '/'), ($got -join '/'))
        }
    }
}
if (-not $summaryChecked) { Write-Warning 'The summary table was not found in the document, so item counts were not cross-checked.' }

$sorted = @($rows | Sort-Object { [int]$_.Topic }, { [int]($_.Id.Split('.')[1]) })
$target = [System.IO.Path]::GetFullPath($OutputPath)
# Explicit CRLF so the file is identical on every platform and Git does not need to rewrite it.
$text = ((@($sorted | ConvertTo-Csv -NoTypeInformation)) -join "`r`n") + "`r`n"
[System.IO.File]::WriteAllText($target, $text, (New-Object System.Text.UTF8Encoding($true)))
"Wrote $($sorted.Count) checklist items from $tables tables to $target"
