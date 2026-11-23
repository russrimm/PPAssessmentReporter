# Contributing

This is a personal project, but changes are welcome as issues or pull requests. Please read this first.

## Ground rules

- **Read-only.** A check must never create, change or delete anything in a tenant. Use a POST only when a read endpoint requires it.
- **Honest results.** If the data cannot be read, report Not verified (`Add-Unavailable`). Never report Pass for something you could not see.
- **Optional features are not gaps.** When a feature is each customer's decision (Managed Environments, default environment routing, the admin digest, IP firewall, cookie binding, sharing limits and similar), report Pass or Info with a "Recommended:" action. Reserve Fail and Warning for controls whose absence is a risk on its own.
- **Say what you could not confirm.** If a setting might exist but the API data does not show it (for example HTTP endpoint filtering rules, or a missing flow trigger setting), report Warning or Info and say so. Never present "not seen" as "does not exist".
- **US English** in all text.
- **Redactable output.** `-Redact` replaces names at the output boundary, so every file the script writes must go through it: write CSV with `Export-SafeCsv`, JSON through `Protect-Object` and HTML through `Protect-Html`, and build file names from redacted text (`Protect-Text`). A new evidence or usage column that holds a name of an environment, agent, app, flow, site, policy, group or person belongs in `$script:RedactionColumns` or `$script:RedactionUserColumns`. The check after writing scans every text file in the output folder, so a file that skips redaction shows up as a warning.

## Script encoding

`Invoke-PPCSReview.ps1` must be UTF-8 **with a byte order mark**, **CRLF** line endings and **ASCII-only** text. That is what lets it parse in both PowerShell 7 and Windows PowerShell 5.1. `.gitattributes` stops Git from rewriting it. Use `-` instead of an em dash and straight quotes.

## Adding a check

1. **Write the check** in a function and call it from `Invoke-Review` through the existing step wrapper, so one failure cannot stop the run. Raise findings with `Add-Finding` (or `Add-Unavailable` when a call failed). Give each one the framework ID, a short title, status, severity, confidence, value, detail, and a `-Recommendation` when there is something to do.
2. **Add a Why rule** to `$WhyRules` in `Get-WhyText`. Rules are first match wins, so put a title-specific rule before the generic rule for the same ID.
3. **Add a Learn rule** to `$LearnRules` in `Get-LearnLinks`, with the same ordering rule. Use real `learn.microsoft.com` pages and confirm each URL returns HTTP 200.
4. **Update the README**: add an entry to the check reference under the right area (a bullet that starts with the ID, then the check title, how it is rated, Do and Why, Learn links). Keep the Why and Learn text identical to the script.
5. **Update `CHANGELOG.md`** and bump `$ScriptVersion` for a user-visible change.

## Checks to run before a pull request

These also run in CI (`.github/workflows/validate.yml`) on every push and pull request.

```powershell
# 1. Parse on both PowerShell editions
foreach ($exe in 'pwsh', 'powershell') {
    & $exe -NoProfile -Command "`$e = `$null; [void][System.Management.Automation.Language.Parser]::ParseFile('.\Invoke-PPCSReview.ps1', [ref]`$null, [ref]`$e); `$e.Count"
}

# 2. Lint: 0 errors expected; do not add warnings
Invoke-ScriptAnalyzer -Path .\Invoke-PPCSReview.ps1 -Severity Error, Warning

# 3. Every finding in the script appears in the README reference
.\tools\Test-ReadmeCoverage.ps1

# 4. The checklist is present, matches the framework document and covers every check ID the script reports
.\tools\Test-Checklist.ps1
```

New functions should use singular nouns and avoid unused parameters so the lint warning count does not grow.

## The checklist file

`PPCS-Checklist.csv` is generated from the framework document (`PowerPlatform_CopilotStudio_Security_Review_v2.docx`), which is the source of truth. Do not edit the CSV by hand. Change the document, run `.\tools\Export-Checklist.ps1`, and commit all of it. The tool also rewrites the compressed copy of the checklist inside `Invoke-PPCSReview.ps1` (the `EMBEDDED CHECKLIST` block, which the script uses when no CSV is found next to it); never edit that block by hand either. The tool is ASCII and US English only, writes UTF-8 with a byte order mark and CRLF, and `.gitattributes` stops Git from rewriting the CSV. If you add a check with a new ID, the ID must exist in the document's checklist, or `tools\Test-Checklist.ps1` fails. That test also fails when the CSV, the built-in copy and the document disagree, and it runs in CI.

## Testing

There is no automated test suite and no recorded tests against a live tenant. The checks have been exercised against a mocked tenant only. When you change a check, say in the pull request how you tested it (ideally with a real tenant you own) and attach the `api-log.csv` of that run with tenant details removed.

## Contact

Russ Rimmerman, Cloud Solution Architect: [russ.rimmerman@microsoft.com](mailto:russ.rimmerman@microsoft.com). This is not an official Microsoft product.
