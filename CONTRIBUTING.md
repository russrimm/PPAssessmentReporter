# Contributing

This is a personal project, but changes are welcome as issues or pull requests. Please read this first.

## Ground rules

- **Read-only.** A check must never create, change or delete anything in a tenant. Use a POST only when a read endpoint requires it.
- **Honest results.** If the data cannot be read, report Not verified (`Add-Unavailable`). Never report Pass for something you could not see.
- **Optional features are not gaps.** When a feature is each customer's decision (Managed Environments, IP firewall, cookie binding, sharing limits and similar), report Pass or Info with a "Recommended:" action. Reserve Fail and Warning for controls whose absence is a risk on its own.
- **US English** in all text.

## Script encoding

`Invoke-PPCSReview.ps1` must be UTF-8 **with a byte order mark**, **CRLF** line endings and **ASCII-only** text. That is what lets it parse in both PowerShell 7 and Windows PowerShell 5.1. `.gitattributes` stops Git from rewriting it. Use `-` instead of an em dash and straight quotes.

## Adding a check

1. **Write the check** in a function and call it from `Invoke-Review` through the existing step wrapper, so one failure cannot stop the run. Raise findings with `Add-Finding` (or `Add-Unavailable` when a call failed). Give each one the framework ID, a short title, status, severity, confidence, value, detail, and a `-Recommendation` when there is something to do.
2. **Add a Why rule** to `$WhyRules` in `Get-WhyText`. Rules are first match wins, so put a title-specific rule before the generic rule for the same ID.
3. **Add a Learn rule** to `$LearnRules` in `Get-LearnLinks`, with the same ordering rule. Use real `learn.microsoft.com` pages and confirm each URL returns HTTP 200.
4. **Update the README**: add a row to the check reference under the right area (ID, check, how it is rated, Do and Why, Learn links). Keep the Why and Learn text identical to the script.
5. **Update `CHANGELOG.md`** and bump `$ScriptVersion` for a user-visible change.

## Checks to run before a pull request

```powershell
# 1. Parse on both PowerShell editions
foreach ($exe in 'pwsh', 'powershell') {
    & $exe -NoProfile -Command "`$e = `$null; [void][System.Management.Automation.Language.Parser]::ParseFile('.\Invoke-PPCSReview.ps1', [ref]`$null, [ref]`$e); `$e.Count"
}

# 2. Lint: 0 errors expected; do not add warnings
Invoke-ScriptAnalyzer -Path .\Invoke-PPCSReview.ps1 -Severity Error, Warning

# 3. Every finding in the script appears in the README reference
.\tools\Test-ReadmeCoverage.ps1
```

New functions should use singular nouns and avoid unused parameters so the lint warning count does not grow.

## Testing

There is no automated test suite and no recorded tests against a live tenant. The checks have been exercised against a mocked tenant only. When you change a check, say in the pull request how you tested it (ideally with a real tenant you own) and attach the `api-log.csv` of that run with tenant details removed.

## Contact

Russ Rimmerman, Cloud Solution Architect: [russ.rimmerman@microsoft.com](mailto:russ.rimmerman@microsoft.com). This is not an official Microsoft product.
